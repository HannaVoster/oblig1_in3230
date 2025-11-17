/*
 *  Ansvar:
 *  - Mottar og håndterer MIPTP-pakker fra MIP-daemonen (mipd)
 *  - Skiller mellom datapakker (DATA-PDU) og kvitteringer (ACK-PDU)
 *  - Oppdaterer Go-Back-N vinduet ved ACK
 *  - Leverer in-order data til riktig applikasjon
 *  - Håndterer flere samtidige inbound og outbound transfers per app
 *  - Bruker src_mip + src_port til å identifisere riktig transfer
 */

#include "miptpd_incoming.h"
#include "miptpd_utils.h"   
#include "miptpd_send.h"   

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

/*
 *  handle_incoming_miptp_packet()
 *
 *  Formål:
 *  - Tar imot en MIPTP-pakke fra MIP-daemonen (mipd)
 *  - Pakker ut headeren og identifiserer om den er DATA eller ACK
 *
 *  Parametere:
 *      buf     - hele mottatte PDU fra mipd
 *      len     - total lengde på pakken
 *      src_mip - MIP-adressen til avsender
 *
 *  Logikk:
 *      1. Validerer pakkelengde
 *      2. Leser ut MIPTP-header
 *      3. Deler på om det er ACK (tom payload) eller DATA
 */
void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip) {
    if (len < sizeof(miptp_hdr_t)) {
        fprintf(stderr, "[MIPTPD] Incoming packet too short (%zu bytes)\n", len);
        return;
    }

    if(debug_mode) printf("[MIPTPD] Packet from mip %d len=%zu\n", src_mip, len);

    //pakker ut header og felt 
    miptp_hdr_t hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    uint8_t *payload = buf + sizeof(hdr);
    size_t payload_len = len - sizeof(hdr);

    uint16_t seq;
    uint8_t pad;
    unpack_seq_pad(ntohs(hdr.seq_pad), &seq, &pad);

    // skiller mellom ACK og DATA s
    if (payload_len == 0)
        handle_incoming_ack(&hdr, seq, src_mip);
    else
        handle_incoming_data(&hdr, payload, payload_len, seq, pad, src_mip);
}

/*
 *  handle_incoming_ack()
 *
 *  Formål:
 *  - Behandler mottatte ACKer for Go-Back-N-protokollen
 *  - Oppdaterer base_seq og frigjør vindusplasser
 *  - Sender eventuelle køede pakker dersom vinduet åpnes
 *
 *  Parametere:
 *      hdr     - peker til MIPTP-headeren
 *      seq     - sekvensnummeret som ble ACKet
 *      src_mip - MIP-adresse til avsender
 */
void handle_incoming_ack(miptp_hdr_t *hdr, uint16_t seq, uint8_t src_mip) {
    int fd = get_fd_from_port(hdr->dst_port); // Finner applikasjonens socket basert på destinasjonsporten i headeren
    if (fd < 0) {
        printf("[MIPTPD] ACK for unknown app port=%d ignored\n", hdr->dst_port);
        return; // Ignorerer ACK — det finnes ingen gyldig mottaker
    }

    int idx = get_index(fd);
    if (idx < 0) return;
    app_connection *app= &app_connections[idx]; // Peker til applikasjonens forbindelsesstruktur

    outbound_transfer_state *t = find_outbound_for_ack(app, src_mip, hdr->src_port); // finner transfer
    if (!t) {
        return; // ignorerer
    }

    if(debug_mode) printf("[MIPTPD][ACK] seq=%u (port=%d)\n", seq, hdr->dst_port);

    // --- Valider at ACK gjelder for det aktive vinduet ---
    uint16_t diff = (seq + MIPTP_MAX_SEQ - t->base_seq) % MIPTP_MAX_SEQ; // Hvor langt unna base_seq denne ACKen er
    if (diff >= MIPTP_WINDOW_SIZE) {                                        // Hvis ACKen gjelder en pakke utenfor gjeldende vindu
        printf("[MIPTPD][GBN] Ignored stale ACK (ack=%u base=%u)\n", seq, t->base_seq);
        return;
    }

    // --- Flytter vindu fremover ---
    uint16_t old_base = t->base_seq;
    t->base_seq = (seq + 1) % MIPTP_MAX_SEQ;     // ACK betyr at alle sekvenser opp til og med `seq` er mottatt
                                                // Oppdaterer base_seq for akkurat denne transferen (src_mip, src_port)

    if (t->base_seq != old_base && debug_mode) {
        if(debug_mode) printf("[MIPTPD][GBN] Window advanced → base=%u\n", t->base_seq);
    }

    // --- Marker vindusplasser som ACKet ---
    for (uint16_t s = old_base; s != t->base_seq; s = (s + 1) % MIPTP_MAX_SEQ) {
        int slot = s % MIPTP_WINDOW_SIZE; // Finner posisjon (sirkulært vindu)
        if (!t->window[slot].acked && t->window[slot].len > 0) {
            t->window_count--; // REDUSER vindusteller
        }
        t->window[slot].acked = 1; //markerer som acket
        t->window[slot].len = 0;
    }

    // --- Sjekker om man kan sende flere pakker fra køen ---
    while (t->queue_count > 0 &&
          ((t->next_seq + MIPTP_MAX_SEQ - t->base_seq) % MIPTP_MAX_SEQ) < MIPTP_WINDOW_SIZE) { // er det pakker i kø og er vindu ikke fullt

        int pos = t->queue_head % MIPTP_MAX_QUEUE;
    
        send_miptp_data_on_transfer(app, t,
                            t->queue[pos].data,
                            t->queue[pos].len); //Tømmer kø

        t->queue_head++; // Flytter køhode fremover
        t->queue_count--;
    }
}
/*
 *  handle_incoming_data()
 *
 *  Formål:
 *  - Tar imot datapakker (SDU) fra en annen MIP-node
 *  - Kontrollerer sekvensrekkefølge (Go-Back-N)
 *  - Leverer kun in-order pakker til applikasjonen
 *  - Sender ACK tilbake for siste korrekte pakke
 *
 *  Parametere:
 *      hdr      - peker til MIPTP-header
 *      payload  - peker til datafeltet
 *      len      - lengde på datafeltet
 *      seq      - sekvensnummer for pakken
 *      pad      - antall pad-byte (0–3)
 *      src_mip  - MIP-adresse til avsender
 */
void handle_incoming_data(miptp_hdr_t *hdr, uint8_t *payload, size_t len,
                          uint16_t seq, uint8_t pad, uint8_t src_mip) {

    uint8_t src_port = hdr->src_port;
    uint8_t dst_port = hdr->dst_port;

    int app = get_fd_from_port(hdr->dst_port);// Finner file descriptor (socket) til applikasjonen som har registrert denne destinasjonsporten
    if (app < 0) {
        fprintf(stderr, "[MIPTPD] No app registered on port %d\n", hdr->dst_port);
        return;
    }

    int idx = get_index(app); // Finner indeksen i app_connections[] som tilsvarer denne applikasjonen
    if (idx < 0) return;
    app_connection *appc = &app_connections[idx];

    // Finner eksisterende inbound-transfer basert på (src_mip, src_port)
    // Hvis dette er en ny avsender (ny fil), opprettes en ny transfer
    transfer_state *t = find_transfer(appc, src_mip, src_port);
    if (!t) {
        t = create_transfer_state(appc, src_mip, src_port);
        printf("[MIPTPD] New inbound transfer %d:%d → port %d\n",
            src_mip, src_port, dst_port);

        // Legger på metadata (src_mip, src_port) slik at applikasjonen kan vite
        // hvilken avsenders transfer denne pakken kommer fra
        uint8_t ctrl_msg[3] = {0xFF, src_mip, src_port};
        write(app, ctrl_msg, 3);
    }

    // Init synkronisering på første mottatte pakke
    if (!t->synced) {
        t->expected_seq = seq; // forventer at første pakke i en ny transfer har dette sekvensnummeret
        t->synced = 1;         // Merker forbindelsen som “synkronisert” (klar for Go-Back-N)

        if(debug_mode) printf("[MIPTPD][INIT] First packet seq=%u → synced\n", seq);
    }

    uint16_t expected = t->expected_seq;
    uint16_t ahead = (seq + MIPTP_MAX_SEQ - expected) % MIPTP_MAX_SEQ; // Beregner hvor langt frem (eller bak) den mottatte sekvensen er i forhold til det forventede

    // kontroll ------ Duplikatpakke 
    if (ahead >= MIPTP_MAX_SEQ - MIPTP_WINDOW_SIZE) { // Hvis sekvensnummeret ligger “bak” i vinduet (duplikat)
        printf("[MIPTPD][RX] Duplicate DATA ignored (seq=%u expected=%u)\n", seq, expected);
        send_miptp_ack(src_mip, hdr->dst_port, hdr->src_port,
                       (expected - 1 + MIPTP_MAX_SEQ) % MIPTP_MAX_SEQ);
        return;
    }

    // kontroll ------ Out-of-order pakke 
    if (seq != expected) { // Hvis sekvensnummeret ikke er det som forventes (dvs. en pakke har blitt droppet)
        if(debug_mode) printf("[MIPTPD][RX] Out-of-order DATA ignored (seq=%u expected=%u)\n", seq, expected);

        send_miptp_ack(src_mip, hdr->dst_port, hdr->src_port,
                       (expected - 1 + MIPTP_MAX_SEQ) % MIPTP_MAX_SEQ); // Bekrefter siste mottatte riktige pakke, slik at avsender vet hvor den må retransmittere fra
        return; // Ignorerer denne pakken (venter på riktig sekvens)
    }

    // In-order pakke, leveres til applikasjonen
    uint8_t msg[2 + len];       // buffer for å sende opp til appen, 2 ekstra byte til metadata
    msg[0] = src_mip;           // mip addressen til avsender
    msg[1] = hdr->src_port;     // kildeport, hvilken port på avsender
    memcpy(msg + 2, payload, len);

    if (len >= pad) len -= pad;
    //ssize_t sent = write(app, payload, len);  
    ssize_t sent = write(app, msg, len + 2);  

    if (sent > 0)
        printf("[MIPTPD] Delivered %zd bytes to app port %d (fd=%d)\n", sent, hdr->dst_port, app);
    else
        perror("[MIPTPD] write to app failed");

    // Oppdater forventet sekvens og send ACK til avsender for å bekrefte mottak
    t->expected_seq = (seq + 1) % MIPTP_MAX_SEQ;
    send_miptp_ack(src_mip, hdr->dst_port, hdr->src_port, seq);
}


