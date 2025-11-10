/*
 *  Ansvar:
 *  - Mottar og håndterer MIPTP-pakker fra MIP-daemonen (mipd)
 *  - Skiller mellom datapakker (DATA-PDU) og kvitteringer (ACK-PDU)
 *  - Oppdaterer Go-Back-N vinduet ved ACK
 *  - Leverer in-order data til riktig applikasjon
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

    //pakker ut header og felt 
    miptp_hdr_t hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    uint8_t *payload = buf + sizeof(hdr);
    size_t payload_len = len - sizeof(hdr);

    uint16_t seq;
    uint8_t pad;
    unpack_seq_pad(ntohs(hdr.seq_pad), &seq, &pad);

    printf("[MIPTPD] Got packet from MIP %d, src_port=%d dst_port=%d len=%zu seq=%u pad=%u\n",
           src_mip, hdr.src_port, hdr.dst_port, payload_len, seq, pad);

    // skiller mellom ACK og DATA s
    if (payload_len == 0)
        handle_incoming_ack(&hdr, seq);
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
void handle_incoming_ack(miptp_hdr_t *hdr, uint16_t seq) {
    int fd = get_fd_from_port(hdr->dst_port); // Finner applikasjonens socket basert på destinasjonsporten i headeren
    if (fd < 0) {
        printf("[MIPTPD] ACK for unknown app port=%d ignored\n", hdr->dst_port);
        return; // Ignorerer ACK — det finnes ingen gyldig mottaker
    }

    int idx = get_index(fd);
    if (idx < 0) return;
    app_connection *conn = &app_connections[idx]; // Peker til applikasjonens forbindelsesstruktur

    printf("[MIPTPD] ACK received for seq=%u (port=%d)\n", seq, hdr->dst_port);

    // --- Valider at ACK gjelder for det aktive vinduet ---
    uint16_t diff = (seq + MIPTP_MAX_SEQ - conn->base_seq) % MIPTP_MAX_SEQ; // Hvor langt unna base_seq denne ACKen er
    if (diff >= MIPTP_WINDOW_SIZE) {                                        // Hvis ACKen gjelder en pakke utenfor gjeldende vindu
        printf("[MIPTPD][GBN] Ignored stale ACK (ack=%u base=%u)\n", seq, conn->base_seq);
        return;
    }

    // --- Flytter vindu fremover ---
    uint16_t old_base = conn->base_seq;
    conn->base_seq = (seq + 1) % MIPTP_MAX_SEQ;  // ACK indikerer at alle pakker opp til seq er mottatt

    // --- Marker vindusplasser som ACKet ---
    for (uint16_t s = old_base; s != conn->base_seq; s = (s + 1) % MIPTP_MAX_SEQ) {
        int slot = s % MIPTP_WINDOW_SIZE; // Finner posisjon (sirkulært vindu)
        if (!conn->window[slot].acked && conn->window[slot].len > 0) {
            conn->window_count--; // REDUSER vindusteller
        }
        conn->window[slot].acked = 1; //markerer som acket
        conn->window[slot].len = 0;
    }

    // --- Sjekker om man kan sende flere pakker fra køen ---
    while (conn->queue_count > 0 &&
          ((conn->next_seq + MIPTP_MAX_SEQ - conn->base_seq) % MIPTP_MAX_SEQ) < MIPTP_WINDOW_SIZE) { // er det pakker i kø og er vindu ikke fullt

        int pos = conn->queue_head % MIPTP_MAX_QUEUE;
    
        send_miptp_data(conn->app_fd, conn->queue[pos].data, conn->queue[pos].len); // tømmer kø

        conn->queue_head++; // Flytter køhode fremover
        conn->queue_count--;
    }

    // --- Logger status på vinduet etter oppdatering ---
    if (conn->base_seq == conn->next_seq)
        printf("[MIPTPD][GBN] All packets ACKed — window empty\n");
    else
        printf("[MIPTPD][GBN] Waiting for more ACKs (base=%u next=%u)\n",
               conn->base_seq, conn->next_seq);
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

    hex_debug("[MIPTPD][FROM MIPD] Raw payload", payload, len);

    uint8_t src_port = hdr->src_port;
    uint8_t dst_port = hdr->dst_port;

    int app = get_fd_from_port(hdr->dst_port);// Finner file descriptor (socket) til applikasjonen som har registrert denne destinasjonsporten
    if (app < 0) {
        fprintf(stderr, "[MIPTPD] No app registered on port %d\n", hdr->dst_port);
        return;
    }

    int idx = get_index(app); // Finner indeksen i app_connections[] som tilsvarer denne applikasjonen
    if (idx < 0) return;
    app_connection *conn = &app_connections[idx];

    // sjekk om ny (src_mip, src_port)
    if (!transfer_exists(conn, src_mip, src_port)) {
        register_new_transfer(conn, src_mip, src_port);

        uint8_t ctrl_msg[3] = {0xFF, src_mip, src_port};
        write(conn->app_fd, ctrl_msg, sizeof(ctrl_msg));

        printf("[MIPTPD][NEW TRANSFER] src=%u:%u -> dst_port=%u\n",
               src_mip, src_port, dst_port);
    }

    // Init synkronisering på første mottatte pakke
    if (!conn->synced) {
        conn->expected_seq = seq; // Setter forventet sekvensnummer til neste etter den som nettopp ble mottatt
        conn->synced = 1;                               // Merker forbindelsen som “synkronisert” (klar for Go-Back-N)

         printf("[MIPTPD][INIT] First packet seq=%u → synced\n", seq);
    }

    uint16_t expected = conn->expected_seq;
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
        printf("[MIPTPD][RX] Out-of-order DATA ignored (seq=%u expected=%u)\n", seq, expected);
        send_miptp_ack(src_mip, hdr->dst_port, hdr->src_port,
                       (expected - 1 + MIPTP_MAX_SEQ) % MIPTP_MAX_SEQ); // Bekrefter siste mottatte riktige pakke, slik at avsender vet hvor den må retransmittere fra
        return; // Ignorerer denne pakken (venter på riktig sekvens)
    }

    // // In-order pakke, leveres til applikasjonen
    // if (len >= pad) len -= pad; // fjerner padding som ble lagt til ved sending
    uint8_t msg[2 + len];       // buffer for å sende opp til appen, 2 ekstra byte til metadata
    msg[0] = src_mip;           // mip addressen til avsender
    msg[1] = hdr->src_port;     // kildeport, hvilken port på avsender
    memcpy(msg + 2, payload, len);

    hex_debug("[MIPTPD][TO APP] Deliver", payload, len);

    if (len >= pad) len -= pad;
    //ssize_t sent = write(app, payload, len);  
    ssize_t sent = write(app, msg, len + 2);  

    if (sent > 0)
        printf("[MIPTPD] Delivered %zd bytes to app port %d (fd=%d)\n", sent, hdr->dst_port, app);
    else
        perror("[MIPTPD] write to app failed");

    // Oppdater forventet sekvens og send ACK til avsender for å bekrefte mottak
    conn->expected_seq = (seq + 1) % MIPTP_MAX_SEQ;
    send_miptp_ack(src_mip, hdr->dst_port, hdr->src_port, seq);
}


