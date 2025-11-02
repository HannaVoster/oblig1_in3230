// kommunikasjon med MIP-daemon
//grensesnitt mot MIP deamon, nederste lag, under

/*
**Ansvar:**

- Kommunisere via UNIX-socket med `mipd`
- Pakke ut og tolke MIPTP-header
- Dele opp logikken mellom “data” og “ACK”-pakker

*/
#include "miptpd.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

/*
Metode for å:
    ta data fra en applikasjon og pakke inn i en miptp pakke
    pakken skal senere sendes ned til mipd gjennom UNIX socket, 
    og mipd skal sende den ut på nettverket

    Tar inn
        app_fd: socket til applikajsonen
        data: payloaden/data som skal sendes
        len: lengden på data

    header består av:
        source port
        destination port
        sequence number + padding length
        sdu + padding
*/

void send_miptp_data(int app_fd, uint8_t *data, size_t len) {
    printf("[MIPTPD] send_miptp_data() called (fd=%d, len=%zu)\n", app_fd, len);

    //sjekekr at lengden på payloaded er stor nok
    if (len < 2) {
        fprintf(stderr, "[MIPTPD] Invalid payload (too short)\n");
        return;
    }

    // -- pakker ut app meldingen
    uint8_t dst_mip  = data[0]; // der pakken skal
    uint8_t dst_port = data[1]; //porten pakkes skal sendes ut på
    uint8_t *payload = data + 2; //selve dataen som skal sendes
    size_t payload_len = len - 2; //lengden på dataen, -2 siden dst_mip og dst_port har data[0] og data[1]

    // -- henter faktisk port fra app_fd (lagret i en connections_table)
    uint8_t src_port = get_port_from_fd(app_fd);

    //-- finner riktig forbindelse
    int idx = get_index(app_fd);
    if (idx < 0) return;

    app_connection *connection = &app_connections[idx];

     // -- sjekker om vinduet er fullt
    if ((connection->next_seq - connection->base_seq) >= MIPTP_WINDOW_SIZE) {
        // Hvis antall pakker i flyt (next_seq - base_seq) er lik vindusstørrelsen
        printf("[MIPTPD] Window full for port %d — cannot send yet\n", connection->port);
        return;
    }

    // -- setter sekvensnummer
    uint16_t seq = connection->next_seq; // Bruker gjeldende next_seq som sekvensnummer for denne pakken
    connection->next_seq = (connection->next_seq + 1) % MIPTP_MAX_SEQ; // mod 2^14 for å håndtere sekvens-wraparound

    // -- Lager selve MIPTP-header
    // miptp_hdr_t hdr = {0};
    // hdr.src_port = src_port;
    // hdr.dst_port = dst_port;
    // hdr.seq_pad = pack_seq_pad(seq, 0);// 0 = data, ikke ack
    printf("[MIPTPD] Sending seq=%u from port %d\n", seq, src_port);

    // -- Bygger selve MIPTP-pakken, [Header][Payload]
    uint8_t packet[1500];
    size_t offset = 0;

    packet[offset++] = dst_mip;
    // src_port
    packet[offset++] = src_port;
    // dst_port
    packet[offset++] = dst_port;
    // seq_pad
    uint16_t seq_pad_net = pack_seq_pad(seq, 0);

    memcpy(packet + offset, &seq_pad_net, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    // payload
    memcpy(packet + offset, payload, payload_len);
    ssize_t packet_len = offset + payload_len;

    // -- lagrer pakken i sendebuffer for retransmisjon
    int slot = seq % MIPTP_WINDOW_SIZE; // Beregner plass i vinduet (sirkulær buffer)
    connection->window[slot].seq = seq; // Lagrer sekvensnummer i vindusplassen
    connection->window[slot].len = packet_len; // Lagre hvor lang pakken er (for retransmisjon)

    memcpy(connection->window[slot].data, packet, packet_len); // Kopier hele pakken inn i vindusbufferen (slik den kan sendes igjen)
    connection->window[slot].sent_time = time(NULL); // Merker tidspunktet pakken ble sendt (for timeout-sjekk)
    connection->window[slot].acked = 0;   // Setter ACK-status til 0 — den er sendt, men ikke bekreftet

    // sender pakken til mip deamon for å sende ut på nettverket
    ssize_t sent = write(MIP_FD, packet, packet_len);


    if (sent < 0){
        perror("[MIPTPD] write to mipd");
    }
    else {
        printf("[MIPTPD] Sent %zd bytes to mipd\n", sent);
        printf("[MIPTPD] Sending packet to mipd (dst_mip=%d, len=%zd)\n", packet[0], sent);
     }

            //-------------------------------------------------------------
    // 👇 LOKAL LOOPBACK-SIMULERING
    //-------------------------------------------------------------
        // int dest_fd = get_fd_from_port(dst_port); // Finn mottaker-app via port
        // if (dest_fd > 0) {
        //     uint8_t msg[2 + payload_len];
        //     msg[0] = hdr.src_port;   // avsenderport (så mottaker vet hvem det er fra)
        //     msg[1] = dst_port;       // mottakerport
        //     memcpy(msg + 2, payload, payload_len);

        //     ssize_t delivered = write(dest_fd, msg, sizeof(msg));
        //     if (delivered > 0) {
        //         printf("[LOOPBACK] Delivered %zd bytes locally to app port %d (fd=%d)\n",
        //             delivered, dst_port, dest_fd);
        //     } else {
        //         perror("[LOOPBACK] write to local app failed");
        //     }
        // } else {
        //     printf("[LOOPBACK] No local receiver on port %d — skipping local delivery\n", dst_port);
        // }

        // //TEST
        // sleep(1); // simulér RTT
        // miptp_hdr_t ack_hdr = {0};
        // ack_hdr.src_port = hdr.dst_port;
        // ack_hdr.dst_port = hdr.src_port;
        // ack_hdr.seq_pad   = pack_seq_pad(seq, 1);

        // uint8_t ack_packet[1 + sizeof(ack_hdr)];
        // ack_packet[0] = 1; // dummy MIP address
        // memcpy(ack_packet + 1, &ack_hdr, sizeof(ack_hdr));

        // printf("[SIM] Injecting fake ACK for seq=%u\n", seq);

        // if (seq % 2 == 0) {
        //     printf("[SIM] Injecting fake ACK for seq=%u\n", seq);
        //     handle_incoming_miptp_packet(ack_packet + 1, sizeof(ack_hdr), 1);
        // } else {
        //     printf("[SIM] Dropping ACK for seq=%u (simulate loss)\n", seq);
        // }
    
}

/*
Ansvar:
  Behandler en MIPTP-pakke som er mottatt fra MIP-daemonen (mipd)
  Pakken kommer inn via UNIX-socketen mellom miptpd og mipd, og denne
  funksjonen står skal tolke MIPTP-headeren og videresende payload
  til riktig applikasjon (som er identifisert med destinasjonsport)
    inkluderer
        finne riktig destinasjonsport
        slå opp app_fd med get_fd_from_port()
        skriv tilbake til riktig app

  Tar inn:
    buf: peker til pakken inkludert header
    len: den totale lengden på pakken
    src_mip: mip addressen til avsender

 Fremtidige utvidelser:
 *   - Implementer sekvenskontroll (ikke lever SDUs utenfor rekkefølge)
 *   - Send ACK tilbake til avsender (hdr.src_port)
 *   - Håndter duplikater og tapte pakker (Go-Back-N logikk)
 *   - Fjern eventuell padding fra payload
*/
void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip) {
    // er pakken stor nok til å ha en header
    if (len < sizeof(miptp_hdr_t)) return;
    
     // Debug: dump hele rå MIPTP-pakken slik den kommer fra mipd
    printf("[DEBUG] Raw incoming MIPTP packet (len=%zu): ", len);
    for (size_t i = 0; i < len; i++) printf("%02X ", buf[i]);
    printf("\n");

    //kopierer ut miptpd header fra buffer
    miptp_hdr_t hdr;
    memcpy(&hdr, buf+1, sizeof(hdr));

    //lager en peker til payload og beregner lengde
    uint8_t *payload = buf +1 + sizeof(hdr);
    size_t payload_len = len - 1 - sizeof(hdr);

    printf("[MIPTPD] Got packet from MIP %d, src_port=%d dst_port=%d len=%zu\n",
           src_mip, hdr.src_port, hdr.dst_port, payload_len);
    
    // uint16_t seq = (hdr.seq_pad) >> 2; // hent 14-bit sekvens
    // uint8_t pad = hdr.seq_pad & 0x3; //brukes senere for padding controll

    uint16_t seq;
    uint8_t pad;

    unpack_seq_pad(ntohs(hdr.seq_pad), &seq, &pad);

    printf("[MIPTPD] Got packet seq=%u src_port=%d dst_port=%d len=%zu\n",
       seq, hdr.src_port, hdr.dst_port, payload_len);

    // ACK pdu
    if (pad == 1) {
        int fd = get_fd_from_port(hdr.dst_port); //henter hvilken app tilkobling acken hører til
        if (fd >= 0) {
            int idx = get_index(fd); //henter indexen appen har i app_connections tabellen
          
            if (idx >= 0) {
                app_connection *connection = &app_connections[idx];
                uint16_t ack_seq = seq;

                printf("[MIPTPD] ACK received for seq=%u (port=%d)\n",
                    seq, hdr.dst_port);

                // marker pakken som ACKet
                int slot = ack_seq % MIPTP_WINDOW_SIZE; // Finner posisjonen i vinduet (mod MIPTP_WINDOW_SIZE for sirkulær buffer)
                connection->window[slot].acked = 1; //markerer pakken som mottatt

                // flytter base_seq frem hvis mulig (ruller frem vinduet)
                while (connection->base_seq != connection->next_seq && // det finnes usendte eller uackede pakker
                    connection->window[connection->base_seq % MIPTP_WINDOW_SIZE].acked) { // // og den eldste (base_seq) er ACK-et

                    connection->base_seq = (connection->base_seq + 1) % MIPTP_MAX_SEQ; // flytter base_seq ett steg frem (vindusstart flyttes)
                    connection->window_count--; // reduser antall pakker i vinduet (frigjør plass)
                }

                return; 
            }
        }
        printf("[MIPTPD] ACK received but no matching connection found (dst_port=%d)\n",
               hdr.dst_port);
        return;
    }
    
    //data pdu
    int app_fd = get_fd_from_port(hdr.dst_port);
    if (app_fd < 0) {
        fprintf(stderr, "[MIPTPD] No app registered on port %d\n", hdr.dst_port);
        return;
    }
    
    uint8_t msg[2 + payload_len];
    msg[0] = src_mip;
    msg[1] = hdr.src_port;
    memcpy(msg + 2, payload, payload_len);

    ssize_t sent = write(app_fd, msg, sizeof(msg));
    send_miptp_ack(src_mip, hdr.dst_port, hdr.src_port, seq);
 
    if (sent > 0) {
    printf("[MIPTPD] Delivered %zd bytes to app port %d (fd=%d)\n",
           sent, hdr.dst_port, app_fd);
    } else {
        perror("[MIPTPD] write to app failed");
        fprintf(stderr, "[DEBUG] Current connection table:\n");
        for (int i = 0; i < MAX_APPS; i++)
            if (app_connections[i].app_fd)
                fprintf(stderr, "  [%d] fd=%d port=%d\n",
                        i, app_connections[i].app_fd, app_connections[i].port);
    }
}


void send_miptp_ack(uint8_t dst_mip, uint8_t src_port, uint8_t dst_port, uint16_t seq) {
    miptp_hdr_t hdr = {0};
    hdr.src_port = dst_port; // egen port er nå source
    hdr.dst_port = src_port; // sender tilbake ack til source

    // padlen=1 (ACK-type), sekvensnummer settes som vanlig
    hdr.seq_pad = pack_seq_pad(seq, 1);

    // Bygg pakken
    uint8_t packet[1 + sizeof(hdr)];
    packet[0] = dst_mip;
    memcpy(packet + 1, &hdr, sizeof(hdr));

    ssize_t sent = write(MIP_FD, packet, sizeof(packet));
    if (sent < 0)
        perror("[MIPTPD] write ACK to mipd");
    else
        printf("[MIPTPD] Sent ACK (seq=%u) to MIP %d, port=%d\n", seq, dst_mip, dst_port);
}



// int init_mip_socket(const char *path);
// void send_miptp_data(uint8_t dst_mip, uint8_t *pdu, size_t len);
// void send_miptp_ack(uint8_t dst_mip, uint8_t dst_port, uint16_t seq);
// void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip);


// // Fra miptp_mip.c
// void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip);
// void send_miptp_data(int app_fd, uint8_t *data, size_t len);


/*
  Sender en MIPTP-ACK tilbake til avsender.
  - dst_mip: MIP-adressen pakken skal til
  - src_port: porten som sender ACK (vår port)
  - dst_port: porten vi svarer til
  - seq: sekvensnummeret vi bekrefter
*/
