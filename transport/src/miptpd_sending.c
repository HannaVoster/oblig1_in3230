/*
 *  Ansvar:
 *  - Håndtere utsending av MIPTP-pakker til MIP-daemonen (mipd)
 *  - Pakke applikasjonsdata i MIPTP-format (PDU)
 *  - Implementere Go-Back-N logikk for utsending og vindushåndtering
 *  - Håndtere kø når vinduet er fullt
 *  - Utføre selve sendingen av data og ACKs (ikke retransmisjon)
 */

#include "miptpd_send.h"
#include "miptpd_utils.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

/*
  Sender en ferdigbygget MIPTP-PDU til MIP-daemonen
  Legger på MIP-routing-header (MIP + TTL) før utsending via UNIX-socket
*/
void send_miptp_pdu(uint8_t dst_mip, uint8_t *miptp_pdu, size_t pdu_len) {
    uint8_t ttl = 10; // kan være standard
    uint8_t buffer[2 + pdu_len];

    buffer[0] = dst_mip; // destinasjons-MIP, mipd bruker denne for routing
    buffer[1] = ttl;     // TTL-felt som mipd legger i MIP-headeren
    memcpy(buffer + 2, miptp_pdu, pdu_len); //selve pdu data

    // skriver til mipd-socket (MIP_FD)
    ssize_t sent = write(MIP_FD, buffer, sizeof(buffer));
    if (sent < 0)
        perror("[MIPTPD] write to mipd");
    else
        printf("[MIPTPD] Sent %zd bytes to mipd (dst=%d)\n", sent, dst_mip);
}

/*
  Bygger og sender en MIPTP-ACK tilbake til avsenderen
  Brukes av mottakeren for å bekrefte mottak av data
*/
void send_miptp_ack(uint8_t dst_mip, uint8_t src_port, uint8_t dst_port, uint16_t seq) {
    size_t pdu_len;
    uint8_t *pdu = build_ack_pdu(src_port, dst_port, seq, &pdu_len); // bare MIPTP-laget

    // send til mipd som UNIX-klient
    send_miptp_pdu(dst_mip, pdu, pdu_len);
    free(pdu); //frigjør buffer

    printf("[MIPTPD] Sent ACK (seq=%u) to MIP %d, port=%d\n", seq, dst_mip, dst_port);
}


/*
  Tar data fra en applikasjon og pakker det inn i en MIPTP PDU.
  Sender deretter PDU-en til mipd for videresending over nettverket.

  Funksjonen håndterer også:
  - Go-Back-N vindustyring
  - Køhåndtering hvis vinduet er fullt
  - Lagring av pakker for eventuell retransmisjon
*/

void send_miptp_data(int app_fd, uint8_t *data, size_t len) {
    printf("[MIPTPD] send_miptp_data() called (fd=%d, len=%zu)\n", app_fd, len);

    if (len < 2) {
        fprintf(stderr, "[MIPTPD] Invalid payload (too short)\n");
        return;
    }

    // ---- Pakker ut felter fra app-meldingen ---
    uint8_t dst_mip  = data[0];  // destinasjons-MIP
    uint8_t dst_port = data[1];  // mottakerens port
    uint8_t *payload = data + 2; // selve nyttelasten
    size_t payload_len = len - 2;

    // ---- Finner avsenderport og connection ---
    uint8_t src_port = get_port_from_fd(app_fd);
    int idx = get_index(app_fd);
    if (idx < 0) return; // ugyldig tilkobling

    app_connection *connection = &app_connections[idx];
    connection->peer_mip = dst_mip; // lagrer mottakerens MIP-adresse, brujes av miptpd_retransmit

    // --- Sjekker at vinduet ikke er fullt -----
    if ((connection->next_seq - connection->base_seq) >= MIPTP_WINDOW_SIZE) {
        // hvis også køen er full, må forbindelsen avsluttes
        if (connection->queue_count >= MIPTP_MAX_QUEUE) {
            fprintf(stderr, "[MIPTPD] Send queue overflow — closing app connection\n");
            remove_app_connection(app_fd);
            return;
        }

        // ellers: legger meldingen i kø til senere sending
        int pos = connection->queue_tail % MIPTP_MAX_QUEUE;
        memcpy(connection->queue[pos].data, data, len);
        connection->queue[pos].len = len;
        connection->queue_tail++;
        connection->queue_count++;

        printf("[MIPTPD][QUEUE] Window full — queued SDU (total queued=%d)\n",
            connection->queue_count);
        return;
    }

    // --- Setter sekvensnummer ----
    uint16_t seq = connection->next_seq;
    connection->next_seq = (connection->next_seq + 1) % MIPTP_MAX_SEQ;

    printf("[MIPTPD] Sending seq=%u from port %d\n", seq, src_port);

    // --- Bygg MIPTP PDU ---
    size_t pdu_len;
    uint8_t *pdu = build_data_pdu(src_port, dst_port, seq, payload, payload_len, &pdu_len);

    // --- Lagrer i sendvinduet for retransmisjon ---
    int slot = seq % MIPTP_WINDOW_SIZE;
    connection->window[slot].seq = seq;
    connection->window[slot].len = pdu_len;
    memcpy(connection->window[slot].data, pdu, pdu_len);
    connection->window[slot].sent_time = time(NULL);
    connection->window[slot].acked = 0;
    connection->window_count++;

    // ----- Sender pdu til mipd -----
    send_miptp_pdu(dst_mip, pdu, pdu_len);
    free(pdu);

    printf("[MIPTPD] Packet queued and sent (dst_mip=%d, seq=%u, len=%zu)\n",
           dst_mip, seq, pdu_len);
}
