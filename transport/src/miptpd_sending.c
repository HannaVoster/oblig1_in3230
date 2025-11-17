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
    uint8_t ttl = 10; 
    uint8_t buffer[2 + pdu_len];

    buffer[0] = dst_mip; // destinasjons-MIP, mipd bruker denne for routing
    buffer[1] = ttl;     // TTL-felt som mipd legger i MIP-headeren
    memcpy(buffer + 2, miptp_pdu, pdu_len); //selve pdu data


    // skriver til mipd-socket (MIP_FD)
    ssize_t sent = write(MIP_FD, buffer, 2 + pdu_len);

    if (sent < 0)
        perror("[MIPTPD] write to mipd");
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

    if(debug_mode) printf("[MIPTPD][ACK] seq=%u to %d:%d\n", seq, dst_mip, dst_port);

}


/*
  Tar data fra en applikasjon og pakker det inn i en MIPTP PDU.
  Sender deretter PDU-en til mipd for videresending over nettverket.

  Funksjonen håndterer også:
  - Go-Back-N vindustyring
  - Køhåndtering hvis vinduet er fullt
  - Lagring av pakker for eventuell retransmisjon
*/

void send_miptp_data(int app_fd, uint8_t *data, size_t len)
{
    uint8_t dst_mip  = data[0];
    uint8_t dst_port = data[1];
    uint8_t *payload = data + 2;
    size_t payload_len = len - 2;

    int idx = get_index(app_fd);
    if (idx < 0) return;

    app_connection *appc = &app_connections[idx];

    outbound_transfer_state *t =
        find_or_create_outbound(appc, dst_mip, dst_port);

    if (!t) return;

    // --- Window full → queue ---
    if ((t->next_seq - t->base_seq) >= MIPTP_WINDOW_SIZE) {

        if (t->queue_count >= MIPTP_MAX_QUEUE) {
            fprintf(stderr, "[MIPTPD] outbound queue overflow!\n");
            return;
        }

        int pos = t->queue_tail % MIPTP_MAX_QUEUE;
        memcpy(t->queue[pos].data, payload, payload_len);
        t->queue[pos].len = payload_len;
        t->queue_tail++;
        t->queue_count++;

        if(debug_mode) printf("[MIPTPD][QUEUE] Outbound SDU queued (%u:%u)\n", dst_mip, dst_port);
        return;
    }

    send_miptp_data_on_transfer(appc, t, payload, payload_len);
}

void send_miptp_data_on_transfer(app_connection *appc,
                                 outbound_transfer_state *t,
                                 uint8_t *payload,
                                 size_t payload_len)
{
    uint8_t dst_mip  = t->dst_mip;
    uint8_t dst_port = t->dst_port;
    uint8_t src_port = appc->port;

    // vindu fullt bør aldri skje
    if ((t->next_seq - t->base_seq) >= MIPTP_WINDOW_SIZE) {
        printf("[MIPTPD][BUG] send_miptp_data_on_transfer() called but window full!\n");
        return;
    }

    uint16_t seq = t->next_seq;
    t->next_seq = (t->next_seq + 1) % MIPTP_MAX_SEQ;

    size_t pdu_len;
    uint8_t *pdu =
        build_data_pdu(src_port, dst_port, seq, payload, payload_len, &pdu_len);

    int slot = seq % MIPTP_WINDOW_SIZE;
    t->window[slot].seq = seq;
    t->window[slot].len = pdu_len;
    memcpy(t->window[slot].data, pdu, pdu_len);
    t->window[slot].acked = 0;
    t->window[slot].sent_time = time(NULL);
    t->window_count++;

    if(debug_mode) printf("[MIPTPD][SEND] seq=%u → %d:%d (%zu bytes, slot=%d)\n",
       seq, dst_mip, dst_port, payload_len, slot);


    send_miptp_pdu(dst_mip, pdu, pdu_len);
    free(pdu);
}
