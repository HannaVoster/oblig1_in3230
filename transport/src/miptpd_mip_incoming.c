// kommunikasjon med MIP-daemon
//grensesnitt mot MIP deamon, nederste lag, under

/*
**Ansvar:**

- Kommunisere via UNIX-socket med `mipd`
- Pakke ut og tolke MIPTP-header
- Dele opp logikken mellom “data” og “ACK”-pakker

*/
#include "miptpd_incoming.h"
#include "miptpd_utils.h"   
#include "miptpd_send.h" 

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>


void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip) {
    if (len < sizeof(miptp_hdr_t)) {
        fprintf(stderr, "[MIPTPD] Incoming packet too short (%zu bytes)\n", len);
        return;
    }
    // --- Debug & header parsing ---
    miptp_hdr_t hdr;
    memcpy(&hdr, buf, sizeof(hdr));
    uint8_t *payload = buf + sizeof(hdr);
    size_t payload_len = len - sizeof(hdr);

    uint16_t seq; uint8_t pad;
    unpack_seq_pad(ntohs(hdr.seq_pad), &seq, &pad);

    printf("[MIPTPD] Got packet from MIP %d, src_port=%d dst_port=%d len=%zu seq=%u pad=%u\n",
           src_mip, hdr.src_port, hdr.dst_port, payload_len, seq, pad);

    // --- Skille mellom ACK og DATA ---
    if (payload_len == 0)
        handle_incoming_ack(&hdr, seq, src_mip);
    else
        handle_incoming_data(&hdr, payload, payload_len, seq, pad, src_mip);
}


void handle_incoming_ack(miptp_hdr_t *hdr, uint16_t seq, uint8_t src_mip) {
    int fd = get_fd_from_port(hdr->dst_port);
    if (fd < 0) {
        printf("[MIPTPD] ACK for unknown app port=%d ignored\n", hdr->dst_port);
        return;
    }

    int idx = get_index(fd);
    if (idx < 0) return;
    app_connection *conn = &app_connections[idx];

    printf("[MIPTPD] ACK received for seq=%u (port=%d)\n", seq, hdr->dst_port);

    uint16_t diff = (seq + MIPTP_MAX_SEQ - conn->base_seq) % MIPTP_MAX_SEQ;
    if (diff >= MIPTP_WINDOW_SIZE) {
        printf("[MIPTPD][GBN] Ignored stale ACK (ack=%u base=%u)\n", seq, conn->base_seq);
        return;
    }

    // Flytt base frem til ack_seq + 1
    uint16_t old_base = conn->base_seq;
    conn->base_seq = (seq + 1) % MIPTP_MAX_SEQ;

    for (uint16_t s = old_base; s != conn->base_seq; s = (s + 1) % MIPTP_MAX_SEQ) {
        int slot = s % MIPTP_WINDOW_SIZE;
        conn->window[slot].acked = 1;
        conn->window[slot].len = 0;
    }

    // Send køede meldinger hvis plass i vinduet
    while (conn->queue_count > 0 &&
          ((conn->next_seq + MIPTP_MAX_SEQ - conn->base_seq) % MIPTP_MAX_SEQ) < MIPTP_WINDOW_SIZE) {
        int pos = conn->queue_head % MIPTP_MAX_QUEUE;
        send_miptp_data(conn->app_fd, conn->queue[pos].data, conn->queue[pos].len);
        conn->queue_head++;
        conn->queue_count--;
    }

    if (conn->base_seq == conn->next_seq)
        printf("[MIPTPD][GBN] All packets ACKed — window empty\n");
    else
        printf("[MIPTPD][GBN] Waiting for more ACKs (base=%u next=%u)\n",
               conn->base_seq, conn->next_seq);
}


void handle_incoming_data(miptp_hdr_t *hdr, uint8_t *payload, size_t len,
                          uint16_t seq, uint8_t pad, uint8_t src_mip) {
    int app_fd = get_fd_from_port(hdr->dst_port);
    if (app_fd < 0) {
        fprintf(stderr, "[MIPTPD] No app registered on port %d\n", hdr->dst_port);
        return;
    }

    int idx = get_index(app_fd);
    if (idx < 0) return;
    app_connection *conn = &app_connections[idx];

    if (!conn->synced) {
        conn->expected_seq = (seq + 1) % MIPTP_MAX_SEQ;
        conn->synced = 1;
        printf("[MIPTPD][INIT] First packet seq=%u → expected_seq=%u\n",
               seq, conn->expected_seq);
    }

    uint16_t expected = conn->expected_seq;
    uint16_t ahead = (seq + MIPTP_MAX_SEQ - expected) % MIPTP_MAX_SEQ;

    // Duplikat?
    if (ahead >= MIPTP_MAX_SEQ - MIPTP_WINDOW_SIZE) {
        printf("[MIPTPD][RX] Duplicate DATA ignored (seq=%u expected=%u)\n", seq, expected);
        send_miptp_ack(src_mip, hdr->dst_port, hdr->src_port,
                       (expected - 1 + MIPTP_MAX_SEQ) % MIPTP_MAX_SEQ);
        return;
    }

    // Out-of-order?
    if (seq != expected) {
        printf("[MIPTPD][RX] Out-of-order DATA ignored (seq=%u expected=%u)\n", seq, expected);
        send_miptp_ack(src_mip, hdr->dst_port, hdr->src_port,
                       (expected - 1 + MIPTP_MAX_SEQ) % MIPTP_MAX_SEQ);
        return;
    }

    // In-order: lever til app
    if (len >= pad) len -= pad; // fjern padding
    uint8_t msg[2 + len];
    msg[0] = src_mip;
    msg[1] = hdr->src_port;
    memcpy(msg + 2, payload, len);

    ssize_t sent = write(app_fd, msg, sizeof(msg));
    if (sent > 0)
        printf("[MIPTPD] Delivered %zd bytes to app port %d (fd=%d)\n", sent, hdr->dst_port, app_fd);
    else
        perror("[MIPTPD] write to app failed");

    conn->expected_seq = (seq + 1) % MIPTP_MAX_SEQ;
    send_miptp_ack(src_mip, hdr->dst_port, hdr->src_port, seq);
}

