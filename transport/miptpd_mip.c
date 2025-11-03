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

    if (len < 2) {
        fprintf(stderr, "[MIPTPD] Invalid payload (too short)\n");
        return;
    }

    // --- Pakk ut felter fra app-meldingen ---
    uint8_t dst_mip  = data[0];  // destinasjons-MIP
    uint8_t dst_port = data[1];  // mottakerens port
    uint8_t *payload = data + 2; // selve nyttelasten
    size_t payload_len = len - 2;

    // --- Finn avsenderport og connection ---
    uint8_t src_port = get_port_from_fd(app_fd);
    int idx = get_index(app_fd);
    if (idx < 0) return;
    app_connection *connection = &app_connections[idx];
    connection->peer_mip = dst_mip;


    // --- Sjekk at vinduet ikke er fullt ---
    if ((connection->next_seq - connection->base_seq) >= MIPTP_WINDOW_SIZE) {
    if (connection->queue_count >= MIPTP_MAX_QUEUE) {
        fprintf(stderr, "[MIPTPD] Send queue overflow — closing app connection\n");
        close(app_fd);
        return;
    }

    // Legger meldingen i kø
    int pos = connection->queue_tail % MIPTP_MAX_QUEUE;
    memcpy(connection->queue[pos].data, data, len);
    connection->queue[pos].len = len;
    connection->queue_tail++;
    connection->queue_count++;

    printf("[MIPTPD][QUEUE] Window full — queued SDU (total queued=%d)\n",
           connection->queue_count);
    return;
}


    // --- Sett sekvensnummer ---
    uint16_t seq = connection->next_seq;
    connection->next_seq = (connection->next_seq + 1) % MIPTP_MAX_SEQ;

    printf("[MIPTPD] Sending seq=%u from port %d\n", seq, src_port);

    // --- Bygg MIPTP PDU ---
    size_t pdu_len;
    uint8_t *pdu = build_data_pdu(src_port, dst_port, seq, payload, payload_len, &pdu_len);

    // --- Lagre i sendvinduet for retransmisjon ---
    int slot = seq % MIPTP_WINDOW_SIZE;
    connection->window[slot].seq = seq;
    connection->window[slot].len = pdu_len;
    memcpy(connection->window[slot].data, pdu, pdu_len);
    connection->window[slot].sent_time = time(NULL);
    connection->window[slot].acked = 0;
    connection->window_count++;

    // --- Send til mipd ---
    send_miptp_pdu(dst_mip, pdu, pdu_len);
    free(pdu);

    printf("[MIPTPD] Packet queued and sent (dst_mip=%d, seq=%u, len=%zu)\n",
           dst_mip, seq, pdu_len);
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
    if (len < sizeof(miptp_hdr_t)) {
        fprintf(stderr, "[MIPTPD] Incoming packet too short (%zu bytes)\n", len);
        return;
    }

    // Debug print
    printf("[DEBUG][RX<-MIPD] First 10 bytes: ");
    for (size_t i = 0; i < len && i < 10; i++) printf("%02X ", buf[i]);
    printf("\n");

    miptp_hdr_t hdr;
    memcpy(&hdr, buf, sizeof(hdr));

    uint8_t *payload = buf + sizeof(hdr);
    size_t payload_len = len - sizeof(hdr);

    uint16_t seq;
    uint8_t pad;
    unpack_seq_pad(ntohs(hdr.seq_pad), &seq, &pad);

    printf("[MIPTPD] Got packet from MIP %d, src_port=%d dst_port=%d len=%zu seq=%u pad=%u\n",
           src_mip, hdr.src_port, hdr.dst_port, payload_len, seq, pad);

    // =====================================================
    //                  ACK-PDU (ingen payload)
    // =====================================================
    if (payload_len == 0) {
        int fd = get_fd_from_port(hdr.dst_port);
        if (fd < 0) {
            printf("[MIPTPD] ACK for unknown app port=%d (ignored)\n", hdr.dst_port);
            return;
        }

        int idx = get_index(fd);
        if (idx < 0) return;
        app_connection *connection = &app_connections[idx];

        uint16_t ack_seq = seq;
        uint16_t base = connection->base_seq;

        printf("[MIPTPD] ACK received for seq=%u (port=%d)\n", ack_seq, hdr.dst_port);

        // Ignorer ACKer som er for gamle (utenfor vinduet bakover)
        uint16_t diff = (ack_seq + MIPTP_MAX_SEQ - base) % MIPTP_MAX_SEQ;
        if (diff >= MIPTP_WINDOW_SIZE) {
            printf("[MIPTPD][GBN] Ignored stale ACK (ack=%u base=%u)\n", ack_seq, base);
            return;
        }

        // Gyldig ACK -> flytt base_seq frem til ack_seq + 1
        uint16_t old_base = connection->base_seq;
        connection->base_seq = (ack_seq + 1) % MIPTP_MAX_SEQ;
        printf("[MIPTPD][GBN] base_seq advanced %u → %u\n", old_base, connection->base_seq);

        // Fjern ackede pakker fra bufferet
        for (uint16_t s = old_base; s != connection->base_seq; s = (s + 1) % MIPTP_MAX_SEQ) {
            int slot = s % MIPTP_WINDOW_SIZE;
            connection->window[slot].acked = 1;
            connection->window[slot].len = 0;
        }

        // Send køede meldinger om det er plass i vinduet
        while (connection->queue_count > 0 &&
              ((connection->next_seq + MIPTP_MAX_SEQ - connection->base_seq) % MIPTP_MAX_SEQ) < MIPTP_WINDOW_SIZE) {

            int pos = connection->queue_head % MIPTP_MAX_QUEUE;
            uint8_t *next_data = connection->queue[pos].data;
            size_t next_len = connection->queue[pos].len;

            printf("[MIPTPD][QUEUE] Sending queued packet (remaining=%d)\n",
                   connection->queue_count - 1);

            send_miptp_data(connection->app_fd, next_data, next_len);

            connection->queue_head++;
            connection->queue_count--;
        }

        // Logging for status
        if (connection->base_seq == connection->next_seq)
            printf("[MIPTPD][GBN] ✅ All packets ACKed — window empty\n");
        else
            printf("[MIPTPD][GBN] Waiting for more ACKs (base=%u, next=%u)\n",
                   connection->base_seq, connection->next_seq);
        return;
    }

    // =====================================================
    //                  DATA-PDU (har payload)
    // =====================================================
    int app_fd = get_fd_from_port(hdr.dst_port);
    if (app_fd < 0) {
        fprintf(stderr, "[MIPTPD] No app registered on port %d\n", hdr.dst_port);
        return;
    }

    int idx = get_index(app_fd);
    if (idx < 0) return;
    app_connection *connection = &app_connections[idx];

    if (!connection->synced) {
        connection->expected_seq = (seq + 1) % MIPTP_MAX_SEQ;
        connection->synced = 1;
        printf("[MIPTPD][INIT] First packet seq=%u → expected_seq=%u\n",
               seq, connection->expected_seq);
    }

    uint16_t expected = connection->expected_seq;
    uint16_t ahead = (seq + MIPTP_MAX_SEQ - expected) % MIPTP_MAX_SEQ;

    // For gamle pakker (duplikater)
    if (ahead >= MIPTP_MAX_SEQ - MIPTP_WINDOW_SIZE) {
        printf("[MIPTPD][RX] Duplicate DATA ignored (seq=%u expected=%u)\n", seq, expected);
        send_miptp_ack(src_mip, hdr.dst_port, hdr.src_port,
                       (expected - 1 + MIPTP_MAX_SEQ) % MIPTP_MAX_SEQ);
        return;
    }

    // Hvis ikke in-order: ignorer (ingen buffering)
    if (seq != expected) {
        printf("[MIPTPD][RX] Out-of-order DATA ignored (seq=%u expected=%u)\n", seq, expected);
        send_miptp_ack(src_mip, hdr.dst_port, hdr.src_port,
                       (expected - 1 + MIPTP_MAX_SEQ) % MIPTP_MAX_SEQ);
        return;
    }

    // In-order → lever til appen
    if (payload_len >= pad) payload_len -= pad;
    uint8_t msg[2 + payload_len];
    msg[0] = src_mip;
    msg[1] = hdr.src_port;
    memcpy(msg + 2, payload, payload_len);

    ssize_t sent = write(app_fd, msg, sizeof(msg));
    if (sent > 0)
        printf("[MIPTPD] Delivered %zd bytes to app port %d (fd=%d)\n", sent, hdr.dst_port, app_fd);
    else
        perror("[MIPTPD] write to app failed");

    connection->expected_seq = (seq + 1) % MIPTP_MAX_SEQ;
    send_miptp_ack(src_mip, hdr.dst_port, hdr.src_port, seq);
}


uint8_t *build_data_pdu(uint8_t src_port, uint8_t dst_port,
                        uint16_t seq, const uint8_t *sdu, size_t sdu_len,
                        size_t *out_len)
{
    // Finn hvor mange bytes som må til for 32-bit alignment
    uint8_t padlen = (4 - ((sizeof(miptp_hdr_t) + sdu_len) % 4)) % 4;

    // Alloker buffer: header + SDU + pad
    size_t total = sizeof(miptp_hdr_t) + sdu_len + padlen;
    uint8_t *buf = malloc(total);
    if (!buf) {
        perror("malloc build_data_pdu");
        exit(EXIT_FAILURE);
    }

    miptp_hdr_t hdr;
    hdr.src_port = src_port;
    hdr.dst_port = dst_port;
    hdr.seq_pad  = htons(pack_seq_pad(seq, padlen)); // packer 14-bit seq + 2-bit padlen

    memcpy(buf, &hdr, sizeof(hdr));

    if (sdu_len > 0)
        memcpy(buf + sizeof(hdr), sdu, sdu_len);

    if (padlen > 0)
        memset(buf + sizeof(hdr) + sdu_len, 0, padlen);

    if (out_len) *out_len = total;
    return buf;
}

uint8_t *build_ack_pdu(uint8_t src_port, uint8_t dst_port,
                       uint16_t seq, size_t *out_len)
{
    uint8_t padlen = (4 - (sizeof(miptp_hdr_t) % 4)) % 4;

    size_t total = sizeof(miptp_hdr_t) + padlen;
    uint8_t *buf = malloc(total);
    if (!buf) { perror("malloc build_ack_pdu"); exit(EXIT_FAILURE); }

    miptp_hdr_t hdr;
    hdr.src_port = src_port;
    hdr.dst_port = dst_port;
    hdr.seq_pad  = htons(pack_seq_pad(seq, padlen));

    memcpy(buf, &hdr, sizeof(hdr));
    if (padlen > 0) memset(buf + sizeof(hdr), 0, padlen);

    if (out_len) *out_len = total;
    return buf;
}

void send_miptp_pdu(uint8_t dst_mip, uint8_t *miptp_pdu, size_t pdu_len) {
    uint8_t ttl = 10; // kan være standard
    uint8_t buffer[2 + pdu_len];

    buffer[0] = dst_mip; // destinasjons-MIP, mipd bruker denne for routing
    buffer[1] = ttl;     // TTL-felt som mipd legger i MIP-headeren
    memcpy(buffer + 2, miptp_pdu, pdu_len);

    ssize_t sent = write(MIP_FD, buffer, sizeof(buffer));
    if (sent < 0)
        perror("[MIPTPD] write to mipd");
    else
        printf("[MIPTPD] Sent %zd bytes to mipd (dst=%d)\n", sent, dst_mip);
}

/*
  Sender en MIPTP-ACK tilbake til avsender.

*/

void send_miptp_ack(uint8_t dst_mip, uint8_t src_port, uint8_t dst_port, uint16_t seq) {
    size_t pdu_len;
    uint8_t *pdu = build_ack_pdu(src_port, dst_port, seq, &pdu_len); // bare MIPTP-laget

    // send til mipd som UNIX-klient
    send_miptp_pdu(dst_mip, pdu, pdu_len);
    free(pdu);

    printf("[MIPTPD] Sent ACK (seq=%u) to MIP %d, port=%d\n", seq, dst_mip, dst_port);
}


