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

    // --- Sjekk at vinduet ikke er fullt ---
    if ((connection->next_seq - connection->base_seq) >= MIPTP_WINDOW_SIZE) {
        printf("[MIPTPD] Window full for port %d — cannot send yet\n", connection->port);
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
    // Sjekk at vi har nok data til å inneholde minst en MIPTP-header
    if (len < 1 + sizeof(miptp_hdr_t)) {
        fprintf(stderr, "[MIPTPD] Incoming packet too short (%zu bytes)\n", len);
        return;
    }

    printf("[DEBUG][RX<-MIPD] First 10 bytes: ");
    for (size_t i = 0; i < len && i < 10; i++) printf("%02X ", buf[i]);
    printf("\n");

    printf("[DEBUG] Raw incoming MIPTP packet (len=%zu): ", len);
    for (size_t i = 0; i < len; i++) printf("%02X ", buf[i]);
    printf("\n");

    // Pakk ut MIPTP-headeren (starter etter MIP-destinasjonsbyte)
    miptp_hdr_t hdr;
    memcpy(&hdr, buf + 1, sizeof(hdr));

    // Finn peker til payload (SDU) og lengden på den
    uint8_t *payload = buf + 1 + sizeof(hdr);
    size_t payload_len = len - 1 - sizeof(hdr);

    // Hent sekvensnummer og padding fra feltet (14 + 2 bit)
    uint16_t seq;
    uint8_t pad;
    unpack_seq_pad(ntohs(hdr.seq_pad), &seq, &pad);

    printf("[MIPTPD] Got packet from MIP %d, src_port=%d dst_port=%d len=%zu seq=%u pad=%u\n",
           src_mip, hdr.src_port, hdr.dst_port, payload_len, seq, pad);

    // ------------------------------------------
    //  ACK-PDU (ingen payload)
    // ------------------------------------------
    if (payload_len == 0) {
        int fd = get_fd_from_port(hdr.dst_port);
        if (fd >= 0) {
            int idx = get_index(fd);
            if (idx >= 0) {
                app_connection *connection = &app_connections[idx];
                uint16_t ack_seq = seq;

                printf("[MIPTPD] ACK received for seq=%u (port=%d)\n",
                       seq, hdr.dst_port);

                int slot = ack_seq % MIPTP_WINDOW_SIZE;

                if (connection->window[slot].acked) {
                    printf("[DEBUG] Duplicate ACK ignored (seq=%u)\n", ack_seq);
                    return;
                }

                connection->window[slot].acked = 1;

                // Flytt base_seq fremover hvis mulig
                while (connection->base_seq != connection->next_seq &&
                       connection->window[connection->base_seq % MIPTP_WINDOW_SIZE].acked) {
                    connection->base_seq = (connection->base_seq + 1) % MIPTP_MAX_SEQ;
                    connection->window_count--;
                }
                return;
            }
        }

        printf("[MIPTPD] ACK received but no matching connection found (dst_port=%d)\n",
               hdr.dst_port);
        return;
    }

    // ------------------------------------------
    //  DATA-PDU (har payload)
    // ------------------------------------------
    int app_fd = get_fd_from_port(hdr.dst_port);
    if (app_fd < 0) {
        fprintf(stderr, "[MIPTPD] No app registered on port %d\n", hdr.dst_port);
        return;
    }
    if (payload_len >= pad) payload_len -= pad;

    // Lever meldingen til appen (format: [src_mip][src_port][payload])
    uint8_t msg[2 + payload_len];
    msg[0] = src_mip;
    msg[1] = hdr.src_port;
    memcpy(msg + 2, payload, payload_len);

    ssize_t sent = write(app_fd, msg, sizeof(msg));

    // Send ACK tilbake
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
    uint8_t *pdu = build_ack_pdu(src_port, src_port, seq, &pdu_len); // bare MIPTP-laget

    // send til mipd som UNIX-klient
    send_miptp_pdu(dst_mip, pdu, pdu_len);
    free(pdu);

    printf("[MIPTPD] Sent ACK (seq=%u) to MIP %d, port=%d\n", seq, dst_mip, dst_port);
}


