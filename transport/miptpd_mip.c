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
    // Sjekk at vi har nok data til å inneholde minst en MIPTP-header
    if (len < sizeof(miptp_hdr_t)) {
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
    memcpy(&hdr, buf, sizeof(hdr));

    // Finn peker til payload (SDU) og lengden på den
    uint8_t *payload = buf + sizeof(hdr);
    size_t payload_len = len - sizeof(hdr);

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

                //Sjekker for out of window pakker
                // Hvispakker er for gamle eller for langt fremme
                //beskytter mot duplikater eller uventede acks
                uint16_t base = connection->base_seq;
                uint16_t next = connection->next_seq;

                // Beregner "avstand" mellom to sekvensnumre i 14-bit-verden
                int16_t diff_base_ack = (int16_t)((ack_seq - base + MIPTP_MAX_SEQ) % MIPTP_MAX_SEQ);
                int16_t diff_ack_next = (int16_t)((next - ack_seq + MIPTP_MAX_SEQ) % MIPTP_MAX_SEQ);

                // Hvis ack_seq er for gammel eller for langt fremme -> ignorer
                if (diff_base_ack < 0 || diff_ack_next <= 0 || diff_base_ack >= MIPTP_WINDOW_SIZE) {
                    printf("[MIPTPD][GBN] Ignored out-of-window ACK (seq=%u base=%u next=%u)\n",
                        ack_seq, base, next);
                    return;
                }

                //--ACK gyldig --
                int slot = ack_seq % MIPTP_WINDOW_SIZE;

                if (connection->window[slot].acked) {
                    printf("[DEBUG] Duplicate ACK ignored (seq=%u)\n", ack_seq);
                    return;
                }

                connection->window[slot].acked = 1;

                // Flytt base_seq fremover hvis mulig
                // Flytt base_seq fremover hvis mulig
                while (connection->base_seq != connection->next_seq &&
                    connection->window[connection->base_seq % MIPTP_WINDOW_SIZE].acked) {

                    connection->base_seq = (connection->base_seq + 1) % MIPTP_MAX_SEQ;
                    if (connection->window_count > 0) connection->window_count--;

                    printf("[MIPTPD][GBN] base_seq advanced to %u\n", connection->base_seq);
                }

                // Etter at base_seq er flyttet frem, se om vi har plass i vinduet
                while (connection->queue_count > 0 &&
                    (connection->next_seq - connection->base_seq) < MIPTP_WINDOW_SIZE) {

                    int pos = connection->queue_head % MIPTP_MAX_QUEUE;
                    uint8_t *next_data = connection->queue[pos].data;
                    size_t next_len = connection->queue[pos].len;

                    printf("[MIPTPD][QUEUE] Sending queued packet (remaining=%d)\n",
                        connection->queue_count - 1);

                    // Bruker eksisterende app_fd fra denne connection
                    send_miptp_data(connection->app_fd, next_data, next_len);

                    connection->queue_head++;
                    connection->queue_count--;
                }

                // Hvis alt er ACKet
                if (connection->base_seq == connection->next_seq) {
                    printf("[MIPTPD][GBN] ✅ All packets ACKed — window now empty (base_seq=%u)\n",
                        connection->base_seq);
                } else {
                    printf("[MIPTPD][GBN] Waiting for more ACKs (base_seq=%u, next_seq=%u)\n",
                        connection->base_seq, connection->next_seq);
                }
                if (connection->queue_count == 0)
                printf("[MIPTPD][QUEUE] ✅ Queue empty — all queued SDUs sent.\n");

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

    int idx = get_index(app_fd);
    if (idx >= 0) {
        app_connection *connection = &app_connections[idx];
        uint16_t expected = connection->expected_seq;   // neste sekvens vi venter på
        uint16_t max_accept = (expected + MIPTP_WINDOW_SIZE) % MIPTP_MAX_SEQ;

        // Beregner "avstand" mellom seq og expected i 14-bit-verden
        int16_t diff_seq_exp = (int16_t)((seq - expected + MIPTP_MAX_SEQ) % MIPTP_MAX_SEQ);

        // CASE 1: Pakke er gammel (duplikat)
        if (diff_seq_exp < 0) {
            printf("[MIPTPD][RX] Duplicate or old DATA packet ignored (seq=%u expected=%u)\n",
                seq, expected);
            // Send ACK igjen slik at sender vet vi allerede har denne
            // acker den siste gyldige pakken
            send_miptp_ack(src_mip, hdr.dst_port, hdr.src_port, 
               (expected - 1 + MIPTP_MAX_SEQ) % MIPTP_MAX_SEQ);
            return;
        }

        // CASE 2: Pakke er utenfor mottaksvinduet (for langt frem)
        if (diff_seq_exp >= MIPTP_WINDOW_SIZE) {
            printf("[MIPTPD][RX] Out-of-window DATA ignored (seq=%u expected=%u)\n",
                seq, expected);
            return;
        }
    }
    // Gyldig pakke innenfor mottaksvinduet — sjekk om den er in-order
    if (payload_len >= pad) payload_len -= pad;

    // Etter levering: finn connection for å oppdatere expected_seq
    int idx2 = get_index(app_fd);
    if (idx2 >= 0) {
        app_connection *connection = &app_connections[idx2];

        if (seq == connection->expected_seq) {
            // --- IN-ORDER pakke ---
            // Lever meldingen til appen (format: [src_mip][src_port][payload])
            uint8_t msg[2 + payload_len];
            msg[0] = src_mip;
            msg[1] = hdr.src_port;
            memcpy(msg + 2, payload, payload_len);

            ssize_t sent = write(app_fd, msg, sizeof(msg));

            // Oppdater forventet sekvensnummer (venter nå på neste)
            connection->expected_seq = (seq + 1) % MIPTP_MAX_SEQ;

            // Send ACK tilbake for denne pakken
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

        } else {
            // --- OUT-OF-ORDER pakke ---
            printf("[MIPTPD][RX] Out-of-order packet (seq=%u expected=%u) ignored.\n",
                seq, connection->expected_seq);

            // Send ACK for forrige korrekt mottatte pakke
            send_miptp_ack(src_mip, hdr.dst_port, hdr.src_port,
                        (connection->expected_seq - 1 + MIPTP_MAX_SEQ) % MIPTP_MAX_SEQ);
            return;
        }
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
    uint8_t *pdu = build_ack_pdu(src_port, dst_port, seq, &pdu_len); // bare MIPTP-laget

    // send til mipd som UNIX-klient
    send_miptp_pdu(dst_mip, pdu, pdu_len);
    free(pdu);

    printf("[MIPTPD] Sent ACK (seq=%u) to MIP %d, port=%d\n", seq, dst_mip, dst_port);
}


