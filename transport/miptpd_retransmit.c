

#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "miptpd.h"


//sjekker at pakker som ikke er blitt acked innen en viss tid sendes på nytt
/*
    Sjekker alle aktive forbindelser (app_connections) for
    pakker som ikke har blitt ACKet innen tidsfristen (timeout).
    Dersom den første uackede pakken i vinduet har gått ut på tid,
    utføres Go-Back-N retransmisjon — dvs. alle uackede pakker
    i vinduet sendes på nytt.

    Kalles periodisk fra main-løkken
*/

void check_retransmissions() {
    time_t now = time(NULL);

    for (int i = 0; i < MAX_APPS; i++) {
        app_connection *connection = &app_connections[i];
        if (connection->app_fd <= 0)
            continue;

        uint16_t base = connection->base_seq;
        if (base == connection->next_seq)
            continue; // ingen uackede pakker

        packet_entry *p = &connection->window[base % MIPTP_WINDOW_SIZE];
        if (p->acked || p->len == 0)
            continue;

        if (difftime(now, p->sent_time) > 2.0) {
            printf("[MIPTPD][TIMEOUT] base_seq=%u timed out (port=%d) — resending window\n",
                   base, connection->port);

            uint16_t seq = base;
            while (seq != connection->next_seq) {
                int slot = seq % MIPTP_WINDOW_SIZE;
                packet_entry *r = &connection->window[slot];

                if (!r->acked && r->len > 0) {
                    // ✅ Bruk korrekt funksjon slik at MIP-header legges på
                    send_miptp_pdu(connection->peer_mip, r->data, r->len);
                    r->sent_time = now;
                    printf("[MIPTPD][RTX] Resent seq=%u (%zu bytes) to MIP %u\n",
                           seq, r->len, connection->peer_mip);
                }
                seq = (seq + 1) % MIPTP_MAX_SEQ;
            }
        }
    }
}



