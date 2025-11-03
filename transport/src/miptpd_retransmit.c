/*
 *  Ansvar:
 *  - Overvåke alle aktive forbindelser og håndtere retransmisjon
 *    ved Go-Back-N timeout
 *  - Sikre pålitelig levering ved å sende uackede pakker på nytt
 *    dersom tidsfristen overskrides
 *  - Kalles periodisk fra main-løkken i MIPTP-daemonen
 */

#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "miptpd_retransmit.h"


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
    time_t now = time(NULL); // henter nåværende tidspunkt

    for (int i = 0; i < MAX_APPS; i++) {
        app_connection *connection = &app_connections[i];
        if (connection->app_fd <= 0)
            continue; //hopper over inaktive forbindelser

        uint16_t base = connection->base_seq;
        if (base == connection->next_seq)
            continue; // ingen uackede pakker

        // henter den eldste pakken i vinduet
        packet_entry *p = &connection->window[base % MIPTP_WINDOW_SIZE];
        if (p->acked || p->len == 0)
            continue; // hopper over tomme eller ackede plasser i vinduet

        // sjekker for timeout (2 sek) har utløpt
        if (difftime(now, p->sent_time) > 2.0) {
            printf("[MIPTPD][TIMEOUT] base_seq=%u timed out (port=%d) — resending window\n",
                   base, connection->port);

            uint16_t seq = base; //starter fra første uackede pakke
            while (seq != connection->next_seq) { // går igjennom hele vinduet
                int slot = seq % MIPTP_WINDOW_SIZE;
                packet_entry *r = &connection->window[slot];

                //sender kun pakket som ikke har fått ack og har gyldoig data
                if (!r->acked && r->len > 0) {
                    // Bruker funksjoner slik at MIP-header legges på
                    send_miptp_pdu(connection->peer_mip, r->data, r->len);

                    r->sent_time = now; //oppdatter tid for sending

                    printf("[MIPTPD][RTX] Resent seq=%u (%zu bytes) to MIP %u\n",
                           seq, r->len, connection->peer_mip);
                }
                //øker sekvensnummer, wrap around ved maksverdi
                seq = (seq + 1) % MIPTP_MAX_SEQ;
            }
        }
    }
}



