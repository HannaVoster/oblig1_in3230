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
#include "miptpd_send.h"

/*
    Sjekker alle aktive forbindelser (app_connections) for
    pakker som ikke har blitt ACKet innen tidsfristen (timeout).
    Dersom den første uackede pakken i vinduet har gått ut på tid,
    utføres Go-Back-N retransmisjon — dvs. alle uackede pakker
    i vinduet sendes på nytt.

    Kalles periodisk fra main-løkken
*/

void check_retransmissions()
{
    time_t now = time(NULL);

    for (int i = 0; i < MAX_APPS; i++) {
        app_connection *appc = &app_connections[i];
        if (appc->app_fd <= 0)
            continue;

        // Gå gjennom ALLE outbound-transfers
        for (int t_i = 0; t_i < appc->outbound_count; t_i++) {

            outbound_transfer_state *t = &appc->outbound[t_i];

            uint16_t base = t->base_seq;

            // ingen u-ACKede pakker
            if (t->next_seq == base)
                continue;

            // henert første uackede pakke
            packet_entry *p = &t->window[base % MIPTP_WINDOW_SIZE];

            if (p->acked || p->len == 0)
                continue;

            // sjekker timeout (200 ms)
            if (difftime(now, p->sent_time) > 0.2) {

                printf("[MIPTPD][TIMEOUT] Transfer %u:%u base=%u timed out → RTX\n",
                       t->dst_mip, t->dst_port, base);

                uint16_t seq = base;

                // resend alle uackede i vinduet
                while (seq != t->next_seq) {

                    int slot = seq % MIPTP_WINDOW_SIZE;
                    packet_entry *r = &t->window[slot];

                    if (!r->acked && r->len > 0) {

                        send_miptp_pdu(t->dst_mip, r->data, r->len);
                        r->sent_time = now;

                        printf("[MIPTPD][RTX] resent seq=%u (%zu B) → %u:%u\n",
                               seq, r->len,
                               t->dst_mip, t->dst_port);
                    }

                    seq = (seq + 1) % MIPTP_MAX_SEQ;
                }
            }
        }
    }
}




