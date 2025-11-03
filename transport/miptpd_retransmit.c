//Håndtering av Go-Back-N, tidsstyring og vindu

/*
**Ansvar:**

- Holde oversikt over sendervinduet (16 pakker)
- Starte og resette timer ved send/ACK
- Gjenutsending av tapte pakker
- Fjerne ACKede pakker fra bufferen

*/

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
    time_t now = time(NULL); // Henter nåværende tid

    for (int i = 0; i < MAX_APPS; i++) { // Går gjennom alle registrerte applikasjoner
        app_connection *connection = &app_connections[i];
        if (connection->app_fd <= 0)
            continue; // Hopper over inaktive forbindelser

        uint16_t base = connection->base_seq;
        if (base == connection->next_seq)
            continue; // Ingen pakker i vinduet akkurat nå

        // Hent første (eldste) pakke i vinduet — kun denne som har aktiv timer
        packet_entry *p = &connection->window[base % MIPTP_WINDOW_SIZE];
        if (p->acked || p->len == 0)
            continue; // Hopper over tom eller allerede ACKet plass

        // Sjekker om timeout har inntruffet (her etter 2 sekunder)
        if (difftime(now, p->sent_time) > 2.0) {
            printf("[MIPTPD][TIMEOUT] base_seq=%u timed out (port=%d) — resending window\n",
                   base, connection->port);

            // Starter retransmisjon fra base_seq til next_seq - 1
            uint16_t seq = base;

            while (seq != connection->next_seq) { // Sender alle pakker i aktivt vindu
                int slot = seq % MIPTP_WINDOW_SIZE;
                packet_entry *r = &connection->window[slot];

                // Sender kun pakker som fortsatt venter på ACK
                if (!r->acked && r->len > 0) {
                    ssize_t resent = write(MIP_FD, r->data, r->len);
                    if (resent > 0) {
                        r->sent_time = now; // Oppdaterer tidspunkt for ny sending
                        printf("[MIPTPD] Resent seq=%u (%zd bytes)\n", seq, resent);
                    }
                }
                // Øker sekvensnummer (med wrap-around)
                seq = (seq + 1) % MIPTP_MAX_SEQ;
            }
        }
    }
}



