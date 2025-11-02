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

// void init_retransmission_state();
// void check_retransmissions();
// void on_ack_received(uint16_t ack_seq);
// void buffer_outgoing_packet();

//sjekker at pakker som ikke er blitt acked innen en viss tid sendes på nytt
/*
    Henter nåværende tidspunkt
    Går gjennom alle registrerte app-forbindelser
    Går gjennom hver pakke i appens sendebuffer
    Sjekker om pakken er uackede og har “timed out” (>2 sekunder)
    Logger timeout og sender pakken på nytt
    Oppdaterer sent_time
*/
//bruker MIP_FD som global variabel
void check_retransmissions() {
    time_t now = time(NULL); //henter nåværende tid

    for (int i = 0; i < MAX_APPS; i++) { // går igjennom alle registrerte applikajsoner
        app_connection *connection = &app_connections[i];
        if (connection->app_fd <= 0) continue;

        for (int j = 0; j < MIPTP_WINDOW_SIZE; j++) { //går igjennom alle pakker i vinduet for hver applikasjons forbindelse
            packet_entry *p = &connection->window[j]; //peker til packet entry, holder på seq, data, sent_time og acked

            // Hopper over tomme eller allerede ACKede pakker
            if (p->acked || p->len == 0)
                continue;

            // Timeout på første uackede pakke - Go back N-resend
            if (difftime(now, p->sent_time) > 2.0) { // Sjekker om det har gått mer enn 2 sekunder siden den ble sendt
                printf("[MIPTPD] Timeout on seq=%u (port=%d) — resending window...\n",
                       p->seq, connection->port);
                // Resender alle pakker fra base_seq til next_seq-1 når en timeout oppstår

                // Starter fra første uackede pakke (vindusstart)
                uint16_t seq = connection->base_seq;

                while (seq != connection->next_seq) { // sender så lenge man er innen det aktive vinduet

                    int slot = seq % MIPTP_WINDOW_SIZE; //finner bufferplass, sirkulær index i vinduet
                    packet_entry *r = &connection->window[slot]; // peker til pakken vi jobber med i vinduet

                    if (!r->acked && r->len > 0) { //hvis pakken fortsatt avventer ack + er gyldig

                        ssize_t resent = write(MIP_FD, r->data, r->len);
                        if (resent > 0) {
                            r->sent_time = now; //oppdatterer tidspunkt
                            printf("[MIPTPD] Resent seq=%u (%zd bytes)\n", seq, resent);
                        }
                    }
                    seq = (seq + 1) % MIPTP_MAX_SEQ; //øker sekvensnummer med wrap around mod, sirkulært vindu
                }

                break; // Kun én timeout-runde per sjekk
            }
        }
    }
}

// // Fra miptp_retransmit.c
// void check_retransmissions(void);


