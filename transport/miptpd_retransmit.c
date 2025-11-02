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
            packet_entry *p = &connection->window[j]; //packet entry, holder på seq, data, sent_time og acked

            //betingelse for retransmisjon. sjekker:
                // er pakken ikke bekreftet med ack
                // er det data her, det vil si er slot in use
                // har det gått mer enn to sekunder
            if (!p->acked && p->len > 0 && difftime(now, p->sent_time) > 2.0) { //betingelse for retransmisjon
                printf("[MIPTPD] Timeout — resending seq=%u port=%d\n",
                       p->seq, connection->port);
                ssize_t resent = write(MIP_FD, p->data, p->len); //sender hele pakken på nytt ut på mip laget
                if (resent > 0)
                    p->sent_time = now; //setter ny tid hvis sendingen var vellykket
            }
        }
    }
}

// // Fra miptp_retransmit.c
// void check_retransmissions(void);