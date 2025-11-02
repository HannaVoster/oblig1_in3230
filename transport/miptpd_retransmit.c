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


//bruker MIP_FD som global variabel
void check_retransmissions(){
    // Etter for-løkken som håndterer epoll events
    time_t now = time(NULL);

    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].waiting_for_ack &&
            difftime(now, app_connections[i].last_sent_time) > 2.0) {

            printf("[MIPTPD] Timeout — resending packet for port %d (fd=%d)\n",
                app_connections[i].port, app_connections[i].app_fd);

            ssize_t resent = write(MIP_FD, app_connections[i].last_packet,
                                app_connections[i].last_len);
            if (resent > 0) {
                app_connections[i].last_sent_time = now;
                printf("[MIPTPD] Resent %zd bytes for port %d\n",
                    resent, app_connections[i].port);
            } else {
                perror("[MIPTPD] Retransmission failed");
            }
        }
    }
}
// // Fra miptp_retransmit.c
// void check_retransmissions(void);