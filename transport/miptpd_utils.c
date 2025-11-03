// hjelpemetoder (sekvensnummer, padding, logging)

/*
**Ansvar:**

- Sekvensnummer-logikk (inkl. wrap-around)
- Paddingberegning (for 32-bit justering)
- Logging/debug-print
- Generelle verktøy som brukes av flere filer
*/

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "miptpd.h"

app_connection app_connections[MAX_APPS] = {0}; //liste over app connections

// 16 bits total: [type(2 bits)][sequence(14 bits)]
uint16_t pack_seq_pad(uint16_t seq, uint8_t type) {
    // type legges i de to høyeste bitene
    return ((type & 0x03) << 14) | (seq & 0x3FFF);
}

void unpack_seq_pad(uint16_t seq_pad, uint16_t *seq, uint8_t *type) {
    *type = (seq_pad >> 14) & 0x03;   // hent de to øverste bitene
    *seq  = seq_pad & 0x3FFF;         // hent de nederste 14 bitene
}


/*
  Registrerer en ny applikasjon i tabellen
  Returnerer 0 ved suksess, -1 hvis tabellen er full
*/
int new_app_connection(int fd, uint8_t port) {
    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].app_fd == 0) {
            app_connections[i].app_fd = fd;
            app_connections[i].port = port;

            // Initialiser Go-Back-N tilstand
            app_connections[i].base_seq = rand() % MIPTP_MAX_SEQ; // starter med tilfeldig sekvensnummer
            app_connections[i].next_seq = app_connections[i].base_seq;
            app_connections[i].window_count = 0;

            // Nullstill vinduet
            for (int j = 0; j < MIPTP_WINDOW_SIZE; j++) {
                app_connections[i].window[j].acked = 1; // tom plass
                app_connections[i].window[j].len = 0;
            }

            printf("[MIPTPD] Registered app fd=%d on port %d (seq start=%u)\n",
                   fd, port, app_connections[i].base_seq);

            return 0;
        }
    }

    fprintf(stderr, "[MIPTPD] Connection table full, could not register app fd=%d\n", fd);
    return -1;
}


/*
  Fjerner en app fra tabellen når socketen lukkes
 */
int remove_app_connection(int fd) {
    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].app_fd == fd) {
            printf("[MIPTPD] Removed app fd=%d\n", fd);
            // Nullstill hele strukturen
            memset(&app_connections[i], 0, sizeof(app_connection));
            return 0;
        }
    }
    return -1;
}

/*
  Henter portnummeret for en gitt app_fd
  Returnerer 0 hvis ikke funnet (0 er reservert/ugyldig port)
 */
uint8_t get_port_from_fd(int fd) {
    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].app_fd == fd)
            return app_connections[i].port;
    }
    fprintf(stderr, "[MIPTPD] No port found for fd=%d\n", fd);
    return 0;
}

/*
  Henter filbeskrivelsen (app_fd) for en gitt port
  Returnerer -1 hvis ingen app er registrert på den porten
 */
int get_fd_from_port(uint8_t port) {
    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].port == port)
            return app_connections[i].app_fd;
    }
    fprintf(stderr, "[MIPTPD] No app found for port=%d\n", port);
    return -1;
}

// uint16_t pack_seq_pad(uint16_t seq, uint8_t padlen);
// void unpack_seq_pad(uint16_t seq_pad, uint16_t *seq, uint8_t *padlen);
// uint8_t calc_padding(size_t sdu_len);
// int seq_less(uint16_t a, uint16_t b);

int get_index(int fd){
    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].app_fd == fd)
            return i;
    }
    fprintf(stderr, "[MIPTPD] No index found for fd=%d\n", fd);
    return -1;
}

uint16_t get_next_seq(int fd) {
    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].app_fd == fd) {
            return app_connections[i].next_seq++;
        }
    }
    return 0;
}

// void update_last_packet_from_fd(int fd, uint8_t *packet, ssize_t len) {
//     for (int i = 0; i < MAX_APPS; i++) {
//         if (app_connections[i].app_fd == fd){
//             memcpy(app_connections[i].last_packet, packet, len);
//             app_connections[i].last_len = len;
//             app_connections[i].last_sent_time = time(NULL);
//             app_connections[i].waiting_for_ack = 1;
//             return;
//         }   
//     }
//     fprintf(stderr, "[MIPTPD] No connection found for fd=%d (update_last_packet_from_fd)\n", fd);
//     return;
// }
