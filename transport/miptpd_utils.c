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
#include "miptpd.h"

app_connection app_connections[MAX_APPS] = {0}; //liste over app connections

uint16_t pack_seq_pad(uint16_t seq, uint8_t padlen) {
    return (seq << 2) | (padlen & 0x03);
}

void unpack_seq_pad(uint16_t seq_pad, uint16_t *seq, uint8_t *padlen) {
    *padlen = seq_pad & 0x03;
    *seq = seq_pad >> 2;
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
            app_connections[i].next_seq = 0;
            app_connections[i].last_acked_seq = 0;
            printf("[MIPTPD] Registered app fd=%d on port %d\n", fd, port);

            printf("[DEBUG] Table after adding port %d:\n", port);
            for (int i = 0; i < MAX_APPS; i++)
                if (app_connections[i].app_fd)
                    printf("  [%d] fd=%d port=%d\n", i, app_connections[i].app_fd, app_connections[i].port);

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
            app_connections[i].app_fd = 0;
            app_connections[i].port = 0;
            printf("[MIPTPD] Removed app fd=%d\n", fd);
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
