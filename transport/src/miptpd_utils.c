
/*
Ansvar:
- Sekvensnummer-logikk (inkl. wrap-around)
- Paddingberegning (for 32-bit justering)
- Generelle verktøy som brukes av flere filer
*/

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "miptpd_utils.h"

app_connection app_connections[MAX_APPS] = {0}; //liste over aktive app forbinndelser

/*
  Pakker sammen sekvensnummer og pad-lengde i ett 16-bit-felt.
  Øverste 2 bits brukes til pad, nederste 14 til sekvensnummer.
*/
uint16_t pack_seq_pad(uint16_t seq, uint8_t padlen) {
    return ((padlen & 0x03) << 14) | (seq & 0x3FFF);
}

/*
  Dekomprimerer et 16-bit-felt til sekvensnummer og pad-lengde.
  Brukes ved mottak av MIPTP-pakker
*/
void unpack_seq_pad(uint16_t seq_pad, uint16_t *seq, uint8_t *pad) {
    *pad = (seq_pad >> 14) & 0x03;   // hent de to øverste bitene
    *seq  = seq_pad & 0x3FFF;         // hent de nederste 14 bitene
}

/*
  Registrerer en ny applikasjon i tabellen
  Tildeler port, initierer Go-Back-N-tilstand og tomt sendevindu
  Returnerer 0 ved suksess, -1 hvis tabellen er full
*/
int new_app_connection(int fd, uint8_t port) {
    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].app_fd == 0) {
            app_connections[i].app_fd = fd;
            app_connections[i].port = port;

            // Initialiser Go-Back-N tilstand
            app_connections[i].base_seq = rand() % MIPTP_MAX_SEQ; // starter med tilfeldig sekvensnummer, gitt oppgaven
            app_connections[i].next_seq = app_connections[i].base_seq;
            app_connections[i].window_count = 0;

            // Initialiser mottaker-tilstand
            app_connections[i].expected_seq = 0; // venter på første pakke med seq=0
            app_connections[i].synced = 0;

            app_connections[i].queue_head = 0;
            app_connections[i].queue_tail = 0;
            app_connections[i].queue_count = 0;
            app_connections[i].peer_mip = 0;


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
  Nullstiller all tilstand slik at plassen kan brukes på nytt
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
  Returnerer portnummeret som er knyttet til en gitt app_fd
  Returnerer 0 hvis forbindelsen ikke finnes (0 er ugyldig port)
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
  Finner filbeskrivelsen (socket-fd) som hører til en gitt port
  Returnerer -1 hvis ingen app er registrert på porten
*/
int get_fd_from_port(uint8_t port) {
    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].port == port)
            return app_connections[i].app_fd;
    }
    fprintf(stderr, "[MIPTPD] No app found for port=%d\n", port);
    return -1;
}

/*
  Finner indexen i app_connections-tabellen for en gitt fd.
  Returnerer -1 hvis ingen match finnes.
*/
int get_index(int fd){
    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].app_fd == fd)
            return i;
    }
    fprintf(stderr, "[MIPTPD] No index found for fd=%d\n", fd);
    return -1;
}


void hex_debug(const char *prefix, const uint8_t *buf, size_t len) {
    printf("%s (len=%zu): ", prefix, len);
    size_t show = len < 16 ? len : 16;
    for (size_t i = 0; i < show; i++)
        printf("%02x ", buf[i]);
    if (len > 16) printf("...");
    printf("\n");
}

int transfer_exists(app_connection *conn, uint8_t src_mip, uint8_t src_port) {
    for (int i = 0; i < conn->num_transfers; i++) {
        if (conn->active_transfers[i].src_mip == src_mip &&
            conn->active_transfers[i].src_port == src_port)
            return 1;
    }
    return 0;
}

void register_new_transfer(app_connection *conn, uint8_t src_mip, uint8_t src_port) {
    if (conn->num_transfers < MAX_TRANSFERS_PER_APP) {
        conn->active_transfers[conn->num_transfers].src_mip = src_mip;
        conn->active_transfers[conn->num_transfers].src_port = src_port;
        conn->num_transfers++;
    }
}