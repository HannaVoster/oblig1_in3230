// håndtering av UNIX domain sockets (apper)
//fungerer som grensesnitt mot applikasjonene, laget over, øverste lag

/*
**Ansvar:**

- Opprette og lytte på UNIX domain socket
- Akseptere nye apper som kobler til (`accept()`)
- Motta og sende PDU-er til apper i riktig format:

[MIP address][port][payload]

*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include "miptpd.h"   // felles header for MIPTP

// int init_unix_socket(const char *path);
// void handle_new_app_connection(int unix_fd);
// void handle_app_message(int app_fd);

/**
 * Hjelpefunksjon for å vente på at en socket-fil opprettes (fra mipd)
 */
void wait_for_socket(const char *path) {
    for (int i = 0; i < 50; i++) { // prøver i 5 sekunder
        if (access(path, F_OK) == 0)
            return;
        usleep(100000); // 0.1 s
    }
    fprintf(stderr, "[MIPTPD] Timeout: %s finnes ikke\n", path);
    exit(EXIT_FAILURE);
}

/**
 * Koble til MIP-daemon via UNIX domain socket
 */
int connect_to_mipd(const char *path) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect mipd");
        close(fd);
        return -1;
    }

    return fd;
}

/**
 * Opprett UNIX-socket for applikasjoner (klienter som miptp_client/server)
 */
int create_app_socket(const char *path) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    // Fjern gammel fil hvis den finnes
    unlink(path);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        exit(EXIT_FAILURE);
    }

    if (listen(fd, 10) < 0) {
        perror("listen");
        close(fd);
        exit(EXIT_FAILURE);
    }

    return fd;
}
