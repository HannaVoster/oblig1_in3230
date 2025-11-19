/*
 *  Ansvar:
 *  - Opprette og håndtere UNIX domain sockets brukt av MIPTP-daemonen
 *  - Koble til MIP-daemon (mipd)
 *  - Vente på at nødvendige socket-filer blir tilgjengelige
 *  - Opprette server-socket for applikasjoner (f.eks. MIPTP-klienter)
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

#include "miptpd.h"   

/*
  Venter til en gitt socket-fil eksisterer (opprettes av mipd)
  Brukes ved oppstart for å sikre at mipd er klar før tilkobling.
*/
void wait_for_socket(const char *path) {
    for (int i = 0; i < 50; i++) { // prøver i 5 sekunder
        if (access(path, F_OK) == 0) //finnes filen?
            return;
        usleep(100000); // 0.1 s før neste forsøk
    }
    fprintf(stderr, "[MIPTPD] Timeout: %s finnes ikke\n", path);
    exit(EXIT_FAILURE);
}

/*
  Koble til MIP-daemon via UNIX domain socket
  Returnerer socket-fd ved suksess, -1 ved feil
*/
int connect_to_mipd(const char *path) {
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX; // UNIX domain
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1); // setter sti til mipd-socket

    //prøver å koble til mip deamon
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect mipd");
        close(fd);
        return -1;
    }

    return fd; //suksess
}

/*
  Oppretter UNIX domain socket for applikasjoner som vil kommunisere
  med MIPTP-daemonen (for eksempel miptp_client og miptp_server)
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

    // Bind socketen til filstien
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Starter lytting slik at apper kan koble seg til
    if (listen(fd, 10) < 0) {
        perror("listen");
        close(fd);
        exit(EXIT_FAILURE);
    }

    return fd; // socketen er klar til bruk
}



