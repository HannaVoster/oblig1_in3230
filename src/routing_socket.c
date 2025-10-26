#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>

#include "routing_socket.h"
#include "routingd.h"
#include "arp.h"

int connect_to_mipd(const char *socket_path) {
    int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Lag unik lokal UNIX-socket for routingd selv (så flere prosesser ikke kolliderer)
    struct sockaddr_un client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sun_family = AF_UNIX;
    snprintf(client_addr.sun_path, sizeof(client_addr.sun_path),
             "/tmp/routingd_%d.sock", getpid());  // legg den i /tmp/
    unlink(client_addr.sun_path);

    if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("bind client");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // --- Bygg full sti til MIP-daemonens UNIX-socket ---
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    char full_path[sizeof(addr.sun_path)];
    if (socket_path[0] != '/') {
        snprintf(full_path, sizeof(full_path), "/tmp/%s", socket_path);
    } else {
        strncpy(full_path, socket_path, sizeof(full_path) - 1);
        full_path[sizeof(full_path) - 1] = '\0';
    }

    // Kopier inn i addr.sun_path
    strncpy(addr.sun_path, full_path, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    fprintf(stderr, "[ROUTINGD] Connecting to MIP daemon socket: %s\n", addr.sun_path);
    fflush(stderr);

    // --- Koble til MIP-daemonen ---
    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
        perror("connect to mipd");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Registrer routingd som SDU-type 0x04
    uint8_t sdu_type = SDU_TYPE_ROUTING;
    if (write(sock, &sdu_type, 1) != 1) {
        perror("register sdu_type");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Les min MIP-adresse fra MIP-daemonen
    uint8_t my_addr;
    ssize_t n = read(sock, &my_addr, 1);
    if (n == 1) {
        MY_MIP = my_addr;
        fprintf(stderr, "[ROUTINGD] Received MY_MIP = %d from MIPd\n", MY_MIP);
    } else if (n == 0) {
        fprintf(stderr, "[ROUTINGD] Warning: MIP daemon closed socket unexpectedly!\n");
    } else {
        perror("read MY_MIP from MIPd");
    }

    fprintf(stderr, "[ROUTINGD] Connected and registered to socket fd=%d (SDU=0x04)\n", sock);
    fflush(stderr);

    return sock;
}


void wait_for_socket(const char *path) {
    struct stat sb;
    int tries = 0;
    while (stat(path, &sb) != 0) {
        if (tries++ > 50) {
            fprintf(stderr, "[ROUTINGD] Timeout waiting for socket %s\n", path);
            exit(EXIT_FAILURE);
        }
        usleep(100000); // 0.1 sek
    }
}

//generisk metode til å kommuniserer med MIPD over unix socket
int send_unix_message(uint8_t dest, uint8_t ttl, const uint8_t* data, size_t len) {
    uint8_t buf[256];
    if (len + 2 > sizeof(buf)) return -1;
    buf[0] = dest; 
    buf[1] = ttl; 
    memcpy(&buf[2], data, len);
    return write(ROUTING_SOCK, buf, len + 2);
}
