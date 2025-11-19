#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "miptpd.h"  // eller inkluder filen som definerer miptp_hdr_t, pack_seq_pad()


int main(int argc, char *argv[]) {
    const uint8_t my_port = 99;  // denne appens port

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <app_socket>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *socket_arg = argv[1];
    char socket_path[108];

    // Legg til /tmp/ hvis brukeren oppga kun et kort navn
    if (socket_arg[0] != '/') {
        snprintf(socket_path, sizeof(socket_path), "/tmp/%s", socket_arg);
    } else {
        strncpy(socket_path, socket_arg, sizeof(socket_path) - 1);
        socket_path[sizeof(socket_path) - 1] = '\0';
    }

    printf("[SERVER] Starting test server (port %d)\n", my_port);

    // Opprett UNIX-socket
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Koble til miptpd
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("[SERVER] Connected to MIPTP daemon at %s\n", socket_path);

    // Send portnummer som første byte (registrering)
    if (write(fd, &my_port, 1) != 1) {
        perror("write port");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("[SERVER] Registered port %d with MIPTP daemon, waiting for data...\n", my_port);

    // Lytt kontinuerlig etter meldinger fra MIPTPD
    // Lytt kontinuerlig etter meldinger fra MIPTPD
    while (1) {
        uint8_t buf[1500];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;

        uint8_t src_mip = buf[0];
        uint8_t src_port = buf[1];
        printf("[SERVER] Got %zd bytes from MIP=%d, port=%d\n", n, src_mip, src_port);
        printf("[SERVER] Payload: %.*s\n", (int)(n - 2), buf + 2);
    }

    close(fd);
    return 0;
}
