#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define APP_SOCKET_PATH "/tmp/miptp_app.sock"

int main(void) {
    const uint8_t my_port = 99;  // denne appens port
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
    strncpy(addr.sun_path, APP_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("[SERVER] Connected to MIPTP daemon at %s\n", APP_SOCKET_PATH);

    // Send portnummer som første byte (registrering)
    if (write(fd, &my_port, 1) != 1) {
        perror("write port");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("[SERVER] Registered port %d with MIPTP daemon, waiting for data...\n", my_port);

    // Lytt kontinuerlig etter meldinger fra MIPTPD
    while (1) {
        uint8_t buf[1500];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) {
            printf("[SERVER] Connection closed or error.\n");
            break;
        }

        // Første byte i meldingen er avsenderens MIP-adresse
        uint8_t src_mip = buf[0];
        uint8_t src_port = buf[1];

        printf("[SERVER] Got %zd bytes from MIP=%d, port=%d\n", n, src_mip, src_port);
        printf("[SERVER] Payload: %.*s\n", (int)(n - 2), buf + 2);
    }

    close(fd);
    return 0;
}
