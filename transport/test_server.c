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
    // Lytt kontinuerlig etter meldinger fra MIPTPD
    while (1) {
        uint8_t buf[1500];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) {
            printf("[SERVER] Connection closed or error.\n");
            break;
        }

        uint8_t src_port = buf[0];  // avsenderens port (fra klienten)
        uint8_t dst_port = my_port; // denne serverens port

        printf("[SERVER] Got %zd bytes from port=%d → %d\n", n, src_port, dst_port);
        printf("[SERVER] Payload: %.*s\n", (int)(n - 2), buf + 2);

        //-------------------------------------------------------------
        // 👇 SEND ET EKTE ACK TIL MIPTPD
        //-------------------------------------------------------------
        uint16_t seq = 0; // sekvensnummeret er ikke kjent i test_server
                        // så vi kan sende et dummy ACK for nå, eller
                        // utvide senere slik at det pakkes i header.

        // Lag ACK-pakken [dst_mip][dst_port][payload]
        // Her bruker vi “pad=1” for å signalisere at dette er ACK.
        uint8_t ack_msg[4];
        ack_msg[0] = src_port;  // send ACK tilbake til klientporten
        ack_msg[1] = dst_port;  // fra denne porten (server)
        ack_msg[2] = 0xAA;      // symbolsk "ACK" markør
        ack_msg[3] = 0x00;      // reserved / dummy

        ssize_t sent = write(fd, ack_msg, sizeof(ack_msg));
        if (sent > 0)
            printf("[SERVER] Sent ACK back to port %d (%zd bytes)\n", src_port, sent);
        else
            perror("[SERVER] Failed to send ACK");
    }


    close(fd);
    return 0;
}
