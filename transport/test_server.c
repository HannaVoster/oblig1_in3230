#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define APP_SOCKET_PATH "/tmp/miptp_app.sock"
#include "miptpd.h"  // eller inkluder filen som definerer miptp_hdr_t, pack_seq_pad()


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
        // 👇 SEND ET EKTE MIPTP-ACK
        //-------------------------------------------------------------
        miptp_hdr_t ack_hdr = {0};
        ack_hdr.src_port = dst_port;  // fra denne appen (server)
        ack_hdr.dst_port = src_port;  // tilbake til klienten
        ack_hdr.seq_pad = pack_seq_pad(0, 1); // pad = 1 betyr "ACK"

        uint8_t ack_packet[1 + sizeof(ack_hdr)];
        ack_packet[0] = 1; // dummy MIP-adresse, brukes ikke lokalt
        memcpy(ack_packet + 1, &ack_hdr, sizeof(ack_hdr));

        // send til MIPTPD
        ssize_t sent = write(fd, ack_packet, sizeof(ack_packet));
        if (sent > 0)
            printf("[SERVER] Sent MIPTP ACK back to port %d (%zd bytes)\n", src_port, sent);
        else
            perror("[SERVER] Failed to send ACK");

        }


    close(fd);
    return 0;
}
