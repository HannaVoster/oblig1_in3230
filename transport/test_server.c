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
        uint8_t buffer[1500];

        if (n > 0) {
            uint8_t src_port = buffer[0];
            uint8_t dst_port = buffer[1];

            // sjekk om dette er en ekte MIPTP-pakke (minst 1 + header)
            if (n >= 1 + sizeof(miptp_hdr_t)) {
                miptp_hdr_t *hdr = (miptp_hdr_t *)(buffer + 1);
                uint16_t seq;
                uint8_t pad;
                unpack_seq_pad(hdr->seq_pad, &seq, &pad);

                if (pad == 1) {
                    printf("[SERVER] Got ACK for seq=%u from port=%d\n", seq, src_port);
                    continue; // hopp over videre behandling
                }

                // ellers er det en datapakke
                size_t payload_len = n - (1 + sizeof(miptp_hdr_t));
                uint8_t *payload = buffer + 1 + sizeof(miptp_hdr_t);

                printf("[SERVER] Got %zu bytes from port=%d → %d\n", payload_len, src_port, dst_port);
                printf("[SERVER] Payload: %.*s\n", (int)payload_len, payload);

                // Send ACK tilbake med samme seq:
                miptp_hdr_t ack_hdr = {0};
                ack_hdr.src_port = dst_port;
                ack_hdr.dst_port = src_port;
                ack_hdr.seq_pad = pack_seq_pad(seq, 1); // pad=1 -> ACK

                uint8_t ack_packet[1 + sizeof(ack_hdr)];
                ack_packet[0] = 1; // dummy MIP addr
                memcpy(ack_packet + 1, &ack_hdr, sizeof(ack_hdr));

                ssize_t sent = write(fd, ack_packet, sizeof(ack_packet));
                if (sent > 0)
                    printf("[SERVER] Sent ACK back to port %d (seq=%u, %zd bytes)\n", src_port, seq, sent);
            }
        }

    }

    close(fd);
    return 0;
}
