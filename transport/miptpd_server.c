
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#define APP_SOCKET_PATH "/tmp/miptp_app.sock"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <listen_port> <output_dir>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    uint8_t my_port = atoi(argv[1]);
    const char *outdir = argv[2];

    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, APP_SOCKET_PATH, sizeof(addr.sun_path)-1);
    connect(fd, (struct sockaddr*)&addr, sizeof(addr));

    write(fd, &my_port, 1);
    printf("[SERVER] Listening on port %d\n", my_port);

    FILE *curfile = NULL;
    uint8_t src_mip = 0, src_port = 0;
    uint32_t expected_bytes = 0, received_bytes = 0;

    while (1) {
        uint8_t buf[1500];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;

        src_mip = buf[0];
        src_port = buf[1];
        uint8_t *payload = buf + 2;
        size_t payload_len = n - 2;

        if (curfile == NULL) {
            // første melding: fil-lengde (4 byte network order)
            memcpy(&expected_bytes, payload, 4);
            expected_bytes = ntohl(expected_bytes);
            char filename[128];
            snprintf(filename, sizeof(filename),
                     "%s/incoming_%d_%d.bin", outdir, src_mip, src_port);
            curfile = fopen(filename, "wb");
            received_bytes = 0;
            printf("[SERVER] New file %s (%u bytes expected)\n", filename, expected_bytes);
        } else {
            fwrite(payload, 1, payload_len, curfile);
            received_bytes += payload_len;
            if (received_bytes >= expected_bytes) {
                printf("[SERVER] File transfer complete (%u bytes)\n", received_bytes);
                fclose(curfile);
                curfile = NULL;
            }
        }
    }
    close(fd);
}
