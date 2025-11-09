#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>

#define MAX_TRANSFERS 32

typedef struct {
    uint8_t src_mip;
    uint8_t src_port;
    FILE *fp;
    uint32_t expected_size;
    uint32_t received;
    int active;
} transfer_t;

transfer_t transfers[MAX_TRANSFERS];

transfer_t *find_or_create_transfer(uint8_t src_mip, uint8_t src_port, const char *dir) {
    // Try find existing
    for (int i = 0; i < MAX_TRANSFERS; i++) {
        if (transfers[i].active && transfers[i].src_mip == src_mip && transfers[i].src_port == src_port)
            return &transfers[i];
    }

    // Otherwise create new
    for (int i = 0; i < MAX_TRANSFERS; i++) {
        if (!transfers[i].active) {
            transfers[i].src_mip = src_mip;
            transfers[i].src_port = src_port;
            transfers[i].received = 0;
            transfers[i].expected_size = 0;
            transfers[i].active = 1;

            char filename[256];
            snprintf(filename, sizeof(filename), "%s/incoming_%d_%d", dir, src_mip, src_port);
            transfers[i].fp = fopen(filename, "wb");
            if (!transfers[i].fp) {
                perror("fopen");
                transfers[i].active = 0;
                return NULL;
            }
            printf("[SERVER] New file: %s\n", filename);
            return &transfers[i];
        }
    }
    fprintf(stderr, "[SERVER] No available transfer slots!\n");
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <listen_port> <app_socket> <output_dir>\n", argv[0]);
        return EXIT_FAILURE;
    }

    uint8_t my_port = atoi(argv[1]);
    const char *socket_arg = argv[2];
    const char *out_dir = argv[3];

    char socket_path[108];
    if (socket_arg[0] != '/')
        snprintf(socket_path, sizeof(socket_path), "/tmp/%s", socket_arg);
    else
        strncpy(socket_path, socket_arg, sizeof(socket_path) - 1);

    // Create socket
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return EXIT_FAILURE;
    }

    // Register port
    if (write(fd, &my_port, 1) != 1) {
        perror("register port");
        close(fd);
        return EXIT_FAILURE;
    }

    printf("[SERVER] Listening on port %d, saving to %s\n", my_port, out_dir);

    while (1) {
        uint8_t buf[1500];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;

        uint8_t src_mip = buf[0];
        uint8_t src_port = buf[1];
        uint8_t *payload = buf + 2;
        size_t payload_len = n - 2;

        transfer_t *t = find_or_create_transfer(src_mip, src_port, out_dir);
        if (!t) continue;

        if (t->expected_size == 0 && payload_len == 4) {
            memcpy(&t->expected_size, payload, 4);
            t->expected_size = ntohl(t->expected_size);
            printf("[SERVER] File size from %d:%d = %u bytes\n", src_mip, src_port, t->expected_size);
            continue;
        }

        fwrite(payload, 1, payload_len, t->fp);
        t->received += payload_len;

        if (t->received >= t->expected_size && t->expected_size > 0) {
            printf("[SERVER] Transfer complete (%u bytes)\n", t->received);
            fclose(t->fp);
            t->active = 0;
        }
    }

    close(fd);
    return EXIT_SUCCESS;
}

