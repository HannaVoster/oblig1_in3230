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
transfer_t *active_transfer = NULL;

// transfer_t *find_or_create_transfer(const char *dir) {
//     // Finn en inaktiv slot (ikke aktiv = kan brukes)
//     for (int i = 0; i < MAX_TRANSFERS; i++) {
//         if (!transfers[i].active) {
//             printf("[DEBUG] Creating new transfer slot %d — opening file now!\n", i);
//             transfers[i].active = 1;
//             transfers[i].received = 0;
//             transfers[i].expected_size = 0;

//             char filename[256];
//             snprintf(filename, sizeof(filename), "%s/incoming", dir);
//             transfers[i].fp = fopen(filename, "wb");
//             if (!transfers[i].fp) {
//                 perror("fopen");
//                 transfers[i].active = 0;
//                 return NULL;
//             }

//             printf("[SERVER] New file: %s\n", filename);
//             return &transfers[i];
//         }
//     }

//     fprintf(stderr, "[SERVER] No available transfer slots!\n");
//     return NULL;
// }


transfer_t *find_transfer(uint8_t src_mip, uint8_t src_port) {
    for (int i = 0; i < MAX_TRANSFERS; i++) {
        if (transfers[i].active &&
            transfers[i].src_mip == src_mip &&
            transfers[i].src_port == src_port)
            return &transfers[i];
    }
    return NULL;
}

transfer_t *create_transfer(uint8_t src_mip, uint8_t src_port, const char *dir) {
    for (int i = 0; i < MAX_TRANSFERS; i++) {
        if (!transfers[i].active) {
            transfers[i].active = 1;
            transfers[i].src_mip = src_mip;
            transfers[i].src_port = src_port;
            transfers[i].received = 0;
            transfers[i].expected_size = 0;

            char filename[256];
            snprintf(filename, sizeof(filename),
                     "%s/incoming_%u_%u", dir, src_mip, src_port);

            transfers[i].fp = fopen(filename, "wb");
            if (!transfers[i].fp) {
                perror("fopen");
                transfers[i].active = 0;
                return NULL;
            }

            printf("[SERVER] New transfer from %u:%u -> %s\n",
                   src_mip, src_port, filename);
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
    printf("[SERVER] Starting recv loop...\n");

    while (1) {
        uint8_t buf[1500];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;


        // ===  Kontrollmelding fra MIPTPD ===
        if (buf[0] == 0xFF && n == 3) {
            uint8_t src_mip = buf[1];
            uint8_t src_port = buf[2];
            create_transfer(src_mip, src_port, out_dir);
            continue;
        }

        uint8_t src_mip = buf[0];
        uint8_t src_port = buf[1];
        uint8_t *payload = buf + 2;
        size_t payload_len = n - 2;

        transfer_t *t = find_transfer(src_mip, src_port);
        if (!t) {
            fprintf(stderr, "[SERVER][WARN] Got data from unknown %u:%u\n",
                    src_mip, src_port);
            continue;
        }

        printf("[CLIENT][RX] len=%zd first_bytes=", n);
        for (int i = 0; i < (n < 16 ? n : 16); i++)
            printf("%02x ", buf[i]);
        printf("\n");

            // === 3️⃣ Første melding (filstørrelse 4 byte) ===
        if (t->expected_size == 0 && payload_len == 4) {
            uint32_t net_size;
            memcpy(&net_size, payload, 4);
            t->expected_size = ntohl(net_size);
            printf("[SERVER] Expecting %u bytes from %u:%u\n",
                t->expected_size, t->src_mip, t->src_port);
            continue;
        }

            // === 4️⃣ Faktiske data ===
        fwrite(payload, 1, payload_len, t->fp);
        t->received += payload_len;

        printf("[SERVER][DATA] %u:%u wrote %zu bytes (%u/%u)\n",
           t->src_mip, t->src_port,
           payload_len, t->received, t->expected_size);

        if (t->expected_size && t->received >= t->expected_size) {
            printf("[SERVER] Transfer complete from %u:%u (%u bytes)\n",
                t->src_mip, t->src_port, t->received);
            fclose(t->fp);
            t->fp = NULL;
            t->active = 0;
        }

        // Dersom vi ikke har startet en overføring enda:
        // if (!active_transfer) {
        //     // Forvent at dette er meldingen med filstørrelse
        //     if (n == 4) { //  4 størrelse
        //         uint32_t net_size;
        //         memcpy(&net_size, payload, 4);
        //         uint32_t filesize = ntohl(net_size);

        //         active_transfer = &transfers[0];
        //         active_transfer->expected_size = filesize;
        //         active_transfer->received = 0;
        //         active_transfer->active = 1;

        //         char filename[256];
        //         snprintf(filename, sizeof(filename), "%s/incoming", out_dir);
        //         active_transfer->fp = fopen(filename, "wb");
        //         printf("[DEBUG] fopen() called — new file descriptor!\n");

        //         if (!active_transfer->fp) {
        //             perror("fopen");
        //             active_transfer->active = 0;
        //             active_transfer = NULL;
        //             continue;
        //         }

        //         printf("[SERVER] New file: %s\n", filename);
        //         printf("[SERVER] File size = %u bytes\n", filesize);
        //         continue; // vent på neste pakke
        //     } else {
        //         printf("[SERVER][WARN] Got data before size message — ignoring\n");
        //         continue;
        //     }
        // }


        // === Her er vi midt i overføringen ===
        // if (active_transfer && active_transfer->active) {
        
        //     uint8_t *filedata = payload;
        //     size_t data_len = payload_len;

        //     fwrite(filedata, 1, data_len, active_transfer->fp);
        //     active_transfer->received += data_len;

        //     printf("[SERVER][DATA] Wrote %zu bytes (%u/%u total)\n",
        //         data_len, active_transfer->received, active_transfer->expected_size);

        //     // Fullført?
        //     if (active_transfer->received >= active_transfer->expected_size) {
        //         printf("[SERVER] Transfer complete (%u bytes)\n", active_transfer->received);
        //         fflush(active_transfer->fp);
        //         fclose(active_transfer->fp);
        //         active_transfer->active = 0;
        //         active_transfer = NULL;
        //     }
        // }
    }

    sleep(1);
    close(fd);
    return EXIT_SUCCESS;
}

