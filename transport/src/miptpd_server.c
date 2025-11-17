/*
 *  Enkel MIPTP filmottaker (server)
 *
 *  Formål:
 *  - Tar imot filer via MIPTPD og lagrer dem til disk
 *  - Hver ny overføring identifiseres av (src_mip, src_port)
 *  - Kan håndtere flere samtidige overføringer
 *  - Kjører kontinuerlig til brukeren stopper programmet
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>

#define MAX_TRANSFERS 32 // Hvor mange samtidige overføringer som støttes

/*
 *  transfer_t
 *
 *  Holder informasjon om én aktiv filoverføring.
 *  Hver avsender (src_mip, src_port) får sin egen entry i tabellen
 */
typedef struct {
    uint8_t src_mip;
    uint8_t src_port;
    FILE *fp;
    uint32_t expected_size;
    uint32_t received;
    int active;
} transfer_t;

transfer_t transfers[MAX_TRANSFERS]; // Tabell over alle pågående overføringer

/*
 *  find_transfer()
 *
 *  Søker i tabellen etter en pågående overføring
 *  som matcher gitt (src_mip, src_port)
 *  Returnerer peker til overføringen hvis den finnes, ellers NULL
 */
transfer_t *find_transfer(uint8_t src_mip, uint8_t src_port) {
    for (int i = 0; i < MAX_TRANSFERS; i++) {
        if (transfers[i].active &&
            transfers[i].src_mip == src_mip &&
            transfers[i].src_port == src_port)
            return &transfers[i];
    }
    return NULL;
}

/*
 *  create_transfer()
 *
 *  Oppretter en ny overføring i første ledige slot.
 *  Lager en ny fil med navn "incoming_<src_mip>_<src_port>" (gitt fra oppgaven) i valgt katalog
 *  Returnerer peker til den nye overføringen.
 */
transfer_t *create_transfer(uint8_t src_mip, uint8_t src_port, const char *dir) {
    for (int i = 0; i < MAX_TRANSFERS; i++) {
        if (!transfers[i].active) {
            transfers[i].active = 1;
            transfers[i].src_mip = src_mip;
            transfers[i].src_port = src_port;
            transfers[i].received = 0;
            transfers[i].expected_size = 0;

            // Lager filnavn basert på avsender
            char filename[256];
            snprintf(filename, sizeof(filename),
                     "%s/incoming_%u_%u", dir, src_mip, src_port);

            // Åpner fil for skriving
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

/*
 *  main()
 *
 *  Starter serveren.
 *  Kobler til MIPTPD, registrerer portnummer, og går deretter inn i evig løkke
 *  som tar imot pakker fra MIPTPD (både kontrollmeldinger og data).
 */

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

    // Lager sti til MIPTPD-socketen
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    // Oppretter UNIX socket for kommunikasjon med miptpd
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        return EXIT_FAILURE;
    }

    // Registrerer portnummer hos miptpd
    if (write(fd, &my_port, 1) != 1) {
        perror("register port");
        close(fd);
        return EXIT_FAILURE;
    }

    printf("[SERVER] Listening on port %d", my_port);
    printf("[SERVER] Starting recv loop...\n");
    
    /*
     *  Hovedløkke:
     *  Leser meldinger fra MIPTPD kontinuerlig
     *  Hver melding kan være enten
     *   - en kontrollmelding (0xFF + src_mip + src_port)
     *   - eller en datapakke (src_mip, src_port + payload)
     */

    while (1) {
        uint8_t buf[1500];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) break; // Avslutter hvis forbindelsen brytes


        // ===  Kontrollmelding fra MIPTPD om at ny overføring starter ===
        if (buf[0] == 0xFF && n == 3) {
            uint8_t src_mip = buf[1];
            uint8_t src_port = buf[2];
            create_transfer(src_mip, src_port, out_dir);
            continue;
        }

        // === vanlig datapakke ===
        uint8_t src_mip = buf[0];
        uint8_t src_port = buf[1];
        uint8_t *payload = buf + 2;
        size_t payload_len = n - 2;

        // Finner hvilken overføring som pakken tilhører
        transfer_t *t = find_transfer(src_mip, src_port);
        if (!t) {
            fprintf(stderr, "[SERVER][WARNING] Got data from unknown %u:%u\n",
                    src_mip, src_port);
            continue;
        }

        // === Første melding med filstørrelse = 4 byte) ===
        if (t->expected_size == 0 && payload_len == 4) {
            uint32_t net_size;
            memcpy(&net_size, payload, 4);
            t->expected_size = ntohl(net_size);
            printf("[SERVER] Expecting %u bytes from %u:%u\n",
                t->expected_size, t->src_mip, t->src_port);
            continue;
        }

        // === fildata ===
        fwrite(payload, 1, payload_len, t->fp);
        t->received += payload_len;

        printf("[SERVER][DATA] %u:%u wrote %zu bytes (%u/%u)\n",
           t->src_mip, t->src_port,
           payload_len, t->received, t->expected_size);

        // == filoverføring ferdig ==
        if (t->expected_size && t->received >= t->expected_size) {
            printf("[SERVER] Transfer ---COMPLETE--- from %u:%u (%u bytes)\n",
                t->src_mip, t->src_port, t->received);
            fclose(t->fp);
            t->fp = NULL;
            t->active = 0;
        }
    }

    sleep(1);
    close(fd);
    return EXIT_SUCCESS;
}

