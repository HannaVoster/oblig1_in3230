//  PING SERVER
// Program som kjører på en host sammen med mipd
// Lytter på en UNIX-socket (koblet til mipd) for å motta meldinger
// Når det mottar et "PING:<msg>", svarer det med "PONG:<msg>" tilbake

// SDU-type 0x03 brukes for PONG-kommunikasjon

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>

#define BUF_SIZE 512 

int main(int argc, char *argv[]) {
    // Sørger for at printf skriver ut fortløpende
    setvbuf(stdout, NULL, _IOLBF, 0);

    // Sjekker at bruker har gitt et socket_path eller ber om hjelp
    if (argc < 2 || strcmp(argv[1], "-h") == 0) {
        printf("Usage: %s <socket_lower>\n", argv[0]);
        return 0;
    }

    const char *socket_path = argv[1]; //unix socket som kobles til mipd

    // Oppretter en UNIX socket
    int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Sett opp adresse-strukturen for å koble til socketen
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    char full_path[sizeof(addr.sun_path)];

    // Hvis brukeren bare oppga et navn (f.eks. "usockB"), legg til /tmp/
    if (socket_path[0] != '/') {
        snprintf(full_path, sizeof(full_path), "/tmp/%s", socket_path);
    } else {
        strncpy(full_path, socket_path, sizeof(full_path) - 1);
        full_path[sizeof(full_path) - 1] = '\0';
    }

    // Kopier hele banen inn i addr.sun_path
    strncpy(addr.sun_path, full_path, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    fprintf(stderr, "[PING_SERVER] Connecting to %s\n", addr.sun_path);
    fflush(stderr);

    int retries = 10;
    int connected = 0;
    for (int i = 0; i < retries; i++) {
        if (connect(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr_un)) == 0) {
            connected = 1;
            break;
        }
        perror("[PING_SERVER] connect attempt failed");
        fprintf(stderr, "[PING_SERVER] Retrying in 0.5 sec... (%d/%d)\n", i + 1, retries);
        fflush(stderr);
        usleep(500000); // vent 0.5 sek
    }

    if (!connected) {
        fprintf(stderr, "[PING_SERVER] ERROR: Could not connect to MIP daemon after %d attempts.\n", retries);
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Registrer seg som klient med SDU-type, PONG = 0x03
    uint8_t sdu_type = 0x03;

    if (write(sock, &sdu_type, 1) != 1) {
        perror("write sdu_type");
        close(sock);
        return 1;
    }

    // Hovedløkke: vent på PING-meldinger og svar med PONG
    while(1) {
        char buf[BUF_SIZE];
        int n = read(sock, buf, sizeof(buf)); // leser emlding fra mipd
        if (n <= 0) {
            perror("read");
            close(sock);
            return 1;
        }

        uint8_t src = buf[0]; //hvem kom meldingen fra
        uint8_t ttl = buf[1]; // ttl fra mld

        printf("[PING_SERVER] From MIP %u (TTL=%u): %s\n", src, ttl, &buf[2]);

        // Lag svar: [dest=src][ttl=8][PONG:<payload>] format fra oppgaven
        uint8_t reply[BUF_SIZE];
        reply[0] = src;
        reply[1] = 8; // starter ny PONG med full TTL (ikke arvet fra mottatt PING)

        snprintf((char*)&reply[2], BUF_SIZE - 2, "PONG:%.500s", (char*)&buf[2]);

        // Send svaret tilbake til mipd (som sender det videre til ping_client)
        ssize_t total_len = 2 + strlen((char*)&reply[2]);
        ssize_t sent = write(sock, reply, total_len); 

        if (sent < 0) perror("write");

        printf("[PING_SERVER] Sent reply (%zd bytes): PONG:%s\n", sent, &buf[2]);
        fflush(stdout);
    }

    close(sock);
    return 0;
}
