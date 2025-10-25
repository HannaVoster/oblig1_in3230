//mottar meldinger som mipd leverer
//trenger bare socket path til å lytte og ta imot

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
//  PING SERVER
// Program som kjører på en host sammen med mipd.
// Lytter på en UNIX-socket (koblet til mipd) for å motta meldinger.
// Når det mottar et "PING:<msg>", svarer det med "PONG:<msg>" tilbake

#define BUF_SIZE 512 //økt etter warning

int main(int argc, char *argv[]) {
    //setvbuf(stdout, NULL, _IOLBF, 0);

    // Sjekker at bruker har gitt et socket_path eller ber om hjelp
    if (argc < 2 || strcmp(argv[1], "-h") == 0) {
        printf("Usage: %s <socket_lower>\n", argv[0]);
        return 0;
    }

    const char *socket_path = argv[1]; //unix socket som kobles til mipd

    int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Setter opp adresse-strukturen for å koble til socketen
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    // Kobler til mipd sin socket
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    // Registrer SDU-type, PONG = 0x03
    uint8_t sdu_type = 0x03;
    if (write(sock, &sdu_type, 1) != 1) {
        perror("write sdu_type");
        close(sock);
        return 1;
    }
    while(1) {
    // leser meldingen fra mips, som opprinnellig kom gjennom nettverket fra ping_client
        char buf[BUF_SIZE];
        int n = read(sock, buf, sizeof(buf));
        if (n <= 0) {
            perror("read");
            close(sock);
            return 1;
        }

        uint8_t src = buf[0];
        uint8_t ttl = buf[1];
        printf("[PING_SERVER] From MIP %u (TTL=%u): %s\n", src, ttl, &buf[2]);

        // Lag svar: [dest=src][ttl=8][PONG:<payload>]
        uint8_t reply[BUF_SIZE];
        reply[0] = src;
        reply[1] = 8;
        snprintf((char*)&reply[2], BUF_SIZE - 2, "PONG:%.500s", (char*)&buf[2]);

        // Sender svaret tilbake via samme socket (til mipd → ping_client)
        if (write(sock, reply, 2 + strlen((char*)&reply[2])) < 0)  {
            perror("write");
        } else {
            printf("[PING_SERVER] Sent reply: PONG:%s\n", &buf[2]);
            //fflush(stdout);
        }
    }

    close(sock);
    return 0;
}
