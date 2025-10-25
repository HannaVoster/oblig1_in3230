

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <stdint.h>

/* 
 PING CLIENT
Program som sender en melding via MIP-daemonen (mipd), selve brukerprogrammet som sender/avslutter
  - Kobler seg til mipd via en UNIX domain socket (navn gis som argument)
  - Sender en melding til en spesifisert MIP-adresse
  - Venter på svar i opptil 1 sekund, og beregner RTT hvis svar mottas
*/

#define BUF_SIZE 512

int main(int argc, char *argv[]) {
    //sjekker at riktige argumenter er gitt
    if (argc < 5 || strcmp(argv[1], "-h") == 0) {
        printf("Usage: %s <socket_lower> <message> <destination_host>\n", argv[0]);
        return 0;
    }

    const char *socket_path = argv[1];
    const char *message = argv[2];
    uint8_t dest_host = atoi(argv[3]);
    uint8_t ttl = atoi(argv[4]);

    //unix socket
    int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    
    // Koble til mipd via UNIX-socketen
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    //registrerer SDU type melding, klienten starter med PING, 0x02
    uint8_t sdu_type = 0x02;
    if (write(sock, &sdu_type, 1) != 1) {
        perror("write sdu_type");
        close(sock);
        return 1;
    }
    // Lag melding: [dest_host][ttl][PING:<message>]
    char buf[BUF_SIZE];
    buf[0] = dest_host;
    buf[1] = ttl;
    snprintf((char*)&buf[2], BUF_SIZE - 2, "PING:%s", message);

    // Ta starttidspunkt (for RTT-måling)
    struct timeval start, end;
    gettimeofday(&start, NULL);

    // Send melding til mipd
    if (write(sock, buf, 2 + strlen((char*)&buf[2])) < 0) {
        perror("write");
        close(sock);
        return 1;
    }

    // Sett timeout på 1 sekund (venter på svar fra server)
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    struct timeval tv = {1, 0}; //endret til høyere

    int rv = select(sock + 1, &fds, NULL, NULL, &tv);
    if (rv == 0) {
        printf("timeout\n");
        close(sock);
        return 0;
    }

    //henter var hvis det er data å lese
    char reply[BUF_SIZE];
    int n = read(sock, reply, sizeof(reply) - 1);
    if (n > 0) {
        reply[n] = '\0';
        gettimeofday(&end, NULL);
        long ms = (end.tv_sec - start.tv_sec) * 1000000 +
                  (end.tv_usec - start.tv_usec);
        uint8_t src = reply[0];
        uint8_t ttl_reply = reply[1];

        printf("[PING_CLIENT] Reply from MIP %u (TTL=%u): %s (RTT=%ld ms)\n",
               src, ttl_reply, &reply[2], ms);
    } else {
        printf("client timeout\n");
    }

    close(sock);
    return 0;
}
