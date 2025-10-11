
//ROUTING DEAMON
/*
skal koble seg til mipd gjennom UNIX socket,
registrere seg som en klient
ha sdu type 0x04
gi en route respons
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "routingd.h"
#include "arp.h"

int connect_to_mipd(const char *socket_path) {
    int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock < 0) { perror("socket"); exit(EXIT_FAILURE); }

    // Lag unik klientadresse (ellers kolliderer routingd-prosesser)
    struct sockaddr_un client_addr = {0};
    client_addr.sun_family = AF_UNIX;
    snprintf(client_addr.sun_path, sizeof(client_addr.sun_path), "routingd_%d.sock", getpid());
    unlink(client_addr.sun_path);
    if (bind(sock, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
        perror("bind client");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Forsøk å koble til lokal MIP-daemon (usockA–usockE)
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    const char *sockets[] = {
    "./usockA", "./usockB", "./usockC", "./usockD", "./usockE",
    "/tmp/usockA", "/tmp/usockB", "/tmp/usockC", "/tmp/usockD", "/tmp/usockE"
    };

    int connected = 0;
    const char *connected_sock = NULL;

    for (int i = 0; i < 10; i++) {
    strncpy(addr.sun_path, sockets[i], sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        connected = 1;
        connected_sock = sockets[i];
        printf("[ROUTINGD] Connected to %s\n", sockets[i]);
        break;
    }
    }


    if (!connected) {
        fprintf(stderr, "[ROUTINGD] Could not connect to any local MIP socket\n");
        close(sock);
        exit(EXIT_FAILURE);
    }

    uint8_t sdu_type = SDU_TYPE_ROUTING;
    if (write(sock, &sdu_type, 1) != 1) {
        perror("register sdu_type");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("[ROUTINGD] Connected and registered to %s (SDU=0x04)\n", connected_sock);
    return sock;
}



void send_route_response(int sock, uint8_t my_address, uint8_t next){
    uint8_t rsp[6] = { my_address, 0, 'R', 'S', 'P', next }; //etter format fra oppgaven
    if (write(sock, rsp, sizeof(rsp)) != sizeof(rsp))
        perror("write response");
    else
        printf("[ROUTINGD] Sent RESPONSE: next hop =%d\n", next);    
}

void handle_route_request(int sock, uint8_t *msg, ssize_t length){
    if(length < 6){
        printf("[ROUTINGD] Invalid REQUEST message length: %zd\n", length);
        return;
    }

    uint8_t my_address = msg[0];
    //uint8_t dest = msg[5];

    /* Dummy next hop  */
    uint8_t next = 20;
    send_route_response(sock, my_address, next);

}

void handle_hello(){}
void handle_update(){}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <unix_socket_path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *socket_path = argv[1];
    printf("[ROUTINGD] Starting with socket path: %s\n", socket_path);

    // Vent på at mipd oppretter UNIX-socketen
    wait_for_socket(socket_path);
    printf("[ROUTINGD] Socket %s er nå tilgjengelig, kobler til...\n", socket_path);

    int sock = connect_to_mipd(socket_path);
    if (sock < 0) {
        fprintf(stderr, "[ROUTINGD] Klarte ikke å koble til %s\n", socket_path);
        exit(EXIT_FAILURE);
    }

    printf("[ROUTINGD] Listening for route requests...\n");

    // Hovedløkke for å håndtere meldinger fra mipd
    while (1) {
        uint8_t buf[64];
        ssize_t length = read(sock, buf, sizeof(buf));

        if (length < 0) {
            perror("[ROUTINGD] read");
            break;
        } else if (length == 0) {
            printf("[ROUTINGD] Disconnected from mipd\n");
            break;
        }

        // Debug: vis hva som kom inn
        printf("[ROUTINGD] Received %zd bytes: [%02X %02X %02X %02X %02X %02X]\n",
               length, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);

        // Sjekk for ROUTE REQUEST
        if (length >= 6 && buf[2] == 'R' && buf[3] == 'E' && buf[4] == 'Q') {
            printf("[ROUTINGD] Received REQUEST (dest=%u)\n", buf[5]);
            handle_route_request(sock, buf, length);
        }
    }

    close(sock);
    printf("[ROUTINGD] Shutting down.\n");
    return 0;
}


#include <sys/stat.h>
#include <unistd.h>

void wait_for_socket(const char *path) {
    struct stat sb;
    int tries = 0;
    while (stat(path, &sb) != 0) {
        if (tries++ > 50) {
            fprintf(stderr, "[ROUTINGD] Timeout waiting for socket %s\n", path);
            exit(EXIT_FAILURE);
        }
        usleep(100000); // 0.1 sek
    }
}

   

