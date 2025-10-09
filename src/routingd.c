
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

int connect_to_mipd(const char *socket_path[]) {
 
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

    //sender sdu type, for å vise at vi er en routing klinet med sdu_type 0x04
    uint8_t sdu_type = SDU_TYPE_ROUTING;
    if (write(fd, &sdu_type, 1) != 1) {
        perror("register sdu_type");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("[ROUTINGD] Connected and registered to %s (SDU=0x04)\n", socket_path);
    return fd;

}

void send_route_response(){}

void hanlde_route_request(){}

int main(int argc, char *argv[]){
    if (argc != 2) {
        exit(EXIT_FAILURE);
    }

    int sock = connect_to_mipd(argv[1]);
}