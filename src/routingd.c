
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

    //SENDER SDU TYPE VED OPPSTART, for å vise at vi er en routing klinet med sdu_type 0x04
    uint8_t sdu_type = SDU_TYPE_ROUTING;
    if (write(sock, &sdu_type, 1) != 1) {
        perror("register sdu_type");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("[ROUTINGD] Connected and registered to %s (SDU=0x04)\n", socket_path);
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

int main(int argc, char *argv[]){
    if (argc != 2){
        exit(EXIT_FAILURE);
    }

    int sock = connect_to_mipd(argv[1]);

    //while løkke
    while (1)
    {
        uint8_t buf[64];
        ssize_t length = read(sock, buf, sizeof(buf));
        if (length > 0){
            if(buf[2] == 'R' && buf[3] == 'E' && buf[4] == 'Q') { //request mld
                handle_route_request(sock, buf, length); // sender videre 
                printf("[ROUTINGD] sending------\n");
            }
            else if(length == 0){
                printf("[ROUTINGD] Disconnected from mipd\n");
                break;
            }
            else {
                perror("read");
                break;
            }
        }
    }
     //lukker socket
    close(sock);
    return 0;
}
   

