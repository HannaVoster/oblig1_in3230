#ifndef UNIX_H
#define UNIX_H

#include <stdint.h>
#include <stdlib.h>

#define MAX_UNIX_CLIENT 10 // maks antall unix klienter som kan være koblet på mipd samtidig

typedef struct {
    int fd; //fildeskriptor for unix socketen til denne klienten
    uint8_t sdu_type; //ping, pong, routing
    int active; //hvis klienten er koblet til = 1, hvis ikke = 0
} unix_client;

//liste over unix klienter
// defineres i unix.c
extern unix_client unix_clients[MAX_UNIX_CLIENT];

int create_unix_socket(const char *path);
void handle_unix_request(int client_fd, int raw_sock, int my_mip_address);

void handle_route_response(int raw_sock, uint8_t next);
void send_routing_packet(int raw_sock, uint8_t my_mip, uint8_t *payload, size_t len);

void process_unix_message(int raw_sock, uint8_t dest_addr, uint8_t ttl, uint8_t sdu_type, 
        uint8_t *payload, size_t payload_length, int my_mip_address);

#endif