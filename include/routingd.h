#ifndef ROUTINGD_H
#define ROUTINGD_H

#include <stdint.h>

typedef struct {
    uint8_t dest;
    uint8_t next;
} routing_entry;

#define MAX_ROUTES 12

#define SDU_TYPE_ROUTING 0x04

extern routing_entry routing_table[MAX_ROUTES];

//metoder
void handle_route_request(int sock, uint8_t *msg, ssize_t length);
void send_route_response(int sock, uint8_t my_address, uint8_t next);
int connect_to_mipd(const char *socket_path);

void handle_hello();
void handle_update();

#endif