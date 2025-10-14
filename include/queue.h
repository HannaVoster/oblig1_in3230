#ifndef QUEUE_H
#define QUEUE_H

#include <stdint.h>
#include <stddef.h>

//til å legge pakker i kø
#define MAX_PENDING 20

typedef struct { //hvor er ttl og src her?
    uint8_t ultimate_dest;
    uint8_t next; //til arp
    uint8_t src;
    uint8_t ttl;
    uint8_t sdu_type;
    uint8_t *payload;
    size_t length;
    int valid;
} pending_entry;

extern pending_entry pending_queue[MAX_PENDING];


#define MAX_ROUTE_WAIT 16
typedef struct {
    uint8_t ultimate_dest;
    uint8_t next;
    uint8_t src;
    uint8_t ttl;
    uint8_t sdu_type;
    uint8_t *sdu;
    size_t sdu_len;
    int valid;
} route_wait;

extern route_wait route_wait_queue[MAX_ROUTE_WAIT];

//metoder
void queue_message(uint8_t ultimate_dest, uint8_t next_hop,
                   uint8_t src, uint8_t ttl,
                   uint8_t sdu_type, uint8_t *data, size_t length_bytes);

void send_pending_messages(int raw_sock, uint8_t mip_addr,unsigned char *mac, int my_mip_address);

void send_route_request(int routing_fd, uint8_t my_addr, uint8_t dest);

void queue_routing_message(uint8_t dest, uint8_t src, uint8_t ttl, 
    uint8_t sdu_type, const uint8_t *sdu, size_t sdu_len);

#endif