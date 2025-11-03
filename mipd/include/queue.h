#ifndef QUEUE_H
#define QUEUE_H

#include <stdint.h>
#include <stddef.h>

//til å legge pakker i kø, begrenser størrelsen på meldingskøen
#define MAX_PENDING 20
#define MAX_ROUTE_WAIT 16 //hvor mange pakker som kan ligge i routing kø, route_wait_queue

// struktur som holder på meldinger i køen, klar til å bygge og sende pdu senere
typedef struct { 
    uint8_t ultimate_dest;
    uint8_t next; // ikke sikkert neste er samme som ultimate_dest (routing)
    uint8_t src;
    uint8_t ttl;
    uint8_t sdu_type;
    uint8_t *payload;
    size_t length;
    int valid;
} pending_entry;

extern pending_entry pending_queue[MAX_PENDING];
extern pending_entry route_wait_queue[MAX_ROUTE_WAIT];

//metoder
void queue_message(uint8_t ultimate_dest, uint8_t next_hop,
                   uint8_t src, uint8_t ttl,
                   uint8_t sdu_type, uint8_t *data, size_t length_bytes);

void send_pending_messages(int raw_sock, uint8_t mip_addr,unsigned char *mac, int if_index);

void send_route_request(int routing_fd, uint8_t my_addr, uint8_t dest);

void queue_routing_message(uint8_t dest, uint8_t src, uint8_t ttl, 
    uint8_t sdu_type, const uint8_t *sdu, size_t sdu_len);

#endif