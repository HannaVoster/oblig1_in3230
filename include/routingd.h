#ifndef ROUTINGD_H
#define ROUTINGD_H

#include <stdint.h>

#define MAX_ROUTES 12
#define MAX_EVENTS 10 // epoll
#define HELLO_INTERVAL_MS 4000
#define UPDATE_INTERVAL_MS 6000
#define INF_COST 255

// SDU-type er fortsatt 0x04 (routing). Interne msg-typer:
#define RT_MSG_HELLO   0x01 //payload 
#define RT_MSG_UPDATE  0x02 

typedef struct {
    uint8_t dest;       // dest MIP
    uint8_t next_hop;   // next hop MIP
    uint8_t cost;     // hop-count (1 = direkte nabo)
    uint64_t updated_ms; // sist oppdatert
    int valid;
} rt_entry;

typedef struct {
    uint8_t mip;        // naboens MIP-adresse
    uint64_t last_hello_ms;
    int valid;
} neighbor;

#define MAX_NEIGHBORS 16 //begrenset av størrelsen på nettet

extern rt_entry routing_table[MAX_ROUTES];
extern neighbor neighbors[MAX_NEIGHBORS];

extern uint8_t MY_MIP;   // sett fra argv 
extern int ROUTING_SOCK; // SOCK_SEQPACKET til mipd

uint64_t now_ms(void);

#endif