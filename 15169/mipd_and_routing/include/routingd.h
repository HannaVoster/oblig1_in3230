#ifndef ROUTINGD_H
#define ROUTINGD_H

#include <stdint.h>

#define MAX_ROUTES 12 //begrenset av størrelsen på topologien
#define MAX_EVENTS 10 // epoll

//hvor ofte hello og update sendes
#define HELLO_INTERVAL_MS 4000
#define UPDATE_INTERVAL_MS 6000

#define INF_COST 255 // brukes for å indikere ingen rute, poisoned reverse
#define SDU_TYPE_ROUTING 0x04 // samme for MIPD

//  Interne msg-typer:
#define RT_MSG_HELLO   0x01 //payload 
#define RT_MSG_UPDATE  0x02 

// Maks alder for gyldige naboer (i millisekunder)
#define NEIGHBOR_TIMEOUT_MS 15000
// Maks alder for ruter (i millisekunder)
#define ROUTE_TIMEOUT_MS 30000

// routing entry til routing tabellen
typedef struct {
    uint8_t dest;       // dest MIP
    uint8_t next_hop;   // next hop MIP
    uint8_t cost;     // hop-count (1 = direkte nabo)
    uint64_t updated_ms; // sist oppdatert
    int valid;
} rt_entry;

// nabo entry til nabolisten
typedef struct {
    uint8_t mip;        // naboens MIP-adresse
    uint64_t last_hello_ms; // sist gang man hørte fra naboen - 
                            // Brukes ikke per nå, men kan brukes til å "drepe" naboer man ikke har hørt fra
    int valid;
} neighbor;

#define MAX_NEIGHBORS 16 //begrenset av størrelsen på nettet

extern rt_entry routing_table[MAX_ROUTES]; //settes i routingd.c
extern neighbor neighbors[MAX_NEIGHBORS]; //settes i routingd.c

extern uint8_t MY_MIP;   // settes fra routing_socket.c i connect_to_mipd()
extern int ROUTING_SOCK; // SOCK_SEQPACKET til mipd
extern int debug_mode; //git som argument i main
extern int triggered_update;

uint64_t now_ms(void);

#endif