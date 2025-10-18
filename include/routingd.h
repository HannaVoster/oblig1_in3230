#ifndef ROUTINGD_H
#define ROUTINGD_H

#include <stdint.h>

// typedef struct {
//     uint8_t dest;
//     uint8_t next;
// } routing_entry;

#define MAX_ROUTES 12
#define MAX_EVENTS 10 // epoll
#define HELLO_INTERVAL_MS 1000
#define UPDATE_INTERVAL_MS 5000
#define INF_COST 255

// SDU-type er fortsatt 0x04 (routing). Interne msg-typer:
#define RT_MSG_HELLO   0x01 //payload 
#define RT_MSG_UPDATE  0x02 
#define RT_MSG_REQ     'Q'  // du bruker "R","E","Q" allerede
#define RT_MSG_RSP     'P'  // du bruker "R","S","P" allerede

#define NEIGHBOR_DEAD_MS    4000  // nabo død hvis ikke hørt på 4s
#define ROUTE_EXPIRE_MS     12000 // rute utgår hvis ikke fornyet

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

extern rt_entry  routing_table[MAX_ROUTES];
extern neighbor  neighbors[MAX_NEIGHBORS];

extern uint8_t MY_MIP;   // sett fra argv (samme som du sender i REQUEST/RESPONSE)
extern int ROUTING_SOCK; // SOCK_SEQPACKET til mipd

//extern routing_entry routing_table[MAX_ROUTES];

//metoder
void handle_route_request(int sock, uint8_t *msg, ssize_t length);
void send_route_response(int sock, uint8_t my_address, uint8_t next);
int connect_to_mipd(const char *socket_path);
void wait_for_socket(const char *path);


void hello(void);
int send_unix_message(uint8_t dest, uint8_t ttl, const uint8_t* data, size_t len);
int update_or_insert_neighbor(uint8_t dest, uint8_t next_hop, uint8_t cost);
int get_route(uint8_t dest);
int find_or_add_neighbor(uint8_t mip);
void handle_incoming_message(uint8_t from, uint8_t msg_type, const uint8_t *payload, size_t len);
void broadcast_update(void);

void send_update_to_neighbor(uint8_t neighbor_mip);
uint64_t now_ms(void);
void periodic_update(void);

#endif