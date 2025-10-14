#ifndef ROUTINGD_H
#define ROUTINGD_H

#include <stdint.h>

// typedef struct {
//     uint8_t dest;
//     uint8_t next;
// } routing_entry;

#define MAX_ROUTES 12


// SDU-type er fortsatt 0x04 (routing). Interne msg-typer:
#define RT_MSG_HELLO   0x01 //payload 
#define RT_MSG_UPDATE  0x02 
#define RT_MSG_REQ     'Q'  // du bruker "R","E","Q" allerede
#define RT_MSG_RSP     'P'  // du bruker "R","S","P" allerede

#define INF_METRIC     255
#define HELLO_INTERVAL_MS   1000  // send HELLO hvert sekund
#define UPDATE_INTERVAL_MS  2000  // send UPDATE hvert 2. sekund
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

#define MAX_ROUTES   64
#define MAX_NEIGHBORS 16 //begrenset av størrelsen på nettet

static rt_entry  routing_table[MAX_ROUTES];
static neighbor  neighbors[MAX_NEIGHBORS];

static uint8_t MY_MIP = 0;   // sett fra argv (samme som du sender i REQUEST/RESPONSE)
static int ROUTING_SOCK = -1; // SOCK_SEQPACKET til mipd

//extern routing_entry routing_table[MAX_ROUTES];

//metoder
void handle_route_request(int sock, uint8_t *msg, ssize_t length);
void send_route_response(int sock, uint8_t my_address, uint8_t next);
int connect_to_mipd(const char *socket_path);
void wait_for_socket(const char *path);

void handle_hello();
void handle_update();

#endif