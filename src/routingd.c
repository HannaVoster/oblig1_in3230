
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
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "routingd.h"
#include "arp.h"

neighbor neighbors[MAX_NEIGHBORS];
rt_entry routing_table[MAX_ROUTES];   
uint8_t MY_MIP = 0;
int ROUTING_SOCK = -1;

int debug_mode = 0;
int main(int argc, char *argv[]) {
    // Håndterer -h og -d flagg
    int opt;
    while ((opt = getopt(argc, argv, "hd")) != -1) {
        switch(opt) {
            case 'h':
                printf("Usage: %s [-d] <unix_socket_path>\n", argv[0]);
                printf("Options:\n");
                printf("  -h  print help and exit\n");
                printf("  -d  enable debug mode\n");
                return 0;
            case 'd':
                debug_mode = 1;
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Usage: %s [-d] <unix_socket_path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *socket_path = argv[optind];
    printf("[ROUTINGD] Starting with socket path: %s\n", socket_path);
    // Vent på at mipd oppretter UNIX-socketen
    wait_for_socket(socket_path);
    printf("[ROUTINGD] Socket %s er nå tilgjengelig, kobler til...\n", socket_path);

    ROUTING_SOCK = connect_to_mipd(socket_path);
    if (ROUTING_SOCK < 0) {
        fprintf(stderr, "[ROUTINGD] Klarte ikke å koble til %s\n", socket_path);
        exit(EXIT_FAILURE);
    }

    printf("[ROUTINGD] epoll looop - Listening...\n");

    int epollfd = epoll_create1(0);

    if (epollfd < 0) {
        perror("epoll_create1");
        close(ROUTING_SOCK);
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = ROUTING_SOCK;

    //legger til instansen i epollfd (instansen fra tidligere)
    // EPOLL_CTL_ADD forteller instansen at socketen skal overvåkes
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ROUTING_SOCK, &ev) == -1) {
        perror("epoll_ctl: routing_sock");
        exit(EXIT_FAILURE);
    }

    // Tidsstyrte meldinger
    uint64_t last_hello = now_ms();
    uint64_t last_update = now_ms();

    // Hovedløkke for å håndtere meldinger fra mipd
    while (1) { 
        int n = epoll_wait(epollfd, events, MAX_EVENTS, 200); // 200 ms timeout

        if (n < 0) {
            perror("epoll_wait");
            break;
        }
        // Behandle hendelser fra epoll 
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == ROUTING_SOCK && (events[i].events & EPOLLIN)) {
                uint8_t buf[256];
                ssize_t len = read(ROUTING_SOCK, buf, sizeof(buf));
                if (len <= 0) {
                    printf("[ROUTINGD] Disconnected from MIPd\n");
                    goto cleanup;
                }
                uint8_t src = buf[0];
                uint8_t ttl = buf[1];

                if (len >= 6 && buf[2] == 'R' && buf[3] == 'E' && buf[4] == 'Q') {
                    handle_route_request(ROUTING_SOCK, buf, len);
                } else if (len >= 3) {
                    uint8_t msg_type = buf[2];
                    handle_incoming_message(src, msg_type, &buf[3], len - 3);
                }
            }
        }

        uint64_t now = now_ms();

        if (now - last_hello >= HELLO_INTERVAL_MS) {
            hello(); // broadcast HELLO
            last_hello = now;
        }

        if (now - last_update >= UPDATE_INTERVAL_MS) {
            periodic_update(); // send UPDATE (Poisoned Reverse)
            last_update = now;
        }
    }
    cleanup:
        close(epollfd);
        close(ROUTING_SOCK);
        printf("[ROUTINGD] Shutting down.\n");
        return 0;
}

int connect_to_mipd(const char *socket_path) {
    int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);

    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Lag unik lokal klientadresse (ellers kollisjon mellom routingd-prosesser)
    struct sockaddr_un client_addr = {0};
    client_addr.sun_family = AF_UNIX;
    snprintf(client_addr.sun_path, sizeof(client_addr.sun_path), "routingd_%d.sock", getpid());
    unlink(client_addr.sun_path);

    if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("bind client");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Koble til MIP-daemonens UNIX socket (f.eks. ./usockA)
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect to mipd");
        close(sock);
        exit(EXIT_FAILURE);
    }

    uint8_t sdu_type = SDU_TYPE_ROUTING;
    if (write(sock, &sdu_type, 1) != 1) {
        perror("register sdu_type");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Les min MIP-adresse fra mipd
    uint8_t my_addr;
    if (read(sock, &my_addr, 1) == 1) {
        MY_MIP = my_addr;
        printf("[ROUTINGD] Received MY_MIP = %d from MIPd\n", MY_MIP);
    } else {
        perror("read MY_MIP from MIPd");
    }

    printf("[ROUTINGD] Connected and registered to socket fd=%d (SDU=0x04)\n", sock);
    return sock;
}

void send_route_response(int sock, uint8_t my_address, uint8_t next){
    uint8_t rsp[6] = { my_address, 0, 'R', 'S', 'P', next }; //etter format fra oppgaven
    if (write(sock, rsp, sizeof(rsp)) != sizeof(rsp))
        perror("write response");
    else
        printf("[ROUTINGD] Sent RESPONSE: next hop =%d\n", next);    
}

void handle_route_request(int sock, uint8_t *msg, ssize_t length) {
    if (length < 6) { 
        fprintf(stderr, "..."); 
        return; 
    }

    uint8_t my_addr = msg[0];      // egen MIP (ekko fra MIPd)
    uint8_t dest    = msg[5];      // oppslagsdestinasjon

    uint8_t next = 255;            // 255 = ingen rute
    int id = get_route(dest);
    if (id >= 0 && routing_table[id].valid) {
        next = routing_table[id].next_hop;
    }
    send_route_response(sock, my_addr, next);
}

void wait_for_socket(const char *path) {
    struct stat sb;
    int tries = 0;
    while (stat(path, &sb) != 0) {
        if (tries++ > 50) {
            fprintf(stderr, "[ROUTINGD] Timeout waiting for socket %s\n", path);
            exit(EXIT_FAILURE);
        }
        usleep(100000); // 0.1 sek
    }
}

uint64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec/1000000;
}

//metode til å oppdage naboer med HELLO
//leter etter en nabo med en gitt mip addresse, og returnerer naboens index i nabolisten
//hvis naboen ikke finnes, sjekkes nabolisten og noden legges til som en ny entry
//håndterer også tilfelle der tabellen er full og returnerer -1
int find_or_add_neighbor(uint8_t mip){
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (neighbors[i].mip == mip) {
            return i;
        }
    }
    //hvis vi kommer hit - ikke funnet - legg til på ledig plass
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if(!neighbors[i].valid) {
            neighbors[i].mip = mip;
            neighbors[i].valid = 1;
            neighbors[i].last_hello_ms = now_ms(); //noterer tiden naboen ble registrert
            return i;
        }
    }

    return -1;
}
//metode til å finne en lagret rute
//går igjennom routing_table og returnerer indexen til dest hvis dest finnes
//p den måten kan deamonen sjekke at en rute er der før den sender en response om next hop
//hvis dest ikke funnes, returneres -1 . ingen repsonse sendes
int get_route(uint8_t dest) {
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (routing_table[i].dest == dest){
            return i;
        }
    }
    return -1; //ingen rute
}

//metode til å oppdattere eller lage en ny rute
int update_or_insert_neighbor(uint8_t dest, uint8_t next_hop, uint8_t cost){
    int id = get_route(dest);
    if (id < 0) { //ingen rute - lag ny
        for (int i = 0; i < MAX_ROUTES; i++){
            if(!routing_table[i].valid){
                id = i;
                break;
            }
        }
        if (id < 0) return -1; //ingen plass

        routing_table[id].valid = 1;
        routing_table[id].dest = dest;
    }
    //oppdatterer uansett - med neste hopp, kostnad og siste tidspunkt for oppdattering
    routing_table[id].next_hop = next_hop;
    routing_table[id].cost = cost;
    routing_table[id].updated_ms = now_ms();
    return id;
}

//generisk metode til å kommuniserer med MIPD over unix socket
int send_unix_message(uint8_t dest, uint8_t ttl, const uint8_t* data, size_t len) {
    uint8_t buf[256];
    if (len + 2 > sizeof(buf)) return -1;
    buf[0] = dest; 
    buf[1] = ttl; 
    memcpy(&buf[2], data, len);
    return write(ROUTING_SOCK, buf, len + 2);
}

//metode som sender HELLO meldinger 
void hello(void){
    uint8_t msg = RT_MSG_HELLO;
   
    send_unix_message(255, 1, &msg, 1);
}

void broadcast_update(void){
    uint8_t buf[256];
    size_t pos = 0;
    buf[pos++] = RT_MSG_UPDATE;

    for (int i = 0; i < MAX_ROUTES; i++) {
        if (routing_table[i].valid) {
            buf[pos++] = routing_table[i].dest;
            buf[pos++] = routing_table[i].cost;
        }
    }
    send_unix_message(255, 1, buf, pos);
    printf("[ROUTINGD] Sendte UPDATE med %zu ruter\n", pos / 2 - 1);
}

void handle_incoming_message(uint8_t from, uint8_t msg_type, const uint8_t *payload, size_t len){
    // lager en switch basert på meldingstype 
    switch(msg_type) {
        case RT_MSG_HELLO: {
            printf("[ROUTINGD] HELLO mottatt fra %d\n", from);

        // Finn nabo eller legg den til
            int id = find_or_add_neighbor(from);
            neighbors[id].last_hello_ms = now_ms();
            neighbors[id].valid = 1;

            // Oppdater routingtabellen: direkte nabo = cost 1
            update_or_insert_neighbor(from, from, 1);
            break;
        }

        case RT_MSG_UPDATE: {
            printf("[ROUTINGD] UPDATE mottatt fra %d (len=%zu)\n", from, len);
            // Oppdater naboen slik at vi vet at den lever
            int id = find_or_add_neighbor(from);
            neighbors[id].last_hello_ms = now_ms();

            // Parse ruter: 2 bytes per (dest, cost)
            int num_entries = len / 2;
            for (int i = 0; i < num_entries; i++) {
                uint8_t dest = payload[i * 2];
                uint8_t cost = payload[i * 2 + 1];

                if (dest == MY_MIP) continue; // ignorer ruter til deg selv (poison reverse)

                // Oppdater routing-tabellen
                update_or_insert_neighbor(dest, from, cost + 1);
            }

            break;
        }
        default: {
            printf("[ROUTINGD] Ukjent meldingstype 0x%02X fra %d\n", msg_type, from);
            break;
        }

    }
}
void send_update_to_neighbor(uint8_t neighbor_mip) {
    uint8_t buf[256]; 
    size_t pos = 0;
    buf[pos++] = RT_MSG_UPDATE;

    for (int i = 0; i < MAX_ROUTES; i++) {
        if (!routing_table[i].valid) continue;

        uint8_t adv_cost = routing_table[i].cost;

        if (routing_table[i].next_hop == neighbor_mip) {
            adv_cost = INF_COST; // Poisoned Reverse
        }

        buf[pos++] = routing_table[i].dest;
        buf[pos++] = adv_cost;
    }
    // send direkte til naboen (unicast), TTL=1
    send_unix_message(neighbor_mip, 1, buf, pos);
}

void periodic_update(void) {
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (neighbors[i].valid) {
            send_update_to_neighbor(neighbors[i].mip);
        }
    }
    printf("[ROUTINGD] Sent periodic UPDATE to %d neighbors\n", MAX_NEIGHBORS);
}
