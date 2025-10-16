
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


#include "routingd.h"
#include "arp.h"

neighbor neighbors[MAX_NEIGHBORS];
rt_entry routing_table[MAX_ROUTES];   
uint8_t MY_MIP = 0;
int ROUTING_SOCK = -1;

int connect_to_mipd() {
    int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock < 0) { perror("socket"); exit(EXIT_FAILURE); }

    // Lag unik klientadresse (ellers kolliderer routingd-prosesser)
    struct sockaddr_un client_addr = {0};
    client_addr.sun_family = AF_UNIX;
    snprintf(client_addr.sun_path, sizeof(client_addr.sun_path), "routingd_%d.sock", getpid());
    unlink(client_addr.sun_path);
    if (bind(sock, (struct sockaddr*)&client_addr, sizeof(client_addr)) < 0) {
        perror("bind client");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Forsøk å koble til lokal MIP-daemon (usockA–usockE)
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    const char *sockets[] = {
    "./usockA", "./usockB", "./usockC", "./usockD", "./usockE",
    "/tmp/usockA", "/tmp/usockB", "/tmp/usockC", "/tmp/usockD", "/tmp/usockE"
    };

    int connected = 0;
    const char *connected_sock = NULL;

    for (int i = 0; i < 10; i++) {
    strncpy(addr.sun_path, sockets[i], sizeof(addr.sun_path) - 1);
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        connected = 1;
        connected_sock = sockets[i];
        printf("[ROUTINGD] Connected to %s\n", sockets[i]);
        break;
    }
    }


    if (!connected) {
        fprintf(stderr, "[ROUTINGD] Could not connect to any local MIP socket\n");
        close(sock);
        exit(EXIT_FAILURE);
    }

    uint8_t sdu_type = SDU_TYPE_ROUTING;
    if (write(sock, &sdu_type, 1) != 1) {
        perror("register sdu_type");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("[ROUTINGD] Connected and registered to %s (SDU=0x04)\n", connected_sock);
    return sock;
}

// int idx = find_route(50);
// if (idx >= 0)
//     send_route_response(sock, MY_MIP, rtable[idx].next_hop);


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

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <unix_socket_path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *socket_path = argv[1];
    printf("[ROUTINGD] Starting with socket path: %s\n", socket_path);

    // Vent på at mipd oppretter UNIX-socketen
    wait_for_socket(socket_path);
    printf("[ROUTINGD] Socket %s er nå tilgjengelig, kobler til...\n", socket_path);

    int ROUTING_SOCK = connect_to_mipd(socket_path);
    if (ROUTING_SOCK < 0) {
        fprintf(stderr, "[ROUTINGD] Klarte ikke å koble til %s\n", socket_path);
        exit(EXIT_FAILURE);
    }

    printf("[ROUTINGD] Listening for route requests...\n");

    // Hovedløkke for å håndtere meldinger fra mipd
    while (1) {
        uint8_t buf[64];
        ssize_t length = read(ROUTING_SOCK, buf, sizeof(buf));

        if (length < 0) {
            perror("[ROUTINGD] read");
            break;
        } else if (length == 0) {
            printf("[ROUTINGD] Disconnected from mipd\n");
            break;
        }

        if (length >= 6 && buf[2] == 'R' && buf[3] == 'E' && buf[4] == 'Q') {
            // ROUTE REQUEST fra mipd
            printf("[ROUTINGD] Received REQUEST (dest=%u)\n", buf[5]);
            handle_route_request(ROUTING_SOCK, buf, length);
        } 
        else {
            // Ellers er det en routingmelding (HELLO/UPDATE)
            uint8_t from = buf[0];
            uint8_t msg_type = buf[1];
            handle_incoming_message(from, msg_type, &buf[2], length - 2);
        }
    }


    close(ROUTING_SOCK);
    printf("[ROUTINGD] Shutting down.\n");
    return 0;
}


#include <sys/stat.h>
#include <unistd.h>

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
    if (id > 0) { //ingen rute - lag ny
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
    uint8_t msg[2];
    msg[0] = MY_MIP;
    msg[1] = RT_MSG_HELLO;
   
    send_unix_message(255, 1, msg, 2);
}

void update(void){
    uint8_t buf[256];
    size_t pos = 0;
    buf[pos++] = MY_MIP;
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
