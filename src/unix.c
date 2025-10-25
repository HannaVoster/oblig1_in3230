
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>


#include "mipd.h"
#include "arp.h"
#include "pdu.h"
#include "queue.h"
#include "iface.h"
#include "routingd.h"
#include "unix.h"

//#define MAX_PING_PAYLOAD 512

unix_client unix_clients[MAX_UNIX_CLIENT];

/*
- create_unix_socket
oppretter en UNIX-socket på en gitt filbane gitt som argument - path. 
Den binder socketen til adressen, sørger for at en eventuell gammel socket-fil slettes,
og setter den i lyttemodus slik at klienter kan koble seg til. 
returnerer filbeskriveren for socketen, eller avslutter programmet hvis noe feiler
*/

int create_unix_socket(const char *path) {
    int sock;
    struct sockaddr_un addr;

    //lager en unix socket, stopper programmet hvis en feil skjer
    if ((sock = socket(AF_UNIX, SOCK_SEQPACKET, 0)) == -1) {
        perror("unix socket");
        exit(EXIT_FAILURE);
    }

    //nullstiller struct for adressen til socketen
    memset(&addr, 0, sizeof(addr));
    //socket type: UNIX
    addr.sun_family = AF_UNIX;

    //kopierer UNIX_PATH som adressen
    strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);

    //sletter eventuel gammel fil med samme navn fra tidligere kjøring
    unlink(path); 

    printf("[MIPD] Binding UNIX socket at: %s\n", path);


    //kobler socketen til adddressen i addr, slik at klientet kan koble seg på den gjemnnom filbanen
    //typecaster (struct sockaddr*)&addr så bind() skjønner at det sendes en generisk socket addresse
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind unix");
        exit(EXIT_FAILURE);
    }

    //setter socketen i lyttemodus, klar til å ta imot klienter (maks 5 i kø)
    if (listen(sock, 5) == -1) {
        perror("listen unix");
        exit(EXIT_FAILURE);
    }

    return sock;
}


/*
- handle_unix_request
Håndterer forespørsler som kommer fra klient programmer (ping_client).
tar inn unic_sock som er fildeskriptor for socketen
raw_sock som er fildeskriptor for raw socket som brukes til å for sende 
pakker på nettverket (send_pdu)
og my_mip_address som er adressen til noden

Leser melding fra klienten, første byte er dest_addr og resten payload
dest_addr sjekkes opp mot arp cashe, og pakken håndteres ulikt avhengig av om mac er lagret

miss - bygg pakke, legg i kø og send broadcast arp req for å finne mottaker

hit - har riktig mac, kan sende PING
*/
void handle_unix_request(int client_fd, int raw_sock, int my_mip_address) {
    char buffer[256];
    int bytes_read = read(client_fd, buffer, sizeof(buffer));

    if (bytes_read <= 0) {
        // Klienten koblet fra
        for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
            if (unix_clients[i].active && unix_clients[i].fd == client_fd) {
                unix_clients[i].active = 0;
                close(client_fd);
                if (debug_mode)
                    printf("[UNIX] Client fd=%d disconnected\n", client_fd);
                break;
            }
        }
        return;
    }
    // Finn hvilken SDU-type, se hvilken app som snakker med mipd
    uint8_t sdu_type = 0;
    for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
        if (unix_clients[i].active && unix_clients[i].fd == client_fd) {
            sdu_type = unix_clients[i].sdu_type;
            break;
        }
    }
    // Meldingsformat: [dest:1][ttl:1][payload]
    if (bytes_read < 2) {
        fprintf(stderr, "[UNIX] Invalid message: too short\n");
        return;
    }

    uint8_t dest_addr = buffer[0];
    uint8_t ttl = buffer[1];
    uint8_t *payload = (uint8_t *)&buffer[2];
    size_t payload_length = bytes_read - 2;

    if (debug_mode) {
        printf("[UNIX] Message from fd=%d (type=0x%02X) dest=%d ttl=%d len=%zu\n",
               client_fd, sdu_type, dest_addr, ttl, payload_length);
    }
    if (sdu_type == SDU_TYPE_ROUTING) {
        uint8_t ttl = buffer[1];
        uint8_t *payload = &buffer[2];
        size_t len = bytes_read - 2;

        //index 0 i payload viser hvilket intern sdu type routing deamonen satt
        uint8_t routing_type = payload[0];

        switch(routing_type){
            case 0x01:
                send_routing_packet(raw_sock, my_mip_address, payload, len, "HELLO");
                return;

            case 0x02:
                send_routing_packet(raw_sock, my_mip_address, payload, len, "UPDATE");
                return;
            
            case 'R':
                uint8_t next = buffer[5];
                handle_route_response(raw_sock, next);
        }
        return;
    }
    unsigned char mac[6];
    int ifindex = -1;

    if (arp_lookup(dest_addr, mac, &ifindex)) {
        size_t pdu_len;
        uint8_t *pdu = mip_build_pdu(dest_addr, my_mip_address, ttl,
                                     sdu_type, payload, payload_length, &pdu_len);
        send_pdu(raw_sock, pdu, pdu_len, mac, ifindex);
        free(pdu);
        return;
    } 

    queue_routing_message(dest_addr, my_mip_address, ttl, sdu_type, payload, payload_length);

    // Finn routingd blant UNIX-klientene
    for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
        if (unix_clients[i].active && unix_clients[i].sdu_type == SDU_TYPE_ROUTING) {
            send_route_request(unix_clients[i].fd, my_mip_address, dest_addr);
            if (debug_mode)
            printf("[UNIX][ROUTING] Sent route request for dest %u\n", dest_addr);
            return;
        }
    }
    printf("[UNIX][ROUTING] Ingen routingd aktiv — kan ikke finne rute.\n");
}


void handle_ping_server_message(int client, char *buffer, int bytes_read) {
    if (bytes_read < 2){
        printf("[ERROR] unix msg too short");
        return;
    }

    uint8_t src = buffer[0];
    uint8_t ttl = buffer[1];
    uint8_t *payload = (uint8_t *)&buffer[2];
    size_t payload_length = bytes_read - 2;

    uint8_t reply[256];
    //bygger UNIX melding, src, ttl, payload
    reply[0] = src;
    reply[1] = ttl;
    memcpy(&reply[2], payload, payload_length);

    size_t total_len = payload_length + 2;

    if (write(client, reply, total_len) < 0) {
        perror("[ERROR] write to ping_server failed");
    }

    if (debug_mode) {
        printf("[DEBUG] Sent PING to server app (src=%u ttl=%u, len=%zu)\n",
               src, ttl, payload_length);
    }

    close(client);
}

void send_routing_packet(int raw_sock, uint8_t my_mip, uint8_t *payload, size_t len, const char *type_str) {
    unsigned char broadcast_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    //FIKS ikke -1 her
    size_t pdu_len;
    uint8_t *pdu = mip_build_pdu(255, my_mip, 1, SDU_TYPE_ROUTING, payload, len, &pdu_len);

    //printf("[MIPD][ROUTING] Sendte %s broadcast (len=%zu)\n", type_str, len);

    // Send ARP-REQ på alle ikke-loopback interfaces
    for (int i = 0; i < iface_count; i++) {
        int ifindex = iface_indices[i];

        char ifname[IFNAMSIZ];
        if_indextoname(ifindex, ifname);
        if (strncmp(ifname, "lo", 2) == 0) continue; // hopp over loopback

        // Hent MAC til dette interfacet
        unsigned char src_mac[ETH_ALEN];
        if (get_iface_mac(ifname, src_mac) < 0) {
            perror("get_iface_mac");
            continue;
        }

        send_pdu(raw_sock, pdu, pdu_len, broadcast_mac, ifindex);
    }
    free(pdu);
}

void handle_route_response(int raw_sock, uint8_t next){

    printf("[ROUTING] RESPONSE mottatt: next_hop=%d\n", next);
    //sjekker of next = 255 for da er ingen rute funnet
    if (next == 255) {
        printf("[ROUTING] Ingen rute funnet — dropper pakke.\n");
        return;
    }

    //går igjennom køen av finner første pakke i kø
    //oppgaven sier at routing deamon skal håndtere pakker i rekkefølgen de kommer i
    //så første gyldige pakke i køen vil være den svaret gjelder for
    for (int i = 0; i < MAX_ROUTE_WAIT; i++){
        if (route_wait_queue[i].valid) {
            //lagrer verdiene for pakken som skal sendes
            uint8_t dest = route_wait_queue[i].ultimate_dest;
            uint8_t src = route_wait_queue[i].src;
            uint8_t ttl = route_wait_queue[i].ttl;
            uint8_t sdu_type = route_wait_queue[i].sdu_type;
            uint8_t *sdu = route_wait_queue[i].sdu;
            size_t sdu_len = route_wait_queue[i].sdu_len;
            
            //sjekker i arp tabellen om vi har addressen til neste
            unsigned char mac[6];
            int ifindex = -1;
            if (arp_lookup(next, mac, &ifindex)) {
                //treff - addressen finnes - bygg og send pdu
                size_t new_pdu_length;
                uint8_t *new_pdu = mip_build_pdu(dest, src, ttl, sdu_type, sdu, sdu_len, &new_pdu_length);
                send_pdu(raw_sock, new_pdu, new_pdu_length, mac, ifindex);
                free(new_pdu);
                printf("[ROUTING] Sendte pakke til next_hop=%d (dest=%d)\n",
                    next, dest);
            }
            //hvis ikke - mac finnes ikke for neste hopp og må sende arp req
            else{
                printf("[ROUTING] Har ikke MAC for next hop=%d, sender ARP\n", next);
                printf("[DEBUG][ROUTING] queue_message kalles: dest=%d next=%d src=%d ttl=%d type=%d len=%zu\n",
                 dest, next, src, ttl, sdu_type, sdu_len);
                queue_message(dest, next, src, ttl, sdu_type, sdu, sdu_len);
                send_arp_request(raw_sock, next, my_mip_address);
            }

            free(route_wait_queue[i].sdu);
            route_wait_queue[i].valid = 0;
            return;
        }
    }
    printf("[ROUTING] Ingen ventende pakker — ignorerer RESPONSE.\n");
}

