
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

    // Lag UNIX socket
    if ((sock = socket(AF_UNIX, SOCK_SEQPACKET, 0)) == -1) {
        perror("unix socket");
        exit(EXIT_FAILURE);
    }

    // Nullstill adressestruktur
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    // Bygg full sti (plasser socketen i /tmp/)
    char full_path[108];
    if (path[0] != '/') {
        snprintf(full_path, sizeof(full_path), "/tmp/%s", path);
    } else {
        strncpy(full_path, path, sizeof(full_path) - 1);
        full_path[sizeof(full_path) - 1] = '\0';
    }

    if (debug_mode) {
        fprintf(stderr, "[MIPD] Binding UNIX socket at: %s\n", full_path);
        fflush(stderr);
    }

    // Fjern gammel socket-fil om den finnes
    unlink(full_path);

    // Sett socket path
    strncpy(addr.sun_path, full_path, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    // Bind socket
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind unix");
        exit(EXIT_FAILURE);
    }

    // Lytt på socket
    if (listen(sock, 5) == -1) {
        perror("listen unix");
        exit(EXIT_FAILURE);
    }
    return sock;
}

/*
Brukes av handle_unix_message() til å prossessere unix meldinger

  Hvis man allerede vet MAC-adressen til mottakeren (fra ARP-cache),
  sendes meldingen direkte over nettverket via RAW-socket - send_pdu()
 
  Hvis man ikke kjenner MAC-adressen, legges meldingen i kø - queue_routing_message()
  og det sendes en forespørsel til routing-daemonen for å finne ruten videre - send_route_request()

*/
void process_unix_message(int raw_sock, uint8_t dest_addr, uint8_t ttl,
                          uint8_t sdu_type, uint8_t *payload, size_t payload_length, int my_mip_address) {
    unsigned char mac[6];
    int ifindex = -1;

    // Sjekker om man allerede vet MAC-adressen til destinasjonen (fra ARP-cache)
    if (arp_lookup(dest_addr, mac, &ifindex)) {
        //treff
        size_t pdu_len;
        uint8_t *pdu = mip_build_pdu(dest_addr, my_mip_address, ttl, sdu_type, payload, payload_length, &pdu_len);
        
        // Sendes via RAW-socket til riktig interface og MAC
        send_pdu(raw_sock, pdu, pdu_len, mac, ifindex);
        free(pdu); 

    } else {
        // Ingen ARP-treff - vet ikke hvordan man skal nå destinasjonen

        // Legger meldingen i kø til man får en rute
        queue_routing_message(dest_addr, my_mip_address, ttl, sdu_type, payload, payload_length);
        
        // Finn routing-daemonen blant UNIX-klientene
        // sender en route request så routing deamonen kan svare med riktig rute (next_hop)
        for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
            if (unix_clients[i].active && unix_clients[i].sdu_type == SDU_TYPE_ROUTING) {
                send_route_request(unix_clients[i].fd, my_mip_address, dest_addr);

                if (debug_mode)
                printf("[UNIX][ROUTING] Sent route request for dest %u\n", dest_addr);
                return;
            }
        }
    }
}

/*
Håndterer meldinger som kommer fra UNIX-klienter (som ping_client, ping_server, routingd)
Leser meldingen fra socketen, finner ut hvilken type SDU (meldingstype) det er, og sender
den videre via nettverket (raw socket) eller til routingd om nødvendig

Kalles av main i mipd.c til å håndtere klient meldinger som kommer over UNIX socket
*/

void handle_unix_request(int client_fd, int raw_sock, int my_mip_address) {

    char buffer[256];
    int bytes_read = read(client_fd, buffer, sizeof(buffer)); // leser data fra UNIX-klienten

    if (bytes_read <= 0) {
        // Klienten koblet fra
        for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
            if (unix_clients[i].active && unix_clients[i].fd == client_fd) {
                unix_clients[i].active = 0;
                close(client_fd); // lukk socketen
                if (debug_mode)
                    printf("[UNIX] Client fd=%d disconnected\n", client_fd);
                break;
            }
        }
        return;
    }
    // Finn hvilken SDU-type, hvilken app som snakker med mipd
    uint8_t sdu_type = 0;
    for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
        if (unix_clients[i].active && unix_clients[i].fd == client_fd) {
            sdu_type = unix_clients[i].sdu_type;
            break;
        }
    }
   
    // Meldingsformat: [dest:1][ttl:1][payload], gitt av oppgaven, kompatibel med appene
    if (bytes_read < 2) { //for kort melding
        fprintf(stderr, "[UNIX] Invalid message: too short\n");
        fflush(stdout);
        return;
    }

    // Pakker ut feltene fra meldingen
    uint8_t dest_addr = buffer[0]; //dest MIP addresse
    uint8_t ttl = buffer[1]; 
    uint8_t *payload = (uint8_t *)&buffer[2]; // resten av meldingen, selve dataen
    size_t payload_length = bytes_read - 2; 

    if (debug_mode) {
        printf("[UNIX] Message from fd=%d (type=0x%02X) dest=%d ttl=%d len=%zu\n",
               client_fd, sdu_type, dest_addr, ttl, payload_length);
    }
    // Håndter PING (0x02) og PONG (0x03), behandles likt
    if (sdu_type == SDU_TYPE_PING || sdu_type == SDU_TYPE_PONG) {
        process_unix_message(raw_sock, dest_addr, ttl, sdu_type, payload, payload_length, my_mip_address);
        return;
    }

    // Håndter meldinger fra routing-daemonen
    if (sdu_type == SDU_TYPE_ROUTING) {
        uint8_t ttl = buffer[1];
        uint8_t *payload = &buffer[2];
        size_t len = bytes_read - 2;

        //index 0 i payload viser hvilket intern sdu type routing deamonen satt (hello, update evt 'R' fra 'R''E''Q')
        uint8_t routing_type = payload[0];

        switch(routing_type){
            case 0x01:
            case 0x02:
                send_routing_packet(raw_sock, my_mip_address, payload, len);
                return;

            case 'R':
                uint8_t next = buffer[5];
                handle_route_response(raw_sock, next);
        }
        return;
    }
    unsigned char mac[6];
    int ifindex = -1;

    // Alle andre meldinger håndteres likt (sendes videre eller legges i køen)
    process_unix_message(raw_sock, dest_addr, ttl, sdu_type, payload, payload_length, my_mip_address);
    return;
}

// Hjelpemetode som brukes til å sende routing pakker (enten hello eller update) ut på nettverket
// så andre noder i nettverket får oppdattert rutetabellene (update) sine og oppdaget naboer (hello)
void send_routing_packet(int raw_sock, uint8_t my_mip, uint8_t *payload, size_t len) {
    unsigned char broadcast_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

    size_t pdu_len;
    // Bygg MIP-PDU for routing-pakken
    // dest = 255 (broadcast MIP-adresse)
    uint8_t *pdu = mip_build_pdu(255, my_mip, 1, SDU_TYPE_ROUTING, payload, len, &pdu_len);

    // Sender pakken ut på alle grensesnitt
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

// Metode som håndtere en RSP fra routing deamonen
// Metoden sjekker først om det er en gyldig rute, 255 = ikke gyldig -> droppes
// Hvis det er en gyldig rute går metoden gjennom køstrukturen for routing pakker og sender den første gyldige (valid)
// Sjekker først om addressen ligger i arp cashen og sender en arp request hvis den ikke finnes
void handle_route_response(int raw_sock, uint8_t next){

    if(debug_mode) printf("[ROUTING] RESPONSE mottatt: next_hop=%d\n", next);

    //sjekker of next = 255 for da er ingen rute funnet
    if (next == 255) {
        if(debug_mode) printf("[ROUTING] Ingen rute funnet — dropper pakke.\n");
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
            uint8_t *payload = route_wait_queue[i].payload;
            size_t length = route_wait_queue[i].length;
            
            //sjekker i arp tabellen om man har addressen til neste hopp
            unsigned char mac[6];
            int ifindex = -1;

            if (arp_lookup(next, mac, &ifindex)) {
                //treff - addressen finnes - bygger og sender pdu
                size_t new_pdu_length;
                uint8_t *new_pdu = mip_build_pdu(dest, src, ttl, sdu_type, payload, length, &new_pdu_length);

                send_pdu(raw_sock, new_pdu, new_pdu_length, mac, ifindex);
                free(new_pdu);
                
                printf("[ROUTING] Sendte pakke til next_hop=%d (dest=%d)\n",
                    next, dest);
            }
            //hvis ikke - mac finnes ikke for neste hopp og må sende arp req
            else{
                if(debug_mode) printf("[DEBUG][ROUTING] Har ikke MAC for next hop, queue_message kalles og det sendes arp request: dest=%d next=%d src=%d ttl=%d type=%d len=%zu\n",
                        dest, next, src, ttl, sdu_type, length);

                queue_message(dest, next, src, ttl, sdu_type, payload, length);
                send_arp_request(raw_sock, next, my_mip_address);
            }

            free(route_wait_queue[i].payload);
            route_wait_queue[i].valid = 0;
            return;
        }
    }
    printf("[ROUTING] Ingen ventende pakker — ignorerer RESPONSE.\n");
}

