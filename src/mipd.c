#include <stdio.h>         
#include <stdlib.h>        
#include <string.h>       
#include <unistd.h>        
#include <sys/epoll.h>      
#include <sys/socket.h>     
#include <sys/un.h>         
#include <sys/ioctl.h>      
#include <netpacket/packet.h> 
#include <net/ethernet.h>  
#include <net/if.h>       
#include <arpa/inet.h>      
#include <netinet/if_ether.h> 
#include <ifaddrs.h>       

#include "mipd.h"
#include "pdu.h"
#include "arp.h"
#include "routingd.h"
#include "iface.h"
#include "queue.h"


/*
- create_unix_socket
oppretter en UNIX-socket på en gitt filbane gitt som argument - path. 
Den binder socketen til adressen, sørger for at en eventuell gammel socket-fil slettes,
og setter den i lyttemodus slik at klienter kan koble seg til. 
returnerer filbeskriveren for socketen, eller avslutter programmet hvis noe feiler
*/

#define MAX_PING_PAYLOAD 512
unix_client unix_clients[MAX_UNIX_CLIENT];


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
    //prover

    // Finn hvilken SDU-type denne klienten har
    uint8_t sdu_type = 0;
    for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
        if (unix_clients[i].active && unix_clients[i].fd == client_fd) {
            sdu_type = unix_clients[i].sdu_type;
            break;
        }
    }

    if (sdu_type == SDU_TYPE_ROUTING) {
        //sjekker om noen av pakkene i kø har samme dest og trenger neste hopp?
        if (bytes_read >= 6 && buffer[2] == 'R' && buffer[3] == 'S' && buffer[4] == 'P') {
            uint8_t next = buffer[5]; 
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
                    uint8_t dest = route_wait_queue[i].dest;
                    uint8_t src = route_wait_queue[i].src;
                    uint8_t ttl = route_wait_queue[i].ttl;
                    uint8_t sdu_type = route_wait_queue[i].sdu_type;
                    uint8_t *sdu = route_wait_queue[i].sdu;
                    size_t sdu_len = route_wait_queue[i].sdu_len;
                    
                    //sjekker i arp tabellen om vi har addressen til neste
                    unsigned char mac[6];
                    if (arp_lookup(next, mac)) {
                        //treff - addressen finnes - bygg og send pdu
                        size_t new_pdu_length;
                        uint8_t *new_pdu = mip_build_pdu(dest, src, ttl, sdu_type, sdu, sdu_len, &new_pdu_length);
                        send_pdu(raw_sock, new_pdu, new_pdu_length, mac);
                        free(new_pdu);
                        printf("[ROUTING] Sendte pakke til next_hop=%d (dest=%d)\n",
                           next, dest);
                    }
                    //hvis ikke - mac finnes ikke for neste hopp og må sende arp req
                    else{
                        printf("[ROUTING] Har ikke MAC for next hop=%d, sender ARP\n", next);
                        queue_message(next, sdu_type, sdu, sdu_len);
                        send_arp_request(raw_sock, next, my_mip_address);
                    }

                    free(route_wait_queue[i].sdu);
                    route_wait_queue[i].valid = 0;
                    return;
                }
            }
            printf("[ROUTING] Ingen ventende pakker — ignorerer RESPONSE.\n");
        }
        return;
    }

    // Les data etter nytt format: [dest:1][ttl:1][payload]
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

    // Slå opp MAC i ARP-cache og send eller kølegg
    unsigned char mac[6];
    if (arp_lookup(dest_addr, mac)) {
        size_t pdu_len;
        uint8_t *pdu = mip_build_pdu(dest_addr, my_mip_address, ttl,
                                     sdu_type, payload, payload_length, &pdu_len);
        send_pdu(raw_sock, pdu, pdu_len, mac);
        free(pdu);
    } else {
             // TESTMODUS: legg inn "fake" MAC så vi kan sende direkte
        // unsigned char fake_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, dest_addr};
        // arp_update(dest_addr, fake_mac);

        // printf("[DEBUG][TEST] Ingen ARP entry for MIP %d → lagt inn fake MAC\n", dest_addr);

        // Hent den rett etterpå som normalt
        if (arp_lookup(dest_addr, mac)) {
            size_t pdu_len;
            uint8_t *pdu = mip_build_pdu(dest_addr, my_mip_address, 4, sdu_type, payload, payload_length, &pdu_len);
            send_pdu(raw_sock, pdu, pdu_len, mac);
            free(pdu);
        }
        else {
            queue_message(dest_addr, sdu_type, payload, payload_length);
            send_arp_request(raw_sock, dest_addr, my_mip_address);
        }
    }
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


void send_arp_request(int raw_sock, uint8_t dest_addr, int my_mip_address) {
    mip_arp_msg req = {
        .type = ARP_REQUEST,
        .mip_addr = dest_addr,
        .reserved = 0
    };

    size_t arp_len;
    uint8_t *arp_pdu = mip_build_pdu(
        0xFF,                      // broadcast dest (MIP)
        my_mip_address,            // source = meg
        1,                         // TTL
        SDU_TYPE_ARP,              // type = ARP
        (uint8_t*)&req,
        sizeof(req),
        &arp_len
    );

    unsigned char bmac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};


    // Nå håndterer send_pdu() looping over alle interfaces
    send_pdu(raw_sock, arp_pdu, arp_len, bmac);

    free(arp_pdu);
}






/*
- handle_raw_packet
mottar råpakker fra nettverkskortet via raw_sock. 
Den sjekker at det faktisk er en MIP-pakke, pakker opp headeren, og håndterer innholdet avhengig av SDU-typen

PING svarer med en PONG tilbake.
PONG skriver svaret tilbake til den siste UNIX-klienten.
ARP-REQUEST svarer med en ARP-RESPONSE hvis forespørselen gjelder egen MIP-adresse.
ARP-RESPONSE oppdaterer ARP-cachen og sender eventuelle ventende meldinger til den adressen

raw_sock: rå-socketen vi lytter på.
my_mip_address: egen MIP-adresse
                brukes til å avgjøre om en pakke er til seg selv og til å fylle ut svar

last_unix_client_fd – kan lukkes eller skrives til når en PONG mottas
arp_cache – oppdateres når ARP-RESP mottas (gjennom arp_update)
pending_queue – tømmes når ventende meldinger sendes etter en ARP-RESP (send_pending_message)
Bruker debug_mode for logging
*/
void handle_raw_packet(int raw_sock, int my_mip_address) {
    uint8_t buffer[2000]; // Buffer for å lagre innkommende råpakke
    struct sockaddr_ll src_addr; // Struktur for å lagre avsenderadresse

    // iovec beskriver hvor data skal plasseres når vi mottar meldingen
    struct iovec iov = { buffer, sizeof(buffer) };

    // msghdr brukes av recvmsg() for å motta både data og metadata
    struct msghdr msg = { .msg_name = &src_addr, .msg_namelen = sizeof(src_addr),
                          .msg_iov = &iov, .msg_iovlen = 1 };

    int len = recvmsg(raw_sock, &msg, 0);

    if(debug_mode){
        printf("[DEBUG][RAW] handle_raw_packet CALLED, len=%d\n", len);
    }

    if (len < (int)sizeof(struct ethhdr)) return; // må minst ha Ethernet-header

    // Tolker starten av bufferet som en Ethernet-header
    struct ethhdr *eh = (struct ethhdr *)buffer;

    uint16_t proto = htons(eh->h_proto);

    int if_index = src_addr.sll_ifindex;

    char if_name[IFNAMSIZ];
    if_indextoname(if_index, if_name); // oversett til navn (f.eks. "A-eth0")

    if (debug_mode) {
        printf("[DEBUG][RAW] Packet received on interface %s (index=%d)\n",
               if_name, if_index);
        printf("[DEBUG][RAW] RX dst=%02X:%02X:%02X:%02X:%02X:%02X "
               "src=%02X:%02X:%02X:%02X:%02X:%02X proto=0x%04X\n",
               eh->h_dest[0], eh->h_dest[1], eh->h_dest[2],
               eh->h_dest[3], eh->h_dest[4], eh->h_dest[5],
               eh->h_source[0], eh->h_source[1], eh->h_source[2],
               eh->h_source[3], eh->h_source[4], eh->h_source[5],
               proto);
    }

    if (proto != ETH_P_MIP) {
        printf("[ERROR][RAW] PROTO ER FEIL (ikke MIP)\n\n");
        return;
    }
        
    //mip pakken starter etter ethernet header
    const uint8_t *mip_start = buffer + sizeof(struct ethhdr);
    size_t mip_len = len - sizeof(struct ethhdr);

    uint8_t dest, src, ttl, sdu_type;
    const uint8_t *sdu;

    // Pakk ut og tolk MIP-headeren
    ssize_t sdu_len = mip_parse(mip_start, mip_len,
                                &dest, &src, &ttl,
                                &sdu_type, &sdu);
    if (sdu_len < 0) {
        printf("[ERROR][RAW] ugyldig MIP PDU (len=%d)\n", len);
        return;
    }

    //denne koden kjører ikke fordi man ikke kan motta pakker over rawsocket
    if (dest != my_mip_address && dest != 255) { //255 = broadcast
        // ikke til meg og ikke broadcast - FORWARD PAKKEN  
        if (ttl <= 1) {
            if(debug_mode) printf("[DEBUG][FWD] Dropper pakke til %d (TTL utløpt)\n", dest);
            return;
        }
        //justerer ttl før den forwardes
        uint8_t ttl_new = ttl - 1;

        if (debug_mode) {
            printf("[DEBUG][RAW][FWD] Routing lookup: dest=%d, src=%d, ttl=%d→%d\n",
               dest, src, ttl, ttl_new);
        }

        queue_routing_message(dest, src, ttl_new, sdu_type, sdu, sdu_len);

        for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
            if (unix_clients[i].active && unix_clients[i].sdu_type == SDU_TYPE_ROUTING) {
                send_route_request(unix_clients[i].fd, my_mip_address, dest);
                break;
            }
        }

        if(debug_mode) printf("[DEBUG][RAW][FWD] Route request sendt til routingd, pakke lagret midlertidig.\n");
        return;
    }

    //setter opp en switch som håndterer de ulike sdu typene
    switch (sdu_type) {
        case SDU_TYPE_PING: {
            printf("[RAW] PING mottatt fra MIP %u\n\n", src);

            arp_update(src, eh->h_source); //lagrer avsender i ARP til senere

           for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
                if (unix_clients[i].active && unix_clients[i].sdu_type == SDU_TYPE_PONG) {
                    uint8_t reply[256];
                    reply[0] = src;   // avsender MIP
                    reply[1] = ttl;   // TTL
                    memcpy(&reply[2], sdu, sdu_len);
                    write(unix_clients[i].fd, reply, 2 + sdu_len);
                    if (debug_mode) {
                        printf("[DEBUG] Sent PING to UNIX app (src=%u ttl=%u len=%zd)\n",
                            src, ttl, sdu_len);
                    }
                    break;
                }
            }
            break;
        }

        case SDU_TYPE_PONG: {
            // Mottatt et PONG-svar fra en node vi tidligere sendte en PING til
            printf("[RAW] PONG mottatt fra MIP %u: %.*s\n\n",
                   src, (int)sdu_len, (char*)sdu);

            // Skriver svaret (payloaden) tilbake til UNIX-klienten som startet forespørselen
            // må finne hvilken unix klient
            for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
                if (unix_clients[i].active && unix_clients[i].sdu_type == SDU_TYPE_PING) {
                    uint8_t reply[256];
                    reply[0] = src;   // hvem meldingen kom fra
                    reply[1] = ttl;
                    memcpy(&reply[2], sdu, sdu_len);
                    write(unix_clients[i].fd, reply, 2 + sdu_len);
                    break;
                }
            }
            break;
        }

        case SDU_TYPE_ARP: {
            // arp meldinger, enten request eller response

            //payload må være stor nok til å inneholde en mip_arp_msg
            if (sdu_len < (ssize_t)sizeof(mip_arp_msg)) {
                printf("[ERROR] ARP SDU for kort (%zd bytes)\n\n", sdu_len);
                return;
            }

            //mip_arp_message definert i arp.h (type: reqest eller response, addresse og ev padding)
            //payloaden tolkes slik
            const mip_arp_msg *arp = (const mip_arp_msg*)sdu;

            if(debug_mode){
                printf("[DEBUG] ARP msg: type=%u mip_addr=%u (payload_len=%zd)\n\n",
                   arp->type, arp->mip_addr, sdu_len);
            }

            if (arp->type == 0x00 && arp->mip_addr == my_mip_address) {
                // Dette er en ARP request (0x00), og den spør etter nodens MIP-adresse
                // Da bygges en ARP response (0x01) med egen MIP-adresse
                printf("[RAW] ARP-REQ mottatt fra MIP %d\n\n", arp->mip_addr);
                mip_arp_msg resp = { .type = 0x01, .mip_addr = my_mip_address, .reserved = 0 };
                size_t pdu_len = 0;
                uint8_t *pdu = mip_build_pdu(
                    src, 
                    my_mip_address,
                    1,
                    SDU_TYPE_ARP,
                    (uint8_t*)&resp, 
                    sizeof(resp),
                    &pdu_len
                );
                send_pdu(raw_sock, pdu, pdu_len, eh->h_source);
                free(pdu);
            }
            else if (arp->type == 0x01) {
                // Dette er en ARP response (0x01)
                //oppdatterer arp med mac adresse og mip
                printf("[RAW] ARP-RESP mottatt for MIP %d\n\n", arp->mip_addr);
                arp_update(arp->mip_addr, eh->h_source);

                if (debug_mode){
                    print_arp_cache();
                }

                //har fått response, så kan sjekke om det er noen pakker som venter på å bli sent
                //og som venter på denne aaddressen
                send_pending_messages(raw_sock, arp->mip_addr, eh->h_source, my_mip_address);
            }
            break;
        }

        default:
            printf("[RAW] Ukjent SDU-type: %u\n\n", sdu_type);
            break;
    }
}









