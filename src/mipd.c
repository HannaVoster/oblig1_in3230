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


/*
- create_unix_socket
oppretter en UNIX-socket på en gitt filbane gitt som argument - path. 
Den binder socketen til adressen, sørger for at en eventuell gammel socket-fil slettes,
og setter den i lyttemodus slik at klienter kan koble seg til. 
returnerer filbeskriveren for socketen, eller avslutter programmet hvis noe feiler
*/

#define MAX_PING_PAYLOAD 512
unix_client unix_clients[MAX_UNIX_CLIENT];

route_wait route_wait_queue[MAX_ROUTE_WAIT];


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
-create_raw_socket
lager en råsocket for å sende og motta MIP-pakker direkte over Ethernet. 
funksjonen binder socketen til det valgte nettverksinterface, 
og returnerer filbeskriveren. Programmet avsluttes hvis noe går galt.
*/
int create_raw_socket() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_MIP));
    if (sock < 0) {
        perror("raw socket");
        exit(EXIT_FAILURE);
    }

    // Bind socketen til valgt interface (iface_name settes i find_iface())
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_MIP);
    sll.sll_ifindex  = if_nametoindex(iface_name);

    if(debug_mode){
        printf("[DEBUG] create_raw_socket: iface=%s idx=%d proto=0x%X\n\n",
           iface_name, sll.sll_ifindex, ETH_P_MIP);
    }

    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind raw socket");
        close(sock);
        exit(EXIT_FAILURE);
    }

    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = if_nametoindex(iface_name);
    mreq.mr_type = PACKET_MR_PROMISC;

    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt PROMISC");
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
       if ((my_mip_address == 10 && dest_addr == 20) ||
        (my_mip_address == 20 && (dest_addr == 10 || dest_addr == 30)) ||
        (my_mip_address == 30 && dest_addr == 20)) {

        unsigned char fake_mac[6] = {0,0,0,0,0,dest_addr};
        arp_update(dest_addr, fake_mac);
        printf("[DEBUG] Fake MAC for direkte nabo %d\n", dest_addr);

        // Hent den rett etterpå og send pakken
        if (arp_lookup(dest_addr, mac)) {
            size_t pdu_len;
            uint8_t *pdu = mip_build_pdu(dest_addr, my_mip_address, ttl,
                                         sdu_type, payload, payload_length, &pdu_len);
            send_pdu(raw_sock, pdu, pdu_len, mac);
            free(pdu);
        }
    } else {
        printf("[DEBUG] Ikke direkte nabo — sender ARP request (routing vil trigges)\n");
        queue_message(dest_addr, sdu_type, payload, payload_length);
        send_arp_request(raw_sock, dest_addr, my_mip_address);
        return;
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
    mip_arp_msg req = { .type = ARP_REQUEST, .mip_addr = dest_addr, .reserved = 0 };
    size_t arp_len;
    uint8_t *arp_pdu = mip_build_pdu(
        0xFF, my_mip_address, 1, SDU_TYPE_ARP,
        (uint8_t*)&req, sizeof(req), &arp_len
    );
    unsigned char bmac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
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
    if(debug_mode){
        printf("[DEBUG] handle_raw_packet CALLED\n\n");
    }
    uint8_t buffer[2000]; // Buffer for å lagre innkommende råpakke
    struct sockaddr_ll src_addr; // Struktur for å lagre avsenderadresse

    // iovec beskriver hvor data skal plasseres når vi mottar meldingen
    struct iovec iov = { buffer, sizeof(buffer) };

    // msghdr brukes av recvmsg() for å motta både data og metadata
    struct msghdr msg = { .msg_name = &src_addr, .msg_namelen = sizeof(src_addr),
                          .msg_iov = &iov, .msg_iovlen = 1 };

    int len = recvmsg(raw_sock, &msg, 0);

    printf("[DEBUG] handle_raw_packet CALLED, len=%d\n", len);

    if (len < (int)sizeof(struct ethhdr)) return; // må minst ha Ethernet-header

    // Tolker starten av bufferet som en Ethernet-header
    struct ethhdr *eh = (struct ethhdr *)buffer;

    uint16_t proto = htons(eh->h_proto);

    if (debug_mode) {
        printf("[DEBUG] handle_raw_packet: mottatt proto=0x%04X (ETH_P_MIP=0x%04X)\n",
            proto, ETH_P_MIP);
    }

    if (debug_mode) {
        printf("[DEBUG] RX frame ethertype=0x%04X\n\n", proto);
        // Dump Ethernet-header (14 bytes)
        printf("[DEBUG] RX dst=%02X:%02X:%02X:%02X:%02X:%02X "
            "src=%02X:%02X:%02X:%02X:%02X:%02X\n\n",
            eh->h_dest[0], eh->h_dest[1], eh->h_dest[2],
            eh->h_dest[3], eh->h_dest[4], eh->h_dest[5],
            eh->h_source[0], eh->h_source[1], eh->h_source[2],
            eh->h_source[3], eh->h_source[4], eh->h_source[5]);
    }
    if (proto != ETH_P_MIP) {
        printf("[DEBUG] PROTO ER FEIL (ikke MIP)\n\n");
        return;
    }
        
    if(debug_mode){
        printf("[DEBUG] PROTO = MIP! Nå kan vi parse PDU.\n\n");
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
        printf("[ERROR] ugyldig MIP PDU (len=%d)\n", len);
        return;
    }

    //denne koden kjører ikke fordi man ikke kan motta pakker over rawsocket
    if (dest != my_mip_address && dest != 255) { //255 = broadcast
        // ikke til meg og ikke broadcast - FORWARD PAKKEN  
        if (ttl <= 1) {
            printf("[FWD] Dropper pakke til %d (TTL utløpt)\n", dest);
            return;
        }
        //justerer ttl før den forwardes
        uint8_t ttl_new = ttl - 1;

        if (debug_mode) {
            printf("[FWD] Routing lookup: dest=%d, src=%d, ttl=%d→%d\n",
               dest, src, ttl, ttl_new);
        }

        queue_routing_message(dest, src, ttl_new, sdu_type, sdu, sdu_len);

        for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
            if (unix_clients[i].active && unix_clients[i].sdu_type == SDU_TYPE_ROUTING) {
                send_route_request(unix_clients[i].fd, my_mip_address, dest);
                break;
            }
        }

        printf("[FWD] Route request sendt til routingd, pakke lagret midlertidig.\n");
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


// Denne funksjonen finner et nettverksinterface (f.eks. "eth0")
// som kan bruker for AF_PACKET rå-sockets.
// Den hopper over "lo" (loopback), siden man ikke vil sende MIP-pakker internt
void find_iface(void) {
    //deklarerer to pekere, ifaddr til starten av listen, ifa til løpepeker
    struct ifaddrs *ifaddr, *ifa;

    // Henter en lenket liste over alle nettverksinterfaces på maskinen.
    // ifaddr peker til starten av lista.
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs"); // Skriver feilmelding hvis det feiler
        exit(1);
    }

    // Går gjennom alle entries i lista
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue; // Hopp over ugyldige entries

        if (debug_mode) {
            printf("[DEBUG] Fant interface: %s (family=%d)\n\n",
                   ifa->ifa_name,
                   ifa->ifa_addr->sa_family);
        }
        // Kun interessert i interfaces av type AF_PACKET, lavnivå nettverksinterfaces (Ethernet)
        // Ikke f.eks. IPv4 eller IPv6 
        if (ifa->ifa_addr->sa_family == AF_PACKET &&
            strcmp(ifa->ifa_name, "lo") != 0) { // Hopper over "lo" (loopback)
            
            // kopierer inntil IFNAMSIZ tegn fra ifa->ifa_name inn i iface_name
            strncpy(iface_name, ifa->ifa_name, IFNAMSIZ);

            iface_name[IFNAMSIZ - 1] = '\0'; // Sørger for at string alltid nulltermineres

            if (debug_mode) {
                printf("[DEBUG] Valgte interface: %s\n\n", iface_name);
            }

            break; //  tar det første gyldige 
        }
    }

    // Ferdig med lista – frigjør minnet
    freeifaddrs(ifaddr);

    // Hvis ikke fant noe interface, feiler 
    if (iface_name[0] == '\0') {
        fprintf(stderr, "Fant ikke noe gyldig interface!\n\n");
        exit(1);
    }

    // Debug: skriv ut hvilket interface vi valgte
    if (debug_mode) {
        printf("[DEBUG] Bruker interface: %s\n\n", iface_name);
    }
}

/*
Denne funksjonen tar inn navnet på et nettverksinterface, 
oppretter en socket for å spørre kjernen om informasjon, 
og bruker ioctl med flagget SIOCGIFHWADDR for å hente MAC-adressen. 

Resultatet kopieres til bufferet mac. Den returnerer 0 hvis alt gikk bra, ellers -1

brukes av send_pdu i pdu.c
*/
int get_iface_mac(const char *ifname, unsigned char *mac) {

    // Åpner en socket for å kunne utføre ioctl-kall på interfacet
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    // Henter hardware-adressen (MAC) via ioctl
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        close(fd);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(fd);
    return 0;
}
/*
Legg melding i pending-kø dersom mottakers addresse er ukjent
 - venter på å sende PING uten arp resp
meldingene lagres til ARP response kommer og kan sendes via send_pending_message

pending_queue er en global kø med pending_entries og feltene settes av parameterene funskjonen tar
*/
void queue_message(uint8_t dest_mip, uint8_t sdu_type,
                   uint8_t *data, size_t length_bytes) {

    for (int i = 0; i < MAX_PENDING; i++) {
        if (!pending_queue[i].valid) {
            if (debug_mode) {
                printf("[DEBUG] queue_message: dest=%d type=%d len=%zu bytes\n\n",
                       dest_mip, sdu_type, length_bytes);
            }

            // Nullstill og sett metadata
            pending_queue[i].payload = NULL;
            pending_queue[i].length  = length_bytes;
            pending_queue[i].dest_mip = dest_mip;
            pending_queue[i].sdu_type = sdu_type;
            pending_queue[i].valid    = 1;

            // Alloker minne kun hvis data faktisk finnes
            if (length_bytes > 0) {
                pending_queue[i].payload = malloc(length_bytes);
                if (!pending_queue[i].payload) {
                    perror("[ERROR] malloc queue_message");
                    exit(EXIT_FAILURE);
                }
                //kopierer payload
                memcpy(pending_queue[i].payload, data, length_bytes);
            }

            if (debug_mode) {
                printf("[DEBUG] queue_message saved: len=%zu at slot=%d",
                       pending_queue[i].length, i);
                if (length_bytes > 0)
                    printf(", payload[0]=0x%02X", pending_queue[i].payload[0]);
                printf("\n\n");
            }

            printf("[QUEUE] Meldingen for MIP %d lagt i kø\n\n", dest_mip);
            return;
        }
    }
    printf("[QUEUE] Kø full, kunne ikke legge til melding for MIP %d\n\n", dest_mip);
}


/*
Sender meldinger som ligger i pending-køen for en gitt MIP-adresse
Alle meldinger i køen som er adressert til den MIP-adressen pakkes på nytt som en MIP PDU og sendes
fjerner deretter køelementet fra den globale køen


tar inn raw socket for å sende i send_pdu of adresse for å vite hvem som skal få
og hvem som sender
*/
void send_pending_messages(int raw_sock, uint8_t mip_addr,
                           unsigned char *mac, int my_mip_address) {

    for (int i = 0; i < MAX_PENDING; i++) {
        // Se etter meldinger i køen for denne destinasjons-MIPen
        if (pending_queue[i].valid && pending_queue[i].dest_mip == mip_addr) {
            
            // Sjekk at køelementet er gyldig (payload finnes og lengden > 0)
            if (pending_queue[i].length == 0 || pending_queue[i].payload == NULL) {
                printf("[ERROR] Pending entry corrupt: len=0 eller payload=NULL for MIP %d\n\n",
                       pending_queue[i].dest_mip);
                pending_queue[i].valid = 0;
                continue;
            }

            if (debug_mode) {
                printf("[DEBUG] send_pending_messages using slot=%d "
                       "len=%zu type=%d dest=%d\n\n",
                       i,
                       pending_queue[i].length,
                       pending_queue[i].sdu_type,
                       pending_queue[i].dest_mip);
            }

            // Bygg PDU på nytt fra payload
            size_t pdu_len;
            uint8_t *pdu = mip_build_pdu(
                pending_queue[i].dest_mip,    // dest
                my_mip_address,               // src
                4,                            // TTL
                pending_queue[i].sdu_type,    // SDU type
                pending_queue[i].payload,     // SDU data
                pending_queue[i].length,      // SDU lengde i bytes
                &pdu_len
            );

            send_pdu(raw_sock, pdu, pdu_len, mac);

            free(pdu);

            // Invalider køelementet FØR payloaden frigis
            pending_queue[i].valid = 0;
            free(pending_queue[i].payload);
            pending_queue[i].payload = NULL;

            printf("[QUEUE] Sendt kø-melding til MIP %d\n\n", mip_addr);

            if (debug_mode) {
                printf("[DEBUG] Etter send_pending_messages():\n");
                print_arp_cache();
            }
        }
    }
}

void send_route_request(int routing_fd, uint8_t my_addr, uint8_t dest) {
    uint8_t req[6] = { my_addr, 0, 'R', 'E', 'Q', dest };
    if (write(routing_fd, req, sizeof(req)) != sizeof(req))
        perror("[MIPD] write route request");
    else
        printf("[MIPD] Sent ROUTE REQUEST for dest=%d\n", dest);
}

void queue_routing_message(uint8_t dest, uint8_t src, uint8_t ttl,
                           uint8_t sdu_type, const uint8_t *sdu, size_t sdu_len) {

    for (int i = 0; i < MAX_ROUTE_WAIT; i++) {
        if (!route_wait_queue[i].valid) {
            if (debug_mode) {
                printf("[DEBUG] queue_routing_message: dest=%d type=%d len=%zu bytes\n\n",
                       dest, sdu_type, sdu_len);
            }

            // Nullstill og sett metadata
            route_wait_queue[i].dest = dest;
            route_wait_queue[i].src = src;
            route_wait_queue[i].ttl = ttl;
            route_wait_queue[i].sdu_type = sdu_type;
            //route_wait_queue[i].sdu = malloc(sdu_len);
            
            route_wait_queue[i].sdu_len = sdu_len;
            route_wait_queue[i].valid = 1;

            // Alloker minne kun hvis data faktisk finnes
            if (sdu_len > 0) {
                route_wait_queue[i].sdu = malloc(sdu_len);
                if (!route_wait_queue[i].sdu) {
                    perror("[ERROR] malloc queue_message");
                    exit(EXIT_FAILURE);
                }
                //kopierer payload
                memcpy(route_wait_queue[i].sdu, sdu, sdu_len);
            }

            if (debug_mode) {
                printf("[DEBUG] routing queue_message saved: len=%zu at slot=%d",
                       route_wait_queue[i].sdu_len, i);
            }
            return;
        }
    }
    printf("[WARNING] route_wait_queue is full, dropping packet (dest=%d)\n", dest);
}



