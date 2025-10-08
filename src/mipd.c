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

/*
- create_unix_socket
oppretter en UNIX-socket på en gitt filbane gitt som argument - path. 
Den binder socketen til adressen, sørger for at en eventuell gammel socket-fil slettes,
og setter den i lyttemodus slik at klienter kan koble seg til. 
returnerer filbeskriveren for socketen, eller avslutter programmet hvis noe feiler
*/

#define MAX_PING_PAYLOAD 512

char last_ping_payload[MAX_PING_PAYLOAD];
size_t last_ping_payload_len = 0;
int ping_waiting = 0;  // 0 = ingen ny ping tilgjengelig, 1 = klar for ping_server


int create_unix_socket(const char *path) {
    int sock;
    struct sockaddr_un addr;

    //lager en unix socket, stopper programmet hvis en feil skjer
    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
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
    int sock = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL);
    if (sock < 0) {
        perror("raw socket");
        exit(EXIT_FAILURE);
    }

    // Bind socketen til valgt interface (iface_name settes i find_iface())
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = if_nametoindex(iface_name);

    if(debug_mode){
        printf("[DEBUG] create_raw_socket: iface=%s idx=%d proto=0x%X\n\n",
           iface_name, sll.sll_ifindex, ETH_P_ALL);
    }

    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind raw socket");
        close(sock);
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
void handle_unix_request(int unix_sock, int raw_sock, int my_mip_address) {
    int client = accept(unix_sock, NULL, NULL);
    if (client < 0) return;

    char buffer[256];
    int n = read(client, buffer, sizeof(buffer));

    if (n > 0) {
        //hvis ping_server kobler til for å lese ventende PING fra mipd
        if (ping_waiting && strncmp(buffer, "PING:", 5) != 0) {
            write(client, last_ping_payload, last_ping_payload_len);
            ping_waiting = 0;
            close(client);
            return;
        }

        uint8_t dest_addr;
        uint8_t* payload;
        size_t payload_length;
        uint8_t sdu_type;
        
        if (strncmp(buffer, "PONG:", 5) == 0) {
            // Dette er et PONG-svar fra applikasjonen
            if (last_ping_src < 0) {
                printf("[WARNING] PONG mottatt, men ingen tidligere PING-avsender lagret\n");
                close(client);
                return;
            }
            dest_addr = (uint8_t)last_ping_src;
            payload = (uint8_t*)buffer;
            payload_length = n;
            sdu_type = SDU_TYPE_PONG;
        } else {
            // Vanlig klientmelding: første byte er destinasjon
            dest_addr = buffer[0];
            payload = (uint8_t*)&buffer[1];
            payload_length = n - 1;
            sdu_type = SDU_TYPE_PING;
        }

        if(debug_mode){
            printf("[DEBUG] handle_unix_request: n=%d dest=%d payload_len=%zu\n\n",
               n, dest_addr, payload_length);
            printf("[DEBUG] payload bytes: ");
            for (size_t i = 0; i < payload_length && i < 8; i++) {
                printf("%02X ", payload[i]);
            }
            printf("\n\n");
            printf("[DEBUG] Checking ARP for dest=%u\n\n", dest_addr);
        }
        
        unsigned char mac[6];
    
        if (arp_lookup(dest_addr, mac)) {
            // MAC finnes - bygg og send PING nå
            size_t pdu_len; //oppdateres av funksjonen under
            uint8_t* pdu = mip_build_pdu(
                dest_addr,             
                my_mip_address,        
                4,                     
                sdu_type,        
                payload,               
                payload_length, // payload_len (bytes!)
                &pdu_len
            );
            send_pdu(raw_sock, pdu, pdu_len, mac);
            free(pdu);

        } else {
            // MAC finnes IKKE - legg på vent i kø
            queue_message(dest_addr, SDU_TYPE_PING, payload, payload_length);

            // Send ARP request
            mip_arp_msg req = { .type = ARP_REQUEST, .mip_addr = dest_addr, .reserved = 0 };
            size_t arp_len;
            uint8_t* arp_pdu = mip_build_pdu(
                0xFF,                  // broadcast dest
                my_mip_address,        // src
                1,                     //ttl
                SDU_TYPE_ARP,          // type
                (uint8_t*)&req,        // payload
                sizeof(req),           // payload_len
                &arp_len
            );
            //sender arp request med broadcast mac for å finne riktig mottaker
            unsigned char bmac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
            send_pdu(raw_sock, arp_pdu, arp_len, bmac);
            free(arp_pdu);
        }

        // Håndter UNIX client FD
        if (last_unix_client_fd > 0) {
            close(last_unix_client_fd);
        }
        last_unix_client_fd = client;
        return;
    }

    close(client);
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

    if (len < (int)sizeof(struct ethhdr)) return; // må minst ha Ethernet-header

    // Tolker starten av bufferet som en Ethernet-header
    struct ethhdr *eh = (struct ethhdr *)buffer;

    uint16_t proto = ntohs(eh->h_proto);
    //SJEKK 

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

    // Håndterer TTL
    if (--ttl == 0) {
        if (debug_mode) {
            printf("[DEBUG] Dropping packet: TTL expired\n\n");
        }
        return; // Ikke prosesser videre
    }

    if (dest != my_mip_address && dest != 0xFF) {
        // ikke til meg og ikke broadcast
        return;
    }

    //setter opp en switch som håndterer de ulike sdu typene
    switch (sdu_type) {
        case SDU_TYPE_PING: {
            printf("[RAW] PING mottatt fra MIP %u\n\n", src);

            arp_update(src, eh->h_source); //lagrer avsender i ARP til senere

            last_ping_src = src;

            memset(last_ping_payload, 0, sizeof(last_ping_payload));
            memcpy(last_ping_payload, sdu, sdu_len);
            last_ping_payload_len = sdu_len;
            ping_waiting = 1;
         
            break;
        }

        case SDU_TYPE_PONG: {
            // Mottatt et PONG-svar fra en node vi tidligere sendte en PING til
            printf("[RAW] PONG mottatt fra MIP %u: %.*s\n\n",
                   src, (int)sdu_len, (char*)sdu);

            // Skriver svaret (payloaden) tilbake til UNIX-klienten som startet forespørselen
            if (last_unix_client_fd > 0) {
                (void)write(last_unix_client_fd, sdu, sdu_len);

                //lukker klientens socket og 'last_unix_client_fd' settes til -1
                //så klart til senere
                close(last_unix_client_fd);
                last_unix_client_fd = -1;
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
        }
    }
}






