// daemonen som kjører i bakgrunnen og håndterer trafikk på vegne av applikasjonene

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netpacket/packet.h>   // AF_PACKET, sockaddr_ll
#include <net/ethernet.h>       // ETH_P_*
#include <net/if.h>             // if_nametoindex(), struct ifreq
#include <arpa/inet.h>
#include <netinet/if_ether.h>   // struct ethhdr (klassisk Ethernet-header)
#include <ifaddrs.h>

#include "mipd.h"

#define MAX_EVENTS 10
#define UNIX_PATH "/tmp/mip_socket"

int debug_mode = 0; // global flagg for debug
int last_unix_client_fd = -1; 
int my_mip_address = -1;
char iface_name[IFNAMSIZ] = {0};


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

int create_raw_socket() {
    //lager en raw socket

    //AF_PACKET forteller at adressen tilhører ethernet rammer, på et lavt nivå
    //SOCK_RAW socket type, tar imot hele ethernet rammer med både header og payload
    //htons(ETH_P_MIP) 
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("raw socket");
        exit(EXIT_FAILURE);
    }
    return sock;
}

//håndterer en forbindelse på UNIX socket
void handle_unix_request(int unix_sock, int raw_sock, int my_mip_address) {
    int client = accept(unix_sock, NULL, NULL);
    if (client < 0) return;

    char buffer[256];
    int n = read(client, buffer, sizeof(buffer)-1);

    if (n > 0) {
        buffer[n] = '\0';
        uint8_t dest_addr = buffer[0];
        uint8_t* payload = (uint8_t*)&buffer[1];
        uint16_t payload_length = n - 1;

        size_t pdu_len;
        uint8_t* pdu = build_pdu(dest_addr, my_mip_address, 4,
                                 payload_length, SDU_TYPE_PING,
                                 payload, &pdu_len);

        unsigned char mac[6];
        if (arp_lookup(dest_addr, mac)) {
            send_pdu(raw_sock, pdu, pdu_len, mac);
        } else {
            queue_message(dest_addr, pdu, pdu_len);

            mip_arp_msg req = { .type = 0x00, .mip_addr = dest_addr, .reserved = 0 };
            size_t arp_len;
            uint8_t* arp_pdu = build_pdu(0xFF, my_mip_address, 1,
                                         sizeof(req), SDU_TYPE_ARP,
                                         (uint8_t*)&req, &arp_len);

            unsigned char bmac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
            send_pdu(raw_sock, arp_pdu, arp_len, bmac);
            free(arp_pdu);
        }
        free(pdu);
        if (last_unix_client_fd > 0) {
            close(last_unix_client_fd);
        }
        last_unix_client_fd = client;
        return;
    }
    close(client);
}

//håndterer en forbindelse på RAW socket
void handle_raw_packet(int raw_sock) {
    uint8_t buffer[2000];
    struct sockaddr_ll src_addr;
    struct iovec iov = { buffer, sizeof(buffer) };
    struct msghdr msg = { .msg_name = &src_addr, .msg_namelen = sizeof(src_addr),
                          .msg_iov = &iov, .msg_iovlen = 1 };

    int len = recvmsg(raw_sock, &msg, 0);
    if (len < (int)sizeof(struct ethhdr)) return; // må minst ha Ethernet-header

    printf("[DEBUG] recvmsg got %d bytes\n", len);
    for (int i = 0; i < len; i++) {
        printf("%02X ", buffer[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // Tolker Ethernet-header
    struct ethhdr *eh = (struct ethhdr *)buffer;

    // Filtrer på vårt eget Ethertype
    if (ntohs(eh->h_proto) != ETH_P_MIP) return;

    // Debug: MAC-adresser
    if (debug_mode) {
        printf("[DEBUG] recv: src=");
        for (int i = 0; i < ETH_ALEN; i++) printf("%02X:", eh->h_source[i]);
        printf(" dst=");
        for (int i = 0; i < ETH_ALEN; i++) printf("%02X:", eh->h_dest[i]);
        printf(" proto=0x%04X\n", ntohs(eh->h_proto));
    }

    // Pek på MIP-headeren rett etter Ethernet
    uint8_t *mip_hdr_start = buffer + sizeof(struct ethhdr);

    mip_header_t hdr;
    memcpy(&hdr, mip_hdr_start, sizeof(mip_header_t));

    uint8_t src_mip   = get_src(&hdr);
    uint8_t dest_mip  = get_dest(&hdr);
    uint8_t sdu_type  = get_type(&hdr);
    uint16_t sdu_len  = get_length(&hdr) * 4;
    uint8_t *payload  = mip_hdr_start + sizeof(mip_header_t);

    if (dest_mip != my_mip_address && dest_mip != 0xFF) return;

    switch (sdu_type) {
        case SDU_TYPE_PING: {
            printf("[RAW] PING mottatt fra MIP %d\n", src_mip);
            size_t pdu_len;
            uint8_t* pdu = build_pdu(src_mip, my_mip_address, 4,
                                     sdu_len, SDU_TYPE_PONG,
                                     payload, &pdu_len);
            send_pdu(raw_sock, pdu, pdu_len, eh->h_source); // bruk src MAC fra Ethernet
            free(pdu);
            break;
        }

        case SDU_TYPE_PONG:
            printf("[RAW] PONG mottatt fra MIP %d: %.*s\n", src_mip, sdu_len, payload);
            if (last_unix_client_fd > 0) {
                write(last_unix_client_fd, payload, sdu_len);
                close(last_unix_client_fd);
                last_unix_client_fd = -1;
            }
            break;

        case SDU_TYPE_ARP: {
            mip_arp_msg *arp = (mip_arp_msg*)payload;

            if (arp->type == 0x00 && arp->mip_addr == my_mip_address) {
                printf("[RAW] ARP-REQ for meg (%d)\n", my_mip_address);
                mip_arp_msg resp = { .type = 0x01, .mip_addr = my_mip_address, .reserved = 0 };
                size_t pdu_len;
                uint8_t* pdu = build_pdu(src_mip, my_mip_address, 1,
                                         sizeof(resp), SDU_TYPE_ARP,
                                         (uint8_t*)&resp, &pdu_len);
                send_pdu(raw_sock, pdu, pdu_len, eh->h_source);
                free(pdu);
            } 
            else if (arp->type == 0x01) {
                printf("[RAW] ARP-RESP mottatt for MIP %d\n", arp->mip_addr);
                arp_update(arp->mip_addr, eh->h_source);
                send_pending_messages(raw_sock, arp->mip_addr, eh->h_source);
            }
            break;
        }

        default:
            printf("[RAW] Ukjent SDU-type: %d\n", sdu_type);
            break;
    }
}


// Denne funksjonen finner et nettverksinterface (f.eks. "eth0")
// som vi kan bruke for AF_PACKET rå-sockets.
// Den hopper over "lo" (loopback), siden vi ikke vil sende MIP-pakker dit.
void find_iface(void) {
    struct ifaddrs *ifaddr, *ifa;

    // Henter en lenket liste over alle nettverksinterfaces på maskinen.
    // ifaddr peker til starten av lista.
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs"); // Skriver feilmelding hvis det feiler
        exit(1);
    }

    // Vi går gjennom alle entries i lista
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue; // Hopp over ugyldige entries

        // Vi er kun interessert i interfaces av type AF_PACKET,
        // altså lavnivå nettverksinterfaces (Ethernet, etc.)
        // Ikke f.eks. IPv4 (AF_INET) eller IPv6 (AF_INET6).
        if (ifa->ifa_addr->sa_family == AF_PACKET &&
            strcmp(ifa->ifa_name, "lo") != 0) { // Hopper over "lo" (loopback)
            
            // Kopierer navnet (eks: "eth0", "ens33", etc.) inn i global variabel
            strncpy(iface_name, ifa->ifa_name, IFNAMSIZ);
            iface_name[IFNAMSIZ - 1] = '\0'; // Sørg for at string alltid nulltermineres
            break; // Vi tar det første gyldige vi finner
        }
    }

    // Ferdig med lista – frigjør minnet
    freeifaddrs(ifaddr);

    // Hvis vi ikke fant noe interface, feiler vi
    if (iface_name[0] == '\0') {
        fprintf(stderr, "Fant ikke noe gyldig interface!\n");
        exit(1);
    }

    // Debug: skriv ut hvilket interface vi valgte
    if (debug_mode) {
        printf("[DEBUG] Bruker interface: %s\n", iface_name);
    }
}


int main(int argc, char *argv[]) {
    // Håndterer -h og -d
    int opt;
    while ((opt = getopt(argc, argv, "hd")) != -1) {
        switch(opt) {
            case 'h':
                printf("Usage: %s [-d] <socket_upper> <MIP address>\n", argv[0]);
                printf("Options:\n");
                printf("  -h      print help and exit\n");
                printf("  -d      enable debug mode\n");
                return 0;
            case 'd':
                debug_mode = 1;
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                return 1;
        }
    }

    if (optind + 2 > argc) {
        fprintf(stderr, "Usage: %s [-d] <socket_upper> <MIP address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
  
    char *socket_path = argv[optind];
    int my_mip_address;
    my_mip_address = atoi(argv[optind+1]);

    find_iface();

    

    if (debug_mode) {
        printf("[DEBUG] Starting MIP daemon on UNIX socket '%s' with MIP address %d\n",
               socket_path, my_mip_address);
        printf("[DEBUG] Initial ARP cache:\n");
        print_arp_cache();
    }

    int unix_sock = create_unix_socket(socket_path);
    int raw_sock = create_raw_socket();
    
    //ev brukes til å registrere en enkelt socket
    //events er et array av hendelser som epoll_wait() returnerer og forteller hvilke
    //sockets som har tilgjengelig data
    struct epoll_event ev, events[MAX_EVENTS];

    // oppretter en epoll instans
    // epoll instans er en beholder som kan overvåle flere fildeskroptorer samtidig
    //sockets eller filer
    int epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    // Registrer UNIX-socket
    ev.events = EPOLLIN; // ønsker å overvåke innkommende data
    ev.data.fd = unix_sock; //fil deskriptor til epoll for å vite hvilken socket det er snakk om

    //legger til instansen i epollfd (instansen fra tidligere)
    // EPOLL_CTL_ADD forteller instansen at socketen skal overvåkes
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, unix_sock, &ev) == -1) {
        perror("epoll_ctl: unix_sock");
        exit(EXIT_FAILURE);
    }

    // Registrer RAW-socket
    ev.events = EPOLLIN; // ønsker å overvåke innkommende data
    ev.data.fd = raw_sock; //fil deskriptor til epoll for å vite hvilken socket det er snakk om
    
    //samme som med unix socket
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_sock, &ev) == -1) {
        perror("epoll_ctl: raw_sock");
        exit(EXIT_FAILURE);
    }

    printf("Daemon running. Listening on UNIX + RAW sockets...\n");

    //overvåking av sockets i en evig løkke
    while (1) {
        // epoll.wait() venter på at en av de registrerte socketene får innkommende data
        //nfds holder verdien i int for hvor mange sockets som har hendelser
        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
    
        if (nfds == -1) {
            perror("epoll_wait");
            exit(EXIT_FAILURE);
        }

        //går igjennom eventuelle events i events array og sjekker om det er en unix/raw socket
        //kaller de respektive metodene for å håndtere informasjonen som mottas i forbindelsene
        for (int n = 0; n < nfds; n++) {
            if (events[n].data.fd == unix_sock) {
                handle_unix_request(unix_sock, raw_sock, my_mip_address);
            } else if (events[n].data.fd == raw_sock) {
                handle_raw_packet(raw_sock);
            }
        }
    }

    //ferdig - lukker socketene
    close(unix_sock);
    close(raw_sock);
    return 0;
}


