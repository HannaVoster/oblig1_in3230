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
#include "pdu.h"

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

    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind raw socket");
        close(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}


void handle_unix_request(int unix_sock, int raw_sock, int my_mip_address) {
    int client = accept(unix_sock, NULL, NULL);
    if (client < 0) return;

    char buffer[256];
    int n = read(client, buffer, sizeof(buffer));

    if (n > 0) {
        uint8_t dest_addr = buffer[0];
        uint8_t* payload = (uint8_t*)&buffer[1];
        size_t payload_length = n - 1;   // korrekt lengde

        // Debug
        printf("[DEBUG] handle_unix_request: n=%d dest=%d payload_len=%zu\n",
               n, dest_addr, payload_length);
        printf("[DEBUG] payload bytes: ");
        for (size_t i = 0; i < payload_length && i < 8; i++) {
            printf("%02X ", payload[i]);
        }
        printf("\n");

        unsigned char mac[6];
        printf("[DEBUG] Checking ARP for dest=%u\n", dest_addr);
        if (arp_lookup(dest_addr, mac)) {
            // MAC finnes → bygg og send PING nå
            size_t pdu_len;
            uint8_t* pdu = mip_build_pdu(
                dest_addr,             // dest
                my_mip_address,        // src
                4,                     // ttl
                SDU_TYPE_PING,         // type
                payload,               // payload
                payload_length,        // payload_len (bytes!)
                &pdu_len
            );
            send_pdu(raw_sock, pdu, pdu_len, mac);
            free(pdu);
        } else {
            // MAC finnes ikke → legg på vent
            queue_message(dest_addr, SDU_TYPE_PING, payload, payload_length);

            // Send ARP request
            mip_arp_msg req = { .type = 0x00, .mip_addr = dest_addr, .reserved = 0 };
            size_t arp_len;
            uint8_t* arp_pdu = mip_build_pdu(
                0xFF,                  // broadcast dest
                my_mip_address,        // src
                1,                     // ttl
                SDU_TYPE_ARP,          // type
                (uint8_t*)&req,        // payload
                sizeof(req),           // payload_len
                &arp_len
            );
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

void handle_raw_packet(int raw_sock, int my_mip_address) {
    uint8_t buffer[2000];
    struct sockaddr_ll src_addr;
    struct iovec iov = { buffer, sizeof(buffer) };
    struct msghdr msg = { .msg_name = &src_addr, .msg_namelen = sizeof(src_addr),
                          .msg_iov = &iov, .msg_iovlen = 1 };

    int len = recvmsg(raw_sock, &msg, 0);
    if (len < (int)sizeof(struct ethhdr)) return; // må minst ha Ethernet-header

    struct ethhdr *eh = (struct ethhdr *)buffer;

    if (ntohs(eh->h_proto) != ETH_P_MIP)
        return; // feil protokoll

    const uint8_t *mip_start = buffer + sizeof(struct ethhdr);
    size_t mip_len = len - sizeof(struct ethhdr);

    uint8_t dest, src, ttl, sdu_type;
    const uint8_t *sdu;
    ssize_t sdu_len = mip_parse(mip_start, mip_len,
                                &dest, &src, &ttl,
                                &sdu_type, &sdu);
    if (sdu_len < 0) {
        printf("[ERROR] ugyldig MIP PDU (len=%d)\n", len);
        return;
    }

    if (dest != my_mip_address && dest != 0xFF) {
        // ikke til meg og ikke broadcast
        return;
    }

    switch (sdu_type) {
        case SDU_TYPE_PING: {
            printf("[RAW] PING mottatt fra MIP %u\n", src);
            size_t pdu_len = 0;
            uint8_t *pdu = mip_build_pdu(
                /*dest*/ src,
                /*src */ my_mip_address,
                /*ttl */ 4,
                /*type*/ SDU_TYPE_PONG,
                sdu, (uint16_t)sdu_len,
                &pdu_len
            );
            send_pdu(raw_sock, pdu, pdu_len, eh->h_source);
            free(pdu);
            break;
        }

        case SDU_TYPE_PONG: {
            printf("[RAW] PONG mottatt fra MIP %u: %.*s\n",
                   src, (int)sdu_len, (char*)sdu);
            if (last_unix_client_fd > 0) {
                (void)write(last_unix_client_fd, sdu, sdu_len);
                close(last_unix_client_fd);
                last_unix_client_fd = -1;
            }
            break;
        }

        case SDU_TYPE_ARP: {
            if (sdu_len < (ssize_t)sizeof(mip_arp_msg)) {
                printf("[ERROR] ARP SDU for kort (%zd bytes)\n", sdu_len);
                return;
            }

            const mip_arp_msg *arp = (const mip_arp_msg*)sdu;
            printf("[DEBUG] ARP msg: type=%u mip_addr=%u (payload_len=%zd)\n",
                   arp->type, arp->mip_addr, sdu_len);

            if (arp->type == 0x00 && arp->mip_addr == my_mip_address) {
                // REQ til meg
                mip_arp_msg resp = { .type = 0x01, .mip_addr = (uint8_t)my_mip_address, .reserved = 0 };
                size_t pdu_len = 0;
                uint8_t *pdu = mip_build_pdu(
                    src, my_mip_address, 1,
                    SDU_TYPE_ARP,
                    (uint8_t*)&resp, sizeof(resp),
                    &pdu_len
                );
                send_pdu(raw_sock, pdu, pdu_len, eh->h_source);
                free(pdu);
            }
            else if (arp->type == 0x01) {
                // RESP
                printf("[RAW] ARP-RESP mottatt for MIP %d\n", arp->mip_addr);
                arp_update(arp->mip_addr, eh->h_source);
                send_pending_messages(raw_sock, arp->mip_addr, eh->h_source, my_mip_address);
            }
            break;
        }

        default:
            printf("[RAW] Ukjent SDU-type: %u\n", sdu_type);
            break;
    }
}

//Ok

// håndterer en forbindelse på RAW socket
// void handle_raw_packet(int raw_sock) {
//     uint8_t buffer[2000];
//     struct sockaddr_ll src_addr;
//     struct iovec iov = { .iov_base = buffer, .iov_len = sizeof(buffer) };
//     struct msghdr msg = {
//         .msg_name    = &src_addr,
//         .msg_namelen = sizeof(src_addr),
//         .msg_iov     = &iov,
//         .msg_iovlen  = 1
//     };

//     // Bruk ssize_t (match recvmsg-signatur)
//     ssize_t len = recvmsg(raw_sock, &msg, 0);
//     if (len < 0) {
//         perror("recvmsg");
//         return;
//     }

//     if (len < (ssize_t)sizeof(struct ethhdr)) {
//         // For lite til å inneholde Ethernet-header
//         return;
//     }

//     if (debug_mode) {
//         printf("[DEBUG] recvmsg got %zd bytes\n", len);
//         for (ssize_t i = 0; i < len; i++) {
//             printf("%02X ", buffer[i]);
//             if ((i + 1) % 16 == 0) printf("\n");
//         }
//         printf("\n");
//     }

//     // Tolker Ethernet-header
//     struct ethhdr *eh = (struct ethhdr *)buffer;

//     // Filtrer på vårt Ethertype (MIP)
//     if (ntohs(eh->h_proto) != ETH_P_MIP) return;

//     if (debug_mode) {
//         printf("[DEBUG] recv: src=");
//         for (int i = 0; i < ETH_ALEN; i++) printf("%02X:", eh->h_source[i]);
//         printf(" dst=");
//         for (int i = 0; i < ETH_ALEN; i++) printf("%02X:", eh->h_dest[i]);
//         printf(" proto=0x%04X\n", ntohs(eh->h_proto));
//     }

//     // Sjekk at vi har plass til MIP-header etter Ethernet
//     if (len < (ssize_t)(sizeof(struct ethhdr) + sizeof(mip_header_t))) {
//         printf("[ERROR] Frame for kort: len=%zd\n", len);
//         return;
//     }

//     // Pek på MIP-headeren rett etter Ethernet
//     uint8_t *mip_hdr_start = buffer + sizeof(struct ethhdr);

//     mip_header_t hdr;
//     memcpy(&hdr, mip_hdr_start, sizeof(mip_header_t));

//     uint8_t  src_mip  = get_src(&hdr);
//     uint8_t  dest_mip = get_dest(&hdr);
//     uint8_t  ttl      = get_ttl(&hdr);
//     uint8_t  sdu_type = get_type(&hdr);
//     uint16_t sdu_len  = get_length(&hdr) * 4; // length feltet er i 32-bit ord

//     // Sjekk at hele SDU faktisk er mottatt
//     ssize_t need = (ssize_t)(sizeof(struct ethhdr) + sizeof(mip_header_t) + sdu_len);
//     if (len < need) {
//         printf("[ERROR] Frame len=%zd for kort for SDU=%u (need=%zd)\n", len, sdu_len, need);
//         return;
//     }

//     uint8_t *payload = mip_hdr_start + sizeof(mip_header_t);

//     if (debug_mode) {
//         printf("[DEBUG] Parsed MIP header: src=%u dest=%u ttl=%u len=%u type=%u\n",
//                src_mip, dest_mip, ttl, sdu_len, sdu_type);

//         printf("[DEBUG] Payload dump (%u bytes):\n", sdu_len);
//         for (uint16_t i = 0; i < sdu_len; i++) {
//             printf("%02X ", payload[i]);
//             if ((i + 1) % 16 == 0) printf("\n");
//         }
//         printf("\n");
//     }

//     // Kun prosesser pakker til oss eller broadcast
//     if (dest_mip != my_mip_address && dest_mip != 0xFF) return;

//     printf("[DEBUG] handle_raw_packet: src_mip=%u dest_mip=%u type=%u len=%u\n",
//        src_mip, dest_mip, sdu_type, sdu_len);

//     switch (sdu_type) {
//         case SDU_TYPE_PING: {
//             printf("[RAW] PING mottatt fra MIP %u\n", src_mip);
//             // Bygg PONG med samme payload tilbake
//             size_t pdu_len = 0;
//             uint8_t *pdu = build_pdu(
//                 /*dest*/ src_mip,
//                 /*src */ my_mip_address,
//                 /*ttl */ 4,
//                 /*len */ sdu_len,
//                 /*type*/ SDU_TYPE_PONG,
//                 /*data*/ payload,
//                 &pdu_len
//             );
//             // Svar til avsenders MAC fra Ethernet-header
//             send_pdu(raw_sock, pdu, pdu_len, eh->h_source);
//             free(pdu);
//             break;
//         }

//         case SDU_TYPE_PONG: {
//             printf("[RAW] PONG mottatt fra MIP %u: %.*s\n", src_mip, sdu_len, (char*)payload);
//             if (last_unix_client_fd > 0) {
//                 // send SDU tilbake til klient på UNIX-socket
//                 (void)write(last_unix_client_fd, payload, sdu_len);
//                 close(last_unix_client_fd);
//                 last_unix_client_fd = -1;
//             }
//             break;
//         }

//         case SDU_TYPE_ARP: {
//             // MIP-ARP payload forventes å være minst 4 bytes (type + addr + padding)
//             if (sdu_len < 4) {
//                 printf("[ERROR] ARP SDU for kort (%u bytes)\n", sdu_len);
//                 return;
//             }

//             mip_arp_msg *arp = (mip_arp_msg*)payload;

//             printf("[DEBUG] ARP msg: type=%u mip_addr=%u (payload_len=%u)\n",
//             arp->type, arp->mip_addr, sdu_len);

//             if (arp->type == 0x00 /*REQ*/ && arp->mip_addr == my_mip_address) {
//                 printf("[RAW] ARP-REQ for meg (%d)\n", my_mip_address);

//                 // Send ARP-RESP tilbake unicast
//                 mip_arp_msg resp = { .type = 0x01, .mip_addr = (uint8_t)my_mip_address, .reserved = 0 };
//                 size_t pdu_len = 0;
//                 uint8_t *pdu = build_pdu(
//                     /*dest*/ src_mip,
//                     /*src */ my_mip_address,
//                     /*ttl */ 1,
//                     /*len */ (uint16_t)sizeof(resp),
//                     /*type*/ SDU_TYPE_ARP,
//                     /*data*/ (uint8_t*)&resp,
//                     &pdu_len
//                 );
//                 send_pdu(raw_sock, pdu, pdu_len, eh->h_source);
//                 free(pdu);
//             }
//             else if (arp->type == 0x01 /*RESP*/) {
//                 printf("[RAW] ARP-RESP mottatt for MIP %d\n", arp->mip_addr);
//                 // Lær MAC fra Ethernet-kilde
//                 arp_update(arp->mip_addr, eh->h_source);
//                 // Send alle køede meldinger til denne MIP-adressen
//                 send_pending_messages(raw_sock, arp->mip_addr, eh->h_source, my_mip_address);
//             }
//             break;
//         }

//         default:
//             printf("[RAW] Ukjent SDU-type: %u\n", sdu_type);
//             break;
//     }
// }



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
                handle_raw_packet(raw_sock, my_mip_address);
            }
        }
    }

    mip_header_t h = {0};

    set_dest(&h, 0xFF);
    set_src(&h, 0x0A);
    set_ttl(&h, 1);
    set_length(&h, 1);
    set_type(&h, 1);

    printf("ttl_len=0x%02X len_type=0x%02X\n", h.ttl_len, h.len_type);
    printf("dest=%d src=%d ttl=%d len=%d type=%d\n",
        get_dest(&h), get_src(&h), get_ttl(&h),
        get_length(&h), get_type(&h));

    //ferdig - lukker socketene
    close(unix_sock);
    close(raw_sock);
    return 0;
}


