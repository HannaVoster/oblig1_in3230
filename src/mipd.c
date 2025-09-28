#include <stdio.h>          // printf, perror, fprintf
#include <stdlib.h>         // malloc, free, exit
#include <string.h>         // memset, memcpy, strncpy, strcmp
#include <unistd.h>         // read, write, close, unlink
#include <sys/epoll.h>      // epoll_event, epoll_* (hvis brukt)
#include <sys/socket.h>     // socket, bind, listen, accept, recvmsg
#include <sys/un.h>         // sockaddr_un
#include <sys/ioctl.h>      // ioctl
#include <netpacket/packet.h> // sockaddr_ll, AF_PACKET
#include <net/ethernet.h>   // ETH_P_*, ETH_ALEN
#include <net/if.h>         // if_nametoindex, ifreq, IFNAMSIZ
#include <arpa/inet.h>      // htons, ntohs
#include <netinet/if_ether.h> // struct ether_header
#include <ifaddrs.h>        // getifaddrs, freeifaddrs

#include "mipd.h"
#include "pdu.h"
#include "arp.h"


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

pending_entry pending_queue[MAX_PENDING] = {0};

// Bygger en Ethernet + MIP-ramme
// - dst_mac: MAC til mottaker (fra ARP eller FF:FF:FF:FF:FF:FF)
// - src_mac: MAC til vårt interface (fra ioctl(SIOCGIFHWADDR))
// - payload: peker til MIP-header + SDU (bygget av build_pdu())
// - payload_len: lengde av MIP-header + SDU
// - out_len: returnerer total lengde på Ethernet-ramma
uint8_t* build_frame(unsigned char *dst_mac,
                     unsigned char *src_mac,
                     uint8_t *payload, size_t payload_len,
                     size_t *out_len) {
    // Ethernet header er 14 bytes
    size_t frame_len = sizeof(struct ether_header) + payload_len;
    uint8_t *frame = malloc(frame_len);
    if (!frame) {
        perror("malloc frame");
        exit(1);
    }

    // Pek til headeren i bufferen
    struct ether_header *eh = (struct ether_header *)frame;

    // Kopier MAC-adressene
    memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
    memcpy(eh->ether_shost, src_mac, ETH_ALEN);

    // Sett protokollfeltet til vår egen MIP-protokoll
    eh->ether_type = htons(ETH_P_MIP);

    // Kopier inn payload rett etter Ethernet-headeren
    memcpy(frame + sizeof(struct ether_header), payload, payload_len);

    // Returner total lengde
    *out_len = frame_len;
    return frame;
}


// Henter MAC-adressen til vårt interface
int get_iface_mac(const char *ifname, unsigned char *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        close(fd);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(fd);
    return 0;
}



// Legg melding i pending-kø
void queue_message(uint8_t dest_mip, uint8_t sdu_type,
                   uint8_t *data, size_t length_bytes) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (!pending_queue[i].valid) {
            printf("[DEBUG] queue_message: dest=%d type=%d len=%zu bytes\n",
                   dest_mip, sdu_type, length_bytes);

            pending_queue[i].valid    = 1;
            pending_queue[i].dest_mip = dest_mip;
            pending_queue[i].sdu_type = sdu_type;
            pending_queue[i].length   = length_bytes;  // alltid bytes

            pending_queue[i].payload = malloc(length_bytes);

            printf("[DEBUG] queue_message saved: len=%zu at slot=%d, payload[0]=0x%02X\n",
                pending_queue[i].length, i, pending_queue[i].payload[0]);

            if (!pending_queue[i].payload) {
                perror("[ERROR] malloc queue_message");
                exit(EXIT_FAILURE);
            }
            memcpy(pending_queue[i].payload, data, length_bytes);

            printf("[QUEUE] Meldingen for MIP %d lagt i kø\n", dest_mip);
            return;
        }
    }
    printf("[QUEUE] Kø full, kunne ikke legge til melding for MIP %d\n", dest_mip);
}


void send_pending_messages(int raw_sock, uint8_t mip_addr,
                           unsigned char *mac, int my_mip_address) {

    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending_queue[i].valid && pending_queue[i].dest_mip == mip_addr) {
            printf("[DEBUG] send_pending_messages: dest=%d type=%d len=%zu bytes valid=%d\n",
                   pending_queue[i].dest_mip,
                   pending_queue[i].sdu_type,
                   pending_queue[i].length,
                   pending_queue[i].valid);

            if (pending_queue[i].length == 0 || pending_queue[i].payload == NULL) {
                printf("[ERROR] Pending entry corrupt: len=0 eller payload=NULL for MIP %d\n",
                       pending_queue[i].dest_mip);
                pending_queue[i].valid = 0;
                continue;
            }

            printf("[DEBUG] send_pending_messages using slot=%d len=%zu type=%d dest=%d\n",
                   i,
                   pending_queue[i].length,
                   pending_queue[i].sdu_type,
                   pending_queue[i].dest_mip);

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
            free(pending_queue[i].payload);
            pending_queue[i].payload = NULL;
            pending_queue[i].valid = 0;

            printf("[QUEUE] Sendt kø-melding til MIP %d\n", mip_addr);
        }
    }
}





