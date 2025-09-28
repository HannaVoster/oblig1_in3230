#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include "mipd.h"
#include "pdu.h"
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h> 
#include <sys/ioctl.h>
#include <unistd.h>

pending_entry pending_queue[MAX_PENDING] = {0};

//----------------------HEADER--------------------------
//GET/SET

// SET
void set_dest(mip_header_t *h, uint8_t dest) { h->dest = dest; }
void set_src(mip_header_t *h, uint8_t src)   { h->src  = src; }

void set_ttl(mip_header_t *h, uint8_t ttl) {
    h->ttl_len = (ttl << 4) | (h->ttl_len & 0x0F);
}

void set_length(mip_header_t *h, uint16_t len_words) {
    // split opp length = 9 bits i high(4) + low(5)
    uint8_t high = (len_words >> 5) & 0x0F;  // øverste 4
    uint8_t low  = len_words & 0x1F;         // nederste 5
    // sett low inn i len_type[7:3], behold type i [2:0]
    h->len_type = (low << 3) | (h->len_type & 0x07);
    // sett high inn i ttl_len[3:0], behold TTL i [7:4]
    h->ttl_len  = (h->ttl_len & 0xF0) | high;
}

void set_type(mip_header_t *h, uint8_t type) {
    h->len_type = (h->len_type & 0xF8) | (type & 0x07);
}

// GET
uint8_t get_dest(const mip_header_t *h) { return h->dest; }
uint8_t get_src (const mip_header_t *h) { return h->src; }

uint8_t get_ttl(const mip_header_t *h) {
    return (h->ttl_len >> 4) & 0x0F;
}

uint16_t get_length(const mip_header_t *h) {
    uint16_t high = h->ttl_len & 0x0F;
    uint16_t low  = (h->len_type >> 3) & 0x1F;
    return (high << 5) | low;
}

uint8_t get_type(const mip_header_t *h) {
    return h->len_type & 0x07;
}

//------------------PDU------------------

// pdu = header + payload
uint8_t* build_pdu(uint8_t dest_addr,
                   uint8_t src_addr,
                   uint8_t ttl,
                   uint16_t sdu_length_bytes,
                   uint8_t sdu_type,
                   const uint8_t* payload,
                   size_t* out_length) 
{
    printf("[DEBUG] build_pdu CALLED: sdu_length_bytes=%u\n", sdu_length_bytes);

    // Align til 32-bit (RFC: payload må være delelig på 4)
    uint16_t aligned_length_bytes = (sdu_length_bytes + 3) & ~0x03;
    uint16_t length_in_words = aligned_length_bytes / 4;

    // Alloker buffer: header (4) + payload (aligned)
    size_t total_len = sizeof(mip_header_t) + aligned_length_bytes;
    uint8_t* pdu = malloc(total_len);
    if (!pdu) {
        perror("malloc build_pdu");
        exit(EXIT_FAILURE);
    }

    // Sett opp header
    mip_header_t hdr = {0};
    set_dest(&hdr, dest_addr);
    set_src(&hdr, src_addr);
    set_ttl(&hdr, ttl);
    set_length(&hdr, length_in_words);
    set_type(&hdr, sdu_type);

    // Kopier header
    memcpy(pdu, &hdr, sizeof(mip_header_t));

    // Kopier reell payload (kan være 17)
    if (sdu_length_bytes > 0 && payload) {
        memcpy(pdu + sizeof(mip_header_t), payload, sdu_length_bytes);
    }

    // Pad resten med nuller (hvis ikke allerede aligned)
    if (aligned_length_bytes > sdu_length_bytes) {
        memset(pdu + sizeof(mip_header_t) + sdu_length_bytes,
               0,
               aligned_length_bytes - sdu_length_bytes);
    }

    // Sett ut-lengde (total PDU)
    if (out_length) {
        *out_length = total_len;
    }

    if (debug_mode) {
        printf("[DEBUG] build_pdu: dest=%u src=%u ttl=%u type=%u "
               "sdu_length=%u aligned=%u words=%u total=%zu\n",
               dest_addr, src_addr, ttl, sdu_type,
               sdu_length_bytes, aligned_length_bytes,
               length_in_words, total_len);
    }

    return pdu;
}



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

int send_pdu(int rawsocket, uint8_t *pdu, size_t pdu_length, unsigned char *dest_mac) {
    if (rawsocket < 0) {
        perror("rawsocket");
        exit(1);
    }

    unsigned ifidx = if_nametoindex(iface_name);
    if (!ifidx) {
        perror("if_nametoindex");
        return -1;
    }

    unsigned char src_mac[ETH_ALEN];
    if (get_iface_mac(iface_name, src_mac) < 0) {
        perror("get_iface_mac");
        return -1;
    }

    // Bygg Ethernet-ramme
    size_t frame_len = sizeof(struct ethhdr) + pdu_length;
    uint8_t *frame = malloc(frame_len);
    if (!frame) {
        perror("malloc");
        return -1;
    }

    struct ethhdr *eh = (struct ethhdr *)frame;
    memcpy(eh->h_dest, dest_mac, ETH_ALEN);
    memcpy(eh->h_source, src_mac, ETH_ALEN);
    eh->h_proto = htons(ETH_P_MIP);

    memcpy(frame + sizeof(struct ethhdr), pdu, pdu_length);

    // Sett opp sockaddr_ll
    struct sockaddr_ll device;
    memset(&device, 0, sizeof(device));
    device.sll_family   = AF_PACKET;
    device.sll_protocol = htons(ETH_P_MIP);
    device.sll_ifindex  = ifidx;
    device.sll_halen    = ETH_ALEN;
    memcpy(device.sll_addr, dest_mac, ETH_ALEN);

    // Minste Ethernet-frame (uten FCS) er 60 bytes
    if (frame_len < 60) {
        memset(frame + frame_len, 0, 60 - frame_len);  // pad med nuller
        frame_len = 60;
    }

    printf("[DEBUG] Dump av Ethernet frame (%zu bytes):\n", frame_len);
    for (size_t i = 0; i < frame_len; i++) {
        printf("%02X ", frame[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n");

    int sent = sendto(rawsocket, frame, frame_len, 0,
                      (struct sockaddr*)&device, sizeof(device));

    free(frame);

    if (sent < 0) {
        perror("sendto");
    } else {
        printf("[DEBUG] sendto ok, bytes=%d\n", sent);
    }

    return sent;
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








