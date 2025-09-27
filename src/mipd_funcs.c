#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include "mipd.h"
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

uint8_t* build_pdu(
    uint8_t dest_addr, 
    uint8_t src_addr, 
    uint8_t ttl, 
    uint16_t sdu_length_bytes,
    uint8_t sdu_type,
    const uint8_t* payload,
    size_t* out_length
    ){ 
    //build buffer with both header and payload

    //kontroller lengde på payload for å gjøre pdu delelig med 4?

    uint16_t aligned_length_bytes = (sdu_length_bytes + 3) & ~0x03;

    // RFC: SDU length skal lagres i words (32-bit ord)
    uint16_t length_in_words = aligned_length_bytes / 4;

    printf("[DEBUG] build_pdu: sdu_length=%u aligned=%u words=%u total=%zu\n",
       sdu_length_bytes, aligned_length_bytes, length_in_words,
       sizeof(mip_header_t)+aligned_length_bytes);

    // Alloker plass: header (4 byte) + payload (padded)
    uint8_t* pdu = malloc(sizeof(mip_header_t) + aligned_length_bytes);
    if (!pdu) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // Bygg header
    mip_header_t hdr = {0};
    set_dest(&hdr, dest_addr);
    set_src(&hdr, src_addr);
    set_ttl(&hdr, ttl);
    set_length(&hdr, length_in_words);
    set_type(&hdr, sdu_type);

    printf("ttl_len=0x%02X len_type=0x%02X\n", hdr.ttl_len, hdr.len_type);


    printf("[DEBUG] Header: dest=%u src=%u ttl=%u len_words=%u type=%u\n",
       get_dest(&hdr), get_src(&hdr), get_ttl(&hdr),
       get_length(&hdr), get_type(&hdr));

    printf("[DEBUG] build_pdu: len_words=%u, sdu_type=%u\n", length_in_words, sdu_type);
    // Kopier header inn i PDU
    memcpy(pdu, &hdr, sizeof(mip_header_t));

    printf("sizeof(mip_header_t)=%zu\n", sizeof(mip_header_t));
    // Kopier payload
    memcpy(pdu + sizeof(mip_header_t), payload, sdu_length_bytes);

    // Nullfyll padding hvis nødvendig
    if (aligned_length_bytes > sdu_length_bytes) {
        memset(pdu + sizeof(mip_header_t) + sdu_length_bytes, 0,
               aligned_length_bytes - sdu_length_bytes);
    }

    // Total PDU-lengde i bytes (inkl. header)
    if (out_length) {
        *out_length = sizeof(mip_header_t) + aligned_length_bytes;
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


//Broadcast
int send_broadcast(int dst, int rawsocket){
    //raw socket broadcast kode
    mip_arp_msg req;
    req.type = 0x00; // ARP Request
    req.mip_addr = dst;
    req.reserved = 0;

    size_t pdu_len;
    uint8_t* pdu = build_pdu(
        dst,
        my_mip_address,
        1, //TTL
        sizeof(req), 
        SDU_TYPE_ARP,  
        (uint8_t*)&req,
        &pdu_len)
        ;

    unsigned char broadcast_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; // broadcast mac adresse

    send_pdu(rawsocket, pdu, pdu_len, broadcast_mac);
  
    free(pdu);
    return 0;
}


void queue_message(uint8_t dest_mip, uint8_t sdu_type, uint8_t* data, size_t length) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (!pending_queue[i].valid) {
            pending_queue[i].valid = 1;
            pending_queue[i].dest_mip = dest_mip;
            pending_queue[i].sdu_type = sdu_type;
            pending_queue[i].payload = malloc(length);
            memcpy(pending_queue[i].payload, data, length);
            pending_queue[i].length = length;
            printf("[QUEUE] Meldingen for MIP %d lagt i kø\n", dest_mip);
            return;
        }
    }
    printf("[QUEUE] Kø full, kunne ikke legge til melding for MIP %d\n", dest_mip);
}


void send_pending_messages(int raw_sock, uint8_t mip_addr, unsigned char* mac, int my_mip_address) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending_queue[i].valid && pending_queue[i].dest_mip == mip_addr) {
            size_t pdu_len;
            uint8_t *pdu = build_pdu(
                pending_queue[i].dest_mip,
                my_mip_address,
                4, // ttl
                pending_queue[i].length,
                pending_queue[i].sdu_type,
                pending_queue[i].payload,
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






