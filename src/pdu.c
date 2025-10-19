#include <stdio.h>       
#include <stdlib.h>      
#include <string.h>      
#include <stdint.h>     
#include <arpa/inet.h>   
#include <net/if.h>      
#include <netpacket/packet.h> 
#include <net/ethernet.h>    
#include <sys/ioctl.h>   
#include <unistd.h>      

#include "mipd.h"
#include "pdu.h"
#include "iface.h"

/*
Bygger en komplett MIP_PDU protocol data unit som består av:
4 byte mip header
sdu, service data unit (padded til 32 bit grense)

metoden returnerer en peker til en nyallokert buffer som holder PDU
*out_len settes også til den totale lengden så den kan brukes til å sende pdu senere
*/
uint8_t *mip_build_pdu(uint8_t dest, uint8_t src, uint8_t ttl,
                       uint8_t sdu_type,
                       const uint8_t *sdu, uint16_t sdu_len_bytes,
                       size_t *out_len)
{
    // SDU må være 32-bit justert
    uint16_t aligned = (sdu_len_bytes + 3) & ~0x03;
    uint16_t len_words = aligned / 4;

    // alloker buffer (4 byte header + SDU + pad)
    size_t total = 4 + aligned;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) {
        perror("malloc mip_build_pdu");
        exit(EXIT_FAILURE);
    }

    // pakk inn headerfeltene
    buf[0] = dest;
    buf[1] = src;
    buf[2] = ((ttl & 0x0F) << 4) | ((len_words >> 5) & 0x0F);
    buf[3] = ((len_words & 0x1F) << 3) | (sdu_type & 0x07);

    // Kopier SDU + pad
    if (sdu_len_bytes && sdu) {
        memcpy(buf + 4, sdu, sdu_len_bytes);
    }
    //pad resterende bytes opp til aligned length
    if (aligned > sdu_len_bytes) {
        memset(buf + 4 + sdu_len_bytes, 0, aligned - sdu_len_bytes);
    }

    // Gi total lengde tilbake til caller
    if (out_len) *out_len = total;

    if (debug_mode) {
        printf("[DEBUG] mip_build_pdu: dest=%u src=%u ttl=%u type=%u "
               "sdu_len=%u aligned=%u words=%u total=%zu\n\n",
               dest, src, ttl, sdu_type,
               sdu_len_bytes, aligned, len_words, total);
    }
    return buf; //caller må free()
}


ssize_t mip_parse(const uint8_t *rcv, size_t rcv_len,
                  uint8_t *dest, uint8_t *src, uint8_t *ttl,
                  uint8_t *sdu_type, const uint8_t **sdu_out)
{
    if (rcv_len < 4) return -1;

    // pakker ut header
    *dest = rcv[0];
    *src  = rcv[1];
    *ttl  = (rcv[2] >> 4) & 0x0F;
    uint16_t len_words = ((rcv[2] & 0x0F) << 5) | ((rcv[3] >> 3) & 0x1F);
    *sdu_type = rcv[3] & 0x07;

    // beregner sdu lengde
    size_t sdu_bytes = (size_t)len_words * 4;
    if (rcv_len < 4 + sdu_bytes) return -1;

    if (sdu_out) *sdu_out = rcv + 4;

    if (debug_mode) {
        printf("[DEBUG][PDU] mip_parse decoded: dest=%u src=%u ttl=%u len_words=%u sdu_type=%u\n\n",
            *dest, *src, *ttl, len_words, *sdu_type);
    }
    return (ssize_t)sdu_bytes;
}

int send_pdu(int rawsocket, uint8_t *pdu, size_t pdu_length, unsigned char *dest_mac, int ifindex) {
    if (rawsocket < 0) {
        perror("rawsocket");
        exit(1);
    }

    // Bygg Ethernet-rammen (uten src MAC ennå)
    size_t frame_len = sizeof(struct ethhdr) + pdu_length;
    if (frame_len < 60) frame_len = 60; // minimum Ethernet frame size

    uint8_t *frame = calloc(1, frame_len);
    if (!frame) {
        perror("calloc");
        return -1;
    }

    // Finn interfacenavnet fra ifindex
    char ifname[IFNAMSIZ];
    unsigned char src_mac[ETH_ALEN];
    if (if_indextoname(ifindex, ifname) == NULL) {
        perror("if_indextoname");
        printf("  [DEBUG] could not resolve interface index %d\n", ifindex);
        return -1;
    } else {
        printf("  [DEBUG] using interface %s (index=%d)\n", ifname, ifindex);
    }

    if (get_iface_mac(ifname, src_mac) < 0) {
        perror("get_iface_mac");
        return -1;
    }

    // Bygg Ethernet-header for dette interfacet
    struct ethhdr *eh = (struct ethhdr *)frame;
    memcpy(eh->h_dest, dest_mac, ETH_ALEN);
    memcpy(eh->h_source, src_mac, ETH_ALEN);
    eh->h_proto = htons(ETH_P_MIP);

    // Kopier MIP-PDU inn i rammen etter headeren
    memcpy(frame + sizeof(struct ethhdr), pdu, pdu_length);

    // Sett opp sockaddr_11
    struct sockaddr_ll device = {0};
    device.sll_family   = AF_PACKET;
    device.sll_protocol = htons(ETH_P_MIP);
    device.sll_ifindex  = ifindex;
    device.sll_halen    = ETH_ALEN;
    memcpy(device.sll_addr, dest_mac, ETH_ALEN);

    // Send rammen
    int sent = sendto(rawsocket, frame, frame_len, 0,
                        (struct sockaddr *)&device, sizeof(device));

    if (sent < 0) {
        perror("sendto");
    } else if (debug_mode) {
        printf("[DEBUG] send_pdu: TX via %s (index=%d) bytes=%d\n",
                ifname, ifindex, sent);
    }
    free(frame);
    return sent;
}


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