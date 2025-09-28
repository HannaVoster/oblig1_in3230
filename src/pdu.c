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

void mip_build_header_bytes(uint8_t *hdr,
                            uint8_t dest,
                            uint8_t src,
                            uint8_t ttl,
                            uint16_t len_words,
                            uint8_t sdu_type)
{
    hdr[0] = dest;
    hdr[1] = src;
    hdr[2] = ((ttl & 0x0F) << 4) | ((len_words >> 5) & 0x0F);
    hdr[3] = ((len_words & 0x1F) << 3) | (sdu_type & 0x07);
}


void mip_unpack_header(const uint8_t *hdr,
                       uint8_t *dest,
                       uint8_t *src,
                       uint8_t *ttl,
                       uint16_t *len_words,
                       uint8_t *sdu_type)
{
    *dest = hdr[0];
    *src  = hdr[1];
    *ttl  = (hdr[2] >> 4) & 0x0F;                 // øverste 4 bits av byte 2
    *len_words = ((hdr[2] & 0x0F) << 5) |         // nederste 4 bits av byte 2
                 ((hdr[3] >> 3) & 0x1F);          // øverste 5 bits av byte 3
    *sdu_type  = hdr[3] & 0x07;                   // nederste 3 bits av byte 3
}

uint8_t *mip_build_pdu(uint8_t dest, uint8_t src, uint8_t ttl,
                       uint8_t sdu_type,
                       const uint8_t *sdu, uint16_t sdu_len_bytes,
                       size_t *out_len)
{
    // SDU må være 32-bit justert
    uint16_t aligned = (sdu_len_bytes + 3) & ~0x03;
    uint16_t len_words = aligned / 4;

    // alloker (4 byte header + SDU pad)
    size_t total = 4 + aligned;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) {
        perror("malloc mip_build_pdu");
        exit(EXIT_FAILURE);
    }

    // pakk header (manuelt)
    buf[0] = dest;
    buf[1] = src;
    buf[2] = ((ttl & 0x0F) << 4) | ((len_words >> 5) & 0x0F);
    buf[3] = ((len_words & 0x1F) << 3) | (sdu_type & 0x07);

    // Kopier SDU + pad
    if (sdu_len_bytes && sdu) {
        memcpy(buf + 4, sdu, sdu_len_bytes);
    }
    if (aligned > sdu_len_bytes) {
        memset(buf + 4 + sdu_len_bytes, 0, aligned - sdu_len_bytes);
    }

    if (out_len) *out_len = total;

    if (debug_mode) {
        printf("[DEBUG] mip_build_pdu: dest=%u src=%u ttl=%u type=%u "
               "sdu_len=%u aligned=%u words=%u total=%zu\n\n",
               dest, src, ttl, sdu_type,
               sdu_len_bytes, aligned, len_words, total);
    }
    return buf;
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
        printf("[DEBUG] mip_parse raw header bytes: %02X %02X %02X %02X\n\n",
            rcv[0], rcv[1], rcv[2], rcv[3]);
        printf("[DEBUG] mip_parse decoded: dest=%u src=%u ttl=%u len_words=%u sdu_type=%u\n\n",
            *dest, *src, *ttl, len_words, *sdu_type);
    }
    return (ssize_t)sdu_bytes;
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
    size_t alloc_len = frame_len < 60 ? 60 : frame_len; // ny linje forå fikse malloc

    uint8_t *frame = malloc(alloc_len);

    if (!frame) {
        perror("malloc");
        return -1;
    }

    memset(frame, 0, alloc_len);

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
    
    if(debug_mode){
        printf("[DEBUG] Dump av Ethernet frame (%zu bytes):\n", frame_len);
        for (size_t i = 0; i < frame_len; i++) {
            printf("%02X ", frame[i]);
            if ((i+1) % 16 == 0) printf("\n");
        }
        printf("\n\n");
        printf("[DEBUG] TX via ifindex=%d iface=%s dest_mac=%02X:%02X:%02X:%02X:%02X:%02X\n\n",
        device.sll_ifindex, iface_name,
        dest_mac[0], dest_mac[1], dest_mac[2],
        dest_mac[3], dest_mac[4], dest_mac[5]);
    }

    size_t send_len = alloc_len;

    int sent = sendto(rawsocket, frame, send_len, 0,
                      (struct sockaddr*)&device, sizeof(device));

    free(frame);

    if (sent < 0) {
        perror("sendto");
    } else {
        if(debug_mode){printf("[DEBUG] sendto ok, bytes=%d\n", sent);}
    }
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