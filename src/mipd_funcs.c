#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include "mipd.h"
#include <netpacket/packet.h>
#include <net/ethernet.h>


pending_msg pending_queue[MAX_PENDING] = {0};

//----------------------HEADER--------------------------
//GET/SET

// SET
void set_dest(mip_header_t *h, uint8_t dest) { h->dest = dest; }
void set_src(mip_header_t *h, uint8_t src)   { h->src  = src; }

void set_ttl(mip_header_t *h, uint8_t ttl) {
    h->ttl_len = (h->ttl_len & 0x0F) | ((ttl & 0x0F) << 4);
}

void set_length(mip_header_t *h, uint16_t len_words) {
    // len_words = antall 32-bits ord (ikke bytes!)
    // øverste 4 bits går i ttl_len (lavere halvdel)
    h->ttl_len = (h->ttl_len & 0xF0) | ((len_words >> 5) & 0x0F);
    // de 5 neste bit + type havner i len_type
    h->len_type = (h->len_type & 0x07) | ((len_words & 0x1F) << 3);
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

    // Kopier header inn i PDU
    memcpy(pdu, &hdr, sizeof(mip_header_t));

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

//endret til å ha en generisk sende metode
int send_pdu(int rawsocket, uint8_t *pdu, size_t pdu_length, unsigned char *dest_mac){
    if (rawsocket < 0){
        perror("socket");
        exit(1);
    }

    struct sockaddr_ll device;
    
    unsigned ifidx = if_nametoindex(iface_name);
    printf("[DEBUG] iface=%s ifindex=%d\n", iface_name, ifidx);

    if (!ifidx) {
        perror("if_nametoindex");
        return -1;
    }

    memset(&device, 0, sizeof(device)); // nullstiller
    device.sll_family   = AF_PACKET; 
    device.sll_protocol = htons(ETH_P_MIP); 
    device.sll_ifindex  = ifidx;
    device.sll_halen    = ETH_ALEN; // 6 bytes (MAC-lengde)
    memcpy(device.sll_addr, dest_mac, 6);

    int send = sendto(rawsocket, pdu, pdu_length, 0,
                      (struct sockaddr*)&device, sizeof(device));
    if(send < 0){
        perror("send_pdu");
    }

    return send;
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


void queue_message(uint8_t dest_mip, uint8_t* pdu, size_t length) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (!pending_queue[i].valid) {
            pending_queue[i].valid = 1;
            pending_queue[i].dest_mip = dest_mip;
            pending_queue[i].payload = malloc(length);
            memcpy(pending_queue[i].payload, pdu, length);
            pending_queue[i].length = length;
            printf("[QUEUE] Meldingen for MIP %d lagt i kø\n", dest_mip);
            return;
        }
    }
    printf("[QUEUE] Kø full, kunne ikke legge til melding for MIP %d\n", dest_mip);
}

void send_pending_messages(int raw_sock, uint8_t mip_addr, unsigned char* mac) {
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending_queue[i].valid && pending_queue[i].dest_mip == mip_addr) {
            send_pdu(raw_sock, pending_queue[i].payload, pending_queue[i].length, mac);
            free(pending_queue[i].payload);
            pending_queue[i].payload = NULL;
            pending_queue[i].valid = 0;
            printf("[QUEUE] Sendt kø-melding til MIP %d\n", mip_addr);
        }
    }
}





