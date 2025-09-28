#include <stdio.h>        // printf
#include <string.h>       // memcpy
#include <stdlib.h>       // free
#include <stdint.h>       // uint8_t
#include <net/ethernet.h> // ETH_ALEN

#include "mipd.h"
#include "pdu.h"
#include "arp.h"

arp_entry arp_cache[MAX_ARP] = {0};

void arp_update(int mip_addr, const unsigned char *mac) {
    if (!mac) return;

    // Oppdater hvis finnes
    for (int i = 0; i < MAX_ARP; i++) {
        if (arp_cache[i].valid && arp_cache[i].mip_addr == mip_addr) {
            memcpy(arp_cache[i].mac, mac, 6);
            printf("[ARP] Oppdatert MIP %d -> %02X:%02X:%02X:%02X:%02X:%02X\n",
                   mip_addr,
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return;
        }
    }
    // Sett inn ny
    for (int i = 0; i < MAX_ARP; i++) {
        if (!arp_cache[i].valid) {
            arp_cache[i].valid = 1;
            arp_cache[i].mip_addr = mip_addr;
            memcpy(arp_cache[i].mac, mac, 6);
            printf("[ARP] Lagt til MIP %d -> %02X:%02X:%02X:%02X:%02X:%02X\n",
                   mip_addr,
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return;
        }
    }
    printf("[ARP] Cache full, kunne ikke lagre MIP %d\n", mip_addr);
}


int arp_lookup(int mip_addr, unsigned char *mac_out) {
    if(debug_mode){
        printf("[DEBUG] arp_lookup CALLED for mip=%u\n", mip_addr);
    }
    
    for (int i = 0; i < MAX_ARP; i++) {
        if (arp_cache[i].valid && arp_cache[i].mip_addr == mip_addr) {
            if(debug_mode){
                printf("[DEBUG] arp_lookup FOUND for mip=%u\n", mip_addr);
            }
            memcpy(mac_out, arp_cache[i].mac, 6);
            return 1;
        }
    }
    return 0;
}

void print_arp_cache(void) {
    printf("=== ARP CACHE ===\n");
    for (int i = 0; i < MAX_ARP; i++) {
        if (arp_cache[i].valid) {
            printf("  MIP %d -> %02X:%02X:%02X:%02X:%02X:%02X\n",
                   arp_cache[i].mip_addr,
                   arp_cache[i].mac[0], arp_cache[i].mac[1], arp_cache[i].mac[2],
                   arp_cache[i].mac[3], arp_cache[i].mac[4], arp_cache[i].mac[5]);
        }
    }
}


int send_arp_request(int rawsock, int dest_mip) {
    mip_arp_msg req = { .type = 0x00, .mip_addr = (uint8_t)dest_mip, .reserved = 0 };

    size_t pdu_len = 0;
    uint8_t *pdu = build_pdu(
        /*dest_mip*/ 0xFF,                // broadcast på MIP-nivå
        /*src_mip*/  my_mip_address,
        /*ttl*/      1,
        /*sdu_len*/  sizeof(req),
        /*sdu_type*/ SDU_TYPE_ARP,
        /*payload*/  (uint8_t*)&req,
        &pdu_len
    );

    unsigned char bcast[ETH_ALEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    int sent = send_pdu(rawsock, pdu, pdu_len, bcast);
    free(pdu);
    return sent;
}

