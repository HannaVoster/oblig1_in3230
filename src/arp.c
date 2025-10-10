#include <stdio.h>        // printf
#include <string.h>       // memcpy
#include <stdlib.h>       // free
#include <stdint.h>       // uint8_t
#include <net/ethernet.h> // ETH_ALEN

#include "mipd.h"
#include "pdu.h"
#include "arp.h"

arp_entry arp_cache[MAX_ARP] = {0};


void arp_init_cache() {
    for (int i = 0; i < MAX_ARP; i++) {
        arp_cache[i].valid = 0;
        arp_cache[i].mip_addr = 0;
        memset(arp_cache[i].mac, 0, 6);
    }
}
// Oppdaterer ARP-cachen med en MIP-adresse og tilhørende MAC-adresse
void arp_update(int mip_addr, const unsigned char *mac) {
    if (!mac) return;

    // Gå gjennom hele ARP-cachen for å se om entry finnes fra før
    for (int i = 0; i < MAX_ARP; i++) {
        if (arp_cache[i].valid && arp_cache[i].mip_addr == mip_addr) {
            // fant en eksisterende entry, oppdater MAC-adressen
            memcpy(arp_cache[i].mac, mac, 6);
            printf("[ARP] Oppdatert MIP %d -> %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                   mip_addr,
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return;
        }
    }
    // Sett inn ny mapping
    for (int i = 0; i < MAX_ARP; i++) {
        if (!arp_cache[i].valid) {
            arp_cache[i].valid = 1;
            arp_cache[i].mip_addr = mip_addr;
            memcpy(arp_cache[i].mac, mac, 6);
            printf("[ARP] Lagt til MIP %d -> %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                   mip_addr,
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            return;
        }
    }
    printf("[ARP] Cache full, kunne ikke lagre MIP %d\n", mip_addr);
}

// Søker i ARP-cachen etter en gitt MIP-adresse
// unsigned char *mac_out peker til bufferet hvor mac addressen eventuellt lagres
int arp_lookup(int mip_addr, unsigned char *mac_out) {
    for (int i = 0; i < MAX_ARP; i++) {
        // Sjekk om entry er gyldig og har riktig MIP-adresse
        if (arp_cache[i].valid && arp_cache[i].mip_addr == mip_addr) {
            if(debug_mode){
                printf("[DEBUG] arp_lookup FOUND for mip=%u\n\n", mip_addr);
            }
            memcpy(mac_out, arp_cache[i].mac, 6);
            return 1;
        }
    }
    return 0; //ikke funnet
}
//funksjon til debugging, for å sjekke at ARP cashe oppdateeres riktig
//brukes av main
void print_arp_cache(void) {
    printf("-- ARP CACHE --\n");
    for (int i = 0; i < MAX_ARP; i++) {
        if (arp_cache[i].valid) {
            printf("  MIP %d -> %02X:%02X:%02X:%02X:%02X:%02X\n\n",
                   arp_cache[i].mip_addr,
                   arp_cache[i].mac[0], arp_cache[i].mac[1], arp_cache[i].mac[2],
                   arp_cache[i].mac[3], arp_cache[i].mac[4], arp_cache[i].mac[5]);
        }
    }
}
