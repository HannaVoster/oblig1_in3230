#include <stdio.h>        
#include <string.h>       
#include <stdlib.h>       
#include <stdint.h>     
#include <net/ethernet.h> 
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>  

#include "mipd.h"
#include "pdu.h"
#include "arp.h"
#include "iface.h"

arp_entry arp_cache[MAX_ARP] = {0};


void arp_init_cache() {
    for (int i = 0; i < MAX_ARP; i++) {
        arp_cache[i].valid = 0;
        arp_cache[i].mip_addr = 0;
        memset(arp_cache[i].mac, 0, 6);
    }
}
// Oppdaterer ARP-cachen med en MIP-adresse og tilhørende MAC-adresse
void arp_update(int mip_addr, const unsigned char *mac, int ifindex) {
    if (!mac) return;

    // Gå gjennom hele ARP-cachen for å se om entry finnes fra før
    for (int i = 0; i < MAX_ARP; i++) {
        if (arp_cache[i].valid && arp_cache[i].mip_addr == mip_addr) {
            // fant en eksisterende entry, oppdater MAC-adressen
            memcpy(arp_cache[i].mac, mac, 6);
            arp_cache[i].ifindex = ifindex;
            printf("[ARP] Oppdatert MIP %d -> %02X:%02X:%02X:%02X:%02X:%02X if = %d\n\n",
                   mip_addr,
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                   ifindex);
            return;
        }
    }
    // Sett inn ny mapping
    for (int i = 0; i < MAX_ARP; i++) {
        if (!arp_cache[i].valid) {
            arp_cache[i].valid = 1;
            arp_cache[i].mip_addr = mip_addr;
            memcpy(arp_cache[i].mac, mac, 6);
            arp_cache[i].ifindex = ifindex;
            printf("[ARP] Lagt til MIP %d -> %02X:%02X:%02X:%02X:%02X:%02X if = %d\n\n",
                   mip_addr,
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                   ifindex);
            return;
        }
    }
    printf("[ARP] Cache full, kunne ikke lagre MIP %d\n", mip_addr);
}

// Søker i ARP-cachen etter en gitt MIP-adresse
// unsigned char *mac_out peker til bufferet hvor mac addressen eventuellt lagres
int arp_lookup(int mip_addr, unsigned char *mac_out, int *ifindex_out) {
    for (int i = 0; i < MAX_ARP; i++) {
        // Sjekk om entry er gyldig og har riktig MIP-adresse
        if (arp_cache[i].valid && arp_cache[i].mip_addr == mip_addr) {
            if(debug_mode){
                printf("[DEBUG] arp_lookup FOUND for mip=%u\n\n", mip_addr);
            }
            if (mac_out) memcpy(mac_out, arp_cache[i].mac, 6);
            if (ifindex_out) *ifindex_out = arp_cache[i].ifindex;
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


void send_arp_request(int raw_sock, uint8_t dest_addr, int my_mip_address) {
    mip_arp_msg req = {
        .type = ARP_REQUEST,
        .mip_addr = dest_addr,
        .reserved = 0
    };

    size_t arp_len;
    uint8_t *arp_pdu = mip_build_pdu(
        0xFF,               // broadcast MIP-destinasjon
        my_mip_address,     // kilde
        1,                  // TTL = 1
        SDU_TYPE_ARP,       // type = ARP
        (uint8_t *)&req,
        sizeof(req),
        &arp_len
    );

    unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    // Send ARP-REQ på alle ikke-loopback interfaces
    for (int i = 0; i < iface_count; i++) {
        int ifindex = iface_indices[i];

        char ifname[IFNAMSIZ];
        if_indextoname(ifindex, ifname);
        if (strncmp(ifname, "lo", 2) == 0) continue; // hopp over loopback

        // Hent MAC til dette interfacet
        unsigned char src_mac[ETH_ALEN];
        if (get_iface_mac(ifname, src_mac) < 0) {
            perror("get_iface_mac");
            continue;
        }

        // Bygg Ethernet-header (du kan også gjenbruke send_pdu her)
        send_pdu(raw_sock, arp_pdu, arp_len, broadcast_mac, ifindex);
    //     struct ethhdr eh;
    //     memcpy(eh.h_dest, broadcast_mac, ETH_ALEN);
    //     memcpy(eh.h_source, src_mac, ETH_ALEN);
    //     eh.h_proto = htons(ETH_P_MIP);

    //     uint8_t frame[sizeof(struct ethhdr) + arp_len];
    //     memcpy(frame, &eh, sizeof(struct ethhdr));
    //     memcpy(frame + sizeof(struct ethhdr), arp_pdu, arp_len);

    //     struct sockaddr_ll device = {0};
    //     device.sll_family = AF_PACKET;
    //     device.sll_protocol = htons(ETH_P_MIP);
    //     device.sll_ifindex = ifindex;
    //     device.sll_halen = ETH_ALEN;
    //     memcpy(device.sll_addr, broadcast_mac, ETH_ALEN);

    //     // Send via dette interfacet
    //     int sent = sendto(raw_sock, frame,
    //                       sizeof(struct ethhdr) + arp_len, 0,
    //                       (struct sockaddr *)&device, sizeof(device));

    //     if (sent < 0) {
    //         perror("sendto");
    //     } else if (debug_mode) {
    //         printf("[DEBUG] Sent ARP-REQ for MIP %d via %s (index=%d)\n",
    //                dest_addr, ifname, ifindex);
    //     }
    // }

    free(arp_pdu);
}
}