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

arp_entry arp_cache[MAX_ARP] = {0}; // global cashe tilhørende arp.h

// Bruker i mipd.c sin main() til å initialisere ARP
// slik at MIP-daemonen starter med en ren cache uten gamle adresser
void arp_init_cache() {
    // Går gjennom hele ARP-cachen og nullstiller alle oppføringer
    for (int i = 0; i < MAX_ARP; i++) {
        arp_cache[i].valid = 0; // markerer at oppføringen ikke er gyldig
        arp_cache[i].mip_addr = 0;
        memset(arp_cache[i].mac, 0, 6); // nuller ut MAC-adressen (6 bytes)
    }
}

// Oppdaterer ARP-cachen med en MIP-adresse og tilhørende MAC-adresse
// brukes når det mottas en PING eller når man får en ARP RSP i raw_handler.c
void arp_update(int mip_addr, const unsigned char *mac, int ifindex) {
    if (!mac) return;

    // Gå gjennom hele ARP-cachen for å se om entry finnes fra før
    for (int i = 0; i < MAX_ARP; i++) {
        if (arp_cache[i].valid && arp_cache[i].mip_addr == mip_addr) {
            // fant en eksisterende entry, oppdater MAC-adressen og ifindex
            memcpy(arp_cache[i].mac, mac, 6);
            arp_cache[i].ifindex = ifindex;

            if(debug_mode) printf("[DEBUG][ARP_UPDATE] Oppdatert MIP %d -> %02X:%02X:%02X:%02X:%02X:%02X if = %d\n\n",
                   mip_addr,
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                   ifindex);
            return;
        }
    }
    // Sett inn ny mapping dersom addressen ikke finnes i arp cashen
    for (int i = 0; i < MAX_ARP; i++) {
        if (!arp_cache[i].valid) { // ledig plass

            arp_cache[i].valid = 1;
            arp_cache[i].mip_addr = mip_addr;
            memcpy(arp_cache[i].mac, mac, 6);
            arp_cache[i].ifindex = ifindex;

            if(debug_mode) printf("[DEBUG][ARP_UPDATE] Lagt til MIP %d -> %02X:%02X:%02X:%02X:%02X:%02X if = %d\n\n",
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
// samme med ifindex_out
int arp_lookup(int mip_addr, unsigned char *mac_out, int *ifindex_out) {
   if(debug_mode) printf("[DEBUG][ARP_LOOKUP] Søker etter MIP=%d\n", mip_addr);

    for (int i = 0; i < MAX_ARP; i++) {
        // Sjekk om entry er gyldig og har riktig MIP-adresse
        if (arp_cache[i].valid && arp_cache[i].mip_addr == mip_addr) {
            
               if(debug_mode) printf("[DEBUG] arp_lookup FOUND for mip=%u\n\n", mip_addr);
            
            if (mac_out) memcpy(mac_out, arp_cache[i].mac, 6); // kopierer over mac addresse
            if (ifindex_out) *ifindex_out = arp_cache[i].ifindex; // kopierer over ifindex

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

/*
Sender en ARP REQ til alle ikke loopback interface

 Flyt i systemet:
    1. En pakke skal videresendes, men routingd må først finne ruten - send_route_request()
    2. Routingd svarer med handle_route_response(next_hop)
    3. Hvis MAC-adressen til next_hop ikke finnes i ARP-cachen - HER send_arp_request() kalles
    4. Når ARP-RESP kommer, oppdateres ARP-cachen (arp_update)
       og eventuelle ventende meldinger sendes (send_pending_messages())
*/
void send_arp_request(int raw_sock, uint8_t dest_addr, int my_mip_address) {

     // Lager en ARP-request-melding som spør hvem som har mip addressen, dest_addr
    mip_arp_msg req = {
        .type = ARP_REQUEST,
        .mip_addr = dest_addr,
        .reserved = 0
    };

     // Bygger en MIP-PDU som inneholder ARP-requesten
    size_t arp_len;
    uint8_t *arp_pdu = mip_build_pdu(
        0xFF,               // broadcast MIP-destinasjon, sendes til alle
        my_mip_address,     // kilde
        1,                  // TTL = 1, skal ikke videresendes
        SDU_TYPE_ARP,       // type = ARP
        (uint8_t *)&req,
        sizeof(req),
        &arp_len
    );

    // Setter opp broadcast MAC-adresse
    unsigned char broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    // Send ARP-REQ på alle ikke-loopback interfaces
    for (int i = 0; i < iface_count; i++) {
        int ifindex = iface_indices[i];

        char ifname[IFNAMSIZ];
        if_indextoname(ifindex, ifname); // oversetter ifindex til navn 

        if (strncmp(ifname, "lo", 2) == 0) continue; // hopp over loopback

        // Hent MAC til dette interfacet
        unsigned char src_mac[ETH_ALEN];
        if (get_iface_mac(ifname, src_mac) < 0) {
            perror("get_iface_mac");
            continue;
        }

         // Sender PDU-en som en Ethernet-broadcast på dette interfacet
        send_pdu(raw_sock, arp_pdu, arp_len, broadcast_mac, ifindex);
    }

    // Frigir minnet som ble allokert for ARP-PDU-en
    free(arp_pdu);
}