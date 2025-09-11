#include "../src/mipd.h"
#include <stdio.h>

int main() {
    printf("=== Tester MIP-header funksjoner ===\n");

    mip_header h = {0};

    // Test set/get dest og src
    set_dest_addr(h, 42);
    set_src_addr(h, 17);
    printf("Dest: %d (forventet 42)\n", get_dest_addr(h));
    printf("Src: %d (forventet 17)\n", get_src_addr(h));

    // Test TTL
    set_ttl(h, 7);
    printf("TTL: %d (forventet 7)\n", get_ttl(h));

    // Test SDU length og type
    set_sdu_length(h, 300);  // 300 = 0x12C
    set_sdu_type(h, 9);
    printf("SDU length: %d (forventet 300)\n", get_sdu_length(h));
    printf("SDU type: %d (forventet 9)\n", get_sdu_type(h));

    printf("\n=== Tester ARP-cache funksjoner ===\n");

    // ARP test: oppdater og lookup
    unsigned char mac[6] = {0xDE,0xAD,0xBE,0xEF,0x00,0x01};
    arp_update(5, mac);

    unsigned char out[6] = {0};
    if(arp_lookup(5, out)) {
        printf("ARP HIT for MIP 5: %02X:%02X:%02X:%02X:%02X:%02X\n",
               out[0], out[1], out[2], out[3], out[4], out[5]);
    } else {
        printf("ARP MISS for MIP 5\n");
    }

    // Sjekk ARP-miss
    if(!arp_lookup(99, out)) {
        printf("ARP MISS for MIP 99 (forventet)\n");
    }

    return 0;
}
