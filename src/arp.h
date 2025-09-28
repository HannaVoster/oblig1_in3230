#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <net/ethernet.h>  // For ETH_ALEN

#define MAX_ARP 256
#define SDU_TYPE_ARP   0x01

// ARP message (SDU payload)
// typedef struct __attribute__((packed)) {
//     uint8_t type;       // 0x00 = request, 0x01 = response
//     uint8_t mip_addr;   // hvem vi spør om / hvem som svarer
//     uint16_t reserved;  // padding = 0
// } mip_arp_msg;

// MIP-ARP message (nøyaktig 32 bits totalt)
typedef struct __attribute__((packed)) {
    unsigned int type     : 1;   // 1 bit (0 = request, 1 = response)
    unsigned int mip_addr : 8;   // 8 bits (MIP address vi spør om/svarer for)
    unsigned int reserved : 23;  // 23 bits (alltid 0)
} mip_arp_msg;

// ARP entry
typedef struct {
    uint8_t mip_addr;
    unsigned char mac[ETH_ALEN]; //alltid 6
    int valid;
} arp_entry;

extern arp_entry arp_cache[MAX_ARP];

// Funksjoner
void arp_update(int mip_addr, const unsigned char *mac);
int arp_lookup(int mip_addr, unsigned char *mac_out);
void print_arp_cache(void);

#endif
