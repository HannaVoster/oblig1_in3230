#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <net/ethernet.h>  // For ETH_ALEN

#define MAX_ARP 10

#define SDU_TYPE_ARP 0x01

#define ARP_REQUEST    0x00
#define ARP_RESPONSE   0x01

#define SDU_TYPE_ROUTING 0x04

// ARP message (SDU payload)
typedef struct __attribute__((packed)) {
    uint8_t type;       // 0x00 = request, 0x01 = response
    uint8_t mip_addr;   // hvem vi spør om / hvem som svarer
    uint16_t reserved;  // padding = 0
} mip_arp_msg;

// ARP entry
typedef struct {
    uint8_t mip_addr;
    unsigned char mac[6]; //alltid 6
    int valid;
} arp_entry;

extern arp_entry arp_cache[MAX_ARP]; 

// Funksjoner for å bruke arp tabellen/vise den
void arp_update(int mip_addr, const unsigned char *mac);
int arp_lookup(int mip_addr, unsigned char *mac_out);
void print_arp_cache(void);
void arp_init_cache();
void send_arp_request(int raw_sock, uint8_t dest_addr, int my_mip_address);
void print_pending_queue(void);

#endif
