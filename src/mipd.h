//funksjonsdeklarering for mipd.c

#ifndef MIPD_H
#define MIPD_H

#include <stdint.h>
typedef uint8_t mip_header[4];

// ARP-funksjoner
void arp_update(int mip_addr, unsigned char *mac);
int arp_lookup(int mip_addr, unsigned char *mac_out);

// Header-funksjoner
void set_dest_addr(mip_header header, uint8_t dest_addr);
void set_src_addr(mip_header header, uint8_t scr_addr);
void set_ttl(mip_header header, uint8_t ttl);
void set_sdu_length(mip_header header, uint16_t sdu_length);
void set_sdu_type(mip_header header, uint8_t sdu_type);

uint8_t get_dest_addr(const mip_header header);
uint8_t get_src_addr(const mip_header header);
uint8_t get_ttl(const mip_header header);
uint16_t get_sdu_length(const mip_header header);
uint8_t get_sdu_type(const mip_header header);

#endif