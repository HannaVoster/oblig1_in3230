#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "mipd.h"


//----------------------ARP CASHE--------------------------
#define MAX_ARP 256

// MIP ARP CASHE
typedef struct {
	int mip_addr;
	unsigned char mac[6];
	int valid;
} arp_entry;

arp_entry arp_cash[MAX_ARP];


//method for updating arp cashe
void arp_update(int mip_addr, unsigned char *mac){
	for(int i = 0; i < MAX_ARP; i++){
		if(!arp_cash[i].valid){
			arp_cash[i].valid = 1;
			arp_cash[i].mip_addr = mip_addr;

			if (mac){
				memcpy(arp_cash[i].mac, mac, 6);
			}

			else {
                unsigned char dummy[6] = {0x02,0x00,0x00,0x00,0x00,0x01};
                memcpy(arp_cash[i].mac, dummy, 6);
            }

			printf("[ARP] UPDATE: la inn MIP %d med MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
                   mip_addr,
                   arp_cash[i].mac[0], arp_cash[i].mac[1], arp_cash[i].mac[2],
                   arp_cash[i].mac[3], arp_cash[i].mac[4], arp_cash[i].mac[5]);
            return;
		}
	}

	printf("[ARP] CACHE FULL: kunne ikke lagre MIP %d\n", mip_addr);
};


// Sjekk om MIP finnes i cache. Fyll mac_out hvis ikke NULL.
int arp_lookup(int mip_addr, unsigned char *mac_out) {
    for (int i = 0; i < MAX_ARP; i++) {
        if (arp_cash[i].valid && arp_cash[i].mip_addr == mip_addr) {

            if (mac_out) {
				memcpy(mac_out, arp_cash[i].mac, 6);
			}

            printf("[ARP] HIT: MIP %d finnes i cache\n", mip_addr);
            return 1;
        }
    }
    printf("[ARP] MISS: MIP %d ikke i cache → (ville sendt broadcast nå)\n", mip_addr);
    return 0;
}

//----------------------HEADER--------------------------
//GET/SET

typedef uint8_t mip_header[4]; //fast størrelse på 4 bytes, bruker set/get metoder under

//SET

void set_dest_addr(mip_header header, uint8_t dest_addr){
    header[0] = dest_addr;
}
void set_src_addr(mip_header header, uint8_t scr_addr){
    header[1] = scr_addr;
}
void set_ttl(mip_header header, uint8_t ttl){
    header[2] = (header[2] & 0x0F) | (ttl & 0x0F) << 4;
    //Beholde de nederste 4 bitene.
    //Nullstille de øverste 4 bitene
    //Legge inn TTL der
}
void set_sdu_length(mip_header header, uint16_t sdu_length){
    header[2] = (header[2] & 0xF0) | ((sdu_length >> 8) & 0x0F); // øverste bits
    header[3] = sdu_length & 0xFF; // nederste bits
}
void set_sdu_type(mip_header header, uint8_t sdu_type){
    header[3] = (header[3] & 0xF0) | (sdu_type & 0x0F);
}

//GET

uint8_t get_dest_addr(const mip_header header) {
	return header[0]; // header i byte 0(1)
}

uint8_t get_src_addr(const mip_header header) {
	return header[1];
}

uint8_t get_ttl(const mip_header header) {
	return (header[2] >> 4) & 0x0F;

	//flytter de fire første bitene til de fire laveste
	//nullstiller så de fire første så bare ttl returneres 
}

//lenger siden sdu length er 9 bits
uint16_t get_sdu_length(const mip_header header) {
	return (header[2] & 0x0F) << 8 | header[3];
    // ta de fire nederste bit fra header[2]
    //flytt dem til høye bitposisjon
    //legg til hele innholdet i header[3]
}

uint8_t get_sdu_type(const mip_header header) {
    return (header[3] & 0x0F);
	//de fire øverste bitene nullstilt, og de fire nederste beholdes.
}


//------------------PDU------------------


// pdu = header + payload

uint8_t* build_pdu(uint8_t dest_addr, uint8_t scr_addr, uint8_t ttl, uint16_t sdu_length, uint8_t sdu_type, const uint8_t* payload){
    //build buffer with both header and payload

    //kontroller lengde på payload for å gjøre pdu delelig med 4?

    uint16_t aligned_length = sdu_length;
    if (sdu_length % 4 != 0) {
        aligned_length += 4 - (sdu_length % 4);
    }

    uint8_t* pdu = malloc(4 + aligned_length); // 4 bytes header + SDU

    //header
    mip_header header;
    set_dest_addr(header, dest_addr);
    set_sdu_length(header, sdu_length);
    set_sdu_type(header, sdu_type);
    set_ttl(header, ttl);
    set_src_addr(header, scr_addr);

    //kopierer header over i pdu
    //pdu peker til buffer, header legges inn, 4 er antall bytes som kopieres
    memcpy(pdu, header, 4);

    memcpy(pdu + 4, payload, sdu_length);

    if (aligned_length > sdu_length){
        memset(pdu + 4 + sdu_length, 0, aligned_length  - sdu_length);
    }

    return pdu;

}