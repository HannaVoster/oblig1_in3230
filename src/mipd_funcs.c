#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "mipd.h"


//----------------------ARP CASHE--------------------------




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
    
    if (aligned_length > sdu_length) {
        memset(pdu + 4 + sdu_length, 0, aligned_length - sdu_length);
    }   

    return pdu;
}
//endret til å ha en generisk sende metode
int send_pdu(int rawsocket, uint8_t *pdu, size_t pdu_length, unsigned char *dest_mac){
    #ifdef __linux__
    if (rawsocket < 0){
        perror("socket");
        exit(1);
    }

    struct sockaddr_ll device;

    memset(&device, 0, sizeof(device)); //nullstiller
    device.sll_ifindex = if_nametoindex("eth0"); //interface
    device.sll_family = AF_PACKET; // ethernet
    device.sll_halen = ETH_ALEN; //6 lengde på mac adresse
    memcpy(device.sll_addr, dest_mac, 6);

    int send = sendto(rawsocket, pdu, pdu_length, 0, (struct sockaddr*)&device, sizeof(device));
    if(send < 0){
        perror("send_pdu");
    }

    return send;

    #elif __APPLE__
    printf("[SEND_PDU] SEND ON MAC");
    return 1;
    #endif
}

//Broadcast
int send_broadcast(int dst, int rawsocket){
    #ifdef __linux__
    //raw socket broadcast kode
    req mip_arp_msg;
    mip_arp_msg.type = SDU_TYPE_ARP_REQ;
    mip_arp_msg.mip_addr = dst;

    //setter mac feltet i req til  være tom
    memset(mip_arp_msg.mac, 0,6);

    // type cast: (uint8_t*)&req
    uint8_t* pdu = build_pdu(
        dst,
        my_mip_address,
        2, 
        sizeof(mip_arp_msg), 
        SDU_TYPE_ARP_REQ,  
        (uint8_t*)&mip_arp_msg);

    unsigned char broadcast_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; // broadcast mac adresse

    send_pdu(rawsocket, pdu, 4 + sizeof(mip_arp_msg), broadcast_mac)
  
    free(pdu);

    #elif __APPLE__
    printf("[ARP] Simulert broadcast for MIP");
    
    #endif

    return 0;
}

int wait_for_broadcast_response(){}

//Sende pakke

int send_packet(int clientfd, unsigned char *mac_address, int dst){
     //---- RAW SOCKET--
        // Linux RAW Ethernet socket
        //AF PACKET -adress family, til å motta ethernet rammer, under ip nivået
        //SOCK RAW - type socket, raw socket gir pakker slik de faktisk er
        // htons - gir "network byte order" ETH_P_ALL gir alle rammetyper
        #ifdef __linux__
        int rawsocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (rawsocket < 0){
            perror("socket");
            exit(1);
        }

        struct sockaddr_ll device;

        //nullstiller
        memset(&device, 0, sizeof(device));
        device.sll_ifindex = if_nametoindex("eth0"); //interface
        device.sll_family = AF_PACKET; // ethernet
        device.sll_halen = ETH_ALEN; //6 lengde på mac adresse

        //kopierer mac adressen til destinasjonen - hentet fra tidligere
        memcpy(device.sll_addr, mac_address, 6);

        //send datagram //DUMMY DATA ENDRE TIL ANNERLEDES LENGDE SENERE
        uint8_t payload[8] = {0,1,2,3,4,5,6,7};

        uint16_t sdu_length = sizeof(payload);

        uint8_t* pdu = build_pdu(dst, my_mip_address, 4, sdu_length, 9, payload);

        uint16_t pdu_length = 4 + sdu_length;

        //send
        sendto(rawsocket, pdu, pdu_length, 0, (struct sockaddr*)&device, sizeof(device));

        free(pdu);

        #elif __APPLE__
        printf("[TX-simulert] Ville sendt PDU til MIP %d\n", dst);

        #endif  

		printf("[TX] Ville sendt MIP-PDU til MIP %d (MAC %02X:%02X:%02X:%02X:%02X:%02X)\n",
			dst, mac_address[0], mac_address[1], mac_address[2], mac_address[3], mac_address[4], mac_address[5]);

		// Send et enkelt svar tilbake til klienten for å vise at flyten fungerer
		const char *reply = "PONG (simulert)\n";
		write(clientfd, reply, strlen(reply));
	}
