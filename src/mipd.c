#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


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

typedef uint8_t mip_header[4]; //fast størrelse på 4 bytes, bruker set/get metoder under

void set_dest_addr(mip_header header, uint8_t dest_addr){}
void set_src_addr(mip_header header, uint8_t scr_addr){}
void set_ttl(mip_header header, uint8_t ttl){}
void set_sdu_length(mip_header header, uint16_t sdu_length){}
void set_sdu_type(mip_header header, uint8_t sdu_type){}

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
	return (header[2] );
}

uint8_t get_sdu_type(const mip_header header) {
	//
}
// typedef struct {
// 	unsigned char dest_addrs; // Destination address 	The MIP address of the destination node
// 	unsigned char src_addrs; // Source address  	The MIP address of the source node
// 	unsigned char ttl : 4 ; // TTL Time To Live		maximum hop count
// 	unsigned short sdu_length : 9; //SDU length      Length of the SDU (i.e. payload) encapsulated within this MIP datagram.
// 	unsigned char sdu_type : 3; //SDU type	The type of the SDU (i.e. upper layer protocol type)
// } mip_header;


// simulering av oppdatering for testing

//----------------------MAIN--------------------------

int main(int argc, char *argv[]) {

    if (argc != 3) {
        printf("Usage: %s <socket_path> <MIP_address>\n", argv[0]);
        return 1;
    }

    char *socket_path = argv[1];
    int mip_address = atoi(argv[2]);

    printf("Starting MIP-daemon...\n");
    printf("Socket path: %s\n", socket_path);
    printf("MIP address: %d\n", mip_address);

    int sockfd;
    struct sockaddr_un address;

    // 1. Lag UNIX socket
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    // 2. Sett opp adresse
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, socket_path, sizeof(address.sun_path)-1);

    // 3. Fjern evt gammel socket-fil
    unlink(socket_path);

    // 4. Bind socket
    if (bind(sockfd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind");
        exit(1);
    }

    // 5. Listen
    if (listen(sockfd, 5) < 0) {
        perror("listen");
        exit(1);
    }

    printf("Daemon venter på klient...\n");

    // 6. Accept
    int clientfd = accept(sockfd, NULL, NULL);
    if (clientfd < 0) {
        perror("accept");
        exit(1);
    }

    printf("Klient koblet til!\n");

    // 7. Les data fra klient
    char buffer[256];
    int n = read(clientfd, buffer, sizeof(buffer)-1);
    if (n < 0) {
        perror("read");
        exit(1);
    }

    buffer[n] = '\0';
    printf("Mottatt melding: %s\n", buffer);

	// Sjekk om meldingen fra klient starter med "PING:" (de første 5 tegnene)
	if (strncmp(buffer, "PING:", 5) == 0) {

		// Hent destinasjons-MIP-adressen som følger etter "PING:" i meldingen
		int dst = atoi(buffer + 5); // Konverter fra streng til heltall

		// Opprett en lokal variabel for å lagre MAC-adressen til destinasjonen
		unsigned char mac[6];

		// Sjekk om MIP-adressen allerede finnes i ARP-cachen
		if (!arp_lookup(dst, mac)) {
			// Hvis ikke funnet (MISS), simuler at vi mottar et ARP-svar
			// Her sender vi NULL, som gjør at arp_update bruker en dummy MAC-adresse
			arp_update(dst, NULL);

			// Hent MAC-adressen på nytt fra cache etter oppdatering (for logging)
			arp_lookup(dst, mac);
		}

		// Skriv ut hva daemonen ville ha sendt på MIP-laget
		// Printer både MIP-adresse og MAC-adresse i hex-format@

		//int rawfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		//sendto(rawfd, packet_data, packet_len, 0, (struct sockaddr*)&eth_addr, sizeof(eth_addr));


		printf("[TX] Ville sendt MIP-PDU til MIP %d (MAC %02X:%02X:%02X:%02X:%02X:%02X)\n",
			dst, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

		// Send et enkelt svar tilbake til klienten for å vise at flyten fungerer
		const char *reply = "PONG (simulert)\n";
		write(clientfd, reply, strlen(reply));
	}

    // 8. Svar tilbake (debug)
    const char *reply = "Hei fra MIP-daemon!\n";
    write(clientfd, reply, strlen(reply));

    // 9. Lukk alt
    close(clientfd);
    close(sockfd);
    unlink(socket_path);

    return 0;
}

