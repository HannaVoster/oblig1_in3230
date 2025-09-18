#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>


#ifdef __linux__
#include <netinet/if_ether.h>
#include <net/if.h>
#include <linux/if_packet.h>
#endif


#include "mipd.h" // header fil som igjen pekes på av mipd_funcs.c for å unngå dobbel main

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
        memcpy(device.sll_addr, mac, 6);

        //send datagram //DUMMY DATA ENDRE TIL ANNERLEDES LENGDE SENERE
        uint8_t payload[8] = {0,1,2,3,4,5,6,7};

        uint16_t sdu_length = sizeof(payload);

        uint8_t* pdu = build_pdu(42, 17, 4, sdu_length, 9, payload);

        uint16_t pdu_length = 4 + sdu_length;

        //send
        sendto(rawsocket, pdu, pdu_length, 0, (struct sockaddr*)&device, sizeof(device));

        free(pdu);


        #elif __APPLE__
        printf("[TX-simulert] Ville sendt PDU til MIP %d\n", dst);

        #endif  

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

