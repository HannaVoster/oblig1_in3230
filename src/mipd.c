// daemonen som kjører i bakgrunnen og håndterer trafikk på vegne av applikasjonene

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>



#ifdef __linux__
#include <netinet/if_ether.h>
#include <net/if.h>
#include <linux/if_packet.h>
#endif

#include "mipd.h"

#define MAX_EVENTS 10
#define UNIX_PATH "/tmp/mip_socket"


int create_unix_socket(const char *path) {
    int sock;
    struct sockaddr_un addr;

    //lager en unix socket, stopper programmet hvis en feil skjer
    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("unix socket");
        exit(EXIT_FAILURE);
    }

    //nullstiller struct for adressen til socketen
    memset(&addr, 0, sizeof(addr));
    //socket type: UNIX
    addr.sun_family = AF_UNIX;

    //kopierer UNIX_PATH som adressen
    strncpy(addr.sun_path, path, sizeof(addr.sun_path)-1);

    //sletter eventuel gammel fil med samme navn fra tidligere kjøring
    unlink(path); 

    //kobler socketen til adddressen i addr, slik at klientet kan koble seg på den gjemnnom filbanen
    //typecaster (struct sockaddr*)&addr så bind() skjønner at det sendes en generisk socket addresse
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind unix");
        exit(EXIT_FAILURE);
    }

    //setter socketen i lyttemodus, klar til å ta imot klienter (maks 5 i kø)
    if (listen(sock, 5) == -1) {
        perror("listen unix");
        exit(EXIT_FAILURE);
    }

    return sock;
}

int create_raw_socket() {
    //lager en raw socket

    //AF_PACKET forteller at adressen tilhører ethernet rammer, på et lavt nivå
    //SOCK_RAW socket type, tar imot hele ethernet rammer med både header og payload
    //htons(ETH_P_ALL) tar imot alle typer ethernet
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("raw socket");
        exit(EXIT_FAILURE);
    }
    return sock;
}

//håndterer en forbindelse på UNIX socket
void handle_unix_request(int unix_sock, int raw_sock, int my_mip_address) {

    //client - fildeskriptor som representerer forbindelsen
    int client = accept(unix_sock, NULL, NULL);
    if (client < 0) {
        perror("accept");
        return;
    }

    //buffer til å holde det som skal leses fra klinetforbindelsen
    char buffer[256];

    //leser fra klienten, legger inn i buffer
    int n = read(client, buffer, sizeof(buffer)-1);

    //passer på at det er plass til en nullterminering
    //bygger pdu som sendes gjennom raw_socket
    if (n > 0) {
        buffer[n] = '\0';
        printf("[UNIX] Received from client: %s\n", buffer);
        
        //hent ut dest mip adresse og payload
        uint8_t dest_addr = buffer[0];
        uint8_t* payload = (uint8_t*)&buffer[1];
        uint16_t payload_length = n - 1; // første byte er addresse

        size_t pdu_len;
            uint8_t* pdu = build_pdu(
                dest_addr,
                my_mip_address,
                4,
                payload_length,
                SDU_TYPE_PING,
                payload,
                &pdu_len
            );

        //sjekk ARP cashe med arp_lookup
        unsigned char mac[6];
        if (arp_lookup(dest_addr, mac)){
            //hvis HIT -> PDU til MAC via raw socket
            //fant mac - send pdu
            send_pdu(raw_sock, pdu, pdu_len, mac);
            free(pdu);
        }
        else{
            //hvis MISS -> send ARP request, broadcast for å finne MAC
            queue_message(dest_addr, pdu, pdu_len);
            free(pdu);

            printf("[ARP] MIP %d ikke funnet, må sende ARP request\n", dest_addr);
            send_broadcast(dest_addr, raw_sock);

        }

    }
    //ferdig med forbindelsen så lukker den for å frigjøre ressurser
    close(client);
}

//håndterer en forbindelse på RAW socket
void handle_raw_packet(int raw_sock) {
    //lager buffer til å holde det som leses
    // uint8_t pga rå bytes og ikke tekst
    uint8_t buffer[2000];

    //henter ethernet ramme, legger over i buffer, med max antall bytes og eventuelle flagg(her 0)
    int len = recv(raw_sock, buffer, sizeof(buffer), 0);

    //len representerer lengden, antall bytes som mottas. hvis < 0 -> feil skjedd og returner
    if (len < 0) {
        perror("recv raw");
        return;
    }
    printf("[rawsocket] Got packet of length %d\n", len);

    //headeren er 4 bytes, så pakken må være minst det for å kunne tolkes
    if (len < 4){
        printf("raw socket, pakken er for kort");
        return;
    }

    //parser mip header med hjelpemetoder
    mip_header header;
    mepcpy(&header, buffer, 4);
    uint8_t src_addr = get_src_addr(header);
    uint8_t dest_addr = get_dest_addr(header);
    uint8_t ttl = get_ttl(header);
    uint8_t sdu_type = get_sdu_type(header);
    uint16_t sdu_length = get_sdu_lengt(header);

    if (dest_addr != my_mip_address){
        printf("[rawsocket], ikke pakken min");
        return;
    }

    //henter payload
    uint8_t* payload = buffer + 4;

    //lager en switch som håndterer de ulike casene av sdu typer
    switch(sdu_type){

        case SDU_TYPE_PING: {
            //hvis PING - PONG tilbake til avsender
            printf("[RAW] PING mottatt fra MIP %d\n", src_addr);

            // bygg pfu klar for PONG
            size_t pdu_len;
            uint8_t *pdu = build_pdu(src_addr, my_mip_address, 4, sdu_length, SDU_TYPE_PONG, payload, &pdu_len);

            //må ha mac for å kunne sende, sjekker ARP
            unsigned char mac[6]; // plass til mac adressen
            if (arp_lookup(src_addr, mac)) {
                send_pdu(raw_sock, pdu, pdu_len, mac);
                free(pdu);
            }
            else{
                printf("[RAW] MAC for %d ikke i cache, sender ARP request\n", src_addr);

                queue_message(src_addr, pdu, pdu_len);
                free(pdu);
                //mac ikke funnet, sender broadcast for å kunne oppdatere arp tabellen/finne mac
                send_broadcast(dest_addr, raw_sock);
            }
            
            break;


        }
        case SDU_TYPE_PONG: {
            // logg eller send videre til UNIX klient
            printf("[RAW] PONG mottatt fra MIP %d: %.*s\n", src_addr, sdu_length, payload);
            //HVA NÅ? sende melding til unix klient???
            break;

        }
        case SDU_TYPE_ARP_REQ: {
            // bygg og send ARP respons
            //caster payloaded til å passe til mip_arp_msg
            mip_arp_msg *req = (mip_arp_msg*)payload;

            //sjekker om forespørselen er for denne maskinen før vi går videre
            if(req-> mip_addr == my_mip_address){
                printf("[RAW] ARP request for me (%d) mottatt\n", my_mip_address);

                mip_arp_msg resp;
                resp.mip_addr = my_mip_address;
                resp.type = SDU_TYPE_ARP_RESP;
                memset(req.mac, 0, 6); //jeg spør, de trenger ikke vite min (per nå)

                size_t pdu_len;
                uint8_t *pdu = build_pdu(src_addr, my_mip_address, 4, sizeof(resp), SDU_TYPE_ARP_RESP, (uint8_t*)&resp, &pdu_len );

                unsigned char mac[6];
                if(arp_lookup(src_addr, mac)){
                    send_pdu(raw_sock, pdu, pdu_len, mac);
                }
                else{
                    unsigned char broadcast_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
                    send_pdu(raw_sock, pdu, pdu_len, broadcast_mac);
                }
            }
            free(pdu);
            break;

        }
        case SDU_TYPE_ARP_RESP: {
            // oppdater ARP- cashe
            mip_arp_msg *resp = (mip_arp_msg*)payload;

            printf("[RAW] ARP response for MIP %d mottatt\n", resp->mip_addr);

            arp_update(resp->mip_addr, resp->mac);

            //meldinger som eventuelt venter i kø til denne mac adressen kan nå sendes
            send_pending_messages(raw_sock, resp->mip_addr, resp->mac);

            break;

        }
        default: {
            printf("ukjent SDU type");
            break;
        }
    }
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <socket_upper> <MIP_address>\n", argv[0]);
        return 1;
    }

    char *socket_path = argv[1];
    int my_mip_address;
    my_mip_address = atoi(argv[2]);

    int unix_sock = create_unix_socket(socket_path);
    int raw_sock = create_raw_socket();
    
    //ev brukes til å registrere en enkelt socket
    //events er et array av hendelser som epoll_wait() returnerer og forteller hvilke
    //sockets som har tilgjengelig data
    struct epoll_event ev, events[MAX_EVENTS];

    // oppretter en epoll instans
    // epoll instans er en beholder som kan overvåle flere fildeskroptorer samtidig
    //sockets eller filer
    int epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    // Registrer UNIX-socket
    ev.events = EPOLLIN; // ønsker å overvåke innkommende data
    ev.data.fd = unix_sock; //fil deskriptor til epoll for å vite hvilken socket det er snakk om

    //legger til instansen i epollfd (instansen fra tidligere)
    // EPOLL_CTL_ADD forteller instansen at socketen skal overvåkes
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, unix_sock, &ev) == -1) {
        perror("epoll_ctl: unix_sock");
        exit(EXIT_FAILURE);
    }

    // Registrer RAW-socket
    ev.events = EPOLLIN; // ønsker å overvåke innkommende data
    ev.data.fd = raw_sock; //fil deskriptor til epoll for å vite hvilken socket det er snakk om
    
    //samme som med unix socket
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, raw_sock, &ev) == -1) {
        perror("epoll_ctl: raw_sock");
        exit(EXIT_FAILURE);
    }

    printf("Daemon running. Listening on UNIX + RAW sockets...\n");

    //overvåking av sockets i en evig løkke
    while (1) {
        // epoll.wait() venter på at en av de registrerte socketene får innkommende data
        //nfds holder verdien i int for hvor mange sockets som har hendelser
        int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);
    
        if (nfds == -1) {
            perror("epoll_wait");
            exit(EXIT_FAILURE);
        }

        //går igjennom eventuelle events i events array og sjekker om det er en unix/raw socket
        //kaller de respektive metodene for å håndtere informasjonen som mottas i forbindelsene
        for (int n = 0; n < nfds; n++) {
            if (events[n].data.fd == unix_sock) {
                handle_unix_request(unix_sock, raw_sock, my_mip_address);
            } else if (events[n].data.fd == raw_sock) {
                handle_raw_packet(raw_sock);
            }
        }
    }

    //ferdig - lukker socketene
    close(unix_sock);
    close(raw_sock);
    return 0;
}


