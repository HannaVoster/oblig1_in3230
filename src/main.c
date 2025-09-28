#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "mipd.h"
#include "pdu.h"
#include "arp.h"

#define MAX_EVENTS 10 // epoll

int debug_mode = 0; // debug flagg
int last_unix_client_fd = -1; // siste unix klient
int my_mip_address = -1; // min mip addresse
char iface_name[IFNAMSIZ] = {0}; //navn på interface
pending_entry pending_queue[MAX_PENDING] = {0}; // kø av meldinger

/*
Denne funksjonen starter MIP-daemonen. 
Den håndterer flaggene -h og -d, henter inn socket-sti og MIP-adresse fra argumentene,
 finner nettverksinterface og oppretter både UNIX- og råsocket. 
 Disse legges i en epoll-instans, og programmet går deretter i en løkke som behandler 
 enten klientforespørsler eller mottatte MIP-pakker

 main setter globale variabler som debug_mode, my_mip_address og iface_name,
 Disse variablene brukes senere av andre funksjoner
 */

int main(int argc, char *argv[]) {
    // Håndterer -h og -d
    // getopt() returnerer flagg-bokstaven som en char eller -1 når det ikke er flere flagg
    int opt;
    while ((opt = getopt(argc, argv, "hd")) != -1) {
        switch(opt) {
            case 'h':
                printf("Usage: %s [-d] <socket_upper> <MIP address>\n", argv[0]);
                printf("Options:\n");
                printf("  -h print help and exit\n");
                printf("  -d enable debug mode\n");
                return 0;
            case 'd':
                debug_mode = 1;
                break;
            default:
                //stderr skriver til standard error
                fprintf(stderr, "Unknown option\n");
                return 1;
        }
    }
    //sjekker at argumentene gis riktig, avslutter hvis det ikke finnes mindt 2
    if (optind + 2 > argc) {
        fprintf(stderr, "Usage: %s [-d] <socket_upper> <MIP address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    //henter ut filsti og adresse fra argumentene
    char *socket_path = argv[optind];
    my_mip_address = atoi(argv[optind+1]);

    //finner interface, metode i mipd
    find_iface();

    if (debug_mode) {
        printf("[DEBUG] Starting MIP daemon on UNIX socket '%s' with MIP address %d\n",
               socket_path, my_mip_address);
        printf("[DEBUG] Initial ARP cache:\n");
        print_arp_cache();
    }

    //lager sockets
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
                handle_raw_packet(raw_sock, my_mip_address);
            }
        }
    }
    //ferdig - lukker socketene
    close(unix_sock);
    close(raw_sock);
    return 0;
}