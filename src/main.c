#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "mipd.h"
#include "pdu.h"
#include "arp.h"
#include "routingd.h"

#define MAX_EVENTS 10 // epoll

int debug_mode = 0; // debug flagg
int last_unix_client_fd = -1; // siste unix klient
int last_ping_src = -1;
int my_mip_address = -1; // min mip addresse
char iface_name[IFNAMSIZ] = {0}; //navn på interface
pending_entry pending_queue[MAX_PENDING] = {0}; // kø av meldinger
//routing_entry routing_table[MAX_ROUTES];

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
    find_ifaces();
    arp_init_cache();
    create_raw_sockets();


 


    if (debug_mode) {
        printf("[DEBUG] Starting MIP daemon on UNIX socket '%s' with MIP address %d\n",
               socket_path, my_mip_address);
        printf("[DEBUG] Initial ARP cache:\n");
        print_arp_cache();
    }

    //lager sockets
    int unix_sock = create_unix_socket(socket_path); //lytte socket
    int raw_sock = create_raw_socket();

    // oppretter en epoll instans
    // epoll instans er en beholder som kan overvåle flere fildeskroptorer samtidig
    //sockets eller filer
    int epollfd = epoll_create1(0);

    if (epollfd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

     //ev brukes til å registrere en enkelt socket
    //events er et array av hendelser som epoll_wait() returnerer og forteller hvilke
    //sockets som har tilgjengelig data
    struct epoll_event ev, events[MAX_EVENTS];

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
    for (int i = 0; i < iface_count; i++) {
        ev.events = EPOLLIN;
        ev.data.fd = interfaces[i].raw_sock;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, interfaces[i].raw_sock, &ev) == -1) {
            perror("epoll_ctl: raw_sock");
            exit(EXIT_FAILURE);
        }
    }

    printf("Daemon running. Listening on UNIX + RAW sockets...\n");


    //overvåking av sockets i en evig løkke
    while (1) {
    int nfds = epoll_wait(epollfd, events, MAX_EVENTS, -1);

    if (nfds == -1) {
        perror("epoll_wait");
        exit(EXIT_FAILURE);
    }

    for (int n = 0; n < nfds; n++) {
        int fd = events[n].data.fd;

        // 1️⃣ Ny UNIX-klient som kobler til
        if (fd == unix_sock) {
            int client_fd = accept(unix_sock, NULL, NULL);
            if (client_fd == -1) {
                perror("accept");
                continue;
            }

            uint8_t sdu_type;
            if (read(client_fd, &sdu_type, 1) != 1) {
                perror("read sdu type");
                close(client_fd);
                continue;
            }

            for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
                if (!unix_clients[i].active) {
                    unix_clients[i].fd = client_fd;
                    unix_clients[i].sdu_type = sdu_type;
                    unix_clients[i].active = 1;
                    if (debug_mode)
                        printf("[UNIX] New client registered: fd=%d, sdu_type=0x%02X\n",
                               client_fd, sdu_type);
                    break;
                }
            }

            // Registrer klienten i epoll
            ev.events = EPOLLIN;
            ev.data.fd = client_fd;
            if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client_fd, &ev) == -1) {
                perror("epoll_ctl: client_fd");
                close(client_fd);
                continue;
            }
        }

        // 2️⃣ En hendelse fra *en av flere* RAW-sockets
        else {
            int handled = 0;
            for (int i = 0; i < iface_count; i++) {
                if (fd == interfaces[i].raw_sock) {
                    handle_raw_packet(fd, my_mip_address);
                    handled = 1;
                    break;
                }
            }

            // 3️⃣ Hvis det ikke var en råsocket, er det en UNIX-klient
            if (!handled) {
                handle_unix_request(fd, -1, my_mip_address);
            }
        }
    }
}
        // Ferdig – lukk alle sockets
    close(unix_sock);

    for (int i = 0; i < iface_count; i++) {
        if (interfaces[i].raw_sock > 0) {
            close(interfaces[i].raw_sock);
            if (debug_mode)
                printf("[DEBUG] Lukket raw socket for %s (fd=%d)\n",
                    interfaces[i].name, interfaces[i].raw_sock);
        }
    }

    return 0;
}


int create_raw_sockets(void) {
    for (int i = 0; i < iface_count; i++) {
        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_MIP));
        if (sock < 0) {
            perror("socket");
            exit(1);
        }

        // bind til interface
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, interfaces[i].name, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            perror("ioctl SIOCGIFINDEX");
            close(sock);
            continue;
        }

        struct sockaddr_ll sll = {0};
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_MIP);
        sll.sll_ifindex = ifr.ifr_ifindex;

        if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
            perror("bind raw_sock");
            close(sock);
            continue;
        }

        // legg til promisc mode for å fange alt på linken
        struct packet_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.mr_ifindex = ifr.ifr_ifindex;
        mreq.mr_type = PACKET_MR_PROMISC;
        setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

        interfaces[i].raw_sock = sock;
        interfaces[i].ifindex = ifr.ifr_ifindex;

        if (debug_mode)
            printf("[DEBUG] create_raw_socket: iface=%s idx=%d proto=0x%X\n",
                   interfaces[i].name, ifr.ifr_ifindex, ETH_P_MIP);
    }

    return iface_count;
}
