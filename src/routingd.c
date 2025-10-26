
//ROUTING DEAMON
/*
skal koble seg til mipd gjennom UNIX socket,
registrere seg som en klient
ha sdu type 0x04
gi en route respons
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "routingd.h"
#include "arp.h"
#include "routing_socket.h"

neighbor neighbors[MAX_NEIGHBORS];
rt_entry routing_table[MAX_ROUTES];   
uint8_t MY_MIP = 0;
int ROUTING_SOCK = -1;

int debug_mode = 0;
int main(int argc, char *argv[]) {
    // Håndterer -h og -d flagg
    int opt;
    while ((opt = getopt(argc, argv, "hd")) != -1) {
        switch(opt) {
            case 'h':
                printf("Usage: %s [-d] <unix_socket_path>\n", argv[0]);
                printf("Options:\n");
                printf("  -h  print help and exit\n");
                printf("  -d  enable debug mode\n");
                return 0;
            case 'd':
                debug_mode = 1;
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "Usage: %s [-d] <unix_socket_path>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *socket_path = argv[optind];
    printf("[ROUTINGD] Starting with socket path: %s\n", socket_path);
    // Vent på at mipd oppretter UNIX-socketen
    wait_for_socket(socket_path);
    printf("[ROUTINGD] Socket %s er nå tilgjengelig, kobler til...\n", socket_path);

    ROUTING_SOCK = connect_to_mipd(socket_path);
    if (ROUTING_SOCK < 0) {
        fprintf(stderr, "[ROUTINGD] Klarte ikke å koble til %s\n", socket_path);
        exit(EXIT_FAILURE);
    }

    printf("[ROUTINGD] epoll looop - Listening...\n");

    int epollfd = epoll_create1(0);

    if (epollfd < 0) {
        perror("epoll_create1");
        close(ROUTING_SOCK);
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = ROUTING_SOCK;

    //legger til instansen i epollfd (instansen fra tidligere)
    // EPOLL_CTL_ADD forteller instansen at socketen skal overvåkes
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ROUTING_SOCK, &ev) == -1) {
        perror("epoll_ctl: routing_sock");
        exit(EXIT_FAILURE);
    }
    memset(neighbors, 0, sizeof(neighbors));
    memset(routing_table, 0, sizeof(routing_table));

    for (int i = 0; i < MAX_ROUTES; i++) {
        routing_table[i].valid = 0;
        routing_table[i].cost = 255;   // INF_COST
    }
    update_or_insert_neighbor(MY_MIP, MY_MIP, 0); // rute til seg selv

    // Tidsstyrte meldinger
    uint64_t last_hello = now_ms();
    uint64_t last_update = now_ms();
    uint64_t last_print= now_ms();

    // Hovedløkke for å håndtere meldinger fra mipd
    while (1) { 
        int n = epoll_wait(epollfd, events, MAX_EVENTS, 200); // 200 ms timeout

        if (n < 0) {
            perror("epoll_wait");
            break;
        }
        // Behandle hendelser fra epoll 
        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == ROUTING_SOCK && (events[i].events & EPOLLIN)) {
                uint8_t buf[256];
                ssize_t len = read(ROUTING_SOCK, buf, sizeof(buf));
                printf("[ROUTINGD] Read %zd bytes: ", len);
                for (int i = 0; i < len; i++) printf("%02X ", buf[i]);
                printf("\n");
                if (len <= 0) {
                    printf("[ROUTINGD] Disconnected from MIPd\n");
                    goto cleanup;
                }
                uint8_t src = buf[0];
                uint8_t msg_type = buf[1]; // for HELLO/UPDATE - ellers ttl, men brukes ikke videre

                if (len >= 6 && buf[2] == 'R' && buf[3] == 'E' && buf[4] == 'Q') {
                    handle_route_request(ROUTING_SOCK, buf, len);
                } else if (len >= 3) {
                    handle_incoming_message(src, msg_type, &buf[2], len - 2);
                }
            }
        }

        uint64_t now = now_ms();

        if (now - last_hello >= HELLO_INTERVAL_MS) {
            hello(); // broadcast HELLO
            last_hello = now;
        }

        if (now - last_update >= UPDATE_INTERVAL_MS) {
            broadcast_update(); // send UPDATE (Poisoned Reverse)
            last_update = now;
        }

        if (now_ms() - last_print > 10000) {
            print_routing_table();
            last_print = now_ms();
        }
    }
    cleanup:
        close(epollfd);
        close(ROUTING_SOCK);
        printf("[ROUTINGD] Shutting down.\n");
        return 0;
}

uint64_t now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec/1000000;
}



