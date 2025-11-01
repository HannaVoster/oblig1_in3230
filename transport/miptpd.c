/*
Hovedprogram til miptpd

main funksjon og event loop

**Ansvar:**

- Initialisere UNIX- og MIP-sockets (kalle `init_unix_socket()` og `init_mip_socket()`)
- Holde `select()`eller `poll()`løkken, EPOLL???
- Kalle de riktige handlerne (f.eks. `handle_app_message()`, `handle_incoming_miptp_packet()`)
- Holde oversikt over forbindelser (`connections[]`, porter osv.)
- Starte periodiske retransmisjonssjekker

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include "miptpd.h"   // felles header for MIPTP

#define MAX_EVENTS 32
int debug_mode = 0;

/**
 * Main-funksjon: oppretter sockets og kjører epoll-løkke
 */
int main(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "hd")) != -1) {
        switch (opt) {
            case 'h':
                printf("Usage: %s [-d] <mipd_socket> <app_socket>\n", argv[0]);
                printf("  -d  enable debug output\n");
                return 0;
            case 'd':
                debug_mode = 1;
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                return 1;
        }
    }

    if (optind + 1 >= argc) {
        fprintf(stderr, "Usage: %s [-d] <mipd_socket> <app_socket>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *mipd_path = argv[optind];
    const char *app_path = argv[optind + 1];

    printf("[MIPTPD] Starting...\n");
    printf("[MIPTPD] MIPD socket: %s\n", mipd_path);
    printf("[MIPTPD] APP socket:  %s\n", app_path);

    wait_for_socket(mipd_path);
    usleep(200000);

    // Koble til MIP-daemon
    int mip_fd = connect_to_mipd(mipd_path);
    if (mip_fd < 0) {
        fprintf(stderr, "[MIPTPD] Failed to connect to mipd.\n");
        exit(EXIT_FAILURE);
    }

    // Opprett socket for applikasjoner
    int app_listen_fd = create_app_socket(app_path);

    // Opprett epoll-instans
    int epollfd = epoll_create1(0);
    if (epollfd < 0) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = mip_fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, mip_fd, &ev) == -1) {
        perror("epoll_ctl: mip_fd");
        exit(EXIT_FAILURE);
    }

    ev.events = EPOLLIN;
    ev.data.fd = app_listen_fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, app_listen_fd, &ev) == -1) {
        perror("epoll_ctl: app_listen_fd");
        exit(EXIT_FAILURE);
    }

    printf("[MIPTPD] Ready — entering event loop.\n");

    while (1) {
        int n = epoll_wait(epollfd, events, MAX_EVENTS, 500);
        if (n < 0) {
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            // Hendelse fra MIP-daemonen
            if (fd == mip_fd && (events[i].events & EPOLLIN)) {
                uint8_t buf[1500];
                ssize_t len = read(mip_fd, buf, sizeof(buf));
                if (len <= 0) {
                    printf("[MIPTPD] Disconnected from mipd.\n");
                    goto cleanup;
                }
                if (DEBUG)
                    printf("[MIPTPD] Received %zd bytes from mipd\n", len);

                // TODO: parse MIPTP header og lever til riktig app
                handle_incoming_miptp_packet(buf, len, buf[0]); // foreløpig placeholder
            }

            // Ny applikasjonsforbindelse
            else if (fd == app_listen_fd && (events[i].events & EPOLLIN)) {
                int new_fd = accept(app_listen_fd, NULL, NULL);
                if (new_fd < 0) {
                    perror("accept");
                    continue;
                }
                if (DEBUG)
                    printf("[MIPTPD] New app connected (fd=%d)\n", new_fd);

                // legg den nye socketen inn i epoll
                ev.events = EPOLLIN;
                ev.data.fd = new_fd;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, new_fd, &ev) == -1)
                    perror("epoll_ctl: new_fd");

                // TODO: les første byte (portnummer) fra app
            }

            // Meldinger fra applikasjoner
            else if (events[i].events & EPOLLIN) {
                uint8_t buf[1500];
                ssize_t len = read(fd, buf, sizeof(buf));
                if (len <= 0) {
                    if (DEBUG)
                        printf("[MIPTPD] App fd=%d closed.\n", fd);
                    close(fd);
                    continue;
                }

                if (debug_mode)
                    printf("[MIPTPD] Received %zd bytes from app fd=%d\n", len, fd);

                // TODO: pakk inn i MIPTP-header og send via mip_fd
                send_miptp_data(fd, buf, len);
            }
        }

        // TODO: kall check_retransmissions() her senere
    }

cleanup:
    close(epollfd);
    close(mip_fd);
    close(app_listen_fd);
    printf("[MIPTPD] Shutting down.\n");
    return 0;
}
