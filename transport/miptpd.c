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
#include <sys/stat.h>
#include <time.h>

#include "miptpd.h"   // felles header for MIPTP

#define MAX_EVENTS 32
int debug_mode = 0;
int MIP_FD; // global referanse til mipd-socket

/**
 * Main-funksjon: oppretter sockets og kjører epoll-løkke
 */
int main(int argc, char *argv[]) {
    //flagghåndtering
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

    // Leser inn socket-stier fra argumentene
    const char *mipd_arg = argv[optind];
    const char *app_arg  = argv[optind + 1];

    char mipd_path[108];
    char app_path[108];

    // Hvis ikke absolutt sti, legg til /tmp/
    if (mipd_arg[0] != '/') {
        snprintf(mipd_path, sizeof(mipd_path), "/tmp/%s", mipd_arg);
    } else {
        strncpy(mipd_path, mipd_arg, sizeof(mipd_path) - 1);
        mipd_path[sizeof(mipd_path) - 1] = '\0';
    }

    if (app_arg[0] != '/') {
        snprintf(app_path, sizeof(app_path), "/tmp/%s", app_arg);
    } else {
        strncpy(app_path, app_arg, sizeof(app_path) - 1);
        app_path[sizeof(app_path) - 1] = '\0';
    }

    printf("[MIPTPD] Starting...\n");
    printf("[MIPTPD] MIPD socket: %s\n", mipd_path);
    printf("[MIPTPD] APP socket:  %s\n", app_path);

    wait_for_socket(mipd_path);
    usleep(200000);

    // Koble til MIP-daemon
    int mip_fd = connect_to_mipd(mipd_path);
    MIP_FD = mip_fd;
    if (mip_fd < 0) {
        perror("[MIPTPD] connect mipd failed");
        exit(EXIT_FAILURE);
    }
    uint8_t sdu_type = MIPTP_SDU_TYPE;
    ssize_t n = write(mip_fd, &sdu_type, sizeof(sdu_type));
    if (n != sizeof(sdu_type)) {
        perror("[MIPTPD] register sdu_type");
        close(mip_fd);
        exit(EXIT_FAILURE);
    }
    if (debug_mode) printf("[MIPTPD] Registered with MIPD (SDU type 0x%02X)\n", sdu_type);
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
                if (debug_mode)
                    printf("[MIPTPD] Received %zd bytes from mipd\n", len);

                // TODO: parse MIPTP header og lever til riktig app
                handle_incoming_miptp_packet(buf, len, buf[0]); 
            }

            // Ny applikasjonsforbindelse
            else if (fd == app_listen_fd && (events[i].events & EPOLLIN)) {
                int new_fd = accept(app_listen_fd, NULL, NULL);
                if (new_fd < 0) {
                    perror("accept");
                    continue;
                }

                printf("[MIPTPD] New app connected (fd=%d)\n", new_fd);

                // Les portnummeret (første byte appen sender)
                uint8_t port = 0;
                ssize_t n = read(new_fd, &port, 1);
                if (n <= 0) {
                    fprintf(stderr, "[MIPTPD] Failed to read port number from app (fd=%d)\n", new_fd);
                    close(new_fd);
                    continue;
                }

                // Registrer app i forbindelsestabellen
                if (new_app_connection(new_fd, port) == 0)
                    printf("[MIPTPD] Registered app on port %d (fd=%d)\n", port, new_fd);
                else {
                    fprintf(stderr, "[MIPTPD] Could not register new app (fd=%d)\n", new_fd);
                    close(new_fd);
                    continue;
                }

                // Legger den nye socketen inn i epoll
                ev.events = EPOLLIN;
                ev.data.fd = new_fd;
                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, new_fd, &ev) == -1)
                    perror("epoll_ctl: new_fd");
            }


            // Meldinger fra applikasjoner
            else if (events[i].events & EPOLLIN) {
                uint8_t buf[1500];
                ssize_t len = read(fd, buf, sizeof(buf));
                if (len <= 0) {
                    if (debug_mode)
                        printf("[MIPTPD] App fd=%d closed.\n", fd);
                    close(fd);
                    continue;
                }

                if (debug_mode)
                    printf("[MIPTPD] Received %zd bytes from app fd=%d\n", len, fd);

                // TODO: pakk inn i MIPTP-header og send via mip_fd
                printf("[MIPTPD] Message received from app fd=%d\n", fd);
                send_miptp_data(fd, buf, len);
            }
        }

        check_retransmissions();

        // TODO: kall check_retransmissions() her senere
    }

cleanup:
    close(epollfd);
    close(mip_fd);
    close(app_listen_fd);
    printf("[MIPTPD] Shutting down.\n");
    return 0;
}


