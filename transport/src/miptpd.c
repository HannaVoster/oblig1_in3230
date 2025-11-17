/*
 * Hovedprogram til miptpd
 * 
 * main funksjon og event loop
 * 
 * **Ansvar:**
 * - Initialisere UNIX- og MIP-sockets
 * - Holde epoll-løkke
 * - Kalle riktige hendelseshåndterere
 * - Holde oversikt over forbindelser og porter
 * - Starte periodiske retransmisjonssjekker
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

#include "miptpd.h"
#include "miptpd_utils.h"
#include "miptpd_send.h"
#include "miptpd_incoming.h"
#include "miptpd_retransmit.h"


#define MAX_EVENTS 32
int debug_mode = 0;
int MIP_FD; // global referanse til mipd-socket

// ......Main .....
int main(int argc, char *argv[]) {
    handle_flags(argc, argv);

    const char *mipd_arg = argv[optind];
    const char *app_arg  = argv[optind + 1];

    char mipd_path[108];
    char app_path[108];
    parse_socket_paths((char *)mipd_arg, (char *)app_arg, mipd_path, app_path);

    printf("[MIPTPD] Starting...\n");
    printf("[MIPTPD] MIPD socket: %s\n", mipd_path);
    printf("[MIPTPD] APP socket:  %s\n", app_path);

    wait_for_socket(mipd_path);
    usleep(200000);

    int mip_fd = setup_mip_connection(mipd_path);
    int app_listen_fd = create_app_socket(app_path);
    int epollfd = setup_epoll(mip_fd, app_listen_fd);

    printf("[MIPTPD] Ready — entering event loop.\n");
    run_event_loop(epollfd, mip_fd, app_listen_fd);

    cleanup(epollfd, mip_fd, app_listen_fd);
    return 0;
}

// ......Støttemetoder til main.........

/*
  Leser kommandolinjeflagg og argumenter ved oppstart.
  - Støtter flaggene:
      -h  viser hjelpetekst og avslutter
      -d  aktiverer debug-modus
  - Kontrollerer at to socket-stier (mipd_socket og app_socket) er oppgitt
*/
void handle_flags(int argc, char *argv[]) {
    int opt;
    while ((opt = getopt(argc, argv, "hd")) != -1) {
        switch (opt) {
            case 'h':
                printf("Usage: %s [-d] <mipd_socket> <app_socket>\n", argv[0]);
                printf("  -d  enable debug output\n");
                exit(0);
            case 'd':
                debug_mode = 1;
                break;
            default:
                fprintf(stderr, "Unknown option\n");
                exit(1);
        }
    }

    if (optind + 1 >= argc) {
        fprintf(stderr, "Usage: %s [-d] <mipd_socket> <app_socket>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
}

/*
  Bygger fullstendige UNIX-socketstier for MIPD og appen.
  Hvis brukeren oppgir et navn uten '/', legges "/tmp/" foran
  Hvis en full sti oppgis, brukes den direkte
*/

void parse_socket_paths(char *mipd_arg, char *app_arg, char *mipd_path, char *app_path) {
    if (mipd_arg[0] != '/') {
        snprintf(mipd_path, 108, "/tmp/%s", mipd_arg);
    } else {
        strncpy(mipd_path, mipd_arg, 107);
        mipd_path[107] = '\0';
    }

    if (app_arg[0] != '/') {
        snprintf(app_path, 108, "/tmp/%s", app_arg);
    } else {
        strncpy(app_path, app_arg, 107);
        app_path[107] = '\0';
    }
}
/*
  Kobler transportlaget (miptpd) til MIP-daemonen via UNIX-socket
  Registrerer MIPTP som SDU-type slik at MIPD vet hvilke pakker som skal sendes hit
  Avslutter programmet hvis forbindelsen feiler
*/
int setup_mip_connection(const char *mipd_path) {
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

    if (debug_mode)
        printf("[MIPTPD] Registered with MIPD (SDU type 0x%02X)\n", sdu_type);

    return mip_fd;
}
/*
  Setter opp et epoll-objekt for å overvåke hendelser på flere file descriptors:
  - mip_fd: kommunikasjon med MIP-daemonen
  - app_listen_fd: nye tilkoblinger fra apper
  Returnerer epoll-fd som brukes i main og inn i eventloopen
*/
int setup_epoll(int mip_fd, int app_listen_fd) {
    int epollfd = epoll_create1(0);
    if (epollfd < 0) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    struct epoll_event ev;
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

    return epollfd;
}

/*
  Hovedhendelsesløkke som venter på data eller tilkoblinger via epoll
  - Leser fra mip_fd når MIP-pakker kommer
  - Godtar nye apper via app_listen_fd
  - Leser meldinger fra eksisterende app-forbindelser
  - Kaller jevnlig check_retransmissions() for å håndtere tidsavbrudd
*/
void run_event_loop(int epollfd, int mip_fd, int app_listen_fd) {
    struct epoll_event events[MAX_EVENTS];

    while (1) {
        int n = epoll_wait(epollfd, events, MAX_EVENTS, 500);
        if (n < 0) {
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if (fd == mip_fd && (events[i].events & EPOLLIN)) {
                handle_mip_event(mip_fd);
            }
            else if (fd == app_listen_fd && (events[i].events & EPOLLIN)) {
                handle_new_app_connection(app_listen_fd, epollfd);
            }
            else if (events[i].events & EPOLLIN) {
                handle_app_message(fd);
            }
        }

        check_retransmissions();
    }
}

/*
  Behandler innkommende data fra MIP-daemonen (mipd)
  Leser hele MIPTP-pakken og sender den videre til pakkebehandling
  Avslutter programmet hvis forbindelsen til mipd brytes
*/
void handle_mip_event(int mip_fd) {
    uint8_t buf[1500];
    ssize_t len = read(mip_fd, buf, sizeof(buf));
    if (len <= 0) {
        printf("[MIPTPD] Disconnected from mipd.\n");
        exit(EXIT_FAILURE);
    }
    uint8_t src_mip = buf[0]; 
    uint8_t *payload = buf + 1;
    size_t payload_len = len - 1;

    handle_incoming_miptp_packet(payload, payload_len, src_mip);
}

/*
  Håndterer nye applikasjonsforbindelser 
  Leser første byte for å finne portnummeret appen vil bruke
  Registrerer appen i app_connections-tabellen og legger til i epoll
*/
void handle_new_app_connection(int app_listen_fd, int epollfd) {
    struct epoll_event ev;
    int new_fd = accept(app_listen_fd, NULL, NULL);
    if (new_fd < 0) {
        perror("accept");
        return;
    }

    if(debug_mode) printf("[MIPTPD] New app connected (fd=%d)\n", new_fd);

    uint8_t port = 0;
    ssize_t n = read(new_fd, &port, 1);
    if (n <= 0) {
        fprintf(stderr, "[MIPTPD] Failed to read port number from app (fd=%d)\n", new_fd);
        close(new_fd);
        return;
    }

    if (new_app_connection(new_fd, port) == 0){
        if(debug_mode) printf("[MIPTPD] Registered app on port %d (fd=%d)\n", port, new_fd);
    }
    else {
        fprintf(stderr, "[MIPTPD] Could not register new app (fd=%d)\n", new_fd);
        close(new_fd);
        return;
    }

    ev.events = EPOLLIN;
    ev.data.fd = new_fd;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, new_fd, &ev) == -1)
        perror("epoll_ctl: new_fd");
}

/*
  Leser meldinger sendt fra en applikasjon til transportlaget
  Hvis forbindelsen er lukket, fjernes den
  Ellers sendes dataen videre via MIPTP (send_miptp_data)
*/
void handle_app_message(int fd)
{
    // Finner tilkoblingen for denne app-socketen
    int idx = get_index(fd);
    if (idx < 0) {
        close(fd);
        return;
    }

    app_connection *conn = &app_connections[idx];

    // Første byte fra app er portnummeret den vil bruke
    if (!conn->registered) {
        uint8_t port;
        if (read(fd, &port, 1) != 1) {
            close(fd);
            return;
        }
        // Prøver å registrere porten
        if (new_app_connection(fd, port) != 0) {
            close(fd);
            return;
        }

        conn->registered = 1;
        return;
    }
    // Leser data fra app
    uint8_t buf[4096];
    ssize_t len = read(fd, buf, sizeof(buf));

    // Hvis appen lukker forbindelsen
    if (len <= 0) {
        // Venter litt for å la outstanding ACKs komme inn
        int waits = 0;
        const int MAX_WAITS = 2;   // ca. 400 ms totalt

        while (waits < MAX_WAITS) {
            int outstanding = 0;

            // Sjekk om noen overføringer fortsatt har pakker i vinduet
            for (int i = 0; i < conn->outbound_count; i++) {
                outbound_transfer_state *t = &conn->outbound[i];
                if (t->window_count > 0) {
                    outstanding = 1;
                    break;
                }
            }
            // Alt er ferdig, kan avslutte
            if (!outstanding)
                break;

            // Venter litt og prøv igjen
            struct timespec ts = {0, 200 * 1000000};
            nanosleep(&ts, NULL);
            waits++;
        }
        if (debug_mode)
            printf("[MIPTPD] App fd=%d closed; removing connection.\n", fd);

        // Fjerner apptilkoblingen
        remove_app_connection(fd);
        close(fd);
        return;
    }
    // Vanlig data fra app - send som MIPTP
    send_miptp_data(fd, buf, len);
}


/*
  Lukker alle åpne file descriptors og skriver ut en avslutningsmelding.
  Brukes ved normal nedstenging av miptpd
*/
void cleanup(int epollfd, int mip_fd, int app_listen_fd) {
    close(epollfd);
    close(mip_fd);
    close(app_listen_fd);
    printf("[MIPTPD] Shutting down.\n");
}

