/*
Denne filen håndterer det som har med kommunikasjon mellom routing-daemonen og MIP-daemonen å gjøre

Den oppretter og kobler til UNIX-socketen, venter på at MIPd-socketen skal bli tilgjengelig, 
og har en funskjon for å sende meldinger mellom prosessene

Funksjonene gjør dette:
connect_to_mipd(): kobler routing-daemonen til riktig MIP-daemon via UNIX-socket
wait_for_socket(): venter til socket-filen faktisk finnes før tilkobling
send_unix_message(): sender meldinger (HELLO, UPDATE, REQ, RSP) til MIP-daemonen over UNIX-socketen
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>

#include "routing_socket.h"
#include "routingd.h"

/*
Kobler routingd til MIP-daemonen via en UNIX socket
Lager først sin egen lokale socket, og kobler deretter til MIP-daemonens socket i /tmp/
Etter tilkobling registreres routingd med SDU-type 0x04 og mottar sin MIP-adresse
*/
int connect_to_mipd(const char *socket_path) {
    int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Lager unik lokal UNIX-socket for routingd selv (så flere prosesser ikke kolliderer)
    struct sockaddr_un client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sun_family = AF_UNIX;
    snprintf(client_addr.sun_path, sizeof(client_addr.sun_path),
             "/tmp/routingd_%d.sock", getpid());  // legg den i /tmp/

    unlink(client_addr.sun_path);

    if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("bind client");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Bygger full sti til MIP-daemonens UNIX-socket (legg til /tmp/ hvis ikke absolutt sti)
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;

    char full_path[sizeof(addr.sun_path)];

    // Sjekker om brukeren oppga bare et navn (eg. "usockA") eller en full sti (eg. "/tmp/usockA").
    // Hvis det bare var et navn, legges "/tmp/" foran, siden alle socket-filer ligger der
    if (socket_path[0] != '/') {
        snprintf(full_path, sizeof(full_path), "/tmp/%s", socket_path);
    } else {
        strncpy(full_path, socket_path, sizeof(full_path) - 1);
        full_path[sizeof(full_path) - 1] = '\0';
    }
    // Kopier inn i addr.sun_path
    strncpy(addr.sun_path, full_path, sizeof(addr.sun_path) - 1);
    addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

    fprintf(stderr, "[ROUTINGD] Connecting to MIP daemon socket: %s\n", addr.sun_path);

    // Kobler til MIP-daemonen socket
    int retries = 10;
    int connected = 0;
    for (int i = 0; i < retries; i++) {
        if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == 0) {
            connected = 1;
            break;
        }
        perror("[ROUTINGD] connect attempt failed");
        fprintf(stderr, "[ROUTINGD] Retrying in 0.5 sec... (%d/%d)\n", i + 1, retries);
        usleep(500000); // 0.5 sek
    }

    if (!connected) {
        fprintf(stderr, "[ROUTINGD] ERROR: Could not connect to MIP daemon after %d attempts.\n", retries);
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Registrer routingd som SDU-type 0x04
    uint8_t sdu_type = SDU_TYPE_ROUTING;
    if (write(sock, &sdu_type, 1) != 1) {
        perror("register sdu_type");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Les min MIP-adresse fra MIP-daemonen
    uint8_t my_addr;
    ssize_t n = read(sock, &my_addr, 1);
    if (n == 1) {
        MY_MIP = my_addr;
        fprintf(stderr, "[ROUTINGD] Received MY_MIP = %d from MIPd\n", MY_MIP);
    } else if (n == 0) {
        fprintf(stderr, "[ROUTINGD] Warning: MIP daemon closed socket unexpectedly\n");
    } else {
        perror("read MY_MIP from MIPd");
    }

    fprintf(stderr, "[ROUTINGD] Connected and registered to socket fd=%d (SDU=0x04)\n", sock);

    return sock;
}

// Venter på at MIP-daemonens UNIX-socket-fil skal dukke opp før routing deamon prøver å koble til
// Brukes for å unngå at routingd starter før MIPd faktisk har laget socketen
// void wait_for_socket(const char *path) {
//     struct stat sb; // en struktur som lagrer filinfo, bruket den til å sjekke om path finnes
//     int tries = 0;

//     // Sjekker gjentatte ganger om socket-filen finnes
//     while (stat(path, &sb) != 0) {
//         if (tries++ > 100) {
//             fprintf(stderr, "[ROUTINGD] Timeout waiting for socket %s\n", path);
//             exit(EXIT_FAILURE);
//         }
//         usleep(100000); // 0.1 sek
//     }
// }

void wait_for_socket(const char *path) {
    char full_path[108];

    // Hvis path ikke allerede starter med '/', legg til /tmp/
    if (path[0] != '/') {
        snprintf(full_path, sizeof(full_path), "/tmp/%s", path);
    } else {
        strncpy(full_path, path, sizeof(full_path) - 1);
        full_path[sizeof(full_path) - 1] = '\0';
    }

    struct stat sb;
    int tries = 0;

    // Sjekker gjentatte ganger om socket-filen finnes
    while (stat(full_path, &sb) != 0) {
        if (tries++ > 100) {
            fprintf(stderr, "[ROUTINGD] Timeout waiting for socket %s\n", full_path);
            exit(EXIT_FAILURE);
        }
        usleep(100000); // 0.1 sek
    }

    fprintf(stderr, "[ROUTINGD] Socket %s is now available\n", full_path);
}


// Generisk metode til å kommuniserer med MIPD over unix socket
// Pakker destinasjon, TTL og payload inn i en buffer og skriver den ut på ROUTING_SOCK
int send_unix_message(uint8_t dest, uint8_t ttl, const uint8_t* data, size_t len) {
    uint8_t buf[256];

    //ikke send dersom meldingen er for stor for bufferen
    if (len + 2 > sizeof(buf)) return -1;

    buf[0] = dest; 
    buf[1] = ttl; 

    // Kopierer inn selve dataen
    memcpy(&buf[2], data, len);

    // Skriver alt til MIP-daemonens socket
    return write(ROUTING_SOCK, buf, len + 2);
}
