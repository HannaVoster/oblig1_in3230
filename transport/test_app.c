#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define APP_SOCKET_PATH "/tmp/miptp_app.sock"

int main(void) {
    const uint8_t my_port = 42;   // appens egen port

    // Opprett UNIX-socket
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Sett opp adresse til miptpd
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, APP_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        exit(EXIT_FAILURE);
    }

    printf("Connected to MIPTP daemon at %s\n", APP_SOCKET_PATH);

    // 1️⃣ Send portnummeret først (registrering)
    if (write(fd, &my_port, 1) != 1) {
        perror("write port");
        close(fd);
        exit(EXIT_FAILURE);
    }
    printf("Sent port number %d to miptpd.\n", my_port);

    // Bygg og send flere meldinger i rask rekkefølge
    const uint8_t dst_mip = 1;
    const uint8_t dst_port = 99;

    for (int i = 0; i < 5; i++) {
        char msg[64];
        snprintf(msg, sizeof(msg), "Hello #%d from port %d", i, my_port);

        uint8_t packet[2 + strlen(msg)];
        packet[0] = dst_mip;  // Hvem vi sender til
        packet[1] = dst_port; // Hvilken port hos mottaker
        memcpy(packet + 2, msg, strlen(msg));

        ssize_t sent = write(fd, packet, sizeof(packet));
        if (sent < 0) {
            perror("write message");
            break;
        }

        printf("[CLIENT] Sent message %d (%zd bytes)\n", i, sent);
        usleep(200000); // 0.2 sek mellom sendingene for tydelig logging
    }

    printf("[CLIENT] All messages sent, waiting for potential responses...\n");

    // Valgfritt: vent litt for å se eventuelle svar
    sleep(3);
    close(fd);
    return 0;
}