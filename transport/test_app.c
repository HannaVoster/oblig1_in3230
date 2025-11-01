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
    const uint8_t dst_mip = 1;    // hvem vi vil sende til (eksempel)
    const uint8_t dst_port = 99;  // port hos mottakerappen

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

    // 2️⃣ Bygg meldingen: [dst_mip][dst_port][payload...]
    const char *message = "Hello from test_app!";
    size_t msg_len = strlen(message);

    uint8_t packet[2 + msg_len];
    packet[0] = dst_mip;
    packet[1] = dst_port;
    memcpy(packet + 2, message, msg_len);

    // 3️⃣ Send meldingen
    ssize_t sent = write(fd, packet, sizeof(packet));
    if (sent < 0) {
        perror("write message");
    } else {
        printf("Sent message to MIP=%d, port=%d (%zd bytes)\n", dst_mip, dst_port, sent);
    }

    // 4️⃣ (Valgfritt) Vent på svar
    uint8_t buf[256];
    ssize_t n = read(fd, buf, sizeof(buf));
    if (n > 0) {
        printf("Got reply: %.*s\n", (int)n, buf);
    } else {
        printf("No reply or connection closed.\n");
    }

    close(fd);
    return 0;
}
