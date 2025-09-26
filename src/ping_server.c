//mottar meldinger som mipd leverer
//trenger bare socket path til å lytte og ta imot

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#define BUF_SIZE 512 //økt etter warning

int main(int argc, char *argv[]) {
    if (argc < 2 || strcmp(argv[1], "-h") == 0) {
        printf("Usage: %s <socket_lower>\n", argv[0]);
        return 0;
    }

    const char *socket_path = argv[1];

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(EXIT_FAILURE);
    }

    char buf[BUF_SIZE];
    int n = read(sock, buf, sizeof(buf) - 1);
    if (n <= 0) {
        perror("read");
        close(sock);
        return 1;
    }
    buf[n] = '\0';

    printf("[PING_SERVER] Received: %s\n", buf);

    // Lag svar: "PONG:<received>"
    char reply[BUF_SIZE];
    snprintf(reply, sizeof(reply), "PONG:%s", buf);

    if (write(sock, reply, strlen(reply)) < 0) {
        perror("write");
    } else {
        printf("[PING_SERVER] Sent: %s\n", reply);
    }

    close(sock);
    return 0;
}
