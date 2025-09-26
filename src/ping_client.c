// program som brukes til å sende melding via mipd
//sender til en destinasjons mip addresse

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>

#define BUF_SIZE 256

int main(int argc, char *argv[]) {
    if (argc < 4 || strcmp(argv[1], "-h") == 0) {
        printf("Usage: %s <socket_lower> <message> <destination_host>\n", argv[0]);
        return 0;
    }

    const char *socket_path = argv[1];
    const char *message = argv[2];
    uint8_t dest_host = atoi(argv[3]);

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

    // Lag melding: [dest_host][PING:<message>]
    char buf[BUF_SIZE];
    buf[0] = dest_host;
    snprintf(&buf[1], BUF_SIZE - 1, "PING:%s", message);

    struct timeval start, end;
    gettimeofday(&start, NULL);

    if (write(sock, buf, strlen(&buf[1]) + 1) < 0) {
        perror("write");
        close(sock);
        return 1;
    }

    // Sett timeout på 1 sekund
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    struct timeval tv = {1, 0};

    int rv = select(sock + 1, &fds, NULL, NULL, &tv);
    if (rv == 0) {
        printf("timeout\n");
        close(sock);
        return 0;
    }

    char reply[BUF_SIZE];
    int n = read(sock, reply, sizeof(reply) - 1);
    if (n > 0) {
        reply[n] = '\0';
        gettimeofday(&end, NULL);
        long ms = (end.tv_sec - start.tv_sec) * 1000 +
                  (end.tv_usec - start.tv_usec) / 1000;
        printf("[PING_CLIENT] Reply: %s (RTT=%ld ms)\n", reply, ms);
    } else {
        printf("timeout\n");
    }

    close(sock);
    return 0;
}
