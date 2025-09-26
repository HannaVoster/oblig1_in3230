#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <socket_path> <message>\n", argv[0]);
        return 1;
    }

    char *socket_path = argv[1];
    char *msg = argv[2];

    int sockfd;
    struct sockaddr_un address;

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) { perror("socket"); exit(1); }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, socket_path, sizeof(address.sun_path)-1);

    if (connect(sockfd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("connect"); exit(1);
    }

    write(sockfd, msg, strlen(msg));

    char buffer[256];
    int n = read(sockfd, buffer, sizeof(buffer)-1);
    if (n > 0) {
        buffer[n] = '\0';
        printf("Svar fra daemon: %s\n", buffer);
    }

    close(sockfd);
    return 0;
}
