#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {

    if (argc != 3) {
        printf("Usage: %s <socket_path> <MIP_address>\n", argv[0]);
        return 1;
    }

    char *socket_path = argv[1];
    int mip_address = atoi(argv[2]);

    printf("Starting MIP-daemon...\n");
    printf("Socket path: %s\n", socket_path);
    printf("MIP address: %d\n", mip_address);

    int sockfd;
    struct sockaddr_un address;

    // 1. Lag UNIX socket
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    // 2. Sett opp adresse
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, socket_path, sizeof(address.sun_path)-1);

    // 3. Fjern evt gammel socket-fil
    unlink(socket_path);

    // 4. Bind socket
    if (bind(sockfd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind");
        exit(1);
    }

    // 5. Listen
    if (listen(sockfd, 5) < 0) {
        perror("listen");
        exit(1);
    }

    printf("Daemon venter på klient...\n");

    // 6. Accept
    int clientfd = accept(sockfd, NULL, NULL);
    if (clientfd < 0) {
        perror("accept");
        exit(1);
    }

    printf("Klient koblet til!\n");

    // 7. Les data fra klient
    char buffer[256];
    int n = read(clientfd, buffer, sizeof(buffer)-1);
    if (n < 0) {
        perror("read");
        exit(1);
    }

    buffer[n] = '\0';
    printf("Mottatt melding: %s\n", buffer);

    // 8. Svar tilbake (debug)
    const char *reply = "Hei fra MIP-daemon!\n";
    write(clientfd, reply, strlen(reply));

    // 9. Lukk alt
    close(clientfd);
    close(sockfd);
    unlink(socket_path);

    return 0;
}

