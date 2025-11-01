#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdint.h>

int main() {
    const char *sock_path = "/tmp/miptp_app.sock";
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    // Send portnummer (f.eks. 42)
    uint8_t port = 42;
    write(fd, &port, 1);

    printf("Connected and sent port number %d to miptpd.\n", port);
    close(fd);
    return 0;
}
