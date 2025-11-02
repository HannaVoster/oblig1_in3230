#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <time.h>

/*

Registrere porten den skal lytte på (f.eks. 99)
Motta data-PDUs fra miptpd
Når ny (src_mip, src_port) dukker opp → åpne fil
Første melding inneholder 4-byte fil-lengde
Deretter mottas 1400-bytes chunks til filen er komplett

*/

#define APP_SOCKET_PATH "/tmp/miptp_app.sock"
#define CHUNK 1400

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <file> <dst_mip> <dst_port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    const char *filename = argv[1];
    uint8_t dst_mip  = atoi(argv[2]);
    uint8_t dst_port = atoi(argv[3]);

    srand(time(NULL));
    uint8_t my_port = 20 + rand()%200; // tilfeldig app-port

    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, APP_SOCKET_PATH, sizeof(addr.sun_path)-1);
    connect(fd, (struct sockaddr*)&addr, sizeof(addr));

    write(fd, &my_port, 1);
    printf("[CLIENT] Using port %d\n", my_port);

    FILE *f = fopen(filename, "rb");
    if (!f) { perror("fopen"); exit(1); }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    // send lengde
    uint32_t len_net = htonl((uint32_t)fsize);
    uint8_t hdr[2 + 4];
    hdr[0] = dst_mip;
    hdr[1] = dst_port;
    memcpy(hdr+2, &len_net, 4);
    write(fd, hdr, sizeof(hdr));

    // send innhold
    uint8_t buf[CHUNK];
    size_t n;
    while ((n = fread(buf, 1, CHUNK, f)) > 0) {
        uint8_t pkt[2 + n];
        pkt[0] = dst_mip;
        pkt[1] = dst_port;
        memcpy(pkt+2, buf, n);
        write(fd, pkt, sizeof(pkt));
        usleep(1000); // liten pause
    }
    fclose(f);
    printf("[CLIENT] File sent (%ld bytes)\n", fsize);
    close(fd);
}
