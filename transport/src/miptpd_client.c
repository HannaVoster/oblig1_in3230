#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <arpa/inet.h>

#define MAX_RETRIES 3
#define CHUNK_SIZE 1400

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "Usage: %s <file_to_send> <dst_mip> <dst_port> <app_socket>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *filename = argv[1];
    uint8_t dst_mip = atoi(argv[2]);
    uint8_t dst_port = atoi(argv[3]);
    const char *socket_arg = argv[4];

    // binder UNIX socket path
    char socket_path[108];
    if (socket_arg[0] != '/')
        snprintf(socket_path, sizeof(socket_path), "/tmp/%s", socket_arg);
    else
        strncpy(socket_path, socket_arg, sizeof(socket_path) - 1);

    // åpner filen
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    fseek(file, 0, SEEK_END);
    uint32_t filesize = ftell(file);
    rewind(file);
    printf("[CLIENT] File size: %u bytes\n", filesize);

    // lager UNIX socket
    int fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd < 0) {
        perror("socket");
        fclose(file);
        return EXIT_FAILURE;
    }

    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(fd);
        fclose(file);
        return EXIT_FAILURE;
    }

    // prøver random porter opp til 3 ganger
    srand(time(NULL));
    uint8_t my_port;
    for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        //my_port = rand() % 256;
        do { my_port = (rand() % 255) + 1; } while (my_port == dst_port);
        if (write(fd, &my_port, 1) == 1) {
            printf("[CLIENT] Registered port %d\n", my_port);
            break;
        }
        printf("[CLIENT] Port %d rejected, retrying...\n", my_port);
        if (attempt == MAX_RETRIES) {
            fprintf(stderr, "[CLIENT] Failed to register port after %d attempts\n", MAX_RETRIES);
            close(fd);
            fclose(file);
            return EXIT_FAILURE;
        }
    }

    // Sender fil størrelse (4 bytes, network byte order)
    uint32_t net_size = htonl(filesize);
   // type 0 = metadata, 1 = filedata
    uint8_t size_msg[2 + sizeof(net_size)];
    size_msg[0] = dst_mip;
    size_msg[1] = dst_port;
    memcpy(size_msg + 2, &net_size, sizeof(net_size));

    if (write(fd, size_msg, sizeof(size_msg)) < 0) {
        perror("write filesize");
        close(fd);
        fclose(file);
        return EXIT_FAILURE;
    }

    // Etter å ha sendt size_msg:
    usleep(200 * 1000); // 200 ms

    // Sender fil contents in 1400-byte chunks
    uint8_t buffer[CHUNK_SIZE];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {

        // Vis hva som faktisk ble lest fra testfilen
        printf("[CLIENT][FILE] Read %zu bytes, first_bytes=", bytes_read);
        for (int i = 0; i < (int)(bytes_read < 16 ? bytes_read : 16); i++)
            printf("%02x ", buffer[i]);
        printf("\n");

        uint8_t packet[2 + bytes_read];
        packet[0] = dst_mip;
        packet[1] = dst_port;
        memcpy(packet + 2, buffer, bytes_read);

            // Vis hva som sendes (uten de to første bytene)
        printf("[CLIENT][SEND] len=%zu first_bytes=", bytes_read);
        for (int i = 0; i < (bytes_read < 16 ? bytes_read : 16); i++)
            printf("%02x ", packet[i + 2]);
        printf("\n");

        ssize_t sent = write(fd, packet, 2 + bytes_read);
        if (sent < 0) {
            perror("write data");
            break;
        }
        printf("[CLIENT] Sent %zd bytes\n", sent - 2);
        usleep(5000); // small delay for readability
    }

    printf("[CLIENT] File transmission complete.\n");
    sleep(1);
    fclose(file);
    close(fd);
    return EXIT_SUCCESS;
}

