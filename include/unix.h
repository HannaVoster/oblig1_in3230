#ifndef UNIX_H
#define UNIX_H

#include <stdint.h>
#include <stdlib.h>

#define MAX_UNIX_CLIENT 10

typedef struct {
    int fd;
    uint8_t sdu_type;
    int active;
} unix_client;

//liste over unix klienter
extern unix_client unix_clients[MAX_UNIX_CLIENT];

int create_unix_socket(const char *path);
void handle_unix_request(int client_fd, int raw_sock, int my_mip_address);
void handle_ping_server_message(int client, char *buffer, int bytes_read);

#endif