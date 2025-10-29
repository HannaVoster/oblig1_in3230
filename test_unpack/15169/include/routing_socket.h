#ifndef ROUTING_SOCKET_H
#define ROUTING_SOCKET_H

#include <stdint.h>

int connect_to_mipd(const char *socket_path);
void wait_for_socket(const char *path);
int send_unix_message(uint8_t dest, uint8_t ttl, const uint8_t* data, size_t len);

#endif