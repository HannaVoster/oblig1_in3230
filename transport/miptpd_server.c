

#include <stdint.h>
#include <stdlib.h>

int main(int argc, char *argv[]);
int connect_to_miptp(const char *socket_path, uint8_t listen_port);
void handle_incoming_message(uint8_t src_mip, uint8_t src_port, uint8_t *data, size_t len);
