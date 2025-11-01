#include <stdint.h>


int main(int argc, char *argv[]);
int connect_to_miptp(const char *socket_path, uint8_t local_port);
void send_file(int fd, uint8_t dst_mip, uint8_t dst_port, const char *filename);


