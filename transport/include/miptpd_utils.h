#ifndef MIPTPD_UTILS_H
#define MIPTPD_UTILS_H

#include "miptpd.h"

uint16_t pack_seq_pad(uint16_t seq, uint8_t padlen);
void unpack_seq_pad(uint16_t seq_pad, uint16_t *seq, uint8_t *pad);

uint8_t get_port_from_fd(int fd);
int remove_app_connection(int fd);
int new_app_connection(int fd, uint8_t port);
int get_fd_from_port(uint8_t port);
int get_index(int fd);

#endif
