#ifndef MIPTPD_UTILS_H
#define MIPTPD_UTILS_H

#include "miptpd.h"

// til padding i header
uint16_t pack_seq_pad(uint16_t seq, uint8_t padlen);
void unpack_seq_pad(uint16_t seq_pad, uint16_t *seq, uint8_t *pad);

// hjelpefunksjoner for å hente ut app data
uint8_t get_port_from_fd(int fd);
int get_fd_from_port(uint8_t port);
int get_index(int fd);

// funskjoner for å legge til og fjerne appper
int remove_app_connection(int fd);
int new_app_connection(int fd, uint8_t port);

// funskjoner for å håndtere transfer state på tvers alle appene
transfer_state *create_transfer_state(app_connection *app,
                                      uint8_t src_mip,
                                      uint8_t src_port);
transfer_state *find_transfer(app_connection *app, uint8_t src_mip, uint8_t src_port);

outbound_transfer_state *
find_or_create_outbound(app_connection *app,
                        uint8_t dst_mip,
                        uint8_t dst_port);

outbound_transfer_state *
find_outbound_for_ack(app_connection *app,
                      uint8_t ack_src_mip,   
                      uint8_t ack_src_port);
#endif
