#ifndef MIPTPD_INCOMING_H
#define MIPTPD_INCOMING_H

#include "miptpd.h"

void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip);
void handle_incoming_ack(miptp_hdr_t *hdr, uint16_t seq);
void handle_incoming_data(miptp_hdr_t *hdr, uint8_t *payload, size_t len,
                          uint16_t seq, uint8_t pad, uint8_t src_mip);

#endif
