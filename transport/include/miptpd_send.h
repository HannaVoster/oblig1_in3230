#ifndef MIPTPD_SEND_H
#define MIPTPD_SEND_H

#include "miptpd.h"

// sendefunskjoner - miptpd_send.c
void send_miptp_data(int app_fd, uint8_t *data, size_t len);
void send_miptp_ack(uint8_t dst_mip, uint8_t src_port, uint8_t dst_port, uint16_t seq);
void send_miptp_pdu(uint8_t dst_mip, uint8_t *miptp_pdu, size_t pdu_len);
void send_miptp_data_on_transfer(app_connection *appc,
                                 outbound_transfer_state *t,
                                 uint8_t *payload,
                                 size_t payload_len);

// pdu for data og ack - miptpd_pdu.c
uint8_t *build_data_pdu(uint8_t src_port, uint8_t dst_port,
                        uint16_t seq, const uint8_t *sdu, size_t sdu_len,
                        size_t *out_len);
uint8_t *build_ack_pdu(uint8_t src_port, uint8_t dst_port,
                       uint16_t seq, size_t *out_len);


#endif
