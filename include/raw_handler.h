#ifndef RAW_HANDLER_H
#define RAW_HANDLER_H

#include <stdint.h>
#include <sys/types.h>
#include <net/ethernet.h>  // for struct ethhdr

void handle_raw_packet(int raw_sock, int my_mip_address);

void handle_routing_message(uint8_t src, const uint8_t *sdu, ssize_t sdu_len);

void handle_ping_message(int my_mip_address,
                         uint8_t dest, uint8_t src, uint8_t ttl,
                         const uint8_t *sdu, ssize_t sdu_len,
                         struct ethhdr *eh, int if_index);

void handle_pong_message(int my_mip_address,
                         uint8_t dest, uint8_t src, uint8_t ttl,
                         const uint8_t *sdu, ssize_t sdu_len);

void handle_arp_message(int raw_sock, int my_mip_address,
                        const uint8_t *sdu, ssize_t sdu_len,
                        const struct ethhdr *eh, int if_index, uint8_t src);

int forward_packet(int my_mip_address,
                   uint8_t dest, uint8_t src, uint8_t ttl,
                   uint8_t sdu_type, const uint8_t *sdu, ssize_t sdu_len);

//HJEMMEEKSAMEN 2
void handle_miptp_message(int my_mip_address,
                          uint8_t dest, uint8_t src, uint8_t ttl,
                          const uint8_t *payload, size_t length);
void print_payload_hex(const uint8_t *data, size_t len);

#endif
