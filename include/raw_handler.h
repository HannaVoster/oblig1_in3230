#ifndef RAW_HANDLER_H
#define RAW_HANDLER_H

void handle_raw_packet(int raw_sock, int my_mip_address);

void handle_ping_message(int raw_sock, int my_mip_address,
                         uint8_t dest, uint8_t src, uint8_t ttl,
                         const uint8_t *sdu, ssize_t sdu_len,
                         struct ethhdr *eh, int if_index);

int forward_packet(int raw_sock, int my_mip_address,
                   uint8_t dest, uint8_t src, uint8_t ttl,
                   uint8_t sdu_type, const uint8_t *sdu, ssize_t sdu_len);

void handle_arp_message(int raw_sock, int my_mip_address,
                        const uint8_t *sdu, ssize_t sdu_len,
                        const struct ethhdr *eh, int if_index, uint8_t src);

void handle_pong_message(int raw_sock, int my_mip_address,
                    uint8_t dest, uint8_t src, uint8_t ttl,
                    const uint8_t *sdu, ssize_t sdu_len)
#endif