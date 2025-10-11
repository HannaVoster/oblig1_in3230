#ifndef MIP_HEADER_H
#define MIP_HEADER_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#define SDU_TYPE_PING  0x02
#define SDU_TYPE_PONG  0x03


// PDU header
typedef struct __attribute__((packed)) {
    uint8_t dest;
    uint8_t src;
    uint8_t ttl_len;   // øvre 4 bit = TTL, nedre 4 = high bits av length
    uint8_t len_type;  // nedre 4 bit = SDU-type, øvre 4 bit kan være high bits av length
} mip_header_t;

uint8_t *mip_build_pdu(uint8_t dest, uint8_t src, uint8_t ttl,
                       uint8_t sdu_type,
                       const uint8_t *sdu, uint16_t sdu_len_bytes,
                       size_t *out_len);

ssize_t mip_parse(const uint8_t *rcv, size_t rcv_len,
                  uint8_t *dest, uint8_t *src, uint8_t *ttl,
                  uint8_t *sdu_type, const uint8_t **sdu_out);

int send_pdu(int rawsocket, uint8_t *pdu, size_t pdu_length, unsigned char *dest_mac);

// hentefunksjoner
uint8_t get_src(const mip_header_t *h);
uint8_t get_dest(const mip_header_t *h);
uint8_t get_type(const mip_header_t *h);
uint16_t get_length(const mip_header_t *h);
uint8_t get_ttl(const mip_header_t *h);

//sette funksjoner
void set_dest(mip_header_t *h, uint8_t dest);
void set_src(mip_header_t *h, uint8_t src);
void set_ttl(mip_header_t *h, uint8_t ttl);
void set_length(mip_header_t *h, uint16_t len_words);
void set_type(mip_header_t *h, uint8_t type);

#endif
