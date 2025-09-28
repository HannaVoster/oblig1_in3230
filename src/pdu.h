#ifndef MIP_HEADER_H
#define MIP_HEADER_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

uint32_t mip_pack_header(uint8_t dest,
                         uint8_t src,
                         uint8_t ttl,
                         uint16_t len_words,
                         uint8_t sdu_type);

void mip_unpack_header(uint32_t h_net,
                       uint8_t *dest,
                       uint8_t *src,
                       uint8_t *ttl,
                       uint16_t *len_words,
                       uint8_t *sdu_type);

uint8_t *mip_build_pdu(uint8_t dest, uint8_t src, uint8_t ttl,
                       uint8_t sdu_type,
                       const uint8_t *sdu, uint16_t sdu_len_bytes,
                       size_t *out_len);

// Parse en mottatt PDU-buffer (fra etter Ethernet-headeren)
// Returnerer SDU-lengde i bytes, eller -1 ved feil.
// Setter ut-parametere dest/src/ttl/type, og gir peker til SDU-området.
ssize_t mip_parse(const uint8_t *rcv, size_t rcv_len,
                  uint8_t *dest, uint8_t *src, uint8_t *ttl,
                  uint8_t *sdu_type, const uint8_t **sdu_out);

#endif
