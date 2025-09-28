#include <stdio.h>    // for perror
#include <stdlib.h>   // for malloc, exit
#include <string.h>   // for memcpy, memset
#include <stdint.h>   // for uint8_t, uint32_t
#include <arpa/inet.h> // for htonl, ntohl
#include "pdu.h"


uint32_t mip_pack_header(uint8_t dest,
                         uint8_t src,
                         uint8_t ttl,
                         uint16_t len_words,
                         uint8_t sdu_type)
{
    uint32_t h = 0;
    h |= ((uint32_t)dest      & 0xFF) << 24;
    h |= ((uint32_t)src       & 0xFF) << 16;
    h |= ((uint32_t)ttl       & 0x0F) << 12;
    h |= ((uint32_t)len_words & 0x1FF) << 3;
    h |= ((uint32_t)sdu_type  & 0x07);
    return h;
}

void mip_unpack_header(uint32_t h_net,
                       uint8_t *dest,
                       uint8_t *src,
                       uint8_t *ttl,
                       uint16_t *len_words,
                       uint8_t *sdu_type)
{
    uint32_t h = ntohl(h_net);
    if (dest)      *dest      = (h >> 24) & 0xFF;
    if (src)       *src       = (h >> 16) & 0xFF;
    if (ttl)       *ttl       = (h >> 12) & 0x0F;
    if (len_words) *len_words = (h >> 3)  & 0x1FF;
    if (sdu_type)  *sdu_type  =  h        & 0x07;
}

uint8_t *mip_build_pdu(uint8_t dest, uint8_t src, uint8_t ttl,
                       uint8_t sdu_type,
                       const uint8_t *sdu, uint16_t sdu_len_bytes,
                       size_t *out_len)
{
    // SDU må være 32-bit justert
    uint16_t aligned = (sdu_len_bytes + 3) & ~0x03;
    uint16_t len_words = aligned / 4;

    // alloker (4 byte header + SDU pad)
    size_t total = 4 + aligned;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) {
        perror("malloc mip_build_pdu");
        exit(EXIT_FAILURE);
    }

    // pakk header -> nettverksbyteorden
    uint32_t h_host = mip_pack_header(dest, src, ttl, len_words, sdu_type);
    uint32_t h_net  = htonl(h_host);
    memcpy(buf, &h_net, 4);

    // kopier SDU + pad med nuller
    if (sdu_len_bytes && sdu) {
        memcpy(buf + 4, sdu, sdu_len_bytes);
    }
    if (aligned > sdu_len_bytes) {
        memset(buf + 4 + sdu_len_bytes, 0, aligned - sdu_len_bytes);
    }

    if (out_len) *out_len = total;
    return buf;
}
