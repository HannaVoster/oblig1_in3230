// hjelpemetoder (sekvensnummer, padding, logging)

/*
**Ansvar:**

- Sekvensnummer-logikk (inkl. wrap-around)
- Paddingberegning (for 32-bit justering)
- Logging/debug-print
- Generelle verktøy som brukes av flere filer
*/

#include <stdint.h>
#include <stdlib.h>
#include "miptpd.h"

uint16_t pack_seq_pad(uint16_t seq, uint8_t padlen) {
    return (seq << 2) | (padlen & 0x03);
}

void unpack_seq_pad(uint16_t seq_pad, uint16_t *seq, uint8_t *padlen) {
    *padlen = seq_pad & 0x03;
    *seq = seq_pad >> 2;
}

// uint16_t pack_seq_pad(uint16_t seq, uint8_t padlen);
// void unpack_seq_pad(uint16_t seq_pad, uint16_t *seq, uint8_t *padlen);
// uint8_t calc_padding(size_t sdu_len);
// int seq_less(uint16_t a, uint16_t b);
