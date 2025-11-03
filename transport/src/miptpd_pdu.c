/*
 *  Ansvar:
 *  - Bygge MIPTP-protokollpakker (PDUs) for både data og ACK
 *  - Sørge for korrekt padding (32-bit alignment)
 *  - Pakke inn sekvensnummer og pad-lengde i MIPTP-headeren
 *  - Returnere ferdige byte-buffere klare for sending til mipd
 */

#include "miptpd_send.h"
#include "miptpd_utils.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

/*
  Bygger en MIPTP Data-PDU som inneholder:
    - MIPTP-header (src_port, dst_port, seq_pad)
    - SDU (Service Data Unit) fra applikasjonen
    - Padding slik at total lengde blir 32-bit aligned

  Returnerer en allokert buffer (må frigjøres av kallende funksjon).
*/
uint8_t *build_data_pdu(uint8_t src_port, uint8_t dst_port,
                        uint16_t seq, const uint8_t *sdu, size_t sdu_len,
                        size_t *out_len)
{
    // Finn hvor mange bytes som må til for 32-bit alignment
    uint8_t padlen = (4 - ((sizeof(miptp_hdr_t) + sdu_len) % 4)) % 4;

    // Alloker buffer: header + SDU + pad
    size_t total = sizeof(miptp_hdr_t) + sdu_len + padlen;
    uint8_t *buf = malloc(total);
    if (!buf) {
        perror("malloc build_data_pdu");
        exit(EXIT_FAILURE);
    }

    miptp_hdr_t hdr;
    hdr.src_port = src_port;
    hdr.dst_port = dst_port;
    hdr.seq_pad  = htons(pack_seq_pad(seq, padlen)); // packer 14-bit seq + 2-bit padlen

    memcpy(buf, &hdr, sizeof(hdr));

    if (sdu_len > 0)
        memcpy(buf + sizeof(hdr), sdu, sdu_len);

    if (padlen > 0)
        memset(buf + sizeof(hdr) + sdu_len, 0, padlen);

    if (out_len) *out_len = total;
    return buf;
}

/*
  Bygger en MIPTP ACK-PDU (uten nyttelast).
  Inneholder kun header med sekvensnummeret som bekreftes,
  samt eventuell padding for 32-bit alignment.
*/
uint8_t *build_ack_pdu(uint8_t src_port, uint8_t dst_port,
                       uint16_t seq, size_t *out_len)
{
    // Beregn padding basert på kun header-størrelse
    uint8_t padlen = (4 - (sizeof(miptp_hdr_t) % 4)) % 4;

    // Total lengde = header + ev. padding
    size_t total = sizeof(miptp_hdr_t) + padlen;
    uint8_t *buf = malloc(total);
    if (!buf) { perror("malloc build_ack_pdu"); exit(EXIT_FAILURE); }

    // Sett opp headerfeltene
    miptp_hdr_t hdr;
    hdr.src_port = src_port;
    hdr.dst_port = dst_port;
    hdr.seq_pad  = htons(pack_seq_pad(seq, padlen));

    // Kopier header til buffer
    memcpy(buf, &hdr, sizeof(hdr));

    // Legg til padding (nuller) hvis nødvendig
    if (padlen > 0) memset(buf + sizeof(hdr), 0, padlen);
    
    // Oppdater utlengde
    if (out_len) *out_len = total;
    return buf;
}