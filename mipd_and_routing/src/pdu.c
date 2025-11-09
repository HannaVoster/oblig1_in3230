#include <stdio.h>       
#include <stdlib.h>      
#include <string.h>      
#include <stdint.h>     
#include <arpa/inet.h>   
#include <net/if.h>      
#include <netpacket/packet.h> 
#include <net/ethernet.h>    
#include <sys/ioctl.h>   
#include <unistd.h>      

#include "mipd.h"
#include "pdu.h"
#include "iface.h"

/*
Bygger en komplett MIP_PDU protocol data unit som består av:
4 byte mip header
sdu, service data unit (padded til 32 bit grense)

metoden returnerer en peker til en nyallokert buffer som holder PDU
*out_len settes også til den totale lengden så den kan brukes til å sende pdu senere
*/
uint8_t *mip_build_pdu(uint8_t dest, uint8_t src, uint8_t ttl,
                       uint8_t sdu_type,
                       const uint8_t *sdu, uint16_t sdu_len_bytes,
                       size_t *out_len)
{
    // Beregn antall 32-bits ord (avrund opp)
    uint16_t len_words = (sdu_len_bytes + 3) / 4;

    size_t sdu_aligned = len_words * 4;

    // Total faktisk lengde (header + ekte data, ingen padding)
    size_t total = 4 + sdu_aligned;
    uint8_t *buf = malloc(total);
    if (!buf) {
        perror("malloc mip_build_pdu");
        exit(EXIT_FAILURE);
    }

    // Pakk inn headerfeltene
    buf[0] = dest;
    buf[1] = src;
    buf[2] = ((ttl & 0x0F) << 4) | ((len_words >> 5) & 0x0F);
    buf[3] = ((len_words & 0x1F) << 3) | (sdu_type & 0x07);

    // Kopier SDU (ingen padding!)
    if (sdu && sdu_len_bytes)
        memcpy(buf + 4, sdu, sdu_len_bytes);
    
    // Nullfyll hvis SDU ble avrundet opp
    if (sdu_aligned > sdu_len_bytes)
        memset(buf + 4 + sdu_len_bytes, 0, sdu_aligned - sdu_len_bytes);

    if (out_len)
        *out_len = total;
        
    printf("[DEBUG][BUILD] sdu_len_bytes=%u len_words=%u total=%zu\n",
       sdu_len_bytes, len_words, total);

    printf("[DBG][MIP_BUILD] header bytes: %02x %02x %02x %02x\n",
           buf[0], buf[1], buf[2], buf[3]);

    if (debug_mode) {
        printf("[DEBUG] mip_build_pdu: dest=%u src=%u ttl=%u type=%u "
               "sdu_len=%u words=%u total=%zu\n",
               dest, src, ttl, sdu_type, sdu_len_bytes, len_words, total);
    }

    return buf; // caller må free()
}


//Tolker og parser en mip pakke fra rådata mottat i handle_raw_packet
//returnerer en peker til sdu delen - payloaden til pakken
ssize_t mip_parse(const uint8_t *rcv, size_t rcv_len,
                  uint8_t *dest, uint8_t *src, uint8_t *ttl,
                  uint8_t *sdu_type, const uint8_t **sdu_out)
{
    // Sjekk at pakken er minst 4 byte (nok til header)
    if (rcv_len < 4) return -1;

    // pakker ut headerfelt 
    *dest = rcv[0]; //destinasjonens mip
    *src  = rcv[1]; //kilde -mip

    // Byte 2 inneholder TTL i de øverste 4 bitene
    *ttl  = (rcv[2] >> 4) & 0x0F;
    
    // Lengden på SDU-delen er lagret i "ord" (4 bytes per ord)
    uint16_t len_words = ((rcv[2] & 0x0F) << 5) | ((rcv[3] >> 3) & 0x1F);

    // SDU-type er de 3 laveste bitene i byte 3
    *sdu_type = rcv[3] & 0x07;

    // beregner sdu lengde i bytes
    size_t sdu_bytes = (size_t)len_words * 4;

    // Sjekk at bufferen faktisk er stor nok til å inneholde alt
    if (rcv_len < 4 + sdu_bytes) return -1;

    // Sett peker til starten av SDU-delen (etter headeren)
    if (sdu_out) *sdu_out = rcv + 4;

    if (debug_mode) {
        printf("[DEBUG][PDU] mip_parse decoded: dest=%u src=%u ttl=%u len_words=%u sdu_type=%u\n\n",
            *dest, *src, *ttl, len_words, *sdu_type);
    }
    // Returner hvor mange bytes SDU-delen er på
    return (ssize_t)sdu_bytes;
}

/*
Denne funksjonen tar en ferdig MIP-pakke (PDU), legger den inn i en Ethernet-ramme, og sender den ut på riktig nettverkskort.
Først bygges headeren med riktig MAC-adresser og EtherType
Deretter kopieres selve PDU-en inn og sendes med sendto() via raw socket
*/

int send_pdu(int rawsocket, uint8_t *pdu, size_t pdu_length, unsigned char *dest_mac, int ifindex) {

    // Sjekk at socketen er gyldig
    if (rawsocket < 0) {
        perror("rawsocket");
        exit(1);
    }

    // Ethernet-ramme = Ethernet-header + PDU-data
    size_t frame_len = sizeof(struct ethhdr) + pdu_length;
    if (frame_len < 60) frame_len = 60; // minimum Ethernet frame size

    // Alloker minne for hele rammen
    uint8_t *frame = calloc(1, frame_len);
    if (!frame) {
        perror("calloc");
        return -1;
    }

   // Henter navn og MAC-adresse til interfacet, for kilde-MAC
    char ifname[IFNAMSIZ];
    unsigned char src_mac[ETH_ALEN];
    if (if_indextoname(ifindex, ifname) == NULL) {
        perror("if_indextoname");
        printf("[DEBUG] could not resolve interface index %d\n", ifindex);
        return -1;
    } 

    // Henter MAC-adressen til dette interfacet (for avsenderfeltet)
    if (get_iface_mac(ifname, src_mac) < 0) {
        perror("get_iface_mac");
        return -1;
    }

    // Bygg Ethernet-header 
    struct ethhdr *eh = (struct ethhdr *)frame;
    memcpy(eh->h_dest, dest_mac, ETH_ALEN); // mottaker
    memcpy(eh->h_source, src_mac, ETH_ALEN); // nodens eget interface
    eh->h_proto = htons(ETH_P_MIP); // egendefinert MIP protokoll

    // Kopier MIP-PDU inn i rammen etter headeren
    memcpy(frame + sizeof(struct ethhdr), pdu, pdu_length);

    // Setter opp sockaddr_11 for å spesifisere hvilket interface det skal sendes på
    struct sockaddr_ll device = {0};
    device.sll_family   = AF_PACKET;
    device.sll_protocol = htons(ETH_P_MIP);
    device.sll_ifindex  = ifindex;
    device.sll_halen    = ETH_ALEN;
    memcpy(device.sll_addr, dest_mac, ETH_ALEN);

    // Sender rammen ut på nettverket
    int sent = sendto(rawsocket, frame, frame_len, 0, (struct sockaddr *)&device, sizeof(device));

    // Sjekker om sendingen var vellykket
    if (sent < 0) {
        perror("[send_pdu] sendto");
    } else if (debug_mode) {
        printf("[DEBUG] send_pdu: TX via %s (index=%d) bytes=%d\n",
                ifname, ifindex, sent);
    }
   
    return sent;
}


