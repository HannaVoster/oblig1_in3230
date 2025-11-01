// kommunikasjon med MIP-daemon
//grensesnitt mot MIP deamon, nederste lag, under

/*
**Ansvar:**

- Kommunisere via UNIX-socket med `mipd`
- Pakke ut og tolke MIPTP-header
- Dele opp logikken mellom “data” og “ACK”-pakker

*/
#include "miptpd.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void send_miptp_data(int app_fd, uint8_t *data, size_t len) {
    miptp_hdr_t hdr = {0};
    hdr.src_port = 42;   // midlertidig, skal være appens port
    hdr.dst_port = data[1]; // eksempel: hent fra første byte i data
    hdr.seq_pad = pack_seq_pad(0, 0); // sekvens=0, ingen padding

    uint8_t packet[1500];
    memcpy(packet, &hdr, sizeof(hdr));
    memcpy(packet + sizeof(hdr), data, len);

    ssize_t sent = write(MIP_FD, packet, sizeof(hdr) + len);
    if (sent < 0)
        perror("[MIPTPD] write to mipd");
    else
        printf("[MIPTPD] Sent %zd bytes to mipd\n", sent);
}

void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip) {
    if (len < sizeof(miptp_hdr_t)) return;

    miptp_hdr_t hdr;
    memcpy(&hdr, buf, sizeof(hdr));

    uint8_t *payload = buf + sizeof(hdr);
    size_t payload_len = len - sizeof(hdr);

    printf("[MIPTPD] Got packet from MIP %d, src_port=%d dst_port=%d len=%zu\n",
           src_mip, hdr.src_port, hdr.dst_port, payload_len);

    // TODO: slå opp riktig app-fd for dst_port
    // write(app_fd, payload, payload_len);
}


// int init_mip_socket(const char *path);
// void send_miptp_data(uint8_t dst_mip, uint8_t *pdu, size_t len);
// void send_miptp_ack(uint8_t dst_mip, uint8_t dst_port, uint16_t seq);
// void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip);


// // Fra miptp_mip.c
// void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip);
// void send_miptp_data(int app_fd, uint8_t *data, size_t len);