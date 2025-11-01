// kommunikasjon med MIP-daemon
//grensesnitt mot MIP deamon, nederste lag, under

/*
**Ansvar:**

- Kommunisere via UNIX-socket med `mipd`
- Pakke ut og tolke MIPTP-header
- Dele opp logikken mellom “data” og “ACK”-pakker

*/
#include <stdint.h>
#include <stdlib.h>


int init_mip_socket(const char *path);
void send_miptp_data(uint8_t dst_mip, uint8_t *pdu, size_t len);
void send_miptp_ack(uint8_t dst_mip, uint8_t dst_port, uint16_t seq);
void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip);