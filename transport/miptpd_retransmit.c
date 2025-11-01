//Håndtering av Go-Back-N, tidsstyring og vindu

/*
**Ansvar:**

- Holde oversikt over sendervinduet (16 pakker)
- Starte og resette timer ved send/ACK
- Gjenutsending av tapte pakker
- Fjerne ACKede pakker fra bufferen

*/

#include <stdint.h>
#include <stdlib.h>

void init_retransmission_state();
void check_retransmissions();
void on_ack_received(uint16_t ack_seq);
void buffer_outgoing_packet();


// // Fra miptp_retransmit.c
// void check_retransmissions(void);