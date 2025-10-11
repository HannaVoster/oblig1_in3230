#ifndef MIPD_H
#define MIPD_H

#include <stdint.h>
#include <stddef.h>
#include <net/if.h>  //for IFNAMIZ til interface


#include "queue.h"

//globale verdier

extern int my_mip_address; // MIP-adressen som er tildelt denne daemon-instansen
extern int debug_mode; // Flag som skrur på/av debug-utskrifter, gis som arg i main
extern int last_unix_client_fd; // filbeskrivelse til den sist koblede unix klienten

extern int last_ping_src;

extern char last_ping_payload[];
extern size_t last_ping_payload_len;
extern int ping_waiting;


#define MAX_EVENTS 10 // epoll

extern int debug_mode; // debug flagg
extern int last_unix_client_fd; // siste unix klient
extern int last_ping_src;
extern int my_mip_address; // min mip addresse


#endif
