#ifndef MIPD_H
#define MIPD_H

#include <stdint.h>
#include <stddef.h>
#include <net/if.h>  //for IFNAMIZ til interface


//globale verdier
#define MAX_EVENTS 10 // epoll
#define MIPTP_SDU_TYPE 0x05

extern int my_mip_address; // MIP-adressen som er tildelt denne daemon-instansen
extern int debug_mode; // Flag som skrur på/av debug-utskrifter, gis som arg i main

#endif
