#ifndef ROUTING_H
#define ROUTING_H

#include <stdint.h>

typedef struct {
    uint8_t dest;
    uint8_t next;
} routing_entry;

#define MAX_ROUTES 12

extern routing_entry routing_table[MAX_ROUTES];


#endif