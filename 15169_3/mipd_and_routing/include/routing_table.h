

#ifndef ROUTING_TABLE_H
#define ROUTING_TABLE_H

#include <stdint.h>

int update_or_insert_neighbor(uint8_t dest, uint8_t next_hop, uint8_t cost);
int get_route(uint8_t dest);
int find_or_add_neighbor(uint8_t mip);
void print_routing_table(void);

#endif
