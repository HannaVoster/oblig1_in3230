

#ifndef ROUTING_PROTOCOL_H
#define ROUTING_PROTOCOL_H

#include <stdint.h>
#include <sys/types.h>

void handle_route_request(int sock, uint8_t *msg, ssize_t length);
void send_route_response(int sock, uint8_t my_address, uint8_t next);
void handle_incoming_message(uint8_t from, uint8_t msg_type, const uint8_t *payload, size_t len);
void broadcast_update(void);
void hello(void);
void expire_stale_routes(int triggered_update);

#endif
