#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#include "routing_protocol.h"
#include "routing_table.h"
#include "routing_socket.h"
#include "routingd.h"


void handle_route_request(int sock, uint8_t *msg, ssize_t length) {
    if (length < 6) { 
        fprintf(stderr, "[ROUTINGD] Ugyldig REQUEST (for kort)\n");
        return; 
    }

    uint8_t my_addr = msg[0];      // egen MIP (ekko fra MIPd)
    uint8_t dest    = msg[5];      // oppslagsdestinasjon
    printf("[ROUTINGD] handle_route_request: my=%d dest=%d\n", my_addr, dest);

    uint8_t next = 255;            // 255 = ingen rute
    int id = get_route(dest);
    if (id >= 0 && routing_table[id].valid) {
        printf("[ROUTINGD] Found route: dest=%d via=%d\n",
               routing_table[id].dest, routing_table[id].next_hop);
    } else {
        printf("[ROUTINGD] No route found for dest=%d\n id = %d, routing_table[id].valid = %d ", dest, id, routing_table[id].valid);
    }
    if (id >= 0 && routing_table[id].valid) {
        next = routing_table[id].next_hop;
    }

    printf("[ROUTINGD] handle_route_request: my=%d dest=%d -> id=%d valid=%d next=%d cost=%d\n",
       my_addr, dest, id,
       (id >= 0 ? routing_table[id].valid : -1),
       (id >= 0 ? routing_table[id].next_hop : -1),
       (id >= 0 ? routing_table[id].cost : -1));

    send_route_response(sock, my_addr, next);
}

void send_route_response(int sock, uint8_t my_address, uint8_t next){
    printf("[ROUTINGD] Sent RESPONSE: my=%d next_hop=%d)\n",
       my_address, next);
    
    uint8_t rsp[6] = { my_address, 0, 'R', 'S', 'P', next }; //etter format fra oppgaven
    if (write(sock, rsp, sizeof(rsp)) != sizeof(rsp))
        perror("write response");
    else
        printf("[ROUTINGD] Sent RESPONSE: next hop =%d\n", next);    
}

void handle_incoming_message(uint8_t from, uint8_t msg_type, const uint8_t *payload, size_t len){
    // lager en switch basert på meldingstype 
    switch(msg_type) {
        case RT_MSG_HELLO: {
            if(debug_mode){
                printf("[ROUTINGD] HELLO mottatt fra %d\n", from);
            }
        // Finn nabo eller legg den til
            int id = find_or_add_neighbor(from);
            neighbors[id].last_hello_ms = now_ms();
            neighbors[id].valid = 1;

            // Oppdater routingtabellen: direkte nabo = cost 1
            update_or_insert_neighbor(from, from, 1);
            break;
        }

        case RT_MSG_UPDATE: {
            if (debug_mode){
                printf("[ROUTINGD] UPDATE mottatt fra %d (len=%zu)\n", from, len);
            }

            int id = find_or_add_neighbor(from);
            neighbors[id].last_hello_ms = now_ms();

            if (len < 2) break;
            if (len % 2 != 0) {
                if (debug_mode)
                    printf("[ROUTINGD] WARNING: Odd UPDATE len=%zu, justerer ned.\n", len);
                len--; // dropp siste byte hvis den er ujevn
            }

            int num_entries = len / 2; // fordi payload = [dest, cost, dest, cost, ...]

            if (debug_mode) {
                printf("[TRACE] Parsing %d entries in UPDATE fra %d\n", num_entries, from);
            }
            for (int i = 0; i < num_entries; i++) {
                uint8_t dest = payload[i * 2];
                uint8_t cost = payload[i * 2 + 1];

                if (debug_mode)
                    printf("[TRACE] UPDATE entry %d: dest=%d cost=%d\n", i, dest, cost);

                if (dest == 0 || dest > 254 || dest == MY_MIP)
                    continue;

                // Ignorer poisoned reverse
                if (cost == 255) {
                    if (debug_mode)
                        printf("[ROUTINGD] Ignorerer poisoned reverse for dest=%d fra %d\n",
                            dest, from);
                    continue;
                }

                // Kostnaden via denne naboen (1 ekstra hopp)
                uint8_t new_cost = (cost >= 254) ? 255 : cost + 1;

                // Finn eksisterende rute
                int id = get_route(dest);

                // Hvis vi ikke har rute, eller denne nye veien er bedre — oppdater
                if (id < 0 || new_cost < routing_table[id].cost || routing_table[id].next_hop == from) {
                    if (debug_mode)
                        printf("[TRACE] Oppdaterer rute: dest=%d via=%d cost=%d\n",
                            dest, from, new_cost);
                    update_or_insert_neighbor(dest, from, new_cost);
                } else if (debug_mode) {
                    printf("[TRACE] Beholder eksisterende rute til dest=%d (bedre eller lik)\n", dest);
                }
            }

            break;
        }
        default: {
            printf("[ROUTINGD] Ukjent meldingstype 0x%02X fra %d\n", msg_type, from);
            break;
        }

    }
}

void broadcast_update(void) {
    // Tell antall gyldige naboer først
    int neighbor_count = 0;
    for (int n = 0; n < MAX_NEIGHBORS; n++) {
        if (neighbors[n].valid)
            neighbor_count++;
    }

    for (int n = 0; n < MAX_NEIGHBORS; n++) {
        if (!neighbors[n].valid) continue;

        uint8_t neighbor_addr = neighbors[n].mip;

        uint8_t buf[256];
        size_t pos = 1; // reserver plass til RT_MSG_UPDATE først

        for (int i = 0; i < MAX_ROUTES; i++) {
            if (!routing_table[i].valid) continue;

            buf[pos++] = routing_table[i].dest;
            uint8_t advertised_cost = routing_table[i].cost;
            // Poison Reverse hvis:
            //  - vi har mer enn én nabo (ellers vil single-link nett stoppe)
            //  - ruten ble lært VIA denne naboen
            //  - destinasjonen ikke ER naboen selv
            //  - ruten faktisk har en gyldig kost (ikke INF)
            if (neighbor_count > 1 &&
                routing_table[i].next_hop == neighbor_addr &&
                routing_table[i].dest != neighbor_addr &&
                routing_table[i].cost < 255) {

                advertised_cost = 255;  // poison reverse
            if (debug_mode) {
                printf("[ROUTINGD] Poisoned reverse: dest=%d via=%d (cost=%d -> 255)\n",
                    routing_table[i].dest, neighbor_addr, routing_table[i].cost);
            }
        }

            buf[pos++] = advertised_cost;
        }
        // Legg inn meldingstypen (RT_MSG_UPDATE) først
        buf[0] = RT_MSG_UPDATE;
        // Send unicast til denne naboen
        send_unix_message(neighbor_addr, 1, buf, pos);
        if (debug_mode) {
            printf("[ROUTINGD] Sent UPDATE to %d with %zu routes (%s)\n",
                   neighbor_addr,
                   (pos - 1) / 2,
                   (neighbor_count > 1 ? "poisoned reverse enabled" : "single neighbor, no poison"));
        }
    }
}

//metode som sender HELLO meldinger 
void hello(void){
    uint8_t msg = RT_MSG_HELLO;
    if (debug_mode){
        printf("[ROUTINGD] Sending HELLO broadcast (MIP=%d)\n", MY_MIP);
    }
    
    send_unix_message(255, 1, &msg, 1);
}



