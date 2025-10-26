// ROUTING TABLE HANDLER
// Håndterer oppdatering, oppslag og utskrift av rutetabellen og naboer.

#include <stdio.h>
#include <stdint.h>

#include "routing_table.h"
#include "routingd.h"

// Oppdaterer en eksisterende rute, eller legger den til hvis den ikke finnes
// Brukes både når nye naboer oppdages og når det mottas oppdateringer fra andre noder
int update_or_insert_neighbor(uint8_t dest, uint8_t next_hop, uint8_t cost) {

    // Hvis destinasjonen er meg selv, lag en "egen rute" med kost 0
    if (dest == MY_MIP) {
        int id = get_route(dest);
        // Finn en ledig plass hvis den ikke allerede finnes
        if (id < 0) {
            for (int i = 0; i < MAX_ROUTES; i++) {
                if (!routing_table[i].valid) {
                    id = i;
                    break;
                }
            }
        }
        // Opprett eller oppdater selv-ruten
        if (id >= 0) {
            routing_table[id].valid = 1;
            routing_table[id].dest = MY_MIP;
            routing_table[id].next_hop = MY_MIP;
            routing_table[id].cost = 0;
            routing_table[id].updated_ms = now_ms();

            if (debug_mode)
                printf("[ROUTINGD] Route self: dest=%d via=%d cost=%d (slot=%d)\n",
                    MY_MIP, MY_MIP, 0, id);
        }
        return id;
    }
    // // Kostnad 0 gir ingen mening, justerer til 1
    // if (cost == 0) {
    //     cost = 1;
    //     if (debug_mode)
    //         printf("[ROUTINGD] Justerte 0-cost til 1 for dest=%d via=%d\n",
    //                dest, next_hop);
    // }

    int id = get_route(dest);
    if (id < 0) { // ingen rute – lag ny
        for (int i = 0; i < MAX_ROUTES; i++) {
            if (!routing_table[i].valid) {
                id = i;
                break;
            }
        }
        if (id < 0) return -1; // ingen plass

        routing_table[id].valid = 1;
        routing_table[id].dest = dest;
        routing_table[id].next_hop = next_hop;
        routing_table[id].cost = cost;
        routing_table[id].updated_ms = now_ms();

        if (debug_mode)
            printf("[ROUTINGD] NEW route: dest=%d via=%d cost=%d (slot=%d)\n",
                   dest, next_hop, cost, id);

        return id;
    }
    // sjekk om verdier faktisk endres
    uint8_t old_next_hop = routing_table[id].next_hop;
    uint8_t old_cost = routing_table[id].cost;

    if (old_next_hop != next_hop || old_cost != cost) {
        routing_table[id].next_hop = next_hop;
        routing_table[id].cost = cost;
        routing_table[id].updated_ms = now_ms();

        if (debug_mode) {
            printf("[ROUTINGD] UPDATED route: dest=%d via=%d→%d cost=%d→%d (slot=%d)\n",
                   dest, old_next_hop, next_hop, old_cost, cost, id);
            fflush(stdout);
        }
    } else {
        // Bare oppdater timestamp (naboen lever, men ingen endring)
        routing_table[id].updated_ms = now_ms();
    }

    return id;
}

//metode til å finne en lagret rute
//går igjennom routing_table og returnerer indexen til dest hvis dest finnes
//p den måten kan deamonen sjekke at en rute er der før den sender en response om next hop
//hvis dest ikke funnes, returneres -1 . ingen repsonse sendes
int get_route(uint8_t dest) {
    for (int i = 0; i < MAX_ROUTES; i++) {
        // if (routing_table[i].valid) {
        //     printf("[ROUTINGD] Route entry %d: dest=%d via=%d cost=%d\n",
        //             i, routing_table[i].dest,
        //             routing_table[i].next_hop,
        //             routing_table[i].cost);
        // }
        if (routing_table[i].valid && routing_table[i].dest == dest){
            return i;
        }
    }
    return -1; //ingen rute
}


//metode til å oppdage naboer med HELLO
//leter etter en nabo med en gitt mip addresse, og returnerer naboens index i nabolisten
//hvis naboen ikke finnes, sjekkes nabolisten og noden legges til som en ny entry
//håndterer også tilfelle der tabellen er full og returnerer -1
int find_or_add_neighbor(uint8_t mip){
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (neighbors[i].mip == mip) {
            return i;
        }
    }
    //hvis vi kommer hit - ikke funnet - legg til på ledig plass
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if(!neighbors[i].valid) {
            neighbors[i].mip = mip;
            neighbors[i].valid = 1;
            neighbors[i].last_hello_ms = now_ms(); //noterer tiden naboen ble registrert
            return i;
        }
    }

    return -1;
}

void print_routing_table(void) {
    printf("=== ROUTING TABLE for MIP %d ===\n", MY_MIP);
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (routing_table[i].valid) {
            printf("  dest=%d via=%d cost=%d (slot=%d)\n",
                   routing_table[i].dest,
                   routing_table[i].next_hop,
                   routing_table[i].cost,
                   i);
        }
    }
    printf("===============================\n");
}
