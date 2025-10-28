
/*
Denne filen håndterer oppdatering, oppslag og utskrift av rutetabellen og naboer

Funksjonene gjør dette:
update_or_insert_neighbor(): legger til eller oppdaterer en rute i rutetabellen

get_route(): finner og returnerer indeksen til en rute basert på destinasjonsadressen

find_or_add_neighbor(): finner en kjent nabo eller legger den til hvis den er ny

print_routing_table(): skriver ut rutetabellen for debugging og oversikt
*/

#include <stdio.h>
#include <stdint.h>

#include "routing_table.h"
#include "routingd.h"


/*
Oppdaterer en eksisterende rute, eller legger den til hvis den ikke finnes
Brukes både når nye naboer oppdages og når det mottas oppdateringer fra andre noder

Hvis destinasjonen er en selv - legg inn "selv-rute" med kostnad 0
Hvis ruten ikke finnes - opprett ny
Hvis den finnes - oppdater bare hvis noe faktisk har endret seg
Ellers - bare oppdater tidspunktet (naboen er fortsatt aktiv)
*/
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

    // Sjekker om vi allerede har en rute til denne destinasjonen
    int id = get_route(dest);

    // Ingen eksisterende rute, opprett en ny
    if (id < 0) { 
        for (int i = 0; i < MAX_ROUTES; i++) {
            if (!routing_table[i].valid) {
                id = i;
                break;
            }
        }
        if (id < 0) return -1; // ingen plass i tabellen

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
    // Hvis ruten finnes, sjekker om next hop eller kostnad har endret seg
    uint8_t old_next_hop = routing_table[id].next_hop;
    uint8_t old_cost = routing_table[id].cost;

    if (old_next_hop != next_hop || old_cost != cost) {
        if (cost >= INF_COST) {
            routing_table[id].valid = 0;
            routing_table[id].cost = INF_COST;
            if (debug_mode)
                printf("[ROUTINGD] Route to %d invalidated (via %d, cost=INF)\n", dest, next_hop);
        } else {
            routing_table[id].valid = 1;
            routing_table[id].next_hop = next_hop;
            routing_table[id].cost = cost;
            routing_table[id].updated_ms = now_ms();

            if (debug_mode) {
                printf("[ROUTINGD] UPDATED route: dest=%d via=%d→%d cost=%d→%d (slot=%d)\n",
                    dest, old_next_hop, next_hop, old_cost, cost, id);
            }
        } 
    }
    return id;
}

/*
Sjekker om det finnes en rute til en gitt destinasjon
Går gjennom routing_tabellen og returnerer indeksen hvis destinasjonen finnes
Brukes for å sjekke om en rute allerede er lagret før man sender svar eller oppdaterer den
Returnerer -1 hvis ingen rute finnes
 */
int get_route(uint8_t dest) {
    for (int i = 0; i < MAX_ROUTES; i++) {
        if (routing_table[i].valid && routing_table[i].dest == dest){
            return i;
        }
    }
    return -1; 
}


/*
Metode til å oppdage naboer med HELLO
Leter etter en nabo med en gitt mip addresse, og returnerer naboens index i nabolisten
Hvis naboen ikke finnes, sjekkes nabolisten og noden legges til som en ny entry
Håndterer også tilfelle der tabellen er full og returnerer -1
*/
int find_or_add_neighbor(uint8_t mip){
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (neighbors[i].mip == mip) {
            return i;
        }
    }
    //ikke funnet - legg til på ledig plass
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

//Hjelpemetode for debugging, kalles hver 15 s fra main i routingd.c
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
