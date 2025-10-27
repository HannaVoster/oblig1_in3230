/*
Denne filen inneholder funksjonene som håndterer selve routing-protokollen (DVR)
Her behandles meldinger som kommer fra MIP-daemonen, og oppdateringer sendes ut til naboer

Funksjonene gjør dette:
handle_route_request(): mottar ruteforespørsler (REQ) fra MIPd og finner riktig next hop

send_route_response(): sender ruteinformasjon (RSP) tilbake til MIPd

handle_incoming_message(): håndterer meldinger mellom routing-daemoner (HELLO og UPDATE)

broadcast_update(): sender hele routing-tabellen til alle naboer, med poison reverse

hello(): sender HELLO-meldinger for å oppdage naboer
*/

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#include "routing_protocol.h"
#include "routing_table.h"
#include "routing_socket.h"
#include "routingd.h"

// Håndterer en ROUTE REQUEST melding fra MIP-daemon
// Mottar forespørsel om rute til en gitt destinasjon og svarer med neste hopp (hvis veien er kjent)
void handle_route_request(int sock, uint8_t *msg, ssize_t length) {

    //avslutter hvis meldingen er for kort for formatet
    if (length < 6) { 
        fprintf(stderr, "[ROUTINGD] Ugyldig REQUEST (for kort)\n");
        return; 
    }

    uint8_t my_addr = msg[0]; // egen MIP
    uint8_t dest    = msg[5]; // destinasjonsadressen som skal slås opp

    if(debug_mode)("[ROUTINGD] handle_route_request: my=%d dest=%d\n", my_addr, dest);

    //standardverdi for ingen rute funnet, 255
    uint8_t next = INF_COST; 

    int id = get_route(dest);

    // Hvis gyldig rute ble funnet, hent ut neste hopp
    if (id >= 0 && routing_table[id].valid) {
        next = routing_table[id].next_hop;
    }

    // Sender ROUTE RESPONSE tilbake til MIP-daemonen med resultatet
    send_route_response(sock, my_addr, next);
}

// Sender en ROUTE RESPONSE tilbake til MIP-daemonen
// Svar på en tidligere forespørsel med informasjon om neste hopp til destinasjonen
void send_route_response(int sock, uint8_t my_address, uint8_t next){
    if(debug_mode) printf("[ROUTINGD] Sent RESPONSE: my=%d next_hop=%d)\n",my_address, next);
    
    uint8_t rsp[6] = { my_address, 0, 'R', 'S', 'P', next }; //etter format gitt av oppgaven

    // Sender meldingen over UNIX-socketen til MIP-daemonen
    if (write(sock, rsp, sizeof(rsp)) != sizeof(rsp)){
        perror("write response");
    } 
}

// Håndterer meldinger som kommer fra andre noder (via MIP-daemonen).
// Kan være enten HELLO-meldinger (nabo-oppdagelse) eller UPDATE-meldinger (ruteoppdateringer)
void handle_incoming_message(uint8_t from, uint8_t msg_type, const uint8_t *payload, size_t len){

    // lager en switch basert på meldingstype 
    switch(msg_type) {
        case RT_MSG_HELLO: {
            // Finn nabo i listen eller legg den til hvis den ikke finnes
            int id = find_or_add_neighbor(from);

            // Oppdaterer tidspunktet for når vi sist hørte fra denne naboen
            neighbors[id].last_hello_ms = now_ms();
            neighbors[id].valid = 1;

            // Oppdater routingtabellen: direkte nabo = cost 1
            update_or_insert_neighbor(from, from, 1);
            break;
        }

        case RT_MSG_UPDATE: {
            // Sørger for at avsenderen er registrert som nabo
            int id = find_or_add_neighbor(from);
            neighbors[id].last_hello_ms = now_ms();

            // En UPDATE må ha minst 2 byte (dest, cost)
            if (len < 2) break;

            if (len % 2 != 0) {
                len--; // dropp siste byte hvis den er ujevn
            }

            int num_entries = len / 2; // fordi payload = [dest, cost, dest, cost, ...]

            // Går gjennom hver oppføring i rutetabellen fra naboen
            for (int i = 0; i < num_entries; i++) {
                uint8_t dest = payload[i * 2];
                uint8_t cost = payload[i * 2 + 1];

                // Hopper over ugyldige eller irrelevante adresser
                if (dest == 0 || dest > 254 || dest == MY_MIP) continue;

                // Ignorer poisoned reverse, kostnad = 255 = uoppnåelig
                if (cost == INF_COST) continue;

                // Kostnaden via denne naboen (1 ekstra hopp), 255(inf) hvis cost er høy
                uint8_t new_cost = (cost >= 254) ? INF_COST : cost + 1;

                // Finn eventuell eksisterende rute
                int id = get_route(dest);

                // Hvis det ikke finnes en rute, eller denne nye veien er bedre — oppdater
                if (id < 0 || new_cost < routing_table[id].cost || routing_table[id].next_hop == from) {
                    if (debug_mode)
                        printf("[ROUTINGD][handle_incoming_message] Oppdaterer rute: dest=%d via=%d cost=%d\n",
                            dest, from, new_cost);
                    update_or_insert_neighbor(dest, from, new_cost);
                } 
            }
            break;
        }
        //ukjent meldingstype
        default: {
            printf("[ROUTINGD] Ukjent meldingstype 0x%02X fra %d\n", msg_type, from);
            break;
        }
    }
}
// Metode som Sender en UPDATE-melding til alle naboer.
// Hver UPDATE inneholder routing-tabellen slik at naboene kan oppdatere sine egne ruter
void broadcast_update(void) {

    // Tell antall gyldige naboer først
    int neighbor_count = 0;
    for (int n = 0; n < MAX_NEIGHBORS; n++) {
        if (neighbors[n].valid)
            neighbor_count++;
    }
    // Går igjennom alle naboene
    for (int n = 0; n < MAX_NEIGHBORS; n++) {
        if (!neighbors[n].valid) continue;

        uint8_t neighbor_addr = neighbors[n].mip; //henter ut naboens mip fra strukturen

        uint8_t buf[256]; //update melding buffer
        size_t pos = 1; // reserver plass til RT_MSG_UPDATE først, settes senere

        // Går igjennom routing tabellen
        for (int i = 0; i < MAX_ROUTES; i++) {
            if (!routing_table[i].valid) continue; //hopp over tomme ruter

            //Legger til destinasjonen i meldingen
            buf[pos++] = routing_table[i].dest; 

            //kostnad for destinasjonen
            uint8_t advertised_cost = routing_table[i].cost;

            // Poison Reverse HVIS:
            //  - vi har mer enn en nabo (ellers vil single-link nett stoppe)
            //  - ruten ble lært VIA denne naboen
            //  - destinasjonen ikke ER naboen selv
            //  - ruten faktisk har en gyldig kost (ikke INF)
            if (neighbor_count > 1 &&
                routing_table[i].next_hop == neighbor_addr &&
                routing_table[i].dest != neighbor_addr &&
                routing_table[i].cost < INF_COST) {

                advertised_cost = INF_COST;  // poison reverse
        }
            // Legger til kostnaden (enten vanlig eller "poisoned")
            buf[pos++] = advertised_cost;
        }
        // Legg inn meldingstypen (RT_MSG_UPDATE) først
        buf[0] = RT_MSG_UPDATE;

        // Sender meldingen direkte til denne naboen
        // ttl = 1, bare ett hopp
        send_unix_message(neighbor_addr, 1, buf, pos);
    }
}

// Enkel hjelpemetode som sender HELLO meldinger, kalles periodisk fra main i routingd.c
void hello(void){
    uint8_t msg = RT_MSG_HELLO;
    
    send_unix_message(INF_COST, 1, &msg, 1);
}



