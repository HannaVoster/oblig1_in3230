
#include <stdio.h>      
#include <stdlib.h>     
#include <stdint.h>      
#include <string.h>      
#include <unistd.h>     

#include "mipd.h"      
#include "pdu.h"       
#include "iface.h"      
#include "queue.h"
#include "arp.h"

route_wait route_wait_queue[MAX_ROUTE_WAIT];
pending_entry pending_queue[MAX_PENDING];

/*
Legg melding i pending-kø dersom mottakers addresse er ukjent
 - venter på å sende PING uten arp resp
meldingene lagres til ARP response kommer og kan sendes via send_pending_message

pending_queue er en global kø med pending_entries og feltene settes av parameterene funskjonen tar
*/
void queue_message(uint8_t ultimate_dest, uint8_t next_hop,
                   uint8_t src, uint8_t ttl,
                   uint8_t sdu_type, uint8_t *data, size_t length_bytes)
{
    for (int i = 0; i < MAX_PENDING; i++) {
        if (!pending_queue[i].valid) {
            pending_queue[i].ultimate_dest = ultimate_dest;
            pending_queue[i].next = next_hop;
            pending_queue[i].src = src;
            pending_queue[i].ttl = ttl;
            pending_queue[i].sdu_type = sdu_type;
            pending_queue[i].length = length_bytes;
            pending_queue[i].valid = 1;

            if (length_bytes > 0) {
                pending_queue[i].payload = malloc(length_bytes);
                if (!pending_queue[i].payload) {
                    perror("malloc queue_message");
                    exit(EXIT_FAILURE);
                }
                memcpy(pending_queue[i].payload, data, length_bytes);
            } else {
                pending_queue[i].payload = NULL;
            }

            if (debug_mode) {
                printf("[DEBUG][QUEUE] Lagret melding: dest=%d next=%d src=%d ttl=%d "
                       "type=%d len=%zu\n",
                       ultimate_dest, next_hop, src, ttl, sdu_type, length_bytes);
            }
            return;
        }
    }

    printf("[QUEUE] Kø full – kunne ikke legge til melding for dest=%d\n", ultimate_dest);
}



/*
Sender meldinger som ligger i pending-køen for en gitt MIP-adresse
Alle meldinger i køen som er adressert til den MIP-adressen pakkes på nytt som en MIP PDU og sendes
fjerner deretter køelementet fra den globale køen


tar inn raw socket for å sende i send_pdu of adresse for å vite hvem som skal få
og hvem som sender
*/
void send_pending_messages(int raw_sock, uint8_t next_hop,
                           unsigned char *mac, int if_index)
{
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending_queue[i].valid && pending_queue[i].next == next_hop) {

            if (pending_queue[i].length == 0 || pending_queue[i].payload == NULL) {
                printf("[ERROR][QUEUE] Tom eller ugyldig oppføring i kø for next=%d\n", next_hop);
                pending_queue[i].valid = 0;
                continue;
            }

            if (debug_mode) {
                printf("[DEBUG][QUEUE] Skal sende pending pakke: "
                       "slot=%d dest=%d next=%d src=%d ttl=%d type=%d len=%zu\n",
                       i,
                       pending_queue[i].ultimate_dest,
                       pending_queue[i].next,
                       pending_queue[i].src,
                       pending_queue[i].ttl,
                       pending_queue[i].sdu_type,
                       pending_queue[i].length);
            }

            // Bygg MIP-PDU med ultimate_dest
            size_t pdu_len;
            uint8_t *pdu = mip_build_pdu(
                pending_queue[i].ultimate_dest, // den egentlige destinasjonen
                pending_queue[i].src,           // avsender
                pending_queue[i].ttl,           // behold TTL fra opprinnelig pakke
                pending_queue[i].sdu_type,
                pending_queue[i].payload,
                pending_queue[i].length,
                &pdu_len
            );
          
            printf("[DEBUG][QUEUE] Sender pending → next_hop=%d via if_index=%d\n", next_hop, if_index);
            int sent = send_pdu(raw_sock, pdu, pdu_len, mac, if_index);
            printf("[DEBUG][QUEUE] send_pdu returnerte %d\n", sent);


            free(pdu);
            free(pending_queue[i].payload);
            pending_queue[i].valid = 0;
            pending_queue[i].payload = NULL;

            printf("[QUEUE] Sendte pending melding til next_hop=%d (ultimate_dest=%d)\n",
                   next_hop, pending_queue[i].ultimate_dest);
        }
    }

    if (debug_mode)
        print_pending_queue();
}


void send_route_request(int routing_fd, uint8_t my_addr, uint8_t dest) {
    uint8_t req[6] = { my_addr, 0, 'R', 'E', 'Q', dest };
    if (write(routing_fd, req, sizeof(req)) != sizeof(req))
        perror("[ERROR][MIPD] write route request");
    else
        printf("[MIPD][ROUTING] Sent ROUTE REQUEST for dest=%d\n", dest);
}

void queue_routing_message(uint8_t ultimate_dest, uint8_t src, uint8_t ttl,
                           uint8_t sdu_type, const uint8_t *sdu, size_t sdu_len) {

    for (int i = 0; i < MAX_ROUTE_WAIT; i++) {
        if (!route_wait_queue[i].valid) {
            if (debug_mode) {
                printf("[DEBUG] queue_routing_message: dest=%d type=%d len=%zu bytes\n\n",
                       ultimate_dest, sdu_type, sdu_len);
            }

            // Nullstill og sett metadata
            route_wait_queue[i].ultimate_dest = ultimate_dest;
            route_wait_queue[i].src = src;
            route_wait_queue[i].ttl = ttl;
            route_wait_queue[i].sdu_type = sdu_type;        
            route_wait_queue[i].sdu_len = sdu_len;
            route_wait_queue[i].valid = 1;
            route_wait_queue[i].next = 0; //vi vet ikke enda

            // Alloker minne kun hvis data faktisk finnes
            if (sdu_len > 0) {
                route_wait_queue[i].sdu = malloc(sdu_len);
                if (!route_wait_queue[i].sdu) {
                    perror("[ERROR] malloc queue_message");
                    exit(EXIT_FAILURE);
                }
                //kopierer payload
                memcpy(route_wait_queue[i].sdu, sdu, sdu_len);
            }
            else{
                route_wait_queue[i].sdu = NULL;
            }

             printf("[QUEUE][ROUTING] Meldingen for dest %d lagt i route_wait_queue (slot=%d)\n",
                   ultimate_dest, i);

            return;
        }
    }
    printf("[WARNING] route_wait_queue is full, dropping packet (dest=%d)\n", ultimate_dest);
}


void print_pending_queue(void) {
    int empty = 1;
    printf("Status:\n");
    for (int i = 0; i < MAX_PENDING; i++) {
        if (pending_queue[i].valid) {
            printf("  slot=%d → dest=%d len=%zu type=%d\n",
                   i,
                   pending_queue[i].ultimate_dest,
                   pending_queue[i].length,
                   pending_queue[i].sdu_type);
            empty = 0;
        }
    }
    if(empty){
        printf("EMPTY PENDING QUEUE\n");
    }
}
