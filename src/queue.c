/*
Denne filen håndterer mellomlagring av meldinger som ikke kan sendes umiddelbart fordi nødvendig informasjon mangler
(når MIP-adressen til mottakeren ennå ikke er kjent via ARP eller routing)

Filen definerer to hovedkøer:
    pending_queue: Meldinger som venter på en ARP-respons (MAC-adressen til mottaker er ukjent)
    route_wait_queue: Meldinger som venter på routinginformasjon (neste hopp er ukjent)

*/
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
    // Går gjennom hele pending-køen for å finne en ledig plass
    for (int i = 0; i < MAX_PENDING; i++) {
        if (!pending_queue[i].valid) {

            // Fyller inn metadata om meldingen
            pending_queue[i].ultimate_dest = ultimate_dest;
            pending_queue[i].next = next_hop;
            pending_queue[i].src = src;
            pending_queue[i].ttl = ttl;
            pending_queue[i].sdu_type = sdu_type;
            pending_queue[i].length = length_bytes;
            pending_queue[i].valid = 1;

            // Hvis det finnes faktisk data (payload) — alloker plass og kopier den inn
            if (length_bytes > 0) {
                pending_queue[i].payload = malloc(length_bytes);
                if (!pending_queue[i].payload) {
                    perror("malloc queue_message");
                    exit(EXIT_FAILURE);
                }
                memcpy(pending_queue[i].payload, data, length_bytes); // kopier inn selve meldingen
            } else {
                pending_queue[i].payload = NULL; // ingen data å lagre
            }

            if (debug_mode) {
                printf("[DEBUG][QUEUE] Lagret melding: dest=%d next=%d src=%d ttl=%d "
                       "type=%d len=%zu\n",
                       ultimate_dest, next_hop, src, ttl, sdu_type, length_bytes);
            }
            return;
        }
    }
    printf("[QUEUE] Kø full kunne ikke legge til melding for dest=%d\n", ultimate_dest);
}

/*
Sender meldinger som ligger i pending-køen for en gitt MIP-adresse
Alle meldinger i køen som er adressert til den MIP-adressen pakkes på nytt som en MIP PDU og sendes
fjerner deretter køelementet fra den globale køen

tar inn raw socket for å sende i send_pdu og adresser for å vite hvem som skal få
og hvem som sender
*/
void send_pending_messages(int raw_sock, uint8_t next_hop,
                           unsigned char *mac, int if_index)
{
    // Går gjennom hele køen for å se om det ligger noen meldinger som venter på denne mottakeren (next_hop)
    for (int i = 0; i < MAX_PENDING; i++) {

        // Sjekker om køplassen er gyldig og om den matcher riktig neste hopp
        if (pending_queue[i].valid && pending_queue[i].next == next_hop) {

            // Hvis lengden eller payload mangler, er oppføringen ødelagt, sletter den og hopper videre
            if (pending_queue[i].length == 0 || pending_queue[i].payload == NULL) {
                printf("[ERROR][QUEUE] Tom eller ugyldig oppføring i kø for next=%d\n", next_hop);
                pending_queue[i].valid = 0;
                continue;
            }

            // Bygg MIP-PDU med ultimate_dest, nå som man vet mac kan den sendes
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

            //kaller på send_pdu() som sender pakken ut på nettverkskortet
            int sent = send_pdu(raw_sock, pdu, pdu_len, mac, if_index); 

            // Frigjør minne for både PDU og lagret payload etter at den er sendt
            free(pdu);
            free(pending_queue[i].payload);

            // Markerer køplassen som tom igjen
            pending_queue[i].valid = 0;
            pending_queue[i].payload = NULL;

            printf("[QUEUE] Sendte pending melding til next_hop=%d (ultimate_dest=%d)\n",
                   next_hop, pending_queue[i].ultimate_dest);
        }
    }
}

// Bygger og sender en route request til routing deamon
// brukes for forwarding av forward_packet i raw_handler.c
void send_route_request(int routing_fd, uint8_t my_addr, uint8_t dest) {
    uint8_t req[6] = { my_addr, 0, 'R', 'E', 'Q', dest }; //format gitt av oppgaven

    if (write(routing_fd, req, sizeof(req)) != sizeof(req))
        perror("[ERROR][MIPD] write route request");
    else
        printf("[MIPD][ROUTING] Sent ROUTE REQUEST for dest=%d\n", dest);
}

// Metode som legger en melding i route_wait_queue mens deamonen venter på at routingd skal svare med neste hopp (RSP)
// Brukes av forward_packet i raw_handler.c
void queue_routing_message(uint8_t ultimate_dest, uint8_t src, uint8_t ttl,
                           uint8_t sdu_type, const uint8_t *sdu, size_t sdu_len) {
    
    // Går gjennom hele route_wait_queue for å finne en ledig plass
    for (int i = 0; i < MAX_ROUTE_WAIT; i++) {
        if (!route_wait_queue[i].valid) {

            // Nullstiller og setter metadata
            route_wait_queue[i].ultimate_dest = ultimate_dest; // endelig destinasjon
            route_wait_queue[i].src = src;                     // hvem som sendte
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
                route_wait_queue[i].sdu = NULL; //ingen payload
            }

            if(debug_mode) printf("[QUEUE][ROUTING] Meldingen for dest %d lagt i route_wait_queue (slot=%d)\n",
                   ultimate_dest, i);

            return;
        }
    }
    printf("[WARNING] route_wait_queue is full, dropping packet (dest=%d)\n", ultimate_dest);
}

//slett

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
