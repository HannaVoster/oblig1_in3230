
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

/*
Legg melding i pending-kø dersom mottakers addresse er ukjent
 - venter på å sende PING uten arp resp
meldingene lagres til ARP response kommer og kan sendes via send_pending_message

pending_queue er en global kø med pending_entries og feltene settes av parameterene funskjonen tar
*/
void queue_message(uint8_t dest_mip, uint8_t sdu_type,
                   uint8_t *data, size_t length_bytes) {

    for (int i = 0; i < MAX_PENDING; i++) {
        if (!pending_queue[i].valid) {
            if (debug_mode) {
                printf("[DEBUG][QUEUE] queue_message: dest=%d type=%d len=%zu bytes\n",
                       dest_mip, sdu_type, length_bytes);
            }

            // Nullstill og sett metadata
            pending_queue[i].payload = NULL;
            pending_queue[i].length  = length_bytes;
            pending_queue[i].dest_mip = dest_mip;
            pending_queue[i].sdu_type = sdu_type;
            pending_queue[i].valid    = 1;

            // Alloker minne kun hvis data faktisk finnes
            if (length_bytes > 0) {
                pending_queue[i].payload = malloc(length_bytes);
                if (!pending_queue[i].payload) {
                    perror("[ERROR] malloc queue_message");
                    exit(EXIT_FAILURE);
                }
                //kopierer payload
                memcpy(pending_queue[i].payload, data, length_bytes);
            }

            if (debug_mode) {
                printf("[DEBUG][QUEUE] queue_message saved: len=%zu at slot=%d",
                       pending_queue[i].length, i);
                if (length_bytes > 0)
                    printf(", payload[0]=0x%02X", pending_queue[i].payload[0]);
                printf("\n\n");
            }

            printf("[QUEUE] Meldingen for MIP %d lagt i kø\n\n", dest_mip);
            return;
        }
    }
    printf("[QUEUE] Kø full, kunne ikke legge til melding for MIP %d\n\n", dest_mip);
}


/*
Sender meldinger som ligger i pending-køen for en gitt MIP-adresse
Alle meldinger i køen som er adressert til den MIP-adressen pakkes på nytt som en MIP PDU og sendes
fjerner deretter køelementet fra den globale køen


tar inn raw socket for å sende i send_pdu of adresse for å vite hvem som skal få
og hvem som sender
*/
void send_pending_messages(int raw_sock, uint8_t mip_addr,
                           unsigned char *mac, int my_mip_address) {

    for (int i = 0; i < MAX_PENDING; i++) {
        // Se etter meldinger i køen for denne destinasjons-MIPen
        if (pending_queue[i].valid && pending_queue[i].dest_mip == mip_addr) {
            
            // Sjekk at køelementet er gyldig (payload finnes og lengden > 0)
            if (pending_queue[i].length == 0 || pending_queue[i].payload == NULL) {
                printf("[ERROR][QUEUE] Pending entry corrupt: len=0 eller payload=NULL for MIP %d\n\n",
                       pending_queue[i].dest_mip);
                pending_queue[i].valid = 0;
                continue;
            }

            if (debug_mode) {
                printf("[DEBUG][QUEUE] send_pending_messages using slot=%d "
                       "len=%zu type=%d dest=%d\n\n",
                       i,
                       pending_queue[i].length,
                       pending_queue[i].sdu_type,
                       pending_queue[i].dest_mip);
            }

            // Bygg PDU på nytt fra payload
            size_t pdu_len;
            uint8_t *pdu = mip_build_pdu(
                pending_queue[i].dest_mip,    // dest
                my_mip_address,               // src
                4,                            // TTL
                pending_queue[i].sdu_type,    // SDU type
                pending_queue[i].payload,     // SDU data
                pending_queue[i].length,      // SDU lengde i bytes
                &pdu_len
            );

            send_pdu(raw_sock, pdu, pdu_len, mac);

            free(pdu);

            // Invalider køelementet FØR payloaden frigis
            pending_queue[i].valid = 0;
            free(pending_queue[i].payload);
            pending_queue[i].payload = NULL;

            printf("[QUEUE] Sent melding til MIP %d, sdu type: %d\n\n", mip_addr, pending_queue[i].sdu_type);

            if (debug_mode) {
                printf("[DEBUG][QUEUE] Updated ARP CASHE after send_pending_messages():\n");
                print_arp_cache();
            }
        }
    }
}

void send_route_request(int routing_fd, uint8_t my_addr, uint8_t dest) {
    uint8_t req[6] = { my_addr, 0, 'R', 'E', 'Q', dest };
    if (write(routing_fd, req, sizeof(req)) != sizeof(req))
        perror("[ERROR][MIPD] write route request");
    else
        printf("[MIPD][ROUTING] Sent ROUTE REQUEST for dest=%d\n", dest);
}

void queue_routing_message(uint8_t dest, uint8_t src, uint8_t ttl,
                           uint8_t sdu_type, const uint8_t *sdu, size_t sdu_len) {

    for (int i = 0; i < MAX_ROUTE_WAIT; i++) {
        if (!route_wait_queue[i].valid) {
            if (debug_mode) {
                printf("[DEBUG] queue_routing_message: dest=%d type=%d len=%zu bytes\n\n",
                       dest, sdu_type, sdu_len);
            }

            // Nullstill og sett metadata
            route_wait_queue[i].dest = dest;
            route_wait_queue[i].src = src;
            route_wait_queue[i].ttl = ttl;
            route_wait_queue[i].sdu_type = sdu_type;
            //route_wait_queue[i].sdu = malloc(sdu_len);
            
            route_wait_queue[i].sdu_len = sdu_len;
            route_wait_queue[i].valid = 1;

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

            if (debug_mode) {
                printf("[DEBUG][QUEUE][ROUTING] routing queue_message saved: len=%zu at slot=%d",
                       route_wait_queue[i].sdu_len, i);
            }

            printf("[QUEUE][ROUTING] Meldingen for dest %d lagt i kø\n", dest);

            return;
        }
    }
    printf("[WARNING] route_wait_queue is full, dropping packet (dest=%d)\n", dest);
}