
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "mipd.h"
#include "pdu.h"
#include "iface.h"
#include "queue.h"
#include "arp.h"


/*
- handle_raw_packet
mottar råpakker fra nettverkskortet via raw_sock. 
Den sjekker at det faktisk er en MIP-pakke, pakker opp headeren, og håndterer innholdet avhengig av SDU-typen

PING svarer med en PONG tilbake.
PONG skriver svaret tilbake til den siste UNIX-klienten.
ARP-REQUEST svarer med en ARP-RESPONSE hvis forespørselen gjelder egen MIP-adresse.
ARP-RESPONSE oppdaterer ARP-cachen og sender eventuelle ventende meldinger til den adressen

raw_sock: rå-socketen vi lytter på.
my_mip_address: egen MIP-adresse
                brukes til å avgjøre om en pakke er til seg selv og til å fylle ut svar

last_unix_client_fd – kan lukkes eller skrives til når en PONG mottas
arp_cache – oppdateres når ARP-RESP mottas (gjennom arp_update)
pending_queue – tømmes når ventende meldinger sendes etter en ARP-RESP (send_pending_message)
Bruker debug_mode for logging
*/
void handle_raw_packet(int raw_sock, int my_mip_address) {
    uint8_t buffer[2000]; // Buffer for å lagre innkommende råpakke
    struct sockaddr_ll src_addr; // Struktur for å lagre avsenderadresse
    // iovec beskriver hvor data skal plasseres når vi mottar meldingen
    struct iovec iov = { buffer, sizeof(buffer) };
    // msghdr brukes av recvmsg() for å motta både data og metadata
    struct msghdr msg = { .msg_name = &src_addr, .msg_namelen = sizeof(src_addr),
                          .msg_iov = &iov, .msg_iovlen = 1 };
    int len = recvmsg(raw_sock, &msg, 0);

    if(debug_mode){
        printf("[DEBUG][RAW] handle_raw_packet CALLED, len=%d\n", len);
    }

    if (len < (int)sizeof(struct ethhdr)) return; // må minst ha Ethernet-header

    // Tolker starten av bufferet som en Ethernet-header
    struct ethhdr *eh = (struct ethhdr *)buffer;

    uint16_t proto = htons(eh->h_proto);

    int if_index = src_addr.sll_ifindex;
    char if_name[IFNAMSIZ];
    if_indextoname(if_index, if_name); // oversett til navn (f.eks. "A-eth0")

    if (debug_mode) {
        printf("[DEBUG][RAW] Packet received on interface %s (index=%d)\n",
               if_name, if_index);
        printf("[DEBUG][RAW] RX dst=%02X:%02X:%02X:%02X:%02X:%02X "
               "src=%02X:%02X:%02X:%02X:%02X:%02X proto=0x%04X\n",
               eh->h_dest[0], eh->h_dest[1], eh->h_dest[2],
               eh->h_dest[3], eh->h_dest[4], eh->h_dest[5],
               eh->h_source[0], eh->h_source[1], eh->h_source[2],
               eh->h_source[3], eh->h_source[4], eh->h_source[5],
               proto);
    }

    if (proto != ETH_P_MIP) {
        printf("[ERROR][RAW] PROTO ER FEIL (ikke MIP)\n\n");
        return;
    }
        
    //mip pakken starter etter ethernet header
    const uint8_t *mip_start = buffer + sizeof(struct ethhdr);
    size_t mip_len = len - sizeof(struct ethhdr);

    uint8_t dest, src, ttl, sdu_type;
    const uint8_t *sdu;

    // Pakk ut og tolk MIP-headeren
    ssize_t sdu_len = mip_parse(mip_start, mip_len,
                                &dest, &src, &ttl,
                                &sdu_type, &sdu);
    if (sdu_len < 0) {
        printf("[ERROR][RAW] ugyldig MIP PDU (len=%d)\n", len);
        return;
    }

    if (dest != my_mip_address && dest != 255) { //255 = broadcast
        // ikke til meg og ikke broadcast - FORWARD PAKKEN  
        if (ttl <= 1) {
            if(debug_mode) printf("[DEBUG][FWD] Dropper pakke til %d (TTL utløpt)\n", dest);
            return;
        }
        //justerer ttl før den forwardes
        uint8_t ttl_new = ttl - 1;

        if (debug_mode) {
            printf("[DEBUG][RAW][FWD] Routing lookup: dest=%d, src=%d, ttl=%d→%d\n",
               dest, src, ttl, ttl_new);
        }

        queue_routing_message(dest, src, ttl_new, sdu_type, sdu, sdu_len);

        for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
            if (unix_clients[i].active && unix_clients[i].sdu_type == SDU_TYPE_ROUTING) {
                send_route_request(unix_clients[i].fd, my_mip_address, dest);
                break;
            }
        }
        if(debug_mode) printf("[DEBUG][RAW][FWD] Route request sendt til routingd, pakke lagret midlertidig.\n");
        return;
    }

    //setter opp en switch som håndterer de ulike sdu typene
    switch (sdu_type) {
        case SDU_TYPE_PING: {
            printf("[RAW] PING mottatt fra MIP %u\n\n", src);

            arp_update(src, eh->h_source); //lagrer avsender i ARP til senere

           for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
                if (unix_clients[i].active && unix_clients[i].sdu_type == SDU_TYPE_PONG) {
                    uint8_t reply[256];
                    reply[0] = src;   // avsender MIP
                    reply[1] = ttl;   // TTL
                    memcpy(&reply[2], sdu, sdu_len);
                    write(unix_clients[i].fd, reply, 2 + sdu_len);
                    if (debug_mode) {
                        printf("[DEBUG] Sent PING to UNIX app (src=%u ttl=%u len=%zd)\n",
                            src, ttl, sdu_len);
                    }
                    break;
                }
            }
            break;
        }

        case SDU_TYPE_PONG: {
            // Mottatt et PONG-svar fra en node vi tidligere sendte en PING til
            printf("[RAW] PONG mottatt fra MIP %u: %.*s\n\n",
                   src, (int)sdu_len, (char*)sdu);

            // Skriver svaret (payloaden) tilbake til UNIX-klienten som startet forespørselen
            // må finne hvilken unix klient
            for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
                if (unix_clients[i].active && unix_clients[i].sdu_type == SDU_TYPE_PING) {
                    uint8_t reply[256];
                    reply[0] = src;   // hvem meldingen kom fra
                    reply[1] = ttl;
                    memcpy(&reply[2], sdu, sdu_len);
                    write(unix_clients[i].fd, reply, 2 + sdu_len);
                    break;
                }
            }
            break;
        }

        case SDU_TYPE_ARP: {
            // arp meldinger, enten request eller response

            //payload må være stor nok til å inneholde en mip_arp_msg
            if (sdu_len < (ssize_t)sizeof(mip_arp_msg)) {
                printf("[ERROR] ARP SDU for kort (%zd bytes)\n\n", sdu_len);
                return;
            }

            //mip_arp_message definert i arp.h (type: reqest eller response, addresse og ev padding)
            //payloaden tolkes slik
            const mip_arp_msg *arp = (const mip_arp_msg*)sdu;

            if(debug_mode){
                printf("[DEBUG] ARP msg: type=%u mip_addr=%u (payload_len=%zd)\n\n",
                   arp->type, arp->mip_addr, sdu_len);
            }

            if (arp->type == 0x00 && arp->mip_addr == my_mip_address) {
                // Dette er en ARP request (0x00), og den spør etter nodens MIP-adresse
                // Da bygges en ARP response (0x01) med egen MIP-adresse
                printf("[RAW] ARP-REQ mottatt fra MIP %d\n\n", arp->mip_addr);
                mip_arp_msg resp = { .type = 0x01, .mip_addr = my_mip_address, .reserved = 0 };
                size_t pdu_len = 0;
                uint8_t *pdu = mip_build_pdu(
                    src, 
                    my_mip_address,
                    1,
                    SDU_TYPE_ARP,
                    (uint8_t*)&resp, 
                    sizeof(resp),
                    &pdu_len
                );
                send_pdu(raw_sock, pdu, pdu_len, eh->h_source);
                free(pdu);
            }
            else if (arp->type == 0x01) {
                // Dette er en ARP response (0x01)
                //oppdatterer arp med mac adresse og mip
                printf("[RAW] ARP-RESP mottatt for MIP %d\n\n", arp->mip_addr);
                arp_update(arp->mip_addr, eh->h_source);

                if (debug_mode){
                    print_arp_cache();
                }

                //har fått response, så kan sjekke om det er noen pakker som venter på å bli sent
                //og som venter på denne aaddressen
                send_pending_messages(raw_sock, arp->mip_addr, eh->h_source, my_mip_address);
            }
            break;
        }

        default:
            printf("[RAW] Ukjent SDU-type: %u\n\n", sdu_type);
            break;
    }
}