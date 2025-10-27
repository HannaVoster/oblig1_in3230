/*

 Hovedansvar:
 - Motta rå Ethernet-pakker via raw socket
 - Parse MIP-protokollen (header + payload)
 - Route pakkene videre basert på SDU-type (PING, PONG, ARP, ROUTING)
 - Samhandle med routingd via UNIX-sockets
 - Utføre forwarding og ARP-respons ved behov

*/      

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
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
#include "raw_handler.h"
#include "unix.h"


/*
Mottar rå Ethernet-pakker fra nettverkskortet via raw_sock

Sjekker at det faktisk er en MIP-pakke, pakker ut headeren, og håndterer innholdet basert på SDU-typen:
    -PING: videresendes eller leveres lokalt, og besvares med en PONG
    -PONG: skrives tilbake til siste UNIX-klient (ping_client)
    -ARP-REQUEST: besvares med en ARP-RESPONSE hvis den gjelder egen MIP-adresse
    -ARP-RESPONSE: oppdaterer ARP-cachen og sender eventuelle ventende meldinger
    -ROUTING: sendes videre til routing-daemonen via UNIX-socket

Parametre:
raw_sock – rå socket som lyttes på (mottar pakker fra nettverkskortet)
my_mip_address – egen MIP-adresse (brukes for å se om pakken er til en selv)
*/

void handle_raw_packet(int raw_sock, int my_mip_address) {
    uint8_t buffer[2000]; // Buffer for å lagre innkommende råpakke

    struct sockaddr_ll src_addr; // Lagrer metadata om avsender, mac og interface

    // iovec beskriver hvor data skal plasseres når meldingen mottas
    struct iovec iov = { buffer, sizeof(buffer) };

    // msghdr beskriver hele meldingen (inkludert metadata)
    struct msghdr msg = { 
        .msg_name = &src_addr,
        .msg_namelen = sizeof(src_addr),
        .msg_iov = &iov, 
        .msg_iovlen = 1 
    };

    printf("[RAW] Venter på pakke...\n");

    // Leser en pakke fra nettverksgrensesnittet
    int len = recvmsg(raw_sock, &msg, 0);

    printf("[RAW] Mottok %d bytes på ifindex=%d\n", len, src_addr.sll_ifindex);

    if (len < (int)sizeof(struct ethhdr)) return; // må være stor nok til å inneholde en Ethernet-header

    // Tolker starten av bufferet som en Ethernet-header
    struct ethhdr *eh = (struct ethhdr *)buffer;

    // Leser ut protokollfeltet (skal være MIP)
    uint16_t proto = htons(eh->h_proto);

    int if_index = src_addr.sll_ifindex;
    char if_name[IFNAMSIZ];
    if_indextoname(if_index, if_name); // oversett til navn (f.eks. "A-eth0")

    // Sjekker at pakken faktisk er av MIP-type
    if (proto != ETH_P_MIP) {
        printf("[ERROR][RAW] PROTO ER FEIL (ikke MIP)\n\n");
        return;
    }
    
    //Mip pakken starter etter ethernet header
    const uint8_t *mip_start = buffer + sizeof(struct ethhdr);
    size_t mip_len = len - sizeof(struct ethhdr);

    uint8_t dest, src, ttl, sdu_type;
    const uint8_t *payload;

    // Pakk ut og tolk MIP-headeren
    ssize_t length = mip_parse(mip_start, mip_len, &dest, &src, &ttl, &sdu_type, &payload);

    if (length < 0) {
        printf("[ERROR][RAW] ugyldig MIP PDU (len=%d)\n", len);
        return;
    }

    //setter opp en switch som håndterer nehandler pakken avhengig av pakkens SDU
    switch (sdu_type) {
        case SDU_TYPE_ROUTING: {
            // Routingmeldinger (HELLO / UPDATE) sendes opp til routingd
            handle_routing_message(src, payload, length);
            break;
        }

        case SDU_TYPE_PING: {
            // PING videresendes eller leveres lokalt
            handle_ping_message(my_mip_address, dest, src, ttl, payload, length, eh, src_addr.sll_ifindex);
            break;
        }

        case SDU_TYPE_PONG: {
            //PONG videresendes eller leveres opp til ping_client
            handle_pong_message(my_mip_address, dest, src, ttl, payload, length);
            break;
        }

        case SDU_TYPE_ARP: {
            // ARP meldinger håndteres (request/response)
            handle_arp_message(raw_sock, my_mip_address, payload, length, eh, src_addr.sll_ifindex, src);
            break;
        }
           
        default:
            printf("[RAW] Ukjent SDU-type: %u\n\n", sdu_type);
            break;
    }
}

// Håndterer routing-meldinger (HELLO og UPDATE) som kommer inn fra nettverket
// Sender dem videre til routing-daemonen via UNIX-socket
void handle_routing_message(uint8_t src, const uint8_t *payload, ssize_t length){
     uint8_t rt_type = payload[0]; // Første byte i payload angir routingmeldingen (HELLO eller UPDATE)

    if (debug_mode) {
        printf("[DEBUG][ROUTING] Mottatt SDU_TYPE_ROUTING fra %d, type=0x%02X\n", src, rt_type);
    }

    switch (rt_type) {
    case 0x01: // HELLO
    case 0x02: // UPDATE
    {
        // Bygg buffer for å sende OPP til routingd
        uint8_t up_buf[256];
        up_buf[0] = src; // legg inn hvem meldingen kom fra
        memcpy(&up_buf[1], payload, length);

        // Send via UNIX til routingd (din egen routingd-prosess)
        for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
            if (unix_clients[i].active &&
                unix_clients[i].sdu_type == SDU_TYPE_ROUTING) {

                write(unix_clients[i].fd, up_buf, length + 1);
                if (debug_mode)
                    printf("[DEBUG][ROUTING] Sendte HELLO/UPDATE opp til routingd (fra %d)\n", src);
                break;
            }
        }
        break;
    }

    default:
        // Ukjent routingtype (ignorer)
        if (debug_mode)
            printf("[DEBUG][ROUTING] Ukjent routing-type 0x%02X — ignorerer\n", rt_type);
        break;
    }
}

// Håndterer innkommende PING-meldinger
// Prøver først å forwarde hvis pakken ikke er til en selv
// Hvis den er til seg selv, leverer PING-en opp til UNIX-klienten
void handle_ping_message(int my_mip_address, uint8_t dest, uint8_t src, uint8_t ttl,
                         const uint8_t *payload, ssize_t length,
                         struct ethhdr *eh, int if_index)
{
    int fwd_result = forward_packet(my_mip_address, dest, src, ttl, SDU_TYPE_PING, payload, length);

    if (fwd_result != 0) {
        // 1 = forwarded, -1 = droppet
        return;
    }

    if(debug_mode) printf("[RAW] PING mottatt fra MIP %u\n\n", src);

    arp_update(src, eh->h_source, if_index); //lagrer avsender i ARP til senere

    for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
        if (unix_clients[i].active && unix_clients[i].sdu_type == SDU_TYPE_PONG) {
            uint8_t reply[256];
            reply[0] = src; // avsender MIP
            reply[1] = ttl; // TTL
            memcpy(&reply[2], payload, length);
            write(unix_clients[i].fd, reply, 2 + length);
            if (debug_mode) {
                printf("[DEBUG] Sent PING to UNIX app (src=%u ttl=%u len=%zd)\n",
                    src, ttl, length);
            }
            break;
        }
    }
}

// Håndterer mottatte PONG-meldinger.
// Forsøker først å forwarde pakken hvis den ikke er til meg eller broadcast.
// Hvis den er til meg, leveres den opp til UNIX-klienten (ping_client).
void handle_pong_message(int my_mip_address,
                         uint8_t dest, uint8_t src, uint8_t ttl,
                         const uint8_t *payload, ssize_t length)
{
    // Forsøk å forwarde pakken (bruker samme hjelpefunksjon som PING)
    int fwd_result = forward_packet(my_mip_address,
                                    dest, src, ttl,
                                    SDU_TYPE_PONG, payload, length);

    if (fwd_result != 0) {
        // 1 = forwarded, -1 = droppet → ferdig
        return;
    }
    // Til meg: lever opp til ping_client
    if (debug_mode) printf("[RAW] PONG mottatt fra MIP %u: %.*s\n\n",
           src, (int)length, (char*)payload);

    for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
        if (unix_clients[i].active &&
            unix_clients[i].sdu_type == SDU_TYPE_PING) {

            uint8_t reply[256];
            reply[0] = src; // hvem svaret kom fra
            reply[1] = ttl; // TTL fra meldingen
            memcpy(&reply[2], payload, length);

            write(unix_clients[i].fd, reply, 2 + length);

            if (debug_mode) {
                printf("[DEBUG] Sent PONG to UNIX app (src=%u ttl=%u len=%zd)\n",
                       src, ttl, length);
            }
            break;
        }
    }
}

// Håndterer mottatte ARP-meldinger (både request og response).
void handle_arp_message(int raw_sock, int my_mip_address,
                        const uint8_t *payload, ssize_t length,
                        const struct ethhdr *eh, int if_index, uint8_t src)
{
    // Sjekk at payloaden er stor nok til å inneholde en mip_arp_msg
    if (length < (ssize_t)sizeof(mip_arp_msg)) {
        printf("[ERROR] ARP SDU for kort (%zd bytes)\n\n", length);
        return;
    }

    // Tolker payloaden som en ARP-melding (definert i arp.h)
    const mip_arp_msg *arp = (const mip_arp_msg *)payload;

    if (debug_mode) {
        printf("[DEBUG] ARP msg: type=%u mip_addr=%u (payload_len=%zd)\n\n",
               arp->type, arp->mip_addr, length);
    }

    // ARP REQUEST 
    if (arp->type == 0x00 && arp->mip_addr == my_mip_address) {
        // Dette er en ARP-request som spør etter meg — svar med min adresse
        printf("[RAW] ARP-REQ mottatt fra MIP %d\n\n", arp->mip_addr);

        // Bygg ARP-respons med egen MIP-adresse
        mip_arp_msg resp = { .type = 0x01, .mip_addr = my_mip_address, .reserved = 0 };
        size_t pdu_len = 0;

        uint8_t *pdu = mip_build_pdu(
            src,                   // destinasjon (naboen som spurte)
            my_mip_address,        // kildeadresse (meg)
            1,                     // TTL
            SDU_TYPE_ARP,          // SDU-type
            (uint8_t *)&resp,      // payload
            sizeof(resp),          // payload-størrelse
            &pdu_len               // returnerer total lengde
        );

        // Send svaret tilbake til avsenderens MAC-adresse
        send_pdu(raw_sock, pdu, pdu_len, (unsigned char *)eh->h_source, if_index);
        free(pdu);
    }

    // ARP RESPONSE 
    else if (arp->type == 0x01) {
        // Dette er et svar på en tidligere ARP-forespørsel
        printf("[RAW] ARP-RESP mottatt for MIP %d\n\n", arp->mip_addr);

        // Oppdater ARP-tabellen med MAC-adressen til avsenderen
        arp_update(arp->mip_addr, eh->h_source, if_index);

        if (debug_mode) {
            print_arp_cache();
        }

        // Sjekk om noen meldinger ligger på vent til denne MIP-adressen, da kan de sendes
        send_pending_messages(raw_sock, arp->mip_addr, (unsigned char *)eh->h_source, if_index);
    }
}


// Hjelpemetode som forsøker å forwarde en pakke til destinasjonen
// Returnerer 1 hvis pakken ble forwarded (lagt i kø),
// 0 hvis pakken var til en selv eller broadcast,
// -1 hvis pakken ble droppet (f.eks. TTL utløpt)
int forward_packet(int my_mip_address,
                   uint8_t dest, uint8_t src, uint8_t ttl,
                   uint8_t sdu_type, const uint8_t *payload, ssize_t length)
{
    // Ikke forward hvis pakken er til meg eller broadcast (255)
    if (dest == my_mip_address || dest == 255) {
        return 0; // håndteres lokalt
    }

    // Dropp pakker med TTL = 0 eller 1
    if (ttl <= 1) {
        if (debug_mode)
            printf("[DEBUG][FWD] Dropper pakke til %d (TTL utløpt)\n", dest);
        return -1;
    }

    // Reduser TTL med 1 før videresending
    uint8_t ttl_new = ttl - 1;

    if (debug_mode) {
        printf("[DEBUG][RAW][FWD] Routing lookup: dest=%d, src=%d, ttl=%d→%d\n",
               dest, src, ttl, ttl_new);
    }

    // Legg meldingen i kø mens man venter på routingd sitt svar
    queue_routing_message(dest, src, ttl_new, sdu_type, payload, length);

    // Send en route request til routingd for å finne neste hopp
    for (int i = 0; i < MAX_UNIX_CLIENT; i++) {
        if (unix_clients[i].active &&
            unix_clients[i].sdu_type == SDU_TYPE_ROUTING) {

            send_route_request(unix_clients[i].fd, my_mip_address, dest);
            break;
        }
    }

    if (debug_mode)
        printf("[DEBUG][RAW][FWD] Route request sendt til routingd, pakke lagret midlertidig.\n");

    return 1;
}
