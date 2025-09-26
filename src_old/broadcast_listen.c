#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "mipd.h"

//funnksjon som åpner en raw socket og venter i en evig løkke for å sjekke om mac matcher
void listen_for_broadcast(int rawsocket){
    //buffer for å holde på inkommende pakker
    uint8_t buffer[2000];

    //evig loop, venter på broadcast
    while(1){
        int len = recv(rawsocket, buffer, sizeof(buffer), 0);

        //sjeker om det er skjedd en feil
        if(len < 0){
            perror("recv");
            continue;
        }

        //henter ut headeren
        mip_header header;
        //kopierer headeren over i buffer
        memcpy(header, buffer, 4);

        //henter sdu type for å sjekke meldingen
        uint8_t sdu_type = get_sdu_type(header);

        if(sdu_type == SDU_TYPE_ARP_REQ){
            //sjekker om mac adressen matcher
            //peker til payloaden som er på buffer+4
            mip_arp_msg *req = (mip_arp_msg*)(buffer + 4);

            if((*req).mip_addr == my_mip_address){
                send_arp_response(req);
            }
        }
    }
}

void send_arp_response(int rawsocket, mip_arp_msg *req, mip_header header){
    //match, må sende svar
    mip_arp_msg arp_response ;
    unsigned char my_mac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};

    arp_response.type = SDU_TYPE_ARP_RESP;
    arp_response.mip_addr = my_mip_address;

    memcpy(arp_response.mac, my_mac, 6);

    //bygger pdu for respons   
    uint8_t* pdu = build_pdu(
        header.scr_addr,
        my_mip_address,
        2, 
        sizeof(arp_response), 
        SDU_TYPE_ARP_RESP,  
        (uint8_t*)&arp_response
        );

    sen_pdu(rawsocket, pdu, 4 + sizeof(arp_response), )

}

