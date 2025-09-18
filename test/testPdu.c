#include "../src/mipd.h"
#include <stdio.h>
#include <stdlib.h>

int main() {

    // Header info
    uint8_t dest = 42;
    uint8_t src = 17;
    uint8_t ttl = 4;
    uint16_t sdu_length = 300; // eksempel
    uint8_t sdu_type = 9;

    // Lag litt test-payload
    uint8_t payload[300];
    for (int i = 0; i < 300; i++) {
        payload[i] = i % 256; // fyller med verdier 0-255
    }

    // Bygg PDU
    uint8_t* pdu = build_pdu(dest, src, ttl, sdu_length, sdu_type, payload);


    // Skriv ut PDU i hex
    printf("PDU (hex):\n");
    for (int i = 0; i < 4 + ((sdu_length + 3)/4)*4; i++) { // 4 byte header + padding
        printf("%02X ", pdu[i]);
        if ((i+1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // Frigjør minnet
    free(pdu);

    return 0;

}