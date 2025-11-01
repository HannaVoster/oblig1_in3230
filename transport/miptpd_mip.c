// kommunikasjon med MIP-daemon
//grensesnitt mot MIP deamon, nederste lag, under

/*
**Ansvar:**

- Kommunisere via UNIX-socket med `mipd`
- Pakke ut og tolke MIPTP-header
- Dele opp logikken mellom “data” og “ACK”-pakker

*/
#include "miptpd.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
Metode for å:
    ta data fra en applikasjon og pakke inn i en miptp pakke
    pakken skal senere sendes ned til mipd gjennom UNIX socket, 
    og mipd skal sende den ut på nettverket

    Tar inn
        app_fd: socket til applikajsonen
        data: payloaden/data som skal sendes
        len: lengden på data

    header består av:
        source port
        destination port
        sequence number + padding length
        sdu + padding
*/

void send_miptp_data(int app_fd, uint8_t *data, size_t len) {
    //sjekekr at lengden på payloaded er stor nok
    if (len < 2) {
        fprintf(stderr, "[MIPTPD] Invalid payload (too short)\n");
        return;
    }

    miptp_hdr_t hdr = {0};

    uint8_t dst_mip  = data[0]; // der pakken skal
    uint8_t dst_port = data[1]; //porten pakkes skal sendes ut på
    uint8_t *payload = data + 2; //selve dataen som skal sendes
    size_t payload_len = len - 2; //lengden på dataen, -2 siden dst_mip og dst_port har data[0] og data[1]

    // henter faktisk port fra app_fd (lagret i en connections_table)
    uint8_t src_port = get_port_from_fd(app_fd);

    // Lager selve MIPTP-header
    hdr.src_port = src_port;
    hdr.dst_port = dst_port;
    hdr.seq_pad = pack_seq_pad(0, 0); //TODO , sekvensnummer per app

    // Bygger MIPTP-pakken, [Header][Payload]
    uint8_t packet[1500];
    packet[0] = dst_mip;

    memcpy(packet + 1, &hdr, sizeof(hdr)); //kopierer MIPTP-header til pakken
    memcpy(packet + 1 + sizeof(hdr), payload, payload_len); //kopierer dataen

    // sender pakken til mip deamon for å sende ut på nettverket
    ssize_t sent = write(MIP_FD, packet, 1+ sizeof(hdr) + payload_len);
    if (sent < 0)
        perror("[MIPTPD] write to mipd");
    else
        printf("[MIPTPD] Sent %zd bytes to mipd\n", sent);
}

/*
Ansvar:
  Behandler en MIPTP-pakke som er mottatt fra MIP-daemonen (mipd)
  Pakken kommer inn via UNIX-socketen mellom miptpd og mipd, og denne
  funksjonen står skal tolke MIPTP-headeren og videresende payload
  til riktig applikasjon (som er identifisert med destinasjonsport)

  Tar inn:
    buf: peker til pakken inkludert header
    len: den totale lengden på pakken
    src_mip: mip addressen til avsender

 Fremtidige utvidelser:
 *   - Implementer sekvenskontroll (ikke lever SDUs utenfor rekkefølge)
 *   - Send ACK tilbake til avsender (hdr.src_port)
 *   - Håndter duplikater og tapte pakker (Go-Back-N logikk)
 *   - Fjern eventuell padding fra payload
*/
void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip) {
    // er pakken stor nok til å ha en header
    if (len < sizeof(miptp_hdr_t)) return;

    //kopierer ut miptpd header fra buffer
    miptp_hdr_t hdr;
    memcpy(&hdr, buf, sizeof(hdr));

    //lager en peker til payload og beregner lengde
    uint8_t *payload = buf + sizeof(hdr);
    size_t payload_len = len - sizeof(hdr);

    printf("[MIPTPD] Got packet from MIP %d, src_port=%d dst_port=%d len=%zu\n",
           src_mip, hdr.src_port, hdr.dst_port, payload_len);

    int app_fd = get_fd_from_port(hdr.dst_port);
    if (app_fd >= 0) {
        uint8_t msg[2 + payload_len];
        msg[0] = src_mip;
        msg[1] = hdr.src_port;
        memcpy(msg + 2, payload, payload_len);

        write(app_fd, msg, sizeof(msg));
        printf("[MIPTPD] Delivered %zu bytes to app port %d (fd=%d)\n",
               payload_len, hdr.dst_port, app_fd);
    } else {
        printf("[MIPTPD] No app registered for port %d\n", hdr.dst_port);
    }
}


// int init_mip_socket(const char *path);
// void send_miptp_data(uint8_t dst_mip, uint8_t *pdu, size_t len);
// void send_miptp_ack(uint8_t dst_mip, uint8_t dst_port, uint16_t seq);
// void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip);


// // Fra miptp_mip.c
// void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip);
// void send_miptp_data(int app_fd, uint8_t *data, size_t len);