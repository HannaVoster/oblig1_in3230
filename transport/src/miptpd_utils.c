/*
 * Ansvar:
 *  - Holder global state for alle app-forbindelser (app_connections[])
 *  - Registrerer og fjerner apper som kobler til MIPTPD
 *  - Oppslag mellom fd - port og fd - index
 *  - Hjelpefunksjoner for inbound- og outbound-transfers:
 *        - Opprette nye transfers (inbound + outbound)
 *        - Finne eksisterende transfers
 *  - Go-Back-N grunnlogikk:
 *        - Initiering av base_seq og next_seq
 *        - Håndtering av vindusbuffer for både send og mottak
 *  - Sekvensnummer- og pad-pakking/oppløsning
 */


#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "miptpd_utils.h"
#include "miptpd.h"  

app_connection app_connections[MAX_APPS] = {0}; //liste over aktive app forbinndelser

/*
  Pakker sammen sekvensnummer og pad-lengde i ett 16-bit-felt.
  Øverste 2 bits brukes til pad, nederste 14 til sekvensnummer.
*/
uint16_t pack_seq_pad(uint16_t seq, uint8_t padlen) {
    return ((padlen & 0x03) << 14) | (seq & 0x3FFF);
}

/*
  Dekomprimerer et 16-bit-felt til sekvensnummer og pad-lengde.
  Brukes ved mottak av MIPTP-pakker
*/
void unpack_seq_pad(uint16_t seq_pad, uint16_t *seq, uint8_t *pad) {
    *pad = (seq_pad >> 14) & 0x03;   // hent de to øverste bitene
    *seq  = seq_pad & 0x3FFF;         // hent de nederste 14 bitene
}

/*
  Registrerer en ny applikasjon i tabellen
*/
int new_app_connection(int fd, uint8_t port) {

    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].app_fd != 0 &&
            app_connections[i].port == port) {
            printf("[MIPTPD] Port %d already in use — rejecting app\n", port);
            return -1;
        }
    }
    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].app_fd == 0) {

            app_connections[i].app_fd = fd;
            app_connections[i].port = port;

            app_connections[i].num_transfers = 0;
            app_connections[i].registered = 1;

            printf("[MIPTPD] Registered app fd=%d on port %d\n", fd, port);
            return 0;
        }
    }

    fprintf(stderr, "[MIPTPD] Connection table full\n");
    return -1;
}
/*
 * Fjerner en app-forbindelse når appens socket lukkes
 *
 * - Finner riktig entry basert på fd
 * - Stopper alle retransmisjoner ved å merke alle uackede vindusplasser som tomme
 * - Nullstiller outbound- og inbound-transferstate for appen
 * - Setter app_fd til 0, men lar porten stå slik at ingen andre tar samme port
 * Returnerer 0 ved suksess
 */
int remove_app_connection(int fd) {
    for (int i = 0; i < MAX_APPS; i++) {

        app_connection *c = &app_connections[i];

        if (c->app_fd == fd) {
            printf("[MIPTPD] Removing app fd=%d (port=%u)\n",
                   fd, c->port);

            for (int t = 0; t < c->outbound_count; t++) {
                outbound_transfer_state *ot = &c->outbound[t];
                for (int w = 0; w < MIPTP_WINDOW_SIZE; w++) {
                    ot->window[w].acked = 1;
                    ot->window[w].len = 0;
                }
                ot->window_count = 0;
            }

            c->app_fd = 0;
            c->outbound_count = 0;
            c->num_transfers = 0;

            return 0;
        }
    }
    return -1;
}

/*
  Returnerer portnummeret som er knyttet til en gitt app_fd
  Returnerer 0 hvis forbindelsen ikke finnes (0 er ugyldig port)
*/
uint8_t get_port_from_fd(int fd) {
    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].app_fd == fd)
            return app_connections[i].port;
    }
    fprintf(stderr, "[MIPTPD] No port found for fd=%d\n", fd);
    return 0;
}

/*
  Finner filbeskrivelsen (socket-fd) som hører til en gitt port
  Returnerer -1 hvis ingen app er registrert på porten
*/
int get_fd_from_port(uint8_t port) {
    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].port == port)
            return app_connections[i].app_fd;
    }
    fprintf(stderr, "[MIPTPD] No app found for port=%d\n", port);
    return -1;
}

/*
  Finner indexen i app_connections-tabellen for en gitt fd.
  Returnerer -1 hvis ingen match finnes.
*/
int get_index(int fd){
    for (int i = 0; i < MAX_APPS; i++) {
        if (app_connections[i].app_fd == fd)
            return i;
    }
    fprintf(stderr, "[MIPTPD] No index found for fd=%d\n", fd);
    return -1;
}


void hex_debug(const char *prefix, const uint8_t *buf, size_t len) {
    printf("%s (len=%zu): ", prefix, len);
    size_t show = len < 16 ? len : 16;
    for (size_t i = 0; i < show; i++)
        printf("%02x ", buf[i]);
    if (len > 16) printf("...");
    printf("\n");
}

/*
    Oppretter en ny inbound-transfer for en app.
    Brukes når appen mottar data fra en ny avsender (MIP + port) for første gang
    Setter opp både send- og mottaksdelen av Go-Back-N for denne forbindelsen
    Holder styr på forventet seq, base_seq og vinduet som skal brukes senere
*/

transfer_state *create_transfer_state(app_connection *app,
                                      uint8_t src_mip,
                                      uint8_t src_port)
{
    // sjekker om appen allerede har maks antall transfers
    if (app->num_transfers >= MAX_TRANSFERS_PER_APP) {
        fprintf(stderr, "Too many transfers for this app\n");
        return NULL;
    }

    // lager en ny transfer i arrayet
    transfer_state *t = &app->transfers[app->num_transfers++];
    memset(t, 0, sizeof(*t));

    t->src_mip = src_mip;
    t->src_port = src_port;

      // starter GBN-send side
    t->base_seq = rand() % MIPTP_MAX_SEQ;
    t->next_seq = t->base_seq;

    // marker alle vindusplasser som tomme/ACKed
    for (int i = 0; i < MIPTP_WINDOW_SIZE; i++)
        t->window[i].acked = 1;

    // init mottaksdelen
    t->expected_seq = 0;
    t->synced = 0;

    printf("[MIPTPD] New transfer src=%u:%u\n", src_mip, src_port);

    return t;
}

/*
    Leter etter en eksisterende inbound-transfer basert på MIP-adresse og port
    Brukes for å finne riktig forbindelse når det kommer en datapakke fra nettverket
    Returnerer transferen hvis den finnes, ellers NULL
*/
transfer_state *find_transfer(app_connection *app, uint8_t src_mip, uint8_t src_port)
{
    for (int i = 0; i < app->num_transfers; i++) {
        if (app->transfers[i].src_mip == src_mip &&
            app->transfers[i].src_port == src_port)
            return &app->transfers[i];
    }
    return NULL;
}

/*
    Finner en outbound-transfer for gitt destinasjon (dst_mip + dst_port)
    Hvis den finnes - returner eksisterende
    Hvis ikke - opprett en ny outbound-transfer og initialiser GBN-senderstate
    Brukes når appen ønsker å sende data til en bestemt MIP/port
*/
outbound_transfer_state *
find_or_create_outbound(app_connection *app,
                        uint8_t dst_mip,
                        uint8_t dst_port)
{
    // Finn eksisterende transfer
    for (int i = 0; i < app->outbound_count; i++) {
        outbound_transfer_state *t = &app->outbound[i];
        if (t->dst_mip == dst_mip && t->dst_port == dst_port && t->app_fd == app->app_fd) {
            return t;
        }
    }

    // Opprett ny hvis ingen finnes
    if (app->outbound_count >= MAX_OUT_TRANSFERS) {
        fprintf(stderr, "[MIPTPD] ERROR: Too many outbound transfers for app_fd=%d\n",
                app->app_fd);
        return NULL;
    }

    outbound_transfer_state *t = &app->outbound[app->outbound_count++];
    memset(t, 0, sizeof(*t));
    t->dst_mip  = dst_mip;
    t->dst_port = dst_port;
    t->app_fd = app->app_fd;

    // Init GBN for denne transferen
    t->base_seq = rand() % MIPTP_MAX_SEQ;
    t->next_seq = t->base_seq;

    if(debug_mode) printf("[MIPTPD][TX] Created outbound transfer to %u:%u (seq=%u)\n",
           dst_mip, dst_port, t->base_seq);

    return t;
}

/*
    Finner en outbound-transfer for gitt destinasjon (dst_mip + dst_port)
    Hvis den finnes - returner eksisterende
    Hvis ikke - opprett en ny outbound-transfer og initialiser GBN-senderstate
    Brukes når appen ønsker å sende data til en bestemt MIP/port
*/
outbound_transfer_state *
find_outbound_for_ack(app_connection *app,
                      uint8_t ack_src_mip,    
                      uint8_t ack_src_port)   
{
    // leter etter outbound-transfer som matcher avsenderen av ACKen
    for (int i = 0; i < app->outbound_count; i++) {
        outbound_transfer_state *t = &app->outbound[i];

        if (t->dst_mip  == ack_src_mip &&
            t->dst_port == ack_src_port &&
            t->app_fd   == app->app_fd)
        {
            return t; // fant hvilken transfer ACK hører til
        }
    }
    return NULL;
}

