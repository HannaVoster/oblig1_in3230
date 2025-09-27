#ifndef MIPD_H
#define MIPD_H

#include <stdint.h>
#include <stddef.h>
#include <net/if.h>  //for IFNAMIZ til interface

// SDU typer i henhold til RFC Appendix A
#define SDU_TYPE_ARP   0x01
#define SDU_TYPE_PING  0x02
#define SDU_TYPE_PONG  0x03

#define MAX_PENDING 20

#define ETH_P_MIP 0x88B5

extern char iface_name[IFNAMSIZ];


typedef struct {
    int valid;
    uint8_t dest_mip;
    uint8_t sdu_type;
    uint8_t *payload;
    size_t length;
} pending_entry;


// global kø
extern pending_entry pending_queue[MAX_PENDING];
extern int last_unix_client_fd;

// ARP message (SDU payload)
typedef struct __attribute__((packed)) {
    uint8_t type;       // 0x00 = request, 0x01 = response
    uint8_t mip_addr;   // hvem vi spør om / hvem som svarer
    uint16_t reserved;  // padding = 0
} mip_arp_msg;

// ARP cache entry
typedef struct {
    int mip_addr;
    unsigned char mac[6];
    int valid;
} arp_entry;

#define MAX_ARP 256
extern arp_entry arp_cache[MAX_ARP];

// PDU header
typedef struct __attribute__((packed)) {
    uint8_t dest;
    uint8_t src;
    uint8_t ttl_len;   // øvre 4 bit = TTL, nedre 4 = high bits av length
    uint8_t len_type;  // nedre 4 bit = SDU-type, øvre 4 bit kan være high bits av length
} mip_header_t;

extern int my_mip_address;

// ARP-funksjoner
void arp_update(int mip_addr, const unsigned char *mac);
int arp_lookup(int mip_addr, unsigned char *mac_out);
void print_arp_cache(void);

// PDU-funksjoner
uint8_t* build_pdu(uint8_t dest_addr, uint8_t src_addr, uint8_t ttl,
                   uint16_t sdu_length_bytes, uint8_t sdu_type,
                   const uint8_t* payload, size_t* out_length);

int send_pdu(int rawsocket, uint8_t *pdu, size_t pdu_length, unsigned char *dest_mac);

// Broadcast / kø
int send_broadcast(int dest, int rawsocket);

void queue_message(uint8_t dest_mip, uint8_t sdu_type, uint8_t* data, size_t length);
void send_pending_messages(int raw_sock, uint8_t mip_addr, unsigned char* mac, int my_mip_address);

// hentefunksjoner
uint8_t get_src(const mip_header_t *h);
uint8_t get_dest(const mip_header_t *h);
uint8_t get_type(const mip_header_t *h);
uint16_t get_length(const mip_header_t *h);

void set_dest(mip_header_t *h, uint8_t dest);
void set_src(mip_header_t *h, uint8_t src);
void set_ttl(mip_header_t *h, uint8_t ttl);
void set_length(mip_header_t *h, uint16_t len_words);
void set_type(mip_header_t *h, uint8_t type);

#endif
