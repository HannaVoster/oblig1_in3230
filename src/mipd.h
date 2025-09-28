#ifndef MIPD_H
#define MIPD_H

#include <stdint.h>
#include <stddef.h>
#include <net/if.h>  //for IFNAMIZ til interface

// SDU typer i henhold til RFC Appendix A
// #define ETH_P_MIP 0x88B5

extern char iface_name[IFNAMSIZ];
extern int my_mip_address;
extern int debug_mode;


#define MAX_PENDING 20
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

// uint8_t* build_pdu(uint8_t dest_addr, uint8_t src_addr, uint8_t ttl,
//                    uint16_t sdu_length_bytes, uint8_t sdu_type,
//                    const uint8_t* payload, size_t* out_length);


void queue_message(uint8_t dest_mip, uint8_t sdu_type, uint8_t* data, size_t length);
void send_pending_messages(int raw_sock, uint8_t mip_addr, unsigned char* mac, int my_mip_address);

//Daemon funksjoner
void handle_unix_request(int unix_sock, int raw_sock, int my_mip_address);
void handle_raw_packet(int raw_sock, int my_mip_address);
int create_raw_socket();
int create_unix_socket(const char *path);
void find_iface(void);

#endif
