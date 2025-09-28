#ifndef MIPD_H
#define MIPD_H

#include <stdint.h>
#include <stddef.h>
#include <net/if.h>  //for IFNAMIZ til interface

//globale verdier
extern char iface_name[IFNAMSIZ];
extern int my_mip_address;
extern int debug_mode;
extern int last_unix_client_fd;

//til å legge pakker i kø
#define MAX_PENDING 20

typedef struct {
    int valid;
    uint8_t dest_mip;
    uint8_t sdu_type;
    uint8_t *payload;
    size_t length;
} pending_entry;

extern pending_entry pending_queue[MAX_PENDING];

//mipd.c funksjoner

int get_iface_mac(const char *ifname, unsigned char *mac);
void find_iface(void);

void queue_message(uint8_t dest_mip, uint8_t sdu_type, uint8_t* data, size_t length);
void send_pending_messages(int raw_sock, uint8_t mip_addr, unsigned char* mac, int my_mip_address);

void handle_unix_request(int unix_sock, int raw_sock, int my_mip_address);
void handle_raw_packet(int raw_sock, int my_mip_address);

int create_raw_socket();
int create_unix_socket(const char *path);

#endif
