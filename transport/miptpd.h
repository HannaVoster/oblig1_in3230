

#ifndef MIPTP_H
#define MIPTP_H

#include <stdint.h>
#include <stdlib.h>

#define MIPTP_SDU_TYPE 0x05
#define MIPTP_MAX_PAYLOAD 1400
#define MIPTP_WINDOW_SIZE 16
#define MIPTP_MAX_SEQ 16384  // 14 bits

#define MAX_APPS 20

extern int debug_mode;
extern int MIP_FD;

typedef struct {
    uint8_t src_port;
    uint8_t dst_port;
    uint16_t seq_pad; //[ sequence number (14 bits) | padding length (2 bits) ] = 16 bits

    // payload follows
} __attribute__((packed)) miptp_hdr_t;

typedef struct {
    uint8_t dst_mip;
    uint8_t dst_port;
    uint16_t seq;
    size_t len;
    uint8_t *data;
} miptp_packet_t;

//lager en connections tabell med app_fd, og port
typedef struct {
    int app_fd;
    uint8_t port;
    uint16_t next_seq;
    uint16_t last_acked_seq;
} app_connection;

extern app_connection app_connections[MAX_APPS];

// Oppstart og initiering
int main(int argc, char *argv[]);
// void init_unix_socket(const char *path);
// void init_mip_socket(const char *path);

// // Håndtering av applikasjoner
// void handle_new_app_connection();
// void handle_app_message(int app_fd);

// // Håndtering av mottatte MIPTP-pakker
// void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip);

// // Sendefunksjoner
// void send_miptp_data(...);
// void send_miptp_ack(...);

// // Tidsstyring / retransmisjon
// void check_retransmissions();

// // Hjelpefunksjoner
// uint16_t pack_seq_pad(uint16_t seq, uint8_t padlen);
// void unpack_seq_pad(uint16_t seq_pad, uint16_t *seq, uint8_t *padlen);

//miptpd_unix.c
void wait_for_socket(const char *path);
int connect_to_mipd(const char *path);
int create_app_socket(const char *path);
void handle_new_app_connection(int unix_fd);
void handle_app_message(int app_fd);

// // Fra miptp_mip.c
void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip);
void send_miptp_data(int app_fd, uint8_t *data, size_t len);

// // Fra miptp_retransmit.c
// void check_retransmissions(void);

// // Fra miptp_utils.c
uint16_t pack_seq_pad(uint16_t seq, uint8_t padlen);
void unpack_seq_pad(uint16_t seq_pad, uint16_t *seq, uint8_t *padlen);
uint8_t get_port_from_fd(int fd);
int remove_app_connection(int fd);
int new_app_connection(int fd, uint8_t port);
int get_fd_from_port(uint8_t port);
int get_index(int fd); //brukes denne?
uint16_t get_next_seq(int fd);



#endif
