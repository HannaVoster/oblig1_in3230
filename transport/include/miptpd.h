#ifndef MIPTPD_H
#define MIPTPD_H

#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>


/*
 *  miptpd.h
 *  Sentral header for MIPTP-daemonen
 *
 *  Inneholder:
 *   - Globale konstanter
 *   - Datastrukturer brukt på tvers av moduler
 *   - Globale variabler (extern)
 */

// Konstanter og begrensninger
#define MIPTP_SDU_TYPE       0x05
#define MIPTP_MAX_PAYLOAD    1400
#define MIPTP_WINDOW_SIZE    16
#define MIPTP_MAX_SEQ        16384 // 14-bit sekvensnummer
#define MIPTP_MAX_QUEUE      64
#define MAX_APPS             20


// Globale variabler
extern int debug_mode;   // styrer logging, settes som flagg til main
extern int MIP_FD;       // file descriptor til mipd-socket


// Datastrukturer

#define MAX_TRANSFERS_PER_APP 64
#define MAX_OUT_TRANSFERS 32

typedef struct {
    uint8_t src_mip;
    uint8_t src_port;
} transfer_key;

// MIPTP-header (brukes både ved bygging og parsing)
typedef struct {
    uint8_t  src_port;
    uint8_t  dst_port;
    uint16_t seq_pad; // [sequence number (14 bits) | pad length (2 bits)]
} __attribute__((packed)) miptp_hdr_t;

// Oppføring i Go-Back-N sendvindu
typedef struct {
    uint8_t  data[1500];
    ssize_t  len;
    uint16_t seq;
    time_t   sent_time;
    int      acked;
} packet_entry;

// Køoppføring (brukes når vinduet er fullt)
typedef struct {
    uint8_t data[1500];
    size_t  len;
} queued_packet;


typedef struct {
    // Identifikasjon av denne forbindelsen
    uint8_t src_mip;
    uint8_t src_port;

    // GBN SEND-STATE (per transfer)
    uint16_t base_seq;
    uint16_t next_seq;
    packet_entry window[MIPTP_WINDOW_SIZE];
    int window_count;

    // Kø for SDUer som venter på sending
    queued_packet queue[MIPTP_MAX_QUEUE];
    int queue_head;
    int queue_tail;
    int queue_count;

    // GBN RECEIVE-STATE (per transfer)
    uint16_t expected_seq;
    int synced;

    //time_t last_activity;  ´
} transfer_state;


typedef struct {
    uint8_t dst_mip;
    uint8_t dst_port;

    uint16_t base_seq;
    uint16_t next_seq;

    packet_entry window[MIPTP_WINDOW_SIZE];
    uint8_t window_count;

    queued_packet queue[MIPTP_MAX_QUEUE];
    int queue_head;
    int queue_tail;
    int queue_count;

} outbound_transfer_state;


typedef struct {
    int app_fd;
    uint8_t port;  // dst_port

    transfer_state transfers[MAX_TRANSFERS_PER_APP];
    int num_transfers;

    outbound_transfer_state outbound[MAX_OUT_TRANSFERS];
    int outbound_count;
} app_connection;

// Global tabell for aktive app-tilkoblinger
extern app_connection app_connections[MAX_APPS];

// Grunnfunksjoner fra miptpd.c

void parse_socket_paths(char *mipd_arg, char *app_arg,
                        char *mipd_path, char *app_path);
void handle_flags(int argc, char *argv[]);
int  setup_mip_connection(const char *mipd_path);
int  setup_epoll(int mip_fd, int app_listen_fd);
void run_event_loop(int epollfd, int mip_fd, int app_listen_fd);
void handle_mip_event(int mip_fd);
void handle_new_app_connection(int app_listen_fd, int epollfd);
void handle_app_message(int fd);
void cleanup(int epollfd, int mip_fd, int app_listen_fd);

// UNIX-sockets, miptpd_unix.c
void wait_for_socket(const char *path);
int  connect_to_mipd(const char *path);
int  create_app_socket(const char *path);

#endif 
