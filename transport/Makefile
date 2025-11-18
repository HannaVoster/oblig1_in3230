
# Makefile for transport-laget (MIPTP)

CC      = gcc
CFLAGS  = -Wall -Wextra -g -Iinclude
BIN_DIR = ../bin
SRC_DIR = src

TARGETS = $(BIN_DIR)/miptpd \
           $(BIN_DIR)/miptpd_client \
           $(BIN_DIR)/miptpd_server

all: $(BIN_DIR) $(TARGETS)

# Sørg for at bin/ finnes
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Kilde­filene til MIPTP-daemon
MIPTPD_SRC = $(SRC_DIR)/miptpd.c \
              $(SRC_DIR)/miptpd_unix.c \
              $(SRC_DIR)/miptpd_mip_incoming.c \
              $(SRC_DIR)/miptpd_retransmit.c \
              $(SRC_DIR)/miptpd_sending.c \
              $(SRC_DIR)/miptpd_pdu.c \
              $(SRC_DIR)/miptpd_utils.c

# MIPTP daemon
$(BIN_DIR)/miptpd: $(MIPTPD_SRC)
	$(CC) $(CFLAGS) -o $@ $(MIPTPD_SRC)

# Klient
$(BIN_DIR)/miptpd_client: $(SRC_DIR)/miptpd_client.c
	$(CC) $(CFLAGS) -o $@ $^

# Server
$(BIN_DIR)/miptpd_server: $(SRC_DIR)/miptpd_server.c
	$(CC) $(CFLAGS) -o $@ $^

# Rydd opp
clean:
	rm -f $(BIN_DIR)/miptpd \
	      $(BIN_DIR)/miptpd_client \
	      $(BIN_DIR)/miptpd_server 


