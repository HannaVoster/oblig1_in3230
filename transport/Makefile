# Kompileringsvalg
CC      = gcc
CFLAGS  = -Wall -Wextra -g -I../include
BIN_DIR = ../bin
SRC_DIR = .

TARGETS = $(BIN_DIR)/miptpd \
           $(BIN_DIR)/miptp_client \
           $(BIN_DIR)/miptp_server

all: $(BIN_DIR) $(TARGETS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

MIPTPD_SRC = $(SRC_DIR)/miptpd.c \
              $(SRC_DIR)/miptp_unix.c \
              $(SRC_DIR)/miptp_mip.c \
              $(SRC_DIR)/miptp_retransmit.c \
              $(SRC_DIR)/miptp_utils.c

$(BIN_DIR)/miptpd: $(MIPTPD_SRC) $(SRC_DIR)/miptp.h
	$(CC) $(CFLAGS) -o $@ $(MIPTPD_SRC)

$(BIN_DIR)/miptp_client: $(SRC_DIR)/miptp_client.c $(SRC_DIR)/miptp.h
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/miptp_client.c

$(BIN_DIR)/miptp_server: $(SRC_DIR)/miptp_server.c $(SRC_DIR)/miptp.h
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/miptp_server.c

clean:
	rm -f $(BIN_DIR)/miptpd $(BIN_DIR)/miptp_client $(BIN_DIR)/miptp_server
