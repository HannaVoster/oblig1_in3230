# ================================
# Kompileringsvalg
# ================================
CC      = gcc
CFLAGS  = -Wall -Wextra -g -I../include
BIN_DIR = ../bin
SRC_DIR = .

TARGETS = $(BIN_DIR)/miptpd \
           $(BIN_DIR)/miptpd_client \
           $(BIN_DIR)/miptpd_server \
           $(BIN_DIR)/test_app \
           $(BIN_DIR)/test_server

all: $(BIN_DIR) $(TARGETS)

# Sørg for at bin/ finnes
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

MIPTPD_SRC = $(SRC_DIR)/miptpd.c \
              $(SRC_DIR)/miptpd_unix.c \
              $(SRC_DIR)/miptpd_mip_incoming.c \
              $(SRC_DIR)/miptpd_retransmit.c \
              $(SRC_DIR)/miptpd_sending.c \
              $(SRC_DIR)/miptpd_pdu.c \
              $(SRC_DIR)/miptpd_utils.c


# MIPTP daemon
$(BIN_DIR)/miptpd: $(MIPTPD_SRC) ../include/miptpd.h
	$(CC) $(CFLAGS) -o $@ $(MIPTPD_SRC)

# Klient
$(BIN_DIR)/miptpd_client: $(SRC_DIR)/miptpd_client.c ../include/miptpd.h
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/miptpd_client.c

# Server
$(BIN_DIR)/miptpd_server: $(SRC_DIR)/miptpd_server.c ../include/miptpd.h
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/miptpd_server.c

# Tester
$(BIN_DIR)/test_app: $(SRC_DIR)/test_app.c ../include/miptpd.h
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/test_app.c

$(BIN_DIR)/test_server: $(SRC_DIR)/test_server.c ../include/miptpd.h
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/test_server.c

clean:
	rm -f $(BIN_DIR)/*

