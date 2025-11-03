# Kompileringsvalg
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

# Sørgrt for at bin/ finnes
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Kilde­filene til transport-daemon
MIPTPD_SRC = $(SRC_DIR)/miptpd.c \
              $(SRC_DIR)/miptpd_unix.c \
              $(SRC_DIR)/miptpd_mip_incoming.c \
              $(SRC_DIR)/miptpd_retransmit.c \
			  $(SRC_DIR)/miptpd_sending.c \
			  $(SRC_DIR)/miptpd_pdu.c \
              $(SRC_DIR)/miptpd_utils.c

# Bygger selve MIPTP-daemonen
$(BIN_DIR)/miptpd: $(MIPTPD_SRC) $(SRC_DIR)/miptpd.h
	$(CC) $(CFLAGS) -o $@ $(MIPTPD_SRC)

$(BIN_DIR)/miptpd_client: $(SRC_DIR)/miptpd_client.c $(SRC_DIR)/miptpd.h
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/miptpd_client.c

$(BIN_DIR)/miptpd_server: $(SRC_DIR)/miptpd_server.c $(SRC_DIR)/miptpd.h
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/miptpd_server.c

#TESTER
# Test applications
$(BIN_DIR)/test_app: $(SRC_DIR)/test_app.c $(SRC_DIR)/miptpd.h
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/test_app.c

$(BIN_DIR)/test_server: $(SRC_DIR)/test_server.c $(SRC_DIR)/miptpd.h
	$(CC) $(CFLAGS) -o $@ $(SRC_DIR)/test_server.c


clean:
	rm -f $(BIN_DIR)/miptpd $(BIN_DIR)/miptpd_client $(BIN_DIR)/miptpd_server
