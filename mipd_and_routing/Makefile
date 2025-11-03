
# Makefile for mipd_and_routing


# Kompilator og flagg
CC      = gcc
CFLAGS  = -Wall -Wextra -g -Isrc -Iinclude

# Mapper
BIN_DIR = ../bin
SRC_DIR = src

# Programmer som skal bygges
TARGETS = $(BIN_DIR)/mipd \
           $(BIN_DIR)/ping_client \
           $(BIN_DIR)/ping_server \
           $(BIN_DIR)/routingd

# Standardregel
all: $(BIN_DIR) $(TARGETS)

# Opprett bin/ hvis den ikke finnes
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Bygg MIP-daemon (nettverkslaget)
$(BIN_DIR)/mipd: $(SRC_DIR)/mipd.c \
                 $(SRC_DIR)/pdu.c \
                 $(SRC_DIR)/arp.c \
                 $(SRC_DIR)/iface.c \
                 $(SRC_DIR)/queue.c \
                 $(SRC_DIR)/raw_handler.c \
                 $(SRC_DIR)/unix.c
	$(CC) $(CFLAGS) -o $@ $^

# Bygg ping_client
$(BIN_DIR)/ping_client: $(SRC_DIR)/ping_client.c
	$(CC) $(CFLAGS) -o $@ $^

# Bygg ping_server
$(BIN_DIR)/ping_server: $(SRC_DIR)/ping_server.c
	$(CC) $(CFLAGS) -o $@ $^

# Bygg routingd
$(BIN_DIR)/routingd: $(SRC_DIR)/routingd.c \
                     $(SRC_DIR)/routing_socket.c \
                     $(SRC_DIR)/routing_table.c \
                     $(SRC_DIR)/routing_protocol.c
	$(CC) $(CFLAGS) -o $@ $^

# Rydd opp
clean:
	rm -f $(BIN_DIR)/mipd \
	      $(BIN_DIR)/ping_client \
	      $(BIN_DIR)/ping_server \
	      $(BIN_DIR)/routingd

