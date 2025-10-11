# Kompileringsvalg
CC      = gcc
CFLAGS  = -Wall -Wextra -g -Iinclude

# Mapper
SRC_DIR = src
BIN_DIR = bin

# Programmer
TARGETS = $(BIN_DIR)/mipd $(BIN_DIR)/ping_client $(BIN_DIR)/ping_server

# Standardregel
all: $(TARGETS)

# Lag bin/ hvis den ikke finnes
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Bygg mipd
$(BIN_DIR)/mipd: $(SRC_DIR)/main.c \
                 $(SRC_DIR)/mipd.c \
                 $(SRC_DIR)/pdu.c \
                 $(SRC_DIR)/arp.c \
                 $(SRC_DIR)/iface.c \
				 $(SRC_DIR)/queue.c \
				 $(SRC_DIR)/raw_handler.c \
				 $(SRC_DIR)/unix.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

# Bygg ping_client
$(BIN_DIR)/ping_client: $(SRC_DIR)/ping_client.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

# Bygg ping_server
$(BIN_DIR)/ping_server: $(SRC_DIR)/ping_server.c | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $^

$(BIN_DIR)/routingd: $(SRC_DIR)/routingd.c include/routingd.h | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $<

# Rydd opp
clean:
	rm -rf $(BIN_DIR) $(SRC_DIR)/*.o
