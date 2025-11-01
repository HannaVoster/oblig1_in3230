# Kompileringsvalg
CC      = gcc
CFLAGS  = -Wall -Wextra -g -Iinclude

# Mapper
SRC_DIR = src
BIN_DIR = bin

# Programmer
TARGETS = $(BIN_DIR)/mipd $(BIN_DIR)/ping_client $(BIN_DIR)/ping_server $(BIN_DIR)/routingd


# Standardregel
all: $(TARGETS) deploy

# Lag bin/ hvis den ikke finnes
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Bygg mipd
$(BIN_DIR)/mipd: $(SRC_DIR)/mipd.c \
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

# Bygg routingd
$(BIN_DIR)/routingd: \
	$(SRC_DIR)/routingd.c \
	$(SRC_DIR)/routing_socket.c \
	$(SRC_DIR)/routing_table.c \
	$(SRC_DIR)/routing_protocol.c 
	$(CC) $(CFLAGS) -o $@ $^


# Rydd opp
clean:
	rm -rf $(BIN_DIR) $(SRC_DIR)/*.o

DEPLOY_DIR = $(PWD)

deploy:
	cp $(BIN_DIR)/* $(DEPLOY_DIR)/
	@echo "Deploy fullført: Binærfiler kopiert til $(DEPLOY_DIR)"