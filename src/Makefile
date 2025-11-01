# Kompilator og flagg
# -Wall og -Wextra: viser nyttige advarsler
# -g: inkluderer feilsøkingsinformasjon
# -I../include: ser etter header-filer i felles include-mappen
CC      = gcc
CFLAGS  = -Wall -Wextra -g -I../include

# Mappe for binærfiler (en felles for hele prosjektet)
BIN_DIR = ../bin

# Programnavn som skal bygges
TARGETS = $(BIN_DIR)/mipd \
           $(BIN_DIR)/ping_client \
           $(BIN_DIR)/ping_server \
           $(BIN_DIR)/routingd

# Standardregel: bygg alle programmer
# Lager også bin/ hvis den ikke finnes
all: $(BIN_DIR) $(TARGETS)

# Oppretter bin/-mappen dersom den ikke finnes
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Bygg MIP-daemon (nettverkslaget)
# Her lenkes alle nødvendige .c-filer sammen
$(BIN_DIR)/mipd: mipd.c pdu.c arp.c iface.c queue.c raw_handler.c unix.c
	$(CC) $(CFLAGS) -o $@ $^

# Bygg ping_client (testapplikasjon for MIP)
$(BIN_DIR)/ping_client: ping_client.c
	$(CC) $(CFLAGS) -o $@ $^

# Bygg ping_server (mottar meldinger fra ping_client)
$(BIN_DIR)/ping_server: ping_server.c
	$(CC) $(CFLAGS) -o $@ $^

# Bygg routingd (routingtjeneste)
$(BIN_DIR)/routingd: routingd.c routing_socket.c routing_table.c routing_protocol.c
	$(CC) $(CFLAGS) -o $@ $^

# Rydd opp (fjerner kompilerte binærfiler)
clean:
	rm -f $(BIN_DIR)/mipd \
	      $(BIN_DIR)/ping_client \
	      $(BIN_DIR)/ping_server \
	      $(BIN_DIR)/routingd

