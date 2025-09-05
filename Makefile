#hvilken kompulator
CC = gcc

#flags 
CFLAGS= -Wall -Wextra -g

# Standard: bygg programmet "mip_test"
all: mip_test

# Hvordan lage "mip_test" fra main.c
mip_test: src/main.c
	$(CC) $(CFLAGS) -o mip_test src/main.c

# Rydd opp (fjern den kompilerte fila)
clean:
	rm -f mip_test
