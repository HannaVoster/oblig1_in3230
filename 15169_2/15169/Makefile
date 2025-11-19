

.PHONY: all clean install

# Bygg begge delene av prosjektet
all:
	$(MAKE) -C mipd_and_routing
	$(MAKE) -C transport
	$(MAKE) install

# Kopier binærfiler til prosjektroten 
install:
	cp  bin/mipd .
	cp  bin/miptpd .
	cp  bin/miptpd_client .
	cp  bin/miptpd_server .
	cp  bin/ping_client .
	cp  bin/ping_server .
	cp  bin/routingd .

# Rydd opp i alt
clean:
	$(MAKE) -C mipd_and_routing clean
	$(MAKE) -C transport clean
	rm -f mipd miptpd miptpd_client miptpd_server ping_client ping_server routingd 


