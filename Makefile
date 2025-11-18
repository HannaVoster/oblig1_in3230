

.PHONY: all clean install

# Bygg begge delene av prosjektet
all:
	$(MAKE) -C mipd_and_routing
	$(MAKE) -C transport
	$(MAKE) install

# Kopier binærfiler til prosjektroten 
install:
	cp -u bin/mipd .
	cp -u bin/miptpd .
	cp -u bin/miptpd_client .
	cp -u bin/miptpd_server .
	cp -u bin/ping_client .
	cp -u bin/ping_server .
	cp -u bin/routingd .

# Rydd opp i alt
clean:
	$(MAKE) -C mipd_and_routing clean
	$(MAKE) -C transport clean
	rm -f mipd miptpd miptpd_client miptpd_server ping_client ping_server routingd 


