

.PHONY: all clean install

# Bygg begge delene av prosjektet
all:
	$(MAKE) -C mipd_and_routing
	$(MAKE) -C transport
	$(MAKE) install

# Kopier binærfiler til prosjektroten (for kompatibilitet med testskript)
install:
	cp -u bin/mipd .
	cp -u bin/miptpd .
	cp -u bin/miptpd_client .
	cp -u bin/miptpd_server .
	cp -u bin/ping_client .
	cp -u bin/ping_server .
	cp -u bin/routingd .
	cp -u bin/test_app .
	cp -u bin/test_server .

# Rydd opp i alt
clean:
	$(MAKE) -C mipd_and_routing clean
	$(MAKE) -C transport clean
	rm -f mipd miptpd miptpd_client miptpd_server ping_client ping_server routingd test_app test_server


