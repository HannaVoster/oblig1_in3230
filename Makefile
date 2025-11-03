

.PHONY: all clean install

all:
	$(MAKE) -C mipd
	$(MAKE) -C transport
	$(MAKE) install

# Kopier binærfiler ut i prosjektroten for kompatibilitet 
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
clean:
	$(MAKE) -C mipd clean
	$(MAKE) -C transport clean
	rm -f mipd miptpd miptpd_client miptpd_server ping_client ping_server routingd

