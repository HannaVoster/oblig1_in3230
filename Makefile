

.PHONY: all clean

all:
	$(MAKE) -C src
	$(MAKE) -C transport

clean:
	$(MAKE) -C src clean
	$(MAKE) -C transport clean
