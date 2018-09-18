CFLAGS ?= -Wall -Wextra -Werror -g -O2
CFLAGS+=`pkg-config --cflags fuse`
CFLAGS+=`pkg-config --cflags smbclient`
LDLIBS=-lsmbclient -lfuse

all: foxtrot

foxtrot: foxtrot.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

install:
	install -d $(DESTDIR)/usr/bin
	install -m 755 foxtrot $(DESTDIR)/usr/bin

clean:
	rm -f foxtrot

.PHONY: all clean
