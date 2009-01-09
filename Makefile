HAS_GC=-D_HAS_GC
LDGC=-lgc
CFLAGS=-g -Wall ${HAS_GC}
LDTCPSMASH=-lpcap ${LDGC}
LDNCTCPSMASH=-lpcap -lncurses ${LDGC}

all:
	gcc ${CFLAGS} -o tcpsmash main.c pack_handle.c misc.c file.c ${LDTCPSMASH}
	gcc ${CFLAGS} -o nctcpsmash NCtcpsmash/main.c NCtcpsmash/pack_handle.c NCtcpsmash/dumper.c NCtcpsmash/misc.c NCtcpsmash/file.c NCtcpsmash/list.c ${LDNCTCPSMASH}

install:
	cp tcpsmash /usr/local/bin
	cp nctcpsmash /usr/local/bin
	mkdir -p /usr/local/man
	mkdir -p /usr/local/man/man7
	cp tcpsmash.7.gz /usr/local/man/man7
	cp nctcpsmash.7.gz /usr/local/man/man7

clean:
	rm tcpsmash
	rm nctcpsmash

uninstall:
	rm /usr/local/bin/tcpsmash
	rm /usr/local/man/man7/tcpsmash.7.gz
	rm /usr/local/man/man7/nctcpsmash.7.gz
