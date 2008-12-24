all:
	gcc -Wall -o tcpsmash main.c pack_handle.c misc.c file.c -lpcap -g
install:
	cp tcpsmash /usr/bin
	mkdir -p /usr/man
	mkdir -p /usr/man/man7
	cp tcpsmash.7.gz /usr/man/man7
clean:
	rm tcpsmash

uninstall:
	rm /usr/bin/tcpsmash
	rm /usr/man/man7/tcpsmash.7.gz
