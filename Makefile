all:
	gcc -Ilibpcap-1.9.0 -o sniffer sniffer.c ~/libpcap-1.9.0/libpcap.a
clean:
	rm sniffer

