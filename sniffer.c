#include <pcap.h>
#include <stdlib.h>
#include <ctype.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>


#define UDPS 0
#define LSNAP 1500
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;
struct sniff_udp {
	u_short uh_sport;
	u_short uh_dport;
	u_short uh_ulen;
	u_short uh_sum;

};
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];
        u_char  ether_shost[ETHER_ADDR_LEN];
        u_short ether_type;
};

struct sniff_ip {
        u_char  ip_vhl;
        u_char  ip_tos;
        u_short ip_len;
        u_short ip_id;
        u_short ip_off;
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char  ip_ttl;
        u_char  ip_p;
        u_short ip_sum;
        struct  in_addr ip_src,ip_dst;
};
void
callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
printer_func(const u_char *data, int len);

void
exiting();

void
exiting()
{
  printf("\nSIGINT detected. Exiting program...\n");
  exit(0);
}

void
printer_func(const u_char *data, int len)
{

	int i;
	const u_char *ch;

	ch = data;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
//    else
//      printf(".");
		ch++;
	}
	printf("\n\n");

return;
}

void
callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	int size_ip;
	const struct sniff_ethernet *ethernet;
	int size_tcp;
	const struct sniff_ip *ip;
	const struct sniff_udp *udp;
	const char *data;
	int sizep;

	ethernet = (struct sniff_ethernet*)(packet);

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
  // IP size is atleast 20.
	if (size_ip < 20) {
		return;
	}
  // Enters if if packet is UDP.
  if (ip->ip_p == IPPROTO_UDP){
    printf( "Sender: %s" , inet_ntoa(ip->ip_src));
    printf( "\nReceiver: %s\nMessage: " , inet_ntoa(ip->ip_dst));

    udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + UDPS);

    data = (u_char *)(packet + SIZE_ETHERNET + size_ip + UDPS);

    sizep = ntohs(ip->ip_len) - (size_ip + UDPS);
    if (sizep > ntohs(udp->uh_ulen))
      sizep = ntohs(udp->uh_ulen);

    // calls printer_func to print the packet payload.
    // doesn't enter the if statement if the size is 0.
    if (sizep > 0) {
      printer_func(data, sizep);
    }
  }

	return;
}

int main(int argc, char **argv)
{
  printf("\n");
  signal(SIGINT, exiting);

	char *dev = NULL;
	char error[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;

	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "Wrong arguments.\n");
		exit(0);
	}
	else {
    // set default device as eth0
		dev = "eth0";
	}
  // enters if no netmask found.
	if (pcap_lookupnet(dev, &net, &mask, error) == -1) {
		net = 0;
		mask = 0;
	}

//	printf("Capturing packets of device %s\n", dev);
//	printf("This program only captures UDP packets.\n\n");


  // dev is the device (default: eth0)
  // LSNAP is the maximum capacity of Ethernet
  // 1 means its in promiscuous mode
	handle = pcap_open_live(dev, LSNAP, 1, 2000, error);
	if (handle == NULL) {
		fprintf(stderr, "Needs sudo to run.\nUsage: sudo ./sniffer\nExiting...\n\n");
		exit(0);
	}

  // 0 means loop doesn't end on its own.
  // our callback function runs with each handle
	pcap_loop(handle, 0, callback, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

return 0;
}

