#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/signal.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netdb.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <pthread.h>

#define	TIMEOUT		1
#define	DELAY		10
#define	ETH_LEN		14
#define	PACK_MAXSIZE	65535
#define	SEND_DELAY	10000

typedef unsigned char __u8; 
typedef unsigned short __u16;

int sd;
struct sockaddr_ll dlink;
__u8 *t_hw;
__u8 *t1_hw,*t2_hw;
__u8 *t1,*t2;
__u8 *ifc;

struct arp_hdr {
	__u16  hw_format;
	__u16  prot_format;
	__u8   hw_len;
	__u8   prot_len;
	__u16  opcode;
	__u8  hw_sender[ETH_ALEN];
	__u8  ip_sender[4];
	__u8  hw_target[ETH_ALEN];
	__u8  ip_target[4];
};

__u8* get_hw_addr(char *ifc);
__u8* get_host_addr (__u8 *host);

char* get_ipv4_addr(char *ifc);
int ifindex (char *ifc);
int doarp();
int arpsmash (__u8* interface, __u8* addr1, __u8* addr2);

void handle(int sig);
void term(int sig);
void die(int ret);
void* hw_addr (void *arg);
void* forward (void *arg);

