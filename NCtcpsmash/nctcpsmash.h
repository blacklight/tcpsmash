#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <errno.h>
#include <netdb.h>

#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>

#include <ncurses.h>
#include <pthread.h>
#include <pcap.h>
#include <regex.h>

#define	VERSION	"0.3"
#define	NORMAL	"\033[0m"
#define	BOLD		"\033[1m"
#define	RED		"\033[91m"
#define	GREEN	"\033[92m"
#define	YELLOW	"\033[01;93m"

#ifdef _HAS_GC
	#include <gc.h>
#else
	#define GC_MALLOC	malloc
	#define GC_REALLOC	realloc
	#define GC_STRDUP	strdup
#endif

struct record  {
	int len;
	struct timeval tv;
	char descr[0x200];
	char packet[0x400];
};

struct _node  {
	int num;
	struct _node *next;
} node;

typedef struct _node *list;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long  u32;
typedef enum  { hex, ascii } mode;

struct arphdr_t
{
	unsigned short ar_hrd;
	unsigned short ar_pro;
	unsigned char  ar_hln;
	unsigned char  ar_pln;
	unsigned short ar_op;
	unsigned char  ar_sha[ETH_ALEN];
	unsigned char  ar_sip[4];
	unsigned char  ar_tha[ETH_ALEN];
	unsigned char  ar_tip[4];
};

struct _CAPINFO {
	int npack;
	mode viewmode;
};

WINDOW *mainw, *w, *line, *status, *head, *info;
struct _CAPINFO *capinfo;

int dlink_type;
int dlink_offset;
int fd, fdpack;
int pid[2];
int SCRSIZ;
int SCRWID;
int undumping;

char *strfilter;
char *dump_file;
struct record *start;

int get_dlink_offset (int dlink_type);
int check_filter(char *filter, const u_char *packet, int plen);

void _refresh();
void dump (struct record r);
void pack_handle(u_char *pnull, const struct pcap_pkthdr *p_info, const u_char *packet);
void print_tcp_flags (struct tcphdr *tcp);
void file_dump (char* file);

char* getline();
u16 csum (u16 *buf, int nwords);

int Contains (int val, list l);
int Head (list l);
list Tail (list l);
list Insert (int val, list l);
list filter_packets (char* filter, int* size);
list get_tcpstream (struct record r, int *size);

