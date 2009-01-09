/*
 * tcpsmash.h
 *
 * (C) 2007,2009, BlackLight <blacklight@autistici.org>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		3 of the License, or (at your option) any later version.
 */

#ifndef	_TCPSMASH_H
#define	_TCPSMASH_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <signal.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <regex.h>

#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>

#ifdef _HAS_GC
	#include <gc.h>
#else
	#define	GC_MALLOC		malloc
	#define	GC_REALLOC	realloc
	#define	GC_STRDUP		strdup
#endif

#define	PROTO	"TCP protocol: %s\n"
#define	VERSION	"0.3"

#define	NORMAL	"\033[0m"
#define	BOLD		"\033[1m"
#define	RED		"\033[91m"
#define	GREEN	"\033[92m"
#define	YELLOW	"\033[01;93m"

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

typedef unsigned char u8;
typedef enum { false,true } bool;

bool use_flags;
bool use_dump;
bool use_log;
bool undumping;
bool quick;

unsigned int count;
unsigned int maxcount;
unsigned int dlink_offset;

int dlink_type;
char* strfilter;
FILE* out;

int get_dlink_offset (int dlink_type);
int preg_match (char* regex, char* s);
void pack_handle (u_char *pnull, const struct pcap_pkthdr *p_info, const u_char *packet);
void foo (int sig);
void help();
void print_proto (int sport, int dport);
void print_tcp_flags (struct tcphdr *tcp);
void file_dump (char* file);
bool check_filter(const u_char *packet, int plen);

#endif

