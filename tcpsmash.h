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
#define	VERSION	"0.3.2"

#define	NORMAL	"\033[0m"
#define	BOLD		"\033[1m"
#define	RED		"\033[91m"
#define	GREEN	"\033[92m"
#define	YELLOW	"\033[01;93m"

/**
 * @brief Struct to manipulate ARP headers
 */
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

/**
 * @brief Pseudo-enum to manipulate boolean types
 */
typedef enum { false,true } bool;

/**
 * @brief true if I want to see TCP flags for each packet, false elsewhere. Just kept for back-compatibility
 */
bool use_flags;

/**
 * @brief true if each packet must be dumped without any analysis, false elsewhere
 */
bool use_dump;

/**
 * @brief true if the traffic will be saved on a logfile, false elsewhere
 */
bool use_log;

/**
 * @brief true if I'm examinating a log file, false elsewhere
 */
bool undumping;

/**
 * @brief true if I'm using quick tcpdump-like view for each packet, false if I'm using detailed view (default)
 */
bool quick;

/**
 * @brief true if I'm doing a MITM attack through ARP poisoning, false elsewhere
 */
bool arp;

/**
 * @brief It counts the number of sniffed packets
 */
unsigned int count;

/**
 * @brief Variable set when I'm going to sniff a maximum given number of packets and stop the application
 */
unsigned int maxcount;

/**
 * @brief Data link offset for the given interface
 */
unsigned int dlink_offset;

/**
 * @brief Data link type for the given interface
 */
int dlink_type;

/**
 * @brief String set when I'm filtering traffic content on a given string or regex
 */
char* strfilter;

/**
 * @brief addr1 and addr2 are set when doing a ARP poisoning attack
 */
char *addr1, *addr2;

/**
 * @brief File descriptor to write to. It may be set to stdout (default) or to a log file
 */
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

