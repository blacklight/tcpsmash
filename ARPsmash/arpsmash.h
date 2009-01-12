/*
 * ARPsmash/arpsmash.h
 *
 * (C) 2007,2009, BlackLight <blacklight@autistici.org>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		3 of the License, or (at your option) any later version.
 */

#ifndef __ARPSMASH_H
#define __ARPSMASH_H

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

#define	NORMAL	"\033[0m"
#define	BOLD		"\033[1m"
#define	RED		"\033[91m"
#define	GREEN	"\033[92m"
#define	YELLOW	"\033[01;93m"
#define	CYAN		"\033[01;36m"

#define	VERSION		"0.3.2"
#define	TIMEOUT		1
#define	DELAY		10
#define	ETH_LEN		14
#define	PACK_MAXSIZE	65535
#define	SEND_DELAY	10000

typedef unsigned char __u8; 
typedef unsigned short __u16;

/**
 * @brief All-purpose socket descriptor
 */
int sd;

/**
 * @brief Data link sockaddr descriptor
 */
struct sockaddr_ll dlink;

/**
 * @brief My HW address
 */
__u8 *t_hw;

/**
 * @brief Targets' HW addresses
 */
__u8 *t1_hw,*t2_hw;

/**
 * @brief Targets' names/addresses
 */
__u8 *t1,*t2;

/**
 * @brief Network interface to sniff
 */
__u8 *ifc;

/**
 * @brief Struct to manage ARP headers
 */
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

#endif

