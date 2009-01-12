/*
 * ARPsmash/iface.c
 *
 * (C) 2007,2009, BlackLight <blacklight@autistici.org>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		3 of the License, or (at your option) any later version.
 */

#include "arpsmash.h"

/**
 * @brief It gets the HW address associated to a network interface
 * @param ifc Interface name
 * @return HW address
 */
__u8* get_hw_addr(char *ifc)  {
	int raw=socket(AF_INET,SOCK_DGRAM,0);
	unsigned char *hwaddr = (unsigned char*) malloc(ETH_ALEN);
	struct ifreq ifr;
	
	strncpy (ifr.ifr_name,ifc,sizeof(ifr.ifr_name));
	ioctl(raw,SIOCGIFHWADDR,&ifr);
	memcpy (hwaddr,&ifr.ifr_hwaddr.sa_data,ETH_ALEN);
	return hwaddr;
}

/**
 * @brief It gets the IP address associated to a network interface
 * @param ifc Interface name
 * @return IP address
 */
char* get_ipv4_addr(char *ifc)  {
	int raw=socket(AF_INET,SOCK_STREAM,0);
	struct ifreq ifr;

	strncpy (ifr.ifr_name,ifc,sizeof(ifr.ifr_name));
	struct sockaddr_in *sin = (struct sockaddr_in*) &ifr.ifr_addr;

	ioctl(raw,SIOCGIFNAME,&ifr);
	ioctl(raw,SIOCGIFADDR,&ifr);

	if (!sin->sin_addr.s_addr) return NULL;
	else return inet_ntoa(sin->sin_addr);
}

/**
 * @brief It gets the index of a network interface
 * @param ifc Interface name
 * @return -1 in case of error, network interface's index elsewhere
 */
int ifindex (char *ifc)  {
	int raw;
	struct ifreq ifr;

	if ((raw=socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP)))<0)
		return -1;

	strncpy((char *)ifr.ifr_name, ifc, IFNAMSIZ);

	if(ioctl(raw,SIOCGIFINDEX,&ifr) < 0) 
		return -1;
	return ifr.ifr_ifindex;
}

/**
 * @brief Function associated to a thread that gets HW address of a given IP address analyzing its ARP replies
 * @param arg IP addr
 */
void* hw_addr (void *arg)  {
	struct arp_hdr arp;
	struct sockaddr_ll sll;
	int sll_size=sizeof(sll);
	__u8 *inaddr = (__u8*) arg;

	while (1)  {
		if (recvfrom(sd, &arp, sizeof(arp), 0, (struct sockaddr*) &sll, (unsigned int*) &sll_size)<0)
			return NULL;

		if (arp.opcode==htons(ARPOP_REPLY) && !memcmp(inaddr,arp.ip_sender,
					sizeof(arp.ip_sender)))
			break;
	}

	t_hw = (__u8*) malloc(sizeof(arp.hw_sender));
	memcpy (t_hw, &arp.hw_sender, sizeof(arp.hw_sender));
	kill (getpid(),SIGUSR1);
	pthread_exit(0);
}

/**
 * @brief It returns IP addr of a host given its host name
 * @param host Host name
 * @return host's IP address
 */
__u8* get_host_addr (__u8 *host)  {
	struct hostent *h;
	__u8 *addr = (__u8*) malloc(INET6_ADDRSTRLEN);

	if (!(h=gethostbyname((char*) host)))
		return NULL;

	inet_ntop(AF_INET, h->h_addr, (char*) addr, INET6_ADDRSTRLEN);
	return addr;
}

