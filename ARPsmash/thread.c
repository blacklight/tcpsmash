/*
 * ARPsmash/thread.c
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
 * @brief Thread for forwarding sniffed packets to the right targets
 */
void* forward (void *arg)  {
	__u8 pack[PACK_MAXSIZE];
	struct ethhdr eth;
	struct iphdr ip;
	struct sockaddr_ll sll;
	struct ifreq ifr;
	int raw,sll_size=sizeof(sll);
	__u8 *myhw;

	bzero (&sll,sizeof(sll));
	bzero (&ifr,sizeof(ifr));
	myhw=get_hw_addr((char*) ifc);

	if((raw=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0)  {
		fprintf (stderr,"%s***Error: Unable to initialize raw socket: %s%s\n", RED, strerror(errno), NORMAL);
		die(-1);
	}

	strncpy((char *)ifr.ifr_name, (char*) ifc, IFNAMSIZ);

	if((ioctl(raw, SIOCGIFINDEX, &ifr))<0)  {
		fprintf (stderr,"%s***Error: Unable to ioctl(): %s%s\n", RED, strerror(errno), NORMAL);
		die(-2);
	}

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_halen=ETH_ALEN;
	memcpy (&sll.sll_addr, (__u8*) myhw, ETH_ALEN);

	if(bind(raw, (struct sockaddr*) &sll, sll_size)<0)  {
		fprintf (stderr,"%s***Error: Unable to bind: %s%s\n", RED, strerror(errno), NORMAL);
		die(-3);
	}

	while (1)  {
		bzero (pack,sizeof(pack));
		bzero (&eth,sizeof(eth));
		bzero (&ip,sizeof(ip));

		if (recvfrom(raw, (__u8*) pack, PACK_MAXSIZE, 0, (struct sockaddr*) &sll, (unsigned int*) &sll_size)<0)  {
			fprintf (stderr,"%s***Error while receiving from %s: %s%s\n", RED, ifc, strerror(errno), NORMAL);
			die(-4);
		}

		memcpy (&eth,pack,sizeof(eth));
		memcpy (&ip,pack+ETH_LEN,sizeof(ip));

		char addr[INET6_ADDRSTRLEN];
		inet_ntop (AF_INET,&ip.daddr,addr,sizeof(addr));

		if (ip.daddr==inet_addr((char*) t1) || ip.daddr==inet_addr((char*) t2))  {
			unsigned short int len=htons(ip.tot_len)+ETH_LEN;
			memcpy (eth.h_source, (__u8*) myhw, ETH_ALEN);

			if (ip.daddr==inet_addr((char*) t1))  {
				memcpy (eth.h_dest, (__u8*) t1_hw, ETH_ALEN);
				memcpy (pack, (void*) &eth, sizeof(eth));
			}

			if (ip.daddr==inet_addr((char*) t2))  {
				memcpy (eth.h_dest, (__u8*) t2_hw, ETH_ALEN);
				memcpy (pack, (void*) &eth, sizeof(eth));
			}

			if (sendto(raw, (__u8*) pack, len, 0,
						(struct sockaddr*) &sll, sizeof(struct sockaddr_ll))<0)  {
				fprintf (stderr,"%s***Error in sendto: %s%s\n", RED, strerror(errno), NORMAL);
			}
		}
	}
}

