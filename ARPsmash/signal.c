/*
 * ARPsmash/signal.c
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
 * @brief This function does nothing. It's just used to manage signals for which I want no direct action
 * @param sig Signal number
 */
void handle(int sig)  {}

/**
 * @brief Function called when exiting ARPsmash. It re-ARPs target hosts correctly
 * @param sig Signal number
 */
void term(int sig)  {
	struct in_addr ip4addr;
	struct arp_hdr arp;

	printf ("\n%s*** Signal %d caught. Re-ARPing victims...%s\n", CYAN, sig, NORMAL);

	arp.hw_format=htons(ARPHRD_ETHER);
	arp.prot_format=htons(ETH_P_IP);
	arp.hw_len=ETH_ALEN;
	arp.prot_len=4;
	arp.opcode=htons(ARPOP_REPLY);

	memcpy (&dlink.sll_addr, (__u8*) t1_hw, ETH_ALEN);
	ip4addr.s_addr=inet_addr((char*) t1);
	memcpy (arp.ip_sender, (__u8*) &ip4addr, sizeof(arp.ip_sender));
	memcpy (arp.hw_sender, (__u8*) t1_hw, sizeof(arp.hw_sender));

	ip4addr.s_addr=inet_addr((char*) t2);
	memcpy (arp.ip_target, (__u8*) &ip4addr, sizeof(ip4addr));
	memcpy (arp.hw_target, (__u8*) t2_hw, sizeof(arp.hw_target));
	
	if (sendto(sd, &arp, sizeof(arp), 0, (struct sockaddr*) &dlink, sizeof(dlink))<0)  {
		fprintf (stderr,"\t*** Error in sendto: %s\n",strerror(errno));
		exit(-2);
	}

	memcpy (&dlink.sll_addr, (__u8*) t2_hw, ETH_ALEN);
	ip4addr.s_addr=inet_addr((char*) t2);
	memcpy (arp.ip_sender, (__u8*) &ip4addr, sizeof(arp.ip_sender));
	memcpy (arp.hw_sender, (__u8*) t2_hw, sizeof(arp.hw_sender));

	ip4addr.s_addr=inet_addr((char*) t1);
	memcpy (arp.ip_target, (__u8*) &ip4addr, sizeof(ip4addr));
	memcpy (arp.hw_target, (__u8*) t1_hw, sizeof(arp.hw_target));

	if (sendto(sd, &arp, sizeof(arp), 0, (struct sockaddr*) &dlink, sizeof(dlink))<0)  {
		fprintf (stderr,"\t*** Error in sendto: %s\n",strerror(errno));
		exit(-2);
	}

	printf ("%s*** Re-ARP OK, exiting...%s\n", GREEN, NORMAL);
	exit(0);
}

/**
 * @brief Function called whenever ARPsmash execution ends anomally
 * @param ret Return value
 */
void die(int ret)  {
	term(ret);
}

