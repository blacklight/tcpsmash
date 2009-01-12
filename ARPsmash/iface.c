#include "arpsmash.h"

__u8* get_hw_addr(char *ifc)  {
	int raw=socket(AF_INET,SOCK_DGRAM,0);
	unsigned char *hwaddr = (unsigned char*) malloc(ETH_ALEN);
	struct ifreq ifr;
	
	strncpy (ifr.ifr_name,ifc,sizeof(ifr.ifr_name));
	ioctl(raw,SIOCGIFHWADDR,&ifr);
	memcpy (hwaddr,&ifr.ifr_hwaddr.sa_data,ETH_ALEN);
	return hwaddr;
}

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

void* hw_addr (void *arg)  {
	struct arp_hdr arp;
	struct sockaddr_ll sll;
	int sll_size=sizeof(sll);
	__u8 *inaddr = (__u8*) arg;

	while (1)  {
		if (recvfrom(sd, &arp, sizeof(arp), 0, (struct sockaddr*) &sll, &sll_size)<0)
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

__u8* get_host_addr (__u8 *host)  {
	struct hostent *h;
	__u8 *addr = (__u8*) malloc(INET6_ADDRSTRLEN);

	if (!(h=gethostbyname(host)))
		return NULL;

	inet_ntop(AF_INET,h->h_addr,addr,INET6_ADDRSTRLEN);
	return addr;
}

