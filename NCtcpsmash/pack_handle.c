/*
 * pack_handle.c
 *
 * (C) 2007,2009, BlackLight <blacklight@autistici.org>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		3 of the License, or (at your option) any later version.
 */

#include "nctcpsmash.h"

void pack_handle(u_char *pnull, const struct pcap_pkthdr *p_info, const u_char *packet)  {
	int plen;
	int tcpflags = 0;
	unsigned short int check, expect_check;
	char src[BUFSIZ], dst[BUFSIZ], tmpaddr[BUFSIZ];

	struct ethhdr   eth;
	struct iphdr    ip;
	struct tcphdr   tcp;
	struct udphdr   udp;
	struct icmphdr  icmp;
	struct arphdr_t arp;
	struct igmp __igmp;

	struct servent  *serv;
	struct hostent  *host;
	struct record   r;

	memset (&r, 0x0, sizeof(struct record));
	r.len = p_info->len;
	plen  = r.len;
	memcpy (&(r.packet), packet, plen);

	if (strfilter)  {
		if (!check_filter(strfilter, packet,plen))
			return;
	}

	r.tv.tv_sec  = p_info->ts.tv_sec;
	r.tv.tv_usec = p_info->ts.tv_usec;
	(capinfo->npack)++;

	if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )  {
		memcpy (&eth, packet, sizeof(struct ethhdr));
	
		if (eth.h_proto==ntohs(ETH_P_ARP))  {
			memcpy (&arp, packet+sizeof(struct ethhdr), sizeof(struct arphdr_t));

			if (arp.ar_op==ntohs(ARPOP_REQUEST))
				snprintf (r.descr, sizeof(r.descr),
						"arp who-has %d.%d.%d.%d tell %d.%d.%d.%d\n",
						arp.ar_tip[0],arp.ar_tip[1],arp.ar_tip[2],arp.ar_tip[3],
						arp.ar_sip[0],arp.ar_sip[1],arp.ar_sip[2],arp.ar_sip[3]
						);
			else if (arp.ar_op==ntohs(ARPOP_REPLY))
				snprintf (r.descr, sizeof(r.descr),
						"arp reply %d.%d.%d.%d is-at %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
						arp.ar_sip[0],arp.ar_sip[1],arp.ar_sip[2],arp.ar_sip[3],
						arp.ar_sha[0],arp.ar_sha[1],arp.ar_sha[2],
						arp.ar_sha[3],arp.ar_sha[4],arp.ar_sha[5]
						);
			fflush(stdout);
		}
	} else {
		packet += dlink_offset;
		plen -= dlink_offset;
		goto ipsmash;
	}
	
	if (eth.h_proto==ntohs(ETH_P_IP))  {
		ipsmash:

		if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
			memcpy (&ip, packet+sizeof(struct ethhdr), sizeof(struct iphdr));
		else
			memcpy (&ip, packet, sizeof(struct iphdr));

		sprintf (r.descr, "IP ");

		if (!(host = gethostbyaddr(&(ip.saddr), sizeof(ip.saddr), AF_INET)))
			inet_ntop (AF_INET, &(ip.saddr), src, sizeof(src));
		else
			snprintf (src, sizeof(src), "%s", host->h_name);

		if (!(host = gethostbyaddr(&(ip.daddr), sizeof(ip.daddr), AF_INET)))
			inet_ntop (AF_INET, &(ip.daddr), dst, sizeof(dst));
		else
			snprintf (dst, sizeof(dst), "%s", host->h_name);

		check = ip.check;
		ip.check = 0;
		expect_check = csum((u16*) &ip, sizeof(ip) >> 1);

		if (ip.protocol==IPPROTO_ICMP)  {
			if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
				memcpy (&icmp, packet+sizeof(struct ethhdr)+sizeof(struct iphdr), sizeof(struct icmphdr));
			else
				memcpy (&icmp, packet+sizeof(struct iphdr), sizeof(struct icmphdr));

			if (icmp.type==ICMP_ECHOREPLY)  {
				sprintf (r.descr, "%s%s > %s: ICMP echo reply\n",
						r.descr, src, dst);
			}
			
			if (icmp.type==ICMP_DEST_UNREACH)  {
				sprintf (r.descr,
						"%s%s > %s: ICMP destination unreachable\n",
						r.descr, src, dst);
			}

			if (icmp.type==ICMP_SOURCE_QUENCH)  {
				sprintf (r.descr,
						"%s%s > %s: ICMP source quence\n",
						r.descr, src, dst);
			}

			if (icmp.type==ICMP_REDIRECT)  {
				sprintf (r.descr,
						"%s%s > %s: ICMP redirect\n",
						r.descr, src, dst);
			}
		
			if (icmp.type==ICMP_ECHO)  {
				sprintf (r.descr,
						"%s%s > %s: ICMP echo request\n",
						r.descr, src, dst);
			}

			if (icmp.type==ICMP_TIME_EXCEEDED)  {
				sprintf (r.descr,
						"%s%s > %s: ICMP time exceeded\n",
						r.descr, src, dst);
			}

			if (icmp.type==ICMP_PARAMETERPROB)  {
				sprintf (r.descr,
						"%s%s > %s: ICMP parameter problem\n",
						r.descr, src, dst);
			}

			if (icmp.type==ICMP_TIMESTAMP)  {
				sprintf (r.descr,
						"%s%s > %s: ICMP timestamp request\n",
						r.descr, src, dst);
			}

			if (icmp.type==ICMP_TIMESTAMPREPLY)  {
				sprintf (r.descr,
						"%s%s > %s: ICMP timestamp reply\n",
						r.descr, src, dst);
			}

			if (icmp.type==ICMP_INFO_REQUEST)  {
				sprintf (r.descr,
						"%s%s > %s: ICMP information request\n",
						r.descr, src, dst);
			}

			if (icmp.type==ICMP_INFO_REPLY)  {
				sprintf (r.descr,
						"%s%s > %s: ICMP information reply\n",
						r.descr, src, dst);
			}

			if (icmp.type==ICMP_ADDRESS)  {
				sprintf (r.descr,
						"%s%s > %s: ICMP address mask request",
						r.descr, src, dst);
			}

			if (icmp.type==ICMP_ADDRESSREPLY)  {
				sprintf (r.descr,
						"%s%s > %s: ICMP address mask reply\n",
						r.descr, src, dst);
			}
		}

		if (ip.protocol==IPPROTO_IGMP)  {
			if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
				memcpy (&__igmp, packet+sizeof(struct ethhdr)+sizeof(struct iphdr), sizeof(struct igmp));
			else
				memcpy (&__igmp, packet+sizeof(struct iphdr), sizeof(struct igmp));
			
			inet_ntop (AF_INET, &(__igmp.igmp_group), tmpaddr, sizeof(tmpaddr));
			printf ("%s > %s: IGMP, type: %d\n", src, dst, __igmp.igmp_type);
		}

		if (ip.protocol==IPPROTO_UDP)  {
			if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
				memcpy (&udp, packet+sizeof(struct ethhdr)+sizeof(struct iphdr), sizeof(struct udphdr));
			else
				memcpy (&udp, packet+sizeof(struct iphdr), sizeof(struct udphdr));
			
			if (ntohs(udp.source) < 0x8000)  {
				if ((serv = getservbyport(udp.source, NULL)))
					sprintf (r.descr, "%s%s.%s > ", r.descr, src, serv->s_name);
				else
					sprintf (r.descr, "%s%s.%u > ", r.descr, src, ntohs(udp.source));
			} else
				sprintf (r.descr, "%s%s.%u > ", r.descr, src, ntohs(udp.source));

			if (ntohs(udp.dest) < 0x8000)  {
				if ((serv = getservbyport(udp.dest, NULL)))
					sprintf (r.descr,
							"%s%s.%s: UDP\n", r.descr, dst, serv->s_name);
				else
					sprintf (r.descr,
							"%s%s.%u: UDP\n", r.descr, dst, ntohs(udp.dest));
			} else
				sprintf (r.descr,
						"%s%s.%u: UDP\n", r.descr, dst, ntohs(udp.dest));
		}

		if (ip.protocol==IPPROTO_TCP)  {
			if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
				memcpy (&tcp, packet+sizeof(struct ethhdr)+sizeof(struct iphdr), sizeof(struct tcphdr));
			else
				memcpy (&tcp, packet+sizeof(struct iphdr), sizeof(struct tcphdr));

			if (ntohs(udp.source) < 0x8000)  {
				if ((serv = getservbyport(udp.source, NULL)))
					sprintf (r.descr,
							"%s%s.%s > ", r.descr, src, serv->s_name);
				else
					sprintf (r.descr,
							"%s%s.%u > ", r.descr, src, ntohs(tcp.source));
			} else
				sprintf (r.descr, "%s%s.%u > ", r.descr, src, ntohs(tcp.source));

			if (ntohs(udp.dest) < 0x8000)  {
				if ((serv = getservbyport(udp.dest, NULL)))
					sprintf (r.descr, "%s%s.%s ", r.descr, dst, serv->s_name);
				else
					sprintf (r.descr, "%s%s.%u ", r.descr, dst, ntohs(tcp.dest));
			} else
				sprintf (r.descr, "%s%s.%u ", r.descr, dst, ntohs(tcp.dest));

			if (tcp.syn)  {
				sprintf (r.descr, "%sS", r.descr);
				tcpflags = 1;
			}

			if (tcp.ack)  {
				sprintf (r.descr, "%sA", r.descr);
				tcpflags = 1;
			}

			if (tcp.rst)  {
				sprintf (r.descr, "%sR", r.descr);
				tcpflags = 1;
			}

			if (tcp.fin)  {
				sprintf (r.descr, "%sF", r.descr);
				tcpflags = 1;
			}

			if (tcp.psh)  {
				sprintf (r.descr, "%sP", r.descr);
				tcpflags = 1;
			}

			if (!tcpflags)
				sprintf (r.descr, "%s.", r.descr);
			sprintf (r.descr, "%s\n", r.descr);
		}
	}

	write (fd, &r, sizeof(struct record));
	kill (pid[1], SIGUSR1);
}

