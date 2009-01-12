/*
 * NCtcpsmash/dumper.c
 *
 * (C) 2007,2009, BlackLight <blacklight@autistici.org>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		3 of the License, or (at your option) any later version.
 */

#include "nctcpsmash.h"

/**
 * @brief It prints info about a sniffed packet
 * @param r Reference to the packet
 */
void dump (struct record r)  {
	int i,j,offset;
	int plen = r.len;
	
	char timestamp[20];
	char src[BUFSIZ], dst[BUFSIZ], tmpaddr[BUFSIZ];
	
	unsigned char u8[16];
	unsigned short int check, expect_check;

	struct ethhdr   eth;
	struct iphdr    ip;
	struct tcphdr   tcp;
	struct udphdr   udp;
	struct icmphdr  icmp;
	struct igmp __igmp;
	struct arphdr_t arp;

	struct servent  *serv;
	struct hostent  *host;
	struct tm *t;
	FILE *fp;

	t = localtime(&(r.tv.tv_sec));
	strftime (timestamp, sizeof(timestamp),"%D,%T", t);

	wclear(info);
	wcolor_set (info, 3, NULL);
	wprintw (info, "Packet received at %s\n",timestamp);
	wcolor_set (info, 4, NULL);
	wprintw (info, "Packet length: %u bytes\n\n", plen-dlink_offset);
	wcolor_set (info, 1, NULL);

	if (dump_file)  {
		if (!(fp=fopen(dump_file,"rb")))  {
			endwin();
			fprintf (stderr, "*** Fatal: Unable to read from %s\n", dump_file);
			exit(1);
		}

		fread (&dlink_type, sizeof(int), 1, fp);
		fclose(fp);
	}

	if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )  {
		memcpy (&eth, r.packet, sizeof(struct ethhdr));
	
		wprintw (info, "Source MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
				eth.h_source[0],eth.h_source[1],eth.h_source[2],
				eth.h_source[3],eth.h_source[4],eth.h_source[5]);

		wprintw (info, "Destination MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n\n",
				eth.h_dest[0],eth.h_dest[1],eth.h_dest[2],
				eth.h_dest[3],eth.h_dest[4],eth.h_dest[5]);

		if (eth.h_proto==ntohs(ETH_P_ARP))  {
			memcpy (&arp, r.packet+sizeof(struct ethhdr), sizeof(struct arphdr_t));

			if (arp.ar_op==ntohs(ARPOP_REQUEST))
				wprintw (info,"Type: ARP REQUEST\n");
			if (arp.ar_op==ntohs(ARPOP_REPLY))
				wprintw (info,"Type: ARP REPLY\n");
			if (arp.ar_op==ntohs(ARPOP_RREQUEST))
				wprintw (info,"Type: RARP REQUEST\n");
			if (arp.ar_op==ntohs(ARPOP_RREPLY))
				wprintw (info,"Type: RARP REPLY\n");

			wprintw (info, "Sender MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
					arp.ar_sha[0],arp.ar_sha[1],arp.ar_sha[2],
					arp.ar_sha[3],arp.ar_sha[4],arp.ar_sha[5]);

			wprintw (info, "Sender IP: %d.%d.%d.%d\n",
					arp.ar_sip[0],arp.ar_sip[1],arp.ar_sip[2],arp.ar_sip[3]);

			wprintw (info, "Target MAC: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
					arp.ar_tha[0],arp.ar_tha[1],arp.ar_tha[2],
					arp.ar_tha[3],arp.ar_tha[4],arp.ar_tha[5]);

			wprintw (info, "Target IP: %d.%d.%d.%d\n\n",
					arp.ar_tip[0],arp.ar_tip[1],arp.ar_tip[2],arp.ar_tip[3]);

			wprintw (info, "Content:\n\n");
			goto show;
		}
	} else {
		if (dump_file)
			dlink_offset = get_dlink_offset(dlink_type);

		for (i=0; i < plen; i++)
			r.packet[i] = r.packet[i+dlink_offset];
		plen -= dlink_offset;

		goto ipsmash;
	}
	
	if (eth.h_proto==ntohs(ETH_P_IP))  {
	ipsmash:

		if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
			memcpy (&ip, r.packet+sizeof(struct ethhdr), sizeof(struct iphdr));
		else
			memcpy (&ip, r.packet, sizeof(struct iphdr));

		if (!(host = gethostbyaddr(&(ip.saddr), sizeof(ip.saddr), AF_INET)))
			inet_ntop (AF_INET, &(ip.saddr), src, sizeof(src));
		else
			snprintf (src, sizeof(src), "%s", host->h_name);

		wprintw (info,"Source: ");
		wcolor_set (info, 5, NULL);
		wprintw (info, "%s\n", src);
		wcolor_set (info, 1, NULL);

		if (!(host = gethostbyaddr(&(ip.daddr), sizeof(ip.daddr), AF_INET)))
			inet_ntop (AF_INET, &(ip.daddr), dst, sizeof(dst));
		else
			snprintf (dst, sizeof(dst), "%s", host->h_name);

		wprintw (info,"Destination: ");
		wcolor_set (info, 5, NULL);
		wprintw (info, "%s\n", dst);
		wcolor_set (info, 1, NULL);

		check = ip.check;
		ip.check = 0;
		expect_check = csum((u16*) &ip, sizeof(ip) >> 1);

		if (check == expect_check)  {
			wprintw (info,"IP checksum: ");
			wcolor_set (info, 3, NULL);
			wprintw (info, "OK\n\n");
			wcolor_set (info, 1, NULL);
		} else {
			wprintw (info,"IP checksum: ");
			wcolor_set (info, 6, NULL);
			wprintw (info, "KO");
			wcolor_set (info, 1, NULL);
			wprintw (info, " (it was 0x%x, should be 0x%x)\n\n", check,expect_check);
		}
	}

	if (ip.protocol==IPPROTO_ICMP)  {
		if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
			memcpy (&icmp, r.packet+sizeof(struct ethhdr)+sizeof(struct iphdr), sizeof(struct icmphdr));
		else  
			memcpy (&icmp, r.packet+sizeof(struct iphdr), sizeof(struct icmphdr));

		wprintw (info,"Protocol: ");
		wcolor_set (info, 7, NULL);
		wprintw (info,"ICMP\n");
		wcolor_set (info, 1, NULL);

		if (icmp.type==ICMP_ECHOREPLY)  {
			wprintw (info,"Type: ECHO REPLY\n\n");
		}

		if (icmp.type==ICMP_DEST_UNREACH)  {
			wprintw (info,"Type: DESTINATION UNREACHABLE\n\n");
		}

		if (icmp.type==ICMP_SOURCE_QUENCH)  {
			wprintw (info,"Type: SOURCE QUENCE\n\n");
		}

		if (icmp.type==ICMP_REDIRECT)  {
			wprintw (info,"Type: REDIRECT\n\n");
		}

		if (icmp.type==ICMP_ECHO)  {
			wprintw (info,"Type: ECHO REQUEST\n\n");
		}

		if (icmp.type==ICMP_TIME_EXCEEDED)  {
			wprintw (info,"Type: TIME EXCEEDED\n\n");
		}

		if (icmp.type==ICMP_PARAMETERPROB)  {
			wprintw (info,"Type: PARAMETER PROBLEM\n\n");
		}

		if (icmp.type==ICMP_TIMESTAMP)  {
			wprintw (info,"Type: TIMESTAMP REQUEST\n\n");
		}

		if (icmp.type==ICMP_TIMESTAMPREPLY)  {
			wprintw (info,"Type: TIMESTAMP REPLY\n\n");
		}

		if (icmp.type==ICMP_INFO_REQUEST)  {
			wprintw (info,"Type: INFORMATION REQUEST\n\n");
		}

		if (icmp.type==ICMP_INFO_REPLY)  {
			wprintw (info,"Type: INFORMATION REPLY\n\n");
		}

		if (icmp.type==ICMP_ADDRESS)  {
			wprintw (info,"Type: ADDRESS MASK REQUEST\n\n");
		}

		if (icmp.type==ICMP_ADDRESSREPLY)  {
			wprintw (info,"Type: ADDRESS MASK REPLY\n\n");
		}
		
		wprintw (info,"Content:\n\n");
	}

	if (ip.protocol==IPPROTO_IGMP)  {
		if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
			memcpy (&__igmp, r.packet+sizeof(struct ethhdr)+sizeof(struct iphdr), sizeof(struct igmp));
		else
			memcpy (&__igmp, r.packet+sizeof(struct iphdr), sizeof(struct igmp));

		inet_ntop (AF_INET, &(__igmp.igmp_group), tmpaddr, sizeof(tmpaddr));
		wprintw (info,"Protocol: ");
		wcolor_set (info, 7, NULL);
		wprintw (info,"IGMP\n");
		wcolor_set (info, 1, NULL);

		switch (__igmp.igmp_type)  {
			case IGMP_MEMBERSHIP_QUERY:
				wprintw (info,"IGMP type: MEMBERSHIP QUERY\n");
				break;

			case IGMP_V1_MEMBERSHIP_REPORT:
			case IGMP_V2_MEMBERSHIP_REPORT:
				wprintw (info,"IGMP type: MEMBERSHIP REPORT\n");
				break;

			case IGMP_V2_LEAVE_GROUP:
				wprintw (info,"IGMP type: LEAVE GROUP\n");
				break;

			case IGMP_DVMRP:
				wprintw (info,"IGMP type: DVMRP routing message\n");
				break;

			case IGMP_PIM:
				wprintw (info,"IGMP type: PIM routing message\n");
				break;

			case IGMP_TRACE:
				wprintw (info,"IGMP type: IGMP trace\n");
				break;

			case IGMP_MTRACE_RESP:
				wprintw (info,"IGMP type: MTRACE response\n");
				break;

			case IGMP_MTRACE:
				wprintw (info,"IGMP type: MTRACE message\n");
				break;
		}

		wprintw (info,"Destination address: %s\n",tmpaddr);
	}

	if (ip.protocol==IPPROTO_UDP)  {
		if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
			memcpy (&udp, r.packet+sizeof(struct ethhdr)+sizeof(struct iphdr), sizeof(struct udphdr));
		else
			memcpy (&udp, r.packet+sizeof(struct iphdr), sizeof(struct udphdr));

		wprintw (info,"Protocol: ");
		wcolor_set (info, 7, NULL);
		wprintw (info,"UDP\n");
		wcolor_set (info, 1, NULL);

		if (ntohs(udp.source) < 0x8000)  {
			if ((serv = getservbyport(udp.source, NULL)))
				wprintw (info,"Source port: %d [%s]\n", ntohs(udp.source), serv->s_name);
			else
				wprintw (info,"Source port: %d\n",ntohs(udp.source));
		} else
			wprintw (info,"Source port: %d\n",ntohs(udp.source));

		if (ntohs(udp.dest) < 0x8000)  {
			if ((serv = getservbyport(udp.dest, NULL)))
				wprintw (info,"Destination port: %d [%s]\n", ntohs(udp.dest), serv->s_name);
			else
				wprintw (info,"Destination port: %d\n",ntohs(udp.dest));
		}
		else
			wprintw (info,"Destination port: %d\n\n",ntohs(udp.dest));
		wprintw (info,"Content:\n\n");
	}

	if (ip.protocol==IPPROTO_TCP)  {
		if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
			memcpy (&tcp, r.packet+sizeof(struct ethhdr)+sizeof(struct iphdr), sizeof(struct tcphdr));
		else
			memcpy (&tcp, r.packet+sizeof(struct iphdr), sizeof(struct tcphdr));

		wprintw (info,"Protocol: ");
		wcolor_set (info, 7, NULL);
		wprintw (info,"TCP\n");
		wcolor_set (info, 1, NULL);

		if (ntohs(tcp.source) < 0x8000)  {
			if ((serv = getservbyport(tcp.source, NULL)))
				wprintw (info,"Source port: %d [%s]\n", ntohs(tcp.source), serv->s_name);
			else
				wprintw (info,"Source port: %d\n",ntohs(tcp.source));
		} else
			wprintw (info,"Source port: %d\n",ntohs(tcp.source));

		if (ntohs(tcp.dest) < 0x8000)  {
			if ((serv = getservbyport(tcp.dest, NULL)))
				wprintw (info,"Destination port: %d [%s]\n", ntohs(tcp.dest), serv->s_name);
			else
				wprintw (info,"Destination port: %d\n",ntohs(tcp.dest));
		} else
			wprintw (info,"Destination port: %d\n",ntohs(tcp.dest));

		wprintw (info,"SEQ number: 0x%x\n",htonl(tcp.seq));
		wprintw (info,"ACK number: 0x%x\n",htonl(tcp.ack_seq));
		print_tcp_flags(&tcp);

		wprintw (info,"\nContent:\n\n");
	}

show:
	for (i=0; i < plen - ( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(struct ethhdr) : 0) ; i++)  {
		if (capinfo->viewmode == hex)  {
			u8[i%8]=r.packet[i + ( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(struct ethhdr) : 0)];

			if (i%8==7)  {
				wprintw (info,"\t");

				for (j=0; j<7; j+=2)
					wprintw (info,"%.2x%.2x ",u8[j],u8[j+1]);
				wprintw (info,"\t");

				for (j=0; j<8; j++)  {
					if (u8[j]>=0x21 && u8[j]<=0x7e)
						wprintw (info,"%c",u8[j]);
					else
						wprintw (info,".");
				}

				wprintw (info,"\n");
			}
		} else {
			u8[i%32]=r.packet[i + ( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(struct ethhdr) : 0)];

			if (i%32==31)  {
				wprintw (info,"\t");

				for (j=0; j<32; j++)  {
					if (u8[j]>=0x21 && u8[j]<=0x7e)
						wprintw (info,"%c",u8[j]);
					else
						wprintw (info,".");
				}

				wprintw (info,"\n");
			}
		}
	}

	offset = plen - (int) (plen/8)*8;
	wprintw (info,"\t");

	for (i=0; i<offset; i+=2)
		wprintw (info,"%.2x%.2x ",u8[i],u8[i+1]);
	wprintw (info,"\n\n");

	wrefresh(info);
}

