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

#include "tcpsmash.h"

typedef unsigned short int u16;
typedef unsigned long  int u32;

/**
 * @brief Checksum algorithm
 * @param buf I want to know the checksum of this data portion
 * @param nwords Number of words (number of bits / 16) contained in buf
 * @return buf's checksum
 */
u16 csum (u16 *buf, int nwords)  {
	u32 sum;
	
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
		sum = (sum >> 16) + (sum & 0xffff);
		sum += (sum >> 16);
	return ~sum;
}

/**
 * @brief It checks if a certain string matches a given regex or not
 * @param regex Regular expression
 * @param s String to check
 * @return 1 if s =~ /regex/, 0 elsewhere
 */
int preg_match (char* regex, char* s)  {
	regex_t re;

	if (regcomp(&re,regex,REG_EXTENDED|REG_NOSUB)!=0)
		return -1;
				 
	if (regexec(&re, s, (size_t) 0, NULL, 0))  {
		regfree(&re);
		return 0;
	}
				 
	regfree(&re);
	return 1;
}

/**
 * @brief Function made to manipulate each packet's contents
 * @param pnull NULL pointer
 * @param p_info Struct containing info about the sniffed packet
 * @param packet Packet
 */
void pack_handle(u_char *pnull, const struct pcap_pkthdr *p_info, const u_char *packet)  {
	int i,j,offset = 0;
	int plen = p_info->len;
	int tcpflags = 0;

	unsigned short int check, expect_check;
	time_t ltime;
	struct tm *t;
	char timestamp[20];
	char src[BUFSIZ], dst[BUFSIZ], tmpaddr[BUFSIZ];
	unsigned char u8[16];

	struct ethhdr   eth;
	struct iphdr    ip;
	struct tcphdr   tcp;
	struct udphdr   udp;
	struct icmphdr  icmp;
	struct igmp __igmp;
	struct arphdr_t arp;

	struct timeval  tv;
	struct servent  *serv;
	struct hostent  *host;

	if (strfilter)  {
		if (!check_filter(packet,plen))
			return;
	}

	count++;

	if (use_dump)  {
		if (use_log)  {
			tv.tv_sec  = time(NULL);
			tv.tv_usec = 0;
			fwrite (&tv, sizeof(tv), 1, stdout);
		}

		for (i=0; i<plen; i++)
			printf ("%c",packet[i]);
		return;
	}

	if (!undumping)  {
		ltime = time(NULL);
		t = localtime(&ltime);

		if (!quick)  {
			strftime (timestamp,sizeof(timestamp),"%D,%T",t);
			printf ("%sPacket received at %s%s\n",GREEN,timestamp,NORMAL);
		} else {
			srand((unsigned) time(NULL));
			strftime (timestamp,sizeof(timestamp),"%H:%M:%S",t);
			printf ("%s.%d ", timestamp, rand()%1000000);
			fflush(stdout);
		}
	} else {
		t = localtime(&(p_info->ts.tv_sec));
		
		if (!quick)  {
			strftime (timestamp,sizeof(timestamp),"%D,%T",t);
			printf ("%sPacket received at %s%s\n",GREEN,timestamp,NORMAL);
		} else {
			strftime (timestamp,sizeof(timestamp),"%H:%M:%S",t);
			printf ("%s.%d ", timestamp, (int) p_info->ts.tv_usec);
			fflush(stdout);	
		}
	}

	if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )  {
		memcpy (&eth, packet, sizeof(struct ethhdr));
	
		if (!quick)  {
			printf ("Source MAC: %s%.2x:%.2x:%.2x:%.2x:%.2x:%.2x%s\n",
					BOLD,
					eth.h_source[0],eth.h_source[1],eth.h_source[2],
					eth.h_source[3],eth.h_source[4],eth.h_source[5],
					NORMAL);

			printf ("Destination MAC: %s%.2x:%.2x:%.2x:%.2x:%.2x:%.2x%s\n",
					BOLD,
					eth.h_dest[0],eth.h_dest[1],eth.h_dest[2],
					eth.h_dest[3],eth.h_dest[4],eth.h_dest[5],
					NORMAL);
		}

		if (eth.h_proto==ntohs(ETH_P_ARP))  {
			memcpy (&arp, packet+sizeof(struct ethhdr), sizeof(struct arphdr_t));
			offset += dlink_offset;

			if (!quick)  {
				if (arp.ar_op==ntohs(ARPOP_REQUEST))
					printf ("Type: ARP REQUEST\n");
				if (arp.ar_op==ntohs(ARPOP_REPLY))
					printf ("Type: ARP REPLY\n");
				if (arp.ar_op==ntohs(ARPOP_RREQUEST))
					printf ("Type: RARP REQUEST\n");
				if (arp.ar_op==ntohs(ARPOP_RREPLY))
					printf ("Type: RARP REPLY\n");

				printf ("Sender MAC: %s%.2x:%.2x:%.2x:%.2x:%.2x:%.2x%s\n",
						BOLD,
						arp.ar_sha[0],arp.ar_sha[1],arp.ar_sha[2],
						arp.ar_sha[3],arp.ar_sha[4],arp.ar_sha[5],
						NORMAL);
				printf ("Sender IP: %s%d.%d.%d.%d%s\n",
						BOLD,
						arp.ar_sip[0],arp.ar_sip[1],arp.ar_sip[2],arp.ar_sip[3],
						NORMAL);

				printf ("Target MAC: %s%.2x:%.2x:%.2x:%.2x:%.2x:%.2x%s\n",
						BOLD,
						arp.ar_tha[0],arp.ar_tha[1],arp.ar_tha[2],
						arp.ar_tha[3],arp.ar_tha[4],arp.ar_tha[5],
						NORMAL);

				printf ("Target IP: %s%d.%d.%d.%d%s\n",
						BOLD,
						arp.ar_tip[0],arp.ar_tip[1],arp.ar_tip[2],arp.ar_tip[3],
						NORMAL);

				printf ("\nContent:\n");
				goto content;
			} else {
				if (arp.ar_op==ntohs(ARPOP_REQUEST))
					printf ("arp who-has %d.%d.%d.%d tell %d.%d.%d.%d\n",
							arp.ar_tip[0],arp.ar_tip[1],arp.ar_tip[2],arp.ar_tip[3],
							arp.ar_sip[0],arp.ar_sip[1],arp.ar_sip[2],arp.ar_sip[3]
							);
				else if (arp.ar_op==ntohs(ARPOP_REPLY))
					printf ("arp reply %d.%d.%d.%d is-at %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
							arp.ar_sip[0],arp.ar_sip[1],arp.ar_sip[2],arp.ar_sip[3],
							arp.ar_sha[0],arp.ar_sha[1],arp.ar_sha[2],
							arp.ar_sha[3],arp.ar_sha[4],arp.ar_sha[5]
							);

				fflush(stdout);
			}
		}
	} else {
		packet += dlink_offset;
		plen -= dlink_offset;
		goto ipsmash;
	}
	
	if (eth.h_proto==ntohs(ETH_P_IP))  {
ipsmash:
		offset += dlink_offset + sizeof(struct iphdr);

		if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
			memcpy (&ip, packet+sizeof(struct ethhdr), sizeof(struct iphdr));
		else
			memcpy (&ip, packet, sizeof(struct iphdr));

		if (quick)
			printf ("IP ");

		if (!(host = gethostbyaddr(&(ip.saddr), sizeof(ip.saddr), AF_INET)))
			inet_ntop (AF_INET, &(ip.saddr), src, sizeof(src));
		else
			snprintf (src, sizeof(src), "%s", host->h_name);

		if (!quick)
			printf ("Source: %s%s%s\n",BOLD,src,NORMAL);

		if (!(host = gethostbyaddr(&(ip.daddr), sizeof(ip.daddr), AF_INET)))
			inet_ntop (AF_INET, &(ip.daddr), dst, sizeof(dst));
		else
			snprintf (dst, sizeof(dst), "%s", host->h_name);

		if (!quick)
			printf ("Destination: %s%s%s\n",BOLD,dst,NORMAL);

		check = ip.check;
		ip.check = 0;
		expect_check = csum((u16*) &ip, sizeof(ip) >> 1);

		if (!quick)  {
			if (check == expect_check)
				printf ("IP checksum: %sOK%s\n",GREEN,NORMAL);
			else
				printf ("IP checksum: %sKO%s (it was 0x%x, should be 0x%x)\n",RED,NORMAL,check,expect_check);
		}

		if (ip.protocol==IPPROTO_ICMP)  {
			offset += sizeof(struct icmphdr);

			if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
				memcpy (&icmp, packet+sizeof(struct ethhdr)+sizeof(struct iphdr), sizeof(struct icmphdr));
			else
				memcpy (&icmp, packet+sizeof(struct iphdr), sizeof(struct icmphdr));

			if (!quick)
				printf ("Protocol: ICMP\n");

			if (icmp.type==ICMP_ECHOREPLY)  {
				if (!quick)
					printf ("Type: ECHO REPLY\n");
				else
					printf ("%s > %s: ICMP echo reply, id %d, seq %d, length %lu\n",
							src, dst, icmp.un.echo.id, icmp.un.echo.sequence, (long unsigned int) plen -
										( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(eth) : 0 ) - sizeof(ip));
			}
			
			if (icmp.type==ICMP_DEST_UNREACH)  {
				if (!quick)
					printf ("Type: DESTINATION UNREACHABLE\n");
				else
					printf ("%s > %s: ICMP destination unreachable, id %d, seq %d, length %lu\n",
							src, dst, icmp.un.echo.id, icmp.un.echo.sequence, (long unsigned int) plen -
							 ( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(eth) : 0 ) - sizeof(ip));
			}

			if (icmp.type==ICMP_SOURCE_QUENCH)  {
				if (!quick)
					printf ("Type: SOURCE QUENCE\n");
				else
					printf ("%s > %s: ICMP source quence, id %d, seq %d, length %lu\n",
							src, dst, icmp.un.echo.id, icmp.un.echo.sequence, (long unsigned int) plen -
							( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(eth) : 0 ) - sizeof(ip));
			}

			if (icmp.type==ICMP_REDIRECT)  {
				if (!quick)
					printf ("Type: REDIRECT\n");
				else
					printf ("%s > %s: ICMP redirect, id %d, seq %d, length %lu\n",
							src, dst, icmp.un.echo.id, icmp.un.echo.sequence, (long unsigned int) plen -
							( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(eth) : 0 ) - sizeof(ip));
			}
		
			if (icmp.type==ICMP_ECHO)  {
				if (!quick)
					printf ("Type: ECHO REQUEST\n");
				else
					printf ("%s > %s: ICMP echo request, id %d, seq %d, length %lu\n",
							src, dst, icmp.un.echo.id, icmp.un.echo.sequence, (long unsigned int) plen -
							( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(eth) : 0 ) - sizeof(ip));
			}

			if (icmp.type==ICMP_TIME_EXCEEDED)  {
				if (!quick)
					printf ("Type: TIME EXCEEDED\n");
				else
					printf ("%s > %s: ICMP time exceeded, id %d, seq %d, length %lu\n",
							src, dst, icmp.un.echo.id, icmp.un.echo.sequence, (long unsigned int) plen -
							( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(eth) : 0 ) - sizeof(ip));
			}

			if (icmp.type==ICMP_PARAMETERPROB)  {
				if (!quick)
					printf ("Type: PARAMETER PROBLEM\n");
				else
					printf ("%s > %s: ICMP parameter problem, id %d, seq %d, length %lu\n",
							src, dst, icmp.un.echo.id, icmp.un.echo.sequence, (long unsigned int) plen -
							( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(eth) : 0 ) - sizeof(ip));
			}

			if (icmp.type==ICMP_TIMESTAMP)  {
				if (!quick)
					printf ("Type: TIMESTAMP REQUEST\n");
				else
					printf ("%s > %s: ICMP timestamp request, id %d, seq %d, length %lu\n",
							src, dst, icmp.un.echo.id, icmp.un.echo.sequence, (long unsigned int) plen -
							( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(eth) : 0 ) - sizeof(ip));
			}

			if (icmp.type==ICMP_TIMESTAMPREPLY)  {
				if (!quick)
					printf ("Type: TIMESTAMP REPLY\n");
				else
					printf ("%s > %s: ICMP timestamp reply, id %d, seq %d, length %lu\n",
							src, dst, icmp.un.echo.id, icmp.un.echo.sequence, (long unsigned int) plen -
							( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(eth) : 0 ) - sizeof(ip));
			}

			if (icmp.type==ICMP_INFO_REQUEST)  {
				if (!quick)
					printf ("Type: INFORMATION REQUEST\n");
				else
					printf ("%s > %s: ICMP information request, id %d, seq %d, length %lu\n",
							src, dst, icmp.un.echo.id, icmp.un.echo.sequence, (long unsigned int) plen -
							( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(eth) : 0 ) - sizeof(ip));
			}

			if (icmp.type==ICMP_INFO_REPLY)  {
				if (!quick)
					printf ("Type: INFORMATION REPLY\n");
				else
					printf ("%s > %s: ICMP information reply, id %d, seq %d, length %lu\n",
							src, dst, icmp.un.echo.id, icmp.un.echo.sequence, (long unsigned int) plen -
							( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(eth) : 0 ) - sizeof(ip));
			}

			if (icmp.type==ICMP_ADDRESS)  {
				if (!quick)
					printf ("Type: ADDRESS MASK REQUEST\n");
				else
					printf ("%s > %s: ICMP address mask request, id %d, seq %d, length %lu\n",
							src, dst, icmp.un.echo.id, icmp.un.echo.sequence, (long unsigned int) plen -
							( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(eth) : 0 ) - sizeof(ip));
			}

			if (icmp.type==ICMP_ADDRESSREPLY)  {
				if (!quick)
					printf ("Type: ADDRESS MASK REPLY\n");
				else
					printf ("%s > %s: ICMP address mask reply, id %d, seq %d, length %lu\n",
							src, dst, icmp.un.echo.id, icmp.un.echo.sequence, (long unsigned int) plen -
							( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(eth) : 0 ) - sizeof(ip));
			}

			if (quick)
				return;
		}

		if (ip.protocol==IPPROTO_IGMP)  {
			offset += sizeof(struct igmp);

			if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
				memcpy (&__igmp, packet+sizeof(struct ethhdr)+sizeof(struct iphdr), sizeof(struct igmp));
			else
				memcpy (&__igmp, packet+sizeof(struct iphdr), sizeof(struct igmp));
			
			inet_ntop (AF_INET, &(__igmp.igmp_group), tmpaddr, sizeof(tmpaddr));

			if (!quick)  {
				printf ("Protocol: IGMP\n");

				switch (__igmp.igmp_type)  {
					case IGMP_MEMBERSHIP_QUERY:
						printf ("IGMP type: %sMEMBERSHIP QUERY%s\n", BOLD, NORMAL);
						break;
					
					case IGMP_V1_MEMBERSHIP_REPORT:
					case IGMP_V2_MEMBERSHIP_REPORT:
						printf ("IGMP type: %sMEMBERSHIP REPORT%s\n", BOLD, NORMAL);
						break;
					
					case IGMP_V2_LEAVE_GROUP:
						printf ("IGMP type: %sLEAVE GROUP%s\n", BOLD, NORMAL);
						break;
					
					case IGMP_DVMRP:
						printf ("IGMP type: %sDVMRP routing message%s\n", BOLD, NORMAL);
						break;
					
					case IGMP_PIM:
						printf ("IGMP type: %sPIM routing message%s\n", BOLD, NORMAL);
						break;
					
					case IGMP_TRACE:
						printf ("IGMP type: %sIGMP trace%s\n", BOLD, NORMAL);
						break;
					
					case IGMP_MTRACE_RESP:
						printf ("IGMP type: %sMTRACE response%s\n", BOLD, NORMAL);
						break;
					
					case IGMP_MTRACE:
						printf ("IGMP type: %sMTRACE message%s\n", BOLD, NORMAL);
						break;
				}
				
				printf ("Destination address: %s%s%s\n", BOLD, tmpaddr, NORMAL);
			} else {
				printf ("%s > %s: IGMP, type: %d\n", src, dst, __igmp.igmp_type);
			}
		}

		if (ip.protocol==IPPROTO_UDP)  {
			offset += sizeof(struct udphdr);

			if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
				memcpy (&udp, packet+sizeof(struct ethhdr)+sizeof(struct iphdr), sizeof(struct udphdr));
			else
				memcpy (&udp, packet+sizeof(struct iphdr), sizeof(struct udphdr));
			
			if (!quick)  {
				printf ("Protocol: UDP\n");

				if (ntohs(udp.source) < 0x8000)  {
					if ((serv = getservbyport(udp.source, NULL)))
						printf ("Source port: %s%d%s [%s]\n",BOLD, ntohs(udp.source), NORMAL, serv->s_name);
					else
						printf ("Source port: %s%d%s\n",BOLD,ntohs(udp.source),NORMAL);
				} else
					printf ("Source port: %s%d%s\n",BOLD,ntohs(udp.source),NORMAL);

				if (ntohs(udp.dest) < 0x8000)  {
					if ((serv = getservbyport(udp.dest, NULL)))
						printf ("Destination port: %s%d%s [%s]\n",BOLD, ntohs(udp.dest), NORMAL, serv->s_name);
					else
						printf ("Destination port: %s%d%s\n",BOLD,ntohs(udp.dest),NORMAL);
				}
				else
					printf ("Destination port: %s%d%s\n",BOLD,ntohs(udp.dest),NORMAL);
				printf ("Content:\n");
			} else {
				if (ntohs(udp.source) < 0x8000)  {
					if ((serv = getservbyport(udp.source, NULL)))
						printf ("%s.%s > ", src, serv->s_name);
					else
						printf ("%s.%u > ", src, ntohs(udp.source));
				} else
					printf ("%s.%u > ", src, ntohs(udp.source));
				
				if (ntohs(udp.dest) < 0x8000)  {
					if ((serv = getservbyport(udp.dest, NULL)))
						printf ("%s.%s: UDP, length %u\n", dst, serv->s_name, ntohs(udp.len));
					else
						printf ("%s.%u: UDP, length %u\n", dst, ntohs(udp.dest), ntohs(udp.len));
				} else
					printf ("%s.%u: UDP, length %u\n", dst, ntohs(udp.dest), ntohs(udp.len));

				return;
			}
		}

		if (ip.protocol==IPPROTO_TCP)  {
			offset += sizeof(struct tcphdr);

			if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
				memcpy (&tcp, packet+sizeof(struct ethhdr)+sizeof(struct iphdr), sizeof(struct tcphdr));
			else
				memcpy (&tcp, packet+sizeof(struct iphdr), sizeof(struct tcphdr));

			if (quick)  {
				if (ntohs(udp.source) < 0x8000)  {
					if ((serv = getservbyport(udp.source, NULL)))
						printf ("%s.%s > ", src, serv->s_name);
					else
						printf ("%s.%u > ", src, ntohs(udp.source));
				} else
					printf ("%s.%u > ", src, ntohs(udp.source));
				
				if (ntohs(udp.dest) < 0x8000)  {
					if ((serv = getservbyport(udp.dest, NULL)))
						printf ("%s.%s ", dst, serv->s_name);
					else
						printf ("%s.%u ", dst, ntohs(udp.dest));
				} else
					printf ("%s.%u ", dst, ntohs(udp.dest));

				if (tcp.syn)  {
					printf ("S");
					tcpflags = 1;
				}
				
				if (tcp.ack)  {
					printf ("A");
					tcpflags = 1;
				}
				
				if (tcp.rst)  {
					printf ("R");
					tcpflags = 1;
				}
				
				if (tcp.fin)  {
					printf ("F");
					tcpflags = 1;
				}
				
				if (tcp.psh)  {
					printf ("P");
					tcpflags = 1;
				}
				
				if (!tcpflags)
					printf (".");

				printf (" %u:%u ", ntohl(tcp.seq), ntohl(tcp.seq));

				if (tcp.ack)
					printf ("ack %u ", ntohl(tcp.ack_seq));

				printf ("%u\n", ntohs(tcp.window));
				return;
			}

			printf ("Protocol: TCP\n");

			if (ntohs(tcp.source) < 0x8000)  {
				if ((serv = getservbyport(tcp.source, NULL)))
					printf ("Source port: %s%d%s [%s]\n",BOLD, ntohs(tcp.source), NORMAL, serv->s_name);
				else
					printf ("Source port: %s%d%s\n",BOLD,ntohs(tcp.source),NORMAL);
			} else
				printf ("Source port: %s%d%s\n",BOLD,ntohs(tcp.source),NORMAL);

			if (ntohs(tcp.dest) < 0x8000)  {
				if ((serv = getservbyport(tcp.dest, NULL)))
					printf ("Destination port: %s%d%s [%s]\n",BOLD, ntohs(tcp.dest), NORMAL, serv->s_name);
				else
					printf ("Destination port: %s%d%s\n",BOLD,ntohs(tcp.dest),NORMAL);
			} else
				printf ("Destination port: %s%d%s\n",BOLD,ntohs(tcp.dest),NORMAL);

			printf ("SEQ number: %s0x%x%s\n",BOLD,htonl(tcp.seq),NORMAL);
			printf ("ACK number: %s0x%x%s\n",BOLD,htonl(tcp.ack_seq),NORMAL);

			if (use_flags)
				print_tcp_flags(&tcp);

			printf ("Content:\n");
		}

content:
		//for (i=0; i < plen - offset; i++)  {
		for (i=0; i < plen - ( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(struct ethhdr) : 0) ; i++)  {
			u8[i%16]=packet[i + ( ((dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB)) ? sizeof(struct ethhdr) : 0)];
			//u8[i%16] = packet[i+offset];

			if (i%16==15)  {
				printf ("\t");

				for (j=0; j<15; j+=2)
					printf ("%.2x%.2x ",u8[j],u8[j+1]);
				printf ("\t");

				for (j=0; j<16; j++)  {
					if (u8[j]>=0x21 && u8[j]<=0x7e)
						printf ("%c",u8[j]);
					else
						printf (".");
				}

				printf ("\n");
			}
		}

		offset = plen - (int) (plen/16)*16;
		printf ("\t");

		for (i=0; i<offset; i+=2)
			printf ("%.2x%.2x ",u8[i],u8[i+1]);
		printf ("\n\n");
	}

	if (maxcount != -1)  {
		if (count == maxcount)  {
			fprintf (stderr,"%s%d packets captured - tcpsmash is terminating%s\n",
					YELLOW,count,NORMAL);
			exit(0);
		}
	}
}

