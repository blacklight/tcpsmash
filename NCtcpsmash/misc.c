/*
 * NCtcpsmash/misc.c
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
 * @brief This function prints info about TCP flags of a TCP packet. Kept for back-compatibility.
 * @param tcp Reference to a valid TCP header
 */
void print_tcp_flags (struct tcphdr *tcp)  {
	wprintw (info,"TCP flags: ");
	wcolor_set (info, 7, NULL);
	
	if (tcp->fin)
		wprintw (info,"F");
	if (tcp->syn)
		wprintw (info,"S");
	if (tcp->rst)
		wprintw (info,"R");
	if (tcp->psh)
		wprintw (info,"P");
	if (tcp->ack)
		wprintw (info,"A");
	if (tcp->urg)
		wprintw (info,"U");

	wcolor_set (info, 1, NULL);
	wprintw (info,"\n");
}

/**
 * @brief Checks if a certain packet's content matches a given filter (plain string or regex) or not
 * @param packet Packet to analyze
 * @param plen packet length
 * @return true if the content is matched, false elsewhere
 */
u16 csum (u16 *buf, int nwords)  {
	u32 sum;
	
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
		sum = (sum >> 16) + (sum & 0xffff);
		sum += (sum >> 16);
	return ~sum;
}

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
 * @brief It gets the dlink offset at which IP/ARP header is found depending on dlink type. Greetz to evilsocket's IPGrep for this algorithm.
 * @param dlink_type Data link type, depending on the kind of interface used (ethernet, PPP, PPPoE, token ring, SLIP...) and known through pcap_datalink
 * @return Data link offset
 */
int get_dlink_offset (int dlink_type)  {
	switch(dlink_type)  {
		case DLT_RAW:
			dlink_offset = 0; break;

		case DLT_PPP:
		case DLT_LOOP:
		case DLT_NULL:
			dlink_offset = 4; break;

		case DLT_PPP_ETHER:
			dlink_offset = 8; break;

		case DLT_EN10MB:
		case DLT_EN3MB:
			dlink_offset = 14; break;

		case DLT_LINUX_SLL:
		case DLT_SLIP:
			dlink_offset = 16; break;

		case DLT_SLIP_BSDOS:
		case DLT_PPP_BSDOS:
		case DLT_IEEE802_11:
			dlink_offset = 24; break;

		case DLT_PFLOG:
			dlink_offset = 48; break;

		default :		   
			fprintf (stderr,"***Error: unsupported device datalink layer\n");
			exit(3);
	}

	return dlink_offset;
}

char* getline()  {
	int size=0;
	char *str = NULL;
	char ch;

	while ((ch=getch()) != '\n')  {
		if (ch >= 0x20 && ch <= 0x7E)  {
			str = (char*) GC_REALLOC(str, ++size);
			str[size-1]=ch;
			wprintw (status, "%c", ch);
			wrefresh (status);
		}
	}

	if (!size)
		return NULL;
	else  {
		str[size]=0;
		return str;
	}
}

int check_filter(char *filter, const u_char *packet, int plen)  {
	int i,j;
	char *unnull, *regex;

	unnull = (char*) GC_MALLOC(plen);
	j=0;

	for (i=0; i < plen; i++)
		if (packet[i])
			unnull[j++] = packet[i];
	unnull[j] = 0;

	if (filter[0] == '/' && filter[strlen(filter)-1] == '/')  {
		regex = GC_STRDUP(filter);
		regex[strlen(filter)-1] = 0;

			for (i=0; i<strlen(regex); i++)
				regex[i] = regex[i+1];

			if (preg_match(regex, unnull) != 1)  {
#ifndef _HAS_GC
				free(regex);
				free(unnull);
#endif
				return 0;
			}
	} else {
		if (!strstr(unnull, filter))  {
#ifndef _HAS_GC
			free(unnull);
#endif
			return 0;
		}
	}

#ifndef _HAS_GC
	free(unnull);
#endif

	return 1;
}

int contains (int val, int *v, int size)  {
	int i;

	for (i=0; i<size && v[i] <= val; i++)  {
		if (v[i] == val)
			return 1;
	}

	return 0;
}

