/*
 * tcp_mng.c
 *
 * (C) 2007,2009, BlackLight <blacklight@autistici.org>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		3 of the License, or (at your option) any later version.
 */

#include "tcpsmash.h"

/**
 * @brief This function prints info about TCP flags of a TCP packet. Kept for back-compatibility.
 * @param tcp Reference to a valid TCP header
 */
void print_tcp_flags (struct tcphdr *tcp)  {
	printf ("TCP flags: %s",YELLOW);
	
	if (tcp->fin)
		printf ("F");
	if (tcp->syn)
		printf ("S");
	if (tcp->rst)
		printf ("R");
	if (tcp->psh)
		printf ("P");
	if (tcp->ack)
		printf ("A");
	if (tcp->urg)
		printf ("U");
	printf ("%s\n",NORMAL);
}

/**
 * @brief Checks if a certain packet's content matches a given filter (plain string or regex) or not
 * @param packet Packet to analyze
 * @param plen packet length
 * @return true if the content is matched, false elsewhere
 */
bool check_filter(const u_char *packet, int plen)  {
	int i,j;
	char *unnull, *regex;

	unnull = (char*) GC_MALLOC(plen);
	j=0;

	for (i=0; i < plen; i++)
		if (packet[i])
			unnull[j++] = packet[i];
	unnull[j] = 0;

	if (strfilter[0] == '/' && strfilter[strlen(strfilter)-1] == '/')  {
		regex = GC_STRDUP(strfilter);
		regex[strlen(strfilter)-1] = 0;

			for (i=0; i<strlen(regex); i++)
				regex[i] = regex[i+1];

			if (preg_match(regex, unnull) != 1)  {
			#ifndef _HAS_GC
				free(regex);
				free(unnull);
			#endif
				return false;
			}
	} else {
		if (!strstr(unnull, strfilter))  {
		#ifndef _HAS_GC
			free(unnull);
		#endif
			return false;
		}
	}

#ifndef _HAS_GC
	free(unnull);
#endif
	return true;
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

