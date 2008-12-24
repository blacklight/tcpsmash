/*
 * tcp_mng.c
 *
 * Version:	0.2.6,	08/12/2008 [dd/mm/yyyy]
 * (C) 2007,2008, BlackLight <blacklight86@gmail.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		3 of the License, or (at your option) any later version.
 */

#include "tcpsmash.h"

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

bool check_filter(u_char *packet, int plen)  {
	int i,j;
	char *unnull, *regex;

	unnull = (char*) malloc(plen);
	j=0;

	for (i=0; i < plen; i++)
		if (packet[i])
			unnull[j++] = packet[i];
	unnull[j] = 0;

	if (strfilter[0] == '/' && strfilter[strlen(strfilter)-1] == '/')  {
		regex = strdup(strfilter);
		regex[strlen(strfilter)-1] = 0;

			for (i=0; i<strlen(regex); i++)
				regex[i] = regex[i+1];

			if (preg_match(regex, unnull) != 1)  {
				free(regex);
				free(unnull);
				return false;
			}
	} else {
		if (!strstr(unnull, strfilter))  {
			free(unnull);
			return false;
		}
	}

	free(unnull);
	return true;
}

