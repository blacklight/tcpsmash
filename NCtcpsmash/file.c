/*
 * file.c
 *
 * (C) 2007,2009, BlackLight <blacklight@autistici.org>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		3 of the License, or (at your option) any later version.
 */

#include "nctcpsmash.h"

void file_dump (char* file)  {
	struct ethhdr eth;
	struct iphdr  ip;
	struct arphdr_t arp;
	struct pcap_pkthdr pcap;
	struct timeval tv;

	FILE *fp;
	int len;
	char *buff;

	if (!(fp=fopen(file,"rb")))  {
		fprintf (stderr,"%s*** Error: Unable to read from %s: %s ***%s\n",
				RED, file, strerror(errno), NORMAL);
		exit(1);
	}

	fread (&dlink_type, sizeof(int), 1, fp);
	dlink_offset = get_dlink_offset(dlink_type);

	while (!feof(fp))  {
		buff = NULL;
		len=0;
		fread (&tv, sizeof(tv), 1, fp);

		if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )  {
			fread (&eth, sizeof(struct ethhdr), 1, fp);
			len += sizeof(struct ethhdr);
			buff = (char*) GC_REALLOC(buff,len);
			memcpy (buff, &eth, sizeof(struct ethhdr));
		
			if (eth.h_proto == ntohs(ETH_P_ARP))  {
				fread (&arp, sizeof(struct arphdr_t), 1, fp);
				len += sizeof(struct arphdr_t);
				buff = (char*) GC_REALLOC(buff,len);
				memcpy (buff+sizeof(struct ethhdr), &arp, sizeof(struct arphdr_t));
			} else if (eth.h_proto == ntohs(ETH_P_IP))
				goto ipsmash;
		} else {
		ipsmash:
			fread (&ip, sizeof(struct iphdr), 1, fp);
			len += sizeof(struct iphdr);
			buff = (char*) GC_REALLOC(buff,len);
		
			if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
				memcpy (buff+sizeof(struct ethhdr), &ip, sizeof(struct iphdr));
			else
				memcpy (buff, &ip, sizeof(struct iphdr));

			len += ( ntohs(ip.tot_len) - sizeof(struct iphdr) );
			buff = (char*) GC_REALLOC(buff,len);

			if ( (dlink_type == DLT_EN10MB) || (dlink_type == DLT_EN3MB) )
				fread (
						buff + sizeof(struct ethhdr) + sizeof(struct iphdr),
						(htons(ip.tot_len) - sizeof(struct iphdr)),
						1,
						fp
					);
			else
				fread (
						buff + sizeof(struct iphdr),
						(htons(ip.tot_len) - sizeof(struct iphdr)),
						1,
						fp
					);
		}

		memset (&pcap, 0x0, sizeof(pcap));
		pcap.ts = tv;
		pcap.caplen = len;
		pcap.len = len;
		pack_handle(NULL,&pcap,(u8*) buff);

#ifndef _HAS_GC
		free(buff);
#endif
	}

	return;
}

list filter_packets (char* filter, int* size)  {
	int i;
	list nums = NULL;
	u_char *packet;
	struct record *tmp;

	*size = 0;

	for (i=0, tmp=start; i < capinfo->npack; i++, tmp++)  {
		packet = (u_char*) GC_MALLOC(tmp->len);
		memcpy (packet, tmp->packet, tmp->len);

		if (check_filter(filter, packet, tmp->len))  {
			nums = Insert (i,nums);
			(*size)++;
		}
	}

	return nums;
}

list get_tcpstream (struct record r, int *size)  {
	int i,j,len;
	char *packet = NULL;
	struct record *tmp;
	struct iphdr  ip;
	struct tcphdr tcp;
	FILE *fp;

	u16 sport, dport;
	u32 saddr, daddr;
	list nums = NULL;

	len = r.len - dlink_offset;
	packet = (char*) GC_MALLOC(len);

	if (dump_file)  {
		if (!(fp=fopen(dump_file, "rb")))  {
			endwin();
			fprintf (stderr, "Fatal: Unable to read from %s", dump_file);
			exit(1);
		}

		fread (&dlink_type, sizeof(int), 1, fp);
		dlink_offset = get_dlink_offset(dlink_type);
		fclose(fp);
	}

	for (i=dlink_offset; i < r.len; i++)
		packet[i-dlink_offset] = r.packet[i];

	memcpy (&ip, packet, sizeof(struct iphdr));

	if (ip.protocol != IPPROTO_TCP)  {
		wclear (status);
		wcolor_set(status, 6, NULL);
		wprintw (status, "You did not choose a valid TCP packet");
		wcolor_set(status, 1, NULL);
		wrefresh (status);

		return NULL;
	}

	memcpy (&tcp, packet+sizeof(struct iphdr), sizeof(struct tcphdr));

	saddr = ntohl(ip.saddr);
	daddr = ntohl(ip.daddr);
	sport = ntohs(tcp.source);
	dport = ntohs(tcp.dest);

#ifndef _HAS_GC
	free (packet);
#endif

	for (i=0, tmp=start; i < capinfo->npack; i++, tmp++)  {
		memset (&ip,  0x0, sizeof(struct iphdr));
		memset (&tcp, 0x0, sizeof(struct tcphdr));
		packet = NULL;

		len = tmp->len - dlink_offset;
		packet = (char*) GC_MALLOC(len);

		for (j=dlink_offset; j < tmp->len; j++)
			packet[j-dlink_offset] = tmp->packet[j];

		memcpy (&ip, packet, sizeof(struct iphdr));

		if (ip.protocol != IPPROTO_TCP)
			continue;
	
		memcpy (&tcp, packet+sizeof(struct iphdr), sizeof(struct tcphdr));
			
		if (
				((ntohl(ip.saddr) == saddr) &&
				(ntohl(ip.daddr) == daddr) &&
				(ntohs(tcp.source) == sport) &&
				(ntohs(tcp.dest) == dport)) ||

				((ntohl(ip.saddr) == daddr) &&
				(ntohl(ip.daddr) == saddr) &&
				(ntohs(tcp.source) == dport) &&
				(ntohs(tcp.dest) == sport))
		   )  {
			nums = Insert(i, nums);
			(*size)++;
		}

#ifndef _HAS_GC
		free(packet);
#endif
	}

	return nums;
}

