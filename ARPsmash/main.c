/*
 * ARPsmash/main.c
 *
 * (C) 2007,2009, BlackLight <blacklight@autistici.org>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		3 of the License, or (at your option) any later version.
 */

#include "arpsmash.h"

/**
 * @brief Just a banner
 */
void banner()  {
	printf ("---=== ARPsmash - BlackLight's ARP spoofer ===---\n"
		   "-- copyleft 2008, by BlackLight\n"
		   "-- Released under GNU GPL licence 3.0\n\n");
}

/**
 * @brief Just the main
 */
int main (int argc, char **argv)  {
	int c;
	__u8 *addr1, *addr2;
	banner();

	if (argc<7)  {
		fprintf (stderr,"%s*** Usage: %s -i <interface> -1 <ip host #1> -2 <ip host #2>%s\n", YELLOW, argv[0], NORMAL);
		return -1;
	}

	if (setreuid(0,0))  {
		fprintf (stderr,"%s***Error: You must be root to run this application. Sorry dude...%s\n", RED, NORMAL);
		exit(-1);
	}

	while ((c=getopt(argc,argv,"i:1:2:"))>0)  {
		switch (c)  {
			case 'i':
				ifc = (__u8*) strdup(optarg);
				break;

			case '1':
				addr1 = (__u8*) strdup(optarg);
				break;

			case '2':
				addr2 = (__u8*) strdup(optarg);
				break;

			default:
				fprintf (stderr,"%s*** Usage: %s -i <interface> -1 <ip host #1> -2 <ip host #2>%s\n", YELLOW, argv[0], NORMAL);
				return -1;
				break;
		}
	}

	if (arpsmash(ifc,addr1,addr2)<0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

