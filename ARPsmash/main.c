#include "arpsmash.h"

void banner()  {
	printf ("---=== ARPsmash - BlackLight's ARP spoofer ===---\n"
		   "-- copyleft 2008, by BlackLight\n"
		   "-- Released under GNU GPL licence 3.0\n\n");
}

int main (int argc, char **argv)  {
	int c;
	__u8 *addr1, *addr2;
	banner();

	if (argc<7)  {
		fprintf (stderr,"*** Usage: %s -i <interface> -1 <ip host #1> -2 <ip host #2>\n",argv[0]);
		return -1;
	}

	if (setreuid(0,0))  {
		fprintf (stderr,"*** You must be root to run this application. Sorry dude...\n");
		exit(-1);
	}

	while ((c=getopt(argc,argv,"i:1:2:"))>0)  {
		switch (c)  {
			case 'i':
				ifc = optarg;
				break;

			case '1':
				addr1 = optarg;
				break;

			case '2':
				addr2 = optarg;
				break;

			default:
				fprintf (stderr,"*** Usage: %s -i <interface> -1 <ip host #1> -2 <ip host #2>\n",argv[0]);
				return -1;
				break;
		}
	}

	if (arpsmash(strdup(ifc), strdup(addr1), strdup(addr2))<0)
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

