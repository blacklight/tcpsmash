/*
 * main.c
 *
 * (C) 2007,2009, BlackLight <blacklight@autistici.org>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		3 of the License, or (at your option) any later version.
 */


#include "tcpsmash.h"

pcap_t *sniff;

void foo (int sig)  {
	struct pcap_stat st;
	pcap_stats (sniff, &st);
	fprintf (stderr,"\n%sSignal %d caught - Program terminated\n\n%d packets captured on the interface\n"
			"%d packets captured by the filter\n%d packets dropped%s\n",
			YELLOW, sig, st.ps_recv/2, count, st.ps_drop/2, NORMAL);
	exit(255);
}

void help(char *app)  {
	fprintf (stderr,"%s~~~ TCPsmash v.%s ~~~%s\n"
			"%sby BlackLight { http://blacklight.gotdns.org }%s\n\n",
			BOLD,VERSION,NORMAL,YELLOW,NORMAL);
	
	fprintf (stderr,"Usage: %s [-h] [-l] [-n] [-v] [-q] [-t] [-D] [-f \"<string>\"] [-C \"<string\"] [-w <logfile>] [-F <logfile>] [-c <count>] [-i <interface>]\n\n",app);
	
	fprintf (stderr,"\t-n\t\t\tDo not use promiscuous mode (default mode for tcpsmash)\n"
			"\t-h\t\t\tPrint this help and exit\n"
			"\t-l\t\t\tList active network interfaces\n"
			"\t-q\t\t\tGenerate quick output, with a tcpdump-like flavour\n"
			"\t-D\t\t\tDump each packet on output, without printing additional info\n"
			"\t-v\t\t\tPrint info about the version of the program\n"
			"\t-w logfile\t\tWrite the output to a log file in binary format. The file will be then read using -F option\n"
			"\t-F logfile\t\tRead packets from a dump file previously created by using -w <logfile>\n"
			"\t-c count\t\tOnly capture \"count\" packets and exit\n"
			"\t-f \"<string>\"\t\tUse a filter string on the packets in BPF format, i.e. \"tcp dst port 80\"\n"
			"\t-C \"<string>\"\t\tOnly capture packets containing \"string\" in any part of them (headers, application contents...), i.e. \"password:\"\n"
			"\t\t\t\tYou can also specify a regex with this option, between / and /, i.e. -C \"/password:\\s*[a-z]+/\"\n"
			"\t-i interface\t\tChoose a network interface to sniff\n"
		   );

}

void print_ver()  {
	fprintf (stderr,"%s~~~ tcpsmash %s ~~~%s\n",BOLD,VERSION,NORMAL);
	fprintf (stderr,"%s(C)2007,2008, BlackLight  { http://blacklight.gotdns.org }\n",YELLOW);
	fprintf (stderr,"Released under GNU General Public Licence (GPL) v.3%s\n\n",NORMAL);
}

void unformatted_help(char *app)  {
	printf ("Usage: %s [-h] [-l] [-n] [-v] [-q] [-t] [-D] [-f \"<string>\"] [-C \"<string\"] [-w <logfile>] [-F <logfile>] [-c <count>] [-i <interface>]\n\n",app);
	
	printf ("\t-n\t\t\tDo not use promiscuous mode (default mode for tcpsmash)\n"
			"\t-h\t\t\tPrint this help and exit\n"
			"\t-l\t\t\tList active network interfaces\n"
			"\t-q\t\t\tGenerate quick output, with a tcpdump-like flavour\n"
			"\t-D\t\t\tDump each packet on output, without printing additional info\n"
			"\t-v\t\t\tPrint info about the version of the program\n"
			"\t-w logfile\t\tWrite the output to a log file in binary format. The file will be then read using -F option\n"
			"\t-F logfile\t\tRead packets from a dump file previously created by using -w <logfile>\n"
			"\t-c count\t\tOnly capture \"count\" packets and exit\n"
			"\t-f \"<string>\"\t\tUse a filter string on the packets in BPF format, i.e. \"tcp dst port 80\"\n"
			"\t-C \"<string>\"\t\tOnly capture packets containing \"string\" in any part of them (headers, application contents...), i.e. \"password:\"\n"
			"\t\t\t\tYou can also specify a regex with this option, between / and /, i.e. -C \"/password:\\s*[a-z]+/\"\n"
			"\t-i interface\t\tChoose a network interface to sniff\n"
		   );
}

void unformatted_print_ver()  {
	printf ("tcpsmash v.%s\n",VERSION);
}

int main(int argc, char **argv)  {
	int i,fd,ch,promisc=0;

	char choice;
	char err[PCAP_ERRBUF_SIZE];
	char ipaddr[INET6_ADDRSTRLEN];
	char *log_file  = NULL,
		*interface = NULL,
		*dump_file = NULL;

	char *filter_string = (char*) GC_MALLOC(BUFSIZ*sizeof(char));
	struct sockaddr_in *addr;
	struct bpf_program filter;

	bpf_u_int32 net,mask;
	pcap_if_t *ifc;

#ifdef	_HAS_GC
	GC_INIT()
#endif

	memset (filter_string, 0x0, BUFSIZ);
	use_flags = true;
	use_dump  = false;
	use_log   = false;
	undumping = false;
	arp = false;
	quick     = false;
	strfilter = NULL;
	maxcount  = -1;

	for (i=1; i<argc; i++)  {
		if (!strcmp(argv[i],"--help"))  {
			unformatted_help(argv[0]);
			exit(0);
		} else if (!strcmp(argv[i],"--version")) {
			unformatted_print_ver();
			exit(0);
		}
	}

	while ((ch=getopt(argc,argv,"a1:2:qnhlw:f:i:F:c:C:Dv"))>0)  {
		switch (ch)  {
			case 'w':
				log_file = GC_STRDUP(optarg);
				use_dump = true;
				use_log  = true;

				if ((fd=creat(log_file,0644))<0)  {
					fprintf (stderr,"***ERROR: Unable to write logfile %s: %s\n",
							log_file, strerror(errno));
					exit(-1);
				}

				close (1);
				dup(fd);
				
				if (!(out = fdopen(fd,"w")))  {
					fprintf (stderr,"%s***ERROR: Unable to write logfile %s: %s%s\n",
							RED, log_file, strerror(errno), NORMAL);
					exit(-1);
				}

				break;

			case 'f':
				filter_string = GC_STRDUP(optarg);
				break;

			case 'l':
				pcap_findalldevs (&ifc,err);
				printf ("%s*** Network interfaces found on the machine:%s\n",
						GREEN,NORMAL);
			
				do  {
					printf ("\n%s%s%s: %s\n",YELLOW,ifc->name,NORMAL,
							(ifc->description) ? ifc->description :
							"(no description)");
					int i=0;

					while (ifc->addresses)  {
						if (i == 1)  {
							memset (ipaddr,0x0,sizeof(ipaddr));
							addr = (struct sockaddr_in*) ifc->addresses->addr;
							inet_ntop(AF_INET, &(addr->sin_addr), ipaddr, sizeof(ipaddr));
							printf ("\t%sAddress:%s %s\n",
									BOLD,NORMAL, ipaddr
									);

							memset (ipaddr,0x0,sizeof(ipaddr));
							
							if ((addr = (struct sockaddr_in*) ifc->addresses->broadaddr))  {
								inet_ntop(AF_INET, &(addr->sin_addr), ipaddr, sizeof(ipaddr));
								printf ("\t%sBroadcast:%s %s\n",
										BOLD,NORMAL,ipaddr);
							}

							memset (ifc->addresses, 0x0, sizeof(ifc->addresses));
							i=0;
						}

						ifc->addresses=ifc->addresses->next;
						i++;
					}
				
					ifc=ifc->next;
				} while (ifc->next);

				exit(0);
				break;

			case 'h':
				help(argv[0]);
				exit(0);
				break;

			case 'n':
				promisc=1;
				break;

			case 'i':
				interface = GC_STRDUP(optarg);
				break;

			case 'v':
				print_ver();
				exit(0);

			case 'D':
				use_dump=true;
				break;

			case 'F':
				undumping = true;
				dump_file = GC_STRDUP(optarg);
				break;

			case 'q':
				quick=true;
				break;

			case 'c':
				maxcount = atoi(optarg);
				break;

			case 'C':
				strfilter = GC_STRDUP(optarg);
				break;

			default:
				fprintf (stderr, "%s*** Unknown option: %c%s\n",
						RED,ch,NORMAL);
				exit(1);
				break;
		}
	}

	print_ver();
	setreuid(0,0);

	if (geteuid())  {
		printf ("*** %sError: You MUST be root in order to use this application ***%s\n",
				RED,NORMAL);
		exit(255);
	}

	if (!interface)  {
		printf ("%s***WARNING: Specifying no interface to sniff will\n"
				"produce traffic sniffing on any interface. This may\n"
				"lead to software inconsistency, and you should not\n"
				"save a log file for this sniffing session, as I cannot\n"
				"determine the data link type for undumping your log file\n"
				"and I will dump out random stuff. Are you sure you\n"
				"really want to continue?%s (y/n) ", RED, NORMAL);
		scanf ("%c",&choice);

		if (choice != 'y')  {
			printf ("\nexiting %s...\n", argv[0]);
			exit(1);
		}
	}

	if (!log_file)
		if (!(out = fdopen(1,"w")))  {
			fprintf (stderr,"%s*** Error: Unable to open stdout: %s%s\n",
					RED,strerror(errno),NORMAL);
			exit(1);
		}

	if (dump_file)  {
		file_dump(dump_file);
		exit(0);
	}

	if (!filter_string[0])
		filter_string = GC_STRDUP("ip or arp");

	if (pcap_lookupnet(NULL,&net,&mask,err)==-1)  {
		fprintf (stderr,"***Error connecting to the network interface: %s\n",err);
		exit(1);
	}

	if (!(sniff=pcap_open_live(interface,1024,promisc,0,err)))  {
		fprintf (stderr,"***Error starting sniffing session: %s\n",err);
		exit(2);
	}

	if ((dlink_type = pcap_datalink(sniff)) < 0)  {
		fprintf (stderr,"***Error while getting datalink type: %s\n",err);
		exit(3);
	}

	dlink_offset = get_dlink_offset (dlink_type);

	if (log_file)
		fwrite (&dlink_type, sizeof(int), 1, stdout);

	signal (SIGINT,foo);
	signal (SIGTERM,foo);
	fprintf (stderr,"%sSniffing on %s...%s\n\n",GREEN,interface,NORMAL);

	pcap_compile (sniff,&filter,filter_string,0,net);
	pcap_setfilter (sniff,&filter);

	count=0;
	pcap_loop (sniff,0,pack_handle,NULL);
	return 0;
}

