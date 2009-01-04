#include "nctcpsmash.h"

char fname[BUFSIZ], fnpack[BUFSIZ];
pcap_t *sniff;

// This function does nothing. But it does greatly.
void foo(int signum)  {}

// This should return statistics about sniffed traffic when exiting nctcpsmash.
// This will never happen anyway, unless your eye's not fast enough to notice it,
// but the function exists anyway.
void STATS(int sig)  {
	struct pcap_stat st;
	pcap_stats (sniff, &st);
	fprintf (stderr,"\n%sSignal %d caught - Program terminated\n\n%d packets captured on the interface\n"
			"%d packets captured by the filter\n%d packets dropped%s\n",
			YELLOW, sig, st.ps_recv/2, *npack, st.ps_drop/2, NORMAL);
	exit(255);
}

// This will be executed when you exit nctcpsmash.
void __on_exit (int signum)  {
	int i;

	endwin();
	unlink (fname);
	unlink (fnpack);

	for (i=0; i<2; i++)
		kill (pid[i], SIGTERM);

	STATS(signum);
	exit(0);
}

// Refreshing everything.
void _refresh()  {
	wrefresh(stdscr);
	wrefresh(head);
	wrefresh(mainw);
	wrefresh(w);
	wrefresh(line);
	wrefresh(status);
	wrefresh(info);
	refresh();
}

void _pause (int sig)  {
	pause();
}

// Need help? This is the place for you, baby.
void help(char *app)  {
	fprintf (stderr,"%s~~~ ncTCPsmash v.%s ~~~%s\n"
			"A NCurses-based interface for TCPsmash - The coolest packet sniffer\n"
			"%sby BlackLight { http://blacklight.gotdns.org }%s\n\n",
			BOLD,VERSION,NORMAL,YELLOW,NORMAL);
	
	fprintf (stderr,"Usage: %s [-h] [-n] [-v] [-F <logfile>][-f \"<string>\"] [-C \"<string\"] [-c <count>] [-i <interface>]\n\n",app);
	
	fprintf (stderr,
			"\t-h\t\t\tPrint this help and exit\n"
			"\t-v\t\t\tPrint info about the version of the program\n"
			"\t-c count\t\tOnly capture \"count\" packets and exit\n"
			"\t-f \"<string>\"\t\tUse a filter string on the packets in BPF format, i.e. \"tcp dst port 80\"\n"
			"\t-F <logfile>\t\tRead packets from a dump file previously created by using -w <logfile> or \"w\" command on nctcpsmash\n"
			"\t-C \"<string>\"\t\tOnly capture packets containing \"string\" in any part of them (headers, application contents...), i.e. \"password:\"\n"
			"\t\t\t\tYou can also specify a regex with this option, between / and /, i.e. -C \"/password:\\s*[a-z]+/\"\n"
			"\t-i interface\t\tChoose a network interface to sniff\n\n"
		   );

	fprintf (stderr,
			"Commands:\n\n"
			"\tUp/Down arrow:\t\tselect previous/next packet\n"
			"\tLeft/Right arrow:\tgoto first/last packet\n"
			"\tPage up/down:\t\tshow previous/next page\n"
			"\tENTER:\t\t\tshow info about selected packet\n"
			"\th:\t\t\tshow this help\n"
			"\tw:\t\t\twrite dumped traffic to a logfile, to be examined using tcpsmash -F logfile\n"
			"\ts:\t\t\tpause traffic sniffing\n"
			"\tr:\t\t\tresume traffic sniffing when paused\n"
			"\tt:\t\t\tif a TCP packet is selected, this command highlights the\n"
			"\t\t\t\tTCP stream the packet is belonging to\n"
			"\t/ search_pattern | regex:\n"
			"\t\t\t\thighlight (in red) packets containing specified string or regex.\n"
			"\t\t\t\tTo specify a string, just write it.\n"
			"\t\t\t\tTo specify a regex, include it between / and / -> /this is a regex/\n"
			"\tq:\t\t\tquit (nc)tcpsmash\n");
}

// What version are you using right now?
void print_ver()  {
	fprintf (stderr,"%s~~~ nctcpsmash %s ~~~%s\n",BOLD,VERSION,NORMAL);
	fprintf (stderr,"%s(C)2007,2009, BlackLight  { http://blacklight.gotdns.org }\n",YELLOW);
	fprintf (stderr,"Released under GNU General Public Licence (GPL) v.3%s\n\n",NORMAL);
}

void unformatted_help(char *app)  {
	printf ("Usage: %s [-h] [-n] [-v] [-F <logfile>] [-f \"<string>\"] [-C \"<string\"] [-c <count>] [-i <interface>]\n\n",app);
	
	printf ("\t-h\t\t\tPrint this help and exit\n"
			"\t-v\t\t\tPrint info about the version of the program\n"
			"\t-c count\t\tOnly capture \"count\" packets and exit\n"
			"\t-f \"<string>\"\t\tUse a filter string on the packets in BPF format, i.e. \"tcp dst port 80\"\n"
			"\t-F <logfile>\t\tRead packets from a dump file previously created by using -w <logfile> or \"w\" command on nctcpsmash\n"
			"\t-C \"<string>\"\t\tOnly capture packets containing \"string\" in any part of them (headers, application contents...), i.e. \"password:\"\n"
			"\t\t\t\tYou can also specify a regex with this option, between / and /, i.e. -C \"/password:\\s*[a-z]+/\"\n"
			"\t-i interface\t\tChoose a network interface to sniff\n\n"
		   );

	printf ("Commands:\n\n"
			"\tUp/Down arrow:\t\tselect previous/next packet\n"
			"\tLeft/Right arrow:\tgoto first/last packet\n"
			"\tPage up/down:\t\tshow previous/next page\n"
			"\tENTER:\t\t\tshow info about selected packet\n"
			"\th:\t\t\tshow this help\n"
			"\tw:\t\t\twrite dumped traffic to a logfile, to be examined using tcpsmash -F logfile\n"
			"\ts:\t\t\tpause traffic sniffing\n"
			"\tr:\t\t\tresume traffic sniffing when paused\n"
			"\tq:\t\t\tquit (nc)tcpsmash\n");
}

void unformatted_print_ver()  {
	printf ("nctcpsmash v.%s\n",VERSION);
}

void print_help()  {
	wclear(info);
	wcolor_set (info, 6, NULL);
	wprintw (info, "HELP\n\n");
	wcolor_set (info, 1, NULL);
	
	wcolor_set (info, 3, NULL);
	wprintw (info, "Left window:");
	wcolor_set (info, 1, NULL);

	wprintw (info, "\tit contains the list of\n\t\tsniffed packets,\n\t\twith a short tcpdump-like\n\t\tdescription for each of them\n\n");
	
	wcolor_set (info, 3, NULL);
	wprintw (info, "Right window:");
	wcolor_set (info, 1, NULL);

	wprintw (info, "\tit contains this\n\t\thelp by default, then,\n\t\twhen you choose a packet to\n\t\tsee from left windows by\n\t\t"
			"pressing ENTER, it shows the\n\t\tdetailed infos about that packet\n\n");

	wcolor_set (info, 4, NULL);
	wprintw (info, "Commands\n\n");
	wcolor_set (info, 1, NULL);
	
	wcolor_set (info, 5, NULL);
	wprintw (info, "See man tcpsmash | man nctcpsmash |\nREADME file | nctcpsmash -h\nfor a complete list\nof options | commands");
	wcolor_set (info, 1, NULL);

	/*wcolor_set (info, 4, NULL);
	wprintw (info, "Browsing left window\n\n");
	wcolor_set (info, 1, NULL);

	wcolor_set (info, 7, NULL);
	wprintw (info, "Up/Down arrow:");
	wcolor_set (info, 1, NULL);
	wprintw (info, "\t\tselect previous/next\n\t\t\tpacket\n");

	wcolor_set (info, 7, NULL);
	wprintw (info, "Left/Right arrow:");
	wcolor_set (info, 1, NULL);
	wprintw (info, "\tgoto first/last packet\n");

	wcolor_set (info, 7, NULL);
	wprintw (info, "Page up/down:");
	wcolor_set (info, 1, NULL);
	wprintw (info, "\t\tshow previous/next page\n");

	wcolor_set (info, 7, NULL);
	wprintw (info, "ENTER:");
	wcolor_set (info, 1, NULL);
	wprintw (info, "\t\t\tshow info about selected\n\t\t\tpacket\n");

	wcolor_set (info, 7, NULL);
	wprintw (info, "h:");
	wcolor_set (info, 1, NULL);
	wprintw (info, "\t\t\tshow this help\n");

	wcolor_set (info, 7, NULL);
	wprintw (info, "q:");
	wcolor_set (info, 1, NULL);
	wprintw (info, "\t\t\tquit (nc)tcpsmash\n");
	
	wcolor_set (info, 7, NULL);
	wprintw (info, "w:");
	wcolor_set (info, 1, NULL);
	wprintw (info, "\t\t\tsave sniffed traffic\n\t\t\tto a logfile\n\t\t\t(to be examined using\n\t\t\ttcpsmash -F logfile)\n");

	wcolor_set (info, 7, NULL);
	wprintw (info, "s:");
	wcolor_set (info, 1, NULL);
	wprintw (info, "\t\t\tstop a packet sniffing\n\t\t\tsession\n");

	wcolor_set (info, 7, NULL);
	wprintw (info, "r:");
	wcolor_set (info, 1, NULL);
	wprintw (info, "\t\t\tresume a packet sniffing\n\t\t\tsession previously stopped\n");*/
		
	wcolor_set (info, 3, NULL);
	wprintw (info, "\n\ndeveloped by Blacklight\n<blacklight@autistici.org>\nand relesed under GNU GPL licence 3.0\n(C) 2007-2009\n");
	wcolor_set (info, 1, NULL);
}

// Save traffic to a dump file.
int save_dump (char* dump_file)  {
	int i,j,fd;
	struct record *ptr;

	if ((fd = open(dump_file, O_WRONLY|O_CREAT, 0644))<0)
		return -1;

	write (fd, &dlink_type, sizeof(int));

	for (i=0; i < *npack; i++)  {
		ptr = start+i;
		write (fd, &(ptr->tv), sizeof(struct timeval));

		for (j=0; j < ptr->len; j++)
			write (fd, &(ptr->packet[j]), 1);
	}

	close(fd);
	return 0;
}

int main (int argc, char **argv)  {
	int i, ch;
	int row = 0;
	int curstart = 0;
	int promisc = 0;
	int stopped = 0;
	int filtered = 0;
	int streamed = 0;

	char err[PCAP_ERRBUF_SIZE];
	char *interface = NULL;
	char *filter_string = NULL;
	char *search_pattern = NULL;

	bpf_u_int32 net,mask;
	list nums = NULL,
		tcpstream = NULL;

	struct record r;
	struct record *ptr;
	struct bpf_program filter;

	dump_file = NULL;

	for (i=1; i<argc; i++)  {
		if (!strcmp(argv[i],"--help"))  {
			unformatted_help(argv[0]);
			exit(0);
		} else if (!strcmp(argv[i],"--version")) {
			unformatted_print_ver();
			exit(0);
		}
	}

	while ((ch=getopt(argc, argv, "hvi:f:C:F:"))>0)  {
		switch (ch)  {
			case 'i':
				interface = strdup(optarg);
				break;

			case 'f':
				filter_string = strdup(optarg);
				break;

			case 'h':
				help(argv[0]);
				exit(0);
				break;

			case 'C':
				strfilter = strdup(optarg);
				break;

			case 'F':
				dump_file = strdup(optarg);
				break;
		}
	}
	
	strfilter = NULL;
	snprintf (fname,  sizeof(fname),  "/tmp/nctcpsmash-shared-%d", getpid());
	snprintf (fnpack, sizeof(fnpack), "/tmp/nctcpsmash-npack-%d",  getpid());
	
	setreuid(0,0);

	if (geteuid())  {
		printf ("*** Error: You MUST be root in order to use this application ***\n");
		exit(255);
	}

	if ((fd = open(fname, O_RDWR|O_CREAT, 0644)) < 0)
		return 1;
	
	if ((fdpack = open(fnpack, O_RDWR|O_CREAT, 0644)) < 0)
		return 1;

	i=0;
	write (fdpack, &i, sizeof(int));
	
	signal(SIGUSR1, foo);
	signal(SIGUSR2, _pause);
	signal(SIGINT,  __on_exit);
		
	if (!(ptr = mmap(NULL, 0x8000*sizeof(struct record), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)))
		return 2;
	
	if (!(npack = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED, fdpack, 0)))
		return 2;

	start=ptr;

	if (dump_file)
		goto gui;

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
	pcap_compile (sniff,&filter,filter_string,0,net);
	pcap_setfilter (sniff,&filter);

gui:
	mainw = initscr();
	SCRSIZ = (mainw->_maxy) - 3;
	SCRWID = (mainw->_maxx) - 3;
	wbkgdset(mainw,' ');

	cbreak();
	noecho();
	keypad(stdscr,TRUE);
	keypad(mainw,TRUE);

	if (start_color())  {
		endwin();
		return 1;
	}

	init_pair(1, COLOR_WHITE,   COLOR_BLACK);
	init_pair(2, COLOR_BLACK,   COLOR_GREEN);
	init_pair(3, COLOR_GREEN,   COLOR_BLACK);
	init_pair(4, COLOR_MAGENTA, COLOR_BLACK);
	init_pair(5, COLOR_CYAN,    COLOR_BLACK);
	init_pair(6, COLOR_RED,     COLOR_BLACK);
	init_pair(7, COLOR_YELLOW,  COLOR_BLACK);
	init_pair(8, COLOR_WHITE,   COLOR_RED);
	init_pair(9, COLOR_WHITE,   COLOR_BLUE);

	head = newwin(1,SCRWID,0,0);
	wcolor_set(head, 2, NULL);
	mvwaddstr(head,0,0,"tcpsmash - Just the coolest packet sniffer - by BlackLight, <blacklight@autistici.org>");
	wcolor_set(head, 1, NULL);

	line = newwin(SCRSIZ+2, 2, 1, ((int) (4*SCRWID)/7)-1);
	box (line, ACS_VLINE, ACS_VLINE);

	w = newwin(SCRSIZ, ((int) (4*SCRWID)/7)-3, 2, 0);
	wcolor_set(w, 1, NULL);
	keypad(w,TRUE);

	info = newwin(SCRSIZ, ((int) (3*SCRWID)/7), 2, ((int) (4*SCRWID)/7)+2);
	print_help();
	
	wmove (stdscr, row, 0);
	status = newwin(2, SCRWID, SCRSIZ+3, 0);
	
	wcolor_set(status, 6, NULL);
	wprintw (status,"Sniffing on %s...", (interface) ? interface : "any interface");
	wcolor_set(status, 1, NULL);
	_refresh();

	if (!dump_file)  {
		pid[0] = fork();

		if (!pid[0])  {
			pid[1] = fork();

			if (!pid[1])  {
				for (; ; ptr++)  {
					pause();

					if (*npack <= curstart + SCRSIZ && *npack >= curstart - 2)  {
						wprintw (w, "%s", ptr->descr);
						wrefresh(w);
					}
				}
			}

			pcap_loop (sniff,0,pack_handle,NULL);
			exit(0);
		}
	} else {
		pid[0] = fork();

		if (!pid[0])  {
			pid[1] = fork();

			if (!pid[1])  {
				for (; ; ptr++)  {
					pause();

					if (*npack <= curstart + SCRSIZ && *npack >= curstart - 2)  {
						wprintw (w, "%s", ptr->descr);
						wrefresh(w);
					}
				}
			}
		} else {
			file_dump(dump_file);
			wait((int*) 0);
		}
	}

	do  {
		ch = getch();
		wclear(w);

		if (ch == KEY_UP && row > 0)  {
			row--;

			if (row == curstart && curstart > 0)
				curstart--;
		}

		if (ch == KEY_DOWN && row <= *npack-2)  {
			row++;

			if (row == curstart+SCRSIZ && row < *npack)
				curstart++;
		}

		if (ch == KEY_PPAGE && row-SCRSIZ >= 0)  {
			row -= SCRSIZ;

			if (curstart-SCRSIZ >= 0)
				curstart -= SCRSIZ;
		}

		if (ch == KEY_NPAGE && row + SCRSIZ < *npack)  {
			row += SCRSIZ;

			if (curstart+SCRSIZ < *npack)
				curstart += SCRSIZ;
		}

		if (ch == KEY_LEFT || ch == KEY_HOME)  {
			row=0;
			curstart=0;
		}

		if (ch == KEY_RIGHT || ch == KEY_END)  {
			row = *npack - 1;
			
			if (*npack >= SCRSIZ)  {
				curstart = *npack-SCRSIZ;
			}
		}

		if (ch == '\n')  {
			r = *(start+row);
			dump (r);
		}

		if (ch == 'h')  {
			print_help();
			wrefresh (info);
		}

		if (ch == 'w')  {
			wclear (status);
			wprintw (status, "fname: ");
			wrefresh (status);
			dump_file = getline();

			if (dump_file)  {
				wclear (status);
		
				if (save_dump(dump_file)<0)  {
					wcolor_set (status, 6, NULL);
					wprintw (status, "Unable to write %s", dump_file);
				} else {
					wcolor_set (status, 3, NULL);
					wprintw (status, "Dump file %s successfully written", dump_file);
					wcolor_set (status, 1, NULL);
				}

				wrefresh (status);
			} else {
				wclear(status);
				wrefresh(status);
			}
		}

		if (ch == 's' && !stopped)  {
			kill (pid[0], SIGUSR2);
			stopped=1;
			
			wclear (status);
			wcolor_set (status, 6, NULL);
			wprintw (status, "Packet sniffing stopped - Press 'r' to resume");
			wcolor_set (status, 1, NULL);
			wrefresh (status);
		}

		if (ch == 'r' && stopped)  {
			kill (pid[0], SIGUSR1);
			stopped=0;

			wclear (status);
			wcolor_set (status, 3, NULL);
			wprintw (status, "Packet sniffing resumed");
			wcolor_set (status, 1, NULL);
			wrefresh (status);
		}

		if (ch == '/')  {
			wclear (status);
			wprintw (status, "/search: ");
			wrefresh (status);

			if (filtered > 0)  {
				free(nums);
				filtered=0;
			}

			search_pattern = NULL;
			search_pattern = getline();

			if (search_pattern)  {
				nums = NULL;
				filtered = 0;
				
				wclear (status);
				wcolor_set (status, 5, NULL);
				wprintw (status, "Searching...");
				wcolor_set (status, 1, NULL);
				wrefresh (status);
				nums = filter_packets (search_pattern, &filtered);

				wclear (status);
				wcolor_set (status, 3, NULL);
				wprintw (status, "%d packets found with pattern '%s'", filtered, search_pattern);
				wcolor_set (status, 1, NULL);
				wrefresh (status);
			} else {
				filtered=0;
				free(search_pattern);
				
				wclear(status);
				wcolor_set (status, 3, NULL);
				wprintw (status, "Search filter: cleared\n");
				wcolor_set (status, 1, NULL);
				wrefresh(status);
			}
		}

		if (ch == 't')  {
			streamed = 0;
			tcpstream = NULL;

			r = *(start+row);
			tcpstream = get_tcpstream (r, &streamed);
		
			if (tcpstream)  {
				wclear (status);
				wcolor_set (status, 5, NULL);
				wprintw (status, "%d packet found belonging to selected TCP stream", streamed);
				wcolor_set (status, 1, NULL);
				wrefresh (status);
			}
		}

		for (i=curstart; i < curstart+SCRSIZ && i <= *npack; i++)  {
			if (filtered > 0 && Contains(i,nums))
				wcolor_set(w, 8, NULL);
			else if (streamed > 0 && Contains(i,tcpstream))
				wcolor_set(w, 9, NULL);
			else
				wcolor_set(w, 1, NULL);

			if (i == row) wcolor_set(w, 2, NULL);

			ptr = start+i;
			wprintw (w, "%s", ptr->descr);
			wrefresh(w);

			if (i == row) wcolor_set(w, 1, NULL);
		}

		wmove (stdscr, row-curstart+2, 0);
	} while (ch != 'q');

	unlink (fname);
	unlink (fnpack);
	endwin();

	for (i=0; i<2; i++)
		kill (pid[i], SIGTERM);

	STATS(0);
	return 0;
}
