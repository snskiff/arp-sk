/*
 * Copyright 2002 Frédéric RAYNAL <pappy@security-labs.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Niels Provos.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "sk.h"
#include "arp-eth-ip.h"


int do_classical_hook(arpsk_arp_pkt_t *arp_pkt);
int do_random_hook(arpsk_arp_pkt_t *arp_pkt);

#define PRINT_ETH(ptr) printf("%02x:%02x:%02x:%02x:%02x:%02x\n", \
			      ptr[0], ptr[1], ptr[2],ptr[3], ptr[4], ptr[5])


static libnet_ptag_t t_arp, t_hwa;

int sk_code = 0;
int opt_code = -1;

#define SK_WHO_HAS 1
#define SK_REPLY   2
#define SK_ARPING  4
#define SK_ARPMIM  8


int sk_use_ts = 0;


#define OPT_WHO_HAS            0
#define OPT_REPLY              1
#define OPT_ARPING             2
#define OPT_ARPMIM             3

#define OPT_DST                4
#define OPT_SRC                5
#define OPT_RAND_HWA           6
#define OPT_RAND_HWA_DST       7
#define OPT_RAND_HWA_SRC       8

#define OPT_ARP_DST            9
#define OPT_ARP_SRC           10
#define OPT_RAND_ARP          11
#define OPT_RAND_ARP_DST      12
#define OPT_RAND_ARP_SRC      13
#define OPT_RAND_ARP_HWA_DST  14
#define OPT_RAND_ARP_LOG_DST  15
#define OPT_RAND_ARP_HWA_SRC  16
#define OPT_RAND_ARP_LOG_SRC  17

#define OPT_IFACE             18
#define OPT_COUNT             19
#define OPT_TIME              20
#define OPT_RAND_TIME         21
#define OPT_BEEP              22
#define OPT_NETWORK           23
#define OPT_USE_TS            24
#define OPT_CALL_DNS          25
#define OPT_VERSION           26
#define OPT_HELP              27



const struct option sk_options[] = {

    /*
     * Modes 
     */
    {"who-has", no_argument, 0, 'w'},	/* ARP Who-has packets */
    {"reply", no_argument, 0, 'r'},	/* ARP Reply packets */
    {"arping", no_argument, 0, 'p'},	/* RARP emulation */
    {"arpmim", no_argument, 0, 'm'},	/* Man in the Middle */

    /*
     * Addresses for the Hwa layer packet 
     */
    {"dst", required_argument, 0, 'd'},	/* all targets - ip or mac */
    {"src", required_argument, 0, 's'},	/* source - ip or mac address */

    {"rand-hwa", no_argument, 0, 512},
    {"rand-hwa-dst", no_argument, 0, 513},
    {"rand-hwa-src", no_argument, 0, 514},

    /*
     * ARP message 
     */
    {"arp-dst", required_argument, 0, 'D'},	/* IP:MAC */
    {"arp-src", required_argument, 0, 'S'},	/* IP:MAC */

    {"rand-arp", no_argument, 0, 1024},
    {"rand-arp-dst", no_argument, 0, 1025},
    {"rand-arp-src", no_argument, 0, 1026},
    {"rand-arp-hwa-dst", no_argument, 0, 1027},
    {"rand-arp-log-dst", no_argument, 0, 1028},
    {"rand-arp-hwa-src", no_argument, 0, 1029},
    {"rand-arp-log-src", no_argument, 0, 1030},

    /*
     * Misc. 
     */
    {"interface", required_argument, 0, 'i'},	/* interface */
    {"count", required_argument, 0, 'c'},	/* amount of pkts sent */
    {"time", required_argument, 0, 'T'},	/* time between 2 packets */
    {"rand-time", required_argument, 0, 2048},	/* time variance */
    {"beep", no_argument, &sk_opt_beep, 1},	/* beep for each packet sent */
    {"network", required_argument, 0, 'n'},	/* dst network of ICMP pkt */
    {"use-ts", no_argument, &sk_use_ts, 1},	/* send timestamp */
    {"call-dns", no_argument, 0, 'N'},	/* force name resolution */
    {"version", no_argument, 0, 'V'},	/*  */
    {"help", no_argument, 0, 'h'},	/*  */
    {NULL, 0, 0, 0}

};


void
usage(char *name)
{

    int i = 0;

    show_version();
    printf("\nUsage: %s\n", name);
    do
    {
	switch (i)
	{
	    case OPT_WHO_HAS:
		printf("-%c --%-13s send a ARP Who-has\n",
		    sk_options[i].val, sk_options[i].name);
		break;
	    case OPT_REPLY:
		printf("-%c --%-13s send a ARP Reply\n",
		    sk_options[i].val, sk_options[i].name);
		break;
	    case OPT_ARPING:
		printf
		    ("-%c --%-13s (bad) RARP emulation (NOT YET IMPLEMANTED)\n",
		    sk_options[i].val, sk_options[i].name);
		break;
	    case OPT_ARPMIM:
		printf
		    ("-%c --%-13s Man in the Middle (NOT YET IMPLEMANTED)\n\n",
		    sk_options[i].val, sk_options[i].name);
		break;

	    case OPT_DST:
		printf
		    ("-%c --%-13s dst in link layer (<hotname|hostip|MAC>)\n",
		    sk_options[i].val, sk_options[i].name);
		break;
	    case OPT_SRC:
		printf
		    ("-%c --%-13s dst in link layer (<hotname|hostip|MAC>)\n",
		    sk_options[i].val, sk_options[i].name);
		break;

	    case OPT_RAND_HWA:
		printf("--%-16s set random addresses in link header\n",
		    sk_options[i].name);
		break;
	    case OPT_RAND_HWA_DST:
		printf("--%-16s set random dst in link header\n",
		    sk_options[i].name);
		break;
	    case OPT_RAND_HWA_SRC:
		printf("--%-16s set random src in link header\n\n",
		    sk_options[i].name);
		break;

	    case OPT_ARP_DST:
		printf
		    ("-%c --%-13s dst in ARP message ([hostname|hostip][:MAC])\n",
		    sk_options[i].val, sk_options[i].name);
		break;
	    case OPT_ARP_SRC:
		printf
		    ("-%c --%-13s dst in ARP message ([hostname|hostip][:MAC])\n",
		    sk_options[i].val, sk_options[i].name);
		break;


	    case OPT_RAND_ARP:
		printf("--%-16s set random adresses in ARP message\n",
		    sk_options[i].name);
		break;
	    case OPT_RAND_ARP_DST:
		printf("--%-16s set random dst adresses in ARP message\n",
		    sk_options[i].name);
		break;
	    case OPT_RAND_ARP_SRC:
		printf("--%-16s set random src adresses in ARP message\n",
		    sk_options[i].name);
		break;
	    case OPT_RAND_ARP_HWA_DST:
		printf("--%-16s set random dst MAC adress in ARP message\n",
		    sk_options[i].name);
		break;
	    case OPT_RAND_ARP_LOG_DST:
		printf("--%-16s set random dst IP adress in ARP message\n",
		    sk_options[i].name);
		break;
	    case OPT_RAND_ARP_HWA_SRC:
		printf("--%-16s set random src MAC adress in ARP message\n",
		    sk_options[i].name);
		break;
	    case OPT_RAND_ARP_LOG_SRC:
		printf("--%-16s set random src IP adress in ARP message\n\n",
		    sk_options[i].name);
		break;

	    case OPT_IFACE:
		printf("-%c --%-13s specify interface (eth0)\n",
		    sk_options[i].val, sk_options[i].name);
		break;
	    case OPT_COUNT:
		printf("-%c --%-13s # of packets to send (infinity)\n",
		    sk_options[i].val, sk_options[i].name);
		break;
	    case OPT_TIME:
		printf
		    ("-%c --%-13s wait the specified number of seconds between sending \\\n                   each packet (or X micro seconds with -%c uX)\n",
		    sk_options[i].val, sk_options[i].name, sk_options[i].val);
		break;
	    case OPT_RAND_TIME:
		printf
		    ("--%-16s randomize the sending period of the packets\n",
		    sk_options[i].name);
		break;
	    case OPT_BEEP:
		printf("--%-16s beeps for each packet sent\n",
		    sk_options[i].name);
		break;
	    case OPT_NETWORK:
		printf
		    ("-%c --%-13s broadcast address to use for icmp-timestamp\n",
		    sk_options[i].val, sk_options[i].name);
		break;
	    case OPT_USE_TS:
		printf
		    ("--%-16s an icmp-timestamp is send to resolve MAC to IP\n",
		    sk_options[i].name);
		break;
	    case OPT_CALL_DNS:
		printf
		    ("-%c --%-13s force address resolution in outputs (default is off)\n",
		    sk_options[i].val, sk_options[i].name);
		break;
	    case OPT_VERSION:
		printf("-%c --%-13s print version and exit\n",
		    sk_options[i].val, sk_options[i].name);
		break;
	    case OPT_HELP:
		printf("-%c --%-13s this help :)\n",
		    sk_options[i].val, sk_options[i].name);
		break;

	}
    }
    while(sk_options[++i].name);
    printf("\n");

}


/* Computes the weight of a number, i.e. the # of 1s */
unsigned short
weight(unsigned long x, int sz)
{

    unsigned short res = 0;
    int i;

    for(i = 0; i < sz; i++)
	res += (x >> i) & 1;
    return (res);
}

int
main(int argc, char **argv)
{

    char errbuf[LIBNET_ERRBUF_SIZE];	/* buffer to hold error text */
    char str[255];
    int opt_idx = 0, ch;
    int old_arp = 0;

    char *pOptHwaDst = NULL, *pOptHwaSrc = NULL;
    char *pOptArpDst = NULL, *pOptArpSrc = NULL;

    arpsk_arp_pkt_t *arp_pkt = NULL;
    u_char ifhwa[20];		/* use to set the arp_pkt */
    u_long log_addr;
    u_long src_addr = -1, dst_addr = -1;
    u_char *pHwaSrc = NULL;
    u_char *pHwaDst = NULL;

    u_char hwalen;

    /*
     * init 
     */
    if(argc == 1)
    {
	usage(argv[0]);
	exit(EXIT_SUCCESS);
    }

    memset(ifhwa, 0, sizeof(ifhwa));
    memset(errbuf, 0, LIBNET_ERRBUF_SIZE);
    memset(sk_ifname, 0, MAXIFNAMELEN);
    snprintf(sk_ifname, sizeof(sk_ifname) - 1, "eth0");/* FIXME: linux && Ethernet */

    while((ch =
	    getopt_long(argc, argv, "wrpmd:s:D:S:i:c:T:a:n:NhV", sk_options,
		&opt_idx)) != -1)
    {
	switch (ch)
	{

	    /*
	     * Modes 
	     */
	    case 'w':
		if(sk_code)
		    fatal("** Error (%s): %s mode already set.\n",
			sk_options[OPT_WHO_HAS].name,
			sk_options[opt_code].name);

		sk_code |= SK_WHO_HAS;
		opt_code = OPT_WHO_HAS;
		break;

	    case 'r':
		if(sk_code)
		    fatal("** Error (%s): %s mode already set.\n",
			sk_options[OPT_REPLY].name,
			sk_options[opt_code].name);

		sk_code |= SK_REPLY;
		opt_code = OPT_REPLY;
		break;

	    case 'p':
		if(sk_code)
		    fatal("** Error (%s): %s mode already set.\n",
			sk_options[OPT_ARPING].name,
			sk_options[opt_code].name);

		sk_code |= SK_ARPING;
		opt_code = OPT_ARPING;
		break;

	    case 'm':		/* TODO */
		if(sk_code)
		    fatal("** Error (%s): %s mode already set.\n",
			sk_options[OPT_ARPMIM].name,
			sk_options[opt_code].name);

		sk_code |= SK_ARPMIM;
		opt_code = OPT_ARPMIM;
		fatal(" **Error : arpmim not yet implemented.\n");
		break;

	    case 0:
		printf("option %s\n", sk_options[opt_idx].name);
		/*
		 * If this option sets a flag, do nothing else now. 
		 */
		if(sk_options[opt_idx].flag != 0)
		    break;
		if(optarg)
		    printf(" with arg %s", optarg);
		printf("\n");
		break;

	    /*
	     * Addresses for the Link layer packet 
	     */
	    case 'd':
		if(pOptHwaDst)
		{
		    fatal("** Error: multiple -d used\n");
		}
		pOptHwaDst = optarg;
		break;

	    case 's':
		if(pOptHwaSrc)
		    fatal("** Error: multiple -s used\n");

		pOptHwaSrc = optarg;
		break;

	    case 512:
		if(sk_rand_pkt & SK_RAND_HWA_SRC)
		    fatal("** Error (%s): rand-hwa-src already set.\n",
			sk_options[OPT_RAND_HWA].name);

		if(sk_rand_pkt & SK_RAND_HWA_DST)
		    fatal("** Error (%s): rand-hwa-dst already set.\n",
			sk_options[OPT_RAND_HWA].name);

		sk_rand_pkt |= SK_RAND_HWA;
		break;

	    case 513:
		if(sk_rand_pkt & SK_RAND_HWA)
		    fatal("** Error (%s): rand-hwa already set.\n",
			sk_options[OPT_RAND_HWA_DST].name);

		if(sk_rand_pkt & SK_RAND_HWA_SRC)
		    sk_rand_pkt |= SK_RAND_HWA;
		else
		    sk_rand_pkt |= SK_RAND_HWA_DST;
		break;

	    case 514:
		if(sk_rand_pkt & SK_RAND_HWA)
		    fatal("** Error (%s): rand-hwa already set.\n",
			sk_options[OPT_RAND_HWA_SRC].name);

		if(sk_rand_pkt & SK_RAND_HWA_SRC)
		    sk_rand_pkt |= SK_RAND_HWA;
		else
		    sk_rand_pkt |= SK_RAND_HWA_SRC;
		break;


            /*
	     * ARP message 
	     */
	    case 'D':
		if(pOptArpDst)
		    fatal("** Error: multiple -D used\n");

		pOptArpDst = optarg;
		break;

	    case 'S':
		if(pOptArpSrc)
		    fatal("** Error: multiple -S used\n");

		pOptArpSrc = optarg;
		break;

	    case 1024:
		if(old_arp)
		    fatal("** Error (%s): %s already set.\n",
			sk_options[OPT_RAND_ARP].name,
			sk_options[old_arp].name);

		sk_rand_pkt |= SK_RAND_ARP;
		break;

	    case 1025:
		if(sk_rand_pkt & SK_RAND_ARP)
		    fatal("** Error (%s) : %s already set.\n",
			sk_options[OPT_RAND_ARP_DST].name,
			sk_options[OPT_RAND_ARP].name);

		if(sk_rand_pkt & SK_RAND_ARP_HWA_DST)
		    fatal("** Error (%s) :  %s already set.\n",
			sk_options[OPT_RAND_ARP_DST].name,
			sk_options[OPT_RAND_ARP_HWA_DST].name);

		if(sk_rand_pkt & SK_RAND_ARP_LOG_DST)
		    fatal("** Error (%s) :  %s already set.\n",
			sk_options[OPT_RAND_ARP_DST].name,
			sk_options[OPT_RAND_ARP_LOG_DST].name);

		sk_rand_pkt |= SK_RAND_ARP_DST;
		old_arp = OPT_RAND_ARP_DST;
		break;

	    case 1026:
		if(sk_rand_pkt & SK_RAND_ARP)
		    fatal("** Error (%s) : %s already set.\n",
			sk_options[OPT_RAND_ARP_SRC].name,
			sk_options[OPT_RAND_ARP].name);

		if(sk_rand_pkt & SK_RAND_ARP_HWA_SRC)
		    fatal("** Error (%s) :  %s already set.\n",
			sk_options[OPT_RAND_ARP_SRC].name,
			sk_options[OPT_RAND_ARP_HWA_SRC].name);

		if(sk_rand_pkt & SK_RAND_ARP_LOG_SRC)
		    fatal("** Error (%s) :  %s already set.\n",
			sk_options[OPT_RAND_ARP_SRC].name,
			sk_options[OPT_RAND_ARP_LOG_SRC].name);

		sk_rand_pkt |= SK_RAND_ARP_SRC;
		old_arp = OPT_RAND_ARP_SRC;
		break;

	    case 1027:
		if(sk_rand_pkt & SK_RAND_ARP)
		    fatal("** Error (%s) : %s already set.\n",
			sk_options[OPT_RAND_ARP_HWA_DST].name,
			sk_options[OPT_RAND_ARP].name);

		if(sk_rand_pkt & SK_RAND_ARP_DST)
		    fatal("** Error (%s) :  %s already set.\n",
			sk_options[OPT_RAND_ARP_HWA_DST].name,
			sk_options[OPT_RAND_ARP_DST].name);

		sk_rand_pkt |= SK_RAND_ARP_HWA_DST;
		old_arp = OPT_RAND_ARP_HWA_DST;
		break;

	    case 1028:
		if(sk_rand_pkt & SK_RAND_ARP)
		    fatal("** Error (%s) : %s already set.\n",
			sk_options[OPT_RAND_ARP_LOG_DST].name,
			sk_options[OPT_RAND_ARP].name);

		if(sk_rand_pkt & SK_RAND_ARP_DST)
		    fatal("** Error (%s) :  %s already set.\n",
			sk_options[OPT_RAND_ARP_LOG_DST].name,
			sk_options[OPT_RAND_ARP_DST].name);

		sk_rand_pkt |= SK_RAND_ARP_LOG_DST;
		old_arp = OPT_RAND_ARP_LOG_DST;
		break;

	    case 1029:
		if(sk_rand_pkt & SK_RAND_ARP)
		    fatal("** Error (%s) : %s already set.\n",
			sk_options[OPT_RAND_ARP_HWA_SRC].name,
			sk_options[OPT_RAND_ARP].name);

		if(sk_rand_pkt & SK_RAND_ARP_SRC)
		    fatal("** Error (%s) :  %s already set.\n",
			sk_options[OPT_RAND_ARP_HWA_SRC].name,
			sk_options[OPT_RAND_ARP_SRC].name);

		sk_rand_pkt |= SK_RAND_ARP_HWA_SRC;
		old_arp = OPT_RAND_ARP_HWA_SRC;
		break;

	    case 1030:
		if(sk_rand_pkt & SK_RAND_ARP)
		    fatal("** Error (%s) : %s already set.\n",
			sk_options[OPT_RAND_ARP_LOG_SRC].name,
			sk_options[OPT_RAND_ARP].name);

		if(sk_rand_pkt & SK_RAND_ARP_SRC)
		    fatal("** Error (%s) :  %s already set.\n",
			sk_options[OPT_RAND_ARP_LOG_SRC].name,
			sk_options[OPT_RAND_ARP_SRC].name);

		sk_rand_pkt |= SK_RAND_ARP_LOG_SRC;
		old_arp = OPT_RAND_ARP_LOG_SRC;
		break;


	    /*
	     * Misc options 
	     */
	    case 'i':
		memcpy(sk_ifname, optarg, MAXIFNAMELEN - 1);
		break;

	    case 'c':
		sk_opt_count = atoi(optarg);
		break;

	    case 'T':
		if(*optarg == 'u')	/* micro sec */
		{
		    sk_opt_udelay = 1;
		    sk_opt_usec_delay.it_value.tv_sec =
			sk_opt_usec_delay.it_interval.tv_sec = 0;
		    sk_opt_usec_delay.it_value.tv_usec =
			sk_opt_usec_delay.it_interval.tv_usec =
			atol(optarg + 1);
		}
		else
		{
		    sk_opt_delay = atoi(optarg);
		}
		break;

	    case 2048:
		sk_opt_rand_delay = atol(optarg);
		break;

/*
	    case 'a':
		if(!strncmp("eth-ip", optarg, 6))
		{
		    if(!(arp_pkt = sk_init(ARP_ETH_IP)))
		    {
			fatal("** Error: fail to init (ARP_ETH_IP).\n");
		    }
		}
		else
		{
		    fatal("** Error: address spaces %s not yet supported.\n",
			optarg);
		}
		break;
*/
	    case 'n':	/* FIXME (maybe) : sk_bcast is IP specific ??? */
		if(!inet_aton(optarg, (struct in_addr *)&sk_bcast))
		{
		    fatal
			("** Error (%s): can't convert network address %s.\n",
			sk_options[OPT_NETWORK].name, optarg);
		}
		break;

	    case 'N':
		sk_opt_call_dns = LIBNET_RESOLVE;
		break;

	    case 'V':
		show_version();
		exit(EXIT_SUCCESS);

	    case 'h':
		show_version();
		usage(argv[0]);
		exit(EXIT_SUCCESS);

	    case '?':
		exit(EXIT_FAILURE);
		break;

	    default:
		fprintf(stderr,
		    "** Error: unknown option: %s (%d).\n", optarg, optind);
		exit(EXIT_FAILURE);
	}
    }				/* while(getopt()) */

    if(!arp_pkt && !(arp_pkt = sk_init(ARP_ETH_IP)))
    {
	fatal("** Error: fail to init arp default (ARP_ETH_IP).\n");
    }

    hwalen = arpsk_get_hlen(arp_pkt);

    if(sk_code & ARPOP_REQUEST)
    {
	arpsk_set_code(arp_pkt, ARPOP_REQUEST);
    }


    /*
     * Check options 
     * TODO: what to do if rand options are used ... 
     */
    if(!sk_code)
    {
	warning("- Warning: no mode given, using default.\n");
	sk_code = SK_REPLY;
	opt_code = OPT_REPLY;
    }
    printf("+ Running mode \"%s\"\n", sk_options[opt_code].name);


    /*
     * Initialize the arguments 
     */
    if(!(sk_libnet_link = libnet_init(LIBNET_LINK, sk_ifname, errbuf)))
    {
	fatal("** Error: can't open link interface %s:\n%s\n",
	    sk_ifname, errbuf);
    }
    printf("+ Ifname: %s\n", libnet_getdevice(sk_libnet_link));


    /*
     * HW src 
     */
    pHwaSrc = arpsk_get_hwa_src(arp_pkt);
    arpsk_get_ifhwa(sk_ifname, ifhwa);

    if(pOptHwaSrc)
    {
	if(strchr(pOptHwaSrc, ':'))
	{
	    arpsk_parse_mac(pOptHwaSrc, pHwaSrc);
	}
	else			/* IP is given as target */
	{
	    if((src_addr = libnet_name2addr4(sk_libnet_link,
			(char *) pOptHwaSrc, LIBNET_RESOLVE)) == (u_long)-1)
	    {
		fatal("** Error: %s\n", libnet_geterror(sk_libnet_link));
	    }

	    if(!arpsk_resolve_hwa_from_log(pHwaSrc, src_addr))
	    {
		warning("- Warning: "
		    "can't find MAC addr for %s => using local.\n",
		    pOptHwaSrc);
		arpsk_set_hwa_src(arp_pkt, ifhwa);
	    }
	}
    }
    else
    {
	if(sk_rand_pkt & (SK_RAND_HWA | SK_RAND_HWA_SRC))
	{
	    arpsk_get_rand_hwa(ifhwa);
	}
	arpsk_set_hwa_src(arp_pkt, ifhwa);
    }

    arpsk_snprintf_hwa_src(str, sizeof(str), arp_pkt);
    printf("+ Source MAC: %s\n", str);


    /*
     * ARP src (i.e. the answer in a reply packet) 
     */
    if(pOptArpSrc)		/* IP[:MAC] or Name:[MAC] */
    {
	if(!arpsk_str2hwlog(pOptArpSrc, arpsk_get_arp_src(arp_pkt), 0x00))
	{
	    fatal("** Error: can't parse src %s.\n", pOptArpSrc);
	}

	/*
	 * if no MAC is given in the ARP message put the one provided
	 * in the Ethernet layer 
	 */
	if(!strchr(pOptArpSrc, ':'))
	{
	    arpsk_set_arp_src_hwa(arp_pkt, pHwaSrc);
	}
    }
    else
    {
	/*
	 * no source provided => use what is provided in the Ethernet layer 
	 */
	arpsk_set_arp_src_hwa(arp_pkt, pHwaSrc);
	if(src_addr != (u_long)-1)
	{
	    memcpy(ifhwa, pHwaSrc, hwalen * sizeof(u_char));
	    log_addr = src_addr;
	}
	else
	{
	    /*
	     * is it the local iface ? 
	     */

	    if(memcmp(pHwaSrc, ifhwa, hwalen * sizeof(u_char)))
	    {
		/*
		 * nop, thus  get the remote IP 
		 */
		if(!sk_use_ts ||
		    !arpsk_resolve_log_from_hwa(&log_addr, pHwaSrc))
		{
		    /*
		     * argh, we can't ... use the local address anyway 
		     */
		    arpsk_snprintf_arp_src_hwa(str, sizeof(str), arp_pkt);
		    warning("- Warning: "
			"can't resolve from mac %s => use local one.\n", str);
		    arpsk_get_iflog(sk_ifname, &log_addr);
		}
	    }
	    else
	    {
		/*
		 * yep, thus get the local addr 
		 */
		arpsk_get_iflog(sk_ifname, &log_addr);
	    }
	}
	arpsk_set_arp_src_log(arp_pkt, log_addr);
    }

    /*
     * Random arp src 
     */
    if(sk_rand_pkt & (SK_RAND_ARP | SK_RAND_ARP_SRC | SK_RAND_ARP_HWA_SRC))
    {
	arpsk_get_rand_hwa(ifhwa);
	arpsk_set_arp_src_hwa(arp_pkt, ifhwa);
    }

    if(sk_rand_pkt & (SK_RAND_ARP | SK_RAND_ARP_SRC | SK_RAND_ARP_LOG_SRC))
    {
	arpsk_get_rand_log(&log_addr);
	arpsk_set_arp_src_log(arp_pkt, log_addr);
    }

    arpsk_snprintf_arp_src_hwa(str, sizeof(str), arp_pkt);
    printf("+ Source ARP MAC: %s\n", str);
    arpsk_snprintf_arp_src_log(str, sizeof(str), arp_pkt,
	LIBNET_DONT_RESOLVE);
    printf("+ Source ARP IP : %s ", str);
    if(sk_opt_call_dns == LIBNET_RESOLVE)
    {
	arpsk_snprintf_arp_src_log(str, sizeof(str), arp_pkt, LIBNET_RESOLVE);
	printf("(%s)\n", str);
    }
    else
	printf("\n");

    /*
     * HW dst 
     */
    pHwaDst = arpsk_get_hwa_dst(arp_pkt);
    memset(ifhwa, 0xff, sizeof(ifhwa) - 1);
    ifhwa[sizeof(ifhwa) - 1] = 0;

    if(pOptHwaDst)
    {
	if(strchr(pOptHwaDst, ':'))
	{
	    arpsk_parse_mac(pOptHwaDst, pHwaDst);
	}
	else			/* IP is given as target */
	{
	    if((dst_addr = libnet_name2addr4(sk_libnet_link,
			(char *) pOptHwaDst, LIBNET_RESOLVE)) == (u_long)-1)
	    {
		fatal("** Error: %s (%s)\n", 
		      libnet_geterror(sk_libnet_link),
		      pOptHwaDst);
	    }

	    if(!arpsk_resolve_hwa_from_log(pHwaDst, dst_addr))
	    {
		warning("- Warning: "
		    "can't find MAC addr for %s => using bcast.\n",
		    pOptHwaDst);
		arpsk_set_hwa_dst(arp_pkt, ifhwa);
	    }
	}
    }
    else
    {
	if(sk_rand_pkt & (SK_RAND_HWA | SK_RAND_HWA_DST))
	{
	    arpsk_get_rand_hwa(ifhwa);
	}
	arpsk_set_hwa_dst(arp_pkt, ifhwa);
    }

    arpsk_snprintf_hwa_dst(str, sizeof(str), arp_pkt);
    printf("+ Target MAC: %s\n", str);


    /*
     * ARP dst 
     */
    if(pOptArpDst)
    {
	if(!arpsk_str2hwlog(pOptArpDst,
		arpsk_get_arp_dst(arp_pkt),
		(sk_code & SK_WHO_HAS ? 0x00 : 0xff)))
	{
	    fatal("** Error: can't parse dst %s.\n", pOptArpDst);
	}

	/*
	 * if no MAC is given in the ARP message put the one provided
	 * in the Ethernet layer 
	 */
	if((sk_code & ~SK_WHO_HAS) &&
	    !strchr(pOptArpDst, ':') &&
	    memcmp(pHwaDst, ifhwa, hwalen * sizeof(u_char)))
	{
	    arpsk_set_arp_dst_hwa(arp_pkt, pHwaDst);
	}
    }
    else
    {
	if(dst_addr != (u_long)-1)
	{
	    memcpy(ifhwa, pHwaDst, hwalen * sizeof(u_char));
	    log_addr = dst_addr;
	}
	else
	{
	    /*
	     * broadcast in link layer ? 
	     */
	    if(memcmp(ifhwa, pHwaDst, hwalen * sizeof(u_char)))
	    {
		memcpy((char *)ifhwa, (char *)pHwaDst,  hwalen * sizeof(u_char));

		if(!sk_use_ts ||
		    !arpsk_resolve_log_from_hwa(&log_addr, pHwaDst))
		{
		    arpsk_snprintf_hwa_dst(str, sizeof(str), arp_pkt);
		    warning("- Warning: "
			"can't resolve from mac address %s.\n", str);
		    log_addr = 0;	/*FIXME: this is not valid */
		}
	    }
	    else
	    {
		if(arpsk_get_code(arp_pkt) == ARPOP_REQUEST)
		{
		    memset(ifhwa, 0x0, sizeof(ifhwa));
		}
		log_addr = -1;
	    }
	}
	arpsk_set_arp_dst_hwa(arp_pkt, ifhwa);
	arpsk_set_arp_dst_log(arp_pkt, log_addr);
    }

    /*
     * random arp src 
     */
    if(sk_rand_pkt & (SK_RAND_ARP | SK_RAND_ARP_DST | SK_RAND_ARP_HWA_DST))
    {
	arpsk_get_rand_hwa(ifhwa);
	arpsk_set_arp_dst_hwa(arp_pkt, ifhwa);
    }

    if(sk_rand_pkt & (SK_RAND_ARP | SK_RAND_ARP_DST | SK_RAND_ARP_LOG_DST))
    {
	arpsk_get_rand_log(&log_addr);
	arpsk_set_arp_dst_log(arp_pkt, log_addr);
    }

    arpsk_snprintf_arp_dst_hwa(str, sizeof(str), arp_pkt);
    printf("+ Target ARP MAC: %s\n", str);
    arpsk_snprintf_arp_dst_log(str, sizeof(str), arp_pkt,
	LIBNET_DONT_RESOLVE);
    printf("+ Target ARP IP : %s ", str);
    if(sk_opt_call_dns == LIBNET_RESOLVE)
    {
	arpsk_snprintf_arp_dst_log(str, sizeof(str), arp_pkt, LIBNET_RESOLVE);
	printf("(%s)\n", str);
    }
    else
	printf("\n");

    /*
     * Building the packets 
     */
    t_arp = build_arp(arp_pkt, 0);
    t_hwa = arpsk_build_hwa(arp_pkt, 0);

    /*
     * Write the packets 
     */

#ifdef HAVE_SIGSEND
    /*
     * use SIGALRM to send packets like ping does
     */
    Signal(SIGALRM, send_packet);
#endif
    Signal(SIGHUP, cleanup);
    Signal(SIGINT, cleanup);
    Signal(SIGTERM, cleanup);


    return (sk_rand_pkt ?
	do_random_hook(arp_pkt) : do_classical_hook(arp_pkt));
}

int
do_classical_hook(arpsk_arp_pkt_t *arp_pkt)
{

    printf("\n--- Start classical sending ---\n");

    /*
     * start packet sending 
     */
    sk_pkt = arp_pkt;

#ifdef HAVE_SIGSEND
    kill(getpid(), SIGALRM);
    while(1)			/* FIXME: this is too much CPU consuming */
	pause();
#endif

#if !defined(HAVE_SIGSEND)
    while(sk_opt_count == -1 || sk_opt_count)
    {
	send_packet(42);
    }

    cleanup(42);
#endif /* HAVE_SIGSEND */

    return (EXIT_SUCCESS);
}


int
do_random_hook(arpsk_arp_pkt_t *arp_pkt)
{

    u_char ifhwa[20];
    u_long addr;

#ifdef HAVE_SIGSEND
    sigset_t sset;

    sigemptyset(&sset);
    sigaddset(&sset, SIGALRM);
    sigaddset(&sset, SIGHUP);
    sigaddset(&sset, SIGINT);
    sigaddset(&sset, SIGTERM);
#endif

    printf("\n--- Start sending with random data ---\n");

    /*
     * start packet sending 
     */
    sk_pkt = arp_pkt;

#if !defined(HAVE_SIGSEND)
    while(sk_opt_count == -1 || sk_opt_count)
    {
	send_packet(42);
#else
    kill(getpid(), SIGALRM);

    while(1)
    {
	sigprocmask(SIG_BLOCK, &sset, NULL);
#endif

	/*
	 * rand hwa 
	 */
	if(sk_rand_pkt & (SK_RAND_HWA | SK_RAND_HWA_SRC))
	{
	    arpsk_get_rand_hwa(ifhwa);
	    arpsk_set_hwa_src(arp_pkt, ifhwa);
	}

	if(sk_rand_pkt & (SK_RAND_HWA | SK_RAND_HWA_DST))
	{
	    arpsk_get_rand_hwa(ifhwa);
	    arpsk_set_hwa_dst(arp_pkt, ifhwa);
	}

	/*
	 * rand arp 
	 */
	if(sk_rand_pkt &
	    (SK_RAND_ARP | SK_RAND_ARP_SRC | SK_RAND_ARP_HWA_SRC))
	{
	    arpsk_get_rand_hwa(ifhwa);
	    arpsk_set_arp_src_hwa(arp_pkt, ifhwa);
	}

	if(sk_rand_pkt &
	    (SK_RAND_ARP | SK_RAND_ARP_SRC | SK_RAND_ARP_LOG_SRC))
	{
	    arpsk_get_rand_log(&addr);
	    arpsk_set_arp_src_log(arp_pkt, addr);
	}

	if(sk_rand_pkt &
	    (SK_RAND_ARP | SK_RAND_ARP_DST | SK_RAND_ARP_HWA_DST))
	{
	    arpsk_get_rand_hwa(ifhwa);
	    arpsk_set_arp_dst_hwa(arp_pkt, ifhwa);
	}

	if(sk_rand_pkt &
	    (SK_RAND_ARP | SK_RAND_ARP_DST | SK_RAND_ARP_LOG_DST))
	{
	    arpsk_get_rand_log(&addr);
	    arpsk_set_arp_dst_log(arp_pkt, addr);
	}

	/*
	 * FIXME: is it really necessary to rebuild the 2 layers if only 1 
	 * was modified ? 
	 * To be tested ...
	 */
	t_arp = build_arp(arp_pkt, t_arp);
	t_hwa = arpsk_build_hwa(arp_pkt, t_hwa);

#ifdef HAVE_SIGSEND
	sigprocmask(SIG_UNBLOCK, &sset, NULL);
	pause();
#endif

    }

    cleanup(42);

    return (EXIT_SUCCESS);
}
