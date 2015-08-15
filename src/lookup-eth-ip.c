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


/*
 * lookup.c
 * Contains all functions related to address resolution
 * 
 *
 * Copied from net/if_arp.h
 *
 * ARP Flag values.
 * #define ATF_COM	   0x02		Completed entry (ha valid).
 * #define ATF_PERM	   0x04		Permanent entry.
 * #define ATF_PUBL	   0x08		Publish entry.
 * #define ATF_USETRAILERS 0x10		Has requested trailers.
 * #define ATF_NETMASK     0x20         Want to use a netmask (only
 *                                      for proxy entries).
 * #define ATF_DONTPUB	   0x40		Don't answer this addresses.
 * #define ATF_MAGIC	   0x80		Automatically added entry.
 * 
 */

#include "sk.h"
#include "arp-eth-ip.h"
#include <net/if_arp.h>

libnet_ptag_t tag_icmp = LIBNET_PTAG_INITIALIZER;
libnet_ptag_t tag_ipv4 = LIBNET_PTAG_INITIALIZER;
libnet_ptag_t tag_ethernet = LIBNET_PTAG_INITIALIZER;


u_long sk_bcast = -1;		/* broadcast */

#if defined(HAVE_PSEUDO_PROCFS) || defined(__linux__)

int
lookup_in_arp_cache(char *etheraddr, char *ipaddr, char resolve)
{

    FILE *fd;
    char buffer[256];
    char *ptr, *ip, *hwtype, *f, *ether;
    size_t len;
    unsigned long int flags;

    if(!(fd = fopen(ARP_CACHE_FILE, "r")))
    {
	perror("** Error: can't open " ARP_CACHE_FILE "\n");
	return 0;
    }

    fgets(buffer, sizeof(buffer) - 1, fd);	/* skip header (1st line) */
    memset(buffer, 0, sizeof(buffer));

    while(fgets(buffer, sizeof(buffer) - 1, fd))
    {
	ptr = buffer;
	ip = strtok(ptr, " \t");	/* IP address */
	hwtype = strtok(NULL, " \t");	/* HW type */

	if (strtoul(hwtype, 0, 16) != ARPHRD_ETHER)
	{
#ifdef _DEBUG_
	    fprintf(stderr,"%s: found a non eth address:\n[%s]\n",
		    __FUNCTION__, buffer);
#endif
	    continue;
	}

	f = strtok(NULL, " \t");	/* Flags */
	flags = strtoul(f, 0, 16);
/*
	if ( (flags & ATF_PUBL) )
	{
#ifdef _DEBUG_
	    fprintf(stderr,"%s: found a proxied entry :\n[%s]\n",
		    __FUNCTION__, buffer);
#endif
	    continue;
	}
*/
	if ( !(flags & ATF_COM) )
	{
#ifdef _DEBUG_
	    fprintf(stderr,"%s: found an invalid entry :\n[%s]\n",
		    __FUNCTION__, buffer);
#endif
	    continue;
	}

	ether = strtok(NULL, " \t");	/* HW address */

	if(resolve == LOOKUP_ETHER)	/* lookup ETHER and returns IP */
	{
	    if(!strncasecmp(etheraddr, ether, strlen(etheraddr)))
	    {
		strlcpy(ipaddr, ip, MAX_IP_ADDR);
		fclose(fd);
		return 1;
	    }
	}
	else			/* lookup IP and returns ETHER */
	{
	    len = strlen(ipaddr);
	    if(strlen(ip) ==  len && !strncmp(ipaddr, ip, len))
	    {
		strlcpy(etheraddr, ether, MAX_ETHER_ADDR);
		fclose(fd);
		return 1;
	    }
	}
    }
    fclose(fd);
    return 0;
}


#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>



#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
int
lookup_in_arp_cache(char *etheraddr, char *ipaddr, char resolve)
{
    size_t needed;
    char *lim, *buf, *next;
    char iphost[MAXHOSTNAMELEN];
    char *mac;
    u_char ether[6];
    struct rt_msghdr *rtm;
    struct sockaddr_inarp *sin;
    struct sockaddr_dl *sdl;
    int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET,
		   NET_RT_FLAGS, RTF_LLINFO };
    
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
	return (-1);
    
    if (needed == 0)
	return (0);

    if ((buf = (char *)malloc(needed)) == NULL)
	return (-1);
	
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0) {
	free(buf);
	return (-1);
    }
    lim = buf + needed;
    if (resolve == LOOKUP_ETHER)
	parse_ethernet(etheraddr, ether);

    for (next = buf; next < lim; next += rtm->rtm_msglen) 
    {
	rtm = (struct rt_msghdr *)next;
	sin = (struct sockaddr_inarp *)(rtm + 1);
	sdl = (struct sockaddr_dl*)((char*)sin + ROUNDUP(sin->sin_len));
	mac = LLADDR(sdl);

	if(resolve == LOOKUP_ETHER)	/* lookup ETHER and returns IP */
	{

#ifdef _DEBUG_
	    printf("mac = %02x:%02x:%02x:%02x:%02x:%02x\n", 
		   mac[0]&0xff, mac[1]&0xff, mac[2]&0xff, 
		   mac[3]&0xff, mac[4]&0xff, mac[5]&0xff);

	    printf("ether = %02x:%02x:%02x:%02x:%02x:%02x\n", 
		   ether[0]&0xff, ether[1]&0xff, ether[2]&0xff, 
		   ether[3]&0xff, ether[4]&0xff, ether[5]&0xff);
#endif /* _DEBUG_ */

	    if (ether[0] == (mac[0]&0xff) && ether[1] == (mac[1]&0xff) &&
		ether[2] == (mac[2]&0xff) && ether[3] == (mac[3]&0xff) &&
		ether[4] == (mac[4]&0xff) && ether[5] == (mac[5]&0xff))
	    {
		strlcpy(ipaddr, inet_ntoa(sin->sin_addr), MAXHOSTNAMELEN);
		free(buf);
		return (1);
	    }
	}
	else /* lookup IP and returns ETHER */
	{
	    strlcpy(iphost, inet_ntoa(sin->sin_addr), MAXHOSTNAMELEN);

#ifdef _DEBUG_
	    printf("ip = %s\n", iphost);
	    printf("mac = %02x:%02x:%02x:%02x:%02x:%02x\n", 
		   mac[0]&0xff, mac[1]&0xff, mac[2]&0xff, 
		   mac[3]&0xff, mac[4]&0xff, mac[5]&0xff);
#endif /* _DEBUG_ */

	    if (!strcmp(iphost, ipaddr))
	    {
		snprintf(etheraddr, MAX_ETHER_ADDR,
			 "%02x:%02x:%02x:%02x:%02x:%02x", 
			 mac[0]&0xff, mac[1]&0xff, mac[2]&0xff, 
			 mac[3]&0xff, mac[4]&0xff, mac[5]&0xff);
		free(buf);
		return (1);
	    }
	}
    }
    free(buf);
    return (0);
}

#else

int
lookup_in_arp_cache(char *etheraddr, char *ipaddr, char resolve)
{
    fprintf(stderr, "lookup_in_arp_cache(): system not supported\n");
    fprintf(stderr, 
	    "You can use the --with-arpcache with configure to setup a fake "
	    "arp cache.\n\n");
    fprintf(stderr, "Please contact me: F. Raynal <pappy@security-labs.org>\n");
    exit (-1);
}
#endif


int
resolve_ip_from_eth(u_long * ip, u_char * eth)
{

    u_long myip;
    int i = 0;
    char ether[MAX_ETHER_ADDR];
    char host[MAXHOSTNAMELEN];
    libnet_t *icmp_link;
    char errbuf[LIBNET_ERRBUF_SIZE];

    if(!(icmp_link = libnet_init(LIBNET_LINK, sk_ifname, errbuf)))
    {
	fatal("** Error(%s): can't open link interface %s:\n%s\n",
	    __FUNCTION__, sk_ifname, errbuf);
    }

    snprintf(ether, sizeof(ether), "%02x:%02x:%02x:%02x:%02x:%02x",
	eth[0] & 0xff, eth[1] & 0xff, eth[2] & 0xff,
	eth[3] & 0xff, eth[4] & 0xff, eth[5] & 0xff);

    /*
     * lookup in cache 
     */
    if(lookup_in_arp_cache(ether, host, LOOKUP_ETHER))
    {
	return inet_aton(host, (struct in_addr *)ip);
    }

    /*
     * if it is not there ... send a broadcast ping (timestamp) ... 
     */
    myip = libnet_get_ipaddr4(icmp_link);

    tag_icmp = libnet_build_icmpv4_timestamp(ICMP_TSTAMP,	/* type */
	0,			/* code */
	0,			/* checksum */
	242,			/* id */
	424,			/* sequence number */
	1000,			/* otime */
	2000,			/* rtime */
	3000,			/* ttime */
	NULL,			/* payload */
	0,			/* payload size */
	icmp_link,		/* libnet handle */
	0);

    if(tag_icmp == -1)
    {
	fatal("** Error: can't build ICMP header: %s\n",
	    libnet_geterror(icmp_link));
    }

    tag_ipv4 = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_ICMPV4_TS_H,	/* length */
	0,			/* TOS */
	242,			/* IP ID */
	0,			/* IP Frag */
	64,			/* TTL */
	IPPROTO_ICMP,		/* protocol */
	0,			/* checksum */
	myip,			/* source IP */
	sk_bcast,		/* destination IP */
	NULL,			/* payload */
	0,			/* payload size */
	icmp_link,		/* libnet handle */
	0);

    if(tag_ipv4 == -1)
    {
	fatal("** Error: can't build IP header: %s\n",
	    libnet_geterror(icmp_link));
    }

    tag_ethernet = libnet_autobuild_ethernet(eth,  /* ethernet destination */
	ETHERTYPE_IP,		/* protocol type */
	icmp_link);	        /* libnet handle */

    if(tag_ethernet == -1)
    {
	fatal("** Error: can't build ETHER header: %s\n",
	    libnet_geterror(icmp_link));
    }

    if((i = libnet_write(icmp_link)) == -1)
    {
	fatal("** Error: write error: %s\n", libnet_geterror(icmp_link));
    }

    printf("Wrote ICMP timestamp (%d bytes) to retrieve IP address ... \n",
	i);

    libnet_destroy(icmp_link);

    /*
     * and look again in /proc/net/arp 
     */
    sleep(ARP_RESOLVE_DELAY);

    if(lookup_in_arp_cache(ether, host, LOOKUP_ETHER))
    {
	return inet_aton(host, (struct in_addr *)ip);
    }

    return 0;
}

int
resolve_eth_from_ip(u_char * eth, u_long ip)
{

    int i = 0, s;
    char ether[MAX_ETHER_ADDR];
    struct sockaddr_in sock_in;
    char host[MAXHOSTNAMELEN];
    struct in_addr ipaddr;

    /*
     * lookup in cache 
     */
    ipaddr.s_addr = ip;
    strlcpy(host, inet_ntoa(ipaddr), MAXHOSTNAMELEN);
    if(lookup_in_arp_cache(ether, host, LOOKUP_IP))
    {
	parse_ethernet(ether, eth);
	return 1;
    }

    /*
     * Shit ... got to send a fake packet 
     * Thanks to Dug Song and his dsniff for this trick 
     */
    if((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
	perror("** Error: can't open socket.\n");
	return 0;
    }

    memset(&sock_in, 0, sizeof(sock_in));
    sock_in.sin_family = AF_INET;
    sock_in.sin_addr.s_addr = libnet_name2addr4(sk_libnet_link,
	(char *) host, LIBNET_RESOLVE);
    sock_in.sin_port = htons(53);

    i = sendto(s, NULL, 0, 0, (struct sockaddr *)&sock_in, sizeof(sock_in));

    close(s);

    /*
     * and look again in /proc/net/arp 
     */
    sleep(ARP_RESOLVE_DELAY);

    if(lookup_in_arp_cache(ether, host, LOOKUP_IP))
    {
	parse_ethernet(ether, eth);
	return 1;
    }

    return 0;
}
