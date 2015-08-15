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


#include "sk.h"
#include "arp-eth-ip.h"
#include <net/ethernet.h>

void
parse_ethernet(char *eth_str, u_char * eth)
{

    unsigned int tmp[6];
    int i;

    i = sscanf(eth_str, "%02X:%02X:%02X:%02X:%02X:%02X",
	&tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);

    if(i != 6)
    {
	fatal("** Error: invalid eth address (%s).\n", eth_str);
    }

    for(i = 0; i < 6; i++)
	eth[i] = tmp[i];
}

int
get_if_eth_addr(char *ifname, u_char * eth)
{

    libnet_t *link = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    struct libnet_ether_addr *hwaddr;
    int i;

    if(!(link = libnet_init(LIBNET_LINK, ifname, errbuf)))
    {
	fatal("** Error (%s): can't open link interface %s:\n%s\n",
	    __FILE__, ifname, errbuf);
    }

    hwaddr = libnet_get_hwaddr(link);
    if(!hwaddr)
    {
	fatal("** Error (%s): can't get hardware address: %s\n",
	    __FILE__, libnet_geterror(sk_libnet_link));
    }

    for(i = 0; i < 6; i++)
	eth[i] = (u_char) (hwaddr->ether_addr_octet[i]);

    libnet_destroy(link);

    return (1);
}


/* 
 * FIXME: why is there casting involving eIarp ?
 * try something like casting only on the Ethernet structure arpsk_ethernet_t
 */
libnet_ptag_t
build_eth(arpsk_arp_pkt_t * p, libnet_ptag_t tag)
{

    arpsk_eiarp_pkt_t *pkt = p;

    tag = libnet_build_ethernet(pkt->eth.dst,	/* ethernet destination */
	pkt->eth.src,		/* ethernet source */
	ETHERTYPE_ARP,		/* protocol type */
	NULL,			/* payload */
	0,			/* payload size */
	sk_libnet_link,		/* libnet handle */
	tag);			/* libnet id */

    if(tag == -1)
    {
	fatal("** Error: can't build ETHER header: %s\n",
	    libnet_geterror(sk_libnet_link));
    }

    return (tag);
}

void
get_rand_eth(u_char * eth)
{

    int i;

    for(i = 0; i < 6; i++)
	eth[i] = random() % 0xff;
}
