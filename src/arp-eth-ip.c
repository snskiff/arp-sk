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


#include "arp-eth-ip.h"


int
sk_init_eiarp_pkt(arpsk_arp_pkt_t *p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    printf("+ Initialization of the packet structure\n");

    memset(p, 0, sizeof(*p));

    pkt->arp.hdr.code = ARPOP_REPLY;
    pkt->arp.hdr.link_proto = ARPHRD_ETHER;
    pkt->arp.hdr.log_proto = ETHERTYPE_IP;
    pkt->arp.hdr.hlen = 6;
    pkt->arp.hdr.llen = 4;

    arpsk_build_hwa = build_eth;

    arpsk_parse_mac = parse_ethernet;
    arpsk_str2hwlog = str2ethip;
    arpsk_get_ifhwa = get_if_eth_addr;
    arpsk_get_iflog = get_if_ip_addr;

    arpsk_get_rand_hwa = get_rand_eth;
    arpsk_get_rand_log = get_rand_ip;

    arpsk_resolve_log_from_hwa = resolve_ip_from_eth;
    arpsk_resolve_hwa_from_log = resolve_eth_from_ip;

    arpsk_set_hwa = set_eth_in_eiarp_pkt;
    arpsk_set_hwa_dst = set_eth_dst_in_eiarp_pkt;
    arpsk_set_hwa_src = set_eth_src_in_eiarp_pkt;

    arpsk_set_arp_msg = set_arp_in_eiarp_pkt;
    arpsk_set_arp_dst = set_arp_dst_in_eiarp_pkt;
    arpsk_set_arp_dst_hwa = set_arp_dst_eth_in_eiarp_pkt;
    arpsk_set_arp_dst_log = set_arp_dst_ip_in_eiarp_pkt;
    arpsk_set_arp_src = set_arp_src_in_eiarp_pkt;
    arpsk_set_arp_src_hwa = set_arp_src_eth_in_eiarp_pkt;
    arpsk_set_arp_src_log = set_arp_src_ip_in_eiarp_pkt;

    arpsk_set_code = set_code_in_eiarp_pkt;

    arpsk_get_code = get_code_in_eiarp_pkt;
    arpsk_get_link_proto = get_link_proto_in_eiarp_pkt;
    arpsk_get_log_proto = get_log_proto_in_eiarp_pkt;
    arpsk_get_hlen = get_hlen_in_eiarp_pkt;
    arpsk_get_llen = get_llen_in_eiarp_pkt;

    arpsk_get_hwa_dst = get_eth_dst_in_eiarp_pkt;
    arpsk_get_hwa_src = get_eth_src_in_eiarp_pkt;

    arpsk_get_arp_dst = get_arp_dst_in_eiarp_pkt;
    arpsk_get_arp_dst_hwa = get_arp_dst_eth_in_eiarp_pkt;
    arpsk_get_arp_dst_log = get_arp_dst_ip_in_eiarp_pkt;
    arpsk_get_arp_src = get_arp_src_in_eiarp_pkt;
    arpsk_get_arp_src_hwa = get_arp_src_eth_in_eiarp_pkt;
    arpsk_get_arp_src_log = get_arp_src_ip_in_eiarp_pkt;

    arpsk_snprintf_hwa_dst = snprintf_eth_dst_in_eiarp_pkt;
    arpsk_snprintf_hwa_src = snprintf_eth_src_in_eiarp_pkt;

    arpsk_snprintf_arp_dst_hwa = snprintf_arp_dst_eth_in_eiarp_pkt;
    arpsk_snprintf_arp_dst_log = snprintf_arp_dst_ip_in_eiarp_pkt;
    arpsk_snprintf_arp_src_hwa = snprintf_arp_src_eth_in_eiarp_pkt;
    arpsk_snprintf_arp_src_log = snprintf_arp_src_ip_in_eiarp_pkt;

    arpsk_snprintf_pkt = snprintf_eiarp_pkt;
    arpsk_snprintf_log_msg = snprintf_arp_in_eiarp_pkt;
    arpsk_snprintf_hwa_msg = snprintf_eth_in_eiarp_pkt;

    return 1;
}

int
get_if_ip_addr(char *ifname, u_long * ip)
{

    *ip = libnet_get_ipaddr4(sk_libnet_link);
    if(*ip == (unsigned long)-1)
    {
	fatal("** Error: "
	    "failure when looking up IP address for interface %s.\n"
	    "%s\n", ifname, libnet_geterror(sk_libnet_link));
    }
    return 1;
}


int
snprintf_arp_dst_ip_in_eiarp_pkt(char *name, size_t sz, arpsk_arp_pkt_t *p, int resolve)
{

    arpsk_eiarp_pkt_t *pkt = (arpsk_eiarp_pkt_t *) p;

    if(!name || !p)
	return -1;

    return snprintf(name, sz, "%s",
	libnet_addr2name4(pkt->arp.dst.ip, resolve));
}

int
snprintf_arp_dst_eth_in_eiarp_pkt(char *hwaddr, size_t sz, arpsk_arp_pkt_t *p)
{

    arpsk_eiarp_pkt_t *pkt = (arpsk_eiarp_pkt_t *) p;
    u_char *ptr;

    if(!hwaddr || !p)
	return -1;

    ptr = pkt->arp.dst.eth;
    return snprintf(hwaddr, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
	ptr[0] & 0xff, ptr[1] & 0xff, ptr[2] & 0xff,
	ptr[3] & 0xff, ptr[4] & 0xff, ptr[5] & 0xff);
}

int
snprintf_eth_dst_in_eiarp_pkt(char *hwaddr, size_t sz, arpsk_arp_pkt_t *p)
{

    arpsk_eiarp_pkt_t *pkt = (arpsk_eiarp_pkt_t *) p;
    u_char *ptr;

    if(!hwaddr || !p)
	return -1;

    ptr = pkt->eth.dst;
    return snprintf(hwaddr, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
	ptr[0] & 0xff, ptr[1] & 0xff, ptr[2] & 0xff,
	ptr[3] & 0xff, ptr[4] & 0xff, ptr[5] & 0xff);
}

int
snprintf_arp_src_ip_in_eiarp_pkt(char *name, size_t sz, arpsk_arp_pkt_t *p, int resolve)
{

    arpsk_eiarp_pkt_t *pkt = (arpsk_eiarp_pkt_t *) p;

    if(!name || !p)
	return -1;

    return snprintf(name, sz, "%s",
	libnet_addr2name4(pkt->arp.src.ip, resolve));
}

int
snprintf_arp_src_eth_in_eiarp_pkt(char *hwaddr, size_t sz, arpsk_arp_pkt_t *p)
{

    arpsk_eiarp_pkt_t *pkt = (arpsk_eiarp_pkt_t *) p;
    u_char *ptr;

    if(!hwaddr || !p)
	return -1;

    ptr = pkt->arp.src.eth;
    return snprintf(hwaddr, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
	ptr[0] & 0xff, ptr[1] & 0xff, ptr[2] & 0xff,
	ptr[3] & 0xff, ptr[4] & 0xff, ptr[5] & 0xff);
}

int
snprintf_eth_src_in_eiarp_pkt(char *hwaddr, size_t sz, arpsk_arp_pkt_t *p)
{

    arpsk_eiarp_pkt_t *pkt = (arpsk_eiarp_pkt_t *) p;
    u_char *ptr;

    if(!hwaddr || !p)
	return -1;

    ptr = pkt->eth.src;
    return snprintf(hwaddr, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
	ptr[0] & 0xff, ptr[1] & 0xff, ptr[2] & 0xff,
	ptr[3] & 0xff, ptr[4] & 0xff, ptr[5] & 0xff);
}


int
snprintf_eth_in_eiarp_pkt(char *str, size_t sz, arpsk_arp_pkt_t *p)
{

    arpsk_eiarp_pkt_t *pkt = (arpsk_eiarp_pkt_t *) p;

    if(!str || !p)
	return -1;

    return snprintf(str, sz,
	       "To: %02x:%02x:%02x:%02x:%02x:%02x "    /* eth dst */
  	       "From: %02x:%02x:%02x:%02x:%02x:%02x "  /* eth src */
  	       "0x0806",                               /* type */
	       pkt->eth.dst[0] & 0xff, pkt->eth.dst[1] & 0xff, pkt->eth.dst[2] & 0xff,
               pkt->eth.dst[3] & 0xff, pkt->eth.dst[4] & 0xff, pkt->eth.dst[5] & 0xff,
	       pkt->eth.src[0] & 0xff, pkt->eth.src[1] & 0xff, pkt->eth.src[2] & 0xff,
               pkt->eth.src[3] & 0xff, pkt->eth.src[4] & 0xff, pkt->eth.src[5] & 0xff);
}

int
snprintf_arp_in_eiarp_pkt(char *str, size_t sz, arpsk_arp_pkt_t *p)
{

    arpsk_eiarp_pkt_t *pkt = (arpsk_eiarp_pkt_t *) p;

    if(!str || !p)
	return -1;

    if (pkt->arp.hdr.code == ARPOP_REQUEST)
    {
	return snprintf(str, sz,
	    "Who has %s (%02x:%02x:%02x:%02x:%02x:%02x) ?\n"
	    "        Tell %s (%02x:%02x:%02x:%02x:%02x:%02x)",
	    libnet_addr2name4(pkt->arp.dst.ip, LIBNET_DONT_RESOLVE),
	    pkt->arp.dst.eth[0] & 0xff, pkt->arp.dst.eth[1] & 0xff, pkt->arp.dst.eth[2] & 0xff,
	    pkt->arp.dst.eth[3] & 0xff, pkt->arp.dst.eth[4] & 0xff, pkt->arp.dst.eth[5] & 0xff,
	    libnet_addr2name4(pkt->arp.src.ip, LIBNET_DONT_RESOLVE),
	    pkt->arp.src.eth[0] & 0xff, pkt->arp.src.eth[1] & 0xff, pkt->arp.src.eth[2] & 0xff,
	    pkt->arp.src.eth[3] & 0xff, pkt->arp.src.eth[4] & 0xff, pkt->arp.src.eth[5] & 0xff);
    }

    return snprintf(str, sz,
	"For %s (%02x:%02x:%02x:%02x:%02x:%02x):\n"
	"        %s is at %02x:%02x:%02x:%02x:%02x:%02x",
	libnet_addr2name4(pkt->arp.dst.ip, LIBNET_DONT_RESOLVE),
	pkt->arp.dst.eth[0] & 0xff, pkt->arp.dst.eth[1] & 0xff, pkt->arp.dst.eth[2] & 0xff,
	pkt->arp.dst.eth[3] & 0xff, pkt->arp.dst.eth[4] & 0xff, pkt->arp.dst.eth[5] & 0xff,
        libnet_addr2name4(pkt->arp.src.ip, LIBNET_DONT_RESOLVE),
	pkt->arp.src.eth[0] & 0xff, pkt->arp.src.eth[1] & 0xff, pkt->arp.src.eth[2] & 0xff,
	pkt->arp.src.eth[3] & 0xff, pkt->arp.src.eth[4] & 0xff, pkt->arp.src.eth[5] & 0xff);
}

int
snprintf_eiarp_pkt(char *str, size_t sz, arpsk_arp_pkt_t *p)
{

    size_t count = 0;
    int res;

    if(!str || !p)
	return -1;

    res = snprintf_eth_in_eiarp_pkt(str, sz, p);
    if(res == -1 || sz < count+res)
	return -1;
    count+=res;

    res = snprintf(str + count, sz - count, "\n    ARP ");
    if(res == -1 || sz < count+res)
	return -1;
    count+=res;

    res = snprintf_arp_in_eiarp_pkt(str + count, sz - count, p);

    return (res == -1 || sz < count+res ? -1 : (int)(count+res));
}



int
set_eth_dst_in_eiarp_pkt(arpsk_arp_pkt_t * p, u_char * eth)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p || !eth)
	return 0;

    memcpy(pkt->eth.dst, eth, sizeof(pkt->eth.dst));

    return 1;
}

int
set_eth_src_in_eiarp_pkt(arpsk_arp_pkt_t * p, u_char * eth)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p || !eth)
	return 0;

    memcpy(pkt->eth.src, eth, sizeof(pkt->eth.src));

    return 1;
}

int
set_eth_in_eiarp_pkt(arpsk_arp_pkt_t * p, u_char * src, u_char * dst)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p || !src || !dst)
	return 0;

    memcpy(pkt->eth.src, src, sizeof(pkt->eth.src));
    memcpy(pkt->eth.dst, dst, sizeof(pkt->eth.dst));

    return 1;
}

int
set_arp_in_eiarp_pkt(arpsk_arp_pkt_t * p, u_char * src, u_char * dst,
    u_long s_ip, u_long d_ip)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p || !src || !dst)
	return 0;

    memcpy(pkt->arp.src.eth, src, sizeof(pkt->arp.src.eth));
    memcpy(pkt->arp.dst.eth, dst, sizeof(pkt->arp.dst.eth));
    pkt->arp.src.ip = s_ip;
    pkt->arp.dst.ip = d_ip;

    return 1;
}

int
set_arp_dst_in_eiarp_pkt(arpsk_arp_pkt_t * p, u_char * hwa, u_long ip)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p || !hwa)
	return 0;

    memcpy(pkt->arp.dst.eth, hwa, sizeof(pkt->arp.dst.eth));
    pkt->arp.dst.ip = ip;

    return 1;
}

int
set_arp_dst_eth_in_eiarp_pkt(arpsk_arp_pkt_t * p, u_char * hwa)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p || !hwa)
	return 0;

    memcpy(pkt->arp.dst.eth, hwa, sizeof(pkt->arp.dst.eth));

    return 1;
}

int
set_arp_dst_ip_in_eiarp_pkt(arpsk_arp_pkt_t * p, u_long ip)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p)
	return 0;

    pkt->arp.dst.ip = ip;

    return 1;
}

int
set_arp_src_in_eiarp_pkt(arpsk_arp_pkt_t * p, u_char * hwa, u_long ip)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p || !hwa)
	return 0;

    memcpy(pkt->arp.src.eth, hwa, sizeof(pkt->arp.src.eth));
    pkt->arp.src.ip = ip;

    return 1;
}

int
set_arp_src_eth_in_eiarp_pkt(arpsk_arp_pkt_t * p, u_char * hwa)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p || !hwa)
	return 0;

    memcpy(pkt->arp.src.eth, hwa, sizeof(pkt->arp.src.eth));

    return 1;
}

int
set_arp_src_ip_in_eiarp_pkt(arpsk_arp_pkt_t * p, u_long ip)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p)
	return 0;

    pkt->arp.src.ip = ip;

    return 1;
}

u_long
get_arp_src_ip_in_eiarp_pkt(arpsk_arp_pkt_t * p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p)
	return -1;

    return pkt->arp.src.ip;
}

u_long
get_arp_dst_ip_in_eiarp_pkt(arpsk_arp_pkt_t * p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p)
	return -1;

    return pkt->arp.dst.ip;
}

void *
get_arp_src_in_eiarp_pkt(arpsk_arp_pkt_t * p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p)
	return NULL;

    return (void *)&pkt->arp.src;
}

void *
get_arp_dst_in_eiarp_pkt(arpsk_arp_pkt_t * p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p)
	return NULL;

    return (void *)&pkt->arp.dst;
}

u_char *
get_arp_src_eth_in_eiarp_pkt(arpsk_arp_pkt_t * p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p)
	return NULL;

    return pkt->arp.src.eth;
}

u_char *
get_arp_dst_eth_in_eiarp_pkt(arpsk_arp_pkt_t * p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p)
	return NULL;

    return pkt->arp.dst.eth;
}


u_char *
get_eth_src_in_eiarp_pkt(arpsk_arp_pkt_t * p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p)
	return NULL;

    return pkt->eth.src;
}

u_char *
get_eth_dst_in_eiarp_pkt(arpsk_arp_pkt_t * p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    if(!p)
	return NULL;

    return pkt->eth.dst;
}

char
set_code_in_eiarp_pkt(arpsk_arp_pkt_t * p, char code)
{

    arpsk_eiarp_pkt_t *pkt = p;

    return (pkt->arp.hdr.code = code);
}

char
get_code_in_eiarp_pkt(arpsk_arp_pkt_t * p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    return pkt->arp.hdr.code;
}

u_int
get_link_proto_in_eiarp_pkt(arpsk_arp_pkt_t * p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    return pkt->arp.hdr.link_proto;
}

u_int
get_log_proto_in_eiarp_pkt(arpsk_arp_pkt_t * p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    return pkt->arp.hdr.log_proto;
}

u_char
get_hlen_in_eiarp_pkt(arpsk_arp_pkt_t * p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    return pkt->arp.hdr.hlen;
}

u_char
get_llen_in_eiarp_pkt(arpsk_arp_pkt_t * p)
{

    arpsk_eiarp_pkt_t *pkt = p;

    return pkt->arp.hdr.llen;
}



int
str2ethip(char *ipmac, void *a, char c)
{

    char str[256], *ptr;
    arpsk_ethip_t *addr = (arpsk_ethip_t *) a;

    if(!str || !a)
	return -1;

    memset(addr, 0, sizeof(arpsk_ethip_t));

    memcpy(str, ipmac, sizeof(str));
    str[sizeof(str) - 1] = 0;

    /*
     * eth 
     */
    if((ptr = strchr(str, ':')))
    {
	*ptr = 0;
	parse_ethernet(++ptr, addr->eth);
    }
    else
	memset(addr->eth, c, sizeof(addr->eth));

    /*
     * IP or name 
     */
    if(*ipmac == ':')		/* no IP, just :MAC */
	addr->ip = -1;
    else if((addr->ip = libnet_name2addr4(sk_libnet_link,
		(char *) str, LIBNET_RESOLVE)) == (u_long)-1)
	fatal("** Error: %s\n", libnet_geterror(sk_libnet_link));

    return 1;
}
