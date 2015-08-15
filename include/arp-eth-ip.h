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


#ifndef _ARP_ETH_IP_H_
#define _ARP_ETH_IP_H_

#include <stdio.h>
#include <libnet.h>

#include "sk.h"


extern libnet_ptag_t tag_arp_request;
extern libnet_ptag_t tag_arp_reply;
extern libnet_ptag_t tag_arp;



typedef struct {
    u_char src[6];                    /* source MAC address */
    u_char dst[6];                    /* destination MAC address */
} arpsk_ethernet_t;


typedef struct {
    u_char eth[6];
    u_long ip;
} arpsk_ethip_t;

typedef struct {
    arpsk_arp_hdr_t hdr;
    arpsk_ethip_t src;
    arpsk_ethip_t dst;
} arpsk_eiarp_t;


typedef struct {
    arpsk_ethernet_t eth;
    arpsk_eiarp_t arp;
} arpsk_eiarp_pkt_t;



/**  void *p **/
/* Functions  with void* argument are public, i.e. they can be called from */
/* anywhere in the source files. */
int sk_init_eiarp_pkt(arpsk_arp_pkt_t *ptr);

int get_if_ip_addr(char *ifname, u_long *ip);

int snprintf_arp_dst_ip_in_eiarp_pkt(char *name, size_t sz, arpsk_arp_pkt_t *p, int resolve);
int snprintf_arp_dst_eth_in_eiarp_pkt(char *hwaddr, size_t sz, arpsk_arp_pkt_t *p);
int snprintf_eth_dst_in_eiarp_pkt(char *hwaddr, size_t sz, arpsk_arp_pkt_t *p);


int snprintf_arp_src_ip_in_eiarp_pkt(char *name, size_t sz, arpsk_arp_pkt_t *p, int resolve);
int snprintf_arp_src_eth_in_eiarp_pkt(char *hwaddr, size_t sz, arpsk_arp_pkt_t *p);
int snprintf_eth_src_in_eiarp_pkt(char *hwaddr, size_t sz, arpsk_arp_pkt_t *p);

int snprintf_eiarp_pkt(char *str, size_t sz, arpsk_arp_pkt_t *p);
int snprintf_arp_in_eiarp_pkt(char *str, size_t sz, arpsk_arp_pkt_t *p);
int snprintf_eth_in_eiarp_pkt(char *str, size_t sz, arpsk_arp_pkt_t *p);


/**  arpsk_arp_pkt_t *p **/
/* Functions  with arpsk_arp_pkt_t* argument are protected, i.e. they can be  */
/* called from anywhere in the sources files RELATED TO ARP. */
int set_arp_in_eiarp_pkt(arpsk_arp_pkt_t *p, u_char *src, u_char *dst, 
			 u_long s_ip, u_long d_ip);
int set_arp_dst_in_eiarp_pkt(arpsk_arp_pkt_t *p, u_char *pwa, u_long ip);
int set_arp_dst_eth_in_eiarp_pkt(arpsk_arp_pkt_t *p, u_char *pwa);
int set_arp_dst_ip_in_eiarp_pkt(arpsk_arp_pkt_t *p, u_long ip);
int set_arp_src_in_eiarp_pkt(arpsk_arp_pkt_t *p, u_char *pwa, u_long ip);
int set_arp_src_eth_in_eiarp_pkt(arpsk_arp_pkt_t *p, u_char *pwa);
int set_arp_src_ip_in_eiarp_pkt(arpsk_arp_pkt_t *p, u_long ip);


int set_eth_in_eiarp_pkt(arpsk_arp_pkt_t *p, u_char *src, u_char *dst);

int set_eth_src_in_eiarp_pkt(arpsk_arp_pkt_t *p, u_char *eth);
int set_eth_dst_in_eiarp_pkt(arpsk_arp_pkt_t *p, u_char *eth);

u_long get_arp_src_ip_in_eiarp_pkt(arpsk_arp_pkt_t *p);
u_long get_arp_dst_ip_in_eiarp_pkt(arpsk_arp_pkt_t *p);
u_char* get_arp_src_eth_in_eiarp_pkt(arpsk_arp_pkt_t *p);
u_char* get_arp_dst_eth_in_eiarp_pkt(arpsk_arp_pkt_t *p);
u_char* get_eth_src_in_eiarp_pkt(arpsk_arp_pkt_t *p);
u_char* get_eth_dst_in_eiarp_pkt(arpsk_arp_pkt_t *p);
void* get_arp_src_in_eiarp_pkt(arpsk_arp_pkt_t *p);
void* get_arp_dst_in_eiarp_pkt(arpsk_arp_pkt_t *p);


char set_code_in_eiarp_pkt(arpsk_arp_pkt_t *p, char code);

char   get_code_in_eiarp_pkt(arpsk_arp_pkt_t *p);
u_int  get_link_proto_in_eiarp_pkt(arpsk_arp_pkt_t *p);
u_int  get_log_proto_in_eiarp_pkt(arpsk_arp_pkt_t *p);
u_char get_hlen_in_eiarp_pkt(arpsk_arp_pkt_t *p);
u_char get_llen_in_eiarp_pkt(arpsk_arp_pkt_t *p);



int str2ethip(char *ipmac, void* addr, char c);


#endif /* _ARP_ETH_IP_H_ */
