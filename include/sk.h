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


#ifndef _SK_H_
#define _SK_H_

#ifdef HAVE_CONFIG_H
#include "../include/config.h"
#endif


#include <stdio.h>
#include <libnet.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <errno.h>

#include <compat.h>



#define MAXIFNAMELEN 16

extern char sk_ifname[MAXIFNAMELEN];

#define MAXHOSTNAMELEN 256

#define MAX_ETHER_ADDR  18   /* strlen(XX:XX:XX:XX:XX:XX) + 1 */
#define MAX_IP_ADDR     16   /* strlen(XXX.XXX.XXX.XXX) + 1   */



/* Compatibility ... but not tested */
#if __WIN32__
#define random rand
#endif



/**********************************************************************/
/*                             PROTO ARP                              */
/*                                                                    */
/* Here are defined the general structures/pointers that will allow   */
/* to manipulate ARP packets for all differents protocols it can      */
/* handle.                                                            */
/*                                                                    */
/* Right now, only IP over Ethernet is supported.                     */
/*                                                                    */
/**********************************************************************/

/* Indexes for the array of handlers */
#define ARP_ETH_IP         0


typedef struct {
    char code;                        /* code of ARP packets  */
    u_int link_proto;                 /* link layer protocol */
    u_int log_proto;                  /* level 3 proto (usually IP) */
    u_char hlen;                      /* hardware address length */
    u_char llen;                      /* logical address length */
} arpsk_arp_hdr_t;

typedef void arpsk_arp_pkt_t;

extern libnet_ptag_t (*arpsk_build_hwa)(arpsk_arp_pkt_t *, libnet_ptag_t);

extern void (*arpsk_parse_mac)(char *, u_char *);
extern int (*arpsk_str2hwlog)(char *, void*, char);

extern int (*arpsk_get_ifhwa)(char *, u_char *);
extern int (*arpsk_get_iflog)(char *, u_long *);

extern void (*arpsk_get_rand_hwa)(u_char *);
extern void (*arpsk_get_rand_log)(u_long *);

extern int (*arpsk_resolve_log_from_hwa)(u_long *, u_char *);
extern int (*arpsk_resolve_hwa_from_log)(u_char *, u_long);

extern int (*arpsk_set_hwa)(arpsk_arp_pkt_t *, u_char *, u_char *);
extern int (*arpsk_set_hwa_dst)(arpsk_arp_pkt_t *, u_char *);
extern int (*arpsk_set_hwa_src)(arpsk_arp_pkt_t *, u_char *);

extern int (*arpsk_set_arp_msg)(arpsk_arp_pkt_t *, u_char *, u_char *, u_long, u_long);
extern int (*arpsk_set_arp_dst)(arpsk_arp_pkt_t *, u_char *, u_long);
extern int (*arpsk_set_arp_dst_hwa)(arpsk_arp_pkt_t *, u_char *);
extern int (*arpsk_set_arp_dst_log) (arpsk_arp_pkt_t *, u_long);
extern int (*arpsk_set_arp_src)(arpsk_arp_pkt_t *, u_char *, u_long);
extern int (*arpsk_set_arp_src_hwa)(arpsk_arp_pkt_t *, u_char *);
extern int (*arpsk_set_arp_src_log) (arpsk_arp_pkt_t *, u_long);

extern char (*arpsk_set_code)(arpsk_arp_pkt_t *, char);

extern char   (*arpsk_get_code)(arpsk_arp_pkt_t *);
extern u_int  (*arpsk_get_link_proto)(arpsk_arp_pkt_t *);
extern u_int  (*arpsk_get_log_proto) (arpsk_arp_pkt_t *);
extern u_char (*arpsk_get_hlen)(arpsk_arp_pkt_t *);
extern u_char (*arpsk_get_llen)(arpsk_arp_pkt_t *);

extern u_char* (*arpsk_get_hwa_dst)(arpsk_arp_pkt_t *);
extern u_char* (*arpsk_get_hwa_src)(arpsk_arp_pkt_t *);

extern void*   (*arpsk_get_arp_dst)(arpsk_arp_pkt_t *);
extern u_char* (*arpsk_get_arp_dst_hwa)(arpsk_arp_pkt_t *);
extern u_long  (*arpsk_get_arp_dst_log)(arpsk_arp_pkt_t *);

extern void*   (*arpsk_get_arp_src)(arpsk_arp_pkt_t *);
extern u_char* (*arpsk_get_arp_src_hwa)(arpsk_arp_pkt_t *);
extern u_long  (*arpsk_get_arp_src_log)(arpsk_arp_pkt_t *);


/** writing in a string **/
extern int (*arpsk_snprintf_hwa_dst)(char*, size_t, arpsk_arp_pkt_t *);
extern int (*arpsk_snprintf_hwa_src)(char*, size_t, arpsk_arp_pkt_t *);

extern int (*arpsk_snprintf_arp_dst_hwa)(char*, size_t, arpsk_arp_pkt_t *);
extern int (*arpsk_snprintf_arp_dst_log)(char*, size_t, arpsk_arp_pkt_t *, int);
extern int (*arpsk_snprintf_arp_src_hwa)(char*, size_t, arpsk_arp_pkt_t *);
extern int (*arpsk_snprintf_arp_src_log)(char*, size_t, arpsk_arp_pkt_t *, int);

extern int (*arpsk_snprintf_pkt)(char*, size_t, arpsk_arp_pkt_t *);
extern int (*arpsk_snprintf_log_msg)(char*, size_t, arpsk_arp_pkt_t *);
extern int (*arpsk_snprintf_hwa_msg)(char*, size_t, arpsk_arp_pkt_t *);


/**********************************************************************/
/*                          eth-common.c                              */
/*                                                                    */
/* parse_ethernet(): converts the provided "XX:XX:XX:XX:XX:XX" to     */
/*                   the provided  u_char[6].                         */
/* get_if_eth_addr(): return the address of the interface             */
/* get_rand_eth(): intialize randomly the argument as an eth addr     */
/*                                                                    */
/**********************************************************************/

void parse_ethernet(char *eth_str, u_char *eth);
int  get_if_eth_addr(char *ifname, u_char *eth);
libnet_ptag_t build_eth(arpsk_arp_pkt_t *p, libnet_ptag_t tag);
void get_rand_eth(u_char *eth);

/**********************************************************************/
/*                          arp-common.c                              */
/*                                                                    */
/* build_arp(): build an arp message.                                 */
/*                                                                    */
/**********************************************************************/

/* Should we build the packet with randomness ? */
extern int sk_rand_pkt;


#define SK_RAND_HWA          1
#define SK_RAND_HWA_DST      2
#define SK_RAND_HWA_SRC      4

#define SK_RAND_ARP          8 
#define SK_RAND_ARP_DST      16
#define SK_RAND_ARP_SRC      32
#define SK_RAND_ARP_HWA_DST  64
#define SK_RAND_ARP_LOG_DST  128
#define SK_RAND_ARP_HWA_SRC  256
#define SK_RAND_ARP_LOG_SRC  512


libnet_ptag_t build_arp(arpsk_arp_pkt_t *p, libnet_ptag_t tag);

/**********************************************************************/
/*                           ip-common.c                              */
/*                                                                    */
/* ip_is_reserved(): copied from nmap.                                */
/* get_rand_ip(): randomly generates a valid ip.                      */
/*                                                                    */
/**********************************************************************/

int ip_is_reserved(struct in_addr *ip);
void get_rand_ip(u_long *ip) ;



/**********************************************************************/
/*                               sk.c                                 */
/*                                                                    */
/* fatal(): quit properly by writing an error, closing, and leaving   */
/* warning(): display a warning ;-)                                   */
/* sk_init(): set some globals and structure according to the         */
/*            requested protocol.                                     */
/* sk_malloc(): (expected) safe memory allocator.                     */
/* show_version(): no comment ;-)                                     */
/*                                                                    */
/**********************************************************************/

void fatal(const char *format, ...);
void warning(const char *format, ...);
arpsk_arp_pkt_t* sk_init(int proto);
void *sk_malloc(int size);
void show_version();

/**********************************************************************/
/*                        lookup-eth-ip.c                             */
/*                                                                    */
/* lookup_in_arp_cache(): look in /proc/net/arp ...                   */
/*   Assumptions :                                                    */
/*     sizeof(etheraddr) = 18 (MAX_ETHER_ADDR)                        */
/*     sizeof(ipaddr)    = 16 (MAX_IP_ADDR)                           */
/*                                                                    */
/*  resolve_ip_from_eth(): retrieve the IP from the MAC address       */
/*  resolve_eth_from_ip(): retrieve the MAC address from the IP       */
/*                                                                    */
/**********************************************************************/

#define LOOKUP_ETHER 0
#define LOOKUP_IP 1

/* Delay (in seconds) to sleep while waiting for the answers to a broadcast 
   icmp message before */
#define ARP_RESOLVE_DELAY 5 


/*
  extern libnet_ptag_t tag_icmp;
  extern libnet_ptag_t tag_ipv4;
*/
extern u_long sk_bcast;

int lookup_in_arp_cache(char *etheraddr, char *ipaddr, char resolve);
int resolve_ip_from_eth(u_long *ip, u_char *eth);
int resolve_eth_from_ip(u_char *eth, u_long ip);

/**********************************************************************/
/*                           signal.c                                 */
/*                                                                    */
/* Signal(): special portable signal handler                          */
/*                                                                    */
/**********************************************************************/

void (*Signal(int signo, void (*func)(int)))(int);

/**********************************************************************/
/*                         sendpacket.c                               */
/*                                                                    */
/* send_packet(): send a packet described by both sk_libnet_link and  */
/*                sk_pkt.                                             */
/*                These 2 globals must be set in the different hooks  */
/*                used to send packets since it is the packet it      */
/*                points to that is going on the wire.                */
/*                                                                    */
/**********************************************************************/

extern libnet_t *sk_libnet_link;   /* interface 'descriptor' */
extern void *sk_pkt;               /* pointer to the sk-structure */
                                   /* describing the pkt */

extern int sk_opt_call_dns;        /* do name resolution */
extern int sk_opt_count;           /* #packets to send (infinity) */
extern int sk_opt_beep;            /* silent by default (aka quiet mode ;-) */
extern int sk_opt_delay;           /* delay between 2 packets */
extern int sk_opt_udelay;          /* delay is given in microseconds */
extern int sk_opt_rand_delay;      /* variations on the delay(s) */
extern struct itimerval sk_opt_usec_delay;


void cleanup(int signal_id);
void send_packet(int signal_id);




#endif /* _SK_H_ */


