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



libnet_ptag_t tag_arp_request = LIBNET_PTAG_INITIALIZER;
libnet_ptag_t tag_arp_reply = LIBNET_PTAG_INITIALIZER;
libnet_ptag_t tag_arp = LIBNET_PTAG_INITIALIZER;

/* Should we build the packet with randomness ? */
int sk_rand_pkt = 0;


libnet_ptag_t
build_arp(arpsk_arp_pkt_t *p, libnet_ptag_t tag)
{

    u_long src = arpsk_get_arp_src_log(p);
    u_long dst = arpsk_get_arp_dst_log(p);

    tag = libnet_build_arp(arpsk_get_link_proto(p),  /* hardware addr */
			   arpsk_get_log_proto(p),   /* protocol addr */
			   arpsk_get_hlen(p),	     /* hardware addr size */
			   arpsk_get_llen(p),	     /* protocol addr size */
			   arpsk_get_code(p),	     /* operation type */
			   arpsk_get_arp_src_hwa(p), 
			   (u_char *) & src, 
			   arpsk_get_arp_dst_hwa(p), 
			   (u_char *) & dst, 
			   NULL,	             /* payload */
			   0,			     /* payload size */
			   sk_libnet_link,	     /* libnet handle */
			   tag);		     /* libnet id */
    
    if(tag == -1)
    {
	fatal("** Error: can't build ARP (%d): %s\n",
	    arpsk_get_code(p), libnet_geterror(sk_libnet_link));
    }

    if(arpsk_get_code(p) == ARPOP_REQUEST)
    {
	tag_arp_request = tag;
    }
    else
    {
	tag_arp_reply = tag;
    }

    return tag;
}
