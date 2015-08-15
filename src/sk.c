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
#include "version.h"
#include <stdarg.h>

/*
 * Let's define all the pointer on function that are needed
 */
libnet_ptag_t (*arpsk_build_hwa)(arpsk_arp_pkt_t *, libnet_ptag_t);

void (*arpsk_parse_mac)(char *, u_char *);
int (*arpsk_str2hwlog)(char *, void*, char);

int (*arpsk_get_ifhwa)(char *, u_char *);
int (*arpsk_get_iflog)(char *, u_long *);

void (*arpsk_get_rand_hwa)(u_char *);
void (*arpsk_get_rand_log)(u_long *);

int (*arpsk_resolve_log_from_hwa)(u_long *, u_char *);
int (*arpsk_resolve_hwa_from_log)(u_char *, u_long);

int (*arpsk_set_hwa)(arpsk_arp_pkt_t *, u_char *, u_char *);
int (*arpsk_set_hwa_dst)(arpsk_arp_pkt_t *, u_char *);
int (*arpsk_set_hwa_src)(arpsk_arp_pkt_t *, u_char *);

int (*arpsk_set_arp_msg)(arpsk_arp_pkt_t *, u_char *, u_char *, u_long, u_long);
int (*arpsk_set_arp_dst)(arpsk_arp_pkt_t *, u_char *, u_long);
int (*arpsk_set_arp_dst_hwa)(arpsk_arp_pkt_t *, u_char *);
int (*arpsk_set_arp_dst_log) (arpsk_arp_pkt_t *, u_long);
int (*arpsk_set_arp_src)(arpsk_arp_pkt_t *, u_char *, u_long);
int (*arpsk_set_arp_src_hwa)(arpsk_arp_pkt_t *, u_char *);
int (*arpsk_set_arp_src_log) (arpsk_arp_pkt_t *, u_long);

char (*arpsk_set_code)(arpsk_arp_pkt_t *, char);

char   (*arpsk_get_code)(arpsk_arp_pkt_t *);
u_int  (*arpsk_get_link_proto)(arpsk_arp_pkt_t *);
u_int  (*arpsk_get_log_proto) (arpsk_arp_pkt_t *);
u_char (*arpsk_get_hlen)(arpsk_arp_pkt_t *);
u_char (*arpsk_get_llen)(arpsk_arp_pkt_t *);

u_char* (*arpsk_get_hwa_dst)(arpsk_arp_pkt_t *);
u_char* (*arpsk_get_hwa_src)(arpsk_arp_pkt_t *);

void*   (*arpsk_get_arp_dst)(arpsk_arp_pkt_t *);
u_char* (*arpsk_get_arp_dst_hwa)(arpsk_arp_pkt_t *);
u_long  (*arpsk_get_arp_dst_log)(arpsk_arp_pkt_t *);

void*   (*arpsk_get_arp_src)(arpsk_arp_pkt_t *);
u_char* (*arpsk_get_arp_src_hwa)(arpsk_arp_pkt_t *);
u_long  (*arpsk_get_arp_src_log)(arpsk_arp_pkt_t *);


/** writing in a string **/
int (*arpsk_snprintf_hwa_dst)(char*, size_t, arpsk_arp_pkt_t *);
int (*arpsk_snprintf_hwa_src)(char*, size_t, arpsk_arp_pkt_t *);

int (*arpsk_snprintf_arp_dst_hwa)(char*, size_t, arpsk_arp_pkt_t *);
int (*arpsk_snprintf_arp_dst_log)(char*, size_t, arpsk_arp_pkt_t *, int);
int (*arpsk_snprintf_arp_src_hwa)(char*, size_t, arpsk_arp_pkt_t *);
int (*arpsk_snprintf_arp_src_log)(char*, size_t, arpsk_arp_pkt_t *, int);

int (*arpsk_snprintf_pkt)(char*, size_t, arpsk_arp_pkt_t *);
int (*arpsk_snprintf_log_msg)(char*, size_t, arpsk_arp_pkt_t *);
int (*arpsk_snprintf_hwa_msg)(char*, size_t, arpsk_arp_pkt_t *);




/* failure notice and exit */
void
fatal(const char *format, ...)
{

    va_list ap;

    va_start(ap, format);

    if(format)
	vfprintf(stderr, format, ap);

    va_end(ap);

    fflush(stderr);

    if(sk_libnet_link)
	libnet_destroy(sk_libnet_link);
    if(sk_pkt)
	free(sk_pkt);

    exit(EXIT_FAILURE);
}

void
warning(const char *format, ...)
{

    va_list ap;

    va_start(ap, format);

    if(format)
	vfprintf(stderr, format, ap);

    va_end(ap);
    fflush(stderr);
}

arpsk_arp_pkt_t *
sk_init(int proto)
{

    arpsk_arp_pkt_t *pkt = NULL;

#if !(__WIN32__)
    struct timeval seed;
#endif

#if __WIN32__
    srand(0);
#else
    if(gettimeofday(&seed, NULL) == -1)
	fatal("** Error: cannot gettimeofday.\n");

    srandom((unsigned)((seed.tv_sec ^ seed.tv_usec) ^ getpid()));
#endif

    switch (proto)
    {
	case ARP_ETH_IP:
	    pkt = sk_malloc(sizeof(arpsk_eiarp_pkt_t));
	    sk_init_eiarp_pkt(pkt);
	    return pkt;

	default:
	    fprintf(stderr, "** Error: proto not yet supported.\n");
	    exit(EXIT_FAILURE);
    }
}

void *
sk_malloc(int size)
{

    void *mymem;

    if(size <= 0)
    {
	fatal("** Error: trying to malloc <= 0 amount of memory (%d) !!!\n",
	    size);
    }

    mymem = malloc(size);

    if(!mymem)
    {
	fatal("** Error: malloc failed, %s\n", strerror(errno));
    }

    return mymem;
}

void
show_version()
{

    printf("%s version %s (%s)\n", PACKAGE, ARPSK_VERSION, ARPSK_DATE);
    printf("Author: %s\n", ARPSK_AUTHOR);
}
