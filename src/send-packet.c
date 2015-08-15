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
#include <time.h>

/* globals */
char sk_ifname[MAXIFNAMELEN] = "";      /* Which interface to use */
libnet_t *sk_libnet_link = NULL;	/* interface 'descriptor' */
void *sk_pkt;			        /* pointer to the sk-structure */

int sk_opt_call_dns = LIBNET_DONT_RESOLVE;
int sk_opt_count = -1;		/* #packets to send (infinity) */
int sk_opt_beep = 0;		/* silent by default (aka quiet mode ;-) */
int sk_opt_delay = 5;		/* delay between 2 packets */
int sk_opt_udelay = 0;		/* delay is given in microseconds */
int sk_opt_rand_delay = 0;	/* variations on the delay(s) */
struct itimerval sk_opt_usec_delay;

static unsigned long sk_total_time = 0;






#define LINE_SIZE          1024	/* Max size of a line to display a packet */


void
print_stats()
{

    char str[LINE_SIZE];
    char name[LINE_SIZE];
    char hwaddr[LINE_SIZE];

    memset(name, 0, LINE_SIZE);
    if(sk_rand_pkt & (SK_RAND_ARP | SK_RAND_ARP_LOG_DST))
    {
	strlcpy(name, " --[ random ]-- ", sizeof(name));
    }
    else
    {
	arpsk_snprintf_arp_dst_log(name, LINE_SIZE, sk_pkt, sk_opt_call_dns);
    }

    memset(hwaddr, 0, LINE_SIZE);
    if(sk_rand_pkt & (SK_RAND_ARP | SK_RAND_ARP_HWA_DST))
    {
	strlcpy(hwaddr, " --[ random ]-- ", sizeof(hwaddr));
    }
    else
    {
	arpsk_snprintf_arp_dst_hwa(hwaddr, LINE_SIZE, sk_pkt);
    }

    printf("--- %s (%s) statistic ---\n", name, hwaddr);

    memset(str, 0, LINE_SIZE);
    if(sk_rand_pkt)
    {
	printf("Last \"random\" packet:\n");
    }

    arpsk_snprintf_pkt(str, LINE_SIZE, sk_pkt);
    printf("%s\n", str);

    /*
     * FIXME: get global stat ... even if arena was used 
     */
    /*
     * len = sk_packets_pool[i].len;
     * printf("%ld packets tramitted (each: %ld bytes - total: %ld bytes)\n",
     * sk_packets_pool[i].packets_sent, len, sk_packets_pool[i].bytes_written);
     */

    printf("Total time: %lu ", sk_total_time);
    if(sk_opt_udelay)
	printf("u");
    printf("sec\n");
}

void
cleanup(int signal_id)
{

#ifdef HAVE_SIGSEND
    sigset_t sset, osset;

    sigemptyset(&sset);
    sigaddset(&sset, SIGALRM);
    sigaddset(&sset, SIGHUP);
    sigaddset(&sset, SIGINT);
    sigaddset(&sset, SIGTERM);
    sigprocmask(SIG_BLOCK, &sset, &osset);
#endif
    print_stats();

    /*
     * free global memory 
     */
    libnet_destroy(sk_libnet_link);
    if(sk_pkt)
	free(sk_pkt);

    exit(EXIT_SUCCESS);

#ifdef HAVE_SIGSEND
    sigprocmask(SIG_SETMASK, &osset, NULL);
#endif
}

/* 
 * This function sends the "packet" that is currently pointed to by
 * sk_libnet_link
 */
void
send_packet(int signal_id)
{

    int c, delay, sec;
    int rand = 0;
    char str[LINE_SIZE];
    struct timeval time;
    struct tm *tm;

    c = libnet_write(sk_libnet_link);
    if(c == -1)
    {
#ifdef HAVE_SIGSEND
	sigset_t sset, osset;

	sigemptyset(&sset);
	sigaddset(&sset, SIGALRM);
	sigaddset(&sset, SIGHUP);
	sigaddset(&sset, SIGINT);
	sigaddset(&sset, SIGTERM);
	sigprocmask(SIG_BLOCK, &sset, &osset);
#endif
	fatal("** Error: can't write %s\n", libnet_geterror(sk_libnet_link));
    }

    /*
     * display pkt 
     */
    gettimeofday(&time, NULL);
    tm = localtime(&(time.tv_sec));
    sec = time.tv_sec % 86400;
    printf("TS: %02d:%02d:%02d.%06ld\n",
	tm->tm_hour, tm->tm_min, tm->tm_sec, time.tv_usec);

    memset(str, 0, LINE_SIZE);
    arpsk_snprintf_pkt(str, LINE_SIZE, sk_pkt);

    if(sk_opt_count != -1)
	printf("(%d) ", sk_opt_count);
    printf("%s\n\n", str);

    if(sk_opt_beep)
	fprintf(stdout, "\a");

    if(sk_opt_rand_delay)
	rand = random() % (2 * sk_opt_rand_delay);

    delay =
	(sk_opt_udelay ? sk_opt_usec_delay.it_interval.
	tv_usec : sk_opt_delay) - sk_opt_rand_delay + rand;

    if(delay <= 0)
	delay = 1;

    sk_total_time += delay;

#ifdef HAVE_SIGSEND
    if(sk_opt_count == -1 || --sk_opt_count)
    {
	Signal(SIGALRM, send_packet);

	if(!sk_opt_udelay)
	{
	    alarm(delay);
	}
	else
	{
	    sk_opt_usec_delay.it_value.tv_usec = delay;
	    setitimer(ITIMER_REAL, &sk_opt_usec_delay, NULL);
	}
    }
    else
    {
	Signal(SIGALRM, cleanup);
	alarm(1);
    }
#endif

#if !defined(HAVE_SIGSEND)
    if(sk_opt_count != -1)
	--sk_opt_count;

    if(!sk_opt_udelay)
	sleep(delay);
    else
	usleep(sk_opt_usec_delay.it_interval.tv_usec);


#endif

}
