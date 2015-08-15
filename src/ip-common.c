/**
 *
 *     CUT AND PASTE FROM nmap-3.0
 *     All honors to Fyodor <fyodor@insecure.org>
 *
 * Returns 1 if this is a reserved IP address, where "reserved" means
 * either a private address, non-routable address, or even a non-reserved
 * but unassigned address which has an extremely high probability of being
 * black-holed.
 *
 * We try to optimize speed when ordering the tests. This optimization
 * assumes that all byte values are equally likely in the input.
 *
 * Warning: This function could easily become outdated if the IANA
 * starts to assign some more IPv4 ranges to RIPE, etc. as they have
 * started doing this year (2001), for example 80.0.0.0/4 used to be
 * completely unassigned until they gave 80.0.0.0/7 to RIPE in April
 * 2001 (www.junk.org is an example of a new address in this range).
 *
 * Check <http://www.iana.org/assignments/ipv4-address-space> for
 * the most recent assigments.
 */

#include "sk.h"


int
ip_is_reserved(struct in_addr *ip)
{

    char *ipc = (char *)&(ip->s_addr);
    unsigned char i1 = ipc[0], i2 = ipc[1], i3 = ipc[2], i4 = ipc[3];

    /*
     * 221-223/8 is IANA reserved 
     * 224-239/8 is all multicast stuff 
     * 240-255/8 is IANA reserved 
     */
    if(i1 >= 221)
	return 1;

    /*
     * 096-126/8 is IANA reserved 
     * 127/8 is reserved for loopback 
     */
    if(i1 >= 96 && i1 <= 127)
	return 1;

    /*
     * 069-079/8 is IANA reserved 
     */
    if(i1 >= 69 && i1 <= 79)
	return 1;

    /*
     * 082-095/8 is IANA reserved 
     */
    if(i1 >= 82 && i1 <= 95)
	return 1;

    /*
     * do all the /7's and /8's with a big switch statement, hopefully the
     * compiler will be able to optimize this a little better using a jump 
     * table or what have you
     */
    switch (i1)
    {
	case 0:		/* 000/8 is IANA reserved       */
	case 1:		/* 001/8 is IANA reserved       */
	case 2:		/* 002/8 is IANA reserved       */
	case 5:		/* 005/8 is IANA reserved       */
	case 6:		/* USA Army ISC                 */
	case 7:		/* used for BGP protocol        */
	case 10:		/* the infamous 10.0.0.0/8      */
	case 23:		/* 023/8 is IANA reserved       */
	case 27:		/* 027/8 is IANA reserved       */
	case 31:		/* 031/8 is IANA reserved       */
	case 36:		/* 036/8 is IANA reserved       */
	case 37:		/* 037/8 is IANA reserved       */
	case 39:		/* 039/8 is IANA reserved       */
	case 41:		/* 041/8 is IANA reserved       */
	case 42:		/* 042/8 is IANA reserved       */
	case 55:		/* misc. U.S.A. Armed forces    */
	case 58:		/* 058/8 is IANA reserved       */
	case 59:		/* 059/8 is IANA reserved       */
	case 60:		/* 060/8 is IANA reserved       */
	case 197:
	    return 1;
	default:
	    break;
    }

    /*
     * 172.16.0.0/12 is reserved for private nets by RFC1819 
     */
    if(i1 == 172 && i2 >= 16 && i2 <= 31)
	return 1;

    /*
     * 192.168.0.0/16 is reserved for private nets by RFC1819 
     * 192.0.2.0/24 is reserved for documentation and examples 
     */
    if(i1 == 192)
    {
	if(i2 == 168)
	    return 1;
	else if(i2 == 0 && i3 == 2)
	    return 1;
    }

    /*
     * reserved for DHCP clients seeking addresses, not routable outside LAN 
     */
    if(i1 == 169 && i2 == 254)
	return 1;

    /*
     * believe it or not, 204.152.64.0/23 is some bizarre Sun proprietary
     * clustering thing 
     */
    if(i1 == 204 && i2 == 152 && (i3 == 64 || i3 == 65))
	return 1;

    /*
     * 255.255.255.255, note we already tested for i1 in this range 
     */
    if(i2 == 255 && i3 == 255 && i4 == 255)
	return 1;

    return 0;

}

void
get_rand_ip(u_long * ip)
{

    struct in_addr _ip;

    do
    {
	_ip.s_addr = random();
    }
    while(ip_is_reserved(&_ip));

    *ip = _ip.s_addr;
}
