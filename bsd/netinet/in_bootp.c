/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 *  Copyright (c) 1988-1999 Apple Computer, Inc. All Rights Reserved 
 */

/*
 * bootp.c
 * - be a BOOTP client over a particular interface to retrieve
 *   the IP address, netmask, and router
 */

/* 
 * Modification History
 *
 * February 19, 1999	Dieter Siegmund	(dieter@apple.com)
 * - completely rewritten
 */

#include <sys/param.h>
#include <sys/types.h>
#include <mach/boolean.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/mbuf.h>
#include <sys/vnode.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/bootp.h>
#include <sys/systm.h>
#include <sys/malloc.h>


#ifdef	BOOTP_DEBUG
#define	dprintf(x) printf x;
#else	BOOTP_DEBUG
#define	dprintf(x)
#endif	BOOTP_DEBUG

/* ip address formatting macros */
#define IP_FORMAT	"%d.%d.%d.%d"
#define IP_CH(ip)	((u_char *)ip)
#define IP_LIST(ip)	IP_CH(ip)[0],IP_CH(ip)[1],IP_CH(ip)[2],IP_CH(ip)[3]

/* tag values (from RFC 2132) */
#define TAG_PAD			0
#define TAG_END			255
#define TAG_SUBNET_MASK		1
#define TAG_ROUTER		3
#define RFC_OPTIONS_MAGIC	{ 99, 130, 83, 99 }
static unsigned char		rfc_magic[4] = RFC_OPTIONS_MAGIC;


static struct sockaddr_in	blank_sin = { sizeof(struct sockaddr_in),
					      AF_INET };

static __inline__ void
print_reply(struct bootp *bp, int bp_len)
{
	int i, j, len;

	printf("bp_op = ");
	if (bp->bp_op == BOOTREQUEST) printf("BOOTREQUEST\n");
	else if (bp->bp_op == BOOTREPLY) printf("BOOTREPLY\n");
	else
	{
		i = bp->bp_op;
		printf("%d\n", i);
	}

	i = bp->bp_htype;
	printf("bp_htype = %d\n", i);

	len = bp->bp_hlen;
	printf("bp_hlen = %d\n", len);

	i = bp->bp_hops;
	printf("bp_hops = %d\n", i);

	printf("bp_xid = %lu\n", bp->bp_xid);

	printf("bp_secs = %u\n", bp->bp_secs);

	printf("bp_ciaddr = " IP_FORMAT "\n", IP_LIST(&bp->bp_ciaddr));
	printf("bp_yiaddr = " IP_FORMAT "\n", IP_LIST(&bp->bp_yiaddr));
	printf("bp_siaddr = " IP_FORMAT "\n", IP_LIST(&bp->bp_siaddr));
	printf("bp_giaddr = " IP_FORMAT "\n", IP_LIST(&bp->bp_giaddr));

	printf("bp_chaddr = ");
	for (j = 0; j < len; j++)
	{
		i = bp->bp_chaddr[j];
		printf("%0x", i);
		if (j < (len - 1)) printf(":");
	}
	printf("\n");

	printf("bp_sname = %s\n", bp->bp_sname);
	printf("bp_file = %s\n", bp->bp_file);
}

static __inline__ void
print_reply_short(struct bootp *bp, int bp_len)
{
	printf("bp_yiaddr = " IP_FORMAT "\n", IP_LIST(&bp->bp_yiaddr));
	printf("bp_sname = %s\n", bp->bp_sname);
}


static __inline__ long
random_range(long bottom, long top)
{
    long number = top - bottom + 1;
    long range_size = LONG_MAX / number;
    return (((long)random()) / range_size + bottom);
}

/*
 * Function: make_bootp_request
 * Purpose:
 *   Create a "blank" bootp packet.
 */
static void
make_bootp_request(struct bootp_packet * pkt, 
		   u_char * hwaddr, u_char hwtype, u_char hwlen)
{
    bzero(pkt, sizeof (*pkt));
    pkt->bp_ip.ip_v = IPVERSION;
    pkt->bp_ip.ip_hl = sizeof (struct ip) >> 2;
    pkt->bp_ip.ip_id = htons(ip_id++);
    pkt->bp_ip.ip_ttl = MAXTTL;
    pkt->bp_ip.ip_p = IPPROTO_UDP;
    pkt->bp_ip.ip_src.s_addr = 0;
    pkt->bp_ip.ip_dst.s_addr = htonl(INADDR_BROADCAST);
    pkt->bp_udp.uh_sport = htons(IPPORT_BOOTPC);
    pkt->bp_udp.uh_dport = htons(IPPORT_BOOTPS);
    pkt->bp_udp.uh_sum = 0;
    pkt->bp_bootp.bp_op = BOOTREQUEST;
    pkt->bp_bootp.bp_htype = hwtype;
    pkt->bp_bootp.bp_hlen = hwlen;
    pkt->bp_bootp.bp_ciaddr.s_addr = 0;
    bcopy(hwaddr, pkt->bp_bootp.bp_chaddr, hwlen);
    bcopy(rfc_magic, pkt->bp_bootp.bp_vend, sizeof(rfc_magic));
    pkt->bp_bootp.bp_vend[4] = TAG_END;
    pkt->bp_udp.uh_ulen = htons(sizeof(pkt->bp_udp) + sizeof(pkt->bp_bootp));
    pkt->bp_ip.ip_len = htons(sizeof(struct ip) + ntohs(pkt->bp_udp.uh_ulen));
    pkt->bp_ip.ip_sum = 0;
    return;
}

/*
 * Function: ip_pkt_to_mbuf
 * Purpose:
 *   Put the given IP packet into an mbuf, calculate the
 *   IP checksum.
 */
struct mbuf *
ip_pkt_to_mbuf(caddr_t pkt, int pktsize)
{
    struct ip *		ip;
    struct mbuf	*	m;
    
    m = (struct mbuf *)m_devget(pkt, pktsize, 0, 0, 0);
    if (m == 0) {
	printf("bootp: ip_pkt_to_mbuf: m_devget failed\n");
	return 0;
    }
    m->m_flags |= M_BCAST;
    /* Compute the checksum */
    ip = mtod(m, struct ip *);
    ip->ip_sum = 0;
    ip->ip_sum = in_cksum(m, sizeof (struct ip));
    return (m);
}

static __inline__ u_char *
link_address(struct sockaddr_dl * dl_p)
{
    return (dl_p->sdl_data + dl_p->sdl_nlen);
}

static __inline__ void
link_print(struct sockaddr_dl * dl_p)
{
    int i;

#if 0
    printf("len %d index %d family %d type 0x%x nlen %d alen %d"
	   " slen %d addr ", dl_p->sdl_len, 
	   dl_p->sdl_index,  dl_p->sdl_family, dl_p->sdl_type,
	   dl_p->sdl_nlen, dl_p->sdl_alen, dl_p->sdl_slen);
#endif 0
    for (i = 0; i < dl_p->sdl_alen; i++) 
	printf("%s%x", i ? ":" : "", 
	       (link_address(dl_p))[i]);
    printf("\n");
    return;
}

static struct sockaddr_dl *
link_from_ifnet(struct ifnet * ifp)
{
    struct ifaddr * addr;

/*    for (addr = ifp->if_addrlist; addr; addr = addr->ifa_next) */

    TAILQ_FOREACH(addr, &ifp->if_addrhead, ifa_link) {
	if (addr->ifa_addr->sa_family == AF_LINK) {
	    struct sockaddr_dl * dl_p = (struct sockaddr_dl *)(addr->ifa_addr);
	    
	    return (dl_p);
	}
    }
    return (NULL);
}

/*
 * Function: send_bootp_request
 * Purpose:
 *     Send the request by calling the interface's output routine
 *     bypassing routing code.
 */
static int
send_bootp_request(struct ifnet * ifp, struct socket * so,
		   struct bootp_packet * pkt)
{
    struct mbuf	*	m;
    struct sockaddr_in	sin;
    
    /* Address to send to */
    sin = blank_sin;
    sin.sin_port = htons(IPPORT_BOOTPS);
    sin.sin_addr.s_addr = INADDR_BROADCAST;
    
    m = ip_pkt_to_mbuf((caddr_t)pkt, sizeof(*pkt));
    return (dlil_output((u_long) ifp, m, 0, (struct sockaddr *)&sin, 0));
}

/*
 * Function: receive_packet
 * Purpose:
 *   Return a received packet or an error if none available.
 */
int
receive_packet(struct socket * so, caddr_t pp, int psize)
{
    struct iovec	aiov;
    struct uio		auio;
    int			rcvflg;
    int			error;

    aiov.iov_base = pp;
    aiov.iov_len = psize;
    auio.uio_iov = &aiov;
    auio.uio_iovcnt = 1;
    auio.uio_segflg = UIO_SYSSPACE;
    auio.uio_offset = 0;
    auio.uio_resid = psize;
    auio.uio_rw = UIO_READ;
    rcvflg = MSG_WAITALL;
    
    error = soreceive(so, (struct sockaddr **) 0, &auio, 0, 0, &rcvflg);
    return (error);
}

/*
 * Function: bootp_timeout
 * Purpose:
 *   Wakeup the process waiting for something on a socket.
 */
static void
bootp_timeout(struct socket * * socketflag)
{
    struct socket * so = *socketflag;
    boolean_t 	funnel_state;
    
    dprintf(("bootp: timeout\n"));

    funnel_state = thread_funnel_set(network_flock,TRUE);
    *socketflag = NULL;
    sowakeup(so, &so->so_rcv);
    (void) thread_funnel_set(network_flock, FALSE);
    return;
}

#define TAG_OFFSET	0
#define LEN_OFFSET	1
#define OPTION_OFFSET	2

void *
packet_option(struct bootp * pkt, u_char t) 
{
    void *		buffer = pkt->bp_vend + sizeof(rfc_magic);
    int			len;
    unsigned char	option_len;
    void *		ret = NULL;
    unsigned char *	scan;
    unsigned char	tag = TAG_PAD;

    len = sizeof(pkt->bp_vend) - sizeof(rfc_magic);
    for (scan = buffer; len > 0; ) {
	tag = scan[TAG_OFFSET];
	if (tag == TAG_END) /* we hit the end of the options */
	    break;
	if (tag == TAG_PAD) { /* discard pad characters */
	    scan++;
	    len--;
	}
	else {
	    if (t == tag && ret == NULL)
		ret = scan + OPTION_OFFSET;
	    option_len = scan[LEN_OFFSET];
	    len -= (option_len + 2);
	    scan += (option_len + 2);
	}
    }
    if (len < 0 || tag != TAG_END) { /* we ran off the end */
	if (len < 0) {
	    dprintf(("bootp: error parsing options\n"));
	}
	else {
	    dprintf(("bootp: end tag missing\n"));
	}
	ret = NULL;
    }
    return (ret);
}

/*
 * Function: rate_packet
 * Purpose:
 *   Return an integer point rating value for the given bootp packet.
 *   If yiaddr non-zero, the packet gets a rating of 1.
 *   Another point is given if the packet contains the subnet mask,
 *   and another if the router is present.
 */
#define GOOD_RATING	3
static __inline__ int 
rate_packet(struct bootp * pkt)
{
    int rating = 0;

    if (pkt->bp_yiaddr.s_addr) {
	struct in_addr * ip;

	rating++;
	ip = (struct in_addr *)packet_option(pkt, TAG_SUBNET_MASK);
	if (ip)
	    rating++;
	ip = (struct in_addr *)packet_option(pkt, TAG_ROUTER);
	if (ip)
	    rating++;
    }
    return (rating);
}

#define INITIAL_WAIT_SECS		4
#define MAX_WAIT_SECS			64
#define GATHER_TIME_SECS		2
#define RAND_TICKS			(hz)	/* one second */

/*
 * Function: bootp_loop
 * Purpose:
 *   Do the actual BOOTP protocol.
 *   The algorithm sends out a packet, waits for a response.
 *   We try max_try times, waiting in an exponentially increasing
 *   amount of time.  Once we receive a good response, we start
 *   a new time period called the "gather time", during which we
 *   either find the perfect packet (one that has ip, mask and router)
 *   or we continue to gather responses.  At the end of the gather period,
 *   we use the best response gathered.
 */
static int
bootp_loop(struct socket * so, struct ifnet * ifp, int max_try,
	   struct in_addr * iaddr_p, struct in_addr * netmask_p,
	   struct in_addr * router_p)
{
    struct timeval		current_time;
    struct sockaddr_dl *	dl_p;
    int				error = 0;
    char *			hwaddr;
    int				hwlen;
    char			hwtype = 0;
    struct bootp_packet * 	request = NULL;
    struct bootp *		reply = NULL;
    struct bootp *		saved_reply = NULL;
    struct timeval		start_time;
    u_long			xid;
    int				retry;
    struct socket *		timeflag;
    int				wait_ticks = INITIAL_WAIT_SECS * hz;

    /* get the hardware address from the interface */
    dl_p = link_from_ifnet(ifp);
    if (dl_p == NULL) {
	printf("bootp: can't get link address\n");
	return (ENXIO);
    }

    printf("bootp: h/w addr ");
    link_print(dl_p);

    hwaddr = link_address(dl_p);
    hwlen = dl_p->sdl_alen;
    switch (dl_p->sdl_type) {
        case IFT_ETHER:
	    hwtype = ARPHRD_ETHER;
	    break;
        default:
	    printf("bootp: hardware type %d not supported\n",
		   dl_p->sdl_type);
	    panic("bootp: hardware type not supported");
	    break;
    }

    /* set transaction id and remember the start time */
    microtime(&start_time);
    current_time = start_time;
    xid = random();
    
    /* make a request/reply packet */
    request = (struct bootp_packet *)kalloc(sizeof(*request));
    make_bootp_request(request, hwaddr, hwtype, hwlen);
    reply = (struct bootp *)kalloc(sizeof(*reply));
    saved_reply = (struct bootp *)kalloc(sizeof(*saved_reply));
    iaddr_p->s_addr = 0;
    printf("bootp: sending request");
    for (retry = 0; retry < max_try; retry++) {
	int	 	gather_count = 0;
	int		last_rating = 0;

	/* Send the request */
	printf(".");
	request->bp_bootp.bp_secs = htons((u_short)(current_time.tv_sec 
						    - start_time.tv_sec));
	request->bp_bootp.bp_xid = htonl(xid);
	error = send_bootp_request(ifp, so, request);
	if (error)
	    goto cleanup;

	timeflag = so;
	wait_ticks += random_range(-RAND_TICKS, RAND_TICKS);
	dprintf(("bootp: waiting %d ticks\n", wait_ticks));
	timeout(bootp_timeout, &timeflag, wait_ticks);

	while (TRUE) {
	    error = receive_packet(so, (caddr_t)reply, sizeof(*reply));
	    if (error == 0) {
		dprintf(("\nbootp: received packet\n"));
		if (ntohl(reply->bp_xid) == xid
		    && reply->bp_yiaddr.s_addr
		    && bcmp(reply->bp_chaddr, hwaddr, hwlen) == 0) {
		    int rating;
#ifdef	BOOTP_DEBUG
		    print_reply_short(reply, sizeof(*reply));
#endif BOOTP_DEBUG
		    rating = rate_packet(reply);
		    if (rating > last_rating)
			*saved_reply = *reply;
		    if (rating >= GOOD_RATING) {
			untimeout(bootp_timeout, &timeflag);
			goto save_values;
		    }
		    if (gather_count == 0) {
			untimeout(bootp_timeout, &timeflag);
			timeflag = so;
			timeout(bootp_timeout, &timeflag, 
				hz * GATHER_TIME_SECS);
		    }
		    gather_count++;
		}
		else {
		    dprintf(("bootp: packet ignored\n"));
		}
	    }
	    else if ((error != EWOULDBLOCK)) {
		break;
	    }
	    else if (timeflag == NULL) { /* timed out */
		if (gather_count) {
		    dprintf(("bootp: gathering time has expired"));
		    goto save_values; /* we have a packet */
		}
		break; /* retry */
	    }
	    else
		sbwait(&so->so_rcv);
	}
	if (error && (error != EWOULDBLOCK)) {
	    dprintf(("bootp: failed to receive packets: %d\n", error));
	    untimeout(bootp_timeout, &timeflag);
	    goto cleanup;
	}
	wait_ticks *= 2;
	if (wait_ticks > (MAX_WAIT_SECS * hz))
	    wait_ticks = MAX_WAIT_SECS * hz;
	xid++;
	microtime(&current_time);
    }
    error = ETIMEDOUT;
    goto cleanup;

 save_values:
    error = 0;
    printf("\nbootp: got response from %s (" IP_FORMAT ")\n", 
	   saved_reply->bp_sname, IP_LIST(&saved_reply->bp_siaddr));
    /* return the ip address */
    *iaddr_p = saved_reply->bp_yiaddr;
    {
	struct in_addr * ip;
	ip = (struct in_addr *)packet_option(saved_reply, TAG_SUBNET_MASK);
	if (ip)
	    *netmask_p = *ip;
	ip = (struct in_addr *)packet_option(saved_reply, TAG_ROUTER);
	if (ip)
	    *router_p = *ip;
    }

 cleanup:
    if (request)
	kfree((caddr_t)request, sizeof (*request));
    if (reply)
	kfree((caddr_t)reply, sizeof(*reply));
    if (saved_reply)
	kfree((caddr_t)saved_reply, sizeof(*saved_reply));
    return (error);
}

/*
 * Routine: bootp
 * Function:
 *	Use the BOOTP protocol to resolve what our IP address should be
 *	on a particular interface.
 */
int bootp(struct ifnet * ifp, struct in_addr * iaddr_p, int max_try,
	  struct in_addr * netmask_p, struct in_addr * router_p,
	  struct proc * procp)
{
    boolean_t			addr_set = FALSE;
    struct ifreq 		ifr;
    int				error;
    struct socket *		so = NULL;

    /* get a socket */
    error = socreate(AF_INET, &so, SOCK_DGRAM, 0);
    if (error) {
	dprintf(("bootp: socreate failed %d\n", error));
	return (error);
    }

    /* assign the all-zeroes address */
    bzero(&ifr, sizeof(ifr));
    sprintf(ifr.ifr_name, "%s%d", ifp->if_name, ifp->if_unit);
    *((struct sockaddr_in *)&ifr.ifr_addr) = blank_sin;
    error = ifioctl(so, SIOCSIFADDR, (caddr_t)&ifr, procp);
    if (error) {
	dprintf(("bootp: SIOCSIFADDR all-zeroes IP failed: %d\n",
		 error));
	goto cleanup;
    }
    dprintf(("bootp: all-zeroes IP address assigned\n"));
    addr_set = TRUE;
    
    { /* bind the socket */
	struct sockaddr_in * sin;

	sin = _MALLOC(sizeof(struct sockaddr_in), M_IFADDR, M_WAIT);
	if (sin == NULL) {
	  	error = ENOMEM;
		goto cleanup;
	}
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_port = htons(IPPORT_BOOTPC);
	sin->sin_addr.s_addr = INADDR_ANY;
	error = sobind(so, (struct sockaddr *) sin);

	FREE(sin, M_IFADDR);
	if (error) {
	    dprintf(("bootp: sobind failed, %d\n", error));
	    goto cleanup;
	}
	so->so_state |= SS_NBIO;
    }
    /* do the protocol */
    error = bootp_loop(so, ifp, max_try, iaddr_p, netmask_p, router_p);
    
 cleanup:
    if (so) {
	if (addr_set) {
	    (void) ifioctl(so, SIOCDIFADDR, (caddr_t) &ifr, procp);
	}
	soclose(so);
    }
    return (error);
}

