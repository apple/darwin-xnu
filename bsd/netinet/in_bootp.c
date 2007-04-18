/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
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
#include <sys/uio_internal.h>
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
#include <netinet/dhcp_options.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>

#ifdef	BOOTP_DEBUG
#define	dprintf(x) printf x;
#else	/* !BOOTP_DEBUG */
#define	dprintf(x)
#endif	/* BOOTP_DEBUG */

int bootp(struct ifnet * ifp, struct in_addr * iaddr_p, int max_try,
	  struct in_addr * netmask_p, struct in_addr * router_p,
	  struct proc * procp);
struct mbuf * ip_pkt_to_mbuf(caddr_t pkt, int pktsize);
int receive_packet(struct socket * so, caddr_t pp, int psize, int * actual_size);


/* ip address formatting macros */
#define IP_FORMAT	"%d.%d.%d.%d"
#define IP_CH(ip)	((u_char *)ip)
#define IP_LIST(ip)	IP_CH(ip)[0],IP_CH(ip)[1],IP_CH(ip)[2],IP_CH(ip)[3]

static __inline__ struct sockaddr_in
blank_sin()
{
    struct sockaddr_in	blank = { sizeof(struct sockaddr_in), AF_INET };
    return (blank);
}

static __inline__ void
print_reply(struct bootp *bp, __unused int bp_len)
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
print_reply_short(struct bootp *bp, __unused int bp_len)
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
    char		rfc_magic[4] = RFC_OPTIONS_MAGIC;

    bzero(pkt, sizeof (*pkt));
    pkt->bp_ip.ip_v = IPVERSION;
    pkt->bp_ip.ip_hl = sizeof (struct ip) >> 2;
#ifdef RANDOM_IP_ID
    pkt->bp_ip.ip_id = ip_randomid();
#else
    pkt->bp_ip.ip_id = htons(ip_id++);
#endif
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
    pkt->bp_bootp.bp_vend[4] = dhcptag_end_e;
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
#endif
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

	ifnet_lock_shared(ifp);
    TAILQ_FOREACH(addr, &ifp->if_addrhead, ifa_link) {
	if (addr->ifa_addr->sa_family == AF_LINK) {
	    struct sockaddr_dl * dl_p = (struct sockaddr_dl *)(addr->ifa_addr);
	    
	    ifnet_lock_done(ifp);
	    return (dl_p);
	}
    }
    ifnet_lock_done(ifp);
    return (NULL);
}

/*
 * Function: send_bootp_request
 * Purpose:
 *     Send the request by calling the interface's output routine
 *     bypassing routing code.
 */
static int
send_bootp_request(struct ifnet * ifp, __unused struct socket * so,
		   struct bootp_packet * pkt)
{
    struct mbuf	*	m;
    struct sockaddr_in	sin;
    
    /* Address to send to */
    sin = blank_sin();
    sin.sin_port = htons(IPPORT_BOOTPS);
    sin.sin_addr.s_addr = INADDR_BROADCAST;
    
    m = ip_pkt_to_mbuf((caddr_t)pkt, sizeof(*pkt));
    return dlil_output(ifp, PF_INET, m, 0, (struct sockaddr *)&sin, 0);
}

/*
 * Function: receive_packet
 * Purpose:
 *   Return a received packet or an error if none available.
 */
int
receive_packet(struct socket * so, caddr_t pp, int psize, int * actual_size)
{
    uio_t		auio;
    int			rcvflg;
    int			error;
	char		uio_buf[ UIO_SIZEOF(1) ];

 	auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, 
								  &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, CAST_USER_ADDR_T(pp), psize);
    rcvflg = MSG_WAITALL;
    
    error = soreceive(so, (struct sockaddr **) 0, auio, 0, 0, &rcvflg);
    *actual_size = psize - uio_resid(auio);
    return (error);
}

/*
 * Function: bootp_timeout
 * Purpose:
 *   Wakeup the process waiting for something on a socket.
 */
static void
bootp_timeout(void * arg)
{
    struct socket * * socketflag = (struct socket * *)arg;
    struct socket * so = *socketflag;
    
    dprintf(("bootp: timeout\n"));

    *socketflag = NULL;
    socket_lock(so, 1);
    sowakeup(so, &so->so_rcv);
    socket_unlock(so, 1);
    return;
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
rate_packet(__unused struct bootp * pkt, __unused int pkt_size, dhcpol_t * options_p)
{
    int		len;
    int 	rating = 1;

    if (dhcpol_find(options_p, dhcptag_subnet_mask_e, &len, NULL) != NULL) {
	rating++;
    }
    if (dhcpol_find(options_p, dhcptag_router_e, &len, NULL) != NULL) {
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
    int				reply_size = DHCP_PACKET_MIN;
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
    reply = (struct bootp *)kalloc(reply_size);
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
	timeout((timeout_fcn_t)bootp_timeout, &timeflag, wait_ticks);

	while (TRUE) {
	    int 	n = 0;

	    error = receive_packet(so, (caddr_t)reply, reply_size, &n);
	    if (error == 0) {
		dprintf(("\nbootp: received packet\n"));
		if (ntohl(reply->bp_xid) == xid
		    && reply->bp_yiaddr.s_addr
		    && bcmp(reply->bp_chaddr, hwaddr, hwlen) == 0) {
		    int 		rating;
		    dhcpol_t		options;

#ifdef	BOOTP_DEBUG
		    print_reply_short(reply, n);
#endif /* BOOTP_DEBUG */
		    (void)dhcpol_parse_packet(&options, (struct dhcp *)reply, 
					      n, NULL);
		    rating = rate_packet(reply, n, &options);
		    if (rating > last_rating) {
			struct in_addr * 	ip;
			int			len;

			*iaddr_p = reply->bp_yiaddr;
			ip = (struct in_addr *)
			    dhcpol_find(&options, 
					dhcptag_subnet_mask_e, &len, NULL);
			if (ip) {
			    *netmask_p = *ip;
			}
			ip = (struct in_addr *)
			    dhcpol_find(&options, dhcptag_router_e, &len, NULL);
			if (ip) {
			    *router_p = *ip;
			}
			printf("%sbootp: got "
			       "response from %s (" IP_FORMAT ")\n",
			       last_rating == 0 ? "\n" : "",
			       reply->bp_sname, 
			       IP_LIST(&reply->bp_siaddr));
		    }
		    dhcpol_free(&options);
		    if (rating >= GOOD_RATING) {
			untimeout((timeout_fcn_t)bootp_timeout, &timeflag);
			goto done;
		    }
		    if (gather_count == 0) {
			untimeout((timeout_fcn_t)bootp_timeout, &timeflag);
			timeflag = so;
			timeout((timeout_fcn_t)bootp_timeout, &timeflag, 
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
		    goto done; /* we have a packet */
		}
		break; /* retry */
	    }
	    else {
		socket_lock(so, 1);
		error = sbwait(&so->so_rcv);
		socket_unlock(so, 1);
	    }
	}
	if (error && (error != EWOULDBLOCK)) {
	    dprintf(("bootp: failed to receive packets: %d\n", error));
	    untimeout((timeout_fcn_t)bootp_timeout, &timeflag);
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

 done:
    error = 0;

 cleanup:
    if (request)
	kfree(request, sizeof (*request));
    if (reply)
	kfree(reply, reply_size);
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
    *((struct sockaddr_in *)&ifr.ifr_addr) = blank_sin();
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
	socket_lock(so, 1);
	so->so_state |= SS_NBIO;
	socket_unlock(so, 1);
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
