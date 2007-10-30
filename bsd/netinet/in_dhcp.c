/*
 * Copyright (c) 1988-2007 Apple Inc. All rights reserved.
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
 * in_dhcp.c
 * - use DHCP to allocate an IP address and get the subnet mask and router
 */

/* 
 * Modification History
 *
 * April 17, 2007	Dieter Siegmund	(dieter@apple.com)
 * - created based on in_bootp.c
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
#include <net/dlil.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/bootp.h>
#include <netinet/dhcp.h>
#include <netinet/in_dhcp.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <netinet/dhcp_options.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>

#ifdef	DHCP_DEBUG
#define	dprintf(x) printf x;
#else	/* !DHCP_DEBUG */
#define	dprintf(x)
#endif	/* DHCP_DEBUG */

#define INITIAL_WAIT_SECS		2
#define MAX_WAIT_SECS			64
#define GATHER_TIME_SECS		4
#define RAND_TICKS			(hz)	/* one second */

const struct sockaddr_in blank_sin = {
    sizeof(struct sockaddr_in), 
    AF_INET, 
    0, 
    { 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0 }
};

__private_extern__ int
inet_aifaddr(struct socket * so, const char * name,
	     const struct in_addr * addr, 
	     const struct in_addr * mask,
	     const struct in_addr * broadcast)
{
    struct ifaliasreq	ifra;

    bzero(&ifra, sizeof(ifra));
    strlcpy(ifra.ifra_name, name, sizeof(ifra.ifra_name));
    if (addr) {
	*((struct sockaddr_in *)&ifra.ifra_addr) = blank_sin;
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_addr = *addr;
    }
    if (mask) {
	*((struct sockaddr_in *)&ifra.ifra_mask) = blank_sin;
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_addr = *mask;
    }
    if (broadcast) {
	*((struct sockaddr_in *)&ifra.ifra_broadaddr) = blank_sin;
	((struct sockaddr_in *)&ifra.ifra_broadaddr)->sin_addr = *broadcast;
    }
    return (ifioctl(so, SIOCAIFADDR, (caddr_t)&ifra, current_proc()));
}


struct dhcp_context {
    struct ifnet *		ifp;
    struct sockaddr_dl *	dl_p;
    struct ifreq 		ifr;
    struct socket *		so;
    uint8_t			request[DHCP_PACKET_MIN];
    dhcpoa_t			request_options;
    uint8_t			reply[DHCP_PAYLOAD_MIN];
    struct timeval		start_time;
    uint32_t			xid;
    int				max_try;
    struct in_addr  		iaddr;
    struct in_addr  		netmask;
    struct in_addr 		router;
    struct in_addr		server_id;
};

static __inline__ struct dhcp_packet *
dhcp_context_request(struct dhcp_context * context)
{
    return ((struct dhcp_packet *)context->request);
}

static __inline__ struct dhcp *
dhcp_context_reply(struct dhcp_context * context)
{
    return ((struct dhcp *)context->reply);
}

struct mbuf * ip_pkt_to_mbuf(caddr_t pkt, int pktsize);

static int
receive_packet(struct socket * so, void * pp, int psize,
	       int * actual_size);

/* ip address formatting macros */
#define IP_FORMAT	"%d.%d.%d.%d"
#define IP_CH(ip)	((const uint8_t *)ip)
#define IP_LIST(ip)	IP_CH(ip)[0],IP_CH(ip)[1],IP_CH(ip)[2],IP_CH(ip)[3]

#define SUGGESTED_LEASE_LENGTH		(60 * 60 * 24 * 30 * 3) /* 3 months */

static const uint8_t dhcp_params[] = {
    dhcptag_subnet_mask_e, 
    dhcptag_router_e,
};

#define	N_DHCP_PARAMS 	(sizeof(dhcp_params) / sizeof(dhcp_params[0]))

static __inline__ long
random_range(long bottom, long top)
{
    long number = top - bottom + 1;
    long range_size = LONG_MAX / number;
    return (((long)random()) / range_size + bottom);
}

static void
init_dhcp_packet_header(struct dhcp_packet * pkt, int pkt_size)
{
    bzero(&pkt->ip, sizeof(pkt->ip));
    bzero(&pkt->udp, sizeof(pkt->udp));
    pkt->ip.ip_v = IPVERSION;
    pkt->ip.ip_hl = sizeof(struct ip) >> 2;
    pkt->ip.ip_ttl = MAXTTL;
    pkt->ip.ip_p = IPPROTO_UDP;
    pkt->ip.ip_src.s_addr = 0;
    pkt->ip.ip_dst.s_addr = htonl(INADDR_BROADCAST);
    pkt->ip.ip_len = htons(pkt_size);
    pkt->ip.ip_sum = 0;
    pkt->udp.uh_sport = htons(IPPORT_BOOTPC);
    pkt->udp.uh_dport = htons(IPPORT_BOOTPS);
    pkt->udp.uh_sum = 0;
    pkt->udp.uh_ulen = htons(pkt_size - sizeof(pkt->ip));
    return;
}

/*
 * Function: make_dhcp_request
 * Purpose:
 *   Initialize the DHCP-specific parts of the message.
 */
static void
make_dhcp_request(struct dhcp * request, int request_size,
		  dhcp_msgtype_t msg, 
		  const uint8_t * hwaddr, uint8_t hwtype, int hwlen,
		  dhcpoa_t * options_p)
{
    uint8_t		cid[ETHER_ADDR_LEN + 1];
    uint8_t		rfc_magic[RFC_MAGIC_SIZE] = RFC_OPTIONS_MAGIC;

    if (hwlen > (int)sizeof(cid)) {
	printf("dhcp: hwlen is %d (> %d), truncating\n", hwlen,
	       (int)sizeof(cid));
	hwlen = sizeof(cid);
    }
    bzero(request, request_size);
    request->dp_op = BOOTREQUEST;
    request->dp_htype = hwtype;
    request->dp_hlen = hwlen;
    bcopy(hwaddr, request->dp_chaddr, hwlen);
    bcopy(rfc_magic, request->dp_options, RFC_MAGIC_SIZE);
    dhcpoa_init(options_p, request->dp_options + RFC_MAGIC_SIZE,
		request_size - sizeof(struct dhcp) - RFC_MAGIC_SIZE);
    /* make the request a dhcp packet */
    dhcpoa_add_dhcpmsg(options_p, msg);

    /* add the list of required parameters */
    dhcpoa_add(options_p, dhcptag_parameter_request_list_e,
	       N_DHCP_PARAMS, dhcp_params);

    /* add the DHCP client identifier */
    cid[0] = hwtype;
    bcopy(hwaddr, cid + 1, hwlen);
    dhcpoa_add(options_p, dhcptag_client_identifier_e, hwlen + 1, cid);

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
    
    m = (struct mbuf *)m_devget(pkt, pktsize, 0, NULL, NULL);
    if (m == 0) {
	printf("dhcp: ip_pkt_to_mbuf: m_devget failed\n");
	return NULL;
    }
    m->m_flags |= M_BCAST;
    /* Compute the checksum */
    ip = mtod(m, struct ip *);
    ip->ip_sum = 0;
    ip->ip_sum = in_cksum(m, sizeof(struct ip));
    return (m);
}

static __inline__ u_char *
link_address(struct sockaddr_dl * dl_p)
{
    return (u_char *)(dl_p->sdl_data + dl_p->sdl_nlen);
}

static __inline__ int
link_address_length(struct sockaddr_dl * dl_p)
{
    return (dl_p->sdl_alen);
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
 * Function: send_packet
 * Purpose:
 *     Send the request directly on the interface, bypassing the routing code.
 */
static int
send_packet(struct ifnet * ifp, struct dhcp_packet * pkt, int pkt_size)
{
    struct mbuf	*	m;
    struct sockaddr_in	dest;
    
    dest = blank_sin;
    dest.sin_port = htons(IPPORT_BOOTPS);
    dest.sin_addr.s_addr = INADDR_BROADCAST;
    m = ip_pkt_to_mbuf((caddr_t)pkt, pkt_size);
    return dlil_output(ifp, PF_INET, m, 0, (struct sockaddr *)&dest, 0);
}

/*
 * Function: receive_packet
 * Purpose:
 *   Return a received packet or an error if none available.
 */
static int
receive_packet(struct socket * so, void * pp, int psize, int * actual_size)
{
    uio_t	auio;
    int		error;
    int		rcvflg;
    char	uio_buf[ UIO_SIZEOF(1) ];

    auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, 
				&uio_buf[0], sizeof(uio_buf));
    uio_addiov(auio, CAST_USER_ADDR_T(pp), psize);
    rcvflg = MSG_WAITALL;
    
    error = soreceive(so, (struct sockaddr **) 0, auio, 0, 0, &rcvflg);
    *actual_size = psize - uio_resid(auio);
    return (error);
}

/*
 * Function: dhcp_timeout
 * Purpose:
 *   Wakeup the process waiting for something on a socket.
 */
static void
dhcp_timeout(void * arg)
{
    struct socket * * timer_arg = (struct socket * *)arg;
    struct socket * so = *timer_arg;
    
    dprintf(("dhcp: timeout\n"));

    *timer_arg = NULL;
    socket_lock(so, 1);
    sowakeup(so, &so->so_rcv);
    socket_unlock(so, 1);
    return;
}

/*
 * Function: rate_packet
 * Purpose:
 *   Return an integer point rating value for the given dhcp packet.
 *   If yiaddr non-zero, the packet gets a rating of 1.
 *   Another point is given if the packet contains the subnet mask,
 *   and another if the router is present.
 */
#define GOOD_RATING	3
static __inline__ int 
rate_packet(dhcpol_t * options_p)
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

static dhcp_msgtype_t
get_dhcp_msgtype(dhcpol_t * options_p)
{
    int				len;
    const uint8_t * 		opt;

    opt = dhcpol_find(options_p, dhcptag_dhcp_message_type_e, &len, NULL);
    if (opt != NULL && len == 1) {
	return (*opt);
    }
    return (dhcp_msgtype_none_e);
}

static int
dhcp_get_ack(struct dhcp_context * context, int wait_ticks)
{
    int				error = 0;
    const struct in_addr * 	ip;
    int				len;
    int				n;
    struct dhcp *		reply;
    struct in_addr		server_id;
    struct socket * 		timer_arg;

    timer_arg = context->so;
    reply = dhcp_context_reply(context);
    timeout((timeout_fcn_t)dhcp_timeout, &timer_arg, wait_ticks);
    while (1) {
	error = receive_packet(context->so, context->reply,
			       sizeof(context->reply), &n);
	if (error == 0) {
	    dhcp_msgtype_t	msg;
	    dhcpol_t		options;

	    dprintf(("\ndhcp: received packet length %d\n", n));
	    if (n < (int)sizeof(struct dhcp)) {
		dprintf(("dhcp: packet is too short %d < %d\n",
			 n, (int)sizeof(struct dhcp)));
		continue;
	    }
	    if (ntohl(reply->dp_xid) != context->xid
		|| bcmp(reply->dp_chaddr, link_address(context->dl_p), 
			link_address_length(context->dl_p)) != 0) {
		/* not for us */
		continue;
	    }
	    (void)dhcpol_parse_packet(&options, reply, n);
	    server_id.s_addr = 0;
	    ip = (const struct in_addr *)
		dhcpol_find(&options, 
			    dhcptag_server_identifier_e, &len, NULL);
	    if (ip != NULL && len >= (int)sizeof(*ip)) {
		server_id = *ip;
	    }
	    msg = get_dhcp_msgtype(&options);
	    if (msg == dhcp_msgtype_nak_e
		&& server_id.s_addr == context->server_id.s_addr) {
		/* server NAK'd us, start over */
		dhcpol_free(&options);
		error = EPROTO;
		untimeout((timeout_fcn_t)dhcp_timeout, &timer_arg);
		break;
	    }
	    if (msg != dhcp_msgtype_ack_e
		|| reply->dp_yiaddr.s_addr == 0
		|| reply->dp_yiaddr.s_addr == INADDR_BROADCAST) {
		/* ignore the packet */
		goto next_packet;
	    }
	    printf("dhcp: received ACK: server " IP_FORMAT
		   " IP address "  IP_FORMAT "\n",
		   IP_LIST(&server_id), IP_LIST(&reply->dp_yiaddr));
	    context->iaddr = reply->dp_yiaddr;
	    ip = (const struct in_addr *)
		dhcpol_find(&options, 
			    dhcptag_subnet_mask_e, &len, NULL);
	    if (ip != NULL && len >= (int)sizeof(*ip)) {
		context->netmask = *ip;
	    }
	    ip = (const struct in_addr *)
		dhcpol_find(&options, dhcptag_router_e, &len, NULL);
	    if (ip != NULL && len >= (int)sizeof(*ip)) {
		context->router = *ip;
	    }
	    dhcpol_free(&options);
	    untimeout((timeout_fcn_t)dhcp_timeout, &timer_arg);
	    break;

	next_packet:
	    dhcpol_free(&options);
	}
	else if ((error != EWOULDBLOCK)) {
	    /* if some other error occurred, we're done */
	    untimeout((timeout_fcn_t)dhcp_timeout, &timer_arg);
	    break;
	}
	else if (timer_arg == NULL) { 
	    /* timed out */
	    break;
	}
	else {
	    /* wait for a wait to arrive, or a timeout to occur */
	    socket_lock(context->so, 1);
	    error = sbwait(&context->so->so_rcv);
	    socket_unlock(context->so, 1);
	}
    }
    return (error);
}

static int
dhcp_select(struct dhcp_context * context)
{
    struct timeval		current_time;
    int				error = 0;
    dhcpoa_t *			options_p;
    struct dhcp_packet *	request;
    int				request_size;
    int				retry;
    int				wait_ticks;

    /* format a DHCP Request packet */
    request = dhcp_context_request(context);
    options_p = &context->request_options;

    make_dhcp_request(&request->dhcp, DHCP_PAYLOAD_MIN,
		      dhcp_msgtype_request_e,
		      link_address(context->dl_p), ARPHRD_ETHER,
		      link_address_length(context->dl_p),
		      options_p);
    /* insert server identifier and requested ip address */
    dhcpoa_add(options_p, dhcptag_requested_ip_address_e,
	       sizeof(context->iaddr), &context->iaddr);
    dhcpoa_add(options_p, dhcptag_server_identifier_e,
	       sizeof(context->server_id), &context->server_id);
    dhcpoa_add(options_p, dhcptag_end_e, 0, 0);
    request_size = sizeof(*request) + RFC_MAGIC_SIZE 
	+ dhcpoa_used(options_p);
    if (request_size < (int)sizeof(struct bootp_packet)) {
	/* pad out to BOOTP-sized packet */
	request_size = sizeof(struct bootp_packet);
    }
    init_dhcp_packet_header(request, request_size);

    wait_ticks = INITIAL_WAIT_SECS * hz;
#define SELECT_RETRY_COUNT	3
    for (retry = 0; retry < SELECT_RETRY_COUNT; retry++) {
	/* Send the request */
	printf("dhcp: sending REQUEST: server " IP_FORMAT 
	       " IP address " IP_FORMAT "\n",
	       IP_LIST(&context->server_id),
	       IP_LIST(&context->iaddr));
	microtime(&current_time);
	request->dhcp.dp_secs 
	    = htons((u_short)
		    (current_time.tv_sec - context->start_time.tv_sec));
	request->dhcp.dp_xid = htonl(context->xid);
#ifdef RANDOM_IP_ID
	request->ip.ip_id = ip_randomid();
#else
	request->ip.ip_id = htons(ip_id++);
#endif
	error = send_packet(context->ifp, request, request_size);
	if (error != 0) {
	    printf("dhcp: send_packet failed with %d\n", error);
	    goto failed;
	}

	wait_ticks += random_range(-RAND_TICKS, RAND_TICKS);
	dprintf(("dhcp: waiting %d ticks\n", wait_ticks));
	error = dhcp_get_ack(context, wait_ticks);
	switch (error) {
	case 0:
	    /* we're done */
	    goto done;
	case EPROTO:
	    printf("dhcp: server " IP_FORMAT " send us a NAK\n",
		   IP_LIST(&context->server_id));
	    goto failed;
	case EWOULDBLOCK:
	    break;
	default:
	    dprintf(("dhcp: failed to receive packets: %d\n", error));
	    goto failed;
	}
	wait_ticks *= 2;
	if (wait_ticks > (MAX_WAIT_SECS * hz))
	    wait_ticks = MAX_WAIT_SECS * hz;
	microtime(&current_time);
    }
    error = ETIMEDOUT;
    goto failed;
    
 done:
    error = 0;

 failed:
    return (error);
}

static int
dhcp_get_offer(struct dhcp_context * context, int wait_ticks)
{
    int				error = 0;
    int	 			gather_count = 0;
    const struct in_addr * 	ip;
    int				last_rating = 0;
    int				len;
    int				n;
    int 			rating;
    struct dhcp *		reply;
    struct in_addr		server_id;
    struct socket * 		timer_arg;

    timer_arg = context->so;
    reply = dhcp_context_reply(context);
    timeout((timeout_fcn_t)dhcp_timeout, &timer_arg, wait_ticks);
    while (1) {
	error = receive_packet(context->so, context->reply,
			       sizeof(context->reply), &n);
	if (error == 0) {
	    dhcpol_t		options;

	    dprintf(("\ndhcp: received packet length %d\n", n));
	    if (n < (int)sizeof(struct dhcp)) {
		dprintf(("dhcp: packet is too short %d < %d\n",
			 n, (int)sizeof(struct dhcp)));
		continue;
	    }
	    if (ntohl(reply->dp_xid) != context->xid
		|| reply->dp_yiaddr.s_addr == 0
		|| reply->dp_yiaddr.s_addr == INADDR_BROADCAST
		|| bcmp(reply->dp_chaddr,
			link_address(context->dl_p), 
			link_address_length(context->dl_p)) != 0) {
		/* not for us */
		continue;
	    }
	    (void)dhcpol_parse_packet(&options, reply, n);
	    if (get_dhcp_msgtype(&options) != dhcp_msgtype_offer_e) {
		/* not an offer */
		goto next_packet;
	    }
	    ip = (const struct in_addr *)
		dhcpol_find(&options, 
			    dhcptag_server_identifier_e, &len, NULL);
	    if (ip == NULL || len < (int)sizeof(*ip)) {
		/* missing/invalid server identifier */
		goto next_packet;
	    }
	    printf("dhcp: received OFFER: server " IP_FORMAT
		   " IP address "  IP_FORMAT "\n",
		   IP_LIST(ip), IP_LIST(&reply->dp_yiaddr));
	    server_id = *ip;
	    rating = rate_packet(&options);
	    if (rating > last_rating) {
		context->iaddr = reply->dp_yiaddr;
		ip = (const struct in_addr *)
		    dhcpol_find(&options, 
				dhcptag_subnet_mask_e, &len, NULL);
		if (ip != NULL && len >= (int)sizeof(*ip)) {
		    context->netmask = *ip;
		}
		ip = (const struct in_addr *)
		    dhcpol_find(&options, dhcptag_router_e, &len, NULL);
		if (ip != NULL && len >= (int)sizeof(*ip)) {
		    context->router = *ip;
		}
		context->server_id = server_id;
	    }
	    if (rating >= GOOD_RATING) {
		dhcpol_free(&options);
		/* packet is good enough */
		untimeout((timeout_fcn_t)dhcp_timeout, &timer_arg);
		break;
	    }
	    if (gather_count == 0) {
		untimeout((timeout_fcn_t)dhcp_timeout, &timer_arg);
		timer_arg = context->so;
		timeout((timeout_fcn_t)dhcp_timeout, &timer_arg, 
			hz * GATHER_TIME_SECS);
	    }
	    gather_count = 1;
	next_packet:
	    dhcpol_free(&options);
	}
	else if ((error != EWOULDBLOCK)) {
	    untimeout((timeout_fcn_t)dhcp_timeout, &timer_arg);
	    break;
	}
	else if (timer_arg == NULL) { /* timed out */
	    if (gather_count != 0) {
		dprintf(("dhcp: gathering time has expired\n"));
		error = 0;
	    }
	    break;
	}
	else {
	    socket_lock(context->so, 1);
	    error = sbwait(&context->so->so_rcv);
	    socket_unlock(context->so, 1);
	}
    }
    return (error);
}

/*
 * Function: dhcp_init
 * Purpose:
 *   Start in the DHCP INIT state sending DISCOVER's.  When we get OFFER's,
 *   try to select one of them by sending a REQUEST and waiting for an ACK.
 */
static int
dhcp_init(struct dhcp_context * context)
{
    struct timeval		current_time;
    int				error = 0;
    uint32_t			lease_option = htonl(SUGGESTED_LEASE_LENGTH);
    dhcpoa_t *			options_p;
    struct dhcp_packet *	request;
    int				request_size;
    int				retry;
    int				wait_ticks;

    /* remember the time we started */
    microtime(&context->start_time);
    current_time = context->start_time;
    
    request = dhcp_context_request(context);
    options_p = &context->request_options;

 retry:
    /* format a DHCP DISCOVER packet */
    make_dhcp_request(&request->dhcp, DHCP_PAYLOAD_MIN,
		      dhcp_msgtype_discover_e,
		      link_address(context->dl_p), ARPHRD_ETHER,
		      link_address_length(context->dl_p), 
		      options_p);
    /* add the requested lease time */
    dhcpoa_add(options_p, dhcptag_lease_time_e,
	       sizeof(lease_option), &lease_option);
    dhcpoa_add(options_p, dhcptag_end_e, 0, 0);
    request_size = sizeof(*request) + RFC_MAGIC_SIZE 
	+ dhcpoa_used(options_p);
    if (request_size < (int)sizeof(struct bootp_packet)) {
	/* pad out to BOOTP-sized packet */
	request_size = sizeof(struct bootp_packet);
    }
    init_dhcp_packet_header(request, request_size);

    wait_ticks = INITIAL_WAIT_SECS * hz;
    for (retry = 0; retry < context->max_try; retry++) {
	/* Send the request */
	printf("dhcp: sending DISCOVER\n");
	request->dhcp.dp_secs 
	    = htons((u_short)(current_time.tv_sec 
			      - context->start_time.tv_sec));
	request->dhcp.dp_xid = htonl(context->xid);
#ifdef RANDOM_IP_ID
	request->ip.ip_id = ip_randomid();
#else
	request->ip.ip_id = htons(ip_id++);
#endif
	error = send_packet(context->ifp, request, request_size);
	if (error != 0) {
	    printf("dhcp: send_packet failed with %d\n", error);
	    goto failed;
	}
	wait_ticks += random_range(-RAND_TICKS, RAND_TICKS);
	dprintf(("dhcp: waiting %d ticks\n", wait_ticks));
	error = dhcp_get_offer(context, wait_ticks);
	if (error == 0) {
	    /* send a REQUEST */
	    error = dhcp_select(context);
	    if (error == 0) {
		/* we're done !*/
		goto done;
	    }
	    if (error != EPROTO && error != ETIMEDOUT) {
		/* fatal error */ 
		dprintf(("dhcp: dhcp_select failed %d\n", error));
		goto failed;
	    }
	    /* wait 10 seconds, and try again */
	    printf("dhcp: trying again in 10 seconds\n");
	    tsleep(&error, PRIBIO, "dhcp_init", 10 * hz);
	    context->xid++;
	    goto retry;
	}
	else if (error != EWOULDBLOCK) {
	    dprintf(("dhcp: failed to receive packets: %d\n", error));
	    goto failed;
	}
	wait_ticks *= 2;
	if (wait_ticks > (MAX_WAIT_SECS * hz))
	    wait_ticks = MAX_WAIT_SECS * hz;
	microtime(&current_time);
    }
    error = ETIMEDOUT;
    goto failed;
    
 done:
    error = 0;

 failed:
    return (error);
}

static void
dhcp_context_free(struct dhcp_context * context, struct proc * procp)
{
    if (context == NULL) {
	return;
    }
    if (context->so != NULL) {
	int		error;

	/* disable reception of DHCP packets before address assignment */
	context->ifr.ifr_intval = 0;
	error = ifioctl(context->so, SIOCAUTOADDR,
			(caddr_t)&context->ifr, procp);
	if (error) {
	    printf("dhcp: SIOCAUTOADDR failed: %d\n", error);
	}
	soclose(context->so);
    }
    kfree(context, sizeof(*context));
    return;
}

static struct dhcp_context *
dhcp_context_create(struct ifnet * ifp, int max_try,
		    struct proc * procp, int * error_p)
{
    struct dhcp_context	*	context = NULL;
    struct sockaddr_dl *	dl_p;
    struct in_addr		lo_addr;
    struct in_addr		lo_mask;
    int				error;
    struct sockaddr_in		sin;

    /* get the hardware address from the interface */
    dl_p = link_from_ifnet(ifp);
    if (dl_p == NULL) {
	printf("dhcp: can't get link address\n");
	error = ENXIO;
	goto failed;
    }

    printf("dhcp: h/w addr ");
    link_print(dl_p);
    if (dl_p->sdl_type != IFT_ETHER) {
	printf("dhcp: hardware type %d not supported\n",
	       dl_p->sdl_type);
	error = ENXIO;
	goto failed;
    }

    context = (struct dhcp_context *)kalloc(sizeof(*context));
    if (context == NULL) {
	printf("dhcp: failed to allocate context\n");
	error = ENOMEM;
	goto failed;
    }
    bzero(context, sizeof(*context));

    /* get a socket */
    error = socreate(AF_INET, &context->so, SOCK_DGRAM, 0);
    if (error != 0) {
	printf("dhcp: socreate failed %d\n", error);
	goto failed;
    }

    /* assign 127.0.0.1 to lo0 so that the bind will succeed */
    lo_addr.s_addr = htonl(INADDR_LOOPBACK);
    lo_mask.s_addr = htonl(IN_CLASSA_NET);
    error = inet_aifaddr(context->so, "lo0", &lo_addr, &lo_mask, NULL);
    if (error != 0) {
	printf("dhcp: assigning loopback address failed %d\n", error);
    }

    /* enable reception of DHCP packets before an address is assigned */
    snprintf(context->ifr.ifr_name, 
	     sizeof(context->ifr.ifr_name), "%s%d", ifp->if_name,
	     ifp->if_unit);
    context->ifr.ifr_intval = 1;

    error = ifioctl(context->so, SIOCAUTOADDR, (caddr_t)&context->ifr, procp);
    if (error) {
	printf("dhcp: SIOCAUTOADDR failed: %d\n", error);
	goto failed;
    }
    dprintf(("dhcp: SIOCAUTOADDR done\n"));

    error = ifioctl(context->so, SIOCPROTOATTACH, (caddr_t)&context->ifr, 
		    procp);
    if (error) {
	printf("dhcp: SIOCPROTOATTACH failed: %d\n", error);
	goto failed;
    }
    dprintf(("dhcp: SIOCPROTOATTACH done\n"));
    
    /* bind the socket */
    sin.sin_len = sizeof(sin);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(IPPORT_BOOTPC);
    sin.sin_addr.s_addr = INADDR_ANY;
    error = sobind(context->so, (struct sockaddr *)&sin);
    if (error) {
	printf("dhcp: sobind failed, %d\n", error);
	goto failed;
    }

    /* make it non-blocking I/O */
    socket_lock(context->so, 1);
    context->so->so_state |= SS_NBIO;
    socket_unlock(context->so, 1);

    /* save passed-in information */
    context->max_try = max_try;
    context->dl_p = dl_p;
    context->ifp = ifp;

    /* get a random transaction id */
    context->xid = random();

    return (context);

 failed:
    dhcp_context_free(context, procp);
    *error_p = error;
    return (NULL);
}

/*
 * Routine: dhcp
 * Function:
 *   Do DHCP over the specified interface to retrieve the IP address,
 *   subnet mask, and router.	
 */
int 
dhcp(struct ifnet * ifp, struct in_addr * iaddr_p, int max_try,
     struct in_addr * netmask_p, struct in_addr * router_p,
     struct proc * procp)
{
    int				error = 0;
    struct dhcp_context	*	context;

    context = dhcp_context_create(ifp, max_try, procp, &error);
    if (context == NULL) {
	return (error);
    }
 
    /* start DHCP in the INIT state */
    error = dhcp_init(context);
    if (error == 0) {
	*iaddr_p = context->iaddr;
	*netmask_p = context->netmask;
	*router_p = context->router;
    }
    dhcp_context_free(context, procp);
    return (error);
}
