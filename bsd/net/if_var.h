/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	From: @(#)if.h	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/net/if_var.h,v 1.18.2.7 2001/07/24 19:10:18 brooks Exp $
 */

#ifndef	_NET_IF_VAR_H_
#define	_NET_IF_VAR_H_
#include <sys/appleapiopts.h>

#ifdef __APPLE__
#define APPLE_IF_FAM_LOOPBACK  1
#define APPLE_IF_FAM_ETHERNET  2
#define APPLE_IF_FAM_SLIP      3
#define APPLE_IF_FAM_TUN       4
#define APPLE_IF_FAM_VLAN      5
#define APPLE_IF_FAM_PPP       6
#define APPLE_IF_FAM_PVC       7
#define APPLE_IF_FAM_DISC      8
#define APPLE_IF_FAM_MDECAP    9
#define APPLE_IF_FAM_GIF       10
#define APPLE_IF_FAM_FAITH     11
#define APPLE_IF_FAM_STF	   12
#endif

/*
 * Structures defining a network interface, providing a packet
 * transport mechanism (ala level 0 of the PUP protocols).
 *
 * Each interface accepts output datagrams of a specified maximum
 * length, and provides higher level routines with input datagrams
 * received from its medium.
 *
 * Output occurs when the routine if_output is called, with three parameters:
 *	(*ifp->if_output)(ifp, m, dst, rt)
 * Here m is the mbuf chain to be sent and dst is the destination address.
 * The output routine encapsulates the supplied datagram if necessary,
 * and then transmits it on its medium.
 *
 * On input, each interface unwraps the data received by it, and either
 * places it on the input queue of a internetwork datagram routine
 * and posts the associated software interrupt, or passes the datagram to a raw
 * packet input routine.
 *
 * Routines exist for locating interfaces by their addresses
 * or for locating a interface on a certain network, as well as more general
 * routing and gateway routines maintaining information used to locate
 * interfaces.  These routines live in the files if.c and route.c
 */

#ifdef __STDC__
/*
 * Forward structure declarations for function prototypes [sic].
 */
struct	mbuf;
struct	proc;
struct	rtentry;
struct	socket;
struct	ether_header;
struct  sockaddr_dl;
#endif

#define	IFNAMSIZ	16

#include <sys/queue.h>		/* get TAILQ macros */

#ifdef __APPLE_API_UNSTABLE
#ifdef __APPLE__
struct tqdummy;

TAILQ_HEAD(tailq_head, tqdummy);

/* This belongs up in socket.h or socketvar.h, depending on how far the
 *   event bubbles up.
 */

struct net_event_data {
     u_long		if_family;
     u_long		if_unit;
     char		if_name[IFNAMSIZ];
};
#endif


TAILQ_HEAD(ifnethead, ifnet);	/* we use TAILQs so that the order of */
TAILQ_HEAD(ifaddrhead, ifaddr);	/* instantiation is preserved in the list */
TAILQ_HEAD(ifprefixhead, ifprefix);
LIST_HEAD(ifmultihead, ifmultiaddr);

#ifdef __APPLE__
/*
 * Structure describing information about an interface
 * which may be of interest to management entities.
 */
struct if_data {
	/* generic interface information */
	u_char	ifi_type;		/* ethernet, tokenring, etc */
#ifdef __APPLE__
	u_char	ifi_typelen;		/* Length of frame type id */
#endif
	u_char	ifi_physical;		/* e.g., AUI, Thinnet, 10base-T, etc */
	u_char	ifi_addrlen;		/* media address length */
	u_char	ifi_hdrlen;		/* media header length */
	u_char	ifi_recvquota;		/* polling quota for receive intrs */
	u_char	ifi_xmitquota;		/* polling quota for xmit intrs */
	u_long	ifi_mtu;		/* maximum transmission unit */
	u_long	ifi_metric;		/* routing metric (external only) */
	u_long	ifi_baudrate;		/* linespeed */
	/* volatile statistics */
	u_long	ifi_ipackets;		/* packets received on interface */
	u_long	ifi_ierrors;		/* input errors on interface */
	u_long	ifi_opackets;		/* packets sent on interface */
	u_long	ifi_oerrors;		/* output errors on interface */
	u_long	ifi_collisions;		/* collisions on csma interfaces */
	u_long	ifi_ibytes;		/* total number of octets received */
	u_long	ifi_obytes;		/* total number of octets sent */
	u_long	ifi_imcasts;		/* packets received via multicast */
	u_long	ifi_omcasts;		/* packets sent via multicast */
	u_long	ifi_iqdrops;		/* dropped on input, this interface */
	u_long	ifi_noproto;		/* destined for unsupported protocol */
#ifdef __APPLE__
	u_long	ifi_recvtiming;		/* usec spent receiving when timing */
	u_long	ifi_xmittiming;		/* usec spent xmitting when timing */
#endif
	struct	timeval ifi_lastchange;	/* time of last administrative change */
#ifdef __APPLE__
	u_long	default_proto;		/* Default dl_tag when none is specified 
								 * on dlil_output */
#endif
	u_long	ifi_hwassist;		/* HW offload capabilities */
	u_long	ifi_reserved1;		/* for future use */
	u_long	ifi_reserved2;		/* for future use */
};
#endif

/*
 * Structure defining a queue for a network interface.
 */
struct	ifqueue {
	struct	mbuf *ifq_head;
	struct	mbuf *ifq_tail;
	int	ifq_len;
	int	ifq_maxlen;
	int	ifq_drops;
};

/*
 * Structure defining a network interface.
 *
 * (Would like to call this struct ``if'', but C isn't PL/1.)
 */
struct ifnet {
	void	*if_softc;		/* pointer to driver state */
	char	*if_name;		/* name, e.g. ``en'' or ``lo'' */
	TAILQ_ENTRY(ifnet) if_link; 	/* all struct ifnets are chained */
	struct	ifaddrhead if_addrhead;	/* linked list of addresses per if */
#ifdef __APPLE__
	struct  tailq_head proto_head;  /* Head for if_proto structures */  
#endif
        int	if_pcount;		/* number of promiscuous listeners */
	struct	bpf_if *if_bpf;		/* packet filter structure */
	u_short	if_index;		/* numeric abbreviation for this if  */
	short	if_unit;		/* sub-unit for lower level driver */
	short	if_timer;		/* time 'til if_watchdog called */
	short	if_flags;		/* up/down, broadcast, etc. */
	int	if_ipending;		/* interrupts pending */
	void	*if_linkmib;		/* link-type-specific MIB data */
	size_t	if_linkmiblen;		/* length of above data */
	struct	if_data if_data;

#ifdef __APPLE__
/* New with DLIL */
	int	refcnt;
	int	offercnt;
	int	(*if_output)(struct ifnet *ifnet_ptr, struct mbuf *m);
	int	(*if_ioctl)(struct ifnet *ifnet_ptr, u_long  ioctl_code, void  *ioctl_arg);
	int	(*if_set_bpf_tap)(struct ifnet *ifp, int mode, 
				  int (*bpf_callback)(struct ifnet *, struct mbuf *));
	int	(*if_free)(struct ifnet *ifnet_ptr);
	int	(*if_demux)(struct ifnet  *ifnet_ptr, struct mbuf  *mbuf_ptr, 
			    char *frame_ptr, void  *if_proto_ptr);

	int	(*if_event)(struct ifnet  *ifnet_ptr, caddr_t  event_ptr);

	int	(*if_framer)(struct ifnet    *ifp,
			     struct mbuf     **m,
			     struct sockaddr *dest,
			     char            *dest_linkaddr,
			     char	     *frame_type);

	u_long  if_family;		/* ulong assigned by Apple */
	struct tailq_head   if_flt_head;

/* End DLIL specific */

	void 	*reserved0;	/* for future use */
	void    *if_private;	/* private to interface */
	long	if_eflags;		/* autoaddr, autoaddr done, etc. */
#endif /* __APPLE__ */

	struct	ifmultihead if_multiaddrs; /* multicast addresses configured */
	int	if_amcount;		/* number of all-multicast requests */
/* procedure handles */
#ifndef __APPLE__
	int	(*if_output)		/* output routine (enqueue) */
		__P((struct ifnet *, struct mbuf *, struct sockaddr *,
		     struct rtentry *));
	void	(*if_start)		/* initiate output routine */
		__P((struct ifnet *));
	int	(*if_done)		/* output complete routine */
		__P((struct ifnet *));	/* (XXX not used; fake prototype) */
	int	(*if_ioctl)		/* ioctl routine */
		__P((struct ifnet *, u_long, caddr_t));
	void	(*if_watchdog)		/* timer routine */
		__P((struct ifnet *));
#endif
	int	(*if_poll_recv)		/* polled receive routine */
		__P((struct ifnet *, int *));
	int	(*if_poll_xmit)		/* polled transmit routine */
		__P((struct ifnet *, int *));
	void	(*if_poll_intren)	/* polled interrupt reenable routine */
		__P((struct ifnet *));
	void	(*if_poll_slowinput)	/* input routine for slow devices */
		__P((struct ifnet *, struct mbuf *));
	void	(*if_init)		/* Init routine */
		__P((void *));
	int	(*if_resolvemulti)	/* validate/resolve multicast */
		__P((struct ifnet *, struct sockaddr **, struct sockaddr *));
	struct	ifqueue if_snd;		/* output queue */
	struct	ifqueue *if_poll_slowq;	/* input queue for slow devices */
#ifdef __APPLE__
	u_long  family_cookie;	
	struct	ifprefixhead if_prefixhead; /* list of prefixes per if */
	void *reserved1;	/* for future use */
#else
	struct	ifprefixhead if_prefixhead; /* list of prefixes per if */
#endif /* __APPLE__ */
};
typedef void if_init_f_t __P((void *));

#define	if_mtu		if_data.ifi_mtu
#define	if_type		if_data.ifi_type
#define if_typelen	if_data.ifi_typelen
#define if_physical	if_data.ifi_physical
#define	if_addrlen	if_data.ifi_addrlen
#define	if_hdrlen	if_data.ifi_hdrlen
#define	if_metric	if_data.ifi_metric
#define	if_baudrate	if_data.ifi_baudrate
#define	if_hwassist	if_data.ifi_hwassist
#define	if_ipackets	if_data.ifi_ipackets
#define	if_ierrors	if_data.ifi_ierrors
#define	if_opackets	if_data.ifi_opackets
#define	if_oerrors	if_data.ifi_oerrors
#define	if_collisions	if_data.ifi_collisions
#define	if_ibytes	if_data.ifi_ibytes
#define	if_obytes	if_data.ifi_obytes
#define	if_imcasts	if_data.ifi_imcasts
#define	if_omcasts	if_data.ifi_omcasts
#define	if_iqdrops	if_data.ifi_iqdrops
#define	if_noproto	if_data.ifi_noproto
#define	if_lastchange	if_data.ifi_lastchange
#define if_recvquota	if_data.ifi_recvquota
#define	if_xmitquota	if_data.ifi_xmitquota
#define if_rawoutput(if, m, sa) if_output(if, m, sa, (struct rtentry *)0)

#ifndef __APPLE__
/* for compatibility with other BSDs */
#define	if_addrlist	if_addrhead
#define	if_list		if_link
#endif

/*
 * Bit values in if_ipending
 */
#define	IFI_RECV	1	/* I want to receive */
#define	IFI_XMIT	2	/* I want to transmit */

/*
 * Output queues (ifp->if_snd) and slow device input queues (*ifp->if_slowq)
 * are queues of messages stored on ifqueue structures
 * (defined above).  Entries are added to and deleted from these structures
 * by these macros, which should be called with ipl raised to splimp().
 */
#define	IF_QFULL(ifq)		((ifq)->ifq_len >= (ifq)->ifq_maxlen)
#define	IF_DROP(ifq)		((ifq)->ifq_drops++)
#define	IF_ENQUEUE(ifq, m) { \
	(m)->m_nextpkt = 0; \
	if ((ifq)->ifq_tail == 0) \
		(ifq)->ifq_head = m; \
	else \
		(ifq)->ifq_tail->m_nextpkt = m; \
	(ifq)->ifq_tail = m; \
	(ifq)->ifq_len++; \
}
#define	IF_PREPEND(ifq, m) { \
	(m)->m_nextpkt = (ifq)->ifq_head; \
	if ((ifq)->ifq_tail == 0) \
		(ifq)->ifq_tail = (m); \
	(ifq)->ifq_head = (m); \
	(ifq)->ifq_len++; \
}
#define	IF_DEQUEUE(ifq, m) { \
	(m) = (ifq)->ifq_head; \
	if (m) { \
		if (((ifq)->ifq_head = (m)->m_nextpkt) == 0) \
			(ifq)->ifq_tail = 0; \
		(m)->m_nextpkt = 0; \
		(ifq)->ifq_len--; \
	} \
}

#ifdef KERNEL
#define	IF_ENQ_DROP(ifq, m)	if_enq_drop(ifq, m)

#if defined(__GNUC__) && defined(MT_HEADER)
static __inline int
if_queue_drop(struct ifqueue *ifq, struct mbuf *m)
{
	IF_DROP(ifq);
	return 0;
}

static __inline int
if_enq_drop(struct ifqueue *ifq, struct mbuf *m)
{
	if (IF_QFULL(ifq) &&
	    !if_queue_drop(ifq, m))
		return 0;
	IF_ENQUEUE(ifq, m);
	return 1;
}
#else

#ifdef MT_HEADER
int	if_enq_drop __P((struct ifqueue *, struct mbuf *));
#endif

#endif
#endif /* __APPLE_API_UNSTABLE */

/*
 * 72 was chosen below because it is the size of a TCP/IP
 * header (40) + the minimum mss (32).
 */
#define	IF_MINMTU	72
#define	IF_MAXMTU	65535

#endif /* KERNEL */

#ifdef __APPLE_API_UNSTABLE
/*
 * The ifaddr structure contains information about one address
 * of an interface.  They are maintained by the different address families,
 * are allocated and attached when an address is set, and are linked
 * together so all addresses for an interface can be located.
 */
struct ifaddr {
	struct	sockaddr *ifa_addr;	/* address of interface */
	struct	sockaddr *ifa_dstaddr;	/* other end of p-to-p link */
#define	ifa_broadaddr	ifa_dstaddr	/* broadcast address interface */
	struct	sockaddr *ifa_netmask;	/* used to determine subnet */
#ifndef __APPLE__
	/* Use of if_data doesn't justify change of API */
	struct	if_data if_data;	/* not all members are meaningful */
#endif
	struct	ifnet *ifa_ifp;		/* back-pointer to interface */
	TAILQ_ENTRY(ifaddr) ifa_link;	/* queue macro glue */
	void	(*ifa_rtrequest)	/* check or clean routes (+ or -)'d */
		__P((int, struct rtentry *, struct sockaddr *));
	u_short	ifa_flags;		/* mostly rt_flags for cloning */
	short	ifa_refcnt;/* 16bit ref count, use ifaref, ifafree */
	int	ifa_metric;		/* cost of going out this interface */
#ifdef notdef
	struct	rtentry *ifa_rt;	/* XXXX for ROUTETOIF ????? */
#endif
	u_long  ifa_dlt;
	int (*ifa_claim_addr)		/* check if an addr goes to this if */
		__P((struct ifaddr *, struct sockaddr *));
};
#define	IFA_ROUTE	RTF_UP		/* route installed */

/*
 * The prefix structure contains information about one prefix
 * of an interface.  They are maintained by the different address families,
 * are allocated and attached when an prefix or an address is set,
 * and are linked together so all prefixes for an interface can be located.
 */
struct ifprefix {
	struct	sockaddr *ifpr_prefix;	/* prefix of interface */
	struct	ifnet *ifpr_ifp;	/* back-pointer to interface */
	TAILQ_ENTRY(ifprefix) ifpr_list; /* queue macro glue */
	u_char	ifpr_plen;		/* prefix length in bits */
	u_char	ifpr_type;		/* protocol dependent prefix type */
};

/*
 * Multicast address structure.  This is analogous to the ifaddr
 * structure except that it keeps track of multicast addresses.
 * Also, the reference count here is a count of requests for this
 * address, not a count of pointers to this structure.
 */
struct ifmultiaddr {
	LIST_ENTRY(ifmultiaddr) ifma_link; /* queue macro glue */
	struct	sockaddr *ifma_addr; 	/* address this membership is for */
	struct	sockaddr *ifma_lladdr;	/* link-layer translation, if any */
	struct	ifnet *ifma_ifp;	/* back-pointer to interface */
	u_int	ifma_refcount;		/* reference count */
	void	*ifma_protospec;	/* protocol-specific state, if any */
};

#ifdef KERNEL
#define IFAREF(ifa) ifaref(ifa)
#define IFAFREE(ifa) ifafree(ifa)

#ifdef __APPLE_API_PRIVATE
extern	struct ifnethead ifnet;
extern struct	ifnet	**ifindex2ifnet;
extern	int ifqmaxlen;
extern	struct ifnet loif[];
extern	int if_index;
extern	struct ifaddr **ifnet_addrs;
#endif /* __APPLE_API_PRIVATE */

#ifndef __APPLE__
void	ether_ifattach __P((struct ifnet *, int));
void	ether_ifdetach __P((struct ifnet *, int));
void	ether_input __P((struct ifnet *, struct ether_header *, struct mbuf *));
void	ether_demux __P((struct ifnet *, struct ether_header *, struct mbuf *));
int	ether_output __P((struct ifnet *,
	   struct mbuf *, struct sockaddr *, struct rtentry *));
int	ether_output_frame __P((struct ifnet *, struct mbuf *));
int	ether_ioctl __P((struct ifnet *, int, caddr_t));
#endif

int	if_addmulti __P((struct ifnet *, struct sockaddr *,
			 struct ifmultiaddr **));
int	if_allmulti __P((struct ifnet *, int));
void	if_attach __P((struct ifnet *));
int	if_delmulti __P((struct ifnet *, struct sockaddr *));
void	if_down __P((struct ifnet *));
void	if_route __P((struct ifnet *, int flag, int fam));
void	if_unroute __P((struct ifnet *, int flag, int fam));
void	if_up __P((struct ifnet *));
/*void	ifinit __P((void));*/ /* declared in systm.h for main() */
int	ifioctl __P((struct socket *, u_long, caddr_t, struct proc *));
int	ifpromisc __P((struct ifnet *, int));
struct	ifnet *ifunit __P((const char *));
struct  ifnet *if_withname __P((struct sockaddr *));

int	if_poll_recv_slow __P((struct ifnet *ifp, int *quotap));
void	if_poll_xmit_slow __P((struct ifnet *ifp, int *quotap));
void	if_poll_throttle __P((void));
void	if_poll_unthrottle __P((void *));
void	if_poll_init __P((void));
void	if_poll __P((void));

struct	ifaddr *ifa_ifwithaddr __P((struct sockaddr *));
struct	ifaddr *ifa_ifwithdstaddr __P((struct sockaddr *));
struct	ifaddr *ifa_ifwithnet __P((struct sockaddr *));
struct	ifaddr *ifa_ifwithroute __P((int, struct sockaddr *,
					struct sockaddr *));
struct	ifaddr *ifaof_ifpforaddr __P((struct sockaddr *, struct ifnet *));
void	ifafree __P((struct ifaddr *));
void	ifaref __P((struct ifaddr *));

struct	ifmultiaddr *ifmaof_ifpforaddr __P((struct sockaddr *, 
					    struct ifnet *));
#ifndef __APPLE__
int	if_simloop __P((struct ifnet *ifp, struct mbuf *m,
		struct sockaddr *dst, int hlen));
#endif

#endif /* KERNEL */


#endif /* __APPLE_API_UNSTABLE */
#endif /* !_NET_IF_VAR_H_ */
