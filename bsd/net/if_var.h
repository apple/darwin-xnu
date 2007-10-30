/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>		/* get TAILQ macros */
#ifdef KERNEL_PRIVATE
#include <kern/locks.h>
#endif /* KERNEL_PRIVATE */

#ifdef KERNEL
#include <net/kpi_interface.h>
#endif KERNEL

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
#define APPLE_IF_FAM_STF       12
#define APPLE_IF_FAM_FIREWIRE  13
#define APPLE_IF_FAM_BOND      14
#endif /* __APPLE__ */

/*
 * 72 was chosen below because it is the size of a TCP/IP
 * header (40) + the minimum mss (32).
 */
#define	IF_MINMTU	72
#define	IF_MAXMTU	65535

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

#define	IFNAMSIZ	16

/* This belongs up in socket.h or socketvar.h, depending on how far the
 *   event bubbles up.
 */

struct net_event_data {
	u_int32_t	if_family;
	u_int32_t	if_unit;
	char		if_name[IFNAMSIZ];
};

#if defined(__LP64__)
#define __need_struct_timeval32
#include <sys/_structs.h>
#define IF_DATA_TIMEVAL timeval32
#else
#define IF_DATA_TIMEVAL timeval
#endif

#pragma pack(4)

/*
 * Structure describing information about an interface
 * which may be of interest to management entities.
 */
struct if_data {
	/* generic interface information */
	u_char		ifi_type;	/* ethernet, tokenring, etc */
	u_char		ifi_typelen;	/* Length of frame type id */
	u_char		ifi_physical;	/* e.g., AUI, Thinnet, 10base-T, etc */
	u_char		ifi_addrlen;	/* media address length */
	u_char		ifi_hdrlen;	/* media header length */
	u_char		ifi_recvquota;	/* polling quota for receive intrs */
	u_char		ifi_xmitquota;	/* polling quota for xmit intrs */
	u_char		ifi_unused1;	/* for future use */
	u_int32_t	ifi_mtu;	/* maximum transmission unit */
	u_int32_t	ifi_metric;	/* routing metric (external only) */
	u_int32_t	ifi_baudrate;	/* linespeed */
	/* volatile statistics */
	u_int32_t	ifi_ipackets;	/* packets received on interface */
	u_int32_t	ifi_ierrors;	/* input errors on interface */
	u_int32_t	ifi_opackets;	/* packets sent on interface */
	u_int32_t	ifi_oerrors;	/* output errors on interface */
	u_int32_t	ifi_collisions;	/* collisions on csma interfaces */
	u_int32_t	ifi_ibytes;	/* total number of octets received */
	u_int32_t	ifi_obytes;	/* total number of octets sent */
	u_int32_t	ifi_imcasts;	/* packets received via multicast */
	u_int32_t	ifi_omcasts;	/* packets sent via multicast */
	u_int32_t	ifi_iqdrops;	/* dropped on input, this interface */
	u_int32_t	ifi_noproto;	/* destined for unsupported protocol */
	u_int32_t	ifi_recvtiming;	/* usec spent receiving when timing */
	u_int32_t	ifi_xmittiming;	/* usec spent xmitting when timing */
	struct IF_DATA_TIMEVAL ifi_lastchange;	/* time of last administrative change */
	u_int32_t	ifi_unused2;	/* used to be the default_proto */
	u_int32_t	ifi_hwassist;	/* HW offload capabilities */
	u_int32_t	ifi_reserved1;	/* for future use */
	u_int32_t	ifi_reserved2;	/* for future use */
};

/*
 * Structure describing information about an interface
 * which may be of interest to management entities.
 */
struct if_data64 {
	/* generic interface information */
	u_char		ifi_type;		/* ethernet, tokenring, etc */
	u_char		ifi_typelen;		/* Length of frame type id */
	u_char		ifi_physical;		/* e.g., AUI, Thinnet, 10base-T, etc */
	u_char		ifi_addrlen;		/* media address length */
	u_char		ifi_hdrlen;		/* media header length */
	u_char		ifi_recvquota;		/* polling quota for receive intrs */
	u_char		ifi_xmitquota;		/* polling quota for xmit intrs */
	u_char		ifi_unused1;		/* for future use */
	u_int32_t	ifi_mtu;		/* maximum transmission unit */
	u_int32_t	ifi_metric;		/* routing metric (external only) */
	u_int64_t	ifi_baudrate;		/* linespeed */
	/* volatile statistics */
	u_int64_t	ifi_ipackets;		/* packets received on interface */
	u_int64_t	ifi_ierrors;		/* input errors on interface */
	u_int64_t	ifi_opackets;		/* packets sent on interface */
	u_int64_t	ifi_oerrors;		/* output errors on interface */
	u_int64_t	ifi_collisions;		/* collisions on csma interfaces */
	u_int64_t	ifi_ibytes;		/* total number of octets received */
	u_int64_t	ifi_obytes;		/* total number of octets sent */
	u_int64_t	ifi_imcasts;		/* packets received via multicast */
	u_int64_t	ifi_omcasts;		/* packets sent via multicast */
	u_int64_t	ifi_iqdrops;		/* dropped on input, this interface */
	u_int64_t	ifi_noproto;		/* destined for unsupported protocol */
	u_int32_t	ifi_recvtiming;		/* usec spent receiving when timing */
	u_int32_t	ifi_xmittiming;		/* usec spent xmitting when timing */
	struct IF_DATA_TIMEVAL ifi_lastchange;	/* time of last administrative change */
};

#pragma pack()

#ifdef PRIVATE
/*
 * Internal storage of if_data. This is bound to change. Various places in the
 * stack will translate this data structure in to the externally visible
 * if_data structure above.
 */
struct if_data_internal {
	/* generic interface information */
	u_char		ifi_type;	/* ethernet, tokenring, etc */
	u_char		ifi_typelen;	/* Length of frame type id */
	u_char		ifi_physical;	/* e.g., AUI, Thinnet, 10base-T, etc */
	u_char		ifi_addrlen;	/* media address length */
	u_char		ifi_hdrlen;	/* media header length */
	u_char		ifi_recvquota;	/* polling quota for receive intrs */
	u_char		ifi_xmitquota;	/* polling quota for xmit intrs */
	u_char		ifi_unused1;	/* for future use */
	u_int32_t	ifi_mtu;	/* maximum transmission unit */
	u_int32_t	ifi_metric;	/* routing metric (external only) */
	u_int32_t	ifi_baudrate;	/* linespeed */
	/* volatile statistics */
	u_int64_t	ifi_ipackets;	/* packets received on interface */
	u_int64_t	ifi_ierrors;	/* input errors on interface */
	u_int64_t	ifi_opackets;	/* packets sent on interface */
	u_int64_t	ifi_oerrors;	/* output errors on interface */
	u_int64_t	ifi_collisions;	/* collisions on csma interfaces */
	u_int64_t	ifi_ibytes;	/* total number of octets received */
	u_int64_t	ifi_obytes;	/* total number of octets sent */
	u_int64_t	ifi_imcasts;	/* packets received via multicast */
	u_int64_t	ifi_omcasts;	/* packets sent via multicast */
	u_int64_t	ifi_iqdrops;	/* dropped on input, this interface */
	u_int64_t	ifi_noproto;	/* destined for unsupported protocol */
	u_int32_t	ifi_recvtiming;	/* usec spent receiving when timing */
	u_int32_t	ifi_xmittiming;	/* usec spent xmitting when timing */
#define IF_LASTCHANGEUPTIME	1	/* lastchange: 1-uptime 0-calendar time */
	struct	timeval ifi_lastchange;	/* time of last administrative change */
	u_int32_t	ifi_hwassist;	/* HW offload capabilities */
};

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
#define if_iflags	if_data.ifi_iflags

struct	mbuf;
struct ifaddr;
TAILQ_HEAD(ifnethead, ifnet);	/* we use TAILQs so that the order of */
TAILQ_HEAD(ifaddrhead, ifaddr);	/* instantiation is preserved in the list */
TAILQ_HEAD(ifprefixhead, ifprefix);
LIST_HEAD(ifmultihead, ifmultiaddr);
struct tqdummy;
TAILQ_HEAD(tailq_head, tqdummy);

/*
 * Forward structure declarations for function prototypes [sic].
 */
struct	proc;
struct	rtentry;
struct	socket;
struct	ether_header;
struct  sockaddr_dl;
struct ifnet_filter;

TAILQ_HEAD(ifnet_filter_head, ifnet_filter);
TAILQ_HEAD(ddesc_head_name, dlil_demux_desc);

/* bottom 16 bits reserved for hardware checksum */
#define IF_HWASSIST_CSUM_IP		0x0001	/* will csum IP */
#define IF_HWASSIST_CSUM_TCP		0x0002	/* will csum TCP */
#define IF_HWASSIST_CSUM_UDP		0x0004	/* will csum UDP */
#define IF_HWASSIST_CSUM_IP_FRAGS	0x0008	/* will csum IP fragments */
#define IF_HWASSIST_CSUM_FRAGMENT	0x0010  /* will do IP fragmentation */
#define IF_HWASSIST_CSUM_TCP_SUM16	0x1000	/* simple TCP Sum16 computation */
#define IF_HWASSIST_CSUM_MASK		0xffff
#define IF_HWASSIST_CSUM_FLAGS(hwassist)	((hwassist) & IF_HWASSIST_CSUM_MASK)

/* VLAN support */
#define IF_HWASSIST_VLAN_TAGGING	0x10000	/* supports VLAN tagging */
#define IF_HWASSIST_VLAN_MTU		0x20000 /* supports VLAN MTU-sized packet (for software VLAN) */

#define IFNET_RW_LOCK 1

#endif /* PRIVATE */
/*
 * Structure defining a queue for a network interface.
 */
struct	ifqueue {
	void *ifq_head;
	void *ifq_tail;
	int	ifq_len;
	int	ifq_maxlen;
	int	ifq_drops;
};

#ifdef PRIVATE

struct ddesc_head_str;
struct proto_hash_entry;
struct kev_msg;
struct dlil_threading_info;

/*
 * Structure defining a network interface.
 *
 * (Would like to call this struct ``if'', but C isn't PL/1.)
 */
struct ifnet {
	void	*if_softc;		/* pointer to driver state */
	const char	*if_name;		/* name, e.g. ``en'' or ``lo'' */
	TAILQ_ENTRY(ifnet) if_link; 	/* all struct ifnets are chained */
	struct	ifaddrhead if_addrhead;	/* linked list of addresses per if */
	u_long	if_refcnt;
#ifdef __KPI_INTERFACE__
	ifnet_check_multi	if_check_multi;
#else
	void*				if_check_multi;
#endif __KPI_INTERFACE__
	int	if_pcount;		/* number of promiscuous listeners */
	struct	bpf_if *if_bpf;		/* packet filter structure */
	u_short	if_index;		/* numeric abbreviation for this if  */
	short	if_unit;		/* sub-unit for lower level driver */
	short	if_timer;		/* time 'til if_watchdog called */
	short	if_flags;		/* up/down, broadcast, etc. */
	int	if_ipending;		/* interrupts pending */
	void	*if_linkmib;		/* link-type-specific MIB data */
	size_t	if_linkmiblen;		/* length of above data */
	struct	if_data_internal if_data;

/* New with DLIL */
#ifdef BSD_KERNEL_PRIVATE
	int	if_usecnt;
#else
	int	refcnt;
#endif
#ifdef __KPI_INTERFACE__
	ifnet_output_func	if_output;
	ifnet_ioctl_func	if_ioctl;
	ifnet_set_bpf_tap	if_set_bpf_tap;
	ifnet_detached_func	if_free;
	ifnet_demux_func	if_demux;
	ifnet_event_func	if_event;
	ifnet_framer_func	if_framer;
	ifnet_family_t		if_family;		/* ulong assigned by Apple */
#else
	void*				if_output;
	void*				if_ioctl;
	void*				if_set_bpf_tap;
	void*				if_free;
	void*				if_demux;
	void*				if_event;
	void*				if_framer;
	u_long				if_family;		/* ulong assigned by Apple */
#endif

	struct ifnet_filter_head if_flt_head;

/* End DLIL specific */

	u_long 	if_delayed_detach; /* need to perform delayed detach */
	void    *if_private;	/* private to interface */
	long	if_eflags;		/* autoaddr, autoaddr done, etc. */

	struct	ifmultihead if_multiaddrs; /* multicast addresses configured */
	int	if_amcount;		/* number of all-multicast requests */
/* procedure handles */
#ifdef __KPI_INTERFACE__
	ifnet_add_proto_func	if_add_proto;
	ifnet_del_proto_func	if_del_proto;
#else __KPI_INTERFACE__
	void*	if_add_proto;
	void*	if_del_proto;
#endif __KPI_INTERFACE__
	struct proto_hash_entry	*if_proto_hash;
	void					*if_kpi_storage;
#if 0	
	void	*unused_was_init;
#else
	struct dlil_threading_info *if_input_thread;
#endif
	void	*unused_was_resolvemulti;
	
	struct ifqueue	if_snd;
	u_long 	unused_2[1];
#ifdef __APPLE__
	u_long	family_cookie;
	struct	ifprefixhead if_prefixhead; /* list of prefixes per if */

#ifdef _KERN_LOCKS_H_
#if IFNET_RW_LOCK
	lck_rw_t *if_lock;		/* Lock to protect this interface */
#else
	lck_mtx_t *if_lock;		/* Lock to protect this interface */
#endif
#else
	void	*if_lock;
#endif

#else
	struct	ifprefixhead if_prefixhead; /* list of prefixes per if */
#endif /* __APPLE__ */
	struct {
		u_long	length;
		union {
			u_char	buffer[8];
			u_char	*ptr;
		} u;
	} if_broadcast;
#if CONFIG_MACF_NET
	struct  label *if_label;	/* interface MAC label */
#endif
};

#ifndef __APPLE__
/* for compatibility with other BSDs */
#define	if_addrlist	if_addrhead
#define	if_list		if_link
#endif !__APPLE__


#endif /* PRIVATE */

#ifdef KERNEL_PRIVATE
/*
 * Structure describing a `cloning' interface.
 */
struct if_clone {
	LIST_ENTRY(if_clone) ifc_list;	/* on list of cloners */
	const char *ifc_name;			/* name of device, e.g. `vlan' */
	size_t ifc_namelen;		/* length of name */
	int ifc_minifs;			/* minimum number of interfaces */
	int ifc_maxunit;		/* maximum unit number */
	unsigned char *ifc_units;	/* bitmap to handle units */
	int ifc_bmlen;			/* bitmap length */

	int	(*ifc_create)(struct if_clone *, int);
	void	(*ifc_destroy)(struct ifnet *);
};

#define IF_CLONE_INITIALIZER(name, create, destroy, minifs, maxunit)	\
    { { NULL, NULL }, name, sizeof(name) - 1, minifs, maxunit, NULL, 0, create, destroy }

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
		((struct mbuf*)(ifq)->ifq_tail)->m_nextpkt = m; \
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

#define	IF_ENQ_DROP(ifq, m)	if_enq_drop(ifq, m)

#if defined(__GNUC__) && defined(MT_HEADER)
static __inline int
if_queue_drop(struct ifqueue *ifq, __unused struct mbuf *m)
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
int	if_enq_drop(struct ifqueue *, struct mbuf *);
#endif MT_HEADER

#endif defined(__GNUC__) && defined(MT_HEADER)

#endif /* KERNEL_PRIVATE */


#ifdef PRIVATE
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
	struct	ifnet *ifa_ifp;		/* back-pointer to interface */
	TAILQ_ENTRY(ifaddr) ifa_link;	/* queue macro glue */
	void	(*ifa_rtrequest)	/* check or clean routes (+ or -)'d */
		(int, struct rtentry *, struct sockaddr *);
	u_short	ifa_flags;		/* mostly rt_flags for cloning */
	int	ifa_refcnt;/* 32bit ref count, use ifaref, ifafree */
	int	ifa_metric;		/* cost of going out this interface */
#ifdef notdef
	struct	rtentry *ifa_rt;	/* XXXX for ROUTETOIF ????? */
#endif
	int (*ifa_claim_addr)		/* check if an addr goes to this if */
		(struct ifaddr *, const struct sockaddr *);
	u_long	ifa_debug;		/* debug flags */
};
#define	IFA_ROUTE	RTF_UP		/* route installed (0x1) */
#define	IFA_CLONING	RTF_CLONING	/* (0x100) */
#define IFA_ATTACHED 	0x1		/* ifa_debug: IFA is attached to an interface */

#endif /* PRIVATE */

#ifdef KERNEL_PRIVATE
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
#endif /* KERNEL_PRIVATE */

#ifdef PRIVATE
typedef void (*ifma_protospec_free_func)(void* ifma_protospec);

/*
 * Multicast address structure.  This is analogous to the ifaddr
 * structure except that it keeps track of multicast addresses.
 * Also, the reference count here is a count of requests for this
 * address, not a count of pointers to this structure.
 */
struct ifmultiaddr {
	LIST_ENTRY(ifmultiaddr) ifma_link; /* queue macro glue */
	struct	sockaddr *ifma_addr; 	/* address this membership is for */
	struct ifmultiaddr *ifma_ll;	/* link-layer translation, if any */
	struct	ifnet *ifma_ifp;		/* back-pointer to interface */
	u_int	ifma_usecount;			/* use count, protected by ifp's lock */
	void	*ifma_protospec;		/* protocol-specific state, if any */
	int32_t	ifma_refcount;			/* reference count, atomically protected */
	ifma_protospec_free_func ifma_free;	/* function called to free ifma_protospec */
};
#endif /* PRIVATE */

#ifdef KERNEL_PRIVATE
#define IFAREF(ifa) ifaref(ifa)
#define IFAFREE(ifa) ifafree(ifa)

/*
 * To preserve kmem compatibility, we define
 * ifnet_head to ifnet. This should be temp.
 */
#define ifnet_head ifnet
extern	struct ifnethead ifnet_head;
extern struct	ifnet	**ifindex2ifnet;
extern	int ifqmaxlen;
extern	ifnet_t  lo_ifp;
extern	int if_index;
extern	struct ifaddr **ifnet_addrs;

int	if_addmulti(struct ifnet *, const struct sockaddr *, struct ifmultiaddr **);
int	if_allmulti(struct ifnet *, int);
void	if_attach(struct ifnet *);
int	if_delmultiaddr(struct ifmultiaddr *ifma, int locked);
int	if_delmulti(struct ifnet *, const struct sockaddr *);
void	if_down(struct ifnet *);
int 	if_down_all(void);
void	if_route(struct ifnet *, int flag, int fam);
void	if_unroute(struct ifnet *, int flag, int fam);
void	if_up(struct ifnet *);
void	if_updown(struct ifnet *ifp, int up);
/*void	ifinit(void));*/ /* declared in systm.h for main( */
int	ifioctl(struct socket *, u_long, caddr_t, struct proc *);
int	ifioctllocked(struct socket *, u_long, caddr_t, struct proc *);
struct	ifnet *ifunit(const char *);
struct  ifnet *if_withname(struct sockaddr *);

void	if_clone_attach(struct if_clone *);
void	if_clone_detach(struct if_clone *);

void	ifnet_lock_assert(struct ifnet *ifp, int what);
void	ifnet_lock_shared(struct ifnet *ifp);
void	ifnet_lock_exclusive(struct ifnet *ifp);
void	ifnet_lock_done(struct ifnet *ifp);

void	ifnet_head_lock_shared(void);
void	ifnet_head_lock_exclusive(void);
void	ifnet_head_done(void);

void	if_attach_ifa(struct ifnet * ifp, struct ifaddr *ifa);
void	if_detach_ifa(struct ifnet * ifp, struct ifaddr *ifa);

void	ifma_reference(struct ifmultiaddr *ifma);
void	ifma_release(struct ifmultiaddr *ifma);

struct	ifaddr *ifa_ifwithaddr(const struct sockaddr *);
struct	ifaddr *ifa_ifwithdstaddr(const struct sockaddr *);
struct	ifaddr *ifa_ifwithnet(const struct sockaddr *);
struct	ifaddr *ifa_ifwithroute(int, const struct sockaddr *, const struct sockaddr *);
struct	ifaddr *ifa_ifwithroute_locked(int, const struct sockaddr *, const struct sockaddr *);
struct	ifaddr *ifaof_ifpforaddr(const struct sockaddr *, struct ifnet *);
struct	ifaddr *ifa_ifpgetprimary(struct ifnet *, int);
void	ifafree(struct ifaddr *);
void	ifaref(struct ifaddr *);

struct	ifmultiaddr *ifmaof_ifpforaddr(const struct sockaddr *, struct ifnet *);

int	ifa_foraddr(unsigned int addr);

#ifdef BSD_KERNEL_PRIVATE
enum {
	kIfNetUseCount_MayBeZero = 0,
	kIfNetUseCount_MustNotBeZero = 1
};

int ifp_use(struct ifnet *ifp, int handle_zero);
int ifp_unuse(struct ifnet *ifp);
void ifp_use_reached_zero(struct ifnet *ifp);

void	if_data_internal_to_if_data(struct ifnet *ifp, const struct if_data_internal *if_data_int,
			   struct if_data *if_data);
void	if_data_internal_to_if_data64(struct ifnet *ifp, const struct if_data_internal *if_data_int,
							   struct if_data64 *if_data64);
#endif /* BSD_KERNEL_PRIVATE */
#endif /* KERNEL_PRIVATE */
#endif /* !_NET_IF_VAR_H_ */
