/*
 * Copyright (c) 2004-2012 Apple Inc. All rights reserved.
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

/*	$NetBSD: if_bridge.c,v 1.31 2005/06/01 19:45:34 jdc Exp $	*/
/*
 * Copyright 2001 Wasabi Systems, Inc.
 * All rights reserved.
 *
 * Written by Jason R. Thorpe for Wasabi Systems, Inc.
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
 *	This product includes software developed for the NetBSD Project by
 *	Wasabi Systems, Inc.
 * 4. The name of Wasabi Systems, Inc. may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY WASABI SYSTEMS, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL WASABI SYSTEMS, INC
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 1999, 2000 Jason L. Wright (jason@thought.net)
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * OpenBSD: if_bridge.c,v 1.60 2001/06/15 03:38:33 itojun Exp
 */

/*
 * Network interface bridge support.
 *
 * TODO:
 *
 *	- Currently only supports Ethernet-like interfaces (Ethernet,
 *	  802.11, VLANs on Ethernet, etc.)  Figure out a nice way
 *	  to bridge other types of interfaces (FDDI-FDDI, and maybe
 *	  consider heterogenous bridges).
 */

#include <sys/cdefs.h>

#define BRIDGE_DEBUG 1
#ifndef BRIDGE_DEBUG
#define BRIDGE_DEBUG 0
#endif /* BRIDGE_DEBUG */

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/protosw.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/socket.h> /* for net/if.h */
#include <sys/sockio.h>
#include <sys/kernel.h>
#include <sys/random.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/mcache.h>

#include <sys/kauth.h>

#include <libkern/libkern.h>

#include <kern/zalloc.h>

#if NBPFILTER > 0
#include <net/bpf.h>
#endif
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_var.h>

#include <netinet/in.h> /* for struct arpcom */
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif
#ifdef DEV_CARP
#include <netinet/ip_carp.h>
#endif
#include <netinet/if_ether.h> /* for struct arpcom */
#include <net/bridgestp.h>
#include <net/if_bridgevar.h>
#include <net/if_llc.h>
#if NVLAN > 0
#include <net/if_vlan_var.h>
#endif /* NVLAN > 0 */

#include <net/if_ether.h>
#include <net/dlil.h>
#include <net/kpi_interfacefilter.h>

#include <net/route.h>
#ifdef PFIL_HOOKS
#include <netinet/ip_fw2.h>
#include <netinet/ip_dummynet.h>
#endif /* PFIL_HOOKS */

#if BRIDGE_DEBUG

#define BR_LCKDBG_MAX			4

#define BRIDGE_LOCK(_sc)		bridge_lock(_sc)
#define BRIDGE_UNLOCK(_sc)		bridge_unlock(_sc)
#define BRIDGE_LOCK_ASSERT(_sc)		\
	lck_mtx_assert((_sc)->sc_mtx, LCK_MTX_ASSERT_OWNED)
#define	BRIDGE_LOCK2REF(_sc, _err)	_err = bridge_lock2ref(_sc)
#define	BRIDGE_UNREF(_sc)		bridge_unref(_sc)
#define	BRIDGE_XLOCK(_sc)		bridge_xlock(_sc)
#define	BRIDGE_XDROP(_sc)		bridge_xdrop(_sc)

#else /* BRIDGE_DEBUG */

#define BRIDGE_LOCK(_sc)		lck_mtx_lock((_sc)->sc_mtx)
#define BRIDGE_UNLOCK(_sc)		lck_mtx_unlock((_sc)->sc_mtx)
#define BRIDGE_LOCK_ASSERT(_sc)		\
	lck_mtx_assert((_sc)->sc_mtx, LCK_MTX_ASSERT_OWNED)
#define	BRIDGE_LOCK2REF(_sc, _err)	do {				\
	lck_mtx_assert((_sc)->sc_mtx, LCK_MTX_ASSERT_OWNED);		\
	if ((_sc)->sc_iflist_xcnt > 0)					\
		(_err) = EBUSY;						\
	else								\
		(_sc)->sc_iflist_ref++;					\
	lck_mtx_unlock((_sc)->sc_mtx);					\
} while (0)
#define	BRIDGE_UNREF(_sc)		do {				\
	lck_mtx_lock((_sc)->sc_mtx);					\
	(_sc)->sc_iflist_ref--;						\
	if (((_sc)->sc_iflist_xcnt > 0) && ((_sc)->sc_iflist_ref == 0))	{ \
		lck_mtx_unlock((_sc)->sc_mtx);				\
		wakeup(&(_sc)->sc_cv);					\
	} else								\
		lck_mtx_unlock((_sc)->sc_mtx);				\
} while (0)
#define	BRIDGE_XLOCK(_sc)		do {				\
	lck_mtx_assert((_sc)->sc_mtx, LCK_MTX_ASSERT_OWNED);		\
	(_sc)->sc_iflist_xcnt++;					\
	while ((_sc)->sc_iflist_ref > 0)				\
		msleep(&(_sc)->sc_cv, (_sc)->sc_mtx, PZERO,		\
		    "BRIDGE_XLOCK", NULL);				\
} while (0)
#define	BRIDGE_XDROP(_sc)		do {				\
	lck_mtx_assert((_sc)->sc_mtx, LCK_MTX_ASSERT_OWNED);		\
	(_sc)->sc_iflist_xcnt--;					\
} while (0)

#endif /* BRIDGE_DEBUG */

#if NBPFILTER > 0
#define BRIDGE_BPF_MTAP_INPUT(sc, m)					\
	if (sc->sc_bpf_input)						\
		bridge_bpf_input(sc->sc_ifp, m)
#else /* NBPFILTER */
#define BRIDGE_BPF_MTAP_INPUT(ifp, m)
#endif /* NBPFILTER */

/*
 * Size of the route hash table.  Must be a power of two.
 */
/* APPLE MODIFICATION - per Wasabi performance improvement, change the hash table size */
#if 0
#ifndef BRIDGE_RTHASH_SIZE
#define	BRIDGE_RTHASH_SIZE		1024
#endif
#else
#ifndef BRIDGE_RTHASH_SIZE
#define	BRIDGE_RTHASH_SIZE		256
#endif
#endif

/* APPLE MODIFICATION - support for HW checksums */
#if APPLE_BRIDGE_HWCKSUM_SUPPORT
#include <netinet/udp.h>
#include <netinet/tcp.h>
#endif

#define	BRIDGE_RTHASH_MASK		(BRIDGE_RTHASH_SIZE - 1)

/*
 * Maximum number of addresses to cache.
 */
#ifndef BRIDGE_RTABLE_MAX
#define	BRIDGE_RTABLE_MAX		100
#endif


/*
 * Timeout (in seconds) for entries learned dynamically.
 */
#ifndef BRIDGE_RTABLE_TIMEOUT
#define	BRIDGE_RTABLE_TIMEOUT		(20 * 60)	/* same as ARP */
#endif

/*
 * Number of seconds between walks of the route list.
 */
#ifndef BRIDGE_RTABLE_PRUNE_PERIOD
#define	BRIDGE_RTABLE_PRUNE_PERIOD	(5 * 60)
#endif

/*
 * List of capabilities to possibly mask on the member interface.
 */
#define	BRIDGE_IFCAPS_MASK		(IFCAP_TOE|IFCAP_TSO|IFCAP_TXCSUM)
/*
 * List of capabilities to disable on the member interface.
 */
#define	BRIDGE_IFCAPS_STRIP		IFCAP_LRO

/*
 * Bridge interface list entry.
 */
struct bridge_iflist {
	TAILQ_ENTRY(bridge_iflist) bif_next;
	struct ifnet		*bif_ifp;	/* member if */
	struct bstp_port	bif_stp;	/* STP state */
	uint32_t		bif_flags;	/* member if flags */
	int			bif_savedcaps;	/* saved capabilities */
	uint32_t		bif_addrmax;	/* max # of addresses */
	uint32_t		bif_addrcnt;	/* cur. # of addresses */
	uint32_t		bif_addrexceeded;/* # of address violations */

	interface_filter_t	bif_iff_ref;
	struct bridge_softc	*bif_sc;
	char		bif_promisc;		/* promiscuous mode set */
	char		bif_proto_attached;	/* protocol attached */
	char		bif_filter_attached;	/* interface filter attached */
};

/*
 * Bridge route node.
 */
struct bridge_rtnode {
	LIST_ENTRY(bridge_rtnode) brt_hash;	/* hash table linkage */
	LIST_ENTRY(bridge_rtnode) brt_list;	/* list linkage */
	struct bridge_iflist	*brt_dst;	/* destination if */
	unsigned long		brt_expire;	/* expiration time */
	uint8_t			brt_flags;	/* address flags */
	uint8_t			brt_addr[ETHER_ADDR_LEN];
	uint16_t		brt_vlan;	/* vlan id */

};
#define	brt_ifp			brt_dst->bif_ifp

/*
 * Software state for each bridge.
 */
struct bridge_softc {
	struct ifnet		*sc_ifp;	/* make this an interface */
	LIST_ENTRY(bridge_softc) sc_list;
	lck_mtx_t		*sc_mtx;
	void			*sc_cv;
	uint32_t		sc_brtmax;	/* max # of addresses */
	uint32_t		sc_brtcnt;	/* cur. # of addresses */
	uint32_t		sc_brttimeout;	/* rt timeout in seconds */
	uint32_t		sc_iflist_ref;	/* refcount for sc_iflist */
	uint32_t		sc_iflist_xcnt;	/* refcount for sc_iflist */
	TAILQ_HEAD(, bridge_iflist) sc_iflist;	/* member interface list */
	LIST_HEAD(, bridge_rtnode) *sc_rthash;	/* our forwarding table */
	LIST_HEAD(, bridge_rtnode) sc_rtlist;	/* list version of above */
	uint32_t		sc_rthash_key;	/* key for hash */
	TAILQ_HEAD(, bridge_iflist) sc_spanlist;	/* span ports list */
	struct bstp_state	sc_stp;		/* STP state */
	uint32_t		sc_brtexceeded;	/* # of cache drops */
	uint32_t		sc_filter_flags; /* ipf and flags */

	char			sc_if_xname[IFNAMSIZ];
	bpf_packet_func		sc_bpf_input;
	bpf_packet_func		sc_bpf_output;
	u_int32_t		sc_flags;

#if BRIDGE_DEBUG
	void			*lock_lr[BR_LCKDBG_MAX];        /* locking calling history */
	int			next_lock_lr;
	void			*unlock_lr[BR_LCKDBG_MAX];      /* unlocking caller history */
	int			next_unlock_lr;
#endif /* BRIDGE_DEBUG */
};

#define SCF_DETACHING 0x1

decl_lck_mtx_data(static, bridge_list_mtx_data);
static lck_mtx_t	*bridge_list_mtx = &bridge_list_mtx_data;

int	bridge_rtable_prune_period = BRIDGE_RTABLE_PRUNE_PERIOD;

static zone_t bridge_rtnode_pool = NULL;

static int	bridge_clone_create(struct if_clone *, uint32_t, void *);
static int	bridge_clone_destroy(struct ifnet *);

static errno_t	bridge_ioctl(struct ifnet *, u_long, void *);
#if HAS_IF_CAP
static void	bridge_mutecaps(struct bridge_softc *);
static void	bridge_set_ifcap(struct bridge_softc *, struct bridge_iflist *,
		    int);
#endif
__private_extern__ void	bridge_ifdetach(struct bridge_iflist *, struct ifnet *);
static int	bridge_init(struct ifnet *);
#if HAS_BRIDGE_DUMMYNET
static void	bridge_dummynet(struct mbuf *, struct ifnet *);
#endif
static void	bridge_ifstop(struct ifnet *, int);
static int	bridge_output(struct ifnet *, struct mbuf *);
static void	bridge_start(struct ifnet *);
__private_extern__ errno_t bridge_input(struct ifnet *, struct mbuf *, void *);
#if BRIDGE_MEMBER_OUT_FILTER
static errno_t bridge_iff_output(void *, ifnet_t, protocol_family_t ,
    mbuf_t *);
static int	bridge_member_output(struct ifnet *, struct mbuf *,
		    struct sockaddr *, struct rtentry *);
#endif
static int	bridge_enqueue(struct bridge_softc *, struct ifnet *,
		    struct mbuf *);
static void	bridge_rtdelete(struct bridge_softc *, struct ifnet *ifp, int);

static void	bridge_forward(struct bridge_softc *, struct bridge_iflist *,
		    struct mbuf *m);

static void	bridge_timer(void *);

static void	bridge_broadcast(struct bridge_softc *, struct ifnet *,
		    struct mbuf *, int);
static void	bridge_span(struct bridge_softc *, struct mbuf *);

static int	bridge_rtupdate(struct bridge_softc *, const uint8_t *,
		    uint16_t, struct bridge_iflist *, int, uint8_t);
static struct ifnet *bridge_rtlookup(struct bridge_softc *, const uint8_t *,
		    uint16_t);
static void	bridge_rttrim(struct bridge_softc *);
static void	bridge_rtage(struct bridge_softc *);
static void	bridge_rtflush(struct bridge_softc *, int);
static int	bridge_rtdaddr(struct bridge_softc *, const uint8_t *,
		    uint16_t);

static int	bridge_rtable_init(struct bridge_softc *);
static void	bridge_rtable_fini(struct bridge_softc *);

static int	bridge_rtnode_addr_cmp(const uint8_t *, const uint8_t *);
static struct bridge_rtnode *bridge_rtnode_lookup(struct bridge_softc *,
		    const uint8_t *, uint16_t);
static int	bridge_rtnode_insert(struct bridge_softc *,
		    struct bridge_rtnode *);
static void	bridge_rtnode_destroy(struct bridge_softc *,
		    struct bridge_rtnode *);
#if BRIDGESTP
static void	bridge_rtable_expire(struct ifnet *, int);
static void	bridge_state_change(struct ifnet *, int);
#endif /* BRIDGESTP */

static struct bridge_iflist *bridge_lookup_member(struct bridge_softc *,
		    const char *name);
static struct bridge_iflist *bridge_lookup_member_if(struct bridge_softc *,
		    struct ifnet *ifp);
static void	bridge_delete_member(struct bridge_softc *,
		    struct bridge_iflist *, int);
static void	bridge_delete_span(struct bridge_softc *,
		    struct bridge_iflist *);

static int	bridge_ioctl_add(struct bridge_softc *, void *);
static int	bridge_ioctl_del(struct bridge_softc *, void *);
static int	bridge_ioctl_gifflags(struct bridge_softc *, void *);
static int	bridge_ioctl_sifflags(struct bridge_softc *, void *);
static int	bridge_ioctl_scache(struct bridge_softc *, void *);
static int	bridge_ioctl_gcache(struct bridge_softc *, void *);
static int	bridge_ioctl_gifs32(struct bridge_softc *, void *);
static int	bridge_ioctl_gifs64(struct bridge_softc *, void *);
static int	bridge_ioctl_rts32(struct bridge_softc *, void *);
static int	bridge_ioctl_rts64(struct bridge_softc *, void *);
static int	bridge_ioctl_saddr32(struct bridge_softc *, void *);
static int	bridge_ioctl_saddr64(struct bridge_softc *, void *);
static int	bridge_ioctl_sto(struct bridge_softc *, void *);
static int	bridge_ioctl_gto(struct bridge_softc *, void *);
static int	bridge_ioctl_daddr32(struct bridge_softc *, void *);
static int	bridge_ioctl_daddr64(struct bridge_softc *, void *);
static int	bridge_ioctl_flush(struct bridge_softc *, void *);
static int	bridge_ioctl_gpri(struct bridge_softc *, void *);
static int	bridge_ioctl_spri(struct bridge_softc *, void *);
static int	bridge_ioctl_ght(struct bridge_softc *, void *);
static int	bridge_ioctl_sht(struct bridge_softc *, void *);
static int	bridge_ioctl_gfd(struct bridge_softc *, void *);
static int	bridge_ioctl_sfd(struct bridge_softc *, void *);
static int	bridge_ioctl_gma(struct bridge_softc *, void *);
static int	bridge_ioctl_sma(struct bridge_softc *, void *);
static int	bridge_ioctl_sifprio(struct bridge_softc *, void *);
static int	bridge_ioctl_sifcost(struct bridge_softc *, void *);
static int	bridge_ioctl_sifmaxaddr(struct bridge_softc *, void *);
static int	bridge_ioctl_addspan(struct bridge_softc *, void *);
static int	bridge_ioctl_delspan(struct bridge_softc *, void *);
static int	bridge_ioctl_gbparam32(struct bridge_softc *, void *);
static int	bridge_ioctl_gbparam64(struct bridge_softc *, void *);
static int	bridge_ioctl_grte(struct bridge_softc *, void *);
static int	bridge_ioctl_gifsstp32(struct bridge_softc *, void *);
static int	bridge_ioctl_gifsstp64(struct bridge_softc *, void *);
static int	bridge_ioctl_sproto(struct bridge_softc *, void *);
static int	bridge_ioctl_stxhc(struct bridge_softc *, void *);
static int  bridge_ioctl_purge(struct bridge_softc *sc, void *arg);
static int	bridge_ioctl_gfilt(struct bridge_softc *, void *);
static int	bridge_ioctl_sfilt(struct bridge_softc *, void *);
#ifdef PFIL_HOOKS
static int	bridge_pfil(struct mbuf **, struct ifnet *, struct ifnet *,
		    int);
static int	bridge_ip_checkbasic(struct mbuf **mp);
#ifdef INET6
static int	bridge_ip6_checkbasic(struct mbuf **mp);
#endif /* INET6 */
static int	bridge_fragment(struct ifnet *, struct mbuf *,
		    struct ether_header *, int, struct llc *);
#endif /* PFIL_HOOKS */

static errno_t bridge_set_bpf_tap(ifnet_t ifn, bpf_tap_mode mode, bpf_packet_func bpf_callback);
__private_extern__ errno_t bridge_bpf_input(ifnet_t ifp, struct mbuf *m);
__private_extern__ errno_t bridge_bpf_output(ifnet_t ifp, struct mbuf *m);

static void bridge_detach(ifnet_t ifp);

#define m_copypacket(m, how) m_copym(m, 0, M_COPYALL, how)

/* The default bridge vlan is 1 (IEEE 802.1Q-2003 Table 9-2) */
#define	VLANTAGOF(_m)	0

u_int8_t bstp_etheraddr[ETHER_ADDR_LEN] =
    { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x00 };

#if BRIDGESTP
static struct bstp_cb_ops bridge_ops = {
	.bcb_state = bridge_state_change,
	.bcb_rtage = bridge_rtable_expire
};
#endif /* BRIDGESTP */

SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, IFT_BRIDGE, bridge, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
    "Bridge");

#if defined(PFIL_HOOKS)
static int pfil_onlyip = 1; /* only pass IP[46] packets when pfil is enabled */
static int pfil_bridge = 1; /* run pfil hooks on the bridge interface */
static int pfil_member = 1; /* run pfil hooks on the member interface */
static int pfil_ipfw = 0;   /* layer2 filter with ipfw */
static int pfil_ipfw_arp = 0;   /* layer2 filter with ipfw */
static int pfil_local_phys = 0; /* run pfil hooks on the physical interface for
                                   locally destined packets */
SYSCTL_INT(_net_link_bridge, OID_AUTO, pfil_onlyip, CTLFLAG_RW|CTLFLAG_LOCKED,
    &pfil_onlyip, 0, "Only pass IP packets when pfil is enabled");
SYSCTL_INT(_net_link_bridge, OID_AUTO, ipfw_arp, CTLFLAG_RW|CTLFLAG_LOCKED,
    &pfil_ipfw_arp, 0, "Filter ARP packets through IPFW layer2");
SYSCTL_INT(_net_link_bridge, OID_AUTO, pfil_bridge, CTLFLAG_RW|CTLFLAG_LOCKED,
    &pfil_bridge, 0, "Packet filter on the bridge interface");
SYSCTL_INT(_net_link_bridge, OID_AUTO, pfil_member, CTLFLAG_RW|CTLFLAG_LOCKED,
    &pfil_member, 0, "Packet filter on the member interface");
SYSCTL_INT(_net_link_bridge, OID_AUTO, pfil_local_phys,
    CTLFLAG_RW|CTLFLAG_LOCKED, &pfil_local_phys, 0,
    "Packet filter on the physical interface for locally destined packets");
#endif /* PFIL_HOOKS */

#if BRIDGESTP
static int log_stp   = 0;   /* log STP state changes */
SYSCTL_INT(_net_link_bridge, OID_AUTO, log_stp, CTLFLAG_RW,
    &log_stp, 0, "Log STP state changes");
#endif /* BRIDGESTP */

struct bridge_control {
	int		(*bc_func)(struct bridge_softc *, void *);
	unsigned int	bc_argsize;
	unsigned int	bc_flags;
};

#define	BC_F_COPYIN		0x01	/* copy arguments in */
#define	BC_F_COPYOUT		0x02	/* copy arguments out */
#define	BC_F_SUSER		0x04	/* do super-user check */

static const struct bridge_control bridge_control_table32[] = {
	{ bridge_ioctl_add,		sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_del,		sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gifflags,	sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_COPYOUT },
	{ bridge_ioctl_sifflags,	sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_scache,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_gcache,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },

	{ bridge_ioctl_gifs32,		sizeof (struct ifbifconf32),
	    BC_F_COPYIN|BC_F_COPYOUT },
	{ bridge_ioctl_rts32,		sizeof (struct ifbaconf32),
	    BC_F_COPYIN|BC_F_COPYOUT },

	{ bridge_ioctl_saddr32,		sizeof (struct ifbareq32),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_sto,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_gto,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },

	{ bridge_ioctl_daddr32,		sizeof (struct ifbareq32),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_flush,		sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gpri,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },
	{ bridge_ioctl_spri,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_ght,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },
	{ bridge_ioctl_sht,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gfd,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },
	{ bridge_ioctl_sfd,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gma,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },
	{ bridge_ioctl_sma,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_sifprio,		sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_sifcost,		sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gfilt,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },
	{ bridge_ioctl_sfilt,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_purge,		sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_addspan,		sizeof (struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_delspan,		sizeof (struct ifbreq),
		BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gbparam32,	sizeof (struct ifbropreq32),
	    BC_F_COPYOUT },

	{ bridge_ioctl_grte,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },

	{ bridge_ioctl_gifsstp32,	sizeof (struct ifbpstpconf32),
	    BC_F_COPYIN|BC_F_COPYOUT },

	{ bridge_ioctl_sproto,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_stxhc,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_sifmaxaddr,	sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },
};

static const struct bridge_control bridge_control_table64[] = {
	{ bridge_ioctl_add,		sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_del,		sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gifflags,	sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_COPYOUT },
	{ bridge_ioctl_sifflags,	sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_scache,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_gcache,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },

	{ bridge_ioctl_gifs64,		sizeof (struct ifbifconf64),
	    BC_F_COPYIN|BC_F_COPYOUT },
	{ bridge_ioctl_rts64,		sizeof (struct ifbaconf64),
	    BC_F_COPYIN|BC_F_COPYOUT },

	{ bridge_ioctl_saddr64,		sizeof (struct ifbareq64),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_sto,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_gto,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },

	{ bridge_ioctl_daddr64,		sizeof (struct ifbareq64),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_flush,		sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gpri,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },
	{ bridge_ioctl_spri,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_ght,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },
	{ bridge_ioctl_sht,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gfd,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },
	{ bridge_ioctl_sfd,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gma,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },
	{ bridge_ioctl_sma,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_sifprio,		sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_sifcost,		sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gfilt,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },
	{ bridge_ioctl_sfilt,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_purge,	sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_addspan,		sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },
	{ bridge_ioctl_delspan,		sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_gbparam64,	sizeof (struct ifbropreq64),
	    BC_F_COPYOUT },

	{ bridge_ioctl_grte,		sizeof (struct ifbrparam),
	    BC_F_COPYOUT },

	{ bridge_ioctl_gifsstp64,	sizeof (struct ifbpstpconf64),
	    BC_F_COPYIN|BC_F_COPYOUT },

	{ bridge_ioctl_sproto,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_stxhc,		sizeof (struct ifbrparam),
	    BC_F_COPYIN|BC_F_SUSER },

	{ bridge_ioctl_sifmaxaddr,	sizeof (struct ifbreq),
	    BC_F_COPYIN|BC_F_SUSER },
};

static const unsigned int bridge_control_table_size =
    sizeof (bridge_control_table32) / sizeof (bridge_control_table32[0]);

static LIST_HEAD(, bridge_softc) bridge_list =
    LIST_HEAD_INITIALIZER(bridge_list);

static lck_grp_t *bridge_lock_grp = NULL;
static lck_attr_t *bridge_lock_attr = NULL;

static if_clone_t bridge_cloner = NULL;

static int if_bridge_txstart = 0;
SYSCTL_INT(_net_link_bridge, OID_AUTO, txstart, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_bridge_txstart, 0, "Bridge interface uses TXSTART model");

#if BRIDGE_DEBUG
static int if_bridge_debug = 0;
SYSCTL_INT(_net_link_bridge, OID_AUTO, debug, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_bridge_debug, 0, "Bridge debug");

static void printf_ether_header(struct ether_header *eh);
static void printf_mbuf_data(mbuf_t m, size_t offset, size_t len);
static void printf_mbuf_pkthdr(mbuf_t m, const char *prefix, const char *suffix);
static void printf_mbuf(mbuf_t m, const char *prefix, const char *suffix);
static void link_print(struct sockaddr_dl *dl_p);

static void bridge_lock(struct bridge_softc *);
static void bridge_unlock(struct bridge_softc *);
static int bridge_lock2ref(struct bridge_softc *);
static void bridge_unref(struct bridge_softc *);
static void bridge_xlock(struct bridge_softc *);
static void bridge_xdrop(struct bridge_softc *);

static void
bridge_lock(struct bridge_softc *sc)
{
	void *lr_saved = __builtin_return_address(0);

	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_NOTOWNED);

	lck_mtx_lock(sc->sc_mtx);

	sc->lock_lr[sc->next_lock_lr] = lr_saved;
	sc->next_lock_lr = (sc->next_lock_lr+1) % SO_LCKDBG_MAX;
}

static void
bridge_unlock(struct bridge_softc *sc)
{
	void *lr_saved = __builtin_return_address(0);

	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_OWNED);

	sc->unlock_lr[sc->next_unlock_lr] = lr_saved;
	sc->next_unlock_lr = (sc->next_unlock_lr+1) % SO_LCKDBG_MAX;

	lck_mtx_unlock(sc->sc_mtx);
}

static int
bridge_lock2ref(struct bridge_softc *sc)
{
	int error = 0;
	void *lr_saved = __builtin_return_address(0);

	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_OWNED);

	if (sc->sc_iflist_xcnt > 0)
		error = EBUSY;
	else
		sc->sc_iflist_ref++;

	sc->unlock_lr[sc->next_unlock_lr] = lr_saved;
	sc->next_unlock_lr = (sc->next_unlock_lr+1) % SO_LCKDBG_MAX;
	lck_mtx_unlock(sc->sc_mtx);

	return (error);
}

static void
bridge_unref(struct bridge_softc *sc)
{
	void *lr_saved = __builtin_return_address(0);

	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_NOTOWNED);

	lck_mtx_lock(sc->sc_mtx);
	sc->lock_lr[sc->next_lock_lr] = lr_saved;
	sc->next_lock_lr = (sc->next_lock_lr+1) % SO_LCKDBG_MAX;

	sc->sc_iflist_ref--;

	sc->unlock_lr[sc->next_unlock_lr] = lr_saved;
	sc->next_unlock_lr = (sc->next_unlock_lr+1) % SO_LCKDBG_MAX;
	if ((sc->sc_iflist_xcnt > 0) && (sc->sc_iflist_ref == 0)) {
		lck_mtx_unlock(sc->sc_mtx);
		wakeup(&sc->sc_cv);
	} else
		lck_mtx_unlock(sc->sc_mtx);
}

static void
bridge_xlock(struct bridge_softc *sc)
{
	void *lr_saved = __builtin_return_address(0);

	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_OWNED);

	sc->sc_iflist_xcnt++;
	while (sc->sc_iflist_ref > 0) {
		sc->unlock_lr[sc->next_unlock_lr] = lr_saved;
		sc->next_unlock_lr = (sc->next_unlock_lr+1) % SO_LCKDBG_MAX;

		msleep(&sc->sc_cv, sc->sc_mtx, PZERO, "BRIDGE_XLOCK", NULL);

		sc->lock_lr[sc->next_lock_lr] = lr_saved;
		sc->next_lock_lr = (sc->next_lock_lr+1) % SO_LCKDBG_MAX;
	}
}

static void
bridge_xdrop(struct bridge_softc *sc)
{
	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_OWNED);

	sc->sc_iflist_xcnt--;
}

void
printf_mbuf_pkthdr(mbuf_t m, const char *prefix, const char *suffix)
{
	if (m)
		printf("%spktlen: %u rcvif: %p header: %p nextpkt: %p%s",
		    prefix ? prefix : "", (unsigned int)mbuf_pkthdr_len(m),
		    mbuf_pkthdr_rcvif(m), mbuf_pkthdr_header(m),
		    mbuf_nextpkt(m), suffix ? suffix : "");
	else
		printf("%s<NULL>%s\n", prefix, suffix);
}

void
printf_mbuf(mbuf_t m, const char *prefix, const char *suffix)
{
	if (m) {
		printf("%s%p type: %u flags: 0x%x len: %u data: %p maxlen: %u "
		    "datastart: %p next: %p%s", prefix ? prefix : "",
		    m, mbuf_type(m), mbuf_flags(m), (unsigned int)mbuf_len(m),
		    mbuf_data(m), (unsigned int)mbuf_maxlen(m),
		    mbuf_datastart(m), mbuf_next(m),
		    !suffix || (mbuf_flags(m) & MBUF_PKTHDR) ? "" : suffix);
		if ((mbuf_flags(m) & MBUF_PKTHDR))
			printf_mbuf_pkthdr(m, " ", suffix);
	} else
		printf("%s<NULL>%s\n", prefix, suffix);
}

void
printf_mbuf_data(mbuf_t m, size_t offset, size_t len)
{
	mbuf_t			n;
	size_t			i, j;
	size_t			pktlen, mlen, maxlen;
	unsigned char	*ptr;

	pktlen = mbuf_pkthdr_len(m);

	if (offset > pktlen)
		return;

	maxlen = (pktlen - offset > len) ? len : pktlen;
	n = m;
	mlen = mbuf_len(n);
	ptr = mbuf_data(n);
	for (i = 0, j = 0; i < maxlen; i++, j++) {
		if (j >= mlen) {
			n = mbuf_next(n);
			if (n == 0)
				break;
			ptr = mbuf_data(n);
			mlen = mbuf_len(n);
			j = 0;
		}
		if (i >= offset) {
			printf("%02x%s", ptr[j], i % 2 ? " " : "");
		}
	}
}

static void
printf_ether_header(struct ether_header *eh)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x > "
	    "%02x:%02x:%02x:%02x:%02x:%02x 0x%04x ",
	    eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2],
	    eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5],
	    eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
	    eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5],
	    eh->ether_type);
}

static void
link_print(struct sockaddr_dl *dl_p)
{
	int i;

#if 1
	printf("sdl len %d index %d family %d type 0x%x nlen %d alen %d"
           " slen %d addr ", dl_p->sdl_len,
           dl_p->sdl_index,  dl_p->sdl_family, dl_p->sdl_type,
           dl_p->sdl_nlen, dl_p->sdl_alen, dl_p->sdl_slen);
#endif
	for (i = 0; i < dl_p->sdl_alen; i++)
        printf("%s%x", i ? ":" : "", (CONST_LLADDR(dl_p))[i]);
	printf("\n");
}

#endif /* BRIDGE_DEBUG */

/*
 * bridgeattach:
 *
 *	Pseudo-device attach routine.
 */
__private_extern__ int
bridgeattach(__unused int n)
{
	int error;
	lck_grp_attr_t *lck_grp_attr = NULL;
	struct ifnet_clone_params ifnet_clone_params;

	bridge_rtnode_pool = zinit(sizeof (struct bridge_rtnode),
	    1024 * sizeof (struct bridge_rtnode), 0, "bridge_rtnode");
	zone_change(bridge_rtnode_pool, Z_CALLERACCT, FALSE);

	lck_grp_attr = lck_grp_attr_alloc_init();

	bridge_lock_grp = lck_grp_alloc_init("if_bridge", lck_grp_attr);

	bridge_lock_attr = lck_attr_alloc_init();

#if BRIDGE_DEBUG
	lck_attr_setdebug(bridge_lock_attr);
#endif

	lck_mtx_init(bridge_list_mtx, bridge_lock_grp, bridge_lock_attr);

	/* can free the attributes once we've allocated the group lock */
	lck_grp_attr_free(lck_grp_attr);

	LIST_INIT(&bridge_list);

#if BRIDGESTP
	bstp_sys_init();
#endif /* BRIDGESTP */

	ifnet_clone_params.ifc_name = "bridge";
	ifnet_clone_params.ifc_create = bridge_clone_create;
	ifnet_clone_params.ifc_destroy = bridge_clone_destroy;

	error = ifnet_clone_attach(&ifnet_clone_params, &bridge_cloner);
	if (error != 0)
		printf("%s: ifnet_clone_attach failed %d\n", __func__, error);

	return (error);
}

#if defined(PFIL_HOOKS)
/*
 * handler for net.link.bridge.pfil_ipfw
 */
static int
sysctl_pfil_ipfw SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int enable = pfil_ipfw;
	int error;

	error = sysctl_handle_int(oidp, &enable, 0, req);
	enable = (enable) ? 1 : 0;

	if (enable != pfil_ipfw) {
		pfil_ipfw = enable;

		/*
		 * Disable pfil so that ipfw doesnt run twice, if the user
		 * really wants both then they can re-enable pfil_bridge and/or
		 * pfil_member. Also allow non-ip packets as ipfw can filter by
		 * layer2 type.
		 */
		if (pfil_ipfw) {
			pfil_onlyip = 0;
			pfil_bridge = 0;
			pfil_member = 0;
		}
	}

	return (error);
}

SYSCTL_PROC(_net_link_bridge, OID_AUTO, ipfw, CTLTYPE_INT|CTLFLAG_RW,
	    &pfil_ipfw, 0, &sysctl_pfil_ipfw, "I", "Layer2 filter with IPFW");
#endif /* PFIL_HOOKS */

/*
 * bridge_clone_create:
 *
 *	Create a new bridge instance.
 */
static int
bridge_clone_create(struct if_clone *ifc, uint32_t unit, __unused void *params)
{
	struct ifnet *ifp = NULL;
	struct bridge_softc *sc;
	u_char eaddr[6];
	struct ifnet_init_eparams init_params;
	errno_t error = 0;
	uint32_t sdl_buffer[offsetof(struct sockaddr_dl, sdl_data) +
	    IFNAMSIZ + ETHER_ADDR_LEN];
	struct sockaddr_dl *sdl = (struct sockaddr_dl *)sdl_buffer;

	sc = _MALLOC(sizeof (*sc), M_DEVBUF, M_WAITOK);
	memset(sc, 0, sizeof (*sc));

	sc->sc_mtx = lck_mtx_alloc_init(bridge_lock_grp, bridge_lock_attr);
	sc->sc_brtmax = BRIDGE_RTABLE_MAX;
	sc->sc_brttimeout = BRIDGE_RTABLE_TIMEOUT;
	sc->sc_filter_flags = IFBF_FILT_DEFAULT;
#ifndef BRIDGE_IPF
	/*
	 * For backwards compatibility with previous behaviour...
	 * Switch off filtering on the bridge itself if BRIDGE_IPF is
	 * not defined.
	 */
	sc->sc_filter_flags &= ~IFBF_FILT_USEIPF;
#endif

	/* Initialize our routing table. */
	error = bridge_rtable_init(sc);
	if (error != 0) {
		printf("%s: bridge_rtable_init failed %d\n", __func__, error);
		goto done;
	}

	TAILQ_INIT(&sc->sc_iflist);
	TAILQ_INIT(&sc->sc_spanlist);

	/* use the interface name as the unique id for ifp recycle */
	snprintf(sc->sc_if_xname, sizeof (sc->sc_if_xname), "%s%d",
             ifc->ifc_name, unit);
	bzero(&init_params, sizeof (init_params));
	init_params.ver			= IFNET_INIT_CURRENT_VERSION;
	init_params.len			= sizeof (init_params);
	if (if_bridge_txstart) {
		init_params.start	= bridge_start;
	} else {
		init_params.flags	= IFNET_INIT_LEGACY;
		init_params.output	= bridge_output;
	}
	init_params.uniqueid		= sc->sc_if_xname;
	init_params.uniqueid_len	= strlen(sc->sc_if_xname);
	init_params.sndq_maxlen		= IFQ_MAXLEN;
	init_params.name		= ifc->ifc_name;
	init_params.unit		= unit;
	init_params.family		= IFNET_FAMILY_ETHERNET;
	init_params.type		= IFT_BRIDGE;
	init_params.demux		= ether_demux;
	init_params.add_proto		= ether_add_proto;
	init_params.del_proto		= ether_del_proto;
	init_params.check_multi		= ether_check_multi;
	init_params.framer		= ether_frameout;
	init_params.softc		= sc;
	init_params.ioctl		= bridge_ioctl;
	init_params.set_bpf_tap		= bridge_set_bpf_tap;
	init_params.detach		= bridge_detach;
	init_params.broadcast_addr	= etherbroadcastaddr;
	init_params.broadcast_len	= ETHER_ADDR_LEN;
	error = ifnet_allocate_extended(&init_params, &ifp);
	if (error != 0) {
		printf("%s: ifnet_allocate failed %d\n", __func__, error);
		goto done;
	}
	sc->sc_ifp = ifp;

	error = ifnet_set_mtu(ifp, ETHERMTU);
	if (error != 0) {
		printf("%s: ifnet_set_mtu failed %d\n", __func__, error);
		goto done;
	}
	error = ifnet_set_addrlen(ifp, ETHER_ADDR_LEN);
	if (error != 0) {
		printf("%s: ifnet_set_addrlen failed %d\n", __func__, error);
		goto done;
	}
	error = ifnet_set_hdrlen(ifp, ETHER_HDR_LEN);
	if (error != 0) {
		printf("%s: ifnet_set_hdrlen failed %d\n", __func__, error);
		goto done;
	}
	error = ifnet_set_flags(ifp,
	    IFF_BROADCAST | IFF_SIMPLEX | IFF_NOTRAILERS | IFF_MULTICAST,
	    0xffff);
	if (error != 0) {
		printf("%s: ifnet_set_flags failed %d\n", __func__, error);
		goto done;
	}

#if 0
	/*
	 * Generate a random ethernet address with a locally administered
	 * address.
	 *
	 * Since we are using random ethernet addresses for the bridge, it is
	 * possible that we might have address collisions, so make sure that
	 * this hardware address isn't already in use on another bridge.
	 */
	{
		int retry;

		for (retry = 1; retry != 0;) {
			struct ifnet *bifp;
			struct bridge_softc *sc2;

			read_random(eaddr, ETHER_ADDR_LEN);
			eaddr[0] &= ~1;		/* clear multicast bit */
			eaddr[0] |= 2;		/* set the LAA bit */
			retry = 0;
			lck_mtx_lock(bridge_list_mtx);
			LIST_FOREACH(sc2, &bridge_list, sc_list) {
				bifp = sc2->sc_ifp;
				if (memcmp(eaddr, ifnet_lladdr(bifp),
				    ETHER_ADDR_LEN) == 0)
					retry = 1;
			}
			lck_mtx_unlock(bridge_list_mtx);
		}
	}
#else
	/*
	 * Generate a random ethernet address and use the private AC:DE:48
	 * OUI code.
	 */
	{
		uint32_t r;

		read_random(&r, sizeof (r));
		eaddr[0] = 0xAC;
		eaddr[1] = 0xDE;
		eaddr[2] = 0x48;
		eaddr[3] = (r >> 0)  & 0xffu;
		eaddr[4] = (r >> 8)  & 0xffu;
		eaddr[5] = (r >> 16) & 0xffu;
	}
#endif

	memset(sdl, 0, sizeof (sdl_buffer));
	sdl->sdl_family = AF_LINK;
	sdl->sdl_nlen = strlen(sc->sc_if_xname);
	sdl->sdl_alen = ETHER_ADDR_LEN;
	sdl->sdl_len = offsetof(struct sockaddr_dl, sdl_data);
	memcpy(sdl->sdl_data, sc->sc_if_xname, sdl->sdl_nlen);
	memcpy(LLADDR(sdl), eaddr, ETHER_ADDR_LEN);

#if BRIDGE_DEBUG
	if (if_bridge_debug)
		link_print(sdl);
#endif

	error = ifnet_attach(ifp, NULL);
	if (error != 0) {
		printf("%s: ifnet_attach failed %d\n", __func__, error);
		goto done;
	}

	error = ifnet_set_lladdr_and_type(ifp, eaddr, ETHER_ADDR_LEN,
	    IFT_ETHER);
	if (error != 0) {
		printf("%s: ifnet_set_lladdr_and_type failed %d\n", __func__,
		    error);
		goto done;
	}

#if APPLE_BRIDGE_HWCKSUM_SUPPORT
	/*
	 * APPLE MODIFICATION - our bridge can support HW checksums
	 * (useful if underlying interfaces support them) on TX,
	 * RX is not that interesting, since the stack just looks to
	 * see if the packet has been checksummed already (I think)
	 * but we might as well indicate we support it
	 */
	ifp->if_capabilities =
	    IFCAP_CSUM_IPv4_Tx | IFCAP_CSUM_TCPv4_Tx | IFCAP_CSUM_UDPv4_Tx |
	    IFCAP_CSUM_IPv4_Rx | IFCAP_CSUM_TCPv4_Rx | IFCAP_CSUM_UDPv4_Rx;
#endif

#if BRIDGESTP
	bstp_attach(&sc->sc_stp, &bridge_ops);
#endif /* BRIDGESTP */

	lck_mtx_lock(bridge_list_mtx);
	LIST_INSERT_HEAD(&bridge_list, sc, sc_list);
	lck_mtx_unlock(bridge_list_mtx);

	/* attach as ethernet */
	error = bpf_attach(ifp, DLT_EN10MB, sizeof (struct ether_header),
	    NULL, NULL);

done:
	if (error != 0) {
		printf("%s failed error %d\n", __func__, error);
		/* Cleanup TBD */
	}

	return (error);
}

/*
 * bridge_clone_destroy:
 *
 *	Destroy a bridge instance.
 */
static int
bridge_clone_destroy(struct ifnet *ifp)
{
	struct bridge_softc *sc = ifp->if_softc;
	struct bridge_iflist *bif;
	errno_t error;

	BRIDGE_LOCK(sc);
	if ((sc->sc_flags & SCF_DETACHING)) {
		BRIDGE_UNLOCK(sc);
		return (0);
	}
	sc->sc_flags |= SCF_DETACHING;

	bridge_ifstop(ifp, 1);

	error = ifnet_set_flags(ifp, 0, IFF_UP);
	if (error != 0) {
		printf("%s: ifnet_set_flags failed %d\n", __func__, error);
	}

	while ((bif = TAILQ_FIRST(&sc->sc_iflist)) != NULL)
		bridge_delete_member(sc, bif, 0);

	while ((bif = TAILQ_FIRST(&sc->sc_spanlist)) != NULL) {
		bridge_delete_span(sc, bif);
	}

	BRIDGE_UNLOCK(sc);

	error = ifnet_detach(ifp);
	if (error != 0) {
		panic("bridge_clone_destroy: ifnet_detach(%p) failed %d\n",
		    ifp, error);
		if ((sc = (struct bridge_softc *)ifnet_softc(ifp)) != NULL) {
			BRIDGE_LOCK(sc);
			sc->sc_flags &= ~SCF_DETACHING;
			BRIDGE_UNLOCK(sc);
		}
		return (0);
	}

	return (0);
}

#define DRVSPEC do { \
	if (ifd->ifd_cmd >= bridge_control_table_size) {		\
		error = EINVAL;						\
		break;							\
	}								\
	bc = &bridge_control_table[ifd->ifd_cmd];			\
									\
	if (cmd == SIOCGDRVSPEC &&					\
	    (bc->bc_flags & BC_F_COPYOUT) == 0) {			\
		error = EINVAL;						\
		break;							\
	} else if (cmd == SIOCSDRVSPEC &&				\
	    (bc->bc_flags & BC_F_COPYOUT) != 0) {			\
		error = EINVAL;						\
		break;							\
	}								\
									\
	if (bc->bc_flags & BC_F_SUSER) {				\
		error = kauth_authorize_generic(kauth_cred_get(),	\
		    KAUTH_GENERIC_ISSUSER);				\
		if (error)						\
			break;						\
	}								\
									\
	if (ifd->ifd_len != bc->bc_argsize ||				\
	    ifd->ifd_len > sizeof (args)) {				\
		error = EINVAL;						\
		break;							\
	}								\
									\
	bzero(&args, sizeof (args));					\
	if (bc->bc_flags & BC_F_COPYIN) {				\
		error = copyin(ifd->ifd_data, &args, ifd->ifd_len);	\
		if (error)						\
			break;						\
	}								\
									\
	BRIDGE_LOCK(sc);						\
	error = (*bc->bc_func)(sc, &args);				\
	BRIDGE_UNLOCK(sc);						\
	if (error)							\
		break;							\
									\
	if (bc->bc_flags & BC_F_COPYOUT)				\
		error = copyout(&args, ifd->ifd_data, ifd->ifd_len);	\
} while (0)


/*
 * bridge_ioctl:
 *
 *	Handle a control request from the operator.
 */
static errno_t
bridge_ioctl(struct ifnet *ifp, u_long cmd, void *data)
{
	struct bridge_softc *sc = ifp->if_softc;
	struct ifreq *ifr = (struct ifreq *)data;
	int error = 0;

	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_NOTOWNED);

#if BRIDGE_DEBUG
	if (if_bridge_debug)
		printf("%s: ifp %p cmd 0x%08lx (%c%c [%lu] %c %lu)\n",
		    __func__, ifp, cmd, (cmd & IOC_IN) ? 'I' : ' ',
		    (cmd & IOC_OUT) ? 'O' : ' ', IOCPARM_LEN(cmd),
		    (char)IOCGROUP(cmd), cmd & 0xff);
#endif

	switch (cmd) {

	case SIOCSIFADDR:
	case SIOCAIFADDR:
		ifnet_set_flags(ifp, IFF_UP, IFF_UP);
		break;

	case SIOCGIFMEDIA32:
	case SIOCGIFMEDIA64:
		error = EINVAL;
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;

	case SIOCSDRVSPEC32:
	case SIOCGDRVSPEC32: {
		union {
			struct ifbreq ifbreq;
			struct ifbifconf32 ifbifconf;
			struct ifbareq32 ifbareq;
			struct ifbaconf32 ifbaconf;
			struct ifbrparam ifbrparam;
			struct ifbropreq32 ifbropreq;
		} args;
		struct ifdrv32 *ifd = (struct ifdrv32 *)data;
		const struct bridge_control *bridge_control_table =
		    bridge_control_table32, *bc;

		DRVSPEC;

		break;
	}
	case SIOCSDRVSPEC64:
	case SIOCGDRVSPEC64: {
		union {
			struct ifbreq ifbreq;
			struct ifbifconf64 ifbifconf;
			struct ifbareq64 ifbareq;
			struct ifbaconf64 ifbaconf;
			struct ifbrparam ifbrparam;
			struct ifbropreq64 ifbropreq;
		} args;
		struct ifdrv64 *ifd = (struct ifdrv64 *)data;
		const struct bridge_control *bridge_control_table =
		    bridge_control_table64, *bc;

		DRVSPEC;

		break;
	}

	case SIOCSIFFLAGS:
		if (!(ifp->if_flags & IFF_UP) &&
		    (ifp->if_flags & IFF_RUNNING)) {
			/*
			 * If interface is marked down and it is running,
			 * then stop and disable it.
			 */
			BRIDGE_LOCK(sc);
			bridge_ifstop(ifp, 1);
			BRIDGE_UNLOCK(sc);
		} else if ((ifp->if_flags & IFF_UP) &&
		    !(ifp->if_flags & IFF_RUNNING)) {
			/*
			 * If interface is marked up and it is stopped, then
			 * start it.
			 */
			BRIDGE_LOCK(sc);
			error = bridge_init(ifp);
			BRIDGE_UNLOCK(sc);
		}
		break;

	case SIOCSIFLLADDR:
		error = ifnet_set_lladdr(ifp, ifr->ifr_addr.sa_data,
		    ifr->ifr_addr.sa_len);
		if (error != 0)
			printf("%s: ifnet_set_lladdr failed %d\n", __func__,
			    error);
		break;

	case SIOCSIFMTU:
		/* Do not allow the MTU to be changed on the bridge */
		error = EINVAL;
		break;

	default:
		error = ether_ioctl(ifp, cmd, data);
#if BRIDGE_DEBUG
		if (error != 0 && error != EOPNOTSUPP)
			printf("%s: ether_ioctl ifp %p cmd 0x%08lx "
			    "(%c%c [%lu] %c %lu) failed error: %d\n",
			    __func__, ifp, cmd, (cmd & IOC_IN) ? 'I' : ' ',
			    (cmd & IOC_OUT) ? 'O' : ' ',
			    IOCPARM_LEN(cmd), (char)IOCGROUP(cmd),
			    cmd & 0xff, error);
#endif /* BRIDGE_DEBUG */
		break;
	}
	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_NOTOWNED);

	return (error);
}

#if HAS_IF_CAP
/*
 * bridge_mutecaps:
 *
 *	Clear or restore unwanted capabilities on the member interface
 */
static void
bridge_mutecaps(struct bridge_softc *sc)
{
	struct bridge_iflist *bif;
	int enabled, mask;

	/* Initial bitmask of capabilities to test */
	mask = BRIDGE_IFCAPS_MASK;

	TAILQ_FOREACH(bif, &sc->sc_iflist, bif_next) {
		/* Every member must support it or its disabled */
		mask &= bif->bif_savedcaps;
	}

	TAILQ_FOREACH(bif, &sc->sc_iflist, bif_next) {
		enabled = bif->bif_ifp->if_capenable;
		enabled &= ~BRIDGE_IFCAPS_STRIP;
		/* strip off mask bits and enable them again if allowed */
		enabled &= ~BRIDGE_IFCAPS_MASK;
		enabled |= mask;

		bridge_set_ifcap(sc, bif, enabled);
	}

}

static void
bridge_set_ifcap(struct bridge_softc *sc, struct bridge_iflist *bif, int set)
{
	struct ifnet *ifp = bif->bif_ifp;
	struct ifreq ifr;
	int error;

	bzero(&ifr, sizeof (ifr));
	ifr.ifr_reqcap = set;

	if (ifp->if_capenable != set) {
		IFF_LOCKGIANT(ifp);
		error = (*ifp->if_ioctl)(ifp, SIOCSIFCAP, (caddr_t)&ifr);
		IFF_UNLOCKGIANT(ifp);
		if (error)
			printf("%s: error setting interface capabilities "
			    "on %s\n", __func__, ifnet_name(sc->sc_ifp),
			    ifnet_unit(sc->sc_ifp), ifp->if_xname);
	}
}
#endif /* HAS_IF_CAP */

/*
 * bridge_lookup_member:
 *
 *	Lookup a bridge member interface.
 */
static struct bridge_iflist *
bridge_lookup_member(struct bridge_softc *sc, const char *name)
{
	struct bridge_iflist *bif;
	struct ifnet *ifp;
	char if_xname[IFNAMSIZ];

	BRIDGE_LOCK_ASSERT(sc);

	TAILQ_FOREACH(bif, &sc->sc_iflist, bif_next) {
		ifp = bif->bif_ifp;
		snprintf(if_xname, sizeof (if_xname), "%s%d",
                 ifnet_name(ifp), ifnet_unit(ifp));
		if (strncmp(if_xname, name, sizeof (if_xname)) == 0)
			return (bif);
	}

	return (NULL);
}

/*
 * bridge_lookup_member_if:
 *
 *	Lookup a bridge member interface by ifnet*.
 */
static struct bridge_iflist *
bridge_lookup_member_if(struct bridge_softc *sc, struct ifnet *member_ifp)
{
	struct bridge_iflist *bif;

	BRIDGE_LOCK_ASSERT(sc);

	TAILQ_FOREACH(bif, &sc->sc_iflist, bif_next) {
		if (bif->bif_ifp == member_ifp)
			return (bif);
	}

	return (NULL);
}

static errno_t
bridge_iff_input(void *cookie, ifnet_t ifp, __unused protocol_family_t protocol,
    mbuf_t *data, char **frame_ptr)
{
	errno_t error = 0;
	struct bridge_iflist *bif = (struct bridge_iflist *)cookie;
	struct bridge_softc *sc = bif->bif_sc;
	int included = 0;
	size_t frmlen = 0;
	mbuf_t m = *data;

	if ((m->m_flags & M_PROTO1))
		goto out;

	if (*frame_ptr >= (char *)mbuf_datastart(m) &&
	    *frame_ptr <= (char *)mbuf_data(m)) {
		included = 1;
		frmlen = (char *)mbuf_data(m) - *frame_ptr;
	}
#if BRIDGE_DEBUG
	if (if_bridge_debug) {
		printf("%s: %s%d from %s%d m %p data %p frame %p %s "
		    "frmlen %lu\n", __func__, ifnet_name(sc->sc_ifp),
		    ifnet_unit(sc->sc_ifp), ifnet_name(ifp), ifnet_unit(ifp),
		    m, mbuf_data(m), *frame_ptr,
		    included ? "inside" : "outside", frmlen);

		if (if_bridge_debug > 1) {
			printf_mbuf(m, "bridge_iff_input[", "\n");
			printf_ether_header((struct ether_header *)
			    (void *)*frame_ptr);
			printf_mbuf_data(m, 0, 20);
			printf("\n");
		}
	}
#endif /* BRIDGE_DEBUG */

	/* Move data pointer to start of frame to the link layer header */
	if (included) {
		(void) mbuf_setdata(m, (char *)mbuf_data(m) - frmlen,
		    mbuf_len(m) + frmlen);
		(void) mbuf_pkthdr_adjustlen(m, frmlen);
	} else {
		printf("%s: frame_ptr outside mbuf\n", __func__);
		goto out;
	}

	error = bridge_input(ifp, m, *frame_ptr);

	/* Adjust packet back to original */
	if (error == 0) {
		(void) mbuf_setdata(m, (char *)mbuf_data(m) + frmlen,
		    mbuf_len(m) - frmlen);
		(void) mbuf_pkthdr_adjustlen(m, -frmlen);
	}
#if BRIDGE_DEBUG
	if (if_bridge_debug > 1) {
		printf("\n");
		printf_mbuf(m, "bridge_iff_input]", "\n");
	}
#endif /* BRIDGE_DEBUG */

out:
	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_NOTOWNED);

	return (error);
}


#if BRIDGE_MEMBER_OUT_FILTER
static errno_t
bridge_iff_output(void *cookie, ifnet_t ifp, __unused protocol_family_t protocol, mbuf_t *data)
{
	errno_t error = 0;
	struct bridge_iflist *bif = (struct bridge_iflist *)cookie;
	struct bridge_softc *sc = bif->bif_sc;
	mbuf_t m = *data;

	if ((m->m_flags & M_PROTO1))
		goto out;

#if BRIDGE_DEBUG
	if (if_bridge_debug) {
		printf("%s: %s%d from %s%d m %p data %p\n", __func__,
		    ifnet_name(sc->sc_ifp), ifnet_unit(sc->sc_ifp),
		    ifnet_name(ifp), ifnet_unit(ifp), m, mbuf_data(m));
	}
#endif /* BRIDGE_DEBUG */

	error = bridge_member_output(sc, ifp, m);
	if (error != 0) {
		printf("%s: bridge_member_output failed error %d\n", __func__,
		    error);
	}

out:
	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_NOTOWNED);

	return (error);
}
#endif /* BRIDGE_MEMBER_OUT_FILTER */


static void
bridge_iff_event(void *cookie, ifnet_t ifp, __unused protocol_family_t protocol,
    const struct kev_msg *event_msg)
{
	struct bridge_iflist *bif = (struct bridge_iflist *)cookie;

	if (event_msg->vendor_code == KEV_VENDOR_APPLE &&
		event_msg->kev_class == KEV_NETWORK_CLASS &&
		event_msg->kev_subclass == KEV_DL_SUBCLASS) {
		switch (event_msg->event_code) {
			case KEV_DL_IF_DETACHING:
			case KEV_DL_IF_DETACHED:
				bridge_ifdetach(bif, ifp);
				break;

			case KEV_DL_LINK_OFF:
			case KEV_DL_LINK_ON: {
#if BRIDGESTP
				bstp_linkstate(ifp, event_msg->event_code);
#endif /* BRIDGESTP */
				break;
			}

			case KEV_DL_SIFFLAGS: {
				if (bif->bif_promisc == 0 &&
				    (ifp->if_flags & IFF_UP)) {
					errno_t error =
					    ifnet_set_promiscuous(ifp, 1);
					if (error != 0) {
						printf("%s: "
						    "ifnet_set_promiscuous"
						    "(%s%d) failed %d\n",
						    __func__, ifnet_name(ifp),
						    ifnet_unit(ifp), error);
					} else {
						bif->bif_promisc = 1;
					}
				}
				break;
			}

			default:
				break;
		}
	}
}

/*
 * bridge_iff_detached:
 *
 *	Detach an interface from a bridge.  Called when a member
 *	interface is detaching.
 */
static void
bridge_iff_detached(void *cookie, __unused ifnet_t ifp)
{
	struct bridge_iflist *bif = (struct bridge_iflist *)cookie;

#if BRIDGE_DEBUG
	printf("%s: %s%d\n", __func__, ifnet_name(ifp), ifnet_unit(ifp));
#endif

	bridge_ifdetach(bif, ifp);

	_FREE(bif, M_DEVBUF);
}

static errno_t
bridge_proto_input(ifnet_t ifp, __unused protocol_family_t protocol,
    __unused mbuf_t packet, __unused char *header)
{
	printf("%s: unexpected packet from %s%d\n", __func__,
	    ifnet_name(ifp), ifnet_unit(ifp));
	return (0);
}

static int
bridge_attach_protocol(struct ifnet *ifp)
{
	int	error;
	struct ifnet_attach_proto_param	reg;

	printf("%s: %s%d\n", __func__, ifnet_name(ifp), ifnet_unit(ifp));

	bzero(&reg, sizeof (reg));
	reg.input = bridge_proto_input;

	error = ifnet_attach_protocol(ifp, PF_BRIDGE, &reg);
	if (error)
		printf("%s: ifnet_attach_protocol(%s%d) failed, %d\n",
		    __func__, ifnet_name(ifp), ifnet_unit(ifp), error);

	return (error);
}

static int
bridge_detach_protocol(struct ifnet *ifp)
{
	int         error;

	printf("%s: %s%d\n", __func__, ifnet_name(ifp), ifnet_unit(ifp));

	error = ifnet_detach_protocol(ifp, PF_BRIDGE);
	if (error)
		printf("%s: ifnet_detach_protocol(%s%d) failed, %d\n",
		    __func__, ifnet_name(ifp), ifnet_unit(ifp), error);

	return (error);
}

/*
 * bridge_delete_member:
 *
 *	Delete the specified member interface.
 */
static void
bridge_delete_member(struct bridge_softc *sc, struct bridge_iflist *bif,
    int gone)
{
	struct ifnet *ifs = bif->bif_ifp;

	BRIDGE_LOCK_ASSERT(sc);

	if (!gone) {
		switch (ifs->if_type) {
		case IFT_ETHER:
		case IFT_L2VLAN:
			/*
			 * Take the interface out of promiscuous mode.
			 */
			if (bif->bif_promisc)
				(void) ifnet_set_promiscuous(ifs, 0);
			break;

		case IFT_GIF:
			break;

		default:
#ifdef DIAGNOSTIC
			panic("bridge_delete_member: impossible");
#endif
			break;
		}

#if HAS_IF_CAP
		/* reneable any interface capabilities */
		bridge_set_ifcap(sc, bif, bif->bif_savedcaps);
#endif
	}

	if (bif->bif_proto_attached) {
		/* Respect lock ordering with DLIL lock */
		BRIDGE_UNLOCK(sc);
		(void) bridge_detach_protocol(ifs);
		BRIDGE_LOCK(sc);
	}
#if BRIDGESTP
	if (bif->bif_flags & IFBIF_STP)
		bstp_disable(&bif->bif_stp);
#endif /* BRIDGESTP */

	ifs->if_bridge = NULL;
	BRIDGE_XLOCK(sc);
	TAILQ_REMOVE(&sc->sc_iflist, bif, bif_next);
	BRIDGE_XDROP(sc);

	ifnet_release(ifs);

#if HAS_IF_CAP
	bridge_mutecaps(sc);	/* recalcuate now this interface is removed */
#endif /* HAS_IF_CAP */
	bridge_rtdelete(sc, ifs, IFBF_FLUSHALL);
	KASSERT(bif->bif_addrcnt == 0,
	    ("%s: %d bridge routes referenced", __func__, bif->bif_addrcnt));

#if BRIDGESTP
	BRIDGE_UNLOCK(sc);
	bstp_destroy(&bif->bif_stp);	/* prepare to free */
	BRIDGE_LOCK(sc);
#endif /* BRIDGESTP */

	if (bif->bif_filter_attached) {
		/* Respect lock ordering with DLIL lock */
		BRIDGE_UNLOCK(sc);
		iflt_detach(bif->bif_iff_ref);
		BRIDGE_LOCK(sc);
	} else {
		_FREE(bif, M_DEVBUF);
	}
}

/*
 * bridge_delete_span:
 *
 *	Delete the specified span interface.
 */
static void
bridge_delete_span(struct bridge_softc *sc, struct bridge_iflist *bif)
{
	BRIDGE_LOCK_ASSERT(sc);

	KASSERT(bif->bif_ifp->if_bridge == NULL,
	    ("%s: not a span interface", __func__));

	ifnet_release(bif->bif_ifp);

	TAILQ_REMOVE(&sc->sc_spanlist, bif, bif_next);
	_FREE(bif, M_DEVBUF);
}

static int
bridge_ioctl_add(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif = NULL;
	struct ifnet *ifs;
	int error = 0;
	struct iff_filter iff;

	ifs = ifunit(req->ifbr_ifsname);
	if (ifs == NULL)
		return (ENOENT);
	if (ifs->if_ioctl == NULL)	/* must be supported */
		return (EINVAL);

	/* If it's in the span list, it can't be a member. */
	TAILQ_FOREACH(bif, &sc->sc_spanlist, bif_next)
		if (ifs == bif->bif_ifp)
			return (EBUSY);

	/* Allow the first Ethernet member to define the MTU */
	if (ifs->if_type != IFT_GIF) {
		if (TAILQ_EMPTY(&sc->sc_iflist))
			sc->sc_ifp->if_mtu = ifs->if_mtu;
		else if (sc->sc_ifp->if_mtu != ifs->if_mtu) {
			printf("%s: %s%d: invalid MTU for %s%d", __func__,
			    ifnet_name(sc->sc_ifp), ifnet_unit(sc->sc_ifp),
			    ifnet_name(ifs), ifnet_unit(ifs));
			return (EINVAL);
		}
	}

	if (ifs->if_bridge == sc)
		return (EEXIST);

	if (ifs->if_bridge != NULL)
		return (EBUSY);

	bif = _MALLOC(sizeof (*bif), M_DEVBUF, M_NOWAIT|M_ZERO);
	if (bif == NULL)
		return (ENOMEM);

	bif->bif_ifp = ifs;
	bif->bif_flags = IFBIF_LEARNING | IFBIF_DISCOVER;
#if HAS_IF_CAP
	bif->bif_savedcaps = ifs->if_capenable;
#endif /* HAS_IF_CAP */
	bif->bif_sc = sc;

	ifnet_reference(ifs);

	ifs->if_bridge = sc;
#if BRIDGESTP
	bstp_create(&sc->sc_stp, &bif->bif_stp, bif->bif_ifp);
#endif /* BRIDGESTP */
	/*
	 * XXX: XLOCK HERE!?!
	 */
	TAILQ_INSERT_TAIL(&sc->sc_iflist, bif, bif_next);

#if HAS_IF_CAP
	/* Set interface capabilities to the intersection set of all members */
	bridge_mutecaps(sc);
#endif /* HAS_IF_CAP */


	switch (ifs->if_type) {
	case IFT_ETHER:
	case IFT_L2VLAN:
		/*
		 * Place the interface into promiscuous mode.
		 */
		error = ifnet_set_promiscuous(ifs, 1);
		if (error) {
			/* Ignore error when device is not up */
			if (error != ENETDOWN)
				goto out;
			error = 0;
		} else {
			bif->bif_promisc = 1;
		}
		break;

	case IFT_GIF:
		break;

	default:
		error = EINVAL;
		goto out;
	}

	/* 
	 * Respect lock ordering with DLIL lock for the following operations
	 */
	BRIDGE_UNLOCK(sc);

	/*
	 * install an interface filter
	 */
	memset(&iff, 0, sizeof (struct iff_filter));
	iff.iff_cookie = bif;
	iff.iff_name = "com.apple.kernel.bsd.net.if_bridge";
	iff.iff_input = bridge_iff_input;
#if BRIDGE_MEMBER_OUT_FILTER
	iff.iff_output = bridge_iff_output;
#endif /* BRIDGE_MEMBER_OUT_FILTER */
	iff.iff_event = bridge_iff_event;
	iff.iff_detached = bridge_iff_detached;
	error = iflt_attach(ifs, &iff, &bif->bif_iff_ref);
	if (error != 0) {
		printf("%s: iflt_attach failed %d\n", __func__, error);
		BRIDGE_LOCK(sc);
		goto out;
	}
	bif->bif_filter_attached = 1;

	/*
	 * install an dummy "bridge" protocol
	 */
	if ((error = bridge_attach_protocol(ifs)) != 0) {
		if (error != 0) {
			printf("%s: bridge_attach_protocol failed %d\n",
			    __func__, error);
			BRIDGE_LOCK(sc);
			goto out;
		}
	}
	bif->bif_proto_attached = 1;

	BRIDGE_LOCK(sc);

out:
	if (error && bif != NULL)
		bridge_delete_member(sc, bif, 1);

	return (error);
}

static int
bridge_ioctl_del(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;

	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);

	bridge_delete_member(sc, bif, 0);

	return (0);
}

static int
bridge_ioctl_purge(__unused struct bridge_softc *sc, __unused void *arg)
{
	return (0);
}

static int
bridge_ioctl_gifflags(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;
	struct bstp_port *bp;

	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);

	bp = &bif->bif_stp;
	req->ifbr_ifsflags = bif->bif_flags;
	req->ifbr_state = bp->bp_state;
	req->ifbr_priority = bp->bp_priority;
	req->ifbr_path_cost = bp->bp_path_cost;
	req->ifbr_portno = bif->bif_ifp->if_index & 0xfff;
	req->ifbr_proto = bp->bp_protover;
	req->ifbr_role = bp->bp_role;
	req->ifbr_stpflags = bp->bp_flags;
	req->ifbr_addrcnt = bif->bif_addrcnt;
	req->ifbr_addrmax = bif->bif_addrmax;
	req->ifbr_addrexceeded = bif->bif_addrexceeded;

	/* Copy STP state options as flags */
	if (bp->bp_operedge)
		req->ifbr_ifsflags |= IFBIF_BSTP_EDGE;
	if (bp->bp_flags & BSTP_PORT_AUTOEDGE)
		req->ifbr_ifsflags |= IFBIF_BSTP_AUTOEDGE;
	if (bp->bp_ptp_link)
		req->ifbr_ifsflags |= IFBIF_BSTP_PTP;
	if (bp->bp_flags & BSTP_PORT_AUTOPTP)
		req->ifbr_ifsflags |= IFBIF_BSTP_AUTOPTP;
	if (bp->bp_flags & BSTP_PORT_ADMEDGE)
		req->ifbr_ifsflags |= IFBIF_BSTP_ADMEDGE;
	if (bp->bp_flags & BSTP_PORT_ADMCOST)
		req->ifbr_ifsflags |= IFBIF_BSTP_ADMCOST;
	return (0);
}

static int
bridge_ioctl_sifflags(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;
#if BRIDGESTP
	struct bstp_port *bp;
	int error;
#endif /* BRIDGESTP */

	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);

	if (req->ifbr_ifsflags & IFBIF_SPAN)
		/* SPAN is readonly */
		return (EINVAL);


#if BRIDGESTP
	if (req->ifbr_ifsflags & IFBIF_STP) {
		if ((bif->bif_flags & IFBIF_STP) == 0) {
			error = bstp_enable(&bif->bif_stp);
			if (error)
				return (error);
		}
	} else {
		if ((bif->bif_flags & IFBIF_STP) != 0)
			bstp_disable(&bif->bif_stp);
	}

	/* Pass on STP flags */
	bp = &bif->bif_stp;
	bstp_set_edge(bp, req->ifbr_ifsflags & IFBIF_BSTP_EDGE ? 1 : 0);
	bstp_set_autoedge(bp, req->ifbr_ifsflags & IFBIF_BSTP_AUTOEDGE ? 1 : 0);
	bstp_set_ptp(bp, req->ifbr_ifsflags & IFBIF_BSTP_PTP ? 1 : 0);
	bstp_set_autoptp(bp, req->ifbr_ifsflags & IFBIF_BSTP_AUTOPTP ? 1 : 0);
#else /* !BRIDGESTP */
	if (req->ifbr_ifsflags & IFBIF_STP)
		return (EOPNOTSUPP);
#endif /* !BRIDGESTP */

	/* Save the bits relating to the bridge */
	bif->bif_flags = req->ifbr_ifsflags & IFBIFMASK;


	return (0);
}

static int
bridge_ioctl_scache(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	sc->sc_brtmax = param->ifbrp_csize;
	bridge_rttrim(sc);

	return (0);
}

static int
bridge_ioctl_gcache(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	param->ifbrp_csize = sc->sc_brtmax;

	return (0);
}


#define BRIDGE_IOCTL_GIFS do { \
	struct bridge_iflist *bif;					\
	struct ifbreq breq;						\
	char *buf, *outbuf;						\
	unsigned int count, buflen, len;				\
									\
	count = 0;							\
	TAILQ_FOREACH(bif, &sc->sc_iflist, bif_next)			\
		count++;						\
	TAILQ_FOREACH(bif, &sc->sc_spanlist, bif_next)			\
		count++;						\
									\
	buflen = sizeof (breq) * count;					\
	if (bifc->ifbic_len == 0) {					\
		bifc->ifbic_len = buflen;				\
		return (0);						\
	}								\
	BRIDGE_UNLOCK(sc);						\
	outbuf = _MALLOC(buflen, M_TEMP, M_WAITOK | M_ZERO);		\
	BRIDGE_LOCK(sc);						\
									\
	count = 0;							\
	buf = outbuf;							\
	len = min(bifc->ifbic_len, buflen);				\
	bzero(&breq, sizeof (breq));					\
	TAILQ_FOREACH(bif, &sc->sc_iflist, bif_next) {			\
		if (len < sizeof (breq))				\
			break;						\
									\
		snprintf(breq.ifbr_ifsname, sizeof (breq.ifbr_ifsname),	\
		    "%s%d", ifnet_name(bif->bif_ifp),			\
		    ifnet_unit(bif->bif_ifp));				\
		/* Fill in the ifbreq structure */			\
		error = bridge_ioctl_gifflags(sc, &breq);		\
		if (error)						\
			break;						\
		memcpy(buf, &breq, sizeof (breq));			\
		count++;						\
		buf += sizeof (breq);					\
		len -= sizeof (breq);					\
	}								\
	TAILQ_FOREACH(bif, &sc->sc_spanlist, bif_next) {		\
		if (len < sizeof (breq))				\
			break;						\
									\
		snprintf(breq.ifbr_ifsname, sizeof (breq.ifbr_ifsname),	\
		    "%s%d", ifnet_name(bif->bif_ifp),			\
		    ifnet_unit(bif->bif_ifp));				\
		breq.ifbr_ifsflags = bif->bif_flags;			\
		breq.ifbr_portno = bif->bif_ifp->if_index & 0xfff;	\
		memcpy(buf, &breq, sizeof (breq));			\
		count++;						\
		buf += sizeof (breq);					\
		len -= sizeof (breq);					\
	}								\
									\
	BRIDGE_UNLOCK(sc);						\
	bifc->ifbic_len = sizeof (breq) * count;			\
	error = copyout(outbuf, bifc->ifbic_req, bifc->ifbic_len);	\
	BRIDGE_LOCK(sc);						\
	_FREE(outbuf, M_TEMP);						\
} while (0)

static int
bridge_ioctl_gifs64(struct bridge_softc *sc, void *arg)
{
	struct ifbifconf64 *bifc = arg;
	int error = 0;

	BRIDGE_IOCTL_GIFS;

	return (error);
}

static int
bridge_ioctl_gifs32(struct bridge_softc *sc, void *arg)
{
	struct ifbifconf32 *bifc = arg;
	int error = 0;

	BRIDGE_IOCTL_GIFS;

	return (error);
}


#define BRIDGE_IOCTL_RTS do {						    \
	struct bridge_rtnode *brt;					    \
	char *buf, *outbuf;						    \
	unsigned int count, buflen, len;				    \
	struct timespec now;						    \
									    \
	if (bac->ifbac_len == 0)					    \
		return (0);						    \
									    \
	count = 0;							    \
	LIST_FOREACH(brt, &sc->sc_rtlist, brt_list)			    \
		count++;						    \
	buflen = sizeof (bareq) * count;				    \
									    \
	BRIDGE_UNLOCK(sc);						    \
	outbuf = _MALLOC(buflen, M_TEMP, M_WAITOK | M_ZERO);		    \
	BRIDGE_LOCK(sc);						    \
									    \
	count = 0;							    \
	buf = outbuf;							    \
	len = min(bac->ifbac_len, buflen);				    \
	bzero(&bareq, sizeof (bareq));					    \
	LIST_FOREACH(brt, &sc->sc_rtlist, brt_list) {			    \
		if (len < sizeof (bareq))				    \
			goto out;					    \
		snprintf(bareq.ifba_ifsname, sizeof (bareq.ifba_ifsname),    \
		    "%s%d", ifnet_name(brt->brt_ifp),			    \
		    ifnet_unit(brt->brt_ifp));				    \
		memcpy(bareq.ifba_dst, brt->brt_addr, sizeof (brt->brt_addr)); \
		bareq.ifba_vlan = brt->brt_vlan;			    \
		if ((brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC) {   \
			nanouptime(&now);				    \
			if ((unsigned long)now.tv_sec < brt->brt_expire)    \
				bareq.ifba_expire =			    \
				    brt->brt_expire - now.tv_sec;	    \
		} else							    \
			bareq.ifba_expire = 0;				    \
		bareq.ifba_flags = brt->brt_flags;			    \
									    \
		memcpy(buf, &bareq, sizeof (bareq));			    \
		count++;						    \
		buf += sizeof (bareq);					    \
		len -= sizeof (bareq);					    \
	}								    \
out:									    \
	BRIDGE_UNLOCK(sc);						    \
	bac->ifbac_len = sizeof (bareq) * count;				    \
	error = copyout(outbuf, bac->ifbac_req, bac->ifbac_len);	    \
	BRIDGE_LOCK(sc);						    \
	_FREE(outbuf, M_TEMP);						    \
	return (error);							    \
} while (0)

static int
bridge_ioctl_rts64(struct bridge_softc *sc, void *arg)
{
	struct ifbaconf64 *bac = arg;
	struct ifbareq64 bareq;
	int error = 0;

	BRIDGE_IOCTL_RTS;

	return (error);
}

static int
bridge_ioctl_rts32(struct bridge_softc *sc, void *arg)
{
	struct ifbaconf32 *bac = arg;
	struct ifbareq32 bareq;
	int error = 0;

	BRIDGE_IOCTL_RTS;

	return (error);
}

static int
bridge_ioctl_saddr32(struct bridge_softc *sc, void *arg)
{
	struct ifbareq32 *req = arg;
	struct bridge_iflist *bif;
	int error;

	bif = bridge_lookup_member(sc, req->ifba_ifsname);
	if (bif == NULL)
		return (ENOENT);

	error = bridge_rtupdate(sc, req->ifba_dst, req->ifba_vlan, bif, 1,
	    req->ifba_flags);

	return (error);
}

static int
bridge_ioctl_saddr64(struct bridge_softc *sc, void *arg)
{
	struct ifbareq64 *req = arg;
	struct bridge_iflist *bif;
	int error;

	bif = bridge_lookup_member(sc, req->ifba_ifsname);
	if (bif == NULL)
		return (ENOENT);

	error = bridge_rtupdate(sc, req->ifba_dst, req->ifba_vlan, bif, 1,
	    req->ifba_flags);

	return (error);
}

static int
bridge_ioctl_sto(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	sc->sc_brttimeout = param->ifbrp_ctime;
	return (0);
}

static int
bridge_ioctl_gto(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	param->ifbrp_ctime = sc->sc_brttimeout;
	return (0);
}

static int
bridge_ioctl_daddr32(struct bridge_softc *sc, void *arg)
{
	struct ifbareq32 *req = arg;

	return (bridge_rtdaddr(sc, req->ifba_dst, req->ifba_vlan));
}

static int
bridge_ioctl_daddr64(struct bridge_softc *sc, void *arg)
{
	struct ifbareq64 *req = arg;

	return (bridge_rtdaddr(sc, req->ifba_dst, req->ifba_vlan));
}

static int
bridge_ioctl_flush(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;

	bridge_rtflush(sc, req->ifbr_ifsflags);
	return (0);
}

static int
bridge_ioctl_gpri(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	struct bstp_state *bs = &sc->sc_stp;

	param->ifbrp_prio = bs->bs_bridge_priority;
	return (0);
}

static int
bridge_ioctl_spri(struct bridge_softc *sc, void *arg)
{
#if BRIDGESTP
	struct ifbrparam *param = arg;

	return (bstp_set_priority(&sc->sc_stp, param->ifbrp_prio));
#else /* !BRIDGESTP */
#pragma unused(sc, arg)
	return (EOPNOTSUPP);
#endif /* !BRIDGESTP */
}

static int
bridge_ioctl_ght(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	struct bstp_state *bs = &sc->sc_stp;

	param->ifbrp_hellotime = bs->bs_bridge_htime >> 8;
	return (0);
}

static int
bridge_ioctl_sht(struct bridge_softc *sc, void *arg)
{
#if BRIDGESTP
	struct ifbrparam *param = arg;

	return (bstp_set_htime(&sc->sc_stp, param->ifbrp_hellotime));
#else /* !BRIDGESTP */
#pragma unused(sc, arg)
	return (EOPNOTSUPP);
#endif /* !BRIDGESTP */
}

static int
bridge_ioctl_gfd(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	struct bstp_state *bs = &sc->sc_stp;

	param->ifbrp_fwddelay = bs->bs_bridge_fdelay >> 8;
	return (0);
}

static int
bridge_ioctl_sfd(struct bridge_softc *sc, void *arg)
{
#if BRIDGESTP
	struct ifbrparam *param = arg;

	return (bstp_set_fdelay(&sc->sc_stp, param->ifbrp_fwddelay));
#else /* !BRIDGESTP */
#pragma unused(sc, arg)
	return (EOPNOTSUPP);
#endif /* !BRIDGESTP */
}

static int
bridge_ioctl_gma(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;
	struct bstp_state *bs = &sc->sc_stp;

	param->ifbrp_maxage = bs->bs_bridge_max_age >> 8;
	return (0);
}

static int
bridge_ioctl_sma(struct bridge_softc *sc, void *arg)
{
#if BRIDGESTP
	struct ifbrparam *param = arg;

	return (bstp_set_maxage(&sc->sc_stp, param->ifbrp_maxage));
#else /* !BRIDGESTP */
#pragma unused(sc, arg)
	return (EOPNOTSUPP);
#endif /* !BRIDGESTP */
}

static int
bridge_ioctl_sifprio(struct bridge_softc *sc, void *arg)
{
#if BRIDGESTP
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;

	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);

	return (bstp_set_port_priority(&bif->bif_stp, req->ifbr_priority));
#else /* !BRIDGESTP */
#pragma unused(sc, arg)
	return (EOPNOTSUPP);
#endif /* !BRIDGESTP */
}

static int
bridge_ioctl_sifcost(struct bridge_softc *sc, void *arg)
{
#if BRIDGESTP
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;

	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);

	return (bstp_set_path_cost(&bif->bif_stp, req->ifbr_path_cost));
#else /* !BRIDGESTP */
#pragma unused(sc, arg)
	return (EOPNOTSUPP);
#endif /* !BRIDGESTP */
}

static int
bridge_ioctl_gfilt(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	param->ifbrp_filter = sc->sc_filter_flags;

	return (0);
}

static int
bridge_ioctl_sfilt(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	if (param->ifbrp_filter & ~IFBF_FILT_MASK)
		return (EINVAL);

#ifndef BRIDGE_IPF
	if (param->ifbrp_filter & IFBF_FILT_USEIPF)
		return (EINVAL);
#endif

	sc->sc_filter_flags = param->ifbrp_filter;

	return (0);
}

static int
bridge_ioctl_sifmaxaddr(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;

	bif = bridge_lookup_member(sc, req->ifbr_ifsname);
	if (bif == NULL)
		return (ENOENT);

	bif->bif_addrmax = req->ifbr_addrmax;
	return (0);
}

static int
bridge_ioctl_addspan(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif = NULL;
	struct ifnet *ifs;

	ifs = ifunit(req->ifbr_ifsname);
	if (ifs == NULL)
		return (ENOENT);

	TAILQ_FOREACH(bif, &sc->sc_spanlist, bif_next)
		if (ifs == bif->bif_ifp)
			return (EBUSY);

	if (ifs->if_bridge != NULL)
		return (EBUSY);

	switch (ifs->if_type) {
		case IFT_ETHER:
		case IFT_GIF:
		case IFT_L2VLAN:
			break;
		default:
			return (EINVAL);
	}

	bif = _MALLOC(sizeof (*bif), M_DEVBUF, M_NOWAIT|M_ZERO);
	if (bif == NULL)
		return (ENOMEM);

	bif->bif_ifp = ifs;
	bif->bif_flags = IFBIF_SPAN;

	ifnet_reference(bif->bif_ifp);

	TAILQ_INSERT_HEAD(&sc->sc_spanlist, bif, bif_next);

	return (0);
}

static int
bridge_ioctl_delspan(struct bridge_softc *sc, void *arg)
{
	struct ifbreq *req = arg;
	struct bridge_iflist *bif;
	struct ifnet *ifs;

	ifs = ifunit(req->ifbr_ifsname);
	if (ifs == NULL)
		return (ENOENT);

	TAILQ_FOREACH(bif, &sc->sc_spanlist, bif_next)
		if (ifs == bif->bif_ifp)
			break;

	if (bif == NULL)
		return (ENOENT);

	bridge_delete_span(sc, bif);

	return (0);
}

#define BRIDGE_IOCTL_GBPARAM do {					\
	struct bstp_state *bs = &sc->sc_stp;				\
	struct bstp_port *root_port;					\
									\
	req->ifbop_maxage = bs->bs_bridge_max_age >> 8;			\
	req->ifbop_hellotime = bs->bs_bridge_htime >> 8;		\
	req->ifbop_fwddelay = bs->bs_bridge_fdelay >> 8;		\
									\
	root_port = bs->bs_root_port;					\
	if (root_port == NULL)						\
		req->ifbop_root_port = 0;				\
	else								\
		req->ifbop_root_port = root_port->bp_ifp->if_index;	\
									\
	req->ifbop_holdcount = bs->bs_txholdcount;			\
	req->ifbop_priority = bs->bs_bridge_priority;			\
	req->ifbop_protocol = bs->bs_protover;				\
	req->ifbop_root_path_cost = bs->bs_root_pv.pv_cost;		\
	req->ifbop_bridgeid = bs->bs_bridge_pv.pv_dbridge_id;		\
	req->ifbop_designated_root = bs->bs_root_pv.pv_root_id;		\
	req->ifbop_designated_bridge = bs->bs_root_pv.pv_dbridge_id;	\
	req->ifbop_last_tc_time.tv_sec = bs->bs_last_tc_time.tv_sec;	\
	req->ifbop_last_tc_time.tv_usec = bs->bs_last_tc_time.tv_usec;	\
} while (0)

static int
bridge_ioctl_gbparam32(struct bridge_softc *sc, void *arg)
{
	struct ifbropreq32 *req = arg;

	BRIDGE_IOCTL_GBPARAM;

	return (0);
}

static int
bridge_ioctl_gbparam64(struct bridge_softc *sc, void *arg)
{
	struct ifbropreq64 *req = arg;

	BRIDGE_IOCTL_GBPARAM;

	return (0);
}

static int
bridge_ioctl_grte(struct bridge_softc *sc, void *arg)
{
	struct ifbrparam *param = arg;

	param->ifbrp_cexceeded = sc->sc_brtexceeded;
	return (0);
}

#define BRIDGE_IOCTL_GIFSSTP do {					\
	struct bridge_iflist *bif;					\
	struct bstp_port *bp;						\
	struct ifbpstpreq bpreq;					\
	char *buf, *outbuf;						\
	unsigned int count, buflen, len;				\
									\
	count = 0;							\
	TAILQ_FOREACH(bif, &sc->sc_iflist, bif_next) {			\
		if ((bif->bif_flags & IFBIF_STP) != 0)			\
			count++;					\
	}								\
									\
	buflen = sizeof (bpreq) * count;				\
	if (bifstp->ifbpstp_len == 0) {					\
		bifstp->ifbpstp_len = buflen;				\
		return (0);						\
	}								\
									\
	BRIDGE_UNLOCK(sc);						\
	outbuf = _MALLOC(buflen, M_TEMP, M_WAITOK | M_ZERO);		\
	BRIDGE_LOCK(sc);						\
									\
	count = 0;							\
	buf = outbuf;							\
	len = min(bifstp->ifbpstp_len, buflen);				\
	bzero(&bpreq, sizeof (bpreq));					\
	TAILQ_FOREACH(bif, &sc->sc_iflist, bif_next) {			\
		if (len < sizeof (bpreq))				\
			break;						\
									\
		if ((bif->bif_flags & IFBIF_STP) == 0)			\
			continue;					\
									\
		bp = &bif->bif_stp;					\
		bpreq.ifbp_portno = bif->bif_ifp->if_index & 0xfff;	\
		bpreq.ifbp_fwd_trans = bp->bp_forward_transitions;	\
		bpreq.ifbp_design_cost = bp->bp_desg_pv.pv_cost;	\
		bpreq.ifbp_design_port = bp->bp_desg_pv.pv_port_id;	\
		bpreq.ifbp_design_bridge = bp->bp_desg_pv.pv_dbridge_id; \
		bpreq.ifbp_design_root = bp->bp_desg_pv.pv_root_id;	\
									\
		memcpy(buf, &bpreq, sizeof (bpreq));			\
		count++;						\
		buf += sizeof (bpreq);					\
		len -= sizeof (bpreq);					\
	}								\
									\
	BRIDGE_UNLOCK(sc);						\
	bifstp->ifbpstp_len = sizeof (bpreq) * count;			\
	error = copyout(outbuf, bifstp->ifbpstp_req, bifstp->ifbpstp_len); \
	BRIDGE_LOCK(sc);						\
	_FREE(outbuf, M_TEMP);						\
	return (error);							\
} while (0)

static int
bridge_ioctl_gifsstp32(struct bridge_softc *sc, void *arg)
{
	struct ifbpstpconf32 *bifstp = arg;
	int error = 0;

	BRIDGE_IOCTL_GIFSSTP;

	return (error);
}

static int
bridge_ioctl_gifsstp64(struct bridge_softc *sc, void *arg)
{
	struct ifbpstpconf64 *bifstp = arg;
	int error = 0;

	BRIDGE_IOCTL_GIFSSTP;

	return (error);
}

static int
bridge_ioctl_sproto(struct bridge_softc *sc, void *arg)
{
#if BRIDGESTP
	struct ifbrparam *param = arg;

	return (bstp_set_protocol(&sc->sc_stp, param->ifbrp_proto));
#else /* !BRIDGESTP */
#pragma unused(sc, arg)
	return (EOPNOTSUPP);
#endif /* !BRIDGESTP */
}

static int
bridge_ioctl_stxhc(struct bridge_softc *sc, void *arg)
{
#if BRIDGESTP
	struct ifbrparam *param = arg;

	return (bstp_set_holdcount(&sc->sc_stp, param->ifbrp_txhc));
#else /* !BRIDGESTP */
#pragma unused(sc, arg)
	return (EOPNOTSUPP);
#endif /* !BRIDGESTP */
}

/*
 * bridge_ifdetach:
 *
 *	Detach an interface from a bridge.  Called when a member
 *	interface is detaching.
 */
__private_extern__ void
bridge_ifdetach(struct bridge_iflist *bif, struct ifnet *ifp)
{
	struct bridge_softc *sc = ifp->if_bridge;

#if BRIDGE_DEBUG
	printf("%s: %s%d\n", __func__, ifnet_name(ifp), ifnet_unit(ifp));
#endif

	/* Check if the interface is a bridge member */
	if (sc != NULL) {
		BRIDGE_LOCK(sc);

		bif = bridge_lookup_member_if(sc, ifp);
		if (bif != NULL)
			bridge_delete_member(sc, bif, 1);

		BRIDGE_UNLOCK(sc);
		return;
	}

	/* Check if the interface is a span port */
	lck_mtx_lock(bridge_list_mtx);
	LIST_FOREACH(sc, &bridge_list, sc_list) {
		BRIDGE_LOCK(sc);
		TAILQ_FOREACH(bif, &sc->sc_spanlist, bif_next)
			if (ifp == bif->bif_ifp) {
				bridge_delete_span(sc, bif);
				break;
			}

		BRIDGE_UNLOCK(sc);
	}
	lck_mtx_unlock(bridge_list_mtx);
}

/*
 * bridge_init:
 *
 *	Initialize a bridge interface.
 */
static int
bridge_init(struct ifnet *ifp)
{
	struct bridge_softc *sc = (struct bridge_softc *)ifp->if_softc;
	struct timespec ts;
	errno_t error;

	BRIDGE_LOCK_ASSERT(sc);

	if ((ifnet_flags(ifp) & IFF_RUNNING))
		return (0);

	ts.tv_sec = bridge_rtable_prune_period;
	ts.tv_nsec = 0;
	bsd_timeout(bridge_timer, sc, &ts);

	error = ifnet_set_flags(ifp, IFF_RUNNING, IFF_RUNNING);
#if BRIDGESTP
	if (error == 0)
		bstp_init(&sc->sc_stp);		/* Initialize Spanning Tree */
#endif /* BRIDGESTP */

	return (error);
}

/*
 * bridge_ifstop:
 *
 *	Stop the bridge interface.
 */
static void
bridge_ifstop(struct ifnet *ifp, __unused int disable)
{
	struct bridge_softc *sc = ifp->if_softc;

	BRIDGE_LOCK_ASSERT(sc);

	if ((ifnet_flags(ifp) & IFF_RUNNING) == 0)
		return;

	bsd_untimeout(bridge_timer, sc);
#if BRIDGESTP
	bstp_stop(&sc->sc_stp);
#endif /* BRIDGESTP */

	bridge_rtflush(sc, IFBF_FLUSHDYN);

	(void) ifnet_set_flags(ifp, 0, IFF_RUNNING);
}

/*
 * bridge_enqueue:
 *
 *	Enqueue a packet on a bridge member interface.
 *
 */
static int
bridge_enqueue(struct bridge_softc *sc, struct ifnet *dst_ifp, struct mbuf *m)
{
	int len, error = 0;
	short mflags;
	struct mbuf *m0;

	VERIFY(dst_ifp != NULL);

	/*
	 * We may be sending a fragment so traverse the mbuf
	 *
	 * NOTE: bridge_fragment() is called only when PFIL_HOOKS is enabled.
	 */
	for (; m; m = m0) {
		errno_t _error;
		struct flowadv adv = { FADV_SUCCESS };

		m0 = m->m_nextpkt;
		m->m_nextpkt = NULL;

		len = m->m_pkthdr.len;
		mflags = m->m_flags;
		m->m_flags |= M_PROTO1; /* set to avoid loops */

#if HAS_IF_CAP
		/*
		 * If underlying interface can not do VLAN tag insertion itself
		 * then attach a packet tag that holds it.
		 */
		if ((m->m_flags & M_VLANTAG) &&
		    (dst_ifp->if_capenable & IFCAP_VLAN_HWTAGGING) == 0) {
			m = ether_vlanencap(m, m->m_pkthdr.ether_vtag);
			if (m == NULL) {
				printf("%s: %s%d: unable to prepend VLAN "
				    "header\n", __func__, ifnet_name(dst_ifp),
				    ifnet_unit(dst_ifp));
				(void) ifnet_stat_increment_out(dst_ifp,
				    0, 0, 1);
				continue;
			}
			m->m_flags &= ~M_VLANTAG;
		}
#endif /* HAS_IF_CAP */

		_error = dlil_output(dst_ifp, 0, m, NULL, NULL, 1, &adv);

		/* Preserve existing error value */
		if (error == 0) {
			if (_error != 0)
				error = _error;
			else if (adv.code == FADV_FLOW_CONTROLLED)
				error = EQFULL;
			else if (adv.code == FADV_SUSPENDED)
				error = EQSUSPENDED;
		}

		if (_error == 0) {
			(void) ifnet_stat_increment_out(sc->sc_ifp, 1, len, 0);
		} else {
			(void) ifnet_stat_increment_out(sc->sc_ifp, 0, 0, 1);
		}
	}

	return (error);
}

#if HAS_BRIDGE_DUMMYNET
/*
 * bridge_dummynet:
 *
 *	Receive a queued packet from dummynet and pass it on to the output
 *	interface.
 *
 *	The mbuf has the Ethernet header already attached.
 */
static void
bridge_dummynet(struct mbuf *m, struct ifnet *ifp)
{
	struct bridge_softc *sc;

	sc = ifp->if_bridge;

	/*
	 * The packet didnt originate from a member interface. This should only
	 * ever happen if a member interface is removed while packets are
	 * queued for it.
	 */
	if (sc == NULL) {
		m_freem(m);
		return;
	}

	if (PFIL_HOOKED(&inet_pfil_hook)
#ifdef INET6
	    || PFIL_HOOKED(&inet6_pfil_hook)
#endif
	    ) {
		if (bridge_pfil(&m, sc->sc_ifp, ifp, PFIL_OUT) != 0)
			return;
		if (m == NULL)
			return;
	}

	(void) bridge_enqueue(sc, ifp, m);
}
#endif /* HAS_BRIDGE_DUMMYNET */

#if BRIDGE_MEMBER_OUT_FILTER
/*
 * bridge_member_output:
 *
 *	Send output from a bridge member interface.  This
 *	performs the bridging function for locally originated
 *	packets.
 *
 *	The mbuf has the Ethernet header already attached.  We must
 *	enqueue or free the mbuf before returning.
 */
static int
bridge_member_output(struct ifnet *ifp, struct mbuf *m,
    __unused struct sockaddr *sa, __unused struct rtentry *rt)
{
	struct ether_header *eh;
	struct ifnet *dst_if;
	struct bridge_softc *sc;
	uint16_t vlan;

#if BRIDGE_DEBUG
	if (if_bridge_debug)
		printf("%s: ifp %p %s%d\n", __func__, ifp, ifnet_name(ifp),
		    ifnet_unit(ifp));
#endif /* BRIDGE_DEBUG */

	if (m->m_len < ETHER_HDR_LEN) {
		m = m_pullup(m, ETHER_HDR_LEN);
		if (m == NULL)
			return (0);
	}

	eh = mtod(m, struct ether_header *);
	sc = ifp->if_bridge;
	vlan = VLANTAGOF(m);

	BRIDGE_LOCK(sc);

	/*
	 * APPLE MODIFICATION
	 * If the packet is an 802.1X ethertype, then only send on the
	 * original output interface.
	 */
	if (eh->ether_type == htons(ETHERTYPE_PAE)) {
		dst_if = ifp;
		goto sendunicast;
	}

	/*
	 * If bridge is down, but the original output interface is up,
	 * go ahead and send out that interface.  Otherwise, the packet
	 * is dropped below.
	 */
	if ((sc->sc_ifp->if_flags & IFF_RUNNING) == 0) {
		dst_if = ifp;
		goto sendunicast;
	}

	/*
	 * If the packet is a multicast, or we don't know a better way to
	 * get there, send to all interfaces.
	 */
	if (ETHER_IS_MULTICAST(eh->ether_dhost))
		dst_if = NULL;
	else
		dst_if = bridge_rtlookup(sc, eh->ether_dhost, vlan);
	if (dst_if == NULL) {
		struct bridge_iflist *bif;
		struct mbuf *mc;
		int error = 0, used = 0;

		bridge_span(sc, m);

		BRIDGE_LOCK2REF(sc, error);
		if (error) {
			m_freem(m);
			return (0);
		}

		TAILQ_FOREACH(bif, &sc->sc_iflist, bif_next) {
			dst_if = bif->bif_ifp;

			if (dst_if->if_type == IFT_GIF)
				continue;
			if ((dst_if->if_flags & IFF_RUNNING) == 0)
				continue;

			/*
			 * If this is not the original output interface,
			 * and the interface is participating in spanning
			 * tree, make sure the port is in a state that
			 * allows forwarding.
			 */
			if (dst_if != ifp && (bif->bif_flags & IFBIF_STP) &&
			    bif->bif_stp.bp_state == BSTP_IFSTATE_DISCARDING)
				continue;

			if (LIST_NEXT(bif, bif_next) == NULL) {
				used = 1;
				mc = m;
			} else {
				mc = m_copypacket(m, M_DONTWAIT);
				if (mc == NULL) {
					(void) ifnet_stat_increment_out(
					    sc->sc_ifp, 0, 0, 1);
					continue;
				}
			}

			(void) bridge_enqueue(sc, dst_if, mc);
		}
		if (used == 0)
			m_freem(m);
		BRIDGE_UNREF(sc);
		return (0);
	}

sendunicast:
	/*
	 * XXX Spanning tree consideration here?
	 */

	bridge_span(sc, m);
	if ((dst_if->if_flags & IFF_RUNNING) == 0) {
		m_freem(m);
		BRIDGE_UNLOCK(sc);
		return (0);
	}

	BRIDGE_UNLOCK(sc);
	(void) bridge_enqueue(sc, dst_if, m);
	return (0);
}
#endif /* BRIDGE_MEMBER_OUT_FILTER */

#if APPLE_BRIDGE_HWCKSUM_SUPPORT
static struct mbuf *
bridge_fix_txcsum(struct mbuf *m)
{
	/*
	 * basic tests indicate that the vast majority of packets being
	 * processed here have an Ethernet header mbuf pre-pended to them
	 * (the first case below)
	 *
	 * the second highest are those where the Ethernet and IP/TCP/UDP
	 * headers are all in one mbuf (second case below)
	 *
	 * the third case has, in fact, never hit for me -- although if I
	 * comment out the first two cases, that code works for them, so I
	 * consider it a decent general solution
	 */
	int amt = ETHER_HDR_LEN;
	int hlen = M_CSUM_DATA_IPv4_IPHL(m->m_pkthdr.csum_data);
	int off = M_CSUM_DATA_IPv4_OFFSET(m->m_pkthdr.csum_data);

	/*
	 * NOTE we should never get vlan-attached packets here;
	 * support for those COULD be added, but we don't use them
	 * and it really kinda slows things down to worry about them
	 */

#ifdef DIAGNOSTIC
	if (m_tag_find(m, PACKET_TAG_VLAN, NULL) != NULL) {
		printf("%s: transmitting packet tagged with VLAN?\n", __func__);
		KASSERT(0);
		m_freem(m);
		return (NULL);
	}
#endif

	if (m->m_pkthdr.csum_flags & M_CSUM_IPv4) {
		amt += hlen;
	}
	if (m->m_pkthdr.csum_flags & M_CSUM_TCPv4) {
		amt += off + sizeof (uint16_t);
	}

	if (m->m_pkthdr.csum_flags & M_CSUM_UDPv4) {
		amt += off + sizeof (uint16_t);
	}

	if (m->m_len == ETHER_HDR_LEN) {
		/*
		 * this is the case where there's an Ethernet header in an
		 * mbuf the first mbuf is the Ethernet header -- just strip
		 * it off and do the checksum
		 */
		/* set up m_ip so the cksum operations work */
		struct mbuf *m_ip = m->m_next;

		/* APPLE MODIFICATION 22 Apr 2008 <mvega@apple.com>
		 *  <rdar://5817385> Clear the m_tag list before setting
		 *  M_PKTHDR.
		 *
		 *  If this m_buf chain was extended via M_PREPEND(), then
		 *  m_ip->m_pkthdr is identical to m->m_pkthdr (see
		 *  M_MOVE_PKTHDR()). The only thing preventing access to this
		 *  invalid packet header data is the fact that the M_PKTHDR
		 *  flag is clear, i.e., m_ip->m_flag & M_PKTHDR == 0, but we're
		 *  about to set the M_PKTHDR flag, so to be safe we initialize,
		 *  more accurately, we clear, m_ip->m_pkthdr.tags via
		 *  m_tag_init().
		 *
		 *  Suppose that we do not do this; if m_pullup(), below, fails,
		 *  then m_ip will be freed along with m_ip->m_pkthdr.tags, but
		 *  we will also free m soon after, via m_freem(), and
		 *  consequently attempt to free m->m_pkthdr.tags in the
		 *  process. The problem is that m->m_pkthdr.tags will have
		 *  already been freed by virtue of being equal to
		 *  m_ip->m_pkthdr.tags. Attempts to dereference
		 *  m->m_pkthdr.tags in m_tag_delete_chain() will result in a
		 *  panic.
		 */
		m_tag_init(m_ip);
		/* END MODIFICATION */
		m_ip->m_flags |= M_PKTHDR;
		m_ip->m_pkthdr.csum_flags = m->m_pkthdr.csum_flags;
		m_ip->m_pkthdr.csum_data = m->m_pkthdr.csum_data;
		m_ip->m_pkthdr.len = m->m_pkthdr.len - ETHER_HDR_LEN;

		/*
		 * set up the header mbuf so we can prepend it
		 * back on again later
		 */
		m->m_pkthdr.csum_flags = 0;
		m->m_pkthdr.csum_data = 0;
		m->m_pkthdr.len = ETHER_HDR_LEN;
		m->m_next = NULL;

		/* now do the checksums we need -- first IP */
		if (m_ip->m_pkthdr.csum_flags & M_CSUM_IPv4) {
			/*
			 * make sure the IP header (or at least the part with
			 * the cksum) is there
			 */
			m_ip = m_pullup(m_ip, sizeof (struct ip));
			if (m_ip == NULL) {
				printf("%s: failed to flatten header\n",
				    __func__);
				m_freem(m);
				return (NULL);
			}

			/* now do the checksum */
			{
				struct ip *ip = mtod(m_ip, struct ip *);
				ip->ip_sum = in_cksum(m_ip, hlen);

#ifdef VERY_VERY_VERY_DIAGNOSTIC
				printf("%s: performed IPv4 checksum\n",
				    __func__);
#endif
			}
		}

		/* now do a TCP or UDP delayed checksum */
		if (m_ip->m_pkthdr.csum_flags & (M_CSUM_TCPv4|M_CSUM_UDPv4)) {
			in_delayed_cksum(m_ip);

#ifdef VERY_VERY_VERY_DIAGNOSTIC
			printf("%s: performed TCPv4/UDPv4 checksum\n",
			    __func__);
#endif
		}

		/* now attach the ethernet header back onto the IP packet */
		m->m_next = m_ip;
		m->m_pkthdr.len += m_length(m_ip);

		/*
		 * clear the M_PKTHDR flags on the ip packet (again,
		 * we re-attach later)
		 */
		m_ip->m_flags &= ~M_PKTHDR;

		/* and clear any csum flags */
		m->m_pkthdr.csum_flags &=
		    ~(M_CSUM_TCPv4|M_CSUM_UDPv4|M_CSUM_IPv4);
	} else if (m->m_len >= amt) {
		/*
		 * everything fits in the first mbuf, so futz with
		 * m->m_data, m->m_len and m->m_pkthdr.len to make it work
		 */
		m->m_len -= ETHER_HDR_LEN;
		m->m_data += ETHER_HDR_LEN;
		m->m_pkthdr.len -= ETHER_HDR_LEN;

		/* now do the checksums we need -- first IP */
		if (m->m_pkthdr.csum_flags & M_CSUM_IPv4) {
			struct ip *ip = mtod(m, struct ip *);
			ip->ip_sum = in_cksum(m, hlen);

#ifdef VERY_VERY_VERY_DIAGNOSTIC
			printf("%s: performed IPv4 checksum\n", __func__);
#endif
		}

		// now do a TCP or UDP delayed checksum
		if (m->m_pkthdr.csum_flags & (M_CSUM_TCPv4|M_CSUM_UDPv4)) {
			in_delayed_cksum(m);

#ifdef VERY_VERY_VERY_DIAGNOSTIC
			printf("%s: performed TCPv4/UDPv4 checksum\n",
			    __func__);
#endif
		}

		/* now stick the ethernet header back on */
		m->m_len += ETHER_HDR_LEN;
		m->m_data -= ETHER_HDR_LEN;
		m->m_pkthdr.len += ETHER_HDR_LEN;

		/* and clear any csum flags */
		m->m_pkthdr.csum_flags &=
		    ~(M_CSUM_TCPv4|M_CSUM_UDPv4|M_CSUM_IPv4);
	} else {
		struct mbuf *m_ip;

		/*
		 * general case -- need to simply split it off and deal
		 * first, calculate how much needs to be made writable
		 * (we may have a read-only mbuf here)
		 */
		hlen = M_CSUM_DATA_IPv4_IPHL(m->m_pkthdr.csum_data);
#if PARANOID
		off = M_CSUM_DATA_IPv4_OFFSET(m->m_pkthdr.csum_data);

		if (m->m_pkthdr.csum_flags & M_CSUM_IPv4) {
			amt += hlen;
		}

		if (m->m_pkthdr.csum_flags & M_CSUM_TCPv4) {
			amt += sizeof (struct tcphdr *);
			amt += off;
		}

		if (m->m_pkthdr.csum_flags & M_CSUM_UDPv4) {
			amt += sizeof (struct udphdr *);
			amt += off;
		}
#endif

		/*
		 * now split the ethernet header off of the IP packet
		 * (we'll re-attach later)
		 */
		m_ip = m_split(m, ETHER_HDR_LEN, M_NOWAIT);
		if (m_ip == NULL) {
			printf("%s: could not split ether header\n", __func__);

			m_freem(m);
			return (NULL);
		}

#if PARANOID
		/*
		 * make sure that the IP packet is writable
		 * for the portion we need
		 */
		if (m_makewritable(&m_ip, 0, amt, M_DONTWAIT) != 0) {
			printf("%s: could not make %d bytes writable\n",
			    __func__, amt);

			m_freem(m);
			m_freem(m_ip);
			return (NULL);
		}
#endif

		m_ip->m_pkthdr.csum_flags = m->m_pkthdr.csum_flags;
		m_ip->m_pkthdr.csum_data = m->m_pkthdr.csum_data;

		m->m_pkthdr.csum_flags = 0;
		m->m_pkthdr.csum_data = 0;

		/* now do the checksums we need -- first IP */
		if (m_ip->m_pkthdr.csum_flags & M_CSUM_IPv4) {
			/*
			 * make sure the IP header (or at least the part
			 * with the cksum) is there
			 */
			m_ip = m_pullup(m_ip, sizeof (struct ip));
			if (m_ip == NULL) {
				printf("%s: failed to flatten header\n",
				    __func__);
				m_freem(m);
				return (NULL);
			}

			/* now do the checksum */
			{
				struct ip *ip = mtod(m_ip, struct ip *);
				ip->ip_sum = in_cksum(m_ip, hlen);

#ifdef VERY_VERY_VERY_DIAGNOSTIC
				printf("%s: performed IPv4 checksum\n",
				    __func__);
#endif
			}
		}

		/* now do a TCP or UDP delayed checksum */
		if (m_ip->m_pkthdr.csum_flags & (M_CSUM_TCPv4|M_CSUM_UDPv4)) {
			in_delayed_cksum(m_ip);

#ifdef VERY_VERY_VERY_DIAGNOSTIC
			printf("%s: performed TCPv4/UDPv4 checksum\n",
			    __func__);
#endif
		}

		// now attach the ethernet header back onto the IP packet
		m->m_next = m_ip;
		m->m_pkthdr.len += m_length(m_ip);

		/*
		 * clear the M_PKTHDR flags on the ip packet
		 * (again, we re-attach later)
		 */
		m_ip->m_flags &= ~M_PKTHDR;

		/* and clear any csum flags */
		m->m_pkthdr.csum_flags &=
		    ~(M_CSUM_TCPv4|M_CSUM_UDPv4|M_CSUM_IPv4);
	}

	return (m);
}
#endif

/*
 * Output callback.
 *
 * This routine is called externally from above only when if_bridge_txstart
 * is disabled; otherwise it is called internally by bridge_start().
 */
static int
bridge_output(struct ifnet *ifp, struct mbuf *m)
{
	struct bridge_softc *sc = ifnet_softc(ifp);
	struct ether_header *eh;
	struct ifnet *dst_if;
	int error = 0;

	eh = mtod(m, struct ether_header *);
	dst_if = NULL;

	BRIDGE_LOCK(sc);
	if (!(m->m_flags & (M_BCAST|M_MCAST))) {
		dst_if = bridge_rtlookup(sc, eh->ether_dhost, 0);
	}

#if APPLE_BRIDGE_HWCKSUM_SUPPORT
	/*
	 * APPLE MODIFICATION - if the packet needs a checksum
	 * (i.e., checksum has been deferred for HW support)
	 * AND the destination interface doesn't support HW
	 * checksums, then we need to fix-up the checksum here
	 */
	if ((m->m_pkthdr.csum_flags &
	    (M_CSUM_TCPv4|M_CSUM_UDPv4|M_CSUM_IPv4)) &&
	    (dst_if == NULL ||
	    (dst_if->if_csum_flags_tx & m->m_pkthdr.csum_flags) !=
	    m->m_pkthdr.csum_flags)) {
		m = bridge_fix_txcsum(m);
		if (m == NULL) {
			BRIDGE_UNLOCK(sc);
			return (0);
		}
	}
#else
	if (eh->ether_type == htons(ETHERTYPE_IP))
		mbuf_outbound_finalize(m, PF_INET, sizeof (*eh));
	else
		m->m_pkthdr.csum_flags = 0;
#endif /* APPLE_BRIDGE_HWCKSUM_SUPPORT */

	atomic_add_64(&ifp->if_obytes, m->m_pkthdr.len);
	atomic_add_64(&ifp->if_opackets, 1);

#if NBPFILTER > 0
	if (sc->sc_bpf_output)
		bridge_bpf_output(ifp, m);
#endif

	if (dst_if == NULL) {
		/* callee will unlock */
		bridge_broadcast(sc, ifp, m, 0);
	} else {
		BRIDGE_UNLOCK(sc);
		error = bridge_enqueue(sc, dst_if, m);
	}

	return (error);
}

/*
 * bridge_start:
 *
 *	Start output on a bridge.
 *
 * This routine is invoked by the start worker thread; because we never call
 * it directly, there is no need do deploy any serialization mechanism other
 * than what's already used by the worker thread, i.e. this is already single
 * threaded.
 *
 * This routine is called only when if_bridge_txstart is enabled.
 */
static void
bridge_start(struct ifnet *ifp)
{
	struct mbuf *m;

	for (;;) {
		if (ifnet_dequeue(ifp, &m) != 0)
			break;

		(void) bridge_output(ifp, m);
	}
}

/*
 * bridge_forward:
 *
 *	The forwarding function of the bridge.
 *
 *	NOTE: Releases the lock on return.
 */
static void
bridge_forward(struct bridge_softc *sc, struct bridge_iflist *sbif,
    struct mbuf *m)
{
	struct bridge_iflist *dbif;
	struct ifnet *src_if, *dst_if, *ifp;
	struct ether_header *eh;
	uint16_t vlan;
	uint8_t *dst;
	int error;

	lck_mtx_assert(sc->sc_mtx, LCK_MTX_ASSERT_OWNED);

#if BRIDGE_DEBUG
	if (if_bridge_debug)
		printf("%s: %s%d m%p\n", __func__, ifnet_name(sc->sc_ifp),
		    ifnet_unit(sc->sc_ifp), m);
#endif /* BRIDGE_DEBUG */

	src_if = m->m_pkthdr.rcvif;
	ifp = sc->sc_ifp;

	(void) ifnet_stat_increment_in(ifp, 1, m->m_pkthdr.len, 0);
	vlan = VLANTAGOF(m);


	if ((sbif->bif_flags & IFBIF_STP) &&
	    sbif->bif_stp.bp_state == BSTP_IFSTATE_DISCARDING)
		goto drop;

	eh = mtod(m, struct ether_header *);
	dst = eh->ether_dhost;

	/* If the interface is learning, record the address. */
	if (sbif->bif_flags & IFBIF_LEARNING) {
		error = bridge_rtupdate(sc, eh->ether_shost, vlan,
		    sbif, 0, IFBAF_DYNAMIC);
		/*
		 * If the interface has addresses limits then deny any source
		 * that is not in the cache.
		 */
		if (error && sbif->bif_addrmax)
			goto drop;
	}

	if ((sbif->bif_flags & IFBIF_STP) != 0 &&
	    sbif->bif_stp.bp_state == BSTP_IFSTATE_LEARNING)
		goto drop;

	/*
	 * At this point, the port either doesn't participate
	 * in spanning tree or it is in the forwarding state.
	 */

	/*
	 * If the packet is unicast, destined for someone on
	 * "this" side of the bridge, drop it.
	 */
	if ((m->m_flags & (M_BCAST|M_MCAST)) == 0) {
		dst_if = bridge_rtlookup(sc, dst, vlan);
		if (src_if == dst_if)
			goto drop;
	} else {
		/*
		 * Check if its a reserved multicast address, any address
		 * listed in 802.1D section 7.12.6 may not be forwarded by the
		 * bridge.
		 * This is currently 01-80-C2-00-00-00 to 01-80-C2-00-00-0F
		 */
		if (dst[0] == 0x01 && dst[1] == 0x80 &&
		    dst[2] == 0xc2 && dst[3] == 0x00 &&
		    dst[4] == 0x00 && dst[5] <= 0x0f)
			goto drop;


		/* ...forward it to all interfaces. */
		atomic_add_64(&ifp->if_imcasts, 1);
		dst_if = NULL;
	}

	/*
	 * If we have a destination interface which is a member of our bridge,
	 * OR this is a unicast packet, push it through the bpf(4) machinery.
	 * For broadcast or multicast packets, don't bother because it will
	 * be reinjected into ether_input. We do this before we pass the packets
	 * through the pfil(9) framework, as it is possible that pfil(9) will
	 * drop the packet, or possibly modify it, making it difficult to debug
	 * firewall issues on the bridge.
	 */
#if NBPFILTER > 0
	if (eh->ether_type == htons(ETHERTYPE_RSN_PREAUTH) ||
	    dst_if != NULL || (m->m_flags & (M_BCAST | M_MCAST)) == 0) {
		m->m_pkthdr.rcvif = ifp;
		if (sc->sc_bpf_input)
			bridge_bpf_input(ifp, m);
	}
#endif /* NBPFILTER */

#if defined(PFIL_HOOKS)
	/* run the packet filter */
	if (PFIL_HOOKED(&inet_pfil_hook)
#ifdef INET6
	    || PFIL_HOOKED(&inet6_pfil_hook)
#endif /* INET6 */
	    ) {
		BRIDGE_UNLOCK(sc);
		if (bridge_pfil(&m, ifp, src_if, PFIL_IN) != 0)
			return;
		if (m == NULL)
			return;
		BRIDGE_LOCK(sc);
	}
#endif /* PFIL_HOOKS */

	if (dst_if == NULL) {
		/*
		 * Clear any in-bound checksum flags for this packet.
		 */
		mbuf_inbound_modified(m);

		bridge_broadcast(sc, src_if, m, 1);

		return;
	}

	/*
	 * At this point, we're dealing with a unicast frame
	 * going to a different interface.
	 */
	if ((dst_if->if_flags & IFF_RUNNING) == 0)
		goto drop;

	dbif = bridge_lookup_member_if(sc, dst_if);
	if (dbif == NULL)
		/* Not a member of the bridge (anymore?) */
		goto drop;

	/* Private segments can not talk to each other */
	if (sbif->bif_flags & dbif->bif_flags & IFBIF_PRIVATE)
		goto drop;

	if ((dbif->bif_flags & IFBIF_STP) &&
	    dbif->bif_stp.bp_state == BSTP_IFSTATE_DISCARDING)
		goto drop;

#if HAS_DHCPRA_MASK
	/* APPLE MODIFICATION <rdar://6985737> */
	if ((dst_if->if_extflags & IFEXTF_DHCPRA_MASK) != 0) {
		m = ip_xdhcpra_output(dst_if, m);
		if (!m) {
			++sc->sc_sc.sc_ifp.if_xdhcpra;
			return;
		}
	}
#endif /* HAS_DHCPRA_MASK */

	BRIDGE_UNLOCK(sc);

#if defined(PFIL_HOOKS)
	if (PFIL_HOOKED(&inet_pfil_hook)
#ifdef INET6
	    || PFIL_HOOKED(&inet6_pfil_hook)
#endif
	    ) {
		if (bridge_pfil(&m, ifp, dst_if, PFIL_OUT) != 0)
			return;
		if (m == NULL)
			return;
	}
#endif /* PFIL_HOOKS */

	/*
	 * Clear any in-bound checksum flags for this packet.
	 */
	mbuf_inbound_modified(m);

	(void) bridge_enqueue(sc, dst_if, m);
	return;

drop:
	BRIDGE_UNLOCK(sc);
	m_freem(m);
}

#if BRIDGE_DEBUG

char *ether_ntop(char *, size_t, const u_char *);

__private_extern__ char *
ether_ntop(char *buf, size_t len, const u_char *ap)
{
	snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
	    ap[0], ap[1], ap[2], ap[3], ap[4], ap[5]);

	return (buf);
}

#endif /* BRIDGE_DEBUG */

/*
 * bridge_input:
 *
 *	Filter input from a member interface.  Queue the packet for
 *	bridging if it is not for us.
 */
__private_extern__ errno_t
bridge_input(struct ifnet *ifp, struct mbuf *m, __unused void *frame_header)
{
	struct bridge_softc *sc = ifp->if_bridge;
	struct bridge_iflist *bif, *bif2;
	struct ifnet *bifp;
	struct ether_header *eh;
	struct mbuf *mc, *mc2;
	uint16_t vlan;
	int error;

#if BRIDGE_DEBUG
	if (if_bridge_debug)
		printf("%s: %s%d from %s%d m %p data %p\n", __func__,
		    ifnet_name(sc->sc_ifp), ifnet_unit(sc->sc_ifp),
		    ifnet_name(ifp), ifnet_unit(ifp), m, mbuf_data(m));
#endif /* BRIDGE_DEBUG */

	if ((sc->sc_ifp->if_flags & IFF_RUNNING) == 0) {
#if BRIDGE_DEBUG
		if (if_bridge_debug)
			printf("%s: %s%d not running passing along\n",
			    __func__, ifnet_name(sc->sc_ifp),
			    ifnet_unit(sc->sc_ifp));
#endif /* BRIDGE_DEBUG */
		return (0);
	}

	bifp = sc->sc_ifp;
	vlan = VLANTAGOF(m);

#ifdef IFF_MONITOR
	/*
	 * Implement support for bridge monitoring. If this flag has been
	 * set on this interface, discard the packet once we push it through
	 * the bpf(4) machinery, but before we do, increment the byte and
	 * packet counters associated with this interface.
	 */
	if ((bifp->if_flags & IFF_MONITOR) != 0) {
		m->m_pkthdr.rcvif  = bifp;
		BRIDGE_BPF_MTAP_INPUT(sc, m);
		(void) ifnet_stat_increment_in(bifp, 1, m->m_pkthdr.len, 0);
		m_freem(m);
		return (EJUSTRETURN);
	}
#endif /* IFF_MONITOR */

	/*
	 * Need to clear the promiscous flags otherwise it will be
	 * dropped by DLIL after processing filters
	 */
	if ((mbuf_flags(m) & MBUF_PROMISC))
		mbuf_setflags_mask(m, 0, MBUF_PROMISC);

	BRIDGE_LOCK(sc);
	bif = bridge_lookup_member_if(sc, ifp);
	if (bif == NULL) {
		BRIDGE_UNLOCK(sc);
#if BRIDGE_DEBUG
		if (if_bridge_debug)
			printf("%s: %s%d bridge_lookup_member_if failed\n",
			    __func__, ifnet_name(sc->sc_ifp),
			    ifnet_unit(sc->sc_ifp));
#endif /* BRIDGE_DEBUG */
		return (0);
	}

	eh = mtod(m, struct ether_header *);

	bridge_span(sc, m);

	if (m->m_flags & (M_BCAST|M_MCAST)) {

#if BRIDGE_DEBUG
		if (if_bridge_debug)
			if ((m->m_flags & M_MCAST))
				printf("%s: mulicast: "
				    "%02x:%02x:%02x:%02x:%02x:%02x\n",
				    __func__,
				    eh->ether_dhost[0], eh->ether_dhost[1],
				    eh->ether_dhost[2], eh->ether_dhost[3],
				    eh->ether_dhost[4], eh->ether_dhost[5]);
#endif /* BRIDGE_DEBUG */

		/* Tap off 802.1D packets; they do not get forwarded. */
		if (memcmp(eh->ether_dhost, bstp_etheraddr,
		    ETHER_ADDR_LEN) == 0) {
#if BRIDGESTP
			m = bstp_input(&bif->bif_stp, ifp, m);
#else /* !BRIDGESTP */
			m_freem(m);
			m = NULL;
#endif /* !BRIDGESTP */
			if (m == NULL) {
				BRIDGE_UNLOCK(sc);
				return (EJUSTRETURN);
			}
		}

		if ((bif->bif_flags & IFBIF_STP) &&
		    bif->bif_stp.bp_state == BSTP_IFSTATE_DISCARDING) {
			BRIDGE_UNLOCK(sc);
			return (0);
		}

		/*
		 * Make a deep copy of the packet and enqueue the copy
		 * for bridge processing; return the original packet for
		 * local processing.
		 */
		mc = m_dup(m, M_DONTWAIT);
		if (mc == NULL) {
			BRIDGE_UNLOCK(sc);
			return (0);
		}

		/*
		 * Perform the bridge forwarding function with the copy.
		 *
		 * Note that bridge_forward calls BRIDGE_UNLOCK
		 */
		bridge_forward(sc, bif, mc);

		/*
		 * Reinject the mbuf as arriving on the bridge so we have a
		 * chance at claiming multicast packets. We can not loop back
		 * here from ether_input as a bridge is never a member of a
		 * bridge.
		 */
		KASSERT(bifp->if_bridge == NULL,
		    ("loop created in bridge_input"));
		mc2 = m_dup(m, M_DONTWAIT);
		if (mc2 != NULL) {
			/* Keep the layer3 header aligned */
			int i = min(mc2->m_pkthdr.len, max_protohdr);
			mc2 = m_copyup(mc2, i, ETHER_ALIGN);
		}
		if (mc2 != NULL) {
			// mark packet as arriving on the bridge
			mc2->m_pkthdr.rcvif = bifp;
			mc2->m_pkthdr.header = mbuf_data(mc2);

#if NBPFILTER > 0
			if (sc->sc_bpf_input)
				bridge_bpf_input(bifp, mc2);
#endif /* NBPFILTER */
			(void) mbuf_setdata(mc2,
			    (char *)mbuf_data(mc2) + ETHER_HDR_LEN,
			    mbuf_len(mc2) - ETHER_HDR_LEN);
			(void) mbuf_pkthdr_adjustlen(mc2, - ETHER_HDR_LEN);

			(void) ifnet_stat_increment_in(bifp, 1,
			    mbuf_pkthdr_len(mc2), 0);

#if BRIDGE_DEBUG
			if (if_bridge_debug)
				printf("%s: %s%d mcast for us\n", __func__,
				    ifnet_name(sc->sc_ifp),
				    ifnet_unit(sc->sc_ifp));
#endif /* BRIDGE_DEBUG */

			dlil_input_packet_list(bifp, mc2);
		}

		/* Return the original packet for local processing. */
		return (0);
	}

	if ((bif->bif_flags & IFBIF_STP) &&
	    bif->bif_stp.bp_state == BSTP_IFSTATE_DISCARDING) {
		BRIDGE_UNLOCK(sc);
		return (0);
	}

#ifdef DEV_CARP
#   define OR_CARP_CHECK_WE_ARE_DST(iface) \
	|| ((iface)->if_carp \
	    && carp_forus((iface)->if_carp, eh->ether_dhost))
#   define OR_CARP_CHECK_WE_ARE_SRC(iface) \
	|| ((iface)->if_carp \
	    && carp_forus((iface)->if_carp, eh->ether_shost))
#else
#   define OR_CARP_CHECK_WE_ARE_DST(iface)
#   define OR_CARP_CHECK_WE_ARE_SRC(iface)
#endif

#ifdef INET6
#   define OR_PFIL_HOOKED_INET6 \
	|| PFIL_HOOKED(&inet6_pfil_hook)
#else
#   define OR_PFIL_HOOKED_INET6
#endif

#if defined(PFIL_HOOKS)
#define	PFIL_PHYS(sc, ifp, m) do {					\
	if (pfil_local_phys &&						\
	(PFIL_HOOKED(&inet_pfil_hook) OR_PFIL_HOOKED_INET6)) {		\
		if (bridge_pfil(&m, NULL, ifp,				\
		    PFIL_IN) != 0 || m == NULL) {			\
			BRIDGE_UNLOCK(sc);				\
			return (NULL);					\
		}							\
	}								\
} while (0)
#else /* PFIL_HOOKS */
#define	PFIL_PHYS(sc, ifp, m)
#endif /* PFIL_HOOKS */

#define	GRAB_OUR_PACKETS(iface)						\
	if ((iface)->if_type == IFT_GIF)				\
		continue;						\
	/* It is destined for us. */					\
	if (memcmp(ifnet_lladdr((iface)), eh->ether_dhost,		\
	    ETHER_ADDR_LEN) == 0 OR_CARP_CHECK_WE_ARE_DST((iface))) {	\
		if ((iface)->if_type == IFT_BRIDGE) {			\
			BRIDGE_BPF_MTAP_INPUT(sc, m);			\
			/* Filter on the physical interface. */		\
			PFIL_PHYS(sc, iface, m);			\
		}							\
		if (bif->bif_flags & IFBIF_LEARNING) {			\
			error = bridge_rtupdate(sc, eh->ether_shost,	\
			    vlan, bif, 0, IFBAF_DYNAMIC);		\
			if (error && bif->bif_addrmax) {		\
				BRIDGE_UNLOCK(sc);			\
				return (EJUSTRETURN);			\
			}						\
		}							\
		m->m_pkthdr.rcvif = iface;				\
		BRIDGE_UNLOCK(sc);					\
		return (0);						\
	}								\
									\
	/* We just received a packet that we sent out. */		\
	if (memcmp(ifnet_lladdr((iface)), eh->ether_shost,		\
	    ETHER_ADDR_LEN) == 0 OR_CARP_CHECK_WE_ARE_SRC((iface))) {	\
		BRIDGE_UNLOCK(sc);					\
		return (EJUSTRETURN);					\
	}

	/*
	 * Unicast.
	 */
	/*
	 * If the packet is for us, set the packets source as the
	 * bridge, and return the packet back to ether_input for
	 * local processing.
	 */
	if (memcmp(eh->ether_dhost, ifnet_lladdr(bifp),
	    ETHER_ADDR_LEN) == 0 OR_CARP_CHECK_WE_ARE_DST(bifp)) {

		/* Mark the packet as arriving on the bridge interface */
		(void) mbuf_pkthdr_setrcvif(m, bifp);
		mbuf_pkthdr_setheader(m, frame_header);

		/*
		 * If the interface is learning, and the source
		 * address is valid and not multicast, record
		 * the address.
		 */
		if ((bif->bif_flags & IFBIF_LEARNING) != 0 &&
		    ETHER_IS_MULTICAST(eh->ether_shost) == 0 &&
		    (eh->ether_shost[0] | eh->ether_shost[1] |
		    eh->ether_shost[2] | eh->ether_shost[3] |
		    eh->ether_shost[4] | eh->ether_shost[5]) != 0) {
			(void) bridge_rtupdate(sc, eh->ether_shost,
			    vlan, bif, 0, IFBAF_DYNAMIC);
		}

		BRIDGE_BPF_MTAP_INPUT(sc, m);

		(void) mbuf_setdata(m, (char *)mbuf_data(m) + ETHER_HDR_LEN,
		    mbuf_len(m) - ETHER_HDR_LEN);
		(void) mbuf_pkthdr_adjustlen(m, - ETHER_HDR_LEN);

		(void) ifnet_stat_increment_in(bifp, 1, mbuf_pkthdr_len(m), 0);

		BRIDGE_UNLOCK(sc);

#if BRIDGE_DEBUG
		if (if_bridge_debug)
			printf("%s: %s%d packet for bridge\n", __func__,
			    ifnet_name(sc->sc_ifp), ifnet_unit(sc->sc_ifp));
#endif /* BRIDGE_DEBUG */

		dlil_input_packet_list(bifp, m);

		return (EJUSTRETURN);
	}

	/*
	 * if the destination of the packet is for the MAC address of
	 * the member interface itself, then we don't need to forward
	 * it -- just pass it back.  Note that it'll likely just be
	 * dropped by the stack, but if something else is bound to
	 * the interface directly (for example, the wireless stats
	 * protocol -- although that actually uses BPF right now),
	 * then it will consume the packet
	 *
	 * ALSO, note that we do this check AFTER checking for the
	 * bridge's own MAC address, because the bridge may be
	 * using the SAME MAC address as one of its interfaces
	 */
	if (memcmp(eh->ether_dhost, ifnet_lladdr(ifp), ETHER_ADDR_LEN) == 0) {

#ifdef VERY_VERY_VERY_DIAGNOSTIC
			printf("%s: not forwarding packet bound for member "
			    "interface\n", __func__);
#endif
			BRIDGE_UNLOCK(sc);
			return (0);
	}

	/* Now check the all bridge members. */
	TAILQ_FOREACH(bif2, &sc->sc_iflist, bif_next) {
		GRAB_OUR_PACKETS(bif2->bif_ifp)
	}

#undef OR_CARP_CHECK_WE_ARE_DST
#undef OR_CARP_CHECK_WE_ARE_SRC
#undef OR_PFIL_HOOKED_INET6
#undef GRAB_OUR_PACKETS

	/*
	 * Perform the bridge forwarding function.
	 *
	 * Note that bridge_forward calls BRIDGE_UNLOCK
	 */
	bridge_forward(sc, bif, m);

	return (EJUSTRETURN);
}

/*
 * bridge_broadcast:
 *
 *	Send a frame to all interfaces that are members of
 *	the bridge, except for the one on which the packet
 *	arrived.
 *
 *	NOTE: Releases the lock on return.
 */
static void
bridge_broadcast(struct bridge_softc *sc, struct ifnet *src_if,
    struct mbuf *m, int runfilt)
{
#ifndef PFIL_HOOKS
#pragma unused(runfilt)
#endif
	struct bridge_iflist *dbif, *sbif;
	struct mbuf *mc;
	struct ifnet *dst_if;
	int error = 0, used = 0;

	sbif = bridge_lookup_member_if(sc, src_if);

	BRIDGE_LOCK2REF(sc, error);
	if (error) {
		m_freem(m);
		return;
	}

#ifdef PFIL_HOOKS
	/* Filter on the bridge interface before broadcasting */
	if (runfilt && (PFIL_HOOKED(&inet_pfil_hook)
#ifdef INET6
	    || PFIL_HOOKED(&inet6_pfil_hook)
#endif /* INET6 */
	    )) {
		if (bridge_pfil(&m, sc->sc_ifp, NULL, PFIL_OUT) != 0)
			goto out;
		if (m == NULL)
			goto out;
	}
#endif /* PFIL_HOOKS */

	TAILQ_FOREACH(dbif, &sc->sc_iflist, bif_next) {
		dst_if = dbif->bif_ifp;
		if (dst_if == src_if)
			continue;

		/* Private segments can not talk to each other */
		if (sbif && (sbif->bif_flags & dbif->bif_flags & IFBIF_PRIVATE))
			continue;

		if ((dbif->bif_flags & IFBIF_STP) &&
		    dbif->bif_stp.bp_state == BSTP_IFSTATE_DISCARDING)
			continue;

		if ((dbif->bif_flags & IFBIF_DISCOVER) == 0 &&
		    (m->m_flags & (M_BCAST|M_MCAST)) == 0)
			continue;

		if ((dst_if->if_flags & IFF_RUNNING) == 0)
			continue;

		if (TAILQ_NEXT(dbif, bif_next) == NULL) {
			mc = m;
			used = 1;
		} else {
			mc = m_dup(m, M_DONTWAIT);
			if (mc == NULL) {
				(void) ifnet_stat_increment_out(sc->sc_ifp,
				    0, 0, 1);
				continue;
			}
		}

#ifdef PFIL_HOOKS
		/*
		 * Filter on the output interface. Pass a NULL bridge interface
		 * pointer so we do not redundantly filter on the bridge for
		 * each interface we broadcast on.
		 */
		if (runfilt && (PFIL_HOOKED(&inet_pfil_hook)
#ifdef INET6
		    || PFIL_HOOKED(&inet6_pfil_hook)
#endif
		    )) {
			if (used == 0) {
				/* Keep the layer3 header aligned */
				int i = min(mc->m_pkthdr.len, max_protohdr);
				mc = m_copyup(mc, i, ETHER_ALIGN);
				if (mc == NULL) {
					(void) ifnet_stat_increment_out(
					    sc->sc_ifp, 0, 0, 1);
					continue;
				}
			}
			if (bridge_pfil(&mc, NULL, dst_if, PFIL_OUT) != 0)
				continue;
			if (mc == NULL)
				continue;
		}
#endif /* PFIL_HOOKS */

		(void) bridge_enqueue(sc, dst_if, mc);
	}
	if (used == 0)
		m_freem(m);

#ifdef PFIL_HOOKS
out:
#endif /* PFIL_HOOKS */

	BRIDGE_UNREF(sc);
}

/*
 * bridge_span:
 *
 *	Duplicate a packet out one or more interfaces that are in span mode,
 *	the original mbuf is unmodified.
 */
static void
bridge_span(struct bridge_softc *sc, struct mbuf *m)
{
	struct bridge_iflist *bif;
	struct ifnet *dst_if;
	struct mbuf *mc;

	if (TAILQ_EMPTY(&sc->sc_spanlist))
		return;

	TAILQ_FOREACH(bif, &sc->sc_spanlist, bif_next) {
		dst_if = bif->bif_ifp;

		if ((dst_if->if_flags & IFF_RUNNING) == 0)
			continue;

		mc = m_copypacket(m, M_DONTWAIT);
		if (mc == NULL) {
			(void) ifnet_stat_increment_out(sc->sc_ifp, 0, 0, 1);
			continue;
		}

		(void) bridge_enqueue(sc, dst_if, mc);
	}
}



/*
 * bridge_rtupdate:
 *
 *	Add a bridge routing entry.
 */
static int
bridge_rtupdate(struct bridge_softc *sc, const uint8_t *dst, uint16_t vlan,
    struct bridge_iflist *bif, int setflags, uint8_t flags)
{
	struct bridge_rtnode *brt;
	int error;

	BRIDGE_LOCK_ASSERT(sc);

	/* Check the source address is valid and not multicast. */
	if (ETHER_IS_MULTICAST(dst) ||
	    (dst[0] == 0 && dst[1] == 0 && dst[2] == 0 &&
	    dst[3] == 0 && dst[4] == 0 && dst[5] == 0) != 0)
		return (EINVAL);


	/* 802.1p frames map to vlan 1 */
	if (vlan == 0)
		vlan = 1;

	/*
	 * A route for this destination might already exist.  If so,
	 * update it, otherwise create a new one.
	 */
	if ((brt = bridge_rtnode_lookup(sc, dst, vlan)) == NULL) {
		if (sc->sc_brtcnt >= sc->sc_brtmax) {
			sc->sc_brtexceeded++;
			return (ENOSPC);
		}
		/* Check per interface address limits (if enabled) */
		if (bif->bif_addrmax && bif->bif_addrcnt >= bif->bif_addrmax) {
			bif->bif_addrexceeded++;
			return (ENOSPC);
		}

		/*
		 * Allocate a new bridge forwarding node, and
		 * initialize the expiration time and Ethernet
		 * address.
		 */
		brt = zalloc_noblock(bridge_rtnode_pool);
		if (brt == NULL)
			return (ENOMEM);

		if (bif->bif_flags & IFBIF_STICKY)
			brt->brt_flags = IFBAF_STICKY;
		else
			brt->brt_flags = IFBAF_DYNAMIC;

		memcpy(brt->brt_addr, dst, ETHER_ADDR_LEN);
		brt->brt_vlan = vlan;


		if ((error = bridge_rtnode_insert(sc, brt)) != 0) {
			zfree(bridge_rtnode_pool, brt);
			return (error);
		}
		brt->brt_dst = bif;
		bif->bif_addrcnt++;
	}

	if ((brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC &&
	    brt->brt_dst != bif) {
		brt->brt_dst->bif_addrcnt--;
		brt->brt_dst = bif;
		brt->brt_dst->bif_addrcnt++;
	}

	if ((flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC) {
		struct timespec now;

		nanouptime(&now);
		brt->brt_expire = now.tv_sec + sc->sc_brttimeout;
	}
	if (setflags)
		brt->brt_flags = flags;


	return (0);
}

/*
 * bridge_rtlookup:
 *
 *	Lookup the destination interface for an address.
 */
static struct ifnet *
bridge_rtlookup(struct bridge_softc *sc, const uint8_t *addr, uint16_t vlan)
{
	struct bridge_rtnode *brt;

	BRIDGE_LOCK_ASSERT(sc);

	if ((brt = bridge_rtnode_lookup(sc, addr, vlan)) == NULL)
		return (NULL);

	return (brt->brt_ifp);
}

/*
 * bridge_rttrim:
 *
 *	Trim the routine table so that we have a number
 *	of routing entries less than or equal to the
 *	maximum number.
 */
static void
bridge_rttrim(struct bridge_softc *sc)
{
	struct bridge_rtnode *brt, *nbrt;

	BRIDGE_LOCK_ASSERT(sc);

	/* Make sure we actually need to do this. */
	if (sc->sc_brtcnt <= sc->sc_brtmax)
		return;

	/* Force an aging cycle; this might trim enough addresses. */
	bridge_rtage(sc);
	if (sc->sc_brtcnt <= sc->sc_brtmax)
		return;

	LIST_FOREACH_SAFE(brt, &sc->sc_rtlist, brt_list, nbrt) {
		if ((brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC) {
			bridge_rtnode_destroy(sc, brt);
			if (sc->sc_brtcnt <= sc->sc_brtmax)
				return;
		}
	}
}

/*
 * bridge_timer:
 *
 *	Aging timer for the bridge.
 */
static void
bridge_timer(void *arg)
{
	struct bridge_softc *sc = arg;

	BRIDGE_LOCK(sc);

	bridge_rtage(sc);

	BRIDGE_UNLOCK(sc);

	if (sc->sc_ifp->if_flags & IFF_RUNNING) {
		struct timespec ts;

		ts.tv_sec = bridge_rtable_prune_period;
		ts.tv_nsec = 0;
		bsd_timeout(bridge_timer, sc, &ts);
	}
}

/*
 * bridge_rtage:
 *
 *	Perform an aging cycle.
 */
static void
bridge_rtage(struct bridge_softc *sc)
{
	struct bridge_rtnode *brt, *nbrt;

	BRIDGE_LOCK_ASSERT(sc);

	LIST_FOREACH_SAFE(brt, &sc->sc_rtlist, brt_list, nbrt) {
		if ((brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC) {
			struct timespec now;

			nanouptime(&now);
			if ((unsigned long)now.tv_sec >= brt->brt_expire)
				bridge_rtnode_destroy(sc, brt);
		}
	}
}

/*
 * bridge_rtflush:
 *
 *	Remove all dynamic addresses from the bridge.
 */
static void
bridge_rtflush(struct bridge_softc *sc, int full)
{
	struct bridge_rtnode *brt, *nbrt;

	BRIDGE_LOCK_ASSERT(sc);

	LIST_FOREACH_SAFE(brt, &sc->sc_rtlist, brt_list, nbrt) {
		if (full || (brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC)
			bridge_rtnode_destroy(sc, brt);
	}
}

/*
 * bridge_rtdaddr:
 *
 *	Remove an address from the table.
 */
static int
bridge_rtdaddr(struct bridge_softc *sc, const uint8_t *addr, uint16_t vlan)
{
	struct bridge_rtnode *brt;
	int found = 0;

	BRIDGE_LOCK_ASSERT(sc);

	/*
	 * If vlan is zero then we want to delete for all vlans so the lookup
	 * may return more than one.
	 */
	while ((brt = bridge_rtnode_lookup(sc, addr, vlan)) != NULL) {
		bridge_rtnode_destroy(sc, brt);
		found = 1;
	}

	return (found ? 0 : ENOENT);
}

/*
 * bridge_rtdelete:
 *
 *	Delete routes to a speicifc member interface.
 */
static void
bridge_rtdelete(struct bridge_softc *sc, struct ifnet *ifp, int full)
{
	struct bridge_rtnode *brt, *nbrt;

	BRIDGE_LOCK_ASSERT(sc);

	LIST_FOREACH_SAFE(brt, &sc->sc_rtlist, brt_list, nbrt) {
		if (brt->brt_ifp == ifp && (full ||
		    (brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC))
			bridge_rtnode_destroy(sc, brt);
	}
}

/*
 * bridge_rtable_init:
 *
 *	Initialize the route table for this bridge.
 */
static int
bridge_rtable_init(struct bridge_softc *sc)
{
	int i;

	sc->sc_rthash = _MALLOC(sizeof (*sc->sc_rthash) * BRIDGE_RTHASH_SIZE,
	    M_DEVBUF, M_NOWAIT);
	if (sc->sc_rthash == NULL)
		return (ENOMEM);

	for (i = 0; i < BRIDGE_RTHASH_SIZE; i++)
		LIST_INIT(&sc->sc_rthash[i]);

	sc->sc_rthash_key = random();

	LIST_INIT(&sc->sc_rtlist);

	return (0);
}

/*
 * bridge_rtable_fini:
 *
 *	Deconstruct the route table for this bridge.
 */
static void
bridge_rtable_fini(struct bridge_softc *sc)
{

	KASSERT(sc->sc_brtcnt == 0,
	    ("%s: %d bridge routes referenced", __func__, sc->sc_brtcnt));
	_FREE(sc->sc_rthash, M_DEVBUF);
}

/*
 * The following hash function is adapted from "Hash Functions" by Bob Jenkins
 * ("Algorithm Alley", Dr. Dobbs Journal, September 1997).
 */
#define	mix(a, b, c)							\
do {									\
	a -= b; a -= c; a ^= (c >> 13);					\
	b -= c; b -= a; b ^= (a << 8);					\
	c -= a; c -= b; c ^= (b >> 13);					\
	a -= b; a -= c; a ^= (c >> 12);					\
	b -= c; b -= a; b ^= (a << 16);					\
	c -= a; c -= b; c ^= (b >> 5);					\
	a -= b; a -= c; a ^= (c >> 3);					\
	b -= c; b -= a; b ^= (a << 10);					\
	c -= a; c -= b; c ^= (b >> 15);					\
} while (/*CONSTCOND*/0)

static __inline uint32_t
bridge_rthash(struct bridge_softc *sc, const uint8_t *addr)
{
	uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = sc->sc_rthash_key;

	b += addr[5] << 8;
	b += addr[4];
	a += addr[3] << 24;
	a += addr[2] << 16;
	a += addr[1] << 8;
	a += addr[0];

	mix(a, b, c);

	return (c & BRIDGE_RTHASH_MASK);
}

#undef mix

static int
bridge_rtnode_addr_cmp(const uint8_t *a, const uint8_t *b)
{
	int i, d;

	for (i = 0, d = 0; i < ETHER_ADDR_LEN && d == 0; i++) {
		d = ((int)a[i]) - ((int)b[i]);
	}

	return (d);
}

/*
 * bridge_rtnode_lookup:
 *
 *	Look up a bridge route node for the specified destination. Compare the
 *	vlan id or if zero then just return the first match.
 */
static struct bridge_rtnode *
bridge_rtnode_lookup(struct bridge_softc *sc, const uint8_t *addr,
    uint16_t vlan)
{
	struct bridge_rtnode *brt;
	uint32_t hash;
	int dir;

	BRIDGE_LOCK_ASSERT(sc);

	hash = bridge_rthash(sc, addr);
	LIST_FOREACH(brt, &sc->sc_rthash[hash], brt_hash) {
		dir = bridge_rtnode_addr_cmp(addr, brt->brt_addr);
		if (dir == 0 && (brt->brt_vlan == vlan || vlan == 0))
			return (brt);
		if (dir > 0)
			return (NULL);
	}

	return (NULL);
}

/*
 * bridge_rtnode_insert:
 *
 *	Insert the specified bridge node into the route table.  We
 *	assume the entry is not already in the table.
 */
static int
bridge_rtnode_insert(struct bridge_softc *sc, struct bridge_rtnode *brt)
{
	struct bridge_rtnode *lbrt;
	uint32_t hash;
	int dir;

	BRIDGE_LOCK_ASSERT(sc);

	hash = bridge_rthash(sc, brt->brt_addr);

	lbrt = LIST_FIRST(&sc->sc_rthash[hash]);
	if (lbrt == NULL) {
		LIST_INSERT_HEAD(&sc->sc_rthash[hash], brt, brt_hash);
		goto out;
	}

	do {
		dir = bridge_rtnode_addr_cmp(brt->brt_addr, lbrt->brt_addr);
		if (dir == 0 && brt->brt_vlan == lbrt->brt_vlan)
			return (EEXIST);
		if (dir > 0) {
			LIST_INSERT_BEFORE(lbrt, brt, brt_hash);
			goto out;
		}
		if (LIST_NEXT(lbrt, brt_hash) == NULL) {
			LIST_INSERT_AFTER(lbrt, brt, brt_hash);
			goto out;
		}
		lbrt = LIST_NEXT(lbrt, brt_hash);
	} while (lbrt != NULL);

#ifdef DIAGNOSTIC
	panic("bridge_rtnode_insert: impossible");
#endif

out:
	LIST_INSERT_HEAD(&sc->sc_rtlist, brt, brt_list);
	sc->sc_brtcnt++;

	return (0);
}

/*
 * bridge_rtnode_destroy:
 *
 *	Destroy a bridge rtnode.
 */
static void
bridge_rtnode_destroy(struct bridge_softc *sc, struct bridge_rtnode *brt)
{
	BRIDGE_LOCK_ASSERT(sc);

	LIST_REMOVE(brt, brt_hash);

	LIST_REMOVE(brt, brt_list);
	sc->sc_brtcnt--;
	brt->brt_dst->bif_addrcnt--;
	zfree(bridge_rtnode_pool, brt);
}

#if BRIDGESTP
/*
 * bridge_rtable_expire:
 *
 *	Set the expiry time for all routes on an interface.
 */
static void
bridge_rtable_expire(struct ifnet *ifp, int age)
{
	struct bridge_softc *sc = ifp->if_bridge;
	struct bridge_rtnode *brt;

	BRIDGE_LOCK(sc);

	/*
	 * If the age is zero then flush, otherwise set all the expiry times to
	 * age for the interface
	 */
	if (age == 0) {
		bridge_rtdelete(sc, ifp, IFBF_FLUSHDYN);
	} else {
		LIST_FOREACH(brt, &sc->sc_rtlist, brt_list) {
			struct timespec now;

			nanouptime(&now);
			/* Cap the expiry time to 'age' */
			if (brt->brt_ifp == ifp &&
			    brt->brt_expire > (unsigned long)now.tv_sec + age &&
			    (brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC)
				brt->brt_expire =
				    (unsigned long)now.tv_sec + age;
		}
	}
	BRIDGE_UNLOCK(sc);
}

/*
 * bridge_state_change:
 *
 *	Callback from the bridgestp code when a port changes states.
 */
static void
bridge_state_change(struct ifnet *ifp, int state)
{
	struct bridge_softc *sc = ifp->if_bridge;
	static const char *stpstates[] = {
		"disabled",
		"listening",
		"learning",
		"forwarding",
		"blocking",
		"discarding"
	};

	if (log_stp)
		log(LOG_NOTICE, "%s%d: state changed to %s on %s%d\n",
		    ifnet_name(sc->sc_ifp), ifnet_unit(sc->sc_ifp),
		    stpstates[state], ifnet_name(ifp), ifnet_unit(ifp));
}
#endif /* BRIDGESTP */

#ifdef PFIL_HOOKS
/*
 * Send bridge packets through pfil if they are one of the types pfil can deal
 * with, or if they are ARP or REVARP.  (pfil will pass ARP and REVARP without
 * question.) If *bifp or *ifp are NULL then packet filtering is skipped for
 * that interface.
 */
static int
bridge_pfil(struct mbuf **mp, struct ifnet *bifp, struct ifnet *ifp, int dir)
{
	int snap, error, i, hlen;
	struct ether_header *eh1, eh2;
	struct ip_fw_args args;
	struct ip *ip;
	struct llc llc1;
	u_int16_t ether_type;

	snap = 0;
	error = -1;	/* Default error if not error == 0 */

#if 0
	/* we may return with the IP fields swapped, ensure its not shared */
	KASSERT(M_WRITABLE(*mp), ("%s: modifying a shared mbuf", __func__));
#endif

	if (pfil_bridge == 0 && pfil_member == 0 && pfil_ipfw == 0)
		return (0); /* filtering is disabled */

	i = min((*mp)->m_pkthdr.len, max_protohdr);
	if ((*mp)->m_len < i) {
		*mp = m_pullup(*mp, i);
		if (*mp == NULL) {
			printf("%s: m_pullup failed\n", __func__);
			return (-1);
		}
	}

	eh1 = mtod(*mp, struct ether_header *);
	ether_type = ntohs(eh1->ether_type);

	/*
	 * Check for SNAP/LLC.
	 */
	if (ether_type < ETHERMTU) {
		struct llc *llc2 = (struct llc *)(eh1 + 1);

		if ((*mp)->m_len >= ETHER_HDR_LEN + 8 &&
		    llc2->llc_dsap == LLC_SNAP_LSAP &&
		    llc2->llc_ssap == LLC_SNAP_LSAP &&
		    llc2->llc_control == LLC_UI) {
			ether_type = htons(llc2->llc_un.type_snap.ether_type);
			snap = 1;
		}
	}

	/*
	 * If we're trying to filter bridge traffic, don't look at anything
	 * other than IP and ARP traffic.  If the filter doesn't understand
	 * IPv6, don't allow IPv6 through the bridge either.  This is lame
	 * since if we really wanted, say, an AppleTalk filter, we are hosed,
	 * but of course we don't have an AppleTalk filter to begin with.
	 * (Note that since pfil doesn't understand ARP it will pass *ALL*
	 * ARP traffic.)
	 */
	switch (ether_type) {
		case ETHERTYPE_ARP:
		case ETHERTYPE_REVARP:
			if (pfil_ipfw_arp == 0)
				return (0); /* Automatically pass */
			break;

		case ETHERTYPE_IP:
#ifdef INET6
		case ETHERTYPE_IPV6:
#endif /* INET6 */
			break;
		default:
			/*
			 * Check to see if the user wants to pass non-ip
			 * packets, these will not be checked by pfil(9) and
			 * passed unconditionally so the default is to drop.
			 */
			if (pfil_onlyip)
				goto bad;
	}

	/* Strip off the Ethernet header and keep a copy. */
	m_copydata(*mp, 0, ETHER_HDR_LEN, (caddr_t)&eh2);
	m_adj(*mp, ETHER_HDR_LEN);

	/* Strip off snap header, if present */
	if (snap) {
		m_copydata(*mp, 0, sizeof (struct llc), (caddr_t)&llc1);
		m_adj(*mp, sizeof (struct llc));
	}

	/*
	 * Check the IP header for alignment and errors
	 */
	if (dir == PFIL_IN) {
		switch (ether_type) {
			case ETHERTYPE_IP:
				error = bridge_ip_checkbasic(mp);
				break;
#ifdef INET6
			case ETHERTYPE_IPV6:
				error = bridge_ip6_checkbasic(mp);
				break;
#endif /* INET6 */
			default:
				error = 0;
		}
		if (error)
			goto bad;
	}

	if (IPFW_LOADED && pfil_ipfw != 0 && dir == PFIL_OUT && ifp != NULL) {
		error = -1;
		args.rule = ip_dn_claim_rule(*mp);
		if (args.rule != NULL && fw_one_pass)
			goto ipfwpass; /* packet already partially processed */

		args.m = *mp;
		args.oif = ifp;
		args.next_hop = NULL;
		args.eh = &eh2;
		args.inp = NULL;	/* used by ipfw uid/gid/jail rules */
		i = ip_fw_chk_ptr(&args);
		*mp = args.m;

		if (*mp == NULL)
			return (error);

		if (DUMMYNET_LOADED && (i == IP_FW_DUMMYNET)) {

			/* put the Ethernet header back on */
			M_PREPEND(*mp, ETHER_HDR_LEN, M_DONTWAIT);
			if (*mp == NULL)
				return (error);
			bcopy(&eh2, mtod(*mp, caddr_t), ETHER_HDR_LEN);

			/*
			 * Pass the pkt to dummynet, which consumes it. The
			 * packet will return to us via bridge_dummynet().
			 */
			args.oif = ifp;
			ip_dn_io_ptr(mp, DN_TO_IFB_FWD, &args, DN_CLIENT_IPFW);
			return (error);
		}

		if (i != IP_FW_PASS) /* drop */
			goto bad;
	}

ipfwpass:
	error = 0;

	/*
	 * Run the packet through pfil
	 */
	switch (ether_type) {
	case ETHERTYPE_IP:
		/*
		 * before calling the firewall, swap fields the same as
		 * IP does. here we assume the header is contiguous
		 */
		ip = mtod(*mp, struct ip *);

		ip->ip_len = ntohs(ip->ip_len);
		ip->ip_off = ntohs(ip->ip_off);

		/*
		 * Run pfil on the member interface and the bridge, both can
		 * be skipped by clearing pfil_member or pfil_bridge.
		 *
		 * Keep the order:
		 *   in_if -> bridge_if -> out_if
		 */
		if (pfil_bridge && dir == PFIL_OUT && bifp != NULL)
			error = pfil_run_hooks(&inet_pfil_hook, mp, bifp,
			    dir, NULL);

		if (*mp == NULL || error != 0) /* filter may consume */
			break;

		if (pfil_member && ifp != NULL)
			error = pfil_run_hooks(&inet_pfil_hook, mp, ifp,
			    dir, NULL);

		if (*mp == NULL || error != 0) /* filter may consume */
			break;

		if (pfil_bridge && dir == PFIL_IN && bifp != NULL)
			error = pfil_run_hooks(&inet_pfil_hook, mp, bifp,
			    dir, NULL);

		if (*mp == NULL || error != 0) /* filter may consume */
			break;

		/* check if we need to fragment the packet */
		if (pfil_member && ifp != NULL && dir == PFIL_OUT) {
			i = (*mp)->m_pkthdr.len;
			if (i > ifp->if_mtu) {
				error = bridge_fragment(ifp, *mp, &eh2, snap,
				    &llc1);
				return (error);
			}
		}

		/* Recalculate the ip checksum and restore byte ordering */
		ip = mtod(*mp, struct ip *);
		hlen = ip->ip_hl << 2;
		if (hlen < sizeof (struct ip))
			goto bad;
		if (hlen > (*mp)->m_len) {
			if ((*mp = m_pullup(*mp, hlen)) == 0)
				goto bad;
			ip = mtod(*mp, struct ip *);
			if (ip == NULL)
				goto bad;
		}
		ip->ip_len = htons(ip->ip_len);
		ip->ip_off = htons(ip->ip_off);
		ip->ip_sum = 0;
		if (hlen == sizeof (struct ip))
			ip->ip_sum = in_cksum_hdr(ip);
		else
			ip->ip_sum = in_cksum(*mp, hlen);

		break;
#ifdef INET6
	case ETHERTYPE_IPV6:
		if (pfil_bridge && dir == PFIL_OUT && bifp != NULL)
			error = pfil_run_hooks(&inet6_pfil_hook, mp, bifp,
			    dir, NULL);

		if (*mp == NULL || error != 0) /* filter may consume */
			break;

		if (pfil_member && ifp != NULL)
			error = pfil_run_hooks(&inet6_pfil_hook, mp, ifp,
			    dir, NULL);

		if (*mp == NULL || error != 0) /* filter may consume */
			break;

		if (pfil_bridge && dir == PFIL_IN && bifp != NULL)
			error = pfil_run_hooks(&inet6_pfil_hook, mp, bifp,
			    dir, NULL);
		break;
#endif
	default:
		error = 0;
		break;
	}

	if (*mp == NULL)
		return (error);
	if (error != 0)
		goto bad;

	error = -1;

	/*
	 * Finally, put everything back the way it was and return
	 */
	if (snap) {
		M_PREPEND(*mp, sizeof (struct llc), M_DONTWAIT);
		if (*mp == NULL)
			return (error);
		bcopy(&llc1, mtod(*mp, caddr_t), sizeof (struct llc));
	}

	M_PREPEND(*mp, ETHER_HDR_LEN, M_DONTWAIT);
	if (*mp == NULL)
		return (error);
	bcopy(&eh2, mtod(*mp, caddr_t), ETHER_HDR_LEN);

	return (0);

bad:
	m_freem(*mp);
	*mp = NULL;
	return (error);
}


/*
 * Perform basic checks on header size since
 * pfil assumes ip_input has already processed
 * it for it.  Cut-and-pasted from ip_input.c.
 * Given how simple the IPv6 version is,
 * does the IPv4 version really need to be
 * this complicated?
 *
 * XXX Should we update ipstat here, or not?
 * XXX Right now we update ipstat but not
 * XXX csum_counter.
 */
static int
bridge_ip_checkbasic(struct mbuf **mp)
{
	struct mbuf *m = *mp;
	struct ip *ip;
	int len, hlen;
	u_short sum;

	if (*mp == NULL)
		return (-1);

	if (IP_HDR_ALIGNED_P(mtod(m, caddr_t)) == 0) {
		/* max_linkhdr is already rounded up to nearest 4-byte */
		if ((m = m_copyup(m, sizeof (struct ip),
		    max_linkhdr)) == NULL) {
			/* XXXJRT new stat, please */
			ipstat.ips_toosmall++;
			goto bad;
		}
	} else if (__predict_false(m->m_len < sizeof (struct ip))) {
		if ((m = m_pullup(m, sizeof (struct ip))) == NULL) {
			ipstat.ips_toosmall++;
			goto bad;
		}
	}
	ip = mtod(m, struct ip *);
	if (ip == NULL) goto bad;

	if (ip->ip_v != IPVERSION) {
		ipstat.ips_badvers++;
		goto bad;
	}
	hlen = ip->ip_hl << 2;
	if (hlen < sizeof (struct ip)) { /* minimum header length */
		ipstat.ips_badhlen++;
		goto bad;
	}
	if (hlen > m->m_len) {
		if ((m = m_pullup(m, hlen)) == 0) {
			ipstat.ips_badhlen++;
			goto bad;
		}
		ip = mtod(m, struct ip *);
		if (ip == NULL) goto bad;
	}

	if (m->m_pkthdr.csum_flags & CSUM_IP_CHECKED) {
		sum = !(m->m_pkthdr.csum_flags & CSUM_IP_VALID);
	} else {
		if (hlen == sizeof (struct ip)) {
			sum = in_cksum_hdr(ip);
		} else {
			sum = in_cksum(m, hlen);
		}
	}
	if (sum) {
		ipstat.ips_badsum++;
		goto bad;
	}

	/* Retrieve the packet length. */
	len = ntohs(ip->ip_len);

	/*
	 * Check for additional length bogosity
	 */
	if (len < hlen) {
		ipstat.ips_badlen++;
		goto bad;
	}

	/*
	 * Check that the amount of data in the buffers
	 * is as at least much as the IP header would have us expect.
	 * Drop packet if shorter than we expect.
	 */
	if (m->m_pkthdr.len < len) {
		ipstat.ips_tooshort++;
		goto bad;
	}

	/* Checks out, proceed */
	*mp = m;
	return (0);

bad:
	*mp = m;
	return (-1);
}

#ifdef INET6
/*
 * Same as above, but for IPv6.
 * Cut-and-pasted from ip6_input.c.
 * XXX Should we update ip6stat, or not?
 */
static int
bridge_ip6_checkbasic(struct mbuf **mp)
{
	struct mbuf *m = *mp;
	struct ip6_hdr *ip6;

	/*
	 * If the IPv6 header is not aligned, slurp it up into a new
	 * mbuf with space for link headers, in the event we forward
	 * it.  Otherwise, if it is aligned, make sure the entire base
	 * IPv6 header is in the first mbuf of the chain.
	 */
	if (IP6_HDR_ALIGNED_P(mtod(m, caddr_t)) == 0) {
		struct ifnet *inifp = m->m_pkthdr.rcvif;
		/* max_linkhdr is already rounded up to nearest 4-byte */
		if ((m = m_copyup(m, sizeof (struct ip6_hdr),
		    max_linkhdr)) == NULL) {
			/* XXXJRT new stat, please */
			ip6stat.ip6s_toosmall++;
			in6_ifstat_inc(inifp, ifs6_in_hdrerr);
			goto bad;
		}
	} else if (__predict_false(m->m_len < sizeof (struct ip6_hdr))) {
		struct ifnet *inifp = m->m_pkthdr.rcvif;
		if ((m = m_pullup(m, sizeof (struct ip6_hdr))) == NULL) {
			ip6stat.ip6s_toosmall++;
			in6_ifstat_inc(inifp, ifs6_in_hdrerr);
			goto bad;
		}
	}

	ip6 = mtod(m, struct ip6_hdr *);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
		ip6stat.ip6s_badvers++;
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_hdrerr);
		goto bad;
	}

	/* Checks out, proceed */
	*mp = m;
	return (0);

bad:
	*mp = m;
	return (-1);
}
#endif /* INET6 */

/*
 * bridge_fragment:
 *
 *	Return a fragmented mbuf chain.
 */
static int
bridge_fragment(struct ifnet *ifp, struct mbuf *m, struct ether_header *eh,
    int snap, struct llc *llc)
{
	struct mbuf *m0;
	struct ip *ip;
	int error = -1;

	if (m->m_len < sizeof (struct ip) &&
	    (m = m_pullup(m, sizeof (struct ip))) == NULL)
		goto out;
	ip = mtod(m, struct ip *);

	error = ip_fragment(ip, &m, ifp->if_mtu, ifp->if_hwassist,
	    CSUM_DELAY_IP);
	if (error)
		goto out;

	/* walk the chain and re-add the Ethernet header */
	for (m0 = m; m0; m0 = m0->m_nextpkt) {
		if (error == 0) {
			if (snap) {
				M_PREPEND(m0, sizeof (struct llc), M_DONTWAIT);
				if (m0 == NULL) {
					error = ENOBUFS;
					continue;
				}
				bcopy(llc, mtod(m0, caddr_t),
				    sizeof (struct llc));
			}
			M_PREPEND(m0, ETHER_HDR_LEN, M_DONTWAIT);
			if (m0 == NULL) {
				error = ENOBUFS;
				continue;
			}
			bcopy(eh, mtod(m0, caddr_t), ETHER_HDR_LEN);
		} else {
			m_freem(m);
		}
	}

	if (error == 0)
		ipstat.ips_fragmented++;

	return (error);

out:
	if (m != NULL)
		m_freem(m);
	return (error);
}
#endif /* PFIL_HOOKS */

static errno_t
bridge_set_bpf_tap(ifnet_t ifp, bpf_tap_mode mode, bpf_packet_func bpf_callback)
{
	struct bridge_softc *sc = (struct bridge_softc *)ifnet_softc(ifp);

	/* TBD locking */
	if (sc == NULL || (sc->sc_flags & SCF_DETACHING)) {
		return (ENODEV);
	}

	switch (mode) {
		case BPF_TAP_DISABLE:
			sc->sc_bpf_input = sc->sc_bpf_output = NULL;
			break;

		case BPF_TAP_INPUT:
			sc->sc_bpf_input = bpf_callback;
			break;

		case BPF_TAP_OUTPUT:
			sc->sc_bpf_output = bpf_callback;
			break;

		case BPF_TAP_INPUT_OUTPUT:
			sc->sc_bpf_input = sc->sc_bpf_output = bpf_callback;
			break;

		default:
			break;
	}

	return (0);
}

static void
bridge_detach(ifnet_t ifp)
{
	struct bridge_softc *sc = (struct bridge_softc *)ifnet_softc(ifp);

#if BRIDGESTP
	bstp_detach(&sc->sc_stp);
#endif /* BRIDGESTP */

	/* Tear down the routing table. */
	bridge_rtable_fini(sc);

	lck_mtx_lock(bridge_list_mtx);
	LIST_REMOVE(sc, sc_list);
	lck_mtx_unlock(bridge_list_mtx);

	ifnet_release(ifp);

	lck_mtx_free(sc->sc_mtx, bridge_lock_grp);

	_FREE(sc, M_DEVBUF);
}

__private_extern__ errno_t
bridge_bpf_input(ifnet_t ifp, struct mbuf *m)
{
	struct bridge_softc *sc = (struct bridge_softc *)ifnet_softc(ifp);

	if (sc->sc_bpf_input) {
		if (mbuf_pkthdr_rcvif(m) != ifp) {
			printf("%s: rcvif: %p != ifp %p\n", __func__,
			    mbuf_pkthdr_rcvif(m), ifp);
		}
		(*sc->sc_bpf_input)(ifp, m);
	}
	return (0);
}

__private_extern__ errno_t
bridge_bpf_output(ifnet_t ifp, struct mbuf *m)
{
	struct bridge_softc *sc = (struct bridge_softc *)ifnet_softc(ifp);

	if (sc->sc_bpf_output) {
		(*sc->sc_bpf_output)(ifp, m);
	}
	return (0);
}
