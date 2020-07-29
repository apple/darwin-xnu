/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1991, 1993
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
 *	@(#)in.c	8.4 (Berkeley) 1/9/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/socketvar.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/kern_event.h>
#include <sys/syslog.h>
#include <sys/mcache.h>
#include <sys/protosw.h>
#include <sys/file.h>

#include <kern/zalloc.h>
#include <pexpert/pexpert.h>
#include <os/log.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/kpi_protocol.h>
#include <net/dlil.h>
#include <net/if_llatbl.h>
#include <net/if_arp.h>
#if PF
#include <net/pfvar.h>
#endif /* PF */

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_pcb.h>
#include <netinet/igmp_var.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/if_ether.h>

static int inctl_associd(struct socket *, u_long, caddr_t);
static int inctl_connid(struct socket *, u_long, caddr_t);
static int inctl_conninfo(struct socket *, u_long, caddr_t);
static int inctl_autoaddr(struct ifnet *, struct ifreq *);
static int inctl_arpipll(struct ifnet *, struct ifreq *);
static int inctl_setrouter(struct ifnet *, struct ifreq *);
static int inctl_ifaddr(struct ifnet *, struct in_ifaddr *, u_long,
    struct ifreq *);
static int inctl_ifdstaddr(struct ifnet *, struct in_ifaddr *, u_long,
    struct ifreq *);
static int inctl_ifbrdaddr(struct ifnet *, struct in_ifaddr *, u_long,
    struct ifreq *);
static int inctl_ifnetmask(struct ifnet *, struct in_ifaddr *, u_long,
    struct ifreq *);

static void in_socktrim(struct sockaddr_in *);
static int in_ifinit(struct ifnet *, struct in_ifaddr *,
    struct sockaddr_in *, int);

#define IA_HASH_INIT(ia) {                                      \
	(ia)->ia_hash.tqe_next = (void *)(uintptr_t)-1;         \
	(ia)->ia_hash.tqe_prev = (void *)(uintptr_t)-1;         \
}

#define IA_IS_HASHED(ia)                                        \
	(!((ia)->ia_hash.tqe_next == (void *)(uintptr_t)-1 ||   \
	(ia)->ia_hash.tqe_prev == (void *)(uintptr_t)-1))

static void in_iahash_remove(struct in_ifaddr *);
static void in_iahash_insert(struct in_ifaddr *);
static void in_iahash_insert_ptp(struct in_ifaddr *);
static struct in_ifaddr *in_ifaddr_alloc(int);
static void in_ifaddr_attached(struct ifaddr *);
static void in_ifaddr_detached(struct ifaddr *);
static void in_ifaddr_free(struct ifaddr *);
static void in_ifaddr_trace(struct ifaddr *, int);

static int in_getassocids(struct socket *, uint32_t *, user_addr_t);
static int in_getconnids(struct socket *, sae_associd_t, uint32_t *, user_addr_t);

/* IPv4 Layer 2 neighbor cache management routines */
static void in_lltable_destroy_lle_unlocked(struct llentry *lle);
static void in_lltable_destroy_lle(struct llentry *lle);
static struct llentry *in_lltable_new(struct in_addr addr4, u_int flags);
static int in_lltable_match_prefix(const struct sockaddr *saddr,
    const struct sockaddr *smask, u_int flags, struct llentry *lle);
static void in_lltable_free_entry(struct lltable *llt, struct llentry *lle);
static int in_lltable_rtcheck(struct ifnet *ifp, u_int flags, const struct sockaddr *l3addr);
static inline uint32_t in_lltable_hash_dst(const struct in_addr dst, uint32_t hsize);
static uint32_t in_lltable_hash(const struct llentry *lle, uint32_t hsize);
static void in_lltable_fill_sa_entry(const struct llentry *lle, struct sockaddr *sa);
static inline struct llentry * in_lltable_find_dst(struct lltable *llt, struct in_addr dst);
static void in_lltable_delete_entry(struct lltable *llt, struct llentry *lle);
static struct llentry * in_lltable_alloc(struct lltable *llt, u_int flags, const struct sockaddr *l3addr);
static struct llentry * in_lltable_lookup(struct lltable *llt, u_int flags, const struct sockaddr *l3addr);
static int in_lltable_dump_entry(struct lltable *llt, struct llentry *lle, struct sysctl_req *wr);
static struct lltable * in_lltattach(struct ifnet *ifp);

static int subnetsarelocal = 0;
SYSCTL_INT(_net_inet_ip, OID_AUTO, subnets_are_local,
    CTLFLAG_RW | CTLFLAG_LOCKED, &subnetsarelocal, 0, "");

/* Track whether or not the SIOCARPIPLL ioctl has been called */
u_int32_t ipv4_ll_arp_aware = 0;

#define INIFA_TRACE_HIST_SIZE   32      /* size of trace history */

/* For gdb */
__private_extern__ unsigned int inifa_trace_hist_size = INIFA_TRACE_HIST_SIZE;

struct in_ifaddr_dbg {
	struct in_ifaddr        inifa;                  /* in_ifaddr */
	struct in_ifaddr        inifa_old;              /* saved in_ifaddr */
	u_int16_t               inifa_refhold_cnt;      /* # of IFA_ADDREF */
	u_int16_t               inifa_refrele_cnt;      /* # of IFA_REMREF */
	/*
	 * Alloc and free callers.
	 */
	ctrace_t                inifa_alloc;
	ctrace_t                inifa_free;
	/*
	 * Circular lists of IFA_ADDREF and IFA_REMREF callers.
	 */
	ctrace_t                inifa_refhold[INIFA_TRACE_HIST_SIZE];
	ctrace_t                inifa_refrele[INIFA_TRACE_HIST_SIZE];
	/*
	 * Trash list linkage
	 */
	TAILQ_ENTRY(in_ifaddr_dbg) inifa_trash_link;
};

/* List of trash in_ifaddr entries protected by inifa_trash_lock */
static TAILQ_HEAD(, in_ifaddr_dbg) inifa_trash_head;
static decl_lck_mtx_data(, inifa_trash_lock);

#if DEBUG
static unsigned int inifa_debug = 1;            /* debugging (enabled) */
#else
static unsigned int inifa_debug;                /* debugging (disabled) */
#endif /* !DEBUG */
static unsigned int inifa_size;                 /* size of zone element */
static struct zone *inifa_zone;                 /* zone for in_ifaddr */

#define INIFA_ZONE_MAX          64              /* maximum elements in zone */
#define INIFA_ZONE_NAME         "in_ifaddr"     /* zone name */

static const unsigned int in_extra_size = sizeof(struct in_ifextra);
static const unsigned int in_extra_bufsize = in_extra_size +
    sizeof(void *) + sizeof(uint64_t);

/*
 * Return 1 if the address is
 * - loopback
 * - unicast or multicast link local
 * - routed via a link level gateway
 * - belongs to a directly connected (sub)net
 */
int
inaddr_local(struct in_addr in)
{
	struct rtentry *rt;
	struct sockaddr_in sin;
	int local = 0;

	if (ntohl(in.s_addr) == INADDR_LOOPBACK ||
	    IN_LINKLOCAL(ntohl(in.s_addr))) {
		local = 1;
	} else if (ntohl(in.s_addr) >= INADDR_UNSPEC_GROUP &&
	    ntohl(in.s_addr) <= INADDR_MAX_LOCAL_GROUP) {
		local = 1;
	} else {
		sin.sin_family = AF_INET;
		sin.sin_len = sizeof(sin);
		sin.sin_addr = in;
		rt = rtalloc1((struct sockaddr *)&sin, 0, 0);

		if (rt != NULL) {
			RT_LOCK_SPIN(rt);
			if (rt->rt_gateway->sa_family == AF_LINK ||
			    (rt->rt_ifp->if_flags & IFF_LOOPBACK)) {
				local = 1;
			}
			RT_UNLOCK(rt);
			rtfree(rt);
		} else {
			local = in_localaddr(in);
		}
	}
	return local;
}

/*
 * Return 1 if an internet address is for a ``local'' host
 * (one to which we have a connection).  If subnetsarelocal
 * is true, this includes other subnets of the local net,
 * otherwise, it includes the directly-connected (sub)nets.
 * The IPv4 link local prefix 169.254/16 is also included.
 */
int
in_localaddr(struct in_addr in)
{
	u_int32_t i = ntohl(in.s_addr);
	struct in_ifaddr *ia;

	if (IN_LINKLOCAL(i)) {
		return 1;
	}

	if (subnetsarelocal) {
		lck_rw_lock_shared(in_ifaddr_rwlock);
		for (ia = in_ifaddrhead.tqh_first; ia != NULL;
		    ia = ia->ia_link.tqe_next) {
			IFA_LOCK(&ia->ia_ifa);
			if ((i & ia->ia_netmask) == ia->ia_net) {
				IFA_UNLOCK(&ia->ia_ifa);
				lck_rw_done(in_ifaddr_rwlock);
				return 1;
			}
			IFA_UNLOCK(&ia->ia_ifa);
		}
		lck_rw_done(in_ifaddr_rwlock);
	} else {
		lck_rw_lock_shared(in_ifaddr_rwlock);
		for (ia = in_ifaddrhead.tqh_first; ia != NULL;
		    ia = ia->ia_link.tqe_next) {
			IFA_LOCK(&ia->ia_ifa);
			if ((i & ia->ia_subnetmask) == ia->ia_subnet) {
				IFA_UNLOCK(&ia->ia_ifa);
				lck_rw_done(in_ifaddr_rwlock);
				return 1;
			}
			IFA_UNLOCK(&ia->ia_ifa);
		}
		lck_rw_done(in_ifaddr_rwlock);
	}
	return 0;
}

/*
 * Determine whether an IP address is in a reserved set of addresses
 * that may not be forwarded, or whether datagrams to that destination
 * may be forwarded.
 */
boolean_t
in_canforward(struct in_addr in)
{
	u_int32_t i = ntohl(in.s_addr);
	u_int32_t net;

	if (IN_EXPERIMENTAL(i) || IN_MULTICAST(i)) {
		return FALSE;
	}
	if (IN_CLASSA(i)) {
		net = i & IN_CLASSA_NET;
		if (net == 0 || net == (IN_LOOPBACKNET << IN_CLASSA_NSHIFT)) {
			return FALSE;
		}
	}
	return TRUE;
}

/*
 * Trim a mask in a sockaddr
 */
static void
in_socktrim(struct sockaddr_in *ap)
{
	char *cplim = (char *)&ap->sin_addr;
	char *cp = (char *)(&ap->sin_addr + 1);

	ap->sin_len = 0;
	while (--cp >= cplim) {
		if (*cp) {
			(ap)->sin_len = cp - (char *)(ap) + 1;
			break;
		}
	}
}

static int in_interfaces;       /* number of external internet interfaces */

static int
in_domifattach(struct ifnet *ifp)
{
	int error;

	VERIFY(ifp != NULL);

	if ((error = proto_plumb(PF_INET, ifp)) && error != EEXIST) {
		log(LOG_ERR, "%s: proto_plumb returned %d if=%s\n",
		    __func__, error, if_name(ifp));
	} else if (error == 0 && ifp->if_inetdata == NULL) {
		void **pbuf, *base;
		struct in_ifextra *ext;
		int errorx;

		if ((ext = (struct in_ifextra *)_MALLOC(in_extra_bufsize,
		    M_IFADDR, M_WAITOK | M_ZERO)) == NULL) {
			error = ENOMEM;
			errorx = proto_unplumb(PF_INET, ifp);
			if (errorx != 0) {
				log(LOG_ERR,
				    "%s: proto_unplumb returned %d if=%s%d\n",
				    __func__, errorx, ifp->if_name,
				    ifp->if_unit);
			}
			goto done;
		}

		/* Align on 64-bit boundary */
		base = (void *)P2ROUNDUP((intptr_t)ext + sizeof(uint64_t),
		    sizeof(uint64_t));
		VERIFY(((intptr_t)base + in_extra_size) <=
		    ((intptr_t)ext + in_extra_bufsize));
		pbuf = (void **)((intptr_t)base - sizeof(void *));
		*pbuf = ext;
		ifp->if_inetdata = base;
		IN_IFEXTRA(ifp)->ii_llt = in_lltattach(ifp);
		VERIFY(IS_P2ALIGNED(ifp->if_inetdata, sizeof(uint64_t)));
	}
done:
	if (error == 0 && ifp->if_inetdata != NULL) {
		/*
		 * Since the structure is never freed, we need to
		 * zero out its contents to avoid reusing stale data.
		 * A little redundant with allocation above, but it
		 * keeps the code simpler for all cases.
		 */
		bzero(ifp->if_inetdata, in_extra_size);
	}
	return error;
}

static __attribute__((noinline)) int
inctl_associd(struct socket *so, u_long cmd, caddr_t data)
{
	int error = 0;
	union {
		struct so_aidreq32 a32;
		struct so_aidreq64 a64;
	} u;

	VERIFY(so != NULL);

	switch (cmd) {
	case SIOCGASSOCIDS32:           /* struct so_aidreq32 */
		bcopy(data, &u.a32, sizeof(u.a32));
		error = in_getassocids(so, &u.a32.sar_cnt, u.a32.sar_aidp);
		if (error == 0) {
			bcopy(&u.a32, data, sizeof(u.a32));
		}
		break;

	case SIOCGASSOCIDS64:           /* struct so_aidreq64 */
		bcopy(data, &u.a64, sizeof(u.a64));
		error = in_getassocids(so, &u.a64.sar_cnt, u.a64.sar_aidp);
		if (error == 0) {
			bcopy(&u.a64, data, sizeof(u.a64));
		}
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return error;
}

static __attribute__((noinline)) int
inctl_connid(struct socket *so, u_long cmd, caddr_t data)
{
	int error = 0;
	union {
		struct so_cidreq32 c32;
		struct so_cidreq64 c64;
	} u;

	VERIFY(so != NULL);

	switch (cmd) {
	case SIOCGCONNIDS32:            /* struct so_cidreq32 */
		bcopy(data, &u.c32, sizeof(u.c32));
		error = in_getconnids(so, u.c32.scr_aid, &u.c32.scr_cnt,
		    u.c32.scr_cidp);
		if (error == 0) {
			bcopy(&u.c32, data, sizeof(u.c32));
		}
		break;

	case SIOCGCONNIDS64:            /* struct so_cidreq64 */
		bcopy(data, &u.c64, sizeof(u.c64));
		error = in_getconnids(so, u.c64.scr_aid, &u.c64.scr_cnt,
		    u.c64.scr_cidp);
		if (error == 0) {
			bcopy(&u.c64, data, sizeof(u.c64));
		}
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return error;
}

static __attribute__((noinline)) int
inctl_conninfo(struct socket *so, u_long cmd, caddr_t data)
{
	int error = 0;
	union {
		struct so_cinforeq32 ci32;
		struct so_cinforeq64 ci64;
	} u;

	VERIFY(so != NULL);

	switch (cmd) {
	case SIOCGCONNINFO32:           /* struct so_cinforeq32 */
		bcopy(data, &u.ci32, sizeof(u.ci32));
		error = in_getconninfo(so, u.ci32.scir_cid, &u.ci32.scir_flags,
		    &u.ci32.scir_ifindex, &u.ci32.scir_error, u.ci32.scir_src,
		    &u.ci32.scir_src_len, u.ci32.scir_dst, &u.ci32.scir_dst_len,
		    &u.ci32.scir_aux_type, u.ci32.scir_aux_data,
		    &u.ci32.scir_aux_len);
		if (error == 0) {
			bcopy(&u.ci32, data, sizeof(u.ci32));
		}
		break;

	case SIOCGCONNINFO64:           /* struct so_cinforeq64 */
		bcopy(data, &u.ci64, sizeof(u.ci64));
		error = in_getconninfo(so, u.ci64.scir_cid, &u.ci64.scir_flags,
		    &u.ci64.scir_ifindex, &u.ci64.scir_error, u.ci64.scir_src,
		    &u.ci64.scir_src_len, u.ci64.scir_dst, &u.ci64.scir_dst_len,
		    &u.ci64.scir_aux_type, u.ci64.scir_aux_data,
		    &u.ci64.scir_aux_len);
		if (error == 0) {
			bcopy(&u.ci64, data, sizeof(u.ci64));
		}
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return error;
}

/*
 * Caller passes in the ioctl data pointer directly via "ifr", with the
 * expectation that this routine always uses bcopy() or other byte-aligned
 * memory accesses.
 */
static __attribute__((noinline)) int
inctl_autoaddr(struct ifnet *ifp, struct ifreq *ifr)
{
	int error = 0, intval;

	VERIFY(ifp != NULL);

	bcopy(&ifr->ifr_intval, &intval, sizeof(intval));

	ifnet_lock_exclusive(ifp);
	if (intval) {
		/*
		 * An interface in IPv4 router mode implies that it
		 * is configured with a static IP address and should
		 * not act as a DHCP client; prevent SIOCAUTOADDR from
		 * being set in that mode.
		 */
		if (ifp->if_eflags & IFEF_IPV4_ROUTER) {
			intval = 0;     /* be safe; clear flag if set */
			error = EBUSY;
		} else {
			ifp->if_eflags |= IFEF_AUTOCONFIGURING;
		}
	}
	if (!intval) {
		ifp->if_eflags &= ~IFEF_AUTOCONFIGURING;
	}
	ifnet_lock_done(ifp);

	return error;
}

/*
 * Caller passes in the ioctl data pointer directly via "ifr", with the
 * expectation that this routine always uses bcopy() or other byte-aligned
 * memory accesses.
 */
static __attribute__((noinline)) int
inctl_arpipll(struct ifnet *ifp, struct ifreq *ifr)
{
	int error = 0, intval;

	VERIFY(ifp != NULL);

	bcopy(&ifr->ifr_intval, &intval, sizeof(intval));
	ipv4_ll_arp_aware = 1;

	ifnet_lock_exclusive(ifp);
	if (intval) {
		/*
		 * An interface in IPv4 router mode implies that it
		 * is configured with a static IP address and should
		 * not have to deal with IPv4 Link-Local Address;
		 * prevent SIOCARPIPLL from being set in that mode.
		 */
		if (ifp->if_eflags & IFEF_IPV4_ROUTER) {
			intval = 0;     /* be safe; clear flag if set */
			error = EBUSY;
		} else {
			ifp->if_eflags |= IFEF_ARPLL;
		}
	}
	if (!intval) {
		ifp->if_eflags &= ~IFEF_ARPLL;
	}
	ifnet_lock_done(ifp);

	return error;
}

/*
 * Handle SIOCSETROUTERMODE to set or clear the IPv4 router mode flag on
 * the interface.  When in this mode, IPv4 Link-Local Address support is
 * disabled in ARP, and DHCP client support is disabled in IP input; turning
 * any of them on would cause an error to be returned.  Entering or exiting
 * this mode will result in the removal of IPv4 addresses currently configured
 * on the interface.
 *
 * Caller passes in the ioctl data pointer directly via "ifr", with the
 * expectation that this routine always uses bcopy() or other byte-aligned
 * memory accesses.
 */
static __attribute__((noinline)) int
inctl_setrouter(struct ifnet *ifp, struct ifreq *ifr)
{
	int error = 0, intval;

	VERIFY(ifp != NULL);

	/* Router mode isn't valid for loopback */
	if (ifp->if_flags & IFF_LOOPBACK) {
		return ENODEV;
	}

	bcopy(&ifr->ifr_intval, &intval, sizeof(intval));

	ifnet_lock_exclusive(ifp);
	if (intval) {
		ifp->if_eflags |= IFEF_IPV4_ROUTER;
		ifp->if_eflags &= ~(IFEF_ARPLL | IFEF_AUTOCONFIGURING);
	} else {
		ifp->if_eflags &= ~IFEF_IPV4_ROUTER;
	}
	ifnet_lock_done(ifp);

	/* purge all IPv4 addresses configured on this interface */
	in_purgeaddrs(ifp);

	return error;
}

/*
 * Caller passes in the ioctl data pointer directly via "ifr", with the
 * expectation that this routine always uses bcopy() or other byte-aligned
 * memory accesses.
 */
static __attribute__((noinline)) int
inctl_ifaddr(struct ifnet *ifp, struct in_ifaddr *ia, u_long cmd,
    struct ifreq *ifr)
{
	struct kev_in_data in_event_data;
	struct kev_msg ev_msg;
	struct sockaddr_in addr;
	struct ifaddr *ifa;
	int error = 0;

	VERIFY(ifp != NULL);

	bzero(&in_event_data, sizeof(struct kev_in_data));
	bzero(&ev_msg, sizeof(struct kev_msg));

	switch (cmd) {
	case SIOCGIFADDR:               /* struct ifreq */
		if (ia == NULL) {
			error = EADDRNOTAVAIL;
			break;
		}
		IFA_LOCK(&ia->ia_ifa);
		bcopy(&ia->ia_addr, &ifr->ifr_addr, sizeof(addr));
		IFA_UNLOCK(&ia->ia_ifa);
		break;

	case SIOCSIFADDR:               /* struct ifreq */
		VERIFY(ia != NULL);
		bcopy(&ifr->ifr_addr, &addr, sizeof(addr));
		/*
		 * If this is a new address, the reference count for the
		 * hash table has been taken at creation time above.
		 */
		error = in_ifinit(ifp, ia, &addr, 1);
		if (error == 0) {
			(void) ifnet_notify_address(ifp, AF_INET);
		}
		break;

	case SIOCAIFADDR: {             /* struct {if,in_}aliasreq */
		struct in_aliasreq *ifra = (struct in_aliasreq *)ifr;
		struct sockaddr_in broadaddr, mask;
		int hostIsNew, maskIsNew;

		VERIFY(ia != NULL);
		bcopy(&ifra->ifra_addr, &addr, sizeof(addr));
		bcopy(&ifra->ifra_broadaddr, &broadaddr, sizeof(broadaddr));
		bcopy(&ifra->ifra_mask, &mask, sizeof(mask));

		maskIsNew = 0;
		hostIsNew = 1;
		error = 0;

		IFA_LOCK(&ia->ia_ifa);
		if (ia->ia_addr.sin_family == AF_INET) {
			if (addr.sin_len == 0) {
				addr = ia->ia_addr;
				hostIsNew = 0;
			} else if (addr.sin_addr.s_addr ==
			    ia->ia_addr.sin_addr.s_addr) {
				hostIsNew = 0;
			}
		}
		if (mask.sin_len != 0) {
			IFA_UNLOCK(&ia->ia_ifa);
			in_ifscrub(ifp, ia, 0);
			IFA_LOCK(&ia->ia_ifa);
			ia->ia_sockmask = mask;
			ia->ia_subnetmask =
			    ntohl(ia->ia_sockmask.sin_addr.s_addr);
			maskIsNew = 1;
		}
		if ((ifp->if_flags & IFF_POINTOPOINT) &&
		    (broadaddr.sin_family == AF_INET)) {
			IFA_UNLOCK(&ia->ia_ifa);
			in_ifscrub(ifp, ia, 0);
			IFA_LOCK(&ia->ia_ifa);
			ia->ia_dstaddr = broadaddr;
			ia->ia_dstaddr.sin_family = AF_INET;
			ia->ia_dstaddr.sin_len = sizeof(struct sockaddr_in);
			ia->ia_dstaddr.sin_port = 0;
			bzero(&ia->ia_dstaddr.sin_zero, sizeof(ia->ia_dstaddr.sin_zero));
			maskIsNew  = 1; /* We lie; but the effect's the same */
		}
		if (addr.sin_family == AF_INET && (hostIsNew || maskIsNew)) {
			IFA_UNLOCK(&ia->ia_ifa);
			error = in_ifinit(ifp, ia, &addr, 0);
		} else {
			IFA_UNLOCK(&ia->ia_ifa);
		}
		if (error == 0) {
			(void) ifnet_notify_address(ifp, AF_INET);
		}
		IFA_LOCK(&ia->ia_ifa);
		if ((ifp->if_flags & IFF_BROADCAST) &&
		    (broadaddr.sin_family == AF_INET)) {
			ia->ia_broadaddr.sin_family = AF_INET;
			ia->ia_broadaddr.sin_len = sizeof(struct sockaddr_in);
			ia->ia_broadaddr.sin_port = 0;
			ia->ia_broadaddr.sin_addr = broadaddr.sin_addr;
			bzero(&ia->ia_broadaddr.sin_zero, sizeof(ia->ia_broadaddr.sin_zero));
		}

		/*
		 * Report event.
		 */
		if ((error == 0) || (error == EEXIST)) {
			ev_msg.vendor_code      = KEV_VENDOR_APPLE;
			ev_msg.kev_class        = KEV_NETWORK_CLASS;
			ev_msg.kev_subclass     = KEV_INET_SUBCLASS;

			if (hostIsNew) {
				ev_msg.event_code = KEV_INET_NEW_ADDR;
			} else {
				ev_msg.event_code = KEV_INET_CHANGED_ADDR;
			}

			if (ia->ia_ifa.ifa_dstaddr) {
				in_event_data.ia_dstaddr =
				    ((struct sockaddr_in *)(void *)ia->
				    ia_ifa.ifa_dstaddr)->sin_addr;
			} else {
				in_event_data.ia_dstaddr.s_addr = INADDR_ANY;
			}
			in_event_data.ia_addr           = ia->ia_addr.sin_addr;
			in_event_data.ia_net            = ia->ia_net;
			in_event_data.ia_netmask        = ia->ia_netmask;
			in_event_data.ia_subnet         = ia->ia_subnet;
			in_event_data.ia_subnetmask     = ia->ia_subnetmask;
			in_event_data.ia_netbroadcast   = ia->ia_netbroadcast;
			IFA_UNLOCK(&ia->ia_ifa);
			(void) strlcpy(&in_event_data.link_data.if_name[0],
			    ifp->if_name, IFNAMSIZ);
			in_event_data.link_data.if_family = ifp->if_family;
			in_event_data.link_data.if_unit = ifp->if_unit;

			ev_msg.dv[0].data_ptr    = &in_event_data;
			ev_msg.dv[0].data_length = sizeof(struct kev_in_data);
			ev_msg.dv[1].data_length = 0;

			dlil_post_complete_msg(ifp, &ev_msg);
		} else {
			IFA_UNLOCK(&ia->ia_ifa);
		}
		break;
	}

	case SIOCDIFADDR:               /* struct ifreq */
		VERIFY(ia != NULL);
		error = ifnet_ioctl(ifp, PF_INET, SIOCDIFADDR, ia);
		if (error == EOPNOTSUPP) {
			error = 0;
		}
		if (error != 0) {
			break;
		}

		/* Fill out the kernel event information */
		ev_msg.vendor_code      = KEV_VENDOR_APPLE;
		ev_msg.kev_class        = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass     = KEV_INET_SUBCLASS;

		ev_msg.event_code       = KEV_INET_ADDR_DELETED;

		IFA_LOCK(&ia->ia_ifa);
		if (ia->ia_ifa.ifa_dstaddr) {
			in_event_data.ia_dstaddr = ((struct sockaddr_in *)
			    (void *)ia->ia_ifa.ifa_dstaddr)->sin_addr;
		} else {
			in_event_data.ia_dstaddr.s_addr = INADDR_ANY;
		}
		in_event_data.ia_addr           = ia->ia_addr.sin_addr;
		in_event_data.ia_net            = ia->ia_net;
		in_event_data.ia_netmask        = ia->ia_netmask;
		in_event_data.ia_subnet         = ia->ia_subnet;
		in_event_data.ia_subnetmask     = ia->ia_subnetmask;
		in_event_data.ia_netbroadcast   = ia->ia_netbroadcast;
		IFA_UNLOCK(&ia->ia_ifa);
		(void) strlcpy(&in_event_data.link_data.if_name[0],
		    ifp->if_name, IFNAMSIZ);
		in_event_data.link_data.if_family = ifp->if_family;
		in_event_data.link_data.if_unit  = (u_int32_t)ifp->if_unit;

		ev_msg.dv[0].data_ptr    = &in_event_data;
		ev_msg.dv[0].data_length = sizeof(struct kev_in_data);
		ev_msg.dv[1].data_length = 0;

		ifa = &ia->ia_ifa;
		lck_rw_lock_exclusive(in_ifaddr_rwlock);
		/* Release ia_link reference */
		IFA_REMREF(ifa);
		TAILQ_REMOVE(&in_ifaddrhead, ia, ia_link);
		IFA_LOCK(ifa);
		if (IA_IS_HASHED(ia)) {
			in_iahash_remove(ia);
		}
		IFA_UNLOCK(ifa);
		lck_rw_done(in_ifaddr_rwlock);

		/*
		 * in_ifscrub kills the interface route.
		 */
		in_ifscrub(ifp, ia, 0);
		ifnet_lock_exclusive(ifp);
		IFA_LOCK(ifa);
		/* if_detach_ifa() releases ifa_link reference */
		if_detach_ifa(ifp, ifa);
		/* Our reference to this address is dropped at the bottom */
		IFA_UNLOCK(ifa);

		/* invalidate route caches */
		routegenid_inet_update();

		/*
		 * If the interface supports multicast, and no address is left,
		 * remove the "all hosts" multicast group from that interface.
		 */
		if ((ifp->if_flags & IFF_MULTICAST) ||
		    ifp->if_allhostsinm != NULL) {
			TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
				IFA_LOCK(ifa);
				if (ifa->ifa_addr->sa_family == AF_INET) {
					IFA_UNLOCK(ifa);
					break;
				}
				IFA_UNLOCK(ifa);
			}
			ifnet_lock_done(ifp);

			lck_mtx_lock(&ifp->if_addrconfig_lock);
			if (ifa == NULL && ifp->if_allhostsinm != NULL) {
				struct in_multi *inm = ifp->if_allhostsinm;
				ifp->if_allhostsinm = NULL;

				in_delmulti(inm);
				/* release the reference for allhostsinm */
				INM_REMREF(inm);
			}
			lck_mtx_unlock(&ifp->if_addrconfig_lock);
		} else {
			ifnet_lock_done(ifp);
		}

		/* Post the kernel event */
		dlil_post_complete_msg(ifp, &ev_msg);

		/*
		 * See if there is any IPV4 address left and if so,
		 * reconfigure KDP to use current primary address.
		 */
		ifa = ifa_ifpgetprimary(ifp, AF_INET);
		if (ifa != NULL) {
			/*
			 * NOTE: SIOCSIFADDR is defined with struct ifreq
			 * as parameter, but here we are sending it down
			 * to the interface with a pointer to struct ifaddr,
			 * for legacy reasons.
			 */
			error = ifnet_ioctl(ifp, PF_INET, SIOCSIFADDR, ifa);
			if (error == EOPNOTSUPP) {
				error = 0;
			}

			/* Release reference from ifa_ifpgetprimary() */
			IFA_REMREF(ifa);
		}
		(void) ifnet_notify_address(ifp, AF_INET);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return error;
}

/*
 * Caller passes in the ioctl data pointer directly via "ifr", with the
 * expectation that this routine always uses bcopy() or other byte-aligned
 * memory accesses.
 */
static __attribute__((noinline)) int
inctl_ifdstaddr(struct ifnet *ifp, struct in_ifaddr *ia, u_long cmd,
    struct ifreq *ifr)
{
	struct kev_in_data in_event_data;
	struct kev_msg ev_msg;
	struct sockaddr_in dstaddr;
	int error = 0;

	VERIFY(ifp != NULL);

	if (!(ifp->if_flags & IFF_POINTOPOINT)) {
		return EINVAL;
	}

	bzero(&in_event_data, sizeof(struct kev_in_data));
	bzero(&ev_msg, sizeof(struct kev_msg));

	switch (cmd) {
	case SIOCGIFDSTADDR:            /* struct ifreq */
		if (ia == NULL) {
			error = EADDRNOTAVAIL;
			break;
		}
		IFA_LOCK(&ia->ia_ifa);
		bcopy(&ia->ia_dstaddr, &ifr->ifr_dstaddr, sizeof(dstaddr));
		IFA_UNLOCK(&ia->ia_ifa);
		break;

	case SIOCSIFDSTADDR:            /* struct ifreq */
		VERIFY(ia != NULL);
		IFA_LOCK(&ia->ia_ifa);
		dstaddr = ia->ia_dstaddr;

		bcopy(&ifr->ifr_dstaddr, &ia->ia_dstaddr, sizeof(dstaddr));
		ia->ia_dstaddr.sin_family = AF_INET;
		ia->ia_dstaddr.sin_len = sizeof(struct sockaddr_in);
		ia->ia_dstaddr.sin_port = 0;
		bzero(&ia->ia_dstaddr.sin_zero, sizeof(ia->ia_dstaddr.sin_zero));

		IFA_UNLOCK(&ia->ia_ifa);
		/*
		 * NOTE: SIOCSIFDSTADDR is defined with struct ifreq
		 * as parameter, but here we are sending it down
		 * to the interface with a pointer to struct ifaddr,
		 * for legacy reasons.
		 */
		error = ifnet_ioctl(ifp, PF_INET, SIOCSIFDSTADDR, ia);
		IFA_LOCK(&ia->ia_ifa);
		if (error == EOPNOTSUPP) {
			error = 0;
		}
		if (error != 0) {
			ia->ia_dstaddr = dstaddr;
			IFA_UNLOCK(&ia->ia_ifa);
			break;
		}
		IFA_LOCK_ASSERT_HELD(&ia->ia_ifa);

		ev_msg.vendor_code      = KEV_VENDOR_APPLE;
		ev_msg.kev_class        = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass     = KEV_INET_SUBCLASS;

		ev_msg.event_code       = KEV_INET_SIFDSTADDR;

		if (ia->ia_ifa.ifa_dstaddr) {
			in_event_data.ia_dstaddr = ((struct sockaddr_in *)
			    (void *)ia->ia_ifa.ifa_dstaddr)->sin_addr;
		} else {
			in_event_data.ia_dstaddr.s_addr = INADDR_ANY;
		}

		in_event_data.ia_addr           = ia->ia_addr.sin_addr;
		in_event_data.ia_net            = ia->ia_net;
		in_event_data.ia_netmask        = ia->ia_netmask;
		in_event_data.ia_subnet         = ia->ia_subnet;
		in_event_data.ia_subnetmask     = ia->ia_subnetmask;
		in_event_data.ia_netbroadcast   = ia->ia_netbroadcast;
		IFA_UNLOCK(&ia->ia_ifa);
		(void) strlcpy(&in_event_data.link_data.if_name[0],
		    ifp->if_name, IFNAMSIZ);
		in_event_data.link_data.if_family = ifp->if_family;
		in_event_data.link_data.if_unit  = (u_int32_t)ifp->if_unit;

		ev_msg.dv[0].data_ptr    = &in_event_data;
		ev_msg.dv[0].data_length = sizeof(struct kev_in_data);
		ev_msg.dv[1].data_length = 0;

		dlil_post_complete_msg(ifp, &ev_msg);

		lck_mtx_lock(rnh_lock);
		IFA_LOCK(&ia->ia_ifa);
		if (ia->ia_flags & IFA_ROUTE) {
			ia->ia_ifa.ifa_dstaddr = (struct sockaddr *)&dstaddr;
			IFA_UNLOCK(&ia->ia_ifa);
			rtinit_locked(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
			IFA_LOCK(&ia->ia_ifa);
			ia->ia_ifa.ifa_dstaddr =
			    (struct sockaddr *)&ia->ia_dstaddr;
			IFA_UNLOCK(&ia->ia_ifa);
			rtinit_locked(&(ia->ia_ifa), (int)RTM_ADD,
			    RTF_HOST | RTF_UP);
		} else {
			IFA_UNLOCK(&ia->ia_ifa);
		}
		lck_mtx_unlock(rnh_lock);
		break;



	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return error;
}

/*
 * Caller passes in the ioctl data pointer directly via "ifr", with the
 * expectation that this routine always uses bcopy() or other byte-aligned
 * memory accesses.
 */
static __attribute__((noinline)) int
inctl_ifbrdaddr(struct ifnet *ifp, struct in_ifaddr *ia, u_long cmd,
    struct ifreq *ifr)
{
	struct kev_in_data in_event_data;
	struct kev_msg ev_msg;
	int error = 0;

	VERIFY(ifp != NULL);

	if (ia == NULL) {
		return EADDRNOTAVAIL;
	}

	if (!(ifp->if_flags & IFF_BROADCAST)) {
		return EINVAL;
	}

	bzero(&in_event_data, sizeof(struct kev_in_data));
	bzero(&ev_msg, sizeof(struct kev_msg));

	switch (cmd) {
	case SIOCGIFBRDADDR:            /* struct ifreq */
		IFA_LOCK(&ia->ia_ifa);
		bcopy(&ia->ia_broadaddr, &ifr->ifr_broadaddr,
		    sizeof(struct sockaddr_in));
		IFA_UNLOCK(&ia->ia_ifa);
		break;

	case SIOCSIFBRDADDR:            /* struct ifreq */
		IFA_LOCK(&ia->ia_ifa);
		bcopy(&ifr->ifr_broadaddr, &ia->ia_broadaddr,
		    sizeof(struct sockaddr_in));

		ia->ia_broadaddr.sin_family = AF_INET;
		ia->ia_broadaddr.sin_len = sizeof(struct sockaddr_in);
		ia->ia_broadaddr.sin_port = 0;
		bzero(&ia->ia_broadaddr.sin_zero, sizeof(ia->ia_broadaddr.sin_zero));

		ev_msg.vendor_code      = KEV_VENDOR_APPLE;
		ev_msg.kev_class        = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass     = KEV_INET_SUBCLASS;

		ev_msg.event_code = KEV_INET_SIFBRDADDR;

		if (ia->ia_ifa.ifa_dstaddr) {
			in_event_data.ia_dstaddr = ((struct sockaddr_in *)
			    (void *)ia->ia_ifa.ifa_dstaddr)->sin_addr;
		} else {
			in_event_data.ia_dstaddr.s_addr = INADDR_ANY;
		}
		in_event_data.ia_addr           = ia->ia_addr.sin_addr;
		in_event_data.ia_net            = ia->ia_net;
		in_event_data.ia_netmask        = ia->ia_netmask;
		in_event_data.ia_subnet         = ia->ia_subnet;
		in_event_data.ia_subnetmask     = ia->ia_subnetmask;
		in_event_data.ia_netbroadcast   = ia->ia_netbroadcast;
		IFA_UNLOCK(&ia->ia_ifa);
		(void) strlcpy(&in_event_data.link_data.if_name[0],
		    ifp->if_name, IFNAMSIZ);
		in_event_data.link_data.if_family = ifp->if_family;
		in_event_data.link_data.if_unit  = (u_int32_t)ifp->if_unit;

		ev_msg.dv[0].data_ptr    = &in_event_data;
		ev_msg.dv[0].data_length = sizeof(struct kev_in_data);
		ev_msg.dv[1].data_length = 0;

		dlil_post_complete_msg(ifp, &ev_msg);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return error;
}

/*
 * Caller passes in the ioctl data pointer directly via "ifr", with the
 * expectation that this routine always uses bcopy() or other byte-aligned
 * memory accesses.
 */
static __attribute__((noinline)) int
inctl_ifnetmask(struct ifnet *ifp, struct in_ifaddr *ia, u_long cmd,
    struct ifreq *ifr)
{
	struct kev_in_data in_event_data;
	struct kev_msg ev_msg;
	struct sockaddr_in mask;
	int error = 0;

	VERIFY(ifp != NULL);

	bzero(&in_event_data, sizeof(struct kev_in_data));
	bzero(&ev_msg, sizeof(struct kev_msg));

	switch (cmd) {
	case SIOCGIFNETMASK:            /* struct ifreq */
		if (ia == NULL) {
			error = EADDRNOTAVAIL;
			break;
		}
		IFA_LOCK(&ia->ia_ifa);
		bcopy(&ia->ia_sockmask, &ifr->ifr_addr, sizeof(mask));
		IFA_UNLOCK(&ia->ia_ifa);
		break;

	case SIOCSIFNETMASK: {          /* struct ifreq */
		in_addr_t i;

		bcopy(&ifr->ifr_addr, &mask, sizeof(mask));
		i = mask.sin_addr.s_addr;

		VERIFY(ia != NULL);
		IFA_LOCK(&ia->ia_ifa);
		ia->ia_subnetmask = ntohl(ia->ia_sockmask.sin_addr.s_addr = i);
		ev_msg.vendor_code      = KEV_VENDOR_APPLE;
		ev_msg.kev_class        = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass     = KEV_INET_SUBCLASS;

		ev_msg.event_code = KEV_INET_SIFNETMASK;

		if (ia->ia_ifa.ifa_dstaddr) {
			in_event_data.ia_dstaddr = ((struct sockaddr_in *)
			    (void *)ia->ia_ifa.ifa_dstaddr)->sin_addr;
		} else {
			in_event_data.ia_dstaddr.s_addr = INADDR_ANY;
		}
		in_event_data.ia_addr           = ia->ia_addr.sin_addr;
		in_event_data.ia_net            = ia->ia_net;
		in_event_data.ia_netmask        = ia->ia_netmask;
		in_event_data.ia_subnet         = ia->ia_subnet;
		in_event_data.ia_subnetmask     = ia->ia_subnetmask;
		in_event_data.ia_netbroadcast   = ia->ia_netbroadcast;
		IFA_UNLOCK(&ia->ia_ifa);
		(void) strlcpy(&in_event_data.link_data.if_name[0],
		    ifp->if_name, IFNAMSIZ);
		in_event_data.link_data.if_family = ifp->if_family;
		in_event_data.link_data.if_unit  = (u_int32_t)ifp->if_unit;

		ev_msg.dv[0].data_ptr    = &in_event_data;
		ev_msg.dv[0].data_length = sizeof(struct kev_in_data);
		ev_msg.dv[1].data_length = 0;

		dlil_post_complete_msg(ifp, &ev_msg);
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return error;
}

/*
 * Generic INET control operations (ioctl's).
 *
 * ifp is NULL if not an interface-specific ioctl.
 *
 * Most of the routines called to handle the ioctls would end up being
 * tail-call optimized, which unfortunately causes this routine to
 * consume too much stack space; this is the reason for the "noinline"
 * attribute used on those routines.
 *
 * If called directly from within the networking stack (as opposed to via
 * pru_control), the socket parameter may be NULL.
 */
int
in_control(struct socket *so, u_long cmd, caddr_t data, struct ifnet *ifp,
    struct proc *p)
{
	struct ifreq *ifr = (struct ifreq *)(void *)data;
	struct sockaddr_in addr, dstaddr;
	struct sockaddr_in sin, *sa = NULL;
	boolean_t privileged = (proc_suser(p) == 0);
	boolean_t so_unlocked = FALSE;
	struct in_ifaddr *ia = NULL;
	struct ifaddr *ifa;
	int error = 0;

	/* In case it's NULL, make sure it came from the kernel */
	VERIFY(so != NULL || p == kernproc);

	/*
	 * ioctls which don't require ifp, but require socket.
	 */
	switch (cmd) {
	case SIOCGASSOCIDS32:           /* struct so_aidreq32 */
	case SIOCGASSOCIDS64:           /* struct so_aidreq64 */
		return inctl_associd(so, cmd, data);
	/* NOTREACHED */

	case SIOCGCONNIDS32:            /* struct so_cidreq32 */
	case SIOCGCONNIDS64:            /* struct so_cidreq64 */
		return inctl_connid(so, cmd, data);
	/* NOTREACHED */

	case SIOCGCONNINFO32:           /* struct so_cinforeq32 */
	case SIOCGCONNINFO64:           /* struct so_cinforeq64 */
		return inctl_conninfo(so, cmd, data);
		/* NOTREACHED */
	}

	/*
	 * The rest of ioctls require ifp; reject if we don't have one;
	 * return ENXIO to be consistent with ifioctl().
	 */
	if (ifp == NULL) {
		return ENXIO;
	}

	/*
	 * ioctls which require ifp but not interface address.
	 */
	switch (cmd) {
	case SIOCAUTOADDR:              /* struct ifreq */
		if (!privileged) {
			return EPERM;
		}
		return inctl_autoaddr(ifp, ifr);
	/* NOTREACHED */

	case SIOCARPIPLL:               /* struct ifreq */
		if (!privileged) {
			return EPERM;
		}
		return inctl_arpipll(ifp, ifr);
	/* NOTREACHED */

	case SIOCSETROUTERMODE:         /* struct ifreq */
		if (!privileged) {
			return EPERM;
		}
		return inctl_setrouter(ifp, ifr);
	/* NOTREACHED */

	case SIOCPROTOATTACH:           /* struct ifreq */
		if (!privileged) {
			return EPERM;
		}
		return in_domifattach(ifp);
	/* NOTREACHED */

	case SIOCPROTODETACH:           /* struct ifreq */
		if (!privileged) {
			return EPERM;
		}

		/*
		 * If an IPv4 address is still present, refuse to detach.
		 */
		ifnet_lock_shared(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			IFA_LOCK(ifa);
			if (ifa->ifa_addr->sa_family == AF_INET) {
				IFA_UNLOCK(ifa);
				break;
			}
			IFA_UNLOCK(ifa);
		}
		ifnet_lock_done(ifp);
		return (ifa == NULL) ? proto_unplumb(PF_INET, ifp) : EBUSY;
		/* NOTREACHED */
	}

	/*
	 * ioctls which require interface address; obtain sockaddr_in.
	 */
	switch (cmd) {
	case SIOCAIFADDR:               /* struct {if,in_}aliasreq */
		if (!privileged) {
			return EPERM;
		}
		bcopy(&((struct in_aliasreq *)(void *)data)->ifra_addr,
		    &sin, sizeof(sin));
		sa = &sin;
		break;

	case SIOCDIFADDR:               /* struct ifreq */
	case SIOCSIFADDR:               /* struct ifreq */
	case SIOCSIFDSTADDR:            /* struct ifreq */
	case SIOCSIFNETMASK:            /* struct ifreq */
	case SIOCSIFBRDADDR:            /* struct ifreq */
		if (!privileged) {
			return EPERM;
		}
	/* FALLTHRU */
	case SIOCGIFADDR:               /* struct ifreq */
	case SIOCGIFDSTADDR:            /* struct ifreq */
	case SIOCGIFNETMASK:            /* struct ifreq */
	case SIOCGIFBRDADDR:            /* struct ifreq */
		bcopy(&ifr->ifr_addr, &sin, sizeof(sin));
		sa = &sin;
		break;
	}

	/*
	 * Find address for this interface, if it exists.
	 *
	 * If an alias address was specified, find that one instead of
	 * the first one on the interface, if possible.
	 */
	VERIFY(ia == NULL);
	if (sa != NULL) {
		struct in_ifaddr *iap;

		/*
		 * Any failures from this point on must take into account
		 * a non-NULL "ia" with an outstanding reference count, and
		 * therefore requires IFA_REMREF.  Jump to "done" label
		 * instead of calling return if "ia" is valid.
		 */
		lck_rw_lock_shared(in_ifaddr_rwlock);
		TAILQ_FOREACH(iap, INADDR_HASH(sa->sin_addr.s_addr), ia_hash) {
			IFA_LOCK(&iap->ia_ifa);
			if (iap->ia_ifp == ifp &&
			    iap->ia_addr.sin_addr.s_addr ==
			    sa->sin_addr.s_addr) {
				ia = iap;
				IFA_ADDREF_LOCKED(&iap->ia_ifa);
				IFA_UNLOCK(&iap->ia_ifa);
				break;
			}
			IFA_UNLOCK(&iap->ia_ifa);
		}
		lck_rw_done(in_ifaddr_rwlock);

		if (ia == NULL) {
			ifnet_lock_shared(ifp);
			TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
				iap = ifatoia(ifa);
				IFA_LOCK(&iap->ia_ifa);
				if (iap->ia_addr.sin_family == AF_INET) {
					ia = iap;
					IFA_ADDREF_LOCKED(&iap->ia_ifa);
					IFA_UNLOCK(&iap->ia_ifa);
					break;
				}
				IFA_UNLOCK(&iap->ia_ifa);
			}
			ifnet_lock_done(ifp);
		}
	}

	/*
	 * Unlock the socket since ifnet_ioctl() may be invoked by
	 * one of the ioctl handlers below.  Socket will be re-locked
	 * prior to returning.
	 */
	if (so != NULL) {
		socket_unlock(so, 0);
		so_unlocked = TRUE;
	}

	switch (cmd) {
	case SIOCAIFADDR:               /* struct {if,in_}aliasreq */
	case SIOCDIFADDR:               /* struct ifreq */
		if (cmd == SIOCAIFADDR) {
			bcopy(&((struct in_aliasreq *)(void *)data)->
			    ifra_addr, &addr, sizeof(addr));
			bcopy(&((struct in_aliasreq *)(void *)data)->
			    ifra_dstaddr, &dstaddr, sizeof(dstaddr));
		} else {
			VERIFY(cmd == SIOCDIFADDR);
			bcopy(&((struct ifreq *)(void *)data)->ifr_addr,
			    &addr, sizeof(addr));
			bzero(&dstaddr, sizeof(dstaddr));
		}

		if (addr.sin_family == AF_INET) {
			struct in_ifaddr *oia;

			lck_rw_lock_shared(in_ifaddr_rwlock);
			for (oia = ia; ia; ia = ia->ia_link.tqe_next) {
				IFA_LOCK(&ia->ia_ifa);
				if (ia->ia_ifp == ifp &&
				    ia->ia_addr.sin_addr.s_addr ==
				    addr.sin_addr.s_addr) {
					IFA_ADDREF_LOCKED(&ia->ia_ifa);
					IFA_UNLOCK(&ia->ia_ifa);
					break;
				}
				IFA_UNLOCK(&ia->ia_ifa);
			}
			lck_rw_done(in_ifaddr_rwlock);
			if (oia != NULL) {
				IFA_REMREF(&oia->ia_ifa);
			}
			if ((ifp->if_flags & IFF_POINTOPOINT) &&
			    (cmd == SIOCAIFADDR) &&
			    (dstaddr.sin_addr.s_addr == INADDR_ANY)) {
				error = EDESTADDRREQ;
				goto done;
			}
		} else if (cmd == SIOCAIFADDR) {
			error = EINVAL;
			goto done;
		}
		if (cmd == SIOCDIFADDR) {
			if (ia == NULL) {
				error = EADDRNOTAVAIL;
				goto done;
			}

			IFA_LOCK(&ia->ia_ifa);
			/*
			 * Avoid the race condition seen when two
			 * threads process SIOCDIFADDR command
			 * at the same time.
			 */
			while (ia->ia_ifa.ifa_debug & IFD_DETACHING) {
				os_log(OS_LOG_DEFAULT,
				    "Another thread is already attempting to "
				    "delete IPv4 address: %s on interface %s. "
				    "Go to sleep and check again after the operation is done",
				    inet_ntoa(sa->sin_addr), ia->ia_ifp->if_xname);
				ia->ia_ifa.ifa_del_waiters++;
				(void) msleep(ia->ia_ifa.ifa_del_wc, &ia->ia_ifa.ifa_lock, (PZERO - 1),
				    __func__, NULL);
				IFA_LOCK_ASSERT_HELD(&ia->ia_ifa);
			}

			if ((ia->ia_ifa.ifa_debug & IFD_ATTACHED) == 0) {
				error = EADDRNOTAVAIL;
				IFA_UNLOCK(&ia->ia_ifa);
				goto done;
			}

			ia->ia_ifa.ifa_debug |= IFD_DETACHING;
			IFA_UNLOCK(&ia->ia_ifa);
		}

	/* FALLTHROUGH */
	case SIOCSIFADDR:               /* struct ifreq */
	case SIOCSIFDSTADDR:            /* struct ifreq */
	case SIOCSIFNETMASK:            /* struct ifreq */
		if (cmd == SIOCAIFADDR) {
			/* fell thru from above; just repeat it */
			bcopy(&((struct in_aliasreq *)(void *)data)->
			    ifra_addr, &addr, sizeof(addr));
		} else {
			VERIFY(cmd == SIOCDIFADDR || cmd == SIOCSIFADDR ||
			    cmd == SIOCSIFNETMASK || cmd == SIOCSIFDSTADDR);
			bcopy(&((struct ifreq *)(void *)data)->ifr_addr,
			    &addr, sizeof(addr));
		}

		if (addr.sin_family != AF_INET && cmd == SIOCSIFADDR) {
			error = EINVAL;
			goto done;
		}
		if (ia == NULL) {
			ia = in_ifaddr_alloc(M_WAITOK);
			if (ia == NULL) {
				error = ENOBUFS;
				goto done;
			}
			ifnet_lock_exclusive(ifp);
			ifa = &ia->ia_ifa;
			IFA_LOCK(ifa);
			/* Hold a reference for this routine */
			IFA_ADDREF_LOCKED(ifa);
			IA_HASH_INIT(ia);
			ifa->ifa_addr = (struct sockaddr *)&ia->ia_addr;
			ifa->ifa_dstaddr = (struct sockaddr *)&ia->ia_dstaddr;
			ifa->ifa_netmask = (struct sockaddr *)&ia->ia_sockmask;
			ia->ia_sockmask.sin_len = offsetof(struct sockaddr_in, sin_zero);
			if (ifp->if_flags & IFF_BROADCAST) {
				ia->ia_broadaddr.sin_len = sizeof(ia->ia_addr);
				ia->ia_broadaddr.sin_family = AF_INET;
			}
			ia->ia_ifp = ifp;
			if (!(ifp->if_flags & IFF_LOOPBACK)) {
				in_interfaces++;
			}
			/* if_attach_ifa() holds a reference for ifa_link */
			if_attach_ifa(ifp, ifa);
			/*
			 * If we have to go through in_ifinit(), make sure
			 * to avoid installing route(s) based on this address
			 * via PFC_IFUP event, before the link resolver (ARP)
			 * initializes it.
			 */
			if (cmd == SIOCAIFADDR || cmd == SIOCSIFADDR) {
				ifa->ifa_debug |= IFD_NOTREADY;
			}
			IFA_UNLOCK(ifa);
			ifnet_lock_done(ifp);
			lck_rw_lock_exclusive(in_ifaddr_rwlock);
			/* Hold a reference for ia_link */
			IFA_ADDREF(ifa);
			TAILQ_INSERT_TAIL(&in_ifaddrhead, ia, ia_link);
			lck_rw_done(in_ifaddr_rwlock);
			/* discard error */
			(void) in_domifattach(ifp);
			error = 0;
		}
		break;
	}

	switch (cmd) {
	case SIOCGIFDSTADDR:            /* struct ifreq */
	case SIOCSIFDSTADDR:            /* struct ifreq */
		error = inctl_ifdstaddr(ifp, ia, cmd, ifr);
		break;

	case SIOCGIFBRDADDR:            /* struct ifreq */
	case SIOCSIFBRDADDR:            /* struct ifreq */
		error = inctl_ifbrdaddr(ifp, ia, cmd, ifr);
		break;

	case SIOCGIFNETMASK:            /* struct ifreq */
	case SIOCSIFNETMASK:            /* struct ifreq */
		error = inctl_ifnetmask(ifp, ia, cmd, ifr);
		break;

	case SIOCGIFADDR:               /* struct ifreq */
	case SIOCSIFADDR:               /* struct ifreq */
	case SIOCAIFADDR:               /* struct {if,in_}aliasreq */
	case SIOCDIFADDR:               /* struct ifreq */
		error = inctl_ifaddr(ifp, ia, cmd, ifr);
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

done:
	if (ia != NULL) {
		if (cmd == SIOCDIFADDR) {
			IFA_LOCK(&ia->ia_ifa);
			ia->ia_ifa.ifa_debug &= ~IFD_DETACHING;
			if (ia->ia_ifa.ifa_del_waiters > 0) {
				ia->ia_ifa.ifa_del_waiters = 0;
				wakeup(ia->ia_ifa.ifa_del_wc);
			}
			IFA_UNLOCK(&ia->ia_ifa);
		}
		IFA_REMREF(&ia->ia_ifa);
	}
	if (so_unlocked) {
		socket_lock(so, 0);
	}

	return error;
}

/*
 * Delete any existing route for an interface.
 */
void
in_ifscrub(struct ifnet *ifp, struct in_ifaddr *ia, int locked)
{
	IFA_LOCK(&ia->ia_ifa);
	if ((ia->ia_flags & IFA_ROUTE) == 0) {
		IFA_UNLOCK(&ia->ia_ifa);
		return;
	}
	IFA_UNLOCK(&ia->ia_ifa);
	if (!locked) {
		lck_mtx_lock(rnh_lock);
	}
	if (ifp->if_flags & (IFF_LOOPBACK | IFF_POINTOPOINT)) {
		rtinit_locked(&(ia->ia_ifa), (int)RTM_DELETE, RTF_HOST);
	} else {
		rtinit_locked(&(ia->ia_ifa), (int)RTM_DELETE, 0);
	}
	IFA_LOCK(&ia->ia_ifa);
	ia->ia_flags &= ~IFA_ROUTE;
	IFA_UNLOCK(&ia->ia_ifa);
	if (!locked) {
		lck_mtx_unlock(rnh_lock);
	}
}

/*
 * Caller must hold in_ifaddr_rwlock as writer.
 */
static void
in_iahash_remove(struct in_ifaddr *ia)
{
	LCK_RW_ASSERT(in_ifaddr_rwlock, LCK_RW_ASSERT_EXCLUSIVE);
	IFA_LOCK_ASSERT_HELD(&ia->ia_ifa);

	if (!IA_IS_HASHED(ia)) {
		panic("attempt to remove wrong ia %p from hash table\n", ia);
		/* NOTREACHED */
	}
	TAILQ_REMOVE(INADDR_HASH(ia->ia_addr.sin_addr.s_addr), ia, ia_hash);
	IA_HASH_INIT(ia);
	if (IFA_REMREF_LOCKED(&ia->ia_ifa) == NULL) {
		panic("%s: unexpected (missing) refcnt ifa=%p", __func__,
		    &ia->ia_ifa);
		/* NOTREACHED */
	}
}

/*
 * Caller must hold in_ifaddr_rwlock as writer.
 */
static void
in_iahash_insert(struct in_ifaddr *ia)
{
	LCK_RW_ASSERT(in_ifaddr_rwlock, LCK_RW_ASSERT_EXCLUSIVE);
	IFA_LOCK_ASSERT_HELD(&ia->ia_ifa);

	if (ia->ia_addr.sin_family != AF_INET) {
		panic("attempt to insert wrong ia %p into hash table\n", ia);
		/* NOTREACHED */
	} else if (IA_IS_HASHED(ia)) {
		panic("attempt to double-insert ia %p into hash table\n", ia);
		/* NOTREACHED */
	}
	TAILQ_INSERT_HEAD(INADDR_HASH(ia->ia_addr.sin_addr.s_addr),
	    ia, ia_hash);
	IFA_ADDREF_LOCKED(&ia->ia_ifa);
}

/*
 * Some point to point interfaces that are tunnels borrow the address from
 * an underlying interface (e.g. VPN server). In order for source address
 * selection logic to find the underlying interface first, we add the address
 * of borrowing point to point interfaces at the end of the list.
 * (see rdar://6733789)
 *
 * Caller must hold in_ifaddr_rwlock as writer.
 */
static void
in_iahash_insert_ptp(struct in_ifaddr *ia)
{
	struct in_ifaddr *tmp_ifa;
	struct ifnet *tmp_ifp;

	LCK_RW_ASSERT(in_ifaddr_rwlock, LCK_RW_ASSERT_EXCLUSIVE);
	IFA_LOCK_ASSERT_HELD(&ia->ia_ifa);

	if (ia->ia_addr.sin_family != AF_INET) {
		panic("attempt to insert wrong ia %p into hash table\n", ia);
		/* NOTREACHED */
	} else if (IA_IS_HASHED(ia)) {
		panic("attempt to double-insert ia %p into hash table\n", ia);
		/* NOTREACHED */
	}
	IFA_UNLOCK(&ia->ia_ifa);
	TAILQ_FOREACH(tmp_ifa, INADDR_HASH(ia->ia_addr.sin_addr.s_addr),
	    ia_hash) {
		IFA_LOCK(&tmp_ifa->ia_ifa);
		/* ia->ia_addr won't change, so check without lock */
		if (IA_SIN(tmp_ifa)->sin_addr.s_addr ==
		    ia->ia_addr.sin_addr.s_addr) {
			IFA_UNLOCK(&tmp_ifa->ia_ifa);
			break;
		}
		IFA_UNLOCK(&tmp_ifa->ia_ifa);
	}
	tmp_ifp = (tmp_ifa == NULL) ? NULL : tmp_ifa->ia_ifp;

	IFA_LOCK(&ia->ia_ifa);
	if (tmp_ifp == NULL) {
		TAILQ_INSERT_HEAD(INADDR_HASH(ia->ia_addr.sin_addr.s_addr),
		    ia, ia_hash);
	} else {
		TAILQ_INSERT_TAIL(INADDR_HASH(ia->ia_addr.sin_addr.s_addr),
		    ia, ia_hash);
	}
	IFA_ADDREF_LOCKED(&ia->ia_ifa);
}

/*
 * Initialize an interface's internet address
 * and routing table entry.
 */
static int
in_ifinit(struct ifnet *ifp, struct in_ifaddr *ia, struct sockaddr_in *sin,
    int scrub)
{
	u_int32_t i = ntohl(sin->sin_addr.s_addr);
	struct sockaddr_in oldaddr;
	int flags = RTF_UP, error;
	struct ifaddr *ifa0;
	unsigned int cmd;
	int oldremoved = 0;

	/* Take an extra reference for this routine */
	IFA_ADDREF(&ia->ia_ifa);

	lck_rw_lock_exclusive(in_ifaddr_rwlock);
	IFA_LOCK(&ia->ia_ifa);
	oldaddr = ia->ia_addr;
	if (IA_IS_HASHED(ia)) {
		oldremoved = 1;
		in_iahash_remove(ia);
	}
	ia->ia_addr = *sin;
	/*
	 * Interface addresses should not contain port or sin_zero information.
	 */
	SIN(&ia->ia_addr)->sin_family = AF_INET;
	SIN(&ia->ia_addr)->sin_len = sizeof(struct sockaddr_in);
	SIN(&ia->ia_addr)->sin_port = 0;
	bzero(&SIN(&ia->ia_addr)->sin_zero, sizeof(sin->sin_zero));
	if ((ifp->if_flags & IFF_POINTOPOINT)) {
		in_iahash_insert_ptp(ia);
	} else {
		in_iahash_insert(ia);
	}
	IFA_UNLOCK(&ia->ia_ifa);
	lck_rw_done(in_ifaddr_rwlock);

	/*
	 * Give the interface a chance to initialize if this is its first
	 * address, and to validate the address if necessary.  Send down
	 * SIOCSIFADDR for first address, and SIOCAIFADDR for alias(es).
	 * We find the first IPV4 address assigned to it and check if this
	 * is the same as the one passed into this routine.
	 */
	ifa0 = ifa_ifpgetprimary(ifp, AF_INET);
	cmd = (&ia->ia_ifa == ifa0) ? SIOCSIFADDR : SIOCAIFADDR;
	error = ifnet_ioctl(ifp, PF_INET, cmd, ia);
	if (error == EOPNOTSUPP) {
		error = 0;
	}
	/*
	 * If we've just sent down SIOCAIFADDR, send another ioctl down
	 * for SIOCSIFADDR for the first IPV4 address of the interface,
	 * because an address change on one of the addresses will result
	 * in the removal of the previous first IPV4 address.  KDP needs
	 * be reconfigured with the current primary IPV4 address.
	 */
	if (error == 0 && cmd == SIOCAIFADDR) {
		/*
		 * NOTE: SIOCSIFADDR is defined with struct ifreq
		 * as parameter, but here we are sending it down
		 * to the interface with a pointer to struct ifaddr,
		 * for legacy reasons.
		 */
		error = ifnet_ioctl(ifp, PF_INET, SIOCSIFADDR, ifa0);
		if (error == EOPNOTSUPP) {
			error = 0;
		}
	}

	/* Release reference from ifa_ifpgetprimary() */
	IFA_REMREF(ifa0);

	if (error) {
		lck_rw_lock_exclusive(in_ifaddr_rwlock);
		IFA_LOCK(&ia->ia_ifa);
		if (IA_IS_HASHED(ia)) {
			in_iahash_remove(ia);
		}
		ia->ia_addr = oldaddr;
		if (oldremoved) {
			if ((ifp->if_flags & IFF_POINTOPOINT)) {
				in_iahash_insert_ptp(ia);
			} else {
				in_iahash_insert(ia);
			}
		}
		IFA_UNLOCK(&ia->ia_ifa);
		lck_rw_done(in_ifaddr_rwlock);
		/* Release extra reference taken above */
		IFA_REMREF(&ia->ia_ifa);
		return error;
	}
	lck_mtx_lock(rnh_lock);
	IFA_LOCK(&ia->ia_ifa);
	/*
	 * Address has been initialized by the link resolver (ARP)
	 * via ifnet_ioctl() above; it may now generate route(s).
	 */
	ia->ia_ifa.ifa_debug &= ~IFD_NOTREADY;
	if (scrub) {
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&oldaddr;
		IFA_UNLOCK(&ia->ia_ifa);
		in_ifscrub(ifp, ia, 1);
		IFA_LOCK(&ia->ia_ifa);
		ia->ia_ifa.ifa_addr = (struct sockaddr *)&ia->ia_addr;
	}
	IFA_LOCK_ASSERT_HELD(&ia->ia_ifa);
	if (IN_CLASSA(i)) {
		ia->ia_netmask = IN_CLASSA_NET;
	} else if (IN_CLASSB(i)) {
		ia->ia_netmask = IN_CLASSB_NET;
	} else {
		ia->ia_netmask = IN_CLASSC_NET;
	}
	/*
	 * The subnet mask usually includes at least the standard network part,
	 * but may may be smaller in the case of supernetting.
	 * If it is set, we believe it.
	 */
	if (ia->ia_subnetmask == 0) {
		ia->ia_subnetmask = ia->ia_netmask;
		ia->ia_sockmask.sin_addr.s_addr = htonl(ia->ia_subnetmask);
	} else {
		ia->ia_netmask &= ia->ia_subnetmask;
	}
	ia->ia_net = i & ia->ia_netmask;
	ia->ia_subnet = i & ia->ia_subnetmask;
	in_socktrim(&ia->ia_sockmask);
	/*
	 * Add route for the network.
	 */
	ia->ia_ifa.ifa_metric = ifp->if_metric;
	if (ifp->if_flags & IFF_BROADCAST) {
		ia->ia_broadaddr.sin_addr.s_addr =
		    htonl(ia->ia_subnet | ~ia->ia_subnetmask);
		ia->ia_netbroadcast.s_addr =
		    htonl(ia->ia_net | ~ia->ia_netmask);
	} else if (ifp->if_flags & IFF_LOOPBACK) {
		ia->ia_ifa.ifa_dstaddr = ia->ia_ifa.ifa_addr;
		flags |= RTF_HOST;
	} else if (ifp->if_flags & IFF_POINTOPOINT) {
		if (ia->ia_dstaddr.sin_family != AF_INET) {
			IFA_UNLOCK(&ia->ia_ifa);
			lck_mtx_unlock(rnh_lock);
			/* Release extra reference taken above */
			IFA_REMREF(&ia->ia_ifa);
			return 0;
		}
		ia->ia_dstaddr.sin_len = sizeof(struct sockaddr_in);
		flags |= RTF_HOST;
	}
	IFA_UNLOCK(&ia->ia_ifa);

	if ((error = rtinit_locked(&(ia->ia_ifa), (int)RTM_ADD, flags)) == 0) {
		IFA_LOCK(&ia->ia_ifa);
		ia->ia_flags |= IFA_ROUTE;
		IFA_UNLOCK(&ia->ia_ifa);
	}
	lck_mtx_unlock(rnh_lock);

	/* XXX check if the subnet route points to the same interface */
	if (error == EEXIST) {
		error = 0;
	}

	/*
	 * If the interface supports multicast, join the "all hosts"
	 * multicast group on that interface.
	 */
	if (ifp->if_flags & IFF_MULTICAST) {
		struct in_addr addr;

		lck_mtx_lock(&ifp->if_addrconfig_lock);
		addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
		if (ifp->if_allhostsinm == NULL) {
			struct in_multi *inm;
			inm = in_addmulti(&addr, ifp);

			if (inm != NULL) {
				/*
				 * Keep the reference on inm added by
				 * in_addmulti above for storing the
				 * pointer in allhostsinm.
				 */
				ifp->if_allhostsinm = inm;
			} else {
				printf("%s: failed to add membership to "
				    "all-hosts multicast address on %s\n",
				    __func__, if_name(ifp));
			}
		}
		lck_mtx_unlock(&ifp->if_addrconfig_lock);
	}

	/* Release extra reference taken above */
	IFA_REMREF(&ia->ia_ifa);

	if (error == 0) {
		/* invalidate route caches */
		routegenid_inet_update();
	}

	return error;
}

/*
 * Return TRUE if the address might be a local broadcast address.
 */
boolean_t
in_broadcast(struct in_addr in, struct ifnet *ifp)
{
	struct ifaddr *ifa;
	u_int32_t t;

	if (in.s_addr == INADDR_BROADCAST || in.s_addr == INADDR_ANY) {
		return TRUE;
	}
	if (!(ifp->if_flags & IFF_BROADCAST)) {
		return FALSE;
	}
	t = ntohl(in.s_addr);

	/*
	 * Look through the list of addresses for a match
	 * with a broadcast address.
	 */
#define ia ((struct in_ifaddr *)ifa)
	ifnet_lock_shared(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		IFA_LOCK(ifa);
		if (ifa->ifa_addr->sa_family == AF_INET &&
		    (in.s_addr == ia->ia_broadaddr.sin_addr.s_addr ||
		    in.s_addr == ia->ia_netbroadcast.s_addr ||
		    /*
		     * Check for old-style (host 0) broadcast.
		     */
		    t == ia->ia_subnet || t == ia->ia_net) &&
		    /*
		     * Check for an all one subnetmask. These
		     * only exist when an interface gets a secondary
		     * address.
		     */
		    ia->ia_subnetmask != (u_int32_t)0xffffffff) {
			IFA_UNLOCK(ifa);
			ifnet_lock_done(ifp);
			return TRUE;
		}
		IFA_UNLOCK(ifa);
	}
	ifnet_lock_done(ifp);
	return FALSE;
#undef ia
}

void
in_purgeaddrs(struct ifnet *ifp)
{
	struct ifaddr **ifap;
	int err, i;

	VERIFY(ifp != NULL);

	/*
	 * Be nice, and try the civilized way first.  If we can't get
	 * rid of them this way, then do it the rough way.  We must
	 * only get here during detach time, after the ifnet has been
	 * removed from the global list and arrays.
	 */
	err = ifnet_get_address_list_family_internal(ifp, &ifap, AF_INET, 1,
	    M_WAITOK, 0);
	if (err == 0 && ifap != NULL) {
		struct ifreq ifr;

		bzero(&ifr, sizeof(ifr));
		(void) snprintf(ifr.ifr_name, sizeof(ifr.ifr_name),
		    "%s", if_name(ifp));

		for (i = 0; ifap[i] != NULL; i++) {
			struct ifaddr *ifa;

			ifa = ifap[i];
			IFA_LOCK(ifa);
			bcopy(ifa->ifa_addr, &ifr.ifr_addr,
			    sizeof(struct sockaddr_in));
			IFA_UNLOCK(ifa);
			err = in_control(NULL, SIOCDIFADDR, (caddr_t)&ifr, ifp,
			    kernproc);
			/* if we lost the race, ignore it */
			if (err == EADDRNOTAVAIL) {
				err = 0;
			}
			if (err != 0) {
				char s_addr[MAX_IPv4_STR_LEN];
				char s_dstaddr[MAX_IPv4_STR_LEN];
				struct in_addr *s, *d;

				IFA_LOCK(ifa);
				s = &((struct sockaddr_in *)
				    (void *)ifa->ifa_addr)->sin_addr;
				d = &((struct sockaddr_in *)
				    (void *)ifa->ifa_dstaddr)->sin_addr;
				(void) inet_ntop(AF_INET, &s->s_addr, s_addr,
				    sizeof(s_addr));
				(void) inet_ntop(AF_INET, &d->s_addr, s_dstaddr,
				    sizeof(s_dstaddr));
				IFA_UNLOCK(ifa);

				printf("%s: SIOCDIFADDR ifp=%s ifa_addr=%s "
				    "ifa_dstaddr=%s (err=%d)\n", __func__,
				    ifp->if_xname, s_addr, s_dstaddr, err);
			}
		}
		ifnet_free_address_list(ifap);
	} else if (err != 0 && err != ENXIO) {
		printf("%s: error retrieving list of AF_INET addresses for "
		    "ifp=%s (err=%d)\n", __func__, ifp->if_xname, err);
	}
}

/*
 * Called as part of ip_init
 */
void
in_ifaddr_init(void)
{
	in_multi_init();

	PE_parse_boot_argn("ifa_debug", &inifa_debug, sizeof(inifa_debug));

	inifa_size = (inifa_debug == 0) ? sizeof(struct in_ifaddr) :
	    sizeof(struct in_ifaddr_dbg);

	inifa_zone = zinit(inifa_size, INIFA_ZONE_MAX * inifa_size,
	    0, INIFA_ZONE_NAME);
	if (inifa_zone == NULL) {
		panic("%s: failed allocating %s", __func__, INIFA_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(inifa_zone, Z_EXPAND, TRUE);
	zone_change(inifa_zone, Z_CALLERACCT, FALSE);

	lck_mtx_init(&inifa_trash_lock, ifa_mtx_grp, ifa_mtx_attr);
	TAILQ_INIT(&inifa_trash_head);
}

static struct in_ifaddr *
in_ifaddr_alloc(int how)
{
	struct in_ifaddr *inifa;

	inifa = (how == M_WAITOK) ? zalloc(inifa_zone) :
	    zalloc_noblock(inifa_zone);
	if (inifa != NULL) {
		bzero(inifa, inifa_size);
		inifa->ia_ifa.ifa_free = in_ifaddr_free;
		inifa->ia_ifa.ifa_debug |= IFD_ALLOC;
		inifa->ia_ifa.ifa_del_wc = &inifa->ia_ifa.ifa_debug;
		inifa->ia_ifa.ifa_del_waiters = 0;
		ifa_lock_init(&inifa->ia_ifa);
		if (inifa_debug != 0) {
			struct in_ifaddr_dbg *inifa_dbg =
			    (struct in_ifaddr_dbg *)inifa;
			inifa->ia_ifa.ifa_debug |= IFD_DEBUG;
			inifa->ia_ifa.ifa_trace = in_ifaddr_trace;
			inifa->ia_ifa.ifa_attached = in_ifaddr_attached;
			inifa->ia_ifa.ifa_detached = in_ifaddr_detached;
			ctrace_record(&inifa_dbg->inifa_alloc);
		}
	}
	return inifa;
}

static void
in_ifaddr_free(struct ifaddr *ifa)
{
	IFA_LOCK_ASSERT_HELD(ifa);

	if (ifa->ifa_refcnt != 0) {
		panic("%s: ifa %p bad ref cnt", __func__, ifa);
		/* NOTREACHED */
	}
	if (!(ifa->ifa_debug & IFD_ALLOC)) {
		panic("%s: ifa %p cannot be freed", __func__, ifa);
		/* NOTREACHED */
	}
	if (ifa->ifa_debug & IFD_DEBUG) {
		struct in_ifaddr_dbg *inifa_dbg = (struct in_ifaddr_dbg *)ifa;
		ctrace_record(&inifa_dbg->inifa_free);
		bcopy(&inifa_dbg->inifa, &inifa_dbg->inifa_old,
		    sizeof(struct in_ifaddr));
		if (ifa->ifa_debug & IFD_TRASHED) {
			/* Become a regular mutex, just in case */
			IFA_CONVERT_LOCK(ifa);
			lck_mtx_lock(&inifa_trash_lock);
			TAILQ_REMOVE(&inifa_trash_head, inifa_dbg,
			    inifa_trash_link);
			lck_mtx_unlock(&inifa_trash_lock);
			ifa->ifa_debug &= ~IFD_TRASHED;
		}
	}
	IFA_UNLOCK(ifa);
	ifa_lock_destroy(ifa);
	bzero(ifa, sizeof(struct in_ifaddr));
	zfree(inifa_zone, ifa);
}

static void
in_ifaddr_attached(struct ifaddr *ifa)
{
	struct in_ifaddr_dbg *inifa_dbg = (struct in_ifaddr_dbg *)ifa;

	IFA_LOCK_ASSERT_HELD(ifa);

	if (!(ifa->ifa_debug & IFD_DEBUG)) {
		panic("%s: ifa %p has no debug structure", __func__, ifa);
		/* NOTREACHED */
	}
	if (ifa->ifa_debug & IFD_TRASHED) {
		/* Become a regular mutex, just in case */
		IFA_CONVERT_LOCK(ifa);
		lck_mtx_lock(&inifa_trash_lock);
		TAILQ_REMOVE(&inifa_trash_head, inifa_dbg, inifa_trash_link);
		lck_mtx_unlock(&inifa_trash_lock);
		ifa->ifa_debug &= ~IFD_TRASHED;
	}
}

static void
in_ifaddr_detached(struct ifaddr *ifa)
{
	struct in_ifaddr_dbg *inifa_dbg = (struct in_ifaddr_dbg *)ifa;

	IFA_LOCK_ASSERT_HELD(ifa);

	if (!(ifa->ifa_debug & IFD_DEBUG)) {
		panic("%s: ifa %p has no debug structure", __func__, ifa);
		/* NOTREACHED */
	} else if (ifa->ifa_debug & IFD_TRASHED) {
		panic("%s: ifa %p is already in trash list", __func__, ifa);
		/* NOTREACHED */
	}
	ifa->ifa_debug |= IFD_TRASHED;
	/* Become a regular mutex, just in case */
	IFA_CONVERT_LOCK(ifa);
	lck_mtx_lock(&inifa_trash_lock);
	TAILQ_INSERT_TAIL(&inifa_trash_head, inifa_dbg, inifa_trash_link);
	lck_mtx_unlock(&inifa_trash_lock);
}

static void
in_ifaddr_trace(struct ifaddr *ifa, int refhold)
{
	struct in_ifaddr_dbg *inifa_dbg = (struct in_ifaddr_dbg *)ifa;
	ctrace_t *tr;
	u_int32_t idx;
	u_int16_t *cnt;

	if (!(ifa->ifa_debug & IFD_DEBUG)) {
		panic("%s: ifa %p has no debug structure", __func__, ifa);
		/* NOTREACHED */
	}
	if (refhold) {
		cnt = &inifa_dbg->inifa_refhold_cnt;
		tr = inifa_dbg->inifa_refhold;
	} else {
		cnt = &inifa_dbg->inifa_refrele_cnt;
		tr = inifa_dbg->inifa_refrele;
	}

	idx = atomic_add_16_ov(cnt, 1) % INIFA_TRACE_HIST_SIZE;
	ctrace_record(&tr[idx]);
}

/*
 * Handle SIOCGASSOCIDS ioctl for PF_INET domain.
 */
static int
in_getassocids(struct socket *so, uint32_t *cnt, user_addr_t aidp)
{
	struct inpcb *inp = sotoinpcb(so);
	sae_associd_t aid;

	if (inp == NULL || inp->inp_state == INPCB_STATE_DEAD) {
		return EINVAL;
	}

	/* INPCB has no concept of association */
	aid = SAE_ASSOCID_ANY;
	*cnt = 0;

	/* just asking how many there are? */
	if (aidp == USER_ADDR_NULL) {
		return 0;
	}

	return copyout(&aid, aidp, sizeof(aid));
}

/*
 * Handle SIOCGCONNIDS ioctl for PF_INET domain.
 */
static int
in_getconnids(struct socket *so, sae_associd_t aid, uint32_t *cnt,
    user_addr_t cidp)
{
	struct inpcb *inp = sotoinpcb(so);
	sae_connid_t cid;

	if (inp == NULL || inp->inp_state == INPCB_STATE_DEAD) {
		return EINVAL;
	}

	if (aid != SAE_ASSOCID_ANY && aid != SAE_ASSOCID_ALL) {
		return EINVAL;
	}

	/* if connected, return 1 connection count */
	*cnt = ((so->so_state & SS_ISCONNECTED) ? 1 : 0);

	/* just asking how many there are? */
	if (cidp == USER_ADDR_NULL) {
		return 0;
	}

	/* if INPCB is connected, assign it connid 1 */
	cid = ((*cnt != 0) ? 1 : SAE_CONNID_ANY);

	return copyout(&cid, cidp, sizeof(cid));
}

/*
 * Handle SIOCGCONNINFO ioctl for PF_INET domain.
 */
int
in_getconninfo(struct socket *so, sae_connid_t cid, uint32_t *flags,
    uint32_t *ifindex, int32_t *soerror, user_addr_t src, socklen_t *src_len,
    user_addr_t dst, socklen_t *dst_len, uint32_t *aux_type,
    user_addr_t aux_data, uint32_t *aux_len)
{
	struct inpcb *inp = sotoinpcb(so);
	struct sockaddr_in sin;
	struct ifnet *ifp = NULL;
	int error = 0;
	u_int32_t copy_len = 0;

	/*
	 * Don't test for INPCB_STATE_DEAD since this may be called
	 * after SOF_PCBCLEARING is set, e.g. after tcp_close().
	 */
	if (inp == NULL) {
		error = EINVAL;
		goto out;
	}

	if (cid != SAE_CONNID_ANY && cid != SAE_CONNID_ALL && cid != 1) {
		error = EINVAL;
		goto out;
	}

	ifp = inp->inp_last_outifp;
	*ifindex = ((ifp != NULL) ? ifp->if_index : 0);
	*soerror = so->so_error;
	*flags = 0;
	if (so->so_state & SS_ISCONNECTED) {
		*flags |= (CIF_CONNECTED | CIF_PREFERRED);
	}
	if (inp->inp_flags & INP_BOUND_IF) {
		*flags |= CIF_BOUND_IF;
	}
	if (!(inp->inp_flags & INP_INADDR_ANY)) {
		*flags |= CIF_BOUND_IP;
	}
	if (!(inp->inp_flags & INP_ANONPORT)) {
		*flags |= CIF_BOUND_PORT;
	}

	bzero(&sin, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;

	/* source address and port */
	sin.sin_port = inp->inp_lport;
	sin.sin_addr.s_addr = inp->inp_laddr.s_addr;
	if (*src_len == 0) {
		*src_len = sin.sin_len;
	} else {
		if (src != USER_ADDR_NULL) {
			copy_len = min(*src_len, sizeof(sin));
			error = copyout(&sin, src, copy_len);
			if (error != 0) {
				goto out;
			}
			*src_len = copy_len;
		}
	}

	/* destination address and port */
	sin.sin_port = inp->inp_fport;
	sin.sin_addr.s_addr = inp->inp_faddr.s_addr;
	if (*dst_len == 0) {
		*dst_len = sin.sin_len;
	} else {
		if (dst != USER_ADDR_NULL) {
			copy_len = min(*dst_len, sizeof(sin));
			error = copyout(&sin, dst, copy_len);
			if (error != 0) {
				goto out;
			}
			*dst_len = copy_len;
		}
	}

	if (SOCK_PROTO(so) == IPPROTO_TCP) {
		struct conninfo_tcp tcp_ci;

		*aux_type = CIAUX_TCP;
		if (*aux_len == 0) {
			*aux_len = sizeof(tcp_ci);
		} else {
			if (aux_data != USER_ADDR_NULL) {
				copy_len = min(*aux_len, sizeof(tcp_ci));
				bzero(&tcp_ci, sizeof(tcp_ci));
				tcp_getconninfo(so, &tcp_ci);
				error = copyout(&tcp_ci, aux_data, copy_len);
				if (error != 0) {
					goto out;
				}
				*aux_len = copy_len;
			}
		}
	} else {
		*aux_type = 0;
		*aux_len = 0;
	}

out:
	return error;
}

struct in_llentry {
	struct llentry          base;
};

#define        IN_LLTBL_DEFAULT_HSIZE  32
#define        IN_LLTBL_HASH(k, h) \
    ((((((((k) >> 8) ^ (k)) >> 8) ^ (k)) >> 8) ^ (k)) & ((h) - 1))

/*
 * Do actual deallocation of @lle.
 */
static void
in_lltable_destroy_lle_unlocked(struct llentry *lle)
{
	LLE_LOCK_DESTROY(lle);
	LLE_REQ_DESTROY(lle);
	FREE(lle, M_LLTABLE);
}

/*
 * Called by LLE_FREE_LOCKED when number of references
 * drops to zero.
 */
static void
in_lltable_destroy_lle(struct llentry *lle)
{
	LLE_WUNLOCK(lle);
	in_lltable_destroy_lle_unlocked(lle);
}

static struct llentry *
in_lltable_new(struct in_addr addr4, u_int flags)
{
#pragma unused(flags)
	struct in_llentry *lle;

	MALLOC(lle, struct in_llentry *, sizeof(struct in_llentry), M_LLTABLE, M_NOWAIT | M_ZERO);
	if (lle == NULL) {              /* NB: caller generates msg */
		return NULL;
	}

	/*
	 * For IPv4 this will trigger "arpresolve" to generate
	 * an ARP request.
	 */
	lle->base.la_expire = net_uptime(); /* mark expired */
	lle->base.r_l3addr.addr4 = addr4;
	lle->base.lle_refcnt = 1;
	lle->base.lle_free = in_lltable_destroy_lle;

	LLE_LOCK_INIT(&lle->base);
	LLE_REQ_INIT(&lle->base);
	//callout_init(&lle->base.lle_timer, 1);

	return &lle->base;
}

#define IN_ARE_MASKED_ADDR_EQUAL(d, a, m)      (               \
    ((((d).s_addr ^ (a).s_addr) & (m).s_addr)) == 0 )

static int
in_lltable_match_prefix(const struct sockaddr *saddr,
    const struct sockaddr *smask, u_int flags, struct llentry *lle)
{
	struct in_addr addr, mask, lle_addr;

	addr = ((const struct sockaddr_in *)(const void *)saddr)->sin_addr;
	mask = ((const struct sockaddr_in *)(const void *)smask)->sin_addr;
	lle_addr.s_addr = ntohl(lle->r_l3addr.addr4.s_addr);

	if (IN_ARE_MASKED_ADDR_EQUAL(lle_addr, addr, mask) == 0) {
		return 0;
	}

	if (lle->la_flags & LLE_IFADDR) {
		/*
		 * Delete LLE_IFADDR records IFF address & flag matches.
		 * Note that addr is the interface address within prefix
		 * being matched.
		 * Note also we should handle 'ifdown' cases without removing
		 * ifaddr macs.
		 */
		if (addr.s_addr == lle_addr.s_addr && (flags & LLE_STATIC) != 0) {
			return 1;
		}
		return 0;
	}

	/* flags & LLE_STATIC means deleting both dynamic and static entries */
	if ((flags & LLE_STATIC) || !(lle->la_flags & LLE_STATIC)) {
		return 1;
	}

	return 0;
}

static void
in_lltable_free_entry(struct lltable *llt, struct llentry *lle)
{
	struct ifnet *ifp;
	size_t pkts_dropped;

	LLE_WLOCK_ASSERT(lle);
	KASSERT(llt != NULL, ("lltable is NULL"));

	/* Unlink entry from table if not already */
	if ((lle->la_flags & LLE_LINKED) != 0) {
		ifp = llt->llt_ifp;
		IF_AFDATA_WLOCK_ASSERT(ifp, llt->llt_af);
		lltable_unlink_entry(llt, lle);
	}

#if 0
	/* cancel timer */
	if (callout_stop(&lle->lle_timer) > 0) {
		LLE_REMREF(lle);
	}
#endif
	/* Drop hold queue */
	pkts_dropped = llentry_free(lle);
	arpstat.dropped += pkts_dropped;
}


static int
in_lltable_rtcheck(struct ifnet *ifp, u_int flags, const struct sockaddr *l3addr)
{
#pragma unused(flags)
	struct rtentry *rt;

	KASSERT(l3addr->sa_family == AF_INET,
	    ("sin_family %d", l3addr->sa_family));

	/* XXX rtalloc1 should take a const param */
	rt = rtalloc1(__DECONST(struct sockaddr *, l3addr), 0, 0);
	if (rt == NULL || (rt->rt_flags & RTF_GATEWAY) || rt->rt_ifp != ifp) {
		log(LOG_INFO, "IPv4 address: \"%s\" is not on the network\n",
		    inet_ntoa(((const struct sockaddr_in *)(const void *)l3addr)->sin_addr));
		if (rt != NULL) {
			rtfree_locked(rt);
		}
		return EINVAL;
	}
	rtfree_locked(rt);
	return 0;
}

static inline uint32_t
in_lltable_hash_dst(const struct in_addr dst, uint32_t hsize)
{
	return IN_LLTBL_HASH(dst.s_addr, hsize);
}

static uint32_t
in_lltable_hash(const struct llentry *lle, uint32_t hsize)
{
	return in_lltable_hash_dst(lle->r_l3addr.addr4, hsize);
}


static void
in_lltable_fill_sa_entry(const struct llentry *lle, struct sockaddr *sa)
{
	struct sockaddr_in *sin;

	sin = (struct sockaddr_in *)(void *)sa;
	bzero(sin, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);
	sin->sin_addr = lle->r_l3addr.addr4;
}

static inline struct llentry *
in_lltable_find_dst(struct lltable *llt, struct in_addr dst)
{
	struct llentry *lle;
	struct llentries *lleh;
	u_int hashidx;

	hashidx = in_lltable_hash_dst(dst, llt->llt_hsize);
	lleh = &llt->lle_head[hashidx];
	LIST_FOREACH(lle, lleh, lle_next) {
		if (lle->la_flags & LLE_DELETED) {
			continue;
		}
		if (lle->r_l3addr.addr4.s_addr == dst.s_addr) {
			break;
		}
	}

	return lle;
}

static void
in_lltable_delete_entry(struct lltable *llt, struct llentry *lle)
{
#pragma unused(llt)
	lle->la_flags |= LLE_DELETED;
	//EVENTHANDLER_INVOKE(lle_event, lle, LLENTRY_DELETED);
#ifdef DIAGNOSTIC
	log(LOG_INFO, "ifaddr cache = %p is deleted\n", lle);
#endif
	llentry_free(lle);
}

static struct llentry *
in_lltable_alloc(struct lltable *llt, u_int flags, const struct sockaddr *l3addr)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *) (const void *)l3addr;
	struct ifnet *ifp = llt->llt_ifp;
	struct llentry *lle;

	KASSERT(l3addr->sa_family == AF_INET,
	    ("sin_family %d", l3addr->sa_family));

	/*
	 * A route that covers the given address must have
	 * been installed 1st because we are doing a resolution,
	 * verify this.
	 */
	if (!(flags & LLE_IFADDR) &&
	    in_lltable_rtcheck(ifp, flags, l3addr) != 0) {
		return NULL;
	}

	lle = in_lltable_new(sin->sin_addr, flags);
	if (lle == NULL) {
		log(LOG_INFO, "lla_lookup: new lle malloc failed\n");
		return NULL;
	}
	lle->la_flags = flags & ~LLE_CREATE;
	if (flags & LLE_STATIC) {
		lle->r_flags |= RLLE_VALID;
	}
	if ((flags & LLE_IFADDR) == LLE_IFADDR) {
		lltable_set_entry_addr(ifp, lle, LLADDR(SDL(ifp->if_lladdr->ifa_addr)));
		lle->la_flags |= LLE_STATIC;
		lle->r_flags |= (RLLE_VALID | RLLE_IFADDR);
	}
	return lle;
}

/*
 * Return NULL if not found or marked for deletion.
 * If found return lle read locked.
 */
static struct llentry *
in_lltable_lookup(struct lltable *llt, u_int flags, const struct sockaddr *l3addr)
{
	const struct sockaddr_in *sin = (const struct sockaddr_in *)(const void *)l3addr;
	struct llentry *lle;

	IF_AFDATA_WLOCK_ASSERT(llt->llt_ifp, llt->llt_af);

	KASSERT(l3addr->sa_family == AF_INET,
	    ("sin_family %d", l3addr->sa_family));
	lle = in_lltable_find_dst(llt, sin->sin_addr);

	if (lle == NULL) {
		return NULL;
	}

	KASSERT((flags & (LLE_UNLOCKED | LLE_EXCLUSIVE)) !=
	    (LLE_UNLOCKED | LLE_EXCLUSIVE), ("wrong lle request flags: 0x%X",
	    flags));

	if (flags & LLE_UNLOCKED) {
		return lle;
	}

	if (flags & LLE_EXCLUSIVE) {
		LLE_WLOCK(lle);
	} else {
		LLE_RLOCK(lle);
	}

	return lle;
}

static int
in_lltable_dump_entry(struct lltable *llt, struct llentry *lle,
    struct sysctl_req *wr)
{
	struct ifnet *ifp = llt->llt_ifp;
	/* XXX stack use */
	struct {
		struct rt_msghdr        rtm;
		struct sockaddr_in      sin;
		struct sockaddr_dl      sdl;
	} arpc;
	struct sockaddr_dl *sdl;
	int error;

	bzero(&arpc, sizeof(arpc));
	/* skip deleted entries */
	if ((lle->la_flags & LLE_DELETED) == LLE_DELETED) {
		return 0;
	}
	/* Skip if jailed and not a valid IP of the prison. */
	lltable_fill_sa_entry(lle, (struct sockaddr *)&arpc.sin);
	/*
	 * produce a msg made of:
	 *  struct rt_msghdr;
	 *  struct sockaddr_in; (IPv4)
	 *  struct sockaddr_dl;
	 */
	arpc.rtm.rtm_msglen = sizeof(arpc);
	arpc.rtm.rtm_version = RTM_VERSION;
	arpc.rtm.rtm_type = RTM_GET;
	arpc.rtm.rtm_flags = RTF_UP;
	arpc.rtm.rtm_addrs = RTA_DST | RTA_GATEWAY;

	/* publish */
	if (lle->la_flags & LLE_PUB) {
		arpc.rtm.rtm_flags |= RTF_ANNOUNCE;
	}

	sdl = &arpc.sdl;
	sdl->sdl_family = AF_LINK;
	sdl->sdl_len = sizeof(*sdl);
	sdl->sdl_index = ifp->if_index;
	sdl->sdl_type = ifp->if_type;
	if ((lle->la_flags & LLE_VALID) == LLE_VALID) {
		sdl->sdl_alen = ifp->if_addrlen;
		bcopy(&lle->ll_addr, LLADDR(sdl), ifp->if_addrlen);
	} else {
		sdl->sdl_alen = 0;
		bzero(LLADDR(sdl), ifp->if_addrlen);
	}

	arpc.rtm.rtm_rmx.rmx_expire =
	    lle->la_flags & LLE_STATIC ? 0 : lle->la_expire;
	arpc.rtm.rtm_flags |= (RTF_HOST | RTF_LLDATA);
	if (lle->la_flags & LLE_STATIC) {
		arpc.rtm.rtm_flags |= RTF_STATIC;
	}
	if (lle->la_flags & LLE_IFADDR) {
		arpc.rtm.rtm_flags |= RTF_PINNED;
	}
	arpc.rtm.rtm_flags |= RTF_PINNED;
	arpc.rtm.rtm_index = ifp->if_index;
	error = SYSCTL_OUT(wr, &arpc, sizeof(arpc));

	return error;
}

static struct lltable *
in_lltattach(struct ifnet *ifp)
{
	struct lltable *llt;

	llt = lltable_allocate_htbl(IN_LLTBL_DEFAULT_HSIZE);
	llt->llt_af = AF_INET;
	llt->llt_ifp = ifp;

	llt->llt_lookup = in_lltable_lookup;
	llt->llt_alloc_entry = in_lltable_alloc;
	llt->llt_delete_entry = in_lltable_delete_entry;
	llt->llt_dump_entry = in_lltable_dump_entry;
	llt->llt_hash = in_lltable_hash;
	llt->llt_fill_sa_entry = in_lltable_fill_sa_entry;
	llt->llt_free_entry = in_lltable_free_entry;
	llt->llt_match_prefix = in_lltable_match_prefix;
	lltable_link(llt);

	return llt;
}

struct in_ifaddr*
inifa_ifpwithflag(struct ifnet * ifp, uint32_t flag)
{
	struct ifaddr *ifa;

	ifnet_lock_shared(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_link)
	{
		IFA_LOCK_SPIN(ifa);
		if (ifa->ifa_addr->sa_family != AF_INET) {
			IFA_UNLOCK(ifa);
			continue;
		}
		if ((((struct in_ifaddr *)ifa)->ia_flags & flag) == flag) {
			IFA_ADDREF_LOCKED(ifa);
			IFA_UNLOCK(ifa);
			break;
		}
		IFA_UNLOCK(ifa);
	}
	ifnet_lock_done(ifp);

	return (struct in_ifaddr *)ifa;
}

struct in_ifaddr *
inifa_ifpclatv4(struct ifnet * ifp)
{
	struct ifaddr *ifa;

	ifnet_lock_shared(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_link)
	{
		uint32_t addr = 0;
		IFA_LOCK_SPIN(ifa);
		if (ifa->ifa_addr->sa_family != AF_INET) {
			IFA_UNLOCK(ifa);
			continue;
		}

		addr = ntohl(SIN(ifa->ifa_addr)->sin_addr.s_addr);
		if (!IN_LINKLOCAL(addr) &&
		    !IN_LOOPBACK(addr)) {
			IFA_ADDREF_LOCKED(ifa);
			IFA_UNLOCK(ifa);
			break;
		}
		IFA_UNLOCK(ifa);
	}
	ifnet_lock_done(ifp);

	return (struct in_ifaddr *)ifa;
}
