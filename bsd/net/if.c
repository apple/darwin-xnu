/*
 * Copyright (c) 2000-2017 Apple Inc. All rights reserved.
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
 * Copyright (c) 1980, 1986, 1993
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
 *	@(#)if.c	8.3 (Berkeley) 1/4/94
 * $FreeBSD: src/sys/net/if.c,v 1.85.2.9 2001/07/24 19:10:17 brooks Exp $
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2006 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <kern/locks.h>

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/kernel.h>
#include <sys/sockio.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/mcache.h>
#include <sys/kauth.h>
#include <sys/priv.h>
#include <kern/zalloc.h>
#include <mach/boolean.h>

#include <machine/endian.h>

#include <pexpert/pexpert.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/if_ppp.h>
#include <net/ethernet.h>
#include <net/network_agent.h>
#include <net/radix.h>
#include <net/route.h>
#include <net/dlil.h>
#include <net/nwk_wq.h>

#include <sys/domain.h>
#include <libkern/OSAtomic.h>

#if INET || INET6
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_tclass.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#if INET6
#include <netinet6/in6_var.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#endif /* INET6 */
#endif /* INET || INET6 */

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif

/*
 * System initialization
 */

extern char *proc_name_address(void *);

/* Lock group and attribute for ifaddr lock */
lck_attr_t	*ifa_mtx_attr;
lck_grp_t	*ifa_mtx_grp;
static lck_grp_attr_t	*ifa_mtx_grp_attr;

static int ifioctl_ifreq(struct socket *, u_long, struct ifreq *,
    struct proc *);
static int ifioctl_ifconf(u_long, caddr_t);
static int ifioctl_ifclone(u_long, caddr_t);
static int ifioctl_iforder(u_long, caddr_t);
static int ifioctl_ifdesc(struct ifnet *, u_long, caddr_t, struct proc *);
static int ifioctl_linkparams(struct ifnet *, u_long, caddr_t, struct proc *);
static int ifioctl_qstats(struct ifnet *, u_long, caddr_t);
static int ifioctl_throttle(struct ifnet *, u_long, caddr_t, struct proc *);
static int ifioctl_netsignature(struct ifnet *, u_long, caddr_t);
static int ifconf(u_long cmd, user_addr_t ifrp, int * ret_space);
__private_extern__ void link_rtrequest(int, struct rtentry *, struct sockaddr *);
void if_rtproto_del(struct ifnet *ifp, int protocol);

static int if_addmulti_common(struct ifnet *, const struct sockaddr *,
    struct ifmultiaddr **, int);
static int if_delmulti_common(struct ifmultiaddr *, struct ifnet *,
    const struct sockaddr *, int);
static struct ifnet *ifunit_common(const char *, boolean_t);

static int if_rtmtu(struct radix_node *, void *);
static void if_rtmtu_update(struct ifnet *);

static int if_clone_list(int, int *, user_addr_t);

MALLOC_DEFINE(M_IFADDR, "ifaddr", "interface address");

struct	ifnethead ifnet_head = TAILQ_HEAD_INITIALIZER(ifnet_head);

/* ifnet_ordered_head and if_ordered_count are protected by the ifnet_head lock */
struct	ifnethead ifnet_ordered_head = TAILQ_HEAD_INITIALIZER(ifnet_ordered_head);
static	u_int32_t if_ordered_count = 0;

static int	if_cloners_count;
LIST_HEAD(, if_clone) if_cloners = LIST_HEAD_INITIALIZER(if_cloners);

static struct ifaddr *ifa_ifwithnet_common(const struct sockaddr *,
    unsigned int);
static void if_attach_ifa_common(struct ifnet *, struct ifaddr *, int);
static void if_detach_ifa_common(struct ifnet *, struct ifaddr *, int);

static void if_attach_ifma(struct ifnet *, struct ifmultiaddr *, int);
static int if_detach_ifma(struct ifnet *, struct ifmultiaddr *, int);

static struct ifmultiaddr *ifma_alloc(int);
static void ifma_free(struct ifmultiaddr *);
static void ifma_trace(struct ifmultiaddr *, int);

#if DEBUG
static unsigned int ifma_debug = 1;	/* debugging (enabled) */
#else
static unsigned int ifma_debug;		/* debugging (disabled) */
#endif /* !DEBUG */
static unsigned int ifma_size;		/* size of zone element */
static struct zone *ifma_zone;		/* zone for ifmultiaddr */

#define	IFMA_TRACE_HIST_SIZE	32	/* size of trace history */

/* For gdb */
__private_extern__ unsigned int ifma_trace_hist_size = IFMA_TRACE_HIST_SIZE;

struct ifmultiaddr_dbg {
	struct ifmultiaddr	ifma;			/* ifmultiaddr */
	u_int16_t		ifma_refhold_cnt;	/* # of ref */
	u_int16_t		ifma_refrele_cnt;	/* # of rele */
	/*
	 * Circular lists of IFA_ADDREF and IFA_REMREF callers.
	 */
	ctrace_t		ifma_refhold[IFMA_TRACE_HIST_SIZE];
	ctrace_t		ifma_refrele[IFMA_TRACE_HIST_SIZE];
	/*
	 * Trash list linkage
	 */
	TAILQ_ENTRY(ifmultiaddr_dbg) ifma_trash_link;
};

/* List of trash ifmultiaddr entries protected by ifma_trash_lock */
static TAILQ_HEAD(, ifmultiaddr_dbg) ifma_trash_head;
static decl_lck_mtx_data(, ifma_trash_lock);

#define	IFMA_ZONE_MAX		64		/* maximum elements in zone */
#define	IFMA_ZONE_NAME		"ifmultiaddr"	/* zone name */

#if INET6
/*
 * XXX: declare here to avoid to include many inet6 related files..
 * should be more generalized?
 */
extern void	nd6_setmtu(struct ifnet *);
extern lck_mtx_t *nd6_mutex;
#endif

SYSCTL_NODE(_net, PF_LINK, link, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "Link layers");
SYSCTL_NODE(_net_link, 0, generic, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
	"Generic link-management");

SYSCTL_DECL(_net_link_generic_system);

static uint32_t if_verbose = 0;
SYSCTL_INT(_net_link_generic_system, OID_AUTO, if_verbose,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_verbose, 0, "");

boolean_t intcoproc_unrestricted;

/* Eventhandler context for interface events */
struct eventhandler_lists_ctxt ifnet_evhdlr_ctxt;

void
ifa_init(void)
{
	/* Setup lock group and attribute for ifaddr */
	ifa_mtx_grp_attr = lck_grp_attr_alloc_init();
	ifa_mtx_grp = lck_grp_alloc_init("ifaddr", ifa_mtx_grp_attr);
	ifa_mtx_attr = lck_attr_alloc_init();

	PE_parse_boot_argn("ifa_debug", &ifma_debug, sizeof (ifma_debug));

	ifma_size = (ifma_debug == 0) ? sizeof (struct ifmultiaddr) :
	    sizeof (struct ifmultiaddr_dbg);

	ifma_zone = zinit(ifma_size, IFMA_ZONE_MAX * ifma_size, 0,
	    IFMA_ZONE_NAME);
	if (ifma_zone == NULL) {
		panic("%s: failed allocating %s", __func__, IFMA_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(ifma_zone, Z_EXPAND, TRUE);
	zone_change(ifma_zone, Z_CALLERACCT, FALSE);

	lck_mtx_init(&ifma_trash_lock, ifa_mtx_grp, ifa_mtx_attr);
	TAILQ_INIT(&ifma_trash_head);

	PE_parse_boot_argn("intcoproc_unrestricted", &intcoproc_unrestricted,
           sizeof (intcoproc_unrestricted));
}

/*
 * Network interface utility routines.
 *
 * Routines with ifa_ifwith* names take sockaddr *'s as
 * parameters.
 */

int if_index;
struct ifaddr **ifnet_addrs;
struct ifnet **ifindex2ifnet;

__private_extern__ void
if_attach_ifa(struct ifnet *ifp, struct ifaddr *ifa)
{
	if_attach_ifa_common(ifp, ifa, 0);
}

__private_extern__ void
if_attach_link_ifa(struct ifnet *ifp, struct ifaddr *ifa)
{
	if_attach_ifa_common(ifp, ifa, 1);
}

static void
if_attach_ifa_common(struct ifnet *ifp, struct ifaddr *ifa, int link)
{
	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_EXCLUSIVE);
	IFA_LOCK_ASSERT_HELD(ifa);

	if (ifa->ifa_ifp != ifp) {
		panic("%s: Mismatch ifa_ifp=%p != ifp=%p", __func__,
		    ifa->ifa_ifp, ifp);
		/* NOTREACHED */
	} else if (ifa->ifa_debug & IFD_ATTACHED) {
		panic("%s: Attempt to attach an already attached ifa=%p",
		    __func__, ifa);
		/* NOTREACHED */
	} else if (link && !(ifa->ifa_debug & IFD_LINK)) {
		panic("%s: Unexpected non-link address ifa=%p", __func__, ifa);
		/* NOTREACHED */
	} else if (!link && (ifa->ifa_debug & IFD_LINK)) {
		panic("%s: Unexpected link address ifa=%p", __func__, ifa);
		/* NOTREACHED */
	}
	IFA_ADDREF_LOCKED(ifa);
	ifa->ifa_debug |= IFD_ATTACHED;
	if (link)
		TAILQ_INSERT_HEAD(&ifp->if_addrhead, ifa, ifa_link);
	else
		TAILQ_INSERT_TAIL(&ifp->if_addrhead, ifa, ifa_link);

	if (ifa->ifa_attached != NULL)
		(*ifa->ifa_attached)(ifa);
}

__private_extern__ void
if_detach_ifa(struct ifnet *ifp, struct ifaddr *ifa)
{
	if_detach_ifa_common(ifp, ifa, 0);
}

__private_extern__ void
if_detach_link_ifa(struct ifnet *ifp, struct ifaddr *ifa)
{
	if_detach_ifa_common(ifp, ifa, 1);
}

static void
if_detach_ifa_common(struct ifnet *ifp, struct ifaddr *ifa, int link)
{
	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_EXCLUSIVE);
	IFA_LOCK_ASSERT_HELD(ifa);

	if (link && !(ifa->ifa_debug & IFD_LINK)) {
		panic("%s: Unexpected non-link address ifa=%p", __func__, ifa);
		/* NOTREACHED */
	} else if (link && ifa != TAILQ_FIRST(&ifp->if_addrhead)) {
		panic("%s: Link address ifa=%p not first", __func__, ifa);
		/* NOTREACHED */
	} else if (!link && (ifa->ifa_debug & IFD_LINK)) {
		panic("%s: Unexpected link address ifa=%p", __func__, ifa);
		/* NOTREACHED */
	} else if (!(ifa->ifa_debug & IFD_ATTACHED)) {
		panic("%s: Attempt to detach an unattached address ifa=%p",
		    __func__, ifa);
		/* NOTREACHED */
	} else if (ifa->ifa_ifp != ifp) {
		panic("%s: Mismatch ifa_ifp=%p, ifp=%p", __func__,
		    ifa->ifa_ifp, ifp);
		/* NOTREACHED */
	} else if (ifa->ifa_debug & IFD_DEBUG) {
		struct ifaddr *ifa2;
		TAILQ_FOREACH(ifa2, &ifp->if_addrhead, ifa_link) {
			if (ifa2 == ifa)
				break;
		}
		if (ifa2 != ifa) {
			panic("%s: Attempt to detach a stray address ifa=%p",
			    __func__, ifa);
			/* NOTREACHED */
		}
	}
	TAILQ_REMOVE(&ifp->if_addrhead, ifa, ifa_link);
	/* This must not be the last reference to the ifaddr */
	if (IFA_REMREF_LOCKED(ifa) == NULL) {
		panic("%s: unexpected (missing) refcnt ifa=%p", __func__, ifa);
		/* NOTREACHED */
	}
	ifa->ifa_debug &= ~(IFD_ATTACHED | IFD_DETACHING);

	if (ifa->ifa_detached != NULL)
		(*ifa->ifa_detached)(ifa);

}

#define	INITIAL_IF_INDEXLIM	8

/*
 * Function: if_next_index
 * Purpose:
 *   Return the next available interface index.
 *   Grow the ifnet_addrs[] and ifindex2ifnet[] arrays to accomodate the
 *   added entry when necessary.
 *
 * Note:
 *   ifnet_addrs[] is indexed by (if_index - 1), whereas
 *   ifindex2ifnet[] is indexed by ifp->if_index.  That requires us to
 *   always allocate one extra element to hold ifindex2ifnet[0], which
 *   is unused.
 */
int if_next_index(void);

__private_extern__ int
if_next_index(void)
{
	static int 	if_indexlim = 0;
	int		new_index;

	new_index = ++if_index;
	if (if_index > if_indexlim) {
		unsigned 	n;
		int		new_if_indexlim;
		caddr_t		new_ifnet_addrs;
		caddr_t		new_ifindex2ifnet;
		caddr_t		old_ifnet_addrs;

		old_ifnet_addrs = (caddr_t)ifnet_addrs;
		if (ifnet_addrs == NULL) {
			new_if_indexlim = INITIAL_IF_INDEXLIM;
		} else {
			new_if_indexlim = if_indexlim << 1;
		}

		/* allocate space for the larger arrays */
		n = (2 * new_if_indexlim + 1) * sizeof(caddr_t);
		new_ifnet_addrs = _MALLOC(n, M_IFADDR, M_WAITOK | M_ZERO);
		if (new_ifnet_addrs == NULL) {
			--if_index;
			return (-1);
		}

		new_ifindex2ifnet = new_ifnet_addrs
			+ new_if_indexlim * sizeof(caddr_t);
		if (ifnet_addrs != NULL) {
			/* copy the existing data */
			bcopy((caddr_t)ifnet_addrs, new_ifnet_addrs,
			    if_indexlim * sizeof(caddr_t));
			bcopy((caddr_t)ifindex2ifnet,
			    new_ifindex2ifnet,
			    (if_indexlim + 1) * sizeof(caddr_t));
		}

		/* switch to the new tables and size */
		ifnet_addrs = (struct ifaddr **)(void *)new_ifnet_addrs;
		ifindex2ifnet = (struct ifnet **)(void *)new_ifindex2ifnet;
		if_indexlim = new_if_indexlim;

		/* release the old data */
		if (old_ifnet_addrs != NULL) {
			_FREE((caddr_t)old_ifnet_addrs, M_IFADDR);
		}
	}
	return (new_index);
}

/*
 * Create a clone network interface.
 */
static int
if_clone_create(char *name, int len, void *params)
{
	struct if_clone *ifc;
	char *dp;
	int wildcard;
	u_int32_t bytoff, bitoff;
	u_int32_t unit;
	int err;

	ifc = if_clone_lookup(name, &unit);
	if (ifc == NULL)
		return (EINVAL);

	if (ifunit(name) != NULL)
		return (EEXIST);

	bytoff = bitoff = 0;
	wildcard = (unit == UINT32_MAX);
	/*
	 * Find a free unit if none was given.
	 */
	if (wildcard) {
		while ((bytoff < ifc->ifc_bmlen) &&
		    (ifc->ifc_units[bytoff] == 0xff))
			bytoff++;
		if (bytoff >= ifc->ifc_bmlen)
			return (ENOSPC);
		while ((ifc->ifc_units[bytoff] & (1 << bitoff)) != 0)
			bitoff++;
		unit = (bytoff << 3) + bitoff;
	}

	if (unit > ifc->ifc_maxunit)
		return (ENXIO);

	err = (*ifc->ifc_create)(ifc, unit, params);
	if (err != 0)
		return (err);

	if (!wildcard) {
		bytoff = unit >> 3;
		bitoff = unit - (bytoff << 3);
	}

	/*
	 * Allocate the unit in the bitmap.
	 */
	KASSERT((ifc->ifc_units[bytoff] & (1 << bitoff)) == 0,
	    ("%s: bit is already set", __func__));
	ifc->ifc_units[bytoff] |= (1 << bitoff);

	/* In the wildcard case, we need to update the name. */
	if (wildcard) {
		for (dp = name; *dp != '\0'; dp++);
		if (snprintf(dp, len - (dp-name), "%d", unit) >
		    len - (dp-name) - 1) {
			/*
			 * This can only be a programmer error and
			 * there's no straightforward way to recover if
			 * it happens.
			 */
			panic("%s: interface name too long", __func__);
			/* NOTREACHED */
		}

	}

	return (0);
}

/*
 * Destroy a clone network interface.
 */
static int
if_clone_destroy(const char *name)
{
	struct if_clone *ifc;
	struct ifnet *ifp;
	int bytoff, bitoff;
	u_int32_t unit;

	ifc = if_clone_lookup(name, &unit);
	if (ifc == NULL)
		return (EINVAL);

	if (unit < ifc->ifc_minifs)
		return (EINVAL);

	ifp = ifunit(name);
	if (ifp == NULL)
		return (ENXIO);

	if (ifc->ifc_destroy == NULL)
		return (EOPNOTSUPP);

	(*ifc->ifc_destroy)(ifp);

	/*
	 * Compute offset in the bitmap and deallocate the unit.
	 */
	bytoff = unit >> 3;
	bitoff = unit - (bytoff << 3);
	KASSERT((ifc->ifc_units[bytoff] & (1 << bitoff)) != 0,
	    ("%s: bit is already cleared", __func__));
	ifc->ifc_units[bytoff] &= ~(1 << bitoff);
	return (0);
}

/*
 * Look up a network interface cloner.
 */

__private_extern__ struct if_clone *
if_clone_lookup(const char *name, u_int32_t *unitp)
{
	struct if_clone *ifc;
	const char *cp;
	u_int32_t i;

	for (ifc = LIST_FIRST(&if_cloners); ifc != NULL; ) {
		for (cp = name, i = 0; i < ifc->ifc_namelen; i++, cp++) {
			if (ifc->ifc_name[i] != *cp)
				goto next_ifc;
		}
		goto found_name;
next_ifc:
		ifc = LIST_NEXT(ifc, ifc_list);
	}

	/* No match. */
	return ((struct if_clone *)NULL);

found_name:
	if (*cp == '\0') {
		i = UINT32_MAX;
	} else {
		for (i = 0; *cp != '\0'; cp++) {
			if (*cp < '0' || *cp > '9') {
				/* Bogus unit number. */
				return (NULL);
			}
			i = (i * 10) + (*cp - '0');
		}
	}

	if (unitp != NULL)
		*unitp = i;
	return (ifc);
}

/*
 * Register a network interface cloner.
 */
int
if_clone_attach(struct if_clone *ifc)
{
	int bytoff, bitoff;
	int err;
	int len, maxclone;
	u_int32_t unit;

	KASSERT(ifc->ifc_minifs - 1 <= ifc->ifc_maxunit,
	    ("%s: %s requested more units then allowed (%d > %d)",
	    __func__, ifc->ifc_name, ifc->ifc_minifs,
	    ifc->ifc_maxunit + 1));
	/*
	 * Compute bitmap size and allocate it.
	 */
	maxclone = ifc->ifc_maxunit + 1;
	len = maxclone >> 3;
	if ((len << 3) < maxclone)
		len++;
	ifc->ifc_units = _MALLOC(len, M_CLONE, M_WAITOK | M_ZERO);
	if (ifc->ifc_units == NULL)
		return (ENOBUFS);
	ifc->ifc_bmlen = len;

	LIST_INSERT_HEAD(&if_cloners, ifc, ifc_list);
	if_cloners_count++;

	for (unit = 0; unit < ifc->ifc_minifs; unit++) {
		err = (*ifc->ifc_create)(ifc, unit, NULL);
		KASSERT(err == 0,
		    ("%s: failed to create required interface %s%d",
		    __func__, ifc->ifc_name, unit));

		/* Allocate the unit in the bitmap. */
		bytoff = unit >> 3;
		bitoff = unit - (bytoff << 3);
		ifc->ifc_units[bytoff] |= (1 << bitoff);
	}

	return (0);
}

/*
 * Unregister a network interface cloner.
 */
void
if_clone_detach(struct if_clone *ifc)
{
	LIST_REMOVE(ifc, ifc_list);
	FREE(ifc->ifc_units, M_CLONE);
	if_cloners_count--;
}

/*
 * Provide list of interface cloners to userspace.
 */
static int
if_clone_list(int count, int *ret_total, user_addr_t dst)
{
	char outbuf[IFNAMSIZ];
	struct if_clone *ifc;
	int error = 0;

	*ret_total = if_cloners_count;
	if (dst == USER_ADDR_NULL) {
		/* Just asking how many there are. */
		return (0);
	}

	if (count < 0)
		return (EINVAL);

	count = (if_cloners_count < count) ? if_cloners_count : count;

	for (ifc = LIST_FIRST(&if_cloners); ifc != NULL && count != 0;
	    ifc = LIST_NEXT(ifc, ifc_list), count--, dst += IFNAMSIZ) {
		bzero(outbuf, sizeof(outbuf));
		strlcpy(outbuf, ifc->ifc_name,
		    min(strlen(ifc->ifc_name), IFNAMSIZ));
		error = copyout(outbuf, dst, IFNAMSIZ);
		if (error)
			break;
	}

	return (error);
}

u_int32_t
if_functional_type(struct ifnet *ifp, bool exclude_delegate)
{
	u_int32_t ret = IFRTYPE_FUNCTIONAL_UNKNOWN;
	if (ifp != NULL) {
		if (ifp->if_flags & IFF_LOOPBACK) {
			ret = IFRTYPE_FUNCTIONAL_LOOPBACK;
		} else if ((exclude_delegate &&
		    (ifp->if_subfamily == IFNET_SUBFAMILY_WIFI)) ||
		    (!exclude_delegate && IFNET_IS_WIFI(ifp))) {
			if (ifp->if_eflags & IFEF_AWDL)
				ret = IFRTYPE_FUNCTIONAL_WIFI_AWDL;
			else
				ret = IFRTYPE_FUNCTIONAL_WIFI_INFRA;
		} else if ((exclude_delegate &&
		    (ifp->if_type == IFT_CELLULAR)) ||
		    (!exclude_delegate && IFNET_IS_CELLULAR(ifp))) {
			ret = IFRTYPE_FUNCTIONAL_CELLULAR;
		} else if (IFNET_IS_INTCOPROC(ifp)) {
			ret = IFRTYPE_FUNCTIONAL_INTCOPROC;
		} else if ((exclude_delegate &&
		    (ifp->if_family == IFNET_FAMILY_ETHERNET ||
		    ifp->if_family == IFNET_FAMILY_FIREWIRE)) ||
		    (!exclude_delegate && IFNET_IS_WIRED(ifp))) {
			ret = IFRTYPE_FUNCTIONAL_WIRED;
		}
	}

	return (ret);
}

/*
 * Similar to ifa_ifwithaddr, except that this is IPv4 specific
 * and that it matches only the local (not broadcast) address.
 */
__private_extern__ struct in_ifaddr *
ifa_foraddr(unsigned int addr)
{
	return (ifa_foraddr_scoped(addr, IFSCOPE_NONE));
}

/*
 * Similar to ifa_foraddr, except with the added interface scope
 * constraint (unless the caller passes in IFSCOPE_NONE in which
 * case there is no scope restriction).
 */
__private_extern__ struct in_ifaddr *
ifa_foraddr_scoped(unsigned int addr, unsigned int scope)
{
	struct in_ifaddr *ia = NULL;

	lck_rw_lock_shared(in_ifaddr_rwlock);
	TAILQ_FOREACH(ia, INADDR_HASH(addr), ia_hash) {
		IFA_LOCK_SPIN(&ia->ia_ifa);
		if (ia->ia_addr.sin_addr.s_addr == addr &&
		    (scope == IFSCOPE_NONE || ia->ia_ifp->if_index == scope)) {
			IFA_ADDREF_LOCKED(&ia->ia_ifa);	/* for caller */
			IFA_UNLOCK(&ia->ia_ifa);
			break;
		}
		IFA_UNLOCK(&ia->ia_ifa);
	}
	lck_rw_done(in_ifaddr_rwlock);
	return (ia);
}

#if INET6
/*
 * Similar to ifa_foraddr, except that this for IPv6.
 */
__private_extern__ struct in6_ifaddr *
ifa_foraddr6(struct in6_addr *addr6)
{
	return (ifa_foraddr6_scoped(addr6, IFSCOPE_NONE));
}

__private_extern__ struct in6_ifaddr *
ifa_foraddr6_scoped(struct in6_addr *addr6, unsigned int scope)
{
	struct in6_ifaddr *ia = NULL;

	lck_rw_lock_shared(&in6_ifaddr_rwlock);
	for (ia = in6_ifaddrs; ia; ia = ia->ia_next) {
		IFA_LOCK(&ia->ia_ifa);
		if (IN6_ARE_ADDR_EQUAL(&ia->ia_addr.sin6_addr, addr6) &&
		    (scope == IFSCOPE_NONE || ia->ia_ifp->if_index == scope)) {
			IFA_ADDREF_LOCKED(&ia->ia_ifa); /* for caller */
			IFA_UNLOCK(&ia->ia_ifa);
			break;
		}
		IFA_UNLOCK(&ia->ia_ifa);
	}
	lck_rw_done(&in6_ifaddr_rwlock);

	return (ia);
}
#endif /* INET6 */

/*
 * Return the first (primary) address of a given family on an interface.
 */
__private_extern__ struct ifaddr *
ifa_ifpgetprimary(struct ifnet *ifp, int family)
{
	struct ifaddr *ifa;

	ifnet_lock_shared(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		IFA_LOCK_SPIN(ifa);
		if (ifa->ifa_addr->sa_family == family) {
			IFA_ADDREF_LOCKED(ifa);	/* for caller */
			IFA_UNLOCK(ifa);
			break;
		}
		IFA_UNLOCK(ifa);
	}
	ifnet_lock_done(ifp);

	return (ifa);
}

static inline int
ifa_equal(const struct sockaddr *sa1, const struct sockaddr *sa2)
{

	if (!sa1 || !sa2)
		return 0;
	if (sa1->sa_len != sa2->sa_len)
		return 0;

	return (bcmp(sa1, sa2, sa1->sa_len) == 0);
}

/*
 * Locate an interface based on a complete address.
 */
struct ifaddr *
ifa_ifwithaddr_locked(const struct sockaddr *addr)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	struct ifaddr *result = NULL;

	for (ifp = ifnet_head.tqh_first; ifp && !result;
	    ifp = ifp->if_link.tqe_next) {
		ifnet_lock_shared(ifp);
		for (ifa = ifp->if_addrhead.tqh_first; ifa;
		    ifa = ifa->ifa_link.tqe_next) {
			IFA_LOCK_SPIN(ifa);
			if (ifa->ifa_addr->sa_family != addr->sa_family) {
				IFA_UNLOCK(ifa);
				continue;
			}
			if (ifa_equal(addr, ifa->ifa_addr)) {
				result = ifa;
				IFA_ADDREF_LOCKED(ifa);	/* for caller */
				IFA_UNLOCK(ifa);
				break;
			}
			if ((ifp->if_flags & IFF_BROADCAST) &&
			    ifa->ifa_broadaddr != NULL &&
			    /* IP6 doesn't have broadcast */
			    ifa->ifa_broadaddr->sa_len != 0 &&
			    ifa_equal(ifa->ifa_broadaddr, addr)) {
				result = ifa;
				IFA_ADDREF_LOCKED(ifa);	/* for caller */
				IFA_UNLOCK(ifa);
				break;
			}
			IFA_UNLOCK(ifa);
		}
		ifnet_lock_done(ifp);
	}

	return (result);
}

struct ifaddr *
ifa_ifwithaddr(const struct sockaddr *addr)
{
	struct ifaddr *result = NULL;

	ifnet_head_lock_shared();

	result = ifa_ifwithaddr_locked(addr);

	ifnet_head_done();

	return (result);
}
/*
 * Locate the point to point interface with a given destination address.
 */
/*ARGSUSED*/
struct ifaddr *
ifa_ifwithdstaddr(const struct sockaddr *addr)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	struct ifaddr *result = NULL;

	ifnet_head_lock_shared();
	for (ifp = ifnet_head.tqh_first; ifp && !result;
	    ifp = ifp->if_link.tqe_next) {
	    if ((ifp->if_flags & IFF_POINTOPOINT)) {
			ifnet_lock_shared(ifp);
			for (ifa = ifp->if_addrhead.tqh_first; ifa;
			    ifa = ifa->ifa_link.tqe_next) {
				IFA_LOCK_SPIN(ifa);
				if (ifa->ifa_addr->sa_family !=
				    addr->sa_family) {
					IFA_UNLOCK(ifa);
					continue;
				}
				if (ifa_equal(addr, ifa->ifa_dstaddr)) {
					result = ifa;
					IFA_ADDREF_LOCKED(ifa);	/* for caller */
					IFA_UNLOCK(ifa);
					break;
				}
				IFA_UNLOCK(ifa);
			}
			ifnet_lock_done(ifp);
		}
	}
	ifnet_head_done();
	return (result);
}

/*
 * Locate the source address of an interface based on a complete address.
 */
struct ifaddr *
ifa_ifwithaddr_scoped_locked(const struct sockaddr *addr, unsigned int ifscope)
{
	struct ifaddr *result = NULL;
	struct ifnet *ifp;

	if (ifscope == IFSCOPE_NONE)
		return (ifa_ifwithaddr_locked(addr));

	if (ifscope > (unsigned int)if_index) {
		return (NULL);
	}

	ifp = ifindex2ifnet[ifscope];
	if (ifp != NULL) {
		struct ifaddr *ifa = NULL;

		/*
		 * This is suboptimal; there should be a better way
		 * to search for a given address of an interface
		 * for any given address family.
		 */
		ifnet_lock_shared(ifp);
		for (ifa = ifp->if_addrhead.tqh_first; ifa != NULL;
		    ifa = ifa->ifa_link.tqe_next) {
			IFA_LOCK_SPIN(ifa);
			if (ifa->ifa_addr->sa_family != addr->sa_family) {
				IFA_UNLOCK(ifa);
				continue;
			}
			if (ifa_equal(addr, ifa->ifa_addr)) {
				result = ifa;
				IFA_ADDREF_LOCKED(ifa);	/* for caller */
				IFA_UNLOCK(ifa);
				break;
			}
			if ((ifp->if_flags & IFF_BROADCAST) &&
			    ifa->ifa_broadaddr != NULL &&
			    /* IP6 doesn't have broadcast */
			    ifa->ifa_broadaddr->sa_len != 0 &&
			    ifa_equal(ifa->ifa_broadaddr, addr)) {
				result = ifa;
				IFA_ADDREF_LOCKED(ifa);	/* for caller */
				IFA_UNLOCK(ifa);
				break;
			}
			IFA_UNLOCK(ifa);
		}
		ifnet_lock_done(ifp);
	}

	return (result);
}

struct ifaddr *
ifa_ifwithaddr_scoped(const struct sockaddr *addr, unsigned int ifscope)
{
	struct ifaddr *result = NULL;

	ifnet_head_lock_shared();

	result = ifa_ifwithaddr_scoped_locked(addr, ifscope);

	ifnet_head_done();

	return (result);
}

struct ifaddr *
ifa_ifwithnet(const struct sockaddr *addr)
{
	return (ifa_ifwithnet_common(addr, IFSCOPE_NONE));
}

struct ifaddr *
ifa_ifwithnet_scoped(const struct sockaddr *addr, unsigned int ifscope)
{
	return (ifa_ifwithnet_common(addr, ifscope));
}

/*
 * Find an interface on a specific network.  If many, choice
 * is most specific found.
 */
static struct ifaddr *
ifa_ifwithnet_common(const struct sockaddr *addr, unsigned int ifscope)
{
	struct ifnet *ifp;
	struct ifaddr *ifa = NULL;
	struct ifaddr *ifa_maybe = NULL;
	u_int af = addr->sa_family;
	const char *addr_data = addr->sa_data, *cplim;

#if INET6
	if (af != AF_INET && af != AF_INET6)
#else
	if (af != AF_INET)
#endif /* !INET6 */
		ifscope = IFSCOPE_NONE;

	ifnet_head_lock_shared();
	/*
	 * AF_LINK addresses can be looked up directly by their index number,
	 * so do that if we can.
	 */
	if (af == AF_LINK) {
		const struct sockaddr_dl *sdl =
		    (const struct sockaddr_dl *)(uintptr_t)(size_t)addr;
		if (sdl->sdl_index && sdl->sdl_index <= if_index) {
			ifa = ifnet_addrs[sdl->sdl_index - 1];
			if (ifa != NULL)
				IFA_ADDREF(ifa);

			ifnet_head_done();
			return (ifa);
		}
	}

	/*
	 * Scan though each interface, looking for ones that have
	 * addresses in this address family.
	 */
	for (ifp = ifnet_head.tqh_first; ifp; ifp = ifp->if_link.tqe_next) {
		ifnet_lock_shared(ifp);
		for (ifa = ifp->if_addrhead.tqh_first; ifa;
		     ifa = ifa->ifa_link.tqe_next) {
			const char *cp, *cp2, *cp3;

			IFA_LOCK(ifa);
			if (ifa->ifa_addr == NULL ||
			    ifa->ifa_addr->sa_family != af) {
next:
				IFA_UNLOCK(ifa);
				continue;
			}
			/*
			 * If we're looking up with a scope,
			 * find using a matching interface.
			 */
			if (ifscope != IFSCOPE_NONE &&
			    ifp->if_index != ifscope) {
				IFA_UNLOCK(ifa);
				continue;
			}

			/*
			 * Scan all the bits in the ifa's address.
			 * If a bit dissagrees with what we are
			 * looking for, mask it with the netmask
			 * to see if it really matters.
			 * (A byte at a time)
			 */
			if (ifa->ifa_netmask == 0) {
				IFA_UNLOCK(ifa);
				continue;
			}
			cp = addr_data;
			cp2 = ifa->ifa_addr->sa_data;
			cp3 = ifa->ifa_netmask->sa_data;
			cplim = ifa->ifa_netmask->sa_len +
			    (char *)ifa->ifa_netmask;
			while (cp3 < cplim)
				if ((*cp++ ^ *cp2++) & *cp3++)
					goto next; /* next address! */
			/*
			 * If the netmask of what we just found
			 * is more specific than what we had before
			 * (if we had one) then remember the new one
			 * before continuing to search
			 * for an even better one.
			 */
			if (ifa_maybe == NULL ||
			    rn_refines((caddr_t)ifa->ifa_netmask,
			    (caddr_t)ifa_maybe->ifa_netmask)) {
				IFA_ADDREF_LOCKED(ifa);	/* ifa_maybe */
				IFA_UNLOCK(ifa);
				if (ifa_maybe != NULL)
					IFA_REMREF(ifa_maybe);
				ifa_maybe = ifa;
			} else {
				IFA_UNLOCK(ifa);
			}
			IFA_LOCK_ASSERT_NOTHELD(ifa);
		}
		ifnet_lock_done(ifp);

		if (ifa != NULL)
			break;
	}
	ifnet_head_done();

	if (ifa == NULL)
		ifa = ifa_maybe;
	else if (ifa_maybe != NULL)
		IFA_REMREF(ifa_maybe);

	return (ifa);
}

/*
 * Find an interface address specific to an interface best matching
 * a given address.
 */
struct ifaddr *
ifaof_ifpforaddr(const struct sockaddr *addr, struct ifnet *ifp)
{
	struct ifaddr *ifa = NULL;
	const char *cp, *cp2, *cp3;
	char *cplim;
	struct ifaddr *ifa_maybe = NULL;
	struct ifaddr *better_ifa_maybe = NULL;
	u_int af = addr->sa_family;

	if (af >= AF_MAX)
		return (NULL);

	ifnet_lock_shared(ifp);
	for (ifa = ifp->if_addrhead.tqh_first; ifa;
	     ifa = ifa->ifa_link.tqe_next) {
		IFA_LOCK(ifa);
		if (ifa->ifa_addr->sa_family != af) {
			IFA_UNLOCK(ifa);
			continue;
		}
		if (ifa_maybe == NULL) {
			IFA_ADDREF_LOCKED(ifa);	/* for ifa_maybe */
			ifa_maybe = ifa;
		}
		if (ifa->ifa_netmask == 0) {
			if (ifa_equal(addr, ifa->ifa_addr) ||
			    ifa_equal(addr, ifa->ifa_dstaddr)) {
				IFA_ADDREF_LOCKED(ifa);	/* for caller */
				IFA_UNLOCK(ifa);
				break;
			}
			IFA_UNLOCK(ifa);
			continue;
		}
		if (ifp->if_flags & IFF_POINTOPOINT) {
			if (ifa_equal(addr, ifa->ifa_dstaddr)) {
				IFA_ADDREF_LOCKED(ifa);	/* for caller */
				IFA_UNLOCK(ifa);
				break;
			}
		} else {
			if (ifa_equal(addr, ifa->ifa_addr)) {
				/* exact match */
				IFA_ADDREF_LOCKED(ifa);	/* for caller */
				IFA_UNLOCK(ifa);
				break;
			}
			cp = addr->sa_data;
			cp2 = ifa->ifa_addr->sa_data;
			cp3 = ifa->ifa_netmask->sa_data;
			cplim = ifa->ifa_netmask->sa_len +
			    (char *)ifa->ifa_netmask;
			for (; cp3 < cplim; cp3++)
				if ((*cp++ ^ *cp2++) & *cp3)
					break;
			if (cp3 == cplim) {
				/* subnet match */
				if (better_ifa_maybe == NULL) {
					/* for better_ifa_maybe */
					IFA_ADDREF_LOCKED(ifa);
					better_ifa_maybe = ifa;
				}
			}
		}
		IFA_UNLOCK(ifa);
	}

	if (ifa == NULL) {
		if (better_ifa_maybe != NULL) {
			ifa = better_ifa_maybe;
			better_ifa_maybe = NULL;
		} else {
			ifa = ifa_maybe;
			ifa_maybe = NULL;
		}
	}

	ifnet_lock_done(ifp);

	if (better_ifa_maybe != NULL)
		IFA_REMREF(better_ifa_maybe);
	if (ifa_maybe != NULL)
		IFA_REMREF(ifa_maybe);

	return (ifa);
}

#include <net/route.h>

/*
 * Default action when installing a route with a Link Level gateway.
 * Lookup an appropriate real ifa to point to.
 * This should be moved to /sys/net/link.c eventually.
 */
void
link_rtrequest(int cmd, struct rtentry *rt, struct sockaddr *sa)
{
	struct ifaddr *ifa;
	struct sockaddr *dst;
	struct ifnet *ifp;
	void (*ifa_rtrequest)(int, struct rtentry *, struct sockaddr *);

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_OWNED);
	RT_LOCK_ASSERT_HELD(rt);

	if (cmd != RTM_ADD || ((ifa = rt->rt_ifa) == 0) ||
	    ((ifp = ifa->ifa_ifp) == 0) || ((dst = rt_key(rt)) == 0))
		return;

	/* Become a regular mutex, just in case */
	RT_CONVERT_LOCK(rt);

	ifa = ifaof_ifpforaddr(dst, ifp);
	if (ifa) {
		rtsetifa(rt, ifa);
		IFA_LOCK_SPIN(ifa);
		ifa_rtrequest = ifa->ifa_rtrequest;
		IFA_UNLOCK(ifa);
		if (ifa_rtrequest != NULL && ifa_rtrequest != link_rtrequest)
			ifa_rtrequest(cmd, rt, sa);
		IFA_REMREF(ifa);
	}
}

/*
 * if_updown will set the interface up or down. It will
 * prevent other up/down events from occurring until this
 * up/down event has completed.
 *
 * Caller must lock ifnet. This function will drop the
 * lock. This allows ifnet_set_flags to set the rest of
 * the flags after we change the up/down state without
 * dropping the interface lock between setting the
 * up/down state and updating the rest of the flags.
 */
__private_extern__ void
if_updown( struct ifnet *ifp, int up)
{
	int i;
	struct ifaddr **ifa;
	struct timespec	tv;
	struct ifclassq *ifq = &ifp->if_snd;

	/* Wait until no one else is changing the up/down state */
	while ((ifp->if_eflags & IFEF_UPDOWNCHANGE) != 0) {
		tv.tv_sec = 0;
		tv.tv_nsec = NSEC_PER_SEC / 10;
		ifnet_lock_done(ifp);
		msleep(&ifp->if_eflags, NULL, 0, "if_updown", &tv);
		ifnet_lock_exclusive(ifp);
	}

	/* Verify that the interface isn't already in the right state */
	if ((!up && (ifp->if_flags & IFF_UP) == 0) ||
		(up && (ifp->if_flags & IFF_UP) == IFF_UP)) {
		return;
	}

	/* Indicate that the up/down state is changing */
	ifp->if_eflags |= IFEF_UPDOWNCHANGE;

	/* Mark interface up or down */
	if (up) {
		ifp->if_flags |= IFF_UP;
	} else {
		ifp->if_flags &= ~IFF_UP;
	}

	ifnet_touch_lastchange(ifp);

	/* Drop the lock to notify addresses and route */
	ifnet_lock_done(ifp);

	IFCQ_LOCK(ifq);
	if_qflush(ifp, 1);

	/* Inform all transmit queues about the new link state */
	ifnet_update_sndq(ifq, up ? CLASSQ_EV_LINK_UP : CLASSQ_EV_LINK_DOWN);
	IFCQ_UNLOCK(ifq);

	if (ifnet_get_address_list(ifp, &ifa) == 0) {
		for (i = 0; ifa[i] != 0; i++) {
			pfctlinput(up ? PRC_IFUP : PRC_IFDOWN, ifa[i]->ifa_addr);
		}
		ifnet_free_address_list(ifa);
	}
	rt_ifmsg(ifp);

	/* Aquire the lock to clear the changing flag */
	ifnet_lock_exclusive(ifp);
	ifp->if_eflags &= ~IFEF_UPDOWNCHANGE;
	wakeup(&ifp->if_eflags);
}

/*
 * Mark an interface down and notify protocols of
 * the transition.
 */
void
if_down(
	struct ifnet *ifp)
{
	ifnet_lock_exclusive(ifp);
	if_updown(ifp, 0);
	ifnet_lock_done(ifp);
}

/*
 * Mark an interface up and notify protocols of
 * the transition.
 */
void
if_up(
	struct ifnet *ifp)
{
	ifnet_lock_exclusive(ifp);
	if_updown(ifp, 1);
	ifnet_lock_done(ifp);
}

/*
 * Flush an interface queue.
 */
void
if_qflush(struct ifnet *ifp, int ifq_locked)
{
	struct ifclassq *ifq = &ifp->if_snd;

	if (!ifq_locked)
		IFCQ_LOCK(ifq);

	if (IFCQ_IS_ENABLED(ifq))
		IFCQ_PURGE(ifq);

	VERIFY(IFCQ_IS_EMPTY(ifq));

	if (!ifq_locked)
		IFCQ_UNLOCK(ifq);
}

void
if_qflush_sc(struct ifnet *ifp, mbuf_svc_class_t sc, u_int32_t flow,
    u_int32_t *packets, u_int32_t *bytes, int ifq_locked)
{
	struct ifclassq *ifq = &ifp->if_snd;
	u_int32_t cnt = 0, len = 0;
	u_int32_t a_cnt = 0, a_len = 0;

	VERIFY(sc == MBUF_SC_UNSPEC || MBUF_VALID_SC(sc));
	VERIFY(flow != 0);

	if (!ifq_locked)
		IFCQ_LOCK(ifq);

	if (IFCQ_IS_ENABLED(ifq))
		IFCQ_PURGE_SC(ifq, sc, flow, cnt, len);

	if (!ifq_locked)
		IFCQ_UNLOCK(ifq);

	if (packets != NULL)
		*packets = cnt + a_cnt;
	if (bytes != NULL)
		*bytes = len + a_len;
}

/*
 * Extracts interface unit number and name from string, returns -1 upon failure.
 * Upon success, returns extracted unit number, and interface name in dst.
 */
int
ifunit_extract(const char *src, char *dst, size_t dstlen, int *unit)
{
	const char *cp;
	size_t len, m;
	char c;
	int u;

	if (src == NULL || dst == NULL || dstlen == 0 || unit == NULL)
		return (-1);

	len = strlen(src);
	if (len < 2 || len > dstlen)
		return (-1);
	cp = src + len - 1;
	c = *cp;
	if (c < '0' || c > '9')
		return (-1);		/* trailing garbage */
	u = 0;
	m = 1;
	do {
		if (cp == src)
			return (-1);	/* no interface name */
		u += (c - '0') * m;
		if (u > 1000000)
			return (-1);	/* number is unreasonable */
		m *= 10;
		c = *--cp;
	} while (c >= '0' && c <= '9');
	len = cp - src + 1;
	bcopy(src, dst, len);
	dst[len] = '\0';
	*unit = u;

	return (0);
}

/*
 * Map interface name to
 * interface structure pointer.
 */
static struct ifnet *
ifunit_common(const char *name, boolean_t hold)
{
	char namebuf[IFNAMSIZ + 1];
	struct ifnet *ifp;
	int unit;

	if (ifunit_extract(name, namebuf, sizeof (namebuf), &unit) < 0)
		return (NULL);

	/* for safety, since we use strcmp() below */
	namebuf[sizeof (namebuf) - 1] = '\0';

	/*
	 * Now search all the interfaces for this name/number
	 */
	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		/*
		 * Use strcmp() rather than strncmp() here,
		 * since we want to match the entire string.
		 */
		if (strcmp(ifp->if_name, namebuf))
			continue;
		if (unit == ifp->if_unit)
			break;
	}

	/* if called from ifunit_ref() and ifnet is not attached, bail */
	if (hold && ifp != NULL && !ifnet_is_attached(ifp, 1))
		ifp = NULL;

	ifnet_head_done();
	return (ifp);
}

struct ifnet *
ifunit(const char *name)
{
	return (ifunit_common(name, FALSE));
}

/*
 * Similar to ifunit(), except that we hold an I/O reference count on an
 * attached interface, which must later be released via ifnet_decr_iorefcnt().
 * Will return NULL unless interface exists and is fully attached.
 */
struct ifnet *
ifunit_ref(const char *name)
{
	return (ifunit_common(name, TRUE));
}

/*
 * Map interface name in a sockaddr_dl to
 * interface structure pointer.
 */
struct ifnet *
if_withname(struct sockaddr *sa)
{
	char ifname[IFNAMSIZ+1];
	struct sockaddr_dl *sdl = (struct sockaddr_dl *)(void *)sa;

	if ((sa->sa_family != AF_LINK) || (sdl->sdl_nlen == 0) ||
	    (sdl->sdl_nlen > IFNAMSIZ))
		return (NULL);

	/*
	 * ifunit wants a null-terminated name.  It may not be null-terminated
	 * in the sockaddr.  We don't want to change the caller's sockaddr,
	 * and there might not be room to put the trailing null anyway, so we
	 * make a local copy that we know we can null terminate safely.
	 */

	bcopy(sdl->sdl_data, ifname, sdl->sdl_nlen);
	ifname[sdl->sdl_nlen] = '\0';
	return (ifunit(ifname));
}

static __attribute__((noinline)) int
ifioctl_ifconf(u_long cmd, caddr_t data)
{
	int error = 0;

	switch (cmd) {
	case OSIOCGIFCONF32:			/* struct ifconf32 */
	case SIOCGIFCONF32: {			/* struct ifconf32 */
		struct ifconf32 ifc;
		bcopy(data, &ifc, sizeof (ifc));
		error = ifconf(cmd, CAST_USER_ADDR_T(ifc.ifc_req),
		    &ifc.ifc_len);
		bcopy(&ifc, data, sizeof (ifc));
		break;
	}

	case SIOCGIFCONF64:			/* struct ifconf64 */
	case OSIOCGIFCONF64: {			/* struct ifconf64 */
		struct ifconf64 ifc;
		bcopy(data, &ifc, sizeof (ifc));
		error = ifconf(cmd, ifc.ifc_req, &ifc.ifc_len);
		bcopy(&ifc, data, sizeof (ifc));
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static __attribute__((noinline)) int
ifioctl_ifclone(u_long cmd, caddr_t data)
{
	int error = 0;

	switch (cmd) {
	case SIOCIFGCLONERS32: {		/* struct if_clonereq32 */
		struct if_clonereq32 ifcr;
		bcopy(data, &ifcr, sizeof (ifcr));
		error = if_clone_list(ifcr.ifcr_count, &ifcr.ifcr_total,
		    CAST_USER_ADDR_T(ifcr.ifcru_buffer));
		bcopy(&ifcr, data, sizeof (ifcr));
		break;
	}

	case SIOCIFGCLONERS64: {		/* struct if_clonereq64 */
		struct if_clonereq64 ifcr;
		bcopy(data, &ifcr, sizeof (ifcr));
		error = if_clone_list(ifcr.ifcr_count, &ifcr.ifcr_total,
		    ifcr.ifcru_buffer);
		bcopy(&ifcr, data, sizeof (ifcr));
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static __attribute__((noinline)) int
ifioctl_ifdesc(struct ifnet *ifp, u_long cmd, caddr_t data, struct proc *p)
{
	struct if_descreq *ifdr = (struct if_descreq *)(void *)data;
	u_int32_t ifdr_len;
	int error = 0;

	VERIFY(ifp != NULL);

	switch (cmd) {
	case SIOCSIFDESC: {			/* struct if_descreq */
		if ((error = proc_suser(p)) != 0)
			break;

		ifnet_lock_exclusive(ifp);
		bcopy(&ifdr->ifdr_len, &ifdr_len, sizeof (ifdr_len));
		if (ifdr_len > sizeof (ifdr->ifdr_desc) ||
		    ifdr_len > ifp->if_desc.ifd_maxlen) {
			error = EINVAL;
			ifnet_lock_done(ifp);
			break;
		}

		bzero(ifp->if_desc.ifd_desc, ifp->if_desc.ifd_maxlen);
		if ((ifp->if_desc.ifd_len = ifdr_len) > 0) {
			bcopy(ifdr->ifdr_desc, ifp->if_desc.ifd_desc,
			    MIN(ifdr_len, ifp->if_desc.ifd_maxlen));
		}
		ifnet_lock_done(ifp);
		break;
	}

	case SIOCGIFDESC: {			/* struct if_descreq */
		ifnet_lock_shared(ifp);
		ifdr_len = MIN(ifp->if_desc.ifd_len, sizeof (ifdr->ifdr_desc));
		bcopy(&ifdr_len, &ifdr->ifdr_len, sizeof (ifdr_len));
		bzero(&ifdr->ifdr_desc, sizeof (ifdr->ifdr_desc));
		if (ifdr_len > 0) {
			bcopy(ifp->if_desc.ifd_desc, ifdr->ifdr_desc, ifdr_len);
		}
		ifnet_lock_done(ifp);
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static __attribute__((noinline)) int
ifioctl_linkparams(struct ifnet *ifp, u_long cmd, caddr_t data, struct proc *p)
{
	struct if_linkparamsreq *iflpr =
	    (struct if_linkparamsreq *)(void *)data;
	struct ifclassq *ifq;
	int error = 0;

	VERIFY(ifp != NULL);
	ifq = &ifp->if_snd;

	switch (cmd) {
	case SIOCSIFLINKPARAMS: {		/* struct if_linkparamsreq */
		struct tb_profile tb = { 0, 0, 0 };

		if ((error = proc_suser(p)) != 0)
		break;

		IFCQ_LOCK(ifq);
		if (!IFCQ_IS_READY(ifq)) {
			error = ENXIO;
			IFCQ_UNLOCK(ifq);
			break;
		}
		bcopy(&iflpr->iflpr_output_tbr_rate, &tb.rate,
		    sizeof (tb.rate));
		bcopy(&iflpr->iflpr_output_tbr_percent, &tb.percent,
		    sizeof (tb.percent));
		error = ifclassq_tbr_set(ifq, &tb, TRUE);
		IFCQ_UNLOCK(ifq);
		break;
	}

	case SIOCGIFLINKPARAMS: {		/* struct if_linkparamsreq */
		u_int32_t sched_type = PKTSCHEDT_NONE, flags = 0;
		u_int64_t tbr_bw = 0, tbr_pct = 0;

		IFCQ_LOCK(ifq);

		if (IFCQ_IS_ENABLED(ifq))
			sched_type = ifq->ifcq_type;

		bcopy(&sched_type, &iflpr->iflpr_output_sched,
		    sizeof (iflpr->iflpr_output_sched));

		if (IFCQ_TBR_IS_ENABLED(ifq)) {
			tbr_bw = ifq->ifcq_tbr.tbr_rate_raw;
			tbr_pct = ifq->ifcq_tbr.tbr_percent;
		}
		bcopy(&tbr_bw, &iflpr->iflpr_output_tbr_rate,
		    sizeof (iflpr->iflpr_output_tbr_rate));
		bcopy(&tbr_pct, &iflpr->iflpr_output_tbr_percent,
		    sizeof (iflpr->iflpr_output_tbr_percent));
		IFCQ_UNLOCK(ifq);

		if (ifp->if_output_sched_model ==
		    IFNET_SCHED_MODEL_DRIVER_MANAGED)
			flags |= IFLPRF_DRVMANAGED;
		bcopy(&flags, &iflpr->iflpr_flags, sizeof (iflpr->iflpr_flags));
		bcopy(&ifp->if_output_bw, &iflpr->iflpr_output_bw,
		    sizeof (iflpr->iflpr_output_bw));
		bcopy(&ifp->if_input_bw, &iflpr->iflpr_input_bw,
		    sizeof (iflpr->iflpr_input_bw));
		bcopy(&ifp->if_output_lt, &iflpr->iflpr_output_lt,
		    sizeof (iflpr->iflpr_output_lt));
		bcopy(&ifp->if_input_lt, &iflpr->iflpr_input_lt,
		    sizeof (iflpr->iflpr_input_lt));
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static __attribute__((noinline)) int
ifioctl_qstats(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct if_qstatsreq *ifqr = (struct if_qstatsreq *)(void *)data;
	u_int32_t ifqr_len, ifqr_slot;
	int error = 0;

	VERIFY(ifp != NULL);

	switch (cmd) {
	case SIOCGIFQUEUESTATS: {		/* struct if_qstatsreq */
		bcopy(&ifqr->ifqr_slot, &ifqr_slot, sizeof (ifqr_slot));
		bcopy(&ifqr->ifqr_len, &ifqr_len, sizeof (ifqr_len));
		error = ifclassq_getqstats(&ifp->if_snd, ifqr_slot,
		    ifqr->ifqr_buf, &ifqr_len);
		if (error != 0)
			ifqr_len = 0;
		bcopy(&ifqr_len, &ifqr->ifqr_len, sizeof (ifqr_len));
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static __attribute__((noinline)) int
ifioctl_throttle(struct ifnet *ifp, u_long cmd, caddr_t data, struct proc *p)
{
	struct if_throttlereq *ifthr = (struct if_throttlereq *)(void *)data;
	u_int32_t ifthr_level;
	int error = 0;

	VERIFY(ifp != NULL);

	switch (cmd) {
	case SIOCSIFTHROTTLE: {			/* struct if_throttlereq */
		/*
		 * XXX: Use priv_check_cred() instead of root check?
		 */
		if ((error = proc_suser(p)) != 0)
			break;

		bcopy(&ifthr->ifthr_level, &ifthr_level, sizeof (ifthr_level));
		error = ifnet_set_throttle(ifp, ifthr_level);
		if (error == EALREADY)
			error = 0;
		break;
	}

	case SIOCGIFTHROTTLE: {			/* struct if_throttlereq */
		if ((error = ifnet_get_throttle(ifp, &ifthr_level)) == 0) {
			bcopy(&ifthr_level, &ifthr->ifthr_level,
			    sizeof (ifthr_level));
		}
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static int
ifioctl_getnetagents(struct ifnet *ifp, u_int32_t *count, user_addr_t uuid_p)
{
	int error = 0;
	u_int32_t index = 0;
	u_int32_t valid_netagent_count = 0;
	*count = 0;

	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_SHARED);

	if (ifp->if_agentids != NULL) {
		for (index = 0; index < ifp->if_agentcount; index++) {
			uuid_t *netagent_uuid = &(ifp->if_agentids[index]);
			if (!uuid_is_null(*netagent_uuid)) {
				if (uuid_p != USER_ADDR_NULL) {
					error = copyout(netagent_uuid,
						uuid_p + sizeof(uuid_t) * valid_netagent_count,
						sizeof(uuid_t));
					if (error != 0) {
						return (error);
					}
				}
				valid_netagent_count++;
			}
		}
	}
	*count = valid_netagent_count;

	return (0);
}

#define	IF_MAXAGENTS		64
#define	IF_AGENT_INCREMENT	8
static int
if_add_netagent_locked(struct ifnet *ifp, uuid_t new_agent_uuid)
{
	uuid_t *first_empty_slot = NULL;
	u_int32_t index = 0;
	bool already_added = FALSE;

	if (ifp->if_agentids != NULL) {
		for (index = 0; index < ifp->if_agentcount; index++) {
			uuid_t *netagent_uuid = &(ifp->if_agentids[index]);
			if (uuid_compare(*netagent_uuid, new_agent_uuid) == 0) {
				/* Already present, ignore */
				already_added = TRUE;
				break;
			}
			if (first_empty_slot == NULL &&
				uuid_is_null(*netagent_uuid)) {
				first_empty_slot = netagent_uuid;
			}
		}
	}
	if (already_added) {
		/* Already added agent, don't return an error */
		return (0);
	}
	if (first_empty_slot == NULL) {
		if (ifp->if_agentcount >= IF_MAXAGENTS) {
			/* No room for another netagent UUID, bail */
			return (ENOMEM);
		} else {
			/* Calculate new array size */
			u_int32_t new_agent_count =
			MIN(ifp->if_agentcount + IF_AGENT_INCREMENT,
			    IF_MAXAGENTS);

			/* Reallocate array */
			uuid_t *new_agent_array = _REALLOC(ifp->if_agentids,
			    sizeof(uuid_t) * new_agent_count, M_NETAGENT,
			    M_WAITOK | M_ZERO);
			if (new_agent_array == NULL) {
				return (ENOMEM);
			}

			/* Save new array */
			ifp->if_agentids = new_agent_array;

			/* Set first empty slot */
			first_empty_slot =
			    &(ifp->if_agentids[ifp->if_agentcount]);

			/* Save new array length */
			ifp->if_agentcount = new_agent_count;
		}
	}
	uuid_copy(*first_empty_slot, new_agent_uuid);
	netagent_post_updated_interfaces(new_agent_uuid);
	return (0);
}

int
if_add_netagent(struct ifnet *ifp, uuid_t new_agent_uuid)
{
	VERIFY(ifp != NULL);

	ifnet_lock_exclusive(ifp);

	int error = if_add_netagent_locked(ifp, new_agent_uuid);

	ifnet_lock_done(ifp);

	return (error);
}

static int
if_delete_netagent_locked(struct ifnet *ifp, uuid_t remove_agent_uuid)
{
	u_int32_t index = 0;
	bool removed_agent_id = FALSE;

	if (ifp->if_agentids != NULL) {
		for (index = 0; index < ifp->if_agentcount; index++) {
			uuid_t *netagent_uuid = &(ifp->if_agentids[index]);
			if (uuid_compare(*netagent_uuid,
			    remove_agent_uuid) == 0) {
				uuid_clear(*netagent_uuid);
				removed_agent_id = TRUE;
				break;
			}
		}
	}
	if (removed_agent_id)
		netagent_post_updated_interfaces(remove_agent_uuid);

	return (0);
}

int
if_delete_netagent(struct ifnet *ifp, uuid_t remove_agent_uuid)
{
	VERIFY(ifp != NULL);

	ifnet_lock_exclusive(ifp);

	int error = if_delete_netagent_locked(ifp, remove_agent_uuid);

	ifnet_lock_done(ifp);

	return (error);
}

static __attribute__((noinline)) int
ifioctl_netagent(struct ifnet *ifp, u_long cmd, caddr_t data, struct proc *p)
{
	struct if_agentidreq *ifar = (struct if_agentidreq *)(void *)data;
	union {
		struct if_agentidsreq32 s32;
		struct if_agentidsreq64 s64;
	} u;
	int error = 0;

	VERIFY(ifp != NULL);

	/* Get an io ref count if the interface is attached */
	if (!ifnet_is_attached(ifp, 1)) {
		return (EOPNOTSUPP);
	}

	if (cmd == SIOCAIFAGENTID ||
		cmd == SIOCDIFAGENTID) {
		ifnet_lock_exclusive(ifp);
	} else {
		ifnet_lock_shared(ifp);
	}

	switch (cmd) {
		case SIOCAIFAGENTID: {		/* struct if_agentidreq */
			// TODO: Use priv_check_cred() instead of root check
			if ((error = proc_suser(p)) != 0) {
				break;
			}
			error = if_add_netagent_locked(ifp, ifar->ifar_uuid);
			break;
		}
		case SIOCDIFAGENTID: {			/* struct if_agentidreq */
			// TODO: Use priv_check_cred() instead of root check
			if ((error = proc_suser(p)) != 0) {
				break;
			}
			error = if_delete_netagent_locked(ifp, ifar->ifar_uuid);
			break;
		}
		case SIOCGIFAGENTIDS32: {	/* struct if_agentidsreq32 */
			bcopy(data, &u.s32, sizeof(u.s32));
			error = ifioctl_getnetagents(ifp, &u.s32.ifar_count,
			    u.s32.ifar_uuids);
			if (error == 0) {
				bcopy(&u.s32, data, sizeof(u.s32));
			}
			break;
		}
		case SIOCGIFAGENTIDS64: {	/* struct if_agentidsreq64 */
			bcopy(data, &u.s64, sizeof(u.s64));
			error = ifioctl_getnetagents(ifp, &u.s64.ifar_count,
			    u.s64.ifar_uuids);
			if (error == 0) {
				bcopy(&u.s64, data, sizeof(u.s64));
			}
			break;
		}
		default:
			VERIFY(0);
			/* NOTREACHED */
	}

	ifnet_lock_done(ifp);
	ifnet_decr_iorefcnt(ifp);

	return (error);
}

void
ifnet_clear_netagent(uuid_t netagent_uuid)
{
	struct ifnet *ifp = NULL;
	u_int32_t index = 0;

	ifnet_head_lock_shared();

	TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		ifnet_lock_shared(ifp);
		if (ifp->if_agentids != NULL) {
			for (index = 0; index < ifp->if_agentcount; index++) {
				uuid_t *ifp_netagent_uuid = &(ifp->if_agentids[index]);
				if (uuid_compare(*ifp_netagent_uuid, netagent_uuid) == 0) {
					uuid_clear(*ifp_netagent_uuid);
				}
			}
		}
		ifnet_lock_done(ifp);
	}

	ifnet_head_done();
}

void
ifnet_increment_generation(ifnet_t interface)
{
	OSIncrementAtomic(&interface->if_generation);
}

u_int32_t
ifnet_get_generation(ifnet_t interface)
{
	return (interface->if_generation);
}

void
ifnet_remove_from_ordered_list(struct ifnet *ifp)
{
	ifnet_head_assert_exclusive();

	// Remove from list
	TAILQ_REMOVE(&ifnet_ordered_head, ifp, if_ordered_link);
	ifp->if_ordered_link.tqe_next = NULL;
	ifp->if_ordered_link.tqe_prev = NULL;

	// Update ordered count
	VERIFY(if_ordered_count > 0);
	if_ordered_count--;
}

static int
ifnet_reset_order(u_int32_t *ordered_indices, u_int32_t count)
{
	struct ifnet *ifp = NULL;
	int error = 0;

	ifnet_head_lock_exclusive();
	for (u_int32_t order_index = 0; order_index < count; order_index++) {
		if (ordered_indices[order_index] == IFSCOPE_NONE ||
		    ordered_indices[order_index] > (uint32_t)if_index) {
			error = EINVAL;
			ifnet_head_done();
			return (error);
		}
	}
	// Flush current ordered list
	for (ifp = TAILQ_FIRST(&ifnet_ordered_head); ifp != NULL;
	    ifp = TAILQ_FIRST(&ifnet_ordered_head)) {
		ifnet_lock_exclusive(ifp);
		ifnet_remove_from_ordered_list(ifp);
		ifnet_lock_done(ifp);
	}

	VERIFY(if_ordered_count == 0);

	for (u_int32_t order_index = 0; order_index < count; order_index++) {
		u_int32_t interface_index = ordered_indices[order_index];
		ifp = ifindex2ifnet[interface_index];
		if (ifp == NULL) {
			continue;
		}
		ifnet_lock_exclusive(ifp);
		TAILQ_INSERT_TAIL(&ifnet_ordered_head, ifp, if_ordered_link);
		ifnet_lock_done(ifp);
		if_ordered_count++;
	}

	ifnet_head_done();

	necp_update_all_clients();

	return (error);
}

int
if_set_qosmarking_mode(struct ifnet *ifp, u_int32_t mode)
{
	int error = 0;
	u_int32_t old_mode = ifp->if_qosmarking_mode;

	switch (mode) {
		case IFRTYPE_QOSMARKING_MODE_NONE:
			ifp->if_qosmarking_mode = IFRTYPE_QOSMARKING_MODE_NONE;
			ifp->if_eflags &= ~IFEF_QOSMARKING_CAPABLE;
			break;
		case IFRTYPE_QOSMARKING_FASTLANE:
			ifp->if_qosmarking_mode = IFRTYPE_QOSMARKING_FASTLANE;
			ifp->if_eflags |= IFEF_QOSMARKING_CAPABLE;
			if (net_qos_policy_capable_enabled != 0)
				ifp->if_eflags |= IFEF_QOSMARKING_ENABLED;
			break;
		default:
			error = EINVAL;
			break;
	}
	if (error == 0 && old_mode != ifp->if_qosmarking_mode) {
		dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_QOS_MODE_CHANGED,
		    NULL, sizeof(struct kev_dl_rrc_state));

	}
	return (error);
}

static __attribute__((noinline)) int
ifioctl_iforder(u_long cmd, caddr_t data)
{
	int error = 0;
	u_int32_t *ordered_indices = NULL;
	if (data == NULL) {
		return (EINVAL);
	}

	switch (cmd) {
	case SIOCSIFORDER: {		/* struct if_order */
		struct if_order *ifo = (struct if_order *)(void *)data;

		if (ifo->ifo_count == 0 || ifo->ifo_count > (u_int32_t)if_index) {
			error = EINVAL;
			break;
		}

		size_t length =	(ifo->ifo_count * sizeof(u_int32_t));
		if (length > 0) {
			if (ifo->ifo_ordered_indices == USER_ADDR_NULL) {
				error = EINVAL;
				break;
			}
			ordered_indices = _MALLOC(length, M_NECP, M_WAITOK);
			if (ordered_indices == NULL) {
				error = ENOMEM;
				break;
			}

			error = copyin(ifo->ifo_ordered_indices,
			    ordered_indices, length);
			if (error != 0) {
				break;
			}
		}
		/* ordered_indices should not contain duplicates */
		bool found_duplicate = FALSE;
		for (uint32_t i = 0; i < (ifo->ifo_count - 1) && !found_duplicate ; i++){
			for (uint32_t j = i + 1; j < ifo->ifo_count && !found_duplicate ; j++){
				if (ordered_indices[j] == ordered_indices[i]){
					error = EINVAL;
					found_duplicate = TRUE;
					break;
				}
			}
		}
		if (found_duplicate)
			break;

		error = ifnet_reset_order(ordered_indices, ifo->ifo_count);

		break;
	}

	case SIOCGIFORDER: {		/* struct if_order */
		struct if_order *ifo = (struct if_order *)(void *)data;
		u_int32_t ordered_count = *((volatile u_int32_t *)&if_ordered_count);

		if (ifo->ifo_count == 0 ||
			ordered_count == 0) {
			ifo->ifo_count = 0;
		} else if (ifo->ifo_ordered_indices != USER_ADDR_NULL) {
			u_int32_t count_to_copy =
			    MIN(ordered_count, ifo->ifo_count);
			size_t length =	(count_to_copy * sizeof(u_int32_t));
			struct ifnet *ifp = NULL;
			u_int32_t cursor = 0;

			ordered_indices = _MALLOC(length, M_NECP, M_WAITOK | M_ZERO);
			if (ordered_indices == NULL) {
				error = ENOMEM;
				break;
			}

			ifnet_head_lock_shared();
			TAILQ_FOREACH(ifp, &ifnet_ordered_head, if_ordered_link) {
				if (cursor >= count_to_copy ||
				    cursor >= if_ordered_count) {
					break;
				}
				ordered_indices[cursor] = ifp->if_index;
				cursor++;
			}
			ifnet_head_done();

			/* We might have parsed less than the original length
			 * because the list could have changed.
			 */
			length = cursor * sizeof(u_int32_t);
			ifo->ifo_count = cursor;
			error = copyout(ordered_indices,
			    ifo->ifo_ordered_indices, length);
		} else {
			error = EINVAL;
		}
		break;
	}

	default: {
		VERIFY(0);
		/* NOTREACHED */
	}
	}

	if (ordered_indices != NULL) {
		_FREE(ordered_indices, M_NECP);
	}

	return (error);
}

static __attribute__((noinline)) int
ifioctl_netsignature(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct if_nsreq *ifnsr = (struct if_nsreq *)(void *)data;
	u_int16_t flags;
	int error = 0;

	VERIFY(ifp != NULL);

	switch (cmd) {
	case SIOCSIFNETSIGNATURE:		/* struct if_nsreq */
		if (ifnsr->ifnsr_len > sizeof (ifnsr->ifnsr_data)) {
			error = EINVAL;
			break;
		}
		bcopy(&ifnsr->ifnsr_flags, &flags, sizeof (flags));
		error = ifnet_set_netsignature(ifp, ifnsr->ifnsr_family,
		    ifnsr->ifnsr_len, flags, ifnsr->ifnsr_data);
		break;

	case SIOCGIFNETSIGNATURE:		/* struct if_nsreq */
		ifnsr->ifnsr_len = sizeof (ifnsr->ifnsr_data);
		error = ifnet_get_netsignature(ifp, ifnsr->ifnsr_family,
		    &ifnsr->ifnsr_len, &flags, ifnsr->ifnsr_data);
		if (error == 0)
			bcopy(&flags, &ifnsr->ifnsr_flags, sizeof (flags));
		else
			ifnsr->ifnsr_len = 0;
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

#if INET6
static __attribute__((noinline)) int
ifioctl_nat64prefix(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct if_nat64req *ifnat64 = (struct if_nat64req *)(void *)data;
	int error = 0;

	VERIFY(ifp != NULL);

	switch (cmd) {
	case SIOCSIFNAT64PREFIX:		/* struct if_nat64req */
		error = ifnet_set_nat64prefix(ifp, ifnat64->ifnat64_prefixes);
		break;

	case SIOCGIFNAT64PREFIX:		/* struct if_nat64req */
		error = ifnet_get_nat64prefix(ifp, ifnat64->ifnat64_prefixes);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}
#endif


/*
 * List the ioctl()s we can perform on restricted INTCOPROC interfaces.
 */
static bool
ifioctl_restrict_intcoproc(unsigned long cmd, const char *ifname,
    struct ifnet *ifp, struct proc *p)
{

	if (intcoproc_unrestricted == TRUE) {
		return (false);
	}
	if (proc_pid(p) == 0) {
		return (false);
	}
	if (ifname) {
		ifp = ifunit(ifname);
	}
	if (ifp == NULL) {
		return (false);
	}
	if (!IFNET_IS_INTCOPROC(ifp)) {
		return (false);
	}
	switch (cmd) {
	case SIOCGIFBRDADDR:
	case SIOCGIFCONF32:
	case SIOCGIFCONF64:
	case SIOCGIFFLAGS:
	case SIOCGIFEFLAGS:
	case SIOCGIFCAP:
	case SIOCGIFMAC:
	case SIOCGIFMETRIC:
	case SIOCGIFMTU:
	case SIOCGIFPHYS:
	case SIOCGIFTYPE:
	case SIOCGIFFUNCTIONALTYPE:
	case SIOCGIFPSRCADDR:
	case SIOCGIFPDSTADDR:
	case SIOCGIFGENERIC:
	case SIOCGIFDEVMTU:
	case SIOCGIFVLAN:
	case SIOCGIFBOND:
	case SIOCGIFWAKEFLAGS:
	case SIOCGIFGETRTREFCNT:
	case SIOCGIFOPPORTUNISTIC:
	case SIOCGIFLINKQUALITYMETRIC:
	case SIOCGIFLOG:
	case SIOCGIFDELEGATE:
	case SIOCGIFEXPENSIVE:
	case SIOCGIFINTERFACESTATE:
	case SIOCGIFPROBECONNECTIVITY:
	case SIOCGIFTIMESTAMPENABLED:
	case SIOCGECNMODE:
	case SIOCGQOSMARKINGMODE:
	case SIOCGQOSMARKINGENABLED:
	case SIOCGIFLOWINTERNET:
	case SIOCGIFSTATUS:
	case SIOCGIFMEDIA32:
	case SIOCGIFMEDIA64:
	case SIOCGIFDESC:
	case SIOCGIFLINKPARAMS:
	case SIOCGIFQUEUESTATS:
	case SIOCGIFTHROTTLE:
	case SIOCGIFAGENTIDS32:
	case SIOCGIFAGENTIDS64:
	case SIOCGIFNETSIGNATURE:
	case SIOCGIFINFO_IN6:
	case SIOCGIFAFLAG_IN6:
	case SIOCGNBRINFO_IN6:
	case SIOCGIFALIFETIME_IN6:
	case SIOCGIFNETMASK_IN6:
		return (false);
	default:
#if (DEBUG || DEVELOPMENT)
		printf("%s: cmd 0x%lx not allowed (pid %u)\n",
		    __func__, cmd, proc_pid(p));
#endif
		return (true);
	}
	return (false);
}

/*
 * Interface ioctls.
 *
 * Most of the routines called to handle the ioctls would end up being
 * tail-call optimized, which unfortunately causes this routine to
 * consume too much stack space; this is the reason for the "noinline"
 * attribute used on those routines.
 */
int
ifioctl(struct socket *so, u_long cmd, caddr_t data, struct proc *p)
{
	char ifname[IFNAMSIZ + 1];
	struct ifnet *ifp = NULL;
	struct ifstat *ifs = NULL;
	int error = 0;

	bzero(ifname, sizeof (ifname));

	/*
	 * ioctls which don't require ifp, or ifreq ioctls
	 */
	switch (cmd) {
	case OSIOCGIFCONF32:			/* struct ifconf32 */
	case SIOCGIFCONF32:			/* struct ifconf32 */
	case SIOCGIFCONF64:			/* struct ifconf64 */
	case OSIOCGIFCONF64:			/* struct ifconf64 */
		error = ifioctl_ifconf(cmd, data);
		goto done;

	case SIOCIFGCLONERS32:			/* struct if_clonereq32 */
	case SIOCIFGCLONERS64:			/* struct if_clonereq64 */
		error = ifioctl_ifclone(cmd, data);
		goto done;

	case SIOCGIFAGENTDATA32:		/* struct netagent_req32 */
	case SIOCGIFAGENTDATA64:		/* struct netagent_req64 */
	case SIOCGIFAGENTLIST32:                /* struct netagentlist_req32 */
	case SIOCGIFAGENTLIST64:                /* struct netagentlist_req64 */
		error = netagent_ioctl(cmd, data);
		goto done;

	case SIOCSIFORDER:			/* struct if_order */
	case SIOCGIFORDER:		/* struct if_order */
		error = ifioctl_iforder(cmd, data);
		goto done;

	case SIOCSIFDSTADDR:			/* struct ifreq */
	case SIOCSIFADDR:			/* struct ifreq */
	case SIOCSIFBRDADDR:			/* struct ifreq */
	case SIOCSIFNETMASK:			/* struct ifreq */
	case OSIOCGIFADDR:			/* struct ifreq */
	case OSIOCGIFDSTADDR:			/* struct ifreq */
	case OSIOCGIFBRDADDR:			/* struct ifreq */
	case OSIOCGIFNETMASK:			/* struct ifreq */
	case SIOCSIFKPI:			/* struct ifreq */
		if (so->so_proto == NULL) {
			error = EOPNOTSUPP;
			goto done;
		}
		/* FALLTHRU */
	case SIOCIFCREATE:			/* struct ifreq */
	case SIOCIFCREATE2:			/* struct ifreq */
	case SIOCIFDESTROY:			/* struct ifreq */
	case SIOCGIFFLAGS:			/* struct ifreq */
	case SIOCGIFEFLAGS:			/* struct ifreq */
	case SIOCGIFCAP:			/* struct ifreq */
#if CONFIG_MACF_NET
	case SIOCGIFMAC:			/* struct ifreq */
	case SIOCSIFMAC:			/* struct ifreq */
#endif /* CONFIG_MACF_NET */
	case SIOCGIFMETRIC:			/* struct ifreq */
	case SIOCGIFMTU:			/* struct ifreq */
	case SIOCGIFPHYS:			/* struct ifreq */
	case SIOCSIFFLAGS:			/* struct ifreq */
	case SIOCSIFCAP:			/* struct ifreq */
	case SIOCSIFMETRIC:			/* struct ifreq */
	case SIOCSIFPHYS:			/* struct ifreq */
	case SIOCSIFMTU:			/* struct ifreq */
	case SIOCADDMULTI:			/* struct ifreq */
	case SIOCDELMULTI:			/* struct ifreq */
	case SIOCDIFPHYADDR:			/* struct ifreq */
	case SIOCSIFMEDIA:			/* struct ifreq */
	case SIOCSIFGENERIC:			/* struct ifreq */
	case SIOCSIFLLADDR:			/* struct ifreq */
	case SIOCSIFALTMTU:			/* struct ifreq */
	case SIOCSIFVLAN:			/* struct ifreq */
	case SIOCSIFBOND:			/* struct ifreq */
	case SIOCGIFLLADDR:			/* struct ifreq */
	case SIOCGIFTYPE:			/* struct ifreq */
	case SIOCGIFFUNCTIONALTYPE:		/* struct ifreq */
	case SIOCGIFPSRCADDR:			/* struct ifreq */
	case SIOCGIFPDSTADDR:			/* struct ifreq */
	case SIOCGIFGENERIC:			/* struct ifreq */
	case SIOCGIFDEVMTU:			/* struct ifreq */
	case SIOCGIFVLAN:			/* struct ifreq */
	case SIOCGIFBOND:			/* struct ifreq */
	case SIOCGIFWAKEFLAGS:			/* struct ifreq */
	case SIOCGIFGETRTREFCNT:		/* struct ifreq */
	case SIOCSIFOPPORTUNISTIC:		/* struct ifreq */
	case SIOCGIFOPPORTUNISTIC:		/* struct ifreq */
	case SIOCGIFLINKQUALITYMETRIC:		/* struct ifreq */
	case SIOCSIFLOG:			/* struct ifreq */
	case SIOCGIFLOG:			/* struct ifreq */
	case SIOCGIFDELEGATE: 			/* struct ifreq */
	case SIOCGIFEXPENSIVE:			/* struct ifreq */
	case SIOCSIFEXPENSIVE: 			/* struct ifreq */
	case SIOCSIF2KCL:			/* struct ifreq */
	case SIOCGIF2KCL: 			/* struct ifreq */
	case SIOCSIFINTERFACESTATE:		/* struct ifreq */
	case SIOCGIFINTERFACESTATE:		/* struct ifreq */
	case SIOCSIFPROBECONNECTIVITY:		/* struct ifreq */
	case SIOCGIFPROBECONNECTIVITY:		/* struct ifreq */
	case SIOCGSTARTDELAY:			/* struct ifreq */
	case SIOCSIFTIMESTAMPENABLE:		/* struct ifreq */
	case SIOCSIFTIMESTAMPDISABLE:		/* struct ifreq */
	case SIOCGIFTIMESTAMPENABLED:		/* struct ifreq */
#if (DEBUG || DEVELOPMENT)
	case SIOCSIFDISABLEOUTPUT:		/* struct ifreq */
#endif /* (DEBUG || DEVELOPMENT) */
	case SIOCGECNMODE:			/* struct ifreq */
	case SIOCSECNMODE:
	case SIOCSQOSMARKINGMODE:		/* struct ifreq */
	case SIOCSQOSMARKINGENABLED:		/* struct ifreq */
	case SIOCGQOSMARKINGMODE:		/* struct ifreq */
	case SIOCGQOSMARKINGENABLED:		/* struct ifreq */
	case SIOCSIFLOWINTERNET:		/* struct ifreq */
	case SIOCGIFLOWINTERNET:		/* struct ifreq */
	{			/* struct ifreq */
		struct ifreq ifr;
		bcopy(data, &ifr, sizeof (ifr));
		ifr.ifr_name[IFNAMSIZ - 1] = '\0';
		bcopy(&ifr.ifr_name, ifname, IFNAMSIZ);
		if (ifioctl_restrict_intcoproc(cmd, ifname, NULL, p) == true) {
			error = EPERM;
			goto done;
		}
		error = ifioctl_ifreq(so, cmd, &ifr, p);
		bcopy(&ifr, data, sizeof (ifr));
		goto done;
	}
	}

	/*
	 * ioctls which require ifp.  Note that we acquire dlil_ifnet_lock
	 * here to ensure that the ifnet, if found, has been fully attached.
	 */
	dlil_if_lock();
	switch (cmd) {
	case SIOCSIFPHYADDR:			/* struct {if,in_}aliasreq */
		bcopy(((struct in_aliasreq *)(void *)data)->ifra_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;

#if INET6
	case SIOCSIFPHYADDR_IN6_32:		/* struct in6_aliasreq_32 */
		bcopy(((struct in6_aliasreq_32 *)(void *)data)->ifra_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;

	case SIOCSIFPHYADDR_IN6_64:		/* struct in6_aliasreq_64 */
		bcopy(((struct in6_aliasreq_64 *)(void *)data)->ifra_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;
#endif /* INET6 */

	case SIOCGIFSTATUS:			/* struct ifstat */
		ifs = _MALLOC(sizeof (*ifs), M_DEVBUF, M_WAITOK);
		if (ifs == NULL) {
			error = ENOMEM;
			dlil_if_unlock();
			goto done;
		}
		bcopy(data, ifs, sizeof (*ifs));
		ifs->ifs_name[IFNAMSIZ - 1] = '\0';
		bcopy(ifs->ifs_name, ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;

	case SIOCGIFMEDIA32:			/* struct ifmediareq32 */
		bcopy(((struct ifmediareq32 *)(void *)data)->ifm_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;

	case SIOCGIFMEDIA64:			/* struct ifmediareq64 */
		bcopy(((struct ifmediareq64 *)(void *)data)->ifm_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;

	case SIOCSIFDESC:			/* struct if_descreq */
	case SIOCGIFDESC:			/* struct if_descreq */
		bcopy(((struct if_descreq *)(void *)data)->ifdr_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;

	case SIOCSIFLINKPARAMS:			/* struct if_linkparamsreq */
	case SIOCGIFLINKPARAMS:			/* struct if_linkparamsreq */
		bcopy(((struct if_linkparamsreq *)(void *)data)->iflpr_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;

	case SIOCGIFQUEUESTATS:			/* struct if_qstatsreq */
		bcopy(((struct if_qstatsreq *)(void *)data)->ifqr_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;

	case SIOCSIFTHROTTLE:			/* struct if_throttlereq */
	case SIOCGIFTHROTTLE:			/* struct if_throttlereq */
		bcopy(((struct if_throttlereq *)(void *)data)->ifthr_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;

	case SIOCAIFAGENTID:			/* struct if_agentidreq */
	case SIOCDIFAGENTID:			/* struct if_agentidreq */
	case SIOCGIFAGENTIDS32:		/* struct if_agentidsreq32 */
	case SIOCGIFAGENTIDS64:		/* struct if_agentidsreq64 */
		bcopy(((struct if_agentidreq *)(void *)data)->ifar_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;

	case SIOCSIFNETSIGNATURE:		/* struct if_nsreq */
	case SIOCGIFNETSIGNATURE:		/* struct if_nsreq */
		bcopy(((struct if_nsreq *)(void *)data)->ifnsr_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;

	default:
		/*
		 * This is a bad assumption, but the code seems to
		 * have been doing this in the past; caveat emptor.
		 */
		bcopy(((struct ifreq *)(void *)data)->ifr_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;
	}
	dlil_if_unlock();

	if (ifp == NULL) {
		error = ENXIO;
		goto done;
	}

	if (ifioctl_restrict_intcoproc(cmd, NULL, ifp, p) == true) {
		error = EPERM;
		goto done;
	}
	switch (cmd) {
	case SIOCSIFPHYADDR:			/* struct {if,in_}aliasreq */
#if INET6
	case SIOCSIFPHYADDR_IN6_32:		/* struct in6_aliasreq_32 */
	case SIOCSIFPHYADDR_IN6_64:		/* struct in6_aliasreq_64 */
#endif /* INET6 */
		error = proc_suser(p);
		if (error != 0)
			break;

		error = ifnet_ioctl(ifp, SOCK_DOM(so), cmd, data);
		if (error != 0)
			break;

		ifnet_touch_lastchange(ifp);
		break;

	case SIOCGIFSTATUS:			/* struct ifstat */
		VERIFY(ifs != NULL);
		ifs->ascii[0] = '\0';

		error = ifnet_ioctl(ifp, SOCK_DOM(so), cmd, (caddr_t)ifs);

		bcopy(ifs, data, sizeof (*ifs));
		break;

	case SIOCGIFMEDIA32:			/* struct ifmediareq32 */
	case SIOCGIFMEDIA64:			/* struct ifmediareq64 */
		error = ifnet_ioctl(ifp, SOCK_DOM(so), cmd, data);
		break;

	case SIOCSIFDESC:			/* struct if_descreq */
	case SIOCGIFDESC:			/* struct if_descreq */
		error = ifioctl_ifdesc(ifp, cmd, data, p);
		break;

	case SIOCSIFLINKPARAMS:			/* struct if_linkparamsreq */
	case SIOCGIFLINKPARAMS:			/* struct if_linkparamsreq */
		error = ifioctl_linkparams(ifp, cmd, data, p);
		break;

	case SIOCGIFQUEUESTATS:			/* struct if_qstatsreq */
		error = ifioctl_qstats(ifp, cmd, data);
		break;

	case SIOCSIFTHROTTLE:			/* struct if_throttlereq */
	case SIOCGIFTHROTTLE:			/* struct if_throttlereq */
		error = ifioctl_throttle(ifp, cmd, data, p);
		break;

	case SIOCAIFAGENTID:			/* struct if_agentidreq */
	case SIOCDIFAGENTID:			/* struct if_agentidreq */
	case SIOCGIFAGENTIDS32:		/* struct if_agentidsreq32 */
	case SIOCGIFAGENTIDS64:		/* struct if_agentidsreq64 */
		error = ifioctl_netagent(ifp, cmd, data, p);
		break;

	case SIOCSIFNETSIGNATURE:		/* struct if_nsreq */
	case SIOCGIFNETSIGNATURE:		/* struct if_nsreq */
		error = ifioctl_netsignature(ifp, cmd, data);
		break;

#if INET6
	case SIOCSIFNAT64PREFIX:		/* struct if_nsreq */
	case SIOCGIFNAT64PREFIX:		/* struct if_nsreq */
		error = ifioctl_nat64prefix(ifp, cmd, data);
		break;
#endif
	default:
		if (so->so_proto == NULL) {
			error = EOPNOTSUPP;
			break;
		}

		socket_lock(so, 1);
		error = ((*so->so_proto->pr_usrreqs->pru_control)(so, cmd,
		    data, ifp, p));
		socket_unlock(so, 1);

		if (error == EOPNOTSUPP || error == ENOTSUP) {
			error = ifnet_ioctl(ifp, SOCK_DOM(so), cmd, data);
		}
		break;
	}

done:
	if (ifs != NULL)
		_FREE(ifs, M_DEVBUF);

	if (if_verbose) {
		if (ifname[0] == '\0')
			(void) snprintf(ifname, sizeof (ifname), "%s",
			    "NULL");
		else if (ifp != NULL)
			(void) snprintf(ifname, sizeof (ifname), "%s",
			    if_name(ifp));

		if (error != 0) {
			printf("%s[%s,%d]: ifp %s cmd 0x%08lx (%c%c [%lu] "
			    "%c %lu) error %d\n", __func__,
			    proc_name_address(p), proc_pid(p),
			    ifname, cmd, (cmd & IOC_IN) ? 'I' : ' ',
			    (cmd & IOC_OUT) ? 'O' : ' ', IOCPARM_LEN(cmd),
			    (char)IOCGROUP(cmd), cmd & 0xff, error);
		} else if (if_verbose > 1) {
			printf("%s[%s,%d]: ifp %s cmd 0x%08lx (%c%c [%lu] "
			    "%c %lu) OK\n", __func__,
			    proc_name_address(p), proc_pid(p),
			    ifname, cmd, (cmd & IOC_IN) ? 'I' : ' ',
			    (cmd & IOC_OUT) ? 'O' : ' ', IOCPARM_LEN(cmd),
			    (char)IOCGROUP(cmd), cmd & 0xff);
		}
	}

	return (error);
}

static __attribute__((noinline)) int
ifioctl_ifreq(struct socket *so, u_long cmd, struct ifreq *ifr, struct proc *p)
{
	struct ifnet *ifp;
	u_long ocmd = cmd;
	int error = 0;
	struct kev_msg ev_msg;
	struct net_event_data ev_data;

	bzero(&ev_data, sizeof (struct net_event_data));
	bzero(&ev_msg, sizeof (struct kev_msg));

	switch (cmd) {
	case SIOCIFCREATE:
	case SIOCIFCREATE2:
		error = proc_suser(p);
		if (error)
			return (error);
		return (if_clone_create(ifr->ifr_name, sizeof(ifr->ifr_name),
		    cmd == SIOCIFCREATE2 ? ifr->ifr_data : NULL));
	case SIOCIFDESTROY:
		error = proc_suser(p);
		if (error)
			return (error);
		return (if_clone_destroy(ifr->ifr_name));
	}

	/*
	 * ioctls which require ifp.  Note that we acquire dlil_ifnet_lock
	 * here to ensure that the ifnet, if found, has been fully attached.
	 */
	dlil_if_lock();
	ifp = ifunit(ifr->ifr_name);
	dlil_if_unlock();

	if (ifp == NULL)
		return (ENXIO);

	switch (cmd) {
	case SIOCGIFFLAGS:
		ifnet_lock_shared(ifp);
		ifr->ifr_flags = ifp->if_flags;
		ifnet_lock_done(ifp);
		break;

	case SIOCGIFEFLAGS:
		ifnet_lock_shared(ifp);
		ifr->ifr_eflags = ifp->if_eflags;
		ifnet_lock_done(ifp);
		break;

	case SIOCGIFCAP:
		ifnet_lock_shared(ifp);
		ifr->ifr_reqcap = ifp->if_capabilities;
		ifr->ifr_curcap = ifp->if_capenable;
		ifnet_lock_done(ifp);
		break;

#if CONFIG_MACF_NET
	case SIOCGIFMAC:
		error = mac_ifnet_label_get(kauth_cred_get(), ifr, ifp);
		break;

	case SIOCSIFMAC:
		error = mac_ifnet_label_set(kauth_cred_get(), ifr, ifp);
		break;
#endif /* CONFIG_MACF_NET */

	case SIOCGIFMETRIC:
		ifnet_lock_shared(ifp);
		ifr->ifr_metric = ifp->if_metric;
		ifnet_lock_done(ifp);
		break;

	case SIOCGIFMTU:
		ifnet_lock_shared(ifp);
		ifr->ifr_mtu = ifp->if_mtu;
		ifnet_lock_done(ifp);
		break;

	case SIOCGIFPHYS:
		ifnet_lock_shared(ifp);
		ifr->ifr_phys = ifp->if_physical;
		ifnet_lock_done(ifp);
		break;

	case SIOCSIFFLAGS:
		error = proc_suser(p);
		if (error != 0)
			break;

		(void) ifnet_set_flags(ifp, ifr->ifr_flags,
		    (u_int16_t)~IFF_CANTCHANGE);

		/*
		 * Note that we intentionally ignore any error from below
		 * for the SIOCSIFFLAGS case.
		 */
		(void) ifnet_ioctl(ifp, SOCK_DOM(so), cmd, (caddr_t)ifr);

		/*
		 * Send the event even upon error from the driver because
		 * we changed the flags.
		 */
		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass   = KEV_DL_SUBCLASS;

		ev_msg.event_code = KEV_DL_SIFFLAGS;
		strlcpy(&ev_data.if_name[0], ifp->if_name, IFNAMSIZ);
		ev_data.if_family = ifp->if_family;
		ev_data.if_unit   = (u_int32_t) ifp->if_unit;
		ev_msg.dv[0].data_length = sizeof(struct net_event_data);
		ev_msg.dv[0].data_ptr    = &ev_data;
		ev_msg.dv[1].data_length = 0;
		dlil_post_complete_msg(ifp, &ev_msg);

		ifnet_touch_lastchange(ifp);
		break;

	case SIOCSIFCAP:
		error = proc_suser(p);
		if (error != 0)
			break;

		if ((ifr->ifr_reqcap & ~ifp->if_capabilities)) {
			error = EINVAL;
			break;
		}
		error = ifnet_ioctl(ifp, SOCK_DOM(so), cmd, (caddr_t)ifr);

		ifnet_touch_lastchange(ifp);
		break;

	case SIOCSIFMETRIC:
		error = proc_suser(p);
		if (error != 0)
			break;

		ifp->if_metric = ifr->ifr_metric;

		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass   = KEV_DL_SUBCLASS;

		ev_msg.event_code = KEV_DL_SIFMETRICS;
		strlcpy(&ev_data.if_name[0], ifp->if_name, IFNAMSIZ);
		ev_data.if_family = ifp->if_family;
		ev_data.if_unit   = (u_int32_t) ifp->if_unit;
		ev_msg.dv[0].data_length = sizeof(struct net_event_data);
		ev_msg.dv[0].data_ptr    = &ev_data;

		ev_msg.dv[1].data_length = 0;
		dlil_post_complete_msg(ifp, &ev_msg);

		ifnet_touch_lastchange(ifp);
		break;

	case SIOCSIFPHYS:
		error = proc_suser(p);
		if (error != 0)
			break;

		error = ifnet_ioctl(ifp, SOCK_DOM(so), cmd, (caddr_t)ifr);
		if (error != 0)
			break;

		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass   = KEV_DL_SUBCLASS;

		ev_msg.event_code = KEV_DL_SIFPHYS;
		strlcpy(&ev_data.if_name[0], ifp->if_name, IFNAMSIZ);
		ev_data.if_family = ifp->if_family;
		ev_data.if_unit   = (u_int32_t) ifp->if_unit;
		ev_msg.dv[0].data_length = sizeof(struct net_event_data);
		ev_msg.dv[0].data_ptr    = &ev_data;
		ev_msg.dv[1].data_length = 0;
		dlil_post_complete_msg(ifp, &ev_msg);

		ifnet_touch_lastchange(ifp);
		break;

	case SIOCSIFMTU: {
		u_int32_t oldmtu = ifp->if_mtu;
		struct ifclassq *ifq = &ifp->if_snd;

		error = proc_suser(p);
		if (error != 0)
			break;

		if (ifp->if_ioctl == NULL) {
			error = EOPNOTSUPP;
			break;
		}
		if (ifr->ifr_mtu < IF_MINMTU || ifr->ifr_mtu > IF_MAXMTU) {
			error = EINVAL;
			break;
		}
		error = ifnet_ioctl(ifp, SOCK_DOM(so), cmd, (caddr_t)ifr);
		if (error != 0)
			break;

		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass   = KEV_DL_SUBCLASS;

		ev_msg.event_code = KEV_DL_SIFMTU;
		strlcpy(&ev_data.if_name[0], ifp->if_name, IFNAMSIZ);
		ev_data.if_family = ifp->if_family;
		ev_data.if_unit   = (u_int32_t) ifp->if_unit;
		ev_msg.dv[0].data_length = sizeof(struct net_event_data);
		ev_msg.dv[0].data_ptr    = &ev_data;
		ev_msg.dv[1].data_length = 0;
		dlil_post_complete_msg(ifp, &ev_msg);

		ifnet_touch_lastchange(ifp);
		rt_ifmsg(ifp);

		/*
		 * If the link MTU changed, do network layer specific procedure
		 * and update all route entries associated with the interface,
		 * so that their MTU metric gets updated.
		 */
		if (ifp->if_mtu != oldmtu) {
			if_rtmtu_update(ifp);
#if INET6
			nd6_setmtu(ifp);
#endif /* INET6 */
			/* Inform all transmit queues about the new MTU */
			IFCQ_LOCK(ifq);
			ifnet_update_sndq(ifq, CLASSQ_EV_LINK_MTU);
			IFCQ_UNLOCK(ifq);
		}
		break;
	}

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		error = proc_suser(p);
		if (error != 0)
			break;

		/* Don't allow group membership on non-multicast interfaces. */
		if ((ifp->if_flags & IFF_MULTICAST) == 0) {
			error = EOPNOTSUPP;
			break;
		}

		/* Don't let users screw up protocols' entries. */
		if (ifr->ifr_addr.sa_family != AF_UNSPEC &&
		    ifr->ifr_addr.sa_family != AF_LINK) {
			error = EINVAL;
			break;
		}

		/*
		 * User is permitted to anonymously join a particular link
		 * multicast group via SIOCADDMULTI.  Subsequent join requested
		 * for the same record which has an outstanding refcnt from a
		 * past if_addmulti_anon() will not result in EADDRINUSE error
		 * (unlike other BSDs.)  Anonymously leaving a group is also
		 * allowed only as long as there is an outstanding refcnt held
		 * by a previous anonymous request, or else ENOENT (even if the
		 * link-layer multicast membership exists for a network-layer
		 * membership.)
		 */
		if (cmd == SIOCADDMULTI) {
			error = if_addmulti_anon(ifp, &ifr->ifr_addr, NULL);
			ev_msg.event_code = KEV_DL_ADDMULTI;
		} else {
			error = if_delmulti_anon(ifp, &ifr->ifr_addr);
			ev_msg.event_code = KEV_DL_DELMULTI;
		}
		if (error != 0)
			break;

		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass   = KEV_DL_SUBCLASS;
		strlcpy(&ev_data.if_name[0], ifp->if_name, IFNAMSIZ);

		ev_data.if_family = ifp->if_family;
		ev_data.if_unit   = (u_int32_t) ifp->if_unit;
		ev_msg.dv[0].data_length = sizeof(struct net_event_data);
		ev_msg.dv[0].data_ptr    = &ev_data;
		ev_msg.dv[1].data_length = 0;
		dlil_post_complete_msg(ifp, &ev_msg);

		ifnet_touch_lastchange(ifp);
		break;

	case SIOCDIFPHYADDR:
	case SIOCSIFMEDIA:
	case SIOCSIFGENERIC:
	case SIOCSIFLLADDR:
	case SIOCSIFALTMTU:
	case SIOCSIFVLAN:
	case SIOCSIFBOND:
		error = proc_suser(p);
		if (error != 0)
			break;

		error = ifnet_ioctl(ifp, SOCK_DOM(so), cmd, (caddr_t)ifr);
		if (error != 0)
			break;

		ifnet_touch_lastchange(ifp);
		break;

	case SIOCGIFLLADDR: {
		struct sockaddr_dl *sdl = SDL(ifp->if_lladdr->ifa_addr);

		if (sdl->sdl_alen == 0) {
			error = EADDRNOTAVAIL;
			break;
		}
		/* If larger than 14-bytes we'll need another mechanism */
		if (sdl->sdl_alen > sizeof (ifr->ifr_addr.sa_data)) {
			error = EMSGSIZE;
			break;
		}
		/* Follow the same convention used by SIOCSIFLLADDR */
		bzero(&ifr->ifr_addr, sizeof (ifr->ifr_addr));
		ifr->ifr_addr.sa_family = AF_LINK;
		ifr->ifr_addr.sa_len = sdl->sdl_alen;
		error = ifnet_guarded_lladdr_copy_bytes(ifp,
		    &ifr->ifr_addr.sa_data, sdl->sdl_alen);
		break;
	}

	case SIOCGIFTYPE:
		ifr->ifr_type.ift_type = ifp->if_type;
		ifr->ifr_type.ift_family = ifp->if_family;
		ifr->ifr_type.ift_subfamily = ifp->if_subfamily;
		break;

	case SIOCGIFFUNCTIONALTYPE:
		ifr->ifr_functional_type = if_functional_type(ifp, FALSE);
		break;

	case SIOCGIFPSRCADDR:
	case SIOCGIFPDSTADDR:
	case SIOCGIFGENERIC:
	case SIOCGIFDEVMTU:
	case SIOCGIFVLAN:
	case SIOCGIFBOND:
		error = ifnet_ioctl(ifp, SOCK_DOM(so), cmd, (caddr_t)ifr);
		break;

	case SIOCGIFWAKEFLAGS:
		ifnet_lock_shared(ifp);
		ifr->ifr_wake_flags = ifnet_get_wake_flags(ifp);
		ifnet_lock_done(ifp);
		break;

	case SIOCGIFGETRTREFCNT:
		ifnet_lock_shared(ifp);
		ifr->ifr_route_refcnt = ifp->if_route_refcnt;
		ifnet_lock_done(ifp);
		break;

	case SIOCSIFOPPORTUNISTIC:
	case SIOCGIFOPPORTUNISTIC:
		error = ifnet_getset_opportunistic(ifp, cmd, ifr, p);
		break;

	case SIOCGIFLINKQUALITYMETRIC:
		ifnet_lock_shared(ifp);
		if ((ifp->if_interface_state.valid_bitmask &
		    IF_INTERFACE_STATE_LQM_STATE_VALID)) {
			ifr->ifr_link_quality_metric =
			    ifp->if_interface_state.lqm_state;
		} else if (IF_FULLY_ATTACHED(ifp)) {
			ifr->ifr_link_quality_metric =
			    IFNET_LQM_THRESH_UNKNOWN;
		} else {
			ifr->ifr_link_quality_metric =
			    IFNET_LQM_THRESH_OFF;
		}
		ifnet_lock_done(ifp);
		break;

	case SIOCSIFLOG:
	case SIOCGIFLOG:
		error = ifnet_getset_log(ifp, cmd, ifr, p);
		break;

	case SIOCGIFDELEGATE:
		ifnet_lock_shared(ifp);
		ifr->ifr_delegated = ((ifp->if_delegated.ifp != NULL) ?
		    ifp->if_delegated.ifp->if_index : 0);
		ifnet_lock_done(ifp);
		break;

	case SIOCGIFEXPENSIVE:
		ifnet_lock_shared(ifp);
		if (ifp->if_eflags & IFEF_EXPENSIVE)
			ifr->ifr_expensive = 1;
		else
			ifr->ifr_expensive = 0;
		ifnet_lock_done(ifp);
		break;

	case SIOCSIFEXPENSIVE:
	{
		struct ifnet *difp;

		if ((error = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_INTERFACE_CONTROL, 0)) != 0)
			return (error);
		ifnet_lock_exclusive(ifp);
		if (ifr->ifr_expensive)
			ifp->if_eflags |= IFEF_EXPENSIVE;
		else
			ifp->if_eflags &= ~IFEF_EXPENSIVE;
		ifnet_lock_done(ifp);
		/*
		 * Update the expensive bit in the delegated interface
		 * structure.
		 */
		ifnet_head_lock_shared();
		TAILQ_FOREACH(difp, &ifnet_head, if_link) {
			ifnet_lock_exclusive(difp);
			if (difp->if_delegated.ifp == ifp) {
				difp->if_delegated.expensive =
				    ifp->if_eflags & IFEF_EXPENSIVE ? 1 : 0;

			}
			ifnet_lock_done(difp);
		}
		ifnet_head_done();
		break;
	}

	case SIOCGIF2KCL:
		ifnet_lock_shared(ifp);
		if (ifp->if_eflags & IFEF_2KCL)
			ifr->ifr_2kcl = 1;
		else
			ifr->ifr_2kcl = 0;
		ifnet_lock_done(ifp);
		break;

	case SIOCSIF2KCL:
		if ((error = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_INTERFACE_CONTROL, 0)) != 0)
			return (error);
		ifnet_lock_exclusive(ifp);
		if (ifr->ifr_2kcl)
			ifp->if_eflags |= IFEF_2KCL;
		else
			ifp->if_eflags &= ~IFEF_2KCL;
		ifnet_lock_done(ifp);
		break;
	case SIOCGSTARTDELAY:
		ifnet_lock_shared(ifp);
		if (ifp->if_eflags & IFEF_ENQUEUE_MULTI) {
			ifr->ifr_start_delay_qlen =
			    ifp->if_start_delay_qlen;
			ifr->ifr_start_delay_timeout =
			    ifp->if_start_delay_timeout;
		} else {
			ifr->ifr_start_delay_qlen = 0;
			ifr->ifr_start_delay_timeout = 0;
		}
		ifnet_lock_done(ifp);
		break;
	case SIOCSIFDSTADDR:
	case SIOCSIFADDR:
	case SIOCSIFBRDADDR:
	case SIOCSIFNETMASK:
	case OSIOCGIFADDR:
	case OSIOCGIFDSTADDR:
	case OSIOCGIFBRDADDR:
	case OSIOCGIFNETMASK:
	case SIOCSIFKPI:
		VERIFY(so->so_proto != NULL);

		if (cmd == SIOCSIFDSTADDR || cmd == SIOCSIFADDR ||
		    cmd == SIOCSIFBRDADDR || cmd == SIOCSIFNETMASK) {
#if BYTE_ORDER != BIG_ENDIAN
			if (ifr->ifr_addr.sa_family == 0 &&
			    ifr->ifr_addr.sa_len < 16) {
				ifr->ifr_addr.sa_family = ifr->ifr_addr.sa_len;
				ifr->ifr_addr.sa_len = 16;
			}
#else
			if (ifr->ifr_addr.sa_len == 0)
				ifr->ifr_addr.sa_len = 16;
#endif
		} else if (cmd == OSIOCGIFADDR) {
			cmd = SIOCGIFADDR;	/* struct ifreq */
		} else if (cmd == OSIOCGIFDSTADDR) {
			cmd = SIOCGIFDSTADDR;	/* struct ifreq */
		} else if (cmd == OSIOCGIFBRDADDR) {
			cmd = SIOCGIFBRDADDR;	/* struct ifreq */
		} else if (cmd == OSIOCGIFNETMASK) {
			cmd = SIOCGIFNETMASK;	/* struct ifreq */
		}

		socket_lock(so, 1);
		error = ((*so->so_proto->pr_usrreqs->pru_control)(so, cmd,
		    (caddr_t)ifr, ifp, p));
		socket_unlock(so, 1);

		switch (ocmd) {
		case OSIOCGIFADDR:
		case OSIOCGIFDSTADDR:
		case OSIOCGIFBRDADDR:
		case OSIOCGIFNETMASK:
			bcopy(&ifr->ifr_addr.sa_family, &ifr->ifr_addr,
			    sizeof (u_short));
		}

		if (cmd == SIOCSIFKPI) {
			int temperr = proc_suser(p);
			if (temperr != 0)
				error = temperr;
		}

		if (error == EOPNOTSUPP || error == ENOTSUP) {
			error = ifnet_ioctl(ifp, SOCK_DOM(so), cmd,
			    (caddr_t)ifr);
		}
		break;

	case SIOCGIFINTERFACESTATE:
		if_get_state(ifp, &ifr->ifr_interface_state);

		break;
	case SIOCSIFINTERFACESTATE:
		if ((error = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_INTERFACE_CONTROL, 0)) != 0)
			return (error);

		error = if_state_update(ifp, &ifr->ifr_interface_state);

		break;
	case SIOCSIFPROBECONNECTIVITY:
		if ((error = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_INTERFACE_CONTROL, 0)) != 0)
			return (error);
		error = if_probe_connectivity(ifp,
		    ifr->ifr_probe_connectivity);
		break;
	case SIOCGIFPROBECONNECTIVITY:
		if ((error = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_INTERFACE_CONTROL, 0)) != 0)
			return (error);
		if (ifp->if_eflags & IFEF_PROBE_CONNECTIVITY)
			ifr->ifr_probe_connectivity = 1;
		else
			ifr->ifr_probe_connectivity = 0;
		break;
	case SIOCGECNMODE:
		if ((ifp->if_eflags & (IFEF_ECN_ENABLE|IFEF_ECN_DISABLE)) ==
		    IFEF_ECN_ENABLE)
			ifr->ifr_ecn_mode = IFRTYPE_ECN_ENABLE;
		else if ((ifp->if_eflags & (IFEF_ECN_ENABLE|IFEF_ECN_DISABLE)) ==
		    IFEF_ECN_DISABLE)
			ifr->ifr_ecn_mode = IFRTYPE_ECN_DISABLE;
		else
			ifr->ifr_ecn_mode = IFRTYPE_ECN_DEFAULT;
		break;
	case SIOCSECNMODE:
		if ((error = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_INTERFACE_CONTROL, 0)) != 0)
			return (error);
		if (ifr->ifr_ecn_mode == IFRTYPE_ECN_DEFAULT) {
			ifp->if_eflags &= ~(IFEF_ECN_ENABLE|IFEF_ECN_DISABLE);
		} else if (ifr->ifr_ecn_mode == IFRTYPE_ECN_ENABLE) {
			ifp->if_eflags |= IFEF_ECN_ENABLE;
			ifp->if_eflags &= ~IFEF_ECN_DISABLE;
		} else if (ifr->ifr_ecn_mode == IFRTYPE_ECN_DISABLE) {
			ifp->if_eflags |= IFEF_ECN_DISABLE;
			ifp->if_eflags &= ~IFEF_ECN_ENABLE;
		} else
			error = EINVAL;
		break;
	case SIOCSIFTIMESTAMPENABLE:
	case SIOCSIFTIMESTAMPDISABLE:
		error = proc_suser(p);
		if (error != 0)
			break;

		ifnet_lock_exclusive(ifp);
		if ((cmd == SIOCSIFTIMESTAMPENABLE &&
		    (ifp->if_xflags & IFXF_TIMESTAMP_ENABLED) != 0) ||
		    (cmd == SIOCSIFTIMESTAMPDISABLE &&
		    (ifp->if_xflags & IFXF_TIMESTAMP_ENABLED) == 0)) {
			ifnet_lock_done(ifp);
			break;
		}
		if (cmd == SIOCSIFTIMESTAMPENABLE)
			ifp->if_xflags |= IFXF_TIMESTAMP_ENABLED;
		else
			ifp->if_xflags &= ~IFXF_TIMESTAMP_ENABLED;
		ifnet_lock_done(ifp);
		/*
		 * Pass the setting to the interface if it supports either
		 * software or hardware time stamping
		 */
		if (ifp->if_capabilities & (IFCAP_HW_TIMESTAMP |
		    IFCAP_SW_TIMESTAMP)) {
			error = ifnet_ioctl(ifp, SOCK_DOM(so), cmd,
			    (caddr_t)ifr);
		}
		break;
	case SIOCGIFTIMESTAMPENABLED: {
		if ((ifp->if_xflags & IFXF_TIMESTAMP_ENABLED) != 0)
			ifr->ifr_intval = 1;
		else
			ifr->ifr_intval = 0;
		break;
	}
	case SIOCSQOSMARKINGMODE:
		if ((error = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_INTERFACE_CONTROL, 0)) != 0)
			return (error);
		error = if_set_qosmarking_mode(ifp, ifr->ifr_qosmarking_mode);
		break;

	case SIOCGQOSMARKINGMODE:
		ifr->ifr_qosmarking_mode = ifp->if_qosmarking_mode;
		break;

	case SIOCSQOSMARKINGENABLED:
		if ((error = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_INTERFACE_CONTROL, 0)) != 0)
			return (error);
		if (ifr->ifr_qosmarking_enabled != 0)
			ifp->if_eflags |= IFEF_QOSMARKING_ENABLED;
		else
			ifp->if_eflags &= ~IFEF_QOSMARKING_ENABLED;
		break;

	case SIOCGQOSMARKINGENABLED:
		ifr->ifr_qosmarking_enabled =
			(ifp->if_eflags & IFEF_QOSMARKING_ENABLED) ? 1 : 0;
		break;

	case SIOCSIFDISABLEOUTPUT:
#if (DEBUG || DEVELOPMENT)
		if (ifr->ifr_disable_output == 1) {
			error = ifnet_disable_output(ifp);
		} else if (ifr->ifr_disable_output == 0) {
			error = ifnet_enable_output(ifp);
		} else {
			error = EINVAL;
		}
#else
		error = EINVAL;
#endif /* (DEBUG || DEVELOPMENT) */
		break;
	case SIOCSIFLOWINTERNET:
		if ((error = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_INTERFACE_CONTROL, 0)) != 0)
			return (error);

		ifnet_lock_exclusive(ifp);
		if (ifr->ifr_low_internet & IFRTYPE_LOW_INTERNET_ENABLE_UL)
			ifp->if_xflags |= IFXF_LOW_INTERNET_UL;
		else
			ifp->if_xflags &= ~(IFXF_LOW_INTERNET_UL);
		if (ifr->ifr_low_internet & IFRTYPE_LOW_INTERNET_ENABLE_DL)
			ifp->if_xflags |= IFXF_LOW_INTERNET_DL;
		else
			ifp->if_xflags &= ~(IFXF_LOW_INTERNET_DL);
		ifnet_lock_done(ifp);
		break;
	case SIOCGIFLOWINTERNET:
		ifnet_lock_shared(ifp);
		ifr->ifr_low_internet = 0;
		if (ifp->if_xflags & IFXF_LOW_INTERNET_UL)
			ifr->ifr_low_internet |=
			    IFRTYPE_LOW_INTERNET_ENABLE_UL;
		if (ifp->if_xflags & IFXF_LOW_INTERNET_DL)
			ifr->ifr_low_internet |=
			    IFRTYPE_LOW_INTERNET_ENABLE_DL;
		ifnet_lock_done(ifp);
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

int
ifioctllocked(struct socket *so, u_long cmd, caddr_t data, struct proc *p)
{
	int error;

	socket_unlock(so, 0);
	error = ifioctl(so, cmd, data, p);
	socket_lock(so, 0);
	return (error);
}

/*
 * Set/clear promiscuous mode on interface ifp based on the truth value
 * of pswitch.  The calls are reference counted so that only the first
 * "on" request actually has an effect, as does the final "off" request.
 * Results are undefined if the "off" and "on" requests are not matched.
 */
errno_t
ifnet_set_promiscuous(
	ifnet_t	ifp,
	int pswitch)
{
	int error = 0;
	int oldflags = 0;
	int newflags = 0;

	ifnet_lock_exclusive(ifp);
	oldflags = ifp->if_flags;
	ifp->if_pcount += pswitch ? 1 : -1;

	if (ifp->if_pcount > 0)
		ifp->if_flags |= IFF_PROMISC;
	else
		ifp->if_flags &= ~IFF_PROMISC;

	newflags = ifp->if_flags;
	ifnet_lock_done(ifp);

	if (newflags != oldflags && (newflags & IFF_UP) != 0) {
		error = ifnet_ioctl(ifp, 0, SIOCSIFFLAGS, NULL);
		if (error == 0) {
			rt_ifmsg(ifp);
		} else {
			ifnet_lock_exclusive(ifp);
			// revert the flags
			ifp->if_pcount -= pswitch ? 1 : -1;
			if (ifp->if_pcount > 0)
			    ifp->if_flags |= IFF_PROMISC;
			else
			    ifp->if_flags &= ~IFF_PROMISC;
			ifnet_lock_done(ifp);
		}
	}

	if (newflags != oldflags) {
		log(LOG_INFO, "%s: promiscuous mode %s%s\n",
		    if_name(ifp),
		    (newflags & IFF_PROMISC) != 0 ? "enable" : "disable",
		    error != 0 ? " failed" : " succeeded");
	}
	return (error);
}

/*
 * Return interface configuration
 * of system.  List may be used
 * in later ioctl's (above) to get
 * other information.
 */
/*ARGSUSED*/
static int
ifconf(u_long cmd, user_addr_t ifrp, int *ret_space)
{
	struct ifnet *ifp = NULL;
	struct ifaddr *ifa;
	struct ifreq ifr;
	int error = 0;
	size_t space;
	net_thread_marks_t marks;

	marks = net_thread_marks_push(NET_THREAD_CKREQ_LLADDR);

	/*
	 * Zero the ifr buffer to make sure we don't
	 * disclose the contents of the stack.
	 */
	bzero(&ifr, sizeof (struct ifreq));

	space = *ret_space;
	ifnet_head_lock_shared();
	for (ifp = ifnet_head.tqh_first; space > sizeof (ifr) &&
	    ifp; ifp = ifp->if_link.tqe_next) {
		char workbuf[64];
		size_t ifnlen, addrs;

		ifnlen = snprintf(workbuf, sizeof (workbuf),
		    "%s", if_name(ifp));
		if (ifnlen + 1 > sizeof (ifr.ifr_name)) {
			error = ENAMETOOLONG;
			break;
		} else {
			strlcpy(ifr.ifr_name, workbuf, IFNAMSIZ);
		}

		ifnet_lock_shared(ifp);

		addrs = 0;
		ifa = ifp->if_addrhead.tqh_first;
		for (; space > sizeof (ifr) && ifa;
		    ifa = ifa->ifa_link.tqe_next) {
			struct sockaddr *sa;
			union {
				struct sockaddr sa;
				struct sockaddr_dl sdl;
				uint8_t buf[SOCK_MAXADDRLEN + 1];
			} u;

			/*
			 * Make sure to accomodate the largest possible
			 * size of SA(if_lladdr)->sa_len.
			 */
			_CASSERT(sizeof (u) == (SOCK_MAXADDRLEN + 1));

			IFA_LOCK(ifa);
			sa = ifa->ifa_addr;
			addrs++;

			if (ifa == ifp->if_lladdr) {
				VERIFY(sa->sa_family == AF_LINK);
				bcopy(sa, &u, sa->sa_len);
				IFA_UNLOCK(ifa);
				ifnet_guarded_lladdr_copy_bytes(ifp,
				    LLADDR(&u.sdl), u.sdl.sdl_alen);
				IFA_LOCK(ifa);
				sa = &u.sa;
			}

			if (cmd == OSIOCGIFCONF32 || cmd == OSIOCGIFCONF64) {
				struct osockaddr *osa =
				    (struct osockaddr *)(void *)&ifr.ifr_addr;
				ifr.ifr_addr = *sa;
				osa->sa_family = sa->sa_family;
				error = copyout((caddr_t)&ifr, ifrp,
				    sizeof (ifr));
				ifrp += sizeof (struct ifreq);
			} else if (sa->sa_len <= sizeof (*sa)) {
				ifr.ifr_addr = *sa;
				error = copyout((caddr_t)&ifr, ifrp,
				    sizeof (ifr));
				ifrp += sizeof (struct ifreq);
			} else {
				if (space <
				    sizeof (ifr) + sa->sa_len - sizeof (*sa)) {
					IFA_UNLOCK(ifa);
					break;
				}
				space -= sa->sa_len - sizeof (*sa);
				error = copyout((caddr_t)&ifr, ifrp,
				    sizeof (ifr.ifr_name));
				if (error == 0) {
					error = copyout((caddr_t)sa, (ifrp +
					    offsetof(struct ifreq, ifr_addr)),
					    sa->sa_len);
				}
				ifrp += (sa->sa_len + offsetof(struct ifreq,
				    ifr_addr));
			}
			IFA_UNLOCK(ifa);
			if (error)
				break;
			space -= sizeof (ifr);
		}
		ifnet_lock_done(ifp);

		if (error)
			break;
		if (!addrs) {
			bzero((caddr_t)&ifr.ifr_addr, sizeof (ifr.ifr_addr));
			error = copyout((caddr_t)&ifr, ifrp, sizeof (ifr));
			if (error)
				break;
			space -= sizeof (ifr);
			ifrp += sizeof (struct ifreq);
		}
	}
	ifnet_head_done();
	*ret_space -= space;
	net_thread_marks_pop(marks);
	return (error);
}

/*
 * Just like if_promisc(), but for all-multicast-reception mode.
 */
int
if_allmulti(struct ifnet *ifp, int onswitch)
{
	int error = 0;
	int	modified = 0;

	ifnet_lock_exclusive(ifp);

	if (onswitch) {
		if (ifp->if_amcount++ == 0) {
			ifp->if_flags |= IFF_ALLMULTI;
			modified = 1;
		}
	} else {
		if (ifp->if_amcount > 1) {
			ifp->if_amcount--;
		} else {
			ifp->if_amcount = 0;
			ifp->if_flags &= ~IFF_ALLMULTI;
			modified = 1;
		}
	}
	ifnet_lock_done(ifp);

	if (modified)
		error = ifnet_ioctl(ifp, 0, SIOCSIFFLAGS, NULL);

	if (error == 0)
		rt_ifmsg(ifp);
	return (error);
}

static struct ifmultiaddr *
ifma_alloc(int how)
{
	struct ifmultiaddr *ifma;

	ifma = (how == M_WAITOK) ? zalloc(ifma_zone) :
	    zalloc_noblock(ifma_zone);

	if (ifma != NULL) {
		bzero(ifma, ifma_size);
		lck_mtx_init(&ifma->ifma_lock, ifa_mtx_grp, ifa_mtx_attr);
		ifma->ifma_debug |= IFD_ALLOC;
		if (ifma_debug != 0) {
			ifma->ifma_debug |= IFD_DEBUG;
			ifma->ifma_trace = ifma_trace;
		}
	}
	return (ifma);
}

static void
ifma_free(struct ifmultiaddr *ifma)
{
	IFMA_LOCK(ifma);

	if (ifma->ifma_protospec != NULL) {
		panic("%s: Protospec not NULL for ifma=%p", __func__, ifma);
		/* NOTREACHED */
	} else if ((ifma->ifma_flags & IFMAF_ANONYMOUS) ||
	    ifma->ifma_anoncnt != 0) {
		panic("%s: Freeing ifma=%p with outstanding anon req",
		    __func__, ifma);
		/* NOTREACHED */
	} else if (ifma->ifma_debug & IFD_ATTACHED) {
		panic("%s: ifma=%p attached to ifma_ifp=%p is being freed",
		    __func__, ifma, ifma->ifma_ifp);
		/* NOTREACHED */
	} else if (!(ifma->ifma_debug & IFD_ALLOC)) {
		panic("%s: ifma %p cannot be freed", __func__, ifma);
		/* NOTREACHED */
	} else if (ifma->ifma_refcount != 0) {
		panic("%s: non-zero refcount ifma=%p", __func__, ifma);
		/* NOTREACHED */
	} else if (ifma->ifma_reqcnt != 0) {
		panic("%s: non-zero reqcnt ifma=%p", __func__, ifma);
		/* NOTREACHED */
	} else if (ifma->ifma_ifp != NULL) {
		panic("%s: non-NULL ifma_ifp=%p for ifma=%p", __func__,
		    ifma->ifma_ifp, ifma);
		/* NOTREACHED */
	} else if (ifma->ifma_ll != NULL) {
		panic("%s: non-NULL ifma_ll=%p for ifma=%p", __func__,
		    ifma->ifma_ll, ifma);
		/* NOTREACHED */
	}
	ifma->ifma_debug &= ~IFD_ALLOC;
	if ((ifma->ifma_debug & (IFD_DEBUG | IFD_TRASHED)) ==
	    (IFD_DEBUG | IFD_TRASHED)) {
		lck_mtx_lock(&ifma_trash_lock);
		TAILQ_REMOVE(&ifma_trash_head, (struct ifmultiaddr_dbg *)ifma,
		    ifma_trash_link);
		lck_mtx_unlock(&ifma_trash_lock);
		ifma->ifma_debug &= ~IFD_TRASHED;
	}
	IFMA_UNLOCK(ifma);

	if (ifma->ifma_addr != NULL) {
		FREE(ifma->ifma_addr, M_IFADDR);
		ifma->ifma_addr = NULL;
	}
	lck_mtx_destroy(&ifma->ifma_lock, ifa_mtx_grp);
	zfree(ifma_zone, ifma);
}

static void
ifma_trace(struct ifmultiaddr *ifma, int refhold)
{
	struct ifmultiaddr_dbg *ifma_dbg = (struct ifmultiaddr_dbg *)ifma;
	ctrace_t *tr;
	u_int32_t idx;
	u_int16_t *cnt;

	if (!(ifma->ifma_debug & IFD_DEBUG)) {
		panic("%s: ifma %p has no debug structure", __func__, ifma);
		/* NOTREACHED */
	}
	if (refhold) {
		cnt = &ifma_dbg->ifma_refhold_cnt;
		tr = ifma_dbg->ifma_refhold;
	} else {
		cnt = &ifma_dbg->ifma_refrele_cnt;
		tr = ifma_dbg->ifma_refrele;
	}

	idx = atomic_add_16_ov(cnt, 1) % IFMA_TRACE_HIST_SIZE;
	ctrace_record(&tr[idx]);
}

void
ifma_addref(struct ifmultiaddr *ifma, int locked)
{
	if (!locked)
		IFMA_LOCK(ifma);
	else
		IFMA_LOCK_ASSERT_HELD(ifma);

	if (++ifma->ifma_refcount == 0) {
		panic("%s: ifma=%p wraparound refcnt", __func__, ifma);
		/* NOTREACHED */
	} else if (ifma->ifma_trace != NULL) {
		(*ifma->ifma_trace)(ifma, TRUE);
	}
	if (!locked)
		IFMA_UNLOCK(ifma);
}

void
ifma_remref(struct ifmultiaddr *ifma)
{
	struct ifmultiaddr *ll;

	IFMA_LOCK(ifma);

	if (ifma->ifma_refcount == 0) {
		panic("%s: ifma=%p negative refcnt", __func__, ifma);
		/* NOTREACHED */
	} else if (ifma->ifma_trace != NULL) {
		(*ifma->ifma_trace)(ifma, FALSE);
	}

	--ifma->ifma_refcount;
	if (ifma->ifma_refcount > 0) {
		IFMA_UNLOCK(ifma);
		return;
	}

	ll = ifma->ifma_ll;
	ifma->ifma_ifp = NULL;
	ifma->ifma_ll = NULL;
	IFMA_UNLOCK(ifma);
	ifma_free(ifma);	/* deallocate it */

	if (ll != NULL)
		IFMA_REMREF(ll);
}

static void
if_attach_ifma(struct ifnet *ifp, struct ifmultiaddr *ifma, int anon)
{
	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_EXCLUSIVE);
	IFMA_LOCK_ASSERT_HELD(ifma);

	if (ifma->ifma_ifp != ifp) {
		panic("%s: Mismatch ifma_ifp=%p != ifp=%p", __func__,
		    ifma->ifma_ifp, ifp);
		/* NOTREACHED */
	} else if (ifma->ifma_debug & IFD_ATTACHED) {
		panic("%s: Attempt to attach an already attached ifma=%p",
		    __func__, ifma);
		/* NOTREACHED */
	} else if (anon && (ifma->ifma_flags & IFMAF_ANONYMOUS)) {
		panic("%s: ifma=%p unexpected IFMAF_ANONYMOUS", __func__, ifma);
		/* NOTREACHED */
	} else if (ifma->ifma_debug & IFD_TRASHED) {
		panic("%s: Attempt to reattach a detached ifma=%p",
		    __func__, ifma);
		/* NOTREACHED */
	}

	ifma->ifma_reqcnt++;
	VERIFY(ifma->ifma_reqcnt == 1);
	IFMA_ADDREF_LOCKED(ifma);
	ifma->ifma_debug |= IFD_ATTACHED;
	if (anon) {
		ifma->ifma_anoncnt++;
		VERIFY(ifma->ifma_anoncnt == 1);
		ifma->ifma_flags |= IFMAF_ANONYMOUS;
	}

	LIST_INSERT_HEAD(&ifp->if_multiaddrs, ifma, ifma_link);
}

static int
if_detach_ifma(struct ifnet *ifp, struct ifmultiaddr *ifma, int anon)
{
	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_EXCLUSIVE);
	IFMA_LOCK_ASSERT_HELD(ifma);

	if (ifma->ifma_reqcnt == 0) {
		panic("%s: ifma=%p negative reqcnt", __func__, ifma);
		/* NOTREACHED */
	} else if (anon && !(ifma->ifma_flags & IFMAF_ANONYMOUS)) {
		panic("%s: ifma=%p missing IFMAF_ANONYMOUS", __func__, ifma);
		/* NOTREACHED */
	} else if (anon && ifma->ifma_anoncnt == 0) {
		panic("%s: ifma=%p negative anonreqcnt", __func__, ifma);
		/* NOTREACHED */
	} else if (ifma->ifma_ifp != ifp) {
		panic("%s: Mismatch ifma_ifp=%p, ifp=%p", __func__,
		    ifma->ifma_ifp, ifp);
		/* NOTREACHED */
	}

	if (anon) {
		--ifma->ifma_anoncnt;
		if (ifma->ifma_anoncnt > 0)
			return (0);
		ifma->ifma_flags &= ~IFMAF_ANONYMOUS;
	}

	--ifma->ifma_reqcnt;
	if (ifma->ifma_reqcnt > 0)
		return (0);

	if (ifma->ifma_protospec != NULL) {
		panic("%s: Protospec not NULL for ifma=%p", __func__, ifma);
		/* NOTREACHED */
	} else if ((ifma->ifma_flags & IFMAF_ANONYMOUS) ||
	    ifma->ifma_anoncnt != 0) {
		panic("%s: Detaching ifma=%p with outstanding anon req",
		    __func__, ifma);
		/* NOTREACHED */
	} else if (!(ifma->ifma_debug & IFD_ATTACHED)) {
		panic("%s: Attempt to detach an unattached address ifma=%p",
		    __func__, ifma);
		/* NOTREACHED */
	} else if (ifma->ifma_debug & IFD_TRASHED) {
		panic("%s: ifma %p is already in trash list", __func__, ifma);
		/* NOTREACHED */
	}

	/*
	 * NOTE: Caller calls IFMA_REMREF
	 */
	ifma->ifma_debug &= ~IFD_ATTACHED;
	LIST_REMOVE(ifma, ifma_link);
	if (LIST_EMPTY(&ifp->if_multiaddrs))
		ifp->if_updatemcasts = 0;

	if (ifma->ifma_debug & IFD_DEBUG) {
		/* Become a regular mutex, just in case */
		IFMA_CONVERT_LOCK(ifma);
		lck_mtx_lock(&ifma_trash_lock);
		TAILQ_INSERT_TAIL(&ifma_trash_head,
		    (struct ifmultiaddr_dbg *)ifma, ifma_trash_link);
		lck_mtx_unlock(&ifma_trash_lock);
		ifma->ifma_debug |= IFD_TRASHED;
	}

	return (1);
}

/*
 * Find an ifmultiaddr that matches a socket address on an interface.
 *
 * Caller is responsible for holding the ifnet_lock while calling
 * this function.
 */
static int
if_addmulti_doesexist(struct ifnet *ifp, const struct sockaddr *sa,
    struct ifmultiaddr **retifma, int anon)
{
	struct ifmultiaddr *ifma;

	for (ifma = LIST_FIRST(&ifp->if_multiaddrs); ifma != NULL;
	    ifma = LIST_NEXT(ifma, ifma_link)) {
		IFMA_LOCK_SPIN(ifma);
		if (!ifa_equal(sa, ifma->ifma_addr)) {
			IFMA_UNLOCK(ifma);
			continue;
		}
		if (anon) {
			VERIFY(!(ifma->ifma_flags & IFMAF_ANONYMOUS) ||
			    ifma->ifma_anoncnt != 0);
			VERIFY((ifma->ifma_flags & IFMAF_ANONYMOUS) ||
			    ifma->ifma_anoncnt == 0);
			ifma->ifma_anoncnt++;
			if (!(ifma->ifma_flags & IFMAF_ANONYMOUS)) {
				VERIFY(ifma->ifma_anoncnt == 1);
				ifma->ifma_flags |= IFMAF_ANONYMOUS;
			}
		}
		if (!anon || ifma->ifma_anoncnt == 1) {
			ifma->ifma_reqcnt++;
			VERIFY(ifma->ifma_reqcnt > 1);
		}
		if (retifma != NULL) {
			*retifma = ifma;
			IFMA_ADDREF_LOCKED(ifma);
		}
		IFMA_UNLOCK(ifma);
		return (0);
	}
	return (ENOENT);
}

/*
 * Radar 3642395, make sure all multicasts are in a standard format.
 */
static struct sockaddr *
copy_and_normalize(const struct sockaddr *original)
{
	int			alen = 0;
	const u_char		*aptr = NULL;
	struct sockaddr		*copy = NULL;
	struct sockaddr_dl	*sdl_new = NULL;
	int			len = 0;

	if (original->sa_family != AF_LINK &&
	    original->sa_family != AF_UNSPEC) {
		/* Just make a copy */
		MALLOC(copy, struct sockaddr *, original->sa_len,
		    M_IFADDR, M_WAITOK);
		if (copy != NULL)
			bcopy(original, copy, original->sa_len);
		return (copy);
	}

	switch (original->sa_family) {
		case AF_LINK: {
			const struct sockaddr_dl *sdl_original =
			    (struct sockaddr_dl *)(uintptr_t)(size_t)original;

			if (sdl_original->sdl_nlen + sdl_original->sdl_alen +
			    sdl_original->sdl_slen +
			    offsetof(struct sockaddr_dl, sdl_data) >
			    sdl_original->sdl_len)
				return (NULL);

			alen = sdl_original->sdl_alen;
			aptr = CONST_LLADDR(sdl_original);
		}
		break;

		case AF_UNSPEC: {
			if (original->sa_len < ETHER_ADDR_LEN +
			    offsetof(struct sockaddr, sa_data)) {
				return (NULL);
			}

			alen = ETHER_ADDR_LEN;
			aptr = (const u_char *)original->sa_data;
		}
		break;
	}

	if (alen == 0 || aptr == NULL)
		return (NULL);

	len = alen + offsetof(struct sockaddr_dl, sdl_data);
	MALLOC(sdl_new, struct sockaddr_dl *, len, M_IFADDR, M_WAITOK);

	if (sdl_new != NULL) {
		bzero(sdl_new, len);
		sdl_new->sdl_len = len;
		sdl_new->sdl_family = AF_LINK;
		sdl_new->sdl_alen = alen;
		bcopy(aptr, LLADDR(sdl_new), alen);
	}

	return ((struct sockaddr *)sdl_new);
}

/*
 * Network-layer protocol domains which hold references to the underlying
 * link-layer record must use this routine.
 */
int
if_addmulti(struct ifnet *ifp, const struct sockaddr *sa,
    struct ifmultiaddr **retifma)
{
	return (if_addmulti_common(ifp, sa, retifma, 0));
}

/*
 * Anything other than network-layer protocol domains which hold references
 * to the underlying link-layer record must use this routine: SIOCADDMULTI
 * ioctl, ifnet_add_multicast(), if_bond.
 */
int
if_addmulti_anon(struct ifnet *ifp, const struct sockaddr *sa,
    struct ifmultiaddr **retifma)
{
	return (if_addmulti_common(ifp, sa, retifma, 1));
}

/*
 * Register an additional multicast address with a network interface.
 *
 * - If the address is already present, bump the reference count on the
 *   address and return.
 * - If the address is not link-layer, look up a link layer address.
 * - Allocate address structures for one or both addresses, and attach to the
 *   multicast address list on the interface.  If automatically adding a link
 *   layer address, the protocol address will own a reference to the link
 *   layer address, to be freed when it is freed.
 * - Notify the network device driver of an addition to the multicast address
 *   list.
 *
 * 'sa' points to caller-owned memory with the desired multicast address.
 *
 * 'retifma' will be used to return a pointer to the resulting multicast
 * address reference, if desired.
 *
 * 'anon' indicates a link-layer address with no protocol address reference
 * made to it.  Anything other than network-layer protocol domain requests
 * are considered as anonymous.
 */
static int
if_addmulti_common(struct ifnet *ifp, const struct sockaddr *sa,
    struct ifmultiaddr **retifma, int anon)
{
	struct sockaddr_storage storage;
	struct sockaddr *llsa = NULL;
	struct sockaddr *dupsa = NULL;
	int error = 0, ll_firstref = 0, lladdr;
	struct ifmultiaddr *ifma = NULL;
	struct ifmultiaddr *llifma = NULL;

	/* Only AF_UNSPEC/AF_LINK is allowed for an "anonymous" address */
	VERIFY(!anon || sa->sa_family == AF_UNSPEC ||
	    sa->sa_family == AF_LINK);

	/* If sa is a AF_LINK or AF_UNSPEC, duplicate and normalize it */
	if (sa->sa_family == AF_LINK || sa->sa_family == AF_UNSPEC) {
		dupsa = copy_and_normalize(sa);
		if (dupsa == NULL) {
			error = ENOMEM;
			goto cleanup;
		}
		sa = dupsa;
	}

	ifnet_lock_exclusive(ifp);
	if (!(ifp->if_flags & IFF_MULTICAST)) {
		error = EADDRNOTAVAIL;
		ifnet_lock_done(ifp);
		goto cleanup;
	}

	/* If the address is already present, return a new reference to it */
	error = if_addmulti_doesexist(ifp, sa, retifma, anon);
	ifnet_lock_done(ifp);
	if (error == 0)
		goto cleanup;

	/*
	 * The address isn't already present; give the link layer a chance
	 * to accept/reject it, and also find out which AF_LINK address this
	 * maps to, if it isn't one already.
	 */
	error = dlil_resolve_multi(ifp, sa, (struct sockaddr *)&storage,
	    sizeof (storage));
	if (error == 0 && storage.ss_len != 0) {
		llsa = copy_and_normalize((struct sockaddr *)&storage);
		if (llsa == NULL) {
			error = ENOMEM;
			goto cleanup;
		}

		llifma = ifma_alloc(M_WAITOK);
		if (llifma == NULL) {
			error = ENOMEM;
			goto cleanup;
		}
	}

	/* to be similar to FreeBSD */
	if (error == EOPNOTSUPP)
		error = 0;
	else if (error != 0)
		goto cleanup;

	/* Allocate while we aren't holding any locks */
	if (dupsa == NULL) {
		dupsa = copy_and_normalize(sa);
		if (dupsa == NULL) {
			error = ENOMEM;
			goto cleanup;
		}
	}
	ifma = ifma_alloc(M_WAITOK);
	if (ifma == NULL) {
		error = ENOMEM;
		goto cleanup;
	}

	ifnet_lock_exclusive(ifp);
	/*
	 * Check again for the matching multicast.
	 */
	error = if_addmulti_doesexist(ifp, sa, retifma, anon);
	if (error == 0) {
		ifnet_lock_done(ifp);
		goto cleanup;
	}

	if (llifma != NULL) {
		VERIFY(!anon);	/* must not get here if "anonymous" */
		if (if_addmulti_doesexist(ifp, llsa, &ifma->ifma_ll, 0) == 0) {
			FREE(llsa, M_IFADDR);
			llsa = NULL;
			ifma_free(llifma);
			llifma = NULL;
			VERIFY(ifma->ifma_ll->ifma_ifp == ifp);
		} else {
			ll_firstref = 1;
			llifma->ifma_addr = llsa;
			llifma->ifma_ifp = ifp;
			IFMA_LOCK(llifma);
			if_attach_ifma(ifp, llifma, 0);
			/* add extra refcnt for ifma */
			IFMA_ADDREF_LOCKED(llifma);
			IFMA_UNLOCK(llifma);
			ifma->ifma_ll = llifma;
		}
	}

	/* "anonymous" request should not result in network address */
	VERIFY(!anon || ifma->ifma_ll == NULL);

	ifma->ifma_addr = dupsa;
	ifma->ifma_ifp = ifp;
	IFMA_LOCK(ifma);
	if_attach_ifma(ifp, ifma, anon);
	IFMA_ADDREF_LOCKED(ifma);		/* for this routine */
	if (retifma != NULL) {
		*retifma = ifma;
		IFMA_ADDREF_LOCKED(*retifma);	/* for caller */
	}
	lladdr = (ifma->ifma_addr->sa_family == AF_UNSPEC ||
	    ifma->ifma_addr->sa_family == AF_LINK);
	IFMA_UNLOCK(ifma);
	ifnet_lock_done(ifp);

	rt_newmaddrmsg(RTM_NEWMADDR, ifma);
	IFMA_REMREF(ifma);			/* for this routine */

	/*
	 * We are certain we have added something, so call down to the
	 * interface to let them know about it.  Do this only for newly-
	 * added AF_LINK/AF_UNSPEC address in the if_multiaddrs set.
	 */
	if (lladdr || ll_firstref)
		(void) ifnet_ioctl(ifp, 0, SIOCADDMULTI, NULL);

	if (ifp->if_updatemcasts > 0)
		ifp->if_updatemcasts = 0;

	return (0);

cleanup:
	if (ifma != NULL)
		ifma_free(ifma);
	if (dupsa != NULL)
		FREE(dupsa, M_IFADDR);
	if (llifma != NULL)
		ifma_free(llifma);
	if (llsa != NULL)
		FREE(llsa, M_IFADDR);

	return (error);
}

/*
 * Delete a multicast group membership by network-layer group address.
 * This routine is deprecated.
 */
int
if_delmulti(struct ifnet *ifp, const struct sockaddr *sa)
{
	return (if_delmulti_common(NULL, ifp, sa, 0));
}

/*
 * Delete a multicast group membership by group membership pointer.
 * Network-layer protocol domains must use this routine.
 */
int
if_delmulti_ifma(struct ifmultiaddr *ifma)
{
	return (if_delmulti_common(ifma, NULL, NULL, 0));
}

/*
 * Anything other than network-layer protocol domains which hold references
 * to the underlying link-layer record must use this routine: SIOCDELMULTI
 * ioctl, ifnet_remove_multicast(), if_bond.
 */
int
if_delmulti_anon(struct ifnet *ifp, const struct sockaddr *sa)
{
	return (if_delmulti_common(NULL, ifp, sa, 1));
}

/*
 * Delete a multicast group membership by network-layer group address.
 *
 * Returns ENOENT if the entry could not be found.
 */
static int
if_delmulti_common(struct ifmultiaddr *ifma, struct ifnet *ifp,
    const struct sockaddr *sa, int anon)
{
	struct sockaddr		*dupsa = NULL;
	int			lastref, ll_lastref = 0, lladdr;
	struct ifmultiaddr	*ll = NULL;

	/* sanity check for callers */
	VERIFY(ifma != NULL || (ifp != NULL && sa != NULL));

	if (ifma != NULL)
		ifp = ifma->ifma_ifp;

	if (sa != NULL &&
	    (sa->sa_family == AF_LINK || sa->sa_family == AF_UNSPEC)) {
		dupsa = copy_and_normalize(sa);
		if (dupsa == NULL)
			return (ENOMEM);
		sa = dupsa;
	}

	ifnet_lock_exclusive(ifp);
	if (ifma == NULL) {
		for (ifma = LIST_FIRST(&ifp->if_multiaddrs); ifma != NULL;
		    ifma = LIST_NEXT(ifma, ifma_link)) {
			IFMA_LOCK(ifma);
			if (!ifa_equal(sa, ifma->ifma_addr) ||
			    (anon && !(ifma->ifma_flags & IFMAF_ANONYMOUS))) {
				VERIFY(!(ifma->ifma_flags & IFMAF_ANONYMOUS) ||
				    ifma->ifma_anoncnt != 0);
				IFMA_UNLOCK(ifma);
				continue;
			}
			/* found; keep it locked */
			break;
		}
		if (ifma == NULL) {
			if (dupsa != NULL)
				FREE(dupsa, M_IFADDR);
			ifnet_lock_done(ifp);
			return (ENOENT);
		}
	} else {
		IFMA_LOCK(ifma);
	}
	IFMA_LOCK_ASSERT_HELD(ifma);
	IFMA_ADDREF_LOCKED(ifma);	/* for this routine */
	lastref = if_detach_ifma(ifp, ifma, anon);
	VERIFY(!lastref || (!(ifma->ifma_debug & IFD_ATTACHED) &&
	    ifma->ifma_reqcnt == 0));
	VERIFY(!anon || ifma->ifma_ll == NULL);
	ll = ifma->ifma_ll;
	lladdr = (ifma->ifma_addr->sa_family == AF_UNSPEC ||
	    ifma->ifma_addr->sa_family == AF_LINK);
	IFMA_UNLOCK(ifma);
	if (lastref && ll != NULL) {
		IFMA_LOCK(ll);
		ll_lastref = if_detach_ifma(ifp, ll, 0);
		IFMA_UNLOCK(ll);
	}
	ifnet_lock_done(ifp);

	if (lastref)
		rt_newmaddrmsg(RTM_DELMADDR, ifma);

	if ((ll == NULL && lastref && lladdr) || ll_lastref) {
		/*
		 * Make sure the interface driver is notified in the
		 * case of a link layer mcast group being left.  Do
		 * this only for a AF_LINK/AF_UNSPEC address that has
		 * been removed from the if_multiaddrs set.
		 */
		ifnet_ioctl(ifp, 0, SIOCDELMULTI, NULL);
	}

	if (lastref)
		IFMA_REMREF(ifma);	/* for if_multiaddrs list */
	if (ll_lastref)
		IFMA_REMREF(ll);	/* for if_multiaddrs list */

	IFMA_REMREF(ifma);		/* for this routine */
	if (dupsa != NULL)
		FREE(dupsa, M_IFADDR);

	return (0);
}

/*
 * Shutdown all network activity.  Used boot() when halting
 * system.
 */
int
if_down_all(void)
{
	struct ifnet **ifp;
	u_int32_t	count;
	u_int32_t	i;

	if (ifnet_list_get_all(IFNET_FAMILY_ANY, &ifp, &count) == 0) {
		for (i = 0; i < count; i++) {
			if_down(ifp[i]);
			dlil_proto_unplumb_all(ifp[i]);
		}
		ifnet_list_free(ifp);
	}

	return (0);
}

/*
 * Delete Routes for a Network Interface
 *
 * Called for each routing entry via the rnh->rnh_walktree() call above
 * to delete all route entries referencing a detaching network interface.
 *
 * Arguments:
 *	rn	pointer to node in the routing table
 *	arg	argument passed to rnh->rnh_walktree() - detaching interface
 *
 * Returns:
 *	0	successful
 *	errno	failed - reason indicated
 *
 */
static int
if_rtdel(struct radix_node *rn, void *arg)
{
	struct rtentry	*rt = (struct rtentry *)rn;
	struct ifnet	*ifp = arg;
	int		err;

	if (rt == NULL)
		return (0);
	/*
	 * Checking against RTF_UP protects against walktree
	 * recursion problems with cloned routes.
	 */
	RT_LOCK(rt);
	if (rt->rt_ifp == ifp && (rt->rt_flags & RTF_UP)) {
		/*
		 * Safe to drop rt_lock and use rt_key, rt_gateway,
		 * since holding rnh_lock here prevents another thread
		 * from calling rt_setgate() on this route.
		 */
		RT_UNLOCK(rt);
		err = rtrequest_locked(RTM_DELETE, rt_key(rt), rt->rt_gateway,
		    rt_mask(rt), rt->rt_flags, NULL);
		if (err) {
			log(LOG_WARNING, "if_rtdel: error %d\n", err);
		}
	} else {
		RT_UNLOCK(rt);
	}
	return (0);
}

/*
 * Removes routing table reference to a given interface
 * for a given protocol family
 */
void
if_rtproto_del(struct ifnet *ifp, int protocol)
{
	struct radix_node_head  *rnh;

	if ((protocol <= AF_MAX) && (protocol >= 0) &&
		((rnh = rt_tables[protocol]) != NULL) && (ifp != NULL)) {
		lck_mtx_lock(rnh_lock);
		(void) rnh->rnh_walktree(rnh, if_rtdel, ifp);
		lck_mtx_unlock(rnh_lock);
	}
}

static int
if_rtmtu(struct radix_node *rn, void *arg)
{
	struct rtentry *rt = (struct rtentry *)rn;
	struct ifnet *ifp = arg;

	RT_LOCK(rt);
	if (rt->rt_ifp == ifp) {
		/*
		 * Update the MTU of this entry only if the MTU
		 * has not been locked (RTV_MTU is not set) and
		 * if it was non-zero to begin with.
		 */
		if (!(rt->rt_rmx.rmx_locks & RTV_MTU) && rt->rt_rmx.rmx_mtu)
			rt->rt_rmx.rmx_mtu = ifp->if_mtu;
	}
	RT_UNLOCK(rt);

	return (0);
}

/*
 * Update the MTU metric of all route entries in all protocol tables
 * associated with a particular interface; this is called when the
 * MTU of that interface has changed.
 */
static void
if_rtmtu_update(struct ifnet *ifp)
{
	struct radix_node_head *rnh;
	int p;

	for (p = 0; p < AF_MAX + 1; p++) {
		if ((rnh = rt_tables[p]) == NULL)
			continue;

		lck_mtx_lock(rnh_lock);
		(void) rnh->rnh_walktree(rnh, if_rtmtu, ifp);
		lck_mtx_unlock(rnh_lock);
	}
	routegenid_update();
}

__private_extern__ void
if_data_internal_to_if_data(struct ifnet *ifp,
    const struct if_data_internal *if_data_int, struct if_data *if_data)
{
#pragma unused(ifp)
#define	COPYFIELD(fld)		if_data->fld = if_data_int->fld
#define	COPYFIELD32(fld)	if_data->fld = (u_int32_t)(if_data_int->fld)
/* compiler will cast down to 32-bit */
#define	COPYFIELD32_ATOMIC(fld) do {					\
	atomic_get_64(if_data->fld,					\
	    (u_int64_t *)(void *)(uintptr_t)&if_data_int->fld);		\
} while (0)

	COPYFIELD(ifi_type);
	COPYFIELD(ifi_typelen);
	COPYFIELD(ifi_physical);
	COPYFIELD(ifi_addrlen);
	COPYFIELD(ifi_hdrlen);
	COPYFIELD(ifi_recvquota);
	COPYFIELD(ifi_xmitquota);
	if_data->ifi_unused1 = 0;
	COPYFIELD(ifi_mtu);
	COPYFIELD(ifi_metric);
	if (if_data_int->ifi_baudrate & 0xFFFFFFFF00000000LL) {
		if_data->ifi_baudrate = 0xFFFFFFFF;
	} else {
		COPYFIELD32(ifi_baudrate);
	}

	COPYFIELD32_ATOMIC(ifi_ipackets);
	COPYFIELD32_ATOMIC(ifi_ierrors);
	COPYFIELD32_ATOMIC(ifi_opackets);
	COPYFIELD32_ATOMIC(ifi_oerrors);
	COPYFIELD32_ATOMIC(ifi_collisions);
	COPYFIELD32_ATOMIC(ifi_ibytes);
	COPYFIELD32_ATOMIC(ifi_obytes);
	COPYFIELD32_ATOMIC(ifi_imcasts);
	COPYFIELD32_ATOMIC(ifi_omcasts);
	COPYFIELD32_ATOMIC(ifi_iqdrops);
	COPYFIELD32_ATOMIC(ifi_noproto);

	COPYFIELD(ifi_recvtiming);
	COPYFIELD(ifi_xmittiming);

	if_data->ifi_lastchange.tv_sec = if_data_int->ifi_lastchange.tv_sec;
	if_data->ifi_lastchange.tv_usec = if_data_int->ifi_lastchange.tv_usec;

	if_data->ifi_lastchange.tv_sec += boottime_sec();

	if_data->ifi_unused2 = 0;
	COPYFIELD(ifi_hwassist);
	if_data->ifi_reserved1 = 0;
	if_data->ifi_reserved2 = 0;
#undef COPYFIELD32_ATOMIC
#undef COPYFIELD32
#undef COPYFIELD
}

__private_extern__ void
if_data_internal_to_if_data64(struct ifnet *ifp,
    const struct if_data_internal *if_data_int,
    struct if_data64 *if_data64)
{
#pragma unused(ifp)
#define	COPYFIELD64(fld)	if_data64->fld = if_data_int->fld
#define	COPYFIELD64_ATOMIC(fld) do {					\
	atomic_get_64(if_data64->fld,					\
	    (u_int64_t *)(void *)(uintptr_t)&if_data_int->fld);		\
} while (0)

	COPYFIELD64(ifi_type);
	COPYFIELD64(ifi_typelen);
	COPYFIELD64(ifi_physical);
	COPYFIELD64(ifi_addrlen);
	COPYFIELD64(ifi_hdrlen);
	COPYFIELD64(ifi_recvquota);
	COPYFIELD64(ifi_xmitquota);
	if_data64->ifi_unused1 = 0;
	COPYFIELD64(ifi_mtu);
	COPYFIELD64(ifi_metric);
	COPYFIELD64(ifi_baudrate);

	COPYFIELD64_ATOMIC(ifi_ipackets);
	COPYFIELD64_ATOMIC(ifi_ierrors);
	COPYFIELD64_ATOMIC(ifi_opackets);
	COPYFIELD64_ATOMIC(ifi_oerrors);
	COPYFIELD64_ATOMIC(ifi_collisions);
	COPYFIELD64_ATOMIC(ifi_ibytes);
	COPYFIELD64_ATOMIC(ifi_obytes);
	COPYFIELD64_ATOMIC(ifi_imcasts);
	COPYFIELD64_ATOMIC(ifi_omcasts);
	COPYFIELD64_ATOMIC(ifi_iqdrops);
	COPYFIELD64_ATOMIC(ifi_noproto);

	/*
	 * Note these two fields are actually 32 bit, so doing
	 * COPYFIELD64_ATOMIC will cause them to be misaligned
	 */
	COPYFIELD64(ifi_recvtiming);
	COPYFIELD64(ifi_xmittiming);

	if_data64->ifi_lastchange.tv_sec = if_data_int->ifi_lastchange.tv_sec;
	if_data64->ifi_lastchange.tv_usec = if_data_int->ifi_lastchange.tv_usec;

	if_data64->ifi_lastchange.tv_sec += boottime_sec();

#undef COPYFIELD64
}

__private_extern__ void
if_copy_traffic_class(struct ifnet *ifp,
    struct if_traffic_class *if_tc)
{
#define	COPY_IF_TC_FIELD64_ATOMIC(fld) do {			\
	atomic_get_64(if_tc->fld,				\
	    (u_int64_t *)(void *)(uintptr_t)&ifp->if_tc.fld);	\
} while (0)

	bzero(if_tc, sizeof (*if_tc));
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ibepackets);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ibebytes);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_obepackets);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_obebytes);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ibkpackets);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ibkbytes);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_obkpackets);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_obkbytes);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ivipackets);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ivibytes);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ovipackets);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ovibytes);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ivopackets);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ivobytes);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ovopackets);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ovobytes);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ipvpackets);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_ipvbytes);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_opvpackets);
	COPY_IF_TC_FIELD64_ATOMIC(ifi_opvbytes);

#undef COPY_IF_TC_FIELD64_ATOMIC
}

void
if_copy_data_extended(struct ifnet *ifp, struct if_data_extended *if_de)
{
#define	COPY_IF_DE_FIELD64_ATOMIC(fld) do {			\
	atomic_get_64(if_de->fld,				\
	    (u_int64_t *)(void *)(uintptr_t)&ifp->if_data.fld);	\
} while (0)

	bzero(if_de, sizeof (*if_de));
	COPY_IF_DE_FIELD64_ATOMIC(ifi_alignerrs);
	COPY_IF_DE_FIELD64_ATOMIC(ifi_dt_bytes);
	COPY_IF_DE_FIELD64_ATOMIC(ifi_fpackets);
	COPY_IF_DE_FIELD64_ATOMIC(ifi_fbytes);

#undef COPY_IF_DE_FIELD64_ATOMIC
}

void
if_copy_packet_stats(struct ifnet *ifp, struct if_packet_stats *if_ps)
{
#define	COPY_IF_PS_TCP_FIELD64_ATOMIC(fld) do {				\
	atomic_get_64(if_ps->ifi_tcp_##fld,				\
	    (u_int64_t *)(void *)(uintptr_t)&ifp->if_tcp_stat->fld);	\
} while (0)

#define	COPY_IF_PS_UDP_FIELD64_ATOMIC(fld) do {				\
	atomic_get_64(if_ps->ifi_udp_##fld,				\
	    (u_int64_t *)(void *)(uintptr_t)&ifp->if_udp_stat->fld);	\
} while (0)

	COPY_IF_PS_TCP_FIELD64_ATOMIC(badformat);
	COPY_IF_PS_TCP_FIELD64_ATOMIC(unspecv6);
	COPY_IF_PS_TCP_FIELD64_ATOMIC(synfin);
	COPY_IF_PS_TCP_FIELD64_ATOMIC(badformatipsec);
	COPY_IF_PS_TCP_FIELD64_ATOMIC(noconnnolist);
	COPY_IF_PS_TCP_FIELD64_ATOMIC(noconnlist);
	COPY_IF_PS_TCP_FIELD64_ATOMIC(listbadsyn);
	COPY_IF_PS_TCP_FIELD64_ATOMIC(icmp6unreach);
	COPY_IF_PS_TCP_FIELD64_ATOMIC(deprecate6);
	COPY_IF_PS_TCP_FIELD64_ATOMIC(ooopacket);
	COPY_IF_PS_TCP_FIELD64_ATOMIC(rstinsynrcv);
	COPY_IF_PS_TCP_FIELD64_ATOMIC(dospacket);
	COPY_IF_PS_TCP_FIELD64_ATOMIC(cleanup);
	COPY_IF_PS_TCP_FIELD64_ATOMIC(synwindow);

	COPY_IF_PS_UDP_FIELD64_ATOMIC(port_unreach);
	COPY_IF_PS_UDP_FIELD64_ATOMIC(faithprefix);
	COPY_IF_PS_UDP_FIELD64_ATOMIC(port0);
	COPY_IF_PS_UDP_FIELD64_ATOMIC(badlength);
	COPY_IF_PS_UDP_FIELD64_ATOMIC(badchksum);
	COPY_IF_PS_UDP_FIELD64_ATOMIC(badmcast);
	COPY_IF_PS_UDP_FIELD64_ATOMIC(cleanup);
	COPY_IF_PS_UDP_FIELD64_ATOMIC(badipsec);

#undef COPY_IF_PS_TCP_FIELD64_ATOMIC
#undef COPY_IF_PS_UDP_FIELD64_ATOMIC
}

void
if_copy_rxpoll_stats(struct ifnet *ifp, struct if_rxpoll_stats *if_rs)
{
	bzero(if_rs, sizeof (*if_rs));
	if (!(ifp->if_eflags & IFEF_RXPOLL) || !ifnet_is_attached(ifp, 1))
		return;

	/* by now, ifnet will stay attached so if_inp must be valid */
	VERIFY(ifp->if_inp != NULL);
	bcopy(&ifp->if_inp->pstats, if_rs, sizeof (*if_rs));

	/* Release the IO refcnt */
	ifnet_decr_iorefcnt(ifp);
}

struct ifaddr *
ifa_remref(struct ifaddr *ifa, int locked)
{
	if (!locked)
		IFA_LOCK_SPIN(ifa);
	else
		IFA_LOCK_ASSERT_HELD(ifa);

	if (ifa->ifa_refcnt == 0)
		panic("%s: ifa %p negative refcnt\n", __func__, ifa);
	else if (ifa->ifa_trace != NULL)
		(*ifa->ifa_trace)(ifa, FALSE);
	if (--ifa->ifa_refcnt == 0) {
		if (ifa->ifa_debug & IFD_ATTACHED)
			panic("ifa %p attached to ifp is being freed\n", ifa);
		/*
		 * Some interface addresses are allocated either statically
		 * or carved out of a larger block.  Only free it if it was
		 * allocated via MALLOC or via the corresponding per-address
		 * family allocator.  Otherwise, leave it alone.
		 */
		if (ifa->ifa_debug & IFD_ALLOC) {
			if (ifa->ifa_free == NULL) {
				IFA_UNLOCK(ifa);
				FREE(ifa, M_IFADDR);
			} else {
				/* Become a regular mutex */
				IFA_CONVERT_LOCK(ifa);
				/* callee will unlock */
				(*ifa->ifa_free)(ifa);
			}
		} else {
			IFA_UNLOCK(ifa);
		}
		ifa = NULL;
	}

	if (!locked && ifa != NULL)
		IFA_UNLOCK(ifa);

	return (ifa);
}

void
ifa_addref(struct ifaddr *ifa, int locked)
{
	if (!locked)
		IFA_LOCK_SPIN(ifa);
	else
		IFA_LOCK_ASSERT_HELD(ifa);

	if (++ifa->ifa_refcnt == 0) {
		panic("%s: ifa %p wraparound refcnt\n", __func__, ifa);
		/* NOTREACHED */
	} else if (ifa->ifa_trace != NULL) {
		(*ifa->ifa_trace)(ifa, TRUE);
	}
	if (!locked)
		IFA_UNLOCK(ifa);
}

void
ifa_lock_init(struct ifaddr *ifa)
{
	lck_mtx_init(&ifa->ifa_lock, ifa_mtx_grp, ifa_mtx_attr);
}

void
ifa_lock_destroy(struct ifaddr *ifa)
{
	IFA_LOCK_ASSERT_NOTHELD(ifa);
	lck_mtx_destroy(&ifa->ifa_lock, ifa_mtx_grp);
}

/*
 * 'i' group ioctls.
 *
 * The switch statement below does nothing at runtime, as it serves as a
 * compile time check to ensure that all of the socket 'i' ioctls (those
 * in the 'i' group going thru soo_ioctl) that are made available by the
 * networking stack is unique.  This works as long as this routine gets
 * updated each time a new interface ioctl gets added.
 *
 * Any failures at compile time indicates duplicated ioctl values.
 */
static __attribute__((unused)) void
ifioctl_cassert(void)
{
	/*
	 * This is equivalent to _CASSERT() and the compiler wouldn't
	 * generate any instructions, thus for compile time only.
	 */
	switch ((u_long)0) {
	case 0:

	/* bsd/net/if_ppp.h */
	case SIOCGPPPSTATS:
	case SIOCGPPPCSTATS:

#if INET6
	/* bsd/netinet6/in6_var.h */
	case SIOCSIFADDR_IN6:
	case SIOCGIFADDR_IN6:
	case SIOCSIFDSTADDR_IN6:
	case SIOCSIFNETMASK_IN6:
	case SIOCGIFDSTADDR_IN6:
	case SIOCGIFNETMASK_IN6:
	case SIOCDIFADDR_IN6:
	case SIOCAIFADDR_IN6_32:
	case SIOCAIFADDR_IN6_64:
	case SIOCSIFPHYADDR_IN6_32:
	case SIOCSIFPHYADDR_IN6_64:
	case SIOCGIFPSRCADDR_IN6:
	case SIOCGIFPDSTADDR_IN6:
	case SIOCGIFAFLAG_IN6:
	case SIOCGDRLST_IN6_32:
	case SIOCGDRLST_IN6_64:
	case SIOCGPRLST_IN6_32:
	case SIOCGPRLST_IN6_64:
	case OSIOCGIFINFO_IN6:
	case SIOCGIFINFO_IN6:
	case SIOCSNDFLUSH_IN6:
	case SIOCGNBRINFO_IN6_32:
	case SIOCGNBRINFO_IN6_64:
	case SIOCSPFXFLUSH_IN6:
	case SIOCSRTRFLUSH_IN6:
	case SIOCGIFALIFETIME_IN6:
	case SIOCSIFALIFETIME_IN6:
	case SIOCGIFSTAT_IN6:
	case SIOCGIFSTAT_ICMP6:
	case SIOCSDEFIFACE_IN6_32:
	case SIOCSDEFIFACE_IN6_64:
	case SIOCGDEFIFACE_IN6_32:
	case SIOCGDEFIFACE_IN6_64:
	case SIOCSIFINFO_FLAGS:
	case SIOCSSCOPE6:
	case SIOCGSCOPE6:
	case SIOCGSCOPE6DEF:
	case SIOCSIFPREFIX_IN6:
	case SIOCGIFPREFIX_IN6:
	case SIOCDIFPREFIX_IN6:
	case SIOCAIFPREFIX_IN6:
	case SIOCCIFPREFIX_IN6:
	case SIOCSGIFPREFIX_IN6:
	case SIOCPROTOATTACH_IN6_32:
	case SIOCPROTOATTACH_IN6_64:
	case SIOCPROTODETACH_IN6:
	case SIOCLL_START_32:
	case SIOCLL_START_64:
	case SIOCLL_STOP:
	case SIOCAUTOCONF_START:
	case SIOCAUTOCONF_STOP:
	case SIOCSETROUTERMODE_IN6:
	case SIOCLL_CGASTART_32:
	case SIOCLL_CGASTART_64:
	case SIOCGIFCGAPREP_IN6:
	case SIOCSIFCGAPREP_IN6:
#endif /* INET6 */

	/* bsd/sys/sockio.h */
	case SIOCSIFADDR:
	case OSIOCGIFADDR:
	case SIOCSIFDSTADDR:
	case OSIOCGIFDSTADDR:
	case SIOCSIFFLAGS:
	case SIOCGIFFLAGS:
	case OSIOCGIFBRDADDR:
	case SIOCSIFBRDADDR:
	case OSIOCGIFCONF32:
	case OSIOCGIFCONF64:
	case OSIOCGIFNETMASK:
	case SIOCSIFNETMASK:
	case SIOCGIFMETRIC:
	case SIOCSIFMETRIC:
	case SIOCDIFADDR:
	case SIOCAIFADDR:

	case SIOCGIFADDR:
	case SIOCGIFDSTADDR:
	case SIOCGIFBRDADDR:
	case SIOCGIFCONF32:
	case SIOCGIFCONF64:
	case SIOCGIFNETMASK:
	case SIOCAUTOADDR:
	case SIOCAUTONETMASK:
	case SIOCARPIPLL:

	case SIOCADDMULTI:
	case SIOCDELMULTI:
	case SIOCGIFMTU:
	case SIOCSIFMTU:
	case SIOCGIFPHYS:
	case SIOCSIFPHYS:
	case SIOCSIFMEDIA:
	case SIOCGIFMEDIA32:
	case SIOCGIFMEDIA64:
	case SIOCSIFGENERIC:
	case SIOCGIFGENERIC:
	case SIOCRSLVMULTI:

	case SIOCSIFLLADDR:
	case SIOCGIFSTATUS:
	case SIOCSIFPHYADDR:
	case SIOCGIFPSRCADDR:
	case SIOCGIFPDSTADDR:
	case SIOCDIFPHYADDR:

	case SIOCGIFDEVMTU:
	case SIOCSIFALTMTU:
	case SIOCGIFALTMTU:
	case SIOCSIFBOND:
	case SIOCGIFBOND:

	case SIOCPROTOATTACH:
	case SIOCPROTODETACH:

	case SIOCSIFCAP:
	case SIOCGIFCAP:

	case SIOCIFCREATE:
	case SIOCIFDESTROY:
	case SIOCIFCREATE2:

	case SIOCSDRVSPEC32:
	case SIOCGDRVSPEC32:
	case SIOCSDRVSPEC64:
	case SIOCGDRVSPEC64:

	case SIOCSIFVLAN:
	case SIOCGIFVLAN:

	case SIOCIFGCLONERS32:
	case SIOCIFGCLONERS64:

	case SIOCGIFASYNCMAP:
	case SIOCSIFASYNCMAP:
#if CONFIG_MACF_NET
	case SIOCGIFMAC:
	case SIOCSIFMAC:
#endif /* CONFIG_MACF_NET */
	case SIOCSIFKPI:
	case SIOCGIFKPI:

	case SIOCGIFWAKEFLAGS:

	case SIOCGIFGETRTREFCNT:
	case SIOCGIFLINKQUALITYMETRIC:
	case SIOCSIFOPPORTUNISTIC:
	case SIOCGIFOPPORTUNISTIC:
	case SIOCSETROUTERMODE:
	case SIOCGIFEFLAGS:
	case SIOCSIFDESC:
	case SIOCGIFDESC:
	case SIOCSIFLINKPARAMS:
	case SIOCGIFLINKPARAMS:
	case SIOCGIFQUEUESTATS:
	case SIOCSIFTHROTTLE:
	case SIOCGIFTHROTTLE:

	case SIOCGASSOCIDS32:
	case SIOCGASSOCIDS64:
	case SIOCGCONNIDS32:
	case SIOCGCONNIDS64:
	case SIOCGCONNINFO32:
	case SIOCGCONNINFO64:
	case SIOCSCONNORDER:
	case SIOCGCONNORDER:

	case SIOCSIFLOG:
	case SIOCGIFLOG:
	case SIOCGIFDELEGATE:
	case SIOCGIFLLADDR:
	case SIOCGIFTYPE:
	case SIOCGIFEXPENSIVE:
	case SIOCSIFEXPENSIVE:
	case SIOCGIF2KCL:
	case SIOCSIF2KCL:
	case SIOCGSTARTDELAY:

	case SIOCAIFAGENTID:
	case SIOCDIFAGENTID:
	case SIOCGIFAGENTIDS32:
	case SIOCGIFAGENTIDS64:
	case SIOCGIFAGENTDATA32:
	case SIOCGIFAGENTDATA64:
	case SIOCGIFAGENTLIST32:
	case SIOCGIFAGENTLIST64:


	case SIOCSIFINTERFACESTATE:
	case SIOCGIFINTERFACESTATE:
	case SIOCSIFPROBECONNECTIVITY:
	case SIOCGIFPROBECONNECTIVITY:

	case SIOCGIFFUNCTIONALTYPE:
	case SIOCSIFNETSIGNATURE:
	case SIOCGIFNETSIGNATURE:

	case SIOCGECNMODE:
	case SIOCSECNMODE:

	case SIOCSQOSMARKINGMODE:
	case SIOCSQOSMARKINGENABLED:
	case SIOCGQOSMARKINGMODE:
	case SIOCGQOSMARKINGENABLED:
		;
	}
}

/*
 * XXX: This API is only used by BSD stack and for now will always return 0.
 * For Skywalk native drivers, preamble space need not be allocated in mbuf
 * as the preamble will be reserved in the translated skywalk packet
 * which is transmitted to the driver.
 * For Skywalk compat drivers currently headroom is always set to zero.
 */
uint32_t
ifnet_mbuf_packetpreamblelen(struct ifnet *ifp)
{
#pragma unused(ifp)
	return (0);
}

/* The following is used to enqueue work items for interface events */
struct intf_event {
	struct ifnet *ifp;
	union sockaddr_in_4_6 addr;
	uint32_t intf_event_code;
};

static void
intf_event_callback(void *arg)
{
	struct intf_event *p_intf_ev = (struct intf_event *)arg;

	/* Call this before we walk the tree */
	EVENTHANDLER_INVOKE(&ifnet_evhdlr_ctxt, ifnet_event, p_intf_ev->ifp,
	    (struct sockaddr *)&(p_intf_ev->addr), p_intf_ev->intf_event_code);
}

struct intf_event_nwk_wq_entry {
	struct nwk_wq_entry nwk_wqe;
	struct intf_event intf_ev_arg;
};

void
intf_event_enqueue_nwk_wq_entry(struct ifnet *ifp, struct sockaddr *addrp,
    uint32_t intf_event_code)
{
#pragma unused(addrp)
	struct intf_event_nwk_wq_entry *p_intf_ev = NULL;

	MALLOC(p_intf_ev, struct intf_event_nwk_wq_entry *,
	    sizeof(struct intf_event_nwk_wq_entry),
	    M_NWKWQ, M_WAITOK | M_ZERO);

	p_intf_ev->intf_ev_arg.ifp = ifp;
	/*
	 * XXX Not using addr in the arg. This will be used
	 * once we need IP address add/delete events
	 */
	p_intf_ev->intf_ev_arg.intf_event_code = intf_event_code;
	p_intf_ev->nwk_wqe.func = intf_event_callback;
	p_intf_ev->nwk_wqe.is_arg_managed = TRUE;
	p_intf_ev->nwk_wqe.arg = &p_intf_ev->intf_ev_arg;
	nwk_wq_enqueue((struct nwk_wq_entry*)p_intf_ev);
}
