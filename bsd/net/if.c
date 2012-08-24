/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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
#include <kern/zalloc.h>

#include <machine/endian.h>

#include <pexpert/pexpert.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/net_osdep.h>
#include <net/ethernet.h>

#include <net/radix.h>
#include <net/route.h>
#ifdef __APPLE__
#include <net/dlil.h>
//#include <string.h>
#include <sys/domain.h>
#include <libkern/OSAtomic.h>
#endif

#if INET || INET6
/*XXX*/
#include <netinet/in.h>
#include <netinet/in_var.h>
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
#endif
#endif

#if CONFIG_MACF_NET 
#include <security/mac_framework.h>
#endif

#if PF_ALTQ
#include <net/altq/if_altq.h>
#endif /* !PF_ALTQ */

/*
 * System initialization
 */

/* Lock group and attribute for ifaddr lock */
lck_attr_t	*ifa_mtx_attr;
lck_grp_t	*ifa_mtx_grp;
static lck_grp_attr_t	*ifa_mtx_grp_attr;

static int ifioctl_ifreq(struct socket *, u_long, struct ifreq *,
    struct proc *);
static int ifconf(u_long cmd, user_addr_t ifrp, int * ret_space);
__private_extern__ void link_rtrequest(int, struct rtentry *, struct sockaddr *);
void if_rtproto_del(struct ifnet *ifp, int protocol);

static int if_addmulti_common(struct ifnet *, const struct sockaddr *,
    struct ifmultiaddr **, int);
static int if_delmulti_common(struct ifmultiaddr *, struct ifnet *,
    const struct sockaddr *, int);

static int if_rtmtu(struct radix_node *, void *);
static void if_rtmtu_update(struct ifnet *);

#if IF_CLONE_LIST
static int	if_clone_list(int count, int * total, user_addr_t dst);
#endif /* IF_CLONE_LIST */

MALLOC_DEFINE(M_IFADDR, "ifaddr", "interface address");

struct	ifnethead ifnet_head = TAILQ_HEAD_INITIALIZER(ifnet_head);

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
	ifa->ifa_debug &= ~IFD_ATTACHED;

	if (ifa->ifa_detached != NULL)
		(*ifa->ifa_detached)(ifa);
}

#define INITIAL_IF_INDEXLIM	8

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
		new_ifnet_addrs = _MALLOC(n, M_IFADDR, M_WAITOK);
		if (new_ifnet_addrs == NULL) {
			--if_index;
			return -1;
		}

		new_ifindex2ifnet = new_ifnet_addrs 
			+ new_if_indexlim * sizeof(caddr_t);
		bzero(new_ifnet_addrs, n);
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
		while ((bytoff < ifc->ifc_bmlen)
		    && (ifc->ifc_units[bytoff] == 0xff))
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
	size_t i;

	for (ifc = LIST_FIRST(&if_cloners); ifc != NULL;) {
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
		i = 0xffff;
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
		return ENOBUFS;
	bzero(ifc->ifc_units, len);
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

	return 0;
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

#if IF_CLONE_LIST
/*
 * Provide list of interface cloners to userspace.
 */
static int
if_clone_list(int count, int * total, user_addr_t dst)
{
	char outbuf[IFNAMSIZ];
	struct if_clone *ifc;
	int error = 0;

	*total = if_cloners_count;
	if (dst == USER_ADDR_NULL) {
		/* Just asking how many there are. */
		return (0);
	}

	if (count < 0)
		return (EINVAL);

	count = (if_cloners_count < count) ? if_cloners_count : count;

	for (ifc = LIST_FIRST(&if_cloners); ifc != NULL && count != 0;
	     ifc = LIST_NEXT(ifc, ifc_list), count--, dst += IFNAMSIZ) {
		strlcpy(outbuf, ifc->ifc_name, IFNAMSIZ);
		error = copyout(outbuf, dst, IFNAMSIZ);
		if (error)
			break;
	}

	return (error);
}
#endif /* IF_CLONE_LIST */

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

/*
 * Locate an interface based on a complete address.
 */
/*ARGSUSED*/
struct ifaddr *
ifa_ifwithaddr(const struct sockaddr *addr)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	struct ifaddr *result = NULL;

#define	equal(a1, a2)							\
	(bcmp((const void*)(a1), (const void*)(a2),			\
	    ((const struct sockaddr *)(a1))->sa_len) == 0)

	ifnet_head_lock_shared();
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
			if (equal(addr, ifa->ifa_addr)) {
				result = ifa;
				IFA_ADDREF_LOCKED(ifa);	/* for caller */
				IFA_UNLOCK(ifa);
				break;
			}
			if ((ifp->if_flags & IFF_BROADCAST) &&
			    ifa->ifa_broadaddr != NULL &&
			    /* IP6 doesn't have broadcast */
			    ifa->ifa_broadaddr->sa_len != 0 &&
			    equal(ifa->ifa_broadaddr, addr)) {
				result = ifa;
				IFA_ADDREF_LOCKED(ifa);	/* for caller */
				IFA_UNLOCK(ifa);
				break;
			}
			IFA_UNLOCK(ifa);
		}
		ifnet_lock_done(ifp);
	}
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
				if (ifa->ifa_dstaddr &&
				    equal(addr, ifa->ifa_dstaddr)) {
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
ifa_ifwithaddr_scoped(const struct sockaddr *addr, unsigned int ifscope)
{
	struct ifaddr *result = NULL;
	struct ifnet *ifp;

	if (ifscope == IFSCOPE_NONE)
		return (ifa_ifwithaddr(addr));

	ifnet_head_lock_shared();
	if (ifscope > (unsigned int)if_index) {
		ifnet_head_done();
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
			if (equal(addr, ifa->ifa_addr)) {
				result = ifa;
				IFA_ADDREF_LOCKED(ifa);	/* for caller */
				IFA_UNLOCK(ifa);
				break;
			}
			if ((ifp->if_flags & IFF_BROADCAST) &&
			    ifa->ifa_broadaddr != NULL &&
			    /* IP6 doesn't have broadcast */
			    ifa->ifa_broadaddr->sa_len != 0 &&
			    equal(ifa->ifa_broadaddr, addr)) {
				result = ifa;
				IFA_ADDREF_LOCKED(ifa);	/* for caller */
				IFA_UNLOCK(ifa);
				break;
			}
			IFA_UNLOCK(ifa);
		}
		ifnet_lock_done(ifp);
	}
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
	if ((af != AF_INET && af != AF_INET6) ||
	    (af == AF_INET && !ip_doscopedroute) ||
	    (af == AF_INET6 && !ip6_doscopedroute))
#else
	if (af != AF_INET || !ip_doscopedroute)
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
#ifndef __APPLE__
/* This breaks tunneling application trying to install a route with
 * a specific subnet and the local address as the destination
 * It's breaks binary compatibility with previous version of MacOS X
 */
			if (
#if INET6 /* XXX: for maching gif tunnel dst as routing entry gateway */
			    addr->sa_family != AF_INET6 &&
#endif
			    ifp->if_flags & IFF_POINTOPOINT) {
				/*
				 * This is a bit broken as it doesn't
				 * take into account that the remote end may
				 * be a single node in the network we are
				 * looking for.
				 * The trouble is that we don't know the
				 * netmask for the remote end.
				 */
				if (ifa->ifa_dstaddr != 0 &&
				    equal(addr, ifa->ifa_dstaddr)) {
					IFA_ADDREF_LOCKED(ifa);
					IFA_UNLOCK(ifa);
					break;
				}
				IFA_UNLOCK(ifa);
			} else
#endif /* __APPLE__*/
			{
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
				cplim = ifa->ifa_netmask->sa_len
					+ (char *)ifa->ifa_netmask;
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
			if (equal(addr, ifa->ifa_addr) || (ifa->ifa_dstaddr &&
			    equal(addr, ifa->ifa_dstaddr))) {
				IFA_ADDREF_LOCKED(ifa);	/* for caller */
				IFA_UNLOCK(ifa);
				break;
			}
			IFA_UNLOCK(ifa);
			continue;
		}
		if (ifp->if_flags & IFF_POINTOPOINT) {
			if (ifa->ifa_dstaddr && equal(addr, ifa->ifa_dstaddr)) {
				IFA_ADDREF_LOCKED(ifa);	/* for caller */
				IFA_UNLOCK(ifa);
				break;
			}
		} else {
			if (equal(addr, ifa->ifa_addr)) {
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

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);
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
if_updown(
	struct ifnet	*ifp,
	int				up)
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
	}
	else {
		ifp->if_flags &= ~IFF_UP;
	}

	ifnet_touch_lastchange(ifp);

	/* Drop the lock to notify addresses and route */
	ifnet_lock_done(ifp);
	if (ifnet_get_address_list(ifp, &ifa) == 0) {
		for (i = 0; ifa[i] != 0; i++) {
			pfctlinput(up ? PRC_IFUP : PRC_IFDOWN, ifa[i]->ifa_addr);
		}
		ifnet_free_address_list(ifa);
	}
	rt_ifmsg(ifp);

	if (!up)
		if_qflush(ifp, 0);

	/* Inform all transmit queues about the new link state */
	IFCQ_LOCK(ifq);
	ifnet_update_sndq(ifq, up ? CLASSQ_EV_LINK_UP : CLASSQ_EV_LINK_DOWN);
	IFCQ_UNLOCK(ifq);

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
#if PF_ALTQ
	if (IFCQ_IS_DRAINING(ifq))
		ifq->ifcq_drain = 0;
	if (ALTQ_IS_ENABLED(IFCQ_ALTQ(ifq)))
		ALTQ_PURGE(IFCQ_ALTQ(ifq));
#endif /* PF_ALTQ */

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
#if PF_ALTQ
	if (IFCQ_IS_DRAINING(ifq)) {
		VERIFY((signed)(ifq->ifcq_drain - cnt) >= 0);
		ifq->ifcq_drain -= cnt;
	}
	if (ALTQ_IS_ENABLED(IFCQ_ALTQ(ifq)))
		ALTQ_PURGE_SC(IFCQ_ALTQ(ifq), sc, flow, a_cnt, a_len);
#endif /* PF_ALTQ */

	if (!ifq_locked)
		IFCQ_UNLOCK(ifq);

	if (packets != NULL)
		*packets = cnt + a_cnt;
	if (bytes != NULL)
		*bytes = len + a_len;
}

/*
 * Map interface name to
 * interface structure pointer.
 */
struct ifnet *
ifunit(const char *name)
{
	char namebuf[IFNAMSIZ + 1];
	const char *cp;
	struct ifnet *ifp;
	int unit;
	unsigned len, m;
	char c;

	len = strlen(name);
	if (len < 2 || len > IFNAMSIZ)
		return (NULL);
	cp = name + len - 1;
	c = *cp;
	if (c < '0' || c > '9')
		return (NULL);		/* trailing garbage */
	unit = 0;
	m = 1;
	do {
		if (cp == name)
			return (NULL);	/* no interface name */
		unit += (c - '0') * m;
		if (unit > 1000000)
			return (NULL);	/* number is unreasonable */
		m *= 10;
		c = *--cp;
	} while (c >= '0' && c <= '9');
	len = cp - name + 1;
	bcopy(name, namebuf, len);
	namebuf[len] = '\0';
	/*
	 * Now search all the interfaces for this name/number
	 */
	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		if (strncmp(ifp->if_name, namebuf, len))
			continue;
		if (unit == ifp->if_unit)
			break;
	}
	ifnet_head_done();
	return (ifp);
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

	if ( (sa->sa_family != AF_LINK) || (sdl->sdl_nlen == 0) ||
	     (sdl->sdl_nlen > IFNAMSIZ) )
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


/*
 * Interface ioctls.
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
	case SIOCGIFCONF32: {			/* struct ifconf32 */
		struct ifconf32 ifc;
		bcopy(data, &ifc, sizeof (ifc));
		error = ifconf(cmd, CAST_USER_ADDR_T(ifc.ifc_req),
		    &ifc.ifc_len);
		bcopy(&ifc, data, sizeof (ifc));
		goto done;
	}

	case SIOCGIFCONF64:			/* struct ifconf64 */
	case OSIOCGIFCONF64: {			/* struct ifconf64 */
		struct ifconf64 ifc;
		bcopy(data, &ifc, sizeof (ifc));
		error = ifconf(cmd, ifc.ifc_req, &ifc.ifc_len);
		bcopy(&ifc, data, sizeof (ifc));
		goto done;
	}

#if IF_CLONE_LIST
	case SIOCIFGCLONERS32: {		/* struct if_clonereq32 */
		struct if_clonereq32 ifcr;
		bcopy(data, &ifcr, sizeof (ifcr));
		error = if_clone_list(ifcr.ifcr_count, &ifcr.ifcr_total,
		    CAST_USER_ADDR_T(ifcr.ifcru_buffer));
		bcopy(&ifcr, data, sizeof (ifcr));
		goto done;
	}

	case SIOCIFGCLONERS64: {		/* struct if_clonereq64 */
		struct if_clonereq64 ifcr;
		bcopy(data, &ifcr, sizeof (ifcr));
		error = if_clone_list(ifcr.ifcr_count, &ifcr.ifcr_total,
		    ifcr.ifcru_buffer);
		bcopy(&ifcr, data, sizeof (ifcr));
		goto done;
	}
#endif /* IF_CLONE_LIST */

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
	case SIOCGIFMAC:			/* struct ifreq */
	case SIOCGIFMETRIC:			/* struct ifreq */
	case SIOCGIFMTU:			/* struct ifreq */
	case SIOCGIFPHYS:			/* struct ifreq */
	case SIOCSIFFLAGS:			/* struct ifreq */
	case SIOCSIFCAP:			/* struct ifreq */
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
	case SIOCGIFLINKQUALITYMETRIC: {	/* struct ifreq */
		struct ifreq ifr;
		bcopy(data, &ifr, sizeof (ifr));
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
	case SIOCSIFPHYADDR: {			/* struct ifaliasreq */
		bcopy(((struct ifaliasreq *)(void *)data)->ifra_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;
	}

#if INET6
	case SIOCSIFPHYADDR_IN6_32: {		/* struct in6_aliasreq_32 */
		bcopy(((struct in6_aliasreq_32 *)(void *)data)->ifra_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;
	}

	case SIOCSIFPHYADDR_IN6_64: {		/* struct in6_aliasreq_64 */
		bcopy(((struct in6_aliasreq_64 *)(void *)data)->ifra_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;
	}
#endif

	case SIOCSLIFPHYADDR:			/* struct if_laddrreq */
	case SIOCGLIFPHYADDR: {			/* struct if_laddrreq */
		bcopy(((struct if_laddrreq *)(void *)data)->iflr_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;
	}

	case SIOCGIFSTATUS: {			/* struct ifstat */
		ifs = _MALLOC(sizeof (*ifs), M_DEVBUF, M_WAITOK);
		if (ifs == NULL) {
			error = ENOMEM;
			dlil_if_unlock();
			goto done;
		}
		bcopy(data, ifs, sizeof (*ifs));
		ifs->ifs_name[IFNAMSIZ - 1] = '\0';
		ifp = ifunit(ifs->ifs_name);
		break;
	}

	case SIOCGIFMEDIA32: {			/* struct ifmediareq32 */
		bcopy(((struct ifmediareq32 *)(void *)data)->ifm_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;
	}

	case SIOCGIFMEDIA64: {			/* struct ifmediareq64 */
		bcopy(((struct ifmediareq64 *)(void *)data)->ifm_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;
	}

	case SIOCSIFDESC:			/* struct if_descreq */
	case SIOCGIFDESC: {			/* struct if_descreq */
		bcopy(((struct if_descreq *)(void *)data)->ifdr_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;
	}

	case SIOCSIFLINKPARAMS:			/* struct if_linkparamsreq */
	case SIOCGIFLINKPARAMS: {		/* struct if_linkparamsreq */
		bcopy(((struct if_linkparamsreq *)(void *)data)->iflpr_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;
	}

	case SIOCGIFQUEUESTATS: {		/* struct if_qstatsreq */
		bcopy(((struct if_qstatsreq *)(void *)data)->ifqr_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;
	}

	case SIOCSIFTHROTTLE:			/* struct if_throttlereq */
	case SIOCGIFTHROTTLE: {			/* struct if_throttlereq */
		bcopy(((struct if_throttlereq *)(void *)data)->ifthr_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;
	}

	default: {
		/*
		 * This is a bad assumption, but the code seems to
		 * have been doing this in the past; caveat emptor.
		 */
		bcopy(((struct ifreq *)(void *)data)->ifr_name,
		    ifname, IFNAMSIZ);
		ifp = ifunit(ifname);
		break;
	}
	}
	dlil_if_unlock();

	if (ifp == NULL) {
		error = ENXIO;
		goto done;
	}

	switch (cmd) {
	case SIOCSIFPHYADDR:			/* struct ifaliasreq */
#if INET6
	case SIOCSIFPHYADDR_IN6_32:		/* struct in6_aliasreq_32 */
	case SIOCSIFPHYADDR_IN6_64:		/* struct in6_aliasreq_64 */
#endif
	case SIOCSLIFPHYADDR:			/* struct if_laddrreq */
		error = proc_suser(p);
		if (error != 0)
			break;

		error = ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family,
		    cmd, data);
		if (error != 0)
			break;

		ifnet_touch_lastchange(ifp);
		break;

	case SIOCGIFSTATUS:			/* struct ifstat */
		VERIFY(ifs != NULL);
		ifs->ascii[0] = '\0';

		error = ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family,
		    cmd, (caddr_t)ifs);

		bcopy(ifs, data, sizeof (*ifs));
		break;

	case SIOCGLIFPHYADDR:			/* struct if_laddrreq */
	case SIOCGIFMEDIA32:			/* struct ifmediareq32 */
	case SIOCGIFMEDIA64:			/* struct ifmediareq64 */
		error = ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family,
		    cmd, data);
		break;

	case SIOCSIFDESC: {			/* struct if_descreq */
		struct if_descreq *ifdr = (struct if_descreq *)(void *)data;
		u_int32_t ifdr_len;

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
		struct if_descreq *ifdr = (struct if_descreq *)(void *)data;
		u_int32_t ifdr_len;

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

	case SIOCSIFLINKPARAMS: {		/* struct if_linkparamsreq */
		struct if_linkparamsreq *iflpr =
		    (struct if_linkparamsreq *)(void *)data;
		struct ifclassq *ifq = &ifp->if_snd;
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
		struct if_linkparamsreq *iflpr =
		    (struct if_linkparamsreq *)(void *)data;
		struct ifclassq *ifq = &ifp->if_snd;
		u_int32_t sched_type = PKTSCHEDT_NONE, flags = 0;
		u_int64_t tbr_bw = 0, tbr_pct = 0;

		IFCQ_LOCK(ifq);
#if PF_ALTQ
		if (ALTQ_IS_ENABLED(IFCQ_ALTQ(ifq))) {
			sched_type = IFCQ_ALTQ(ifq)->altq_type;
			flags |= IFLPRF_ALTQ;
		} else
#endif /* PF_ALTQ */
		{
			if (IFCQ_IS_ENABLED(ifq))
				sched_type = ifq->ifcq_type;
		}
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
		break;
	}

	case SIOCGIFQUEUESTATS: {		/* struct if_qstatsreq */
		struct if_qstatsreq *ifqr = (struct if_qstatsreq *)(void *)data;
		u_int32_t ifqr_len, ifqr_slot;

		bcopy(&ifqr->ifqr_slot, &ifqr_slot, sizeof (ifqr_slot));
		bcopy(&ifqr->ifqr_len, &ifqr_len, sizeof (ifqr_len));
		error = ifclassq_getqstats(&ifp->if_snd, ifqr_slot,
		    ifqr->ifqr_buf, &ifqr_len);
		if (error != 0)
			ifqr_len = 0;
		bcopy(&ifqr_len, &ifqr->ifqr_len, sizeof (ifqr_len));
		break;
	}

	case SIOCSIFTHROTTLE: {			/* struct if_throttlereq */
		struct if_throttlereq *ifthr =
		    (struct if_throttlereq *)(void *)data;
		u_int32_t ifthr_level;

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
		struct if_throttlereq *ifthr =
		    (struct if_throttlereq *)(void *)data;
		u_int32_t ifthr_level;

		if ((error = ifnet_get_throttle(ifp, &ifthr_level)) == 0) {
			bcopy(&ifthr_level, &ifthr->ifthr_level,
			    sizeof (ifthr_level));
		}
		break;
	}

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
			error = ifnet_ioctl(ifp,
			    so->so_proto->pr_domain->dom_family, cmd, data);
		}
		break;
	}

done:
	if (ifs != NULL)
		_FREE(ifs, M_DEVBUF);

	return (error);
}

static int
ifioctl_ifreq(struct socket *so, u_long cmd, struct ifreq *ifr, struct proc *p)
{
	struct ifnet *ifp;
	u_long ocmd = cmd;
	int error = 0;
	struct kev_msg ev_msg;
	struct net_event_data ev_data;

	bzero(&ev_data, sizeof (struct net_event_data));
	bzero(&ev_msg, sizeof (struct kev_msg));

	ifr->ifr_name[IFNAMSIZ - 1] = '\0';

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

	ifp = ifunit(ifr->ifr_name);
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
#endif
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

	case SIOCGIFLINKQUALITYMETRIC:
		ifnet_lock_shared(ifp);
		ifr->ifr_link_quality_metric = ifp->if_lqm;
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
		(void) ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family,
		    cmd, (caddr_t)ifr);

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
		kev_post_msg(&ev_msg);

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
		error = ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family,
		    cmd, (caddr_t)ifr);

		ifnet_touch_lastchange(ifp);
		break;

#if CONFIG_MACF_NET
	case SIOCSIFMAC:
		error = mac_ifnet_label_set(kauth_cred_get(), ifr, ifp);
		break;
#endif
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
		kev_post_msg(&ev_msg);

		ifnet_touch_lastchange(ifp);
		break;

	case SIOCSIFPHYS:
		error = proc_suser(p);
		if (error != 0)
			break;

		error = ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family,
		    cmd, (caddr_t)ifr);
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
		kev_post_msg(&ev_msg);

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
		error = ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family,
		    cmd, (caddr_t)ifr);
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
		kev_post_msg(&ev_msg);

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
#endif
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
		kev_post_msg(&ev_msg);

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

		error = ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family,
		    cmd, (caddr_t)ifr);
		if (error != 0)
			break;

		ifnet_touch_lastchange(ifp);
		break;

	case SIOCGIFPSRCADDR:
	case SIOCGIFPDSTADDR:
	case SIOCGIFGENERIC:
	case SIOCGIFDEVMTU:
	case SIOCGIFVLAN:
	case SIOCGIFBOND:
		error = ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family,
		    cmd, (caddr_t)ifr);
		break;

	case SIOCSIFOPPORTUNISTIC:
	case SIOCGIFOPPORTUNISTIC:
		error = ifnet_getset_opportunistic(ifp, cmd, ifr, p);
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
			error = ifnet_ioctl(ifp,
			    so->so_proto->pr_domain->dom_family, cmd,
			    (caddr_t)ifr);
		}
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
	return(error);
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
		log(LOG_INFO, "%s%d: promiscuous mode %s%s\n",
		    ifp->if_name, ifp->if_unit,
		    (newflags & IFF_PROMISC) != 0 ? "enable" : "disable",
		    error != 0 ? " failed" : " succeeded");
	}
	return error;
}

/*
 * Return interface configuration
 * of system.  List may be used
 * in later ioctl's (above) to get
 * other information.
 */
/*ARGSUSED*/
static int
ifconf(u_long cmd, user_addr_t ifrp, int * ret_space)
{
	struct ifnet *ifp = NULL;
	struct ifaddr *ifa;
	struct ifreq ifr;
	int error = 0;
	size_t space;

	/*
	 * Zero the ifr buffer to make sure we don't
	 * disclose the contents of the stack.
	 */
	bzero(&ifr, sizeof(struct ifreq));

	space = *ret_space;
	ifnet_head_lock_shared();
	for (ifp = ifnet_head.tqh_first; space > sizeof(ifr) &&
	    ifp; ifp = ifp->if_link.tqe_next) {
		char workbuf[64];
		size_t ifnlen, addrs;

		ifnlen = snprintf(workbuf, sizeof(workbuf),
		    "%s%d", ifp->if_name, ifp->if_unit);
		if(ifnlen + 1 > sizeof ifr.ifr_name) {
			error = ENAMETOOLONG;
			break;
		} else {
			strlcpy(ifr.ifr_name, workbuf, IFNAMSIZ);
		}

		ifnet_lock_shared(ifp);

		addrs = 0;
		ifa = ifp->if_addrhead.tqh_first;
		for ( ; space > sizeof (ifr) && ifa;
		    ifa = ifa->ifa_link.tqe_next) {
			struct sockaddr *sa;

			IFA_LOCK(ifa);
			sa = ifa->ifa_addr;
#ifndef __APPLE__
			if (curproc->p_prison && prison_if(curproc, sa)) {
				IFA_UNLOCK(ifa);
				continue;
			}
#endif
			addrs++;
			if (cmd == OSIOCGIFCONF32 || cmd == OSIOCGIFCONF64) {
				struct osockaddr *osa =
				    (struct osockaddr *)(void *)&ifr.ifr_addr;
				ifr.ifr_addr = *sa;
				osa->sa_family = sa->sa_family;
				error = copyout((caddr_t)&ifr, ifrp,
				    sizeof (ifr));
				ifrp += sizeof(struct ifreq);
			} else if (sa->sa_len <= sizeof(*sa)) {
				ifr.ifr_addr = *sa;
				error = copyout((caddr_t)&ifr, ifrp,
				    sizeof (ifr));
				ifrp += sizeof(struct ifreq);
			} else {
				if (space <
				    sizeof (ifr) + sa->sa_len - sizeof(*sa)) {
					IFA_UNLOCK(ifa);
					break;
				}
				space -= sa->sa_len - sizeof(*sa);
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
			bzero((caddr_t)&ifr.ifr_addr, sizeof(ifr.ifr_addr));
			error = copyout((caddr_t)&ifr, ifrp, sizeof (ifr));
			if (error)
				break;
			space -= sizeof (ifr);
			ifrp += sizeof(struct ifreq);
		}
	}
	ifnet_head_done();
	*ret_space -= space;
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
	return error;
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
		if (!equal(sa, ifma->ifma_addr)) {
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
static struct sockaddr*
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
		MALLOC(copy, struct sockaddr*, original->sa_len,
		    M_IFADDR, M_WAITOK);
		if (copy != NULL)
			bcopy(original, copy, original->sa_len);
		return (copy);
	}

	switch (original->sa_family) {
		case AF_LINK: {
			const struct sockaddr_dl *sdl_original =
			    (struct sockaddr_dl*)(uintptr_t)(size_t)original;

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
			aptr = (const u_char*)original->sa_data;
		}
		break;
	}

	if (alen == 0 || aptr == NULL)
		return (NULL);

	len = alen + offsetof(struct sockaddr_dl, sdl_data);
	MALLOC(sdl_new, struct sockaddr_dl*, len, M_IFADDR, M_WAITOK);

	if (sdl_new != NULL) {
		bzero(sdl_new, len);
		sdl_new->sdl_len = len;
		sdl_new->sdl_family = AF_LINK;
		sdl_new->sdl_alen = alen;
		bcopy(aptr, LLADDR(sdl_new), alen);
	}

	return ((struct sockaddr*)sdl_new);
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
 * ioctl, ifnet_add_multicast(), AppleTalk, if_bond.
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
 * ioctl, ifnet_remove_multicast(), AppleTalk, if_bond.
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
			if (!equal(sa, ifma->ifma_addr) ||
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
 * We don't use if_setlladdr, our interfaces are responsible for
 * handling the SIOCSIFLLADDR ioctl.
 */
#ifndef __APPLE__
int
if_setlladdr(struct ifnet *ifp, const u_char *lladdr, int len)
{
	...
}
#endif

SYSCTL_NODE(_net, PF_LINK, link, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "Link layers");
SYSCTL_NODE(_net_link, 0, generic, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "Generic link-management");


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

	return 0;
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

	if (use_routegenid)
		routegenid_update();
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
static
void if_rtmtu_update(struct ifnet *ifp)
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

	if (use_routegenid)
		routegenid_update();
}

__private_extern__ void
if_data_internal_to_if_data(struct ifnet *ifp,
    const struct if_data_internal *if_data_int, struct if_data *if_data)
{
#pragma unused(ifp)
#define COPYFIELD(fld)		if_data->fld = if_data_int->fld
#define COPYFIELD32(fld)	if_data->fld = (u_int32_t)(if_data_int->fld)
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

#if IF_LASTCHANGEUPTIME
	if_data->ifi_lastchange.tv_sec += boottime_sec();
#endif

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
#define COPYFIELD64(fld)	if_data64->fld = if_data_int->fld
#define COPYFIELD64_ATOMIC(fld) do {					\
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

	/* Note these two fields are actually 32 bit, so doing COPYFIELD64_ATOMIC will
	 * cause them to be misaligned
	 */
	COPYFIELD64(ifi_recvtiming);
	COPYFIELD64(ifi_xmittiming);

	if_data64->ifi_lastchange.tv_sec = if_data_int->ifi_lastchange.tv_sec;
	if_data64->ifi_lastchange.tv_usec = if_data_int->ifi_lastchange.tv_usec;

#if IF_LASTCHANGEUPTIME
	if_data64->ifi_lastchange.tv_sec += boottime_sec();
#endif

#undef COPYFIELD64
}

__private_extern__ void
if_copy_traffic_class(struct ifnet *ifp,
    struct if_traffic_class *if_tc)
{
#define COPY_IF_TC_FIELD64_ATOMIC(fld) do {			\
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
#define COPY_IF_DE_FIELD64_ATOMIC(fld) do {			\
	atomic_get_64(if_de->fld,				\
	    (u_int64_t *)(void *)(uintptr_t)&ifp->if_data.fld);	\
} while (0)

	bzero(if_de, sizeof (*if_de));
	COPY_IF_DE_FIELD64_ATOMIC(ifi_alignerrs);

#undef COPY_IF_DE_FIELD64_ATOMIC
}

void
if_copy_packet_stats(struct ifnet *ifp, struct if_packet_stats *if_ps)
{
#define COPY_IF_PS_TCP_FIELD64_ATOMIC(fld) do {				\
	atomic_get_64(if_ps->ifi_tcp_##fld,				\
	    (u_int64_t *)(void *)(uintptr_t)&ifp->if_tcp_stat->fld);	\
} while (0)

#define COPY_IF_PS_UDP_FIELD64_ATOMIC(fld) do {				\
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
		 * or carved out of a larger block; e.g. AppleTalk addresses.
		 * Only free it if it was allocated via MALLOC or via the
		 * corresponding per-address family allocator.  Otherwise,
		 * leave it alone.
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
