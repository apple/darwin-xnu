/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
#if INET6
#include <netinet6/in6_var.h>
#include <netinet6/in6_ifattach.h>
#endif
#endif

extern u_long route_generation;
extern int use_routegenid;
extern int dlil_multithreaded_input;
extern struct dlil_threading_info *dlil_lo_thread_ptr;

#if CONFIG_MACF_NET 
#include <security/mac_framework.h>
#endif

/*
 * System initialization
 */

static int ifconf(u_long cmd, user_addr_t ifrp, int * ret_space);
static void if_qflush(struct ifqueue *);
__private_extern__ void link_rtrequest(int, struct rtentry *, struct sockaddr *);
void if_rtproto_del(struct ifnet *ifp, int protocol);

static int if_rtmtu(struct radix_node *, void *);
static void if_rtmtu_update(struct ifnet *);

static struct	if_clone *if_clone_lookup(const char *, int *);
#ifdef IF_CLONE_LIST
static int	if_clone_list(int count, int * total, user_addr_t dst);
#endif

MALLOC_DEFINE(M_IFADDR, "ifaddr", "interface address");
MALLOC_DEFINE(M_IFMADDR, "ether_multi", "link-level multicast address");

int	ifqmaxlen = IFQ_MAXLEN;
struct	ifnethead ifnet_head = TAILQ_HEAD_INITIALIZER(ifnet_head);

static int	if_cloners_count;
LIST_HEAD(, if_clone) if_cloners = LIST_HEAD_INITIALIZER(if_cloners);

static struct ifaddr *ifa_ifwithnet_common(const struct sockaddr *,
    unsigned int);

#if INET6
/*
 * XXX: declare here to avoid to include many inet6 related files..
 * should be more generalized?
 */
extern void	nd6_setmtu(struct ifnet *);
#endif

#define M_CLONE		M_IFADDR

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
if_attach_ifa(
	struct ifnet *ifp,
	struct ifaddr *ifa)
{
	ifnet_lock_assert(ifp, LCK_MTX_ASSERT_OWNED);
	if (ifa->ifa_debug & IFA_ATTACHED) {
		panic("if_attach_ifa: Attempted to attach address that's already attached!\n");
	}
	ifaref(ifa);
	ifa->ifa_debug |= IFA_ATTACHED;
	TAILQ_INSERT_TAIL(&ifp->if_addrhead, ifa, ifa_link);
}

__private_extern__ void
if_detach_ifa(
	struct ifnet *ifp,
	struct ifaddr *ifa)
{
	ifnet_lock_assert(ifp, LCK_MTX_ASSERT_OWNED);
#if 1
	/* Debugging code */
	if ((ifa->ifa_debug & IFA_ATTACHED) == 0) {
		printf("if_detach_ifa: ifa is not attached to any interface! flags=%lu\n", ifa->ifa_debug);
		return;
	}
	else {
		struct ifaddr *ifa2;
		TAILQ_FOREACH(ifa2, &ifp->if_addrhead, ifa_link) {
			if (ifa2 == ifa)
				break;
		}
		if (ifa2 != ifa) {
			printf("if_detach_ifa: Attempted to detach IFA that was not attached!\n");
		}	
	}
#endif
	TAILQ_REMOVE(&ifp->if_addrhead, ifa, ifa_link);
	ifa->ifa_debug &= ~IFA_ATTACHED;
	ifafree(ifa);
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
		ifnet_addrs = (struct ifaddr **)new_ifnet_addrs;
		ifindex2ifnet = (struct ifnet **)new_ifindex2ifnet;
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
if_clone_create(char *name, int len)
{
	struct if_clone *ifc;
	char *dp;
	int wildcard, bytoff, bitoff;
	int unit;
	int err;

	ifc = if_clone_lookup(name, &unit);
	if (ifc == NULL)
		return (EINVAL);

	if (ifunit(name) != NULL)
		return (EEXIST);

	bytoff = bitoff = 0;
	wildcard = (unit < 0);
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

	err = (*ifc->ifc_create)(ifc, unit);
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
			panic("if_clone_create(): interface name too long");
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
	int unit;

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

static struct if_clone *
if_clone_lookup(const char *name, int *unitp)
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
		i = -1;
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
void
if_clone_attach(struct if_clone *ifc)
{
	int bytoff, bitoff;
	int err;
	int len, maxclone;
	int unit;

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
	bzero(ifc->ifc_units, len);
	ifc->ifc_bmlen = len;

	LIST_INSERT_HEAD(&if_cloners, ifc, ifc_list);
	if_cloners_count++;

	for (unit = 0; unit < ifc->ifc_minifs; unit++) {
		err = (*ifc->ifc_create)(ifc, unit);
		KASSERT(err == 0,
		    ("%s: failed to create required interface %s%d",
		    __func__, ifc->ifc_name, unit));

		/* Allocate the unit in the bitmap. */
		bytoff = unit >> 3;
		bitoff = unit - (bytoff << 3);
		ifc->ifc_units[bytoff] |= (1 << bitoff);
	}
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

#ifdef IF_CLONE_LIST
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
#endif IF_CLONE_LIST

__private_extern__ int
ifa_foraddr(
	unsigned int addr)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	unsigned int addr2;
	int	result = 0;
	
	ifnet_head_lock_shared();
	for (ifp = ifnet_head.tqh_first; ifp && !result; ifp = ifp->if_link.tqe_next) {
		ifnet_lock_shared(ifp);
	    for (ifa = ifp->if_addrhead.tqh_first; ifa;
		 ifa = ifa->ifa_link.tqe_next) {
			if (ifa->ifa_addr->sa_family != AF_INET)
				continue;
			addr2 = IA_SIN(ifa)->sin_addr.s_addr;
			
			if (addr == addr2) {
				result = 1;
				break;
			}
		}
		ifnet_lock_done(ifp);
	}
	ifnet_head_done();
	
	return result;
}

/*
 * Return the first (primary) address of a given family on an interface.
 */
__private_extern__ struct ifaddr *
ifa_ifpgetprimary(struct ifnet *ifp, int family)
{
	struct ifaddr *ifa0 = NULL, *ifa;

	ifnet_lock_shared(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
		if (ifa->ifa_addr->sa_family == family && ifa0 == NULL) {
			ifa0 = ifa;
			break;
		}
	}
	if (ifa0 != NULL)
		ifaref(ifa0);
	ifnet_lock_done(ifp);

	return (ifa0);
}

/*
 * Locate an interface based on a complete address.
 */
/*ARGSUSED*/
struct ifaddr *
ifa_ifwithaddr(
	const struct sockaddr *addr)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	struct ifaddr *result = NULL;

#define	equal(a1, a2) \
  (bcmp((const void*)(a1), (const void*)(a2), ((const struct sockaddr *)(a1))->sa_len) == 0)
  
	ifnet_head_lock_shared();
	for (ifp = ifnet_head.tqh_first; ifp && !result; ifp = ifp->if_link.tqe_next) {
		ifnet_lock_shared(ifp);
		for (ifa = ifp->if_addrhead.tqh_first; ifa;
			 ifa = ifa->ifa_link.tqe_next) {
			if (ifa->ifa_addr->sa_family != addr->sa_family)
				continue;
			if (equal(addr, ifa->ifa_addr)) {
				result = ifa;
				break;
			}
			if ((ifp->if_flags & IFF_BROADCAST) && ifa->ifa_broadaddr &&
				/* IP6 doesn't have broadcast */
				ifa->ifa_broadaddr->sa_len != 0 &&
				equal(ifa->ifa_broadaddr, addr)) {
				result = ifa;
				break;
			}
		}
		if (result)
			ifaref(result);
		ifnet_lock_done(ifp);
	}
	ifnet_head_done();
	
	return result;
}
/*
 * Locate the point to point interface with a given destination address.
 */
/*ARGSUSED*/
struct ifaddr *
ifa_ifwithdstaddr(
	const struct sockaddr *addr)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	struct ifaddr *result = NULL;

	ifnet_head_lock_shared();
	for (ifp = ifnet_head.tqh_first; ifp && !result; ifp = ifp->if_link.tqe_next) {
	    if (ifp->if_flags & IFF_POINTOPOINT) {
			ifnet_lock_shared(ifp);
			for (ifa = ifp->if_addrhead.tqh_first; ifa;
				 ifa = ifa->ifa_link.tqe_next) {
				if (ifa->ifa_addr->sa_family != addr->sa_family)
					continue;
				if (ifa->ifa_dstaddr && equal(addr, ifa->ifa_dstaddr)) {
					result = ifa;
					break;
				}
			}
			if (result)
				ifaref(result);
			ifnet_lock_done(ifp);
		}
	}
	ifnet_head_done();
	return result;
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
		 * to search for a given address of an interface.
		 */
		ifnet_lock_shared(ifp);
		for (ifa = ifp->if_addrhead.tqh_first; ifa != NULL;
		    ifa = ifa->ifa_link.tqe_next) {
			if (ifa->ifa_addr->sa_family != addr->sa_family)
				continue;
			if (equal(addr, ifa->ifa_addr)) {
				result = ifa;
				break;
			}
			if ((ifp->if_flags & IFF_BROADCAST) &&
			    ifa->ifa_broadaddr != NULL &&
			    /* IP6 doesn't have broadcast */
			    ifa->ifa_broadaddr->sa_len != 0 &&
			    equal(ifa->ifa_broadaddr, addr)) {
				result = ifa;
				break;
			}
		}
		if (result != NULL)
			ifaref(result);
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
	struct ifaddr *ifa_maybe = (struct ifaddr *) 0;
	u_int af = addr->sa_family;
	const char *addr_data = addr->sa_data, *cplim;

	if (!ip_doscopedroute || addr->sa_family != AF_INET)
		ifscope = IFSCOPE_NONE;

	ifnet_head_lock_shared();
	/*
	 * AF_LINK addresses can be looked up directly by their index number,
	 * so do that if we can.
	 */
	if (af == AF_LINK) {
	    const struct sockaddr_dl *sdl = (const struct sockaddr_dl *)addr;
	    if (sdl->sdl_index && sdl->sdl_index <= if_index) {
			ifa = ifnet_addrs[sdl->sdl_index - 1];
	
			if (ifa)
				ifaref(ifa);
			
			ifnet_head_done();
			return ifa;
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

			if (ifa->ifa_addr->sa_family != af)
next:				continue;
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
				if (ifa->ifa_dstaddr != 0
				    && equal(addr, ifa->ifa_dstaddr)) {
				    break;
 				}
			} else
#endif /* __APPLE__*/
			{
				/*
				 * If we're looking up with a scope,
				 * find using a matching interface.
				 */
				if (ifscope != IFSCOPE_NONE &&
				    ifp->if_index != ifscope)
					continue;

				/*
				 * if we have a special address handler,
				 * then use it instead of the generic one.
				 */
	          		if (ifa->ifa_claim_addr) {
					if (ifa->ifa_claim_addr(ifa, addr)) {
						break;
					} else {
						continue;
					}
				}

				/*
				 * Scan all the bits in the ifa's address.
				 * If a bit dissagrees with what we are
				 * looking for, mask it with the netmask
				 * to see if it really matters.
				 * (A byte at a time)
				 */
				if (ifa->ifa_netmask == 0)
					continue;
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
				if (ifa_maybe == 0 ||
				    rn_refines((caddr_t)ifa->ifa_netmask,
				    (caddr_t)ifa_maybe->ifa_netmask)) {
					ifaref(ifa);
					if (ifa_maybe)
						ifafree(ifa_maybe);
					ifa_maybe = ifa;
				}
			}
		}
		
		if (ifa) {
			ifaref(ifa);
		}
		
		/*
		 * ifa is set if we found an exact match.
		 * take a reference to the ifa before
		 * releasing the ifp lock
		 */
		ifnet_lock_done(ifp);
		
		if (ifa) {
			break;
		}
	}
	ifnet_head_done();
	if (!ifa)
		ifa = ifa_maybe;
	else if (ifa_maybe) {
		ifafree(ifa_maybe);
		ifa_maybe = NULL;
	}
	return ifa;
}

/*
 * Find an interface address specific to an interface best matching
 * a given address.
 */
struct ifaddr *
ifaof_ifpforaddr(
	const struct sockaddr *addr,
	struct ifnet *ifp)
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
		if (ifa->ifa_addr->sa_family != af)
			continue;
		if (ifa_maybe == 0)
			ifa_maybe = ifa;
		if (ifa->ifa_netmask == 0) {
			if (equal(addr, ifa->ifa_addr) ||
			    (ifa->ifa_dstaddr && equal(addr, ifa->ifa_dstaddr)))
			    break;
			continue;
		}
		if (ifp->if_flags & IFF_POINTOPOINT) {
			if (equal(addr, ifa->ifa_dstaddr))
				break;
		} else {
		    	if (equal(addr, ifa->ifa_addr)) {
				/* exact match */
				break;
			}
			cp = addr->sa_data;
			cp2 = ifa->ifa_addr->sa_data;
			cp3 = ifa->ifa_netmask->sa_data;
			cplim = ifa->ifa_netmask->sa_len + (char *)ifa->ifa_netmask;
			for (; cp3 < cplim; cp3++)
				if ((*cp++ ^ *cp2++) & *cp3)
					break;
			if (cp3 == cplim) {
				/* subnet match */
				if (better_ifa_maybe == NULL) {
					better_ifa_maybe = ifa;
				}
			}
		}
	}
	
	if (ifa == NULL) {
		if (better_ifa_maybe != NULL) {
			ifa = better_ifa_maybe;
		} else {
			ifa = ifa_maybe;
		}
	}
	if (ifa) ifaref(ifa);
	
	ifnet_lock_done(ifp);
	return ifa;
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

	if (cmd != RTM_ADD || ((ifa = rt->rt_ifa) == 0) ||
	    ((ifp = ifa->ifa_ifp) == 0) || ((dst = rt_key(rt)) == 0))
		return;
	ifa = ifaof_ifpforaddr(dst, ifp);
	if (ifa) {
		rtsetifa(rt, ifa);
		if (ifa->ifa_rtrequest && ifa->ifa_rtrequest != link_rtrequest)
			ifa->ifa_rtrequest(cmd, rt, sa);
		ifafree(ifa);
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
	
	/* Aquire the lock to clear the changing flag and flush the send queue */
	ifnet_lock_exclusive(ifp);
	if (!up)
		if_qflush(&ifp->if_snd);
	ifp->if_eflags &= ~IFEF_UPDOWNCHANGE;
	wakeup(&ifp->if_eflags);
	
	return;
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
static void
if_qflush(struct ifqueue *ifq)
{
	struct mbuf *m, *n;

	n = ifq->ifq_head;
	while ((m = n) != 0) {
		n = m->m_act;
		m_freem(m);
	}
	ifq->ifq_head = NULL;
	ifq->ifq_tail = NULL;
	ifq->ifq_len = 0;
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
		return NULL;
	cp = name + len - 1;
	c = *cp;
	if (c < '0' || c > '9')
		return NULL;		/* trailing garbage */
	unit = 0;
	m = 1;
	do {
		if (cp == name)
			return NULL;	/* no interface name */
		unit += (c - '0') * m;
		if (unit > 1000000)
			return NULL;	/* number is unreasonable */
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
	struct sockaddr_dl *sdl = (struct sockaddr_dl *)sa;

	if ( (sa->sa_family != AF_LINK) || (sdl->sdl_nlen == 0) ||
	     (sdl->sdl_nlen > IFNAMSIZ) )
		return NULL;

	/*
	 * ifunit wants a null-terminated name.  It may not be null-terminated
	 * in the sockaddr.  We don't want to change the caller's sockaddr,
	 * and there might not be room to put the trailing null anyway, so we
	 * make a local copy that we know we can null terminate safely.
	 */

	bcopy(sdl->sdl_data, ifname, sdl->sdl_nlen);
	ifname[sdl->sdl_nlen] = '\0';
	return ifunit(ifname);
}


/*
 * Interface ioctls.
 */
int
ifioctl(struct socket *so, u_long cmd, caddr_t data, struct proc *p)
{
	struct ifnet *ifp;
	struct ifreq *ifr;
	struct ifstat *ifs;
	int error = 0;
	short oif_flags;
	struct kev_msg        ev_msg;
	struct net_event_data ev_data;

	switch (cmd) {
	case SIOCGIFCONF:
	case OSIOCGIFCONF:
	case SIOCGIFCONF64:
	    {
	    	struct ifconf64 *	ifc = (struct ifconf64 *)data;
		user_addr_t		user_addr;
		
		user_addr = proc_is64bit(p)
		    ? ifc->ifc_req64 : CAST_USER_ADDR_T(ifc->ifc_req);
		return (ifconf(cmd, user_addr, &ifc->ifc_len));
	    }
	    break;
	}
	ifr = (struct ifreq *)data;
	switch (cmd) {
	case SIOCIFCREATE:
	case SIOCIFDESTROY:
		error = proc_suser(p);
		if (error)
			return (error);
		return ((cmd == SIOCIFCREATE) ?
			if_clone_create(ifr->ifr_name, sizeof(ifr->ifr_name)) :
			if_clone_destroy(ifr->ifr_name));
#if IF_CLONE_LIST
	case SIOCIFGCLONERS:
	case SIOCIFGCLONERS64:
	    {
		struct if_clonereq64 *	ifcr = (struct if_clonereq64 *)data;
		user_addr = proc_is64bit(p)
		    ? ifcr->ifcr_ifcru.ifcru_buffer64
		    : CAST_USER_ADDR_T(ifcr->ifcr_ifcru.ifcru_buffer32);
		return (if_clone_list(ifcr->ifcr_count, &ifcr->ifcr_total,
				      user_data));
	    }
#endif IF_CLONE_LIST
	}

	ifp = ifunit(ifr->ifr_name);
	if (ifp == 0)
		return (ENXIO);
	switch (cmd) {

	case SIOCGIFFLAGS:
		ifnet_lock_shared(ifp);
		ifr->ifr_flags = ifp->if_flags;
		ifnet_lock_done(ifp);
		break;

#if CONFIG_MACF_NET
	case SIOCGIFMAC:
		error = mac_ifnet_label_get(kauth_cred_get(), ifr, ifp);
		if (error)
			return (error);
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

	case SIOCSIFFLAGS:
		error = proc_suser(p);
		if (error)
			return (error);

		ifnet_set_flags(ifp, ifr->ifr_flags, (u_int16_t)~IFF_CANTCHANGE);

		error = ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family, 
				   			cmd, data);

		if (error == 0) {
			 ev_msg.vendor_code    = KEV_VENDOR_APPLE;
			 ev_msg.kev_class      = KEV_NETWORK_CLASS;
			 ev_msg.kev_subclass   = KEV_DL_SUBCLASS;

			 ev_msg.event_code = KEV_DL_SIFFLAGS;
			 strlcpy(&ev_data.if_name[0], ifp->if_name, IFNAMSIZ);
			 ev_data.if_family = ifp->if_family;
			 ev_data.if_unit   = (unsigned long) ifp->if_unit;
			 ev_msg.dv[0].data_length = sizeof(struct net_event_data);
			 ev_msg.dv[0].data_ptr    = &ev_data;
			 ev_msg.dv[1].data_length = 0;
			 kev_post_msg(&ev_msg);
		}
		ifnet_touch_lastchange(ifp);
		break;

#if CONFIG_MACF_NET
	case SIOCSIFMAC:
		error = mac_ifnet_label_set(kauth_cred_get(), ifr, ifp);
		if (error)
			return (error);
		break;
#endif
	case SIOCSIFMETRIC:
		error = proc_suser(p);
		if (error)
			return (error);
		ifp->if_metric = ifr->ifr_metric;


		ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		ev_msg.kev_class      = KEV_NETWORK_CLASS;
		ev_msg.kev_subclass   = KEV_DL_SUBCLASS;
	
		ev_msg.event_code = KEV_DL_SIFMETRICS;
		strlcpy(&ev_data.if_name[0], ifp->if_name, IFNAMSIZ);
		ev_data.if_family = ifp->if_family;
		ev_data.if_unit   = (unsigned long) ifp->if_unit;
		ev_msg.dv[0].data_length = sizeof(struct net_event_data);
		ev_msg.dv[0].data_ptr    = &ev_data;

		ev_msg.dv[1].data_length = 0;
		kev_post_msg(&ev_msg);

		ifnet_touch_lastchange(ifp);
		break;

	case SIOCSIFPHYS:
		error = proc_suser(p);
		if (error)
			return error;

		error = ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family, 
							cmd, data);

		if (error == 0) {
			ev_msg.vendor_code    = KEV_VENDOR_APPLE;
			ev_msg.kev_class      = KEV_NETWORK_CLASS;
			ev_msg.kev_subclass   = KEV_DL_SUBCLASS;

			ev_msg.event_code = KEV_DL_SIFPHYS;
			strlcpy(&ev_data.if_name[0], ifp->if_name, IFNAMSIZ);
			ev_data.if_family = ifp->if_family;
			ev_data.if_unit   = (unsigned long) ifp->if_unit;
			ev_msg.dv[0].data_length = sizeof(struct net_event_data);
			ev_msg.dv[0].data_ptr    = &ev_data;
			ev_msg.dv[1].data_length = 0;
			kev_post_msg(&ev_msg);

			ifnet_touch_lastchange(ifp);
		}
		return(error);

	case SIOCSIFMTU:
	{
		u_long oldmtu = ifp->if_mtu;

		error = proc_suser(p);
		if (error)
			return (error);
		if (ifp->if_ioctl == NULL)
			return (EOPNOTSUPP);
		if (ifr->ifr_mtu < IF_MINMTU || ifr->ifr_mtu > IF_MAXMTU)
			return (EINVAL);

		error = ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family, 
				   			cmd, data);

		if (error == 0) {
		     ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		     ev_msg.kev_class      = KEV_NETWORK_CLASS;
		     ev_msg.kev_subclass   = KEV_DL_SUBCLASS;
	
		     ev_msg.event_code = KEV_DL_SIFMTU;
		     strlcpy(&ev_data.if_name[0], ifp->if_name, IFNAMSIZ);
		     ev_data.if_family = ifp->if_family;
		     ev_data.if_unit   = (unsigned long) ifp->if_unit;
		     ev_msg.dv[0].data_length = sizeof(struct net_event_data);
		     ev_msg.dv[0].data_ptr    = &ev_data;
		     ev_msg.dv[1].data_length = 0;
		     kev_post_msg(&ev_msg);

			ifnet_touch_lastchange(ifp);
			rt_ifmsg(ifp);
		}
		/*
		 * If the link MTU changed, do network layer specific procedure
		 * and update all route entries associated with the interface,
		 * so that their MTU metric gets updated.
		 */
		if (error == 0 && ifp->if_mtu != oldmtu) {
			if_rtmtu_update(ifp);
#if INET6
			nd6_setmtu(ifp);
#endif
		}
		return (error);
	}

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		error = proc_suser(p);
		if (error)
			return (error);

		/* Don't allow group membership on non-multicast interfaces. */
		if ((ifp->if_flags & IFF_MULTICAST) == 0)
			return EOPNOTSUPP;

#ifndef __APPLE__
		/* Don't let users screw up protocols' entries. */
		if (ifr->ifr_addr.sa_family != AF_LINK)
			return EINVAL;
#endif

		if (cmd == SIOCADDMULTI) {
			error = if_addmulti(ifp, &ifr->ifr_addr, NULL);
			ev_msg.event_code = KEV_DL_ADDMULTI;
		} else {
			error = if_delmulti(ifp, &ifr->ifr_addr);
			ev_msg.event_code = KEV_DL_DELMULTI;
		}
		if (error == 0) {
		     ev_msg.vendor_code    = KEV_VENDOR_APPLE;
		     ev_msg.kev_class      = KEV_NETWORK_CLASS;
		     ev_msg.kev_subclass   = KEV_DL_SUBCLASS;
		     strlcpy(&ev_data.if_name[0], ifp->if_name, IFNAMSIZ);
	
		     ev_data.if_family = ifp->if_family;
		     ev_data.if_unit   = (unsigned long) ifp->if_unit;
		     ev_msg.dv[0].data_length = sizeof(struct net_event_data);
		     ev_msg.dv[0].data_ptr    = &ev_data;
		     ev_msg.dv[1].data_length = 0;
		     kev_post_msg(&ev_msg);

		     ifnet_touch_lastchange(ifp);
		}
		return error;

	case SIOCSIFPHYADDR:
	case SIOCDIFPHYADDR:
#if INET6
	case SIOCSIFPHYADDR_IN6:
#endif
	case SIOCSLIFPHYADDR:
	case SIOCSIFMEDIA:
	case SIOCSIFGENERIC:
	case SIOCSIFLLADDR:
	case SIOCSIFALTMTU:
	case SIOCSIFVLAN:
	case SIOCSIFBOND:
		error = proc_suser(p);
		if (error)
			return (error);

		error = ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family, 
				   			cmd, data);

		if (error == 0)
			ifnet_touch_lastchange(ifp);
		return error;

	case SIOCGIFSTATUS:
		ifs = (struct ifstat *)data;
		ifs->ascii[0] = '\0';
		
	case SIOCGIFPSRCADDR:
	case SIOCGIFPDSTADDR:
	case SIOCGLIFPHYADDR:
	case SIOCGIFMEDIA:
	case SIOCGIFGENERIC:
	case SIOCGIFDEVMTU:
		return ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family, 
				   		   cmd, data);
	case SIOCGIFVLAN:
	case SIOCGIFBOND:
		return ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family, 
				   		   cmd, data);

	default:
		oif_flags = ifp->if_flags;
		if (so->so_proto == 0)
			return (EOPNOTSUPP);
	    {
		int ocmd = cmd;

		switch (cmd) {

		case SIOCSIFDSTADDR:
		case SIOCSIFADDR:
		case SIOCSIFBRDADDR:
		case SIOCSIFNETMASK:
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
			break;

		case OSIOCGIFADDR:
			cmd = SIOCGIFADDR;
			break;

		case OSIOCGIFDSTADDR:
			cmd = SIOCGIFDSTADDR;
			break;

		case OSIOCGIFBRDADDR:
			cmd = SIOCGIFBRDADDR;
			break;

		case OSIOCGIFNETMASK:
			cmd = SIOCGIFNETMASK;
		}
		socket_lock(so, 1);
		error =  ((*so->so_proto->pr_usrreqs->pru_control)(so, cmd,
				data, ifp, p));
		socket_unlock(so, 1);
		switch (ocmd) {

		case OSIOCGIFADDR:
		case OSIOCGIFDSTADDR:
		case OSIOCGIFBRDADDR:
		case OSIOCGIFNETMASK:
			*(u_short *)&ifr->ifr_addr = ifr->ifr_addr.sa_family;

		}
	    }
		if (cmd == SIOCSIFKPI) {
			int temperr = proc_suser(p);
			if (temperr != 0)
				error = temperr;
		}

		if (error == EOPNOTSUPP || error == ENOTSUP)
			error = ifnet_ioctl(ifp, so->so_proto->pr_domain->dom_family,
								cmd, data);

		return (error);
	}
	return (0);
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
	struct ifreq ifr;
	int error = 0;
	int oldflags;
	int locked = 0;
	int changed = 0;

	ifnet_lock_exclusive(ifp);
	locked = 1;
	oldflags = ifp->if_flags;
	if (pswitch) {
		/*
		 * If the device is not configured up, we cannot put it in
		 * promiscuous mode.
		 */
		if ((ifp->if_flags & IFF_UP) == 0) {
			error = ENETDOWN;
			goto done;
		}
		if (ifp->if_pcount++ != 0) {
			goto done;
		}
		ifp->if_flags |= IFF_PROMISC;
	} else {
		if (--ifp->if_pcount > 0)
			goto done;
		ifp->if_flags &= ~IFF_PROMISC;
	}
	ifr.ifr_flags = ifp->if_flags;
	locked = 0;
	ifnet_lock_done(ifp);
	error = ifnet_ioctl(ifp, 0, SIOCSIFFLAGS, &ifr);
	if (error == 0)
		rt_ifmsg(ifp);
	else
		ifp->if_flags = oldflags;
done:
	if (locked) ifnet_lock_done(ifp);
	if (changed) {
		log(LOG_INFO, "%s%d: promiscuous mode %s\n",
		    ifp->if_name, ifp->if_unit,
		    pswitch != 0 ? "enabled" : "disabled");
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
	for (ifp = ifnet_head.tqh_first; space > sizeof(ifr) && ifp; ifp = ifp->if_link.tqe_next) {
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
			struct sockaddr *sa = ifa->ifa_addr;
#ifndef __APPLE__
			if (curproc->p_prison && prison_if(curproc, sa))
				continue;
#endif
			addrs++;
			if (cmd == OSIOCGIFCONF) {
				struct osockaddr *osa =
					 (struct osockaddr *)&ifr.ifr_addr;
				ifr.ifr_addr = *sa;
				osa->sa_family = sa->sa_family;
				error = copyout((caddr_t)&ifr, ifrp, sizeof(ifr));
				ifrp += sizeof(struct ifreq);
			} else if (sa->sa_len <= sizeof(*sa)) {
				ifr.ifr_addr = *sa;
				error = copyout((caddr_t)&ifr, ifrp, sizeof(ifr));
				ifrp += sizeof(struct ifreq);
			} else {
				if (space < sizeof (ifr) + sa->sa_len - sizeof(*sa))
					break;
				space -= sa->sa_len - sizeof(*sa);
				error = copyout((caddr_t)&ifr, ifrp, sizeof (ifr.ifr_name));
				if (error == 0) {
				    error = copyout((caddr_t)sa,
						(ifrp + offsetof(struct ifreq, ifr_addr)),
						sa->sa_len);
				}
				ifrp += (sa->sa_len + offsetof(struct ifreq, ifr_addr));
			}
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

void
ifma_reference(
	struct ifmultiaddr *ifma)
{
	if (OSIncrementAtomic((SInt32 *)&ifma->ifma_refcount) <= 0)
		panic("ifma_reference: ifma already released or invalid\n");
}

void
ifma_release(
	struct ifmultiaddr *ifma)
{
	while (ifma) {
		struct ifmultiaddr *next;
		int32_t prevValue = OSDecrementAtomic((SInt32 *)&ifma->ifma_refcount);
		if (prevValue < 1)
			panic("ifma_release: ifma already released or invalid\n");
		if (prevValue != 1)
			break;
		
		/* Allow the allocator of the protospec to free it */
		if (ifma->ifma_protospec && ifma->ifma_free) {
			ifma->ifma_free(ifma->ifma_protospec);
		}
		
		next = ifma->ifma_ll;
		FREE(ifma->ifma_addr, M_IFMADDR);
		FREE(ifma, M_IFMADDR);
		ifma = next;
	}
}

 /*
  * Find an ifmultiaddr that matches a socket address on an interface. 
  *
  * Caller is responsible for holding the ifnet_lock while calling
  * this function.
  */
static int
if_addmulti_doesexist(
	struct ifnet *ifp,
	const struct sockaddr *sa,
	struct ifmultiaddr **retifma)
{
	struct ifmultiaddr *ifma;
	for (ifma = ifp->if_multiaddrs.lh_first; ifma;
	     ifma = ifma->ifma_link.le_next) {
		if (equal(sa, ifma->ifma_addr)) {
			ifma->ifma_usecount++;
			if (retifma) {
				*retifma = ifma;
				ifma_reference(*retifma);
			}
			return 0;
		}
	}
	
	return ENOENT;
}

/*
 * Radar 3642395, make sure all multicasts are in a standard format.
 */
static struct sockaddr*
copy_and_normalize(
	const struct sockaddr	*original)
{
	int					alen = 0;
	const u_char		*aptr = NULL;
	struct sockaddr		*copy = NULL;
	struct sockaddr_dl	*sdl_new = NULL;
	int					len = 0;
	
	if (original->sa_family != AF_LINK &&
		original->sa_family != AF_UNSPEC) {
		/* Just make a copy */
		MALLOC(copy, struct sockaddr*, original->sa_len, M_IFADDR, M_WAITOK);
		if (copy != NULL)
			bcopy(original, copy, original->sa_len);
		return copy;
	}
	
	switch (original->sa_family) {
		case AF_LINK: {
			const struct sockaddr_dl	*sdl_original =
											(const struct sockaddr_dl*)original;
			
			if (sdl_original->sdl_nlen + sdl_original->sdl_alen + sdl_original->sdl_slen +
				offsetof(struct sockaddr_dl, sdl_data) > sdl_original->sdl_len)
				return NULL;
			
			alen = sdl_original->sdl_alen;
			aptr = CONST_LLADDR(sdl_original);
		}
		break;
		
		case AF_UNSPEC: {
			if (original->sa_len < ETHER_ADDR_LEN +
				offsetof(struct sockaddr, sa_data)) {
				return NULL;
			}
			
			alen = ETHER_ADDR_LEN;
			aptr = (const u_char*)original->sa_data;
		}
		break;
	}
	
	if (alen == 0 || aptr == NULL)
		return NULL;
	
	len = alen + offsetof(struct sockaddr_dl, sdl_data);
	MALLOC(sdl_new, struct sockaddr_dl*, len, M_IFADDR, M_WAITOK);
	
	if (sdl_new != NULL) {
		bzero(sdl_new, len);
		sdl_new->sdl_len = len;
		sdl_new->sdl_family = AF_LINK;
		sdl_new->sdl_alen = alen;
		bcopy(aptr, LLADDR(sdl_new), alen);
	}
	
	return (struct sockaddr*)sdl_new;
}

/*
 * Add a multicast listenership to the interface in question.
 * The link layer provides a routine which converts
 */
int
if_addmulti(
	struct ifnet *ifp,	/* interface to manipulate */
	const struct sockaddr *sa,	/* address to add */
	struct ifmultiaddr **retifma)
{
	struct sockaddr_storage storage;
	struct sockaddr *llsa = NULL;
	struct sockaddr *dupsa = NULL;
	int error = 0;
	struct ifmultiaddr *ifma = NULL;
	struct ifmultiaddr *llifma = NULL;
	
	/* If sa is a AF_LINK or AF_UNSPEC, duplicate and normalize it */
	if (sa->sa_family == AF_LINK || sa->sa_family == AF_UNSPEC) {
		dupsa = copy_and_normalize(sa);
		if (dupsa == NULL) {
			return ENOMEM;
		}
		sa = dupsa;
	}
	
	ifnet_lock_exclusive(ifp);
	error = if_addmulti_doesexist(ifp, sa, retifma);
	ifnet_lock_done(ifp);
	
	if (error == 0) {
		goto cleanup;
	}

	/*
	 * Give the link layer a chance to accept/reject it, and also
	 * find out which AF_LINK address this maps to, if it isn't one
	 * already.
	 */
	error = dlil_resolve_multi(ifp, sa, (struct sockaddr*)&storage,
							   sizeof(storage));
	if (error == 0 && storage.ss_len != 0) {
		llsa = copy_and_normalize((struct sockaddr*)&storage);
		if (llsa == NULL) {
			error = ENOMEM;
			goto cleanup;
		}
		
		MALLOC(llifma, struct ifmultiaddr *, sizeof *llifma, M_IFMADDR, M_WAITOK);
		if (llifma == NULL) {
			error = ENOMEM;
			goto cleanup;
		}
	}
	
	/* to be similar to FreeBSD */
	if (error == EOPNOTSUPP) {
		error = 0;
	}
	else if (error) {
		goto cleanup;
	}

	/* Allocate while we aren't holding any locks */
	if (dupsa == NULL) {
		dupsa = copy_and_normalize(sa);
		if (dupsa == NULL) {
			error = ENOMEM;
			goto cleanup;
		}
	}
	MALLOC(ifma, struct ifmultiaddr *, sizeof *ifma, M_IFMADDR, M_WAITOK);
	if (ifma == NULL) {
		error = ENOMEM;
		goto cleanup;
	}
	
	ifnet_lock_exclusive(ifp);
	/*
	 * Check again for the matching multicast.
	 */
	if ((error = if_addmulti_doesexist(ifp, sa, retifma)) == 0) {
		ifnet_lock_done(ifp);
		goto cleanup;
	}

	bzero(ifma, sizeof(*ifma));
	ifma->ifma_addr = dupsa;
	ifma->ifma_ifp = ifp;
	ifma->ifma_usecount = 1;
	ifma->ifma_refcount = 1;
	
	if (llifma != 0) {
		if (if_addmulti_doesexist(ifp, llsa, &ifma->ifma_ll) == 0) {
			FREE(llsa, M_IFMADDR);
			FREE(llifma, M_IFMADDR);
		} else {
			bzero(llifma, sizeof(*llifma));
			llifma->ifma_addr = llsa;
			llifma->ifma_ifp = ifp;
			llifma->ifma_usecount = 1;
			llifma->ifma_refcount = 1;
			LIST_INSERT_HEAD(&ifp->if_multiaddrs, llifma, ifma_link);

			ifma->ifma_ll = llifma;
			ifma_reference(ifma->ifma_ll);
		}
	}
	
	LIST_INSERT_HEAD(&ifp->if_multiaddrs, ifma, ifma_link);
	
	if (retifma) {
		*retifma = ifma;
		ifma_reference(*retifma);
	}

	ifnet_lock_done(ifp);
	
	if (llsa != 0)
		rt_newmaddrmsg(RTM_NEWMADDR, ifma);

	/*
	 * We are certain we have added something, so call down to the
	 * interface to let them know about it.
	 */
	ifnet_ioctl(ifp, 0, SIOCADDMULTI, NULL);
	
	return 0;
	
cleanup:
	if (ifma)
		FREE(ifma, M_IFADDR);
	if (dupsa)
		FREE(dupsa, M_IFADDR);
	if (llifma)
		FREE(llifma, M_IFADDR);
	if (llsa)
		FREE(llsa, M_IFADDR);
	
	return error;
}

int
if_delmultiaddr(
	struct ifmultiaddr *ifma,
	int locked)
{
	struct ifnet *ifp;
	int	do_del_multi = 0;
	
	ifp = ifma->ifma_ifp;
	
	if (!locked && ifp) {
		ifnet_lock_exclusive(ifp);
	}
	
	while (ifma != NULL) {
		struct ifmultiaddr *ll_ifma;
		
		if (ifma->ifma_usecount > 1) {
			ifma->ifma_usecount--;
			break;
		}
		
		if (ifp)
			LIST_REMOVE(ifma, ifma_link);
	
		ll_ifma = ifma->ifma_ll;
	
		if (ll_ifma) { /* send a routing msg for network addresses only */
			if (ifp)
				ifnet_lock_done(ifp);
			rt_newmaddrmsg(RTM_DELMADDR, ifma);
			if (ifp)
				ifnet_lock_exclusive(ifp);
		}
		
		/*
		 * Make sure the interface driver is notified
		 * in the case of a link layer mcast group being left.
		 */
		if (ll_ifma == 0) {
			if (ifp && ifma->ifma_addr->sa_family == AF_LINK)
				do_del_multi = 1;
			break;
		}
		
		if (ifp)
			ifma_release(ifma);
	
		ifma = ll_ifma;
	}
	
	if (!locked && ifp) {
		/* This wasn't initially locked, we should unlock it */
		ifnet_lock_done(ifp);
	}
	
	if (do_del_multi) {
		if (locked)
			ifnet_lock_done(ifp);
		ifnet_ioctl(ifp, 0, SIOCDELMULTI, NULL);
		if (locked)
			ifnet_lock_exclusive(ifp);
	}
	
	return 0;
}

/*
 * Remove a reference to a multicast address on this interface.  Yell
 * if the request does not match an existing membership.
 */
int
if_delmulti(
	struct ifnet *ifp,
	const struct sockaddr *sa)
{
	struct ifmultiaddr	*ifma;
	struct sockaddr		*dupsa = NULL;
	int retval = 0;

	if (sa->sa_family == AF_LINK || sa->sa_family == AF_UNSPEC) {
		dupsa = copy_and_normalize(sa);
		if (dupsa == NULL) {
			return ENOMEM;
		}
		sa = dupsa;
	}
	
	ifnet_lock_exclusive(ifp);
	for (ifma = ifp->if_multiaddrs.lh_first; ifma;
	     ifma = ifma->ifma_link.le_next)
		if (equal(sa, ifma->ifma_addr))
			break;
	if (ifma == 0) {
		ifnet_lock_done(ifp);
		if (dupsa)
			FREE(dupsa, M_IFADDR);
		return ENOENT;
	}
	
	retval = if_delmultiaddr(ifma, 1);
	ifnet_lock_done(ifp);
	if (dupsa)
		FREE(dupsa, M_IFADDR);
	
	return retval;
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

struct ifmultiaddr *
ifmaof_ifpforaddr(const struct sockaddr *sa, struct ifnet *ifp)
{
	struct ifmultiaddr *ifma;
	
	ifnet_lock_shared(ifp);
	for (ifma = ifp->if_multiaddrs.lh_first; ifma;
	     ifma = ifma->ifma_link.le_next)
		if (equal(ifma->ifma_addr, sa))
			break;
	ifnet_lock_done(ifp);

	return ifma;
}

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
if_rtdel(
	struct radix_node	*rn,
	void			*arg)
{
	struct rtentry	*rt = (struct rtentry *)rn;
	struct ifnet	*ifp = arg;
	int		err;

	if (rt != NULL && rt->rt_ifp == ifp) {
		
		/*
		 * Protect (sorta) against walktree recursion problems
		 * with cloned routes
		 */
		if ((rt->rt_flags & RTF_UP) == 0)
			return (0);

		err = rtrequest_locked(RTM_DELETE, rt_key(rt), rt->rt_gateway,
				rt_mask(rt), rt->rt_flags,
				(struct rtentry **) NULL);
		if (err) {
			log(LOG_WARNING, "if_rtdel: error %d\n", err);
		}
	}

	return (0);
}

/*
 * Removes routing table reference to a given interfacei
 * for a given protocol family
 */
void if_rtproto_del(struct ifnet *ifp, int protocol)
{
	struct radix_node_head  *rnh;
	if (use_routegenid) 
		route_generation++;
	if ((protocol <= AF_MAX) && (protocol >= 0) &&
		((rnh = rt_tables[protocol]) != NULL) && (ifp != NULL)) {
		lck_mtx_lock(rt_mtx);
		(void) rnh->rnh_walktree(rnh, if_rtdel, ifp);
		lck_mtx_unlock(rt_mtx);
	}
}

static int
if_rtmtu(struct radix_node *rn, void *arg)
{
	struct rtentry *rt = (struct rtentry *)rn;
	struct ifnet *ifp = arg;

	if (rt->rt_ifp == ifp) {
		/*
		 * Update the MTU of this entry only if the MTU
		 * has not been locked (RTV_MTU is not set) and
		 * if it was non-zero to begin with.
		 */
		if (!(rt->rt_rmx.rmx_locks & RTV_MTU) && rt->rt_rmx.rmx_mtu)
			rt->rt_rmx.rmx_mtu = ifp->if_mtu;
	}

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

		lck_mtx_lock(rt_mtx);
		(void) rnh->rnh_walktree(rnh, if_rtmtu, ifp);
		lck_mtx_unlock(rt_mtx);
	}

	if (use_routegenid)
		route_generation++;
}

__private_extern__ void
if_data_internal_to_if_data(
	struct ifnet *ifp,
	const struct if_data_internal	*if_data_int,
	struct if_data					*if_data)
{
	struct dlil_threading_info *thread;
       	if ((thread = ifp->if_input_thread) == NULL || (dlil_multithreaded_input == 0))
		thread = dlil_lo_thread_ptr;

#define COPYFIELD(fld)	if_data->fld = if_data_int->fld
#define COPYFIELD32(fld)	if_data->fld = (u_int32_t)(if_data_int->fld)
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
	}
	else {
		COPYFIELD32(ifi_baudrate);
	}
	
	lck_mtx_lock(thread->input_lck);
	COPYFIELD32(ifi_ipackets);
	COPYFIELD32(ifi_ierrors);
	COPYFIELD32(ifi_opackets);
	COPYFIELD32(ifi_oerrors);
	COPYFIELD32(ifi_collisions);
	COPYFIELD32(ifi_ibytes);
	COPYFIELD32(ifi_obytes);
	COPYFIELD32(ifi_imcasts);
	COPYFIELD32(ifi_omcasts);
	COPYFIELD32(ifi_iqdrops);
	COPYFIELD32(ifi_noproto);
	COPYFIELD32(ifi_recvtiming);
	COPYFIELD32(ifi_xmittiming);
	COPYFIELD(ifi_lastchange);
	lck_mtx_unlock(thread->input_lck);
	
#if IF_LASTCHANGEUPTIME
	if_data->ifi_lastchange.tv_sec += boottime_sec();
#endif

	if_data->ifi_unused2 = 0;
	COPYFIELD(ifi_hwassist);
	if_data->ifi_reserved1 = 0;
	if_data->ifi_reserved2 = 0;
#undef COPYFIELD32
#undef COPYFIELD
}

__private_extern__ void
if_data_internal_to_if_data64(
	struct ifnet *ifp,
	const struct if_data_internal	*if_data_int,
	struct if_data64				*if_data64)
{
	struct dlil_threading_info *thread;
       	if ((thread = ifp->if_input_thread) == NULL || (dlil_multithreaded_input == 0))
		thread = dlil_lo_thread_ptr;

#define COPYFIELD(fld)	if_data64->fld = if_data_int->fld
	COPYFIELD(ifi_type);
	COPYFIELD(ifi_typelen);
	COPYFIELD(ifi_physical);
	COPYFIELD(ifi_addrlen);
	COPYFIELD(ifi_hdrlen);
	COPYFIELD(ifi_recvquota);
	COPYFIELD(ifi_xmitquota);
	if_data64->ifi_unused1 = 0;
	COPYFIELD(ifi_mtu);
	COPYFIELD(ifi_metric);
	COPYFIELD(ifi_baudrate);

	lck_mtx_lock(thread->input_lck);
	COPYFIELD(ifi_ipackets);
	COPYFIELD(ifi_ierrors);
	COPYFIELD(ifi_opackets);
	COPYFIELD(ifi_oerrors);
	COPYFIELD(ifi_collisions);
	COPYFIELD(ifi_ibytes);
	COPYFIELD(ifi_obytes);
	COPYFIELD(ifi_imcasts);
	COPYFIELD(ifi_omcasts);
	COPYFIELD(ifi_iqdrops);
	COPYFIELD(ifi_noproto);
	COPYFIELD(ifi_recvtiming);
	COPYFIELD(ifi_xmittiming);
	COPYFIELD(ifi_lastchange);
	lck_mtx_unlock(thread->input_lck);
	
#if IF_LASTCHANGEUPTIME
	if_data64->ifi_lastchange.tv_sec += boottime_sec();
#endif

#undef COPYFIELD
}
