/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
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
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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
 *	@(#)in_pcb.c	8.2 (Berkeley) 1/4/94
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/kauth.h>
#include <sys/priv.h>
#include <kern/lock.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/ip6_var.h>
#include <netinet6/scope6_var.h>
#include <netinet6/nd6.h>

#include <net/net_osdep.h>

#include "loop.h"

SYSCTL_DECL(_net_inet6_ip6);

static int ip6_select_srcif_debug = 0;
SYSCTL_INT(_net_inet6_ip6, OID_AUTO, select_srcif_debug,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip6_select_srcif_debug, 0,
	"log source interface selection debug info");

#define	ADDR_LABEL_NOTAPP (-1)
struct in6_addrpolicy defaultaddrpolicy;

int ip6_prefer_tempaddr = 1;
#ifdef ENABLE_ADDRSEL
extern lck_mtx_t *addrsel_mutex;
#define	ADDRSEL_LOCK()		lck_mtx_lock(addrsel_mutex)
#define	ADDRSEL_UNLOCK()	lck_mtx_unlock(addrsel_mutex)
#else
#define	ADDRSEL_LOCK()
#define	ADDRSEL_UNLOCK()
#endif

static int selectroute(struct sockaddr_in6 *, struct sockaddr_in6 *,
	struct ip6_pktopts *, struct ip6_moptions *, struct in6_ifaddr **,
	struct route_in6 *, struct ifnet **, struct rtentry **, int, int,
	struct ip6_out_args *ip6oa);
static int in6_selectif(struct sockaddr_in6 *, struct ip6_pktopts *,
	struct ip6_moptions *, struct route_in6 *ro,
	struct ip6_out_args *, struct ifnet **);
static void init_policy_queue(void);
static int add_addrsel_policyent(const struct in6_addrpolicy *);
#ifdef ENABLE_ADDRSEL
static int delete_addrsel_policyent(const struct in6_addrpolicy *);
#endif
static int walk_addrsel_policy(int (*)(const struct in6_addrpolicy *, void *),
	void *);
static int dump_addrsel_policyent(const struct in6_addrpolicy *, void *);
static struct in6_addrpolicy *match_addrsel_policy(struct sockaddr_in6 *);
void addrsel_policy_init(void);

/*
 * Return an IPv6 address, which is the most appropriate for a given
 * destination and user specified options.
 * If necessary, this function lookups the routing table and returns
 * an entry to the caller for later use.
 */
#define	REPLACE(r) do {\
	if ((r) < sizeof (ip6stat.ip6s_sources_rule) / \
		sizeof (ip6stat.ip6s_sources_rule[0])) /* check for safety */ \
		ip6stat.ip6s_sources_rule[(r)]++; \
	goto replace; \
} while (0)
#define	NEXTSRC(r) do {\
	if ((r) < sizeof (ip6stat.ip6s_sources_rule) / \
		sizeof (ip6stat.ip6s_sources_rule[0])) /* check for safety */ \
		ip6stat.ip6s_sources_rule[(r)]++; \
	goto next;		/* XXX: we can't use 'continue' here */ \
} while (0)
#define	BREAK(r) do { \
	if ((r) < sizeof (ip6stat.ip6s_sources_rule) / \
		sizeof (ip6stat.ip6s_sources_rule[0])) /* check for safety */ \
		ip6stat.ip6s_sources_rule[(r)]++; \
	goto out;		/* XXX: we can't use 'break' here */ \
} while (0)

/*
 * Regardless of error, it will return an ifp with a reference held if the
 * caller provides a non-NULL ifpp.  The caller is responsible for checking
 * if the returned ifp is valid and release its reference at all times.
 */
struct in6_addr *
in6_selectsrc(struct sockaddr_in6 *dstsock, struct ip6_pktopts *opts,
    struct inpcb *inp, struct route_in6 *ro,
    struct ifnet **ifpp, struct in6_addr *src_storage, unsigned int ifscope,
    int *errorp)
{
	struct in6_addr dst;
	struct ifnet *ifp = NULL;
	struct in6_ifaddr *ia = NULL, *ia_best = NULL;
	struct in6_pktinfo *pi = NULL;
	int dst_scope = -1, best_scope = -1, best_matchlen = -1;
	struct in6_addrpolicy *dst_policy = NULL, *best_policy = NULL;
	u_int32_t odstzone;
	int prefer_tempaddr;
	struct ip6_moptions *mopts;
	struct ip6_out_args ip6oa = { ifscope, { 0 }, IP6OAF_SELECT_SRCIF, 0 };
	boolean_t islocal = FALSE;
	uint64_t secs = net_uptime();

	dst = dstsock->sin6_addr; /* make a copy for local operation */
	*errorp = 0;
	if (ifpp != NULL)
		*ifpp = NULL;

	if (inp != NULL) {
		mopts = inp->in6p_moptions;
		if (inp->inp_flags & INP_NO_IFT_CELLULAR)
			ip6oa.ip6oa_flags |= IP6OAF_NO_CELLULAR;
	} else {
		mopts = NULL;
	}

	if (ip6oa.ip6oa_boundif != IFSCOPE_NONE)
		ip6oa.ip6oa_flags |= IP6OAF_BOUND_IF;

	/*
	 * If the source address is explicitly specified by the caller,
	 * check if the requested source address is indeed a unicast address
	 * assigned to the node, and can be used as the packet's source
	 * address.  If everything is okay, use the address as source.
	 */
	if (opts && (pi = opts->ip6po_pktinfo) &&
	    !IN6_IS_ADDR_UNSPECIFIED(&pi->ipi6_addr)) {
		struct sockaddr_in6 srcsock;
		struct in6_ifaddr *ia6;

		/* get the outgoing interface */
		if ((*errorp = in6_selectif(dstsock, opts, mopts, ro, &ip6oa,
		    &ifp)) != 0) {
			src_storage = NULL;
			goto done;
		}

		/*
		 * determine the appropriate zone id of the source based on
		 * the zone of the destination and the outgoing interface.
		 * If the specified address is ambiguous wrt the scope zone,
		 * the interface must be specified; otherwise, ifa_ifwithaddr()
		 * will fail matching the address.
		 */
		bzero(&srcsock, sizeof (srcsock));
		srcsock.sin6_family = AF_INET6;
		srcsock.sin6_len = sizeof (srcsock);
		srcsock.sin6_addr = pi->ipi6_addr;
		if (ifp != NULL) {
			*errorp = in6_setscope(&srcsock.sin6_addr, ifp, NULL);
			if (*errorp != 0) {
				src_storage = NULL;
				goto done;
			}
		}
		ia6 = (struct in6_ifaddr *)ifa_ifwithaddr((struct sockaddr *)
		    (&srcsock));
		if (ia6 == NULL) {
			*errorp = EADDRNOTAVAIL;
			src_storage = NULL;
			goto done;
		}
		IFA_LOCK_SPIN(&ia6->ia_ifa);
		if ((ia6->ia6_flags & (IN6_IFF_ANYCAST | IN6_IFF_NOTREADY)) ||
		    ((ip6oa.ip6oa_flags & IP6OAF_NO_CELLULAR) &&
		    IFNET_IS_CELLULAR(ia6->ia_ifa.ifa_ifp))) {
			IFA_UNLOCK(&ia6->ia_ifa);
			IFA_REMREF(&ia6->ia_ifa);
			*errorp = EHOSTUNREACH;
			src_storage = NULL;
			goto done;
		}

		*src_storage = satosin6(&ia6->ia_addr)->sin6_addr;
		IFA_UNLOCK(&ia6->ia_ifa);
		IFA_REMREF(&ia6->ia_ifa);
		goto done;
	}

	/*
	 * Otherwise, if the socket has already bound the source, just use it.
	 */
	if (inp != NULL && !IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)) {
		src_storage = &inp->in6p_laddr;
		goto done;
	}

	/*
	 * If the address is not specified, choose the best one based on
	 * the outgoing interface and the destination address.
	 */

	/* get the outgoing interface */
	if ((*errorp = in6_selectif(dstsock, opts, mopts, ro, &ip6oa,
	    &ifp)) != 0) {
		src_storage = NULL;
		goto done;
	}

	*errorp = in6_setscope(&dst, ifp, &odstzone);
	if (*errorp != 0) {
		src_storage = NULL;
		goto done;
	}
	lck_rw_lock_shared(&in6_ifaddr_rwlock);

	for (ia = in6_ifaddrs; ia; ia = ia->ia_next) {
		int new_scope = -1, new_matchlen = -1;
		struct in6_addrpolicy *new_policy = NULL;
		u_int32_t srczone, osrczone, dstzone;
		struct in6_addr src;
		struct ifnet *ifp1 = ia->ia_ifp;

		IFA_LOCK(&ia->ia_ifa);
		/*
		 * We'll never take an address that breaks the scope zone
		 * of the destination.  We also skip an address if its zone
		 * does not contain the outgoing interface.
		 * XXX: we should probably use sin6_scope_id here.
		 */
		if (in6_setscope(&dst, ifp1, &dstzone) ||
		    odstzone != dstzone)
			goto next;

		src = ia->ia_addr.sin6_addr;
		if (in6_setscope(&src, ifp, &osrczone) ||
		    in6_setscope(&src, ifp1, &srczone) ||
		    osrczone != srczone)
			goto next;

		/* avoid unusable addresses */
		if ((ia->ia6_flags &
		    (IN6_IFF_NOTREADY | IN6_IFF_ANYCAST | IN6_IFF_DETACHED)))
			goto next;

		if (!ip6_use_deprecated && IFA6_IS_DEPRECATED(ia, secs))
			goto next;

		if (!nd6_optimistic_dad &&
		    (ia->ia6_flags & IN6_IFF_OPTIMISTIC) != 0)
			goto next;

		/* Rule 1: Prefer same address */
		if (IN6_ARE_ADDR_EQUAL(&dst, &ia->ia_addr.sin6_addr))
			BREAK(1); /* there should be no better candidate */

		if (ia_best == NULL)
			REPLACE(0);

		/* Rule 2: Prefer appropriate scope */
		if (dst_scope < 0)
			dst_scope = in6_addrscope(&dst);
		new_scope = in6_addrscope(&ia->ia_addr.sin6_addr);
		if (IN6_ARE_SCOPE_CMP(best_scope, new_scope) < 0) {
			if (IN6_ARE_SCOPE_CMP(best_scope, dst_scope) < 0)
				REPLACE(2);
			NEXTSRC(2);
		} else if (IN6_ARE_SCOPE_CMP(new_scope, best_scope) < 0) {
			if (IN6_ARE_SCOPE_CMP(new_scope, dst_scope) < 0)
				NEXTSRC(2);
			REPLACE(2);
		}

		/*
		 * Rule 3: Avoid deprecated addresses.  Note that the case of
		 * !ip6_use_deprecated is already rejected above.
		 */
		if (!IFA6_IS_DEPRECATED(ia_best, secs) &&
		    IFA6_IS_DEPRECATED(ia, secs))
			NEXTSRC(3);
		if (IFA6_IS_DEPRECATED(ia_best, secs) &&
		    !IFA6_IS_DEPRECATED(ia, secs))
			REPLACE(3);

		/*
		 * RFC 4429 says that optimistic addresses are equivalent to
		 * deprecated addresses, so avoid them here.
		 */
		if ((ia_best->ia6_flags & IN6_IFF_OPTIMISTIC) == 0 &&
		    (ia->ia6_flags & IN6_IFF_OPTIMISTIC) != 0)
			NEXTSRC(3);
		if ((ia_best->ia6_flags & IN6_IFF_OPTIMISTIC) != 0 &&
		    (ia->ia6_flags & IN6_IFF_OPTIMISTIC) == 0)
			REPLACE(3);

		/* Rule 4: Prefer home addresses */
		/*
		 * XXX: This is a TODO.  We should probably merge the MIP6
		 * case above.
		 */

		/* Rule 5: Prefer outgoing interface */
		if (ia_best->ia_ifp == ifp && ia->ia_ifp != ifp)
			NEXTSRC(5);
		if (ia_best->ia_ifp != ifp && ia->ia_ifp == ifp)
			REPLACE(5);

		/*
		 * Rule 6: Prefer matching label
		 * Note that best_policy should be non-NULL here.
		 */
		if (dst_policy == NULL)
			dst_policy = in6_addrsel_lookup_policy(dstsock);
		if (dst_policy->label != ADDR_LABEL_NOTAPP) {
			new_policy = in6_addrsel_lookup_policy(&ia->ia_addr);
			if (dst_policy->label == best_policy->label &&
			    dst_policy->label != new_policy->label)
				NEXTSRC(6);
			if (dst_policy->label != best_policy->label &&
			    dst_policy->label == new_policy->label)
				REPLACE(6);
		}

		/*
		 * Rule 7: Prefer public addresses.
		 * We allow users to reverse the logic by configuring
		 * a sysctl variable, so that privacy conscious users can
		 * always prefer temporary addresses.
		 * Don't use temporary addresses for local destinations or
		 * for multicast addresses unless we were passed in an option.
		 */
		if (IN6_IS_ADDR_MULTICAST(&dst) ||
		    in6_matchlen(&ia_best->ia_addr.sin6_addr, &dst) >=
		    ia_best->ia_plen)
			islocal = TRUE;
		if (opts == NULL ||
		    opts->ip6po_prefer_tempaddr == IP6PO_TEMPADDR_SYSTEM) {
			prefer_tempaddr = islocal ? 0 : ip6_prefer_tempaddr;
		} else if (opts->ip6po_prefer_tempaddr ==
		    IP6PO_TEMPADDR_NOTPREFER) {
			prefer_tempaddr = 0;
		} else
			prefer_tempaddr = 1;
		if (!(ia_best->ia6_flags & IN6_IFF_TEMPORARY) &&
		    (ia->ia6_flags & IN6_IFF_TEMPORARY)) {
			if (prefer_tempaddr)
				REPLACE(7);
			else
				NEXTSRC(7);
		}
		if ((ia_best->ia6_flags & IN6_IFF_TEMPORARY) &&
		    !(ia->ia6_flags & IN6_IFF_TEMPORARY)) {
			if (prefer_tempaddr)
				NEXTSRC(7);
			else
				REPLACE(7);
		}

		/*
		 * Rule 8: prefer addresses on alive interfaces.
		 * This is a KAME specific rule.
		 */
		if ((ia_best->ia_ifp->if_flags & IFF_UP) &&
		    !(ia->ia_ifp->if_flags & IFF_UP))
			NEXTSRC(8);
		if (!(ia_best->ia_ifp->if_flags & IFF_UP) &&
		    (ia->ia_ifp->if_flags & IFF_UP))
			REPLACE(8);

		/*
		 * Rule 14: Use longest matching prefix.
		 * Note: in the address selection draft, this rule is
		 * documented as "Rule 8".  However, since it is also
		 * documented that this rule can be overridden, we assign
		 * a large number so that it is easy to assign smaller numbers
		 * to more preferred rules.
		 */
		new_matchlen = in6_matchlen(&ia->ia_addr.sin6_addr, &dst);
		if (best_matchlen < new_matchlen)
			REPLACE(14);
		if (new_matchlen < best_matchlen)
			NEXTSRC(14);

		/* Rule 15 is reserved. */

		/*
		 * Last resort: just keep the current candidate.
		 * Or, do we need more rules?
		 */
		IFA_UNLOCK(&ia->ia_ifa);
		continue;

replace:
		best_scope = (new_scope >= 0 ? new_scope :
		    in6_addrscope(&ia->ia_addr.sin6_addr));
		best_policy = (new_policy ? new_policy :
		    in6_addrsel_lookup_policy(&ia->ia_addr));
		best_matchlen = (new_matchlen >= 0 ? new_matchlen :
		    in6_matchlen(&ia->ia_addr.sin6_addr, &dst));
		IFA_ADDREF_LOCKED(&ia->ia_ifa);	/* for ia_best */
		IFA_UNLOCK(&ia->ia_ifa);
		if (ia_best != NULL)
			IFA_REMREF(&ia_best->ia_ifa);
		ia_best = ia;
		continue;

next:
		IFA_UNLOCK(&ia->ia_ifa);
		continue;

out:
		IFA_ADDREF_LOCKED(&ia->ia_ifa);	/* for ia_best */
		IFA_UNLOCK(&ia->ia_ifa);
		if (ia_best != NULL)
			IFA_REMREF(&ia_best->ia_ifa);
		ia_best = ia;
		break;
	}

	lck_rw_done(&in6_ifaddr_rwlock);

	if (ia_best != NULL &&
	    (ip6oa.ip6oa_flags & IP6OAF_NO_CELLULAR) &&
	    IFNET_IS_CELLULAR(ia_best->ia_ifa.ifa_ifp)) {
		IFA_REMREF(&ia_best->ia_ifa);
		ia_best = NULL;
		*errorp = EHOSTUNREACH;
	}

	if ((ia = ia_best) == NULL) {
		if (*errorp == 0)
			*errorp = EADDRNOTAVAIL;
		src_storage = NULL;
		goto done;
	}

	IFA_LOCK_SPIN(&ia->ia_ifa);
	*src_storage = satosin6(&ia->ia_addr)->sin6_addr;
	IFA_UNLOCK(&ia->ia_ifa);
	IFA_REMREF(&ia->ia_ifa);
done:
	if (ifpp != NULL) {
		/* if ifp is non-NULL, refcnt held in in6_selectif() */
		*ifpp = ifp;
	} else if (ifp != NULL) {
		ifnet_release(ifp);
	}
	return (src_storage);
}

/*
 * Given a source IPv6 address (and route, if available), determine the best
 * interface to send the packet from.  Checking for (and updating) the
 * ROF_SRCIF_SELECTED flag in the pcb-supplied route placeholder is done
 * without any locks, based on the assumption that in the event this is
 * called from ip6_output(), the output operation is single-threaded per-pcb,
 * i.e. for any given pcb there can only be one thread performing output at
 * the IPv6 layer.
 *
 * This routine is analogous to in_selectsrcif() for IPv4.  Regardless of
 * error, it will return an ifp with a reference held if the caller provides
 * a non-NULL retifp.  The caller is responsible for checking if the
 * returned ifp is valid and release its reference at all times.
 *
 * clone - meaningful only for bsdi and freebsd
 */
static int
selectroute(struct sockaddr_in6 *srcsock, struct sockaddr_in6 *dstsock,
    struct ip6_pktopts *opts, struct ip6_moptions *mopts,
    struct in6_ifaddr **retsrcia, struct route_in6 *ro,
    struct ifnet **retifp, struct rtentry **retrt, int clone,
    int norouteok, struct ip6_out_args *ip6oa)
{
	int error = 0;
	struct ifnet *ifp = NULL, *ifp0 = NULL;
	struct route_in6 *route = NULL;
	struct sockaddr_in6 *sin6_next;
	struct in6_pktinfo *pi = NULL;
	struct in6_addr *dst = &dstsock->sin6_addr;
	struct ifaddr *ifa = NULL;
	char s_src[MAX_IPv6_STR_LEN], s_dst[MAX_IPv6_STR_LEN];
	boolean_t select_srcif, proxied_ifa = FALSE, local_dst = FALSE;
	unsigned int ifscope = ((ip6oa != NULL) ?
	    ip6oa->ip6oa_boundif : IFSCOPE_NONE);

#if 0
	char ip6buf[INET6_ADDRSTRLEN];

	if (dstsock->sin6_addr.s6_addr32[0] == 0 &&
	    dstsock->sin6_addr.s6_addr32[1] == 0 &&
	    !IN6_IS_ADDR_LOOPBACK(&dstsock->sin6_addr)) {
		printf("in6_selectroute: strange destination %s\n",
		    ip6_sprintf(ip6buf, &dstsock->sin6_addr));
	} else {
		printf("in6_selectroute: destination = %s%%%d\n",
		    ip6_sprintf(ip6buf, &dstsock->sin6_addr),
		    dstsock->sin6_scope_id); /* for debug */
	}
#endif

	if (retifp != NULL)
		*retifp = NULL;

	if (retrt != NULL)
		*retrt = NULL;

	if (ip6_select_srcif_debug) {
		struct in6_addr src;
		src = (srcsock != NULL) ? srcsock->sin6_addr : in6addr_any;
		(void) inet_ntop(AF_INET6, &src, s_src, sizeof (s_src));
		(void) inet_ntop(AF_INET6, dst, s_dst, sizeof (s_dst));
	}

	/*
	 * If the destination address is UNSPECIFIED addr, bail out.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(dst)) {
		error = EHOSTUNREACH;
		goto done;
	}

	/*
	 * Perform source interface selection only if Scoped Routing
	 * is enabled and a source address that isn't unspecified.
	 */
	select_srcif = (ip6_doscopedroute && srcsock != NULL &&
	    !IN6_IS_ADDR_UNSPECIFIED(&srcsock->sin6_addr));

	/*
	 * If Scoped Routing is disabled, ignore the given ifscope.
	 * Otherwise even if source selection won't be performed,
	 * we still obey IPV6_BOUND_IF.
	 */
	if (!ip6_doscopedroute && ifscope != IFSCOPE_NONE)
		ifscope = IFSCOPE_NONE;

	/* If the caller specified the outgoing interface explicitly, use it */
	if (opts != NULL && (pi = opts->ip6po_pktinfo) != NULL &&
	    pi->ipi6_ifindex != 0) {
		/*
		 * If IPV6_PKTINFO takes precedence over IPV6_BOUND_IF.
		 */
		ifscope = pi->ipi6_ifindex;
		ifnet_head_lock_shared();
		/* ifp may be NULL if detached or out of range */
		ifp = ifp0 =
		    ((ifscope <= if_index) ? ifindex2ifnet[ifscope] : NULL);
		ifnet_head_done();
		if (norouteok || retrt == NULL || IN6_IS_ADDR_MULTICAST(dst)) {
			/*
			 * We do not have to check or get the route for
			 * multicast.  If the caller didn't ask/care for
			 * the route and we have no interface to use,
			 * it's an error.
			 */
			if (ifp == NULL)
				error = EHOSTUNREACH;
			goto done;
		} else {
			goto getsrcif;
		}
	}

	/*
	 * If the destination address is a multicast address and the outgoing
	 * interface for the address is specified by the caller, use it.
	 */
	if (IN6_IS_ADDR_MULTICAST(dst) && mopts != NULL) {
		IM6O_LOCK(mopts);
		if ((ifp = ifp0 = mopts->im6o_multicast_ifp) != NULL) {
			IM6O_UNLOCK(mopts);
			goto done; /* we do not need a route for multicast. */
		}
		IM6O_UNLOCK(mopts);
	}

getsrcif:
	/*
	 * If the outgoing interface was not set via IPV6_BOUND_IF or
	 * IPV6_PKTINFO, use the scope ID in the destination address.
	 */
	if (ip6_doscopedroute && ifscope == IFSCOPE_NONE)
		ifscope = dstsock->sin6_scope_id;

	/*
	 * Perform source interface selection; the source IPv6 address
	 * must belong to one of the addresses of the interface used
	 * by the route.  For performance reasons, do this only if
	 * there is no route, or if the routing table has changed,
	 * or if we haven't done source interface selection on this
	 * route (for this PCB instance) before.
	 */
	if (!select_srcif) {
		goto getroute;
	} else if (!ROUTE_UNUSABLE(ro) && ro->ro_srcia != NULL &&
	    (ro->ro_flags & ROF_SRCIF_SELECTED)) {
		if (ro->ro_rt->rt_ifp->if_flags & IFF_LOOPBACK)
			local_dst = TRUE;
		ifa = ro->ro_srcia;
		IFA_ADDREF(ifa);	/* for caller */
		goto getroute;
	}

	/*
	 * Given the source IPv6 address, find a suitable source interface
	 * to use for transmission; if a scope ID has been specified,
	 * optimize the search by looking at the addresses only for that
	 * interface.  This is still suboptimal, however, as we need to
	 * traverse the per-interface list.
	 */
	if (ifscope != IFSCOPE_NONE || (ro != NULL && ro->ro_rt != NULL)) {
		unsigned int scope = ifscope;
		struct ifnet *rt_ifp;

		rt_ifp = (ro->ro_rt != NULL) ? ro->ro_rt->rt_ifp : NULL;

		/*
		 * If no scope is specified and the route is stale (pointing
		 * to a defunct interface) use the current primary interface;
		 * this happens when switching between interfaces configured
		 * with the same IPv6 address.  Otherwise pick up the scope
		 * information from the route; the ULP may have looked up a
		 * correct route and we just need to verify it here and mark
		 * it with the ROF_SRCIF_SELECTED flag below.
		 */
		if (scope == IFSCOPE_NONE) {
			scope = rt_ifp->if_index;
			if (scope != get_primary_ifscope(AF_INET6) &&
			    ROUTE_UNUSABLE(ro))
				scope = get_primary_ifscope(AF_INET6);
		}

		ifa = (struct ifaddr *)
		    ifa_foraddr6_scoped(&srcsock->sin6_addr, scope);

		/*
		 * If we are forwarding and proxying prefix(es), see if the
		 * source address is one of ours and is a proxied address;
		 * if so, use it.
		 */
		if (ifa == NULL && ip6_forwarding && nd6_prproxy) {
			ifa = (struct ifaddr *)
			    ifa_foraddr6(&srcsock->sin6_addr);
			if (ifa != NULL && !(proxied_ifa =
			    nd6_prproxy_ifaddr((struct in6_ifaddr *)ifa))) {
				IFA_REMREF(ifa);
				ifa = NULL;
			}
		}

		if (ip6_select_srcif_debug && ifa != NULL) {
			if (ro->ro_rt != NULL) {
				printf("%s->%s ifscope %d->%d ifa_if %s "
				    "ro_if %s\n", s_src, s_dst, ifscope,
				    scope, if_name(ifa->ifa_ifp),
				    if_name(rt_ifp));
			} else {
				printf("%s->%s ifscope %d->%d ifa_if %s\n",
				    s_src, s_dst, ifscope, scope,
				    if_name(ifa->ifa_ifp));
			}
		}
	}

	/*
	 * Slow path; search for an interface having the corresponding source
	 * IPv6 address if the scope was not specified by the caller, and:
	 *
	 *   1) There currently isn't any route, or,
	 *   2) The interface used by the route does not own that source
	 *	IPv6 address; in this case, the route will get blown away
	 *	and we'll do a more specific scoped search using the newly
	 *	found interface.
	 */
	if (ifa == NULL && ifscope == IFSCOPE_NONE) {
		struct ifaddr *ifadst;

		/* Check if the destination address is one of ours */
		ifadst = (struct ifaddr *)ifa_foraddr6(&dstsock->sin6_addr);
		if (ifadst != NULL) {
			local_dst = TRUE;
			IFA_REMREF(ifadst);
		}

		ifa = (struct ifaddr *)ifa_foraddr6(&srcsock->sin6_addr);

		if (ip6_select_srcif_debug && ifa != NULL) {
			printf("%s->%s ifscope %d ifa_if %s\n",
			    s_src, s_dst, ifscope, if_name(ifa->ifa_ifp));
		}

	}

getroute:
	if (ifa != NULL && !proxied_ifa && !local_dst)
		ifscope = ifa->ifa_ifp->if_index;

	/*
	 * If the next hop address for the packet is specified by the caller,
	 * use it as the gateway.
	 */
	if (opts != NULL && opts->ip6po_nexthop != NULL) {
		struct route_in6 *ron;

		sin6_next = satosin6(opts->ip6po_nexthop);

		/* at this moment, we only support AF_INET6 next hops */
		if (sin6_next->sin6_family != AF_INET6) {
			error = EAFNOSUPPORT; /* or should we proceed? */
			goto done;
		}

		/*
		 * If the next hop is an IPv6 address, then the node identified
		 * by that address must be a neighbor of the sending host.
		 */
		ron = &opts->ip6po_nextroute;
		if (ron->ro_rt != NULL)
			RT_LOCK(ron->ro_rt);
		if (ROUTE_UNUSABLE(ron) || (ron->ro_rt != NULL &&
		    (!(ron->ro_rt->rt_flags & RTF_LLINFO) ||
		    (select_srcif && (ifa == NULL ||
		    (ifa->ifa_ifp != ron->ro_rt->rt_ifp && !proxied_ifa))))) ||
		    !IN6_ARE_ADDR_EQUAL(&satosin6(&ron->ro_dst)->sin6_addr,
		    &sin6_next->sin6_addr)) {
			if (ron->ro_rt != NULL)
				RT_UNLOCK(ron->ro_rt);

			ROUTE_RELEASE(ron);
			*satosin6(&ron->ro_dst) = *sin6_next;
		}
		if (ron->ro_rt == NULL) {
			rtalloc_scoped((struct route *)ron, ifscope);
			if (ron->ro_rt != NULL)
				RT_LOCK(ron->ro_rt);
			if (ROUTE_UNUSABLE(ron) ||
			    !(ron->ro_rt->rt_flags & RTF_LLINFO) ||
			    !IN6_ARE_ADDR_EQUAL(&satosin6(rt_key(ron->ro_rt))->
			    sin6_addr, &sin6_next->sin6_addr)) {
				if (ron->ro_rt != NULL)
					RT_UNLOCK(ron->ro_rt);

				ROUTE_RELEASE(ron);
				error = EHOSTUNREACH;
				goto done;
			}
		}
		route = ron;
		ifp = ifp0 = ron->ro_rt->rt_ifp;

		/*
		 * When cloning is required, try to allocate a route to the
		 * destination so that the caller can store path MTU
		 * information.
		 */
		if (!clone) {
			if (select_srcif) {
				/* Keep the route locked */
				goto validateroute;
			}
			RT_UNLOCK(ron->ro_rt);
			goto done;
		}
		RT_UNLOCK(ron->ro_rt);
	}

	/*
	 * Use a cached route if it exists and is valid, else try to allocate
	 * a new one.  Note that we should check the address family of the
	 * cached destination, in case of sharing the cache with IPv4.
	 */
	if (ro == NULL)
		goto done;
	if (ro->ro_rt != NULL)
		RT_LOCK_SPIN(ro->ro_rt);
	if (ROUTE_UNUSABLE(ro) || (ro->ro_rt != NULL &&
	    (satosin6(&ro->ro_dst)->sin6_family != AF_INET6 ||
	    !IN6_ARE_ADDR_EQUAL(&satosin6(&ro->ro_dst)->sin6_addr, dst) ||
	    (select_srcif && (ifa == NULL ||
	    (ifa->ifa_ifp != ro->ro_rt->rt_ifp && !proxied_ifa)))))) {
		if (ro->ro_rt != NULL)
			RT_UNLOCK(ro->ro_rt);

		ROUTE_RELEASE(ro);
	}
	if (ro->ro_rt == NULL) {
		struct sockaddr_in6 *sa6;

		if (ro->ro_rt != NULL)
			RT_UNLOCK(ro->ro_rt);
		/* No route yet, so try to acquire one */
		bzero(&ro->ro_dst, sizeof (struct sockaddr_in6));
		sa6 = (struct sockaddr_in6 *)&ro->ro_dst;
		sa6->sin6_family = AF_INET6;
		sa6->sin6_len = sizeof (struct sockaddr_in6);
		sa6->sin6_addr = *dst;
		if (IN6_IS_ADDR_MULTICAST(dst)) {
			ro->ro_rt = rtalloc1_scoped(
			    &((struct route *)ro)->ro_dst, 0, 0, ifscope);
		} else {
			rtalloc_scoped((struct route *)ro, ifscope);
		}
		if (ro->ro_rt != NULL)
			RT_LOCK_SPIN(ro->ro_rt);
	}

	/*
	 * Do not care about the result if we have the nexthop
	 * explicitly specified (in case we're asked to clone.)
	 */
	if (opts != NULL && opts->ip6po_nexthop != NULL) {
		if (ro->ro_rt != NULL)
			RT_UNLOCK(ro->ro_rt);
		goto done;
	}

	if (ro->ro_rt != NULL) {
		RT_LOCK_ASSERT_HELD(ro->ro_rt);
		ifp = ifp0 = ro->ro_rt->rt_ifp;
	} else {
		error = EHOSTUNREACH;
	}
	route = ro;

validateroute:
	if (select_srcif) {
		boolean_t has_route = (route != NULL && route->ro_rt != NULL);
		boolean_t srcif_selected = FALSE;

		if (has_route)
			RT_LOCK_ASSERT_HELD(route->ro_rt);
		/*
		 * If there is a non-loopback route with the wrong interface,
		 * or if there is no interface configured with such an address,
		 * blow it away.  Except for local/loopback, we look for one
		 * with a matching interface scope/index.
		 */
		if (has_route && (ifa == NULL ||
		    (ifa->ifa_ifp != ifp && ifp != lo_ifp) ||
		    !(route->ro_rt->rt_flags & RTF_UP))) {
			/*
			 * If the destination address belongs to a proxied
			 * prefix, relax the requirement and allow the packet
			 * to come out of the proxy interface with the source
			 * address of the real interface.
			 */
			if (ifa != NULL && proxied_ifa &&
			    (route->ro_rt->rt_flags & (RTF_UP|RTF_PROXY)) ==
			    (RTF_UP|RTF_PROXY)) {
				srcif_selected = TRUE;
			} else {
				if (ip6_select_srcif_debug) {
					if (ifa != NULL) {
						printf("%s->%s ifscope %d "
						    "ro_if %s != ifa_if %s "
						    "(cached route cleared)\n",
						    s_src, s_dst,
						    ifscope, if_name(ifp),
						    if_name(ifa->ifa_ifp));
					} else {
						printf("%s->%s ifscope %d "
						    "ro_if %s (no ifa_if "
						    "found)\n", s_src, s_dst,
						    ifscope, if_name(ifp));
					}
				}
				RT_UNLOCK(route->ro_rt);
				ROUTE_RELEASE(route);
				error = EHOSTUNREACH;
				/* Undo the settings done above */
				route = NULL;
				ifp = NULL;	/* ditch ifp; keep ifp0 */
				has_route = FALSE;
			}
		} else if (has_route) {
			srcif_selected = TRUE;
		}

		if (srcif_selected) {
			VERIFY(has_route);
			if (ifa != route->ro_srcia ||
			    !(route->ro_flags & ROF_SRCIF_SELECTED)) {
				RT_CONVERT_LOCK(route->ro_rt);
				if (ifa != NULL)
					IFA_ADDREF(ifa); /* for route_in6 */
				if (route->ro_srcia != NULL)
					IFA_REMREF(route->ro_srcia);
				route->ro_srcia = ifa;
				route->ro_flags |= ROF_SRCIF_SELECTED;
				RT_GENID_SYNC(route->ro_rt);
			}
			RT_UNLOCK(route->ro_rt);
		}
	} else {
		if (ro->ro_rt != NULL)
			RT_UNLOCK(ro->ro_rt);
		if (ifp != NULL && opts != NULL &&
		    opts->ip6po_pktinfo != NULL &&
		    opts->ip6po_pktinfo->ipi6_ifindex != 0) {
			/*
			 * Check if the outgoing interface conflicts with the
			 * interface specified by ipi6_ifindex (if specified).
			 * Note that loopback interface is always okay.
			 * (this may happen when we are sending a packet to
			 * one of our own addresses.)
			 */
			if (!(ifp->if_flags & IFF_LOOPBACK) && ifp->if_index !=
			    opts->ip6po_pktinfo->ipi6_ifindex) {
				error = EHOSTUNREACH;
				goto done;
			}
		}
	}

done:
	if (error == 0) {
		if (ip6oa != NULL &&
		    (ip6oa->ip6oa_flags & IP6OAF_NO_CELLULAR) &&
		    ((ifp != NULL && IFNET_IS_CELLULAR(ifp)) ||
		    (route != NULL && route->ro_rt != NULL &&
		    IFNET_IS_CELLULAR(route->ro_rt->rt_ifp)))) {
			if (route != NULL && route->ro_rt != NULL) {
				ROUTE_RELEASE(route);
				route = NULL;
			}
			ifp = NULL;	/* ditch ifp; keep ifp0 */
			error = EHOSTUNREACH;
			ip6oa->ip6oa_retflags |= IP6OARF_IFDENIED;
		}
	}

	/*
	 * If the interface is disabled for IPv6, then ENETDOWN error.
	 */
	if (error == 0 &&
	    ifp != NULL && (ifp->if_eflags & IFEF_IPV6_DISABLED)) {
		error = ENETDOWN;
	}

	if (ifp == NULL && (route == NULL || route->ro_rt == NULL)) {
		/*
		 * This can happen if the caller did not pass a cached route
		 * nor any other hints.  We treat this case an error.
		 */
		error = EHOSTUNREACH;
	}
	if (error == EHOSTUNREACH || error == ENETDOWN)
		ip6stat.ip6s_noroute++;

	/*
	 * We'll return ifp regardless of error, so pick it up from ifp0
	 * in case it was nullified above.  Caller is responsible for
	 * releasing the ifp if it is non-NULL.
	 */
	ifp = ifp0;
	if (retifp != NULL) {
		if (ifp != NULL)
			ifnet_reference(ifp);	/* for caller */
		*retifp = ifp;
	}

	if (retsrcia != NULL) {
		if (ifa != NULL)
			IFA_ADDREF(ifa);	/* for caller */
		*retsrcia = (struct in6_ifaddr *)ifa;
	}

	if (error == 0) {
		if (retrt != NULL && route != NULL)
			*retrt = route->ro_rt;	/* ro_rt may be NULL */
	} else if (select_srcif && ip6_select_srcif_debug) {
		printf("%s->%s ifscope %d ifa_if %s ro_if %s (error=%d)\n",
		    s_src, s_dst, ifscope,
		    (ifa != NULL) ? if_name(ifa->ifa_ifp) : "NONE",
		    (ifp != NULL) ? if_name(ifp) : "NONE", error);
	}

	if (ifa != NULL)
		IFA_REMREF(ifa);

	return (error);
}

/*
 * Regardless of error, it will return an ifp with a reference held if the
 * caller provides a non-NULL retifp.  The caller is responsible for checking
 * if the returned ifp is valid and release its reference at all times.
 */
static int
in6_selectif(struct sockaddr_in6 *dstsock, struct ip6_pktopts *opts,
    struct ip6_moptions *mopts, struct route_in6 *ro,
    struct ip6_out_args *ip6oa, struct ifnet **retifp)
{
	int err = 0;
	struct route_in6 sro;
	struct rtentry *rt = NULL;

	if (ro == NULL) {
		bzero(&sro, sizeof (sro));
		ro = &sro;
	}

	if ((err = selectroute(NULL, dstsock, opts, mopts, NULL, ro, retifp,
	    &rt, 0, 1, ip6oa)) != 0)
		goto done;

	/*
	 * do not use a rejected or black hole route.
	 * XXX: this check should be done in the L2 output routine.
	 * However, if we skipped this check here, we'd see the following
	 * scenario:
	 * - install a rejected route for a scoped address prefix
	 *   (like fe80::/10)
	 * - send a packet to a destination that matches the scoped prefix,
	 *   with ambiguity about the scope zone.
	 * - pick the outgoing interface from the route, and disambiguate the
	 *   scope zone with the interface.
	 * - ip6_output() would try to get another route with the "new"
	 *   destination, which may be valid.
	 * - we'd see no error on output.
	 * Although this may not be very harmful, it should still be confusing.
	 * We thus reject the case here.
	 */
	if (rt && (rt->rt_flags & (RTF_REJECT | RTF_BLACKHOLE))) {
		err = ((rt->rt_flags & RTF_HOST) ? EHOSTUNREACH : ENETUNREACH);
		goto done;
	}

	/*
	 * Adjust the "outgoing" interface.  If we're going to loop the packet
	 * back to ourselves, the ifp would be the loopback interface.
	 * However, we'd rather know the interface associated to the
	 * destination address (which should probably be one of our own
	 * addresses.)
	 */
	if (rt != NULL && rt->rt_ifa != NULL && rt->rt_ifa->ifa_ifp != NULL &&
	    retifp != NULL) {
		ifnet_reference(rt->rt_ifa->ifa_ifp);
		if (*retifp != NULL)
			ifnet_release(*retifp);
		*retifp = rt->rt_ifa->ifa_ifp;
	}

done:
	if (ro == &sro) {
		VERIFY(rt == NULL || rt == ro->ro_rt);
		ROUTE_RELEASE(ro);
	}

	/*
	 * retifp might point to a valid ifp with a reference held;
	 * caller is responsible for releasing it if non-NULL.
	 */
	return (err);
}

/*
 * Regardless of error, it will return an ifp with a reference held if the
 * caller provides a non-NULL retifp.  The caller is responsible for checking
 * if the returned ifp is valid and release its reference at all times.
 *
 * clone - meaningful only for bsdi and freebsd
 */
int
in6_selectroute(struct sockaddr_in6 *srcsock, struct sockaddr_in6 *dstsock,
    struct ip6_pktopts *opts, struct ip6_moptions *mopts,
    struct in6_ifaddr **retsrcia, struct route_in6 *ro, struct ifnet **retifp,
    struct rtentry **retrt, int clone, struct ip6_out_args *ip6oa)
{

	return (selectroute(srcsock, dstsock, opts, mopts, retsrcia, ro, retifp,
	    retrt, clone, 0, ip6oa));
}

/*
 * Default hop limit selection. The precedence is as follows:
 * 1. Hoplimit value specified via ioctl.
 * 2. (If the outgoing interface is detected) the current
 *     hop limit of the interface specified by router advertisement.
 * 3. The system default hoplimit.
 */
int
in6_selecthlim(struct in6pcb *in6p, struct ifnet *ifp)
{
	if (in6p && in6p->in6p_hops >= 0) {
		return (in6p->in6p_hops);
	} else {
		lck_rw_lock_shared(nd_if_rwlock);
		if (ifp && ifp->if_index < nd_ifinfo_indexlim) {
			u_int8_t chlim;
			struct nd_ifinfo *ndi = &nd_ifinfo[ifp->if_index];

			if (ndi->initialized) {
				/* access chlim without lock, for performance */
				chlim = ndi->chlim;
			} else {
				chlim = ip6_defhlim;
			}
			lck_rw_done(nd_if_rwlock);
			return (chlim);
		} else {
			lck_rw_done(nd_if_rwlock);
			return (ip6_defhlim);
		}
	}
}

/*
 * XXX: this is borrowed from in6_pcbbind(). If possible, we should
 * share this function by all *bsd*...
 */
int
in6_pcbsetport(struct in6_addr *laddr, struct inpcb *inp, struct proc *p,
    int locked)
{
#pragma unused(laddr)
	struct socket *so = inp->inp_socket;
	u_int16_t lport = 0, first, last, *lastport;
	int count, error = 0, wild = 0;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	kauth_cred_t cred;
	if (!locked) { /* Make sure we don't run into a deadlock: 4052373 */
		if (!lck_rw_try_lock_exclusive(pcbinfo->ipi_lock)) {
			socket_unlock(inp->inp_socket, 0);
			lck_rw_lock_exclusive(pcbinfo->ipi_lock);
			socket_lock(inp->inp_socket, 0);
		}
	}

	/* XXX: this is redundant when called from in6_pcbbind */
	if ((so->so_options & (SO_REUSEADDR|SO_REUSEPORT)) == 0)
		wild = INPLOOKUP_WILDCARD;

	inp->inp_flags |= INP_ANONPORT;

	if (inp->inp_flags & INP_HIGHPORT) {
		first = ipport_hifirstauto;	/* sysctl */
		last  = ipport_hilastauto;
		lastport = &pcbinfo->ipi_lasthi;
	} else if (inp->inp_flags & INP_LOWPORT) {
		cred = kauth_cred_proc_ref(p);
		error = priv_check_cred(cred, PRIV_NETINET_RESERVEDPORT, 0);
		kauth_cred_unref(&cred);
		if (error != 0) {
			if (!locked)
				lck_rw_done(pcbinfo->ipi_lock);
			return (error);
		}
		first = ipport_lowfirstauto;	/* 1023 */
		last  = ipport_lowlastauto;	/* 600 */
		lastport = &pcbinfo->ipi_lastlow;
	} else {
		first = ipport_firstauto;	/* sysctl */
		last  = ipport_lastauto;
		lastport = &pcbinfo->ipi_lastport;
	}
	/*
	 * Simple check to ensure all ports are not used up causing
	 * a deadlock here.
	 *
	 * We split the two cases (up and down) so that the direction
	 * is not being tested on each round of the loop.
	 */
	if (first > last) {
		/*
		 * counting down
		 */
		count = first - last;

		do {
			if (count-- < 0) {	/* completely used? */
				/*
				 * Undo any address bind that may have
				 * occurred above.
				 */
				inp->in6p_laddr = in6addr_any;
				inp->in6p_last_outifp = NULL;
				if (!locked)
					lck_rw_done(pcbinfo->ipi_lock);
				return (EAGAIN);
			}
			--*lastport;
			if (*lastport > first || *lastport < last)
				*lastport = first;
			lport = htons(*lastport);
		} while (in6_pcblookup_local(pcbinfo, &inp->in6p_laddr, lport,
		    wild));
	} else {
		/* counting up */
		count = last - first;

		do {
			if (count-- < 0) {	/* completely used? */
				/*
				 * Undo any address bind that may have
				 * occurred above.
				 */
				inp->in6p_laddr = in6addr_any;
				inp->in6p_last_outifp = NULL;
				if (!locked)
					lck_rw_done(pcbinfo->ipi_lock);
				return (EAGAIN);
			}
			++*lastport;
			if (*lastport < first || *lastport > last)
				*lastport = first;
			lport = htons(*lastport);
		} while (in6_pcblookup_local(pcbinfo, &inp->in6p_laddr, lport,
		    wild));
	}

	inp->inp_lport = lport;
	if (in_pcbinshash(inp, 1) != 0) {
		inp->in6p_laddr = in6addr_any;
		inp->inp_lport = 0;
		inp->in6p_last_outifp = NULL;
		if (!locked)
			lck_rw_done(pcbinfo->ipi_lock);
		return (EAGAIN);
	}

	if (!locked)
		lck_rw_done(pcbinfo->ipi_lock);
	return (0);
}

/*
 * The followings are implementation of the policy table using a
 * simple tail queue.
 * XXX such details should be hidden.
 * XXX implementation using binary tree should be more efficient.
 */
struct addrsel_policyent {
	TAILQ_ENTRY(addrsel_policyent) ape_entry;
	struct in6_addrpolicy ape_policy;
};

TAILQ_HEAD(addrsel_policyhead, addrsel_policyent);

struct addrsel_policyhead addrsel_policytab;

static void
init_policy_queue(void)
{
	TAILQ_INIT(&addrsel_policytab);
}

void
addrsel_policy_init(void)
{
	/*
	 * Default address selection policy based on RFC 3484 and
	 * draft-arifumi-6man-rfc3484-revise-03.
	 */
	static const struct in6_addrpolicy defaddrsel[] = {
		/* localhost */
		{
			.addr = {
				.sin6_family = AF_INET6,
				.sin6_addr   = IN6ADDR_LOOPBACK_INIT,
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.addrmask = {
				.sin6_family = AF_INET6,
				.sin6_addr   = IN6MASK128,
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.preced   = 60,
			.label    = 0
		},

		/* ULA */
		{
			.addr = {
				.sin6_family = AF_INET6,
				.sin6_addr   = {{{ 0xfc }}},
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.addrmask = {
				.sin6_family = AF_INET6,
				.sin6_addr   = IN6MASK7,
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.preced   = 50,
			.label    = 1
		},

		/* any IPv6 src */
		{
			.addr = {
				.sin6_family = AF_INET6,
				.sin6_addr   = IN6ADDR_ANY_INIT,
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.addrmask = {
				.sin6_family = AF_INET6,
				.sin6_addr   = IN6MASK0,
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.preced   = 40,
			.label    = 2 },

		/* any IPv4 src */
		{
			.addr = {
				.sin6_family = AF_INET6,
				.sin6_addr   = IN6ADDR_V4MAPPED_INIT,
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.addrmask = {
				.sin6_family = AF_INET6,
				.sin6_addr   = IN6MASK96,
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.preced   = 30,
			.label    = 3
		},

		/* 6to4 */
		{
			.addr = {
				.sin6_family = AF_INET6,
				.sin6_addr   = {{{ 0x20, 0x02 }}},
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.addrmask = {
				.sin6_family = AF_INET6,
				.sin6_addr   = IN6MASK16,
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.preced   = 20,
			.label    = 4
		},

		/* Teredo */
		{
			.addr = {
				.sin6_family = AF_INET6,
				.sin6_addr   = {{{ 0x20, 0x01 }}},
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.addrmask = {
				.sin6_family = AF_INET6,
				.sin6_addr   = IN6MASK32,
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.preced   = 10,
			.label    = 5
		},

		/* v4 compat addresses */
		{
			.addr = {
				.sin6_family = AF_INET6,
				.sin6_addr = IN6ADDR_ANY_INIT,
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.addrmask = {
				.sin6_family = AF_INET6,
				.sin6_addr = IN6MASK96,
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.preced   = 1,
			.label    = 10
		},

		/* site-local (deprecated) */
		{
			.addr = {
				.sin6_family = AF_INET6,
				.sin6_addr = {{{ 0xfe, 0xc0 }}},
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.addrmask = {
				.sin6_family = AF_INET6,
				.sin6_addr = IN6MASK16,
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.preced   = 1,
			.label    = 11
		},

		/* 6bone (deprecated) */
		{
			.addr = {
				.sin6_family = AF_INET6,
				.sin6_addr = {{{ 0x3f, 0xfe }}},
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.addrmask = {
				.sin6_family = AF_INET6,
				.sin6_addr = IN6MASK16,
				.sin6_len    = sizeof (struct sockaddr_in6)
			},
			.preced   = 1,
			.label    = 12
		},
	};
	int i;

	init_policy_queue();

	/* initialize the "last resort" policy */
	bzero(&defaultaddrpolicy, sizeof (defaultaddrpolicy));
	defaultaddrpolicy.label = ADDR_LABEL_NOTAPP;

	for (i = 0; i < sizeof (defaddrsel) / sizeof (defaddrsel[0]); i++)
		add_addrsel_policyent(&defaddrsel[i]);

}

struct in6_addrpolicy *
in6_addrsel_lookup_policy(struct sockaddr_in6 *key)
{
	struct in6_addrpolicy *match = NULL;

	ADDRSEL_LOCK();
	match = match_addrsel_policy(key);

	if (match == NULL)
		match = &defaultaddrpolicy;
	else
		match->use++;
	ADDRSEL_UNLOCK();

	return (match);
}

static struct in6_addrpolicy *
match_addrsel_policy(struct sockaddr_in6 *key)
{
	struct addrsel_policyent *pent;
	struct in6_addrpolicy *bestpol = NULL, *pol;
	int matchlen, bestmatchlen = -1;
	u_char *mp, *ep, *k, *p, m;

	TAILQ_FOREACH(pent, &addrsel_policytab, ape_entry) {
		matchlen = 0;

		pol = &pent->ape_policy;
		mp = (u_char *)&pol->addrmask.sin6_addr;
		ep = mp + 16;	/* XXX: scope field? */
		k = (u_char *)&key->sin6_addr;
		p = (u_char *)&pol->addr.sin6_addr;
		for (; mp < ep && *mp; mp++, k++, p++) {
			m = *mp;
			if ((*k & m) != *p)
				goto next; /* not match */
			if (m == 0xff) /* short cut for a typical case */
				matchlen += 8;
			else {
				while (m >= 0x80) {
					matchlen++;
					m <<= 1;
				}
			}
		}

		/* matched.  check if this is better than the current best. */
		if (bestpol == NULL ||
		    matchlen > bestmatchlen) {
			bestpol = pol;
			bestmatchlen = matchlen;
		}

	next:
		continue;
	}

	return (bestpol);
}

static int
add_addrsel_policyent(const struct in6_addrpolicy *newpolicy)
{
	struct addrsel_policyent *new, *pol;

	MALLOC(new, struct addrsel_policyent *, sizeof (*new), M_IFADDR,
	    M_WAITOK);

	ADDRSEL_LOCK();

	/* duplication check */
	TAILQ_FOREACH(pol, &addrsel_policytab, ape_entry) {
		if (IN6_ARE_ADDR_EQUAL(&newpolicy->addr.sin6_addr,
		    &pol->ape_policy.addr.sin6_addr) &&
		    IN6_ARE_ADDR_EQUAL(&newpolicy->addrmask.sin6_addr,
		    &pol->ape_policy.addrmask.sin6_addr)) {
			ADDRSEL_UNLOCK();
			FREE(new, M_IFADDR);
			return (EEXIST);	/* or override it? */
		}
	}

	bzero(new, sizeof (*new));

	/* XXX: should validate entry */
	new->ape_policy = *newpolicy;

	TAILQ_INSERT_TAIL(&addrsel_policytab, new, ape_entry);
	ADDRSEL_UNLOCK();

	return (0);
}
#ifdef ENABLE_ADDRSEL
static int
delete_addrsel_policyent(const struct in6_addrpolicy *key)
{
	struct addrsel_policyent *pol;


	ADDRSEL_LOCK();

	/* search for the entry in the table */
	TAILQ_FOREACH(pol, &addrsel_policytab, ape_entry) {
		if (IN6_ARE_ADDR_EQUAL(&key->addr.sin6_addr,
		    &pol->ape_policy.addr.sin6_addr) &&
		    IN6_ARE_ADDR_EQUAL(&key->addrmask.sin6_addr,
		    &pol->ape_policy.addrmask.sin6_addr)) {
			break;
		}
	}
	if (pol == NULL) {
		ADDRSEL_UNLOCK();
		return (ESRCH);
	}

	TAILQ_REMOVE(&addrsel_policytab, pol, ape_entry);
	FREE(pol, M_IFADDR);
	pol = NULL;
	ADDRSEL_UNLOCK();

	return (0);
}
#endif /* ENABLE_ADDRSEL */

int
walk_addrsel_policy(int (*callback)(const struct in6_addrpolicy *, void *),
    void *w)
{
	struct addrsel_policyent *pol;
	int error = 0;

	ADDRSEL_LOCK();
	TAILQ_FOREACH(pol, &addrsel_policytab, ape_entry) {
		if ((error = (*callback)(&pol->ape_policy, w)) != 0) {
			ADDRSEL_UNLOCK();
			return (error);
		}
	}
	ADDRSEL_UNLOCK();
	return (error);
}
/*
 * Subroutines to manage the address selection policy table via sysctl.
 */
struct walkarg {
	struct sysctl_req *w_req;
};


static int
dump_addrsel_policyent(const struct in6_addrpolicy *pol, void *arg)
{
	int error = 0;
	struct walkarg *w = arg;

	error = SYSCTL_OUT(w->w_req, pol, sizeof (*pol));

	return (error);
}

static int
in6_src_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
struct walkarg w;

	if (req->newptr)
		return (EPERM);
	bzero(&w, sizeof (w));
	w.w_req = req;

	return (walk_addrsel_policy(dump_addrsel_policyent, &w));
}


SYSCTL_NODE(_net_inet6_ip6, IPV6CTL_ADDRCTLPOLICY, addrctlpolicy,
	CTLFLAG_RD | CTLFLAG_LOCKED, in6_src_sysctl, "");
int
in6_src_ioctl(u_long cmd, caddr_t data)
{
	int i;
	struct in6_addrpolicy ent0;

	if (cmd != SIOCAADDRCTL_POLICY && cmd != SIOCDADDRCTL_POLICY)
		return (EOPNOTSUPP); /* check for safety */

	bcopy(data, &ent0, sizeof (ent0));

	if (ent0.label == ADDR_LABEL_NOTAPP)
		return (EINVAL);
	/* check if the prefix mask is consecutive. */
	if (in6_mask2len(&ent0.addrmask.sin6_addr, NULL) < 0)
		return (EINVAL);
	/* clear trailing garbages (if any) of the prefix address. */
	for (i = 0; i < 4; i++) {
		ent0.addr.sin6_addr.s6_addr32[i] &=
			ent0.addrmask.sin6_addr.s6_addr32[i];
	}
	ent0.use = 0;

	switch (cmd) {
	case SIOCAADDRCTL_POLICY:
#ifdef ENABLE_ADDRSEL
		return (add_addrsel_policyent(&ent0));
#else
		return (ENOTSUP);
#endif
	case SIOCDADDRCTL_POLICY:
#ifdef ENABLE_ADDRSEL
		return (delete_addrsel_policyent(&ent0));
#else
		return (ENOTSUP);
#endif
	}

	return (0);		/* XXX: compromise compilers */
}

/*
 * generate kernel-internal form (scopeid embedded into s6_addr16[1]).
 * If the address scope of is link-local, embed the interface index in the
 * address.  The routine determines our precedence
 * between advanced API scope/interface specification and basic API
 * specification.
 *
 * this function should be nuked in the future, when we get rid of
 * embedded scopeid thing.
 *
 * XXX actually, it is over-specification to return ifp against sin6_scope_id.
 * there can be multiple interfaces that belong to a particular scope zone
 * (in specification, we have 1:N mapping between a scope zone and interfaces).
 * we may want to change the function to return something other than ifp.
 */
int
in6_embedscope(struct in6_addr *in6, const struct sockaddr_in6 *sin6,
    struct in6pcb *in6p, struct ifnet **ifpp, struct ip6_pktopts *opt)
{
	struct ifnet *ifp = NULL;
	u_int32_t scopeid;
	struct ip6_pktopts *optp = NULL;

	*in6 = sin6->sin6_addr;
	scopeid = sin6->sin6_scope_id;
	if (ifpp != NULL)
		*ifpp = NULL;

	/*
	 * don't try to read sin6->sin6_addr beyond here, since the caller may
	 * ask us to overwrite existing sockaddr_in6
	 */

#ifdef ENABLE_DEFAULT_SCOPE
	if (scopeid == 0)
		scopeid = scope6_addr2default(in6);
#endif

	if (IN6_IS_SCOPE_LINKLOCAL(in6)) {
		struct in6_pktinfo *pi;
		struct ifnet *im6o_multicast_ifp = NULL;

		if (in6p != NULL && IN6_IS_ADDR_MULTICAST(in6) &&
		    in6p->in6p_moptions != NULL) {
			IM6O_LOCK(in6p->in6p_moptions);
			im6o_multicast_ifp =
			    in6p->in6p_moptions->im6o_multicast_ifp;
			IM6O_UNLOCK(in6p->in6p_moptions);
		}

		if (opt != NULL)
			optp = opt;
		else if (in6p != NULL)
			optp = in6p->in6p_outputopts;
		/*
		 * KAME assumption: link id == interface id
		 */
		if (in6p != NULL && optp != NULL &&
		    (pi = optp->ip6po_pktinfo) != NULL &&
		    pi->ipi6_ifindex != 0) {
			/* ifp is needed here if only we're returning it */
			if (ifpp != NULL) {
				ifnet_head_lock_shared();
				ifp = ifindex2ifnet[pi->ipi6_ifindex];
				ifnet_head_done();
			}
			in6->s6_addr16[1] = htons(pi->ipi6_ifindex);
		} else if (in6p != NULL && IN6_IS_ADDR_MULTICAST(in6) &&
		    in6p->in6p_moptions != NULL && im6o_multicast_ifp != NULL) {
			ifp = im6o_multicast_ifp;
			in6->s6_addr16[1] = htons(ifp->if_index);
		} else if (scopeid != 0) {
			/*
			 * Since scopeid is unsigned, we only have to check it
			 * against if_index (ifnet_head_lock not needed since
			 * if_index is an ever-increasing integer.)
			 */
			if (if_index < scopeid)
				return (ENXIO);  /* XXX EINVAL? */

			/* ifp is needed here only if we're returning it */
			if (ifpp != NULL) {
				ifnet_head_lock_shared();
				ifp = ifindex2ifnet[scopeid];
				ifnet_head_done();
			}
			/* XXX assignment to 16bit from 32bit variable */
			in6->s6_addr16[1] = htons(scopeid & 0xffff);
		}

		if (ifpp != NULL) {
			if (ifp != NULL)
				ifnet_reference(ifp);	/* for caller */
			*ifpp = ifp;
		}
	}

	return (0);
}

/*
 * generate standard sockaddr_in6 from embedded form.
 * touches sin6_addr and sin6_scope_id only.
 *
 * this function should be nuked in the future, when we get rid of
 * embedded scopeid thing.
 */
int
in6_recoverscope(
	struct sockaddr_in6 *sin6,
	const struct in6_addr *in6,
	struct ifnet *ifp)
{
	u_int32_t scopeid;

	sin6->sin6_addr = *in6;

	/*
	 * don't try to read *in6 beyond here, since the caller may
	 * ask us to overwrite existing sockaddr_in6
	 */

	sin6->sin6_scope_id = 0;
	if (IN6_IS_SCOPE_LINKLOCAL(in6)) {
		/*
		 * KAME assumption: link id == interface id
		 */
		scopeid = ntohs(sin6->sin6_addr.s6_addr16[1]);
		if (scopeid) {
			/*
			 * sanity check
			 *
			 * Since scopeid is unsigned, we only have to check it
			 * against if_index
			 */
			if (if_index < scopeid)
				return (ENXIO);
			if (ifp && ifp->if_index != scopeid)
				return (ENXIO);
			sin6->sin6_addr.s6_addr16[1] = 0;
			sin6->sin6_scope_id = scopeid;
		}
	}

	return (0);
}
