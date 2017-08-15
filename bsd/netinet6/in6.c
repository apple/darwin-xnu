/*
 * Copyright (c) 2003-2016 Apple Inc. All rights reserved.
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
 *	@(#)in.c	8.2 (Berkeley) 11/15/93
 */


#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/kern_event.h>
#include <sys/mcache.h>
#include <sys/protosw.h>

#include <kern/locks.h>
#include <kern/zalloc.h>
#include <libkern/OSAtomic.h>
#include <machine/machine_routines.h>
#include <mach/boolean.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_var.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/kpi_protocol.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>

#include <netinet6/nd6.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/mld6_var.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/scope6_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/in6_pcb.h>

#include <net/net_osdep.h>

#include <net/dlil.h>

#if PF
#include <net/pfvar.h>
#endif /* PF */

/*
 * Definitions of some costant IP6 addresses.
 */
const struct in6_addr in6addr_any = IN6ADDR_ANY_INIT;
const struct in6_addr in6addr_loopback = IN6ADDR_LOOPBACK_INIT;
const struct in6_addr in6addr_nodelocal_allnodes =
	IN6ADDR_NODELOCAL_ALLNODES_INIT;
const struct in6_addr in6addr_linklocal_allnodes =
	IN6ADDR_LINKLOCAL_ALLNODES_INIT;
const struct in6_addr in6addr_linklocal_allrouters =
	IN6ADDR_LINKLOCAL_ALLROUTERS_INIT;
const struct in6_addr in6addr_linklocal_allv2routers =
	IN6ADDR_LINKLOCAL_ALLV2ROUTERS_INIT;

const struct in6_addr in6mask0 = IN6MASK0;
const struct in6_addr in6mask7 = IN6MASK7;
const struct in6_addr in6mask16 = IN6MASK16;
const struct in6_addr in6mask32 = IN6MASK32;
const struct in6_addr in6mask64 = IN6MASK64;
const struct in6_addr in6mask96 = IN6MASK96;
const struct in6_addr in6mask128 = IN6MASK128;

const struct sockaddr_in6 sa6_any = {
	sizeof (sa6_any), AF_INET6, 0, 0, IN6ADDR_ANY_INIT, 0
};

static int in6ctl_associd(struct socket *, u_long, caddr_t);
static int in6ctl_connid(struct socket *, u_long, caddr_t);
static int in6ctl_conninfo(struct socket *, u_long, caddr_t);
static int in6ctl_llstart(struct ifnet *, u_long, caddr_t);
static int in6ctl_llstop(struct ifnet *);
static int in6ctl_cgastart(struct ifnet *, u_long, caddr_t);
static int in6ctl_gifaddr(struct ifnet *, struct in6_ifaddr *, u_long,
    struct in6_ifreq *);
static int in6ctl_gifstat(struct ifnet *, u_long, struct in6_ifreq *);
static int in6ctl_alifetime(struct in6_ifaddr *, u_long, struct in6_ifreq *,
    boolean_t);
static int in6ctl_aifaddr(struct ifnet *, struct in6_aliasreq *);
static void in6ctl_difaddr(struct ifnet *, struct in6_ifaddr *);
static int in6_autoconf(struct ifnet *, int);
static int in6_setrouter(struct ifnet *, int);
static int in6_ifinit(struct ifnet *, struct in6_ifaddr *, int);
static int in6_ifaupdate_aux(struct in6_ifaddr *, struct ifnet *, int);
static void in6_unlink_ifa(struct in6_ifaddr *, struct ifnet *);
static struct in6_ifaddr *in6_ifaddr_alloc(int);
static void in6_ifaddr_attached(struct ifaddr *);
static void in6_ifaddr_detached(struct ifaddr *);
static void in6_ifaddr_free(struct ifaddr *);
static void in6_ifaddr_trace(struct ifaddr *, int);
#if defined(__LP64__)
static void in6_cgareq_32_to_64(struct in6_cgareq_32 *,
    struct in6_cgareq_64 *);
#else
static void in6_cgareq_64_to_32(struct in6_cgareq_64 *,
    struct in6_cgareq_32 *);
#endif
static struct in6_aliasreq *in6_aliasreq_to_native(void *, int,
    struct in6_aliasreq *);
static struct in6_cgareq *in6_cgareq_to_native(void *, int,
    struct in6_cgareq *);
static int in6_to_kamescope(struct sockaddr_in6 *, struct ifnet *);
static int in6_getassocids(struct socket *, uint32_t *, user_addr_t);
static int in6_getconnids(struct socket *, sae_associd_t, uint32_t *,
    user_addr_t);
static int in6_getconninfo(struct socket *, sae_connid_t, uint32_t *,
    uint32_t *, int32_t *, user_addr_t, socklen_t *, user_addr_t, socklen_t *,
    uint32_t *, user_addr_t, uint32_t *);

static void in6_if_up_dad_start(struct ifnet *);

extern lck_mtx_t *nd6_mutex;

#define	IN6IFA_TRACE_HIST_SIZE	32	/* size of trace history */

/* For gdb */
__private_extern__ unsigned int in6ifa_trace_hist_size = IN6IFA_TRACE_HIST_SIZE;

struct in6_ifaddr_dbg {
	struct in6_ifaddr	in6ifa;			/* in6_ifaddr */
	struct in6_ifaddr	in6ifa_old;		/* saved in6_ifaddr */
	u_int16_t		in6ifa_refhold_cnt;	/* # of IFA_ADDREF */
	u_int16_t		in6ifa_refrele_cnt;	/* # of IFA_REMREF */
	/*
	 * Alloc and free callers.
	 */
	ctrace_t		in6ifa_alloc;
	ctrace_t		in6ifa_free;
	/*
	 * Circular lists of IFA_ADDREF and IFA_REMREF callers.
	 */
	ctrace_t		in6ifa_refhold[IN6IFA_TRACE_HIST_SIZE];
	ctrace_t		in6ifa_refrele[IN6IFA_TRACE_HIST_SIZE];
	/*
	 * Trash list linkage
	 */
	TAILQ_ENTRY(in6_ifaddr_dbg) in6ifa_trash_link;
};

/* List of trash in6_ifaddr entries protected by in6ifa_trash_lock */
static TAILQ_HEAD(, in6_ifaddr_dbg) in6ifa_trash_head;
static decl_lck_mtx_data(, in6ifa_trash_lock);

#if DEBUG
static unsigned int in6ifa_debug = 1;		/* debugging (enabled) */
#else
static unsigned int in6ifa_debug;		/* debugging (disabled) */
#endif /* !DEBUG */
static unsigned int in6ifa_size;		/* size of zone element */
static struct zone *in6ifa_zone;		/* zone for in6_ifaddr */

#define	IN6IFA_ZONE_MAX		64		/* maximum elements in zone */
#define	IN6IFA_ZONE_NAME	"in6_ifaddr"	/* zone name */

/*
 * Subroutine for in6_ifaddloop() and in6_ifremloop().
 * This routine does actual work.
 */
static void
in6_ifloop_request(int cmd, struct ifaddr *ifa)
{
	struct sockaddr_in6 all1_sa;
	struct rtentry *nrt = NULL;
	int e;

	bzero(&all1_sa, sizeof (all1_sa));
	all1_sa.sin6_family = AF_INET6;
	all1_sa.sin6_len = sizeof (struct sockaddr_in6);
	all1_sa.sin6_addr = in6mask128;

	/*
	 * We specify the address itself as the gateway, and set the
	 * RTF_LLINFO flag, so that the corresponding host route would have
	 * the flag, and thus applications that assume traditional behavior
	 * would be happy.  Note that we assume the caller of the function
	 * (probably implicitly) set nd6_rtrequest() to ifa->ifa_rtrequest,
	 * which changes the outgoing interface to the loopback interface.
	 * ifa_addr for INET6 is set once during init; no need to hold lock.
	 */
	lck_mtx_lock(rnh_lock);
	e = rtrequest_locked(cmd, ifa->ifa_addr, ifa->ifa_addr,
	    (struct sockaddr *)&all1_sa, RTF_UP|RTF_HOST|RTF_LLINFO, &nrt);
	if (e != 0) {
		log(LOG_ERR, "in6_ifloop_request: "
		    "%s operation failed for %s (errno=%d)\n",
		    cmd == RTM_ADD ? "ADD" : "DELETE",
		    ip6_sprintf(&((struct in6_ifaddr *)ifa)->ia_addr.sin6_addr),
		    e);
	}

	if (nrt != NULL)
		RT_LOCK(nrt);
	/*
	 * Make sure rt_ifa be equal to IFA, the second argument of the
	 * function.
	 * We need this because when we refer to rt_ifa->ia6_flags in
	 * ip6_input, we assume that the rt_ifa points to the address instead
	 * of the loopback address.
	 */
	if (cmd == RTM_ADD && nrt && ifa != nrt->rt_ifa) {
		rtsetifa(nrt, ifa);
	}

	/*
	 * Report the addition/removal of the address to the routing socket.
	 * XXX: since we called rtinit for a p2p interface with a destination,
	 *   we end up reporting twice in such a case.  Should we rather
	 *   omit the second report?
	 */
	if (nrt != NULL) {
		rt_newaddrmsg(cmd, ifa, e, nrt);
		if (cmd == RTM_DELETE) {
			RT_UNLOCK(nrt);
			rtfree_locked(nrt);
		} else {
			/* the cmd must be RTM_ADD here */
			RT_REMREF_LOCKED(nrt);
			RT_UNLOCK(nrt);
		}
	}
	lck_mtx_unlock(rnh_lock);
}

/*
 * Add ownaddr as loopback rtentry.  We previously add the route only if
 * necessary (ex. on a p2p link).  However, since we now manage addresses
 * separately from prefixes, we should always add the route.  We can't
 * rely on the cloning mechanism from the corresponding interface route
 * any more.
 */
static void
in6_ifaddloop(struct ifaddr *ifa)
{
	struct rtentry *rt;

	/*
	 * If there is no loopback entry, allocate one.  ifa_addr for
	 * INET6 is set once during init; no need to hold lock.
	 */
	rt = rtalloc1(ifa->ifa_addr, 0, 0);
	if (rt != NULL)
		RT_LOCK(rt);
	if (rt == NULL || (rt->rt_flags & RTF_HOST) == 0 ||
	    (rt->rt_ifp->if_flags & IFF_LOOPBACK) == 0) {
		if (rt != NULL) {
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
		}
		in6_ifloop_request(RTM_ADD, ifa);
	} else if (rt != NULL) {
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
	}
}

/*
 * Remove loopback rtentry of ownaddr generated by in6_ifaddloop(),
 * if it exists.
 */
static void
in6_ifremloop(struct ifaddr *ifa)
{
	struct in6_ifaddr *ia;
	struct rtentry *rt;
	int ia_count = 0;

	/*
	 * Some of BSD variants do not remove cloned routes
	 * from an interface direct route, when removing the direct route
	 * (see comments in net/net_osdep.h).  Even for variants that do remove
	 * cloned routes, they could fail to remove the cloned routes when
	 * we handle multple addresses that share a common prefix.
	 * So, we should remove the route corresponding to the deleted address
	 * regardless of the result of in6_is_ifloop_auto().
	 */

	/*
	 * Delete the entry only if exact one ifa exists.  More than one ifa
	 * can exist if we assign a same single address to multiple
	 * (probably p2p) interfaces.
	 * XXX: we should avoid such a configuration in IPv6...
	 */
	lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
	for (ia = in6_ifaddrs; ia; ia = ia->ia_next) {
		IFA_LOCK(&ia->ia_ifa);
		if (IN6_ARE_ADDR_EQUAL(IFA_IN6(ifa), &ia->ia_addr.sin6_addr)) {
			ia_count++;
			if (ia_count > 1) {
				IFA_UNLOCK(&ia->ia_ifa);
				break;
			}
		}
		IFA_UNLOCK(&ia->ia_ifa);
	}
	lck_rw_done(&in6_ifaddr_rwlock);

	if (ia_count == 1) {
		/*
		 * Before deleting, check if a corresponding loopbacked host
		 * route surely exists.  With this check, we can avoid to
		 * delete an interface direct route whose destination is same
		 * as the address being removed.  This can happen when removing
		 * a subnet-router anycast address on an interface attahced
		 * to a shared medium.  ifa_addr for INET6 is set once during
		 * init; no need to hold lock.
		 */
		rt = rtalloc1(ifa->ifa_addr, 0, 0);
		if (rt != NULL) {
			RT_LOCK(rt);
			if ((rt->rt_flags & RTF_HOST) != 0 &&
			    (rt->rt_ifp->if_flags & IFF_LOOPBACK) != 0) {
				RT_REMREF_LOCKED(rt);
				RT_UNLOCK(rt);
				in6_ifloop_request(RTM_DELETE, ifa);
			} else {
				RT_UNLOCK(rt);
			}
		}
	}
}


int
in6_mask2len(struct in6_addr *mask, u_char *lim0)
{
	int x = 0, y;
	u_char *lim = lim0, *p;

	/* ignore the scope_id part */
	if (lim0 == NULL || lim0 - (u_char *)mask > sizeof (*mask))
		lim = (u_char *)mask + sizeof (*mask);
	for (p = (u_char *)mask; p < lim; x++, p++) {
		if (*p != 0xff)
			break;
	}
	y = 0;
	if (p < lim) {
		for (y = 0; y < 8; y++) {
			if ((*p & (0x80 >> y)) == 0)
				break;
		}
	}

	/*
	 * when the limit pointer is given, do a stricter check on the
	 * remaining bits.
	 */
	if (p < lim) {
		if (y != 0 && (*p & (0x00ff >> y)) != 0)
			return (-1);
		for (p = p + 1; p < lim; p++)
			if (*p != 0)
				return (-1);
	}

	return (x * 8 + y);
}

void
in6_len2mask(struct in6_addr *mask, int len)
{
	int i;

	bzero(mask, sizeof (*mask));
	for (i = 0; i < len / 8; i++)
		mask->s6_addr8[i] = 0xff;
	if (len % 8)
		mask->s6_addr8[i] = (0xff00 >> (len % 8)) & 0xff;
}

void
in6_aliasreq_64_to_32(struct in6_aliasreq_64 *src, struct in6_aliasreq_32 *dst)
{
	bzero(dst, sizeof (*dst));
	bcopy(src->ifra_name, dst->ifra_name, sizeof (dst->ifra_name));
	dst->ifra_addr = src->ifra_addr;
	dst->ifra_dstaddr = src->ifra_dstaddr;
	dst->ifra_prefixmask = src->ifra_prefixmask;
	dst->ifra_flags = src->ifra_flags;
	dst->ifra_lifetime.ia6t_expire = src->ifra_lifetime.ia6t_expire;
	dst->ifra_lifetime.ia6t_preferred = src->ifra_lifetime.ia6t_preferred;
	dst->ifra_lifetime.ia6t_vltime = src->ifra_lifetime.ia6t_vltime;
	dst->ifra_lifetime.ia6t_pltime = src->ifra_lifetime.ia6t_pltime;
}

void
in6_aliasreq_32_to_64(struct in6_aliasreq_32 *src, struct in6_aliasreq_64 *dst)
{
	bzero(dst, sizeof (*dst));
	bcopy(src->ifra_name, dst->ifra_name, sizeof (dst->ifra_name));
	dst->ifra_addr = src->ifra_addr;
	dst->ifra_dstaddr = src->ifra_dstaddr;
	dst->ifra_prefixmask = src->ifra_prefixmask;
	dst->ifra_flags = src->ifra_flags;
	dst->ifra_lifetime.ia6t_expire = src->ifra_lifetime.ia6t_expire;
	dst->ifra_lifetime.ia6t_preferred = src->ifra_lifetime.ia6t_preferred;
	dst->ifra_lifetime.ia6t_vltime = src->ifra_lifetime.ia6t_vltime;
	dst->ifra_lifetime.ia6t_pltime = src->ifra_lifetime.ia6t_pltime;
}

#if defined(__LP64__)
void
in6_cgareq_32_to_64(struct in6_cgareq_32 *src,
    struct in6_cgareq_64 *dst)
{
	bzero(dst, sizeof (*dst));
	bcopy(src->cgar_name, dst->cgar_name, sizeof (dst->cgar_name));
	dst->cgar_flags = src->cgar_flags;
	bcopy(src->cgar_cgaprep.cga_modifier.octets,
	    dst->cgar_cgaprep.cga_modifier.octets,
	    sizeof (dst->cgar_cgaprep.cga_modifier.octets));
	dst->cgar_cgaprep.cga_security_level =
	    src->cgar_cgaprep.cga_security_level;
	dst->cgar_lifetime.ia6t_expire = src->cgar_lifetime.ia6t_expire;
	dst->cgar_lifetime.ia6t_preferred = src->cgar_lifetime.ia6t_preferred;
	dst->cgar_lifetime.ia6t_vltime = src->cgar_lifetime.ia6t_vltime;
	dst->cgar_lifetime.ia6t_pltime = src->cgar_lifetime.ia6t_pltime;
}
#endif

#if !defined(__LP64__)
void
in6_cgareq_64_to_32(struct in6_cgareq_64 *src,
    struct in6_cgareq_32 *dst)
{
	bzero(dst, sizeof (*dst));
	bcopy(src->cgar_name, dst->cgar_name, sizeof (dst->cgar_name));
	dst->cgar_flags = src->cgar_flags;
	bcopy(src->cgar_cgaprep.cga_modifier.octets,
	    dst->cgar_cgaprep.cga_modifier.octets,
	    sizeof (dst->cgar_cgaprep.cga_modifier.octets));
	dst->cgar_cgaprep.cga_security_level =
	    src->cgar_cgaprep.cga_security_level;
	dst->cgar_lifetime.ia6t_expire = src->cgar_lifetime.ia6t_expire;
	dst->cgar_lifetime.ia6t_preferred = src->cgar_lifetime.ia6t_preferred;
	dst->cgar_lifetime.ia6t_vltime = src->cgar_lifetime.ia6t_vltime;
	dst->cgar_lifetime.ia6t_pltime = src->cgar_lifetime.ia6t_pltime;
}
#endif

static struct in6_aliasreq *
in6_aliasreq_to_native(void *data, int data_is_64, struct in6_aliasreq *dst)
{
#if defined(__LP64__)
	if (data_is_64)
		bcopy(data, dst, sizeof (*dst));
	else
		in6_aliasreq_32_to_64((struct in6_aliasreq_32 *)data,
		    (struct in6_aliasreq_64 *)dst);
#else
	if (data_is_64)
		in6_aliasreq_64_to_32((struct in6_aliasreq_64 *)data,
		    (struct in6_aliasreq_32 *)dst);
	else
		bcopy(data, dst, sizeof (*dst));
#endif /* __LP64__ */
	return (dst);
}

static struct in6_cgareq *
in6_cgareq_to_native(void *data, int is64, struct in6_cgareq *dst)
{
#if defined(__LP64__)
	if (is64)
		bcopy(data, dst, sizeof (*dst));
	else
		in6_cgareq_32_to_64((struct in6_cgareq_32 *)data,
		    (struct in6_cgareq_64 *)dst);
#else
	if (is64)
		in6_cgareq_64_to_32((struct in6_cgareq_64 *)data,
		    (struct in6_cgareq_32 *)dst);
	else
		bcopy(data, dst, sizeof (*dst));
#endif /* __LP64__ */
	return (dst);
}

static __attribute__((noinline)) int
in6ctl_associd(struct socket *so, u_long cmd, caddr_t data)
{
	int error = 0;
	union {
		struct so_aidreq32 a32;
		struct so_aidreq64 a64;
	} u;

	VERIFY(so != NULL);

	switch (cmd) {
	case SIOCGASSOCIDS32: {		/* struct so_aidreq32 */
		bcopy(data, &u.a32, sizeof (u.a32));
		error = in6_getassocids(so, &u.a32.sar_cnt, u.a32.sar_aidp);
		if (error == 0)
			bcopy(&u.a32, data, sizeof (u.a32));
		break;
	}

	case SIOCGASSOCIDS64: {		/* struct so_aidreq64 */
		bcopy(data, &u.a64, sizeof (u.a64));
		error = in6_getassocids(so, &u.a64.sar_cnt, u.a64.sar_aidp);
		if (error == 0)
			bcopy(&u.a64, data, sizeof (u.a64));
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static __attribute__((noinline)) int
in6ctl_connid(struct socket *so, u_long cmd, caddr_t data)
{
	int error = 0;
	union {
		struct so_cidreq32 c32;
		struct so_cidreq64 c64;
	} u;

	VERIFY(so != NULL);

	switch (cmd) {
	case SIOCGCONNIDS32: {		/* struct so_cidreq32 */
		bcopy(data, &u.c32, sizeof (u.c32));
		error = in6_getconnids(so, u.c32.scr_aid, &u.c32.scr_cnt,
		    u.c32.scr_cidp);
		if (error == 0)
			bcopy(&u.c32, data, sizeof (u.c32));
		break;
	}

	case SIOCGCONNIDS64: {		/* struct so_cidreq64 */
		bcopy(data, &u.c64, sizeof (u.c64));
		error = in6_getconnids(so, u.c64.scr_aid, &u.c64.scr_cnt,
		    u.c64.scr_cidp);
		if (error == 0)
			bcopy(&u.c64, data, sizeof (u.c64));
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static __attribute__((noinline)) int
in6ctl_conninfo(struct socket *so, u_long cmd, caddr_t data)
{
	int error = 0;
	union {
		struct so_cinforeq32 ci32;
		struct so_cinforeq64 ci64;
	} u;

	VERIFY(so != NULL);

	switch (cmd) {
	case SIOCGCONNINFO32: {		/* struct so_cinforeq32 */
		bcopy(data, &u.ci32, sizeof (u.ci32));
		error = in6_getconninfo(so, u.ci32.scir_cid, &u.ci32.scir_flags,
		    &u.ci32.scir_ifindex, &u.ci32.scir_error, u.ci32.scir_src,
		    &u.ci32.scir_src_len, u.ci32.scir_dst, &u.ci32.scir_dst_len,
		    &u.ci32.scir_aux_type, u.ci32.scir_aux_data,
		    &u.ci32.scir_aux_len);
		if (error == 0)
			bcopy(&u.ci32, data, sizeof (u.ci32));
		break;
	}

	case SIOCGCONNINFO64: {		/* struct so_cinforeq64 */
		bcopy(data, &u.ci64, sizeof (u.ci64));
		error = in6_getconninfo(so, u.ci64.scir_cid, &u.ci64.scir_flags,
		    &u.ci64.scir_ifindex, &u.ci64.scir_error, u.ci64.scir_src,
		    &u.ci64.scir_src_len, u.ci64.scir_dst, &u.ci64.scir_dst_len,
		    &u.ci64.scir_aux_type, u.ci64.scir_aux_data,
		    &u.ci64.scir_aux_len);
		if (error == 0)
			bcopy(&u.ci64, data, sizeof (u.ci64));
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static __attribute__((noinline)) int
in6ctl_llstart(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct in6_aliasreq sifra, *ifra = NULL;
	boolean_t is64;
	int error = 0;

	VERIFY(ifp != NULL);

	switch (cmd) {
	case SIOCLL_START_32:		/* struct in6_aliasreq_32 */
	case SIOCLL_START_64:		/* struct in6_aliasreq_64 */
		is64 = (cmd == SIOCLL_START_64);
		/*
		 * Convert user ifra to the kernel form, when appropriate.
		 * This allows the conversion between different data models
		 * to be centralized, so that it can be passed around to other
		 * routines that are expecting the kernel form.
		 */
		ifra = in6_aliasreq_to_native(data, is64, &sifra);

		/*
		 * NOTE: All the interface specific DLIL attachements should
		 * be done here.  They are currently done in in6_ifattach_aux()
		 * for the interfaces that need it.
		 */
		if (ifra->ifra_addr.sin6_family == AF_INET6 &&
		    /* Only check ifra_dstaddr if valid */
		    (ifra->ifra_dstaddr.sin6_len == 0 ||
		    ifra->ifra_dstaddr.sin6_family == AF_INET6)) {
		    /* some interfaces may provide LinkLocal addresses */
			error = in6_ifattach_aliasreq(ifp, NULL, ifra);
		} else {
			error = in6_ifattach_aliasreq(ifp, NULL, NULL);
		}
		if (error == 0)
			in6_if_up_dad_start(ifp);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

static __attribute__((noinline)) int
in6ctl_llstop(struct ifnet *ifp)
{
	struct in6_ifaddr *ia;
	struct nd_prefix pr0, *pr;

	VERIFY(ifp != NULL);

	/* Remove link local addresses from interface */
	lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
	ia = in6_ifaddrs;
	while (ia != NULL) {
		if (ia->ia_ifa.ifa_ifp != ifp) {
			ia = ia->ia_next;
			continue;
		}
		IFA_LOCK(&ia->ia_ifa);
		if (IN6_IS_ADDR_LINKLOCAL(&ia->ia_addr.sin6_addr)) {
			IFA_ADDREF_LOCKED(&ia->ia_ifa);	/* for us */
			IFA_UNLOCK(&ia->ia_ifa);
			lck_rw_done(&in6_ifaddr_rwlock);
			in6_purgeaddr(&ia->ia_ifa);
			IFA_REMREF(&ia->ia_ifa);	/* for us */
			lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
			/*
			 * Purging the address caused in6_ifaddr_rwlock
			 * to be dropped and reacquired;
			 * therefore search again from the beginning
			 * of in6_ifaddrs list.
			 */
			ia = in6_ifaddrs;
			continue;
		}
		IFA_UNLOCK(&ia->ia_ifa);
		ia = ia->ia_next;
	}
	lck_rw_done(&in6_ifaddr_rwlock);

	/* Delete the link local prefix */
	bzero(&pr0, sizeof(pr0));
	pr0.ndpr_plen = 64;
	pr0.ndpr_ifp = ifp;
	pr0.ndpr_prefix.sin6_addr.s6_addr16[0] = IPV6_ADDR_INT16_ULL;
	in6_setscope(&pr0.ndpr_prefix.sin6_addr, ifp, NULL);
	pr = nd6_prefix_lookup(&pr0, ND6_PREFIX_EXPIRY_UNSPEC);
	if (pr) {
		lck_mtx_lock(nd6_mutex);
		NDPR_LOCK(pr);
		prelist_remove(pr);
		NDPR_UNLOCK(pr);
		NDPR_REMREF(pr); /* Drop the reference from lookup */
		lck_mtx_unlock(nd6_mutex);
	}

	return (0);
}

/*
 * This routine configures secure link local address
 */
static __attribute__((noinline)) int
in6ctl_cgastart(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct in6_cgareq llcgasr;
	int is64, error = 0;

	VERIFY(ifp != NULL);

	switch (cmd) {
	case SIOCLL_CGASTART_32:	/* struct in6_cgareq_32 */
	case SIOCLL_CGASTART_64:	/* struct in6_cgareq_64 */
		is64 = (cmd == SIOCLL_CGASTART_64);
		/*
		 * Convert user cgareq to the kernel form, when appropriate.
		 * This allows the conversion between different data models
		 * to be centralized, so that it can be passed around to other
		 * routines that are expecting the kernel form.
		 */
		in6_cgareq_to_native(data, is64, &llcgasr);

		/*
		 * NOTE: All the interface specific DLIL attachements
		 * should be done here.  They are currently done in
		 * in6_ifattach_cgareq() for the interfaces that
		 * need it.
		 */
		error = in6_ifattach_llcgareq(ifp, &llcgasr);
		if (error == 0)
			in6_if_up_dad_start(ifp);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

/*
 * Caller passes in the ioctl data pointer directly via "ifr", with the
 * expectation that this routine always uses bcopy() or other byte-aligned
 * memory accesses.
 */
static __attribute__((noinline)) int
in6ctl_gifaddr(struct ifnet *ifp, struct in6_ifaddr *ia, u_long cmd,
    struct in6_ifreq *ifr)
{
	struct sockaddr_in6 addr;
	int error = 0;

	VERIFY(ifp != NULL);

	if (ia == NULL)
		return (EADDRNOTAVAIL);

	switch (cmd) {
	case SIOCGIFADDR_IN6:		/* struct in6_ifreq */
		IFA_LOCK(&ia->ia_ifa);
		bcopy(&ia->ia_addr, &addr, sizeof (addr));
		IFA_UNLOCK(&ia->ia_ifa);
		if ((error = sa6_recoverscope(&addr, TRUE)) != 0)
			break;
		bcopy(&addr, &ifr->ifr_addr, sizeof (addr));
		break;

	case SIOCGIFDSTADDR_IN6:	/* struct in6_ifreq */
		if (!(ifp->if_flags & IFF_POINTOPOINT)) {
			error = EINVAL;
			break;
		}
		/*
		 * XXX: should we check if ifa_dstaddr is NULL and return
		 * an error?
		 */
		IFA_LOCK(&ia->ia_ifa);
		bcopy(&ia->ia_dstaddr, &addr, sizeof (addr));
		IFA_UNLOCK(&ia->ia_ifa);
		if ((error = sa6_recoverscope(&addr, TRUE)) != 0)
			break;
		bcopy(&addr, &ifr->ifr_dstaddr, sizeof (addr));
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

/*
 * Caller passes in the ioctl data pointer directly via "ifr", with the
 * expectation that this routine always uses bcopy() or other byte-aligned
 * memory accesses.
 */
static __attribute__((noinline)) int
in6ctl_gifstat(struct ifnet *ifp, u_long cmd, struct in6_ifreq *ifr)
{
	int error = 0, index;

	VERIFY(ifp != NULL);
	index = ifp->if_index;

	switch (cmd) {
	case SIOCGIFSTAT_IN6:		/* struct in6_ifreq */
		/* N.B.: if_inet6data is never freed once set. */
		if (IN6_IFEXTRA(ifp) == NULL) {
			/* return (EAFNOSUPPORT)? */
			bzero(&ifr->ifr_ifru.ifru_stat,
			    sizeof (ifr->ifr_ifru.ifru_stat));
		} else {
			bcopy(&IN6_IFEXTRA(ifp)->in6_ifstat,
			    &ifr->ifr_ifru.ifru_stat,
			    sizeof (ifr->ifr_ifru.ifru_stat));
		}
		break;

	case SIOCGIFSTAT_ICMP6:		/* struct in6_ifreq */
		/* N.B.: if_inet6data is never freed once set. */
		if (IN6_IFEXTRA(ifp) == NULL) {
			/* return (EAFNOSUPPORT)? */
			bzero(&ifr->ifr_ifru.ifru_stat,
			    sizeof (ifr->ifr_ifru.ifru_icmp6stat));
		} else {
			bcopy(&IN6_IFEXTRA(ifp)->icmp6_ifstat,
			    &ifr->ifr_ifru.ifru_icmp6stat,
			    sizeof (ifr->ifr_ifru.ifru_icmp6stat));
		}
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

/*
 * Caller passes in the ioctl data pointer directly via "ifr", with the
 * expectation that this routine always uses bcopy() or other byte-aligned
 * memory accesses.
 */
static __attribute__((noinline)) int
in6ctl_alifetime(struct in6_ifaddr *ia, u_long cmd, struct in6_ifreq *ifr,
    boolean_t p64)
{
	uint64_t timenow = net_uptime();
	struct in6_addrlifetime ia6_lt;
	struct timeval caltime;
	int error = 0;

	if (ia == NULL)
		return (EADDRNOTAVAIL);

	switch (cmd) {
	case SIOCGIFALIFETIME_IN6:	/* struct in6_ifreq */
		IFA_LOCK(&ia->ia_ifa);
		/* retrieve time as calendar time (last arg is 1) */
		in6ifa_getlifetime(ia, &ia6_lt, 1);
		if (p64) {
			struct in6_addrlifetime_64 lt;

			bzero(&lt, sizeof (lt));
			lt.ia6t_expire = ia6_lt.ia6t_expire;
			lt.ia6t_preferred = ia6_lt.ia6t_preferred;
			lt.ia6t_vltime = ia6_lt.ia6t_vltime;
			lt.ia6t_pltime = ia6_lt.ia6t_pltime;
			bcopy(&lt, &ifr->ifr_ifru.ifru_lifetime, sizeof (lt));
		} else {
			struct in6_addrlifetime_32 lt;

			bzero(&lt, sizeof (lt));
			lt.ia6t_expire = (uint32_t)ia6_lt.ia6t_expire;
			lt.ia6t_preferred = (uint32_t)ia6_lt.ia6t_preferred;
			lt.ia6t_vltime = (uint32_t)ia6_lt.ia6t_vltime;
			lt.ia6t_pltime = (uint32_t)ia6_lt.ia6t_pltime;
			bcopy(&lt, &ifr->ifr_ifru.ifru_lifetime, sizeof (lt));
		}
		IFA_UNLOCK(&ia->ia_ifa);
		break;

	case SIOCSIFALIFETIME_IN6:	/* struct in6_ifreq */
		getmicrotime(&caltime);

		/* sanity for overflow - beware unsigned */
		if (p64) {
			struct in6_addrlifetime_64 lt;

			bcopy(&ifr->ifr_ifru.ifru_lifetime, &lt, sizeof (lt));
			if (lt.ia6t_vltime != ND6_INFINITE_LIFETIME &&
			    lt.ia6t_vltime + caltime.tv_sec < caltime.tv_sec) {
				error = EINVAL;
				break;
			}
			if (lt.ia6t_pltime != ND6_INFINITE_LIFETIME &&
			    lt.ia6t_pltime + caltime.tv_sec < caltime.tv_sec) {
				error = EINVAL;
				break;
			}
		} else {
			struct in6_addrlifetime_32 lt;

			bcopy(&ifr->ifr_ifru.ifru_lifetime, &lt, sizeof (lt));
			if (lt.ia6t_vltime != ND6_INFINITE_LIFETIME &&
			    lt.ia6t_vltime + caltime.tv_sec < caltime.tv_sec) {
				error = EINVAL;
				break;
			}
			if (lt.ia6t_pltime != ND6_INFINITE_LIFETIME &&
			    lt.ia6t_pltime + caltime.tv_sec < caltime.tv_sec) {
				error = EINVAL;
				break;
			}
		}

		IFA_LOCK(&ia->ia_ifa);
		if (p64) {
			struct in6_addrlifetime_64 lt;

			bcopy(&ifr->ifr_ifru.ifru_lifetime, &lt, sizeof (lt));
			ia6_lt.ia6t_expire = lt.ia6t_expire;
			ia6_lt.ia6t_preferred = lt.ia6t_preferred;
			ia6_lt.ia6t_vltime = lt.ia6t_vltime;
			ia6_lt.ia6t_pltime = lt.ia6t_pltime;
		} else {
			struct in6_addrlifetime_32 lt;

			bcopy(&ifr->ifr_ifru.ifru_lifetime, &lt, sizeof (lt));
			ia6_lt.ia6t_expire = (uint32_t)lt.ia6t_expire;
			ia6_lt.ia6t_preferred = (uint32_t)lt.ia6t_preferred;
			ia6_lt.ia6t_vltime = lt.ia6t_vltime;
			ia6_lt.ia6t_pltime = lt.ia6t_pltime;
		}
		/* for sanity */
		if (ia6_lt.ia6t_vltime != ND6_INFINITE_LIFETIME)
			ia6_lt.ia6t_expire = timenow + ia6_lt.ia6t_vltime;
		else
			ia6_lt.ia6t_expire = 0;

		if (ia6_lt.ia6t_pltime != ND6_INFINITE_LIFETIME)
			ia6_lt.ia6t_preferred = timenow + ia6_lt.ia6t_pltime;
		else
			ia6_lt.ia6t_preferred = 0;

		in6ifa_setlifetime(ia, &ia6_lt);
		IFA_UNLOCK(&ia->ia_ifa);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (error);
}

#define	ifa2ia6(ifa)	((struct in6_ifaddr *)(void *)(ifa))

/*
 * Generic INET6 control operations (ioctl's).
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
in6_control(struct socket *so, u_long cmd, caddr_t data, struct ifnet *ifp,
    struct proc *p)
{
	struct in6_ifreq *ifr = (struct in6_ifreq *)(void *)data;
	struct in6_aliasreq sifra, *ifra = NULL;
	struct in6_ifaddr *ia = NULL;
	struct sockaddr_in6 sin6, *sa6 = NULL;
	boolean_t privileged = (proc_suser(p) == 0);
	boolean_t p64 = proc_is64bit(p);
	boolean_t so_unlocked = FALSE;
	int intval, error = 0;

	/* In case it's NULL, make sure it came from the kernel */
	VERIFY(so != NULL || p == kernproc);

	/*
	 * ioctls which don't require ifp, may require socket.
	 */
	switch (cmd) {
	case SIOCAADDRCTL_POLICY:	/* struct in6_addrpolicy */
	case SIOCDADDRCTL_POLICY:	/* struct in6_addrpolicy */
		if (!privileged)
			return (EPERM);
		return (in6_src_ioctl(cmd, data));
		/* NOTREACHED */

	case SIOCDRADD_IN6_32:		/* struct in6_defrouter_32 */
	case SIOCDRADD_IN6_64:		/* struct in6_defrouter_64 */
	case SIOCDRDEL_IN6_32:		/* struct in6_defrouter_32 */
	case SIOCDRDEL_IN6_64:		/* struct in6_defrouter_64 */
		if (!privileged)
			return (EPERM);
		return (defrtrlist_ioctl(cmd, data));
		/* NOTREACHED */

	case SIOCGASSOCIDS32:		/* struct so_aidreq32 */
	case SIOCGASSOCIDS64:		/* struct so_aidreq64 */
		return (in6ctl_associd(so, cmd, data));
		/* NOTREACHED */

	case SIOCGCONNIDS32:		/* struct so_cidreq32 */
	case SIOCGCONNIDS64:		/* struct so_cidreq64 */
		return (in6ctl_connid(so, cmd, data));
		/* NOTREACHED */

	case SIOCGCONNINFO32:		/* struct so_cinforeq32 */
	case SIOCGCONNINFO64:		/* struct so_cinforeq64 */
		return (in6ctl_conninfo(so, cmd, data));
		/* NOTREACHED */
	}

	/*
	 * The rest of ioctls require ifp; reject if we don't have one;
	 * return ENXIO to be consistent with ifioctl().
	 */
	if (ifp == NULL)
		return (ENXIO);

	/*
	 * Unlock the socket since ifnet_ioctl() may be invoked by
	 * one of the ioctl handlers below.  Socket will be re-locked
	 * prior to returning.
	 */
	if (so != NULL) {
		socket_unlock(so, 0);
		so_unlocked = TRUE;
	}

	/*
	 * ioctls which require ifp but not interface address.
	 */
	switch (cmd) {
	case SIOCAUTOCONF_START:	/* struct in6_ifreq */
		if (!privileged) {
			error = EPERM;
			goto done;
		}
		error = in6_autoconf(ifp, TRUE);
		goto done;

	case SIOCAUTOCONF_STOP:		/* struct in6_ifreq */
		if (!privileged) {
			error = EPERM;
			goto done;
		}
		error = in6_autoconf(ifp, FALSE);
		goto done;

	case SIOCLL_START_32:		/* struct in6_aliasreq_32 */
	case SIOCLL_START_64:		/* struct in6_aliasreq_64 */
		if (!privileged) {
			error = EPERM;
			goto done;
		}
		error = in6ctl_llstart(ifp, cmd, data);
		goto done;

	case SIOCLL_STOP:		/* struct in6_ifreq */
		if (!privileged) {
			error = EPERM;
			goto done;
		}
		error = in6ctl_llstop(ifp);
		goto done;

	case SIOCSETROUTERMODE_IN6:	/* struct in6_ifreq */
		if (!privileged) {
			error = EPERM;
			goto done;
		}
		bcopy(&((struct in6_ifreq *)(void *)data)->ifr_intval,
		    &intval, sizeof (intval));

		error = in6_setrouter(ifp, intval);
		goto done;

	case SIOCPROTOATTACH_IN6_32:	/* struct in6_aliasreq_32 */
	case SIOCPROTOATTACH_IN6_64:	/* struct in6_aliasreq_64 */
		if (!privileged) {
			error = EPERM;
			goto done;
		}
		error = in6_domifattach(ifp);
		goto done;

	case SIOCPROTODETACH_IN6:	/* struct in6_ifreq */
		if (!privileged) {
			error = EPERM;
			goto done;
		}
		/* Cleanup interface routes and addresses */
		in6_purgeif(ifp);

		if ((error = proto_unplumb(PF_INET6, ifp)))
			log(LOG_ERR, "SIOCPROTODETACH_IN6: %s error=%d\n",
			    if_name(ifp), error);
		goto done;

	case SIOCSNDFLUSH_IN6:		/* struct in6_ifreq */
	case SIOCSPFXFLUSH_IN6:		/* struct in6_ifreq */
	case SIOCSRTRFLUSH_IN6:		/* struct in6_ifreq */
	case SIOCSDEFIFACE_IN6_32:	/* struct in6_ndifreq_32 */
	case SIOCSDEFIFACE_IN6_64:	/* struct in6_ndifreq_64 */
	case SIOCSIFINFO_FLAGS:		/* struct in6_ndireq */
	case SIOCGIFCGAPREP_IN6:	/* struct in6_ifreq */
	case SIOCSIFCGAPREP_IN6:	/* struct in6_ifreq */
		if (!privileged) {
			error = EPERM;
			goto done;
		}
		/* FALLTHRU */
	case OSIOCGIFINFO_IN6:		/* struct in6_ondireq */
	case SIOCGIFINFO_IN6:		/* struct in6_ondireq */
	case SIOCGDRLST_IN6_32:		/* struct in6_drlist_32 */
	case SIOCGDRLST_IN6_64:		/* struct in6_drlist_64 */
	case SIOCGPRLST_IN6_32:		/* struct in6_prlist_32 */
	case SIOCGPRLST_IN6_64:		/* struct in6_prlist_64 */
	case SIOCGNBRINFO_IN6_32:	/* struct in6_nbrinfo_32 */
	case SIOCGNBRINFO_IN6_64:	/* struct in6_nbrinfo_64 */
	case SIOCGDEFIFACE_IN6_32:	/* struct in6_ndifreq_32 */
	case SIOCGDEFIFACE_IN6_64:	/* struct in6_ndifreq_64 */
		error = nd6_ioctl(cmd, data, ifp);
		goto done;

	case SIOCSIFPREFIX_IN6:		/* struct in6_prefixreq (deprecated) */
	case SIOCDIFPREFIX_IN6:		/* struct in6_prefixreq (deprecated) */
	case SIOCAIFPREFIX_IN6:		/* struct in6_rrenumreq (deprecated) */
	case SIOCCIFPREFIX_IN6:		/* struct in6_rrenumreq (deprecated) */
	case SIOCSGIFPREFIX_IN6:	/* struct in6_rrenumreq (deprecated) */
	case SIOCGIFPREFIX_IN6:		/* struct in6_prefixreq (deprecated) */
		log(LOG_NOTICE,
		    "prefix ioctls are now invalidated. "
		    "please use ifconfig.\n");
		error = EOPNOTSUPP;
		goto done;

	case SIOCSSCOPE6:		/* struct in6_ifreq (deprecated) */
	case SIOCGSCOPE6:		/* struct in6_ifreq (deprecated) */
	case SIOCGSCOPE6DEF:		/* struct in6_ifreq (deprecated) */
		error = EOPNOTSUPP;
		goto done;
	
	case SIOCLL_CGASTART_32:	/* struct in6_cgareq_32 */
	case SIOCLL_CGASTART_64:	/* struct in6_cgareq_64 */
		if (!privileged)
			error = EPERM;
		else
			error = in6ctl_cgastart(ifp, cmd, data);
		goto done;

	case SIOCGIFSTAT_IN6:		/* struct in6_ifreq */
	case SIOCGIFSTAT_ICMP6:		/* struct in6_ifreq */
		error = in6ctl_gifstat(ifp, cmd, ifr);
		goto done;
	}

	/*
	 * ioctls which require interface address; obtain sockaddr_in6.
	 */
	switch (cmd) {
	case SIOCSIFADDR_IN6:		/* struct in6_ifreq (deprecated) */
	case SIOCSIFDSTADDR_IN6:	/* struct in6_ifreq (deprecated) */
	case SIOCSIFNETMASK_IN6:	/* struct in6_ifreq (deprecated) */
		/*
		 * Since IPv6 allows a node to assign multiple addresses
		 * on a single interface, SIOCSIFxxx ioctls are deprecated.
		 */
		/* we decided to obsolete this command (20000704) */
		error = EOPNOTSUPP;
		goto done;

	case SIOCAIFADDR_IN6_32:	/* struct in6_aliasreq_32 */
	case SIOCAIFADDR_IN6_64:	/* struct in6_aliasreq_64 */
		if (!privileged) {
			error = EPERM;
			goto done;
		} 
		/*
		 * Convert user ifra to the kernel form, when appropriate.
		 * This allows the conversion between different data models
		 * to be centralized, so that it can be passed around to other
		 * routines that are expecting the kernel form.
		 */
		ifra = in6_aliasreq_to_native(data,
		    (cmd == SIOCAIFADDR_IN6_64), &sifra);
		bcopy(&ifra->ifra_addr, &sin6, sizeof (sin6));
		sa6 = &sin6;
		break;

	case SIOCDIFADDR_IN6:		/* struct in6_ifreq */
	case SIOCSIFALIFETIME_IN6:	/* struct in6_ifreq */
		if (!privileged) {
			error = EPERM;
			goto done;
		}
		/* FALLTHRU */
	case SIOCGIFADDR_IN6:		/* struct in6_ifreq */
	case SIOCGIFDSTADDR_IN6:	/* struct in6_ifreq */
	case SIOCGIFNETMASK_IN6:	/* struct in6_ifreq */
	case SIOCGIFAFLAG_IN6:		/* struct in6_ifreq */
	case SIOCGIFALIFETIME_IN6:	/* struct in6_ifreq */
		bcopy(&ifr->ifr_addr, &sin6, sizeof (sin6));
		sa6 = &sin6;
		break;
	}

	/*
	 * Find address for this interface, if it exists.
	 *
	 * In netinet code, we have checked ifra_addr in SIOCSIF*ADDR operation
	 * only, and used the first interface address as the target of other
	 * operations (without checking ifra_addr).  This was because netinet
	 * code/API assumed at most 1 interface address per interface.
	 * Since IPv6 allows a node to assign multiple addresses
	 * on a single interface, we almost always look and check the
	 * presence of ifra_addr, and reject invalid ones here.
	 * It also decreases duplicated code among SIOC*_IN6 operations.
	 */
	VERIFY(ia == NULL);
	if (sa6 != NULL && sa6->sin6_family == AF_INET6) {
		if (IN6_IS_ADDR_LINKLOCAL(&sa6->sin6_addr)) {
			if (sa6->sin6_addr.s6_addr16[1] == 0) {
				/* link ID is not embedded by the user */
				sa6->sin6_addr.s6_addr16[1] =
				    htons(ifp->if_index);
			} else if (sa6->sin6_addr.s6_addr16[1] !=
			    htons(ifp->if_index)) {
				error = EINVAL; /* link ID contradicts */
				goto done;
			}
			if (sa6->sin6_scope_id) {
				if (sa6->sin6_scope_id !=
				    (u_int32_t)ifp->if_index) {
					error = EINVAL;
					goto done;
				}
				sa6->sin6_scope_id = 0; /* XXX: good way? */
			}
		}
		/*
		 * Any failures from this point on must take into account
		 * a non-NULL "ia" with an outstanding reference count, and
		 * therefore requires IFA_REMREF.  Jump to "done" label
		 * instead of calling return if "ia" is valid.
		 */
		ia = in6ifa_ifpwithaddr(ifp, &sa6->sin6_addr);
	}

	/*
	 * SIOCDIFADDR_IN6/SIOCAIFADDR_IN6 specific tests.
	 */
	switch (cmd) {
	case SIOCDIFADDR_IN6:		/* struct in6_ifreq */
		if (ia == NULL) {
			error = EADDRNOTAVAIL;
			goto done;
		}
		/* FALLTHROUGH */
	case SIOCAIFADDR_IN6_32:	/* struct in6_aliasreq_32 */
	case SIOCAIFADDR_IN6_64:	/* struct in6_aliasreq_64 */
		VERIFY(sa6 != NULL);
		/*
		 * We always require users to specify a valid IPv6 address for
		 * the corresponding operation.  Use "sa6" instead of "ifra"
		 * since SIOCDIFADDR_IN6 falls thru above.
		 */
		if (sa6->sin6_family != AF_INET6 ||
		    sa6->sin6_len != sizeof (struct sockaddr_in6)) {
			error = EAFNOSUPPORT;
			goto done;
		}
		break;
	}

	/*
	 * And finally process address-related ioctls.
	 */
	switch (cmd) {
	case SIOCGIFADDR_IN6:		/* struct in6_ifreq */
		/* This interface is basically deprecated. use SIOCGIFCONF. */
		/* FALLTHRU */
	case SIOCGIFDSTADDR_IN6:	/* struct in6_ifreq */
		error = in6ctl_gifaddr(ifp, ia, cmd, ifr);
		break;

	case SIOCGIFNETMASK_IN6:	/* struct in6_ifreq */
		if (ia != NULL) {
			IFA_LOCK(&ia->ia_ifa);
			bcopy(&ia->ia_prefixmask, &ifr->ifr_addr,
			    sizeof (struct sockaddr_in6));
			IFA_UNLOCK(&ia->ia_ifa);
		} else {
			error = EADDRNOTAVAIL;
		}
		break;

	case SIOCGIFAFLAG_IN6:		/* struct in6_ifreq */
		if (ia != NULL) {
			IFA_LOCK(&ia->ia_ifa);
			bcopy(&ia->ia6_flags, &ifr->ifr_ifru.ifru_flags6,
			    sizeof (ifr->ifr_ifru.ifru_flags6));
			IFA_UNLOCK(&ia->ia_ifa);
		} else {
			error = EADDRNOTAVAIL;
		}
		break;

	case SIOCGIFALIFETIME_IN6:	/* struct in6_ifreq */
	case SIOCSIFALIFETIME_IN6:	/* struct in6_ifreq */
		error = in6ctl_alifetime(ia, cmd, ifr, p64);
		break;

	case SIOCAIFADDR_IN6_32:	/* struct in6_aliasreq_32 */
	case SIOCAIFADDR_IN6_64:	/* struct in6_aliasreq_64 */
		error = in6ctl_aifaddr(ifp, ifra);
		break;

	case SIOCDIFADDR_IN6:
		in6ctl_difaddr(ifp, ia);
		break;

	default:
		error = ifnet_ioctl(ifp, PF_INET6, cmd, data);
		break;
	}

done:
	if (ia != NULL)
		IFA_REMREF(&ia->ia_ifa);
	if (so_unlocked)
		socket_lock(so, 0);

	return (error);
}

static __attribute__((noinline)) int
in6ctl_aifaddr(struct ifnet *ifp, struct in6_aliasreq *ifra)
{
	int i, error, addtmp, plen;
	struct nd_prefix pr0, *pr;
	struct in6_ifaddr *ia;

	VERIFY(ifp != NULL && ifra != NULL);
	ia = NULL;

	/* Attempt to attach the protocol, in case it isn't attached */
	error = in6_domifattach(ifp);
	if (error == 0) {
		/* PF_INET6 wasn't previously attached */
		error = in6_ifattach_aliasreq(ifp, NULL, NULL);
		if (error != 0)
			goto done;

		in6_if_up_dad_start(ifp);
	} else if (error != EEXIST) {
		goto done;
	}

	/*
	 * First, make or update the interface address structure, and link it
	 * to the list.
	 */
	error = in6_update_ifa(ifp, ifra, 0, &ia);
	if (error != 0)
		goto done;
	VERIFY(ia != NULL);

	/* Now, make the prefix on-link on the interface. */
	plen = in6_mask2len(&ifra->ifra_prefixmask.sin6_addr, NULL);
	if (plen == 128)
		goto done;

	/*
	 * NOTE: We'd rather create the prefix before the address, but we need
	 * at least one address to install the corresponding interface route,
	 * so we configure the address first.
	 */

	/*
	 * Convert mask to prefix length (prefixmask has already been validated
	 * in in6_update_ifa().
	 */
	bzero(&pr0, sizeof (pr0));
	pr0.ndpr_plen = plen;
	pr0.ndpr_ifp = ifp;
	pr0.ndpr_prefix = ifra->ifra_addr;
	pr0.ndpr_mask = ifra->ifra_prefixmask.sin6_addr;

	/* apply the mask for safety. */
	for (i = 0; i < 4; i++) {
		pr0.ndpr_prefix.sin6_addr.s6_addr32[i] &=
		    ifra->ifra_prefixmask.sin6_addr.s6_addr32[i];
	}

	/*
	 * Since we don't have an API to set prefix (not address) lifetimes, we
	 * just use the same lifetimes as addresses. The (temporarily)
	 * installed lifetimes can be overridden by later advertised RAs (when
	 * accept_rtadv is non 0), which is an intended behavior.
	 */
	pr0.ndpr_raf_onlink = 1; /* should be configurable? */
	pr0.ndpr_raf_auto = !!(ifra->ifra_flags & IN6_IFF_AUTOCONF);
	pr0.ndpr_vltime = ifra->ifra_lifetime.ia6t_vltime;
	pr0.ndpr_pltime = ifra->ifra_lifetime.ia6t_pltime;
	pr0.ndpr_stateflags |= NDPRF_STATIC;
	lck_mtx_init(&pr0.ndpr_lock, ifa_mtx_grp, ifa_mtx_attr);

	/* add the prefix if there's none. */
	if ((pr = nd6_prefix_lookup(&pr0, ND6_PREFIX_EXPIRY_NEVER)) == NULL) {
		/*
		 * nd6_prelist_add will install the corresponding interface
		 * route.
		 */
		error = nd6_prelist_add(&pr0, NULL, &pr, FALSE);
		if (error != 0)
			goto done;

		if (pr == NULL) {
			log(LOG_ERR, "%s: nd6_prelist_add okay, but"
			    " no prefix.\n", __func__);
			error = EINVAL;
			goto done;
		}
	}

	IFA_LOCK(&ia->ia_ifa);

	/* if this is a new autoconfed addr */
	addtmp = FALSE;
	if (ia->ia6_ndpr == NULL) {
		NDPR_LOCK(pr);
		++pr->ndpr_addrcnt;
		VERIFY(pr->ndpr_addrcnt != 0);
		ia->ia6_ndpr = pr;
		NDPR_ADDREF_LOCKED(pr);	/* for addr reference */

		/*
		 * If this is the first autoconf address from the prefix,
		 * create a temporary address as well (when specified).
		 */
		if ((ia->ia6_flags & IN6_IFF_AUTOCONF) != 0 &&
		    ip6_use_tempaddr &&
		    pr->ndpr_addrcnt == 1) {
			addtmp = true;
		}
		NDPR_UNLOCK(pr);
	}

	IFA_UNLOCK(&ia->ia_ifa);

	if (addtmp) {
		int e;
		e = in6_tmpifadd(ia, 1);
		if (e != 0)
			log(LOG_NOTICE, "%s: failed to create a"
			    " temporary address, error=%d\n",
			    __func__, e);
	}

	/*
	 * This might affect the status of autoconfigured addresses, that is,
	 * this address might make other addresses detached.
	 */
	lck_mtx_lock(nd6_mutex);
	pfxlist_onlink_check();
	lck_mtx_unlock(nd6_mutex);

	/* Drop use count held above during lookup/add */
	NDPR_REMREF(pr);

done:
	if (ia != NULL)
		IFA_REMREF(&ia->ia_ifa);
	return (error);
}

static __attribute__((noinline)) void
in6ctl_difaddr(struct ifnet *ifp, struct in6_ifaddr *ia)
{
	int i = 0;
	struct nd_prefix pr0, *pr;

	VERIFY(ifp != NULL && ia != NULL);

	/*
	 * If the address being deleted is the only one that owns
	 * the corresponding prefix, expire the prefix as well.
	 * XXX: theoretically, we don't have to worry about such
	 * relationship, since we separate the address management
	 * and the prefix management.  We do this, however, to provide
	 * as much backward compatibility as possible in terms of
	 * the ioctl operation.
	 * Note that in6_purgeaddr() will decrement ndpr_addrcnt.
	 */
	IFA_LOCK(&ia->ia_ifa);
	bzero(&pr0, sizeof (pr0));
	pr0.ndpr_ifp = ifp;
	pr0.ndpr_plen = in6_mask2len(&ia->ia_prefixmask.sin6_addr, NULL);
	if (pr0.ndpr_plen == 128) {
		IFA_UNLOCK(&ia->ia_ifa);
		goto purgeaddr;
	}
	pr0.ndpr_prefix = ia->ia_addr;
	pr0.ndpr_mask = ia->ia_prefixmask.sin6_addr;
	for (i = 0; i < 4; i++) {
		pr0.ndpr_prefix.sin6_addr.s6_addr32[i] &=
		    ia->ia_prefixmask.sin6_addr.s6_addr32[i];
	}
	IFA_UNLOCK(&ia->ia_ifa);

	if ((pr = nd6_prefix_lookup(&pr0, ND6_PREFIX_EXPIRY_UNSPEC)) != NULL) {
		IFA_LOCK(&ia->ia_ifa);
		NDPR_LOCK(pr);
		if (pr->ndpr_addrcnt == 1) {
			/* XXX: just for expiration */
			pr->ndpr_expire = 1;
		}
		NDPR_UNLOCK(pr);
		IFA_UNLOCK(&ia->ia_ifa);

		/* Drop use count held above during lookup */
		NDPR_REMREF(pr);
	}

purgeaddr:
	in6_purgeaddr(&ia->ia_ifa);
}

static __attribute__((noinline)) int
in6_autoconf(struct ifnet *ifp, int enable)
{
	int error = 0;

	VERIFY(ifp != NULL);

	if (ifp->if_flags & IFF_LOOPBACK)
		return (EINVAL);

	if (enable) {
		/*
		 * An interface in IPv6 router mode implies that it
		 * is either configured with a static IP address or
		 * autoconfigured via a locally-generated RA.  Prevent
		 * SIOCAUTOCONF_START from being set in that mode.
		 */
		ifnet_lock_exclusive(ifp);
		if (ifp->if_eflags & IFEF_IPV6_ROUTER) {
			ifp->if_eflags &= ~IFEF_ACCEPT_RTADV;
			error = EBUSY;
		} else {
			ifp->if_eflags |= IFEF_ACCEPT_RTADV;
		}
		ifnet_lock_done(ifp);
	} else {
		struct in6_ifaddr *ia = NULL;

		ifnet_lock_exclusive(ifp);
		ifp->if_eflags &= ~IFEF_ACCEPT_RTADV;
		ifnet_lock_done(ifp);

		/* Remove autoconfigured address from interface */
		lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
		ia = in6_ifaddrs;
		while (ia != NULL) {
			if (ia->ia_ifa.ifa_ifp != ifp) {
				ia = ia->ia_next;
				continue;
			}
			IFA_LOCK(&ia->ia_ifa);
			if (ia->ia6_flags & IN6_IFF_AUTOCONF) {
				IFA_ADDREF_LOCKED(&ia->ia_ifa);	/* for us */
				IFA_UNLOCK(&ia->ia_ifa);
				lck_rw_done(&in6_ifaddr_rwlock);
				in6_purgeaddr(&ia->ia_ifa);
				IFA_REMREF(&ia->ia_ifa);	/* for us */
				lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
				/*
				 * Purging the address caused in6_ifaddr_rwlock
				 * to be dropped and reacquired;
				 * therefore search again from the beginning
				 * of in6_ifaddrs list.
				 */
				ia = in6_ifaddrs;
				continue;
			}
			IFA_UNLOCK(&ia->ia_ifa);
			ia = ia->ia_next;
		}
		lck_rw_done(&in6_ifaddr_rwlock);
	}
	return (error);
}

/*
 * Handle SIOCSETROUTERMODE_IN6 to set or clear the IPv6 router mode flag on
 * the interface.  Entering or exiting this mode will result in the removal of
 * autoconfigured IPv6 addresses on the interface.
 */
static __attribute__((noinline)) int
in6_setrouter(struct ifnet *ifp, int enable)
{
	VERIFY(ifp != NULL);

	if (ifp->if_flags & IFF_LOOPBACK)
		return (ENODEV);

	if (enable) {
		struct nd_ifinfo *ndi = NULL;

		ndi = ND_IFINFO(ifp);
		if (ndi != NULL && ndi->initialized) {
			lck_mtx_lock(&ndi->lock);
			if (ndi->flags & ND6_IFF_PROXY_PREFIXES) {
				/* No proxy if we are an advertising router */
				ndi->flags &= ~ND6_IFF_PROXY_PREFIXES;
				lck_mtx_unlock(&ndi->lock);
				(void) nd6_if_prproxy(ifp, FALSE);
			} else {
				lck_mtx_unlock(&ndi->lock);
			}
		}
	}

	ifnet_lock_exclusive(ifp);
	if (enable) {
		ifp->if_eflags |= IFEF_IPV6_ROUTER;
	} else {
		ifp->if_eflags &= ~IFEF_IPV6_ROUTER;
	}
	ifnet_lock_done(ifp);

	lck_mtx_lock(nd6_mutex);
	defrouter_select(ifp);
	lck_mtx_unlock(nd6_mutex);

	if_allmulti(ifp, enable);

	return (in6_autoconf(ifp, FALSE));
}

static int
in6_to_kamescope(struct sockaddr_in6 *sin6, struct ifnet *ifp)
{
	struct sockaddr_in6 tmp;
	int error, id;

	VERIFY(sin6 != NULL);
	tmp = *sin6;

	error = in6_recoverscope(&tmp, &sin6->sin6_addr, ifp);
	if (error != 0)
		return (error);

	id = in6_addr2scopeid(ifp, &tmp.sin6_addr);
	if (tmp.sin6_scope_id == 0)
		tmp.sin6_scope_id = id;
	else if (tmp.sin6_scope_id != id)
		return (EINVAL); /* scope ID mismatch. */

	error = in6_embedscope(&tmp.sin6_addr, &tmp, NULL, NULL, NULL);
	if (error != 0)
		return (error);

	tmp.sin6_scope_id = 0;
	*sin6 = tmp;
	return (0);
}

/*
 * When the address is being configured we should clear out certain flags
 * coming in from the caller.
 */
#define	IN6_IFF_CLR_ADDR_FLAG_MASK	(~(IN6_IFF_DEPRECATED | IN6_IFF_DETACHED | IN6_IFF_DUPLICATED))

static int
in6_ifaupdate_aux(struct in6_ifaddr *ia, struct ifnet *ifp, int ifaupflags)
{
	struct sockaddr_in6 mltaddr, mltmask;
	struct in6_addr llsol;
	struct ifaddr *ifa;
	struct in6_multi *in6m_sol;
	struct in6_multi_mship *imm;
	struct rtentry *rt;
	int delay, error = 0;

	VERIFY(ifp != NULL && ia != NULL);
	ifa = &ia->ia_ifa;
	in6m_sol = NULL;

	nd6log2((LOG_DEBUG, "%s - %s ifp %s ia6_flags 0x%x ifaupflags 0x%x\n",
	    __func__,
	    ip6_sprintf(&ia->ia_addr.sin6_addr),
	    if_name(ia->ia_ifp),
	    ia->ia6_flags,
	    ifaupflags));

	/*
	 * Just to be safe, always clear certain flags when address
	 * is being configured
	 */
	ia->ia6_flags &= IN6_IFF_CLR_ADDR_FLAG_MASK;

	/*
	 * Mark the address as tentative before joining multicast addresses,
	 * so that corresponding MLD responses would not have a tentative
	 * source address.
	 */
	if (in6if_do_dad(ifp)) {
		in6_ifaddr_set_dadprogress(ia);
		/*
		 * Do not delay sending neighbor solicitations when using optimistic
		 * duplicate address detection, c.f. RFC 4429.
		 */
		if (ia->ia6_flags & IN6_IFF_OPTIMISTIC)
			ifaupflags &= ~IN6_IFAUPDATE_DADDELAY;
		else
			ifaupflags |= IN6_IFAUPDATE_DADDELAY;
	} else {
		/*
		 * If the interface has been marked to not perform
		 * DAD, make sure to reset DAD in progress flags
		 * that may come in from the caller.
		 */
		ia->ia6_flags &= ~IN6_IFF_DADPROGRESS;
	}

	/* Join necessary multicast groups */
	if ((ifp->if_flags & IFF_MULTICAST) != 0) {

		/* join solicited multicast addr for new host id */
		bzero(&llsol, sizeof (struct in6_addr));
		llsol.s6_addr32[0] = IPV6_ADDR_INT32_MLL;
		llsol.s6_addr32[1] = 0;
		llsol.s6_addr32[2] = htonl(1);
		llsol.s6_addr32[3] = ia->ia_addr.sin6_addr.s6_addr32[3];
		llsol.s6_addr8[12] = 0xff;
		if ((error = in6_setscope(&llsol, ifp, NULL)) != 0) {
			/* XXX: should not happen */
			log(LOG_ERR, "%s: in6_setscope failed\n", __func__);
			goto unwind;
		}
		delay = 0;
		if ((ifaupflags & IN6_IFAUPDATE_DADDELAY)) {
			/*
			 * We need a random delay for DAD on the address
			 * being configured.  It also means delaying
			 * transmission of the corresponding MLD report to
			 * avoid report collision. [RFC 4862]
			 */
			delay = random() % MAX_RTR_SOLICITATION_DELAY;
		}
		imm = in6_joingroup(ifp, &llsol, &error, delay);
		if (imm == NULL) {
			nd6log((LOG_WARNING,
			    "%s: addmulti failed for %s on %s (errno=%d)\n",
			    __func__, ip6_sprintf(&llsol), if_name(ifp),
			    error));
			VERIFY(error != 0);
			goto unwind;
		}
		in6m_sol = imm->i6mm_maddr;
		/* take a refcount for this routine */
		IN6M_ADDREF(in6m_sol);

		IFA_LOCK_SPIN(ifa);
		LIST_INSERT_HEAD(&ia->ia6_memberships, imm, i6mm_chain);
		IFA_UNLOCK(ifa);

		bzero(&mltmask, sizeof (mltmask));
		mltmask.sin6_len = sizeof (struct sockaddr_in6);
		mltmask.sin6_family = AF_INET6;
		mltmask.sin6_addr = in6mask32;
#define	MLTMASK_LEN  4	/* mltmask's masklen (=32bit=4octet) */

		/*
		 * join link-local all-nodes address
		 */
		bzero(&mltaddr, sizeof (mltaddr));
		mltaddr.sin6_len = sizeof (struct sockaddr_in6);
		mltaddr.sin6_family = AF_INET6;
		mltaddr.sin6_addr = in6addr_linklocal_allnodes;
		if ((error = in6_setscope(&mltaddr.sin6_addr, ifp, NULL)) != 0)
			goto unwind; /* XXX: should not fail */

		/*
		 * XXX: do we really need this automatic routes?
		 * We should probably reconsider this stuff.  Most applications
		 * actually do not need the routes, since they usually specify
		 * the outgoing interface.
		 */
		rt = rtalloc1_scoped((struct sockaddr *)&mltaddr, 0, 0UL,
		    ia->ia_ifp->if_index);
		if (rt) {
			if (memcmp(&mltaddr.sin6_addr, &((struct sockaddr_in6 *)
			    (void *)rt_key(rt))->sin6_addr, MLTMASK_LEN)) {
				rtfree(rt);
				rt = NULL;
			}
		}
		if (!rt) {
			error = rtrequest_scoped(RTM_ADD,
			    (struct sockaddr *)&mltaddr,
			    (struct sockaddr *)&ia->ia_addr,
			    (struct sockaddr *)&mltmask, RTF_UP | RTF_CLONING,
			    NULL, ia->ia_ifp->if_index);
			if (error)
				goto unwind;
		} else {
			rtfree(rt);
		}

		imm = in6_joingroup(ifp, &mltaddr.sin6_addr, &error, 0);
		if (!imm) {
			nd6log((LOG_WARNING,
			    "%s: addmulti failed for %s on %s (errno=%d)\n",
			    __func__, ip6_sprintf(&mltaddr.sin6_addr),
			    if_name(ifp), error));
			VERIFY(error != 0);
			goto unwind;
		}
		IFA_LOCK_SPIN(ifa);
		LIST_INSERT_HEAD(&ia->ia6_memberships, imm, i6mm_chain);
		IFA_UNLOCK(ifa);

		/*
		 * join node information group address
		 */
#define	hostnamelen	strlen(hostname)
		delay = 0;
		if ((ifaupflags & IN6_IFAUPDATE_DADDELAY)) {
			/*
			 * The spec doesn't say anything about delay for this
			 * group, but the same logic should apply.
			 */
			delay = random() % MAX_RTR_SOLICITATION_DELAY;
		}
		if (in6_nigroup(ifp, hostname, hostnamelen, &mltaddr.sin6_addr)
		    == 0) {
			imm = in6_joingroup(ifp, &mltaddr.sin6_addr, &error,
			    delay); /* XXX jinmei */
			if (!imm) {
				nd6log((LOG_WARNING,
				    "%s: addmulti failed for %s on %s "
				    "(errno=%d)\n",
				    __func__, ip6_sprintf(&mltaddr.sin6_addr),
				    if_name(ifp), error));
				/* XXX not very fatal, go on... */
				error = 0;
			} else {
				IFA_LOCK_SPIN(ifa);
				LIST_INSERT_HEAD(&ia->ia6_memberships,
				    imm, i6mm_chain);
				IFA_UNLOCK(ifa);
			}
		}
#undef hostnamelen

		/*
		 * join interface-local all-nodes address.
		 * (ff01::1%ifN, and ff01::%ifN/32)
		 */
		mltaddr.sin6_addr = in6addr_nodelocal_allnodes;
		if ((error = in6_setscope(&mltaddr.sin6_addr, ifp, NULL)) != 0)
			goto unwind; /* XXX: should not fail */
		/* XXX: again, do we really need the route? */
		rt = rtalloc1_scoped((struct sockaddr *)&mltaddr, 0, 0UL,
		    ia->ia_ifp->if_index);
		if (rt) {
			if (memcmp(&mltaddr.sin6_addr, &((struct sockaddr_in6 *)
			    (void *)rt_key(rt))->sin6_addr, MLTMASK_LEN)) {
				rtfree(rt);
				rt = NULL;
			}
		}
		if (!rt) {
			error = rtrequest_scoped(RTM_ADD,
			    (struct sockaddr *)&mltaddr,
			    (struct sockaddr *)&ia->ia_addr,
			    (struct sockaddr *)&mltmask, RTF_UP | RTF_CLONING,
			    NULL, ia->ia_ifp->if_index);
			if (error)
				goto unwind;
		} else
			rtfree(rt);

		imm = in6_joingroup(ifp, &mltaddr.sin6_addr, &error, 0);
		if (!imm) {
			nd6log((LOG_WARNING,
			    "%s: addmulti failed for %s on %s (errno=%d)\n",
			    __func__, ip6_sprintf(&mltaddr.sin6_addr),
			    if_name(ifp), error));
			VERIFY(error != 0);
			goto unwind;
		}
		IFA_LOCK(ifa);
		LIST_INSERT_HEAD(&ia->ia6_memberships, imm, i6mm_chain);
		IFA_UNLOCK(ifa);
	}
#undef	MLTMASK_LEN

	/* Ensure nd6_service() is scheduled as soon as it's convenient */
	++nd6_sched_timeout_want;

	/*
	 * Perform DAD, if needed.
	 * XXX It may be of use, if we can administratively
	 * disable DAD.
	 */
	IFA_LOCK_SPIN(ifa);
	if (in6if_do_dad(ifp) && ((ifa->ifa_flags & IN6_IFF_NODAD) == 0) &&
	    (ia->ia6_flags & IN6_IFF_DADPROGRESS)) {
		int mindelay, maxdelay;
		int *delayptr, delayval;

		IFA_UNLOCK(ifa);
		delayptr = NULL;
		/*
		 * Avoid the DAD delay if the caller wants us to skip it.
		 * This is not compliant with RFC 2461, but it's only being
		 * used for signalling and not for actual DAD.
		 */
		if ((ifaupflags & IN6_IFAUPDATE_DADDELAY) &&
		    !(ia->ia6_flags & IN6_IFF_SWIFTDAD)) {
			/*
			 * We need to impose a delay before sending an NS
			 * for DAD.  Check if we also needed a delay for the
			 * corresponding MLD message.  If we did, the delay
			 * should be larger than the MLD delay (this could be
			 * relaxed a bit, but this simple logic is at least
			 * safe).
			 */
			mindelay = 0;
			if (in6m_sol != NULL) {
				IN6M_LOCK(in6m_sol);
				if (in6m_sol->in6m_state ==
				    MLD_REPORTING_MEMBER)
					mindelay = in6m_sol->in6m_timer;
				IN6M_UNLOCK(in6m_sol);
			}
			maxdelay = MAX_RTR_SOLICITATION_DELAY * hz;
			if (maxdelay - mindelay == 0)
				delayval = 0;
			else {
				delayval =
				    (random() % (maxdelay - mindelay)) +
				    mindelay;
			}
			delayptr = &delayval;
		}

		nd6_dad_start((struct ifaddr *)ia, delayptr);
	} else {
		IFA_UNLOCK(ifa);
	}

	goto done;

unwind:
	VERIFY(error != 0);
	in6_purgeaddr(&ia->ia_ifa);

done:
	/* release reference held for this routine */
	if (in6m_sol != NULL)
		IN6M_REMREF(in6m_sol);
	return (error);
}

/*
 * Request an IPv6 interface address.  If the address is new, then it will be
 * constructed and appended to the interface address chains.  The interface
 * address structure is optionally returned with a reference for the caller.
 */
int
in6_update_ifa(struct ifnet *ifp, struct in6_aliasreq *ifra, int ifaupflags,
    struct in6_ifaddr **iar)
{
	struct in6_addrlifetime ia6_lt;
	struct in6_ifaddr *ia;
	struct ifaddr *ifa;
	struct ifaddr *xifa;
	struct in6_addrlifetime *lt;
	uint64_t timenow;
	int plen, error;

	/* Sanity check parameters and initialize locals */
	VERIFY(ifp != NULL && ifra != NULL && iar != NULL);
	ia = NULL;
	ifa = NULL;
	error = 0;

	/*
	 * We always require users to specify a valid IPv6 address for
	 * the corresponding operation.
	 */
	if (ifra->ifra_addr.sin6_family != AF_INET6 ||
	    ifra->ifra_addr.sin6_len != sizeof (struct sockaddr_in6)) {
		error = EAFNOSUPPORT;
		goto unwind;
	}

	/* Validate ifra_prefixmask.sin6_len is properly bounded. */
	if (ifra->ifra_prefixmask.sin6_len == 0 ||
	    ifra->ifra_prefixmask.sin6_len > sizeof (struct sockaddr_in6)) {
		error = EINVAL;
		goto unwind;
	}

	/* Validate prefix length extracted from ifra_prefixmask structure. */
	plen = in6_mask2len(&ifra->ifra_prefixmask.sin6_addr,
	    (u_char *)&ifra->ifra_prefixmask + ifra->ifra_prefixmask.sin6_len);
	if (plen <= 0) {
		error = EINVAL;
		goto unwind;
	}

	/* Validate lifetimes */
	lt = &ifra->ifra_lifetime;
	if (lt->ia6t_pltime > lt->ia6t_vltime) {
		log(LOG_INFO,
		    "%s: pltime 0x%x > vltime 0x%x for %s\n", __func__,
		    lt->ia6t_pltime, lt->ia6t_vltime,
		    ip6_sprintf(&ifra->ifra_addr.sin6_addr));
		error = EINVAL;
		goto unwind;
	}
	if (lt->ia6t_vltime == 0) {
		/*
		 * the following log might be noisy, but this is a typical
		 * configuration mistake or a tool's bug.
		 */
		log(LOG_INFO, "%s: valid lifetime is 0 for %s\n", __func__,
		    ip6_sprintf(&ifra->ifra_addr.sin6_addr));
	}

	/*
	 * Before we lock the ifnet structure, we first check to see if the
	 * address already exists. If so, then we don't allocate and link a
	 * new one here.
	 */
	ia = in6ifa_ifpwithaddr(ifp, &ifra->ifra_addr.sin6_addr);
	if (ia != NULL)
		ifa = &ia->ia_ifa;

	/*
	 * Validate destination address on interface types that require it.
	 */
	if ((ifp->if_flags & (IFF_LOOPBACK|IFF_POINTOPOINT)) != 0) {
		switch (ifra->ifra_dstaddr.sin6_family) {
		case AF_INET6:
			if (plen != 128) {
				/* noisy message for diagnostic purposes */
				log(LOG_INFO,
				    "%s: prefix length < 128 with"
				    " explicit dstaddr.\n", __func__);
				error = EINVAL;
				goto unwind;
			}
			break;

		case AF_UNSPEC:
			break;

		default:
			error = EAFNOSUPPORT;
			goto unwind;
		}
	} else if (ifra->ifra_dstaddr.sin6_family != AF_UNSPEC) {
		log(LOG_INFO,
		    "%s: dstaddr valid only on p2p and loopback interfaces.\n",
		    __func__);
		error = EINVAL;
		goto unwind;
	}

	timenow = net_uptime();

	if (ia == NULL) {
		int how;

		/* Is this the first new IPv6 address for the interface? */
		ifaupflags |= IN6_IFAUPDATE_NEWADDR;

		/* Allocate memory for IPv6 interface address structure. */
		how = !(ifaupflags & IN6_IFAUPDATE_NOWAIT) ? M_WAITOK : 0;
		ia = in6_ifaddr_alloc(how);
		if (ia == NULL) {
			error = ENOBUFS;
			goto unwind;
		}

		ifa = &ia->ia_ifa;

		/*
		 * Initialize interface address structure.
		 *
		 * Note well: none of these sockaddr_in6 structures contain a
		 * valid sin6_port, sin6_flowinfo or even a sin6_scope_id field.
		 * We still embed link-local scope identifiers at the end of an
		 * arbitrary fe80::/32 prefix, for historical reasons. Also, the
		 * ifa_dstaddr field is always non-NULL on point-to-point and
		 * loopback interfaces, and conventionally points to a socket
		 * address of AF_UNSPEC family when there is no destination.
		 *
		 * Please enjoy the dancing sea turtle.
		 */
		IFA_ADDREF(ifa); /* for this and optionally for caller */
		ifa->ifa_addr = (struct sockaddr *)&ia->ia_addr;
		if (ifra->ifra_dstaddr.sin6_family == AF_INET6 ||
		    (ifp->if_flags & (IFF_POINTOPOINT | IFF_LOOPBACK)) != 0)
			ifa->ifa_dstaddr = (struct sockaddr *)&ia->ia_dstaddr;
		ifa->ifa_netmask = (struct sockaddr *)&ia->ia_prefixmask;
		ifa->ifa_ifp = ifp;
		ifa->ifa_metric = ifp->if_metric;
		ifa->ifa_rtrequest = nd6_rtrequest;

		LIST_INIT(&ia->ia6_memberships);
		ia->ia_addr.sin6_family = AF_INET6;
		ia->ia_addr.sin6_len = sizeof (ia->ia_addr);
		ia->ia_addr.sin6_addr = ifra->ifra_addr.sin6_addr;
		ia->ia_prefixmask.sin6_family = AF_INET6;
		ia->ia_prefixmask.sin6_len = sizeof (ia->ia_prefixmask);
		ia->ia_prefixmask.sin6_addr = ifra->ifra_prefixmask.sin6_addr;
		error = in6_to_kamescope(&ia->ia_addr, ifp);
		if (error != 0)
			goto unwind;
		if (ifa->ifa_dstaddr != NULL) {
			ia->ia_dstaddr = ifra->ifra_dstaddr;
			error = in6_to_kamescope(&ia->ia_dstaddr, ifp);
			if (error != 0)
				goto unwind;
		}

		/* Append to address chains */
		ifnet_lock_exclusive(ifp);
		ifaupflags |= IN6_IFAUPDATE_1STADDR;
		TAILQ_FOREACH(xifa, &ifp->if_addrlist, ifa_list) {
			IFA_LOCK_SPIN(xifa);
			if (xifa->ifa_addr->sa_family != AF_INET6) {
				IFA_UNLOCK(xifa);
				ifaupflags &= ~IN6_IFAUPDATE_1STADDR;
				break;
			}
			IFA_UNLOCK(xifa);
		}

		IFA_LOCK_SPIN(ifa);
		if_attach_ifa(ifp, ifa); /* holds reference for ifnet link */
		IFA_UNLOCK(ifa);
		ifnet_lock_done(ifp);

		lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
		if (in6_ifaddrs != NULL) {
			struct in6_ifaddr *iac;
			for (iac = in6_ifaddrs; iac->ia_next != NULL;
			    iac = iac->ia_next)
				continue;
			iac->ia_next = ia;
		} else {
			in6_ifaddrs = ia;
		}
		IFA_ADDREF(ifa); /* hold for in6_ifaddrs link */
		lck_rw_done(&in6_ifaddr_rwlock);
	} else {
		ifa = &ia->ia_ifa;
		ifaupflags &= ~(IN6_IFAUPDATE_NEWADDR|IN6_IFAUPDATE_1STADDR);
	}

	VERIFY(ia != NULL && ifa == &ia->ia_ifa);
	IFA_LOCK(ifa);

	/*
	 * Set lifetimes.  We do not refer to ia6t_expire and ia6t_preferred
	 * to see if the address is deprecated or invalidated, but initialize
	 * these members for applications.
	 */
	ia->ia6_updatetime = ia->ia6_createtime = timenow;
	ia6_lt = *lt;
	if (ia6_lt.ia6t_vltime != ND6_INFINITE_LIFETIME)
		ia6_lt.ia6t_expire = timenow + ia6_lt.ia6t_vltime;
	else
		ia6_lt.ia6t_expire = 0;
	if (ia6_lt.ia6t_pltime != ND6_INFINITE_LIFETIME)
		ia6_lt.ia6t_preferred = timenow + ia6_lt.ia6t_pltime;
	else
		ia6_lt.ia6t_preferred = 0;
	in6ifa_setlifetime(ia, &ia6_lt);

	/*
	 * Backward compatibility - if IN6_IFF_DEPRECATED is set from the
	 * userland, make it deprecated.
	 */
	if ((ia->ia6_flags & IN6_IFF_DEPRECATED) != 0) {
		ia->ia6_lifetime.ia6ti_pltime = 0;
		ia->ia6_lifetime.ia6ti_preferred = timenow;
	}

	/*
	 * Update flag or prefix length
	 */
	ia->ia_plen = plen;
	ia->ia6_flags = ifra->ifra_flags;

	/* Release locks (new address available to concurrent tasks) */
	IFA_UNLOCK(ifa);

	/* Further initialization of the interface address */
	error = in6_ifinit(ifp, ia, ifaupflags);
	if (error != 0)
		goto unwind;

	/* Finish updating the address while other tasks are working with it */
	error = in6_ifaupdate_aux(ia, ifp, ifaupflags);
	if (error != 0)
		goto unwind;

	/* Return success (optionally w/ address for caller). */
	VERIFY(error == 0);
	(void) ifnet_notify_address(ifp, AF_INET6);
	goto done;

unwind:
	VERIFY(error != 0);
	if (ia != NULL) {
		VERIFY(ifa == &ia->ia_ifa);
		IFA_REMREF(ifa);
		ia = NULL;
	}

done:
	*iar = ia;
	return (error);
}

void
in6_purgeaddr(struct ifaddr *ifa)
{
	struct ifnet *ifp = ifa->ifa_ifp;
	struct in6_ifaddr *ia = (struct in6_ifaddr *)ifa;
	struct in6_multi_mship *imm;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_NOTOWNED);

	/* stop DAD processing */
	nd6_dad_stop(ifa);

	/*
	 * delete route to the destination of the address being purged.
	 * The interface must be p2p or loopback in this case.
	 */
	IFA_LOCK(ifa);
	if ((ia->ia_flags & IFA_ROUTE) && ia->ia_plen == 128) {
		int error, rtf;

		IFA_UNLOCK(ifa);
		rtf = (ia->ia_dstaddr.sin6_family == AF_INET6) ? RTF_HOST : 0;
		error = rtinit(&(ia->ia_ifa), RTM_DELETE, rtf);
		if (error != 0) {
			log(LOG_ERR, "in6_purgeaddr: failed to remove "
			    "a route to the p2p destination: %s on %s, "
			    "errno=%d\n",
			    ip6_sprintf(&ia->ia_addr.sin6_addr), if_name(ifp),
			    error);
			/* proceed anyway... */
		}
		IFA_LOCK_SPIN(ifa);
		ia->ia_flags &= ~IFA_ROUTE;
	}
	IFA_UNLOCK(ifa);

	/* Remove ownaddr's loopback rtentry, if it exists. */
	in6_ifremloop(&(ia->ia_ifa));

	/*
	 * leave from multicast groups we have joined for the interface
	 */
	IFA_LOCK(ifa);
	while ((imm = ia->ia6_memberships.lh_first) != NULL) {
		LIST_REMOVE(imm, i6mm_chain);
		IFA_UNLOCK(ifa);
		in6_leavegroup(imm);
		IFA_LOCK(ifa);
	}
	IFA_UNLOCK(ifa);

	/* in6_unlink_ifa() will need exclusive access */
	in6_unlink_ifa(ia, ifp);
	in6_post_msg(ifp, KEV_INET6_ADDR_DELETED, ia, NULL);

	(void) ifnet_notify_address(ifp, AF_INET6);
}

static void
in6_unlink_ifa(struct in6_ifaddr *ia, struct ifnet *ifp)
{
	struct in6_ifaddr *oia;
	struct ifaddr *ifa;
	int unlinked;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_NOTOWNED);

	ifa = &ia->ia_ifa;
	IFA_ADDREF(ifa);

	ifnet_lock_exclusive(ifp);
	IFA_LOCK(ifa);
	if (ifa->ifa_debug & IFD_ATTACHED)
		if_detach_ifa(ifp, ifa);
	IFA_UNLOCK(ifa);
	ifnet_lock_done(ifp);

	unlinked = 1;
	lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
	oia = ia;
	if (oia == (ia = in6_ifaddrs)) {
		in6_ifaddrs = ia->ia_next;
	} else {
		while (ia->ia_next && (ia->ia_next != oia))
			ia = ia->ia_next;
		if (ia->ia_next) {
			ia->ia_next = oia->ia_next;
		} else {
			/* search failed */
			log(LOG_NOTICE, "%s: search failed.\n", __func__);
			unlinked = 0;
		}
	}

	/*
	 * When IPv6 address is being removed, release the
	 * reference to the base prefix.
	 * Also, since the release might, affect the status
	 * of other (detached) addresses, call
	 * pfxlist_onlink_check().
	 */
	ifa = &oia->ia_ifa;
	IFA_LOCK(ifa);
	/*
	 * Only log the below message for addresses other than
	 * link local.
	 * Only one LLA (auto-configured or statically) is allowed
	 * on an interface.
	 * LLA prefix, while added to the prefix list, is not
	 * reference countedi (as it is the only one).
	 * The prefix also never expires on its own as LLAs
	 * have infinite lifetime.
	 *
	 * For now quiece down the log message for LLAs.
	 */
	if (!IN6_IS_ADDR_LINKLOCAL(&oia->ia_addr.sin6_addr)) {
		if (oia->ia6_ndpr == NULL)
			log(LOG_NOTICE, "in6_unlink_ifa: IPv6 address "
			    "0x%llx has no prefix\n",
			    (uint64_t)VM_KERNEL_ADDRPERM(oia));
		else {
			struct nd_prefix *pr = oia->ia6_ndpr;
			oia->ia6_flags &= ~IN6_IFF_AUTOCONF;
			oia->ia6_ndpr = NULL;
			NDPR_LOCK(pr);
			VERIFY(pr->ndpr_addrcnt != 0);
			pr->ndpr_addrcnt--;
			NDPR_UNLOCK(pr);
			NDPR_REMREF(pr);	/* release addr reference */
		}
	}
	IFA_UNLOCK(ifa);
	lck_rw_done(&in6_ifaddr_rwlock);

	if ((oia->ia6_flags & IN6_IFF_AUTOCONF) != 0) {
		lck_mtx_lock(nd6_mutex);
		pfxlist_onlink_check();
		lck_mtx_unlock(nd6_mutex);
	}
	/*
	 * release another refcnt for the link from in6_ifaddrs.
	 * Do this only if it's not already unlinked in the event that we lost
	 * the race, since in6_ifaddr_rwlock was momentarily dropped above.
	 */
	if (unlinked)
		IFA_REMREF(ifa);

	/* release reference held for this routine */
	IFA_REMREF(ifa);

	/* invalidate route caches */
	routegenid_inet6_update();
}

void
in6_purgeif(struct ifnet *ifp)
{
	struct in6_ifaddr *ia;

	if (ifp == NULL)
		return;

	lck_mtx_assert(nd6_mutex, LCK_MTX_ASSERT_NOTOWNED);

	lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
	ia = in6_ifaddrs;
	while (ia != NULL) {
		if (ia->ia_ifa.ifa_ifp != ifp) {
			ia = ia->ia_next;
			continue;
		}
		IFA_ADDREF(&ia->ia_ifa);	/* for us */
		lck_rw_done(&in6_ifaddr_rwlock);
		in6_purgeaddr(&ia->ia_ifa);
		IFA_REMREF(&ia->ia_ifa);	/* for us */
		lck_rw_lock_exclusive(&in6_ifaddr_rwlock);
		/*
		 * Purging the address would have caused
		 * in6_ifaddr_rwlock to be dropped and reacquired;
		 * therefore search again from the beginning
		 * of in6_ifaddrs list.
		 */
		ia = in6_ifaddrs;
	}
	lck_rw_done(&in6_ifaddr_rwlock);

	in6_ifdetach(ifp);
}

/*
 * Initialize an interface's internet6 address and routing table entry.
 */
static int
in6_ifinit(struct ifnet *ifp, struct in6_ifaddr *ia, int ifaupflags)
{
	int error;
	struct ifaddr *ifa;

	error = 0;
	ifa = &ia->ia_ifa;

	/*
	 * NOTE: SIOCSIFADDR is defined with struct ifreq as parameter,
	 * but here we are sending it down to the interface with a pointer
	 * to struct ifaddr, for legacy reasons.
	 */
	if ((ifaupflags & IN6_IFAUPDATE_1STADDR) != 0) {
		error = ifnet_ioctl(ifp, PF_INET6, SIOCSIFADDR, ia);
		if (error != 0) {
			if (error != EOPNOTSUPP)
				return (error);
			error = 0;
		}
	}

	IFA_LOCK(ifa);

	/*
	 * Special case:
	 * If the destination address is specified for a point-to-point
	 * interface, install a route to the destination as an interface
	 * direct route.
	 */
	if (!(ia->ia_flags & IFA_ROUTE) && ia->ia_plen == 128 &&
	    ia->ia_dstaddr.sin6_family == AF_INET6) {
		IFA_UNLOCK(ifa);
		error = rtinit(ifa, RTM_ADD, RTF_UP | RTF_HOST);
		if (error != 0)
			return (error);
		IFA_LOCK(ifa);
		ia->ia_flags |= IFA_ROUTE;
	}
	IFA_LOCK_ASSERT_HELD(ifa);
	if (ia->ia_plen < 128) {
		/*
		 * The RTF_CLONING flag is necessary for in6_is_ifloop_auto().
		 */
		ia->ia_flags |= RTF_CLONING;
	}

	IFA_UNLOCK(ifa);

	/* Add ownaddr as loopback rtentry, if necessary (ex. on p2p link). */
	if ((ifaupflags & IN6_IFAUPDATE_NEWADDR) != 0)
		in6_ifaddloop(ifa);

	/* invalidate route caches */
	routegenid_inet6_update();

	VERIFY(error == 0);
	return (0);
}

void
in6_purgeaddrs(struct ifnet *ifp)
{
	in6_purgeif(ifp);
}

/*
 * Find an IPv6 interface link-local address specific to an interface.
 */
struct in6_ifaddr *
in6ifa_ifpforlinklocal(struct ifnet *ifp, int ignoreflags)
{
	struct ifaddr *ifa;

	ifnet_lock_shared(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
	{
		IFA_LOCK_SPIN(ifa);
		if (ifa->ifa_addr->sa_family != AF_INET6) {
			IFA_UNLOCK(ifa);
			continue;
		}
		if (IN6_IS_ADDR_LINKLOCAL(IFA_IN6(ifa))) {
			if ((((struct in6_ifaddr *)ifa)->ia6_flags &
			    ignoreflags) != 0) {
				IFA_UNLOCK(ifa);
				continue;
			}
			IFA_ADDREF_LOCKED(ifa);	/* for caller */
			IFA_UNLOCK(ifa);
			break;
		}
		IFA_UNLOCK(ifa);
	}
	ifnet_lock_done(ifp);

	return ((struct in6_ifaddr *)ifa);
}

/*
 * find the internet address corresponding to a given interface and address.
 */
struct in6_ifaddr *
in6ifa_ifpwithaddr(struct ifnet *ifp, struct in6_addr *addr)
{
	struct ifaddr *ifa;

	ifnet_lock_shared(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list)
	{
		IFA_LOCK_SPIN(ifa);
		if (ifa->ifa_addr->sa_family != AF_INET6) {
			IFA_UNLOCK(ifa);
			continue;
		}
		if (IN6_ARE_ADDR_EQUAL(addr, IFA_IN6(ifa))) {
			IFA_ADDREF_LOCKED(ifa);	/* for caller */
			IFA_UNLOCK(ifa);
			break;
		}
		IFA_UNLOCK(ifa);
	}
	ifnet_lock_done(ifp);

	return ((struct in6_ifaddr *)ifa);
}

struct in6_ifaddr *
in6ifa_prproxyaddr(struct in6_addr *addr)
{
	struct in6_ifaddr *ia;

	lck_rw_lock_shared(&in6_ifaddr_rwlock);
	for (ia = in6_ifaddrs; ia; ia = ia->ia_next) {
		IFA_LOCK(&ia->ia_ifa);
		if (IN6_ARE_ADDR_EQUAL(addr, IFA_IN6(&ia->ia_ifa))) {
			IFA_ADDREF_LOCKED(&ia->ia_ifa);	/* for caller */
			IFA_UNLOCK(&ia->ia_ifa);
			break;
		}
		IFA_UNLOCK(&ia->ia_ifa);
	}
	lck_rw_done(&in6_ifaddr_rwlock);

	if (ia != NULL && !nd6_prproxy_ifaddr(ia)) {
		IFA_REMREF(&ia->ia_ifa);
		ia = NULL;
	}

	return (ia);
}

void
in6ifa_getlifetime(struct in6_ifaddr *ia6, struct in6_addrlifetime *t_dst,
    int iscalendar)
{
	struct in6_addrlifetime_i *t_src = &ia6->ia6_lifetime;
	struct timeval caltime;

	t_dst->ia6t_vltime = t_src->ia6ti_vltime;
	t_dst->ia6t_pltime = t_src->ia6ti_pltime;
	t_dst->ia6t_expire = 0;
	t_dst->ia6t_preferred = 0;

	/* account for system time change */
	getmicrotime(&caltime);
	t_src->ia6ti_base_calendartime +=
	    NET_CALCULATE_CLOCKSKEW(caltime,
	    t_src->ia6ti_base_calendartime, net_uptime(),
	    t_src->ia6ti_base_uptime);

	if (iscalendar) {
		if (t_src->ia6ti_expire != 0 &&
		    t_src->ia6ti_vltime != ND6_INFINITE_LIFETIME)
			t_dst->ia6t_expire = t_src->ia6ti_base_calendartime +
			    t_src->ia6ti_expire - t_src->ia6ti_base_uptime;

		if (t_src->ia6ti_preferred != 0 &&
		    t_src->ia6ti_pltime != ND6_INFINITE_LIFETIME)
			t_dst->ia6t_preferred = t_src->ia6ti_base_calendartime +
			    t_src->ia6ti_preferred - t_src->ia6ti_base_uptime;
	} else {
		if (t_src->ia6ti_expire != 0 &&
		    t_src->ia6ti_vltime != ND6_INFINITE_LIFETIME)
			t_dst->ia6t_expire = t_src->ia6ti_expire;

		if (t_src->ia6ti_preferred != 0 &&
		    t_src->ia6ti_pltime != ND6_INFINITE_LIFETIME)
			t_dst->ia6t_preferred = t_src->ia6ti_preferred;
	}
}

void
in6ifa_setlifetime(struct in6_ifaddr *ia6, struct in6_addrlifetime *t_src)
{
	struct in6_addrlifetime_i *t_dst = &ia6->ia6_lifetime;
	struct timeval caltime;

	/* account for system time change */
	getmicrotime(&caltime);
	t_dst->ia6ti_base_calendartime +=
	    NET_CALCULATE_CLOCKSKEW(caltime,
	    t_dst->ia6ti_base_calendartime, net_uptime(),
	    t_dst->ia6ti_base_uptime);

	/* trust the caller for the values */
	t_dst->ia6ti_expire = t_src->ia6t_expire;
	t_dst->ia6ti_preferred = t_src->ia6t_preferred;
	t_dst->ia6ti_vltime = t_src->ia6t_vltime;
	t_dst->ia6ti_pltime = t_src->ia6t_pltime;
}

/*
 * Convert IP6 address to printable (loggable) representation.
 */
char *
ip6_sprintf(const struct in6_addr *addr)
{
	static const char digits[] = "0123456789abcdef";
	static int ip6round = 0;
	static char ip6buf[8][48];

	int i;
	char *cp;
	const u_short *a = (const u_short *)addr;
	const u_char *d;
	u_char n;
	int dcolon = 0;
	int zpad = 0;

	ip6round = (ip6round + 1) & 7;
	cp = ip6buf[ip6round];

	for (i = 0; i < 8; i++) {
		if (dcolon == 1) {
			if (*a == 0) {
				if (i == 7)
					*cp++ = ':';
				a++;
				continue;
			} else
				dcolon = 2;
		}
		if (*a == 0) {
			if (dcolon == 0 && *(a + 1) == 0) {
				if (i == 0)
					*cp++ = ':';
				*cp++ = ':';
				dcolon = 1;
			} else {
				*cp++ = '0';
				*cp++ = ':';
			}
			a++;
			continue;
		}
		d = (const u_char *)a;
		zpad = 0;
		if ((n = *d >> 4) != 0) {
			*cp++ = digits[n];
			zpad = 1;
		}
		if ((n = *d++ & 0xf) != 0 || zpad) {
			*cp++ = digits[n];
			zpad = 1;
		}
		if ((n = *d >> 4) != 0 || zpad) {
			*cp++ = digits[n];
			zpad = 1;
		}
		if ((n = *d & 0xf) != 0 || zpad)
			*cp++ = digits[n];
		*cp++ = ':';
		a++;
	}
	*--cp = 0;
	return (ip6buf[ip6round]);
}

int
in6addr_local(struct in6_addr *in6)
{
	struct rtentry *rt;
	struct sockaddr_in6 sin6;
	int local = 0;

	if (IN6_IS_ADDR_LOOPBACK(in6) || IN6_IS_SCOPE_LINKLOCAL(in6))
		return (1);

	sin6.sin6_family = AF_INET6;
	sin6.sin6_len = sizeof (sin6);
	bcopy(in6, &sin6.sin6_addr, sizeof (*in6));
	rt = rtalloc1((struct sockaddr *)&sin6, 0, 0);

	if (rt != NULL) {
		RT_LOCK_SPIN(rt);
		if (rt->rt_gateway->sa_family == AF_LINK)
			local = 1;
		RT_UNLOCK(rt);
		rtfree(rt);
	} else {
		local = in6_localaddr(in6);
	}
	return (local);
}

int
in6_localaddr(struct in6_addr *in6)
{
	struct in6_ifaddr *ia;

	if (IN6_IS_ADDR_LOOPBACK(in6) || IN6_IS_ADDR_LINKLOCAL(in6))
		return (1);

	lck_rw_lock_shared(&in6_ifaddr_rwlock);
	for (ia = in6_ifaddrs; ia; ia = ia->ia_next) {
		IFA_LOCK_SPIN(&ia->ia_ifa);
		if (IN6_ARE_MASKED_ADDR_EQUAL(in6, &ia->ia_addr.sin6_addr,
		    &ia->ia_prefixmask.sin6_addr)) {
			IFA_UNLOCK(&ia->ia_ifa);
			lck_rw_done(&in6_ifaddr_rwlock);
			return (1);
		}
		IFA_UNLOCK(&ia->ia_ifa);
	}
	lck_rw_done(&in6_ifaddr_rwlock);
	return (0);
}

/*
 * return length of part which dst and src are equal
 * hard coding...
 */
int
in6_matchlen(struct in6_addr *src, struct in6_addr *dst)
{
	int match = 0;
	u_char *s = (u_char *)src, *d = (u_char *)dst;
	u_char *lim = s + 16, r;

	while (s < lim)
		if ((r = (*d++ ^ *s++)) != 0) {
			while (r < 128) {
				match++;
				r <<= 1;
			}
			break;
		} else
			match += 8;
	return (match);
}

/* XXX: to be scope conscious */
int
in6_are_prefix_equal(struct in6_addr *p1, struct in6_addr *p2, int len)
{
	int bytelen, bitlen;

	/* sanity check */
	if (0 > len || len > 128) {
		log(LOG_ERR, "%s: invalid prefix length(%d)\n", __func__, len);
		return (0);
	}

	bytelen = len / 8;
	bitlen = len % 8;

	if (bcmp(&p1->s6_addr, &p2->s6_addr, bytelen))
		return (0);
	if (bitlen != 0 &&
	    p1->s6_addr[bytelen] >> (8 - bitlen) !=
	    p2->s6_addr[bytelen] >> (8 - bitlen))
		return (0);

	return (1);
}

void
in6_prefixlen2mask(struct in6_addr *maskp, int len)
{
	u_char maskarray[8] = {0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};
	int bytelen, bitlen, i;

	/* sanity check */
	if (0 > len || len > 128) {
		log(LOG_ERR, "%s: invalid prefix length(%d)\n", __func__, len);
		return;
	}

	bzero(maskp, sizeof (*maskp));
	bytelen = len / 8;
	bitlen = len % 8;
	for (i = 0; i < bytelen; i++)
		maskp->s6_addr[i] = 0xff;
	if (bitlen)
		maskp->s6_addr[bytelen] = maskarray[bitlen - 1];
}

/*
 * return the best address out of the same scope
 */
struct in6_ifaddr *
in6_ifawithscope(struct ifnet *oifp, struct in6_addr *dst)
{
	int dst_scope =	in6_addrscope(dst), src_scope, best_scope = 0;
	int blen = -1;
	struct ifaddr *ifa;
	struct ifnet *ifp;
	struct in6_ifaddr *ifa_best = NULL;

	if (oifp == NULL) {
		return (NULL);
	}

	/*
	 * We search for all addresses on all interfaces from the beginning.
	 * Comparing an interface with the outgoing interface will be done
	 * only at the final stage of tiebreaking.
	 */
	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_list) {
		/*
		 * We can never take an address that breaks the scope zone
		 * of the destination.
		 */
		if (in6_addr2scopeid(ifp, dst) != in6_addr2scopeid(oifp, dst))
			continue;

		ifnet_lock_shared(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
			int tlen = -1, dscopecmp, bscopecmp, matchcmp;

			IFA_LOCK(ifa);
			if (ifa->ifa_addr->sa_family != AF_INET6) {
				IFA_UNLOCK(ifa);
				continue;
			}
			src_scope = in6_addrscope(IFA_IN6(ifa));

			/*
			 * Don't use an address before completing DAD
			 * nor a duplicated address.
			 */
			if (((struct in6_ifaddr *)ifa)->ia6_flags &
			    IN6_IFF_NOTREADY) {
				IFA_UNLOCK(ifa);
				continue;
			}
			/* XXX: is there any case to allow anycasts? */
			if (((struct in6_ifaddr *)ifa)->ia6_flags &
			    IN6_IFF_ANYCAST) {
				IFA_UNLOCK(ifa);
				continue;
			}
			if (((struct in6_ifaddr *)ifa)->ia6_flags &
			    IN6_IFF_DETACHED) {
				IFA_UNLOCK(ifa);
				continue;
			}
			/*
			 * If this is the first address we find,
			 * keep it anyway.
			 */
			if (ifa_best == NULL)
				goto replace;

			/*
			 * ifa_best is never NULL beyond this line except
			 * within the block labeled "replace".
			 */

			/*
			 * If ifa_best has a smaller scope than dst and
			 * the current address has a larger one than
			 * (or equal to) dst, always replace ifa_best.
			 * Also, if the current address has a smaller scope
			 * than dst, ignore it unless ifa_best also has a
			 * smaller scope.
			 * Consequently, after the two if-clause below,
			 * the followings must be satisfied:
			 * (scope(src) < scope(dst) &&
			 *  scope(best) < scope(dst))
			 *  OR
			 * (scope(best) >= scope(dst) &&
			 *  scope(src) >= scope(dst))
			 */
			if (IN6_ARE_SCOPE_CMP(best_scope, dst_scope) < 0 &&
			    IN6_ARE_SCOPE_CMP(src_scope, dst_scope) >= 0)
				goto replace; /* (A) */
			if (IN6_ARE_SCOPE_CMP(src_scope, dst_scope) < 0 &&
			    IN6_ARE_SCOPE_CMP(best_scope, dst_scope) >= 0) {
				IFA_UNLOCK(ifa);
				continue; /* (B) */
			}
			/*
			 * A deprecated address SHOULD NOT be used in new
			 * communications if an alternate (non-deprecated)
			 * address is available and has sufficient scope.
			 * RFC 4862, Section 5.5.4.
			 */
			if (((struct in6_ifaddr *)ifa)->ia6_flags &
			    IN6_IFF_DEPRECATED) {
				/*
				 * Ignore any deprecated addresses if
				 * specified by configuration.
				 */
				if (!ip6_use_deprecated) {
					IFA_UNLOCK(ifa);
					continue;
				}
				/*
				 * If we have already found a non-deprecated
				 * candidate, just ignore deprecated addresses.
				 */
				if ((ifa_best->ia6_flags & IN6_IFF_DEPRECATED)
				    == 0) {
					IFA_UNLOCK(ifa);
					continue;
				}
			}

			/*
			 * A non-deprecated address is always preferred
			 * to a deprecated one regardless of scopes and
			 * address matching (Note invariants ensured by the
			 * conditions (A) and (B) above.)
			 */
			if ((ifa_best->ia6_flags & IN6_IFF_DEPRECATED) &&
			    (((struct in6_ifaddr *)ifa)->ia6_flags &
			    IN6_IFF_DEPRECATED) == 0)
				goto replace;

			/*
			 * When we use temporary addresses described in
			 * RFC 4941, we prefer temporary addresses to
			 * public autoconf addresses.  Again, note the
			 * invariants from (A) and (B).  Also note that we
			 * don't have any preference between static addresses
			 * and autoconf addresses (despite of whether or not
			 * the latter is temporary or public.)
			 */
			if (ip6_use_tempaddr) {
				struct in6_ifaddr *ifat;

				ifat = (struct in6_ifaddr *)ifa;
				if ((ifa_best->ia6_flags &
				    (IN6_IFF_AUTOCONF|IN6_IFF_TEMPORARY))
				    == IN6_IFF_AUTOCONF &&
				    (ifat->ia6_flags &
				    (IN6_IFF_AUTOCONF|IN6_IFF_TEMPORARY))
				    == (IN6_IFF_AUTOCONF|IN6_IFF_TEMPORARY)) {
					goto replace;
				}
				if ((ifa_best->ia6_flags &
				    (IN6_IFF_AUTOCONF|IN6_IFF_TEMPORARY))
				    == (IN6_IFF_AUTOCONF|IN6_IFF_TEMPORARY) &&
				    (ifat->ia6_flags &
				    (IN6_IFF_AUTOCONF|IN6_IFF_TEMPORARY))
				    == IN6_IFF_AUTOCONF) {
					IFA_UNLOCK(ifa);
					continue;
				}
			}

			/*
			 * At this point, we have two cases:
			 * 1. we are looking at a non-deprecated address,
			 *    and ifa_best is also non-deprecated.
			 * 2. we are looking at a deprecated address,
			 *    and ifa_best is also deprecated.
			 * Also, we do not have to consider a case where
			 * the scope of if_best is larger(smaller) than dst and
			 * the scope of the current address is smaller(larger)
			 * than dst. Such a case has already been covered.
			 * Tiebreaking is done according to the following
			 * items:
			 * - the scope comparison between the address and
			 *   dst (dscopecmp)
			 * - the scope comparison between the address and
			 *   ifa_best (bscopecmp)
			 * - if the address match dst longer than ifa_best
			 *   (matchcmp)
			 * - if the address is on the outgoing I/F (outI/F)
			 *
			 * Roughly speaking, the selection policy is
			 * - the most important item is scope. The same scope
			 *   is best. Then search for a larger scope.
			 *   Smaller scopes are the last resort.
			 * - A deprecated address is chosen only when we have
			 *   no address that has an enough scope, but is
			 *   prefered to any addresses of smaller scopes
			 *   (this must be already done above.)
			 * - addresses on the outgoing I/F are preferred to
			 *   ones on other interfaces if none of above
			 *   tiebreaks.  In the table below, the column "bI"
			 *   means if the best_ifa is on the outgoing
			 *   interface, and the column "sI" means if the ifa
			 *   is on the outgoing interface.
			 * - If there is no other reasons to choose one,
			 *   longest address match against dst is considered.
			 *
			 * The precise decision table is as follows:
			 * dscopecmp bscopecmp  match   bI oI | replace?
			 *   N/A       equal    N/A     Y   N |   No (1)
			 *   N/A       equal    N/A     N   Y |  Yes (2)
			 *   N/A       equal    larger   N/A  |  Yes (3)
			 *   N/A       equal    !larger  N/A  |   No (4)
			 *   larger    larger   N/A      N/A  |   No (5)
			 *   larger    smaller  N/A      N/A  |  Yes (6)
			 *   smaller   larger   N/A      N/A  |  Yes (7)
			 *   smaller   smaller  N/A      N/A  |   No (8)
			 *   equal     smaller  N/A      N/A  |  Yes (9)
			 *   equal     larger   (already done at A above)
			 */
			dscopecmp = IN6_ARE_SCOPE_CMP(src_scope, dst_scope);
			bscopecmp = IN6_ARE_SCOPE_CMP(src_scope, best_scope);

			if (bscopecmp == 0) {
				struct ifnet *bifp = ifa_best->ia_ifp;

				if (bifp == oifp && ifp != oifp) { /* (1) */
					IFA_UNLOCK(ifa);
					continue;
				}
				if (bifp != oifp && ifp == oifp) /* (2) */
					goto replace;

				/*
				 * Both bifp and ifp are on the outgoing
				 * interface, or both two are on a different
				 * interface from the outgoing I/F.
				 * now we need address matching against dst
				 * for tiebreaking.
				 */
				tlen = in6_matchlen(IFA_IN6(ifa), dst);
				matchcmp = tlen - blen;
				if (matchcmp > 0) /* (3) */
					goto replace;
				IFA_UNLOCK(ifa);
				continue; /* (4) */
			}
			if (dscopecmp > 0) {
				if (bscopecmp > 0) { /* (5) */
					IFA_UNLOCK(ifa);
					continue;
				}
				goto replace; /* (6) */
			}
			if (dscopecmp < 0) {
				if (bscopecmp > 0) /* (7) */
					goto replace;
				IFA_UNLOCK(ifa);
				continue; /* (8) */
			}

			/* now dscopecmp must be 0 */
			if (bscopecmp < 0)
				goto replace; /* (9) */

replace:
			IFA_ADDREF_LOCKED(ifa);	/* for ifa_best */
			blen = tlen >= 0 ? tlen :
			    in6_matchlen(IFA_IN6(ifa), dst);
			best_scope =
			    in6_addrscope(&ifa2ia6(ifa)->ia_addr.sin6_addr);
			IFA_UNLOCK(ifa);
			if (ifa_best)
				IFA_REMREF(&ifa_best->ia_ifa);
			ifa_best = (struct in6_ifaddr *)ifa;
		}
		ifnet_lock_done(ifp);
	}
	ifnet_head_done();

	/* count statistics for future improvements */
	if (ifa_best == NULL)
		ip6stat.ip6s_sources_none++;
	else {
		IFA_LOCK_SPIN(&ifa_best->ia_ifa);
		if (oifp == ifa_best->ia_ifp)
			ip6stat.ip6s_sources_sameif[best_scope]++;
		else
			ip6stat.ip6s_sources_otherif[best_scope]++;

		if (best_scope == dst_scope)
			ip6stat.ip6s_sources_samescope[best_scope]++;
		else
			ip6stat.ip6s_sources_otherscope[best_scope]++;

		if ((ifa_best->ia6_flags & IN6_IFF_DEPRECATED) != 0)
			ip6stat.ip6s_sources_deprecated[best_scope]++;
		IFA_UNLOCK(&ifa_best->ia_ifa);
	}

	return (ifa_best);
}

/*
 * return the best address out of the same scope. if no address was
 * found, return the first valid address from designated IF.
 */
struct in6_ifaddr *
in6_ifawithifp(struct ifnet *ifp, struct in6_addr *dst)
{
	int dst_scope =	in6_addrscope(dst), blen = -1, tlen;
	struct ifaddr *ifa;
	struct in6_ifaddr *besta = NULL;
	struct in6_ifaddr *dep[2];	/* last-resort: deprecated */

	dep[0] = dep[1] = NULL;

	/*
	 * We first look for addresses in the same scope.
	 * If there is one, return it.
	 * If two or more, return one which matches the dst longest.
	 * If none, return one of global addresses assigned other ifs.
	 */
	ifnet_lock_shared(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		IFA_LOCK(ifa);
		if (ifa->ifa_addr->sa_family != AF_INET6) {
			IFA_UNLOCK(ifa);
			continue;
		}
		if (ifa2ia6(ifa)->ia6_flags & IN6_IFF_ANYCAST) {
			IFA_UNLOCK(ifa);
			continue; /* XXX: is there any case to allow anycast? */
		}
		if (ifa2ia6(ifa)->ia6_flags & IN6_IFF_NOTREADY) {
			IFA_UNLOCK(ifa);
			continue; /* don't use this interface */
		}
		if (ifa2ia6(ifa)->ia6_flags & IN6_IFF_DETACHED) {
			IFA_UNLOCK(ifa);
			continue;
		}
		if (ifa2ia6(ifa)->ia6_flags & IN6_IFF_DEPRECATED) {
			if (ip6_use_deprecated) {
				IFA_ADDREF_LOCKED(ifa);	/* for dep[0] */
				IFA_UNLOCK(ifa);
				if (dep[0] != NULL)
					IFA_REMREF(&dep[0]->ia_ifa);
				dep[0] = (struct in6_ifaddr *)ifa;
			} else {
				IFA_UNLOCK(ifa);
			}
			continue;
		}

		if (dst_scope == in6_addrscope(IFA_IN6(ifa))) {
			/*
			 * call in6_matchlen() as few as possible
			 */
			if (besta) {
				if (blen == -1) {
					IFA_UNLOCK(ifa);
					IFA_LOCK(&besta->ia_ifa);
					blen = in6_matchlen(
					    &besta->ia_addr.sin6_addr, dst);
					IFA_UNLOCK(&besta->ia_ifa);
					IFA_LOCK(ifa);
				}
				tlen = in6_matchlen(IFA_IN6(ifa), dst);
				if (tlen > blen) {
					blen = tlen;
					IFA_ADDREF_LOCKED(ifa);	/* for besta */
					IFA_UNLOCK(ifa);
					IFA_REMREF(&besta->ia_ifa);
					besta = (struct in6_ifaddr *)ifa;
				} else {
					IFA_UNLOCK(ifa);
				}
			} else {
				besta = (struct in6_ifaddr *)ifa;
				IFA_ADDREF_LOCKED(ifa);	/* for besta */
				IFA_UNLOCK(ifa);
			}
		} else {
			IFA_UNLOCK(ifa);
		}
	}
	if (besta) {
		ifnet_lock_done(ifp);
		if (dep[0] != NULL)
			IFA_REMREF(&dep[0]->ia_ifa);
		return (besta);
	}

	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		IFA_LOCK(ifa);
		if (ifa->ifa_addr->sa_family != AF_INET6) {
			IFA_UNLOCK(ifa);
			continue;
		}
		if (ifa2ia6(ifa)->ia6_flags & IN6_IFF_ANYCAST) {
			IFA_UNLOCK(ifa);
			continue; /* XXX: is there any case to allow anycast? */
		}
		if (ifa2ia6(ifa)->ia6_flags & IN6_IFF_NOTREADY) {
			IFA_UNLOCK(ifa);
			continue; /* don't use this interface */
		}
		if (ifa2ia6(ifa)->ia6_flags & IN6_IFF_DETACHED) {
			IFA_UNLOCK(ifa);
			continue;
		}
		if (ifa2ia6(ifa)->ia6_flags & IN6_IFF_DEPRECATED) {
			if (ip6_use_deprecated) {
				IFA_ADDREF_LOCKED(ifa);	/* for dep[1] */
				IFA_UNLOCK(ifa);
				if (dep[1] != NULL)
					IFA_REMREF(&dep[1]->ia_ifa);
				dep[1] = (struct in6_ifaddr *)ifa;
			} else {
				IFA_UNLOCK(ifa);
			}
			continue;
		}
		IFA_ADDREF_LOCKED(ifa);	/* for caller */
		IFA_UNLOCK(ifa);
		ifnet_lock_done(ifp);
		if (dep[0] != NULL)
			IFA_REMREF(&dep[0]->ia_ifa);
		if (dep[1] != NULL)
			IFA_REMREF(&dep[1]->ia_ifa);
		return ((struct in6_ifaddr *)ifa);
	}
	ifnet_lock_done(ifp);

	/* use the last-resort values, that are, deprecated addresses */
	if (dep[0]) {
		if (dep[1] != NULL)
			IFA_REMREF(&dep[1]->ia_ifa);
		return (dep[0]);
	}
	if (dep[1])
		return (dep[1]);

	return (NULL);
}

/*
 * perform DAD when interface becomes IFF_UP.
 */
static void
in6_if_up_dad_start(struct ifnet *ifp)
{
	struct ifaddr *ifa;
	struct nd_ifinfo *ndi = NULL;

	ndi = ND_IFINFO(ifp);
	VERIFY((NULL != ndi)  && (TRUE == ndi->initialized));
	if (!(ndi->flags & ND6_IFF_DAD))
		return;

	/* start DAD on all the interface addresses */
	ifnet_lock_exclusive(ifp);
	TAILQ_FOREACH(ifa, &ifp->if_addrlist, ifa_list) {
		struct in6_ifaddr *ia6;

		IFA_LOCK_SPIN(ifa);
		if (ifa->ifa_addr->sa_family != AF_INET6) {
			IFA_UNLOCK(ifa);
			continue;
		}
		ia6 = (struct in6_ifaddr *)ifa;
		if (ia6->ia6_flags & IN6_IFF_DADPROGRESS) {
			int delay = 0;	/* delay ticks before DAD output */
			IFA_UNLOCK(ifa);
			nd6_dad_start(ifa, &delay);
		} else {
			IFA_UNLOCK(ifa);
		}
	}
	ifnet_lock_done(ifp);
}

int
in6if_do_dad(
	struct ifnet *ifp)
{
	struct nd_ifinfo *ndi = NULL;

	if ((ifp->if_flags & IFF_LOOPBACK) != 0)
		return (0);

	ndi = ND_IFINFO(ifp);
	VERIFY((NULL != ndi)  && (TRUE == ndi->initialized));
	if (!(ndi->flags & ND6_IFF_DAD))
		return (0);

	/*
	 * If we are using the alternative neighbor discovery
	 * interface on this interface, then skip DAD.
	 *
	 * Also, skip it for interfaces marked "local private"
	 * for now, even when not marked as using the alternative
	 * interface.  This is for historical reasons.
	 */
	if (ifp->if_eflags & 
	    (IFEF_IPV6_ND6ALT|IFEF_LOCALNET_PRIVATE|IFEF_DIRECTLINK))
		return (0);

	switch (ifp->if_type) {
#if IFT_DUMMY
	case IFT_DUMMY:
#endif
	case IFT_FAITH:
		/*
		 * These interfaces do not have the IFF_LOOPBACK flag,
		 * but loop packets back.  We do not have to do DAD on such
		 * interfaces.  We should even omit it, because loop-backed
		 * NS would confuse the DAD procedure.
		 */
		return (0);
	default:
		/*
		 * Our DAD routine requires the interface up and running.
		 * However, some interfaces can be up before the RUNNING
		 * status.  Additionaly, users may try to assign addresses
		 * before the interface becomes up (or running).
		 * We simply skip DAD in such a case as a work around.
		 * XXX: we should rather mark "tentative" on such addresses,
		 * and do DAD after the interface becomes ready.
		 */
		if ((ifp->if_flags & (IFF_UP|IFF_RUNNING)) !=
		    (IFF_UP|IFF_RUNNING))
			return (0);

		return (1);
	}
}

/*
 * Calculate max IPv6 MTU through all the interfaces and store it
 * to in6_maxmtu.
 */
void
in6_setmaxmtu(void)
{
	u_int32_t maxmtu = 0;
	struct ifnet *ifp;

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_list) {
		struct nd_ifinfo *ndi = NULL;

		if ((ndi = ND_IFINFO(ifp)) != NULL && !ndi->initialized)
			ndi = NULL;
		if (ndi != NULL)
			lck_mtx_lock(&ndi->lock);
		if ((ifp->if_flags & IFF_LOOPBACK) == 0 &&
		    IN6_LINKMTU(ifp) > maxmtu)
			maxmtu = IN6_LINKMTU(ifp);
		if (ndi != NULL)
			lck_mtx_unlock(&ndi->lock);
	}
	ifnet_head_done();
	if (maxmtu)	/* update only when maxmtu is positive */
		in6_maxmtu = maxmtu;
}
/*
 * Provide the length of interface identifiers to be used for the link attached
 * to the given interface.  The length should be defined in "IPv6 over
 * xxx-link" document.  Note that address architecture might also define
 * the length for a particular set of address prefixes, regardless of the
 * link type.  Also see RFC 4862 for additional background.
 */
int
in6_if2idlen(struct ifnet *ifp)
{
	switch (ifp->if_type) {
	case IFT_ETHER:		/* RFC2464 */
	case IFT_IEEE8023ADLAG:	/* IEEE802.3ad Link Aggregate */
#ifdef IFT_PROPVIRTUAL
	case IFT_PROPVIRTUAL:	/* XXX: no RFC. treat it as ether */
#endif
#ifdef IFT_L2VLAN
	case IFT_L2VLAN:	/* ditto */
#endif
#ifdef IFT_IEEE80211
	case IFT_IEEE80211:	/* ditto */
#endif
#ifdef IFT_MIP
	case IFT_MIP:	/* ditto */
#endif
		return (64);
	case IFT_FDDI:		/* RFC2467 */
		return (64);
	case IFT_ISO88025:	/* RFC2470 (IPv6 over Token Ring) */
		return (64);
	case IFT_PPP:		/* RFC2472 */
		return (64);
	case IFT_ARCNET:	/* RFC2497 */
		return (64);
	case IFT_FRELAY:	/* RFC2590 */
		return (64);
	case IFT_IEEE1394:	/* RFC3146 */
		return (64);
	case IFT_GIF:
		return (64);	/* draft-ietf-v6ops-mech-v2-07 */
	case IFT_LOOP:
		return (64);	/* XXX: is this really correct? */
	case IFT_OTHER:
		return (64);	/* for utun interfaces */
	case IFT_CELLULAR:
		return (64);	/* Packet Data over Cellular */
	case IFT_BRIDGE:
		return (64);	/* Transparent bridge interface */
	default:
		/*
		 * Unknown link type:
		 * It might be controversial to use the today's common constant
		 * of 64 for these cases unconditionally.  For full compliance,
		 * we should return an error in this case.  On the other hand,
		 * if we simply miss the standard for the link type or a new
		 * standard is defined for a new link type, the IFID length
		 * is very likely to be the common constant.  As a compromise,
		 * we always use the constant, but make an explicit notice
		 * indicating the "unknown" case.
		 */
		log(LOG_NOTICE, "%s: unknown link type (%d)\n", __func__,
		    ifp->if_type);
		return (64);
	}
}
/*
 * Convert sockaddr_in6 to sockaddr_in.  Original sockaddr_in6 must be
 * v4 mapped addr or v4 compat addr
 */
void
in6_sin6_2_sin(struct sockaddr_in *sin, struct sockaddr_in6 *sin6)
{
	bzero(sin, sizeof (*sin));
	sin->sin_len = sizeof (struct sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_port = sin6->sin6_port;
	sin->sin_addr.s_addr = sin6->sin6_addr.s6_addr32[3];
}

/* Convert sockaddr_in to sockaddr_in6 in v4 mapped addr format. */
void
in6_sin_2_v4mapsin6(struct sockaddr_in *sin, struct sockaddr_in6 *sin6)
{
	bzero(sin6, sizeof (*sin6));
	sin6->sin6_len = sizeof (struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = sin->sin_port;
	sin6->sin6_addr.s6_addr32[0] = 0;
	sin6->sin6_addr.s6_addr32[1] = 0;
	if (sin->sin_addr.s_addr) {
		sin6->sin6_addr.s6_addr32[2] = IPV6_ADDR_INT32_SMP;
		sin6->sin6_addr.s6_addr32[3] = sin->sin_addr.s_addr;
	} else {
		sin6->sin6_addr.s6_addr32[2] = 0;
		sin6->sin6_addr.s6_addr32[3] = 0;
	}
}

/* Convert sockaddr_in6 into sockaddr_in. */
void
in6_sin6_2_sin_in_sock(struct sockaddr *nam)
{
	struct sockaddr_in *sin_p;
	struct sockaddr_in6 sin6;

	/*
	 * Save original sockaddr_in6 addr and convert it
	 * to sockaddr_in.
	 */
	sin6 = *(struct sockaddr_in6 *)(void *)nam;
	sin_p = (struct sockaddr_in *)(void *)nam;
	in6_sin6_2_sin(sin_p, &sin6);
}

/* Convert sockaddr_in into sockaddr_in6 in v4 mapped addr format. */
int
in6_sin_2_v4mapsin6_in_sock(struct sockaddr **nam)
{
	struct sockaddr_in *sin_p;
	struct sockaddr_in6 *sin6_p;

	MALLOC(sin6_p, struct sockaddr_in6 *, sizeof (*sin6_p), M_SONAME,
	    M_WAITOK);
	if (sin6_p == NULL)
		return (ENOBUFS);
	sin_p = (struct sockaddr_in *)(void *)*nam;
	in6_sin_2_v4mapsin6(sin_p, sin6_p);
	FREE(*nam, M_SONAME);
	*nam = (struct sockaddr *)sin6_p;

	return (0);
}

/*
 * Posts in6_event_data message kernel events.
 *
 * To get the same size of kev_in6_data between ILP32 and LP64 data models
 * we are using a special version of the in6_addrlifetime structure that
 * uses only 32 bits fields to be compatible with Leopard, and that
 * are large enough to span 68 years.
 */
void
in6_post_msg(struct ifnet *ifp, u_int32_t event_code, struct in6_ifaddr *ifa,
    uint8_t *mac)
{
	struct kev_msg ev_msg;
	struct kev_in6_data in6_event_data;
	struct in6_addrlifetime ia6_lt;

	bzero(&in6_event_data, sizeof (struct kev_in6_data));
	bzero(&ev_msg, sizeof (struct kev_msg));
	ev_msg.vendor_code	= KEV_VENDOR_APPLE;
	ev_msg.kev_class	= KEV_NETWORK_CLASS;
	ev_msg.kev_subclass	= KEV_INET6_SUBCLASS;
	ev_msg.event_code	= event_code;

	IFA_LOCK(&ifa->ia_ifa);
	in6_event_data.ia_addr		= ifa->ia_addr;
	in6_event_data.ia_net		= ifa->ia_net;
	in6_event_data.ia_dstaddr	= ifa->ia_dstaddr;
	in6_event_data.ia_prefixmask	= ifa->ia_prefixmask;
	in6_event_data.ia_plen		= ifa->ia_plen;
	in6_event_data.ia6_flags	= (u_int32_t)ifa->ia6_flags;

	/* retrieve time as calendar time (last arg is 1) */
	in6ifa_getlifetime(ifa, &ia6_lt, 1);
	in6_event_data.ia_lifetime.ia6t_expire = ia6_lt.ia6t_expire;
	in6_event_data.ia_lifetime.ia6t_preferred = ia6_lt.ia6t_preferred;
	in6_event_data.ia_lifetime.ia6t_vltime = ia6_lt.ia6t_vltime;
	in6_event_data.ia_lifetime.ia6t_pltime = ia6_lt.ia6t_pltime;
	IFA_UNLOCK(&ifa->ia_ifa);

	if (ifp != NULL) {
		(void) strlcpy(&in6_event_data.link_data.if_name[0],
		    ifp->if_name, IFNAMSIZ);
		in6_event_data.link_data.if_family = ifp->if_family;
		in6_event_data.link_data.if_unit  = (u_int32_t)ifp->if_unit;
	}

	if (mac != NULL)
		memcpy(&in6_event_data.ia_mac, mac, 
		    sizeof(in6_event_data.ia_mac));

	ev_msg.dv[0].data_ptr    = &in6_event_data;
	ev_msg.dv[0].data_length = sizeof (in6_event_data);
	ev_msg.dv[1].data_length = 0;

	dlil_post_complete_msg(NULL, &ev_msg);
}

/*
 * Called as part of ip6_init
 */
void
in6_ifaddr_init(void)
{
	in6_cga_init();
	in6_multi_init();

	PE_parse_boot_argn("ifa_debug", &in6ifa_debug, sizeof (in6ifa_debug));

	in6ifa_size = (in6ifa_debug == 0) ? sizeof (struct in6_ifaddr) :
	    sizeof (struct in6_ifaddr_dbg);

	in6ifa_zone = zinit(in6ifa_size, IN6IFA_ZONE_MAX * in6ifa_size,
	    0, IN6IFA_ZONE_NAME);
	if (in6ifa_zone == NULL) {
		panic("%s: failed allocating %s", __func__, IN6IFA_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(in6ifa_zone, Z_EXPAND, TRUE);
	zone_change(in6ifa_zone, Z_CALLERACCT, FALSE);

	lck_mtx_init(&in6ifa_trash_lock, ifa_mtx_grp, ifa_mtx_attr);
	TAILQ_INIT(&in6ifa_trash_head);
}

static struct in6_ifaddr *
in6_ifaddr_alloc(int how)
{
	struct in6_ifaddr *in6ifa;

	in6ifa = (how == M_WAITOK) ? zalloc(in6ifa_zone) :
	    zalloc_noblock(in6ifa_zone);
	if (in6ifa != NULL) {
		bzero(in6ifa, in6ifa_size);
		in6ifa->ia_ifa.ifa_free = in6_ifaddr_free;
		in6ifa->ia_ifa.ifa_debug |= IFD_ALLOC;
		ifa_lock_init(&in6ifa->ia_ifa);
		if (in6ifa_debug != 0) {
			struct in6_ifaddr_dbg *in6ifa_dbg =
			    (struct in6_ifaddr_dbg *)in6ifa;
			in6ifa->ia_ifa.ifa_debug |= IFD_DEBUG;
			in6ifa->ia_ifa.ifa_trace = in6_ifaddr_trace;
			in6ifa->ia_ifa.ifa_attached = in6_ifaddr_attached;
			in6ifa->ia_ifa.ifa_detached = in6_ifaddr_detached;
			ctrace_record(&in6ifa_dbg->in6ifa_alloc);
		}
	}

	return (in6ifa);
}

static void
in6_ifaddr_free(struct ifaddr *ifa)
{
	IFA_LOCK_ASSERT_HELD(ifa);

	if (ifa->ifa_refcnt != 0) {
		panic("%s: ifa %p bad ref cnt", __func__, ifa);
		/* NOTREACHED */
	} else if (!(ifa->ifa_debug & IFD_ALLOC)) {
		panic("%s: ifa %p cannot be freed", __func__, ifa);
		/* NOTREACHED */
	}
	if (ifa->ifa_debug & IFD_DEBUG) {
		struct in6_ifaddr_dbg *in6ifa_dbg =
		    (struct in6_ifaddr_dbg *)ifa;
		ctrace_record(&in6ifa_dbg->in6ifa_free);
		bcopy(&in6ifa_dbg->in6ifa, &in6ifa_dbg->in6ifa_old,
		    sizeof (struct in6_ifaddr));
		if (ifa->ifa_debug & IFD_TRASHED) {
			/* Become a regular mutex, just in case */
			IFA_CONVERT_LOCK(ifa);
			lck_mtx_lock(&in6ifa_trash_lock);
			TAILQ_REMOVE(&in6ifa_trash_head, in6ifa_dbg,
			    in6ifa_trash_link);
			lck_mtx_unlock(&in6ifa_trash_lock);
			ifa->ifa_debug &= ~IFD_TRASHED;
		}
	}
	IFA_UNLOCK(ifa);
	ifa_lock_destroy(ifa);
	bzero(ifa, sizeof (struct in6_ifaddr));
	zfree(in6ifa_zone, ifa);
}

static void
in6_ifaddr_attached(struct ifaddr *ifa)
{
	struct in6_ifaddr_dbg *in6ifa_dbg = (struct in6_ifaddr_dbg *)ifa;

	IFA_LOCK_ASSERT_HELD(ifa);

	if (!(ifa->ifa_debug & IFD_DEBUG)) {
		panic("%s: ifa %p has no debug structure", __func__, ifa);
		/* NOTREACHED */
	}
	if (ifa->ifa_debug & IFD_TRASHED) {
		/* Become a regular mutex, just in case */
		IFA_CONVERT_LOCK(ifa);
		lck_mtx_lock(&in6ifa_trash_lock);
		TAILQ_REMOVE(&in6ifa_trash_head, in6ifa_dbg, in6ifa_trash_link);
		lck_mtx_unlock(&in6ifa_trash_lock);
		ifa->ifa_debug &= ~IFD_TRASHED;
	}
}

static void
in6_ifaddr_detached(struct ifaddr *ifa)
{
	struct in6_ifaddr_dbg *in6ifa_dbg = (struct in6_ifaddr_dbg *)ifa;

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
	lck_mtx_lock(&in6ifa_trash_lock);
	TAILQ_INSERT_TAIL(&in6ifa_trash_head, in6ifa_dbg, in6ifa_trash_link);
	lck_mtx_unlock(&in6ifa_trash_lock);
}

static void
in6_ifaddr_trace(struct ifaddr *ifa, int refhold)
{
	struct in6_ifaddr_dbg *in6ifa_dbg = (struct in6_ifaddr_dbg *)ifa;
	ctrace_t *tr;
	u_int32_t idx;
	u_int16_t *cnt;

	if (!(ifa->ifa_debug & IFD_DEBUG)) {
		panic("%s: ifa %p has no debug structure", __func__, ifa);
		/* NOTREACHED */
	}
	if (refhold) {
		cnt = &in6ifa_dbg->in6ifa_refhold_cnt;
		tr = in6ifa_dbg->in6ifa_refhold;
	} else {
		cnt = &in6ifa_dbg->in6ifa_refrele_cnt;
		tr = in6ifa_dbg->in6ifa_refrele;
	}

	idx = atomic_add_16_ov(cnt, 1) % IN6IFA_TRACE_HIST_SIZE;
	ctrace_record(&tr[idx]);
}

/*
 * Handle SIOCGASSOCIDS ioctl for PF_INET6 domain.
 */
static int
in6_getassocids(struct socket *so, uint32_t *cnt, user_addr_t aidp)
{
	struct in6pcb *in6p = sotoin6pcb(so);
	sae_associd_t aid;

	if (in6p == NULL || in6p->inp_state == INPCB_STATE_DEAD)
		return (EINVAL);

	/* IN6PCB has no concept of association */
	aid = SAE_ASSOCID_ANY;
	*cnt = 0;

	/* just asking how many there are? */
	if (aidp == USER_ADDR_NULL)
		return (0);

	return (copyout(&aid, aidp, sizeof (aid)));
}

/*
 * Handle SIOCGCONNIDS ioctl for PF_INET6 domain.
 */
static int
in6_getconnids(struct socket *so, sae_associd_t aid, uint32_t *cnt,
    user_addr_t cidp)
{
	struct in6pcb *in6p = sotoin6pcb(so);
	sae_connid_t cid;

	if (in6p == NULL || in6p->inp_state == INPCB_STATE_DEAD)
		return (EINVAL);

	if (aid != SAE_ASSOCID_ANY && aid != SAE_ASSOCID_ALL)
		return (EINVAL);

	/* if connected, return 1 connection count */
	*cnt = ((so->so_state & SS_ISCONNECTED) ? 1 : 0);

	/* just asking how many there are? */
	if (cidp == USER_ADDR_NULL)
		return (0);

	/* if IN6PCB is connected, assign it connid 1 */
	cid = ((*cnt != 0) ? 1 : SAE_CONNID_ANY);

	return (copyout(&cid, cidp, sizeof (cid)));
}

/*
 * Handle SIOCGCONNINFO ioctl for PF_INET6 domain.
 */
static int
in6_getconninfo(struct socket *so, sae_connid_t cid, uint32_t *flags,
    uint32_t *ifindex, int32_t *soerror, user_addr_t src, socklen_t *src_len,
    user_addr_t dst, socklen_t *dst_len, uint32_t *aux_type,
    user_addr_t aux_data, uint32_t *aux_len)
{
#pragma unused(aux_data)
	struct in6pcb *in6p = sotoin6pcb(so);
	struct sockaddr_in6 sin6;
	struct ifnet *ifp = NULL;
	int error = 0;
	u_int32_t copy_len = 0;

	/*
	 * Don't test for INPCB_STATE_DEAD since this may be called
	 * after SOF_PCBCLEARING is set, e.g. after tcp_close().
	 */
	if (in6p == NULL) {
		error = EINVAL;
		goto out;
	}

	if (cid != SAE_CONNID_ANY && cid != SAE_CONNID_ALL && cid != 1) {
		error = EINVAL;
		goto out;
	}

	ifp = in6p->in6p_last_outifp;
	*ifindex = ((ifp != NULL) ? ifp->if_index : 0);
	*soerror = so->so_error;
	*flags = 0;
	if (so->so_state & SS_ISCONNECTED)
		*flags |= (CIF_CONNECTED | CIF_PREFERRED);
	if (in6p->in6p_flags & INP_BOUND_IF)
		*flags |= CIF_BOUND_IF;
	if (!(in6p->in6p_flags & INP_IN6ADDR_ANY))
		*flags |= CIF_BOUND_IP;
	if (!(in6p->in6p_flags & INP_ANONPORT))
		*flags |= CIF_BOUND_PORT;

	bzero(&sin6, sizeof (sin6));
	sin6.sin6_len = sizeof (sin6);
	sin6.sin6_family = AF_INET6;

	/* source address and port */
	sin6.sin6_port = in6p->in6p_lport;
	in6_recoverscope(&sin6, &in6p->in6p_laddr, NULL);
	if (*src_len == 0) {
		*src_len = sin6.sin6_len;
	} else {
		if (src != USER_ADDR_NULL) {
			copy_len = min(*src_len, sizeof (sin6));
			error = copyout(&sin6, src, copy_len);
			if (error != 0)
				goto out;
			*src_len = copy_len;
		}
	}

	/* destination address and port */
	sin6.sin6_port = in6p->in6p_fport;
	in6_recoverscope(&sin6, &in6p->in6p_faddr, NULL);
	if (*dst_len == 0) {
		*dst_len = sin6.sin6_len;
	} else {
		if (dst != USER_ADDR_NULL) {
			copy_len = min(*dst_len, sizeof (sin6));
			error = copyout(&sin6, dst, copy_len);
			if (error != 0)
				goto out;
			*dst_len = copy_len;
		}
	}

	*aux_type = 0;
	*aux_len = 0;
	if (SOCK_PROTO(so) == IPPROTO_TCP) {
		struct conninfo_tcp tcp_ci;

		*aux_type = CIAUX_TCP;
		if (*aux_len == 0) {
			*aux_len = sizeof (tcp_ci);
		} else {
			if (aux_data != USER_ADDR_NULL) {
				copy_len = min(*aux_len, sizeof (tcp_ci));
				bzero(&tcp_ci, sizeof (tcp_ci));
				tcp_getconninfo(so, &tcp_ci);
				error = copyout(&tcp_ci, aux_data, copy_len);
				if (error != 0)
					goto out;
				*aux_len = copy_len;
			}
		}
	}

out:
	return (error);
}

/*
 * 'u' group ioctls.
 *
 * The switch statement below does nothing at runtime, as it serves as a
 * compile time check to ensure that all of the socket 'u' ioctls (those
 * in the 'u' group going thru soo_ioctl) that are made available by the
 * networking stack is unique.  This works as long as this routine gets
 * updated each time a new interface ioctl gets added.
 *
 * Any failures at compile time indicates duplicated ioctl values.
 */
static __attribute__((unused)) void
in6ioctl_cassert(void)
{
	/*
	 * This is equivalent to _CASSERT() and the compiler wouldn't
	 * generate any instructions, thus for compile time only.
	 */
	switch ((u_long)0) {
	case 0:

	/* bsd/netinet6/in6_var.h */
	case SIOCAADDRCTL_POLICY:
	case SIOCDADDRCTL_POLICY:
	case SIOCDRADD_IN6_32:
	case SIOCDRADD_IN6_64:
	case SIOCDRDEL_IN6_32:
	case SIOCDRDEL_IN6_64:
		;
	}
}
