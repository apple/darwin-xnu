/*	$KAME: in6_src.c,v 1.10 2000/03/28 09:02:23 k-sugyou Exp $	*/

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

/* for MIP6 */
#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#endif

#ifdef __NetBSD__
#include "opt_ipsec.h"
#endif

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 4)
#include <sys/ioctl.h>
#endif
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/proc.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#if !(defined(__OpenBSD__) || (defined(__bsdi__) && _BSDI_VERSION >= 199802))
#include <netinet6/in6_pcb.h>
#endif
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>

#include <net/net_osdep.h>

#ifndef __bsdi__
#include "loop.h"
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__)
extern struct ifnet loif[NLOOP];
#endif

#if MIP6
#include <netinet6/mip6.h>
#include <netinet6/mip6_common.h>

extern struct nd_prefix *(*mip6_get_home_prefix_hook) __P((void));
#endif

/*
 * Return an IPv6 address, which is the most appropriate for given
 * destination and user specified options.
 * If necessary, this function lookups the routing table and return
 * an entry to the caller for later use.
 */
struct in6_addr *
in6_selectsrc(dstsock, opts, mopts, ro, laddr, errorp)
	struct sockaddr_in6 *dstsock;
	struct ip6_pktopts *opts;
	struct ip6_moptions *mopts;
	struct route_in6 *ro;
	struct in6_addr *laddr;
	int *errorp;
{
	struct in6_addr *dst;
	struct in6_ifaddr *ia6 = 0;
	struct in6_pktinfo *pi = NULL;

	dst = &dstsock->sin6_addr;
	*errorp = 0;

	/*
	 * If the source address is explicitly specified by the caller,
	 * use it.
	 */
	if (opts && (pi = opts->ip6po_pktinfo) &&
	    !IN6_IS_ADDR_UNSPECIFIED(&pi->ipi6_addr))
		return(&pi->ipi6_addr);

	/*
	 * If the source address is not specified but the socket(if any)
	 * is already bound, use the bound address.
	 */
	if (laddr && !IN6_IS_ADDR_UNSPECIFIED(laddr))
		return(laddr);

	/*
	 * If the caller doesn't specify the source address but
	 * the outgoing interface, use an address associated with
	 * the interface.
	 */
	if (pi && pi->ipi6_ifindex) {
		/* XXX boundary check is assumed to be already done. */
		ia6 = in6_ifawithscope(ifindex2ifnet[pi->ipi6_ifindex],
				       dst);
		if (ia6 == 0) {
			*errorp = EADDRNOTAVAIL;
			return(0);
		}
		return(&satosin6(&ia6->ia_addr)->sin6_addr);
	}

	/*
	 * If the destination address is a link-local unicast address or
	 * a multicast address, and if the outgoing interface is specified
	 * by the sin6_scope_id filed, use an address associated with the
	 * interface.
	 * XXX: We're now trying to define more specific semantics of
	 *      sin6_scope_id field, so this part will be rewritten in
	 *      the near future.
	 */
	if ((IN6_IS_ADDR_LINKLOCAL(dst) || IN6_IS_ADDR_MULTICAST(dst)) &&
	    dstsock->sin6_scope_id) {
		/*
		 * I'm not sure if boundary check for scope_id is done
		 * somewhere...
		 */
		if (dstsock->sin6_scope_id < 0 ||
		    if_index < dstsock->sin6_scope_id) {
			*errorp = ENXIO; /* XXX: better error? */
			return(0);
		}
		ia6 = in6_ifawithscope(ifindex2ifnet[dstsock->sin6_scope_id],
				       dst);
		if (ia6 == 0) {
			*errorp = EADDRNOTAVAIL;
			return(0);
		}
		return(&satosin6(&ia6->ia_addr)->sin6_addr);
	}

	/*
	 * If the destination address is a multicast address and
	 * the outgoing interface for the address is specified
	 * by the caller, use an address associated with the interface.
	 * There is a sanity check here; if the destination has node-local
	 * scope, the outgoing interfacde should be a loopback address.
	 * Even if the outgoing interface is not specified, we also
	 * choose a loopback interface as the outgoing interface.
	 */
	if (IN6_IS_ADDR_MULTICAST(dst)) {
		struct ifnet *ifp = mopts ? mopts->im6o_multicast_ifp : NULL;
#ifdef __bsdi__
#if _BSDI_VERSION >= 199802
		extern struct ifnet *loifp;
#else
		extern struct ifnet loif;
		struct ifnet *loifp = &loif;
#endif
#endif

		if (ifp == NULL && IN6_IS_ADDR_MC_NODELOCAL(dst)) {
#ifdef __bsdi__
			ifp = loifp;
#else
			ifp = &loif[0];
#endif
		}

		if (ifp) {
			ia6 = in6_ifawithscope(ifp, dst);
			if (ia6 == 0) {
				*errorp = EADDRNOTAVAIL;
				return(0);
			}
			return(&satosin6(&ia6->ia_addr)->sin6_addr);
		}
	}

	/*
	 * If the next hop address for the packet is specified
	 * by caller, use an address associated with the route
	 * to the next hop.
	 */
	{
		struct sockaddr_in6 *sin6_next;
		struct rtentry *rt;

		if (opts && opts->ip6po_nexthop) {
			sin6_next = satosin6(opts->ip6po_nexthop);
			rt = nd6_lookup(&sin6_next->sin6_addr, 1, NULL);
			if (rt) {
				ia6 = in6_ifawithscope(rt->rt_ifp, dst);
				if (ia6 == 0)
					ia6 = ifatoia6(rt->rt_ifa);
			}
			if (ia6 == 0) {
				*errorp = EADDRNOTAVAIL;
				return(0);
			}
			return(&satosin6(&ia6->ia_addr)->sin6_addr);
		}
	}

#if MIP6
	/*
	 * This is needed to assure that the Home Address is used for
	 * outgoing packets when not at home. We can't choose any other
	 * address if we want to keep connections up during movement.
	 */
	if (mip6_get_home_prefix_hook) {	/* Only Mobile Node */
		struct nd_prefix *pr;
		if ((pr = (*mip6_get_home_prefix_hook)()) &&
		    !IN6_IS_ADDR_UNSPECIFIED(&pr->ndpr_addr)) {
			if (in6_addrscope(dst) ==
			    in6_addrscope(&pr->ndpr_addr)) {
#if MIP6_DEBUG
				/* Noisy but useful */
				mip6_debug("%s: Local address %s is chosen "
					   "for pcb to dest %s.\n",
					   __FUNCTION__,
					   ip6_sprintf(&pr->ndpr_addr),
					   ip6_sprintf(dst));
#endif
				return(&pr->ndpr_addr);
			}
		}
	}
#endif /* MIP6 */

	/*
	 * If route is known or can be allocated now,
	 * our src addr is taken from the i/f, else punt.
	 */
	if (ro) {
		if (ro->ro_rt &&
		    !IN6_ARE_ADDR_EQUAL(&satosin6(&ro->ro_dst)->sin6_addr, dst)) {
			RTFREE(ro->ro_rt);
			ro->ro_rt = (struct rtentry *)0;
		}
		if (ro->ro_rt == (struct rtentry *)0 ||
		    ro->ro_rt->rt_ifp == (struct ifnet *)0) {
			/* No route yet, so try to acquire one */
			bzero(&ro->ro_dst, sizeof(struct sockaddr_in6));
			ro->ro_dst.sin6_family = AF_INET6;
			ro->ro_dst.sin6_len = sizeof(struct sockaddr_in6);
			ro->ro_dst.sin6_addr = *dst;
			if (IN6_IS_ADDR_MULTICAST(dst)) {
#if defined( __FreeBSD__) || defined (__APPLE__)
				ro->ro_rt = rtalloc1(&((struct route *)ro)
						     ->ro_dst, 0, 0UL);
#else
				ro->ro_rt = rtalloc1(&((struct route *)ro)
						     ->ro_dst, 0);
#endif /*__FreeBSD__*/
			} else {
#ifdef __bsdi__  /* bsdi needs rtcalloc to make a host route */
				rtcalloc((struct route *)ro);
#else
				rtalloc((struct route *)ro);
#endif
			}
		}

		/*
		 * in_pcbconnect() checks out IFF_LOOPBACK to skip using
		 * the address. But we don't know why it does so.
		 * It is necessary to ensure the scope even for lo0
		 * so doesn't check out IFF_LOOPBACK.
		 */

		if (ro->ro_rt) {
			ia6 = in6_ifawithscope(ro->ro_rt->rt_ifa->ifa_ifp, dst);
			if (ia6 == 0) /* xxx scope error ?*/
				ia6 = ifatoia6(ro->ro_rt->rt_ifa);
		}
#if 0
		/*
		 * xxx The followings are necessary? (kazu)
		 * I don't think so.
		 * It's for SO_DONTROUTE option in IPv4.(jinmei)
		 */
		if (ia6 == 0) {
			struct sockaddr_in6 sin6 = {sizeof(sin6), AF_INET6, 0};

			sin6->sin6_addr = *dst;

			ia6 = ifatoia6(ifa_ifwithdstaddr(sin6tosa(&sin6)));
			if (ia6 == 0)
				ia6 = ifatoia6(ifa_ifwithnet(sin6tosa(&sin6)));
			if (ia6 == 0)
				return(0);
			return(&satosin6(&ia6->ia_addr)->sin6_addr);
		}
#endif /* 0 */
		if (ia6 == 0) {
			*errorp = EHOSTUNREACH;	/* no route */
			return(0);
		}
		return(&satosin6(&ia6->ia_addr)->sin6_addr);
	}

	*errorp = EADDRNOTAVAIL;
	return(0);
}

/*
 * Default hop limit selection. The precedence is as follows:
 * 1. Hoplimit value specified via ioctl.
 * 2. (If the outgoing interface is detected) the current
 *     hop limit of the interface specified by router advertisement.
 * 3. The system default hoplimit.
*/
#if HAVE_NRL_INPCB
#define in6pcb		inpcb
#define in6p_hops	inp_hops	
#endif
int
in6_selecthlim(in6p, ifp)
	struct in6pcb *in6p;
	struct ifnet *ifp;
{
	if (in6p && in6p->in6p_hops >= 0)
		return(in6p->in6p_hops);
	else if (ifp)
		return(nd_ifinfo[ifp->if_index].chlim);
	else
		return(ip6_defhlim);
}
#if HAVE_NRL_INPCB
#undef in6pcb
#undef in6p_hops
#endif

#if !(defined(__FreeBSD__) && __FreeBSD__ >= 3) && !defined(__OpenBSD__) && !defined(__APPLE__)
/*
 * Find an empty port and set it to the specified PCB.
 */
#if HAVE_NRL_INPCB	/* XXX: I really hate such ugly macros...(jinmei) */
#define in6pcb		inpcb
#define in6p_socket	inp_socket
#define in6p_lport	inp_lport
#define in6p_head	inp_head
#define in6p_flags	inp_flags
#define IN6PLOOKUP_WILDCARD INPLOOKUP_WILDCARD
#endif
int
in6_pcbsetport(laddr, in6p)
	struct in6_addr *laddr;
	struct in6pcb *in6p;
{
	struct socket *so = in6p->in6p_socket;
	struct in6pcb *head = in6p->in6p_head;
	u_int16_t last_port, lport = 0;
	int wild = 0;
	void *t;
	u_int16_t min, max;
#ifdef __NetBSD__
	struct proc *p = curproc;		/* XXX */
#endif

	/* XXX: this is redundant when called from in6_pcbbind */
	if ((so->so_options & (SO_REUSEADDR|SO_REUSEPORT)) == 0 &&
	   ((so->so_proto->pr_flags & PR_CONNREQUIRED) == 0 ||
	    (so->so_options & SO_ACCEPTCONN) == 0))
		wild = IN6PLOOKUP_WILDCARD;

	if (in6p->in6p_flags & IN6P_LOWPORT) {
#ifdef __NetBSD__
		if (p == 0 || (suser(p->p_ucred, &p->p_acflag) != 0))
			return (EACCES);
#else
		if ((so->so_state & SS_PRIV) == 0)
			return (EACCES);
#endif
		min = IPV6PORT_RESERVEDMIN;
		max = IPV6PORT_RESERVEDMAX;
	} else {
		min = IPV6PORT_ANONMIN;
		max = IPV6PORT_ANONMAX;
	}

	/* value out of range */
	if (head->in6p_lport < min)
		head->in6p_lport = min;
	else if (head->in6p_lport > max)
		head->in6p_lport = min;
	last_port = head->in6p_lport;
	goto startover;	/*to randomize*/
	for (;;) {
		lport = htons(head->in6p_lport);
		if (IN6_IS_ADDR_V4MAPPED(laddr)) {
#if 0
			t = in_pcblookup_bind(&tcbtable,
					      (struct in_addr *)&in6p->in6p_laddr.s6_addr32[3],
					      lport);
#else
			t = NULL;
#endif
		} else {
#if HAVE_NRL_INPCB
			/* XXX: ugly cast... */
			t = in_pcblookup(head, (struct in_addr *)&zeroin6_addr,
					 0, (struct in_addr *)laddr,
					 lport, wild | INPLOOKUP_IPV6);
#else
			t = in6_pcblookup(head, &zeroin6_addr, 0, laddr,
					  lport, wild);
#endif
		}
		if (t == 0)
			break;
	  startover:
		if (head->in6p_lport >= max)
			head->in6p_lport = min;
		else
			head->in6p_lport++;
		if (head->in6p_lport == last_port)
			return (EADDRINUSE);
	}

	in6p->in6p_lport = lport;
	return(0);		/* success */
}
#if HAVE_NRL_INPCB
#undef in6pcb
#undef in6p_socket
#undef in6p_lport
#undef in6p_head
#undef in6p_flags
#undef IN6PLOOKUP_WILDCARD
#endif
#endif /* !FreeBSD3 && !OpenBSD*/
