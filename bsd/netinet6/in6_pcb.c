/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
 *
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
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/proc.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet/in_pcb.h>
#include <netinet6/in6_pcb.h>
#include <net/if_types.h>

#include <kern/kern_types.h>
#include <kern/zalloc.h>

#include "faith.h"
#if defined(NFAITH) && NFAITH > 0
#include <net/if_faith.h>
#endif

#if IPSEC
#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
#include <netinet6/ah.h>
#if INET6
#include <netinet6/ah6.h>
#endif
#include <netkey/key.h>
extern lck_mtx_t *sadb_mutex;
#endif /* IPSEC */

struct	in6_addr zeroin6_addr;

int
in6_pcbbind(
	struct inpcb *inp,
	struct sockaddr *nam,
	struct proc *p)
{
	struct socket *so = inp->inp_socket;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)NULL;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	u_short	lport = 0;
	int wild = 0, reuseport = (so->so_options & SO_REUSEPORT);

	if (!in6_ifaddrs) /* XXX broken! */
		return (EADDRNOTAVAIL);
	if (inp->inp_lport || !IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr))
		return(EINVAL);
	if ((so->so_options & (SO_REUSEADDR|SO_REUSEPORT)) == 0)
		wild = 1;
	socket_unlock(so, 0); /* keep reference */
	lck_rw_lock_exclusive(pcbinfo->mtx);
	if (nam) {
		sin6 = (struct sockaddr_in6 *)nam;
		if (nam->sa_len != sizeof(*sin6)) {
			lck_rw_done(pcbinfo->mtx);
			socket_lock(so, 0);
			return(EINVAL);
		}
		/*
		 * family check.
		 */
		if (nam->sa_family != AF_INET6) {
			lck_rw_done(pcbinfo->mtx);
			socket_lock(so, 0);
			return(EAFNOSUPPORT);
		}

		/* KAME hack: embed scopeid */
		if (in6_embedscope(&sin6->sin6_addr, sin6, inp, NULL) != 0) {
			lck_rw_done(pcbinfo->mtx);
			socket_lock(so, 0);
			return EINVAL;
		}
		/* this must be cleared for ifa_ifwithaddr() */
		sin6->sin6_scope_id = 0;

		lport = sin6->sin6_port;
		if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
			/*
			 * Treat SO_REUSEADDR as SO_REUSEPORT for multicast;
			 * allow compepte duplication of binding if
			 * SO_REUSEPORT is set, or if SO_REUSEADDR is set
			 * and a multicast address is bound on both
			 * new and duplicated sockets.
			 */
			if (so->so_options & SO_REUSEADDR)
				reuseport = SO_REUSEADDR|SO_REUSEPORT;
		} else if (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
			struct ifaddr *ia = NULL;

			sin6->sin6_port = 0;		/* yech... */
			if ((ia = ifa_ifwithaddr((struct sockaddr *)sin6)) == 0) {
				lck_rw_done(pcbinfo->mtx);
				socket_lock(so, 0);
				return(EADDRNOTAVAIL);
			}

			/*
			 * XXX: bind to an anycast address might accidentally
			 * cause sending a packet with anycast source address.
			 * We should allow to bind to a deprecated address, since
			 * the application dare to use it.
			 */
			if (ia &&
			    ((struct in6_ifaddr *)ia)->ia6_flags &
			    (IN6_IFF_ANYCAST|IN6_IFF_NOTREADY|IN6_IFF_DETACHED)) {
			    	ifafree(ia);
				lck_rw_done(pcbinfo->mtx);
				socket_lock(so, 0);
				return(EADDRNOTAVAIL);
			}
			ifafree(ia);
			ia = NULL;
		}
		if (lport) {
			struct inpcb *t;

			/* GROSS */
			if (ntohs(lport) < IPV6PORT_RESERVED && p &&
                            ((so->so_state & SS_PRIV) == 0)) {
				lck_rw_done(pcbinfo->mtx);
				socket_lock(so, 0);
				return(EACCES);
			}

			if (so->so_uid &&
			    !IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
				t = in6_pcblookup_local(pcbinfo,
				    &sin6->sin6_addr, lport,
				    INPLOOKUP_WILDCARD);
				if (t &&
				    (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) ||
				     !IN6_IS_ADDR_UNSPECIFIED(&t->in6p_laddr) ||
				     (t->inp_socket->so_options &
				      SO_REUSEPORT) == 0) &&
				    so->so_uid != t->inp_socket->so_uid) {
					lck_rw_done(pcbinfo->mtx);
					socket_lock(so, 0);
					return (EADDRINUSE);
				}
				if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0 &&
				    IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
					struct sockaddr_in sin;

					in6_sin6_2_sin(&sin, sin6);
					t = in_pcblookup_local(pcbinfo,
						sin.sin_addr, lport,
						INPLOOKUP_WILDCARD);
					if (t &&
					    (so->so_uid !=
					     t->inp_socket->so_uid) &&
					    (ntohl(t->inp_laddr.s_addr) !=
					     INADDR_ANY ||
					     INP_SOCKAF(so) ==
					     INP_SOCKAF(t->inp_socket))) {

						lck_rw_done(pcbinfo->mtx);
						socket_lock(so, 0);
						return (EADDRINUSE);
					}
				}
			}
			t = in6_pcblookup_local(pcbinfo, &sin6->sin6_addr,
						lport, wild);
			if (t && (reuseport & t->inp_socket->so_options) == 0) {
				lck_rw_done(pcbinfo->mtx);
				socket_lock(so, 0);
				return(EADDRINUSE);
			}
			if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0 &&
			    IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
				struct sockaddr_in sin;

				in6_sin6_2_sin(&sin, sin6);
				t = in_pcblookup_local(pcbinfo, sin.sin_addr,
						       lport, wild);
				if (t &&
				    (reuseport & t->inp_socket->so_options)
				    == 0 &&
				    (ntohl(t->inp_laddr.s_addr)
				     != INADDR_ANY ||
				     INP_SOCKAF(so) ==
				     INP_SOCKAF(t->inp_socket))) {
					lck_rw_done(pcbinfo->mtx);
					socket_lock(so, 0);
					return (EADDRINUSE);
				}
			}
		}
		inp->in6p_laddr = sin6->sin6_addr;
	}
	socket_lock(so, 0);
	if (lport == 0) {
		int e;
		if ((e = in6_pcbsetport(&inp->in6p_laddr, inp, p, 1)) != 0) {
			lck_rw_done(pcbinfo->mtx);
			return(e);
		}
	}
	else {
		inp->inp_lport = lport;
		if (in_pcbinshash(inp, 1) != 0) {
			inp->in6p_laddr = in6addr_any;
			inp->inp_lport = 0;
			lck_rw_done(pcbinfo->mtx);
			return (EAGAIN);
		}
	}	
	lck_rw_done(pcbinfo->mtx);
	return(0);
}

/*
 *   Transform old in6_pcbconnect() into an inner subroutine for new
 *   in6_pcbconnect(): Do some validity-checking on the remote
 *   address (in mbuf 'nam') and then determine local host address
 *   (i.e., which interface) to use to access that remote host.
 *
 *   This preserves definition of in6_pcbconnect(), while supporting a
 *   slightly different version for T/TCP.  (This is more than
 *   a bit of a kludge, but cleaning up the internal interfaces would
 *   have forced minor changes in every protocol).
 */

int
in6_pcbladdr(
	struct inpcb *inp,
	struct sockaddr *nam,
	struct in6_addr *plocal_addr6)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)nam;
	struct in6_addr *addr6 = NULL;
	struct in6_addr src_storage;
	
	struct ifnet *ifp = NULL;
	int error = 0;

	if (nam->sa_len != sizeof (*sin6))
		return (EINVAL);
	if (sin6->sin6_family != AF_INET6)
		return (EAFNOSUPPORT);
	if (sin6->sin6_port == 0)
		return (EADDRNOTAVAIL);

	/* KAME hack: embed scopeid */
	if (in6_embedscope(&sin6->sin6_addr, sin6, inp, &ifp) != 0)
		return EINVAL;

	if (in6_ifaddrs) {
		/*
		 * If the destination address is UNSPECIFIED addr,
		 * use the loopback addr, e.g ::1.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
			sin6->sin6_addr = in6addr_loopback;
	}
	{
		/*
		 * XXX: in6_selectsrc might replace the bound local address
		 * with the address specified by setsockopt(IPV6_PKTINFO).
		 * Is it the intended behavior?
		 */
		addr6 = in6_selectsrc(sin6, inp->in6p_outputopts,
					      inp->in6p_moptions,
					      &inp->in6p_route,
					      &inp->in6p_laddr, &src_storage, &error);
		if (addr6 == 0) {
			if (error == 0)
				error = EADDRNOTAVAIL;
			return(error);
		}
		*plocal_addr6 = *addr6;
		/*
		 * Don't do pcblookup call here; return interface in
		 * plocal_addr6
		 * and exit to caller, that will do the lookup.
		 */
	}

	if (inp->in6p_route.ro_rt)
		ifp = inp->in6p_route.ro_rt->rt_ifp;

	return(0);
}

/*
 * Outer subroutine:
 * Connect from a socket to a specified address.
 * Both address and port must be specified in argument sin.
 * If don't have a local address for this socket yet,
 * then pick one.
 */
int
in6_pcbconnect(inp, nam, p)
	struct inpcb *inp;
	struct sockaddr *nam;
	struct proc *p;
{
	struct in6_addr addr6;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)nam;
	struct inpcb *pcb;
	int error;

	/*
	 * Call inner routine, to assign local interface address.
	 * in6_pcbladdr() may automatically fill in sin6_scope_id.
	 */
	if ((error = in6_pcbladdr(inp, nam, &addr6)) != 0)
		return(error);
	socket_unlock(inp->inp_socket, 0);
	pcb = in6_pcblookup_hash(inp->inp_pcbinfo, &sin6->sin6_addr,
			       sin6->sin6_port,
			      IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)
			      ? &addr6 : &inp->in6p_laddr,
			      inp->inp_lport, 0, NULL);
	socket_lock(inp->inp_socket, 0);
	if (pcb != NULL) {
		in_pcb_checkstate(pcb, WNT_RELEASE, 0);
		return (EADDRINUSE);
	}
	if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)) {
		if (inp->inp_lport == 0) {
			error = in6_pcbbind(inp, (struct sockaddr *)0, p);
			if (error)
				return (error);
		}
		inp->in6p_laddr = addr6;
	}
	if (!lck_rw_try_lock_exclusive(inp->inp_pcbinfo->mtx)) {
		/*lock inversion issue, mostly with udp multicast packets */
		socket_unlock(inp->inp_socket, 0);
		lck_rw_lock_exclusive(inp->inp_pcbinfo->mtx);
		socket_lock(inp->inp_socket, 0);
	}
	inp->in6p_faddr = sin6->sin6_addr;
	inp->inp_fport = sin6->sin6_port;
	/* update flowinfo - draft-itojun-ipv6-flowlabel-api-00 */
	inp->in6p_flowinfo &= ~IPV6_FLOWLABEL_MASK;
	if (inp->in6p_flags & IN6P_AUTOFLOWLABEL)
		inp->in6p_flowinfo |=
		    (htonl(ip6_flow_seq++) & IPV6_FLOWLABEL_MASK);

	in_pcbrehash(inp);
	lck_rw_done(inp->inp_pcbinfo->mtx);
	return (0);
}

#if 0
/*
 * Return an IPv6 address, which is the most appropriate for given
 * destination and user specified options.
 * If necessary, this function lookups the routing table and return
 * an entry to the caller for later use.
 */
struct in6_addr *
in6_selectsrc(
	struct sockaddr_in6 *dstsock,
	struct ip6_pktopts *opts,
	struct ip6_moptions *mopts,
	struct route_in6 *ro,
	struct in6_addr *laddr,
	struct in6_addr *src_storage,
	int *errorp)
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
		*src_storage = satosin6(&ia6->ia_addr)->sin6_addr;
		ifafree(&ia6->ia_ifa);
		return(src_storage);
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
		*src_storage = satosin6(&ia6->ia_addr)->sin6_addr;
		ifafree(&ia6->ia_ifa);
		return(src_storage);
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

		if (ifp == NULL && IN6_IS_ADDR_MC_NODELOCAL(dst)) {
			ifp = &loif[0];
		}

		if (ifp) {
			ia6 = in6_ifawithscope(ifp, dst);
			if (ia6 == 0) {
				*errorp = EADDRNOTAVAIL;
				return(0);
			}
			*src_storage = ia6->ia_addr.sin6_addr;
			ifafree(&ia6->ia_ifa);
			return(src_storage);
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
			rt = nd6_lookup(&sin6_next->sin6_addr, 1, NULL, 0);
			if (rt) {
				ia6 = in6_ifawithscope(rt->rt_ifp, dst);
				if (ia6 == 0) {
					ifaref(&rt->rt_ifa);
					ia6 = ifatoia6(rt->rt_ifa);
				}
			}
			if (ia6 == 0) {
				*errorp = EADDRNOTAVAIL;
				return(0);
			}
			*src_storage = satosin6(&ia6->ia_addr)->sin6_addr;
			ifaref(&rt->rt_ifa);
			return(src_storage);
		}
	}

	/*
	 * If route is known or can be allocated now,
	 * our src addr is taken from the i/f, else punt.
	 */
	if (ro) {
		if (ro->ro_rt &&
		    !IN6_ARE_ADDR_EQUAL(&satosin6(&ro->ro_dst)->sin6_addr, dst)) {
			rtfree(ro->ro_rt);
			ro->ro_rt = (struct rtentry *)0;
		}
		if (ro->ro_rt == (struct rtentry *)0 ||
		    ro->ro_rt->rt_ifp == (struct ifnet *)0) {
			struct sockaddr_in6 *dst6;

			/* No route yet, so try to acquire one */
			bzero(&ro->ro_dst, sizeof(struct sockaddr_in6));
			dst6 = (struct sockaddr_in6 *)&ro->ro_dst;
			dst6->sin6_family = AF_INET6;
			dst6->sin6_len = sizeof(struct sockaddr_in6);
			dst6->sin6_addr = *dst;
			if (IN6_IS_ADDR_MULTICAST(dst)) {
				ro->ro_rt = rtalloc1(&((struct route *)ro)
						     ->ro_dst, 0, 0UL);
			} else {
				rtalloc((struct route *)ro);
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
			if (ia6 == 0) { /* xxx scope error ?*/
				ifaref(ro->ro_rt->rt_ifa);
				ia6 = ifatoia6(ro->ro_rt->rt_ifa);
			}
		}
		if (ia6 == 0) {
			*errorp = EHOSTUNREACH;	/* no route */
			return(0);
		}
		*src_storage = satosin6(&ia6->ia_addr)->sin6_addr;
		ifaref(&rt->rt_ifa);
		return(src_storage);
	}

	*errorp = EADDRNOTAVAIL;
	return(0);
}

/*
 * Default hop limit selection. The precedence is as follows:
 * 1. Hoplimit valued specified via ioctl.
 * 2. (If the outgoing interface is detected) the current
 *     hop limit of the interface specified by router advertisement.
 * 3. The system default hoplimit.
*/
int
in6_selecthlim(
	struct in6pcb *in6p,
	struct ifnet *ifp)
{
	if (in6p && in6p->in6p_hops >= 0)
		return(in6p->in6p_hops);
	else if (ifp)
		return(nd_ifinfo[ifp->if_index].chlim);
	else
		return(ip6_defhlim);
}
#endif

void
in6_pcbdisconnect(inp)
	struct inpcb *inp;
{
	if (!lck_rw_try_lock_exclusive(inp->inp_pcbinfo->mtx)) {
		/*lock inversion issue, mostly with udp multicast packets */
		socket_unlock(inp->inp_socket, 0);
		lck_rw_lock_exclusive(inp->inp_pcbinfo->mtx);
		socket_lock(inp->inp_socket, 0);
	}
	bzero((caddr_t)&inp->in6p_faddr, sizeof(inp->in6p_faddr));
	inp->inp_fport = 0;
	/* clear flowinfo - draft-itojun-ipv6-flowlabel-api-00 */
	inp->in6p_flowinfo &= ~IPV6_FLOWLABEL_MASK;
	in_pcbrehash(inp);
	lck_rw_done(inp->inp_pcbinfo->mtx);
	if (inp->inp_socket->so_state & SS_NOFDREF)
		in6_pcbdetach(inp);
}

void
in6_pcbdetach(inp)
	struct inpcb *inp;
{
	struct socket *so = inp->inp_socket;
	struct inpcbinfo *ipi = inp->inp_pcbinfo;

#if IPSEC
	if (inp->in6p_sp != NULL) {
		lck_mtx_lock(sadb_mutex);
		ipsec6_delete_pcbpolicy(inp);
		lck_mtx_unlock(sadb_mutex);
	}
#endif /* IPSEC */

	if (in_pcb_checkstate(inp, WNT_STOPUSING, 1) != WNT_STOPUSING)
		printf("in6_pcbdetach so=%x can't be marked dead ok\n", so);

	inp->inp_state = INPCB_STATE_DEAD;

	if ((so->so_flags & SOF_PCBCLEARING) == 0) {
		inp->inp_vflag = 0;
		so->so_flags |= SOF_PCBCLEARING;
		inp->inp_gencnt = ++ipi->ipi_gencnt;
		if (inp->in6p_options)
			m_freem(inp->in6p_options);
 		ip6_freepcbopts(inp->in6p_outputopts);
 		ip6_freemoptions(inp->in6p_moptions);
		if (inp->in6p_route.ro_rt)
			rtfree(inp->in6p_route.ro_rt);
		/* Check and free IPv4 related resources in case of mapped addr */
		if (inp->inp_options)
			(void)m_free(inp->inp_options);
 		ip_freemoptions(inp->inp_moptions);
		inp->inp_moptions = NULL;
	
	}
}

struct sockaddr *
in6_sockaddr(port, addr_p)
	in_port_t port;
	struct in6_addr *addr_p;
{
	struct sockaddr_in6 *sin6;

	MALLOC(sin6, struct sockaddr_in6 *, sizeof *sin6, M_SONAME, M_WAITOK);
	bzero(sin6, sizeof *sin6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(*sin6);
	sin6->sin6_port = port;
	sin6->sin6_addr = *addr_p;
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		sin6->sin6_scope_id = ntohs(sin6->sin6_addr.s6_addr16[1]);
	else
		sin6->sin6_scope_id = 0;	/*XXX*/
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		sin6->sin6_addr.s6_addr16[1] = 0;

	return (struct sockaddr *)sin6;
}

struct sockaddr *
in6_v4mapsin6_sockaddr(port, addr_p)
	in_port_t port;
	struct in_addr *addr_p;
{
	struct sockaddr_in sin;
	struct sockaddr_in6 *sin6_p;

	bzero(&sin, sizeof sin);
	sin.sin_family = AF_INET;
	sin.sin_len = sizeof(sin);
	sin.sin_port = port;
	sin.sin_addr = *addr_p;

	MALLOC(sin6_p, struct sockaddr_in6 *, sizeof *sin6_p, M_SONAME,
		M_WAITOK);
	in6_sin_2_v4mapsin6(&sin, sin6_p);

	return (struct sockaddr *)sin6_p;
}

/*
 * The calling convention of in6_setsockaddr() and in6_setpeeraddr() was
 * modified to match the pru_sockaddr() and pru_peeraddr() entry points
 * in struct pr_usrreqs, so that protocols can just reference then directly
 * without the need for a wrapper function.  The socket must have a valid
 * (i.e., non-nil) PCB, but it should be impossible to get an invalid one
 * except through a kernel programming error, so it is acceptable to panic
 * (or in this case trap) if the PCB is invalid.  (Actually, we don't trap
 * because there actually /is/ a programming error somewhere... XXX)
 */
int
in6_setsockaddr(so, nam)
	struct socket *so;
	struct sockaddr **nam;
{
	struct inpcb *inp;
	struct in6_addr addr;
	in_port_t port;

	inp = sotoinpcb(so);
	if (!inp) {
		return EINVAL;
	}
	port = inp->inp_lport;
	addr = inp->in6p_laddr;

	*nam = in6_sockaddr(port, &addr);
	return 0;
}

int
in6_setpeeraddr(so, nam)
	struct socket *so;
	struct sockaddr **nam;
{
	struct inpcb *inp;
	struct in6_addr addr;
	in_port_t port;

	inp = sotoinpcb(so);
	if (!inp) {
		return EINVAL;
	}
	port = inp->inp_fport;
	addr = inp->in6p_faddr;

	*nam = in6_sockaddr(port, &addr);
	return 0;
}

int
in6_mapped_sockaddr(struct socket *so, struct sockaddr **nam)
{
	struct	inpcb *inp = sotoinpcb(so);
	int	error;

	if (inp == NULL)
		return EINVAL;
	if (inp->inp_vflag & INP_IPV4) {
		error = in_setsockaddr(so, nam);
		if (error == 0)
			in6_sin_2_v4mapsin6_in_sock(nam);
	} else
	/* scope issues will be handled in in6_setsockaddr(). */
	error = in6_setsockaddr(so, nam);

	return error;
}

int
in6_mapped_peeraddr(struct socket *so, struct sockaddr **nam)
{
	struct	inpcb *inp = sotoinpcb(so);
	int	error;

	if (inp == NULL)
		return EINVAL;
	if (inp->inp_vflag & INP_IPV4) {
		error = in_setpeeraddr(so, nam);
		if (error == 0)
			in6_sin_2_v4mapsin6_in_sock(nam);
	} else
	/* scope issues will be handled in in6_setpeeraddr(). */
	error = in6_setpeeraddr(so, nam);

	return error;
}

/*
 * Pass some notification to all connections of a protocol
 * associated with address dst.  The local address and/or port numbers
 * may be specified to limit the search.  The "usual action" will be
 * taken, depending on the ctlinput cmd.  The caller must filter any
 * cmds that are uninteresting (e.g., no error in the map).
 * Call the protocol specific routine (if any) to report
 * any errors for each matching socket.
 *
 * Must be called at splnet.
 */
void
in6_pcbnotify(pcbinfo, dst, fport_arg, src, lport_arg, cmd, notify)
	struct inpcbinfo *pcbinfo;
	struct sockaddr *dst;
	const struct sockaddr *src;
	u_int fport_arg, lport_arg;
	int cmd;
//	struct inpcb *(*notify)(struct inpcb *, int);
	void (*notify)(struct inpcb *, int);
{
	struct inpcb *inp, *ninp;
	struct sockaddr_in6 sa6_src, *sa6_dst;
	u_short	fport = fport_arg, lport = lport_arg;
	u_int32_t flowinfo;
	int errno;
	struct inpcbhead *head = pcbinfo->listhead;

	if ((unsigned)cmd > PRC_NCMDS || dst->sa_family != AF_INET6)
		return;

	sa6_dst = (struct sockaddr_in6 *)dst;
	if (IN6_IS_ADDR_UNSPECIFIED(&sa6_dst->sin6_addr))
		return;

	/*
	 * note that src can be NULL when we get notify by local fragmentation.
	 */
	sa6_src = (src == NULL) ? sa6_any : *(const struct sockaddr_in6 *)src;
	flowinfo = sa6_src.sin6_flowinfo;

	/*
	 * Redirects go to all references to the destination,
	 * and use in6_rtchange to invalidate the route cache.
	 * Dead host indications: also use in6_rtchange to invalidate
	 * the cache, and deliver the error to all the sockets.
	 * Otherwise, if we have knowledge of the local port and address,
	 * deliver only to that socket.
	 */
	if (PRC_IS_REDIRECT(cmd) || cmd == PRC_HOSTDEAD) {
		fport = 0;
		lport = 0;
		bzero((caddr_t)&sa6_src.sin6_addr, sizeof(sa6_src.sin6_addr));

		if (cmd != PRC_HOSTDEAD)
			notify = in6_rtchange;
	}
	errno = inet6ctlerrmap[cmd];
	lck_rw_lock_shared(pcbinfo->mtx);
 	for (inp = LIST_FIRST(head); inp != NULL; inp = ninp) {
 		ninp = LIST_NEXT(inp, inp_list);

 		if ((inp->inp_vflag & INP_IPV6) == 0)
			continue;

		/*
		 * Detect if we should notify the error. If no source and
		 * destination ports are specifed, but non-zero flowinfo and
		 * local address match, notify the error. This is the case
		 * when the error is delivered with an encrypted buffer
		 * by ESP. Otherwise, just compare addresses and ports
		 * as usual.
		 */
		if (lport == 0 && fport == 0 && flowinfo &&
		    inp->inp_socket != NULL &&
		    flowinfo == (inp->in6p_flowinfo & IPV6_FLOWLABEL_MASK) &&
		    IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr, &sa6_src.sin6_addr))
			goto do_notify;
		else if (!IN6_ARE_ADDR_EQUAL(&inp->in6p_faddr,
					     &sa6_dst->sin6_addr) ||
			 inp->inp_socket == 0 ||
			 (lport && inp->inp_lport != lport) ||
			 (!IN6_IS_ADDR_UNSPECIFIED(&sa6_src.sin6_addr) &&
			  !IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr,
					      &sa6_src.sin6_addr)) ||
			 (fport && inp->inp_fport != fport)) 
			continue;
		     

	  do_notify:
		if (notify) {
			if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) == WNT_STOPUSING)
				continue;
			socket_lock(inp->inp_socket, 1);
			(*notify)(inp, errno);
			(void)in_pcb_checkstate(inp, WNT_RELEASE, 1);
			socket_unlock(inp->inp_socket, 1);
		}
	}
	lck_rw_done(pcbinfo->mtx);
}

/*
 * Lookup a PCB based on the local address and port.
 */
struct inpcb *
in6_pcblookup_local(pcbinfo, laddr, lport_arg, wild_okay)
	struct inpcbinfo *pcbinfo;
	struct in6_addr *laddr;
	u_int lport_arg;
	int wild_okay;
{
	struct inpcb *inp;
	int matchwild = 3, wildcard;
	u_short lport = lport_arg;

	if (!wild_okay) {
		struct inpcbhead *head;
		/*
		 * Look for an unconnected (wildcard foreign addr) PCB that
		 * matches the local address and port we're looking for.
		 */
		head = &pcbinfo->hashbase[INP_PCBHASH(INADDR_ANY, lport, 0,
						      pcbinfo->hashmask)];
		LIST_FOREACH(inp, head, inp_hash) {
			if ((inp->inp_vflag & INP_IPV6) == 0)
				continue;
			if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr) &&
			    IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr, laddr) &&
			    inp->inp_lport == lport) {
				/*
				 * Found.
				 */
				return (inp);
			}
		}
		/*
		 * Not found.
		 */
		return (NULL);
	} else {
		struct inpcbporthead *porthash;
		struct inpcbport *phd;
		struct inpcb *match = NULL;
		/*
		 * Best fit PCB lookup.
		 *
		 * First see if this local port is in use by looking on the
		 * port hash list.
		 */
		porthash = &pcbinfo->porthashbase[INP_PCBPORTHASH(lport,
		    pcbinfo->porthashmask)];
		LIST_FOREACH(phd, porthash, phd_hash) {
			if (phd->phd_port == lport)
				break;
		}
		if (phd != NULL) {
			/*
			 * Port is in use by one or more PCBs. Look for best
			 * fit.
			 */
			LIST_FOREACH(inp, &phd->phd_pcblist, inp_portlist) {
				wildcard = 0;
				if ((inp->inp_vflag & INP_IPV6) == 0)
					continue;
				if (!IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr))
					wildcard++;
				if (!IN6_IS_ADDR_UNSPECIFIED(
					&inp->in6p_laddr)) {
					if (IN6_IS_ADDR_UNSPECIFIED(laddr))
						wildcard++;
					else if (!IN6_ARE_ADDR_EQUAL(
						&inp->in6p_laddr, laddr))
						continue;
				} else {
					if (!IN6_IS_ADDR_UNSPECIFIED(laddr))
						wildcard++;
				}
				if (wildcard < matchwild) {
					match = inp;
					matchwild = wildcard;
					if (matchwild == 0) {
						break;
					}
				}
			}
		}
		return (match);
	}
}
#ifndef APPLE
/* this is not used in Darwin */
void
in6_pcbpurgeif0(
	struct in6pcb *head,
	struct ifnet *ifp)
{
	struct in6pcb *in6p;
	struct ip6_moptions *im6o;
	struct in6_multi_mship *imm, *nimm;

	for (in6p = head; in6p != NULL; in6p = LIST_NEXT(in6p, inp_list)) {
		im6o = in6p->in6p_moptions;
		if ((in6p->inp_vflag & INP_IPV6) &&
		    im6o) {
			/*
			 * Unselect the outgoing interface if it is being
			 * detached.
			 */
			if (im6o->im6o_multicast_ifp == ifp)
				im6o->im6o_multicast_ifp = NULL;

			/*
			 * Drop multicast group membership if we joined
			 * through the interface being detached.
			 * XXX controversial - is it really legal for kernel
			 * to force this?
			 */
			for (imm = im6o->im6o_memberships.lh_first;
			     imm != NULL; imm = nimm) {
				nimm = imm->i6mm_chain.le_next;
				if (imm->i6mm_maddr->in6m_ifp == ifp) {
					LIST_REMOVE(imm, i6mm_chain);
					in6_delmulti(imm->i6mm_maddr);
					FREE(imm, M_IPMADDR);
				}
			}
		}
	}
}
#endif

/*
 * Check for alternatives when higher level complains
 * about service problems.  For now, invalidate cached
 * routing information.  If the route was created dynamically
 * (by a redirect), time to try a default gateway again.
 */
void
in6_losing(in6p)
	struct inpcb *in6p;
{
	struct rtentry *rt;
	struct rt_addrinfo info;

	if ((rt = in6p->in6p_route.ro_rt) != NULL) {
		in6p->in6p_route.ro_rt = 0;
		bzero((caddr_t)&info, sizeof(info));
		info.rti_info[RTAX_DST] =
			(struct sockaddr *)&in6p->in6p_route.ro_dst;
		info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
		info.rti_info[RTAX_NETMASK] = rt_mask(rt);
		lck_mtx_lock(rt_mtx);
		rt_missmsg(RTM_LOSING, &info, rt->rt_flags, 0);
		if (rt->rt_flags & RTF_DYNAMIC)
			(void)rtrequest_locked(RTM_DELETE, rt_key(rt),
					rt->rt_gateway, rt_mask(rt), rt->rt_flags,
					(struct rtentry **)0);
		else
		/*
		 * A new route can be allocated
		 * the next time output is attempted.
		 */
			rtfree_locked(rt);
		lck_mtx_unlock(rt_mtx);
	}
}

/*
 * After a routing change, flush old routing
 * and allocate a (hopefully) better one.
 */
void
in6_rtchange(
	struct inpcb *inp,
	int errno)
{
	if (inp->in6p_route.ro_rt) {
		rtfree(inp->in6p_route.ro_rt);
		inp->in6p_route.ro_rt = 0;
		/*
		 * A new route can be allocated the next time
		 * output is attempted.
		 */
	}
}

/*
 * Lookup PCB in hash list.
 */
struct inpcb *
in6_pcblookup_hash(
	struct inpcbinfo *pcbinfo,
	struct in6_addr *faddr,
	u_int fport_arg,
	struct in6_addr *laddr,
	u_int lport_arg,
	int wildcard,
	struct ifnet *ifp)
{
	struct inpcbhead *head;
	struct inpcb *inp;
	u_short fport = fport_arg, lport = lport_arg;
	int faith;

#if defined(NFAITH) && NFAITH > 0
	faith = faithprefix(laddr);
#else
	faith = 0;
#endif

	lck_rw_lock_shared(pcbinfo->mtx);

	/*
	 * First look for an exact match.
	 */
	head = &pcbinfo->hashbase[INP_PCBHASH(faddr->s6_addr32[3] /* XXX */,
					      lport, fport,
					      pcbinfo->hashmask)];
	LIST_FOREACH(inp, head, inp_hash) {
		if ((inp->inp_vflag & INP_IPV6) == 0)
			continue;
		if (IN6_ARE_ADDR_EQUAL(&inp->in6p_faddr, faddr) &&
		    IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr, laddr) &&
		    inp->inp_fport == fport &&
		    inp->inp_lport == lport) {
			/*
		 	* Found. Check if pcb is still valid
		 	*/
			if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) != WNT_STOPUSING) {
				lck_rw_done(pcbinfo->mtx);
				return (inp);
			}
			else {	/* it's there but dead, say it isn't found */
				lck_rw_done(pcbinfo->mtx);	
	    			return(NULL);
			}
		}
	}
	if (wildcard) {
		struct inpcb *local_wild = NULL;

		head = &pcbinfo->hashbase[INP_PCBHASH(INADDR_ANY, lport, 0,
						      pcbinfo->hashmask)];
		LIST_FOREACH(inp, head, inp_hash) {
			if ((inp->inp_vflag & INP_IPV6) == 0)
				continue;
			if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr) &&
			    inp->inp_lport == lport) {
				if (faith && (inp->inp_flags & INP_FAITH) == 0)
					continue;
				if (IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr,
						       laddr)) {
					if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) != WNT_STOPUSING) {
						lck_rw_done(pcbinfo->mtx);
						return (inp);
					}
					else {	/* it's there but dead, say it isn't found */
						lck_rw_done(pcbinfo->mtx);	
	    					return(NULL);
					}
				}
				else if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr))
					local_wild = inp;
			}
		}
		if (local_wild && in_pcb_checkstate(local_wild, WNT_ACQUIRE, 0) != WNT_STOPUSING) {
			lck_rw_done(pcbinfo->mtx);
			return (local_wild);
		}
		else {
			lck_rw_done(pcbinfo->mtx);
			return (NULL);
		}
	}

	/*
	 * Not found.
	 */
	lck_rw_done(pcbinfo->mtx);
	return (NULL);
}

void
init_sin6(struct sockaddr_in6 *sin6, struct mbuf *m)
{
	struct ip6_hdr *ip;

	ip = mtod(m, struct ip6_hdr *);
	bzero(sin6, sizeof(*sin6));
	sin6->sin6_len = sizeof(*sin6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = ip->ip6_src;
	if (IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		sin6->sin6_addr.s6_addr16[1] = 0;
	sin6->sin6_scope_id =
		(m->m_pkthdr.rcvif && IN6_IS_SCOPE_LINKLOCAL(&sin6->sin6_addr))
		? m->m_pkthdr.rcvif->if_index : 0;

	return;
}
