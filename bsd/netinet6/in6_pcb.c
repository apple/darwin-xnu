/*
 * Copyright (c) 2003-2012 Apple Inc. All rights reserved.
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
#include <sys/kauth.h>
#include <sys/priv.h>

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
#include <net/if_var.h>

#include <kern/kern_types.h>
#include <kern/zalloc.h>

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
#endif /* IPSEC */

struct	in6_addr zeroin6_addr;

/*
  in6_pcblookup_local_and_cleanup does everything
  in6_pcblookup_local does but it checks for a socket
  that's going away. Since we know that the lock is
  held read+write when this function is called, we
  can safely dispose of this socket like the slow
  timer would usually do and return NULL. This is
  great for bind.
*/
static struct inpcb*
in6_pcblookup_local_and_cleanup(
	struct inpcbinfo *pcbinfo,
	struct in6_addr *laddr,
	u_int lport_arg,
	int wild_okay)
{
	struct inpcb *inp;
	
	/* Perform normal lookup */
	inp = in6_pcblookup_local(pcbinfo, laddr, lport_arg, wild_okay);
	
	/* Check if we found a match but it's waiting to be disposed */
	if (inp && inp->inp_wantcnt == WNT_STOPUSING) {
		struct socket *so = inp->inp_socket;
		
		lck_mtx_lock(&inp->inpcb_mtx);
		
		if (so->so_usecount == 0) {
			if (inp->inp_state != INPCB_STATE_DEAD)
				in6_pcbdetach(inp);
			in_pcbdispose(inp);
			inp = NULL;
		}
		else {
			lck_mtx_unlock(&inp->inpcb_mtx);
		}
	}
	
	return inp;
}

int
in6_pcbbind(struct inpcb *inp, struct sockaddr *nam, struct proc *p)
{
	struct socket *so = inp->inp_socket;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)NULL;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	u_short	lport = 0;
	int wild = 0, reuseport = (so->so_options & SO_REUSEPORT);
#if !CONFIG_EMBEDDED
	int error;
	kauth_cred_t cred;
#endif

	if (!in6_ifaddrs) /* XXX broken! */
		return (EADDRNOTAVAIL);
	if (inp->inp_lport || !IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr))
		return(EINVAL);
	if ((so->so_options & (SO_REUSEADDR|SO_REUSEPORT)) == 0)
		wild = 1;
	socket_unlock(so, 0); /* keep reference */
	lck_rw_lock_exclusive(pcbinfo->mtx);
	if (nam) {
		struct ifnet *outif = NULL;

		sin6 = (struct sockaddr_in6 *)(void *)nam;
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
		if (in6_embedscope(&sin6->sin6_addr, sin6, inp, NULL,
		    NULL) != 0) {
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
			struct ifaddr *ifa;

			sin6->sin6_port = 0;		/* yech... */
			if ((ifa = ifa_ifwithaddr((struct sockaddr *)sin6)) == 0) {
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
			if (ifa != NULL) {
				IFA_LOCK_SPIN(ifa);
				if (((struct in6_ifaddr *)ifa)->ia6_flags &
				    (IN6_IFF_ANYCAST|IN6_IFF_NOTREADY|IN6_IFF_DETACHED)) {
					IFA_UNLOCK(ifa);
					IFA_REMREF(ifa);
					lck_rw_done(pcbinfo->mtx);
					socket_lock(so, 0);
					return(EADDRNOTAVAIL);
				}
				outif = ifa->ifa_ifp;
				IFA_UNLOCK(ifa);
				IFA_REMREF(ifa);
			}
		}
		if (lport) {
			struct inpcb *t;

			/* GROSS */
#if !CONFIG_EMBEDDED
			if (ntohs(lport) < IPV6PORT_RESERVED) {
				cred = kauth_cred_proc_ref(p);
				error = priv_check_cred(cred, PRIV_NETINET_RESERVEDPORT, 0);
				kauth_cred_unref(&cred);
				if (error != 0) {
					lck_rw_done(pcbinfo->mtx);
					socket_lock(so, 0);
					return(EACCES);
				}
			}
#endif

			if (kauth_cred_getuid(so->so_cred) &&
			    !IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
				t = in6_pcblookup_local_and_cleanup(pcbinfo,
				    &sin6->sin6_addr, lport,
				    INPLOOKUP_WILDCARD);
				if (t &&
				    (!IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr) ||
				     !IN6_IS_ADDR_UNSPECIFIED(&t->in6p_laddr) ||
				     (t->inp_socket->so_options &
				      SO_REUSEPORT) == 0) &&
				     (kauth_cred_getuid(so->so_cred) !=
					 kauth_cred_getuid(t->inp_socket->so_cred)) &&
				     ((t->inp_socket->so_flags & SOF_REUSESHAREUID) == 0)) {
					lck_rw_done(pcbinfo->mtx);
					socket_lock(so, 0);
					return (EADDRINUSE);
				}
				if ((inp->inp_flags & IN6P_IPV6_V6ONLY) == 0 &&
				    IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
					struct sockaddr_in sin;

					in6_sin6_2_sin(&sin, sin6);
					t = in_pcblookup_local_and_cleanup(pcbinfo,
						sin.sin_addr, lport,
						INPLOOKUP_WILDCARD);
					if (t && (t->inp_socket->so_options & SO_REUSEPORT) == 0 &&
					    (kauth_cred_getuid(so->so_cred) !=
					        kauth_cred_getuid(t->inp_socket->so_cred)) &&
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
			t = in6_pcblookup_local_and_cleanup(pcbinfo, &sin6->sin6_addr,
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
				t = in_pcblookup_local_and_cleanup(pcbinfo, sin.sin_addr,
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
		inp->in6p_last_outifp = outif;
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
			inp->in6p_last_outifp = NULL;
			lck_rw_done(pcbinfo->mtx);
			return (EAGAIN);
		}
	}
	lck_rw_done(pcbinfo->mtx);
	sflt_notify(so, sock_evt_bound, NULL);
	return(0);
}

/*
 * Transform old in6_pcbconnect() into an inner subroutine for new
 * in6_pcbconnect(): Do some validity-checking on the remote
 * address (in mbuf 'nam') and then determine local host address
 * (i.e., which interface) to use to access that remote host.
 *
 * This preserves definition of in6_pcbconnect(), while supporting a
 * slightly different version for T/TCP.  (This is more than
 * a bit of a kludge, but cleaning up the internal interfaces would
 * have forced minor changes in every protocol).
 *
 * This routine might return an ifp with a reference held if the caller
 * provides a non-NULL outif, even in the error case.  The caller is
 * responsible for releasing its reference.
 */
int
in6_pcbladdr(struct inpcb *inp, struct sockaddr *nam,
    struct in6_addr *plocal_addr6, struct ifnet **outif)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(void *)nam;
	struct in6_addr *addr6 = NULL;
	struct in6_addr src_storage;
	int error = 0;
	unsigned int ifscope;

	if (outif != NULL)
		*outif = NULL;
	if (nam->sa_len != sizeof (*sin6))
		return (EINVAL);
	if (sin6->sin6_family != AF_INET6)
		return (EAFNOSUPPORT);
	if (sin6->sin6_port == 0)
		return (EADDRNOTAVAIL);

	/* KAME hack: embed scopeid */
	if (in6_embedscope(&sin6->sin6_addr, sin6, inp, NULL, NULL) != 0)
		return (EINVAL);

	if (in6_ifaddrs) {
		/*
		 * If the destination address is UNSPECIFIED addr,
		 * use the loopback addr, e.g ::1.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
			sin6->sin6_addr = in6addr_loopback;
	}

	ifscope = (inp->inp_flags & INP_BOUND_IF) ?
	   inp->inp_boundifp->if_index : IFSCOPE_NONE;

	/*
	 * XXX: in6_selectsrc might replace the bound local address
	 * with the address specified by setsockopt(IPV6_PKTINFO).
	 * Is it the intended behavior?
	 *
	 * in6_selectsrc() might return outif with its reference held
	 * even in the error case; caller always needs to release it
	 * if non-NULL.
	 */
	addr6 = in6_selectsrc(sin6, inp->in6p_outputopts, inp,
	    &inp->in6p_route, outif, &src_storage, ifscope, &error);

	if (outif != NULL) {
		struct rtentry *rt = inp->in6p_route.ro_rt;
		/*
		 * If in6_selectsrc() returns a route, it should be one
		 * which points to the same ifp as outif.  Just in case
		 * it isn't, use the one from the route for consistency.
		 * Otherwise if there is no route, leave outif alone as
		 * it could still be useful to the caller.
		 */
		if (rt != NULL && rt->rt_ifp != *outif) {
			ifnet_reference(rt->rt_ifp);	/* for caller */
			if (*outif != NULL)
				ifnet_release(*outif);
			*outif = rt->rt_ifp;
		}
	}

	if (addr6 == NULL) {
		if (outif != NULL && (*outif) != NULL &&
			(inp->inp_flags & INP_NO_IFT_CELLULAR) &&
			(*outif)->if_type == IFT_CELLULAR)
			soevent(inp->inp_socket,
			    (SO_FILT_HINT_LOCKED | SO_FILT_HINT_IFDENIED));
		if (error == 0)
			error = EADDRNOTAVAIL;
		return (error);
	}

	*plocal_addr6 = *addr6;
	/*
	 * Don't do pcblookup call here; return interface in
	 * plocal_addr6 and exit to caller, that will do the lookup.
	 */
	return (0);
}

/*
 * Outer subroutine:
 * Connect from a socket to a specified address.
 * Both address and port must be specified in argument sin.
 * If don't have a local address for this socket yet,
 * then pick one.
 */
int
in6_pcbconnect(
	struct inpcb *inp,
	struct sockaddr *nam,
	struct proc *p)
{
	struct in6_addr addr6;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)(void *)nam;
	struct inpcb *pcb;
	int error = 0;
	struct ifnet *outif = NULL;

	/*
	 * Call inner routine, to assign local interface address.
	 * in6_pcbladdr() may automatically fill in sin6_scope_id.
	 *
	 * in6_pcbladdr() might return an ifp with its reference held
	 * even in the error case, so make sure that it's released
	 * whenever it's non-NULL.
	 */
	if ((error = in6_pcbladdr(inp, nam, &addr6, &outif)) != 0) {
		if ((inp->inp_flags & INP_NO_IFT_CELLULAR) &&
			outif != NULL &&
			outif->if_type == IFT_CELLULAR)
			soevent(inp->inp_socket, 
			    (SO_FILT_HINT_LOCKED | SO_FILT_HINT_IFDENIED));
		goto done;
	}
	socket_unlock(inp->inp_socket, 0);
	pcb = in6_pcblookup_hash(inp->inp_pcbinfo, &sin6->sin6_addr,
			       sin6->sin6_port,
			      IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)
			      ? &addr6 : &inp->in6p_laddr,
			      inp->inp_lport, 0, NULL);
	socket_lock(inp->inp_socket, 0);
	if (pcb != NULL) {
		in_pcb_checkstate(pcb, WNT_RELEASE, pcb == inp ? 1 : 0);
		error = EADDRINUSE;
		goto done;
	}
	if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr)) {
		if (inp->inp_lport == 0) {
			error = in6_pcbbind(inp, (struct sockaddr *)0, p);
			if (error)
				goto done;
		}
		inp->in6p_laddr = addr6;
		inp->in6p_last_outifp = outif;	/* no reference needed */
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

done:
	if (outif != NULL)
		ifnet_release(outif);

	return (error);
}

void
in6_pcbdisconnect(
	struct inpcb *inp)
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
in6_pcbdetach(
	struct inpcb *inp)
{
	struct socket *so = inp->inp_socket;
	struct inpcbinfo *ipi = inp->inp_pcbinfo;

#if IPSEC
	if (inp->in6p_sp != NULL) {
		ipsec6_delete_pcbpolicy(inp);
	}
#endif /* IPSEC */

	if (in_pcb_checkstate(inp, WNT_STOPUSING, 1) != WNT_STOPUSING)
		printf("in6_pcbdetach so=%p can't be marked dead ok\n", so);

	inp->inp_state = INPCB_STATE_DEAD;

	if ((so->so_flags & SOF_PCBCLEARING) == 0) {
		struct ip_moptions *imo;
		struct ip6_moptions *im6o;

		inp->inp_vflag = 0;
		so->so_flags |= SOF_PCBCLEARING;
		inp->inp_gencnt = ++ipi->ipi_gencnt;
		if (inp->in6p_options)
			m_freem(inp->in6p_options);
		ip6_freepcbopts(inp->in6p_outputopts);
		if (inp->in6p_route.ro_rt) {
			rtfree(inp->in6p_route.ro_rt);
			inp->in6p_route.ro_rt = NULL;
		}
		/* Check and free IPv4 related resources in case of mapped addr */
		if (inp->inp_options)
			(void)m_free(inp->inp_options);

		im6o = inp->in6p_moptions;
		inp->in6p_moptions = NULL;
		if (im6o != NULL)
			IM6O_REMREF(im6o);

		imo = inp->inp_moptions;
		inp->inp_moptions = NULL;
		if (imo != NULL)
			IMO_REMREF(imo);
	}
}

struct sockaddr *
in6_sockaddr(
	in_port_t port,
	struct in6_addr *addr_p)
{
	struct sockaddr_in6 *sin6;

	MALLOC(sin6, struct sockaddr_in6 *, sizeof *sin6, M_SONAME, M_WAITOK);
	if (sin6 == NULL)
		return NULL;
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
in6_v4mapsin6_sockaddr(
	in_port_t port,
	struct in_addr *addr_p)
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
	if (sin6_p == NULL)
		return NULL;
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
in6_setsockaddr(
	struct socket *so,
	struct sockaddr **nam)
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
	if (*nam == NULL)
		return ENOBUFS;
	return 0;
}

int
in6_setpeeraddr(
	struct socket *so,
	struct sockaddr **nam)
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
	if (*nam == NULL)
		return ENOBUFS;
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
			error = in6_sin_2_v4mapsin6_in_sock(nam);
	} else {
		/* scope issues will be handled in in6_setsockaddr(). */
		error = in6_setsockaddr(so, nam);
	}
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
			error = in6_sin_2_v4mapsin6_in_sock(nam);
	} else {
		/* scope issues will be handled in in6_setpeeraddr(). */
		error = in6_setpeeraddr(so, nam);
	}
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
 */
void
in6_pcbnotify(pcbinfo, dst, fport_arg, src, lport_arg, cmd, cmdarg, notify)
	struct inpcbinfo *pcbinfo;
	struct sockaddr *dst;
	const struct sockaddr *src;
	u_int fport_arg, lport_arg;
	int cmd;
	void *cmdarg;
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

	sa6_dst = (struct sockaddr_in6 *)(void *)dst;
	if (IN6_IS_ADDR_UNSPECIFIED(&sa6_dst->sin6_addr))
		return;

	/*
	 * note that src can be NULL when we get notify by local fragmentation.
	 */
	sa6_src = (src == NULL) ?
	    sa6_any : *(struct sockaddr_in6 *)(uintptr_t)(size_t)src;
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
		 * If the error designates a new path MTU for a destination
		 * and the application (associated with this socket) wanted to
		 * know the value, notify. Note that we notify for all
		 * disconnected sockets if the corresponding application
		 * wanted. This is because some UDP applications keep sending
		 * sockets disconnected.
		 * XXX: should we avoid to notify the value to TCP sockets?
		 */
		if (cmd == PRC_MSGSIZE && (inp->inp_flags & IN6P_MTU) != 0 &&
		    (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr) ||
		     IN6_ARE_ADDR_EQUAL(&inp->in6p_faddr, &sa6_dst->sin6_addr))) {
			ip6_notify_pmtu(inp, (struct sockaddr_in6 *)(void *)dst,
			    (u_int32_t *)cmdarg);
		}

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
in6_pcblookup_local(
	struct inpcbinfo *pcbinfo,
	struct in6_addr *laddr,
	u_int lport_arg,
	int wild_okay)
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

/*
 * Check for alternatives when higher level complains
 * about service problems.  For now, invalidate cached
 * routing information.  If the route was created dynamically
 * (by a redirect), time to try a default gateway again.
 */
void
in6_losing(
	struct inpcb *in6p)
{
	struct rtentry *rt;
	struct rt_addrinfo info;

	if ((rt = in6p->in6p_route.ro_rt) != NULL) {
		in6p->in6p_route.ro_rt = NULL;
		RT_LOCK(rt);
		bzero((caddr_t)&info, sizeof(info));
		info.rti_info[RTAX_DST] =
			(struct sockaddr *)&in6p->in6p_route.ro_dst;
		info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
		info.rti_info[RTAX_NETMASK] = rt_mask(rt);
		rt_missmsg(RTM_LOSING, &info, rt->rt_flags, 0);
		if (rt->rt_flags & RTF_DYNAMIC) {
			/*
			 * Prevent another thread from modifying rt_key,
			 * rt_gateway via rt_setgate() after the rt_lock
			 * is dropped by marking the route as defunct.
			 */
			rt->rt_flags |= RTF_CONDEMNED;
			RT_UNLOCK(rt);
			(void) rtrequest(RTM_DELETE, rt_key(rt),
			    rt->rt_gateway, rt_mask(rt), rt->rt_flags, NULL);
		} else {
			RT_UNLOCK(rt);
		}
		/*
		 * A new route can be allocated
		 * the next time output is attempted.
		 */
		rtfree(rt);
	}
}

/*
 * After a routing change, flush old routing
 * and allocate a (hopefully) better one.
 */
void
in6_rtchange(
	struct inpcb *inp,
	__unused int errno)
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
 * Check if PCB exists hash list. Also returns uid and gid of socket
 */
int
in6_pcblookup_hash_exists(
	struct inpcbinfo *pcbinfo,
	struct in6_addr *faddr,
	u_int fport_arg,
	struct in6_addr *laddr,
	u_int lport_arg,
	int wildcard,
	uid_t *uid,
	gid_t *gid,
	struct ifnet *ifp)
{
	struct inpcbhead *head;
	struct inpcb *inp;
	u_short fport = fport_arg, lport = lport_arg;
	int found;

	*uid = UID_MAX;
	*gid = GID_MAX;

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

		if (ip6_restrictrecvif && ifp != NULL &&
		    (ifp->if_eflags & IFEF_RESTRICTED_RECV) &&
		    !(inp->in6p_flags & IN6P_RECV_ANYIF))
			continue;

		if (IN6_ARE_ADDR_EQUAL(&inp->in6p_faddr, faddr) &&
		    IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr, laddr) &&
		    inp->inp_fport == fport &&
		    inp->inp_lport == lport) {
			if ((found = (inp->inp_socket != NULL))) {
				/*
				 * Found. Check if pcb is still valid
				 */
				*uid = kauth_cred_getuid(
				    inp->inp_socket->so_cred);
				*gid = kauth_cred_getgid(
				    inp->inp_socket->so_cred);
			}
			lck_rw_done(pcbinfo->mtx);
			return (found);
		}
	}
	if (wildcard) {
		struct inpcb *local_wild = NULL;

		head = &pcbinfo->hashbase[INP_PCBHASH(INADDR_ANY, lport, 0,
						      pcbinfo->hashmask)];
		LIST_FOREACH(inp, head, inp_hash) {
			if ((inp->inp_vflag & INP_IPV6) == 0)
				continue;

			if (ip6_restrictrecvif && ifp != NULL &&
			    (ifp->if_eflags & IFEF_RESTRICTED_RECV) &&
			    !(inp->in6p_flags & IN6P_RECV_ANYIF))
				continue;

			if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr) &&
			    inp->inp_lport == lport) {
				if (IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr,
						       laddr)) {
					if ((found = (inp->inp_socket != NULL))) {
						*uid = kauth_cred_getuid(
						    inp->inp_socket->so_cred);
						*gid = kauth_cred_getgid(
						    inp->inp_socket->so_cred);
					}
					lck_rw_done(pcbinfo->mtx);
					return (found);
				}
				else if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr))
					local_wild = inp;
			}
		}
		if (local_wild) {
			if ((found = (local_wild->inp_socket != NULL))) {
				*uid = kauth_cred_getuid(
				    local_wild->inp_socket->so_cred);
				*gid = kauth_cred_getgid(
				    local_wild->inp_socket->so_cred);
			}
			lck_rw_done(pcbinfo->mtx);
			return (found);
		}
	}

	/*
	 * Not found.
	 */
	lck_rw_done(pcbinfo->mtx);
	return (0);
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
	__unused struct ifnet *ifp)
{
	struct inpcbhead *head;
	struct inpcb *inp;
	u_short fport = fport_arg, lport = lport_arg;

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

		if (ip6_restrictrecvif && ifp != NULL &&
		    (ifp->if_eflags & IFEF_RESTRICTED_RECV) &&
		    !(inp->in6p_flags & IN6P_RECV_ANYIF))
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
				return (NULL);
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

			if (ip6_restrictrecvif && ifp != NULL &&
			    (ifp->if_eflags & IFEF_RESTRICTED_RECV) &&
			    !(inp->in6p_flags & IN6P_RECV_ANYIF))
				continue;

			if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr) &&
			    inp->inp_lport == lport) {
				if (IN6_ARE_ADDR_EQUAL(&inp->in6p_laddr,
						       laddr)) {
					if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) != WNT_STOPUSING) {
						lck_rw_done(pcbinfo->mtx);
						return (inp);
					}
					else {	/* it's there but dead, say it isn't found */
						lck_rw_done(pcbinfo->mtx);
						return (NULL);
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

void
in6p_route_copyout(struct inpcb *inp, struct route_in6 *dst)
{
	struct route_in6 *src = &inp->in6p_route;

	lck_mtx_assert(&inp->inpcb_mtx, LCK_MTX_ASSERT_OWNED);

	/* Minor sanity check */
	if (src->ro_rt != NULL && rt_key(src->ro_rt)->sa_family != AF_INET6)
		panic("%s: wrong or corrupted route: %p", __func__, src);
	
	route_copyout((struct route *)dst, (struct route *)src, sizeof(*dst));
}

void
in6p_route_copyin(struct inpcb *inp, struct route_in6 *src)
{
	struct route_in6 *dst = &inp->in6p_route;

	lck_mtx_assert(&inp->inpcb_mtx, LCK_MTX_ASSERT_OWNED);

	/* Minor sanity check */
	if (src->ro_rt != NULL && rt_key(src->ro_rt)->sa_family != AF_INET6)
		panic("%s: wrong or corrupted route: %p", __func__, src);

	route_copyin((struct route *)src, (struct route *)dst, sizeof(*src));
}

