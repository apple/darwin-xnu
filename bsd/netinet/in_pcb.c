/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1991, 1993, 1995
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
 *	@(#)in_pcb.c	8.4 (Berkeley) 5/24/95
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#if INET6 
#include <sys/domain.h>
#endif 
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>

#include <machine/limits.h>

#if ISFB31
#include <vm/vm_zone.h>
#else
#include <kern/zalloc.h>
#endif

#include <net/if.h>
#include <net/route.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#if INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif /* INET6 */

#include "faith.h"

#if IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#include <netkey/key_debug.h>
#endif /* IPSEC */

#include <sys/kdebug.h>


#define DBG_FNC_PCB_LOOKUP	NETDBG_CODE(DBG_NETTCP, (6 << 8))
#define DBG_FNC_PCB_HLOOKUP	NETDBG_CODE(DBG_NETTCP, ((6 << 8) | 1))

struct	in_addr zeroin_addr;

void	in_pcbremlists __P((struct inpcb *));
static void	in_rtchange __P((struct inpcb *, int));


/*
 * These configure the range of local port addresses assigned to
 * "unspecified" outgoing connections/packets/whatever.
 */
int ipport_lowfirstauto  = IPPORT_RESERVED - 1;	/* 1023 */
int ipport_lowlastauto = IPPORT_RESERVEDSTART;	/* 600 */
int ipport_firstauto = IPPORT_HIFIRSTAUTO;	/* 49152 */
int ipport_lastauto  = IPPORT_HILASTAUTO;	/* 65535 */
int ipport_hifirstauto = IPPORT_HIFIRSTAUTO;	/* 49152 */
int ipport_hilastauto  = IPPORT_HILASTAUTO;	/* 65535 */

#define RANGECHK(var, min, max) \
	if ((var) < (min)) { (var) = (min); } \
	else if ((var) > (max)) { (var) = (max); }


static int
sysctl_net_ipport_check SYSCTL_HANDLER_ARGS
{
	int error = sysctl_handle_int(oidp,
		oidp->oid_arg1, oidp->oid_arg2, req);
	if (!error) {
		RANGECHK(ipport_lowfirstauto, 1, IPPORT_RESERVED - 1);
		RANGECHK(ipport_lowlastauto, 1, IPPORT_RESERVED - 1);
		RANGECHK(ipport_firstauto, IPPORT_RESERVED, USHRT_MAX);
		RANGECHK(ipport_lastauto, IPPORT_RESERVED, USHRT_MAX);
		RANGECHK(ipport_hifirstauto, IPPORT_RESERVED, USHRT_MAX);
		RANGECHK(ipport_hilastauto, IPPORT_RESERVED, USHRT_MAX);
	}
	return error;
}

#undef RANGECHK

SYSCTL_NODE(_net_inet_ip, IPPROTO_IP, portrange, CTLFLAG_RW, 0, "IP Ports");

SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, lowfirst, CTLTYPE_INT|CTLFLAG_RW,
	   &ipport_lowfirstauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, lowlast, CTLTYPE_INT|CTLFLAG_RW,
	   &ipport_lowlastauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, first, CTLTYPE_INT|CTLFLAG_RW,
	   &ipport_firstauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, last, CTLTYPE_INT|CTLFLAG_RW,
	   &ipport_lastauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, hifirst, CTLTYPE_INT|CTLFLAG_RW,
	   &ipport_hifirstauto, 0, &sysctl_net_ipport_check, "I", "");
SYSCTL_PROC(_net_inet_ip_portrange, OID_AUTO, hilast, CTLTYPE_INT|CTLFLAG_RW,
	   &ipport_hilastauto, 0, &sysctl_net_ipport_check, "I", "");

/*
 * in_pcb.c: manage the Protocol Control Blocks.
 *
 * NOTE: It is assumed that most of these functions will be called at
 * splnet(). XXX - There are, unfortunately, a few exceptions to this
 * rule that should be fixed.
 */

/*
 * Allocate a PCB and associate it with the socket.
 */
int
in_pcballoc(so, pcbinfo, p)
	struct socket *so;
	struct inpcbinfo *pcbinfo;
	struct proc *p;
{
	register struct inpcb *inp;
	caddr_t		      temp;

	if (so->cached_in_sock_layer == 0) {
#if TEMPDEBUG
	    printf("PCBALLOC calling zalloc for socket %x\n", so);
#endif
	    inp = (struct inpcb *) zalloc(pcbinfo->ipi_zone);
	    if (inp == NULL)
		 return (ENOBUFS);
	    bzero((caddr_t)inp, sizeof(*inp));
	}
	else {
#if TEMPDEBUG
	    printf("PCBALLOC reusing PCB for socket %x\n", so);
#endif
	    inp = (struct inpcb *) so->so_saved_pcb;
	    temp = inp->inp_saved_ppcb;
	    bzero((caddr_t) inp, sizeof(*inp));
	    inp->inp_saved_ppcb = temp;
	}

	inp->inp_gencnt = ++pcbinfo->ipi_gencnt;
	inp->inp_pcbinfo = pcbinfo;
	inp->inp_socket = so;
	LIST_INSERT_HEAD(pcbinfo->listhead, inp, inp_list);
	pcbinfo->ipi_count++;
	so->so_pcb = (caddr_t)inp;
	return (0);
}

int
in_pcbbind(inp, nam, p)
	register struct inpcb *inp;
	struct sockaddr *nam;
	struct proc *p;
{
	register struct socket *so = inp->inp_socket;
	u_short *lastport;
	struct sockaddr_in *sin;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	u_short lport = 0;
	int wild = 0, reuseport = (so->so_options & SO_REUSEPORT);
	int error;

	if (TAILQ_EMPTY(&in_ifaddrhead)) /* XXX broken! */
		return (EADDRNOTAVAIL);
	if (inp->inp_lport || inp->inp_laddr.s_addr != INADDR_ANY)
		return (EINVAL);
	if ((so->so_options & (SO_REUSEADDR|SO_REUSEPORT)) == 0)
		wild = 1;
	if (nam) {
		sin = (struct sockaddr_in *)nam;
		if (nam->sa_len != sizeof (*sin))
			return (EINVAL);
#ifdef notdef
		/*
		 * We should check the family, but old programs
		 * incorrectly fail to initialize it.
		 */
		if (sin->sin_family != AF_INET)
			return (EAFNOSUPPORT);
#endif
		lport = sin->sin_port;
		if (IN_MULTICAST(ntohl(sin->sin_addr.s_addr))) {
			/*
			 * Treat SO_REUSEADDR as SO_REUSEPORT for multicast;
			 * allow complete duplication of binding if
			 * SO_REUSEPORT is set, or if SO_REUSEADDR is set
			 * and a multicast address is bound on both
			 * new and duplicated sockets.
			 */
			if (so->so_options & SO_REUSEADDR)
				reuseport = SO_REUSEADDR|SO_REUSEPORT;
		} else if (sin->sin_addr.s_addr != INADDR_ANY) {
			sin->sin_port = 0;		/* yech... */
			if (ifa_ifwithaddr((struct sockaddr *)sin) == 0)
				return (EADDRNOTAVAIL);
		}
		if (lport) {
			struct inpcb *t;

			/* GROSS */
			if (ntohs(lport) < IPPORT_RESERVED && p &&
			    suser(p->p_ucred, &p->p_acflag))
				return (EACCES);
			if (so->so_uid &&
			    !IN_MULTICAST(ntohl(sin->sin_addr.s_addr))) {
				t = in_pcblookup_local(inp->inp_pcbinfo,
				    sin->sin_addr, lport, INPLOOKUP_WILDCARD);
				if (t &&
				    (ntohl(sin->sin_addr.s_addr) != INADDR_ANY ||
				     ntohl(t->inp_laddr.s_addr) != INADDR_ANY ||
				     (t->inp_socket->so_options &
					 SO_REUSEPORT) == 0) &&
				     (so->so_uid != t->inp_socket->so_uid)) {
#if INET6
					if (ip6_mapped_addr_on == 0 ||
					    ntohl(sin->sin_addr.s_addr) !=
					    INADDR_ANY ||
					    ntohl(t->inp_laddr.s_addr) !=
					    INADDR_ANY ||
					    INP_SOCKAF(so) ==
					    INP_SOCKAF(t->inp_socket))
#endif
					return (EADDRINUSE);
				}
			}
			t = in_pcblookup_local(pcbinfo, sin->sin_addr,
			    lport, wild);
			if (t &&
			    (reuseport & t->inp_socket->so_options) == 0) {
#if INET6
				if (ip6_mapped_addr_on == 0 ||
				    ntohl(sin->sin_addr.s_addr) !=
				    INADDR_ANY ||
				    ntohl(t->inp_laddr.s_addr) !=
				    INADDR_ANY ||
				    INP_SOCKAF(so) ==
				    INP_SOCKAF(t->inp_socket))
#endif
				return (EADDRINUSE);
			}
		}
		inp->inp_laddr = sin->sin_addr;
	}
	if (lport == 0) {
		u_short first, last;
		int count;

		inp->inp_flags |= INP_ANONPORT;

		if (inp->inp_flags & INP_HIGHPORT) {
			first = ipport_hifirstauto;	/* sysctl */
			last  = ipport_hilastauto;
			lastport = &pcbinfo->lasthi;
		} else if (inp->inp_flags & INP_LOWPORT) {
			if (p && (error = suser(p->p_ucred, &p->p_acflag)))
				return error;
			first = ipport_lowfirstauto;	/* 1023 */
			last  = ipport_lowlastauto;	/* 600 */
			lastport = &pcbinfo->lastlow;
		} else {
			first = ipport_firstauto;	/* sysctl */
			last  = ipport_lastauto;
			lastport = &pcbinfo->lastport;
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
					inp->inp_laddr.s_addr = INADDR_ANY;
					return (EAGAIN);
				}
				--*lastport;
				if (*lastport > first || *lastport < last)
					*lastport = first;
				lport = htons(*lastport);
			} while (in_pcblookup_local(pcbinfo,
				 inp->inp_laddr, lport, wild));
		} else {
			/*
			 * counting up
			 */
			count = last - first;

			do {
				if (count-- < 0) {	/* completely used? */
					/*
					 * Undo any address bind that may have
					 * occurred above.
					 */
					inp->inp_laddr.s_addr = INADDR_ANY;
					return (EAGAIN);
				}
				++*lastport;
				if (*lastport < first || *lastport > last)
					*lastport = first;
				lport = htons(*lastport);
			} while (in_pcblookup_local(pcbinfo,
				 inp->inp_laddr, lport, wild));
		}
	}
	inp->inp_lport = lport;
	if (in_pcbinshash(inp) != 0) {
		inp->inp_laddr.s_addr = INADDR_ANY;
		inp->inp_lport = 0;
		return (EAGAIN);
	}
	return (0);
}

/*
 *   Transform old in_pcbconnect() into an inner subroutine for new
 *   in_pcbconnect(): Do some validity-checking on the remote
 *   address (in mbuf 'nam') and then determine local host address
 *   (i.e., which interface) to use to access that remote host.
 *
 *   This preserves definition of in_pcbconnect(), while supporting a
 *   slightly different version for T/TCP.  (This is more than
 *   a bit of a kludge, but cleaning up the internal interfaces would
 *   have forced minor changes in every protocol).
 */

int
in_pcbladdr(inp, nam, plocal_sin)
	register struct inpcb *inp;
	struct sockaddr *nam;
	struct sockaddr_in **plocal_sin;
{
	struct in_ifaddr *ia;
	register struct sockaddr_in *sin = (struct sockaddr_in *)nam;

	if (nam->sa_len != sizeof (*sin))
		return (EINVAL);
	if (sin->sin_family != AF_INET)
		return (EAFNOSUPPORT);
	if (sin->sin_port == 0)
		return (EADDRNOTAVAIL);
	if (!TAILQ_EMPTY(&in_ifaddrhead)) {
		/*
		 * If the destination address is INADDR_ANY,
		 * use the primary local address.
		 * If the supplied address is INADDR_BROADCAST,
		 * and the primary interface supports broadcast,
		 * choose the broadcast address for that interface.
		 */
#define	satosin(sa)	((struct sockaddr_in *)(sa))
#define sintosa(sin)	((struct sockaddr *)(sin))
#define ifatoia(ifa)	((struct in_ifaddr *)(ifa))
		if (sin->sin_addr.s_addr == INADDR_ANY)
		    sin->sin_addr = IA_SIN(in_ifaddrhead.tqh_first)->sin_addr;
		else if (sin->sin_addr.s_addr == (u_long)INADDR_BROADCAST &&
		  (in_ifaddrhead.tqh_first->ia_ifp->if_flags & IFF_BROADCAST))
		    sin->sin_addr = satosin(&in_ifaddrhead.tqh_first->ia_broadaddr)->sin_addr;
	}
	if (inp->inp_laddr.s_addr == INADDR_ANY) {
		register struct route *ro;

		ia = (struct in_ifaddr *)0;
		/*
		 * If route is known or can be allocated now,
		 * our src addr is taken from the i/f, else punt.
		 */
		ro = &inp->inp_route;
		if (ro->ro_rt &&
		    (satosin(&ro->ro_dst)->sin_addr.s_addr !=
			sin->sin_addr.s_addr ||
		    inp->inp_socket->so_options & SO_DONTROUTE)) {
			RTFREE(ro->ro_rt);
			ro->ro_rt = (struct rtentry *)0;
		}
		if ((inp->inp_socket->so_options & SO_DONTROUTE) == 0 && /*XXX*/
		    (ro->ro_rt == (struct rtentry *)0 ||
		    ro->ro_rt->rt_ifp == (struct ifnet *)0)) {
			/* No route yet, so try to acquire one */
			ro->ro_dst.sa_family = AF_INET;
			ro->ro_dst.sa_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in *) &ro->ro_dst)->sin_addr =
				sin->sin_addr;
			rtalloc(ro);
		}
		/*
		 * If we found a route, use the address
		 * corresponding to the outgoing interface
		 * unless it is the loopback (in case a route
		 * to our address on another net goes to loopback).
		 */
		if (ro->ro_rt && !(ro->ro_rt->rt_ifp->if_flags & IFF_LOOPBACK))
			ia = ifatoia(ro->ro_rt->rt_ifa);
		if (ia == 0) {
			u_short fport = sin->sin_port;

			sin->sin_port = 0;
			ia = ifatoia(ifa_ifwithdstaddr(sintosa(sin)));
			if (ia == 0)
				ia = ifatoia(ifa_ifwithnet(sintosa(sin)));
			sin->sin_port = fport;
			if (ia == 0)
				ia = in_ifaddrhead.tqh_first;
			if (ia == 0)
				return (EADDRNOTAVAIL);
		}
		/*
		 * If the destination address is multicast and an outgoing
		 * interface has been set as a multicast option, use the
		 * address of that interface as our source address.
		 */
		if (IN_MULTICAST(ntohl(sin->sin_addr.s_addr)) &&
		    inp->inp_moptions != NULL) {
			struct ip_moptions *imo;
			struct ifnet *ifp;

			imo = inp->inp_moptions;
			if (imo->imo_multicast_ifp != NULL) {
				ifp = imo->imo_multicast_ifp;
				for (ia = in_ifaddrhead.tqh_first; ia; 
				     ia = ia->ia_link.tqe_next)
					if (ia->ia_ifp == ifp)
						break;
				if (ia == 0)
					return (EADDRNOTAVAIL);
			}
		}
	/*
	 * Don't do pcblookup call here; return interface in plocal_sin
	 * and exit to caller, that will do the lookup.
	 */
		*plocal_sin = &ia->ia_addr;

	}
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
in_pcbconnect(inp, nam, p)
	register struct inpcb *inp;
	struct sockaddr *nam;
	struct proc *p;
{
	struct sockaddr_in *ifaddr;
	register struct sockaddr_in *sin = (struct sockaddr_in *)nam;
	int error;

	/*
	 *   Call inner routine, to assign local interface address.
	 */
	if ((error = in_pcbladdr(inp, nam, &ifaddr)) != 0)
		return(error);

	if (in_pcblookup_hash(inp->inp_pcbinfo, sin->sin_addr, sin->sin_port,
	    inp->inp_laddr.s_addr ? inp->inp_laddr : ifaddr->sin_addr,
	    inp->inp_lport, 0, NULL) != NULL) {
		return (EADDRINUSE);
	}
	if (inp->inp_laddr.s_addr == INADDR_ANY) {
		if (inp->inp_lport == 0)
			(void)in_pcbbind(inp, (struct sockaddr *)0, p);
		inp->inp_laddr = ifaddr->sin_addr;
	}
	inp->inp_faddr = sin->sin_addr;
	inp->inp_fport = sin->sin_port;
	in_pcbrehash(inp);
	return (0);
}

void
in_pcbdisconnect(inp)
	struct inpcb *inp;
{

	inp->inp_faddr.s_addr = INADDR_ANY;
	inp->inp_fport = 0;
	in_pcbrehash(inp);
	if (inp->inp_socket->so_state & SS_NOFDREF)
		in_pcbdetach(inp);
}

void
in_pcbdetach(inp)
	struct inpcb *inp;
{
	struct socket *so = inp->inp_socket;
	struct inpcbinfo *ipi = inp->inp_pcbinfo;

#if IPSEC
	ipsec4_delete_pcbpolicy(inp);
#endif /*IPSEC*/
	inp->inp_gencnt = ++ipi->ipi_gencnt;
	in_pcbremlists(inp);

#if TEMPDEBUG
	if (so->cached_in_sock_layer)
	    printf("PCB_DETACH for cached socket %x\n", so);
	else
	    printf("PCB_DETACH for allocated socket %x\n", so);
#endif

	so->so_pcb = 0;

	if (inp->inp_options)
		(void)m_free(inp->inp_options);
	if (inp->inp_route.ro_rt)
		rtfree(inp->inp_route.ro_rt);
	ip_freemoptions(inp->inp_moptions);
	if (so->cached_in_sock_layer)
	     so->so_saved_pcb = (caddr_t) inp;
	else
	     zfree(ipi->ipi_zone, (vm_offset_t) inp);

	sofree(so);
}

/*
 * The calling convention of in_setsockaddr() and in_setpeeraddr() was
 * modified to match the pru_sockaddr() and pru_peeraddr() entry points
 * in struct pr_usrreqs, so that protocols can just reference then directly
 * without the need for a wrapper function.  The socket must have a valid
 * (i.e., non-nil) PCB, but it should be impossible to get an invalid one
 * except through a kernel programming error, so it is acceptable to panic
 * (or in this case trap) if the PCB is invalid.  (Actually, we don't trap
 * because there actually /is/ a programming error somewhere... XXX)
 */
int
in_setsockaddr(so, nam)
	struct socket *so;
	struct sockaddr **nam;
{
	int s;
	register struct inpcb *inp;
	register struct sockaddr_in *sin;

	/*
	 * Do the malloc first in case it blocks.
	 */
	MALLOC(sin, struct sockaddr_in *, sizeof *sin, M_SONAME, M_WAITOK);
	if (sin == NULL)
		return ENOBUFS;
	bzero(sin, sizeof *sin);
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);

	s = splnet();
	inp = sotoinpcb(so);
	if (!inp) {
		splx(s);
		FREE(sin, M_SONAME);
		return EINVAL;
	}
	sin->sin_port = inp->inp_lport;
	sin->sin_addr = inp->inp_laddr;
	splx(s);

	*nam = (struct sockaddr *)sin;
	return 0;
}

int
in_setpeeraddr(so, nam)
	struct socket *so;
	struct sockaddr **nam;
{
	int s;
	struct inpcb *inp;
	register struct sockaddr_in *sin;

	/*
	 * Do the malloc first in case it blocks.
	 */
	MALLOC(sin, struct sockaddr_in *, sizeof *sin, M_SONAME, M_WAITOK);
	if (sin == NULL)
		return ENOBUFS;
	bzero((caddr_t)sin, sizeof (*sin));
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);

	s = splnet();
	inp = sotoinpcb(so);
	if (!inp) {
		splx(s);
		FREE(sin, M_SONAME);
		return EINVAL;
	}
	sin->sin_port = inp->inp_fport;
	sin->sin_addr = inp->inp_faddr;
	splx(s);

	*nam = (struct sockaddr *)sin;
	return 0;
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
in_pcbnotify(head, dst, fport_arg, laddr, lport_arg, cmd, notify)
	struct inpcbhead *head;
	struct sockaddr *dst;
	u_int fport_arg, lport_arg;
	struct in_addr laddr;
	int cmd;
	void (*notify) __P((struct inpcb *, int));
{
	register struct inpcb *inp, *oinp;
	struct in_addr faddr;
	u_short fport = fport_arg, lport = lport_arg;
	int errno, s;

	if ((unsigned)cmd > PRC_NCMDS || dst->sa_family != AF_INET)
		return;
	faddr = ((struct sockaddr_in *)dst)->sin_addr;
	if (faddr.s_addr == INADDR_ANY)
		return;

	/*
	 * Redirects go to all references to the destination,
	 * and use in_rtchange to invalidate the route cache.
	 * Dead host indications: notify all references to the destination.
	 * Otherwise, if we have knowledge of the local port and address,
	 * deliver only to that socket.
	 */
	if (PRC_IS_REDIRECT(cmd) || cmd == PRC_HOSTDEAD) {
		fport = 0;
		lport = 0;
		laddr.s_addr = 0;
		if (cmd != PRC_HOSTDEAD)
			notify = in_rtchange;
	}
	errno = inetctlerrmap[cmd];
	s = splnet();
	for (inp = head->lh_first; inp != NULL;) {
		if ((inp->inp_vflag & INP_IPV4) == NULL) {
			inp = LIST_NEXT(inp, inp_list);
			continue;
		}
		if (inp->inp_faddr.s_addr != faddr.s_addr ||
		    inp->inp_socket == 0 ||
		    (lport && inp->inp_lport != lport) ||
		    (laddr.s_addr && inp->inp_laddr.s_addr != laddr.s_addr) ||
		    (fport && inp->inp_fport != fport)) {
			inp = LIST_NEXT(inp, inp_list);
			continue;
		}
		oinp = inp;
		inp = LIST_NEXT(inp, inp_list);
		if (notify)
			(*notify)(oinp, errno);
	}
	splx(s);
}

/*
 * Check for alternatives when higher level complains
 * about service problems.  For now, invalidate cached
 * routing information.  If the route was created dynamically
 * (by a redirect), time to try a default gateway again.
 */
void
in_losing(inp)
	struct inpcb *inp;
{
	register struct rtentry *rt;
	struct rt_addrinfo info;

	if ((rt = inp->inp_route.ro_rt)) {
		inp->inp_route.ro_rt = 0;
		bzero((caddr_t)&info, sizeof(info));
		info.rti_info[RTAX_DST] =
			(struct sockaddr *)&inp->inp_route.ro_dst;
		info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
		info.rti_info[RTAX_NETMASK] = rt_mask(rt);
		rt_missmsg(RTM_LOSING, &info, rt->rt_flags, 0);
		if (rt->rt_flags & RTF_DYNAMIC)
			(void) rtrequest(RTM_DELETE, rt_key(rt),
				rt->rt_gateway, rt_mask(rt), rt->rt_flags,
				(struct rtentry **)0);
		else
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
static void
in_rtchange(inp, errno)
	register struct inpcb *inp;
	int errno;
{
	if (inp->inp_route.ro_rt) {
		rtfree(inp->inp_route.ro_rt);
		inp->inp_route.ro_rt = 0;
		/*
		 * A new route can be allocated the next time
		 * output is attempted.
		 */
	}
}

/*
 * Lookup a PCB based on the local address and port.
 */
struct inpcb *
in_pcblookup_local(pcbinfo, laddr, lport_arg, wild_okay)
	struct inpcbinfo *pcbinfo;
	struct in_addr laddr;
	u_int lport_arg;
	int wild_okay;
{
	register struct inpcb *inp;
	int matchwild = 3, wildcard;
	u_short lport = lport_arg;

	KERNEL_DEBUG(DBG_FNC_PCB_LOOKUP | DBG_FUNC_START, 0,0,0,0,0);

	if (!wild_okay) {
		struct inpcbhead *head;
		/*
		 * Look for an unconnected (wildcard foreign addr) PCB that
		 * matches the local address and port we're looking for.
		 */
		head = &pcbinfo->hashbase[INP_PCBHASH(INADDR_ANY, lport, 0, pcbinfo->hashmask)];
		for (inp = head->lh_first; inp != NULL; inp = inp->inp_hash.le_next) {
			if ((inp->inp_vflag & INP_IPV4) == NULL)
				continue;
			if (inp->inp_faddr.s_addr == INADDR_ANY &&
			    inp->inp_laddr.s_addr == laddr.s_addr &&
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
		KERNEL_DEBUG(DBG_FNC_PCB_LOOKUP | DBG_FUNC_END, 0,0,0,0,0);
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
		for (phd = porthash->lh_first; phd != NULL; phd = phd->phd_hash.le_next) {
			if (phd->phd_port == lport)
				break;
		}
		if (phd != NULL) {
			/*
			 * Port is in use by one or more PCBs. Look for best
			 * fit.
			 */
			for (inp = phd->phd_pcblist.lh_first; inp != NULL;
			    inp = inp->inp_portlist.le_next) {
				wildcard = 0;
				if ((inp->inp_vflag & INP_IPV4) == NULL)
					continue;
				if (inp->inp_faddr.s_addr != INADDR_ANY)
					wildcard++;
				if (inp->inp_laddr.s_addr != INADDR_ANY) {
					if (laddr.s_addr == INADDR_ANY)
						wildcard++;
					else if (inp->inp_laddr.s_addr != laddr.s_addr)
						continue;
				} else {
					if (laddr.s_addr != INADDR_ANY)
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
		KERNEL_DEBUG(DBG_FNC_PCB_LOOKUP | DBG_FUNC_END, match,0,0,0,0);
		return (match);
	}
}

/*
 * Lookup PCB in hash list.
 */
struct inpcb *
in_pcblookup_hash(pcbinfo, faddr, fport_arg, laddr, lport_arg, wildcard, ifp)
	struct inpcbinfo *pcbinfo;
	struct in_addr faddr, laddr;
	u_int fport_arg, lport_arg;
	int wildcard;
	struct ifnet *ifp;
{
	struct inpcbhead *head;
	register struct inpcb *inp;
	u_short fport = fport_arg, lport = lport_arg;

	/*
	 * We may have found the pcb in the last lookup - check this first.
	 */

	if ((!IN_MULTICAST(laddr.s_addr)) && (pcbinfo->last_pcb)) {
	    if (faddr.s_addr == pcbinfo->last_pcb->inp_faddr.s_addr &&
		laddr.s_addr == pcbinfo->last_pcb->inp_laddr.s_addr &&
		fport_arg    == pcbinfo->last_pcb->inp_fport &&
		lport_arg    == pcbinfo->last_pcb->inp_lport) {
		/*
		 * Found.
		 */
		return (pcbinfo->last_pcb);
	    }

	    pcbinfo->last_pcb = 0;
	}

	/*
	 * First look for an exact match.
	 */
	head = &pcbinfo->hashbase[INP_PCBHASH(faddr.s_addr, lport, fport, pcbinfo->hashmask)];
	for (inp = head->lh_first; inp != NULL; inp = inp->inp_hash.le_next) {
		if ((inp->inp_vflag & INP_IPV4) == NULL)
			continue;
		if (inp->inp_faddr.s_addr == faddr.s_addr &&
		    inp->inp_laddr.s_addr == laddr.s_addr &&
		    inp->inp_fport == fport &&
		    inp->inp_lport == lport) {
			/*
			 * Found.
			 */
			return (inp);
		}
	}
	if (wildcard) {
		struct inpcb *local_wild = NULL;
#if INET6
		struct inpcb *local_wild_mapped = NULL;
#endif

		head = &pcbinfo->hashbase[INP_PCBHASH(INADDR_ANY, lport, 0, pcbinfo->hashmask)];
		for (inp = head->lh_first; inp != NULL; inp = inp->inp_hash.le_next) {
			if ((inp->inp_vflag & INP_IPV4) == NULL)
				continue;
			if (inp->inp_faddr.s_addr == INADDR_ANY &&
			    inp->inp_lport == lport) {
#if defined(NFAITH) && NFAITH > 0
				if (ifp && ifp->if_type == IFT_FAITH &&
				    (inp->inp_flags & INP_FAITH) == 0)
					continue;
#endif
				if (inp->inp_laddr.s_addr == laddr.s_addr)
					return (inp);
				else if (inp->inp_laddr.s_addr == INADDR_ANY) {
#if INET6
					if (INP_CHECK_SOCKAF(inp->inp_socket,
							     AF_INET6))
						local_wild_mapped = inp;
					else
#endif
					local_wild = inp;
				}
			}
		}
#if INET6
		if (local_wild == NULL)
			return (local_wild_mapped);
#endif
		return (local_wild);
	}

	/*
	 * Not found.
	 */
	return (NULL);
}

/*
 * Insert PCB onto various hash lists.
 */
int
in_pcbinshash(inp)
	struct inpcb *inp;
{
	struct inpcbhead *pcbhash;
	struct inpcbporthead *pcbporthash;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	struct inpcbport *phd;
	u_int32_t hashkey_faddr;

#if INET6
	if (inp->inp_vflag & INP_IPV6)
		hashkey_faddr = inp->in6p_faddr.s6_addr32[3] /* XXX */;
	else
#endif /* INET6 */
	hashkey_faddr = inp->inp_faddr.s_addr;

	pcbhash = &pcbinfo->hashbase[INP_PCBHASH(hashkey_faddr,
		 inp->inp_lport, inp->inp_fport, pcbinfo->hashmask)];

	pcbporthash = &pcbinfo->porthashbase[INP_PCBPORTHASH(inp->inp_lport,
	    pcbinfo->porthashmask)];

	/*
	 * Go through port list and look for a head for this lport.
	 */
	for (phd = pcbporthash->lh_first; phd != NULL; phd = phd->phd_hash.le_next) {
		if (phd->phd_port == inp->inp_lport)
			break;
	}
	/*
	 * If none exists, malloc one and tack it on.
	 */
	if (phd == NULL) {
		MALLOC(phd, struct inpcbport *, sizeof(struct inpcbport), M_PCB, M_WAITOK);
		if (phd == NULL) {
			return (ENOBUFS); /* XXX */
		}
		phd->phd_port = inp->inp_lport;
		LIST_INIT(&phd->phd_pcblist);
		LIST_INSERT_HEAD(pcbporthash, phd, phd_hash);
	}
	inp->inp_phd = phd;
	LIST_INSERT_HEAD(&phd->phd_pcblist, inp, inp_portlist);
	LIST_INSERT_HEAD(pcbhash, inp, inp_hash);
	inp->hash_element = INP_PCBHASH(inp->inp_faddr.s_addr, inp->inp_lport, 
					inp->inp_fport, pcbinfo->hashmask);
	return (0);
}

/*
 * Move PCB to the proper hash bucket when { faddr, fport } have  been
 * changed. NOTE: This does not handle the case of the lport changing (the
 * hashed port list would have to be updated as well), so the lport must
 * not change after in_pcbinshash() has been called.
 */
void
in_pcbrehash(inp)
	struct inpcb *inp;
{
	struct inpcbhead *head;
	u_int32_t hashkey_faddr;

#if INET6
	if (inp->inp_vflag & INP_IPV6)
		hashkey_faddr = inp->in6p_faddr.s6_addr32[3] /* XXX */;
	else
#endif /* INET6 */
	hashkey_faddr = inp->inp_faddr.s_addr;

	head = &inp->inp_pcbinfo->hashbase[INP_PCBHASH(hashkey_faddr,
		inp->inp_lport, inp->inp_fport, inp->inp_pcbinfo->hashmask)];

	LIST_REMOVE(inp, inp_hash);
	LIST_INSERT_HEAD(head, inp, inp_hash);
	inp->hash_element = INP_PCBHASH(inp->inp_faddr.s_addr, inp->inp_lport, 
					inp->inp_fport, inp->inp_pcbinfo->hashmask);
}

/*
 * Remove PCB from various lists.
 */
void
in_pcbremlists(inp)
	struct inpcb *inp;
{
	inp->inp_gencnt = ++inp->inp_pcbinfo->ipi_gencnt;
	if (inp == inp->inp_pcbinfo->last_pcb)
	    inp->inp_pcbinfo->last_pcb = 0;

	if (inp->inp_lport) {
		struct inpcbport *phd = inp->inp_phd;

		LIST_REMOVE(inp, inp_hash);
		LIST_REMOVE(inp, inp_portlist);
		if (phd->phd_pcblist.lh_first == NULL) {
			LIST_REMOVE(phd, phd_hash);
			FREE(phd, M_PCB);
		}
	}

	LIST_REMOVE(inp, inp_list);
	inp->inp_pcbinfo->ipi_count--;
}

int	
in_pcb_grab_port  __P((struct inpcbinfo *pcbinfo,
		       u_short          options,
		       struct in_addr	laddr, 
		       u_short		*lport,
		       struct in_addr	faddr,
		       u_short		fport,
		       u_int		cookie, 
		       u_char		owner_id))
{
    struct inpcb  *pcb;
    struct sockaddr_in sin;
    struct proc *p = current_proc();
    int  stat;


    pcbinfo->nat_dummy_socket.so_pcb = 0;
    pcbinfo->nat_dummy_socket.so_options = 0;
    if (*lport) {
	/* The grabber wants a particular port */

	if (faddr.s_addr || fport) {
	    /*
	     * This is either the second half of an active connect, or
	     * it's from the acceptance of an incoming connection.
	    */	
	    if (laddr.s_addr == 0) {
		return EINVAL;
	    }

	    if (in_pcblookup_hash(pcbinfo, faddr, fport,
				  laddr, *lport, 0, NULL) != NULL) {
		if (!(IN_MULTICAST(ntohl(laddr.s_addr)))) {
		    return (EADDRINUSE);
		}
	    }
	    
	    stat = in_pcballoc(&pcbinfo->nat_dummy_socket, pcbinfo, p);
	    if (stat)
	        return stat;
	    pcb = sotoinpcb(&pcbinfo->nat_dummy_socket);
	    pcb->inp_vflag |= INP_IPV4;

	    pcb->inp_lport = *lport;
	    pcb->inp_laddr.s_addr = laddr.s_addr;

	    pcb->inp_faddr = faddr;
	    pcb->inp_fport = fport;
	    in_pcbinshash(pcb);
	}
	else {
	    /*
	     * This is either a bind for a passive socket, or it's the 
	     * first part of bind-connect sequence (not likely since an 
	     * ephemeral port is usually used in this case). Or, it's
	     * the result of a connection acceptance when the foreign
	     * address/port cannot be provided (which requires the SO_REUSEADDR
	     * flag if laddr is not multicast).
	     */

	    stat = in_pcballoc(&pcbinfo->nat_dummy_socket, pcbinfo, p);
	    if (stat)
		return stat;
	    pcb = sotoinpcb(&pcbinfo->nat_dummy_socket);
	    pcb->inp_vflag |= INP_IPV4;

	    pcbinfo->nat_dummy_socket.so_options = options; 
	    bzero(&sin, sizeof(struct sockaddr_in));
	    sin.sin_len = sizeof(struct sockaddr_in);
	    sin.sin_family = AF_INET;
	    sin.sin_addr.s_addr = laddr.s_addr;
	    sin.sin_port = *lport;

	    stat = in_pcbbind((struct inpcb *) pcbinfo->nat_dummy_socket.so_pcb, 
			      (struct sockaddr *) &sin, p);
	    if (stat) {
		in_pcbdetach(pcb);
		return stat;
	    }
	}
    }
    else {
	/* The grabber wants an ephemeral port */

	stat = in_pcballoc(&pcbinfo->nat_dummy_socket, pcbinfo, p);
	if (stat)
	    return stat;
	pcb = sotoinpcb(&pcbinfo->nat_dummy_socket);
	pcb->inp_vflag |= INP_IPV4;

	bzero(&sin, sizeof(struct sockaddr_in));
	sin.sin_len = sizeof(struct sockaddr_in);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = laddr.s_addr;
	sin.sin_port = 0;

	if (faddr.s_addr || fport) {
	    /*
	     * Not sure if this case will be used - could occur when connect
	     * is called, skipping the bind.
	     */

	    if (laddr.s_addr == 0) {
		in_pcbdetach(pcb);
		return EINVAL;
	    }

	    stat = in_pcbbind((struct inpcb *) pcbinfo->nat_dummy_socket.so_pcb, 
			      (struct sockaddr *) &sin, p);
	    if (stat) {
		in_pcbdetach(pcb);
		return stat;
	    }

	    if (in_pcblookup_hash(pcbinfo, faddr, fport,
				  pcb->inp_laddr, pcb->inp_lport, 0, NULL) != NULL) {
		in_pcbdetach(pcb);
		return (EADDRINUSE);
	    }
	    
	    pcb->inp_faddr = faddr;
	    pcb->inp_fport = fport;
	    in_pcbrehash(pcb);
	}
	else {
	    /*
	     * This is a simple bind of an ephemeral port. The local addr
	     * may or may not be defined.
	     */
	    
	    stat = in_pcbbind((struct inpcb *) pcbinfo->nat_dummy_socket.so_pcb, 
			      (struct sockaddr *) &sin, p);
	    if (stat) {
		in_pcbdetach(pcb);
		return stat;
	    }
	}
	*lport = pcb->inp_lport;
    }
    

    pcb->nat_owner = owner_id;
    pcb->nat_cookie = cookie;
    pcb->inp_ppcb = (caddr_t) pcbinfo->dummy_cb;
    return 0;
}

int	
in_pcb_letgo_port __P((struct inpcbinfo *pcbinfo, struct in_addr laddr, u_short lport,
		       struct in_addr faddr, u_short fport, u_char owner_id))
{
    struct inpcbhead *head;
    register struct inpcb *inp;


    /*
     * First look for an exact match.
     */
    head = &pcbinfo->hashbase[INP_PCBHASH(faddr.s_addr, lport, fport, pcbinfo->hashmask)];
    for (inp = head->lh_first; inp != NULL; inp = inp->inp_hash.le_next) {
	if (inp->inp_faddr.s_addr == faddr.s_addr &&
	    inp->inp_laddr.s_addr == laddr.s_addr &&
	    inp->inp_fport == fport &&
	    inp->inp_lport == lport &&
	    inp->nat_owner == owner_id) {
	    /*
	     * Found.
	     */
	    in_pcbdetach(inp);
	    return 0;
	}
    }

    return ENOENT;
}

u_char	
in_pcb_get_owner(struct inpcbinfo *pcbinfo,
		 struct in_addr laddr, u_short lport,
		 struct in_addr faddr, u_short fport,
		 u_int	 *cookie)

{
    struct inpcb *inp;
    u_char       owner_id = INPCB_NO_OWNER;
    struct	 inpcbport *phd;
    struct inpcbporthead *porthash;


    if (IN_MULTICAST(laddr.s_addr)) {
	/*
	 * Walk through PCB's looking for registered
	 * owners.
	*/

	porthash = &pcbinfo->porthashbase[INP_PCBPORTHASH(lport,
							  pcbinfo->porthashmask)];
	for (phd = porthash->lh_first; phd != NULL; phd = phd->phd_hash.le_next) {
	    if (phd->phd_port == lport)
		break;
	}

	if (phd == 0) {
	    return INPCB_NO_OWNER;
	}
		
	owner_id = INPCB_NO_OWNER;
	for (inp = phd->phd_pcblist.lh_first; inp != NULL;
	     inp = inp->inp_portlist.le_next) {

	    if (inp->inp_laddr.s_addr == laddr.s_addr) {
		if (inp->nat_owner == 0) 
		    owner_id |= INPCB_OWNED_BY_X;
		else
		    owner_id |= inp->nat_owner;
	    }
	}

	return owner_id;
    }
    else {
	inp = in_pcblookup_hash(pcbinfo, faddr, fport,
				laddr, lport, 1, NULL);
	if (inp) {
	    if (inp->nat_owner) {
		owner_id = inp->nat_owner;
		*cookie   = inp->nat_cookie;
	    }
	    else {
		pcbinfo->last_pcb = inp;
		owner_id = INPCB_OWNED_BY_X;
	    }
	}
	else 
	    owner_id = INPCB_NO_OWNER;

	return owner_id;
    }
}

int
in_pcb_new_share_client(struct inpcbinfo *pcbinfo, u_char *owner_id)
{

    int i;


    for (i=0; i < INPCB_MAX_IDS; i++) {
	if ((pcbinfo->all_owners & (1 << i)) == 0) {
	    pcbinfo->all_owners |= (1 << i);
	    *owner_id = (1 << i);
	    return 0;
	}
    }

    return ENOSPC;
}		

int
in_pcb_rem_share_client(struct inpcbinfo *pcbinfo, u_char owner_id)
{
    struct inpcb *inp;


    if (pcbinfo->all_owners & owner_id) {
	pcbinfo->all_owners &= ~owner_id;
	for (inp = pcbinfo->listhead->lh_first; inp != NULL; inp = inp->inp_list.le_next) {
	    if (inp->nat_owner & owner_id) {
		if (inp->nat_owner == owner_id) 
		    /*
		     * Deallocate the pcb
		     */
		    in_pcbdetach(inp);
		else
		    inp->nat_owner &= ~owner_id;
	    }
	}
    }
    else {
	return ENOENT;
    }

    return 0;
}

void  in_pcb_nat_init(struct inpcbinfo *pcbinfo, int afamily, 
		      int pfamily, int protocol)
{
    bzero(&pcbinfo->nat_dummy_socket, sizeof(struct socket));
    pcbinfo->nat_dummy_socket.so_proto = pffindproto(afamily, pfamily, protocol);
    pcbinfo->all_owners = 0;
}
