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
 * $FreeBSD: src/sys/netinet/in_pcb.c,v 1.59.2.17 2001/08/13 16:26:17 ume Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/proc.h>
#ifndef __APPLE__
#include <sys/jail.h>
#endif
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <libkern/OSAtomic.h>

#include <machine/limits.h>

#ifdef __APPLE__
#include <kern/zalloc.h>
#endif

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>

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
#endif /* IPSEC */

#include <sys/kdebug.h>
#include <sys/random.h>

#if IPSEC
extern int ipsec_bypass;
#endif

#define DBG_FNC_PCB_LOOKUP	NETDBG_CODE(DBG_NETTCP, (6 << 8))
#define DBG_FNC_PCB_HLOOKUP	NETDBG_CODE(DBG_NETTCP, ((6 << 8) | 1))

struct	in_addr zeroin_addr;

/*
 * These configure the range of local port addresses assigned to
 * "unspecified" outgoing connections/packets/whatever.
 */
int	ipport_lowfirstauto  = IPPORT_RESERVED - 1;	/* 1023 */
int	ipport_lowlastauto = IPPORT_RESERVEDSTART;	/* 600 */
#ifndef __APPLE__
int	ipport_firstauto = IPPORT_RESERVED;		/* 1024 */
int	ipport_lastauto  = IPPORT_USERRESERVED;		/* 5000 */
#else
int 	ipport_firstauto = IPPORT_HIFIRSTAUTO;      	/* 49152 */
int 	ipport_lastauto  = IPPORT_HILASTAUTO;       	/* 65535 */
#endif
int	ipport_hifirstauto = IPPORT_HIFIRSTAUTO;	/* 49152 */
int	ipport_hilastauto  = IPPORT_HILASTAUTO;		/* 65535 */

#define RANGECHK(var, min, max) \
	if ((var) < (min)) { (var) = (min); } \
	else if ((var) > (max)) { (var) = (max); }

static int
sysctl_net_ipport_check SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
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

SYSCTL_NODE(_net_inet_ip, IPPROTO_IP, portrange, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "IP Ports");

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

extern int	udp_use_randomport;
extern int	tcp_use_randomport;

/*
 * in_pcb.c: manage the Protocol Control Blocks.
 *
 * NOTE: It is assumed that most of these functions will be called at
 * splnet(). XXX - There are, unfortunately, a few exceptions to this
 * rule that should be fixed.
 */

/*
 * Allocate a PCB and associate it with the socket.
 *
 * Returns:	0			Success
 *		ENOBUFS
 *		ENOMEM
 *	ipsec_init_policy:???		[IPSEC]
 */
int
in_pcballoc(struct socket *so, struct inpcbinfo *pcbinfo, __unused struct proc *p)
{
	struct inpcb *inp;
	caddr_t		      temp;
#if IPSEC
#ifndef __APPLE__
	int error;
#endif
#endif
#if CONFIG_MACF_NET
	int mac_error;
#endif

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
#if CONFIG_MACF_NET
	mac_error = mac_inpcb_label_init(inp, M_WAITOK);
	if (mac_error != 0) {
		if (so->cached_in_sock_layer == 0)
			zfree(pcbinfo->ipi_zone, inp);
		return (mac_error);
	}
	mac_inpcb_label_associate(so, inp);
#endif
	so->so_pcb = (caddr_t)inp;

	if (so->so_proto->pr_flags & PR_PCBLOCK) {
		inp->inpcb_mtx = lck_mtx_alloc_init(pcbinfo->mtx_grp, pcbinfo->mtx_attr);
		if (inp->inpcb_mtx == NULL) {
			printf("in_pcballoc: can't alloc mutex! so=%p\n", so);
			return(ENOMEM);
		}
	}

#if IPSEC
#ifndef __APPLE__
	if (ipsec_bypass == 0) {
		error = ipsec_init_policy(so, &inp->inp_sp);
		if (error != 0) {
			zfree(pcbinfo->ipi_zone, inp);
			return error;
		}
	}
#endif
#endif /*IPSEC*/
#if INET6
	if (INP_SOCKAF(so) == AF_INET6 && !ip6_mapped_addr_on)
		inp->inp_flags |= IN6P_IPV6_V6ONLY;
#endif
	
#if INET6
	if (ip6_auto_flowlabel)
		inp->inp_flags |= IN6P_AUTOFLOWLABEL;
#endif
	lck_rw_lock_exclusive(pcbinfo->mtx);
	inp->inp_gencnt = ++pcbinfo->ipi_gencnt;
	LIST_INSERT_HEAD(pcbinfo->listhead, inp, inp_list);
	pcbinfo->ipi_count++;
	lck_rw_done(pcbinfo->mtx);
	return (0);
}


/*
  in_pcblookup_local_and_cleanup does everything
  in_pcblookup_local does but it checks for a socket
  that's going away. Since we know that the lock is
  held read+write when this funciton is called, we
  can safely dispose of this socket like the slow
  timer would usually do and return NULL. This is
  great for bind.
*/
struct inpcb*
in_pcblookup_local_and_cleanup(
	struct inpcbinfo *pcbinfo,
	struct in_addr laddr,
	u_int lport_arg,
	int wild_okay)
{
	struct inpcb *inp;
	
	/* Perform normal lookup */
	inp = in_pcblookup_local(pcbinfo, laddr, lport_arg, wild_okay);
	
	/* Check if we found a match but it's waiting to be disposed */
	if (inp && inp->inp_wantcnt == WNT_STOPUSING) {
		struct socket *so = inp->inp_socket;
		
		lck_mtx_lock(inp->inpcb_mtx);
		
		if (so->so_usecount == 0) {
			if (inp->inp_state != INPCB_STATE_DEAD)
				in_pcbdetach(inp);
			in_pcbdispose(inp);
			inp = NULL;
		}
		else {
			lck_mtx_unlock(inp->inpcb_mtx);
		}
	}
	
	return inp;
}

#ifdef __APPLE_API_PRIVATE
static void
in_pcb_conflict_post_msg(u_int16_t port)
{
	/* 
	 * Radar 5523020 send a kernel event notification if a non-participating socket tries to bind
	 * 		 the port a socket who has set SOF_NOTIFYCONFLICT owns.
	 */
	struct kev_msg        ev_msg;
	struct kev_in_portinuse	in_portinuse;

	in_portinuse.port = ntohs(port);	/* port in host order */
	in_portinuse.req_pid = proc_selfpid();
	ev_msg.vendor_code = KEV_VENDOR_APPLE;
	ev_msg.kev_class = KEV_NETWORK_CLASS;
	ev_msg.kev_subclass = KEV_INET_SUBCLASS;
	ev_msg.event_code = KEV_INET_PORTINUSE;
	ev_msg.dv[0].data_ptr = &in_portinuse;
	ev_msg.dv[0].data_length      = sizeof(struct kev_in_portinuse);
	ev_msg.dv[1].data_length = 0;
	kev_post_msg(&ev_msg);
}
#endif
/*
 * Returns:	0			Success
 *		EADDRNOTAVAIL		Address not available.
 *		EINVAL			Invalid argument
 *		EAFNOSUPPORT		Address family not supported [notdef]
 *		EACCES			Permission denied
 *		EADDRINUSE		Address in use
 *		EAGAIN			Resource unavailable, try again
 *		proc_suser:EPERM	Operation not permitted
 */
int
in_pcbbind(struct inpcb *inp, struct sockaddr *nam, struct proc *p)
{
	struct socket *so = inp->inp_socket;
	unsigned short *lastport;
	struct sockaddr_in *sin;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	u_short lport = 0, rand_port = 0;
	int wild = 0, reuseport = (so->so_options & SO_REUSEPORT);
	int error, randomport, conflict = 0;

	if (TAILQ_EMPTY(&in_ifaddrhead)) /* XXX broken! */
		return (EADDRNOTAVAIL);
	if (inp->inp_lport || inp->inp_laddr.s_addr != INADDR_ANY)
		return (EINVAL);
	if ((so->so_options & (SO_REUSEADDR|SO_REUSEPORT)) == 0)
		wild = 1;
	socket_unlock(so, 0); /* keep reference on socket */
	lck_rw_lock_exclusive(pcbinfo->mtx);
	if (nam) {
		sin = (struct sockaddr_in *)nam;
		if (nam->sa_len != sizeof (*sin)) {
			lck_rw_done(pcbinfo->mtx);
			socket_lock(so, 0);
			return (EINVAL);
		}
#ifdef notdef
		/*
		 * We should check the family, but old programs
		 * incorrectly fail to initialize it.
		 */
		if (sin->sin_family != AF_INET) {
			lck_rw_done(pcbinfo->mtx);
			socket_lock(so, 0);
			return (EAFNOSUPPORT);
		}
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
			struct ifaddr *ifa;
			sin->sin_port = 0;		/* yech... */
			if ((ifa = ifa_ifwithaddr((struct sockaddr *)sin)) == 0) {
				lck_rw_done(pcbinfo->mtx);
				socket_lock(so, 0);
				return (EADDRNOTAVAIL);
			}
			else {
				ifafree(ifa);
			}
		}
		if (lport) {
			struct inpcb *t;

			/* GROSS */
#if !CONFIG_EMBEDDED
			if (ntohs(lport) < IPPORT_RESERVED && proc_suser(p)) {
				lck_rw_done(pcbinfo->mtx);
				socket_lock(so, 0);
				return (EACCES);
			}
#endif
			if (so->so_uid &&
			    !IN_MULTICAST(ntohl(sin->sin_addr.s_addr))) {
				t = in_pcblookup_local_and_cleanup(inp->inp_pcbinfo,
				    sin->sin_addr, lport, INPLOOKUP_WILDCARD);
				if (t &&
				    (ntohl(sin->sin_addr.s_addr) != INADDR_ANY ||
				     ntohl(t->inp_laddr.s_addr) != INADDR_ANY ||
				     (t->inp_socket->so_options &
					 SO_REUSEPORT) == 0) &&
				     (so->so_uid != t->inp_socket->so_uid) &&
				      ((t->inp_socket->so_flags & SOF_REUSESHAREUID) == 0)) {
#if INET6
					if (ntohl(sin->sin_addr.s_addr) !=
					    INADDR_ANY ||
					    ntohl(t->inp_laddr.s_addr) !=
					    INADDR_ANY ||
					    INP_SOCKAF(so) ==
					    INP_SOCKAF(t->inp_socket))
#endif /* INET6 */
					{
#ifdef __APPLE_API_PRIVATE

						if ((t->inp_socket->so_flags & SOF_NOTIFYCONFLICT) && ((so->so_flags & SOF_NOTIFYCONFLICT) == 0)) 
							conflict = 1;

						lck_rw_done(pcbinfo->mtx);

						if (conflict)
							in_pcb_conflict_post_msg(lport);
#else
						lck_rw_done(pcbinfo->mtx);
#endif /* __APPLE_API_PRIVATE */

						socket_lock(so, 0);
						return (EADDRINUSE);
					}
				}
			}
			t = in_pcblookup_local_and_cleanup(pcbinfo, sin->sin_addr,
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
#endif /* INET6 */
				{
#ifdef __APPLE_API_PRIVATE

					if ((t->inp_socket->so_flags & SOF_NOTIFYCONFLICT) && ((so->so_flags & SOF_NOTIFYCONFLICT) == 0)) 
						conflict = 1;

					lck_rw_done(pcbinfo->mtx);

					if (conflict)
						in_pcb_conflict_post_msg(lport);
#else
					lck_rw_done(pcbinfo->mtx);
#endif /* __APPLE_API_PRIVATE */
					socket_lock(so, 0);
					return (EADDRINUSE);
				}
			}
		}
		inp->inp_laddr = sin->sin_addr;
	}
	if (lport == 0) {
		u_short first, last;
		int count;

		randomport = (so->so_flags & SOF_BINDRANDOMPORT) || 
			(so->so_type == SOCK_STREAM ? tcp_use_randomport : udp_use_randomport);

		inp->inp_flags |= INP_ANONPORT;

		if (inp->inp_flags & INP_HIGHPORT) {
			first = ipport_hifirstauto;	/* sysctl */
			last  = ipport_hilastauto;
			lastport = &pcbinfo->lasthi;
		} else if (inp->inp_flags & INP_LOWPORT) {
			if ((error = proc_suser(p)) != 0) {
				lck_rw_done(pcbinfo->mtx);
				socket_lock(so, 0);
				return error;
			}
			first = ipport_lowfirstauto;	/* 1023 */
			last  = ipport_lowlastauto;	/* 600 */
			lastport = &pcbinfo->lastlow;
		} else {
			first = ipport_firstauto;	/* sysctl */
			last  = ipport_lastauto;
			lastport = &pcbinfo->lastport;
		}
		/* No point in randomizing if only one port is available */

		if (first == last)
			randomport = 0; 
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
			if (randomport) {
				read_random(&rand_port, sizeof(rand_port));
				*lastport = first - (rand_port % (first - last));
			}
			count = first - last;

			do {
				if (count-- < 0) {	/* completely used? */
					lck_rw_done(pcbinfo->mtx);
					socket_lock(so, 0);
					inp->inp_laddr.s_addr = INADDR_ANY;
					return (EADDRNOTAVAIL);
				}
				--*lastport;
				if (*lastport > first || *lastport < last)
					*lastport = first;
				lport = htons(*lastport);
			} while (in_pcblookup_local_and_cleanup(pcbinfo,
				 inp->inp_laddr, lport, wild));
		} else {
			/*
			 * counting up
			 */
			if (randomport) {
				read_random(&rand_port, sizeof(rand_port));
				*lastport = first + (rand_port % (first - last));
			}
			count = last - first;

			do {
				if (count-- < 0) {	/* completely used? */
					lck_rw_done(pcbinfo->mtx);
					socket_lock(so, 0);
					inp->inp_laddr.s_addr = INADDR_ANY;
					return (EADDRNOTAVAIL);
				}
				++*lastport;
				if (*lastport < first || *lastport > last)
					*lastport = first;
				lport = htons(*lastport);
			} while (in_pcblookup_local_and_cleanup(pcbinfo,
				 inp->inp_laddr, lport, wild));
		}
	}
	socket_lock(so, 0);
	inp->inp_lport = lport;
	if (in_pcbinshash(inp, 1) != 0) {
		inp->inp_laddr.s_addr = INADDR_ANY;
		inp->inp_lport = 0;
		lck_rw_done(pcbinfo->mtx);
		return (EAGAIN);
	}
	lck_rw_done(pcbinfo->mtx);
	sflt_notify(so, sock_evt_bound, NULL);
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
 *
 * Returns:	0			Success
 *		EINVAL			Invalid argument
 *		EAFNOSUPPORT		Address family not supported
 *		EADDRNOTAVAIL		Address not available
 */
int
in_pcbladdr(struct inpcb *inp, struct sockaddr *nam,
	    struct sockaddr_in **plocal_sin)
{
	struct in_ifaddr *ia;
	struct sockaddr_in *sin = (struct sockaddr_in *)nam;

	if (nam->sa_len != sizeof (*sin))
		return (EINVAL);
	if (sin->sin_family != AF_INET)
		return (EAFNOSUPPORT);
	if (sin->sin_port == 0)
		return (EADDRNOTAVAIL);

	lck_rw_lock_shared(in_ifaddr_rwlock);
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
		    sin->sin_addr = IA_SIN(TAILQ_FIRST(&in_ifaddrhead))->sin_addr;
		else if (sin->sin_addr.s_addr == (u_int32_t)INADDR_BROADCAST &&
		  (TAILQ_FIRST(&in_ifaddrhead)->ia_ifp->if_flags & IFF_BROADCAST))
		    sin->sin_addr = satosin(&TAILQ_FIRST(&in_ifaddrhead)->ia_broadaddr)->sin_addr;
	}
	lck_rw_done(in_ifaddr_rwlock);

	if (inp->inp_laddr.s_addr == INADDR_ANY) {
		struct route *ro;
		unsigned int ifscope;

		ia = (struct in_ifaddr *)0;
		ifscope = (inp->inp_flags & INP_BOUND_IF) ?
		    inp->inp_boundif : IFSCOPE_NONE;
		/*
		 * If route is known or can be allocated now,
		 * our src addr is taken from the i/f, else punt.
		 * Note that we should check the address family of the cached
		 * destination, in case of sharing the cache with IPv6.
		 */
		ro = &inp->inp_route;
		if (ro->ro_rt != NULL)
			RT_LOCK_SPIN(ro->ro_rt);
		if (ro->ro_rt && (ro->ro_dst.sa_family != AF_INET ||
		    satosin(&ro->ro_dst)->sin_addr.s_addr !=
		    sin->sin_addr.s_addr ||
		    inp->inp_socket->so_options & SO_DONTROUTE ||
		    ro->ro_rt->generation_id != route_generation)) {
			RT_UNLOCK(ro->ro_rt);
			rtfree(ro->ro_rt);
			ro->ro_rt = NULL;
		}
		if ((inp->inp_socket->so_options & SO_DONTROUTE) == 0 && /*XXX*/
		    (ro->ro_rt == NULL || ro->ro_rt->rt_ifp == NULL)) {
			if (ro->ro_rt != NULL)
				RT_UNLOCK(ro->ro_rt);
			/* No route yet, so try to acquire one */
			bzero(&ro->ro_dst, sizeof(struct sockaddr_in));
			ro->ro_dst.sa_family = AF_INET;
			ro->ro_dst.sa_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in *) &ro->ro_dst)->sin_addr =
				sin->sin_addr;
			rtalloc_scoped_ign(ro, 0, ifscope);
			if (ro->ro_rt != NULL)
				RT_LOCK_SPIN(ro->ro_rt);
		}
		/*
		 * If we found a route, use the address
		 * corresponding to the outgoing interface
		 * unless it is the loopback (in case a route
		 * to our address on another net goes to loopback).
		 */
		if (ro->ro_rt != NULL) {
			RT_LOCK_ASSERT_HELD(ro->ro_rt);
			if (!(ro->ro_rt->rt_ifp->if_flags & IFF_LOOPBACK)) {
				ia = ifatoia(ro->ro_rt->rt_ifa);
				if (ia)
					ifaref(&ia->ia_ifa);
			}
			RT_UNLOCK(ro->ro_rt);
		}
		if (ia == 0) {
			u_short fport = sin->sin_port;

			sin->sin_port = 0;
			ia = ifatoia(ifa_ifwithdstaddr(sintosa(sin)));
			if (ia == 0) {
				ia = ifatoia(ifa_ifwithnet_scoped(sintosa(sin),
				    ifscope));
			}
			sin->sin_port = fport;
			if (ia == 0) {
				lck_rw_lock_shared(in_ifaddr_rwlock);
				ia = TAILQ_FIRST(&in_ifaddrhead);
				if (ia)
					ifaref(&ia->ia_ifa);
				lck_rw_done(in_ifaddr_rwlock);
			}
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
			if (imo->imo_multicast_ifp != NULL && (ia == NULL ||
				ia->ia_ifp != imo->imo_multicast_ifp)) {
				ifp = imo->imo_multicast_ifp;
				if (ia)
					ifafree(&ia->ia_ifa);
				lck_rw_lock_shared(in_ifaddr_rwlock);
				TAILQ_FOREACH(ia, &in_ifaddrhead, ia_link) {
					if (ia->ia_ifp == ifp)
						break;
				}
				if (ia)
					ifaref(&ia->ia_ifa);
				lck_rw_done(in_ifaddr_rwlock);
				if (ia == 0)
					return (EADDRNOTAVAIL);
			}
		}
		/*
		 * Don't do pcblookup call here; return interface in plocal_sin
		 * and exit to caller, that will do the lookup.
		 */
		*plocal_sin = &ia->ia_addr;
		ifafree(&ia->ia_ifa);
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
in_pcbconnect(struct inpcb *inp, struct sockaddr *nam, struct proc *p)
{
	struct sockaddr_in *ifaddr;
	struct sockaddr_in *sin = (struct sockaddr_in *)nam;
	struct inpcb *pcb;
	int error;

	/*
	 *   Call inner routine, to assign local interface address.
	 */
	if ((error = in_pcbladdr(inp, nam, &ifaddr)) != 0)
		return(error);

	socket_unlock(inp->inp_socket, 0);
	pcb = in_pcblookup_hash(inp->inp_pcbinfo, sin->sin_addr, sin->sin_port,
	    inp->inp_laddr.s_addr ? inp->inp_laddr : ifaddr->sin_addr,
	    inp->inp_lport, 0, NULL);
	socket_lock(inp->inp_socket, 0);
	if (pcb != NULL) {
		in_pcb_checkstate(pcb, WNT_RELEASE, pcb == inp ? 1 : 0);
		return (EADDRINUSE);
	}
	if (inp->inp_laddr.s_addr == INADDR_ANY) {
		if (inp->inp_lport == 0) {
			error = in_pcbbind(inp, (struct sockaddr *)0, p);
			if (error)
			    return (error);
		}
		if (!lck_rw_try_lock_exclusive(inp->inp_pcbinfo->mtx)) {
			/*lock inversion issue, mostly with udp multicast packets */
			socket_unlock(inp->inp_socket, 0);
			lck_rw_lock_exclusive(inp->inp_pcbinfo->mtx);
			socket_lock(inp->inp_socket, 0);
		}
		inp->inp_laddr = ifaddr->sin_addr;
		inp->inp_flags |= INP_INADDR_ANY;
	}
	 else {
		if (!lck_rw_try_lock_exclusive(inp->inp_pcbinfo->mtx)) {
			/*lock inversion issue, mostly with udp multicast packets */
			socket_unlock(inp->inp_socket, 0);
			lck_rw_lock_exclusive(inp->inp_pcbinfo->mtx);
			socket_lock(inp->inp_socket, 0);
		}
	}
	inp->inp_faddr = sin->sin_addr;
	inp->inp_fport = sin->sin_port;
	in_pcbrehash(inp);
	lck_rw_done(inp->inp_pcbinfo->mtx);
	return (0);
}

void
in_pcbdisconnect(struct inpcb *inp)
{

	inp->inp_faddr.s_addr = INADDR_ANY;
	inp->inp_fport = 0;

	if (!lck_rw_try_lock_exclusive(inp->inp_pcbinfo->mtx)) {
		/*lock inversion issue, mostly with udp multicast packets */
		socket_unlock(inp->inp_socket, 0);
		lck_rw_lock_exclusive(inp->inp_pcbinfo->mtx);
		socket_lock(inp->inp_socket, 0);
	}

	in_pcbrehash(inp);
	lck_rw_done(inp->inp_pcbinfo->mtx);

	if (inp->inp_socket->so_state & SS_NOFDREF) 
		in_pcbdetach(inp);
}

void
in_pcbdetach(struct inpcb *inp)
{
	struct socket *so = inp->inp_socket;

	if (so->so_pcb == 0) { /* we've been called twice */
		panic("in_pcbdetach: inp=%p so=%p proto=%d so_pcb is null!\n",
			inp, so, so->so_proto->pr_protocol);
	}

#if IPSEC
	if (ipsec_bypass == 0) {
		ipsec4_delete_pcbpolicy(inp);
	}
#endif /*IPSEC*/

	/* mark socket state as dead */
	if (in_pcb_checkstate(inp, WNT_STOPUSING, 1) != WNT_STOPUSING)
		panic("in_pcbdetach so=%p prot=%x couldn't set to STOPUSING\n", so, so->so_proto->pr_protocol);

#if TEMPDEBUG
	if (so->cached_in_sock_layer)
	    printf("in_pcbdetach for cached socket %x flags=%x\n", so, so->so_flags);
	else
	    printf("in_pcbdetach for allocated socket %x flags=%x\n", so, so->so_flags);
#endif
	if ((so->so_flags & SOF_PCBCLEARING) == 0) {
		struct rtentry *rt;

		inp->inp_vflag = 0;
		if (inp->inp_options) 
			(void)m_free(inp->inp_options);
		if ((rt = inp->inp_route.ro_rt) != NULL) {
			inp->inp_route.ro_rt = NULL;
			rtfree(rt);
		}
		ip_freemoptions(inp->inp_moptions);
		inp->inp_moptions = NULL;
		sofreelastref(so, 0);
		inp->inp_state = INPCB_STATE_DEAD;
		so->so_flags |= SOF_PCBCLEARING; /* makes sure we're not called twice from so_close */
	}
}


void 
in_pcbdispose(struct inpcb *inp) 
{
	struct socket *so = inp->inp_socket;
	struct inpcbinfo *ipi = inp->inp_pcbinfo;

#if TEMPDEBUG
	if (inp->inp_state != INPCB_STATE_DEAD) {
		printf("in_pcbdispose: not dead yet? so=%p\n", so);
	}
#endif

	if (so && so->so_usecount != 0)
		panic("in_pcbdispose: use count=%x so=%p\n", so->so_usecount, so);

	lck_rw_assert(ipi->mtx, LCK_RW_ASSERT_EXCLUSIVE);

	inp->inp_gencnt = ++ipi->ipi_gencnt;
	/*### access ipi in in_pcbremlists */
	in_pcbremlists(inp);
	
	if (so) {
		if (so->so_proto->pr_flags & PR_PCBLOCK) {
			sofreelastref(so, 0);
			if (so->so_rcv.sb_cc || so->so_snd.sb_cc) {
#if TEMPDEBUG
				printf("in_pcbdispose sb not cleaned up so=%p rc_cci=%x snd_cc=%x\n",
				       	so, so->so_rcv.sb_cc, so->so_snd.sb_cc);	
#endif
				sbrelease(&so->so_rcv);
				sbrelease(&so->so_snd);
			}
			if (so->so_head != NULL)
				panic("in_pcbdispose, so=%p head still exist\n", so);
  			lck_mtx_unlock(inp->inpcb_mtx);	
  			lck_mtx_free(inp->inpcb_mtx, ipi->mtx_grp);	
		}
		so->so_flags |= SOF_PCBCLEARING; /* makes sure we're not called twice from so_close */
		so->so_saved_pcb = (caddr_t) inp;
		so->so_pcb = 0; 
		inp->inp_socket = 0;
#if CONFIG_MACF_NET
		mac_inpcb_label_destroy(inp);
#endif
		/*
		 * In case there a route cached after a detach (possible
		 * in the tcp case), make sure that it is freed before
		 * we deallocate the structure.
		 */
		if (inp->inp_route.ro_rt != NULL) {
			rtfree(inp->inp_route.ro_rt);
			inp->inp_route.ro_rt = NULL;
		}
		if (so->cached_in_sock_layer == 0) {
			zfree(ipi->ipi_zone, inp);
		}
		sodealloc(so);
	}
#if TEMPDEBUG
	else
		printf("in_pcbdispose: no socket for inp=%p\n", inp);
#endif
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
 *
 * Returns:	0			Success
 *		ENOBUFS			No buffer space available
 *		ECONNRESET		Connection reset
 */
int
in_setsockaddr(struct socket *so, struct sockaddr **nam)
{
	struct inpcb *inp;
	struct sockaddr_in *sin;

	/*
	 * Do the malloc first in case it blocks.
	 */
	MALLOC(sin, struct sockaddr_in *, sizeof *sin, M_SONAME, M_WAITOK);
	if (sin == NULL)
		return ENOBUFS;
	bzero(sin, sizeof *sin);
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);

	inp = sotoinpcb(so);
	if (!inp) {
		FREE(sin, M_SONAME);
		return ECONNRESET;
	}
	sin->sin_port = inp->inp_lport;
	sin->sin_addr = inp->inp_laddr;

	*nam = (struct sockaddr *)sin;
	return 0;
}

int
in_setpeeraddr(struct socket *so, struct sockaddr **nam)
{
	struct inpcb *inp;
	struct sockaddr_in *sin;

	/*
	 * Do the malloc first in case it blocks.
	 */
	MALLOC(sin, struct sockaddr_in *, sizeof *sin, M_SONAME, M_WAITOK);
	if (sin == NULL)
		return ENOBUFS;
	bzero((caddr_t)sin, sizeof (*sin));
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);

	inp = sotoinpcb(so);
	if (!inp) {
		FREE(sin, M_SONAME);
		return ECONNRESET;
	}
	sin->sin_port = inp->inp_fport;
	sin->sin_addr = inp->inp_faddr;

	*nam = (struct sockaddr *)sin;
	return 0;
}

void
in_pcbnotifyall(struct inpcbinfo *pcbinfo, struct in_addr faddr,
		int errno, void (*notify)(struct inpcb *, int))
{
	struct inpcb *inp;

	lck_rw_lock_shared(pcbinfo->mtx);

	LIST_FOREACH(inp, pcbinfo->listhead, inp_list) {
#if INET6
		if ((inp->inp_vflag & INP_IPV4) == 0)
			continue;
#endif
		if (inp->inp_faddr.s_addr != faddr.s_addr ||
		    inp->inp_socket == NULL)
				continue;
		if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) == WNT_STOPUSING) 
			continue;
		socket_lock(inp->inp_socket, 1);
		(*notify)(inp, errno);
		(void)in_pcb_checkstate(inp, WNT_RELEASE, 1);
		socket_unlock(inp->inp_socket, 1);
	}
	lck_rw_done(pcbinfo->mtx);
}

/*
 * Check for alternatives when higher level complains
 * about service problems.  For now, invalidate cached
 * routing information.  If the route was created dynamically
 * (by a redirect), time to try a default gateway again.
 */
void
in_losing(struct inpcb *inp)
{
	struct rtentry *rt;
	struct rt_addrinfo info;

	if ((rt = inp->inp_route.ro_rt) != NULL) {
		struct in_ifaddr *ia;

		bzero((caddr_t)&info, sizeof(info));
		RT_LOCK(rt);
		info.rti_info[RTAX_DST] =
			(struct sockaddr *)&inp->inp_route.ro_dst;
		info.rti_info[RTAX_GATEWAY] = rt->rt_gateway;
		info.rti_info[RTAX_NETMASK] = rt_mask(rt);
		rt_missmsg(RTM_LOSING, &info, rt->rt_flags, 0);
		if (rt->rt_flags & RTF_DYNAMIC) {
			/*
			 * Prevent another thread from modifying rt_key,
			 * rt_gateway via rt_setgate() after rt_lock is
			 * dropped by marking the route as defunct.
			 */
			rt->rt_flags |= RTF_CONDEMNED;
			RT_UNLOCK(rt);
			(void) rtrequest(RTM_DELETE, rt_key(rt),
				rt->rt_gateway, rt_mask(rt), rt->rt_flags,
				(struct rtentry **)0);
		} else {
			RT_UNLOCK(rt);
		}
		/* if the address is gone keep the old route in the pcb */
		if ((ia = ifa_foraddr(inp->inp_laddr.s_addr)) != NULL) {
			inp->inp_route.ro_rt = NULL;
			rtfree(rt);
			ifafree(&ia->ia_ifa);
		}
		/*
		 * A new route can be allocated
		 * the next time output is attempted.
		 */
	}
}

/*
 * After a routing change, flush old routing
 * and allocate a (hopefully) better one.
 */
void
in_rtchange(struct inpcb *inp, __unused int errno)
{
	struct rtentry *rt;

	if ((rt = inp->inp_route.ro_rt) != NULL) {
		struct in_ifaddr *ia;

		if ((ia = ifa_foraddr(inp->inp_laddr.s_addr)) == NULL) {
			return; /* we can't remove the route now. not sure if still ok to use src */
		}
		ifafree(&ia->ia_ifa);
		rtfree(rt);
		inp->inp_route.ro_rt = NULL;
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
in_pcblookup_local(struct inpcbinfo *pcbinfo, struct in_addr laddr,
		   unsigned int lport_arg, int wild_okay)
{
	struct inpcb *inp;
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
		LIST_FOREACH(inp, head, inp_hash) {
#if INET6
			if ((inp->inp_vflag & INP_IPV4) == 0)
				continue;
#endif
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
#if INET6
				if ((inp->inp_vflag & INP_IPV4) == 0)
					continue;
#endif
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
in_pcblookup_hash(
	struct inpcbinfo *pcbinfo,
	struct in_addr faddr,
	u_int fport_arg,
	struct in_addr laddr,
	u_int lport_arg,
	int wildcard,
	__unused struct ifnet *ifp)
{
	struct inpcbhead *head;
	struct inpcb *inp;
	u_short fport = fport_arg, lport = lport_arg;

	/*
	 * We may have found the pcb in the last lookup - check this first.
	 */

	lck_rw_lock_shared(pcbinfo->mtx);

	/*
	 * First look for an exact match.
	 */
	head = &pcbinfo->hashbase[INP_PCBHASH(faddr.s_addr, lport, fport, pcbinfo->hashmask)];
	LIST_FOREACH(inp, head, inp_hash) {
#if INET6
		if ((inp->inp_vflag & INP_IPV4) == 0)
			continue;
#endif
		if (inp->inp_faddr.s_addr == faddr.s_addr &&
		    inp->inp_laddr.s_addr == laddr.s_addr &&
		    inp->inp_fport == fport &&
		    inp->inp_lport == lport) {
			/*
			 * Found.
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
#if INET6
		struct inpcb *local_wild_mapped = NULL;
#endif

		head = &pcbinfo->hashbase[INP_PCBHASH(INADDR_ANY, lport, 0, pcbinfo->hashmask)];
		LIST_FOREACH(inp, head, inp_hash) {
#if INET6
			if ((inp->inp_vflag & INP_IPV4) == 0)
				continue;
#endif
			if (inp->inp_faddr.s_addr == INADDR_ANY &&
			    inp->inp_lport == lport) {
#if defined(NFAITH) && NFAITH > 0
				if (ifp && ifp->if_type == IFT_FAITH &&
				    (inp->inp_flags & INP_FAITH) == 0)
					continue;
#endif
				if (inp->inp_laddr.s_addr == laddr.s_addr) {
					if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) != WNT_STOPUSING) {
						lck_rw_done(pcbinfo->mtx);
						return (inp);
					}
					else {	/* it's there but dead, say it isn't found */
						lck_rw_done(pcbinfo->mtx);	
	    					return(NULL);
					}
				}
				else if (inp->inp_laddr.s_addr == INADDR_ANY) {
#if INET6
					if (INP_CHECK_SOCKAF(inp->inp_socket,
							     AF_INET6))
						local_wild_mapped = inp;
					else
#endif /* INET6 */
					local_wild = inp;
				}
			}
		}
		if (local_wild == NULL) {
#if INET6
			if (local_wild_mapped != NULL) {
				if (in_pcb_checkstate(local_wild_mapped, WNT_ACQUIRE, 0) != WNT_STOPUSING) {
					lck_rw_done(pcbinfo->mtx);
					return (local_wild_mapped);
				}
				else {	/* it's there but dead, say it isn't found */
					lck_rw_done(pcbinfo->mtx);	
	    				return(NULL);
				}
			}
#endif /* INET6 */
			lck_rw_done(pcbinfo->mtx);
			return (NULL);
		}
		if (in_pcb_checkstate(local_wild, WNT_ACQUIRE, 0) != WNT_STOPUSING) {
			lck_rw_done(pcbinfo->mtx);
			return (local_wild);
		}
		else {	/* it's there but dead, say it isn't found */
			lck_rw_done(pcbinfo->mtx);	
	    		return(NULL);
		}
	}

	/*
	 * Not found.
	 */
	lck_rw_done(pcbinfo->mtx);
	return (NULL);
}

/*
 * Insert PCB onto various hash lists.
 */
int
in_pcbinshash(struct inpcb *inp, int locked)
{
	struct inpcbhead *pcbhash;
	struct inpcbporthead *pcbporthash;
	struct inpcbinfo *pcbinfo = inp->inp_pcbinfo;
	struct inpcbport *phd;
	u_int32_t hashkey_faddr;

        if (!locked) {
                if (!lck_rw_try_lock_exclusive(pcbinfo->mtx)) {
                /*lock inversion issue, mostly with udp multicast packets */
                        socket_unlock(inp->inp_socket, 0);
                        lck_rw_lock_exclusive(pcbinfo->mtx);
                        socket_lock(inp->inp_socket, 0);
                }
        }

#if INET6
	if (inp->inp_vflag & INP_IPV6)
		hashkey_faddr = inp->in6p_faddr.s6_addr32[3] /* XXX */;
	else
#endif /* INET6 */
	hashkey_faddr = inp->inp_faddr.s_addr;

	inp->hash_element = INP_PCBHASH(hashkey_faddr, inp->inp_lport, inp->inp_fport, pcbinfo->hashmask);

	pcbhash = &pcbinfo->hashbase[inp->hash_element];

	pcbporthash = &pcbinfo->porthashbase[INP_PCBPORTHASH(inp->inp_lport,
	    pcbinfo->porthashmask)];

	/*
	 * Go through port list and look for a head for this lport.
	 */
	LIST_FOREACH(phd, pcbporthash, phd_hash) {
		if (phd->phd_port == inp->inp_lport)
			break;
	}
	/*
	 * If none exists, malloc one and tack it on.
	 */
	if (phd == NULL) {
		MALLOC(phd, struct inpcbport *, sizeof(struct inpcbport), M_PCB, M_WAITOK);
		if (phd == NULL) {
			if (!locked)
				lck_rw_done(pcbinfo->mtx);
			return (ENOBUFS); /* XXX */
		}
		phd->phd_port = inp->inp_lport;
		LIST_INIT(&phd->phd_pcblist);
		LIST_INSERT_HEAD(pcbporthash, phd, phd_hash);
	}
	inp->inp_phd = phd;
	LIST_INSERT_HEAD(&phd->phd_pcblist, inp, inp_portlist);
	LIST_INSERT_HEAD(pcbhash, inp, inp_hash);
	if (!locked)
		lck_rw_done(pcbinfo->mtx);
	return (0);
}

/*
 * Move PCB to the proper hash bucket when { faddr, fport } have  been
 * changed. NOTE: This does not handle the case of the lport changing (the
 * hashed port list would have to be updated as well), so the lport must
 * not change after in_pcbinshash() has been called.
 */
void
in_pcbrehash(struct inpcb *inp)
{
	struct inpcbhead *head;
	u_int32_t hashkey_faddr;

#if INET6
	if (inp->inp_vflag & INP_IPV6)
		hashkey_faddr = inp->in6p_faddr.s6_addr32[3] /* XXX */;
	else
#endif /* INET6 */
	hashkey_faddr = inp->inp_faddr.s_addr;
	inp->hash_element = INP_PCBHASH(hashkey_faddr, inp->inp_lport, 
				inp->inp_fport, inp->inp_pcbinfo->hashmask);
	head = &inp->inp_pcbinfo->hashbase[inp->hash_element];

	LIST_REMOVE(inp, inp_hash);
	LIST_INSERT_HEAD(head, inp, inp_hash);
}

/*
 * Remove PCB from various lists.
 */
//###LOCK must be called with list lock held
void
in_pcbremlists(struct inpcb *inp)
{
	inp->inp_gencnt = ++inp->inp_pcbinfo->ipi_gencnt;

	if (inp->inp_lport) {
		struct inpcbport *phd = inp->inp_phd;

		LIST_REMOVE(inp, inp_hash);
		LIST_REMOVE(inp, inp_portlist);
		if (phd != NULL && (LIST_FIRST(&phd->phd_pcblist) == NULL)) {
			LIST_REMOVE(phd, phd_hash);
			FREE(phd, M_PCB);
		}
	}
	LIST_REMOVE(inp, inp_list);
	inp->inp_pcbinfo->ipi_count--;
}

/* Mechanism used to defer the memory release of PCBs
 * The pcb list will contain the pcb until the ripper can clean it up if
 * the following conditions are met: 1) state "DEAD", 2) wantcnt is STOPUSING
 * 3) usecount is null
 * This function will be called to either mark the pcb as
*/
int
in_pcb_checkstate(struct inpcb *pcb, int mode, int locked)
{

	volatile UInt32 *wantcnt	= (volatile UInt32 *)&pcb->inp_wantcnt;
	UInt32 origwant;
	UInt32 newwant;

	switch (mode) {

		case WNT_STOPUSING:	/* try to mark the pcb as ready for recycling */

			/* compareswap with STOPUSING, if success we're good, if it's in use, will be marked later */

			if (locked == 0)
				socket_lock(pcb->inp_socket, 1);
			pcb->inp_state = INPCB_STATE_DEAD;
stopusing:
			if (pcb->inp_socket->so_usecount < 0)
				panic("in_pcb_checkstate STOP pcb=%p so=%p usecount is negative\n", pcb, pcb->inp_socket);
			if (locked == 0)
				socket_unlock(pcb->inp_socket, 1);

			origwant = *wantcnt;
        		if ((UInt16) origwant == 0xffff ) /* should stop using */
				return (WNT_STOPUSING);
			newwant = 0xffff;			
			if ((UInt16) origwant == 0) {/* try to mark it as unsuable now */
    				OSCompareAndSwap(origwant, newwant, wantcnt) ;
			}
			return (WNT_STOPUSING);
			break;

		case WNT_ACQUIRE:	/* try to increase reference to pcb */
					/* if WNT_STOPUSING should bail out */
			/*
			 * if socket state DEAD, try to set count to STOPUSING, return failed
			 * otherwise increase cnt
			 */
			do {
				origwant = *wantcnt;
        			if ((UInt16) origwant == 0xffff ) {/* should stop using */
//					printf("in_pcb_checkstate: ACQ PCB was STOPUSING while release. odd pcb=%p\n", pcb);
					return (WNT_STOPUSING);
				}
				newwant = origwant + 1;		
			} while (!OSCompareAndSwap(origwant, newwant, wantcnt));
			return (WNT_ACQUIRE);
			break;

		case WNT_RELEASE:	/* release reference. if result is null and pcb state is DEAD,
					   set wanted bit to STOPUSING
					 */

			if (locked == 0)
				socket_lock(pcb->inp_socket, 1);

			do {
				origwant = *wantcnt;
        			if ((UInt16) origwant == 0x0 ) 
					panic("in_pcb_checkstate pcb=%p release with zero count", pcb);
        			if ((UInt16) origwant == 0xffff ) {/* should stop using */
#if TEMPDEBUG
					printf("in_pcb_checkstate: REL PCB was STOPUSING while release. odd pcb=%p\n", pcb);
#endif
					if (locked == 0)
						socket_unlock(pcb->inp_socket, 1);
					return (WNT_STOPUSING);
				}
				newwant = origwant - 1;		
			} while (!OSCompareAndSwap(origwant, newwant, wantcnt));

			if (pcb->inp_state == INPCB_STATE_DEAD) 
				goto stopusing;
			if (pcb->inp_socket->so_usecount < 0)
				panic("in_pcb_checkstate RELEASE pcb=%p so=%p usecount is negative\n", pcb, pcb->inp_socket);
				
			if (locked == 0)
				socket_unlock(pcb->inp_socket, 1);
			return (WNT_RELEASE);
			break;

		default:

			panic("in_pcb_checkstate: so=%p not a valid state =%x\n", pcb->inp_socket, mode);
	}

	/* NOTREACHED */
	return (mode);
}

/*
 * inpcb_to_compat copies specific bits of an inpcb to a inpcb_compat.
 * The inpcb_compat data structure is passed to user space and must
 * not change. We intentionally avoid copying pointers.
 */
void
inpcb_to_compat(
	struct inpcb *inp,
	struct inpcb_compat *inp_compat)
{
	bzero(inp_compat, sizeof(*inp_compat));
	inp_compat->inp_fport = inp->inp_fport;
	inp_compat->inp_lport = inp->inp_lport;
	inp_compat->nat_owner = inp->nat_owner;
	inp_compat->nat_cookie = inp->nat_cookie;
	inp_compat->inp_gencnt = inp->inp_gencnt;
	inp_compat->inp_flags = inp->inp_flags;
	inp_compat->inp_flow = inp->inp_flow;
	inp_compat->inp_vflag = inp->inp_vflag;
	inp_compat->inp_ip_ttl = inp->inp_ip_ttl;
	inp_compat->inp_ip_p = inp->inp_ip_p;
	inp_compat->inp_dependfaddr.inp6_foreign = inp->inp_dependfaddr.inp6_foreign;
	inp_compat->inp_dependladdr.inp6_local = inp->inp_dependladdr.inp6_local;
	inp_compat->inp_depend4.inp4_ip_tos = inp->inp_depend4.inp4_ip_tos;
	inp_compat->inp_depend6.inp6_hlim = inp->inp_depend6.inp6_hlim;
	inp_compat->inp_depend6.inp6_cksum = inp->inp_depend6.inp6_cksum;
	inp_compat->inp_depend6.inp6_ifindex = inp->inp_depend6.inp6_ifindex;
	inp_compat->inp_depend6.inp6_hops = inp->inp_depend6.inp6_hops;
}

#if !CONFIG_EMBEDDED

void
inpcb_to_xinpcb64(
        struct inpcb *inp,
        struct xinpcb64 *xinp)
{
        xinp->inp_fport = inp->inp_fport;
        xinp->inp_lport = inp->inp_lport;
        xinp->inp_gencnt = inp->inp_gencnt;
        xinp->inp_flags = inp->inp_flags;
        xinp->inp_flow = inp->inp_flow;
        xinp->inp_vflag = inp->inp_vflag;
        xinp->inp_ip_ttl = inp->inp_ip_ttl;
        xinp->inp_ip_p = inp->inp_ip_p;
        xinp->inp_dependfaddr.inp6_foreign = inp->inp_dependfaddr.inp6_foreign;
        xinp->inp_dependladdr.inp6_local = inp->inp_dependladdr.inp6_local;
        xinp->inp_depend4.inp4_ip_tos = inp->inp_depend4.inp4_ip_tos;
        xinp->inp_depend6.inp6_hlim = inp->inp_depend6.inp6_hlim;
        xinp->inp_depend6.inp6_cksum = inp->inp_depend6.inp6_cksum;
	xinp->inp_depend6.inp6_ifindex = inp->inp_depend6.inp6_ifindex;
        xinp->inp_depend6.inp6_hops = inp->inp_depend6.inp6_hops;
}

#endif /* !CONFIG_EMBEDDED */

/*
 * The following routines implement this scheme:
 *
 * Callers of ip_output() that intend to cache the route in the inpcb pass
 * a local copy of the struct route to ip_output().  Using a local copy of
 * the cached route significantly simplifies things as IP no longer has to
 * worry about having exclusive access to the passed in struct route, since
 * it's defined in the caller's stack; in essence, this allows for a lock-
 * less operation when updating the struct route at the IP level and below,
 * whenever necessary. The scheme works as follows:
 *
 * Prior to dropping the socket's lock and calling ip_output(), the caller
 * copies the struct route from the inpcb into its stack, and adds a reference
 * to the cached route entry, if there was any.  The socket's lock is then
 * dropped and ip_output() is called with a pointer to the copy of struct
 * route defined on the stack (not to the one in the inpcb.)
 *
 * Upon returning from ip_output(), the caller then acquires the socket's
 * lock and synchronizes the cache; if there is no route cached in the inpcb,
 * it copies the local copy of struct route (which may or may not contain any
 * route) back into the cache; otherwise, if the inpcb has a route cached in
 * it, the one in the local copy will be freed, if there's any.  Trashing the
 * cached route in the inpcb can be avoided because ip_output() is single-
 * threaded per-PCB (i.e. multiple transmits on a PCB are always serialized
 * by the socket/transport layer.)
 */
void
inp_route_copyout(struct inpcb *inp, struct route *dst)
{
	struct route *src = &inp->inp_route;

	lck_mtx_assert(inp->inpcb_mtx, LCK_MTX_ASSERT_OWNED);

	/*
	 * If the route in the PCB is not for IPv4, blow it away;
	 * this is possible in the case of IPv4-mapped address case.
	 */
	if (src->ro_rt != NULL && rt_key(src->ro_rt)->sa_family != AF_INET) {
		rtfree(src->ro_rt);
		src->ro_rt = NULL;
	}

	/* Copy everything (rt, dst, flags) from PCB */
	bcopy(src, dst, sizeof (*dst));

	/* Hold one reference for the local copy of struct route */
	if (dst->ro_rt != NULL)
		RT_ADDREF(dst->ro_rt);
}

void
inp_route_copyin(struct inpcb *inp, struct route *src)
{
	struct route *dst = &inp->inp_route;

	lck_mtx_assert(inp->inpcb_mtx, LCK_MTX_ASSERT_OWNED);

	/* Minor sanity check */
	if (src->ro_rt != NULL && rt_key(src->ro_rt)->sa_family != AF_INET)
		panic("%s: wrong or corrupted route: %p", __func__, src);

	/* No cached route in the PCB? */
	if (dst->ro_rt == NULL) {
		/*
		 * Copy everything (rt, dst, flags) from ip_output();
		 * the reference to the route was held at the time
		 * it was allocated and is kept intact.
		 */
		bcopy(src, dst, sizeof (*dst));
	} else if (src->ro_rt != NULL) {
		/*
		 * If the same, update just the ro_flags and ditch the one
		 * in the local copy.  Else ditch the one that is currently
		 * cached, and cache what we got back from ip_output().
		 */
		if (dst->ro_rt == src->ro_rt) {
			dst->ro_flags = src->ro_flags;
			rtfree(src->ro_rt);
			src->ro_rt = NULL;
		} else {
			rtfree(dst->ro_rt);
			bcopy(src, dst, sizeof (*dst));
		}
	}
}
