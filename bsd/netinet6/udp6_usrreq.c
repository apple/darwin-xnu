/*	$KAME: udp6_usrreq.c,v 1.25 2000/04/04 11:18:10 itojun Exp $	*/

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
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)udp_var.h	8.1 (Berkeley) 6/10/93
 */
#if BSD310
#include "opt_inet.h"
#endif

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/proc.h>

#include <net/if.h>
#include <net/route.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet/icmp6.h>
#include <netinet6/udp6_var.h>
#include <netinet6/ip6protosw.h>

#if IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

#include "faith.h"

/*
 * UDP protocol inplementation.
 * Per RFC 768, August, 1980.
 */

extern	struct protosw inetsw[];
static	int in6_mcmatch __P((struct inpcb *, struct in6_addr *, struct ifnet *));
static	int udp6_detach __P((struct socket *so));

static int
in6_mcmatch(in6p, ia6, ifp)
	struct inpcb *in6p;
	register struct in6_addr *ia6;
	struct ifnet *ifp;
{
	struct ip6_moptions *im6o = in6p->in6p_moptions;
	struct in6_multi_mship *imm;

	if (im6o == NULL)
		return 0;

	for (imm = im6o->im6o_memberships.lh_first; imm != NULL;
	     imm = imm->i6mm_chain.le_next) {
		if ((ifp == NULL ||
		     imm->i6mm_maddr->in6m_ifp == ifp) &&
		    IN6_ARE_ADDR_EQUAL(&imm->i6mm_maddr->in6m_addr,
				       ia6))
			return 1;
	}
	return 0;
}

int
udp6_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp, proto;
{
	struct mbuf *m = *mp;
	register struct ip6_hdr *ip6;
	register struct udphdr *uh;
	register struct inpcb *in6p;
	struct ip6_recvpktopts opts;
	int off = *offp;
	int plen, ulen;
	struct sockaddr_in6 udp_in6;

#if defined(NFAITH) && 0 < NFAITH
	if (m->m_pkthdr.rcvif) {
		if (m->m_pkthdr.rcvif->if_type == IFT_FAITH) {
			/* XXX send icmp6 host/port unreach? */
			m_freem(m);
			return IPPROTO_DONE;
		}
	}
#endif
	udpstat.udps_ipackets++;
	bzero(&opts, sizeof(opts));

	IP6_EXTHDR_CHECK(m, off, sizeof(struct udphdr), IPPROTO_DONE);

	ip6 = mtod(m, struct ip6_hdr *);
	plen = ntohs(ip6->ip6_plen) - off + sizeof(*ip6);
	uh = (struct udphdr *)((caddr_t)ip6 + off);
	ulen = ntohs((u_short)uh->uh_ulen);

	if (plen != ulen) {
		udpstat.udps_badlen++;
		goto bad;
	}

	/*
	 * Checksum extended UDP header and data.
	 */
//	if (uh->uh_sum == 0)
//		udpstat.udps_nosum++;
	else if (in6_cksum(m, IPPROTO_UDP, off, ulen) != 0) {
		udpstat.udps_badsum++;
		goto bad;
	}

	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		struct	inpcb *last;

		/*
		 * Deliver a multicast datagram to all sockets
		 * for which the local and remote addresses and ports match
		 * those of the incoming datagram.  This allows more than
		 * one process to receive multicasts on the same port.
		 * (This really ought to be done for unicast datagrams as
		 * well, but that would cause problems with existing
		 * applications that open both address-specific sockets and
		 * a wildcard socket listening to the same port -- they would
		 * end up receiving duplicates of every unicast datagram.
		 * Those applications open the multiple sockets to overcome an
		 * inadequacy of the UDP socket interface, but for backwards
		 * compatibility we avoid the problem here rather than
		 * fixing the interface.  Maybe 4.5BSD will remedy this?)
		 */

		/*
		 * In a case that laddr should be set to the link-local
		 * address (this happens in RIPng), the multicast address
		 * specified in the received packet does not match with
		 * laddr. To cure this situation, the matching is relaxed
		 * if the receiving interface is the same as one specified
		 * in the socket and if the destination multicast address
		 * matches one of the multicast groups specified in the socket.
		 */

		/*
		 * Construct sockaddr format source address.
		 */
		init_sin6(&udp_in6, m); /* general init */
		udp_in6.sin6_port = uh->uh_sport;
		/*
		 * KAME note: usually we drop udphdr from mbuf here.
		 * We need udphdr for IPsec processing so we do that later.
		 */

		/*
		 * Locate pcb(s) for datagram.
		 * (Algorithm copied from raw_intr().)
		 */
		last = NULL;
		LIST_FOREACH(in6p, &udb, inp_list) {
			if ((in6p->inp_vflag & INP_IPV6) == 0)
				continue;
			if (in6p->in6p_lport != uh->uh_dport)
				continue;
			if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_laddr)) {
				if (!IN6_ARE_ADDR_EQUAL(&in6p->in6p_laddr,
							&ip6->ip6_dst) &&
				    !in6_mcmatch(in6p, &ip6->ip6_dst,
						 m->m_pkthdr.rcvif))
					continue;
			}
			if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr)) {
				if (!IN6_ARE_ADDR_EQUAL(&in6p->in6p_faddr,
							&ip6->ip6_src) ||
				   in6p->in6p_fport != uh->uh_sport)
					continue;
			}

			if (last != NULL) {
				struct	mbuf *n;

#if IPSEC
				/*
				 * Check AH/ESP integrity.
				 */
				if (ipsec6_in_reject_so(m, last->inp_socket))
					ipsec6stat.in_polvio++;
					/* do not inject data into pcb */
				else
#endif /*IPSEC*/
				if ((n = m_copy(m, 0, M_COPYALL)) != NULL) {
					/*
					 * KAME NOTE: do not
					 * m_copy(m, offset, ...) above.
					 * sbappendaddr() expects M_PKTHDR,
					 * and m_copy() will copy M_PKTHDR
					 * only if offset is 0.
					 */
					if (last->in6p_flags & IN6P_CONTROLOPTS
					    || last->in6p_socket->so_options & SO_TIMESTAMP)
						ip6_savecontrol(last, ip6, n,
								&opts, NULL);
								
					m_adj(n, off + sizeof(struct udphdr));
					if (sbappendaddr(&last->in6p_socket->so_rcv,
							(struct sockaddr *)&udp_in6,
							n, opts.head) == 0) {
						m_freem(n);
						if (opts.head)
							m_freem(opts.head);
						udpstat.udps_fullsock++;
					} else
						sorwakeup(last->in6p_socket);
					bzero(&opts, sizeof(opts));
				}
			}
			last = in6p;
			/*
			 * Don't look for additional matches if this one does
			 * not have either the SO_REUSEPORT or SO_REUSEADDR
			 * socket options set.  This heuristic avoids searching
			 * through all pcbs in the common case of a non-shared
			 * port.  It assumes that an application will never
			 * clear these options after setting them.
			 */
			if ((last->in6p_socket->so_options &
			     (SO_REUSEPORT|SO_REUSEADDR)) == 0)
				break;
		}

		if (last == NULL) {
			/*
			 * No matching pcb found; discard datagram.
			 * (No need to send an ICMP Port Unreachable
			 * for a broadcast or multicast datgram.)
			 */
			udpstat.udps_noport++;
//			udpstat.udps_noportmcast++;
			goto bad;
		}
#if IPSEC
		/*
		 * Check AH/ESP integrity.
		 */
		if (ipsec6_in_reject_so(m, last->inp_socket)) {
			ipsec6stat.in_polvio++;
			goto bad;
		}
#endif /*IPSEC*/
		if (last->in6p_flags & IN6P_CONTROLOPTS
		    || last->in6p_socket->so_options & SO_TIMESTAMP)
			ip6_savecontrol(last, ip6, m, &opts, NULL);

		m_adj(m, off + sizeof(struct udphdr));
		if (sbappendaddr(&last->in6p_socket->so_rcv,
				(struct sockaddr *)&udp_in6,
				m, opts.head) == 0) {
			udpstat.udps_fullsock++;
			goto bad;
		}
		sorwakeup(last->in6p_socket);
		return IPPROTO_DONE;
	}
	/*
	 * Locate pcb for datagram.
	 */
	in6p = in6_pcblookup_hash(&udbinfo, &ip6->ip6_src, uh->uh_sport,
				  &ip6->ip6_dst, uh->uh_dport, 1,
				  m->m_pkthdr.rcvif);
	if (in6p == 0) {
		if (log_in_vain) {
			char buf[INET6_ADDRSTRLEN];

			strcpy(buf, ip6_sprintf(&ip6->ip6_dst));
			log(LOG_INFO,
			    "Connection attempt to UDP %s:%d from %s:%d\n",
			    buf, ntohs(uh->uh_dport),
			    ip6_sprintf(&ip6->ip6_src), ntohs(uh->uh_sport));
		}
		udpstat.udps_noport++;
		if (m->m_flags & M_MCAST) {
			printf("UDP6: M_MCAST is set in a unicast packet.\n");
//			udpstat.udps_noportmcast++;
			goto bad;
		}
		icmp6_error(m, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_NOPORT, 0);
		return IPPROTO_DONE;
	}
#if IPSEC
	/*
	 * Check AH/ESP integrity.
	 */
	if (ipsec6_in_reject_so(m, in6p->in6p_socket)) {
		ipsec6stat.in_polvio++;
		goto bad;
	}
#endif /*IPSEC*/

	/*
	 * Construct sockaddr format source address.
	 * Stuff source address and datagram in user buffer.
	 */
	init_sin6(&udp_in6, m); /* general init */
	udp_in6.sin6_port = uh->uh_sport;
	if (in6p->in6p_flags & IN6P_CONTROLOPTS
	    || in6p->in6p_socket->so_options & SO_TIMESTAMP)
		ip6_savecontrol(in6p, ip6, m, &opts, NULL);
	m_adj(m, off + sizeof(struct udphdr));
	if (sbappendaddr(&in6p->in6p_socket->so_rcv,
			(struct sockaddr *)&udp_in6,
			m, opts.head) == 0) {
		udpstat.udps_fullsock++;
		goto bad;
	}
	sorwakeup(in6p->in6p_socket);
	return IPPROTO_DONE;
bad:
	if (m)
		m_freem(m);
	if (opts.head)
		m_freem(opts.head);
	return IPPROTO_DONE;
}

void
udp6_ctlinput(cmd, sa, d)
	int cmd;
	struct sockaddr *sa;
	void *d;
{
	register struct udphdr *uhp;
	struct udphdr uh;
	struct sockaddr_in6 sa6;
	struct ip6_hdr *ip6;
	struct mbuf *m;
	int off = 0;
	void (*notify) __P((struct inpcb *, int)) = udp_notify;

	if (sa->sa_family != AF_INET6 ||
	    sa->sa_len != sizeof(struct sockaddr_in6))
		return;

	if ((unsigned)cmd >= PRC_NCMDS)
		return;
	if (PRC_IS_REDIRECT(cmd))
		notify = in6_rtchange, d = NULL;
	else if (cmd == PRC_HOSTDEAD)
		d = NULL;
	else if (inet6ctlerrmap[cmd] == 0)
		return;

	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		struct ip6ctlparam *ip6cp = (struct ip6ctlparam *)d;
		m = ip6cp->ip6c_m;
		ip6 = ip6cp->ip6c_ip6;
		off = ip6cp->ip6c_off;
	} else {
		m = NULL;
		ip6 = NULL;
	}

	/* translate addresses into internal form */
	sa6 = *(struct sockaddr_in6 *)sa;
	if (IN6_IS_ADDR_LINKLOCAL(&sa6.sin6_addr) && m && m->m_pkthdr.rcvif)
		sa6.sin6_addr.s6_addr16[1] = htons(m->m_pkthdr.rcvif->if_index);

	if (ip6) {
		/*
		 * XXX: We assume that when IPV6 is non NULL,
		 * M and OFF are valid.
		 */
		struct in6_addr s;

		/* translate addresses into internal form */
		memcpy(&s, &ip6->ip6_src, sizeof(s));
		if (IN6_IS_ADDR_LINKLOCAL(&s))
			s.s6_addr16[1] = htons(m->m_pkthdr.rcvif->if_index);

		if (m->m_len < off + sizeof(uh)) {
			/*
			 * this should be rare case,
			 * so we compromise on this copy...
			 */
			m_copydata(m, off, sizeof(uh), (caddr_t)&uh);
			uhp = &uh;
		} else
			uhp = (struct udphdr *)(mtod(m, caddr_t) + off);
		(void) in6_pcbnotify(&udb, (struct sockaddr *)&sa6,
				     uhp->uh_dport, &s,
				     uhp->uh_sport, cmd, notify);
	} else
		(void) in6_pcbnotify(&udb, (struct sockaddr *)&sa6, 0,
				     &zeroin6_addr, 0, cmd, notify);
}
#if 0
static int
udp6_getcred SYSCTL_HANDLER_ARGS
{
	struct sockaddr_in6 addrs[2];
	struct inpcb *inp;
	int error, s;

	error = suser(req->p->p_ucred, &req->p->p_acflag);
	if (error)
		return (error);

	if (req->newlen != sizeof(addrs))
		return (EINVAL);
	if (req->oldlen != sizeof(struct ucred))
		return (EINVAL);
	error = SYSCTL_IN(req, addrs, sizeof(addrs));
	if (error)
		return (error);
	s = splnet();
	inp = in6_pcblookup_hash(&udbinfo, &addrs[1].sin6_addr,
				 addrs[1].sin6_port,
				 &addrs[0].sin6_addr, addrs[0].sin6_port,
				 1, NULL);
	if (!inp || !inp->inp_socket || !inp->inp_socket->so_cred) {
		error = ENOENT;
		goto out;
	}
	error = SYSCTL_OUT(req, inp->inp_socket->so_cred->pc_ucred,
			   sizeof(struct ucred));

out:
	splx(s);
	return (error);
}

SYSCTL_PROC(_net_inet6_udp6, OID_AUTO, getcred, CTLTYPE_OPAQUE|CTLFLAG_RW,
	    0, 0,
	    udp6_getcred, "S,ucred", "Get the ucred of a UDP6 connection");
#endif
int
udp6_output(in6p, m, addr6, control, p)
	register struct inpcb *in6p;
	register struct mbuf *m;
	struct sockaddr *addr6;
	struct mbuf *control;
	struct proc *p;
{
	register int ulen = m->m_pkthdr.len;
	int plen = sizeof(struct udphdr) + ulen;
	struct ip6_hdr *ip6;
	struct udphdr *udp6;
	struct	in6_addr laddr6;
	int s = 0, error = 0;
	struct ip6_pktopts opt, *stickyopt = in6p->in6p_outputopts;
	int flags;

	if (control) {
		if (error = ip6_setpktoptions(control, &opt,
					      p &&
					      suser(p->p_ucred, &p->p_acflag), 0))
			goto release;
		in6p->in6p_outputopts = &opt;
	}

	if (addr6) {
		laddr6 = in6p->in6p_laddr;
		if (!IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr)) {
			error = EISCONN;
			goto release;
		}
		/*
		 * Must block input while temporarily connected.
		 */
		s = splnet();
		/*
		 * XXX: the user might want to overwrite the local address
		 * via an ancillary data.
		 */
		bzero(&in6p->in6p_laddr, sizeof(struct in6_addr));
		error = in6_pcbconnect(in6p, addr6, p);
		if (error) {
			splx(s);
			goto release;
		}
	} else {
		if (IN6_IS_ADDR_UNSPECIFIED(&in6p->in6p_faddr)) {
			error = ENOTCONN;
			goto release;
		}
	}
	/*
	 * Calculate data length and get a mbuf
	 * for UDP and IP6 headers.
	 */
	M_PREPEND(m, sizeof(struct ip6_hdr) + sizeof(struct udphdr),
		  M_DONTWAIT);
	if (m == 0) {
		error = ENOBUFS;
		if (addr6)
			splx(s);
		goto release;
	}

	/*
	 * Stuff checksum and output datagram.
	 */
	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow	= in6p->in6p_flowinfo & IPV6_FLOWINFO_MASK;
	ip6->ip6_vfc 	|= IPV6_VERSION;
#if 0				/* ip6_plen will be filled in ip6_output. */
	ip6->ip6_plen	= htons((u_short)plen);
#endif
	ip6->ip6_nxt	= IPPROTO_UDP;
	ip6->ip6_hlim   = in6_selecthlim(in6p,
					 in6p->in6p_route.ro_rt ?
					 in6p->in6p_route.ro_rt->rt_ifp :
					 NULL);
	ip6->ip6_src	= in6p->in6p_laddr;
	ip6->ip6_dst	= in6p->in6p_faddr;

	udp6 = (struct udphdr *)(ip6 + 1);
	udp6->uh_sport = in6p->in6p_lport;
	udp6->uh_dport = in6p->in6p_fport;
	udp6->uh_ulen  = htons((u_short)plen);
	udp6->uh_sum   = 0;

	if ((udp6->uh_sum = in6_cksum(m, IPPROTO_UDP,
					sizeof(struct ip6_hdr), plen)) == 0) {
		udp6->uh_sum = 0xffff;
	}

	flags = 0;
	if (in6p->in6p_flags & IN6P_MINMTU)
		flags |= IPV6_MINMTU;

	udpstat.udps_opackets++;

#if IPSEC
	ipsec_setsocket(m, in6p->in6p_socket);
#endif /*IPSEC*/
	error = ip6_output(m, in6p->in6p_outputopts, &in6p->in6p_route,
			    flags, in6p->in6p_moptions, NULL);

	if (addr6) {
		in6_pcbdisconnect(in6p);
		in6p->in6p_laddr = laddr6;
		splx(s);
	}
	goto releaseopt;

release:
	m_freem(m);

releaseopt:
	if (control) {
		ip6_clearpktopts(in6p->in6p_outputopts, 0, -1);
		in6p->in6p_outputopts = stickyopt;
		m_freem(control);
	}
	return(error);
}

static int
udp6_abort(struct socket *so)
{
	struct inpcb *inp;
	int s;

	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;	/* ??? possible? panic instead? */
	soisdisconnected(so);
	s = splnet();
	in6_pcbdetach(inp);
	splx(s);
	return 0;
}

static int
udp6_attach(struct socket *so, int proto, struct proc *p)
{
	struct inpcb *inp;
	int s, error;

	inp = sotoinpcb(so);
	if (inp != 0)
		return EINVAL;

	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = soreserve(so, udp_sendspace, udp_recvspace);
		if (error)
			return error;
	}
	s = splnet();
	error = in_pcballoc(so, &udbinfo, p);
	splx(s);
	if (error)
		return error;
	inp = (struct inpcb *)so->so_pcb;
	inp->inp_vflag |= INP_IPV6;
	inp->in6p_hops = -1;	/* use kernel default */
	inp->in6p_cksum = -1;	/* just to be sure */
#if IPSEC
	error = ipsec_init_policy(so, &inp->in6p_sp);
	if (error != 0) {
		in6_pcbdetach(inp);
		return (error);
	}
#endif /*IPSEC*/
	return 0;
}

static int
udp6_bind(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp;
	int s, error;

	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;

	inp->inp_vflag &= ~INP_IPV4;
	inp->inp_vflag |= INP_IPV6;
	if (ip6_mapped_addr_on && (inp->inp_flags & IN6P_BINDV6ONLY) == 0) {
		struct sockaddr_in6 *sin6_p;

		sin6_p = (struct sockaddr_in6 *)nam;

		if (IN6_IS_ADDR_UNSPECIFIED(&sin6_p->sin6_addr))
			inp->inp_vflag |= INP_IPV4;
		else if (IN6_IS_ADDR_V4MAPPED(&sin6_p->sin6_addr)) {
			struct sockaddr_in sin;

			in6_sin6_2_sin(&sin, sin6_p);
			inp->inp_vflag |= INP_IPV4;
			inp->inp_vflag &= ~INP_IPV6;
			s = splnet();
			error = in_pcbbind(inp, (struct sockaddr *)&sin, p);
			splx(s);
			return error;
		}
	}

	s = splnet();
	error = in6_pcbbind(inp, nam, p);
	splx(s);
	return error;
}

static int
udp6_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{
	struct inpcb *inp;
	int s, error;

	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;

	if (ip6_mapped_addr_on) {
		struct sockaddr_in6 *sin6_p;

		sin6_p = (struct sockaddr_in6 *)nam;
		if (IN6_IS_ADDR_V4MAPPED(&sin6_p->sin6_addr)) {
			struct sockaddr_in sin;

			if (inp->inp_faddr.s_addr != INADDR_ANY)
				return EISCONN;
			in6_sin6_2_sin(&sin, sin6_p);
			s = splnet();
			error = in_pcbconnect(inp, (struct sockaddr *)&sin, p);
			splx(s);
			if (error == 0) {
				inp->inp_vflag |= INP_IPV4;
				inp->inp_vflag &= ~INP_IPV6;
				soisconnected(so);
			}
			return error;
		}
	}

	if (!IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr))
		return EISCONN;
	s = splnet();
	error = in6_pcbconnect(inp, nam, p);
	if (ip6_auto_flowlabel) {
		inp->in6p_flowinfo &= ~IPV6_FLOWLABEL_MASK;
		inp->in6p_flowinfo |= 
			(htonl(ip6_flow_seq++) & IPV6_FLOWLABEL_MASK);
	}
	splx(s);
	if (error == 0) {
		if (ip6_mapped_addr_on) { /* should be non mapped addr */
			inp->inp_vflag &= ~INP_IPV4;
			inp->inp_vflag |= INP_IPV6;
		}
		soisconnected(so);
	}
	return error;
}

static int
udp6_detach(struct socket *so)
{
	struct inpcb *inp;
	int s;

	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;
	s = splnet();
	in6_pcbdetach(inp);
	splx(s);
	return 0;
}

static int
udp6_disconnect(struct socket *so)
{
	struct inpcb *inp;
	int s;

	inp = sotoinpcb(so);
	if (inp == 0)
		return EINVAL;

	if (inp->inp_vflag & INP_IPV4) {
		struct pr_usrreqs *pru;

		pru = ip_protox[IPPROTO_UDP]->pr_usrreqs;
		return ((*pru->pru_disconnect)(so));
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr))
		return ENOTCONN;

	s = splnet();
	in6_pcbdisconnect(inp);
	inp->in6p_laddr = in6addr_any;
	splx(s);
	so->so_state &= ~SS_ISCONNECTED;		/* XXX */
	return 0;
}

static int
udp6_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *addr,
	  struct mbuf *control, struct proc *p)
{
	struct inpcb *inp;

	inp = sotoinpcb(so);
	if (inp == 0) {
		m_freem(m);
		return EINVAL;
	}

	if (ip6_mapped_addr_on) {
		int hasv4addr;
		struct sockaddr_in6 *sin6 = 0;

		if (addr == 0)
			hasv4addr = (inp->inp_vflag & INP_IPV4);
		else {
			sin6 = (struct sockaddr_in6 *)addr;
			hasv4addr = IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)
				? 1 : 0;
		}
		if (hasv4addr) {
			struct pr_usrreqs *pru;
			int error;

			if (sin6)
				in6_sin6_2_sin_in_sock(addr);
			pru = ip_protox[IPPROTO_UDP]->pr_usrreqs;
			error = ((*pru->pru_send)(so, flags, m, addr, control,
						  p));
			/* addr will just be freed in sendit(). */
			return error;
		}
	}

	return udp6_output(inp, m, addr, control, p);
}

struct pr_usrreqs udp6_usrreqs = {
	udp6_abort, pru_accept_notsupp, udp6_attach, udp6_bind, udp6_connect,
	pru_connect2_notsupp, in6_control, udp6_detach, udp6_disconnect,
	pru_listen_notsupp, in6_mapped_peeraddr, pru_rcvd_notsupp,
	pru_rcvoob_notsupp, udp6_send, pru_sense_null, udp_shutdown,
	in6_mapped_sockaddr, sosend, soreceive, sopoll
};
