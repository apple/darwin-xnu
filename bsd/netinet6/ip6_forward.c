/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/ip6_forward.c,v 1.16 2002/10/16 02:25:05 sam Exp $	*/
/*	$KAME: ip6_forward.c,v 1.69 2001/05/17 03:48:30 itojun Exp $	*/

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


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>

#include <netinet/in_pcb.h>

#if IPSEC
#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
#include <netkey/key.h>
extern int ipsec_bypass;
#endif /* IPSEC */
extern lck_mtx_t *ip6_mutex;

#include <netinet6/ip6_fw.h>

#include <net/net_osdep.h>

#if PF
#include <net/pfvar.h>
#endif /* PF */

/*
 * Forward a packet.  If some error occurs return the sender
 * an icmp packet.  Note we can't always generate a meaningful
 * icmp message because icmp doesn't have a large enough repertoire
 * of codes and types.
 *
 * If not forwarding, just drop the packet.  This could be confusing
 * if ipforwarding was zero but some routing protocol was advancing
 * us as a gateway to somewhere.  However, we must let the routing
 * protocol deal with that.
 *
 */

void
ip6_forward(struct mbuf *m, struct route_in6 *ip6forward_rt,
    int srcrt, int locked)
{
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	struct sockaddr_in6 *dst;
	struct rtentry *rt;
	int error, type = 0, code = 0;
	struct mbuf *mcopy = NULL;
	struct ifnet *ifp, *origifp;	/* maybe unnecessary */
#if IPSEC
	struct secpolicy *sp = NULL;
#endif
	struct timeval timenow;
	int	tunneledv4 = 0;

	getmicrotime(&timenow);


#if IPSEC
	/*
	 * Check AH/ESP integrity.
	 */
	/*
	 * Don't increment ip6s_cantforward because this is the check
	 * before forwarding packet actually.
	 */
	if (ipsec_bypass == 0) {
		if (ipsec6_in_reject(m, NULL)) {
			IPSEC_STAT_INCREMENT(ipsec6stat.in_polvio);
			m_freem(m);
			return;
		}
	}
#endif /*IPSEC*/

	/*
	 * Do not forward packets to multicast destination (should be handled
	 * by ip6_mforward().
	 * Do not forward packets with unspecified source.  It was discussed
	 * in July 2000, on ipngwg mailing list.
	 */
	if ((m->m_flags & (M_BCAST|M_MCAST)) != 0 ||
	    IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) ||
	    IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src)) {
		ip6stat.ip6s_cantforward++;
		/* XXX in6_ifstat_inc(rt->rt_ifp, ifs6_in_discard) */
		if (ip6_log_time + ip6_log_interval < timenow.tv_sec) {
			ip6_log_time = timenow.tv_sec;
			log(LOG_DEBUG,
			    "cannot forward "
			    "from %s to %s nxt %d received on %s\n",
			    ip6_sprintf(&ip6->ip6_src),
			    ip6_sprintf(&ip6->ip6_dst),
			    ip6->ip6_nxt,
			    if_name(m->m_pkthdr.rcvif));
		}
		m_freem(m);
		return;
	}

	if (ip6->ip6_hlim <= IPV6_HLIMDEC) {
		/* XXX in6_ifstat_inc(rt->rt_ifp, ifs6_in_discard) */
		if (locked)
			lck_mtx_unlock(ip6_mutex);
		icmp6_error(m, ICMP6_TIME_EXCEEDED,
				ICMP6_TIME_EXCEED_TRANSIT, 0);
		if (locked)
			lck_mtx_lock(ip6_mutex);
		return;
	}
	ip6->ip6_hlim -= IPV6_HLIMDEC;

	/*
	 * Save at most ICMPV6_PLD_MAXLEN (= the min IPv6 MTU -
	 * size of IPv6 + ICMPv6 headers) bytes of the packet in case
	 * we need to generate an ICMP6 message to the src.
	 * Thanks to M_EXT, in most cases copy will not occur.
	 *
	 * It is important to save it before IPsec processing as IPsec
	 * processing may modify the mbuf.
	 */
	mcopy = m_copy(m, 0, imin(m->m_pkthdr.len, ICMPV6_PLD_MAXLEN));

#if IPSEC
	if (ipsec_bypass != 0)
		goto skip_ipsec;
	/* get a security policy for this packet */
	sp = ipsec6_getpolicybyaddr(m, IPSEC_DIR_OUTBOUND, IP_FORWARDING,
	    &error);
	if (sp == NULL) {
		IPSEC_STAT_INCREMENT(ipsec6stat.out_inval);
		ip6stat.ip6s_cantforward++;
		if (mcopy) {
#if 0
			/* XXX: what icmp ? */
#else
			m_freem(mcopy);
#endif
		}
		m_freem(m);
		return;
	}

	error = 0;

	/* check policy */
	switch (sp->policy) {
	case IPSEC_POLICY_DISCARD:
        case IPSEC_POLICY_GENERATE:
		/*
		 * This packet is just discarded.
		 */
		IPSEC_STAT_INCREMENT(ipsec6stat.out_polvio);
		ip6stat.ip6s_cantforward++;
		key_freesp(sp, KEY_SADB_UNLOCKED);
		if (mcopy) {
#if 0
			/* XXX: what icmp ? */
#else
			m_freem(mcopy);
#endif
		}
		m_freem(m);
		return;

	case IPSEC_POLICY_BYPASS:
	case IPSEC_POLICY_NONE:
		/* no need to do IPsec. */
		key_freesp(sp, KEY_SADB_UNLOCKED);
		goto skip_ipsec;

	case IPSEC_POLICY_IPSEC:
		if (sp->req == NULL) {
			/* XXX should be panic ? */
			printf("ip6_forward: No IPsec request specified.\n");
			ip6stat.ip6s_cantforward++;
			key_freesp(sp, KEY_SADB_UNLOCKED);
			if (mcopy) {
#if 0
				/* XXX: what icmp ? */
#else
				m_freem(mcopy);
#endif
			}
			m_freem(m);
			return;
		}
		/* do IPsec */
		break;

	case IPSEC_POLICY_ENTRUST:
	default:
		/* should be panic ?? */
		printf("ip6_forward: Invalid policy found. %d\n", sp->policy);
		key_freesp(sp, KEY_SADB_UNLOCKED);
		goto skip_ipsec;
	}

    {
	struct ipsec_output_state state;

	/*
	 * All the extension headers will become inaccessible
	 * (since they can be encrypted).
	 * Don't panic, we need no more updates to extension headers
	 * on inner IPv6 packet (since they are now encapsulated).
	 *
	 * IPv6 [ESP|AH] IPv6 [extension headers] payload
	 */
	bzero(&state, sizeof(state));
	state.m = m;
	state.ro = NULL;	/* update at ipsec6_output_tunnel() */
	state.dst = NULL;	/* update at ipsec6_output_tunnel() */

	if (locked)
		lck_mtx_unlock(ip6_mutex);
	error = ipsec6_output_tunnel(&state, sp, 0, &tunneledv4);
	if (locked)
		lck_mtx_lock(ip6_mutex);
	key_freesp(sp, KEY_SADB_UNLOCKED);
	if (tunneledv4)
		return;  /* packet is gone - sent over IPv4 */
		
	m = state.m;
	if (error) {
		/* mbuf is already reclaimed in ipsec6_output_tunnel. */
		switch (error) {
		case EHOSTUNREACH:
		case ENETUNREACH:
		case EMSGSIZE:
		case ENOBUFS:
		case ENOMEM:
			break;
		default:
			printf("ip6_output (ipsec): error code %d\n", error);
			/* fall through */
		case ENOENT:
			/* don't show these error codes to the user */
			break;
		}
		ip6stat.ip6s_cantforward++;
		if (mcopy) {
#if 0
			/* XXX: what icmp ? */
#else
			m_freem(mcopy);
#endif
		}
		m_freem(m);
		return;
	}
    }
    skip_ipsec:
#endif /* IPSEC */

	/*
	 * If "locked", ip6forward_rt points to the globally defined
	 * struct route cache which requires ip6_mutex, e.g. when this
	 * is called from ip6_input().  Else the caller is responsible
	 * for the struct route and its serialization (if needed), e.g.
	 * when this is called from ip6_rthdr0().
	 */
	if (locked)
		lck_mtx_assert(ip6_mutex, LCK_MTX_ASSERT_OWNED);
	dst = (struct sockaddr_in6 *)&ip6forward_rt->ro_dst;
	if ((rt = ip6forward_rt->ro_rt) != NULL) {
		RT_LOCK(rt);
		/* Take an extra ref for ourselves */
		RT_ADDREF_LOCKED(rt);
	}

	if (!srcrt) {
		/*
		 * ip6forward_rt->ro_dst.sin6_addr is equal to ip6->ip6_dst
		 */
		if (rt == NULL || !(rt->rt_flags & RTF_UP) ||
		    rt->generation_id != route_generation) {
			if (rt != NULL) {
				/* Release extra ref */
				RT_REMREF_LOCKED(rt);
				RT_UNLOCK(rt);
				rtfree(rt);
				ip6forward_rt->ro_rt = NULL;
			}
			/* this probably fails but give it a try again */
			rtalloc_ign((struct route *)ip6forward_rt,
			    RTF_PRCLONING);
			if ((rt = ip6forward_rt->ro_rt) != NULL) {
				RT_LOCK(rt);
				/* Take an extra ref for ourselves */
				RT_ADDREF_LOCKED(rt);
			}
		}

		if (rt == NULL) {
			ip6stat.ip6s_noroute++;
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_noroute);
			if (mcopy) {
				if (locked)
					lck_mtx_unlock(ip6_mutex);
				icmp6_error(mcopy, ICMP6_DST_UNREACH,
					    ICMP6_DST_UNREACH_NOROUTE, 0);
				if (locked)
					lck_mtx_lock(ip6_mutex);
			}
			m_freem(m);
			return;
		}
		RT_LOCK_ASSERT_HELD(rt);
	} else if (rt == NULL || !(rt->rt_flags & RTF_UP) ||
	    !IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst, &dst->sin6_addr) ||
	    rt->generation_id != route_generation) {
		if (rt != NULL) {
			/* Release extra ref */
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
			rtfree(rt);
			ip6forward_rt->ro_rt = NULL;
		}
		bzero(dst, sizeof(*dst));
		dst->sin6_len = sizeof(struct sockaddr_in6);
		dst->sin6_family = AF_INET6;
		dst->sin6_addr = ip6->ip6_dst;

		rtalloc_ign((struct route *)ip6forward_rt, RTF_PRCLONING);
		if ((rt = ip6forward_rt->ro_rt) == NULL) {
			ip6stat.ip6s_noroute++;
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_noroute);
			if (mcopy) {
				if (locked)
					lck_mtx_unlock(ip6_mutex);
				icmp6_error(mcopy, ICMP6_DST_UNREACH,
				    ICMP6_DST_UNREACH_NOROUTE, 0);
				if (locked)
					lck_mtx_lock(ip6_mutex);
			}
			m_freem(m);
			return;
		}
		RT_LOCK(rt);
		/* Take an extra ref for ourselves */
		RT_ADDREF_LOCKED(rt);
	}

	/*
	 * Scope check: if a packet can't be delivered to its destination
	 * for the reason that the destination is beyond the scope of the
	 * source address, discard the packet and return an icmp6 destination
	 * unreachable error with Code 2 (beyond scope of source address).
	 * [draft-ietf-ipngwg-icmp-v3-02.txt, Section 3.1]
	 */
	if (in6_addr2scopeid(m->m_pkthdr.rcvif, &ip6->ip6_src) !=
	    in6_addr2scopeid(rt->rt_ifp, &ip6->ip6_src)) {
		ip6stat.ip6s_cantforward++;
		ip6stat.ip6s_badscope++;
		in6_ifstat_inc(rt->rt_ifp, ifs6_in_discard);

		if (ip6_log_time + ip6_log_interval < timenow.tv_sec) {
			ip6_log_time = timenow.tv_sec;
			log(LOG_DEBUG,
			    "cannot forward "
			    "src %s, dst %s, nxt %d, rcvif %s, outif %s\n",
			    ip6_sprintf(&ip6->ip6_src),
			    ip6_sprintf(&ip6->ip6_dst),
			    ip6->ip6_nxt,
			    if_name(m->m_pkthdr.rcvif), if_name(rt->rt_ifp));
		}
		/* Release extra ref */
		RT_REMREF_LOCKED(rt);
		RT_UNLOCK(rt);
		if (mcopy) {
			if (locked)
				lck_mtx_unlock(ip6_mutex);
			icmp6_error(mcopy, ICMP6_DST_UNREACH,
				    ICMP6_DST_UNREACH_BEYONDSCOPE, 0);
			if (locked)
				lck_mtx_lock(ip6_mutex);
		}
		m_freem(m);
		return;
	}

	if (m->m_pkthdr.len > rt->rt_ifp->if_mtu) {
		in6_ifstat_inc(rt->rt_ifp, ifs6_in_toobig);
		if (mcopy) {
			uint32_t mtu;
#if IPSEC
			struct secpolicy *sp2;
			int ipsecerror;
			size_t ipsechdrsiz;
#endif

			mtu = rt->rt_ifp->if_mtu;
#if IPSEC
			/*
			 * When we do IPsec tunnel ingress, we need to play
			 * with if_mtu value (decrement IPsec header size
			 * from mtu value).  The code is much simpler than v4
			 * case, as we have the outgoing interface for
			 * encapsulated packet as "rt->rt_ifp".
			 */
			sp2 = ipsec6_getpolicybyaddr(mcopy, IPSEC_DIR_OUTBOUND,
				IP_FORWARDING, &ipsecerror);
			if (sp2) {
				ipsechdrsiz = ipsec6_hdrsiz(mcopy,
					IPSEC_DIR_OUTBOUND, NULL);
				if (ipsechdrsiz < mtu)
					mtu -= ipsechdrsiz;
				key_freesp(sp2, KEY_SADB_UNLOCKED);
			}
			/*
			 * if mtu becomes less than minimum MTU,
			 * tell minimum MTU (and I'll need to fragment it).
			 */
			if (mtu < IPV6_MMTU)
				mtu = IPV6_MMTU;
#endif
			/* Release extra ref */
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
			if (locked)
				lck_mtx_unlock(ip6_mutex);
			icmp6_error(mcopy, ICMP6_PACKET_TOO_BIG, 0, mtu);
			if (locked)
				lck_mtx_lock(ip6_mutex);
		} else {
			/* Release extra ref */
			RT_REMREF_LOCKED(rt);
			RT_UNLOCK(rt);
		}
		m_freem(m);
		return;
 	}

	if (rt->rt_flags & RTF_GATEWAY)
		dst = (struct sockaddr_in6 *)rt->rt_gateway;

	/*
	 * If we are to forward the packet using the same interface
	 * as one we got the packet from, perhaps we should send a redirect
	 * to sender to shortcut a hop.
	 * Only send redirect if source is sending directly to us,
	 * and if packet was not source routed (or has any options).
	 * Also, don't send redirect if forwarding using a route
	 * modified by a redirect.
	 */
	if (rt->rt_ifp == m->m_pkthdr.rcvif && !srcrt &&
	    (rt->rt_flags & (RTF_DYNAMIC|RTF_MODIFIED)) == 0) {
		if ((rt->rt_ifp->if_flags & IFF_POINTOPOINT) != 0) {
			/*
			 * If the incoming interface is equal to the outgoing
			 * one, and the link attached to the interface is
			 * point-to-point, then it will be highly probable
			 * that a routing loop occurs. Thus, we immediately
			 * drop the packet and send an ICMPv6 error message.
			 *
			 * type/code is based on suggestion by Rich Draves.
			 * not sure if it is the best pick.
			 */
			RT_REMREF_LOCKED(rt);	/* Release extra ref */
			RT_UNLOCK(rt);
			if (locked)
				lck_mtx_unlock(ip6_mutex);
			icmp6_error(mcopy, ICMP6_DST_UNREACH,
				    ICMP6_DST_UNREACH_ADDR, 0);
			if (locked)
				lck_mtx_lock(ip6_mutex);
			m_freem(m);
			return;
		}
		type = ND_REDIRECT;
	}

	/*
	 * Check with the firewall...
	 */
	if (ip6_fw_enable && ip6_fw_chk_ptr) {
		u_short port = 0;
		ifp = rt->rt_ifp;
		/* Drop the lock but retain the extra ref */
		RT_UNLOCK(rt);
		/* If ipfw says divert, we have to just drop packet */
		if (ip6_fw_chk_ptr(&ip6, ifp, &port, &m)) {
			m_freem(m);
			goto freecopy;
		}
		if (!m) {
			goto freecopy;
		}
		/* We still have the extra ref on rt */
		RT_LOCK(rt);
	}

	/*
	 * Fake scoped addresses. Note that even link-local source or
	 * destinaion can appear, if the originating node just sends the
	 * packet to us (without address resolution for the destination).
	 * Since both icmp6_error and icmp6_redirect_output fill the embedded
	 * link identifiers, we can do this stuff after making a copy for
	 * returning an error.
	 */
	if ((rt->rt_ifp->if_flags & IFF_LOOPBACK) != 0) {
		/*
		 * See corresponding comments in ip6_output.
		 * XXX: but is it possible that ip6_forward() sends a packet
		 *      to a loopback interface? I don't think so, and thus
		 *      I bark here. (jinmei@kame.net)
		 * XXX: it is common to route invalid packets to loopback.
		 *	also, the codepath will be visited on use of ::1 in
		 *	rthdr. (itojun)
		 */
#if 1
		if (0)
#else
		if ((rt->rt_flags & (RTF_BLACKHOLE|RTF_REJECT)) == 0)
#endif
		{
			printf("ip6_forward: outgoing interface is loopback. "
				"src %s, dst %s, nxt %d, rcvif %s, outif %s\n",
				ip6_sprintf(&ip6->ip6_src),
				ip6_sprintf(&ip6->ip6_dst),
				ip6->ip6_nxt, if_name(m->m_pkthdr.rcvif),
				if_name(rt->rt_ifp));
		}

		/* we can just use rcvif in forwarding. */
		origifp = m->m_pkthdr.rcvif;
	}
	else
		origifp = rt->rt_ifp;
#ifndef SCOPEDROUTING
	/*
	 * clear embedded scope identifiers if necessary.
	 * in6_clearscope will touch the addresses only when necessary.
	 */
	in6_clearscope(&ip6->ip6_src);
	in6_clearscope(&ip6->ip6_dst);
#endif

	ifp = rt->rt_ifp;
	/* Drop the lock but retain the extra ref */
	RT_UNLOCK(rt);

#if PF
	if (locked)
		lck_mtx_unlock(ip6_mutex);

	/* Invoke outbound packet filter */
	error = pf_af_hook(ifp, NULL, &m, AF_INET6, FALSE);

	if (locked)
		lck_mtx_lock(ip6_mutex);

	if (error) {
		if (m != NULL) {
			panic("%s: unexpected packet %p\n", __func__, m);
			/* NOTREACHED */
		}
		/* Already freed by callee */
		goto senderr;
	}
	ip6 = mtod(m, struct ip6_hdr *);
#endif /* PF */

	error = nd6_output(ifp, origifp, m, dst, rt, locked);
	if (error) {
		in6_ifstat_inc(ifp, ifs6_out_discard);
		ip6stat.ip6s_cantforward++;
	} else {
		ip6stat.ip6s_forward++;
		in6_ifstat_inc(ifp, ifs6_out_forward);
		if (type)
			ip6stat.ip6s_redirectsent++;
		else {
			if (mcopy) {
				goto freecopy;
			}
		}
	}
#if PF
senderr:
#endif /* PF */
	if (mcopy == NULL) {
		/* Release extra ref */
		RT_REMREF(rt);
		return;
	}
	switch (error) {
	case 0:
#if 1
		if (type == ND_REDIRECT) {
			icmp6_redirect_output(mcopy, rt);
			/* Release extra ref */
			RT_REMREF(rt);
			return;
		}
#endif
		goto freecopy;

	case EMSGSIZE:
		/* xxx MTU is constant in PPP? */
		goto freecopy;

	case ENOBUFS:
		/* Tell source to slow down like source quench in IP? */
		goto freecopy;

	case ENETUNREACH:	/* shouldn't happen, checked above */
	case EHOSTUNREACH:
	case ENETDOWN:
	case EHOSTDOWN:
	default:
		type = ICMP6_DST_UNREACH;
		code = ICMP6_DST_UNREACH_ADDR;
		break;
	}
	if (locked)
		lck_mtx_unlock(ip6_mutex);
	icmp6_error(mcopy, type, code, 0);
	if (locked)
		lck_mtx_lock(ip6_mutex);
	/* Release extra ref */
	RT_REMREF(rt);
	return;

 freecopy:
	m_freem(mcopy);
	/* Release extra ref */
	RT_REMREF(rt);
	return;
}
