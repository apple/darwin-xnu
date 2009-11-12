/*
 * Copyright (c) 2003-2008 Apple Inc. All rights reserved.
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
/*	$FreeBSD: src/sys/netinet6/ip6_input.c,v 1.11.2.10 2001/07/24 19:10:18 brooks Exp $	*/
/*	$KAME: ip6_input.c,v 1.194 2001/05/27 13:28:35 itojun Exp $	*/

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
 * Copyright (c) 1982, 1986, 1988, 1993
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
 *	@(#)ip_input.c	8.2 (Berkeley) 1/4/94
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/proc.h>
#include <sys/kauth.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/kpi_protocol.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#if INET
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif /*INET*/
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet/in_pcb.h>
#include <netinet/icmp6.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/nd6.h>
#include <netinet6/in6_prefix.h>

#if IPSEC
#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
extern int ipsec_bypass;
#endif

#include <netinet6/ip6_fw.h>

#include <netinet/kpi_ipfilter_var.h>

#include <netinet6/ip6protosw.h>

/* we need it for NLOOP. */
#include "loop.h"
#include "faith.h"

#include <net/net_osdep.h>

#if PF
#include <net/pfvar.h>
#endif /* PF */

extern struct domain inet6domain;
extern struct ip6protosw inet6sw[];

struct ip6protosw *  ip6_protox[IPPROTO_MAX];
static int ip6qmaxlen = IFQ_MAXLEN;
struct in6_ifaddr *in6_ifaddrs;

int ip6_forward_srcrt;			/* XXX */
int ip6_sourcecheck;			/* XXX */
int ip6_sourcecheck_interval;		/* XXX */
const int int6intrq_present = 1;

int ip6_ours_check_algorithm;
int in6_init2done = 0;


#if IPFW2
/* firewall hooks */
ip6_fw_chk_t *ip6_fw_chk_ptr;
ip6_fw_ctl_t *ip6_fw_ctl_ptr;
int ip6_fw_enable = 1;
#endif

struct ip6stat ip6stat;

#ifdef __APPLE__
struct ifqueue ip6intrq;
lck_mtx_t 		*ip6_mutex;
lck_mtx_t 		*dad6_mutex;
lck_mtx_t 		*nd6_mutex;
lck_mtx_t		*prefix6_mutex;
lck_mtx_t		*scope6_mutex;
lck_attr_t		*ip6_mutex_attr;
lck_grp_t		*ip6_mutex_grp;
lck_grp_attr_t		*ip6_mutex_grp_attr;
extern lck_mtx_t	*inet6_domain_mutex;
#endif
extern int loopattach_done;

static void ip6_init2(void *);
static struct ip6aux *ip6_setdstifaddr(struct mbuf *, struct in6_ifaddr *);

static int ip6_hopopts_input(u_int32_t *, u_int32_t *, struct mbuf **, int *);
#if PULLDOWN_TEST
static struct mbuf *ip6_pullexthdr(struct mbuf *, size_t, int);
#endif

#ifdef __APPLE__
void gifattach(void);
void faithattach(void);
void stfattach(void);
#endif

extern lck_mtx_t *domain_proto_mtx;


static void
ip6_proto_input(
	__unused protocol_family_t	protocol,
	mbuf_t				packet)
{
	ip6_input(packet);
}

/*
 * IP6 initialization: fill in IP6 protocol switch table.
 * All protocols not implemented in kernel go to raw IP6 protocol handler.
 */
void
ip6_init()
{
	struct ip6protosw *pr;
	int i;
	struct timeval tv;

#if DIAGNOSTIC
	if (sizeof(struct protosw) != sizeof(struct ip6protosw))
		panic("sizeof(protosw) != sizeof(ip6protosw)");
#endif
	pr = (struct ip6protosw *)pffindproto_locked(PF_INET6, IPPROTO_RAW, SOCK_RAW);
	if (pr == 0)
		panic("ip6_init");
	for (i = 0; i < IPPROTO_MAX; i++)
		ip6_protox[i] = pr;
	for (pr = (struct ip6protosw*)inet6domain.dom_protosw; pr; pr = pr->pr_next) {
		if(!(pr->pr_domain)) continue;    /* If uninitialized, skip */
		if (pr->pr_domain->dom_family == PF_INET6 &&
		    pr->pr_protocol && pr->pr_protocol != IPPROTO_RAW) {
			ip6_protox[pr->pr_protocol] = pr;
		}
	}

	ip6_mutex_grp_attr  = lck_grp_attr_alloc_init();

	ip6_mutex_grp = lck_grp_alloc_init("ip6", ip6_mutex_grp_attr);
	ip6_mutex_attr = lck_attr_alloc_init();

	if ((ip6_mutex = lck_mtx_alloc_init(ip6_mutex_grp, ip6_mutex_attr)) == NULL) {
		panic("ip6_init: can't alloc ip6_mutex\n");
	}
	if ((dad6_mutex = lck_mtx_alloc_init(ip6_mutex_grp, ip6_mutex_attr)) == NULL) {
		panic("ip6_init: can't alloc dad6_mutex\n");
	}
	if ((nd6_mutex = lck_mtx_alloc_init(ip6_mutex_grp, ip6_mutex_attr)) == NULL) {
		panic("ip6_init: can't alloc nd6_mutex\n");
	}

	if ((prefix6_mutex = lck_mtx_alloc_init(ip6_mutex_grp, ip6_mutex_attr)) == NULL) {
		panic("ip6_init: can't alloc prefix6_mutex\n");
	}

	if ((scope6_mutex = lck_mtx_alloc_init(ip6_mutex_grp, ip6_mutex_attr)) == NULL) {
		panic("ip6_init: can't alloc scope6_mutex\n");
	}


	inet6domain.dom_flags = DOM_REENTRANT;	

	ip6intrq.ifq_maxlen = ip6qmaxlen;
	in6_ifaddr_init();
	nd6_init();
	frag6_init();
	icmp6_init();
	/*
	 * in many cases, random() here does NOT return random number
	 * as initialization during bootstrap time occur in fixed order.
	 */
	microtime(&tv);
	ip6_flow_seq = random() ^ tv.tv_usec;
	microtime(&tv);
	ip6_desync_factor = (random() ^ tv.tv_usec) % MAX_TEMP_DESYNC_FACTOR;
	timeout(ip6_init2, (caddr_t)0, 1 * hz);

	lck_mtx_unlock(domain_proto_mtx);	
	proto_register_input(PF_INET6, ip6_proto_input, NULL, 0);
	lck_mtx_lock(domain_proto_mtx);	
}

static void
ip6_init2(
	__unused void *dummy)
{
	/*
	 * to route local address of p2p link to loopback,
	 * assign loopback address first.
	 */
	if (loopattach_done == 0) {
		timeout(ip6_init2, (caddr_t)0, 1 * hz);
		return;
	}
	(void) in6_ifattach(lo_ifp, NULL, NULL);

#ifdef __APPLE__
	/* nd6_timer_init */
	timeout(nd6_timer, (caddr_t)0, hz);

	/* router renumbering prefix list maintenance */
	timeout(in6_rr_timer, (caddr_t)0, hz);

	/* timer for regeneranation of temporary addresses randomize ID */
	timeout(in6_tmpaddrtimer, (caddr_t)0,
		(ip6_temp_preferred_lifetime - ip6_desync_factor -
		       ip6_temp_regen_advance) * hz);

#if NGIF
	gifattach();
#endif
#if NFAITH
	faithattach();
#endif
#if NSTF
	stfattach();
#endif
#else
	/* nd6_timer_init */

	callout_init(&nd6_timer_ch);
	callout_reset(&nd6_timer_ch, hz, nd6_timer, NULL);

	/* router renumbering prefix list maintenance */
	callout_init(&in6_rr_timer_ch);
	callout_reset(&in6_rr_timer_ch, hz, in6_rr_timer, NULL);

	/* timer for regeneranation of temporary addresses randomize ID */
	callout_reset(&in6_tmpaddrtimer_ch,
		      (ip6_temp_preferred_lifetime - ip6_desync_factor -
		       ip6_temp_regen_advance) * hz,
		      in6_tmpaddrtimer, NULL);
#endif

	in6_init2done = 1;
}

#if __FreeBSD__
/* cheat */
/* This must be after route_init(), which is now SI_ORDER_THIRD */
SYSINIT(netinet6init2, SI_SUB_PROTO_DOMAIN, SI_ORDER_MIDDLE, ip6_init2, NULL);
#endif

/*
 * ip6_forward_rt contains the route entry that was recently used during
 * the forwarding of an IPv6 packet and thus acts as a route cache.  Access
 * to this variable is protected by the global lock ip6_mutex.
 */
static struct route_in6 ip6_forward_rt;

void
ip6_input(m)
	struct mbuf *m;
{
	struct ip6_hdr *ip6;
	int off = sizeof(struct ip6_hdr), nest;
	u_int32_t plen;
	u_int32_t rtalert = ~0;
	int nxt = 0, ours = 0;
	struct ifnet *deliverifp = NULL;
	ipfilter_t inject_ipfref = 0;
	int seen;

	/*
	 * No need to proccess packet twice if we've 
	 * already seen it
	 */
	inject_ipfref = ipf_get_inject_filter(m);
	if (inject_ipfref != 0) {
		ip6 = mtod(m, struct ip6_hdr *);
		nxt = ip6->ip6_nxt;
		seen = 0;
		goto injectit;
	} else
		seen = 1;
	
#if IPSEC
	/*
	 * should the inner packet be considered authentic?
	 * see comment in ah4_input().
	 */
	if (m) {
		m->m_flags &= ~M_AUTHIPHDR;
		m->m_flags &= ~M_AUTHIPDGM;
	}
#endif

	/*
	 * make sure we don't have onion peering information into m_aux.
	 */
	ip6_delaux(m);

	lck_mtx_lock(ip6_mutex);
	/*
	 * mbuf statistics
	 */
	if (m->m_flags & M_EXT) {
		if (m->m_next)
			ip6stat.ip6s_mext2m++;
		else
			ip6stat.ip6s_mext1++;
	} else {
#define M2MMAX	(sizeof(ip6stat.ip6s_m2m)/sizeof(ip6stat.ip6s_m2m[0]))
		if (m->m_next) {
			if (m->m_flags & M_LOOP) {
				ip6stat.ip6s_m2m[ifnet_index(lo_ifp)]++;	/* XXX */
			} else if (m->m_pkthdr.rcvif->if_index < M2MMAX)
				ip6stat.ip6s_m2m[m->m_pkthdr.rcvif->if_index]++;
			else
				ip6stat.ip6s_m2m[0]++;
		} else
			ip6stat.ip6s_m1++;
#undef M2MMAX
	}

	in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_receive);
	ip6stat.ip6s_total++;

#ifndef PULLDOWN_TEST
	/*
	 * L2 bridge code and some other code can return mbuf chain
	 * that does not conform to KAME requirement.  too bad.
	 * XXX: fails to join if interface MTU > MCLBYTES.  jumbogram?
	 */
	if (m && m->m_next != NULL && m->m_pkthdr.len < MCLBYTES) {
		struct mbuf *n;

		MGETHDR(n, M_DONTWAIT, MT_HEADER);	/* MAC-OK */
		if (n)
			M_COPY_PKTHDR(n, m);
		if (n && m->m_pkthdr.len > MHLEN) {
			MCLGET(n, M_DONTWAIT);
			if ((n->m_flags & M_EXT) == 0) {
				m_freem(n);
				n = NULL;
			}
		}
		if (n == NULL) {
			m_freem(m);
			lck_mtx_unlock(ip6_mutex);
			return;	/*ENOBUFS*/
		}

		m_copydata(m, 0, m->m_pkthdr.len, mtod(n, caddr_t));
		n->m_len = m->m_pkthdr.len;
		m_freem(m);
		m = n;
	}
	IP6_EXTHDR_CHECK(m, 0, sizeof(struct ip6_hdr),
		{lck_mtx_unlock(ip6_mutex); return;}); 
#endif

	if (m->m_len < sizeof(struct ip6_hdr)) {
		struct ifnet *inifp;
		inifp = m->m_pkthdr.rcvif;
		if ((m = m_pullup(m, sizeof(struct ip6_hdr))) == 0) {
			ip6stat.ip6s_toosmall++;
			in6_ifstat_inc(inifp, ifs6_in_hdrerr);
			lck_mtx_unlock(ip6_mutex);
			return;
		}
	}

	ip6 = mtod(m, struct ip6_hdr *);

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
		ip6stat.ip6s_badvers++;
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_hdrerr);
		goto bad;
	}

	ip6stat.ip6s_nxthist[ip6->ip6_nxt]++;

#if IPFW2
	/*
	 * Check with the firewall...
	 */
	if (ip6_fw_enable && ip6_fw_chk_ptr) {
		u_short port = 0;
		/* If ipfw says divert, we have to just drop packet */
		/* use port as a dummy argument */
		if ((*ip6_fw_chk_ptr)(&ip6, NULL, &port, &m)) {
			m_freem(m);
			m = NULL;
		}
		if (!m) {
			lck_mtx_unlock(ip6_mutex);
			return;
		}
	}
#endif

	/*
	 * Check against address spoofing/corruption.
	 */
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_src) ||
	    IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_dst)) {
		/*
		 * XXX: "badscope" is not very suitable for a multicast source.
		 */
		ip6stat.ip6s_badscope++;
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_addrerr);
		goto bad;
	}
	if ((IN6_IS_ADDR_LOOPBACK(&ip6->ip6_src) ||
	     IN6_IS_ADDR_LOOPBACK(&ip6->ip6_dst)) &&
	    (m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK) == 0) {
		ip6stat.ip6s_badscope++;
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_addrerr);
		goto bad;
	}

	/*
	 * The following check is not documented in specs.  A malicious
	 * party may be able to use IPv4 mapped addr to confuse tcp/udp stack
	 * and bypass security checks (act as if it was from 127.0.0.1 by using
	 * IPv6 src ::ffff:127.0.0.1).	Be cautious.
	 *
	 * This check chokes if we are in an SIIT cloud.  As none of BSDs
	 * support IPv4-less kernel compilation, we cannot support SIIT
	 * environment at all.  So, it makes more sense for us to reject any
	 * malicious packets for non-SIIT environment, than try to do a
	 * partical support for SIIT environment.
	 */
	if (IN6_IS_ADDR_V4MAPPED(&ip6->ip6_src) ||
	    IN6_IS_ADDR_V4MAPPED(&ip6->ip6_dst)) {
		ip6stat.ip6s_badscope++;
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_addrerr);
		goto bad;
	}
#if 0
	/*
	 * Reject packets with IPv4 compatible addresses (auto tunnel).
	 *
	 * The code forbids auto tunnel relay case in RFC1933 (the check is
	 * stronger than RFC1933).  We may want to re-enable it if mech-xx
	 * is revised to forbid relaying case.
	 */
	if (IN6_IS_ADDR_V4COMPAT(&ip6->ip6_src) ||
	    IN6_IS_ADDR_V4COMPAT(&ip6->ip6_dst)) {
		ip6stat.ip6s_badscope++;
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_addrerr);
		goto bad;
	}
#endif

#if PF
	/* Invoke inbound packet filter */
	lck_mtx_unlock(ip6_mutex);
	if (pf_af_hook(m->m_pkthdr.rcvif, NULL, &m, AF_INET6, TRUE) != 0) {
		if (m != NULL) {
			panic("%s: unexpected packet %p\n", __func__, m);
			/* NOTREACHED */
		}
		/* Already freed by callee */
		return;
	}
	ip6 = mtod(m, struct ip6_hdr *);
	lck_mtx_lock(ip6_mutex);
#endif /* PF */

	/* drop packets if interface ID portion is already filled */
	if ((m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK) == 0) {
		if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src) &&
		    ip6->ip6_src.s6_addr16[1]) {
			ip6stat.ip6s_badscope++;
			goto bad;
		}
		if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst) &&
		    ip6->ip6_dst.s6_addr16[1]) {
			ip6stat.ip6s_badscope++;
			goto bad;
		}
	}

	if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src))
		ip6->ip6_src.s6_addr16[1]
			= htons(m->m_pkthdr.rcvif->if_index);
	if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst))
		ip6->ip6_dst.s6_addr16[1]
			= htons(m->m_pkthdr.rcvif->if_index);

#if 0 /* this case seems to be unnecessary. (jinmei, 20010401) */
	/*
	 * We use rt->rt_ifp to determine if the address is ours or not.
	 * If rt_ifp is lo0, the address is ours.
	 * The problem here is, rt->rt_ifp for fe80::%lo0/64 is set to lo0,
	 * so any address under fe80::%lo0/64 will be mistakenly considered
	 * local.  The special case is supplied to handle the case properly
	 * by actually looking at interface addresses
	 * (using in6ifa_ifpwithaddr).
	 */
	if ((m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK) != 0 &&
	    IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_dst)) {
	    struct in6_ifaddr *ia6;
		if (!(ia6 = in6ifa_ifpwithaddr(m->m_pkthdr.rcvif, &ip6->ip6_dst))) {
			lck_mtx_unlock(ip6_mutex);
			icmp6_error(m, ICMP6_DST_UNREACH,
			    ICMP6_DST_UNREACH_ADDR, 0);
			/* m is already freed */
			return;
		}
		ifafree(&ia6->ia_ifa);

		ours = 1;
		deliverifp = m->m_pkthdr.rcvif;
		goto hbhcheck;
	}
#endif

	/*
	 * Multicast check
	 */
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		struct	in6_multi *in6m = 0;
		struct ifnet *ifp = m->m_pkthdr.rcvif;

		in6_ifstat_inc(ifp, ifs6_in_mcast);
		/*
		 * See if we belong to the destination multicast group on the
		 * arrival interface.
		 */
		ifnet_lock_shared(ifp);
		IN6_LOOKUP_MULTI(ip6->ip6_dst, ifp, in6m);
		ifnet_lock_done(ifp);
		if (in6m)
			ours = 1;
		else if (!ip6_mrouter) {
			ip6stat.ip6s_notmember++;
			ip6stat.ip6s_cantforward++;
			in6_ifstat_inc(ifp, ifs6_in_discard);
			goto bad;
		}
		deliverifp = ifp;
		goto hbhcheck;
	}

	if (ip6_forward_rt.ro_rt != NULL)
		RT_LOCK(ip6_forward_rt.ro_rt);
	/*
	 *  Unicast check
	 */
	if (ip6_forward_rt.ro_rt != NULL &&
	    (ip6_forward_rt.ro_rt->rt_flags & RTF_UP) &&
	    IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst,
	    &((struct sockaddr_in6 *)(&ip6_forward_rt.ro_dst))->sin6_addr) &&
	    ip6_forward_rt.ro_rt->generation_id == route_generation) {
		ip6stat.ip6s_forward_cachehit++;
	} else {
		struct sockaddr_in6 *dst6;

		if (ip6_forward_rt.ro_rt != NULL) {
			/* route is down/stale or destination is different */
			ip6stat.ip6s_forward_cachemiss++;
			RT_UNLOCK(ip6_forward_rt.ro_rt);
			rtfree(ip6_forward_rt.ro_rt);
			ip6_forward_rt.ro_rt = NULL;
		}

		bzero(&ip6_forward_rt.ro_dst, sizeof(struct sockaddr_in6));
		dst6 = (struct sockaddr_in6 *)&ip6_forward_rt.ro_dst;
		dst6->sin6_len = sizeof(struct sockaddr_in6);
		dst6->sin6_family = AF_INET6;
		dst6->sin6_addr = ip6->ip6_dst;
#if SCOPEDROUTING
		ip6_forward_rt.ro_dst.sin6_scope_id =
			in6_addr2scopeid(m->m_pkthdr.rcvif, &ip6->ip6_dst);
#endif

		rtalloc_ign((struct route *)&ip6_forward_rt, RTF_PRCLONING);
		if (ip6_forward_rt.ro_rt != NULL)
			RT_LOCK(ip6_forward_rt.ro_rt);
	}

#define rt6_key(r) ((struct sockaddr_in6 *)((r)->rt_nodes->rn_key))

	/*
	 * Accept the packet if the forwarding interface to the destination
	 * according to the routing table is the loopback interface,
	 * unless the associated route has a gateway.
	 * Note that this approach causes to accept a packet if there is a
	 * route to the loopback interface for the destination of the packet.
	 * But we think it's even useful in some situations, e.g. when using
	 * a special daemon which wants to intercept the packet.
	 *
	 * XXX: some OSes automatically make a cloned route for the destination
	 * of an outgoing packet.  If the outgoing interface of the packet
	 * is a loopback one, the kernel would consider the packet to be
	 * accepted, even if we have no such address assinged on the interface.
	 * We check the cloned flag of the route entry to reject such cases,
	 * assuming that route entries for our own addresses are not made by
	 * cloning (it should be true because in6_addloop explicitly installs
	 * the host route).  However, we might have to do an explicit check
	 * while it would be less efficient.  Or, should we rather install a
	 * reject route for such a case?
	 */
	if (ip6_forward_rt.ro_rt != NULL &&
	    (ip6_forward_rt.ro_rt->rt_flags &
	     (RTF_HOST|RTF_GATEWAY)) == RTF_HOST &&
#if RTF_WASCLONED
	    !(ip6_forward_rt.ro_rt->rt_flags & RTF_WASCLONED) &&
#endif
#if 0
	    /*
	     * The check below is redundant since the comparison of
	     * the destination and the key of the rtentry has
	     * already done through looking up the routing table.
	     */
	    IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst,
				&rt6_key(ip6_forward_rt.ro_rt)->sin6_addr)
#endif
	    ip6_forward_rt.ro_rt->rt_ifp->if_type == IFT_LOOP) {
		struct in6_ifaddr *ia6 =
			(struct in6_ifaddr *)ip6_forward_rt.ro_rt->rt_ifa;

		/*
		 * record address information into m_aux.
		 */
		(void)ip6_setdstifaddr(m, ia6);

		/*
		 * packets to a tentative, duplicated, or somehow invalid
		 * address must not be accepted.
		 */
		if (!(ia6->ia6_flags & IN6_IFF_NOTREADY)) {
			/* this address is ready */
			ours = 1;
			deliverifp = ia6->ia_ifp;	/* correct? */
			/* Count the packet in the ip address stats */
#ifndef __APPLE__

			ia6->ia_ifa.if_ipackets++;
			ia6->ia_ifa.if_ibytes += m->m_pkthdr.len;
#endif
			RT_UNLOCK(ip6_forward_rt.ro_rt);
			goto hbhcheck;
		} else {
			RT_UNLOCK(ip6_forward_rt.ro_rt);
			/* address is not ready, so discard the packet. */
			nd6log((LOG_INFO,
			    "ip6_input: packet to an unready address %s->%s\n",
			    ip6_sprintf(&ip6->ip6_src),
			    ip6_sprintf(&ip6->ip6_dst)));
			goto bad;
		}
	}

	/*
	 * FAITH(Firewall Aided Internet Translator)
	 */
#if defined(NFAITH) && 0 < NFAITH
	if (ip6_keepfaith) {
		if (ip6_forward_rt.ro_rt && ip6_forward_rt.ro_rt->rt_ifp
		 && ip6_forward_rt.ro_rt->rt_ifp->if_type == IFT_FAITH) {
			/* XXX do we need more sanity checks? */
			ours = 1;
			deliverifp = ip6_forward_rt.ro_rt->rt_ifp; /* faith */
			RT_UNLOCK(ip6_forward_rt.ro_rt);
			goto hbhcheck;
		}
	}
#endif
	if (ip6_forward_rt.ro_rt != NULL)
		RT_UNLOCK(ip6_forward_rt.ro_rt);

	/*
	 * Now there is no reason to process the packet if it's not our own
	 * and we're not a router.
	 */
	if (!ip6_forwarding) {
		ip6stat.ip6s_cantforward++;
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_discard);
		goto bad;
	}

  hbhcheck:
	/*
	 * record address information into m_aux, if we don't have one yet.
	 * note that we are unable to record it, if the address is not listed
	 * as our interface address (e.g. multicast addresses, addresses
	 * within FAITH prefixes and such).
	 */
	if (deliverifp && !ip6_getdstifaddr(m)) {
		struct in6_ifaddr *ia6;

		ia6 = in6_ifawithifp(deliverifp, &ip6->ip6_dst);
		if (ia6) {
			if (!ip6_setdstifaddr(m, ia6)) {
				/*
				 * XXX maybe we should drop the packet here,
				 * as we could not provide enough information
				 * to the upper layers.
				 */
			}
			ifafree(&ia6->ia_ifa);
		}
	}

	/*
	 * Process Hop-by-Hop options header if it's contained.
	 * m may be modified in ip6_hopopts_input().
	 * If a JumboPayload option is included, plen will also be modified.
	 */
	plen = (u_int32_t)ntohs(ip6->ip6_plen);
	if (ip6->ip6_nxt == IPPROTO_HOPOPTS) {
		struct ip6_hbh *hbh;

		if (ip6_hopopts_input(&plen, &rtalert, &m, &off)) {
#if 0	/*touches NULL pointer*/
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_discard);
#endif
			lck_mtx_unlock(ip6_mutex);
			return;	/* m have already been freed */
		}

		/* adjust pointer */
		ip6 = mtod(m, struct ip6_hdr *);

		/*
		 * if the payload length field is 0 and the next header field
		 * indicates Hop-by-Hop Options header, then a Jumbo Payload
		 * option MUST be included.
		 */
		if (ip6->ip6_plen == 0 && plen == 0) {
			/*
			 * Note that if a valid jumbo payload option is
			 * contained, ip6_hoptops_input() must set a valid
			 * (non-zero) payload length to the variable plen. 
			 */
			ip6stat.ip6s_badoptions++;
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_discard);
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_hdrerr);
			lck_mtx_unlock(ip6_mutex);
			icmp6_error(m, ICMP6_PARAM_PROB,
				    ICMP6_PARAMPROB_HEADER,
				    (caddr_t)&ip6->ip6_plen - (caddr_t)ip6);
			return;
		}
#ifndef PULLDOWN_TEST
		/* ip6_hopopts_input() ensures that mbuf is contiguous */
		hbh = (struct ip6_hbh *)(ip6 + 1);
#else
		IP6_EXTHDR_GET(hbh, struct ip6_hbh *, m, sizeof(struct ip6_hdr),
			sizeof(struct ip6_hbh));
		if (hbh == NULL) {
			ip6stat.ip6s_tooshort++;
			lck_mtx_unlock(ip6_mutex);
			return;
		}
#endif
		nxt = hbh->ip6h_nxt;

		/*
		 * accept the packet if a router alert option is included
		 * and we act as an IPv6 router.
		 */
		if (rtalert != ~0 && ip6_forwarding)
			ours = 1;
	} else
		nxt = ip6->ip6_nxt;

	/*
	 * Check that the amount of data in the buffers
	 * is as at least much as the IPv6 header would have us expect.
	 * Trim mbufs if longer than we expect.
	 * Drop packet if shorter than we expect.
	 */
	if (m->m_pkthdr.len - sizeof(struct ip6_hdr) < plen) {
		ip6stat.ip6s_tooshort++;
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_truncated);
		goto bad;
	}
	if (m->m_pkthdr.len > sizeof(struct ip6_hdr) + plen) {
		if (m->m_len == m->m_pkthdr.len) {
			m->m_len = sizeof(struct ip6_hdr) + plen;
			m->m_pkthdr.len = sizeof(struct ip6_hdr) + plen;
		} else
			m_adj(m, sizeof(struct ip6_hdr) + plen - m->m_pkthdr.len);
	}

	/*
	 * Forward if desirable.
	 */
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		/*
		 * If we are acting as a multicast router, all
		 * incoming multicast packets are passed to the
		 * kernel-level multicast forwarding function.
		 * The packet is returned (relatively) intact; if
		 * ip6_mforward() returns a non-zero value, the packet
		 * must be discarded, else it may be accepted below.
		 */
		if (ip6_mrouter && ip6_mforward(ip6, m->m_pkthdr.rcvif, m)) {
			ip6stat.ip6s_cantforward++;
			m_freem(m);
			lck_mtx_unlock(ip6_mutex);
			return;
		}
		if (!ours) {
			m_freem(m);
			lck_mtx_unlock(ip6_mutex);
			return;
		}
	} else if (!ours) {
		ip6_forward(m, &ip6_forward_rt, 0, 1);
		lck_mtx_unlock(ip6_mutex);
		return;
	}	

	ip6 = mtod(m, struct ip6_hdr *);

	/*
	 * Malicious party may be able to use IPv4 mapped addr to confuse
	 * tcp/udp stack and bypass security checks (act as if it was from
	 * 127.0.0.1 by using IPv6 src ::ffff:127.0.0.1).  Be cautious.
	 *
	 * For SIIT end node behavior, you may want to disable the check.
	 * However, you will  become vulnerable to attacks using IPv4 mapped
	 * source.
	 */
	if (IN6_IS_ADDR_V4MAPPED(&ip6->ip6_src) ||
	    IN6_IS_ADDR_V4MAPPED(&ip6->ip6_dst)) {
		ip6stat.ip6s_badscope++;
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_addrerr);
		goto bad;
	}

	/*
	 * Tell launch routine the next header
	 */
	ip6stat.ip6s_delivered++;
	in6_ifstat_inc(deliverifp, ifs6_in_deliver);

	lck_mtx_unlock(ip6_mutex);
injectit:
	nest = 0;

	while (nxt != IPPROTO_DONE) {
		struct ipfilter *filter;
		
		if (ip6_hdrnestlimit && (++nest > ip6_hdrnestlimit)) {
			ip6stat.ip6s_toomanyhdr++;
			goto badunlocked;
		}

		/*
		 * protection against faulty packet - there should be
		 * more sanity checks in header chain processing.
		 */
		if (m->m_pkthdr.len < off) {
			ip6stat.ip6s_tooshort++;
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_truncated);
			goto badunlocked;
		}

#if 0
		/*
		 * do we need to do it for every header?  yeah, other
		 * functions can play with it (like re-allocate and copy).
		 */
		mhist = ip6_addaux(m);
		if (mhist && M_TRAILINGSPACE(mhist) >= sizeof(nxt)) {
			hist = mtod(mhist, caddr_t) + mhist->m_len;
			bcopy(&nxt, hist, sizeof(nxt));
			mhist->m_len += sizeof(nxt);
		} else {
			ip6stat.ip6s_toomanyhdr++;
			goto bad;
		}
#endif

#if IPSEC
		/*
		 * enforce IPsec policy checking if we are seeing last header.
		 * note that we do not visit this with protocols with pcb layer
		 * code - like udp/tcp/raw ip.
		 */
		if ((ipsec_bypass == 0) && (ip6_protox[nxt]->pr_flags & PR_LASTHDR) != 0) {
			if (ipsec6_in_reject(m, NULL)) {
				IPSEC_STAT_INCREMENT(ipsec6stat.in_polvio);
				goto badunlocked;
		    }
		}
#endif

		/*
		 * Call IP filter
		 */
		if (!TAILQ_EMPTY(&ipv6_filters)) {
			ipf_ref();
			TAILQ_FOREACH(filter, &ipv6_filters, ipf_link) {
				if (seen == 0) {
					if ((struct ipfilter *)inject_ipfref == filter)
						seen = 1;
				} else if (filter->ipf_filter.ipf_input) {
					errno_t result;
					
					result = filter->ipf_filter.ipf_input(
						filter->ipf_filter.cookie, (mbuf_t*)&m, off, nxt);
					if (result == EJUSTRETURN) {
						ipf_unref();
						return;
					}
					if (result != 0) {
						ipf_unref();
						m_freem(m);
						return;
					}
				}
			}
			ipf_unref();
		}
		if (!(ip6_protox[nxt]->pr_flags & PR_PROTOLOCK)) {
			lck_mtx_lock(inet6_domain_mutex);
			nxt = (*ip6_protox[nxt]->pr_input)(&m, &off);
			lck_mtx_unlock(inet6_domain_mutex);
		}
		else
			nxt = (*ip6_protox[nxt]->pr_input)(&m, &off);
	}
	return;
 bad:
	lck_mtx_unlock(ip6_mutex);
 badunlocked:
	m_freem(m);
	return;
}

/*
 * set/grab in6_ifaddr correspond to IPv6 destination address.
 * XXX backward compatibility wrapper
 */
static struct ip6aux *
ip6_setdstifaddr(struct mbuf *m, struct in6_ifaddr *ia6)
{
	struct ip6aux *n;

	n = ip6_addaux(m);
	if (n)
		n->ip6a_dstia6 = ia6;
	return (struct ip6aux *)n;	/* NULL if failed to set */
}

struct in6_ifaddr *
ip6_getdstifaddr(m)
	struct mbuf *m;
{
	struct ip6aux *n;

	n = ip6_findaux(m);
	if (n)
		return n->ip6a_dstia6;
	else
		return NULL;
}

/*
 * Hop-by-Hop options header processing. If a valid jumbo payload option is
 * included, the real payload length will be stored in plenp.
 */
static int
ip6_hopopts_input(plenp, rtalertp, mp, offp)
	u_int32_t *plenp;
	u_int32_t *rtalertp;	/* XXX: should be stored more smart way */
	struct mbuf **mp;
	int *offp;
{
	struct mbuf *m = *mp;
	int off = *offp, hbhlen;
	struct ip6_hbh *hbh;
	u_int8_t *opt;

	/* validation of the length of the header */
#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, sizeof(*hbh), return -1);
	hbh = (struct ip6_hbh *)(mtod(m, caddr_t) + off);
	hbhlen = (hbh->ip6h_len + 1) << 3;

	IP6_EXTHDR_CHECK(m, off, hbhlen, return -1);
	hbh = (struct ip6_hbh *)(mtod(m, caddr_t) + off);
#else
	IP6_EXTHDR_GET(hbh, struct ip6_hbh *, m,
		sizeof(struct ip6_hdr), sizeof(struct ip6_hbh));
	if (hbh == NULL) {
		ip6stat.ip6s_tooshort++;
		return -1;
	}
	hbhlen = (hbh->ip6h_len + 1) << 3;
	IP6_EXTHDR_GET(hbh, struct ip6_hbh *, m, sizeof(struct ip6_hdr),
		hbhlen);
	if (hbh == NULL) {
		ip6stat.ip6s_tooshort++;
		return -1;
	}
#endif
	off += hbhlen;
	hbhlen -= sizeof(struct ip6_hbh);
	opt = (u_int8_t *)hbh + sizeof(struct ip6_hbh);

	if (ip6_process_hopopts(m, (u_int8_t *)hbh + sizeof(struct ip6_hbh),
				hbhlen, rtalertp, plenp) < 0)
		return(-1);

	*offp = off;
	*mp = m;
	return(0);
}

/*
 * Search header for all Hop-by-hop options and process each option.
 * This function is separate from ip6_hopopts_input() in order to
 * handle a case where the sending node itself process its hop-by-hop
 * options header. In such a case, the function is called from ip6_output().
 *
 * The function assumes that hbh header is located right after the IPv6 header
 * (RFC2460 p7), opthead is pointer into data content in m, and opthead to
 * opthead + hbhlen is located in continuous memory region.
 */
int
ip6_process_hopopts(m, opthead, hbhlen, rtalertp, plenp)
	struct mbuf *m;
	u_int8_t *opthead;
	int hbhlen;
	u_int32_t *rtalertp;
	u_int32_t *plenp;
{
	struct ip6_hdr *ip6;
	int optlen = 0;
	u_int8_t *opt = opthead;
	u_int16_t rtalert_val;
	u_int32_t jumboplen;
	const int erroff = sizeof(struct ip6_hdr) + sizeof(struct ip6_hbh);

	for (; hbhlen > 0; hbhlen -= optlen, opt += optlen) {
		switch (*opt) {
		case IP6OPT_PAD1:
			optlen = 1;
			break;
		case IP6OPT_PADN:
			if (hbhlen < IP6OPT_MINLEN) {
				ip6stat.ip6s_toosmall++;
				goto bad;
			}
			optlen = *(opt + 1) + 2;
			break;
		case IP6OPT_RTALERT:
			/* XXX may need check for alignment */
			if (hbhlen < IP6OPT_RTALERT_LEN) {
				ip6stat.ip6s_toosmall++;
				goto bad;
			}
			if (*(opt + 1) != IP6OPT_RTALERT_LEN - 2) {
				/* XXX stat */
				lck_mtx_unlock(ip6_mutex);
				icmp6_error(m, ICMP6_PARAM_PROB,
					    ICMP6_PARAMPROB_HEADER,
					    erroff + opt + 1 - opthead);
				lck_mtx_lock(ip6_mutex);
				return(-1);
			}
			optlen = IP6OPT_RTALERT_LEN;
			bcopy((caddr_t)(opt + 2), (caddr_t)&rtalert_val, 2);
			*rtalertp = ntohs(rtalert_val);
			break;
		case IP6OPT_JUMBO:
			/* XXX may need check for alignment */
			if (hbhlen < IP6OPT_JUMBO_LEN) {
				ip6stat.ip6s_toosmall++;
				goto bad;
			}
			if (*(opt + 1) != IP6OPT_JUMBO_LEN - 2) {
				/* XXX stat */
				lck_mtx_unlock(ip6_mutex);
				icmp6_error(m, ICMP6_PARAM_PROB,
					    ICMP6_PARAMPROB_HEADER,
					    erroff + opt + 1 - opthead);
				lck_mtx_lock(ip6_mutex);
				return(-1);
			}
			optlen = IP6OPT_JUMBO_LEN;

			/*
			 * IPv6 packets that have non 0 payload length
			 * must not contain a jumbo payload option.
			 */
			ip6 = mtod(m, struct ip6_hdr *);
			if (ip6->ip6_plen) {
				ip6stat.ip6s_badoptions++;
				lck_mtx_unlock(ip6_mutex);
				icmp6_error(m, ICMP6_PARAM_PROB,
					    ICMP6_PARAMPROB_HEADER,
					    erroff + opt - opthead);
				lck_mtx_lock(ip6_mutex);
				return(-1);
			}

			/*
			 * We may see jumbolen in unaligned location, so
			 * we'd need to perform bcopy().
			 */
			bcopy(opt + 2, &jumboplen, sizeof(jumboplen));
			jumboplen = (u_int32_t)htonl(jumboplen);

#if 1
			/*
			 * if there are multiple jumbo payload options,
			 * *plenp will be non-zero and the packet will be
			 * rejected.
			 * the behavior may need some debate in ipngwg -
			 * multiple options does not make sense, however,
			 * there's no explicit mention in specification.
			 */
			if (*plenp != 0) {
				ip6stat.ip6s_badoptions++;
				lck_mtx_unlock(ip6_mutex);
				icmp6_error(m, ICMP6_PARAM_PROB,
					    ICMP6_PARAMPROB_HEADER,
					    erroff + opt + 2 - opthead);
				lck_mtx_lock(ip6_mutex);
				return(-1);
			}
#endif

			/*
			 * jumbo payload length must be larger than 65535.
			 */
			if (jumboplen <= IPV6_MAXPACKET) {
				ip6stat.ip6s_badoptions++;
				lck_mtx_unlock(ip6_mutex);
				icmp6_error(m, ICMP6_PARAM_PROB,
					    ICMP6_PARAMPROB_HEADER,
					    erroff + opt + 2 - opthead);
				lck_mtx_lock(ip6_mutex);
				return(-1);
			}
			*plenp = jumboplen;

			break;
		default:		/* unknown option */
			if (hbhlen < IP6OPT_MINLEN) {
				ip6stat.ip6s_toosmall++;
				goto bad;
			}
			optlen = ip6_unknown_opt(opt, m,
			    erroff + opt - opthead, 1);
			if (optlen == -1) {
				/* ip6_unknown opt unlocked ip6_mutex */
				return(-1);
			}
			optlen += 2;
			break;
		}
	}

	return(0);

  bad:	
	m_freem(m);
	return(-1);
}

/*
 * Unknown option processing.
 * The third argument `off' is the offset from the IPv6 header to the option,
 * which is necessary if the IPv6 header the and option header and IPv6 header
 * is not continuous in order to return an ICMPv6 error.
 */
int
ip6_unknown_opt(optp, m, off, locked)
	u_int8_t *optp;
	struct mbuf *m;
	int off;
	int locked;
{
	struct ip6_hdr *ip6;

	switch (IP6OPT_TYPE(*optp)) {
	case IP6OPT_TYPE_SKIP: /* ignore the option */
		return((int)*(optp + 1));
	case IP6OPT_TYPE_DISCARD:	/* silently discard */
		m_freem(m);
		return(-1);
	case IP6OPT_TYPE_FORCEICMP: /* send ICMP even if multicasted */
		ip6stat.ip6s_badoptions++;
		if (locked)
			lck_mtx_unlock(ip6_mutex);
		icmp6_error(m, ICMP6_PARAM_PROB, ICMP6_PARAMPROB_OPTION, off);
		if (locked)
			lck_mtx_lock(ip6_mutex);
		return(-1);
	case IP6OPT_TYPE_ICMP: /* send ICMP if not multicasted */
		ip6stat.ip6s_badoptions++;
		ip6 = mtod(m, struct ip6_hdr *);
		if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) ||
		    (m->m_flags & (M_BCAST|M_MCAST)))
			m_freem(m);
		else {
			if (locked)
				lck_mtx_unlock(ip6_mutex);
			icmp6_error(m, ICMP6_PARAM_PROB,
				    ICMP6_PARAMPROB_OPTION, off);
			if (locked)
				lck_mtx_lock(ip6_mutex);
		}
		return(-1);
	}

	m_freem(m);		/* XXX: NOTREACHED */
	return(-1);
}

/*
 * Create the "control" list for this pcb.
 * The function will not modify mbuf chain at all.
 *
 * with KAME mbuf chain restriction:
 * The routine will be called from upper layer handlers like tcp6_input().
 * Thus the routine assumes that the caller (tcp6_input) have already
 * called IP6_EXTHDR_CHECK() and all the extension headers are located in the
 * very first mbuf on the mbuf chain.
 */
void
ip6_savecontrol(in6p, mp, ip6, m)
	struct inpcb *in6p;
	struct mbuf **mp;
	struct ip6_hdr *ip6;
	struct mbuf *m;
{
	int rthdr_exist = 0;

#if SO_TIMESTAMP
	if ((in6p->in6p_socket->so_options & SO_TIMESTAMP) != 0) {
		struct timeval tv;

		microtime(&tv);
		*mp = sbcreatecontrol((caddr_t) &tv, sizeof(tv),
				      SCM_TIMESTAMP, SOL_SOCKET);
		if (*mp) {
			mp = &(*mp)->m_next;
		}
	}
#endif

	/* some OSes call this logic with IPv4 packet, for SO_TIMESTAMP */
	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return;

	/* RFC 2292 sec. 5 */
	if ((in6p->in6p_flags & IN6P_PKTINFO) != 0) {
		struct in6_pktinfo pi6;
		bcopy(&ip6->ip6_dst, &pi6.ipi6_addr, sizeof(struct in6_addr));
		if (IN6_IS_SCOPE_LINKLOCAL(&pi6.ipi6_addr))
			pi6.ipi6_addr.s6_addr16[1] = 0;
		pi6.ipi6_ifindex = (m && m->m_pkthdr.rcvif)
					? m->m_pkthdr.rcvif->if_index
					: 0;
		*mp = sbcreatecontrol((caddr_t) &pi6,
			sizeof(struct in6_pktinfo), IPV6_PKTINFO,
			IPPROTO_IPV6);
		if (*mp)
			mp = &(*mp)->m_next;
	}

	if ((in6p->in6p_flags & IN6P_HOPLIMIT) != 0) {
		int hlim = ip6->ip6_hlim & 0xff;
		*mp = sbcreatecontrol((caddr_t) &hlim,
			sizeof(int), IPV6_HOPLIMIT, IPPROTO_IPV6);
		if (*mp)
			mp = &(*mp)->m_next;
	}

        if ((in6p->in6p_flags & IN6P_TCLASS) != 0) {
                u_int32_t flowinfo;
                int tclass;

                flowinfo = (u_int32_t)ntohl(ip6->ip6_flow & IPV6_FLOWINFO_MASK);
                flowinfo >>= 20;

                tclass = flowinfo & 0xff;
                *mp = sbcreatecontrol((caddr_t) &tclass, sizeof(tclass),
                    IPV6_TCLASS, IPPROTO_IPV6);
                if (*mp)
                        mp = &(*mp)->m_next;
        }

	/*
	 * IPV6_HOPOPTS socket option.  Recall that we required super-user
	 * privilege for the option (see ip6_ctloutput), but it might be too
	 * strict, since there might be some hop-by-hop options which can be
	 * returned to normal user.
	 * See RFC 2292 section 6.
	 */
	if ((in6p->in6p_flags & IN6P_HOPOPTS) != 0) {
		/*
		 * Check if a hop-by-hop options header is contatined in the
		 * received packet, and if so, store the options as ancillary
		 * data. Note that a hop-by-hop options header must be
		 * just after the IPv6 header, which fact is assured through
		 * the IPv6 input processing.
		 */
		ip6 = mtod(m, struct ip6_hdr *);
		if (ip6->ip6_nxt == IPPROTO_HOPOPTS) {
			struct ip6_hbh *hbh;
			int hbhlen = 0;
#if PULLDOWN_TEST
			struct mbuf *ext;
#endif

#ifndef PULLDOWN_TEST
			hbh = (struct ip6_hbh *)(ip6 + 1);
			hbhlen = (hbh->ip6h_len + 1) << 3;
#else
			ext = ip6_pullexthdr(m, sizeof(struct ip6_hdr),
			    ip6->ip6_nxt);
			if (ext == NULL) {
				ip6stat.ip6s_tooshort++;
				return;
			}
			hbh = mtod(ext, struct ip6_hbh *);
			hbhlen = (hbh->ip6h_len + 1) << 3;
			if (hbhlen != ext->m_len) {
				m_freem(ext);
				ip6stat.ip6s_tooshort++;
				return;
			}
#endif

			/*
			 * XXX: We copy whole the header even if a jumbo
			 * payload option is included, which option is to
			 * be removed before returning in the RFC 2292.
			 * Note: this constraint is removed in 2292bis.
			 */
			*mp = sbcreatecontrol((caddr_t)hbh, hbhlen,
					      IPV6_HOPOPTS, IPPROTO_IPV6);
			if (*mp)
				mp = &(*mp)->m_next;
#if PULLDOWN_TEST
			m_freem(ext);
#endif
		}
	}

	/* IPV6_DSTOPTS and IPV6_RTHDR socket options */
	if ((in6p->in6p_flags & (IN6P_DSTOPTS | IN6P_RTHDRDSTOPTS)) != 0) {
		int proto, off, nxt;

		/*
		 * go through the header chain to see if a routing header is
		 * contained in the packet. We need this information to store
		 * destination options headers (if any) properly.
		 * XXX: performance issue. We should record this info when
		 * processing extension headers in incoming routine.
		 * (todo) use m_aux? 
		 */
		proto = IPPROTO_IPV6;
		off = 0;
		nxt = -1;
		while (1) {
			int newoff;

			newoff = ip6_nexthdr(m, off, proto, &nxt);
			if (newoff < 0)
				break;
			if (newoff < off) /* invalid, check for safety */
				break;
			if ((proto = nxt) == IPPROTO_ROUTING) {
				rthdr_exist = 1;
				break;
			}
			off = newoff;
		}
	}

	if ((in6p->in6p_flags &
	     (IN6P_RTHDR | IN6P_DSTOPTS | IN6P_RTHDRDSTOPTS)) != 0) {
		ip6 = mtod(m, struct ip6_hdr *);
		int nxt = ip6->ip6_nxt, off = sizeof(struct ip6_hdr);

		/*
		 * Search for destination options headers or routing
		 * header(s) through the header chain, and stores each
		 * header as ancillary data.
		 * Note that the order of the headers remains in
		 * the chain of ancillary data.
		 */
		while (1) {	/* is explicit loop prevention necessary? */
			struct ip6_ext *ip6e = NULL;
			int elen;
#if PULLDOWN_TEST
			struct mbuf *ext = NULL;
#endif

			/*
			 * if it is not an extension header, don't try to
			 * pull it from the chain.
			 */
			switch (nxt) {
			case IPPROTO_DSTOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_HOPOPTS:
			case IPPROTO_AH: /* is it possible? */
				break;
			default:
				goto loopend;
			}

#ifndef PULLDOWN_TEST
			if (off + sizeof(*ip6e) > m->m_len)
				goto loopend;
			ip6e = (struct ip6_ext *)(mtod(m, caddr_t) + off);
			if (nxt == IPPROTO_AH)
				elen = (ip6e->ip6e_len + 2) << 2;
			else
				elen = (ip6e->ip6e_len + 1) << 3;
			if (off + elen > m->m_len)
				goto loopend;
#else
			ext = ip6_pullexthdr(m, off, nxt);
			if (ext == NULL) {
				ip6stat.ip6s_tooshort++;
				return;
			}
			ip6e = mtod(ext, struct ip6_ext *);
			if (nxt == IPPROTO_AH)
				elen = (ip6e->ip6e_len + 2) << 2;
			else
				elen = (ip6e->ip6e_len + 1) << 3;
			if (elen != ext->m_len) {
				m_freem(ext);
				ip6stat.ip6s_tooshort++;
				return;
			}
#endif

			switch (nxt) {
			case IPPROTO_DSTOPTS:
				if ((in6p->in6p_flags & IN6P_DSTOPTS) == 0)
					break;

				*mp = sbcreatecontrol((caddr_t)ip6e, elen,
						      IPV6_DSTOPTS,
						      IPPROTO_IPV6);
				if (*mp)
					mp = &(*mp)->m_next;
				break;
			case IPPROTO_ROUTING:
				if (!in6p->in6p_flags & IN6P_RTHDR)
					break;

				*mp = sbcreatecontrol((caddr_t)ip6e, elen,
						      IPV6_RTHDR,
						      IPPROTO_IPV6);
				if (*mp)
					mp = &(*mp)->m_next;
				break;
			case IPPROTO_HOPOPTS:
			case IPPROTO_AH: /* is it possible? */
				break;

			default:
				/*
			 	 * other cases have been filtered in the above.
				 * none will visit this case.  here we supply
				 * the code just in case (nxt overwritten or
				 * other cases).
				 */
#if PULLDOWN_TEST
				m_freem(ext);
#endif
				goto loopend;

			}

			/* proceed with the next header. */
			off += elen;
			nxt = ip6e->ip6e_nxt;
			ip6e = NULL;
#if PULLDOWN_TEST
			m_freem(ext);
			ext = NULL;
#endif
		}
	  loopend:
		;
	}

}

#if PULLDOWN_TEST
/*
 * pull single extension header from mbuf chain.  returns single mbuf that
 * contains the result, or NULL on error.
 */
static struct mbuf *
ip6_pullexthdr(m, off, nxt)
	struct mbuf *m;
	size_t off;
	int nxt;
{
	struct ip6_ext ip6e;
	size_t elen;
	struct mbuf *n;

#if DIAGNOSTIC
	switch (nxt) {
	case IPPROTO_DSTOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_HOPOPTS:
	case IPPROTO_AH: /* is it possible? */
		break;
	default:
		printf("ip6_pullexthdr: invalid nxt=%d\n", nxt);
	}
#endif

	m_copydata(m, off, sizeof(ip6e), (caddr_t)&ip6e);
	if (nxt == IPPROTO_AH)
		elen = (ip6e.ip6e_len + 2) << 2;
	else
		elen = (ip6e.ip6e_len + 1) << 3;

	MGET(n, M_DONTWAIT, MT_DATA);
	if (n && elen >= MLEN) {
		MCLGET(n, M_DONTWAIT);
		if ((n->m_flags & M_EXT) == 0) {
			m_free(n);
			n = NULL;
		}
	}
	if (!n)
		return NULL;

	n->m_len = 0;
	if (elen >= M_TRAILINGSPACE(n)) {
		m_free(n);
		return NULL;
	}

	m_copydata(m, off, elen, mtod(n, caddr_t));
	n->m_len = elen;
	return n;
}
#endif

/*
 * Get pointer to the previous header followed by the header
 * currently processed.
 * XXX: This function supposes that
 *	M includes all headers,
 *	the next header field and the header length field of each header
 *	are valid, and
 *	the sum of each header length equals to OFF.
 * Because of these assumptions, this function must be called very
 * carefully. Moreover, it will not be used in the near future when
 * we develop `neater' mechanism to process extension headers.
 */
char *
ip6_get_prevhdr(m, off)
	struct mbuf *m;
	int off;
{
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);

	if (off == sizeof(struct ip6_hdr))
		return((char *) &ip6->ip6_nxt);
	else {
		int len, nxt;
		struct ip6_ext *ip6e = NULL;

		nxt = ip6->ip6_nxt;
		len = sizeof(struct ip6_hdr);
		while (len < off) {
			ip6e = (struct ip6_ext *)(mtod(m, caddr_t) + len);

			switch (nxt) {
			case IPPROTO_FRAGMENT:
				len += sizeof(struct ip6_frag);
				break;
			case IPPROTO_AH:
				len += (ip6e->ip6e_len + 2) << 2;
				break;
			default:
				len += (ip6e->ip6e_len + 1) << 3;
				break;
			}
			nxt = ip6e->ip6e_nxt;
		}
		if (ip6e)
			return((char *) &ip6e->ip6e_nxt);
		else
			return NULL;
	}
}

/*
 * get next header offset.  m will be retained.
 */
int
ip6_nexthdr(m, off, proto, nxtp)
	struct mbuf *m;
	int off;
	int proto;
	int *nxtp;
{
	struct ip6_hdr ip6;
	struct ip6_ext ip6e;
	struct ip6_frag fh;

	/* just in case */
	if (m == NULL)
		panic("ip6_nexthdr: m == NULL");
	if ((m->m_flags & M_PKTHDR) == 0 || m->m_pkthdr.len < off)
		return -1;

	switch (proto) {
	case IPPROTO_IPV6:
		if (m->m_pkthdr.len < off + sizeof(ip6))
			return -1;
		m_copydata(m, off, sizeof(ip6), (caddr_t)&ip6);
		if (nxtp)
			*nxtp = ip6.ip6_nxt;
		off += sizeof(ip6);
		return off;

	case IPPROTO_FRAGMENT:
		/*
		 * terminate parsing if it is not the first fragment,
		 * it does not make sense to parse through it.
		 */
		if (m->m_pkthdr.len < off + sizeof(fh))
			return -1;
		m_copydata(m, off, sizeof(fh), (caddr_t)&fh);
		/* IP6F_OFF_MASK = 0xfff8(BigEndian), 0xf8ff(LittleEndian) */
		if (fh.ip6f_offlg & IP6F_OFF_MASK)
			return -1;
		if (nxtp)
			*nxtp = fh.ip6f_nxt;
		off += sizeof(struct ip6_frag);
		return off;

	case IPPROTO_AH:
		if (m->m_pkthdr.len < off + sizeof(ip6e))
			return -1;
		m_copydata(m, off, sizeof(ip6e), (caddr_t)&ip6e);
		if (nxtp)
			*nxtp = ip6e.ip6e_nxt;
		off += (ip6e.ip6e_len + 2) << 2;
		return off;

	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_DSTOPTS:
		if (m->m_pkthdr.len < off + sizeof(ip6e))
			return -1;
		m_copydata(m, off, sizeof(ip6e), (caddr_t)&ip6e);
		if (nxtp)
			*nxtp = ip6e.ip6e_nxt;
		off += (ip6e.ip6e_len + 1) << 3;
		return off;

	case IPPROTO_NONE:
	case IPPROTO_ESP:
	case IPPROTO_IPCOMP:
		/* give up */
		return -1;

	default:
		return -1;
	}

	return -1;
}

/*
 * get offset for the last header in the chain.  m will be kept untainted.
 */
int
ip6_lasthdr(m, off, proto, nxtp)
	struct mbuf *m;
	int off;
	int proto;
	int *nxtp;
{
	int newoff;
	int nxt;

	if (!nxtp) {
		nxt = -1;
		nxtp = &nxt;
	}
	while (1) {
		newoff = ip6_nexthdr(m, off, proto, nxtp);
		if (newoff < 0)
			return off;
		else if (newoff < off)
			return -1;	/* invalid */
		else if (newoff == off)
			return newoff;

		off = newoff;
		proto = *nxtp;
	}
}

struct ip6aux *
ip6_addaux(
	struct mbuf *m)
{
	struct m_tag		*tag;
	
	/* Check if one is already allocated */
	tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_INET6, NULL);
	if (tag == NULL) {
		/* Allocate a tag */
		tag = m_tag_alloc(KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_INET6,
		    sizeof (struct ip6aux), M_DONTWAIT);

		/* Attach it to the mbuf */
		if (tag) {
			m_tag_prepend(m, tag);
		}
	}
	
	return tag ? (struct ip6aux*)(tag + 1) : NULL;
}

struct ip6aux *
ip6_findaux(
	struct mbuf *m)
{
	struct m_tag	*tag;
	
	tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_ENCAP, NULL);
	
	return tag ? (struct ip6aux*)(tag + 1) : NULL;
}

void
ip6_delaux(
	struct mbuf *m)
{
	struct m_tag	*tag;

	tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_ENCAP, NULL);
	if (tag) {
		m_tag_delete(m, tag);
	}
}

/*
 * System control for IP6
 */

u_char	inet6ctlerrmap[PRC_NCMDS] = {
	0,		0,		0,		0,
	0,		EMSGSIZE,	EHOSTDOWN,	EHOSTUNREACH,
	EHOSTUNREACH,	EHOSTUNREACH,	ECONNREFUSED,	ECONNREFUSED,
	EMSGSIZE,	EHOSTUNREACH,	0,		0,
	0,		0,		0,		0,
	ENOPROTOOPT
};
