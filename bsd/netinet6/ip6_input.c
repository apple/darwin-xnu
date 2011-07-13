/*
 * Copyright (c) 2003-2011 Apple Inc. All rights reserved.
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
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/mcache.h>
#include <mach/mach_time.h>

#include <pexpert/pexpert.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/kpi_protocol.h>
#include <net/ntstat.h>

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
#include <netinet6/scope6_var.h>
#include <mach/sdt.h>

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

static lck_grp_attr_t	*in6_ifaddr_rwlock_grp_attr;
static lck_grp_t	*in6_ifaddr_rwlock_grp;
static lck_attr_t	*in6_ifaddr_rwlock_attr;
decl_lck_rw_data(, in6_ifaddr_rwlock);

/* Protected by in6_ifaddr_rwlock */
struct in6_ifaddr *in6_ifaddrs = NULL;

int ip6_forward_srcrt;			/* XXX */
int ip6_sourcecheck;			/* XXX */
int ip6_sourcecheck_interval;		/* XXX */
const int int6intrq_present = 1;

int ip6_ours_check_algorithm;
int in6_init2done = 0;
int in6_init_done = 0;

#define _CASSERT(x)	\
	switch (0) { case 0: case (x): ; }
#define IN6_IFSTAT_REQUIRE_ALIGNED_64(f)	\
	_CASSERT(!(offsetof(struct in6_ifstat, f) % sizeof (uint64_t)))
#define ICMP6_IFSTAT_REQUIRE_ALIGNED_64(f)	\
	_CASSERT(!(offsetof(struct icmp6_ifstat, f) % sizeof (uint64_t)))

#if IPFW2
/* firewall hooks */
ip6_fw_chk_t *ip6_fw_chk_ptr;
ip6_fw_ctl_t *ip6_fw_ctl_ptr;
int ip6_fw_enable = 1;
#endif

struct ip6stat ip6stat;

#ifdef __APPLE__
struct ifqueue ip6intrq;
decl_lck_mtx_data(, ip6_init_mutex);
lck_mtx_t 		*dad6_mutex;
lck_mtx_t 		*nd6_mutex;
lck_mtx_t		*prefix6_mutex;
lck_mtx_t		*scope6_mutex;
#ifdef ENABLE_ADDRSEL
lck_mtx_t		*addrsel_mutex;
#endif
decl_lck_rw_data(, in6_ifs_rwlock);
decl_lck_rw_data(, icmp6_ifs_rwlock);
lck_attr_t		*ip6_mutex_attr;
lck_grp_t		*ip6_mutex_grp;
lck_grp_attr_t		*ip6_mutex_grp_attr;
extern lck_mtx_t	*inet6_domain_mutex;
#endif
extern int loopattach_done;
extern void addrsel_policy_init(void);

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

SYSCTL_DECL(_net_inet6_ip6);

int	ip6_doscopedroute = 1;
SYSCTL_INT(_net_inet6_ip6, OID_AUTO, scopedroute, CTLFLAG_RD | CTLFLAG_LOCKED,
     &ip6_doscopedroute, 0, "Enable IPv6 scoped routing");

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

	PE_parse_boot_argn("net.inet6.ip6.scopedroute", &ip6_doscopedroute,
	    sizeof (ip6_doscopedroute));

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

#ifdef ENABLE_ADDRSEL
	if ((addrsel_mutex = lck_mtx_alloc_init(ip6_mutex_grp, ip6_mutex_attr)) == NULL) {
		panic("ip6_init: can't alloc addrsel_mutex\n");
	}
#endif

	lck_rw_init(&in6_ifs_rwlock, ip6_mutex_grp, ip6_mutex_attr);
	lck_rw_init(&icmp6_ifs_rwlock, ip6_mutex_grp, ip6_mutex_attr);
	lck_mtx_init(&ip6_init_mutex, ip6_mutex_grp, ip6_mutex_attr);

	inet6domain.dom_flags = DOM_REENTRANT;	

	ip6intrq.ifq_maxlen = ip6qmaxlen;

	in6_ifaddr_rwlock_grp_attr = lck_grp_attr_alloc_init();
	in6_ifaddr_rwlock_grp = lck_grp_alloc_init("in6_ifaddr_rwlock",
	    in6_ifaddr_rwlock_grp_attr);
	in6_ifaddr_rwlock_attr = lck_attr_alloc_init();
	lck_rw_init(&in6_ifaddr_rwlock, in6_ifaddr_rwlock_grp,
	    in6_ifaddr_rwlock_attr);

	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_receive);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_hdrerr);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_toobig);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_noroute);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_addrerr);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_protounknown);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_truncated);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_discard);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_deliver);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_forward);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_request);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_discard);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_fragok);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_fragfail);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_fragcreat);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_reass_reqd);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_reass_ok);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_reass_fail);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_mcast);
	IN6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_mcast); 

	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_msg);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_error);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_dstunreach);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_adminprohib);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_timeexceed);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_paramprob);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_pkttoobig);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_echo);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_echoreply);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_routersolicit);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_routeradvert);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_neighborsolicit);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_neighboradvert);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_redirect);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_mldquery);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_mldreport);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_in_mlddone);

	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_msg);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_error);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_dstunreach);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_adminprohib);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_timeexceed);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_paramprob);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_pkttoobig);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_echo);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_echoreply);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_routersolicit);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_routeradvert);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_neighborsolicit);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_neighboradvert);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_redirect);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_mldquery);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_mldreport);
	ICMP6_IFSTAT_REQUIRE_ALIGNED_64(ifs6_out_mlddone);

	in6_ifaddr_init();
	ip6_moptions_init();
	nd6_init();
	frag6_init();
	icmp6_init();
	addrsel_policy_init();
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
#endif
	in6_init2done = 1;

	lck_mtx_lock(&ip6_init_mutex);
	in6_init_done = 1;
	wakeup(&in6_init_done);
	lck_mtx_unlock(&ip6_init_mutex);
}

void
ip6_fin()
{
	lck_mtx_lock(&ip6_init_mutex);
	while (in6_init_done == 0) {
		(void) msleep(&in6_init_done, &ip6_init_mutex, 0, "ip6_fin()", NULL);
	}
	lck_mtx_unlock(&ip6_init_mutex);
}

void
ip6_input(struct mbuf *m)
{
	struct ip6_hdr *ip6;
	int off = sizeof(struct ip6_hdr), nest;
	u_int32_t plen;
	u_int32_t rtalert = ~0;
	int nxt = 0, ours = 0;
	struct ifnet *deliverifp = NULL;
	ipfilter_t inject_ipfref = 0;
	int seen;
	struct in6_ifaddr *ia6 = NULL;
	struct route_in6 ip6_forward_rt;
	struct sockaddr_in6 *dst6;

	bzero(&ip6_forward_rt, sizeof(ip6_forward_rt));

	/* Check if the packet we received is valid after interface filter
	 * processing
	 */
	MBUF_INPUT_CHECK(m, m->m_pkthdr.rcvif);

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

	/* drop the packet if IPv6 operation is disabled on the IF */
	lck_rw_lock_shared(nd_if_rwlock);
	if (m->m_pkthdr.rcvif->if_index < nd_ifinfo_indexlim &&
	    (nd_ifinfo[m->m_pkthdr.rcvif->if_index].flags & ND6_IFF_IFDISABLED)) {
		lck_rw_done(nd_if_rwlock);
		goto bad;
	}
	lck_rw_done(nd_if_rwlock);

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
		if (n == NULL)
			goto bad;

		m_copydata(m, 0, m->m_pkthdr.len, mtod(n, caddr_t));
		n->m_len = m->m_pkthdr.len;
		m_freem(m);
		m = n;
	}
	IP6_EXTHDR_CHECK(m, 0, sizeof(struct ip6_hdr),
		{goto done;}); 
#endif

	if (m->m_len < sizeof(struct ip6_hdr)) {
		struct ifnet *inifp;
		inifp = m->m_pkthdr.rcvif;
		if ((m = m_pullup(m, sizeof(struct ip6_hdr))) == 0) {
			ip6stat.ip6s_toosmall++;
			in6_ifstat_inc(inifp, ifs6_in_hdrerr);
			goto done;
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
		if (!m)
			goto done;
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
	if (IN6_IS_ADDR_MC_INTFACELOCAL(&ip6->ip6_dst) &&
	    !(m->m_flags & M_LOOP)) {
		/*
		 * In this case, the packet should come from the loopback
		 * interface.  However, we cannot just check the if_flags,
		 * because ip6_mloopback() passes the "actual" interface
		 * as the outgoing/incoming interface.
		 */
		ip6stat.ip6s_badscope++;
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_addrerr);
		goto bad;
	}

	/*
	 * The following check is not documented in specs.  A malicious
	 * party may be able to use IPv4 mapped addr to confuse tcp/udp stack
	 * and bypass security checks (act as if it was from 127.0.0.1 by using
	 * IPv6 src ::ffff:127.0.0.1).  Be cautious.
	 *
	 * This check chokes if we are in an SIIT cloud.  As none of BSDs
	 * support IPv4-less kernel compilation, we cannot support SIIT
	 * environment at all.  So, it makes more sense for us to reject any
	 * malicious packets for non-SIIT environment, than try to do a
	 * partial support for SIIT environment.
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

	/*
	 * Naively assume we can attribute inbound data to the route we would
	 * use to send to this destination. Asymetric routing breaks this
	 * assumption, but it still allows us to account for traffic from
	 * a remote node in the routing table.
	 * this has a very significant performance impact so we bypass
	 * if nstat_collect is disabled. We may also bypass if the
	 * protocol is tcp in the future because tcp will have a route that
	 * we can use to attribute the data to. That does mean we would not
	 * account for forwarded tcp traffic.
	 */
	if (nstat_collect) {
		struct rtentry *rte =
		    ifnet_cached_rtlookup_inet6(m->m_pkthdr.rcvif,
		    &ip6->ip6_src);
		if (rte != NULL) {
			nstat_route_rx(rte, 1, m->m_pkthdr.len, 0);
			rtfree(rte);
		}
	}

#if PF
	/* Invoke inbound packet filter */
	if (PF_IS_ENABLED) {
		int error;
		error = pf_af_hook(m->m_pkthdr.rcvif, NULL, &m, AF_INET6, TRUE);
		if (error != 0) {
			if (m != NULL) {
				panic("%s: unexpected packet %p\n", __func__, m);
				/* NOTREACHED */
			}
			/* Already freed by callee */
			goto done;
		}
		ip6 = mtod(m, struct ip6_hdr *);
	}
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

	/*
	 * Multicast check
	 */
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
		struct	in6_multi *in6m = NULL;
		struct ifnet *ifp = m->m_pkthdr.rcvif;

		in6_ifstat_inc(ifp, ifs6_in_mcast);
		/*
		 * See if we belong to the destination multicast group on the
		 * arrival interface.
		 */
		in6_multihead_lock_shared();
		IN6_LOOKUP_MULTI(&ip6->ip6_dst, ifp, in6m);
		in6_multihead_lock_done();
		if (in6m != NULL) {
			IN6M_REMREF(in6m);
			ours = 1;
		}
		else 
#if MROUTING
		if (!ip6_mrouter)
#endif
		{
			ip6stat.ip6s_notmember++;
			ip6stat.ip6s_cantforward++;
			in6_ifstat_inc(ifp, ifs6_in_discard);
			goto bad;
		}
		deliverifp = ifp;
		goto hbhcheck;
	}

	/*
	 *  Unicast check
	 */
	dst6 = (struct sockaddr_in6 *)&ip6_forward_rt.ro_dst;
	dst6->sin6_len = sizeof(struct sockaddr_in6);
	dst6->sin6_family = AF_INET6;
	dst6->sin6_addr = ip6->ip6_dst;

	rtalloc_scoped_ign((struct route *)&ip6_forward_rt,
	    RTF_PRCLONING, IFSCOPE_NONE);
	if (ip6_forward_rt.ro_rt != NULL)
		RT_LOCK(ip6_forward_rt.ro_rt);

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
		ia6 = (struct in6_ifaddr *)ip6_forward_rt.ro_rt->rt_ifa;

		/*
		 * record address information into m_aux.
		 */
		(void)ip6_setdstifaddr(m, ia6);

		/*
		 * packets to a tentative, duplicated, or somehow invalid
		 * address must not be accepted.
		 */
		RT_CONVERT_LOCK(ip6_forward_rt.ro_rt);	/* just in case */
		IFA_LOCK_SPIN(&ia6->ia_ifa);
		if (!(ia6->ia6_flags & IN6_IFF_NOTREADY)) {
			IFA_UNLOCK(&ia6->ia_ifa);
			/* this address is ready */
			ours = 1;
			deliverifp = ia6->ia_ifp;	/* correct? */
			/* Count the packet in the ip address stats */

			RT_UNLOCK(ip6_forward_rt.ro_rt);
			ia6 = NULL;
			goto hbhcheck;
		}
		IFA_UNLOCK(&ia6->ia_ifa);
		RT_UNLOCK(ip6_forward_rt.ro_rt);
		/* address is not ready, so discard the packet. */
		nd6log((LOG_INFO,
		    "ip6_input: packet to an unready address %s->%s\n",
		    ip6_sprintf(&ip6->ip6_src),
		    ip6_sprintf(&ip6->ip6_dst)));
		ia6 = NULL;
		goto bad;
	}

	/*
	 * FAITH (Firewall Aided Internet Translator)
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
	if (deliverifp && (ia6 = ip6_getdstifaddr(m)) == NULL) {
		ia6 = in6_ifawithifp(deliverifp, &ip6->ip6_dst);
		if (ia6) {
			if (!ip6_setdstifaddr(m, ia6)) {
				/*
				 * XXX maybe we should drop the packet here,
				 * as we could not provide enough information
				 * to the upper layers.
				 */
			}
			IFA_REMREF(&ia6->ia_ifa);
			ia6 = NULL;
		}
	}

	if (ia6 != NULL) {
		IFA_REMREF(&ia6->ia_ifa);
		ia6 = NULL;
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
			goto done;	/* m have already been freed */
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
			 * contained, ip6_hopopts_input() must set a valid
			 * (non-zero) payload length to the variable plen.
			 */
			ip6stat.ip6s_badoptions++;
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_discard);
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_hdrerr);
			icmp6_error(m, ICMP6_PARAM_PROB,
				    ICMP6_PARAMPROB_HEADER,
				    (caddr_t)&ip6->ip6_plen - (caddr_t)ip6);
			goto done;
		}
#ifndef PULLDOWN_TEST
		/* ip6_hopopts_input() ensures that mbuf is contiguous */
		hbh = (struct ip6_hbh *)(ip6 + 1);
#else
		IP6_EXTHDR_GET(hbh, struct ip6_hbh *, m, sizeof(struct ip6_hdr),
			sizeof(struct ip6_hbh));
		if (hbh == NULL) {
			ip6stat.ip6s_tooshort++;
			goto done;
		}
#endif
		nxt = hbh->ip6h_nxt;

		/*
		 * If we are acting as a router and the packet contains a
		 * router alert option, see if we know the option value.
		 * Currently, we only support the option value for MLD, in which
		 * case we should pass the packet to the multicast routing
		 * daemon.
		 */
		if (rtalert != ~0 && ip6_forwarding) {
			switch (rtalert) {
			case IP6OPT_RTALERT_MLD:
				ours = 1;
				break;
			default:
				/*
				 * RFC2711 requires unrecognized values must be
				 * silently ignored.
				 */
				break;
			}
		}
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
#if MROUTING
		if (ip6_mrouter && ip6_mforward(ip6, m->m_pkthdr.rcvif, m)) {
			ip6stat.ip6s_cantforward++;
			goto bad;
		}
#endif
		if (!ours)
			goto bad;
	} else if (!ours) {
		ip6_forward(m, &ip6_forward_rt, 0);
		goto done;
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

injectit:
	nest = 0;

	while (nxt != IPPROTO_DONE) {
		struct ipfilter *filter;
		int (*pr_input)(struct mbuf **, int *, int);

		if (ip6_hdrnestlimit && (++nest > ip6_hdrnestlimit)) {
			ip6stat.ip6s_toomanyhdr++;
			goto bad;
		}

		/*
		 * protection against faulty packet - there should be
		 * more sanity checks in header chain processing.
		 */
		if (m->m_pkthdr.len < off) {
			ip6stat.ip6s_tooshort++;
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_truncated);
			goto bad;
		}


#if IPSEC
		/*
		 * enforce IPsec policy checking if we are seeing last header.
		 * note that we do not visit this with protocols with pcb layer
		 * code - like udp/tcp/raw ip.
		 */
		if ((ipsec_bypass == 0) && (ip6_protox[nxt]->pr_flags & PR_LASTHDR) != 0) {
			if (ipsec6_in_reject(m, NULL)) {
				IPSEC_STAT_INCREMENT(ipsec6stat.in_polvio);
				goto bad;
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
						goto done;
					}
					if (result != 0) {
						ipf_unref();
						goto bad;
					}
				}
			}
			ipf_unref();
		}

		DTRACE_IP6(receive, struct mbuf *, m, struct inpcb *, NULL,
			struct ip6_hdr *, ip6, struct ifnet *, m->m_pkthdr.rcvif,
			struct ip *, NULL, struct ip6_hdr *, ip6);

		if ((pr_input = ip6_protox[nxt]->pr_input) == NULL) {
			m_freem(m);
			m = NULL;
			nxt = IPPROTO_DONE;
		} else if (!(ip6_protox[nxt]->pr_flags & PR_PROTOLOCK)) {
			lck_mtx_lock(inet6_domain_mutex);
			nxt = pr_input(&m, &off, nxt);
			lck_mtx_unlock(inet6_domain_mutex);
		} else {
			nxt = pr_input(&m, &off, nxt);
		}
	}
done:
	if (ip6_forward_rt.ro_rt != NULL)
		rtfree(ip6_forward_rt.ro_rt);
	return;
 bad:
	m_freem(m);
	goto done;
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
	if (n != NULL) {
		if (ia6 != NULL)
			IFA_ADDREF(&ia6->ia_ifa);
		if (n->ip6a_dstia6 != NULL)
			IFA_REMREF(&n->ip6a_dstia6->ia_ifa);
		n->ip6a_dstia6 = ia6;
	}
	return (struct ip6aux *)n;	/* NULL if failed to set */
}

struct in6_ifaddr *
ip6_getdstifaddr(m)
	struct mbuf *m;
{
	struct ip6aux *n;

	n = ip6_findaux(m);
	if (n != NULL) {
		if (n->ip6a_dstia6 != NULL)
			IFA_ADDREF(&n->ip6a_dstia6->ia_ifa);
		return (n->ip6a_dstia6);
	}
	return (NULL);
}

/*
 * Hop-by-Hop options header processing. If a valid jumbo payload option is
 * included, the real payload length will be stored in plenp.
 */
static int
ip6_hopopts_input(uint32_t *plenp, uint32_t *rtalertp, struct mbuf **mp,
    int *offp)
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
		return (-1);

	*offp = off;
	*mp = m;
	return (0);
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
		case IP6OPT_ROUTER_ALERT:
			/* XXX may need check for alignment */
			if (hbhlen < IP6OPT_RTALERT_LEN) {
				ip6stat.ip6s_toosmall++;
				goto bad;
			}
			if (*(opt + 1) != IP6OPT_RTALERT_LEN - 2) {
				/* XXX stat */
				icmp6_error(m, ICMP6_PARAM_PROB,
					    ICMP6_PARAMPROB_HEADER,
					    erroff + opt + 1 - opthead);
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
				icmp6_error(m, ICMP6_PARAM_PROB,
					    ICMP6_PARAMPROB_HEADER,
					    erroff + opt + 1 - opthead);
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
				icmp6_error(m, ICMP6_PARAM_PROB,
					    ICMP6_PARAMPROB_HEADER,
					    erroff + opt - opthead);
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
				icmp6_error(m, ICMP6_PARAM_PROB,
					    ICMP6_PARAMPROB_HEADER,
					    erroff + opt + 2 - opthead);
				return(-1);
			}
#endif

			/*
			 * jumbo payload length must be larger than 65535.
			 */
			if (jumboplen <= IPV6_MAXPACKET) {
				ip6stat.ip6s_badoptions++;
				icmp6_error(m, ICMP6_PARAM_PROB,
					    ICMP6_PARAMPROB_HEADER,
					    erroff + opt + 2 - opthead);
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
			    erroff + opt - opthead);
			if (optlen == -1) {
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
ip6_unknown_opt(uint8_t *optp, struct mbuf *m, int off)
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
		icmp6_error(m, ICMP6_PARAM_PROB, ICMP6_PARAMPROB_OPTION, off);
		return(-1);
	case IP6OPT_TYPE_ICMP: /* send ICMP if not multicasted */
		ip6stat.ip6s_badoptions++;
		ip6 = mtod(m, struct ip6_hdr *);
		if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) ||
		    (m->m_flags & (M_BCAST|M_MCAST)))
			m_freem(m);
		else
			icmp6_error(m, ICMP6_PARAM_PROB,
				    ICMP6_PARAMPROB_OPTION, off);
		return(-1);
	}

	m_freem(m);		/* XXX: NOTREACHED */
	return (-1);
}

/*
 * Create the "control" list for this pcb.
 * These functions will not modify mbuf chain at all.
 *
 * With KAME mbuf chain restriction:
 * The routine will be called from upper layer handlers like tcp6_input().
 * Thus the routine assumes that the caller (tcp6_input) have already
 * called IP6_EXTHDR_CHECK() and all the extension headers are located in the
 * very first mbuf on the mbuf chain.
 *
 * ip6_savecontrol_v4 will handle those options that are possible to be
 * set on a v4-mapped socket.
 * ip6_savecontrol will directly call ip6_savecontrol_v4 to handle those
 * options and handle the v6-only ones itself.
 */
struct mbuf **
ip6_savecontrol_v4(struct inpcb *inp, struct mbuf *m, struct mbuf **mp,
    int *v4only)
{
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);

	if ((inp->inp_socket->so_options & SO_TIMESTAMP) != 0) {
		struct timeval tv;

		microtime(&tv);
		mp = sbcreatecontrol_mbuf((caddr_t) &tv, sizeof(tv),
		    SCM_TIMESTAMP, SOL_SOCKET, mp);
		if (*mp == NULL) 
			return NULL;
	}
        if ((inp->inp_socket->so_options & SO_TIMESTAMP_MONOTONIC) != 0) {
                uint64_t time;

                time = mach_absolute_time();
                mp = sbcreatecontrol_mbuf((caddr_t) &time, sizeof(time),
                        SCM_TIMESTAMP_MONOTONIC, SOL_SOCKET, mp);

			if (*mp == NULL) 
				return NULL;
        }
	if ((inp->inp_socket->so_flags & SOF_RECV_TRAFFIC_CLASS) != 0) {
		int tc = m->m_pkthdr.prio;
		
		mp = sbcreatecontrol_mbuf((caddr_t) &tc, sizeof(tc),
			SO_TRAFFIC_CLASS, SOL_SOCKET, mp);
		if (*mp == NULL) 
			return NULL;
	}

	if ((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION) {
		if (v4only != NULL)
			*v4only = 1;
		return (mp);
	}

#define IS2292(inp, x, y)	(((inp)->inp_flags & IN6P_RFC2292) ? (x) : (y))
	/* RFC 2292 sec. 5 */
	if ((inp->inp_flags & IN6P_PKTINFO) != 0) {
		struct in6_pktinfo pi6;

		bcopy(&ip6->ip6_dst, &pi6.ipi6_addr, sizeof(struct in6_addr));
		in6_clearscope(&pi6.ipi6_addr);	/* XXX */
		pi6.ipi6_ifindex =
		    (m && m->m_pkthdr.rcvif) ? m->m_pkthdr.rcvif->if_index : 0;

		mp = sbcreatecontrol_mbuf((caddr_t) &pi6,
		    sizeof(struct in6_pktinfo),
		    IS2292(inp, IPV6_2292PKTINFO, IPV6_PKTINFO), IPPROTO_IPV6, mp);
		if (*mp == NULL) 
			return NULL;
	}

	if ((inp->inp_flags & IN6P_HOPLIMIT) != 0) {
		int hlim = ip6->ip6_hlim & 0xff;

		mp = sbcreatecontrol_mbuf((caddr_t) &hlim, sizeof(int),
		    IS2292(inp, IPV6_2292HOPLIMIT, IPV6_HOPLIMIT),
		    IPPROTO_IPV6, mp);
		if (*mp == NULL) 
			return NULL;
	}

	if (v4only != NULL)
		*v4only = 0;
	return (mp);
}

int
ip6_savecontrol(struct inpcb *in6p, struct mbuf *m, struct mbuf **mp)
{
	struct mbuf **np;
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
	int v4only = 0;

	*mp = NULL;
	np = ip6_savecontrol_v4(in6p, m, mp, &v4only);
	if (np == NULL)
		goto no_mbufs;

	mp = np;
	if (v4only)
		return(0);

	if ((in6p->inp_flags & IN6P_TCLASS) != 0) {
		u_int32_t flowinfo;
		int tclass;

		flowinfo = (u_int32_t)ntohl(ip6->ip6_flow & IPV6_FLOWINFO_MASK);
		flowinfo >>= 20;

		tclass = flowinfo & 0xff;
		mp = sbcreatecontrol_mbuf((caddr_t) &tclass, sizeof(tclass),
		    IPV6_TCLASS, IPPROTO_IPV6, mp);
		if (*mp == NULL) 
			goto no_mbufs;
	}

	/*
	 * IPV6_HOPOPTS socket option.  Recall that we required super-user
	 * privilege for the option (see ip6_ctloutput), but it might be too
	 * strict, since there might be some hop-by-hop options which can be
	 * returned to normal user.
	 * See also RFC 2292 section 6 (or RFC 3542 section 8).
	 */
	if ((in6p->inp_flags & IN6P_HOPOPTS) != 0) {
		/*
		 * Check if a hop-by-hop options header is contatined in the
		 * received packet, and if so, store the options as ancillary
		 * data. Note that a hop-by-hop options header must be
		 * just after the IPv6 header, which is assured through the
		 * IPv6 input processing.
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
				return(0);
			}
			hbh = mtod(ext, struct ip6_hbh *);
			hbhlen = (hbh->ip6h_len + 1) << 3;
			if (hbhlen != ext->m_len) {
				m_freem(ext);
				ip6stat.ip6s_tooshort++;
				return(0);
			}
#endif

			/*
			 * XXX: We copy the whole header even if a
			 * jumbo payload option is included, the option which
			 * is to be removed before returning according to
			 * RFC2292.
			 * Note: this constraint is removed in RFC3542
			 */
			mp = sbcreatecontrol_mbuf((caddr_t)hbh, hbhlen,
			    IS2292(in6p, IPV6_2292HOPOPTS, IPV6_HOPOPTS),
			    IPPROTO_IPV6, mp);

#if PULLDOWN_TEST
			m_freem(ext);
#endif
			if (*mp == NULL) {
				goto no_mbufs;
			}
		}
	}

	if ((in6p->inp_flags & (IN6P_RTHDR | IN6P_DSTOPTS)) != 0) {
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
				return(0);
			}
			ip6e = mtod(ext, struct ip6_ext *);
			if (nxt == IPPROTO_AH)
				elen = (ip6e->ip6e_len + 2) << 2;
			else
				elen = (ip6e->ip6e_len + 1) << 3;
			if (elen != ext->m_len) {
				m_freem(ext);
				ip6stat.ip6s_tooshort++;
				return(0);
			}
#endif

			switch (nxt) {
			case IPPROTO_DSTOPTS:
				if (!(in6p->inp_flags & IN6P_DSTOPTS))
					break;

				mp = sbcreatecontrol_mbuf((caddr_t)ip6e, elen,
				    IS2292(in6p,
					IPV6_2292DSTOPTS, IPV6_DSTOPTS),
				    IPPROTO_IPV6, mp);
					if (*mp == NULL) {
#if PULLDOWN_TEST
					m_freem(ext);
#endif
					goto no_mbufs;
				}
				break;
			case IPPROTO_ROUTING:
				if (!in6p->inp_flags & IN6P_RTHDR)
					break;

				mp = sbcreatecontrol_mbuf((caddr_t)ip6e, elen,
				    IS2292(in6p, IPV6_2292RTHDR, IPV6_RTHDR),
				    IPPROTO_IPV6, mp);
				if (*mp == NULL) {
#if PULLDOWN_TEST
					m_freem(ext);
#endif
					goto no_mbufs;
				}
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
	return(0);
no_mbufs:
	ip6stat.ip6s_pktdropcntrl++;
	/* XXX increment a stat to show the failure */
	return(ENOBUFS);
}
#undef IS2292

void
ip6_notify_pmtu(struct inpcb *in6p, struct sockaddr_in6 *dst, u_int32_t *mtu)
{
	struct socket *so;
	struct mbuf *m_mtu;
	struct ip6_mtuinfo mtuctl;

	so =  in6p->inp_socket;

	if (mtu == NULL)
		return;

#ifdef DIAGNOSTIC
	if (so == NULL)		/* I believe this is impossible */
		panic("ip6_notify_pmtu: socket is NULL");
#endif

	bzero(&mtuctl, sizeof(mtuctl));	/* zero-clear for safety */
	mtuctl.ip6m_mtu = *mtu;
	mtuctl.ip6m_addr = *dst;
	if (sa6_recoverscope(&mtuctl.ip6m_addr))
		return;

	if ((m_mtu = sbcreatecontrol((caddr_t)&mtuctl, sizeof(mtuctl),
	    IPV6_PATHMTU, IPPROTO_IPV6)) == NULL)
		return;

	if (sbappendaddr(&so->so_rcv, (struct sockaddr *)dst, NULL, m_mtu, NULL)
	    == 0) {
		m_freem(m_mtu);
		/* XXX: should count statistics */
	} else
		sorwakeup(so);

	return;
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
		tag = m_tag_create(KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_INET6,
		    sizeof (struct ip6aux), M_DONTWAIT, m);

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
	
	tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_INET6, NULL);
	
	return tag ? (struct ip6aux*)(tag + 1) : NULL;
}

void
ip6_delaux(
	struct mbuf *m)
{
	struct m_tag	*tag;

	tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_INET6, NULL);
	if (tag) {
		m_tag_delete(m, tag);
	}
}

/*
 * Called by m_tag_free().
 */
void
ip6_destroyaux(struct ip6aux *n)
{
	if (n->ip6a_dstia6 != NULL) {
		IFA_REMREF(&n->ip6a_dstia6->ia_ifa);
		n->ip6a_dstia6 = NULL;
	}
}

/*
 * Called by m_tag_copy()
 */
void
ip6_copyaux(struct ip6aux *src, struct ip6aux *dst)
{
	bcopy(src, dst, sizeof (*dst));
	if (dst->ip6a_dstia6 != NULL)
		IFA_ADDREF(&dst->ip6a_dstia6->ia_ifa);
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
