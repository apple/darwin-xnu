/*	$KAME: ip6_input.c,v 1.75 2000/03/28 23:11:05 itojun Exp $	*/

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
#define _IP_VHL
#ifdef __FreeBSD__
#include "opt_ip6fw.h"
#endif
#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__NetBSD__)
#include "opt_inet.h"
#ifdef __NetBSD__	/*XXX*/
#include "opt_ipsec.h"
#endif
#endif

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
#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
#include <sys/proc.h>
#endif

#include <net/if.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/netisr.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#if INET
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#endif /*INET*/
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#if (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined(__OpenBSD__) || (defined(__bsdi__) && _BSDI_VERSION >= 199802) || defined (__APPLE__)
#include <netinet/in_pcb.h>
#endif
#if defined(__OpenBSD__) || (defined(__bsdi__) && _BSDI_VERSION >= 199802)
#include <netinet6/in6_pcb.h>
#endif
#include <netinet/icmp6.h>
#include <netinet6/in6_ifattach.h>
#include <netinet6/nd6.h>
#include <netinet6/in6_prefix.h>

#if MIP6
#include <netinet6/mip6.h>
#endif

#if IPV6FIREWALL
#include <netinet6/ip6_fw.h>
#endif

#include <netinet6/ip6protosw.h>

/* we need it for NLOOP. */
#ifndef __bsdi__
#include "loop.h"
#endif
#include "faith.h"
#include "gif.h"
#include "bpfilter.h"

#include <net/net_osdep.h>

extern struct domain inet6domain;
extern struct ip6protosw inet6sw[];
#ifdef __bsdi__
#if _BSDI_VERSION < 199802
extern struct ifnet loif;
#else
extern struct ifnet *loifp;
#endif
#endif

struct ip6protosw *  ip6_protox[IPPROTO_MAX];
static int ip6qmaxlen = IFQ_MAXLEN;
struct in6_ifaddr *in6_ifaddr;
#if !(defined(__FreeBSD__) && __FreeBSD__ >= 4)
struct ifqueue ip6intrq;
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
extern struct ifnet loif[NLOOP];
#endif
int ip6_forward_srcrt;			/* XXX */
int ip6_sourcecheck;			/* XXX */
int ip6_sourcecheck_interval;		/* XXX */
#if defined(__FreeBSD__) && __FreeBSD__ >= 4
const int int6intrq_present = 1;
#endif

#if IPV6FIREWALL
/* firewall hooks */
ip6_fw_chk_t *ip6_fw_chk_ptr;
ip6_fw_ctl_t *ip6_fw_ctl_ptr;
#endif

struct ip6stat ip6stat;

static void ip6_init2 __P((void *));

static int ip6_hopopts_input __P((u_int32_t *, u_int32_t *, struct mbuf **, int *));
#if PULLDOWN_TEST
static struct mbuf *ip6_pullexthdr __P((struct mbuf *, size_t, int));
#endif

#if NATPT
extern	int		ip6_protocol_tr;

int	natpt_in6	__P((struct mbuf *, struct mbuf **));
extern void ip_forward	__P((struct mbuf *, int));
#endif

/* Initialize the PF_INET6 domain, and add in the pre-defined protos */
void
in6_dinit()
{	register int i;
	register struct ip6protosw *pr;
	register struct domain *dp;
	static inet6domain_initted = 0;
	extern int in6_proto_count; 

	if (!inet6domain_initted)
	{	
		dp = &inet6domain;

		for (i=0, pr = &inet6sw[0]; i<in6_proto_count; i++, pr++) {
			if (net_add_proto(pr, dp))
				printf("in6_dinit: warning net_add_proto failed for pr=%x proto #%d\n", pr, i);
			
		}
		inet6domain_initted = 1;
	}
}

#ifdef MIP6
int (*mip6_new_packet_hook)(struct mbuf *m) = 0;
int (*mip6_route_optimize_hook)(struct mbuf *m) = 0;
#endif

/*
 * IP6 initialization: fill in IP6 protocol switch table.
 * All protocols not implemented in kernel go to raw IP6 protocol handler.
 */
void
ip6_init()
{
	register struct protosw *pr;
	register int i;
	struct timeval tv;

	pr = (struct protosw *)pffindproto(PF_INET6, IPPROTO_RAW, SOCK_RAW);
	if (pr == 0)
		panic("ip6_init");
	for (i = 0; i < IPPROTO_MAX; i++)
		ip6_protox[i] = pr;
	for (pr = inet6domain.dom_protosw; pr; pr = pr->pr_next) {
		if(!((unsigned int)pr->pr_domain)) continue;    /* If uninitialized, skip */
		if (pr->pr_domain->dom_family == PF_INET6 &&
		    pr->pr_protocol && pr->pr_protocol != IPPROTO_RAW) {
			ip6_protox[pr->pr_protocol] = pr;
		}
	}

	ip6intrq.ifq_maxlen = ip6qmaxlen;
	nd6_init();
	frag6_init();
#if IPV6FIREWALL
	ip6_fw_init();
#endif
	/*
	 * in many cases, random() here does NOT return random number
	 * as initialization during bootstrap time occur in fixed order.
	 */
	microtime(&tv);
	ip6_flow_seq = random() ^ tv.tv_usec;
	timeout(ip6_init2, (caddr_t)0, 6 * hz);
}

static void
ip6_init2(dummy)
	void *dummy;
{
	int ret;
#if defined(__bsdi__) && _BSDI_VERSION < 199802
	struct ifnet *loifp = &loif;
#endif
#ifdef __APPLE__
    	boolean_t   funnel_state;
    	funnel_state = thread_funnel_set(network_flock, TRUE);
#endif

	/* get EUI64 from somewhere */
	ret = in6_ifattach_getifid(NULL);

	/*
	 * to route local address of p2p link to loopback,
	 * assign loopback address first.
	 */
	in6_ifattach(&loif[0], IN6_IFT_LOOP, NULL, 0);

#if MIP6
	/* Initialize the Mobile IPv6 code */
	mip6_init();
#endif

#import <gif.h>
#if NGIF > 0
      gifattach();
#endif
#import <faith.h>
#if NFAITH > 0
      faithattach();
#endif

	/* nd6_timer_init */
	timeout(nd6_timer_funneled, (caddr_t)0, hz);
	/* router renumbering prefix list maintenance */
	timeout(in6_rr_timer_funneled, (caddr_t)0, hz);
#ifdef __APPLE__
        (void) thread_funnel_set(network_flock, FALSE);
#endif
}

#if __FreeBSD__
/* cheat */
SYSINIT(netinet6init2, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, ip6_init2, NULL);
#endif

/*
 * IP6 input interrupt handling. Just pass the packet to ip6_input.
 */
void
ip6intr(void)
{
	int s;
	struct mbuf *m;

	for (;;) {
		s = splimp();
		IF_DEQUEUE(&ip6intrq, m);
		splx(s);
		if (m == 0)
			return;
		ip6_input(m);
	}
}

NETISR_SET(NETISR_IPV6, ip6intr);

extern struct	route_in6 ip6_forward_rt;

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
#if defined(__bsdi__) && _BSDI_VERSION < 199802
	struct ifnet *loifp = &loif;
#endif

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
	 * mbuf statistics by kazu
	 */
	if (m->m_flags & M_EXT) {
		if (m->m_next)
			ip6stat.ip6s_mext2m++;
		else
			ip6stat.ip6s_mext1++;
	} else {
		if (m->m_next) {
			if (m->m_flags & M_LOOP)
				ip6stat.ip6s_m2m[loif[0].if_index]++;	/*XXX*/
			else if (m->m_pkthdr.rcvif->if_index <= 31)
				ip6stat.ip6s_m2m[m->m_pkthdr.rcvif->if_index]++;
			else
				ip6stat.ip6s_m2m[0]++;
		} else
			ip6stat.ip6s_m1++;
	}

	in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_receive);
	ip6stat.ip6s_total++;

#ifndef PULLDOWN_TEST
	/* XXX is the line really necessary? */
	IP6_EXTHDR_CHECK(m, 0, sizeof(struct ip6_hdr), /*nothing*/);
#endif

	if (m->m_len < sizeof(struct ip6_hdr)) {
		struct ifnet *inifp;
		inifp = m->m_pkthdr.rcvif;
		if ((m = m_pullup(m, sizeof(struct ip6_hdr))) == 0) {
			ip6stat.ip6s_toosmall++;
			in6_ifstat_inc(inifp, ifs6_in_hdrerr);
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

#if IPV6FIREWALL
	/*
	 * Check with the firewall...
	 */
	if (ip6_fw_chk_ptr) {
		u_short port = 0;
		/* If ipfw says divert, we have to just drop packet */
		/* use port as a dummy argument */
		if ((*ip6_fw_chk_ptr)(&ip6, NULL, &port, &m)) {
			m_freem(m);
			m = NULL;
		}
		if (!m)
			return;
	}
#endif

	/*
	 * Scope check
	 */
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_src) ||
	    IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_dst)) {
		ip6stat.ip6s_badscope++;
		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_addrerr);
		goto bad;
	}

	/*
	 * Don't check IPv4 mapped address here.  SIIT assumes that
	 * routers would forward IPv6 native packets with IPv4 mapped
	 * address normally.
	 */
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
	if (IN6_IS_ADDR_LOOPBACK(&ip6->ip6_src) ||
	    IN6_IS_ADDR_LOOPBACK(&ip6->ip6_dst)) {
		if (m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK) {
			ours = 1;
			deliverifp = m->m_pkthdr.rcvif;
			goto hbhcheck;
		} else {
			ip6stat.ip6s_badscope++;
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_addrerr);
			goto bad;
		}
	}

	if (m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK) {
		if (IN6_IS_ADDR_LINKLOCAL(&ip6->ip6_dst)) {
			ours = 1;
			deliverifp = m->m_pkthdr.rcvif;
			goto hbhcheck;
		}
	} else {
		if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src))
			ip6->ip6_src.s6_addr16[1]
				= htons(m->m_pkthdr.rcvif->if_index);
		if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst))
			ip6->ip6_dst.s6_addr16[1]
				= htons(m->m_pkthdr.rcvif->if_index);
	}

	/*
	 * Multicast check
	 */
	if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst)) {
	  	struct	in6_multi *in6m = 0;

		in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_mcast);
		/*
		 * See if we belong to the destination multicast group on the
		 * arrival interface.
		 */
		IN6_LOOKUP_MULTI(ip6->ip6_dst, m->m_pkthdr.rcvif, in6m);
		if (in6m)
			ours = 1;
		else if (!ip6_mrouter) {
			ip6stat.ip6s_notmember++;
			ip6stat.ip6s_cantforward++;
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_discard);
			goto bad;
		}
		deliverifp = m->m_pkthdr.rcvif;
		goto hbhcheck;
	}

	/*
	 *  Unicast check
	 */
	if (ip6_forward_rt.ro_rt == 0 ||
	    !IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst,
				&ip6_forward_rt.ro_dst.sin6_addr)) {
		if (ip6_forward_rt.ro_rt) {
			RTFREE(ip6_forward_rt.ro_rt);
			ip6_forward_rt.ro_rt = 0;
		}
		bzero(&ip6_forward_rt.ro_dst, sizeof(struct sockaddr_in6));
		ip6_forward_rt.ro_dst.sin6_len = sizeof(struct sockaddr_in6);
		ip6_forward_rt.ro_dst.sin6_family = AF_INET6;
		ip6_forward_rt.ro_dst.sin6_addr = ip6->ip6_dst;

#if __FreeBSD__ || defined(__APPLE__)
		rtalloc_ign((struct route *)&ip6_forward_rt, RTF_PRCLONING);
#else
		rtalloc((struct route *)&ip6_forward_rt);
#endif
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
	 */
	if (ip6_forward_rt.ro_rt &&
	    (ip6_forward_rt.ro_rt->rt_flags &
	     (RTF_HOST|RTF_GATEWAY)) == RTF_HOST &&
#if 0
	    /*
	     * The check below is redundant since the comparison of
	     * the destination and the key of the rtentry has
	     * already done through looking up the routing table.
	     */
	    IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst,
			       &rt6_key(ip6_forward_rt.ro_rt)->sin6_addr) &&
#endif
	    ip6_forward_rt.ro_rt->rt_ifp->if_type == IFT_LOOP) {
		struct in6_ifaddr *ia6 =
			(struct in6_ifaddr *)ip6_forward_rt.ro_rt->rt_ifa;
		/* packet to tentative address must not be received */
		if (ia6->ia6_flags & IN6_IFF_ANYCAST)
			m->m_flags |= M_ANYCAST6;
		if (!(ia6->ia6_flags & IN6_IFF_NOTREADY)) {
			/* this interface is ready */
			ours = 1;
			deliverifp = ia6->ia_ifp;	/* correct? */
			goto hbhcheck;
		} else {
			/* this interface is not ready, fall through */
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
			deliverifp = ip6_forward_rt.ro_rt->rt_ifp; /*faith*/
			goto hbhcheck;
		}
	}
#endif

#if NATPT
	/*
	 * NAT-PT (Network Address Translation - Protocol Translation)
	 */
	if (ip6_protocol_tr)
	{
	    struct mbuf *m1 = NULL;

	    switch (natpt_in6(m, &m1))
	    {
	      case IPPROTO_IP:					goto processpacket;
	      case IPPROTO_IPV4:	ip_forward(m1, 0);	break;
	      case IPPROTO_IPV6:	ip6_forward(m1, 0);	break;
	      case IPPROTO_MAX:			/* discard this packet	*/
	      default:						break;

	      case IPPROTO_DONE:		/* discard without free	*/
		return;
	    }

	    if (m != m1)
		m_freem(m);

	    return;
	}

  processpacket:
#endif

#if 0
    {
	/*
	 * Last resort: check in6_ifaddr for incoming interface.
	 * The code is here until I update the "goto ours hack" code above
	 * working right.
	 */
	struct ifaddr *ifa;
	for (ifa = m->m_pkthdr.rcvif->if_addrlist.tqh_first;
	     ifa;
	     ifa = ifa->ifa_list.tqe_next) {
		if (ifa->ifa_addr == NULL)
			continue;	/* just for safety */
		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;
		if (IN6_ARE_ADDR_EQUAL(IFA_IN6(ifa), &ip6->ip6_dst)) {
			ours = 1;
			deliverifp = ifa->ifa_ifp;
			goto hbhcheck;
		}
	}
    }
#endif

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
			return;	/* m have already been freed */
		}
		/* adjust pointer */
		ip6 = mtod(m, struct ip6_hdr *);
#ifndef PULLDOWN_TEST
		/* ip6_hopopts_input() ensures that mbuf is contiguous */
		hbh = (struct ip6_hbh *)(ip6 + 1);
#else
		IP6_EXTHDR_GET(hbh, struct ip6_hbh *, m, sizeof(struct ip6_hdr),
			sizeof(struct ip6_hbh));
		if (hbh == NULL) {
			ip6stat.ip6s_tooshort++;
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
			return;
		}
		if (!ours) {
			m_freem(m);
			return;
		}
	} else if (!ours) {
		ip6_forward(m, 0);
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
#if defined(__NetBSD__) && defined(IFA_STATS)
	if (IFA_STATS && deliverifp != NULL) {
		struct in6_ifaddr *ia6;
		ia6 = in6_ifawithifp(deliverifp, &ip6->ip6_dst);
		if (ia6)
			ia6->ia_ifa.ifa_data.ifad_inbytes += m->m_pkthdr.len;
	}
#endif
	ip6stat.ip6s_delivered++;
	in6_ifstat_inc(deliverifp, ifs6_in_deliver);
	nest = 0;

#if MIP6
	/*
	 * Mobile IPv6
	 *
	 * Assume that the received packet shall be processed by MIPv6 when
	 * the destination header has been taken care of. Because of this,
	 * some flags have to be reset for later evaluation.
	 */
	if (mip6_new_packet_hook)
		(*mip6_new_packet_hook)(m);
#endif /* MIP6 */

	while (nxt != IPPROTO_DONE) {
		if (ip6_hdrnestlimit && (++nest > ip6_hdrnestlimit)) {
			ip6stat.ip6s_toomanyhdr++;
			goto bad;
		}

		/*
		 * protection against faulty packet - there should be
		 * more sanity checks in header chain processing.
		 */
		if (m->m_pkthdr.len == 0 || m->m_pkthdr.len < off) {
			ip6stat.ip6s_tooshort++;
			in6_ifstat_inc(m->m_pkthdr.rcvif, ifs6_in_truncated);
			goto bad;
		}
		
#if MIP6
		if ((nxt != IPPROTO_HOPOPTS) && (nxt != IPPROTO_DSTOPTS) &&
		    (nxt != IPPROTO_ROUTING) && (nxt != IPPROTO_FRAGMENT) &&
		    (nxt != IPPROTO_ESP) && (nxt != IPPROTO_AH)) {
			if (mip6_route_optimize_hook)
				(*mip6_route_optimize_hook)(m);
		}
#endif
		nxt = (*ip6_protox[nxt]->pr_input)(&m, &off, nxt);
	}
	return;
 bad:
	m_freem(m);
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
	register struct mbuf *m = *mp;
	int off = *offp, hbhlen;
	struct ip6_hbh *hbh;
	u_int8_t *opt;

	/* validation of the length of the header */
#ifndef PULLDOWN_TEST
	IP6_EXTHDR_CHECK(m, off, sizeof(*hbh), -1);
	hbh = (struct ip6_hbh *)(mtod(m, caddr_t) + off);
	hbhlen = (hbh->ip6h_len + 1) << 3;

	IP6_EXTHDR_CHECK(m, off, hbhlen, -1);
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

	for (; hbhlen > 0; hbhlen -= optlen, opt += optlen) {
		switch(*opt) {
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
			 if (*(opt + 1) != IP6OPT_RTALERT_LEN - 2)
				  /* XXX: should we discard the packet? */
				 log(LOG_ERR, "length of router alert opt is inconsitent(%d)",
				     *(opt + 1));
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
			 if (*(opt + 1) != IP6OPT_JUMBO_LEN - 2)
				  /* XXX: should we discard the packet? */
				 log(LOG_ERR, "length of jumbopayload opt "
				     "is inconsistent(%d)",
				     *(opt + 1));
			 optlen = IP6OPT_JUMBO_LEN;

			 /*
			  * We can simply cast because of the alignment
			  * requirement of the jumbo payload option.
			  */
#if 0
			 *plenp = ntohl(*(u_int32_t *)(opt + 2));
#else
			 bcopy(opt + 2, plenp, sizeof(*plenp));
			 *plenp = htonl(*plenp);
#endif
			 if (*plenp <= IPV6_MAXPACKET) {
				 /*
				  * jumbo payload length must be larger
				  * than 65535
				  */
				 ip6stat.ip6s_badoptions++;
				 icmp6_error(m, ICMP6_PARAM_PROB,
					     ICMP6_PARAMPROB_HEADER,
					     sizeof(struct ip6_hdr) +
					     sizeof(struct ip6_hbh) +
					     opt + 2 - opthead);
				 return(-1);
			 }

			 ip6 = mtod(m, struct ip6_hdr *);
			 if (ip6->ip6_plen) {
				 /*
				  * IPv6 packets that have non 0 payload length
				  * must not contain a jumbo paylod option.
				  */
				 ip6stat.ip6s_badoptions++;
				 icmp6_error(m, ICMP6_PARAM_PROB,
					     ICMP6_PARAMPROB_HEADER,
					     sizeof(struct ip6_hdr) +
					     sizeof(struct ip6_hbh) +
					     opt - opthead);
				 return(-1);
			 }
			 break;
		 default:		/* unknown option */
			 if (hbhlen < IP6OPT_MINLEN) {
				 ip6stat.ip6s_toosmall++;
				 goto bad;
			 }
			 if ((optlen = ip6_unknown_opt(opt, m,
						       sizeof(struct ip6_hdr) +
						       sizeof(struct ip6_hbh) +
						       opt - opthead)) == -1)
				 return(-1);
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
ip6_unknown_opt(optp, m, off)
	u_int8_t *optp;
	struct mbuf *m;
	int off;
{
	struct ip6_hdr *ip6;

	switch(IP6OPT_TYPE(*optp)) {
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
ip6_savecontrol(in6p, ip6, m, ctl, prevctlp)
#if defined(__FreeBSD__) && __FreeBSD__ >= 3 || defined(__APPLE__)
	register struct inpcb *in6p;
#else
	register struct in6pcb *in6p;
#endif
	register struct ip6_hdr *ip6;
	register struct mbuf *m;
	struct ip6_recvpktopts *ctl, **prevctlp;
{
	register struct mbuf **mp;
	struct cmsghdr *cm = NULL;
	struct ip6_recvpktopts *prevctl = NULL;
#if HAVE_NRL_INPCB
# define in6p_flags	inp_flags
#endif
#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ >= 3) || defined (__APPLE__)
	struct proc *p = current_proc();	/* XXX */
#endif
#ifdef __bsdi__
# define sbcreatecontrol	so_cmsg
#endif
	int privileged = 0;


	if (ctl == NULL)	/* validity check */
		return;
	bzero(ctl, sizeof(*ctl)); /* XXX is it really OK? */
	mp = &ctl->head;

	/*
	 * If caller wanted to keep history, allocate space to store the
	 * history at the first time.
	 */
	if (prevctlp) {
		if (*prevctlp == NULL) {
			MALLOC(prevctl, struct ip6_recvpktopts *,
			       sizeof(*prevctl), M_IP6OPT, M_NOWAIT);
			if (prevctl == NULL) {
				printf("ip6_savecontrol: can't allocate "
				       " enough space for history\n");
				return;
			}
			bzero(prevctl, sizeof(*prevctl));
			*prevctlp = prevctl;
		}
		else
			prevctl = *prevctlp;
	}

#if defined(__NetBSD__) || (defined(__FreeBSD__) && __FreeBSD__ == 3)
	if (p && !suser(p->p_ucred, &p->p_acflag))
		privileged++;
#elif defined(__FreeBSD__) && __FreeBSD__ >= 4
	if (p && !suser(p))
 		privileged++;
#else
#if HAVE_NRL_INPCB
	if ((in6p->inp_socket->so_state & SS_PRIV) != 0)
		privileged++;
#else
	if ((in6p->in6p_socket->so_state & SS_PRIV) != 0)
		privileged++;
#endif
#endif

#if SO_TIMESTAMP
	if (in6p->in6p_socket->so_options & SO_TIMESTAMP) {
		struct timeval tv;

		microtime(&tv);
		*mp = sbcreatecontrol((caddr_t) &tv, sizeof(tv),
				      SCM_TIMESTAMP, SOL_SOCKET);
		if (*mp) {
			/* always set regradless of the previous value */
			ctl->timestamp = *mp;
			mp = &(*mp)->m_next;
		}
	}
#endif

	/* RFC 2292 sec. 5 */
	if (in6p->in6p_flags & IN6P_PKTINFO) {
		struct in6_pktinfo pi6, *prevpi = NULL;
		bcopy(&ip6->ip6_dst, &pi6.ipi6_addr, sizeof(struct in6_addr));
		if (IN6_IS_SCOPE_LINKLOCAL(&pi6.ipi6_addr))
			pi6.ipi6_addr.s6_addr16[1] = 0;
		pi6.ipi6_ifindex = (m && m->m_pkthdr.rcvif)
					? m->m_pkthdr.rcvif->if_index
					: 0;
		if (prevctl && prevctl->pktinfo) {
			cm = mtod(prevctl->pktinfo, struct cmsghdr *);
			prevpi = (struct in6_pktinfo *)CMSG_DATA(cm);
		}

		/*
		 * Make a new option only if this is the first time or if the
		 * option value is chaned from last time.
		 */
		if (prevpi == NULL || bcmp(prevpi, &pi6, sizeof(pi6))) {
			*mp = sbcreatecontrol((caddr_t) &pi6,
					      sizeof(struct in6_pktinfo),
					      IPV6_PKTINFO,
					      IPPROTO_IPV6);
			if (*mp) {
				ctl->pktinfo = *mp;
				mp = &(*mp)->m_next;
			}
		}
	}

	if (in6p->in6p_flags & IN6P_HOPLIMIT) {
		int hlim = ip6->ip6_hlim & 0xff, oldhlim = -1;

		if (prevctl && prevctl->hlim) {
			cm = mtod(prevctl->hlim, struct cmsghdr *);
			oldhlim = (*(int *)CMSG_DATA(cm)) & 0xff;
		}

		if (oldhlim < 0 || hlim != oldhlim) {
			*mp = sbcreatecontrol((caddr_t) &hlim,
					      sizeof(int), IPV6_HOPLIMIT,
					      IPPROTO_IPV6);
			if (*mp) {
				ctl->hlim = *mp;
				mp = &(*mp)->m_next;
			}
		}
	}

	/*
	 * IPV6_HOPOPTS socket option. We require super-user privilege
	 * for the option, but it might be too strict, since there might
	 * be some hop-by-hop options which can be returned to normal user.
	 * See RFC 2292 section 6.
	 */
	if ((in6p->in6p_flags & IN6P_HOPOPTS) && privileged) {
		/*
		 * Check if a hop-by-hop options header is contatined in the
		 * received packet, and if so, store the options as ancillary
		 * data. Note that a hop-by-hop options header must be
		 * just after the IPv6 header, which fact is assured through
		 * the IPv6 input processing.
		 */
		struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
		if (ip6->ip6_nxt == IPPROTO_HOPOPTS) {
			struct ip6_hbh *hbh, *prevhbh = NULL;
			int hbhlen = 0, prevhbhlen = 0;
#ifdef PULLDOWN_TEST
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

			if (prevctl && prevctl->hbh) {
				cm = mtod(prevctl->hbh, struct cmsghdr *);
				prevhbh = (struct ip6_hbh *)CMSG_DATA(cm);
				prevhbhlen = (prevhbh->ip6h_len + 1) << 3;
			}
			/*
			 * Check if there's difference between the current
			 * and previous HbH headers.
			 * XXX: should the next header field be ignored?
			 */
			if (prevhbh == NULL || hbhlen != prevhbhlen ||
			    bcmp(prevhbh, hbh, hbhlen)) {
				/*
				 * XXX: We copy whole the header even if a
				 * jumbo payload option is included, which
				 * option is to be removed before returning
				 * in the RFC 2292.
				 * Note: this constraint is removed in
				 * 2292bis.
				 */
				*mp = sbcreatecontrol((caddr_t)hbh, hbhlen,
						      IPV6_HOPOPTS,
						      IPPROTO_IPV6);
				if (*mp) {
					ctl->hbh = *mp;
					mp = &(*mp)->m_next;
				}
			}
#ifdef PULLDOWN_TEST
			m_freem(ext);
#endif
		}
	}

	/* IPV6_DSTOPTS and IPV6_RTHDR socket options */
	if (in6p->in6p_flags & (IN6P_DSTOPTS | IN6P_RTHDR)) {
		struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
		int nxt = ip6->ip6_nxt, off = sizeof(struct ip6_hdr);
		int rthdr = 0;	/* flag if we've passed a routing header */

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
#ifdef PULLDOWN_TEST
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
			{
				struct ip6_dest *prevdest1 = NULL,
					*prevdest2 = NULL;
				int prevdestlen;

				if ((in6p->in6p_flags &
				     (IN6P_DSTOPTS | IN6P_RTHDRDSTOPTS)) == 0)
					break;

				 /*
				  * We also require super-user privilege for
				  * the option.
				  * See the comments on IN6_HOPOPTS.
				  */
				if (!privileged)
					break;

				 /*
				  * Save a dst opt header before a routing
				  * header if the user wanted.
				  */
				if (rthdr == 0 &&
				    (in6p->in6p_flags & IN6P_RTHDRDSTOPTS)) {
					if (prevctl && prevctl->dest1) {
						cm = mtod(prevctl->dest1,
							  struct cmsghdr *);
						prevdest1 = (struct ip6_dest *)CMSG_DATA(cm);
						prevdestlen = (prevdest1->ip6d_len + 1) << 3;
					}

					/*
					 * If this is the 1st dst opt header
					 * (that is placed before rthdr)
					 * we enconter and this header is
					 * not different from the previous one,
					 * simply ignore the header.
					 */
					if (ctl->dest1 == NULL &&
					    (prevdest1 &&
					     prevdestlen == elen &&
					     bcmp(ip6e, prevdest1, elen) == 0))
						break;

					*mp = sbcreatecontrol((caddr_t)ip6e,
							      elen,
							      IPV6_RTHDRDSTOPTS,
							      IPPROTO_IPV6);
					if (ctl->dest1 == NULL)
						ctl->dest1 = *mp;
					if (*mp)
						mp = &(*mp)->m_next;
				}
				/*
				 * Save a dst opt header after a routing
				 * header if the user wanted.
				 */
				if (rthdr &&
				    (in6p->in6p_flags & IN6P_DSTOPTS)) {
					if (prevctl && prevctl->dest2) {
						cm = mtod(prevctl->dest2,
							  struct cmsghdr *);
						prevdest2 = (struct ip6_dest *)CMSG_DATA(cm);
						prevdestlen = (prevdest2->ip6d_len + 1) << 3;
					}
					/* see the above comment */
					if (ctl->dest2 == NULL &&
					    (prevdest2 &&
					     prevdestlen == elen &&
					     bcmp(ip6e, prevdest2, elen) == 0))
						break;

					*mp = sbcreatecontrol((caddr_t)ip6e,
							      elen,
							      IPV6_DSTOPTS,
							      IPPROTO_IPV6);
					if (ctl->dest2 == NULL)
						ctl->dest2 = *mp;

					if (*mp)
						mp = &(*mp)->m_next;
				}
				break;
			}
			case IPPROTO_ROUTING:
			{
				struct ip6_rthdr *prevrth = NULL;
				int prevrhlen = 0;

				rthdr++;
				if (!in6p->in6p_flags & IN6P_RTHDR)
					break;

				if (prevctl && prevctl->rthdr) {
					cm = mtod(prevctl->rthdr,
						  struct cmsghdr *);
					prevrth = (struct ip6_rthdr *)CMSG_DATA(cm);
					prevrhlen =
						(prevrth->ip6r_len + 1) << 3;
				}

				/*
				 * Check if the rthdr should be passed to
				 * a user. See the comments for dstopt hdr.
				 */
				if (ctl->rthdr == NULL && prevrth &&
				    prevrhlen == elen &&
				    bcmp(ip6e, prevrth, elen) == 0)
					break;

				*mp = sbcreatecontrol((caddr_t)ip6e, elen,
						      IPV6_RTHDR,
						      IPPROTO_IPV6);
				if (ctl->rthdr == NULL)
					ctl->rthdr = *mp;
				if (*mp)
					mp = &(*mp)->m_next;
				break;
			}
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
#ifdef PULLDOWN_TEST
				m_freem(ext);
#endif
				goto loopend;

			}

			/* proceed with the next header. */
			off += elen;
			nxt = ip6e->ip6e_nxt;
			ip6e = NULL;
#ifdef PULLDOWN_TEST
			m_freem(ext);
			ext = NULL;
#endif
		}
	  loopend:
	}

#ifdef __bsdi__
# undef sbcreatecontrol
#endif
#ifdef __OpenBSD__
# undef in6p_flags
#endif
}

#ifdef PULLDOWN_TEST
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

#ifdef DIAGNOSTIC
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
 * Merge new IPv6 received options to previous ones.
 * If a new option is not given, just re-link the option chain.
 * If an old option exists but a corresponding new one doesn't, just
 * keep the ole option.
 * If a new option exists but a corresponding old one doesn't, just
 * copy the new option.
 * If both new and old options exist, free old one and overwrite the option
 * with the new option.
 * Otherwise, do nothing for the option.
 * XXX: in any case, options that don't follow the recommend order and
 *      number of extension headers (RFC 2460 Section 4.1) are simply ignored.
 * XXX: We assume that each option is stored in a single mbuf.
 */
#define CLEAN_RECVOPT(old, type) \
do {								\
	if ((old)->type && (old)->type->m_next) {		\
		(old)->type->m_next = NULL;			\
	}							\
} while (0)
#define MERGE_RECVOPT(new, old, type) if ((new)->type) {\
		if ((old)->type)\
			m_free((old)->type);\
		(old)->type = m_copy((new)->type, 0, (new)->type->m_len);\
		if (((old)->type) && ((old)->type->m_next)) {\
			m_freem((old)->type);\
			old->type = NULL;\
		}\
	}
#define LINK_RECVOPTS(opt, type, p) if ((opt)->type) {\
		*(p) = (opt)->type;\
		(p) = &(opt)->type->m_next;\
	}

static void dump_inputopts __P((char *, struct ip6_recvpktopts *));
static void
dump_inputopts(str, p)
	char *str;
	struct ip6_recvpktopts *p;
{
#if 1
	return;
#else
#define PRINT1(p, name) \
do { \
	if (p->name) { \
		printf(" %s: %p", #name, (p)->name); \
		if (p->name->m_next) \
			printf("[%p]", (p)->name->m_next); \
	} \
} while (0)

	printf("%s p=%p head=%p", str, p, p->head);
	PRINT1(p, hlim);
	PRINT1(p, pktinfo);
	PRINT1(p, hbh);
	PRINT1(p, dest1);
	PRINT1(p, dest2);
	PRINT1(p, rthdr);
	printf("\n");
#undef PRINT1
#endif
}

void
ip6_update_recvpcbopt(old, new)
	struct ip6_recvpktopts *new, *old;
{
	struct mbuf **mp;

	if (old == NULL) {
		printf("ip6_update_recvpcbopt: invalid arguments\n");
		return;
	}

	dump_inputopts("old before", old);
	if (new)
		dump_inputopts("new before", new);

#if 0
	/*
	 * cleanup m->m_next linkage. note that we do it in reverse order
	 * to prevent possible memory leakage.
	 */
	old->head = NULL;
	CLEAN_RECVOPT(old, rthdr);
	CLEAN_RECVOPT(old, dest2);
	CLEAN_RECVOPT(old, dest1);
	CLEAN_RECVOPT(old, hbh);
	CLEAN_RECVOPT(old, pktinfo);
	CLEAN_RECVOPT(old, hlim);
#endif

	if (new) {
		MERGE_RECVOPT(new, old, hlim);
		MERGE_RECVOPT(new, old, pktinfo);
		MERGE_RECVOPT(new, old, hbh);
		MERGE_RECVOPT(new, old, dest1);
		MERGE_RECVOPT(new, old, dest2);
		MERGE_RECVOPT(new, old, rthdr);
	}

	dump_inputopts("old middle", old);
	if (new)
		dump_inputopts("new middle", new);

	/* link options */
	mp = &old->head;
	LINK_RECVOPTS(old, hlim, mp);
	LINK_RECVOPTS(old, pktinfo, mp);
	LINK_RECVOPTS(old, hbh, mp);
	LINK_RECVOPTS(old, dest1, mp);
	LINK_RECVOPTS(old, dest2, mp);
	LINK_RECVOPTS(old, rthdr, mp);
	*mp = NULL;

	dump_inputopts("old after", old);
	if (new)
		dump_inputopts("new after", new);
}

#undef MERGE_RECVOPT
#undef LINK_RECVOPTS

void
ip6_reset_rcvopt(opts, optname)
	struct ip6_recvpktopts *opts;
	int optname;
{
	if (opts == NULL)
		return;

	switch(optname) {
	case IPV6_RECVPKTINFO:
		if (opts->pktinfo) m_free(opts->pktinfo);
		opts->pktinfo = NULL;
		break;
	case IPV6_RECVHOPLIMIT:
		if (opts->hlim) m_free(opts->hlim);
		opts->hlim = NULL;
		break;
	case IPV6_RECVHOPOPTS:
		if (opts->hbh) m_free(opts->hbh);
		opts->hbh = NULL;
		break;
	case IPV6_RECVRTHDRDSTOPTS:
		if (opts->dest1) m_free(opts->dest1);
		opts->dest1 = NULL;
		break;
	case IPV6_RECVDSTOPTS:
		if (opts->dest2) m_free(opts->dest2);
		opts->dest2 = NULL;
		break;
	case IPV6_RECVRTHDR:
		if (opts->rthdr) m_free(opts->rthdr);
		opts->rthdr = NULL;
		break;
	default:
		printf("ip6_reset_rcvopt: invalid option name (%d)\n",
		       optname);
		return;
	}

	ip6_update_recvpcbopt(opts, NULL); /* re-link the option chain */
}

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
		return(&ip6->ip6_nxt);
	else {
		int len, nxt;
		struct ip6_ext *ip6e = NULL;

		nxt = ip6->ip6_nxt;
		len = sizeof(struct ip6_hdr);
		while (len < off) {
			ip6e = (struct ip6_ext *)(mtod(m, caddr_t) + len);

			switch(nxt) {
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
			return(&ip6e->ip6e_nxt);
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
		if ((ntohs(fh.ip6f_offlg) & IP6F_OFF_MASK) != 0)
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

#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <vm/vm.h>
#include <sys/sysctl.h>

int
ip6_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
{
	/* All sysctl names at this level are terminal. */
	if (namelen != 1)
		return ENOTDIR;

	switch (name[0]) {

	case IPV6CTL_FORWARDING:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				  &ip6_forwarding);
	case IPV6CTL_SENDREDIRECTS:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&ip6_sendredirects);
	case IPV6CTL_DEFHLIM:
		return sysctl_int(oldp, oldlenp, newp, newlen, &ip6_defhlim);
	case IPV6CTL_MAXFRAGPACKETS:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&ip6_maxfragpackets);
	case IPV6CTL_ACCEPT_RTADV:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&ip6_accept_rtadv);
	case IPV6CTL_KEEPFAITH:
		return sysctl_int(oldp, oldlenp, newp, newlen, &ip6_keepfaith);
	case IPV6CTL_LOG_INTERVAL:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&ip6_log_interval);
	case IPV6CTL_HDRNESTLIMIT:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&ip6_hdrnestlimit);
	case IPV6CTL_DAD_COUNT:
		return sysctl_int(oldp, oldlenp, newp, newlen, &ip6_dad_count);
	case IPV6CTL_AUTO_FLOWLABEL:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&ip6_auto_flowlabel);
	case IPV6CTL_DEFMCASTHLIM:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&ip6_defmcasthlim);
	case IPV6CTL_GIF_HLIM:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&ip6_gif_hlim);
	case IPV6CTL_KAME_VERSION:
		return sysctl_rdstring(oldp, oldlenp, newp, __KAME_VERSION);
	case IPV6CTL_USE_DEPRECATED:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&ip6_use_deprecated);
	case IPV6CTL_RR_PRUNE:
		return sysctl_int(oldp, oldlenp, newp, newlen, &ip6_rr_prune);
#if defined(__NetBSD__) && !defined(INET6_BINDV6ONLY)
	case IPV6CTL_BINDV6ONLY:
		return sysctl_int(oldp, oldlenp, newp, newlen,
				&ip6_bindv6only);
#endif
	default:
		return EOPNOTSUPP;
	}
	/* NOTREACHED */
}
#endif /* __NetBSD__ || __OpenBSD__ */

#ifdef __bsdi__
int *ip6_sysvars[] = IPV6CTL_VARS;

int
ip6_sysctl(name, namelen, oldp, oldlenp, newp, newlen)
	int	*name;
	u_int	namelen;
	void	*oldp;
	size_t	*oldlenp;
	void	*newp;
	size_t	newlen;
{
	if (name[0] >= IPV6CTL_MAXID)
		return (EOPNOTSUPP);

	switch (name[0]) {
	case IPV6CTL_STATS:
		return sysctl_rdtrunc(oldp, oldlenp, newp, &ip6stat,
		    sizeof(ip6stat));
	case IPV6CTL_KAME_VERSION:
		return sysctl_rdstring(oldp, oldlenp, newp, __KAME_VERSION);
	default:
		return (sysctl_int_arr(ip6_sysvars, name, namelen,
		    oldp, oldlenp, newp, newlen));
	}
}
#endif /* __bsdi__ */
