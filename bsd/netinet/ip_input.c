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
 *	$ANA: ip_input.c,v 1.5 1996/09/18 14:34:59 wollman Exp $
 */

#define	_IP_VHL

#include <stddef.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>

#include <kern/queue.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/netisr.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#ifdef INET6
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <sys/socketvar.h>

#include <sys/kdebug.h>


#define DBG_LAYER_BEG		NETDBG_CODE(DBG_NETIP, 0)
#define DBG_LAYER_END		NETDBG_CODE(DBG_NETIP, 2)
#define DBG_FNC_IP_INPUT	NETDBG_CODE(DBG_NETIP, (2 << 8))


#if IPFIREWALL
#include <netinet/ip_fw.h>
#endif

#if IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#include <netkey/key_debug.h>
#endif

#include "faith.h"
#if defined(NFAITH) && NFAITH > 0
#include <net/if_types.h>
#endif

#if DUMMYNET
#include <netinet/ip_dummynet.h>
#endif

int rsvp_on = 0;
static int ip_rsvp_on;
struct socket *ip_rsvpd;

int	ipforwarding = 0;
SYSCTL_INT(_net_inet_ip, IPCTL_FORWARDING, forwarding, CTLFLAG_RW,
	&ipforwarding, 0, "");

static int	ipsendredirects = 1; /* XXX */
SYSCTL_INT(_net_inet_ip, IPCTL_SENDREDIRECTS, redirect, CTLFLAG_RW,
	&ipsendredirects, 0, "");

int	ip_defttl = IPDEFTTL;
SYSCTL_INT(_net_inet_ip, IPCTL_DEFTTL, ttl, CTLFLAG_RW,
	&ip_defttl, 0, "");

static int	ip_dosourceroute = 0;
SYSCTL_INT(_net_inet_ip, IPCTL_SOURCEROUTE, sourceroute, CTLFLAG_RW,
	&ip_dosourceroute, 0, "");

static int	ip_acceptsourceroute = 0;
SYSCTL_INT(_net_inet_ip, IPCTL_ACCEPTSOURCEROUTE, accept_sourceroute,
	CTLFLAG_RW, &ip_acceptsourceroute, 0, "");

static int	ip_keepfaith = 0;
SYSCTL_INT(_net_inet_ip, IPCTL_KEEPFAITH, keepfaith, CTLFLAG_RW,
	&ip_keepfaith,	0, "");

#if DIAGNOSTIC
static int	ipprintfs = 0;
#endif

extern	struct domain inetdomain;
extern	struct protosw inetsw[];
struct protosw *ip_protox[IPPROTO_MAX];
static int	ipqmaxlen = IFQ_MAXLEN;
struct	in_ifaddrhead in_ifaddrhead; /* first inet address */
struct	ifqueue ipintrq;
SYSCTL_INT(_net_inet_ip, IPCTL_INTRQMAXLEN, intr_queue_maxlen, CTLFLAG_RD,
	&ipintrq.ifq_maxlen, 0, "");
SYSCTL_INT(_net_inet_ip, IPCTL_INTRQDROPS, intr_queue_drops, CTLFLAG_RD,
	&ipintrq.ifq_drops, 0, "");

struct ipstat ipstat;
SYSCTL_STRUCT(_net_inet_ip, IPCTL_STATS, stats, CTLFLAG_RD,
	&ipstat, ipstat, "");

/* Packet reassembly stuff */
#define IPREASS_NHASH_LOG2      6
#define IPREASS_NHASH           (1 << IPREASS_NHASH_LOG2)
#define IPREASS_HMASK           (IPREASS_NHASH - 1)
#define IPREASS_HASH(x,y) \
	((((x) & 0xF | ((((x) >> 8) & 0xF) << 4)) ^ (y)) & IPREASS_HMASK)

static struct ipq ipq[IPREASS_NHASH];
static int    nipq = 0;         /* total # of reass queues */
static int    maxnipq;

#if IPCTL_DEFMTU
SYSCTL_INT(_net_inet_ip, IPCTL_DEFMTU, mtu, CTLFLAG_RW,
	&ip_mtu, 0, "");
#endif

#if !defined(COMPAT_IPFW) || COMPAT_IPFW == 1
#undef COMPAT_IPFW
#define COMPAT_IPFW 1
#else
#undef COMPAT_IPFW
#endif

#if COMPAT_IPFW

#include <netinet/ip_fw.h>

/* Firewall hooks */
ip_fw_chk_t *ip_fw_chk_ptr;
ip_fw_ctl_t *ip_fw_ctl_ptr;

#if DUMMYNET
ip_dn_ctl_t *ip_dn_ctl_ptr;
#endif

/* IP Network Address Translation (NAT) hooks */ 
ip_nat_t *ip_nat_ptr;
ip_nat_ctl_t *ip_nat_ctl_ptr;
#endif

#if defined(IPFILTER_LKM) || defined(IPFILTER)
int iplattach __P((void));
int (*fr_checkp) __P((struct ip *, int, struct ifnet *, int, struct mbuf **)) = NULL;
#endif


/*
 * We need to save the IP options in case a protocol wants to respond
 * to an incoming packet over the same route if the packet got here
 * using IP source routing.  This allows connection establishment and
 * maintenance when the remote end is on a network that is not known
 * to us.
 */
static int	ip_nhops = 0;
static	struct ip_srcrt {
	struct	in_addr dst;			/* final destination */
	char	nop;				/* one NOP to align */
	char	srcopt[IPOPT_OFFSET + 1];	/* OPTVAL, OLEN and OFFSET */
	struct	in_addr route[MAX_IPOPTLEN/sizeof(struct in_addr)];
} ip_srcrt;

#if IPDIVERT
/*
 * Shared variable between ip_input() and ip_reass() to communicate
 * about which packets, once assembled from fragments, get diverted,
 * and to which port.
 */
static u_short	frag_divert_port;
#endif

struct sockaddr_in *ip_fw_fwd_addr;

static void save_rte __P((u_char *, struct in_addr));
static int	 ip_dooptions __P((struct mbuf *));
#ifndef NATPT
static
#endif
void	 ip_forward __P((struct mbuf *, int));
static void	 ip_freef __P((struct ipq *));
static struct ip *
	 ip_reass __P((struct mbuf *, struct ipq *, struct ipq *));
static struct in_ifaddr *
	 ip_rtaddr __P((struct in_addr));
void	ipintr __P((void));

#if PM
extern	int	doNatFil;
extern	int	doRoute;

extern	int		 pm_in	    __P((struct ifnet *, struct ip *, struct mbuf *));
extern	struct route	*pm_route   __P((struct mbuf *));
#endif

#if defined(NATPT)
extern	int		ip6_protocol_tr;

int	 natpt_in4	__P((struct mbuf *, struct mbuf **));

#endif	/* NATPT	*/

/*
 * IP initialization: fill in IP protocol switch table.
 * All protocols not implemented in kernel go to raw IP protocol handler.
 */
void
ip_init()
{
	register struct protosw *pr;
	register int i;
	static ip_initialized = 0;

	if (!ip_initialized)
	{
		TAILQ_INIT(&in_ifaddrhead);
		pr = pffindproto(PF_INET, IPPROTO_RAW, SOCK_RAW);
		if (pr == 0)
			panic("ip_init");
		for (i = 0; i < IPPROTO_MAX; i++)
			ip_protox[i] = pr;
		for (pr = inetdomain.dom_protosw; pr; pr = pr->pr_next)
		{	if(!((unsigned int)pr->pr_domain)) continue;    /* If uninitialized, skip */
			if (pr->pr_domain->dom_family == PF_INET &&
			    pr->pr_protocol && pr->pr_protocol != IPPROTO_RAW)
				ip_protox[pr->pr_protocol] = pr;
		}
		for (i = 0; i < IPREASS_NHASH; i++)
		    ipq[i].next = ipq[i].prev = &ipq[i];

		maxnipq = nmbclusters/4;

		ip_id = time_second & 0xffff;
		ipintrq.ifq_maxlen = ipqmaxlen;
#if DUMMYNET
		ip_dn_init();
#endif
#if IPNAT
		ip_nat_init();
#endif
#if IPFILTER
		iplattach();
#endif
		ip_initialized = 1;
	}
}

/* Initialize the PF_INET domain, and add in the pre-defined protos */
void
in_dinit()
{	register int i;
	register struct protosw *pr;
	register struct domain *dp;
	static inetdomain_initted = 0;
	extern int in_proto_count; 

	if (!inetdomain_initted)
	{	kprintf("Initing %d protosw entries\n", in_proto_count);
		dp = &inetdomain;

		for (i=0, pr = &inetsw[0]; i<in_proto_count; i++, pr++)
			net_add_proto(pr, dp);
		inetdomain_initted = 1;
	}
}

static struct	sockaddr_in ipaddr = { sizeof(ipaddr), AF_INET };
static struct	route ipforward_rt;

/*
 * Ip input routine.  Checksum and byte swap header.  If fragmented
 * try to reassemble.  Process options.  Pass to next level.
 */
void
ip_input(struct mbuf *m)
{
	struct ip *ip;
	struct ipq *fp;
	struct in_ifaddr *ia;
	int    i, hlen, mff;
	u_short sum;
#if !IPDIVERT /* dummy variable for the firewall code to play with */
        u_short ip_divert_cookie = 0 ;
#endif
#if COMPAT_IPFW
	struct ip_fw_chain *rule = NULL ;
#endif

#if IPFIREWALL && DUMMYNET
        /*
         * dummynet packet are prepended a vestigial mbuf with
         * m_type = MT_DUMMYNET and m_data pointing to the matching
         * rule.
         */
        if (m->m_type == MT_DUMMYNET) {
            struct mbuf *m0 = m ;
            rule = (struct ip_fw_chain *)(m->m_data) ;
            m = m->m_next ;
            FREE(m0, M_IPFW);
            ip = mtod(m, struct ip *);
            hlen = IP_VHL_HL(ip->ip_vhl) << 2;
            goto iphack ;
        } else
            rule = NULL ;
#endif

#if	DIAGNOSTIC
	if (m == NULL || (m->m_flags & M_PKTHDR) == 0)
		panic("ip_input no HDR");
#endif
	/*
	 * If no IP addresses have been set yet but the interfaces
	 * are receiving, can't do anything with incoming packets yet.
	 * XXX This is broken! We should be able to receive broadcasts
	 * and multicasts even without any local addresses configured.
	 */
	if (TAILQ_EMPTY(&in_ifaddrhead))
		goto bad;
	ipstat.ips_total++;

	if (m->m_pkthdr.len < sizeof(struct ip))
		goto tooshort;

	if (m->m_len < sizeof (struct ip) &&
	    (m = m_pullup(m, sizeof (struct ip))) == 0) {
		ipstat.ips_toosmall++;
		return;
	}
	ip = mtod(m, struct ip *);

	KERNEL_DEBUG(DBG_LAYER_BEG, ip->ip_dst.s_addr, 
		     ip->ip_src.s_addr, ip->ip_p, ip->ip_off, ip->ip_len);

	if (IP_VHL_V(ip->ip_vhl) != IPVERSION) {
		ipstat.ips_badvers++;
		goto bad;
	}

	hlen = IP_VHL_HL(ip->ip_vhl) << 2;
	if (hlen < sizeof(struct ip)) {	/* minimum header length */
		ipstat.ips_badhlen++;
		goto bad;
	}
	if (hlen > m->m_len) {
		if ((m = m_pullup(m, hlen)) == 0) {
			ipstat.ips_badhlen++;
			return;
		}
		ip = mtod(m, struct ip *);
	}

	sum = in_cksum(m, hlen);

	if (sum) {
		ipstat.ips_badsum++;
		goto bad;
	}

	/*
	 * Convert fields to host representation.
	 */
	NTOHS(ip->ip_len);
	if (ip->ip_len < hlen) {
		ipstat.ips_badlen++;
		goto bad;
	}
	NTOHS(ip->ip_id);
	NTOHS(ip->ip_off);

	/*
	 * Check that the amount of data in the buffers
	 * is as at least much as the IP header would have us expect.
	 * Trim mbufs if longer than we expect.
	 * Drop packet if shorter than we expect.
	 */
	if (m->m_pkthdr.len < ip->ip_len) {
tooshort:
		ipstat.ips_tooshort++;
		goto bad;
	}
	if (m->m_pkthdr.len > ip->ip_len) {
		if (m->m_len == m->m_pkthdr.len) {
			m->m_len = ip->ip_len;
			m->m_pkthdr.len = ip->ip_len;
		} else
			m_adj(m, ip->ip_len - m->m_pkthdr.len);
	}
	/*
	 * IpHack's section.
	 * Right now when no processing on packet has done
	 * and it is still fresh out of network we do our black
	 * deals with it.
	 * - Firewall: deny/allow/divert
	 * - Xlate: translate packet's addr/port (NAT).
	 * - Pipe: pass pkt through dummynet.
	 * - Wrap: fake packet's addr/port <unimpl.>
	 * - Encapsulate: put it in another IP and send out. <unimp.>
 	 */

#if defined(IPFIREWALL) && defined(DUMMYNET)
iphack:
#endif
#if defined(IPFILTER) || defined(IPFILTER_LKM)
	/*
	 * Check if we want to allow this packet to be processed.
	 * Consider it to be bad if not.
	 */
	if (fr_checkp) {
		struct	mbuf	*m1 = m;

		if ((*fr_checkp)(ip, hlen, m->m_pkthdr.rcvif, 0, &m1) || !m1)
			return;
		ip = mtod(m = m1, struct ip *);
	}
#endif
#if COMPAT_IPFW
	if (ip_fw_chk_ptr) {
#if IPFIREWALL_FORWARD
		/*
		 * If we've been forwarded from the output side, then
		 * skip the firewall a second time
		 */
		if (ip_fw_fwd_addr)
			goto ours;
#endif	/* IPFIREWALL_FORWARD */
		i = (*ip_fw_chk_ptr)(&ip, hlen, NULL, &ip_divert_cookie,
					&m, &rule, &ip_fw_fwd_addr);
		/*
		 * see the comment in ip_output for the return values
		 * produced by the firewall.
		 */
		if (!m) /* packet discarded by firewall */
			return ;
		if (i == 0 && ip_fw_fwd_addr == NULL) /* common case */
			goto pass ;
#if DUMMYNET
                if (i & 0x10000) {
                        /* send packet to the appropriate pipe */
                        dummynet_io(i&0xffff,DN_TO_IP_IN,m,NULL,NULL,0, rule);
			return ;
		}
#endif
#if IPDIVERT
		if (i > 0 && i < 0x10000) {
			/* Divert packet */
			frag_divert_port = i & 0xffff ;
			goto ours;
		}
#endif
#if IPFIREWALL_FORWARD
		if (i == 0 && ip_fw_fwd_addr != NULL)
			goto pass ;
#endif
		/*
		 * if we get here, the packet must be dropped
		 */
			m_freem(m);
			return;
	}
pass:

        if (ip_nat_ptr && !(*ip_nat_ptr)(&ip, &m, m->m_pkthdr.rcvif, IP_NAT_IN)) {
#if IPFIREWALL_FORWARD
		ip_fw_fwd_addr = NULL;
#endif
		return;
	}
#endif	/* !COMPAT_IPFW */

#if defined(PM)
	/*
	 * Process ip-filter/NAT.
	 * Return TRUE  if this packed is discarded.
	 * Return FALSE if this packed is accepted.
	 */

	if (doNatFil && pm_in(m->m_pkthdr.rcvif, ip, m))
	    return;
#endif

#if defined(NATPT)
	/*
	 *
	 */
	if (ip6_protocol_tr)
	{
	    struct mbuf	*m1 = NULL;
	    
	    switch (natpt_in4(m, &m1))
	    {
	      case IPPROTO_IP:					goto dooptions;
	      case IPPROTO_IPV4:	ip_forward(m1, 0);	break;
	      case IPPROTO_IPV6:	ip6_forward(m1, 1);	break;
	      case IPPROTO_MAX:			/* discard this packet	*/
	      default:
	    }

	    if (m != m1)
		m_freem(m);

	    return;
	}
  dooptions:
#endif

	/*
	 * Process options and, if not destined for us,
	 * ship it on.  ip_dooptions returns 1 when an
	 * error was detected (causing an icmp message
	 * to be sent and the original packet to be freed).
	 */
	ip_nhops = 0;		/* for source routed packets */
	if (hlen > sizeof (struct ip) && ip_dooptions(m)) {
#if IPFIREWALL_FORWARD
		ip_fw_fwd_addr = NULL;
#endif
		return;
	}

        /* greedy RSVP, snatches any PATH packet of the RSVP protocol and no
         * matter if it is destined to another node, or whether it is 
         * a multicast one, RSVP wants it! and prevents it from being forwarded
         * anywhere else. Also checks if the rsvp daemon is running before
	 * grabbing the packet.
         */
	if (rsvp_on && ip->ip_p==IPPROTO_RSVP) 
		goto ours;

	/*
	 * Check our list of addresses, to see if the packet is for us.
	 */
	for (ia = TAILQ_FIRST(&in_ifaddrhead); ia;
					ia = TAILQ_NEXT(ia, ia_link)) {
#define	satosin(sa)	((struct sockaddr_in *)(sa))

		if (IA_SIN(ia)->sin_addr.s_addr == ip->ip_dst.s_addr)
			goto ours;

		if (IA_SIN(ia)->sin_addr.s_addr == INADDR_ANY)
			goto ours;

#if IPFIREWALL_FORWARD
		/*
		 * If the addr to forward to is one of ours, we pretend to
		 * be the destination for this packet.
		 */
		if (ip_fw_fwd_addr == NULL) {
			if (IA_SIN(ia)->sin_addr.s_addr == ip->ip_dst.s_addr)
				goto ours;
		} else if (IA_SIN(ia)->sin_addr.s_addr ==
					 ip_fw_fwd_addr->sin_addr.s_addr)
			goto ours;
#else
		if (IA_SIN(ia)->sin_addr.s_addr == ip->ip_dst.s_addr)
			goto ours;
#endif
		if (ia->ia_ifp && ia->ia_ifp->if_flags & IFF_BROADCAST) {
			if (satosin(&ia->ia_broadaddr)->sin_addr.s_addr ==
			    ip->ip_dst.s_addr)
				goto ours;
			if (ip->ip_dst.s_addr == ia->ia_netbroadcast.s_addr)
				goto ours;
		}
	}
	if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr))) {
		struct in_multi *inm;
		if (ip_mrouter) {
			/*
			 * If we are acting as a multicast router, all
			 * incoming multicast packets are passed to the
			 * kernel-level multicast forwarding function.
			 * The packet is returned (relatively) intact; if
			 * ip_mforward() returns a non-zero value, the packet
			 * must be discarded, else it may be accepted below.
			 *
			 * (The IP ident field is put in the same byte order
			 * as expected when ip_mforward() is called from
			 * ip_output().)
			 */
			ip->ip_id = htons(ip->ip_id);
			if (ip_mforward(ip, m->m_pkthdr.rcvif, m, 0) != 0) {
				ipstat.ips_cantforward++;
				m_freem(m);
				return;
			}
			ip->ip_id = ntohs(ip->ip_id);

			/*
			 * The process-level routing demon needs to receive
			 * all multicast IGMP packets, whether or not this
			 * host belongs to their destination groups.
			 */
			if (ip->ip_p == IPPROTO_IGMP)
				goto ours;
			ipstat.ips_forward++;
		}
		/*
		 * See if we belong to the destination multicast group on the
		 * arrival interface.
		 */
		IN_LOOKUP_MULTI(ip->ip_dst, m->m_pkthdr.rcvif, inm);
		if (inm == NULL) {
			ipstat.ips_notmember++;
			m_freem(m);
			return;
		}
		goto ours;
	}
	if (ip->ip_dst.s_addr == (u_long)INADDR_BROADCAST)
		goto ours;
	if (ip->ip_dst.s_addr == INADDR_ANY)
		goto ours;

#if defined(NFAITH) && NFAITH > 0
	/*
	 * FAITH(Firewall Aided Internet Translator)
	 */
	if (m->m_pkthdr.rcvif && m->m_pkthdr.rcvif->if_type == IFT_FAITH) {
		if (ip_keepfaith) {
			if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_ICMP) 
				goto ours;
		}
		m_freem(m);
		return;
	}
#endif
	/*
	 * Not for us; forward if possible and desirable.
	 */
	if (ipforwarding == 0) {
		ipstat.ips_cantforward++;
		m_freem(m);
	} else
		ip_forward(m, 0);
#if IPFIREWALL_FORWARD
	ip_fw_fwd_addr = NULL;
#endif
	return;

ours:

	/*
	 * If offset or IP_MF are set, must reassemble.
	 * Otherwise, nothing need be done.
	 * (We could look in the reassembly queue to see
	 * if the packet was previously fragmented,
	 * but it's not worth the time; just let them time out.)
	 */
	if (ip->ip_off & (IP_MF | IP_OFFMASK | IP_RF)) {
		if (m->m_flags & M_EXT) {		/* XXX */
			if ((m = m_pullup(m, hlen)) == 0) {
				ipstat.ips_toosmall++;
#if IPDIVERT
				frag_divert_port = 0;
				ip_divert_cookie = 0;
#endif
#if IPFIREWALL_FORWARD
				ip_fw_fwd_addr = NULL;
#endif
				return;
			}
			ip = mtod(m, struct ip *);
		}
		sum = IPREASS_HASH(ip->ip_src.s_addr, ip->ip_id);
		/*
		 * Look for queue of fragments
		 * of this datagram.
		 */
		for (fp = ipq[sum].next; fp != &ipq[sum]; fp = fp->next)
			if (ip->ip_id == fp->ipq_id &&
			    ip->ip_src.s_addr == fp->ipq_src.s_addr &&
			    ip->ip_dst.s_addr == fp->ipq_dst.s_addr &&
			    ip->ip_p == fp->ipq_p)
				goto found;

		fp = 0;

		/* check if there's a place for the new queue */
		if (nipq > maxnipq) {
		    /*
		     * drop something from the tail of the current queue
		     * before proceeding further
		     */
		    if (ipq[sum].prev == &ipq[sum]) {   /* gak */
			for (i = 0; i < IPREASS_NHASH; i++) {
			    if (ipq[i].prev != &ipq[i]) {
				ip_freef(ipq[i].prev);
				break;
			    }
			}
		    } else
			ip_freef(ipq[sum].prev);
		}
found:
		/*
		 * Adjust ip_len to not reflect header,
		 * set ip_mff if more fragments are expected,
		 * convert offset of this to bytes.
		 */
		ip->ip_len -= hlen;
		mff = (ip->ip_off & IP_MF) != 0;
		if (mff) {
		        /*
		         * Make sure that fragments have a data length
			 * that's a non-zero multiple of 8 bytes.
		         */
			if (ip->ip_len == 0 || (ip->ip_len & 0x7) != 0) {
				ipstat.ips_toosmall++; /* XXX */
				goto bad;
			}
			m->m_flags |= M_FRAG;
		}
		ip->ip_off <<= 3;

		/*
		 * If datagram marked as having more fragments
		 * or if this is not the first fragment,
		 * attempt reassembly; if it succeeds, proceed.
		 */
		if (mff || ip->ip_off) {
			ipstat.ips_fragments++;
			m->m_pkthdr.header = ip;
			ip = ip_reass(m, fp, &ipq[sum]);
			if (ip == 0) {
#if	IPFIREWALL_FORWARD
				ip_fw_fwd_addr = NULL;
#endif
				return;
			}
			/* Get the length of the reassembled packets header */
			hlen = IP_VHL_HL(ip->ip_vhl) << 2;
			ipstat.ips_reassembled++;
			m = dtom(ip);
#if IPDIVERT
			if (frag_divert_port) {
				struct mbuf m;
				m.m_next = 0;
				m.m_len = hlen;
				m.m_data = (char *) ip;
				ip->ip_len += hlen;
				HTONS(ip->ip_len);
				HTONS(ip->ip_off);
				HTONS(ip->ip_id);
				ip->ip_sum = 0;
				ip->ip_sum = in_cksum(&m, hlen);
				NTOHS(ip->ip_id);
				NTOHS(ip->ip_off);
				NTOHS(ip->ip_len);
				ip->ip_len -= hlen;
			}
#endif
		} else
			if (fp)
				ip_freef(fp);
	} else
		ip->ip_len -= hlen;

#if IPDIVERT
	/*
	 * Divert reassembled packets to the divert protocol if required
	 *  If divert port is null then cookie should be too,
	 * so we shouldn't need to clear them here. Assume ip_divert does so.
	 */
	if (frag_divert_port) {
		ipstat.ips_delivered++;
		ip_divert_port = frag_divert_port;
		frag_divert_port = 0;
		(*ip_protox[IPPROTO_DIVERT]->pr_input)(m, hlen);
		return;
	}

	/* Don't let packets divert themselves */
	if (ip->ip_p == IPPROTO_DIVERT) {
		ipstat.ips_noproto++;
		goto bad;
	}

#endif

	/*
	 * Switch out to protocol's input routine.
	 */
	ipstat.ips_delivered++;

	KERNEL_DEBUG(DBG_LAYER_END, ip->ip_dst.s_addr, 
		     ip->ip_src.s_addr, ip->ip_p, ip->ip_off, ip->ip_len);

	(*ip_protox[ip->ip_p]->pr_input)(m, hlen);
#if	IPFIREWALL_FORWARD
	ip_fw_fwd_addr = NULL;	/* tcp needed it */
#endif
	return;
bad:
#if	IPFIREWALL_FORWARD
	ip_fw_fwd_addr = NULL;
#endif
	KERNEL_DEBUG(DBG_LAYER_END, 0,0,0,0,0);
	m_freem(m);
}

/*
 * IP software interrupt routine - to go away sometime soon
 */
void
ipintr(void)
{
	int s;
	struct mbuf *m;

	KERNEL_DEBUG(DBG_FNC_IP_INPUT | DBG_FUNC_START, 0,0,0,0,0);

	while(1) {
		s = splimp();
		IF_DEQUEUE(&ipintrq, m);
		splx(s);
		if (m == 0) {
		  KERNEL_DEBUG(DBG_FNC_IP_INPUT | DBG_FUNC_END, 0,0,0,0,0);
		  return;
		}

		ip_input(m);
	}
}

NETISR_SET(NETISR_IP, ipintr);
  
/*
 * Take incoming datagram fragment and try to
 * reassemble it into whole datagram.  If a chain for
 * reassembly of this datagram already exists, then it
 * is given as fp; otherwise have to make a chain.
 */
static struct ip *
ip_reass(m, fp, where)
	register struct mbuf *m;
	register struct ipq *fp;
	struct   ipq    *where;
{
	struct ip *ip = mtod(m, struct ip *);
	register struct mbuf *p = 0, *q, *nq;
	struct mbuf *t;
	int hlen = IP_VHL_HL(ip->ip_vhl) << 2;
	int i, next;

	/*
	 * Presence of header sizes in mbufs
	 * would confuse code below.
	 */
	m->m_data += hlen;
	m->m_len -= hlen;

	/*
	 * If first fragment to arrive, create a reassembly queue.
	 */
	if (fp == 0) {
		if ((t = m_get(M_DONTWAIT, MT_FTABLE)) == NULL)
			goto dropfrag;
		fp = mtod(t, struct ipq *);
		insque((void *) fp, (void *) where);
		nipq++;
		fp->ipq_ttl = IPFRAGTTL;
		fp->ipq_p = ip->ip_p;
		fp->ipq_id = ip->ip_id;
		fp->ipq_src = ip->ip_src;
		fp->ipq_dst = ip->ip_dst;
		fp->ipq_frags = m;
		m->m_nextpkt = NULL;
#if IPDIVERT
		fp->ipq_divert = 0;
		fp->ipq_div_cookie = 0;
#endif
		goto inserted;
	}

#define GETIP(m)	((struct ip*)((m)->m_pkthdr.header))

	/*
	 * Find a segment which begins after this one does.
	 */
	for (p = NULL, q = fp->ipq_frags; q; p = q, q = q->m_nextpkt)
		if (GETIP(q)->ip_off > ip->ip_off)
			break;

	/*
	 * If there is a preceding segment, it may provide some of
	 * our data already.  If so, drop the data from the incoming
	 * segment.  If it provides all of our data, drop us, otherwise
	 * stick new segment in the proper place.
	 */
	if (p) {
		i = GETIP(p)->ip_off + GETIP(p)->ip_len - ip->ip_off;
		if (i > 0) {
			if (i >= ip->ip_len)
				goto dropfrag;
			m_adj(dtom(ip), i);
			ip->ip_off += i;
			ip->ip_len -= i;
		}
		m->m_nextpkt = p->m_nextpkt;
		p->m_nextpkt = m;
	} else {
		m->m_nextpkt = fp->ipq_frags;
		fp->ipq_frags = m;
	}

	/*
	 * While we overlap succeeding segments trim them or,
	 * if they are completely covered, dequeue them.
	 */
	for (; q != NULL && ip->ip_off + ip->ip_len > GETIP(q)->ip_off;
	     q = nq) {
		i = (ip->ip_off + ip->ip_len) -
		    GETIP(q)->ip_off;
		if (i < GETIP(q)->ip_len) {
			GETIP(q)->ip_len -= i;
			GETIP(q)->ip_off += i;
			m_adj(q, i);
			break;
		}
		nq = q->m_nextpkt;
		m->m_nextpkt = nq;
		m_freem(q);
	}

inserted:

#if IPDIVERT
	/*
	 * Any fragment diverting causes the whole packet to divert
	 */
	if (frag_divert_port) {
		fp->ipq_divert = frag_divert_port;
		fp->ipq_div_cookie = ip_divert_cookie;
	}
	frag_divert_port = 0;
	ip_divert_cookie = 0;
#endif

	/*
	 * Check for complete reassembly.
	 */
	next = 0;
	for (p = NULL, q = fp->ipq_frags; q; p = q, q = q->m_nextpkt) {
		if (GETIP(q)->ip_off != next)
			return (0);
		next += GETIP(q)->ip_len;
	}
	/* Make sure the last packet didn't have the IP_MF flag */
	if (p->m_flags & M_FRAG)
		return (0);

	/*
	 * Reassembly is complete.  Make sure the packet is a sane size.
	 */
	q = fp->ipq_frags;
	ip = GETIP(q);
	if (next + (IP_VHL_HL(ip->ip_vhl) << 2) > IP_MAXPACKET) {
		ipstat.ips_toolong++;
		ip_freef(fp);
		return (0);
	}

	/*
	 * Concatenate fragments.
	 */
	m = q;
	t = m->m_next;
	m->m_next = 0;
	m_cat(m, t);
	nq = q->m_nextpkt;
	q->m_nextpkt = 0;
	for (q = nq; q != NULL; q = nq) {
		nq = q->m_nextpkt;
		q->m_nextpkt = NULL;
		m_cat(m, q);
	}

#if IPDIVERT
	/*
	 * extract divert port for packet, if any
	 */
	frag_divert_port = fp->ipq_divert;
	ip_divert_cookie = fp->ipq_div_cookie;
#endif

	/*
	 * Create header for new ip packet by
	 * modifying header of first packet;
	 * dequeue and discard fragment reassembly header.
	 * Make header visible.
	 */
	ip->ip_len = next;
	ip->ip_src = fp->ipq_src;
	ip->ip_dst = fp->ipq_dst;
	remque((void *) fp);
	nipq--;
	(void) m_free(dtom(fp));
	m->m_len += (IP_VHL_HL(ip->ip_vhl) << 2);
	m->m_data -= (IP_VHL_HL(ip->ip_vhl) << 2);
	/* some debugging cruft by sklower, below, will go away soon */
	if (m->m_flags & M_PKTHDR) { /* XXX this should be done elsewhere */
		register int plen = 0;
		for (t = m; m; m = m->m_next)
			plen += m->m_len;
		t->m_pkthdr.len = plen;
	}
	return (ip);

dropfrag:
#if IPDIVERT
	frag_divert_port = 0;
	ip_divert_cookie = 0;
#endif
	ipstat.ips_fragdropped++;
	m_freem(m);
	return (0);

#undef GETIP
}

/*
 * Free a fragment reassembly header and all
 * associated datagrams.
 */
static void
ip_freef(fp)
	struct ipq *fp;
{
	register struct mbuf *q;

	while (fp->ipq_frags) {
		q = fp->ipq_frags;
		fp->ipq_frags = q->m_nextpkt;
		m_freem(q);
	}
	remque((void *) fp);
	(void) m_free(dtom(fp));
	nipq--;
}

/*
 * IP timer processing;
 * if a timer expires on a reassembly
 * queue, discard it.
 */
void
ip_slowtimo()
{
	register struct ipq *fp;
	int s = splnet();
	int i;

	for (i = 0; i < IPREASS_NHASH; i++) {
		fp = ipq[i].next;
		if (fp == 0)
			continue;
		while (fp != &ipq[i]) {
			--fp->ipq_ttl;
			fp = fp->next;
			if (fp->prev->ipq_ttl == 0) {
				ipstat.ips_fragtimeout++;
				ip_freef(fp->prev);
			}
		}
	}
	ipflow_slowtimo();
	splx(s);
}

/*
 * Drain off all datagram fragments.
 */
void
ip_drain()
{
	int     i;

	for (i = 0; i < IPREASS_NHASH; i++) {
		while (ipq[i].next != &ipq[i]) {
			ipstat.ips_fragdropped++;
			ip_freef(ipq[i].next);
		}
	}
	in_rtqdrain();
}

/*
 * Do option processing on a datagram,
 * possibly discarding it if bad options are encountered,
 * or forwarding it if source-routed.
 * Returns 1 if packet has been forwarded/freed,
 * 0 if the packet should be processed further.
 */
static int
ip_dooptions(m)
	struct mbuf *m;
{
	register struct ip *ip = mtod(m, struct ip *);
	register u_char *cp;
	register struct ip_timestamp *ipt;
	register struct in_ifaddr *ia;
	int opt, optlen, cnt, off, code, type = ICMP_PARAMPROB, forward = 0;
	struct in_addr *sin, dst;
	n_time ntime;

	dst = ip->ip_dst;
	cp = (u_char *)(ip + 1);
	cnt = (IP_VHL_HL(ip->ip_vhl) << 2) - sizeof (struct ip);
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[IPOPT_OPTVAL];
		if (opt == IPOPT_EOL)
			break;
		if (opt == IPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < IPOPT_OLEN + sizeof(*cp)) {
			        code = &cp[IPOPT_OLEN] - (u_char *)ip;
				goto bad;
			}
			optlen = cp[IPOPT_OLEN];
			if (optlen < IPOPT_OLEN + sizeof(*cp) || optlen > cnt) {
				code = &cp[IPOPT_OLEN] - (u_char *)ip;
				goto bad;
			}
		}
		switch (opt) {

		default:
			break;

		/*
		 * Source routing with record.
		 * Find interface with current destination address.
		 * If none on this machine then drop if strictly routed,
		 * or do nothing if loosely routed.
		 * Record interface address and bring up next address
		 * component.  If strictly routed make sure next
		 * address is on directly accessible net.
		 */
		case IPOPT_LSRR:
		case IPOPT_SSRR:
			if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
				code = &cp[IPOPT_OFFSET] - (u_char *)ip;
				goto bad;
			}
			ipaddr.sin_addr = ip->ip_dst;
			ia = (struct in_ifaddr *)
				ifa_ifwithaddr((struct sockaddr *)&ipaddr);
			if (ia == 0) {
				if (opt == IPOPT_SSRR) {
					type = ICMP_UNREACH;
					code = ICMP_UNREACH_SRCFAIL;
					goto bad;
				}
				if (!ip_dosourceroute)
					goto nosourcerouting;
				/*
				 * Loose routing, and not at next destination
				 * yet; nothing to do except forward.
				 */
				break;
			}
			off--;			/* 0 origin */
			if (off > optlen - sizeof(struct in_addr)) {
				/*
				 * End of source route.  Should be for us.
				 */
				if (!ip_acceptsourceroute)
					goto nosourcerouting;
				save_rte(cp, ip->ip_src);
				break;
			}

			if (!ip_dosourceroute) {
				if (ipforwarding) {
					char buf[16]; /* aaa.bbb.ccc.ddd\0 */
					/*
					 * Acting as a router, so generate ICMP
					 */
nosourcerouting:
					strcpy(buf, inet_ntoa(ip->ip_dst));
					log(LOG_WARNING, 
					    "attempted source route from %s to %s\n",
					    inet_ntoa(ip->ip_src), buf);
					type = ICMP_UNREACH;
					code = ICMP_UNREACH_SRCFAIL;
					goto bad;
				} else {
					/*
					 * Not acting as a router, so silently drop.
					 */
					ipstat.ips_cantforward++;
					m_freem(m);
					return (1);
				}
			}

			/*
			 * locate outgoing interface
			 */
			(void)memcpy(&ipaddr.sin_addr, cp + off,
			    sizeof(ipaddr.sin_addr));

			if (opt == IPOPT_SSRR) {
#define	INA	struct in_ifaddr *
#define	SA	struct sockaddr *
			    if ((ia = (INA)ifa_ifwithdstaddr((SA)&ipaddr)) == 0)
				ia = (INA)ifa_ifwithnet((SA)&ipaddr);
			} else
				ia = ip_rtaddr(ipaddr.sin_addr);
			if (ia == 0) {
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_SRCFAIL;
				goto bad;
			}
			ip->ip_dst = ipaddr.sin_addr;
			(void)memcpy(cp + off, &(IA_SIN(ia)->sin_addr),
			    sizeof(struct in_addr));
			cp[IPOPT_OFFSET] += sizeof(struct in_addr);
			/*
			 * Let ip_intr's mcast routing check handle mcast pkts
			 */
			forward = !IN_MULTICAST(ntohl(ip->ip_dst.s_addr));
			break;

		case IPOPT_RR:
			if (optlen < IPOPT_OFFSET + sizeof(*cp)) {
				code = &cp[IPOPT_OFFSET] - (u_char *)ip;
				goto bad;
			}
			if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
				code = &cp[IPOPT_OFFSET] - (u_char *)ip;
				goto bad;
			}
			/*
			 * If no space remains, ignore.
			 */
			off--;			/* 0 origin */
			if (off > optlen - sizeof(struct in_addr))
				break;
			(void)memcpy(&ipaddr.sin_addr, &ip->ip_dst,
			    sizeof(ipaddr.sin_addr));
			/*
			 * locate outgoing interface; if we're the destination,
			 * use the incoming interface (should be same).
			 */
			if ((ia = (INA)ifa_ifwithaddr((SA)&ipaddr)) == 0 &&
			    (ia = ip_rtaddr(ipaddr.sin_addr)) == 0) {
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_HOST;
				goto bad;
			}
			(void)memcpy(cp + off, &(IA_SIN(ia)->sin_addr),
			    sizeof(struct in_addr));
			cp[IPOPT_OFFSET] += sizeof(struct in_addr);
			break;

		case IPOPT_TS:
			code = cp - (u_char *)ip;
			ipt = (struct ip_timestamp *)cp;
			if (ipt->ipt_len < 5)
				goto bad;
			if (ipt->ipt_ptr > ipt->ipt_len - sizeof(int32_t)) {
				if (++ipt->ipt_oflw == 0)
					goto bad;
				break;
			}
			sin = (struct in_addr *)(cp + ipt->ipt_ptr - 1);
			switch (ipt->ipt_flg) {

			case IPOPT_TS_TSONLY:
				break;

			case IPOPT_TS_TSANDADDR:
				if (ipt->ipt_ptr - 1 + sizeof(n_time) +
				    sizeof(struct in_addr) > ipt->ipt_len)
					goto bad;
				ipaddr.sin_addr = dst;
				ia = (INA)ifaof_ifpforaddr((SA)&ipaddr,
							    m->m_pkthdr.rcvif);
				if (ia == 0)
					continue;
				(void)memcpy(sin, &IA_SIN(ia)->sin_addr,
				    sizeof(struct in_addr));
				ipt->ipt_ptr += sizeof(struct in_addr);
				break;

			case IPOPT_TS_PRESPEC:
				if (ipt->ipt_ptr - 1 + sizeof(n_time) +
				    sizeof(struct in_addr) > ipt->ipt_len)
					goto bad;
				(void)memcpy(&ipaddr.sin_addr, sin,
				    sizeof(struct in_addr));
				if (ifa_ifwithaddr((SA)&ipaddr) == 0)
					continue;
				ipt->ipt_ptr += sizeof(struct in_addr);
				break;

			default:
				goto bad;
			}
			ntime = iptime();
			(void)memcpy(cp + ipt->ipt_ptr - 1, &ntime,
			    sizeof(n_time));
			ipt->ipt_ptr += sizeof(n_time);
		}
	}
	if (forward && ipforwarding) {
		ip_forward(m, 1);
		return (1);
	}
	return (0);
bad:
	ip->ip_len -= IP_VHL_HL(ip->ip_vhl) << 2;   /* XXX icmp_error adds in hdr length */
	icmp_error(m, type, code, 0, 0);
	ipstat.ips_badoptions++;
	return (1);
}

/*
 * Given address of next destination (final or next hop),
 * return internet address info of interface to be used to get there.
 */
static struct in_ifaddr *
ip_rtaddr(dst)
	 struct in_addr dst;
{
	register struct sockaddr_in *sin;

	sin = (struct sockaddr_in *) &ipforward_rt.ro_dst;

	if (ipforward_rt.ro_rt == 0 || dst.s_addr != sin->sin_addr.s_addr) {
		if (ipforward_rt.ro_rt) {
			RTFREE(ipforward_rt.ro_rt);
			ipforward_rt.ro_rt = 0;
		}
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		sin->sin_addr = dst;

		rtalloc_ign(&ipforward_rt, RTF_PRCLONING);
	}
	if (ipforward_rt.ro_rt == 0)
		return ((struct in_ifaddr *)0);
	return ((struct in_ifaddr *) ipforward_rt.ro_rt->rt_ifa);
}

/*
 * Save incoming source route for use in replies,
 * to be picked up later by ip_srcroute if the receiver is interested.
 */
void
save_rte(option, dst)
	u_char *option;
	struct in_addr dst;
{
	unsigned olen;

	olen = option[IPOPT_OLEN];
#if DIAGNOSTIC
	if (ipprintfs)
		printf("save_rte: olen %d\n", olen);
#endif
	if (olen > sizeof(ip_srcrt) - (1 + sizeof(dst)))
		return;
	bcopy(option, ip_srcrt.srcopt, olen);
	ip_nhops = (olen - IPOPT_OFFSET - 1) / sizeof(struct in_addr);
	ip_srcrt.dst = dst;
}

/*
 * Retrieve incoming source route for use in replies,
 * in the same form used by setsockopt.
 * The first hop is placed before the options, will be removed later.
 */
struct mbuf *
ip_srcroute()
{
	register struct in_addr *p, *q;
	register struct mbuf *m;

	if (ip_nhops == 0)
		return ((struct mbuf *)0);
	m = m_get(M_DONTWAIT, MT_HEADER);
	if (m == 0)
		return ((struct mbuf *)0);

#define OPTSIZ	(sizeof(ip_srcrt.nop) + sizeof(ip_srcrt.srcopt))

	/* length is (nhops+1)*sizeof(addr) + sizeof(nop + srcrt header) */
	m->m_len = ip_nhops * sizeof(struct in_addr) + sizeof(struct in_addr) +
	    OPTSIZ;
#if DIAGNOSTIC
	if (ipprintfs)
		printf("ip_srcroute: nhops %d mlen %d", ip_nhops, m->m_len);
#endif

	/*
	 * First save first hop for return route
	 */
	p = &ip_srcrt.route[ip_nhops - 1];
	*(mtod(m, struct in_addr *)) = *p--;
#if DIAGNOSTIC
	if (ipprintfs)
		printf(" hops %lx", (u_long)ntohl(mtod(m, struct in_addr *)->s_addr));
#endif

	/*
	 * Copy option fields and padding (nop) to mbuf.
	 */
	ip_srcrt.nop = IPOPT_NOP;
	ip_srcrt.srcopt[IPOPT_OFFSET] = IPOPT_MINOFF;
	(void)memcpy(mtod(m, caddr_t) + sizeof(struct in_addr),
	    &ip_srcrt.nop, OPTSIZ);
	q = (struct in_addr *)(mtod(m, caddr_t) +
	    sizeof(struct in_addr) + OPTSIZ);
#undef OPTSIZ
	/*
	 * Record return path as an IP source route,
	 * reversing the path (pointers are now aligned).
	 */
	while (p >= ip_srcrt.route) {
#if DIAGNOSTIC
		if (ipprintfs)
			printf(" %lx", (u_long)ntohl(q->s_addr));
#endif
		*q++ = *p--;
	}
	/*
	 * Last hop goes to final destination.
	 */
	*q = ip_srcrt.dst;
#if DIAGNOSTIC
	if (ipprintfs)
		printf(" %lx\n", (u_long)ntohl(q->s_addr));
#endif
	return (m);
}

/*
 * Strip out IP options, at higher
 * level protocol in the kernel.
 * Second argument is buffer to which options
 * will be moved, and return value is their length.
 * XXX should be deleted; last arg currently ignored.
 */
void
ip_stripoptions(m, mopt)
	register struct mbuf *m;
	struct mbuf *mopt;
{
	register int i;
	struct ip *ip = mtod(m, struct ip *);
	register caddr_t opts;
	int olen;

	olen = (IP_VHL_HL(ip->ip_vhl) << 2) - sizeof (struct ip);
	opts = (caddr_t)(ip + 1);
	i = m->m_len - (sizeof (struct ip) + olen);
	bcopy(opts + olen, opts, (unsigned)i);
	m->m_len -= olen;
	if (m->m_flags & M_PKTHDR)
		m->m_pkthdr.len -= olen;
	ip->ip_vhl = IP_MAKE_VHL(IPVERSION, sizeof(struct ip) >> 2);
}

u_char inetctlerrmap[PRC_NCMDS] = {
	0,		0,		0,		0,
	0,		EMSGSIZE,	EHOSTDOWN,	EHOSTUNREACH,
	EHOSTUNREACH,	EHOSTUNREACH,	ECONNREFUSED,	ECONNREFUSED,
	EMSGSIZE,	EHOSTUNREACH,	0,		0,
	0,		0,		0,		0,
	ENOPROTOOPT
};

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
 * The srcrt parameter indicates whether the packet is being forwarded
 * via a source route.
 */
#ifndef NATPT
static
#endif
void
ip_forward(m, srcrt)
	struct mbuf *m;
	int srcrt;
{
	register struct ip *ip = mtod(m, struct ip *);
	register struct sockaddr_in *sin;
	register struct rtentry *rt;
	int error, type = 0, code = 0;
	struct mbuf *mcopy;
	n_long dest;
	struct ifnet *destifp;
#if IPSEC
	struct ifnet dummyifp;
#endif

	dest = 0;
#if DIAGNOSTIC
	if (ipprintfs)
		printf("forward: src %lx dst %lx ttl %x\n",
		    (u_long)ip->ip_src.s_addr, (u_long)ip->ip_dst.s_addr,
		    ip->ip_ttl);
#endif


	if (m->m_flags & M_BCAST || in_canforward(ip->ip_dst) == 0) {
		ipstat.ips_cantforward++;
		m_freem(m);
		return;
	}
	HTONS(ip->ip_id);
	if (ip->ip_ttl <= IPTTLDEC) {
		icmp_error(m, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS, dest, 0);
		return;
	}
	ip->ip_ttl -= IPTTLDEC;

#if defined(PM)
	if (doRoute)
	{
	    struct  route   *ipfw_rt;

	    if ((ipfw_rt = pm_route(m)) != NULL)
	    {
		mcopy = m_copy(m, 0, imin((int)ip->ip_len, 64));
#if IPSEC
		ipsec_setsocket(m, NULL);
#endif /*IPSEC*/
		error = ip_output(m, (struct mbuf *)0, ipfw_rt,
				  IP_FORWARDING | IP_PROTOCOLROUTE , 0);
		goto    clearAway;
	    }

	}
#endif

	sin = (struct sockaddr_in *)&ipforward_rt.ro_dst;
	if ((rt = ipforward_rt.ro_rt) == 0 ||
	    ip->ip_dst.s_addr != sin->sin_addr.s_addr) {
		if (ipforward_rt.ro_rt) {
			RTFREE(ipforward_rt.ro_rt);
			ipforward_rt.ro_rt = 0;
		}
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof(*sin);
		sin->sin_addr = ip->ip_dst;

		rtalloc_ign(&ipforward_rt, RTF_PRCLONING);
		if (ipforward_rt.ro_rt == 0) {
			icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_HOST, dest, 0);
			return;
		}
		rt = ipforward_rt.ro_rt;
	}

	/*
	 * Save at most 64 bytes of the packet in case
	 * we need to generate an ICMP message to the src.
	 */
	mcopy = m_copy(m, 0, imin((int)ip->ip_len, 64));

	/*
	 * If forwarding packet using same interface that it came in on,
	 * perhaps should send a redirect to sender to shortcut a hop.
	 * Only send redirect if source is sending directly to us,
	 * and if packet was not source routed (or has any options).
	 * Also, don't send redirect if forwarding using a default route
	 * or a route modified by a redirect.
	 */
#define	satosin(sa)	((struct sockaddr_in *)(sa))
	if (rt->rt_ifp == m->m_pkthdr.rcvif &&
	    (rt->rt_flags & (RTF_DYNAMIC|RTF_MODIFIED)) == 0 &&
	    satosin(rt_key(rt))->sin_addr.s_addr != 0 &&
	    ipsendredirects && !srcrt) {
#define	RTA(rt)	((struct in_ifaddr *)(rt->rt_ifa))
		u_long src = ntohl(ip->ip_src.s_addr);

		if (RTA(rt) &&
		    (src & RTA(rt)->ia_subnetmask) == RTA(rt)->ia_subnet) {
		    if (rt->rt_flags & RTF_GATEWAY)
			dest = satosin(rt->rt_gateway)->sin_addr.s_addr;
		    else
			dest = ip->ip_dst.s_addr;
		    /* Router requirements says to only send host redirects */
		    type = ICMP_REDIRECT;
		    code = ICMP_REDIRECT_HOST;
#if DIAGNOSTIC
		    if (ipprintfs)
		        printf("redirect (%d) to %lx\n", code, (u_long)dest);
#endif
		}
	}

#if IPSEC
	ipsec_setsocket(m, NULL);
#endif /*IPSEC*/
	error = ip_output(m, (struct mbuf *)0, &ipforward_rt, 
			  IP_FORWARDING, 0);
#if defined(PM)
      clearAway:;
#endif
	if (error)
		ipstat.ips_cantforward++;
	else {
		ipstat.ips_forward++;
		if (type)
			ipstat.ips_redirectsent++;
		else {
			if (mcopy) {
				ipflow_create(&ipforward_rt, mcopy);
				m_freem(mcopy);
			}
			return;
		}
	}
	if (mcopy == NULL)
		return;
	destifp = NULL;

	switch (error) {

	case 0:				/* forwarded, but need redirect */
		/* type, code set above */
		break;

	case ENETUNREACH:		/* shouldn't happen, checked above */
	case EHOSTUNREACH:
	case ENETDOWN:
	case EHOSTDOWN:
	default:
		type = ICMP_UNREACH;
		code = ICMP_UNREACH_HOST;
		break;

	case EMSGSIZE:
		type = ICMP_UNREACH;
		code = ICMP_UNREACH_NEEDFRAG;
#ifndef IPSEC
		if (ipforward_rt.ro_rt)
			destifp = ipforward_rt.ro_rt->rt_ifp;
#else
		/*
		 * If the packet is routed over IPsec tunnel, tell the
		 * originator the tunnel MTU.
		 *	tunnel MTU = if MTU - sizeof(IP) - ESP/AH hdrsiz
		 * XXX quickhack!!!
		 */
		if (ipforward_rt.ro_rt) {
			struct secpolicy *sp = NULL;
			int ipsecerror;
			int ipsechdr;
			struct route *ro;

			sp = ipsec4_getpolicybyaddr(mcopy,
						IPSEC_DIR_OUTBOUND,
			                            IP_FORWARDING,
			                            &ipsecerror);

			if (sp == NULL)
				destifp = ipforward_rt.ro_rt->rt_ifp;
			else {
				/* count IPsec header size */
				ipsechdr = ipsec4_hdrsiz(mcopy,
							 IPSEC_DIR_OUTBOUND,
							 NULL);

				/*
				 * find the correct route for outer IPv4
				 * header, compute tunnel MTU.
				 *
				 * XXX BUG ALERT
				 * The "dummyifp" code relies upon the fact
				 * that icmp_error() touches only ifp->if_mtu.
				 */
				/*XXX*/
				destifp = NULL;
				if (sp->req != NULL
				 && sp->req->sav != NULL
				 && sp->req->sav->sah != NULL) {
					ro = &sp->req->sav->sah->sa_route;
					if (ro->ro_rt && ro->ro_rt->rt_ifp) {
						dummyifp.if_mtu =
						    ro->ro_rt->rt_ifp->if_mtu;
						dummyifp.if_mtu -= ipsechdr;
						destifp = &dummyifp;
					}
				}

				key_freesp(sp);
			}
		}
#endif /*IPSEC*/
		ipstat.ips_cantfrag++;
		break;

	case ENOBUFS:
		type = ICMP_SOURCEQUENCH;
		code = 0;
		break;
	}
	icmp_error(mcopy, type, code, dest, destifp);
}

void
ip_savecontrol(inp, mp, ip, m)
	register struct inpcb *inp;
	register struct mbuf **mp;
	register struct ip *ip;
	register struct mbuf *m;
{
	if (inp->inp_socket->so_options & SO_TIMESTAMP) {
		struct timeval tv;

		microtime(&tv);
		*mp = sbcreatecontrol((caddr_t) &tv, sizeof(tv),
			SCM_TIMESTAMP, SOL_SOCKET);
		if (*mp)
			mp = &(*mp)->m_next;
	}
	if (inp->inp_flags & INP_RECVDSTADDR) {
		*mp = sbcreatecontrol((caddr_t) &ip->ip_dst,
		    sizeof(struct in_addr), IP_RECVDSTADDR, IPPROTO_IP);
		if (*mp)
			mp = &(*mp)->m_next;
	}
#ifdef notyet
	/* XXX
	 * Moving these out of udp_input() made them even more broken
	 * than they already were.
	 */
	/* options were tossed already */
	if (inp->inp_flags & INP_RECVOPTS) {
		*mp = sbcreatecontrol((caddr_t) opts_deleted_above,
		    sizeof(struct in_addr), IP_RECVOPTS, IPPROTO_IP);
		if (*mp)
			mp = &(*mp)->m_next;
	}
	/* ip_srcroute doesn't do what we want here, need to fix */
	if (inp->inp_flags & INP_RECVRETOPTS) {
		*mp = sbcreatecontrol((caddr_t) ip_srcroute(),
		    sizeof(struct in_addr), IP_RECVRETOPTS, IPPROTO_IP);
		if (*mp)
			mp = &(*mp)->m_next;
	}
#endif
	if (inp->inp_flags & INP_RECVIF) {
		struct ifnet *ifp;
		struct sdlbuf {
			struct sockaddr_dl sdl;
			u_char	pad[32];
		} sdlbuf;
		struct sockaddr_dl *sdp;
		struct sockaddr_dl *sdl2 = &sdlbuf.sdl;

		if (((ifp = m->m_pkthdr.rcvif)) 
		&& ( ifp->if_index && (ifp->if_index <= if_index))) {
			sdp = (struct sockaddr_dl *)(ifnet_addrs
					[ifp->if_index - 1]->ifa_addr);
			/*
			 * Change our mind and don't try copy.
			 */
			if ((sdp->sdl_family != AF_LINK)
			|| (sdp->sdl_len > sizeof(sdlbuf))) {
				goto makedummy;
			}
			bcopy(sdp, sdl2, sdp->sdl_len);
		} else {
makedummy:	
			sdl2->sdl_len
				= offsetof(struct sockaddr_dl, sdl_data[0]);
			sdl2->sdl_family = AF_LINK;
			sdl2->sdl_index = 0;
			sdl2->sdl_nlen = sdl2->sdl_alen = sdl2->sdl_slen = 0;
		}
		*mp = sbcreatecontrol((caddr_t) sdl2, sdl2->sdl_len,
			IP_RECVIF, IPPROTO_IP);
		if (*mp)
			mp = &(*mp)->m_next;
	}
}

int
ip_rsvp_init(struct socket *so)
{
	if (so->so_type != SOCK_RAW ||
	    so->so_proto->pr_protocol != IPPROTO_RSVP)
	  return EOPNOTSUPP;

	if (ip_rsvpd != NULL)
	  return EADDRINUSE;

	ip_rsvpd = so;
	/*
	 * This may seem silly, but we need to be sure we don't over-increment
	 * the RSVP counter, in case something slips up.
	 */
	if (!ip_rsvp_on) {
		ip_rsvp_on = 1;
		rsvp_on++;
	}

	return 0;
}

int
ip_rsvp_done(void)
{
	ip_rsvpd = NULL;
	/*
	 * This may seem silly, but we need to be sure we don't over-decrement
	 * the RSVP counter, in case something slips up.
	 */
	if (ip_rsvp_on) {
		ip_rsvp_on = 0;
		rsvp_on--;
	}
	return 0;
}
