/*
 * Copyright (c) 2000-2011 Apple Inc. All rights reserved.
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
 * $FreeBSD: src/sys/netinet/ip_input.c,v 1.130.2.25 2001/08/29 21:41:37 jesper Exp $
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2007 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#define	_IP_VHL

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
#include <sys/mcache.h>
#include <mach/mach_time.h>

#include <machine/endian.h>

#include <kern/queue.h>
#include <kern/locks.h>

#include <pexpert/pexpert.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/kpi_protocol.h>
#include <net/ntstat.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/in_arp.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <sys/socketvar.h>

#include <netinet/ip_fw.h>
#include <netinet/ip_divert.h>

#include <netinet/kpi_ipfilter_var.h>

/* needed for AUTOCONFIGURING: */
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/bootp.h>
#include <mach/sdt.h>

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif

#include <sys/kdebug.h>
#include <libkern/OSAtomic.h>

#define DBG_LAYER_BEG		NETDBG_CODE(DBG_NETIP, 0)
#define DBG_LAYER_END		NETDBG_CODE(DBG_NETIP, 2)
#define DBG_FNC_IP_INPUT	NETDBG_CODE(DBG_NETIP, (2 << 8))


#if IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif

#include "faith.h"
#if defined(NFAITH) && NFAITH > 0
#include <net/if_types.h>
#endif

#if DUMMYNET
#include <netinet/ip_dummynet.h>
#endif

#if PF
#include <net/pfvar.h>
#endif /* PF */

#if IPSEC
extern int ipsec_bypass;
extern lck_mtx_t *sadb_mutex;

lck_grp_t         *sadb_stat_mutex_grp;
lck_grp_attr_t    *sadb_stat_mutex_grp_attr;
lck_attr_t        *sadb_stat_mutex_attr;
lck_mtx_t         *sadb_stat_mutex;

#endif

int rsvp_on = 0;
static int ip_rsvp_on;
struct socket *ip_rsvpd;

static int sysctl_ipforwarding SYSCTL_HANDLER_ARGS;

int	ipforwarding = 0;
SYSCTL_PROC(_net_inet_ip, IPCTL_FORWARDING, forwarding,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &ipforwarding, 0,
    sysctl_ipforwarding, "I", "Enable IP forwarding between interfaces");

static int	ipsendredirects = 1; /* XXX */
SYSCTL_INT(_net_inet_ip, IPCTL_SENDREDIRECTS, redirect, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ipsendredirects, 0, "Enable sending IP redirects");

int	ip_defttl = IPDEFTTL;
SYSCTL_INT(_net_inet_ip, IPCTL_DEFTTL, ttl, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ip_defttl, 0, "Maximum TTL on IP packets");

static int	ip_dosourceroute = 0;
SYSCTL_INT(_net_inet_ip, IPCTL_SOURCEROUTE, sourceroute, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ip_dosourceroute, 0, "Enable forwarding source routed IP packets");

static int	ip_acceptsourceroute = 0;
SYSCTL_INT(_net_inet_ip, IPCTL_ACCEPTSOURCEROUTE, accept_sourceroute, 
    CTLFLAG_RW | CTLFLAG_LOCKED, &ip_acceptsourceroute, 0, 
    "Enable accepting source routed IP packets");

static int	ip_keepfaith = 0;
SYSCTL_INT(_net_inet_ip, IPCTL_KEEPFAITH, keepfaith, CTLFLAG_RW | CTLFLAG_LOCKED,
	&ip_keepfaith,	0,
	"Enable packet capture for FAITH IPv4->IPv6 translater daemon");

static int	nipq = 0;	/* total # of reass queues */
static int	maxnipq;
SYSCTL_INT(_net_inet_ip, OID_AUTO, maxfragpackets, CTLFLAG_RW | CTLFLAG_LOCKED,
	&maxnipq, 0,
	"Maximum number of IPv4 fragment reassembly queue entries");

static int    maxfragsperpacket;
SYSCTL_INT(_net_inet_ip, OID_AUTO, maxfragsperpacket, CTLFLAG_RW | CTLFLAG_LOCKED,
	&maxfragsperpacket, 0,
	"Maximum number of IPv4 fragments allowed per packet");

static int    maxfrags;
SYSCTL_INT(_net_inet_ip, OID_AUTO, maxfrags, CTLFLAG_RW | CTLFLAG_LOCKED,
	&maxfrags, 0, "Maximum number of IPv4 fragments allowed");

static int    currentfrags = 0;

int	ip_doscopedroute = 1;
SYSCTL_INT(_net_inet_ip, OID_AUTO, scopedroute, CTLFLAG_RD | CTLFLAG_LOCKED,
     &ip_doscopedroute, 0, "Enable IPv4 scoped routing");

/*
 * XXX - Setting ip_checkinterface mostly implements the receive side of
 * the Strong ES model described in RFC 1122, but since the routing table
 * and transmit implementation do not implement the Strong ES model,
 * setting this to 1 results in an odd hybrid.
 *
 * XXX - ip_checkinterface currently must be disabled if you use ipnat
 * to translate the destination address to another local interface.
 *
 * XXX - ip_checkinterface must be disabled if you add IP aliases
 * to the loopback interface instead of the interface where the
 * packets for those addresses are received.
 */
static int	ip_checkinterface = 0;
SYSCTL_INT(_net_inet_ip, OID_AUTO, check_interface, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ip_checkinterface, 0, "Verify packet arrives on correct interface");


#if DIAGNOSTIC
static int	ipprintfs = 0;
#endif

extern int in_proto_count; 
extern	struct domain inetdomain;
extern	struct protosw inetsw[];
struct protosw *ip_protox[IPPROTO_MAX];
static int	ipqmaxlen = IFQ_MAXLEN;

static lck_grp_attr_t	*in_ifaddr_rwlock_grp_attr;
static lck_grp_t	*in_ifaddr_rwlock_grp;
static lck_attr_t	*in_ifaddr_rwlock_attr;
lck_rw_t		*in_ifaddr_rwlock;

/* Protected by in_ifaddr_rwlock */
struct in_ifaddrhead in_ifaddrhead;		/* first inet address */
struct in_ifaddrhashhead *in_ifaddrhashtbl;	/* inet addr hash table  */

#define	INADDR_NHASH	61
static u_int32_t inaddr_nhash;			/* hash table size */
static u_int32_t inaddr_hashp;			/* next largest prime */

struct	ifqueue ipintrq;
SYSCTL_INT(_net_inet_ip, IPCTL_INTRQMAXLEN, intr_queue_maxlen, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ipintrq.ifq_maxlen, 0, "Maximum size of the IP input queue");
SYSCTL_INT(_net_inet_ip, IPCTL_INTRQDROPS, intr_queue_drops, CTLFLAG_RD | CTLFLAG_LOCKED,
    &ipintrq.ifq_drops, 0, "Number of packets dropped from the IP input queue");

struct ipstat ipstat;
SYSCTL_STRUCT(_net_inet_ip, IPCTL_STATS, stats, CTLFLAG_RD | CTLFLAG_LOCKED,
    &ipstat, ipstat, "IP statistics (struct ipstat, netinet/ip_var.h)");

/* Packet reassembly stuff */
#define IPREASS_NHASH_LOG2      6
#define IPREASS_NHASH           (1 << IPREASS_NHASH_LOG2)
#define IPREASS_HMASK           (IPREASS_NHASH - 1)
#define IPREASS_HASH(x,y) \
	(((((x) & 0xF) | ((((x) >> 8) & 0xF) << 4)) ^ (y)) & IPREASS_HMASK)

static struct ipq ipq[IPREASS_NHASH];
static TAILQ_HEAD(ipq_list, ipq) ipq_list =
	TAILQ_HEAD_INITIALIZER(ipq_list);
const  int    ipintrq_present = 1;
lck_mtx_t		*ip_mutex;
lck_attr_t		*ip_mutex_attr;
lck_grp_t		*ip_mutex_grp;
lck_grp_attr_t		*ip_mutex_grp_attr;
lck_mtx_t 		*inet_domain_mutex;
extern lck_mtx_t 	*domain_proto_mtx;

#if IPCTL_DEFMTU
SYSCTL_INT(_net_inet_ip, IPCTL_DEFMTU, mtu, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ip_mtu, 0, "Default MTU");
#endif

#if IPSTEALTH
static int	ipstealth = 0;
SYSCTL_INT(_net_inet_ip, OID_AUTO, stealth, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ipstealth, 0, "");
#endif


/* Firewall hooks */
#if IPFIREWALL
ip_fw_chk_t *ip_fw_chk_ptr;
int fw_enable = 1;
int fw_bypass = 1;
int fw_one_pass = 0;

#if DUMMYNET
ip_dn_io_t *ip_dn_io_ptr;
#endif

int (*fr_checkp)(struct ip *, int, struct ifnet *, int, struct mbuf **) = NULL;
#endif /* IPFIREWALL */

SYSCTL_NODE(_net_inet_ip, OID_AUTO, linklocal, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "link local");

struct ip_linklocal_stat ip_linklocal_stat;
SYSCTL_STRUCT(_net_inet_ip_linklocal, OID_AUTO, stat, CTLFLAG_RD | CTLFLAG_LOCKED,
        &ip_linklocal_stat, ip_linklocal_stat,
        "Number of link local packets with TTL less than 255");

SYSCTL_NODE(_net_inet_ip_linklocal, OID_AUTO, in, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "link local input");

int ip_linklocal_in_allowbadttl = 1;
SYSCTL_INT(_net_inet_ip_linklocal_in, OID_AUTO, allowbadttl, CTLFLAG_RW | CTLFLAG_LOCKED,
        &ip_linklocal_in_allowbadttl, 0,
        "Allow incoming link local packets with TTL less than 255");


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

static void	in_ifaddrhashtbl_init(void);
static void	save_rte(u_char *, struct in_addr);
static int	ip_dooptions(struct mbuf *, int, struct sockaddr_in *);
static void	ip_forward(struct mbuf *, int, struct sockaddr_in *);
static void	ip_freef(struct ipq *);
#if IPDIVERT
#ifdef IPDIVERT_44
static struct	mbuf *ip_reass(struct mbuf *,
			struct ipq *, struct ipq *, u_int32_t *, u_int16_t *);
#else
static struct	mbuf *ip_reass(struct mbuf *,
			struct ipq *, struct ipq *, u_int16_t *, u_int16_t *);
#endif
#else
static struct	mbuf *ip_reass(struct mbuf *, struct ipq *, struct ipq *);
#endif
static void ip_fwd_route_copyout(struct ifnet *, struct route *);
static void ip_fwd_route_copyin(struct ifnet *, struct route *);
void	ipintr(void);
void	in_dinit(void);

#if RANDOM_IP_ID
extern u_short ip_id;

int	ip_use_randomid = 1;
SYSCTL_INT(_net_inet_ip, OID_AUTO, random_id, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ip_use_randomid, 0, "Randomize IP packets IDs");
#endif

#define	satosin(sa)	((struct sockaddr_in *)(sa))
#define	ifatoia(ifa)	((struct in_ifaddr *)(ifa))

/*
 * IP initialization: fill in IP protocol switch table.
 * All protocols not implemented in kernel go to raw IP protocol handler.
 */
void
ip_init(void)
{
	struct protosw *pr;
	int i;
	static int ip_initialized = 0;

	if (!ip_initialized)
	{
		PE_parse_boot_argn("net.inet.ip.scopedroute",
		    &ip_doscopedroute, sizeof (ip_doscopedroute));

		in_ifaddr_init();

		in_ifaddr_rwlock_grp_attr = lck_grp_attr_alloc_init();
		in_ifaddr_rwlock_grp = lck_grp_alloc_init("in_ifaddr_rwlock",
		    in_ifaddr_rwlock_grp_attr);
		in_ifaddr_rwlock_attr = lck_attr_alloc_init();
		in_ifaddr_rwlock = lck_rw_alloc_init(in_ifaddr_rwlock_grp,
		    in_ifaddr_rwlock_attr);

		TAILQ_INIT(&in_ifaddrhead);
		in_ifaddrhashtbl_init();

		ip_moptions_init();

		pr = pffindproto_locked(PF_INET, IPPROTO_RAW, SOCK_RAW);
		if (pr == 0)
			panic("ip_init");
		for (i = 0; i < IPPROTO_MAX; i++)
			ip_protox[i] = pr;
		for (pr = inetdomain.dom_protosw; pr; pr = pr->pr_next) {
			if (pr->pr_domain == NULL)
				continue;    /* If uninitialized, skip */
			if (pr->pr_domain->dom_family == PF_INET &&
			    pr->pr_protocol && pr->pr_protocol != IPPROTO_RAW)
				ip_protox[pr->pr_protocol] = pr;
		}
		for (i = 0; i < IPREASS_NHASH; i++)
		    ipq[i].next = ipq[i].prev = &ipq[i];

	maxnipq = nmbclusters / 32;
	maxfrags = maxnipq * 2;
	maxfragsperpacket = 128; /* enough for 64k in 512 byte fragments */

#if RANDOM_IP_ID
		{
			struct timeval timenow;
			getmicrotime(&timenow);
			ip_id = timenow.tv_sec & 0xffff;
		}
#endif
		ipintrq.ifq_maxlen = ipqmaxlen;

		ipf_init();

		ip_mutex_grp_attr  = lck_grp_attr_alloc_init();

		ip_mutex_grp = lck_grp_alloc_init("ip", ip_mutex_grp_attr);

		ip_mutex_attr = lck_attr_alloc_init();

		if ((ip_mutex = lck_mtx_alloc_init(ip_mutex_grp, ip_mutex_attr)) == NULL) {
			printf("ip_init: can't alloc ip_mutex\n");
			return;
		}

#if IPSEC
	
		sadb_stat_mutex_grp_attr = lck_grp_attr_alloc_init();
		sadb_stat_mutex_grp = lck_grp_alloc_init("sadb_stat", sadb_stat_mutex_grp_attr);
		sadb_stat_mutex_attr = lck_attr_alloc_init();

		if ((sadb_stat_mutex = lck_mtx_alloc_init(sadb_stat_mutex_grp, sadb_stat_mutex_attr)) == NULL) {
			printf("ip_init: can't alloc sadb_stat_mutex\n");
			return;
		}

#endif
		arp_init();

		ip_initialized = 1;
	}
}

/*
 * Initialize IPv4 source address hash table.
 */
static void
in_ifaddrhashtbl_init(void)
{
	int i, k, p;

	if (in_ifaddrhashtbl != NULL)
		return;

	PE_parse_boot_argn("inaddr_nhash", &inaddr_nhash, sizeof (inaddr_nhash));
	if (inaddr_nhash == 0)
		inaddr_nhash = INADDR_NHASH;

	MALLOC(in_ifaddrhashtbl, struct in_ifaddrhashhead *,
	    inaddr_nhash * sizeof (*in_ifaddrhashtbl),
	    M_IFADDR, M_WAITOK | M_ZERO);
	if (in_ifaddrhashtbl == NULL)
		panic("in_ifaddrhashtbl_init allocation failed");

	/*
	 * Generate the next largest prime greater than inaddr_nhash.
	 */
	k = (inaddr_nhash % 2 == 0) ? inaddr_nhash + 1 : inaddr_nhash + 2;
	for (;;) {
		p = 1;
		for (i = 3; i * i <= k; i += 2) {
			if (k % i == 0)
				p = 0;
		}
		if (p == 1)
			break;
		k += 2;
	}
	inaddr_hashp = k;
}

u_int32_t
inaddr_hashval(u_int32_t key)
{
	/*
	 * The hash index is the computed prime times the key modulo
	 * the hash size, as documented in "Introduction to Algorithms"
	 * (Cormen, Leiserson, Rivest).
	 */
	if (inaddr_nhash > 1)
		return ((key * inaddr_hashp) % inaddr_nhash);
	else
		return (0);
}

static void
ip_proto_input(
	protocol_family_t	__unused protocol,
	mbuf_t				packet_list)
{
	mbuf_t	packet;
	int how_many = 0 ;
	
	/* ip_input should handle a list of packets but does not yet */
	
	for (packet = packet_list; packet; packet = packet_list) {
		how_many++;
		packet_list = mbuf_nextpkt(packet);
		mbuf_setnextpkt(packet, NULL);
		ip_input(packet);
	}
}

/* Initialize the PF_INET domain, and add in the pre-defined protos */
void
in_dinit(void)
{
	int i;
	struct protosw *pr;
	struct domain *dp;
	static int inetdomain_initted = 0;

	if (!inetdomain_initted)
	{
		/* kprintf("Initing %d protosw entries\n", in_proto_count); */
		dp = &inetdomain;
		dp->dom_flags = DOM_REENTRANT;

		for (i=0, pr = &inetsw[0]; i<in_proto_count; i++, pr++)
			net_add_proto(pr, dp);
		inet_domain_mutex = dp->dom_mtx;
		inetdomain_initted = 1;
	
		lck_mtx_unlock(domain_proto_mtx);	
		proto_register_input(PF_INET, ip_proto_input, NULL, 1);
		lck_mtx_lock(domain_proto_mtx);	
	}
}

__private_extern__ void
ip_proto_dispatch_in(
					struct mbuf	*m,
					int			hlen,
					u_int8_t	proto,
					ipfilter_t	inject_ipfref)
{
	struct ipfilter *filter;
	int seen = (inject_ipfref == 0);
	int	changed_header = 0;
	struct ip *ip;
	void (*pr_input)(struct mbuf *, int len);

	if (!TAILQ_EMPTY(&ipv4_filters)) {	
		ipf_ref();
		TAILQ_FOREACH(filter, &ipv4_filters, ipf_link) {
			if (seen == 0) {
				if ((struct ipfilter *)inject_ipfref == filter)
					seen = 1;
			} else if (filter->ipf_filter.ipf_input) {
				errno_t result;
		
				if (changed_header == 0) {
					changed_header = 1;
					ip = mtod(m, struct ip *);
					ip->ip_len = htons(ip->ip_len + hlen);
					ip->ip_off = htons(ip->ip_off);
					ip->ip_sum = 0;
					ip->ip_sum = in_cksum(m, hlen);
				}
				result = filter->ipf_filter.ipf_input(
					filter->ipf_filter.cookie, (mbuf_t*)&m, hlen, proto);
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
	/*
	 * If there isn't a specific lock for the protocol
	 * we're about to call, use the generic lock for AF_INET.
	 * otherwise let the protocol deal with its own locking
	 */
	ip = mtod(m, struct ip *);

	if (changed_header) {
		ip->ip_len = ntohs(ip->ip_len) - hlen;
		ip->ip_off = ntohs(ip->ip_off);
	}

	if ((pr_input = ip_protox[ip->ip_p]->pr_input) == NULL) {
		m_freem(m);
	} else if (!(ip_protox[ip->ip_p]->pr_flags & PR_PROTOLOCK)) {
		lck_mtx_lock(inet_domain_mutex);
		pr_input(m, hlen);
		lck_mtx_unlock(inet_domain_mutex);
	} else {
		pr_input(m, hlen);
	}
}

/*
 * Ip input routine.  Checksum and byte swap header.  If fragmented
 * try to reassemble.  Process options.  Pass to next level.
 */
void
ip_input(struct mbuf *m)
{
	struct ip *ip;
	struct ipq *fp;
	struct in_ifaddr *ia = NULL;
	int    hlen, checkif;
	u_short sum;
	struct in_addr pkt_dst;
#if IPFIREWALL
	int i;
	u_int32_t div_info = 0;		/* packet divert/tee info */
	struct ip_fw_args args;
	struct m_tag	*tag;
#endif
	ipfilter_t inject_filter_ref = 0;

	/* Check if the mbuf is still valid after interface filter processing */
	MBUF_INPUT_CHECK(m, m->m_pkthdr.rcvif);

#if IPFIREWALL
	args.eh = NULL;
	args.oif = NULL;
	args.rule = NULL;
	args.divert_rule = 0;			/* divert cookie */
	args.next_hop = NULL;

	/*
	 * Don't bother searching for tag(s) if there's none.
	 */
	if (SLIST_EMPTY(&m->m_pkthdr.tags))
		goto ipfw_tags_done;

	/* Grab info from mtags prepended to the chain */
#if DUMMYNET
	if ((tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID,
	    KERNEL_TAG_TYPE_DUMMYNET, NULL)) != NULL) {
		struct dn_pkt_tag	*dn_tag;

		dn_tag = (struct dn_pkt_tag *)(tag+1);
		args.rule = dn_tag->rule;

		m_tag_delete(m, tag);
	}
#endif /* DUMMYNET */

#if IPDIVERT
	if ((tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID,
	    KERNEL_TAG_TYPE_DIVERT, NULL)) != NULL) {
		struct divert_tag	*div_tag;

		div_tag = (struct divert_tag *)(tag+1);
		args.divert_rule = div_tag->cookie;

		m_tag_delete(m, tag);
	}
#endif

	if ((tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID,
	    KERNEL_TAG_TYPE_IPFORWARD, NULL)) != NULL) {
		struct ip_fwd_tag	*ipfwd_tag;

		ipfwd_tag = (struct ip_fwd_tag *)(tag+1);
		args.next_hop = ipfwd_tag->next_hop;

		m_tag_delete(m, tag);
	}

#if	DIAGNOSTIC
	if (m == NULL || (m->m_flags & M_PKTHDR) == 0)
		panic("ip_input no HDR");
#endif

	if (args.rule) {	/* dummynet already filtered us */
		ip = mtod(m, struct ip *);
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;
		inject_filter_ref = ipf_get_inject_filter(m);
		goto iphack ;
	}
ipfw_tags_done:
#endif /* IPFIREWALL */

	/*
	 * No need to proccess packet twice if we've already seen it.
	 */
	if (!SLIST_EMPTY(&m->m_pkthdr.tags))
		inject_filter_ref = ipf_get_inject_filter(m);
	if (inject_filter_ref != 0) {
		ip = mtod(m, struct ip *);
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;

		DTRACE_IP6(receive, struct mbuf *, m, struct inpcb *, NULL, 
			struct ip *, ip, struct ifnet *, m->m_pkthdr.rcvif,
			struct ip *, ip, struct ip6_hdr *, NULL);
               
		ip->ip_len = ntohs(ip->ip_len) - hlen;
		ip->ip_off = ntohs(ip->ip_off);
		ip_proto_dispatch_in(m, hlen, ip->ip_p, inject_filter_ref);
		return;
	}

	OSAddAtomic(1, &ipstat.ips_total);

	if (m->m_pkthdr.len < sizeof(struct ip))
		goto tooshort;

	if (m->m_len < sizeof (struct ip) &&
	    (m = m_pullup(m, sizeof (struct ip))) == 0) {
		OSAddAtomic(1, &ipstat.ips_toosmall);
		return;
	}
	ip = mtod(m, struct ip *);

	KERNEL_DEBUG(DBG_LAYER_BEG, ip->ip_dst.s_addr, 
		     ip->ip_src.s_addr, ip->ip_p, ip->ip_off, ip->ip_len);

	if (IP_VHL_V(ip->ip_vhl) != IPVERSION) {
		OSAddAtomic(1, &ipstat.ips_badvers);
		goto bad;
	}

	hlen = IP_VHL_HL(ip->ip_vhl) << 2;
	if (hlen < sizeof(struct ip)) {	/* minimum header length */
		OSAddAtomic(1, &ipstat.ips_badhlen);
		goto bad;
	}
	if (hlen > m->m_len) {
		if ((m = m_pullup(m, hlen)) == 0) {
			OSAddAtomic(1, &ipstat.ips_badhlen);
			return;
		}
		ip = mtod(m, struct ip *);
	}

	/* 127/8 must not appear on wire - RFC1122 */
	if ((ntohl(ip->ip_dst.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET ||
	    (ntohl(ip->ip_src.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET) {
		if ((m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK) == 0) {
			OSAddAtomic(1, &ipstat.ips_badaddr);
			goto bad;
		}
	}

	/* IPv4 Link-Local Addresses as defined in <draft-ietf-zeroconf-ipv4-linklocal-05.txt> */
	if ((IN_LINKLOCAL(ntohl(ip->ip_dst.s_addr)) || 
	    IN_LINKLOCAL(ntohl(ip->ip_src.s_addr)))) {
		ip_linklocal_stat.iplls_in_total++;
		if (ip->ip_ttl != MAXTTL) {
			OSAddAtomic(1, &ip_linklocal_stat.iplls_in_badttl);
			/* Silently drop link local traffic with bad TTL */
			if (!ip_linklocal_in_allowbadttl)
				goto bad;
		}
	}
	if ((IF_HWASSIST_CSUM_FLAGS(m->m_pkthdr.rcvif->if_hwassist) == 0) 
	    || (apple_hwcksum_rx == 0) ||
	   ((m->m_pkthdr.csum_flags & CSUM_TCP_SUM16) && ip->ip_p != IPPROTO_TCP)) {
			m->m_pkthdr.csum_flags = 0; /* invalidate HW generated checksum flags */
	}

	if (m->m_pkthdr.csum_flags & CSUM_IP_CHECKED) {
		sum = !(m->m_pkthdr.csum_flags & CSUM_IP_VALID);
	} else if (!(m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK) ||
	    apple_hwcksum_tx == 0) {
		/*
		 * Either this is not loopback packet coming from an interface
		 * that does not support checksum offloading, or it is loopback
		 * packet that has undergone software checksumming at the send
		 * side because apple_hwcksum_tx was set to 0.  In this case,
		 * calculate the checksum in software to validate the packet.
		 */
		sum = in_cksum(m, hlen);
	} else {
		/*
		 * This is a loopback packet without any valid checksum since
		 * the send side has bypassed it (apple_hwcksum_tx set to 1).
		 * We get here because apple_hwcksum_rx was set to 0, and so
		 * we pretend that all is well.
		 */
		sum = 0;
		m->m_pkthdr.csum_flags |= CSUM_DATA_VALID | CSUM_PSEUDO_HDR |
		    CSUM_IP_CHECKED | CSUM_IP_VALID;
                m->m_pkthdr.csum_data = 0xffff;
	}
	if (sum) {
		OSAddAtomic(1, &ipstat.ips_badsum);
		goto bad;
	}

	DTRACE_IP6(receive, struct mbuf *, m, struct inpcb *, NULL, 
		struct ip *, ip, struct ifnet *, m->m_pkthdr.rcvif,
		struct ip *, ip, struct ip6_hdr *, NULL);

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
		struct rtentry *rt =
		    ifnet_cached_rtlookup_inet(m->m_pkthdr.rcvif, ip->ip_src);
		if (rt != NULL) {
			nstat_route_rx(rt, 1, m->m_pkthdr.len, 0);
			rtfree(rt);
		}
	}

	/*
	 * Convert fields to host representation.
	 */
#if BYTE_ORDER != BIG_ENDIAN
	NTOHS(ip->ip_len);
#endif
	
	if (ip->ip_len < hlen) {
		OSAddAtomic(1, &ipstat.ips_badlen);
		goto bad;
	}

#if BYTE_ORDER != BIG_ENDIAN
	NTOHS(ip->ip_off);
#endif
	/*
	 * Check that the amount of data in the buffers
	 * is as at least much as the IP header would have us expect.
	 * Trim mbufs if longer than we expect.
	 * Drop packet if shorter than we expect.
	 */
	if (m->m_pkthdr.len < ip->ip_len) {
tooshort:
		OSAddAtomic(1, &ipstat.ips_tooshort);
		goto bad;
	}
	if (m->m_pkthdr.len > ip->ip_len) {
		/* Invalidate hwcksuming */
		m->m_pkthdr.csum_flags = 0;
		m->m_pkthdr.csum_data = 0;

		if (m->m_len == m->m_pkthdr.len) {
			m->m_len = ip->ip_len;
			m->m_pkthdr.len = ip->ip_len;
		} else
			m_adj(m, ip->ip_len - m->m_pkthdr.len);
	}

#if PF
	/* Invoke inbound packet filter */
	if (PF_IS_ENABLED) { 
		int error;
		error = pf_af_hook(m->m_pkthdr.rcvif, NULL, &m, AF_INET, TRUE);
		if (error != 0) {
			if (m != NULL) {
				panic("%s: unexpected packet %p\n", __func__, m);
				/* NOTREACHED */
			}
			/* Already freed by callee */
			return;
		} 
		ip = mtod(m, struct ip *);
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;
	}
#endif /* PF */

#if IPSEC
	if (ipsec_bypass == 0 && ipsec_gethist(m, NULL))
		goto pass;
#endif

#if IPFIREWALL
#if DUMMYNET
iphack:
#endif /* DUMMYNET */
	/*
	 * Check if we want to allow this packet to be processed.
	 * Consider it to be bad if not.
	 */
	if (fr_checkp) {
		struct	mbuf	*m1 = m;

		if (fr_checkp(ip, hlen, m->m_pkthdr.rcvif, 0, &m1) || !m1) {
			return;
		}
		ip = mtod(m = m1, struct ip *);
	}
	if (fw_enable && IPFW_LOADED) {
#if IPFIREWALL_FORWARD
		/*
		 * If we've been forwarded from the output side, then
		 * skip the firewall a second time
		 */
		if (args.next_hop)
			goto ours;
#endif	/* IPFIREWALL_FORWARD */

		args.m = m;

		i = ip_fw_chk_ptr(&args);
		m = args.m;

		if ( (i & IP_FW_PORT_DENY_FLAG) || m == NULL) { /* drop */
			if (m)
				m_freem(m);
			return;
		}
		ip = mtod(m, struct ip *); /* just in case m changed */
		
		if (i == 0 && args.next_hop == NULL) {	/* common case */
			goto pass;
		}
#if DUMMYNET
                if (DUMMYNET_LOADED && (i & IP_FW_PORT_DYNT_FLAG) != 0) {
			/* Send packet to the appropriate pipe */
			ip_dn_io_ptr(m, i&0xffff, DN_TO_IP_IN, &args);
			return;
		}
#endif /* DUMMYNET */
#if IPDIVERT
		if (i != 0 && (i & IP_FW_PORT_DYNT_FLAG) == 0) {
			/* Divert or tee packet */
			div_info = i;
			goto ours;
		}
#endif
#if IPFIREWALL_FORWARD
		if (i == 0 && args.next_hop != NULL) {
			goto pass;
		}
#endif
		/*
		 * if we get here, the packet must be dropped
		 */
		m_freem(m);
		return;
	}
#endif /* IPFIREWALL */
pass:

	/*
	 * Process options and, if not destined for us,
	 * ship it on.  ip_dooptions returns 1 when an
	 * error was detected (causing an icmp message
	 * to be sent and the original packet to be freed).
	 */
	ip_nhops = 0;		/* for source routed packets */
#if IPFIREWALL
	if (hlen > sizeof (struct ip) && ip_dooptions(m, 0, args.next_hop)) {
#else
	if (hlen > sizeof (struct ip) && ip_dooptions(m, 0, NULL)) {
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
	 * If we don't have any addresses, assume any unicast packet
	 * we receive might be for us (and let the upper layers deal
	 * with it).
	 */
	if (TAILQ_EMPTY(&in_ifaddrhead) &&
	    (m->m_flags & (M_MCAST|M_BCAST)) == 0)
		goto ours;

	/*
	 * Cache the destination address of the packet; this may be
	 * changed by use of 'ipfw fwd'.
	 */
#if IPFIREWALL
	pkt_dst = args.next_hop == NULL ?
	    ip->ip_dst : args.next_hop->sin_addr;
#else
	pkt_dst = ip->ip_dst;
#endif

	/*
	 * Enable a consistency check between the destination address
	 * and the arrival interface for a unicast packet (the RFC 1122
	 * strong ES model) if IP forwarding is disabled and the packet
	 * is not locally generated and the packet is not subject to
	 * 'ipfw fwd'.
	 *
	 * XXX - Checking also should be disabled if the destination
	 * address is ipnat'ed to a different interface.
	 *
	 * XXX - Checking is incompatible with IP aliases added
	 * to the loopback interface instead of the interface where
	 * the packets are received.
	 */
	checkif = ip_checkinterface && (ipforwarding == 0) && 
	    ((m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK) == 0)
#if IPFIREWALL
	    && (args.next_hop == NULL);
#else
		;
#endif

	/*
	 * Check for exact addresses in the hash bucket.
	 */
	lck_rw_lock_shared(in_ifaddr_rwlock);
	TAILQ_FOREACH(ia, INADDR_HASH(pkt_dst.s_addr), ia_hash) {
		/*
		 * If the address matches, verify that the packet
		 * arrived via the correct interface if checking is
		 * enabled.
		 */
		IFA_LOCK_SPIN(&ia->ia_ifa);
		if (IA_SIN(ia)->sin_addr.s_addr == pkt_dst.s_addr && 
		    (!checkif || ia->ia_ifp == m->m_pkthdr.rcvif)) {
			IFA_UNLOCK(&ia->ia_ifa);
			lck_rw_done(in_ifaddr_rwlock);
			goto ours;
		}
		IFA_UNLOCK(&ia->ia_ifa);
	}
	lck_rw_done(in_ifaddr_rwlock);

	/*
	 * Check for broadcast addresses.
	 *
	 * Only accept broadcast packets that arrive via the matching
	 * interface.  Reception of forwarded directed broadcasts would be
	 * handled via ip_forward() and ether_frameout() with the loopback
	 * into the stack for SIMPLEX interfaces handled by ether_frameout().
	 */
	if (m->m_pkthdr.rcvif->if_flags & IFF_BROADCAST) {
		struct ifaddr *ifa;
		struct ifnet *ifp = m->m_pkthdr.rcvif;

		ifnet_lock_shared(ifp);
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			IFA_LOCK_SPIN(ifa);
			if (ifa->ifa_addr->sa_family != AF_INET) {
				IFA_UNLOCK(ifa);
				continue;
			}
			ia = ifatoia(ifa);
			if (satosin(&ia->ia_broadaddr)->sin_addr.s_addr ==
			    pkt_dst.s_addr || ia->ia_netbroadcast.s_addr ==
			    pkt_dst.s_addr) {
				IFA_UNLOCK(ifa);
				ifnet_lock_done(ifp);
				goto ours;
			}
			IFA_UNLOCK(ifa);
		}
		ifnet_lock_done(ifp);
	}

	if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr))) {
		struct in_multi *inm;
		struct ifnet *ifp = m->m_pkthdr.rcvif;
#if MROUTING
		if (ip_mrouter) {
			/*
			 * If we are acting as a multicast router, all
			 * incoming multicast packets are passed to the
			 * kernel-level multicast forwarding function.
			 * The packet is returned (relatively) intact; if
			 * ip_mforward() returns a non-zero value, the packet
			 * must be discarded, else it may be accepted below.
			 */
			lck_mtx_lock(ip_mutex);
			if (ip_mforward && ip_mforward(ip, ifp, m, 0) != 0) {
				OSAddAtomic(1, &ipstat.ips_cantforward);
				m_freem(m);
				lck_mtx_unlock(ip_mutex);
				return;
			}

			/*
			 * The process-level routing daemon needs to receive
			 * all multicast IGMP packets, whether or not this
			 * host belongs to their destination groups.
			 */
			if (ip->ip_p == IPPROTO_IGMP)
				goto ours;
			OSAddAtomic(1, &ipstat.ips_forward);
		}
#endif /* MROUTING */
		/*
		 * See if we belong to the destination multicast group on the
		 * arrival interface.
		 */
		in_multihead_lock_shared();
		IN_LOOKUP_MULTI(&ip->ip_dst, ifp, inm);
		in_multihead_lock_done();
		if (inm == NULL) {
			OSAddAtomic(1, &ipstat.ips_notmember);
			m_freem(m);
			return;
		}
		INM_REMREF(inm);
		goto ours;
	}
	if (ip->ip_dst.s_addr == (u_int32_t)INADDR_BROADCAST)
		goto ours;
	if (ip->ip_dst.s_addr == INADDR_ANY)
		goto ours;

	/* Allow DHCP/BootP responses through */
	if (m->m_pkthdr.rcvif != NULL
	    && (m->m_pkthdr.rcvif->if_eflags & IFEF_AUTOCONFIGURING)
	    && hlen == sizeof(struct ip)
	    && ip->ip_p == IPPROTO_UDP) {
		struct udpiphdr *ui;
		if (m->m_len < sizeof(struct udpiphdr)
		    && (m = m_pullup(m, sizeof(struct udpiphdr))) == 0) {
			OSAddAtomic(1, &udpstat.udps_hdrops);
			return;
		}
		ui = mtod(m, struct udpiphdr *);
		if (ntohs(ui->ui_dport) == IPPORT_BOOTPC) {
			goto ours;
		}
		ip = mtod(m, struct ip *); /* in case it changed */
	}

#if defined(NFAITH) && 0 < NFAITH
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
		OSAddAtomic(1, &ipstat.ips_cantforward);
		m_freem(m);
	} else {
#if IPFIREWALL
		ip_forward(m, 0, args.next_hop);
#else
		ip_forward(m, 0, NULL);
#endif
	}
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

		/* If maxnipq is 0, never accept fragments. */
		if (maxnipq == 0) {

			OSAddAtomic(1, &ipstat.ips_fragments);
			OSAddAtomic(1, &ipstat.ips_fragdropped);
			goto bad;
		}
		
		/*
		 * If we will exceed the number of fragments in queues, timeout the
		 * oldest fragemented packet to make space.
		 */
		lck_mtx_lock(ip_mutex); 
		if (currentfrags >= maxfrags) {
			fp = TAILQ_LAST(&ipq_list, ipq_list);
			OSAddAtomic(fp->ipq_nfrags, &ipstat.ips_fragtimeout);
			
			if (ip->ip_id == fp->ipq_id &&
				ip->ip_src.s_addr == fp->ipq_src.s_addr &&
				ip->ip_dst.s_addr == fp->ipq_dst.s_addr &&
				ip->ip_p == fp->ipq_p) {
				/*
				 * If we match the fragment queue we were going to
				 * discard, drop this packet too.
				 */
				OSAddAtomic(1, &ipstat.ips_fragdropped);
				ip_freef(fp);
				lck_mtx_unlock(ip_mutex); 
				goto bad;
			}
			
			ip_freef(fp);
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
#if CONFIG_MACF_NET
			    mac_ipq_label_compare(m, fp) &&
#endif
			    ip->ip_p == fp->ipq_p)
				goto found;

		/*
		 * Enforce upper bound on number of fragmented packets
		 * for which we attempt reassembly;
		 * If maxnipq is -1, accept all fragments without limitation.
		 */
		if ((nipq > maxnipq) && (maxnipq > 0)) {
		    /*
		     * drop the oldest fragment before proceeding further
		     */
		    fp = TAILQ_LAST(&ipq_list, ipq_list);
		    OSAddAtomic(fp->ipq_nfrags, &ipstat.ips_fragtimeout);
		    ip_freef(fp);
		}

		fp = NULL;

found:
		/*
		 * Adjust ip_len to not reflect header,
		 * convert offset of this to bytes.
		 */
		ip->ip_len -= hlen;
		if (ip->ip_off & IP_MF) {
		        /*
		         * Make sure that fragments have a data length
				 * that's a non-zero multiple of 8 bytes.
		         */
			if (ip->ip_len == 0 || (ip->ip_len & 0x7) != 0) {
				OSAddAtomic(1, &ipstat.ips_toosmall);
				lck_mtx_unlock(ip_mutex);
				goto bad;
			}
			m->m_flags |= M_FRAG;
		} else {
			/* Clear the flag in case packet comes from loopback */
			m->m_flags &= ~M_FRAG;
		}
		ip->ip_off <<= 3;

		/*
		 * Attempt reassembly; if it succeeds, proceed.
		 * ip_reass() will return a different mbuf, and update
		 * the divert info in div_info and args.divert_rule.
		 */
			OSAddAtomic(1, &ipstat.ips_fragments);
			m->m_pkthdr.header = ip;
#if IPDIVERT
			m = ip_reass(m, fp, &ipq[sum],
			    (u_int16_t *)&div_info, &args.divert_rule);
#else
			m = ip_reass(m, fp, &ipq[sum]);
#endif
			if (m == 0) {
				lck_mtx_unlock(ip_mutex);
				return;
			}
			OSAddAtomic(1, &ipstat.ips_reassembled);
			ip = mtod(m, struct ip *);
			/* Get the header length of the reassembled packet */
			hlen = IP_VHL_HL(ip->ip_vhl) << 2;

#if IPDIVERT
			/* Restore original checksum before diverting packet */
			if (div_info != 0) {
				ip->ip_len += hlen;

#if BYTE_ORDER != BIG_ENDIAN
				HTONS(ip->ip_len);
				HTONS(ip->ip_off);
#endif
				
				ip->ip_sum = 0;
				ip->ip_sum = in_cksum(m, hlen);

#if BYTE_ORDER != BIG_ENDIAN
				NTOHS(ip->ip_off);
				NTOHS(ip->ip_len);
#endif
				
				ip->ip_len -= hlen;
			}
#endif
		lck_mtx_unlock(ip_mutex);
		} else
		ip->ip_len -= hlen;

#if IPDIVERT
	/*
	 * Divert or tee packet to the divert protocol if required.
	 *
	 * If div_info is zero then cookie should be too, so we shouldn't
	 * need to clear them here.  Assume divert_packet() does so also.
	 */
	if (div_info != 0) {
		struct mbuf *clone = NULL;

		/* Clone packet if we're doing a 'tee' */
		if ((div_info & IP_FW_PORT_TEE_FLAG) != 0)
			clone = m_dup(m, M_DONTWAIT);

		/* Restore packet header fields to original values */
		ip->ip_len += hlen;

#if BYTE_ORDER != BIG_ENDIAN
		HTONS(ip->ip_len);
		HTONS(ip->ip_off);
#endif
		/* Deliver packet to divert input routine */
		OSAddAtomic(1, &ipstat.ips_delivered);
		divert_packet(m, 1, div_info & 0xffff, args.divert_rule);

		/* If 'tee', continue with original packet */
		if (clone == NULL) {
			return;
		}
		m = clone;
		ip = mtod(m, struct ip *);
	}
#endif

#if IPSEC
	/*
	 * enforce IPsec policy checking if we are seeing last header.
	 * note that we do not visit this with protocols with pcb layer
	 * code - like udp/tcp/raw ip.
	 */
	if (ipsec_bypass == 0 && (ip_protox[ip->ip_p]->pr_flags & PR_LASTHDR) != 0) {
		if (ipsec4_in_reject(m, NULL)) {
			IPSEC_STAT_INCREMENT(ipsecstat.in_polvio);
			goto bad;	
		}
	}
#endif

	/*
	 * Switch out to protocol's input routine.
	 */
	OSAddAtomic(1, &ipstat.ips_delivered);
	{
#if IPFIREWALL
		if (args.next_hop && ip->ip_p == IPPROTO_TCP) {
			/* TCP needs IPFORWARD info if available */
			struct m_tag *fwd_tag;
			struct ip_fwd_tag	*ipfwd_tag;
			
			fwd_tag = m_tag_create(KERNEL_MODULE_TAG_ID,
			    KERNEL_TAG_TYPE_IPFORWARD, sizeof (*ipfwd_tag),
			    M_NOWAIT, m);
			if (fwd_tag == NULL) {
				goto bad;
			}
			
			ipfwd_tag = (struct ip_fwd_tag *)(fwd_tag+1);
			ipfwd_tag->next_hop = args.next_hop;

			m_tag_prepend(m, fwd_tag);
	
			KERNEL_DEBUG(DBG_LAYER_END, ip->ip_dst.s_addr, 
			     ip->ip_src.s_addr, ip->ip_p, ip->ip_off, ip->ip_len);
	
	
			/* TCP deals with its own locking */
			ip_proto_dispatch_in(m, hlen, ip->ip_p, 0);
		} else {
			KERNEL_DEBUG(DBG_LAYER_END, ip->ip_dst.s_addr, 
			     ip->ip_src.s_addr, ip->ip_p, ip->ip_off, ip->ip_len);
		
			ip_proto_dispatch_in(m, hlen, ip->ip_p, 0);
		}
#else
		ip_proto_dispatch_in(m, hlen, ip->ip_p, 0);
#endif
		
		return;
	}
bad:
	KERNEL_DEBUG(DBG_LAYER_END, 0,0,0,0,0);
	m_freem(m);
}

/*
 * Take incoming datagram fragment and try to reassemble it into
 * whole datagram.  If a chain for reassembly of this datagram already
 * exists, then it is given as fp; otherwise have to make a chain.
 *
 * When IPDIVERT enabled, keep additional state with each packet that
 * tells us if we need to divert or tee the packet we're building.
 */

static struct mbuf *
#if IPDIVERT
ip_reass(struct mbuf *m, struct ipq *fp, struct ipq *where,
#ifdef IPDIVERT_44
	 u_int32_t *divinfo,
#else /* IPDIVERT_44 */
	 u_int16_t *divinfo,
#endif /* IPDIVERT_44 */
	 u_int16_t *divcookie)
#else /* IPDIVERT */
ip_reass(struct mbuf *m, struct ipq *fp, struct ipq *where)
#endif /* IPDIVERT */
{
	struct ip *ip = mtod(m, struct ip *);
	struct mbuf *p = 0, *q, *nq;
	struct mbuf *t;
	int hlen = IP_VHL_HL(ip->ip_vhl) << 2;
	int i, next;
	u_int8_t ecn, ecn0;

	lck_mtx_assert(ip_mutex, LCK_MTX_ASSERT_OWNED);
	/*
	 * Presence of header sizes in mbufs
	 * would confuse code below.
	 */
	m->m_data += hlen;
	m->m_len -= hlen;

	if (m->m_pkthdr.csum_flags & CSUM_TCP_SUM16) 
               	m->m_pkthdr.csum_flags = 0;
	/*
	 * If first fragment to arrive, create a reassembly queue.
	 */
	if (fp == 0) {
		if ((t = m_get(M_DONTWAIT, MT_FTABLE)) == NULL)
			goto dropfrag;
		fp = mtod(t, struct ipq *);
#if CONFIG_MACF_NET
		if (mac_ipq_label_init(fp, M_NOWAIT) != 0) {
			m_free(t);
			fp = NULL;
			goto dropfrag;
		}
		mac_ipq_label_associate(m, fp);
#endif
		insque((void*)fp, (void*)where);
		nipq++;
		fp->ipq_nfrags = 1;
		fp->ipq_ttl = IPFRAGTTL;
		fp->ipq_p = ip->ip_p;
		fp->ipq_id = ip->ip_id;
		fp->ipq_src = ip->ip_src;
		fp->ipq_dst = ip->ip_dst;
		fp->ipq_frags = m;
		m->m_nextpkt = NULL;
#if IPDIVERT
#ifdef IPDIVERT_44
		fp->ipq_div_info = 0;
#else
		fp->ipq_divert = 0;
#endif
		fp->ipq_div_cookie = 0;
#endif
		TAILQ_INSERT_HEAD(&ipq_list, fp, ipq_list);
		goto inserted;
	} else {
		fp->ipq_nfrags++;
#if CONFIG_MACF_NET
		mac_ipq_label_update(m, fp);
#endif
	}

#define GETIP(m)	((struct ip*)((m)->m_pkthdr.header))

	/*
	 * Handle ECN by comparing this segment with the first one;
	 * if CE is set, do not lose CE.
	 * drop if CE and not-ECT are mixed for the same packet.
	 */
	ecn = ip->ip_tos & IPTOS_ECN_MASK;
	ecn0 = GETIP(fp->ipq_frags)->ip_tos & IPTOS_ECN_MASK;
	if (ecn == IPTOS_ECN_CE) {
		if (ecn0 == IPTOS_ECN_NOTECT)
			goto dropfrag;
		if (ecn0 != IPTOS_ECN_CE)
			GETIP(fp->ipq_frags)->ip_tos |= IPTOS_ECN_CE;
	}
	if (ecn == IPTOS_ECN_NOTECT && ecn0 != IPTOS_ECN_NOTECT)
		goto dropfrag;

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
	 *
	 * If some of the data is dropped from the the preceding
	 * segment, then it's checksum is invalidated.
	 */
	if (p) {
		i = GETIP(p)->ip_off + GETIP(p)->ip_len - ip->ip_off;
		if (i > 0) {
			if (i >= ip->ip_len)
				goto dropfrag;
			m_adj(m, i);
			m->m_pkthdr.csum_flags = 0;
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
			q->m_pkthdr.csum_flags = 0;
			break;
		}
		nq = q->m_nextpkt;
		m->m_nextpkt = nq;
		OSAddAtomic(1, &ipstat.ips_fragdropped);
		fp->ipq_nfrags--;
		m_freem(q);
	}

inserted:
	currentfrags++;

#if IPDIVERT
	/*
	 * Transfer firewall instructions to the fragment structure.
	 * Only trust info in the fragment at offset 0.
	 */
	if (ip->ip_off == 0) {
#ifdef IPDIVERT_44
	fp->ipq_div_info = *divinfo;
#else
	fp->ipq_divert = *divinfo;
#endif
	fp->ipq_div_cookie = *divcookie;
	}
	*divinfo = 0;
	*divcookie = 0;
#endif

	/*
	 * Check for complete reassembly and perform frag per packet
	 * limiting.
	 *
	 * Frag limiting is performed here so that the nth frag has
	 * a chance to complete the packet before we drop the packet.
	 * As a result, n+1 frags are actually allowed per packet, but
	 * only n will ever be stored. (n = maxfragsperpacket.)
	 *
	 */
	next = 0;
	for (p = NULL, q = fp->ipq_frags; q; p = q, q = q->m_nextpkt) {
		if (GETIP(q)->ip_off != next) {
			if (fp->ipq_nfrags > maxfragsperpacket) {
				OSAddAtomic(fp->ipq_nfrags, &ipstat.ips_fragdropped);
				ip_freef(fp);
			}
			return (0);
		}
		next += GETIP(q)->ip_len;
	}
	/* Make sure the last packet didn't have the IP_MF flag */
	if (p->m_flags & M_FRAG) {
		if (fp->ipq_nfrags > maxfragsperpacket) {
			OSAddAtomic(fp->ipq_nfrags, &ipstat.ips_fragdropped);
			ip_freef(fp);
		}
		return (0);
	}

	/*
	 * Reassembly is complete.  Make sure the packet is a sane size.
	 */
	q = fp->ipq_frags;
	ip = GETIP(q);
	if (next + (IP_VHL_HL(ip->ip_vhl) << 2) > IP_MAXPACKET) {
		OSAddAtomic(1, &ipstat.ips_toolong);
		OSAddAtomic(fp->ipq_nfrags, &ipstat.ips_fragdropped);
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
		if (q->m_pkthdr.csum_flags & CSUM_TCP_SUM16) 
	    		m->m_pkthdr.csum_flags = 0;
		else {
			m->m_pkthdr.csum_flags &= q->m_pkthdr.csum_flags;
			m->m_pkthdr.csum_data += q->m_pkthdr.csum_data;
		}
		m_cat(m, q);
	}

#if IPDIVERT
	/*
	 * Extract firewall instructions from the fragment structure.
	 */
#ifdef IPDIVERT_44
	*divinfo = fp->ipq_div_info;
#else
	*divinfo = fp->ipq_divert;
#endif
	*divcookie = fp->ipq_div_cookie;
#endif

#if CONFIG_MACF_NET
	mac_mbuf_label_associate_ipq(fp, m);
	mac_ipq_label_destroy(fp);
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
	remque((void*)fp);
	TAILQ_REMOVE(&ipq_list, fp, ipq_list);
	currentfrags -= fp->ipq_nfrags;
	nipq--;
	(void) m_free(dtom(fp));
	m->m_len += (IP_VHL_HL(ip->ip_vhl) << 2);
	m->m_data -= (IP_VHL_HL(ip->ip_vhl) << 2);
	/* some debugging cruft by sklower, below, will go away soon */
	if (m->m_flags & M_PKTHDR) { /* XXX this should be done elsewhere */
		int plen = 0;
		for (t = m; t; t = t->m_next)
			plen += t->m_len;
		m->m_pkthdr.len = plen;
	}
	return (m);

dropfrag:
#if IPDIVERT
	*divinfo = 0;
	*divcookie = 0;
#endif
	OSAddAtomic(1, &ipstat.ips_fragdropped);
	if (fp != 0)
		fp->ipq_nfrags--;
	m_freem(m);
	return (0);

#undef GETIP
}

/*
 * Free a fragment reassembly header and all
 * associated datagrams.
 */
static void
ip_freef(struct ipq *fp)
{
	lck_mtx_assert(ip_mutex, LCK_MTX_ASSERT_OWNED);
	currentfrags -= fp->ipq_nfrags;
	m_freem_list(fp->ipq_frags);
	remque((void*)fp);
	TAILQ_REMOVE(&ipq_list, fp, ipq_list);
	(void) m_free(dtom(fp));
	nipq--;
}

/*
 * IP timer processing;
 * if a timer expires on a reassembly
 * queue, discard it.
 */
void
ip_slowtimo(void)
{
	struct ipq *fp;
	int i;
	lck_mtx_lock(ip_mutex);
	for (i = 0; i < IPREASS_NHASH; i++) {
		fp = ipq[i].next;
		if (fp == 0)
			continue;
		while (fp != &ipq[i]) {
			--fp->ipq_ttl;
			fp = fp->next;
			if (fp->prev->ipq_ttl == 0) {
				OSAddAtomic(fp->ipq_nfrags, &ipstat.ips_fragtimeout);
				ip_freef(fp->prev);
			}
		}
	}
	/*
	 * If we are over the maximum number of fragments
	 * (due to the limit being lowered), drain off
	 * enough to get down to the new limit.
	 */
	if (maxnipq >= 0 && nipq > maxnipq) {
	for (i = 0; i < IPREASS_NHASH; i++) {
			while (nipq > maxnipq &&
				(ipq[i].next != &ipq[i])) {
				OSAddAtomic(ipq[i].next->ipq_nfrags, &ipstat.ips_fragdropped);
				ip_freef(ipq[i].next);
			}
		}
	}
	lck_mtx_unlock(ip_mutex);
}

/*
 * Drain off all datagram fragments.
 */
void
ip_drain(void)
{
	int     i;

	lck_mtx_lock(ip_mutex);
	for (i = 0; i < IPREASS_NHASH; i++) {
		while (ipq[i].next != &ipq[i]) {
			OSAddAtomic(ipq[i].next->ipq_nfrags, &ipstat.ips_fragdropped);
			ip_freef(ipq[i].next);
		}
	}
	lck_mtx_unlock(ip_mutex);
	in_rtqdrain();
}

/*
 * Do option processing on a datagram,
 * possibly discarding it if bad options are encountered,
 * or forwarding it if source-routed.
 * The pass argument is used when operating in the IPSTEALTH
 * mode to tell what options to process:
 * [LS]SRR (pass 0) or the others (pass 1).
 * The reason for as many as two passes is that when doing IPSTEALTH,
 * non-routing options should be processed only if the packet is for us.
 * Returns 1 if packet has been forwarded/freed,
 * 0 if the packet should be processed further.
 */
static int
ip_dooptions(struct mbuf *m, __unused int pass, struct sockaddr_in *next_hop)
{
	struct ip *ip = mtod(m, struct ip *);
	u_char *cp;
	struct ip_timestamp *ipt;
	struct in_ifaddr *ia;
	int opt, optlen, cnt, off, code, type = ICMP_PARAMPROB, forward = 0;
	struct in_addr *sin, dst;
	n_time ntime;
	struct sockaddr_in ipaddr = {
	    sizeof (ipaddr), AF_INET , 0 , { 0 }, { 0, } };

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
			if (optlen < IPOPT_OFFSET + sizeof(*cp)) {
				code = &cp[IPOPT_OLEN] - (u_char *)ip;
				goto bad;
			}
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
			else {
				IFA_REMREF(&ia->ia_ifa);
				ia = NULL;
			}
			off--;			/* 0 origin */
			if (off > optlen - (int)sizeof(struct in_addr)) {
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
					char buf[MAX_IPv4_STR_LEN];
					char buf2[MAX_IPv4_STR_LEN];
					/*
					 * Acting as a router, so generate ICMP
					 */
nosourcerouting:
					log(LOG_WARNING,
					    "attempted source route from %s to %s\n",
					    inet_ntop(AF_INET, &ip->ip_src, buf, sizeof(buf)),
					    inet_ntop(AF_INET, &ip->ip_dst, buf2, sizeof(buf2)));
					type = ICMP_UNREACH;
					code = ICMP_UNREACH_SRCFAIL;
					goto bad;
				} else {
					/*
					 * Not acting as a router, so silently drop.
					 */
					OSAddAtomic(1, &ipstat.ips_cantforward);
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
			    if ((ia = (INA)ifa_ifwithdstaddr((SA)&ipaddr)) == 0) {
					ia = (INA)ifa_ifwithnet((SA)&ipaddr);
				}
			} else {
				ia = ip_rtaddr(ipaddr.sin_addr);
			}
			if (ia == 0) {
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_SRCFAIL;
				goto bad;
			}
			ip->ip_dst = ipaddr.sin_addr;
			IFA_LOCK(&ia->ia_ifa);
			(void)memcpy(cp + off, &(IA_SIN(ia)->sin_addr),
			    sizeof(struct in_addr));
			IFA_UNLOCK(&ia->ia_ifa);
			IFA_REMREF(&ia->ia_ifa);
			ia = NULL;
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
			if (off > optlen - (int)sizeof(struct in_addr))
				break;
			(void)memcpy(&ipaddr.sin_addr, &ip->ip_dst,
			    sizeof(ipaddr.sin_addr));
			/*
			 * locate outgoing interface; if we're the destination,
			 * use the incoming interface (should be same).
			 */
			if ((ia = (INA)ifa_ifwithaddr((SA)&ipaddr)) == 0) {
				if ((ia = ip_rtaddr(ipaddr.sin_addr)) == 0) {
					type = ICMP_UNREACH;
					code = ICMP_UNREACH_HOST;
					goto bad;
				}
			}
			IFA_LOCK(&ia->ia_ifa);
			(void)memcpy(cp + off, &(IA_SIN(ia)->sin_addr),
			    sizeof(struct in_addr));
			IFA_UNLOCK(&ia->ia_ifa);
			IFA_REMREF(&ia->ia_ifa);
			ia = NULL;
			cp[IPOPT_OFFSET] += sizeof(struct in_addr);
			break;

		case IPOPT_TS:
			code = cp - (u_char *)ip;
			ipt = (struct ip_timestamp *)cp;
			if (ipt->ipt_len < 4 || ipt->ipt_len > 40) {
				code = (u_char *)&ipt->ipt_len - (u_char *)ip;
				goto bad;
			}
			if (ipt->ipt_ptr < 5) {
				code = (u_char *)&ipt->ipt_ptr - (u_char *)ip;
				goto bad;
			}
			if (ipt->ipt_ptr >
			    ipt->ipt_len - (int)sizeof(int32_t)) {
				if (++ipt->ipt_oflw == 0) {
					code = (u_char *)&ipt->ipt_ptr -
					    (u_char *)ip;
					goto bad;
				}
				break;
			}
			sin = (struct in_addr *)(cp + ipt->ipt_ptr - 1);
			switch (ipt->ipt_flg) {

			case IPOPT_TS_TSONLY:
				break;

			case IPOPT_TS_TSANDADDR:
				if (ipt->ipt_ptr - 1 + sizeof(n_time) +
				    sizeof(struct in_addr) > ipt->ipt_len) {
					code = (u_char *)&ipt->ipt_ptr -
					    (u_char *)ip;
					goto bad;
				}
				ipaddr.sin_addr = dst;
				ia = (INA)ifaof_ifpforaddr((SA)&ipaddr,
							    m->m_pkthdr.rcvif);
				if (ia == 0)
					continue;
				IFA_LOCK(&ia->ia_ifa);
				(void)memcpy(sin, &IA_SIN(ia)->sin_addr,
				    sizeof(struct in_addr));
				IFA_UNLOCK(&ia->ia_ifa);
				ipt->ipt_ptr += sizeof(struct in_addr);
				IFA_REMREF(&ia->ia_ifa);
				ia = NULL;
				break;

			case IPOPT_TS_PRESPEC:
				if (ipt->ipt_ptr - 1 + sizeof(n_time) +
				    sizeof(struct in_addr) > ipt->ipt_len) {
					code = (u_char *)&ipt->ipt_ptr -
					    (u_char *)ip;
					goto bad;
				}
				(void)memcpy(&ipaddr.sin_addr, sin,
				    sizeof(struct in_addr));
				if ((ia = (struct in_ifaddr*)ifa_ifwithaddr((SA)&ipaddr)) == 0)
					continue;
				IFA_REMREF(&ia->ia_ifa);
				ia = NULL;
				ipt->ipt_ptr += sizeof(struct in_addr);
				break;

			default:
				/* XXX can't take &ipt->ipt_flg */
				code = (u_char *)&ipt->ipt_ptr -
				    (u_char *)ip + 1;
				goto bad;
			}
			ntime = iptime();
			(void)memcpy(cp + ipt->ipt_ptr - 1, &ntime,
			    sizeof(n_time));
			ipt->ipt_ptr += sizeof(n_time);
		}
	}
	if (forward && ipforwarding) {
		ip_forward(m, 1, next_hop);
		return (1);
	}
	return (0);
bad:
	ip->ip_len -= IP_VHL_HL(ip->ip_vhl) << 2;   /* XXX icmp_error adds in hdr length */
	icmp_error(m, type, code, 0, 0);
	OSAddAtomic(1, &ipstat.ips_badoptions);
	return (1);
}

/*
 * Given address of next destination (final or next hop),
 * return internet address info of interface to be used to get there.
 */
struct in_ifaddr *
ip_rtaddr(struct in_addr dst)
{
	struct sockaddr_in *sin;
	struct ifaddr *rt_ifa;
	struct route ro;

	bzero(&ro, sizeof (ro));
	sin = (struct sockaddr_in *)&ro.ro_dst;
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof (*sin);
	sin->sin_addr = dst;

	rtalloc_ign(&ro, RTF_PRCLONING);
	if (ro.ro_rt == NULL)
		return (NULL);

	RT_LOCK(ro.ro_rt);
	if ((rt_ifa = ro.ro_rt->rt_ifa) != NULL)
		IFA_ADDREF(rt_ifa);
	RT_UNLOCK(ro.ro_rt);
	rtfree(ro.ro_rt);

	return ((struct in_ifaddr *)rt_ifa);
}

/*
 * Save incoming source route for use in replies,
 * to be picked up later by ip_srcroute if the receiver is interested.
 */
void
save_rte(u_char *option, struct in_addr dst)
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
ip_srcroute(void)
{
	struct in_addr *p, *q;
	struct mbuf *m;

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
		printf(" hops %lx", (u_int32_t)ntohl(mtod(m, struct in_addr *)->s_addr));
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
			printf(" %lx", (u_int32_t)ntohl(q->s_addr));
#endif
		*q++ = *p--;
	}
	/*
	 * Last hop goes to final destination.
	 */
	*q = ip_srcrt.dst;
#if DIAGNOSTIC
	if (ipprintfs)
		printf(" %lx\n", (u_int32_t)ntohl(q->s_addr));
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
ip_stripoptions(struct mbuf *m, __unused struct mbuf *mopt)
{
	int i;
	struct ip *ip = mtod(m, struct ip *);
	caddr_t opts;
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
	ENETUNREACH,	EHOSTUNREACH,	ECONNREFUSED,	ECONNREFUSED,
	EMSGSIZE,	EHOSTUNREACH,	0,		0,
	0,		0,		0,		0,
	ENOPROTOOPT,	ECONNREFUSED
};

static int
sysctl_ipforwarding SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int i, was_ipforwarding = ipforwarding;

	i = sysctl_handle_int(oidp, oidp->oid_arg1, oidp->oid_arg2, req);
	if (i != 0 || req->newptr == USER_ADDR_NULL)
		return (i);

	if (was_ipforwarding && !ipforwarding) {
		/* clean up IPv4 forwarding cached routes */
		ifnet_head_lock_shared();
		for (i = 0; i <= if_index; i++) {
			struct ifnet *ifp = ifindex2ifnet[i];
			if (ifp != NULL) {
				lck_mtx_lock(&ifp->if_cached_route_lock);
				if (ifp->if_fwd_route.ro_rt != NULL)
					rtfree(ifp->if_fwd_route.ro_rt);
				bzero(&ifp->if_fwd_route,
				    sizeof (ifp->if_fwd_route));
				lck_mtx_unlock(&ifp->if_cached_route_lock);
			}
		}
		ifnet_head_done();
	}

	return (0);
}

/*
 * Similar to inp_route_{copyout,copyin} routines except that these copy
 * out the cached IPv4 forwarding route from struct ifnet instead of the
 * inpcb.  See comments for those routines for explanations.
 */
static void
ip_fwd_route_copyout(struct ifnet *ifp, struct route *dst)
{
	struct route *src = &ifp->if_fwd_route;

	lck_mtx_lock_spin(&ifp->if_cached_route_lock);
	lck_mtx_convert_spin(&ifp->if_cached_route_lock);

	/* Minor sanity check */
	if (src->ro_rt != NULL && rt_key(src->ro_rt)->sa_family != AF_INET)
		panic("%s: wrong or corrupted route: %p", __func__, src);

	route_copyout(dst, src, sizeof(*dst));

	lck_mtx_unlock(&ifp->if_cached_route_lock);
}

static void
ip_fwd_route_copyin(struct ifnet *ifp, struct route *src)
{
	struct route *dst = &ifp->if_fwd_route;

	lck_mtx_lock_spin(&ifp->if_cached_route_lock);
	lck_mtx_convert_spin(&ifp->if_cached_route_lock);

	/* Minor sanity check */
	if (src->ro_rt != NULL && rt_key(src->ro_rt)->sa_family != AF_INET)
		panic("%s: wrong or corrupted route: %p", __func__, src);

	if (ifp->if_fwd_cacheok)
		route_copyin(src, dst, sizeof(*src));

	lck_mtx_unlock(&ifp->if_cached_route_lock);
}

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
static void
ip_forward(struct mbuf *m, int srcrt, struct sockaddr_in *next_hop)
{
#if !IPFIREWALL
#pragma unused(next_hop)
#endif
	struct ip *ip = mtod(m, struct ip *);
	struct sockaddr_in *sin;
	struct rtentry *rt;
	struct route fwd_rt;
	int error, type = 0, code = 0;
	struct mbuf *mcopy;
	n_long dest;
	struct in_addr pkt_dst;
	u_int32_t nextmtu = 0;
	struct ip_out_args ipoa = { IFSCOPE_NONE, 0 };
	struct ifnet *ifp = m->m_pkthdr.rcvif;
#if PF
	struct pf_mtag *pf_mtag;
#endif /* PF */

	dest = 0;
#if IPFIREWALL
	/*
	 * Cache the destination address of the packet; this may be
	 * changed by use of 'ipfw fwd'.
	 */
	pkt_dst = next_hop ? next_hop->sin_addr : ip->ip_dst;
#else
	pkt_dst = ip->ip_dst;
#endif

#if DIAGNOSTIC
	if (ipprintfs)
		printf("forward: src %lx dst %lx ttl %x\n",
		    (u_int32_t)ip->ip_src.s_addr, (u_int32_t)pkt_dst.s_addr,
		    ip->ip_ttl);
#endif

	if (m->m_flags & (M_BCAST|M_MCAST) || in_canforward(pkt_dst) == 0) {
		OSAddAtomic(1, &ipstat.ips_cantforward);
		m_freem(m);
		return;
	}
#if IPSTEALTH
	if (!ipstealth) {
#endif
		if (ip->ip_ttl <= IPTTLDEC) {
			icmp_error(m, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS,
			    dest, 0);
			return;
		}
#if IPSTEALTH
	}
#endif

#if PF
	pf_mtag = pf_find_mtag(m);
	if (pf_mtag != NULL && pf_mtag->rtableid != IFSCOPE_NONE)
		ipoa.ipoa_boundif = pf_mtag->rtableid;
#endif /* PF */

	ip_fwd_route_copyout(ifp, &fwd_rt);

	sin = (struct sockaddr_in *)&fwd_rt.ro_dst;
	if (fwd_rt.ro_rt == NULL ||
	    fwd_rt.ro_rt->generation_id != route_generation ||
	    pkt_dst.s_addr != sin->sin_addr.s_addr) {
		if (fwd_rt.ro_rt != NULL) {
			rtfree(fwd_rt.ro_rt);
			fwd_rt.ro_rt = NULL;
		}
		sin->sin_family = AF_INET;
		sin->sin_len = sizeof (*sin);
		sin->sin_addr = pkt_dst;

		rtalloc_scoped_ign(&fwd_rt, RTF_PRCLONING, ipoa.ipoa_boundif);
		if (fwd_rt.ro_rt == NULL) {
			icmp_error(m, ICMP_UNREACH, ICMP_UNREACH_HOST, dest, 0);
			goto done;
		}
	}
	rt = fwd_rt.ro_rt;

	/*
	 * Save the IP header and at most 8 bytes of the payload,
	 * in case we need to generate an ICMP message to the src.
	 *
	 * We don't use m_copy() because it might return a reference
	 * to a shared cluster. Both this function and ip_output()
	 * assume exclusive access to the IP header in `m', so any
	 * data in a cluster may change before we reach icmp_error().
	 */
	MGET(mcopy, M_DONTWAIT, m->m_type);
	if (mcopy != NULL) {
		M_COPY_PKTHDR(mcopy, m);
		mcopy->m_len = imin((IP_VHL_HL(ip->ip_vhl) << 2) + 8,
		    (int)ip->ip_len);
		m_copydata(m, 0, mcopy->m_len, mtod(mcopy, caddr_t));
	}

#if IPSTEALTH
	if (!ipstealth) {
#endif
		ip->ip_ttl -= IPTTLDEC;
#if IPSTEALTH
	}
#endif

	/*
	 * If forwarding packet using same interface that it came in on,
	 * perhaps should send a redirect to sender to shortcut a hop.
	 * Only send redirect if source is sending directly to us,
	 * and if packet was not source routed (or has any options).
	 * Also, don't send redirect if forwarding using a default route
	 * or a route modified by a redirect.
	 */
	RT_LOCK_SPIN(rt);
	if (rt->rt_ifp == m->m_pkthdr.rcvif &&
	    (rt->rt_flags & (RTF_DYNAMIC|RTF_MODIFIED)) == 0 &&
	    satosin(rt_key(rt))->sin_addr.s_addr != 0 &&
	    ipsendredirects && !srcrt && rt->rt_ifa != NULL) {
		struct in_ifaddr *ia = (struct in_ifaddr *)rt->rt_ifa;
		u_int32_t src = ntohl(ip->ip_src.s_addr);

		/* Become a regular mutex */
		RT_CONVERT_LOCK(rt);
		IFA_LOCK_SPIN(&ia->ia_ifa);
		if ((src & ia->ia_subnetmask) == ia->ia_subnet) {
			if (rt->rt_flags & RTF_GATEWAY)
				dest = satosin(rt->rt_gateway)->sin_addr.s_addr;
			else
				dest = pkt_dst.s_addr;
			/* Router requirements says to only send host redirects */
			type = ICMP_REDIRECT;
			code = ICMP_REDIRECT_HOST;
#if DIAGNOSTIC
			if (ipprintfs)
				printf("redirect (%d) to %lx\n", code, (u_int32_t)dest);
#endif
		}
		IFA_UNLOCK(&ia->ia_ifa);
	}
	RT_UNLOCK(rt);

#if IPFIREWALL
	if (next_hop) {
		/* Pass IPFORWARD info if available */
		struct m_tag *tag;
		struct ip_fwd_tag	*ipfwd_tag;

		tag = m_tag_create(KERNEL_MODULE_TAG_ID,
		    KERNEL_TAG_TYPE_IPFORWARD,
		    sizeof (*ipfwd_tag), M_NOWAIT, m);
		if (tag == NULL) {
			error = ENOBUFS;
			m_freem(m);
			goto done;
		}

		ipfwd_tag = (struct ip_fwd_tag *)(tag+1);
		ipfwd_tag->next_hop = next_hop;

		m_tag_prepend(m, tag);
	}
#endif
	error = ip_output_list(m, 0, NULL, &fwd_rt,
	    IP_FORWARDING | IP_OUTARGS, 0, &ipoa);

	/* Refresh rt since the route could have changed while in IP */
	rt = fwd_rt.ro_rt;

	if (error) {
		OSAddAtomic(1, &ipstat.ips_cantforward);
	} else {
		OSAddAtomic(1, &ipstat.ips_forward);
		if (type)
			OSAddAtomic(1, &ipstat.ips_redirectsent);
		else {
			if (mcopy) {
				/*
				 * If we didn't have to go thru ipflow and
				 * the packet was successfully consumed by
				 * ip_output, the mcopy is rather a waste;
				 * this could be further optimized.
				 */
				m_freem(mcopy);
			}
			goto done;
		}
	}
	if (mcopy == NULL)
		goto done;

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
		if (rt != NULL) {
			RT_LOCK_SPIN(rt);
			if (rt->rt_ifp != NULL)
				nextmtu = rt->rt_ifp->if_mtu;
			RT_UNLOCK(rt);
		}
#else
		/*
		 * If the packet is routed over IPsec tunnel, tell the
		 * originator the tunnel MTU.
		 *	tunnel MTU = if MTU - sizeof(IP) - ESP/AH hdrsiz
		 * XXX quickhack!!!
		 */
		if (rt != NULL) {
			struct secpolicy *sp = NULL;
			int ipsecerror;
			int ipsechdr;
			struct route *ro;

			RT_LOCK_SPIN(rt);
			if (rt->rt_ifp != NULL)
				nextmtu = rt->rt_ifp->if_mtu;
			RT_UNLOCK(rt);

			if (ipsec_bypass) {
				OSAddAtomic(1, &ipstat.ips_cantfrag);
				break;
			}
			sp = ipsec4_getpolicybyaddr(mcopy,
						    IPSEC_DIR_OUTBOUND,
			                            IP_FORWARDING,
			                            &ipsecerror);

			if (sp != NULL) {
				/* count IPsec header size */
				ipsechdr = ipsec_hdrsiz(sp);

				/*
				 * find the correct route for outer IPv4
				 * header, compute tunnel MTU.
				 */
				nextmtu = 0;

				if (sp->req != NULL) {
					if (sp->req->saidx.mode == IPSEC_MODE_TUNNEL) {
						struct secasindex saidx;
						struct ip *ipm;
						struct secasvar *sav;

						ipm = mtod(mcopy, struct ip *);
						bcopy(&sp->req->saidx, &saidx, sizeof(saidx));
						saidx.mode = sp->req->saidx.mode;
						saidx.reqid = sp->req->saidx.reqid;
						sin = (struct sockaddr_in *)&saidx.src;
						if (sin->sin_len == 0) {
							sin->sin_len = sizeof(*sin);
							sin->sin_family = AF_INET;
							sin->sin_port = IPSEC_PORT_ANY;
							bcopy(&ipm->ip_src, &sin->sin_addr,
								sizeof(sin->sin_addr));
						}
						sin = (struct sockaddr_in *)&saidx.dst;
						if (sin->sin_len == 0) {
							sin->sin_len = sizeof(*sin);
							sin->sin_family = AF_INET;
							sin->sin_port = IPSEC_PORT_ANY;
							bcopy(&ipm->ip_dst, &sin->sin_addr,
								sizeof(sin->sin_addr));
						}
						sav = key_allocsa_policy(&saidx);
						if (sav != NULL) {
							lck_mtx_lock(sadb_mutex);
							if (sav->sah != NULL) {
								ro = &sav->sah->sa_route;
								if (ro->ro_rt != NULL) {
									RT_LOCK(ro->ro_rt);
									if (ro->ro_rt->rt_ifp != NULL) {
										nextmtu = ro->ro_rt->rt_ifp->if_mtu;
										nextmtu -= ipsechdr;
									}
									RT_UNLOCK(ro->ro_rt);
								}
							}
							key_freesav(sav, KEY_SADB_LOCKED);
							lck_mtx_unlock(sadb_mutex);
						}
					}
				}
				key_freesp(sp, KEY_SADB_UNLOCKED);
			}
		}
#endif /*IPSEC*/
		OSAddAtomic(1, &ipstat.ips_cantfrag);
		break;

	case ENOBUFS:
		type = ICMP_SOURCEQUENCH;
		code = 0;
		break;

	case EACCES:			/* ipfw denied packet */
		m_freem(mcopy);
		goto done;
	}

	icmp_error(mcopy, type, code, dest, nextmtu);
done:
	ip_fwd_route_copyin(ifp, &fwd_rt);
}

int
ip_savecontrol(
	struct inpcb *inp,
	struct mbuf **mp,
	struct ip *ip,
	struct mbuf *m)
{
	*mp = NULL;
	if (inp->inp_socket->so_options & SO_TIMESTAMP) {
		struct timeval tv;

		microtime(&tv);
		mp = sbcreatecontrol_mbuf((caddr_t) &tv, sizeof(tv),
			SCM_TIMESTAMP, SOL_SOCKET, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
	if ((inp->inp_socket->so_options & SO_TIMESTAMP_MONOTONIC) != 0) {
		uint64_t time;

		time = mach_absolute_time();
		mp = sbcreatecontrol_mbuf((caddr_t) &time, sizeof(time),
			SCM_TIMESTAMP_MONOTONIC, SOL_SOCKET, mp);
		
		if (*mp == NULL) {
			goto no_mbufs;
		}
	} 
	if (inp->inp_flags & INP_RECVDSTADDR) {
		mp = sbcreatecontrol_mbuf((caddr_t) &ip->ip_dst,
			sizeof(struct in_addr), IP_RECVDSTADDR, IPPROTO_IP, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
#ifdef notyet
	/* XXX
	 * Moving these out of udp_input() made them even more broken
	 * than they already were.
	 */
	/* options were tossed already */
	if (inp->inp_flags & INP_RECVOPTS) {
		mp = sbcreatecontrol_mbuf((caddr_t) opts_deleted_above,
			sizeof(struct in_addr), IP_RECVOPTS, IPPROTO_IP, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
	/* ip_srcroute doesn't do what we want here, need to fix */
	if (inp->inp_flags & INP_RECVRETOPTS) {
		mp = sbcreatecontrol_mbuf((caddr_t) ip_srcroute(),
			sizeof(struct in_addr), IP_RECVRETOPTS, IPPROTO_IP, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
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

		ifnet_head_lock_shared();
		if ((ifp = m->m_pkthdr.rcvif) != NULL &&
		    ifp->if_index && (ifp->if_index <= if_index)) {
			struct ifaddr *ifa = ifnet_addrs[ifp->if_index - 1];

			if (!ifa || !ifa->ifa_addr)
				goto makedummy;

			IFA_LOCK_SPIN(ifa);
			sdp = (struct sockaddr_dl *)ifa->ifa_addr;
			/*
			 * Change our mind and don't try copy.
			 */
			if ((sdp->sdl_family != AF_LINK) ||
			    (sdp->sdl_len > sizeof(sdlbuf))) {
				IFA_UNLOCK(ifa);
				goto makedummy;
			}
			bcopy(sdp, sdl2, sdp->sdl_len);
			IFA_UNLOCK(ifa);
		} else {
makedummy:
			sdl2->sdl_len
				= offsetof(struct sockaddr_dl, sdl_data[0]);
			sdl2->sdl_family = AF_LINK;
			sdl2->sdl_index = 0;
			sdl2->sdl_nlen = sdl2->sdl_alen = sdl2->sdl_slen = 0;
		}
		ifnet_head_done();
		mp = sbcreatecontrol_mbuf((caddr_t) sdl2, sdl2->sdl_len,
			IP_RECVIF, IPPROTO_IP, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
	if (inp->inp_flags & INP_RECVTTL) {
		mp = sbcreatecontrol_mbuf((caddr_t)&ip->ip_ttl, sizeof(ip->ip_ttl), 
			IP_RECVTTL, IPPROTO_IP, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
	if ((inp->inp_socket->so_flags & SOF_RECV_TRAFFIC_CLASS) != 0) {
		int tc = m->m_pkthdr.prio;
		
		mp = sbcreatecontrol_mbuf((caddr_t) &tc, sizeof(tc),
			SO_TRAFFIC_CLASS, SOL_SOCKET, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
	if (inp->inp_flags & INP_PKTINFO) {
		struct in_pktinfo pi;

		bzero(&pi, sizeof(struct in_pktinfo));
		bcopy(&ip->ip_dst, &pi.ipi_addr, sizeof(struct in_addr));
		pi.ipi_ifindex = (m && m->m_pkthdr.rcvif) ? m->m_pkthdr.rcvif->if_index : 0;
		
		mp = sbcreatecontrol_mbuf((caddr_t)&pi, sizeof(struct in_pktinfo), 
			IP_RECVPKTINFO, IPPROTO_IP, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
	return 0;

no_mbufs:
	ipstat.ips_pktdropcntrl++;
	return ENOBUFS;
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
