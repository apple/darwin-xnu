/*
 * Copyright (c) 2000-2015 Apple Inc. All rights reserved.
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
#include <sys/socketvar.h>
#include <sys/kdebug.h>
#include <mach/mach_time.h>
#include <mach/sdt.h>

#include <machine/endian.h>
#include <dev/random/randomdev.h>

#include <kern/queue.h>
#include <kern/locks.h>
#include <libkern/OSAtomic.h>

#include <pexpert/pexpert.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <net/kpi_protocol.h>
#include <net/ntstat.h>
#include <net/dlil.h>
#include <net/classq/classq.h>
#include <net/net_perf.h>
#if PF
#include <net/pfvar.h>
#endif /* PF */

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/in_arp.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_fw.h>
#include <netinet/ip_divert.h>
#include <netinet/kpi_ipfilter_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/bootp.h>
#include <netinet/lro_ext.h>

#if DUMMYNET
#include <netinet/ip_dummynet.h>
#endif /* DUMMYNET */

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif /* CONFIG_MACF_NET */

#if IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif /* IPSEC */

#define	DBG_LAYER_BEG		NETDBG_CODE(DBG_NETIP, 0)
#define	DBG_LAYER_END		NETDBG_CODE(DBG_NETIP, 2)
#define	DBG_FNC_IP_INPUT	NETDBG_CODE(DBG_NETIP, (2 << 8))

#if IPSEC
extern int ipsec_bypass;
extern lck_mtx_t *sadb_mutex;

lck_grp_t	*sadb_stat_mutex_grp;
lck_grp_attr_t	*sadb_stat_mutex_grp_attr;
lck_attr_t	*sadb_stat_mutex_attr;
decl_lck_mtx_data(, sadb_stat_mutex_data);
lck_mtx_t	*sadb_stat_mutex = &sadb_stat_mutex_data;
#endif /* IPSEC */

MBUFQ_HEAD(fq_head);

static int frag_timeout_run;		/* frag timer is scheduled to run */
static void frag_timeout(void *);
static void frag_sched_timeout(void);

static struct ipq *ipq_alloc(int);
static void ipq_free(struct ipq *);
static void ipq_updateparams(void);
static void ip_input_second_pass(struct mbuf *, struct ifnet *,
    u_int32_t, int, int, struct ip_fw_in_args *, int);

decl_lck_mtx_data(static, ipqlock);
static lck_attr_t	*ipqlock_attr;
static lck_grp_t	*ipqlock_grp;
static lck_grp_attr_t	*ipqlock_grp_attr;

/* Packet reassembly stuff */
#define	IPREASS_NHASH_LOG2	6
#define	IPREASS_NHASH		(1 << IPREASS_NHASH_LOG2)
#define	IPREASS_HMASK		(IPREASS_NHASH - 1)
#define	IPREASS_HASH(x, y) \
	(((((x) & 0xF) | ((((x) >> 8) & 0xF) << 4)) ^ (y)) & IPREASS_HMASK)

/* IP fragment reassembly queues (protected by ipqlock) */
static TAILQ_HEAD(ipqhead, ipq) ipq[IPREASS_NHASH]; /* ip reassembly queues */
static int maxnipq;			/* max packets in reass queues */
static u_int32_t maxfragsperpacket;	/* max frags/packet in reass queues */
static u_int32_t nipq;			/* # of packets in reass queues */
static u_int32_t ipq_limit;		/* ipq allocation limit */
static u_int32_t ipq_count;		/* current # of allocated ipq's */

static int sysctl_ipforwarding SYSCTL_HANDLER_ARGS;
static int sysctl_maxnipq SYSCTL_HANDLER_ARGS;
static int sysctl_maxfragsperpacket SYSCTL_HANDLER_ARGS;
static int sysctl_reset_ip_input_stats SYSCTL_HANDLER_ARGS;
static int sysctl_ip_input_measure_bins SYSCTL_HANDLER_ARGS;
static int sysctl_ip_input_getperf SYSCTL_HANDLER_ARGS;

int ipforwarding = 0;
SYSCTL_PROC(_net_inet_ip, IPCTL_FORWARDING, forwarding,
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &ipforwarding, 0,
	sysctl_ipforwarding, "I", "Enable IP forwarding between interfaces");

static int ipsendredirects = 1; /* XXX */
SYSCTL_INT(_net_inet_ip, IPCTL_SENDREDIRECTS, redirect,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ipsendredirects, 0,
	"Enable sending IP redirects");

int ip_defttl = IPDEFTTL;
SYSCTL_INT(_net_inet_ip, IPCTL_DEFTTL, ttl, CTLFLAG_RW | CTLFLAG_LOCKED,
	&ip_defttl, 0, "Maximum TTL on IP packets");

static int ip_dosourceroute = 0;
SYSCTL_INT(_net_inet_ip, IPCTL_SOURCEROUTE, sourceroute,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip_dosourceroute, 0,
	"Enable forwarding source routed IP packets");

static int ip_acceptsourceroute = 0;
SYSCTL_INT(_net_inet_ip, IPCTL_ACCEPTSOURCEROUTE, accept_sourceroute,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip_acceptsourceroute, 0,
	"Enable accepting source routed IP packets");

static int ip_sendsourcequench = 0;
SYSCTL_INT(_net_inet_ip, OID_AUTO, sendsourcequench,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip_sendsourcequench, 0,
	"Enable the transmission of source quench packets");

SYSCTL_PROC(_net_inet_ip, OID_AUTO, maxfragpackets,
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &maxnipq, 0, sysctl_maxnipq,
	"I", "Maximum number of IPv4 fragment reassembly queue entries");

SYSCTL_UINT(_net_inet_ip, OID_AUTO, fragpackets, CTLFLAG_RD | CTLFLAG_LOCKED,
	&nipq, 0, "Current number of IPv4 fragment reassembly queue entries");

SYSCTL_PROC(_net_inet_ip, OID_AUTO, maxfragsperpacket,
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &maxfragsperpacket, 0,
	sysctl_maxfragsperpacket, "I",
	"Maximum number of IPv4 fragments allowed per packet");

int ip_doscopedroute = 1;
SYSCTL_INT(_net_inet_ip, OID_AUTO, scopedroute, CTLFLAG_RD | CTLFLAG_LOCKED,
	&ip_doscopedroute, 0, "Enable IPv4 scoped routing");

static uint32_t ip_adj_clear_hwcksum = 0;
SYSCTL_UINT(_net_inet_ip, OID_AUTO, adj_clear_hwcksum,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip_adj_clear_hwcksum, 0,
	"Invalidate hwcksum info when adjusting length");

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
static int ip_checkinterface = 0;
SYSCTL_INT(_net_inet_ip, OID_AUTO, check_interface, CTLFLAG_RW | CTLFLAG_LOCKED,
	&ip_checkinterface, 0, "Verify packet arrives on correct interface");

static int ip_chaining = 1;
SYSCTL_INT(_net_inet_ip, OID_AUTO, rx_chaining, CTLFLAG_RW | CTLFLAG_LOCKED,
	&ip_chaining, 1, "Do receive side ip address based chaining");

static int ip_chainsz = 6;
SYSCTL_INT(_net_inet_ip, OID_AUTO, rx_chainsz, CTLFLAG_RW | CTLFLAG_LOCKED,
	&ip_chainsz, 1, "IP receive side max chaining");

static int ip_input_measure = 0;
SYSCTL_PROC(_net_inet_ip, OID_AUTO, input_perf,
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
	&ip_input_measure, 0, sysctl_reset_ip_input_stats, "I", "Do time measurement");

static uint64_t ip_input_measure_bins = 0;
SYSCTL_PROC(_net_inet_ip, OID_AUTO, input_perf_bins,
	CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED, &ip_input_measure_bins, 0,
	sysctl_ip_input_measure_bins, "I",
	"bins for chaining performance data histogram");

static net_perf_t net_perf;
SYSCTL_PROC(_net_inet_ip, OID_AUTO, input_perf_data,
	CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
	0, 0, sysctl_ip_input_getperf, "S,net_perf",
	"IP input performance data (struct net_perf, net/net_perf.h)");

#if DIAGNOSTIC
static int ipprintfs = 0;
#endif

struct protosw *ip_protox[IPPROTO_MAX];

static lck_grp_attr_t	*in_ifaddr_rwlock_grp_attr;
static lck_grp_t	*in_ifaddr_rwlock_grp;
static lck_attr_t	*in_ifaddr_rwlock_attr;
decl_lck_rw_data(, in_ifaddr_rwlock_data);
lck_rw_t		*in_ifaddr_rwlock = &in_ifaddr_rwlock_data;

/* Protected by in_ifaddr_rwlock */
struct in_ifaddrhead in_ifaddrhead;		/* first inet address */
struct in_ifaddrhashhead *in_ifaddrhashtbl;	/* inet addr hash table  */

#define	INADDR_NHASH	61
static u_int32_t inaddr_nhash;			/* hash table size */
static u_int32_t inaddr_hashp;			/* next largest prime */

static int ip_getstat SYSCTL_HANDLER_ARGS;
struct ipstat ipstat;
SYSCTL_PROC(_net_inet_ip, IPCTL_STATS, stats,
	CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
	0, 0, ip_getstat, "S,ipstat",
	"IP statistics (struct ipstat, netinet/ip_var.h)");

#if IPCTL_DEFMTU
SYSCTL_INT(_net_inet_ip, IPCTL_DEFMTU, mtu, CTLFLAG_RW | CTLFLAG_LOCKED,
	&ip_mtu, 0, "Default MTU");
#endif /* IPCTL_DEFMTU */

#if IPSTEALTH
static int	ipstealth = 0;
SYSCTL_INT(_net_inet_ip, OID_AUTO, stealth, CTLFLAG_RW | CTLFLAG_LOCKED,
	&ipstealth, 0, "");
#endif /* IPSTEALTH */

/* Firewall hooks */
#if IPFIREWALL
ip_fw_chk_t *ip_fw_chk_ptr;
int fw_enable = 1;
int fw_bypass = 1;
int fw_one_pass = 0;
#endif /* IPFIREWALL */

#if DUMMYNET
ip_dn_io_t *ip_dn_io_ptr;
#endif /* DUMMYNET */

SYSCTL_NODE(_net_inet_ip, OID_AUTO, linklocal,
	CTLFLAG_RW | CTLFLAG_LOCKED, 0, "link local");

struct ip_linklocal_stat ip_linklocal_stat;
SYSCTL_STRUCT(_net_inet_ip_linklocal, OID_AUTO, stat,
	CTLFLAG_RD | CTLFLAG_LOCKED, &ip_linklocal_stat, ip_linklocal_stat,
	"Number of link local packets with TTL less than 255");

SYSCTL_NODE(_net_inet_ip_linklocal, OID_AUTO, in,
	CTLFLAG_RW | CTLFLAG_LOCKED, 0, "link local input");

int ip_linklocal_in_allowbadttl = 1;
SYSCTL_INT(_net_inet_ip_linklocal_in, OID_AUTO, allowbadttl,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ip_linklocal_in_allowbadttl, 0,
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
	struct	in_addr route[MAX_IPOPTLEN / sizeof (struct in_addr)];
} ip_srcrt;

static void in_ifaddrhashtbl_init(void);
static void save_rte(u_char *, struct in_addr);
static int ip_dooptions(struct mbuf *, int, struct sockaddr_in *);
static void ip_forward(struct mbuf *, int, struct sockaddr_in *);
static void frag_freef(struct ipqhead *, struct ipq *);
#if IPDIVERT
#ifdef IPDIVERT_44
static struct mbuf *ip_reass(struct mbuf *, u_int32_t *, u_int16_t *);
#else /* !IPDIVERT_44 */
static struct mbuf *ip_reass(struct mbuf *, u_int16_t *, u_int16_t *);
#endif /* !IPDIVERT_44 */
#else /* !IPDIVERT */
static struct mbuf *ip_reass(struct mbuf *);
#endif /* !IPDIVERT */
static void ip_fwd_route_copyout(struct ifnet *, struct route *);
static void ip_fwd_route_copyin(struct ifnet *, struct route *);
static inline u_short ip_cksum(struct mbuf *, int);

int ip_use_randomid = 1;
SYSCTL_INT(_net_inet_ip, OID_AUTO, random_id, CTLFLAG_RW | CTLFLAG_LOCKED,
	&ip_use_randomid, 0, "Randomize IP packets IDs");

/*
 * On platforms which require strict alignment (currently for anything but
 * i386 or x86_64), check if the IP header pointer is 32-bit aligned; if not,
 * copy the contents of the mbuf chain into a new chain, and free the original
 * one.  Create some head room in the first mbuf of the new chain, in case
 * it's needed later on.
 */
#if defined(__i386__) || defined(__x86_64__)
#define	IP_HDR_ALIGNMENT_FIXUP(_m, _ifp, _action) do { } while (0)
#else /* !__i386__ && !__x86_64__ */
#define	IP_HDR_ALIGNMENT_FIXUP(_m, _ifp, _action) do {			\
	if (!IP_HDR_ALIGNED_P(mtod(_m, caddr_t))) {			\
		struct mbuf *_n;					\
		struct ifnet *__ifp = (_ifp);				\
		atomic_add_64(&(__ifp)->if_alignerrs, 1);		\
		if (((_m)->m_flags & M_PKTHDR) &&			\
		    (_m)->m_pkthdr.pkt_hdr != NULL)			\
			(_m)->m_pkthdr.pkt_hdr = NULL;			\
		_n = m_defrag_offset(_m, max_linkhdr, M_NOWAIT);	\
		if (_n == NULL) {					\
			atomic_add_32(&ipstat.ips_toosmall, 1);		\
			m_freem(_m);					\
			(_m) = NULL;					\
			_action;					\
		} else {						\
			VERIFY(_n != (_m));				\
			(_m) = _n;					\
		}							\
	}								\
} while (0)
#endif /* !__i386__ && !__x86_64__ */

/*
 * GRE input handler function, settable via ip_gre_register_input() for PPTP.
 */
static gre_input_func_t gre_input_func;

/*
 * IP initialization: fill in IP protocol switch table.
 * All protocols not implemented in kernel go to raw IP protocol handler.
 */
void
ip_init(struct protosw *pp, struct domain *dp)
{
	static int ip_initialized = 0;
	struct protosw *pr;
	struct timeval tv;
	int i;

	domain_proto_mtx_lock_assert_held();
	VERIFY((pp->pr_flags & (PR_INITIALIZED|PR_ATTACHED)) == PR_ATTACHED);

	/* ipq_alloc() uses mbufs for IP fragment queue structures */
	_CASSERT(sizeof (struct ipq) <= _MLEN);

	/*
	 * Some ioctls (e.g. SIOCAIFADDR) use ifaliasreq struct, which is
	 * interchangeable with in_aliasreq; they must have the same size.
	 */
	_CASSERT(sizeof (struct ifaliasreq) == sizeof (struct in_aliasreq));

	if (ip_initialized)
		return;
	ip_initialized = 1;

	PE_parse_boot_argn("net.inet.ip.scopedroute",
	    &ip_doscopedroute, sizeof (ip_doscopedroute));

	in_ifaddr_init();

	in_ifaddr_rwlock_grp_attr = lck_grp_attr_alloc_init();
	in_ifaddr_rwlock_grp = lck_grp_alloc_init("in_ifaddr_rwlock",
	    in_ifaddr_rwlock_grp_attr);
	in_ifaddr_rwlock_attr = lck_attr_alloc_init();
	lck_rw_init(in_ifaddr_rwlock, in_ifaddr_rwlock_grp,
	    in_ifaddr_rwlock_attr);

	TAILQ_INIT(&in_ifaddrhead);
	in_ifaddrhashtbl_init();

	ip_moptions_init();

	pr = pffindproto_locked(PF_INET, IPPROTO_RAW, SOCK_RAW);
	if (pr == NULL) {
		panic("%s: Unable to find [PF_INET,IPPROTO_RAW,SOCK_RAW]\n",
		    __func__);
		/* NOTREACHED */
	}

	/* Initialize the entire ip_protox[] array to IPPROTO_RAW. */
	for (i = 0; i < IPPROTO_MAX; i++)
		ip_protox[i] = pr;
	/*
	 * Cycle through IP protocols and put them into the appropriate place
	 * in ip_protox[], skipping protocols IPPROTO_{IP,RAW}.
	 */
	VERIFY(dp == inetdomain && dp->dom_family == PF_INET);
	TAILQ_FOREACH(pr, &dp->dom_protosw, pr_entry) {
		VERIFY(pr->pr_domain == dp);
		if (pr->pr_protocol != 0 && pr->pr_protocol != IPPROTO_RAW) {
			/* Be careful to only index valid IP protocols. */
			if (pr->pr_protocol < IPPROTO_MAX)
				ip_protox[pr->pr_protocol] = pr;
		}
	}

	/* IP fragment reassembly queue lock */
	ipqlock_grp_attr  = lck_grp_attr_alloc_init();
	ipqlock_grp = lck_grp_alloc_init("ipqlock", ipqlock_grp_attr);
	ipqlock_attr = lck_attr_alloc_init();
	lck_mtx_init(&ipqlock, ipqlock_grp, ipqlock_attr);

	lck_mtx_lock(&ipqlock);
	/* Initialize IP reassembly queue. */
	for (i = 0; i < IPREASS_NHASH; i++)
		TAILQ_INIT(&ipq[i]);

	maxnipq = nmbclusters / 32;
	maxfragsperpacket = 128; /* enough for 64k in 512 byte fragments */
	ipq_updateparams();
	lck_mtx_unlock(&ipqlock);

	getmicrotime(&tv);
	ip_id = RandomULong() ^ tv.tv_usec;
	ip_initid();

	ipf_init();

#if IPSEC
	sadb_stat_mutex_grp_attr = lck_grp_attr_alloc_init();
	sadb_stat_mutex_grp = lck_grp_alloc_init("sadb_stat",
	    sadb_stat_mutex_grp_attr);
	sadb_stat_mutex_attr = lck_attr_alloc_init();
	lck_mtx_init(sadb_stat_mutex, sadb_stat_mutex_grp,
	    sadb_stat_mutex_attr);

#endif
	arp_init();
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

	PE_parse_boot_argn("inaddr_nhash", &inaddr_nhash,
	    sizeof (inaddr_nhash));
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

void
ip_proto_dispatch_in_wrapper(struct mbuf *m, int hlen, u_int8_t proto)
{
	ip_proto_dispatch_in(m, hlen, proto, 0);
}

__private_extern__ void
ip_proto_dispatch_in(struct mbuf *m, int hlen, u_int8_t proto,
    ipfilter_t inject_ipfref)
{
	struct ipfilter *filter;
	int seen = (inject_ipfref == NULL);
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
					/*
					 * Perform IP header alignment fixup,
					 * if needed, before passing packet
					 * into filter(s).
					 */
					IP_HDR_ALIGNMENT_FIXUP(m,
					    m->m_pkthdr.rcvif, ipf_unref());

					/* ipf_unref() already called */
					if (m == NULL)
						return;

					changed_header = 1;
					ip = mtod(m, struct ip *);
					ip->ip_len = htons(ip->ip_len + hlen);
					ip->ip_off = htons(ip->ip_off);
					ip->ip_sum = 0;
					ip->ip_sum = ip_cksum_hdr_in(m, hlen);
				}
				result = filter->ipf_filter.ipf_input(
				    filter->ipf_filter.cookie, (mbuf_t *)&m,
				    hlen, proto);
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

	/* Perform IP header alignment fixup (post-filters), if needed */
	IP_HDR_ALIGNMENT_FIXUP(m, m->m_pkthdr.rcvif, return);

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

struct pktchain_elm {
	struct mbuf	*pkte_head;
	struct mbuf	*pkte_tail;
	struct in_addr	pkte_saddr;
	struct in_addr	pkte_daddr;
	uint16_t	pkte_npkts;
	uint16_t	pkte_proto;
	uint32_t	pkte_nbytes;
};

typedef struct pktchain_elm pktchain_elm_t;

/* Store upto PKTTBL_SZ unique flows on the stack */
#define PKTTBL_SZ	7

static struct mbuf *
ip_chain_insert(struct mbuf *packet, pktchain_elm_t *tbl)
{
	struct ip*	ip;
	int		pkttbl_idx = 0;

	ip = mtod(packet, struct ip*);

	/* reusing the hash function from inaddr_hashval */
	pkttbl_idx = inaddr_hashval(ntohs(ip->ip_src.s_addr)) % PKTTBL_SZ;
	if (tbl[pkttbl_idx].pkte_head == NULL) {
		tbl[pkttbl_idx].pkte_head = packet;
		tbl[pkttbl_idx].pkte_saddr.s_addr = ip->ip_src.s_addr;
		tbl[pkttbl_idx].pkte_daddr.s_addr = ip->ip_dst.s_addr;
		tbl[pkttbl_idx].pkte_proto = ip->ip_p;
	} else {
		if ((ip->ip_dst.s_addr == tbl[pkttbl_idx].pkte_daddr.s_addr) &&
		    (ip->ip_src.s_addr == tbl[pkttbl_idx].pkte_saddr.s_addr) &&
		    (ip->ip_p == tbl[pkttbl_idx].pkte_proto)) {
		} else {
			return (packet);
		}
	}
	if (tbl[pkttbl_idx].pkte_tail != NULL)
		mbuf_setnextpkt(tbl[pkttbl_idx].pkte_tail, packet);

	tbl[pkttbl_idx].pkte_tail = packet;
	tbl[pkttbl_idx].pkte_npkts += 1;
	tbl[pkttbl_idx].pkte_nbytes += packet->m_pkthdr.len;
	return (NULL);
}

/* args is a dummy variable here for backward compatibility */
static void
ip_input_second_pass_loop_tbl(pktchain_elm_t *tbl, struct ip_fw_in_args *args)
{
	int i = 0;

	for (i = 0; i < PKTTBL_SZ; i++) {
		if (tbl[i].pkte_head != NULL) {
			struct mbuf *m = tbl[i].pkte_head;
			ip_input_second_pass(m, m->m_pkthdr.rcvif, 0,
			    tbl[i].pkte_npkts, tbl[i].pkte_nbytes, args, 0);

			if (tbl[i].pkte_npkts > 2)
				ipstat.ips_rxc_chainsz_gt2++;
			if (tbl[i].pkte_npkts > 4)
				ipstat.ips_rxc_chainsz_gt4++;

			if (ip_input_measure)
				net_perf_histogram(&net_perf, tbl[i].pkte_npkts);

			tbl[i].pkte_head = tbl[i].pkte_tail = NULL;
			tbl[i].pkte_npkts = 0;
			tbl[i].pkte_nbytes = 0;
			/* no need to initialize address and protocol in tbl */
		}
	}
}

static void
ip_input_cpout_args(struct ip_fw_in_args *args, struct ip_fw_args *args1,
    boolean_t *done_init)
{
	if (*done_init == FALSE) {
		bzero(args1, sizeof(struct ip_fw_args));
		*done_init = TRUE;
	}
	args1->fwa_next_hop = args->fwai_next_hop;
	args1->fwa_ipfw_rule = args->fwai_ipfw_rule;
	args1->fwa_pf_rule = args->fwai_pf_rule;
	args1->fwa_divert_rule = args->fwai_divert_rule;
}

static void
ip_input_cpin_args(struct ip_fw_args *args1, struct ip_fw_in_args *args)
{
	args->fwai_next_hop = args1->fwa_next_hop;
	args->fwai_ipfw_rule = args1->fwa_ipfw_rule;
	args->fwai_pf_rule = args1->fwa_pf_rule;
	args->fwai_divert_rule = args1->fwa_divert_rule;
}

typedef enum {
	IPINPUT_DOCHAIN = 0,
	IPINPUT_DONTCHAIN,
	IPINPUT_FREED,
	IPINPUT_DONE
} ipinput_chain_ret_t;

static void
ip_input_update_nstat(struct ifnet *ifp, struct in_addr src_ip,
    u_int32_t packets, u_int32_t bytes)
{
	if (nstat_collect) {
		struct rtentry *rt = ifnet_cached_rtlookup_inet(ifp,
		    src_ip);
		if (rt != NULL) {
			nstat_route_rx(rt, packets, bytes, 0);
			rtfree(rt);
		}
	}
}

static void
ip_input_dispatch_chain(struct mbuf *m)
{
	struct mbuf *tmp_mbuf = m;
	struct mbuf *nxt_mbuf = NULL;
	struct ip *ip = NULL;
	unsigned int hlen;

	ip = mtod(tmp_mbuf, struct ip *);
	hlen = IP_VHL_HL(ip->ip_vhl) << 2;
	while(tmp_mbuf) {
		nxt_mbuf = mbuf_nextpkt(tmp_mbuf);
		mbuf_setnextpkt(tmp_mbuf, NULL);

		if ((sw_lro) && (ip->ip_p == IPPROTO_TCP))
			tmp_mbuf = tcp_lro(tmp_mbuf, hlen);
		if (tmp_mbuf)
			ip_proto_dispatch_in(tmp_mbuf, hlen, ip->ip_p, 0);
		tmp_mbuf = nxt_mbuf;
		if (tmp_mbuf) {
			ip = mtod(tmp_mbuf, struct ip *);
			/* first mbuf of chain already has adjusted ip_len */
			hlen = IP_VHL_HL(ip->ip_vhl) << 2;
			ip->ip_len -= hlen;
		}
	}
}

static void
ip_input_setdst_chain(struct mbuf *m, uint32_t ifindex, struct in_ifaddr *ia)
{
	struct mbuf *tmp_mbuf = m;

	while (tmp_mbuf) {
		ip_setdstifaddr_info(tmp_mbuf, ifindex, ia);
		tmp_mbuf = mbuf_nextpkt(tmp_mbuf);
	}
}

/*
 * First pass does all essential packet validation and places on a per flow
 * queue for doing operations that have same outcome for all packets of a flow.
 * div_info is packet divert/tee info
 */
static ipinput_chain_ret_t
ip_input_first_pass(struct mbuf *m, u_int32_t *div_info,
    struct ip_fw_in_args *args, int *ours, struct mbuf **modm)
{
	struct ip	*ip;
	struct ifnet	*inifp;
	unsigned int	hlen;
	int		retval = IPINPUT_DOCHAIN;
	int		len = 0;
	struct in_addr	src_ip;
#if IPFIREWALL
	int		i;
#endif
#if IPFIREWALL || DUMMYNET
	struct m_tag		*copy;
	struct m_tag		*p;
	boolean_t		delete = FALSE;
	struct ip_fw_args	args1;
	boolean_t		init = FALSE;
#endif
	ipfilter_t inject_filter_ref = NULL;

#if !IPFIREWALL
#pragma unused (args)
#endif

#if !IPDIVERT
#pragma unused (div_info)
#pragma unused (ours)
#endif

#if !IPFIREWALL_FORWARD
#pragma unused (ours)
#endif

	/* Check if the mbuf is still valid after interface filter processing */
	MBUF_INPUT_CHECK(m, m->m_pkthdr.rcvif);
	inifp = mbuf_pkthdr_rcvif(m);
	VERIFY(inifp != NULL);

	/* Perform IP header alignment fixup, if needed */
	IP_HDR_ALIGNMENT_FIXUP(m, inifp, goto bad);

	m->m_pkthdr.pkt_flags &= ~PKTF_FORWARDED;

#if IPFIREWALL || DUMMYNET

	/*
	 * Don't bother searching for tag(s) if there's none.
	 */
	if (SLIST_EMPTY(&m->m_pkthdr.tags))
		goto ipfw_tags_done;

	/* Grab info from mtags prepended to the chain */
	p = m_tag_first(m);
	while (p) {
		if (p->m_tag_id == KERNEL_MODULE_TAG_ID) {
#if DUMMYNET
			if (p->m_tag_type == KERNEL_TAG_TYPE_DUMMYNET) {
				struct dn_pkt_tag *dn_tag;

				dn_tag = (struct dn_pkt_tag *)(p+1);
				args->fwai_ipfw_rule = dn_tag->dn_ipfw_rule;
				args->fwai_pf_rule = dn_tag->dn_pf_rule;
				delete = TRUE;
			}
#endif

#if IPDIVERT
			if (p->m_tag_type == KERNEL_TAG_TYPE_DIVERT) {
				struct divert_tag *div_tag;

				div_tag = (struct divert_tag *)(p+1);
				args->fwai_divert_rule = div_tag->cookie;
				delete = TRUE;
			}
#endif

			if (p->m_tag_type == KERNEL_TAG_TYPE_IPFORWARD) {
				struct ip_fwd_tag *ipfwd_tag;

				ipfwd_tag = (struct ip_fwd_tag *)(p+1);
				args->fwai_next_hop = ipfwd_tag->next_hop;
				delete = TRUE;
			}

			if (delete) {
				copy = p;
				p = m_tag_next(m, p);
				m_tag_delete(m, copy);
			} else	{
				p = m_tag_next(m, p);
			}
		} else {
			p = m_tag_next(m, p);
		}
	}

#if DIAGNOSTIC
	if (m == NULL || !(m->m_flags & M_PKTHDR))
		panic("ip_input no HDR");
#endif

#if DUMMYNET
	if (args->fwai_ipfw_rule || args->fwai_pf_rule) {
		/* dummynet already filtered us */
		ip = mtod(m, struct ip *);
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;
		inject_filter_ref = ipf_get_inject_filter(m);
#if IPFIREWALL
		if (args->fwai_ipfw_rule)
			goto iphack;
#endif /* IPFIREWALL */
		if (args->fwai_pf_rule)
			goto check_with_pf;
	}
#endif /* DUMMYNET */
ipfw_tags_done:
#endif /* IPFIREWALL || DUMMYNET */

	/*
	 * No need to process packet twice if we've already seen it.
	 */
	if (!SLIST_EMPTY(&m->m_pkthdr.tags))
		inject_filter_ref = ipf_get_inject_filter(m);
	if (inject_filter_ref != NULL) {
		ip = mtod(m, struct ip *);
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;

		DTRACE_IP6(receive, struct mbuf *, m, struct inpcb *, NULL,
		    struct ip *, ip, struct ifnet *, inifp,
		    struct ip *, ip, struct ip6_hdr *, NULL);

		ip->ip_len = ntohs(ip->ip_len) - hlen;
		ip->ip_off = ntohs(ip->ip_off);
		ip_proto_dispatch_in(m, hlen, ip->ip_p, inject_filter_ref);
		return (IPINPUT_DONE);
	}

	if (m->m_pkthdr.len < sizeof (struct ip)) {
		OSAddAtomic(1, &ipstat.ips_total);
		OSAddAtomic(1, &ipstat.ips_tooshort);
		m_freem(m);
		return (IPINPUT_FREED);
	}

	if (m->m_len < sizeof (struct ip) &&
	    (m = m_pullup(m, sizeof (struct ip))) == NULL) {
		OSAddAtomic(1, &ipstat.ips_total);
		OSAddAtomic(1, &ipstat.ips_toosmall);
		return (IPINPUT_FREED);
	}

	ip = mtod(m, struct ip *);
	*modm = m;

	KERNEL_DEBUG(DBG_LAYER_BEG, ip->ip_dst.s_addr, ip->ip_src.s_addr,
	    ip->ip_p, ip->ip_off, ip->ip_len);

	if (IP_VHL_V(ip->ip_vhl) != IPVERSION) {
		OSAddAtomic(1, &ipstat.ips_total);
		OSAddAtomic(1, &ipstat.ips_badvers);
		KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
		m_freem(m);
		return (IPINPUT_FREED);
	}

	hlen = IP_VHL_HL(ip->ip_vhl) << 2;
	if (hlen < sizeof (struct ip)) {
		OSAddAtomic(1, &ipstat.ips_total);
		OSAddAtomic(1, &ipstat.ips_badhlen);
		KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
		m_freem(m);
		return (IPINPUT_FREED);
	}

	if (hlen > m->m_len) {
		if ((m = m_pullup(m, hlen)) == NULL) {
			OSAddAtomic(1, &ipstat.ips_total);
			OSAddAtomic(1, &ipstat.ips_badhlen);
			KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
			return (IPINPUT_FREED);
		}
		ip = mtod(m, struct ip *);
		*modm = m;
	}

	/* 127/8 must not appear on wire - RFC1122 */
	if ((ntohl(ip->ip_dst.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET ||
	    (ntohl(ip->ip_src.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET) {
		/*
		 * Allow for the following exceptions:
		 *
		 *   1. If the packet was sent to loopback (i.e. rcvif
		 *      would have been set earlier at output time.)
		 *
		 *   2. If the packet was sent out on loopback from a local
		 *      source address which belongs to a non-loopback
		 *      interface (i.e. rcvif may not necessarily be a
		 *      loopback interface, hence the test for PKTF_LOOP.)
		 *      Unlike IPv6, there is no interface scope ID, and
		 *      therefore we don't care so much about PKTF_IFINFO.
		 */
		if (!(inifp->if_flags & IFF_LOOPBACK) &&
		     !(m->m_pkthdr.pkt_flags & PKTF_LOOP)) {
			OSAddAtomic(1, &ipstat.ips_total);
			OSAddAtomic(1, &ipstat.ips_badaddr);
			KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
			m_freem(m);
			return (IPINPUT_FREED);
		}
	}

	/* IPv4 Link-Local Addresses as defined in RFC3927 */
	if ((IN_LINKLOCAL(ntohl(ip->ip_dst.s_addr)) ||
	    IN_LINKLOCAL(ntohl(ip->ip_src.s_addr)))) {
		ip_linklocal_stat.iplls_in_total++;
		if (ip->ip_ttl != MAXTTL) {
			OSAddAtomic(1, &ip_linklocal_stat.iplls_in_badttl);
			/* Silently drop link local traffic with bad TTL */
			if (!ip_linklocal_in_allowbadttl) {
				OSAddAtomic(1, &ipstat.ips_total);
				KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
				m_freem(m);
				return (IPINPUT_FREED);
			}
		}
	}

	if (ip_cksum(m, hlen)) {
		OSAddAtomic(1, &ipstat.ips_total);
		KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
		m_freem(m);
		return (IPINPUT_FREED);
	}

	DTRACE_IP6(receive, struct mbuf *, m, struct inpcb *, NULL,
	    struct ip *, ip, struct ifnet *, inifp,
	    struct ip *, ip, struct ip6_hdr *, NULL);

	/*
	 * Convert fields to host representation.
	 */
#if BYTE_ORDER != BIG_ENDIAN
	NTOHS(ip->ip_len);
#endif

	if (ip->ip_len < hlen) {
		OSAddAtomic(1, &ipstat.ips_total);
		OSAddAtomic(1, &ipstat.ips_badlen);
		KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
		m_freem(m);
		return (IPINPUT_FREED);
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
		OSAddAtomic(1, &ipstat.ips_total);
		OSAddAtomic(1, &ipstat.ips_tooshort);
		KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
		m_freem(m);
		return (IPINPUT_FREED);
	}

	if (m->m_pkthdr.len > ip->ip_len) {
		/*
		 * Invalidate hardware checksum info if ip_adj_clear_hwcksum
		 * is set; useful to handle buggy drivers.  Note that this
		 * should not be enabled by default, as we may get here due
		 * to link-layer padding.
		 */
		if (ip_adj_clear_hwcksum &&
		    (m->m_pkthdr.csum_flags & CSUM_DATA_VALID) &&
		    !(inifp->if_flags & IFF_LOOPBACK) &&
		    !(m->m_pkthdr.pkt_flags & PKTF_LOOP)) {
			m->m_pkthdr.csum_flags &= ~CSUM_DATA_VALID;
			m->m_pkthdr.csum_data = 0;
			ipstat.ips_adj_hwcsum_clr++;
		}

		ipstat.ips_adj++;
		if (m->m_len == m->m_pkthdr.len) {
			m->m_len = ip->ip_len;
			m->m_pkthdr.len = ip->ip_len;
		} else
			m_adj(m, ip->ip_len - m->m_pkthdr.len);
	}

	/* for consistency */
	m->m_pkthdr.pkt_proto = ip->ip_p;

	/* for netstat route statistics */
	src_ip = ip->ip_src;
	len = m->m_pkthdr.len;

#if DUMMYNET
check_with_pf:
#endif
#if PF
	/* Invoke inbound packet filter */
	if (PF_IS_ENABLED) {
		int error;
		ip_input_cpout_args(args, &args1, &init);

#if DUMMYNET
		error = pf_af_hook(inifp, NULL, &m, AF_INET, TRUE, &args1);
#else
		error = pf_af_hook(inifp, NULL, &m, AF_INET, TRUE, NULL);
#endif /* DUMMYNET */
		if (error != 0 || m == NULL) {
			if (m != NULL) {
				panic("%s: unexpected packet %p\n",
				    __func__, m);
				/* NOTREACHED */
			}
			/* Already freed by callee */
			ip_input_update_nstat(inifp, src_ip, 1, len);
			KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
			OSAddAtomic(1, &ipstat.ips_total);
			return (IPINPUT_FREED);
		}
		ip = mtod(m, struct ip *);
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;
		*modm = m;
		ip_input_cpin_args(&args1, args);
	}
#endif /* PF */

#if IPSEC
	if (ipsec_bypass == 0 && ipsec_gethist(m, NULL)) {
		retval = IPINPUT_DONTCHAIN; /* XXX scope for chaining here? */
		goto pass;
	}
#endif

#if IPFIREWALL
#if DUMMYNET
iphack:
#endif /* DUMMYNET */
	/*
	 * Check if we want to allow this packet to be processed.
	 * Consider it to be bad if not.
	 */
	if (fw_enable && IPFW_LOADED) {
#if IPFIREWALL_FORWARD
		/*
		 * If we've been forwarded from the output side, then
		 * skip the firewall a second time
		 */
		if (args->fwai_next_hop) {
			*ours = 1;
			return (IPINPUT_DONTCHAIN);
		}
#endif	/* IPFIREWALL_FORWARD */
		ip_input_cpout_args(args, &args1, &init);
		args1.fwa_m = m;

		i = ip_fw_chk_ptr(&args1);
		m = args1.fwa_m;

		if ((i & IP_FW_PORT_DENY_FLAG) || m == NULL) { /* drop */
			if (m)
				m_freem(m);
			ip_input_update_nstat(inifp, src_ip, 1, len);
			KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
			OSAddAtomic(1, &ipstat.ips_total);
			return (IPINPUT_FREED);
		}
		ip = mtod(m, struct ip *); /* just in case m changed */
		*modm = m;
		ip_input_cpin_args(&args1, args);

		if (i == 0 && args->fwai_next_hop == NULL) { /* common case */
			goto pass;
		}
#if DUMMYNET
		if (DUMMYNET_LOADED && (i & IP_FW_PORT_DYNT_FLAG) != 0) {
			/* Send packet to the appropriate pipe */
			ip_dn_io_ptr(m, i&0xffff, DN_TO_IP_IN, &args1,
			    DN_CLIENT_IPFW);
			ip_input_update_nstat(inifp, src_ip, 1, len);
			KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
			OSAddAtomic(1, &ipstat.ips_total);
			return (IPINPUT_FREED);
		}
#endif /* DUMMYNET */
#if IPDIVERT
		if (i != 0 && (i & IP_FW_PORT_DYNT_FLAG) == 0) {
			/* Divert or tee packet */
			*div_info = i;
			*ours = 1;
			return (IPINPUT_DONTCHAIN);
		}
#endif
#if IPFIREWALL_FORWARD
		if (i == 0 && args->fwai_next_hop != NULL) {
			retval = IPINPUT_DONTCHAIN;
			goto pass;
		}
#endif
		/*
		 * if we get here, the packet must be dropped
		 */
		ip_input_update_nstat(inifp, src_ip, 1, len);
		KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
		m_freem(m);
		OSAddAtomic(1, &ipstat.ips_total);
		return (IPINPUT_FREED);
	}
#endif /* IPFIREWALL */
#if IPSEC | IPFIREWALL
pass:
#endif
	/*
	 * Process options and, if not destined for us,
	 * ship it on.  ip_dooptions returns 1 when an
	 * error was detected (causing an icmp message
	 * to be sent and the original packet to be freed).
	 */
	ip_nhops = 0;		/* for source routed packets */
#if IPFIREWALL
	if (hlen > sizeof (struct ip) &&
	    ip_dooptions(m, 0, args->fwai_next_hop)) {
#else /* !IPFIREWALL */
	if (hlen > sizeof (struct ip) && ip_dooptions(m, 0, NULL)) {
#endif /* !IPFIREWALL */
		ip_input_update_nstat(inifp, src_ip, 1, len);
		KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
		OSAddAtomic(1, &ipstat.ips_total);
		return (IPINPUT_FREED);
	}

	/*
	 * Don't chain fragmented packets as the process of determining
	 * if it is our fragment or someone else's plus the complexity of
	 * divert and fw args makes it harder to do chaining.
	 */
	if (ip->ip_off & ~(IP_DF | IP_RF))
		return (IPINPUT_DONTCHAIN);

	/* Allow DHCP/BootP responses through */
	if ((inifp->if_eflags & IFEF_AUTOCONFIGURING) &&
	    hlen == sizeof (struct ip) && ip->ip_p == IPPROTO_UDP) {
		struct udpiphdr *ui;

		if (m->m_len < sizeof (struct udpiphdr) &&
		    (m = m_pullup(m, sizeof (struct udpiphdr))) == NULL) {
			OSAddAtomic(1, &udpstat.udps_hdrops);
			KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
			OSAddAtomic(1, &ipstat.ips_total);
			return (IPINPUT_FREED);
		}
		*modm = m;
		ui = mtod(m, struct udpiphdr *);
		if (ntohs(ui->ui_dport) == IPPORT_BOOTPC) {
			ip_setdstifaddr_info(m, inifp->if_index, NULL);
			return (IPINPUT_DONTCHAIN);
		}
	}

	/* Avoid chaining raw sockets as ipsec checks occur later for them */
	if (ip_protox[ip->ip_p]->pr_flags & PR_LASTHDR)
		return (IPINPUT_DONTCHAIN);

	return (retval);
#if !defined(__i386__) && !defined(__x86_64__)
bad:
	m_freem(m);
	return (IPINPUT_FREED);
#endif
}

static void
ip_input_second_pass(struct mbuf *m, struct ifnet *inifp, u_int32_t div_info,
    int npkts_in_chain, int bytes_in_chain, struct ip_fw_in_args *args, int ours)
{
	unsigned int		checkif;
	struct mbuf		*tmp_mbuf = NULL;
	struct in_ifaddr	*ia = NULL;
	struct in_addr		pkt_dst;
	unsigned int		hlen;

#if !IPFIREWALL
#pragma unused (args)
#endif

#if !IPDIVERT
#pragma unused (div_info)
#endif

	struct ip *ip = mtod(m, struct ip *);
	hlen = IP_VHL_HL(ip->ip_vhl) << 2;

	OSAddAtomic(npkts_in_chain, &ipstat.ips_total);

	/*
	 * Naively assume we can attribute inbound data to the route we would
	 * use to send to this destination. Asymmetric routing breaks this
	 * assumption, but it still allows us to account for traffic from
	 * a remote node in the routing table.
	 * this has a very significant performance impact so we bypass
	 * if nstat_collect is disabled. We may also bypass if the
	 * protocol is tcp in the future because tcp will have a route that
	 * we can use to attribute the data to. That does mean we would not
	 * account for forwarded tcp traffic.
	 */
	ip_input_update_nstat(inifp, ip->ip_src, npkts_in_chain,
	    bytes_in_chain);

	if (ours)
		goto ours;

	/*
	 * Check our list of addresses, to see if the packet is for us.
	 * If we don't have any addresses, assume any unicast packet
	 * we receive might be for us (and let the upper layers deal
	 * with it).
	 */
	tmp_mbuf = m;
	if (TAILQ_EMPTY(&in_ifaddrhead)) {
		while (tmp_mbuf) {
			if (!(tmp_mbuf->m_flags & (M_MCAST|M_BCAST))) {
				ip_setdstifaddr_info(tmp_mbuf, inifp->if_index,
				    NULL);
			}
			tmp_mbuf = mbuf_nextpkt(tmp_mbuf);
		}
		goto ours;
	}
	/*
	 * Cache the destination address of the packet; this may be
	 * changed by use of 'ipfw fwd'.
	 */
#if IPFIREWALL
	pkt_dst = args->fwai_next_hop == NULL ?
	    ip->ip_dst : args->fwai_next_hop->sin_addr;
#else /* !IPFIREWALL */
	pkt_dst = ip->ip_dst;
#endif /* !IPFIREWALL */

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
	    !(inifp->if_flags & IFF_LOOPBACK) &&
	    !(m->m_pkthdr.pkt_flags & PKTF_LOOP)
#if IPFIREWALL
	    && (args->fwai_next_hop == NULL);
#else /* !IPFIREWALL */
		;
#endif /* !IPFIREWALL */

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
		if (IA_SIN(ia)->sin_addr.s_addr == pkt_dst.s_addr &&
		    (!checkif || ia->ia_ifp == inifp)) {
			ip_input_setdst_chain(m, 0, ia);
			lck_rw_done(in_ifaddr_rwlock);
			goto ours;
		}
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
	if (inifp->if_flags & IFF_BROADCAST) {
		struct ifaddr *ifa;

		ifnet_lock_shared(inifp);
		TAILQ_FOREACH(ifa, &inifp->if_addrhead, ifa_link) {
			if (ifa->ifa_addr->sa_family != AF_INET) {
				continue;
			}
			ia = ifatoia(ifa);
			if (satosin(&ia->ia_broadaddr)->sin_addr.s_addr ==
			    pkt_dst.s_addr || ia->ia_netbroadcast.s_addr ==
			    pkt_dst.s_addr) {
				ip_input_setdst_chain(m, 0, ia);
				ifnet_lock_done(inifp);
				goto ours;
			}
		}
		ifnet_lock_done(inifp);
	}

	if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr))) {
		struct in_multi *inm;
		/*
		 * See if we belong to the destination multicast group on the
		 * arrival interface.
		 */
		in_multihead_lock_shared();
		IN_LOOKUP_MULTI(&ip->ip_dst, inifp, inm);
		in_multihead_lock_done();
		if (inm == NULL) {
			OSAddAtomic(npkts_in_chain, &ipstat.ips_notmember);
			m_freem_list(m);
			KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
			return;
		}
		ip_input_setdst_chain(m, inifp->if_index, NULL);
		INM_REMREF(inm);
		goto ours;
	}

	if (ip->ip_dst.s_addr == (u_int32_t)INADDR_BROADCAST ||
	    ip->ip_dst.s_addr == INADDR_ANY) {
		ip_input_setdst_chain(m, inifp->if_index, NULL);
		goto ours;
	}

	if (ip->ip_p == IPPROTO_UDP) {
		struct udpiphdr *ui;
		ui = mtod(m, struct udpiphdr *);
		if (ntohs(ui->ui_dport) == IPPORT_BOOTPC) {
			goto ours;
		}
	}

	tmp_mbuf = m;
	struct mbuf *nxt_mbuf = NULL;
	while (tmp_mbuf) {
		nxt_mbuf = mbuf_nextpkt(tmp_mbuf);
		/*
		 * Not for us; forward if possible and desirable.
		 */
		mbuf_setnextpkt(tmp_mbuf, NULL);
		if (ipforwarding == 0) {
			OSAddAtomic(1, &ipstat.ips_cantforward);
			m_freem(tmp_mbuf);
		} else {
#if IPFIREWALL
			ip_forward(tmp_mbuf, 0, args->fwai_next_hop);
#else
			ip_forward(tmp_mbuf, 0, NULL);
#endif
		}
		tmp_mbuf = nxt_mbuf;
	}
	KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
	return;
ours:
	/*
	 * If offset or IP_MF are set, must reassemble.
	 */
	if (ip->ip_off & ~(IP_DF | IP_RF)) {
		VERIFY(npkts_in_chain == 1);
		/*
		 * ip_reass() will return a different mbuf, and update
		 * the divert info in div_info and args->fwai_divert_rule.
		 */
#if IPDIVERT
		m = ip_reass(m, (u_int16_t *)&div_info, &args->fwai_divert_rule);
#else
		m = ip_reass(m);
#endif
		if (m == NULL)
			return;
		ip = mtod(m, struct ip *);
		/* Get the header length of the reassembled packet */
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#if IPDIVERT
		/* Restore original checksum before diverting packet */
		if (div_info != 0) {
			VERIFY(npkts_in_chain == 1);
#if BYTE_ORDER != BIG_ENDIAN
			HTONS(ip->ip_len);
			HTONS(ip->ip_off);
#endif
			ip->ip_sum = 0;
			ip->ip_sum = ip_cksum_hdr_in(m, hlen);
#if BYTE_ORDER != BIG_ENDIAN
			NTOHS(ip->ip_off);
			NTOHS(ip->ip_len);
#endif
		}
#endif
	}

	/*
	 * Further protocols expect the packet length to be w/o the
	 * IP header.
	 */
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
		VERIFY(npkts_in_chain == 1);

		/* Clone packet if we're doing a 'tee' */
		if (div_info & IP_FW_PORT_TEE_FLAG)
			clone = m_dup(m, M_DONTWAIT);

		/* Restore packet header fields to original values */
		ip->ip_len += hlen;

#if BYTE_ORDER != BIG_ENDIAN
		HTONS(ip->ip_len);
		HTONS(ip->ip_off);
#endif
		/* Deliver packet to divert input routine */
		OSAddAtomic(1, &ipstat.ips_delivered);
		divert_packet(m, 1, div_info & 0xffff, args->fwai_divert_rule);

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
	if (ipsec_bypass == 0 && (ip_protox[ip->ip_p]->pr_flags & PR_LASTHDR)) {
		VERIFY(npkts_in_chain == 1);
		if (ipsec4_in_reject(m, NULL)) {
			IPSEC_STAT_INCREMENT(ipsecstat.in_polvio);
			goto bad;
		}
	}
#endif /* IPSEC */

	/*
	 * Switch out to protocol's input routine.
	 */
	OSAddAtomic(npkts_in_chain, &ipstat.ips_delivered);

#if IPFIREWALL
	if (args->fwai_next_hop && ip->ip_p == IPPROTO_TCP) {
		/* TCP needs IPFORWARD info if available */
		struct m_tag *fwd_tag;
		struct ip_fwd_tag *ipfwd_tag;

		VERIFY(npkts_in_chain == 1);
		fwd_tag = m_tag_create(KERNEL_MODULE_TAG_ID,
		    KERNEL_TAG_TYPE_IPFORWARD, sizeof (*ipfwd_tag),
		    M_NOWAIT, m);
		if (fwd_tag == NULL)
			goto bad;

		ipfwd_tag = (struct ip_fwd_tag *)(fwd_tag+1);
		ipfwd_tag->next_hop = args->fwai_next_hop;

		m_tag_prepend(m, fwd_tag);

		KERNEL_DEBUG(DBG_LAYER_END, ip->ip_dst.s_addr,
		    ip->ip_src.s_addr, ip->ip_p, ip->ip_off, ip->ip_len);

		/* TCP deals with its own locking */
		ip_proto_dispatch_in(m, hlen, ip->ip_p, 0);
	} else {
		KERNEL_DEBUG(DBG_LAYER_END, ip->ip_dst.s_addr,
		    ip->ip_src.s_addr, ip->ip_p, ip->ip_off, ip->ip_len);

		ip_input_dispatch_chain(m);

	}
#else /* !IPFIREWALL */
	ip_input_dispatch_chain(m);

#endif /* !IPFIREWALL */
	KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
	return;
bad:
	KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
	m_freem(m);
}

void
ip_input_process_list(struct mbuf *packet_list)
{
	pktchain_elm_t	pktchain_tbl[PKTTBL_SZ];

	struct mbuf	*packet = NULL;
	struct mbuf	*modm = NULL; /* modified mbuf */
	int		retval = 0;
	u_int32_t	div_info = 0;
	int		ours = 0;
	struct timeval start_tv;
	int	num_pkts = 0;
	int chain = 0;
	struct ip_fw_in_args       args;

	if (ip_chaining == 0) {
		struct mbuf *m = packet_list;
		if (ip_input_measure)
			net_perf_start_time(&net_perf, &start_tv);
		while (m) {
			packet_list = mbuf_nextpkt(m);
			mbuf_setnextpkt(m, NULL);
			ip_input(m);
			m = packet_list;
			num_pkts++;
		}
		if (ip_input_measure)
			net_perf_measure_time(&net_perf, &start_tv, num_pkts);
		return;
	}
	if (ip_input_measure)
		net_perf_start_time(&net_perf, &start_tv);

	bzero(&pktchain_tbl, sizeof(pktchain_tbl));
restart_list_process:
	chain = 0;
	for (packet = packet_list; packet; packet = packet_list) {
		packet_list = mbuf_nextpkt(packet);
		mbuf_setnextpkt(packet, NULL);

		num_pkts++;
		modm = NULL;
		div_info = 0;
		bzero(&args, sizeof (args));

		retval = ip_input_first_pass(packet, &div_info, &args,
		    &ours, &modm);

		if (retval == IPINPUT_DOCHAIN) {
			if (modm)
				packet = modm;
			packet = ip_chain_insert(packet, &pktchain_tbl[0]);
			if (packet == NULL) {
				ipstat.ips_rxc_chained++;
				chain++;
				if (chain > ip_chainsz)
					break;
			} else {
				ipstat.ips_rxc_collisions++;
				break;
			}
		} else if (retval == IPINPUT_DONTCHAIN) {
			/* in order to preserve order, exit from chaining */
			if (modm)
				packet = modm;
			ipstat.ips_rxc_notchain++;
			break;
		} else {
			/* packet was freed or delivered, do nothing. */
		}
	}

	/* do second pass here for pktchain_tbl */
	if (chain)
		ip_input_second_pass_loop_tbl(&pktchain_tbl[0], &args);

	if (packet) {
		/*
		 * equivalent update in chaining case if performed in
		 * ip_input_second_pass_loop_tbl().
		 */
		if (ip_input_measure)
			net_perf_histogram(&net_perf, 1);

		ip_input_second_pass(packet, packet->m_pkthdr.rcvif, div_info,
		    1, packet->m_pkthdr.len, &args, ours);
	}

	if (packet_list)
		goto restart_list_process;

	if (ip_input_measure)
		net_perf_measure_time(&net_perf, &start_tv, num_pkts);
}
/*
 * Ip input routine.  Checksum and byte swap header.  If fragmented
 * try to reassemble.  Process options.  Pass to next level.
 */
void
ip_input(struct mbuf *m)
{
	struct ip *ip;
	struct in_ifaddr *ia = NULL;
	unsigned int hlen, checkif;
	u_short sum = 0;
	struct in_addr pkt_dst;
#if IPFIREWALL
	int i;
	u_int32_t div_info = 0;		/* packet divert/tee info */
#endif
#if IPFIREWALL || DUMMYNET
	struct ip_fw_args args;
	struct m_tag	*tag;
#endif
	ipfilter_t inject_filter_ref = NULL;
	struct ifnet *inifp;

	/* Check if the mbuf is still valid after interface filter processing */
	MBUF_INPUT_CHECK(m, m->m_pkthdr.rcvif);
	inifp = m->m_pkthdr.rcvif;
	VERIFY(inifp != NULL);

	ipstat.ips_rxc_notlist++;

	/* Perform IP header alignment fixup, if needed */
	IP_HDR_ALIGNMENT_FIXUP(m, inifp, goto bad);

	m->m_pkthdr.pkt_flags &= ~PKTF_FORWARDED;

#if IPFIREWALL || DUMMYNET
	bzero(&args, sizeof (struct ip_fw_args));

	/*
	 * Don't bother searching for tag(s) if there's none.
	 */
	if (SLIST_EMPTY(&m->m_pkthdr.tags))
		goto ipfw_tags_done;

	/* Grab info from mtags prepended to the chain */
#if DUMMYNET
	if ((tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID,
	    KERNEL_TAG_TYPE_DUMMYNET, NULL)) != NULL) {
		struct dn_pkt_tag *dn_tag;

		dn_tag = (struct dn_pkt_tag *)(tag+1);
		args.fwa_ipfw_rule = dn_tag->dn_ipfw_rule;
		args.fwa_pf_rule = dn_tag->dn_pf_rule;

		m_tag_delete(m, tag);
	}
#endif /* DUMMYNET */

#if IPDIVERT
	if ((tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID,
	    KERNEL_TAG_TYPE_DIVERT, NULL)) != NULL) {
		struct divert_tag *div_tag;

		div_tag = (struct divert_tag *)(tag+1);
		args.fwa_divert_rule = div_tag->cookie;

		m_tag_delete(m, tag);
	}
#endif

	if ((tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID,
	    KERNEL_TAG_TYPE_IPFORWARD, NULL)) != NULL) {
		struct ip_fwd_tag *ipfwd_tag;

		ipfwd_tag = (struct ip_fwd_tag *)(tag+1);
		args.fwa_next_hop = ipfwd_tag->next_hop;

		m_tag_delete(m, tag);
	}

#if	DIAGNOSTIC
	if (m == NULL || !(m->m_flags & M_PKTHDR))
		panic("ip_input no HDR");
#endif

#if DUMMYNET
	if (args.fwa_ipfw_rule || args.fwa_pf_rule) {
		/* dummynet already filtered us */
		ip = mtod(m, struct ip *);
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;
		inject_filter_ref = ipf_get_inject_filter(m);
#if IPFIREWALL
		if (args.fwa_ipfw_rule)
			goto iphack;
#endif /* IPFIREWALL */
		if (args.fwa_pf_rule)
			goto check_with_pf;
	}
#endif /* DUMMYNET */
ipfw_tags_done:
#endif /* IPFIREWALL || DUMMYNET */

	/*
	 * No need to process packet twice if we've already seen it.
	 */
	if (!SLIST_EMPTY(&m->m_pkthdr.tags))
		inject_filter_ref = ipf_get_inject_filter(m);
	if (inject_filter_ref != NULL) {
		ip = mtod(m, struct ip *);
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;

		DTRACE_IP6(receive, struct mbuf *, m, struct inpcb *, NULL,
		    struct ip *, ip, struct ifnet *, inifp,
		    struct ip *, ip, struct ip6_hdr *, NULL);

		ip->ip_len = ntohs(ip->ip_len) - hlen;
		ip->ip_off = ntohs(ip->ip_off);
		ip_proto_dispatch_in(m, hlen, ip->ip_p, inject_filter_ref);
		return;
	}

	OSAddAtomic(1, &ipstat.ips_total);
	if (m->m_pkthdr.len < sizeof (struct ip))
		goto tooshort;

	if (m->m_len < sizeof (struct ip) &&
	    (m = m_pullup(m, sizeof (struct ip))) == NULL) {
		OSAddAtomic(1, &ipstat.ips_toosmall);
		return;
	}
	ip = mtod(m, struct ip *);

	KERNEL_DEBUG(DBG_LAYER_BEG, ip->ip_dst.s_addr, ip->ip_src.s_addr,
	    ip->ip_p, ip->ip_off, ip->ip_len);

	if (IP_VHL_V(ip->ip_vhl) != IPVERSION) {
		OSAddAtomic(1, &ipstat.ips_badvers);
		goto bad;
	}

	hlen = IP_VHL_HL(ip->ip_vhl) << 2;
	if (hlen < sizeof (struct ip)) {	/* minimum header length */
		OSAddAtomic(1, &ipstat.ips_badhlen);
		goto bad;
	}
	if (hlen > m->m_len) {
		if ((m = m_pullup(m, hlen)) == NULL) {
			OSAddAtomic(1, &ipstat.ips_badhlen);
			return;
		}
		ip = mtod(m, struct ip *);
	}

	/* 127/8 must not appear on wire - RFC1122 */
	if ((ntohl(ip->ip_dst.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET ||
	    (ntohl(ip->ip_src.s_addr) >> IN_CLASSA_NSHIFT) == IN_LOOPBACKNET) {
		/*
		 * Allow for the following exceptions:
		 *
		 *   1. If the packet was sent to loopback (i.e. rcvif
		 *	would have been set earlier at output time.)
		 *
		 *   2. If the packet was sent out on loopback from a local
		 *	source address which belongs to a non-loopback
		 *	interface (i.e. rcvif may not necessarily be a
		 *	loopback interface, hence the test for PKTF_LOOP.)
		 *	Unlike IPv6, there is no interface scope ID, and
		 *	therefore we don't care so much about PKTF_IFINFO.
		 */
		if (!(inifp->if_flags & IFF_LOOPBACK) &&
		    !(m->m_pkthdr.pkt_flags & PKTF_LOOP)) {
			OSAddAtomic(1, &ipstat.ips_badaddr);
			goto bad;
		}
	}

	/* IPv4 Link-Local Addresses as defined in RFC3927 */
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

	sum = ip_cksum(m, hlen);
	if (sum) {
		goto bad;
	}

	DTRACE_IP6(receive, struct mbuf *, m, struct inpcb *, NULL,
	    struct ip *, ip, struct ifnet *, inifp,
	    struct ip *, ip, struct ip6_hdr *, NULL);

	/*
	 * Naively assume we can attribute inbound data to the route we would
	 * use to send to this destination. Asymmetric routing breaks this
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
		    ifnet_cached_rtlookup_inet(inifp, ip->ip_src);
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
		/*
		 * Invalidate hardware checksum info if ip_adj_clear_hwcksum
		 * is set; useful to handle buggy drivers.  Note that this
		 * should not be enabled by default, as we may get here due
		 * to link-layer padding.
		 */
		if (ip_adj_clear_hwcksum &&
		    (m->m_pkthdr.csum_flags & CSUM_DATA_VALID) &&
		    !(inifp->if_flags & IFF_LOOPBACK) &&
		    !(m->m_pkthdr.pkt_flags & PKTF_LOOP)) {
			m->m_pkthdr.csum_flags &= ~CSUM_DATA_VALID;
			m->m_pkthdr.csum_data = 0;
			ipstat.ips_adj_hwcsum_clr++;
		}

		ipstat.ips_adj++;
		if (m->m_len == m->m_pkthdr.len) {
			m->m_len = ip->ip_len;
			m->m_pkthdr.len = ip->ip_len;
		} else
			m_adj(m, ip->ip_len - m->m_pkthdr.len);
	}

	/* for consistency */
	m->m_pkthdr.pkt_proto = ip->ip_p;

#if DUMMYNET
check_with_pf:
#endif
#if PF
	/* Invoke inbound packet filter */
	if (PF_IS_ENABLED) {
		int error;
#if DUMMYNET
		error = pf_af_hook(inifp, NULL, &m, AF_INET, TRUE, &args);
#else
		error = pf_af_hook(inifp, NULL, &m, AF_INET, TRUE, NULL);
#endif /* DUMMYNET */
		if (error != 0 || m == NULL) {
			if (m != NULL) {
				panic("%s: unexpected packet %p\n",
				    __func__, m);
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
	if (fw_enable && IPFW_LOADED) {
#if IPFIREWALL_FORWARD
		/*
		 * If we've been forwarded from the output side, then
		 * skip the firewall a second time
		 */
		if (args.fwa_next_hop)
			goto ours;
#endif	/* IPFIREWALL_FORWARD */

		args.fwa_m = m;

		i = ip_fw_chk_ptr(&args);
		m = args.fwa_m;

		if ((i & IP_FW_PORT_DENY_FLAG) || m == NULL) { /* drop */
			if (m)
				m_freem(m);
			return;
		}
		ip = mtod(m, struct ip *); /* just in case m changed */

		if (i == 0 && args.fwa_next_hop == NULL) { /* common case */
			goto pass;
		}
#if DUMMYNET
		if (DUMMYNET_LOADED && (i & IP_FW_PORT_DYNT_FLAG) != 0) {
			/* Send packet to the appropriate pipe */
			ip_dn_io_ptr(m, i&0xffff, DN_TO_IP_IN, &args,
			    DN_CLIENT_IPFW);
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
		if (i == 0 && args.fwa_next_hop != NULL) {
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
#if IPSEC | IPFIREWALL
pass:
#endif
	/*
	 * Process options and, if not destined for us,
	 * ship it on.  ip_dooptions returns 1 when an
	 * error was detected (causing an icmp message
	 * to be sent and the original packet to be freed).
	 */
	ip_nhops = 0;		/* for source routed packets */
#if IPFIREWALL
	if (hlen > sizeof (struct ip) &&
	    ip_dooptions(m, 0, args.fwa_next_hop)) {
#else /* !IPFIREWALL */
	if (hlen > sizeof (struct ip) && ip_dooptions(m, 0, NULL)) {
#endif /* !IPFIREWALL */
		return;
	}

	/*
	 * Check our list of addresses, to see if the packet is for us.
	 * If we don't have any addresses, assume any unicast packet
	 * we receive might be for us (and let the upper layers deal
	 * with it).
	 */
	if (TAILQ_EMPTY(&in_ifaddrhead) && !(m->m_flags & (M_MCAST|M_BCAST))) {
		ip_setdstifaddr_info(m, inifp->if_index, NULL);
		goto ours;
	}

	/*
	 * Cache the destination address of the packet; this may be
	 * changed by use of 'ipfw fwd'.
	 */
#if IPFIREWALL
	pkt_dst = args.fwa_next_hop == NULL ?
	    ip->ip_dst : args.fwa_next_hop->sin_addr;
#else /* !IPFIREWALL */
	pkt_dst = ip->ip_dst;
#endif /* !IPFIREWALL */

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
	    !(inifp->if_flags & IFF_LOOPBACK) &&
	    !(m->m_pkthdr.pkt_flags & PKTF_LOOP)
#if IPFIREWALL
	    && (args.fwa_next_hop == NULL);
#else /* !IPFIREWALL */
		;
#endif /* !IPFIREWALL */

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
		if (IA_SIN(ia)->sin_addr.s_addr == pkt_dst.s_addr &&
		    (!checkif || ia->ia_ifp == inifp)) {
			ip_setdstifaddr_info(m, 0, ia);
			lck_rw_done(in_ifaddr_rwlock);
			goto ours;
		}
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
	if (inifp->if_flags & IFF_BROADCAST) {
		struct ifaddr *ifa;

		ifnet_lock_shared(inifp);
		TAILQ_FOREACH(ifa, &inifp->if_addrhead, ifa_link) {
			if (ifa->ifa_addr->sa_family != AF_INET) {
				continue;
			}
			ia = ifatoia(ifa);
			if (satosin(&ia->ia_broadaddr)->sin_addr.s_addr ==
			    pkt_dst.s_addr || ia->ia_netbroadcast.s_addr ==
			    pkt_dst.s_addr) {
				ip_setdstifaddr_info(m, 0, ia);
				ifnet_lock_done(inifp);
				goto ours;
			}
		}
		ifnet_lock_done(inifp);
	}

	if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr))) {
		struct in_multi *inm;
		/*
		 * See if we belong to the destination multicast group on the
		 * arrival interface.
		 */
		in_multihead_lock_shared();
		IN_LOOKUP_MULTI(&ip->ip_dst, inifp, inm);
		in_multihead_lock_done();
		if (inm == NULL) {
			OSAddAtomic(1, &ipstat.ips_notmember);
			m_freem(m);
			return;
		}
		ip_setdstifaddr_info(m, inifp->if_index, NULL);
		INM_REMREF(inm);
		goto ours;
	}
	if (ip->ip_dst.s_addr == (u_int32_t)INADDR_BROADCAST ||
	    ip->ip_dst.s_addr == INADDR_ANY) {
		ip_setdstifaddr_info(m, inifp->if_index, NULL);
		goto ours;
	}

	/* Allow DHCP/BootP responses through */
	if ((inifp->if_eflags & IFEF_AUTOCONFIGURING) &&
	    hlen == sizeof (struct ip) && ip->ip_p == IPPROTO_UDP) {
		struct udpiphdr *ui;

		if (m->m_len < sizeof (struct udpiphdr) &&
		    (m = m_pullup(m, sizeof (struct udpiphdr))) == NULL) {
			OSAddAtomic(1, &udpstat.udps_hdrops);
			return;
		}
		ui = mtod(m, struct udpiphdr *);
		if (ntohs(ui->ui_dport) == IPPORT_BOOTPC) {
			ip_setdstifaddr_info(m, inifp->if_index, NULL);
			goto ours;
		}
		ip = mtod(m, struct ip *); /* in case it changed */
	}

	/*
	 * Not for us; forward if possible and desirable.
	 */
	if (ipforwarding == 0) {
		OSAddAtomic(1, &ipstat.ips_cantforward);
		m_freem(m);
	} else {
#if IPFIREWALL
		ip_forward(m, 0, args.fwa_next_hop);
#else
		ip_forward(m, 0, NULL);
#endif
	}
	return;

ours:
	/*
	 * If offset or IP_MF are set, must reassemble.
	 */
	if (ip->ip_off & ~(IP_DF | IP_RF)) {
		/*
		 * ip_reass() will return a different mbuf, and update
		 * the divert info in div_info and args.fwa_divert_rule.
		 */
#if IPDIVERT
		m = ip_reass(m, (u_int16_t *)&div_info, &args.fwa_divert_rule);
#else
		m = ip_reass(m);
#endif
		if (m == NULL)
			return;
		ip = mtod(m, struct ip *);
		/* Get the header length of the reassembled packet */
		hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#if IPDIVERT
		/* Restore original checksum before diverting packet */
		if (div_info != 0) {
#if BYTE_ORDER != BIG_ENDIAN
			HTONS(ip->ip_len);
			HTONS(ip->ip_off);
#endif
			ip->ip_sum = 0;
			ip->ip_sum = ip_cksum_hdr_in(m, hlen);
#if BYTE_ORDER != BIG_ENDIAN
			NTOHS(ip->ip_off);
			NTOHS(ip->ip_len);
#endif
		}
#endif
	}

	/*
	 * Further protocols expect the packet length to be w/o the
	 * IP header.
	 */
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
		if (div_info & IP_FW_PORT_TEE_FLAG)
			clone = m_dup(m, M_DONTWAIT);

		/* Restore packet header fields to original values */
		ip->ip_len += hlen;

#if BYTE_ORDER != BIG_ENDIAN
		HTONS(ip->ip_len);
		HTONS(ip->ip_off);
#endif
		/* Deliver packet to divert input routine */
		OSAddAtomic(1, &ipstat.ips_delivered);
		divert_packet(m, 1, div_info & 0xffff, args.fwa_divert_rule);

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
	if (ipsec_bypass == 0 && (ip_protox[ip->ip_p]->pr_flags & PR_LASTHDR)) {
		if (ipsec4_in_reject(m, NULL)) {
			IPSEC_STAT_INCREMENT(ipsecstat.in_polvio);
			goto bad;
		}
	}
#endif /* IPSEC */

	/*
	 * Switch out to protocol's input routine.
	 */
	OSAddAtomic(1, &ipstat.ips_delivered);

#if IPFIREWALL
	if (args.fwa_next_hop && ip->ip_p == IPPROTO_TCP) {
		/* TCP needs IPFORWARD info if available */
		struct m_tag *fwd_tag;
		struct ip_fwd_tag *ipfwd_tag;

		fwd_tag = m_tag_create(KERNEL_MODULE_TAG_ID,
		    KERNEL_TAG_TYPE_IPFORWARD, sizeof (*ipfwd_tag),
		    M_NOWAIT, m);
		if (fwd_tag == NULL)
			goto bad;

		ipfwd_tag = (struct ip_fwd_tag *)(fwd_tag+1);
		ipfwd_tag->next_hop = args.fwa_next_hop;

		m_tag_prepend(m, fwd_tag);

		KERNEL_DEBUG(DBG_LAYER_END, ip->ip_dst.s_addr,
		    ip->ip_src.s_addr, ip->ip_p, ip->ip_off, ip->ip_len);

		/* TCP deals with its own locking */
		ip_proto_dispatch_in(m, hlen, ip->ip_p, 0);
	} else {
		KERNEL_DEBUG(DBG_LAYER_END, ip->ip_dst.s_addr,
		    ip->ip_src.s_addr, ip->ip_p, ip->ip_off, ip->ip_len);

		if ((sw_lro) && (ip->ip_p == IPPROTO_TCP)) {
			m = tcp_lro(m, hlen);
			if (m == NULL)
				return;
		}

		ip_proto_dispatch_in(m, hlen, ip->ip_p, 0);
	}
#else /* !IPFIREWALL */
	if ((sw_lro) && (ip->ip_p == IPPROTO_TCP)) {
		m = tcp_lro(m, hlen);
		if (m == NULL)
			return;
	}
	ip_proto_dispatch_in(m, hlen, ip->ip_p, 0);
#endif /* !IPFIREWALL */
	return;

bad:
	KERNEL_DEBUG(DBG_LAYER_END, 0, 0, 0, 0, 0);
	m_freem(m);
}

static void
ipq_updateparams(void)
{
	lck_mtx_assert(&ipqlock, LCK_MTX_ASSERT_OWNED);
	/*
	 * -1 for unlimited allocation.
	 */
	if (maxnipq < 0)
		ipq_limit = 0;
	/*
	 * Positive number for specific bound.
	 */
	if (maxnipq > 0)
		ipq_limit = maxnipq;
	/*
	 * Zero specifies no further fragment queue allocation -- set the
	 * bound very low, but rely on implementation elsewhere to actually
	 * prevent allocation and reclaim current queues.
	 */
	if (maxnipq == 0)
		ipq_limit = 1;
	/*
	 * Arm the purge timer if not already and if there's work to do
	 */
	frag_sched_timeout();
}

static int
sysctl_maxnipq SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, i;

	lck_mtx_lock(&ipqlock);
	i = maxnipq;
	error = sysctl_handle_int(oidp, &i, 0, req);
	if (error || req->newptr == USER_ADDR_NULL)
		goto done;
	/* impose bounds */
	if (i < -1 || i > (nmbclusters / 4)) {
		error = EINVAL;
		goto done;
	}
	maxnipq = i;
	ipq_updateparams();
done:
	lck_mtx_unlock(&ipqlock);
	return (error);
}

static int
sysctl_maxfragsperpacket SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, i;

	lck_mtx_lock(&ipqlock);
	i = maxfragsperpacket;
	error = sysctl_handle_int(oidp, &i, 0, req);
	if (error || req->newptr == USER_ADDR_NULL)
		goto done;
	maxfragsperpacket = i;
	ipq_updateparams();	/* see if we need to arm timer */
done:
	lck_mtx_unlock(&ipqlock);
	return (error);
}

/*
 * Take incoming datagram fragment and try to reassemble it into
 * whole datagram.  If a chain for reassembly of this datagram already
 * exists, then it is given as fp; otherwise have to make a chain.
 *
 * When IPDIVERT enabled, keep additional state with each packet that
 * tells us if we need to divert or tee the packet we're building.
 *
 * The IP header is *NOT* adjusted out of iplen.
 */
static struct mbuf *
#if IPDIVERT
ip_reass(struct mbuf *m,
#ifdef IPDIVERT_44
    u_int32_t *divinfo,
#else /* IPDIVERT_44 */
    u_int16_t *divinfo,
#endif /* IPDIVERT_44 */
    u_int16_t *divcookie)
#else /* IPDIVERT */
ip_reass(struct mbuf *m)
#endif /* IPDIVERT */
{
	struct ip *ip;
	struct mbuf *p, *q, *nq, *t;
	struct ipq *fp = NULL;
	struct ipqhead *head;
	int i, hlen, next;
	u_int8_t ecn, ecn0;
	uint32_t csum, csum_flags;
	uint16_t hash;
	struct fq_head dfq;

	MBUFQ_INIT(&dfq);	/* for deferred frees */

	/* If maxnipq or maxfragsperpacket is 0, never accept fragments. */
	if (maxnipq == 0 || maxfragsperpacket == 0) {
		ipstat.ips_fragments++;
		ipstat.ips_fragdropped++;
		m_freem(m);
		if (nipq > 0) {
			lck_mtx_lock(&ipqlock);
			frag_sched_timeout();	/* purge stale fragments */
			lck_mtx_unlock(&ipqlock);
		}
		return (NULL);
	}

	ip = mtod(m, struct ip *);
	hlen = IP_VHL_HL(ip->ip_vhl) << 2;

	lck_mtx_lock(&ipqlock);

	hash = IPREASS_HASH(ip->ip_src.s_addr, ip->ip_id);
	head = &ipq[hash];

	/*
	 * Look for queue of fragments
	 * of this datagram.
	 */
	TAILQ_FOREACH(fp, head, ipq_list) {
		if (ip->ip_id == fp->ipq_id &&
		    ip->ip_src.s_addr == fp->ipq_src.s_addr &&
		    ip->ip_dst.s_addr == fp->ipq_dst.s_addr &&
#if CONFIG_MACF_NET
		    mac_ipq_label_compare(m, fp) &&
#endif
		    ip->ip_p == fp->ipq_p)
			goto found;
	}

	fp = NULL;

	/*
	 * Attempt to trim the number of allocated fragment queues if it
	 * exceeds the administrative limit.
	 */
	if ((nipq > (unsigned)maxnipq) && (maxnipq > 0)) {
		/*
		 * drop something from the tail of the current queue
		 * before proceeding further
		 */
		struct ipq *fq = TAILQ_LAST(head, ipqhead);
		if (fq == NULL) {   /* gak */
			for (i = 0; i < IPREASS_NHASH; i++) {
				struct ipq *r = TAILQ_LAST(&ipq[i], ipqhead);
				if (r) {
					ipstat.ips_fragtimeout += r->ipq_nfrags;
					frag_freef(&ipq[i], r);
					break;
				}
			}
		} else {
			ipstat.ips_fragtimeout += fq->ipq_nfrags;
			frag_freef(head, fq);
		}
	}

found:
	/*
	 * Leverage partial checksum offload for IP fragments.  Narrow down
	 * the scope to cover only UDP without IP options, as that is the
	 * most common case.
	 *
	 * Perform 1's complement adjustment of octets that got included/
	 * excluded in the hardware-calculated checksum value.  Ignore cases
	 * where the value includes or excludes the IP header span, as the
	 * sum for those octets would already be 0xffff and thus no-op.
	 */
	if (ip->ip_p == IPPROTO_UDP && hlen == sizeof (struct ip) &&
	    (m->m_pkthdr.csum_flags &
	    (CSUM_DATA_VALID | CSUM_PARTIAL | CSUM_PSEUDO_HDR)) ==
	    (CSUM_DATA_VALID | CSUM_PARTIAL)) {
		uint32_t start;

		start = m->m_pkthdr.csum_rx_start;
		csum = m->m_pkthdr.csum_rx_val;

		if (start != 0 && start != hlen) {
#if BYTE_ORDER != BIG_ENDIAN
			if (start < hlen) {
				HTONS(ip->ip_len);
				HTONS(ip->ip_off);
			}
#endif
			/* callee folds in sum */
			csum = m_adj_sum16(m, start, hlen, csum);
#if BYTE_ORDER != BIG_ENDIAN
			if (start < hlen) {
				NTOHS(ip->ip_off);
				NTOHS(ip->ip_len);
			}
#endif
		}
		csum_flags = m->m_pkthdr.csum_flags;
	} else {
		csum = 0;
		csum_flags = 0;
	}

	/* Invalidate checksum */
	m->m_pkthdr.csum_flags &= ~CSUM_DATA_VALID;

	ipstat.ips_fragments++;

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
			/*
			 * Reassembly queue may have been found if previous
			 * fragments were valid; given that this one is bad,
			 * we need to drop it.  Make sure to set fp to NULL
			 * if not already, since we don't want to decrement
			 * ipq_nfrags as it doesn't include this packet.
			 */
			fp = NULL;
			goto dropfrag;
		}
		m->m_flags |= M_FRAG;
	} else {
		/* Clear the flag in case packet comes from loopback */
		m->m_flags &= ~M_FRAG;
	}
	ip->ip_off <<= 3;

	m->m_pkthdr.pkt_hdr = ip;

	/* Previous ip_reass() started here. */
	/*
	 * Presence of header sizes in mbufs
	 * would confuse code below.
	 */
	m->m_data += hlen;
	m->m_len -= hlen;

	/*
	 * If first fragment to arrive, create a reassembly queue.
	 */
	if (fp == NULL) {
		fp = ipq_alloc(M_DONTWAIT);
		if (fp == NULL)
			goto dropfrag;
#if CONFIG_MACF_NET
		if (mac_ipq_label_init(fp, M_NOWAIT) != 0) {
			ipq_free(fp);
			fp = NULL;
			goto dropfrag;
		}
		mac_ipq_label_associate(m, fp);
#endif
		TAILQ_INSERT_HEAD(head, fp, ipq_list);
		nipq++;
		fp->ipq_nfrags = 1;
		fp->ipq_ttl = IPFRAGTTL;
		fp->ipq_p = ip->ip_p;
		fp->ipq_id = ip->ip_id;
		fp->ipq_src = ip->ip_src;
		fp->ipq_dst = ip->ip_dst;
		fp->ipq_frags = m;
		m->m_nextpkt = NULL;
		/*
		 * If the first fragment has valid checksum offload
		 * info, the rest of fragments are eligible as well.
		 */
		if (csum_flags != 0) {
			fp->ipq_csum = csum;
			fp->ipq_csum_flags = csum_flags;
		}
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
#endif /* IPDIVERT */
		m = NULL;	/* nothing to return */
		goto done;
	} else {
		fp->ipq_nfrags++;
#if CONFIG_MACF_NET
		mac_ipq_label_update(m, fp);
#endif
	}

#define	GETIP(m)	((struct ip *)((m)->m_pkthdr.pkt_hdr))

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
	 * If some of the data is dropped from the preceding
	 * segment, then it's checksum is invalidated.
	 */
	if (p) {
		i = GETIP(p)->ip_off + GETIP(p)->ip_len - ip->ip_off;
		if (i > 0) {
			if (i >= ip->ip_len)
				goto dropfrag;
			m_adj(m, i);
			fp->ipq_csum_flags = 0;
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
		i = (ip->ip_off + ip->ip_len) - GETIP(q)->ip_off;
		if (i < GETIP(q)->ip_len) {
			GETIP(q)->ip_len -= i;
			GETIP(q)->ip_off += i;
			m_adj(q, i);
			fp->ipq_csum_flags = 0;
			break;
		}
		nq = q->m_nextpkt;
		m->m_nextpkt = nq;
		ipstat.ips_fragdropped++;
		fp->ipq_nfrags--;
		/* defer freeing until after lock is dropped */
		MBUFQ_ENQUEUE(&dfq, q);
	}

	/*
	 * If this fragment contains similar checksum offload info
	 * as that of the existing ones, accumulate checksum.  Otherwise,
	 * invalidate checksum offload info for the entire datagram.
	 */
	if (csum_flags != 0 && csum_flags == fp->ipq_csum_flags)
		fp->ipq_csum += csum;
	else if (fp->ipq_csum_flags != 0)
		fp->ipq_csum_flags = 0;

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
#endif /* IPDIVERT */

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
				ipstat.ips_fragdropped += fp->ipq_nfrags;
				frag_freef(head, fp);
			}
			m = NULL;	/* nothing to return */
			goto done;
		}
		next += GETIP(q)->ip_len;
	}
	/* Make sure the last packet didn't have the IP_MF flag */
	if (p->m_flags & M_FRAG) {
		if (fp->ipq_nfrags > maxfragsperpacket) {
			ipstat.ips_fragdropped += fp->ipq_nfrags;
			frag_freef(head, fp);
		}
		m = NULL;		/* nothing to return */
		goto done;
	}

	/*
	 * Reassembly is complete.  Make sure the packet is a sane size.
	 */
	q = fp->ipq_frags;
	ip = GETIP(q);
	if (next + (IP_VHL_HL(ip->ip_vhl) << 2) > IP_MAXPACKET) {
		ipstat.ips_toolong++;
		ipstat.ips_fragdropped += fp->ipq_nfrags;
		frag_freef(head, fp);
		m = NULL;		/* nothing to return */
		goto done;
	}

	/*
	 * Concatenate fragments.
	 */
	m = q;
	t = m->m_next;
	m->m_next = NULL;
	m_cat(m, t);
	nq = q->m_nextpkt;
	q->m_nextpkt = NULL;
	for (q = nq; q != NULL; q = nq) {
		nq = q->m_nextpkt;
		q->m_nextpkt = NULL;
		m_cat(m, q);
	}

	/*
	 * Store partial hardware checksum info from the fragment queue;
	 * the receive start offset is set to 20 bytes (see code at the
	 * top of this routine.)
	 */
	if (fp->ipq_csum_flags != 0) {
		csum = fp->ipq_csum;

		ADDCARRY(csum);

		m->m_pkthdr.csum_rx_val = csum;
		m->m_pkthdr.csum_rx_start = sizeof (struct ip);
		m->m_pkthdr.csum_flags = fp->ipq_csum_flags;
	} else if ((m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK) ||
	    (m->m_pkthdr.pkt_flags & PKTF_LOOP)) {
		/* loopback checksums are always OK */
		m->m_pkthdr.csum_data = 0xffff;
		m->m_pkthdr.csum_flags &= ~CSUM_PARTIAL;
		m->m_pkthdr.csum_flags =
		    CSUM_DATA_VALID | CSUM_PSEUDO_HDR |
		    CSUM_IP_CHECKED | CSUM_IP_VALID;
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
#endif /* IPDIVERT */

#if CONFIG_MACF_NET
	mac_mbuf_label_associate_ipq(fp, m);
	mac_ipq_label_destroy(fp);
#endif
	/*
	 * Create header for new ip packet by modifying header of first
	 * packet; dequeue and discard fragment reassembly header.
	 * Make header visible.
	 */
	ip->ip_len = (IP_VHL_HL(ip->ip_vhl) << 2) + next;
	ip->ip_src = fp->ipq_src;
	ip->ip_dst = fp->ipq_dst;

	fp->ipq_frags = NULL;	/* return to caller as 'm' */
	frag_freef(head, fp);
	fp = NULL;

	m->m_len += (IP_VHL_HL(ip->ip_vhl) << 2);
	m->m_data -= (IP_VHL_HL(ip->ip_vhl) << 2);
	/* some debugging cruft by sklower, below, will go away soon */
	if (m->m_flags & M_PKTHDR)	/* XXX this should be done elsewhere */
		m_fixhdr(m);
	ipstat.ips_reassembled++;

	/* arm the purge timer if not already and if there's work to do */
	frag_sched_timeout();
	lck_mtx_unlock(&ipqlock);
	/* perform deferred free (if needed) now that lock is dropped */
	if (!MBUFQ_EMPTY(&dfq))
		MBUFQ_DRAIN(&dfq);
	VERIFY(MBUFQ_EMPTY(&dfq));
	return (m);

done:
	VERIFY(m == NULL);
	/* arm the purge timer if not already and if there's work to do */
	frag_sched_timeout();
	lck_mtx_unlock(&ipqlock);
	/* perform deferred free (if needed) */
	if (!MBUFQ_EMPTY(&dfq))
		MBUFQ_DRAIN(&dfq);
	VERIFY(MBUFQ_EMPTY(&dfq));
	return (NULL);

dropfrag:
#if IPDIVERT
	*divinfo = 0;
	*divcookie = 0;
#endif /* IPDIVERT */
	ipstat.ips_fragdropped++;
	if (fp != NULL)
		fp->ipq_nfrags--;
	/* arm the purge timer if not already and if there's work to do */
	frag_sched_timeout();
	lck_mtx_unlock(&ipqlock);
	m_freem(m);
	/* perform deferred free (if needed) */
	if (!MBUFQ_EMPTY(&dfq))
		MBUFQ_DRAIN(&dfq);
	VERIFY(MBUFQ_EMPTY(&dfq));
	return (NULL);
#undef GETIP
}

/*
 * Free a fragment reassembly header and all
 * associated datagrams.
 */
static void
frag_freef(struct ipqhead *fhp, struct ipq *fp)
{
	lck_mtx_assert(&ipqlock, LCK_MTX_ASSERT_OWNED);

	fp->ipq_nfrags = 0;
	if (fp->ipq_frags != NULL) {
		m_freem_list(fp->ipq_frags);
		fp->ipq_frags = NULL;
	}
	TAILQ_REMOVE(fhp, fp, ipq_list);
	nipq--;
	ipq_free(fp);
}

/*
 * IP reassembly timer processing
 */
static void
frag_timeout(void *arg)
{
#pragma unused(arg)
	struct ipq *fp;
	int i;

	/*
	 * Update coarse-grained networking timestamp (in sec.); the idea
	 * is to piggy-back on the timeout callout to update the counter
	 * returnable via net_uptime().
	 */
	net_update_uptime();

	lck_mtx_lock(&ipqlock);
	for (i = 0; i < IPREASS_NHASH; i++) {
		for (fp = TAILQ_FIRST(&ipq[i]); fp; ) {
			struct ipq *fpp;

			fpp = fp;
			fp = TAILQ_NEXT(fp, ipq_list);
			if (--fpp->ipq_ttl == 0) {
				ipstat.ips_fragtimeout += fpp->ipq_nfrags;
				frag_freef(&ipq[i], fpp);
			}
		}
	}
	/*
	 * If we are over the maximum number of fragments
	 * (due to the limit being lowered), drain off
	 * enough to get down to the new limit.
	 */
	if (maxnipq >= 0 && nipq > (unsigned)maxnipq) {
		for (i = 0; i < IPREASS_NHASH; i++) {
			while (nipq > (unsigned)maxnipq &&
			    !TAILQ_EMPTY(&ipq[i])) {
				ipstat.ips_fragdropped +=
				    TAILQ_FIRST(&ipq[i])->ipq_nfrags;
				frag_freef(&ipq[i], TAILQ_FIRST(&ipq[i]));
			}
		}
	}
	/* re-arm the purge timer if there's work to do */
	frag_timeout_run = 0;
	frag_sched_timeout();
	lck_mtx_unlock(&ipqlock);
}

static void
frag_sched_timeout(void)
{
	lck_mtx_assert(&ipqlock, LCK_MTX_ASSERT_OWNED);

	if (!frag_timeout_run && nipq > 0) {
		frag_timeout_run = 1;
		timeout(frag_timeout, NULL, hz);
	}
}

/*
 * Drain off all datagram fragments.
 */
static void
frag_drain(void)
{
	int i;

	lck_mtx_lock(&ipqlock);
	for (i = 0; i < IPREASS_NHASH; i++) {
		while (!TAILQ_EMPTY(&ipq[i])) {
			ipstat.ips_fragdropped +=
			    TAILQ_FIRST(&ipq[i])->ipq_nfrags;
			frag_freef(&ipq[i], TAILQ_FIRST(&ipq[i]));
		}
	}
	lck_mtx_unlock(&ipqlock);
}

static struct ipq *
ipq_alloc(int how)
{
	struct mbuf *t;
	struct ipq *fp;

	/*
	 * See comments in ipq_updateparams().  Keep the count separate
	 * from nipq since the latter represents the elements already
	 * in the reassembly queues.
	 */
	if (ipq_limit > 0 && ipq_count > ipq_limit)
		return (NULL);

	t = m_get(how, MT_FTABLE);
	if (t != NULL) {
		atomic_add_32(&ipq_count, 1);
		fp = mtod(t, struct ipq *);
		bzero(fp, sizeof (*fp));
	} else {
		fp = NULL;
	}
	return (fp);
}

static void
ipq_free(struct ipq *fp)
{
	(void) m_free(dtom(fp));
	atomic_add_32(&ipq_count, -1);
}

/*
 * Drain callback
 */
void
ip_drain(void)
{
	frag_drain();		/* fragments */
	in_rtqdrain();		/* protocol cloned routes */
	in_arpdrain(NULL);	/* cloned routes: ARP */
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
ip_dooptions(struct mbuf *m, int pass, struct sockaddr_in *next_hop)
{
#pragma unused(pass)
	struct ip *ip = mtod(m, struct ip *);
	u_char *cp;
	struct ip_timestamp *ipt;
	struct in_ifaddr *ia;
	int opt, optlen, cnt, off, code, type = ICMP_PARAMPROB, forward = 0;
	struct in_addr *sin, dst;
	u_int32_t ntime;
	struct sockaddr_in ipaddr = {
	    sizeof (ipaddr), AF_INET, 0, { 0 }, { 0, } };

	/* Expect 32-bit aligned data pointer on strict-align platforms */
	MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

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
			if (cnt < IPOPT_OLEN + sizeof (*cp)) {
				code = &cp[IPOPT_OLEN] - (u_char *)ip;
				goto bad;
			}
			optlen = cp[IPOPT_OLEN];
			if (optlen < IPOPT_OLEN + sizeof (*cp) ||
			    optlen > cnt) {
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
			if (optlen < IPOPT_OFFSET + sizeof (*cp)) {
				code = &cp[IPOPT_OLEN] - (u_char *)ip;
				goto bad;
			}
			if ((off = cp[IPOPT_OFFSET]) < IPOPT_MINOFF) {
				code = &cp[IPOPT_OFFSET] - (u_char *)ip;
				goto bad;
			}
			ipaddr.sin_addr = ip->ip_dst;
			ia = (struct in_ifaddr *)ifa_ifwithaddr(SA(&ipaddr));
			if (ia == NULL) {
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
			} else {
				IFA_REMREF(&ia->ia_ifa);
				ia = NULL;
			}
			off--;			/* 0 origin */
			if (off > optlen - (int)sizeof (struct in_addr)) {
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
					    "attempted source route from %s "
					    "to %s\n",
					    inet_ntop(AF_INET, &ip->ip_src,
					    buf, sizeof (buf)),
					    inet_ntop(AF_INET, &ip->ip_dst,
					    buf2, sizeof (buf2)));
					type = ICMP_UNREACH;
					code = ICMP_UNREACH_SRCFAIL;
					goto bad;
				} else {
					/*
					 * Not acting as a router,
					 * so silently drop.
					 */
					OSAddAtomic(1, &ipstat.ips_cantforward);
					m_freem(m);
					return (1);
				}
			}

			/*
			 * locate outgoing interface
			 */
			(void) memcpy(&ipaddr.sin_addr, cp + off,
			    sizeof (ipaddr.sin_addr));

			if (opt == IPOPT_SSRR) {
#define	INA	struct in_ifaddr *
				if ((ia = (INA)ifa_ifwithdstaddr(
				    SA(&ipaddr))) == NULL) {
					ia = (INA)ifa_ifwithnet(SA(&ipaddr));
				}
			} else {
				ia = ip_rtaddr(ipaddr.sin_addr);
			}
			if (ia == NULL) {
				type = ICMP_UNREACH;
				code = ICMP_UNREACH_SRCFAIL;
				goto bad;
			}
			ip->ip_dst = ipaddr.sin_addr;
			IFA_LOCK(&ia->ia_ifa);
			(void) memcpy(cp + off, &(IA_SIN(ia)->sin_addr),
			    sizeof (struct in_addr));
			IFA_UNLOCK(&ia->ia_ifa);
			IFA_REMREF(&ia->ia_ifa);
			ia = NULL;
			cp[IPOPT_OFFSET] += sizeof (struct in_addr);
			/*
			 * Let ip_intr's mcast routing check handle mcast pkts
			 */
			forward = !IN_MULTICAST(ntohl(ip->ip_dst.s_addr));
			break;

		case IPOPT_RR:
			if (optlen < IPOPT_OFFSET + sizeof (*cp)) {
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
			if (off > optlen - (int)sizeof (struct in_addr))
				break;
			(void) memcpy(&ipaddr.sin_addr, &ip->ip_dst,
			    sizeof (ipaddr.sin_addr));
			/*
			 * locate outgoing interface; if we're the destination,
			 * use the incoming interface (should be same).
			 */
			if ((ia = (INA)ifa_ifwithaddr(SA(&ipaddr))) == NULL) {
				if ((ia = ip_rtaddr(ipaddr.sin_addr)) == NULL) {
					type = ICMP_UNREACH;
					code = ICMP_UNREACH_HOST;
					goto bad;
				}
			}
			IFA_LOCK(&ia->ia_ifa);
			(void) memcpy(cp + off, &(IA_SIN(ia)->sin_addr),
			    sizeof (struct in_addr));
			IFA_UNLOCK(&ia->ia_ifa);
			IFA_REMREF(&ia->ia_ifa);
			ia = NULL;
			cp[IPOPT_OFFSET] += sizeof (struct in_addr);
			break;

		case IPOPT_TS:
			code = cp - (u_char *)ip;
			ipt = (struct ip_timestamp *)(void *)cp;
			if (ipt->ipt_len < 4 || ipt->ipt_len > 40) {
				code = (u_char *)&ipt->ipt_len - (u_char *)ip;
				goto bad;
			}
			if (ipt->ipt_ptr < 5) {
				code = (u_char *)&ipt->ipt_ptr - (u_char *)ip;
				goto bad;
			}
			if (ipt->ipt_ptr >
			    ipt->ipt_len - (int)sizeof (int32_t)) {
				if (++ipt->ipt_oflw == 0) {
					code = (u_char *)&ipt->ipt_ptr -
					    (u_char *)ip;
					goto bad;
				}
				break;
			}
			sin = (struct in_addr *)(void *)(cp + ipt->ipt_ptr - 1);
			switch (ipt->ipt_flg) {

			case IPOPT_TS_TSONLY:
				break;

			case IPOPT_TS_TSANDADDR:
				if (ipt->ipt_ptr - 1 + sizeof (n_time) +
				    sizeof (struct in_addr) > ipt->ipt_len) {
					code = (u_char *)&ipt->ipt_ptr -
					    (u_char *)ip;
					goto bad;
				}
				ipaddr.sin_addr = dst;
				ia = (INA)ifaof_ifpforaddr(SA(&ipaddr),
				    m->m_pkthdr.rcvif);
				if (ia == NULL)
					continue;
				IFA_LOCK(&ia->ia_ifa);
				(void) memcpy(sin, &IA_SIN(ia)->sin_addr,
				    sizeof (struct in_addr));
				IFA_UNLOCK(&ia->ia_ifa);
				ipt->ipt_ptr += sizeof (struct in_addr);
				IFA_REMREF(&ia->ia_ifa);
				ia = NULL;
				break;

			case IPOPT_TS_PRESPEC:
				if (ipt->ipt_ptr - 1 + sizeof (n_time) +
				    sizeof (struct in_addr) > ipt->ipt_len) {
					code = (u_char *)&ipt->ipt_ptr -
					    (u_char *)ip;
					goto bad;
				}
				(void) memcpy(&ipaddr.sin_addr, sin,
				    sizeof (struct in_addr));
				if ((ia = (struct in_ifaddr *)ifa_ifwithaddr(
				    SA(&ipaddr))) == NULL)
					continue;
				IFA_REMREF(&ia->ia_ifa);
				ia = NULL;
				ipt->ipt_ptr += sizeof (struct in_addr);
				break;

			default:
				/* XXX can't take &ipt->ipt_flg */
				code = (u_char *)&ipt->ipt_ptr -
				    (u_char *)ip + 1;
				goto bad;
			}
			ntime = iptime();
			(void) memcpy(cp + ipt->ipt_ptr - 1, &ntime,
			    sizeof (n_time));
			ipt->ipt_ptr += sizeof (n_time);
		}
	}
	if (forward && ipforwarding) {
		ip_forward(m, 1, next_hop);
		return (1);
	}
	return (0);
bad:
	icmp_error(m, type, code, 0, 0);
	OSAddAtomic(1, &ipstat.ips_badoptions);
	return (1);
}

/*
 * Check for the presence of the IP Router Alert option [RFC2113]
 * in the header of an IPv4 datagram.
 *
 * This call is not intended for use from the forwarding path; it is here
 * so that protocol domains may check for the presence of the option.
 * Given how FreeBSD's IPv4 stack is currently structured, the Router Alert
 * option does not have much relevance to the implementation, though this
 * may change in future.
 * Router alert options SHOULD be passed if running in IPSTEALTH mode and
 * we are not the endpoint.
 * Length checks on individual options should already have been peformed
 * by ip_dooptions() therefore they are folded under DIAGNOSTIC here.
 *
 * Return zero if not present or options are invalid, non-zero if present.
 */
int
ip_checkrouteralert(struct mbuf *m)
{
	struct ip *ip = mtod(m, struct ip *);
	u_char *cp;
	int opt, optlen, cnt, found_ra;

	found_ra = 0;
	cp = (u_char *)(ip + 1);
	cnt = (IP_VHL_HL(ip->ip_vhl) << 2) - sizeof (struct ip);
	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[IPOPT_OPTVAL];
		if (opt == IPOPT_EOL)
			break;
		if (opt == IPOPT_NOP)
			optlen = 1;
		else {
#ifdef DIAGNOSTIC
			if (cnt < IPOPT_OLEN + sizeof (*cp))
				break;
#endif
			optlen = cp[IPOPT_OLEN];
#ifdef DIAGNOSTIC
			if (optlen < IPOPT_OLEN + sizeof (*cp) || optlen > cnt)
				break;
#endif
		}
		switch (opt) {
		case IPOPT_RA:
#ifdef DIAGNOSTIC
			if (optlen != IPOPT_OFFSET + sizeof (uint16_t) ||
			    (*((uint16_t *)(void *)&cp[IPOPT_OFFSET]) != 0))
				break;
			else
#endif
				found_ra = 1;
			break;
		default:
			break;
		}
	}

	return (found_ra);
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
	sin = SIN(&ro.ro_dst);
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof (*sin);
	sin->sin_addr = dst;

	rtalloc_ign(&ro, RTF_PRCLONING);
	if (ro.ro_rt == NULL) {
		ROUTE_RELEASE(&ro);
		return (NULL);
	}

	RT_LOCK(ro.ro_rt);
	if ((rt_ifa = ro.ro_rt->rt_ifa) != NULL)
		IFA_ADDREF(rt_ifa);
	RT_UNLOCK(ro.ro_rt);
	ROUTE_RELEASE(&ro);

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
	if (olen > sizeof (ip_srcrt) - (1 + sizeof (dst)))
		return;
	bcopy(option, ip_srcrt.srcopt, olen);
	ip_nhops = (olen - IPOPT_OFFSET - 1) / sizeof (struct in_addr);
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
		return (NULL);

	m = m_get(M_DONTWAIT, MT_HEADER);
	if (m == NULL)
		return (NULL);

#define	OPTSIZ	(sizeof (ip_srcrt.nop) + sizeof (ip_srcrt.srcopt))

	/* length is (nhops+1)*sizeof(addr) + sizeof(nop + srcrt header) */
	m->m_len = ip_nhops * sizeof (struct in_addr) +
	    sizeof (struct in_addr) + OPTSIZ;
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
		printf(" hops %lx",
		    (u_int32_t)ntohl(mtod(m, struct in_addr *)->s_addr));
#endif

	/*
	 * Copy option fields and padding (nop) to mbuf.
	 */
	ip_srcrt.nop = IPOPT_NOP;
	ip_srcrt.srcopt[IPOPT_OFFSET] = IPOPT_MINOFF;
	(void) memcpy(mtod(m, caddr_t) + sizeof (struct in_addr),
	    &ip_srcrt.nop, OPTSIZ);
	q = (struct in_addr *)(void *)(mtod(m, caddr_t) +
	    sizeof (struct in_addr) + OPTSIZ);
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
ip_stripoptions(struct mbuf *m, struct mbuf *mopt)
{
#pragma unused(mopt)
	int i;
	struct ip *ip = mtod(m, struct ip *);
	caddr_t opts;
	int olen;

	/* Expect 32-bit aligned data pointer on strict-align platforms */
	MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	olen = (IP_VHL_HL(ip->ip_vhl) << 2) - sizeof (struct ip);
	opts = (caddr_t)(ip + 1);
	i = m->m_len - (sizeof (struct ip) + olen);
	bcopy(opts + olen, opts, (unsigned)i);
	m->m_len -= olen;
	if (m->m_flags & M_PKTHDR)
		m->m_pkthdr.len -= olen;
	ip->ip_vhl = IP_MAKE_VHL(IPVERSION, sizeof (struct ip) >> 2);
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
				ROUTE_RELEASE(&ifp->if_fwd_route);
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

	route_copyout(dst, src, sizeof (*dst));

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
		route_copyin(src, dst, sizeof (*src));

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
	u_int32_t nextmtu = 0, len;
	struct ip_out_args ipoa = { IFSCOPE_NONE, { 0 }, 0, 0 };
	struct ifnet *rcvifp = m->m_pkthdr.rcvif;
#if IPSEC
	struct secpolicy *sp = NULL;
	int ipsecerror;
#endif /* IPSEC */
#if PF
	struct pf_mtag *pf_mtag;
#endif /* PF */

	dest = 0;
#if IPFIREWALL
	/*
	 * Cache the destination address of the packet; this may be
	 * changed by use of 'ipfw fwd'.
	 */
	pkt_dst = ((next_hop != NULL) ? next_hop->sin_addr : ip->ip_dst);
#else /* !IPFIREWALL */
	pkt_dst = ip->ip_dst;
#endif /* !IPFIREWALL */

#if DIAGNOSTIC
	if (ipprintfs)
		printf("forward: src %lx dst %lx ttl %x\n",
		    (u_int32_t)ip->ip_src.s_addr, (u_int32_t)pkt_dst.s_addr,
		    ip->ip_ttl);
#endif

	if (m->m_flags & (M_BCAST|M_MCAST) || !in_canforward(pkt_dst)) {
		OSAddAtomic(1, &ipstat.ips_cantforward);
		m_freem(m);
		return;
	}
#if IPSTEALTH
	if (!ipstealth) {
#endif /* IPSTEALTH */
		if (ip->ip_ttl <= IPTTLDEC) {
			icmp_error(m, ICMP_TIMXCEED, ICMP_TIMXCEED_INTRANS,
			    dest, 0);
			return;
		}
#if IPSTEALTH
	}
#endif /* IPSTEALTH */

#if PF
	pf_mtag = pf_find_mtag(m);
	if (pf_mtag != NULL && pf_mtag->pftag_rtableid != IFSCOPE_NONE) {
		ipoa.ipoa_boundif = pf_mtag->pftag_rtableid;
		ipoa.ipoa_flags |= IPOAF_BOUND_IF;
	}
#endif /* PF */

	ip_fwd_route_copyout(rcvifp, &fwd_rt);

	sin = SIN(&fwd_rt.ro_dst);
	if (ROUTE_UNUSABLE(&fwd_rt) || pkt_dst.s_addr != sin->sin_addr.s_addr) {
		ROUTE_RELEASE(&fwd_rt);

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
#endif /* IPSTEALTH */
		ip->ip_ttl -= IPTTLDEC;
#if IPSTEALTH
	}
#endif /* IPSTEALTH */

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
	    !(rt->rt_flags & (RTF_DYNAMIC|RTF_MODIFIED)) &&
	    satosin(rt_key(rt))->sin_addr.s_addr != INADDR_ANY &&
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
			/*
			 * Router requirements says to only send
			 * host redirects.
			 */
			type = ICMP_REDIRECT;
			code = ICMP_REDIRECT_HOST;
#if DIAGNOSTIC
			if (ipprintfs)
				printf("redirect (%d) to %lx\n", code,
				    (u_int32_t)dest);
#endif
		}
		IFA_UNLOCK(&ia->ia_ifa);
	}
	RT_UNLOCK(rt);

#if IPFIREWALL
	if (next_hop != NULL) {
		/* Pass IPFORWARD info if available */
		struct m_tag *tag;
		struct ip_fwd_tag *ipfwd_tag;

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
#endif /* IPFIREWALL */

	/* Mark this packet as being forwarded from another interface */
	m->m_pkthdr.pkt_flags |= PKTF_FORWARDED;
	len = m_pktlen(m);

	error = ip_output(m, NULL, &fwd_rt, IP_FORWARDING | IP_OUTARGS,
	    NULL, &ipoa);

	/* Refresh rt since the route could have changed while in IP */
	rt = fwd_rt.ro_rt;

	if (error != 0) {
		OSAddAtomic(1, &ipstat.ips_cantforward);
	} else {
		/*
		 * Increment stats on the source interface; the ones
		 * for destination interface has been taken care of
		 * during output above by virtue of PKTF_FORWARDED.
		 */
		rcvifp->if_fpackets++;
		rcvifp->if_fbytes += len;

		OSAddAtomic(1, &ipstat.ips_forward);
		if (type != 0) {
			OSAddAtomic(1, &ipstat.ips_redirectsent);
		} else {
			if (mcopy != NULL) {
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

		if (rt == NULL) {
			break;
		} else {
			RT_LOCK_SPIN(rt);
			if (rt->rt_ifp != NULL)
				nextmtu = rt->rt_ifp->if_mtu;
			RT_UNLOCK(rt);
		}
#ifdef IPSEC
		if (ipsec_bypass)
			break;

		/*
		 * If the packet is routed over IPsec tunnel, tell the
		 * originator the tunnel MTU.
		 *	tunnel MTU = if MTU - sizeof(IP) - ESP/AH hdrsiz
		 * XXX quickhack!!!
		 */
		sp = ipsec4_getpolicybyaddr(mcopy, IPSEC_DIR_OUTBOUND,
		    IP_FORWARDING, &ipsecerror);

		if (sp == NULL)
			break;

		/*
		 * find the correct route for outer IPv4
		 * header, compute tunnel MTU.
		 */
		nextmtu = 0;

		if (sp->req != NULL &&
		    sp->req->saidx.mode == IPSEC_MODE_TUNNEL) {
			struct secasindex saidx;
			struct secasvar *sav;
			struct route *ro;
			struct ip *ipm;
			int ipsechdr;

			/* count IPsec header size */
			ipsechdr = ipsec_hdrsiz(sp);

			ipm = mtod(mcopy, struct ip *);
			bcopy(&sp->req->saidx, &saidx, sizeof (saidx));
			saidx.mode = sp->req->saidx.mode;
			saidx.reqid = sp->req->saidx.reqid;
			sin = SIN(&saidx.src);
			if (sin->sin_len == 0) {
				sin->sin_len = sizeof (*sin);
				sin->sin_family = AF_INET;
				sin->sin_port = IPSEC_PORT_ANY;
				bcopy(&ipm->ip_src, &sin->sin_addr,
				    sizeof (sin->sin_addr));
			}
			sin = SIN(&saidx.dst);
			if (sin->sin_len == 0) {
				sin->sin_len = sizeof (*sin);
				sin->sin_family = AF_INET;
				sin->sin_port = IPSEC_PORT_ANY;
				bcopy(&ipm->ip_dst, &sin->sin_addr,
				    sizeof (sin->sin_addr));
			}
			sav = key_allocsa_policy(&saidx);
			if (sav != NULL) {
				lck_mtx_lock(sadb_mutex);
				if (sav->sah != NULL) {
					ro = &sav->sah->sa_route;
					if (ro->ro_rt != NULL) {
						RT_LOCK(ro->ro_rt);
						if (ro->ro_rt->rt_ifp != NULL) {
							nextmtu = ro->ro_rt->
							    rt_ifp->if_mtu;
							nextmtu -= ipsechdr;
						}
						RT_UNLOCK(ro->ro_rt);
					}
				}
				key_freesav(sav, KEY_SADB_LOCKED);
				lck_mtx_unlock(sadb_mutex);
			}
		}
		key_freesp(sp, KEY_SADB_UNLOCKED);
#endif /* IPSEC */
		break;

	case ENOBUFS:
		/*
		 * A router should not generate ICMP_SOURCEQUENCH as
		 * required in RFC1812 Requirements for IP Version 4 Routers.
		 * Source quench could be a big problem under DoS attacks,
		 * or if the underlying interface is rate-limited.
		 * Those who need source quench packets may re-enable them
		 * via the net.inet.ip.sendsourcequench sysctl.
		 */
		if (ip_sendsourcequench == 0) {
			m_freem(mcopy);
			goto done;
		} else {
			type = ICMP_SOURCEQUENCH;
			code = 0;
		}
		break;

	case EACCES:			/* ipfw denied packet */
		m_freem(mcopy);
		goto done;
	}

	if (type == ICMP_UNREACH && code == ICMP_UNREACH_NEEDFRAG)
		OSAddAtomic(1, &ipstat.ips_cantfrag);

	icmp_error(mcopy, type, code, dest, nextmtu);
done:
	ip_fwd_route_copyin(rcvifp, &fwd_rt);
}

int
ip_savecontrol(struct inpcb *inp, struct mbuf **mp, struct ip *ip,
    struct mbuf *m)
{
	*mp = NULL;
	if (inp->inp_socket->so_options & SO_TIMESTAMP) {
		struct timeval tv;

		getmicrotime(&tv);
		mp = sbcreatecontrol_mbuf((caddr_t)&tv, sizeof (tv),
		    SCM_TIMESTAMP, SOL_SOCKET, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
	if (inp->inp_socket->so_options & SO_TIMESTAMP_MONOTONIC) {
		uint64_t time;

		time = mach_absolute_time();
		mp = sbcreatecontrol_mbuf((caddr_t)&time, sizeof (time),
		    SCM_TIMESTAMP_MONOTONIC, SOL_SOCKET, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
	if (inp->inp_flags & INP_RECVDSTADDR) {
		mp = sbcreatecontrol_mbuf((caddr_t)&ip->ip_dst,
		    sizeof (struct in_addr), IP_RECVDSTADDR, IPPROTO_IP, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
#ifdef notyet
	/*
	 * XXX
	 * Moving these out of udp_input() made them even more broken
	 * than they already were.
	 */
	/* options were tossed already */
	if (inp->inp_flags & INP_RECVOPTS) {
		mp = sbcreatecontrol_mbuf((caddr_t)opts_deleted_above,
		    sizeof (struct in_addr), IP_RECVOPTS, IPPROTO_IP, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
	/* ip_srcroute doesn't do what we want here, need to fix */
	if (inp->inp_flags & INP_RECVRETOPTS) {
		mp = sbcreatecontrol_mbuf((caddr_t)ip_srcroute(),
		    sizeof (struct in_addr), IP_RECVRETOPTS, IPPROTO_IP, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
#endif /* notyet */
	if (inp->inp_flags & INP_RECVIF) {
		struct ifnet *ifp;
		uint8_t sdlbuf[SOCK_MAXADDRLEN + 1];
		struct sockaddr_dl *sdl2 = SDL(&sdlbuf);

		/*
		 * Make sure to accomodate the largest possible
		 * size of SA(if_lladdr)->sa_len.
		 */
		_CASSERT(sizeof (sdlbuf) == (SOCK_MAXADDRLEN + 1));

		ifnet_head_lock_shared();
		if ((ifp = m->m_pkthdr.rcvif) != NULL &&
		    ifp->if_index && (ifp->if_index <= if_index)) {
			struct ifaddr *ifa = ifnet_addrs[ifp->if_index - 1];
			struct sockaddr_dl *sdp;

			if (!ifa || !ifa->ifa_addr)
				goto makedummy;

			IFA_LOCK_SPIN(ifa);
			sdp = SDL(ifa->ifa_addr);
			/*
			 * Change our mind and don't try copy.
			 */
			if (sdp->sdl_family != AF_LINK) {
				IFA_UNLOCK(ifa);
				goto makedummy;
			}
			/* the above _CASSERT ensures sdl_len fits in sdlbuf */
			bcopy(sdp, sdl2, sdp->sdl_len);
			IFA_UNLOCK(ifa);
		} else {
makedummy:
			sdl2->sdl_len =
			    offsetof(struct sockaddr_dl, sdl_data[0]);
			sdl2->sdl_family = AF_LINK;
			sdl2->sdl_index = 0;
			sdl2->sdl_nlen = sdl2->sdl_alen = sdl2->sdl_slen = 0;
		}
		ifnet_head_done();
		mp = sbcreatecontrol_mbuf((caddr_t)sdl2, sdl2->sdl_len,
		    IP_RECVIF, IPPROTO_IP, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
	if (inp->inp_flags & INP_RECVTTL) {
		mp = sbcreatecontrol_mbuf((caddr_t)&ip->ip_ttl,
		    sizeof (ip->ip_ttl), IP_RECVTTL, IPPROTO_IP, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
	if (inp->inp_socket->so_flags & SOF_RECV_TRAFFIC_CLASS) {
		int tc = m_get_traffic_class(m);

		mp = sbcreatecontrol_mbuf((caddr_t)&tc, sizeof (tc),
		    SO_TRAFFIC_CLASS, SOL_SOCKET, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
	if (inp->inp_flags & INP_PKTINFO) {
		struct in_pktinfo pi;

		bzero(&pi, sizeof (struct in_pktinfo));
		bcopy(&ip->ip_dst, &pi.ipi_addr, sizeof (struct in_addr));
		pi.ipi_ifindex = (m != NULL && m->m_pkthdr.rcvif != NULL) ?
		    m->m_pkthdr.rcvif->if_index : 0;

		mp = sbcreatecontrol_mbuf((caddr_t)&pi,
		    sizeof (struct in_pktinfo), IP_RECVPKTINFO, IPPROTO_IP, mp);
		if (*mp == NULL) {
			goto no_mbufs;
		}
	}
	return (0);

no_mbufs:
	ipstat.ips_pktdropcntrl++;
	return (ENOBUFS);
}

static inline u_short
ip_cksum(struct mbuf *m, int hlen)
{
	u_short sum;

	if (m->m_pkthdr.csum_flags & CSUM_IP_CHECKED) {
		sum = !(m->m_pkthdr.csum_flags & CSUM_IP_VALID);
	} else if (!(m->m_pkthdr.rcvif->if_flags & IFF_LOOPBACK) &&
	    !(m->m_pkthdr.pkt_flags & PKTF_LOOP)) {
		/*
		 * The packet arrived on an interface which isn't capable
		 * of performing IP header checksum; compute it now.
		 */
		sum = ip_cksum_hdr_in(m, hlen);
	} else {
		sum = 0;
		m->m_pkthdr.csum_flags |= (CSUM_DATA_VALID | CSUM_PSEUDO_HDR |
		    CSUM_IP_CHECKED | CSUM_IP_VALID);
		m->m_pkthdr.csum_data = 0xffff;
	}

	if (sum != 0)
		OSAddAtomic(1, &ipstat.ips_badsum);

	return (sum);
}

static int
ip_getstat SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	if (req->oldptr == USER_ADDR_NULL)
		req->oldlen = (size_t)sizeof (struct ipstat);

	return (SYSCTL_OUT(req, &ipstat, MIN(sizeof (ipstat), req->oldlen)));
}

void
ip_setsrcifaddr_info(struct mbuf *m, uint32_t src_idx, struct in_ifaddr *ia)
{
	VERIFY(m->m_flags & M_PKTHDR);

	/*
	 * If the source ifaddr is specified, pick up the information
	 * from there; otherwise just grab the passed-in ifindex as the
	 * caller may not have the ifaddr available.
	 */
	if (ia != NULL) {
		m->m_pkthdr.pkt_flags |= PKTF_IFAINFO;
		m->m_pkthdr.src_ifindex = ia->ia_ifp->if_index;
	} else {
		m->m_pkthdr.src_ifindex = src_idx;
		if (src_idx != 0)
			m->m_pkthdr.pkt_flags |= PKTF_IFAINFO;
	}
}

void
ip_setdstifaddr_info(struct mbuf *m, uint32_t dst_idx, struct in_ifaddr *ia)
{
	VERIFY(m->m_flags & M_PKTHDR);

	/*
	 * If the destination ifaddr is specified, pick up the information
	 * from there; otherwise just grab the passed-in ifindex as the
	 * caller may not have the ifaddr available.
	 */
	if (ia != NULL) {
		m->m_pkthdr.pkt_flags |= PKTF_IFAINFO;
		m->m_pkthdr.dst_ifindex = ia->ia_ifp->if_index;
	} else {
		m->m_pkthdr.dst_ifindex = dst_idx;
		if (dst_idx != 0)
			m->m_pkthdr.pkt_flags |= PKTF_IFAINFO;
	}
}

int
ip_getsrcifaddr_info(struct mbuf *m, uint32_t *src_idx, uint32_t *iaf)
{
	VERIFY(m->m_flags & M_PKTHDR);

	if (!(m->m_pkthdr.pkt_flags & PKTF_IFAINFO))
		return (-1);

	if (src_idx != NULL)
		*src_idx = m->m_pkthdr.src_ifindex;

	if (iaf != NULL)
		*iaf = 0;

	return (0);
}

int
ip_getdstifaddr_info(struct mbuf *m, uint32_t *dst_idx, uint32_t *iaf)
{
	VERIFY(m->m_flags & M_PKTHDR);

	if (!(m->m_pkthdr.pkt_flags & PKTF_IFAINFO))
		return (-1);

	if (dst_idx != NULL)
		*dst_idx = m->m_pkthdr.dst_ifindex;

	if (iaf != NULL)
		*iaf = 0;

	return (0);
}

/*
 * Protocol input handler for IPPROTO_GRE.
 */
void
gre_input(struct mbuf *m, int off)
{
	gre_input_func_t fn = gre_input_func;

	/*
	 * If there is a registered GRE input handler, pass mbuf to it.
	 */
	if (fn != NULL) {
		lck_mtx_unlock(inet_domain_mutex);
		m = fn(m, off, (mtod(m, struct ip *))->ip_p);
		lck_mtx_lock(inet_domain_mutex);
	}

	/*
	 * If no matching tunnel that is up is found, we inject
	 * the mbuf to raw ip socket to see if anyone picks it up.
	 */
	if (m != NULL)
		rip_input(m, off);
}

/*
 * Private KPI for PPP/PPTP.
 */
int
ip_gre_register_input(gre_input_func_t fn)
{
	lck_mtx_lock(inet_domain_mutex);
	gre_input_func = fn;
	lck_mtx_unlock(inet_domain_mutex);

	return (0);
}

static int
sysctl_reset_ip_input_stats SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, i;

	i = ip_input_measure;
	error = sysctl_handle_int(oidp, &i, 0, req);
	if (error || req->newptr == USER_ADDR_NULL)
		goto done;
	/* impose bounds */
	if (i < 0 || i > 1) {
		error = EINVAL;
		goto done;
	}
	if (ip_input_measure != i && i == 1) {
		net_perf_initialize(&net_perf, ip_input_measure_bins);
	}
	ip_input_measure = i;
done:
	return (error);
}

static int
sysctl_ip_input_measure_bins SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error;
	uint64_t i;

	i = ip_input_measure_bins;
	error = sysctl_handle_quad(oidp, &i, 0, req);
	if (error || req->newptr == USER_ADDR_NULL)
		goto done;
	/* validate data */
	if (!net_perf_validate_bins(i)) {
		error = EINVAL;
		goto done;
	}
	ip_input_measure_bins = i;
done:
	return (error);
}

static int
sysctl_ip_input_getperf SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	if (req->oldptr == USER_ADDR_NULL)
		req->oldlen = (size_t)sizeof (struct ipstat);

	return (SYSCTL_OUT(req, &net_perf, MIN(sizeof (net_perf), req->oldlen)));
}

