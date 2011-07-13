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
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
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
 *	@(#)tcp_subr.c	8.2 (Berkeley) 5/24/95
 * $FreeBSD: src/sys/netinet/tcp_subr.c,v 1.73.2.22 2001/08/22 00:59:12 silby Exp $
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/random.h>
#include <sys/syslog.h>
#include <sys/mcache.h>
#include <kern/locks.h>
#include <kern/zalloc.h>

#include <net/route.h>
#include <net/if.h>

#define tcp_minmssoverload fring
#define _IP_VHL
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#if INET6
#include <netinet/ip6.h>
#endif
#include <netinet/in_pcb.h>
#if INET6
#include <netinet6/in6_pcb.h>
#endif
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/icmp_var.h>
#if INET6
#include <netinet6/ip6_var.h>
#endif
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_cc.h>
#include <kern/thread_call.h>

#if INET6
#include <netinet6/tcp6_var.h>
#endif
#include <netinet/tcpip.h>
#if TCPDEBUG
#include <netinet/tcp_debug.h>
#endif
#include <netinet6/ip6protosw.h>

#if IPSEC
#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
#endif /*IPSEC*/

#undef tcp_minmssoverload

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif /* MAC_NET */

#include <libkern/crypto/md5.h>
#include <sys/kdebug.h>
#include <mach/sdt.h>

#define DBG_FNC_TCP_CLOSE	NETDBG_CODE(DBG_NETTCP, ((5 << 8) | 2))

extern int tcp_lq_overflow;

/* temporary: for testing */
#if IPSEC
extern int ipsec_bypass;
#endif

int 	tcp_mssdflt = TCP_MSS;
SYSCTL_INT(_net_inet_tcp, TCPCTL_MSSDFLT, mssdflt, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_mssdflt , 0, "Default TCP Maximum Segment Size");

#if INET6
int	tcp_v6mssdflt = TCP6_MSS;
SYSCTL_INT(_net_inet_tcp, TCPCTL_V6MSSDFLT, v6mssdflt,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_v6mssdflt , 0,
	"Default TCP Maximum Segment Size for IPv6");
#endif

/*
 * Minimum MSS we accept and use. This prevents DoS attacks where
 * we are forced to a ridiculous low MSS like 20 and send hundreds
 * of packets instead of one. The effect scales with the available
 * bandwidth and quickly saturates the CPU and network interface
 * with packet generation and sending. Set to zero to disable MINMSS
 * checking. This setting prevents us from sending too small packets.
 */
int	tcp_minmss = TCP_MINMSS;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, minmss, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_minmss , 0, "Minmum TCP Maximum Segment Size");

/*
 * Number of TCP segments per second we accept from remote host
 * before we start to calculate average segment size. If average
 * segment size drops below the minimum TCP MSS we assume a DoS
 * attack and reset+drop the connection. Care has to be taken not to
 * set this value too small to not kill interactive type connections
 * (telnet, SSH) which send many small packets.
 */
#ifdef FIX_WORKAROUND_FOR_3894301
__private_extern__ int     tcp_minmssoverload = TCP_MINMSSOVERLOAD;
#else
__private_extern__ int     tcp_minmssoverload = 0;
#endif
SYSCTL_INT(_net_inet_tcp, OID_AUTO, minmssoverload, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_minmssoverload , 0, "Number of TCP Segments per Second allowed to"
    "be under the MINMSS Size");

static int	tcp_do_rfc1323 = 1;
SYSCTL_INT(_net_inet_tcp, TCPCTL_DO_RFC1323, rfc1323, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_do_rfc1323 , 0, "Enable rfc1323 (high performance TCP) extensions");

// Not used
static int	tcp_do_rfc1644 = 0;
SYSCTL_INT(_net_inet_tcp, TCPCTL_DO_RFC1644, rfc1644, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_do_rfc1644 , 0, "Enable rfc1644 (TTCP) extensions");

static int	do_tcpdrain = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, do_tcpdrain, CTLFLAG_RW | CTLFLAG_LOCKED, &do_tcpdrain, 0,
     "Enable tcp_drain routine for extra help when low on mbufs");

SYSCTL_INT(_net_inet_tcp, OID_AUTO, pcbcount, CTLFLAG_RD | CTLFLAG_LOCKED, 
    &tcbinfo.ipi_count, 0, "Number of active PCBs");

static int	icmp_may_rst = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, icmp_may_rst, CTLFLAG_RW | CTLFLAG_LOCKED, &icmp_may_rst, 0, 
    "Certain ICMP unreachable messages may abort connections in SYN_SENT");

static int	tcp_strict_rfc1948 = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, strict_rfc1948, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_strict_rfc1948, 0, "Determines if RFC1948 is followed exactly");

static int	tcp_isn_reseed_interval = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, isn_reseed_interval, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_isn_reseed_interval, 0, "Seconds between reseeding of ISN secret");
static int 	tcp_background_io_enabled = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, background_io_enabled, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_background_io_enabled, 0, "Background IO Enabled");

int 	tcp_TCPTV_MIN = 100;	/* 100ms minimum RTT */
SYSCTL_INT(_net_inet_tcp, OID_AUTO, rtt_min, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_TCPTV_MIN, 0, "min rtt value allowed");

int tcp_rexmt_slop = TCPTV_REXMTSLOP;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, rexmt_slop, CTLFLAG_RW,
	&tcp_rexmt_slop, 0, "Slop added to retransmit timeout");

__private_extern__ int tcp_use_randomport = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, randomize_ports, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_use_randomport, 0, "Randomize TCP port numbers");

extern struct tcp_cc_algo tcp_cc_newreno;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, newreno_sockets, CTLFLAG_RD | CTLFLAG_LOCKED,
	&tcp_cc_newreno.num_sockets, 0, "Number of sockets using newreno");

extern struct tcp_cc_algo tcp_cc_ledbat;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, background_sockets, CTLFLAG_RD | CTLFLAG_LOCKED,
	&tcp_cc_ledbat.num_sockets, 0, "Number of sockets using background transport");

static void	tcp_cleartaocache(void);
static void	tcp_notify(struct inpcb *, int);
static void	tcp_cc_init(void);

struct zone	*sack_hole_zone;
struct zone	*tcp_reass_zone;

/* The array containing pointers to currently implemented TCP CC algorithms */
struct tcp_cc_algo* tcp_cc_algo_list[TCP_CC_ALGO_COUNT];

extern unsigned int total_mb_cnt;
extern unsigned int total_cl_cnt;
extern int sbspace_factor;
extern int tcp_sockthreshold;
extern int slowlink_wsize;	/* window correction for slow links */
extern int path_mtu_discovery;


/*
 * Target size of TCP PCB hash tables. Must be a power of two.
 *
 * Note that this can be overridden by the kernel environment
 * variable net.inet.tcp.tcbhashsize
 */
#ifndef TCBHASHSIZE
#define TCBHASHSIZE	CONFIG_TCBHASHSIZE
#endif

__private_extern__ int	tcp_tcbhashsize = TCBHASHSIZE;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, tcbhashsize, CTLFLAG_RD | CTLFLAG_LOCKED,
     &tcp_tcbhashsize, 0, "Size of TCP control-block hashtable");

/*
 * This is the actual shape of what we allocate using the zone
 * allocator.  Doing it this way allows us to protect both structures
 * using the same generation count, and also eliminates the overhead
 * of allocating tcpcbs separately.  By hiding the structure here,
 * we avoid changing most of the rest of the code (although it needs
 * to be changed, eventually, for greater efficiency).
 */
#define	ALIGNMENT	32
struct	inp_tp {
	struct	inpcb	inp;
	struct	tcpcb	tcb __attribute__((aligned(ALIGNMENT)));
};
#undef ALIGNMENT

extern struct	inpcbhead	time_wait_slots[];
extern struct tcptimerlist tcp_timer_list;

int  get_inpcb_str_size(void);
int  get_tcp_str_size(void);

static void tcpcb_to_otcpcb(struct tcpcb *, struct otcpcb *);

static lck_attr_t *tcp_uptime_mtx_attr = NULL;		/* mutex attributes */
static lck_grp_t *tcp_uptime_mtx_grp = NULL;		/* mutex group definition */
static lck_grp_attr_t *tcp_uptime_mtx_grp_attr = NULL;	/* mutex group attributes */


int  get_inpcb_str_size(void)
{
	return sizeof(struct inpcb);
}


int  get_tcp_str_size(void)
{
	return sizeof(struct tcpcb);
}

int	tcp_freeq(struct tcpcb *tp);

/*
 * Initialize TCP congestion control algorithms.
 */

void
tcp_cc_init(void)
{
	bzero(&tcp_cc_algo_list, sizeof(tcp_cc_algo_list));
	tcp_cc_algo_list[TCP_CC_ALGO_NEWRENO_INDEX] = &tcp_cc_newreno;
	tcp_cc_algo_list[TCP_CC_ALGO_BACKGROUND_INDEX] = &tcp_cc_ledbat;
}

/*
 * Tcp initialization
 */
void
tcp_init()
{
	vm_size_t       str_size;
	int i;
    	struct inpcbinfo *pcbinfo;
	
	tcp_ccgen = 1;
	tcp_cleartaocache();

	tcp_keepinit = TCPTV_KEEP_INIT;
	tcp_keepidle = TCPTV_KEEP_IDLE;
	tcp_keepintvl = TCPTV_KEEPINTVL;
	tcp_maxpersistidle = TCPTV_KEEP_IDLE;
	tcp_msl = TCPTV_MSL;

	microuptime(&tcp_uptime);
	read_random(&tcp_now, sizeof(tcp_now));
	tcp_now = tcp_now & 0x3fffffff; /* Starts tcp internal clock at a random value */

	LIST_INIT(&tcb);
	tcbinfo.listhead = &tcb;
	pcbinfo = &tcbinfo;
	if (!powerof2(tcp_tcbhashsize)) {
		printf("WARNING: TCB hash size not a power of 2\n");
		tcp_tcbhashsize = 512; /* safe default */
	}
	tcbinfo.hashsize = tcp_tcbhashsize;
	tcbinfo.hashbase = hashinit(tcp_tcbhashsize, M_PCB, &tcbinfo.hashmask);
	tcbinfo.porthashbase = hashinit(tcp_tcbhashsize, M_PCB,
					&tcbinfo.porthashmask);
	str_size = P2ROUNDUP(sizeof(struct inp_tp), sizeof(u_int64_t));
	tcbinfo.ipi_zone = (void *) zinit(str_size, 120000*str_size, 8192, "tcpcb");
	zone_change(tcbinfo.ipi_zone, Z_CALLERACCT, FALSE);
	zone_change(tcbinfo.ipi_zone, Z_EXPAND, TRUE);

	str_size = P2ROUNDUP(sizeof(struct sackhole), sizeof(u_int64_t));
	sack_hole_zone = zinit(str_size, 120000*str_size, 8192, "sack_hole zone");
	zone_change(sack_hole_zone, Z_CALLERACCT, FALSE);
	zone_change(sack_hole_zone, Z_EXPAND, TRUE);

	tcp_reass_maxseg = nmbclusters / 16;
	str_size = P2ROUNDUP(sizeof(struct tseg_qent), sizeof(u_int64_t));
	tcp_reass_zone = zinit(str_size, (tcp_reass_maxseg + 1) * str_size,
		0, "tcp_reass_zone");
	if (tcp_reass_zone == NULL) {
		panic("%s: failed allocating tcp_reass_zone", __func__);
		/* NOTREACHED */
	}
	zone_change(tcp_reass_zone, Z_CALLERACCT, FALSE);
	zone_change(tcp_reass_zone, Z_EXPAND, TRUE);

#if INET6
#define TCP_MINPROTOHDR (sizeof(struct ip6_hdr) + sizeof(struct tcphdr))
#else /* INET6 */
#define TCP_MINPROTOHDR (sizeof(struct tcpiphdr))
#endif /* INET6 */
	if (max_protohdr < TCP_MINPROTOHDR)
		max_protohdr = TCP_MINPROTOHDR;
	if (max_linkhdr + TCP_MINPROTOHDR > MHLEN)
		panic("tcp_init");
#undef TCP_MINPROTOHDR

	/*
	 * allocate lock group attribute and group for tcp pcb mutexes
	 */
	pcbinfo->mtx_grp_attr = lck_grp_attr_alloc_init();
	pcbinfo->mtx_grp = lck_grp_alloc_init("tcppcb", pcbinfo->mtx_grp_attr);
		
	/*
	 * allocate the lock attribute for tcp pcb mutexes
	 */
	pcbinfo->mtx_attr = lck_attr_alloc_init();

	if ((pcbinfo->mtx = lck_rw_alloc_init(pcbinfo->mtx_grp, pcbinfo->mtx_attr)) == NULL) {
		printf("tcp_init: mutex not alloced!\n");
		return;	/* pretty much dead if this fails... */
	}

	for (i=0; i < N_TIME_WAIT_SLOTS; i++) {
	     LIST_INIT(&time_wait_slots[i]);
	}

	bzero(&tcp_timer_list, sizeof(tcp_timer_list));
	LIST_INIT(&tcp_timer_list.lhead);
	/*
	 * allocate lock group attribute, group and attribute for the tcp timer list
	 */
	tcp_timer_list.mtx_grp_attr = lck_grp_attr_alloc_init();
	tcp_timer_list.mtx_grp = lck_grp_alloc_init("tcptimerlist", tcp_timer_list.mtx_grp_attr);
	tcp_timer_list.mtx_attr = lck_attr_alloc_init();
	if ((tcp_timer_list.mtx = lck_mtx_alloc_init(tcp_timer_list.mtx_grp, tcp_timer_list.mtx_attr)) == NULL) {
		panic("failed to allocate memory for tcp_timer_list.mtx\n");
	};
	tcp_timer_list.fast_quantum = TCP_FASTTIMER_QUANTUM;
	tcp_timer_list.slow_quantum = TCP_SLOWTIMER_QUANTUM;
	if ((tcp_timer_list.call = thread_call_allocate(tcp_run_timerlist, NULL)) == NULL) {
		panic("failed to allocate call entry 1 in tcp_init\n");
	}

	/*
	 * allocate lock group attribute, group and attribute for tcp_uptime_lock
	 */
	tcp_uptime_mtx_grp_attr = lck_grp_attr_alloc_init();
	tcp_uptime_mtx_grp = lck_grp_alloc_init("tcpuptime", tcp_uptime_mtx_grp_attr);
	tcp_uptime_mtx_attr = lck_attr_alloc_init();
	tcp_uptime_lock = lck_spin_alloc_init(tcp_uptime_mtx_grp, tcp_uptime_mtx_attr);

	/* Initialize TCP congestion control algorithms list */
	tcp_cc_init();
}

/*
 * Fill in the IP and TCP headers for an outgoing packet, given the tcpcb.
 * tcp_template used to store this data in mbufs, but we now recopy it out
 * of the tcpcb each time to conserve mbufs.
 */
void
tcp_fillheaders(tp, ip_ptr, tcp_ptr)
	struct tcpcb *tp;
	void *ip_ptr;
	void *tcp_ptr;
{
	struct inpcb *inp = tp->t_inpcb;
	struct tcphdr *tcp_hdr = (struct tcphdr *)tcp_ptr;

#if INET6
	if ((inp->inp_vflag & INP_IPV6) != 0) {
		struct ip6_hdr *ip6;

		ip6 = (struct ip6_hdr *)ip_ptr;
		ip6->ip6_flow = (ip6->ip6_flow & ~IPV6_FLOWINFO_MASK) |
			(inp->in6p_flowinfo & IPV6_FLOWINFO_MASK);
		ip6->ip6_vfc = (ip6->ip6_vfc & ~IPV6_VERSION_MASK) |
			(IPV6_VERSION & IPV6_VERSION_MASK);
		ip6->ip6_nxt = IPPROTO_TCP;
		ip6->ip6_plen = sizeof(struct tcphdr);
		ip6->ip6_src = inp->in6p_laddr;
		ip6->ip6_dst = inp->in6p_faddr;
		tcp_hdr->th_sum = in6_cksum_phdr(&inp->in6p_laddr,
		    &inp->in6p_faddr, htonl(sizeof(struct tcphdr)),
		    htonl(IPPROTO_TCP));
	} else
#endif
	{
	struct ip *ip = (struct ip *) ip_ptr;

	ip->ip_vhl = IP_VHL_BORING;
	ip->ip_tos = 0;
	ip->ip_len = 0;
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_ttl = 0;
	ip->ip_sum = 0;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_src = inp->inp_laddr;
	ip->ip_dst = inp->inp_faddr;
	tcp_hdr->th_sum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
		htons(sizeof(struct tcphdr) + IPPROTO_TCP));
	}

	tcp_hdr->th_sport = inp->inp_lport;
	tcp_hdr->th_dport = inp->inp_fport;
	tcp_hdr->th_seq = 0;
	tcp_hdr->th_ack = 0;
	tcp_hdr->th_x2 = 0;
	tcp_hdr->th_off = 5;
	tcp_hdr->th_flags = 0;
	tcp_hdr->th_win = 0;
	tcp_hdr->th_urp = 0;
}

/*
 * Create template to be used to send tcp packets on a connection.
 * Allocates an mbuf and fills in a skeletal tcp/ip header.  The only
 * use for this function is in keepalives, which use tcp_respond.
 */
struct tcptemp *
tcp_maketemplate(tp)
	struct tcpcb *tp;
{
	struct mbuf *m;
	struct tcptemp *n;

	m = m_get(M_DONTWAIT, MT_HEADER);
	if (m == NULL)
		return (0);
	m->m_len = sizeof(struct tcptemp);
	n = mtod(m, struct tcptemp *);

	tcp_fillheaders(tp, (void *)&n->tt_ipgen, (void *)&n->tt_t);
	return (n);
}

/*
 * Send a single message to the TCP at address specified by
 * the given TCP/IP header.  If m == 0, then we make a copy
 * of the tcpiphdr at ti and send directly to the addressed host.
 * This is used to force keep alive messages out using the TCP
 * template for a connection.  If flags are given then we send
 * a message back to the TCP which originated the * segment ti,
 * and discard the mbuf containing it and any other attached mbufs.
 *
 * In any case the ack and sequence number of the transmitted
 * segment are as specified by the parameters.
 *
 * NOTE: If m != NULL, then ti must point to *inside* the mbuf.
 */
void
tcp_respond(
	struct tcpcb *tp,
	void *ipgen,
	register struct tcphdr *th,
	register struct mbuf *m,
	tcp_seq ack,
	tcp_seq seq,
	int flags,
	unsigned int ifscope,
	unsigned int nocell
	)
{
	register int tlen;
	int win = 0;
	struct route *ro = 0;
	struct route sro;
	struct ip *ip;
	struct tcphdr *nth;
#if INET6
	struct route_in6 *ro6 = 0;
	struct route_in6 sro6;
	struct ip6_hdr *ip6;
	int isipv6;
#endif /* INET6 */
	unsigned int outif;

#if INET6
	isipv6 = IP_VHL_V(((struct ip *)ipgen)->ip_vhl) == 6;
	ip6 = ipgen;
#endif /* INET6 */
	ip = ipgen;

	if (tp) {
		if (!(flags & TH_RST)) {
			win = tcp_sbspace(tp);
			if (win > (int32_t)TCP_MAXWIN << tp->rcv_scale)
				win = (int32_t)TCP_MAXWIN << tp->rcv_scale;
		}
#if INET6
		if (isipv6)
			ro6 = &tp->t_inpcb->in6p_route;
		else
#endif /* INET6 */
		ro = &tp->t_inpcb->inp_route;
	} else {
#if INET6
		if (isipv6) {
			ro6 = &sro6;
			bzero(ro6, sizeof *ro6);
		} else
#endif /* INET6 */
		{
			ro = &sro;
			bzero(ro, sizeof *ro);
		}
	}
	if (m == 0) {
		m = m_gethdr(M_DONTWAIT, MT_HEADER);	/* MAC-OK */
		if (m == NULL)
			return;
		tlen = 0;
		m->m_data += max_linkhdr;
#if INET6
		if (isipv6) {
			bcopy((caddr_t)ip6, mtod(m, caddr_t), 
			      sizeof(struct ip6_hdr));
			ip6 = mtod(m, struct ip6_hdr *);
			nth = (struct tcphdr *)(ip6 + 1);
		} else
#endif /* INET6 */
		{
			bcopy((caddr_t)ip, mtod(m, caddr_t), sizeof(struct ip));
			ip = mtod(m, struct ip *);
			nth = (struct tcphdr *)(ip + 1);
		}
		bcopy((caddr_t)th, (caddr_t)nth, sizeof(struct tcphdr));
		flags = TH_ACK;
	} else {
		m_freem(m->m_next);
		m->m_next = 0;
		m->m_data = (caddr_t)ipgen;
		/* m_len is set later */
		tlen = 0;
#define xchg(a,b,type) { type t; t=a; a=b; b=t; }
#if INET6
		if (isipv6) {
			xchg(ip6->ip6_dst, ip6->ip6_src, struct in6_addr);
			nth = (struct tcphdr *)(ip6 + 1);
		} else
#endif /* INET6 */
	      {
		xchg(ip->ip_dst.s_addr, ip->ip_src.s_addr, n_long);
		nth = (struct tcphdr *)(ip + 1);
	      }
		if (th != nth) {
			/*
			 * this is usually a case when an extension header
			 * exists between the IPv6 header and the
			 * TCP header.
			 */
			nth->th_sport = th->th_sport;
			nth->th_dport = th->th_dport;
		}
		xchg(nth->th_dport, nth->th_sport, n_short);
#undef xchg
	}
#if INET6
	if (isipv6) {
		ip6->ip6_plen = htons((u_short)(sizeof (struct tcphdr) +
						tlen));
		tlen += sizeof (struct ip6_hdr) + sizeof (struct tcphdr);
	} else
#endif
      {
	tlen += sizeof (struct tcpiphdr);
	ip->ip_len = tlen;
	ip->ip_ttl = ip_defttl;
      }
	m->m_len = tlen;
	m->m_pkthdr.len = tlen;
	m->m_pkthdr.rcvif = 0;
#if CONFIG_MACF_NET
	if (tp != NULL && tp->t_inpcb != NULL) {
		/*
		 * Packet is associated with a socket, so allow the
		 * label of the response to reflect the socket label.
		 */
		mac_mbuf_label_associate_inpcb(tp->t_inpcb, m);
	} else {
		/*
		 * Packet is not associated with a socket, so possibly
		 * update the label in place.
		 */
		mac_netinet_tcp_reply(m);
	}
#endif

	nth->th_seq = htonl(seq);
	nth->th_ack = htonl(ack);
	nth->th_x2 = 0;
	nth->th_off = sizeof (struct tcphdr) >> 2;
	nth->th_flags = flags;
	if (tp)
		nth->th_win = htons((u_short) (win >> tp->rcv_scale));
	else
		nth->th_win = htons((u_short)win);
	nth->th_urp = 0;
#if INET6
	if (isipv6) {
		nth->th_sum = 0;
		nth->th_sum = in6_cksum_phdr(&ip6->ip6_src,
		    &ip6->ip6_dst, htons((u_short)(tlen - sizeof(struct ip6_hdr))),
		    		htonl(IPPROTO_TCP));
		m->m_pkthdr.csum_flags = CSUM_TCPIPV6;
		m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
		ip6->ip6_hlim = in6_selecthlim(tp ? tp->t_inpcb : NULL,
					       ro6 && ro6->ro_rt ?
					       ro6->ro_rt->rt_ifp :
					       NULL);
	} else
#endif /* INET6 */
	{
		nth->th_sum = in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
		htons((u_short)(tlen - sizeof(struct ip) + ip->ip_p)));
		m->m_pkthdr.csum_flags = CSUM_TCP;
		m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
	}
#if TCPDEBUG
	if (tp == NULL || (tp->t_inpcb->inp_socket->so_options & SO_DEBUG))
		tcp_trace(TA_OUTPUT, 0, tp, mtod(m, void *), th, 0);
#endif
#if IPSEC
	if (ipsec_bypass == 0 && ipsec_setsocket(m, tp ? tp->t_inpcb->inp_socket : NULL) != 0) {
		m_freem(m);
		return;
	}
#endif

	if (tp != NULL)
		set_packet_tclass(m, tp->t_inpcb->inp_socket, MBUF_TC_UNSPEC, isipv6);

#if INET6
	if (isipv6) {
		struct ip6_out_args ip6oa = { ifscope, nocell };

		(void) ip6_output(m, NULL, ro6, IPV6_OUTARGS, NULL,
		    NULL, &ip6oa);
		if (ro6->ro_rt != NULL) {
			if (ro6 == &sro6) {
				rtfree(ro6->ro_rt);
				ro6->ro_rt = NULL;
			} else if ((outif = ro6->ro_rt->rt_ifp->if_index) !=
			    tp->t_inpcb->in6p_last_outif) {
				tp->t_inpcb->in6p_last_outif = outif;
			}
		}
	} else
#endif /* INET6 */
	{
		struct ip_out_args ipoa = { ifscope, nocell };

		if (ro != &sro) {
			/* Copy the cached route and take an extra reference */
			inp_route_copyout(tp->t_inpcb, &sro);
		}
		/*
		 * For consistency, pass a local route copy.
		 */
		(void) ip_output(m, NULL, &sro, IP_OUTARGS, NULL, &ipoa);

		if (ro != &sro) {
			if (sro.ro_rt != NULL &&
			    (outif = sro.ro_rt->rt_ifp->if_index) !=
			    tp->t_inpcb->inp_last_outif)
				tp->t_inpcb->inp_last_outif = outif;
			/* Synchronize cached PCB route */
			inp_route_copyin(tp->t_inpcb, &sro);
		} else if (sro.ro_rt != NULL) {
			rtfree(sro.ro_rt);
		}
	}
}

/*
 * Create a new TCP control block, making an
 * empty reassembly queue and hooking it to the argument
 * protocol control block.  The `inp' parameter must have
 * come from the zone allocator set up in tcp_init().
 */
struct tcpcb *
tcp_newtcpcb(inp)
	struct inpcb *inp;
{
	struct inp_tp *it;
	register struct tcpcb *tp;
	register struct socket *so = inp->inp_socket;	
#if INET6
	int isipv6 = (inp->inp_vflag & INP_IPV6) != 0;
#endif /* INET6 */

	calculate_tcp_clock();

	if (so->cached_in_sock_layer == 0) {
	     it = (struct inp_tp *)inp;
	     tp = &it->tcb;
	}
	else
	     tp = (struct tcpcb *) inp->inp_saved_ppcb;
	
	bzero((char *) tp, sizeof(struct tcpcb));
	LIST_INIT(&tp->t_segq);
	tp->t_maxseg = tp->t_maxopd =
#if INET6
		isipv6 ? tcp_v6mssdflt :
#endif /* INET6 */
		tcp_mssdflt;

	if (tcp_do_rfc1323)
		tp->t_flags = (TF_REQ_SCALE|TF_REQ_TSTMP);
	tp->sack_enable = tcp_do_sack;
	TAILQ_INIT(&tp->snd_holes);
	tp->t_inpcb = inp;	/* XXX */
	/*
	 * Init srtt to TCPTV_SRTTBASE (0), so we can tell that we have no
	 * rtt estimate.  Set rttvar so that srtt + 4 * rttvar gives
	 * reasonable initial retransmit time.
	 */
	tp->t_srtt = TCPTV_SRTTBASE;
	tp->t_rttvar = ((TCPTV_RTOBASE - TCPTV_SRTTBASE) << TCP_RTTVAR_SHIFT) / 4;
	tp->t_rttmin = tcp_TCPTV_MIN;
	tp->t_rxtcur = TCPTV_RTOBASE;

	/* Initialize congestion control algorithm for this connection 
	 * to newreno by default
	 */
	tp->tcp_cc_index = TCP_CC_ALGO_NEWRENO_INDEX;
	if (CC_ALGO(tp)->init != NULL) {
		CC_ALGO(tp)->init(tp);
	}

	tp->snd_cwnd = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	tp->snd_bwnd = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	tp->snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	tp->snd_ssthresh_prev = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	tp->t_rcvtime = tcp_now;
	tp->t_bw_rtttime = 0;
	tp->tentry.timer_start = tcp_now;
	tp->t_persist_timeout = tcp_max_persist_timeout;
	tp->t_persist_stop = 0;
	tp->t_flagsext |= TF_RCVUNACK_WAITSS;
	/*
	 * IPv4 TTL initialization is necessary for an IPv6 socket as well,
	 * because the socket may be bound to an IPv6 wildcard address,
	 * which may match an IPv4-mapped IPv6 address.
	 */
	inp->inp_ip_ttl = ip_defttl;
	inp->inp_ppcb = (caddr_t)tp;
	return (tp);		/* XXX */
}

/*
 * Drop a TCP connection, reporting
 * the specified error.  If connection is synchronized,
 * then send a RST to peer.
 */
struct tcpcb *
tcp_drop(tp, errno)
	register struct tcpcb *tp;
	int errno;
{
	struct socket *so = tp->t_inpcb->inp_socket;
#if CONFIG_DTRACE
	struct inpcb *inp = tp->t_inpcb;
#endif /* CONFIG_DTRACE */

	if (TCPS_HAVERCVDSYN(tp->t_state)) {
		DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
			struct tcpcb *, tp, int32_t, TCPS_CLOSED);
		tp->t_state = TCPS_CLOSED;
		(void) tcp_output(tp);
		tcpstat.tcps_drops++;
	} else
		tcpstat.tcps_conndrops++;
	if (errno == ETIMEDOUT && tp->t_softerror)
		errno = tp->t_softerror;
	so->so_error = errno;
	return (tcp_close(tp));
}

/*
 * Close a TCP control block:
 *	discard all space held by the tcp
 *	discard internet protocol block
 *	wake up any sleepers
 */
struct tcpcb *
tcp_close(tp)
	register struct tcpcb *tp;
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
#if INET6
	int isipv6 = (inp->inp_vflag & INP_IPV6) != 0;
#endif /* INET6 */
	struct rtentry *rt;
	int dosavessthresh;

	if ( inp->inp_ppcb == NULL) /* tcp_close was called previously, bail */
		return(NULL);

	tcp_canceltimers(tp);
	KERNEL_DEBUG(DBG_FNC_TCP_CLOSE | DBG_FUNC_START, tp,0,0,0,0);

	/*
	 * If another thread for this tcp is currently in ip (indicated by
	 * the TF_SENDINPROG flag), defer the cleanup until after it returns
	 * back to tcp.  This is done to serialize the close until after all
	 * pending output is finished, in order to avoid having the PCB be
	 * detached and the cached route cleaned, only for ip to cache the
	 * route back into the PCB again.  Note that we've cleared all the
	 * timers at this point.  Set TF_CLOSING to indicate to tcp_output()
	 * that is should call us again once it returns from ip; at that
	 * point both flags should be cleared and we can proceed further
	 * with the cleanup.
	 */
	if (tp->t_flags & (TF_CLOSING|TF_SENDINPROG)) {
		tp->t_flags |= TF_CLOSING;
		return (NULL);
	}

	if (CC_ALGO(tp)->cleanup != NULL) {
		CC_ALGO(tp)->cleanup(tp);
	}

#if INET6
	rt = isipv6 ? inp->in6p_route.ro_rt : inp->inp_route.ro_rt;
#else
	rt = inp->inp_route.ro_rt;
#endif
	if (rt != NULL)
		RT_LOCK_SPIN(rt);

	/*
	 * If we got enough samples through the srtt filter,
	 * save the rtt and rttvar in the routing entry.
	 * 'Enough' is arbitrarily defined as the 16 samples.
	 * 16 samples is enough for the srtt filter to converge
	 * to within 5% of the correct value; fewer samples and
	 * we could save a very bogus rtt.
	 *
	 * Don't update the default route's characteristics and don't
	 * update anything that the user "locked".
	 */
	if (tp->t_rttupdated >= 16) {
		register u_int32_t i = 0;

#if INET6
		if (isipv6) {
			struct sockaddr_in6 *sin6;

			if (rt == NULL)
				goto no_valid_rt;
			sin6 = (struct sockaddr_in6 *)rt_key(rt);
			if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
				goto no_valid_rt;
		}
		else
#endif /* INET6 */
		if (rt == NULL || !(rt->rt_flags & RTF_UP) ||
		    ((struct sockaddr_in *)rt_key(rt))->sin_addr.s_addr ==
		    INADDR_ANY || rt->generation_id != route_generation) {
			if (tp->t_state >= TCPS_CLOSE_WAIT) {
				DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
					struct tcpcb *, tp, int32_t, TCPS_CLOSING);
				tp->t_state = TCPS_CLOSING;
			}
			goto no_valid_rt;
		}

		RT_LOCK_ASSERT_HELD(rt);
		if ((rt->rt_rmx.rmx_locks & RTV_RTT) == 0) {
			i = tp->t_srtt *
			    (RTM_RTTUNIT / (TCP_RETRANSHZ * TCP_RTT_SCALE));
			if (rt->rt_rmx.rmx_rtt && i)
				/*
				 * filter this update to half the old & half
				 * the new values, converting scale.
				 * See route.h and tcp_var.h for a
				 * description of the scaling constants.
				 */
				rt->rt_rmx.rmx_rtt =
				    (rt->rt_rmx.rmx_rtt + i) / 2;
			else
				rt->rt_rmx.rmx_rtt = i;
			tcpstat.tcps_cachedrtt++;
		}
		if ((rt->rt_rmx.rmx_locks & RTV_RTTVAR) == 0) {
			i = tp->t_rttvar *
			    (RTM_RTTUNIT / (TCP_RETRANSHZ * TCP_RTTVAR_SCALE));
			if (rt->rt_rmx.rmx_rttvar && i)
				rt->rt_rmx.rmx_rttvar =
				    (rt->rt_rmx.rmx_rttvar + i) / 2;
			else
				rt->rt_rmx.rmx_rttvar = i;
			tcpstat.tcps_cachedrttvar++;
		}
		/*
		 * The old comment here said:
		 * update the pipelimit (ssthresh) if it has been updated
		 * already or if a pipesize was specified & the threshhold
		 * got below half the pipesize.  I.e., wait for bad news
		 * before we start updating, then update on both good
		 * and bad news.
		 *
		 * But we want to save the ssthresh even if no pipesize is
		 * specified explicitly in the route, because such
		 * connections still have an implicit pipesize specified
		 * by the global tcp_sendspace.  In the absence of a reliable
		 * way to calculate the pipesize, it will have to do.
		 */
		i = tp->snd_ssthresh;
		if (rt->rt_rmx.rmx_sendpipe != 0)
			dosavessthresh = (i < rt->rt_rmx.rmx_sendpipe / 2);
		else
			dosavessthresh = (i < so->so_snd.sb_hiwat / 2);
		if (((rt->rt_rmx.rmx_locks & RTV_SSTHRESH) == 0 &&
		     i != 0 && rt->rt_rmx.rmx_ssthresh != 0)
		    || dosavessthresh) {
			/*
			 * convert the limit from user data bytes to
			 * packets then to packet data bytes.
			 */
			i = (i + tp->t_maxseg / 2) / tp->t_maxseg;
			if (i < 2)
				i = 2;
			i *= (u_int32_t)(tp->t_maxseg +
#if INET6
				      (isipv6 ? sizeof (struct ip6_hdr) +
					       sizeof (struct tcphdr) :
#endif
				       sizeof (struct tcpiphdr)
#if INET6
				       )
#endif
				      );
			if (rt->rt_rmx.rmx_ssthresh)
				rt->rt_rmx.rmx_ssthresh =
				    (rt->rt_rmx.rmx_ssthresh + i) / 2;
			else
				rt->rt_rmx.rmx_ssthresh = i;
			tcpstat.tcps_cachedssthresh++;
		}
	}

	/*
	 * Mark route for deletion if no information is cached.
	 */
	if (rt != NULL && (so->so_flags & SOF_OVERFLOW) && tcp_lq_overflow) {
		if (!(rt->rt_rmx.rmx_locks & RTV_RTT) &&
		    rt->rt_rmx.rmx_rtt == 0) {
			rt->rt_flags |= RTF_DELCLONE;
		}
	}

no_valid_rt:
	if (rt != NULL)
		RT_UNLOCK(rt);

	/* free the reassembly queue, if any */
	(void) tcp_freeq(tp);

	tcp_free_sackholes(tp);

	/* Free the packet list */
	if (tp->t_pktlist_head != NULL)
		m_freem_list(tp->t_pktlist_head);
	TCP_PKTLIST_CLEAR(tp);

#ifdef __APPLE__
	if (so->cached_in_sock_layer)
	    inp->inp_saved_ppcb = (caddr_t) tp;
#endif
	/* Issue a wakeup before detach so that we don't miss
	 * a wakeup
	 */
	sodisconnectwakeup(so);

#if INET6
	if (INP_CHECK_SOCKAF(so, AF_INET6))
		in6_pcbdetach(inp);
	else
#endif /* INET6 */
	in_pcbdetach(inp);

	/* Call soisdisconnected after detach because it might unlock the socket */
	soisdisconnected(so);
	tcpstat.tcps_closed++;
	KERNEL_DEBUG(DBG_FNC_TCP_CLOSE | DBG_FUNC_END, tcpstat.tcps_closed,0,0,0,0);
	return(NULL);
}

int
tcp_freeq(tp)
	struct tcpcb *tp;
{

	register struct tseg_qent *q;
	int rv = 0;

	while((q = LIST_FIRST(&tp->t_segq)) != NULL) {
		LIST_REMOVE(q, tqe_q);
		m_freem(q->tqe_m);
		zfree(tcp_reass_zone, q);
		tcp_reass_qsize--;
		rv = 1;
	}
	return (rv);
}

void
tcp_drain()
{
	if (do_tcpdrain)
	{
		struct inpcb *inpb;
		struct tcpcb *tcpb;
		struct tseg_qent *te;

	/*
	 * Walk the tcpbs, if existing, and flush the reassembly queue,
	 * if there is one...
	 * XXX: The "Net/3" implementation doesn't imply that the TCP
	 *      reassembly queue should be flushed, but in a situation
	 * 	where we're really low on mbufs, this is potentially
	 *  	usefull.	
	 */
		if (!lck_rw_try_lock_exclusive(tcbinfo.mtx)) /* do it next time if the lock is in use */
			return;

		for (inpb = LIST_FIRST(tcbinfo.listhead); inpb;
	    		inpb = LIST_NEXT(inpb, inp_list)) {
				if ((tcpb = intotcpcb(inpb))) {
					while ((te = LIST_FIRST(&tcpb->t_segq))
					       != NULL) {
					LIST_REMOVE(te, tqe_q);
					m_freem(te->tqe_m);
					zfree(tcp_reass_zone, te);
					tcp_reass_qsize--;
				}
			}
		}
		lck_rw_done(tcbinfo.mtx);

	}
}

/*
 * Notify a tcp user of an asynchronous error;
 * store error as soft error, but wake up user
 * (for now, won't do anything until can select for soft error).
 *
 * Do not wake up user since there currently is no mechanism for
 * reporting soft errors (yet - a kqueue filter may be added).
 */
static void
tcp_notify(inp, error)
	struct inpcb *inp;
	int error;
{
	struct tcpcb *tp;

	if (inp == NULL || (inp->inp_state == INPCB_STATE_DEAD)) 
		return; /* pcb is gone already */

	tp = (struct tcpcb *)inp->inp_ppcb;

	/*
	 * Ignore some errors if we are hooked up.
	 * If connection hasn't completed, has retransmitted several times,
	 * and receives a second error, give up now.  This is better
	 * than waiting a long time to establish a connection that
	 * can never complete.
	 */
	if (tp->t_state == TCPS_ESTABLISHED &&
	     (error == EHOSTUNREACH || error == ENETUNREACH ||
	      error == EHOSTDOWN)) {
		return;
	} else if (tp->t_state < TCPS_ESTABLISHED && tp->t_rxtshift > 3 &&
	    tp->t_softerror)
		tcp_drop(tp, error);
	else
		tp->t_softerror = error;
#if 0
	wakeup((caddr_t) &so->so_timeo);
	sorwakeup(so);
	sowwakeup(so);
#endif
}

/*
 * tcpcb_to_otcpcb copies specific bits of a tcpcb to a otcpcb format.
 * The otcpcb data structure is passed to user space and must not change.
 */
static void
tcpcb_to_otcpcb(struct tcpcb *tp, struct otcpcb *otp)
{
	int i;

	otp->t_segq = (u_int32_t)(uintptr_t)tp->t_segq.lh_first;
	otp->t_dupacks = tp->t_dupacks;
	for (i = 0; i < TCPT_NTIMERS_EXT; i++)
		otp->t_timer[i] = tp->t_timer[i];
	otp->t_inpcb = (_TCPCB_PTR(struct inpcb *))(uintptr_t)tp->t_inpcb;
	otp->t_state = tp->t_state;
	otp->t_flags = tp->t_flags;
	otp->t_force = tp->t_force;
	otp->snd_una = tp->snd_una;
	otp->snd_max = tp->snd_max;
	otp->snd_nxt = tp->snd_nxt;
	otp->snd_up = tp->snd_up;
	otp->snd_wl1 = tp->snd_wl1;
	otp->snd_wl2 = tp->snd_wl2;
	otp->iss = tp->iss;
	otp->irs = tp->irs;
	otp->rcv_nxt = tp->rcv_nxt;
	otp->rcv_adv = tp->rcv_adv;
	otp->rcv_wnd = tp->rcv_wnd;
	otp->rcv_up = tp->rcv_up;
	otp->snd_wnd = tp->snd_wnd;
	otp->snd_cwnd = tp->snd_cwnd;
	otp->snd_ssthresh = tp->snd_ssthresh;
	otp->t_maxopd = tp->t_maxopd;
	otp->t_rcvtime = tp->t_rcvtime;
	otp->t_starttime = tp->t_starttime;
	otp->t_rtttime = tp->t_rtttime;
	otp->t_rtseq = tp->t_rtseq;
	otp->t_rxtcur = tp->t_rxtcur;
	otp->t_maxseg = tp->t_maxseg;
	otp->t_srtt = tp->t_srtt;
	otp->t_rttvar = tp->t_rttvar;
	otp->t_rxtshift = tp->t_rxtshift;
	otp->t_rttmin = tp->t_rttmin;
	otp->t_rttupdated = tp->t_rttupdated;
	otp->max_sndwnd = tp->max_sndwnd;
	otp->t_softerror = tp->t_softerror;
	otp->t_oobflags = tp->t_oobflags;
	otp->t_iobc = tp->t_iobc;
	otp->snd_scale = tp->snd_scale;
	otp->rcv_scale = tp->rcv_scale;
	otp->request_r_scale = tp->request_r_scale;
	otp->requested_s_scale = tp->requested_s_scale;
	otp->ts_recent = tp->ts_recent;
	otp->ts_recent_age = tp->ts_recent_age;
	otp->last_ack_sent = tp->last_ack_sent;
	otp->cc_send = tp->cc_send;
	otp->cc_recv = tp->cc_recv;
	otp->snd_recover = tp->snd_recover;
	otp->snd_cwnd_prev = tp->snd_cwnd_prev;
	otp->snd_ssthresh_prev = tp->snd_ssthresh_prev;
	otp->t_badrxtwin = tp->t_badrxtwin;
}

static int
tcp_pcblist SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error, i, n;
	struct inpcb *inp, **inp_list;
	inp_gen_t gencnt;
	struct xinpgen xig;
	int slot;

	/*
	 * The process of preparing the TCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	lck_rw_lock_shared(tcbinfo.mtx);
	if (req->oldptr == USER_ADDR_NULL) {
		n = tcbinfo.ipi_count;
		req->oldidx = 2 * (sizeof xig)
			+ (n + n/8) * sizeof(struct xtcpcb);
		lck_rw_done(tcbinfo.mtx);
		return 0;
	}

	if (req->newptr != USER_ADDR_NULL) {
		lck_rw_done(tcbinfo.mtx);
		return EPERM;
	}

	/*
	 * OK, now we're committed to doing something.
	 */
	gencnt = tcbinfo.ipi_gencnt;
	n = tcbinfo.ipi_count;

	bzero(&xig, sizeof(xig));
	xig.xig_len = sizeof xig;
	xig.xig_count = n;
	xig.xig_gen = gencnt;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof xig);
	if (error) {
		lck_rw_done(tcbinfo.mtx);
		return error;
	}
	/*
	 * We are done if there is no pcb
	 */
	if (n == 0) {
		lck_rw_done(tcbinfo.mtx);
		return 0; 
	}

	inp_list = _MALLOC(n * sizeof *inp_list, M_TEMP, M_WAITOK);
	if (inp_list == 0) {
		lck_rw_done(tcbinfo.mtx);
		return ENOMEM;
	}
	
	for (inp = LIST_FIRST(tcbinfo.listhead), i = 0; inp && i < n;
	     inp = LIST_NEXT(inp, inp_list)) {
#ifdef __APPLE__
		if (inp->inp_gencnt <= gencnt && inp->inp_state != INPCB_STATE_DEAD)
#else
		if (inp->inp_gencnt <= gencnt && !prison_xinpcb(req->p, inp))
#endif
			inp_list[i++] = inp;
	}

	for (slot = 0; slot < N_TIME_WAIT_SLOTS; slot++) {
		struct inpcb *inpnxt;

		for (inp = time_wait_slots[slot].lh_first; inp && i < n; inp = inpnxt) {
			inpnxt = inp->inp_list.le_next;
			if (inp->inp_gencnt <= gencnt && inp->inp_state != INPCB_STATE_DEAD)
				inp_list[i++] = inp;
		}
	}

	n = i;

	error = 0;
	for (i = 0; i < n; i++) {
		inp = inp_list[i];
		if (inp->inp_gencnt <= gencnt && inp->inp_state != INPCB_STATE_DEAD) {
			struct xtcpcb xt;
			caddr_t inp_ppcb;

			bzero(&xt, sizeof(xt));
			xt.xt_len = sizeof xt;
			/* XXX should avoid extra copy */
			inpcb_to_compat(inp, &xt.xt_inp);
			inp_ppcb = inp->inp_ppcb;
			if (inp_ppcb != NULL) {
				tcpcb_to_otcpcb((struct tcpcb *)inp_ppcb,
				    &xt.xt_tp);
			} else {
				bzero((char *) &xt.xt_tp, sizeof xt.xt_tp);
			}
			if (inp->inp_socket)
				sotoxsocket(inp->inp_socket, &xt.xt_socket);
			error = SYSCTL_OUT(req, &xt, sizeof xt);
		}
	}
	if (!error) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
		bzero(&xig, sizeof(xig));
		xig.xig_len = sizeof xig;
		xig.xig_gen = tcbinfo.ipi_gencnt;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = tcbinfo.ipi_count;
		error = SYSCTL_OUT(req, &xig, sizeof xig);
	}
	FREE(inp_list, M_TEMP);
	lck_rw_done(tcbinfo.mtx);
	return error;
}

SYSCTL_PROC(_net_inet_tcp, TCPCTL_PCBLIST, pcblist, CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
	    tcp_pcblist, "S,xtcpcb", "List of active TCP connections");

#if !CONFIG_EMBEDDED

static void
tcpcb_to_xtcpcb64(struct tcpcb *tp, struct xtcpcb64 *otp)
{
        int i;

        otp->t_segq = (u_int32_t)(uintptr_t)tp->t_segq.lh_first;
        otp->t_dupacks = tp->t_dupacks;
        for (i = 0; i < TCPT_NTIMERS_EXT; i++)
                otp->t_timer[i] = tp->t_timer[i];
        otp->t_state = tp->t_state;
        otp->t_flags = tp->t_flags;
        otp->t_force = tp->t_force;
        otp->snd_una = tp->snd_una;
        otp->snd_max = tp->snd_max;
        otp->snd_nxt = tp->snd_nxt;
        otp->snd_up = tp->snd_up;
        otp->snd_wl1 = tp->snd_wl1;
        otp->snd_wl2 = tp->snd_wl2;
        otp->iss = tp->iss;
        otp->irs = tp->irs;
        otp->rcv_nxt = tp->rcv_nxt;
        otp->rcv_adv = tp->rcv_adv;
        otp->rcv_wnd = tp->rcv_wnd;
        otp->rcv_up = tp->rcv_up;
        otp->snd_wnd = tp->snd_wnd;
        otp->snd_cwnd = tp->snd_cwnd;
        otp->snd_ssthresh = tp->snd_ssthresh;
        otp->t_maxopd = tp->t_maxopd;
        otp->t_rcvtime = tp->t_rcvtime;
        otp->t_starttime = tp->t_starttime;
        otp->t_rtttime = tp->t_rtttime;
        otp->t_rtseq = tp->t_rtseq;
        otp->t_rxtcur = tp->t_rxtcur;
        otp->t_maxseg = tp->t_maxseg;
        otp->t_srtt = tp->t_srtt;
        otp->t_rttvar = tp->t_rttvar;
        otp->t_rxtshift = tp->t_rxtshift;
        otp->t_rttmin = tp->t_rttmin;
        otp->t_rttupdated = tp->t_rttupdated;
        otp->max_sndwnd = tp->max_sndwnd;
        otp->t_softerror = tp->t_softerror;
        otp->t_oobflags = tp->t_oobflags;
        otp->t_iobc = tp->t_iobc;
        otp->snd_scale = tp->snd_scale;
        otp->rcv_scale = tp->rcv_scale;
        otp->request_r_scale = tp->request_r_scale;
        otp->requested_s_scale = tp->requested_s_scale;
        otp->ts_recent = tp->ts_recent;
        otp->ts_recent_age = tp->ts_recent_age;
        otp->last_ack_sent = tp->last_ack_sent;
        otp->cc_send = tp->cc_send;
        otp->cc_recv = tp->cc_recv;
        otp->snd_recover = tp->snd_recover;
        otp->snd_cwnd_prev = tp->snd_cwnd_prev;
        otp->snd_ssthresh_prev = tp->snd_ssthresh_prev;
        otp->t_badrxtwin = tp->t_badrxtwin;
}


static int
tcp_pcblist64 SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
        int error, i, n;
        struct inpcb *inp, **inp_list;
        inp_gen_t gencnt;
        struct xinpgen xig;
        int slot;

        /*
         * The process of preparing the TCB list is too time-consuming and
         * resource-intensive to repeat twice on every request.
         */
        lck_rw_lock_shared(tcbinfo.mtx);
        if (req->oldptr == USER_ADDR_NULL) {
                n = tcbinfo.ipi_count;
                req->oldidx = 2 * (sizeof xig)
                        + (n + n/8) * sizeof(struct xtcpcb64);
                lck_rw_done(tcbinfo.mtx);
                return 0;
        }

        if (req->newptr != USER_ADDR_NULL) {
                lck_rw_done(tcbinfo.mtx);
                return EPERM;
        }

        /*
         * OK, now we're committed to doing something.
         */
        gencnt = tcbinfo.ipi_gencnt;
        n = tcbinfo.ipi_count;

        bzero(&xig, sizeof(xig));
        xig.xig_len = sizeof xig;
        xig.xig_count = n;
        xig.xig_gen = gencnt;
        xig.xig_sogen = so_gencnt;
        error = SYSCTL_OUT(req, &xig, sizeof xig);
        if (error) {
                lck_rw_done(tcbinfo.mtx);
                return error;
        }
        /*
         * We are done if there is no pcb
         */
        if (n == 0) {
                lck_rw_done(tcbinfo.mtx);
                return 0;
        }

        inp_list = _MALLOC(n * sizeof *inp_list, M_TEMP, M_WAITOK);
        if (inp_list == 0) {
                lck_rw_done(tcbinfo.mtx);
                return ENOMEM;
        }

        for (inp = LIST_FIRST(tcbinfo.listhead), i = 0; inp && i < n;
             inp = LIST_NEXT(inp, inp_list)) {
#ifdef __APPLE__
                if (inp->inp_gencnt <= gencnt && inp->inp_state != INPCB_STATE_DEAD)
#else
                if (inp->inp_gencnt <= gencnt && !prison_xinpcb(req->p, inp))
#endif
                        inp_list[i++] = inp;
        }

        for (slot = 0; slot < N_TIME_WAIT_SLOTS; slot++) {
                struct inpcb *inpnxt;

                for (inp = time_wait_slots[slot].lh_first; inp && i < n; inp = inpnxt) {
                        inpnxt = inp->inp_list.le_next;
                        if (inp->inp_gencnt <= gencnt && inp->inp_state != INPCB_STATE_DEAD)
                                inp_list[i++] = inp;
                }
        }

        n = i;

        error = 0;
        for (i = 0; i < n; i++) {
                inp = inp_list[i];
                if (inp->inp_gencnt <= gencnt && inp->inp_state != INPCB_STATE_DEAD) {
					struct xtcpcb64 xt;
					
					bzero(&xt, sizeof(xt));
					xt.xt_len = sizeof xt;
					inpcb_to_xinpcb64(inp, &xt.xt_inpcb);
					xt.xt_inpcb.inp_ppcb = (u_int64_t)(uintptr_t)inp->inp_ppcb;
					if (inp->inp_ppcb != NULL)
						tcpcb_to_xtcpcb64((struct tcpcb *)inp->inp_ppcb, &xt);
					if (inp->inp_socket)
						sotoxsocket64(inp->inp_socket, &xt.xt_inpcb.xi_socket);
					error = SYSCTL_OUT(req, &xt, sizeof xt);
                }
        }
        if (!error) {
			/*
			 * Give the user an updated idea of our state.
			 * If the generation differs from what we told
			 * her before, she knows that something happened
			 * while we were processing this request, and it
			 * might be necessary to retry.
			 */
			bzero(&xig, sizeof(xig));
			xig.xig_len = sizeof xig;
			xig.xig_gen = tcbinfo.ipi_gencnt;
			xig.xig_sogen = so_gencnt;
			xig.xig_count = tcbinfo.ipi_count;
			error = SYSCTL_OUT(req, &xig, sizeof xig);
        }
        FREE(inp_list, M_TEMP);
        lck_rw_done(tcbinfo.mtx);
        return error;
}

SYSCTL_PROC(_net_inet_tcp, OID_AUTO, pcblist64, CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
            tcp_pcblist64, "S,xtcpcb64", "List of active TCP connections");

#endif /* !CONFIG_EMBEDDED */

static int
tcp_pcblist_n SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;
	
	error = get_pcblist_n(IPPROTO_TCP, req, &tcbinfo);
	
	return error;
}


SYSCTL_PROC(_net_inet_tcp, OID_AUTO, pcblist_n, CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
            tcp_pcblist_n, "S,xtcpcb_n", "List of active TCP connections");


void
tcp_ctlinput(cmd, sa, vip)
	int cmd;
	struct sockaddr *sa;
	void *vip;
{
	tcp_seq icmp_tcp_seq;
	struct ip *ip = vip;
	struct tcphdr *th;
	struct in_addr faddr;
	struct inpcb *inp;
	struct tcpcb *tp;
	
	void (*notify)(struct inpcb *, int) = tcp_notify;

	struct icmp *icp;

	faddr = ((struct sockaddr_in *)sa)->sin_addr;
	if (sa->sa_family != AF_INET || faddr.s_addr == INADDR_ANY)
		return;

	if (cmd == PRC_MSGSIZE)
		notify = tcp_mtudisc;
	else if (icmp_may_rst && (cmd == PRC_UNREACH_ADMIN_PROHIB ||
		cmd == PRC_UNREACH_PORT) && ip)
		notify = tcp_drop_syn_sent;
	else if (PRC_IS_REDIRECT(cmd)) {
		ip = 0;
		notify = in_rtchange;
	} else if (cmd == PRC_HOSTDEAD)
		ip = 0;
	/* Source quench is deprecated */
	else if (cmd == PRC_QUENCH) 
		return;
	else if ((unsigned)cmd > PRC_NCMDS || inetctlerrmap[cmd] == 0)
		return;
	if (ip) {
		icp = (struct icmp *)((caddr_t)ip
			       	- offsetof(struct icmp, icmp_ip));
		th = (struct tcphdr *)((caddr_t)ip 
			       + (IP_VHL_HL(ip->ip_vhl) << 2));
		inp = in_pcblookup_hash(&tcbinfo, faddr, th->th_dport,
		    ip->ip_src, th->th_sport, 0, NULL);
		if (inp != NULL && inp->inp_socket != NULL) {
			tcp_lock(inp->inp_socket, 1, 0);
			if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) {
				tcp_unlock(inp->inp_socket, 1, 0);
				return;
			}
			icmp_tcp_seq = htonl(th->th_seq);
			tp = intotcpcb(inp);
			if (SEQ_GEQ(icmp_tcp_seq, tp->snd_una) &&
			    SEQ_LT(icmp_tcp_seq, tp->snd_max)) {
				if (cmd == PRC_MSGSIZE) {

					/*
				  	 * MTU discovery:
				 	 * If we got a needfrag and there is a host route to the
				 	 * original destination, and the MTU is not locked, then
				 	 * set the MTU in the route to the suggested new value
				 	 * (if given) and then notify as usual.  The ULPs will
				 	 * notice that the MTU has changed and adapt accordingly.
				 	 * If no new MTU was suggested, then we guess a new one
				 	 * less than the current value.  If the new MTU is 
				 	 * unreasonably small (defined by sysctl tcp_minmss), then
				 	 * we reset the MTU to the interface value and enable the
				 	 * lock bit, indicating that we are no longer doing MTU
				 	 * discovery.
				 	 */
					struct rtentry *rt;
					int mtu;
					struct sockaddr_in icmpsrc = { sizeof (struct sockaddr_in), AF_INET, 
										0 , { 0 }, { 0,0,0,0,0,0,0,0 } };
					icmpsrc.sin_addr = icp->icmp_ip.ip_dst;

					rt = rtalloc1((struct sockaddr *)&icmpsrc, 0,
					    RTF_CLONING | RTF_PRCLONING);
					if (rt != NULL) {
						RT_LOCK(rt);
						if ((rt->rt_flags & RTF_HOST) &&
						    !(rt->rt_rmx.rmx_locks & RTV_MTU)) {
							mtu = ntohs(icp->icmp_nextmtu);
							if (!mtu)
								mtu = ip_next_mtu(rt->rt_rmx.
								    rmx_mtu, 1);
#if DEBUG_MTUDISC
							printf("MTU for %s reduced to %d\n",
							    inet_ntop(AF_INET,
							    &icmpsrc.sin_addr, ipv4str,
							    sizeof (ipv4str)), mtu);
#endif
							if (mtu < max(296, (tcp_minmss +
							    sizeof (struct tcpiphdr)))) {
								/* rt->rt_rmx.rmx_mtu =
									rt->rt_ifp->if_mtu; */
								rt->rt_rmx.rmx_locks |= RTV_MTU;
							} else if (rt->rt_rmx.rmx_mtu > mtu) {
								rt->rt_rmx.rmx_mtu = mtu;
							}
						}
						RT_UNLOCK(rt);
						rtfree(rt);
					}
				}

				(*notify)(inp, inetctlerrmap[cmd]);
			}
			tcp_unlock(inp->inp_socket, 1, 0);
		}
	} else
		in_pcbnotifyall(&tcbinfo, faddr, inetctlerrmap[cmd], notify);
}

#if INET6
void
tcp6_ctlinput(cmd, sa, d)
	int cmd;
	struct sockaddr *sa;
	void *d;
{
	struct tcphdr th;
	void (*notify)(struct inpcb *, int) = tcp_notify;
	struct ip6_hdr *ip6;
	struct mbuf *m;
	struct ip6ctlparam *ip6cp = NULL;
	const struct sockaddr_in6 *sa6_src = NULL;
	int off;
	struct tcp_portonly {
		u_int16_t th_sport;
		u_int16_t th_dport;
	} *thp;

	if (sa->sa_family != AF_INET6 ||
	    sa->sa_len != sizeof(struct sockaddr_in6))
		return;

	if (cmd == PRC_MSGSIZE)
		notify = tcp_mtudisc;
	else if (!PRC_IS_REDIRECT(cmd) &&
		 ((unsigned)cmd > PRC_NCMDS || inet6ctlerrmap[cmd] == 0))
		return;
	/* Source quench is deprecated */
	else if (cmd == PRC_QUENCH) 
		return;

	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		ip6cp = (struct ip6ctlparam *)d;
		m = ip6cp->ip6c_m;
		ip6 = ip6cp->ip6c_ip6;
		off = ip6cp->ip6c_off;
		sa6_src = ip6cp->ip6c_src;
	} else {
		m = NULL;
		ip6 = NULL;
		off = 0;	/* fool gcc */
		sa6_src = &sa6_any;
	}

	if (ip6) {
		/*
		 * XXX: We assume that when IPV6 is non NULL,
		 * M and OFF are valid.
		 */

		/* check if we can safely examine src and dst ports */
		if (m->m_pkthdr.len < off + sizeof(*thp))
			return;

		bzero(&th, sizeof(th));
		m_copydata(m, off, sizeof(*thp), (caddr_t)&th);

		in6_pcbnotify(&tcbinfo, sa, th.th_dport,
		    (struct sockaddr *)ip6cp->ip6c_src,
		    th.th_sport, cmd, NULL, notify);
	} else {
		in6_pcbnotify(&tcbinfo, sa, 0,
		    (struct sockaddr *)(size_t)sa6_src, 0, cmd, NULL, notify);
	}
}
#endif /* INET6 */


/*
 * Following is where TCP initial sequence number generation occurs.
 *
 * There are two places where we must use initial sequence numbers:
 * 1.  In SYN-ACK packets.
 * 2.  In SYN packets.
 *
 * The ISNs in SYN-ACK packets have no monotonicity requirement, 
 * and should be as unpredictable as possible to avoid the possibility
 * of spoofing and/or connection hijacking.  To satisfy this
 * requirement, SYN-ACK ISNs are generated via the arc4random()
 * function.  If exact RFC 1948 compliance is requested via sysctl,
 * these ISNs will be generated just like those in SYN packets.
 *
 * The ISNs in SYN packets must be monotonic; TIME_WAIT recycling
 * depends on this property.  In addition, these ISNs should be
 * unguessable so as to prevent connection hijacking.  To satisfy
 * the requirements of this situation, the algorithm outlined in
 * RFC 1948 is used to generate sequence numbers.
 *
 * For more information on the theory of operation, please see
 * RFC 1948.
 *
 * Implementation details:
 *
 * Time is based off the system timer, and is corrected so that it
 * increases by one megabyte per second.  This allows for proper
 * recycling on high speed LANs while still leaving over an hour
 * before rollover.
 *
 * Two sysctls control the generation of ISNs:
 *
 * net.inet.tcp.isn_reseed_interval controls the number of seconds
 * between seeding of isn_secret.  This is normally set to zero,
 * as reseeding should not be necessary.
 *
 * net.inet.tcp.strict_rfc1948 controls whether RFC 1948 is followed
 * strictly.  When strict compliance is requested, reseeding is
 * disabled and SYN-ACKs will be generated in the same manner as
 * SYNs.  Strict mode is disabled by default.
 *
 */

#define ISN_BYTES_PER_SECOND 1048576

tcp_seq
tcp_new_isn(tp)
	struct tcpcb *tp;
{
	u_int32_t md5_buffer[4];
	tcp_seq new_isn;
	struct timeval timenow;
	u_char isn_secret[32];
	int isn_last_reseed = 0;
	MD5_CTX isn_ctx;

	/* Use arc4random for SYN-ACKs when not in exact RFC1948 mode. */
	if (((tp->t_state == TCPS_LISTEN) || (tp->t_state == TCPS_TIME_WAIT))
	   && tcp_strict_rfc1948 == 0)
#ifdef __APPLE__
		return random();
#else
		return arc4random();
#endif
	getmicrotime(&timenow);

	/* Seed if this is the first use, reseed if requested. */
	if ((isn_last_reseed == 0) ||
	    ((tcp_strict_rfc1948 == 0) && (tcp_isn_reseed_interval > 0) &&
	     (((u_int)isn_last_reseed + (u_int)tcp_isn_reseed_interval*hz)
		< (u_int)timenow.tv_sec))) {
#ifdef __APPLE__
		read_random(&isn_secret, sizeof(isn_secret));
#else
		read_random_unlimited(&isn_secret, sizeof(isn_secret));
#endif
		isn_last_reseed = timenow.tv_sec;
	}
		
	/* Compute the md5 hash and return the ISN. */
	MD5Init(&isn_ctx);
	MD5Update(&isn_ctx, (u_char *) &tp->t_inpcb->inp_fport, sizeof(u_short));
	MD5Update(&isn_ctx, (u_char *) &tp->t_inpcb->inp_lport, sizeof(u_short));
#if INET6
	if ((tp->t_inpcb->inp_vflag & INP_IPV6) != 0) {
		MD5Update(&isn_ctx, (u_char *) &tp->t_inpcb->in6p_faddr,
			  sizeof(struct in6_addr));
		MD5Update(&isn_ctx, (u_char *) &tp->t_inpcb->in6p_laddr,
			  sizeof(struct in6_addr));
	} else
#endif
	{
		MD5Update(&isn_ctx, (u_char *) &tp->t_inpcb->inp_faddr,
			  sizeof(struct in_addr));
		MD5Update(&isn_ctx, (u_char *) &tp->t_inpcb->inp_laddr,
			  sizeof(struct in_addr));
	}
	MD5Update(&isn_ctx, (u_char *) &isn_secret, sizeof(isn_secret));
	MD5Final((u_char *) &md5_buffer, &isn_ctx);
	new_isn = (tcp_seq) md5_buffer[0];
	new_isn += timenow.tv_sec * (ISN_BYTES_PER_SECOND / hz);
	return new_isn;
}


/*
 * When a specific ICMP unreachable message is received and the
 * connection state is SYN-SENT, drop the connection.  This behavior
 * is controlled by the icmp_may_rst sysctl.
 */
void
tcp_drop_syn_sent(inp, errno)
	struct inpcb *inp;
	int errno;
{
	struct tcpcb *tp = intotcpcb(inp);

	if (tp && tp->t_state == TCPS_SYN_SENT)
		tcp_drop(tp, errno);
}

/*
 * When `need fragmentation' ICMP is received, update our idea of the MSS
 * based on the new value in the route.  Also nudge TCP to send something,
 * since we know the packet we just sent was dropped.
 * This duplicates some code in the tcp_mss() function in tcp_input.c.
 */
void
tcp_mtudisc(
	struct inpcb *inp,
	__unused int errno
)
{
	struct tcpcb *tp = intotcpcb(inp);
	struct rtentry *rt;
	struct rmxp_tao *taop;
	struct socket *so = inp->inp_socket;
	int offered;
	int mss;
#if INET6
	int isipv6 = (tp->t_inpcb->inp_vflag & INP_IPV6) != 0;
#endif /* INET6 */

	if (tp) {
#if INET6
		if (isipv6)
			rt = tcp_rtlookup6(inp, IFSCOPE_NONE);
		else
#endif /* INET6 */
		rt = tcp_rtlookup(inp, IFSCOPE_NONE);
		if (!rt || !rt->rt_rmx.rmx_mtu) {
			tp->t_maxopd = tp->t_maxseg =
#if INET6
				isipv6 ? tcp_v6mssdflt :
#endif /* INET6 */
				tcp_mssdflt;

			/* Route locked during lookup above */
			if (rt != NULL)
				RT_UNLOCK(rt);
			return;
		}
		taop = rmx_taop(rt->rt_rmx);
		offered = taop->tao_mssopt;
		mss = rt->rt_rmx.rmx_mtu -
#if INET6
			(isipv6 ?
			 sizeof(struct ip6_hdr) + sizeof(struct tcphdr) :
#endif /* INET6 */
			 sizeof(struct tcpiphdr)
#if INET6
			 )
#endif /* INET6 */
			;

		/* Route locked during lookup above */
		RT_UNLOCK(rt);

		if (offered)
			mss = min(mss, offered);
		/*
		 * XXX - The above conditional probably violates the TCP
		 * spec.  The problem is that, since we don't know the
		 * other end's MSS, we are supposed to use a conservative
		 * default.  But, if we do that, then MTU discovery will
		 * never actually take place, because the conservative
		 * default is much less than the MTUs typically seen
		 * on the Internet today.  For the moment, we'll sweep
		 * this under the carpet.
		 *
		 * The conservative default might not actually be a problem
		 * if the only case this occurs is when sending an initial
		 * SYN with options and data to a host we've never talked
		 * to before.  Then, they will reply with an MSS value which
		 * will get recorded and the new parameters should get
		 * recomputed.  For Further Study.
		 */
		if (tp->t_maxopd <= mss)
			return;
		tp->t_maxopd = mss;

		if ((tp->t_flags & (TF_REQ_TSTMP|TF_NOOPT)) == TF_REQ_TSTMP &&
		    (tp->t_flags & TF_RCVD_TSTMP) == TF_RCVD_TSTMP)
			mss -= TCPOLEN_TSTAMP_APPA;

		if (so->so_snd.sb_hiwat < mss)
			mss = so->so_snd.sb_hiwat;

		tp->t_maxseg = mss;

		/*
		 * Reset the slow-start flight size as it may depends on the new MSS
		 */
		if (CC_ALGO(tp)->cwnd_init != NULL)
			CC_ALGO(tp)->cwnd_init(tp);
		tcpstat.tcps_mturesent++;
		tp->t_rtttime = 0;
		tp->snd_nxt = tp->snd_una;
		tcp_output(tp);
	}
}

/*
 * Look-up the routing entry to the peer of this inpcb.  If no route
 * is found and it cannot be allocated the return NULL.  This routine
 * is called by TCP routines that access the rmx structure and by tcp_mss
 * to get the interface MTU.  If a route is found, this routine will
 * hold the rtentry lock; the caller is responsible for unlocking.
 */
struct rtentry *
tcp_rtlookup(inp, input_ifscope)
	struct inpcb *inp;
	unsigned int input_ifscope;
{
	struct route *ro;
	struct rtentry *rt;
	struct tcpcb *tp;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);

	ro = &inp->inp_route;
	if ((rt = ro->ro_rt) != NULL)
		RT_LOCK(rt);

	if (rt == NULL || !(rt->rt_flags & RTF_UP) ||
	    rt->generation_id != route_generation) {
		/* No route yet, so try to acquire one */
		if (inp->inp_faddr.s_addr != INADDR_ANY) {
			unsigned int ifscope;

			ro->ro_dst.sa_family = AF_INET;
			ro->ro_dst.sa_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in *) &ro->ro_dst)->sin_addr =
				inp->inp_faddr;

			/*
			 * If the socket was bound to an interface, then
			 * the bound-to-interface takes precedence over
			 * the inbound interface passed in by the caller
			 * (if we get here as part of the output path then
			 * input_ifscope is IFSCOPE_NONE).
			 */
			ifscope = (inp->inp_flags & INP_BOUND_IF) ?
			    inp->inp_boundif : input_ifscope;

			if (rt != NULL)
				RT_UNLOCK(rt);
			rtalloc_scoped(ro, ifscope);
			if ((rt = ro->ro_rt) != NULL)
				RT_LOCK(rt);
		}
	}

	/*
	 * Update MTU discovery determination. Don't do it if:
	 *	1) it is disabled via the sysctl
	 *	2) the route isn't up
	 *	3) the MTU is locked (if it is, then discovery has been
	 *	   disabled)
	 */

	 tp = intotcpcb(inp);

	if (!path_mtu_discovery || ((rt != NULL) && 
	    (!(rt->rt_flags & RTF_UP) || (rt->rt_rmx.rmx_locks & RTV_MTU)))) 
		tp->t_flags &= ~TF_PMTUD;
	else
		tp->t_flags |= TF_PMTUD;

#if CONFIG_IFEF_NOWINDOWSCALE
	if (tcp_obey_ifef_nowindowscale &&
	    tp->t_state == TCPS_SYN_SENT && rt != NULL && rt->rt_ifp != NULL &&
	    (rt->rt_ifp->if_eflags & IFEF_NOWINDOWSCALE)) {
		/* Window scaling is enabled on this interface */
		tp->t_flags &= ~TF_REQ_SCALE;
	}
#endif

	if (rt != NULL && rt->rt_ifp != NULL) {
		somultipages(inp->inp_socket,
		    (rt->rt_ifp->if_hwassist & IFNET_MULTIPAGES));
		tcp_set_tso(tp, rt->rt_ifp);
	}

	/*
	 * Caller needs to call RT_UNLOCK(rt).
	 */
	return rt;
}

#if INET6
struct rtentry *
tcp_rtlookup6(inp, input_ifscope)
	struct inpcb *inp;
	unsigned int input_ifscope;
{
	struct route_in6 *ro6;
	struct rtentry *rt;
	struct tcpcb *tp;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);

	ro6 = &inp->in6p_route;
	if ((rt = ro6->ro_rt) != NULL)
		RT_LOCK(rt);

	if (rt == NULL || !(rt->rt_flags & RTF_UP) ||
	    rt->generation_id != route_generation) {
		/* No route yet, so try to acquire one */
		if (!IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr)) {
			struct sockaddr_in6 *dst6;
			unsigned int ifscope;

			dst6 = (struct sockaddr_in6 *)&ro6->ro_dst;
			dst6->sin6_family = AF_INET6;
			dst6->sin6_len = sizeof(*dst6);
			dst6->sin6_addr = inp->in6p_faddr;

			/*
			 * If the socket was bound to an interface, then
			 * the bound-to-interface takes precedence over
			 * the inbound interface passed in by the caller
			 * (if we get here as part of the output path then
			 * input_ifscope is IFSCOPE_NONE).
			 */
			ifscope = (inp->inp_flags & INP_BOUND_IF) ?
			    inp->inp_boundif : input_ifscope;

			if (rt != NULL)
				RT_UNLOCK(rt);
			rtalloc_scoped((struct route *)ro6, ifscope);
			if ((rt = ro6->ro_rt) != NULL)
				RT_LOCK(rt);
		}
	}
	/*
	 * Update path MTU Discovery determination
	 * while looking up the route:
	 *  1) we have a valid route to the destination
	 *  2) the MTU is not locked (if it is, then discovery has been
	 *    disabled)
	 */


	 tp = intotcpcb(inp);

	/*
	 * Update MTU discovery determination. Don't do it if:
	 *	1) it is disabled via the sysctl
	 *	2) the route isn't up
	 *	3) the MTU is locked (if it is, then discovery has been
	 *	   disabled)
	 */

	if (!path_mtu_discovery || ((rt != NULL) && 
	    (!(rt->rt_flags & RTF_UP) || (rt->rt_rmx.rmx_locks & RTV_MTU)))) 
		tp->t_flags &= ~TF_PMTUD;
	else
		tp->t_flags |= TF_PMTUD;

#if CONFIG_IFEF_NOWINDOWSCALE
	if (tcp_obey_ifef_nowindowscale &&
	    tp->t_state == TCPS_SYN_SENT && rt != NULL && rt->rt_ifp != NULL &&
	    (rt->rt_ifp->if_eflags & IFEF_NOWINDOWSCALE)) {
		/* Window scaling is not enabled on this interface */
		tp->t_flags &= ~TF_REQ_SCALE;
	}
#endif

	if (rt != NULL && rt->rt_ifp != NULL) {
		somultipages(inp->inp_socket,
		    (rt->rt_ifp->if_hwassist & IFNET_MULTIPAGES));
		tcp_set_tso(tp, rt->rt_ifp);
	}

	/*
	 * Caller needs to call RT_UNLOCK(rt).
	 */
	return rt;
}
#endif /* INET6 */

#if IPSEC
/* compute ESP/AH header size for TCP, including outer IP header. */
size_t
ipsec_hdrsiz_tcp(tp)
	struct tcpcb *tp;
{
	struct inpcb *inp;
	struct mbuf *m;
	size_t hdrsiz;
	struct ip *ip;
#if INET6
	struct ip6_hdr *ip6 = NULL;
#endif /* INET6 */
	struct tcphdr *th;

	if ((tp == NULL) || ((inp = tp->t_inpcb) == NULL))
		return 0;
	MGETHDR(m, M_DONTWAIT, MT_DATA);	/* MAC-OK */
	if (!m)
		return 0;

#if INET6
	if ((inp->inp_vflag & INP_IPV6) != 0) {
		ip6 = mtod(m, struct ip6_hdr *);
		th = (struct tcphdr *)(ip6 + 1);
		m->m_pkthdr.len = m->m_len =
			sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
		tcp_fillheaders(tp, ip6, th);
		hdrsiz = ipsec6_hdrsiz(m, IPSEC_DIR_OUTBOUND, inp);
	} else
#endif /* INET6 */
      {
	ip = mtod(m, struct ip *);
	th = (struct tcphdr *)(ip + 1);
	m->m_pkthdr.len = m->m_len = sizeof(struct tcpiphdr);
	tcp_fillheaders(tp, ip, th);
	hdrsiz = ipsec4_hdrsiz(m, IPSEC_DIR_OUTBOUND, inp);
      }
	m_free(m);
	return hdrsiz;
}
#endif /*IPSEC*/

/*
 * Return a pointer to the cached information about the remote host.
 * The cached information is stored in the protocol specific part of
 * the route metrics.
 */
struct rmxp_tao *
tcp_gettaocache(inp)
	struct inpcb *inp;
{
	struct rtentry *rt;
	struct rmxp_tao *taop;

#if INET6
	if ((inp->inp_vflag & INP_IPV6) != 0)
		rt = tcp_rtlookup6(inp, IFSCOPE_NONE);
	else
#endif /* INET6 */
	rt = tcp_rtlookup(inp, IFSCOPE_NONE);

	/* Make sure this is a host route and is up. */
	if (rt == NULL ||
	    (rt->rt_flags & (RTF_UP|RTF_HOST)) != (RTF_UP|RTF_HOST)) {
		/* Route locked during lookup above */
		if (rt != NULL)
			RT_UNLOCK(rt);
		return NULL;
	}
	
	taop = rmx_taop(rt->rt_rmx);
	/* Route locked during lookup above */
	RT_UNLOCK(rt);
	return (taop);
}

/*
 * Clear all the TAO cache entries, called from tcp_init.
 *
 * XXX
 * This routine is just an empty one, because we assume that the routing
 * routing tables are initialized at the same time when TCP, so there is
 * nothing in the cache left over.
 */
static void
tcp_cleartaocache()
{
}

int
tcp_lock(struct socket *so, int refcount, void *lr)
{
	void *lr_saved;

	if (lr == NULL)
		lr_saved = __builtin_return_address(0);
	else
		lr_saved = lr;

	if (so->so_pcb != NULL) {
		lck_mtx_lock(&((struct inpcb *)so->so_pcb)->inpcb_mtx);
	} else  {
		panic("tcp_lock: so=%p NO PCB! lr=%p lrh= %s\n", 
		    so, lr_saved, solockhistory_nr(so));
		/* NOTREACHED */
	}

	if (so->so_usecount < 0) {
		panic("tcp_lock: so=%p so_pcb=%p lr=%p ref=%x lrh= %s\n",
		    so, so->so_pcb, lr_saved, so->so_usecount, solockhistory_nr(so));
		/* NOTREACHED */
	}
	if (refcount)
		so->so_usecount++;
	so->lock_lr[so->next_lock_lr] = lr_saved;
	so->next_lock_lr = (so->next_lock_lr+1) % SO_LCKDBG_MAX;
	return (0);
}

int
tcp_unlock(struct socket *so, int refcount, void *lr)
{
	void *lr_saved;

	if (lr == NULL)
		lr_saved = __builtin_return_address(0);
	else
		lr_saved = lr;

#ifdef MORE_TCPLOCK_DEBUG
	printf("tcp_unlock: so=%p sopcb=%p lock=%p ref=%x lr=%p\n",
	    so, so->so_pcb, &((struct inpcb *)so->so_pcb)->inpcb_mtx,
	    so->so_usecount, lr_saved);
#endif
	if (refcount)
		so->so_usecount--;

	if (so->so_usecount < 0) {
		panic("tcp_unlock: so=%p usecount=%x lrh= %s\n", 
		    so, so->so_usecount, solockhistory_nr(so));
		/* NOTREACHED */
	}
	if (so->so_pcb == NULL) {
		panic("tcp_unlock: so=%p NO PCB usecount=%x lr=%p lrh= %s\n", 
		    so, so->so_usecount, lr_saved, solockhistory_nr(so));
		/* NOTREACHED */
	} else {
		lck_mtx_assert(&((struct inpcb *)so->so_pcb)->inpcb_mtx,
		    LCK_MTX_ASSERT_OWNED);
		so->unlock_lr[so->next_unlock_lr] = lr_saved;
		so->next_unlock_lr = (so->next_unlock_lr+1) % SO_LCKDBG_MAX;
		lck_mtx_unlock(&((struct inpcb *)so->so_pcb)->inpcb_mtx);
	}
	return (0);
}

lck_mtx_t *
tcp_getlock(
	struct socket *so,
	__unused int locktype)
{
	struct inpcb *inp = sotoinpcb(so);

	if (so->so_pcb)  {
		if (so->so_usecount < 0)
			panic("tcp_getlock: so=%p usecount=%x lrh= %s\n", 
			    so, so->so_usecount, solockhistory_nr(so));	
		return(&inp->inpcb_mtx);
	}
	else {
		panic("tcp_getlock: so=%p NULL so_pcb %s\n", 
		    so, solockhistory_nr(so));
		return (so->so_proto->pr_domain->dom_mtx);
	}
}

int32_t
tcp_sbspace(struct tcpcb *tp)
{
	struct sockbuf *sb = &tp->t_inpcb->inp_socket->so_rcv;
	int32_t space, newspace;

	space =  ((int32_t) imin((sb->sb_hiwat - sb->sb_cc), 
		(sb->sb_mbmax - sb->sb_mbcnt)));
	if (space < 0) 
		space = 0;

	/* Avoid increasing window size if the current window
	 * is already very low, we could be in "persist" mode and
	 * we could break some apps (see rdar://5409343)
	 */

	if (space < tp->t_maxseg) 
		return space;

	/* Clip window size for slower link */ 

	if (((tp->t_flags & TF_SLOWLINK) != 0) && slowlink_wsize > 0 )	
		return imin(space, slowlink_wsize);

	/*
	 * Check for ressources constraints before over-ajusting the amount of space we can
	 * advertise in the TCP window size updates.
	 */

	if (sbspace_factor && (tp->t_inpcb->inp_pcbinfo->ipi_count < tcp_sockthreshold) &&
      		    (total_mb_cnt / 8) < (mbstat.m_clusters / sbspace_factor)) {
		if (space < (int32_t)(sb->sb_maxused - sb->sb_cc)) {/* make sure we don't constrain the window if we have enough ressources */
			space = (int32_t) imax((sb->sb_maxused - sb->sb_cc), tp->rcv_maxbyps);
		}
		newspace = (int32_t) imax(((int32_t)sb->sb_maxused - sb->sb_cc), (int32_t)tp->rcv_maxbyps);

		if (newspace > space)
			space = newspace;
	}
	return space;
}
/*
 * Checks TCP Segment Offloading capability for a given connection and interface pair.
 */
void
tcp_set_tso(tp, ifp)
	struct tcpcb *tp;
	struct ifnet *ifp;
{
#if INET6
	struct inpcb *inp = tp->t_inpcb;
	int isipv6 = (inp->inp_vflag & INP_IPV6) != 0;

	if (isipv6) {
		if (ifp && ifp->if_hwassist & IFNET_TSO_IPV6) {
			tp->t_flags |= TF_TSO;
			if (ifp->if_tso_v6_mtu != 0) 
				tp->tso_max_segment_size = ifp->if_tso_v6_mtu;
			else
				tp->tso_max_segment_size = TCP_MAXWIN;
		} else
				tp->t_flags &= ~TF_TSO;

	} else 
#endif /* INET6 */

	{
		if (ifp && ifp->if_hwassist & IFNET_TSO_IPV4) {
			tp->t_flags |= TF_TSO;
			if (ifp->if_tso_v4_mtu != 0) 
				tp->tso_max_segment_size = ifp->if_tso_v4_mtu;
			else
				tp->tso_max_segment_size = TCP_MAXWIN;
		} else
				tp->t_flags &= ~TF_TSO;
	}
}

#define TIMEVAL_TO_TCPHZ(_tv_) ((_tv_).tv_sec * TCP_RETRANSHZ + (_tv_).tv_usec / TCP_RETRANSHZ_TO_USEC)

/* Function to calculate the tcp clock. The tcp clock will get updated
 * at the boundaries of the tcp layer. This is done at 3 places:
 * 1. Right before processing an input tcp packet 
 * 2. Whenever a connection wants to access the network using tcp_usrreqs
 * 3. When a tcp timer fires or before tcp slow timeout
 *
 */

void
calculate_tcp_clock()
{
	struct timeval tv = tcp_uptime;
	struct timeval interval = {0, TCP_RETRANSHZ_TO_USEC};
	struct timeval now, hold_now;
	uint32_t incr = 0;

	timevaladd(&tv, &interval);
	microuptime(&now);
	if (timevalcmp(&now, &tv, >)) {
		/* time to update the clock */
		lck_spin_lock(tcp_uptime_lock);
		if (timevalcmp(&tcp_uptime, &now, >=)) {
			/* clock got updated while we were waiting for the lock */
			lck_spin_unlock(tcp_uptime_lock);
			return;
			}

		microuptime(&now);
		hold_now = now;
		tv = tcp_uptime;
		timevalsub(&now, &tv);

		incr = TIMEVAL_TO_TCPHZ(now);
		if (incr > 0) {
			tcp_uptime = hold_now;
			tcp_now += incr;
		}

                lck_spin_unlock(tcp_uptime_lock);
        }
        return;
}

/* DSEP Review Done pl-20051213-v02 @3253,@3391,@3400 */
