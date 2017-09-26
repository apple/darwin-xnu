/*
 * Copyright (c) 2000-2017 Apple Inc. All rights reserved.
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

#include <dev/random/randomdev.h>

#include <net/route.h>
#include <net/if.h>
#include <net/content_filter.h>

#define	tcp_minmssoverload fring
#define	_IP_VHL
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#if INET6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
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
#include <netinet/mptcp_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_cc.h>
#include <netinet/tcp_cache.h>
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
#endif /* IPSEC */

#if NECP
#include <net/necp.h>
#endif /* NECP */

#undef tcp_minmssoverload

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif /* MAC_NET */

#include <corecrypto/ccaes.h>
#include <libkern/crypto/aes.h>
#include <libkern/crypto/md5.h>
#include <sys/kdebug.h>
#include <mach/sdt.h>

#include <netinet/lro_ext.h>

#define	DBG_FNC_TCP_CLOSE	NETDBG_CODE(DBG_NETTCP, ((5 << 8) | 2))

static tcp_cc tcp_ccgen;
extern int tcp_lq_overflow;

extern struct tcptimerlist tcp_timer_list;
extern struct tcptailq tcp_tw_tailq;

SYSCTL_SKMEM_TCP_INT(TCPCTL_MSSDFLT, mssdflt, CTLFLAG_RW | CTLFLAG_LOCKED,
	int, tcp_mssdflt, TCP_MSS, "Default TCP Maximum Segment Size");

#if INET6
SYSCTL_SKMEM_TCP_INT(TCPCTL_V6MSSDFLT, v6mssdflt,
	CTLFLAG_RW | CTLFLAG_LOCKED, int, tcp_v6mssdflt, TCP6_MSS,
	"Default TCP Maximum Segment Size for IPv6");
#endif

int tcp_sysctl_fastopenkey(struct sysctl_oid *, void *, int,
    struct sysctl_req *);
SYSCTL_PROC(_net_inet_tcp, OID_AUTO, fastopen_key, CTLTYPE_STRING | CTLFLAG_WR,
	0, 0, tcp_sysctl_fastopenkey, "S", "TCP Fastopen key");

/* Current count of half-open TFO connections */
int	tcp_tfo_halfcnt = 0;

/* Maximum of half-open TFO connection backlog */
SYSCTL_SKMEM_TCP_INT(OID_AUTO, fastopen_backlog,
	CTLFLAG_RW | CTLFLAG_LOCKED, int, tcp_tfo_backlog, 10,
	"Backlog queue for half-open TFO connections");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, fastopen, CTLFLAG_RW | CTLFLAG_LOCKED,
	int, tcp_fastopen, TCP_FASTOPEN_CLIENT | TCP_FASTOPEN_SERVER,
	"Enable TCP Fastopen (RFC 7413)");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, now_init, CTLFLAG_RD | CTLFLAG_LOCKED,
	uint32_t, tcp_now_init, 0, "Initial tcp now value");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, microuptime_init, CTLFLAG_RD | CTLFLAG_LOCKED,
	uint32_t, tcp_microuptime_init, 0, "Initial tcp uptime value in micro seconds");

/*
 * Minimum MSS we accept and use. This prevents DoS attacks where
 * we are forced to a ridiculous low MSS like 20 and send hundreds
 * of packets instead of one. The effect scales with the available
 * bandwidth and quickly saturates the CPU and network interface
 * with packet generation and sending. Set to zero to disable MINMSS
 * checking. This setting prevents us from sending too small packets.
 */
SYSCTL_SKMEM_TCP_INT(OID_AUTO, minmss, CTLFLAG_RW | CTLFLAG_LOCKED,
	int, tcp_minmss, TCP_MINMSS, "Minmum TCP Maximum Segment Size");
int tcp_do_rfc1323 = 1;
#if (DEVELOPMENT || DEBUG)
SYSCTL_INT(_net_inet_tcp, TCPCTL_DO_RFC1323, rfc1323,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_do_rfc1323, 0,
	"Enable rfc1323 (high performance TCP) extensions");
#endif /* (DEVELOPMENT || DEBUG) */

// Not used
static int	tcp_do_rfc1644 = 0;
SYSCTL_INT(_net_inet_tcp, TCPCTL_DO_RFC1644, rfc1644,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_do_rfc1644, 0,
	"Enable rfc1644 (TTCP) extensions");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, do_tcpdrain, CTLFLAG_RW | CTLFLAG_LOCKED,
	static int, do_tcpdrain, 0,
	"Enable tcp_drain routine for extra help when low on mbufs");

SYSCTL_INT(_net_inet_tcp, OID_AUTO, pcbcount, CTLFLAG_RD | CTLFLAG_LOCKED,
	&tcbinfo.ipi_count, 0, "Number of active PCBs");

SYSCTL_INT(_net_inet_tcp, OID_AUTO, tw_pcbcount, CTLFLAG_RD | CTLFLAG_LOCKED,
	&tcbinfo.ipi_twcount, 0, "Number of pcbs in time-wait state");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, icmp_may_rst, CTLFLAG_RW | CTLFLAG_LOCKED,
	static int, icmp_may_rst, 1,
	"Certain ICMP unreachable messages may abort connections in SYN_SENT");

static int	tcp_strict_rfc1948 = 0;
static int	tcp_isn_reseed_interval = 0;
#if (DEVELOPMENT || DEBUG)
SYSCTL_INT(_net_inet_tcp, OID_AUTO, strict_rfc1948, CTLFLAG_RW | CTLFLAG_LOCKED,
	&tcp_strict_rfc1948, 0, "Determines if RFC1948 is followed exactly");

SYSCTL_INT(_net_inet_tcp, OID_AUTO, isn_reseed_interval,
	CTLFLAG_RW | CTLFLAG_LOCKED,
	&tcp_isn_reseed_interval, 0, "Seconds between reseeding of ISN secret");
#endif /* (DEVELOPMENT || DEBUG) */

SYSCTL_SKMEM_TCP_INT(OID_AUTO, rtt_min, CTLFLAG_RW | CTLFLAG_LOCKED,
	int, tcp_TCPTV_MIN, 100, "min rtt value allowed");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, rexmt_slop, CTLFLAG_RW,
	int, tcp_rexmt_slop, TCPTV_REXMTSLOP, "Slop added to retransmit timeout");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, randomize_ports, CTLFLAG_RW | CTLFLAG_LOCKED,
	__private_extern__ int , tcp_use_randomport, 0,
	"Randomize TCP port numbers");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, win_scale_factor, CTLFLAG_RW | CTLFLAG_LOCKED,
	__private_extern__ int, tcp_win_scale, 3, "Window scaling factor");

static void	tcp_cleartaocache(void);
static void	tcp_notify(struct inpcb *, int);

struct zone	*sack_hole_zone;
struct zone	*tcp_reass_zone;
struct zone	*tcp_bwmeas_zone;
struct zone	*tcp_rxt_seg_zone;

extern int slowlink_wsize;	/* window correction for slow links */
extern int path_mtu_discovery;

static void tcp_sbrcv_grow_rwin(struct tcpcb *tp, struct sockbuf *sb);

#define	TCP_BWMEAS_BURST_MINSIZE 6
#define	TCP_BWMEAS_BURST_MAXSIZE 25

static uint32_t bwmeas_elm_size;

/*
 * Target size of TCP PCB hash tables. Must be a power of two.
 *
 * Note that this can be overridden by the kernel environment
 * variable net.inet.tcp.tcbhashsize
 */
#ifndef TCBHASHSIZE
#define	TCBHASHSIZE	CONFIG_TCBHASHSIZE
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

int  get_inpcb_str_size(void);
int  get_tcp_str_size(void);

static void tcpcb_to_otcpcb(struct tcpcb *, struct otcpcb *);

static lck_attr_t *tcp_uptime_mtx_attr = NULL;
static lck_grp_t *tcp_uptime_mtx_grp = NULL;
static lck_grp_attr_t *tcp_uptime_mtx_grp_attr = NULL;
int tcp_notsent_lowat_check(struct socket *so);
static void tcp_flow_lim_stats(struct ifnet_stats_per_flow *ifs,
    struct if_lim_perf_stat *stat);
static void tcp_flow_ecn_perf_stats(struct ifnet_stats_per_flow *ifs,
    struct if_tcp_ecn_perf_stat *stat);

static aes_encrypt_ctx tfo_ctx; /* Crypto-context for TFO */

void
tcp_tfo_gen_cookie(struct inpcb *inp, u_char *out, size_t blk_size)
{
	u_char in[CCAES_BLOCK_SIZE];
#if INET6
	int isipv6 = inp->inp_vflag & INP_IPV6;
#endif

	VERIFY(blk_size == CCAES_BLOCK_SIZE);

	bzero(&in[0], CCAES_BLOCK_SIZE);
	bzero(&out[0], CCAES_BLOCK_SIZE);

#if INET6
	if (isipv6)
		memcpy(in, &inp->in6p_faddr, sizeof(struct in6_addr));
	else
#endif /* INET6 */
		memcpy(in, &inp->inp_faddr, sizeof(struct in_addr));

	aes_encrypt_cbc(in, NULL, 1, out, &tfo_ctx);
}

__private_extern__ int
tcp_sysctl_fastopenkey(__unused struct sysctl_oid *oidp, __unused void *arg1,
    __unused int arg2, struct sysctl_req *req)
{
	int error = 0;
	/*
	 * TFO-key is expressed as a string in hex format
	 * (+1 to account for \0 char)
	 */
	char keystring[TCP_FASTOPEN_KEYLEN * 2 + 1];
	u_int32_t key[TCP_FASTOPEN_KEYLEN / sizeof(u_int32_t)];
	int i;

	/* -1, because newlen is len without the terminating \0 character */
	if (req->newlen != (sizeof(keystring) - 1)) {
		error = EINVAL;
		goto exit;
	}

	/*
	 * sysctl_io_string copies keystring into the oldptr of the sysctl_req.
	 * Make sure everything is zero, to avoid putting garbage in there or
	 * leaking the stack.
	 */
	bzero(keystring, sizeof(keystring));

	error = sysctl_io_string(req, keystring, sizeof(keystring), 0, NULL);
	if (error)
		goto exit;

	for (i = 0; i < (TCP_FASTOPEN_KEYLEN / sizeof(u_int32_t)); i++) {
		/*
		 * We jump over the keystring in 8-character (4 byte in hex)
		 * steps
		 */
		if (sscanf(&keystring[i * 8], "%8x", &key[i]) != 1) {
			error = EINVAL;
			goto exit;
		}
	}

	aes_encrypt_key128((u_char *)key, &tfo_ctx);

exit:
	return (error);
}

int
get_inpcb_str_size(void)
{
	return (sizeof(struct inpcb));
}

int
get_tcp_str_size(void)
{
	return (sizeof(struct tcpcb));
}

int	tcp_freeq(struct tcpcb *tp);

static int scale_to_powerof2(int size);

/*
 * This helper routine returns one of the following scaled value of size:
 * 1. Rounded down power of two value of size if the size value passed as
 *    argument is not a power of two and the rounded up value overflows.
 * OR
 * 2. Rounded up power of two value of size if the size value passed as
 *    argument is not a power of two and the rounded up value does not overflow
 * OR
 * 3. Same value as argument size if it is already a power of two.
 */
static int
scale_to_powerof2(int size) {
	/* Handle special case of size = 0 */
	int ret = size ? size : 1;

	if (!powerof2(ret)) {
		while (!powerof2(size)) {
			/*
			 * Clear out least significant
			 * set bit till size is left with
			 * its highest set bit at which point
			 * it is rounded down power of two.
			 */
			size = size & (size -1);
		}

		/* Check for overflow when rounding up */
		if (0 == (size << 1)) {
			ret = size;
		} else {
			ret = size << 1;
		}
	}

	return (ret);
}

static void
tcp_tfo_init(void)
{
	u_char key[TCP_FASTOPEN_KEYLEN];

	read_frandom(key, sizeof(key));
	aes_encrypt_key128(key, &tfo_ctx);
}

/*
 * Tcp initialization
 */
void
tcp_init(struct protosw *pp, struct domain *dp)
{
#pragma unused(dp)
	static int tcp_initialized = 0;
	vm_size_t str_size;
	struct inpcbinfo *pcbinfo;

	VERIFY((pp->pr_flags & (PR_INITIALIZED|PR_ATTACHED)) == PR_ATTACHED);

	if (tcp_initialized)
		return;
	tcp_initialized = 1;

	tcp_ccgen = 1;
	tcp_cleartaocache();

	tcp_keepinit = TCPTV_KEEP_INIT;
	tcp_keepidle = TCPTV_KEEP_IDLE;
	tcp_keepintvl = TCPTV_KEEPINTVL;
	tcp_keepcnt = TCPTV_KEEPCNT;
	tcp_maxpersistidle = TCPTV_KEEP_IDLE;
	tcp_msl = TCPTV_MSL;

	microuptime(&tcp_uptime);
	read_frandom(&tcp_now, sizeof(tcp_now));

	/* Starts tcp internal clock at a random value */
	tcp_now = tcp_now & 0x3fffffff;

	/* expose initial uptime/now via systcl for utcp to keep time sync */
	tcp_now_init = tcp_now;
	tcp_microuptime_init = tcp_uptime.tv_sec * 1000 + tcp_uptime.tv_usec;
	SYSCTL_SKMEM_UPDATE_FIELD(tcp.microuptime_init, tcp_microuptime_init);
	SYSCTL_SKMEM_UPDATE_FIELD(tcp.now_init, tcp_now_init);

	tcp_tfo_init();

	LIST_INIT(&tcb);
	tcbinfo.ipi_listhead = &tcb;

	pcbinfo = &tcbinfo;
	/*
	 * allocate lock group attribute and group for tcp pcb mutexes
	 */
	pcbinfo->ipi_lock_grp_attr = lck_grp_attr_alloc_init();
	pcbinfo->ipi_lock_grp = lck_grp_alloc_init("tcppcb",
	    pcbinfo->ipi_lock_grp_attr);

	/*
	 * allocate the lock attribute for tcp pcb mutexes
	 */
	pcbinfo->ipi_lock_attr = lck_attr_alloc_init();

	if ((pcbinfo->ipi_lock = lck_rw_alloc_init(pcbinfo->ipi_lock_grp,
	    pcbinfo->ipi_lock_attr)) == NULL) {
		panic("%s: unable to allocate PCB lock\n", __func__);
		/* NOTREACHED */
	}

	if (tcp_tcbhashsize == 0) {
		/* Set to default */
		tcp_tcbhashsize = 512;
	}

	if (!powerof2(tcp_tcbhashsize)) {
		int old_hash_size = tcp_tcbhashsize;
		tcp_tcbhashsize = scale_to_powerof2(tcp_tcbhashsize);
		/* Lower limit of 16  */
		if (tcp_tcbhashsize < 16) {
			tcp_tcbhashsize = 16;
		}
		printf("WARNING: TCB hash size not a power of 2, "
				"scaled from %d to %d.\n",
				old_hash_size,
				tcp_tcbhashsize);
	}

	tcbinfo.ipi_hashbase = hashinit(tcp_tcbhashsize, M_PCB,
	    &tcbinfo.ipi_hashmask);
	tcbinfo.ipi_porthashbase = hashinit(tcp_tcbhashsize, M_PCB,
					&tcbinfo.ipi_porthashmask);
	str_size = P2ROUNDUP(sizeof(struct inp_tp), sizeof(u_int64_t));
	tcbinfo.ipi_zone = zinit(str_size, 120000*str_size, 8192, "tcpcb");
	zone_change(tcbinfo.ipi_zone, Z_CALLERACCT, FALSE);
	zone_change(tcbinfo.ipi_zone, Z_EXPAND, TRUE);

	tcbinfo.ipi_gc = tcp_gc;
	tcbinfo.ipi_timer = tcp_itimer;
	in_pcbinfo_attach(&tcbinfo);

	str_size = P2ROUNDUP(sizeof(struct sackhole), sizeof(u_int64_t));
	sack_hole_zone = zinit(str_size, 120000*str_size, 8192,
	    "sack_hole zone");
	zone_change(sack_hole_zone, Z_CALLERACCT, FALSE);
	zone_change(sack_hole_zone, Z_EXPAND, TRUE);

	str_size = P2ROUNDUP(sizeof(struct tseg_qent), sizeof(u_int64_t));
	tcp_reass_zone = zinit(str_size, (nmbclusters >> 4) * str_size,
		0, "tcp_reass_zone");
	if (tcp_reass_zone == NULL) {
		panic("%s: failed allocating tcp_reass_zone", __func__);
		/* NOTREACHED */
	}
	zone_change(tcp_reass_zone, Z_CALLERACCT, FALSE);
	zone_change(tcp_reass_zone, Z_EXPAND, TRUE);

	bwmeas_elm_size = P2ROUNDUP(sizeof(struct bwmeas), sizeof(u_int64_t));
	tcp_bwmeas_zone = zinit(bwmeas_elm_size, (100 * bwmeas_elm_size), 0,
	    "tcp_bwmeas_zone");
	if (tcp_bwmeas_zone == NULL) {
		panic("%s: failed allocating tcp_bwmeas_zone", __func__);
		/* NOTREACHED */
	}
	zone_change(tcp_bwmeas_zone, Z_CALLERACCT, FALSE);
	zone_change(tcp_bwmeas_zone, Z_EXPAND, TRUE);

	str_size = P2ROUNDUP(sizeof(struct tcp_ccstate), sizeof(u_int64_t));
	tcp_cc_zone = zinit(str_size, 20000 * str_size, 0, "tcp_cc_zone");
	zone_change(tcp_cc_zone, Z_CALLERACCT, FALSE);
	zone_change(tcp_cc_zone, Z_EXPAND, TRUE);

	str_size = P2ROUNDUP(sizeof(struct tcp_rxt_seg), sizeof(u_int64_t));
	tcp_rxt_seg_zone = zinit(str_size, 10000 * str_size, 0,
	    "tcp_rxt_seg_zone");
	zone_change(tcp_rxt_seg_zone, Z_CALLERACCT, FALSE);
	zone_change(tcp_rxt_seg_zone, Z_EXPAND, TRUE);

#if INET6
#define	TCP_MINPROTOHDR (sizeof(struct ip6_hdr) + sizeof(struct tcphdr))
#else /* INET6 */
#define	TCP_MINPROTOHDR (sizeof(struct tcpiphdr))
#endif /* INET6 */
	if (max_protohdr < TCP_MINPROTOHDR) {
		_max_protohdr = TCP_MINPROTOHDR;
		_max_protohdr = max_protohdr;	/* round it up */
	}
	if (max_linkhdr + max_protohdr > MCLBYTES)
		panic("tcp_init");
#undef TCP_MINPROTOHDR

	/* Initialize time wait and timer lists */
	TAILQ_INIT(&tcp_tw_tailq);

	bzero(&tcp_timer_list, sizeof(tcp_timer_list));
	LIST_INIT(&tcp_timer_list.lhead);
	/*
	 * allocate lock group attribute, group and attribute for
	 * the tcp timer list
	 */
	tcp_timer_list.mtx_grp_attr = lck_grp_attr_alloc_init();
	tcp_timer_list.mtx_grp = lck_grp_alloc_init("tcptimerlist",
	    tcp_timer_list.mtx_grp_attr);
	tcp_timer_list.mtx_attr = lck_attr_alloc_init();
	if ((tcp_timer_list.mtx = lck_mtx_alloc_init(tcp_timer_list.mtx_grp,
	    tcp_timer_list.mtx_attr)) == NULL) {
		panic("failed to allocate memory for tcp_timer_list.mtx\n");
	};
	tcp_timer_list.call = thread_call_allocate(tcp_run_timerlist, NULL);
	if (tcp_timer_list.call == NULL) {
		panic("failed to allocate call entry 1 in tcp_init\n");
	}

	/*
	 * allocate lock group attribute, group and attribute for
	 * tcp_uptime_lock
	 */
	tcp_uptime_mtx_grp_attr = lck_grp_attr_alloc_init();
	tcp_uptime_mtx_grp = lck_grp_alloc_init("tcpuptime",
	    tcp_uptime_mtx_grp_attr);
	tcp_uptime_mtx_attr = lck_attr_alloc_init();
	tcp_uptime_lock = lck_spin_alloc_init(tcp_uptime_mtx_grp,
	    tcp_uptime_mtx_attr);

	/* Initialize TCP LRO data structures */
	tcp_lro_init();

	/* Initialize TCP Cache */
	tcp_cache_init();

	/*
	 * If more than 60 MB of mbuf pool is available, increase the
	 * maximum allowed receive and send socket buffer size.
	 */
	if (nmbclusters > 30720) {
		#if CONFIG_EMBEDDED
			tcp_autorcvbuf_max = 2 * 1024 * 1024;
			tcp_autosndbuf_max = 2 * 1024 * 1024;
		#else
			tcp_autorcvbuf_max = 1024 * 1024;
			tcp_autosndbuf_max = 1024 * 1024;
		#endif /* CONFIG_EMBEDDED */
		SYSCTL_SKMEM_UPDATE_FIELD(tcp.autorcvbufmax, tcp_autorcvbuf_max);
		SYSCTL_SKMEM_UPDATE_FIELD(tcp.autosndbufmax, tcp_autosndbuf_max);

		/*
		 * Receive buffer max for cellular interfaces supporting
		 * Carrier Aggregation is higher
		 */
		tcp_autorcvbuf_max_ca = 2 * 1024 * 1024;
	}
}

/*
 * Fill in the IP and TCP headers for an outgoing packet, given the tcpcb.
 * tcp_template used to store this data in mbufs, but we now recopy it out
 * of the tcpcb each time to conserve mbufs.
 */
void
tcp_fillheaders(struct tcpcb *tp, void *ip_ptr, void *tcp_ptr)
{
	struct inpcb *inp = tp->t_inpcb;
	struct tcphdr *tcp_hdr = (struct tcphdr *)tcp_ptr;

#if INET6
	if ((inp->inp_vflag & INP_IPV6) != 0) {
		struct ip6_hdr *ip6;

		ip6 = (struct ip6_hdr *)ip_ptr;
		ip6->ip6_flow = (ip6->ip6_flow & ~IPV6_FLOWINFO_MASK) |
			(inp->inp_flow & IPV6_FLOWINFO_MASK);
		ip6->ip6_vfc = (ip6->ip6_vfc & ~IPV6_VERSION_MASK) |
			(IPV6_VERSION & IPV6_VERSION_MASK);
		ip6->ip6_plen = htons(sizeof(struct tcphdr));
		ip6->ip6_nxt = IPPROTO_TCP;
		ip6->ip6_hlim = 0;
		ip6->ip6_src = inp->in6p_laddr;
		ip6->ip6_dst = inp->in6p_faddr;
		tcp_hdr->th_sum = in6_pseudo(&inp->in6p_laddr, &inp->in6p_faddr,
		    htonl(sizeof (struct tcphdr) + IPPROTO_TCP));
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
		tcp_hdr->th_sum =
		    in_pseudo(ip->ip_src.s_addr, ip->ip_dst.s_addr,
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
tcp_maketemplate(struct tcpcb *tp)
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
tcp_respond(struct tcpcb *tp, void *ipgen, struct tcphdr *th, struct mbuf *m,
    tcp_seq ack, tcp_seq seq, int flags, struct tcp_respond_args *tra)
{
	int tlen;
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
	struct ifnet *outif;
	int sotc = SO_TC_UNSPEC;

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
			bzero(ro6, sizeof(*ro6));
		} else
#endif /* INET6 */
		{
			ro = &sro;
			bzero(ro, sizeof(*ro));
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
			VERIFY((MHLEN - max_linkhdr) >=
			    (sizeof (*ip6) + sizeof (*nth)));
			bcopy((caddr_t)ip6, mtod(m, caddr_t),
			    sizeof(struct ip6_hdr));
			ip6 = mtod(m, struct ip6_hdr *);
			nth = (struct tcphdr *)(void *)(ip6 + 1);
		} else
#endif /* INET6 */
		{
			VERIFY((MHLEN - max_linkhdr) >=
			    (sizeof (*ip) + sizeof (*nth)));
			bcopy((caddr_t)ip, mtod(m, caddr_t), sizeof(struct ip));
			ip = mtod(m, struct ip *);
			nth = (struct tcphdr *)(void *)(ip + 1);
		}
		bcopy((caddr_t)th, (caddr_t)nth, sizeof(struct tcphdr));
#if MPTCP
		if ((tp) && (tp->t_mpflags & TMPF_RESET))
			flags = (TH_RST | TH_ACK);
		else
#endif
		flags = TH_ACK;
	} else {
		m_freem(m->m_next);
		m->m_next = 0;
		m->m_data = (caddr_t)ipgen;
		/* m_len is set later */
		tlen = 0;
#define	xchg(a, b, type) { type t; t = a; a = b; b = t; }
#if INET6
		if (isipv6) {
			/* Expect 32-bit aligned IP on strict-align platforms */
			IP6_HDR_STRICT_ALIGNMENT_CHECK(ip6);
			xchg(ip6->ip6_dst, ip6->ip6_src, struct in6_addr);
			nth = (struct tcphdr *)(void *)(ip6 + 1);
		} else
#endif /* INET6 */
		{
			/* Expect 32-bit aligned IP on strict-align platforms */
			IP_HDR_STRICT_ALIGNMENT_CHECK(ip);
			xchg(ip->ip_dst.s_addr, ip->ip_src.s_addr, n_long);
			nth = (struct tcphdr *)(void *)(ip + 1);
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
		nth->th_sum = in6_pseudo(&ip6->ip6_src, &ip6->ip6_dst,
		    htonl((tlen - sizeof (struct ip6_hdr)) + IPPROTO_TCP));
		m->m_pkthdr.csum_flags = CSUM_TCPIPV6;
		m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
		ip6->ip6_hlim = in6_selecthlim(tp ? tp->t_inpcb : NULL,
		    ro6 && ro6->ro_rt ? ro6->ro_rt->rt_ifp : NULL);
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

#if NECP
	necp_mark_packet_from_socket(m, tp ? tp->t_inpcb : NULL, 0, 0);
#endif /* NECP */

#if IPSEC
	if (tp != NULL && tp->t_inpcb->inp_sp != NULL &&
		ipsec_setsocket(m, tp ? tp->t_inpcb->inp_socket : NULL) != 0) {
		m_freem(m);
		return;
	}
#endif

	if (tp != NULL) {
		u_int32_t svc_flags = 0;
		if (isipv6) {
			svc_flags |= PKT_SCF_IPV6;
		}
		sotc = tp->t_inpcb->inp_socket->so_traffic_class;
		set_packet_service_class(m, tp->t_inpcb->inp_socket,
		    sotc, svc_flags);

		/* Embed flowhash and flow control flags */
		m->m_pkthdr.pkt_flowsrc = FLOWSRC_INPCB;
		m->m_pkthdr.pkt_flowid = tp->t_inpcb->inp_flowhash;
		m->m_pkthdr.pkt_flags |= (PKTF_FLOW_ID | PKTF_FLOW_LOCALSRC | PKTF_FLOW_ADV);
		m->m_pkthdr.pkt_proto = IPPROTO_TCP;
	}

#if INET6
	if (isipv6) {
		struct ip6_out_args ip6oa = { tra->ifscope, { 0 },
		    IP6OAF_SELECT_SRCIF | IP6OAF_BOUND_SRCADDR, 0,
		    SO_TC_UNSPEC, _NET_SERVICE_TYPE_UNSPEC};

		if (tra->ifscope != IFSCOPE_NONE)
			ip6oa.ip6oa_flags |= IP6OAF_BOUND_IF;
		if (tra->nocell)
			ip6oa.ip6oa_flags |= IP6OAF_NO_CELLULAR;
		if (tra->noexpensive)
			ip6oa.ip6oa_flags |= IP6OAF_NO_EXPENSIVE;
		if (tra->awdl_unrestricted)
			ip6oa.ip6oa_flags |= IP6OAF_AWDL_UNRESTRICTED;
		if (tra->intcoproc_allowed)
			ip6oa.ip6oa_flags |= IP6OAF_INTCOPROC_ALLOWED;
		ip6oa.ip6oa_sotc = sotc;
		if (tp != NULL) {
			if ((tp->t_inpcb->inp_socket->so_flags1 & SOF1_QOSMARKING_ALLOWED))
				ip6oa.ip6oa_flags |= IP6OAF_QOSMARKING_ALLOWED;
			ip6oa.ip6oa_netsvctype = tp->t_inpcb->inp_socket->so_netsvctype;
		}
		(void) ip6_output(m, NULL, ro6, IPV6_OUTARGS, NULL,
		    NULL, &ip6oa);

		if (tp != NULL && ro6 != NULL && ro6->ro_rt != NULL &&
		    (outif = ro6->ro_rt->rt_ifp) !=
		    tp->t_inpcb->in6p_last_outifp) {
			tp->t_inpcb->in6p_last_outifp = outif;
		}

		if (ro6 == &sro6)
			ROUTE_RELEASE(ro6);
	} else
#endif /* INET6 */
	{
		struct ip_out_args ipoa = { tra->ifscope, { 0 },
		    IPOAF_SELECT_SRCIF | IPOAF_BOUND_SRCADDR, 0,
		    SO_TC_UNSPEC, _NET_SERVICE_TYPE_UNSPEC };

		if (tra->ifscope != IFSCOPE_NONE)
			ipoa.ipoa_flags |= IPOAF_BOUND_IF;
		if (tra->nocell)
			ipoa.ipoa_flags |= IPOAF_NO_CELLULAR;
		if (tra->noexpensive)
			ipoa.ipoa_flags |= IPOAF_NO_EXPENSIVE;
		if (tra->awdl_unrestricted)
			ipoa.ipoa_flags |= IPOAF_AWDL_UNRESTRICTED;
		ipoa.ipoa_sotc = sotc;
		if (tp != NULL) {
			if ((tp->t_inpcb->inp_socket->so_flags1 & SOF1_QOSMARKING_ALLOWED))
				ipoa.ipoa_flags |= IPOAF_QOSMARKING_ALLOWED;
			ipoa.ipoa_netsvctype = tp->t_inpcb->inp_socket->so_netsvctype;
		}
		if (ro != &sro) {
			/* Copy the cached route and take an extra reference */
			inp_route_copyout(tp->t_inpcb, &sro);
		}
		/*
		 * For consistency, pass a local route copy.
		 */
		(void) ip_output(m, NULL, &sro, IP_OUTARGS, NULL, &ipoa);

		if (tp != NULL && sro.ro_rt != NULL &&
		    (outif = sro.ro_rt->rt_ifp) !=
		    tp->t_inpcb->inp_last_outifp) {
			tp->t_inpcb->inp_last_outifp = outif;

		}
		if (ro != &sro) {
			/* Synchronize cached PCB route */
			inp_route_copyin(tp->t_inpcb, &sro);
		} else {
			ROUTE_RELEASE(&sro);
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
tcp_newtcpcb(struct inpcb *inp)
{
	struct inp_tp *it;
	struct tcpcb *tp;
	struct socket *so = inp->inp_socket;
#if INET6
	int isipv6 = (inp->inp_vflag & INP_IPV6) != 0;
#endif /* INET6 */

	calculate_tcp_clock();

	if ((so->so_flags1 & SOF1_CACHED_IN_SOCK_LAYER) == 0) {
	    it = (struct inp_tp *)(void *)inp;
	    tp = &it->tcb;
	} else {
	    tp = (struct tcpcb *)(void *)inp->inp_saved_ppcb;
	}

	bzero((char *) tp, sizeof(struct tcpcb));
	LIST_INIT(&tp->t_segq);
	tp->t_maxseg = tp->t_maxopd =
#if INET6
		isipv6 ? tcp_v6mssdflt :
#endif /* INET6 */
		tcp_mssdflt;

	if (tcp_do_rfc1323)
		tp->t_flags = (TF_REQ_SCALE|TF_REQ_TSTMP);
	if (tcp_do_sack)
		tp->t_flagsext |= TF_SACK_ENABLE;

	TAILQ_INIT(&tp->snd_holes);
	SLIST_INIT(&tp->t_rxt_segments);
	SLIST_INIT(&tp->t_notify_ack);
	tp->t_inpcb = inp;
	/*
	 * Init srtt to TCPTV_SRTTBASE (0), so we can tell that we have no
	 * rtt estimate.  Set rttvar so that srtt + 4 * rttvar gives
	 * reasonable initial retransmit time.
	 */
	tp->t_srtt = TCPTV_SRTTBASE;
	tp->t_rttvar =
	    ((TCPTV_RTOBASE - TCPTV_SRTTBASE) << TCP_RTTVAR_SHIFT) / 4;
	tp->t_rttmin = tcp_TCPTV_MIN;
	tp->t_rxtcur = TCPTV_RTOBASE;

	if (tcp_use_newreno)
		/* use newreno by default */
		tp->tcp_cc_index = TCP_CC_ALGO_NEWRENO_INDEX;
	else
		tp->tcp_cc_index = TCP_CC_ALGO_CUBIC_INDEX;

	tcp_cc_allocate_state(tp);

	if (CC_ALGO(tp)->init != NULL)
		CC_ALGO(tp)->init(tp);

	tp->snd_cwnd = TCP_CC_CWND_INIT_BYTES;
	tp->snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	tp->snd_ssthresh_prev = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	tp->t_rcvtime = tcp_now;
	tp->tentry.timer_start = tcp_now;
	tp->t_persist_timeout = tcp_max_persist_timeout;
	tp->t_persist_stop = 0;
	tp->t_flagsext |= TF_RCVUNACK_WAITSS;
	tp->t_rexmtthresh = tcprexmtthresh;

	/* Enable bandwidth measurement on this connection */
	tp->t_flagsext |= TF_MEASURESNDBW;
	if (tp->t_bwmeas == NULL) {
		tp->t_bwmeas = tcp_bwmeas_alloc(tp);
		if (tp->t_bwmeas == NULL)
			tp->t_flagsext &= ~TF_MEASURESNDBW;
	}

	/* Clear time wait tailq entry */
	tp->t_twentry.tqe_next = NULL;
	tp->t_twentry.tqe_prev = NULL;

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
tcp_drop(struct tcpcb *tp, int errno)
{
	struct socket *so = tp->t_inpcb->inp_socket;
#if CONFIG_DTRACE
	struct inpcb *inp = tp->t_inpcb;
#endif

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

void
tcp_getrt_rtt(struct tcpcb *tp, struct rtentry *rt)
{
	u_int32_t rtt = rt->rt_rmx.rmx_rtt;
	int isnetlocal = (tp->t_flags & TF_LOCAL);

	if (rtt != 0) {
		/*
		 * XXX the lock bit for RTT indicates that the value
		 * is also a minimum value; this is subject to time.
		 */
		if (rt->rt_rmx.rmx_locks & RTV_RTT)
			tp->t_rttmin = rtt / (RTM_RTTUNIT / TCP_RETRANSHZ);
		else
			tp->t_rttmin = isnetlocal ? tcp_TCPTV_MIN :
			    TCPTV_REXMTMIN;
		tp->t_srtt =
		    rtt / (RTM_RTTUNIT / (TCP_RETRANSHZ * TCP_RTT_SCALE));
		tcpstat.tcps_usedrtt++;
		if (rt->rt_rmx.rmx_rttvar) {
			tp->t_rttvar = rt->rt_rmx.rmx_rttvar /
			    (RTM_RTTUNIT / (TCP_RETRANSHZ * TCP_RTTVAR_SCALE));
			tcpstat.tcps_usedrttvar++;
		} else {
			/* default variation is +- 1 rtt */
			tp->t_rttvar =
			    tp->t_srtt * TCP_RTTVAR_SCALE / TCP_RTT_SCALE;
		}
		TCPT_RANGESET(tp->t_rxtcur,
			((tp->t_srtt >> 2) + tp->t_rttvar) >> 1,
			tp->t_rttmin, TCPTV_REXMTMAX,
			TCP_ADD_REXMTSLOP(tp));
	}
}

static inline void
tcp_create_ifnet_stats_per_flow(struct tcpcb *tp,
    struct ifnet_stats_per_flow *ifs)
{
	struct inpcb *inp;
	struct socket *so;
	if (tp == NULL || ifs == NULL)
		return;

	bzero(ifs, sizeof(*ifs));
	inp = tp->t_inpcb;
	so = inp->inp_socket;

	ifs->ipv4 = (inp->inp_vflag & INP_IPV6) ? 0 : 1;
	ifs->local = (tp->t_flags & TF_LOCAL) ? 1 : 0;
	ifs->connreset = (so->so_error == ECONNRESET) ? 1 : 0;
	ifs->conntimeout = (so->so_error == ETIMEDOUT) ? 1 : 0;
	ifs->ecn_flags = tp->ecn_flags;
	ifs->txretransmitbytes = tp->t_stat.txretransmitbytes;
	ifs->rxoutoforderbytes = tp->t_stat.rxoutoforderbytes;
	ifs->rxmitpkts = tp->t_stat.rxmitpkts;
	ifs->rcvoopack = tp->t_rcvoopack;
	ifs->pawsdrop = tp->t_pawsdrop;
	ifs->sack_recovery_episodes = tp->t_sack_recovery_episode;
	ifs->reordered_pkts = tp->t_reordered_pkts;
	ifs->dsack_sent = tp->t_dsack_sent;
	ifs->dsack_recvd = tp->t_dsack_recvd;
	ifs->srtt = tp->t_srtt;
	ifs->rttupdated = tp->t_rttupdated;
	ifs->rttvar = tp->t_rttvar;
	ifs->rttmin = get_base_rtt(tp);
	if (tp->t_bwmeas != NULL && tp->t_bwmeas->bw_sndbw_max > 0) {
		ifs->bw_sndbw_max = tp->t_bwmeas->bw_sndbw_max;
	} else {
		ifs->bw_sndbw_max = 0;
	}
	if (tp->t_bwmeas!= NULL && tp->t_bwmeas->bw_rcvbw_max > 0) {
		ifs->bw_rcvbw_max = tp->t_bwmeas->bw_rcvbw_max;
	} else {
		ifs->bw_rcvbw_max = 0;
	}
	ifs->bk_txpackets = so->so_tc_stats[MBUF_TC_BK].txpackets;
	ifs->txpackets = inp->inp_stat->txpackets;
	ifs->rxpackets = inp->inp_stat->rxpackets;
}

static inline void
tcp_flow_ecn_perf_stats(struct ifnet_stats_per_flow *ifs,
    struct if_tcp_ecn_perf_stat *stat)
{
	u_int64_t curval, oldval;
	stat->total_txpkts += ifs->txpackets;
	stat->total_rxpkts += ifs->rxpackets;
	stat->total_rxmitpkts += ifs->rxmitpkts;
	stat->total_oopkts += ifs->rcvoopack;
	stat->total_reorderpkts += (ifs->reordered_pkts +
	    ifs->pawsdrop + ifs->dsack_sent + ifs->dsack_recvd);

	/* Average RTT */
	curval = ifs->srtt >> TCP_RTT_SHIFT;
	if (curval > 0 && ifs->rttupdated >= 16) {
		if (stat->rtt_avg == 0) {
			stat->rtt_avg = curval;
		} else {
			oldval = stat->rtt_avg;
			stat->rtt_avg = ((oldval << 4) - oldval + curval) >> 4;
		}
	}

	/* RTT variance */
	curval = ifs->rttvar >> TCP_RTTVAR_SHIFT;
	if (curval > 0 && ifs->rttupdated >= 16) {
		if (stat->rtt_var == 0) {
			stat->rtt_var = curval;
		} else {
			oldval = stat->rtt_var;
			stat->rtt_var =
			    ((oldval << 4) - oldval + curval) >> 4;
		}
	}

	/* SACK episodes */
	stat->sack_episodes += ifs->sack_recovery_episodes;
	if (ifs->connreset)
		stat->rst_drop++;
}

static inline void
tcp_flow_lim_stats(struct ifnet_stats_per_flow *ifs,
    struct if_lim_perf_stat *stat)
{
	u_int64_t curval, oldval;

	stat->lim_total_txpkts += ifs->txpackets;
	stat->lim_total_rxpkts += ifs->rxpackets;
	stat->lim_total_retxpkts += ifs->rxmitpkts;
	stat->lim_total_oopkts += ifs->rcvoopack;

	if (ifs->bw_sndbw_max > 0) {
		/* convert from bytes per ms to bits per second */
		ifs->bw_sndbw_max *= 8000;
		stat->lim_ul_max_bandwidth = max(stat->lim_ul_max_bandwidth,
		    ifs->bw_sndbw_max);
	}

	if (ifs->bw_rcvbw_max > 0) {
		/* convert from bytes per ms to bits per second */
		ifs->bw_rcvbw_max *= 8000;
		stat->lim_dl_max_bandwidth = max(stat->lim_dl_max_bandwidth,
		    ifs->bw_rcvbw_max);
	}

	/* Average RTT */
	curval = ifs->srtt >> TCP_RTT_SHIFT;
	if (curval > 0 && ifs->rttupdated >= 16) {
		if (stat->lim_rtt_average == 0) {
			stat->lim_rtt_average = curval;
		} else {
			oldval = stat->lim_rtt_average;
			stat->lim_rtt_average =
			    ((oldval << 4) - oldval + curval) >> 4;
		}
	}

	/* RTT variance */
	curval = ifs->rttvar >> TCP_RTTVAR_SHIFT;
	if (curval > 0 && ifs->rttupdated >= 16) {
		if (stat->lim_rtt_variance == 0) {
			stat->lim_rtt_variance = curval;
		} else {
			oldval = stat->lim_rtt_variance;
			stat->lim_rtt_variance =
			    ((oldval << 4) - oldval + curval) >> 4;
		}
	}

	if (stat->lim_rtt_min == 0) {
		stat->lim_rtt_min = ifs->rttmin;
	} else {
		stat->lim_rtt_min = min(stat->lim_rtt_min, ifs->rttmin);
	}

	/* connection timeouts */
	stat->lim_conn_attempts++;
	if (ifs->conntimeout)
		stat->lim_conn_timeouts++;

	/* bytes sent using background delay-based algorithms */
	stat->lim_bk_txpkts += ifs->bk_txpackets;

}

/*
 * Close a TCP control block:
 *	discard all space held by the tcp
 *	discard internet protocol block
 *	wake up any sleepers
 */
struct tcpcb *
tcp_close(struct tcpcb *tp)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
#if INET6
	int isipv6 = (inp->inp_vflag & INP_IPV6) != 0;
#endif /* INET6 */
	struct route *ro;
	struct rtentry *rt;
	int dosavessthresh;
	struct ifnet_stats_per_flow ifs;

	/* tcp_close was called previously, bail */
	if (inp->inp_ppcb == NULL)
		return (NULL);

	tcp_canceltimers(tp);
	KERNEL_DEBUG(DBG_FNC_TCP_CLOSE | DBG_FUNC_START, tp, 0, 0, 0, 0);

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
	if ((tp->t_flags & TF_CLOSING) ||
		inp->inp_sndinprog_cnt > 0) {
		tp->t_flags |= TF_CLOSING;
		return (NULL);
	}

	DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
		struct tcpcb *, tp, int32_t, TCPS_CLOSED);

#if INET6
	ro = (isipv6 ? (struct route *)&inp->in6p_route : &inp->inp_route);
#else
	ro = &inp->inp_route;
#endif
	rt = ro->ro_rt;
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
		u_int32_t i = 0;

#if INET6
		if (isipv6) {
			struct sockaddr_in6 *sin6;

			if (rt == NULL)
				goto no_valid_rt;
			sin6 = (struct sockaddr_in6 *)(void *)rt_key(rt);
			if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
				goto no_valid_rt;
		}
		else
#endif /* INET6 */
		if (ROUTE_UNUSABLE(ro) ||
		    SIN(rt_key(rt))->sin_addr.s_addr == INADDR_ANY) {
			DTRACE_TCP4(state__change, void, NULL,
			    struct inpcb *, inp, struct tcpcb *, tp,
			    int32_t, TCPS_CLOSED);
			tp->t_state = TCPS_CLOSED;
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
		    i != 0 && rt->rt_rmx.rmx_ssthresh != 0) ||
		    dosavessthresh) {
			/*
			 * convert the limit from user data bytes to
			 * packets then to packet data bytes.
			 */
			i = (i + tp->t_maxseg / 2) / tp->t_maxseg;
			if (i < 2)
				i = 2;
			i *= (u_int32_t)(tp->t_maxseg +
#if INET6
			    isipv6 ? sizeof (struct ip6_hdr) +
			    sizeof (struct tcphdr) :
#endif /* INET6 */
			    sizeof (struct tcpiphdr));
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

	/* performance stats per interface */
	tcp_create_ifnet_stats_per_flow(tp, &ifs);
	tcp_update_stats_per_flow(&ifs, inp->inp_last_outifp);

	tcp_free_sackholes(tp);
	tcp_notify_ack_free(tp);

	inp_decr_sndbytes_allunsent(so, tp->snd_una);

	if (tp->t_bwmeas != NULL) {
		tcp_bwmeas_free(tp);
	}
	tcp_rxtseg_clean(tp);
	/* Free the packet list */
	if (tp->t_pktlist_head != NULL)
		m_freem_list(tp->t_pktlist_head);
	TCP_PKTLIST_CLEAR(tp);

	if (so->so_flags1 & SOF1_CACHED_IN_SOCK_LAYER)
	    inp->inp_saved_ppcb = (caddr_t) tp;

	tp->t_state = TCPS_CLOSED;

	/*
	 * Issue a wakeup before detach so that we don't miss
	 * a wakeup
	 */
	sodisconnectwakeup(so);

	/*
	 * Clean up any LRO state
	 */
	if (tp->t_flagsext & TF_LRO_OFFLOADED) {
		tcp_lro_remove_state(inp->inp_laddr, inp->inp_faddr,
		    inp->inp_lport, inp->inp_fport);
		tp->t_flagsext &= ~TF_LRO_OFFLOADED;
	}

	/*
	 * If this is a socket that does not want to wakeup the device
	 * for it's traffic, the application might need to know that the
	 * socket is closed, send a notification.
	 */
	if ((so->so_options & SO_NOWAKEFROMSLEEP) &&
	    inp->inp_state != INPCB_STATE_DEAD &&
	    !(inp->inp_flags2 & INP2_TIMEWAIT))
		socket_post_kev_msg_closed(so);

	if (CC_ALGO(tp)->cleanup != NULL) {
		CC_ALGO(tp)->cleanup(tp);
	}

	if (tp->t_ccstate != NULL) {
		zfree(tcp_cc_zone, tp->t_ccstate);
		tp->t_ccstate = NULL;
	}
	tp->tcp_cc_index = TCP_CC_ALGO_NONE;

	/* Can happen if we close the socket before receiving the third ACK */
	if ((tp->t_tfo_flags & TFO_F_COOKIE_VALID)) {
		OSDecrementAtomic(&tcp_tfo_halfcnt);

		/* Panic if something has gone terribly wrong. */
		VERIFY(tcp_tfo_halfcnt >= 0);

		tp->t_tfo_flags &= ~TFO_F_COOKIE_VALID;
	}

#if INET6
	if (SOCK_CHECK_DOM(so, PF_INET6))
		in6_pcbdetach(inp);
	else
#endif /* INET6 */
	in_pcbdetach(inp);

	/*
	 * Call soisdisconnected after detach because it might unlock the socket
	 */
	soisdisconnected(so);
	tcpstat.tcps_closed++;
	KERNEL_DEBUG(DBG_FNC_TCP_CLOSE | DBG_FUNC_END,
	    tcpstat.tcps_closed, 0, 0, 0, 0);
	return (NULL);
}

int
tcp_freeq(struct tcpcb *tp)
{
	struct tseg_qent *q;
	int rv = 0;

	while ((q = LIST_FIRST(&tp->t_segq)) != NULL) {
		LIST_REMOVE(q, tqe_q);
		m_freem(q->tqe_m);
		zfree(tcp_reass_zone, q);
		rv = 1;
	}
	tp->t_reassqlen = 0;
	return (rv);
}


/*
 * Walk the tcpbs, if existing, and flush the reassembly queue,
 * if there is one when do_tcpdrain is enabled
 * Also defunct the extended background idle socket
 * Do it next time if the pcbinfo lock is in use
 */
void
tcp_drain(void)
{
	struct inpcb *inp;
	struct tcpcb *tp;

	if (!lck_rw_try_lock_exclusive(tcbinfo.ipi_lock))
		return;

	LIST_FOREACH(inp, tcbinfo.ipi_listhead, inp_list) {
		if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) !=
			WNT_STOPUSING) {
			socket_lock(inp->inp_socket, 1);
			if (in_pcb_checkstate(inp, WNT_RELEASE, 1)
				== WNT_STOPUSING) {
				/* lost a race, try the next one */
				socket_unlock(inp->inp_socket, 1);
				continue;
			}
			tp = intotcpcb(inp);

			if (do_tcpdrain)
				tcp_freeq(tp);

			so_drain_extended_bk_idle(inp->inp_socket);

			socket_unlock(inp->inp_socket, 1);
		}
	}
	lck_rw_done(tcbinfo.ipi_lock);

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
tcp_notify(struct inpcb *inp, int error)
{
	struct tcpcb *tp;

	if (inp == NULL || (inp->inp_state == INPCB_STATE_DEAD))
		return; /* pcb is gone already */

	tp = (struct tcpcb *)inp->inp_ppcb;

	VERIFY(tp != NULL);
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
		if (inp->inp_route.ro_rt) {
			rtfree(inp->inp_route.ro_rt);
			inp->inp_route.ro_rt = (struct rtentry *)NULL;
		}
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

struct bwmeas *
tcp_bwmeas_alloc(struct tcpcb *tp)
{
	struct bwmeas *elm;
	elm = zalloc(tcp_bwmeas_zone);
	if (elm == NULL)
		return (elm);

	bzero(elm, bwmeas_elm_size);
	elm->bw_minsizepkts = TCP_BWMEAS_BURST_MINSIZE;
	elm->bw_minsize = elm->bw_minsizepkts * tp->t_maxseg;
	return (elm);
}

void
tcp_bwmeas_free(struct tcpcb *tp)
{
	zfree(tcp_bwmeas_zone, tp->t_bwmeas);
	tp->t_bwmeas = NULL;
	tp->t_flagsext &= ~(TF_MEASURESNDBW);
}

int
get_tcp_inp_list(struct inpcb **inp_list, int n, inp_gen_t gencnt)
{
	struct tcpcb *tp;
	struct inpcb *inp;
	int i = 0;

	LIST_FOREACH(inp, tcbinfo.ipi_listhead, inp_list) {
		if (inp->inp_gencnt <= gencnt &&
		    inp->inp_state != INPCB_STATE_DEAD)
			inp_list[i++] = inp;
		if (i >= n)
			break;
	}

	TAILQ_FOREACH(tp, &tcp_tw_tailq, t_twentry) {
		inp = tp->t_inpcb;
		if (inp->inp_gencnt <= gencnt &&
			inp->inp_state != INPCB_STATE_DEAD)
			inp_list[i++] = inp;
		if (i >= n)
			break;
	}
	return (i);
}

/*
 * tcpcb_to_otcpcb copies specific bits of a tcpcb to a otcpcb format.
 * The otcpcb data structure is passed to user space and must not change.
 */
static void
tcpcb_to_otcpcb(struct tcpcb *tp, struct otcpcb *otp)
{
	otp->t_segq = (uint32_t)VM_KERNEL_ADDRPERM(tp->t_segq.lh_first);
	otp->t_dupacks = tp->t_dupacks;
	otp->t_timer[TCPT_REXMT_EXT] = tp->t_timer[TCPT_REXMT];
	otp->t_timer[TCPT_PERSIST_EXT] = tp->t_timer[TCPT_PERSIST];
	otp->t_timer[TCPT_KEEP_EXT] = tp->t_timer[TCPT_KEEP];
	otp->t_timer[TCPT_2MSL_EXT] = tp->t_timer[TCPT_2MSL];
	otp->t_inpcb =
	    (_TCPCB_PTR(struct inpcb *))VM_KERNEL_ADDRPERM(tp->t_inpcb);
	otp->t_state = tp->t_state;
	otp->t_flags = tp->t_flags;
	otp->t_force = (tp->t_flagsext & TF_FORCE) ? 1 : 0;
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
	otp->cc_send = 0;
	otp->cc_recv = 0;
	otp->snd_recover = tp->snd_recover;
	otp->snd_cwnd_prev = tp->snd_cwnd_prev;
	otp->snd_ssthresh_prev = tp->snd_ssthresh_prev;
	otp->t_badrxtwin = 0;
}

static int
tcp_pcblist SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error, i = 0, n;
	struct inpcb **inp_list;
	inp_gen_t gencnt;
	struct xinpgen xig;

	/*
	 * The process of preparing the TCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	lck_rw_lock_shared(tcbinfo.ipi_lock);
	if (req->oldptr == USER_ADDR_NULL) {
		n = tcbinfo.ipi_count;
		req->oldidx = 2 * (sizeof(xig))
			+ (n + n/8) * sizeof(struct xtcpcb);
		lck_rw_done(tcbinfo.ipi_lock);
		return (0);
	}

	if (req->newptr != USER_ADDR_NULL) {
		lck_rw_done(tcbinfo.ipi_lock);
		return (EPERM);
	}

	/*
	 * OK, now we're committed to doing something.
	 */
	gencnt = tcbinfo.ipi_gencnt;
	n = tcbinfo.ipi_count;

	bzero(&xig, sizeof(xig));
	xig.xig_len = sizeof(xig);
	xig.xig_count = n;
	xig.xig_gen = gencnt;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof(xig));
	if (error) {
		lck_rw_done(tcbinfo.ipi_lock);
		return (error);
	}
	/*
	 * We are done if there is no pcb
	 */
	if (n == 0) {
		lck_rw_done(tcbinfo.ipi_lock);
		return (0);
	}

	inp_list = _MALLOC(n * sizeof (*inp_list), M_TEMP, M_WAITOK);
	if (inp_list == 0) {
		lck_rw_done(tcbinfo.ipi_lock);
		return (ENOMEM);
	}

	n = get_tcp_inp_list(inp_list, n, gencnt);

	error = 0;
	for (i = 0; i < n; i++) {
		struct xtcpcb xt;
		caddr_t inp_ppcb;
		struct inpcb *inp;

		inp = inp_list[i];

		if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) == WNT_STOPUSING)
			continue;
		socket_lock(inp->inp_socket, 1);
		if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) {
			socket_unlock(inp->inp_socket, 1);
			continue;
		}
		if (inp->inp_gencnt > gencnt) {
			socket_unlock(inp->inp_socket, 1);
			continue;
		}

		bzero(&xt, sizeof(xt));
		xt.xt_len = sizeof(xt);
		/* XXX should avoid extra copy */
		inpcb_to_compat(inp, &xt.xt_inp);
		inp_ppcb = inp->inp_ppcb;
		if (inp_ppcb != NULL) {
			tcpcb_to_otcpcb((struct tcpcb *)(void *)inp_ppcb,
			    &xt.xt_tp);
		} else {
			bzero((char *) &xt.xt_tp, sizeof(xt.xt_tp));
		}
		if (inp->inp_socket)
			sotoxsocket(inp->inp_socket, &xt.xt_socket);

		socket_unlock(inp->inp_socket, 1);

		error = SYSCTL_OUT(req, &xt, sizeof(xt));
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
		xig.xig_len = sizeof(xig);
		xig.xig_gen = tcbinfo.ipi_gencnt;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = tcbinfo.ipi_count;
		error = SYSCTL_OUT(req, &xig, sizeof(xig));
	}
	FREE(inp_list, M_TEMP);
	lck_rw_done(tcbinfo.ipi_lock);
	return (error);
}

SYSCTL_PROC(_net_inet_tcp, TCPCTL_PCBLIST, pcblist,
	    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
	    tcp_pcblist, "S,xtcpcb", "List of active TCP connections");

#if !CONFIG_EMBEDDED

static void
tcpcb_to_xtcpcb64(struct tcpcb *tp, struct xtcpcb64 *otp)
{
	otp->t_segq = (uint32_t)VM_KERNEL_ADDRPERM(tp->t_segq.lh_first);
	otp->t_dupacks = tp->t_dupacks;
	otp->t_timer[TCPT_REXMT_EXT] = tp->t_timer[TCPT_REXMT];
	otp->t_timer[TCPT_PERSIST_EXT] = tp->t_timer[TCPT_PERSIST];
	otp->t_timer[TCPT_KEEP_EXT] = tp->t_timer[TCPT_KEEP];
	otp->t_timer[TCPT_2MSL_EXT] = tp->t_timer[TCPT_2MSL];
	otp->t_state = tp->t_state;
	otp->t_flags = tp->t_flags;
	otp->t_force = (tp->t_flagsext & TF_FORCE) ? 1 : 0;
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
	otp->cc_send = 0;
	otp->cc_recv = 0;
	otp->snd_recover = tp->snd_recover;
	otp->snd_cwnd_prev = tp->snd_cwnd_prev;
	otp->snd_ssthresh_prev = tp->snd_ssthresh_prev;
	otp->t_badrxtwin = 0;
}


static int
tcp_pcblist64 SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error, i = 0, n;
	struct inpcb **inp_list;
	inp_gen_t gencnt;
	struct xinpgen xig;

	/*
	 * The process of preparing the TCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	lck_rw_lock_shared(tcbinfo.ipi_lock);
	if (req->oldptr == USER_ADDR_NULL) {
		n = tcbinfo.ipi_count;
		req->oldidx = 2 * (sizeof(xig))
			+ (n + n/8) * sizeof(struct xtcpcb64);
		lck_rw_done(tcbinfo.ipi_lock);
		return (0);
	}

	if (req->newptr != USER_ADDR_NULL) {
		lck_rw_done(tcbinfo.ipi_lock);
		return (EPERM);
	}

	/*
	 * OK, now we're committed to doing something.
	 */
	gencnt = tcbinfo.ipi_gencnt;
	n = tcbinfo.ipi_count;

	bzero(&xig, sizeof(xig));
	xig.xig_len = sizeof(xig);
	xig.xig_count = n;
	xig.xig_gen = gencnt;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof(xig));
	if (error) {
		lck_rw_done(tcbinfo.ipi_lock);
		return (error);
	}
	/*
	 * We are done if there is no pcb
	 */
	if (n == 0) {
		lck_rw_done(tcbinfo.ipi_lock);
		return (0);
	}

	inp_list = _MALLOC(n * sizeof (*inp_list), M_TEMP, M_WAITOK);
	if (inp_list == 0) {
		lck_rw_done(tcbinfo.ipi_lock);
		return (ENOMEM);
	}

	n = get_tcp_inp_list(inp_list, n, gencnt);

	error = 0;
	for (i = 0; i < n; i++) {
		struct xtcpcb64 xt;
		struct inpcb *inp;

		inp = inp_list[i];

		if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) == WNT_STOPUSING)
			continue;
		socket_lock(inp->inp_socket, 1);
		if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) {
			socket_unlock(inp->inp_socket, 1);
			continue;
		}
		if (inp->inp_gencnt > gencnt) {
			socket_unlock(inp->inp_socket, 1);
			continue;
		}

		bzero(&xt, sizeof(xt));
		xt.xt_len = sizeof(xt);
		inpcb_to_xinpcb64(inp, &xt.xt_inpcb);
		xt.xt_inpcb.inp_ppcb =
		    (uint64_t)VM_KERNEL_ADDRPERM(inp->inp_ppcb);
		if (inp->inp_ppcb != NULL)
			tcpcb_to_xtcpcb64((struct tcpcb *)inp->inp_ppcb,
			    &xt);
		if (inp->inp_socket)
			sotoxsocket64(inp->inp_socket,
			    &xt.xt_inpcb.xi_socket);

		socket_unlock(inp->inp_socket, 1);

		error = SYSCTL_OUT(req, &xt, sizeof(xt));
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
			xig.xig_len = sizeof(xig);
			xig.xig_gen = tcbinfo.ipi_gencnt;
			xig.xig_sogen = so_gencnt;
			xig.xig_count = tcbinfo.ipi_count;
			error = SYSCTL_OUT(req, &xig, sizeof(xig));
	}
	FREE(inp_list, M_TEMP);
	lck_rw_done(tcbinfo.ipi_lock);
	return (error);
}

SYSCTL_PROC(_net_inet_tcp, OID_AUTO, pcblist64,
	    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
	    tcp_pcblist64, "S,xtcpcb64", "List of active TCP connections");

#endif /* !CONFIG_EMBEDDED */

static int
tcp_pcblist_n SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int error = 0;

	error = get_pcblist_n(IPPROTO_TCP, req, &tcbinfo);

	return (error);
}


SYSCTL_PROC(_net_inet_tcp, OID_AUTO, pcblist_n,
	    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
	    tcp_pcblist_n, "S,xtcpcb_n", "List of active TCP connections");


__private_extern__ void
tcp_get_ports_used(uint32_t ifindex, int protocol, uint32_t flags,
    bitstr_t *bitfield)
{
		inpcb_get_ports_used(ifindex, protocol, flags, bitfield,
		    &tcbinfo);
}

__private_extern__ uint32_t
tcp_count_opportunistic(unsigned int ifindex, u_int32_t flags)
{
	return (inpcb_count_opportunistic(ifindex, &tcbinfo, flags));
}

__private_extern__ uint32_t
tcp_find_anypcb_byaddr(struct ifaddr *ifa)
{
		return (inpcb_find_anypcb_byaddr(ifa, &tcbinfo));
}

static void
tcp_handle_msgsize(struct ip *ip, struct inpcb *inp)
{
	struct rtentry *rt = NULL;
	u_short ifscope = IFSCOPE_NONE;
	int mtu;
	struct sockaddr_in icmpsrc = {
	    sizeof (struct sockaddr_in),
	    AF_INET, 0, { 0 },
	    { 0, 0, 0, 0, 0, 0, 0, 0 } };
	struct icmp *icp = NULL;

	icp = (struct icmp *)(void *)
	    ((caddr_t)ip - offsetof(struct icmp, icmp_ip));

	icmpsrc.sin_addr = icp->icmp_ip.ip_dst;

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
	if (ROUTE_UNUSABLE(&(inp->inp_route)) == false)
		rt = inp->inp_route.ro_rt;

	/*
	 * icmp6_mtudisc_update scopes the routing lookup
	 * to the incoming interface (delivered from mbuf
	 * packet header.
	 * That is mostly ok but for asymmetric networks
	 * that may be an issue.
	 * Frag needed OR Packet too big really communicates
	 * MTU for the out data path.
	 * Take the interface scope from cached route or
	 * the last outgoing interface from inp
	 */
	if (rt != NULL)
		ifscope = (rt->rt_ifp != NULL) ?
		    rt->rt_ifp->if_index : IFSCOPE_NONE;
	else
		ifscope = (inp->inp_last_outifp != NULL) ?
		    inp->inp_last_outifp->if_index : IFSCOPE_NONE;

	if ((rt == NULL) ||
	    !(rt->rt_flags & RTF_HOST) ||
	    (rt->rt_flags & (RTF_CLONING | RTF_PRCLONING))) {
		rt = rtalloc1_scoped((struct sockaddr *)&icmpsrc, 0,
		    RTF_CLONING | RTF_PRCLONING, ifscope);
	} else if (rt) {
		RT_LOCK(rt);
		rtref(rt);
		RT_UNLOCK(rt);
	}

	if (rt != NULL) {
		RT_LOCK(rt);
		if ((rt->rt_flags & RTF_HOST) &&
		    !(rt->rt_rmx.rmx_locks & RTV_MTU)) {
			mtu = ntohs(icp->icmp_nextmtu);
			/*
			 * XXX Stock BSD has changed the following
			 * to compare with icp->icmp_ip.ip_len
			 * to converge faster when sent packet
			 * < route's MTU. We may want to adopt
			 * that change.
			 */
			if (mtu == 0)
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
				rt->rt_rmx.rmx_locks |= RTV_MTU;
			} else if (rt->rt_rmx.rmx_mtu > mtu) {
				rt->rt_rmx.rmx_mtu = mtu;
			}
		}
		RT_UNLOCK(rt);
		rtfree(rt);
	}
}

void
tcp_ctlinput(int cmd, struct sockaddr *sa, void *vip, __unused struct ifnet *ifp)
{
	tcp_seq icmp_tcp_seq;
	struct ip *ip = vip;
	struct in_addr faddr;
	struct inpcb *inp;
	struct tcpcb *tp;
	struct tcphdr *th;
	struct icmp *icp;
	void (*notify)(struct inpcb *, int) = tcp_notify;

	faddr = ((struct sockaddr_in *)(void *)sa)->sin_addr;
	if (sa->sa_family != AF_INET || faddr.s_addr == INADDR_ANY)
		return;

	if ((unsigned)cmd >= PRC_NCMDS)
		return;

	/* Source quench is deprecated */
	if (cmd == PRC_QUENCH)
                return;

	if (cmd == PRC_MSGSIZE)
		notify = tcp_mtudisc;
	else if (icmp_may_rst && (cmd == PRC_UNREACH_ADMIN_PROHIB ||
		cmd == PRC_UNREACH_PORT || cmd == PRC_UNREACH_PROTOCOL ||
		cmd == PRC_TIMXCEED_INTRANS) && ip)
		notify = tcp_drop_syn_sent;
	/*
	 * Hostdead is ugly because it goes linearly through all PCBs.
	 * XXX: We never get this from ICMP, otherwise it makes an
	 * excellent DoS attack on machines with many connections.
	 */
        else if (cmd == PRC_HOSTDEAD)
		ip = NULL;
        else if (inetctlerrmap[cmd] == 0 && !PRC_IS_REDIRECT(cmd))
		return;


	if (ip == NULL) {
		in_pcbnotifyall(&tcbinfo, faddr, inetctlerrmap[cmd], notify);
		return;
	}

	icp = (struct icmp *)(void *)
	    ((caddr_t)ip - offsetof(struct icmp, icmp_ip));
	th = (struct tcphdr *)(void *)((caddr_t)ip + (IP_VHL_HL(ip->ip_vhl) << 2));
	icmp_tcp_seq = ntohl(th->th_seq);

	inp = in_pcblookup_hash(&tcbinfo, faddr, th->th_dport,
	    ip->ip_src, th->th_sport, 0, NULL);

	if (inp == NULL ||
	    inp->inp_socket == NULL) {
		return;
	}

	socket_lock(inp->inp_socket, 1);
	if (in_pcb_checkstate(inp, WNT_RELEASE, 1) ==
	    WNT_STOPUSING) {
		socket_unlock(inp->inp_socket, 1);
		return;
	}

	if (PRC_IS_REDIRECT(cmd)) {
		/* signal EHOSTDOWN, as it flushes the cached route */
		(*notify)(inp, EHOSTDOWN);
	} else {
		tp = intotcpcb(inp);
		if (SEQ_GEQ(icmp_tcp_seq, tp->snd_una) &&
		    SEQ_LT(icmp_tcp_seq, tp->snd_max)) {
			if (cmd == PRC_MSGSIZE)
				tcp_handle_msgsize(ip, inp);

			(*notify)(inp, inetctlerrmap[cmd]);
		}
	}
	socket_unlock(inp->inp_socket, 1);
}

#if INET6
void
tcp6_ctlinput(int cmd, struct sockaddr *sa, void *d, __unused struct ifnet *ifp)
{
	tcp_seq icmp_tcp_seq;
	struct in6_addr *dst;
	struct tcphdr *th;
	void (*notify)(struct inpcb *, int) = tcp_notify;
	struct ip6_hdr *ip6;
	struct mbuf *m;
	struct inpcb *inp;
	struct tcpcb *tp;
	struct icmp6_hdr *icmp6;
	struct ip6ctlparam *ip6cp = NULL;
	const struct sockaddr_in6 *sa6_src = NULL;
	unsigned int mtu;
	unsigned int off;

	if (sa->sa_family != AF_INET6 ||
	    sa->sa_len != sizeof(struct sockaddr_in6))
		return;

	/* Source quench is deprecated */
	if (cmd == PRC_QUENCH)
		return;

	if ((unsigned)cmd >= PRC_NCMDS)
		return;

	/* if the parameter is from icmp6, decode it. */
	if (d != NULL) {
		ip6cp = (struct ip6ctlparam *)d;
		icmp6 = ip6cp->ip6c_icmp6;
		m = ip6cp->ip6c_m;
		ip6 = ip6cp->ip6c_ip6;
		off = ip6cp->ip6c_off;
		sa6_src = ip6cp->ip6c_src;
		dst = ip6cp->ip6c_finaldst;
	} else {
		m = NULL;
		ip6 = NULL;
		off = 0;	/* fool gcc */
		sa6_src = &sa6_any;
		dst = NULL;
	}

	if (cmd == PRC_MSGSIZE)
		notify = tcp_mtudisc;
	else if (icmp_may_rst && (cmd == PRC_UNREACH_ADMIN_PROHIB ||
	    cmd == PRC_UNREACH_PORT || cmd == PRC_TIMXCEED_INTRANS) &&
	    ip6 != NULL)
		notify = tcp_drop_syn_sent;
	/*
	 * Hostdead is ugly because it goes linearly through all PCBs.
	 * XXX: We never get this from ICMP, otherwise it makes an
	 * excellent DoS attack on machines with many connections.
	 */
	else if (cmd == PRC_HOSTDEAD)
		ip6 = NULL;
	else if (inet6ctlerrmap[cmd] == 0 && !PRC_IS_REDIRECT(cmd))
		return;


	if (ip6 == NULL) {
		in6_pcbnotify(&tcbinfo, sa, 0, (struct sockaddr *)(size_t)sa6_src,
		    0, cmd, NULL, notify);
		return;
	}

	if (m == NULL ||
	    (m->m_pkthdr.len < (int32_t) (off + offsetof(struct tcphdr, th_seq))))
		return;

	th = (struct tcphdr *)(void *)mtodo(m, off);
	icmp_tcp_seq = ntohl(th->th_seq);

	if (cmd == PRC_MSGSIZE) {
		mtu = ntohl(icmp6->icmp6_mtu);
		/*
		 * If no alternative MTU was proposed, or the proposed
		 * MTU was too small, set to the min.
		 */
		if (mtu < IPV6_MMTU)
			mtu = IPV6_MMTU - 8;
	}

	inp = in6_pcblookup_hash(&tcbinfo, &ip6->ip6_dst, th->th_dport,
	    &ip6->ip6_src, th->th_sport, 0, NULL);

	if (inp == NULL ||
	    inp->inp_socket == NULL) {
		return;
	}

	socket_lock(inp->inp_socket, 1);
	if (in_pcb_checkstate(inp, WNT_RELEASE, 1) ==
	    WNT_STOPUSING) {
		socket_unlock(inp->inp_socket, 1);
		return;
	}

	if (PRC_IS_REDIRECT(cmd)) {
		/* signal EHOSTDOWN, as it flushes the cached route */
		(*notify)(inp, EHOSTDOWN);
	} else {
		tp = intotcpcb(inp);
		if (SEQ_GEQ(icmp_tcp_seq, tp->snd_una) &&
		    SEQ_LT(icmp_tcp_seq, tp->snd_max)) {
			if (cmd == PRC_MSGSIZE) {
				/*
				 * Only process the offered MTU if it
				 * is smaller than the current one.
				 */
				if (mtu < tp->t_maxseg +
				    (sizeof (*th) + sizeof (*ip6)))
					(*notify)(inp, inetctlerrmap[cmd]);
			} else
				(*notify)(inp, inetctlerrmap[cmd]);
		}
	}
	socket_unlock(inp->inp_socket, 1);
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

#define	ISN_BYTES_PER_SECOND 1048576

tcp_seq
tcp_new_isn(struct tcpcb *tp)
{
	u_int32_t md5_buffer[4];
	tcp_seq new_isn;
	struct timeval timenow;
	u_char isn_secret[32];
	int isn_last_reseed = 0;
	MD5_CTX isn_ctx;

	/* Use arc4random for SYN-ACKs when not in exact RFC1948 mode. */
	if (((tp->t_state == TCPS_LISTEN) || (tp->t_state == TCPS_TIME_WAIT)) &&
	    tcp_strict_rfc1948 == 0)
#ifdef __APPLE__
		return (RandomULong());
#else
		return (arc4random());
#endif
	getmicrotime(&timenow);

	/* Seed if this is the first use, reseed if requested. */
	if ((isn_last_reseed == 0) ||
	    ((tcp_strict_rfc1948 == 0) && (tcp_isn_reseed_interval > 0) &&
	    (((u_int)isn_last_reseed + (u_int)tcp_isn_reseed_interval*hz)
		< (u_int)timenow.tv_sec))) {
#ifdef __APPLE__
		read_frandom(&isn_secret, sizeof(isn_secret));
#else
		read_random_unlimited(&isn_secret, sizeof(isn_secret));
#endif
		isn_last_reseed = timenow.tv_sec;
	}

	/* Compute the md5 hash and return the ISN. */
	MD5Init(&isn_ctx);
	MD5Update(&isn_ctx, (u_char *) &tp->t_inpcb->inp_fport,
	    sizeof(u_short));
	MD5Update(&isn_ctx, (u_char *) &tp->t_inpcb->inp_lport,
	    sizeof(u_short));
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
	return (new_isn);
}


/*
 * When a specific ICMP unreachable message is received and the
 * connection state is SYN-SENT, drop the connection.  This behavior
 * is controlled by the icmp_may_rst sysctl.
 */
void
tcp_drop_syn_sent(struct inpcb *inp, int errno)
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
	u_int32_t mtu;
	u_int32_t protoHdrOverhead = sizeof (struct tcpiphdr);
#if INET6
	int isipv6 = (tp->t_inpcb->inp_vflag & INP_IPV6) != 0;

	if (isipv6)
		protoHdrOverhead = sizeof(struct ip6_hdr) +
		    sizeof(struct tcphdr);
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
		mtu = rt->rt_rmx.rmx_mtu;

		/* Route locked during lookup above */
		RT_UNLOCK(rt);

#if NECP
		// Adjust MTU if necessary.
		mtu = necp_socket_get_effective_mtu(inp, mtu);
#endif /* NECP */
		mss = mtu - protoHdrOverhead;

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

#if MPTCP
		mss -= mptcp_adj_mss(tp, TRUE);
#endif
		if (so->so_snd.sb_hiwat < mss)
			mss = so->so_snd.sb_hiwat;

		tp->t_maxseg = mss;

		/*
		 * Reset the slow-start flight size as it may depends on the
		 * new MSS
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
tcp_rtlookup(struct inpcb *inp, unsigned int input_ifscope)
{
	struct route *ro;
	struct rtentry *rt;
	struct tcpcb *tp;

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);

	ro = &inp->inp_route;
	if ((rt = ro->ro_rt) != NULL)
		RT_LOCK(rt);

	if (ROUTE_UNUSABLE(ro)) {
		if (rt != NULL) {
			RT_UNLOCK(rt);
			rt = NULL;
		}
		ROUTE_RELEASE(ro);
		/* No route yet, so try to acquire one */
		if (inp->inp_faddr.s_addr != INADDR_ANY) {
			unsigned int ifscope;

			ro->ro_dst.sa_family = AF_INET;
			ro->ro_dst.sa_len = sizeof(struct sockaddr_in);
			((struct sockaddr_in *)(void *)&ro->ro_dst)->sin_addr =
				inp->inp_faddr;

			/*
			 * If the socket was bound to an interface, then
			 * the bound-to-interface takes precedence over
			 * the inbound interface passed in by the caller
			 * (if we get here as part of the output path then
			 * input_ifscope is IFSCOPE_NONE).
			 */
			ifscope = (inp->inp_flags & INP_BOUND_IF) ?
			    inp->inp_boundifp->if_index : input_ifscope;

			rtalloc_scoped(ro, ifscope);
			if ((rt = ro->ro_rt) != NULL)
				RT_LOCK(rt);
		}
	}
	if (rt != NULL)
		RT_LOCK_ASSERT_HELD(rt);

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

	if (rt != NULL && rt->rt_ifp != NULL) {
		somultipages(inp->inp_socket,
		    (rt->rt_ifp->if_hwassist & IFNET_MULTIPAGES));
		tcp_set_tso(tp, rt->rt_ifp);
		soif2kcl(inp->inp_socket,
		    (rt->rt_ifp->if_eflags & IFEF_2KCL));
		tcp_set_ecn(tp, rt->rt_ifp);
		if (inp->inp_last_outifp == NULL) {
			inp->inp_last_outifp = rt->rt_ifp;

		}
	}

	/* Note if the peer is local */
	if (rt != NULL && !(rt->rt_ifp->if_flags & IFF_POINTOPOINT) &&
		(rt->rt_gateway->sa_family == AF_LINK ||
		rt->rt_ifp->if_flags & IFF_LOOPBACK ||
		in_localaddr(inp->inp_faddr))) {
		tp->t_flags |= TF_LOCAL;
	}

	/*
	 * Caller needs to call RT_UNLOCK(rt).
	 */
	return (rt);
}

#if INET6
struct rtentry *
tcp_rtlookup6(struct inpcb *inp, unsigned int input_ifscope)
{
	struct route_in6 *ro6;
	struct rtentry *rt;
	struct tcpcb *tp;

	LCK_MTX_ASSERT(rnh_lock, LCK_MTX_ASSERT_NOTOWNED);

	ro6 = &inp->in6p_route;
	if ((rt = ro6->ro_rt) != NULL)
		RT_LOCK(rt);

	if (ROUTE_UNUSABLE(ro6)) {
		if (rt != NULL) {
			RT_UNLOCK(rt);
			rt = NULL;
		}
		ROUTE_RELEASE(ro6);
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
			    inp->inp_boundifp->if_index : input_ifscope;

			rtalloc_scoped((struct route *)ro6, ifscope);
			if ((rt = ro6->ro_rt) != NULL)
				RT_LOCK(rt);
		}
	}
	if (rt != NULL)
		RT_LOCK_ASSERT_HELD(rt);

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

	if (rt != NULL && rt->rt_ifp != NULL) {
		somultipages(inp->inp_socket,
		    (rt->rt_ifp->if_hwassist & IFNET_MULTIPAGES));
		tcp_set_tso(tp, rt->rt_ifp);
		soif2kcl(inp->inp_socket,
		    (rt->rt_ifp->if_eflags & IFEF_2KCL));
		tcp_set_ecn(tp, rt->rt_ifp);
		if (inp->inp_last_outifp == NULL) {
			inp->inp_last_outifp = rt->rt_ifp;
		}
	}

	/* Note if the peer is local */
	if (rt != NULL && !(rt->rt_ifp->if_flags & IFF_POINTOPOINT) &&
		(IN6_IS_ADDR_LOOPBACK(&inp->in6p_faddr) ||
		IN6_IS_ADDR_LINKLOCAL(&inp->in6p_faddr) ||
		rt->rt_gateway->sa_family == AF_LINK ||
		in6_localaddr(&inp->in6p_faddr))) {
		tp->t_flags |= TF_LOCAL;
	}

	/*
	 * Caller needs to call RT_UNLOCK(rt).
	 */
	return (rt);
}
#endif /* INET6 */

#if IPSEC
/* compute ESP/AH header size for TCP, including outer IP header. */
size_t
ipsec_hdrsiz_tcp(struct tcpcb *tp)
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
		return (0);
	MGETHDR(m, M_DONTWAIT, MT_DATA);	/* MAC-OK */
	if (!m)
		return (0);

#if INET6
	if ((inp->inp_vflag & INP_IPV6) != 0) {
		ip6 = mtod(m, struct ip6_hdr *);
		th = (struct tcphdr *)(void *)(ip6 + 1);
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
	return (hdrsiz);
}
#endif /* IPSEC */

/*
 * Return a pointer to the cached information about the remote host.
 * The cached information is stored in the protocol specific part of
 * the route metrics.
 */
struct rmxp_tao *
tcp_gettaocache(struct inpcb *inp)
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
		return (NULL);
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
tcp_cleartaocache(void)
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

retry:
	if (so->so_pcb != NULL) {
		if (so->so_flags & SOF_MP_SUBFLOW) {
			struct mptcb *mp_tp = tptomptp(sototcpcb(so));
			VERIFY(mp_tp);

			mpte_lock_assert_notheld(mp_tp->mpt_mpte);

			mpte_lock(mp_tp->mpt_mpte);

			/*
			 * Check if we became non-MPTCP while waiting for the lock.
			 * If yes, we have to retry to grab the right lock.
			 */
			if (!(so->so_flags & SOF_MP_SUBFLOW)) {
				mpte_unlock(mp_tp->mpt_mpte);
				goto retry;
			}
		} else {
			lck_mtx_lock(&((struct inpcb *)so->so_pcb)->inpcb_mtx);

			if (so->so_flags & SOF_MP_SUBFLOW) {
				/*
				 * While waiting for the lock, we might have
				 * become MPTCP-enabled (see mptcp_subflow_socreate).
				 */
				lck_mtx_unlock(&((struct inpcb *)so->so_pcb)->inpcb_mtx);
				goto retry;
			}
		}
	} else  {
		panic("tcp_lock: so=%p NO PCB! lr=%p lrh= %s\n",
		    so, lr_saved, solockhistory_nr(so));
		/* NOTREACHED */
	}

	if (so->so_usecount < 0) {
		panic("tcp_lock: so=%p so_pcb=%p lr=%p ref=%x lrh= %s\n",
		    so, so->so_pcb, lr_saved, so->so_usecount,
		    solockhistory_nr(so));
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
	printf("tcp_unlock: so=0x%llx sopcb=0x%llx lock=0x%llx ref=%x "
	    "lr=0x%llx\n", (uint64_t)VM_KERNEL_ADDRPERM(so),
	    (uint64_t)VM_KERNEL_ADDRPERM(so->so_pcb),
	    (uint64_t)VM_KERNEL_ADDRPERM(&(sotoinpcb(so)->inpcb_mtx)),
	    so->so_usecount, (uint64_t)VM_KERNEL_ADDRPERM(lr_saved));
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
		so->unlock_lr[so->next_unlock_lr] = lr_saved;
		so->next_unlock_lr = (so->next_unlock_lr+1) % SO_LCKDBG_MAX;

		if (so->so_flags & SOF_MP_SUBFLOW) {
			struct mptcb *mp_tp = tptomptp(sototcpcb(so));

			VERIFY(mp_tp);
			mpte_lock_assert_held(mp_tp->mpt_mpte);

			mpte_unlock(mp_tp->mpt_mpte);
		} else {
			LCK_MTX_ASSERT(&((struct inpcb *)so->so_pcb)->inpcb_mtx,
			    LCK_MTX_ASSERT_OWNED);
			lck_mtx_unlock(&((struct inpcb *)so->so_pcb)->inpcb_mtx);
		}
	}
	return (0);
}

lck_mtx_t *
tcp_getlock(struct socket *so, int flags)
{
	struct inpcb *inp = sotoinpcb(so);

	if (so->so_pcb)  {
		if (so->so_usecount < 0)
			panic("tcp_getlock: so=%p usecount=%x lrh= %s\n",
			    so, so->so_usecount, solockhistory_nr(so));

		if (so->so_flags & SOF_MP_SUBFLOW) {
			struct mptcb *mp_tp = tptomptp(sototcpcb(so));

			return (mpte_getlock(mp_tp->mpt_mpte, flags));
		} else {
			return (&inp->inpcb_mtx);
		}
	} else {
		panic("tcp_getlock: so=%p NULL so_pcb %s\n",
		    so, solockhistory_nr(so));
		return (so->so_proto->pr_domain->dom_mtx);
	}
}

/*
 * Determine if we can grow the recieve socket buffer to avoid sending
 * a zero window update to the peer. We allow even socket buffers that
 * have fixed size (set by the application) to grow if the resource
 * constraints are met. They will also be trimmed after the application
 * reads data.
 */
static void
tcp_sbrcv_grow_rwin(struct tcpcb *tp, struct sockbuf *sb)
{
	u_int32_t rcvbufinc = tp->t_maxseg << 4;
	u_int32_t rcvbuf = sb->sb_hiwat;
	struct socket *so = tp->t_inpcb->inp_socket;

	if (tcp_recv_bg == 1 || IS_TCP_RECV_BG(so))
		return;
	/*
	 * If message delivery is enabled, do not count
	 * unordered bytes in receive buffer towards hiwat
	 */
	if (so->so_flags & SOF_ENABLE_MSGS)
		rcvbuf = rcvbuf - so->so_msg_state->msg_uno_bytes;

	if (tcp_do_autorcvbuf == 1 &&
		tcp_cansbgrow(sb) &&
		(tp->t_flags & TF_SLOWLINK) == 0 &&
		(so->so_flags1 & SOF1_EXTEND_BK_IDLE_WANTED) == 0 &&
		(rcvbuf - sb->sb_cc) < rcvbufinc &&
		rcvbuf < tcp_autorcvbuf_max &&
		(sb->sb_idealsize > 0 &&
		sb->sb_hiwat <= (sb->sb_idealsize + rcvbufinc))) {
		sbreserve(sb,
		    min((sb->sb_hiwat + rcvbufinc), tcp_autorcvbuf_max));
	}
}

int32_t
tcp_sbspace(struct tcpcb *tp)
{
	struct socket *so = tp->t_inpcb->inp_socket;
	struct sockbuf *sb = &so->so_rcv;
	u_int32_t rcvbuf;
	int32_t space;
	int32_t pending = 0;

	tcp_sbrcv_grow_rwin(tp, sb);

	/* hiwat might have changed */
	rcvbuf = sb->sb_hiwat;

	/*
	 * If message delivery is enabled, do not count
	 * unordered bytes in receive buffer towards hiwat mark.
	 * This value is used to return correct rwnd that does
	 * not reflect the extra unordered bytes added to the
	 * receive socket buffer.
	 */
	if (so->so_flags & SOF_ENABLE_MSGS)
		rcvbuf = rcvbuf - so->so_msg_state->msg_uno_bytes;

	space =  ((int32_t) imin((rcvbuf - sb->sb_cc),
		(sb->sb_mbmax - sb->sb_mbcnt)));
	if (space < 0)
		space = 0;

#if CONTENT_FILTER
	/* Compensate for data being processed by content filters */
	pending = cfil_sock_data_space(sb);
#endif /* CONTENT_FILTER */
	if (pending > space)
		space = 0;
	else
		space -= pending;

	/*
	 * Avoid increasing window size if the current window
	 * is already very low, we could be in "persist" mode and
	 * we could break some apps (see rdar://5409343)
	 */

	if (space < tp->t_maxseg)
		return (space);

	/* Clip window size for slower link */

	if (((tp->t_flags & TF_SLOWLINK) != 0) && slowlink_wsize > 0)
		return (imin(space, slowlink_wsize));

	return (space);
}
/*
 * Checks TCP Segment Offloading capability for a given connection
 * and interface pair.
 */
void
tcp_set_tso(struct tcpcb *tp, struct ifnet *ifp)
{
#if INET6
	struct inpcb *inp;
	int isipv6;
#endif /* INET6 */
#if MPTCP
	/*
	 * We can't use TSO if this tcpcb belongs to an MPTCP session.
	 */
	if (tp->t_mpflags & TMPF_MPTCP_TRUE) {
		tp->t_flags &= ~TF_TSO;
		return;
	}
#endif
#if INET6
	inp = tp->t_inpcb;
	isipv6 = (inp->inp_vflag & INP_IPV6) != 0;

	if (isipv6) {
		if (ifp && (ifp->if_hwassist & IFNET_TSO_IPV6)) {
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
		if (ifp && (ifp->if_hwassist & IFNET_TSO_IPV4)) {
			tp->t_flags |= TF_TSO;
			if (ifp->if_tso_v4_mtu != 0)
				tp->tso_max_segment_size = ifp->if_tso_v4_mtu;
			else
				tp->tso_max_segment_size = TCP_MAXWIN;
		} else
				tp->t_flags &= ~TF_TSO;
	}
}

#define	TIMEVAL_TO_TCPHZ(_tv_) ((_tv_).tv_sec * TCP_RETRANSHZ + \
	(_tv_).tv_usec / TCP_RETRANSHZ_TO_USEC)

/*
 * Function to calculate the tcp clock. The tcp clock will get updated
 * at the boundaries of the tcp layer. This is done at 3 places:
 * 1. Right before processing an input tcp packet
 * 2. Whenever a connection wants to access the network using tcp_usrreqs
 * 3. When a tcp timer fires or before tcp slow timeout
 *
 */

void
calculate_tcp_clock(void)
{
	struct timeval tv = tcp_uptime;
	struct timeval interval = {0, TCP_RETRANSHZ_TO_USEC};
	struct timeval now, hold_now;
	uint32_t incr = 0;

	microuptime(&now);

	/*
	 * Update coarse-grained networking timestamp (in sec.); the idea
	 * is to update the counter returnable via net_uptime() when
	 * we read time.
	 */
	net_update_uptime_with_time(&now);

	timevaladd(&tv, &interval);
	if (timevalcmp(&now, &tv, >)) {
		/* time to update the clock */
		lck_spin_lock(tcp_uptime_lock);
		if (timevalcmp(&tcp_uptime, &now, >=)) {
			/* clock got updated while waiting for the lock */
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
}

/*
 * Compute receive window scaling that we are going to request
 * for this connection based on  sb_hiwat. Try to leave some
 * room to potentially increase the window size upto a maximum
 * defined by the constant tcp_autorcvbuf_max.
 */
void
tcp_set_max_rwinscale(struct tcpcb *tp, struct socket *so,
    u_int32_t rcvbuf_max)
{
	u_int32_t maxsockbufsize;
	if (!tcp_do_rfc1323) {
		tp->request_r_scale = 0;
		return;
	}

	tp->request_r_scale = max(tcp_win_scale, tp->request_r_scale);
	maxsockbufsize = ((so->so_rcv.sb_flags & SB_USRSIZE) != 0) ?
		so->so_rcv.sb_hiwat : rcvbuf_max;

	while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
		(TCP_MAXWIN << tp->request_r_scale) < maxsockbufsize)
		tp->request_r_scale++;
	tp->request_r_scale = min(tp->request_r_scale, TCP_MAX_WINSHIFT);

}

int
tcp_notsent_lowat_check(struct socket *so) {
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = NULL;
	int notsent = 0;
	if (inp != NULL) {
		tp = intotcpcb(inp);
	}

	notsent = so->so_snd.sb_cc -
		(tp->snd_nxt - tp->snd_una);

	/*
	 * When we send a FIN or SYN, not_sent can be negative.
	 * In that case also we need to send a write event to the
	 * process if it is waiting. In the FIN case, it will
	 * get an error from send because cantsendmore will be set.
	 */
	if (notsent <= tp->t_notsent_lowat) {
		return (1);
	}

	/*
	 * When Nagle's algorithm is not disabled, it is better
	 * to wakeup the client until there is atleast one
	 * maxseg of data to write.
	 */
	if ((tp->t_flags & TF_NODELAY) == 0 &&
		notsent > 0 && notsent < tp->t_maxseg) {
		return (1);
	}
	return (0);
}

void
tcp_rxtseg_insert(struct tcpcb *tp, tcp_seq start, tcp_seq end)
{
	struct tcp_rxt_seg *rxseg = NULL, *prev = NULL, *next = NULL;
	u_int32_t rxcount = 0;

	if (SLIST_EMPTY(&tp->t_rxt_segments))
		tp->t_dsack_lastuna = tp->snd_una;
	/*
	 * First check if there is a segment already existing for this
	 * sequence space.
	 */

	SLIST_FOREACH(rxseg, &tp->t_rxt_segments, rx_link) {
		if (SEQ_GT(rxseg->rx_start, start))
			break;
		prev = rxseg;
	}
	next = rxseg;

	/* check if prev seg is for this sequence */
	if (prev != NULL && SEQ_LEQ(prev->rx_start, start) &&
	    SEQ_GEQ(prev->rx_end, end)) {
		prev->rx_count++;
		return;
	}

	/*
	 * There are a couple of possibilities at this point.
	 * 1. prev overlaps with the beginning of this sequence
	 * 2. next overlaps with the end of this sequence
	 * 3. there is no overlap.
	 */

	if (prev != NULL && SEQ_GT(prev->rx_end, start)) {
		if (prev->rx_start == start && SEQ_GT(end, prev->rx_end)) {
			start = prev->rx_end + 1;
			prev->rx_count++;
		} else {
			prev->rx_end = (start - 1);
			rxcount = prev->rx_count;
		}
	}

	if (next != NULL && SEQ_LT(next->rx_start, end)) {
		if (SEQ_LEQ(next->rx_end, end)) {
			end = next->rx_start - 1;
			next->rx_count++;
		} else {
			next->rx_start = end + 1;
			rxcount = next->rx_count;
		}
	}
	if (!SEQ_LT(start, end))
		return;

	rxseg = (struct tcp_rxt_seg *) zalloc(tcp_rxt_seg_zone);
	if (rxseg == NULL) {
		return;
	}
	bzero(rxseg, sizeof(*rxseg));
	rxseg->rx_start = start;
	rxseg->rx_end = end;
	rxseg->rx_count = rxcount + 1;

	if (prev != NULL) {
		SLIST_INSERT_AFTER(prev, rxseg, rx_link);
	} else {
		SLIST_INSERT_HEAD(&tp->t_rxt_segments, rxseg, rx_link);
	}
}

struct tcp_rxt_seg *
tcp_rxtseg_find(struct tcpcb *tp, tcp_seq start, tcp_seq end)
{
	struct tcp_rxt_seg *rxseg;
	if (SLIST_EMPTY(&tp->t_rxt_segments))
		return (NULL);

	SLIST_FOREACH(rxseg, &tp->t_rxt_segments, rx_link) {
		if (SEQ_LEQ(rxseg->rx_start, start) &&
		    SEQ_GEQ(rxseg->rx_end, end))
			return (rxseg);
		if (SEQ_GT(rxseg->rx_start, start))
			break;
	}
	return (NULL);
}

void
tcp_rxtseg_clean(struct tcpcb *tp)
{
	struct tcp_rxt_seg *rxseg, *next;

	SLIST_FOREACH_SAFE(rxseg, &tp->t_rxt_segments, rx_link, next) {
		SLIST_REMOVE(&tp->t_rxt_segments, rxseg,
		    tcp_rxt_seg, rx_link);
		zfree(tcp_rxt_seg_zone, rxseg);
	}
	tp->t_dsack_lastuna = tp->snd_max;
}

boolean_t
tcp_rxtseg_detect_bad_rexmt(struct tcpcb *tp, tcp_seq th_ack)
{
	boolean_t bad_rexmt;
	struct tcp_rxt_seg *rxseg;

	if (SLIST_EMPTY(&tp->t_rxt_segments))
		return (FALSE);

	/*
	 * If all of the segments in this window are not cumulatively
	 * acknowledged, then there can still be undetected packet loss.
	 * Do not restore congestion window in that case.
	 */
	if (SEQ_LT(th_ack, tp->snd_recover))
		return (FALSE);

	bad_rexmt = TRUE;
	SLIST_FOREACH(rxseg, &tp->t_rxt_segments, rx_link) {
		if (rxseg->rx_count > 1 ||
		    !(rxseg->rx_flags & TCP_RXT_SPURIOUS)) {
			bad_rexmt = FALSE;
			break;
		}
	}
	return (bad_rexmt);
}

boolean_t
tcp_rxtseg_dsack_for_tlp(struct tcpcb *tp)
{
	boolean_t dsack_for_tlp = FALSE;
	struct tcp_rxt_seg *rxseg;
	if (SLIST_EMPTY(&tp->t_rxt_segments))
		return (FALSE);

	SLIST_FOREACH(rxseg, &tp->t_rxt_segments, rx_link) {
		if (rxseg->rx_count == 1 &&
		    SLIST_NEXT(rxseg, rx_link) == NULL &&
		    (rxseg->rx_flags & TCP_RXT_DSACK_FOR_TLP)) {
			dsack_for_tlp = TRUE;
			break;
		}
	}
	return (dsack_for_tlp);
}

u_int32_t
tcp_rxtseg_total_size(struct tcpcb *tp)
{
	struct tcp_rxt_seg *rxseg;
	u_int32_t total_size = 0;

	SLIST_FOREACH(rxseg, &tp->t_rxt_segments, rx_link) {
		total_size += (rxseg->rx_end - rxseg->rx_start) + 1;
	}
	return (total_size);
}

void
tcp_get_connectivity_status(struct tcpcb *tp,
	struct tcp_conn_status *connstatus)
{
	if (tp == NULL || connstatus == NULL)
		return;
	bzero(connstatus, sizeof(*connstatus));
	if (tp->t_rxtshift >= TCP_CONNECTIVITY_PROBES_MAX) {
		if (TCPS_HAVEESTABLISHED(tp->t_state)) {
			connstatus->write_probe_failed = 1;
		} else {
			connstatus->conn_probe_failed = 1;
		}
	}
	if (tp->t_rtimo_probes >= TCP_CONNECTIVITY_PROBES_MAX)
		connstatus->read_probe_failed = 1;
	if (tp->t_inpcb != NULL && tp->t_inpcb->inp_last_outifp != NULL &&
	    (tp->t_inpcb->inp_last_outifp->if_eflags & IFEF_PROBE_CONNECTIVITY))
		connstatus->probe_activated = 1;
}

boolean_t
tfo_enabled(const struct tcpcb *tp)
{
	return ((tp->t_flagsext & TF_FASTOPEN)? TRUE : FALSE);
}

void
tcp_disable_tfo(struct tcpcb *tp)
{
	tp->t_flagsext &= ~TF_FASTOPEN;
}

static struct mbuf *
tcp_make_keepalive_frame(struct tcpcb *tp, struct ifnet *ifp,
    boolean_t is_probe)
{
	struct inpcb *inp = tp->t_inpcb;
	struct tcphdr *th;
	u_int8_t *data;
	int win = 0;
	struct mbuf *m;

	/*
	 * The code assumes the IP + TCP headers fit in an mbuf packet header
	 */
	_CASSERT(sizeof(struct ip) + sizeof(struct tcphdr) <= _MHLEN);
	_CASSERT(sizeof(struct ip6_hdr) + sizeof(struct tcphdr) <= _MHLEN);

	MGETHDR(m, M_WAIT, MT_HEADER);
	if (m == NULL) {
		return (NULL);
	}
	m->m_pkthdr.pkt_proto = IPPROTO_TCP;

	data = mbuf_datastart(m);

	if (inp->inp_vflag & INP_IPV4) {
		bzero(data, sizeof(struct ip) + sizeof(struct tcphdr));
		th = (struct tcphdr *)(void *) (data + sizeof(struct ip));
		m->m_len = sizeof(struct ip) + sizeof(struct tcphdr);
		m->m_pkthdr.len = m->m_len;
	} else {
		VERIFY(inp->inp_vflag & INP_IPV6);

		bzero(data, sizeof(struct ip6_hdr)
		    + sizeof(struct tcphdr));
		th = (struct tcphdr *)(void *)(data + sizeof(struct ip6_hdr));
		m->m_len = sizeof(struct ip6_hdr) +
		    sizeof(struct tcphdr);
		m->m_pkthdr.len = m->m_len;
	}

	tcp_fillheaders(tp, data, th);

	if (inp->inp_vflag & INP_IPV4) {
		struct ip *ip;

		ip = (__typeof__(ip))(void *)data;

		ip->ip_id = rfc6864 ? 0 : ip_randomid();
		ip->ip_off = htons(IP_DF);
		ip->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
		ip->ip_ttl = inp->inp_ip_ttl;
		ip->ip_tos |= (inp->inp_ip_tos & ~IPTOS_ECN_MASK);
		ip->ip_sum = in_cksum_hdr(ip);
	} else {
		struct ip6_hdr *ip6;

		ip6 = (__typeof__(ip6))(void *)data;

		ip6->ip6_plen = htons(sizeof(struct tcphdr));
		ip6->ip6_hlim = in6_selecthlim(inp, ifp);
		ip6->ip6_flow = ip6->ip6_flow & ~IPV6_FLOW_ECN_MASK;

		if (IN6_IS_SCOPE_EMBED(&ip6->ip6_src))
			ip6->ip6_src.s6_addr16[1] = 0;
		if (IN6_IS_SCOPE_EMBED(&ip6->ip6_dst))
			ip6->ip6_dst.s6_addr16[1] = 0;
	}
	th->th_flags = TH_ACK;

	win = tcp_sbspace(tp);
	if (win > ((int32_t)TCP_MAXWIN << tp->rcv_scale))
	    win = (int32_t)TCP_MAXWIN << tp->rcv_scale;
	th->th_win = htons((u_short) (win >> tp->rcv_scale));

	if (is_probe) {
		th->th_seq = htonl(tp->snd_una - 1);
	} else {
		th->th_seq = htonl(tp->snd_una);
	}
	th->th_ack = htonl(tp->rcv_nxt);

	/* Force recompute TCP checksum to be the final value */
	th->th_sum = 0;
	if (inp->inp_vflag & INP_IPV4) {
		th->th_sum = inet_cksum(m, IPPROTO_TCP,
		    sizeof(struct ip), sizeof(struct tcphdr));
	} else {
		th->th_sum = inet6_cksum(m, IPPROTO_TCP,
		    sizeof(struct ip6_hdr), sizeof(struct tcphdr));
	}

	return (m);
}

void
tcp_fill_keepalive_offload_frames(ifnet_t ifp,
    struct ifnet_keepalive_offload_frame *frames_array,
    u_int32_t frames_array_count, size_t frame_data_offset,
    u_int32_t *used_frames_count)
{
	struct inpcb *inp;
	inp_gen_t gencnt;
	u_int32_t frame_index = *used_frames_count;

	if (ifp == NULL || frames_array == NULL ||
	    frames_array_count == 0 ||
	    frame_index >= frames_array_count ||
	    frame_data_offset >= IFNET_KEEPALIVE_OFFLOAD_FRAME_DATA_SIZE)
		return;

	/*
	 * This function is called outside the regular TCP processing
	 * so we need to update the TCP clock.
	 */
	calculate_tcp_clock();

	lck_rw_lock_shared(tcbinfo.ipi_lock);
	gencnt = tcbinfo.ipi_gencnt;
	LIST_FOREACH(inp, tcbinfo.ipi_listhead, inp_list) {
		struct socket *so;
		struct ifnet_keepalive_offload_frame *frame;
		struct mbuf *m = NULL;
		struct tcpcb *tp = intotcpcb(inp);

		if (frame_index >= frames_array_count)
			break;

		if (inp->inp_gencnt > gencnt ||
		    inp->inp_state == INPCB_STATE_DEAD)
			continue;

		if ((so = inp->inp_socket) == NULL ||
		    (so->so_state & SS_DEFUNCT))
			continue;
		/*
		 * check for keepalive offload flag without socket
		 * lock to avoid a deadlock
		 */
		if (!(inp->inp_flags2 & INP2_KEEPALIVE_OFFLOAD)) {
			continue;
		}

		if (!(inp->inp_vflag & (INP_IPV4 | INP_IPV6))) {
			continue;
		}
		if (inp->inp_ppcb == NULL ||
		    in_pcb_checkstate(inp, WNT_ACQUIRE, 0) == WNT_STOPUSING)
			continue;
		socket_lock(so, 1);
		/* Release the want count */
		if (inp->inp_ppcb == NULL ||
		    (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING)) {
			socket_unlock(so, 1);
			continue;
		}
		if ((inp->inp_vflag & INP_IPV4) &&
		    (inp->inp_laddr.s_addr == INADDR_ANY ||
		    inp->inp_faddr.s_addr == INADDR_ANY)) {
			socket_unlock(so, 1);
			continue;
		}
		if ((inp->inp_vflag & INP_IPV6) &&
		    (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr) ||
		    IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_faddr))) {
			socket_unlock(so, 1);
			continue;
		}
		if (inp->inp_lport == 0 || inp->inp_fport == 0) {
			socket_unlock(so, 1);
			continue;
		}
		if (inp->inp_last_outifp == NULL ||
		    inp->inp_last_outifp->if_index != ifp->if_index) {
			socket_unlock(so, 1);
			continue;
		}
		if ((inp->inp_vflag & INP_IPV4) && frame_data_offset +
		    sizeof(struct ip) + sizeof(struct tcphdr) >
		    IFNET_KEEPALIVE_OFFLOAD_FRAME_DATA_SIZE) {
			socket_unlock(so, 1);
			continue;
		} else if (!(inp->inp_vflag & INP_IPV4) && frame_data_offset +
		    sizeof(struct ip6_hdr) + sizeof(struct tcphdr) >
		    IFNET_KEEPALIVE_OFFLOAD_FRAME_DATA_SIZE) {
			socket_unlock(so, 1);
			continue;
		}
		/*
		 * There is no point in waking up the device for connections
		 * that are not established. Long lived connection are meant
		 * for processes that will sent and receive data
		 */
		if (tp->t_state != TCPS_ESTABLISHED) {
			socket_unlock(so, 1);
			continue;
		}
		/*
		 * This inp has all the information that is needed to
		 * generate an offload frame.
		 */
		frame = &frames_array[frame_index];
		frame->type = IFNET_KEEPALIVE_OFFLOAD_FRAME_TCP;
		frame->ether_type = (inp->inp_vflag & INP_IPV4) ?
		    IFNET_KEEPALIVE_OFFLOAD_FRAME_ETHERTYPE_IPV4 :
		    IFNET_KEEPALIVE_OFFLOAD_FRAME_ETHERTYPE_IPV6;
		frame->interval = tp->t_keepidle > 0 ? tp->t_keepidle :
		    tcp_keepidle;
		frame->keep_cnt = TCP_CONN_KEEPCNT(tp);
		frame->keep_retry = TCP_CONN_KEEPINTVL(tp);
		frame->local_port = ntohs(inp->inp_lport);
		frame->remote_port = ntohs(inp->inp_fport);
		frame->local_seq = tp->snd_nxt;
		frame->remote_seq = tp->rcv_nxt;
		if (inp->inp_vflag & INP_IPV4) {
			frame->length = frame_data_offset +
			    sizeof(struct ip) + sizeof(struct tcphdr);
			frame->reply_length =  frame->length;

			frame->addr_length = sizeof(struct in_addr);
			bcopy(&inp->inp_laddr, frame->local_addr,
			    sizeof(struct in_addr));
			bcopy(&inp->inp_faddr, frame->remote_addr,
			    sizeof(struct in_addr));
		} else {
			struct in6_addr *ip6;

			frame->length = frame_data_offset +
			    sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
			frame->reply_length =  frame->length;

			frame->addr_length = sizeof(struct in6_addr);
			ip6 = (struct in6_addr *)(void *)frame->local_addr;
			bcopy(&inp->in6p_laddr, ip6, sizeof(struct in6_addr));
			if (IN6_IS_SCOPE_EMBED(ip6))
				ip6->s6_addr16[1] = 0;

			ip6 = (struct in6_addr *)(void *)frame->remote_addr;
			bcopy(&inp->in6p_faddr, ip6, sizeof(struct in6_addr));
			if (IN6_IS_SCOPE_EMBED(ip6))
				ip6->s6_addr16[1] = 0;
		}

		/*
		 * First the probe
		 */
		m = tcp_make_keepalive_frame(tp, ifp, TRUE);
		if (m == NULL) {
			socket_unlock(so, 1);
			continue;
		}
		bcopy(m->m_data, frame->data + frame_data_offset,
		    m->m_len);
		m_freem(m);

		/*
		 * Now the response packet to incoming probes
		 */
		m = tcp_make_keepalive_frame(tp, ifp, FALSE);
		if (m == NULL) {
			socket_unlock(so, 1);
			continue;
		}
		bcopy(m->m_data, frame->reply_data + frame_data_offset,
		    m->m_len);
		m_freem(m);

		frame_index++;
		socket_unlock(so, 1);
	}
	lck_rw_done(tcbinfo.ipi_lock);
	*used_frames_count = frame_index;
}

errno_t
tcp_notify_ack_id_valid(struct tcpcb *tp, struct socket *so,
    u_int32_t notify_id)
{
	struct tcp_notify_ack_marker *elm;

	if (so->so_snd.sb_cc == 0)
		return (ENOBUFS);

	SLIST_FOREACH(elm, &tp->t_notify_ack, notify_next) {
		/* Duplicate id is not allowed */
		if (elm->notify_id == notify_id)
			return (EINVAL);
		/* Duplicate position is not allowed */
		if (elm->notify_snd_una == tp->snd_una + so->so_snd.sb_cc)
			return (EINVAL);
	}
	return (0);
}

errno_t
tcp_add_notify_ack_marker(struct tcpcb *tp, u_int32_t notify_id)
{
	struct tcp_notify_ack_marker *nm, *elm = NULL;
	struct socket *so = tp->t_inpcb->inp_socket;

	MALLOC(nm, struct tcp_notify_ack_marker *, sizeof (*nm),
	    M_TEMP, M_WAIT | M_ZERO);
	if (nm == NULL)
		return (ENOMEM);
	nm->notify_id = notify_id;
	nm->notify_snd_una = tp->snd_una + so->so_snd.sb_cc;

	SLIST_FOREACH(elm, &tp->t_notify_ack, notify_next) {
		if (SEQ_GT(nm->notify_snd_una, elm->notify_snd_una))
			break;
	}

	if (elm == NULL) {
		VERIFY(SLIST_EMPTY(&tp->t_notify_ack));
		SLIST_INSERT_HEAD(&tp->t_notify_ack, nm, notify_next);
	} else {
		SLIST_INSERT_AFTER(elm, nm, notify_next);
	}
	tp->t_notify_ack_count++;
	return (0);
}

void
tcp_notify_ack_free(struct tcpcb *tp)
{
	struct tcp_notify_ack_marker *elm, *next;
	if (SLIST_EMPTY(&tp->t_notify_ack))
		return;

	SLIST_FOREACH_SAFE(elm, &tp->t_notify_ack, notify_next, next) {
		SLIST_REMOVE(&tp->t_notify_ack, elm, tcp_notify_ack_marker,
		    notify_next);
		FREE(elm, M_TEMP);
	}
	SLIST_INIT(&tp->t_notify_ack);
	tp->t_notify_ack_count = 0;
}

inline void
tcp_notify_acknowledgement(struct tcpcb *tp, struct socket *so)
{
	struct tcp_notify_ack_marker *elm;

	elm = SLIST_FIRST(&tp->t_notify_ack);
	if (SEQ_GEQ(tp->snd_una, elm->notify_snd_una)) {
		soevent(so, SO_FILT_HINT_LOCKED | SO_FILT_HINT_NOTIFY_ACK);
	}
}

void
tcp_get_notify_ack_count(struct tcpcb *tp,
    struct tcp_notify_ack_complete *retid)
{
	struct tcp_notify_ack_marker *elm;
	size_t	complete = 0;

	SLIST_FOREACH(elm, &tp->t_notify_ack, notify_next) {
		if (SEQ_GEQ(tp->snd_una, elm->notify_snd_una))
			complete++;
		else
			break;
	}
	retid->notify_pending = tp->t_notify_ack_count - complete;
	retid->notify_complete_count = min(TCP_MAX_NOTIFY_ACK, complete);
}

void
tcp_get_notify_ack_ids(struct tcpcb *tp,
    struct tcp_notify_ack_complete *retid)
{
	size_t i = 0;
	struct tcp_notify_ack_marker *elm, *next;

	SLIST_FOREACH_SAFE(elm, &tp->t_notify_ack, notify_next, next) {
		if (i >= retid->notify_complete_count)
			break;
		if (SEQ_GEQ(tp->snd_una, elm->notify_snd_una)) {
			retid->notify_complete_id[i++] = elm->notify_id;
			SLIST_REMOVE(&tp->t_notify_ack, elm,
			    tcp_notify_ack_marker, notify_next);
			FREE(elm, M_TEMP);
			tp->t_notify_ack_count--;
		} else {
			break;
		}
	}
}

bool
tcp_notify_ack_active(struct socket *so)
{
	if ((SOCK_DOM(so) == PF_INET || SOCK_DOM(so) == PF_INET6) &&
	    SOCK_TYPE(so) == SOCK_STREAM) {
		struct tcpcb *tp = intotcpcb(sotoinpcb(so));

		if (!SLIST_EMPTY(&tp->t_notify_ack)) {
			struct tcp_notify_ack_marker *elm;
			elm = SLIST_FIRST(&tp->t_notify_ack);
			if (SEQ_GEQ(tp->snd_una, elm->notify_snd_una))
				return (true);
		}
	}
	return (false);
}

inline int32_t
inp_get_sndbytes_allunsent(struct socket *so, u_int32_t th_ack)
{
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = intotcpcb(inp);

	if ((so->so_snd.sb_flags & SB_SNDBYTE_CNT) &&
	    so->so_snd.sb_cc > 0) {
		int32_t unsent, sent;
		sent = tp->snd_max - th_ack;
		if (tp->t_flags & TF_SENTFIN)
			sent--;
		unsent = so->so_snd.sb_cc - sent;
		return (unsent);
	}
	return (0);
}

#define IFP_PER_FLOW_STAT(_ipv4_, _stat_) { \
	if (_ipv4_) { \
		ifp->if_ipv4_stat->_stat_++; \
	} else { \
		ifp->if_ipv6_stat->_stat_++; \
	} \
}

#define FLOW_ECN_ENABLED(_flags_) \
    ((_flags_ & (TE_ECN_ON)) == (TE_ECN_ON))

void tcp_update_stats_per_flow(struct ifnet_stats_per_flow *ifs,
    struct ifnet *ifp)
{
	if (ifp == NULL || !IF_FULLY_ATTACHED(ifp))
		return;

	ifnet_lock_shared(ifp);
	if (ifs->ecn_flags & TE_SETUPSENT) {
		if (ifs->ecn_flags & TE_CLIENT_SETUP) {
			IFP_PER_FLOW_STAT(ifs->ipv4, ecn_client_setup);
			if (FLOW_ECN_ENABLED(ifs->ecn_flags)) {
				IFP_PER_FLOW_STAT(ifs->ipv4,
				    ecn_client_success);
			} else if (ifs->ecn_flags & TE_LOST_SYN) {
				IFP_PER_FLOW_STAT(ifs->ipv4,
				    ecn_syn_lost);
			} else {
				IFP_PER_FLOW_STAT(ifs->ipv4,
				    ecn_peer_nosupport);
			}
		} else {
			IFP_PER_FLOW_STAT(ifs->ipv4, ecn_server_setup);
			if (FLOW_ECN_ENABLED(ifs->ecn_flags)) {
				IFP_PER_FLOW_STAT(ifs->ipv4,
				    ecn_server_success);
			} else if (ifs->ecn_flags & TE_LOST_SYN) {
				IFP_PER_FLOW_STAT(ifs->ipv4,
				    ecn_synack_lost);
			} else {
				IFP_PER_FLOW_STAT(ifs->ipv4,
				    ecn_peer_nosupport);
			}
		}
	} else {
		IFP_PER_FLOW_STAT(ifs->ipv4, ecn_off_conn);
	}
	if (FLOW_ECN_ENABLED(ifs->ecn_flags)) {
		if (ifs->ecn_flags & TE_RECV_ECN_CE) {
			tcpstat.tcps_ecn_conn_recv_ce++;
			IFP_PER_FLOW_STAT(ifs->ipv4, ecn_conn_recv_ce);
		}
		if (ifs->ecn_flags & TE_RECV_ECN_ECE) {
			tcpstat.tcps_ecn_conn_recv_ece++;
			IFP_PER_FLOW_STAT(ifs->ipv4, ecn_conn_recv_ece);
		}
		if (ifs->ecn_flags & (TE_RECV_ECN_CE | TE_RECV_ECN_ECE)) {
			if (ifs->txretransmitbytes > 0 ||
			    ifs->rxoutoforderbytes > 0) {
				tcpstat.tcps_ecn_conn_pl_ce++;
				IFP_PER_FLOW_STAT(ifs->ipv4, ecn_conn_plce);
			} else {
				tcpstat.tcps_ecn_conn_nopl_ce++;
				IFP_PER_FLOW_STAT(ifs->ipv4, ecn_conn_noplce);
			}
		} else {
			if (ifs->txretransmitbytes > 0 ||
			    ifs->rxoutoforderbytes > 0) {
				tcpstat.tcps_ecn_conn_plnoce++;
				IFP_PER_FLOW_STAT(ifs->ipv4, ecn_conn_plnoce);
			}
		}
	}

	/* Other stats are interesting for non-local connections only */
	if (ifs->local) {
		ifnet_lock_done(ifp);
		return;
	}

	if (ifs->ipv4) {
		ifp->if_ipv4_stat->timestamp = net_uptime();
		if (FLOW_ECN_ENABLED(ifs->ecn_flags)) {
			tcp_flow_ecn_perf_stats(ifs, &ifp->if_ipv4_stat->ecn_on);
		} else {
			tcp_flow_ecn_perf_stats(ifs, &ifp->if_ipv4_stat->ecn_off);
		}
	} else {
		ifp->if_ipv6_stat->timestamp = net_uptime();
		if (FLOW_ECN_ENABLED(ifs->ecn_flags)) {
			tcp_flow_ecn_perf_stats(ifs, &ifp->if_ipv6_stat->ecn_on);
		} else {
			tcp_flow_ecn_perf_stats(ifs, &ifp->if_ipv6_stat->ecn_off);
		}
	}

	if (ifs->rxmit_drop) {
		if (FLOW_ECN_ENABLED(ifs->ecn_flags)) {
			IFP_PER_FLOW_STAT(ifs->ipv4, ecn_on.rxmit_drop);
		} else {
			IFP_PER_FLOW_STAT(ifs->ipv4, ecn_off.rxmit_drop);
		}
	}
	if (ifs->ecn_fallback_synloss)
		IFP_PER_FLOW_STAT(ifs->ipv4, ecn_fallback_synloss);
	if (ifs->ecn_fallback_droprst)
		IFP_PER_FLOW_STAT(ifs->ipv4, ecn_fallback_droprst);
	if (ifs->ecn_fallback_droprxmt)
		IFP_PER_FLOW_STAT(ifs->ipv4, ecn_fallback_droprxmt);
	if (ifs->ecn_fallback_ce)
		IFP_PER_FLOW_STAT(ifs->ipv4, ecn_fallback_ce);
	if (ifs->ecn_fallback_reorder)
		IFP_PER_FLOW_STAT(ifs->ipv4, ecn_fallback_reorder);
	if (ifs->ecn_recv_ce > 0)
		IFP_PER_FLOW_STAT(ifs->ipv4, ecn_recv_ce);
	if (ifs->ecn_recv_ece > 0)
		IFP_PER_FLOW_STAT(ifs->ipv4, ecn_recv_ece);

	tcp_flow_lim_stats(ifs, &ifp->if_lim_stat);
	ifnet_lock_done(ifp);
}
