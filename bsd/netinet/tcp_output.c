/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
 *	@(#)tcp_output.c	8.4 (Berkeley) 5/24/95
 * $FreeBSD: src/sys/netinet/tcp_output.c,v 1.39.2.10 2001/07/07 04:30:38 silby Exp $
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#define _IP_VHL


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/route.h>
#include <net/ntstat.h>
#include <net/if_var.h>
#include <net/if.h>
#include <net/if_types.h>
#include <net/dlil.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/in_tclass.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <mach/sdt.h>
#include <netinet6/in6_pcb.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/tcp.h>
#define TCPOUTFLAGS
#include <netinet/tcp_cache.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_cc.h>
#if TCPDEBUG
#include <netinet/tcp_debug.h>
#endif
#include <netinet/tcp_log.h>
#include <sys/kdebug.h>
#include <mach/sdt.h>

#if IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

#if MPTCP
#include <netinet/mptcp_var.h>
#include <netinet/mptcp.h>
#include <netinet/mptcp_opt.h>
#include <netinet/mptcp_seq.h>
#endif

#include <corecrypto/ccaes.h>

#define DBG_LAYER_BEG           NETDBG_CODE(DBG_NETTCP, 1)
#define DBG_LAYER_END           NETDBG_CODE(DBG_NETTCP, 3)
#define DBG_FNC_TCP_OUTPUT      NETDBG_CODE(DBG_NETTCP, (4 << 8) | 1)

SYSCTL_SKMEM_TCP_INT(OID_AUTO, path_mtu_discovery,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, path_mtu_discovery, 1,
    "Enable Path MTU Discovery");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, local_slowstart_flightsize,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, ss_fltsz_local, 8,
    "Slow start flight size for local networks");

int     tcp_do_tso = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, tso, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_do_tso, 0, "Enable TCP Segmentation Offload");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, ecn_setup_percentage,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, tcp_ecn_setup_percentage, 100,
    "Max ECN setup percentage");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, do_ack_compression,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, tcp_do_ack_compression, 1,
    "Enable TCP ACK compression (on (cell only): 1, off: 0, on (all interfaces): 2)");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, ack_compression_rate,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, tcp_ack_compression_rate, TCP_COMP_CHANGE_RATE,
    "Rate at which we force sending new ACKs (in ms)");

static int
sysctl_change_ecn_setting SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int i, err = 0, changed = 0;
	struct ifnet *ifp;

	err = sysctl_io_number(req, tcp_ecn_outbound, sizeof(int32_t),
	    &i, &changed);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (changed) {
		if ((tcp_ecn_outbound == 0 || tcp_ecn_outbound == 1) &&
		    (i == 0 || i == 1)) {
			tcp_ecn_outbound = i;
			SYSCTL_SKMEM_UPDATE_FIELD(tcp.ecn_initiate_out, tcp_ecn_outbound);
			return err;
		}
		if (tcp_ecn_outbound == 2 && (i == 0 || i == 1)) {
			/*
			 * Reset ECN enable flags on non-cellular
			 * interfaces so that the system default will take
			 * over
			 */
			ifnet_head_lock_shared();
			TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
				if (!IFNET_IS_CELLULAR(ifp)) {
					if_clear_eflags(ifp,
					    IFEF_ECN_ENABLE |
					    IFEF_ECN_DISABLE);
				}
			}
			ifnet_head_done();
		} else {
			/*
			 * Set ECN enable flags on non-cellular
			 * interfaces
			 */
			ifnet_head_lock_shared();
			TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
				if (!IFNET_IS_CELLULAR(ifp)) {
					if_set_eflags(ifp, IFEF_ECN_ENABLE);
					if_clear_eflags(ifp, IFEF_ECN_DISABLE);
				}
			}
			ifnet_head_done();
		}
		tcp_ecn_outbound = i;
		SYSCTL_SKMEM_UPDATE_FIELD(tcp.ecn_initiate_out, tcp_ecn_outbound);
	}
	/* Change the other one too as the work is done */
	if (i == 2 || tcp_ecn_inbound == 2) {
		tcp_ecn_inbound = i;
		SYSCTL_SKMEM_UPDATE_FIELD(tcp.ecn_negotiate_in, tcp_ecn_inbound);
	}
	return err;
}

int     tcp_ecn_outbound = 2;
SYSCTL_PROC(_net_inet_tcp, OID_AUTO, ecn_initiate_out,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_ecn_outbound, 0,
    sysctl_change_ecn_setting, "IU",
    "Initiate ECN for outbound connections");

int     tcp_ecn_inbound = 2;
SYSCTL_PROC(_net_inet_tcp, OID_AUTO, ecn_negotiate_in,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_ecn_inbound, 0,
    sysctl_change_ecn_setting, "IU",
    "Initiate ECN for inbound connections");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, packetchain,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, tcp_packet_chaining, 50,
    "Enable TCP output packet chaining");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, socket_unlocked_on_output,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, tcp_output_unlocked, 1,
    "Unlock TCP when sending packets down to IP");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, min_iaj_win,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, tcp_min_iaj_win, MIN_IAJ_WIN,
    "Minimum recv win based on inter-packet arrival jitter");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, acc_iaj_react_limit,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, tcp_acc_iaj_react_limit,
    ACC_IAJ_REACT_LIMIT, "Accumulated IAJ when receiver starts to react");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, autosndbufinc,
    CTLFLAG_RW | CTLFLAG_LOCKED, uint32_t, tcp_autosndbuf_inc,
    8 * 1024, "Increment in send socket bufffer size");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, autosndbufmax,
    CTLFLAG_RW | CTLFLAG_LOCKED, uint32_t, tcp_autosndbuf_max, 2 * 1024 * 1024,
    "Maximum send socket buffer size");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, rtt_recvbg,
    CTLFLAG_RW | CTLFLAG_LOCKED, uint32_t, tcp_use_rtt_recvbg, 1,
    "Use RTT for bg recv algorithm");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, recv_throttle_minwin,
    CTLFLAG_RW | CTLFLAG_LOCKED, uint32_t, tcp_recv_throttle_minwin, 16 * 1024,
    "Minimum recv win for throttling");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, enable_tlp,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    int32_t, tcp_enable_tlp, 1, "Enable Tail loss probe");

static int32_t packchain_newlist = 0;
static int32_t packchain_looped = 0;
static int32_t packchain_sent = 0;

/* temporary: for testing */
#if IPSEC
extern int ipsec_bypass;
#endif

extern int slowlink_wsize;      /* window correction for slow links */

extern u_int32_t dlil_filter_disable_tso_count;
extern u_int32_t kipf_count;

static int tcp_ip_output(struct socket *, struct tcpcb *, struct mbuf *,
    int, struct mbuf *, int, int, boolean_t);
static int tcp_recv_throttle(struct tcpcb *tp);

static int32_t
tcp_tfo_check(struct tcpcb *tp, int32_t len)
{
	struct socket *so = tp->t_inpcb->inp_socket;
	unsigned int optlen = 0;
	unsigned int cookie_len;

	if (tp->t_flags & TF_NOOPT) {
		goto fallback;
	}

	if (!(tp->t_flagsext & TF_FASTOPEN_FORCE_ENABLE) &&
	    !tcp_heuristic_do_tfo(tp)) {
		tp->t_tfo_stats |= TFO_S_HEURISTICS_DISABLE;
		tcpstat.tcps_tfo_heuristics_disable++;
		goto fallback;
	}

	if (so->so_flags1 & SOF1_DATA_AUTHENTICATED) {
		return len;
	}

	optlen += TCPOLEN_MAXSEG;

	if (tp->t_flags & TF_REQ_SCALE) {
		optlen += 4;
	}

#if MPTCP
	if ((so->so_flags & SOF_MP_SUBFLOW) && mptcp_enable &&
	    (tp->t_rxtshift <= mptcp_mpcap_retries ||
	    (tptomptp(tp)->mpt_mpte->mpte_flags & MPTE_FORCE_ENABLE))) {
		optlen += sizeof(struct mptcp_mpcapable_opt_common) + sizeof(mptcp_key_t);
	}
#endif /* MPTCP */

	if (tp->t_flags & TF_REQ_TSTMP) {
		optlen += TCPOLEN_TSTAMP_APPA;
	}

	if (SACK_ENABLED(tp)) {
		optlen += TCPOLEN_SACK_PERMITTED;
	}

	/* Now, decide whether to use TFO or not */

	/* Don't even bother trying if there is no space at all... */
	if (MAX_TCPOPTLEN - optlen < TCPOLEN_FASTOPEN_REQ) {
		goto fallback;
	}

	cookie_len = tcp_cache_get_cookie_len(tp);
	if (cookie_len == 0) {
		/* No cookie, so we request one */
		return 0;
	}

	/* There is not enough space for the cookie, so we cannot do TFO */
	if (MAX_TCPOPTLEN - optlen < cookie_len) {
		goto fallback;
	}

	/* Do not send SYN+data if there is more in the queue than MSS */
	if (so->so_snd.sb_cc > (tp->t_maxopd - MAX_TCPOPTLEN)) {
		goto fallback;
	}

	/* Ok, everything looks good. We can go on and do TFO */
	return len;

fallback:
	tcp_disable_tfo(tp);
	return 0;
}

/* Returns the number of bytes written to the TCP option-space */
static unsigned int
tcp_tfo_write_cookie_rep(struct tcpcb *tp, unsigned int optlen, u_char *opt)
{
	u_char out[CCAES_BLOCK_SIZE];
	unsigned ret = 0;
	u_char *bp;

	if ((MAX_TCPOPTLEN - optlen) <
	    (TCPOLEN_FASTOPEN_REQ + TFO_COOKIE_LEN_DEFAULT)) {
		return ret;
	}

	tcp_tfo_gen_cookie(tp->t_inpcb, out, sizeof(out));

	bp = opt + optlen;

	*bp++ = TCPOPT_FASTOPEN;
	*bp++ = 2 + TFO_COOKIE_LEN_DEFAULT;
	memcpy(bp, out, TFO_COOKIE_LEN_DEFAULT);
	ret += 2 + TFO_COOKIE_LEN_DEFAULT;

	tp->t_tfo_stats |= TFO_S_COOKIE_SENT;
	tcpstat.tcps_tfo_cookie_sent++;

	return ret;
}

static unsigned int
tcp_tfo_write_cookie(struct tcpcb *tp, unsigned int optlen, int32_t len,
    u_char *opt)
{
	uint8_t tfo_len;
	struct socket *so = tp->t_inpcb->inp_socket;
	unsigned ret = 0;
	int res;
	u_char *bp;

	if (TCPOLEN_FASTOPEN_REQ > MAX_TCPOPTLEN - optlen) {
		return 0;
	}
	tfo_len = (uint8_t)(MAX_TCPOPTLEN - optlen - TCPOLEN_FASTOPEN_REQ);

	if (so->so_flags1 & SOF1_DATA_AUTHENTICATED) {
		/* If there is some data, let's track it */
		if (len > 0) {
			tp->t_tfo_stats |= TFO_S_SYN_DATA_SENT;
			tcpstat.tcps_tfo_syn_data_sent++;
		}

		return 0;
	}

	bp = opt + optlen;

	/*
	 * The cookie will be copied in the appropriate place within the
	 * TCP-option space. That way we avoid the need for an intermediate
	 * variable.
	 */
	res = tcp_cache_get_cookie(tp, bp + TCPOLEN_FASTOPEN_REQ, &tfo_len);
	if (res == 0) {
		*bp++ = TCPOPT_FASTOPEN;
		*bp++ = TCPOLEN_FASTOPEN_REQ;
		ret += TCPOLEN_FASTOPEN_REQ;

		tp->t_tfo_flags |= TFO_F_COOKIE_REQ;

		tp->t_tfo_stats |= TFO_S_COOKIE_REQ;
		tcpstat.tcps_tfo_cookie_req++;
	} else {
		*bp++ = TCPOPT_FASTOPEN;
		*bp++ = TCPOLEN_FASTOPEN_REQ + tfo_len;

		ret += TCPOLEN_FASTOPEN_REQ + tfo_len;

		tp->t_tfo_flags |= TFO_F_COOKIE_SENT;

		/* If there is some data, let's track it */
		if (len > 0) {
			tp->t_tfo_stats |= TFO_S_SYN_DATA_SENT;
			tcpstat.tcps_tfo_syn_data_sent++;
		}
	}

	return ret;
}

static inline bool
tcp_send_ecn_flags_on_syn(struct tcpcb *tp)
{
	return !(tp->ecn_flags & TE_SETUPSENT);
}

void
tcp_set_ecn(struct tcpcb *tp, struct ifnet *ifp)
{
	boolean_t inbound;

	/*
	 * Socket option has precedence
	 */
	if (tp->ecn_flags & TE_ECN_MODE_ENABLE) {
		tp->ecn_flags |= TE_ENABLE_ECN;
		goto check_heuristic;
	}

	if (tp->ecn_flags & TE_ECN_MODE_DISABLE) {
		tp->ecn_flags &= ~TE_ENABLE_ECN;
		return;
	}
	/*
	 * Per interface setting comes next
	 */
	if (ifp != NULL) {
		if (ifp->if_eflags & IFEF_ECN_ENABLE) {
			tp->ecn_flags |= TE_ENABLE_ECN;
			goto check_heuristic;
		}

		if (ifp->if_eflags & IFEF_ECN_DISABLE) {
			tp->ecn_flags &= ~TE_ENABLE_ECN;
			return;
		}
	}
	/*
	 * System wide settings come last
	 */
	inbound = (tp->t_inpcb->inp_socket->so_head != NULL);
	if ((inbound && tcp_ecn_inbound == 1) ||
	    (!inbound && tcp_ecn_outbound == 1)) {
		tp->ecn_flags |= TE_ENABLE_ECN;
		goto check_heuristic;
	} else {
		tp->ecn_flags &= ~TE_ENABLE_ECN;
	}

	return;

check_heuristic:
	if (!tcp_heuristic_do_ecn(tp)) {
		tp->ecn_flags &= ~TE_ENABLE_ECN;
	}

	/*
	 * If the interface setting, system-level setting and heuristics
	 * allow to enable ECN, randomly select 5% of connections to
	 * enable it
	 */
	if ((tp->ecn_flags & (TE_ECN_MODE_ENABLE | TE_ECN_MODE_DISABLE
	    | TE_ENABLE_ECN)) == TE_ENABLE_ECN) {
		/*
		 * Use the random value in iss for randomizing
		 * this selection
		 */
		if ((tp->iss % 100) >= tcp_ecn_setup_percentage) {
			tp->ecn_flags &= ~TE_ENABLE_ECN;
		}
	}
}

int
tcp_flight_size(struct tcpcb *tp)
{
	int ret;

	VERIFY(tp->sackhint.sack_bytes_acked >= 0);
	VERIFY(tp->sackhint.sack_bytes_rexmit >= 0);

	/*
	 * RFC6675, SetPipe (), SACK'd bytes are discounted. All the rest is still in-flight.
	 */
	ret = tp->snd_nxt - tp->snd_una - tp->sackhint.sack_bytes_acked;

	if (ret < 0) {
		/*
		 * This happens when the RTO-timer fires because snd_nxt gets artificially
		 * decreased. If we then receive some SACK-blogs, sack_bytes_acked is
		 * going to be high.
		 */
		ret = 0;
	}

	return ret;
}

/*
 * Tcp output routine: figure out what should be sent and send it.
 *
 * Returns:	0			Success
 *		EADDRNOTAVAIL
 *		ENOBUFS
 *		EMSGSIZE
 *		EHOSTUNREACH
 *		ENETDOWN
 *	ip_output_list:ENOMEM
 *	ip_output_list:EADDRNOTAVAIL
 *	ip_output_list:ENETUNREACH
 *	ip_output_list:EHOSTUNREACH
 *	ip_output_list:EACCES
 *	ip_output_list:EMSGSIZE
 *	ip_output_list:ENOBUFS
 *	ip_output_list:???		[ignorable: mostly IPSEC/firewall/DLIL]
 *	ip6_output_list:EINVAL
 *	ip6_output_list:EOPNOTSUPP
 *	ip6_output_list:EHOSTUNREACH
 *	ip6_output_list:EADDRNOTAVAIL
 *	ip6_output_list:ENETUNREACH
 *	ip6_output_list:EMSGSIZE
 *	ip6_output_list:ENOBUFS
 *	ip6_output_list:???		[ignorable: mostly IPSEC/firewall/DLIL]
 */
int
tcp_output(struct tcpcb *tp)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
	int32_t len, recwin, sendwin, off;
	uint8_t flags;
	int error;
	struct mbuf *m;
	struct ip *ip = NULL;
	struct ip6_hdr *ip6 = NULL;
	struct tcphdr *th;
	u_char opt[TCP_MAXOLEN];
	unsigned int ipoptlen, optlen, hdrlen;
	int idle, sendalot, lost = 0;
	int i, sack_rxmit;
	int tso = 0;
	int sack_bytes_rxmt;
	tcp_seq old_snd_nxt = 0;
	struct sackhole *p;
#if IPSEC
	unsigned int ipsec_optlen = 0;
#endif /* IPSEC */
	int    idle_time = 0;
	struct mbuf *packetlist = NULL;
	struct mbuf *tp_inp_options = inp->inp_depend4.inp4_options;
	int isipv6 = inp->inp_vflag & INP_IPV6;
	int packchain_listadd = 0;
	int so_options = so->so_options;
	struct rtentry *rt;
	u_int32_t svc_flags = 0, allocated_len;
	unsigned int sackoptlen = 0;
#if MPTCP
	boolean_t mptcp_acknow;
#endif /* MPTCP */
	boolean_t cell = FALSE;
	boolean_t wifi = FALSE;
	boolean_t wired = FALSE;
	boolean_t sack_rescue_rxt = FALSE;
	int sotc = so->so_traffic_class;
	boolean_t do_not_compress = FALSE;
	boolean_t sack_rxmted = FALSE;

	/*
	 * Determine length of data that should be transmitted,
	 * and flags that will be used.
	 * If there is some data or critical controls (SYN, RST)
	 * to send, then transmit; otherwise, investigate further.
	 */
	idle = (tp->t_flags & TF_LASTIDLE) || (tp->snd_max == tp->snd_una);

	/* Since idle_time is signed integer, the following integer subtraction
	 * will take care of wrap around of tcp_now
	 */
	idle_time = tcp_now - tp->t_rcvtime;
	if (idle && idle_time >= TCP_IDLETIMEOUT(tp)) {
		if (CC_ALGO(tp)->after_idle != NULL &&
		    (tp->tcp_cc_index != TCP_CC_ALGO_CUBIC_INDEX ||
		    idle_time >= TCP_CC_CWND_NONVALIDATED_PERIOD)) {
			CC_ALGO(tp)->after_idle(tp);
			tcp_ccdbg_trace(tp, NULL, TCP_CC_IDLE_TIMEOUT);
		}

		/*
		 * Do some other tasks that need to be done after
		 * idle time
		 */
		if (!SLIST_EMPTY(&tp->t_rxt_segments)) {
			tcp_rxtseg_clean(tp);
		}

		/* If stretch ack was auto-disabled, re-evaluate it */
		tcp_cc_after_idle_stretchack(tp);
		tp->t_forced_acks = TCP_FORCED_ACKS_COUNT;
	}
	tp->t_flags &= ~TF_LASTIDLE;
	if (idle) {
		if (tp->t_flags & TF_MORETOCOME) {
			tp->t_flags |= TF_LASTIDLE;
			idle = 0;
		}
	}
#if MPTCP
	if (tp->t_mpflags & TMPF_RESET) {
		tcp_check_timer_state(tp);
		/*
		 * Once a RST has been sent for an MPTCP subflow,
		 * the subflow socket stays around until deleted.
		 * No packets such as FINs must be sent after RST.
		 */
		return 0;
	}
#endif /* MPTCP */

again:
#if MPTCP
	mptcp_acknow = FALSE;
#endif
	do_not_compress = FALSE;

	KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_START, 0, 0, 0, 0, 0);

	if (isipv6) {
		KERNEL_DEBUG(DBG_LAYER_BEG,
		    ((inp->inp_fport << 16) | inp->inp_lport),
		    (((inp->in6p_laddr.s6_addr16[0] & 0xffff) << 16) |
		    (inp->in6p_faddr.s6_addr16[0] & 0xffff)),
		    sendalot, 0, 0);
	} else {
		KERNEL_DEBUG(DBG_LAYER_BEG,
		    ((inp->inp_fport << 16) | inp->inp_lport),
		    (((inp->inp_laddr.s_addr & 0xffff) << 16) |
		    (inp->inp_faddr.s_addr & 0xffff)),
		    sendalot, 0, 0);
	}
	/*
	 * If the route generation id changed, we need to check that our
	 * local (source) IP address is still valid. If it isn't either
	 * return error or silently do nothing (assuming the address will
	 * come back before the TCP connection times out).
	 */
	rt = inp->inp_route.ro_rt;
	if (rt != NULL && ROUTE_UNUSABLE(&tp->t_inpcb->inp_route)) {
		struct ifnet *ifp;
		struct in_ifaddr *ia = NULL;
		struct in6_ifaddr *ia6 = NULL;
		int found_srcaddr = 0;

		/* disable multipages at the socket */
		somultipages(so, FALSE);

		/* Disable TSO for the socket until we know more */
		tp->t_flags &= ~TF_TSO;

		soif2kcl(so, FALSE);

		if (isipv6) {
			ia6 = ifa_foraddr6(&inp->in6p_laddr);
			if (ia6 != NULL) {
				found_srcaddr = 1;
			}
		} else {
			ia = ifa_foraddr(inp->inp_laddr.s_addr);
			if (ia != NULL) {
				found_srcaddr = 1;
			}
		}

		/* check that the source address is still valid */
		if (found_srcaddr == 0) {
			soevent(so,
			    (SO_FILT_HINT_LOCKED | SO_FILT_HINT_NOSRCADDR));

			if (tp->t_state >= TCPS_CLOSE_WAIT) {
				tcp_drop(tp, EADDRNOTAVAIL);
				return EADDRNOTAVAIL;
			}

			/*
			 * Set retransmit  timer if it wasn't set,
			 * reset Persist timer and shift register as the
			 * advertised peer window may not be valid anymore
			 */
			if (tp->t_timer[TCPT_REXMT] == 0) {
				tp->t_timer[TCPT_REXMT] =
				    OFFSET_FROM_START(tp, tp->t_rxtcur);
				if (tp->t_timer[TCPT_PERSIST] != 0) {
					tp->t_timer[TCPT_PERSIST] = 0;
					tp->t_persist_stop = 0;
					TCP_RESET_REXMT_STATE(tp);
				}
			}

			if (tp->t_pktlist_head != NULL) {
				m_freem_list(tp->t_pktlist_head);
			}
			TCP_PKTLIST_CLEAR(tp);

			/* drop connection if source address isn't available */
			if (so->so_flags & SOF_NOADDRAVAIL) {
				tcp_drop(tp, EADDRNOTAVAIL);
				return EADDRNOTAVAIL;
			} else {
				tcp_check_timer_state(tp);
				return 0; /* silently ignore, keep data in socket: address may be back */
			}
		}
		if (ia != NULL) {
			IFA_REMREF(&ia->ia_ifa);
		}

		if (ia6 != NULL) {
			IFA_REMREF(&ia6->ia_ifa);
		}

		/*
		 * Address is still valid; check for multipages capability
		 * again in case the outgoing interface has changed.
		 */
		RT_LOCK(rt);
		if ((ifp = rt->rt_ifp) != NULL) {
			somultipages(so, (ifp->if_hwassist & IFNET_MULTIPAGES));
			tcp_set_tso(tp, ifp);
			soif2kcl(so, (ifp->if_eflags & IFEF_2KCL));
			tcp_set_ecn(tp, ifp);
		}
		if (rt->rt_flags & RTF_UP) {
			RT_GENID_SYNC(rt);
		}
		/*
		 * See if we should do MTU discovery. Don't do it if:
		 *	1) it is disabled via the sysctl
		 *	2) the route isn't up
		 *	3) the MTU is locked (if it is, then discovery
		 *         has been disabled)
		 */

		if (!path_mtu_discovery || ((rt != NULL) &&
		    (!(rt->rt_flags & RTF_UP) ||
		    (rt->rt_rmx.rmx_locks & RTV_MTU)))) {
			tp->t_flags &= ~TF_PMTUD;
		} else {
			tp->t_flags |= TF_PMTUD;
		}

		RT_UNLOCK(rt);
	}

	if (rt != NULL) {
		cell = IFNET_IS_CELLULAR(rt->rt_ifp);
		wifi = (!cell && IFNET_IS_WIFI(rt->rt_ifp));
		wired = (!wifi && IFNET_IS_WIRED(rt->rt_ifp));
	}

	/*
	 * If we've recently taken a timeout, snd_max will be greater than
	 * snd_nxt.  There may be SACK information that allows us to avoid
	 * resending already delivered data.  Adjust snd_nxt accordingly.
	 */
	if (SACK_ENABLED(tp) && SEQ_LT(tp->snd_nxt, tp->snd_max)) {
		tcp_sack_adjust(tp);
	}
	sendalot = 0;
	off = tp->snd_nxt - tp->snd_una;
	sendwin = min(tp->snd_wnd, tp->snd_cwnd);

	if (tp->t_flags & TF_SLOWLINK && slowlink_wsize > 0) {
		sendwin = min(sendwin, slowlink_wsize);
	}

	flags = tcp_outflags[tp->t_state];
	/*
	 * Send any SACK-generated retransmissions.  If we're explicitly
	 * trying to send out new data (when sendalot is 1), bypass this
	 * function. If we retransmit in fast recovery mode, decrement
	 * snd_cwnd, since we're replacing a (future) new transmission
	 * with a retransmission now, and we previously incremented
	 * snd_cwnd in tcp_input().
	 */
	/*
	 * Still in sack recovery , reset rxmit flag to zero.
	 */
	sack_rxmit = 0;
	sack_bytes_rxmt = 0;
	len = 0;
	p = NULL;
	if (SACK_ENABLED(tp) && IN_FASTRECOVERY(tp) &&
	    (p = tcp_sack_output(tp, &sack_bytes_rxmt))) {
		int32_t cwin;

		if (tcp_do_better_lr) {
			cwin = min(tp->snd_wnd, tp->snd_cwnd) - tcp_flight_size(tp);
			if (cwin <= 0 && sack_rxmted == FALSE) {
				/* Allow to clock out at least on per period */
				cwin = tp->t_maxseg;
			}

			sack_rxmted = TRUE;
		} else {
			cwin = min(tp->snd_wnd, tp->snd_cwnd) - sack_bytes_rxmt;
		}
		if (cwin < 0) {
			cwin = 0;
		}
		/* Do not retransmit SACK segments beyond snd_recover */
		if (SEQ_GT(p->end, tp->snd_recover)) {
			/*
			 * (At least) part of sack hole extends beyond
			 * snd_recover. Check to see if we can rexmit data
			 * for this hole.
			 */
			if (SEQ_GEQ(p->rxmit, tp->snd_recover)) {
				/*
				 * Can't rexmit any more data for this hole.
				 * That data will be rexmitted in the next
				 * sack recovery episode, when snd_recover
				 * moves past p->rxmit.
				 */
				p = NULL;
				goto after_sack_rexmit;
			} else {
				/* Can rexmit part of the current hole */
				len = ((int32_t)min(cwin,
				    tp->snd_recover - p->rxmit));
			}
		} else {
			len = ((int32_t)min(cwin, p->end - p->rxmit));
		}
		if (len > 0) {
			off = p->rxmit - tp->snd_una;
			sack_rxmit = 1;
			sendalot = 1;
			/* Everything sent after snd_nxt will allow us to account for fast-retransmit of the retransmitted segment */
			tp->send_highest_sack = tp->snd_nxt;
			tp->t_new_dupacks = 0;
			tcpstat.tcps_sack_rexmits++;
			tcpstat.tcps_sack_rexmit_bytes +=
			    min(len, tp->t_maxseg);
		} else {
			len = 0;
		}
	}
after_sack_rexmit:
	/*
	 * Get standard flags, and add SYN or FIN if requested by 'hidden'
	 * state flags.
	 */
	if (tp->t_flags & TF_NEEDFIN) {
		flags |= TH_FIN;
	}

	/*
	 * If in persist timeout with window of 0, send 1 byte.
	 * Otherwise, if window is small but nonzero
	 * and timer expired, we will send what we can
	 * and go to transmit state.
	 */
	if (tp->t_flagsext & TF_FORCE) {
		if (sendwin == 0) {
			/*
			 * If we still have some data to send, then
			 * clear the FIN bit.  Usually this would
			 * happen below when it realizes that we
			 * aren't sending all the data.  However,
			 * if we have exactly 1 byte of unsent data,
			 * then it won't clear the FIN bit below,
			 * and if we are in persist state, we wind
			 * up sending the packet without recording
			 * that we sent the FIN bit.
			 *
			 * We can't just blindly clear the FIN bit,
			 * because if we don't have any more data
			 * to send then the probe will be the FIN
			 * itself.
			 */
			if (off < so->so_snd.sb_cc) {
				flags &= ~TH_FIN;
			}
			sendwin = 1;
		} else {
			tp->t_timer[TCPT_PERSIST] = 0;
			tp->t_persist_stop = 0;
			TCP_RESET_REXMT_STATE(tp);
		}
	}

	/*
	 * If snd_nxt == snd_max and we have transmitted a FIN, the
	 * offset will be > 0 even if so_snd.sb_cc is 0, resulting in
	 * a negative length.  This can also occur when TCP opens up
	 * its congestion window while receiving additional duplicate
	 * acks after fast-retransmit because TCP will reset snd_nxt
	 * to snd_max after the fast-retransmit.
	 *
	 * In the normal retransmit-FIN-only case, however, snd_nxt will
	 * be set to snd_una, the offset will be 0, and the length may
	 * wind up 0.
	 *
	 * If sack_rxmit is true we are retransmitting from the scoreboard
	 * in which case len is already set.
	 */
	if (sack_rxmit == 0) {
		if (sack_bytes_rxmt == 0) {
			len = min(so->so_snd.sb_cc, sendwin) - off;
		} else {
			int32_t cwin;

			if (tcp_do_better_lr) {
				cwin = tp->snd_cwnd - tcp_flight_size(tp);
			} else {
				cwin = tp->snd_cwnd -
				    (tp->snd_nxt - tp->sack_newdata) -
				    sack_bytes_rxmt;
			}
			if (cwin < 0) {
				cwin = 0;
			}
			/*
			 * We are inside of a SACK recovery episode and are
			 * sending new data, having retransmitted all the
			 * data possible in the scoreboard.
			 */
			len = min(so->so_snd.sb_cc, tp->snd_wnd) - off;
			/*
			 * Don't remove this (len > 0) check !
			 * We explicitly check for len > 0 here (although it
			 * isn't really necessary), to work around a gcc
			 * optimization issue - to force gcc to compute
			 * len above. Without this check, the computation
			 * of len is bungled by the optimizer.
			 */
			if (len > 0) {
				len = imin(len, cwin);
			} else {
				len = 0;
			}
			/*
			 * At this point SACK recovery can not send any
			 * data from scoreboard or any new data. Check
			 * if we can do a rescue retransmit towards the
			 * tail end of recovery window.
			 */
			if (len == 0 && cwin > 0 &&
			    SEQ_LT(tp->snd_fack, tp->snd_recover) &&
			    !(tp->t_flagsext & TF_RESCUE_RXT)) {
				len = min((tp->snd_recover - tp->snd_fack),
				    tp->t_maxseg);
				len = imin(len, cwin);
				old_snd_nxt = tp->snd_nxt;
				sack_rescue_rxt = TRUE;
				tp->snd_nxt = tp->snd_recover - len;
				/*
				 * If FIN has been sent, snd_max
				 * must have been advanced to cover it.
				 */
				if ((tp->t_flags & TF_SENTFIN) &&
				    tp->snd_max == tp->snd_recover) {
					tp->snd_nxt--;
				}

				off = tp->snd_nxt - tp->snd_una;
				sendalot = 0;
				tp->t_flagsext |= TF_RESCUE_RXT;
			}
		}
	}

	/*
	 * Lop off SYN bit if it has already been sent.  However, if this
	 * is SYN-SENT state and if segment contains data and if we don't
	 * know that foreign host supports TAO, suppress sending segment.
	 */
	if ((flags & TH_SYN) && SEQ_GT(tp->snd_nxt, tp->snd_una)) {
		if (tp->t_state == TCPS_SYN_RECEIVED && tfo_enabled(tp) && tp->snd_nxt == tp->snd_una + 1) {
			/* We are sending the SYN again! */
			off--;
			len++;
		} else {
			if (tp->t_state != TCPS_SYN_RECEIVED || tfo_enabled(tp)) {
				flags &= ~TH_SYN;
			}

			off--;
			len++;
			if (len > 0 && tp->t_state == TCPS_SYN_SENT) {
				while (inp->inp_sndinprog_cnt == 0 &&
				    tp->t_pktlist_head != NULL) {
					packetlist = tp->t_pktlist_head;
					packchain_listadd = tp->t_lastchain;
					packchain_sent++;
					TCP_PKTLIST_CLEAR(tp);

					error = tcp_ip_output(so, tp, packetlist,
					    packchain_listadd, tp_inp_options,
					    (so_options & SO_DONTROUTE),
					    (sack_rxmit || (sack_bytes_rxmt != 0)),
					    isipv6);
				}

				/*
				 * tcp was closed while we were in ip,
				 * resume close
				 */
				if (inp->inp_sndinprog_cnt == 0 &&
				    (tp->t_flags & TF_CLOSING)) {
					tp->t_flags &= ~TF_CLOSING;
					(void) tcp_close(tp);
				} else {
					tcp_check_timer_state(tp);
				}
				KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END,
				    0, 0, 0, 0, 0);
				return 0;
			}
		}
	}

	/*
	 * Be careful not to send data and/or FIN on SYN segments.
	 * This measure is needed to prevent interoperability problems
	 * with not fully conformant TCP implementations.
	 *
	 * In case of TFO, we handle the setting of the len in
	 * tcp_tfo_check. In case TFO is not enabled, never ever send
	 * SYN+data.
	 */
	if ((flags & TH_SYN) && !tfo_enabled(tp)) {
		len = 0;
		flags &= ~TH_FIN;
	}

	/*
	 * Don't send a RST with data.
	 */
	if (flags & TH_RST) {
		len = 0;
	}

	if ((flags & TH_SYN) && tp->t_state <= TCPS_SYN_SENT && tfo_enabled(tp)) {
		len = tcp_tfo_check(tp, len);
	}

	/*
	 * The check here used to be (len < 0). Some times len is zero
	 * when the congestion window is closed and we need to check
	 * if persist timer has to be set in that case. But don't set
	 * persist until connection is established.
	 */
	if (len <= 0 && !(flags & TH_SYN)) {
		/*
		 * If FIN has been sent but not acked,
		 * but we haven't been called to retransmit,
		 * len will be < 0.  Otherwise, window shrank
		 * after we sent into it.  If window shrank to 0,
		 * cancel pending retransmit, pull snd_nxt back
		 * to (closed) window, and set the persist timer
		 * if it isn't already going.  If the window didn't
		 * close completely, just wait for an ACK.
		 */
		len = 0;
		if (sendwin == 0) {
			tp->t_timer[TCPT_REXMT] = 0;
			tp->t_timer[TCPT_PTO] = 0;
			TCP_RESET_REXMT_STATE(tp);
			tp->snd_nxt = tp->snd_una;
			off = 0;
			if (tp->t_timer[TCPT_PERSIST] == 0) {
				tcp_setpersist(tp);
			}
		}
	}

	/*
	 * Automatic sizing of send socket buffer. Increase the send
	 * socket buffer size if all of the following criteria are met
	 *	1. the receiver has enough buffer space for this data
	 *	2. send buffer is filled to 7/8th with data (so we actually
	 *	   have data to make use of it);
	 *	3. our send window (slow start and congestion controlled) is
	 *	   larger than sent but unacknowledged data in send buffer.
	 */
	if (!INP_WAIT_FOR_IF_FEEDBACK(inp) && !IN_FASTRECOVERY(tp) &&
	    (so->so_snd.sb_flags & (SB_AUTOSIZE | SB_TRIM)) == SB_AUTOSIZE &&
	    tcp_cansbgrow(&so->so_snd)) {
		if ((tp->snd_wnd / 4 * 5) >= so->so_snd.sb_hiwat &&
		    so->so_snd.sb_cc >= (so->so_snd.sb_hiwat / 8 * 7) &&
		    sendwin >= (so->so_snd.sb_cc - (tp->snd_nxt - tp->snd_una))) {
			if (sbreserve(&so->so_snd,
			    min(so->so_snd.sb_hiwat + tcp_autosndbuf_inc,
			    tcp_autosndbuf_max)) == 1) {
				so->so_snd.sb_idealsize = so->so_snd.sb_hiwat;
			}
		}
	}

	/*
	 * Truncate to the maximum segment length or enable TCP Segmentation
	 * Offloading (if supported by hardware) and ensure that FIN is removed
	 * if the length no longer contains the last data byte.
	 *
	 * TSO may only be used if we are in a pure bulk sending state.
	 * The presence of TCP-MD5, SACK retransmits, SACK advertizements,
	 * filters and IP options, as well as disabling hardware checksum
	 * offload prevent using TSO.  With TSO the TCP header is the same
	 * (except for the sequence number) for all generated packets.  This
	 * makes it impossible to transmit any options which vary per generated
	 * segment or packet.
	 *
	 * The length of TSO bursts is limited to TCP_MAXWIN.  That limit and
	 * removal of FIN (if not already catched here) are handled later after
	 * the exact length of the TCP options are known.
	 */
#if IPSEC
	/*
	 * Pre-calculate here as we save another lookup into the darknesses
	 * of IPsec that way and can actually decide if TSO is ok.
	 */
	if (ipsec_bypass == 0) {
		ipsec_optlen = (unsigned int)ipsec_hdrsiz_tcp(tp);
	}
#endif
	if (len > tp->t_maxseg) {
		if ((tp->t_flags & TF_TSO) && tcp_do_tso && hwcksum_tx &&
		    ip_use_randomid && kipf_count == 0 &&
		    dlil_filter_disable_tso_count == 0 &&
		    tp->rcv_numsacks == 0 && sack_rxmit == 0 &&
		    sack_bytes_rxmt == 0 &&
		    inp->inp_options == NULL &&
		    inp->in6p_options == NULL
#if IPSEC
		    && ipsec_optlen == 0
#endif
		    ) {
			tso = 1;
			sendalot = 0;
		} else {
			len = tp->t_maxseg;
			sendalot = 1;
			tso = 0;
		}
	} else {
		tso = 0;
	}

	/* Send one segment or less as a tail loss probe */
	if (tp->t_flagsext & TF_SENT_TLPROBE) {
		len = min(len, tp->t_maxseg);
		sendalot = 0;
		tso = 0;
	}

#if MPTCP
	if (so->so_flags & SOF_MP_SUBFLOW && off < 0) {
		os_log_error(mptcp_log_handle, "%s - %lx: offset is negative! len %d off %d\n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(tp->t_mpsub->mpts_mpte),
		    len, off);
	}

	if ((so->so_flags & SOF_MP_SUBFLOW) &&
	    !(tp->t_mpflags & TMPF_TCP_FALLBACK)) {
		int newlen = len;
		if (tp->t_state >= TCPS_ESTABLISHED &&
		    (tp->t_mpflags & TMPF_SND_MPPRIO ||
		    tp->t_mpflags & TMPF_SND_REM_ADDR ||
		    tp->t_mpflags & TMPF_SND_MPFAIL ||
		    tp->t_mpflags & TMPF_SND_KEYS ||
		    tp->t_mpflags & TMPF_SND_JACK)) {
			if (len > 0) {
				len = 0;
				tso = 0;
			}
			/*
			 * On a new subflow, don't try to send again, because
			 * we are still waiting for the fourth ack.
			 */
			if (!(tp->t_mpflags & TMPF_PREESTABLISHED)) {
				sendalot = 1;
			}
			mptcp_acknow = TRUE;
		} else {
			mptcp_acknow = FALSE;
		}
		/*
		 * The contiguous bytes in the subflow socket buffer can be
		 * discontiguous at the MPTCP level. Since only one DSS
		 * option can be sent in one packet, reduce length to match
		 * the contiguous MPTCP level. Set sendalot to send remainder.
		 */
		if (len > 0 && off >= 0) {
			newlen = mptcp_adj_sendlen(so, off);
		}

		if (newlen < len) {
			len = newlen;
			if (len <= tp->t_maxseg) {
				tso = 0;
			}
		}
	}
#endif /* MPTCP */

	if (sack_rxmit) {
		if (SEQ_LT(p->rxmit + len, tp->snd_una + so->so_snd.sb_cc)) {
			flags &= ~TH_FIN;
		}
	} else {
		if (SEQ_LT(tp->snd_nxt + len, tp->snd_una + so->so_snd.sb_cc)) {
			flags &= ~TH_FIN;
		}
	}
	/*
	 * Compare available window to amount of window
	 * known to peer (as advertised window less
	 * next expected input).  If the difference is at least two
	 * max size segments, or at least 25% of the maximum possible
	 * window, then want to send a window update to peer.
	 */
	recwin = tcp_sbspace(tp);

	if (!(so->so_flags & SOF_MP_SUBFLOW)) {
		if (recwin < (int32_t)(so->so_rcv.sb_hiwat / 4) &&
		    recwin < (int)tp->t_maxseg) {
			recwin = 0;
		}
	} else {
		struct mptcb *mp_tp = tptomptp(tp);
		struct socket *mp_so = mptetoso(mp_tp->mpt_mpte);

		if (recwin < (int32_t)(mp_so->so_rcv.sb_hiwat / 4) &&
		    recwin < (int)tp->t_maxseg) {
			recwin = 0;
		}
	}

#if TRAFFIC_MGT
	if (tcp_recv_bg == 1 || IS_TCP_RECV_BG(so)) {
		if (recwin > 0 && tcp_recv_throttle(tp)) {
			uint32_t min_iaj_win = tcp_min_iaj_win * tp->t_maxseg;
			uint32_t bg_rwintop = tp->rcv_adv;
			if (SEQ_LT(bg_rwintop, tp->rcv_nxt + min_iaj_win)) {
				bg_rwintop =  tp->rcv_nxt + min_iaj_win;
			}
			recwin = imin((int32_t)(bg_rwintop - tp->rcv_nxt),
			    recwin);
			if (recwin < 0) {
				recwin = 0;
			}
		}
	}
#endif /* TRAFFIC_MGT */

	if (recwin > (int32_t)(TCP_MAXWIN << tp->rcv_scale)) {
		recwin = (int32_t)(TCP_MAXWIN << tp->rcv_scale);
	}

	if (!(so->so_flags & SOF_MP_SUBFLOW)) {
		if (recwin < (int32_t)(tp->rcv_adv - tp->rcv_nxt)) {
			recwin = (int32_t)(tp->rcv_adv - tp->rcv_nxt);
		}
	} else {
		struct mptcb *mp_tp = tptomptp(tp);
		int64_t recwin_announced = (int64_t)(mp_tp->mpt_rcvadv - mp_tp->mpt_rcvnxt);

		/* Don't remove what we announced at the MPTCP-layer */
		VERIFY(recwin_announced < INT32_MAX && recwin_announced > INT32_MIN);
		if (recwin < (int32_t)recwin_announced) {
			recwin = (int32_t)recwin_announced;
		}
	}

	/*
	 * Sender silly window avoidance.   We transmit under the following
	 * conditions when len is non-zero:
	 *
	 *	- we've timed out (e.g. persist timer)
	 *	- we need to retransmit
	 *	- We have a full segment (or more with TSO)
	 *	- This is the last buffer in a write()/send() and we are
	 *	  either idle or running NODELAY
	 *	- we have more then 1/2 the maximum send window's worth of
	 *	  data (receiver may be limited the window size)
	 */
	if (len) {
		if (tp->t_flagsext & TF_FORCE) {
			goto send;
		}
		if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
			goto send;
		}
		if (sack_rxmit) {
			goto send;
		}

		/*
		 * If this here is the first segment after SYN/ACK and TFO
		 * is being used, then we always send it, regardless of Nagle,...
		 */
		if (tp->t_state == TCPS_SYN_RECEIVED &&
		    tfo_enabled(tp) &&
		    (tp->t_tfo_flags & TFO_F_COOKIE_VALID) &&
		    tp->snd_nxt == tp->iss + 1) {
			goto send;
		}

		/*
		 * Send new data on the connection only if it is
		 * not flow controlled
		 */
		if (!INP_WAIT_FOR_IF_FEEDBACK(inp) ||
		    tp->t_state != TCPS_ESTABLISHED) {
			if (len >= tp->t_maxseg) {
				goto send;
			}

			if (!(tp->t_flags & TF_MORETOCOME) &&
			    (idle || tp->t_flags & TF_NODELAY ||
			    (tp->t_flags & TF_MAXSEGSNT) ||
			    ALLOW_LIMITED_TRANSMIT(tp)) &&
			    (tp->t_flags & TF_NOPUSH) == 0 &&
			    (len + off >= so->so_snd.sb_cc ||
			    /*
			     * MPTCP needs to respect the DSS-mappings. So, it
			     * may be sending data that *could* have been
			     * coalesced, but cannot because of
			     * mptcp_adj_sendlen().
			     */
			    so->so_flags & SOF_MP_SUBFLOW)) {
				goto send;
			}
			if (len >= tp->max_sndwnd / 2 && tp->max_sndwnd > 0) {
				goto send;
			}
		} else {
			tcpstat.tcps_fcholdpacket++;
		}
	}

	if (recwin > 0) {
		/*
		 * "adv" is the amount we can increase the window,
		 * taking into account that we are limited by
		 * TCP_MAXWIN << tp->rcv_scale.
		 */
		int32_t adv, oldwin = 0;
		adv = imin(recwin, (int)TCP_MAXWIN << tp->rcv_scale) -
		    (tp->rcv_adv - tp->rcv_nxt);

		if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt)) {
			oldwin = tp->rcv_adv - tp->rcv_nxt;
		}

		if (tcp_ack_strategy == TCP_ACK_STRATEGY_LEGACY) {
			if (adv >= (int32_t) (2 * tp->t_maxseg)) {
				/*
				 * Update only if the resulting scaled value of
				 * the window changed, or if there is a change in
				 * the sequence since the last ack. This avoids
				 * what appears as dupe ACKS (see rdar://5640997)
				 *
				 * If streaming is detected avoid sending too many
				 * window updates. We will depend on the delack
				 * timer to send a window update when needed.
				 *
				 * If there is more data to read, don't send an ACK.
				 * Otherwise we will end up sending many ACKs if the
				 * application is doing micro-reads.
				 */
				if (!(tp->t_flags & TF_STRETCHACK) &&
				    (tp->last_ack_sent != tp->rcv_nxt ||
				    ((oldwin + adv) >> tp->rcv_scale) >
				    (oldwin >> tp->rcv_scale))) {
					goto send;
				}
			}
		} else {
			if (adv >= (int32_t) (2 * tp->t_maxseg)) {
				/*
				 * ACK every second full-sized segment, if the
				 * ACK is advancing or the window becomes bigger
				 */
				if (so->so_rcv.sb_cc < so->so_rcv.sb_lowat &&
				    (tp->last_ack_sent != tp->rcv_nxt ||
				    ((oldwin + adv) >> tp->rcv_scale) >
				    (oldwin >> tp->rcv_scale))) {
					goto send;
				}
			} else if (tp->t_flags & TF_DELACK) {
				/*
				 * If we delayed the ACK and the window
				 * is not advancing by a lot (< 2MSS), ACK
				 * immediately if the last incoming packet had
				 * the push flag set and we emptied the buffer.
				 *
				 * This takes care of a sender doing small
				 * repeated writes with Nagle enabled.
				 */
				if (so->so_rcv.sb_cc == 0 &&
				    tp->last_ack_sent != tp->rcv_nxt &&
				    (tp->t_flagsext & TF_LAST_IS_PSH)) {
					goto send;
				}
			}
		}
		if (4 * adv >= (int32_t) so->so_rcv.sb_hiwat) {
			goto send;
		}

		/*
		 * Make sure that the delayed ack timer is set if
		 * we delayed sending a window update because of
		 * streaming detection.
		 */
		if (tcp_ack_strategy == TCP_ACK_STRATEGY_LEGACY &&
		    (tp->t_flags & TF_STRETCHACK) &&
		    !(tp->t_flags & TF_DELACK)) {
			tp->t_flags |= TF_DELACK;
			tp->t_timer[TCPT_DELACK] =
			    OFFSET_FROM_START(tp, tcp_delack);
		}
	}

	/*
	 * Send if we owe the peer an ACK, RST, SYN, or urgent data. ACKNOW
	 * is also a catch-all for the retransmit timer timeout case.
	 */
	if (tp->t_flags & TF_ACKNOW) {
		if (tp->t_forced_acks > 0) {
			tp->t_forced_acks--;
		}
		goto send;
	}
	if ((flags & TH_RST) || (flags & TH_SYN)) {
		goto send;
	}
	if (SEQ_GT(tp->snd_up, tp->snd_una)) {
		goto send;
	}
#if MPTCP
	if (mptcp_acknow) {
		goto send;
	}
#endif /* MPTCP */
	/*
	 * If our state indicates that FIN should be sent
	 * and we have not yet done so, then we need to send.
	 */
	if ((flags & TH_FIN) &&
	    (!(tp->t_flags & TF_SENTFIN) || tp->snd_nxt == tp->snd_una)) {
		goto send;
	}
	/*
	 * In SACK, it is possible for tcp_output to fail to send a segment
	 * after the retransmission timer has been turned off.  Make sure
	 * that the retransmission timer is set.
	 */
	if (SACK_ENABLED(tp) && (tp->t_state >= TCPS_ESTABLISHED) &&
	    SEQ_GT(tp->snd_max, tp->snd_una) &&
	    tp->t_timer[TCPT_REXMT] == 0 &&
	    tp->t_timer[TCPT_PERSIST] == 0) {
		tp->t_timer[TCPT_REXMT] = OFFSET_FROM_START(tp,
		    tp->t_rxtcur);
		goto just_return;
	}
	/*
	 * TCP window updates are not reliable, rather a polling protocol
	 * using ``persist'' packets is used to insure receipt of window
	 * updates.  The three ``states'' for the output side are:
	 *	idle			not doing retransmits or persists
	 *	persisting		to move a small or zero window
	 *	(re)transmitting	and thereby not persisting
	 *
	 * tp->t_timer[TCPT_PERSIST]
	 *	is set when we are in persist state.
	 * tp->t_force
	 *	is set when we are called to send a persist packet.
	 * tp->t_timer[TCPT_REXMT]
	 *	is set when we are retransmitting
	 * The output side is idle when both timers are zero.
	 *
	 * If send window is too small, there is data to transmit, and no
	 * retransmit or persist is pending, then go to persist state.
	 * If nothing happens soon, send when timer expires:
	 * if window is nonzero, transmit what we can,
	 * otherwise force out a byte.
	 */
	if (so->so_snd.sb_cc && tp->t_timer[TCPT_REXMT] == 0 &&
	    tp->t_timer[TCPT_PERSIST] == 0) {
		TCP_RESET_REXMT_STATE(tp);
		tcp_setpersist(tp);
	}
just_return:
	/*
	 * If there is no reason to send a segment, just return.
	 * but if there is some packets left in the packet list, send them now.
	 */
	while (inp->inp_sndinprog_cnt == 0 &&
	    tp->t_pktlist_head != NULL) {
		packetlist = tp->t_pktlist_head;
		packchain_listadd = tp->t_lastchain;
		packchain_sent++;
		TCP_PKTLIST_CLEAR(tp);

		error = tcp_ip_output(so, tp, packetlist,
		    packchain_listadd,
		    tp_inp_options, (so_options & SO_DONTROUTE),
		    (sack_rxmit || (sack_bytes_rxmt != 0)), isipv6);
	}
	/* tcp was closed while we were in ip; resume close */
	if (inp->inp_sndinprog_cnt == 0 &&
	    (tp->t_flags & TF_CLOSING)) {
		tp->t_flags &= ~TF_CLOSING;
		(void) tcp_close(tp);
	} else {
		tcp_check_timer_state(tp);
	}
	KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0, 0, 0, 0, 0);
	return 0;

send:
	/*
	 * Set TF_MAXSEGSNT flag if the segment size is greater than
	 * the max segment size.
	 */
	if (len > 0) {
		do_not_compress = TRUE;

		if (len >= tp->t_maxseg) {
			tp->t_flags |= TF_MAXSEGSNT;
		} else {
			tp->t_flags &= ~TF_MAXSEGSNT;
		}
	}
	/*
	 * Before ESTABLISHED, force sending of initial options
	 * unless TCP set not to do any options.
	 * NOTE: we assume that the IP/TCP header plus TCP options
	 * always fit in a single mbuf, leaving room for a maximum
	 * link header, i.e.
	 *	max_linkhdr + sizeof (struct tcpiphdr) + optlen <= MCLBYTES
	 */
	optlen = 0;
	if (isipv6) {
		hdrlen = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
	} else {
		hdrlen = sizeof(struct tcpiphdr);
	}
	if (flags & TH_SYN) {
		tp->snd_nxt = tp->iss;
		if ((tp->t_flags & TF_NOOPT) == 0) {
			u_short mss;

			opt[0] = TCPOPT_MAXSEG;
			opt[1] = TCPOLEN_MAXSEG;
			mss = htons((u_short) tcp_mssopt(tp));
			(void)memcpy(opt + 2, &mss, sizeof(mss));
			optlen = TCPOLEN_MAXSEG;

			if ((tp->t_flags & TF_REQ_SCALE) &&
			    ((flags & TH_ACK) == 0 ||
			    (tp->t_flags & TF_RCVD_SCALE))) {
				*((u_int32_t *)(void *)(opt + optlen)) = htonl(
					TCPOPT_NOP << 24 |
					        TCPOPT_WINDOW << 16 |
					        TCPOLEN_WINDOW << 8 |
					        tp->request_r_scale);
				optlen += 4;
			}
#if MPTCP
			if (mptcp_enable && (so->so_flags & SOF_MP_SUBFLOW)) {
				optlen = mptcp_setup_syn_opts(so, opt, optlen);
			}
#endif /* MPTCP */
		}
	}

	/*
	 * Send a timestamp and echo-reply if this is a SYN and our side
	 * wants to use timestamps (TF_REQ_TSTMP is set) or both our side
	 * and our peer have sent timestamps in our SYN's.
	 */
	if ((tp->t_flags & (TF_REQ_TSTMP | TF_NOOPT)) == TF_REQ_TSTMP &&
	    (flags & TH_RST) == 0 &&
	    ((flags & TH_ACK) == 0 ||
	    (tp->t_flags & TF_RCVD_TSTMP))) {
		u_int32_t *lp = (u_int32_t *)(void *)(opt + optlen);

		/* Form timestamp option as shown in appendix A of RFC 1323. */
		*lp++ = htonl(TCPOPT_TSTAMP_HDR);
		*lp++ = htonl(tcp_now);
		*lp   = htonl(tp->ts_recent);
		optlen += TCPOLEN_TSTAMP_APPA;
	}

	if (SACK_ENABLED(tp) && ((tp->t_flags & TF_NOOPT) == 0)) {
		/*
		 * Tack on the SACK permitted option *last*.
		 * And do padding of options after tacking this on.
		 * This is because of MSS, TS, WinScale and Signatures are
		 * all present, we have just 2 bytes left for the SACK
		 * permitted option, which is just enough.
		 */
		/*
		 * If this is the first SYN of connection (not a SYN
		 * ACK), include SACK permitted option.  If this is a
		 * SYN ACK, include SACK permitted option if peer has
		 * already done so. This is only for active connect,
		 * since the syncache takes care of the passive connect.
		 */
		if ((flags & TH_SYN) &&
		    (!(flags & TH_ACK) || (tp->t_flags & TF_SACK_PERMIT))) {
			u_char *bp;
			bp = (u_char *)opt + optlen;

			*bp++ = TCPOPT_SACK_PERMITTED;
			*bp++ = TCPOLEN_SACK_PERMITTED;
			optlen += TCPOLEN_SACK_PERMITTED;
		}
	}
#if MPTCP
	if (so->so_flags & SOF_MP_SUBFLOW) {
		/*
		 * Its important to piggyback acks with data as ack only packets
		 * may get lost and data packets that don't send Data ACKs
		 * still advance the subflow level ACK and therefore make it
		 * hard for the remote end to recover in low cwnd situations.
		 */
		if (len != 0) {
			tp->t_mpflags |= (TMPF_SEND_DSN |
			    TMPF_MPTCP_ACKNOW);
		} else {
			tp->t_mpflags |= TMPF_MPTCP_ACKNOW;
		}
		optlen = mptcp_setup_opts(tp, off, &opt[0], optlen, flags,
		    len, &mptcp_acknow, &do_not_compress);
		tp->t_mpflags &= ~TMPF_SEND_DSN;
	}
#endif /* MPTCP */

	if (tfo_enabled(tp) && !(tp->t_flags & TF_NOOPT) &&
	    (flags & (TH_SYN | TH_ACK)) == TH_SYN) {
		optlen += tcp_tfo_write_cookie(tp, optlen, len, opt);
	}

	if (tfo_enabled(tp) &&
	    (flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) &&
	    (tp->t_tfo_flags & TFO_F_OFFER_COOKIE)) {
		optlen += tcp_tfo_write_cookie_rep(tp, optlen, opt);
	}

	if (SACK_ENABLED(tp) && ((tp->t_flags & TF_NOOPT) == 0)) {
		/*
		 * Send SACKs if necessary.  This should be the last
		 * option processed.  Only as many SACKs are sent as
		 * are permitted by the maximum options size.
		 *
		 * In general, SACK blocks consume 8*n+2 bytes.
		 * So a full size SACK blocks option is 34 bytes
		 * (to generate 4 SACK blocks).  At a minimum,
		 * we need 10 bytes (to generate 1 SACK block).
		 * If TCP Timestamps (12 bytes) and TCP Signatures
		 * (18 bytes) are both present, we'll just have
		 * 10 bytes for SACK options 40 - (12 + 18).
		 */
		if (TCPS_HAVEESTABLISHED(tp->t_state) &&
		    (tp->t_flags & TF_SACK_PERMIT) &&
		    (tp->rcv_numsacks > 0 || TCP_SEND_DSACK_OPT(tp)) &&
		    MAX_TCPOPTLEN - optlen - 2 >= TCPOLEN_SACK) {
			int nsack, padlen;
			u_char *bp = (u_char *)opt + optlen;
			u_int32_t *lp;

			nsack = (MAX_TCPOPTLEN - optlen - 2) / TCPOLEN_SACK;
			nsack = min(nsack, (tp->rcv_numsacks +
			    (TCP_SEND_DSACK_OPT(tp) ? 1 : 0)));
			sackoptlen = (2 + nsack * TCPOLEN_SACK);
			VERIFY(sackoptlen < UINT8_MAX);

			/*
			 * First we need to pad options so that the
			 * SACK blocks can start at a 4-byte boundary
			 * (sack option and length are at a 2 byte offset).
			 */
			padlen = (MAX_TCPOPTLEN - optlen - sackoptlen) % 4;
			optlen += padlen;
			while (padlen-- > 0) {
				*bp++ = TCPOPT_NOP;
			}

			tcpstat.tcps_sack_send_blocks++;
			*bp++ = TCPOPT_SACK;
			*bp++ = (uint8_t)sackoptlen;
			lp = (u_int32_t *)(void *)bp;

			/*
			 * First block of SACK option should represent
			 * DSACK. Prefer to send SACK information if there
			 * is space for only one SACK block. This will
			 * allow for faster recovery.
			 */
			if (TCP_SEND_DSACK_OPT(tp) && nsack > 0 &&
			    (tp->rcv_numsacks == 0 || nsack > 1)) {
				*lp++ = htonl(tp->t_dsack_lseq);
				*lp++ = htonl(tp->t_dsack_rseq);
				tcpstat.tcps_dsack_sent++;
				tp->t_dsack_sent++;
				nsack--;
			}
			VERIFY(nsack == 0 || tp->rcv_numsacks >= nsack);
			for (i = 0; i < nsack; i++) {
				struct sackblk sack = tp->sackblks[i];
				*lp++ = htonl(sack.start);
				*lp++ = htonl(sack.end);
			}
			optlen += sackoptlen;
		}
	}

	/* Pad TCP options to a 4 byte boundary */
	if (optlen < MAX_TCPOPTLEN && (optlen % sizeof(u_int32_t))) {
		int pad = sizeof(u_int32_t) - (optlen % sizeof(u_int32_t));
		u_char *bp = (u_char *)opt + optlen;

		optlen += pad;
		while (pad) {
			*bp++ = TCPOPT_EOL;
			pad--;
		}
	}

	/*
	 * RFC 3168 states that:
	 * - If you ever sent an ECN-setup SYN/SYN-ACK you must be prepared
	 * to handle the TCP ECE flag, even if you also later send a
	 * non-ECN-setup SYN/SYN-ACK.
	 * - If you ever send a non-ECN-setup SYN/SYN-ACK, you must not set
	 * the ip ECT flag.
	 *
	 * It is not clear how the ECE flag would ever be set if you never
	 * set the IP ECT flag on outbound packets. All the same, we use
	 * the TE_SETUPSENT to indicate that we have committed to handling
	 * the TCP ECE flag correctly. We use the TE_SENDIPECT to indicate
	 * whether or not we should set the IP ECT flag on outbound packet
	 *
	 * For a SYN-ACK, send an ECN setup SYN-ACK
	 */
	if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) &&
	    (tp->ecn_flags & TE_ENABLE_ECN)) {
		if (tp->ecn_flags & TE_SETUPRECEIVED) {
			if (tcp_send_ecn_flags_on_syn(tp)) {
				/*
				 * Setting TH_ECE makes this an ECN-setup
				 * SYN-ACK
				 */
				flags |= TH_ECE;

				/*
				 * Record that we sent the ECN-setup and
				 * default to setting IP ECT.
				 */
				tp->ecn_flags |= (TE_SETUPSENT | TE_SENDIPECT);
				tcpstat.tcps_ecn_server_setup++;
				tcpstat.tcps_ecn_server_success++;
			} else {
				/*
				 * We sent an ECN-setup SYN-ACK but it was
				 * dropped. Fallback to non-ECN-setup
				 * SYN-ACK and clear flag to indicate that
				 * we should not send data with IP ECT set
				 *
				 * Pretend we didn't receive an
				 * ECN-setup SYN.
				 *
				 * We already incremented the counter
				 * assuming that the ECN setup will
				 * succeed. Decrementing here
				 * tcps_ecn_server_success to correct it.
				 */
				if (tp->ecn_flags & TE_SETUPSENT) {
					tcpstat.tcps_ecn_lost_synack++;
					tcpstat.tcps_ecn_server_success--;
					tp->ecn_flags |= TE_LOST_SYNACK;
				}

				tp->ecn_flags &=
				    ~(TE_SETUPRECEIVED | TE_SENDIPECT |
				    TE_SENDCWR);
			}
		}
	} else if ((flags & (TH_SYN | TH_ACK)) == TH_SYN &&
	    (tp->ecn_flags & TE_ENABLE_ECN)) {
		if (tcp_send_ecn_flags_on_syn(tp)) {
			/*
			 * Setting TH_ECE and TH_CWR makes this an
			 * ECN-setup SYN
			 */
			flags |= (TH_ECE | TH_CWR);
			tcpstat.tcps_ecn_client_setup++;
			tp->ecn_flags |= TE_CLIENT_SETUP;

			/*
			 * Record that we sent the ECN-setup and default to
			 * setting IP ECT.
			 */
			tp->ecn_flags |= (TE_SETUPSENT | TE_SENDIPECT);
		} else {
			/*
			 * We sent an ECN-setup SYN but it was dropped.
			 * Fall back to non-ECN and clear flag indicating
			 * we should send data with IP ECT set.
			 */
			if (tp->ecn_flags & TE_SETUPSENT) {
				tcpstat.tcps_ecn_lost_syn++;
				tp->ecn_flags |= TE_LOST_SYN;
			}
			tp->ecn_flags &= ~TE_SENDIPECT;
		}
	}

	/*
	 * Check if we should set the TCP CWR flag.
	 * CWR flag is sent when we reduced the congestion window because
	 * we received a TCP ECE or we performed a fast retransmit. We
	 * never set the CWR flag on retransmitted packets. We only set
	 * the CWR flag on data packets. Pure acks don't have this set.
	 */
	if ((tp->ecn_flags & TE_SENDCWR) != 0 && len != 0 &&
	    !SEQ_LT(tp->snd_nxt, tp->snd_max) && !sack_rxmit) {
		flags |= TH_CWR;
		tp->ecn_flags &= ~TE_SENDCWR;
	}

	/*
	 * Check if we should set the TCP ECE flag.
	 */
	if ((tp->ecn_flags & TE_SENDECE) != 0 && len == 0) {
		flags |= TH_ECE;
		tcpstat.tcps_ecn_sent_ece++;
	}


	hdrlen += optlen;

	/* Reset DSACK sequence numbers */
	tp->t_dsack_lseq = 0;
	tp->t_dsack_rseq = 0;

	if (isipv6) {
		ipoptlen = ip6_optlen(inp);
	} else {
		if (tp_inp_options) {
			ipoptlen = tp_inp_options->m_len -
			    offsetof(struct ipoption, ipopt_list);
		} else {
			ipoptlen = 0;
		}
	}
#if IPSEC
	ipoptlen += ipsec_optlen;
#endif

	/*
	 * Adjust data length if insertion of options will
	 * bump the packet length beyond the t_maxopd length.
	 * Clear the FIN bit because we cut off the tail of
	 * the segment.
	 *
	 * When doing TSO limit a burst to TCP_MAXWIN minus the
	 * IP, TCP and Options length to keep ip->ip_len from
	 * overflowing.  Prevent the last segment from being
	 * fractional thus making them all equal sized and set
	 * the flag to continue sending.  TSO is disabled when
	 * IP options or IPSEC are present.
	 */
	if (len + optlen + ipoptlen > tp->t_maxopd) {
		/*
		 * If there is still more to send,
		 * don't close the connection.
		 */
		flags &= ~TH_FIN;
		if (tso) {
			int32_t tso_maxlen;

			tso_maxlen = tp->tso_max_segment_size ?
			    tp->tso_max_segment_size : TCP_MAXWIN;

			if (len > tso_maxlen - hdrlen - optlen) {
				len = tso_maxlen - hdrlen - optlen;
				sendalot = 1;
			} else if (tp->t_flags & TF_NEEDFIN) {
				sendalot = 1;
			}

			if (len % (tp->t_maxopd - optlen) != 0) {
				len = len - (len % (tp->t_maxopd - optlen));
				sendalot = 1;
			}
		} else {
			len = tp->t_maxopd - optlen - ipoptlen;
			sendalot = 1;
		}
	}

	if (max_linkhdr + hdrlen > MCLBYTES) {
		panic("tcphdr too big");
	}

	/* Check if there is enough data in the send socket
	 * buffer to start measuring bandwidth
	 */
	if ((tp->t_flagsext & TF_MEASURESNDBW) != 0 &&
	    (tp->t_bwmeas != NULL) &&
	    (tp->t_flagsext & TF_BWMEAS_INPROGRESS) == 0) {
		tp->t_bwmeas->bw_size = min(min(
			    (so->so_snd.sb_cc - (tp->snd_max - tp->snd_una)),
			    tp->snd_cwnd), tp->snd_wnd);
		if (tp->t_bwmeas->bw_minsize > 0 &&
		    tp->t_bwmeas->bw_size < tp->t_bwmeas->bw_minsize) {
			tp->t_bwmeas->bw_size = 0;
		}
		if (tp->t_bwmeas->bw_maxsize > 0) {
			tp->t_bwmeas->bw_size = min(tp->t_bwmeas->bw_size,
			    tp->t_bwmeas->bw_maxsize);
		}
		if (tp->t_bwmeas->bw_size > 0) {
			tp->t_flagsext |= TF_BWMEAS_INPROGRESS;
			tp->t_bwmeas->bw_start = tp->snd_max;
			tp->t_bwmeas->bw_ts = tcp_now;
		}
	}

	VERIFY(inp->inp_flowhash != 0);
	/*
	 * Grab a header mbuf, attaching a copy of data to
	 * be transmitted, and initialize the header from
	 * the template for sends on this connection.
	 */
	if (len) {
		/* Remember what the last head-of-line packet-size was */
		if (tp->t_pmtud_lastseg_size == 0 && tp->snd_nxt == tp->snd_una) {
			ASSERT(len + optlen + ipoptlen <= IP_MAXPACKET);
			tp->t_pmtud_lastseg_size = (uint16_t)(len + optlen + ipoptlen);
		}
		if ((tp->t_flagsext & TF_FORCE) && len == 1) {
			tcpstat.tcps_sndprobe++;
		} else if (SEQ_LT(tp->snd_nxt, tp->snd_max) || sack_rxmit) {
			tcpstat.tcps_sndrexmitpack++;
			tcpstat.tcps_sndrexmitbyte += len;
			if (nstat_collect) {
				nstat_route_tx(inp->inp_route.ro_rt, 1,
				    len, NSTAT_TX_FLAG_RETRANSMIT);
				INP_ADD_STAT(inp, cell, wifi, wired,
				    txpackets, 1);
				INP_ADD_STAT(inp, cell, wifi, wired,
				    txbytes, len);
				tp->t_stat.txretransmitbytes += len;
				tp->t_stat.rxmitpkts++;
			}
		} else {
			tcpstat.tcps_sndpack++;
			tcpstat.tcps_sndbyte += len;

			if (nstat_collect) {
				INP_ADD_STAT(inp, cell, wifi, wired,
				    txpackets, 1);
				INP_ADD_STAT(inp, cell, wifi, wired,
				    txbytes, len);
			}
			inp_decr_sndbytes_unsent(so, len);
		}
		inp_set_activity_bitmap(inp);
#if MPTCP
		if (tp->t_mpflags & TMPF_MPTCP_TRUE) {
			tcpstat.tcps_mp_sndpacks++;
			tcpstat.tcps_mp_sndbytes += len;
		}
#endif /* MPTCP */
		/*
		 * try to use the new interface that allocates all
		 * the necessary mbuf hdrs under 1 mbuf lock and
		 * avoids rescanning the socket mbuf list if
		 * certain conditions are met.  This routine can't
		 * be used in the following cases...
		 * 1) the protocol headers exceed the capacity of
		 * of a single mbuf header's data area (no cluster attached)
		 * 2) the length of the data being transmitted plus
		 * the protocol headers fits into a single mbuf header's
		 * data area (no cluster attached)
		 */
		m = NULL;

		/* minimum length we are going to allocate */
		allocated_len = MHLEN;
		if (MHLEN < hdrlen + max_linkhdr) {
			MGETHDR(m, M_DONTWAIT, MT_HEADER);
			if (m == NULL) {
				error = ENOBUFS;
				goto out;
			}
			MCLGET(m, M_DONTWAIT);
			if ((m->m_flags & M_EXT) == 0) {
				m_freem(m);
				error = ENOBUFS;
				goto out;
			}
			m->m_data += max_linkhdr;
			m->m_len = hdrlen;
			allocated_len = MCLBYTES;
		}
		if (len <= allocated_len - hdrlen - max_linkhdr) {
			if (m == NULL) {
				VERIFY(allocated_len <= MHLEN);
				MGETHDR(m, M_DONTWAIT, MT_HEADER);
				if (m == NULL) {
					error = ENOBUFS;
					goto out;
				}
				m->m_data += max_linkhdr;
				m->m_len = hdrlen;
			}
			/* makes sure we still have data left to be sent at this point */
			if (so->so_snd.sb_mb == NULL || off < 0) {
				if (m != NULL) {
					m_freem(m);
				}
				error = 0; /* should we return an error? */
				goto out;
			}
			m_copydata(so->so_snd.sb_mb, off, (int) len,
			    mtod(m, caddr_t) + hdrlen);
			m->m_len += len;
		} else {
			uint32_t copymode;
			/*
			 * Retain packet header metadata at the socket
			 * buffer if this is is an MPTCP subflow,
			 * otherwise move it.
			 */
			copymode = M_COPYM_MOVE_HDR;
#if MPTCP
			if (so->so_flags & SOF_MP_SUBFLOW) {
				copymode = M_COPYM_NOOP_HDR;
			}
#endif /* MPTCP */
			if (m != NULL) {
				m->m_next = m_copym_mode(so->so_snd.sb_mb,
				    off, (int)len, M_DONTWAIT, copymode);
				if (m->m_next == NULL) {
					(void) m_free(m);
					error = ENOBUFS;
					goto out;
				}
			} else {
				/*
				 * make sure we still have data left
				 * to be sent at this point
				 */
				if (so->so_snd.sb_mb == NULL) {
					error = 0; /* should we return an error? */
					goto out;
				}

				/*
				 * m_copym_with_hdrs will always return the
				 * last mbuf pointer and the offset into it that
				 * it acted on to fullfill the current request,
				 * whether a valid 'hint' was passed in or not.
				 */
				if ((m = m_copym_with_hdrs(so->so_snd.sb_mb,
				    off, len, M_DONTWAIT, NULL, NULL,
				    copymode)) == NULL) {
					error = ENOBUFS;
					goto out;
				}
				m->m_data += max_linkhdr;
				m->m_len = hdrlen;
			}
		}
		/*
		 * If we're sending everything we've got, set PUSH.
		 * (This will keep happy those implementations which only
		 * give data to the user when a buffer fills or
		 * a PUSH comes in.)
		 *
		 * On SYN-segments we should not add the PUSH-flag.
		 */
		if (off + len == so->so_snd.sb_cc && !(flags & TH_SYN)) {
			flags |= TH_PUSH;
		}
	} else {
		if (tp->t_flags & TF_ACKNOW) {
			tcpstat.tcps_sndacks++;
		} else if (flags & (TH_SYN | TH_FIN | TH_RST)) {
			tcpstat.tcps_sndctrl++;
		} else if (SEQ_GT(tp->snd_up, tp->snd_una)) {
			tcpstat.tcps_sndurg++;
		} else {
			tcpstat.tcps_sndwinup++;
		}

		MGETHDR(m, M_DONTWAIT, MT_HEADER);      /* MAC-OK */
		if (m == NULL) {
			error = ENOBUFS;
			goto out;
		}
		if (MHLEN < (hdrlen + max_linkhdr)) {
			MCLGET(m, M_DONTWAIT);
			if ((m->m_flags & M_EXT) == 0) {
				m_freem(m);
				error = ENOBUFS;
				goto out;
			}
		}
		m->m_data += max_linkhdr;
		m->m_len = hdrlen;
	}
	m->m_pkthdr.rcvif = 0;

	/* Any flag other than pure-ACK: Do not compress! */
	if (flags & ~(TH_ACK)) {
		do_not_compress = TRUE;
	}

	if (tp->rcv_scale == 0) {
		do_not_compress = TRUE;
	}

	if (do_not_compress || (tcp_do_ack_compression == 1 && !cell) || __improbable(!tcp_do_ack_compression)) {
		m->m_pkthdr.comp_gencnt = 0;
	} else {
		if (TSTMP_LT(tp->t_comp_lastinc + tcp_ack_compression_rate, tcp_now)) {
			tp->t_comp_gencnt++;
			/* 0 means no compression, thus jump this */
			if (tp->t_comp_gencnt <= TCP_ACK_COMPRESSION_DUMMY) {
				tp->t_comp_gencnt = TCP_ACK_COMPRESSION_DUMMY + 1;
			}
			tp->t_comp_lastinc = tcp_now;
		}
		m->m_pkthdr.comp_gencnt = tp->t_comp_gencnt;
	}

	if (isipv6) {
		ip6 = mtod(m, struct ip6_hdr *);
		th = (struct tcphdr *)(void *)(ip6 + 1);
		tcp_fillheaders(tp, ip6, th);
		if ((tp->ecn_flags & TE_SENDIPECT) != 0 && len &&
		    !SEQ_LT(tp->snd_nxt, tp->snd_max) && !sack_rxmit) {
			ip6->ip6_flow |= htonl(IPTOS_ECN_ECT0 << 20);
		}
		svc_flags |= PKT_SCF_IPV6;
#if PF_ECN
		m_pftag(m)->pftag_hdr = (void *)ip6;
		m_pftag(m)->pftag_flags |= PF_TAG_HDR_INET6;
#endif /* PF_ECN */
	} else {
		ip = mtod(m, struct ip *);
		th = (struct tcphdr *)(void *)(ip + 1);
		/* this picks up the pseudo header (w/o the length) */
		tcp_fillheaders(tp, ip, th);
		if ((tp->ecn_flags & TE_SENDIPECT) != 0 && len &&
		    !SEQ_LT(tp->snd_nxt, tp->snd_max) &&
		    !sack_rxmit && !(flags & TH_SYN)) {
			ip->ip_tos |= IPTOS_ECN_ECT0;
		}
#if PF_ECN
		m_pftag(m)->pftag_hdr = (void *)ip;
		m_pftag(m)->pftag_flags |= PF_TAG_HDR_INET;
#endif /* PF_ECN */
	}

	/*
	 * Fill in fields, remembering maximum advertised
	 * window for use in delaying messages about window sizes.
	 * If resending a FIN, be sure not to use a new sequence number.
	 */
	if ((flags & TH_FIN) && (tp->t_flags & TF_SENTFIN) &&
	    tp->snd_nxt == tp->snd_max) {
		tp->snd_nxt--;
	}
	/*
	 * If we are doing retransmissions, then snd_nxt will
	 * not reflect the first unsent octet.  For ACK only
	 * packets, we do not want the sequence number of the
	 * retransmitted packet, we want the sequence number
	 * of the next unsent octet.  So, if there is no data
	 * (and no SYN or FIN), use snd_max instead of snd_nxt
	 * when filling in ti_seq.  But if we are in persist
	 * state, snd_max might reflect one byte beyond the
	 * right edge of the window, so use snd_nxt in that
	 * case, since we know we aren't doing a retransmission.
	 * (retransmit and persist are mutually exclusive...)
	 *
	 * Note the state of this retransmit segment to detect spurious
	 * retransmissions.
	 */
	if (sack_rxmit == 0) {
		if (len || (flags & (TH_SYN | TH_FIN)) ||
		    tp->t_timer[TCPT_PERSIST]) {
			th->th_seq = htonl(tp->snd_nxt);
			if (len > 0) {
				m->m_pkthdr.tx_start_seq = tp->snd_nxt;
				m->m_pkthdr.pkt_flags |= PKTF_START_SEQ;
			}
			if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
				if (SACK_ENABLED(tp) && len > 1) {
					tcp_rxtseg_insert(tp, tp->snd_nxt,
					    (tp->snd_nxt + len - 1));
				}
				if (len > 0) {
					m->m_pkthdr.pkt_flags |=
					    PKTF_TCP_REXMT;
				}
			}
		} else {
			th->th_seq = htonl(tp->snd_max);
		}
	} else {
		th->th_seq = htonl(p->rxmit);
		if (len > 0) {
			m->m_pkthdr.pkt_flags |=
			    (PKTF_TCP_REXMT | PKTF_START_SEQ);
			m->m_pkthdr.tx_start_seq = p->rxmit;
		}
		tcp_rxtseg_insert(tp, p->rxmit, (p->rxmit + len - 1));
		p->rxmit += len;
		tp->sackhint.sack_bytes_rexmit += len;
	}
	th->th_ack = htonl(tp->rcv_nxt);
	tp->last_ack_sent = tp->rcv_nxt;
	if (optlen) {
		bcopy(opt, th + 1, optlen);
		th->th_off = (sizeof(struct tcphdr) + optlen) >> 2;
	}
	th->th_flags = flags;
	th->th_win = htons((u_short) (recwin >> tp->rcv_scale));
	tp->t_last_recwin = recwin;
	if (!(so->so_flags & SOF_MP_SUBFLOW)) {
		if (recwin > 0 && SEQ_LT(tp->rcv_adv, tp->rcv_nxt + recwin)) {
			tp->rcv_adv = tp->rcv_nxt + recwin;
		}
	} else {
		struct mptcb *mp_tp = tptomptp(tp);
		if (recwin > 0) {
			tp->rcv_adv = tp->rcv_nxt + recwin;
		}

		if (recwin > 0 && MPTCP_SEQ_LT(mp_tp->mpt_rcvadv, mp_tp->mpt_rcvnxt + recwin)) {
			mp_tp->mpt_rcvadv = mp_tp->mpt_rcvnxt + recwin;
		}
	}

	/*
	 * Adjust the RXWIN0SENT flag - indicate that we have advertised
	 * a 0 window.  This may cause the remote transmitter to stall.  This
	 * flag tells soreceive() to disable delayed acknowledgements when
	 * draining the buffer.  This can occur if the receiver is attempting
	 * to read more data then can be buffered prior to transmitting on
	 * the connection.
	 */
	if (th->th_win == 0) {
		tp->t_flags |= TF_RXWIN0SENT;
	} else {
		tp->t_flags &= ~TF_RXWIN0SENT;
	}

	if (SEQ_GT(tp->snd_up, tp->snd_nxt)) {
		th->th_urp = htons((u_short)(tp->snd_up - tp->snd_nxt));
		th->th_flags |= TH_URG;
	} else {
		/*
		 * If no urgent pointer to send, then we pull
		 * the urgent pointer to the left edge of the send window
		 * so that it doesn't drift into the send window on sequence
		 * number wraparound.
		 */
		tp->snd_up = tp->snd_una;               /* drag it along */
	}

	/*
	 * Put TCP length in extended header, and then
	 * checksum extended header and data.
	 */
	m->m_pkthdr.len = hdrlen + len; /* in6_cksum() need this */

	/*
	 * If this is potentially the last packet on the stream, then mark
	 * it in order to enable some optimizations in the underlying
	 * layers
	 */
	if (tp->t_state != TCPS_ESTABLISHED &&
	    (tp->t_state == TCPS_CLOSING || tp->t_state == TCPS_TIME_WAIT
	    || tp->t_state == TCPS_LAST_ACK || (th->th_flags & TH_RST))) {
		m->m_pkthdr.pkt_flags |= PKTF_LAST_PKT;
	}

	if (isipv6) {
		/*
		 * ip6_plen is not need to be filled now, and will be filled
		 * in ip6_output.
		 */
		m->m_pkthdr.csum_flags = CSUM_TCPIPV6;
		m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
		if (len + optlen) {
			th->th_sum = in_addword(th->th_sum,
			    htons((u_short)(optlen + len)));
		}
	} else {
		m->m_pkthdr.csum_flags = CSUM_TCP;
		m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
		if (len + optlen) {
			th->th_sum = in_addword(th->th_sum,
			    htons((u_short)(optlen + len)));
		}
	}

	/*
	 * Enable TSO and specify the size of the segments.
	 * The TCP pseudo header checksum is always provided.
	 */
	if (tso) {
		if (isipv6) {
			m->m_pkthdr.csum_flags |= CSUM_TSO_IPV6;
		} else {
			m->m_pkthdr.csum_flags |= CSUM_TSO_IPV4;
		}

		m->m_pkthdr.tso_segsz = tp->t_maxopd - optlen;
	} else {
		m->m_pkthdr.tso_segsz = 0;
	}

	/*
	 * In transmit state, time the transmission and arrange for
	 * the retransmit.  In persist state, just set snd_max.
	 */
	if (!(tp->t_flagsext & TF_FORCE)
	    || tp->t_timer[TCPT_PERSIST] == 0) {
		tcp_seq startseq = tp->snd_nxt;

		/*
		 * Advance snd_nxt over sequence space of this segment.
		 */
		if (flags & (TH_SYN | TH_FIN)) {
			if (flags & TH_SYN) {
				tp->snd_nxt++;
			}
			if ((flags & TH_FIN) &&
			    !(tp->t_flags & TF_SENTFIN)) {
				tp->snd_nxt++;
				tp->t_flags |= TF_SENTFIN;
			}
		}
		if (sack_rxmit) {
			goto timer;
		}
		if (sack_rescue_rxt == TRUE) {
			tp->snd_nxt = old_snd_nxt;
			sack_rescue_rxt = FALSE;
			tcpstat.tcps_pto_in_recovery++;
		} else {
			tp->snd_nxt += len;
		}
		if (SEQ_GT(tp->snd_nxt, tp->snd_max)) {
			tp->snd_max = tp->snd_nxt;
			tp->t_sndtime = tcp_now;
			/*
			 * Time this transmission if not a retransmission and
			 * not currently timing anything.
			 */
			if (tp->t_rtttime == 0) {
				tp->t_rtttime = tcp_now;
				tp->t_rtseq = startseq;
				tcpstat.tcps_segstimed++;

				/* update variables related to pipe ack */
				tp->t_pipeack_lastuna = tp->snd_una;
			}
		}

		/*
		 * Set retransmit timer if not currently set,
		 * and not doing an ack or a keep-alive probe.
		 */
timer:
		if (tp->t_timer[TCPT_REXMT] == 0 &&
		    ((sack_rxmit && tp->snd_nxt != tp->snd_max) ||
		    tp->snd_nxt != tp->snd_una || (flags & TH_FIN))) {
			if (tp->t_timer[TCPT_PERSIST]) {
				tp->t_timer[TCPT_PERSIST] = 0;
				tp->t_persist_stop = 0;
				TCP_RESET_REXMT_STATE(tp);
			}
			tp->t_timer[TCPT_REXMT] =
			    OFFSET_FROM_START(tp, tp->t_rxtcur);
		}

		/*
		 * Set tail loss probe timeout if new data is being
		 * transmitted. This will be supported only when
		 * SACK option is enabled on a connection.
		 *
		 * Every time new data is sent PTO will get reset.
		 */
		if (tcp_enable_tlp && len != 0 && tp->t_state == TCPS_ESTABLISHED &&
		    SACK_ENABLED(tp) && !IN_FASTRECOVERY(tp) &&
		    tp->snd_nxt == tp->snd_max &&
		    SEQ_GT(tp->snd_nxt, tp->snd_una) &&
		    tp->t_rxtshift == 0 &&
		    (tp->t_flagsext & (TF_SENT_TLPROBE | TF_PKTS_REORDERED)) == 0) {
			uint32_t pto, srtt;

			if (tcp_do_better_lr) {
				srtt = tp->t_srtt >> TCP_RTT_SHIFT;
				pto = 2 * srtt;
				if ((tp->snd_max - tp->snd_una) <= tp->t_maxseg) {
					pto += tcp_delack;
				} else {
					pto += 2;
				}
			} else {
				/*
				 * Using SRTT alone to set PTO can cause spurious
				 * retransmissions on wireless networks where there
				 * is a lot of variance in RTT. Taking variance
				 * into account will avoid this.
				 */
				srtt = tp->t_srtt >> TCP_RTT_SHIFT;
				pto = ((TCP_REXMTVAL(tp)) * 3) >> 1;
				pto = max(2 * srtt, pto);
				if ((tp->snd_max - tp->snd_una) == tp->t_maxseg) {
					pto = max(pto,
					    (((3 * pto) >> 2) + tcp_delack * 2));
				} else {
					pto = max(10, pto);
				}
			}

			/* if RTO is less than PTO, choose RTO instead */
			if (tp->t_rxtcur < pto) {
				pto = tp->t_rxtcur;
			}

			tp->t_timer[TCPT_PTO] = OFFSET_FROM_START(tp, pto);
		}
	} else {
		/*
		 * Persist case, update snd_max but since we are in
		 * persist mode (no window) we do not update snd_nxt.
		 */
		int xlen = len;
		if (flags & TH_SYN) {
			++xlen;
		}
		if ((flags & TH_FIN) &&
		    !(tp->t_flags & TF_SENTFIN)) {
			++xlen;
			tp->t_flags |= TF_SENTFIN;
		}
		if (SEQ_GT(tp->snd_nxt + xlen, tp->snd_max)) {
			tp->snd_max = tp->snd_nxt + len;
			tp->t_sndtime = tcp_now;
		}
	}

#if TCPDEBUG
	/*
	 * Trace.
	 */
	if (so_options & SO_DEBUG) {
		tcp_trace(TA_OUTPUT, tp->t_state, tp, mtod(m, void *), th, 0);
	}
#endif

	/*
	 * Fill in IP length and desired time to live and
	 * send to IP level.  There should be a better way
	 * to handle ttl and tos; we could keep them in
	 * the template, but need a way to checksum without them.
	 */
	/*
	 * m->m_pkthdr.len should have been set before cksum calcuration,
	 * because in6_cksum() need it.
	 */
	if (isipv6) {
		/*
		 * we separately set hoplimit for every segment, since the
		 * user might want to change the value via setsockopt.
		 * Also, desired default hop limit might be changed via
		 * Neighbor Discovery.
		 */
		ip6->ip6_hlim = in6_selecthlim(inp, inp->in6p_route.ro_rt ?
		    inp->in6p_route.ro_rt->rt_ifp : NULL);

		/* TODO: IPv6 IP6TOS_ECT bit on */
		KERNEL_DEBUG(DBG_LAYER_BEG,
		    ((inp->inp_fport << 16) | inp->inp_lport),
		    (((inp->in6p_laddr.s6_addr16[0] & 0xffff) << 16) |
		    (inp->in6p_faddr.s6_addr16[0] & 0xffff)),
		    sendalot, 0, 0);
	} else {
		ASSERT(m->m_pkthdr.len <= IP_MAXPACKET);
		ip->ip_len = (u_short)m->m_pkthdr.len;
		ip->ip_ttl = inp->inp_ip_ttl;   /* XXX */
		ip->ip_tos |= (inp->inp_ip_tos & ~IPTOS_ECN_MASK);/* XXX */
		KERNEL_DEBUG(DBG_LAYER_BEG,
		    ((inp->inp_fport << 16) | inp->inp_lport),
		    (((inp->inp_laddr.s_addr & 0xffff) << 16) |
		    (inp->inp_faddr.s_addr & 0xffff)), 0, 0, 0);
	}

	/*
	 * See if we should do MTU discovery.
	 * Look at the flag updated on the following criterias:
	 *	1) Path MTU discovery is authorized by the sysctl
	 *	2) The route isn't set yet (unlikely but could happen)
	 *	3) The route is up
	 *	4) the MTU is not locked (if it is, then discovery has been
	 *	   disabled for that route)
	 */
	if (!isipv6) {
		if (path_mtu_discovery && (tp->t_flags & TF_PMTUD)) {
			ip->ip_off |= IP_DF;
		}
	}

#if NECP
	{
		necp_kernel_policy_id policy_id;
		necp_kernel_policy_id skip_policy_id;
		u_int32_t route_rule_id;
		u_int32_t pass_flags;
		if (!necp_socket_is_allowed_to_send_recv(inp, NULL, 0, &policy_id, &route_rule_id, &skip_policy_id, &pass_flags)) {
			TCP_LOG_DROP_NECP(isipv6 ? (void *)ip6 : (void *)ip, th, tp, true);
			m_freem(m);
			error = EHOSTUNREACH;
			goto out;
		}
		necp_mark_packet_from_socket(m, inp, policy_id, route_rule_id, skip_policy_id, pass_flags);

		if (net_qos_policy_restricted != 0) {
			necp_socket_update_qos_marking(inp, inp->inp_route.ro_rt, route_rule_id);
		}
	}
#endif /* NECP */

#if IPSEC
	if (inp->inp_sp != NULL) {
		ipsec_setsocket(m, so);
	}
#endif /*IPSEC*/

	/*
	 * The socket is kept locked while sending out packets in ip_output, even if packet chaining is not active.
	 */
	lost = 0;

	/*
	 * Embed the flow hash in pkt hdr and mark the packet as
	 * capable of flow controlling
	 */
	m->m_pkthdr.pkt_flowsrc = FLOWSRC_INPCB;
	m->m_pkthdr.pkt_flowid = inp->inp_flowhash;
	m->m_pkthdr.pkt_flags |= (PKTF_FLOW_ID | PKTF_FLOW_LOCALSRC | PKTF_FLOW_ADV);
	m->m_pkthdr.pkt_proto = IPPROTO_TCP;
	m->m_pkthdr.tx_tcp_pid = so->last_pid;
	if (so->so_flags & SOF_DELEGATED) {
		m->m_pkthdr.tx_tcp_e_pid = so->e_pid;
	} else {
		m->m_pkthdr.tx_tcp_e_pid = 0;
	}

	m->m_nextpkt = NULL;

	if (inp->inp_last_outifp != NULL &&
	    !(inp->inp_last_outifp->if_flags & IFF_LOOPBACK)) {
		/* Hint to prioritize this packet if
		 * 1. if the packet has no data
		 * 2. the interface supports transmit-start model and did
		 *    not disable ACK prioritization.
		 * 3. Only ACK flag is set.
		 * 4. there is no outstanding data on this connection.
		 */
		if (len == 0 && (inp->inp_last_outifp->if_eflags & (IFEF_TXSTART | IFEF_NOACKPRI)) == IFEF_TXSTART) {
			if (th->th_flags == TH_ACK &&
			    tp->snd_una == tp->snd_max &&
			    tp->t_timer[TCPT_REXMT] == 0) {
				svc_flags |= PKT_SCF_TCP_ACK;
			}
			if (th->th_flags & TH_SYN) {
				svc_flags |= PKT_SCF_TCP_SYN;
			}
		}
		set_packet_service_class(m, so, sotc, svc_flags);
	} else {
		/*
		 * Optimization for loopback just set the mbuf
		 * service class
		 */
		(void) m_set_service_class(m, so_tc2msc(sotc));
	}

	TCP_LOG_TH_FLAGS(isipv6 ? (void *)ip6 : (void *)ip, th, tp, true,
	    inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp);

	tp->t_pktlist_sentlen += len;
	tp->t_lastchain++;

	if (isipv6) {
		DTRACE_TCP5(send, struct mbuf *, m, struct inpcb *, inp,
		    struct ip6 *, ip6, struct tcpcb *, tp, struct tcphdr *,
		    th);
	} else {
		DTRACE_TCP5(send, struct mbuf *, m, struct inpcb *, inp,
		    struct ip *, ip, struct tcpcb *, tp, struct tcphdr *, th);
	}

	if (tp->t_pktlist_head != NULL) {
		tp->t_pktlist_tail->m_nextpkt = m;
		tp->t_pktlist_tail = m;
	} else {
		packchain_newlist++;
		tp->t_pktlist_head = tp->t_pktlist_tail = m;
	}

	if (sendalot == 0 || (tp->t_state != TCPS_ESTABLISHED) ||
	    (tp->snd_cwnd <= (tp->snd_wnd / 8)) ||
	    (tp->t_flags & TF_ACKNOW) ||
	    (tp->t_flagsext & TF_FORCE) ||
	    tp->t_lastchain >= tcp_packet_chaining) {
		error = 0;
		while (inp->inp_sndinprog_cnt == 0 &&
		    tp->t_pktlist_head != NULL) {
			packetlist = tp->t_pktlist_head;
			packchain_listadd = tp->t_lastchain;
			packchain_sent++;
			lost = tp->t_pktlist_sentlen;
			TCP_PKTLIST_CLEAR(tp);

			error = tcp_ip_output(so, tp, packetlist,
			    packchain_listadd, tp_inp_options,
			    (so_options & SO_DONTROUTE),
			    (sack_rxmit || (sack_bytes_rxmt != 0)), isipv6);
			if (error) {
				/*
				 * Take into account the rest of unsent
				 * packets in the packet list for this tcp
				 * into "lost", since we're about to free
				 * the whole list below.
				 */
				lost += tp->t_pktlist_sentlen;
				break;
			} else {
				lost = 0;
			}
		}
		/* tcp was closed while we were in ip; resume close */
		if (inp->inp_sndinprog_cnt == 0 &&
		    (tp->t_flags & TF_CLOSING)) {
			tp->t_flags &= ~TF_CLOSING;
			(void) tcp_close(tp);
			return 0;
		}
	} else {
		error = 0;
		packchain_looped++;
		tcpstat.tcps_sndtotal++;

		goto again;
	}
	if (error) {
		/*
		 * Assume that the packets were lost, so back out the
		 * sequence number advance, if any.  Note that the "lost"
		 * variable represents the amount of user data sent during
		 * the recent call to ip_output_list() plus the amount of
		 * user data in the packet list for this tcp at the moment.
		 */
		if (!(tp->t_flagsext & TF_FORCE)
		    || tp->t_timer[TCPT_PERSIST] == 0) {
			/*
			 * No need to check for TH_FIN here because
			 * the TF_SENTFIN flag handles that case.
			 */
			if ((flags & TH_SYN) == 0) {
				if (sack_rxmit) {
					if (SEQ_GT((p->rxmit - lost),
					    tp->snd_una)) {
						p->rxmit -= lost;

						if (SEQ_LT(p->rxmit, p->start)) {
							p->rxmit = p->start;
						}
					} else {
						lost = p->rxmit - tp->snd_una;
						p->rxmit = tp->snd_una;

						if (SEQ_LT(p->rxmit, p->start)) {
							p->rxmit = p->start;
						}
					}
					tp->sackhint.sack_bytes_rexmit -= lost;
					if (tp->sackhint.sack_bytes_rexmit < 0) {
						tp->sackhint.sack_bytes_rexmit = 0;
					}
				} else {
					if (SEQ_GT((tp->snd_nxt - lost),
					    tp->snd_una)) {
						tp->snd_nxt -= lost;
					} else {
						tp->snd_nxt = tp->snd_una;
					}
				}
			}
		}
out:
		if (tp->t_pktlist_head != NULL) {
			m_freem_list(tp->t_pktlist_head);
		}
		TCP_PKTLIST_CLEAR(tp);

		if (error == ENOBUFS) {
			/*
			 * Set retransmit timer if not currently set
			 * when we failed to send a segment that can be
			 * retransmitted (i.e. not pure ack or rst)
			 */
			if (tp->t_timer[TCPT_REXMT] == 0 &&
			    tp->t_timer[TCPT_PERSIST] == 0 &&
			    (len != 0 || (flags & (TH_SYN | TH_FIN)) != 0 ||
			    so->so_snd.sb_cc > 0)) {
				tp->t_timer[TCPT_REXMT] =
				    OFFSET_FROM_START(tp, tp->t_rxtcur);
			}
			tp->snd_cwnd = tp->t_maxseg;
			tp->t_bytes_acked = 0;
			tcp_check_timer_state(tp);
			KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0, 0, 0, 0, 0);

			tcp_ccdbg_trace(tp, NULL, TCP_CC_OUTPUT_ERROR);
			return 0;
		}
		if (error == EMSGSIZE) {
			/*
			 * ip_output() will have already fixed the route
			 * for us.  tcp_mtudisc() will, as its last action,
			 * initiate retransmission, so it is important to
			 * not do so here.
			 *
			 * If TSO was active we either got an interface
			 * without TSO capabilits or TSO was turned off.
			 * Disable it for this connection as too and
			 * immediatly retry with MSS sized segments generated
			 * by this function.
			 */
			if (tso) {
				tp->t_flags &= ~TF_TSO;
			}

			tcp_mtudisc(inp, 0);
			tcp_check_timer_state(tp);

			KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0, 0, 0, 0, 0);
			return 0;
		}
		/*
		 * Unless this is due to interface restriction policy,
		 * treat EHOSTUNREACH/ENETDOWN as a soft error.
		 */
		if ((error == EHOSTUNREACH || error == ENETDOWN) &&
		    TCPS_HAVERCVDSYN(tp->t_state) &&
		    !inp_restricted_send(inp, inp->inp_last_outifp)) {
			tp->t_softerror = error;
			error = 0;
		}
		tcp_check_timer_state(tp);
		KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0, 0, 0, 0, 0);
		return error;
	}

	tcpstat.tcps_sndtotal++;

	KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0, 0, 0, 0, 0);
	if (sendalot) {
		goto again;
	}

	tcp_check_timer_state(tp);

	return 0;
}

static int
tcp_ip_output(struct socket *so, struct tcpcb *tp, struct mbuf *pkt,
    int cnt, struct mbuf *opt, int flags, int sack_in_progress, boolean_t isipv6)
{
	int error = 0;
	boolean_t chain;
	boolean_t unlocked = FALSE;
	boolean_t ifdenied = FALSE;
	struct inpcb *inp = tp->t_inpcb;
	struct ip_out_args ipoa;
	struct route ro;
	struct ifnet *outif = NULL;
	bool check_qos_marking_again = (so->so_flags1 & SOF1_QOSMARKING_POLICY_OVERRIDE) ? FALSE : TRUE;

	bzero(&ipoa, sizeof(ipoa));
	ipoa.ipoa_boundif = IFSCOPE_NONE;
	ipoa.ipoa_flags = IPOAF_SELECT_SRCIF | IPOAF_BOUND_SRCADDR;
	ipoa.ipoa_sotc = SO_TC_UNSPEC;
	ipoa.ipoa_netsvctype = _NET_SERVICE_TYPE_UNSPEC;
	struct ip6_out_args ip6oa;
	struct route_in6 ro6;

	bzero(&ip6oa, sizeof(ip6oa));
	ip6oa.ip6oa_boundif = IFSCOPE_NONE;
	ip6oa.ip6oa_flags = IP6OAF_SELECT_SRCIF | IP6OAF_BOUND_SRCADDR;
	ip6oa.ip6oa_sotc = SO_TC_UNSPEC;
	ip6oa.ip6oa_netsvctype = _NET_SERVICE_TYPE_UNSPEC;

	struct flowadv *adv =
	    (isipv6 ? &ip6oa.ip6oa_flowadv : &ipoa.ipoa_flowadv);

	/* If socket was bound to an ifindex, tell ip_output about it */
	if (inp->inp_flags & INP_BOUND_IF) {
		if (isipv6) {
			ip6oa.ip6oa_boundif = inp->inp_boundifp->if_index;
			ip6oa.ip6oa_flags |= IP6OAF_BOUND_IF;
		} else {
			ipoa.ipoa_boundif = inp->inp_boundifp->if_index;
			ipoa.ipoa_flags |= IPOAF_BOUND_IF;
		}
	}

	if (INP_NO_CELLULAR(inp)) {
		if (isipv6) {
			ip6oa.ip6oa_flags |=  IP6OAF_NO_CELLULAR;
		} else {
			ipoa.ipoa_flags |=  IPOAF_NO_CELLULAR;
		}
	}
	if (INP_NO_EXPENSIVE(inp)) {
		if (isipv6) {
			ip6oa.ip6oa_flags |=  IP6OAF_NO_EXPENSIVE;
		} else {
			ipoa.ipoa_flags |=  IPOAF_NO_EXPENSIVE;
		}
	}
	if (INP_NO_CONSTRAINED(inp)) {
		if (isipv6) {
			ip6oa.ip6oa_flags |=  IP6OAF_NO_CONSTRAINED;
		} else {
			ipoa.ipoa_flags |=  IPOAF_NO_CONSTRAINED;
		}
	}
	if (INP_AWDL_UNRESTRICTED(inp)) {
		if (isipv6) {
			ip6oa.ip6oa_flags |=  IP6OAF_AWDL_UNRESTRICTED;
		} else {
			ipoa.ipoa_flags |=  IPOAF_AWDL_UNRESTRICTED;
		}
	}
	if (INP_INTCOPROC_ALLOWED(inp) && isipv6) {
		ip6oa.ip6oa_flags |=  IP6OAF_INTCOPROC_ALLOWED;
	}
	if (isipv6) {
		ip6oa.ip6oa_sotc = so->so_traffic_class;
		ip6oa.ip6oa_netsvctype = so->so_netsvctype;
		ip6oa.qos_marking_gencount = inp->inp_policyresult.results.qos_marking_gencount;
	} else {
		ipoa.ipoa_sotc = so->so_traffic_class;
		ipoa.ipoa_netsvctype = so->so_netsvctype;
		ipoa.qos_marking_gencount = inp->inp_policyresult.results.qos_marking_gencount;
	}
	if ((so->so_flags1 & SOF1_QOSMARKING_ALLOWED)) {
		if (isipv6) {
			ip6oa.ip6oa_flags |= IP6OAF_QOSMARKING_ALLOWED;
		} else {
			ipoa.ipoa_flags |= IPOAF_QOSMARKING_ALLOWED;
		}
	}
	if (check_qos_marking_again) {
		if (isipv6) {
			ip6oa.ip6oa_flags |= IP6OAF_REDO_QOSMARKING_POLICY;
		} else {
			ipoa.ipoa_flags |= IPOAF_REDO_QOSMARKING_POLICY;
		}
	}
	if (isipv6) {
		flags |= IPV6_OUTARGS;
	} else {
		flags |= IP_OUTARGS;
	}

	/* Copy the cached route and take an extra reference */
	if (isipv6) {
		in6p_route_copyout(inp, &ro6);
	} else {
		inp_route_copyout(inp, &ro);
	}

	/*
	 * Make sure ACK/DELACK conditions are cleared before
	 * we unlock the socket.
	 */
	tp->last_ack_sent = tp->rcv_nxt;
	tp->t_flags &= ~(TF_ACKNOW | TF_DELACK);
	tp->t_timer[TCPT_DELACK] = 0;
	tp->t_unacksegs = 0;

	/* Increment the count of outstanding send operations */
	inp->inp_sndinprog_cnt++;

	/*
	 * If allowed, unlock TCP socket while in IP
	 * but only if the connection is established and
	 * in a normal mode where reentrancy on the tcpcb won't be
	 * an issue:
	 * - there is no SACK episode
	 * - we're not in Fast Recovery mode
	 * - if we're not sending from an upcall.
	 */
	if (tcp_output_unlocked && !so->so_upcallusecount &&
	    (tp->t_state == TCPS_ESTABLISHED) && (sack_in_progress == 0) &&
	    !IN_FASTRECOVERY(tp) && !(so->so_flags & SOF_MP_SUBFLOW)) {
		unlocked = TRUE;
		socket_unlock(so, 0);
	}

	/*
	 * Don't send down a chain of packets when:
	 * - TCP chaining is disabled
	 * - there is an IPsec rule set
	 * - there is a non default rule set for the firewall
	 */

	chain = tcp_packet_chaining > 1
#if IPSEC
	    && ipsec_bypass
#endif
	;         // I'm important, not extraneous

	while (pkt != NULL) {
		struct mbuf *npkt = pkt->m_nextpkt;

		if (!chain) {
			pkt->m_nextpkt = NULL;
			/*
			 * If we are not chaining, make sure to set the packet
			 * list count to 0 so that IP takes the right path;
			 * this is important for cases such as IPsec where a
			 * single mbuf might result in multiple mbufs as part
			 * of the encapsulation.  If a non-zero count is passed
			 * down to IP, the head of the chain might change and
			 * we could end up skipping it (thus generating bogus
			 * packets).  Fixing it in IP would be desirable, but
			 * for now this would do it.
			 */
			cnt = 0;
		}
		if (isipv6) {
			error = ip6_output_list(pkt, cnt,
			    inp->in6p_outputopts, &ro6, flags, NULL, NULL,
			    &ip6oa);
			ifdenied = (ip6oa.ip6oa_retflags & IP6OARF_IFDENIED);
		} else {
			error = ip_output_list(pkt, cnt, opt, &ro, flags, NULL,
			    &ipoa);
			ifdenied = (ipoa.ipoa_retflags & IPOARF_IFDENIED);
		}

		if (chain || error) {
			/*
			 * If we sent down a chain then we are done since
			 * the callee had taken care of everything; else
			 * we need to free the rest of the chain ourselves.
			 */
			if (!chain) {
				m_freem_list(npkt);
			}
			break;
		}
		pkt = npkt;
	}

	if (unlocked) {
		socket_lock(so, 0);
	}

	/*
	 * Enter flow controlled state if the connection is established
	 * and is not in recovery. Flow control is allowed only if there
	 * is outstanding data.
	 *
	 * A connection will enter suspended state even if it is in
	 * recovery.
	 */
	if (((adv->code == FADV_FLOW_CONTROLLED && !IN_FASTRECOVERY(tp)) ||
	    adv->code == FADV_SUSPENDED) &&
	    !(tp->t_flags & TF_CLOSING) &&
	    tp->t_state == TCPS_ESTABLISHED &&
	    SEQ_GT(tp->snd_max, tp->snd_una)) {
		int rc;
		rc = inp_set_fc_state(inp, adv->code);

		if (rc == 1) {
			tcp_ccdbg_trace(tp, NULL,
			    ((adv->code == FADV_FLOW_CONTROLLED) ?
			    TCP_CC_FLOW_CONTROL : TCP_CC_SUSPEND));
		}
	}

	/*
	 * When an interface queue gets suspended, some of the
	 * packets are dropped. Return ENOBUFS, to update the
	 * pcb state.
	 */
	if (adv->code == FADV_SUSPENDED) {
		error = ENOBUFS;
	}

	VERIFY(inp->inp_sndinprog_cnt > 0);
	if (--inp->inp_sndinprog_cnt == 0) {
		inp->inp_flags &= ~(INP_FC_FEEDBACK);
		if (inp->inp_sndingprog_waiters > 0) {
			wakeup(&inp->inp_sndinprog_cnt);
		}
	}

	if (isipv6) {
		/*
		 * When an NECP IP tunnel policy forces the outbound interface,
		 * ip6_output_list() informs the transport layer what is the actual
		 * outgoing interface
		 */
		if (ip6oa.ip6oa_flags & IP6OAF_BOUND_IF) {
			outif = ifindex2ifnet[ip6oa.ip6oa_boundif];
		} else if (ro6.ro_rt != NULL) {
			outif = ro6.ro_rt->rt_ifp;
		}
	} else {
		if (ro.ro_rt != NULL) {
			outif = ro.ro_rt->rt_ifp;
		}
	}
	if (check_qos_marking_again) {
		uint32_t qos_marking_gencount;
		bool allow_qos_marking;
		if (isipv6) {
			qos_marking_gencount = ip6oa.qos_marking_gencount;
			allow_qos_marking = ip6oa.ip6oa_flags & IP6OAF_QOSMARKING_ALLOWED ? TRUE : FALSE;
		} else {
			qos_marking_gencount = ipoa.qos_marking_gencount;
			allow_qos_marking = ipoa.ipoa_flags & IPOAF_QOSMARKING_ALLOWED ? TRUE : FALSE;
		}
		inp->inp_policyresult.results.qos_marking_gencount = qos_marking_gencount;
		if (allow_qos_marking == TRUE) {
			inp->inp_socket->so_flags1 |= SOF1_QOSMARKING_ALLOWED;
		} else {
			inp->inp_socket->so_flags1 &= ~SOF1_QOSMARKING_ALLOWED;
		}
	}

	if (outif != NULL && outif != inp->inp_last_outifp) {
		/* Update the send byte count */
		if (so->so_snd.sb_cc > 0 && so->so_snd.sb_flags & SB_SNDBYTE_CNT) {
			inp_decr_sndbytes_total(so, so->so_snd.sb_cc);
			inp_decr_sndbytes_allunsent(so, tp->snd_una);
			so->so_snd.sb_flags &= ~SB_SNDBYTE_CNT;
		}
		inp->inp_last_outifp = outif;
	}

	if (error != 0 && ifdenied &&
	    (INP_NO_CELLULAR(inp) || INP_NO_EXPENSIVE(inp) || INP_NO_CONSTRAINED(inp))) {
		soevent(so,
		    (SO_FILT_HINT_LOCKED | SO_FILT_HINT_IFDENIED));
	}

	/* Synchronize cached PCB route & options */
	if (isipv6) {
		in6p_route_copyin(inp, &ro6);
	} else {
		inp_route_copyin(inp, &ro);
	}

	if (tp->t_state < TCPS_ESTABLISHED && tp->t_rxtshift == 0 &&
	    tp->t_inpcb->inp_route.ro_rt != NULL) {
		/* If we found the route and there is an rtt on it
		 * reset the retransmit timer
		 */
		tcp_getrt_rtt(tp, tp->t_inpcb->in6p_route.ro_rt);
		tp->t_timer[TCPT_REXMT] = OFFSET_FROM_START(tp, tp->t_rxtcur);
	}
	return error;
}

int tcptv_persmin_val = TCPTV_PERSMIN;

void
tcp_setpersist(struct tcpcb *tp)
{
	int t = ((tp->t_srtt >> 2) + tp->t_rttvar) >> 1;

	/* If a PERSIST_TIMER option was set we will limit the
	 * time the persist timer will be active for that connection
	 * in order to avoid DOS by using zero window probes.
	 * see rdar://5805356
	 */

	if (tp->t_persist_timeout != 0 &&
	    tp->t_timer[TCPT_PERSIST] == 0 &&
	    tp->t_persist_stop == 0) {
		tp->t_persist_stop = tcp_now + tp->t_persist_timeout;
	}

	/*
	 * Start/restart persistance timer.
	 */
	TCPT_RANGESET(tp->t_timer[TCPT_PERSIST],
	    t * tcp_backoff[tp->t_rxtshift],
	    tcptv_persmin_val, TCPTV_PERSMAX, 0);
	tp->t_timer[TCPT_PERSIST] = OFFSET_FROM_START(tp, tp->t_timer[TCPT_PERSIST]);

	if (tp->t_rxtshift < TCP_MAXRXTSHIFT) {
		tp->t_rxtshift++;
	}
}

static int
tcp_recv_throttle(struct tcpcb *tp)
{
	uint32_t base_rtt, newsize;
	struct sockbuf *sbrcv = &tp->t_inpcb->inp_socket->so_rcv;

	if (tcp_use_rtt_recvbg == 1 &&
	    TSTMP_SUPPORTED(tp)) {
		/*
		 * Timestamps are supported on this connection. Use
		 * RTT to look for an increase in latency.
		 */

		/*
		 * If the connection is already being throttled, leave it
		 * in that state until rtt comes closer to base rtt
		 */
		if (tp->t_flagsext & TF_RECV_THROTTLE) {
			return 1;
		}

		base_rtt = get_base_rtt(tp);

		if (base_rtt != 0 && tp->t_rttcur != 0) {
			/*
			 * if latency increased on a background flow,
			 * return 1 to start throttling.
			 */
			if (tp->t_rttcur > (base_rtt + target_qdelay)) {
				tp->t_flagsext |= TF_RECV_THROTTLE;
				if (tp->t_recv_throttle_ts == 0) {
					tp->t_recv_throttle_ts = tcp_now;
				}
				/*
				 * Reduce the recv socket buffer size to
				 * minimize latecy.
				 */
				if (sbrcv->sb_idealsize >
				    tcp_recv_throttle_minwin) {
					newsize = sbrcv->sb_idealsize >> 1;
					/* Set a minimum of 16 K */
					newsize =
					    max(newsize,
					    tcp_recv_throttle_minwin);
					sbrcv->sb_idealsize = newsize;
				}
				return 1;
			} else {
				return 0;
			}
		}
	}

	/*
	 * Timestamps are not supported or there is no good RTT
	 * measurement. Use IPDV in this case.
	 */
	if (tp->acc_iaj > tcp_acc_iaj_react_limit) {
		return 1;
	}

	return 0;
}
