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

#define	_IP_VHL


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
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <mach/sdt.h>
#if INET6
#include <netinet6/in6_pcb.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#endif
#include <netinet/tcp.h>
#define	TCPOUTFLAGS
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
#include <sys/kdebug.h>
#include <mach/sdt.h>

#if IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif /* MAC_SOCKET */

#include <netinet/lro_ext.h>
#if MPTCP
#include <netinet/mptcp_var.h>
#include <netinet/mptcp.h>
#include <netinet/mptcp_opt.h>
#endif

#include <corecrypto/ccaes.h>

#define DBG_LAYER_BEG		NETDBG_CODE(DBG_NETTCP, 1)
#define DBG_LAYER_END		NETDBG_CODE(DBG_NETTCP, 3)
#define DBG_FNC_TCP_OUTPUT	NETDBG_CODE(DBG_NETTCP, (4 << 8) | 1)

int path_mtu_discovery = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, path_mtu_discovery,
	CTLFLAG_RW | CTLFLAG_LOCKED, &path_mtu_discovery, 1,
	"Enable Path MTU Discovery");

int ss_fltsz = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, slowstart_flightsize,
	CTLFLAG_RW | CTLFLAG_LOCKED,&ss_fltsz, 1,
	"Slow start flight size");

int ss_fltsz_local = 8; /* starts with eight segments max */
SYSCTL_INT(_net_inet_tcp, OID_AUTO, local_slowstart_flightsize,
	CTLFLAG_RW | CTLFLAG_LOCKED, &ss_fltsz_local, 1,
	"Slow start flight size for local networks");

int	tcp_do_tso = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, tso, CTLFLAG_RW | CTLFLAG_LOCKED,
	&tcp_do_tso, 0, "Enable TCP Segmentation Offload");

int     tcp_ecn_outbound = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, ecn_initiate_out,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_ecn_outbound, 0,
	"Initiate ECN for outbound connections");

int     tcp_ecn_inbound = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, ecn_negotiate_in,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_ecn_inbound, 0,
	"Allow ECN negotiation for inbound connections");

int	tcp_packet_chaining = 50;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, packetchain,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_packet_chaining, 0,
	"Enable TCP output packet chaining");

int	tcp_output_unlocked = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, socket_unlocked_on_output,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_output_unlocked, 0,
	"Unlock TCP when sending packets down to IP");

int tcp_do_rfc3390 = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, rfc3390,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_do_rfc3390, 1,
	"Calculate intial slowstart cwnd depending on MSS");

int tcp_min_iaj_win = MIN_IAJ_WIN;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, min_iaj_win,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_min_iaj_win, 1,
	"Minimum recv win based on inter-packet arrival jitter");

int tcp_acc_iaj_react_limit = ACC_IAJ_REACT_LIMIT;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, acc_iaj_react_limit,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_acc_iaj_react_limit, 1,
	"Accumulated IAJ when receiver starts to react");

uint32_t tcp_do_autosendbuf = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, doautosndbuf,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_do_autosendbuf, 1,
	"Enable send socket buffer auto-tuning");

uint32_t tcp_autosndbuf_inc = 8 * 1024;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, autosndbufinc,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_autosndbuf_inc, 1,
	"Increment in send socket bufffer size");

uint32_t tcp_autosndbuf_max = 512 * 1024;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, autosndbufmax,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_autosndbuf_max, 1,
	"Maximum send socket buffer size");

uint32_t tcp_prioritize_acks = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, ack_prioritize,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_prioritize_acks, 1,
	"Prioritize pure acks");

uint32_t tcp_use_rtt_recvbg = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, rtt_recvbg,
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_use_rtt_recvbg, 1,
	"Use RTT for bg recv algorithm");

uint32_t tcp_recv_throttle_minwin = 16 * 1024;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, recv_throttle_minwin, 
	CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_recv_throttle_minwin, 1,
	"Minimum recv win for throttling");

int32_t tcp_enable_tlp = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, enable_tlp,
	CTLFLAG_RW | CTLFLAG_LOCKED,
	&tcp_enable_tlp, 1, "Enable Tail loss probe");

static int32_t packchain_newlist = 0;
static int32_t packchain_looped = 0;
static int32_t packchain_sent = 0;

/* temporary: for testing */
#if IPSEC
extern int ipsec_bypass;
#endif

extern int slowlink_wsize;	/* window correction for slow links */
#if IPFIREWALL
extern int fw_enable; 		/* firewall check for packet chaining */
extern int fw_bypass; 		/* firewall check: disable packet chaining if there is rules */
#endif /* IPFIREWALL */

extern u_int32_t dlil_filter_disable_tso_count;
extern u_int32_t kipf_count;
extern int tcp_recv_bg;

static int tcp_ip_output(struct socket *, struct tcpcb *, struct mbuf *, int,
    struct mbuf *, int, int, int32_t, boolean_t);
static struct mbuf* tcp_send_lroacks(struct tcpcb *tp, struct mbuf *m, struct tcphdr *th);
static int tcp_recv_throttle(struct tcpcb *tp);

static int32_t tcp_tfo_check(struct tcpcb *tp, int32_t len)
{
	struct socket *so = tp->t_inpcb->inp_socket;
	unsigned int optlen = 0;
	unsigned int cookie_len;

	if (tp->t_flags & TF_NOOPT)
		goto fallback;

	if (!tcp_heuristic_do_tfo(tp))
		goto fallback;

	optlen += TCPOLEN_MAXSEG;

	if (tp->t_flags & TF_REQ_SCALE)
		optlen += 4;

#if MPTCP
	if ((so->so_flags & SOF_MP_SUBFLOW) && mptcp_enable &&
	    tp->t_rxtshift <= mptcp_mpcap_retries)
		optlen += sizeof(struct mptcp_mpcapable_opt_common) + sizeof(mptcp_key_t);
#endif /* MPTCP */

	if (tp->t_flags & TF_REQ_TSTMP)
		optlen += TCPOLEN_TSTAMP_APPA;

	if (SACK_ENABLED(tp))
		optlen += TCPOLEN_SACK_PERMITTED;

	/* Now, decide whether to use TFO or not */

	/* Don't even bother trying if there is no space at all... */
	if (MAX_TCPOPTLEN - optlen < TCPOLEN_FASTOPEN_REQ)
		goto fallback;

	cookie_len = tcp_cache_get_cookie_len(tp);
	if (cookie_len == 0)
		/* No cookie, so we request one */
		return (0);

	/* Do not send SYN+data if there is more in the queue than MSS */
	if (so->so_snd.sb_cc > (tp->t_maxopd - MAX_TCPOPTLEN))
		goto fallback;

	/* Ok, everything looks good. We can go on and do TFO */
	return (len);

fallback:
	tp->t_flagsext &= ~TF_FASTOPEN;
	return (0);
}

/* Returns the number of bytes written to the TCP option-space */
static unsigned
tcp_tfo_write_cookie_rep(struct tcpcb *tp, unsigned optlen, u_char *opt)
{
	u_char out[CCAES_BLOCK_SIZE];
	unsigned ret = 0;
	u_char *bp;

	if ((MAX_TCPOPTLEN - optlen) <
	    (TCPOLEN_FASTOPEN_REQ + TFO_COOKIE_LEN_DEFAULT))
		return (ret);

	tcp_tfo_gen_cookie(tp->t_inpcb, out, sizeof(out));

	bp = opt + optlen;

	*bp++ = TCPOPT_FASTOPEN;
	*bp++ = 2 + TFO_COOKIE_LEN_DEFAULT;
	memcpy(bp, out, TFO_COOKIE_LEN_DEFAULT);
	ret += 2 + TFO_COOKIE_LEN_DEFAULT;

	tp->t_tfo_stats |= TFO_S_COOKIE_SENT;
	tcpstat.tcps_tfo_cookie_sent++;

	return (ret);
}

static unsigned
tcp_tfo_write_cookie(struct tcpcb *tp, unsigned optlen, int32_t *len,
		     u_char *opt)
{
	u_int8_t tfo_len = MAX_TCPOPTLEN - optlen - TCPOLEN_FASTOPEN_REQ;
	unsigned ret = 0;
	int res;
	u_char *bp;

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
		if (*len) {
			tp->t_tfo_stats |= TFO_S_SYN_DATA_SENT;
			tcpstat.tcps_tfo_syn_data_sent++;
		}
	}

	return (ret);
}

static inline bool
tcp_send_ecn_flags_on_syn(struct tcpcb *tp, struct socket *so)
{
	return(!((tp->ecn_flags & TE_SETUPSENT) ||
	    (so->so_flags & SOF_MP_SUBFLOW) ||
	    (tp->t_flagsext & TF_FASTOPEN)));
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
	int flags, error;
	struct mbuf *m;
	struct ip *ip = NULL;
	struct ipovly *ipov = NULL;
#if INET6
	struct ip6_hdr *ip6 = NULL;
#endif /* INET6 */
	struct tcphdr *th;
	u_char opt[TCP_MAXOLEN];
	unsigned ipoptlen, optlen, hdrlen;
	int idle, sendalot, lost = 0;
	int i, sack_rxmit;
	int tso = 0;
	int sack_bytes_rxmt;
	tcp_seq old_snd_nxt = 0;
	struct sackhole *p;
#if IPSEC
	unsigned ipsec_optlen = 0;
#endif /* IPSEC */
	int    idle_time = 0;
	struct mbuf *packetlist = NULL;
	struct mbuf *tp_inp_options = inp->inp_depend4.inp4_options;
#if INET6
	int isipv6 = inp->inp_vflag & INP_IPV6 ;
#endif
	short packchain_listadd = 0;
	int so_options = so->so_options;
	struct rtentry *rt;
	u_int32_t basertt, svc_flags = 0, allocated_len;
	u_int32_t lro_ackmore = (tp->t_lropktlen != 0) ? 1 : 0;
	struct mbuf *mnext = NULL;
	int sackoptlen = 0;
#if MPTCP
	unsigned int *dlenp = NULL;
	u_int8_t *finp = NULL;
	u_int32_t *sseqp = NULL;
	u_int64_t dss_val = 0;
	boolean_t mptcp_acknow = FALSE;
	boolean_t early_data_sent = FALSE;
#endif /* MPTCP */
	boolean_t cell = FALSE;
	boolean_t wifi = FALSE;
	boolean_t wired = FALSE;
	boolean_t sack_rescue_rxt = FALSE;

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
		if (!SLIST_EMPTY(&tp->t_rxt_segments))
			tcp_rxtseg_clean(tp);

		/* If stretch ack was auto-disabled, re-evaluate it */
		tcp_cc_after_idle_stretchack(tp);
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
		return (0);
	}
#endif /* MPTCP */

again:
	KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_START, 0,0,0,0,0);

#if INET6
	if (isipv6) {
		KERNEL_DEBUG(DBG_LAYER_BEG,
		     ((inp->inp_fport << 16) | inp->inp_lport),
		     (((inp->in6p_laddr.s6_addr16[0] & 0xffff) << 16) |
		      (inp->in6p_faddr.s6_addr16[0] & 0xffff)),
		     sendalot,0,0);
	} else
#endif

	{
		KERNEL_DEBUG(DBG_LAYER_BEG,
		     ((inp->inp_fport << 16) | inp->inp_lport),
		     (((inp->inp_laddr.s_addr & 0xffff) << 16) |
		      (inp->inp_faddr.s_addr & 0xffff)),
		     sendalot,0,0);
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
			if (ia6 != NULL)
				found_srcaddr = 1;
		} else {
			ia = ifa_foraddr(inp->inp_laddr.s_addr);
			if (ia != NULL)
				found_srcaddr = 1;
		}

		/* check that the source address is still valid */
		if (found_srcaddr == 0) {
			soevent(so,
			    (SO_FILT_HINT_LOCKED | SO_FILT_HINT_NOSRCADDR));

			if (tp->t_state >= TCPS_CLOSE_WAIT) {
				tcp_drop(tp, EADDRNOTAVAIL);
				return(EADDRNOTAVAIL);
			}

			/* Set retransmit  timer if it wasn't set,
			 * reset Persist timer and shift register as the
			 * advertised peer window may not be valid anymore
			 */

			if (!tp->t_timer[TCPT_REXMT]) {
				tp->t_timer[TCPT_REXMT] =
				    OFFSET_FROM_START(tp, tp->t_rxtcur);
				if (tp->t_timer[TCPT_PERSIST]) {
					tp->t_timer[TCPT_PERSIST] = 0;
					tp->t_rxtshift = 0;
					tp->t_persist_stop = 0;
					tp->t_rxtstart = 0;
				}
			}

			if (tp->t_pktlist_head != NULL)
				m_freem_list(tp->t_pktlist_head);
			TCP_PKTLIST_CLEAR(tp);

			/* drop connection if source address isn't available */
			if (so->so_flags & SOF_NOADDRAVAIL) { 
				tcp_drop(tp, EADDRNOTAVAIL);
				return(EADDRNOTAVAIL);
			} else {
				tcp_check_timer_state(tp);
				return(0); /* silently ignore, keep data in socket: address may be back */
			}
		}
		if (ia != NULL)
			IFA_REMREF(&ia->ia_ifa);

		if (ia6 != NULL)
			IFA_REMREF(&ia6->ia_ifa);

		/*
		 * Address is still valid; check for multipages capability
		 * again in case the outgoing interface has changed.
		 */
		RT_LOCK(rt);
		if ((ifp = rt->rt_ifp) != NULL) {
			somultipages(so, (ifp->if_hwassist & IFNET_MULTIPAGES));
			tcp_set_tso(tp, ifp);
			soif2kcl(so,
			    (ifp->if_eflags & IFEF_2KCL));
		}
		if (rt->rt_flags & RTF_UP)
			RT_GENID_SYNC(rt);
		/*
		 * See if we should do MTU discovery. Don't do it if:
		 *	1) it is disabled via the sysctl
		 *	2) the route isn't up
		 *	3) the MTU is locked (if it is, then discovery
		 *         has been disabled)
		 */

	    	if (!path_mtu_discovery || ((rt != NULL) && 
		    (!(rt->rt_flags & RTF_UP) ||
		    (rt->rt_rmx.rmx_locks & RTV_MTU)))) 
			tp->t_flags &= ~TF_PMTUD;
		else
			tp->t_flags |= TF_PMTUD;

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
	if (SACK_ENABLED(tp) && SEQ_LT(tp->snd_nxt, tp->snd_max))
		tcp_sack_adjust(tp);
	sendalot = 0;
	off = tp->snd_nxt - tp->snd_una;
	sendwin = min(tp->snd_wnd, tp->snd_cwnd);

	if (tp->t_flags & TF_SLOWLINK && slowlink_wsize > 0)
		sendwin = min(sendwin, slowlink_wsize);

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
		
		cwin = min(tp->snd_wnd, tp->snd_cwnd) - sack_bytes_rxmt;
		if (cwin < 0)
			cwin = 0;
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
			} else
				/* Can rexmit part of the current hole */
				len = ((int32_t)min(cwin,
						   tp->snd_recover - p->rxmit));
		} else {
			len = ((int32_t)min(cwin, p->end - p->rxmit));
		}
		if (len > 0) {
			off = p->rxmit - tp->snd_una; 
			sack_rxmit = 1;
			sendalot = 1;
			tcpstat.tcps_sack_rexmits++;
			tcpstat.tcps_sack_rexmit_bytes +=
			    min(len, tp->t_maxseg);
			if (nstat_collect) {
				nstat_route_tx(inp->inp_route.ro_rt, 1,
					min(len, tp->t_maxseg),
					NSTAT_TX_FLAG_RETRANSMIT);
				INP_ADD_STAT(inp, cell, wifi, wired,
				    txpackets, 1);
				INP_ADD_STAT(inp, cell, wifi, wired,
				    txbytes, min(len, tp->t_maxseg));
				tp->t_stat.txretransmitbytes += min(len, tp->t_maxseg);
			}
		} else {
			len = 0;
		}
	}
after_sack_rexmit:
	/*
	 * Get standard flags, and add SYN or FIN if requested by 'hidden'
	 * state flags.
	 */
	if (tp->t_flags & TF_NEEDFIN)
		flags |= TH_FIN;
	if (tp->t_flags & TF_NEEDSYN)
		flags |= TH_SYN;

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
			if (off < so->so_snd.sb_cc)
				flags &= ~TH_FIN;
			sendwin = 1;
		} else {
			tp->t_timer[TCPT_PERSIST] = 0;
			tp->t_rxtshift = 0;
			tp->t_rxtstart = 0;
			tp->t_persist_stop = 0;
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

			cwin = tp->snd_cwnd -
			    (tp->snd_nxt - tp->sack_newdata) -
			    sack_bytes_rxmt;
			if (cwin < 0)
				cwin = 0;
                        /*
			 * We are inside of a SACK recovery episode and are
			 * sending new data, having retransmitted all the
			 * data possible in the scoreboard.
			 */
			len = min(so->so_snd.sb_cc, tp->snd_wnd) 
			       - off;
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
				    tp->snd_max == tp->snd_recover)
					tp->snd_nxt--;

				off = tp->snd_nxt - tp->snd_una;
				sendalot = 0;
				tp->t_flagsext |= TF_RESCUE_RXT;
			}
		}
	}

#if MPTCP
	if ((tp->t_mpflags & TMPF_FASTJOIN_SEND) &&
	    (tp->t_state == TCPS_SYN_SENT) &&
	    (!(tp->t_flags & TF_CLOSING)) &&
	    (so->so_snd.sb_cc != 0) &&
	    (tp->t_rxtshift == 0)) {
		flags &= ~TH_SYN;
		flags |= TH_ACK;
		off = 0;
		len = min(so->so_snd.sb_cc, tp->t_maxseg);
		early_data_sent = TRUE;
	} else if (early_data_sent) {
		/* for now, we allow only one data segment to be sent */
		return (0);
	}
#endif /* MPTCP */
	/*
	 * Lop off SYN bit if it has already been sent.  However, if this
	 * is SYN-SENT state and if segment contains data and if we don't
	 * know that foreign host supports TAO, suppress sending segment.
	 */
	if ((flags & TH_SYN) && SEQ_GT(tp->snd_nxt, tp->snd_una)) {
		if (tp->t_state != TCPS_SYN_RECEIVED || tfo_enabled(tp))
			flags &= ~TH_SYN;
		off--, len++;
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
				    (sack_rxmit | (sack_bytes_rxmt != 0)), 0,
#if INET6
				    isipv6);
#else /* INET6 */
				    0);
#endif /* !INET6 */


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
			    0,0,0,0,0);
			return(0);
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

	if ((flags & TH_SYN) && tp->t_state <= TCPS_SYN_SENT && tfo_enabled(tp))
		len = tcp_tfo_check(tp, len);

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
			tp->t_rxtshift = 0;
			tp->t_rxtstart = 0;
			tp->snd_nxt = tp->snd_una;
			off = 0;
			if (tp->t_timer[TCPT_PERSIST] == 0)
				tcp_setpersist(tp);
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
	basertt = get_base_rtt(tp);
	if (tcp_do_autosendbuf == 1 &&
	    !INP_WAIT_FOR_IF_FEEDBACK(inp) && !IN_FASTRECOVERY(tp) &&
	    (so->so_snd.sb_flags & (SB_AUTOSIZE | SB_TRIM)) == SB_AUTOSIZE &&
	    tcp_cansbgrow(&so->so_snd)) {
		if ((tp->snd_wnd / 4 * 5) >= so->so_snd.sb_hiwat &&
		    so->so_snd.sb_cc >= (so->so_snd.sb_hiwat / 8 * 7) &&
		    sendwin >= (so->so_snd.sb_cc - 
			(tp->snd_nxt - tp->snd_una))) {
			/* Also increase the send buffer only if the 
			 * round-trip time is not increasing because we do
			 * not want to contribute to latency by filling
			 * buffers.
			 * We also do not want to hold onto application's
			 * old data for too long. Interactive applications
			 * would rather discard old data.
			 */
			if (tp->t_rttcur <= (basertt + 25)) {
				if (sbreserve(&so->so_snd,
				    min(so->so_snd.sb_hiwat + tcp_autosndbuf_inc,
					tcp_autosndbuf_max)) == 1) {
					so->so_snd.sb_idealsize = so->so_snd.sb_hiwat;
				}
			} else {
				so->so_snd.sb_idealsize =
				    max(tcp_sendspace, so->so_snd.sb_hiwat -
					(2 * tcp_autosndbuf_inc));
				so->so_snd.sb_flags |= SB_TRIM;
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
	 * ipfw rules and IP options, as well as disabling hardware checksum
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
	if (ipsec_bypass == 0)
		ipsec_optlen = ipsec_hdrsiz_tcp(tp);
#endif
	if (len > tp->t_maxseg) {
		if ((tp->t_flags & TF_TSO) && tcp_do_tso && hwcksum_tx &&
		    ip_use_randomid && kipf_count == 0 &&
		    dlil_filter_disable_tso_count == 0 &&
		    tp->rcv_numsacks == 0 && sack_rxmit == 0  &&
		    sack_bytes_rxmt == 0 &&
		    inp->inp_options == NULL &&
		    inp->in6p_options == NULL
#if IPSEC
		    && ipsec_optlen == 0
#endif
#if IPFIREWALL
		    && (fw_enable == 0 || fw_bypass)
#endif
		    ) {
			tso = 1;
			sendalot = 0;
		} else {
			len = tp->t_maxseg;
			sendalot = 1;
			tso = 0;
		}
	}

	/* Send one segment or less as a tail loss probe */
	if (tp->t_flagsext & TF_SENT_TLPROBE) {
		len = min(len, tp->t_maxseg);
		sendalot = 0;
		tso = 0;
	}

#if MPTCP
	if ((so->so_flags & SOF_MP_SUBFLOW) && 
	    !(tp->t_mpflags & TMPF_TCP_FALLBACK)) {
		int newlen = len;
		if (!(tp->t_mpflags & TMPF_PREESTABLISHED) &&
		    (tp->t_state > TCPS_CLOSED) &&
		    ((tp->t_mpflags & TMPF_SND_MPPRIO) ||
		    (tp->t_mpflags & TMPF_SND_REM_ADDR) ||
		    (tp->t_mpflags & TMPF_SND_MPFAIL) ||
		    (tp->t_mpflags & TMPF_MPCAP_RETRANSMIT))) {
			if (len > 0) {
				len = 0;
			}
			sendalot = 1;
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
		if (len > 0)
			newlen = mptcp_adj_sendlen(so, off, len);
		if (newlen < len) {
			len = newlen;
			sendalot = 1;
		}
	}
#endif /* MPTCP */

	/*
	 * If the socket is capable of doing unordered send,
	 * pull the amount of data that can be sent from the
	 * unordered priority queues to the serial queue in
	 * the socket buffer. If bytes are not yet available
	 * in the highest priority message, we may not be able 
	 * to send any new data. 
	 */
	if (so->so_flags & SOF_ENABLE_MSGS) {
		if ((off + len) >
		    so->so_msg_state->msg_serial_bytes) {
			sbpull_unordered_data(so, off, len);

			/* check if len needs to be modified */
			if ((off + len) > 
			    so->so_msg_state->msg_serial_bytes) {
				len = so->so_msg_state->msg_serial_bytes - off;
				if (len <= 0) {
					len = 0;
					tcpstat.tcps_msg_sndwaithipri++;
				}
			}
		}
	}

	if (sack_rxmit) {
		if (SEQ_LT(p->rxmit + len, tp->snd_una + so->so_snd.sb_cc))
			flags &= ~TH_FIN;
	} else {
		if (SEQ_LT(tp->snd_nxt + len, tp->snd_una + so->so_snd.sb_cc))
			flags &= ~TH_FIN;
	}

	recwin = tcp_sbspace(tp);

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
		if (tp->t_flagsext & TF_FORCE)
			goto send;
		if (SEQ_LT(tp->snd_nxt, tp->snd_max))
			goto send;
		if (sack_rxmit)
			goto send;

		/*
		 * Send new data on the connection only if it is
		 * not flow controlled
		 */
		if (!INP_WAIT_FOR_IF_FEEDBACK(inp) ||
		    tp->t_state != TCPS_ESTABLISHED) {
			if (len >= tp->t_maxseg)
				goto send;
			if (!(tp->t_flags & TF_MORETOCOME) &&
			    (idle || tp->t_flags & TF_NODELAY || 
			    tp->t_flags & TF_MAXSEGSNT ||
			    ALLOW_LIMITED_TRANSMIT(tp)) &&
			    (tp->t_flags & TF_NOPUSH) == 0 &&
			    len + off >= so->so_snd.sb_cc)
				goto send;
			if (len >= tp->max_sndwnd / 2 && tp->max_sndwnd > 0)
				goto send;
		} else {
			tcpstat.tcps_fcholdpacket++;
		}
	}

	/*
	 * Compare available window to amount of window
	 * known to peer (as advertised window less
	 * next expected input).  If the difference is at least two
	 * max size segments, or at least 25% of the maximum possible
	 * window, then want to send a window update to peer.
	 * Skip this if the connection is in T/TCP half-open state.
	 */
	if (recwin > 0 && !(tp->t_flags & TF_NEEDSYN)) {
		/*
		 * "adv" is the amount we can increase the window,
		 * taking into account that we are limited by
		 * TCP_MAXWIN << tp->rcv_scale.
		 */
		int32_t adv, oldwin = 0;
		adv = imin(recwin, (int)TCP_MAXWIN << tp->rcv_scale) -
			(tp->rcv_adv - tp->rcv_nxt);

		if (SEQ_GT(tp->rcv_adv, tp->rcv_nxt))
			oldwin = tp->rcv_adv - tp->rcv_nxt;

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
			 */
			if (!(tp->t_flags & TF_STRETCHACK) &&
				(tp->last_ack_sent != tp->rcv_nxt || 
				((oldwin + adv) >> tp->rcv_scale) >
				(oldwin >> tp->rcv_scale))) {
				goto send;
			}

			/*
			 * Make sure that the delayed ack timer is set if
			 * we delayed sending a window update because of 
			 * streaming detection.
			 */
			if ((tp->t_flags & TF_STRETCHACK) &&
				!(tp->t_flags & TF_DELACK)) { 
				tp->t_flags |= TF_DELACK;
				tp->t_timer[TCPT_DELACK] = 
					OFFSET_FROM_START(tp, tcp_delack);
			}
		}
		if (4 * adv >= (int32_t) so->so_rcv.sb_hiwat) 
				goto send;
	}

	/*
	 * Send if we owe the peer an ACK, RST, SYN, or urgent data. ACKNOW
	 * is also a catch-all for the retransmit timer timeout case.
	 */
	if (tp->t_flags & TF_ACKNOW)
		goto send;
	if ((flags & TH_RST) ||
	    ((flags & TH_SYN) && (tp->t_flags & TF_NEEDSYN) == 0))
		goto send;
	if (SEQ_GT(tp->snd_up, tp->snd_una))
		goto send;
#if MPTCP
	if (mptcp_acknow)
		goto send;
#endif /* MPTCP */
	/*
	 * If our state indicates that FIN should be sent
	 * and we have not yet done so, then we need to send.
	 */
	if ((flags & TH_FIN) &&
	    (!(tp->t_flags & TF_SENTFIN) || tp->snd_nxt == tp->snd_una))
		goto send;
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
		tp->t_rxtshift = 0;
		tp->t_rxtstart = 0;
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
		    (sack_rxmit | (sack_bytes_rxmt != 0)), recwin,
#if INET6
		    isipv6);
#else /* INET6 */
		    0);
#endif /* !INET6 */
	}
	/* tcp was closed while we were in ip; resume close */
	if (inp->inp_sndinprog_cnt == 0 &&
		(tp->t_flags & TF_CLOSING)) {
		tp->t_flags &= ~TF_CLOSING;
		(void) tcp_close(tp);
	} else {
		tcp_check_timer_state(tp);
	}
	KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
	return (0);

send:
	/*
	 * Set TF_MAXSEGSNT flag if the segment size is greater than
	 * the max segment size.
	 */
	if (len > 0) {
		if (len >= tp->t_maxseg)
			tp->t_flags |= TF_MAXSEGSNT;
		else
			tp->t_flags &= ~TF_MAXSEGSNT;
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
#if INET6
	if (isipv6)
		hdrlen = sizeof (struct ip6_hdr) + sizeof (struct tcphdr);
	else
#endif
		hdrlen = sizeof (struct tcpiphdr);
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
			if (mptcp_enable) {
				optlen = mptcp_setup_syn_opts(so, flags, opt,
				    optlen);
			}
#endif /* MPTCP */
		}
	}

	/*
	 * Send a timestamp and echo-reply if this is a SYN and our side
	 * wants to use timestamps (TF_REQ_TSTMP is set) or both our side
	 * and our peer have sent timestamps in our SYN's.
 	 */
 	if ((tp->t_flags & (TF_REQ_TSTMP|TF_NOOPT)) == TF_REQ_TSTMP &&
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

	/* Note the timestamp for receive buffer autosizing */
	if (tp->rfbuf_ts == 0 && (so->so_rcv.sb_flags & SB_AUTOSIZE))
		tp->rfbuf_ts = tcp_now;

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
		    len, &dlenp, &finp, &dss_val, &sseqp, &mptcp_acknow);
		tp->t_mpflags &= ~TMPF_SEND_DSN;
	}
#endif /* MPTCP */

	if (tfo_enabled(tp) && !(tp->t_flags & TF_NOOPT) &&
	    (flags & (TH_SYN | TH_ACK)) == TH_SYN)
		optlen += tcp_tfo_write_cookie(tp, optlen, &len, opt);

	if (tfo_enabled(tp) &&
	    (flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK) &&
	    (tp->t_tfo_flags & TFO_F_OFFER_COOKIE))
		optlen += tcp_tfo_write_cookie_rep(tp, optlen, opt);

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

			/*
			 * First we need to pad options so that the
			 * SACK blocks can start at a 4-byte boundary
			 * (sack option and length are at a 2 byte offset).
			 */
			padlen = (MAX_TCPOPTLEN - optlen - sackoptlen) % 4;
			optlen += padlen;
			while (padlen-- > 0)
				*bp++ = TCPOPT_NOP;

			tcpstat.tcps_sack_send_blocks++;
			*bp++ = TCPOPT_SACK;
			*bp++ = sackoptlen;
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
	if ((tcp_ecn_inbound || (tp->t_flags & TF_ENABLE_ECN))
	    && (flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
		if (tp->ecn_flags & TE_SETUPRECEIVED) {
			if (tcp_send_ecn_flags_on_syn(tp, so)) {
				/*
				 * Setting TH_ECE makes this an ECN-setup
				 * SYN-ACK
				 */
				flags |= TH_ECE;

				/*
				 * Record that we sent the ECN-setup and
				 * default to setting IP ECT.
				 */
				tp->ecn_flags |= (TE_SETUPSENT|TE_SENDIPECT);
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
				}

				tp->ecn_flags &=
				    ~(TE_SETUPRECEIVED | TE_SENDIPECT |
				    TE_SENDCWR);
			}
		}
	} else if ((tcp_ecn_outbound || (tp->t_flags & TF_ENABLE_ECN))
	    && (flags & (TH_SYN | TH_ACK)) == TH_SYN) {
		if (tcp_send_ecn_flags_on_syn(tp, so)) {
			/*
			 * Setting TH_ECE and TH_CWR makes this an
			 * ECN-setup SYN
			 */
			flags |= (TH_ECE | TH_CWR);
			tcpstat.tcps_ecn_client_setup++;

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
			if (tp->ecn_flags & TE_SETUPSENT)
				tcpstat.tcps_ecn_lost_syn++;
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

#if INET6
	if (isipv6)
		ipoptlen = ip6_optlen(inp);
	else
#endif
	{
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
				len = len - (len % (tp->t_maxopd - optlen));
				sendalot = 1;
			} else if (tp->t_flags & TF_NEEDFIN) {
				sendalot = 1;
			}
		} else {
			len = tp->t_maxopd - optlen - ipoptlen;
			sendalot = 1;
		}
	}
#if MPTCP
	/* Adjust the length in the DSS option, if it is lesser than len */
	if (dlenp) {
		/*
		 * To test this path without SACK, artificially
		 * decrement len with something like
		 * if (len > 10)
			len -= 10;
		 */
		if (ntohs(*dlenp) > len) {
			*dlenp = htons(len);
			/* Unset the FIN flag, if len was adjusted */
			if (finp) {
				*finp &= ~MDSS_F;
			}
			sendalot = 1;
		}
	}
#endif /* MPTCP */

 	if (max_linkhdr + hdrlen > MCLBYTES)
		panic("tcphdr too big");

	/* Check if there is enough data in the send socket
	 * buffer to start measuring bw 
	 */
	if ((tp->t_flagsext & TF_MEASURESNDBW) != 0 &&
		(tp->t_bwmeas != NULL) &&
		(tp->t_flagsext & TF_BWMEAS_INPROGRESS) == 0 &&
		(so->so_snd.sb_cc - (tp->snd_max - tp->snd_una)) >= 
			tp->t_bwmeas->bw_minsize) {
		tp->t_bwmeas->bw_size = min(
			(so->so_snd.sb_cc - (tp->snd_max - tp->snd_una)),
			tp->t_bwmeas->bw_maxsize);
		tp->t_flagsext |= TF_BWMEAS_INPROGRESS;
		tp->t_bwmeas->bw_start = tp->snd_max;
		tp->t_bwmeas->bw_ts = tcp_now;
	}

	VERIFY(inp->inp_flowhash != 0);
	/*
	 * Grab a header mbuf, attaching a copy of data to
	 * be transmitted, and initialize the header from
	 * the template for sends on this connection.
	 */
	if (len) {
		tp->t_pmtud_lastseg_size = len + optlen + ipoptlen;
		if ((tp->t_flagsext & TF_FORCE) && len == 1)
			tcpstat.tcps_sndprobe++;
		else if (SEQ_LT(tp->snd_nxt, tp->snd_max) || sack_rxmit) {
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
		}
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
				if (m != NULL) 	m_freem(m);
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
		if (off + len == so->so_snd.sb_cc && !(flags & TH_SYN))
			flags |= TH_PUSH;
	} else {
		if (tp->t_flags & TF_ACKNOW)
			tcpstat.tcps_sndacks++;
		else if (flags & (TH_SYN|TH_FIN|TH_RST))
			tcpstat.tcps_sndctrl++;
		else if (SEQ_GT(tp->snd_up, tp->snd_una))
			tcpstat.tcps_sndurg++;
		else
			tcpstat.tcps_sndwinup++;

		MGETHDR(m, M_DONTWAIT, MT_HEADER);	/* MAC-OK */
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
#if MPTCP
	/* Before opt is copied to the mbuf, set the csum field */
	mptcp_output_csum(tp, m, len, hdrlen, dss_val, sseqp);
#endif /* MPTCP */
#if CONFIG_MACF_NET
	mac_mbuf_label_associate_inpcb(inp, m);
#endif
#if INET6
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
		m->m_pkthdr.pf_mtag.pftag_hdr = (void *)ip6;
		m->m_pkthdr.pf_mtag.pftag_flags |= PF_TAG_HDR_INET6;
#endif /* PF_ECN */
	} else
#endif /* INET6 */
	{
		ip = mtod(m, struct ip *);
		ipov = (struct ipovly *)ip;
		th = (struct tcphdr *)(void *)(ip + 1);
		/* this picks up the pseudo header (w/o the length) */
		tcp_fillheaders(tp, ip, th);
		if ((tp->ecn_flags & TE_SENDIPECT) != 0 && len &&
		    !SEQ_LT(tp->snd_nxt, tp->snd_max) &&
		    !sack_rxmit && !(flags & TH_SYN)) {
			ip->ip_tos |= IPTOS_ECN_ECT0;
		}
#if PF_ECN
		m->m_pkthdr.pf_mtag.pftag_hdr = (void *)ip;
		m->m_pkthdr.pf_mtag.pftag_flags |= PF_TAG_HDR_INET;
#endif /* PF_ECN */
	}

	/*
	 * Fill in fields, remembering maximum advertised
	 * window for use in delaying messages about window sizes.
	 * If resending a FIN, be sure not to use a new sequence number.
	 */
	if ((flags & TH_FIN) && (tp->t_flags & TF_SENTFIN) &&
	    tp->snd_nxt == tp->snd_max)
		tp->snd_nxt--;
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
		if (len || (flags & (TH_SYN|TH_FIN)) ||
		    tp->t_timer[TCPT_PERSIST]) {
			th->th_seq = htonl(tp->snd_nxt);
			if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
				if (SACK_ENABLED(tp) && len > 1) {
					tcp_rxtseg_insert(tp, tp->snd_nxt,
					    (tp->snd_nxt + len - 1));
				}
				m->m_pkthdr.pkt_flags |= PKTF_TCP_REXMT;
			}
		} else {
			th->th_seq = htonl(tp->snd_max);
		}
	} else {
		th->th_seq = htonl(p->rxmit);
		tcp_rxtseg_insert(tp, p->rxmit, (p->rxmit + len - 1));
		p->rxmit += len;
		tp->sackhint.sack_bytes_rexmit += len;
		m->m_pkthdr.pkt_flags |= PKTF_TCP_REXMT;
	}
	th->th_ack = htonl(tp->rcv_nxt);
	tp->last_ack_sent = tp->rcv_nxt;
#if MPTCP
	/* Initialize the ACK field to a value as 0 ack fields are dropped */
	if (early_data_sent) {
		th->th_ack = th->th_seq + 1;
	}
#endif /* MPTCP */
	if (optlen) {
		bcopy(opt, th + 1, optlen);
		th->th_off = (sizeof (struct tcphdr) + optlen) >> 2;
	}
	th->th_flags = flags;
	/*
	 * Calculate receive window.  Don't shrink window,
	 * but avoid silly window syndrome.
	 */
	if (recwin < (int32_t)(so->so_rcv.sb_hiwat / 4) && recwin < (int)tp->t_maxseg)
		recwin = 0;
	if (recwin < (int32_t)(tp->rcv_adv - tp->rcv_nxt))
		recwin = (int32_t)(tp->rcv_adv - tp->rcv_nxt);
	if (tp->t_flags & TF_SLOWLINK && slowlink_wsize > 0) {
		if (recwin > (int32_t)slowlink_wsize) 
			recwin = slowlink_wsize;
	}

#if TRAFFIC_MGT
	if (tcp_recv_bg == 1  || IS_TCP_RECV_BG(so)) {
		if (tcp_recv_throttle(tp)) {
			uint32_t min_iaj_win = 
				tcp_min_iaj_win * tp->t_maxseg;
			if (tp->iaj_rwintop == 0 ||
				SEQ_LT(tp->iaj_rwintop, tp->rcv_adv))
				tp->iaj_rwintop = tp->rcv_adv; 
			if (SEQ_LT(tp->iaj_rwintop, 
				tp->rcv_nxt + min_iaj_win))
				tp->iaj_rwintop =  tp->rcv_nxt + min_iaj_win;
			recwin = min(tp->iaj_rwintop - tp->rcv_nxt, recwin);
		}
	}
#endif /* TRAFFIC_MGT */

	if (recwin > (int32_t)(TCP_MAXWIN << tp->rcv_scale))
		recwin = (int32_t)(TCP_MAXWIN << tp->rcv_scale);
	th->th_win = htons((u_short) (recwin>>tp->rcv_scale));

	/*
	 * Adjust the RXWIN0SENT flag - indicate that we have advertised
	 * a 0 window.  This may cause the remote transmitter to stall.  This
	 * flag tells soreceive() to disable delayed acknowledgements when
	 * draining the buffer.  This can occur if the receiver is attempting
	 * to read more data then can be buffered prior to transmitting on
	 * the connection.
	 */
	if (th->th_win == 0)
		tp->t_flags |= TF_RXWIN0SENT;
	else
		tp->t_flags &= ~TF_RXWIN0SENT;
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
		tp->snd_up = tp->snd_una;		/* drag it along */
	}

	/*
	 * Put TCP length in extended header, and then
	 * checksum extended header and data.
	 */
	m->m_pkthdr.len = hdrlen + len; /* in6_cksum() need this */
#if INET6
	if (isipv6) {
		/*
		 * ip6_plen is not need to be filled now, and will be filled
		 * in ip6_output.
		 */
		m->m_pkthdr.csum_flags = CSUM_TCPIPV6;
		m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
		if (len + optlen)
			th->th_sum = in_addword(th->th_sum, 
				htons((u_short)(optlen + len)));
	}
	else
#endif /* INET6 */
	{
		m->m_pkthdr.csum_flags = CSUM_TCP;
		m->m_pkthdr.csum_data = offsetof(struct tcphdr, th_sum);
		if (len + optlen)
			th->th_sum = in_addword(th->th_sum, 
				htons((u_short)(optlen + len)));
	}

	/*
	 * Enable TSO and specify the size of the segments.
	 * The TCP pseudo header checksum is always provided.
	 */
	if (tso) {
#if INET6
		if (isipv6)
			m->m_pkthdr.csum_flags |= CSUM_TSO_IPV6;
		else
#endif /* INET6 */
			m->m_pkthdr.csum_flags |= CSUM_TSO_IPV4;

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
		if (flags & (TH_SYN|TH_FIN)) {
			if (flags & TH_SYN)
				tp->snd_nxt++;
			if ((flags & TH_FIN) && 
				!(tp->t_flags & TF_SENTFIN)) {
				tp->snd_nxt++;
				tp->t_flags |= TF_SENTFIN;
			}
		}
		if (sack_rxmit)
			goto timer;
		if (sack_rescue_rxt == TRUE) {
			tp->snd_nxt = old_snd_nxt;
			sack_rescue_rxt = FALSE;
			tcpstat.tcps_pto_in_recovery++;
		} else {
			tp->snd_nxt += len;
		}
		if (SEQ_GT(tp->snd_nxt, tp->snd_max)) {
			tp->snd_max = tp->snd_nxt;
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
				tp->t_rxtshift = 0;
				tp->t_rxtstart = 0;
				tp->t_persist_stop = 0;
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
		if (tcp_enable_tlp && tp->t_state == TCPS_ESTABLISHED &&
		    SACK_ENABLED(tp) && !IN_FASTRECOVERY(tp)
		    && tp->snd_nxt == tp->snd_max
		    && SEQ_GT(tp->snd_nxt, tp->snd_una)
		    && tp->t_rxtshift == 0
		    && (tp->t_flagsext & (TF_SENT_TLPROBE|TF_PKTS_REORDERED)) == 0) {
			u_int32_t pto, srtt, new_rto = 0;

			/*
			 * Using SRTT alone to set PTO can cause spurious
			 * retransmissions on wireless networks where there
			 * is a lot of variance in RTT. Taking variance 
			 * into account will avoid this.
			 */
			srtt = tp->t_srtt >> TCP_RTT_SHIFT;
			pto = ((TCP_REXMTVAL(tp)) * 3) >> 1;
			pto = max (2 * srtt, pto);
			if ((tp->snd_max - tp->snd_una) == tp->t_maxseg)
				pto = max(pto,
				    (((3 * pto) >> 2) + tcp_delack * 2));
			else
				pto = max(10, pto);

			/* if RTO is less than PTO, choose RTO instead */
			if (tp->t_rxtcur < pto) {
				/*
				 * Schedule PTO instead of RTO in favor of
				 * fast recovery.
				 */
				pto = tp->t_rxtcur;

 				/* Reset the next RTO to be after PTO. */
				TCPT_RANGESET(new_rto,
				    (pto + TCP_REXMTVAL(tp)),
				    max(tp->t_rttmin, tp->t_rttcur + 2),
				    TCPTV_REXMTMAX, 0);
				tp->t_timer[TCPT_REXMT] =
				    OFFSET_FROM_START(tp, new_rto);
			}
			tp->t_timer[TCPT_PTO] = OFFSET_FROM_START(tp, pto);
		}
	} else {
		/*
		 * Persist case, update snd_max but since we are in
		 * persist mode (no window) we do not update snd_nxt.
		 */
		int xlen = len;
		if (flags & TH_SYN)
			++xlen;
		if ((flags & TH_FIN) && 
			!(tp->t_flags & TF_SENTFIN)) {
			++xlen;
			tp->t_flags |= TF_SENTFIN;
		}
		if (SEQ_GT(tp->snd_nxt + xlen, tp->snd_max))
			tp->snd_max = tp->snd_nxt + len;
	}

#if TCPDEBUG
	/*
	 * Trace.
	 */
	if (so_options & SO_DEBUG)
		tcp_trace(TA_OUTPUT, tp->t_state, tp, mtod(m, void *), th, 0);
#endif

	/*
	 * Fill in IP length and desired time to live and
	 * send to IP level.  There should be a better way
	 * to handle ttl and tos; we could keep them in
	 * the template, but need a way to checksum without them.
	 */
#if INET6
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
		    sendalot,0,0);
	} else
#endif /* INET6 */
	{
		ip->ip_len = m->m_pkthdr.len;
		ip->ip_ttl = inp->inp_ip_ttl;	/* XXX */
		ip->ip_tos |= (inp->inp_ip_tos & ~IPTOS_ECN_MASK);/* XXX */
 		KERNEL_DEBUG(DBG_LAYER_BEG,
 		    ((inp->inp_fport << 16) | inp->inp_lport),
 		    (((inp->inp_laddr.s_addr & 0xffff) << 16) |
 		    (inp->inp_faddr.s_addr & 0xffff)), 0,0,0);
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
#if INET6
	if (!isipv6)
#endif /* INET6 */
		if (path_mtu_discovery && (tp->t_flags & TF_PMTUD))
			ip->ip_off |= IP_DF;

#if NECP
	{
		necp_kernel_policy_id policy_id;
		u_int32_t route_rule_id;
		if (!necp_socket_is_allowed_to_send_recv(inp, &policy_id, &route_rule_id)) {
			m_freem(m);
			error = EHOSTUNREACH;
			goto out;
		}

		necp_mark_packet_from_socket(m, inp, policy_id, route_rule_id);
	}
#endif /* NECP */

#if IPSEC
	if (inp->inp_sp != NULL)
		ipsec_setsocket(m, so);
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
	m->m_pkthdr.pkt_flags |= PKTF_FLOW_ID | PKTF_FLOW_LOCALSRC;
#if MPTCP
	/* Disable flow advisory when using MPTCP. */
	if (!(tp->t_mpflags & TMPF_MPTCP_TRUE))
#endif /* MPTCP */
		m->m_pkthdr.pkt_flags |= PKTF_FLOW_ADV;
	m->m_pkthdr.pkt_proto = IPPROTO_TCP;

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
		if (tcp_prioritize_acks != 0 && len == 0 &&
		    (inp->inp_last_outifp->if_eflags & 
			(IFEF_TXSTART | IFEF_NOACKPRI)) == IFEF_TXSTART &&
		    th->th_flags == TH_ACK && tp->snd_una == tp->snd_max &&
		    tp->t_timer[TCPT_REXMT] == 0) {
			svc_flags |= PKT_SCF_TCP_ACK;
		}
		set_packet_service_class(m, so, MBUF_SC_UNSPEC, svc_flags);
	}

	tp->t_pktlist_sentlen += len;
	tp->t_lastchain++;

#if INET6
	if (isipv6) {
		DTRACE_TCP5(send, struct mbuf *, m, struct inpcb *, inp,
			struct ip6 *, ip6, struct tcpcb *, tp, struct tcphdr *,
			th);
	} else
#endif /* INET6 */
	{
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

	if ((lro_ackmore) && (!sackoptlen) && (!tp->t_timer[TCPT_PERSIST]) &&
			((th->th_flags & TH_ACK) == TH_ACK) && (!len) &&
			(tp->t_state == TCPS_ESTABLISHED)) {
		/* For a pure ACK, see if you need to send more of them */	
		mnext = tcp_send_lroacks(tp, m, th);
		if (mnext) {
			tp->t_pktlist_tail->m_nextpkt = mnext;
			if (mnext->m_nextpkt == NULL) {
				tp->t_pktlist_tail = mnext;
				tp->t_lastchain++;
			} else {
				struct mbuf *tail, *next;
				next = mnext->m_nextpkt;
				tail = next->m_nextpkt;
				while (tail) {
					next = tail;
					tail = tail->m_nextpkt;
					tp->t_lastchain++;
				}
				tp->t_pktlist_tail = next;
			}
		}
	}

	if (sendalot == 0 || (tp->t_state != TCPS_ESTABLISHED) ||
	    (tp->snd_cwnd <= (tp->snd_wnd / 8)) ||
	    (tp->t_flags & (TH_PUSH | TF_ACKNOW)) ||
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
			    (sack_rxmit | (sack_bytes_rxmt != 0)), recwin,
#if INET6
			    isipv6);
#else /* INET6 */
			    0);
#endif /* !INET6 */
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
			return (0);
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
					} else {
						lost = p->rxmit - tp->snd_una;
						p->rxmit = tp->snd_una;
					}
					tp->sackhint.sack_bytes_rexmit -= lost;
				} else {
					if (SEQ_GT((tp->snd_nxt - lost),
						tp->snd_una))
						tp->snd_nxt -= lost;
					else
						tp->snd_nxt = tp->snd_una;
				}
			}
		}
out:
		if (tp->t_pktlist_head != NULL)
			m_freem_list(tp->t_pktlist_head);
		TCP_PKTLIST_CLEAR(tp);

		if (error == ENOBUFS) {
			if (!tp->t_timer[TCPT_REXMT] &&
				!tp->t_timer[TCPT_PERSIST])
				tp->t_timer[TCPT_REXMT] = 
					OFFSET_FROM_START(tp, tp->t_rxtcur);
			tp->snd_cwnd = tp->t_maxseg;
			tp->t_bytes_acked = 0;
			tcp_check_timer_state(tp);
			KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);

			tcp_ccdbg_trace(tp, NULL, TCP_CC_OUTPUT_ERROR);
			return (0);
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
			if (tso)
				tp->t_flags &= ~TF_TSO;

			tcp_mtudisc(inp, 0);
			tcp_check_timer_state(tp);

			KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
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
		KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
		return (error);
	}

	tcpstat.tcps_sndtotal++;

	KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END,0,0,0,0,0);
	if (sendalot)
		goto again;

	tcp_check_timer_state(tp);
	return (0);
}

static int
tcp_ip_output(struct socket *so, struct tcpcb *tp, struct mbuf *pkt,
    int cnt, struct mbuf *opt, int flags, int sack_in_progress, int recwin,
    boolean_t isipv6)
{
	int error = 0;
	boolean_t chain;
	boolean_t unlocked = FALSE;
	boolean_t ifdenied = FALSE;
	struct inpcb *inp = tp->t_inpcb;
	struct ip_out_args ipoa =
	    { IFSCOPE_NONE, { 0 }, IPOAF_SELECT_SRCIF|IPOAF_BOUND_SRCADDR, 0 };
	struct route ro;
	struct ifnet *outif = NULL;
#if INET6
	struct ip6_out_args ip6oa =
	    { IFSCOPE_NONE, { 0 }, IP6OAF_SELECT_SRCIF|IP6OAF_BOUND_SRCADDR, 0 };
	struct route_in6 ro6;
	struct flowadv *adv =
	    (isipv6 ? &ip6oa.ip6oa_flowadv : &ipoa.ipoa_flowadv);
#else /* INET6 */
	struct flowadv *adv = &ipoa.ipoa_flowadv;
#endif /* !INET6 */

	/* If socket was bound to an ifindex, tell ip_output about it */
	if (inp->inp_flags & INP_BOUND_IF) {
#if INET6
		if (isipv6) {
			ip6oa.ip6oa_boundif = inp->inp_boundifp->if_index;
			ip6oa.ip6oa_flags |= IP6OAF_BOUND_IF;
		} else
#endif /* INET6 */
		{
			ipoa.ipoa_boundif = inp->inp_boundifp->if_index;
			ipoa.ipoa_flags |= IPOAF_BOUND_IF;
		}
	}

	if (INP_NO_CELLULAR(inp)) {
#if INET6
		if (isipv6)
			ip6oa.ip6oa_flags |=  IP6OAF_NO_CELLULAR;
		else
#endif /* INET6 */
			ipoa.ipoa_flags |=  IPOAF_NO_CELLULAR;
	} 
	if (INP_NO_EXPENSIVE(inp)) {
#if INET6
		if (isipv6)
			ip6oa.ip6oa_flags |=  IP6OAF_NO_EXPENSIVE;
		else
#endif /* INET6 */
			ipoa.ipoa_flags |=  IPOAF_NO_EXPENSIVE;
	
	}
	if (INP_AWDL_UNRESTRICTED(inp)) {
#if INET6
		if (isipv6)
			ip6oa.ip6oa_flags |=  IP6OAF_AWDL_UNRESTRICTED;
		else
#endif /* INET6 */
			ipoa.ipoa_flags |=  IPOAF_AWDL_UNRESTRICTED;
	
	}
#if INET6
	if (isipv6)
		flags |= IPV6_OUTARGS;
	else
#endif /* INET6 */
		flags |= IP_OUTARGS;

	/* Copy the cached route and take an extra reference */
#if INET6
	if (isipv6)
		in6p_route_copyout(inp, &ro6);
	else
#endif /* INET6 */
		inp_route_copyout(inp, &ro);

	/*
	 * Data sent (as far as we can tell).
	 * If this advertises a larger window than any other segment,
	 * then remember the size of the advertised window.
	 * Make sure ACK/DELACK conditions are cleared before
	 * we unlock the socket.
	 */
	if (recwin > 0 && SEQ_GT(tp->rcv_nxt + recwin, tp->rcv_adv))
		tp->rcv_adv = tp->rcv_nxt + recwin;
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
	    !IN_FASTRECOVERY(tp)) {

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
#if IPFIREWALL
		&& (fw_enable == 0 || fw_bypass)
#endif
		; // I'm important, not extraneous


	while (pkt != NULL) {
		struct mbuf *npkt = pkt->m_nextpkt;

		if (!chain) {
			pkt->m_nextpkt = NULL;
			/*
			 * If we are not chaining, make sure to set the packet
			 * list count to 0 so that IP takes the right path;
			 * this is important for cases such as IPSec where a
			 * single mbuf might result in multiple mbufs as part
			 * of the encapsulation.  If a non-zero count is passed
			 * down to IP, the head of the chain might change and
			 * we could end up skipping it (thus generating bogus
			 * packets).  Fixing it in IP would be desirable, but
			 * for now this would do it.
			 */
			cnt = 0;
		}
#if INET6
		if (isipv6) {
			error = ip6_output_list(pkt, cnt,
			    inp->in6p_outputopts, &ro6, flags, NULL, NULL,
			    &ip6oa);
			ifdenied = (ip6oa.ip6oa_retflags & IP6OARF_IFDENIED);
		} else {
#endif /* INET6 */
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
			if (!chain)
				m_freem_list(npkt);
			break;
		}
		pkt = npkt;
	}

	if (unlocked)
		socket_lock(so, 0);

	/* 
	 * Enter flow controlled state if the connection is established
	 * and is not in recovery.
	 *
	 * A connection will enter suspended state even if it is in 
	 * recovery.
	 */
	if (((adv->code == FADV_FLOW_CONTROLLED && !IN_FASTRECOVERY(tp)) ||
	    adv->code == FADV_SUSPENDED) && 
	    !(tp->t_flags & TF_CLOSING) &&
	    tp->t_state == TCPS_ESTABLISHED) {
		int rc;
		rc = inp_set_fc_state(inp, adv->code);

		if (rc == 1) 
			tcp_ccdbg_trace(tp, NULL, 
			    ((adv->code == FADV_FLOW_CONTROLLED) ?
			    TCP_CC_FLOW_CONTROL : TCP_CC_SUSPEND));
	}

	/* 
	 * When an interface queue gets suspended, some of the
	 * packets are dropped. Return ENOBUFS, to update the
	 * pcb state.
	 */
	if (adv->code == FADV_SUSPENDED)
		error = ENOBUFS;

	VERIFY(inp->inp_sndinprog_cnt > 0);
	if ( --inp->inp_sndinprog_cnt == 0)
		inp->inp_flags &= ~(INP_FC_FEEDBACK);

#if INET6
	if (isipv6) {
		if (ro6.ro_rt != NULL && (outif = ro6.ro_rt->rt_ifp) !=
		    inp->in6p_last_outifp)
			inp->in6p_last_outifp = outif;
	} else
#endif /* INET6 */
		if (ro.ro_rt != NULL && (outif = ro.ro_rt->rt_ifp) !=
		    inp->inp_last_outifp)
			inp->inp_last_outifp = outif;

	if (error != 0 && ifdenied && 
	    (INP_NO_CELLULAR(inp) || INP_NO_EXPENSIVE(inp)))
		soevent(inp->inp_socket,
		    (SO_FILT_HINT_LOCKED|SO_FILT_HINT_IFDENIED));

	/* Synchronize cached PCB route & options */
#if INET6
	if (isipv6)
		in6p_route_copyin(inp, &ro6);
	else
#endif /* INET6 */
		inp_route_copyin(inp, &ro);

	if (tp->t_state < TCPS_ESTABLISHED && tp->t_rxtshift == 0 && 
		tp->t_inpcb->inp_route.ro_rt != NULL) {
		/* If we found the route and there is an rtt on it
		 * reset the retransmit timer
		 */
		tcp_getrt_rtt(tp, tp->t_inpcb->in6p_route.ro_rt);
		tp->t_timer[TCPT_REXMT] = OFFSET_FROM_START(tp, tp->t_rxtcur);
	}
	return (error);
}

void
tcp_setpersist(tp)
	register struct tcpcb *tp;
{
	int t = ((tp->t_srtt >> 2) + tp->t_rttvar) >> 1;

	/* If a PERSIST_TIMER option was set we will limit the
	 * time the persist timer will be active for that connection
	 * in order to avoid DOS by using zero window probes.
	 * see rdar://5805356
	 */

	if ((tp->t_persist_timeout != 0) &&
       	    (tp->t_timer[TCPT_PERSIST] == 0) &&
       	    (tp->t_persist_stop == 0)) {
		tp->t_persist_stop = tcp_now + tp->t_persist_timeout;
	}

	/*
	 * Start/restart persistance timer.
	 */
	TCPT_RANGESET(tp->t_timer[TCPT_PERSIST],
	    t * tcp_backoff[tp->t_rxtshift],
	    TCPTV_PERSMIN, TCPTV_PERSMAX, 0);
	tp->t_timer[TCPT_PERSIST] = OFFSET_FROM_START(tp, tp->t_timer[TCPT_PERSIST]);

	if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
		tp->t_rxtshift++;
}

/*
 * Send as many acks as data coalesced. Every other packet when stretch
 * ACK is not enabled. Every 8 packets, if stretch ACK is enabled.
 */
static struct mbuf*
tcp_send_lroacks(struct tcpcb *tp, struct mbuf *m, struct tcphdr *th)
{
	struct mbuf *mnext = NULL, *ack_chain = NULL, *tail = NULL;
	int count = 0;
	tcp_seq org_ack = ntohl(th->th_ack);
	tcp_seq prev_ack = 0;
	int tack_offset = 28; /* XXX IPv6 and IP options not supported */
	int twin_offset = 34; /* XXX IPv6 and IP options not supported */
	int ack_size = (tp->t_flags & TF_STRETCHACK) ?
			(maxseg_unacked * tp->t_maxseg) : (tp->t_maxseg << 1);
	int segs_acked = (tp->t_flags & TF_STRETCHACK) ? maxseg_unacked : 2;
	struct mbuf *prev_ack_pkt = NULL;
	struct socket *so = tp->t_inpcb->inp_socket;
	unsigned short winsz = ntohs(th->th_win);
	unsigned int scaled_win = winsz<<tp->rcv_scale;
	tcp_seq win_rtedge = org_ack + scaled_win;

	count = tp->t_lropktlen/tp->t_maxseg;

	prev_ack = (org_ack - tp->t_lropktlen) + ack_size;
	if (prev_ack < org_ack) {
		ack_chain = m_dup(m, M_DONTWAIT);
		if (ack_chain) {
			th->th_ack = htonl(prev_ack);
			/* Keep adv window constant for duplicated ACK packets */
			scaled_win = win_rtedge - prev_ack;
			if (scaled_win > (int32_t)(TCP_MAXWIN << tp->rcv_scale))
				scaled_win = (int32_t)(TCP_MAXWIN << tp->rcv_scale);
			th->th_win = htons(scaled_win>>tp->rcv_scale);
			if (lrodebug == 5) {
				printf("%s: win = %d winsz = %d sc = %d"
				    " lro_len %d %d\n",
				    __func__, scaled_win>>tp->rcv_scale, winsz,
				    tp->rcv_scale, tp->t_lropktlen, count);
			}
			tail = ack_chain;
			count -= segs_acked; /* accounts for prev_ack packet */
			count = (count <= segs_acked) ? 0 : count - segs_acked;
			tcpstat.tcps_sndacks++;
			so_tc_update_stats(m, so, m_get_service_class(m));
		} else {
			return NULL;
		}
	}
	else {
		tp->t_lropktlen = 0;
		return NULL;
	}

	prev_ack_pkt = ack_chain;

	while (count > 0) {
		if ((prev_ack + ack_size) < org_ack) {
			prev_ack += ack_size;
		} else {
			/*
			 * The last ACK sent must have the ACK number that TCP
			 * thinks is the last sent ACK number.
			 */
			 prev_ack = org_ack;
		}
		mnext = m_dup(prev_ack_pkt, M_DONTWAIT);
		if (mnext) {
			/* Keep adv window constant for duplicated ACK packets */
			scaled_win = win_rtedge - prev_ack;
			if (scaled_win > (int32_t)(TCP_MAXWIN << tp->rcv_scale))
				scaled_win = (int32_t)(TCP_MAXWIN << tp->rcv_scale);
			winsz = htons(scaled_win>>tp->rcv_scale);
			if (lrodebug == 5) {
				printf("%s: winsz = %d ack %x count %d\n",
			    	    __func__, scaled_win>>tp->rcv_scale,
				    prev_ack, count);
			}
			bcopy(&winsz, mtod(prev_ack_pkt, caddr_t) + twin_offset, 2);
			HTONL(prev_ack);
			bcopy(&prev_ack, mtod(prev_ack_pkt, caddr_t) + tack_offset, 4);
			NTOHL(prev_ack);
			tail->m_nextpkt = mnext;
			tail = mnext;
			count -= segs_acked;
			tcpstat.tcps_sndacks++;
			so_tc_update_stats(m, so, m_get_service_class(m));
		} else {
			if (lrodebug == 5) {
				printf("%s: failed to alloc mbuf.\n", __func__);
			}
			break;
		}
		prev_ack_pkt = mnext;
	}
	tp->t_lropktlen = 0;
	return ack_chain;
}

static int
tcp_recv_throttle (struct tcpcb *tp)
{
	uint32_t base_rtt, newsize;
	int32_t qdelay;
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
		if (tp->t_flagsext & TF_RECV_THROTTLE)
			return (1);

		base_rtt = get_base_rtt(tp);
		
		if (base_rtt != 0 && tp->t_rttcur != 0) {
			qdelay = tp->t_rttcur - base_rtt;
			/*
			 * if latency increased on a background flow,
			 * return 1 to start throttling.
			 */
			if (qdelay > target_qdelay) {
				tp->t_flagsext |= TF_RECV_THROTTLE;

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
				return (1);
			} else {
				return (0);
			}
		}
	}

	/*
	 * Timestamps are not supported or there is no good RTT
	 * measurement. Use IPDV in this case.
	 */
	if (tp->acc_iaj > tcp_acc_iaj_react_limit)
		return (1);
	
	return (0);
}
