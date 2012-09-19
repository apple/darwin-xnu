/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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

#define DBG_LAYER_BEG		NETDBG_CODE(DBG_NETTCP, 1)
#define DBG_LAYER_END		NETDBG_CODE(DBG_NETTCP, 3)
#define DBG_FNC_TCP_OUTPUT	NETDBG_CODE(DBG_NETTCP, (4 << 8) | 1)

#ifdef notyet
extern struct mbuf *m_copypack();
#endif

int path_mtu_discovery = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, path_mtu_discovery, CTLFLAG_RW | CTLFLAG_LOCKED,
	&path_mtu_discovery, 1, "Enable Path MTU Discovery");

int ss_fltsz = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, slowstart_flightsize, CTLFLAG_RW | CTLFLAG_LOCKED,
	&ss_fltsz, 1, "Slow start flight size");

int ss_fltsz_local = 8; /* starts with eight segments max */
SYSCTL_INT(_net_inet_tcp, OID_AUTO, local_slowstart_flightsize, CTLFLAG_RW | CTLFLAG_LOCKED,
	&ss_fltsz_local, 1, "Slow start flight size for local networks");

int	tcp_do_tso = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, tso, CTLFLAG_RW | CTLFLAG_LOCKED,
	&tcp_do_tso, 0, "Enable TCP Segmentation Offload");


int     tcp_ecn_outbound = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, ecn_initiate_out, CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_ecn_outbound,
        0, "Initiate ECN for outbound connections");

int     tcp_ecn_inbound = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, ecn_negotiate_in, CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_ecn_inbound,
        0, "Allow ECN negotiation for inbound connections");

int	tcp_packet_chaining = 50;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, packetchain, CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_packet_chaining,
        0, "Enable TCP output packet chaining");

int	tcp_output_unlocked = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, socket_unlocked_on_output, CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_output_unlocked,
        0, "Unlock TCP when sending packets down to IP");

int tcp_do_rfc3390 = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, rfc3390, CTLFLAG_RW | CTLFLAG_LOCKED,
	&tcp_do_rfc3390, 1, "Calculate intial slowstart cwnd depending on MSS");

int tcp_min_iaj_win = MIN_IAJ_WIN;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, min_iaj_win, CTLFLAG_RW | CTLFLAG_LOCKED,
	&tcp_min_iaj_win, 1, "Minimum recv win based on inter-packet arrival jitter");

int tcp_acc_iaj_react_limit = ACC_IAJ_REACT_LIMIT;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, acc_iaj_react_limit, CTLFLAG_RW | CTLFLAG_LOCKED,
        &tcp_acc_iaj_react_limit, 1, "Accumulated IAJ when receiver starts to react");

uint32_t tcp_do_autosendbuf = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, doautosndbuf, CTLFLAG_RW | CTLFLAG_LOCKED,
        &tcp_do_autosendbuf, 1, "Enable send socket buffer auto-tuning");

uint32_t tcp_autosndbuf_inc = 8 * 1024;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, autosndbufinc, CTLFLAG_RW | CTLFLAG_LOCKED,
        &tcp_autosndbuf_inc, 1, "Increment in send socket bufffer size");

uint32_t tcp_autosndbuf_max = 512 * 1024;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, autosndbufmax, CTLFLAG_RW | CTLFLAG_LOCKED,
        &tcp_autosndbuf_max, 1, "Maximum send socket buffer size");

uint32_t tcp_prioritize_acks = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, ack_prioritize, CTLFLAG_RW | CTLFLAG_LOCKED,
        &tcp_prioritize_acks, 1, "Prioritize pure acks");

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

extern vm_size_t	so_cache_zone_element_size;
#if RANDOM_IP_ID
extern int 		ip_use_randomid;
#endif /* RANDOM_IP_ID */
extern u_int32_t dlil_filter_count;
extern u_int32_t kipf_count;
extern int tcp_recv_bg;
extern int maxseg_unacked;

static int tcp_ip_output(struct socket *, struct tcpcb *, struct mbuf *, int,
    struct mbuf *, int, int, int32_t, boolean_t);

extern uint32_t get_base_rtt(struct tcpcb *tp);
static struct mbuf* tcp_send_lroacks(struct tcpcb *tp, struct mbuf *m, struct tcphdr *th);

static __inline__ u_int16_t
get_socket_id(struct socket * s)
{
	u_int16_t 		val;

	if (so_cache_zone_element_size == 0) {
		return (0);
	}
	val = (u_int16_t)(((uintptr_t)s) / so_cache_zone_element_size);
	if (val == 0) {
		val = 0xffff;
	}
	return (val);
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
	struct socket *so = tp->t_inpcb->inp_socket;
	int32_t len, recwin, sendwin, off;
	int flags, error;
	register struct mbuf *m;
	struct ip *ip = NULL;
	register struct ipovly *ipov = NULL;
#if INET6
	struct ip6_hdr *ip6 = NULL;
#endif /* INET6 */
	register struct tcphdr *th;
	u_char opt[TCP_MAXOLEN];
	unsigned ipoptlen, optlen, hdrlen;
	int idle, sendalot, lost = 0;
	int i, sack_rxmit;
	int tso = 0;
	int sack_bytes_rxmt;
	struct sackhole *p;
#ifdef IPSEC
	unsigned ipsec_optlen = 0;
#endif
	int    last_off = 0;
	int    m_off;
	int    idle_time = 0;
	struct mbuf *m_lastm = NULL;
	struct mbuf *m_head = NULL;
	struct mbuf *packetlist = NULL;
	struct mbuf *tp_inp_options = tp->t_inpcb->inp_depend4.inp4_options;
#if INET6
	int isipv6 = tp->t_inpcb->inp_vflag & INP_IPV6 ;
#endif
	short packchain_listadd = 0;
	u_int16_t	socket_id = get_socket_id(so);
	int so_options = so->so_options;
	struct rtentry *rt;
	u_int32_t basertt, svc_flags = 0, allocated_len;
	u_int32_t lro_ackmore = (tp->t_lropktlen != 0) ? 1 : 0;
	struct mbuf *mnext = NULL;
	int sackoptlen = 0;

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
		if (CC_ALGO(tp)->after_idle != NULL) 
			CC_ALGO(tp)->after_idle(tp);
		DTRACE_TCP5(cc, void, NULL, struct inpcb *, tp->t_inpcb,
			struct tcpcb *, tp, struct tcphdr *, NULL,
			int32_t, TCP_CC_IDLE_TIMEOUT);
	}
	tp->t_flags &= ~TF_LASTIDLE;
	if (idle) {
		if (tp->t_flags & TF_MORETOCOME) {
			tp->t_flags |= TF_LASTIDLE;
			idle = 0;
		}
	}
again:
	KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_START, 0,0,0,0,0);

#if INET6
	if (isipv6) {
		KERNEL_DEBUG(DBG_LAYER_BEG,
		     ((tp->t_inpcb->inp_fport << 16) | tp->t_inpcb->inp_lport),
		     (((tp->t_inpcb->in6p_laddr.s6_addr16[0] & 0xffff) << 16) |
		      (tp->t_inpcb->in6p_faddr.s6_addr16[0] & 0xffff)),
		     sendalot,0,0);
	} else
#endif

	{
		KERNEL_DEBUG(DBG_LAYER_BEG,
		     ((tp->t_inpcb->inp_fport << 16) | tp->t_inpcb->inp_lport),
		     (((tp->t_inpcb->inp_laddr.s_addr & 0xffff) << 16) |
		      (tp->t_inpcb->inp_faddr.s_addr & 0xffff)),
		     sendalot,0,0);
	}
	/*
	 * If the route generation id changed, we need to check that our
	 * local (source) IP address is still valid. If it isn't either
	 * return error or silently do nothing (assuming the address will
	 * come back before the TCP connection times out).
	 */
	rt = tp->t_inpcb->inp_route.ro_rt;
	if (rt != NULL && (!(rt->rt_flags & RTF_UP) ||
	    rt->generation_id != route_generation)) {
		struct ifnet *ifp;
		struct in_ifaddr *ia = NULL;
		struct in6_ifaddr *ia6 = NULL;
		int found_srcaddr = 0;

		/* disable multipages at the socket */
		somultipages(so, FALSE);

		/* Disable TSO for the socket until we know more */
		tp->t_flags &= ~TF_TSO;

		if (isipv6) {
			ia6 = ifa_foraddr6(&tp->t_inpcb->in6p_laddr);
			if (ia6 != NULL)
				found_srcaddr = 1;
		} else {
			ia = ifa_foraddr(tp->t_inpcb->inp_laddr.s_addr);
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

			/* set Retransmit  timer if it wasn't set
			 * reset Persist timer and shift register as the
			 * advertised peer window may not be valid anymore
			 */

                        if (!tp->t_timer[TCPT_REXMT]) {
                                tp->t_timer[TCPT_REXMT] = OFFSET_FROM_START(tp, tp->t_rxtcur);
				if (tp->t_timer[TCPT_PERSIST]) {
					tp->t_timer[TCPT_PERSIST] = 0;
					tp->t_rxtshift = 0;
					tp->t_persist_stop = 0;
					tp->rxt_start = 0;
				}
			}

			if (tp->t_pktlist_head != NULL)
				m_freem_list(tp->t_pktlist_head);
			TCP_PKTLIST_CLEAR(tp);

			/* drop connection if source address isn't available */
			if (so->so_flags & SOF_NOADDRAVAIL) { 
				tcp_drop(tp, EADDRNOTAVAIL);
				return(EADDRNOTAVAIL);
			}
			else {
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
		}
		if (rt->rt_flags & RTF_UP)
			rt->generation_id = route_generation;
		/*
		 * See if we should do MTU discovery. Don't do it if:
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

		RT_UNLOCK(rt);
	}

	/*
	 * If we've recently taken a timeout, snd_max will be greater than
	 * snd_nxt.  There may be SACK information that allows us to avoid
	 * resending already delivered data.  Adjust snd_nxt accordingly.
	 */
	if (tp->sack_enable && SEQ_LT(tp->snd_nxt, tp->snd_max))
		tcp_sack_adjust(tp);
	sendalot = 0;
	off = tp->snd_nxt - tp->snd_una;
	sendwin = min(tp->snd_wnd, tp->snd_cwnd);

	if (tp->t_flags & TF_SLOWLINK && slowlink_wsize > 0)
		sendwin = min(sendwin, slowlink_wsize);

	flags = tcp_outflags[tp->t_state];
	/*
	 * Send any SACK-generated retransmissions.  If we're explicitly trying
	 * to send out new data (when sendalot is 1), bypass this function.
	 * If we retransmit in fast recovery mode, decrement snd_cwnd, since
	 * we're replacing a (future) new transmission with a retransmission
	 * now, and we previously incremented snd_cwnd in tcp_input().
	 */
	/*
	 * Still in sack recovery , reset rxmit flag to zero.
	 */
	sack_rxmit = 0;
	sack_bytes_rxmt = 0;
	len = 0;
	p = NULL;
	if (tp->sack_enable && IN_FASTRECOVERY(tp) &&
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
			off = p->rxmit - tp->snd_una; /* update off only if we really transmit SACK data */
			sack_rxmit = 1;
			sendalot = 1;
			tcpstat.tcps_sack_rexmits++;
			tcpstat.tcps_sack_rexmit_bytes +=
			    min(len, tp->t_maxseg);
			if (nstat_collect) {
				nstat_route_tx(tp->t_inpcb->inp_route.ro_rt, 1, 
					min(len, tp->t_maxseg), NSTAT_TX_FLAG_RETRANSMIT);
				locked_add_64(&tp->t_inpcb->inp_stat->txpackets, 1);
				locked_add_64(&tp->t_inpcb->inp_stat->txbytes, 
					min(len, tp->t_maxseg));
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
	if (tp->t_force) {
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
			tp->rxt_start = 0;
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
		if (sack_bytes_rxmt == 0)
			len = min(so->so_snd.sb_cc, sendwin) - off;
		else {
			int32_t cwin;

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
				cwin = tp->snd_cwnd - 
					(tp->snd_nxt - tp->sack_newdata) -
					sack_bytes_rxmt;
				if (cwin < 0)
					cwin = 0;
				len = imin(len, cwin);
			}
			else 
				len = 0;
		}
	}

	/*
	 * Lop off SYN bit if it has already been sent.  However, if this
	 * is SYN-SENT state and if segment contains data and if we don't
	 * know that foreign host supports TAO, suppress sending segment.
	 */
	if ((flags & TH_SYN) && SEQ_GT(tp->snd_nxt, tp->snd_una)) {
		flags &= ~TH_SYN;
		off--, len++;
		if (len > 0 && tp->t_state == TCPS_SYN_SENT) {
			while (tp->t_inpcb->inp_sndinprog_cnt == 0 &&
				tp->t_pktlist_head != NULL) {
				packetlist = tp->t_pktlist_head;
				packchain_listadd = tp->t_lastchain;
				packchain_sent++;
				TCP_PKTLIST_CLEAR(tp);

				error = tcp_ip_output(so, tp, packetlist,
				    packchain_listadd, tp_inp_options,
				    (so_options & SO_DONTROUTE),
				    (sack_rxmit | (sack_bytes_rxmt != 0)), 0,
#ifdef INET6
				    isipv6);
#else
				    0);
#endif


			}
			/*
			 * tcp was closed while we were in ip,
			 * resume close 
			 */
			if (tp->t_inpcb->inp_sndinprog_cnt == 0 &&
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
	 */
	if ((flags & TH_SYN) && (tp->t_flags & TF_NOOPT)) {
		len = 0;
		flags &= ~TH_FIN;
	}

	/* The check here used to be (len < 0). Some times len is zero when
	 * the congestion window is closed and we need to check if persist timer
	 * has to be set in that case. But don't set persist until connection 
	 * is established.
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
			tp->t_rxtshift = 0;
			tp->rxt_start = 0;
			tp->snd_nxt = tp->snd_una;
			if (tp->t_timer[TCPT_PERSIST] == 0)
				tcp_setpersist(tp);
		}
	}

	/* Automatic sizing of send socket buffer. Increase the send socket buffer
	 * size if all of the following criteria are met
	 *	1. the receiver has enough buffer space for this data
	 *	2. send buffer is filled to 7/8th with data (so we actually
	 *	   have data to make use of it);
	 *	3. our send window (slow start and congestion controlled) is
	 *	   larger than sent but unacknowledged data in send buffer.
	 */
	basertt = get_base_rtt(tp);
	if (tcp_do_autosendbuf == 1 &&
	    !INP_WAIT_FOR_IF_FEEDBACK(tp->t_inpcb) && !IN_FASTRECOVERY(tp) &&
	    (so->so_snd.sb_flags & (SB_AUTOSIZE | SB_TRIM)) == SB_AUTOSIZE &&
	    tcp_cansbgrow(&so->so_snd)) {
		if ((tp->snd_wnd / 4 * 5) >= so->so_snd.sb_hiwat &&
			so->so_snd.sb_cc >= (so->so_snd.sb_hiwat / 8 * 7) &&
			sendwin >= (so->so_snd.sb_cc - 
				(tp->snd_nxt - tp->snd_una))) {
			/* Also increase the send buffer only if the 
			 * round-trip time is not increasing because we do
			 * not want to contribute to latency by filling buffers.
			 * We also do not want to hold onto application's
			 * old data for too long. Interactive applications would
			 * rather discard old data.
			 */
			if (tp->t_rttcur <= 
				(basertt + 25)) {
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
	 * TSO may only be used if we are in a pure bulk sending state.  The
	 * presence of TCP-MD5, SACK retransmits, SACK advertizements, ipfw rules
	 * and IP options prevent using TSO.  With TSO the TCP header is the same
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
		if ((tp->t_flags & TF_TSO) && tcp_do_tso &&
#if RANDOM_IP_ID
		    ip_use_randomid &&
#endif /* RANDOM_IP_ID */
		    kipf_count == 0 && dlil_filter_count == 0 &&
		    tp->rcv_numsacks == 0 && sack_rxmit == 0  && sack_bytes_rxmt == 0 &&
		    tp->t_inpcb->inp_options == NULL &&
		    tp->t_inpcb->in6p_options == NULL
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
		if (tp->t_force) {
			tp->t_flags &= ~TF_MAXSEGSNT;
			goto send;
		}
		if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
			if (len >= tp->t_maxseg)
				tp->t_flags |= TF_MAXSEGSNT;
			else
				tp->t_flags &= ~TF_MAXSEGSNT;
			goto send;
		}
		if (sack_rxmit)
			goto send;

		/*
		 * Send new data on the connection only if it is
		 * not flow controlled
		 */
		if (!INP_WAIT_FOR_IF_FEEDBACK(tp->t_inpcb) ||
		    tp->t_state != TCPS_ESTABLISHED) {
			if (len >= tp->t_maxseg) {
				tp->t_flags |= TF_MAXSEGSNT;
				goto send;
			}
			if (!(tp->t_flags & TF_MORETOCOME) &&
			    (idle || tp->t_flags & TF_NODELAY || tp->t_flags & TF_MAXSEGSNT) &&
			    (tp->t_flags & TF_NOPUSH) == 0 &&
			    len + off >= so->so_snd.sb_cc) {
				tp->t_flags &= ~TF_MAXSEGSNT;
				goto send;
			}
			if (len >= tp->max_sndwnd / 2 && tp->max_sndwnd > 0) {
				tp->t_flags &= ~TF_MAXSEGSNT;
				goto send;
			}
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
		int32_t adv = imin(recwin, (int)TCP_MAXWIN << tp->rcv_scale) -
			(tp->rcv_adv - tp->rcv_nxt);

		if (adv >= (int32_t) (2 * tp->t_maxseg)) {
			/* Update only if the resulting scaled value of the window changed, or
			 * if there is a change in the sequence since the last ack.
			 * This avoids what appears as dupe ACKS (see rdar://5640997)
			 *
			 * If streaming is detected avoid sending too many window updates.
			 * We will depend on the delack timer to send a window update
			 * when needed.
			 */
			if ((tp->t_flags & TF_STRETCHACK) == 0 &&
				(tp->last_ack_sent != tp->rcv_nxt || 
				((recwin + adv) >> tp->rcv_scale) > recwin)) {
				goto send;
			}

			/* Make sure that the delayed ack timer is set if we
			 * delayed sending a window update because of streaming
			 * detection.
			 */
			if ((tp->t_flags & TF_STRETCHACK) != 0 &&
				(tp->t_flags & TF_DELACK) == 0) { 
				tp->t_flags |= TF_DELACK;
				tp->t_timer[TCPT_DELACK] = OFFSET_FROM_START(tp, tcp_delack);
			}
		}
		if (4 * adv >= (int32_t) so->so_rcv.sb_hiwat) 
				goto send;
	}

	/*
	 * Send if we owe the peer an ACK, RST, SYN, or urgent data.  ACKNOW
	 * is also a catch-all for the retransmit timer timeout case.
	 */
	if (tp->t_flags & TF_ACKNOW)
		goto send;
	if ((flags & TH_RST) ||
	    ((flags & TH_SYN) && (tp->t_flags & TF_NEEDSYN) == 0))
		goto send;
	if (SEQ_GT(tp->snd_up, tp->snd_una))
		goto send;
	/*
	 * If our state indicates that FIN should be sent
	 * and we have not yet done so, then we need to send.
	 */
	if (flags & TH_FIN &&
	    ((tp->t_flags & TF_SENTFIN) == 0 || tp->snd_nxt == tp->snd_una))
		goto send;
	/*
	 * In SACK, it is possible for tcp_output to fail to send a segment
	 * after the retransmission timer has been turned off.  Make sure
	 * that the retransmission timer is set.
	 */
	if (tp->sack_enable && (tp->t_state >= TCPS_ESTABLISHED) && 
	    SEQ_GT(tp->snd_max, tp->snd_una) &&
	    tp->t_timer[TCPT_REXMT] == 0 &&
	    tp->t_timer[TCPT_PERSIST] == 0) {
			tp->t_timer[TCPT_REXMT] = OFFSET_FROM_START(tp, tp->t_rxtcur);
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
		tp->rxt_start = 0;
		tcp_setpersist(tp);
	}
just_return:
	/*
	 * If there is no reason to send a segment, just return.
	 * but if there is some packets left in the packet list, send them now.
	 */
	while (tp->t_inpcb->inp_sndinprog_cnt == 0 &&
		tp->t_pktlist_head != NULL) {
		packetlist = tp->t_pktlist_head;
		packchain_listadd = tp->t_lastchain;
		packchain_sent++;
		TCP_PKTLIST_CLEAR(tp);

		error = tcp_ip_output(so, tp, packetlist, packchain_listadd,
		    tp_inp_options, (so_options & SO_DONTROUTE),
		    (sack_rxmit | (sack_bytes_rxmt != 0)), recwin,
#ifdef INET6
		    isipv6);
#else
		    0);
#endif
	}
	/* tcp was closed while we were in ip; resume close */
	if (tp->t_inpcb->inp_sndinprog_cnt == 0 &&
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
		}
		
 	}
 	
 	/*
 	  RFC 3168 states that:
 	   - If you ever sent an ECN-setup SYN/SYN-ACK you must be prepared
 	   to handle the TCP ECE flag, even if you also later send a
 	   non-ECN-setup SYN/SYN-ACK.
 	   - If you ever send a non-ECN-setup SYN/SYN-ACK, you must not set
 	   the ip ECT flag.
 	   
 	   It is not clear how the ECE flag would ever be set if you never
 	   set the IP ECT flag on outbound packets. All the same, we use
 	   the TE_SETUPSENT to indicate that we have committed to handling
 	   the TCP ECE flag correctly. We use the TE_SENDIPECT to indicate
 	   whether or not we should set the IP ECT flag on outbound packets.
 	 */
	/*
	 * For a SYN-ACK, send an ECN setup SYN-ACK
	 */
	if (tcp_ecn_inbound && (flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) {
		if ((tp->ecn_flags & TE_SETUPRECEIVED) != 0) {
			if ((tp->ecn_flags & TE_SETUPSENT) == 0) {
				/* Setting TH_ECE makes this an ECN-setup SYN-ACK */
				flags |= TH_ECE;
				
				/*
				 * Record that we sent the ECN-setup and default to
				 * setting IP ECT.
				 */
				tp->ecn_flags |= (TE_SETUPSENT | TE_SENDIPECT);
			}
			else {
				/*
				 * We sent an ECN-setup SYN-ACK but it was dropped.
				 * Fallback to non-ECN-setup SYN-ACK and clear flag
				 * that to indicate we should not send data with IP ECT set.
				 *
				 * Pretend we didn't receive an ECN-setup SYN.
				 */
				tp->ecn_flags &= ~TE_SETUPRECEIVED;
			}
		}
	}
	else if (tcp_ecn_outbound && (flags & (TH_SYN | TH_ACK)) == TH_SYN) {
		if ((tp->ecn_flags & TE_SETUPSENT) == 0) {
			/* Setting TH_ECE and TH_CWR makes this an ECN-setup SYN */
			flags |= (TH_ECE | TH_CWR);
			
			/*
			 * Record that we sent the ECN-setup and default to
			 * setting IP ECT.
			 */
			tp->ecn_flags |= (TE_SETUPSENT | TE_SENDIPECT);
		}
		else {
			/*
			 * We sent an ECN-setup SYN but it was dropped.
			 * Fall back to no ECN and clear flag indicating
			 * we should send data with IP ECT set.
			 */
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

	if (tp->sack_enable && ((tp->t_flags & TF_NOOPT) == 0)) {
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
		    (tp->t_flags & TF_SACK_PERMIT) && tp->rcv_numsacks > 0 &&
		    MAX_TCPOPTLEN - optlen - 2 >= TCPOLEN_SACK) {
			int nsack, padlen;
			u_char *bp = (u_char *)opt + optlen;
			u_int32_t *lp;

			nsack = (MAX_TCPOPTLEN - optlen - 2) / TCPOLEN_SACK;
			nsack = min(nsack, tp->rcv_numsacks);
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

	hdrlen += optlen;

#if INET6
	if (isipv6)
		ipoptlen = ip6_optlen(tp->t_inpcb);
	else
#endif
	{
		if (tp_inp_options) {
			ipoptlen = tp_inp_options->m_len -
				offsetof(struct ipoption, ipopt_list);
		} else
			ipoptlen = 0;
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
		 * If there is still more to send, don't close the connection.
		 */
		flags &= ~TH_FIN;
		if (tso) {
			int32_t tso_maxlen;

			tso_maxlen = tp->tso_max_segment_size ? tp->tso_max_segment_size : TCP_MAXWIN;

			if (len > tso_maxlen - hdrlen - optlen) {
				len = tso_maxlen - hdrlen - optlen;
				len = len - (len % (tp->t_maxopd - optlen));
				sendalot = 1;
			} else if (tp->t_flags & TF_NEEDFIN)
				sendalot = 1;
		} else {
			len = tp->t_maxopd - optlen - ipoptlen;
			sendalot = 1;
		}
	}

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
		tp->t_bwmeas->bw_size = min((so->so_snd.sb_cc - (tp->snd_max - tp->snd_una)),
			tp->t_bwmeas->bw_maxsize);
		tp->t_flagsext |= TF_BWMEAS_INPROGRESS;
		tp->t_bwmeas->bw_start = tp->snd_max;
		tp->t_bwmeas->bw_ts = tcp_now;
	}

	VERIFY(tp->t_inpcb->inp_flowhash != 0);
	
	/*
	 * Grab a header mbuf, attaching a copy of data to
	 * be transmitted, and initialize the header from
	 * the template for sends on this connection.
	 */
	if (len) {
		if (tp->t_force && len == 1)
			tcpstat.tcps_sndprobe++;
		else if (SEQ_LT(tp->snd_nxt, tp->snd_max) || sack_rxmit) {
			tcpstat.tcps_sndrexmitpack++;
			tcpstat.tcps_sndrexmitbyte += len;
			if (nstat_collect) {
				nstat_route_tx(tp->t_inpcb->inp_route.ro_rt, 1, 
					len, NSTAT_TX_FLAG_RETRANSMIT);
				locked_add_64(&tp->t_inpcb->inp_stat->txpackets, 1);
				locked_add_64(&tp->t_inpcb->inp_stat->txbytes, len);
				tp->t_stat.txretransmitbytes += len;
			}
		} else {
			tcpstat.tcps_sndpack++;
			tcpstat.tcps_sndbyte += len;
			if (nstat_collect) {
				locked_add_64(&tp->t_inpcb->inp_stat->txpackets, 1);
				locked_add_64(&tp->t_inpcb->inp_stat->txbytes, len);
			}
		}
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
		        if (m != NULL) {
			        m->m_next = m_copy(so->so_snd.sb_mb, off, (int) len);
				if (m->m_next == 0) {
				        (void) m_free(m);
					error = ENOBUFS;
					goto out;
				}
			} else {
			        /*
				 * determine whether the mbuf pointer and offset passed back by the 'last' call
				 * to m_copym_with_hdrs are still valid... if the head of the socket chain has
				 * changed (due to an incoming ACK for instance), or the offset into the chain we
				 * just computed is different from the one last returned by m_copym_with_hdrs (perhaps
				 * we're re-transmitting a packet sent earlier), than we can't pass the mbuf pointer and
				 * offset into it as valid hints for m_copym_with_hdrs to use (if valid, these hints allow
				 * m_copym_with_hdrs to avoid rescanning from the beginning of the socket buffer mbuf list.
				 * setting the mbuf pointer to NULL is sufficient to disable the hint mechanism.
				 */
			        if (m_head != so->so_snd.sb_mb || sack_rxmit || last_off != off)
				        m_lastm = NULL;
				last_off = off + len;
				m_head = so->so_snd.sb_mb;
	
				/* makes sure we still have data left to be sent at this point */
				if (m_head == NULL) {
					error = 0; /* should we return an error? */
					goto out;
				}
				
				/*
				 * m_copym_with_hdrs will always return the last mbuf pointer and the offset into it that
				 * it acted on to fullfill the current request, whether a valid 'hint' was passed in or not
				 */
			        if ((m = m_copym_with_hdrs(so->so_snd.sb_mb, off, len, M_DONTWAIT, &m_lastm, &m_off)) == NULL) {
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
		 */
		if (off + len == so->so_snd.sb_cc)
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
#if CONFIG_MACF_NET
	mac_mbuf_label_associate_inpcb(tp->t_inpcb, m);
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
	} else
#endif /* INET6 */
	{
		ip = mtod(m, struct ip *);
		ipov = (struct ipovly *)ip;
		th = (struct tcphdr *)(void *)(ip + 1);
		/* this picks up the pseudo header (w/o the length) */
		tcp_fillheaders(tp, ip, th);
		if ((tp->ecn_flags & TE_SENDIPECT) != 0 && len &&
			!SEQ_LT(tp->snd_nxt, tp->snd_max) && !sack_rxmit) {
			ip->ip_tos = IPTOS_ECN_ECT0;
		}
	}

	/*
	 * Fill in fields, remembering maximum advertised
	 * window for use in delaying messages about window sizes.
	 * If resending a FIN, be sure not to use a new sequence number.
	 */
	if (flags & TH_FIN && (tp->t_flags & TF_SENTFIN) &&
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
	 */
	if (sack_rxmit == 0) {
		if (len || (flags & (TH_SYN|TH_FIN)) || tp->t_timer[TCPT_PERSIST])
			th->th_seq = htonl(tp->snd_nxt);
		else
			th->th_seq = htonl(tp->snd_max);
	} else {
		th->th_seq = htonl(p->rxmit);
		p->rxmit += len;
		tp->sackhint.sack_bytes_rexmit += len;
	}
	th->th_ack = htonl(tp->rcv_nxt);
	tp->last_ack_sent = tp->rcv_nxt;

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
		if (tp->acc_iaj > tcp_acc_iaj_react_limit) {
			uint32_t min_iaj_win = tcp_min_iaj_win * tp->t_maxseg;
			if (tp->iaj_rwintop == 0 ||
				SEQ_LT(tp->iaj_rwintop, tp->rcv_adv))
				tp->iaj_rwintop = tp->rcv_adv; 
			if (SEQ_LT(tp->iaj_rwintop, tp->rcv_nxt + min_iaj_win))
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
	} else
		/*
		 * If no urgent pointer to send, then we pull
		 * the urgent pointer to the left edge of the send window
		 * so that it doesn't drift into the send window on sequence
		 * number wraparound.
		 */
		tp->snd_up = tp->snd_una;		/* drag it along */

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
			m->m_pkthdr.csum_flags = CSUM_TSO_IPV6;
		else
#endif /* INET6 */
			m->m_pkthdr.csum_flags = CSUM_TSO_IPV4;

		m->m_pkthdr.tso_segsz = tp->t_maxopd - optlen;
	}
	else
		m->m_pkthdr.tso_segsz = 0;

	/*
	 * In transmit state, time the transmission and arrange for
	 * the retransmit.  In persist state, just set snd_max.
	 */
	if (tp->t_force == 0 || tp->t_timer[TCPT_PERSIST] == 0) {
		tcp_seq startseq = tp->snd_nxt;

		/*
		 * Advance snd_nxt over sequence space of this segment.
		 */
		if (flags & (TH_SYN|TH_FIN)) {
			if (flags & TH_SYN)
				tp->snd_nxt++;
			if (flags & TH_FIN) {
				tp->snd_nxt++;
				tp->t_flags |= TF_SENTFIN;
			}
		}
		if (sack_rxmit)
			goto timer;
		tp->snd_nxt += len;
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
			}
		}

		/*
		 * Set retransmit timer if not currently set,
		 * and not doing an ack or a keep-alive probe.
		 * Initial value for retransmit timer is smoothed
		 * round-trip time + 2 * round-trip time variance.
		 * Initialize shift counter which is used for backoff
		 * of retransmit time.
		 */
timer:
		if (tp->t_timer[TCPT_REXMT] == 0 &&
		    ((sack_rxmit && tp->snd_nxt != tp->snd_max) ||
			tp->snd_nxt != tp->snd_una)) {
			if (tp->t_timer[TCPT_PERSIST]) {
				tp->t_timer[TCPT_PERSIST] = 0;
				tp->t_rxtshift = 0;
				tp->rxt_start = 0;
				tp->t_persist_stop = 0;
			}
			tp->t_timer[TCPT_REXMT] = OFFSET_FROM_START(tp, tp->t_rxtcur);
		}
	} else {
		/*
		 * Persist case, update snd_max but since we are in
		 * persist mode (no window) we do not update snd_nxt.
		 */
		int xlen = len;
		if (flags & TH_SYN)
			++xlen;
		if (flags & TH_FIN) {
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
#ifdef INET6
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
		ip6->ip6_hlim = in6_selecthlim(tp->t_inpcb,
					       tp->t_inpcb->in6p_route.ro_rt ?
					       tp->t_inpcb->in6p_route.ro_rt->rt_ifp
					       : NULL);

		/* TODO: IPv6 IP6TOS_ECT bit on */
		KERNEL_DEBUG(DBG_LAYER_BEG,
		    ((tp->t_inpcb->inp_fport << 16) | tp->t_inpcb->inp_lport),
		    (((tp->t_inpcb->in6p_laddr.s6_addr16[0] & 0xffff) << 16) |
		    (tp->t_inpcb->in6p_faddr.s6_addr16[0] & 0xffff)),
		    sendalot,0,0);
	} else
#endif /* INET6 */
	{
		ip->ip_len = m->m_pkthdr.len;
		ip->ip_ttl = tp->t_inpcb->inp_ip_ttl;	/* XXX */
		ip->ip_tos |= (tp->t_inpcb->inp_ip_tos & ~IPTOS_ECN_MASK);/* XXX */
 		KERNEL_DEBUG(DBG_LAYER_BEG,
 		    ((tp->t_inpcb->inp_fport << 16) | tp->t_inpcb->inp_lport),
 		    (((tp->t_inpcb->inp_laddr.s_addr & 0xffff) << 16) |
 		    (tp->t_inpcb->inp_faddr.s_addr & 0xffff)),
 		    0,0,0);
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
#ifdef INET6
	if (!isipv6)
#endif
		if (path_mtu_discovery && (tp->t_flags & TF_PMTUD))
			ip->ip_off |= IP_DF;

#if IPSEC
	if (ipsec_bypass == 0)
 		ipsec_setsocket(m, so);
#endif /*IPSEC*/

	/*
	 * The socket is kept locked while sending out packets in ip_output, even if packet chaining is not active.
	 */
	lost = 0;
	m->m_pkthdr.socket_id = socket_id;

	/*
	 * Embed the flow hash in pkt hdr and mark the packet as
	 * capable of flow controlling
	 */
	m->m_pkthdr.m_flowhash = tp->t_inpcb->inp_flowhash;
	m->m_pkthdr.m_fhflags |=
	    (PF_TAG_TCP | PF_TAG_FLOWHASH | PF_TAG_FLOWADV);

	m->m_nextpkt = NULL;

	if (tp->t_inpcb->inp_last_outifp != NULL &&
	    tp->t_inpcb->inp_last_outifp != lo_ifp) {
		/* Hint to prioritize this packet if
		 * 1. if the packet has no data
		 * 2. the interface supports transmit-start model and did 
		 *    not disable ACK prioritization.
		 * 3. Only ACK flag is set.
		 * 4. there is no outstanding data on this connection.
		 */
		if (tcp_prioritize_acks != 0 && len == 0 &&
		    (tp->t_inpcb->inp_last_outifp->if_eflags & 
			(IFEF_TXSTART | IFEF_NOACKPRI)) == IFEF_TXSTART &&
		    th->th_flags == TH_ACK && tp->snd_una == tp->snd_max &&
		    tp->t_timer[TCPT_REXMT] == 0) {
			svc_flags |= PKT_SCF_TCP_ACK;
		}
		set_packet_service_class(m, so, MBUF_SC_UNSPEC, svc_flags);
	}

	tp->t_pktlist_sentlen += len;
	tp->t_lastchain++;

#ifdef INET6
	if (isipv6) {
		DTRACE_TCP5(send, struct mbuf *, m, struct inpcb *, tp->t_inpcb,
			struct ip6 *, ip6, struct tcpcb *, tp, struct tcphdr *,
			th);
	} else
#endif
	{
		DTRACE_TCP5(send, struct mbuf *, m, struct inpcb *, tp->t_inpcb,
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
	      (tp->t_flags & (TH_PUSH | TF_ACKNOW)) || tp->t_force != 0 ||
	      tp->t_lastchain >= tcp_packet_chaining) {
		error = 0;
		while (tp->t_inpcb->inp_sndinprog_cnt == 0 &&
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
#ifdef INET6
			    isipv6);
#else
			    0);
#endif

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
		if (tp->t_inpcb->inp_sndinprog_cnt == 0 &&
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
		if (tp->t_force == 0 || tp->t_timer[TCPT_PERSIST] == 0) {
			/*
			 * No need to check for TH_FIN here because
			 * the TF_SENTFIN flag handles that case.
			 */
			if ((flags & TH_SYN) == 0) {
				if (sack_rxmit) {
					p->rxmit -= lost;
					tp->sackhint.sack_bytes_rexmit -= lost;
				} else
					tp->snd_nxt -= lost;
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

			DTRACE_TCP5(cc, void, NULL, struct inpcb *, tp->t_inpcb,
				struct tcpcb *, tp, struct tcphdr *, NULL,
				int32_t, TCP_CC_OUTPUT_ERROR);
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

			tcp_mtudisc(tp->t_inpcb, 0);
			tcp_check_timer_state(tp);

			KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
			return 0;
		}
		if ((error == EHOSTUNREACH || error == ENETDOWN)
		    && TCPS_HAVERCVDSYN(tp->t_state)) {
			tp->t_softerror = error;
			tcp_check_timer_state(tp);
			KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
			return (0);
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
	struct inpcb *inp = tp->t_inpcb;
	struct ip_out_args ipoa =
	    { IFSCOPE_NONE, { 0 }, IPOAF_SELECT_SRCIF | IPOAF_BOUND_SRCADDR };
	struct route ro;
	struct ifnet *outif = NULL;
#ifdef INET6
	struct ip6_out_args ip6oa =
	    { IFSCOPE_NONE, { 0 }, IP6OAF_SELECT_SRCIF | IP6OAF_BOUND_SRCADDR };
	struct route_in6 ro6;
	struct flowadv *adv =
	    (isipv6 ? &ip6oa.ip6oa_flowadv : &ipoa.ipoa_flowadv);
#else
	struct flowadv *adv = &ipoa.ipoa_flowadv;
#endif /* !INET6 */

	/* If socket was bound to an ifindex, tell ip_output about it */
	if (inp->inp_flags & INP_BOUND_IF) {
#ifdef INET6
		if (isipv6) {
			ip6oa.ip6oa_boundif = inp->inp_boundifp->if_index;
			ip6oa.ip6oa_flags |= IP6OAF_BOUND_IF;
		} else
#endif
		{
			ipoa.ipoa_boundif = inp->inp_boundifp->if_index;
			ipoa.ipoa_flags |= IPOAF_BOUND_IF;
		}
	}

	if (inp->inp_flags & INP_NO_IFT_CELLULAR) {
#ifdef INET6
		if (isipv6)
			ip6oa.ip6oa_flags |=  IP6OAF_NO_CELLULAR;
		else
#endif
			ipoa.ipoa_flags |=  IPOAF_NO_CELLULAR;
	}
#ifdef INET6
	if (isipv6)
		flags |= IPV6_OUTARGS;
	else
#endif
		flags |= IP_OUTARGS;

	/* Copy the cached route and take an extra reference */
#ifdef INET6
	if (isipv6)
		in6p_route_copyout(inp, &ro6);
	else
#endif
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
	    ((tp->t_flags & TF_FASTRECOVERY) == 0)) {

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
#ifdef INET6
		if (isipv6)
			error = ip6_output_list(pkt, cnt,
			    inp->in6p_outputopts, &ro6, flags, NULL, NULL,
			    &ip6oa);
		else
#endif
			error = ip_output_list(pkt, cnt, opt, &ro, flags, NULL,
			    &ipoa);

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
			DTRACE_TCP5(cc, void, NULL, struct inpcb *, inp,
			    struct tcpcb *, tp, struct tcphdr *, NULL,
			    int32_t, ((adv->code == FADV_FLOW_CONTROLLED) ?
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

#ifdef INET6
	if (isipv6) {
		if (ro6.ro_rt != NULL && (outif = ro6.ro_rt->rt_ifp) !=
		    inp->in6p_last_outifp)
			inp->in6p_last_outifp = outif;
	} else
#endif
		if (ro.ro_rt != NULL && (outif = ro.ro_rt->rt_ifp) !=
		    inp->inp_last_outifp)
			inp->inp_last_outifp = outif;

	if ((inp->inp_flags & INP_NO_IFT_CELLULAR) && outif != NULL &&
	    outif->if_type == IFT_CELLULAR)
		soevent(inp->inp_socket,
		    (SO_FILT_HINT_LOCKED|SO_FILT_HINT_IFDENIED));

	/* Synchronize cached PCB route & options */
#ifdef INET6
	if (isipv6)
		in6p_route_copyin(inp, &ro6);
	else
#endif
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
	int tack_offset = 28; /* XXX IPv6 not supported */
	int ack_size = (tp->t_flags & TF_STRETCHACK) ?
			(maxseg_unacked * tp->t_maxseg) : (tp->t_maxseg << 1);
	int segs_acked = (tp->t_flags & TF_STRETCHACK) ? maxseg_unacked : 2;
	struct mbuf *prev_ack_pkt = NULL;
	struct socket *so = tp->t_inpcb->inp_socket;

	count = tp->t_lropktlen/tp->t_maxseg;

	prev_ack = (org_ack - tp->t_lropktlen) + ack_size;
	if (prev_ack < org_ack) {
		ack_chain = m_dup(m, M_DONTWAIT);
		if (ack_chain) {
			th->th_ack = htonl(prev_ack);
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
			HTONL(prev_ack);
			bcopy(&prev_ack, mtod(prev_ack_pkt, caddr_t) + tack_offset, 4);
			NTOHL(prev_ack);
			tail->m_nextpkt = mnext;
			tail = mnext;
			count -= segs_acked;
			tcpstat.tcps_sndacks++;
			so_tc_update_stats(m, so, m_get_service_class(m));
			if (lrodebug == 5) { 
				printf("%s: lropktlen = %d count = %d, th_ack = %x \n", 
					__func__, tp->t_lropktlen, count, 
					th->th_ack);
			}
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
