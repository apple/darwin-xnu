/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
#include <net/if_var.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
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
#if TCPDEBUG
#include <netinet/tcp_debug.h>
#endif
#include <sys/kdebug.h>

#if IPSEC
#include <netinet6/ipsec.h>
#endif /*IPSEC*/

#if CONFIG_MACF_NET
#include <security/mac_framework.h>
#endif /* MAC_SOCKET */

#define DBG_LAYER_BEG		NETDBG_CODE(DBG_NETTCP, 1)
#define DBG_LAYER_END		NETDBG_CODE(DBG_NETTCP, 3)
#define DBG_FNC_TCP_OUTPUT	NETDBG_CODE(DBG_NETTCP, (4 << 8) | 1)


#ifdef notyet
extern struct mbuf *m_copypack();
#endif

int path_mtu_discovery = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, path_mtu_discovery, CTLFLAG_RW,
	&path_mtu_discovery, 1, "Enable Path MTU Discovery");

int ss_fltsz = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, slowstart_flightsize, CTLFLAG_RW,
	&ss_fltsz, 1, "Slow start flight size");

int ss_fltsz_local = 8; /* starts with eight segments max */
SYSCTL_INT(_net_inet_tcp, OID_AUTO, local_slowstart_flightsize, CTLFLAG_RW,
	&ss_fltsz_local, 1, "Slow start flight size for local networks");

int     tcp_do_newreno = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, newreno, CTLFLAG_RW, &tcp_do_newreno,
        0, "Enable NewReno Algorithms");

int     tcp_ecn_outbound = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, ecn_initiate_out, CTLFLAG_RW, &tcp_ecn_outbound,
        0, "Initiate ECN for outbound connections");

int     tcp_ecn_inbound = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, ecn_negotiate_in, CTLFLAG_RW, &tcp_ecn_inbound,
        0, "Allow ECN negotiation for inbound connections");

int	tcp_packet_chaining = 50;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, packetchain, CTLFLAG_RW, &tcp_packet_chaining,
        0, "Enable TCP output packet chaining");

int	tcp_output_unlocked = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, socket_unlocked_on_output, CTLFLAG_RW, &tcp_output_unlocked,
        0, "Unlock TCP when sending packets down to IP");

static long packchain_newlist = 0;
static long packchain_looped = 0;
static long packchain_sent = 0;


/* temporary: for testing */
#if IPSEC
extern int ipsec_bypass;
#endif

extern int slowlink_wsize;	/* window correction for slow links */
extern u_long  route_generation;
extern int fw_enable; 		/* firewall check for packet chaining */
extern int fw_bypass; 		/* firewall check: disable packet chaining if there is rules */

extern vm_size_t	so_cache_zone_element_size;

static int tcp_ip_output(struct socket *, struct tcpcb *, struct mbuf *, int,
    struct mbuf *, int);

static __inline__ u_int16_t
get_socket_id(struct socket * s)
{
	u_int16_t 		val;

	if (so_cache_zone_element_size == 0) {
		return (0);
	}
	val = (u_int16_t)(((u_int32_t)s) / so_cache_zone_element_size);
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
 *	ip6_output:???			[IPV6 only]
 */
int
tcp_output(struct tcpcb *tp)
{
	struct socket *so = tp->t_inpcb->inp_socket;
	long len, recwin, sendwin;
	int off, flags, error;
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
	int sack_bytes_rxmt;
	struct sackhole *p;

	int maxburst = TCP_MAXBURST;
	int    last_off = 0;
	int    m_off;
	struct mbuf *m_last = NULL;
	struct mbuf *m_head = NULL;
	struct mbuf *packetlist = NULL;
	struct mbuf *tp_inp_options = tp->t_inpcb->inp_depend4.inp4_options;
#if INET6
	int isipv6 = tp->t_inpcb->inp_vflag & INP_IPV6 ;
	struct ip6_pktopts *inp6_pktopts = tp->t_inpcb->inp_depend6.inp6_outputopts;
#endif
	short packchain_listadd = 0;
	u_int16_t	socket_id = get_socket_id(so);
	int so_options = so->so_options;
	struct rtentry *rt;

	/*
	 * Determine length of data that should be transmitted,
	 * and flags that will be used.
	 * If there is some data or critical controls (SYN, RST)
	 * to send, then transmit; otherwise, investigate further.
	 */
	idle = (tp->t_flags & TF_LASTIDLE) || (tp->snd_max == tp->snd_una);
	if (idle && tp->t_rcvtime >= tp->t_rxtcur) {
		/*
		 * We have been idle for "a while" and no acks are
		 * expected to clock out any data we send --
		 * slow start to get ack "clock" running again.
		 *
		 * Set the slow-start flight size depending on whether
		 * this is a local network or not.
		 */
		if (
#if INET6
		    (isipv6 && in6_localaddr(&tp->t_inpcb->in6p_faddr)) ||
		    (!isipv6 &&
#endif
		     in_localaddr(tp->t_inpcb->inp_faddr)
#if INET6
		     )
#endif
		    )
			tp->snd_cwnd = tp->t_maxseg * ss_fltsz_local;
		else     
			tp->snd_cwnd = tp->t_maxseg * ss_fltsz;
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
	}
	else
#endif

	{
		KERNEL_DEBUG(DBG_LAYER_BEG,
		     ((tp->t_inpcb->inp_fport << 16) | tp->t_inpcb->inp_lport),
		     (((tp->t_inpcb->inp_laddr.s_addr & 0xffff) << 16) |
		      (tp->t_inpcb->inp_faddr.s_addr & 0xffff)),
		     sendalot,0,0);
	/*
	 * If the route generation id changed, we need to check that our
	 * local (source) IP address is still valid. If it isn't either
	 * return error or silently do nothing (assuming the address will
	 * come back before the TCP connection times out).
	 */
	rt = tp->t_inpcb->inp_route.ro_rt;
	if (rt != NULL && rt->generation_id != route_generation) {
		struct ifnet *ifp;

		/* disable multipages at the socket */
		somultipages(so, FALSE);

		/* check that the source address is still valid */
		if (ifa_foraddr(tp->t_inpcb->inp_laddr.s_addr) == 0) {

			if (tp->t_state >= TCPS_CLOSE_WAIT) {
				tcp_drop(tp, EADDRNOTAVAIL);
				return(EADDRNOTAVAIL);
			}

			/* set Retransmit  timer if it wasn't set
			 * reset Persist timer and shift register as the
			 * adversed peer window may not be valid anymore
			 */

                        if (!tp->t_timer[TCPT_REXMT]) {
                                tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;
				if (tp->t_timer[TCPT_PERSIST]) {
					tp->t_timer[TCPT_PERSIST] = 0;
					tp->t_rxtshift = 0;
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
			else
				return(0); /* silently ignore, keep data in socket: address may be back */
		}

		/*
		 * Address is still valid; check for multipages capability
		 * again in case the outgoing interface has changed.
		 */
		lck_mtx_lock(rt_mtx);
		rt = tp->t_inpcb->inp_route.ro_rt;
		if (rt != NULL && (ifp = rt->rt_ifp) != NULL)
			somultipages(so, (ifp->if_hwassist & IFNET_MULTIPAGES));
		if (rt != NULL && rt->generation_id != route_generation)
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

		lck_mtx_unlock(rt_mtx);
        }
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
		long cwin;
		
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
				len = ((long)ulmin(cwin,
						   tp->snd_recover - p->rxmit));
		} else
			len = ((long)ulmin(cwin, p->end - p->rxmit));
		off = p->rxmit - tp->snd_una;
		if (len > 0) {
			sack_rxmit = 1;
			sendalot = 1;
			tcpstat.tcps_sack_rexmits++;
			tcpstat.tcps_sack_rexmit_bytes +=
			    min(len, tp->t_maxseg);
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
			len = ((long)ulmin(so->so_snd.sb_cc, sendwin) - off);
		else {
			long cwin;

                        /*
			 * We are inside of a SACK recovery episode and are
			 * sending new data, having retransmitted all the
			 * data possible in the scoreboard.
			 */
			len = ((long)ulmin(so->so_snd.sb_cc, tp->snd_wnd) 
			       - off);
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
				len = lmin(len, cwin);
			}
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
			while (!(tp->t_flags & TF_SENDINPROG) &&
			    tp->t_pktlist_head != NULL) {
				packetlist = tp->t_pktlist_head;
				packchain_listadd = tp->t_lastchain;
				packchain_sent++;
				TCP_PKTLIST_CLEAR(tp);
				tp->t_flags |= TF_SENDINPROG;

				error = tcp_ip_output(so, tp, packetlist,
				    packchain_listadd, tp_inp_options,
				    (so_options & SO_DONTROUTE));

				tp->t_flags &= ~TF_SENDINPROG;
			}
			/* tcp was closed while we were in ip; resume close */
			if ((tp->t_flags &
			    (TF_CLOSING|TF_SENDINPROG)) == TF_CLOSING) {
				tp->t_flags &= ~TF_CLOSING;
				(void) tcp_close(tp);
			}
			KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END,
			    0,0,0,0,0);
			return 0;
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

	if (len < 0) {
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
			tp->snd_nxt = tp->snd_una;
			if (tp->t_timer[TCPT_PERSIST] == 0)
				tcp_setpersist(tp);
		}
	}

	/*
	 * len will be >= 0 after this point.  Truncate to the maximum
	 * segment length and ensure that FIN is removed if the length
	 * no longer contains the last data byte.
	 */
	if (len > tp->t_maxseg) {
		len = tp->t_maxseg;
		sendalot = 1;
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
	 *	- We have a full segment
	 *	- This is the last buffer in a write()/send() and we are
	 *	  either idle or running NODELAY
	 *	- we've timed out (e.g. persist timer)
	 *	- we have more then 1/2 the maximum send window's worth of
	 *	  data (receiver may be limited the window size)
	 *	- we need to retransmit
	 */
	if (len) {
		if (len == tp->t_maxseg) {
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
		if (tp->t_force) {
			tp->t_flags &= ~TF_MAXSEGSNT;
			goto send;
		}
		if (len >= tp->max_sndwnd / 2 && tp->max_sndwnd > 0) {
			tp->t_flags &= ~TF_MAXSEGSNT;
			goto send;
		}
		if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
			tp->t_flags &= ~TF_MAXSEGSNT;
			goto send;
		}
		if (sack_rxmit)
			goto send;
	}

	/*
	 * Compare available window to amount of window
	 * known to peer (as advertised window less
	 * next expected input).  If the difference is at least two
	 * max size segments, or at least 50% of the maximum possible
	 * window, then want to send a window update to peer.
	 * Skip this if the connection is in T/TCP half-open state.
	 */
	if (recwin > 0 && !(tp->t_flags & TF_NEEDSYN)) {
		/*
		 * "adv" is the amount we can increase the window,
		 * taking into account that we are limited by
		 * TCP_MAXWIN << tp->rcv_scale.
		 */
		long adv = lmin(recwin, (long)TCP_MAXWIN << tp->rcv_scale) -
			(tp->rcv_adv - tp->rcv_nxt);

		if (adv >= (long) (2 * tp->t_maxseg))
			goto send;
		if (2 * adv >= (long) so->so_rcv.sb_hiwat)
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
	if (tp->sack_enable && SEQ_GT(tp->snd_max, tp->snd_una) &&
		tp->t_timer[TCPT_REXMT] == 0 &&
	    tp->t_timer[TCPT_PERSIST] == 0) {
			tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;
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
		tcp_setpersist(tp);
	}
just_return:
	/*
	 * If there is no reason to send a segment, just return.
	 * but if there is some packets left in the packet list, send them now.
	 */
	while (!(tp->t_flags & TF_SENDINPROG) && tp->t_pktlist_head != NULL) {
		packetlist = tp->t_pktlist_head;
		packchain_listadd = tp->t_lastchain;
		packchain_sent++;
		TCP_PKTLIST_CLEAR(tp);
		tp->t_flags |= TF_SENDINPROG;

		error = tcp_ip_output(so, tp, packetlist, packchain_listadd,
		    tp_inp_options, (so_options & SO_DONTROUTE));

		tp->t_flags &= ~TF_SENDINPROG;
	}
	/* tcp was closed while we were in ip; resume close */
	if ((tp->t_flags & (TF_CLOSING|TF_SENDINPROG)) == TF_CLOSING) {
		tp->t_flags &= ~TF_CLOSING;
		(void) tcp_close(tp);
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
				*((u_int32_t *)(opt + optlen)) = htonl(
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
		!SEQ_LT(tp->snd_nxt, tp->snd_max)) {
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
		u_int32_t *lp = (u_int32_t *)(opt + optlen);

 		/* Form timestamp option as shown in appendix A of RFC 1323. */
 		*lp++ = htonl(TCPOPT_TSTAMP_HDR);
 		*lp++ = htonl(tcp_now);
 		*lp   = htonl(tp->ts_recent);
 		optlen += TCPOLEN_TSTAMP_APPA;
 	}

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
			int nsack, sackoptlen, padlen;
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
			lp = (u_int32_t *)bp;
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
	if (ipsec_bypass == 0)
		ipoptlen += ipsec_hdrsiz_tcp(tp);
#endif

	/*
	 * Adjust data length if insertion of options will
	 * bump the packet length beyond the t_maxopd length.
	 * Clear the FIN bit because we cut off the tail of
	 * the segment.
	 */
	if (len + optlen + ipoptlen > tp->t_maxopd) {
		/*
		 * If there is still more to send, don't close the connection.
		 */
		flags &= ~TH_FIN;
		len = tp->t_maxopd - optlen - ipoptlen;
		sendalot = 1;
	}

/*#ifdef DIAGNOSTIC*/
#if INET6
 	if (max_linkhdr + hdrlen > MCLBYTES)
		panic("tcphdr too big");
#else
 	if (max_linkhdr + hdrlen > MHLEN)
		panic("tcphdr too big");
#endif
/*#endif*/

	/*
	 * Grab a header mbuf, attaching a copy of data to
	 * be transmitted, and initialize the header from
	 * the template for sends on this connection.
	 */
	if (len) {
		if (tp->t_force && len == 1)
			tcpstat.tcps_sndprobe++;
		else if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
			tcpstat.tcps_sndrexmitpack++;
			tcpstat.tcps_sndrexmitbyte += len;
		} else {
			tcpstat.tcps_sndpack++;
			tcpstat.tcps_sndbyte += len;
		}
#ifdef notyet
		if ((m = m_copypack(so->so_snd.sb_mb, off,
		    (int)len, max_linkhdr + hdrlen)) == 0) {
			error = ENOBUFS;
			goto out;
		}
		/*
		 * m_copypack left space for our hdr; use it.
		 */
		m->m_len += hdrlen;
		m->m_data -= hdrlen;
#else
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
#if INET6
 		if (MHLEN < hdrlen + max_linkhdr) {
		        MGETHDR(m, M_DONTWAIT, MT_HEADER);	/* MAC-OK */
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
		}
#endif
		if (len <= MHLEN - hdrlen - max_linkhdr) {
		        if (m == NULL) {
			        MGETHDR(m, M_DONTWAIT, MT_HEADER);	/* MAC-OK */
				if (m == NULL) {
				        error = ENOBUFS;
					goto out;
				}
				m->m_data += max_linkhdr;
				m->m_len = hdrlen;
			}
			/* makes sure we still have data left to be sent at this point */
			if (so->so_snd.sb_mb == NULL || off == -1) {
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
			        if (m_head != so->so_snd.sb_mb || last_off != off)
				        m_last = NULL;
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
			        if ((m = m_copym_with_hdrs(so->so_snd.sb_mb, off, (int) len, M_DONTWAIT, &m_last, &m_off)) == NULL) {
				        error = ENOBUFS;
					goto out;
				}
				m->m_data += max_linkhdr;
				m->m_len = hdrlen;
			}
		}
#endif
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
#if INET6
		if (isipv6 && (MHLEN < hdrlen + max_linkhdr) &&
		    MHLEN >= hdrlen) {
			MH_ALIGN(m, hdrlen);
		} else
#endif
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
		th = (struct tcphdr *)(ip6 + 1);
		tcp_fillheaders(tp, ip6, th);
	} else
#endif /* INET6 */
	{
		ip = mtod(m, struct ip *);
		ipov = (struct ipovly *)ip;
		th = (struct tcphdr *)(ip + 1);
		/* this picks up the pseudo header (w/o the length) */
		tcp_fillheaders(tp, ip, th);
		if ((tp->ecn_flags & TE_SENDIPECT) != 0 && len &&
			!SEQ_LT(tp->snd_nxt, tp->snd_max)) {
			ip->ip_tos = IPTOS_ECN_ECT0;
		}
	}

	/*
	 * Fill in fields, remembering maximum advertised
	 * window for use in delaying messages about window sizes.
	 * If resending a FIN, be sure not to use a new sequence number.
	 */
	if (flags & TH_FIN && tp->t_flags & TF_SENTFIN &&
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
	if (optlen) {
		bcopy(opt, th + 1, optlen);
		th->th_off = (sizeof (struct tcphdr) + optlen) >> 2;
	}
	th->th_flags = flags;
	/*
	 * Calculate receive window.  Don't shrink window,
	 * but avoid silly window syndrome.
	 */
	if (recwin < (long)(so->so_rcv.sb_hiwat / 4) && recwin < (long)tp->t_maxseg)
		recwin = 0;
	if (recwin < (long)(tp->rcv_adv - tp->rcv_nxt))
		recwin = (long)(tp->rcv_adv - tp->rcv_nxt);
	if (tp->t_flags & TF_SLOWLINK && slowlink_wsize > 0) {
		if (recwin > (long)slowlink_wsize) 
			recwin = slowlink_wsize;
			th->th_win = htons((u_short) (recwin>>tp->rcv_scale));
	}
	else {
		if (recwin > (long)(TCP_MAXWIN << tp->rcv_scale))
			recwin = (long)(TCP_MAXWIN << tp->rcv_scale);
		th->th_win = htons((u_short) (recwin>>tp->rcv_scale));
	}

	/*
	 * Adjust the RXWIN0SENT flag - indicate that we have advertised
	 * a 0 window.  This may cause the remote transmitter to stall.  This
	 * flag tells soreceive() to disable delayed acknowledgements when
	 * draining the buffer.  This can occur if the receiver is attempting
	 * to read more data then can be buffered prior to transmitting on
	 * the connection.
	 */
	if (recwin == 0)
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
	if (isipv6)
		/*
		 * ip6_plen is not need to be filled now, and will be filled
		 * in ip6_output.
		 */
		th->th_sum = in6_cksum(m, IPPROTO_TCP, sizeof(struct ip6_hdr),
				       sizeof(struct tcphdr) + optlen + len);
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
				tp->t_rtttime = 1;
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
			}
			tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;
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
	/*
	 * m->m_pkthdr.len should have been set before cksum calcuration,
	 * because in6_cksum() need it.
	 */
#if INET6
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
#if IPSEC
		if (ipsec_bypass == 0 && ipsec_setsocket(m, so) != 0) {
			m_freem(m);
			error = ENOBUFS;
			goto out;
		}
#endif /*IPSEC*/
		m->m_pkthdr.socket_id = socket_id;
		error = ip6_output(m,
			    inp6_pktopts,
			    &tp->t_inpcb->in6p_route,
			    (so_options & SO_DONTROUTE), NULL, NULL, 0);
	} else
#endif /* INET6 */
    {
	ip->ip_len = m->m_pkthdr.len;
#if INET6
 	if (isipv6)
 		ip->ip_ttl = in6_selecthlim(tp->t_inpcb,
 					    tp->t_inpcb->in6p_route.ro_rt ?
 					    tp->t_inpcb->in6p_route.ro_rt->rt_ifp
 					    : NULL);
 	else
#endif /* INET6 */
	ip->ip_ttl = tp->t_inpcb->inp_ip_ttl;	/* XXX */
	ip->ip_tos |= (tp->t_inpcb->inp_ip_tos & ~IPTOS_ECN_MASK);	/* XXX */


#if INET6
	if (isipv6) {
		KERNEL_DEBUG(DBG_LAYER_BEG,
		     ((tp->t_inpcb->inp_fport << 16) | tp->t_inpcb->inp_lport),
		     (((tp->t_inpcb->in6p_laddr.s6_addr16[0] & 0xffff) << 16) |
		      (tp->t_inpcb->in6p_faddr.s6_addr16[0] & 0xffff)),
		     0,0,0);
	}
        else 
#endif
	{
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
	m->m_nextpkt = NULL;
	tp->t_pktlist_sentlen += len;
	tp->t_lastchain++;
	if (tp->t_pktlist_head != NULL) {
		tp->t_pktlist_tail->m_nextpkt = m;
		tp->t_pktlist_tail = m;
	} else {
		packchain_newlist++;
		tp->t_pktlist_head = tp->t_pktlist_tail = m;
	}

	if (sendalot == 0 || (tp->t_state != TCPS_ESTABLISHED) ||
	      (tp->snd_cwnd <= (tp->snd_wnd / 8)) ||
	      (tp->t_flags & (TH_PUSH | TF_ACKNOW)) || tp->t_force != 0 ||
	      tp->t_lastchain >= tcp_packet_chaining) {
		error = 0;
		while (!(tp->t_flags & TF_SENDINPROG) &&
		    tp->t_pktlist_head != NULL) {
			packetlist = tp->t_pktlist_head;
			packchain_listadd = tp->t_lastchain;
			packchain_sent++;
			lost = tp->t_pktlist_sentlen;
			TCP_PKTLIST_CLEAR(tp);
			tp->t_flags |= TF_SENDINPROG;

			error = tcp_ip_output(so, tp, packetlist,
			    packchain_listadd, tp_inp_options,
			    (so_options & SO_DONTROUTE));

			tp->t_flags &= ~TF_SENDINPROG;
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
		if ((tp->t_flags & (TF_CLOSING|TF_SENDINPROG)) == TF_CLOSING) {
			tp->t_flags &= ~TF_CLOSING;
			(void) tcp_close(tp);
			return (0);
		}
	}
	else {
		error = 0;
		packchain_looped++;
		tcpstat.tcps_sndtotal++;

		if (recwin > 0 && SEQ_GT(tp->rcv_nxt+recwin, tp->rcv_adv))
			tp->rcv_adv = tp->rcv_nxt + recwin;
		tp->last_ack_sent = tp->rcv_nxt;
		tp->t_flags &= ~(TF_ACKNOW|TF_DELACK);
		goto again;
	}
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
                                tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;
			tcp_quench(tp->t_inpcb, 0);
			KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
			return (0);
		}
		if (error == EMSGSIZE) {
			/*
			 * ip_output() will have already fixed the route
			 * for us.  tcp_mtudisc() will, as its last action,
			 * initiate retransmission, so it is important to
			 * not do so here.
			 */
			tcp_mtudisc(tp->t_inpcb, 0);
			KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
			return 0;
		}
		if ((error == EHOSTUNREACH || error == ENETDOWN)
		    && TCPS_HAVERCVDSYN(tp->t_state)) {
			tp->t_softerror = error;
			KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
			return (0);
		}
		KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
		return (error);
	}

	tcpstat.tcps_sndtotal++;

	/*
	 * Data sent (as far as we can tell).
	 * If this advertises a larger window than any other segment,
	 * then remember the size of the advertised window.
	 * Any pending ACK has now been sent.
	 */
	if (recwin > 0 && SEQ_GT(tp->rcv_nxt+recwin, tp->rcv_adv))
		tp->rcv_adv = tp->rcv_nxt + recwin;
	tp->last_ack_sent = tp->rcv_nxt;
	tp->t_flags &= ~(TF_ACKNOW|TF_DELACK);

	KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END,0,0,0,0,0);
	if (sendalot && (!tcp_do_newreno || --maxburst))
		goto again;
	return (0);
}

static int
tcp_ip_output(struct socket *so, struct tcpcb *tp, struct mbuf *pkt,
    int cnt, struct mbuf *opt, int flags)
{
	int error = 0;
	boolean_t chain;
	boolean_t unlocked = FALSE;

	/*
	 * If allowed, unlock TCP socket while in IP 
	 * but only if the connection is established and
	 * if we're not sending from an upcall.
	 */ 

	if (tcp_output_unlocked && ((so->so_flags & SOF_UPCALLINUSE) == 0) &&
	    (tp->t_state == TCPS_ESTABLISHED)) {
			unlocked = TRUE;
			socket_unlock(so, 0);
	}

	/*
	 * Don't send down a chain of packets when:
	 * - TCP chaining is disabled
	 * - there is an IPsec rule set
	 * - there is a non default rule set for the firewall
	 */

	chain = tcp_packet_chaining > 1 &&
#if IPSEC
		ipsec_bypass &&
#endif
		(fw_enable == 0 || fw_bypass);

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
#if CONFIG_FORCE_OUT_IFP
		error = ip_output_list(pkt, cnt, opt, &tp->t_inpcb->inp_route,
		    flags, 0, tp->t_inpcb->pdp_ifp);
#else
		error = ip_output_list(pkt, cnt, opt, &tp->t_inpcb->inp_route,
		    flags, 0, NULL);
#endif
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

	return (error);
}

void
tcp_setpersist(tp)
	register struct tcpcb *tp;
{
	int t = ((tp->t_srtt >> 2) + tp->t_rttvar) >> 1;

	if (tp->t_timer[TCPT_REXMT])
		panic("tcp_setpersist: retransmit pending");
	/*
	 * Start/restart persistance timer.
	 */
	TCPT_RANGESET(tp->t_timer[TCPT_PERSIST],
	    t * tcp_backoff[tp->t_rxtshift],
	    TCPTV_PERSMIN, TCPTV_PERSMAX);
	if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
		tp->t_rxtshift++;
}
