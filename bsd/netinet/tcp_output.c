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

#include <netinet/in.h>
#include <netinet/in_systm.h>
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

#define DBG_LAYER_BEG		NETDBG_CODE(DBG_NETTCP, 1)
#define DBG_LAYER_END		NETDBG_CODE(DBG_NETTCP, 3)
#define DBG_FNC_TCP_OUTPUT	NETDBG_CODE(DBG_NETTCP, (4 << 8) | 1)


#ifdef notyet
extern struct mbuf *m_copypack();
#endif

static int path_mtu_discovery = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, path_mtu_discovery, CTLFLAG_RW,
	&path_mtu_discovery, 1, "Enable Path MTU Discovery");

int ss_fltsz = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, slowstart_flightsize, CTLFLAG_RW,
	&ss_fltsz, 1, "Slow start flight size");

int ss_fltsz_local = 4; /* starts with four segments max */
SYSCTL_INT(_net_inet_tcp, OID_AUTO, local_slowstart_flightsize, CTLFLAG_RW,
	&ss_fltsz_local, 1, "Slow start flight size for local networks");

int     tcp_do_newreno = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, newreno, CTLFLAG_RW, &tcp_do_newreno,
        0, "Enable NewReno Algorithms");

int	tcp_packet_chaining = 50;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, packetchain, CTLFLAG_RW, &tcp_packet_chaining,
        0, "Enable TCP output packet chaining");

struct	mbuf *m_copym_with_hdrs(struct mbuf*, int, int, int, struct mbuf**, int*);
static long packchain_newlist = 0;
static long packchain_looped = 0;
static long packchain_sent = 0;


/* temporary: for testing */
#if IPSEC
extern int ipsec_bypass;
#endif

extern int slowlink_wsize;	/* window correction for slow links */
extern u_long  route_generation;
extern int fw_enable; 		/* firewall is on: disable packet chaining */
extern int ipsec_bypass;

extern vm_size_t	so_cache_zone_element_size;

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
 */
int
tcp_output(tp)
	register struct tcpcb *tp;
{
	register struct socket *so = tp->t_inpcb->inp_socket;
	register long len, win;
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
	int idle, sendalot, howmuchsent = 0;
	int maxburst = TCP_MAXBURST;
	struct rmxp_tao *taop;
	struct rmxp_tao tao_noncached;
	int    last_off = 0;
	int    m_off;
	struct mbuf *m_last = 0;
	struct mbuf *m_head = 0;
	struct mbuf *packetlist = 0;
	struct mbuf *lastpacket = 0;
#if INET6
	int isipv6 = tp->t_inpcb->inp_vflag & INP_IPV6 ;
#endif
	short packchain_listadd = 0;
	u_int16_t	socket_id = get_socket_id(so);


	/*
	 * Determine length of data that should be transmitted,
	 * and flags that will be used.
	 * If there is some data or critical controls (SYN, RST)
	 * to send, then transmit; otherwise, investigate further.
	 */
	idle = (tp->snd_max == tp->snd_una);
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

      if ((tp->t_inpcb->inp_route.ro_rt != NULL &&
           (tp->t_inpcb->inp_route.ro_rt->generation_id != route_generation)) || (tp->t_inpcb->inp_route.ro_rt == NULL)) {
		/* check that the source address is still valid */
		if (ifa_foraddr(tp->t_inpcb->inp_laddr.s_addr) == 0) {
			if (tp->t_state >= TCPS_CLOSE_WAIT) {
				tcp_close(tp);
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

			if (packetlist) {
				error = ip_output_list(packetlist, packchain_listadd, tp->t_inpcb->inp_options, &tp->t_inpcb->inp_route,
    					(so->so_options & SO_DONTROUTE), 0);
				tp->t_lastchain = 0;
			}
			if (so->so_flags & SOF_NOADDRAVAIL)
				return(EADDRNOTAVAIL);
			else
				return(0); /* silently ignore and keep data in socket */
		}
        }
	}
	sendalot = 0;
	off = tp->snd_nxt - tp->snd_una;
	win = min(tp->snd_wnd, tp->snd_cwnd);
	if (tp->t_flags & TF_SLOWLINK && slowlink_wsize > 0)
		win = min(win, slowlink_wsize);

	flags = tcp_outflags[tp->t_state];
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
		if (win == 0) {
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
			win = 1;
		} else {
			tp->t_timer[TCPT_PERSIST] = 0;
			tp->t_rxtshift = 0;
		}
	}

	len = (long)ulmin(so->so_snd.sb_cc, win) - off;

	if ((taop = tcp_gettaocache(tp->t_inpcb)) == NULL) {
		taop = &tao_noncached;
		bzero(taop, sizeof(*taop));
	}

	/*
	 * Lop off SYN bit if it has already been sent.  However, if this
	 * is SYN-SENT state and if segment contains data and if we don't
	 * know that foreign host supports TAO, suppress sending segment.
	 */
	if ((flags & TH_SYN) && SEQ_GT(tp->snd_nxt, tp->snd_una)) {
		flags &= ~TH_SYN;
		off--, len++;
		if (len > 0 && tp->t_state == TCPS_SYN_SENT &&
		    taop->tao_ccsent == 0) {
			if (packetlist) {
				error = ip_output_list(packetlist, packchain_listadd, tp->t_inpcb->inp_options, &tp->t_inpcb->inp_route,
    				(so->so_options & SO_DONTROUTE), 0);
				tp->t_lastchain = 0;
			}
		  KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
		  return 0;
		}
	}

	/*
	 * Be careful not to send data and/or FIN on SYN segments
	 * in cases when no CC option will be sent.
	 * This measure is needed to prevent interoperability problems
	 * with not fully conformant TCP implementations.
	 */
	if ((flags & TH_SYN) &&
	    ((tp->t_flags & TF_NOOPT) || !(tp->t_flags & TF_REQ_CC) ||
	     ((flags & TH_ACK) && !(tp->t_flags & TF_RCVD_CC)))) {
		len = 0;
		flags &= ~TH_FIN;
	}

	if (len < 0) {
		/*
		 * If FIN has been sent but not acked,
		 * but we haven't been called to retransmit,
		 * len will be -1.  Otherwise, window shrank
		 * after we sent into it.  If window shrank to 0,
		 * cancel pending retransmit, pull snd_nxt back
		 * to (closed) window, and set the persist timer
		 * if it isn't already going.  If the window didn't
		 * close completely, just wait for an ACK.
		 */
		len = 0;
		if (win == 0) {
			tp->t_timer[TCPT_REXMT] = 0;
			tp->t_rxtshift = 0;
			tp->snd_nxt = tp->snd_una;
			if (tp->t_timer[TCPT_PERSIST] == 0)
				tcp_setpersist(tp);
		}
	}
	if (len > tp->t_maxseg) {
		len = tp->t_maxseg;
		howmuchsent += len;
		sendalot = 1;
	}
	if (SEQ_LT(tp->snd_nxt + len, tp->snd_una + so->so_snd.sb_cc))
		flags &= ~TH_FIN;

	if (tp->t_flags & TF_SLOWLINK && slowlink_wsize > 0 )	/* Clips window size for slow links */
		win = min(sbspace(&so->so_rcv), slowlink_wsize);
	else
		win = sbspace(&so->so_rcv);

	/*
	 * Sender silly window avoidance.  If connection is idle
	 * and can send all data, a maximum segment,
	 * at least a maximum default-size segment do it,
	 * or are forced, do it; otherwise don't bother.
	 * If peer's buffer is tiny, then send
	 * when window is at least half open.
	 * If retransmitting (possibly after persist timer forced us
	 * to send into a small window), then must resend.
	 */
	if (len) {
		if (len == tp->t_maxseg)
			goto send;
		if (!(tp->t_flags & TF_MORETOCOME) &&
		    (idle || tp->t_flags & TF_NODELAY) &&
		    (tp->t_flags & TF_NOPUSH) == 0 &&
		    len + off >= so->so_snd.sb_cc)
			goto send;
		if (tp->t_force)
			goto send;
		if (len >= tp->max_sndwnd / 2 && tp->max_sndwnd > 0)
			goto send;
		if (SEQ_LT(tp->snd_nxt, tp->snd_max))
			goto send;
	}

	/*
	 * Compare available window to amount of window
	 * known to peer (as advertised window less
	 * next expected input).  If the difference is at least two
	 * max size segments, or at least 50% of the maximum possible
	 * window, then want to send a window update to peer.
	 */
	if (win > 0) {
		/*
		 * "adv" is the amount we can increase the window,
		 * taking into account that we are limited by
		 * TCP_MAXWIN << tp->rcv_scale.
		 */
		long adv = min(win, (long)TCP_MAXWIN << tp->rcv_scale) -
			(tp->rcv_adv - tp->rcv_nxt);

		if (adv >= (long) (2 * tp->t_maxseg))
			goto send;
		if (2 * adv >= (long) so->so_rcv.sb_hiwat)
			goto send;
	}

	/*
	 * Send if we owe peer an ACK.
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
	 * and we have not yet done so, or we're retransmitting the FIN,
	 * then we need to send.
	 */
	if (flags & TH_FIN &&
	    ((tp->t_flags & TF_SENTFIN) == 0 || tp->snd_nxt == tp->snd_una))
		goto send;

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

	/*
	 * If there is no reason to send a segment, just return.
	 * but if there is some packets left in the packet list, send them now.
	 */
	if (packetlist) {
		error = ip_output_list(packetlist, packchain_listadd, tp->t_inpcb->inp_options, &tp->t_inpcb->inp_route,
    			(so->so_options & SO_DONTROUTE), 0);
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

 	/*
	 * Send `CC-family' options if our side wants to use them (TF_REQ_CC),
	 * options are allowed (!TF_NOOPT) and it's not a RST.
 	 */
 	if ((tp->t_flags & (TF_REQ_CC|TF_NOOPT)) == TF_REQ_CC &&
 	     (flags & TH_RST) == 0) {
		switch (flags & (TH_SYN|TH_ACK)) {
		/*
		 * This is a normal ACK, send CC if we received CC before
		 * from our peer.
		 */
		case TH_ACK:
			if (!(tp->t_flags & TF_RCVD_CC))
				break;
			/*FALLTHROUGH*/

		/*
		 * We can only get here in T/TCP's SYN_SENT* state, when
		 * we're a sending a non-SYN segment without waiting for
		 * the ACK of our SYN.  A check above assures that we only
		 * do this if our peer understands T/TCP.
		 */
		case 0:
			opt[optlen++] = TCPOPT_NOP;
			opt[optlen++] = TCPOPT_NOP;
			opt[optlen++] = TCPOPT_CC;
			opt[optlen++] = TCPOLEN_CC;
			*(u_int32_t *)&opt[optlen] = htonl(tp->cc_send);

			optlen += 4;
			break;

		/*
		 * This is our initial SYN, check whether we have to use
		 * CC or CC.new.
		 */
		case TH_SYN:
			opt[optlen++] = TCPOPT_NOP;
			opt[optlen++] = TCPOPT_NOP;
			opt[optlen++] = tp->t_flags & TF_SENDCCNEW ?
						TCPOPT_CCNEW : TCPOPT_CC;
			opt[optlen++] = TCPOLEN_CC;
			*(u_int32_t *)&opt[optlen] = htonl(tp->cc_send);
 			optlen += 4;
			break;

		/*
		 * This is a SYN,ACK; send CC and CC.echo if we received
		 * CC from our peer.
		 */
		case (TH_SYN|TH_ACK):
			if (tp->t_flags & TF_RCVD_CC) {
				opt[optlen++] = TCPOPT_NOP;
				opt[optlen++] = TCPOPT_NOP;
				opt[optlen++] = TCPOPT_CC;
				opt[optlen++] = TCPOLEN_CC;
				*(u_int32_t *)&opt[optlen] =
					htonl(tp->cc_send);
				optlen += 4;
				opt[optlen++] = TCPOPT_NOP;
				opt[optlen++] = TCPOPT_NOP;
				opt[optlen++] = TCPOPT_CCECHO;
				opt[optlen++] = TCPOLEN_CC;
				*(u_int32_t *)&opt[optlen] =
					htonl(tp->cc_recv);
				optlen += 4;
			}
			break;
		}
 	}

 	hdrlen += optlen;
#if INET6
	if (isipv6)
		ipoptlen = ip6_optlen(tp->t_inpcb);
	else
#endif
	{
		if (tp->t_inpcb->inp_options) {
			ipoptlen = tp->t_inpcb->inp_options->m_len -
				offsetof(struct ipoption, ipopt_list);
		} else {
			ipoptlen = 0;
		}
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
		howmuchsent += len;
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
		}
#endif
		if (len <= MHLEN - hdrlen - max_linkhdr) {
		        if (m == NULL) {
			        MGETHDR(m, M_DONTWAIT, MT_HEADER);
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

		MGETHDR(m, M_DONTWAIT, MT_HEADER);
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
	if (len || (flags & (TH_SYN|TH_FIN)) || tp->t_timer[TCPT_PERSIST])
		th->th_seq = htonl(tp->snd_nxt);
	else
		th->th_seq = htonl(tp->snd_max);
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
	if (win < (long)(so->so_rcv.sb_hiwat / 4) && win < (long)tp->t_maxseg)
		win = 0;
	if (win < (long)(tp->rcv_adv - tp->rcv_nxt))
		win = (long)(tp->rcv_adv - tp->rcv_nxt);
	if (tp->t_flags & TF_SLOWLINK && slowlink_wsize > 0) {
		if (win > (long)slowlink_wsize) 
			win = slowlink_wsize;
		th->th_win = htons((u_short) (win>>tp->rcv_scale));
	}
	else {

		if (win > (long)TCP_MAXWIN << tp->rcv_scale)
		win = (long)TCP_MAXWIN << tp->rcv_scale;
		th->th_win = htons((u_short) (win>>tp->rcv_scale));
	}

        /*
         * Adjust the RXWIN0SENT flag - indicate that we have advertised   
         * a 0 window.  This may cause the remote transmitter to stall.  This
         * flag tells soreceive() to disable delayed acknowledgements when
         * draining the buffer.  This can occur if the receiver is attempting
         * to read more data then can be buffered prior to transmitting on   
         * the connection.
         */
        if (win == 0)
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

		/* IP version must be set here for ipv4/ipv6 checking later */
		KASSERT(ip->ip_v == IPVERSION,
			("%s: IP version incorrect: %d", __FUNCTION__, ip->ip_v));
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
		if (tp->t_timer[TCPT_REXMT] == 0 &&
		    tp->snd_nxt != tp->snd_una) {
			tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;
			if (tp->t_timer[TCPT_PERSIST]) {
				tp->t_timer[TCPT_PERSIST] = 0;
				tp->t_rxtshift = 0;
			}
		}
	} else
		if (SEQ_GT(tp->snd_nxt + len, tp->snd_max))
			tp->snd_max = tp->snd_nxt + len;

#if TCPDEBUG
	/*
	 * Trace.
	 */
	if (so->so_options & SO_DEBUG)
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
			    tp->t_inpcb->in6p_outputopts,
			    &tp->t_inpcb->in6p_route,
			    (so->so_options & SO_DONTROUTE), NULL, NULL, 0);
	} else
#endif /* INET6 */
    {
	struct rtentry *rt;
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
	ip->ip_tos = tp->t_inpcb->inp_ip_tos;	/* XXX */


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
	 * See if we should do MTU discovery.  We do it only if the following
	 * are true:
	 *	1) we have a valid route to the destination
	 *	2) the MTU is not locked (if it is, then discovery has been
	 *	   disabled)
	 */
	if (path_mtu_discovery
	    && (rt = tp->t_inpcb->inp_route.ro_rt)
	    && rt->rt_flags & RTF_UP
	    && !(rt->rt_rmx.rmx_locks & RTV_MTU)) {
		ip->ip_off |= IP_DF;
	}
#if IPSEC
	if (ipsec_bypass == 0)
 		ipsec_setsocket(m, so);
#endif /*IPSEC*/

	/*
	 * The socket is kept locked while sending out packets in ip_output, even if packet chaining is not active.
	 */

	m->m_pkthdr.socket_id = socket_id;
	if (packetlist) {
		m->m_nextpkt = NULL;
		lastpacket->m_nextpkt = m;
		lastpacket = m;
		packchain_listadd++;
	}
	else {
		m->m_nextpkt = NULL;
		packchain_newlist++;
		packetlist = lastpacket = m;
		packchain_listadd=0;
	}

       if ((ipsec_bypass == 0) || fw_enable || sendalot == 0 || (tp->t_state != TCPS_ESTABLISHED) || 
		      (tp->snd_cwnd <= (tp->snd_wnd / 4)) || 
		      (tp->t_flags & (TH_PUSH | TF_ACKNOW)) || tp->t_force != 0 ||
		      packchain_listadd >= tcp_packet_chaining) {
	       	lastpacket->m_nextpkt = 0;
		error = ip_output_list(packetlist, packchain_listadd, tp->t_inpcb->inp_options, &tp->t_inpcb->inp_route,
    			(so->so_options & SO_DONTROUTE), 0);
		tp->t_lastchain = packchain_listadd;
		packchain_sent++;
		packetlist = NULL;
		if (error == 0)
			howmuchsent = 0;
	}
	else {
		error = 0;
		packchain_looped++;
		tcpstat.tcps_sndtotal++;
		if (win > 0 && SEQ_GT(tp->rcv_nxt+win, tp->rcv_adv))
			tp->rcv_adv = tp->rcv_nxt + win;
		tp->last_ack_sent = tp->rcv_nxt;
		tp->t_flags &= ~(TF_ACKNOW|TF_DELACK);
		goto again;
	}
   }
	if (error) {

		/*
		 * We know that the packet was lost, so back out the
		 * sequence number advance, if any.
		 */
		if (tp->t_force == 0 || !tp->t_timer[TCPT_PERSIST]) {
			/*
			 * No need to check for TH_FIN here because
			 * the TF_SENTFIN flag handles that case.
			 */
			if ((flags & TH_SYN) == 0) 
				tp->snd_nxt -= howmuchsent;
		}
		howmuchsent = 0;
out:
		if (error == ENOBUFS) {
                        if (!tp->t_timer[TCPT_REXMT] &&
                             !tp->t_timer[TCPT_PERSIST])
                                tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;
			tcp_quench(tp->t_inpcb, 0);
			if (packetlist)
				m_freem_list(packetlist);
			tp->t_lastchain = 0;
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
			if (packetlist)
				m_freem_list(packetlist);
			tp->t_lastchain = 0;
			KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
			return 0;
		}
		if ((error == EHOSTUNREACH || error == ENETDOWN)
		    && TCPS_HAVERCVDSYN(tp->t_state)) {
			tp->t_softerror = error;
			if (packetlist)
				m_freem_list(packetlist);
			tp->t_lastchain = 0;
			KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
			return (0);
		}
		if (packetlist)
			m_freem_list(packetlist);
		tp->t_lastchain = 0;
		KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END, 0,0,0,0,0);
		return (error);
	}
sentit:
	tcpstat.tcps_sndtotal++;

	/*
	 * Data sent (as far as we can tell).
	 * If this advertises a larger window than any other segment,
	 * then remember the size of the advertised window.
	 * Any pending ACK has now been sent.
	 */
	if (win > 0 && SEQ_GT(tp->rcv_nxt+win, tp->rcv_adv))
		tp->rcv_adv = tp->rcv_nxt + win;
	tp->last_ack_sent = tp->rcv_nxt;
	tp->t_flags &= ~(TF_ACKNOW|TF_DELACK);

	KERNEL_DEBUG(DBG_FNC_TCP_OUTPUT | DBG_FUNC_END,0,0,0,0,0);
	if (sendalot && (!tcp_do_newreno || --maxburst))
		goto again;
	return (0);
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
