/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
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
 *	@(#)tcp_timer.c	8.2 (Berkeley) 5/24/95
 * $FreeBSD: src/sys/netinet/tcp_timer.c,v 1.34.2.11 2001/08/22 00:59:12 silby Exp $
 */


#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>

#include <kern/cpu_number.h>	/* before tcp_seq.h, for tcp_random18() */

#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_pcb.h>
#if INET6
#include <netinet6/in6_pcb.h>
#endif
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#if TCPDEBUG
#include <netinet/tcp_debug.h>
#endif
#include <sys/kdebug.h>

#define DBG_FNC_TCP_FAST	NETDBG_CODE(DBG_NETTCP, (5 << 8))
#define DBG_FNC_TCP_SLOW	NETDBG_CODE(DBG_NETTCP, (5 << 8) | 1)

/*
 * NOTE - WARNING
 *
 *
 * 
 *
 */
static int
sysctl_msec_to_ticks SYSCTL_HANDLER_ARGS
{
	int error, s, tt;

	tt = *(int *)oidp->oid_arg1;
	s = tt * 1000 / hz;

	error = sysctl_handle_int(oidp, &s, 0, req);
	if (error || !req->newptr)
		return (error);

	tt = s * hz / 1000;
	if (tt < 1)
		return (EINVAL);

	*(int *)oidp->oid_arg1 = tt;
        return (0);
}

int	tcp_keepinit;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPINIT, keepinit, CTLTYPE_INT|CTLFLAG_RW,
    &tcp_keepinit, 0, sysctl_msec_to_ticks, "I", "");

int	tcp_keepidle;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPIDLE, keepidle, CTLTYPE_INT|CTLFLAG_RW,
    &tcp_keepidle, 0, sysctl_msec_to_ticks, "I", "");

int	tcp_keepintvl;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPINTVL, keepintvl, CTLTYPE_INT|CTLFLAG_RW,
    &tcp_keepintvl, 0, sysctl_msec_to_ticks, "I", "");

int	tcp_delacktime;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_DELACKTIME, delacktime,
    CTLTYPE_INT|CTLFLAG_RW, &tcp_delacktime, 0, sysctl_msec_to_ticks, "I",
    "Time before a delayed ACK is sent");
 
int	tcp_msl;
SYSCTL_PROC(_net_inet_tcp, OID_AUTO, msl, CTLTYPE_INT|CTLFLAG_RW,
    &tcp_msl, 0, sysctl_msec_to_ticks, "I", "Maximum segment lifetime");

static int	always_keepalive = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, always_keepalive, CTLFLAG_RW, 
    &always_keepalive , 0, "Assume SO_KEEPALIVE on all TCP connections");

static int	tcp_keepcnt = TCPTV_KEEPCNT;
	/* max idle probes */
int	tcp_maxpersistidle;
	/* max idle time in persist */
int	tcp_maxidle;

struct	inpcbhead	time_wait_slots[N_TIME_WAIT_SLOTS];
int		cur_tw_slot = 0;

u_long		*delack_bitmask;


void	add_to_time_wait(tp) 
	struct tcpcb	*tp;
{
	int		tw_slot;

	LIST_REMOVE(tp->t_inpcb, inp_list);

	if (tp->t_timer[TCPT_2MSL] == 0) 
	    tp->t_timer[TCPT_2MSL] = 1;

	tp->t_rcvtime += tp->t_timer[TCPT_2MSL] & (N_TIME_WAIT_SLOTS - 1);
	tw_slot = (tp->t_timer[TCPT_2MSL] & (N_TIME_WAIT_SLOTS - 1)) + cur_tw_slot; 
	if (tw_slot >= N_TIME_WAIT_SLOTS)
	    tw_slot -= N_TIME_WAIT_SLOTS;

	LIST_INSERT_HEAD(&time_wait_slots[tw_slot], tp->t_inpcb, inp_list);
}





/*
 * Fast timeout routine for processing delayed acks
 */
void
tcp_fasttimo()
{
    register struct inpcb *inp;
    register struct tcpcb *tp;


    register u_long			i,j;
    register u_long			temp_mask;
    register u_long			elem_base = 0;
    struct inpcbhead			*head;
    int s = splnet();

    static
    int delack_checked = 0;

    KERNEL_DEBUG(DBG_FNC_TCP_FAST | DBG_FUNC_START, 0,0,0,0,0);

    if (!tcp_delack_enabled) 
	return;

    for (i=0; i < (tcbinfo.hashsize / 32); i++) {
	    if (delack_bitmask[i]) {
		temp_mask = 1;
		for (j=0; j < 32; j++) {
		    if (temp_mask & delack_bitmask[i]) {
			head = &tcbinfo.hashbase[elem_base + j];
			for (inp=head->lh_first; inp != 0; inp = inp->inp_hash.le_next) {
			    delack_checked++;
			    if ((tp = (struct tcpcb *)inp->inp_ppcb) && (tp->t_flags & TF_DELACK)) {
				tp->t_flags &= ~TF_DELACK;
				tp->t_flags |= TF_ACKNOW;
				tcpstat.tcps_delack++;
				(void) tcp_output(tp);
			    }
			}
		    }
		    temp_mask <<=  1;
		}
		delack_bitmask[i] = 0;
	    }
	    elem_base += 32;
    }
    KERNEL_DEBUG(DBG_FNC_TCP_FAST | DBG_FUNC_END, delack_checked,tcpstat.tcps_delack,0,0,0);
    splx(s);

}

/*
 * Tcp protocol timeout routine called every 500 ms.
 * Updates the timers in all active tcb's and
 * causes finite state machine actions if timers expire.
 */
void
tcp_slowtimo()
{
	register struct inpcb *ip, *ipnxt;
	register struct tcpcb *tp;
	register int i;
	int s;
#if TCPDEBUG
	int ostate;
#endif
#if KDEBUG
	static int tws_checked;
#endif

	KERNEL_DEBUG(DBG_FNC_TCP_SLOW | DBG_FUNC_START, 0,0,0,0,0);
	s = splnet();

	tcp_maxidle = tcp_keepcnt * tcp_keepintvl;

	ip = tcb.lh_first;
	if (ip == NULL) {
		splx(s);
		return;
	}
	/*
	 * Search through tcb's and update active timers.
	 */
	for (; ip != NULL; ip = ipnxt) {
		ipnxt = ip->inp_list.le_next;
		tp = intotcpcb(ip);
		if (tp == 0 || tp->t_state == TCPS_LISTEN)
			continue;
		/*
 		 * Bogus state when port owned by SharedIP with loopback as the
		 * only configured interface: BlueBox does not filters loopback
		 */
		if (tp->t_state == TCP_NSTATES)
			continue;      

		for (i = 0; i < TCPT_NTIMERS; i++) {
			if (tp->t_timer[i] && --tp->t_timer[i] == 0) {
#if TCPDEBUG
				ostate = tp->t_state;
#endif
				tp = tcp_timers(tp, i);
				if (tp == NULL)
					goto tpgone;
#if TCPDEBUG
				if (tp->t_inpcb->inp_socket->so_options
				    & SO_DEBUG)
					tcp_trace(TA_USER, ostate, tp,
						  (void *)0,
						  (struct tcphdr *)0,
						  PRU_SLOWTIMO);
#endif
			}
		}
		tp->t_rcvtime++;
		tp->t_starttime++;
		if (tp->t_rtttime)
			tp->t_rtttime++;
tpgone:
		;
	}

#if KDEBUG
	tws_checked = 0;
#endif
	KERNEL_DEBUG(DBG_FNC_TCP_SLOW | DBG_FUNC_NONE, tws_checked,0,0,0,0);

	/*
	 * Process the items in the current time-wait slot
	 */

	for (ip = time_wait_slots[cur_tw_slot].lh_first; ip; ip = ipnxt)
	{
#if KDEBUG
	        tws_checked++;
#endif
		ipnxt = ip->inp_list.le_next;
		tp = intotcpcb(ip);
		if (tp == NULL) { /* tp already closed, remove from list */
			LIST_REMOVE(ip, inp_list);
			continue; 
		}
		if (tp->t_timer[TCPT_2MSL] >= N_TIME_WAIT_SLOTS) {
		    tp->t_timer[TCPT_2MSL] -= N_TIME_WAIT_SLOTS;
		    tp->t_rcvtime += N_TIME_WAIT_SLOTS;
		}
		else
		    tp->t_timer[TCPT_2MSL] = 0;

		if (tp->t_timer[TCPT_2MSL] == 0) 
		    tp = tcp_timers(tp, TCPT_2MSL);
	}

	if (++cur_tw_slot >= N_TIME_WAIT_SLOTS)
		cur_tw_slot = 0;
	tcp_now++;					/* for timestamps */
	splx(s);
	KERNEL_DEBUG(DBG_FNC_TCP_SLOW | DBG_FUNC_END, tws_checked, cur_tw_slot,0,0,0);
}

/*
 * Cancel all timers for TCP tp.
 */
void
tcp_canceltimers(tp)
	struct tcpcb *tp;
{
	register int i;

	for (i = 0; i < TCPT_NTIMERS; i++)
		tp->t_timer[i] = 0;
}

int	tcp_syn_backoff[TCP_MAXRXTSHIFT + 1] =
    { 1, 1, 1, 1, 1, 2, 4, 8, 16, 32, 64, 64, 64 };

int	tcp_backoff[TCP_MAXRXTSHIFT + 1] =
    { 1, 2, 4, 8, 16, 32, 64, 64, 64, 64, 64, 64, 64 };

static int tcp_totbackoff = 511;	/* sum of tcp_backoff[] */

/*
 * TCP timer processing.
 */
struct tcpcb *
tcp_timers(tp, timer)
	register struct tcpcb *tp;
	int timer;
{
	register int rexmt;
	struct socket *so_tmp;
	struct tcptemp *t_template;

#if TCPDEBUG
	int ostate;
#endif

#if INET6
	int isipv6 = (tp->t_inpcb->inp_vflag & INP_IPV4) == 0;
#endif /* INET6 */


	switch (timer) {

	/*
	 * 2 MSL timeout in shutdown went off.  If we're closed but
	 * still waiting for peer to close and connection has been idle
	 * too long, or if 2MSL time is up from TIME_WAIT, delete connection
	 * control block.  Otherwise, check again in a bit.
	 */
	case TCPT_2MSL:
		if (tp->t_state != TCPS_TIME_WAIT &&
		    tp->t_rcvtime <= tcp_maxidle) {
			tp->t_timer[TCPT_2MSL] = tcp_keepintvl;
			add_to_time_wait(tp);
		}
		else
			tp = tcp_close(tp);
		break;

	/*
	 * Retransmission timer went off.  Message has not
	 * been acked within retransmit interval.  Back off
	 * to a longer retransmit interval and retransmit one segment.
	 */
	case TCPT_REXMT:
		if (++tp->t_rxtshift > TCP_MAXRXTSHIFT) {
			tp->t_rxtshift = TCP_MAXRXTSHIFT;
			tcpstat.tcps_timeoutdrop++;
			so_tmp = tp->t_inpcb->inp_socket;
			tp = tcp_drop(tp, tp->t_softerror ?
			    tp->t_softerror : ETIMEDOUT);
			postevent(so_tmp, 0, EV_TIMEOUT);			
			break;
		}

		if (tp->t_rxtshift == 1) {
			/*
			 * first retransmit; record ssthresh and cwnd so they can
			 * be recovered if this turns out to be a "bad" retransmit.
			 * A retransmit is considered "bad" if an ACK for this 
			 * segment is received within RTT/2 interval; the assumption
			 * here is that the ACK was already in flight.  See 
			 * "On Estimating End-to-End Network Path Properties" by
			 * Allman and Paxson for more details.
			 */
			tp->snd_cwnd_prev = tp->snd_cwnd;
			tp->snd_ssthresh_prev = tp->snd_ssthresh;
			tp->t_badrxtwin = tcp_now + (tp->t_srtt >> (TCP_RTT_SHIFT + 1));
		}
		tcpstat.tcps_rexmttimeo++;
		if (tp->t_state == TCPS_SYN_SENT)
			rexmt = TCP_REXMTVAL(tp) * tcp_syn_backoff[tp->t_rxtshift];
		else
			rexmt = TCP_REXMTVAL(tp) * tcp_backoff[tp->t_rxtshift];
		TCPT_RANGESET(tp->t_rxtcur, rexmt,
			tp->t_rttmin, TCPTV_REXMTMAX);
		tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;

		/*
		 * Disable rfc1323 and rfc1644 if we havn't got any response to
		 * our third SYN to work-around some broken terminal servers 
		 * (most of which have hopefully been retired) that have bad VJ 
		 * header compression code which trashes TCP segments containing 
		 * unknown-to-them TCP options.
		 */
		if ((tp->t_state == TCPS_SYN_SENT) && (tp->t_rxtshift == 3))
				tp->t_flags &= ~(TF_REQ_SCALE|TF_REQ_TSTMP|TF_REQ_CC);
		/*
		 * If losing, let the lower level know and try for
		 * a better route.  Also, if we backed off this far,
		 * our srtt estimate is probably bogus.  Clobber it
		 * so we'll take the next rtt measurement as our srtt;
		 * move the current srtt into rttvar to keep the current
		 * retransmit times until then.
		 */
		if (tp->t_rxtshift > TCP_MAXRXTSHIFT / 4) {
#if INET6
			if (isipv6)
				in6_losing(tp->t_inpcb);
			else
#endif /* INET6 */
			in_losing(tp->t_inpcb);
			tp->t_rttvar += (tp->t_srtt >> TCP_RTT_SHIFT);
			tp->t_srtt = 0;
		}
		tp->snd_nxt = tp->snd_una;
		/*
		 * Note:  We overload snd_recover to function also as the
		 * snd_last variable described in RFC 2582
		 */
		tp->snd_recover = tp->snd_max;
		/*
		 * Force a segment to be sent.
		 */
		tp->t_flags |= TF_ACKNOW;
		/*
		 * If timing a segment in this window, stop the timer.
		 */
		tp->t_rtttime = 0;
		/*
		 * Close the congestion window down to one segment
		 * (we'll open it by one segment for each ack we get).
		 * Since we probably have a window's worth of unacked
		 * data accumulated, this "slow start" keeps us from
		 * dumping all that data as back-to-back packets (which
		 * might overwhelm an intermediate gateway).
		 *
		 * There are two phases to the opening: Initially we
		 * open by one mss on each ack.  This makes the window
		 * size increase exponentially with time.  If the
		 * window is larger than the path can handle, this
		 * exponential growth results in dropped packet(s)
		 * almost immediately.  To get more time between
		 * drops but still "push" the network to take advantage
		 * of improving conditions, we switch from exponential
		 * to linear window opening at some threshhold size.
		 * For a threshhold, we use half the current window
		 * size, truncated to a multiple of the mss.
		 *
		 * (the minimum cwnd that will give us exponential
		 * growth is 2 mss.  We don't allow the threshhold
		 * to go below this.)
		 */
		{
		u_int win = min(tp->snd_wnd, tp->snd_cwnd) / 2 / tp->t_maxseg;
		if (win < 2)
			win = 2;
		tp->snd_cwnd = tp->t_maxseg;
		tp->snd_ssthresh = win * tp->t_maxseg;
		tp->t_dupacks = 0;
		}
		(void) tcp_output(tp);
		break;

	/*
	 * Persistance timer into zero window.
	 * Force a byte to be output, if possible.
	 */
	case TCPT_PERSIST:
		tcpstat.tcps_persisttimeo++;
		/*
		 * Hack: if the peer is dead/unreachable, we do not
		 * time out if the window is closed.  After a full
		 * backoff, drop the connection if the idle time
		 * (no responses to probes) reaches the maximum
		 * backoff that we would use if retransmitting.
		 */
		if (tp->t_rxtshift == TCP_MAXRXTSHIFT &&
		    (tp->t_rcvtime >= tcp_maxpersistidle ||
		    tp->t_rcvtime >= TCP_REXMTVAL(tp) * tcp_totbackoff)) {
			tcpstat.tcps_persistdrop++;
			so_tmp = tp->t_inpcb->inp_socket;
			tp = tcp_drop(tp, ETIMEDOUT);
			postevent(so_tmp, 0, EV_TIMEOUT);
			break;
		}
		tcp_setpersist(tp);
		tp->t_force = 1;
		(void) tcp_output(tp);
		tp->t_force = 0;
		break;

	/*
	 * Keep-alive timer went off; send something
	 * or drop connection if idle for too long.
	 */
	case TCPT_KEEP:
		tcpstat.tcps_keeptimeo++;
		if (tp->t_state < TCPS_ESTABLISHED)
			goto dropit;
		if ((always_keepalive ||
		    tp->t_inpcb->inp_socket->so_options & SO_KEEPALIVE) &&
		    tp->t_state <= TCPS_CLOSING) {
		    	if (tp->t_rcvtime >= TCP_KEEPIDLE(tp) + tcp_maxidle)
				goto dropit;
			/*
			 * Send a packet designed to force a response
			 * if the peer is up and reachable:
			 * either an ACK if the connection is still alive,
			 * or an RST if the peer has closed the connection
			 * due to timeout or reboot.
			 * Using sequence number tp->snd_una-1
			 * causes the transmitted zero-length segment
			 * to lie outside the receive window;
			 * by the protocol spec, this requires the
			 * correspondent TCP to respond.
			 */
			tcpstat.tcps_keepprobe++;
			t_template = tcp_maketemplate(tp);
			if (t_template) {
				tcp_respond(tp, t_template->tt_ipgen,
				    &t_template->tt_t, (struct mbuf *)NULL,
				    tp->rcv_nxt, tp->snd_una - 1, 0);
				(void) m_free(dtom(t_template));
			}
			tp->t_timer[TCPT_KEEP] = tcp_keepintvl;
		} else
			tp->t_timer[TCPT_KEEP] = TCP_KEEPIDLE(tp);
		break;

#if TCPDEBUG
	if (tp->t_inpcb->inp_socket->so_options & SO_DEBUG)
		tcp_trace(TA_USER, ostate, tp, (void *)0, (struct tcphdr *)0,
			  PRU_SLOWTIMO);
#endif
	dropit:
		tcpstat.tcps_keepdrops++;
		so_tmp = tp->t_inpcb->inp_socket;
		tp = tcp_drop(tp, ETIMEDOUT);
		postevent(so_tmp, 0, EV_TIMEOUT);
		break;
	}
	return (tp);
}
