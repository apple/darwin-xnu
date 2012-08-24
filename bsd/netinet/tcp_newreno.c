/*
 * Copyright (c) 2010-2012 Apple Inc. All rights reserved.
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
 *      The Regents of the University of California.  All rights reserved.
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
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
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
 *      @(#)tcp_input.c 8.12 (Berkeley) 5/24/95
 * $FreeBSD: src/sys/netinet/tcp_input.c,v 1.107.2.16 2001/08/22 00:59:12 silby Exp $
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>

#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#if INET6
#include <netinet/ip6.h>
#endif
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_cc.h>
#include <libkern/OSAtomic.h>

int tcp_newreno_init(struct tcpcb *tp);
int tcp_newreno_cleanup(struct tcpcb *tp);
void tcp_newreno_cwnd_init_or_reset(struct tcpcb *tp);
void tcp_newreno_inseq_ack_rcvd(struct tcpcb *tp, struct tcphdr *th);
void tcp_newreno_ack_rcvd(struct tcpcb *tp, struct tcphdr *th);
void tcp_newreno_pre_fr(struct tcpcb *tp);
void tcp_newreno_post_fr(struct tcpcb *tp, struct tcphdr *th);
void tcp_newreno_after_idle(struct tcpcb *tp);
void tcp_newreno_after_timeout(struct tcpcb *tp);
int tcp_newreno_delay_ack(struct tcpcb *tp, struct tcphdr *th);
void tcp_newreno_switch_cc(struct tcpcb *tp, uint16_t old_index);

struct tcp_cc_algo tcp_cc_newreno = {
	.name = "newreno",
	.init = tcp_newreno_init,
	.cleanup = tcp_newreno_cleanup,
	.cwnd_init = tcp_newreno_cwnd_init_or_reset,
	.inseq_ack_rcvd = tcp_newreno_inseq_ack_rcvd,
	.ack_rcvd = tcp_newreno_ack_rcvd,
	.pre_fr = tcp_newreno_pre_fr,
	.post_fr = tcp_newreno_post_fr,
	.after_idle = tcp_newreno_cwnd_init_or_reset,
	.after_timeout = tcp_newreno_after_timeout,
	.delay_ack = tcp_newreno_delay_ack,
	.switch_to = tcp_newreno_switch_cc
};

extern int tcp_do_rfc3465;
extern int tcp_do_rfc3465_lim2;
extern int maxseg_unacked;
extern u_int32_t tcp_autosndbuf_max;

#define SET_SNDSB_IDEAL_SIZE(sndsb, size) \
	sndsb->sb_idealsize = min(max(tcp_sendspace, tp->snd_ssthresh), \
		tcp_autosndbuf_max); 

void tcp_cc_resize_sndbuf(struct tcpcb *tp) {
	struct sockbuf *sb;
	/* If the send socket buffer size is bigger than ssthresh,
	 * it is time to trim it because we do not want to hold
	 * too many mbufs in the socket buffer
	 */
	sb = &(tp->t_inpcb->inp_socket->so_snd);
	if (sb->sb_hiwat > tp->snd_ssthresh &&
		(sb->sb_flags & SB_AUTOSIZE) != 0) {
		if (sb->sb_idealsize > tp->snd_ssthresh) {
			SET_SNDSB_IDEAL_SIZE(sb, tp->snd_ssthresh);
		}
		sb->sb_flags |= SB_TRIM;
	}
}

void tcp_bad_rexmt_fix_sndbuf(struct tcpcb *tp) {
	struct sockbuf *sb;
	sb = &(tp->t_inpcb->inp_socket->so_snd);
	if ((sb->sb_flags & (SB_TRIM|SB_AUTOSIZE)) == (SB_TRIM|SB_AUTOSIZE)) {
		/* If there was a retransmission that was not necessary 
		 * then the size of socket buffer can be restored to
		 * what it was before
		 */
		SET_SNDSB_IDEAL_SIZE(sb, tp->snd_ssthresh);
		if (sb->sb_hiwat <= sb->sb_idealsize) {
			sbreserve(sb, sb->sb_idealsize);
			sb->sb_flags &= ~SB_TRIM;
		}
	}
}

int tcp_newreno_init(struct tcpcb *tp) {
#pragma unused(tp)
	OSIncrementAtomic((volatile SInt32 *)&tcp_cc_newreno.num_sockets);
	return 0;
}

int tcp_newreno_cleanup(struct tcpcb *tp) {
#pragma unused(tp)
	OSDecrementAtomic((volatile SInt32 *)&tcp_cc_newreno.num_sockets);
	return 0;
}

/* Initialize the congestion window for a connection or
 * handles connections that have been idle for
 * some time. In this state, no acks are
 * expected to clock out any data we send --
 * slow start to get ack "clock" running again.
 *
 * Set the slow-start flight size depending on whether
 * this is a local network or not.
 */
void
tcp_newreno_cwnd_init_or_reset(struct tcpcb *tp) {
	if ( tp->t_flags & TF_LOCAL )
		tp->snd_cwnd = tp->t_maxseg * ss_fltsz_local;
        else {
		/* Calculate initial cwnd according to RFC3390,
		 * - On a standard link, this will result in a higher cwnd
		 * and improve initial transfer rate.
		 * - Keep the old ss_fltsz sysctl for ABI compabitility issues.
		 * but it will be overriden if tcp_do_rfc3390 sysctl is set.
		 */

		if (tcp_do_rfc3390) 
			tp->snd_cwnd = min(4 * tp->t_maxseg, max(2 * tp->t_maxseg, 4380));

		else
			tp->snd_cwnd = tp->t_maxseg * ss_fltsz;
	}
}


/* Function to handle an in-sequence ack during congestion avoidance phase.
 * This will get called from header prediction code.
 */
void
tcp_newreno_inseq_ack_rcvd(struct tcpcb *tp, struct tcphdr *th) {
	int acked = 0;
	acked = th->th_ack - tp->snd_una;
	/*
	 * Grow the congestion window, if the
	 * connection is cwnd bound.
	 */
	if (tp->snd_cwnd < tp->snd_wnd) {
		tp->t_bytes_acked += acked;
		if (tp->t_bytes_acked > tp->snd_cwnd) {
			tp->t_bytes_acked -= tp->snd_cwnd;
			tp->snd_cwnd += tp->t_maxseg;
		}
	}
}
/* Function to process an ack.
 */
void
tcp_newreno_ack_rcvd(struct tcpcb *tp, struct tcphdr *th) {
	/*
	 * RFC 3465 - Appropriate Byte Counting.
	 *
	 * If the window is currently less than ssthresh,
	 * open the window by the number of bytes ACKed by
	 * the last ACK, however clamp the window increase
	 * to an upper limit "L".
	 *
	 * In congestion avoidance phase, open the window by
	 * one segment each time "bytes_acked" grows to be
	 * greater than or equal to the congestion window.
	 */

	register u_int cw = tp->snd_cwnd;
	register u_int incr = tp->t_maxseg;
	int acked = 0;

	acked = th->th_ack - tp->snd_una;
	if (tcp_do_rfc3465) {

		if (cw >= tp->snd_ssthresh) {
			tp->t_bytes_acked += acked;
			if (tp->t_bytes_acked >= cw) {
				/* Time to increase the window. */
				tp->t_bytes_acked -= cw;
			} else {
				/* No need to increase yet. */
				incr = 0;
			}
		} else {
			/*
			 * If the user explicitly enables RFC3465
			 * use 2*SMSS for the "L" param.  Otherwise
			 * use the more conservative 1*SMSS.
			 *
			 * (See RFC 3465 2.3 Choosing the Limit)
			 */
			u_int abc_lim;

			abc_lim = (tcp_do_rfc3465_lim2 &&
				tp->snd_nxt == tp->snd_max) ? incr * 2 : incr;

			incr = lmin(acked, abc_lim);
		}
	} else {
		/*
		 * If the window gives us less than ssthresh packets
		 * in flight, open exponentially (segsz per packet).
		 * Otherwise open linearly: segsz per window
		 * (segsz^2 / cwnd per packet).
		 */

		if (cw >= tp->snd_ssthresh)
			incr = max((incr * incr / cw), 1);
	}
	tp->snd_cwnd = min(cw+incr, TCP_MAXWIN<<tp->snd_scale);
}

void
tcp_newreno_pre_fr(struct tcpcb *tp) {

	uint32_t win;

	win = min(tp->snd_wnd, tp->snd_cwnd) / 
		2 / tp->t_maxseg;
	if ( win < 2 )
		win = 2;
	tp->snd_ssthresh = win * tp->t_maxseg; 
	tcp_cc_resize_sndbuf(tp);

}

void
tcp_newreno_post_fr(struct tcpcb *tp, struct tcphdr *th) {
	int32_t ss;

	ss = tp->snd_max - th->th_ack;

	/*
	 * Complete ack.  Inflate the congestion window to
	 * ssthresh and exit fast recovery.
	 *
	 * Window inflation should have left us with approx.
	 * snd_ssthresh outstanding data.  But in case we
	 * would be inclined to send a burst, better to do
	 * it via the slow start mechanism.
	 */
	if (ss < (int32_t)tp->snd_ssthresh)
		tp->snd_cwnd = ss + tp->t_maxseg;
	else
		tp->snd_cwnd = tp->snd_ssthresh;
	tp->t_bytes_acked = 0;
}

/* Function to change the congestion window when the retransmit 
 * timer fires.
 */
void
tcp_newreno_after_timeout(struct tcpcb *tp) {
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
	if (tp->t_state >=  TCPS_ESTABLISHED) {
		u_int win = min(tp->snd_wnd, tp->snd_cwnd) / 2 / tp->t_maxseg;
		if (win < 2)
			win = 2;
		tp->snd_cwnd = tp->t_maxseg;
		tp->snd_ssthresh = win * tp->t_maxseg;
		tp->t_bytes_acked = 0;
		tp->t_dupacks = 0;

		tcp_cc_resize_sndbuf(tp);
	}
}

/*
 * Indicate whether this ack should be delayed.
 * We can delay the ack if:
 *  - delayed acks are enabled and set to 1, same as when value is set to 2. 
 *    We kept this for binary compatibility.
 *  - delayed acks are enabled and set to 2, will "ack every other packet"
 *      - if our last ack wasn't a 0-sized window.
 *      - if the peer hasn't sent us a TH_PUSH data packet (this solves 3649245). 
 *	  	If TH_PUSH is set, take this as a clue that we need to ACK 
 * 		with no delay. This helps higher level protocols who won't send
 *		us more data even if the window is open because their 
 *		last "segment" hasn't been ACKed
 *  - delayed acks are enabled and set to 3,  will do "streaming detection" 
 *    (see the comment in tcp_input.c) and
 *      - if we receive more than "maxseg_unacked" full packets in the last 100ms
 * 	- if the connection is not in slow-start or idle or loss/recovery states
 *      - if those criteria aren't met, it will ack every other packet.
 */

int
tcp_newreno_delay_ack(struct tcpcb *tp, struct tcphdr *th) {
	switch (tcp_delack_enabled) {
	case 1:
	case 2:
		if ((tp->t_flags & TF_RXWIN0SENT) == 0 &&
			(th->th_flags & TH_PUSH) == 0 &&
			(tp->t_unacksegs == 1))
			return(1);
		break;
	case 3:
		if ((tp->t_flags & TF_RXWIN0SENT) == 0 &&
			(th->th_flags & TH_PUSH) == 0 &&
			((tp->t_unacksegs == 1) ||
			((tp->t_flags & TF_STRETCHACK) != 0 &&
			tp->t_unacksegs < (maxseg_unacked))))
			return(1);
		break;
	}
	return(0);
}

/* Switch to newreno from a different CC. If the connection is in
 * congestion avoidance state, it can continue to use the current
 * congestion window because it is going to be conservative. But
 * if the connection is in slow-start, we will halve the congestion
 * window and let newreno work from there. 
 */
void
tcp_newreno_switch_cc(struct tcpcb *tp, uint16_t old_index) {
#pragma unused(old_index)

	uint32_t cwnd = min(tp->snd_wnd, tp->snd_cwnd);
	if (tp->snd_cwnd >= tp->snd_ssthresh) {
		cwnd = cwnd / tp->t_maxseg;
	} else { 
		cwnd = cwnd / 2 / tp->t_maxseg;
	}
	if (cwnd < 1)
		cwnd = 1;
	tp->snd_cwnd = cwnd * tp->t_maxseg;

	/* Start counting bytes for RFC 3465 again */
	tp->t_bytes_acked = 0;

	OSIncrementAtomic((volatile SInt32 *)&tcp_cc_newreno.num_sockets);
}
