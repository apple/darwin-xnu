/*
 * Copyright (c) 2013-2014 Apple Inc. All rights reserved.
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
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>

#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#if INET6
#include <netinet/ip6.h>
#endif /* INET6 */

#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_cc.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_seq.h>
#include <kern/task.h>
#include <libkern/OSAtomic.h>

static int tcp_cubic_init(struct tcpcb *tp);
static int tcp_cubic_cleanup(struct tcpcb *tp);
static void tcp_cubic_cwnd_init_or_reset(struct tcpcb *tp);
static void tcp_cubic_congestion_avd(struct tcpcb *tp, struct tcphdr *th);
static void tcp_cubic_ack_rcvd(struct tcpcb *tp, struct tcphdr *th);
static void tcp_cubic_pre_fr(struct tcpcb *tp);
static void tcp_cubic_post_fr(struct tcpcb *tp, struct tcphdr *th);
static void tcp_cubic_after_timeout(struct tcpcb *tp);
static int tcp_cubic_delay_ack(struct tcpcb *tp, struct tcphdr *th);
static void tcp_cubic_switch_cc(struct tcpcb *tp, u_int16_t old_index);
static uint32_t tcp_cubic_update(struct tcpcb *tp, u_int32_t rtt);
static uint32_t tcp_cubic_tcpwin(struct tcpcb *tp, struct tcphdr *th);
static inline void tcp_cubic_clear_state(struct tcpcb *tp);


extern float cbrtf(float x);

struct tcp_cc_algo tcp_cc_cubic = {
	.name = "cubic",
	.init = tcp_cubic_init,
	.cleanup = tcp_cubic_cleanup,
	.cwnd_init = tcp_cubic_cwnd_init_or_reset,
	.congestion_avd = tcp_cubic_congestion_avd,
	.ack_rcvd = tcp_cubic_ack_rcvd,
	.pre_fr = tcp_cubic_pre_fr,
	.post_fr = tcp_cubic_post_fr,
	.after_idle = tcp_cubic_cwnd_init_or_reset,
	.after_timeout = tcp_cubic_after_timeout,
	.delay_ack = tcp_cubic_delay_ack,
	.switch_to = tcp_cubic_switch_cc
};

const float tcp_cubic_backoff = 0.2; /* multiplicative decrease factor */
const float tcp_cubic_coeff = 0.4;
const float tcp_cubic_fast_convergence_factor = 0.875;

SYSCTL_SKMEM_TCP_INT(OID_AUTO, cubic_tcp_friendliness, CTLFLAG_RW | CTLFLAG_LOCKED,
	static int, tcp_cubic_tcp_friendliness, 0, "Enable TCP friendliness");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, cubic_fast_convergence, CTLFLAG_RW | CTLFLAG_LOCKED,
	static int, tcp_cubic_fast_convergence, 0, "Enable fast convergence");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, cubic_use_minrtt, CTLFLAG_RW | CTLFLAG_LOCKED,
	static int, tcp_cubic_use_minrtt, 0, "use a min of 5 sec rtt");

static int tcp_cubic_init(struct tcpcb *tp)
{
	OSIncrementAtomic((volatile SInt32 *)&tcp_cc_cubic.num_sockets);

	VERIFY(tp->t_ccstate != NULL);
	tcp_cubic_clear_state(tp);
	return (0);
}

static int tcp_cubic_cleanup(struct tcpcb *tp)
{
#pragma unused(tp)
	OSDecrementAtomic((volatile SInt32 *)&tcp_cc_cubic.num_sockets);
	return (0);
}

/*
 * Initialize the congestion window at the beginning of a connection or 
 * after idle time
 */
static void tcp_cubic_cwnd_init_or_reset(struct tcpcb *tp)
{
	VERIFY(tp->t_ccstate != NULL);	

	tcp_cubic_clear_state(tp);
	tcp_cc_cwnd_init_or_reset(tp);
	tp->t_pipeack = 0;
	tcp_clear_pipeack_state(tp);

	/* Start counting bytes for RFC 3465 again */
	tp->t_bytes_acked = 0;

	/*
	 * slow start threshold could get initialized to a lower value
	 * when there is a cached value in the route metrics. In this case,
	 * the connection can enter congestion avoidance without any packet
	 * loss and Cubic will enter steady-state too early. It is better
	 * to always probe to find the initial slow-start threshold.
	 */
	if (tp->t_inpcb->inp_stat->txbytes <= TCP_CC_CWND_INIT_BYTES
	    && tp->snd_ssthresh < (TCP_MAXWIN << TCP_MAX_WINSHIFT))
		tp->snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;

	/* Initialize cubic last max to be same as ssthresh */
	tp->t_ccstate->cub_last_max = tp->snd_ssthresh;
}

/*
 * Compute the target congestion window for the next RTT according to 
 * cubic equation when an ack is received.
 *
 * W(t) = C(t-K)^3 + W(last_max)
 */
static uint32_t
tcp_cubic_update(struct tcpcb *tp, u_int32_t rtt)
{
	float K, var;
	u_int32_t elapsed_time, win;

	win = min(tp->snd_cwnd, tp->snd_wnd);
	if (tp->t_ccstate->cub_last_max == 0)
		tp->t_ccstate->cub_last_max = tp->snd_ssthresh;

	if (tp->t_ccstate->cub_epoch_start == 0) {
		/*
		 * This is the beginning of a new epoch, initialize some of
		 * the variables that we need to use for computing the 
		 * congestion window later.
		 */
		tp->t_ccstate->cub_epoch_start = tcp_now;
		if (tp->t_ccstate->cub_epoch_start == 0)
			tp->t_ccstate->cub_epoch_start = 1;
		if (win < tp->t_ccstate->cub_last_max) {

			VERIFY(current_task() == kernel_task);

			/*
			 * Compute cubic epoch period, this is the time
			 * period that the window will take to increase to
			 * last_max again after backoff due to loss.
			 */
			K = (tp->t_ccstate->cub_last_max - win)
			    / tp->t_maxseg / tcp_cubic_coeff;
			K = cbrtf(K);
			tp->t_ccstate->cub_epoch_period = K * TCP_RETRANSHZ;
			/* Origin point */
			tp->t_ccstate->cub_origin_point = 
				tp->t_ccstate->cub_last_max;
		} else {
			tp->t_ccstate->cub_epoch_period = 0;
			tp->t_ccstate->cub_origin_point = win;
		}
		tp->t_ccstate->cub_target_win = 0;
	}
	
	VERIFY(tp->t_ccstate->cub_origin_point > 0);	
	/*
	 * Compute the target window for the next RTT using smoothed RTT
	 * as an estimate for next RTT.
	 */
	elapsed_time = timer_diff(tcp_now, 0, 
		tp->t_ccstate->cub_epoch_start, 0);

	if (tcp_cubic_use_minrtt)
		elapsed_time += max(tcp_cubic_use_minrtt, rtt);
	else
		elapsed_time += rtt;
	var = (elapsed_time  - tp->t_ccstate->cub_epoch_period) / TCP_RETRANSHZ;
	var = var * var * var * (tcp_cubic_coeff * tp->t_maxseg);

	tp->t_ccstate->cub_target_win = (u_int32_t)(tp->t_ccstate->cub_origin_point + var);
	return (tp->t_ccstate->cub_target_win);
}

/*
 * Standard TCP utilizes bandwidth well in low RTT and low BDP connections
 * even when there is some packet loss. Enabling TCP mode will help Cubic
 * to achieve this kind of utilization.
 *
 * But if there is a bottleneck link in the path with a fixed size queue
 * and fixed bandwidth, TCP Cubic will help to reduce packet loss at this
 * link because of the steady-state behavior. Using average and mean
 * absolute deviation of W(lastmax), we try to detect if the congestion
 * window is close to the bottleneck bandwidth. In that case, disabling
 * TCP mode will help to minimize packet loss at this link. 
 *
 * Disable TCP mode if the W(lastmax) (the window where previous packet
 * loss happened) is within a small range from the average last max
 * calculated.
 */
#define TCP_CUBIC_ENABLE_TCPMODE(_tp_) \
	((!soissrcrealtime((_tp_)->t_inpcb->inp_socket) && \
	(_tp_)->t_ccstate->cub_mean_dev > (tp->t_maxseg << 1)) ? 1 : 0)

/*
 * Compute the window growth if standard TCP (AIMD) was used with 
 * a backoff of 0.5 and additive increase of 1 packet per RTT.
 * 
 * TCP window at time t can be calculated using the following equation
 * with beta as 0.8 
 *
 * W(t) <- Wmax * beta + 3 * ((1 - beta)/(1 + beta)) * t/RTT
 *
 */
static uint32_t
tcp_cubic_tcpwin(struct tcpcb *tp, struct tcphdr *th)
{
	if (tp->t_ccstate->cub_tcp_win == 0) {
		tp->t_ccstate->cub_tcp_win = min(tp->snd_cwnd, tp->snd_wnd);
		tp->t_ccstate->cub_tcp_bytes_acked = 0;
	} else {
		tp->t_ccstate->cub_tcp_bytes_acked +=
		    BYTES_ACKED(th, tp);
		if (tp->t_ccstate->cub_tcp_bytes_acked >=
		    tp->t_ccstate->cub_tcp_win) {
			tp->t_ccstate->cub_tcp_bytes_acked -=
			    tp->t_ccstate->cub_tcp_win;
			tp->t_ccstate->cub_tcp_win += tp->t_maxseg;
		}
	}	
	return (tp->t_ccstate->cub_tcp_win);
}

/*
 * Handle an in-sequence ack during congestion avoidance phase.
 */
static void
tcp_cubic_congestion_avd(struct tcpcb *tp, struct tcphdr *th)
{
	u_int32_t cubic_target_win, tcp_win, rtt;

	/* Do not increase congestion window in non-validated phase */
	if (tcp_cc_is_cwnd_nonvalidated(tp) != 0)
		return;

	tp->t_bytes_acked += BYTES_ACKED(th, tp);

	rtt = get_base_rtt(tp);
	/*
	 * First compute cubic window. If cubic variables are not
	 * initialized (after coming out of recovery), this call will
	 * initialize them.
	 */
	cubic_target_win = tcp_cubic_update(tp, rtt);

	/* Compute TCP window if a multiplicative decrease of 0.2 is used */
	tcp_win = tcp_cubic_tcpwin(tp, th);

	if (tp->snd_cwnd < tcp_win &&
	    (tcp_cubic_tcp_friendliness == 1 ||
	    TCP_CUBIC_ENABLE_TCPMODE(tp))) {
		/* this connection is in TCP-friendly region */
		if (tp->t_bytes_acked >= tp->snd_cwnd) {
			tp->t_bytes_acked -= tp->snd_cwnd;
			tp->snd_cwnd = min(tcp_win, TCP_MAXWIN << tp->snd_scale);
		}
	} else {
		if (cubic_target_win > tp->snd_cwnd) {
			/*
			 * The target win is computed for the next RTT.
			 * To reach this value, cwnd will have to be updated
			 * one segment at a time. Compute how many bytes 
			 * need to be acknowledged before we can increase 
			 * the cwnd by one segment.
			 */
			u_int64_t incr_win;
			incr_win = tp->snd_cwnd * tp->t_maxseg;
			incr_win /= (cubic_target_win - tp->snd_cwnd);
			if (incr_win > 0 &&
			    tp->t_bytes_acked >= incr_win) {
				tp->t_bytes_acked -= incr_win;
				tp->snd_cwnd = 
				    min((tp->snd_cwnd + tp->t_maxseg),
				    TCP_MAXWIN << tp->snd_scale);
			}
		}
	}
}

static void
tcp_cubic_ack_rcvd(struct tcpcb *tp, struct tcphdr *th)
{
	/* Do not increase the congestion window in non-validated phase */
	if (tcp_cc_is_cwnd_nonvalidated(tp) != 0)
		return;

	if (tp->snd_cwnd >= tp->snd_ssthresh) {
		/* Congestion avoidance phase */
		tcp_cubic_congestion_avd(tp, th);
	} else {
		/*
		 * Use 2*SMSS as limit on increment as suggested
		 * by RFC 3465 section 2.3
		 */
		uint32_t acked, abc_lim, incr;

		acked = BYTES_ACKED(th, tp);
		abc_lim = (tcp_do_rfc3465_lim2 && 
			tp->snd_nxt == tp->snd_max) ?
			2 * tp->t_maxseg : tp->t_maxseg;
		incr = min(acked, abc_lim);

		tp->snd_cwnd += incr;
		tp->snd_cwnd = min(tp->snd_cwnd, 
			TCP_MAXWIN << tp->snd_scale);
	}
}

static void
tcp_cubic_pre_fr(struct tcpcb *tp)
{
	u_int32_t win, avg;
	int32_t dev;
	tp->t_ccstate->cub_epoch_start = 0;
	tp->t_ccstate->cub_tcp_win = 0;
	tp->t_ccstate->cub_target_win = 0;
	tp->t_ccstate->cub_tcp_bytes_acked = 0;

	win = min(tp->snd_cwnd, tp->snd_wnd);
	if (tp->t_flagsext & TF_CWND_NONVALIDATED) {
		tp->t_lossflightsize = tp->snd_max - tp->snd_una;
		win = (max(tp->t_pipeack, tp->t_lossflightsize)) >> 1;
	} else {
		tp->t_lossflightsize = 0;
	}
	/*
	 * Note the congestion window at which packet loss occurred as
	 * cub_last_max.
	 *
	 * If the congestion window is less than the last max window when
	 * loss occurred, it indicates that capacity available in the 
	 * network has gone down. This can happen if a new flow has started
	 * and it is capturing some of the bandwidth. To reach convergence
	 * quickly, backoff a little more. Disable fast convergence to 
	 * disable this behavior.
	 */
	if (win < tp->t_ccstate->cub_last_max &&
		tcp_cubic_fast_convergence == 1)
		tp->t_ccstate->cub_last_max = (u_int32_t)(win *
			tcp_cubic_fast_convergence_factor);
	else
		tp->t_ccstate->cub_last_max = win;

	if (tp->t_ccstate->cub_last_max == 0) {
		/*
		 * If last_max is zero because snd_wnd is zero or for
		 * any other reason, initialize it to the amount of data
		 * in flight
		 */
		tp->t_ccstate->cub_last_max = tp->snd_max - tp->snd_una;
	}

	/*
	 * Compute average and mean absolute deviation of the
	 * window at which packet loss occurred.
	 */
	if (tp->t_ccstate->cub_avg_lastmax == 0) {
		tp->t_ccstate->cub_avg_lastmax = tp->t_ccstate->cub_last_max;
	} else {
		/*
		 * Average is computed by taking 63 parts of
		 * history and one part of the most recent value
		 */
		avg = tp->t_ccstate->cub_avg_lastmax;
		avg = (avg << 6) - avg;
		tp->t_ccstate->cub_avg_lastmax =
		    (avg + tp->t_ccstate->cub_last_max) >> 6; 
	}

	/* caluclate deviation from average */
	dev = tp->t_ccstate->cub_avg_lastmax - tp->t_ccstate->cub_last_max;

	/* Take the absolute value */
	if (dev < 0)
		dev = -dev;

	if (tp->t_ccstate->cub_mean_dev == 0) {
		tp->t_ccstate->cub_mean_dev = dev;
	} else {
		dev = dev + ((tp->t_ccstate->cub_mean_dev << 4)
		    - tp->t_ccstate->cub_mean_dev);
		tp->t_ccstate->cub_mean_dev = dev >> 4;
	}

	/* Backoff congestion window by tcp_cubic_backoff factor */
	win = (u_int32_t)(win - (win * tcp_cubic_backoff));
	win = (win / tp->t_maxseg);
	if (win < 2)
		win = 2;
	tp->snd_ssthresh = win * tp->t_maxseg;
	tcp_cc_resize_sndbuf(tp);
}

static void
tcp_cubic_post_fr(struct tcpcb *tp, struct tcphdr *th)
{
	uint32_t flight_size = 0;

	if (SEQ_LEQ(th->th_ack, tp->snd_max))
		flight_size = tp->snd_max - th->th_ack;

	if (SACK_ENABLED(tp) && tp->t_lossflightsize > 0) {
		u_int32_t total_rxt_size = 0, ncwnd;
		/*
		 * When SACK is enabled, the number of retransmitted bytes
		 * can be counted more accurately.
		 */
		total_rxt_size = tcp_rxtseg_total_size(tp);
		ncwnd = max(tp->t_pipeack, tp->t_lossflightsize);
		if (total_rxt_size <= ncwnd) {
			ncwnd = ncwnd - total_rxt_size;
		}

		/*
		 * To avoid sending a large burst at the end of recovery
		 * set a max limit on ncwnd
		 */
		ncwnd = min(ncwnd, (tp->t_maxseg << 6));
		ncwnd = ncwnd >> 1;
		flight_size = max(ncwnd, flight_size);
	}
	/*
	 * Complete ack. The current window was inflated for fast recovery.
	 * It has to be deflated post recovery.
	 *
	 * Window inflation should have left us with approx snd_ssthresh 
	 * outstanding data. If the flight size is zero or one segment,
	 * make congestion window to be at least as big as 2 segments to
	 * avoid delayed acknowledgements. This is according to RFC 6582.
	 */
	if (flight_size < tp->snd_ssthresh)
		tp->snd_cwnd = max(flight_size, tp->t_maxseg) 
				+ tp->t_maxseg;
	else
		tp->snd_cwnd = tp->snd_ssthresh;
	tp->t_ccstate->cub_tcp_win = 0;
	tp->t_ccstate->cub_target_win = 0;
	tp->t_ccstate->cub_tcp_bytes_acked = 0;
}

static void 
tcp_cubic_after_timeout(struct tcpcb *tp)
{
	VERIFY(tp->t_ccstate != NULL);

	/*
	 * Avoid adjusting congestion window due to SYN retransmissions.
	 * If more than one byte (SYN) is outstanding then it is still
	 * needed to adjust the window.
	 */
	if (tp->t_state < TCPS_ESTABLISHED &&
	    ((int)(tp->snd_max - tp->snd_una) <= 1))
		return;

	if (!IN_FASTRECOVERY(tp)) {
		tcp_cubic_clear_state(tp);
		tcp_cubic_pre_fr(tp);
	}

	/*
	 * Close the congestion window down to one segment as a retransmit
	 * timeout might indicate severe congestion.
	 */
	tp->snd_cwnd = tp->t_maxseg;
}

static int
tcp_cubic_delay_ack(struct tcpcb *tp, struct tcphdr *th)
{
	return (tcp_cc_delay_ack(tp, th));
}

/*
 * When switching from a different CC it is better for Cubic to start 
 * fresh. The state required for Cubic calculation might be stale and it
 * might not represent the current state of the network. If it starts as
 * a new connection it will probe and learn the existing network conditions.
 */
static void
tcp_cubic_switch_cc(struct tcpcb *tp, uint16_t old_cc_index)
{
#pragma unused(old_cc_index)
	tcp_cubic_cwnd_init_or_reset(tp);

	OSIncrementAtomic((volatile SInt32 *)&tcp_cc_cubic.num_sockets);
}

static inline void tcp_cubic_clear_state(struct tcpcb *tp)
{
	tp->t_ccstate->cub_last_max = 0;
	tp->t_ccstate->cub_epoch_start = 0;
	tp->t_ccstate->cub_origin_point = 0;
	tp->t_ccstate->cub_tcp_win = 0;
	tp->t_ccstate->cub_tcp_bytes_acked = 0;
	tp->t_ccstate->cub_epoch_period = 0;
	tp->t_ccstate->cub_target_win = 0;
}
