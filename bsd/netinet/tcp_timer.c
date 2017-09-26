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
#include <sys/domain.h>
#include <sys/mcache.h>
#include <sys/queue.h>
#include <kern/locks.h>
#include <kern/cpu_number.h>	/* before tcp_seq.h, for tcp_random18() */
#include <mach/boolean.h>

#include <net/route.h>
#include <net/if_var.h>
#include <net/ntstat.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_pcb.h>
#if INET6
#include <netinet6/in6_pcb.h>
#endif
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_cache.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_cc.h>
#if INET6
#include <netinet6/tcp6_var.h>
#endif
#include <netinet/tcpip.h>
#if TCPDEBUG
#include <netinet/tcp_debug.h>
#endif
#include <sys/kdebug.h>
#include <mach/sdt.h>
#include <netinet/mptcp_var.h>

/* Max number of times a stretch ack can be delayed on a connection */
#define	TCP_STRETCHACK_DELAY_THRESHOLD	5

/*
 * If the host processor has been sleeping for too long, this is the threshold
 * used to avoid sending stale retransmissions.
 */
#define	TCP_SLEEP_TOO_LONG	(10 * 60 * 1000) /* 10 minutes in ms */

/* tcp timer list */
struct tcptimerlist tcp_timer_list;

/* List of pcbs in timewait state, protected by tcbinfo's ipi_lock */
struct tcptailq tcp_tw_tailq;

static int
sysctl_msec_to_ticks SYSCTL_HANDLER_ARGS
{
#pragma unused(arg2)
	int error, s, tt;

	tt = *(int *)arg1;
	s = tt * 1000 / TCP_RETRANSHZ;;

	error = sysctl_handle_int(oidp, &s, 0, req);
	if (error || !req->newptr)
		return (error);

	tt = s * TCP_RETRANSHZ / 1000;
	if (tt < 1)
		return (EINVAL);

	*(int *)arg1 = tt;
	SYSCTL_SKMEM_UPDATE_AT_OFFSET(arg2, *(int*)arg1);
	return (0);
}

#if SYSCTL_SKMEM
int	tcp_keepinit = TCPTV_KEEP_INIT;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPINIT, keepinit,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_keepinit, offsetof(skmem_sysctl, tcp.keepinit),
	sysctl_msec_to_ticks, "I", "");

int	tcp_keepidle = TCPTV_KEEP_IDLE;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPIDLE, keepidle,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_keepidle, offsetof(skmem_sysctl, tcp.keepidle),
	sysctl_msec_to_ticks, "I", "");

int	tcp_keepintvl = TCPTV_KEEPINTVL;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPINTVL, keepintvl,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_keepintvl, offsetof(skmem_sysctl, tcp.keepintvl),
	sysctl_msec_to_ticks, "I", "");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, keepcnt,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    int, tcp_keepcnt, TCPTV_KEEPCNT, "number of times to repeat keepalive");

int	tcp_msl = TCPTV_MSL;
SYSCTL_PROC(_net_inet_tcp, OID_AUTO, msl,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_msl, offsetof(skmem_sysctl, tcp.msl),
	sysctl_msec_to_ticks, "I", "Maximum segment lifetime");
#else /* SYSCTL_SKMEM */
int     tcp_keepinit;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPINIT, keepinit,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_keepinit, 0, sysctl_msec_to_ticks, "I", "");

int     tcp_keepidle;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPIDLE, keepidle,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_keepidle, 0, sysctl_msec_to_ticks, "I", "");

int     tcp_keepintvl;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPINTVL, keepintvl,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_keepintvl, 0, sysctl_msec_to_ticks, "I", "");

int     tcp_keepcnt;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, keepcnt,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_keepcnt, 0, "number of times to repeat keepalive");

int     tcp_msl;
SYSCTL_PROC(_net_inet_tcp, OID_AUTO, msl,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_msl, 0, sysctl_msec_to_ticks, "I", "Maximum segment lifetime");
#endif /* SYSCTL_SKMEM */

/*
 * Avoid DoS via TCP Robustness in Persist Condition
 * (see http://www.ietf.org/id/draft-ananth-tcpm-persist-02.txt)
 * by allowing a system wide maximum persistence timeout value when in
 * Zero Window Probe mode.
 *
 * Expressed in milliseconds to be consistent without timeout related
 * values, the TCP socket option is in seconds.
 */
#if SYSCTL_SKMEM
u_int32_t tcp_max_persist_timeout = 0;
SYSCTL_PROC(_net_inet_tcp, OID_AUTO, max_persist_timeout,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_max_persist_timeout, offsetof(skmem_sysctl, tcp.max_persist_timeout),
	sysctl_msec_to_ticks, "I", "Maximum persistence timeout for ZWP");
#else /* SYSCTL_SKMEM */
u_int32_t tcp_max_persist_timeout = 0;
SYSCTL_PROC(_net_inet_tcp, OID_AUTO, max_persist_timeout,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_max_persist_timeout, 0, sysctl_msec_to_ticks, "I",
    "Maximum persistence timeout for ZWP");
#endif /* SYSCTL_SKMEM */

SYSCTL_SKMEM_TCP_INT(OID_AUTO, always_keepalive,
    CTLFLAG_RW | CTLFLAG_LOCKED, static int, always_keepalive, 0,
	"Assume SO_KEEPALIVE on all TCP connections");

/*
 * This parameter determines how long the timer list will stay in fast or
 * quick mode even though all connections are idle. In this state, the
 * timer will run more frequently anticipating new data.
 */
SYSCTL_SKMEM_TCP_INT(OID_AUTO, timer_fastmode_idlemax,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, timer_fastmode_idlemax,
	TCP_FASTMODE_IDLERUN_MAX, "Maximum idle generations in fast mode");

/*
 * See tcp_syn_backoff[] for interval values between SYN retransmits;
 * the value set below defines the number of retransmits, before we
 * disable the timestamp and window scaling options during subsequent
 * SYN retransmits.  Setting it to 0 disables the dropping off of those
 * two options.
 */
SYSCTL_SKMEM_TCP_INT(OID_AUTO, broken_peer_syn_rexmit_thres,
    CTLFLAG_RW | CTLFLAG_LOCKED, static int, tcp_broken_peer_syn_rxmit_thres,
	10, "Number of retransmitted SYNs before disabling RFC 1323 "
    "options on local connections");

static int tcp_timer_advanced = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, tcp_timer_advanced,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tcp_timer_advanced, 0,
    "Number of times one of the timers was advanced");

static int tcp_resched_timerlist = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, tcp_resched_timerlist,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tcp_resched_timerlist, 0,
    "Number of times timer list was rescheduled as part of processing a packet");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, pmtud_blackhole_detection,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, tcp_pmtud_black_hole_detect, 1,
    "Path MTU Discovery Black Hole Detection");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, pmtud_blackhole_mss,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, tcp_pmtud_black_hole_mss, 1200,
    "Path MTU Discovery Black Hole Detection lowered MSS");

static u_int32_t tcp_mss_rec_medium = 1200;
static u_int32_t tcp_mss_rec_low = 512;

#define	TCP_REPORT_STATS_INTERVAL	43200 /* 12 hours, in seconds */
int tcp_report_stats_interval = TCP_REPORT_STATS_INTERVAL;

/* performed garbage collection of "used" sockets */
static boolean_t tcp_gc_done = FALSE;

/* max idle probes */
int	tcp_maxpersistidle = TCPTV_KEEP_IDLE;

/*
 * TCP delack timer is set to 100 ms. Since the processing of timer list
 * in fast mode will happen no faster than 100 ms, the delayed ack timer
 * will fire some where between 100 and 200 ms.
 */
int	tcp_delack = TCP_RETRANSHZ / 10;

#if MPTCP
/*
 * MP_JOIN retransmission of 3rd ACK will be every 500 msecs without backoff
 */
int	tcp_jack_rxmt = TCP_RETRANSHZ / 2;
#endif /* MPTCP */

static boolean_t tcp_itimer_done = FALSE;

static void tcp_remove_timer(struct tcpcb *tp);
static void tcp_sched_timerlist(uint32_t offset);
static u_int32_t tcp_run_conn_timer(struct tcpcb *tp, u_int16_t *mode,
    u_int16_t probe_if_index);
static void tcp_sched_timers(struct tcpcb *tp);
static inline void tcp_set_lotimer_index(struct tcpcb *);
__private_extern__ void tcp_remove_from_time_wait(struct inpcb *inp);
static inline void tcp_update_mss_core(struct tcpcb *tp, struct ifnet *ifp);
__private_extern__ void tcp_report_stats(void);

static	u_int64_t tcp_last_report_time;

/*
 * Structure to store previously reported stats so that we can send
 * incremental changes in each report interval.
 */
struct tcp_last_report_stats {
	u_int32_t	tcps_connattempt;
	u_int32_t	tcps_accepts;
	u_int32_t	tcps_ecn_client_setup;
	u_int32_t	tcps_ecn_server_setup;
	u_int32_t	tcps_ecn_client_success;
	u_int32_t	tcps_ecn_server_success;
	u_int32_t	tcps_ecn_not_supported;
	u_int32_t	tcps_ecn_lost_syn;
	u_int32_t	tcps_ecn_lost_synack;
	u_int32_t	tcps_ecn_recv_ce;
	u_int32_t	tcps_ecn_recv_ece;
	u_int32_t	tcps_ecn_sent_ece;
	u_int32_t	tcps_ecn_conn_recv_ce;
	u_int32_t	tcps_ecn_conn_recv_ece;
	u_int32_t	tcps_ecn_conn_plnoce;
	u_int32_t	tcps_ecn_conn_pl_ce;
	u_int32_t	tcps_ecn_conn_nopl_ce;
	u_int32_t	tcps_ecn_fallback_synloss;
	u_int32_t	tcps_ecn_fallback_reorder;
	u_int32_t	tcps_ecn_fallback_ce;

	/* TFO-related statistics */
	u_int32_t	tcps_tfo_syn_data_rcv;
	u_int32_t	tcps_tfo_cookie_req_rcv;
	u_int32_t	tcps_tfo_cookie_sent;
	u_int32_t	tcps_tfo_cookie_invalid;
	u_int32_t	tcps_tfo_cookie_req;
	u_int32_t	tcps_tfo_cookie_rcv;
	u_int32_t	tcps_tfo_syn_data_sent;
	u_int32_t	tcps_tfo_syn_data_acked;
	u_int32_t	tcps_tfo_syn_loss;
	u_int32_t	tcps_tfo_blackhole;
	u_int32_t	tcps_tfo_cookie_wrong;
	u_int32_t	tcps_tfo_no_cookie_rcv;
	u_int32_t	tcps_tfo_heuristics_disable;
	u_int32_t	tcps_tfo_sndblackhole;

	/* MPTCP-related statistics */
	u_int32_t	tcps_mptcp_handover_attempt;
	u_int32_t	tcps_mptcp_interactive_attempt;
	u_int32_t	tcps_mptcp_aggregate_attempt;
	u_int32_t	tcps_mptcp_fp_handover_attempt;
	u_int32_t	tcps_mptcp_fp_interactive_attempt;
	u_int32_t	tcps_mptcp_fp_aggregate_attempt;
	u_int32_t	tcps_mptcp_heuristic_fallback;
	u_int32_t	tcps_mptcp_fp_heuristic_fallback;
	u_int32_t	tcps_mptcp_handover_success_wifi;
	u_int32_t	tcps_mptcp_handover_success_cell;
	u_int32_t	tcps_mptcp_interactive_success;
	u_int32_t	tcps_mptcp_aggregate_success;
	u_int32_t	tcps_mptcp_fp_handover_success_wifi;
	u_int32_t	tcps_mptcp_fp_handover_success_cell;
	u_int32_t	tcps_mptcp_fp_interactive_success;
	u_int32_t	tcps_mptcp_fp_aggregate_success;
	u_int32_t	tcps_mptcp_handover_cell_from_wifi;
	u_int32_t	tcps_mptcp_handover_wifi_from_cell;
	u_int32_t	tcps_mptcp_interactive_cell_from_wifi;
	u_int64_t	tcps_mptcp_handover_cell_bytes;
	u_int64_t	tcps_mptcp_interactive_cell_bytes;
	u_int64_t	tcps_mptcp_aggregate_cell_bytes;
	u_int64_t	tcps_mptcp_handover_all_bytes;
	u_int64_t	tcps_mptcp_interactive_all_bytes;
	u_int64_t	tcps_mptcp_aggregate_all_bytes;
	u_int32_t	tcps_mptcp_back_to_wifi;
	u_int32_t	tcps_mptcp_wifi_proxy;
	u_int32_t	tcps_mptcp_cell_proxy;
};


/* Returns true if the timer is on the timer list */
#define TIMER_IS_ON_LIST(tp) ((tp)->t_flags & TF_TIMER_ONLIST)

/* Run the TCP timerlist atleast once every hour */
#define TCP_TIMERLIST_MAX_OFFSET (60 * 60 * TCP_RETRANSHZ)


static void add_to_time_wait_locked(struct tcpcb *tp, uint32_t delay);
static boolean_t tcp_garbage_collect(struct inpcb *, int);

#define TIMERENTRY_TO_TP(te) ((struct tcpcb *)((uintptr_t)te - offsetof(struct tcpcb, tentry.le.le_next)))

#define VERIFY_NEXT_LINK(elm,field) do {	\
	if (LIST_NEXT((elm),field) != NULL && 	\
	    LIST_NEXT((elm),field)->field.le_prev !=	\
		&((elm)->field.le_next))	\
		panic("Bad link elm %p next->prev != elm", (elm));	\
} while(0)

#define VERIFY_PREV_LINK(elm,field) do {	\
	if (*(elm)->field.le_prev != (elm))	\
		panic("Bad link elm %p prev->next != elm", (elm));	\
} while(0)

#define TCP_SET_TIMER_MODE(mode, i) do { \
	if (IS_TIMER_HZ_10MS(i)) \
		(mode) |= TCP_TIMERLIST_10MS_MODE; \
	else if (IS_TIMER_HZ_100MS(i)) \
		(mode) |= TCP_TIMERLIST_100MS_MODE; \
	else \
		(mode) |= TCP_TIMERLIST_500MS_MODE; \
} while(0)

#if (DEVELOPMENT || DEBUG)
SYSCTL_UINT(_net_inet_tcp, OID_AUTO, mss_rec_medium,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_mss_rec_medium, 0,
    "Medium MSS based on recommendation in link status report");
SYSCTL_UINT(_net_inet_tcp, OID_AUTO, mss_rec_low,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_mss_rec_low, 0,
    "Low MSS based on recommendation in link status report");

static int32_t tcp_change_mss_recommended = 0;
static int
sysctl_change_mss_recommended SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int i, err = 0, changed = 0;
	struct ifnet *ifp;
	struct if_link_status ifsr;
	struct if_cellular_status_v1 *new_cell_sr;
	err = sysctl_io_number(req, tcp_change_mss_recommended,
	    sizeof (int32_t), &i, &changed);
	if (changed) {
		ifnet_head_lock_shared();
		TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
			if (IFNET_IS_CELLULAR(ifp)) {
				bzero(&ifsr, sizeof (ifsr));
				new_cell_sr = &ifsr.ifsr_u.ifsr_cell.if_cell_u.if_status_v1;
				ifsr.ifsr_version = IF_CELLULAR_STATUS_REPORT_CURRENT_VERSION;
				ifsr.ifsr_len = sizeof(*new_cell_sr);

				/* Set MSS recommended */
				new_cell_sr->valid_bitmask |= IF_CELL_UL_MSS_RECOMMENDED_VALID;
				new_cell_sr->mss_recommended = i;
				err = ifnet_link_status_report(ifp, new_cell_sr, sizeof (new_cell_sr));
				if (err == 0) {
					tcp_change_mss_recommended = i;
				} else {
					break;
				}
			}
		}
		ifnet_head_done();
	}
	return (err);
}

SYSCTL_PROC(_net_inet_tcp, OID_AUTO, change_mss_recommended,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_change_mss_recommended,
    0, sysctl_change_mss_recommended, "IU", "Change MSS recommended");

SYSCTL_INT(_net_inet_tcp, OID_AUTO, report_stats_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_report_stats_interval, 0,
    "Report stats interval");
#endif /* (DEVELOPMENT || DEBUG) */

/*
 * Macro to compare two timers. If there is a reset of the sign bit,
 * it is safe to assume that the timer has wrapped around. By doing
 * signed comparision, we take care of wrap around such that the value
 * with the sign bit reset is actually ahead of the other.
 */
inline int32_t
timer_diff(uint32_t t1, uint32_t toff1, uint32_t t2, uint32_t toff2) {
	return (int32_t)((t1 + toff1) - (t2 + toff2));
};

/*
 * Add to tcp timewait list, delay is given in milliseconds.
 */
static void
add_to_time_wait_locked(struct tcpcb *tp, uint32_t delay)
{
	struct inpcbinfo *pcbinfo = &tcbinfo;
	struct inpcb *inp = tp->t_inpcb;
	uint32_t timer;

	/* pcb list should be locked when we get here */
	LCK_RW_ASSERT(pcbinfo->ipi_lock, LCK_RW_ASSERT_EXCLUSIVE);

	/* We may get here multiple times, so check */
	if (!(inp->inp_flags2 & INP2_TIMEWAIT)) {
		pcbinfo->ipi_twcount++;
		inp->inp_flags2 |= INP2_TIMEWAIT;

		/* Remove from global inp list */
		LIST_REMOVE(inp, inp_list);
	} else {
		TAILQ_REMOVE(&tcp_tw_tailq, tp, t_twentry);
	}

	/* Compute the time at which this socket can be closed */
	timer = tcp_now + delay;

	/* We will use the TCPT_2MSL timer for tracking this delay */

	if (TIMER_IS_ON_LIST(tp))
		tcp_remove_timer(tp);
	tp->t_timer[TCPT_2MSL] = timer;

	TAILQ_INSERT_TAIL(&tcp_tw_tailq, tp, t_twentry);
}

void
add_to_time_wait(struct tcpcb *tp, uint32_t delay)
{
	struct inpcbinfo *pcbinfo = &tcbinfo;
	if (tp->t_inpcb->inp_socket->so_options & SO_NOWAKEFROMSLEEP)
		socket_post_kev_msg_closed(tp->t_inpcb->inp_socket);

	/* 19182803: Notify nstat that connection is closing before waiting. */
	nstat_pcb_detach(tp->t_inpcb);

	if (!lck_rw_try_lock_exclusive(pcbinfo->ipi_lock)) {
		socket_unlock(tp->t_inpcb->inp_socket, 0);
		lck_rw_lock_exclusive(pcbinfo->ipi_lock);
		socket_lock(tp->t_inpcb->inp_socket, 0);
	}
	add_to_time_wait_locked(tp, delay);
	lck_rw_done(pcbinfo->ipi_lock);

	inpcb_gc_sched(pcbinfo, INPCB_TIMER_LAZY);
}

/* If this is on time wait queue, remove it. */
void
tcp_remove_from_time_wait(struct inpcb *inp)
{
	struct tcpcb *tp = intotcpcb(inp);
	if (inp->inp_flags2 & INP2_TIMEWAIT)
		TAILQ_REMOVE(&tcp_tw_tailq, tp, t_twentry);
}

static boolean_t
tcp_garbage_collect(struct inpcb *inp, int istimewait)
{
	boolean_t active = FALSE;
	struct socket *so, *mp_so = NULL;
	struct tcpcb *tp;

	so = inp->inp_socket;
	tp = intotcpcb(inp);

	if (so->so_flags & SOF_MP_SUBFLOW) {
		mp_so = mptetoso(tptomptp(tp)->mpt_mpte);
		if (!socket_try_lock(mp_so)) {
			mp_so = NULL;
			active = TRUE;
			goto out;
		}
		mp_so->so_usecount++;
	}

	/*
	 * Skip if still in use or busy; it would have been more efficient
	 * if we were to test so_usecount against 0, but this isn't possible
	 * due to the current implementation of tcp_dropdropablreq() where
	 * overflow sockets that are eligible for garbage collection have
	 * their usecounts set to 1.
	 */
	if (!lck_mtx_try_lock_spin(&inp->inpcb_mtx)) {
		active = TRUE;
		goto out;
	}

	/* Check again under the lock */
	if (so->so_usecount > 1) {
		if (inp->inp_wantcnt == WNT_STOPUSING)
			active = TRUE;
		lck_mtx_unlock(&inp->inpcb_mtx);
		goto out;
	}

	if (istimewait && TSTMP_GEQ(tcp_now, tp->t_timer[TCPT_2MSL]) &&
	    tp->t_state != TCPS_CLOSED) {
		/* Become a regular mutex */
		lck_mtx_convert_spin(&inp->inpcb_mtx);
		tcp_close(tp);
	}

	/*
	 * Overflowed socket dropped from the listening queue?  Do this
	 * only if we are called to clean up the time wait slots, since
	 * tcp_dropdropablreq() considers a socket to have been fully
	 * dropped after add_to_time_wait() is finished.
	 * Also handle the case of connections getting closed by the peer
	 * while in the queue as seen with rdar://6422317
	 *
	 */
	if (so->so_usecount == 1 &&
	    ((istimewait && (so->so_flags & SOF_OVERFLOW)) ||
	    ((tp != NULL) && (tp->t_state == TCPS_CLOSED) &&
	    (so->so_head != NULL) &&
	    ((so->so_state & (SS_INCOMP|SS_CANTSENDMORE|SS_CANTRCVMORE)) ==
	    (SS_INCOMP|SS_CANTSENDMORE|SS_CANTRCVMORE))))) {

		if (inp->inp_state != INPCB_STATE_DEAD) {
			/* Become a regular mutex */
			lck_mtx_convert_spin(&inp->inpcb_mtx);
#if INET6
			if (SOCK_CHECK_DOM(so, PF_INET6))
				in6_pcbdetach(inp);
			else
#endif /* INET6 */
				in_pcbdetach(inp);
		}
		VERIFY(so->so_usecount > 0);
		so->so_usecount--;
		if (inp->inp_wantcnt == WNT_STOPUSING)
			active = TRUE;
		lck_mtx_unlock(&inp->inpcb_mtx);
		goto out;
	} else if (inp->inp_wantcnt != WNT_STOPUSING) {
		lck_mtx_unlock(&inp->inpcb_mtx);
		active = FALSE;
		goto out;
	}

	/*
	 * We get here because the PCB is no longer searchable
	 * (WNT_STOPUSING); detach (if needed) and dispose if it is dead
	 * (usecount is 0).  This covers all cases, including overflow
	 * sockets and those that are considered as "embryonic",
	 * i.e. created by sonewconn() in TCP input path, and have
	 * not yet been committed.  For the former, we reduce the usecount
	 *  to 0 as done by the code above.  For the latter, the usecount
	 * would have reduced to 0 as part calling soabort() when the
	 * socket is dropped at the end of tcp_input().
	 */
	if (so->so_usecount == 0) {
		DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
			struct tcpcb *, tp, int32_t, TCPS_CLOSED);
		/* Become a regular mutex */
		lck_mtx_convert_spin(&inp->inpcb_mtx);

		/*
		 * If this tp still happens to be on the timer list,
		 * take it out
		 */
		if (TIMER_IS_ON_LIST(tp)) {
			tcp_remove_timer(tp);
		}

		if (inp->inp_state != INPCB_STATE_DEAD) {
#if INET6
			if (SOCK_CHECK_DOM(so, PF_INET6))
				in6_pcbdetach(inp);
			else
#endif /* INET6 */
				in_pcbdetach(inp);
		}

		if (mp_so) {
			mptcp_subflow_del(tptomptp(tp)->mpt_mpte, tp->t_mpsub);

			/* so is now unlinked from mp_so - let's drop the lock */
			socket_unlock(mp_so, 1);
			mp_so = NULL;
		}

		in_pcbdispose(inp);
		active = FALSE;
		goto out;
	}

	lck_mtx_unlock(&inp->inpcb_mtx);
	active = TRUE;

out:
	if (mp_so)
		socket_unlock(mp_so, 1);

	return (active);
}

/*
 * TCP garbage collector callback (inpcb_timer_func_t).
 *
 * Returns the number of pcbs that will need to be gc-ed soon,
 * returnining > 0 will keep timer active.
 */
void
tcp_gc(struct inpcbinfo *ipi)
{
	struct inpcb *inp, *nxt;
	struct tcpcb *tw_tp, *tw_ntp;
#if TCPDEBUG
	int ostate;
#endif
#if  KDEBUG
	static int tws_checked = 0;
#endif

	KERNEL_DEBUG(DBG_FNC_TCP_SLOW | DBG_FUNC_START, 0, 0, 0, 0, 0);

	/*
	 * Update tcp_now here as it may get used while
	 * processing the slow timer.
	 */
	calculate_tcp_clock();

	/*
	 * Garbage collect socket/tcpcb: We need to acquire the list lock
	 * exclusively to do this
	 */

	if (lck_rw_try_lock_exclusive(ipi->ipi_lock) == FALSE) {
		/* don't sweat it this time; cleanup was done last time */
		if (tcp_gc_done == TRUE) {
			tcp_gc_done = FALSE;
			KERNEL_DEBUG(DBG_FNC_TCP_SLOW | DBG_FUNC_END,
			    tws_checked, cur_tw_slot, 0, 0, 0);
			/* Lock upgrade failed, give up this round */
			atomic_add_32(&ipi->ipi_gc_req.intimer_fast, 1);
			return;
		}
		/* Upgrade failed, lost lock now take it again exclusive */
		lck_rw_lock_exclusive(ipi->ipi_lock);
	}
	tcp_gc_done = TRUE;

	LIST_FOREACH_SAFE(inp, &tcb, inp_list, nxt) {
		if (tcp_garbage_collect(inp, 0))
			atomic_add_32(&ipi->ipi_gc_req.intimer_fast, 1);
	}

	/* Now cleanup the time wait ones */
	TAILQ_FOREACH_SAFE(tw_tp, &tcp_tw_tailq, t_twentry, tw_ntp) {
		/*
		 * We check the timestamp here without holding the
		 * socket lock for better performance. If there are
		 * any pcbs in time-wait, the timer will get rescheduled.
		 * Hence some error in this check can be tolerated.
		 *
		 * Sometimes a socket on time-wait queue can be closed if
		 * 2MSL timer expired but the application still has a
		 * usecount on it.
		 */
		if (tw_tp->t_state == TCPS_CLOSED ||
		    TSTMP_GEQ(tcp_now, tw_tp->t_timer[TCPT_2MSL])) {
			if (tcp_garbage_collect(tw_tp->t_inpcb, 1))
				atomic_add_32(&ipi->ipi_gc_req.intimer_lazy, 1);
		}
	}

	/* take into account pcbs that are still in time_wait_slots */
	atomic_add_32(&ipi->ipi_gc_req.intimer_lazy, ipi->ipi_twcount);

	lck_rw_done(ipi->ipi_lock);

	/* Clean up the socache while we are here */
	if (so_cache_timer())
		atomic_add_32(&ipi->ipi_gc_req.intimer_lazy, 1);

	KERNEL_DEBUG(DBG_FNC_TCP_SLOW | DBG_FUNC_END, tws_checked,
	    cur_tw_slot, 0, 0, 0);

	return;
}

/*
 * Cancel all timers for TCP tp.
 */
void
tcp_canceltimers(struct tcpcb *tp)
{
	int i;

	tcp_remove_timer(tp);
	for (i = 0; i < TCPT_NTIMERS; i++)
		tp->t_timer[i] = 0;
	tp->tentry.timer_start = tcp_now;
	tp->tentry.index = TCPT_NONE;
}

int	tcp_syn_backoff[TCP_MAXRXTSHIFT + 1] =
    { 1, 1, 1, 1, 1, 2, 4, 8, 16, 32, 64, 64, 64 };

int	tcp_backoff[TCP_MAXRXTSHIFT + 1] =
    { 1, 2, 4, 8, 16, 32, 64, 64, 64, 64, 64, 64, 64 };

static int tcp_totbackoff = 511;	/* sum of tcp_backoff[] */

void
tcp_rexmt_save_state(struct tcpcb *tp)
{
	u_int32_t fsize;
	if (TSTMP_SUPPORTED(tp)) {
		/*
		 * Since timestamps are supported on the connection,
		 * we can do recovery as described in rfc 4015.
		 */
		fsize = tp->snd_max - tp->snd_una;
		tp->snd_ssthresh_prev = max(fsize, tp->snd_ssthresh);
		tp->snd_recover_prev = tp->snd_recover;
	} else {
		/*
		 * Timestamp option is not supported on this connection.
		 * Record ssthresh and cwnd so they can
		 * be recovered if this turns out to be a "bad" retransmit.
		 * A retransmit is considered "bad" if an ACK for this
		 * segment is received within RTT/2 interval; the assumption
		 * here is that the ACK was already in flight.  See
		 * "On Estimating End-to-End Network Path Properties" by
		 * Allman and Paxson for more details.
		 */
		tp->snd_cwnd_prev = tp->snd_cwnd;
		tp->snd_ssthresh_prev = tp->snd_ssthresh;
		tp->snd_recover_prev = tp->snd_recover;
		if (IN_FASTRECOVERY(tp))
			tp->t_flags |= TF_WASFRECOVERY;
		else
			tp->t_flags &= ~TF_WASFRECOVERY;
	}
	tp->t_srtt_prev = (tp->t_srtt >> TCP_RTT_SHIFT) + 2;
	tp->t_rttvar_prev = (tp->t_rttvar >> TCP_RTTVAR_SHIFT);
	tp->t_flagsext &= ~(TF_RECOMPUTE_RTT);
}

/*
 * Revert to the older segment size if there is an indication that PMTU
 * blackhole detection was not needed.
 */
void
tcp_pmtud_revert_segment_size(struct tcpcb *tp)
{
	int32_t optlen;

	VERIFY(tp->t_pmtud_saved_maxopd > 0);
	tp->t_flags |= TF_PMTUD;
	tp->t_flags &= ~TF_BLACKHOLE;
	optlen = tp->t_maxopd - tp->t_maxseg;
	tp->t_maxopd = tp->t_pmtud_saved_maxopd;
	tp->t_maxseg = tp->t_maxopd - optlen;
	/*
	 * Reset the slow-start flight size as it
	 * may depend on the new MSS
	 */
	if (CC_ALGO(tp)->cwnd_init != NULL)
		CC_ALGO(tp)->cwnd_init(tp);
	tp->t_pmtud_start_ts = 0;
	tcpstat.tcps_pmtudbh_reverted++;

	/* change MSS according to recommendation, if there was one */
	tcp_update_mss_locked(tp->t_inpcb->inp_socket, NULL);
}

/*
 * TCP timer processing.
 */
struct tcpcb *
tcp_timers(struct tcpcb *tp, int timer)
{
	int32_t rexmt, optlen = 0, idle_time = 0;
	struct socket *so;
	struct tcptemp *t_template;
#if TCPDEBUG
	int ostate;
#endif

#if INET6
	int isipv6 = (tp->t_inpcb->inp_vflag & INP_IPV4) == 0;
#endif /* INET6 */
	u_int64_t accsleep_ms;
	u_int32_t last_sleep_ms = 0;

	so = tp->t_inpcb->inp_socket;
	idle_time = tcp_now - tp->t_rcvtime;

	switch (timer) {

	/*
	 * 2 MSL timeout in shutdown went off.  If we're closed but
	 * still waiting for peer to close and connection has been idle
	 * too long, or if 2MSL time is up from TIME_WAIT or FIN_WAIT_2,
	 * delete connection control block.
	 * Otherwise, (this case shouldn't happen) check again in a bit
	 * we keep the socket in the main list in that case.
	 */
	case TCPT_2MSL:
		tcp_free_sackholes(tp);
		if (tp->t_state != TCPS_TIME_WAIT &&
		    tp->t_state != TCPS_FIN_WAIT_2 &&
		    ((idle_time > 0) && (idle_time < TCP_CONN_MAXIDLE(tp)))) {
			tp->t_timer[TCPT_2MSL] = OFFSET_FROM_START(tp,
				(u_int32_t)TCP_CONN_KEEPINTVL(tp));
		} else {
			tp = tcp_close(tp);
			return(tp);
		}
		break;

	/*
	 * Retransmission timer went off.  Message has not
	 * been acked within retransmit interval.  Back off
	 * to a longer retransmit interval and retransmit one segment.
	 */
	case TCPT_REXMT:
		absolutetime_to_nanoseconds(mach_absolutetime_asleep,
		    &accsleep_ms);
		accsleep_ms = accsleep_ms / 1000000UL;
		if (accsleep_ms > tp->t_accsleep_ms)
			last_sleep_ms = accsleep_ms - tp->t_accsleep_ms;
		/*
		 * Drop a connection in the retransmit timer
		 * 1. If we have retransmitted more than TCP_MAXRXTSHIFT
		 * times
		 * 2. If the time spent in this retransmission episode is
		 * more than the time limit set with TCP_RXT_CONNDROPTIME
		 * socket option
		 * 3. If TCP_RXT_FINDROP socket option was set and
		 * we have already retransmitted the FIN 3 times without
		 * receiving an ack
		 */
		if (++tp->t_rxtshift > TCP_MAXRXTSHIFT ||
		    (tp->t_rxt_conndroptime > 0 && tp->t_rxtstart > 0 &&
		    (tcp_now - tp->t_rxtstart) >= tp->t_rxt_conndroptime) ||
		    ((tp->t_flagsext & TF_RXTFINDROP) != 0 &&
		    (tp->t_flags & TF_SENTFIN) != 0 && tp->t_rxtshift >= 4) ||
		    (tp->t_rxtshift > 4 && last_sleep_ms >= TCP_SLEEP_TOO_LONG)) {
			if (tp->t_state == TCPS_ESTABLISHED &&
			    tp->t_rxt_minimum_timeout > 0) {
				/*
				 * Avoid dropping a connection if minimum
				 * timeout is set and that time did not
				 * pass. We will retry sending
				 * retransmissions at the maximum interval
				 */
				if (TSTMP_LT(tcp_now, (tp->t_rxtstart +
				    tp->t_rxt_minimum_timeout))) {
					tp->t_rxtshift = TCP_MAXRXTSHIFT - 1;
					goto retransmit_packet;
				}
			}
			if ((tp->t_flagsext & TF_RXTFINDROP) != 0) {
				tcpstat.tcps_rxtfindrop++;
			} else if (last_sleep_ms >= TCP_SLEEP_TOO_LONG) {
				tcpstat.tcps_drop_after_sleep++;
			} else {
				tcpstat.tcps_timeoutdrop++;
			}
			if (tp->t_rxtshift >= TCP_MAXRXTSHIFT) {
				if (TCP_ECN_ENABLED(tp)) {
					INP_INC_IFNET_STAT(tp->t_inpcb,
					    ecn_on.rxmit_drop);
				} else {
					INP_INC_IFNET_STAT(tp->t_inpcb,
					    ecn_off.rxmit_drop);
				}
			}
			tp->t_rxtshift = TCP_MAXRXTSHIFT;
			postevent(so, 0, EV_TIMEOUT);
			soevent(so,
			    (SO_FILT_HINT_LOCKED|SO_FILT_HINT_TIMEOUT));

			if (TCP_ECN_ENABLED(tp) &&
			    tp->t_state == TCPS_ESTABLISHED)
				tcp_heuristic_ecn_droprxmt(tp);

			tp = tcp_drop(tp, tp->t_softerror ?
			    tp->t_softerror : ETIMEDOUT);

			break;
		}
retransmit_packet:
		tcpstat.tcps_rexmttimeo++;
		tp->t_accsleep_ms = accsleep_ms;

		if (tp->t_rxtshift == 1 &&
			tp->t_state == TCPS_ESTABLISHED) {
			/* Set the time at which retransmission started. */
			tp->t_rxtstart = tcp_now;

			/*
			 * if this is the first retransmit timeout, save
			 * the state so that we can recover if the timeout
			 * is spurious.
			 */
			tcp_rexmt_save_state(tp);
		}
#if MPTCP
		if ((tp->t_rxtshift >= mptcp_fail_thresh) &&
		    (tp->t_state == TCPS_ESTABLISHED) &&
		    (tp->t_mpflags & TMPF_MPTCP_TRUE)) {
			mptcp_act_on_txfail(so);

		}

		if (so->so_flags & SOF_MP_SUBFLOW) {
			struct mptses *mpte = tptomptp(tp)->mpt_mpte;

			mptcp_check_subflows_and_add(mpte);
		}
#endif /* MPTCP */

		if (tp->t_adaptive_wtimo > 0 &&
			tp->t_rxtshift > tp->t_adaptive_wtimo &&
			TCPS_HAVEESTABLISHED(tp->t_state)) {
			/* Send an event to the application */
			soevent(so,
				(SO_FILT_HINT_LOCKED|
				SO_FILT_HINT_ADAPTIVE_WTIMO));
		}

		/*
		 * If this is a retransmit timeout after PTO, the PTO
		 * was not effective
		 */
		if (tp->t_flagsext & TF_SENT_TLPROBE) {
			tp->t_flagsext &= ~(TF_SENT_TLPROBE);
			tcpstat.tcps_rto_after_pto++;
		}

		if (tp->t_flagsext & TF_DELAY_RECOVERY) {
			/*
			 * Retransmit timer fired before entering recovery
			 * on a connection with packet re-ordering. This
			 * suggests that the reordering metrics computed
			 * are not accurate.
			 */
			tp->t_reorderwin = 0;
			tp->t_timer[TCPT_DELAYFR] = 0;
			tp->t_flagsext &= ~(TF_DELAY_RECOVERY);
		}

		if (tp->t_state == TCPS_SYN_RECEIVED)
			tcp_disable_tfo(tp);

		if (!(tp->t_tfo_flags & TFO_F_HEURISTIC_DONE) &&
		    (tp->t_tfo_stats & TFO_S_SYN_DATA_SENT) &&
		    !(tp->t_tfo_flags & TFO_F_NO_SNDPROBING) &&
		    ((tp->t_state != TCPS_SYN_SENT && tp->t_rxtshift > 1) ||
		     tp->t_rxtshift > 2)) {
			/*
			 * For regular retransmissions, a first one is being
			 * done for tail-loss probe.
			 * Thus, if rxtshift > 1, this means we have sent the segment
			 * a total of 3 times.
			 *
			 * If we are in SYN-SENT state, then there is no tail-loss
			 * probe thus we have to let rxtshift go up to 3.
			 */
			tcp_heuristic_tfo_middlebox(tp);

			so->so_error = ENODATA;
			sorwakeup(so);
			sowwakeup(so);

			tp->t_tfo_stats |= TFO_S_SEND_BLACKHOLE;
			tcpstat.tcps_tfo_sndblackhole++;
		}

		if (!(tp->t_tfo_flags & TFO_F_HEURISTIC_DONE) &&
		    (tp->t_tfo_stats & TFO_S_SYN_DATA_ACKED) &&
		    tp->t_rxtshift > 1) {
			if (TSTMP_GT(tp->t_sndtime - 10 * TCP_RETRANSHZ, tp->t_rcvtime)) {
				tcp_heuristic_tfo_middlebox(tp);

				so->so_error = ENODATA;
				sorwakeup(so);
				sowwakeup(so);
			}
		}

		if (tp->t_state == TCPS_SYN_SENT) {
			rexmt = TCP_REXMTVAL(tp) * tcp_syn_backoff[tp->t_rxtshift];
			tp->t_stat.synrxtshift = tp->t_rxtshift;

			/* When retransmitting, disable TFO */
			if (tfo_enabled(tp) &&
			    (!(so->so_flags1 & SOF1_DATA_AUTHENTICATED) ||
			     (tp->t_flagsext & TF_FASTOPEN_HEUR))) {
				tp->t_flagsext &= ~TF_FASTOPEN;
				tp->t_tfo_flags |= TFO_F_SYN_LOSS;
			}
		} else {
			rexmt = TCP_REXMTVAL(tp) * tcp_backoff[tp->t_rxtshift];
		}

		TCPT_RANGESET(tp->t_rxtcur, rexmt, tp->t_rttmin, TCPTV_REXMTMAX,
			TCP_ADD_REXMTSLOP(tp));
		tp->t_timer[TCPT_REXMT] = OFFSET_FROM_START(tp, tp->t_rxtcur);

		if (INP_WAIT_FOR_IF_FEEDBACK(tp->t_inpcb))
			goto fc_output;

		tcp_free_sackholes(tp);
		/*
		 * Check for potential Path MTU Discovery Black Hole
		 */
		if (tcp_pmtud_black_hole_detect &&
			!(tp->t_flagsext & TF_NOBLACKHOLE_DETECTION) &&
			(tp->t_state == TCPS_ESTABLISHED)) {
			if ((tp->t_flags & TF_PMTUD) &&
			    ((tp->t_flags & TF_MAXSEGSNT)
			    || tp->t_pmtud_lastseg_size > tcp_pmtud_black_hole_mss) &&
			    tp->t_rxtshift == 2) {
				/*
				 * Enter Path MTU Black-hole Detection mechanism:
				 * - Disable Path MTU Discovery (IP "DF" bit).
				 * - Reduce MTU to lower value than what we
				 * negotiated with the peer.
				 */
				/* Disable Path MTU Discovery for now */
				tp->t_flags &= ~TF_PMTUD;
				/* Record that we may have found a black hole */
				tp->t_flags |= TF_BLACKHOLE;
				optlen = tp->t_maxopd - tp->t_maxseg;
				/* Keep track of previous MSS */
				tp->t_pmtud_saved_maxopd = tp->t_maxopd;
				tp->t_pmtud_start_ts = tcp_now;
				if (tp->t_pmtud_start_ts == 0)
					tp->t_pmtud_start_ts++;
				/* Reduce the MSS to intermediary value */
				if (tp->t_maxopd > tcp_pmtud_black_hole_mss) {
					tp->t_maxopd = tcp_pmtud_black_hole_mss;
				} else {
					tp->t_maxopd = 	/* use the default MSS */
#if INET6
						isipv6 ? tcp_v6mssdflt :
#endif /* INET6 */
							tcp_mssdflt;
				}
				tp->t_maxseg = tp->t_maxopd - optlen;

				/*
	 			 * Reset the slow-start flight size
				 * as it may depend on the new MSS
	 			 */
				if (CC_ALGO(tp)->cwnd_init != NULL)
					CC_ALGO(tp)->cwnd_init(tp);
				tp->snd_cwnd = tp->t_maxseg;
			}
			/*
			 * If further retransmissions are still
			 * unsuccessful with a lowered MTU, maybe this
			 * isn't a Black Hole and we restore the previous
			 * MSS and blackhole detection flags.
			 */
			else {

				if ((tp->t_flags & TF_BLACKHOLE) &&
				    (tp->t_rxtshift > 4)) {
					tcp_pmtud_revert_segment_size(tp);
					tp->snd_cwnd = tp->t_maxseg;
				}
			}
		}


		/*
		 * Disable rfc1323 and rfc1644 if we haven't got any
		 * response to our SYN (after we reach the threshold)
		 * to work-around some broken terminal servers (most of
		 * which have hopefully been retired) that have bad VJ
		 * header compression code which trashes TCP segments
		 * containing unknown-to-them TCP options.
		 * Do this only on non-local connections.
		 */
		if (tp->t_state == TCPS_SYN_SENT &&
		    tp->t_rxtshift == tcp_broken_peer_syn_rxmit_thres)
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

		/* If timing a segment in this window, stop the timer */
		tp->t_rtttime = 0;

		if (!IN_FASTRECOVERY(tp) && tp->t_rxtshift == 1)
			tcpstat.tcps_tailloss_rto++;


		/*
		 * RFC 5681 says: when a TCP sender detects segment loss
		 * using retransmit timer and the given segment has already
		 * been retransmitted by way of the retransmission timer at
		 * least once, the value of ssthresh is held constant
		 */
		if (tp->t_rxtshift == 1 &&
		    CC_ALGO(tp)->after_timeout != NULL) {
			CC_ALGO(tp)->after_timeout(tp);
			/*
			 * CWR notifications are to be sent on new data
			 * right after Fast Retransmits and ECE
			 * notification receipts.
			 */
			if (TCP_ECN_ENABLED(tp))
				tp->ecn_flags |= TE_SENDCWR;
		}

		EXIT_FASTRECOVERY(tp);

		/* Exit cwnd non validated phase */
		tp->t_flagsext &= ~TF_CWND_NONVALIDATED;


fc_output:
		tcp_ccdbg_trace(tp, NULL, TCP_CC_REXMT_TIMEOUT);

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
		 *
		 * Drop the connection if we reached the maximum allowed time for
		 * Zero Window Probes without a non-zero update from the peer.
		 * See rdar://5805356
		 */
		if ((tp->t_rxtshift == TCP_MAXRXTSHIFT &&
		    (idle_time >= tcp_maxpersistidle ||
		    idle_time >= TCP_REXMTVAL(tp) * tcp_totbackoff)) ||
		    ((tp->t_persist_stop != 0) &&
			TSTMP_LEQ(tp->t_persist_stop, tcp_now))) {
			tcpstat.tcps_persistdrop++;
			postevent(so, 0, EV_TIMEOUT);
			soevent(so,
			    (SO_FILT_HINT_LOCKED|SO_FILT_HINT_TIMEOUT));
			tp = tcp_drop(tp, ETIMEDOUT);
			break;
		}
		tcp_setpersist(tp);
		tp->t_flagsext |= TF_FORCE;
		(void) tcp_output(tp);
		tp->t_flagsext &= ~TF_FORCE;
		break;

	/*
	 * Keep-alive timer went off; send something
	 * or drop connection if idle for too long.
	 */
	case TCPT_KEEP:
		tcpstat.tcps_keeptimeo++;
#if MPTCP
		/*
		 * Regular TCP connections do not send keepalives after closing
		 * MPTCP must not also, after sending Data FINs.
		 */
		struct mptcb *mp_tp = tptomptp(tp);
		if ((tp->t_mpflags & TMPF_MPTCP_TRUE) &&
		    (tp->t_state > TCPS_ESTABLISHED)) {
			goto dropit;
		} else if (mp_tp != NULL) {
			if ((mptcp_ok_to_keepalive(mp_tp) == 0))
				goto dropit;
		}
#endif /* MPTCP */
		if (tp->t_state < TCPS_ESTABLISHED)
			goto dropit;
		if ((always_keepalive ||
		    (tp->t_inpcb->inp_socket->so_options & SO_KEEPALIVE) ||
		    (tp->t_flagsext & TF_DETECT_READSTALL) ||
		    (tp->t_tfo_probe_state == TFO_PROBE_PROBING)) &&
		    (tp->t_state <= TCPS_CLOSING || tp->t_state == TCPS_FIN_WAIT_2)) {
		    	if (idle_time >= TCP_CONN_KEEPIDLE(tp) + TCP_CONN_MAXIDLE(tp))
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
				struct inpcb *inp = tp->t_inpcb;
				struct tcp_respond_args tra;

				bzero(&tra, sizeof(tra));
				tra.nocell = INP_NO_CELLULAR(inp);
				tra.noexpensive = INP_NO_EXPENSIVE(inp);
				tra.awdl_unrestricted = INP_AWDL_UNRESTRICTED(inp);
				tra.intcoproc_allowed = INP_INTCOPROC_ALLOWED(inp);
				if (tp->t_inpcb->inp_flags & INP_BOUND_IF)
					tra.ifscope = tp->t_inpcb->inp_boundifp->if_index;
				else
					tra.ifscope = IFSCOPE_NONE;
				tcp_respond(tp, t_template->tt_ipgen,
				    &t_template->tt_t, (struct mbuf *)NULL,
				    tp->rcv_nxt, tp->snd_una - 1, 0, &tra);
				(void) m_free(dtom(t_template));
				if (tp->t_flagsext & TF_DETECT_READSTALL)
					tp->t_rtimo_probes++;
			}
			tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(tp,
			    TCP_CONN_KEEPINTVL(tp));
		} else {
			tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(tp,
			    TCP_CONN_KEEPIDLE(tp));
		}
		if (tp->t_flagsext & TF_DETECT_READSTALL) {
			struct ifnet *outifp = tp->t_inpcb->inp_last_outifp;
			bool reenable_probe = false;
			/*
			 * The keep alive packets sent to detect a read
			 * stall did not get a response from the
			 * peer. Generate more keep-alives to confirm this.
			 * If the number of probes sent reaches the limit,
			 * generate an event.
			 */
			if (tp->t_adaptive_rtimo > 0) {
				if (tp->t_rtimo_probes > tp->t_adaptive_rtimo) {
					/* Generate an event */
					soevent(so,
					    (SO_FILT_HINT_LOCKED |
					    SO_FILT_HINT_ADAPTIVE_RTIMO));
					tcp_keepalive_reset(tp);
				} else {
					reenable_probe = true;
				}
			} else if (outifp != NULL &&
			    (outifp->if_eflags & IFEF_PROBE_CONNECTIVITY) &&
			    tp->t_rtimo_probes <= TCP_CONNECTIVITY_PROBES_MAX) {
				reenable_probe = true;
			} else {
				tp->t_flagsext &= ~TF_DETECT_READSTALL;
			}
			if (reenable_probe) {
				int ind = min(tp->t_rtimo_probes,
				    TCP_MAXRXTSHIFT);
				tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(
				    tp, tcp_backoff[ind] * TCP_REXMTVAL(tp));
			}
		}
		if (tp->t_tfo_probe_state == TFO_PROBE_PROBING) {
			int ind;

			tp->t_tfo_probes++;
			ind = min(tp->t_tfo_probes, TCP_MAXRXTSHIFT);

			/*
			 * We take the minimum among the time set by true
			 * keepalive (see above) and the backoff'd RTO. That
			 * way we backoff in case of packet-loss but will never
			 * timeout slower than regular keepalive due to the
			 * backing off.
			 */
			tp->t_timer[TCPT_KEEP] = min(OFFSET_FROM_START(
			    tp, tcp_backoff[ind] * TCP_REXMTVAL(tp)),
			    tp->t_timer[TCPT_KEEP]);
		} else if (!(tp->t_tfo_flags & TFO_F_HEURISTIC_DONE) &&
			   tp->t_tfo_probe_state == TFO_PROBE_WAIT_DATA) {
			/* Still no data! Let's assume a TFO-error and err out... */
			tcp_heuristic_tfo_middlebox(tp);

			so->so_error = ENODATA;
			sorwakeup(so);
			tp->t_tfo_stats |= TFO_S_RECV_BLACKHOLE;
			tcpstat.tcps_tfo_blackhole++;
		}
		break;
	case TCPT_DELACK:
		if (tcp_delack_enabled && (tp->t_flags & TF_DELACK)) {
			tp->t_flags &= ~TF_DELACK;
			tp->t_timer[TCPT_DELACK] = 0;
			tp->t_flags |= TF_ACKNOW;

			/*
			 * If delayed ack timer fired while stretching
			 * acks, count the number of times the streaming
			 * detection was not correct. If this exceeds a
			 * threshold, disable strech ack on this
			 * connection
			 *
			 * Also, go back to acking every other packet.
			 */
			if ((tp->t_flags & TF_STRETCHACK)) {
				if (tp->t_unacksegs > 1 &&
				    tp->t_unacksegs < maxseg_unacked)
					tp->t_stretchack_delayed++;

				if (tp->t_stretchack_delayed >
					TCP_STRETCHACK_DELAY_THRESHOLD) {
					tp->t_flagsext |= TF_DISABLE_STRETCHACK;
					/*
					 * Note the time at which stretch
					 * ack was disabled automatically
					 */
					tp->rcv_nostrack_ts = tcp_now;
					tcpstat.tcps_nostretchack++;
					tp->t_stretchack_delayed = 0;
					tp->rcv_nostrack_pkts = 0;
				}
				tcp_reset_stretch_ack(tp);
			}

			/*
			 * If we are measuring inter packet arrival jitter
			 * for throttling a connection, this delayed ack
			 * might be the reason for accumulating some
			 * jitter. So let's restart the measurement.
			 */
			CLEAR_IAJ_STATE(tp);

			tcpstat.tcps_delack++;
			(void) tcp_output(tp);
		}
		break;

#if MPTCP
	case TCPT_JACK_RXMT:
		if ((tp->t_state == TCPS_ESTABLISHED) &&
		    (tp->t_mpflags & TMPF_PREESTABLISHED) &&
		    (tp->t_mpflags & TMPF_JOINED_FLOW)) {
			if (++tp->t_mprxtshift > TCP_MAXRXTSHIFT) {
				tcpstat.tcps_timeoutdrop++;
				postevent(so, 0, EV_TIMEOUT);
				soevent(so,
				    (SO_FILT_HINT_LOCKED|
				    SO_FILT_HINT_TIMEOUT));
				tp = tcp_drop(tp, tp->t_softerror ?
				    tp->t_softerror : ETIMEDOUT);
				break;
			}
			tcpstat.tcps_join_rxmts++;
			tp->t_mpflags |= TMPF_SND_JACK;
			tp->t_flags |= TF_ACKNOW;

			/*
			 * No backoff is implemented for simplicity for this
			 * corner case.
			 */
			(void) tcp_output(tp);
		}
		break;
#endif /* MPTCP */

	case TCPT_PTO:
	{
		int32_t snd_len;
		tp->t_flagsext &= ~(TF_SENT_TLPROBE);

		/*
		 * Check if the connection is in the right state to
		 * send a probe
		 */
		if (tp->t_state != TCPS_ESTABLISHED ||
		    (tp->t_rxtshift > 0 && !(tp->t_flagsext & TF_PROBING))
		    || tp->snd_max == tp->snd_una ||
		    !SACK_ENABLED(tp) || !TAILQ_EMPTY(&tp->snd_holes) ||
		    IN_FASTRECOVERY(tp))
			break;

		/*
		 * If there is no new data to send or if the
		 * connection is limited by receive window then
		 * retransmit the last segment, otherwise send
		 * new data.
		 */
		snd_len = min(so->so_snd.sb_cc, tp->snd_wnd)
		    - (tp->snd_max - tp->snd_una);
		if (snd_len > 0) {
			tp->snd_nxt = tp->snd_max;
		} else {
			snd_len = min((tp->snd_max - tp->snd_una),
			    tp->t_maxseg);
			tp->snd_nxt = tp->snd_max - snd_len;
		}

		tcpstat.tcps_pto++;
		if (tp->t_flagsext & TF_PROBING)
			tcpstat.tcps_probe_if++;

		/* If timing a segment in this window, stop the timer */
		tp->t_rtttime = 0;
		/* Note that tail loss probe is being sent */
		tp->t_flagsext |= TF_SENT_TLPROBE;
		tp->t_tlpstart = tcp_now;

		tp->snd_cwnd += tp->t_maxseg;
		(void )tcp_output(tp);
		tp->snd_cwnd -= tp->t_maxseg;

		tp->t_tlphighrxt = tp->snd_nxt;
		break;
	}
	case TCPT_DELAYFR:
		tp->t_flagsext &= ~TF_DELAY_RECOVERY;

		/*
		 * Don't do anything if one of the following is true:
		 * - the connection is already in recovery
		 * - sequence until snd_recover has been acknowledged.
		 * - retransmit timeout has fired
		 */
		if (IN_FASTRECOVERY(tp) ||
		    SEQ_GEQ(tp->snd_una, tp->snd_recover) ||
		    tp->t_rxtshift > 0)
			break;

		VERIFY(SACK_ENABLED(tp));
		tcp_rexmt_save_state(tp);
		if (CC_ALGO(tp)->pre_fr != NULL) {
			CC_ALGO(tp)->pre_fr(tp);
			if (TCP_ECN_ENABLED(tp))
				tp->ecn_flags |= TE_SENDCWR;
		}
		ENTER_FASTRECOVERY(tp);

		tp->t_timer[TCPT_REXMT] = 0;
		tcpstat.tcps_sack_recovery_episode++;
		tp->t_sack_recovery_episode++;
		tp->sack_newdata = tp->snd_nxt;
		tp->snd_cwnd = tp->t_maxseg;
		tcp_ccdbg_trace(tp, NULL, TCP_CC_ENTER_FASTRECOVERY);
		(void) tcp_output(tp);
		break;
	dropit:
		tcpstat.tcps_keepdrops++;
		postevent(so, 0, EV_TIMEOUT);
		soevent(so,
		    (SO_FILT_HINT_LOCKED|SO_FILT_HINT_TIMEOUT));
		tp = tcp_drop(tp, ETIMEDOUT);
		break;
	}
#if TCPDEBUG
	if (tp->t_inpcb->inp_socket->so_options & SO_DEBUG)
		tcp_trace(TA_USER, ostate, tp, (void *)0, (struct tcphdr *)0,
			  PRU_SLOWTIMO);
#endif
	return (tp);
}

/* Remove a timer entry from timer list */
void
tcp_remove_timer(struct tcpcb *tp)
{
	struct tcptimerlist *listp = &tcp_timer_list;

	socket_lock_assert_owned(tp->t_inpcb->inp_socket);
	if (!(TIMER_IS_ON_LIST(tp))) {
		return;
	}
	lck_mtx_lock(listp->mtx);

	/* Check if pcb is on timer list again after acquiring the lock */
	if (!(TIMER_IS_ON_LIST(tp))) {
		lck_mtx_unlock(listp->mtx);
		return;
	}

	if (listp->next_te != NULL && listp->next_te == &tp->tentry)
		listp->next_te = LIST_NEXT(&tp->tentry, le);

	LIST_REMOVE(&tp->tentry, le);
	tp->t_flags &= ~(TF_TIMER_ONLIST);

	listp->entries--;

	tp->tentry.le.le_next = NULL;
	tp->tentry.le.le_prev = NULL;
	lck_mtx_unlock(listp->mtx);
}

/*
 * Function to check if the timerlist needs to be rescheduled to run
 * the timer entry correctly. Basically, this is to check if we can avoid
 * taking the list lock.
 */

static boolean_t
need_to_resched_timerlist(u_int32_t runtime, u_int16_t mode)
{
	struct tcptimerlist *listp = &tcp_timer_list;
	int32_t diff;

	/*
	 * If the list is being processed then the state of the list is
	 * in flux. In this case always acquire the lock and set the state
	 * correctly.
	 */
	if (listp->running)
		return (TRUE);

	if (!listp->scheduled)
		return (TRUE);

	diff = timer_diff(listp->runtime, 0, runtime, 0);
	if (diff <= 0) {
		/* The list is going to run before this timer */
		return (FALSE);
	} else {
		if (mode & TCP_TIMERLIST_10MS_MODE) {
			if (diff <= TCP_TIMER_10MS_QUANTUM)
				return (FALSE);
		} else if (mode & TCP_TIMERLIST_100MS_MODE) {
			if (diff <= TCP_TIMER_100MS_QUANTUM)
				return (FALSE);
		} else {
			if (diff <= TCP_TIMER_500MS_QUANTUM)
				return (FALSE);
		}
	}
	return (TRUE);
}

void
tcp_sched_timerlist(uint32_t offset)
{
	uint64_t deadline = 0;
	struct tcptimerlist *listp = &tcp_timer_list;

	LCK_MTX_ASSERT(listp->mtx, LCK_MTX_ASSERT_OWNED);

	offset = min(offset, TCP_TIMERLIST_MAX_OFFSET);
	listp->runtime = tcp_now + offset;
	listp->schedtime = tcp_now;
	if (listp->runtime == 0) {
		listp->runtime++;
		offset++;
	}

	clock_interval_to_deadline(offset, USEC_PER_SEC, &deadline);

	thread_call_enter_delayed(listp->call, deadline);
	listp->scheduled = TRUE;
}

/*
 * Function to run the timers for a connection.
 *
 * Returns the offset of next timer to be run for this connection which
 * can be used to reschedule the timerlist.
 *
 * te_mode is an out parameter that indicates the modes of active
 * timers for this connection.
 */
u_int32_t
tcp_run_conn_timer(struct tcpcb *tp, u_int16_t *te_mode,
	u_int16_t probe_if_index)
{
	struct socket *so;
	u_int16_t i = 0, index = TCPT_NONE, lo_index = TCPT_NONE;
	u_int32_t timer_val, offset = 0, lo_timer = 0;
	int32_t diff;
	boolean_t needtorun[TCPT_NTIMERS];
	int count = 0;

	VERIFY(tp != NULL);
	bzero(needtorun, sizeof(needtorun));
	*te_mode = 0;

	socket_lock(tp->t_inpcb->inp_socket, 1);

	so = tp->t_inpcb->inp_socket;
	/* Release the want count on inp */
	if (in_pcb_checkstate(tp->t_inpcb, WNT_RELEASE, 1)
		== WNT_STOPUSING) {
		if (TIMER_IS_ON_LIST(tp)) {
			tcp_remove_timer(tp);
		}

		/* Looks like the TCP connection got closed while we
		 * were waiting for the lock.. Done
		 */
		goto done;
	}

	/*
	 * If this connection is over an interface that needs to
	 * be probed, send probe packets to reinitiate communication.
	 */
	if (probe_if_index > 0 && tp->t_inpcb->inp_last_outifp != NULL &&
	    tp->t_inpcb->inp_last_outifp->if_index == probe_if_index) {
		tp->t_flagsext |= TF_PROBING;
		tcp_timers(tp, TCPT_PTO);
		tp->t_timer[TCPT_PTO] = 0;
		tp->t_flagsext &= ~TF_PROBING;
	}

	/*
	 * Since the timer thread needs to wait for tcp lock, it may race
	 * with another thread that can cancel or reschedule the timer
	 * that is about to run. Check if we need to run anything.
	 */
	if ((index = tp->tentry.index) == TCPT_NONE)
		goto done;

	timer_val = tp->t_timer[index];

	diff = timer_diff(tp->tentry.runtime, 0, tcp_now, 0);
	if (diff > 0) {
		if (tp->tentry.index != TCPT_NONE) {
			offset = diff;
			*(te_mode) = tp->tentry.mode;
		}
		goto done;
	}

	tp->t_timer[index] = 0;
	if (timer_val > 0) {
		tp = tcp_timers(tp, index);
		if (tp == NULL)
			goto done;
	}

	/*
	 * Check if there are any other timers that need to be run.
	 * While doing it, adjust the timer values wrt tcp_now.
	 */
	tp->tentry.mode = 0;
	for (i = 0; i < TCPT_NTIMERS; ++i) {
		if (tp->t_timer[i] != 0) {
			diff = timer_diff(tp->tentry.timer_start,
				tp->t_timer[i], tcp_now, 0);
			if (diff <= 0) {
				needtorun[i] = TRUE;
				count++;
			} else {
				tp->t_timer[i] = diff;
				needtorun[i] = FALSE;
				if (lo_timer == 0 || diff < lo_timer) {
					lo_timer = diff;
					lo_index = i;
				}
				TCP_SET_TIMER_MODE(tp->tentry.mode, i);
			}
		}
	}

	tp->tentry.timer_start = tcp_now;
	tp->tentry.index = lo_index;
	VERIFY(tp->tentry.index == TCPT_NONE || tp->tentry.mode > 0);

	if (tp->tentry.index != TCPT_NONE) {
		tp->tentry.runtime = tp->tentry.timer_start +
			tp->t_timer[tp->tentry.index];
		if (tp->tentry.runtime == 0)
			tp->tentry.runtime++;
	}

	if (count > 0) {
		/* run any other timers outstanding at this time. */
		for (i = 0; i < TCPT_NTIMERS; ++i) {
			if (needtorun[i]) {
				tp->t_timer[i] = 0;
				tp = tcp_timers(tp, i);
				if (tp == NULL) {
					offset = 0;
					*(te_mode) = 0;
					goto done;
				}
			}
		}
		tcp_set_lotimer_index(tp);
	}

	if (tp->tentry.index < TCPT_NONE) {
		offset = tp->t_timer[tp->tentry.index];
		*(te_mode) = tp->tentry.mode;
	}

done:
	if (tp != NULL && tp->tentry.index == TCPT_NONE) {
		tcp_remove_timer(tp);
		offset = 0;
	}

	socket_unlock(so, 1);
	return(offset);
}

void
tcp_run_timerlist(void * arg1, void * arg2)
{
#pragma unused(arg1, arg2)
	struct tcptimerentry *te, *next_te;
	struct tcptimerlist *listp = &tcp_timer_list;
	struct tcpcb *tp;
	uint32_t next_timer = 0; /* offset of the next timer on the list */
	u_int16_t te_mode = 0;	/* modes of all active timers in a tcpcb */
	u_int16_t list_mode = 0; /* cumulative of modes of all tcpcbs */
	uint32_t active_count = 0;

	calculate_tcp_clock();

	lck_mtx_lock(listp->mtx);

	int32_t drift = tcp_now - listp->runtime;
	if (drift <= 1) {
		tcpstat.tcps_timer_drift_le_1_ms++;
	} else if (drift <= 10) {
		tcpstat.tcps_timer_drift_le_10_ms++;
	} else if (drift <= 20) {
		tcpstat.tcps_timer_drift_le_20_ms++;
	} else if (drift <= 50) {
		tcpstat.tcps_timer_drift_le_50_ms++;
	} else if (drift <= 100) {
		tcpstat.tcps_timer_drift_le_100_ms++;
	} else if (drift <= 200) {
		tcpstat.tcps_timer_drift_le_200_ms++;
	} else if (drift <= 500) {
		tcpstat.tcps_timer_drift_le_500_ms++;
	} else if (drift <= 1000) {
		tcpstat.tcps_timer_drift_le_1000_ms++;
	} else {
		tcpstat.tcps_timer_drift_gt_1000_ms++;
	}

	listp->running = TRUE;

	LIST_FOREACH_SAFE(te, &listp->lhead, le, next_te) {
		uint32_t offset = 0;
		uint32_t runtime = te->runtime;
		if (te->index < TCPT_NONE && TSTMP_GT(runtime, tcp_now)) {
			offset = timer_diff(runtime, 0, tcp_now, 0);
			if (next_timer == 0 || offset < next_timer) {
				next_timer = offset;
			}
			list_mode |= te->mode;
			continue;
		}

		tp = TIMERENTRY_TO_TP(te);

		/*
		 * Acquire an inp wantcnt on the inpcb so that the socket
		 * won't get detached even if tcp_close is called
		 */
		if (in_pcb_checkstate(tp->t_inpcb, WNT_ACQUIRE, 0)
		    == WNT_STOPUSING) {
			/*
			 * Some how this pcb went into dead state while
			 * on the timer list, just take it off the list.
			 * Since the timer list entry pointers are
			 * protected by the timer list lock, we can
			 * do it here without the socket lock.
			 */
			if (TIMER_IS_ON_LIST(tp)) {
				tp->t_flags &= ~(TF_TIMER_ONLIST);
				LIST_REMOVE(&tp->tentry, le);
				listp->entries--;

				tp->tentry.le.le_next = NULL;
				tp->tentry.le.le_prev = NULL;
			}
			continue;
		}
		active_count++;

		/*
		 * Store the next timerentry pointer before releasing the
		 * list lock. If that entry has to be removed when we
		 * release the lock, this pointer will be updated to the
		 * element after that.
		 */
		listp->next_te = next_te;

		VERIFY_NEXT_LINK(&tp->tentry, le);
		VERIFY_PREV_LINK(&tp->tentry, le);

		lck_mtx_unlock(listp->mtx);

		offset = tcp_run_conn_timer(tp, &te_mode,
		    listp->probe_if_index);

		lck_mtx_lock(listp->mtx);

		next_te = listp->next_te;
		listp->next_te = NULL;

		if (offset > 0 && te_mode != 0) {
			list_mode |= te_mode;

			if (next_timer == 0 || offset < next_timer)
				next_timer = offset;
		}
	}

	if (!LIST_EMPTY(&listp->lhead)) {
		u_int16_t next_mode = 0;
		if ((list_mode & TCP_TIMERLIST_10MS_MODE) ||
			(listp->pref_mode & TCP_TIMERLIST_10MS_MODE))
			next_mode = TCP_TIMERLIST_10MS_MODE;
		else if ((list_mode & TCP_TIMERLIST_100MS_MODE) ||
			(listp->pref_mode & TCP_TIMERLIST_100MS_MODE))
			next_mode = TCP_TIMERLIST_100MS_MODE;
		else
			next_mode = TCP_TIMERLIST_500MS_MODE;

		if (next_mode != TCP_TIMERLIST_500MS_MODE) {
			listp->idleruns = 0;
		} else {
			/*
			 * the next required mode is slow mode, but if
			 * the last one was a faster mode and we did not
			 * have enough idle runs, repeat the last mode.
			 *
			 * We try to keep the timer list in fast mode for
			 * some idle time in expectation of new data.
			 */
			if (listp->mode != next_mode &&
			    listp->idleruns < timer_fastmode_idlemax) {
				listp->idleruns++;
				next_mode = listp->mode;
				next_timer = TCP_TIMER_100MS_QUANTUM;
			} else {
				listp->idleruns = 0;
			}
		}
		listp->mode = next_mode;
		if (listp->pref_offset != 0)
			next_timer = min(listp->pref_offset, next_timer);

		if (listp->mode == TCP_TIMERLIST_500MS_MODE)
			next_timer = max(next_timer,
				TCP_TIMER_500MS_QUANTUM);

		tcp_sched_timerlist(next_timer);
	} else {
		/*
		 * No need to reschedule this timer, but always run
		 * periodically at a much higher granularity.
		 */
		tcp_sched_timerlist(TCP_TIMERLIST_MAX_OFFSET);
	}

	listp->running = FALSE;
	listp->pref_mode = 0;
	listp->pref_offset = 0;
	listp->probe_if_index = 0;

	lck_mtx_unlock(listp->mtx);
}

/*
 * Function to check if the timerlist needs to be rescheduled to run this
 * connection's timers correctly.
 */
void
tcp_sched_timers(struct tcpcb *tp)
{
	struct tcptimerentry *te = &tp->tentry;
	u_int16_t index = te->index;
	u_int16_t mode = te->mode;
	struct tcptimerlist *listp = &tcp_timer_list;
	int32_t offset = 0;
	boolean_t list_locked = FALSE;

	if (tp->t_inpcb->inp_state == INPCB_STATE_DEAD) {
		/* Just return without adding the dead pcb to the list */
		if (TIMER_IS_ON_LIST(tp)) {
			tcp_remove_timer(tp);
		}
		return;
	}

	if (index == TCPT_NONE) {
		/* Nothing to run */
		tcp_remove_timer(tp);
		return;
	}

	/*
	 * compute the offset at which the next timer for this connection
	 * has to run.
	 */
	offset = timer_diff(te->runtime, 0, tcp_now, 0);
	if (offset <= 0) {
		offset = 1;
		tcp_timer_advanced++;
	}

	if (!TIMER_IS_ON_LIST(tp)) {
		if (!list_locked) {
			lck_mtx_lock(listp->mtx);
			list_locked = TRUE;
		}

		if (!TIMER_IS_ON_LIST(tp)) {
			LIST_INSERT_HEAD(&listp->lhead, te, le);
			tp->t_flags |= TF_TIMER_ONLIST;

			listp->entries++;
			if (listp->entries > listp->maxentries)
				listp->maxentries = listp->entries;

			/* if the list is not scheduled, just schedule it */
			if (!listp->scheduled)
				goto schedule;
		}
	}

	/*
	 * Timer entry is currently on the list, check if the list needs
	 * to be rescheduled.
	 */
	if (need_to_resched_timerlist(te->runtime, mode)) {
		tcp_resched_timerlist++;

		if (!list_locked) {
			lck_mtx_lock(listp->mtx);
			list_locked = TRUE;
		}

		VERIFY_NEXT_LINK(te, le);
		VERIFY_PREV_LINK(te, le);

		if (listp->running) {
			listp->pref_mode |= mode;
			if (listp->pref_offset == 0 ||
				offset < listp->pref_offset) {
				listp->pref_offset = offset;
			}
		} else {
			/*
			 * The list could have got rescheduled while
			 * this thread was waiting for the lock
			 */
			if (listp->scheduled) {
				int32_t diff;
				diff = timer_diff(listp->runtime, 0,
				    tcp_now, offset);
				if (diff <= 0)
					goto done;
				else
					goto schedule;
			} else {
				goto schedule;
			}
		}
	}
	goto done;

schedule:
	/*
	 * Since a connection with timers is getting scheduled, the timer
	 * list moves from idle to active state and that is why idlegen is
	 * reset
	 */
	if (mode & TCP_TIMERLIST_10MS_MODE) {
		listp->mode = TCP_TIMERLIST_10MS_MODE;
		listp->idleruns = 0;
		offset = min(offset, TCP_TIMER_10MS_QUANTUM);
	} else if (mode & TCP_TIMERLIST_100MS_MODE) {
		if (listp->mode > TCP_TIMERLIST_100MS_MODE)
			listp->mode = TCP_TIMERLIST_100MS_MODE;
		listp->idleruns = 0;
		offset = min(offset, TCP_TIMER_100MS_QUANTUM);
	}
	tcp_sched_timerlist(offset);

done:
	if (list_locked)
		lck_mtx_unlock(listp->mtx);

	return;
}

static inline void
tcp_set_lotimer_index(struct tcpcb *tp)
{
	uint16_t i, lo_index = TCPT_NONE, mode = 0;
	uint32_t lo_timer = 0;
	for (i = 0; i < TCPT_NTIMERS; ++i) {
		if (tp->t_timer[i] != 0) {
			TCP_SET_TIMER_MODE(mode, i);
			if (lo_timer == 0 || tp->t_timer[i] < lo_timer) {
				lo_timer = tp->t_timer[i];
				lo_index = i;
			}
		}
	}
	tp->tentry.index = lo_index;
	tp->tentry.mode = mode;
	VERIFY(tp->tentry.index == TCPT_NONE || tp->tentry.mode > 0);

	if (tp->tentry.index != TCPT_NONE) {
		tp->tentry.runtime = tp->tentry.timer_start
		    + tp->t_timer[tp->tentry.index];
		if (tp->tentry.runtime == 0)
			tp->tentry.runtime++;
	}
}

void
tcp_check_timer_state(struct tcpcb *tp)
{
	socket_lock_assert_owned(tp->t_inpcb->inp_socket);

	if (tp->t_inpcb->inp_flags2 & INP2_TIMEWAIT)
		return;

	tcp_set_lotimer_index(tp);

	tcp_sched_timers(tp);
	return;
}

static inline void
tcp_cumulative_stat(u_int32_t cur, u_int32_t *prev, u_int32_t *dest)
{
	/* handle wrap around */
	int32_t diff = (int32_t) (cur - *prev);
	if (diff > 0)
		*dest = diff;
	else
		*dest = 0;
	*prev = cur;
	return;
}

static inline void
tcp_cumulative_stat64(u_int64_t cur, u_int64_t *prev, u_int64_t *dest)
{
	/* handle wrap around */
	int64_t diff = (int64_t) (cur - *prev);
	if (diff > 0)
		*dest = diff;
	else
		*dest = 0;
	*prev = cur;
	return;
}

__private_extern__ void
tcp_report_stats(void)
{
	struct nstat_sysinfo_data data;
	struct sockaddr_in dst;
	struct sockaddr_in6 dst6;
	struct rtentry *rt = NULL;
	static struct tcp_last_report_stats prev;
	u_int64_t var, uptime;

#define	stat	data.u.tcp_stats
	if (((uptime = net_uptime()) - tcp_last_report_time) <
		tcp_report_stats_interval)
		return;

	tcp_last_report_time = uptime;

	bzero(&data, sizeof(data));
	data.flags = NSTAT_SYSINFO_TCP_STATS;

	bzero(&dst, sizeof(dst));
	dst.sin_len = sizeof(dst);
	dst.sin_family = AF_INET;

	/* ipv4 avg rtt */
	lck_mtx_lock(rnh_lock);
	rt =  rt_lookup(TRUE, (struct sockaddr *)&dst, NULL,
		rt_tables[AF_INET], IFSCOPE_NONE);
	lck_mtx_unlock(rnh_lock);
	if (rt != NULL) {
		RT_LOCK(rt);
		if (rt_primary_default(rt, rt_key(rt)) &&
			rt->rt_stats != NULL) {
			stat.ipv4_avgrtt = rt->rt_stats->nstat_avg_rtt;
		}
		RT_UNLOCK(rt);
		rtfree(rt);
		rt = NULL;
	}

	/* ipv6 avg rtt */
	bzero(&dst6, sizeof(dst6));
	dst6.sin6_len = sizeof(dst6);
	dst6.sin6_family = AF_INET6;

	lck_mtx_lock(rnh_lock);
	rt = rt_lookup(TRUE,(struct sockaddr *)&dst6, NULL,
		rt_tables[AF_INET6], IFSCOPE_NONE);
	lck_mtx_unlock(rnh_lock);
	if (rt != NULL) {
		RT_LOCK(rt);
		if (rt_primary_default(rt, rt_key(rt)) &&
			rt->rt_stats != NULL) {
			stat.ipv6_avgrtt = rt->rt_stats->nstat_avg_rtt;
		}
		RT_UNLOCK(rt);
		rtfree(rt);
		rt = NULL;
	}

	/* send packet loss rate, shift by 10 for precision */
	if (tcpstat.tcps_sndpack > 0 && tcpstat.tcps_sndrexmitpack > 0) {
		var = tcpstat.tcps_sndrexmitpack << 10;
		stat.send_plr = (var * 100) / tcpstat.tcps_sndpack;
	}

	/* recv packet loss rate, shift by 10 for precision */
	if (tcpstat.tcps_rcvpack > 0 && tcpstat.tcps_recovered_pkts > 0) {
		var = tcpstat.tcps_recovered_pkts << 10;
		stat.recv_plr = (var * 100) / tcpstat.tcps_rcvpack;
	}

	/* RTO after tail loss, shift by 10 for precision */
	if (tcpstat.tcps_sndrexmitpack > 0
	    && tcpstat.tcps_tailloss_rto > 0) {
		var = tcpstat.tcps_tailloss_rto << 10;
		stat.send_tlrto_rate =
			(var * 100) / tcpstat.tcps_sndrexmitpack;
	}

	/* packet reordering */
	if (tcpstat.tcps_sndpack > 0 && tcpstat.tcps_reordered_pkts > 0) {
		var = tcpstat.tcps_reordered_pkts << 10;
		stat.send_reorder_rate =
			(var * 100) / tcpstat.tcps_sndpack;
	}

	if (tcp_ecn_outbound == 1)
		stat.ecn_client_enabled = 1;
	if (tcp_ecn_inbound == 1)
		stat.ecn_server_enabled = 1;
	tcp_cumulative_stat(tcpstat.tcps_connattempt,
	    &prev.tcps_connattempt, &stat.connection_attempts);
	tcp_cumulative_stat(tcpstat.tcps_accepts,
	    &prev.tcps_accepts, &stat.connection_accepts);
	tcp_cumulative_stat(tcpstat.tcps_ecn_client_setup,
	    &prev.tcps_ecn_client_setup, &stat.ecn_client_setup);
	tcp_cumulative_stat(tcpstat.tcps_ecn_server_setup,
	    &prev.tcps_ecn_server_setup, &stat.ecn_server_setup);
	tcp_cumulative_stat(tcpstat.tcps_ecn_client_success,
	    &prev.tcps_ecn_client_success, &stat.ecn_client_success);
	tcp_cumulative_stat(tcpstat.tcps_ecn_server_success,
	    &prev.tcps_ecn_server_success, &stat.ecn_server_success);
	tcp_cumulative_stat(tcpstat.tcps_ecn_not_supported,
	    &prev.tcps_ecn_not_supported, &stat.ecn_not_supported);
	tcp_cumulative_stat(tcpstat.tcps_ecn_lost_syn,
	    &prev.tcps_ecn_lost_syn, &stat.ecn_lost_syn);
	tcp_cumulative_stat(tcpstat.tcps_ecn_lost_synack,
	    &prev.tcps_ecn_lost_synack, &stat.ecn_lost_synack);
	tcp_cumulative_stat(tcpstat.tcps_ecn_recv_ce,
	    &prev.tcps_ecn_recv_ce, &stat.ecn_recv_ce);
	tcp_cumulative_stat(tcpstat.tcps_ecn_recv_ece,
	    &prev.tcps_ecn_recv_ece, &stat.ecn_recv_ece);
	tcp_cumulative_stat(tcpstat.tcps_ecn_recv_ece,
	    &prev.tcps_ecn_recv_ece, &stat.ecn_recv_ece);
	tcp_cumulative_stat(tcpstat.tcps_ecn_sent_ece,
	    &prev.tcps_ecn_sent_ece, &stat.ecn_sent_ece);
	tcp_cumulative_stat(tcpstat.tcps_ecn_sent_ece,
	    &prev.tcps_ecn_sent_ece, &stat.ecn_sent_ece);
	tcp_cumulative_stat(tcpstat.tcps_ecn_conn_recv_ce,
	    &prev.tcps_ecn_conn_recv_ce, &stat.ecn_conn_recv_ce);
	tcp_cumulative_stat(tcpstat.tcps_ecn_conn_recv_ece,
	    &prev.tcps_ecn_conn_recv_ece, &stat.ecn_conn_recv_ece);
	tcp_cumulative_stat(tcpstat.tcps_ecn_conn_plnoce,
	    &prev.tcps_ecn_conn_plnoce, &stat.ecn_conn_plnoce);
	tcp_cumulative_stat(tcpstat.tcps_ecn_conn_pl_ce,
	    &prev.tcps_ecn_conn_pl_ce, &stat.ecn_conn_pl_ce);
	tcp_cumulative_stat(tcpstat.tcps_ecn_conn_nopl_ce,
	    &prev.tcps_ecn_conn_nopl_ce, &stat.ecn_conn_nopl_ce);
	tcp_cumulative_stat(tcpstat.tcps_ecn_fallback_synloss,
	    &prev.tcps_ecn_fallback_synloss, &stat.ecn_fallback_synloss);
	tcp_cumulative_stat(tcpstat.tcps_ecn_fallback_reorder,
	    &prev.tcps_ecn_fallback_reorder, &stat.ecn_fallback_reorder);
	tcp_cumulative_stat(tcpstat.tcps_ecn_fallback_ce,
	    &prev.tcps_ecn_fallback_ce, &stat.ecn_fallback_ce);
	tcp_cumulative_stat(tcpstat.tcps_tfo_syn_data_rcv,
	    &prev.tcps_tfo_syn_data_rcv, &stat.tfo_syn_data_rcv);
	tcp_cumulative_stat(tcpstat.tcps_tfo_cookie_req_rcv,
	    &prev.tcps_tfo_cookie_req_rcv, &stat.tfo_cookie_req_rcv);
	tcp_cumulative_stat(tcpstat.tcps_tfo_cookie_sent,
	    &prev.tcps_tfo_cookie_sent, &stat.tfo_cookie_sent);
	tcp_cumulative_stat(tcpstat.tcps_tfo_cookie_invalid,
	    &prev.tcps_tfo_cookie_invalid, &stat.tfo_cookie_invalid);
	tcp_cumulative_stat(tcpstat.tcps_tfo_cookie_req,
	    &prev.tcps_tfo_cookie_req, &stat.tfo_cookie_req);
	tcp_cumulative_stat(tcpstat.tcps_tfo_cookie_rcv,
	    &prev.tcps_tfo_cookie_rcv, &stat.tfo_cookie_rcv);
	tcp_cumulative_stat(tcpstat.tcps_tfo_syn_data_sent,
	    &prev.tcps_tfo_syn_data_sent, &stat.tfo_syn_data_sent);
	tcp_cumulative_stat(tcpstat.tcps_tfo_syn_data_acked,
	    &prev.tcps_tfo_syn_data_acked, &stat.tfo_syn_data_acked);
	tcp_cumulative_stat(tcpstat.tcps_tfo_syn_loss,
	    &prev.tcps_tfo_syn_loss, &stat.tfo_syn_loss);
	tcp_cumulative_stat(tcpstat.tcps_tfo_blackhole,
	    &prev.tcps_tfo_blackhole, &stat.tfo_blackhole);
	tcp_cumulative_stat(tcpstat.tcps_tfo_cookie_wrong,
	    &prev.tcps_tfo_cookie_wrong, &stat.tfo_cookie_wrong);
	tcp_cumulative_stat(tcpstat.tcps_tfo_no_cookie_rcv,
	    &prev.tcps_tfo_no_cookie_rcv, &stat.tfo_no_cookie_rcv);
	tcp_cumulative_stat(tcpstat.tcps_tfo_heuristics_disable,
	    &prev.tcps_tfo_heuristics_disable, &stat.tfo_heuristics_disable);
	tcp_cumulative_stat(tcpstat.tcps_tfo_sndblackhole,
	    &prev.tcps_tfo_sndblackhole, &stat.tfo_sndblackhole);


	tcp_cumulative_stat(tcpstat.tcps_mptcp_handover_attempt,
	    &prev.tcps_mptcp_handover_attempt , &stat.mptcp_handover_attempt);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_interactive_attempt,
	    &prev.tcps_mptcp_interactive_attempt , &stat.mptcp_interactive_attempt);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_aggregate_attempt,
	    &prev.tcps_mptcp_aggregate_attempt , &stat.mptcp_aggregate_attempt);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_fp_handover_attempt,
	    &prev.tcps_mptcp_fp_handover_attempt , &stat.mptcp_fp_handover_attempt);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_fp_interactive_attempt,
	    &prev.tcps_mptcp_fp_interactive_attempt , &stat.mptcp_fp_interactive_attempt);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_fp_aggregate_attempt,
	    &prev.tcps_mptcp_fp_aggregate_attempt , &stat.mptcp_fp_aggregate_attempt);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_heuristic_fallback,
	    &prev.tcps_mptcp_heuristic_fallback , &stat.mptcp_heuristic_fallback);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_fp_heuristic_fallback,
	    &prev.tcps_mptcp_fp_heuristic_fallback , &stat.mptcp_fp_heuristic_fallback);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_handover_success_wifi,
	    &prev.tcps_mptcp_handover_success_wifi , &stat.mptcp_handover_success_wifi);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_handover_success_cell,
	    &prev.tcps_mptcp_handover_success_cell , &stat.mptcp_handover_success_cell);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_interactive_success,
	    &prev.tcps_mptcp_interactive_success , &stat.mptcp_interactive_success);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_aggregate_success,
	    &prev.tcps_mptcp_aggregate_success , &stat.mptcp_aggregate_success);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_fp_handover_success_wifi,
	    &prev.tcps_mptcp_fp_handover_success_wifi , &stat.mptcp_fp_handover_success_wifi);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_fp_handover_success_cell,
	    &prev.tcps_mptcp_fp_handover_success_cell , &stat.mptcp_fp_handover_success_cell);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_fp_interactive_success,
	    &prev.tcps_mptcp_fp_interactive_success , &stat.mptcp_fp_interactive_success);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_fp_aggregate_success,
	    &prev.tcps_mptcp_fp_aggregate_success , &stat.mptcp_fp_aggregate_success);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_handover_cell_from_wifi,
	    &prev.tcps_mptcp_handover_cell_from_wifi , &stat.mptcp_handover_cell_from_wifi);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_handover_wifi_from_cell,
	    &prev.tcps_mptcp_handover_wifi_from_cell , &stat.mptcp_handover_wifi_from_cell);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_interactive_cell_from_wifi,
	    &prev.tcps_mptcp_interactive_cell_from_wifi , &stat.mptcp_interactive_cell_from_wifi);
	tcp_cumulative_stat64(tcpstat.tcps_mptcp_handover_cell_bytes,
	    &prev.tcps_mptcp_handover_cell_bytes , &stat.mptcp_handover_cell_bytes);
	tcp_cumulative_stat64(tcpstat.tcps_mptcp_interactive_cell_bytes,
	    &prev.tcps_mptcp_interactive_cell_bytes , &stat.mptcp_interactive_cell_bytes);
	tcp_cumulative_stat64(tcpstat.tcps_mptcp_aggregate_cell_bytes,
	    &prev.tcps_mptcp_aggregate_cell_bytes , &stat.mptcp_aggregate_cell_bytes);
	tcp_cumulative_stat64(tcpstat.tcps_mptcp_handover_all_bytes,
	    &prev.tcps_mptcp_handover_all_bytes , &stat.mptcp_handover_all_bytes);
	tcp_cumulative_stat64(tcpstat.tcps_mptcp_interactive_all_bytes,
	    &prev.tcps_mptcp_interactive_all_bytes , &stat.mptcp_interactive_all_bytes);
	tcp_cumulative_stat64(tcpstat.tcps_mptcp_aggregate_all_bytes,
	    &prev.tcps_mptcp_aggregate_all_bytes , &stat.mptcp_aggregate_all_bytes);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_back_to_wifi,
	    &prev.tcps_mptcp_back_to_wifi , &stat.mptcp_back_to_wifi);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_wifi_proxy,
	    &prev.tcps_mptcp_wifi_proxy , &stat.mptcp_wifi_proxy);
	tcp_cumulative_stat(tcpstat.tcps_mptcp_cell_proxy,
	    &prev.tcps_mptcp_cell_proxy , &stat.mptcp_cell_proxy);


	nstat_sysinfo_send_data(&data);

#undef	stat
}

void
tcp_interface_send_probe(u_int16_t probe_if_index)
{
	int32_t offset = 0;
	struct tcptimerlist *listp = &tcp_timer_list;

	/* Make sure TCP clock is up to date */
	calculate_tcp_clock();

	lck_mtx_lock(listp->mtx);
	if (listp->probe_if_index > 0) {
		tcpstat.tcps_probe_if_conflict++;
		goto done;
	}

	listp->probe_if_index = probe_if_index;
	if (listp->running)
		goto done;

	/*
	 * Reschedule the timerlist to run within the next 10ms, which is
	 * the fastest that we can do.
	 */
	offset = TCP_TIMER_10MS_QUANTUM;
	if (listp->scheduled) {
		int32_t diff;
		diff = timer_diff(listp->runtime, 0, tcp_now, offset);
		if (diff <= 0) {
			/* The timer will fire sooner than what's needed */
			goto done;
		}
	}
	listp->mode = TCP_TIMERLIST_10MS_MODE;
	listp->idleruns = 0;

	tcp_sched_timerlist(offset);

done:
	lck_mtx_unlock(listp->mtx);
	return;
}

/*
 * Enable read probes on this connection, if:
 * - it is in established state
 * - doesn't have any data outstanding
 * - the outgoing ifp matches
 * - we have not already sent any read probes
 */
static void
tcp_enable_read_probe(struct tcpcb *tp, struct ifnet *ifp)
{
	if (tp->t_state == TCPS_ESTABLISHED &&
	    tp->snd_max == tp->snd_una &&
	    tp->t_inpcb->inp_last_outifp == ifp &&
	    !(tp->t_flagsext & TF_DETECT_READSTALL) &&
	    tp->t_rtimo_probes == 0) {
		tp->t_flagsext |= TF_DETECT_READSTALL;
		tp->t_rtimo_probes = 0;
		tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(tp,
		    TCP_TIMER_10MS_QUANTUM);
		if (tp->tentry.index == TCPT_NONE) {
			tp->tentry.index = TCPT_KEEP;
			tp->tentry.runtime = tcp_now +
			    TCP_TIMER_10MS_QUANTUM;
		} else {
			int32_t diff = 0;

			/* Reset runtime to be in next 10ms */
			diff = timer_diff(tp->tentry.runtime, 0,
			    tcp_now, TCP_TIMER_10MS_QUANTUM);
			if (diff > 0) {
				tp->tentry.index = TCPT_KEEP;
				tp->tentry.runtime = tcp_now +
				    TCP_TIMER_10MS_QUANTUM;
				if (tp->tentry.runtime == 0)
					tp->tentry.runtime++;
			}
		}
	}
}

/*
 * Disable read probe and reset the keep alive timer
 */
static void
tcp_disable_read_probe(struct tcpcb *tp)
{
	if (tp->t_adaptive_rtimo == 0 &&
	    ((tp->t_flagsext & TF_DETECT_READSTALL) ||
	    tp->t_rtimo_probes > 0)) {
		tcp_keepalive_reset(tp);

		if (tp->t_mpsub)
			mptcp_reset_keepalive(tp);
	}
}

/*
 * Reschedule the tcp timerlist in the next 10ms to re-enable read/write
 * probes on connections going over a particular interface.
 */
void
tcp_probe_connectivity(struct ifnet *ifp, u_int32_t enable)
{
	int32_t offset;
	struct tcptimerlist *listp = &tcp_timer_list;
	struct inpcbinfo *pcbinfo = &tcbinfo;
	struct inpcb *inp, *nxt;

	if (ifp == NULL)
		return;

	/* update clock */
	calculate_tcp_clock();

	/*
	 * Enable keep alive timer on all connections that are
	 * active/established on this interface.
	 */
	lck_rw_lock_shared(pcbinfo->ipi_lock);

	LIST_FOREACH_SAFE(inp, pcbinfo->ipi_listhead, inp_list, nxt) {
		struct tcpcb *tp = NULL;
		if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) ==
		    WNT_STOPUSING)
			continue;

		/* Acquire lock to look at the state of the connection */
		socket_lock(inp->inp_socket, 1);

		/* Release the want count */
		if (inp->inp_ppcb == NULL ||
		    (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING)) {
			socket_unlock(inp->inp_socket, 1);
			continue;
		}
		tp = intotcpcb(inp);
		if (enable)
			tcp_enable_read_probe(tp, ifp);
		else
			tcp_disable_read_probe(tp);

		socket_unlock(inp->inp_socket, 1);
	}
	lck_rw_done(pcbinfo->ipi_lock);

	lck_mtx_lock(listp->mtx);
	if (listp->running) {
		listp->pref_mode |= TCP_TIMERLIST_10MS_MODE;
		goto done;
	}

	/* Reschedule within the next 10ms */
	offset = TCP_TIMER_10MS_QUANTUM;
	if (listp->scheduled) {
		int32_t diff;
		diff = timer_diff(listp->runtime, 0, tcp_now, offset);
		if (diff <= 0) {
			/* The timer will fire sooner than what's needed */
			goto done;
		}
	}
	listp->mode = TCP_TIMERLIST_10MS_MODE;
	listp->idleruns = 0;

	tcp_sched_timerlist(offset);
done:
	lck_mtx_unlock(listp->mtx);
	return;
}

inline void
tcp_update_mss_core(struct tcpcb *tp, struct ifnet *ifp)
{
	struct if_cellular_status_v1 *ifsr;
	u_int32_t optlen;
	ifsr = &ifp->if_link_status->ifsr_u.ifsr_cell.if_cell_u.if_status_v1;
	if (ifsr->valid_bitmask & IF_CELL_UL_MSS_RECOMMENDED_VALID) {
		optlen = tp->t_maxopd - tp->t_maxseg;

		if (ifsr->mss_recommended ==
		    IF_CELL_UL_MSS_RECOMMENDED_NONE &&
		    tp->t_cached_maxopd > 0 &&
		    tp->t_maxopd < tp->t_cached_maxopd) {
			tp->t_maxopd = tp->t_cached_maxopd;
			tcpstat.tcps_mss_to_default++;
		} else if (ifsr->mss_recommended ==
		    IF_CELL_UL_MSS_RECOMMENDED_MEDIUM &&
		    tp->t_maxopd > tcp_mss_rec_medium) {
			tp->t_cached_maxopd = tp->t_maxopd;
			tp->t_maxopd = tcp_mss_rec_medium;
			tcpstat.tcps_mss_to_medium++;
		} else if (ifsr->mss_recommended ==
		    IF_CELL_UL_MSS_RECOMMENDED_LOW &&
		    tp->t_maxopd > tcp_mss_rec_low) {
			tp->t_cached_maxopd = tp->t_maxopd;
			tp->t_maxopd = tcp_mss_rec_low;
			tcpstat.tcps_mss_to_low++;
		}
		tp->t_maxseg = tp->t_maxopd - optlen;

		/*
		 * clear the cached value if it is same as the current
		 */
		if (tp->t_maxopd == tp->t_cached_maxopd)
			tp->t_cached_maxopd = 0;
	}
}

void
tcp_update_mss_locked(struct socket *so, struct ifnet *ifp)
{
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = intotcpcb(inp);

	if (ifp == NULL && (ifp = inp->inp_last_outifp) == NULL)
		return;

	if (!IFNET_IS_CELLULAR(ifp)) {
		/*
		 * This optimization is implemented for cellular
		 * networks only
		 */
		return;
	}
	if ( tp->t_state <= TCPS_CLOSE_WAIT) {
		/*
		 * If the connection is currently doing or has done PMTU
		 * blackhole detection, do not change the MSS
		 */
		if (tp->t_flags & TF_BLACKHOLE)
			return;
		if (ifp->if_link_status == NULL)
			return;
		tcp_update_mss_core(tp, ifp);
	}
}

void
tcp_itimer(struct inpcbinfo *ipi)
{
	struct inpcb *inp, *nxt;

	if (lck_rw_try_lock_exclusive(ipi->ipi_lock) == FALSE) {
		if (tcp_itimer_done == TRUE) {
			tcp_itimer_done = FALSE;
			atomic_add_32(&ipi->ipi_timer_req.intimer_fast, 1);
			return;
		}
		/* Upgrade failed, lost lock now take it again exclusive */
		lck_rw_lock_exclusive(ipi->ipi_lock);
	}
	tcp_itimer_done = TRUE;

	LIST_FOREACH_SAFE(inp, &tcb, inp_list, nxt) {
		struct socket *so;
		struct ifnet *ifp;

		if (inp->inp_ppcb == NULL ||
		    in_pcb_checkstate(inp, WNT_ACQUIRE, 0) == WNT_STOPUSING)
			continue;
		so = inp->inp_socket;
		ifp = inp->inp_last_outifp;
		socket_lock(so, 1);
		if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) {
			socket_unlock(so, 1);
			continue;
		}
		so_check_extended_bk_idle_time(so);
		if (ipi->ipi_flags & INPCBINFO_UPDATE_MSS) {
			tcp_update_mss_locked(so, NULL);
		}
		socket_unlock(so, 1);

		/*
		 * Defunct all system-initiated background sockets if the
		 * socket is using the cellular interface and the interface
		 * has its LQM set to abort.
		 */
		if ((ipi->ipi_flags & INPCBINFO_HANDLE_LQM_ABORT) &&
		    IS_SO_TC_BACKGROUNDSYSTEM(so->so_traffic_class) &&
		    ifp != NULL && IFNET_IS_CELLULAR(ifp) &&
		    (ifp->if_interface_state.valid_bitmask &
		    IF_INTERFACE_STATE_LQM_STATE_VALID) &&
		    ifp->if_interface_state.lqm_state ==
		    IFNET_LQM_THRESH_ABORT) {
			socket_defunct(current_proc(), so,
			    SHUTDOWN_SOCKET_LEVEL_DISCONNECT_ALL);
		}
	}

	ipi->ipi_flags &= ~(INPCBINFO_UPDATE_MSS | INPCBINFO_HANDLE_LQM_ABORT);
	lck_rw_done(ipi->ipi_lock);
}
