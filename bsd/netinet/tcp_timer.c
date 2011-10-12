/*
 * Copyright (c) 2000-2011 Apple Inc. All rights reserved.
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

extern void postevent(struct socket *, struct sockbuf *,
                                               int);
#define DBG_FNC_TCP_FAST	NETDBG_CODE(DBG_NETTCP, (5 << 8))
#define DBG_FNC_TCP_SLOW	NETDBG_CODE(DBG_NETTCP, (5 << 8) | 1)

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

static int 	background_io_trigger = 5;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, background_io_trigger, CTLFLAG_RW | CTLFLAG_LOCKED,
    &background_io_trigger, 0, "Background IO Trigger Setting");

static int
sysctl_msec_to_ticks SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, s, tt;

	tt = *(int *)oidp->oid_arg1;
	s = tt * 1000 / TCP_RETRANSHZ;;

	error = sysctl_handle_int(oidp, &s, 0, req);
	if (error || !req->newptr)
		return (error);

	tt = s * TCP_RETRANSHZ / 1000;
	if (tt < 1)
		return (EINVAL);

	*(int *)oidp->oid_arg1 = tt;
        return (0);
}

int	tcp_keepinit;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPINIT, keepinit, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_keepinit, 0, sysctl_msec_to_ticks, "I", "");

int	tcp_keepidle;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPIDLE, keepidle, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_keepidle, 0, sysctl_msec_to_ticks, "I", "");

int	tcp_keepintvl;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPINTVL, keepintvl, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_keepintvl, 0, sysctl_msec_to_ticks, "I", "");

int	tcp_msl;
SYSCTL_PROC(_net_inet_tcp, OID_AUTO, msl, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_msl, 0, sysctl_msec_to_ticks, "I", "Maximum segment lifetime");

/* 
 * Avoid DoS via TCP Robustness in Persist Condition (see http://www.ietf.org/id/draft-ananth-tcpm-persist-02.txt)
 * by allowing a system wide maximum persistence timeout value when in Zero Window Probe mode.
 * Expressed in milliseconds to be consistent without timeout related values, the TCP socket option is in seconds.
 */
u_int32_t tcp_max_persist_timeout = 0;
SYSCTL_PROC(_net_inet_tcp, OID_AUTO, max_persist_timeout, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_max_persist_timeout, 0, sysctl_msec_to_ticks, "I", "Maximum persistence timout for ZWP");

static int	always_keepalive = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, always_keepalive, CTLFLAG_RW | CTLFLAG_LOCKED,
    &always_keepalive , 0, "Assume SO_KEEPALIVE on all TCP connections");

/* This parameter determines how long the timer list will stay in fast mode even
 * though all connections are idle. In fast mode, the timer will fire more frequently
 * anticipating new data.
 */
int timer_fastmode_idlemax = TCP_FASTMODE_IDLEGEN_MAX;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, timer_fastmode_idlemax, CTLFLAG_RW | CTLFLAG_LOCKED,
	&timer_fastmode_idlemax, 0, "Maximum idle generations in fast mode");

/*
 * See tcp_syn_backoff[] for interval values between SYN retransmits;
 * the value set below defines the number of retransmits, before we
 * disable the timestamp and window scaling options during subsequent
 * SYN retransmits.  Setting it to 0 disables the dropping off of those
 * two options.
 */
static int tcp_broken_peer_syn_rxmit_thres = 7;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, broken_peer_syn_rxmit_thres, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_broken_peer_syn_rxmit_thres, 0, "Number of retransmitted SYNs before "
    "TCP disables rfc1323 and rfc1644 during the rest of attempts");

static int tcp_timer_advanced = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, tcp_timer_advanced, CTLFLAG_RD | CTLFLAG_LOCKED,
    &tcp_timer_advanced, 0, "Number of times one of the timers was advanced");

static int tcp_resched_timerlist = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, tcp_resched_timerlist, CTLFLAG_RD | CTLFLAG_LOCKED,
    &tcp_resched_timerlist, 0, 
    "Number of times timer list was rescheduled as part of processing a packet");

int	tcp_pmtud_black_hole_detect = 1 ;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, pmtud_blackhole_detection, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_pmtud_black_hole_detect, 0, "Path MTU Discovery Black Hole Detection");

int	tcp_pmtud_black_hole_mss = 1200 ;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, pmtud_blackhole_mss, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_pmtud_black_hole_mss, 0, "Path MTU Discovery Black Hole Detection lowered MSS");

static int	tcp_keepcnt = TCPTV_KEEPCNT;
static int	tcp_gc_done = FALSE;	/* perfromed garbage collection of "used" sockets */
	/* max idle probes */
int	tcp_maxpersistidle;
	/* max idle time in persist */
int	tcp_maxidle;

/* TCP delack timer is set to 100 ms. Since the processing of timer list in fast
 * mode will happen no faster than 100 ms, the delayed ack timer will fire some where 
 * between 100 and 200 ms.
 */
int	tcp_delack = TCP_RETRANSHZ / 10;

struct	inpcbhead	time_wait_slots[N_TIME_WAIT_SLOTS];
int		cur_tw_slot = 0;

/* tcp timer list */
struct tcptimerlist tcp_timer_list;

/* The frequency of running through the TCP timer list in 
 * fast and slow mode can be configured.
 */
SYSCTL_UINT(_net_inet_tcp, OID_AUTO, timer_fastquantum, CTLFLAG_RW | CTLFLAG_LOCKED,
	&tcp_timer_list.fast_quantum, TCP_FASTTIMER_QUANTUM, 
	"Frequency of running timer list in fast mode");

SYSCTL_UINT(_net_inet_tcp, OID_AUTO, timer_slowquantum, CTLFLAG_RW | CTLFLAG_LOCKED,
	&tcp_timer_list.slow_quantum, TCP_SLOWTIMER_QUANTUM, 
	"Frequency of running timer list in slow mode");

static void tcp_remove_timer(struct tcpcb *tp);
static void tcp_sched_timerlist(uint32_t offset);
static uint32_t tcp_run_conn_timer(struct tcpcb *tp, uint16_t *next_index);
static void tcp_sched_timers(struct tcpcb *tp);
static inline void tcp_set_lotimer_index(struct tcpcb *);

/* Macro to compare two timers. If there is a reset of the sign bit, it is 
 * safe to assume that the timer has wrapped around. By doing signed comparision, 
 * we take care of wrap around such that the value with the sign bit reset is 
 * actually ahead of the other.
 */

static inline int32_t
timer_diff(uint32_t t1, uint32_t toff1, uint32_t t2, uint32_t toff2) { 
	return (int32_t)((t1 + toff1) - (t2 + toff2));
};

/* Returns true if the timer is on the timer list */
#define TIMER_IS_ON_LIST(tp) ((tp)->t_flags & TF_TIMER_ONLIST)


void	add_to_time_wait_locked(struct tcpcb *tp, uint32_t delay);
void	add_to_time_wait(struct tcpcb *tp, uint32_t delay) ;

static void tcp_garbage_collect(struct inpcb *, int);

void	add_to_time_wait_locked(struct tcpcb *tp, uint32_t delay) 
{
	int		tw_slot;
	struct inpcbinfo *pcbinfo	= &tcbinfo;
	uint32_t timer;

	/* pcb list should be locked when we get here */	
	lck_rw_assert(pcbinfo->mtx, LCK_RW_ASSERT_EXCLUSIVE);

	LIST_REMOVE(tp->t_inpcb, inp_list);

	/* if (tp->t_timer[TCPT_2MSL] <= 0) 
	    tp->t_timer[TCPT_2MSL] = 1; */

	/*
	 * Because we're pulling this pcb out of the main TCP pcb list,
	 * we need to recalculate the TCPT_2MSL timer value for tcp_slowtimo
	 * higher timer granularity.
	 */

	timer = (delay / TCP_RETRANSHZ) * PR_SLOWHZ;
	tp->t_rcvtime = (tp->t_rcvtime / TCP_RETRANSHZ) * PR_SLOWHZ;

	tp->t_rcvtime += timer & (N_TIME_WAIT_SLOTS - 1); 

	tw_slot = (timer & (N_TIME_WAIT_SLOTS - 1)) + cur_tw_slot; 
	if (tw_slot >= N_TIME_WAIT_SLOTS)
	    tw_slot -= N_TIME_WAIT_SLOTS;

	LIST_INSERT_HEAD(&time_wait_slots[tw_slot], tp->t_inpcb, inp_list);
}

void	add_to_time_wait(struct tcpcb *tp, uint32_t delay) 
{
    	struct inpcbinfo *pcbinfo		= &tcbinfo;
	
	if (!lck_rw_try_lock_exclusive(pcbinfo->mtx)) {
		tcp_unlock(tp->t_inpcb->inp_socket, 0, 0);
		lck_rw_lock_exclusive(pcbinfo->mtx);
		tcp_lock(tp->t_inpcb->inp_socket, 0, 0);
	}
	add_to_time_wait_locked(tp, delay);
	lck_rw_done(pcbinfo->mtx);
}

static void
tcp_garbage_collect(struct inpcb *inp, int istimewait)
{
	struct socket *so;
	struct tcpcb *tp;

	so = inp->inp_socket;
	tp = intotcpcb(inp);

	/*
	 * Skip if still in use or busy; it would have been more efficient
	 * if we were to test so_usecount against 0, but this isn't possible
	 * due to the current implementation of tcp_dropdropablreq() where
	 * overflow sockets that are eligible for garbage collection have
	 * their usecounts set to 1.
	 */
	if (so->so_usecount > 1 || !lck_mtx_try_lock_spin(&inp->inpcb_mtx))
		return;

	/* Check again under the lock */
	if (so->so_usecount > 1) {
		lck_mtx_unlock(&inp->inpcb_mtx);
		return;
	}

	/*
	 * Overflowed socket dropped from the listening queue?  Do this
	 * only if we are called to clean up the time wait slots, since
	 * tcp_dropdropablreq() considers a socket to have been fully
	 * dropped after add_to_time_wait() is finished.
	 * Also handle the case of connections getting closed by the peer while in the queue as
	 * seen with rdar://6422317
	 * 
	 */
	if (so->so_usecount == 1 && 
	    ((istimewait && (so->so_flags & SOF_OVERFLOW)) ||
	    ((tp != NULL) && (tp->t_state == TCPS_CLOSED) && (so->so_head != NULL)
	    	 && ((so->so_state & (SS_INCOMP|SS_CANTSENDMORE|SS_CANTRCVMORE)) ==
			 (SS_INCOMP|SS_CANTSENDMORE|SS_CANTRCVMORE))))) {

		if (inp->inp_state != INPCB_STATE_DEAD) {
			/* Become a regular mutex */
			lck_mtx_convert_spin(&inp->inpcb_mtx);
#if INET6
			if (INP_CHECK_SOCKAF(so, AF_INET6))
				in6_pcbdetach(inp);
			else
#endif /* INET6 */
			in_pcbdetach(inp);
		}
		so->so_usecount--;
		lck_mtx_unlock(&inp->inpcb_mtx);
		return;
	} else if (inp->inp_wantcnt != WNT_STOPUSING) {
		lck_mtx_unlock(&inp->inpcb_mtx);
		return;
	}

	/*
	 * We get here because the PCB is no longer searchable (WNT_STOPUSING);
	 * detach (if needed) and dispose if it is dead (usecount is 0).  This
	 * covers all cases, including overflow sockets and those that are
	 * considered as "embryonic", i.e. created by sonewconn() in TCP input
	 * path, and have not yet been committed.  For the former, we reduce
	 * the usecount to 0 as done by the code above.  For the latter, the
	 * usecount would have reduced to 0 as part calling soabort() when the
	 * socket is dropped at the end of tcp_input().
	 */
	if (so->so_usecount == 0) {
		DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
			struct tcpcb *, tp, int32_t, TCPS_CLOSED);
		/* Become a regular mutex */
		lck_mtx_convert_spin(&inp->inpcb_mtx);
		
		/* If this tp still happens to be on the timer list, 
		 * take it out
		 */
		if (TIMER_IS_ON_LIST(tp)) {
			tcp_remove_timer(tp);
		}

		if (inp->inp_state != INPCB_STATE_DEAD) {
#if INET6
			if (INP_CHECK_SOCKAF(so, AF_INET6))
				in6_pcbdetach(inp);
			else
#endif /* INET6 */
			in_pcbdetach(inp);
		}
		in_pcbdispose(inp);
	} else {
		lck_mtx_unlock(&inp->inpcb_mtx);
	}
}

void
tcp_slowtimo(void)
{
	struct inpcb *inp, *nxt;
	struct tcpcb *tp;
#if TCPDEBUG
	int ostate;
#endif

#if  KDEBUG
	static int tws_checked = 0;
#endif

	struct inpcbinfo *pcbinfo		= &tcbinfo;

	KERNEL_DEBUG(DBG_FNC_TCP_SLOW | DBG_FUNC_START, 0,0,0,0,0);

	tcp_maxidle = tcp_keepcnt * tcp_keepintvl;

	/* Update tcp_now here as it may get used while processing the slow timer */
	calculate_tcp_clock();

	/* Garbage collect socket/tcpcb: We need to acquire the list lock 
	 * exclusively to do this
	 */

	if (lck_rw_try_lock_exclusive(pcbinfo->mtx) == FALSE) {
		if (tcp_gc_done == TRUE) {	/* don't sweat it this time. cleanup was done last time */
			tcp_gc_done = FALSE;
			KERNEL_DEBUG(DBG_FNC_TCP_SLOW | DBG_FUNC_END, tws_checked, cur_tw_slot,0,0,0);
			return; /* Upgrade failed and lost lock - give up this time. */
		}
		lck_rw_lock_exclusive(pcbinfo->mtx);	/* Upgrade failed, lost lock now take it again exclusive */
	}
	tcp_gc_done = TRUE;

	/*
	 * Process the items in the current time-wait slot
	 */
#if  KDEBUG
	tws_checked = 0;
#endif
	KERNEL_DEBUG(DBG_FNC_TCP_SLOW | DBG_FUNC_NONE, tws_checked,0,0,0,0);

    	LIST_FOREACH(inp, &time_wait_slots[cur_tw_slot], inp_list) {
#if KDEBUG
	        tws_checked++;
#endif

		if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) == WNT_STOPUSING) 
			continue;

		tcp_lock(inp->inp_socket, 1, 0);

		if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) 
			goto twunlock;

		tp = intotcpcb(inp);
		if (tp == NULL)  /* tp already closed, remove from list */
			goto twunlock;

		if (tp->t_timer[TCPT_2MSL] >= N_TIME_WAIT_SLOTS) {
		    tp->t_timer[TCPT_2MSL] -= N_TIME_WAIT_SLOTS;
		    tp->t_rcvtime += N_TIME_WAIT_SLOTS;
		}
		else
		    tp->t_timer[TCPT_2MSL] = 0;

		if (tp->t_timer[TCPT_2MSL] == 0)  {

			/* That pcb is ready for a close */	
			tcp_free_sackholes(tp);
			tp = tcp_close(tp);
		}
twunlock:
		tcp_unlock(inp->inp_socket, 1, 0);
	}


    	LIST_FOREACH_SAFE(inp, &tcb, inp_list, nxt) {
		tcp_garbage_collect(inp, 0);
	}

	/* Now cleanup the time wait ones */
    	LIST_FOREACH_SAFE(inp, &time_wait_slots[cur_tw_slot], inp_list, nxt) {
		tcp_garbage_collect(inp, 1);
	}

	if (++cur_tw_slot >= N_TIME_WAIT_SLOTS)
		cur_tw_slot = 0;
	
	lck_rw_done(pcbinfo->mtx);
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
	int optlen = 0;
	int idle_time = 0;

#if TCPDEBUG
	int ostate;
#endif

#if INET6
	int isipv6 = (tp->t_inpcb->inp_vflag & INP_IPV4) == 0;
#endif /* INET6 */

	so_tmp = tp->t_inpcb->inp_socket;
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
		    ((idle_time > 0) && (idle_time < tcp_maxidle))) {
			tp->t_timer[TCPT_2MSL] = OFFSET_FROM_START(tp, (u_int32_t)tcp_keepintvl);
		}
		else {
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
		tcp_free_sackholes(tp);
		/* Drop a connection in the retransmit timer
		 * 1. If we have retransmitted more than TCP_MAXRXTSHIFT times
		 * 2. If the time spent in this retransmission episode is more than
		 *    the time limit set with TCP_RXT_CONNDROPTIME socket option
		 * 3. If TCP_RXT_FINDROP socket option was set and we have already
		 *    retransmitted the FIN 3 times without receiving an ack
		 */
		if (++tp->t_rxtshift > TCP_MAXRXTSHIFT ||
			(tp->rxt_conndroptime > 0 && tp->rxt_start > 0 && 
			(tcp_now - tp->rxt_start) >= tp->rxt_conndroptime) ||
			((tp->t_flagsext & TF_RXTFINDROP) != 0 &&
			(tp->t_flags & TF_SENTFIN) != 0 &&
			tp->t_rxtshift >= 4)) {

			if ((tp->t_flagsext & TF_RXTFINDROP) != 0) {
				tcpstat.tcps_rxtfindrop++;
			} else {
				tcpstat.tcps_timeoutdrop++;
			}
			tp->t_rxtshift = TCP_MAXRXTSHIFT;
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
			tp->snd_recover_prev = tp->snd_recover;
			if (IN_FASTRECOVERY(tp))
				  tp->t_flags |= TF_WASFRECOVERY;
			else
				  tp->t_flags &= ~TF_WASFRECOVERY;
			tp->t_badrxtwin = tcp_now  + (tp->t_srtt >> (TCP_RTT_SHIFT)); 

			/* Set the time at which retransmission on this 
			 * connection started
			 */
			tp->rxt_start = tcp_now;
		}
		tcpstat.tcps_rexmttimeo++;
		if (tp->t_state == TCPS_SYN_SENT)
			rexmt = TCP_REXMTVAL(tp) * tcp_syn_backoff[tp->t_rxtshift];
		else
			rexmt = TCP_REXMTVAL(tp) * tcp_backoff[tp->t_rxtshift];
		TCPT_RANGESET(tp->t_rxtcur, rexmt,
			tp->t_rttmin, TCPTV_REXMTMAX, 
			TCP_ADD_REXMTSLOP(tp));
		tp->t_timer[TCPT_REXMT] = OFFSET_FROM_START(tp, tp->t_rxtcur);

		/*
		 * Check for potential Path MTU Discovery Black Hole 
		 */

		if (tcp_pmtud_black_hole_detect && (tp->t_state == TCPS_ESTABLISHED)) {
			if (((tp->t_flags & (TF_PMTUD|TF_MAXSEGSNT)) == (TF_PMTUD|TF_MAXSEGSNT)) && (tp->t_rxtshift == 2)) {
				/* 
				 * Enter Path MTU Black-hole Detection mechanism:
				 * - Disable Path MTU Discovery (IP "DF" bit).
				 * - Reduce MTU to lower value than what we negociated with peer.
				 */

				tp->t_flags &= ~TF_PMTUD; /* Disable Path MTU Discovery for now */
				tp->t_flags |= TF_BLACKHOLE; /* Record that we may have found a black hole */
				optlen = tp->t_maxopd - tp->t_maxseg;
				tp->t_pmtud_saved_maxopd = tp->t_maxopd; /* Keep track of previous MSS */
				if (tp->t_maxopd > tcp_pmtud_black_hole_mss)
					tp->t_maxopd = tcp_pmtud_black_hole_mss; /* Reduce the MSS to intermediary value */
				else {
					tp->t_maxopd = 	/* use the default MSS */
#if INET6
						isipv6 ? tcp_v6mssdflt :
#endif /* INET6 */
							tcp_mssdflt;
				}
				tp->t_maxseg = tp->t_maxopd - optlen;

				/*
	 			 * Reset the slow-start flight size as it may depends on the new MSS
	 			 */
				if (CC_ALGO(tp)->cwnd_init != NULL)
					CC_ALGO(tp)->cwnd_init(tp);
			}
			/*
			 * If further retransmissions are still unsuccessful with a lowered MTU,
			 * maybe this isn't a Black Hole and we restore the previous MSS and
			 * blackhole detection flags.
			 */
			else {
	
				if ((tp->t_flags & TF_BLACKHOLE) && (tp->t_rxtshift > 4)) {
					tp->t_flags |= TF_PMTUD; 
					tp->t_flags &= ~TF_BLACKHOLE; 
					optlen = tp->t_maxopd - tp->t_maxseg;
					tp->t_maxopd = tp->t_pmtud_saved_maxopd;
					tp->t_maxseg = tp->t_maxopd - optlen;
					/*
	 			 	* Reset the slow-start flight size as it may depends on the new MSS
	 			 	*/
					if (CC_ALGO(tp)->cwnd_init != NULL)
						CC_ALGO(tp)->cwnd_init(tp);
				}
			}
		}


		/*
		 * Disable rfc1323 and rfc1644 if we haven't got any response to
		 * our SYN (after we reach the threshold) to work-around some
		 * broken terminal servers (most of which have hopefully been
		 * retired) that have bad VJ header compression code which
		 * trashes TCP segments containing unknown-to-them TCP options.
		 */
		if ((tp->t_state == TCPS_SYN_SENT) &&
		    (tp->t_rxtshift == tcp_broken_peer_syn_rxmit_thres))
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

		if (CC_ALGO(tp)->after_timeout != NULL)
			CC_ALGO(tp)->after_timeout(tp);

		tp->t_dupacks = 0;
		EXIT_FASTRECOVERY(tp);

		DTRACE_TCP5(cc, void, NULL, struct inpcb *, tp->t_inpcb,
			struct tcpcb *, tp, struct tcphdr *, NULL,
			int32_t, TCP_CC_REXMT_TIMEOUT);

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
		    ((tp->t_persist_stop != 0) && (tp->t_persist_stop <= tcp_now))) {
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
		    (tp->t_state <= TCPS_CLOSING || tp->t_state == TCPS_FIN_WAIT_2)) {
		    	if (idle_time >= TCP_KEEPIDLE(tp) + (u_int32_t)tcp_maxidle)
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
				unsigned int ifscope, nocell = 0;

				if (tp->t_inpcb->inp_flags & INP_BOUND_IF)
					ifscope = tp->t_inpcb->inp_boundif;
				else
					ifscope = IFSCOPE_NONE;

				/*
				 * If the socket isn't allowed to use the
				 * cellular interface, indicate it as such.
				 */
				if (tp->t_inpcb->inp_flags & INP_NO_IFT_CELLULAR)
					nocell = 1;

				tcp_respond(tp, t_template->tt_ipgen,
				    &t_template->tt_t, (struct mbuf *)NULL,
				    tp->rcv_nxt, tp->snd_una - 1, 0, ifscope,
				    nocell);
				(void) m_free(dtom(t_template));
			}
			tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(tp, tcp_keepintvl);
		} else
			tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(tp, TCP_KEEPIDLE(tp));
		break;
	case TCPT_DELACK:
		if (tcp_delack_enabled && (tp->t_flags & TF_DELACK)) {
			tp->t_flags &= ~TF_DELACK;
			tp->t_timer[TCPT_DELACK] = 0;
			tp->t_flags |= TF_ACKNOW;

			/* If delayed ack timer fired while we are stretching acks, 
			 * go back to acking every other packet
			 */
			if ((tp->t_flags & TF_STRETCHACK) != 0)
				tcp_reset_stretch_ack(tp);

			tcpstat.tcps_delack++;
			(void) tcp_output(tp);
		}
		break;

#if TCPDEBUG
	if (tp->t_inpcb->inp_socket->so_options & SO_DEBUG)
		tcp_trace(TA_USER, ostate, tp, (void *)0, (struct tcphdr *)0,
			  PRU_SLOWTIMO);
#endif
	dropit:
		tcpstat.tcps_keepdrops++;
		tp = tcp_drop(tp, ETIMEDOUT);
		postevent(so_tmp, 0, EV_TIMEOUT);
		break;
	}
	return (tp);
}

/* Remove a timer entry from timer list */
void
tcp_remove_timer(struct tcpcb *tp)
{
	struct tcptimerlist *listp = &tcp_timer_list;

	lck_mtx_assert(&tp->t_inpcb->inpcb_mtx, LCK_MTX_ASSERT_OWNED);
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

/* Function to check if the timerlist needs to be rescheduled to run
 * the timer entry correctly. Basically, this is to check if we can avoid
 * taking the list lock.
 */

static boolean_t
need_to_resched_timerlist(uint32_t runtime, uint16_t index) {
	struct tcptimerlist *listp = &tcp_timer_list;
	int32_t diff;
	boolean_t is_fast;

	if (runtime == 0 || index == TCPT_NONE)
		return FALSE;
	is_fast = !(IS_TIMER_SLOW(index));

	/* If the list is being processed then the state of the list is in flux.
	 * In this case always acquire the lock and set the state correctly.
	 */
	if (listp->running) {
		return TRUE;
	}

	diff = timer_diff(listp->runtime, 0, runtime, 0);
	if (diff <= 0) {
		/* The list is going to run before this timer */
		return FALSE;
	} else {
		if (is_fast) {
			if (diff <= listp->fast_quantum)
				return FALSE;
		} else {
			if (diff <= listp->slow_quantum)
				return FALSE;
		}
	}
	return TRUE;
}

void
tcp_sched_timerlist(uint32_t offset) 
{

	uint64_t deadline = 0;
	struct tcptimerlist *listp = &tcp_timer_list;

	lck_mtx_assert(listp->mtx, LCK_MTX_ASSERT_OWNED);

	listp->runtime = tcp_now + offset;

	clock_interval_to_deadline(offset, NSEC_PER_SEC / TCP_RETRANSHZ,
		&deadline);

	thread_call_enter_delayed(listp->call, deadline);
}

/* Function to run the timers for a connection.
 *
 * Returns the offset of next timer to be run for this connection which 
 * can be used to reschedule the timerlist.
 */
uint32_t
tcp_run_conn_timer(struct tcpcb *tp, uint16_t *next_index) {

        struct socket *so;
        uint16_t i = 0, index = TCPT_NONE, lo_index = TCPT_NONE;
        uint32_t timer_val, offset = 0, lo_timer = 0;
	int32_t diff;
	boolean_t needtorun[TCPT_NTIMERS];
	int count = 0;

        VERIFY(tp != NULL);
        bzero(needtorun, sizeof(needtorun));

        tcp_lock(tp->t_inpcb->inp_socket, 1, 0);

        so = tp->t_inpcb->inp_socket;
	/* Release the want count on inp */ 
	if (in_pcb_checkstate(tp->t_inpcb, WNT_RELEASE, 1) == WNT_STOPUSING) {
		if (TIMER_IS_ON_LIST(tp)) {
			tcp_remove_timer(tp);
		}

		/* Looks like the TCP connection got closed while we 
		 * were waiting for the lock.. Done
		 */
		goto done;
	}

        /* Since the timer thread needs to wait for tcp lock, it may race
         * with another thread that can cancel or reschedule the timer that is
         * about to run. Check if we need to run anything.
         */
	index = tp->tentry.index;
	timer_val = tp->t_timer[index];

        if (index == TCPT_NONE || tp->tentry.runtime == 0) 
		goto done;

	diff = timer_diff(tp->tentry.runtime, 0, tcp_now, 0);
	if (diff > 0) {
		if (tp->tentry.index != TCPT_NONE) {
			offset = diff;
			*(next_index) = tp->tentry.index;
		}
		goto done;
	}

	tp->t_timer[index] = 0;
	if (timer_val > 0) {
		tp = tcp_timers(tp, index);
		if (tp == NULL) 
			goto done;
	}
	
	/* Check if there are any other timers that need to be run. While doing it,
	 * adjust the timer values wrt tcp_now.
	 */
	for (i = 0; i < TCPT_NTIMERS; ++i) {
		if (tp->t_timer[i] != 0) {
			diff = timer_diff(tp->tentry.timer_start, tp->t_timer[i], tcp_now, 0);
			if (diff <= 0) {
				tp->t_timer[i] = 0;
				needtorun[i] = TRUE;
				count++;
			} else {
				tp->t_timer[i] = diff;
				needtorun[i] = FALSE;
				if (lo_timer == 0 || diff < lo_timer) {
					lo_timer = diff;
					lo_index = i;
				}
			}
		}
	}
	
	tp->tentry.timer_start = tcp_now;
	tp->tentry.index = lo_index;
	if (lo_index != TCPT_NONE) {
		tp->tentry.runtime = tp->tentry.timer_start + tp->t_timer[lo_index];
	} else {
		tp->tentry.runtime = 0;
	}

	if (count > 0) {
		/* run any other timers that are also outstanding at this time. */
		for (i = 0; i < TCPT_NTIMERS; ++i) {
			if (needtorun[i]) {
				tp->t_timer[i] = 0;
				tp = tcp_timers(tp, i);
				if (tp == NULL) 
					goto done;
			}
		}
		tcp_set_lotimer_index(tp);
	}

	if (tp->tentry.index < TCPT_NONE) {
		offset = tp->t_timer[tp->tentry.index];
		*(next_index) = tp->tentry.index;
	}

done:
	if (tp != NULL && tp->tentry.index == TCPT_NONE) {
		tcp_remove_timer(tp);
	}
        tcp_unlock(so, 1, 0);
        return offset;
}

void
tcp_run_timerlist(void * arg1, void * arg2) {

#pragma unused(arg1, arg2)
	
	struct tcptimerentry *te, *next_te;
	struct tcptimerlist *listp = &tcp_timer_list;
	struct tcpcb *tp;
	uint32_t next_timer = 0;
	uint16_t index = TCPT_NONE;
	boolean_t need_fast = FALSE;
	uint32_t active_count = 0;
	uint32_t mode = TCP_TIMERLIST_FASTMODE;

	calculate_tcp_clock();

	lck_mtx_lock(listp->mtx);

	listp->running = TRUE;
	
	LIST_FOREACH_SAFE(te, &listp->lhead, le, next_te) {
		uint32_t offset = 0;
		uint32_t runtime = te->runtime;
		if (TSTMP_GT(runtime, tcp_now)) {
			offset = timer_diff(runtime, 0, tcp_now, 0);
			if (next_timer == 0 || offset < next_timer) {
				next_timer = offset;
			}
			continue;
		}
		active_count++;

		tp = TIMERENTRY_TO_TP(te);

		/* Acquire an inp wantcnt on the inpcb so that the socket won't get
		 * detached even if tcp_close is called
		 */
		if (in_pcb_checkstate(tp->t_inpcb, WNT_ACQUIRE, 0) == WNT_STOPUSING) {
			/* Some how this pcb went into dead state while on the timer list,
			 * just take it off the list. Since the timer list entry pointers 
			 * are protected by the timer list lock, we can do it here
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

		/* Store the next timerentry pointer before releasing the list lock.
		 * If that entry has to be removed when we release the lock, this
		 * pointer will be updated to the element after that.
		 */
		listp->next_te = next_te; 

		VERIFY_NEXT_LINK(&tp->tentry, le);
		VERIFY_PREV_LINK(&tp->tentry, le);

		lck_mtx_unlock(listp->mtx);

		index = TCPT_NONE;
		offset = tcp_run_conn_timer(tp, &index);
		
		lck_mtx_lock(listp->mtx);

		next_te = listp->next_te;
		listp->next_te = NULL;

		if (offset > 0) {
			if (index < TCPT_NONE) {
				/* Check if this is a fast_timer. */
				if (!need_fast && !(IS_TIMER_SLOW(index))) {
					need_fast = TRUE;
				}

				if (next_timer == 0 || offset < next_timer) {
					next_timer = offset;
				}
			}
		}
	}

	if (!LIST_EMPTY(&listp->lhead)) {
		if (listp->mode == TCP_TIMERLIST_FASTMODE) {
			if (need_fast || active_count > 0 || 
				listp->pref_mode == TCP_TIMERLIST_FASTMODE) {
				listp->idlegen = 0;
			} else {
				listp->idlegen++;
				if (listp->idlegen > timer_fastmode_idlemax) {
					mode = TCP_TIMERLIST_SLOWMODE;
					listp->idlegen = 0;
				}
			}
		} else {
			if (!need_fast) {
				mode = TCP_TIMERLIST_SLOWMODE;
			}
		}

		if (mode == TCP_TIMERLIST_FASTMODE || 
			listp->pref_mode == TCP_TIMERLIST_FASTMODE) {
			next_timer = listp->fast_quantum;
		} else {
			if (listp->pref_offset != 0 && 
				listp->pref_offset < next_timer)
				next_timer = listp->pref_offset;
			if (next_timer < listp->slow_quantum)
				next_timer = listp->slow_quantum;
		}

		listp->mode = mode;

		tcp_sched_timerlist(next_timer);
	} else {
		/* No need to reschedule this timer */
		listp->runtime = 0;
	}

	listp->running = FALSE;
	listp->pref_mode = 0;
	listp->pref_offset = 0;

	lck_mtx_unlock(listp->mtx);
}

/* Function to verify if a change in timer state is required for a connection */
void 
tcp_sched_timers(struct tcpcb *tp) 
{
	struct tcptimerentry *te = &tp->tentry;
	uint16_t index = te->index;
	struct tcptimerlist *listp = &tcp_timer_list;
	uint32_t offset = 0;
	boolean_t is_fast;
	int list_locked = 0;

	if (tp->t_inpcb->inp_state == INPCB_STATE_DEAD) {
		/* Just return without adding the dead pcb to the list */
		if (TIMER_IS_ON_LIST(tp)) {
			tcp_remove_timer(tp);
		}
		return;
	}

	if (index == TCPT_NONE) {
		tcp_remove_timer(tp);
		return;
	}

	is_fast = !(IS_TIMER_SLOW(index));
	offset = te->runtime - tcp_now;
	if (offset == 0) {
		offset = 1;
		tcp_timer_advanced++;
	}
	if (is_fast)
		offset = listp->fast_quantum;

	if (!TIMER_IS_ON_LIST(tp)) {
		if (!list_locked) {
			lck_mtx_lock(listp->mtx);
			list_locked = 1;
		}

		LIST_INSERT_HEAD(&listp->lhead, te, le);
		tp->t_flags |= TF_TIMER_ONLIST;

        	listp->entries++;
        	if (listp->entries > listp->maxentries)
                	listp->maxentries = listp->entries;

		/* if the list is not scheduled, just schedule it */
		if (listp->runtime == 0)
			goto schedule;

	}


	/* timer entry is currently on the list */
	if (need_to_resched_timerlist(te->runtime, index)) {
		tcp_resched_timerlist++;
	
		if (!list_locked) {
			lck_mtx_lock(listp->mtx);
			list_locked = 1;
		}

		VERIFY_NEXT_LINK(te, le);
		VERIFY_PREV_LINK(te, le);

		if (listp->running) {
			if (is_fast) {
				listp->pref_mode = TCP_TIMERLIST_FASTMODE;
			} else if (listp->pref_offset == 0 ||
				((int)offset) < listp->pref_offset) {
				listp->pref_offset = offset;
			}
		} else {
			int32_t diff;
			diff = timer_diff(listp->runtime, 0, tcp_now, offset);
			if (diff <= 0) {
				/* The list is going to run before this timer */
				goto done;
			} else {
				goto schedule;
			}
		}
	}
	goto done;

schedule:
	if (is_fast) {
		listp->mode = TCP_TIMERLIST_FASTMODE;
		listp->idlegen = 0;
	}
	tcp_sched_timerlist(offset);

done:
	if (list_locked)
		lck_mtx_unlock(listp->mtx);

	return;
}
		
void
tcp_set_lotimer_index(struct tcpcb *tp) {
	uint16_t i, lo_index = TCPT_NONE;
	uint32_t lo_timer = 0;
	for (i = 0; i < TCPT_NTIMERS; ++i) {
		if (tp->t_timer[i] != 0 &&
			(lo_timer == 0 || tp->t_timer[i] < lo_timer)) {
			lo_timer = tp->t_timer[i];
			lo_index = i;
		}
	}
	tp->tentry.index = lo_index;
	if (lo_index != TCPT_NONE) {
		tp->tentry.runtime = tp->tentry.timer_start + tp->t_timer[lo_index];
	} else {
		tp->tentry.runtime = 0;
	}
}

void
tcp_check_timer_state(struct tcpcb *tp) {

	lck_mtx_assert(&tp->t_inpcb->inpcb_mtx, LCK_MTX_ASSERT_OWNED);

	tcp_set_lotimer_index(tp);

	tcp_sched_timers(tp);
	return;
}
