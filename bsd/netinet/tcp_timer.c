/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
#if INET6
#include <netinet6/tcp6_var.h>
#endif
#include <netinet/tcpip.h>
#if TCPDEBUG
#include <netinet/tcp_debug.h>
#endif
#include <sys/kdebug.h>

extern void postevent(struct socket *, struct sockbuf *,
                                               int);
#define DBG_FNC_TCP_FAST	NETDBG_CODE(DBG_NETTCP, (5 << 8))
#define DBG_FNC_TCP_SLOW	NETDBG_CODE(DBG_NETTCP, (5 << 8) | 1)

static int 	background_io_trigger = 5;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, background_io_trigger, CTLFLAG_RW,
    &background_io_trigger, 0, "Background IO Trigger Setting");

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
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPINIT, keepinit, CTLTYPE_INT|CTLFLAG_RW,
    &tcp_keepinit, 0, sysctl_msec_to_ticks, "I", "");

int	tcp_keepidle;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPIDLE, keepidle, CTLTYPE_INT|CTLFLAG_RW,
    &tcp_keepidle, 0, sysctl_msec_to_ticks, "I", "");

int	tcp_keepintvl;
SYSCTL_PROC(_net_inet_tcp, TCPCTL_KEEPINTVL, keepintvl, CTLTYPE_INT|CTLFLAG_RW,
    &tcp_keepintvl, 0, sysctl_msec_to_ticks, "I", "");

int	tcp_msl;
SYSCTL_PROC(_net_inet_tcp, OID_AUTO, msl, CTLTYPE_INT|CTLFLAG_RW,
    &tcp_msl, 0, sysctl_msec_to_ticks, "I", "Maximum segment lifetime");

static int	always_keepalive = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, always_keepalive, CTLFLAG_RW, 
    &always_keepalive , 0, "Assume SO_KEEPALIVE on all TCP connections");

/*
 * See tcp_syn_backoff[] for interval values between SYN retransmits;
 * the value set below defines the number of retransmits, before we
 * disable the timestamp and window scaling options during subsequent
 * SYN retransmits.  Setting it to 0 disables the dropping off of those
 * two options.
 */
static int tcp_broken_peer_syn_rxmit_thres = 7;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, broken_peer_syn_rxmit_thres, CTLFLAG_RW,
    &tcp_broken_peer_syn_rxmit_thres, 0, "Number of retransmitted SYNs before "
    "TCP disables rfc1323 and rfc1644 during the rest of attempts");

int	tcp_pmtud_black_hole_detect = 1 ;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, pmtud_blackhole_detection, CTLFLAG_RW,
    &tcp_pmtud_black_hole_detect, 0, "Path MTU Discovery Black Hole Detection");

int	tcp_pmtud_black_hole_mss = 1200 ;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, pmtud_blackhole_mss, CTLFLAG_RW,
    &tcp_pmtud_black_hole_mss, 0, "Path MTU Discovery Black Hole Detection lowered MSS");

static int	tcp_keepcnt = TCPTV_KEEPCNT;
static int	tcp_gc_done = FALSE;	/* perfromed garbage collection of "used" sockets */
	/* max idle probes */
int	tcp_maxpersistidle;
	/* max idle time in persist */
int	tcp_maxidle;

struct	inpcbhead	time_wait_slots[N_TIME_WAIT_SLOTS];
int		cur_tw_slot = 0;

u_int32_t		*delack_bitmask;

void	add_to_time_wait_locked(struct tcpcb *tp);
void	add_to_time_wait(struct tcpcb *tp) ;

static void tcp_garbage_collect(struct inpcb *, int);

void	add_to_time_wait_locked(struct tcpcb *tp) 
{
	int		tw_slot;
    struct inpcbinfo *pcbinfo	= &tcbinfo;

	/* pcb list should be locked when we get here */	
	lck_rw_assert(pcbinfo->mtx, LCK_RW_ASSERT_EXCLUSIVE);

	LIST_REMOVE(tp->t_inpcb, inp_list);

	if (tp->t_timer[TCPT_2MSL] <= 0) 
	    tp->t_timer[TCPT_2MSL] = 1;

	/*
	 * Because we're pulling this pcb out of the main TCP pcb list,
	 * we need to recalculate the TCPT_2MSL timer value for tcp_slowtimo
	 * higher timer granularity.
	 */

	tp->t_timer[TCPT_2MSL] = (tp->t_timer[TCPT_2MSL] / TCP_RETRANSHZ) * PR_SLOWHZ;
	tp->t_rcvtime = (tp->t_rcvtime / TCP_RETRANSHZ) * PR_SLOWHZ;

	tp->t_rcvtime += tp->t_timer[TCPT_2MSL] & (N_TIME_WAIT_SLOTS - 1); 

	tw_slot = (tp->t_timer[TCPT_2MSL] & (N_TIME_WAIT_SLOTS - 1)) + cur_tw_slot; 
	if (tw_slot >= N_TIME_WAIT_SLOTS)
	    tw_slot -= N_TIME_WAIT_SLOTS;

	LIST_INSERT_HEAD(&time_wait_slots[tw_slot], tp->t_inpcb, inp_list);
}

void	add_to_time_wait(struct tcpcb *tp) 
{
    	struct inpcbinfo *pcbinfo		= &tcbinfo;
	
	if (!lck_rw_try_lock_exclusive(pcbinfo->mtx)) {
		tcp_unlock(tp->t_inpcb->inp_socket, 0, 0);
		lck_rw_lock_exclusive(pcbinfo->mtx);
		tcp_lock(tp->t_inpcb->inp_socket, 0, 0);
	}
	add_to_time_wait_locked(tp);
	lck_rw_done(pcbinfo->mtx);
}




/*
 * Fast timeout routine for processing delayed acks
 */
void
tcp_fasttimo(void *arg)
{
#pragma unused(arg)
    struct inpcb *inp;
    register struct tcpcb *tp;
    struct socket *so;
#if TCPDEBUG
    int ostate;
#endif


    struct inpcbinfo *pcbinfo	= &tcbinfo;

    int delack_done = 0;

    KERNEL_DEBUG(DBG_FNC_TCP_FAST | DBG_FUNC_START, 0,0,0,0,0);


    lck_rw_lock_shared(pcbinfo->mtx);

    /* Walk the list of valid tcpcbs and send ACKS on the ones with DELACK bit set */

    LIST_FOREACH(inp, &tcb, inp_list) {

	so = inp->inp_socket;

	if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) == WNT_STOPUSING) 
		continue;

	tcp_lock(so, 1, 0);

	if ((in_pcb_checkstate(inp, WNT_RELEASE,1) == WNT_STOPUSING)  && so->so_usecount == 1) {
		tcp_unlock(so, 1, 0);
		continue;
	}

	tp = intotcpcb(inp);

	if (tp == 0 || tp->t_state == TCPS_LISTEN) {
		tcp_unlock(so, 1, 0);
		continue; 
	}


	/* Only run the retransmit timer in that case */
	if (tp->t_timer[0] && --tp->t_timer[0] == 0) {
		tp = tcp_timers(tp, 0);
		if (tp == NULL)
			goto tpgone;
	}

	/* TCP pcb  timers following the tcp_now clock rate */

	tp->t_rcvtime++;
	tp->t_starttime++;
	if (tp->t_rtttime)
		tp->t_rtttime++;	

	/*
	 * Process delayed acks (if enabled) according to PR_FASTHZ, not the retrans timer
	 */

	if (tcp_delack_enabled && (tcp_now % (TCP_RETRANSHZ/PR_FASTHZ)) && tp->t_flags & TF_DELACK) {
		delack_done++;
		tp->t_flags &= ~TF_DELACK;
		tp->t_flags |= TF_ACKNOW;
		tcpstat.tcps_delack++;
		tp->t_unacksegs = 0;
		(void) tcp_output(tp);
	}
tpgone:
	tcp_unlock(so, 1, 0);
    }
    KERNEL_DEBUG(DBG_FNC_TCP_FAST | DBG_FUNC_END, delack_done, 0, tcpstat.tcps_delack,0,0);
    lck_rw_done(pcbinfo->mtx);

    tcp_now++;
    timeout(tcp_fasttimo, 0, hz/TCP_RETRANSHZ);
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
	if (so->so_usecount > 1 || !lck_mtx_try_lock_spin(inp->inpcb_mtx))
		return;

	/* Check again under the lock */
	if (so->so_usecount > 1) {
		lck_mtx_unlock(inp->inpcb_mtx);
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
			lck_mtx_convert_spin(inp->inpcb_mtx);
#if INET6
			if (INP_CHECK_SOCKAF(so, AF_INET6))
				in6_pcbdetach(inp);
			else
#endif /* INET6 */
			in_pcbdetach(inp);
		}
		so->so_usecount--;
		lck_mtx_unlock(inp->inpcb_mtx);
		return;
	} else if (inp->inp_wantcnt != WNT_STOPUSING) {
		lck_mtx_unlock(inp->inpcb_mtx);
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
		/* Become a regular mutex */
		lck_mtx_convert_spin(inp->inpcb_mtx);
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
		lck_mtx_unlock(inp->inpcb_mtx);
	}
}

static int bg_cnt = 0;
#define BG_COUNTER_MAX 3

void
tcp_slowtimo(void)
{
	struct inpcb *inp, *nxt;
	struct tcpcb *tp;
	struct socket *so;
	int i;
#if TCPDEBUG
	int ostate;
#endif

#if  KDEBUG
	static int tws_checked = 0;
#endif

	struct inpcbinfo *pcbinfo		= &tcbinfo;

	KERNEL_DEBUG(DBG_FNC_TCP_SLOW | DBG_FUNC_START, 0,0,0,0,0);

	tcp_maxidle = tcp_keepcnt * tcp_keepintvl;

	lck_rw_lock_shared(pcbinfo->mtx);

	bg_cnt++;

    	LIST_FOREACH(inp, &tcb, inp_list) {

		so = inp->inp_socket;

		if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) == WNT_STOPUSING) 
			continue;

		tcp_lock(so, 1, 0);

		if ((in_pcb_checkstate(inp, WNT_RELEASE,1) == WNT_STOPUSING)  && so->so_usecount == 1) {
			tcp_unlock(so, 1, 0);
			continue;
		}
		tp = intotcpcb(inp);
		if (tp == 0 || tp->t_state == TCPS_LISTEN) {
			tcp_unlock(so, 1, 0);
			continue; 
		}

		tp = intotcpcb(inp);

		if (tp == 0 || tp->t_state == TCPS_LISTEN) 
			goto tpgone;

#if TRAFFIC_MGT
	        if (so->so_traffic_mgt_flags & TRAFFIC_MGT_SO_BG_REGULATE && 
	        	bg_cnt > BG_COUNTER_MAX) {
			u_int32_t	curr_recvtotal = tcpstat.tcps_rcvtotal;
			u_int32_t	curr_bg_recvtotal = tcpstat.tcps_bg_rcvtotal;
			u_int32_t	bg_recvdiff = curr_bg_recvtotal - tp->bg_recv_snapshot;
			u_int32_t	tot_recvdiff = curr_recvtotal - tp->tot_recv_snapshot;
			u_int32_t	fg_recv_change = tot_recvdiff - bg_recvdiff;
			u_int32_t	recv_change;
			
			if (!(so->so_traffic_mgt_flags & TRAFFIC_MGT_SO_BG_SUPPRESSED)) {
				if (tot_recvdiff) 
					recv_change = (fg_recv_change * 100) / tot_recvdiff;
				else 
					recv_change = 0;

				if (recv_change > background_io_trigger) {
					socket_set_traffic_mgt_flags(so, TRAFFIC_MGT_SO_BG_SUPPRESSED);
				}
				
				tp->tot_recv_snapshot = curr_recvtotal;
				tp->bg_recv_snapshot = curr_bg_recvtotal;
			}
			else {	// SUPPRESSED
				// this allows for bg traffic to subside before we start measuring total traffic change
				if (tot_recvdiff)
					recv_change = (bg_recvdiff * 100) / tot_recvdiff;
				else
					recv_change = 0;
					
				if (recv_change < background_io_trigger) {
					// Draconian for now: if there is any change at all, keep suppressed
					if (!tot_recvdiff) {
						socket_clear_traffic_mgt_flags(so, TRAFFIC_MGT_SO_BG_SUPPRESSED);
						tp->t_unacksegs = 0;
						(void) tcp_output(tp);	// open window
					}
				}

				tp->tot_recv_snapshot = curr_recvtotal;
				tp->bg_recv_snapshot = curr_bg_recvtotal;
			}
		}
#endif /* TRAFFIC_MGT */

		for (i = 1; i < TCPT_NTIMERS; i++) {
			if (tp->t_timer[i] != 0) {
				tp->t_timer[i] -= TCP_RETRANSHZ/PR_SLOWHZ;
			       	if (tp->t_timer[i] <=  0) {
#if TCPDEBUG
					ostate = tp->t_state;
#endif

					tp->t_timer[i] = 0; /* account for granularity change between tcp_now and slowtimo */
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
		}
tpgone:
		tcp_unlock(so, 1, 0);
	}
	
	if (bg_cnt > 3) 
		bg_cnt = 0;

	/* Second part of tcp_slowtimo: garbage collect socket/tcpcb
	 * We need to acquire the list lock exclusively to do this
	 */

	if (lck_rw_lock_shared_to_exclusive(pcbinfo->mtx) == FALSE) {
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
	int optlen = 0;

#if TCPDEBUG
	int ostate;
#endif

#if INET6
	int isipv6 = (tp->t_inpcb->inp_vflag & INP_IPV4) == 0;
#endif /* INET6 */

	so_tmp = tp->t_inpcb->inp_socket;

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
		    tp->t_rcvtime < tcp_maxidle) {
			tp->t_timer[TCPT_2MSL] = (u_int32_t)tcp_keepintvl;
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
		if (++tp->t_rxtshift > TCP_MAXRXTSHIFT) {
			tp->t_rxtshift = TCP_MAXRXTSHIFT;
			tcpstat.tcps_timeoutdrop++;
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
			tp->t_unacksegs = 0;
		}
		EXIT_FASTRECOVERY(tp);
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
		tp->t_unacksegs = 0;
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
		    	if (tp->t_rcvtime >= TCP_KEEPIDLE(tp) + (u_int32_t)tcp_maxidle)
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
				unsigned int ifscope;

				if (tp->t_inpcb->inp_flags & INP_BOUND_IF)
					ifscope = tp->t_inpcb->inp_boundif;
				else
					ifscope = IFSCOPE_NONE;

				tcp_respond(tp, t_template->tt_ipgen,
				    &t_template->tt_t, (struct mbuf *)NULL,
				    tp->rcv_nxt, tp->snd_una - 1, 0, ifscope);
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
		tp = tcp_drop(tp, ETIMEDOUT);
		postevent(so_tmp, 0, EV_TIMEOUT);
		break;
	}
	return (tp);
}
