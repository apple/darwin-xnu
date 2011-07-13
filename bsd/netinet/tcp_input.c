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
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1994, 1995
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
 *	@(#)tcp_input.c	8.12 (Berkeley) 5/24/95
 * $FreeBSD: src/sys/netinet/tcp_input.c,v 1.107.2.16 2001/08/22 00:59:12 silby Exp $
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>		/* for proc0 declaration */
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>

#include <kern/cpu_number.h>	/* before tcp_seq.h, for tcp_random18() */

#include <machine/endian.h>

#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/ntstat.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>    /* for ICMP_BANDLIM		*/   
#include <netinet/in_var.h>
#include <netinet/icmp_var.h>	/* for ICMP_BANDLIM	*/
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <mach/sdt.h>
#if INET6
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/in6_pcb.h>
#endif
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_cc.h>
#include <kern/zalloc.h>
#if INET6
#include <netinet6/tcp6_var.h>
#endif
#include <netinet/tcpip.h>
#if TCPDEBUG
#include <netinet/tcp_debug.h>
u_char tcp_saveipgen[40]; /* the size must be of max ip header, now IPv6 */
struct tcphdr tcp_savetcp;
#endif /* TCPDEBUG */

#if IPSEC
#include <netinet6/ipsec.h>
#if INET6
#include <netinet6/ipsec6.h>
#endif
#include <netkey/key.h>
#endif /*IPSEC*/

#if CONFIG_MACF_NET || CONFIG_MACF_SOCKET
#include <security/mac_framework.h>
#endif /* CONFIG_MACF_NET || CONFIG_MACF_SOCKET */

#include <sys/kdebug.h>

#define DBG_LAYER_BEG		NETDBG_CODE(DBG_NETTCP, 0)
#define DBG_LAYER_END		NETDBG_CODE(DBG_NETTCP, 2)
#define DBG_FNC_TCP_INPUT       NETDBG_CODE(DBG_NETTCP, (3 << 8))
#define DBG_FNC_TCP_NEWCONN     NETDBG_CODE(DBG_NETTCP, (7 << 8))

static int	tcprexmtthresh = 2;
tcp_cc	tcp_ccgen;

#if IPSEC
extern int ipsec_bypass;
#endif

struct	tcpstat tcpstat;

static int log_in_vain = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, log_in_vain, CTLFLAG_RW | CTLFLAG_LOCKED,
    &log_in_vain, 0, "Log all incoming TCP connections");

static int blackhole = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, blackhole, CTLFLAG_RW | CTLFLAG_LOCKED,
	&blackhole, 0, "Do not send RST when dropping refused connections");

int tcp_delack_enabled = 3;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, delayed_ack, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_delack_enabled, 0, 
    "Delay ACK to try and piggyback it onto a data packet");

int tcp_lq_overflow = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, tcp_lq_overflow, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_lq_overflow, 0, 
    "Listen Queue Overflow");

int tcp_recv_bg = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, recvbg, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_recv_bg, 0, 
    "Receive background");

#if TCP_DROP_SYNFIN
static int drop_synfin = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, drop_synfin, CTLFLAG_RW | CTLFLAG_LOCKED,
    &drop_synfin, 0, "Drop TCP packets with SYN+FIN set");
#endif

SYSCTL_NODE(_net_inet_tcp, OID_AUTO, reass, CTLFLAG_RW|CTLFLAG_LOCKED, 0,
    "TCP Segment Reassembly Queue");

__private_extern__ int tcp_reass_maxseg = 0;
SYSCTL_INT(_net_inet_tcp_reass, OID_AUTO, maxsegments, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_reass_maxseg, 0,
    "Global maximum number of TCP Segments in Reassembly Queue");

__private_extern__ int tcp_reass_qsize = 0;
SYSCTL_INT(_net_inet_tcp_reass, OID_AUTO, cursegments, CTLFLAG_RD | CTLFLAG_LOCKED,
    &tcp_reass_qsize, 0,
    "Global number of TCP Segments currently in Reassembly Queue");

static int tcp_reass_overflows = 0;
SYSCTL_INT(_net_inet_tcp_reass, OID_AUTO, overflows, CTLFLAG_RD | CTLFLAG_LOCKED,
    &tcp_reass_overflows, 0,
    "Global number of TCP Segment Reassembly Queue Overflows");


__private_extern__ int slowlink_wsize = 8192;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, slowlink_wsize, CTLFLAG_RW | CTLFLAG_LOCKED,
	&slowlink_wsize, 0, "Maximum advertised window size for slowlink");

int maxseg_unacked = 8;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, maxseg_unacked, CTLFLAG_RW | CTLFLAG_LOCKED,
	&maxseg_unacked, 0, "Maximum number of outstanding segments left unacked");

int	tcp_do_rfc3465 = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, rfc3465, CTLFLAG_RW | CTLFLAG_LOCKED,
	&tcp_do_rfc3465, 0, "");

int	tcp_do_rfc3465_lim2 = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, rfc3465_lim2, CTLFLAG_RW | CTLFLAG_LOCKED,
	&tcp_do_rfc3465_lim2, 0, "Appropriate bytes counting w/ L=2*SMSS");

int	rtt_samples_per_slot = 20;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, rtt_samples_per_slot, CTLFLAG_RW | CTLFLAG_LOCKED,
	&rtt_samples_per_slot, 0, "Number of RTT samples stored for rtt history");

int	tcp_allowed_iaj = ALLOWED_IAJ;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, recv_allowed_iaj, CTLFLAG_RW | CTLFLAG_LOCKED,
        &tcp_allowed_iaj, 0, "Allowed inter-packet arrival jiter");

int	tcp_acc_iaj_high_thresh = ACC_IAJ_HIGH_THRESH;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, acc_iaj_high_thresh, CTLFLAG_RW | CTLFLAG_LOCKED,
        &tcp_acc_iaj_high_thresh, 0, "Used in calculating maximum accumulated IAJ");

#if CONFIG_IFEF_NOWINDOWSCALE
int tcp_obey_ifef_nowindowscale = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, obey_ifef_nowindowscale, CTLFLAG_RW | CTLFLAG_LOCKED,
	&tcp_obey_ifef_nowindowscale, 0, "");
#endif

extern int tcp_TCPTV_MIN;
extern int tcp_acc_iaj_high;
extern int tcp_acc_iaj_react_limit;
extern struct zone *tcp_reass_zone;


u_int32_t tcp_now;
struct timeval tcp_uptime;	/* uptime when tcp_now was last updated */
lck_spin_t *tcp_uptime_lock;	/* Used to sychronize updates to tcp_now */

struct inpcbhead tcb;
#define	tcb6	tcb  /* for KAME src sync over BSD*'s */
struct inpcbinfo tcbinfo;

static void tcp_dooptions(struct tcpcb *, u_char *, int, struct tcphdr *,
    struct tcpopt *, unsigned int);
static void	 tcp_pulloutofband(struct socket *,
	    struct tcphdr *, struct mbuf *, int);
static int	 tcp_reass(struct tcpcb *, struct tcphdr *, int *,
				struct mbuf *);
static void	tcp_xmit_timer(struct tcpcb *, int);
static inline unsigned int tcp_maxmtu(struct rtentry *);
static inline int tcp_stretch_ack_enable(struct tcpcb *tp);

#if TRAFFIC_MGT
static inline void update_iaj_state(struct tcpcb *tp, uint32_t tlen, int reset_size);
void compute_iaj(struct tcpcb *tp);
static inline void clear_iaj_state(struct tcpcb *tp);
#endif /* TRAFFIC_MGT */

#if INET6
static inline unsigned int tcp_maxmtu6(struct rtentry *);
#endif

/* Neighbor Discovery, Neighbor Unreachability Detection Upper layer hint. */
#if INET6
#define ND6_HINT(tp) \
do { \
	if ((tp) && (tp)->t_inpcb && \
	    ((tp)->t_inpcb->inp_vflag & INP_IPV6) != 0 && \
	    (tp)->t_inpcb->in6p_route.ro_rt) \
		nd6_nud_hint((tp)->t_inpcb->in6p_route.ro_rt, NULL, 0); \
} while (0)
#else
#define ND6_HINT(tp)
#endif

extern void	add_to_time_wait(struct tcpcb *, uint32_t delay);
extern void postevent(struct socket *, struct sockbuf *, int);

extern  void    ipfwsyslog( int level, const char *format,...);
extern int ChkAddressOK( __uint32_t dstaddr, __uint32_t srcaddr );
extern int fw_verbose;
__private_extern__ int tcp_sockthreshold;
__private_extern__ int tcp_win_scale;

#if IPFIREWALL
#define log_in_vain_log( a ) {            \
        if ( (log_in_vain == 3 ) && (fw_verbose == 2)) {        /* Apple logging, log to ipfw.log */ \
                ipfwsyslog a ;  \
        }                       \
        else log a ;            \
}
#else
#define log_in_vain_log( a ) { log a; }
#endif

int tcp_rcvunackwin = TCPTV_UNACKWIN;
int tcp_maxrcvidle = TCPTV_MAXRCVIDLE;
int tcp_rcvsspktcnt = TCP_RCV_SS_PKTCOUNT;

#define DELAY_ACK(tp, th) (CC_ALGO(tp)->delay_ack != NULL && CC_ALGO(tp)->delay_ack(tp, th))

static int tcp_dropdropablreq(struct socket *head);
static void tcp_newreno_partial_ack(struct tcpcb *tp, struct tcphdr *th);

static void update_base_rtt(struct tcpcb *tp, uint32_t rtt);
uint32_t get_base_rtt(struct tcpcb *tp);
void tcp_set_background_cc(struct socket *so);
void tcp_set_foreground_cc(struct socket *so);
static void tcp_set_new_cc(struct socket *so, uint16_t cc_index);

#if TRAFFIC_MGT
void
reset_acc_iaj(struct tcpcb *tp)
{
	tp->acc_iaj = 0;
	tp->iaj_rwintop = 0;
	clear_iaj_state(tp);
}

static inline void
update_iaj_state(struct tcpcb *tp, uint32_t size, int rst_size)
{
	if (rst_size > 0)
		tp->iaj_size = 0;
	if (tp->iaj_size == 0 || size >= tp->iaj_size) {
		tp->iaj_size = size;
		tp->iaj_rcv_ts = tcp_now;
		tp->iaj_small_pkt = 0;
	}
}

static inline void
clear_iaj_state(struct tcpcb *tp)
{
	tp->iaj_rcv_ts = 0;
}

/* For every 32 bit unsigned integer(v), this function will find the 
 * largest integer n such that (n*n <= v). This takes at most 16 iterations 
 * irrespective of the value of v and does not involve multiplications. 
 */
static inline int
isqrt(unsigned int val) {
	unsigned int sqrt_cache[11] = {0, 1, 4, 9, 16, 25, 36, 49, 64, 81, 100};
	unsigned int temp, g=0, b=0x8000, bshft=15;
	if ( val <= 100) {
		for (g = 0; g <= 10; ++g) {
			if (sqrt_cache[g] > val) {
				g--;
				break;
			} else if (sqrt_cache[g] == val) {
				break;
			}
		}
	} else {
		do {
			temp = (((g << 1) + b) << (bshft--));
			if (val >= temp) {
				g += b;
				val -= temp;
			}
			b >>= 1;
		} while ( b > 0 && val > 0);
	}
	return(g);
} 

void
compute_iaj(struct tcpcb *tp)
{
	/* When accumulated IAJ reaches MAX_ACC_IAJ in milliseconds, throttle the
	 * receive window to a minimum of MIN_IAJ_WIN packets
	 */
#define MAX_ACC_IAJ (tcp_acc_iaj_high_thresh + tcp_acc_iaj_react_limit)

	uint32_t allowed_iaj, acc_iaj = 0;
	uint32_t cur_iaj = tcp_now - tp->iaj_rcv_ts;

	uint32_t mean, temp;
	int32_t cur_iaj_dev;
	cur_iaj_dev = (cur_iaj - tp->avg_iaj);	
	
	/* Allow a jitter of "allowed_iaj" milliseconds. Some connections may have a
	 * constant jitter more than that. We detect this by using
	 * standard deviation.
	 */
	allowed_iaj = tp->avg_iaj + tp->std_dev_iaj;
	if (allowed_iaj < tcp_allowed_iaj)
		allowed_iaj = tcp_allowed_iaj;

	/* Initially when the connection starts, the senders congestion window 
	 * is small. During this period we avoid throttling a connection because
	 * we do not have a good starting point for allowed_iaj. IAJ_IGNORE_PKTCNT
	 * is used to quietly gloss over the first few packets.
	 */
	if (tp->iaj_pktcnt > IAJ_IGNORE_PKTCNT) {
		if ( cur_iaj <= allowed_iaj ) {
			if (tp->acc_iaj >= 2)
				acc_iaj = tp->acc_iaj - 2;
			else
				acc_iaj = 0;
		} else {
			acc_iaj = tp->acc_iaj + (cur_iaj - allowed_iaj);
		}

		if (acc_iaj > MAX_ACC_IAJ)
			acc_iaj = MAX_ACC_IAJ;
		tp->acc_iaj = acc_iaj;
	}

	/* Compute weighted average where the history has a weight of
	 * 15 out of 16 and the current value has a weight of 1 out of 16. 
	 * This will make the short-term measurements have more weight.
	 */
	tp->avg_iaj = (((tp->avg_iaj << 4) - tp->avg_iaj) + cur_iaj) >> 4;

	/* Compute Root-mean-square of deviation where mean is a weighted
	 * average as described above
	 */
	temp = tp->std_dev_iaj * tp->std_dev_iaj;
	mean = (((temp << 4) - temp) + (cur_iaj_dev * cur_iaj_dev)) >> 4;
	
	tp->std_dev_iaj = isqrt(mean);

	DTRACE_TCP3(iaj, struct tcpcb *, tp, uint32_t, cur_iaj, uint32_t, allowed_iaj);

	return;
}
#endif /* TRAFFIC_MGT */

static int
tcp_reass(tp, th, tlenp, m)
	register struct tcpcb *tp;
	register struct tcphdr *th;
	int *tlenp;
	struct mbuf *m;
{
	struct tseg_qent *q;
	struct tseg_qent *p = NULL;
	struct tseg_qent *nq;
	struct tseg_qent *te = NULL;
	struct socket *so = tp->t_inpcb->inp_socket;
	int flags;
	int dowakeup = 0;

	/*
	 * Call with th==0 after become established to
	 * force pre-ESTABLISHED data up to user socket.
	 */
	if (th == NULL)
		goto present;
	
	/* If the reassembly queue already has entries or if we are going to add 
	 * a new one, then the connection has reached a loss state. 
	 * Reset the stretch-ack algorithm at this point.
	 */
	if ((tp->t_flags & TF_STRETCHACK) != 0)
		tcp_reset_stretch_ack(tp);

	/* When the connection reaches a loss state, we need to send more acks
	 * for a period of time so that the sender's congestion window will
	 * open. Wait until we see some packets on the connection before 
	 * stretching acks again.
	 */
	tp->t_flagsext |= TF_RCVUNACK_WAITSS;
	tp->rcv_waitforss = 0;


#if TRAFFIC_MGT
	if (tp->acc_iaj > 0)
		reset_acc_iaj(tp);
#endif /* TRAFFIC_MGT */	

	/*
	 * Limit the number of segments in the reassembly queue to prevent
	 * holding on to too many segments (and thus running out of mbufs).
	 * Make sure to let the missing segment through which caused this
	 * queue.  Always keep one global queue entry spare to be able to
	 * process the missing segment.
	 */
	if (th->th_seq != tp->rcv_nxt &&
	    tcp_reass_qsize + 1 >= tcp_reass_maxseg) {
		tcp_reass_overflows++;
		tcpstat.tcps_rcvmemdrop++;
		m_freem(m);
		*tlenp = 0;
		return (0);
	}

	/* Allocate a new queue entry. If we can't, just drop the pkt. XXX */
	te = (struct tseg_qent *) zalloc_noblock(tcp_reass_zone);
	if (te == NULL) {
		tcpstat.tcps_rcvmemdrop++;
		m_freem(m);
		return (0);
	}
	tcp_reass_qsize++;

	/*
	 * Find a segment which begins after this one does.
	 */
	LIST_FOREACH(q, &tp->t_segq, tqe_q) {
		if (SEQ_GT(q->tqe_th->th_seq, th->th_seq))
			break;
		p = q;
	}

	/*
	 * If there is a preceding segment, it may provide some of
	 * our data already.  If so, drop the data from the incoming
	 * segment.  If it provides all of our data, drop us.
	 */
	if (p != NULL) {
		register int i;
		/* conversion to int (in i) handles seq wraparound */
		i = p->tqe_th->th_seq + p->tqe_len - th->th_seq;
		if (i > 0) {
			if (i >= *tlenp) {
				tcpstat.tcps_rcvduppack++;
				tcpstat.tcps_rcvdupbyte += *tlenp;
				if (nstat_collect) {
					nstat_route_rx(tp->t_inpcb->inp_route.ro_rt, 1, *tlenp, NSTAT_RX_FLAG_DUPLICATE);
					locked_add_64(&tp->t_inpcb->inp_stat->rxpackets, 1);
					locked_add_64(&tp->t_inpcb->inp_stat->rxbytes, *tlenp);
					tp->t_stat.rxduplicatebytes += *tlenp;
				}
				m_freem(m);
				zfree(tcp_reass_zone, te);
				tcp_reass_qsize--;
				/*
				 * Try to present any queued data
				 * at the left window edge to the user.
				 * This is needed after the 3-WHS
				 * completes.
				 */
				goto present;	/* ??? */
			}
			m_adj(m, i);
			*tlenp -= i;
			th->th_seq += i;
		}
	}
	tcpstat.tcps_rcvoopack++;
	tcpstat.tcps_rcvoobyte += *tlenp;
	if (nstat_collect) {
		nstat_route_rx(tp->t_inpcb->inp_route.ro_rt, 1, *tlenp, NSTAT_RX_FLAG_OUT_OF_ORDER);
		locked_add_64(&tp->t_inpcb->inp_stat->rxpackets, 1);
		locked_add_64(&tp->t_inpcb->inp_stat->rxbytes, *tlenp);
		tp->t_stat.rxoutoforderbytes += *tlenp;
	}

	/*
	 * While we overlap succeeding segments trim them or,
	 * if they are completely covered, dequeue them.
	 */
	while (q) {
		register int i = (th->th_seq + *tlenp) - q->tqe_th->th_seq;
		if (i <= 0)
			break;
		if (i < q->tqe_len) {
			q->tqe_th->th_seq += i;
			q->tqe_len -= i;
			m_adj(q->tqe_m, i);
			break;
		}

		nq = LIST_NEXT(q, tqe_q);
		LIST_REMOVE(q, tqe_q);
		m_freem(q->tqe_m);
		zfree(tcp_reass_zone, q);
		tcp_reass_qsize--;
		q = nq;
	}

	/* Insert the new segment queue entry into place. */
	te->tqe_m = m;
	te->tqe_th = th;
	te->tqe_len = *tlenp;

	if (p == NULL) {
		LIST_INSERT_HEAD(&tp->t_segq, te, tqe_q);
	} else {
		LIST_INSERT_AFTER(p, te, tqe_q);
	}

present:
	/*
	 * Present data to user, advancing rcv_nxt through
	 * completed sequence space.
	 */
	if (!TCPS_HAVEESTABLISHED(tp->t_state))
		return (0);
	q = LIST_FIRST(&tp->t_segq);
	if (!q || q->tqe_th->th_seq != tp->rcv_nxt)
		return (0);
	do {
		tp->rcv_nxt += q->tqe_len;
		flags = q->tqe_th->th_flags & TH_FIN;
		nq = LIST_NEXT(q, tqe_q);
		LIST_REMOVE(q, tqe_q);
		if (so->so_state & SS_CANTRCVMORE)
			m_freem(q->tqe_m);
		else {
			so_recv_data_stat(so, q->tqe_m, 0); /* XXXX */
			if (sbappendstream(&so->so_rcv, q->tqe_m))
				dowakeup = 1;
		}
		zfree(tcp_reass_zone, q);
		tcp_reass_qsize--;
		q = nq;
	} while (q && q->tqe_th->th_seq == tp->rcv_nxt);
	ND6_HINT(tp);

#if INET6
	if ((tp->t_inpcb->inp_vflag & INP_IPV6) != 0) {
	
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
	if (dowakeup)
		sorwakeup(so); /* done with socket lock held */
	return (flags);

}

/*
 * Reduce congestion window.
 */
static void
tcp_reduce_congestion_window(
	struct tcpcb	*tp, struct tcphdr *th)
{
	/*
	 * If the current tcp cc module has
	 * defined a hook for tasks to run
	 * before entering FR, call it
	 */
	if (CC_ALGO(tp)->pre_fr != NULL)
		CC_ALGO(tp)->pre_fr(tp, th);
	ENTER_FASTRECOVERY(tp);
	tp->snd_recover = tp->snd_max;
	tp->t_timer[TCPT_REXMT] = 0;
	tp->t_rtttime = 0;
	tp->ecn_flags |= TE_SENDCWR;
	tp->snd_cwnd = tp->snd_ssthresh +
		 tp->t_maxseg * tcprexmtthresh;
}


/*
 * TCP input routine, follows pages 65-76 of the
 * protocol specification dated September, 1981 very closely.
 */
#if INET6
int
tcp6_input(struct mbuf **mp, int *offp, int proto)
{
#pragma unused(proto)
	register struct mbuf *m = *mp;
	struct in6_ifaddr *ia6;

	IP6_EXTHDR_CHECK(m, *offp, sizeof(struct tcphdr), return IPPROTO_DONE);

	/*
	 * draft-itojun-ipv6-tcp-to-anycast
	 * better place to put this in?
	 */
	ia6 = ip6_getdstifaddr(m);
	if (ia6 != NULL) {
		IFA_LOCK_SPIN(&ia6->ia_ifa);
		if (ia6->ia6_flags & IN6_IFF_ANYCAST) {
			struct ip6_hdr *ip6;

			IFA_UNLOCK(&ia6->ia_ifa);
			IFA_REMREF(&ia6->ia_ifa);
			ip6 = mtod(m, struct ip6_hdr *);
			icmp6_error(m, ICMP6_DST_UNREACH,
			    ICMP6_DST_UNREACH_ADDR,
			    (caddr_t)&ip6->ip6_dst - (caddr_t)ip6);
			return (IPPROTO_DONE);
		}
		IFA_UNLOCK(&ia6->ia_ifa);
		IFA_REMREF(&ia6->ia_ifa);
	}

	tcp_input(m, *offp);
	return (IPPROTO_DONE);
}
#endif

/* A receiver will evaluate the flow of packets on a connection 
 * to see if it can reduce ack traffic. The receiver will start 
 * stretching acks if all of the following conditions are met:
 * 1. tcp_delack_enabled is set to 3
 * 2. If the bytes received in the last 100ms is greater than a threshold
 *      defined by maxseg_unacked
 * 3. If the connection has not been idle for tcp_maxrcvidle period.
 * 4. If the connection has seen enough packets to let the slow-start 
 *      finish after connection establishment or after some packet loss.
 *
 * The receiver will stop stretching acks if there is congestion/reordering
 * as indicated by packets on reassembly queue or an ECN. If the delayed-ack 
 * timer fires while stretching acks, it means that the packet flow has gone 
 * below the threshold defined by maxseg_unacked and the receiver will stop
 * stretching acks. The receiver gets no indication when slow-start is completed 
 * or when the connection reaches an idle state. That is why we use 
 * tcp_rcvsspktcnt to cover slow-start and tcp_maxrcvidle to identify idle 
 * state.
 */
 static inline int
 tcp_stretch_ack_enable(struct tcpcb *tp) {
 	if (tp->rcv_by_unackwin >= (maxseg_unacked * tp->t_maxseg) &&
		TSTMP_GT(tp->rcv_unackwin + tcp_maxrcvidle, tcp_now) &&
		(((tp->t_flagsext & TF_RCVUNACK_WAITSS) == 0) ||
		(tp->rcv_waitforss >= tcp_rcvsspktcnt))) {
		return(1);
	}
	return(0);
}

/* Reset the state related to stretch-ack algorithm. This will make
 * the receiver generate an ack every other packet. The receiver
 * will start re-evaluating the rate at which packets come to decide 
 * if it can benefit by lowering the ack traffic.
 */
void
tcp_reset_stretch_ack(struct tcpcb *tp)
{
	tp->t_flags &= ~(TF_STRETCHACK);
	tp->rcv_by_unackwin = 0;
	tp->rcv_unackwin = tcp_now + tcp_rcvunackwin;
}

void
tcp_input(m, off0)
	struct mbuf *m;
	int off0;
{
	register struct tcphdr *th;
	register struct ip *ip = NULL;
	register struct ipovly *ipov;
	register struct inpcb *inp;
	u_char *optp = NULL;
	int optlen = 0;
	int len, tlen, off;
	int drop_hdrlen;
	register struct tcpcb *tp = 0;
	register int thflags;
	struct socket *so = 0;
	int todrop, acked, ourfinisacked, needoutput = 0;
	struct in_addr laddr;
#if INET6
	struct in6_addr laddr6;
#endif
	int dropsocket = 0;
	int iss = 0;
	int nosock = 0;
	u_int32_t tiwin;
	struct tcpopt to;		/* options in this segment */
	struct sockaddr_in *next_hop = NULL;
#if TCPDEBUG
	short ostate = 0;
#endif
	struct m_tag *fwd_tag;
	u_char ip_ecn = IPTOS_ECN_NOTECT;
	unsigned int ifscope, nocell = 0;
	uint8_t isconnected, isdisconnected;

	/*
	 * Record the interface where this segment arrived on; this does not
	 * affect normal data output (for non-detached TCP) as it provides a
	 * hint about which route and interface to use for sending in the
	 * absence of a PCB, when scoped routing (and thus source interface
	 * selection) are enabled.
	 */
	if ((m->m_flags & M_PKTHDR) && m->m_pkthdr.rcvif != NULL)
		ifscope = m->m_pkthdr.rcvif->if_index;
	else
		ifscope = IFSCOPE_NONE;

        /* Since this is an entry point for input processing of tcp packets, we
         * can update the tcp clock here.
         */
        calculate_tcp_clock();

	/* Grab info from PACKET_TAG_IPFORWARD tag prepended to the chain. */
	if (!SLIST_EMPTY(&m->m_pkthdr.tags)) {
		fwd_tag = m_tag_locate(m, KERNEL_MODULE_TAG_ID,
		    KERNEL_TAG_TYPE_IPFORWARD, NULL);
	} else {
		fwd_tag = NULL;
	}
	if (fwd_tag != NULL) {
		struct ip_fwd_tag *ipfwd_tag = (struct ip_fwd_tag *)(fwd_tag+1);
		
		next_hop = ipfwd_tag->next_hop;
		m_tag_delete(m, fwd_tag);
	}
	
#if INET6
	struct ip6_hdr *ip6 = NULL;
	int isipv6;
#endif /* INET6 */
	int rstreason; /* For badport_bandlim accounting purposes */
	struct proc *proc0=current_proc();
	
	KERNEL_DEBUG(DBG_FNC_TCP_INPUT | DBG_FUNC_START,0,0,0,0,0);

#if INET6
	isipv6 = (mtod(m, struct ip *)->ip_v == 6) ? 1 : 0;
#endif
	bzero((char *)&to, sizeof(to));

	tcpstat.tcps_rcvtotal++;



#if INET6
	if (isipv6) {
		/* IP6_EXTHDR_CHECK() is already done at tcp6_input() */
		ip6 = mtod(m, struct ip6_hdr *);
		tlen = sizeof(*ip6) + ntohs(ip6->ip6_plen) - off0;
		th = (struct tcphdr *)((caddr_t)ip6 + off0);

		if ((apple_hwcksum_rx != 0) && (m->m_pkthdr.csum_flags & CSUM_DATA_VALID)) {
			if (m->m_pkthdr.csum_flags & CSUM_PSEUDO_HDR)
				th->th_sum = m->m_pkthdr.csum_data;
			else
				th->th_sum = in6_cksum_phdr(&ip6->ip6_src,
		    			&ip6->ip6_dst, htonl(sizeof(struct tcphdr)),
		    			htonl(IPPROTO_TCP));

			th->th_sum ^= 0xffff;
			if (th->th_sum) {
				tcpstat.tcps_rcvbadsum++;
				goto dropnosock;
			}
		}
		else {
			if (in6_cksum(m, IPPROTO_TCP, off0, tlen)) {
				tcpstat.tcps_rcvbadsum++;
				goto dropnosock;
			}
		}

		KERNEL_DEBUG(DBG_LAYER_BEG, ((th->th_dport << 16) | th->th_sport),
		     (((ip6->ip6_src.s6_addr16[0]) << 16) | (ip6->ip6_dst.s6_addr16[0])),
		     th->th_seq, th->th_ack, th->th_win);
		/*
		 * Be proactive about unspecified IPv6 address in source.
		 * As we use all-zero to indicate unbounded/unconnected pcb,
		 * unspecified IPv6 address can be used to confuse us.
		 *
		 * Note that packets with unspecified IPv6 destination is
		 * already dropped in ip6_input.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&ip6->ip6_src)) {
			/* XXX stat */
			goto dropnosock;
		}
		DTRACE_TCP5(receive, sruct mbuf *, m, struct inpcb *, NULL,
			struct ip6_hdr *, ip6, struct tcpcb *, NULL, 
			struct tcphdr *, th);
        
	ip_ecn = (ntohl(ip6->ip6_flow) >> 20) & IPTOS_ECN_MASK;
	} else
#endif /* INET6 */
	{
	/*
	 * Get IP and TCP header together in first mbuf.
	 * Note: IP leaves IP header in first mbuf.
	 */
	if (off0 > sizeof (struct ip)) {
		ip_stripoptions(m, (struct mbuf *)0);
		off0 = sizeof(struct ip);
		if (m->m_pkthdr.csum_flags & CSUM_TCP_SUM16)
			m->m_pkthdr.csum_flags = 0; /* invalidate hwcksuming */

	}
	if (m->m_len < sizeof (struct tcpiphdr)) {
		if ((m = m_pullup(m, sizeof (struct tcpiphdr))) == 0) {
			tcpstat.tcps_rcvshort++;
			return;
		}
	}
	ip = mtod(m, struct ip *);
	ipov = (struct ipovly *)ip;
	th = (struct tcphdr *)((caddr_t)ip + off0);
	tlen = ip->ip_len;

	DTRACE_TCP5(receive, struct mbuf *, m, struct inpcb *, NULL,
		struct ip *, ip, struct tcpcb *, NULL, struct tcphdr *, th);

	KERNEL_DEBUG(DBG_LAYER_BEG, ((th->th_dport << 16) | th->th_sport),
		     (((ip->ip_src.s_addr & 0xffff) << 16) | (ip->ip_dst.s_addr & 0xffff)),
		     th->th_seq, th->th_ack, th->th_win);

	if (m->m_pkthdr.csum_flags & CSUM_DATA_VALID) {
		if (m->m_pkthdr.csum_flags & CSUM_TCP_SUM16) {
			u_short pseudo;
			char b[9];
			*(uint32_t*)&b[0] = *(uint32_t*)&ipov->ih_x1[0];
			*(uint32_t*)&b[4] = *(uint32_t*)&ipov->ih_x1[4];
			*(uint8_t*)&b[8] = *(uint8_t*)&ipov->ih_x1[8];
			
			bzero(ipov->ih_x1, sizeof(ipov->ih_x1));
			ipov->ih_len = (u_short)tlen;

#if BYTE_ORDER != BIG_ENDIAN
			HTONS(ipov->ih_len);
#endif

			pseudo = in_cksum(m, sizeof (struct ip));
			
			*(uint32_t*)&ipov->ih_x1[0] = *(uint32_t*)&b[0];
			*(uint32_t*)&ipov->ih_x1[4] = *(uint32_t*)&b[4];
			*(uint8_t*)&ipov->ih_x1[8] = *(uint8_t*)&b[8];
			
			th->th_sum = in_addword(pseudo, (m->m_pkthdr.csum_data & 0xFFFF));
		} else {
			if (m->m_pkthdr.csum_flags & CSUM_PSEUDO_HDR)
				th->th_sum = m->m_pkthdr.csum_data;
			else
				th->th_sum = in_pseudo(ip->ip_src.s_addr,
					ip->ip_dst.s_addr, htonl(m->m_pkthdr.csum_data +
					ip->ip_len + IPPROTO_TCP));
		}
		th->th_sum ^= 0xffff;
	} else {
		char b[9];
		/*
		 * Checksum extended TCP header and data.
		 */
		*(uint32_t*)&b[0] = *(uint32_t*)&ipov->ih_x1[0];
		*(uint32_t*)&b[4] = *(uint32_t*)&ipov->ih_x1[4];
		*(uint8_t*)&b[8] = *(uint8_t*)&ipov->ih_x1[8];
		
		len = sizeof (struct ip) + tlen;
		bzero(ipov->ih_x1, sizeof(ipov->ih_x1));
		ipov->ih_len = (u_short)tlen;

#if BYTE_ORDER != BIG_ENDIAN
		HTONS(ipov->ih_len);
#endif

		th->th_sum = in_cksum(m, len);
		
		*(uint32_t*)&ipov->ih_x1[0] = *(uint32_t*)&b[0];
		*(uint32_t*)&ipov->ih_x1[4] = *(uint32_t*)&b[4];
		*(uint8_t*)&ipov->ih_x1[8] = *(uint8_t*)&b[8];

		tcp_in_cksum_stats(len);
	}
	if (th->th_sum) {
		tcpstat.tcps_rcvbadsum++;
		goto dropnosock;
	}
#if INET6
	/* Re-initialization for later version check */
	ip->ip_v = IPVERSION;
#endif
	ip_ecn = (ip->ip_tos & IPTOS_ECN_MASK);
	}

	/*
	 * Check that TCP offset makes sense,
	 * pull out TCP options and adjust length.		XXX
	 */
	off = th->th_off << 2;
	if (off < sizeof (struct tcphdr) || off > tlen) {
		tcpstat.tcps_rcvbadoff++;
		goto dropnosock;
	}
	tlen -= off;	/* tlen is used instead of ti->ti_len */
	if (off > sizeof (struct tcphdr)) {
#if INET6
		if (isipv6) {
			IP6_EXTHDR_CHECK(m, off0, off, return);
			ip6 = mtod(m, struct ip6_hdr *);
			th = (struct tcphdr *)((caddr_t)ip6 + off0);
		} else
#endif /* INET6 */
		{
			if (m->m_len < sizeof(struct ip) + off) {
				if ((m = m_pullup(m, sizeof (struct ip) + off)) == 0) {
					tcpstat.tcps_rcvshort++;
					return;
				}
				ip = mtod(m, struct ip *);
				ipov = (struct ipovly *)ip;
				th = (struct tcphdr *)((caddr_t)ip + off0);
			}
		}
		optlen = off - sizeof (struct tcphdr);
		optp = (u_char *)(th + 1);
		/* 
		 * Do quick retrieval of timestamp options ("options
		 * prediction?").  If timestamp is the only option and it's
		 * formatted as recommended in RFC 1323 appendix A, we
		 * quickly get the values now and not bother calling
		 * tcp_dooptions(), etc.
		 */
		if ((optlen == TCPOLEN_TSTAMP_APPA ||
			(optlen > TCPOLEN_TSTAMP_APPA &&
			optp[TCPOLEN_TSTAMP_APPA] == TCPOPT_EOL)) &&
			*(u_int32_t *)optp == htonl(TCPOPT_TSTAMP_HDR) &&
			(th->th_flags & TH_SYN) == 0) {
			to.to_flags |= TOF_TS;
			to.to_tsval = ntohl(*(u_int32_t *)(optp + 4));
			to.to_tsecr = ntohl(*(u_int32_t *)(optp + 8));
			optp = NULL;	/* we've parsed the options */
		}
	}
	thflags = th->th_flags;

#if TCP_DROP_SYNFIN
	/*
	 * If the drop_synfin option is enabled, drop all packets with
	 * both the SYN and FIN bits set. This prevents e.g. nmap from
	 * identifying the TCP/IP stack.
	 *
	 * This is a violation of the TCP specification.
	 */
	if (drop_synfin && (thflags & (TH_SYN|TH_FIN)) == (TH_SYN|TH_FIN))
		goto dropnosock;
#endif

	/*
	 * Convert TCP protocol specific fields to host format.
	 */

#if BYTE_ORDER != BIG_ENDIAN
	NTOHL(th->th_seq);
	NTOHL(th->th_ack);
	NTOHS(th->th_win);
	NTOHS(th->th_urp);
#endif

	/*
	 * Delay dropping TCP, IP headers, IPv6 ext headers, and TCP options,
	 * until after ip6_savecontrol() is called and before other functions
	 * which don't want those proto headers.
	 * Because ip6_savecontrol() is going to parse the mbuf to
	 * search for data to be passed up to user-land, it wants mbuf
	 * parameters to be unchanged.
	 */
	drop_hdrlen = off0 + off;

	/*
	 * Locate pcb for segment.
	 */
findpcb:

	isconnected = FALSE;
	isdisconnected = FALSE;

#if IPFIREWALL_FORWARD
	if (next_hop != NULL
#if INET6
	    && isipv6 == 0 /* IPv6 support is not yet */
#endif /* INET6 */
	    ) {
		/*
		 * Diverted. Pretend to be the destination.
		 * already got one like this? 
		 */
		inp = in_pcblookup_hash(&tcbinfo, ip->ip_src, th->th_sport,
			ip->ip_dst, th->th_dport, 0, m->m_pkthdr.rcvif);
		if (!inp) {
			/* 
			 * No, then it's new. Try find the ambushing socket
			 */
			if (!next_hop->sin_port) {
				inp = in_pcblookup_hash(&tcbinfo, ip->ip_src,
				    th->th_sport, next_hop->sin_addr,
				    th->th_dport, 1, m->m_pkthdr.rcvif);
			} else {
				inp = in_pcblookup_hash(&tcbinfo,
				    ip->ip_src, th->th_sport,
	    			    next_hop->sin_addr,
				    ntohs(next_hop->sin_port), 1,
				    m->m_pkthdr.rcvif);
			}
		}
	} else
#endif	/* IPFIREWALL_FORWARD */
      {
#if INET6
	if (isipv6)
		inp = in6_pcblookup_hash(&tcbinfo, &ip6->ip6_src, th->th_sport,
					 &ip6->ip6_dst, th->th_dport, 1,
					 m->m_pkthdr.rcvif);
	else
#endif /* INET6 */
	inp = in_pcblookup_hash(&tcbinfo, ip->ip_src, th->th_sport,
	    ip->ip_dst, th->th_dport, 1, m->m_pkthdr.rcvif);
      }

	/*
	 * Use the interface scope information from the PCB for outbound
	 * segments.  If the PCB isn't present and if scoped routing is
	 * enabled, tcp_respond will use the scope of the interface where
	 * the segment arrived on.
	 */
	if (inp != NULL && (inp->inp_flags & INP_BOUND_IF))
		ifscope = inp->inp_boundif;
	/*
	 * If the PCB is present and the socket isn't allowed to use
	 * the cellular interface, indicate it as such for tcp_respond.
	 */
	if (inp != NULL && (inp->inp_flags & INP_NO_IFT_CELLULAR))
		nocell = 1;

#if IPSEC
	if (ipsec_bypass == 0)  {
#if INET6
		if (isipv6) {
		       	if (inp != NULL && ipsec6_in_reject_so(m, inp->inp_socket)) {
				IPSEC_STAT_INCREMENT(ipsec6stat.in_polvio);
				if (in_pcb_checkstate(inp, WNT_RELEASE, 0) == WNT_STOPUSING) 
					inp = NULL;	// pretend we didn't find it 
				goto dropnosock;
			}
		} else
#endif /* INET6 */
			if (inp != NULL && ipsec4_in_reject_so(m, inp->inp_socket)) {
			  	IPSEC_STAT_INCREMENT(ipsecstat.in_polvio);
				if (in_pcb_checkstate(inp, WNT_RELEASE, 0) == WNT_STOPUSING) 
					inp = NULL;	// pretend we didn't find it 
				goto dropnosock;
			}
	}
#endif /*IPSEC*/

	/*
	 * If the state is CLOSED (i.e., TCB does not exist) then
	 * all data in the incoming segment is discarded.
	 * If the TCB exists but is in CLOSED state, it is embryonic,
	 * but should either do a listen or a connect soon.
	 */
	if (inp == NULL) {
		if (log_in_vain) {
#if INET6
			char dbuf[MAX_IPv6_STR_LEN], sbuf[MAX_IPv6_STR_LEN];
#else /* INET6 */
			char dbuf[MAX_IPv4_STR_LEN], sbuf[MAX_IPv4_STR_LEN];
#endif /* INET6 */

#if INET6
			if (isipv6) {
				inet_ntop(AF_INET6, &ip6->ip6_dst, dbuf, sizeof(dbuf));
				inet_ntop(AF_INET6, &ip6->ip6_src, sbuf, sizeof(sbuf));
			} else
#endif
			{
				inet_ntop(AF_INET, &ip->ip_dst, dbuf, sizeof(dbuf));
				inet_ntop(AF_INET, &ip->ip_src, sbuf, sizeof(sbuf));
			}
			switch (log_in_vain) {
			case 1:
				if(thflags & TH_SYN)
					log(LOG_INFO,
						"Connection attempt to TCP %s:%d from %s:%d\n",
						dbuf, ntohs(th->th_dport),
						sbuf,
						ntohs(th->th_sport));
				break;
			case 2:
				log(LOG_INFO,
					"Connection attempt to TCP %s:%d from %s:%d flags:0x%x\n",
					dbuf, ntohs(th->th_dport), sbuf,
					ntohs(th->th_sport), thflags);
				break;
			case 3:
				if ((thflags & TH_SYN) &&
					!(m->m_flags & (M_BCAST | M_MCAST)) &&
#if INET6
					((isipv6 && !IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst, &ip6->ip6_src)) ||
					 (!isipv6 && ip->ip_dst.s_addr != ip->ip_src.s_addr))
#else
					ip->ip_dst.s_addr != ip->ip_src.s_addr
#endif
					 )
					log_in_vain_log((LOG_INFO,
						"Stealth Mode connection attempt to TCP %s:%d from %s:%d\n",
						dbuf, ntohs(th->th_dport),
						sbuf,
						ntohs(th->th_sport)));
				break;
			default:
				break;
			}
		}
		if (blackhole) { 
			if (m->m_pkthdr.rcvif && m->m_pkthdr.rcvif->if_type != IFT_LOOP)
				switch (blackhole) {
				case 1:
					if (thflags & TH_SYN)
						goto dropnosock;
					break;
				case 2:
					goto dropnosock;
				default:
					goto dropnosock;
				}
		}
		rstreason = BANDLIM_RST_CLOSEDPORT;
		goto dropwithresetnosock;
	}
	so = inp->inp_socket;
	if (so == NULL) {
		/* This case shouldn't happen  as the socket shouldn't be null
		 * if inp_state isn't set to INPCB_STATE_DEAD
		 * But just in case, we pretend we didn't find the socket if we hit this case
		 * as this isn't cause for a panic (the socket might be leaked however)...
		 */
		inp = NULL;
#if TEMPDEBUG
		printf("tcp_input: no more socket for inp=%x. This shouldn't happen\n", inp);
#endif
		goto dropnosock;
	}

	tcp_lock(so, 1, 0);
	if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) {
		tcp_unlock(so, 1, (void *)2);
		inp = NULL;	// pretend we didn't find it 
		goto dropnosock;
	}

	tp = intotcpcb(inp);
	if (tp == 0) {
		rstreason = BANDLIM_RST_CLOSEDPORT;
		goto dropwithreset;
	}
	if (tp->t_state == TCPS_CLOSED)
		goto drop;

	/* Unscale the window into a 32-bit value. */
	if ((thflags & TH_SYN) == 0)
		tiwin = th->th_win << tp->snd_scale;
	else
		tiwin = th->th_win;

#if CONFIG_MACF_NET
	if (mac_inpcb_check_deliver(inp, m, AF_INET, SOCK_STREAM))
		goto drop;
#endif

	/* Radar 7377561: Avoid processing packets while closing a listen socket */
	if (tp->t_state == TCPS_LISTEN && (so->so_options & SO_ACCEPTCONN) == 0) 
		goto drop;

	if (so->so_options & (SO_DEBUG|SO_ACCEPTCONN)) {
#if TCPDEBUG
		if (so->so_options & SO_DEBUG) {
			ostate = tp->t_state;
#if INET6
			if (isipv6)
				bcopy((char *)ip6, (char *)tcp_saveipgen,
				      sizeof(*ip6));
			else
#endif /* INET6 */
			bcopy((char *)ip, (char *)tcp_saveipgen, sizeof(*ip));
			tcp_savetcp = *th;
		}
#endif
		if (so->so_options & SO_ACCEPTCONN) {
		    register struct tcpcb *tp0 = tp;
			struct socket *so2;
			struct socket *oso;
			struct sockaddr_storage from;
#if INET6
			struct inpcb *oinp = sotoinpcb(so);
#endif /* INET6 */
			unsigned int head_ifscope;
			unsigned int head_nocell;

			/* Get listener's bound-to-interface, if any */
			head_ifscope = (inp->inp_flags & INP_BOUND_IF) ?
			    inp->inp_boundif : IFSCOPE_NONE;
			/* Get listener's no-cellular information, if any */
			head_nocell = (inp->inp_flags & INP_NO_IFT_CELLULAR) ? 1 : 0;

			/*
			 * If the state is LISTEN then ignore segment if it contains an RST.
			 * If the segment contains an ACK then it is bad and send a RST.
			 * If it does not contain a SYN then it is not interesting; drop it.
			 * If it is from this socket, drop it, it must be forged.
			 */
			if ((thflags & (TH_RST|TH_ACK|TH_SYN)) != TH_SYN) {
				if (thflags & TH_RST) {
					goto drop;
				}
				if (thflags & TH_ACK) {
					tp = NULL;
					tcpstat.tcps_badsyn++;
					rstreason = BANDLIM_RST_OPENPORT;
					goto dropwithreset;
				}

				/* We come here if there is no SYN set */
				tcpstat.tcps_badsyn++;
				goto drop;
			}
			KERNEL_DEBUG(DBG_FNC_TCP_NEWCONN | DBG_FUNC_START,0,0,0,0,0);
	                if (th->th_dport == th->th_sport) {
#if INET6
				if (isipv6) {
					if (IN6_ARE_ADDR_EQUAL(&ip6->ip6_dst,
                                                       &ip6->ip6_src))
						goto drop;
				} else
#endif /* INET6 */
					if (ip->ip_dst.s_addr == ip->ip_src.s_addr)
						goto drop;
			}
			/*
			 * RFC1122 4.2.3.10, p. 104: discard bcast/mcast SYN
			 * in_broadcast() should never return true on a received
			 * packet with M_BCAST not set.
			 *
			 * Packets with a multicast source address should also
			 * be discarded.
			 */
			if (m->m_flags & (M_BCAST|M_MCAST))
				goto drop;
#if INET6
			if (isipv6) {
				if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) ||
					IN6_IS_ADDR_MULTICAST(&ip6->ip6_src))
					goto drop;
			} else
#endif
			if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr)) ||
				IN_MULTICAST(ntohl(ip->ip_src.s_addr)) ||
				ip->ip_src.s_addr == htonl(INADDR_BROADCAST) ||
				in_broadcast(ip->ip_dst, m->m_pkthdr.rcvif))
				goto drop;


#if INET6
			/*
			 * If deprecated address is forbidden,
			 * we do not accept SYN to deprecated interface
			 * address to prevent any new inbound connection from
			 * getting established.
			 * When we do not accept SYN, we send a TCP RST,
			 * with deprecated source address (instead of dropping
			 * it).  We compromise it as it is much better for peer
			 * to send a RST, and RST will be the final packet
			 * for the exchange.
			 *
			 * If we do not forbid deprecated addresses, we accept
			 * the SYN packet.  RFC2462 does not suggest dropping
			 * SYN in this case.
			 * If we decipher RFC2462 5.5.4, it says like this:
			 * 1. use of deprecated addr with existing
			 *    communication is okay - "SHOULD continue to be
			 *    used"
			 * 2. use of it with new communication:
			 *   (2a) "SHOULD NOT be used if alternate address
			 *        with sufficient scope is available"
			 *   (2b) nothing mentioned otherwise.
			 * Here we fall into (2b) case as we have no choice in
			 * our source address selection - we must obey the peer.
			 *
			 * The wording in RFC2462 is confusing, and there are
			 * multiple description text for deprecated address
			 * handling - worse, they are not exactly the same.
			 * I believe 5.5.4 is the best one, so we follow 5.5.4.
			 */
			if (isipv6 && !ip6_use_deprecated) {
				struct in6_ifaddr *ia6;

				ia6 = ip6_getdstifaddr(m);
				if (ia6 != NULL) {
					IFA_LOCK_SPIN(&ia6->ia_ifa);
					if (ia6->ia6_flags & IN6_IFF_DEPRECATED) {
						IFA_UNLOCK(&ia6->ia_ifa);
						IFA_REMREF(&ia6->ia_ifa);
						tp = NULL;
						rstreason = BANDLIM_RST_OPENPORT;
						goto dropwithreset;
					}
					IFA_UNLOCK(&ia6->ia_ifa);
					IFA_REMREF(&ia6->ia_ifa);
				}
			}
#endif
			if (so->so_filt) {
#if INET6
				if (isipv6) {
					struct sockaddr_in6	*sin6 = (struct sockaddr_in6*)&from;
					
					sin6->sin6_len = sizeof(*sin6);
					sin6->sin6_family = AF_INET6;
					sin6->sin6_port = th->th_sport;
					sin6->sin6_flowinfo = 0;
					sin6->sin6_addr = ip6->ip6_src;
					sin6->sin6_scope_id = 0;
 				}
				else
#endif
				{
					struct sockaddr_in *sin = (struct sockaddr_in*)&from;
					
					sin->sin_len = sizeof(*sin);
					sin->sin_family = AF_INET;
					sin->sin_port = th->th_sport;
					sin->sin_addr = ip->ip_src;
				}
				so2 = sonewconn(so, 0, (struct sockaddr*)&from);
			} else {
				so2 = sonewconn(so, 0, NULL);
			}
			if (so2 == 0) {
				tcpstat.tcps_listendrop++;
				if (tcp_dropdropablreq(so)) {
					if (so->so_filt)
						so2 = sonewconn(so, 0, (struct sockaddr*)&from);
					else
						so2 = sonewconn(so, 0, NULL);
				}
				if (!so2) 
					goto drop;
			}

			/* Point "inp" and "tp" in tandem to new socket */
			inp = (struct inpcb *)so2->so_pcb;
			tp = intotcpcb(inp);

			oso = so;
			tcp_unlock(so, 0, 0); /* Unlock but keep a reference on listener for now */

			so = so2;
			tcp_lock(so, 1, 0);
			/*
			 * Mark socket as temporary until we're
			 * committed to keeping it.  The code at
			 * ``drop'' and ``dropwithreset'' check the
			 * flag dropsocket to see if the temporary
			 * socket created here should be discarded.
			 * We mark the socket as discardable until
			 * we're committed to it below in TCPS_LISTEN.
			 * There are some error conditions in which we
			 * have to drop the temporary socket.
			 */
			dropsocket++;
			/*
			 * Inherit INP_BOUND_IF from listener; testing if
			 * head_ifscope is non-zero is sufficient, since it
			 * can only be set to a non-zero value earlier if
			 * the listener has such a flag set.
			 */
			if (head_ifscope != IFSCOPE_NONE) {
				inp->inp_flags |= INP_BOUND_IF;
				inp->inp_boundif = head_ifscope;
			}
			/*
			 * Inherit INP_NO_IFT_CELLULAR from listener.
			 */
			if (head_nocell) {
				inp->inp_flags |= INP_NO_IFT_CELLULAR;
			}
#if INET6
			if (isipv6)
				inp->in6p_laddr = ip6->ip6_dst;
			else {
				inp->inp_vflag &= ~INP_IPV6;
				inp->inp_vflag |= INP_IPV4;
#endif /* INET6 */
				inp->inp_laddr = ip->ip_dst;
#if INET6
			}
#endif /* INET6 */
			inp->inp_lport = th->th_dport;
			if (in_pcbinshash(inp, 0) != 0) {
				/*
				 * Undo the assignments above if we failed to
				 * put the PCB on the hash lists.
				 */
#if INET6
				if (isipv6)
					inp->in6p_laddr = in6addr_any;
				else
#endif /* INET6 */
				inp->inp_laddr.s_addr = INADDR_ANY;
				inp->inp_lport = 0;
				tcp_lock(oso, 0, 0);	/* release ref on parent */
				tcp_unlock(oso, 1, 0);
				goto drop;
			}
#if INET6
			if (isipv6) {
  				/*
 				 * Inherit socket options from the listening
  				 * socket.
 				 * Note that in6p_inputopts are not (even
 				 * should not be) copied, since it stores
				 * previously received options and is used to
 				 * detect if each new option is different than
 				 * the previous one and hence should be passed
 				 * to a user.
 				 * If we copied in6p_inputopts, a user would
 				 * not be able to receive options just after
 				 * calling the accept system call.
 				 */
				inp->inp_flags |=
					oinp->inp_flags & INP_CONTROLOPTS;
 				if (oinp->in6p_outputopts)
 					inp->in6p_outputopts =
 						ip6_copypktopts(oinp->in6p_outputopts,
 								M_NOWAIT);
			} else
#endif /* INET6 */
			inp->inp_options = ip_srcroute();
			tcp_lock(oso, 0, 0);
#if IPSEC
			/* copy old policy into new socket's */
			if (sotoinpcb(oso)->inp_sp)
			{
				int error = 0;
				/* Is it a security hole here to silently fail to copy the policy? */
				if (inp->inp_sp != NULL)
					error = ipsec_init_policy(so, &inp->inp_sp);
				if (error != 0 || ipsec_copy_policy(sotoinpcb(oso)->inp_sp, inp->inp_sp))
					printf("tcp_input: could not copy policy\n");
			}
#endif
			/* inherit states from the listener */
			DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
				struct tcpcb *, tp, int32_t, TCPS_LISTEN);
			tp->t_state = TCPS_LISTEN;
			tp->t_flags |= tp0->t_flags & (TF_NOPUSH|TF_NOOPT|TF_NODELAY);
			tp->t_flagsext |= (tp0->t_flagsext & TF_RXTFINDROP);
			tp->t_keepinit = tp0->t_keepinit;
			tp->t_inpcb->inp_ip_ttl = tp0->t_inpcb->inp_ip_ttl;

			/* now drop the reference on the listener */
			tcp_unlock(oso, 1, 0);

			/* Compute proper scaling value from buffer space */
			if (inp->inp_pcbinfo->ipi_count < tcp_sockthreshold) {
				tp->request_r_scale = max(tcp_win_scale, tp->request_r_scale);
				so->so_rcv.sb_hiwat = imin(TCP_MAXWIN << tp->request_r_scale, (sb_max / (MSIZE+MCLBYTES)) * MCLBYTES);  
			}
			else {
				while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
			   	TCP_MAXWIN << tp->request_r_scale <
			   	so->so_rcv.sb_hiwat)
					tp->request_r_scale++;
			}

			KERNEL_DEBUG(DBG_FNC_TCP_NEWCONN | DBG_FUNC_END,0,0,0,0,0);
		}
	}
	lck_mtx_assert(&((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_OWNED);

 	/*
 	 * Radar 3529618
	 * This is the second part of the MSS DoS prevention code (after
	 * minmss on the sending side) and it deals with too many too small
	 * tcp packets in a too short timeframe (1 second).
	 *
	 * For every full second we count the number of received packets
	 * and bytes. If we get a lot of packets per second for this connection
	 * (tcp_minmssoverload) we take a closer look at it and compute the
	 * average packet size for the past second. If that is less than
	 * tcp_minmss we get too many packets with very small payload which
	 * is not good and burdens our system (and every packet generates
	 * a wakeup to the process connected to our socket). We can reasonable
	 * expect this to be small packet DoS attack to exhaust our CPU
	 * cycles.
	 *
	 * Care has to be taken for the minimum packet overload value. This
	 * value defines the minimum number of packets per second before we
	 * start to worry. This must not be too low to avoid killing for
	 * example interactive connections with many small packets like
	 * telnet or SSH.
	 *
	 * Setting either tcp_minmssoverload or tcp_minmss to "0" disables
	 * this check.
	 *
	 * Account for packet if payload packet, skip over ACK, etc.
	 */
	if (tp->t_state == TCPS_ESTABLISHED && tlen > 0) {
		if (TSTMP_GT(tp->rcv_reset, tcp_now)) {
			tp->rcv_pps++;
			tp->rcv_byps += tlen + off;
			if (tp->rcv_byps > tp->rcv_maxbyps)
				tp->rcv_maxbyps = tp->rcv_byps;
		/*
		 * Setting either tcp_minmssoverload or tcp_minmss to "0" disables
		 * the check. 
		 */
			if (tcp_minmss && tcp_minmssoverload && tp->rcv_pps > tcp_minmssoverload) {
				if ((tp->rcv_byps / tp->rcv_pps) < tcp_minmss) {
					char	ipstrbuf[MAX_IPv6_STR_LEN];
					printf("too many small tcp packets from "
					       "%s:%u, av. %ubyte/packet, "
					       "dropping connection\n",
#if INET6
						isipv6 ?
						inet_ntop(AF_INET6, &inp->in6p_faddr, ipstrbuf,
								  sizeof(ipstrbuf)) :
#endif
						inet_ntop(AF_INET, &inp->inp_faddr, ipstrbuf,
								  sizeof(ipstrbuf)),
						inp->inp_fport,
						tp->rcv_byps / tp->rcv_pps);
					tp = tcp_drop(tp, ECONNRESET);
/*					tcpstat.tcps_minmssdrops++; */
					goto drop;
				}
			}
		} else {
			tp->rcv_reset = tcp_now + TCP_RETRANSHZ;
			tp->rcv_pps = 1;
			tp->rcv_byps = tlen + off;
		}

		/* Evaluate the rate of arrival of packets to see if the 
		 * receiver can reduce the ack traffic. The algorithm to 
		 * stretch acks will be enabled if the connection meets 
		 * certain criteria defined in tcp_stretch_ack_enable function.
		 */
		if ((tp->t_flagsext & TF_RCVUNACK_WAITSS) != 0) {
			tp->rcv_waitforss++;
		}
		if (tcp_stretch_ack_enable(tp)) {
			tp->t_flags |= TF_STRETCHACK;
			tp->t_flagsext &= ~(TF_RCVUNACK_WAITSS);
			tp->rcv_waitforss = 0;
		} else {
			tp->t_flags &= ~(TF_STRETCHACK);
		}
		if (TSTMP_GT(tp->rcv_unackwin, tcp_now)) {
			tp->rcv_by_unackwin += (tlen + off);
		} else {
			tp->rcv_unackwin = tcp_now + tcp_rcvunackwin;
			tp->rcv_by_unackwin = tlen + off;
		}
	}
	
	/*
	   Explicit Congestion Notification - Flag that we need to send ECT if
		+ The IP Congestion experienced flag was set.
		+ Socket is in established state
		+ We negotiated ECN in the TCP setup
		+ This isn't a pure ack (tlen > 0)
		+ The data is in the valid window
	
		TE_SENDECE will be cleared when we receive a packet with TH_CWR set.
	 */
	if (ip_ecn == IPTOS_ECN_CE && tp->t_state == TCPS_ESTABLISHED &&
		(tp->ecn_flags & (TE_SETUPSENT | TE_SETUPRECEIVED)) ==
		 (TE_SETUPSENT | TE_SETUPRECEIVED) && tlen > 0 &&
		SEQ_GEQ(th->th_seq, tp->last_ack_sent) &&
		SEQ_LT(th->th_seq, tp->last_ack_sent + tp->rcv_wnd)) {
		tp->ecn_flags |= TE_SENDECE;
	}
	
	/*
	   Clear TE_SENDECE if TH_CWR is set. This is harmless, so we don't
	   bother doing extensive checks for state and whatnot.
	 */
	if ((thflags & TH_CWR) == TH_CWR) {
		tp->ecn_flags &= ~TE_SENDECE;
	}

	/* If we received an  explicit notification of congestion in 
	 * ip tos ecn bits or by the CWR bit in TCP header flags, reset
	 * the ack-strteching state.
	 */
	if (tp->t_state == TCPS_ESTABLISHED && (tp->t_flags & TF_STRETCHACK) != 0 &&
		((ip_ecn == IPTOS_ECN_CE) || ((thflags & TH_CWR) == TH_CWR)))
		tcp_reset_stretch_ack(tp);
	
	/*
	 * Segment received on connection.
	 * Reset idle time and keep-alive timer.
	 */
	tp->t_rcvtime = tcp_now;
	if (TCPS_HAVEESTABLISHED(tp->t_state))
		tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(tp, TCP_KEEPIDLE(tp));

	/*
	 * Process options if not in LISTEN state,
	 * else do it below (after getting remote address).
	 */
	if (tp->t_state != TCPS_LISTEN && optp)
		tcp_dooptions(tp, optp, optlen, th, &to, ifscope);

	if (tp->t_state == TCPS_SYN_SENT && (thflags & TH_SYN)) {
		if (to.to_flags & TOF_SCALE) {
			tp->t_flags |= TF_RCVD_SCALE;
			tp->requested_s_scale = to.to_requested_s_scale;
			tp->snd_wnd = th->th_win << tp->snd_scale;
			tiwin = tp->snd_wnd;
		}
		if (to.to_flags & TOF_TS) {
			tp->t_flags |= TF_RCVD_TSTMP;
			tp->ts_recent = to.to_tsval;
			tp->ts_recent_age = tcp_now;
		}
		if (to.to_flags & TOF_MSS)
			tcp_mss(tp, to.to_mss, ifscope);
		if (tp->sack_enable) {
			if (!(to.to_flags & TOF_SACK))
				tp->sack_enable = 0;
			else
				tp->t_flags |= TF_SACK_PERMIT;
		}
	}

#if TRAFFIC_MGT
	/* Compute inter-packet arrival jitter. According to RFC 3550, inter-packet 
	 * arrival jitter is defined as the difference in packet spacing at the 
	 * receiver compared to the sender for a pair of packets. When two packets 
	 * of maximum segment size come one after the other with consecutive 
	 * sequence numbers, we consider them as packets sent together at the 
	 * sender and use them as a pair to compute inter-packet arrival jitter.
	 * This metric indicates the delay induced by the network components due
	 * to queuing in edge/access routers.
	 */
	if (tp->t_state == TCPS_ESTABLISHED &&
	    (thflags & (TH_SYN|TH_FIN|TH_RST|TH_URG|TH_ACK|TH_ECE|TH_PUSH)) == TH_ACK &&
	    ((tp->t_flags & (TF_NEEDSYN|TF_NEEDFIN)) == 0) &&
	    ((to.to_flags & TOF_TS) == 0 ||
            TSTMP_GEQ(to.to_tsval, tp->ts_recent)) &&
	    th->th_seq == tp->rcv_nxt &&
	    LIST_EMPTY(&tp->t_segq)) {
		if (tp->iaj_pktcnt <= IAJ_IGNORE_PKTCNT) {
			tp->iaj_pktcnt++;
		}

		if ( tp->iaj_size == 0 || tlen > tp->iaj_size ||
			(tlen == tp->iaj_size && tp->iaj_rcv_ts == 0)) {
			/* State related to inter-arrival jitter is uninitialized 
			 * or we are trying to find a good first packet to start 
			 * computing the metric
			 */
			update_iaj_state(tp, tlen, 0);
		} else {
			if (tlen == tp->iaj_size) {
				/* Compute inter-arrival jitter taking this packet 
				 * as the second packet
				 */
				compute_iaj(tp);
			} 
			if (tlen  < tp->iaj_size) {
				/* There is a smaller packet in the stream.
				 * Some times the maximum size supported on a path can 
				 * change if there is a new link with smaller MTU. 
				 * The receiver will not know about this change. 
				 * If there are too many packets smaller than iaj_size, 
				 * we try to learn the iaj_size again.
				 */
				tp->iaj_small_pkt++;
				if (tp->iaj_small_pkt > RESET_IAJ_SIZE_THRESH) {
					update_iaj_state(tp, tlen, 1);
				} else {
					clear_iaj_state(tp);
				}
			} else {
				update_iaj_state(tp, tlen, 0);
			}
		}
	} else {
		clear_iaj_state(tp);
	}
#endif /* TRAFFIC_MGT */

	/*
	 * Header prediction: check for the two common cases
	 * of a uni-directional data xfer.  If the packet has
	 * no control flags, is in-sequence, the window didn't
	 * change and we're not retransmitting, it's a
	 * candidate.  If the length is zero and the ack moved
	 * forward, we're the sender side of the xfer.  Just
	 * free the data acked & wake any higher level process
	 * that was blocked waiting for space.  If the length
	 * is non-zero and the ack didn't move, we're the
	 * receiver side.  If we're getting packets in-order
	 * (the reassembly queue is empty), add the data to
	 * the socket buffer and note that we need a delayed ack.
	 * Make sure that the hidden state-flags are also off.
	 * Since we check for TCPS_ESTABLISHED above, it can only
	 * be TH_NEEDSYN.
	 */
	if (tp->t_state == TCPS_ESTABLISHED &&
	    (thflags & (TH_SYN|TH_FIN|TH_RST|TH_URG|TH_ACK|TH_ECE)) == TH_ACK &&
	    ((tp->t_flags & (TF_NEEDSYN|TF_NEEDFIN)) == 0) &&
	    ((to.to_flags & TOF_TS) == 0 ||
	     TSTMP_GEQ(to.to_tsval, tp->ts_recent)) &&
	    th->th_seq == tp->rcv_nxt &&
	    tiwin && tiwin == tp->snd_wnd &&
	    tp->snd_nxt == tp->snd_max) {

		/*
		 * If last ACK falls within this segment's sequence numbers,
		 * record the timestamp.
		 * NOTE that the test is modified according to the latest
		 * proposal of the tcplw@cray.com list (Braden 1993/04/26).
		 */
		if ((to.to_flags & TOF_TS) != 0 &&
		   SEQ_LEQ(th->th_seq, tp->last_ack_sent)) {
			tp->ts_recent_age = tcp_now;
			tp->ts_recent = to.to_tsval;
		}

		/* Force acknowledgment if we received a FIN */

		if (thflags & TH_FIN)
			tp->t_flags |= TF_ACKNOW;

		if (tlen == 0) {
			if (SEQ_GT(th->th_ack, tp->snd_una) &&
			    SEQ_LEQ(th->th_ack, tp->snd_max) &&
			    tp->snd_cwnd >= tp->snd_ssthresh &&
			    (!IN_FASTRECOVERY(tp) && 
			    ((!tp->sack_enable && tp->t_dupacks < tcprexmtthresh) ||
			     (tp->sack_enable && to.to_nsacks == 0 &&
			      TAILQ_EMPTY(&tp->snd_holes))))) {
				/*
				 * this is a pure ack for outstanding data.
				 */
				++tcpstat.tcps_predack;
				/*
				 * "bad retransmit" recovery
				 */
				if (tp->t_rxtshift == 1 &&
				    TSTMP_LT(tcp_now, tp->t_badrxtwin)) {
					++tcpstat.tcps_sndrexmitbad;
					tp->snd_cwnd = tp->snd_cwnd_prev;
					tp->snd_ssthresh =
					    tp->snd_ssthresh_prev;
					tp->snd_recover = tp->snd_recover_prev;
					if (tp->t_flags & TF_WASFRECOVERY)
					    ENTER_FASTRECOVERY(tp);
					tp->snd_nxt = tp->snd_max;
					tp->t_badrxtwin = 0;
					tp->t_rxtshift = 0;
					tp->rxt_start = 0;
					DTRACE_TCP5(cc, void, NULL, struct inpcb *, tp->t_inpcb,
						struct tcpcb *, tp, struct tcphdr *, th,
						int32_t, TCP_CC_BAD_REXMT_RECOVERY);
				}
				/*
				 * Recalculate the transmit timer / rtt.
				 *
				 * Some boxes send broken timestamp replies
				 * during the SYN+ACK phase, ignore
				 * timestamps of 0 or we could calculate a
				 * huge RTT and blow up the retransmit timer.
				 */
				if (((to.to_flags & TOF_TS) != 0) && (to.to_tsecr != 0) &&
					TSTMP_GEQ(tcp_now, to.to_tsecr)) { 
					tcp_xmit_timer(tp,
					    tcp_now - to.to_tsecr);
				} else if (tp->t_rtttime &&
					    SEQ_GT(th->th_ack, tp->t_rtseq)) {
					tcp_xmit_timer(tp, tcp_now - tp->t_rtttime);
				}
				acked = th->th_ack - tp->snd_una;
				tcpstat.tcps_rcvackpack++;
				tcpstat.tcps_rcvackbyte += acked;
				
				/* Handle an ack that is in sequence during congestion
				 * avoidance phase. The calculations in this function 
				 * assume that snd_una is not updated yet. 
				 */
				if (CC_ALGO(tp)->inseq_ack_rcvd != NULL)
					CC_ALGO(tp)->inseq_ack_rcvd(tp, th);

				DTRACE_TCP5(cc, void, NULL, struct inpcb *, inp,
					struct tcpcb *, tp, struct tcphdr *, th,
					int32_t, TCP_CC_INSEQ_ACK_RCVD);

				sbdrop(&so->so_snd, acked);
				if (SEQ_GT(tp->snd_una, tp->snd_recover) &&
				    SEQ_LEQ(th->th_ack, tp->snd_recover))
					tp->snd_recover = th->th_ack - 1;
				tp->snd_una = th->th_ack;
				/*
				 * pull snd_wl2 up to prevent seq wrap relative
				 * to th_ack.
				 */
				tp->snd_wl2 = th->th_ack;
				tp->t_dupacks = 0;
				m_freem(m);
				ND6_HINT(tp); /* some progress has been done */

				/*
				 * If all outstanding data are acked, stop
				 * retransmit timer, otherwise restart timer
				 * using current (possibly backed-off) value.
				 * If process is waiting for space,
				 * wakeup/selwakeup/signal.  If data
				 * are ready to send, let tcp_output
				 * decide between more output or persist.
				 */
				if (tp->snd_una == tp->snd_max)
					tp->t_timer[TCPT_REXMT] = 0;
				else if (tp->t_timer[TCPT_PERSIST] == 0)
					tp->t_timer[TCPT_REXMT] = OFFSET_FROM_START(tp, tp->t_rxtcur);

				sowwakeup(so); /* has to be done with socket lock held */
				if ((so->so_snd.sb_cc) || (tp->t_flags & TF_ACKNOW)) {
					(void) tcp_output(tp);
				}

				tcp_check_timer_state(tp);
				tcp_unlock(so, 1, 0);
				KERNEL_DEBUG(DBG_FNC_TCP_INPUT | DBG_FUNC_END,0,0,0,0,0);
				return;
			}
		} else if (th->th_ack == tp->snd_una &&
		    LIST_EMPTY(&tp->t_segq) &&
		    tlen <= tcp_sbspace(tp)) {
			/*
			 * this is a pure, in-sequence data packet
			 * with nothing on the reassembly queue and
			 * we have enough buffer space to take it.
			 */
			/* Clean receiver SACK report if present */
			if (tp->sack_enable && tp->rcv_numsacks)
				tcp_clean_sackreport(tp);
			++tcpstat.tcps_preddat;
			tp->rcv_nxt += tlen;
			/*
			 * Pull snd_wl1 up to prevent seq wrap relative to
			 * th_seq.
			 */
			tp->snd_wl1 = th->th_seq;
			/*
			 * Pull rcv_up up to prevent seq wrap relative to
			 * rcv_nxt.
			 */
			tp->rcv_up = tp->rcv_nxt;
			tcpstat.tcps_rcvpack++;
			tcpstat.tcps_rcvbyte += tlen;
			if (nstat_collect) {
				locked_add_64(&inp->inp_stat->rxpackets, 1);
				locked_add_64(&inp->inp_stat->rxbytes, tlen);
			}
			ND6_HINT(tp);	/* some progress has been done */
			/*
			 * Add data to socket buffer.
			 */
			so_recv_data_stat(so, m, 0);
			m_adj(m, drop_hdrlen);	/* delayed header drop */
			if (sbappendstream(&so->so_rcv, m))
				sorwakeup(so);
#if INET6
			if (isipv6) {
				KERNEL_DEBUG(DBG_LAYER_END, ((th->th_dport << 16) | th->th_sport),
		     			(((ip6->ip6_src.s6_addr16[0]) << 16) | (ip6->ip6_dst.s6_addr16[0])),
			     		th->th_seq, th->th_ack, th->th_win); 
			}
			else
#endif 
			{
				KERNEL_DEBUG(DBG_LAYER_END, ((th->th_dport << 16) | th->th_sport),
		     			(((ip->ip_src.s_addr & 0xffff) << 16) | (ip->ip_dst.s_addr & 0xffff)),
			     		th->th_seq, th->th_ack, th->th_win); 
			}
			if (DELAY_ACK(tp, th))  {
				if ((tp->t_flags & TF_DELACK) == 0) {
			    		tp->t_flags |= TF_DELACK;
					tp->t_timer[TCPT_DELACK] = OFFSET_FROM_START(tp, tcp_delack);
				}
			    	tp->t_unacksegs++;
			} else {
				tp->t_flags |= TF_ACKNOW;
				tcp_output(tp);
			}
			tcp_check_timer_state(tp);
			tcp_unlock(so, 1, 0);
			KERNEL_DEBUG(DBG_FNC_TCP_INPUT | DBG_FUNC_END,0,0,0,0,0);
			return;
		}
	}

	/*
	 * Calculate amount of space in receive window,
	 * and then do TCP input processing.
	 * Receive window is amount of space in rcv queue,
	 * but not less than advertised window.
	 */
	lck_mtx_assert(&((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_OWNED);

	{ int win;

	win = tcp_sbspace(tp);

	if (win < 0)
		win = 0;
	else {	/* clip rcv window to 4K for modems */
		if (tp->t_flags & TF_SLOWLINK && slowlink_wsize > 0)
			win = min(win, slowlink_wsize);
	}
	tp->rcv_wnd = imax(win, (int)(tp->rcv_adv - tp->rcv_nxt));
	}

	switch (tp->t_state) {

	/*
	 * Initialize tp->rcv_nxt, and tp->irs, select an initial
	 * tp->iss, and send a segment:
	 *     <SEQ=ISS><ACK=RCV_NXT><CTL=SYN,ACK>
	 * Also initialize tp->snd_nxt to tp->iss+1 and tp->snd_una to tp->iss.
	 * Fill in remote peer address fields if not previously specified.
	 * Enter SYN_RECEIVED state, and process any other fields of this
	 * segment in this state.
	 */
	case TCPS_LISTEN: {
		register struct sockaddr_in *sin;
#if INET6
		register struct sockaddr_in6 *sin6;
#endif

		lck_mtx_assert(&((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_OWNED);
#if INET6
		if (isipv6) {
			MALLOC(sin6, struct sockaddr_in6 *, sizeof *sin6,
			       M_SONAME, M_NOWAIT);
			if (sin6 == NULL)
				goto drop;
			bzero(sin6, sizeof(*sin6));
			sin6->sin6_family = AF_INET6;
			sin6->sin6_len = sizeof(*sin6);
			sin6->sin6_addr = ip6->ip6_src;
			sin6->sin6_port = th->th_sport;
			laddr6 = inp->in6p_laddr;
			if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr))
				inp->in6p_laddr = ip6->ip6_dst;
			if (in6_pcbconnect(inp, (struct sockaddr *)sin6,
					   proc0)) {
				inp->in6p_laddr = laddr6;
				FREE(sin6, M_SONAME);
				goto drop;
			}
			FREE(sin6, M_SONAME);
		} else
#endif
	    {
			lck_mtx_assert(&((struct inpcb *)so->so_pcb)->inpcb_mtx, LCK_MTX_ASSERT_OWNED);
			MALLOC(sin, struct sockaddr_in *, sizeof *sin, M_SONAME,
		       M_NOWAIT);
			if (sin == NULL)
				goto drop;
			sin->sin_family = AF_INET;
			sin->sin_len = sizeof(*sin);
			sin->sin_addr = ip->ip_src;
			sin->sin_port = th->th_sport;
			bzero((caddr_t)sin->sin_zero, sizeof(sin->sin_zero));
			laddr = inp->inp_laddr;
			if (inp->inp_laddr.s_addr == INADDR_ANY)
				inp->inp_laddr = ip->ip_dst;
			if (in_pcbconnect(inp, (struct sockaddr *)sin, proc0, NULL)) {
				inp->inp_laddr = laddr;
				FREE(sin, M_SONAME);
				goto drop;
			}
			FREE(sin, M_SONAME);
		}

		tcp_dooptions(tp, optp, optlen, th, &to, ifscope);

		if (tp->sack_enable) {
			if (!(to.to_flags & TOF_SACK))
				tp->sack_enable = 0;
			else
				tp->t_flags |= TF_SACK_PERMIT;
		}
		
		if (iss)
			tp->iss = iss;
		else {
			tp->iss = tcp_new_isn(tp);
 		}
		tp->irs = th->th_seq;
		tcp_sendseqinit(tp);
		tcp_rcvseqinit(tp);
		tp->snd_recover = tp->snd_una;
		/*
		 * Initialization of the tcpcb for transaction;
		 *   set SND.WND = SEG.WND,
		 *   initialize CCsend and CCrecv.
		 */
		tp->snd_wnd = tiwin;	/* initial send-window */
		tp->t_flags |= TF_ACKNOW;
		tp->t_unacksegs = 0;
		DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
			struct tcpcb *, tp, int32_t, TCPS_SYN_RECEIVED);
		tp->t_state = TCPS_SYN_RECEIVED;
		tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(tp, 
			tp->t_keepinit ? tp->t_keepinit : tcp_keepinit);
		dropsocket = 0;		/* committed to socket */

		/* reset the incomp processing flag */
		so->so_flags &= ~(SOF_INCOMP_INPROGRESS);
		tcpstat.tcps_accepts++;
		if ((thflags & (TH_ECE | TH_CWR)) == (TH_ECE | TH_CWR)) {
			/* ECN-setup SYN */
			tp->ecn_flags |= (TE_SETUPRECEIVED | TE_SENDIPECT);
		}
#if CONFIG_IFEF_NOWINDOWSCALE
		if (tcp_obey_ifef_nowindowscale && m->m_pkthdr.rcvif != NULL &&
		    (m->m_pkthdr.rcvif->if_eflags & IFEF_NOWINDOWSCALE)) {
			/* Window scaling is not enabled on this interface */
			tp->t_flags &= ~TF_REQ_SCALE;
		}
#endif
		goto trimthenstep6;
		}

	/*
	 * If the state is SYN_RECEIVED:
	 *	if seg contains an ACK, but not for our SYN/ACK, send a RST.
	 */
	case TCPS_SYN_RECEIVED:
		if ((thflags & TH_ACK) &&
		    (SEQ_LEQ(th->th_ack, tp->snd_una) ||
		     SEQ_GT(th->th_ack, tp->snd_max))) {
				rstreason = BANDLIM_RST_OPENPORT;
				goto dropwithreset;
		}
		break;

	/*
	 * If the state is SYN_SENT:
	 *	if seg contains an ACK, but not for our SYN, drop the input.
	 *	if seg contains a RST, then drop the connection.
	 *	if seg does not contain SYN, then drop it.
	 * Otherwise this is an acceptable SYN segment
	 *	initialize tp->rcv_nxt and tp->irs
	 *	if seg contains ack then advance tp->snd_una
	 *	if SYN has been acked change to ESTABLISHED else SYN_RCVD state
	 *	arrange for segment to be acked (eventually)
	 *	continue processing rest of data/controls, beginning with URG
	 */
	case TCPS_SYN_SENT:
		if ((thflags & TH_ACK) &&
		    (SEQ_LEQ(th->th_ack, tp->iss) ||
		     SEQ_GT(th->th_ack, tp->snd_max))) {
			rstreason = BANDLIM_UNLIMITED;
			goto dropwithreset;
		}
		if (thflags & TH_RST) {
			if ((thflags & TH_ACK) != 0) {
				tp = tcp_drop(tp, ECONNREFUSED);
				postevent(so, 0, EV_RESET);
			}
			goto drop;
		}
		if ((thflags & TH_SYN) == 0)
			goto drop;
		tp->snd_wnd = th->th_win;	/* initial send window */

		tp->irs = th->th_seq;
		tcp_rcvseqinit(tp);
		if (thflags & TH_ACK) {
			tcpstat.tcps_connects++;
			
			if ((thflags & (TH_ECE | TH_CWR)) == (TH_ECE)) {
				/* ECN-setup SYN-ACK */
				tp->ecn_flags |= TE_SETUPRECEIVED;
			}
			else {
				/* non-ECN-setup SYN-ACK */
				tp->ecn_flags &= ~TE_SENDIPECT;
			}
			
#if CONFIG_MACF_NET && CONFIG_MACF_SOCKET
			/* XXXMAC: recursive lock: SOCK_LOCK(so); */
			mac_socketpeer_label_associate_mbuf(m, so);
			/* XXXMAC: SOCK_UNLOCK(so); */
#endif
			/* Do window scaling on this connection? */
			if ((tp->t_flags & (TF_RCVD_SCALE|TF_REQ_SCALE)) ==
				(TF_RCVD_SCALE|TF_REQ_SCALE)) {
				tp->snd_scale = tp->requested_s_scale;
				tp->rcv_scale = tp->request_r_scale;
			}
			tp->rcv_adv += tp->rcv_wnd;
			tp->snd_una++;		/* SYN is acked */
			/*
			 * If there's data, delay ACK; if there's also a FIN
			 * ACKNOW will be turned on later.
			 */
			if (DELAY_ACK(tp, th) && tlen != 0) {
				if ((tp->t_flags & TF_DELACK) == 0) {
					tp->t_flags |= TF_DELACK;
					tp->t_timer[TCPT_DELACK] = OFFSET_FROM_START(tp, tcp_delack);
				}
			    	tp->t_unacksegs++;
			}
			else {
				tp->t_flags |= TF_ACKNOW;
			}
			/*
			 * Received <SYN,ACK> in SYN_SENT[*] state.
			 * Transitions:
			 *	SYN_SENT  --> ESTABLISHED
			 *	SYN_SENT* --> FIN_WAIT_1
			 */
			tp->t_starttime = tcp_now;
			if (tp->t_flags & TF_NEEDFIN) {
				DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
					struct tcpcb *, tp, int32_t, TCPS_FIN_WAIT_1);
				tp->t_state = TCPS_FIN_WAIT_1;
				tp->t_flags &= ~TF_NEEDFIN;
				thflags &= ~TH_SYN;
			} else {
				DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
					struct tcpcb *, tp, int32_t, TCPS_ESTABLISHED);
				tp->t_state = TCPS_ESTABLISHED;
				tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(tp, TCP_KEEPIDLE(tp));
				if (nstat_collect)
					nstat_route_connect_success(tp->t_inpcb->inp_route.ro_rt);
			}
			isconnected = TRUE;
		} else {
			/*
			 *  Received initial SYN in SYN-SENT[*] state => simul-
		  	 *  taneous open.  If segment contains CC option and there is
			 *  a cached CC, apply TAO test; if it succeeds, connection is
			 *  half-synchronized.  Otherwise, do 3-way handshake:
			 *        SYN-SENT -> SYN-RECEIVED
			 *        SYN-SENT* -> SYN-RECEIVED*
			 */
			tp->t_flags |= TF_ACKNOW;
			tp->t_timer[TCPT_REXMT] = 0;
			DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
				struct tcpcb *, tp, int32_t, TCPS_SYN_RECEIVED);
			tp->t_state = TCPS_SYN_RECEIVED;

		}

trimthenstep6:
		/*
		 * Advance th->th_seq to correspond to first data byte.
		 * If data, trim to stay within window,
		 * dropping FIN if necessary.
		 */
		th->th_seq++;
		if (tlen > tp->rcv_wnd) {
			todrop = tlen - tp->rcv_wnd;
			m_adj(m, -todrop);
			tlen = tp->rcv_wnd;
			thflags &= ~TH_FIN;
			tcpstat.tcps_rcvpackafterwin++;
			tcpstat.tcps_rcvbyteafterwin += todrop;
		}
		tp->snd_wl1 = th->th_seq - 1;
		tp->rcv_up = th->th_seq;
		/*
		 *  Client side of transaction: already sent SYN and data.
		 *  If the remote host used T/TCP to validate the SYN,
		 *  our data will be ACK'd; if so, enter normal data segment
		 *  processing in the middle of step 5, ack processing.
		 *  Otherwise, goto step 6.
		 */
 		if (thflags & TH_ACK)
			goto process_ACK;
		goto step6;
	/*
	 * If the state is LAST_ACK or CLOSING or TIME_WAIT:
	 *      do normal processing.
	 *
	 * NB: Leftover from RFC1644 T/TCP.  Cases to be reused later.
	 */
	case TCPS_LAST_ACK:
	case TCPS_CLOSING:
	case TCPS_TIME_WAIT:
 		break;  /* continue normal processing */

	/* Received a SYN while connection is already established.
	 * This is a "half open connection and other anomalies" described
	 * in RFC793 page 34, send an ACK so the remote reset the connection
	 * or recovers by adjusting its sequence numberering 
	 */
	case TCPS_ESTABLISHED:
		if (thflags & TH_SYN)  
			goto dropafterack; 
		break;
	}

	/*
	 * States other than LISTEN or SYN_SENT.
	 * First check the RST flag and sequence number since reset segments
	 * are exempt from the timestamp and connection count tests.  This
	 * fixes a bug introduced by the Stevens, vol. 2, p. 960 bugfix
	 * below which allowed reset segments in half the sequence space
	 * to fall though and be processed (which gives forged reset
	 * segments with a random sequence number a 50 percent chance of
	 * killing a connection).
	 * Then check timestamp, if present.
	 * Then check the connection count, if present.
	 * Then check that at least some bytes of segment are within
	 * receive window.  If segment begins before rcv_nxt,
	 * drop leading data (and SYN); if nothing left, just ack.
	 *
	 *
	 * If the RST bit is set, check the sequence number to see
	 * if this is a valid reset segment.
	 * RFC 793 page 37:
	 *   In all states except SYN-SENT, all reset (RST) segments
	 *   are validated by checking their SEQ-fields.  A reset is
	 *   valid if its sequence number is in the window.
	 * Note: this does not take into account delayed ACKs, so
	 *   we should test against last_ack_sent instead of rcv_nxt.
	 *   The sequence number in the reset segment is normally an
	 *   echo of our outgoing acknowlegement numbers, but some hosts
	 *   send a reset with the sequence number at the rightmost edge
	 *   of our receive window, and we have to handle this case.
	 * Note 2: Paul Watson's paper "Slipping in the Window" has shown
	 *   that brute force RST attacks are possible.  To combat this,
	 *   we use a much stricter check while in the ESTABLISHED state,
	 *   only accepting RSTs where the sequence number is equal to
	 *   last_ack_sent.  In all other states (the states in which a
	 *   RST is more likely), the more permissive check is used.
	 * If we have multiple segments in flight, the intial reset
	 * segment sequence numbers will be to the left of last_ack_sent,
	 * but they will eventually catch up.
	 * In any case, it never made sense to trim reset segments to
	 * fit the receive window since RFC 1122 says:
	 *   4.2.2.12  RST Segment: RFC-793 Section 3.4
	 *
	 *    A TCP SHOULD allow a received RST segment to include data.
	 *
	 *    DISCUSSION
	 *         It has been suggested that a RST segment could contain
	 *         ASCII text that encoded and explained the cause of the
	 *         RST.  No standard has yet been established for such
	 *         data.
	 *
	 * If the reset segment passes the sequence number test examine
	 * the state:
	 *    SYN_RECEIVED STATE:
	 *	If passive open, return to LISTEN state.
	 *	If active open, inform user that connection was refused.
	 *    ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT STATES:
	 *	Inform user that connection was reset, and close tcb.
	 *    CLOSING, LAST_ACK STATES:
	 *	Close the tcb.
	 *    TIME_WAIT STATE:
	 *	Drop the segment - see Stevens, vol. 2, p. 964 and
	 *      RFC 1337.
	 *
	 *      Radar 4803931: Allows for the case where we ACKed the FIN but
	 *                     there is already a RST in flight from the peer.
	 *                     In that case, accept the RST for non-established
	 *                     state if it's one off from last_ack_sent.

	 */
	if (thflags & TH_RST) {
		if ((SEQ_GEQ(th->th_seq, tp->last_ack_sent) &&
		    SEQ_LT(th->th_seq, tp->last_ack_sent + tp->rcv_wnd)) ||
		    (tp->rcv_wnd == 0 && 
		     	((tp->last_ack_sent == th->th_seq) || ((tp->last_ack_sent -1) == th->th_seq)))) {
			switch (tp->t_state) {

			case TCPS_SYN_RECEIVED:
				so->so_error = ECONNREFUSED;
				goto close;

			case TCPS_ESTABLISHED:
				if (tp->last_ack_sent != th->th_seq) {
					tcpstat.tcps_badrst++;
					goto drop;
				}
			case TCPS_FIN_WAIT_1:
			case TCPS_CLOSE_WAIT:
				/*
				  Drop through ...
				*/
			case TCPS_FIN_WAIT_2:
				so->so_error = ECONNRESET;
			close:
				postevent(so, 0, EV_RESET);
				DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
					struct tcpcb *, tp, int32_t, TCPS_CLOSED);
				tp->t_state = TCPS_CLOSED;
				tcpstat.tcps_drops++;
				tp = tcp_close(tp);
				break;

			case TCPS_CLOSING:
			case TCPS_LAST_ACK:
				tp = tcp_close(tp);
				break;

			case TCPS_TIME_WAIT:
				break;
			}
		}
		goto drop;
	}

	/*
	 * RFC 1323 PAWS: If we have a timestamp reply on this segment
	 * and it's less than ts_recent, drop it.
	 */
	if ((to.to_flags & TOF_TS) != 0 && tp->ts_recent &&
	    TSTMP_LT(to.to_tsval, tp->ts_recent)) {

		/* Check to see if ts_recent is over 24 days old.  */
		if ((int)(tcp_now - tp->ts_recent_age) > TCP_PAWS_IDLE) {
			/*
			 * Invalidate ts_recent.  If this segment updates
			 * ts_recent, the age will be reset later and ts_recent
			 * will get a valid value.  If it does not, setting
			 * ts_recent to zero will at least satisfy the
			 * requirement that zero be placed in the timestamp
			 * echo reply when ts_recent isn't valid.  The
			 * age isn't reset until we get a valid ts_recent
			 * because we don't want out-of-order segments to be
			 * dropped when ts_recent is old.
			 */
			tp->ts_recent = 0;
		} else {
			tcpstat.tcps_rcvduppack++;
			tcpstat.tcps_rcvdupbyte += tlen;
			tcpstat.tcps_pawsdrop++;
			if (nstat_collect) {
				nstat_route_rx(tp->t_inpcb->inp_route.ro_rt, 1, tlen, NSTAT_RX_FLAG_DUPLICATE);
				locked_add_64(&inp->inp_stat->rxpackets, 1);
				locked_add_64(&inp->inp_stat->rxbytes, tlen);
				tp->t_stat.rxduplicatebytes += tlen;
			}
			if (tlen)
				goto dropafterack;
			goto drop;
		}
	}

	/*
	 * In the SYN-RECEIVED state, validate that the packet belongs to
	 * this connection before trimming the data to fit the receive
	 * window.  Check the sequence number versus IRS since we know
	 * the sequence numbers haven't wrapped.  This is a partial fix
	 * for the "LAND" DoS attack.
	 */
	if (tp->t_state == TCPS_SYN_RECEIVED && SEQ_LT(th->th_seq, tp->irs)) {
		rstreason = BANDLIM_RST_OPENPORT;
		goto dropwithreset;
	}

	todrop = tp->rcv_nxt - th->th_seq;
	if (todrop > 0) {
		if (thflags & TH_SYN) {
			thflags &= ~TH_SYN;
			th->th_seq++;
			if (th->th_urp > 1)
				th->th_urp--;
			else
				thflags &= ~TH_URG;
			todrop--;
		}
		/*
		 * Following if statement from Stevens, vol. 2, p. 960.
		 */
		if (todrop > tlen
		    || (todrop == tlen && (thflags & TH_FIN) == 0)) {
			/*
			 * Any valid FIN must be to the left of the window.
			 * At this point the FIN must be a duplicate or out
			 * of sequence; drop it.
			 */
			thflags &= ~TH_FIN;

			/*
			 * Send an ACK to resynchronize and drop any data.
			 * But keep on processing for RST or ACK.
			 */
			tp->t_flags |= TF_ACKNOW;
			todrop = tlen;
			tcpstat.tcps_rcvduppack++;
			tcpstat.tcps_rcvdupbyte += todrop;
		} else {
			tcpstat.tcps_rcvpartduppack++;
			tcpstat.tcps_rcvpartdupbyte += todrop;
		}
		if (nstat_collect) {
			nstat_route_rx(tp->t_inpcb->inp_route.ro_rt, 1, todrop, NSTAT_RX_FLAG_DUPLICATE);
			locked_add_64(&inp->inp_stat->rxpackets, 1);
			locked_add_64(&inp->inp_stat->rxbytes, todrop);
			tp->t_stat.rxduplicatebytes += todrop;
		}
		drop_hdrlen += todrop;	/* drop from the top afterwards */
		th->th_seq += todrop;
		tlen -= todrop;
		if (th->th_urp > todrop)
			th->th_urp -= todrop;
		else {
			thflags &= ~TH_URG;
			th->th_urp = 0;
		}
	}

	/*
	 * If new data are received on a connection after the
	 * user processes are gone, then RST the other end.
	 */
	if ((so->so_state & SS_NOFDREF) &&
	    tp->t_state > TCPS_CLOSE_WAIT && tlen) {
		tp = tcp_close(tp);
		tcpstat.tcps_rcvafterclose++;
		rstreason = BANDLIM_UNLIMITED;
		goto dropwithreset;
	}

	/*
	 * If segment ends after window, drop trailing data
	 * (and PUSH and FIN); if nothing left, just ACK.
	 */
	todrop = (th->th_seq+tlen) - (tp->rcv_nxt+tp->rcv_wnd);
	if (todrop > 0) {
		tcpstat.tcps_rcvpackafterwin++;
		if (todrop >= tlen) {
			tcpstat.tcps_rcvbyteafterwin += tlen;
			/*
			 * If a new connection request is received
			 * while in TIME_WAIT, drop the old connection
			 * and start over if the sequence numbers
			 * are above the previous ones.
			 */
			if (thflags & TH_SYN &&
			    tp->t_state == TCPS_TIME_WAIT &&
			    SEQ_GT(th->th_seq, tp->rcv_nxt)) {
				iss = tcp_new_isn(tp);
				tp = tcp_close(tp);
				tcp_unlock(so, 1, 0);
				goto findpcb;
			}
			/*
			 * If window is closed can only take segments at
			 * window edge, and have to drop data and PUSH from
			 * incoming segments.  Continue processing, but
			 * remember to ack.  Otherwise, drop segment
			 * and ack.
			 */
			if (tp->rcv_wnd == 0 && th->th_seq == tp->rcv_nxt) {
				tp->t_flags |= TF_ACKNOW;
				tcpstat.tcps_rcvwinprobe++;
			} else
				goto dropafterack;
		} else
			tcpstat.tcps_rcvbyteafterwin += todrop;
		m_adj(m, -todrop);
		tlen -= todrop;
		thflags &= ~(TH_PUSH|TH_FIN);
	}

	/*
	 * If last ACK falls within this segment's sequence numbers,
	 * record its timestamp.
	 * NOTE: 
	 * 1) That the test incorporates suggestions from the latest
	 *    proposal of the tcplw@cray.com list (Braden 1993/04/26).
	 * 2) That updating only on newer timestamps interferes with
	 *    our earlier PAWS tests, so this check should be solely
	 *    predicated on the sequence space of this segment.
	 * 3) That we modify the segment boundary check to be 
	 *        Last.ACK.Sent <= SEG.SEQ + SEG.Len  
	 *    instead of RFC1323's
	 *        Last.ACK.Sent < SEG.SEQ + SEG.Len,
	 *    This modified check allows us to overcome RFC1323's
	 *    limitations as described in Stevens TCP/IP Illustrated
	 *    Vol. 2 p.869. In such cases, we can still calculate the
	 *    RTT correctly when RCV.NXT == Last.ACK.Sent.
	 */
	if ((to.to_flags & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent) &&
	    SEQ_LEQ(tp->last_ack_sent, th->th_seq + tlen +
		((thflags & (TH_SYN|TH_FIN)) != 0))) {
		tp->ts_recent_age = tcp_now;
		tp->ts_recent = to.to_tsval;
	}

	/*
	 * If a SYN is in the window, then this is an
	 * error and we send an RST and drop the connection.
	 */
	if (thflags & TH_SYN) {
		tp = tcp_drop(tp, ECONNRESET);
		rstreason = BANDLIM_UNLIMITED;
		postevent(so, 0, EV_RESET);
		goto dropwithreset;
	}

	/*
	 * If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN
	 * flag is on (half-synchronized state), then queue data for
	 * later processing; else drop segment and return.
	 */
	if ((thflags & TH_ACK) == 0) {
		if (tp->t_state == TCPS_SYN_RECEIVED ||
		    (tp->t_flags & TF_NEEDSYN))
			goto step6;
		else if (tp->t_flags & TF_ACKNOW)
			goto dropafterack;
		else
			goto drop;
	}

	/*
	 * Ack processing.
	 */
	switch (tp->t_state) {

	/*
	 * In SYN_RECEIVED state, the ack ACKs our SYN, so enter
	 * ESTABLISHED state and continue processing.
	 * The ACK was checked above.
	 */
	case TCPS_SYN_RECEIVED:

		tcpstat.tcps_connects++;

		/* Do window scaling? */
		if ((tp->t_flags & (TF_RCVD_SCALE|TF_REQ_SCALE)) ==
			(TF_RCVD_SCALE|TF_REQ_SCALE)) {
			tp->snd_scale = tp->requested_s_scale;
			tp->rcv_scale = tp->request_r_scale;
			tp->snd_wnd = th->th_win << tp->snd_scale;
			tiwin = tp->snd_wnd;
		}
		/*
		 * Make transitions:
		 *      SYN-RECEIVED  -> ESTABLISHED
		 *      SYN-RECEIVED* -> FIN-WAIT-1
		 */
		tp->t_starttime = tcp_now;
		if (tp->t_flags & TF_NEEDFIN) {
			DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
				struct tcpcb *, tp, int32_t, TCPS_FIN_WAIT_1);
			tp->t_state = TCPS_FIN_WAIT_1;
			tp->t_flags &= ~TF_NEEDFIN;
		} else {
			DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
				struct tcpcb *, tp, int32_t, TCPS_ESTABLISHED);
			tp->t_state = TCPS_ESTABLISHED;
			tp->t_timer[TCPT_KEEP] = OFFSET_FROM_START(tp, TCP_KEEPIDLE(tp));
			if (nstat_collect)
				nstat_route_connect_success(tp->t_inpcb->inp_route.ro_rt);
		}
		/*
		 * If segment contains data or ACK, will call tcp_reass()
		 * later; if not, do so now to pass queued data to user.
		 */
		if (tlen == 0 && (thflags & TH_FIN) == 0)
			(void) tcp_reass(tp, (struct tcphdr *)0, &tlen,
			    (struct mbuf *)0);
		tp->snd_wl1 = th->th_seq - 1;

		/* FALLTHROUGH */

		isconnected = TRUE;

	/*
	 * In ESTABLISHED state: drop duplicate ACKs; ACK out of range
	 * ACKs.  If the ack is in the range
	 *	tp->snd_una < th->th_ack <= tp->snd_max
	 * then advance tp->snd_una to th->th_ack and drop
	 * data from the retransmission queue.  If this ACK reflects
	 * more up to date window information we update our window information.
	 */
	case TCPS_ESTABLISHED:
	case TCPS_FIN_WAIT_1:
	case TCPS_FIN_WAIT_2:
	case TCPS_CLOSE_WAIT:
	case TCPS_CLOSING:
	case TCPS_LAST_ACK:
	case TCPS_TIME_WAIT:
		if (SEQ_GT(th->th_ack, tp->snd_max)) {
			tcpstat.tcps_rcvacktoomuch++;
			goto dropafterack;
		}
		if (tp->sack_enable &&
		    (to.to_nsacks > 0 || !TAILQ_EMPTY(&tp->snd_holes)))
			tcp_sack_doack(tp, &to, th->th_ack);
		if (SEQ_LEQ(th->th_ack, tp->snd_una)) {
			if (tlen == 0 && tiwin == tp->snd_wnd) {
				tcpstat.tcps_rcvdupack++;
				/*
				 * If we have outstanding data (other than
				 * a window probe), this is a completely
				 * duplicate ack (ie, window info didn't
				 * change), the ack is the biggest we've
				 * seen and we've seen exactly our rexmt
				 * threshhold of them, assume a packet
				 * has been dropped and retransmit it.
				 * Kludge snd_nxt & the congestion
				 * window so we send only this one
				 * packet.
				 *
				 * We know we're losing at the current
				 * window size so do congestion avoidance
				 * (set ssthresh to half the current window
				 * and pull our congestion window back to
				 * the new ssthresh).
				 *
				 * Dup acks mean that packets have left the
				 * network (they're now cached at the receiver)
				 * so bump cwnd by the amount in the receiver
				 * to keep a constant cwnd packets in the
				 * network.
				 */
				if (tp->t_timer[TCPT_REXMT] == 0 ||
				    th->th_ack != tp->snd_una)
					tp->t_dupacks = 0;
				else if (++tp->t_dupacks > tcprexmtthresh ||
					  IN_FASTRECOVERY(tp)) {
					if (tp->sack_enable && IN_FASTRECOVERY(tp)) {
						int awnd;
						
						/*
						 * Compute the amount of data in flight first.
						 * We can inject new data into the pipe iff 
						 * we have less than 1/2 the original window's 	
						 * worth of data in flight.
						 */
						awnd = (tp->snd_nxt - tp->snd_fack) +
							tp->sackhint.sack_bytes_rexmit;
						if (awnd < tp->snd_ssthresh) {
							tp->snd_cwnd += tp->t_maxseg;
							if (tp->snd_cwnd > tp->snd_ssthresh)
								tp->snd_cwnd = tp->snd_ssthresh;
						}
					} else
						tp->snd_cwnd += tp->t_maxseg;

					DTRACE_TCP5(cc, void, NULL, struct inpcb *, inp,
						struct tcpcb *, tp, struct tcphdr *, th,
						int32_t, TCP_CC_IN_FASTRECOVERY);

					(void) tcp_output(tp);
					goto drop;
				} else if (tp->t_dupacks == tcprexmtthresh) {
					tcp_seq onxt = tp->snd_nxt;

					/*
					 * If we're doing sack, check to
					 * see if we're already in sack
					 * recovery. If we're not doing sack,
					 * check to see if we're in newreno
					 * recovery.
					 */
					if (tp->sack_enable) {
						if (IN_FASTRECOVERY(tp)) {
							tp->t_dupacks = 0;
							break;
						}
					} else {
						if (SEQ_LEQ(th->th_ack,
						    tp->snd_recover)) {
							tp->t_dupacks = 0;
							break;
						}
					}
					
					/*
					 * If the current tcp cc module has 
					 * defined a hook for tasks to run
					 * before entering FR, call it
					 */
					if (CC_ALGO(tp)->pre_fr != NULL)
						CC_ALGO(tp)->pre_fr(tp, th);
					ENTER_FASTRECOVERY(tp);
					tp->snd_recover = tp->snd_max;
					tp->t_timer[TCPT_REXMT] = 0;
					tp->t_rtttime = 0;
					tp->ecn_flags |= TE_SENDCWR;
					if (tp->sack_enable) {
						tcpstat.tcps_sack_recovery_episode++;
						tp->sack_newdata = tp->snd_nxt;
						tp->snd_cwnd = tp->t_maxseg;

						DTRACE_TCP5(cc, void, NULL, struct inpcb *, inp,
							struct tcpcb *, tp, struct tcphdr *, th,
							int32_t, TCP_CC_ENTER_FASTRECOVERY);

						(void) tcp_output(tp);
						goto drop;
					}
					tp->snd_nxt = th->th_ack;
					tp->snd_cwnd = tp->t_maxseg;
					(void) tcp_output(tp);
					tp->snd_cwnd = tp->snd_ssthresh +
					     tp->t_maxseg * tp->t_dupacks;
					if (SEQ_GT(onxt, tp->snd_nxt))
						tp->snd_nxt = onxt;
					DTRACE_TCP5(cc, void, NULL, struct inpcb *, inp,
						struct tcpcb *, tp, struct tcphdr *, th,
						int32_t, TCP_CC_ENTER_FASTRECOVERY);
					goto drop;
				}
			} else
				tp->t_dupacks = 0;
			break;
		}
		/*
		 * If the congestion window was inflated to account
		 * for the other side's cached packets, retract it.
		 */
		if (IN_FASTRECOVERY(tp)) {
			if (SEQ_LT(th->th_ack, tp->snd_recover)) {
				if (tp->sack_enable)
					tcp_sack_partialack(tp, th);
				else
					tcp_newreno_partial_ack(tp, th);			
				
				DTRACE_TCP5(cc, void, NULL, struct inpcb *, inp,
					struct tcpcb *, tp, struct tcphdr *, th,
					int32_t, TCP_CC_PARTIAL_ACK);
			} else {
				EXIT_FASTRECOVERY(tp);
				if (CC_ALGO(tp)->post_fr != NULL)
					CC_ALGO(tp)->post_fr(tp, th);
				tp->t_dupacks = 0;

				DTRACE_TCP5(cc, void, NULL, struct inpcb *, inp,
					struct tcpcb *, tp, struct tcphdr *, th,
					int32_t, TCP_CC_EXIT_FASTRECOVERY);
			}
		} else {
			/*
			 * We were not in fast recovery. Reset the duplicate ack
			 * counter.
			 */
			tp->t_dupacks = 0;
		}


		/*
		 * If we reach this point, ACK is not a duplicate,
		 *     i.e., it ACKs something we sent.
		 */
		if (tp->t_flags & TF_NEEDSYN) {
			/*
			 * T/TCP: Connection was half-synchronized, and our
			 * SYN has been ACK'd (so connection is now fully
			 * synchronized).  Go to non-starred state,
			 * increment snd_una for ACK of SYN, and check if
			 * we can do window scaling.
			 */
			tp->t_flags &= ~TF_NEEDSYN;
			tp->snd_una++;
			/* Do window scaling? */
			if ((tp->t_flags & (TF_RCVD_SCALE|TF_REQ_SCALE)) ==
				(TF_RCVD_SCALE|TF_REQ_SCALE)) {
				tp->snd_scale = tp->requested_s_scale;
				tp->rcv_scale = tp->request_r_scale;
			}
		}

process_ACK:
		acked = th->th_ack - tp->snd_una;
		tcpstat.tcps_rcvackpack++;
		tcpstat.tcps_rcvackbyte += acked;

		/*
		 * If we just performed our first retransmit, and the ACK
		 * arrives within our recovery window, then it was a mistake
		 * to do the retransmit in the first place.  Recover our
		 * original cwnd and ssthresh, and proceed to transmit where
		 * we left off.
		 */
		if (tp->t_rxtshift == 1 && 
			TSTMP_LT(tcp_now, tp->t_badrxtwin)) {
			++tcpstat.tcps_sndrexmitbad;
			tp->snd_cwnd = tp->snd_cwnd_prev;
			tp->snd_ssthresh = tp->snd_ssthresh_prev;
			tp->snd_recover = tp->snd_recover_prev;
			if (tp->t_flags & TF_WASFRECOVERY)
				ENTER_FASTRECOVERY(tp);
			tp->snd_nxt = tp->snd_max;
			tp->t_badrxtwin = 0;	/* XXX probably not required */ 
			tp->t_rxtshift = 0;
			tp->rxt_start = 0;

			DTRACE_TCP5(cc, void, NULL, struct inpcb *, inp,
				struct tcpcb *, tp, struct tcphdr *, th,
				int32_t, TCP_CC_BAD_REXMT_RECOVERY);
		}

		/*
		 * If we have a timestamp reply, update smoothed
		 * round trip time.  If no timestamp is present but
		 * transmit timer is running and timed sequence
		 * number was acked, update smoothed round trip time.
		 * Since we now have an rtt measurement, cancel the
		 * timer backoff (cf., Phil Karn's retransmit alg.).
		 * Recompute the initial retransmit timer.
		 * Also makes sure we have a valid time stamp in hand
		 *
		 * Some boxes send broken timestamp replies
		 * during the SYN+ACK phase, ignore
		 * timestamps of 0 or we could calculate a
		 * huge RTT and blow up the retransmit timer.
		 */
		if (((to.to_flags & TOF_TS) != 0) && (to.to_tsecr != 0) &&
			TSTMP_GEQ(tcp_now, to.to_tsecr)) {
			tcp_xmit_timer(tp, tcp_now - to.to_tsecr);
		} else if (tp->t_rtttime && SEQ_GT(th->th_ack, tp->t_rtseq)) {
			tcp_xmit_timer(tp, tcp_now - tp->t_rtttime);
		}

		/*
		 * If all outstanding data is acked, stop retransmit
		 * timer and remember to restart (more output or persist).
		 * If there is more data to be acked, restart retransmit
		 * timer, using current (possibly backed-off) value.
		 */
		if (th->th_ack == tp->snd_max) {
			tp->t_timer[TCPT_REXMT] = 0;
			needoutput = 1;
		} else if (tp->t_timer[TCPT_PERSIST] == 0)
			tp->t_timer[TCPT_REXMT] = OFFSET_FROM_START(tp, tp->t_rxtcur);

		/*
		 * If no data (only SYN) was ACK'd,
		 *    skip rest of ACK processing.
		 */
		if (acked == 0)
			goto step6;

		if ((thflags & TH_ECE) != 0 &&
			(tp->ecn_flags & TE_SETUPSENT) != 0) {
			/*
			 * Reduce the congestion window if we haven't done so.
			 */
			if (!tp->sack_enable && !IN_FASTRECOVERY(tp) &&
				SEQ_GEQ(th->th_ack, tp->snd_recover)) {
				tcp_reduce_congestion_window(tp, th);
				DTRACE_TCP5(cc, void, NULL, struct inpcb *, inp,
					struct tcpcb *, tp, struct tcphdr *, th, 
					int32_t, TCP_CC_ECN_RCVD);
			}
		}

		/*
		 * When new data is acked, open the congestion window.
		 * The specifics of how this is achieved are up to the
		 * congestion control algorithm in use for this connection.
		 *
		 * The calculations in this function assume that snd_una is
		 * not updated yet.
		 */
		if (!IN_FASTRECOVERY(tp)) {
			if (CC_ALGO(tp)->ack_rcvd != NULL)
				CC_ALGO(tp)->ack_rcvd(tp, th);
			
			DTRACE_TCP5(cc, void, NULL, struct inpcb *, inp,
				struct tcpcb *, tp, struct tcphdr *, th,
				int32_t, TCP_CC_ACK_RCVD);
		}
		if (acked > so->so_snd.sb_cc) {
			tp->snd_wnd -= so->so_snd.sb_cc;
			sbdrop(&so->so_snd, (int)so->so_snd.sb_cc);
			ourfinisacked = 1;
		} else {
			sbdrop(&so->so_snd, acked);
			tp->snd_wnd -= acked;
			ourfinisacked = 0;
		}
		/* detect una wraparound */
		if ( !IN_FASTRECOVERY(tp) &&
		    SEQ_GT(tp->snd_una, tp->snd_recover) &&
		    SEQ_LEQ(th->th_ack, tp->snd_recover))
			tp->snd_recover = th->th_ack - 1;

		if (IN_FASTRECOVERY(tp) &&
		    SEQ_GEQ(th->th_ack, tp->snd_recover))
			EXIT_FASTRECOVERY(tp);

		tp->snd_una = th->th_ack;
		if (tp->sack_enable) {
			if (SEQ_GT(tp->snd_una, tp->snd_recover))
				tp->snd_recover = tp->snd_una;
		}
		if (SEQ_LT(tp->snd_nxt, tp->snd_una))
			tp->snd_nxt = tp->snd_una;
			
		/*
		 * sowwakeup must happen after snd_una, et al. are updated so that
		 * the sequence numbers are in sync with so_snd
		 */
		sowwakeup(so);

		switch (tp->t_state) {

		/*
		 * In FIN_WAIT_1 STATE in addition to the processing
		 * for the ESTABLISHED state if our FIN is now acknowledged
		 * then enter FIN_WAIT_2.
		 */
		case TCPS_FIN_WAIT_1:
			if (ourfinisacked) {
				/*
				 * If we can't receive any more
				 * data, then closing user can proceed.
				 * Starting the timer is contrary to the
				 * specification, but if we don't get a FIN
				 * we'll hang forever.
				 */
				if (so->so_state & SS_CANTRCVMORE) {
					add_to_time_wait(tp, tcp_maxidle);
					isconnected = FALSE;
					isdisconnected = TRUE;
				}
				DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
					struct tcpcb *, tp, int32_t, TCPS_FIN_WAIT_2);
				tp->t_state = TCPS_FIN_WAIT_2;
				/* fall through and make sure we also recognize data ACKed with the FIN */
			}
			tp->t_flags |= TF_ACKNOW;
			break;

	 	/*
		 * In CLOSING STATE in addition to the processing for
		 * the ESTABLISHED state if the ACK acknowledges our FIN
		 * then enter the TIME-WAIT state, otherwise ignore
		 * the segment.
		 */
		case TCPS_CLOSING:
			if (ourfinisacked) {
				DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
					struct tcpcb *, tp, int32_t, TCPS_TIME_WAIT);
				tp->t_state = TCPS_TIME_WAIT;
				tcp_canceltimers(tp);
				/* Shorten TIME_WAIT [RFC-1644, p.28] */
				if (tp->cc_recv != 0 &&
				    ((int)(tcp_now - tp->t_starttime)) < tcp_msl)
					add_to_time_wait(tp, tp->t_rxtcur * TCPTV_TWTRUNC);
				else
					add_to_time_wait(tp, 2 * tcp_msl);
				isconnected = FALSE;
				isdisconnected = TRUE;
			}
			tp->t_flags |= TF_ACKNOW;
			break;

		/*
		 * In LAST_ACK, we may still be waiting for data to drain
		 * and/or to be acked, as well as for the ack of our FIN.
		 * If our FIN is now acknowledged, delete the TCB,
		 * enter the closed state and return.
		 */
		case TCPS_LAST_ACK:
			if (ourfinisacked) {
				tp = tcp_close(tp);
				goto drop;
			}
			break;

		/*
		 * In TIME_WAIT state the only thing that should arrive
		 * is a retransmission of the remote FIN.  Acknowledge
		 * it and restart the finack timer.
		 */
		case TCPS_TIME_WAIT:
			add_to_time_wait(tp, 2 * tcp_msl);
			goto dropafterack;
		}
	}

step6:
	/*
	 * Update window information.
	 * Don't look at window if no ACK: TAC's send garbage on first SYN.
	 */
	if ((thflags & TH_ACK) &&
	    (SEQ_LT(tp->snd_wl1, th->th_seq) ||
	    (tp->snd_wl1 == th->th_seq && (SEQ_LT(tp->snd_wl2, th->th_ack) ||
	     (tp->snd_wl2 == th->th_ack && tiwin > tp->snd_wnd))))) {
		/* keep track of pure window updates */
		if (tlen == 0 &&
		    tp->snd_wl2 == th->th_ack && tiwin > tp->snd_wnd)
			tcpstat.tcps_rcvwinupd++;
		tp->snd_wnd = tiwin;
		tp->snd_wl1 = th->th_seq;
		tp->snd_wl2 = th->th_ack;
		if (tp->snd_wnd > tp->max_sndwnd)
			tp->max_sndwnd = tp->snd_wnd;
		needoutput = 1;
	}

	/*
	 * Process segments with URG.
	 */
	if ((thflags & TH_URG) && th->th_urp &&
	    TCPS_HAVERCVDFIN(tp->t_state) == 0) {
		/*
		 * This is a kludge, but if we receive and accept
		 * random urgent pointers, we'll crash in
		 * soreceive.  It's hard to imagine someone
		 * actually wanting to send this much urgent data.
		 */
		if (th->th_urp + so->so_rcv.sb_cc > sb_max) {
			th->th_urp = 0;			/* XXX */
			thflags &= ~TH_URG;		/* XXX */
			goto dodata;			/* XXX */
		}
		/*
		 * If this segment advances the known urgent pointer,
		 * then mark the data stream.  This should not happen
		 * in CLOSE_WAIT, CLOSING, LAST_ACK or TIME_WAIT STATES since
		 * a FIN has been received from the remote side.
		 * In these states we ignore the URG.
		 *
		 * According to RFC961 (Assigned Protocols),
		 * the urgent pointer points to the last octet
		 * of urgent data.  We continue, however,
		 * to consider it to indicate the first octet
		 * of data past the urgent section as the original
		 * spec states (in one of two places).
		 */
		if (SEQ_GT(th->th_seq+th->th_urp, tp->rcv_up)) {
			tp->rcv_up = th->th_seq + th->th_urp;
			so->so_oobmark = so->so_rcv.sb_cc +
			    (tp->rcv_up - tp->rcv_nxt) - 1;
			if (so->so_oobmark == 0) {
				so->so_state |= SS_RCVATMARK;
				postevent(so, 0, EV_OOB);
			}
			sohasoutofband(so);
			tp->t_oobflags &= ~(TCPOOB_HAVEDATA | TCPOOB_HADDATA);
		}
		/*
		 * Remove out of band data so doesn't get presented to user.
		 * This can happen independent of advancing the URG pointer,
		 * but if two URG's are pending at once, some out-of-band
		 * data may creep in... ick.
		 */
		if (th->th_urp <= (u_int32_t)tlen
#if SO_OOBINLINE
		     && (so->so_options & SO_OOBINLINE) == 0
#endif
		     )
			tcp_pulloutofband(so, th, m,
				drop_hdrlen);	/* hdr drop is delayed */
	} else {
		/*
		 * If no out of band data is expected,
		 * pull receive urgent pointer along
		 * with the receive window.
		 */
		if (SEQ_GT(tp->rcv_nxt, tp->rcv_up))
			tp->rcv_up = tp->rcv_nxt;
	}
dodata:

	/* Set socket's connect or disconnect state correcly before doing data.
	 * The following might unlock the socket if there is an upcall or a socket
	 * filter.
	 */
	if (isconnected) {
		soisconnected(so);
	} else if (isdisconnected) {
		soisdisconnected(so);
	}

	/* Let's check the state of pcb just to make sure that it did not get closed 
	 * when we unlocked above
	 */
	if (inp->inp_state == INPCB_STATE_DEAD) {
		/* Just drop the packet that we are processing and return */
		goto drop;
	}
	
	/*
	 * Process the segment text, merging it into the TCP sequencing queue,
	 * and arranging for acknowledgment of receipt if necessary.
	 * This process logically involves adjusting tp->rcv_wnd as data
	 * is presented to the user (this happens in tcp_usrreq.c,
	 * case PRU_RCVD).  If a FIN has already been received on this
	 * connection then we just ignore the text.
	 */
	if ((tlen || (thflags & TH_FIN)) &&
	    TCPS_HAVERCVDFIN(tp->t_state) == 0) {
		tcp_seq save_start = th->th_seq;
		tcp_seq save_end = th->th_seq + tlen;
		m_adj(m, drop_hdrlen);	/* delayed header drop */
		/*
		 * Insert segment which includes th into TCP reassembly queue
		 * with control block tp.  Set thflags to whether reassembly now
		 * includes a segment with FIN.  This handles the common case
		 * inline (segment is the next to be received on an established
		 * connection, and the queue is empty), avoiding linkage into
		 * and removal from the queue and repetition of various
		 * conversions.
		 * Set DELACK for segments received in order, but ack
		 * immediately when segments are out of order (so
		 * fast retransmit can work).
		 */
		if (th->th_seq == tp->rcv_nxt &&
		    LIST_EMPTY(&tp->t_segq) &&
		    TCPS_HAVEESTABLISHED(tp->t_state)) {
			if (DELAY_ACK(tp, th) && ((tp->t_flags & TF_ACKNOW) == 0)) {
				if ((tp->t_flags & TF_DELACK) == 0) {
					tp->t_flags |= TF_DELACK;
					tp->t_timer[TCPT_DELACK] = OFFSET_FROM_START(tp, tcp_delack);
				}
			    	tp->t_unacksegs++;
			}         
			else {
				tp->t_flags |= TF_ACKNOW;
			}
			tp->rcv_nxt += tlen;
			thflags = th->th_flags & TH_FIN;
			tcpstat.tcps_rcvpack++;
			tcpstat.tcps_rcvbyte += tlen;
			if (nstat_collect) {
				locked_add_64(&inp->inp_stat->rxpackets, 1);
				locked_add_64(&inp->inp_stat->rxbytes, tlen);
			}
			ND6_HINT(tp);
			so_recv_data_stat(so, m, drop_hdrlen);
			if (sbappendstream(&so->so_rcv, m))
				sorwakeup(so);
		} else {
			thflags = tcp_reass(tp, th, &tlen, m);
			tp->t_flags |= TF_ACKNOW;
		}

		if (tlen > 0 && tp->sack_enable)
			tcp_update_sack_list(tp, save_start, save_end);

		if (tp->t_flags & TF_DELACK) 
		{
#if INET6
			if (isipv6) {
				KERNEL_DEBUG(DBG_LAYER_END, ((th->th_dport << 16) | th->th_sport),
		     			(((ip6->ip6_src.s6_addr16[0]) << 16) | (ip6->ip6_dst.s6_addr16[0])),
			     		th->th_seq, th->th_ack, th->th_win); 
			}
			else
#endif
			{
				KERNEL_DEBUG(DBG_LAYER_END, ((th->th_dport << 16) | th->th_sport),
		     			(((ip->ip_src.s_addr & 0xffff) << 16) | (ip->ip_dst.s_addr & 0xffff)),
			     		th->th_seq, th->th_ack, th->th_win); 
			}
				
		}
		/*
		 * Note the amount of data that peer has sent into
		 * our window, in order to estimate the sender's
		 * buffer size.
		 */
		len = (u_int)(so->so_rcv.sb_hiwat - (tp->rcv_adv - tp->rcv_nxt));
		if (len > so->so_rcv.sb_maxused)
			so->so_rcv.sb_maxused = len;
	} else {
		m_freem(m);
		thflags &= ~TH_FIN;
	}

	/*
	 * If FIN is received ACK the FIN and let the user know
	 * that the connection is closing.
	 */
	if (thflags & TH_FIN) {
		if (TCPS_HAVERCVDFIN(tp->t_state) == 0) {
			socantrcvmore(so);
			postevent(so, 0, EV_FIN);
			/*
			 *  If connection is half-synchronized
			 *  (ie NEEDSYN flag on) then delay ACK,
			 * If connection is half-synchronized
			 * (ie NEEDSYN flag on) then delay ACK,
			 * so it may be piggybacked when SYN is sent.
			 * Otherwise, since we received a FIN then no
			 * more input can be expected, send ACK now.
			 */
			if (DELAY_ACK(tp, th) && (tp->t_flags & TF_NEEDSYN)) {
				if ((tp->t_flags & TF_DELACK) == 0) {
					tp->t_flags |= TF_DELACK;
					tp->t_timer[TCPT_DELACK] = OFFSET_FROM_START(tp, tcp_delack);
				}
			    	tp->t_unacksegs++;
			}
			else {
				tp->t_flags |= TF_ACKNOW;
			}
			tp->rcv_nxt++;
		}
		switch (tp->t_state) {

	 	/*
		 * In SYN_RECEIVED and ESTABLISHED STATES
		 * enter the CLOSE_WAIT state.
		 */
		case TCPS_SYN_RECEIVED:
			tp->t_starttime = tcp_now;
		case TCPS_ESTABLISHED:
			DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
				struct tcpcb *, tp, int32_t, TCPS_CLOSE_WAIT);
			tp->t_state = TCPS_CLOSE_WAIT;
			break;

	 	/*
		 * If still in FIN_WAIT_1 STATE FIN has not been acked so
		 * enter the CLOSING state.
		 */
		case TCPS_FIN_WAIT_1:
			DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
				struct tcpcb *, tp, int32_t, TCPS_CLOSING);
			tp->t_state = TCPS_CLOSING;
			break;

	 	/*
		 * In FIN_WAIT_2 state enter the TIME_WAIT state,
		 * starting the time-wait timer, turning off the other
		 * standard timers.
		 */
		case TCPS_FIN_WAIT_2:
			DTRACE_TCP4(state__change, void, NULL, struct inpcb *, inp,
				struct tcpcb *, tp, int32_t, TCPS_TIME_WAIT);
			tp->t_state = TCPS_TIME_WAIT;
			tcp_canceltimers(tp);
			/* Shorten TIME_WAIT [RFC-1644, p.28] */
			if (tp->cc_recv != 0 &&
				((int)(tcp_now - tp->t_starttime)) < tcp_msl) {
				add_to_time_wait(tp, tp->t_rxtcur * TCPTV_TWTRUNC);
				/* For transaction client, force ACK now. */
				tp->t_flags |= TF_ACKNOW;
			    	tp->t_unacksegs = 0;
			}
			else
				add_to_time_wait(tp, 2 * tcp_msl);
			soisdisconnected(so);
			break;

		/*
		 * In TIME_WAIT state restart the 2 MSL time_wait timer.
		 */
		case TCPS_TIME_WAIT:
			add_to_time_wait(tp, 2 * tcp_msl);
			break;
		}
	}
#if TCPDEBUG
	if (so->so_options & SO_DEBUG)
		tcp_trace(TA_INPUT, ostate, tp, (void *)tcp_saveipgen,
			  &tcp_savetcp, 0);
#endif

	/*
	 * Return any desired output.
	 */
	if (needoutput || (tp->t_flags & TF_ACKNOW)) {
		(void) tcp_output(tp);
	}

	tcp_check_timer_state(tp);

	
	tcp_unlock(so, 1, 0);
	KERNEL_DEBUG(DBG_FNC_TCP_INPUT | DBG_FUNC_END,0,0,0,0,0);
	return;

dropafterack:
	/*
	 * Generate an ACK dropping incoming segment if it occupies
	 * sequence space, where the ACK reflects our state.
	 *
	 * We can now skip the test for the RST flag since all
	 * paths to this code happen after packets containing
	 * RST have been dropped.
	 *
	 * In the SYN-RECEIVED state, don't send an ACK unless the
	 * segment we received passes the SYN-RECEIVED ACK test.
	 * If it fails send a RST.  This breaks the loop in the
	 * "LAND" DoS attack, and also prevents an ACK storm
	 * between two listening ports that have been sent forged
	 * SYN segments, each with the source address of the other.
	 */
	if (tp->t_state == TCPS_SYN_RECEIVED && (thflags & TH_ACK) &&
	    (SEQ_GT(tp->snd_una, th->th_ack) ||
	     SEQ_GT(th->th_ack, tp->snd_max)) ) {
		rstreason = BANDLIM_RST_OPENPORT;
		goto dropwithreset;
	}
#if TCPDEBUG
	if (so->so_options & SO_DEBUG)
		tcp_trace(TA_DROP, ostate, tp, (void *)tcp_saveipgen,
			  &tcp_savetcp, 0);
#endif
	m_freem(m);
	tp->t_flags |= TF_ACKNOW;
	(void) tcp_output(tp);

	/* Don't need to check timer state as we should have done it during tcp_output */
	tcp_unlock(so, 1, 0);
	KERNEL_DEBUG(DBG_FNC_TCP_INPUT | DBG_FUNC_END,0,0,0,0,0);
	return;
dropwithresetnosock:
	nosock = 1;
dropwithreset:
	/*
	 * Generate a RST, dropping incoming segment.
	 * Make ACK acceptable to originator of segment.
	 * Don't bother to respond if destination was broadcast/multicast.
	 */
	if ((thflags & TH_RST) || m->m_flags & (M_BCAST|M_MCAST))
		goto drop;
#if INET6
	if (isipv6) {
		if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst) ||
		    IN6_IS_ADDR_MULTICAST(&ip6->ip6_src))
			goto drop;
	} else
#endif /* INET6 */
	if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr)) ||
	    IN_MULTICAST(ntohl(ip->ip_src.s_addr)) ||
	    ip->ip_src.s_addr == htonl(INADDR_BROADCAST) ||
	    in_broadcast(ip->ip_dst, m->m_pkthdr.rcvif))
		goto drop;
	/* IPv6 anycast check is done at tcp6_input() */

	/* 
	 * Perform bandwidth limiting.
	 */
#if ICMP_BANDLIM
	if (badport_bandlim(rstreason) < 0)
		goto drop;
#endif

#if TCPDEBUG
	if (tp == 0 || (tp->t_inpcb->inp_socket->so_options & SO_DEBUG))
		tcp_trace(TA_DROP, ostate, tp, (void *)tcp_saveipgen,
			  &tcp_savetcp, 0);
#endif
	if (thflags & TH_ACK)
		/* mtod() below is safe as long as hdr dropping is delayed */
		tcp_respond(tp, mtod(m, void *), th, m, (tcp_seq)0, th->th_ack,
		    TH_RST, ifscope, nocell);
	else {
		if (thflags & TH_SYN)
			tlen++;
		/* mtod() below is safe as long as hdr dropping is delayed */
		tcp_respond(tp, mtod(m, void *), th, m, th->th_seq+tlen,
		    (tcp_seq)0, TH_RST|TH_ACK, ifscope, nocell);
	}
	/* destroy temporarily created socket */
	if (dropsocket) {
		(void) soabort(so); 
		tcp_unlock(so, 1, 0);
	}
	else if ((inp != NULL) && (nosock == 0)) {
		tcp_unlock(so, 1, 0);
	}
	KERNEL_DEBUG(DBG_FNC_TCP_INPUT | DBG_FUNC_END,0,0,0,0,0);
	return;
dropnosock:
	nosock = 1;
drop:
	/*
	 * Drop space held by incoming segment and return.
	 */
#if TCPDEBUG
	if (tp == 0 || (tp->t_inpcb->inp_socket->so_options & SO_DEBUG))
		tcp_trace(TA_DROP, ostate, tp, (void *)tcp_saveipgen,
			  &tcp_savetcp, 0);
#endif
	m_freem(m);
	/* destroy temporarily created socket */
	if (dropsocket) {
		(void) soabort(so); 
		tcp_unlock(so, 1, 0);
	}
	else if (nosock == 0) {
		tcp_unlock(so, 1, 0);
	}
	KERNEL_DEBUG(DBG_FNC_TCP_INPUT | DBG_FUNC_END,0,0,0,0,0);
	return;
}

static void
tcp_dooptions(tp, cp, cnt, th, to, input_ifscope)
/*
 * Parse TCP options and place in tcpopt.
 */
	struct tcpcb *tp;
	u_char *cp;
	int cnt;
	struct tcphdr *th;
	struct tcpopt *to;
	unsigned int input_ifscope;
{
	u_short mss = 0;
	int opt, optlen;

	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		opt = cp[0];
		if (opt == TCPOPT_EOL)
			break;
		if (opt == TCPOPT_NOP)
			optlen = 1;
		else {
			if (cnt < 2)
				break;
			optlen = cp[1];
			if (optlen < 2 || optlen > cnt)
				break;
		}
		switch (opt) {

		default:
			continue;

		case TCPOPT_MAXSEG:
			if (optlen != TCPOLEN_MAXSEG)
				continue;
			if (!(th->th_flags & TH_SYN))
				continue;
			bcopy((char *) cp + 2, (char *) &mss, sizeof(mss));

#if BYTE_ORDER != BIG_ENDIAN
			NTOHS(mss);
#endif

			break;

		case TCPOPT_WINDOW:
			if (optlen != TCPOLEN_WINDOW)
				continue;
			if (!(th->th_flags & TH_SYN))
				continue;
			tp->t_flags |= TF_RCVD_SCALE;
			tp->requested_s_scale = min(cp[2], TCP_MAX_WINSHIFT);
			break;

		case TCPOPT_TIMESTAMP:
			if (optlen != TCPOLEN_TIMESTAMP)
				continue;
			to->to_flags |= TOF_TS;
			bcopy((char *)cp + 2,
			    (char *)&to->to_tsval, sizeof(to->to_tsval));

#if BYTE_ORDER != BIG_ENDIAN
			NTOHL(to->to_tsval);
#endif

			bcopy((char *)cp + 6,
			    (char *)&to->to_tsecr, sizeof(to->to_tsecr));

#if BYTE_ORDER != BIG_ENDIAN
			NTOHL(to->to_tsecr);
#endif

			/*
			 * A timestamp received in a SYN makes
			 * it ok to send timestamp requests and replies.
			 */
			if (th->th_flags & TH_SYN) {
				tp->t_flags |= TF_RCVD_TSTMP;
				tp->ts_recent = to->to_tsval;
				tp->ts_recent_age = tcp_now;
			}
			break;
		case TCPOPT_SACK_PERMITTED:
			if (!tcp_do_sack ||
			    optlen != TCPOLEN_SACK_PERMITTED)
				continue;
			if (th->th_flags & TH_SYN)
				to->to_flags |= TOF_SACK;
			break;
		case TCPOPT_SACK:
			if (optlen <= 2 || (optlen - 2) % TCPOLEN_SACK != 0)
				continue;
			to->to_nsacks = (optlen - 2) / TCPOLEN_SACK;
			to->to_sacks = cp + 2;
			tcpstat.tcps_sack_rcv_blocks++;

			break;
		}
	}
	if (th->th_flags & TH_SYN)
		tcp_mss(tp, mss, input_ifscope);	/* sets t_maxseg */
}

/*
 * Pull out of band byte out of a segment so
 * it doesn't appear in the user's data queue.
 * It is still reflected in the segment length for
 * sequencing purposes.
 */
static void
tcp_pulloutofband(so, th, m, off)
	struct socket *so;
	struct tcphdr *th;
	register struct mbuf *m;
	int off;		/* delayed to be droped hdrlen */
{
	int cnt = off + th->th_urp - 1;

	while (cnt >= 0) {
		if (m->m_len > cnt) {
			char *cp = mtod(m, caddr_t) + cnt;
			struct tcpcb *tp = sototcpcb(so);

			tp->t_iobc = *cp;
			tp->t_oobflags |= TCPOOB_HAVEDATA;
			bcopy(cp+1, cp, (unsigned)(m->m_len - cnt - 1));
			m->m_len--;
			if (m->m_flags & M_PKTHDR)
				m->m_pkthdr.len--;
			return;
		}
		cnt -= m->m_len;
		m = m->m_next;
		if (m == 0)
			break;
	}
	panic("tcp_pulloutofband");
}

uint32_t
get_base_rtt(struct tcpcb *tp) 
{
	uint32_t base_rtt = 0, i;
	for (i = 0; i < N_RTT_BASE; ++i) {
		if (tp->rtt_hist[i] != 0 &&
			(base_rtt == 0 || tp->rtt_hist[i] < base_rtt))
			base_rtt = tp->rtt_hist[i];
	}
	return base_rtt;
}

/* Each value of RTT base represents the minimum RTT seen in a minute.
 * We keep upto N_RTT_BASE minutes worth of history.
 */
void
update_base_rtt(struct tcpcb *tp, uint32_t rtt)
{
	if (++tp->rtt_count >= rtt_samples_per_slot) {
		int i=0;
		for (i = (N_RTT_BASE-1); i > 0; --i) {
			tp->rtt_hist[i] = tp->rtt_hist[i-1];
		}
		tp->rtt_hist[0] = rtt;
		tp->rtt_count = 0;
	} else {
		tp->rtt_hist[0] = min(tp->rtt_hist[0], rtt);
	}
}

/*
 * Collect new round-trip time estimate
 * and update averages and current timeout.
 */
static void
tcp_xmit_timer(tp, rtt)
	register struct tcpcb *tp;
	int rtt;
{
	register int delta;

	tcpstat.tcps_rttupdated++;
	tp->t_rttupdated++;

	if (rtt > 0) {
		tp->t_rttcur = rtt;
		update_base_rtt(tp, rtt);
	}

	if (tp->t_srtt != 0) {
		/*
		 * srtt is stored as fixed point with 5 bits after the
		 * binary point (i.e., scaled by 32).  The following magic
		 * is equivalent to the smoothing algorithm in rfc793 with
		 * an alpha of .875 (srtt = rtt/8 + srtt*7/8 in fixed
		 * point).
		 *
		 * Freebsd adjusts rtt to origin 0 by subtracting 1 from the provided
		 * rtt value. This was required because of the way t_rtttime was
		 * initiailised to 1 before. Since we changed t_rtttime to be based on
		 * tcp_now, this extra adjustment is not needed.
		 */
		delta = (rtt << TCP_DELTA_SHIFT)
			- (tp->t_srtt >> (TCP_RTT_SHIFT - TCP_DELTA_SHIFT));

		if ((tp->t_srtt += delta) <= 0)
			tp->t_srtt = 1;

		/*
		 * We accumulate a smoothed rtt variance (actually, a
		 * smoothed mean difference), then set the retransmit
		 * timer to smoothed rtt + 4 times the smoothed variance.
		 * rttvar is stored as fixed point with 4 bits after the
		 * binary point (scaled by 16).  The following is
		 * equivalent to rfc793 smoothing with an alpha of .75
		 * (rttvar = rttvar*3/4 + |delta| / 4).  This replaces
		 * rfc793's wired-in beta.
		 */
		if (delta < 0)
			delta = -delta;
		delta -= tp->t_rttvar >> (TCP_RTTVAR_SHIFT - TCP_DELTA_SHIFT);
		if ((tp->t_rttvar += delta) <= 0)
			tp->t_rttvar = 1;
		if (tp->t_rttbest > tp->t_srtt + tp->t_rttvar)
		    tp->t_rttbest = tp->t_srtt + tp->t_rttvar;
	} else {
		/*
		 * No rtt measurement yet - use the unsmoothed rtt.
		 * Set the variance to half the rtt (so our first
		 * retransmit happens at 3*rtt).
		 */
		tp->t_srtt = rtt << TCP_RTT_SHIFT;
		tp->t_rttvar = rtt << (TCP_RTTVAR_SHIFT - 1);
		tp->t_rttbest = tp->t_srtt + tp->t_rttvar;
	}
	nstat_route_rtt(tp->t_inpcb->inp_route.ro_rt, tp->t_srtt, tp->t_rttvar);
	tp->t_rtttime = 0;
	tp->t_rxtshift = 0;
	tp->rxt_start = 0;

	/*
	 * the retransmit should happen at rtt + 4 * rttvar.
	 * Because of the way we do the smoothing, srtt and rttvar
	 * will each average +1/2 tick of bias.  When we compute
	 * the retransmit timer, we want 1/2 tick of rounding and
	 * 1 extra tick because of +-1/2 tick uncertainty in the
	 * firing of the timer.  The bias will give us exactly the
	 * 1.5 tick we need.  But, because the bias is
	 * statistical, we have to test that we don't drop below
	 * the minimum feasible timer (which is 2 ticks).
	 */
	TCPT_RANGESET(tp->t_rxtcur, TCP_REXMTVAL(tp),
		max(tp->t_rttmin, rtt + 2), TCPTV_REXMTMAX, 
		TCP_ADD_REXMTSLOP(tp));

	/*
	 * We received an ack for a packet that wasn't retransmitted;
	 * it is probably safe to discard any error indications we've
	 * received recently.  This isn't quite right, but close enough
	 * for now (a route might have failed after we sent a segment,
	 * and the return path might not be symmetrical).
	 */
	tp->t_softerror = 0;
}

static inline unsigned int
tcp_maxmtu(struct rtentry *rt)
{
	unsigned int maxmtu;

	RT_LOCK_ASSERT_HELD(rt);
	if (rt->rt_rmx.rmx_mtu == 0)
		maxmtu = rt->rt_ifp->if_mtu;
	else
		maxmtu = MIN(rt->rt_rmx.rmx_mtu, rt->rt_ifp->if_mtu);

	return (maxmtu);
}

#if INET6
static inline unsigned int
tcp_maxmtu6(struct rtentry *rt)
{
	unsigned int maxmtu;

	RT_LOCK_ASSERT_HELD(rt);
	lck_rw_lock_shared(nd_if_rwlock);
	if (rt->rt_rmx.rmx_mtu == 0)
		maxmtu = IN6_LINKMTU(rt->rt_ifp);
	else
		maxmtu = MIN(rt->rt_rmx.rmx_mtu, IN6_LINKMTU(rt->rt_ifp));
	lck_rw_done(nd_if_rwlock);

	return (maxmtu);
}
#endif

/*
 * Determine a reasonable value for maxseg size.
 * If the route is known, check route for mtu.
 * If none, use an mss that can be handled on the outgoing
 * interface without forcing IP to fragment; if bigger than
 * an mbuf cluster (MCLBYTES), round down to nearest multiple of MCLBYTES
 * to utilize large mbufs.  If no route is found, route has no mtu,
 * or the destination isn't local, use a default, hopefully conservative
 * size (usually 512 or the default IP max size, but no more than the mtu
 * of the interface), as we can't discover anything about intervening
 * gateways or networks.  We also initialize the congestion/slow start
 * window to be a single segment if the destination isn't local.
 * While looking at the routing entry, we also initialize other path-dependent
 * parameters from pre-set or cached values in the routing entry.
 *
 * Also take into account the space needed for options that we
 * send regularly.  Make maxseg shorter by that amount to assure
 * that we can send maxseg amount of data even when the options
 * are present.  Store the upper limit of the length of options plus
 * data in maxopd.
 *
 * NOTE that this routine is only called when we process an incoming
 * segment, for outgoing segments only tcp_mssopt is called.
 *
 */
void
tcp_mss(tp, offer, input_ifscope)
	struct tcpcb *tp;
	int offer;
	unsigned int input_ifscope;
{
	register struct rtentry *rt;
	struct ifnet *ifp;
	register int rtt, mss;
	u_int32_t bufsize;
	struct inpcb *inp;
	struct socket *so;
	struct rmxp_tao *taop;
	int origoffer = offer;
	u_int32_t sb_max_corrected;
	int isnetlocal = 0;
#if INET6
	int isipv6;
	int min_protoh;
#endif

	inp = tp->t_inpcb;
#if INET6
	isipv6 = ((inp->inp_vflag & INP_IPV6) != 0) ? 1 : 0;
	min_protoh = isipv6 ? sizeof (struct ip6_hdr) + sizeof (struct tcphdr)
			    : sizeof (struct tcpiphdr);
#else
#define min_protoh  (sizeof (struct tcpiphdr))
#endif

#if INET6
	if (isipv6) {
		rt = tcp_rtlookup6(inp, input_ifscope);
		if (rt != NULL &&
		    (IN6_IS_ADDR_LOOPBACK(&inp->in6p_faddr) ||
		    IN6_IS_ADDR_LINKLOCAL(&inp->in6p_faddr) ||
		    rt->rt_gateway->sa_family == AF_LINK ||
		    in6_localaddr(&inp->in6p_faddr))) {
			tp->t_flags |= TF_LOCAL;
		}
	}
	else
#endif /* INET6 */
	{
		rt = tcp_rtlookup(inp, input_ifscope);
		if (rt != NULL &&
		    (rt->rt_gateway->sa_family == AF_LINK ||
		    rt->rt_ifp->if_flags & IFF_LOOPBACK ||
		    in_localaddr(inp->inp_faddr))) {
			tp->t_flags |= TF_LOCAL;
		}
	}
	isnetlocal = (tp->t_flags & TF_LOCAL);

	if (rt == NULL) {
		tp->t_maxopd = tp->t_maxseg =
#if INET6
		isipv6 ? tcp_v6mssdflt :
#endif /* INET6 */
		tcp_mssdflt;
		return;
	}
	ifp = rt->rt_ifp;
	/*
	 * Slower link window correction:
	 * If a value is specificied for slowlink_wsize use it for PPP links
	 * believed to be on a serial modem (speed <128Kbps). Excludes 9600bps as
	 * it is the default value adversized by pseudo-devices over ppp.
	 */
	if (ifp->if_type == IFT_PPP && slowlink_wsize > 0 && 
	    ifp->if_baudrate > 9600 && ifp->if_baudrate <= 128000) {
		tp->t_flags |= TF_SLOWLINK;
	}
	so = inp->inp_socket;

	taop = rmx_taop(rt->rt_rmx);
	/*
	 * Offer == -1 means that we didn't receive SYN yet,
	 * use cached value in that case;
	 */
	if (offer == -1)
		offer = taop->tao_mssopt;
	/*
	 * Offer == 0 means that there was no MSS on the SYN segment,
	 * in this case we use tcp_mssdflt.
	 */
	if (offer == 0)
		offer =
#if INET6
			isipv6 ? tcp_v6mssdflt :
#endif /* INET6 */
			tcp_mssdflt;
	else {
		/*
		 * Prevent DoS attack with too small MSS. Round up
		 * to at least minmss.
		 */
		offer = max(offer, tcp_minmss);
		/*
		 * Sanity check: make sure that maxopd will be large
		 * enough to allow some data on segments even is the
		 * all the option space is used (40bytes).  Otherwise
		 * funny things may happen in tcp_output.
		 */
		offer = max(offer, 64);
	}
	taop->tao_mssopt = offer;

	/*
	 * While we're here, check if there's an initial rtt
	 * or rttvar.  Convert from the route-table units
	 * to scaled multiples of the slow timeout timer.
	 */
	if (tp->t_srtt == 0 && (rtt = rt->rt_rmx.rmx_rtt)) {
		/*
		 * XXX the lock bit for RTT indicates that the value
		 * is also a minimum value; this is subject to time.
		 */
		if (rt->rt_rmx.rmx_locks & RTV_RTT)
			tp->t_rttmin = rtt / (RTM_RTTUNIT / TCP_RETRANSHZ);
		else
			tp->t_rttmin = isnetlocal ? tcp_TCPTV_MIN : TCPTV_REXMTMIN;
		tp->t_srtt = rtt / (RTM_RTTUNIT / (TCP_RETRANSHZ * TCP_RTT_SCALE));
		tcpstat.tcps_usedrtt++;
		if (rt->rt_rmx.rmx_rttvar) {
			tp->t_rttvar = rt->rt_rmx.rmx_rttvar /
			    (RTM_RTTUNIT / (TCP_RETRANSHZ * TCP_RTTVAR_SCALE));
			tcpstat.tcps_usedrttvar++;
		} else {
			/* default variation is +- 1 rtt */
			tp->t_rttvar =
			    tp->t_srtt * TCP_RTTVAR_SCALE / TCP_RTT_SCALE;
		}
		TCPT_RANGESET(tp->t_rxtcur,
			      ((tp->t_srtt >> 2) + tp->t_rttvar) >> 1,
			      tp->t_rttmin, TCPTV_REXMTMAX, 
			      TCP_ADD_REXMTSLOP(tp));
	}
	else
		tp->t_rttmin = isnetlocal ? tcp_TCPTV_MIN : TCPTV_REXMTMIN;

#if INET6
	mss = (isipv6 ? tcp_maxmtu6(rt) : tcp_maxmtu(rt));
#else
	mss = tcp_maxmtu(rt);
#endif
	mss -= min_protoh;

	if (rt->rt_rmx.rmx_mtu == 0) {
#if INET6
		if (isipv6) {
			if (!isnetlocal)
				mss = min(mss, tcp_v6mssdflt);
		} else
#endif /* INET6 */
		if (!isnetlocal)
			mss = min(mss, tcp_mssdflt);
	}

	mss = min(mss, offer);
	/*
	 * maxopd stores the maximum length of data AND options
	 * in a segment; maxseg is the amount of data in a normal
	 * segment.  We need to store this value (maxopd) apart
	 * from maxseg, because now every segment carries options
	 * and thus we normally have somewhat less data in segments.
	 */
	tp->t_maxopd = mss;

	/*
	 * origoffer==-1 indicates, that no segments were received yet.
	 * In this case we just guess.
	 */
	if ((tp->t_flags & (TF_REQ_TSTMP|TF_NOOPT)) == TF_REQ_TSTMP &&
	    (origoffer == -1 ||
	     (tp->t_flags & TF_RCVD_TSTMP) == TF_RCVD_TSTMP))
		mss -= TCPOLEN_TSTAMP_APPA;
	tp->t_maxseg = mss;

	/*
	 * Calculate corrected value for sb_max; ensure to upgrade the
	 * numerator for large sb_max values else it will overflow.
	 */
	sb_max_corrected = (sb_max * (u_int64_t)MCLBYTES) / (MSIZE + MCLBYTES);

	/*
	 * If there's a pipesize (ie loopback), change the socket
	 * buffer to that size only if it's bigger than the current
	 * sockbuf size.  Make the socket buffers an integral
	 * number of mss units; if the mss is larger than
	 * the socket buffer, decrease the mss.
	 */
#if RTV_SPIPE
	bufsize = rt->rt_rmx.rmx_sendpipe;
	if (bufsize < so->so_snd.sb_hiwat)
#endif
		bufsize = so->so_snd.sb_hiwat;
	if (bufsize < mss)
		mss = bufsize;
	else {
		bufsize = (((bufsize + (u_int64_t)mss - 1) / (u_int64_t)mss) * (u_int64_t)mss);
		if (bufsize > sb_max_corrected)
			bufsize = sb_max_corrected;
		(void)sbreserve(&so->so_snd, bufsize);
	}
	tp->t_maxseg = mss;

#if RTV_RPIPE
	bufsize = rt->rt_rmx.rmx_recvpipe;
	if (bufsize < so->so_rcv.sb_hiwat)
#endif
		bufsize = so->so_rcv.sb_hiwat;
	if (bufsize > mss) {
		bufsize = (((bufsize + (u_int64_t)mss - 1) / (u_int64_t)mss) * (u_int64_t)mss);
		if (bufsize > sb_max_corrected)
			bufsize = sb_max_corrected;
		(void)sbreserve(&so->so_rcv, bufsize);
	}

	set_tcp_stream_priority(so);

	if (rt->rt_rmx.rmx_ssthresh) {
		/*
		 * There's some sort of gateway or interface
		 * buffer limit on the path.  Use this to set
		 * the slow start threshhold, but set the
		 * threshold to no less than 2*mss.
		 */
		tp->snd_ssthresh = max(2 * mss, rt->rt_rmx.rmx_ssthresh);
		tcpstat.tcps_usedssthresh++;
	} else {
		tp->snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	}


	/*
	 * Set the slow-start flight size depending on whether this
	 * is a local network or not.
	 */
	if (CC_ALGO(tp)->cwnd_init != NULL)
		CC_ALGO(tp)->cwnd_init(tp);

	DTRACE_TCP5(cc, void, NULL, struct inpcb *, tp->t_inpcb, struct tcpcb *, tp,
		struct tcphdr *, NULL, int32_t, TCP_CC_CWND_INIT);

	/* Route locked during lookup above */
	RT_UNLOCK(rt);
}

/*
 * Determine the MSS option to send on an outgoing SYN.
 */
int
tcp_mssopt(tp)
	struct tcpcb *tp;
{
	struct rtentry *rt;
	int mss;
#if INET6
	int isipv6;
	int min_protoh;
#endif

#if INET6
	isipv6 = ((tp->t_inpcb->inp_vflag & INP_IPV6) != 0) ? 1 : 0;
	min_protoh = isipv6 ? sizeof (struct ip6_hdr) + sizeof (struct tcphdr)
			    : sizeof (struct tcpiphdr);
#else
#define min_protoh  (sizeof (struct tcpiphdr))
#endif

#if INET6
	if (isipv6)
		rt = tcp_rtlookup6(tp->t_inpcb, IFSCOPE_NONE);
	else
#endif /* INET6 */
	rt = tcp_rtlookup(tp->t_inpcb, IFSCOPE_NONE);
	if (rt == NULL) {
		return (
#if INET6
			isipv6 ? tcp_v6mssdflt :
#endif /* INET6 */
			tcp_mssdflt);
	}
	/*
	 * Slower link window correction:
	 * If a value is specificied for slowlink_wsize use it for PPP links
	 * believed to be on a serial modem (speed <128Kbps). Excludes 9600bps as
	 * it is the default value adversized by pseudo-devices over ppp.
	 */
	if (rt->rt_ifp->if_type == IFT_PPP && slowlink_wsize > 0 && 
	    rt->rt_ifp->if_baudrate > 9600 && rt->rt_ifp->if_baudrate <= 128000) {
		tp->t_flags |= TF_SLOWLINK;
	}

#if INET6
	mss = (isipv6 ? tcp_maxmtu6(rt) : tcp_maxmtu(rt));
#else
	mss = tcp_maxmtu(rt);
#endif
	/* Route locked during lookup above */
	RT_UNLOCK(rt);
	return (mss - min_protoh);
}

/*
 * On a partial ack arrives, force the retransmission of the
 * next unacknowledged segment.  Do not clear tp->t_dupacks.
 * By setting snd_nxt to th_ack, this forces retransmission timer to
 * be started again.
 */
static void
tcp_newreno_partial_ack(tp, th)
	struct tcpcb *tp;
	struct tcphdr *th;
{
		tcp_seq onxt = tp->snd_nxt;
		u_int32_t  ocwnd = tp->snd_cwnd;
		tp->t_timer[TCPT_REXMT] = 0;
		tp->t_rtttime = 0;
		tp->snd_nxt = th->th_ack;
		/*
		 * Set snd_cwnd to one segment beyond acknowledged offset
		 * (tp->snd_una has not yet been updated when this function 
		 *  is called)
		 */
		tp->snd_cwnd = tp->t_maxseg + (th->th_ack - tp->snd_una);
		tp->t_flags |= TF_ACKNOW;
		(void) tcp_output(tp);
		tp->snd_cwnd = ocwnd;
		if (SEQ_GT(onxt, tp->snd_nxt))
			tp->snd_nxt = onxt;
		/*
		 * Partial window deflation.  Relies on fact that tp->snd_una
		 * not updated yet.
		 */
		if (tp->snd_cwnd > th->th_ack - tp->snd_una)
			tp->snd_cwnd -= th->th_ack - tp->snd_una;
		else
			tp->snd_cwnd = 0;
		tp->snd_cwnd += tp->t_maxseg;

}

/*
 * Drop a random TCP connection that hasn't been serviced yet and
 * is eligible for discard.  There is a one in qlen chance that
 * we will return a null, saying that there are no dropable
 * requests.  In this case, the protocol specific code should drop
 * the new request.  This insures fairness.
 *
 * The listening TCP socket "head" must be locked
 */
static int
tcp_dropdropablreq(struct socket *head)
{
	struct socket *so, *sonext;
	unsigned int i, j, qlen;
	static int rnd;
	static struct timeval old_runtime;
	static unsigned int cur_cnt, old_cnt;
	struct timeval tv;
	struct inpcb *inp = NULL;
	struct tcpcb *tp;

	if ((head->so_options & SO_ACCEPTCONN) == 0)
		return 0;

	so = TAILQ_FIRST(&head->so_incomp);
	if (!so)
		return 0;

	microtime(&tv);
	if ((i = (tv.tv_sec - old_runtime.tv_sec)) != 0) {
		old_runtime = tv;
		old_cnt = cur_cnt / i;
		cur_cnt = 0;
	}
	
	
	qlen = head->so_incqlen;
	if (++cur_cnt > qlen || old_cnt > qlen) {
		rnd = (314159 * rnd + 66329) & 0xffff;
		j = ((qlen + 1) * rnd) >> 16;

		while (j-- && so)
			so = TAILQ_NEXT(so, so_list);
	}
	/* Find a connection that is not already closing (or being served) */
	while (so) {
		inp = (struct inpcb *)so->so_pcb;
		
		sonext = TAILQ_NEXT(so, so_list);

		if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) != WNT_STOPUSING) {
			/* Avoid the issue of a socket being accepted by one input thread
			 * and being dropped by another input thread.
			 * If we can't get a hold on this mutex, then grab the next socket in line.
			 */
			if (lck_mtx_try_lock(&inp->inpcb_mtx)) {
				so->so_usecount++;
				if ((so->so_usecount == 2) && 
				    (so->so_state & SS_INCOMP) != 0 &&
				    (so->so_flags & SOF_INCOMP_INPROGRESS) == 0) 
					break;
				else {/* don't use if being accepted or used in any other way */
					in_pcb_checkstate(inp, WNT_RELEASE, 1);
					tcp_unlock(so, 1, 0);
				}
			}
			else {
				/* do not try to lock the inp in in_pcb_checkstate
				 * because the lock is already held in some other thread.
				 * Only drop the inp_wntcnt reference.
				 */
				in_pcb_checkstate(inp, WNT_RELEASE, 1);
			}
		}
		so = sonext;
		
	}
	if (!so)
		return 0;

	/* Makes sure socket is still in the right state to be discarded */

	if (in_pcb_checkstate(inp, WNT_RELEASE, 1) == WNT_STOPUSING) {
		tcp_unlock(so, 1, 0);
		return 0;
	}

	if (so->so_usecount != 2 || !(so->so_state & SS_INCOMP)) {
		/* do not discard: that socket is being accepted */
		tcp_unlock(so, 1, 0);
		return 0;
	}

	TAILQ_REMOVE(&head->so_incomp, so, so_list);
	tcp_unlock(head, 0, 0);

	lck_mtx_assert(&inp->inpcb_mtx, LCK_MTX_ASSERT_OWNED);
	tp = sototcpcb(so);
	so->so_flags |= SOF_OVERFLOW;
	so->so_head = NULL;

	tcp_close(tp);
	tp->t_unacksegs = 0;

	if (inp->inp_wantcnt > 0 && inp->inp_wantcnt != WNT_STOPUSING) {
		/* Some one has a wantcnt on this pcb. Since WNT_ACQUIRE
		 * doesn't require a lock, it could have happened while
		 * we are holding the lock. This pcb will have to
		 * be garbage collected later.
		 * Release the reference held for so_incomp queue
		 */
		so->so_usecount--;

		tcp_unlock(so, 1, 0);
	} else {
		/* Unlock this socket and leave the reference on. We need to
		 * acquire the pcbinfo lock in order to fully dispose it off 
		 */
		tcp_unlock(so, 0, 0);

		lck_rw_lock_exclusive(tcbinfo.mtx);

		tcp_lock(so, 0, 0);

		/* Release the reference held for so_incomp queue */
		so->so_usecount--;

		if (so->so_usecount != 1 || 
		    (inp->inp_wantcnt > 0 && inp->inp_wantcnt != WNT_STOPUSING)) {
			/* There is an extra wantcount or usecount that must
			 * have been added when the socket was unlocked. This
			 * socket will have to be garbage collected later
			 */
			tcp_unlock(so, 1, 0);
		} else {

			/* Drop the reference held for this function */
			so->so_usecount--;

			in_pcbdispose(inp);
		}
		lck_rw_done(tcbinfo.mtx);
	}
	tcpstat.tcps_drops++;

	tcp_lock(head, 0, 0);
	head->so_incqlen--;
	head->so_qlen--;
	return(1);
}

/* Set background congestion control on a socket */
void
tcp_set_background_cc(struct socket *so)
{
	tcp_set_new_cc(so, TCP_CC_ALGO_BACKGROUND_INDEX);
}

/* Set foreground congestion control on a socket */
void
tcp_set_foreground_cc(struct socket *so)
{
	tcp_set_new_cc(so, TCP_CC_ALGO_NEWRENO_INDEX);
}

static void
tcp_set_new_cc(struct socket *so, uint16_t cc_index)
{
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = intotcpcb(inp);
	uint16_t old_cc_index = 0;
	if (tp->tcp_cc_index != cc_index) {

		old_cc_index = tp->tcp_cc_index;

		if (CC_ALGO(tp)->cleanup != NULL)
			CC_ALGO(tp)->cleanup(tp);
		tp->tcp_cc_index = cc_index;

		/* Decide if the connection is just starting or if
		 * we have sent some packets on it.
		 */
		if (tp->snd_nxt > tp->iss) {
			/* Already sent some packets */
			if (CC_ALGO(tp)->switch_to != NULL)
				CC_ALGO(tp)->switch_to(tp, old_cc_index);
		} else {	
			if (CC_ALGO(tp)->init != NULL)
				CC_ALGO(tp)->init(tp);
		}
		DTRACE_TCP5(cc, void, NULL, struct inpcb *, inp,
			struct tcpcb *, tp, struct tcphdr *, NULL,
			int32_t, TCP_CC_CHANGE_ALGO);
	}
}

static int
tcp_getstat SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)

	int error;

	if (req->oldptr == 0) {
		req->oldlen= (size_t)sizeof(struct tcpstat);
	}

	error = SYSCTL_OUT(req, &tcpstat, MIN(sizeof (tcpstat), req->oldlen));

        return (error);

}

SYSCTL_PROC(_net_inet_tcp, TCPCTL_STATS, stats, CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
    tcp_getstat, "S,tcpstat", "TCP statistics (struct tcpstat, netinet/tcp_var.h)");

static int
sysctl_rexmtthresh SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)

	int error, val = tcprexmtthresh;

	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
                return (error);

	/*
	 * Constrain the number of duplicate ACKs
	 * to consider for TCP fast retransmit 
	 * to either 2 or 3
	 */

        if (val < 2 || val > 3)
		return (EINVAL);

	 tcprexmtthresh = val;

	return (0);
}

SYSCTL_PROC(_net_inet_tcp, OID_AUTO, rexmt_thresh, CTLTYPE_INT|CTLFLAG_RW | CTLFLAG_LOCKED,
	&tcprexmtthresh, 0, &sysctl_rexmtthresh, "I", "Duplicate ACK Threshold for Fast Retransmit");
