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
 */

#if ISFB31
#include "opt_ipfw.h"		/* for ipfw_fwd		*/
#include "opt_tcpdebug.h"
#endif

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

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>    /* for ICMP_BANDLIM             */   
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/icmp_var.h>   /* for ICMP_BANDLIM             */
#include <netinet/in_pcb.h>
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
#include <netinet/tcpip.h>
#if TCPDEBUG
#include <netinet/tcp_debug.h>
#if INET6
union {
	struct ip _tcp_si4;
	struct ip6_hdr _tcp_si6;
} tcp_saveip;
#else
struct ip tcp_saveip;
#endif /* INET6 */
struct tcphdr tcp_savetcp;
#endif /* TCPDEBUG */

#if IPSEC
#include <netinet6/ipsec.h>
#include <netkey/key.h>
#endif /*IPSEC*/

#include <sys/kdebug.h>

#define DBG_LAYER_BEG		NETDBG_CODE(DBG_NETTCP, 0)
#define DBG_LAYER_END		NETDBG_CODE(DBG_NETTCP, 2)
#define DBG_FNC_TCP_INPUT       NETDBG_CODE(DBG_NETTCP, (3 << 8))
#define DBG_FNC_TCP_NEWCONN     NETDBG_CODE(DBG_NETTCP, (7 << 8))

static int	tcprexmtthresh = 3;
tcp_seq	tcp_iss;
tcp_cc	tcp_ccgen;
extern int apple_hwcksum_rx;

struct	tcpstat tcpstat;
SYSCTL_STRUCT(_net_inet_tcp, TCPCTL_STATS, stats,
	CTLFLAG_RD, &tcpstat , tcpstat, "");

int log_in_vain = 0;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, log_in_vain, CTLFLAG_RW, 
	&log_in_vain, 0, "");

int tcp_delack_enabled = 1;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, delayed_ack, CTLFLAG_RW, 
	&tcp_delack_enabled, 0, "");

u_long	tcp_now;
struct inpcbhead tcb;
#define	tcb6	tcb  /* for KAME src sync over BSD*'s */
struct inpcbinfo tcbinfo;

static void	 tcp_dooptions __P((struct tcpcb *,
	    u_char *, int, struct tcphdr *, struct tcpopt *));
static void	 tcp_pulloutofband __P((struct socket *,
	    struct tcphdr *, struct mbuf *));
static void	 tcp_xmit_timer __P((struct tcpcb *, int));

/*
 * Neighbor Discovery, Neighbor Unreachability Detection
 * Upper layer hint.
 */
#define ND6_HINT(tp) { \
	if ((tp) && (tp)->t_inpcb && (tp)->t_inpcb->in6p_route.ro_rt) \
		nd6_nud_hint((tp)->t_inpcb->in6p_route.ro_rt, NULL); \
}


extern u_long		current_active_connections;
extern u_long		last_active_conn_count;

extern u_long		*delack_bitmask;




/*
 * Insert segment ti into reassembly queue of tcp with
 * control block tp.  Return TH_FIN if reassembly now includes
 * a segment with FIN.  The macro form does the common case inline
 * (segment is the next to be received on an established connection,
 * and the queue is empty), avoiding linkage into and removal
 * from the queue and repetition of various conversions.
 * Set DELACK for segments received in order, but ack immediately
 * when segments are out of order (so fast retransmit can work).
 */
#if INET6
#define	_ONLY_IF_INET6_(x)	x
#else
#define	_ONLY_IF_INET6_(x)
#endif
#define	TCP_REASS(tp, th, tilen, m, so, flags, isipv6, needwakeup) { \
	if ((th)->th_seq == (tp)->rcv_nxt && \
	    (tp)->segq.lh_first == NULL && \
	    (tp)->t_state == TCPS_ESTABLISHED) { \
		if (tcp_delack_enabled) {\
		    if (last_active_conn_count > DELACK_BITMASK_THRESH) \
		       TCP_DELACK_BITSET(tp->t_inpcb->hash_element); \
		    tp->t_flags |= TF_DELACK; \
		    } \
		else \
			tp->t_flags |= TF_ACKNOW; \
		(tp)->rcv_nxt += (tilen); \
		flags = (th)->th_flags & TH_FIN; \
		tcpstat.tcps_rcvpack++;\
		tcpstat.tcps_rcvbyte += (tilen);\
		_ONLY_IF_INET6_(ND6_HINT(tp);) \
		sbappend(&(so)->so_rcv, (m)); \
		needwakeup++; \
	} else { \
		(flags) = tcp_reass((tp), (th), (tilen), (m), (isipv6)); \
		tp->t_flags |= TF_ACKNOW; \
	} \
}

/*
 * Note:
 * in the ip header part of the ipqe_tcp structure only the length is used.
 */
int
tcp_reass(tp, th, tilen, m, isipv6)
	register struct tcpcb *tp;
	register struct tcphdr *th;
	u_int16_t tilen;
	struct mbuf *m;
#if INET6
	int isipv6;
#endif
{
	register struct ipqent *p, *q, *nq, *tiqe;
	struct socket *so = tp->t_inpcb->inp_socket;
	int flags;

	/*
	 * Call with th==0 after become established to
	 * force pre-ESTABLISHED data up to user socket.
	 */
	if (th == 0)
		goto present;

#if 0 /* Not using GETTCP(m) macro */
	m->m_pkthdr.header = ti;
#endif

	/*
	 * Allocate a new queue entry, before we throw away any data.
	 * If we can't, just drop the packet.  XXX
	 */
	MALLOC(tiqe, struct ipqent *, sizeof (struct ipqent), M_SONAME, M_NOWAIT);
	if (tiqe == NULL) {
		tcpstat.tcps_rcvmemdrop++;
		m_freem(m);
		return (0);
	}

	/*
	 * Find a segment which begins after this one does.
	 */
	for (p = NULL, q = tp->segq.lh_first; q != NULL;
	     p = q, q = q->ipqe_q.le_next)
		if (SEQ_GT(q->ipqe_tcp->ti_seq, th->th_seq))
			break;

	/*
	 * If there is a preceding segment, it may provide some of
	 * our data already.  If so, drop the data from the incoming
	 * segment.  If it provides all of our data, drop us.
	 */
	if (p != NULL) {
		register struct tcpiphdr *phdr = p->ipqe_tcp;
		register int i;

		/* conversion to int (in i) handles seq wraparound */
		i = phdr->ti_seq + phdr->ti_len - th->th_seq;
		if (i > 0) {
			if (i >= tilen) {
				tcpstat.tcps_rcvduppack++;
				tcpstat.tcps_rcvdupbyte += tilen;
				m_freem(m);
				FREE(tiqe, M_SONAME);

#if 1 /* XXX: NetBSD just return 0 here */
				/*
				 * Try to present any queued data
				 * at the left window edge to the user.
				 * This is needed after the 3-WHS
				 * completes.
				 */
				goto present;	/* ??? */
#endif
			}
			m_adj(m, i);
			tilen -= i;
			th->th_seq += i;
		}
	}
	tcpstat.tcps_rcvoopack++;
	tcpstat.tcps_rcvoobyte += tilen;

	/*
	 * While we overlap succeeding segments trim them or,
	 * if they are completely covered, dequeue them.
	 */
	while (q) {
		register struct tcpiphdr *qhdr = q->ipqe_tcp;
		register int i = (th->th_seq + tilen) - qhdr->ti_seq;

		if (i <= 0)
			break;
		if (i < qhdr->ti_len) {
			qhdr->ti_seq += i;
			qhdr->ti_len -= i;
			m_adj(q->ipqe_m, i);
			break;
		}
		nq = q->ipqe_q.le_next;
		m_freem(q->ipqe_m);
		LIST_REMOVE(q, ipqe_q);
		FREE(q, M_SONAME);
		q = nq;
	}

	/* Insert the new fragment queue entry into place. */
	tiqe->ipqe_m = m;
	/*
	 * There is a IP or IPv6 header in the mbuf before th
	 * so there is space for an ip header (for the length field)
	 */
#define thtoti(x) \
	((struct tcpiphdr *)(((char *)(x)) - (sizeof (struct ip))))

	tiqe->ipqe_tcp = thtoti(th);
	tiqe->ipqe_tcp->ti_len = tilen;
	if (p == NULL) {
		LIST_INSERT_HEAD(&tp->segq, tiqe, ipqe_q);
	} else {
		LIST_INSERT_AFTER(p, tiqe, ipqe_q);
	}

present:
	/*
	 * Present data to user, advancing rcv_nxt through
	 * completed sequence space.
	 */
	if (!TCPS_HAVEESTABLISHED(tp->t_state))
		return (0);
	q = tp->segq.lh_first;
	if (!q || q->ipqe_tcp->ti_seq != tp->rcv_nxt)
		return (0);
#if 0
      /*
       * XXX from INRIA for NetBSD, but should not happen because
       * TCPS_HAVEESTABLISHED(tp->t_state) should be true here.
       */
	if (tp->t_state == TCPS_SYN_RECEIVED && q->ipqe_tcp->ti_len)
		return (0);
#endif
	do {
		tp->rcv_nxt += q->ipqe_tcp->ti_len;
		flags = q->ipqe_tcp->ti_flags & TH_FIN;
		nq = q->ipqe_q.le_next;
		LIST_REMOVE(q, ipqe_q);
		if (so->so_state & SS_CANTRCVMORE)
			m_freem(q->ipqe_m);
		else
			sbappend(&so->so_rcv, q->ipqe_m);
		FREE(q, M_SONAME);
		q = nq;
	} while (q && q->ipqe_tcp->ti_seq == tp->rcv_nxt);
#if INET6
	if (isipv6)
		ND6_HINT(tp);
#endif

	KERNEL_DEBUG(DBG_LAYER_END, ((th->th_dport << 16) | th->th_sport),
		     (((thtoti(th)->ti_src.s_addr & 0xffff) << 16) | (thtoti(th)->ti_dst.s_addr & 0xffff)),
		     th->th_seq, th->th_ack, th->th_win);

	sorwakeup(so);
	return (flags);
}

/*
 * TCP input routine, follows pages 65-76 of the
 * protocol specification dated September, 1981 very closely.
 */
#if INET6
int
tcp6_input(mp, offp, proto)
	struct mbuf **mp;
	int *offp, proto;
{
	tcp_input(*mp, *offp);
	return IPPROTO_DONE;
}
#endif

void
tcp_input(m, off)
	struct mbuf *m;
	int off;
{
	register struct tcphdr *th;
	register struct ip *ip = NULL;
	register struct ipovly *ipov;
	register struct inpcb *inp;
	u_char *optp = NULL;
	int optlen = 0;
	int len, toff;
	int hdroptlen;
	u_int16_t tilen;
	register struct tcpcb *tp = 0;
	register int thflags;
	struct socket *so = 0;
	int todrop, acked, ourfinisacked, needoutput = 0;
	struct in_addr laddr;
#if 0
	struct in6_addr laddr6;
#endif
	int dropsocket = 0;
	int iss = 0;
	u_long tiwin;
	struct tcpopt to;		/* options in this segment */
	struct rmxp_tao *taop;		/* pointer to our TAO cache entry */
	struct rmxp_tao	tao_noncached;	/* in case there's no cached entry */
	int need_sowwakeup = 0;
	int need_sorwakeup = 0;
#if TCPDEBUG
	short ostate = 0;
#endif
#if INET6
	struct ip6_hdr *ip6 = NULL;
	int lgminh;
#else /* INET6 */
#define lgminh	(sizeof (struct tcpiphdr))
#endif /* INET6 */
	int isipv6 = (mtod(m, struct ip *)->ip_v == 6) ? 1 : 0;

	struct proc *proc0=current_proc();

	KERNEL_DEBUG(DBG_FNC_TCP_INPUT | DBG_FUNC_START,0,0,0,0,0);

	bzero((char *)&to, sizeof(to));

	tcpstat.tcps_rcvtotal++;
	/*
	 * Get IP and TCP header together in first mbuf.
	 * Note: IP leaves IP header in first mbuf.
	 */
	th = mtod(m, struct tcpiphdr *);

	KERNEL_DEBUG(DBG_LAYER_BEG, ((th->th_dport << 16) | th->th_sport),
		     (((thtoti(th)->ti_src.s_addr & 0xffff) << 16) | (thtoti(th)->ti_dst.s_addr & 0xffff)),
		     th->th_seq, th->th_ack, th->th_win);

#if INET6
	if (isipv6) {
		ip6 = mtod(m, struct ip6_hdr *);
		lgminh = sizeof(struct tcpip6hdr);
	} else {
		lgminh = sizeof(struct tcpiphdr);
#endif /* INET6 */
		ip = mtod(m, struct ip *);
		ipov = (struct ipovly *)ip;
#if INET6
	}
#endif /* INET6 */

#if INET6
	/* XXX not a good place to put this into... */
	if (isipv6 &&
	    m && (m->m_flags & M_ANYCAST6)) {
		icmp6_error(m, ICMP6_DST_UNREACH, ICMP6_DST_UNREACH_ADDR,
			(caddr_t)&ip6->ip6_dst - (caddr_t)ip6);
		return;
	}
#endif /* INET6 */

#if INET6
	if (isipv6) {
		IP6_EXTHDR_CHECK(m, off, sizeof(struct tcphdr), );
		ip6 = mtod(m, struct ip6_hdr *);
		tilen = ntohs(ip6->ip6_plen) - off + sizeof(*ip6);

		if (in6_cksum(m, IPPROTO_TCP, off, tilen)) {
			tcpstat.tcps_rcvbadsum++;
			goto drop;
		}
		th = (struct tcphdr *)((caddr_t)ip6 + off);
	} else
#endif /* INET6 */
	{
		/*
		 * Get IP and TCP header together in first mbuf.
		 * Note: IP leaves IP header in first mbuf.
		 */
		/* XXX: should we still require this for IPv4? */
		if (off > sizeof (struct ip)) {
			ip_stripoptions(m, (struct mbuf *)0);
			off = sizeof(struct ip);
			if (m->m_pkthdr.csum_flags & CSUM_TCP_SUM16)
				m->m_pkthdr.csum_flags = 0; /* invalidate hwcksuming */
		}
		if (m->m_len < lgminh) {
			if ((m = m_pullup(m, lgminh)) == 0) {
				tcpstat.tcps_rcvshort++;
				return;
			}
		}
		ip = mtod(m, struct ip *);
		ipov = (struct ipovly *)ip;
        	th = (struct tcphdr *)((caddr_t)ip + off);
		tilen = ip->ip_len;
		len = sizeof (struct ip) + tilen;

		if (m->m_pkthdr.csum_flags & CSUM_DATA_VALID) {

			if (apple_hwcksum_rx && (m->m_pkthdr.csum_flags & CSUM_TCP_SUM16)) {
				u_short pseudo;
				bzero(ipov->ih_x1, sizeof(ipov->ih_x1));
				ipov->ih_len = (u_short)tilen;
				HTONS(ipov->ih_len);
				pseudo = in_cksum(m, sizeof (struct ip));
				th->th_sum = in_addword(pseudo, (m->m_pkthdr.csum_data & 0xFFFF));
			}
                	else {
                		if (m->m_pkthdr.csum_flags & CSUM_PSEUDO_HDR)
                       	 		th->th_sum = m->m_pkthdr.csum_data;
				else goto dotcpcksum;
			}
               		th->th_sum ^= 0xffff;

        	} else { 
	                 /*
       		          * Checksum extended TCP header and data.
       		          */
dotcpcksum:
			if (th->th_sum) {
				len = sizeof (struct ip) + tilen;
				bzero(ipov->ih_x1, sizeof(ipov->ih_x1));
				ipov->ih_len = (u_short)tilen;
				HTONS(ipov->ih_len);
				th = (struct tcphdr *)((caddr_t)ip + off);
				th->th_sum = in_cksum(m, len);
			}
		}

		if (th->th_sum) {
			tcpstat.tcps_rcvbadsum++;
			goto drop;
		}
	}

	/*
	 * Check that TCP offset makes sense,
	 * pull out TCP options and adjust length.		XXX
	 */
	toff = th->th_off << 2;
	if (toff < sizeof (struct tcphdr) || toff > tilen) {
		tcpstat.tcps_rcvbadoff++;
		goto drop;
	}
	tilen -= toff;
	if (toff > sizeof (struct tcphdr)) {
#if INET6
		if (isipv6) {
			IP6_EXTHDR_CHECK(m, off, toff, );
			ip6 = mtod(m, struct ip6_hdr *);
			th = (struct tcphdr *)((caddr_t)ip6 + off);
		} else
#endif /* INET6 */
		{
			if (m->m_len < sizeof(struct ip) + toff) {
				if ((m = m_pullup(m, sizeof (struct ip) + toff)) == 0) {
					tcpstat.tcps_rcvshort++;
					return;
				}
				ip = mtod(m, struct ip *);
				ipov = (struct ipovly *)ip;
				th = (struct tcphdr *)((caddr_t)ip + off);
			}
		}
		optlen = toff - sizeof (struct tcphdr);
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
			to.to_flag |= TOF_TS;
			to.to_tsval = ntohl(*(u_int32_t *)(optp + 4));
			to.to_tsecr = ntohl(*(u_int32_t *)(optp + 8));
			optp = NULL;	/* we've parsed the options */
		}
	}
	thflags = th->th_flags;

	/*
	 * Convert TCP protocol specific fields to host format.
	 */
	NTOHL(th->th_seq);
	NTOHL(th->th_ack);
	NTOHS(th->th_win);
	NTOHS(th->th_urp);

	/*
	 * Drop TCP, IP headers and TCP options.
	 */
	hdroptlen = off+toff;
	m->m_data += hdroptlen;
	m->m_len  -= hdroptlen;

	/*
	 * Locate pcb for segment.
	 */
findpcb:
#if IPFIREWALL_FORWARD
	if (ip_fw_fwd_addr != NULL
#if INET6
	    && isipv6 == NULL
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
			if (!ip_fw_fwd_addr->sin_port) {
				inp = in_pcblookup_hash(&tcbinfo, ip->ip_src,
				    th->th_sport, ip_fw_fwd_addr->sin_addr,
				    th->th_dport, 1, m->m_pkthdr.rcvif);
			} else {
				inp = in_pcblookup_hash(&tcbinfo,
				    ip->ip_src, th->th_sport,
	    			    ip_fw_fwd_addr->sin_addr,
				    ntohs(ip_fw_fwd_addr->sin_port), 1,
				    m->m_pkthdr.rcvif);
			}
		}
		ip_fw_fwd_addr = NULL;
	} else
#endif	/* IPFIREWALL_FORWARD */

#if INET6
	if (isipv6)
		inp = in6_pcblookup_hash(&tcbinfo, &ip6->ip6_src, th->th_sport,
					 &ip6->ip6_dst, th->th_dport, 1,
					 m->m_pkthdr.rcvif);
	else
#endif /* INET6 */
	inp = in_pcblookup_hash(&tcbinfo, ip->ip_src, th->th_sport,
	    ip->ip_dst, th->th_dport, 1, m->m_pkthdr.rcvif);

#if IPSEC
	/* due to difference from other BSD stacks */
	m->m_data -= hdroptlen;
	m->m_len  += hdroptlen;
#if INET6
	if (isipv6) {
		if (inp != NULL && ipsec6_in_reject_so(m, inp->inp_socket)) {
			ipsec6stat.in_polvio++;
			goto drop;
		}
	} else
#endif /* INET6 */
	if (inp != NULL && ipsec4_in_reject_so(m, inp->inp_socket)) {
		ipsecstat.in_polvio++;
		goto drop;
	}
	m->m_data += hdroptlen;
	m->m_len  -= hdroptlen;
#endif /*IPSEC*/

	/*
	 * If the state is CLOSED (i.e., TCB does not exist) then
	 * all data in the incoming segment is discarded.
	 * If the TCB exists but is in CLOSED state, it is embryonic,
	 * but should either do a listen or a connect soon.
	 */
	if (inp == NULL) {
		if (log_in_vain && thflags & TH_SYN) {
#if INET6
			char buf[INET6_ADDRSTRLEN];
#else /* INET6 */
			char buf[4*sizeof "123"];
#endif /* INET6 */

#if INET6
			if (isipv6) {
				strcpy(buf, ip6_sprintf(&ip6->ip6_dst));
				log(LOG_INFO,
				    "Connection attempt to TCP %s:%d from %s:%d\n",
				    buf, ntohs(th->th_dport),
				    ip6_sprintf(&ip6->ip6_src),
				    ntohs(th->th_sport));
			} else {
#endif
			strcpy(buf, inet_ntoa(ip->ip_dst));
			log(LOG_INFO,
			    "Connection attempt to TCP %s:%d from %s:%d\n",
			    buf, ntohs(th->th_dport), inet_ntoa(ip->ip_src),
			    ntohs(th->th_sport));
#if INET6
			}
#endif /* INET6 */
		}
#if ICMP_BANDLIM
		if (badport_bandlim(1) < 0)
			goto drop;
#endif
		goto dropwithreset;
	}
	tp = intotcpcb(inp);
	if (tp == 0)
		goto dropwithreset;
	if (tp->t_state == TCPS_CLOSED)
		goto drop;

	/* Unscale the window into a 32-bit value. */
	if ((thflags & TH_SYN) == 0)
		tiwin = th->th_win << tp->snd_scale;
	else
		tiwin = th->th_win;

	so = inp->inp_socket;
	if (so->so_options & (SO_DEBUG|SO_ACCEPTCONN)) {
#if TCPDEBUG
		if (so->so_options & SO_DEBUG) {
			ostate = tp->t_state;
#if INET6
			if (isipv6)
				tcp_saveip._tcp_si6 = *ip6;
			else
				tcp_saveip._tcp_si4 = *ip;
#else /* INET6 */
			tcp_saveip = *ip;
#endif /* INET6 */

			tcp_savetcp = *th;
		}
#endif
		if (so->so_options & SO_ACCEPTCONN) {
			register struct tcpcb *tp0 = tp;
			struct socket *so2;
#if IPSEC
			struct socket *oso;
#endif
#if INET6
			struct inpcb *oinp = sotoinpcb(so);
#endif /* INET6 */

#if !IPSEC
			if ((thflags & (TH_RST|TH_ACK|TH_SYN)) != TH_SYN) {
				/*
				 * Note: dropwithreset makes sure we don't
				 * send a RST in response to a RST.
				 */
				if (thflags & TH_ACK) {
					tcpstat.tcps_badsyn++;
					goto dropwithreset;
				}
				goto drop;
			}
#endif
			KERNEL_DEBUG(DBG_FNC_TCP_NEWCONN | DBG_FUNC_START,0,0,0,0,0);
			so2 = sonewconn(so, 0);


			if (so2 == 0) {
				tcpstat.tcps_listendrop++;
				so2 = sodropablereq(so);
				if (so2) {
					tcp_drop(sototcpcb(so2), ETIMEDOUT);
					so2 = sonewconn(so, 0);
				}
				if (!so2)
					goto drop;
			}
#if IPSEC
			oso = so;
#endif
			so = so2;
			/*
			 * This is ugly, but ....
			 *
			 * Mark socket as temporary until we're
			 * committed to keeping it.  The code at
			 * ``drop'' and ``dropwithreset'' check the
			 * flag dropsocket to see if the temporary
			 * socket created here should be discarded.
			 * We mark the socket as discardable until
			 * we're committed to it below in TCPS_LISTEN.
			 */
			dropsocket++;
			inp = (struct inpcb *)so->so_pcb;
#if INET6
			if (isipv6)
				inp->in6p_laddr = ip6->ip6_dst;
			else {
				if (ip6_mapped_addr_on) {
					inp->inp_vflag &= ~INP_IPV6;
					inp->inp_vflag |= INP_IPV4;
				}
#endif /* INET6 */
			inp->inp_laddr = ip->ip_dst;
#if INET6
			}
#endif /* INET6 */

			inp->inp_lport = th->th_dport;
			if (in_pcbinshash(inp) != 0) {
				/*
				 * Undo the assignments above if we failed to put
				 * the PCB on the hash lists.
				 */
#if INET6
				if (isipv6)
					inp->in6p_laddr = in6addr_any;
				else
#endif /* INET6 */
				inp->inp_laddr.s_addr = INADDR_ANY;
				inp->inp_lport = 0;
				goto drop;
			}
#if IPSEC
			/*
			 * from IPsec perspective, it is important to do it
			 * after making actual listening socket.
			 * otherwise, cached security association will bark.
			 *
			 * Subject: (KAME-snap 748)
			 * From: Wayne Knowles <w.knowles@niwa.cri.nz>
			 */
			if ((thflags & (TH_RST|TH_ACK|TH_SYN)) != TH_SYN) {
				/*
				 * Note: dropwithreset makes sure we don't
				 * send a RST in response to a RST.
				 */
				if (thflags & TH_ACK) {
					tcpstat.tcps_badsyn++;
					goto dropwithreset;
				}
				goto drop;
			}
#endif
#if INET6
			if (isipv6) {
				struct ip6_recvpktopts newopts;

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
#if IPSEC
			/* copy old policy into new socket's */
			if (ipsec_copy_policy(sotoinpcb(oso)->inp_sp,
			                      inp->inp_sp))
				printf("tcp_input: could not copy policy\n");
#endif

			tp = intotcpcb(inp);
			tp->t_state = TCPS_LISTEN;
			tp->t_flags |= tp0->t_flags & (TF_NOPUSH|TF_NOOPT);

			/* Compute proper scaling value from buffer space */
			while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
			   TCP_MAXWIN << tp->request_r_scale < so->so_rcv.sb_hiwat)
				tp->request_r_scale++;

			KERNEL_DEBUG(DBG_FNC_TCP_NEWCONN | DBG_FUNC_END,0,0,0,0,0);
		}
	}

#if INET6
	/* save packet options if user wanted */
	if (isipv6 && (inp->in6p_flags & INP_CONTROLOPTS) != 0) {
		struct ip6_recvpktopts opts6;

		/*
		 * Temporarily re-adjusting the mbuf before ip6_savecontrol(),
		 * which is necessary for FreeBSD only due to difference from
		 * other BSD stacks.
		 * XXX: we'll soon make a more natural fix after getting a
		 *      consensus.
		 */
#ifndef DEFER_MADJ
		m->m_data -= hdroptlen;
		m->m_len  += hdroptlen;
#endif
		ip6_savecontrol(inp, ip6, m, &opts6, &inp->in6p_inputopts);
		if (inp->in6p_inputopts)
			ip6_update_recvpcbopt(inp->in6p_inputopts, &opts6);
		if (opts6.head) {
			if (sbappendcontrol(&inp->in6p_socket->so_rcv,
					    NULL, opts6.head)
			    == 0)
				m_freem(opts6.head);
		}
#ifndef DEFER_MADJ
		m->m_data += hdroptlen;	/* XXX */
		m->m_len  -= hdroptlen;	/* XXX */
#endif
	}
#endif /* INET6 */

	/*
	 * Segment received on connection.
	 * Reset idle time and keep-alive timer.
	 */
	tp->t_idle = 0;
	if (TCPS_HAVEESTABLISHED(tp->t_state))
		tp->t_timer[TCPT_KEEP] = tcp_keepidle;

	/*
	 * Process options if not in LISTEN state,
	 * else do it below (after getting remote address).
	 */
	if (tp->t_state != TCPS_LISTEN && optp)
		tcp_dooptions(tp, optp, optlen, th, &to);
	if (th->th_flags & TH_SYN)
		tcp_mss(tp, to.to_maxseg, isipv6);	/* sets t_maxseg */

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
	    (thflags & (TH_SYN|TH_FIN|TH_RST|TH_URG|TH_ACK)) == TH_ACK &&
	    ((tp->t_flags & (TF_NEEDSYN|TF_NEEDFIN)) == 0) &&
	    ((to.to_flag & TOF_TS) == 0 ||
	     TSTMP_GEQ(to.to_tsval, tp->ts_recent)) &&
	    /*
	     * Using the CC option is compulsory if once started:
	     *   the segment is OK if no T/TCP was negotiated or
	     *   if the segment has a CC option equal to CCrecv
	     */
	    ((tp->t_flags & (TF_REQ_CC|TF_RCVD_CC)) != (TF_REQ_CC|TF_RCVD_CC) ||
	     ((to.to_flag & TOF_CC) != 0 && to.to_cc == tp->cc_recv)) &&
	    th->th_seq == tp->rcv_nxt &&
	    tiwin && tiwin == tp->snd_wnd &&
	    tp->snd_nxt == tp->snd_max) {

		/*
		 * If last ACK falls within this segment's sequence numbers,
		 * record the timestamp.
		 * NOTE that the test is modified according to the latest
		 * proposal of the tcplw@cray.com list (Braden 1993/04/26).
		 */
		if ((to.to_flag & TOF_TS) != 0 &&
		   SEQ_LEQ(th->th_seq, tp->last_ack_sent)) {
			tp->ts_recent_age = tcp_now;
			tp->ts_recent = to.to_tsval;
		}

		if (tilen == 0) {
			if (SEQ_GT(th->th_ack, tp->snd_una) &&
			    SEQ_LEQ(th->th_ack, tp->snd_max) &&
			    tp->snd_cwnd >= tp->snd_wnd &&
			    tp->t_dupacks < tcprexmtthresh) {
				/*
				 * this is a pure ack for outstanding data.
				 */
				++tcpstat.tcps_predack;
				if ((to.to_flag & TOF_TS) != 0)
					tcp_xmit_timer(tp,
					    tcp_now - to.to_tsecr + 1);
				else if (tp->t_rtt &&
					    SEQ_GT(th->th_ack, tp->t_rtseq))
					tcp_xmit_timer(tp, tp->t_rtt);
				acked = th->th_ack - tp->snd_una;
				tcpstat.tcps_rcvackpack++;
				tcpstat.tcps_rcvackbyte += acked;
				sbdrop(&so->so_snd, acked);
				tp->snd_una = th->th_ack;
				m_freem(m);
#if INET6
				/* some progress has been done */
				if (isipv6)
					ND6_HINT(tp);
#endif

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
					tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;

				if (so->so_snd.sb_cc)
					(void) tcp_output(tp);
				sowwakeup(so);
				KERNEL_DEBUG(DBG_FNC_TCP_INPUT | DBG_FUNC_END,0,0,0,0,0);
				return;
			}
		} else if (th->th_ack == tp->snd_una &&
		    tp->segq.lh_first == NULL &&
		    tilen <= sbspace(&so->so_rcv)) {
			/*
			 * this is a pure, in-sequence data packet
			 * with nothing on the reassembly queue and
			 * we have enough buffer space to take it.
			 */
			++tcpstat.tcps_preddat;
			tp->rcv_nxt += tilen;
			tcpstat.tcps_rcvpack++;
			tcpstat.tcps_rcvbyte += tilen;
#if INET6
			/* some progress has been done */
			if (isipv6)
				ND6_HINT(tp);
#endif
			sbappend(&so->so_rcv, m);
			KERNEL_DEBUG(DBG_LAYER_END, ((th->th_dport << 16) | th->th_sport),
			     (((thtoti(th)->ti_src.s_addr & 0xffff) << 16) | (thtoti(th)->ti_dst.s_addr & 0xffff)),
			     th->th_seq, th->th_ack, th->th_win); 
			if (tcp_delack_enabled) {
			    if (last_active_conn_count > DELACK_BITMASK_THRESH)
				TCP_DELACK_BITSET(tp->t_inpcb->hash_element); 
			    tp->t_flags |= TF_DELACK;
			} else {
				tp->t_flags |= TF_ACKNOW;
				tcp_output(tp);
			}
			sorwakeup(so);
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
	{ int win;

	win = sbspace(&so->so_rcv);
	if (win < 0)
		win = 0;
	tp->rcv_wnd = imax(win, (int)(tp->rcv_adv - tp->rcv_nxt));
	}

	switch (tp->t_state) {

	/*
	 * If the state is LISTEN then ignore segment if it contains an RST.
	 * If the segment contains an ACK then it is bad and send a RST.
	 * If it does not contain a SYN then it is not interesting; drop it.
	 * If it is from this socket, drop it, it must be forged.
	 * Don't bother responding if the destination was a broadcast.
	 * Otherwise initialize tp->rcv_nxt, and tp->irs, select an initial
	 * tp->iss, and send a segment:
	 *     <SEQ=ISS><ACK=RCV_NXT><CTL=SYN,ACK>
	 * Also initialize tp->snd_nxt to tp->iss+1 and tp->snd_una to tp->iss.
	 * Fill in remote peer address fields if not previously specified.
	 * Enter SYN_RECEIVED state, and process any other fields of this
	 * segment in this state.
	 */
	case TCPS_LISTEN: {
		register struct sockaddr_in *sin;
#if 0
		register struct sockaddr_in6 *sin6;
#endif

		if (thflags & TH_RST)
			goto drop;
		if (thflags & TH_ACK)
			goto dropwithreset;
		if ((thflags & TH_SYN) == 0)
			goto drop;
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

#if INET6
		if (isipv6) {
			if (m->m_flags & (M_BCAST|M_MCAST) ||
			    IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst))
				goto drop;
#if 1
			/*
			 * Perhaps this should be a call/macro
			 * to a function like in6_pcbconnect(), but almost
			 * all of the checks have been done: we know
			 * that the association is unique, and the
			 * local address is always set here.
			 */
			if (IN6_IS_ADDR_UNSPECIFIED(&inp->in6p_laddr))
				inp->in6p_laddr = ip6->ip6_dst;
			inp->in6p_faddr = ip6->ip6_src;
			inp->inp_fport = th->th_sport;

			/* TODO: flowinfo initialization */

			in_pcbrehash(inp);
#else
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
					   &proc0)) {
				inp->in6p_laddr = laddr6;
				FREE(sin6, M_SONAME);
				goto drop;
			}
			FREE(sin6, M_SONAME);
#endif
		}
		else {
#endif /* INET6 */
			/*
			 * RFC1122 4.2.3.10, p. 104: discard bcast/mcast SYN
			 * in_broadcast() should never return true on a received
			 * packet with M_BCAST not set.
			 */
			if (m->m_flags & (M_BCAST|M_MCAST) ||
			    IN_MULTICAST(ntohl(ip->ip_dst.s_addr)))
				goto drop;
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
			if (in_pcbconnect(inp, (struct sockaddr *)sin, &proc0)) {
				inp->inp_laddr = laddr;
				FREE(sin, M_SONAME);
				goto drop;
			}
			FREE(sin, M_SONAME);
#if INET6
		}
#endif /* INET6 */

		tp->t_template = tcp_template(tp);
		if (tp->t_template == 0) {
			tp = tcp_drop(tp, ENOBUFS);
			dropsocket = 0;		/* socket is already gone */
			goto drop;
		}
		if ((taop = tcp_gettaocache(inp)) == NULL) {
			taop = &tao_noncached;
			bzero(taop, sizeof(*taop));
		}
		tcp_dooptions(tp, optp, optlen, th, &to);
		if (th->th_flags & TH_SYN)
			tcp_mss(tp, to.to_maxseg, isipv6);	/* sets t_maxseg */
		if (iss)
			tp->iss = iss;
		else {
#ifdef TCP_COMPAT_42
			tcp_iss += TCP_ISSINCR/2;
			tp->iss = tcp_iss;
#else
			tp->iss = tcp_rndiss_next();
#endif /* TCP_COMPAT_42 */
                }
		tp->irs = th->th_seq;
		tcp_sendseqinit(tp);
		tcp_rcvseqinit(tp);
		/*
		 * Initialization of the tcpcb for transaction;
		 *   set SND.WND = SEG.WND,
		 *   initialize CCsend and CCrecv.
		 */
		tp->snd_wnd = tiwin;	/* initial send-window */
		tp->cc_send = CC_INC(tcp_ccgen);
		tp->cc_recv = to.to_cc;
		/*
		 * Perform TAO test on incoming CC (SEG.CC) option, if any.
		 * - compare SEG.CC against cached CC from the same host,
		 *	if any.
		 * - if SEG.CC > chached value, SYN must be new and is accepted
		 *	immediately: save new CC in the cache, mark the socket
		 *	connected, enter ESTABLISHED state, turn on flag to
		 *	send a SYN in the next segment.
		 *	A virtual advertised window is set in rcv_adv to
		 *	initialize SWS prevention.  Then enter normal segment
		 *	processing: drop SYN, process data and FIN.
		 * - otherwise do a normal 3-way handshake.
		 */
		if ((to.to_flag & TOF_CC) != 0) {
		    if (((tp->t_flags & TF_NOPUSH) != 0) &&
			taop->tao_cc != 0 && CC_GT(to.to_cc, taop->tao_cc)) {

			taop->tao_cc = to.to_cc;
			if (tp->t_state != TCPS_ESTABLISHED)
				current_active_connections++;

			tp->t_state = TCPS_ESTABLISHED;

			/*
			 * If there is a FIN, or if there is data and the
			 * connection is local, then delay SYN,ACK(SYN) in
			 * the hope of piggy-backing it on a response
			 * segment.  Otherwise must send ACK now in case
			 * the other side is slow starting.
			 */
			if (tcp_delack_enabled &&
			    ((thflags & TH_FIN) ||
			     (tilen != 0 &&
#if INET6
			      (isipv6 && in6_localaddr(&inp->in6p_faddr))
			      ||
			      (!isipv6 &&
#endif /* INET6 */
			       in_localaddr(inp->inp_faddr)
#if INET6
			       )
#endif /* INET6 */
			      ))) {
			    if (last_active_conn_count > DELACK_BITMASK_THRESH)
				TCP_DELACK_BITSET(tp->t_inpcb->hash_element); 

				tp->t_flags |= (TF_DELACK | TF_NEEDSYN);
			}
			else
				tp->t_flags |= (TF_ACKNOW | TF_NEEDSYN);

			/*
			 * Limit the `virtual advertised window' to TCP_MAXWIN
			 * here.  Even if we requested window scaling, it will
			 * become effective only later when our SYN is acked.
			 */
			tp->rcv_adv += min(tp->rcv_wnd, TCP_MAXWIN);
			tcpstat.tcps_connects++;
			soisconnected(so);
			tp->t_timer[TCPT_KEEP] = tcp_keepinit;
			dropsocket = 0;		/* committed to socket */
			tcpstat.tcps_accepts++;
			goto trimthenstep6;
		    }
		/* else do standard 3-way handshake */
		} else {
		    /*
		     * No CC option, but maybe CC.NEW:
		     *   invalidate cached value.
		     */
		     taop->tao_cc = 0;
		}
		/*
		 * TAO test failed or there was no CC option,
		 *    do a standard 3-way handshake.
		 */
		tp->t_flags |= TF_ACKNOW;
		tp->t_state = TCPS_SYN_RECEIVED;
		tp->t_timer[TCPT_KEEP] = tcp_keepinit;
		dropsocket = 0;		/* committed to socket */
		tcpstat.tcps_accepts++;
		goto trimthenstep6;
		}

	/*
	 * If the state is SYN_RECEIVED:
	 *	if seg contains an ACK, but not for our SYN/ACK, send a RST.
	 */
	case TCPS_SYN_RECEIVED:
		if ((thflags & TH_ACK) &&
		    (SEQ_LEQ(th->th_ack, tp->snd_una) ||
		     SEQ_GT(th->th_ack, tp->snd_max)))
				goto dropwithreset;
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
		if ((taop = tcp_gettaocache(inp)) == NULL) {
			taop = &tao_noncached;
			bzero(taop, sizeof(*taop));
		}

		if ((thflags & TH_ACK) &&
		    (SEQ_LEQ(th->th_ack, tp->iss) ||
		     SEQ_GT(th->th_ack, tp->snd_max))) {
			/*
			 * If we have a cached CCsent for the remote host,
			 * hence we haven't just crashed and restarted,
			 * do not send a RST.  This may be a retransmission
			 * from the other side after our earlier ACK was lost.
			 * Our new SYN, when it arrives, will serve as the
			 * needed ACK.
			 */
			if (taop->tao_ccsent != 0)
				goto drop;
			else
				goto dropwithreset;
		}
		if (thflags & TH_RST) {
			if (thflags & TH_ACK) {
				tp = tcp_drop(tp, ECONNREFUSED);
				postevent(so, 0, EV_RESET);
		  }
			goto drop;
		}
		if ((thflags & TH_SYN) == 0)
			goto drop;
		tp->snd_wnd = th->th_win;	/* initial send window */
		tp->cc_recv = to.to_cc;		/* foreign CC */

		tp->irs = th->th_seq;
		tcp_rcvseqinit(tp);
		if (thflags & TH_ACK) {
			/*
			 * Our SYN was acked.  If segment contains CC.ECHO
			 * option, check it to make sure this segment really
			 * matches our SYN.  If not, just drop it as old
			 * duplicate, but send an RST if we're still playing
			 * by the old rules.  If no CC.ECHO option, make sure
			 * we don't get fooled into using T/TCP.
			 */
			if (to.to_flag & TOF_CCECHO) {
				if (tp->cc_send != to.to_ccecho)
					if (taop->tao_ccsent != 0)
						goto drop;
					else
						goto dropwithreset;
			} else
				tp->t_flags &= ~TF_RCVD_CC;
			tcpstat.tcps_connects++;
			soisconnected(so);
			/* Do window scaling on this connection? */
			if ((tp->t_flags & (TF_RCVD_SCALE|TF_REQ_SCALE)) ==
				(TF_RCVD_SCALE|TF_REQ_SCALE)) {
				tp->snd_scale = tp->requested_s_scale;
				tp->rcv_scale = tp->request_r_scale;
			}
			/* Segment is acceptable, update cache if undefined. */
			if (taop->tao_ccsent == 0)
				taop->tao_ccsent = to.to_ccecho;

			tp->rcv_adv += tp->rcv_wnd;
			tp->snd_una++;		/* SYN is acked */
			/*
			 * If there's data, delay ACK; if there's also a FIN
			 * ACKNOW will be turned on later.
			 */
			if (tcp_delack_enabled && tilen != 0) {
			    if (last_active_conn_count > DELACK_BITMASK_THRESH)
				TCP_DELACK_BITSET(tp->t_inpcb->hash_element); 
				tp->t_flags |= TF_DELACK;
			}
			else
				tp->t_flags |= TF_ACKNOW;
			/*
			 * Received <SYN,ACK> in SYN_SENT[*] state.
			 * Transitions:
			 *	SYN_SENT  --> ESTABLISHED
			 *	SYN_SENT* --> FIN_WAIT_1
			 */
			if (tp->t_flags & TF_NEEDFIN) {
				tp->t_state = TCPS_FIN_WAIT_1;
				tp->t_flags &= ~TF_NEEDFIN;
				thflags &= ~TH_SYN;
			} else {
				if (tp->t_state != TCPS_ESTABLISHED)
					current_active_connections++;
				tp->t_state = TCPS_ESTABLISHED;
				tp->t_timer[TCPT_KEEP] = tcp_keepidle;
			}
		} else {
		/*
		 *  Received initial SYN in SYN-SENT[*] state => simul-
		 *  taneous open.  If segment contains CC option and there is
		 *  a cached CC, apply TAO test; if it succeeds, connection is
		 *  half-synchronized.  Otherwise, do 3-way handshake:
		 *        SYN-SENT -> SYN-RECEIVED
		 *        SYN-SENT* -> SYN-RECEIVED*
		 *  If there was no CC option, clear cached CC value.
		 */
			tp->t_flags |= TF_ACKNOW;
			tp->t_timer[TCPT_REXMT] = 0;
			if (to.to_flag & TOF_CC) {
				if (taop->tao_cc != 0 &&
				    CC_GT(to.to_cc, taop->tao_cc)) {
					/*
					 * update cache and make transition:
					 *        SYN-SENT -> ESTABLISHED*
					 *        SYN-SENT* -> FIN-WAIT-1*
					 */
					taop->tao_cc = to.to_cc;
					if (tp->t_flags & TF_NEEDFIN) {
						tp->t_state = TCPS_FIN_WAIT_1;
						tp->t_flags &= ~TF_NEEDFIN;
					} else {
						if (tp->t_state != TCPS_ESTABLISHED)
							current_active_connections++;
						tp->t_state = TCPS_ESTABLISHED;
						tp->t_timer[TCPT_KEEP] = tcp_keepidle;
					}
					tp->t_flags |= TF_NEEDSYN;
				} else
					tp->t_state = TCPS_SYN_RECEIVED;
			} else {
				/* CC.NEW or no option => invalidate cache */
				taop->tao_cc = 0;
				tp->t_state = TCPS_SYN_RECEIVED;
			}
		}

trimthenstep6:
		/*
		 * Advance th->th_seq to correspond to first data byte.
		 * If data, trim to stay within window,
		 * dropping FIN if necessary.
		 */
		th->th_seq++;
		if (tilen > tp->rcv_wnd) {
			todrop = tilen - tp->rcv_wnd;
			m_adj(m, -todrop);
			tilen = tp->rcv_wnd;
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
	 *	if segment contains a SYN and CC [not CC.NEW] option:
	 *              if state == TIME_WAIT and connection duration > MSL,
	 *                  drop packet and send RST;
	 *
	 *		if SEG.CC > CCrecv then is new SYN, and can implicitly
	 *		    ack the FIN (and data) in retransmission queue.
	 *                  Complete close and delete TCPCB.  Then reprocess
	 *                  segment, hoping to find new TCPCB in LISTEN state;
	 *
	 *		else must be old SYN; drop it.
	 *      else do normal processing.
	 */
	case TCPS_LAST_ACK:
	case TCPS_CLOSING:
	case TCPS_TIME_WAIT:
		if ((thflags & TH_SYN) &&
		    (to.to_flag & TOF_CC) && tp->cc_recv != 0) {
			if (tp->t_state == TCPS_TIME_WAIT &&
					tp->t_duration > TCPTV_MSL)
				goto dropwithreset;
			if (CC_GT(to.to_cc, tp->cc_recv)) {
				tp = tcp_close(tp);
				goto findpcb;
			}
			else
				goto drop;
		}
 		break;  /* continue normal processing */
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
	 *   Also, it does not make sense to allow reset segments with
	 *   sequence numbers greater than last_ack_sent to be processed
	 *   since these sequence numbers are just the acknowledgement
	 *   numbers in our outgoing packets being echoed back at us,
	 *   and these acknowledgement numbers are monotonically
	 *   increasing.
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
	 *    ESTABLISHED, FIN_WAIT_1, FIN_WAIT2, CLOSE_WAIT STATES:
	 *	Inform user that connection was reset, and close tcb.
	 *    CLOSING, LAST_ACK, TIME_WAIT STATES
	 *	Close the tcb.
	 *    TIME_WAIT state:
	 *	Drop the segment - see Stevens, vol. 2, p. 964 and
	 *      RFC 1337.
	 */
	if (thflags & TH_RST) {
		if (tp->last_ack_sent == th->th_seq) {
			switch (tp->t_state) {

			case TCPS_SYN_RECEIVED:
				so->so_error = ECONNREFUSED;
				goto close;

			case TCPS_ESTABLISHED:
			case TCPS_FIN_WAIT_1:
			case TCPS_CLOSE_WAIT:
				current_active_connections--;
				/*
				  Drop through ...
				*/
			case TCPS_FIN_WAIT_2:
				so->so_error = ECONNRESET;
			close:
				postevent(so, 0, EV_RESET);
				tp->t_state = TCPS_CLOSED;
				tcpstat.tcps_drops++;
				tp = tcp_close(tp);
				break;

			case TCPS_CLOSING:
			case TCPS_LAST_ACK:
				current_active_connections--;
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
	if ((to.to_flag & TOF_TS) != 0 && tp->ts_recent &&
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
			tcpstat.tcps_rcvdupbyte += tilen;
			tcpstat.tcps_pawsdrop++;
			goto dropafterack;
		}
	}

	/*
	 * T/TCP mechanism
	 *   If T/TCP was negotiated and the segment doesn't have CC,
	 *   or if its CC is wrong then drop the segment.
	 *   RST segments do not have to comply with this.
	 */
	if ((tp->t_flags & (TF_REQ_CC|TF_RCVD_CC)) == (TF_REQ_CC|TF_RCVD_CC) &&
	    ((to.to_flag & TOF_CC) == 0 || tp->cc_recv != to.to_cc))
 		goto dropafterack;

	/*
	 * In the SYN-RECEIVED state, validate that the packet belongs to
	 * this connection before trimming the data to fit the receive
	 * window.  Check the sequence number versus IRS since we know
	 * the sequence numbers haven't wrapped.  This is a partial fix
	 * for the "LAND" DoS attack.
	 */
	if (tp->t_state == TCPS_SYN_RECEIVED && SEQ_LT(th->th_seq, tp->irs))
		goto dropwithreset;

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
		if (todrop > tilen
		    || (todrop == tilen && (thflags & TH_FIN) == 0)) {
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
			todrop = tilen;
			tcpstat.tcps_rcvduppack++;
			tcpstat.tcps_rcvdupbyte += todrop;
		} else {
			tcpstat.tcps_rcvpartduppack++;
			tcpstat.tcps_rcvpartdupbyte += todrop;
		}
		m_adj(m, todrop);
		th->th_seq += todrop;
		tilen -= todrop;
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
	    tp->t_state > TCPS_CLOSE_WAIT && tilen) {
		tp = tcp_close(tp);
		tcpstat.tcps_rcvafterclose++;
		goto dropwithreset;
	}

	/*
	 * If segment ends after window, drop trailing data
	 * (and PUSH and FIN); if nothing left, just ACK.
	 */
	todrop = (th->th_seq+tilen) - (tp->rcv_nxt+tp->rcv_wnd);
	if (todrop > 0) {
		tcpstat.tcps_rcvpackafterwin++;
		if (todrop >= tilen) {
			tcpstat.tcps_rcvbyteafterwin += tilen;
			/*
			 * If a new connection request is received
			 * while in TIME_WAIT, drop the old connection
			 * and start over if the sequence numbers
			 * are above the previous ones.
			 */
			if (thflags & TH_SYN &&
			    tp->t_state == TCPS_TIME_WAIT &&
			    SEQ_GT(th->th_seq, tp->rcv_nxt)) {
#ifdef TCP_COMPAT_42
				iss = tp->rcv_nxt + TCP_ISSINCR;
#else
				iss = tcp_rndiss_next();
#endif /* TCP_COMPAT_42 */
				tp = tcp_close(tp);
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
		tilen -= todrop;
		thflags &= ~(TH_PUSH|TH_FIN);
	}

	/*
	 * If last ACK falls within this segment's sequence numbers,
	 * record its timestamp.
	 * NOTE that the test is modified according to the latest
	 * proposal of the tcplw@cray.com list (Braden 1993/04/26).
	 */
	if ((to.to_flag & TOF_TS) != 0 &&
	    SEQ_LEQ(th->th_seq, tp->last_ack_sent)) {
		tp->ts_recent_age = tcp_now;
		tp->ts_recent = to.to_tsval;
	}

	/*
	 * If a SYN is in the window, then this is an
	 * error and we send an RST and drop the connection.
	 */
	if (thflags & TH_SYN) {
		tp = tcp_drop(tp, ECONNRESET);
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
		soisconnected(so);
		current_active_connections++;

		/* Do window scaling? */
		if ((tp->t_flags & (TF_RCVD_SCALE|TF_REQ_SCALE)) ==
			(TF_RCVD_SCALE|TF_REQ_SCALE)) {
			tp->snd_scale = tp->requested_s_scale;
			tp->rcv_scale = tp->request_r_scale;
		}
		/*
		 * Upon successful completion of 3-way handshake,
		 * update cache.CC if it was undefined, pass any queued
		 * data to the user, and advance state appropriately.
		 */
		if ((taop = tcp_gettaocache(inp)) != NULL &&
		    taop->tao_cc == 0)
			taop->tao_cc = tp->cc_recv;

		/*
		 * Make transitions:
		 *      SYN-RECEIVED  -> ESTABLISHED
		 *      SYN-RECEIVED* -> FIN-WAIT-1
		 */
		if (tp->t_flags & TF_NEEDFIN) {
			tp->t_state = TCPS_FIN_WAIT_1;
			tp->t_flags &= ~TF_NEEDFIN;
		} else {
			tp->t_state = TCPS_ESTABLISHED;
			tp->t_timer[TCPT_KEEP] = tcp_keepidle;
		}
		/*
		 * If segment contains data or ACK, will call tcp_reass()
		 * later; if not, do so now to pass queued data to user.
		 */
		if (tilen == 0 && (thflags & TH_FIN) == 0)
			(void) tcp_reass(tp, (struct tcphdr *)0, 0,
			    (struct mbuf *)0, isipv6);
		tp->snd_wl1 = th->th_seq - 1;
		/* fall into ... */

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

		if (SEQ_LEQ(th->th_ack, tp->snd_una)) {
			if (tilen == 0 && tiwin == tp->snd_wnd) {
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
				else if (++tp->t_dupacks == tcprexmtthresh) {
					tcp_seq onxt = tp->snd_nxt;
					u_int win =
					    min(tp->snd_wnd, tp->snd_cwnd) / 2 /
						tp->t_maxseg;

					if (win < 2)
						win = 2;
					tp->snd_ssthresh = win * tp->t_maxseg;
					tp->t_timer[TCPT_REXMT] = 0;
					tp->t_rtt = 0;
					tp->snd_nxt = th->th_ack;
					tp->snd_cwnd = tp->t_maxseg;
					(void) tcp_output(tp);
					tp->snd_cwnd = tp->snd_ssthresh +
					       tp->t_maxseg * tp->t_dupacks;
					if (SEQ_GT(onxt, tp->snd_nxt))
						tp->snd_nxt = onxt;
					goto drop;
				} else if (tp->t_dupacks > tcprexmtthresh) {
					tp->snd_cwnd += tp->t_maxseg;
					(void) tcp_output(tp);
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
		if (tp->t_dupacks >= tcprexmtthresh &&
		    tp->snd_cwnd > tp->snd_ssthresh)
			tp->snd_cwnd = tp->snd_ssthresh;
		tp->t_dupacks = 0;
		if (SEQ_GT(th->th_ack, tp->snd_max)) {
			tcpstat.tcps_rcvacktoomuch++;
			goto dropafterack;
		}
		/*
		 *  If we reach this point, ACK is not a duplicate,
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
		 * If we have a timestamp reply, update smoothed
		 * round trip time.  If no timestamp is present but
		 * transmit timer is running and timed sequence
		 * number was acked, update smoothed round trip time.
		 * Since we now have an rtt measurement, cancel the
		 * timer backoff (cf., Phil Karn's retransmit alg.).
		 * Recompute the initial retransmit timer.
		 */
		if (to.to_flag & TOF_TS)
			tcp_xmit_timer(tp, tcp_now - to.to_tsecr + 1);
		else if (tp->t_rtt && SEQ_GT(th->th_ack, tp->t_rtseq))
			tcp_xmit_timer(tp,tp->t_rtt);

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
			tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;

		/*
		 * If no data (only SYN) was ACK'd,
		 *    skip rest of ACK processing.
		 */
		if (acked == 0)
			goto step6;

		/*
		 * When new data is acked, open the congestion window.
		 * If the window gives us less than ssthresh packets
		 * in flight, open exponentially (maxseg per packet).
		 * Otherwise open linearly: maxseg per window
		 * (maxseg^2 / cwnd per packet).
		 */
		{
		register u_int cw = tp->snd_cwnd;
		register u_int incr = tp->t_maxseg;

		if (cw > tp->snd_ssthresh)
			incr = incr * incr / cw;
		tp->snd_cwnd = min(cw + incr, TCP_MAXWIN<<tp->snd_scale);
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
		need_sowwakeup++;
		tp->snd_una = th->th_ack;
		if (SEQ_LT(tp->snd_nxt, tp->snd_una))
			tp->snd_nxt = tp->snd_una;

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
					soisdisconnected(so);
					tp->t_timer[TCPT_2MSL] = tcp_maxidle;
				}
				add_to_time_wait(tp);
				current_active_connections--;
				tp->t_state = TCPS_FIN_WAIT_2;
			}
			break;

	 	/*
		 * In CLOSING STATE in addition to the processing for
		 * the ESTABLISHED state if the ACK acknowledges our FIN
		 * then enter the TIME-WAIT state, otherwise ignore
		 * the segment.
		 */
		case TCPS_CLOSING:
			if (ourfinisacked) {
				tp->t_state = TCPS_TIME_WAIT;
				tcp_canceltimers(tp);
				/* Shorten TIME_WAIT [RFC-1644, p.28] */
				if (tp->cc_recv != 0 &&
				    tp->t_duration < TCPTV_MSL)
					tp->t_timer[TCPT_2MSL] =
					    tp->t_rxtcur * TCPTV_TWTRUNC;
				else
					tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
				add_to_time_wait(tp);
				current_active_connections--;
				soisdisconnected(so);
			}
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
			tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
			add_to_time_wait(tp);
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
		if (tilen == 0 &&
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
		if (th->th_urp <= (u_long)tilen
#if SO_OOBINLINE
		     && (so->so_options & SO_OOBINLINE) == 0
#endif
		     )
			tcp_pulloutofband(so, th, m);
	} else
		/*
		 * If no out of band data is expected,
		 * pull receive urgent pointer along
		 * with the receive window.
		 */
		if (SEQ_GT(tp->rcv_nxt, tp->rcv_up))
			tp->rcv_up = tp->rcv_nxt;
dodata:							/* XXX */

	/*
	 * Process the segment text, merging it into the TCP sequencing queue,
	 * and arranging for acknowledgment of receipt if necessary.
	 * This process logically involves adjusting tp->rcv_wnd as data
	 * is presented to the user (this happens in tcp_usrreq.c,
	 * case PRU_RCVD).  If a FIN has already been received on this
	 * connection then we just ignore the text.
	 */
	if ((tilen || (thflags&TH_FIN)) &&
	    TCPS_HAVERCVDFIN(tp->t_state) == 0) {
		TCP_REASS(tp, th, tilen, m, so, thflags, isipv6, need_sorwakeup);

		if (tp->t_flags & TF_DELACK) 
		{
		KERNEL_DEBUG(DBG_LAYER_END, ((th->th_dport << 16) | th->th_sport),
			     (((thtoti(th)->ti_src.s_addr & 0xffff) << 16) | (thtoti(th)->ti_dst.s_addr & 0xffff)),
			     th->th_seq, th->th_ack, th->th_win); 
		}
		/*
		 * Note the amount of data that peer has sent into
		 * our window, in order to estimate the sender's
		 * buffer size.
		 */
		len = so->so_rcv.sb_hiwat - (tp->rcv_adv - tp->rcv_nxt);
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
			 *  so it may be piggybacked when SYN is sent.
			 *  Otherwise, since we received a FIN then no
			 *  more input can be expected, send ACK now.
			 */
			if (tcp_delack_enabled && (tp->t_flags & TF_NEEDSYN)) {
			    if (last_active_conn_count > DELACK_BITMASK_THRESH)
				TCP_DELACK_BITSET(tp->t_inpcb->hash_element); 

				tp->t_flags |= TF_DELACK;
			}
			else
				tp->t_flags |= TF_ACKNOW;
			tp->rcv_nxt++;
		}
		switch (tp->t_state) {

	 	/*
		 * In SYN_RECEIVED and ESTABLISHED STATES
		 * enter the CLOSE_WAIT state.
		 */
		case TCPS_SYN_RECEIVED:
		case TCPS_ESTABLISHED:
			tp->t_state = TCPS_CLOSE_WAIT;
			break;

	 	/*
		 * If still in FIN_WAIT_1 STATE FIN has not been acked so
		 * enter the CLOSING state.
		 */
		case TCPS_FIN_WAIT_1:
			tp->t_state = TCPS_CLOSING;
			break;

	 	/*
		 * In FIN_WAIT_2 state enter the TIME_WAIT state,
		 * starting the time-wait timer, turning off the other
		 * standard timers.
		 */
		case TCPS_FIN_WAIT_2:
			tp->t_state = TCPS_TIME_WAIT;
			tcp_canceltimers(tp);
			/* Shorten TIME_WAIT [RFC-1644, p.28] */
			if (tp->cc_recv != 0 &&
			    tp->t_duration < TCPTV_MSL) {
				tp->t_timer[TCPT_2MSL] =
				    tp->t_rxtcur * TCPTV_TWTRUNC;
				/* For transaction client, force ACK now. */
				tp->t_flags |= TF_ACKNOW;
			}
			else
				tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;

			add_to_time_wait(tp);
			soisdisconnected(so);
			break;

		/*
		 * In TIME_WAIT state restart the 2 MSL time_wait timer.
		 */
		case TCPS_TIME_WAIT:
			tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
			add_to_time_wait(tp);
			break;
		}
	}
#if TCPDEBUG
	if (so->so_options & SO_DEBUG) {
#if INET6
		if (isipv6)
			tcp_saveip._tcp_si6.ip6_plen = tilen;
		else
			tcp_saveip._tcp_si4.ip_len = tilen;
#else /* INET6 */
		tcp_saveip.ip_len = tilen;
#endif /* INET6 */

		tcp_trace(TA_INPUT, ostate, tp, (void *)&tcp_saveip,
			  &tcp_savetcp, 0);
	}
#endif

	/*
	 * Return any desired output.
	 */
	if (needoutput || (tp->t_flags & TF_ACKNOW))
		(void) tcp_output(tp);
	if (need_sorwakeup)
		sorwakeup(so);
	if (need_sowwakeup)
		sowwakeup(so);
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
	     SEQ_GT(th->th_ack, tp->snd_max)) )
		goto dropwithreset;
#if TCPDEBUG
	if (so->so_options & SO_DEBUG) {
#if INET6
		if (isipv6)
			tcp_saveip._tcp_si6.ip6_plen = tilen;
		else
			tcp_saveip._tcp_si4.ip_len = tilen;
#else /* INET6 */
		tcp_saveip.ip_len = tilen;
#endif /* INET6 */
		tcp_trace(TA_DROP, ostate, tp, (void *)&tcp_saveip,
			  &tcp_savetcp, 0);
	}
#endif
	m_freem(m);
	tp->t_flags |= TF_ACKNOW;
	(void) tcp_output(tp);
	if (need_sorwakeup)
		sorwakeup(so);
	if (need_sowwakeup)
		sowwakeup(so);
	KERNEL_DEBUG(DBG_FNC_TCP_INPUT | DBG_FUNC_END,0,0,0,0,0);
	return;

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
		if (IN6_IS_ADDR_MULTICAST(&ip6->ip6_dst))
			goto drop; /* anycast check is done at the top */
	} else
#endif /* INET6 */
	if (IN_MULTICAST(ntohl(ip->ip_dst.s_addr)))
		goto drop;
#if TCPDEBUG
	if (tp == 0 || (tp->t_inpcb->inp_socket->so_options & SO_DEBUG)) {
		if (tp == 0) {
#if INET6
			if (isipv6)
				tcp_saveip._tcp_si6 = *ip6;
			else
				tcp_saveip._tcp_si4 = *ip;
#else /* INET6 */
			tcp_saveip = *ip;
#endif /* INET6 */
	    	}
#if INET6
		if (isipv6)
			tcp_saveip._tcp_si6.ip6_plen = tilen;
		else
			tcp_saveip._tcp_si4.ip_len = tilen;
#else /* INET6 */
		tcp_saveip.ip_len = tilen;
#endif /* INET6 */
		tcp_trace(TA_DROP, ostate, tp, (void *)&tcp_saveip,
			  &tcp_savetcp, 0);
	}
#endif
	if (thflags & TH_ACK)
#if INET6
		tcp_respond(tp, isipv6 ? (void *)ip6 : (void *)ip, th, m,
			    (tcp_seq)0, th->th_ack, TH_RST, isipv6);
#else /* INET6 */
		tcp_respond(tp, (void *)ip, th, m,
			    (tcp_seq)0, th->th_ack, TH_RST, isipv6);
#endif /* INET6 */
	else {
		if (thflags & TH_SYN)
			tilen++;
#if INET6
		tcp_respond(tp, isipv6 ? (void *)ip6 : (void *)ip, th, m,
			    th->th_seq+tilen, (tcp_seq)0, TH_RST|TH_ACK,
			    isipv6);
#else /* INET6 */
		tcp_respond(tp, (void *)ip, th, m,
			    th->th_seq+tilen, (tcp_seq)0, TH_RST|TH_ACK,
			    isipv6);
#endif /* INET6 */
	}
	/* destroy temporarily created socket */
	if (need_sorwakeup)
		sorwakeup(so);
	if (need_sowwakeup)
		sowwakeup(so);
	if (dropsocket)
		(void) soabort(so);
	KERNEL_DEBUG(DBG_FNC_TCP_INPUT | DBG_FUNC_END,0,0,0,0,0);
	return;

drop:
	/*
	 * Drop space held by incoming segment and return.
	 */
#if TCPDEBUG
	if (tp == 0 || (tp->t_inpcb->inp_socket->so_options & SO_DEBUG)) {
		if (tp == 0) {
#if INET6
			if (isipv6)
				tcp_saveip._tcp_si6 = *ip6;
			else
				tcp_saveip._tcp_si4 = *ip;
#else /* INET6 */
			tcp_saveip = *ip;
#endif /* INET6 */
	    	}
#if INET6
		if (isipv6)
			tcp_saveip._tcp_si6.ip6_plen = tilen;
		else
			tcp_saveip._tcp_si4.ip_len = tilen;
#else /* INET6 */
		tcp_saveip.ip_len = tilen;
#endif /* INET6 */
		tcp_trace(TA_DROP, ostate, tp, (void *)&tcp_saveip,
			  &tcp_savetcp, 0);
	}
#endif
	m_freem(m);
	if (need_sorwakeup)
		sorwakeup(so);
	if (need_sowwakeup)
		sowwakeup(so);
	/* destroy temporarily created socket */
	if (dropsocket)
		(void) soabort(so);
	KERNEL_DEBUG(DBG_FNC_TCP_INPUT | DBG_FUNC_END,0,0,0,0,0);
	return;
}

static void
tcp_dooptions(tp, cp, cnt, th, to)
	struct tcpcb *tp;
	u_char *cp;
	int cnt;
	struct tcphdr *th;
	struct tcpopt *to;
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
			optlen = cp[1];
			if (optlen <= 0)
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
			to->to_maxseg = ntohs(mss);
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
			to->to_flag |= TOF_TS;
			bcopy((char *)cp + 2,
			    (char *)&to->to_tsval, sizeof(to->to_tsval));
			NTOHL(to->to_tsval);
			bcopy((char *)cp + 6,
			    (char *)&to->to_tsecr, sizeof(to->to_tsecr));
			NTOHL(to->to_tsecr);

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
		case TCPOPT_CC:
			if (optlen != TCPOLEN_CC)
				continue;
			to->to_flag |= TOF_CC;
			bcopy((char *)cp + 2,
			    (char *)&to->to_cc, sizeof(to->to_cc));
			NTOHL(to->to_cc);
			/*
			 * A CC or CC.new option received in a SYN makes
			 * it ok to send CC in subsequent segments.
			 */
			if (th->th_flags & TH_SYN)
				tp->t_flags |= TF_RCVD_CC;
			break;
		case TCPOPT_CCNEW:
			if (optlen != TCPOLEN_CC)
				continue;
			if (!(th->th_flags & TH_SYN))
				continue;
			to->to_flag |= TOF_CCNEW;
			bcopy((char *)cp + 2,
			    (char *)&to->to_cc, sizeof(to->to_cc));
			NTOHL(to->to_cc);
			/*
			 * A CC or CC.new option received in a SYN makes
			 * it ok to send CC in subsequent segments.
			 */
			tp->t_flags |= TF_RCVD_CC;
			break;
		case TCPOPT_CCECHO:
			if (optlen != TCPOLEN_CC)
				continue;
			if (!(th->th_flags & TH_SYN))
				continue;
			to->to_flag |= TOF_CCECHO;
			bcopy((char *)cp + 2,
			    (char *)&to->to_ccecho, sizeof(to->to_ccecho));
			NTOHL(to->to_ccecho);
			break;
		}
	}
}

/*
 * Pull out of band byte out of a segment so
 * it doesn't appear in the user's data queue.
 * It is still reflected in the segment length for
 * sequencing purposes.
 */
static void
tcp_pulloutofband(so, th, m)
	struct socket *so;
	struct tcphdr *th;
	register struct mbuf *m;
{
	int cnt = th->th_urp - 1;

	while (cnt >= 0) {
		if (m->m_len > cnt) {
			char *cp = mtod(m, caddr_t) + cnt;
			struct tcpcb *tp = sototcpcb(so);

			tp->t_iobc = *cp;
			tp->t_oobflags |= TCPOOB_HAVEDATA;
			bcopy(cp+1, cp, (unsigned)(m->m_len - cnt - 1));
			m->m_len--;
			return;
		}
		cnt -= m->m_len;
		m = m->m_next;
		if (m == 0)
			break;
	}
	panic("tcp_pulloutofband");
}

/*
 * Collect new round-trip time estimate
 * and update averages and current timeout.
 */
static void
tcp_xmit_timer(tp, rtt)
	register struct tcpcb *tp;
	short rtt;
{
	register int delta;

	tcpstat.tcps_rttupdated++;
	tp->t_rttupdated++;
	if (tp->t_srtt != 0) {
		/*
		 * srtt is stored as fixed point with 5 bits after the
		 * binary point (i.e., scaled by 8).  The following magic
		 * is equivalent to the smoothing algorithm in rfc793 with
		 * an alpha of .875 (srtt = rtt/8 + srtt*7/8 in fixed
		 * point).  Adjust rtt to origin 0.
		 */
		delta = ((rtt - 1) << TCP_DELTA_SHIFT)
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
	} else {
		/*
		 * No rtt measurement yet - use the unsmoothed rtt.
		 * Set the variance to half the rtt (so our first
		 * retransmit happens at 3*rtt).
		 */
		tp->t_srtt = rtt << TCP_RTT_SHIFT;
		tp->t_rttvar = rtt << (TCP_RTTVAR_SHIFT - 1);
	}
	tp->t_rtt = 0;
	tp->t_rxtshift = 0;

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
		      max(tp->t_rttmin, rtt + 2), TCPTV_REXMTMAX);

	/*
	 * We received an ack for a packet that wasn't retransmitted;
	 * it is probably safe to discard any error indications we've
	 * received recently.  This isn't quite right, but close enough
	 * for now (a route might have failed after we sent a segment,
	 * and the return path might not be symmetrical).
	 */
	tp->t_softerror = 0;
}

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
 * In case of T/TCP, we call this routine during implicit connection
 * setup as well (offer = -1), to initialize maxseg from the cached
 * MSS of our peer.
 */
void
tcp_mss(tp, offer, isipv6)
	struct tcpcb *tp;
	int offer;
#if INET6
	int isipv6;
#endif
{
	register struct rtentry *rt;
	struct ifnet *ifp;
	register int rtt, mss;
	u_long bufsize;
	struct inpcb *inp;
	struct socket *so;
	struct rmxp_tao *taop;
	int origoffer = offer;
#if INET6
	int lgminh = isipv6 ? sizeof (struct tcpip6hdr) :
			      sizeof (struct tcpiphdr);
#else /* INET6 */
#define lgminh  (sizeof (struct tcpiphdr))
#endif /* INET6 */

	inp = tp->t_inpcb;
#if INET6
	if (isipv6)
		rt = tcp_rtlookup6(inp);
	else
#endif /* INET6 */
	rt = tcp_rtlookup(inp);
	if (rt == NULL) {
		tp->t_maxopd = tp->t_maxseg =
#if INET6
		isipv6 ? tcp_v6mssdflt :
#endif /* INET6 */
		tcp_mssdflt;
		return;
	}
	ifp = rt->rt_ifp;
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
	else
		/*
		 * Sanity check: make sure that maxopd will be large
		 * enough to allow some data on segments even is the
		 * all the option space is used (40bytes).  Otherwise
		 * funny things may happen in tcp_output.
		 */
		offer = max(offer, 64);
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
			tp->t_rttmin = rtt / (RTM_RTTUNIT / PR_SLOWHZ);
		tp->t_srtt = rtt / (RTM_RTTUNIT / (PR_SLOWHZ * TCP_RTT_SCALE));
		tcpstat.tcps_usedrtt++;
		if (rt->rt_rmx.rmx_rttvar) {
			tp->t_rttvar = rt->rt_rmx.rmx_rttvar /
			    (RTM_RTTUNIT / (PR_SLOWHZ * TCP_RTTVAR_SCALE));
			tcpstat.tcps_usedrttvar++;
		} else {
			/* default variation is +- 1 rtt */
			tp->t_rttvar =
			    tp->t_srtt * TCP_RTTVAR_SCALE / TCP_RTT_SCALE;
		}
		TCPT_RANGESET(tp->t_rxtcur,
		    ((tp->t_srtt >> 2) + tp->t_rttvar) >> 1,
		    tp->t_rttmin, TCPTV_REXMTMAX);
	}
	/*
	 * if there's an mtu associated with the route, use it
	 * else, use the link mtu.
	 */
	if (rt->rt_rmx.rmx_mtu)
		mss = rt->rt_rmx.rmx_mtu - lgminh;
	else
		mss =
#if INET6
			isipv6 ? nd_ifinfo[rt->rt_ifp->if_index].linkmtu :
#endif
			ifp->if_mtu - lgminh;

	if (rt->rt_rmx.rmx_mtu == 0) {
#if INET6
		if (isipv6) {
			if (!in6_localaddr(&inp->in6p_faddr))
				mss = min(mss, tcp_v6mssdflt);
		} else
#endif /* INET6 */
		if (!in_localaddr(inp->inp_faddr))
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
	 * In case of T/TCP, origoffer==-1 indicates, that no segments
	 * were received yet.  In this case we just guess, otherwise
	 * we do the same as before T/TCP.
	 */
 	if ((tp->t_flags & (TF_REQ_TSTMP|TF_NOOPT)) == TF_REQ_TSTMP &&
	    (origoffer == -1 ||
	     (tp->t_flags & TF_RCVD_TSTMP) == TF_RCVD_TSTMP))
		mss -= TCPOLEN_TSTAMP_APPA;
 	if ((tp->t_flags & (TF_REQ_CC|TF_NOOPT)) == TF_REQ_CC &&
	    (origoffer == -1 ||
	     (tp->t_flags & TF_RCVD_CC) == TF_RCVD_CC))
		mss -= TCPOLEN_CC_APPA;

#if	(MCLBYTES & (MCLBYTES - 1)) == 0
		if (mss > MCLBYTES)
			mss &= ~(MCLBYTES-1);
#else
		if (mss > MCLBYTES)
			mss = mss / MCLBYTES * MCLBYTES;
#endif
	/*
	 * If there's a pipesize, change the socket buffer
	 * to that size.  Make the socket buffers an integral
	 * number of mss units; if the mss is larger than
	 * the socket buffer, decrease the mss.
	 */
#if RTV_SPIPE
	if ((bufsize = rt->rt_rmx.rmx_sendpipe) == 0)
#endif
		bufsize = so->so_snd.sb_hiwat;
	if (bufsize < mss)
		mss = bufsize;
	else {
		bufsize = roundup(bufsize, mss);
		if (bufsize > sb_max)
			bufsize = sb_max;
		(void)sbreserve(&so->so_snd, bufsize);
	}
	tp->t_maxseg = mss;

#if RTV_RPIPE
	if ((bufsize = rt->rt_rmx.rmx_recvpipe) == 0)
#endif
		bufsize = so->so_rcv.sb_hiwat;
	if (bufsize > mss) {
		bufsize = roundup(bufsize, mss);
		if (bufsize > sb_max)
			bufsize = sb_max;
		(void)sbreserve(&so->so_rcv, bufsize);
	}
	/*
	 * Don't force slow-start on local network.
	 */
#if INET6
	if (isipv6) {
		if (!in6_localaddr(&inp->in6p_faddr))
			tp->snd_cwnd = mss;
	} else
#endif /* INET6 */
	if (!in_localaddr(inp->inp_faddr))
		tp->snd_cwnd = mss;

	if (rt->rt_rmx.rmx_ssthresh) {
		/*
		 * There's some sort of gateway or interface
		 * buffer limit on the path.  Use this to set
		 * the slow start threshhold, but set the
		 * threshold to no less than 2*mss.
		 */
		tp->snd_ssthresh = max(2 * mss, rt->rt_rmx.rmx_ssthresh);
		tcpstat.tcps_usedssthresh++;
	}
}

/*
 * Determine the MSS option to send on an outgoing SYN.
 */
int
tcp_mssopt(tp, isipv6)
	struct tcpcb *tp;
#if INET6
	int isipv6;
#endif
{
	struct rtentry *rt;
	int mss;
#if INET6
	int lgminh = isipv6 ? sizeof (struct tcpip6hdr) :
			      sizeof (struct tcpiphdr);
#else /* INET6 */
#define lgminh  (sizeof (struct tcpiphdr))
#endif /* INET6 */

#if INET6
	if (isipv6)
		rt = tcp_rtlookup6(tp->t_inpcb);
	else
#endif /* INET6 */
	rt = tcp_rtlookup(tp->t_inpcb);
	if (rt == NULL)
		return
#if INET6
			isipv6 ? tcp_v6mssdflt :
#endif /* INET6 */
			tcp_mssdflt;

	mss = rt->rt_ifp->if_mtu - lgminh;

	return mss;
}
