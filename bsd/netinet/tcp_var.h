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
 * Copyright (c) 1982, 1986, 1993, 1994, 1995
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
 *	@(#)tcp_var.h	8.4 (Berkeley) 5/24/95
 */

#ifndef _NETINET_TCP_VAR_H_
#define _NETINET_TCP_VAR_H_
#define N_TIME_WAIT_SLOTS   128                /* must be power of 2 */

/*
 * Ip (reassembly or sequence) queue structures.
 *
 * XXX -- The following explains why the ipqe_m field is here, for TCP's use:
 * We want to avoid doing m_pullup on incoming packets but that
 * means avoiding dtom on the tcp reassembly code.  That in turn means
 * keeping an mbuf pointer in the reassembly queue (since we might
 * have a cluster).  As a quick hack, the source & destination
 * port numbers (which are no longer needed once we've located the
 * tcpcb) are overlayed with an mbuf pointer.
 */
LIST_HEAD(ipqehead, ipqent);
struct ipqent {
	LIST_ENTRY(ipqent) ipqe_q;
	union {
		struct ip	*_ip;
#if INET6
		struct ipv6	*_ip6;
#endif
		struct tcpiphdr *_tcp;
	} _ipqe_u1;
	struct mbuf	*ipqe_m;	/* mbuf contains packet */
	u_int8_t	ipqe_mff;	/* for IP fragmentation */
};
#define	ipqe_ip		_ipqe_u1._ip
#if INET6
#define	ipqe_ip6	_ipqe_u1._ip6
#endif
#define	ipqe_tcp	_ipqe_u1._tcp
#define tcp6cb		tcpcb  /* for KAME src sync over BSD*'s */

#define TCP_DELACK_BITSET(hash_elem)\
delack_bitmask[((hash_elem) >> 5)] |= 1 << ((hash_elem) & 0x1F)

#define DELACK_BITMASK_ON     1
#define DELACK_BITMASK_THRESH 300

/*
 * Kernel variables for tcp.
 */

/*
 * Tcp control block, one per tcp; fields:
 * Organized for 16 byte cacheline efficiency.
 */
struct tcpcb {
	struct ipqehead segq;		/* sequencing queue */
	int	t_dupacks;		/* consecutive dup acks recd */
	struct tcptemp	*t_template;	/* skeletal packet for transmit */

	int	t_timer[TCPT_NTIMERS];	/* tcp timers */

	struct	inpcb *t_inpcb;		/* back pointer to internet pcb */
	int	t_state;		/* state of this connection */
	u_int	t_flags;
#define	TF_ACKNOW	0x00001		/* ack peer immediately */
#define	TF_DELACK	0x00002		/* ack, but try to delay it */
#define	TF_NODELAY	0x00004		/* don't delay packets to coalesce */
#define	TF_NOOPT	0x00008		/* don't use tcp options */
#define	TF_SENTFIN	0x00010		/* have sent FIN */
#define	TF_REQ_SCALE	0x00020		/* have/will request window scaling */
#define	TF_RCVD_SCALE	0x00040		/* other side has requested scaling */
#define	TF_REQ_TSTMP	0x00080		/* have/will request timestamps */
#define	TF_RCVD_TSTMP	0x00100		/* a timestamp was received in SYN */
#define	TF_SACK_PERMIT	0x00200		/* other side said I could SACK */
#define	TF_NEEDSYN	0x00400		/* send SYN (implicit state) */
#define	TF_NEEDFIN	0x00800		/* send FIN (implicit state) */
#define	TF_NOPUSH	0x01000		/* don't push */
#define	TF_REQ_CC	0x02000		/* have/will request CC */
#define	TF_RCVD_CC	0x04000		/* a CC was received in SYN */
#define	TF_SENDCCNEW	0x08000		/* send CCnew instead of CC in SYN */
#define	TF_MORETOCOME	0x10000		/* More data to be appended to sock */
	int	t_force;		/* 1 if forcing out a byte */

	tcp_seq	snd_una;		/* send unacknowledged */
	tcp_seq	snd_max;		/* highest sequence number sent;
					 * used to recognize retransmits
					 */
	tcp_seq	snd_nxt;		/* send next */
	tcp_seq	snd_up;			/* send urgent pointer */

	tcp_seq	snd_wl1;		/* window update seg seq number */
	tcp_seq	snd_wl2;		/* window update seg ack number */
	tcp_seq	iss;			/* initial send sequence number */
	tcp_seq	irs;			/* initial receive sequence number */

	tcp_seq	rcv_nxt;		/* receive next */
	tcp_seq	rcv_adv;		/* advertised window */
	u_long	rcv_wnd;		/* receive window */
	tcp_seq	rcv_up;			/* receive urgent pointer */

	u_long	snd_wnd;		/* send window */
	u_long	snd_cwnd;		/* congestion-controlled window */
	u_long	snd_ssthresh;		/* snd_cwnd size threshold for
					 * for slow start exponential to
					 * linear switch
					 */
	u_int	t_maxopd;		/* mss plus options */

	u_int	t_idle;			/* inactivity time */
	u_long	t_duration;		/* connection duration */
	int	t_rtt;			/* round trip time */
	tcp_seq	t_rtseq;		/* sequence number being timed */

	int	t_rxtcur;		/* current retransmit value */
	u_int	t_maxseg;		/* maximum segment size */
	int	t_srtt;			/* smoothed round-trip time */
	int	t_rttvar;		/* variance in round-trip time */

	int	t_rxtshift;		/* log(2) of rexmt exp. backoff */
	u_int	t_rttmin;		/* minimum rtt allowed */
	u_long	t_rttupdated;		/* number of times rtt sampled */
	u_long	max_sndwnd;		/* largest window peer has offered */

	int	t_softerror;		/* possible error not yet reported */
/* out-of-band data */
	char	t_oobflags;		/* have some */
	char	t_iobc;			/* input character */
#define	TCPOOB_HAVEDATA	0x01
#define	TCPOOB_HADDATA	0x02
/* RFC 1323 variables */
	u_char	snd_scale;		/* window scaling for send window */
	u_char	rcv_scale;		/* window scaling for recv window */
	u_char	request_r_scale;	/* pending window scaling */
	u_char	requested_s_scale;
	u_long	ts_recent;		/* timestamp echo data */

	u_long	ts_recent_age;		/* when last updated */
	tcp_seq	last_ack_sent;
/* RFC 1644 variables */
	tcp_cc	cc_send;		/* send connection count */
	tcp_cc	cc_recv;		/* receive connection count */
	u_long	reserved[4];
};

/*
 * Structure to hold TCP options that are only used during segment
 * processing (in tcp_input), but not held in the tcpcb.
 * It's basically used to reduce the number of parameters
 * to tcp_dooptions.
 */
struct tcpopt {
	u_long	to_flag;		/* which options are present */
#define TOF_TS		0x0001		/* timestamp */
#define TOF_CC		0x0002		/* CC and CCnew are exclusive */
#define TOF_CCNEW	0x0004
#define	TOF_CCECHO	0x0008
	u_long	to_tsval;
	u_long	to_tsecr;
	tcp_cc	to_cc;		/* holds CC or CCnew */
	tcp_cc	to_ccecho;
	u_short to_maxseg;
};

/*
 * The TAO cache entry which is stored in the protocol family specific
 * portion of the route metrics.
 */
struct rmxp_tao {
	tcp_cc	tao_cc;			/* latest CC in valid SYN */
	tcp_cc	tao_ccsent;		/* latest CC sent to peer */
	u_short	tao_mssopt;		/* peer's cached MSS */
#ifdef notyet
	u_short	tao_flags;		/* cache status flags */
#define	TAOF_DONT	0x0001		/* peer doesn't understand rfc1644 */
#define	TAOF_OK		0x0002		/* peer does understand rfc1644 */
#define	TAOF_UNDEF	0		/* we don't know yet */
#endif /* notyet */
};
#define rmx_taop(r)	((struct rmxp_tao *)(r).rmx_filler)

#define	intotcpcb(ip)	((struct tcpcb *)(ip)->inp_ppcb)
#define	sototcpcb(so)	(intotcpcb(sotoinpcb(so)))

/*
 * The smoothed round-trip time and estimated variance
 * are stored as fixed point numbers scaled by the values below.
 * For convenience, these scales are also used in smoothing the average
 * (smoothed = (1/scale)sample + ((scale-1)/scale)smoothed).
 * With these scales, srtt has 3 bits to the right of the binary point,
 * and thus an "ALPHA" of 0.875.  rttvar has 2 bits to the right of the
 * binary point, and is smoothed with an ALPHA of 0.75.
 */
#define	TCP_RTT_SCALE		32	/* multiplier for srtt; 3 bits frac. */
#define	TCP_RTT_SHIFT		5	/* shift for srtt; 3 bits frac. */
#define	TCP_RTTVAR_SCALE	16	/* multiplier for rttvar; 2 bits */
#define	TCP_RTTVAR_SHIFT	4	/* shift for rttvar; 2 bits */
#define	TCP_DELTA_SHIFT		2	/* see tcp_input.c */

/*
 * The initial retransmission should happen at rtt + 4 * rttvar.
 * Because of the way we do the smoothing, srtt and rttvar
 * will each average +1/2 tick of bias.  When we compute
 * the retransmit timer, we want 1/2 tick of rounding and
 * 1 extra tick because of +-1/2 tick uncertainty in the
 * firing of the timer.  The bias will give us exactly the
 * 1.5 tick we need.  But, because the bias is
 * statistical, we have to test that we don't drop below
 * the minimum feasible timer (which is 2 ticks).
 * This version of the macro adapted from a paper by Lawrence
 * Brakmo and Larry Peterson which outlines a problem caused
 * by insufficient precision in the original implementation,
 * which results in inappropriately large RTO values for very
 * fast networks.
 */
#define	TCP_REXMTVAL(tp) \
	max((tp)->t_rttmin, (((tp)->t_srtt >> (TCP_RTT_SHIFT - TCP_DELTA_SHIFT))  \
	  + (tp)->t_rttvar) >> TCP_DELTA_SHIFT)

/*
 * TCP statistics.
 * Many of these should be kept per connection,
 * but that's inconvenient at the moment.
 */
struct	tcpstat {
	u_long	tcps_connattempt;	/* connections initiated */
	u_long	tcps_accepts;		/* connections accepted */
	u_long	tcps_connects;		/* connections established */
	u_long	tcps_drops;		/* connections dropped */
	u_long	tcps_conndrops;		/* embryonic connections dropped */
	u_long	tcps_closed;		/* conn. closed (includes drops) */
	u_long	tcps_segstimed;		/* segs where we tried to get rtt */
	u_long	tcps_rttupdated;	/* times we succeeded */
	u_long	tcps_delack;		/* delayed acks sent */
	u_long	tcps_timeoutdrop;	/* conn. dropped in rxmt timeout */
	u_long	tcps_rexmttimeo;	/* retransmit timeouts */
	u_long	tcps_persisttimeo;	/* persist timeouts */
	u_long	tcps_keeptimeo;		/* keepalive timeouts */
	u_long	tcps_keepprobe;		/* keepalive probes sent */
	u_long	tcps_keepdrops;		/* connections dropped in keepalive */

	u_long	tcps_sndtotal;		/* total packets sent */
	u_long	tcps_sndpack;		/* data packets sent */
	u_long	tcps_sndbyte;		/* data bytes sent */
	u_long	tcps_sndrexmitpack;	/* data packets retransmitted */
	u_long	tcps_sndrexmitbyte;	/* data bytes retransmitted */
	u_long	tcps_sndacks;		/* ack-only packets sent */
	u_long	tcps_sndprobe;		/* window probes sent */
	u_long	tcps_sndurg;		/* packets sent with URG only */
	u_long	tcps_sndwinup;		/* window update-only packets sent */
	u_long	tcps_sndctrl;		/* control (SYN|FIN|RST) packets sent */

	u_long	tcps_rcvtotal;		/* total packets received */
	u_long	tcps_rcvpack;		/* packets received in sequence */
	u_long	tcps_rcvbyte;		/* bytes received in sequence */
	u_long	tcps_rcvbadsum;		/* packets received with ccksum errs */
	u_long	tcps_rcvbadoff;		/* packets received with bad offset */
	u_long	tcps_rcvmemdrop;	/* packets dropped for lack of memory */
	u_long	tcps_rcvshort;		/* packets received too short */
	u_long	tcps_rcvduppack;	/* duplicate-only packets received */
	u_long	tcps_rcvdupbyte;	/* duplicate-only bytes received */
	u_long	tcps_rcvpartduppack;	/* packets with some duplicate data */
	u_long	tcps_rcvpartdupbyte;	/* dup. bytes in part-dup. packets */
	u_long	tcps_rcvoopack;		/* out-of-order packets received */
	u_long	tcps_rcvoobyte;		/* out-of-order bytes received */
	u_long	tcps_rcvpackafterwin;	/* packets with data after window */
	u_long	tcps_rcvbyteafterwin;	/* bytes rcvd after window */
	u_long	tcps_rcvafterclose;	/* packets rcvd after "close" */
	u_long	tcps_rcvwinprobe;	/* rcvd window probe packets */
	u_long	tcps_rcvdupack;		/* rcvd duplicate acks */
	u_long	tcps_rcvacktoomuch;	/* rcvd acks for unsent data */
	u_long	tcps_rcvackpack;	/* rcvd ack packets */
	u_long	tcps_rcvackbyte;	/* bytes acked by rcvd acks */
	u_long	tcps_rcvwinupd;		/* rcvd window update packets */
	u_long	tcps_pawsdrop;		/* segments dropped due to PAWS */
	u_long	tcps_predack;		/* times hdr predict ok for acks */
	u_long	tcps_preddat;		/* times hdr predict ok for data pkts */
	u_long	tcps_pcbcachemiss;
	u_long	tcps_cachedrtt;		/* times cached RTT in route updated */
	u_long	tcps_cachedrttvar;	/* times cached rttvar updated */
	u_long	tcps_cachedssthresh;	/* times cached ssthresh updated */
	u_long	tcps_usedrtt;		/* times RTT initialized from route */
	u_long	tcps_usedrttvar;	/* times RTTVAR initialized from rt */
	u_long	tcps_usedssthresh;	/* times ssthresh initialized from rt*/
	u_long	tcps_persistdrop;	/* timeout in persist state */
	u_long	tcps_badsyn;		/* bogus SYN, e.g. premature ACK */
	u_long	tcps_mturesent;		/* resends due to MTU discovery */
	u_long	tcps_listendrop;	/* listen queue overflows */
};

/*
 * TCB structure exported to user-land via sysctl(3).
 * Evil hack: declare only if in_pcb.h and sys/socketvar.h have been
 * included.  Not all of our clients do.
 */
#if defined(_NETINET_IN_PCB_H_) && defined(_SYS_SOCKETVAR_H_)
struct	xtcpcb {
	size_t	xt_len;
	struct	inpcb	xt_inp;
	struct	tcpcb	xt_tp;
	struct	xsocket	xt_socket;
	u_quad_t	xt_alignment_hack;
};
#endif

/*
 * Names for TCP sysctl objects
 */
#define	TCPCTL_DO_RFC1323	1	/* use RFC-1323 extensions */
#define	TCPCTL_DO_RFC1644	2	/* use RFC-1644 extensions */
#define	TCPCTL_MSSDFLT		3	/* MSS default */
#define TCPCTL_STATS		4	/* statistics (read-only) */
#define	TCPCTL_RTTDFLT		5	/* default RTT estimate */
#define	TCPCTL_KEEPIDLE		6	/* keepalive idle timer */
#define	TCPCTL_KEEPINTVL	7	/* interval to send keepalives */
#define	TCPCTL_SENDSPACE	8	/* send buffer space */
#define	TCPCTL_RECVSPACE	9	/* receive buffer space */
#define	TCPCTL_KEEPINIT		10	/* receive buffer space */
#define	TCPCTL_PCBLIST		11	/* list of all outstanding PCBs */
#define	TCPCTL_V6MSSDFLT	12	/* MSS default for IPv6 */
#define TCPCTL_MAXID		13

#define TCPCTL_NAMES { \
	{ 0, 0 }, \
	{ "rfc1323", CTLTYPE_INT }, \
	{ "rfc1644", CTLTYPE_INT }, \
	{ "mssdflt", CTLTYPE_INT }, \
	{ "stats", CTLTYPE_STRUCT }, \
	{ "rttdflt", CTLTYPE_INT }, \
	{ "keepidle", CTLTYPE_INT }, \
	{ "keepintvl", CTLTYPE_INT }, \
	{ "sendspace", CTLTYPE_INT }, \
	{ "recvspace", CTLTYPE_INT }, \
	{ "keepinit", CTLTYPE_INT }, \
	{ "pcblist", CTLTYPE_STRUCT }, \
	{ "v6mssdflt", CTLTYPE_INT }, \
}

#ifdef KERNEL
#ifdef SYSCTL_DECL
SYSCTL_DECL(_net_inet_tcp);
#endif

extern	struct inpcbhead tcb;		/* head of queue of active tcpcb's */
extern	struct inpcbinfo tcbinfo;
extern	struct tcpstat tcpstat;	/* tcp statistics */
extern	int tcp_mssdflt;	/* XXX */
extern	int tcp_v6mssdflt;	/* XXX */
extern	u_long tcp_now;		/* for RFC 1323 timestamps */
extern	int tcp_delack_enabled;

void	 tcp_canceltimers __P((struct tcpcb *));
struct tcpcb *
	 tcp_close __P((struct tcpcb *));
void	 tcp_ctlinput __P((int, struct sockaddr *, void *));
#if INET6
struct ip6_hdr;
void	 tcp6_ctlinput __P((int, struct sockaddr *,void *));
#endif
int	 tcp_ctloutput __P((struct socket *, struct sockopt *));
struct tcpcb *
	 tcp_drop __P((struct tcpcb *, int));
void	 tcp_drain __P((void));
void	 tcp_fasttimo __P((void));
struct rmxp_tao *
	 tcp_gettaocache __P((struct inpcb *));
void     tcp_init __P((void));
#if INET6
void     tcp6_init __P((void));
int	 tcp6_input __P((struct mbuf **, int *, int));
#endif /* INET6 */
void	 tcp_input __P((struct mbuf *, int));
#if INET6
void	 tcp_mss __P((struct tcpcb *, int, int));
int	 tcp_mssopt __P((struct tcpcb *, int));
#else /* INET6 */
void	 tcp_mss __P((struct tcpcb *, int));
int	 tcp_mssopt __P((struct tcpcb *));
#endif /* INET6 */

void	 tcp_mtudisc __P((struct inpcb *, int));
struct tcpcb *
	 tcp_newtcpcb __P((struct inpcb *));
int	 tcp_output __P((struct tcpcb *));
void	 tcp_quench __P((struct inpcb *, int));
#if INET6
void	 tcp_respond __P((struct tcpcb *, void *, struct tcphdr *,
			  struct mbuf *, tcp_seq, tcp_seq, int, int));
#else /* INET6 */
void	 tcp_respond __P((struct tcpcb *, void *, struct tcphdr *,
			  struct mbuf *, tcp_seq, tcp_seq, int));
#endif /* INET6 */

struct rtentry *
	 tcp_rtlookup __P((struct inpcb *));
#if INET6
struct rtentry *
	 tcp_rtlookup6 __P((struct inpcb *));
#endif /* INET6 */
void	 tcp_setpersist __P((struct tcpcb *));
void	 tcp_slowtimo __P((void));
struct tcptemp *
	 tcp_template __P((struct tcpcb *));
struct tcpcb *
	 tcp_timers __P((struct tcpcb *, int));
#if INET6
void	 tcp_trace __P((int, int, struct tcpcb *, void *, struct tcphdr *, 
			int));
#else
void	 tcp_trace __P((int, int, struct tcpcb *, struct ip *,
			struct tcphdr *, int));
#endif

#if INET6
int	 tcp_reass __P((struct tcpcb *, struct tcphdr *, int,
	    struct mbuf *, int));
#else /* INET6 */
int	 tcp_reass __P((struct tcpcb *, struct tcphdr *, int, struct mbuf *));
/* suppress INET6 only args */
#define tcp_reass(x, y, z, t, i)		tcp_reass(x, y, z, t)
#define tcp_mss(x, y, i)			tcp_mss(x, y)
#define tcp_mssopt(x, i)			tcp_mssopt(x)
#define tcp_respond(x, y, z, m, s1, s2, f, i)	tcp_respond(x, y, z, m, s1, \
							    s2, f)

#endif /* INET6 */

extern	struct pr_usrreqs tcp_usrreqs;
#if INET6
extern	struct pr_usrreqs tcp6_usrreqs;
#endif /* INET6 */
extern	u_long tcp_sendspace;
extern	u_long tcp_recvspace;
void		tcp_rndiss_init __P((void));
tcp_seq		tcp_rndiss_next __P((void));
u_int16_t	tcp_rndiss_encrypt __P((u_int16_t));
 


#endif /* KERNEL */

#endif /* _NETINET_TCP_VAR_H_ */
