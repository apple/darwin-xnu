/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
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
 * $FreeBSD: src/sys/netinet/tcp_var.h,v 1.56.2.8 2001/08/22 00:59:13 silby Exp $
 */

#ifndef _NETINET_TCP_VAR_H_
#define _NETINET_TCP_VAR_H_
#include <sys/appleapiopts.h>
#include <sys/queue.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp_timer.h>

#if defined(__LP64__)
#define _TCPCB_PTR(x)			u_int32_t
#define _TCPCB_LIST_HEAD(name, type)	\
struct name {				\
	u_int32_t	lh_first;	\
};
#else
#define _TCPCB_PTR(x)			x
#define _TCPCB_LIST_HEAD(name, type)	LIST_HEAD(name, type)
#endif

#define TCP_RETRANSHZ	1000	/* granularity of TCP timestamps, 1ms */		
#define TCP_TIMERHZ	100		/* frequency of TCP fast timer, 100 ms */

/* Minimum time quantum within which the timers are coalesced */
#define TCP_FASTTIMER_QUANTUM   TCP_TIMERHZ	/* fast mode, once every 100ms */
#define TCP_SLOWTIMER_QUANTUM   (TCP_RETRANSHZ/2) /* slow mode, once every 500ms */

#define TCP_RETRANSHZ_TO_USEC 1000

#ifdef KERNEL_PRIVATE
#define N_TIME_WAIT_SLOTS   128     	/* must be power of 2 */

/* Base RTT is stored for N_MIN_RTT_HISTORY slots. This is used to
 * estimate expected minimum RTT for delay based congestion control
 * algorithms.
 */
#define N_RTT_BASE	5

/* Always allow at least 4 packets worth of recv window when adjusting
 * recv window using inter-packet arrival jitter.
 */
#define MIN_IAJ_WIN 4

/* A variation in delay of this many milliseconds is tolerable. This limit has to 
 * be low but greater than zero. We also use standard deviation on jitter to adjust
 * this limit for different link and connection types.
 */
#define ALLOWED_IAJ 5

/* Ignore the first few packets on a connection until the ACK clock gets going
 */
#define IAJ_IGNORE_PKTCNT 40

/* Let the accumulated IAJ value increase by this threshold at most. This limit
 * will control how many ALLOWED_IAJ measurements a receiver will have to see
 * before opening the receive window
 */
#define ACC_IAJ_HIGH_THRESH 100

/* When accumulated IAJ reaches this value, the receiver starts to react by 
 * closing the window
 */
#define ACC_IAJ_REACT_LIMIT 200

/* If the number of small packets (smaller than IAJ packet size) seen on a 
 * connection is more than this threshold, reset the size and learn it again.
 * This is needed because the sender might send smaller segments after PMTU
 * discovery and the receiver has to learn the new size.
 */
#define RESET_IAJ_SIZE_THRESH 20

/*
 * Adaptive timeout is a read/write timeout specified by the application to
 * get a socket event when the transport layer detects a stall in data 
 * transfer. The value specified is the number of probes that can be sent 
 * to the peer before generating an event. Since it is not specified as
 * a time value, the timeout will adjust based on the RTT seen on the link.
 * The timeout will start only when there is an indication that the read/write 
 * operation is not making progress. 
 *
 * If a write operation stalls, the probe will be retransmission of data.
 * If a read operation stalls, the probe will be a keep-alive packet.
 *
 * The maximum value of adaptive timeout is set to 10 which will allow
 * transmission of enough number of probes to the peer.
 */
#define TCP_ADAPTIVE_TIMEOUT_MAX 10

/*
 * Kernel variables for tcp.
 */

/* TCP segment queue entry */
struct tseg_qent {
	LIST_ENTRY(tseg_qent) tqe_q;
	int	tqe_len;		/* TCP segment data length */
	struct	tcphdr *tqe_th;		/* a pointer to tcp header */
	struct	mbuf	*tqe_m;		/* mbuf contains packet */
};
LIST_HEAD(tsegqe_head, tseg_qent);
extern int	tcp_reass_maxseg;
extern int	tcp_reass_qsize;
#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_TSEGQ);
#endif

struct sackblk {
	tcp_seq start;		/* start seq no. of sack block */
	tcp_seq end;		/* end seq no. */
};

struct sackhole {
	tcp_seq start;		/* start seq no. of hole */
	tcp_seq end;		/* end seq no. */
	tcp_seq rxmit;		/* next seq. no in hole to be retransmitted */
	TAILQ_ENTRY(sackhole) scblink;	/* scoreboard linkage */
};

struct sackhint {
	struct sackhole	*nexthole;
	int	sack_bytes_rexmit;
};

struct tcptemp {
	u_char	tt_ipgen[40]; /* the size must be of max ip header, now IPv6 */
	struct	tcphdr tt_t;
};

struct bwmeas {
	tcp_seq bw_start;		/* start of bw measurement */
	uint32_t bw_ts;		/* timestamp when bw measurement started */
	uint32_t bw_size;		/* burst size in bytes for this bw measurement */
	uint32_t bw_minsizepkts;	/* Min burst size as segments */
	uint32_t bw_maxsizepkts;	/* Max burst size as segments */
	uint32_t bw_minsize;	/* Min size in bytes */
	uint32_t bw_maxsize;	/* Max size in bytes */
	uint32_t bw_sndbw;		/* Measured send bw */
};

/* MPTCP Data sequence map entry */
struct mpt_dsn_map {
	uint64_t		mpt_dsn;	/* data seq num recvd */
	uint32_t		mpt_sseq;	/* relative subflow # */
	uint16_t		mpt_len;	/* length of mapping */
	uint16_t		mpt_csum;	/* checksum value if on */
};
#define tcp6cb		tcpcb  /* for KAME src sync over BSD*'s */

/*
 * Tcp control block, one per tcp; fields:
 * Organized for 16 byte cacheline efficiency.
 */
struct tcpcb {
	struct	tsegqe_head t_segq;
	int	t_dupacks;		/* consecutive dup acks recd */
	uint32_t t_timer[TCPT_NTIMERS];	/* tcp timers */
	struct tcptimerentry tentry;	/* entry in timer list */

	struct	inpcb *t_inpcb;		/* back pointer to internet pcb */
	int	t_state;		/* state of this connection */
	uint32_t	t_flags;
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
#define	TF_LOCAL	0x20000		/* connection to a host on local link */
#define	TF_RXWIN0SENT	0x40000		/* sent a receiver win 0 in response */
#define	TF_SLOWLINK	0x80000		/* route is a on a modem speed link */
#define	TF_LASTIDLE	0x100000	/* connection was previously idle */
#define	TF_FASTRECOVERY	0x200000	/* in NewReno Fast Recovery */
#define	TF_WASFRECOVERY	0x400000	/* was in NewReno Fast Recovery */
#define	TF_SIGNATURE	0x800000	/* require MD5 digests (RFC2385) */
#define	TF_MAXSEGSNT	0x1000000	/* last segment sent was a full segment */
#define TF_PMTUD	0x4000000	/* Perform Path MTU Discovery for this connection */
#define	TF_CLOSING	0x8000000	/* pending tcp close */
#define TF_TSO		0x10000000	/* TCP Segment Offloading is enable on this connection */
#define TF_BLACKHOLE	0x20000000	/* Path MTU Discovery Black Hole detection */
#define TF_TIMER_ONLIST 0x40000000	/* pcb is on tcp_timer_list */
#define TF_STRETCHACK	0x80000000	/* receiver is going to delay acks */

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
	u_int32_t	rcv_wnd;		/* receive window */
	tcp_seq	rcv_up;			/* receive urgent pointer */

	u_int32_t	snd_wnd;		/* send window */
	u_int32_t	snd_cwnd;		/* congestion-controlled window */
	u_int32_t	snd_ssthresh;		/* snd_cwnd size threshold for
					 * for slow start exponential to
					 * linear switch
					 */
	tcp_seq	snd_recover;		/* for use in NewReno Fast Recovery */

	u_int	t_maxopd;		/* mss plus options */

	u_int32_t	t_rcvtime;	/* time at which a packet was received */
	u_int32_t	t_starttime;	/* time connection was established */
	int	t_rtttime;		/* tcp clock when rtt calculation was started */
	tcp_seq	t_rtseq;		/* sequence number being timed */

	u_int32_t rfbuf_ts;		/* recv buffer autoscaling timestamp */
	u_int32_t rfbuf_cnt;		/* recv buffer autoscaling byte count */

	int	t_rxtcur;		/* current retransmit value (ticks) */
	u_int	t_maxseg;		/* maximum segment size */
	int	t_srtt;			/* smoothed round-trip time */
	int	t_rttvar;		/* variance in round-trip time */

	int	t_rxtshift;		/* log(2) of rexmt exp. backoff */
	u_int	t_rttmin;		/* minimum rtt allowed */
	u_int	t_rttbest;		/* best rtt we've seen */
	u_int	t_rttcur;		/* most recent value of rtt */
	u_int32_t	t_rttupdated;		/* number of times rtt sampled */
	u_int32_t	t_rxt_conndroptime;	/* retxmt conn gets dropped after this time, when set */
	u_int32_t	t_rxtstart;		/* time at which retransmission started */
	u_int32_t	max_sndwnd;		/* largest window peer has offered */

	int	t_softerror;		/* possible error not yet reported */
/* out-of-band data */
	char	t_oobflags;		/* have some */
	char	t_iobc;			/* input character */
#define	TCPOOB_HAVEDATA	0x01
#define	TCPOOB_HADDATA	0x02
/* RFC 1323 variables */
	u_int8_t snd_scale;		/* window scaling for send window */
	u_int8_t	rcv_scale;		/* window scaling for recv window */
	u_int8_t	request_r_scale;	/* pending window scaling */
	u_int8_t	requested_s_scale;
	u_int8_t	tcp_cc_index;	/* index of congestion control algorithm */
	u_int8_t	t_adaptive_rtimo;	/* Read timeout used as a multiple of RTT */
	u_int8_t	t_adaptive_wtimo;	/* Write timeout used as a multiple of RTT */
	u_int32_t	ts_recent;		/* timestamp echo data */

	u_int32_t	ts_recent_age;		/* when last updated */
	tcp_seq	last_ack_sent;
/* RFC 1644 variables */
	tcp_cc	cc_send;		/* send connection count */
	tcp_cc	cc_recv;		/* receive connection count */
/* RFC 3465 variables */
	u_int32_t	t_bytes_acked;		/* ABC "bytes_acked" parameter */

	int	t_lastchain;		/* amount of packets chained last time around */
	u_int16_t	t_unacksegs;	/* received but unacked segments for delaying acks */
	u_int8_t	t_rexmtthresh;	/* duplicate ack threshold for entering fast recovery */
	u_int8_t	t_rtimo_probes; /* number of adaptive rtimo probes sent */
	u_int32_t	t_persist_timeout;	/* ZWP persistence limit as set by PERSIST_TIMEOUT */
	u_int32_t	t_persist_stop;		/* persistence limit deadline if triggered by ZWP */
	u_int32_t	t_notsent_lowat;	/* Low water for not sent data */

/* Receiver state for stretch-ack algorithm */
	u_int32_t	rcv_unackwin;	/* to measure win for stretching acks */
	u_int32_t	rcv_by_unackwin; /* bytes seen during the last ack-stretching win */
	u_int16_t	rcv_waitforss;	/* wait for packets during slow-start */
	u_int16_t		ecn_flags;
#define TE_SETUPSENT		0x01	/* Indicate we have sent ECN-SETUP SYN or SYN-ACK */
#define TE_SETUPRECEIVED	0x02	/* Indicate we have received ECN-SETUP SYN or SYN-ACK */
#define TE_SENDIPECT		0x04	/* Indicate we haven't sent or received non-ECN-setup SYN or SYN-ACK */
#define TE_SENDCWR		0x08	/* Indicate that the next non-retransmit should have the TCP CWR flag set */
#define TE_SENDECE		0x10	/* Indicate that the next packet should have the TCP ECE flag set */
#define TE_ECN_ON		(TE_SETUPSENT | TE_SETUPRECEIVED) /* Indicate ECN was successfully negotiated on a connection) */

/* state for bad retransmit recovery */
	u_int32_t	snd_cwnd_prev;	/* cwnd prior to retransmit */
	u_int32_t	snd_ssthresh_prev;	/* ssthresh prior to retransmit */
	tcp_seq	snd_recover_prev;	/* snd_recover prior to retransmit */
	int	t_srtt_prev;		/* srtt prior to retransmit */
	int	t_rttvar_prev;		/* rttvar prior to retransmit */
	u_int32_t	t_badrexmt_time;	/* bad rexmt detection time */
	
/* state to limit the number of early retransmits */
	u_int32_t	t_early_rexmt_win; /* window for limiting early retransmits */
	u_int16_t	t_early_rexmt_count; /* number of early rexmts seen in past window */

/* SACK related state */
	int16_t	snd_numholes;		/* number of holes seen by sender */
	TAILQ_HEAD(sackhole_head, sackhole) snd_holes;
						/* SACK scoreboard (sorted) */
	tcp_seq	snd_fack;		/* last seq number(+1) sack'd by rcv'r*/
	int	rcv_numsacks;		/* # distinct sack blks present */
	struct sackblk sackblks[MAX_SACK_BLKS]; /* seq nos. of sack blocks */
	tcp_seq sack_newdata;		/* New data xmitted in this recovery
   					   episode starts at this seq number */
	struct sackhint	sackhint;	/* SACK scoreboard hint */
	
	u_int32_t	t_pktlist_sentlen; /* total bytes in transmit chain */
	struct mbuf	*t_pktlist_head; /* First packet in transmit chain */
	struct mbuf	*t_pktlist_tail; /* Last packet in transmit chain */

	u_int32_t	t_keepidle;	/* keepalive idle timer (override global if > 0) */
	u_int32_t	t_keepinit;	/* connection timeout, i.e. idle time 
					in SYN_SENT or SYN_RECV state */
	u_int32_t	t_keepintvl;	/* interval between keepalives */
	u_int32_t	t_keepcnt;	/* number of keepalives before close */

	u_int32_t	tso_max_segment_size;	/* TCP Segment Offloading maximum segment unit for NIC */
	u_int 		t_pmtud_saved_maxopd;	/* MSS saved before performing PMTU-D BlackHole detection */
	
	struct
	{
		u_int32_t	rxduplicatebytes;
		u_int32_t	rxoutoforderbytes;
		u_int32_t	txretransmitbytes;
		u_int8_t	synrxtshift;
		u_int8_t	unused;
		u_int16_t	unused_pad_to_8;
	} t_stat;
	
	/* Background congestion related state */
	uint32_t	rtt_hist[N_RTT_BASE];	/* history of minimum RTT */
	uint32_t	rtt_count;		/* Number of RTT samples in recent base history */
	uint32_t	bg_ssthresh;		/* Slow start threshold until delay increases */
	uint32_t	t_flagsext;		/* Another field to accommodate more flags */
#define TF_RXTFINDROP	0x1			/* Drop conn after retransmitting FIN 3 times */
#define TF_RCVUNACK_WAITSS	0x2		/* set when the receiver should not stretch acks */
#define TF_BWMEAS_INPROGRESS	0x4		/* Indicate BW meas is happening */
#define TF_MEASURESNDBW		0x8		/* Measure send bw on this connection */
#define TF_LRO_OFFLOADED	0x10		/* Connection LRO offloaded */
#define TF_SACK_ENABLE		0x20		/* SACK is enabled */
#define TF_RECOMPUTE_RTT	0x40		/* recompute RTT after spurious retransmit */
#define TF_DETECT_READSTALL	0x80		/* Used to detect a stall during read operation */
#define TF_RECV_THROTTLE	0x100		/* Input throttling active */
#define	TF_NOSTRETCHACK		0x200		/* ack every other packet */
#define	TF_STREAMEOW		0x400		/* Last packet was small indicating end of write */
#if TRAFFIC_MGT
	/* Inter-arrival jitter related state */
	uint32_t 	iaj_rcv_ts;		/* tcp clock when the first packet was received */
	uint16_t	iaj_size;		/* Size of packet for iaj measurement */
	uint16_t	iaj_small_pkt;		/* Count of packets smaller than iaj_size */
	uint16_t	iaj_pktcnt;		/* packet count, to avoid throttling initially */
	uint16_t	acc_iaj;		/* Accumulated iaj */
	tcp_seq 	iaj_rwintop;		/* recent max advertised window */
	uint32_t	avg_iaj;		/* Mean */
	uint32_t	std_dev_iaj;		/* Standard deviation */
#endif /* TRAFFIC_MGT */
	struct bwmeas	*t_bwmeas;		/* State for bandwidth measurement */ 
	uint32_t	t_lropktlen;		/* Bytes in a LRO frame */
	tcp_seq		t_idleat;		/* rcv_nxt at idle time */
	TAILQ_ENTRY(tcpcb) t_twentry;		/* link for time wait queue */
#if MPTCP
	u_int32_t	t_mpflags;		/* flags for multipath TCP */

#define TMPF_PREESTABLISHED 	0x00000001 /* conn in pre-established state */
#define TMPF_SENT_KEYS		0x00000002 /* indicates that keys were sent */
#define TMPF_MPTCP_TRUE		0x00000004 /* negotiated MPTCP successfully */
#define TMPF_MPTCP_RCVD_KEY	0x00000008 /* state for 3-way handshake */	
#define TMPF_SND_MPPRIO		0x00000010 /* send priority of subflow */
#define TMPF_SND_REM_ADDR	0x00000020 /* initiate address removal */
#define TMPF_UNUSED		0x00000040 /* address addition acked by peer */
#define TMPF_JOINED_FLOW	0x00000080 /* Indicates additional flow */
#define TMPF_BACKUP_PATH	0x00000100 /* Indicates backup path */
#define TMPF_MPTCP_ACKNOW	0x00000200 /* Send Data ACK */
#define TMPF_SEND_DSN		0x00000400 /* Send DSN mapping */
#define TMPF_SEND_DFIN		0x00000800 /* Send Data FIN */
#define TMPF_RECV_DFIN		0x00001000 /* Recv Data FIN */
#define TMPF_SENT_JOIN		0x00002000 /* Sent Join */
#define TMPF_RECVD_JOIN		0x00004000 /* Received Join */
#define TMPF_RESET		0x00008000 /* Send RST */
#define TMPF_TCP_FALLBACK	0x00010000 /* Fallback to TCP */
#define TMPF_FASTCLOSE		0x00020000 /* Send Fastclose option */
#define TMPF_EMBED_DSN		0x00040000 /* tp has DSN mapping */
#define TMPF_MPTCP_READY	0x00080000 /* Can send DSS options on data */
#define TMPF_INFIN_SENT		0x00100000 /* Sent infinite mapping */
#define TMPF_SND_MPFAIL		0x00200000 /* Received mapping csum failure */
	void			*t_mptcb;	/* pointer to MPTCP TCB */
	tcp_seq			t_mpuna;	/* unacknowledged sequence */
	struct mpt_dsn_map	t_rcv_map;	/* Receive mapping list */
	u_int8_t		t_local_aid;	/* Addr Id for authentication */
	u_int8_t		t_rem_aid;	/* Addr ID of another subflow */
	u_int8_t		t_mprxtshift;	/* join retransmission */
#endif /* MPTCP */
};

#define IN_FASTRECOVERY(tp)	(tp->t_flags & TF_FASTRECOVERY)
#define SACK_ENABLED(tp)	(tp->t_flagsext & TF_SACK_ENABLE)

/*
 * If the connection is in a throttled state due to advisory feedback from 
 * the interface output queue, reset that state. We do this in favor
 * of entering recovery because the data transfer during recovery 
 * should be just a trickle and it will help to improve performance.
 * We also do not want to back off twice in the same RTT.
 */
#define ENTER_FASTRECOVERY(_tp_) do {				\
	(_tp_)->t_flags |= TF_FASTRECOVERY;			\
	if (INP_IS_FLOW_CONTROLLED((_tp_)->t_inpcb))		\
		inp_reset_fc_state((_tp_)->t_inpcb);		\
} while(0)

#define EXIT_FASTRECOVERY(_tp_) do {		\
	(_tp_)->t_flags &= ~TF_FASTRECOVERY;	\
	(_tp_)->t_dupacks = 0;			\
	(_tp_)->t_rexmtthresh = tcprexmtthresh;	\
	(_tp_)->t_bytes_acked = 0;		\
} while(0)

/*
 * When the number of duplicate acks received is less than 
 * the retransmit threshold, use Limited Transmit algorithm
 */
extern int tcprexmtthresh;
#define ALLOW_LIMITED_TRANSMIT(_tp_) \
	((_tp_)->t_dupacks > 0 && \
	(_tp_)->t_dupacks < (_tp_)->t_rexmtthresh)

/*
 * This condition is true is timestamp option is supported
 * on a connection.
 */
#define TSTMP_SUPPORTED(_tp_) \
	(((_tp_)->t_flags & (TF_REQ_TSTMP|TF_RCVD_TSTMP)) == \
		(TF_REQ_TSTMP|TF_RCVD_TSTMP))

/*
 * Gives number of bytes acked by this ack
 */
#define BYTES_ACKED(_th_, _tp_) \
	((_th_)->th_ack - (_tp_)->snd_una)

#if CONFIG_DTRACE
enum tcp_cc_event {
	TCP_CC_CWND_INIT,
	TCP_CC_INSEQ_ACK_RCVD,
	TCP_CC_ACK_RCVD,
	TCP_CC_ENTER_FASTRECOVERY,
	TCP_CC_IN_FASTRECOVERY,
	TCP_CC_EXIT_FASTRECOVERY,
	TCP_CC_PARTIAL_ACK,
	TCP_CC_IDLE_TIMEOUT,
	TCP_CC_REXMT_TIMEOUT,
	TCP_CC_ECN_RCVD,
	TCP_CC_BAD_REXMT_RECOVERY,
	TCP_CC_OUTPUT_ERROR,
	TCP_CC_CHANGE_ALGO,
	TCP_CC_FLOW_CONTROL,
	TCP_CC_SUSPEND,
	TCP_CC_LIMITED_TRANSMIT,
	TCP_CC_EARLY_RETRANSMIT
};
#endif /* CONFIG_DTRACE */

/*
 * Structure to hold TCP options that are only used during segment
 * processing (in tcp_input), but not held in the tcpcb.
 * It's basically used to reduce the number of parameters
 * to tcp_dooptions.
 */
struct tcpopt {
	u_int32_t	to_flags;		/* which options are present */
#define TOF_TS		0x0001		/* timestamp */
#define	TOF_MSS		0x0010
#define	TOF_SCALE	0x0020
#define	TOF_SIGNATURE	0x0040	/* signature option present */
#define	TOF_SIGLEN	0x0080	/* signature length valid (RFC2385) */
#define	TOF_SACK	0x0100		/* Peer sent SACK option */
#define	TOF_MPTCP	0x0200	/* MPTCP options to be dropped */
	u_int32_t		to_tsval;
	u_int32_t		to_tsecr;
	u_int16_t	to_mss;
	u_int8_t	to_requested_s_scale;
	u_int8_t	to_nsacks;	/* number of SACK blocks */
	u_char		*to_sacks;	/* pointer to the first SACK blocks */
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
 * The rtt measured is in milliseconds as the timestamp granularity is 
 * a millisecond. The smoothed round-trip time and estimated variance
 * are stored as fixed point numbers scaled by the values below.
 * For convenience, these scales are also used in smoothing the average
 * (smoothed = (1/scale)sample + ((scale-1)/scale)smoothed).
 * With these scales, srtt has 5 bits to the right of the binary point,
 * and thus an "ALPHA" of 0.875.  rttvar has 4 bits to the right of the
 * binary point, and is smoothed with an ALPHA of 0.75.
 */
#define	TCP_RTT_SCALE		32	/* multiplier for srtt; 3 bits frac. */
#define	TCP_RTT_SHIFT		5	/* shift for srtt; 5 bits frac. */
#define	TCP_RTTVAR_SCALE	16	/* multiplier for rttvar; 4 bits */
#define	TCP_RTTVAR_SHIFT	4	/* shift for rttvar; 4 bits */
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
 * Jaguar compatible TCP control block, for xtcpcb
 * Does not have the old fields
 */
struct otcpcb {
#else
struct tseg_qent;
_TCPCB_LIST_HEAD(tsegqe_head, tseg_qent);

struct tcpcb {
#endif /* KERNEL_PRIVATE */
#if defined(KERNEL_PRIVATE)
	u_int32_t t_segq;
#else
	struct	tsegqe_head t_segq;
#endif /* KERNEL_PRIVATE */
	int	t_dupacks;		/* consecutive dup acks recd */
	u_int32_t unused;		/* unused now: was t_template */

	int	t_timer[TCPT_NTIMERS_EXT];	/* tcp timers */

	_TCPCB_PTR(struct inpcb *) t_inpcb;	/* back pointer to internet pcb */
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
#define	TF_LQ_OVERFLOW	0x20000		/* listen queue overflow */
#define	TF_RXWIN0SENT	0x40000		/* sent a receiver win 0 in response */
#define	TF_SLOWLINK	0x80000		/* route is a on a modem speed link */

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
	u_int32_t rcv_wnd;		/* receive window */
	tcp_seq	rcv_up;			/* receive urgent pointer */

	u_int32_t snd_wnd;		/* send window */
	u_int32_t snd_cwnd;		/* congestion-controlled window */
	u_int32_t snd_ssthresh;		/* snd_cwnd size threshold for
					 * for slow start exponential to
					 * linear switch
					 */
	u_int	t_maxopd;		/* mss plus options */

	u_int32_t t_rcvtime;		/* time at which a packet was received */
	u_int32_t t_starttime;		/* time connection was established */
	int	t_rtttime;		/* round trip time */
	tcp_seq	t_rtseq;		/* sequence number being timed */

	int	t_rxtcur;		/* current retransmit value (ticks) */
	u_int	t_maxseg;		/* maximum segment size */
	int	t_srtt;			/* smoothed round-trip time */
	int	t_rttvar;		/* variance in round-trip time */

	int	t_rxtshift;		/* log(2) of rexmt exp. backoff */
	u_int	t_rttmin;		/* minimum rtt allowed */
	u_int32_t t_rttupdated;		/* number of times rtt sampled */
	u_int32_t max_sndwnd;		/* largest window peer has offered */

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
	u_int32_t ts_recent;		/* timestamp echo data */

	u_int32_t ts_recent_age;	/* when last updated */
	tcp_seq	last_ack_sent;
/* RFC 1644 variables */
	tcp_cc	cc_send;		/* send connection count */
	tcp_cc	cc_recv;		/* receive connection count */
	tcp_seq	snd_recover;		/* for use in fast recovery */
/* experimental */
	u_int32_t snd_cwnd_prev;	/* cwnd prior to retransmit */
	u_int32_t snd_ssthresh_prev;	/* ssthresh prior to retransmit */
	u_int32_t t_badrxtwin;		/* window for retransmit recovery */
};


/*
 * TCP statistics.
 * Many of these should be kept per connection,
 * but that's inconvenient at the moment.
 */
struct	tcpstat {
	u_int32_t	tcps_connattempt;	/* connections initiated */
	u_int32_t	tcps_accepts;		/* connections accepted */
	u_int32_t	tcps_connects;		/* connections established */
	u_int32_t	tcps_drops;		/* connections dropped */
	u_int32_t	tcps_conndrops;		/* embryonic connections dropped */
	u_int32_t	tcps_closed;		/* conn. closed (includes drops) */
	u_int32_t	tcps_segstimed;		/* segs where we tried to get rtt */
	u_int32_t	tcps_rttupdated;	/* times we succeeded */
	u_int32_t	tcps_delack;		/* delayed acks sent */
	u_int32_t	tcps_timeoutdrop;	/* conn. dropped in rxmt timeout */
	u_int32_t	tcps_rexmttimeo;	/* retransmit timeouts */
	u_int32_t	tcps_persisttimeo;	/* persist timeouts */
	u_int32_t	tcps_keeptimeo;		/* keepalive timeouts */
	u_int32_t	tcps_keepprobe;		/* keepalive probes sent */
	u_int32_t	tcps_keepdrops;		/* connections dropped in keepalive */

	u_int32_t	tcps_sndtotal;		/* total packets sent */
	u_int32_t	tcps_sndpack;		/* data packets sent */
	u_int32_t	tcps_sndbyte;		/* data bytes sent */
	u_int32_t	tcps_sndrexmitpack;	/* data packets retransmitted */
	u_int32_t	tcps_sndrexmitbyte;	/* data bytes retransmitted */
	u_int32_t	tcps_sndacks;		/* ack-only packets sent */
	u_int32_t	tcps_sndprobe;		/* window probes sent */
	u_int32_t	tcps_sndurg;		/* packets sent with URG only */
	u_int32_t	tcps_sndwinup;		/* window update-only packets sent */
	u_int32_t	tcps_sndctrl;		/* control (SYN|FIN|RST) packets sent */

	u_int32_t	tcps_rcvtotal;		/* total packets received */
	u_int32_t	tcps_rcvpack;		/* packets received in sequence */
	u_int32_t	tcps_rcvbyte;		/* bytes received in sequence */
	u_int32_t	tcps_rcvbadsum;		/* packets received with ccksum errs */
	u_int32_t	tcps_rcvbadoff;		/* packets received with bad offset */
	u_int32_t	tcps_rcvmemdrop;	/* packets dropped for lack of memory */
	u_int32_t	tcps_rcvshort;		/* packets received too short */
	u_int32_t	tcps_rcvduppack;	/* duplicate-only packets received */
	u_int32_t	tcps_rcvdupbyte;	/* duplicate-only bytes received */
	u_int32_t	tcps_rcvpartduppack;	/* packets with some duplicate data */
	u_int32_t	tcps_rcvpartdupbyte;	/* dup. bytes in part-dup. packets */
	u_int32_t	tcps_rcvoopack;		/* out-of-order packets received */
	u_int32_t	tcps_rcvoobyte;		/* out-of-order bytes received */
	u_int32_t	tcps_rcvpackafterwin;	/* packets with data after window */
	u_int32_t	tcps_rcvbyteafterwin;	/* bytes rcvd after window */
	u_int32_t	tcps_rcvafterclose;	/* packets rcvd after "close" */
	u_int32_t	tcps_rcvwinprobe;	/* rcvd window probe packets */
	u_int32_t	tcps_rcvdupack;		/* rcvd duplicate acks */
	u_int32_t	tcps_rcvacktoomuch;	/* rcvd acks for unsent data */
	u_int32_t	tcps_rcvackpack;	/* rcvd ack packets */
	u_int32_t	tcps_rcvackbyte;	/* bytes acked by rcvd acks */
	u_int32_t	tcps_rcvwinupd;		/* rcvd window update packets */
	u_int32_t	tcps_pawsdrop;		/* segments dropped due to PAWS */
	u_int32_t	tcps_predack;		/* times hdr predict ok for acks */
	u_int32_t	tcps_preddat;		/* times hdr predict ok for data pkts */
	u_int32_t	tcps_pcbcachemiss;
	u_int32_t	tcps_cachedrtt;		/* times cached RTT in route updated */
	u_int32_t	tcps_cachedrttvar;	/* times cached rttvar updated */
	u_int32_t	tcps_cachedssthresh;	/* times cached ssthresh updated */
	u_int32_t	tcps_usedrtt;		/* times RTT initialized from route */
	u_int32_t	tcps_usedrttvar;	/* times RTTVAR initialized from rt */
	u_int32_t	tcps_usedssthresh;	/* times ssthresh initialized from rt*/
	u_int32_t	tcps_persistdrop;	/* timeout in persist state */
	u_int32_t	tcps_badsyn;		/* bogus SYN, e.g. premature ACK */
	u_int32_t	tcps_mturesent;		/* resends due to MTU discovery */
	u_int32_t	tcps_listendrop;	/* listen queue overflows */

	/* new stats from FreeBSD 5.4 sync up */
	u_int32_t	tcps_minmssdrops;	/* average minmss too low drops */
	u_int32_t	tcps_sndrexmitbad;	/* unnecessary packet retransmissions */
	u_int32_t	tcps_badrst;		/* ignored RSTs in the window */

	u_int32_t	tcps_sc_added;		/* entry added to syncache */
	u_int32_t	tcps_sc_retransmitted;	/* syncache entry was retransmitted */
	u_int32_t	tcps_sc_dupsyn;		/* duplicate SYN packet */
	u_int32_t	tcps_sc_dropped;	/* could not reply to packet */
	u_int32_t	tcps_sc_completed;	/* successful extraction of entry */
	u_int32_t	tcps_sc_bucketoverflow;	/* syncache per-bucket limit hit */
	u_int32_t	tcps_sc_cacheoverflow;	/* syncache cache limit hit */
	u_int32_t	tcps_sc_reset;		/* RST removed entry from syncache */
	u_int32_t	tcps_sc_stale;		/* timed out or listen socket gone */
	u_int32_t	tcps_sc_aborted;	/* syncache entry aborted */
	u_int32_t	tcps_sc_badack;		/* removed due to bad ACK */
	u_int32_t	tcps_sc_unreach;	/* ICMP unreachable received */
	u_int32_t	tcps_sc_zonefail;	/* zalloc() failed */
	u_int32_t	tcps_sc_sendcookie;	/* SYN cookie sent */
	u_int32_t	tcps_sc_recvcookie;	/* SYN cookie received */

	u_int32_t	tcps_hc_added;		/* entry added to hostcache */
	u_int32_t	tcps_hc_bucketoverflow;	/* hostcache per bucket limit hit */

	/* SACK related stats */
	u_int32_t	tcps_sack_recovery_episode; /* SACK recovery episodes */
	u_int32_t 	tcps_sack_rexmits;	    /* SACK rexmit segments   */
	u_int32_t 	tcps_sack_rexmit_bytes;	    /* SACK rexmit bytes      */
	u_int32_t 	tcps_sack_rcv_blocks;	    /* SACK blocks (options) received */
	u_int32_t 	tcps_sack_send_blocks;	    /* SACK blocks (options) sent     */
	u_int32_t 	tcps_sack_sboverflow;	    /* SACK sendblock overflow   */

	u_int32_t	tcps_bg_rcvtotal;	/* total background packets received */
	u_int32_t	tcps_rxtfindrop;	/* drop conn after retransmitting FIN */
	u_int32_t	tcps_fcholdpacket;	/* packets withheld because of flow control */

	/* LRO related stats */
	u_int32_t	tcps_coalesced_pack;	/* number of coalesced packets */
	u_int32_t	tcps_flowtbl_full;	/* times flow table was full */
	u_int32_t	tcps_flowtbl_collision;	/* collisions in flow tbl */
	u_int32_t	tcps_lro_twopack;	/* 2 packets coalesced */
	u_int32_t	tcps_lro_multpack;	/* 3 or 4 pkts coalesced */
	u_int32_t	tcps_lro_largepack;	/* 5 or more pkts coalesced */

	u_int32_t	tcps_limited_txt;	/* Limited transmit used */
	u_int32_t	tcps_early_rexmt;	/* Early retransmit used */
	u_int32_t	tcps_sack_ackadv;	/* Cumulative ack advanced along with sack */

	/* Checksum related stats */
	u_int32_t	tcps_rcv_swcsum;	/* tcp swcksum (inbound), packets */
	u_int32_t	tcps_rcv_swcsum_bytes;	/* tcp swcksum (inbound), bytes */
	u_int32_t	tcps_rcv6_swcsum;	/* tcp6 swcksum (inbound), packets */
	u_int32_t	tcps_rcv6_swcsum_bytes;	/* tcp6 swcksum (inbound), bytes */
	u_int32_t	tcps_snd_swcsum;	/* tcp swcksum (outbound), packets */
	u_int32_t	tcps_snd_swcsum_bytes;	/* tcp swcksum (outbound), bytes */
	u_int32_t	tcps_snd6_swcsum;	/* tcp6 swcksum (outbound), packets */
	u_int32_t	tcps_snd6_swcsum_bytes;	/* tcp6 swcksum (outbound), bytes */
	u_int32_t	tcps_msg_unopkts;	/* unordered packet on TCP msg stream */
	u_int32_t	tcps_msg_unoappendfail; /* failed to append unordered pkt */
	u_int32_t	tcps_msg_sndwaithipri; /* send is waiting for high priority data */

	/* MPTCP Related stats */
	u_int32_t	tcps_invalid_mpcap;	/* Invalid MPTCP capable opts */
	u_int32_t	tcps_invalid_joins;	/* Invalid MPTCP joins */
	u_int32_t	tcps_mpcap_fallback;	/* TCP fallback in primary */
	u_int32_t	tcps_join_fallback;	/* No MPTCP in secondary */
	u_int32_t	tcps_estab_fallback;	/* DSS option dropped */
	u_int32_t	tcps_invalid_opt;	/* Catchall error stat */
	u_int32_t	tcps_mp_outofwin;	/* Packet lies outside the
						   shared recv window */
	u_int32_t	tcps_mp_reducedwin;	/* Reduced subflow window */
	u_int32_t	tcps_mp_badcsum;	/* Bad DSS csum */
	u_int32_t	tcps_mp_oodata;		/* Out of order data */
	u_int32_t	tcps_mp_switches;	/* number of subflow switch */
	u_int32_t	tcps_mp_rcvtotal;	/* number of rcvd packets */
	u_int32_t	tcps_mp_rcvbytes;	/* number of bytes received */
	u_int32_t	tcps_mp_sndpacks;	/* number of data packs sent */
	u_int32_t	tcps_mp_sndbytes;	/* number of bytes sent */
	u_int32_t	tcps_join_rxmts;	/* join ack retransmits */
};

struct tcpstat_local {
	u_int64_t badformat;
	u_int64_t unspecv6;
	u_int64_t synfin;
	u_int64_t badformatipsec;
	u_int64_t noconnnolist;
	u_int64_t noconnlist;
	u_int64_t listbadsyn;
	u_int64_t icmp6unreach;
	u_int64_t deprecate6;
	u_int64_t ooopacket;
	u_int64_t rstinsynrcv;
	u_int64_t dospacket;
	u_int64_t cleanup;
	u_int64_t synwindow;
};

#pragma pack(4)

/*
 * TCB structure exported to user-land via sysctl(3).
 * Evil hack: declare only if in_pcb.h and sys/socketvar.h have been
 * included.  Not all of our clients do.
 */

struct  xtcpcb {
        u_int32_t       xt_len;
#ifdef KERNEL_PRIVATE
        struct  inpcb_compat    xt_inp;
#else
        struct  inpcb   xt_inp;
#endif
#ifdef KERNEL_PRIVATE
        struct  otcpcb  xt_tp;
#else
        struct  tcpcb   xt_tp;
#endif
        struct  xsocket xt_socket;
        u_quad_t        xt_alignment_hack;
};


struct  xtcpcb64 {
        u_int32_t      		xt_len;
        struct xinpcb64		xt_inpcb;

        u_int64_t t_segq;
        int     t_dupacks;              /* consecutive dup acks recd */

        int t_timer[TCPT_NTIMERS_EXT];  /* tcp timers */

        int     t_state;                /* state of this connection */
        u_int   t_flags;

        int     t_force;                /* 1 if forcing out a byte */

        tcp_seq snd_una;                /* send unacknowledged */
        tcp_seq snd_max;                /* highest sequence number sent;
                                         * used to recognize retransmits
                                         */
        tcp_seq snd_nxt;                /* send next */
        tcp_seq snd_up;                 /* send urgent pointer */

        tcp_seq snd_wl1;                /* window update seg seq number */
        tcp_seq snd_wl2;                /* window update seg ack number */
        tcp_seq iss;                    /* initial send sequence number */
        tcp_seq irs;                    /* initial receive sequence number */

        tcp_seq rcv_nxt;                /* receive next */
        tcp_seq rcv_adv;                /* advertised window */
        u_int32_t rcv_wnd;              /* receive window */
        tcp_seq rcv_up;                 /* receive urgent pointer */

        u_int32_t snd_wnd;              /* send window */
        u_int32_t snd_cwnd;             /* congestion-controlled window */
        u_int32_t snd_ssthresh;         /* snd_cwnd size threshold for
                                         * for slow start exponential to
                                         * linear switch
                                         */
        u_int   t_maxopd;               /* mss plus options */

        u_int32_t t_rcvtime;            /* time at which a packet was received */
        u_int32_t t_starttime;          /* time connection was established */
        int     t_rtttime;              /* round trip time */
        tcp_seq t_rtseq;                /* sequence number being timed */

        int     t_rxtcur;               /* current retransmit value (ticks) */
        u_int   t_maxseg;               /* maximum segment size */
        int     t_srtt;                 /* smoothed round-trip time */
        int     t_rttvar;               /* variance in round-trip time */

        int     t_rxtshift;             /* log(2) of rexmt exp. backoff */
        u_int   t_rttmin;               /* minimum rtt allowed */
        u_int32_t t_rttupdated;         /* number of times rtt sampled */
        u_int32_t max_sndwnd;           /* largest window peer has offered */

        int     t_softerror;            /* possible error not yet reported */
/* out-of-band data */
        char    t_oobflags;             /* have some */
        char    t_iobc;                 /* input character */
/* RFC 1323 variables */
        u_char  snd_scale;              /* window scaling for send window */
        u_char  rcv_scale;              /* window scaling for recv window */
        u_char  request_r_scale;        /* pending window scaling */
        u_char  requested_s_scale;
        u_int32_t ts_recent;            /* timestamp echo data */

        u_int32_t ts_recent_age;        /* when last updated */
        tcp_seq last_ack_sent;
/* RFC 1644 variables */
        tcp_cc  cc_send;                /* send connection count */
        tcp_cc  cc_recv;                /* receive connection count */
        tcp_seq snd_recover;            /* for use in fast recovery */
/* experimental */
        u_int32_t snd_cwnd_prev;        /* cwnd prior to retransmit */
        u_int32_t snd_ssthresh_prev;    /* ssthresh prior to retransmit */
        u_int32_t t_badrxtwin;          /* window for retransmit recovery */

        u_quad_t		xt_alignment_hack;
};


#ifdef PRIVATE

struct  xtcpcb_n {
	u_int32_t      		xt_len;
	u_int32_t			xt_kind;		/* XSO_TCPCB */

	u_int64_t t_segq;
	int     t_dupacks;              /* consecutive dup acks recd */
	
	int t_timer[TCPT_NTIMERS_EXT];  /* tcp timers */
	
	int     t_state;                /* state of this connection */
	u_int   t_flags;
	
	int     t_force;                /* 1 if forcing out a byte */
	
	tcp_seq snd_una;                /* send unacknowledged */
	tcp_seq snd_max;                /* highest sequence number sent;
									 * used to recognize retransmits
									 */
	tcp_seq snd_nxt;                /* send next */
	tcp_seq snd_up;                 /* send urgent pointer */
	
	tcp_seq snd_wl1;                /* window update seg seq number */
	tcp_seq snd_wl2;                /* window update seg ack number */
	tcp_seq iss;                    /* initial send sequence number */
	tcp_seq irs;                    /* initial receive sequence number */
	
	tcp_seq rcv_nxt;                /* receive next */
	tcp_seq rcv_adv;                /* advertised window */
	u_int32_t rcv_wnd;              /* receive window */
	tcp_seq rcv_up;                 /* receive urgent pointer */
	
	u_int32_t snd_wnd;              /* send window */
	u_int32_t snd_cwnd;             /* congestion-controlled window */
	u_int32_t snd_ssthresh;         /* snd_cwnd size threshold for
									 * for slow start exponential to
									 * linear switch
									 */
	u_int   t_maxopd;               /* mss plus options */
	
	u_int32_t t_rcvtime;            /* time at which a packet was received */
	u_int32_t t_starttime;          /* time connection was established */
	int     t_rtttime;              /* round trip time */
	tcp_seq t_rtseq;                /* sequence number being timed */
	
	int     t_rxtcur;               /* current retransmit value (ticks) */
	u_int   t_maxseg;               /* maximum segment size */
	int     t_srtt;                 /* smoothed round-trip time */
	int     t_rttvar;               /* variance in round-trip time */
	
	int     t_rxtshift;             /* log(2) of rexmt exp. backoff */
	u_int   t_rttmin;               /* minimum rtt allowed */
	u_int32_t t_rttupdated;         /* number of times rtt sampled */
	u_int32_t max_sndwnd;           /* largest window peer has offered */
	
	int     t_softerror;            /* possible error not yet reported */
	/* out-of-band data */
	char    t_oobflags;             /* have some */
	char    t_iobc;                 /* input character */
	/* RFC 1323 variables */
	u_char  snd_scale;              /* window scaling for send window */
	u_char  rcv_scale;              /* window scaling for recv window */
	u_char  request_r_scale;        /* pending window scaling */
	u_char  requested_s_scale;
	u_int32_t ts_recent;            /* timestamp echo data */
	
	u_int32_t ts_recent_age;        /* when last updated */
	tcp_seq last_ack_sent;
	/* RFC 1644 variables */
	tcp_cc  cc_send;                /* send connection count */
	tcp_cc  cc_recv;                /* receive connection count */
	tcp_seq snd_recover;            /* for use in fast recovery */
	/* experimental */
	u_int32_t snd_cwnd_prev;        /* cwnd prior to retransmit */
	u_int32_t snd_ssthresh_prev;    /* ssthresh prior to retransmit */
};

#endif /* PRIVATE */

#pragma pack()

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
#define	TCPCTL_KEEPINIT		10	/* timeout for establishing syn */
#define	TCPCTL_PCBLIST		11	/* list of all outstanding PCBs */
#define	TCPCTL_DELACKTIME	12	/* time before sending delayed ACK */
#define	TCPCTL_V6MSSDFLT	13	/* MSS default for IPv6 */
#define	TCPCTL_MAXID		14

#ifdef BSD_KERNEL_PRIVATE
#include <sys/bitstring.h>

#define	TCP_PKTLIST_CLEAR(tp) {						\
	(tp)->t_pktlist_head = (tp)->t_pktlist_tail = NULL;		\
	(tp)->t_lastchain = (tp)->t_pktlist_sentlen = 0;		\
}

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
	{ "delacktime", CTLTYPE_INT }, \
	{ "v6mssdflt", CTLTYPE_INT }, \
}

#ifdef SYSCTL_DECL
SYSCTL_DECL(_net_inet_tcp);
#endif /* SYSCTL_DECL */

/*
 * Flags for TCP's connectx(2) user-protocol request routine.
 */
#if MPTCP
#define	TCP_CONNREQF_MPTCP	0x1	/* called internally by MPTCP */
#endif /* MPTCP */

extern	struct inpcbhead tcb;		/* head of queue of active tcpcb's */
extern	struct inpcbinfo tcbinfo;
extern	struct tcpstat tcpstat;	/* tcp statistics */
extern	int tcp_mssdflt;	/* XXX */
extern	int tcp_minmss;
extern	int ss_fltsz;
extern	int ss_fltsz_local;
extern 	int tcp_do_rfc3390;		/* Calculate ss_fltsz according to RFC 3390 */
extern int target_qdelay;
#ifdef __APPLE__
extern	u_int32_t tcp_now;		/* for RFC 1323 timestamps */ 
extern struct timeval tcp_uptime;
extern lck_spin_t *tcp_uptime_lock;

extern	int tcp_delack_enabled;
#endif /* __APPLE__ */

extern	int tcp_do_sack;	/* SACK enabled/disabled */

#if CONFIG_IFEF_NOWINDOWSCALE
extern int tcp_obey_ifef_nowindowscale;
#endif

struct protosw;
struct domain;

void	 tcp_canceltimers(struct tcpcb *);
struct tcpcb *
	 tcp_close(struct tcpcb *);
void	 tcp_ctlinput(int, struct sockaddr *, void *);
int	 tcp_ctloutput(struct socket *, struct sockopt *);
struct tcpcb *
	 tcp_drop(struct tcpcb *, int);
void	 tcp_drain(void);
void	 tcp_getrt_rtt(struct tcpcb *tp, struct rtentry *rt);
struct rmxp_tao *
	 tcp_gettaocache(struct inpcb *);
void	 tcp_init(struct protosw *, struct domain *);
void	 tcp_input(struct mbuf *, int);
void	 tcp_mss(struct tcpcb *, int, unsigned int);
int	 tcp_mssopt(struct tcpcb *);
void	 tcp_drop_syn_sent(struct inpcb *, int);
void	 tcp_mtudisc(struct inpcb *, int);
struct tcpcb *
	 tcp_newtcpcb(struct inpcb *);
int	 tcp_output(struct tcpcb *);
void	 tcp_respond(struct tcpcb *, void *,
	    struct tcphdr *, struct mbuf *, tcp_seq, tcp_seq, int,
	    unsigned int, unsigned int);
struct rtentry *tcp_rtlookup(struct inpcb *, unsigned int);
void	 tcp_setpersist(struct tcpcb *);
void	tcp_gc(struct inpcbinfo *);
void 	 tcp_check_timer_state(struct tcpcb *tp);
void	 tcp_run_timerlist(void *arg1, void *arg2);

struct tcptemp *
	 tcp_maketemplate(struct tcpcb *);
void	 tcp_fillheaders(struct tcpcb *, void *, void *);
struct tcpcb *
	 tcp_timers(struct tcpcb *, int);
void	 tcp_trace(int, int, struct tcpcb *, void *, struct tcphdr *, int);

void tcp_sack_doack(struct tcpcb *, struct tcpopt *, tcp_seq, u_int32_t *);
void	 tcp_update_sack_list(struct tcpcb *tp, tcp_seq rcv_laststart, tcp_seq rcv_lastend);
void	 tcp_clean_sackreport(struct tcpcb *tp);
void	 tcp_sack_adjust(struct tcpcb *tp);
struct sackhole *tcp_sack_output(struct tcpcb *tp, int *sack_bytes_rexmt);
void	 tcp_sack_partialack(struct tcpcb *, struct tcphdr *);
void	 tcp_free_sackholes(struct tcpcb *tp);
int32_t	 tcp_sbspace(struct tcpcb *tp);
void	 tcp_set_tso(struct tcpcb *tp, struct ifnet *ifp);
void	 tcp_reset_stretch_ack(struct tcpcb *tp);
extern void tcp_get_ports_used(u_int32_t, int, u_int32_t, bitstr_t *);
uint32_t tcp_count_opportunistic(unsigned int ifindex, u_int32_t flags);
uint32_t tcp_find_anypcb_byaddr(struct ifaddr *ifa);
void	 tcp_set_max_rwinscale(struct tcpcb *tp, struct socket *so);
struct bwmeas* tcp_bwmeas_alloc(struct tcpcb *tp);
void tcp_bwmeas_free(struct tcpcb *tp);

extern void tcp_set_background_cc(struct socket *);
extern void tcp_set_foreground_cc(struct socket *);
extern void tcp_set_recv_bg(struct socket *);
extern void tcp_clear_recv_bg(struct socket *);
#define	IS_TCP_RECV_BG(_so)	\
	((_so)->so_traffic_mgt_flags & TRAFFIC_MGT_TCP_RECVBG)

#if TRAFFIC_MGT
#define CLEAR_IAJ_STATE(_tp_) (_tp_)->iaj_rcv_ts = 0
void	 reset_acc_iaj(struct tcpcb *tp);
#endif /* TRAFFIC_MGT */

int	 tcp_lock (struct socket *, int, void *);
int	 tcp_unlock (struct socket *, int, void *);
void	 calculate_tcp_clock(void);

extern void mptcp_insert_rmap(struct tcpcb *, struct mbuf *);
extern void tcp_keepalive_reset(struct tcpcb *);

#ifdef _KERN_LOCKS_H_
lck_mtx_t *	 tcp_getlock (struct socket *, int);
#else
void *	 tcp_getlock (struct socket *, int);
#endif


extern	struct pr_usrreqs tcp_usrreqs;
extern	u_int32_t tcp_sendspace;
extern	u_int32_t tcp_recvspace;
tcp_seq tcp_new_isn(struct tcpcb *);

extern int tcp_input_checksum(int, struct mbuf *, struct tcphdr *, int, int);
extern void tcp_getconninfo(struct socket *, struct conninfo_tcp *);
#if MPTCP
extern uint16_t mptcp_input_csum(struct tcpcb *, struct mbuf *, int);
extern void mptcp_output_csum(struct tcpcb *, struct mbuf *, int32_t, unsigned, 
    u_int64_t, u_int32_t *);
extern int mptcp_adj_mss(struct tcpcb *, boolean_t);
#endif
#endif /* BSD_KERNEL_RPIVATE */

#endif /* _NETINET_TCP_VAR_H_ */
