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
/*-
 * Copyright (c) 1991, 1993
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
 *	@(#)tp_pcb.h	8.1 (Berkeley) 6/10/93
 */

/***********************************************************
		Copyright IBM Corporation 1987

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of IBM not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

IBM DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
IBM BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

******************************************************************/

/*
 * ARGO Project, Computer Sciences Dept., University of Wisconsin - Madison
 */
/* 
 * ARGO TP
 *
 * 
 * This file defines the transport protocol control block (tpcb).
 * and a bunch of #define values that are used in the tpcb.
 */

#ifndef  __TP_PCB__
#define  __TP_PCB__

#include <netiso/tp_param.h>
#include <netiso/tp_timer.h>
#include <netiso/tp_user.h>
#ifndef sblock
#include <sys/socketvar.h>
#endif /* sblock */

/* NOTE: the code depends on REF_CLOSED > REF_OPEN > the rest, and
 * on REF_FREE being zero
 *
 * Possible improvement:
 * think about merging the tp_ref w/ the tpcb and doing a search
 * through the tpcb list, from tpb. This would slow down lookup
 * during data transfer
 * It would be a little nicer also to have something based on the
 * clock (like top n bits of the reference is part of the clock, to
 * minimize the likelihood  of reuse after a crash)
 * also, need to keep the timer servicing part to a minimum (although
 * the cost of this is probably independent of whether the timers are
 * in the pcb or in an array..
 * Last, would have to make the number of timers a function of the amount of
 * mbufs available, plus some for the frozen references.
 *
 * Possible improvement:
 * Might not need the ref_state stuff either...
 * REF_FREE could correspond to tp_state == CLOSED or nonexistend tpcb,
 * REF_OPEN to tp_state anywhere from AK_WAIT or CR_SENT to CLOSING
 * REF_OPENING could correspond to LISTENING, because that's the
 * way it's used, not because the correspondence is exact.
 * REF_CLOSED could correspond to REFWAIT
 */
#define REF_FROZEN 3	/* has ref timer only */
#define REF_OPEN 2		/* has timers, possibly active */
#define REF_OPENING 1	/* in use (has a pcb) but no timers */
#define REF_FREE 0		/* free to reallocate */

#define TM_NTIMERS 		6

struct tp_ref {
	struct tp_pcb 		*tpr_pcb;	/* back ptr to PCB */
};

/* PER system stuff (one static structure instead of a bunch of names) */
struct tp_refinfo {
	struct tp_ref		*tpr_base;
	int					tpr_size;
	int					tpr_maxopen;
	int					tpr_numopen;
};

struct nl_protosw {
	int		nlp_afamily;			/* address family */
	int		(*nlp_putnetaddr)();	/* puts addresses in nl pcb */
	int		(*nlp_getnetaddr)();	/* gets addresses from nl pcb */
	int		(*nlp_cmpnetaddr)();	/* compares address in pcb with sockaddr */
	int		(*nlp_putsufx)();		/* puts transport suffixes in nl pcb */
	int		(*nlp_getsufx)();		/* gets transport suffixes from nl pcb */
	int		(*nlp_recycle_suffix)();/* clears suffix from nl pcb */
	int		(*nlp_mtu)();			/* figures out mtu based on nl used */
	int		(*nlp_pcbbind)();		/* bind to pcb for net level */
	int		(*nlp_pcbconn)();		/* connect for net level */
	int		(*nlp_pcbdisc)();		/* disconnect net level */
	int		(*nlp_pcbdetach)();		/* detach net level pcb */
	int		(*nlp_pcballoc)();		/* allocate a net level pcb */
	int		(*nlp_output)();		/* prepare a packet to give to nl */
	int		(*nlp_dgoutput)();		/* prepare a packet to give to nl */
	int		(*nlp_ctloutput)();		/* hook for network set/get options */
	caddr_t	nlp_pcblist;			/* list of xx_pcb's for connections */
};


struct tp_pcb {
	struct tp_pcb		*tp_next;
	struct tp_pcb		*tp_prev;
	struct tp_pcb		*tp_nextlisten; /* chain all listeners */
	struct socket 		*tp_sock;		/* back ptr */
	u_short 			tp_state;		/* state of fsm */
	short 				tp_retrans;		/* # times can still retrans */
	caddr_t				tp_npcb;		/* to lower layer pcb */
	struct nl_protosw	*tp_nlproto;	/* lower-layer dependent routines */
	struct rtentry		**tp_routep;	/* obtain mtu; inside npcb */


	RefNum				tp_lref;	 	/* local reference */
	RefNum 				tp_fref;		/* foreign reference */

	u_int				tp_seqmask;		/* mask for seq space */
	u_int				tp_seqbit;		/* bit for seq number wraparound */
	u_int				tp_seqhalf;		/* half the seq space */

	struct mbuf			*tp_ucddata;	/* user connect/disconnect data */

	/* credit & sequencing info for SENDING */
	u_short 			tp_fcredit;		/* current remote credit in # packets */
	u_short 			tp_maxfcredit;	/* max remote credit in # packets */
	u_short				tp_dupacks;		/* intuit packet loss before rxt timo */
	u_long				tp_cong_win;	/* congestion window in bytes.
										 * see profuse comments in TCP code
										 */
	u_long				tp_ssthresh;	/* cong_win threshold for slow start
										 * exponential to linear switch
										 */
	SeqNum				tp_snduna;		/* seq # of lowest unacked DT */
	SeqNum				tp_sndnew;		/* seq # of lowest unsent DT  */
	SeqNum				tp_sndnum;		/* next seq # to be assigned */
	SeqNum				tp_sndnxt;		/* what to do next; poss. rxt */
	struct mbuf			*tp_sndnxt_m;	/* packet corres. to sndnxt*/
	int					tp_Nwindow;		/* for perf. measurement */

	/* credit & sequencing info for RECEIVING */
	SeqNum				tp_rcvnxt;		/* next DT seq # expect to recv */
	SeqNum	 			tp_sent_lcdt;	/* cdt according to last ack sent */
	SeqNum	 			tp_sent_uwe;	/* uwe according to last ack sent */
	SeqNum	 			tp_sent_rcvnxt;	/* rcvnxt according to last ack sent 
										 * needed for perf measurements only
										 */
	u_short				tp_lcredit;		/* current local credit in # packets */
	u_short				tp_maxlcredit;	/* needed for reassembly queue */
	struct mbuf			**tp_rsyq;		/* unacked stuff recvd out of order */
	int					tp_rsycnt;		/* number of packets "" "" "" ""    */
	u_long				tp_rhiwat;		/* remember original RCVBUF size */

	/* receiver congestion state stuff ...  */
	u_int               tp_win_recv;

	/* receive window as a scaled int (8 bit fraction part) */

	struct cong_sample {
		ushort  cs_size; 				/* current window size */
		ushort  cs_received;   			/* PDUs received in this sample */
		ushort  cs_ce_set;    /* PDUs received in this sample with CE bit set */
	} tp_cong_sample;


	/* parameters per-connection controllable by user */
	struct tp_conn_param _tp_param; 

#define	tp_Nretrans _tp_param.p_Nretrans
#define	tp_dr_ticks _tp_param.p_dr_ticks
#define	tp_cc_ticks _tp_param.p_cc_ticks
#define	tp_dt_ticks _tp_param.p_dt_ticks
#define	tp_xpd_ticks _tp_param.p_x_ticks
#define	tp_cr_ticks _tp_param.p_cr_ticks
#define	tp_keepalive_ticks _tp_param.p_keepalive_ticks
#define	tp_sendack_ticks _tp_param.p_sendack_ticks
#define	tp_refer_ticks _tp_param.p_ref_ticks
#define	tp_inact_ticks _tp_param.p_inact_ticks
#define	tp_xtd_format _tp_param.p_xtd_format
#define	tp_xpd_service _tp_param.p_xpd_service
#define	tp_ack_strat _tp_param.p_ack_strat
#define	tp_rx_strat _tp_param.p_rx_strat
#define	tp_use_checksum _tp_param.p_use_checksum
#define	tp_use_efc _tp_param.p_use_efc
#define	tp_use_nxpd _tp_param.p_use_nxpd
#define	tp_use_rcc _tp_param.p_use_rcc
#define	tp_tpdusize _tp_param.p_tpdusize
#define	tp_class _tp_param.p_class
#define	tp_winsize _tp_param.p_winsize
#define	tp_no_disc_indications _tp_param.p_no_disc_indications
#define	tp_dont_change_params _tp_param.p_dont_change_params
#define	tp_netservice _tp_param.p_netservice
#define	tp_version _tp_param.p_version
#define	tp_ptpdusize _tp_param.p_ptpdusize

	int					tp_l_tpdusize;
		/* whereas tp_tpdusize is log2(the negotiated max size)
		 * l_tpdusize is the size we'll use when sending, in # chars
		 */

	int					tp_rtv;			/* max round-trip time variance */
	int					tp_rtt; 		/* smoothed round-trip time */
	SeqNum				tp_rttseq;		/* packet being timed */
	int					tp_rttemit;		/* when emitted, in ticks */
	int					tp_idle;		/* last activity, in ticks */
	short				tp_rxtcur;		/* current retransmit value */
	short				tp_rxtshift;	/* log(2) of rexmt exp. backoff */
	u_char				tp_cebit_off;	/* real DEC bit algorithms not in use */
	u_char				tp_oktonagle;	/* Last unsent pckt may be append to */
	u_char				tp_flags;		/* values: */
#define TPF_NLQOS_PDN	 	TPFLAG_NLQOS_PDN
#define TPF_PEER_ON_SAMENET	TPFLAG_PEER_ON_SAMENET
#define TPF_GENERAL_ADDR	TPFLAG_GENERAL_ADDR
#define TPF_DELACK			0x8
#define TPF_ACKNOW			0x10

#define PEER_IS_LOCAL(t)	(((t)->tp_flags & TPF_PEER_ON_SAME_NET) != 0)
#define USES_PDN(t)			(((t)->tp_flags & TPF_NLQOS_PDN) != 0)


	unsigned 
		tp_sendfcc:1,			/* shall next ack include FCC parameter? */
		tp_trace:1,				/* is this pcb being traced? (not used yet) */
		tp_perf_on:1,			/* 0/1 -> performance measuring on  */
		tp_reneged:1,			/* have we reneged on cdt since last ack? */
		tp_decbit:3,			/* dec bit was set, we're in reneg mode  */
		tp_notdetached:1;		/* Call tp_detach before freeing XXXXXXX */

#ifdef TP_PERF_MEAS
	/* performance stats - see tp_stat.h */
	struct tp_pmeas		*tp_p_meas;
	struct mbuf			*tp_p_mbuf;
#endif /* TP_PERF_MEAS */

	/* addressing */
	u_short				tp_domain;		/* domain (INET, ISO) */
	/* for compatibility with the *old* way and with INET, be sure that
	 * that lsuffix and fsuffix are aligned to a short addr.
	 * having them follow the u_short *suffixlen should suffice (choke)
	 */
	u_short				tp_fsuffixlen;	/* foreign suffix */
	char				tp_fsuffix[MAX_TSAP_SEL_LEN];
	u_short				tp_lsuffixlen;	/* local suffix */
	char				tp_lsuffix[MAX_TSAP_SEL_LEN];
#define SHORT_LSUFXP(tpcb) ((short *)((tpcb)->tp_lsuffix))
#define SHORT_FSUFXP(tpcb) ((short *)((tpcb)->tp_fsuffix))

	/* Timer stuff */
	u_char 				tp_vers;			/* protocol version */
	u_char 				tp_peer_acktime;	/* used for DT retrans time */
	u_char	 			tp_refstate;		/* values REF_FROZEN, etc. above */
	struct tp_pcb		*tp_fasttimeo;		/* limit pcbs to examine */
	u_int			 	tp_timer[TM_NTIMERS]; /* C timers */

	struct sockbuf		tp_Xsnd;		/* for expedited data */
/*	struct sockbuf		tp_Xrcv;		/* for expedited data */
#define tp_Xrcv tp_sock->so_rcv
	SeqNum				tp_Xsndnxt;	/* next XPD seq # to send */
	SeqNum				tp_Xuna;		/* seq # of unacked XPD */
	SeqNum				tp_Xrcvnxt;	/* next XPD seq # expect to recv */

	/* AK subsequencing */
	u_short				tp_s_subseq;	/* next subseq to send */
	u_short				tp_r_subseq;	/* highest recv subseq */

};

u_int	tp_start_win;

#define ROUND(scaled_int) (((scaled_int) >> 8) + (((scaled_int) & 0x80) ? 1:0))

/* to round off a scaled int with an 8 bit fraction part */

#define CONG_INIT_SAMPLE(pcb) \
	pcb->tp_cong_sample.cs_received = \
    pcb->tp_cong_sample.cs_ce_set = 0; \
    pcb->tp_cong_sample.cs_size = max(pcb->tp_lcredit, 1) << 1;

#define CONG_UPDATE_SAMPLE(pcb, ce_bit) \
    pcb->tp_cong_sample.cs_received++; \
    if (ce_bit) { \
        pcb->tp_cong_sample.cs_ce_set++; \
    } \
    if (pcb->tp_cong_sample.cs_size <= pcb->tp_cong_sample.cs_received) { \
        if ((pcb->tp_cong_sample.cs_ce_set << 1) >=  \
                    pcb->tp_cong_sample.cs_size ) { \
            pcb->tp_win_recv -= pcb->tp_win_recv >> 3; /* multiply by .875 */ \
            pcb->tp_win_recv = max(1 << 8, pcb->tp_win_recv); \
        } \
        else { \
            pcb->tp_win_recv += (1 << 8); /* add one to the scaled int */ \
        } \
        pcb->tp_lcredit = ROUND(pcb->tp_win_recv); \
        CONG_INIT_SAMPLE(pcb); \
    }

#ifdef KERNEL
extern struct tp_refinfo 	tp_refinfo;
extern struct timeval 	time;
extern struct tp_ref	*tp_ref;
extern struct tp_param	tp_param;
extern struct nl_protosw  nl_protosw[];
extern struct tp_pcb	*tp_listeners;
extern struct tp_pcb	*tp_ftimeolist;
#endif

#define	sototpcb(so) 	((struct tp_pcb *)(so->so_pcb))
#define	sototpref(so)	((sototpcb(so)->tp_ref))
#define	tpcbtoso(tp)	((struct socket *)((tp)->tp_sock))
#define	tpcbtoref(tp)	((struct tp_ref *)((tp)->tp_ref))

#endif  /* __TP_PCB__ */
