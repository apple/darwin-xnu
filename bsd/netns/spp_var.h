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
 * Copyright (c) 1984, 1985, 1986, 1987, 1993
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
 *	@(#)spp_var.h	8.1 (Berkeley) 6/10/93
 */

/*
 * Sp control block, one per connection
 */
struct sppcb {
	struct	spidp_q	s_q;		/* queue for out-of-order receipt */
	struct	nspcb	*s_nspcb;	/* backpointer to internet pcb */
	u_char	s_state;
	u_char	s_flags;
#define	SF_ACKNOW	0x01		/* Ack peer immediately */
#define	SF_DELACK	0x02		/* Ack, but try to delay it */
#define	SF_HI	0x04			/* Show headers on input */
#define	SF_HO	0x08			/* Show headers on output */
#define	SF_PI	0x10			/* Packet (datagram) interface */
#define SF_WIN	0x20			/* Window info changed */
#define SF_RXT	0x40			/* Rxt info changed */
#define SF_RVD	0x80			/* Calling from read usrreq routine */
	u_short s_mtu;			/* Max packet size for this stream */
/* use sequence fields in headers to store sequence numbers for this
   connection */
	struct	idp	*s_idp;
	struct	sphdr	s_shdr;		/* prototype header to transmit */
#define s_cc s_shdr.sp_cc		/* connection control (for EM bit) */
#define s_dt s_shdr.sp_dt		/* datastream type */
#define s_sid s_shdr.sp_sid		/* source connection identifier */
#define s_did s_shdr.sp_did		/* destination connection identifier */
#define s_seq s_shdr.sp_seq		/* sequence number */
#define s_ack s_shdr.sp_ack		/* acknowledge number */
#define s_alo s_shdr.sp_alo		/* allocation number */
#define s_dport s_idp->idp_dna.x_port	/* where we are sending */
	struct sphdr s_rhdr;		/* last received header (in effect!)*/
	u_short s_rack;			/* their acknowledge number */
	u_short s_ralo;			/* their allocation number */
	u_short s_smax;			/* highest packet # we have sent */
	u_short	s_snxt;			/* which packet to send next */

/* congestion control */
#define	CUNIT	1024			/* scaling for ... */
	int	s_cwnd;			/* Congestion-controlled window */
					/* in packets * CUNIT */
	short	s_swnd;			/* == tcp snd_wnd, in packets */
	short	s_smxw;			/* == tcp max_sndwnd */
					/* difference of two spp_seq's can be
					   no bigger than a short */
	u_short	s_swl1;			/* == tcp snd_wl1 */
	u_short	s_swl2;			/* == tcp snd_wl2 */
	int	s_cwmx;			/* max allowable cwnd */
	int	s_ssthresh;		/* s_cwnd size threshhold for
					 * slow start exponential-to-
					 * linear switch */
/* transmit timing stuff
 * srtt and rttvar are stored as fixed point, for convenience in smoothing.
 * srtt has 3 bits to the right of the binary point, rttvar has 2.
 */
	short	s_idle;			/* time idle */
	short	s_timer[SPPT_NTIMERS];	/* timers */
	short	s_rxtshift;		/* log(2) of rexmt exp. backoff */
	short	s_rxtcur;		/* current retransmit value */
	u_short	s_rtseq;		/* packet being timed */
	short	s_rtt;			/* timer for round trips */
	short	s_srtt;			/* averaged timer */
	short	s_rttvar;		/* variance in round trip time */
	char	s_force;		/* which timer expired */
	char	s_dupacks;		/* counter to intuit xmt loss */

/* out of band data */
	char	s_oobflags;
#define SF_SOOB	0x08			/* sending out of band data */
#define SF_IOOB 0x10			/* receiving out of band data */
	char	s_iobc;			/* input characters */
/* debug stuff */
	u_short	s_want;			/* Last candidate for sending */
	char	s_outx;			/* exit taken from spp_output */
	char	s_inx;			/* exit taken from spp_input */
	u_short	s_flags2;		/* more flags for testing */
#define SF_NEWCALL	0x100		/* for new_recvmsg */
#define SO_NEWCALL	10		/* for new_recvmsg */
};

#define	nstosppcb(np)	((struct sppcb *)(np)->nsp_pcb)
#define	sotosppcb(so)	(nstosppcb(sotonspcb(so)))

struct	sppstat {
	long	spps_connattempt;	/* connections initiated */
	long	spps_accepts;		/* connections accepted */
	long	spps_connects;		/* connections established */
	long	spps_drops;		/* connections dropped */
	long	spps_conndrops;		/* embryonic connections dropped */
	long	spps_closed;		/* conn. closed (includes drops) */
	long	spps_segstimed;		/* segs where we tried to get rtt */
	long	spps_rttupdated;	/* times we succeeded */
	long	spps_delack;		/* delayed acks sent */
	long	spps_timeoutdrop;	/* conn. dropped in rxmt timeout */
	long	spps_rexmttimeo;	/* retransmit timeouts */
	long	spps_persisttimeo;	/* persist timeouts */
	long	spps_keeptimeo;		/* keepalive timeouts */
	long	spps_keepprobe;		/* keepalive probes sent */
	long	spps_keepdrops;		/* connections dropped in keepalive */

	long	spps_sndtotal;		/* total packets sent */
	long	spps_sndpack;		/* data packets sent */
	long	spps_sndbyte;		/* data bytes sent */
	long	spps_sndrexmitpack;	/* data packets retransmitted */
	long	spps_sndrexmitbyte;	/* data bytes retransmitted */
	long	spps_sndacks;		/* ack-only packets sent */
	long	spps_sndprobe;		/* window probes sent */
	long	spps_sndurg;		/* packets sent with URG only */
	long	spps_sndwinup;		/* window update-only packets sent */
	long	spps_sndctrl;		/* control (SYN|FIN|RST) packets sent */
	long	spps_sndvoid;		/* couldn't find requested packet*/

	long	spps_rcvtotal;		/* total packets received */
	long	spps_rcvpack;		/* packets received in sequence */
	long	spps_rcvbyte;		/* bytes received in sequence */
	long	spps_rcvbadsum;		/* packets received with ccksum errs */
	long	spps_rcvbadoff;		/* packets received with bad offset */
	long	spps_rcvshort;		/* packets received too short */
	long	spps_rcvduppack;	/* duplicate-only packets received */
	long	spps_rcvdupbyte;	/* duplicate-only bytes received */
	long	spps_rcvpartduppack;	/* packets with some duplicate data */
	long	spps_rcvpartdupbyte;	/* dup. bytes in part-dup. packets */
	long	spps_rcvoopack;		/* out-of-order packets received */
	long	spps_rcvoobyte;		/* out-of-order bytes received */
	long	spps_rcvpackafterwin;	/* packets with data after window */
	long	spps_rcvbyteafterwin;	/* bytes rcvd after window */
	long	spps_rcvafterclose;	/* packets rcvd after "close" */
	long	spps_rcvwinprobe;	/* rcvd window probe packets */
	long	spps_rcvdupack;		/* rcvd duplicate acks */
	long	spps_rcvacktoomuch;	/* rcvd acks for unsent data */
	long	spps_rcvackpack;	/* rcvd ack packets */
	long	spps_rcvackbyte;	/* bytes acked by rcvd acks */
	long	spps_rcvwinupd;		/* rcvd window update packets */
};
struct	spp_istat {
	short	hdrops;
	short	badsum;
	short	badlen;
	short	slotim;
	short	fastim;
	short	nonucn;
	short	noconn;
	short	notme;
	short	wrncon;
	short	bdreas;
	short	gonawy;
	short	notyet;
	short	lstdup;
	struct sppstat newstats;
};

#ifdef KERNEL
struct spp_istat spp_istat;

/* Following was struct sppstat sppstat; */
#ifndef sppstat
#define sppstat spp_istat.newstats
#endif

u_short spp_iss;
extern struct sppcb *spp_close(), *spp_disconnect(),
	*spp_usrclosed(), *spp_timers(), *spp_drop();
#endif

#define	SPP_ISSINCR	128
/*
 * SPP sequence numbers are 16 bit integers operated
 * on with modular arithmetic.  These macros can be
 * used to compare such integers.
 */
#ifdef sun
short xnsCbug;
#define	SSEQ_LT(a,b)	((xnsCbug = (short)((a)-(b))) < 0)
#define	SSEQ_LEQ(a,b)	((xnsCbug = (short)((a)-(b))) <= 0)
#define	SSEQ_GT(a,b)	((xnsCbug = (short)((a)-(b))) > 0)
#define	SSEQ_GEQ(a,b)	((xnsCbug = (short)((a)-(b))) >= 0)
#else
#define	SSEQ_LT(a,b)	(((short)((a)-(b))) < 0)
#define	SSEQ_LEQ(a,b)	(((short)((a)-(b))) <= 0)
#define	SSEQ_GT(a,b)	(((short)((a)-(b))) > 0)
#define	SSEQ_GEQ(a,b)	(((short)((a)-(b))) >= 0)
#endif
