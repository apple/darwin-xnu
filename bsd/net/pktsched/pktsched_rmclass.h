/*
 * Copyright (c) 2011 Apple Inc. All rights reserved.
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

/* $OpenBSD: altq_rmclass.h,v 1.10 2007/06/17 19:58:58 jasper Exp $	*/
/* $KAME: altq_rmclass.h,v 1.6 2000/12/09 09:22:44 kjc Exp $	*/

/*
 * Copyright (c) 1991-1997 Regents of the University of California.
 * All rights reserved.
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
 *	This product includes software developed by the Network Research
 *	Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
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
 */

#ifndef _NET_PKTSCHED_PKTSCHED_RMCLASS_H_
#define	_NET_PKTSCHED_PKTSCHED_RMCLASS_H_

#ifdef PRIVATE
#include <net/classq/classq.h>
#include <net/pktsched/pktsched.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	RM_MAXPRIO	8	/* Max priority */

/* flags for rmc_init and rmc_newclass */
/* class flags */
#define	RMCF_RED		0x0001	/* use RED */
#define	RMCF_ECN		0x0002	/* use ECN with RED/BLUE/SFB */
#define	RMCF_RIO		0x0004	/* use RIO */
#define	RMCF_FLOWVALVE		0x0008	/* use flowvalve (aka penalty-box) */
#define	RMCF_CLEARDSCP		0x0010  /* clear diffserv codepoint */

/* flags for rmc_init */
#define	RMCF_WRR		0x0100
#define	RMCF_EFFICIENT		0x0200

#define	RMCF_BLUE		0x10000	/* use BLUE */
#define	RMCF_SFB		0x20000	/* use SFB */
#define	RMCF_FLOWCTL		0x40000	/* enable flow control advisories */
#ifdef BSD_KERNEL_PRIVATE
#define	RMCF_LAZY		0x10000000 /* on-demand resource allocation */

typedef struct rm_ifdat		rm_ifdat_t;
typedef struct rm_class		rm_class_t;

struct red;
struct rio;
struct blue;
struct sfb;

/*
 * Macros for dealing with time values.  We assume all times are
 * 'timevals'.  `microuptime' is used to get the best available clock
 * resolution.  If `microuptime' *doesn't* return a value that's about
 * ten times smaller than the average packet time on the fastest
 * link that will use these routines, a slightly different clock
 * scheme than this one should be used.
 * (Bias due to truncation error in this scheme will overestimate utilization
 * and discriminate against high bandwidth classes.  To remove this bias an
 * integrator needs to be added.  The simplest integrator uses a history of
 * 10 * avg.packet.time / min.tick.time packet completion entries.  This is
 * straight forward to add but we don't want to pay the extra memory
 * traffic to maintain it if it's not necessary (occasionally a vendor
 * accidentally builds a workstation with a decent clock - e.g., Sun & HP).)
 */

#define	RM_GETTIME(now) microuptime(&now)

#define	TV_LT(a, b) (((a)->tv_sec < (b)->tv_sec) ||  \
	(((a)->tv_usec < (b)->tv_usec) && ((a)->tv_sec <= (b)->tv_sec)))

#define	TV_DELTA(a, b, delta) {						\
	int	xxs;							\
									\
	delta = (a)->tv_usec - (b)->tv_usec;				\
	if ((xxs = (a)->tv_sec - (b)->tv_sec)) {			\
		switch (xxs) {						\
		default:						\
			/*						\
			 * if (xxs < 0)					\
			 *	printf("rm_class: bogus time values\n"); \
			 */						\
			delta = 0;					\
			/* fall through */				\
		case 2:							\
			delta += 1000000;				\
			/* fall through */				\
		case 1:							\
			delta += 1000000;				\
			break;						\
		}							\
	}								\
}

#define	TV_ADD_DELTA(a, delta, res) {					\
	int xxus = (a)->tv_usec + (delta);				\
									\
	(res)->tv_sec = (a)->tv_sec;					\
	while (xxus >= 1000000) {					\
		++((res)->tv_sec);					\
		xxus -= 1000000;					\
	}								\
	(res)->tv_usec = xxus;						\
}

#define	RM_TIMEOUT	2	/* 1 Clock tick. */

#if 1
#define	RM_MAXQUEUED	1	/* this isn't used in ALTQ/CBQ */
#else
#define	RM_MAXQUEUED	16	/* Max number of packets downstream of CBQ */
#endif
#define	RM_MAXQUEUE	64	/* Max queue length */
#define	RM_FILTER_GAIN	5	/* log2 of gain, e.g., 5 => 31/32 */
#define	RM_POWER	(1 << RM_FILTER_GAIN)
#define	RM_MAXDEPTH	32
#define	RM_NS_PER_SEC	(1000000000)

typedef struct _rm_class_stats_ {
	u_int32_t	handle;
	u_int32_t	depth;

	struct pktcntr	xmit_cnt;	/* packets sent in this class */
	struct pktcntr	drop_cnt;	/* dropped packets */
	u_int32_t	over;		/* # times went over limit */
	u_int32_t	borrows;	/* # times tried to borrow */
	u_int32_t	overactions;	/* # times invoked overlimit action */
	u_int32_t	delays;		/* # times invoked delay actions */
} rm_class_stats_t;

/*
 * CBQ Class state structure
 */
struct rm_class {
	class_queue_t	q_;		/* Queue of packets */
	rm_ifdat_t	*ifdat_;
	int		pri_;		/* Class priority. */
	int		depth_;		/* Class depth */
	u_int32_t	ns_per_byte_;	/* NanoSeconds per byte. */
	u_int32_t	maxrate_;	/* Bytes per second for this class. */
	u_int32_t	allotment_;	/* Fraction of link bandwidth. */
	u_int32_t	w_allotment_;	/* Weighted allotment for WRR */
	int		bytes_alloc_;	/* Allocation for round of WRR */

	int		avgidle_;
	int		maxidle_;
	int		minidle_;
	int		offtime_;
	int		sleeping_;	/* != 0 if delaying */
	u_int32_t	qthresh_;	/* Threshold for formal link sharing */
	int		leaf_;		/* Note whether leaf class or not */

	rm_class_t	*children_;	/* Children of this class */
	rm_class_t	*next_;		/* Next pointer, used if child */

	rm_class_t	*peer_;		/* Peer class */
	rm_class_t	*borrow_;	/* Borrow class */
	rm_class_t	*parent_;	/* Parent class */

	void	(*overlimit)(struct rm_class *, struct rm_class *);
	void	(*drop)(struct rm_class *); /* Class drop action. */

	union {
		void		*ptr;
		struct red	*red;	/* RED state */
		struct rio	*rio;	/* RIO state */
		struct blue	*blue;	/* BLUE state */
		struct sfb	*sfb;	/* SFB state */
	} qalg_;
	int		flags_;
	u_int32_t	qflags_;

	int		last_pkttime_;	/* saved pkt_time */
	struct timeval	undertime_;	/* time can next send */
	struct timeval	last_;		/* time last packet sent */
	struct timeval	overtime_;
	struct callout	callout_;	/* for timeout() calls */

	rm_class_stats_t stats_;	/* Class Statistics */
};

#define	red_	qalg_.red
#define	rio_	qalg_.rio
#define	blue_	qalg_.blue
#define	sfb_	qalg_.sfb

/*
 * CBQ Interface state
 */
struct rm_ifdat {
	int		queued_;	/* # pkts queued downstream */
	int		efficient_;	/* Link Efficency bit */
	int		wrr_;		/* Enable Weighted Round-Robin */
	u_long		ns_per_byte_;	/* Link byte speed. */
	int		maxqueued_;	/* Max packets to queue */
	int		maxpkt_;	/* Max packet size. */
	int		qi_;		/* In/out pointers for downstream */
	int		qo_;		/* packets */

	/*
	 * Active class state and WRR state.
	 */
	rm_class_t	*active_[RM_MAXPRIO];	/* Active cl's in each pri */
	int		na_[RM_MAXPRIO];	/* # of active cl's in a pri */
	int		num_[RM_MAXPRIO];	/* # of cl's per pri */
	int		alloc_[RM_MAXPRIO];	/* Byte Allocation */
	u_long		M_[RM_MAXPRIO];		/* WRR weights. */

	/*
	 * Network Interface/Solaris Queue state pointer.
	 */
	struct ifclassq	*ifq_;
	rm_class_t	*default_;	/* Default Pkt class, BE */
	rm_class_t	*root_;		/* Root Link class. */
	rm_class_t	*ctl_;		/* Control Traffic class. */
	void		(*restart)(struct ifclassq *);	/* Restart routine. */

	/*
	 * Current packet downstream packet state and dynamic state.
	 */
	rm_class_t	*borrowed_[RM_MAXQUEUED]; /* Class borrowed last */
	rm_class_t	*class_[RM_MAXQUEUED];	/* class sending */
	int		curlen_[RM_MAXQUEUED];	/* Current pktlen */
	struct timeval	now_[RM_MAXQUEUED];	/* Current packet time */
	int		is_overlimit_[RM_MAXQUEUED]; /* Current packet time */

	int		cutoff_;	/* Cut-off depth for borrowing */

	struct timeval	ifnow_;		/* expected xmit completion time */
#if 1 /* ALTQ4PPP */
	int		maxiftime_;	/* max delay inside interface */
#endif
	rm_class_t	*pollcache_;	/* cached rm_class by poll operation */
};

#define	RMC_IS_A_PARENT_CLASS(cl)	((cl)->children_ != NULL)

extern void rmclass_init(void);
extern rm_class_t *rmc_newclass(int, struct rm_ifdat *, u_int32_t,
    void (*)(struct rm_class *, struct rm_class *), u_int32_t,
    u_int32_t, struct rm_class *, struct rm_class *,
    u_int32_t, int, u_int32_t, int, int);
extern void rmc_delete_class(struct rm_ifdat *, struct rm_class *);
extern int rmc_modclass(struct rm_class *, u_int32_t, int, u_int32_t,
    int, u_int32_t, int);
extern int rmc_init(struct ifclassq *, struct rm_ifdat *, u_int32_t,
    void (*)(struct ifclassq *), u_int32_t, int, int, u_int32_t,
    int, u_int32_t, int);
extern int rmc_queue_packet(struct rm_class *, struct mbuf *, struct pf_mtag *);
extern struct mbuf *rmc_dequeue_next(struct rm_ifdat *, cqdq_op_t);
extern void rmc_update_class_util(struct rm_ifdat *);
extern void rmc_delay_action(struct rm_class *, struct rm_class *);
extern void rmc_drop(struct rm_class *, u_int32_t, u_int32_t *, u_int32_t *);
extern void rmc_dropall(struct rm_class *);
extern int rmc_get_weight(struct rm_ifdat *, int);
extern void rmc_updateq(struct rm_class *, cqev_t);

#endif /* BSD_KERNEL_PRIVATE */

#ifdef __cplusplus
}
#endif
#endif /* PRIVATE */
#endif /* _NET_PKTSCHED_PKTSCHED_RMCLASS_H_ */
