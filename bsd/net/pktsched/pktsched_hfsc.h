/*
 * Copyright (c) 2011-2012 Apple Inc. All rights reserved.
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

/*	$NetBSD: altq_hfsc.h,v 1.8 2006/10/12 19:59:08 peter Exp $	*/
/*	$KAME: altq_hfsc.h,v 1.12 2003/12/05 05:40:46 kjc Exp $	*/

/*
 * Copyright (c) 1997-1999 Carnegie Mellon University. All Rights Reserved.
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation is hereby granted (including for commercial or
 * for-profit use), provided that both the copyright notice and this
 * permission notice appear in all copies of the software, derivative
 * works, or modified versions, and any portions thereof.
 *
 * THIS SOFTWARE IS EXPERIMENTAL AND IS KNOWN TO HAVE BUGS, SOME OF
 * WHICH MAY HAVE SERIOUS CONSEQUENCES.  CARNEGIE MELLON PROVIDES THIS
 * SOFTWARE IN ITS ``AS IS'' CONDITION, AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Carnegie Mellon encourages (but does not require) users of this
 * software to return any improvements or extensions that they make,
 * and to grant Carnegie Mellon the rights to redistribute these
 * changes without encumbrance.
 */
#ifndef _NET_PKTSCHED_PKTSCHED_HFSC_H_
#define	_NET_PKTSCHED_PKTSCHED_HFSC_H_

#ifdef PRIVATE
#include <net/pktsched/pktsched.h>
#include <net/classq/classq.h>
#include <net/classq/classq_red.h>
#include <net/classq/classq_rio.h>
#include <net/classq/classq_blue.h>
#include <net/classq/classq_sfb.h>

#ifdef __cplusplus
extern "C" {
#endif

struct service_curve {
	u_int32_t fl;	/* service curve flags */
	u_int64_t m1;	/* slope of the first segment in bits/sec */
	u_int32_t d;	/* the x-projection of the first segment in msec */
	u_int64_t m2;	/* slope of the second segment in bits/sec */
};

/* valid values for service curve flags */
#define	HFSCF_M1_PCT		0x1	/* m1 is in percentage */
#define	HFSCF_M2_PCT		0x10	/* m2 is in percentage */

#define	HFSCF_USERFLAGS		(HFSCF_M1_PCT | HFSCF_M2_PCT)

/* special class handles */
#define	HFSC_NULLCLASS_HANDLE	0
#define	HFSC_MAX_CLASSES	64

/* hfsc class flags */
#define	HFCF_RED		0x0001	/* use RED */
#define	HFCF_ECN		0x0002  /* use ECN with RED/BLUE/SFB */
#define	HFCF_RIO		0x0004  /* use RIO */
#define	HFCF_CLEARDSCP		0x0010  /* clear diffserv codepoint */
#define	HFCF_BLUE		0x0100	/* use BLUE */
#define	HFCF_SFB		0x0200	/* use SFB */
#define	HFCF_FLOWCTL		0x0400	/* enable flow control advisories */
#define	HFCF_DEFAULTCLASS	0x1000	/* default class */
#ifdef BSD_KERNEL_PRIVATE
#define	HFCF_RSC		0x10000 /* has realtime sc */
#define	HFCF_FSC		0x20000 /* has linkshare sc */
#define	HFCF_USC		0x40000 /* has upperlimit sc */
#define	HFCF_LAZY		0x10000000 /* on-demand resource allocation */
#endif /* BSD_KERNEL_PRIVATE */

#define	HFCF_USERFLAGS							\
	(HFCF_RED | HFCF_ECN | HFCF_RIO | HFCF_CLEARDSCP | HFCF_BLUE |	\
	HFCF_SFB | HFCF_FLOWCTL | HFCF_DEFAULTCLASS)

#ifdef BSD_KERNEL_PRIVATE
#define	HFCF_BITS \
	"\020\1RED\2ECN\3RIO\5CLEARDSCP\11BLUE\12SFB\13FLOWCTL\15DEFAULT" \
	"\21RSC\22FSC\23USC\35LAZY"
#else
#define	HFCF_BITS \
	"\020\1RED\2ECN\3RIO\5CLEARDSCP\11BLUE\12SFB\13FLOWCTL\15DEFAULT"
#endif /* !BSD_KERNEL_PRIVATE */

/* service curve types */
#define	HFSC_REALTIMESC		1
#define	HFSC_LINKSHARINGSC	2
#define	HFSC_UPPERLIMITSC	4
#define	HFSC_DEFAULTSC		(HFSC_REALTIMESC|HFSC_LINKSHARINGSC)

struct hfsc_classstats {
	u_int32_t		class_id;
	u_int32_t		class_handle;
	struct service_curve	rsc;
	struct service_curve	fsc;
	struct service_curve	usc;	/* upper limit service curve */

	u_int64_t		total;	/* total work in bytes */
	u_int64_t		cumul;	/* cumulative work in bytes */
					/*   done by real-time criteria */
	u_int64_t		d;		/* deadline */
	u_int64_t		e;		/* eligible time */
	u_int64_t		vt;		/* virtual time */
	u_int64_t		f;		/* fit time for upper-limit */

	/* info helpful for debugging */
	u_int64_t		initvt;		/* init virtual time */
	u_int64_t		vtoff;		/* cl_vt_ipoff */
	u_int64_t		cvtmax;		/* cl_maxvt */
	u_int64_t		myf;		/* cl_myf */
	u_int64_t		cfmin;		/* cl_mincf */
	u_int64_t		cvtmin;		/* cl_mincvt */
	u_int64_t		myfadj;		/* cl_myfadj */
	u_int64_t		vtadj;		/* cl_vtadj */
	u_int64_t		cur_time;
	u_int32_t		machclk_freq;

	u_int32_t		qlength;
	u_int32_t		qlimit;
	struct pktcntr		xmit_cnt;
	struct pktcntr		drop_cnt;
	u_int32_t		period;

	u_int32_t		vtperiod;	/* vt period sequence no */
	u_int32_t		parentperiod;	/* parent's vt period seqno */
	int			nactive;	/* number of active children */

	/* RED, RIO, BLUE, SFB related info */
	classq_type_t		qtype;
	union {
		/* RIO has 3 red stats */
		struct red_stats	red[RIO_NDROPPREC];
		struct blue_stats	blue;
		struct sfb_stats	sfb;
	};
	classq_state_t		qstate;
};

#ifdef BSD_KERNEL_PRIVATE
#include <sys/queue.h>
/*
 * kernel internal service curve representation
 *	coordinates are given by 64 bit unsigned integers.
 *	x-axis: unit is clock count.  for the intel x86 architecture,
 *		the raw Pentium TSC (Timestamp Counter) value is used.
 *		virtual time is also calculated in this time scale.
 *	y-axis: unit is byte.
 *
 *	the service curve parameters are converted to the internal
 *	representation.
 *	the slope values are scaled to avoid overflow.
 *	the inverse slope values as well as the y-projection of the 1st
 *	segment are kept in order to to avoid 64-bit divide operations
 *	that are expensive on 32-bit architectures.
 *
 *  note: Intel Pentium TSC never wraps around in several thousands of years.
 *	x-axis doesn't wrap around for 1089 years with 1GHz clock.
 *      y-axis doesn't wrap around for 4358 years with 1Gbps bandwidth.
 */

/* kernel internal representation of a service curve */
struct internal_sc {
	u_int64_t	sm1;	/* scaled slope of the 1st segment */
	u_int64_t	ism1;	/* scaled inverse-slope of the 1st segment */
	u_int64_t	dx;	/* the x-projection of the 1st segment */
	u_int64_t	dy;	/* the y-projection of the 1st segment */
	u_int64_t	sm2;	/* scaled slope of the 2nd segment */
	u_int64_t	ism2;	/* scaled inverse-slope of the 2nd segment */
};

/* runtime service curve */
struct runtime_sc {
	u_int64_t	x;	/* current starting position on x-axis */
	u_int64_t	y;	/* current starting position on x-axis */
	u_int64_t	sm1;	/* scaled slope of the 1st segment */
	u_int64_t	ism1;	/* scaled inverse-slope of the 1st segment */
	u_int64_t	dx;	/* the x-projection of the 1st segment */
	u_int64_t	dy;	/* the y-projection of the 1st segment */
	u_int64_t	sm2;	/* scaled slope of the 2nd segment */
	u_int64_t	ism2;	/* scaled inverse-slope of the 2nd segment */
};

/* for TAILQ based ellist and actlist implementation */
struct hfsc_class;
typedef TAILQ_HEAD(_eligible, hfsc_class) ellist_t;
typedef TAILQ_ENTRY(hfsc_class) elentry_t;
typedef TAILQ_HEAD(_active, hfsc_class) actlist_t;
typedef TAILQ_ENTRY(hfsc_class) actentry_t;
#define	ellist_first(s)		TAILQ_FIRST(s)
#define	actlist_first(s)	TAILQ_FIRST(s)
#define	actlist_last(s)		TAILQ_LAST(s, _active)

struct hfsc_class {
	u_int32_t	cl_id;		/* class id (just for debug) */
	u_int32_t	cl_handle;	/* class handle */
	struct hfsc_if	*cl_hif;	/* back pointer to struct hfsc_if */
	u_int32_t	cl_flags;	/* misc flags */

	struct hfsc_class *cl_parent;	/* parent class */
	struct hfsc_class *cl_siblings;	/* sibling classes */
	struct hfsc_class *cl_children;	/* child classes */

	class_queue_t	cl_q;		/* class queue structure */
	u_int32_t	cl_qflags;	/* class queue flags */
	union {
		void		*ptr;
		struct red	*red;	/* RED state */
		struct rio	*rio;	/* RIO state */
		struct blue	*blue;	/* BLUE state */
		struct sfb	*sfb;	/* SFB state */
	} cl_qalg;

	u_int64_t	cl_total;	/* total work in bytes */
	u_int64_t	cl_cumul;	/* cumulative work in bytes */
					/*   done by real-time criteria */
	u_int64_t	cl_d;		/* deadline */
	u_int64_t	cl_e;		/* eligible time */
	u_int64_t	cl_vt;		/* virtual time */
	u_int64_t	cl_f;		/* time when this class will fit for */
					/*   link-sharing, max(myf, cfmin) */
	u_int64_t	cl_myf;		/* my fit-time (as calculated from */
					/*   this class's own upperlimit */
					/*   curve) */
	u_int64_t	cl_myfadj;	/* my fit-time adjustment */
					/*   (to cancel history dependence) */
	u_int64_t	cl_cfmin;	/* earliest children's fit-time (used */
					/*   with cl_myf to obtain cl_f) */
	u_int64_t	cl_cvtmin;	/* minimal virtual time among the */
					/*   children fit for link-sharing */
					/*   (monotonic within a period) */
	u_int64_t	cl_vtadj;	/* intra-period cumulative vt */
					/*   adjustment */
	u_int64_t	cl_vtoff;	/* inter-period cumulative vt offset */
	u_int64_t	cl_cvtmax;	/* max child's vt in the last period */

	u_int64_t	cl_initvt;	/* init virtual time (for debugging) */

	struct service_curve cl_rsc0;	/* external real-time service curve */
	struct service_curve cl_fsc0;	/* external fair service curve */
	struct service_curve cl_usc0;	/* external uppperlimit service curve */
	struct internal_sc cl_rsc;	/* internal real-time service curve */
	struct internal_sc cl_fsc;	/* internal fair service curve */
	struct internal_sc cl_usc;	/* internal upperlimit service curve */
	struct runtime_sc  cl_deadline;	/* deadline curve */
	struct runtime_sc  cl_eligible;	/* eligible curve */
	struct runtime_sc  cl_virtual;	/* virtual curve */
	struct runtime_sc  cl_ulimit;	/* upperlimit curve */

	u_int32_t	cl_vtperiod;	/* vt period sequence no */
	u_int32_t	cl_parentperiod;  /* parent's vt period seqno */
	u_int32_t	cl_nactive;	/* number of active children */
	actlist_t	cl_actc;	/* active children list */

	actentry_t	cl_actlist;	/* active children list entry */
	elentry_t	cl_ellist;	/* eligible list entry */

	struct {
		struct pktcntr	xmit_cnt;
		struct pktcntr	drop_cnt;
		u_int32_t period;
	} cl_stats;
};

#define	cl_red	cl_qalg.red
#define	cl_rio	cl_qalg.rio
#define	cl_blue	cl_qalg.blue
#define	cl_sfb	cl_qalg.sfb

/* hfsc_if flags */
#define	HFSCIFF_ALTQ		0x1	/* configured via PF/ALTQ */

/*
 * hfsc interface state
 */
struct hfsc_if {
	struct ifclassq		*hif_ifq;	/* backpointer to ifclassq */
	struct hfsc_class	*hif_rootclass;		/* root class */
	struct hfsc_class	*hif_defaultclass;	/* default class */
	struct hfsc_class	**hif_class_tbl;
	struct hfsc_class	*hif_pollcache;	/* cache for poll operation */

	u_int32_t		hif_flags;	/* flags */
	u_int32_t		hif_maxclasses;	/* max # of classes in table */
	u_int32_t		hif_classes;	/* # of classes in the tree */
	u_int32_t		hif_packets;	/* # of packets in the tree */
	u_int32_t		hif_classid;	/* class id sequence number */
	u_int64_t		hif_eff_rate;	/* last known effective rate */

	ellist_t hif_eligible;			/* eligible list */
};

#define	HFSCIF_IFP(_hif)	((_hif)->hif_ifq->ifcq_ifp)

extern void hfsc_init(void);
extern struct hfsc_if *hfsc_alloc(struct ifnet *, int, boolean_t);
extern int hfsc_destroy(struct hfsc_if *);
extern void hfsc_purge(struct hfsc_if *);
extern void hfsc_event(struct hfsc_if *, cqev_t);
extern int hfsc_add_queue(struct hfsc_if *, struct service_curve *,
    struct service_curve *, struct service_curve *, u_int32_t, int,
    u_int32_t, u_int32_t, struct hfsc_class **);
extern int hfsc_remove_queue(struct hfsc_if *, u_int32_t);
extern int hfsc_get_class_stats(struct hfsc_if *, u_int32_t,
    struct hfsc_classstats *);
extern int hfsc_enqueue(struct hfsc_if *, struct hfsc_class *,
    struct mbuf *, struct pf_mtag *);
extern struct mbuf *hfsc_dequeue(struct hfsc_if *, cqdq_op_t);
extern int hfsc_setup_ifclassq(struct ifclassq *, u_int32_t);
extern int hfsc_teardown_ifclassq(struct ifclassq *);
extern int hfsc_getqstats_ifclassq(struct ifclassq *, u_int32_t,
    struct if_ifclassq_stats *);
#endif /* BSD_KERNEL_PRIVATE */

#ifdef __cplusplus
}
#endif
#endif /* PRIVATE */
#endif /* _NET_PKTSCHED_PKTSCHED_HFSC_H_ */
