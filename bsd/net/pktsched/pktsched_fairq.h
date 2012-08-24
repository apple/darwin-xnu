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

/*
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * $DragonFly: src/sys/net/altq/altq_fairq.h,v 1.1 2008/04/06 18:58:15 dillon Exp $
 */

#ifndef _NET_PKTSCHED_PKTSCHED_FAIRQ_H_
#define	_NET_PKTSCHED_PKTSCHED_FAIRQ_H_

#ifdef PRIVATE
#include <net/pktsched/pktsched.h>
#include <net/pktsched/pktsched_rmclass.h>
#include <net/classq/classq.h>
#include <net/classq/classq_red.h>
#include <net/classq/classq_rio.h>
#include <net/classq/classq_blue.h>
#include <net/classq/classq_sfb.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	FAIRQ_MAX_BUCKETS	2048	/* maximum number of sorting buckets */
#define	FAIRQ_MAXPRI		RM_MAXPRIO
#define	FAIRQ_BITMAP_WIDTH	(sizeof (fairq_bitmap_t) * 8)
#define	FAIRQ_BITMAP_MASK	(FAIRQ_BITMAP_WIDTH - 1)

/* fairq class flags */
#define	FARF_RED		0x0001	/* use RED */
#define	FARF_ECN		0x0002  /* use ECN with RED/BLUE/SFB */
#define	FARF_RIO		0x0004  /* use RIO */
#define	FARF_CLEARDSCP		0x0010  /* clear diffserv codepoint */
#define	FARF_BLUE		0x0100	/* use BLUE */
#define	FARF_SFB		0x0200	/* use SFB */
#define	FARF_FLOWCTL		0x0400	/* enable flow control advisories */
#define	FARF_DEFAULTCLASS	0x1000	/* default class */
#ifdef BSD_KERNEL_PRIVATE
#define	FARF_HAS_PACKETS	0x2000	/* might have queued packets */
#define	FARF_LAZY		0x10000000 /* on-demand resource allocation */
#endif /* BSD_KERNEL_PRIVATE */

#define	FARF_USERFLAGS							\
	(FARF_RED | FARF_ECN | FARF_RIO | FARF_CLEARDSCP |		\
	FARF_BLUE | FARF_SFB | FARF_FLOWCTL | FARF_DEFAULTCLASS)

#ifdef BSD_KERNEL_PRIVATE
#define	FARF_BITS \
	"\020\1RED\2ECN\3RIO\5CLEARDSCP\11BLUE\12SFB\13FLOWCTL\15DEFAULT" \
	"\16HASPKTS\35LAZY"
#else
#define	FARF_BITS \
	"\020\1RED\2ECN\3RIO\5CLEARDSCP\11BLUE\12SFB\13FLOWCTL\15DEFAULT" \
	"\16HASPKTS"
#endif /* !BSD_KERNEL_PRIVATE */

typedef u_int32_t	fairq_bitmap_t;

struct fairq_classstats {
	u_int32_t		class_handle;
	u_int32_t		priority;

	u_int32_t		qlength;
	u_int32_t		qlimit;
	struct pktcntr		xmit_cnt;  /* transmitted packet counter */
	struct pktcntr		drop_cnt;  /* dropped packet counter */

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

typedef struct fairq_bucket {
	struct fairq_bucket *next;	/* circular list */
	struct fairq_bucket *prev;	/* circular list */
	class_queue_t	queue;		/* the actual queue */
	u_int64_t	bw_bytes;	/* statistics used to calculate bw */
	u_int64_t	bw_delta;	/* statistics used to calculate bw */
	u_int64_t	last_time;
	int		in_use;
} fairq_bucket_t;

struct fairq_class {
	u_int32_t	cl_handle;	/* class handle */
	u_int32_t	cl_nbuckets;	/* (power of 2) */
	u_int32_t	cl_nbucket_mask; /* bucket mask */
	u_int32_t	cl_qflags;	/* class queue flags */
	fairq_bucket_t	*cl_buckets;
	fairq_bucket_t	*cl_head;	/* head of circular bucket list */
	fairq_bucket_t	*cl_polled;
	union {
		void		*ptr;
		struct red	*red;	/* RED state */
		struct rio	*rio;	/* RIO state */
		struct blue	*blue;	/* BLUE state */
		struct sfb	*sfb;	/* SFB state */
	} cl_qalg;
	u_int64_t	cl_hogs_m1;
	u_int64_t	cl_lssc_m1;
	u_int64_t	cl_bandwidth;
	u_int64_t	cl_bw_current;
	u_int64_t	cl_bw_bytes;
	u_int64_t	cl_bw_delta;
	u_int64_t	cl_last_time;
	classq_type_t	cl_qtype;	/* rollup */
	classq_state_t	cl_qstate;	/* state */
	int		cl_qlimit;
	int		cl_pri;		/* priority */
	int		cl_flags;	/* class flags */
	struct fairq_if	*cl_fif;	/* back pointer to fif */

	/* round robin index */

	/* statistics */
	struct pktcntr  cl_xmitcnt;	/* transmitted packet counter */
	struct pktcntr  cl_dropcnt;	/* dropped packet counter */
};

#define	cl_red	cl_qalg.red
#define	cl_rio	cl_qalg.rio
#define	cl_blue	cl_qalg.blue
#define	cl_sfb	cl_qalg.sfb

/* fairq_if flags */
#define	FAIRQIFF_ALTQ		0x1	/* configured via PF/ALTQ */

/*
 * fairq interface state
 */
struct fairq_if {
	struct ifclassq		*fif_ifq;	/* backpointer to ifclassq */
	int			fif_maxpri;	/* max priority in use */
	u_int32_t		fif_flags;	/* flags */
	struct fairq_class	*fif_poll_cache; /* cached poll */
	struct fairq_class	*fif_default;	/* default class */
	struct fairq_class	*fif_classes[FAIRQ_MAXPRI]; /* classes */
};

#define	FAIRQIF_IFP(_fif)	((_fif)->fif_ifq->ifcq_ifp)

struct if_ifclassq_stats;

extern void fairq_init(void);
extern struct fairq_if *fairq_alloc(struct ifnet *, int, boolean_t);
extern int fairq_destroy(struct fairq_if *);
extern void fairq_purge(struct fairq_if *);
extern void fairq_event(struct fairq_if *, cqev_t);
extern int fairq_add_queue(struct fairq_if *, int, u_int32_t, u_int64_t,
    u_int32_t, int, u_int64_t, u_int64_t, u_int64_t, u_int64_t, u_int32_t,
    struct fairq_class **);
extern int fairq_remove_queue(struct fairq_if *, u_int32_t);
extern int fairq_get_class_stats(struct fairq_if *, u_int32_t,
    struct fairq_classstats *);
extern int fairq_enqueue(struct fairq_if *, struct fairq_class *,
    struct mbuf *, struct pf_mtag *);
extern struct mbuf *fairq_dequeue(struct fairq_if *, cqdq_op_t);
extern int fairq_setup_ifclassq(struct ifclassq *, u_int32_t);
extern int fairq_teardown_ifclassq(struct ifclassq *ifq);
extern int fairq_getqstats_ifclassq(struct ifclassq *, u_int32_t,
    struct if_ifclassq_stats *);
#endif /* BSD_KERNEL_PRIVATE */
#ifdef __cplusplus
}
#endif
#endif /* PRIVATE */
#endif /* _NET_PKTSCHED_PKTSCHED_FAIRQ_H_ */
