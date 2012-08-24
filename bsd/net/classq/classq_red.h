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

/*	$NetBSD: altq_red.h,v 1.5 2006/10/12 19:59:08 peter Exp $	*/
/*	$KAME: altq_red.h,v 1.8 2003/07/10 12:07:49 kjc Exp $	*/

/*
 * Copyright (C) 1997-2003
 *	Sony Computer Science Laboratories Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY SONY CSL AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL SONY CSL OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NET_CLASSQ_CLASSQ_RED_H_
#define	_NET_CLASSQ_CLASSQ_RED_H_

#ifdef PRIVATE
#ifdef BSD_KERNEL_PRIVATE
#include <net/classq/if_classq.h>
#endif /* BSD_KERNEL_PRIVATE */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * simpler versions of red parameters and statistics used by other
 * disciplines (e.g., CBQ)
 */
struct redparams {
	int th_min;		/* red min threshold */
	int th_max;		/* red max threshold */
	int inv_pmax;		/* inverse of max drop probability */
};

struct red_stats {
	int32_t		q_avg;
	u_int32_t	_pad;
	u_int32_t	drop_forced;
	u_int32_t	drop_unforced;
	u_int32_t	marked_packets;
};

#ifdef BSD_KERNEL_PRIVATE
/* weight table structure for idle time calibration */
struct wtab {
	struct wtab	*w_next;
	int		 w_weight;
	int		 w_param_max;
	int		 w_refcount;
	int32_t		 w_tab[32];
};

/* red flags */
#define	REDF_ECN4	0x01	/* use packet marking for IPv4 packets */
#define	REDF_ECN6	0x02	/* use packet marking for IPv6 packets */
#define	REDF_ECN	(REDF_ECN4 | REDF_ECN6)
#define	REDF_FLOWVALVE	0x04	/* use flowvalve (aka penalty-box) */

#define	REDF_USERFLAGS							\
	(REDF_ECN4 | REDF_ECN6 | REDF_FLOWVALVE)

typedef struct red {
	int		red_pkttime;	/* average packet time in micro sec */
					/*   used for idle calibration */
	int		red_flags;	/* red flags */
	struct ifnet	*red_ifp;	/* back pointer to ifnet */

	/* red parameters */
	int		red_weight;	/* weight for EWMA */
	int		red_inv_pmax;	/* inverse of max drop probability */
	int		red_thmin;	/* red min threshold */
	int		red_thmax;	/* red max threshold */

	/* variables for internal use */
	int		red_wshift;	/* log(red_weight) */
	int		red_thmin_s;	/* th_min scaled by avgshift */
	int		red_thmax_s;	/* th_max scaled by avgshift */
	int		red_probd;	/* drop probability denominator */

	int		red_avg;	/* queue len avg scaled by avgshift */
	int		red_count;	/* packet count since last dropped/ */
					/*   marked packet */
	int		red_idle;	/* queue was empty */
	int		red_old;	/* avg is above th_min */
	struct wtab	*red_wtab;	/* weight table */
	struct timeval	 red_last;	/* time when the queue becomes idle */

	struct {
		struct pktcntr	xmit_cnt;
		struct pktcntr	drop_cnt;
		u_int32_t	drop_forced;
		u_int32_t	drop_unforced;
		u_int32_t	marked_packets;
	} red_stats;
} red_t;

/* red drop types */
#define	DTYPE_NODROP	0	/* no drop */
#define	DTYPE_FORCED	1	/* a "forced" drop */
#define	DTYPE_EARLY	2	/* an "unforced" (early) drop */

extern void red_init(void);
extern red_t *red_alloc(struct ifnet *, int, int, int, int, int, int);
extern void red_destroy(red_t *);
extern void red_getstats(red_t *, struct red_stats *);
extern int red_addq(red_t *, class_queue_t *, struct mbuf *, struct pf_mtag *);
extern struct mbuf *red_getq(red_t *, class_queue_t *);
extern void red_purgeq(struct red *, class_queue_t *, u_int32_t,
    u_int32_t *, u_int32_t *);
extern void red_updateq(red_t *, cqev_t);
extern int red_suspendq(red_t *, class_queue_t *, boolean_t);

extern int drop_early(int, int, int);
extern struct wtab *wtab_alloc(int);
extern void wtab_destroy(struct wtab *);
extern int32_t pow_w(struct wtab *, int);
#endif /* BSD_KERNEL_PRIVATE */

#ifdef __cplusplus
}
#endif
#endif /* PRIVATE */
#endif /* _NET_CLASSQ_CLASSQ_RED_H_ */
