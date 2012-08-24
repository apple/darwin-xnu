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

/*	$NetBSD: altq_rio.h,v 1.5 2006/10/12 19:59:08 peter Exp $	*/
/*	$KAME: altq_rio.h,v 1.9 2003/07/10 12:07:49 kjc Exp $	*/

/*
 * Copyright (C) 1998-2003
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

#ifndef _NET_CLASSQ_CLASSQ_RIO_H_
#define	_NET_CLASSQ_CLASSQ_RIO_H_

#ifdef PRIVATE
#ifdef BSD_KERNEL_PRIVATE
#include <net/classq/if_classq.h>
#endif /* BSD_KERNEL_PRIVATE */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RIO: RED with IN/OUT bit
 * (extended to support more than 2 drop precedence values)
 */
#define	RIO_NDROPPREC	3	/* number of drop precedence values */

#ifdef BSD_KERNEL_PRIVATE
/* rio flags */
#define	RIOF_ECN4	0x01	/* use packet marking for IPv4 packets */
#define	RIOF_ECN6	0x02	/* use packet marking for IPv6 packets */
#define	RIOF_ECN	(RIOF_ECN4 | RIOF_ECN6)
#define	RIOF_CLEARDSCP	0x200	/* clear diffserv codepoint */

#define	RIOF_USERFLAGS							\
	(RIOF_ECN4 | RIOF_ECN6 | RIOF_CLEARDSCP)

typedef struct rio {
	/* per drop precedence structure */
	struct dropprec_state {
		/* red parameters */
		int	inv_pmax;	/* inverse of max drop probability */
		int	th_min;		/* red min threshold */
		int	th_max;		/* red max threshold */

		/* variables for internal use */
		int	th_min_s;	/* th_min scaled by avgshift */
		int	th_max_s;	/* th_max scaled by avgshift */
		int	probd;		/* drop probability denominator */

		int	qlen;		/* queue length */
		int	avg;		/* (scaled) queue length average */
		int	count;		/* packet count since the last */
					/*   dropped/marked packet */
		int	idle;		/* queue was empty */
		int	old;		/* avg is above th_min */
		struct timeval	last;	/* timestamp when queue becomes idle */
	} rio_precstate[RIO_NDROPPREC];

	int		 rio_wshift;	/* log(red_weight) */
	int		 rio_weight;	/* weight for EWMA */
	struct wtab	*rio_wtab;	/* weight table */

	int		 rio_pkttime;	/* average packet time in micro sec */
					/*   used for idle calibration */
	int		 rio_flags;	/* rio flags */
	struct ifnet	*rio_ifp;	/* back pointer to ifnet */

	u_int8_t	 rio_codepoint;	/* codepoint value to tag packets */
	u_int8_t	 rio_codepointmask;	/* codepoint mask bits */

	struct red_stats q_stats[RIO_NDROPPREC];	/* statistics */
} rio_t;

extern void rio_init(void);
extern rio_t *rio_alloc(struct ifnet *, int, struct redparams *, int, int);
extern void rio_destroy(rio_t *);
extern void rio_getstats(rio_t *, struct red_stats *);
extern int rio_addq(rio_t *, class_queue_t *, struct mbuf *, struct pf_mtag *);
extern struct mbuf *rio_getq(rio_t *, class_queue_t *);
extern void rio_purgeq(struct rio *, class_queue_t *, u_int32_t,
    u_int32_t *, u_int32_t *);
extern void rio_updateq(rio_t *, cqev_t);
extern int rio_suspendq(rio_t *, class_queue_t *, boolean_t);
#endif /* BSD_KERNEL_PRIVATE */

#ifdef __cplusplus
}
#endif
#endif /* PRIVATE */
#endif /* _NET_CLASSQ_CLASSQ_RIO_H_ */
