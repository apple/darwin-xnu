/*
 * Copyright (c) 2007-2013 Apple Inc. All rights reserved.
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

/*	$OpenBSD: altq_rio.c,v 1.11 2007/09/13 20:40:02 chl Exp $	*/
/*	$KAME: altq_rio.c,v 1.8 2000/12/14 08:12:46 thorpej Exp $	*/

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
/*
 * Copyright (c) 1990-1994 Regents of the University of California.
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
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
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

#include <sys/cdefs.h>

#if CLASSQ_RIO

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/errno.h>
#include <sys/kauth.h>
#include <sys/kauth.h>

#include <kern/zalloc.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if INET6
#include <netinet/ip6.h>
#endif

#include <net/classq/classq_red.h>
#include <net/classq/classq_rio.h>
#include <net/net_osdep.h>

/*
 * RIO: RED with IN/OUT bit
 *   described in
 *	"Explicit Allocation of Best Effort Packet Delivery Service"
 *	David D. Clark and Wenjia Fang, MIT Lab for Computer Science
 *	http://diffserv.lcs.mit.edu/Papers/exp-alloc-ddc-wf.{ps,pdf}
 *
 * this implementation is extended to support more than 2 drop precedence
 * values as described in RFC2597 (Assured Forwarding PHB Group).
 *
 */
/*
 * AF DS (differentiated service) codepoints.
 * (classes can be mapped to CBQ or H-FSC classes.)
 *
 *      0   1   2   3   4   5   6   7
 *    +---+---+---+---+---+---+---+---+
 *    |   CLASS   |DropPre| 0 |  CU   |
 *    +---+---+---+---+---+---+---+---+
 *
 *    class 1: 001
 *    class 2: 010
 *    class 3: 011
 *    class 4: 100
 *
 *    low drop prec:    01
 *    medium drop prec: 10
 *    high drop prec:   11
 */

/* normal red parameters */
#define	W_WEIGHT	512	/* inverse of weight of EWMA (511/512) */
				/* q_weight = 0.00195 */

/* red parameters for a slow link */
#define	W_WEIGHT_1	128	/* inverse of weight of EWMA (127/128) */
				/* q_weight = 0.0078125 */

/* red parameters for a very slow link (e.g., dialup) */
#define	W_WEIGHT_2	64	/* inverse of weight of EWMA (63/64) */
				/* q_weight = 0.015625 */

/* fixed-point uses 12-bit decimal places */
#define	FP_SHIFT	12	/* fixed-point shift */

/* red parameters for drop probability */
#define	INV_P_MAX	10	/* inverse of max drop probability */
#define	TH_MIN		 5	/* min threshold */
#define	TH_MAX		15	/* max threshold */

#define	RIO_LIMIT	60	/* default max queue lenght */

/* default rio parameter values */
static struct redparams default_rio_params[RIO_NDROPPREC] = {
  /* th_min,		 th_max,     inv_pmax */
  { TH_MAX * 2 + TH_MIN, TH_MAX * 3, INV_P_MAX }, /* low drop precedence */
  { TH_MAX + TH_MIN,	 TH_MAX * 2, INV_P_MAX }, /* medium drop precedence */
  { TH_MIN,		 TH_MAX,     INV_P_MAX }  /* high drop precedence */
};

#define	RIO_ZONE_MAX	32		/* maximum elements in zone */
#define	RIO_ZONE_NAME	"classq_rio"	/* zone name */

static unsigned int rio_size;		/* size of zone element */
static struct zone *rio_zone;		/* zone for rio */

/* internal function prototypes */
static struct mbuf *rio_getq_flow(struct rio *, class_queue_t *,
    u_int32_t, boolean_t);
static int dscp2index(u_int8_t);

void
rio_init(void)
{
	_CASSERT(RIOF_ECN4 == CLASSQF_ECN4);
	_CASSERT(RIOF_ECN6 == CLASSQF_ECN6);

	rio_size = sizeof (rio_t);
	rio_zone = zinit(rio_size, RIO_ZONE_MAX * rio_size,
	    0, RIO_ZONE_NAME);
	if (rio_zone == NULL) {
		panic("%s: failed allocating %s", __func__, RIO_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(rio_zone, Z_EXPAND, TRUE);
	zone_change(rio_zone, Z_CALLERACCT, TRUE);
}

rio_t *
rio_alloc(struct ifnet *ifp, int weight, struct redparams *params,
    int flags, int pkttime)
{
	rio_t	*rp;
	int	 w, i;
	int	 npkts_per_sec;

	VERIFY(ifp != NULL);

	rp = zalloc(rio_zone);
	if (rp == NULL)
		return (NULL);

	bzero(rp, rio_size);
	rp->rio_ifp = ifp;
	rp->rio_flags = (flags & RIOF_USERFLAGS);
#if !PF_ECN
	if (rp->rio_flags & RIOF_ECN) {
		rp->rio_flags &= ~RIOF_ECN;
		log(LOG_ERR, "%s: RIO ECN not available; ignoring "
		    "RIOF_ECN flag!\n", if_name(ifp));
	}
	if (rp->rio_flags & RIOF_CLEARDSCP) {
		rp->rio_flags &= ~RIOF_CLEARDSCP;
		log(LOG_ERR, "%s: RIO ECN not available; ignoring "
		    "RIOF_CLEARDSCP flag!\n", if_name(ifp));
	}
#endif /* !PF_ECN */

	if (pkttime == 0)
		/* default packet time: 1000 bytes / 10Mbps * 8 * 1000000 */
		rp->rio_pkttime = 800;
	else
		rp->rio_pkttime = pkttime;

	if (weight != 0)
		rp->rio_weight = weight;
	else {
		/* use default */
		rp->rio_weight = W_WEIGHT;

		/* when the link is very slow, adjust red parameters */
		npkts_per_sec = 1000000 / rp->rio_pkttime;
		if (npkts_per_sec < 50) {
			/* up to about 400Kbps */
			rp->rio_weight = W_WEIGHT_2;
		} else if (npkts_per_sec < 300) {
			/* up to about 2.4Mbps */
			rp->rio_weight = W_WEIGHT_1;
		}
	}

	/* calculate wshift.  weight must be power of 2 */
	w = rp->rio_weight;
	for (i = 0; w > 1; i++)
		w = w >> 1;
	rp->rio_wshift = i;
	w = 1 << rp->rio_wshift;
	if (w != rp->rio_weight) {
		printf("invalid weight value %d for red! use %d\n",
		    rp->rio_weight, w);
		rp->rio_weight = w;
	}

	/* allocate weight table */
	rp->rio_wtab = wtab_alloc(rp->rio_weight);
	if (rp->rio_wtab == NULL) {
		rio_destroy(rp);
		return (NULL);
	}

	for (i = 0; i < RIO_NDROPPREC; i++) {
		struct dropprec_state *prec = &rp->rio_precstate[i];

		prec->avg = 0;
		prec->idle = 1;

		if (params == NULL || params[i].inv_pmax == 0)
			prec->inv_pmax = default_rio_params[i].inv_pmax;
		else
			prec->inv_pmax = params[i].inv_pmax;
		if (params == NULL || params[i].th_min == 0)
			prec->th_min = default_rio_params[i].th_min;
		else
			prec->th_min = params[i].th_min;
		if (params == NULL || params[i].th_max == 0)
			prec->th_max = default_rio_params[i].th_max;
		else
			prec->th_max = params[i].th_max;

		/*
		 * th_min_s and th_max_s are scaled versions of th_min
		 * and th_max to be compared with avg.
		 */
		prec->th_min_s = prec->th_min << (rp->rio_wshift + FP_SHIFT);
		prec->th_max_s = prec->th_max << (rp->rio_wshift + FP_SHIFT);

		/*
		 * precompute probability denominator
		 *  probd = (2 * (TH_MAX-TH_MIN) / pmax) in fixed-point
		 */
		prec->probd = (2 * (prec->th_max - prec->th_min) *
		    prec->inv_pmax) << FP_SHIFT;

		microuptime(&prec->last);
	}

	return (rp);
}

void
rio_destroy(rio_t *rp)
{
	if (rp->rio_wtab != NULL) {
		wtab_destroy(rp->rio_wtab);
		rp->rio_wtab = NULL;
	}
	zfree(rio_zone, rp);
}

void
rio_getstats(rio_t *rp, struct red_stats *sp)
{
	int	i;

	for (i = 0; i < RIO_NDROPPREC; i++) {
		bcopy(&rp->q_stats[i], sp, sizeof (struct red_stats));
		sp->q_avg = rp->rio_precstate[i].avg >> rp->rio_wshift;
		sp++;
	}
}

#if (RIO_NDROPPREC == 3)
/*
 * internally, a drop precedence value is converted to an index
 * starting from 0.
 */
static int
dscp2index(u_int8_t dscp)
{
#define	AF_DROPPRECMASK	0x18

	int	dpindex = dscp & AF_DROPPRECMASK;

	if (dpindex == 0)
		return (0);
	return ((dpindex >> 3) - 1);
}
#endif

/* Store RIO precindex in the module private scratch space */
#define	pkt_precidx	pkt_mpriv.__mpriv_u.__mpriv32[0].__mpriv32_u.__val32

#define	RIOM_SET_PRECINDEX(pkt, idx) do {		\
	(pkt)->pkt_precidx = (idx);			\
} while (0)

#define	RIOM_GET_PRECINDEX(pkt)				\
	({ u_int32_t idx; idx = (pkt)->pkt_precidx;	\
	RIOM_SET_PRECINDEX(pkt, 0); idx; })

int
rio_addq(rio_t *rp, class_queue_t *q, struct mbuf *m, struct pf_mtag *tag)
{
#if !PF_ECN
#pragma unused(tag)
#endif /* !PF_ECN */
#define	DSCP_MASK	0xfc
	int			 avg, droptype;
	u_int8_t		 dsfield, odsfield;
	int			 dpindex, i, n, t;
	struct timeval		 now;
	struct dropprec_state	*prec;

#if PF_ECN
	dsfield = odsfield = read_dsfield(m, tag);
#else
	dsfield = odsfield = 0;
#endif /* !PF_ECN */
	dpindex = dscp2index(dsfield);

	/*
	 * update avg of the precedence states whose drop precedence
	 * is larger than or equal to the drop precedence of the packet
	 */
	now.tv_sec = 0;
	for (i = dpindex; i < RIO_NDROPPREC; i++) {
		prec = &rp->rio_precstate[i];
		avg = prec->avg;
		if (prec->idle) {
			prec->idle = 0;
			if (now.tv_sec == 0)
				microuptime(&now);
			t = (now.tv_sec - prec->last.tv_sec);
			if (t > 60)
				avg = 0;
			else {
				t = t * 1000000 +
				    (now.tv_usec - prec->last.tv_usec);
				n = t / rp->rio_pkttime;
				/* calculate (avg = (1 - Wq)^n * avg) */
				if (n > 0) {
					avg = (avg >> FP_SHIFT) *
					    pow_w(rp->rio_wtab, n);
				}
			}
		}

		/* run estimator. (avg is scaled by WEIGHT in fixed-point) */
		avg += (prec->qlen << FP_SHIFT) - (avg >> rp->rio_wshift);
		prec->avg = avg;		/* save the new value */
		/*
		 * count keeps a tally of arriving traffic that has not
		 * been dropped.
		 */
		prec->count++;
	}

	prec = &rp->rio_precstate[dpindex];
	avg = prec->avg;

	/* see if we drop early */
	droptype = DTYPE_NODROP;
	if (avg >= prec->th_min_s && prec->qlen > 1) {
		if (avg >= prec->th_max_s) {
			/* avg >= th_max: forced drop */
			droptype = DTYPE_FORCED;
		} else if (prec->old == 0) {
			/* first exceeds th_min */
			prec->count = 1;
			prec->old = 1;
		} else if (drop_early((avg - prec->th_min_s) >> rp->rio_wshift,
		    prec->probd, prec->count)) {
			/* unforced drop by red */
			droptype = DTYPE_EARLY;
		}
	} else {
		/* avg < th_min */
		prec->old = 0;
	}

	/*
	 * if the queue length hits the hard limit, it's a forced drop.
	 */
	if (droptype == DTYPE_NODROP && qlen(q) >= qlimit(q))
		droptype = DTYPE_FORCED;

	if (droptype != DTYPE_NODROP) {
		/* always drop incoming packet (as opposed to randomdrop) */
		for (i = dpindex; i < RIO_NDROPPREC; i++)
			rp->rio_precstate[i].count = 0;

		if (droptype == DTYPE_EARLY)
			rp->q_stats[dpindex].drop_unforced++;
		else
			rp->q_stats[dpindex].drop_forced++;

		IFCQ_CONVERT_LOCK(&rp->rio_ifp->if_snd);
		m_freem(m);
		return (CLASSQEQ_DROPPED);
	}

	for (i = dpindex; i < RIO_NDROPPREC; i++)
		rp->rio_precstate[i].qlen++;

	/* save drop precedence index in mbuf hdr */
	RIOM_SET_PRECINDEX(&m->m_pkthdr, dpindex);

	if (rp->rio_flags & RIOF_CLEARDSCP)
		dsfield &= ~DSCP_MASK;

#if PF_ECN
	if (dsfield != odsfield)
		write_dsfield(m, tag, dsfield);
#endif /* PF_ECN */

	_addq(q, m);

	return (CLASSQEQ_SUCCESS);
}

static struct mbuf *
rio_getq_flow(struct rio *rp, class_queue_t *q, u_int32_t flow, boolean_t purge)
{
#pragma unused(purge)
	struct mbuf *m;
	int dpindex, i;

	/* flow of 0 means head of queue */
	if ((m = ((flow == 0) ? _getq(q) : _getq_flow(q, flow))) == NULL)
		return (NULL);

	VERIFY(m->m_flags & M_PKTHDR);

	dpindex = RIOM_GET_PRECINDEX(&m->m_pkthdr);
	for (i = dpindex; i < RIO_NDROPPREC; i++) {
		if (--rp->rio_precstate[i].qlen == 0) {
			if (rp->rio_precstate[i].idle == 0) {
				rp->rio_precstate[i].idle = 1;
				microuptime(&rp->rio_precstate[i].last);
			}
		}
	}
	return (m);
}

struct mbuf *
rio_getq(rio_t *rp, class_queue_t *q)
{
	return (rio_getq_flow(rp, q, 0, FALSE));
}

void
rio_purgeq(struct rio *rp, class_queue_t *q, u_int32_t flow, u_int32_t *packets,
    u_int32_t *bytes)
{
	u_int32_t cnt = 0, len = 0;
	struct mbuf *m;

	IFCQ_CONVERT_LOCK(&rp->rio_ifp->if_snd);

	while ((m = rio_getq_flow(rp, q, flow, TRUE)) != NULL) {
		cnt++;
		len += m_pktlen(m);
		m_freem(m);
	}

	if (packets != NULL)
		*packets = cnt;
	if (bytes != NULL)
		*bytes = len;
}

void
rio_updateq(rio_t *rp, cqev_t ev)
{
#pragma unused(rp, ev)
	/* nothing for now */
}

int
rio_suspendq(rio_t *rp, class_queue_t *q, boolean_t on)
{
#pragma unused(rp, q, on)
	return (ENOTSUP);
}
#endif /* CLASSQ_RIO */
