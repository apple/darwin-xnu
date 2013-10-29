/*
 * Copyright (c) 2007-2012 Apple Inc. All rights reserved.
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

/*	$OpenBSD: altq_red.c,v 1.14 2007/09/13 20:40:02 chl Exp $	*/
/*	$KAME: altq_red.c,v 1.10 2002/04/03 05:38:51 kjc Exp $	*/

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
 *
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

#if CLASSQ_RED

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/errno.h>
#include <sys/kauth.h>
#include <dev/random/randomdev.h>
#include <kern/zalloc.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if INET6
#include <netinet/ip6.h>
#endif

#include <net/classq/classq_red.h>
#include <net/net_osdep.h>

/*
 * ALTQ/RED (Random Early Detection) implementation using 32-bit
 * fixed-point calculation.
 *
 * written by kjc using the ns code as a reference.
 * you can learn more about red and ns from Sally's home page at
 * http://www-nrg.ee.lbl.gov/floyd/
 *
 * most of the red parameter values are fixed in this implementation
 * to prevent fixed-point overflow/underflow.
 * if you change the parameters, watch out for overflow/underflow!
 *
 * the parameters used are recommended values by Sally.
 * the corresponding ns config looks:
 *	q_weight=0.00195
 *	minthresh=5 maxthresh=15 queue-size=60
 *	linterm=30
 *	dropmech=drop-tail
 *	bytes=false (can't be handled by 32-bit fixed-point)
 *	doubleq=false dqthresh=false
 *	wait=true
 */
/*
 * alternative red parameters for a slow link.
 *
 * assume the queue length becomes from zero to L and keeps L, it takes
 * N packets for q_avg to reach 63% of L.
 * when q_weight is 0.002, N is about 500 packets.
 * for a slow link like dial-up, 500 packets takes more than 1 minute!
 * when q_weight is 0.008, N is about 127 packets.
 * when q_weight is 0.016, N is about 63 packets.
 * bursts of 50 packets are allowed for 0.002, bursts of 25 packets
 * are allowed for 0.016.
 * see Sally's paper for more details.
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
#define	TH_MIN		5	/* min threshold */
#define	TH_MAX		15	/* max threshold */

#define	RED_LIMIT	60	/* default max queue lenght */

#define	RED_ZONE_MAX	32		/* maximum elements in zone */
#define	RED_ZONE_NAME	"classq_red"	/* zone name */

static unsigned int red_size;		/* size of zone element */
static struct zone *red_zone;		/* zone for red */

/*
 * our default policy for forced-drop is drop-tail.
 * (in altq-1.1.2 or earlier, the default was random-drop.
 * but it makes more sense to punish the cause of the surge.)
 * to switch to the random-drop policy, define "RED_RANDOM_DROP".
 */

/* default red parameter values */
static int default_th_min = TH_MIN;
static int default_th_max = TH_MAX;
static int default_inv_pmax = INV_P_MAX;

static struct mbuf *red_getq_flow(struct red *, class_queue_t *,
    u_int32_t, boolean_t);

void
red_init(void)
{
	_CASSERT(REDF_ECN4 == CLASSQF_ECN4);
	_CASSERT(REDF_ECN6 == CLASSQF_ECN6);

	red_size = sizeof (red_t);
	red_zone = zinit(red_size, RED_ZONE_MAX * red_size,
	    0, RED_ZONE_NAME);
	if (red_zone == NULL) {
		panic("%s: failed allocating %s", __func__, RED_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(red_zone, Z_EXPAND, TRUE);
	zone_change(red_zone, Z_CALLERACCT, TRUE);
}

/*
 * red support routines
 */
red_t *
red_alloc(struct ifnet *ifp, int weight, int inv_pmax, int th_min,
    int th_max, int flags, int pkttime)
{
	red_t	*rp;
	int	 w, i;
	int	 npkts_per_sec;

	VERIFY(ifp != NULL);

	rp = zalloc(red_zone);
	if (rp == NULL)
		return (NULL);

	bzero(rp, red_size);
	rp->red_avg = 0;
	rp->red_idle = 1;

	if (weight == 0)
		rp->red_weight = W_WEIGHT;
	else
		rp->red_weight = weight;
	if (inv_pmax == 0)
		rp->red_inv_pmax = default_inv_pmax;
	else
		rp->red_inv_pmax = inv_pmax;
	if (th_min == 0)
		rp->red_thmin = default_th_min;
	else
		rp->red_thmin = th_min;
	if (th_max == 0)
		rp->red_thmax = default_th_max;
	else
		rp->red_thmax = th_max;

	rp->red_ifp = ifp;
	rp->red_flags = (flags & REDF_USERFLAGS);
#if !PF_ECN
	if (rp->red_flags & REDF_ECN) {
		rp->red_flags &= ~REDF_ECN;
		log(LOG_ERR, "%s: RED ECN not available; ignoring "
		    "REDF_ECN flag!\n", if_name(ifp));
	}
#endif /* !PF_ECN */

	if (pkttime == 0)
		/* default packet time: 1000 bytes / 10Mbps * 8 * 1000000 */
		rp->red_pkttime = 800;
	else
		rp->red_pkttime = pkttime;

	if (weight == 0) {
		/* when the link is very slow, adjust red parameters */
		npkts_per_sec = 1000000 / rp->red_pkttime;
		if (npkts_per_sec < 50) {
			/* up to about 400Kbps */
			rp->red_weight = W_WEIGHT_2;
		} else if (npkts_per_sec < 300) {
			/* up to about 2.4Mbps */
			rp->red_weight = W_WEIGHT_1;
		}
	}

	/* calculate wshift.  weight must be power of 2 */
	w = rp->red_weight;
	for (i = 0; w > 1; i++)
		w = w >> 1;
	rp->red_wshift = i;
	w = 1 << rp->red_wshift;
	if (w != rp->red_weight) {
		printf("invalid weight value %d for red! use %d\n",
		    rp->red_weight, w);
		rp->red_weight = w;
	}

	/*
	 * thmin_s and thmax_s are scaled versions of th_min and th_max
	 * to be compared with avg.
	 */
	rp->red_thmin_s = rp->red_thmin << (rp->red_wshift + FP_SHIFT);
	rp->red_thmax_s = rp->red_thmax << (rp->red_wshift + FP_SHIFT);

	/*
	 * precompute probability denominator
	 *  probd = (2 * (TH_MAX-TH_MIN) / pmax) in fixed-point
	 */
	rp->red_probd = (2 * (rp->red_thmax - rp->red_thmin) *
	    rp->red_inv_pmax) << FP_SHIFT;

	/* allocate weight table */
	rp->red_wtab = wtab_alloc(rp->red_weight);
	if (rp->red_wtab == NULL) {
		red_destroy(rp);
		return (NULL);
	}

	microuptime(&rp->red_last);
	return (rp);
}

void
red_destroy(red_t *rp)
{
	if (rp->red_wtab != NULL) {
		wtab_destroy(rp->red_wtab);
		rp->red_wtab = NULL;
	}
	zfree(red_zone, rp);
}

void
red_getstats(red_t *rp, struct red_stats *sp)
{
	sp->q_avg		= rp->red_avg >> rp->red_wshift;
	sp->drop_forced		= rp->red_stats.drop_forced;
	sp->drop_unforced	= rp->red_stats.drop_unforced;
	sp->marked_packets	= rp->red_stats.marked_packets;
}

int
red_addq(red_t *rp, class_queue_t *q, struct mbuf *m, struct pf_mtag *tag)
{
#if !PF_ECN
#pragma unused(tag)
#endif /* !PF_ECN */
	int avg, droptype;
	int n;

	avg = rp->red_avg;

	/*
	 * if we were idle, we pretend that n packets arrived during
	 * the idle period.
	 */
	if (rp->red_idle) {
		struct timeval now;
		int t;

		rp->red_idle = 0;
		microuptime(&now);
		t = (now.tv_sec - rp->red_last.tv_sec);
		if (t > 60) {
			/*
			 * being idle for more than 1 minute, set avg to zero.
			 * this prevents t from overflow.
			 */
			avg = 0;
		} else {
			t = t * 1000000 + (now.tv_usec - rp->red_last.tv_usec);
			n = t / rp->red_pkttime - 1;

			/* the following line does (avg = (1 - Wq)^n * avg) */
			if (n > 0)
				avg = (avg >> FP_SHIFT) *
				    pow_w(rp->red_wtab, n);
		}
	}

	/* run estimator. (note: avg is scaled by WEIGHT in fixed-point) */
	avg += (qlen(q) << FP_SHIFT) - (avg >> rp->red_wshift);
	rp->red_avg = avg;		/* save the new value */

	/*
	 * red_count keeps a tally of arriving traffic that has not
	 * been dropped.
	 */
	rp->red_count++;

	/* see if we drop early */
	droptype = DTYPE_NODROP;
	if (avg >= rp->red_thmin_s && qlen(q) > 1) {
		if (avg >= rp->red_thmax_s) {
			/* avg >= th_max: forced drop */
			droptype = DTYPE_FORCED;
		} else if (rp->red_old == 0) {
			/* first exceeds th_min */
			rp->red_count = 1;
			rp->red_old = 1;
		} else if (drop_early((avg - rp->red_thmin_s) >> rp->red_wshift,
		    rp->red_probd, rp->red_count)) {
			/* mark or drop by red */
#if PF_ECN
			if ((rp->red_flags & REDF_ECN) &&
			    (tag->pftag_proto == IPPROTO_TCP) && /* only TCP */
			    mark_ecn(m, tag, rp->red_flags)) {
				/* successfully marked.  do not drop. */
				rp->red_count = 0;
				rp->red_stats.marked_packets++;
			} else
#endif /* PF_ECN */
			{
				/* unforced drop by red */
				droptype = DTYPE_EARLY;
			}
		}
	} else {
		/* avg < th_min */
		rp->red_old = 0;
	}

	/*
	 * if the queue length hits the hard limit, it's a forced drop.
	 */
	if (droptype == DTYPE_NODROP && qlen(q) >= qlimit(q))
		droptype = DTYPE_FORCED;

#ifdef RED_RANDOM_DROP
	/* if successful or forced drop, enqueue this packet. */
	if (droptype != DTYPE_EARLY)
		_addq(q, m);
#else
	/* if successful, enqueue this packet. */
	if (droptype == DTYPE_NODROP)
		_addq(q, m);
#endif
	if (droptype != DTYPE_NODROP) {
		if (droptype == DTYPE_EARLY) {
			/* drop the incoming packet */
			rp->red_stats.drop_unforced++;
		} else {
			/* forced drop, select a victim packet in the queue. */
#ifdef RED_RANDOM_DROP
			m = _getq_random(q);
#endif
			rp->red_stats.drop_forced++;
		}
		rp->red_count = 0;
		IFCQ_CONVERT_LOCK(&rp->red_ifp->if_snd);
		m_freem(m);
		return (CLASSQEQ_DROPPED);
	}
	/* successfully queued */
	return (CLASSQEQ_SUCCESS);
}

/*
 * early-drop probability is calculated as follows:
 *   prob = p_max * (avg - th_min) / (th_max - th_min)
 *   prob_a = prob / (2 - count*prob)
 *	    = (avg-th_min) / (2*(th_max-th_min)*inv_p_max - count*(avg-th_min))
 * here prob_a increases as successive undrop count increases.
 * (prob_a starts from prob/2, becomes prob when (count == (1 / prob)),
 * becomes 1 when (count >= (2 / prob))).
 */
int
drop_early(int fp_len, int fp_probd, int count)
{
	int	d;		/* denominator of drop-probability */

	d = fp_probd - count * fp_len;
	if (d <= 0)
		/* count exceeds the hard limit: drop or mark */
		return (1);

	/*
	 * now the range of d is [1..600] in fixed-point. (when
	 * th_max-th_min=10 and p_max=1/30)
	 * drop probability = (avg - TH_MIN) / d
	 */

	if ((RandomULong() % d) < (unsigned)fp_len) {
		/* drop or mark */
		return (1);
	}
	/* no drop/mark */
	return (0);
}

static struct mbuf *
red_getq_flow(struct red *rp, class_queue_t *q, u_int32_t flow, boolean_t purge)
{
#pragma unused(purge)
	struct mbuf *m;

	/* flow of 0 means head of queue */
	if ((m = ((flow == 0) ? _getq(q) : _getq_flow(q, flow))) == NULL) {
		if (rp->red_idle == 0) {
			rp->red_idle = 1;
			microuptime(&rp->red_last);
		}
		return (NULL);
	}

	rp->red_idle = 0;
	return (m);
}

struct mbuf *
red_getq(red_t *rp, class_queue_t *q)
{
	return (red_getq_flow(rp, q, 0, FALSE));
}

void
red_purgeq(struct red *rp, class_queue_t *q, u_int32_t flow, u_int32_t *packets,
    u_int32_t *bytes)
{
	u_int32_t cnt = 0, len = 0;
	struct mbuf *m;

	IFCQ_CONVERT_LOCK(&rp->red_ifp->if_snd);

	while ((m = red_getq_flow(rp, q, flow, TRUE)) != NULL) {
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
red_updateq(red_t *rp, cqev_t ev)
{
#pragma unused(rp, ev)
	/* nothing for now */
}

int
red_suspendq(red_t *rp, class_queue_t *q, boolean_t on)
{
#pragma unused(rp, q, on)
	return (ENOTSUP);
}

/*
 * helper routine to calibrate avg during idle.
 * pow_w(wtab, n) returns (1 - Wq)^n in fixed-point
 * here Wq = 1/weight and the code assumes Wq is close to zero.
 *
 * w_tab[n] holds ((1 - Wq)^(2^n)) in fixed-point.
 */
static struct wtab *wtab_list = NULL;	/* pointer to wtab list */

struct wtab *
wtab_alloc(int weight)
{
	struct wtab	*w;
	int		 i;

	for (w = wtab_list; w != NULL; w = w->w_next)
		if (w->w_weight == weight) {
			w->w_refcount++;
			return (w);
		}

	w = _MALLOC(sizeof (struct wtab), M_DEVBUF, M_WAITOK|M_ZERO);
	if (w == NULL)
		return (NULL);

	w->w_weight = weight;
	w->w_refcount = 1;
	w->w_next = wtab_list;
	wtab_list = w;

	/* initialize the weight table */
	w->w_tab[0] = ((weight - 1) << FP_SHIFT) / weight;
	for (i = 1; i < 32; i++) {
		w->w_tab[i] = (w->w_tab[i-1] * w->w_tab[i-1]) >> FP_SHIFT;
		if (w->w_tab[i] == 0 && w->w_param_max == 0)
			w->w_param_max = 1 << i;
	}

	return (w);
}

void
wtab_destroy(struct wtab *w)
{
	struct wtab	*prev;

	if (--w->w_refcount > 0)
		return;

	if (wtab_list == w)
		wtab_list = w->w_next;
	else for (prev = wtab_list; prev->w_next != NULL; prev = prev->w_next)
		if (prev->w_next == w) {
			prev->w_next = w->w_next;
			break;
		}

	_FREE(w, M_DEVBUF);
}

int32_t
pow_w(struct wtab *w, int n)
{
	int	i, bit;
	int32_t	val;

	if (n >= w->w_param_max)
		return (0);

	val = 1 << FP_SHIFT;
	if (n <= 0)
		return (val);

	bit = 1;
	i = 0;
	while (n) {
		if (n & bit) {
			val = (val * w->w_tab[i]) >> FP_SHIFT;
			n &= ~bit;
		}
		i++;
		bit <<=  1;
	}
	return (val);
}

#endif /* CLASSQ_RED */
