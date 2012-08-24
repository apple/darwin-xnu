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

/*	$NetBSD: altq_blue.c,v 1.21 2006/11/16 01:32:37 christos Exp $	*/
/*	$KAME: altq_blue.c,v 1.15 2005/04/13 03:44:24 suz Exp $	*/

/*
 * Copyright (C) 1997-2002
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

#if CLASSQ_BLUE

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/kauth.h>

#include <kern/zalloc.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if INET6
#include <netinet/ip6.h>
#endif

#include <net/classq/classq_blue.h>
#include <net/net_osdep.h>

/*
 * Blue is proposed and implemented by Wu-chang Feng <wuchang@eecs.umich.edu>.
 * more information on Blue is available from
 * http://www.eecs.umich.edu/~wuchang/blue/
 */

#define	BLUE_LIMIT	200		/* default max queue lenght */

#define	BLUE_ZONE_MAX	32		/* maximum elements in zone */
#define	BLUE_ZONE_NAME	"classq_blue"	/* zone name */

static unsigned int blue_size;		/* size of zone element */
static struct zone *blue_zone;		/* zone for blue */

/* internal function prototypes */
static struct mbuf *blue_getq_flow(struct blue *, class_queue_t *,
    u_int32_t, boolean_t);
static int blue_drop_early(struct blue *);

void
blue_init(void)
{
	_CASSERT(BLUEF_ECN4 == CLASSQF_ECN4);
	_CASSERT(BLUEF_ECN6 == CLASSQF_ECN6);

	blue_size = sizeof (struct blue);
	blue_zone = zinit(blue_size, BLUE_ZONE_MAX * blue_size,
	    0, BLUE_ZONE_NAME);
	if (blue_zone == NULL) {
		panic("%s: failed allocating %s", __func__, BLUE_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(blue_zone, Z_EXPAND, TRUE);
	zone_change(blue_zone, Z_CALLERACCT, TRUE);
}

/*
 * blue support routines
 */
struct blue *
blue_alloc(struct ifnet *ifp, u_int32_t max_pmark, u_int32_t hold_time,
    u_int32_t flags)
{
	struct blue *bp;

	VERIFY(ifp != NULL);

	bp = zalloc(blue_zone);
	if (bp == NULL)
		return (NULL);

	bzero(bp, blue_size);
	bp->blue_idle = 1;
	bp->blue_flags = (flags & BLUEF_USERFLAGS);
	bp->blue_ifp = ifp;

	if (max_pmark == 0)
		bp->blue_max_pmark = 1000;
	else
		bp->blue_max_pmark = max_pmark;

	if (hold_time == 0)
		bp->blue_hold_time = 50000;
	else
		bp->blue_hold_time = hold_time;

	microuptime(&bp->blue_last);

	return (bp);
}

void
blue_destroy(struct blue *bp)
{
	zfree(blue_zone, bp);
}

void
blue_getstats(struct blue *bp, struct blue_stats *sp)
{
	sp->q_pmark		= bp->blue_pmark;
	sp->drop_forced		= bp->blue_stats.drop_forced;
	sp->drop_unforced	= bp->blue_stats.drop_unforced;
	sp->marked_packets	= bp->blue_stats.marked_packets;
}

#define	DTYPE_NODROP	0	/* no drop */
#define	DTYPE_FORCED	1	/* a "forced" drop */
#define	DTYPE_EARLY	2	/* an "unforced" (early) drop */

int
blue_addq(struct blue *bp, class_queue_t *q, struct mbuf *m,
    struct pf_mtag *tag)
{
	int droptype;

	/*
	 * if we were idle, this is an enqueue onto an empty queue
	 * and we should decrement marking probability
	 */
	if (bp->blue_idle) {
		struct timeval now;
		u_int32_t t;

		bp->blue_idle = 0;
		microuptime(&now);
		t = (now.tv_sec - bp->blue_last.tv_sec);
		if (t > 1) {
			bp->blue_pmark = 1;
			microuptime(&bp->blue_last);
		} else {
			t = t * 1000000 + (now.tv_usec - bp->blue_last.tv_usec);
			if (t > bp->blue_hold_time) {
				bp->blue_pmark--;
				if (bp->blue_pmark < 0)
					bp->blue_pmark = 0;
				microuptime(&bp->blue_last);
			}
		}
	}

	/* see if we drop early */
	droptype = DTYPE_NODROP;
	if (blue_drop_early(bp) && qlen(q) > 1) {
		/* mark or drop by blue */
		if ((bp->blue_flags & BLUEF_ECN) &&
		    (tag->pftag_flags & PF_TAG_TCP) &&	/* only for TCP */
		    mark_ecn(m, tag, bp->blue_flags)) {
			/* successfully marked.  do not drop. */
			bp->blue_stats.marked_packets++;
		} else {
			/* unforced drop by blue */
			droptype = DTYPE_EARLY;
		}
	}

	/* if the queue length hits the hard limit, it's a forced drop */
	if (droptype == DTYPE_NODROP && qlen(q) >= qlimit(q))
		droptype = DTYPE_FORCED;

	/* if successful or forced drop, enqueue this packet. */
	if (droptype != DTYPE_EARLY)
		_addq(q, m);

	if (droptype != DTYPE_NODROP) {
		if (droptype == DTYPE_EARLY) {
			/* drop the incoming packet */
			bp->blue_stats.drop_unforced++;
		} else {
			struct timeval now;
			u_int32_t t;
			/* forced drop, select a victim packet in the queue. */
			m = _getq_random(q);
			microuptime(&now);
			t = (now.tv_sec - bp->blue_last.tv_sec);
			t = t * 1000000 + (now.tv_usec - bp->blue_last.tv_usec);
			if (t > bp->blue_hold_time) {
				bp->blue_pmark += bp->blue_max_pmark >> 3;
				if (bp->blue_pmark > bp->blue_max_pmark)
					bp->blue_pmark = bp->blue_max_pmark;
				microuptime(&bp->blue_last);
			}
			bp->blue_stats.drop_forced++;
		}
		IFCQ_CONVERT_LOCK(&bp->blue_ifp->if_snd);
		m_freem(m);
		return (CLASSQEQ_DROPPED);
	}
	/* successfully queued */
	return (CLASSQEQ_SUCCESS);
}

static struct mbuf *
blue_getq_flow(struct blue *bp, class_queue_t *q, u_int32_t flow,
    boolean_t purge)
{
#pragma unused(purge)
	struct mbuf *m;

	/* flow of 0 means head of queue */
	if ((m = ((flow == 0) ? _getq(q) : _getq_flow(q, flow))) == NULL) {
		if (bp->blue_idle == 0) {
			bp->blue_idle = 1;
			microuptime(&bp->blue_last);
		}
		return (NULL);
	}

	bp->blue_idle = 0;
	return (m);
}

struct mbuf *
blue_getq(struct blue *bp, class_queue_t *q)
{
	return (blue_getq_flow(bp, q, 0, FALSE));
}

void
blue_purgeq(struct blue *bp, class_queue_t *q, u_int32_t flow,
    u_int32_t *packets, u_int32_t *bytes)
{
	u_int32_t cnt = 0, len = 0;
	struct mbuf *m;

	IFCQ_CONVERT_LOCK(&bp->blue_ifp->if_snd);

	while ((m = blue_getq_flow(bp, q, flow, TRUE)) != NULL) {
		cnt++;
		len += m_pktlen(m);
		m_freem(m);
	}

	if (packets != NULL)
		*packets = cnt;
	if (bytes != NULL)
		*bytes = len;
}

/*
 * early-drop probability is kept in blue_pmark
 */
static int
blue_drop_early(struct blue *bp)
{
	if ((random() % (unsigned)bp->blue_max_pmark) <
	    (unsigned)bp->blue_pmark) {
		/* drop or mark */
		return (1);
	}
	/* no drop/mark */
	return (0);
}

void
blue_updateq(struct blue *bp, cqev_t ev)
{
#pragma unused(bp, ev)
	/* nothing for now */
}

int
blue_suspendq(struct blue *bp, class_queue_t *q, boolean_t on)
{
#pragma unused(bp, q, on)
	return (ENOTSUP);
}
#endif /* CLASSQ_BLUE */
