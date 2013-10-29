/*
 * Copyright (c) 2011-2013 Apple Inc. All rights reserved.
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
 * $DragonFly: src/sys/net/altq/altq_fairq.c,v 1.2 2008/05/14 11:59:23 sephe Exp $
 */
/*
 * Matt: I gutted altq_priq.c and used it as a skeleton on which to build
 * fairq.  The fairq algorithm is completely different then priq, of course,
 * but because I used priq's skeleton I believe I should include priq's
 * copyright.
 *
 * Copyright (C) 2000-2003
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

#if PF_ALTQ && PKTSCHED_FAIRQ

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kernel.h>

#include <net/if.h>
#include <net/pfvar.h>
#include <net/net_osdep.h>
#include <net/altq/altq.h>
#include <net/altq/altq_fairq.h>
#include <netinet/in.h>

/*
 * function prototypes
 */
static int altq_fairq_enqueue(struct ifaltq *, struct mbuf *);
static struct mbuf *altq_fairq_dequeue(struct ifaltq *, enum altdq_op);
static int altq_fairq_request(struct ifaltq *, enum altrq, void *);

int
altq_fairq_pfattach(struct pf_altq *a)
{
	struct ifnet *ifp;
	int error;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((ifp = ifunit(a->ifname)) == NULL || a->altq_disc == NULL)
		return (EINVAL);

	IFCQ_LOCK(&ifp->if_snd);
	error = altq_attach(IFCQ_ALTQ(&ifp->if_snd), ALTQT_FAIRQ, a->altq_disc,
	    altq_fairq_enqueue, altq_fairq_dequeue, NULL, altq_fairq_request);
	IFCQ_UNLOCK(&ifp->if_snd);

	return (error);
}

int
altq_fairq_add(struct pf_altq *a)
{
	struct fairq_if *fif;
	struct ifnet *ifp;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((ifp = ifunit(a->ifname)) == NULL)
		return (EINVAL);
	if (!ALTQ_IS_READY(IFCQ_ALTQ(&ifp->if_snd)))
		return (ENODEV);

	fif = fairq_alloc(ifp, M_WAITOK, TRUE);
	if (fif == NULL)
		return (ENOMEM);

	/* keep the state in pf_altq */
	a->altq_disc = fif;

	return (0);
}

int
altq_fairq_remove(struct pf_altq *a)
{
	struct fairq_if *fif;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((fif = a->altq_disc) == NULL)
		return (EINVAL);
	a->altq_disc = NULL;

	return (fairq_destroy(fif));
}

int
altq_fairq_add_queue(struct pf_altq *a)
{
	struct fairq_if *fif;
	struct fairq_opts *opts = &a->pq_u.fairq_opts;
	int err;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((fif = a->altq_disc) == NULL)
		return (EINVAL);

	IFCQ_LOCK(fif->fif_ifq);
	err = fairq_add_queue(fif, a->priority, a->qlimit, a->bandwidth,
	    opts->nbuckets, opts->flags, opts->hogs_m1, opts->lssc_m1,
	    opts->lssc_d, opts->lssc_m2, a->qid, NULL);
	IFCQ_UNLOCK(fif->fif_ifq);

	return (err);
}

int
altq_fairq_remove_queue(struct pf_altq *a)
{
	struct fairq_if *fif;
	int err;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((fif = a->altq_disc) == NULL)
		return (EINVAL);

	IFCQ_LOCK(fif->fif_ifq);
	err = fairq_remove_queue(fif, a->qid);
	IFCQ_UNLOCK(fif->fif_ifq);

	return (err);
}

int
altq_fairq_getqstats(struct pf_altq *a, void *ubuf, int *nbytes)
{
	struct ifclassq *ifq = NULL;
	struct fairq_if *fif;
	struct fairq_classstats stats;
	int error = 0;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((unsigned)*nbytes < sizeof (stats))
		return (EINVAL);

	if ((fif = altq_lookup(a->ifname, ALTQT_FAIRQ)) == NULL)
		return (EBADF);

	ifq = fif->fif_ifq;
	IFCQ_LOCK_ASSERT_HELD(ifq);	/* lock held by altq_lookup */
	error = fairq_get_class_stats(fif, a->qid, &stats);
	IFCQ_UNLOCK(ifq);
	if (error != 0)
		return (error);

	if ((error = copyout((caddr_t)&stats, (user_addr_t)(uintptr_t)ubuf,
	    sizeof (stats))) != 0)
		return (error);

	*nbytes = sizeof (stats);

	return (0);
}

static int
altq_fairq_request(struct ifaltq *altq, enum altrq req, void *arg)
{
	struct fairq_if *fif = (struct fairq_if *)altq->altq_disc;

	switch (req) {
	case ALTRQ_PURGE:
		fairq_purge(fif);
		break;

	case ALTRQ_PURGE_SC:
		/* not supported for ALTQ instance */
		break;

	case ALTRQ_EVENT:
		fairq_event(fif, (cqev_t)arg);
		break;

	case ALTRQ_THROTTLE:
	default:
		break;
	}
	return (0);
}

/*
 * altq_fairq_enqueue is an enqueue function to be registered to
 * (*altq_enqueue) in struct ifaltq.
 */
static int
altq_fairq_enqueue(struct ifaltq *altq, struct mbuf *m)
{
	/* grab class set by classifier */
	if (!(m->m_flags & M_PKTHDR)) {
		/* should not happen */
		printf("%s: packet for %s does not have pkthdr\n", __func__,
		    if_name(altq->altq_ifcq->ifcq_ifp));
		m_freem(m);
		return (ENOBUFS);
	}

	return (fairq_enqueue(altq->altq_disc, NULL, m, m_pftag(m)));
}

/*
 * altq_fairq_dequeue is a dequeue function to be registered to
 * (*altq_dequeue) in struct ifaltq.
 *
 * note: ALTDQ_POLL returns the next packet without removing the packet
 *	from the queue.  ALTDQ_REMOVE is a normal dequeue operation.
 *	ALTDQ_REMOVE must return the same packet if called immediately
 *	after ALTDQ_POLL.
 */
static struct mbuf *
altq_fairq_dequeue(struct ifaltq *altq, enum altdq_op op)
{
	return (fairq_dequeue(altq->altq_disc, (cqdq_op_t)op));
}
#endif /* PF_ALTQ && PKTSCHED_FAIRQ */
