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

/*	$OpenBSD: altq_priq.c,v 1.21 2007/09/13 20:40:02 chl Exp $	*/
/*	$KAME: altq_priq.c,v 1.1 2000/10/18 09:15:23 kjc Exp $	*/

/*
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

/*
 * priority queue
 */

#if PF_ALTQ && PKTSCHED_PRIQ

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
#include <net/altq/altq_priq.h>
#include <netinet/in.h>

/*
 * function prototypes
 */
static int altq_priq_enqueue(struct ifaltq *, struct mbuf *);
static struct mbuf *altq_priq_dequeue(struct ifaltq *, enum altdq_op);
static int altq_priq_request(struct ifaltq *, enum altrq, void *);

int
altq_priq_pfattach(struct pf_altq *a)
{
	struct ifnet *ifp;
	int error;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((ifp = ifunit(a->ifname)) == NULL || a->altq_disc == NULL)
		return (EINVAL);

	IFCQ_LOCK(&ifp->if_snd);
	error = altq_attach(IFCQ_ALTQ(&ifp->if_snd), ALTQT_PRIQ, a->altq_disc,
	    altq_priq_enqueue, altq_priq_dequeue, NULL, altq_priq_request);
	IFCQ_UNLOCK(&ifp->if_snd);

	return (error);
}

int
altq_priq_add(struct pf_altq *a)
{
	struct priq_if	*pif;
	struct ifnet	*ifp;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((ifp = ifunit(a->ifname)) == NULL)
		return (EINVAL);
	if (!ALTQ_IS_READY(IFCQ_ALTQ(&ifp->if_snd)))
		return (ENODEV);

	pif = priq_alloc(ifp, M_WAITOK, TRUE);
	if (pif == NULL)
		return (ENOMEM);

	/* keep the state in pf_altq */
	a->altq_disc = pif;

	return (0);
}

int
altq_priq_remove(struct pf_altq *a)
{
	struct priq_if *pif;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((pif = a->altq_disc) == NULL)
		return (EINVAL);
	a->altq_disc = NULL;

	return (priq_destroy(pif));
}

int
altq_priq_add_queue(struct pf_altq *a)
{
	struct priq_if *pif;
	int err;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((pif = a->altq_disc) == NULL)
		return (EINVAL);

	IFCQ_LOCK(pif->pif_ifq);
	err = priq_add_queue(pif, a->priority, a->qlimit,
	    a->pq_u.priq_opts.flags, a->qid, NULL);
	IFCQ_UNLOCK(pif->pif_ifq);

	return (err);
}

int
altq_priq_remove_queue(struct pf_altq *a)
{
	struct priq_if *pif;
	int err;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((pif = a->altq_disc) == NULL)
		return (EINVAL);

	IFCQ_LOCK(pif->pif_ifq);
	err = priq_remove_queue(pif, a->qid);
	IFCQ_UNLOCK(pif->pif_ifq);

	return (err);
}

int
altq_priq_getqstats(struct pf_altq *a, void *ubuf, int *nbytes)
{
	struct ifclassq *ifq = NULL;
	struct priq_if *pif;
	struct priq_classstats stats;
	int error = 0;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((unsigned)*nbytes < sizeof (stats))
		return (EINVAL);

	if ((pif = altq_lookup(a->ifname, ALTQT_PRIQ)) == NULL)
		return (EBADF);

	ifq = pif->pif_ifq;
	IFCQ_LOCK_ASSERT_HELD(ifq);	/* lock held by altq_lookup */
	error = priq_get_class_stats(pif, a->qid, &stats);
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
altq_priq_request(struct ifaltq *altq, enum altrq req, void *arg)
{
	struct priq_if	*pif = (struct priq_if *)altq->altq_disc;

	switch (req) {
	case ALTRQ_PURGE:
		priq_purge(pif);
		break;

	case ALTRQ_PURGE_SC:
	case ALTRQ_THROTTLE:
		/* not supported for ALTQ instance */
		break;

	case ALTRQ_EVENT:
		priq_event(pif, (cqev_t)arg);
		break;
	}
	return (0);
}

/*
 * altq_priq_enqueue is an enqueue function to be registered to
 * (*altq_enqueue) in struct ifaltq.
 */
static int
altq_priq_enqueue(struct ifaltq *altq, struct mbuf *m)
{
	/* grab class set by classifier */
	if (!(m->m_flags & M_PKTHDR)) {
		/* should not happen */
		printf("%s: packet for %s does not have pkthdr\n", __func__,
		    if_name(altq->altq_ifcq->ifcq_ifp));
		m_freem(m);
		return (ENOBUFS);
	}

	return (priq_enqueue(altq->altq_disc, NULL, m, m_pftag(m)));
}

/*
 * altq_priq_dequeue is a dequeue function to be registered to
 * (*altq_dequeue) in struct ifaltq.
 *
 * note: ALTDQ_POLL returns the next packet without removing the packet
 *	from the queue.  ALTDQ_REMOVE is a normal dequeue operation.
 *	ALTDQ_REMOVE must return the same packet if called immediately
 *	after ALTDQ_POLL.
 */
static struct mbuf *
altq_priq_dequeue(struct ifaltq *altq, enum altdq_op op)
{
	return (priq_dequeue(altq->altq_disc, (cqdq_op_t)op));
}
#endif /* PF_ALTQ && PKTSCHED_PRIQ */
