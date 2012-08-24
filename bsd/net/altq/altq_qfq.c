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

/*
 * quick fair queueing
 */

#if PF_ALTQ

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
#include <net/altq/altq_qfq.h>
#include <netinet/in.h>

/*
 * function prototypes
 */
static int altq_qfq_enqueue(struct ifaltq *, struct mbuf *);
static struct mbuf *altq_qfq_dequeue(struct ifaltq *, enum altdq_op);
static int altq_qfq_request(struct ifaltq *, enum altrq, void *);

int
altq_qfq_pfattach(struct pf_altq *a)
{
	struct ifnet *ifp;
	int error;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((ifp = ifunit(a->ifname)) == NULL || a->altq_disc == NULL)
		return (EINVAL);

	IFCQ_LOCK(&ifp->if_snd);
	error = altq_attach(IFCQ_ALTQ(&ifp->if_snd), ALTQT_QFQ, a->altq_disc,
	    altq_qfq_enqueue, altq_qfq_dequeue, NULL, altq_qfq_request);
	IFCQ_UNLOCK(&ifp->if_snd);

	return (error);
}

int
altq_qfq_add(struct pf_altq *a)
{
	struct qfq_if	*qif;
	struct ifnet	*ifp;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((ifp = ifunit(a->ifname)) == NULL)
		return (EINVAL);
	if (!ALTQ_IS_READY(IFCQ_ALTQ(&ifp->if_snd)))
		return (ENODEV);

	qif = qfq_alloc(ifp, M_WAITOK, TRUE);
	if (qif == NULL)
		return (ENOMEM);

	/* keep the state in pf_altq */
	a->altq_disc = qif;

	return (0);
}

int
altq_qfq_remove(struct pf_altq *a)
{
	struct qfq_if *qif;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((qif = a->altq_disc) == NULL)
		return (EINVAL);
	a->altq_disc = NULL;

	return (qfq_destroy(qif));
}

int
altq_qfq_add_queue(struct pf_altq *a)
{
	struct qfq_if *qif;
	int err;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((qif = a->altq_disc) == NULL)
		return (EINVAL);

	IFCQ_LOCK(qif->qif_ifq);
	err = qfq_add_queue(qif, a->qlimit, a->weight, a->pq_u.qfq_opts.lmax,
	    a->pq_u.qfq_opts.flags, a->qid, NULL);
	IFCQ_UNLOCK(qif->qif_ifq);

	return (err);
}

int
altq_qfq_remove_queue(struct pf_altq *a)
{
	struct qfq_if *qif;
	int err;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((qif = a->altq_disc) == NULL)
		return (EINVAL);

	IFCQ_LOCK(qif->qif_ifq);
	err = qfq_remove_queue(qif, a->qid);
	IFCQ_UNLOCK(qif->qif_ifq);

	return (err);
}

int
altq_qfq_getqstats(struct pf_altq *a, void *ubuf, int *nbytes)
{
	struct ifclassq *ifq = NULL;
	struct qfq_if *qif;
	struct qfq_classstats stats;
	int error = 0;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((unsigned)*nbytes < sizeof (stats))
		return (EINVAL);

	if ((qif = altq_lookup(a->ifname, ALTQT_QFQ)) == NULL)
		return (EBADF);

	ifq = qif->qif_ifq;
	IFCQ_LOCK_ASSERT_HELD(ifq);	/* lock held by altq_lookup */
	error = qfq_get_class_stats(qif, a->qid, &stats);
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
altq_qfq_request(struct ifaltq *altq, enum altrq req, void *arg)
{
	struct qfq_if	*qif = (struct qfq_if *)altq->altq_disc;

	switch (req) {
	case ALTRQ_PURGE:
		qfq_purge(qif);
		break;

	case ALTRQ_PURGE_SC:
		/* not supported for ALTQ instance */
		break;

	case ALTRQ_EVENT:
		qfq_event(qif, (cqev_t)arg);
		break;
	}
	return (0);
}

/*
 * altq_qfq_enqueue is an enqueue function to be registered to
 * (*altq_enqueue) in struct ifaltq.
 */
static int
altq_qfq_enqueue(struct ifaltq *altq, struct mbuf *m)
{
	/* grab class set by classifier */
	if (!(m->m_flags & M_PKTHDR)) {
		/* should not happen */
		printf("%s: packet for %s does not have pkthdr\n", __func__,
		    if_name(altq->altq_ifcq->ifcq_ifp));
		m_freem(m);
		return (ENOBUFS);
	}

	return (qfq_enqueue(altq->altq_disc, NULL, m, m_pftag(m)));
}

/*
 * altq_qfq_dequeue is a dequeue function to be registered to
 * (*altq_dequeue) in struct ifaltq.
 *
 * note: ALTDQ_POLL returns the next packet without removing the packet
 *	from the queue.  ALTDQ_REMOVE is a normal dequeue operation.
 *	ALTDQ_REMOVE must return the same packet if called immediately
 *	after ALTDQ_POLL.
 */
static struct mbuf *
altq_qfq_dequeue(struct ifaltq *altq, enum altdq_op op)
{
	return (qfq_dequeue(altq->altq_disc, (cqdq_op_t)op));
}
#endif /* PF_ALTQ */
