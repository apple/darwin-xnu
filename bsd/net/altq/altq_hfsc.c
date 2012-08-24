/*
 * Copyright (c) 2007-2011 Apple Inc. All rights reserved.
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

/*	$OpenBSD: altq_hfsc.c,v 1.25 2007/09/13 20:40:02 chl Exp $	*/
/*	$KAME: altq_hfsc.c,v 1.17 2002/11/29 07:48:33 kjc Exp $	*/

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

#include <sys/cdefs.h>

#if PF_ALTQ && PKTSCHED_HFSC

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
#include <net/altq/altq_hfsc.h>
#include <netinet/in.h>

/*
 * function prototypes
 */
static int altq_hfsc_request(struct ifaltq *, enum altrq, void *);
static int altq_hfsc_enqueue(struct ifaltq *, struct mbuf *);
static struct mbuf *altq_hfsc_dequeue(struct ifaltq *, enum altdq_op);

int
altq_hfsc_pfattach(struct pf_altq *a)
{
	struct ifnet *ifp;
	int error;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((ifp = ifunit(a->ifname)) == NULL || a->altq_disc == NULL)
		return (EINVAL);

	IFCQ_LOCK(&ifp->if_snd);
	error = altq_attach(IFCQ_ALTQ(&ifp->if_snd), ALTQT_HFSC, a->altq_disc,
	    altq_hfsc_enqueue, altq_hfsc_dequeue, NULL, altq_hfsc_request);
	IFCQ_UNLOCK(&ifp->if_snd);

	return (error);
}

int
altq_hfsc_add(struct pf_altq *a)
{
	struct hfsc_if *hif;
	struct ifnet *ifp;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((ifp = ifunit(a->ifname)) == NULL)
		return (EINVAL);
	if (!ALTQ_IS_READY(IFCQ_ALTQ(&ifp->if_snd)))
		return (ENODEV);

	hif = hfsc_alloc(ifp, M_WAITOK, TRUE);
	if (hif == NULL)
		return (ENOMEM);

	/* keep the state in pf_altq */
	a->altq_disc = hif;

	return (0);
}

int
altq_hfsc_remove(struct pf_altq *a)
{
	struct hfsc_if *hif;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((hif = a->altq_disc) == NULL)
		return (EINVAL);
	a->altq_disc = NULL;

	return (hfsc_destroy(hif));
}

int
altq_hfsc_add_queue(struct pf_altq *a)
{
	struct hfsc_if *hif;
	struct hfsc_opts *opts = &a->pq_u.hfsc_opts;
	struct service_curve rtsc, lssc, ulsc;
	int err;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((hif = a->altq_disc) == NULL)
		return (EINVAL);

	bzero(&rtsc, sizeof (rtsc));
	bzero(&lssc, sizeof (lssc));
	bzero(&ulsc, sizeof (ulsc));

	rtsc.m1 = opts->rtsc_m1;
	rtsc.d  = opts->rtsc_d;
	rtsc.m2 = opts->rtsc_m2;
	rtsc.fl = opts->rtsc_fl;
	lssc.m1 = opts->lssc_m1;
	lssc.d  = opts->lssc_d;
	lssc.m2 = opts->lssc_m2;
	lssc.fl = opts->lssc_fl;
	ulsc.m1 = opts->ulsc_m1;
	ulsc.d  = opts->ulsc_d;
	ulsc.m2 = opts->ulsc_m2;
	ulsc.fl = opts->ulsc_fl;

	IFCQ_LOCK(hif->hif_ifq);
	err = hfsc_add_queue(hif, &rtsc, &lssc, &ulsc, a->qlimit,
	    opts->flags, a->parent_qid, a->qid, NULL);
	IFCQ_UNLOCK(hif->hif_ifq);

	return (err);
}

int
altq_hfsc_remove_queue(struct pf_altq *a)
{
	struct hfsc_if *hif;
	int err;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((hif = a->altq_disc) == NULL)
		return (EINVAL);

	IFCQ_LOCK(hif->hif_ifq);
	err = hfsc_remove_queue(hif, a->qid);
	IFCQ_UNLOCK(hif->hif_ifq);

	return (err);
}

int
altq_hfsc_getqstats(struct pf_altq *a, void *ubuf, int *nbytes)
{
	struct ifclassq *ifq = NULL;
	struct hfsc_if *hif;
	struct hfsc_classstats stats;
	int error = 0;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((unsigned)*nbytes < sizeof (stats))
		return (EINVAL);

	if ((hif = altq_lookup(a->ifname, ALTQT_HFSC)) == NULL)
		return (EBADF);

	ifq = hif->hif_ifq;
	IFCQ_LOCK_ASSERT_HELD(ifq);	/* lock held by altq_lookup */
	error = hfsc_get_class_stats(hif, a->qid, &stats);
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
altq_hfsc_request(struct ifaltq *altq, enum altrq req, void *arg)
{
	struct hfsc_if	*hif = (struct hfsc_if *)altq->altq_disc;

	switch (req) {
	case ALTRQ_PURGE:
		hfsc_purge(hif);
		break;

	case ALTRQ_PURGE_SC:
		/* not supported for ALTQ instance */
		break;

	case ALTRQ_EVENT:
		hfsc_event(hif, (cqev_t)arg);
		break;
	}
	return (0);
}

/*
 * altq_hfsc_enqueue is an enqueue function to be registered to
 * (*altq_enqueue) in struct ifaltq.
 */
static int
altq_hfsc_enqueue(struct ifaltq *altq, struct mbuf *m)
{
	/* grab class set by classifier */
	if (!(m->m_flags & M_PKTHDR)) {
		/* should not happen */
		printf("%s: packet for %s does not have pkthdr\n", __func__,
		    if_name(altq->altq_ifcq->ifcq_ifp));
		m_freem(m);
		return (ENOBUFS);
	}

	return (hfsc_enqueue(altq->altq_disc, NULL, m,  m_pftag(m)));
}

/*
 * altq_hfsc_dequeue is a dequeue function to be registered to
 * (*altq_dequeue) in struct ifaltq.
 *
 * note: ALTDQ_POLL returns the next packet without removing the packet
 *	from the queue.  ALTDQ_REMOVE is a normal dequeue operation.
 *	ALTDQ_REMOVE must return the same packet if called immediately
 *	after ALTDQ_POLL.
 */
static struct mbuf *
altq_hfsc_dequeue(struct ifaltq *altq, enum altdq_op op)
{
	return (hfsc_dequeue(altq->altq_disc, (cqdq_op_t)op));
}
#endif /* PF_ALTQ && PKTSCHED_HFSC */
