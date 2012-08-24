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

/*	$OpenBSD: altq_cbq.c,v 1.23 2007/09/13 20:40:02 chl Exp $	*/
/*	$KAME: altq_cbq.c,v 1.9 2000/12/14 08:12:45 thorpej Exp $	*/

/*
 * Copyright (c) Sun Microsystems, Inc. 1993-1998 All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the SMCC Technology
 *      Development Group at Sun Microsystems, Inc.
 *
 * 4. The name of the Sun Microsystems, Inc nor may not be used to endorse or
 *      promote products derived from this software without specific prior
 *      written permission.
 *
 * SUN MICROSYSTEMS DOES NOT CLAIM MERCHANTABILITY OF THIS SOFTWARE OR THE
 * SUITABILITY OF THIS SOFTWARE FOR ANY PARTICULAR PURPOSE.  The software is
 * provided "as is" without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this software.
 */

#if PF_ALTQ && PKTSCHED_CBQ

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
#include <net/altq/altq_cbq.h>
#include <netinet/in.h>

/*
 * Forward Declarations.
 */
static int altq_cbq_request(struct ifaltq *, enum altrq, void *);
static int altq_cbq_enqueue(struct ifaltq *, struct mbuf *);
static struct mbuf *altq_cbq_dequeue(struct ifaltq *, enum altdq_op);

int
altq_cbq_pfattach(struct pf_altq *a)
{
	struct ifnet	*ifp;
	int		 error;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((ifp = ifunit(a->ifname)) == NULL || a->altq_disc == NULL)
		return (EINVAL);

	IFCQ_LOCK(&ifp->if_snd);
	error = altq_attach(IFCQ_ALTQ(&ifp->if_snd), ALTQT_CBQ, a->altq_disc,
	    altq_cbq_enqueue, altq_cbq_dequeue, NULL, altq_cbq_request);
	IFCQ_UNLOCK(&ifp->if_snd);

	return (error);
}

int
altq_cbq_add(struct pf_altq *a)
{
	cbq_state_t	*cbqp;
	struct ifnet	*ifp;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((ifp = ifunit(a->ifname)) == NULL)
		return (EINVAL);
	if (!ALTQ_IS_READY(IFCQ_ALTQ(&ifp->if_snd)))
		return (ENODEV);

	cbqp = cbq_alloc(ifp, M_WAITOK, TRUE);
	if (cbqp == NULL)
		return (ENOMEM);

	/* keep the state in pf_altq */
	a->altq_disc = cbqp;

	return (0);
}

int
altq_cbq_remove(struct pf_altq *a)
{
	cbq_state_t	*cbqp;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((cbqp = a->altq_disc) == NULL)
		return (EINVAL);
	a->altq_disc = NULL;

	return (cbq_destroy(cbqp));
}

int
altq_cbq_add_queue(struct pf_altq *a)
{
	struct cbq_opts	*opts = &a->pq_u.cbq_opts;
	cbq_state_t *cbqp;
	int err;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((cbqp = a->altq_disc) == NULL)
		return (EINVAL);

	IFCQ_LOCK(cbqp->ifnp.ifq_);
	err = cbq_add_queue(cbqp, a->qlimit, a->priority,
	    opts->minburst, opts->maxburst, opts->pktsize, opts->maxpktsize,
	    opts->ns_per_byte, opts->maxidle, opts->minidle, opts->offtime,
	    opts->flags, a->parent_qid, a->qid, NULL);
	IFCQ_UNLOCK(cbqp->ifnp.ifq_);

	return (err);
}

int
altq_cbq_remove_queue(struct pf_altq *a)
{
	cbq_state_t *cbqp;
	int err;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((cbqp = a->altq_disc) == NULL)
		return (EINVAL);

	IFCQ_LOCK(cbqp->ifnp.ifq_);
	err = cbq_remove_queue(cbqp, a->qid);
	IFCQ_UNLOCK(cbqp->ifnp.ifq_);

	return (err);
}

int
altq_cbq_getqstats(struct pf_altq *a, void *ubuf, int *nbytes)
{
	struct ifclassq *ifq = NULL;
	cbq_state_t *cbqp;
	class_stats_t stats;
	int error = 0;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((unsigned)*nbytes < sizeof (stats))
		return (EINVAL);

	if ((cbqp = altq_lookup(a->ifname, ALTQT_CBQ)) == NULL)
		return (EBADF);

	ifq = cbqp->ifnp.ifq_;
	IFCQ_LOCK_ASSERT_HELD(ifq);	/* lock held by altq_lookup */
	error = cbq_get_class_stats(cbqp, a->qid, &stats);
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
altq_cbq_request(struct ifaltq *altq, enum altrq req, void *arg)
{
	cbq_state_t	*cbqp = (cbq_state_t *)altq->altq_disc;

	switch (req) {
	case ALTRQ_PURGE:
		cbq_purge(cbqp);
		break;

	case ALTRQ_PURGE_SC:
		/* not supported for ALTQ instance */
		break;

	case ALTRQ_EVENT:
		cbq_event(cbqp, (cqev_t)arg);
		break;
	}
	return (0);
}

/*
 * altq_cbq_enqueue is an enqueue function to be registered to
 * (*altq_enqueue) in struct ifaltq.
 */
static int
altq_cbq_enqueue(struct ifaltq *altq, struct mbuf *m)
{
	/* grab class set by classifier */
	if (!(m->m_flags & M_PKTHDR)) {
		/* should not happen */
		printf("%s: packet for %s does not have pkthdr\n", __func__,
		    if_name(altq->altq_ifcq->ifcq_ifp));
		m_freem(m);
		return (ENOBUFS);
	}

	return (cbq_enqueue(altq->altq_disc, NULL, m, m_pftag(m)));
}

/*
 * altq_cbq_dequeue is a dequeue function to be registered to
 * (*altq_dequeue) in struct ifaltq.
 *
 * note: ALTDQ_POLL returns the next packet without removing the packet
 *	from the queue.  ALTDQ_REMOVE is a normal dequeue operation.
 *	ALTDQ_REMOVE must return the same packet if called immediately
 *	after ALTDQ_POLL.
 */
static struct mbuf *
altq_cbq_dequeue(struct ifaltq *altq, enum altdq_op op)
{
	return (cbq_dequeue(altq->altq_disc, (cqdq_op_t)op));
}
#endif /* PF_ALTQ && PKTSCHED_CBQ */
