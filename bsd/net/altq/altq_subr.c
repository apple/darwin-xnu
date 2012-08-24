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

/*	$OpenBSD: altq_subr.c,v 1.24 2007/12/11 00:30:14 mikeb Exp $	*/
/*	$KAME: altq_subr.c,v 1.11 2002/01/11 08:11:49 kjc Exp $	*/

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

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#include <sys/syslog.h>
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <sys/mcache.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/pfvar.h>
#include <net/altq/altq.h>
#include <net/pktsched/pktsched.h>

#include <pexpert/pexpert.h>

SYSCTL_NODE(_net, OID_AUTO, altq, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "ALTQ");

static u_int32_t altq_debug;
SYSCTL_UINT(_net_altq, OID_AUTO, debug, CTLFLAG_RW, &altq_debug, 0,
    "Enable ALTQ debugging");

/*
 * look up the queue state by the interface name and the queueing type;
 * upon success, returns with the interface send queue lock held, and
 * the caller is responsible for releasing it.
 */
void *
altq_lookup(char *name, u_int32_t type)
{
	struct ifnet *ifp;
	void *state = NULL;

	if ((ifp = ifunit(name)) != NULL) {
		IFCQ_LOCK(&ifp->if_snd);
		if (type != ALTQT_NONE &&
		    IFCQ_ALTQ(&ifp->if_snd)->altq_type == type)
			state = IFCQ_ALTQ(&ifp->if_snd)->altq_disc;
		if (state == NULL)
			IFCQ_UNLOCK(&ifp->if_snd);
	}

	if (state != NULL)
		IFCQ_LOCK_ASSERT_HELD(&ifp->if_snd);

	return (state);
}

int
altq_attach(struct ifaltq *altq, u_int32_t type, void *discipline,
    altq_enq_func enqueue, altq_deq_func dequeue,
    altq_deq_sc_func dequeue_sc, altq_req_func request)
{
	IFCQ_LOCK_ASSERT_HELD(altq->altq_ifcq);

	if (!ALTQ_IS_READY(altq))
		return (ENXIO);

	VERIFY(enqueue != NULL);
	VERIFY(!(dequeue != NULL && dequeue_sc != NULL));
	VERIFY(request != NULL);

	altq->altq_type = type;
	altq->altq_disc = discipline;
	altq->altq_enqueue = enqueue;
	altq->altq_dequeue = dequeue;
	altq->altq_dequeue_sc = dequeue_sc;
	altq->altq_request = request;
	altq->altq_flags &= (ALTQF_CANTCHANGE|ALTQF_ENABLED);

	return (0);
}

int
altq_detach(struct ifaltq *altq)
{
	IFCQ_LOCK_ASSERT_HELD(altq->altq_ifcq);

	if (!ALTQ_IS_READY(altq))
		return (ENXIO);
	if (ALTQ_IS_ENABLED(altq))
		return (EBUSY);
	if (!ALTQ_IS_ATTACHED(altq))
		return (0);

	altq->altq_type = ALTQT_NONE;
	altq->altq_disc = NULL;
	altq->altq_enqueue = NULL;
	altq->altq_dequeue = NULL;
	altq->altq_dequeue_sc = NULL;
	altq->altq_request = NULL;
	altq->altq_flags &= ALTQF_CANTCHANGE;

	return (0);
}

int
altq_enable(struct ifaltq *altq)
{
	struct ifclassq *ifq = altq->altq_ifcq;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (!ALTQ_IS_READY(altq))
		return (ENXIO);
	if (ALTQ_IS_ENABLED(altq))
		return (0);

	altq->altq_flags |= ALTQF_ENABLED;

	return (0);
}

int
altq_disable(struct ifaltq *altq)
{
	struct ifclassq *ifq = altq->altq_ifcq;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (!ALTQ_IS_ENABLED(altq))
		return (0);

	if_qflush(ifq->ifcq_ifp, 1);

	altq->altq_flags &= ~ALTQF_ENABLED;

	return (0);
}

/*
 * add a discipline or a queue
 */
int
altq_add(struct pf_altq *a)
{
	int error = 0;

	VERIFY(machclk_freq != 0);

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (a->qname[0] != 0)
		return (altq_add_queue(a));

	switch (a->scheduler) {
#if PKTSCHED_CBQ
	case ALTQT_CBQ:
		error = altq_cbq_add(a);
		break;
#endif /* PKTSCHED_CBQ */
#if PKTSCHED_PRIQ
	case ALTQT_PRIQ:
		error = altq_priq_add(a);
		break;
#endif /* PKTSCHED_PRIQ */
#if PKTSCHED_HFSC
	case ALTQT_HFSC:
		error = altq_hfsc_add(a);
		break;
#endif /* PKTSCHED_HFSC */
#if PKTSCHED_FAIRQ
        case ALTQT_FAIRQ:
                error = altq_fairq_add(a);
                break;
#endif /* PKTSCHED_FAIRQ */
        case ALTQT_QFQ:
                error = altq_qfq_add(a);
                break;
	default:
		error = ENXIO;
	}

	return (error);
}

/*
 * remove a discipline or a queue
 */
int
altq_remove(struct pf_altq *a)
{
	int error = 0;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if (a->qname[0] != 0)
		return (altq_remove_queue(a));

	switch (a->scheduler) {
#if PKTSCHED_CBQ
	case ALTQT_CBQ:
		error = altq_cbq_remove(a);
		break;
#endif /* PKTSCHED_CBQ */
#if PKTSCHED_PRIQ
	case ALTQT_PRIQ:
		error = altq_priq_remove(a);
		break;
#endif /* PKTSCHED_PRIQ */
#if PKTSCHED_HFSC
	case ALTQT_HFSC:
		error = altq_hfsc_remove(a);
		break;
#endif /* PKTSCHED_HFSC */
#if PKTSCHED_FAIRQ
        case ALTQT_FAIRQ:
                error = altq_fairq_remove(a);
                break;
#endif /* PKTSCHED_FAIRQ */
        case ALTQT_QFQ:
                error = altq_qfq_remove(a);
                break;
	default:
		error = ENXIO;
	}

	return (error);
}

/*
 * add a queue to the discipline
 */
int
altq_add_queue(struct pf_altq *a)
{
	int error = 0;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	switch (a->scheduler) {
#if PKTSCHED_CBQ
	case ALTQT_CBQ:
		error = altq_cbq_add_queue(a);
		break;
#endif /* PKTSCHED_CBQ */
#if PKTSCHED_PRIQ
	case ALTQT_PRIQ:
		error = altq_priq_add_queue(a);
		break;
#endif /* PKTSCHED_PRIQ */
#if PKTSCHED_HFSC
	case ALTQT_HFSC:
		error = altq_hfsc_add_queue(a);
		break;
#endif /* PKTSCHED_HFSC */
#if PKTSCHED_FAIRQ
        case ALTQT_FAIRQ:
                error = altq_fairq_add_queue(a);
                break;
#endif /* PKTSCHED_FAIRQ */
        case ALTQT_QFQ:
                error = altq_qfq_add_queue(a);
                break;
	default:
		error = ENXIO;
	}

	return (error);
}

/*
 * remove a queue from the discipline
 */
int
altq_remove_queue(struct pf_altq *a)
{
	int error = 0;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	switch (a->scheduler) {
#if PKTSCHED_CBQ
	case ALTQT_CBQ:
		error = altq_cbq_remove_queue(a);
		break;
#endif /* PKTSCHED_CBQ */
#if PKTSCHED_PRIQ
	case ALTQT_PRIQ:
		error = altq_priq_remove_queue(a);
		break;
#endif /* PKTSCHED_PRIQ */
#if PKTSCHED_HFSC
	case ALTQT_HFSC:
		error = altq_hfsc_remove_queue(a);
		break;
#endif /* PKTSCHED_HFSC */
#if PKTSCHED_FAIRQ
        case ALTQT_FAIRQ:
                error = altq_fairq_remove_queue(a);
                break;
#endif /* PKTSCHED_FAIRQ */
        case ALTQT_QFQ:
                error = altq_qfq_remove_queue(a);
                break;
	default:
		error = ENXIO;
	}

	return (error);
}

/*
 * get queue statistics
 */
int
altq_getqstats(struct pf_altq *a, void *ubuf, int *nbytes)
{
	int error = 0;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	switch (a->scheduler) {
#if PKTSCHED_CBQ
	case ALTQT_CBQ:
		error = altq_cbq_getqstats(a, ubuf, nbytes);
		break;
#endif /* PKTSCHED_CBQ */
#if PKTSCHED_PRIQ
	case ALTQT_PRIQ:
		error = altq_priq_getqstats(a, ubuf, nbytes);
		break;
#endif /* PKTSCHED_PRIQ */
#if PKTSCHED_HFSC
	case ALTQT_HFSC:
		error = altq_hfsc_getqstats(a, ubuf, nbytes);
		break;
#endif /* PKTSCHED_HFSC */
#if PKTSCHED_FAIRQ
        case ALTQT_FAIRQ:
                error = altq_fairq_getqstats(a, ubuf, nbytes);
                break;
#endif /* PKTSCHED_FAIRQ */
        case ALTQT_QFQ:
                error = altq_qfq_getqstats(a, ubuf, nbytes);
                break;
	default:
		error = ENXIO;
	}

	return (error);
}

/*
 * attach a discipline to the interface.  if one already exists, it is
 * overridden.
 */
int
altq_pfattach(struct pf_altq *a)
{
	int error = 0;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	switch (a->scheduler) {
	case ALTQT_NONE:
		break;
#if PKTSCHED_CBQ
	case ALTQT_CBQ:
		error = altq_cbq_pfattach(a);
		break;
#endif /* PKTSCHED_CBQ */
#if PKTSCHED_PRIQ
	case ALTQT_PRIQ:
		error = altq_priq_pfattach(a);
		break;
#endif /* PKTSCHED_PRIQ */
#if PKTSCHED_HFSC
	case ALTQT_HFSC:
		error = altq_hfsc_pfattach(a);
		break;
#endif /* PKTSCHED_HFSC */
#if PKTSCHED_FAIRQ
	case ALTQT_FAIRQ:
		error = altq_fairq_pfattach(a);
		break;
#endif /* PKTSCHED_FAIRQ */
	case ALTQT_QFQ:
		error = altq_qfq_pfattach(a);
		break;
	default:
		error = ENXIO;
	}

	return (error);
}

/*
 * detach a discipline from the interface.
 * it is possible that the discipline was already overridden by another
 * discipline.
 */
int
altq_pfdetach(struct pf_altq *a)
{
	struct ifnet *ifp;
	int error = 0;

	lck_mtx_assert(pf_lock, LCK_MTX_ASSERT_OWNED);

	if ((ifp = ifunit(a->ifname)) == NULL)
		return (EINVAL);

	/* if this discipline is no longer referenced, just return */
	IFCQ_LOCK(&ifp->if_snd);
	if (a->altq_disc == NULL ||
	    a->altq_disc != IFCQ_ALTQ(&ifp->if_snd)->altq_disc) {
		IFCQ_UNLOCK(&ifp->if_snd);
		return (0);
	}

	if (ALTQ_IS_ENABLED(IFCQ_ALTQ(&ifp->if_snd)))
		error = altq_disable(IFCQ_ALTQ(&ifp->if_snd));
	if (error == 0)
		error = altq_detach(IFCQ_ALTQ(&ifp->if_snd));
	IFCQ_UNLOCK(&ifp->if_snd);
	return (error);
}


