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

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#include <sys/mcache.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/net_osdep.h>
#include <net/pktsched/pktsched.h>
#include <net/pktsched/pktsched_tcq.h>
#include <net/pktsched/pktsched_qfq.h>
#if PKTSCHED_PRIQ
#include <net/pktsched/pktsched_priq.h>
#endif /* PKTSCHED_PRIQ */
#if PKTSCHED_FAIRQ
#include <net/pktsched/pktsched_fairq.h>
#endif /* PKTSCHED_FAIRQ */
#if PKTSCHED_CBQ
#include <net/pktsched/pktsched_cbq.h>
#endif /* PKTSCHED_CBQ */
#if PKTSCHED_HFSC
#include <net/pktsched/pktsched_hfsc.h>
#endif /* PKTSCHED_HFSC */

#include <pexpert/pexpert.h>

u_int32_t machclk_freq = 0;
u_int64_t machclk_per_sec = 0;
u_int32_t pktsched_verbose;	/* more noise if greater than 1 */

static void init_machclk(void);

SYSCTL_NODE(_net, OID_AUTO, pktsched, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "pktsched");

SYSCTL_UINT(_net_pktsched, OID_AUTO, verbose, CTLFLAG_RW|CTLFLAG_LOCKED,
	&pktsched_verbose, 0, "Packet scheduler verbosity level");

void
pktsched_init(void)
{
	init_machclk();
	if (machclk_freq == 0) {
		panic("%s: no CPU clock available!\n", __func__);
		/* NOTREACHED */
	}

	tcq_init();
	qfq_init();
#if PKTSCHED_PRIQ
	priq_init();
#endif /* PKTSCHED_PRIQ */
#if PKTSCHED_FAIRQ
	fairq_init();
#endif /* PKTSCHED_FAIRQ */
#if PKTSCHED_CBQ
	cbq_init();
#endif /* PKTSCHED_CBQ */
#if PKTSCHED_HFSC
	hfsc_init();
#endif /* PKTSCHED_HFSC */
}

static void
init_machclk(void)
{
	/*
	 * Initialize machclk_freq using the timerbase frequency
	 * value from device specific info.
	 */
	machclk_freq = gPEClockFrequencyInfo.timebase_frequency_hz;

	clock_interval_to_absolutetime_interval(1, NSEC_PER_SEC,
	    &machclk_per_sec);
}

u_int64_t
pktsched_abs_to_nsecs(u_int64_t abstime)
{
	u_int64_t nsecs;

	absolutetime_to_nanoseconds(abstime, &nsecs);
	return (nsecs);
}

u_int64_t
pktsched_nsecs_to_abstime(u_int64_t nsecs)
{
	u_int64_t abstime;

	nanoseconds_to_absolutetime(nsecs, &abstime);
	return (abstime);
}

int
pktsched_setup(struct ifclassq *ifq, u_int32_t scheduler, u_int32_t sflags)
{
	int error = 0;
	u_int32_t qflags = sflags;
	u_int32_t rflags;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	VERIFY(machclk_freq != 0);

	/* Nothing to do unless the scheduler type changes */
	if (ifq->ifcq_type == scheduler)
		return (0);

	qflags &= (PKTSCHEDF_QALG_RED | PKTSCHEDF_QALG_RIO |
	    PKTSCHEDF_QALG_BLUE | PKTSCHEDF_QALG_SFB);

	/* These are mutually exclusive */
	if (qflags != 0 &&
	    qflags != PKTSCHEDF_QALG_RED && qflags != PKTSCHEDF_QALG_RIO &&
	    qflags != PKTSCHEDF_QALG_BLUE && qflags != PKTSCHEDF_QALG_SFB) {
		panic("%s: RED|RIO|BLUE|SFB mutually exclusive\n", __func__);
		/* NOTREACHED */
	}

	/*
	 * Remember the flags that need to be restored upon success, as
	 * they may be cleared when we tear down existing scheduler.
	 */
	rflags = (ifq->ifcq_flags & IFCQF_ENABLED);

	if (ifq->ifcq_type != PKTSCHEDT_NONE) {
		(void) pktsched_teardown(ifq);

		/* Teardown should have succeeded */
		VERIFY(ifq->ifcq_type == PKTSCHEDT_NONE);
		VERIFY(ifq->ifcq_disc == NULL);
		VERIFY(ifq->ifcq_enqueue == NULL);
		VERIFY(ifq->ifcq_dequeue == NULL);
		VERIFY(ifq->ifcq_dequeue_sc == NULL);
		VERIFY(ifq->ifcq_request == NULL);
	}

	switch (scheduler) {
#if PKTSCHED_PRIQ
	case PKTSCHEDT_PRIQ:
		error = priq_setup_ifclassq(ifq, sflags);
		break;
#endif /* PKTSCHED_PRIQ */

	case PKTSCHEDT_TCQ:
		error = tcq_setup_ifclassq(ifq, sflags);
		break;

	case PKTSCHEDT_QFQ:
		error = qfq_setup_ifclassq(ifq, sflags);
		break;

	default:
		error = ENXIO;
		break;
	}

	if (error == 0)
		ifq->ifcq_flags |= rflags;

	return (error);
}

int
pktsched_teardown(struct ifclassq *ifq)
{
	int error = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if_qflush(ifq->ifcq_ifp, 1);
	VERIFY(IFCQ_IS_EMPTY(ifq));

	ifq->ifcq_flags &= ~IFCQF_ENABLED;

	switch (ifq->ifcq_type) {
	case PKTSCHEDT_NONE:
		break;

#if PKTSCHED_PRIQ
	case PKTSCHEDT_PRIQ:
		error = priq_teardown_ifclassq(ifq);
		break;
#endif /* PKTSCHED_PRIQ */

	case PKTSCHEDT_TCQ:
		error = tcq_teardown_ifclassq(ifq);
		break;

	case PKTSCHEDT_QFQ:
		error = qfq_teardown_ifclassq(ifq);
		break;

	default:
		error = ENXIO;
		break;
	}
	return (error);
}

int
pktsched_getqstats(struct ifclassq *ifq, u_int32_t qid,
    struct if_ifclassq_stats *ifqs)
{
	int error;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	switch (ifq->ifcq_type) {
#if PKTSCHED_PRIQ
	case PKTSCHEDT_PRIQ:
		error = priq_getqstats_ifclassq(ifq, qid, ifqs);
		break;
#endif /* PKTSCHED_PRIQ */

	case PKTSCHEDT_TCQ:
		error = tcq_getqstats_ifclassq(ifq, qid, ifqs);
		break;

	case PKTSCHEDT_QFQ:
		error = qfq_getqstats_ifclassq(ifq, qid, ifqs);
		break;

	default:
		error = ENXIO;
		break;
	}

	return (error);
}
