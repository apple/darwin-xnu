/*
 * Copyright (c) 2011-2017 Apple Inc. All rights reserved.
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
#include <net/pktsched/pktsched_fq_codel.h>

#include <pexpert/pexpert.h>


u_int32_t machclk_freq = 0;
u_int64_t machclk_per_sec = 0;
u_int32_t pktsched_verbose;     /* more noise if greater than 1 */

static void init_machclk(void);

SYSCTL_NODE(_net, OID_AUTO, pktsched, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "pktsched");

SYSCTL_UINT(_net_pktsched, OID_AUTO, verbose, CTLFLAG_RW | CTLFLAG_LOCKED,
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
	return nsecs;
}

u_int64_t
pktsched_nsecs_to_abstime(u_int64_t nsecs)
{
	u_int64_t abstime;

	nanoseconds_to_absolutetime(nsecs, &abstime);
	return abstime;
}

int
pktsched_setup(struct ifclassq *ifq, u_int32_t scheduler, u_int32_t sflags,
    classq_pkt_type_t ptype)
{
	int error = 0;
	u_int32_t rflags;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	VERIFY(machclk_freq != 0);

	/* Nothing to do unless the scheduler type changes */
	if (ifq->ifcq_type == scheduler) {
		return 0;
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
	case PKTSCHEDT_TCQ:
		error = tcq_setup_ifclassq(ifq, sflags, ptype);
		break;

	case PKTSCHEDT_QFQ:
		error = qfq_setup_ifclassq(ifq, sflags, ptype);
		break;
	case PKTSCHEDT_FQ_CODEL:
		error = fq_if_setup_ifclassq(ifq, sflags, ptype);
		break;
	default:
		error = ENXIO;
		break;
	}

	if (error == 0) {
		ifq->ifcq_flags |= rflags;
	}

	return error;
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

	case PKTSCHEDT_TCQ:
		error = tcq_teardown_ifclassq(ifq);
		break;

	case PKTSCHEDT_QFQ:
		error = qfq_teardown_ifclassq(ifq);
		break;

	case PKTSCHEDT_FQ_CODEL:
		error = fq_if_teardown_ifclassq(ifq);
		break;
	default:
		error = ENXIO;
		break;
	}
	return error;
}

int
pktsched_getqstats(struct ifclassq *ifq, u_int32_t qid,
    struct if_ifclassq_stats *ifqs)
{
	int error;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	switch (ifq->ifcq_type) {
	case PKTSCHEDT_TCQ:
		error = tcq_getqstats_ifclassq(ifq, qid, ifqs);
		break;

	case PKTSCHEDT_QFQ:
		error = qfq_getqstats_ifclassq(ifq, qid, ifqs);
		break;

	case PKTSCHEDT_FQ_CODEL:
		error = fq_if_getqstats_ifclassq(ifq, qid, ifqs);
		break;
	default:
		error = ENXIO;
		break;
	}

	return error;
}

void
pktsched_pkt_encap(pktsched_pkt_t *pkt, classq_pkt_type_t ptype, void *pp)
{
	pkt->pktsched_ptype = ptype;
	pkt->pktsched_pkt = pp;

	switch (ptype) {
	case QP_MBUF:
		pkt->pktsched_plen =
		    (uint32_t)m_pktlen((struct mbuf *)pkt->pktsched_pkt);
		break;


	default:
		VERIFY(0);
		/* NOTREACHED */
	}
}

void
pktsched_free_pkt(pktsched_pkt_t *pkt)
{
	switch (pkt->pktsched_ptype) {
	case QP_MBUF:
		m_freem(pkt->pktsched_pkt);
		break;


	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	pkt->pktsched_pkt = NULL;
	pkt->pktsched_plen = 0;
	pkt->pktsched_ptype = 0;
}

uint32_t
pktsched_get_pkt_len(pktsched_pkt_t *pkt)
{
	return pkt->pktsched_plen;
}

mbuf_svc_class_t
pktsched_get_pkt_svc(pktsched_pkt_t *pkt)
{
	mbuf_svc_class_t svc = MBUF_SC_UNSPEC;

	switch (pkt->pktsched_ptype) {
	case QP_MBUF:
		svc = m_get_service_class((mbuf_t)pkt->pktsched_pkt);
		break;


	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return svc;
}

void
pktsched_get_pkt_vars(pktsched_pkt_t *pkt, uint32_t **flags,
    uint64_t **timestamp, uint32_t *flowid, uint8_t *flowsrc, uint8_t *proto,
    uint32_t *tcp_start_seq)
{
	switch (pkt->pktsched_ptype) {
	case QP_MBUF: {
		struct mbuf *m = (struct mbuf *)pkt->pktsched_pkt;
		struct pkthdr *pkth = &m->m_pkthdr;

		if (flags != NULL) {
			*flags = &pkth->pkt_flags;
		}
		if (timestamp != NULL) {
			*timestamp = &pkth->pkt_timestamp;
		}
		if (flowid != NULL) {
			*flowid = pkth->pkt_flowid;
		}
		if (flowsrc != NULL) {
			*flowsrc = pkth->pkt_flowsrc;
		}
		if (proto != NULL) {
			*proto = pkth->pkt_proto;
		}
		/*
		 * caller should use this value only if PKTF_START_SEQ
		 * is set in the mbuf packet flags
		 */
		if (tcp_start_seq != NULL) {
			*tcp_start_seq = pkth->tx_start_seq;
		}

		break;
	}


	default:
		VERIFY(0);
		/* NOTREACHED */
	}
}

struct flowadv_fcentry *
pktsched_alloc_fcentry(pktsched_pkt_t *pkt, struct ifnet *ifp, int how)
{
#pragma unused(ifp)
	struct flowadv_fcentry *fce = NULL;

	switch (pkt->pktsched_ptype) {
	case QP_MBUF: {
		struct mbuf *m = (struct mbuf *)pkt->pktsched_pkt;

		fce = flowadv_alloc_entry(how);
		if (fce == NULL) {
			break;
		}

		_CASSERT(sizeof(m->m_pkthdr.pkt_flowid) ==
		    sizeof(fce->fce_flowid));

		fce->fce_flowsrc_type = m->m_pkthdr.pkt_flowsrc;
		fce->fce_flowid = m->m_pkthdr.pkt_flowid;
		break;
	}


	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return fce;
}

uint32_t *
pktsched_get_pkt_sfb_vars(pktsched_pkt_t *pkt, uint32_t **sfb_flags)
{
	uint32_t *hashp = NULL;

	switch (pkt->pktsched_ptype) {
	case QP_MBUF: {
		struct mbuf *m = (struct mbuf *)pkt->pktsched_pkt;
		struct pkthdr *pkth = &m->m_pkthdr;

		_CASSERT(sizeof(pkth->pkt_mpriv_hash) == sizeof(uint32_t));
		_CASSERT(sizeof(pkth->pkt_mpriv_flags) == sizeof(uint32_t));

		*sfb_flags = &pkth->pkt_mpriv_flags;
		hashp = &pkth->pkt_mpriv_hash;
		break;
	}


	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return hashp;
}
