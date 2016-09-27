/*
 * Copyright (c) 2011-2015 Apple Inc. All rights reserved.
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
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/random.h>
#include <sys/kernel_types.h>
#include <sys/sysctl.h>

#include <kern/zalloc.h>

#include <net/if.h>
#include <net/net_osdep.h>
#include <net/classq/classq.h>
#include <pexpert/pexpert.h>
#if CLASSQ_RED
#include <net/classq/classq_red.h>
#endif /* CLASSQ_RED */
#if CLASSQ_RIO
#include <net/classq/classq_rio.h>
#endif /* CLASSQ_RIO */
#if CLASSQ_BLUE
#include <net/classq/classq_blue.h>
#endif /* CLASSQ_BLUE */
#include <net/classq/classq_sfb.h>
#include <net/pktsched/pktsched.h>
#include <net/pktsched/pktsched_fq_codel.h>

#include <libkern/libkern.h>

#if PF_ALTQ
#include <net/altq/altq.h>
#endif /* PF_ALTQ */

static errno_t ifclassq_dequeue_common(struct ifclassq *, mbuf_svc_class_t,
    u_int32_t, u_int32_t, struct mbuf **, struct mbuf **, u_int32_t *,
    u_int32_t *, boolean_t);
static struct mbuf *ifclassq_poll_common(struct ifclassq *,
    mbuf_svc_class_t, boolean_t);
static struct mbuf *ifclassq_tbr_dequeue_common(struct ifclassq *, int,
    mbuf_svc_class_t, boolean_t);

static u_int64_t ifclassq_target_qdelay = 0;
SYSCTL_QUAD(_net_classq, OID_AUTO, target_qdelay, CTLFLAG_RW|CTLFLAG_LOCKED,
    &ifclassq_target_qdelay, "target queue delay in nanoseconds");

static u_int64_t ifclassq_update_interval = 0;
SYSCTL_QUAD(_net_classq, OID_AUTO, update_interval,
    CTLFLAG_RW|CTLFLAG_LOCKED, &ifclassq_update_interval,
    "update interval in nanoseconds");

static int32_t ifclassq_sched_fq_codel;

void
classq_init(void)
{
	_CASSERT(MBUF_TC_BE == 0);
	_CASSERT(MBUF_SC_BE == 0);
	_CASSERT(IFCQ_SC_MAX == MBUF_SC_MAX_CLASSES);

#if CLASSQ_RED
	red_init();
#endif /* CLASSQ_RED */
#if CLASSQ_RIO
	rio_init();
#endif /* CLASSQ_RIO */
#if CLASSQ_BLUE
	blue_init();
#endif /* CLASSQ_BLUE */
	sfb_init();
	fq_codel_scheduler_init();

	if (!PE_parse_boot_argn("fq_codel", &ifclassq_sched_fq_codel,
	    sizeof (ifclassq_sched_fq_codel)))
		ifclassq_sched_fq_codel = 0;
}

int
ifclassq_setup(struct ifnet *ifp, u_int32_t sflags, boolean_t reuse)
{
#pragma unused(reuse)
	struct ifclassq *ifq = &ifp->if_snd;
	int err = 0;

	IFCQ_LOCK(ifq);
	VERIFY(IFCQ_IS_EMPTY(ifq));
	ifq->ifcq_ifp = ifp;
	IFCQ_LEN(ifq) = 0;
	IFCQ_BYTES(ifq) = 0;
	bzero(&ifq->ifcq_xmitcnt, sizeof (ifq->ifcq_xmitcnt));
	bzero(&ifq->ifcq_dropcnt, sizeof (ifq->ifcq_dropcnt));

	VERIFY(!IFCQ_TBR_IS_ENABLED(ifq));
	VERIFY(ifq->ifcq_type == PKTSCHEDT_NONE);
	VERIFY(ifq->ifcq_flags == 0);
	VERIFY(ifq->ifcq_sflags == 0);
	VERIFY(ifq->ifcq_disc == NULL);
	VERIFY(ifq->ifcq_enqueue == NULL);
	VERIFY(ifq->ifcq_dequeue == NULL);
	VERIFY(ifq->ifcq_dequeue_sc == NULL);
	VERIFY(ifq->ifcq_request == NULL);

	if (ifp->if_eflags & IFEF_TXSTART) {
		u_int32_t maxlen = 0;

		if ((maxlen = IFCQ_MAXLEN(ifq)) == 0)
			maxlen = if_sndq_maxlen;
		IFCQ_SET_MAXLEN(ifq, maxlen);

		if (IFCQ_MAXLEN(ifq) != if_sndq_maxlen &&
		    IFCQ_TARGET_QDELAY(ifq) == 0) {
			/*
			 * Choose static queues because the interface has
			 * maximum queue size set
			 */
			sflags &= ~PKTSCHEDF_QALG_DELAYBASED;
		}
		ifq->ifcq_sflags = sflags;
		err = ifclassq_pktsched_setup(ifq);
		if (err == 0)
			ifq->ifcq_flags = (IFCQF_READY | IFCQF_ENABLED);
	}

#if PF_ALTQ
	ifq->ifcq_drain = 0;
	IFCQ_ALTQ(ifq)->altq_ifcq = ifq;
	VERIFY(IFCQ_ALTQ(ifq)->altq_type == ALTQT_NONE);
	VERIFY(IFCQ_ALTQ(ifq)->altq_flags == 0);
	VERIFY(IFCQ_ALTQ(ifq)->altq_disc == NULL);
	VERIFY(IFCQ_ALTQ(ifq)->altq_enqueue == NULL);
	VERIFY(IFCQ_ALTQ(ifq)->altq_dequeue == NULL);
	VERIFY(IFCQ_ALTQ(ifq)->altq_dequeue_sc == NULL);
	VERIFY(IFCQ_ALTQ(ifq)->altq_request == NULL);

	if ((ifp->if_eflags & IFEF_TXSTART) &&
	    ifp->if_output_sched_model != IFNET_SCHED_MODEL_DRIVER_MANAGED)
		ALTQ_SET_READY(IFCQ_ALTQ(ifq));
	else
		ALTQ_CLEAR_READY(IFCQ_ALTQ(ifq));
#endif /* PF_ALTQ */
	IFCQ_UNLOCK(ifq);

	return (err);
}

void
ifclassq_teardown(struct ifnet *ifp)
{
	struct ifclassq *ifq = &ifp->if_snd;

	IFCQ_LOCK(ifq);
#if PF_ALTQ
	if (ALTQ_IS_READY(IFCQ_ALTQ(ifq))) {
		if (ALTQ_IS_ENABLED(IFCQ_ALTQ(ifq)))
			altq_disable(IFCQ_ALTQ(ifq));
		if (ALTQ_IS_ATTACHED(IFCQ_ALTQ(ifq)))
			altq_detach(IFCQ_ALTQ(ifq));
		IFCQ_ALTQ(ifq)->altq_flags = 0;
	}
	ifq->ifcq_drain = 0;
	IFCQ_ALTQ(ifq)->altq_ifcq = NULL;
	VERIFY(IFCQ_ALTQ(ifq)->altq_type == ALTQT_NONE);
	VERIFY(IFCQ_ALTQ(ifq)->altq_flags == 0);
	VERIFY(IFCQ_ALTQ(ifq)->altq_disc == NULL);
	VERIFY(IFCQ_ALTQ(ifq)->altq_enqueue == NULL);
	VERIFY(IFCQ_ALTQ(ifq)->altq_dequeue == NULL);
	VERIFY(IFCQ_ALTQ(ifq)->altq_dequeue_sc == NULL);
	VERIFY(IFCQ_ALTQ(ifq)->altq_request == NULL);
#endif /* PF_ALTQ */

	if (IFCQ_IS_READY(ifq)) {
		if (IFCQ_TBR_IS_ENABLED(ifq)) {
			struct tb_profile tb = { 0, 0, 0 };
			(void) ifclassq_tbr_set(ifq, &tb, FALSE);
		}
		(void) pktsched_teardown(ifq);
		ifq->ifcq_flags = 0;
	}
	ifq->ifcq_sflags = 0;

	VERIFY(IFCQ_IS_EMPTY(ifq));
	VERIFY(!IFCQ_TBR_IS_ENABLED(ifq));
	VERIFY(ifq->ifcq_type == PKTSCHEDT_NONE);
	VERIFY(ifq->ifcq_flags == 0);
	VERIFY(ifq->ifcq_sflags == 0);
	VERIFY(ifq->ifcq_disc == NULL);
	VERIFY(ifq->ifcq_enqueue == NULL);
	VERIFY(ifq->ifcq_dequeue == NULL);
	VERIFY(ifq->ifcq_dequeue_sc == NULL);
	VERIFY(ifq->ifcq_request == NULL);
	IFCQ_LEN(ifq) = 0;
	IFCQ_BYTES(ifq) = 0;
	IFCQ_MAXLEN(ifq) = 0;
	bzero(&ifq->ifcq_xmitcnt, sizeof (ifq->ifcq_xmitcnt));
	bzero(&ifq->ifcq_dropcnt, sizeof (ifq->ifcq_dropcnt));

	IFCQ_UNLOCK(ifq);
}

int
ifclassq_pktsched_setup(struct ifclassq *ifq)
{
	struct ifnet *ifp = ifq->ifcq_ifp;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifp->if_eflags & IFEF_TXSTART);

	switch (ifp->if_output_sched_model) {
	case IFNET_SCHED_MODEL_DRIVER_MANAGED:
		err = pktsched_setup(ifq, PKTSCHEDT_TCQ, ifq->ifcq_sflags);
		break;

	case IFNET_SCHED_MODEL_NORMAL:
		if (ifclassq_sched_fq_codel != 0) {
			err = pktsched_setup(ifq, PKTSCHEDT_FQ_CODEL,
			    ifq->ifcq_sflags);
		} else {
			err = pktsched_setup(ifq, PKTSCHEDT_QFQ,
			    ifq->ifcq_sflags);
		}
		break;
	case IFNET_SCHED_MODEL_FQ_CODEL:
		err = pktsched_setup(ifq, PKTSCHEDT_FQ_CODEL,
		    ifq->ifcq_sflags);
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	return (err);
}

void
ifclassq_set_maxlen(struct ifclassq *ifq, u_int32_t maxqlen)
{
	IFCQ_LOCK(ifq);
	if (maxqlen == 0)
		maxqlen = if_sndq_maxlen;
	IFCQ_SET_MAXLEN(ifq, maxqlen);
	IFCQ_UNLOCK(ifq);
}

u_int32_t
ifclassq_get_maxlen(struct ifclassq *ifq)
{
	return (IFCQ_MAXLEN(ifq));
}

int
ifclassq_get_len(struct ifclassq *ifq, mbuf_svc_class_t sc, u_int32_t *packets,
    u_int32_t *bytes)
{
	int err = 0;

	IFCQ_LOCK(ifq);
	if (sc == MBUF_SC_UNSPEC) {
		VERIFY(packets != NULL);
		*packets = IFCQ_LEN(ifq);
	} else {
		VERIFY(MBUF_VALID_SC(sc));
		VERIFY(packets != NULL && bytes != NULL);
		IFCQ_LEN_SC(ifq, sc, packets, bytes, err);
	}
	IFCQ_UNLOCK(ifq);

	return (err);
}

errno_t
ifclassq_enqueue(struct ifclassq *ifq, struct mbuf *m)
{
	errno_t err;

	IFCQ_LOCK_SPIN(ifq);

#if PF_ALTQ
	if (ALTQ_IS_ENABLED(IFCQ_ALTQ(ifq))) {
		ALTQ_ENQUEUE(IFCQ_ALTQ(ifq), m, err);
	} else {
		u_int32_t qlen = IFCQ_LEN(ifq);
		IFCQ_ENQUEUE(ifq, m, err);
		if (IFCQ_LEN(ifq) > qlen)
			ifq->ifcq_drain += (IFCQ_LEN(ifq) - qlen);
	}
#else /* !PF_ALTQ */
	IFCQ_ENQUEUE(ifq, m, err);
#endif /* PF_ALTQ */

	IFCQ_UNLOCK(ifq);

	return (err);
}

errno_t
ifclassq_dequeue(struct ifclassq *ifq, u_int32_t pkt_limit,
    u_int32_t byte_limit, struct mbuf **head,
    struct mbuf **tail, u_int32_t *cnt, u_int32_t *len)
{
	return (ifclassq_dequeue_common(ifq, MBUF_SC_UNSPEC, pkt_limit,
	    byte_limit, head, tail, cnt, len, FALSE));
}

errno_t
ifclassq_dequeue_sc(struct ifclassq *ifq, mbuf_svc_class_t sc,
    u_int32_t pkt_limit, struct mbuf **head, struct mbuf **tail,
    u_int32_t *cnt, u_int32_t *len)
{
	return (ifclassq_dequeue_common(ifq, sc, pkt_limit,
	    CLASSQ_DEQUEUE_MAX_BYTE_LIMIT, head, tail, cnt, len, TRUE));
}

static errno_t
ifclassq_dequeue_common(struct ifclassq *ifq, mbuf_svc_class_t sc,
    u_int32_t pkt_limit, u_int32_t byte_limit, struct mbuf **head,
    struct mbuf **tail, u_int32_t *cnt, u_int32_t *len, boolean_t drvmgt)
{
	struct ifnet *ifp = ifq->ifcq_ifp;
	u_int32_t i = 0, l = 0;
	struct mbuf **first, *last;
#if PF_ALTQ
	struct ifaltq *altq = IFCQ_ALTQ(ifq);
	boolean_t draining;
#endif /* PF_ALTQ */

	VERIFY(!drvmgt || MBUF_VALID_SC(sc));

	/*
	 * If the scheduler support dequeueing multiple packets at the
	 * same time, call that one instead.
	 */

	if (ifq->ifcq_dequeue_multi != NULL) {
		int err;
		IFCQ_LOCK_SPIN(ifq);
		err = ifq->ifcq_dequeue_multi(ifq, CLASSQDQ_REMOVE,
		    pkt_limit, byte_limit, head, tail, cnt, len);
		IFCQ_UNLOCK(ifq);

		if (err == 0 && (*head) == NULL)
			err = EAGAIN;
		return (err);
	}

	*head = NULL;
	first = &(*head);
	last = NULL;

	IFCQ_LOCK_SPIN(ifq);

	while (i < pkt_limit && l < byte_limit) {
#if PF_ALTQ
		u_int32_t qlen;

		qlen = IFCQ_LEN(ifq);
		draining = IFCQ_IS_DRAINING(ifq);

		if (drvmgt) {
			if (IFCQ_TBR_IS_ENABLED(ifq))
				IFCQ_TBR_DEQUEUE_SC(ifq, sc, *head);
			else if (draining)
				IFCQ_DEQUEUE_SC(ifq, sc, *head);
			else if (ALTQ_IS_ENABLED(altq))
				ALTQ_DEQUEUE_SC(altq, sc, *head);
			else
				*head = NULL;
		} else {
			if (IFCQ_TBR_IS_ENABLED(ifq))
				IFCQ_TBR_DEQUEUE(ifq, *head);
			else if (draining)
				IFCQ_DEQUEUE(ifq, *head);
			else if (ALTQ_IS_ENABLED(altq))
				ALTQ_DEQUEUE(altq, *head);
			else
				*head = NULL;
		}

		if (draining && *head != NULL) {
			VERIFY(ifq->ifcq_drain >= (qlen - IFCQ_LEN(ifq)));
			ifq->ifcq_drain -= (qlen - IFCQ_LEN(ifq));
		}
#else /* ! PF_ALTQ */
		if (drvmgt) {
			if (IFCQ_TBR_IS_ENABLED(ifq))
				IFCQ_TBR_DEQUEUE_SC(ifq, sc, *head);
			else
				IFCQ_DEQUEUE_SC(ifq, sc, *head);
		} else {
			if (IFCQ_TBR_IS_ENABLED(ifq))
				IFCQ_TBR_DEQUEUE(ifq, *head);
			else
				IFCQ_DEQUEUE(ifq, *head);
		}
#endif /* !PF_ALTQ */

		if (*head == NULL)
			break;

		(*head)->m_nextpkt = NULL;
		last = *head;

		l += (*head)->m_pkthdr.len;

#if MEASURE_BW
		(*head)->m_pkthdr.pkt_bwseq =
		    atomic_add_64_ov(&(ifp->if_bw.cur_seq), m_pktlen(*head));
#endif /* MEASURE_BW */
		if (IFNET_IS_CELLULAR(ifp)) {
			(*head)->m_pkthdr.pkt_flags |= PKTF_VALID_UNSENT_DATA;
			(*head)->m_pkthdr.bufstatus_if = IFCQ_BYTES(ifq);
			(*head)->m_pkthdr.bufstatus_sndbuf = ifp->if_sndbyte_unsent;
		}
		head = &(*head)->m_nextpkt;
		i++;
	}

	IFCQ_UNLOCK(ifq);

	if (tail != NULL)
		*tail = last;
	if (cnt != NULL)
		*cnt = i;
	if (len != NULL)
		*len = l;

	return ((*first != NULL) ? 0 : EAGAIN);
}

struct mbuf *
ifclassq_poll(struct ifclassq *ifq)
{
	return (ifclassq_poll_common(ifq, MBUF_SC_UNSPEC, FALSE));
}

struct mbuf *
ifclassq_poll_sc(struct ifclassq *ifq, mbuf_svc_class_t sc)
{
	return (ifclassq_poll_common(ifq, sc, TRUE));
}

static struct mbuf *
ifclassq_poll_common(struct ifclassq *ifq, mbuf_svc_class_t sc,
    boolean_t drvmgt)
{
#if PF_ALTQ
	struct ifaltq *altq = IFCQ_ALTQ(ifq);
#endif /* PF_ALTQ */
	struct mbuf *m;

	VERIFY(!drvmgt || MBUF_VALID_SC(sc));

#if PF_ALTQ
	if (drvmgt) {
		if (IFCQ_TBR_IS_ENABLED(ifq))
			IFCQ_TBR_POLL_SC(ifq, sc, m);
		else if (IFCQ_IS_DRAINING(ifq))
			IFCQ_POLL_SC(ifq, sc, m);
		else if (ALTQ_IS_ENABLED(altq))
			ALTQ_POLL_SC(altq, sc, m);
		else
			m = NULL;
	} else {
		if (IFCQ_TBR_IS_ENABLED(ifq))
			IFCQ_TBR_POLL(ifq, m);
		else if (IFCQ_IS_DRAINING(ifq))
			IFCQ_POLL(ifq, m);
		else if (ALTQ_IS_ENABLED(altq))
			ALTQ_POLL(altq, m);
		else
			m = NULL;
	}
#else /* ! PF_ALTQ */
	if (drvmgt) {
		if (IFCQ_TBR_IS_ENABLED(ifq))
			IFCQ_TBR_POLL_SC(ifq, sc, m);
		else
			IFCQ_POLL_SC(ifq, sc, m);
	} else {
		if (IFCQ_TBR_IS_ENABLED(ifq))
			IFCQ_TBR_POLL(ifq, m);
		else
			IFCQ_POLL(ifq, m);
	}
#endif /* !PF_ALTQ */

	return (m);
}

void
ifclassq_update(struct ifclassq *ifq, cqev_t ev)
{
	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(IFCQ_IS_READY(ifq));

#if PF_ALTQ
	if (ALTQ_IS_ENABLED(IFCQ_ALTQ(ifq)))
		ALTQ_UPDATE(IFCQ_ALTQ(ifq), ev);
#endif /* PF_ALTQ */
	IFCQ_UPDATE(ifq, ev);
}

int
ifclassq_attach(struct ifclassq *ifq, u_int32_t type, void *discipline,
    ifclassq_enq_func enqueue, ifclassq_deq_func dequeue,
    ifclassq_deq_sc_func dequeue_sc, ifclassq_deq_multi_func dequeue_multi,
    ifclassq_req_func request)
{
	IFCQ_LOCK_ASSERT_HELD(ifq);

	VERIFY(ifq->ifcq_disc == NULL);
	VERIFY(enqueue != NULL);
	VERIFY(!(dequeue != NULL && dequeue_sc != NULL));
	VERIFY(request != NULL);

	ifq->ifcq_type = type;
	ifq->ifcq_disc = discipline;
	ifq->ifcq_enqueue = enqueue;
	ifq->ifcq_dequeue = dequeue;
	ifq->ifcq_dequeue_sc = dequeue_sc;
	ifq->ifcq_dequeue_multi = dequeue_multi;
	ifq->ifcq_request = request;

	return (0);
}

int
ifclassq_detach(struct ifclassq *ifq)
{
	IFCQ_LOCK_ASSERT_HELD(ifq);

	VERIFY(ifq->ifcq_disc == NULL);

	ifq->ifcq_type = PKTSCHEDT_NONE;
	ifq->ifcq_disc = NULL;
	ifq->ifcq_enqueue = NULL;
	ifq->ifcq_dequeue = NULL;
	ifq->ifcq_dequeue_sc = NULL;
	ifq->ifcq_request = NULL;

	return (0);
}

int
ifclassq_getqstats(struct ifclassq *ifq, u_int32_t qid, void *ubuf,
    u_int32_t *nbytes)
{
	struct if_ifclassq_stats *ifqs;
	int err;

	if (*nbytes < sizeof (*ifqs))
		return (EINVAL);

	ifqs = _MALLOC(sizeof (*ifqs), M_TEMP, M_WAITOK | M_ZERO);
	if (ifqs == NULL)
		return (ENOMEM);

	IFCQ_LOCK(ifq);
	if (!IFCQ_IS_READY(ifq)) {
		IFCQ_UNLOCK(ifq);
		_FREE(ifqs, M_TEMP);
		return (ENXIO);
	}

	ifqs->ifqs_len = IFCQ_LEN(ifq);
	ifqs->ifqs_maxlen = IFCQ_MAXLEN(ifq);
	*(&ifqs->ifqs_xmitcnt) = *(&ifq->ifcq_xmitcnt);
	*(&ifqs->ifqs_dropcnt) = *(&ifq->ifcq_dropcnt);
	ifqs->ifqs_scheduler = ifq->ifcq_type;

	err = pktsched_getqstats(ifq, qid, ifqs);
	IFCQ_UNLOCK(ifq);

	if (err == 0 && (err = copyout((caddr_t)ifqs,
	    (user_addr_t)(uintptr_t)ubuf, sizeof (*ifqs))) == 0)
		*nbytes = sizeof (*ifqs);

	_FREE(ifqs, M_TEMP);

	return (err);
}

const char *
ifclassq_ev2str(cqev_t ev)
{
	const char *c;

	switch (ev) {
	case CLASSQ_EV_LINK_BANDWIDTH:
		c = "LINK_BANDWIDTH";
		break;

	case CLASSQ_EV_LINK_LATENCY:
		c = "LINK_LATENCY";
		break;

	case CLASSQ_EV_LINK_MTU:
		c = "LINK_MTU";
		break;

	case CLASSQ_EV_LINK_UP:
		c = "LINK_UP";
		break;

	case CLASSQ_EV_LINK_DOWN:
		c = "LINK_DOWN";
		break;

	default:
		c = "UNKNOWN";
		break;
	}

	return (c);
}

/*
 * internal representation of token bucket parameters
 *	rate:	byte_per_unittime << 32
 *		(((bits_per_sec) / 8) << 32) / machclk_freq
 *	depth:	byte << 32
 *
 */
#define	TBR_SHIFT	32
#define	TBR_SCALE(x)	((int64_t)(x) << TBR_SHIFT)
#define	TBR_UNSCALE(x)	((x) >> TBR_SHIFT)

struct mbuf *
ifclassq_tbr_dequeue(struct ifclassq *ifq, int op)
{
	return (ifclassq_tbr_dequeue_common(ifq, op, MBUF_SC_UNSPEC, FALSE));
}

struct mbuf *
ifclassq_tbr_dequeue_sc(struct ifclassq *ifq, int op, mbuf_svc_class_t sc)
{
	return (ifclassq_tbr_dequeue_common(ifq, op, sc, TRUE));
}

static struct mbuf *
ifclassq_tbr_dequeue_common(struct ifclassq *ifq, int op,
    mbuf_svc_class_t sc, boolean_t drvmgt)
{
	struct tb_regulator *tbr;
	struct mbuf *m;
	int64_t interval;
	u_int64_t now;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	VERIFY(!drvmgt || MBUF_VALID_SC(sc));
	VERIFY(IFCQ_TBR_IS_ENABLED(ifq));

	tbr = &ifq->ifcq_tbr;
	if (op == CLASSQDQ_REMOVE && tbr->tbr_lastop == CLASSQDQ_POLL) {
		/* if this is a remove after poll, bypass tbr check */
	} else {
		/* update token only when it is negative */
		if (tbr->tbr_token <= 0) {
			now = read_machclk();
			interval = now - tbr->tbr_last;
			if (interval >= tbr->tbr_filluptime) {
				tbr->tbr_token = tbr->tbr_depth;
			} else {
				tbr->tbr_token += interval * tbr->tbr_rate;
				if (tbr->tbr_token > tbr->tbr_depth)
					tbr->tbr_token = tbr->tbr_depth;
			}
			tbr->tbr_last = now;
		}
		/* if token is still negative, don't allow dequeue */
		if (tbr->tbr_token <= 0)
			return (NULL);
	}

	/*
	 * ifclassq takes precedence over ALTQ queue;
	 * ifcq_drain count is adjusted by the caller.
	 */
#if PF_ALTQ
	if (IFCQ_IS_DRAINING(ifq)) {
#endif /* PF_ALTQ */
		if (op == CLASSQDQ_POLL) {
			if (drvmgt)
				IFCQ_POLL_SC(ifq, sc, m);
			else
				IFCQ_POLL(ifq, m);
		} else {
			if (drvmgt)
				IFCQ_DEQUEUE_SC(ifq, sc, m);
			else
				IFCQ_DEQUEUE(ifq, m);
		}
#if PF_ALTQ
	} else {
		struct ifaltq *altq = IFCQ_ALTQ(ifq);
		if (ALTQ_IS_ENABLED(altq)) {
			if (drvmgt)
				m = (*altq->altq_dequeue_sc)(altq, sc, op);
			else
				m = (*altq->altq_dequeue)(altq, op);
		} else {
			m = NULL;
		}
	}
#endif /* PF_ALTQ */

	if (m != NULL && op == CLASSQDQ_REMOVE)
		tbr->tbr_token -= TBR_SCALE(m_pktlen(m));
	tbr->tbr_lastop = op;

	return (m);
}

/*
 * set a token bucket regulator.
 * if the specified rate is zero, the token bucket regulator is deleted.
 */
int
ifclassq_tbr_set(struct ifclassq *ifq, struct tb_profile *profile,
    boolean_t update)
{
	struct tb_regulator *tbr;
	struct ifnet *ifp = ifq->ifcq_ifp;
	u_int64_t rate, old_rate;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(IFCQ_IS_READY(ifq));

	VERIFY(machclk_freq != 0);

	tbr = &ifq->ifcq_tbr;
	old_rate = tbr->tbr_rate_raw;

	rate = profile->rate;
	if (profile->percent > 0) {
		u_int64_t eff_rate;

		if (profile->percent > 100)
			return (EINVAL);
		if ((eff_rate = ifp->if_output_bw.eff_bw) == 0)
			return (ENODEV);
		rate = (eff_rate * profile->percent) / 100;
	}

	if (rate == 0) {
		if (!IFCQ_TBR_IS_ENABLED(ifq))
			return (ENOENT);

		if (pktsched_verbose)
			printf("%s: TBR disabled\n", if_name(ifp));

		/* disable this TBR */
		ifq->ifcq_flags &= ~IFCQF_TBR;
		bzero(tbr, sizeof (*tbr));
		ifnet_set_start_cycle(ifp, NULL);
		if (update)
			ifclassq_update(ifq, CLASSQ_EV_LINK_BANDWIDTH);
		return (0);
	}

	if (pktsched_verbose) {
		printf("%s: TBR %s (rate %llu bps depth %u)\n", if_name(ifp),
		    (ifq->ifcq_flags & IFCQF_TBR) ? "reconfigured" :
		    "enabled", rate, profile->depth);
	}

	/* set the new TBR */
	bzero(tbr, sizeof (*tbr));
	tbr->tbr_rate_raw = rate;
	tbr->tbr_percent = profile->percent;
	ifq->ifcq_flags |= IFCQF_TBR;

	/*
	 * Note that the TBR fill up time (hence the ifnet restart time)
	 * is directly related to the specified TBR depth.  The ideal
	 * depth value should be computed such that the interval time
	 * between each successive wakeup is adequately spaced apart,
	 * in order to reduce scheduling overheads.  A target interval
	 * of 10 ms seems to provide good performance balance.  This can be
	 * overridden by specifying the depth profile.  Values smaller than
	 * the ideal depth will reduce delay at the expense of CPU cycles.
	 */
	tbr->tbr_rate = TBR_SCALE(rate / 8) / machclk_freq;
	if (tbr->tbr_rate > 0) {
		u_int32_t mtu = ifp->if_mtu;
		int64_t ival, idepth = 0;
		int i;

		if (mtu < IF_MINMTU)
			mtu = IF_MINMTU;

		ival = pktsched_nsecs_to_abstime(10 * NSEC_PER_MSEC); /* 10ms */

		for (i = 1; ; i++) {
			idepth = TBR_SCALE(i * mtu);
			if ((idepth / tbr->tbr_rate) > ival)
				break;
		}
		VERIFY(idepth > 0);

		tbr->tbr_depth = TBR_SCALE(profile->depth);
		if (tbr->tbr_depth == 0) {
			tbr->tbr_filluptime = idepth / tbr->tbr_rate;
			/* a little fudge factor to get closer to rate */
			tbr->tbr_depth = idepth + (idepth >> 3);
		} else {
			tbr->tbr_filluptime = tbr->tbr_depth / tbr->tbr_rate;
		}
	} else {
		tbr->tbr_depth = TBR_SCALE(profile->depth);
		tbr->tbr_filluptime = 0xffffffffffffffffLL;
	}
	tbr->tbr_token = tbr->tbr_depth;
	tbr->tbr_last = read_machclk();
	tbr->tbr_lastop = CLASSQDQ_REMOVE;

	if (tbr->tbr_rate > 0 && (ifp->if_flags & IFF_UP)) {
		struct timespec ts =
		    { 0, pktsched_abs_to_nsecs(tbr->tbr_filluptime) };
		if (pktsched_verbose) {
			printf("%s: TBR calculated tokens %lld "
			    "filluptime %llu ns\n", if_name(ifp),
			    TBR_UNSCALE(tbr->tbr_token),
			    pktsched_abs_to_nsecs(tbr->tbr_filluptime));
		}
		ifnet_set_start_cycle(ifp, &ts);
	} else {
		if (pktsched_verbose) {
			if (tbr->tbr_rate == 0) {
				printf("%s: TBR calculated tokens %lld "
				    "infinite filluptime\n", if_name(ifp),
				    TBR_UNSCALE(tbr->tbr_token));
			} else if (!(ifp->if_flags & IFF_UP)) {
				printf("%s: TBR suspended (link is down)\n",
				    if_name(ifp));
			}
		}
		ifnet_set_start_cycle(ifp, NULL);
	}
	if (update && tbr->tbr_rate_raw != old_rate)
		ifclassq_update(ifq, CLASSQ_EV_LINK_BANDWIDTH);

	return (0);
}

void
ifclassq_calc_target_qdelay(struct ifnet *ifp, u_int64_t *if_target_qdelay)
{
	u_int64_t target_qdelay = 0;
	target_qdelay = IFCQ_TARGET_QDELAY(&ifp->if_snd);

	if (ifclassq_target_qdelay != 0)
		target_qdelay = ifclassq_target_qdelay;

	/*
	 * If we do not know the effective bandwidth, use the default
	 * target queue delay.
	 */
	if (target_qdelay == 0)
		target_qdelay = IFQ_TARGET_DELAY;

	/*
	 * If a delay has been added to ifnet start callback for
	 * coalescing, we have to add that to the pre-set target delay
	 * because the packets can be in the queue longer.
	 */
	if ((ifp->if_eflags & IFEF_ENQUEUE_MULTI) &&
	    ifp->if_start_delay_timeout > 0)
		target_qdelay += ifp->if_start_delay_timeout;

	*(if_target_qdelay) = target_qdelay;
}

void
ifclassq_calc_update_interval(u_int64_t *update_interval)
{
	u_int64_t uint = 0;

	/* If the system level override is set, use it */
	if (ifclassq_update_interval != 0)
		uint = ifclassq_update_interval;

	/* Otherwise use the default value */
	if (uint == 0)
		uint = IFQ_UPDATE_INTERVAL;

	*update_interval = uint;
}
