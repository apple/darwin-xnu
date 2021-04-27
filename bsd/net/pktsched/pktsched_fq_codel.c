/*
 * Copyright (c) 2016-2020 Apple Inc. All rights reserved.
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

#include <sys/types.h>
#include <sys/param.h>
#include <kern/zalloc.h>
#include <net/ethernet.h>
#include <net/if_var.h>
#include <net/if.h>
#include <net/classq/classq.h>
#include <net/classq/classq_fq_codel.h>
#include <net/pktsched/pktsched_fq_codel.h>
#include <os/log.h>

#define FQ_CODEL_DEFAULT_QUANTUM 1500

#define FQ_CODEL_QUANTUM_BK_SYS(_q)    (_q)
#define FQ_CODEL_QUANTUM_BK(_q)        (_q)
#define FQ_CODEL_QUANTUM_BE(_q)        (_q)
#define FQ_CODEL_QUANTUM_RD(_q)        (_q)
#define FQ_CODEL_QUANTUM_OAM(_q)       (_q)
#define FQ_CODEL_QUANTUM_AV(_q)        (_q * 2)
#define FQ_CODEL_QUANTUM_RV(_q)        (_q * 2)
#define FQ_CODEL_QUANTUM_VI(_q)        (_q * 2)
#define FQ_CODEL_QUANTUM_VO(_q)        ((_q * 2) / 5)
#define FQ_CODEL_QUANTUM_CTL(_q)       ((_q * 2) / 5)

#define FQ_CODEL_DRR_MAX_BK_SYS    2
#define FQ_CODEL_DRR_MAX_BK        2
#define FQ_CODEL_DRR_MAX_BE        4
#define FQ_CODEL_DRR_MAX_RD        4
#define FQ_CODEL_DRR_MAX_OAM       4
#define FQ_CODEL_DRR_MAX_AV        6
#define FQ_CODEL_DRR_MAX_RV        6
#define FQ_CODEL_DRR_MAX_VI        6
#define FQ_CODEL_DRR_MAX_VO        8
#define FQ_CODEL_DRR_MAX_CTL       8

static ZONE_DECLARE(fq_if_zone, "pktsched_fq_if", sizeof(fq_if_t), ZC_ZFREE_CLEARMEM);

typedef STAILQ_HEAD(, flowq) flowq_dqlist_t;

static fq_if_t *fq_if_alloc(struct ifnet *, classq_pkt_type_t);
static void fq_if_destroy(fq_if_t *fqs);
static void fq_if_classq_init(fq_if_t *fqs, uint32_t priority,
    uint16_t quantum, uint32_t drr_max, uint32_t svc_class);
static void fq_if_dequeue(fq_if_t *, fq_if_classq_t *, uint32_t,
    int64_t, classq_pkt_t *, classq_pkt_t *, uint32_t *,
    uint32_t *, flowq_dqlist_t *, boolean_t drvmgmt);
void fq_if_stat_sc(fq_if_t *fqs, cqrq_stat_sc_t *stat);
static void fq_if_purge(fq_if_t *);
static void fq_if_purge_classq(fq_if_t *, fq_if_classq_t *);
static void fq_if_purge_flow(fq_if_t *, fq_t *, u_int32_t *, u_int32_t *);
static void fq_if_empty_new_flow(fq_t *fq, fq_if_classq_t *fq_cl,
    bool add_to_old);
static void fq_if_empty_old_flow(fq_if_t *fqs, fq_if_classq_t *fq_cl,
    fq_t *fq, bool remove_hash, bool destroy);

#define FQ_IF_FLOW_HASH_ID(_flowid_) \
	(((_flowid_) >> FQ_IF_HASH_TAG_SHIFT) & FQ_IF_HASH_TAG_MASK)

#define FQ_IF_CLASSQ_IDLE(_fcl_) \
	(STAILQ_EMPTY(&(_fcl_)->fcl_new_flows) && \
	STAILQ_EMPTY(&(_fcl_)->fcl_old_flows))

typedef void (* fq_if_append_pkt_t)(classq_pkt_t *, classq_pkt_t *);
typedef boolean_t (* fq_getq_flow_t)(fq_if_t *, fq_if_classq_t *, fq_t *,
    int64_t, u_int32_t, classq_pkt_t *, classq_pkt_t *, u_int32_t *,
    u_int32_t *, boolean_t *, u_int32_t);

static void
fq_if_append_mbuf(classq_pkt_t *pkt, classq_pkt_t *next_pkt)
{
	pkt->cp_mbuf->m_nextpkt = next_pkt->cp_mbuf;
}



static boolean_t
fq_getq_flow_mbuf(fq_if_t *fqs, fq_if_classq_t *fq_cl, fq_t *fq,
    int64_t byte_limit, u_int32_t pkt_limit, classq_pkt_t *head,
    classq_pkt_t *tail, u_int32_t *byte_cnt, u_int32_t *pkt_cnt,
    boolean_t *qempty, u_int32_t pflags)
{
	u_int32_t plen;
	pktsched_pkt_t pkt;
	boolean_t limit_reached = FALSE;
	struct ifclassq *ifq = fqs->fqs_ifq;
	struct ifnet *ifp = ifq->ifcq_ifp;

	while (fq->fq_deficit > 0 && limit_reached == FALSE &&
	    !MBUFQ_EMPTY(&fq->fq_mbufq)) {
		_PKTSCHED_PKT_INIT(&pkt);
		fq_getq_flow(fqs, fq, &pkt);
		ASSERT(pkt.pktsched_ptype == QP_MBUF);

		plen = pktsched_get_pkt_len(&pkt);
		fq->fq_deficit -= plen;
		pkt.pktsched_pkt_mbuf->m_pkthdr.pkt_flags |= pflags;

		if (head->cp_mbuf == NULL) {
			*head = pkt.pktsched_pkt;
		} else {
			ASSERT(tail->cp_mbuf != NULL);
			ASSERT(tail->cp_mbuf->m_nextpkt == NULL);
			tail->cp_mbuf->m_nextpkt = pkt.pktsched_pkt_mbuf;
		}
		*tail = pkt.pktsched_pkt;
		tail->cp_mbuf->m_nextpkt = NULL;
		fq_cl->fcl_stat.fcl_dequeue++;
		fq_cl->fcl_stat.fcl_dequeue_bytes += plen;
		*pkt_cnt += 1;
		*byte_cnt += plen;

		ifclassq_set_packet_metadata(ifq, ifp, &pkt.pktsched_pkt);

		/* Check if the limit is reached */
		if (*pkt_cnt >= pkt_limit || *byte_cnt >= byte_limit) {
			limit_reached = TRUE;
		}
	}

	*qempty = MBUFQ_EMPTY(&fq->fq_mbufq);
	return limit_reached;
}

fq_if_t *
fq_if_alloc(struct ifnet *ifp, classq_pkt_type_t ptype)
{
	fq_if_t *fqs;

	fqs = zalloc_flags(fq_if_zone, Z_WAITOK | Z_ZERO);
	fqs->fqs_ifq = &ifp->if_snd;
	fqs->fqs_ptype = ptype;

	/* Calculate target queue delay */
	ifclassq_calc_target_qdelay(ifp, &fqs->fqs_target_qdelay);

	/* Calculate update interval */
	ifclassq_calc_update_interval(&fqs->fqs_update_interval);

	/* Configure packet drop limit across all queues */
	fqs->fqs_pkt_droplimit = IFCQ_PKT_DROP_LIMIT(&ifp->if_snd);
	STAILQ_INIT(&fqs->fqs_fclist);
	return fqs;
}

void
fq_if_destroy(fq_if_t *fqs)
{
	fq_if_purge(fqs);
	fqs->fqs_ifq = NULL;
	zfree(fq_if_zone, fqs);
}

static inline uint8_t
fq_if_service_to_priority(fq_if_t *fqs, mbuf_svc_class_t svc)
{
	uint8_t pri;

	if (fqs->fqs_flags & FQS_DRIVER_MANAGED) {
		switch (svc) {
		case MBUF_SC_BK_SYS:
		case MBUF_SC_BK:
			pri = FQ_IF_BK_INDEX;
			break;
		case MBUF_SC_BE:
		case MBUF_SC_RD:
		case MBUF_SC_OAM:
			pri = FQ_IF_BE_INDEX;
			break;
		case MBUF_SC_AV:
		case MBUF_SC_RV:
		case MBUF_SC_VI:
		case MBUF_SC_SIG:
			pri = FQ_IF_VI_INDEX;
			break;
		case MBUF_SC_VO:
		case MBUF_SC_CTL:
			pri = FQ_IF_VO_INDEX;
			break;
		default:
			pri = FQ_IF_BE_INDEX; /* Use best effort by default */
			break;
		}
		return pri;
	}

	/* scheduler is not managed by the driver */
	switch (svc) {
	case MBUF_SC_BK_SYS:
		pri = FQ_IF_BK_SYS_INDEX;
		break;
	case MBUF_SC_BK:
		pri = FQ_IF_BK_INDEX;
		break;
	case MBUF_SC_BE:
		pri = FQ_IF_BE_INDEX;
		break;
	case MBUF_SC_RD:
		pri = FQ_IF_RD_INDEX;
		break;
	case MBUF_SC_OAM:
		pri = FQ_IF_OAM_INDEX;
		break;
	case MBUF_SC_AV:
		pri = FQ_IF_AV_INDEX;
		break;
	case MBUF_SC_RV:
		pri = FQ_IF_RV_INDEX;
		break;
	case MBUF_SC_VI:
		pri = FQ_IF_VI_INDEX;
		break;
	case MBUF_SC_SIG:
		pri = FQ_IF_SIG_INDEX;
		break;
	case MBUF_SC_VO:
		pri = FQ_IF_VO_INDEX;
		break;
	case MBUF_SC_CTL:
		pri = FQ_IF_CTL_INDEX;
		break;
	default:
		pri = FQ_IF_BE_INDEX; /* Use best effort by default */
		break;
	}
	return pri;
}

static void
fq_if_classq_init(fq_if_t *fqs, uint32_t pri, uint16_t quantum,
    uint32_t drr_max, uint32_t svc_class)
{
	fq_if_classq_t *fq_cl;
	VERIFY(pri < FQ_IF_MAX_CLASSES);
	fq_cl = &fqs->fqs_classq[pri];

	VERIFY(fq_cl->fcl_quantum == 0);
	fq_cl->fcl_quantum = quantum;
	fq_cl->fcl_pri = pri;
	fq_cl->fcl_drr_max = drr_max;
	fq_cl->fcl_service_class = svc_class;
	STAILQ_INIT(&fq_cl->fcl_new_flows);
	STAILQ_INIT(&fq_cl->fcl_old_flows);
}

int
fq_if_enqueue_classq(struct ifclassq *ifq, classq_pkt_t *head,
    classq_pkt_t *tail, uint32_t cnt, uint32_t bytes, boolean_t *pdrop)
{
	uint8_t pri;
	fq_if_t *fqs;
	fq_if_classq_t *fq_cl;
	int ret;
	mbuf_svc_class_t svc;
	pktsched_pkt_t pkt;

	pktsched_pkt_encap_chain(&pkt, head, tail, cnt, bytes);

	fqs = (fq_if_t *)ifq->ifcq_disc;
	svc = pktsched_get_pkt_svc(&pkt);
	pri = fq_if_service_to_priority(fqs, svc);
	VERIFY(pri < FQ_IF_MAX_CLASSES);
	fq_cl = &fqs->fqs_classq[pri];

	if (__improbable(svc == MBUF_SC_BK_SYS && fqs->fqs_throttle == 1)) {
		/* BK_SYS is currently throttled */
		atomic_add_32(&fq_cl->fcl_stat.fcl_throttle_drops, 1);
		pktsched_free_pkt(&pkt);
		*pdrop = TRUE;
		ret = EQSUSPENDED;
		goto done;
	}

	IFCQ_LOCK_SPIN(ifq);
	ret = fq_addq(fqs, &pkt, fq_cl);
	if (!(fqs->fqs_flags & FQS_DRIVER_MANAGED) &&
	    !FQ_IF_CLASSQ_IDLE(fq_cl)) {
		if (((fqs->fqs_bitmaps[FQ_IF_ER] | fqs->fqs_bitmaps[FQ_IF_EB]) &
		    (1 << pri)) == 0) {
			/*
			 * this group is not in ER or EB groups,
			 * mark it as IB
			 */
			pktsched_bit_set(pri, &fqs->fqs_bitmaps[FQ_IF_IB]);
		}
	}

	if (__improbable(ret != 0)) {
		if (ret == CLASSQEQ_SUCCESS_FC) {
			/* packet enqueued, return advisory feedback */
			ret = EQFULL;
			*pdrop = FALSE;
		} else if (ret == CLASSQEQ_COMPRESSED) {
			ret = 0;
			*pdrop = FALSE;
		} else {
			IFCQ_UNLOCK(ifq);
			*pdrop = TRUE;
			pktsched_free_pkt(&pkt);
			switch (ret) {
			case CLASSQEQ_DROP:
				ret = ENOBUFS;
				goto done;
			case CLASSQEQ_DROP_FC:
				ret = EQFULL;
				goto done;
			case CLASSQEQ_DROP_SP:
				ret = EQSUSPENDED;
				goto done;
			default:
				VERIFY(0);
				/* NOTREACHED */
				__builtin_unreachable();
			}
			/* NOTREACHED */
			__builtin_unreachable();
		}
	} else {
		*pdrop = FALSE;
	}
	IFCQ_ADD_LEN(ifq, cnt);
	IFCQ_INC_BYTES(ifq, bytes);
	IFCQ_UNLOCK(ifq);
done:
#if DEBUG || DEVELOPMENT
	if (__improbable((ret == EQFULL) && (ifclassq_flow_control_adv == 0))) {
		ret = 0;
	}
#endif /* DEBUG || DEVELOPMENT */
	return ret;
}

void
fq_if_dequeue_classq(struct ifclassq *ifq, classq_pkt_t *pkt)
{
	(void) fq_if_dequeue_classq_multi(ifq, 1,
	    CLASSQ_DEQUEUE_MAX_BYTE_LIMIT, pkt, NULL, NULL, NULL);
}

void
fq_if_dequeue_sc_classq(struct ifclassq *ifq, mbuf_svc_class_t svc,
    classq_pkt_t *pkt)
{
	fq_if_t *fqs = (fq_if_t *)ifq->ifcq_disc;
	uint32_t total_pktcnt = 0, total_bytecnt = 0;
	fq_if_classq_t *fq_cl;
	uint8_t pri;

	pri = fq_if_service_to_priority(fqs, svc);
	fq_cl = &fqs->fqs_classq[pri];

	fq_if_dequeue(fqs, fq_cl, 1, CLASSQ_DEQUEUE_MAX_BYTE_LIMIT,
	    pkt, NULL, &total_pktcnt, &total_bytecnt, NULL, TRUE);

	IFCQ_XMIT_ADD(ifq, total_pktcnt, total_bytecnt);
}

static inline void
fq_dqlist_add(flowq_dqlist_t *fq_dqlist_head, fq_t *fq)
{
	ASSERT(fq->fq_dq_head.cp_mbuf == NULL);
	ASSERT(!fq->fq_in_dqlist);
	STAILQ_INSERT_TAIL(fq_dqlist_head, fq, fq_dqlink);
	fq->fq_in_dqlist = true;
}

static inline void
fq_dqlist_remove(flowq_dqlist_t *fq_dqlist_head, fq_t *fq, classq_pkt_t *head,
    classq_pkt_t *tail)
{
	ASSERT(fq->fq_in_dqlist);
	if (fq->fq_dq_head.cp_mbuf == NULL) {
		goto done;
	}

	if (head->cp_mbuf == NULL) {
		*head = fq->fq_dq_head;
	} else {
		ASSERT(tail->cp_mbuf != NULL);

		switch (fq->fq_ptype) {
		case QP_MBUF:
			ASSERT(tail->cp_mbuf->m_nextpkt == NULL);
			tail->cp_mbuf->m_nextpkt = fq->fq_dq_head.cp_mbuf;
			ASSERT(fq->fq_dq_tail.cp_mbuf->m_nextpkt == NULL);
			break;
		default:
			VERIFY(0);
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}
	*tail = fq->fq_dq_tail;
done:
	STAILQ_REMOVE(fq_dqlist_head, fq, flowq, fq_dqlink);
	CLASSQ_PKT_INIT(&fq->fq_dq_head);
	CLASSQ_PKT_INIT(&fq->fq_dq_tail);
	fq->fq_in_dqlist = false;
	if (fq->fq_flags & FQF_DESTROYED) {
		fq_destroy(fq);
	}
}

static inline void
fq_dqlist_get_packet_list(flowq_dqlist_t *fq_dqlist_head, classq_pkt_t *head,
    classq_pkt_t *tail)
{
	fq_t *fq, *tfq;

	STAILQ_FOREACH_SAFE(fq, fq_dqlist_head, fq_dqlink, tfq) {
		fq_dqlist_remove(fq_dqlist_head, fq, head, tail);
	}
}

int
fq_if_dequeue_classq_multi(struct ifclassq *ifq, u_int32_t maxpktcnt,
    u_int32_t maxbytecnt, classq_pkt_t *first_packet,
    classq_pkt_t *last_packet, u_int32_t *retpktcnt,
    u_int32_t *retbytecnt)
{
	uint32_t total_pktcnt = 0, total_bytecnt = 0;
	classq_pkt_t first = CLASSQ_PKT_INITIALIZER(fisrt);
	classq_pkt_t last = CLASSQ_PKT_INITIALIZER(last);
	classq_pkt_t tmp = CLASSQ_PKT_INITIALIZER(tmp);
	fq_if_append_pkt_t append_pkt;
	flowq_dqlist_t fq_dqlist_head;
	fq_if_classq_t *fq_cl;
	fq_if_t *fqs;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	fqs = (fq_if_t *)ifq->ifcq_disc;
	STAILQ_INIT(&fq_dqlist_head);

	switch (fqs->fqs_ptype) {
	case QP_MBUF:
		append_pkt = fq_if_append_mbuf;
		break;


	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	for (;;) {
		uint32_t pktcnt = 0, bytecnt = 0;
		classq_pkt_t head = CLASSQ_PKT_INITIALIZER(head);
		classq_pkt_t tail = CLASSQ_PKT_INITIALIZER(tail);

		if (fqs->fqs_bitmaps[FQ_IF_ER] == 0 &&
		    fqs->fqs_bitmaps[FQ_IF_EB] == 0) {
			fqs->fqs_bitmaps[FQ_IF_EB] = fqs->fqs_bitmaps[FQ_IF_IB];
			fqs->fqs_bitmaps[FQ_IF_IB] = 0;
			if (fqs->fqs_bitmaps[FQ_IF_EB] == 0) {
				break;
			}
		}
		pri = pktsched_ffs(fqs->fqs_bitmaps[FQ_IF_ER]);
		if (pri == 0) {
			/*
			 * There are no ER flows, move the highest
			 * priority one from EB if there are any in that
			 * category
			 */
			pri = pktsched_ffs(fqs->fqs_bitmaps[FQ_IF_EB]);
			VERIFY(pri > 0);
			pktsched_bit_clr((pri - 1),
			    &fqs->fqs_bitmaps[FQ_IF_EB]);
			pktsched_bit_set((pri - 1),
			    &fqs->fqs_bitmaps[FQ_IF_ER]);
		}
		pri--; /* index starts at 0 */
		fq_cl = &fqs->fqs_classq[pri];

		if (fq_cl->fcl_budget <= 0) {
			/* Update the budget */
			fq_cl->fcl_budget += (min(fq_cl->fcl_drr_max,
			    fq_cl->fcl_stat.fcl_flows_cnt) *
			    fq_cl->fcl_quantum);
			if (fq_cl->fcl_budget <= 0) {
				goto state_change;
			}
		}
		fq_if_dequeue(fqs, fq_cl, (maxpktcnt - total_pktcnt),
		    (maxbytecnt - total_bytecnt), &head, &tail, &pktcnt,
		    &bytecnt, &fq_dqlist_head, FALSE);
		if (head.cp_mbuf != NULL) {
			ASSERT(STAILQ_EMPTY(&fq_dqlist_head));
			if (first.cp_mbuf == NULL) {
				first = head;
			} else {
				ASSERT(last.cp_mbuf != NULL);
				append_pkt(&last, &head);
			}
			last = tail;
			append_pkt(&last, &tmp);
		}
		fq_cl->fcl_budget -= bytecnt;
		total_pktcnt += pktcnt;
		total_bytecnt += bytecnt;

		/*
		 * If the class has exceeded the budget but still has data
		 * to send, move it to IB
		 */
state_change:
		if (!FQ_IF_CLASSQ_IDLE(fq_cl)) {
			if (fq_cl->fcl_budget <= 0) {
				pktsched_bit_set(pri,
				    &fqs->fqs_bitmaps[FQ_IF_IB]);
				pktsched_bit_clr(pri,
				    &fqs->fqs_bitmaps[FQ_IF_ER]);
			}
		} else {
			pktsched_bit_clr(pri, &fqs->fqs_bitmaps[FQ_IF_ER]);
			VERIFY(((fqs->fqs_bitmaps[FQ_IF_ER] |
			    fqs->fqs_bitmaps[FQ_IF_EB] |
			    fqs->fqs_bitmaps[FQ_IF_IB]) & (1 << pri)) == 0);
			fq_cl->fcl_budget = 0;
		}
		if (total_pktcnt >= maxpktcnt || total_bytecnt >= maxbytecnt) {
			break;
		}
	}

	fq_dqlist_get_packet_list(&fq_dqlist_head, &first, &last);

	if (__probable(first_packet != NULL)) {
		*first_packet = first;
	}
	if (last_packet != NULL) {
		*last_packet = last;
	}
	if (retpktcnt != NULL) {
		*retpktcnt = total_pktcnt;
	}
	if (retbytecnt != NULL) {
		*retbytecnt = total_bytecnt;
	}

	IFCQ_XMIT_ADD(ifq, total_pktcnt, total_bytecnt);
	return 0;
}

int
fq_if_dequeue_sc_classq_multi(struct ifclassq *ifq, mbuf_svc_class_t svc,
    u_int32_t maxpktcnt, u_int32_t maxbytecnt, classq_pkt_t *first_packet,
    classq_pkt_t *last_packet, u_int32_t *retpktcnt, u_int32_t *retbytecnt)
{
	fq_if_t *fqs = (fq_if_t *)ifq->ifcq_disc;
	uint8_t pri;
	u_int32_t total_pktcnt = 0, total_bytecnt = 0;
	fq_if_classq_t *fq_cl;
	classq_pkt_t first = CLASSQ_PKT_INITIALIZER(fisrt);
	classq_pkt_t last = CLASSQ_PKT_INITIALIZER(last);
	fq_if_append_pkt_t append_pkt;
	flowq_dqlist_t fq_dqlist_head;

	switch (fqs->fqs_ptype) {
	case QP_MBUF:
		append_pkt = fq_if_append_mbuf;
		break;


	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	STAILQ_INIT(&fq_dqlist_head);
	pri = fq_if_service_to_priority(fqs, svc);
	fq_cl = &fqs->fqs_classq[pri];
	/*
	 * Now we have the queue for a particular service class. We need
	 * to dequeue as many packets as needed, first from the new flows
	 * and then from the old flows.
	 */
	while (total_pktcnt < maxpktcnt && total_bytecnt < maxbytecnt &&
	    fq_cl->fcl_stat.fcl_pkt_cnt > 0) {
		classq_pkt_t head = CLASSQ_PKT_INITIALIZER(head);
		classq_pkt_t tail = CLASSQ_PKT_INITIALIZER(tail);
		u_int32_t pktcnt = 0, bytecnt = 0;

		fq_if_dequeue(fqs, fq_cl, (maxpktcnt - total_pktcnt),
		    (maxbytecnt - total_bytecnt), &head, &tail, &pktcnt,
		    &bytecnt, &fq_dqlist_head, TRUE);
		if (head.cp_mbuf != NULL) {
			if (first.cp_mbuf == NULL) {
				first = head;
			} else {
				ASSERT(last.cp_mbuf != NULL);
				append_pkt(&last, &head);
			}
			last = tail;
		}
		total_pktcnt += pktcnt;
		total_bytecnt += bytecnt;
	}

	fq_dqlist_get_packet_list(&fq_dqlist_head, &first, &last);

	if (__probable(first_packet != NULL)) {
		*first_packet = first;
	}
	if (last_packet != NULL) {
		*last_packet = last;
	}
	if (retpktcnt != NULL) {
		*retpktcnt = total_pktcnt;
	}
	if (retbytecnt != NULL) {
		*retbytecnt = total_bytecnt;
	}

	IFCQ_XMIT_ADD(ifq, total_pktcnt, total_bytecnt);

	return 0;
}

static void
fq_if_purge_flow(fq_if_t *fqs, fq_t *fq, u_int32_t *pktsp,
    u_int32_t *bytesp)
{
	fq_if_classq_t *fq_cl;
	u_int32_t pkts, bytes;
	pktsched_pkt_t pkt;

	fq_cl = &fqs->fqs_classq[fq->fq_sc_index];
	pkts = bytes = 0;
	_PKTSCHED_PKT_INIT(&pkt);
	for (;;) {
		fq_getq_flow(fqs, fq, &pkt);
		if (pkt.pktsched_pkt_mbuf == NULL) {
			VERIFY(pkt.pktsched_ptype == QP_INVALID);
			break;
		}
		pkts++;
		bytes += pktsched_get_pkt_len(&pkt);
		pktsched_free_pkt(&pkt);
	}
	IFCQ_DROP_ADD(fqs->fqs_ifq, pkts, bytes);

	if (fq->fq_flags & FQF_NEW_FLOW) {
		fq_if_empty_new_flow(fq, fq_cl, false);
	} else if (fq->fq_flags & FQF_OLD_FLOW) {
		fq_if_empty_old_flow(fqs, fq_cl, fq, false, true);
	}

	fq_if_destroy_flow(fqs, fq_cl, fq, true);

	if (FQ_IF_CLASSQ_IDLE(fq_cl)) {
		int i;
		for (i = FQ_IF_ER; i < FQ_IF_MAX_STATE; i++) {
			pktsched_bit_clr(fq_cl->fcl_pri,
			    &fqs->fqs_bitmaps[i]);
		}
	}
	if (pktsp != NULL) {
		*pktsp = pkts;
	}
	if (bytesp != NULL) {
		*bytesp = bytes;
	}
}

static void
fq_if_purge_classq(fq_if_t *fqs, fq_if_classq_t *fq_cl)
{
	fq_t *fq, *tfq;
	/*
	 * Take each flow from new/old flow list and flush mbufs
	 * in that flow
	 */
	STAILQ_FOREACH_SAFE(fq, &fq_cl->fcl_new_flows, fq_actlink, tfq) {
		fq_if_purge_flow(fqs, fq, NULL, NULL);
	}
	STAILQ_FOREACH_SAFE(fq, &fq_cl->fcl_old_flows, fq_actlink, tfq) {
		fq_if_purge_flow(fqs, fq, NULL, NULL);
	}
	VERIFY(STAILQ_EMPTY(&fq_cl->fcl_new_flows));
	VERIFY(STAILQ_EMPTY(&fq_cl->fcl_old_flows));

	STAILQ_INIT(&fq_cl->fcl_new_flows);
	STAILQ_INIT(&fq_cl->fcl_old_flows);
	fq_cl->fcl_budget = 0;
}

static void
fq_if_purge(fq_if_t *fqs)
{
	int i;

	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	for (i = 0; i < FQ_IF_MAX_CLASSES; i++) {
		fq_if_purge_classq(fqs, &fqs->fqs_classq[i]);
	}

	VERIFY(STAILQ_EMPTY(&fqs->fqs_fclist));

	fqs->fqs_large_flow = NULL;
	for (i = 0; i < FQ_IF_HASH_TABLE_SIZE; i++) {
		VERIFY(SLIST_EMPTY(&fqs->fqs_flows[i]));
	}

	bzero(&fqs->fqs_bitmaps, sizeof(fqs->fqs_bitmaps));

	IFCQ_LEN(fqs->fqs_ifq) = 0;
	IFCQ_BYTES(fqs->fqs_ifq) = 0;
}

static void
fq_if_purge_sc(fq_if_t *fqs, cqrq_purge_sc_t *req)
{
	fq_t *fq;

	IFCQ_LOCK_ASSERT_HELD(fqs->fqs_ifq);
	req->packets = req->bytes = 0;
	VERIFY(req->flow != 0);

	/* packet type is needed only if we want to create a flow queue */
	fq = fq_if_hash_pkt(fqs, req->flow, req->sc, 0, FALSE, QP_INVALID);

	if (fq != NULL) {
		fq_if_purge_flow(fqs, fq, &req->packets, &req->bytes);
	}
}

static uint16_t
fq_if_calc_quantum(struct ifnet *ifp)
{
	uint16_t quantum;

	switch (ifp->if_family) {
	case IFNET_FAMILY_ETHERNET:
		VERIFY((ifp->if_mtu + ETHER_HDR_LEN) <= UINT16_MAX);
		quantum = (uint16_t)ifp->if_mtu + ETHER_HDR_LEN;
		break;

	case IFNET_FAMILY_CELLULAR:
	case IFNET_FAMILY_IPSEC:
	case IFNET_FAMILY_UTUN:
		VERIFY(ifp->if_mtu <= UINT16_MAX);
		quantum = (uint16_t)ifp->if_mtu;
		break;

	default:
		quantum = FQ_CODEL_DEFAULT_QUANTUM;
		break;
	}

	/*
	 * XXX: Skywalk native interface doesn't support HW TSO offload.
	 */
	if (((ifp->if_eflags & IFEF_SKYWALK_NATIVE) == 0) &&
	    ((ifp->if_hwassist & IFNET_TSOF) != 0)) {
		VERIFY(ifp->if_tso_v4_mtu <= UINT16_MAX);
		VERIFY(ifp->if_tso_v6_mtu <= UINT16_MAX);
		quantum = (uint16_t)MAX(ifp->if_tso_v4_mtu, ifp->if_tso_v6_mtu);
		quantum = (quantum != 0) ? quantum : IF_MAXMTU;
	}

	quantum = MAX(FQ_CODEL_DEFAULT_QUANTUM, quantum);
#if DEBUG || DEVELOPMENT
	quantum = (fq_codel_quantum != 0) ? fq_codel_quantum : quantum;
#endif /* DEBUG || DEVELOPMENT */
	return quantum;
}

static void
fq_if_mtu_update(fq_if_t *fqs)
{
#define _FQ_CLASSQ_UPDATE_QUANTUM(_fqs, _s, _q)    \
	(_fqs)->fqs_classq[FQ_IF_ ## _s ## _INDEX].fcl_quantum = \
	FQ_CODEL_QUANTUM_ ## _s(_q)

	uint16_t quantum;

	quantum = fq_if_calc_quantum(fqs->fqs_ifq->ifcq_ifp);

	if ((fqs->fqs_flags & FQS_DRIVER_MANAGED) != 0) {
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, BK, quantum);
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, BE, quantum);
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, VI, quantum);
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, VO, quantum);
	} else {
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, BK_SYS, quantum);
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, BK, quantum);
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, BE, quantum);
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, RD, quantum);
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, OAM, quantum);
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, AV, quantum);
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, RV, quantum);
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, VI, quantum);
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, VO, quantum);
		_FQ_CLASSQ_UPDATE_QUANTUM(fqs, CTL, quantum);
	}
#undef _FQ_CLASSQ_UPDATE_QUANTUM
}

static void
fq_if_event(fq_if_t *fqs, cqev_t ev)
{
	IFCQ_LOCK_ASSERT_HELD(fqs->fqs_ifq);

	switch (ev) {
	case CLASSQ_EV_LINK_UP:
	case CLASSQ_EV_LINK_DOWN:
		fq_if_purge(fqs);
		break;
	case CLASSQ_EV_LINK_MTU:
		fq_if_mtu_update(fqs);
		break;
	default:
		break;
	}
}

static void
fq_if_classq_suspend(fq_if_t *fqs, fq_if_classq_t *fq_cl)
{
	fq_if_purge_classq(fqs, fq_cl);
	fqs->fqs_throttle = 1;
	fq_cl->fcl_stat.fcl_throttle_on++;
}

static void
fq_if_classq_resume(fq_if_t *fqs, fq_if_classq_t *fq_cl)
{
	VERIFY(FQ_IF_CLASSQ_IDLE(fq_cl));
	fqs->fqs_throttle = 0;
	fq_cl->fcl_stat.fcl_throttle_off++;
}


static int
fq_if_throttle(fq_if_t *fqs, cqrq_throttle_t *tr)
{
	struct ifclassq *ifq = fqs->fqs_ifq;
	uint8_t index;
#if !MACH_ASSERT
#pragma unused(ifq)
#endif
	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (!tr->set) {
		tr->level = fqs->fqs_throttle;
		return 0;
	}

	if (tr->level == fqs->fqs_throttle) {
		return EALREADY;
	}

	/* Throttling is allowed on BK_SYS class only */
	index = fq_if_service_to_priority(fqs, MBUF_SC_BK_SYS);
	switch (tr->level) {
	case IFNET_THROTTLE_OFF:
		fq_if_classq_resume(fqs, &fqs->fqs_classq[index]);
		break;
	case IFNET_THROTTLE_OPPORTUNISTIC:
		fq_if_classq_suspend(fqs, &fqs->fqs_classq[index]);
		break;
	default:
		break;
	}
	return 0;
}

void
fq_if_stat_sc(fq_if_t *fqs, cqrq_stat_sc_t *stat)
{
	uint8_t pri;
	fq_if_classq_t *fq_cl;

	if (stat == NULL) {
		return;
	}

	pri = fq_if_service_to_priority(fqs, stat->sc);
	fq_cl = &fqs->fqs_classq[pri];
	stat->packets = (uint32_t)fq_cl->fcl_stat.fcl_pkt_cnt;
	stat->bytes = (uint32_t)fq_cl->fcl_stat.fcl_byte_cnt;
}

int
fq_if_request_classq(struct ifclassq *ifq, cqrq_t rq, void *arg)
{
	int err = 0;
	fq_if_t *fqs = (fq_if_t *)ifq->ifcq_disc;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	/*
	 * These are usually slow operations, convert the lock ahead of time
	 */
	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	switch (rq) {
	case CLASSQRQ_PURGE:
		fq_if_purge(fqs);
		break;
	case CLASSQRQ_PURGE_SC:
		fq_if_purge_sc(fqs, (cqrq_purge_sc_t *)arg);
		break;
	case CLASSQRQ_EVENT:
		fq_if_event(fqs, (cqev_t)arg);
		break;
	case CLASSQRQ_THROTTLE:
		fq_if_throttle(fqs, (cqrq_throttle_t *)arg);
		break;
	case CLASSQRQ_STAT_SC:
		fq_if_stat_sc(fqs, (cqrq_stat_sc_t *)arg);
		break;
	}
	return err;
}

int
fq_if_setup_ifclassq(struct ifclassq *ifq, u_int32_t flags,
    classq_pkt_type_t ptype)
{
#pragma unused(flags)
#define _FQ_CLASSQ_INIT(_fqs, _s, _q)                         \
	fq_if_classq_init((_fqs), FQ_IF_ ## _s ## _INDEX,     \
	FQ_CODEL_QUANTUM_ ## _s(_q), FQ_CODEL_DRR_MAX_ ## _s, \
	MBUF_SC_ ## _s )

	struct ifnet *ifp = ifq->ifcq_ifp;
	fq_if_t *fqs = NULL;
	uint16_t quantum;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_disc == NULL);
	VERIFY(ifq->ifcq_type == PKTSCHEDT_NONE);

	fqs = fq_if_alloc(ifp, ptype);
	if (fqs == NULL) {
		return ENOMEM;
	}

	quantum = fq_if_calc_quantum(ifp);

	if (flags & PKTSCHEDF_QALG_DRIVER_MANAGED) {
		fqs->fqs_flags |= FQS_DRIVER_MANAGED;
		_FQ_CLASSQ_INIT(fqs, BK, quantum);
		_FQ_CLASSQ_INIT(fqs, BE, quantum);
		_FQ_CLASSQ_INIT(fqs, VI, quantum);
		_FQ_CLASSQ_INIT(fqs, VO, quantum);
	} else {
		/* SIG shares same INDEX with VI */
		_CASSERT(SCIDX_SIG == SCIDX_VI);
		_CASSERT(FQ_IF_SIG_INDEX == FQ_IF_VI_INDEX);

		_FQ_CLASSQ_INIT(fqs, BK_SYS, quantum);
		_FQ_CLASSQ_INIT(fqs, BK, quantum);
		_FQ_CLASSQ_INIT(fqs, BE, quantum);
		_FQ_CLASSQ_INIT(fqs, RD, quantum);
		_FQ_CLASSQ_INIT(fqs, OAM, quantum);
		_FQ_CLASSQ_INIT(fqs, AV, quantum);
		_FQ_CLASSQ_INIT(fqs, RV, quantum);
		_FQ_CLASSQ_INIT(fqs, VI, quantum);
		_FQ_CLASSQ_INIT(fqs, VO, quantum);
		_FQ_CLASSQ_INIT(fqs, CTL, quantum);
	}

	err = ifclassq_attach(ifq, PKTSCHEDT_FQ_CODEL, fqs);
	if (err != 0) {
		os_log_error(OS_LOG_DEFAULT, "%s: error from ifclassq_attach, "
		    "failed to attach fq_if: %d\n", __func__, err);
		fq_if_destroy(fqs);
	}
	return err;
#undef _FQ_CLASSQ_INIT
}

fq_t *
fq_if_hash_pkt(fq_if_t *fqs, u_int32_t flowid, mbuf_svc_class_t svc_class,
    u_int64_t now, boolean_t create, classq_pkt_type_t ptype)
{
	fq_t *fq = NULL;
	flowq_list_t *fq_list;
	fq_if_classq_t *fq_cl;
	u_int8_t fqs_hash_id;
	u_int8_t scidx;

	scidx = fq_if_service_to_priority(fqs, svc_class);

	fqs_hash_id = FQ_IF_FLOW_HASH_ID(flowid);

	fq_list = &fqs->fqs_flows[fqs_hash_id];

	SLIST_FOREACH(fq, fq_list, fq_hashlink) {
		if (fq->fq_flowhash == flowid &&
		    fq->fq_sc_index == scidx) {
			break;
		}
	}
	if (fq == NULL && create == TRUE) {
		ASSERT(ptype == QP_MBUF);

		/* If the flow is not already on the list, allocate it */
		IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
		fq = fq_alloc(ptype);
		if (fq != NULL) {
			fq->fq_flowhash = flowid;
			fq->fq_sc_index = scidx;
			fq->fq_updatetime = now + fqs->fqs_update_interval;
			fq_cl = &fqs->fqs_classq[scidx];
			fq->fq_flags = FQF_FLOWCTL_CAPABLE;
			SLIST_INSERT_HEAD(fq_list, fq, fq_hashlink);
			fq_cl->fcl_stat.fcl_flows_cnt++;
		}
	}

	/*
	 * If getq time is not set because this is the first packet or after
	 * idle time, set it now so that we can detect a stall.
	 */
	if (fq != NULL && fq->fq_getqtime == 0) {
		fq->fq_getqtime = now;
	}

	return fq;
}

void
fq_if_destroy_flow(fq_if_t *fqs, fq_if_classq_t *fq_cl, fq_t *fq,
    bool destroy_now)
{
	u_int8_t hash_id;
	hash_id = FQ_IF_FLOW_HASH_ID(fq->fq_flowhash);
	SLIST_REMOVE(&fqs->fqs_flows[hash_id], fq, flowq,
	    fq_hashlink);
	fq_cl->fcl_stat.fcl_flows_cnt--;
	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	fq->fq_flags |= FQF_DESTROYED;
	if (destroy_now) {
		fq_destroy(fq);
	}
}

inline boolean_t
fq_if_at_drop_limit(fq_if_t *fqs)
{
	return (IFCQ_LEN(fqs->fqs_ifq) >= fqs->fqs_pkt_droplimit) ?
	       TRUE : FALSE;
}

static void
fq_if_empty_old_flow(fq_if_t *fqs, fq_if_classq_t *fq_cl, fq_t *fq,
    bool remove_hash, bool destroy)
{
	/*
	 * Remove the flow queue if it is empty
	 * and delete it
	 */
	STAILQ_REMOVE(&fq_cl->fcl_old_flows, fq, flowq,
	    fq_actlink);
	fq->fq_flags &= ~FQF_OLD_FLOW;
	fq_cl->fcl_stat.fcl_oldflows_cnt--;
	VERIFY(fq->fq_bytes == 0);

	if (remove_hash) {
		/* Remove from the hash list */
		fq_if_destroy_flow(fqs, fq_cl, fq, destroy);
	}
}

static void
fq_if_empty_new_flow(fq_t *fq, fq_if_classq_t *fq_cl, bool add_to_old)
{
	/* Move to the end of old queue list */
	STAILQ_REMOVE(&fq_cl->fcl_new_flows, fq,
	    flowq, fq_actlink);
	fq->fq_flags &= ~FQF_NEW_FLOW;
	fq_cl->fcl_stat.fcl_newflows_cnt--;

	if (add_to_old) {
		STAILQ_INSERT_TAIL(&fq_cl->fcl_old_flows, fq,
		    fq_actlink);
		fq->fq_flags |= FQF_OLD_FLOW;
		fq_cl->fcl_stat.fcl_oldflows_cnt++;
	}
}

inline void
fq_if_drop_packet(fq_if_t *fqs)
{
	fq_t *fq = fqs->fqs_large_flow;
	fq_if_classq_t *fq_cl;
	pktsched_pkt_t pkt;
	volatile uint32_t *pkt_flags;
	uint64_t *pkt_timestamp;

	if (fq == NULL) {
		return;
	}
	/* queue can not be empty on the largest flow */
	VERIFY(!fq_empty(fq));

	fq_cl = &fqs->fqs_classq[fq->fq_sc_index];
	_PKTSCHED_PKT_INIT(&pkt);
	fq_getq_flow_internal(fqs, fq, &pkt);
	ASSERT(pkt.pktsched_ptype != QP_INVALID);

	pktsched_get_pkt_vars(&pkt, &pkt_flags, &pkt_timestamp, NULL, NULL,
	    NULL, NULL);

	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	*pkt_timestamp = 0;
	switch (pkt.pktsched_ptype) {
	case QP_MBUF:
		*pkt_flags &= ~PKTF_PRIV_GUARDED;
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (fq_empty(fq)) {
		fqs->fqs_large_flow = NULL;
		if (fq->fq_flags & FQF_OLD_FLOW) {
			fq_if_empty_old_flow(fqs, fq_cl, fq, true, true);
		} else {
			VERIFY(fq->fq_flags & FQF_NEW_FLOW);
			fq_if_empty_new_flow(fq, fq_cl, true);
		}
	}
	IFCQ_DROP_ADD(fqs->fqs_ifq, 1, pktsched_get_pkt_len(&pkt));

	pktsched_free_pkt(&pkt);
	fq_cl->fcl_stat.fcl_drop_overflow++;
}

inline void
fq_if_is_flow_heavy(fq_if_t *fqs, fq_t *fq)
{
	fq_t *prev_fq;

	if (fqs->fqs_large_flow != NULL &&
	    fqs->fqs_large_flow->fq_bytes < FQ_IF_LARGE_FLOW_BYTE_LIMIT) {
		fqs->fqs_large_flow = NULL;
	}

	if (fq == NULL || fq->fq_bytes < FQ_IF_LARGE_FLOW_BYTE_LIMIT) {
		return;
	}

	prev_fq = fqs->fqs_large_flow;
	if (prev_fq == NULL) {
		if (!fq_empty(fq)) {
			fqs->fqs_large_flow = fq;
		}
		return;
	} else if (fq->fq_bytes > prev_fq->fq_bytes) {
		fqs->fqs_large_flow = fq;
	}
}

boolean_t
fq_if_add_fcentry(fq_if_t *fqs, pktsched_pkt_t *pkt, uint8_t flowsrc,
    fq_t *fq, fq_if_classq_t *fq_cl)
{
	struct flowadv_fcentry *fce;

#if DEBUG || DEVELOPMENT
	if (__improbable(ifclassq_flow_control_adv == 0)) {
		os_log(OS_LOG_DEFAULT, "%s: skipped flow control", __func__);
		return TRUE;
	}
#endif /* DEBUG || DEVELOPMENT */

	STAILQ_FOREACH(fce, &fqs->fqs_fclist, fce_link) {
		if ((uint8_t)fce->fce_flowsrc_type == flowsrc &&
		    fce->fce_flowid == fq->fq_flowhash) {
			/* Already on flowcontrol list */
			return TRUE;
		}
	}
	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	fce = pktsched_alloc_fcentry(pkt, fqs->fqs_ifq->ifcq_ifp, M_WAITOK);
	if (fce != NULL) {
		/* XXX Add number of bytes in the queue */
		STAILQ_INSERT_TAIL(&fqs->fqs_fclist, fce, fce_link);
		fq_cl->fcl_stat.fcl_flow_control++;
		os_log(OS_LOG_DEFAULT, "%s: num: %d, scidx: %d, flowsrc: %d, "
		    "flow: 0x%x, iface: %s\n", __func__,
		    fq_cl->fcl_stat.fcl_flow_control,
		    fq->fq_sc_index, fce->fce_flowsrc_type, fq->fq_flowhash,
		    if_name(fqs->fqs_ifq->ifcq_ifp));
	}
	return (fce != NULL) ? TRUE : FALSE;
}

void
fq_if_flow_feedback(fq_if_t *fqs, fq_t *fq, fq_if_classq_t *fq_cl)
{
	struct flowadv_fcentry *fce = NULL;

	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	STAILQ_FOREACH(fce, &fqs->fqs_fclist, fce_link) {
		if (fce->fce_flowid == fq->fq_flowhash) {
			break;
		}
	}
	if (fce != NULL) {
		STAILQ_REMOVE(&fqs->fqs_fclist, fce, flowadv_fcentry,
		    fce_link);
		STAILQ_NEXT(fce, fce_link) = NULL;
		fq_cl->fcl_stat.fcl_flow_feedback++;
		os_log(OS_LOG_DEFAULT, "%s: num: %d, scidx: %d, flowsrc: %d, "
		    "flow: 0x%x, iface: %s\n", __func__,
		    fq_cl->fcl_stat.fcl_flow_feedback, fq->fq_sc_index,
		    fce->fce_flowsrc_type, fce->fce_flowid,
		    if_name(fqs->fqs_ifq->ifcq_ifp));
		flowadv_add_entry(fce);
	}
	fq->fq_flags &= ~FQF_FLOWCTL_ON;
}

void
fq_if_dequeue(fq_if_t *fqs, fq_if_classq_t *fq_cl, uint32_t pktlimit,
    int64_t bytelimit, classq_pkt_t *top, classq_pkt_t *bottom,
    uint32_t *retpktcnt, uint32_t *retbytecnt, flowq_dqlist_t *fq_dqlist,
    boolean_t drvmgmt)
{
	fq_t *fq = NULL, *tfq = NULL;
	flowq_stailq_t temp_stailq;
	uint32_t pktcnt, bytecnt;
	boolean_t qempty, limit_reached = FALSE;
	classq_pkt_t last = CLASSQ_PKT_INITIALIZER(last);
	fq_getq_flow_t fq_getq_flow_fn;
	classq_pkt_t *head, *tail;

	switch (fqs->fqs_ptype) {
	case QP_MBUF:
		fq_getq_flow_fn = fq_getq_flow_mbuf;
		break;


	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/*
	 * maximum byte limit should not be greater than the budget for
	 * this class
	 */
	if (bytelimit > fq_cl->fcl_budget && !drvmgmt) {
		bytelimit = fq_cl->fcl_budget;
	}

	VERIFY(pktlimit > 0 && bytelimit > 0 && top != NULL);
	pktcnt = bytecnt = 0;
	STAILQ_INIT(&temp_stailq);

	STAILQ_FOREACH_SAFE(fq, &fq_cl->fcl_new_flows, fq_actlink, tfq) {
		ASSERT((fq->fq_flags & (FQF_NEW_FLOW | FQF_OLD_FLOW)) ==
		    FQF_NEW_FLOW);

		if (fq_dqlist != NULL) {
			if (!fq->fq_in_dqlist) {
				fq_dqlist_add(fq_dqlist, fq);
			}
			head = &fq->fq_dq_head;
			tail = &fq->fq_dq_tail;
		} else {
			ASSERT(!fq->fq_in_dqlist);
			head = top;
			tail = &last;
		}

		limit_reached = fq_getq_flow_fn(fqs, fq_cl, fq, bytelimit,
		    pktlimit, head, tail, &bytecnt, &pktcnt, &qempty,
		    PKTF_NEW_FLOW);

		if (fq->fq_deficit <= 0 || qempty) {
			fq_if_empty_new_flow(fq, fq_cl, true);
		}
		fq->fq_deficit += fq_cl->fcl_quantum;
		if (limit_reached) {
			goto done;
		}
	}

	STAILQ_FOREACH_SAFE(fq, &fq_cl->fcl_old_flows, fq_actlink, tfq) {
		VERIFY((fq->fq_flags & (FQF_NEW_FLOW | FQF_OLD_FLOW)) ==
		    FQF_OLD_FLOW);
		bool destroy = true;

		if (fq_dqlist != NULL) {
			if (!fq->fq_in_dqlist) {
				fq_dqlist_add(fq_dqlist, fq);
			}
			head = &fq->fq_dq_head;
			tail = &fq->fq_dq_tail;
			destroy = false;
		} else {
			ASSERT(!fq->fq_in_dqlist);
			head = top;
			tail = &last;
		}

		limit_reached = fq_getq_flow_fn(fqs, fq_cl, fq, bytelimit,
		    pktlimit, head, tail, &bytecnt, &pktcnt, &qempty, 0);

		if (qempty) {
			fq_if_empty_old_flow(fqs, fq_cl, fq, true, destroy);
		} else if (fq->fq_deficit <= 0) {
			STAILQ_REMOVE(&fq_cl->fcl_old_flows, fq,
			    flowq, fq_actlink);
			/*
			 * Move to the end of the old queues list. We do not
			 * need to update the flow count since this flow
			 * will be added to the tail again
			 */
			STAILQ_INSERT_TAIL(&temp_stailq, fq, fq_actlink);
			fq->fq_deficit += fq_cl->fcl_quantum;
		}
		if (limit_reached) {
			break;
		}
	}

done:
	if (!STAILQ_EMPTY(&fq_cl->fcl_old_flows)) {
		STAILQ_CONCAT(&fq_cl->fcl_old_flows, &temp_stailq);
	} else if (!STAILQ_EMPTY(&temp_stailq)) {
		fq_cl->fcl_old_flows = temp_stailq;
	}
	if (last.cp_mbuf != NULL) {
		VERIFY(top->cp_mbuf != NULL);
		if (bottom != NULL) {
			*bottom = last;
		}
	}
	if (retpktcnt != NULL) {
		*retpktcnt = pktcnt;
	}
	if (retbytecnt != NULL) {
		*retbytecnt = bytecnt;
	}
}

void
fq_if_teardown_ifclassq(struct ifclassq *ifq)
{
	fq_if_t *fqs = (fq_if_t *)ifq->ifcq_disc;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(fqs != NULL && ifq->ifcq_type == PKTSCHEDT_FQ_CODEL);

	fq_if_destroy(fqs);
	ifq->ifcq_disc = NULL;
	ifclassq_detach(ifq);
}

static void
fq_export_flowstats(fq_if_t *fqs, fq_t *fq,
    struct fq_codel_flowstats *flowstat)
{
	bzero(flowstat, sizeof(*flowstat));
	flowstat->fqst_min_qdelay = (uint32_t)fq->fq_min_qdelay;
	flowstat->fqst_bytes = fq->fq_bytes;
	flowstat->fqst_flowhash = fq->fq_flowhash;
	if (fq->fq_flags & FQF_NEW_FLOW) {
		flowstat->fqst_flags |= FQ_FLOWSTATS_NEW_FLOW;
	}
	if (fq->fq_flags & FQF_OLD_FLOW) {
		flowstat->fqst_flags |= FQ_FLOWSTATS_OLD_FLOW;
	}
	if (fq->fq_flags & FQF_DELAY_HIGH) {
		flowstat->fqst_flags |= FQ_FLOWSTATS_DELAY_HIGH;
	}
	if (fq->fq_flags & FQF_FLOWCTL_ON) {
		flowstat->fqst_flags |= FQ_FLOWSTATS_FLOWCTL_ON;
	}
	if (fqs->fqs_large_flow == fq) {
		flowstat->fqst_flags |= FQ_FLOWSTATS_LARGE_FLOW;
	}
}

int
fq_if_getqstats_ifclassq(struct ifclassq *ifq, u_int32_t qid,
    struct if_ifclassq_stats *ifqs)
{
	struct fq_codel_classstats *fcls;
	fq_if_classq_t *fq_cl;
	fq_if_t *fqs;
	fq_t *fq = NULL;
	u_int32_t i, flowstat_cnt;

	if (qid >= FQ_IF_MAX_CLASSES) {
		return EINVAL;
	}

	fqs = (fq_if_t *)ifq->ifcq_disc;
	fcls = &ifqs->ifqs_fq_codel_stats;

	fq_cl = &fqs->fqs_classq[qid];

	fcls->fcls_pri = fq_cl->fcl_pri;
	fcls->fcls_service_class = fq_cl->fcl_service_class;
	fcls->fcls_quantum = fq_cl->fcl_quantum;
	fcls->fcls_drr_max = fq_cl->fcl_drr_max;
	fcls->fcls_budget = fq_cl->fcl_budget;
	fcls->fcls_target_qdelay = fqs->fqs_target_qdelay;
	fcls->fcls_update_interval = fqs->fqs_update_interval;
	fcls->fcls_flow_control = fq_cl->fcl_stat.fcl_flow_control;
	fcls->fcls_flow_feedback = fq_cl->fcl_stat.fcl_flow_feedback;
	fcls->fcls_dequeue_stall = fq_cl->fcl_stat.fcl_dequeue_stall;
	fcls->fcls_drop_overflow = fq_cl->fcl_stat.fcl_drop_overflow;
	fcls->fcls_drop_early = fq_cl->fcl_stat.fcl_drop_early;
	fcls->fcls_drop_memfailure = fq_cl->fcl_stat.fcl_drop_memfailure;
	fcls->fcls_flows_cnt = fq_cl->fcl_stat.fcl_flows_cnt;
	fcls->fcls_newflows_cnt = fq_cl->fcl_stat.fcl_newflows_cnt;
	fcls->fcls_oldflows_cnt = fq_cl->fcl_stat.fcl_oldflows_cnt;
	fcls->fcls_pkt_cnt = fq_cl->fcl_stat.fcl_pkt_cnt;
	fcls->fcls_flow_control_fail = fq_cl->fcl_stat.fcl_flow_control_fail;
	fcls->fcls_flow_control_fail = fq_cl->fcl_stat.fcl_flow_control_fail;
	fcls->fcls_dequeue = fq_cl->fcl_stat.fcl_dequeue;
	fcls->fcls_dequeue_bytes = fq_cl->fcl_stat.fcl_dequeue_bytes;
	fcls->fcls_byte_cnt = fq_cl->fcl_stat.fcl_byte_cnt;
	fcls->fcls_throttle_on = fq_cl->fcl_stat.fcl_throttle_on;
	fcls->fcls_throttle_off = fq_cl->fcl_stat.fcl_throttle_off;
	fcls->fcls_throttle_drops = fq_cl->fcl_stat.fcl_throttle_drops;
	fcls->fcls_dup_rexmts = fq_cl->fcl_stat.fcl_dup_rexmts;
	fcls->fcls_pkts_compressible = fq_cl->fcl_stat.fcl_pkts_compressible;
	fcls->fcls_pkts_compressed = fq_cl->fcl_stat.fcl_pkts_compressed;

	/* Gather per flow stats */
	flowstat_cnt = min((fcls->fcls_newflows_cnt +
	    fcls->fcls_oldflows_cnt), FQ_IF_MAX_FLOWSTATS);
	i = 0;
	STAILQ_FOREACH(fq, &fq_cl->fcl_new_flows, fq_actlink) {
		if (i >= fcls->fcls_newflows_cnt || i >= flowstat_cnt) {
			break;
		}

		/* leave space for a few old flows */
		if ((flowstat_cnt - i) < fcls->fcls_oldflows_cnt &&
		    i >= (FQ_IF_MAX_FLOWSTATS >> 1)) {
			break;
		}
		fq_export_flowstats(fqs, fq, &fcls->fcls_flowstats[i]);
		i++;
	}
	STAILQ_FOREACH(fq, &fq_cl->fcl_old_flows, fq_actlink) {
		if (i >= flowstat_cnt) {
			break;
		}
		fq_export_flowstats(fqs, fq, &fcls->fcls_flowstats[i]);
		i++;
	}
	VERIFY(i <= flowstat_cnt);
	fcls->fcls_flowstats_cnt = i;
	return 0;
}
