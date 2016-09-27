/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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
#include <net/if_var.h>
#include <net/if.h>
#include <net/classq/classq.h>
#include <net/classq/classq_fq_codel.h>
#include <net/pktsched/pktsched_fq_codel.h>


static size_t fq_if_size;
static struct zone *fq_if_zone;

static fq_if_t *fq_if_alloc(struct ifnet *ifp, int how);
static void fq_if_destroy(fq_if_t *fqs);
static void fq_if_classq_init(fq_if_t *fqs, u_int32_t priority,
    u_int32_t quantum, u_int32_t drr_max, u_int32_t svc_class);
static int fq_if_enqueue_classq(struct ifclassq *ifq, struct mbuf *m);
static struct mbuf *fq_if_dequeue_classq(struct ifclassq *ifq, cqdq_op_t);
static int fq_if_dequeue_classq_multi(struct ifclassq *, cqdq_op_t,
    u_int32_t, u_int32_t, struct mbuf **, struct mbuf **, u_int32_t *,
    u_int32_t *);
static void fq_if_dequeue(fq_if_t *, fq_if_classq_t *, u_int32_t,
    u_int32_t, struct mbuf **, struct mbuf **, u_int32_t *, u_int32_t *);
static int fq_if_request_classq(struct ifclassq *ifq, cqrq_t op, void *arg);
void fq_if_stat_sc(fq_if_t *fqs, cqrq_stat_sc_t *stat);
static void fq_if_purge(fq_if_t *);
static void fq_if_purge_classq(fq_if_t *, fq_if_classq_t *);
static void fq_if_purge_flow(fq_if_t *, fq_t *, u_int32_t *, u_int32_t *);
static void fq_if_empty_new_flow(fq_t *fq, fq_if_classq_t *fq_cl,
    bool add_to_old);
static void fq_if_empty_old_flow(fq_if_t *fqs, fq_if_classq_t *fq_cl,
    fq_t *fq, bool remove_hash);
static void fq_if_destroy_flow(fq_if_t *fqs, fq_if_classq_t *fq_cl,
    fq_t *fq);

#define	FQ_IF_ZONE_MAX	32	/* Maximum elements in zone */
#define	FQ_IF_ZONE_NAME	"pktsched_fq_if" /* zone for fq_if class */

#define	FQ_IF_FLOW_HASH_ID(_flowid_) \
	(((_flowid_) >> FQ_IF_HASH_TAG_SHIFT) & FQ_IF_HASH_TAG_MASK)

#define	FQ_IF_CLASSQ_IDLE(_fcl_) \
	(STAILQ_EMPTY(&(_fcl_)->fcl_new_flows) && \
	STAILQ_EMPTY(&(_fcl_)->fcl_old_flows))

void
fq_codel_scheduler_init(void)
{
	/* Initialize the zone for flow queue structures */
	fq_codel_init();

	fq_if_size = sizeof (fq_if_t);
	fq_if_zone = zinit(fq_if_size, (FQ_IF_ZONE_MAX * fq_if_size), 0,
	    FQ_IF_ZONE_NAME);
	if (fq_if_zone == NULL) {
		panic("%s: failed allocating from %s", __func__,
		    (FQ_IF_ZONE_NAME));
	}
	zone_change(fq_if_zone, Z_EXPAND, TRUE);
	zone_change(fq_if_zone, Z_CALLERACCT, TRUE);

}

fq_if_t *
fq_if_alloc(struct ifnet *ifp, int how)
{
	fq_if_t *fqs;
	fqs = (how == M_WAITOK) ? zalloc(fq_if_zone) :
	    zalloc_noblock(fq_if_zone);
	if (fqs == NULL)
		return (NULL);

	bzero(fqs, fq_if_size);
	fqs->fqs_ifq = &ifp->if_snd;

	/* Calculate target queue delay */
	ifclassq_calc_target_qdelay(ifp, &fqs->fqs_target_qdelay);

	/* Calculate update interval */
	ifclassq_calc_update_interval(&fqs->fqs_update_interval);
	fqs->fqs_pkt_droplimit = FQ_IF_MAX_PKT_LIMIT;
	STAILQ_INIT(&fqs->fqs_fclist);
	return (fqs);
}

void
fq_if_destroy(fq_if_t *fqs)
{
	IFCQ_LOCK_ASSERT_HELD(fqs->fqs_ifq);
	fq_if_purge(fqs);
	fqs->fqs_ifq = NULL;
	zfree(fq_if_zone, fqs);
}

static inline u_int32_t
fq_if_service_to_priority(mbuf_svc_class_t svc)
{
	u_int32_t pri;

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
	return (pri);
}

void
fq_if_classq_init(fq_if_t *fqs, u_int32_t pri, u_int32_t quantum,
    u_int32_t drr_max, u_int32_t svc_class)
{
	fq_if_classq_t *fq_cl;

	fq_cl = &fqs->fqs_classq[pri];

	VERIFY(pri >= 0 && pri < FQ_IF_MAX_CLASSES &&
	    fq_cl->fcl_quantum == 0);
	fq_cl->fcl_quantum = quantum;
	fq_cl->fcl_pri = pri;
	fq_cl->fcl_drr_max = drr_max;
	fq_cl->fcl_service_class = svc_class;
	STAILQ_INIT(&fq_cl->fcl_new_flows);
	STAILQ_INIT(&fq_cl->fcl_old_flows);
}

int
fq_if_enqueue_classq(struct ifclassq *ifq, struct mbuf *m)
{
	u_int32_t pri;
	fq_if_t *fqs;
	fq_if_classq_t *fq_cl;
	int ret, len;
	mbuf_svc_class_t svc;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	if (!(m->m_flags & M_PKTHDR)) {
		IFCQ_CONVERT_LOCK(ifq);
		m_freem(m);
		return (ENOBUFS);
	}

	fqs = (fq_if_t *)ifq->ifcq_disc;
	svc = mbuf_get_service_class(m);
	pri = fq_if_service_to_priority(svc);
	VERIFY(pri >= 0 && pri < FQ_IF_MAX_CLASSES);
	fq_cl = &fqs->fqs_classq[pri];

	if (svc == MBUF_SC_BK_SYS && fqs->fqs_throttle == 1) {
		/* BK_SYS is currently throttled */
		fq_cl->fcl_stat.fcl_throttle_drops++;
		IFCQ_CONVERT_LOCK(ifq);
		m_freem(m);
		return (EQSUSPENDED);
	}

	len = m_length(m);
	ret = fq_addq(fqs, m, fq_cl);
	if (!FQ_IF_CLASSQ_IDLE(fq_cl)) {
		if (((fqs->fqs_bitmaps[FQ_IF_ER] | fqs->fqs_bitmaps[FQ_IF_EB]) &
		    (1 << pri)) == 0) {
			/*
			 * this group is not in ER or EB groups,
			 * mark it as IB
			 */
			pktsched_bit_set(pri, &fqs->fqs_bitmaps[FQ_IF_IB]);
		}
	}

	if (ret != 0) {
		if (ret == CLASSQEQ_SUCCESS_FC) {
			/* packet enqueued, return advisory feedback */
			ret = EQFULL;
		} else {
			VERIFY(ret == CLASSQEQ_DROPPED ||
			    ret == CLASSQEQ_DROPPED_FC ||
			    ret == CLASSQEQ_DROPPED_SP);
			switch (ret) {
			case CLASSQEQ_DROPPED:
				return (ENOBUFS);
			case CLASSQEQ_DROPPED_FC:
				return (EQFULL);
			case CLASSQEQ_DROPPED_SP:
				return (EQSUSPENDED);
			}
		}
	}
	IFCQ_INC_LEN(ifq);
	IFCQ_INC_BYTES(ifq, len);
	return (ret);
}

struct mbuf *
fq_if_dequeue_classq(struct ifclassq *ifq, cqdq_op_t op)
{
	struct mbuf *top;

	(void) fq_if_dequeue_classq_multi(ifq, op, 1,
	    CLASSQ_DEQUEUE_MAX_BYTE_LIMIT, &top, NULL, NULL, NULL);

	return (top);
}

int
fq_if_dequeue_classq_multi(struct ifclassq *ifq, cqdq_op_t op,
    u_int32_t maxpktcnt, u_int32_t maxbytecnt, struct mbuf **first_packet,
    struct mbuf **last_packet, u_int32_t *retpktcnt, u_int32_t *retbytecnt)
{
#pragma unused(op)
	struct mbuf *top = NULL, *tail = NULL, *first, *last;
	u_int32_t pktcnt = 0, bytecnt = 0, total_pktcnt, total_bytecnt;
	fq_if_t *fqs;
	fq_if_classq_t *fq_cl;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	fqs = (fq_if_t *)ifq->ifcq_disc;

	first = last = NULL;
	total_pktcnt = total_bytecnt = 0;

	for (;;) {
		if (fqs->fqs_bitmaps[FQ_IF_ER] == 0 &&
		    fqs->fqs_bitmaps[FQ_IF_EB] == 0) {
			fqs->fqs_bitmaps[FQ_IF_EB] = fqs->fqs_bitmaps[FQ_IF_IB];
			fqs->fqs_bitmaps[FQ_IF_IB] = 0;
			if (fqs->fqs_bitmaps[FQ_IF_EB] == 0)
				break;
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
			if (fq_cl->fcl_budget <= 0)
				goto state_change;
		}
		fq_if_dequeue(fqs, fq_cl, (maxpktcnt - total_pktcnt),
		    (maxbytecnt - total_bytecnt), &top, &tail, &pktcnt,
		    &bytecnt);
		if (top != NULL) {
			VERIFY(pktcnt > 0 && bytecnt > 0);
			if (first == NULL) {
				first = top;
				last = tail;
				total_pktcnt = pktcnt;
				total_bytecnt = bytecnt;
			} else {
				last->m_nextpkt = top;
				last = tail;
				total_pktcnt += pktcnt;
				total_bytecnt += bytecnt;
			}
			last->m_nextpkt = NULL;
			fq_cl->fcl_budget -= bytecnt;
			pktcnt = 0;
			bytecnt = 0;
		}

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
			    fqs->fqs_bitmaps[FQ_IF_IB])&(1 << pri)) == 0);
			fq_cl->fcl_budget = 0;
		}
		if (total_pktcnt >= maxpktcnt || total_bytecnt >= maxbytecnt)
			break;
	}
	if (first != NULL) {
		if (first_packet != NULL)
			*first_packet = first;
		if (last_packet != NULL)
			*last_packet = last;
		if (retpktcnt != NULL)
			*retpktcnt = total_pktcnt;
		if (retbytecnt != NULL)
			*retbytecnt = total_bytecnt;
		IFCQ_XMIT_ADD(ifq, total_pktcnt, total_bytecnt);
	} else {
		if (first_packet != NULL)
			*first_packet = NULL;
		if (last_packet != NULL)
			*last_packet = NULL;
		if (retpktcnt != NULL)
			*retpktcnt = 0;
		if (retbytecnt != NULL)
			*retbytecnt = 0;
	}
	return (0);
}

static void
fq_if_purge_flow(fq_if_t *fqs, fq_t *fq, u_int32_t *pktsp,
    u_int32_t *bytesp)
{
	fq_if_classq_t *fq_cl;
	u_int32_t pkts, bytes;
	struct mbuf *m;

	fq_cl = &fqs->fqs_classq[fq->fq_sc_index];
	pkts = bytes = 0;
	while ((m = fq_getq_flow(fqs, fq)) != NULL) {
		pkts++;
		bytes += m_length(m);
		m_freem(m);
		m = NULL;
	}
	IFCQ_DROP_ADD(fqs->fqs_ifq, pkts, bytes);

	if (fq->fq_flags & FQF_NEW_FLOW) {
		fq_if_empty_new_flow(fq, fq_cl, false);
	} else if (fq->fq_flags & FQF_OLD_FLOW) {
		fq_if_empty_old_flow(fqs, fq_cl, fq, false);
	}

	fq_if_destroy_flow(fqs, fq_cl, fq);

	if (FQ_IF_CLASSQ_IDLE(fq_cl)) {
		int i;
		for (i = FQ_IF_ER; i < FQ_IF_MAX_STATE; i++) {
			pktsched_bit_clr(fq_cl->fcl_pri,
			    &fqs->fqs_bitmaps[i]);
		}
	}
	if (pktsp != NULL)
		*pktsp = pkts;
	if (bytesp != NULL)
		*bytesp = bytes;
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

	bzero(&fqs->fqs_bitmaps, sizeof (fqs->fqs_bitmaps));

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

	fq = fq_if_hash_pkt(fqs, req->flow, req->sc, 0, FALSE);

	if (fq != NULL)
		fq_if_purge_flow(fqs, fq, &req->packets, &req->bytes);
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
	int index;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (!tr->set) {
		tr->level = fqs->fqs_throttle;
		return (0);
	}

	if (tr->level == fqs->fqs_throttle)
		return (EALREADY);

	/* Throttling is allowed on BK_SYS class only */
	index = fq_if_service_to_priority(MBUF_SC_BK_SYS);
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
	return (0);
}

void
fq_if_stat_sc(fq_if_t *fqs, cqrq_stat_sc_t *stat)
{
	u_int32_t pri;
	fq_if_classq_t *fq_cl;

	if (stat == NULL)
		return;

	pri = fq_if_service_to_priority(stat->sc);
	fq_cl = &fqs->fqs_classq[pri];
	stat->packets = fq_cl->fcl_stat.fcl_pkt_cnt;
	stat->bytes = fq_cl->fcl_stat.fcl_byte_cnt;
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
	return (err);
}

int
fq_if_setup_ifclassq(struct ifclassq *ifq, u_int32_t flags)
{
#pragma unused(flags)
	struct ifnet *ifp = ifq->ifcq_ifp;
	fq_if_t *fqs = NULL;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_disc == NULL);
	VERIFY(ifq->ifcq_type == PKTSCHEDT_NONE);

	fqs = fq_if_alloc(ifp, M_WAITOK);
	if (fqs == NULL)
		return (ENOMEM);

	fq_if_classq_init(fqs, FQ_IF_BK_SYS_INDEX, 1500, 2, MBUF_SC_BK_SYS);
	fq_if_classq_init(fqs, FQ_IF_BK_INDEX, 1500, 2, MBUF_SC_BK);
	fq_if_classq_init(fqs, FQ_IF_BE_INDEX, 1500, 4, MBUF_SC_BE);
	fq_if_classq_init(fqs, FQ_IF_RD_INDEX, 1500, 4, MBUF_SC_RD);
	fq_if_classq_init(fqs, FQ_IF_OAM_INDEX, 1500, 4, MBUF_SC_OAM);
	fq_if_classq_init(fqs, FQ_IF_AV_INDEX, 3000, 6, MBUF_SC_AV);
	fq_if_classq_init(fqs, FQ_IF_RV_INDEX, 3000, 6, MBUF_SC_RV);
	fq_if_classq_init(fqs, FQ_IF_VI_INDEX, 3000, 6, MBUF_SC_VI);
	fq_if_classq_init(fqs, FQ_IF_VO_INDEX, 600, 8, MBUF_SC_VO);
	fq_if_classq_init(fqs, FQ_IF_CTL_INDEX, 600, 8, MBUF_SC_CTL);

	err = ifclassq_attach(ifq, PKTSCHEDT_FQ_CODEL, fqs,
	    fq_if_enqueue_classq, fq_if_dequeue_classq, NULL,
	    fq_if_dequeue_classq_multi, fq_if_request_classq);

	if (err != 0) {
		printf("%s: error from ifclassq_attach, "
		    "failed to attach fq_if: %d\n", __func__, err);
		fq_if_destroy(fqs);
	}
	return (err);
}

fq_t *
fq_if_hash_pkt(fq_if_t *fqs, u_int32_t flowid, mbuf_svc_class_t svc_class,
    u_int64_t now, boolean_t create)
{
	fq_t *fq = NULL;
	flowq_list_t *fq_list;
	fq_if_classq_t *fq_cl;
	u_int8_t fqs_hash_id;
	u_int8_t scidx;

	scidx = fq_if_service_to_priority(svc_class);

	fqs_hash_id = FQ_IF_FLOW_HASH_ID(flowid);

	fq_list = &fqs->fqs_flows[fqs_hash_id];

	SLIST_FOREACH(fq, fq_list, fq_hashlink) {
		if (fq->fq_flowhash == flowid &&
		    fq->fq_sc_index == scidx)
			break;
	}
	if (fq == NULL && create == TRUE) {
		/* If the flow is not already on the list, allocate it */
		IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
		fq = fq_alloc(M_WAITOK);
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
	if (fq->fq_getqtime == 0)
		fq->fq_getqtime = now;

	return (fq);
}

static void
fq_if_destroy_flow(fq_if_t *fqs, fq_if_classq_t *fq_cl, fq_t *fq)
{
	u_int8_t hash_id;
	hash_id = FQ_IF_FLOW_HASH_ID(fq->fq_flowhash);
	SLIST_REMOVE(&fqs->fqs_flows[hash_id], fq, flowq,
	    fq_hashlink);
	fq_cl->fcl_stat.fcl_flows_cnt--;
	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	fq_destroy(fq);

}

inline boolean_t
fq_if_at_drop_limit(fq_if_t *fqs)
{
	return (((IFCQ_LEN(fqs->fqs_ifq) >= fqs->fqs_pkt_droplimit) ?
	    TRUE : FALSE));
}

static void
fq_if_empty_old_flow(fq_if_t *fqs, fq_if_classq_t *fq_cl, fq_t *fq,
    bool remove_hash)
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
		fq_if_destroy_flow(fqs, fq_cl, fq);
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
	struct mbuf *m;
	fq_if_classq_t *fq_cl;

	if (fq == NULL)
		return;
	/* mbufq can not be empty on the largest flow */
	VERIFY(!MBUFQ_EMPTY(&fq->fq_mbufq));

	fq_cl = &fqs->fqs_classq[fq->fq_sc_index];

	m = fq_getq_flow(fqs, fq);

	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	if (MBUFQ_EMPTY(&fq->fq_mbufq)) {
		if (fq->fq_flags & FQF_OLD_FLOW) {
			fq_if_empty_old_flow(fqs, fq_cl, fq, true);
		} else {
			VERIFY(fq->fq_flags & FQF_NEW_FLOW);
			fq_if_empty_new_flow(fq, fq_cl, true);
		}
	}
	IFCQ_DROP_ADD(fqs->fqs_ifq, 1, m_length(m));

	m_freem(m);
	fq_cl->fcl_stat.fcl_drop_overflow++;
}

inline void
fq_if_is_flow_heavy(fq_if_t *fqs, fq_t *fq)
{
	fq_t *prev_fq = fqs->fqs_large_flow;
	if (prev_fq == NULL && !MBUFQ_EMPTY(&fq->fq_mbufq)) {
		fqs->fqs_large_flow = fq;
		return;
	} else if (fq->fq_bytes > prev_fq->fq_bytes) {
		fqs->fqs_large_flow = fq;
	}
}

boolean_t
fq_if_add_fcentry(fq_if_t *fqs, struct pkthdr *pkt, fq_if_classq_t *fq_cl)
{
	struct flowadv_fcentry *fce;
	u_int32_t flowsrc, flowid;

	flowsrc = pkt->pkt_flowsrc;
	flowid = pkt->pkt_flowid;

	STAILQ_FOREACH(fce, &fqs->fqs_fclist, fce_link) {
		if (fce->fce_flowsrc == flowsrc &&
		    fce->fce_flowid == flowid) {
			/* Already on flowcontrol list */
			return (TRUE);
		}
	}

	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	fce = flowadv_alloc_entry(M_WAITOK);
	if (fce != NULL) {
		fce->fce_flowsrc = flowsrc;
		fce->fce_flowid = flowid;
		/* XXX Add number of bytes in the queue */
		STAILQ_INSERT_TAIL(&fqs->fqs_fclist, fce, fce_link);
		fq_cl->fcl_stat.fcl_flow_control++;
	}
	return ((fce != NULL) ? TRUE : FALSE);
}

void
fq_if_flow_feedback(fq_if_t *fqs, fq_t *fq, fq_if_classq_t *fq_cl)
{
	struct flowadv_fcentry *fce = NULL;

	IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
	STAILQ_FOREACH(fce, &fqs->fqs_fclist, fce_link) {
		if (fce->fce_flowid == fq->fq_flowhash)
			break;
	}
	if (fce != NULL) {
		STAILQ_REMOVE(&fqs->fqs_fclist, fce, flowadv_fcentry,
		    fce_link);
		STAILQ_NEXT(fce, fce_link) = NULL;
		flowadv_add_entry(fce);
		fq_cl->fcl_stat.fcl_flow_feedback++;
	}
	fq->fq_flags &= ~FQF_FLOWCTL_ON;
}

void
fq_if_dequeue(fq_if_t *fqs, fq_if_classq_t *fq_cl, u_int32_t pktlimit,
    u_int32_t bytelimit, struct mbuf **top, struct mbuf **tail,
    u_int32_t *retpktcnt, u_int32_t *retbytecnt)
{
	fq_t *fq = NULL, *tfq = NULL;
	struct mbuf *m = NULL, *last = NULL;
	flowq_stailq_t temp_stailq;
	u_int32_t pktcnt, bytecnt, mlen;
	boolean_t limit_reached = FALSE;

	/*
	 * maximum byte limit should not be greater than the budget for
	 * this class
	 */
	if ((int32_t)bytelimit > fq_cl->fcl_budget)
		bytelimit = fq_cl->fcl_budget;

	VERIFY(pktlimit > 0 && bytelimit > 0 && top != NULL);

	*top = NULL;
	pktcnt = bytecnt = 0;
	STAILQ_INIT(&temp_stailq);

	STAILQ_FOREACH_SAFE(fq, &fq_cl->fcl_new_flows, fq_actlink, tfq) {
		VERIFY((fq->fq_flags & (FQF_NEW_FLOW|FQF_OLD_FLOW)) ==
		    FQF_NEW_FLOW);
		while (fq->fq_deficit > 0 && limit_reached == FALSE &&
		    !MBUFQ_EMPTY(&fq->fq_mbufq)) {

			m = fq_getq_flow(fqs, fq);
			m->m_pkthdr.pkt_flags |= PKTF_NEW_FLOW;
			mlen = m_length(m);
			fq->fq_deficit -= mlen;

			if (*top == NULL) {
				*top = m;
			} else {
				last->m_nextpkt = m;
			}
			last = m;
			last->m_nextpkt = NULL;
			fq_cl->fcl_stat.fcl_dequeue++;
			fq_cl->fcl_stat.fcl_dequeue_bytes += mlen;

			pktcnt++;
			bytecnt += mlen;

			/* Check if the limit is reached */
			if (pktcnt >= pktlimit || bytecnt >= bytelimit)
				limit_reached = TRUE;
		}

		if (fq->fq_deficit <= 0 || MBUFQ_EMPTY(&fq->fq_mbufq)) {
			fq_if_empty_new_flow(fq, fq_cl, true);
			fq->fq_deficit += fq_cl->fcl_quantum;
		}
		if (limit_reached == TRUE)
			goto done;
	}

	STAILQ_FOREACH_SAFE(fq, &fq_cl->fcl_old_flows, fq_actlink, tfq) {
		VERIFY((fq->fq_flags & (FQF_NEW_FLOW|FQF_OLD_FLOW)) ==
		    FQF_OLD_FLOW);
		while (fq->fq_deficit > 0 && !MBUFQ_EMPTY(&fq->fq_mbufq) &&
		    limit_reached == FALSE) {
			m = fq_getq_flow(fqs, fq);
			mlen = m_length(m);
			fq->fq_deficit -= mlen;
			if (*top == NULL) {
				*top = m;
			} else {
				last->m_nextpkt = m;
			}
			last = m;
			last->m_nextpkt = NULL;
			fq_cl->fcl_stat.fcl_dequeue++;
			fq_cl->fcl_stat.fcl_dequeue_bytes += mlen;

			pktcnt++;
			bytecnt += mlen;

			/* Check if the limit is reached */
			if (pktcnt >= pktlimit || bytecnt >= bytelimit)
				limit_reached = TRUE;
		}

		if (MBUFQ_EMPTY(&fq->fq_mbufq)) {
			fq_if_empty_old_flow(fqs, fq_cl, fq, true);
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

		if (limit_reached == TRUE)
			break;
	}

done:
	if (!STAILQ_EMPTY(&fq_cl->fcl_old_flows)) {
		STAILQ_CONCAT(&fq_cl->fcl_old_flows, &temp_stailq);
	} else if (!STAILQ_EMPTY(&temp_stailq)) {
		fq_cl->fcl_old_flows = temp_stailq;
	}

	if (last != NULL) {
		VERIFY(*top != NULL);
		if (tail != NULL)
			*tail = last;
		if (retpktcnt != NULL)
			*retpktcnt = pktcnt;
		if (retbytecnt != NULL)
			*retbytecnt = bytecnt;
	}
}

int
fq_if_teardown_ifclassq(struct ifclassq *ifq)
{
	fq_if_t *fqs = (fq_if_t *)ifq->ifcq_disc;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(fqs != NULL && ifq->ifcq_type == PKTSCHEDT_FQ_CODEL);

	fq_if_destroy(fqs);
	ifq->ifcq_disc = NULL;

	return (ifclassq_detach(ifq));
}

int
fq_if_getqstats_ifclassq(struct ifclassq *ifq, u_int32_t qid,
    struct if_ifclassq_stats *ifqs)
{
	struct fq_codel_classstats *fcls;
	fq_if_classq_t *fq_cl;
	fq_if_t *fqs;

	if (qid >= FQ_IF_MAX_CLASSES)
		return (EINVAL);

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

	return (0);
}
