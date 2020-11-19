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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/kauth.h>
#include <sys/sdt.h>
#include <kern/zalloc.h>
#include <netinet/in.h>

#include <net/classq/classq.h>
#include <net/classq/if_classq.h>
#include <net/pktsched/pktsched.h>
#include <net/pktsched/pktsched_fq_codel.h>
#include <net/classq/classq_fq_codel.h>

#include <netinet/tcp_var.h>

static uint32_t flowq_size;                     /* size of flowq */
static struct mcache *flowq_cache = NULL;       /* mcache for flowq */

#define FQ_ZONE_MAX     (32 * 1024)     /* across all interfaces */

#define DTYPE_NODROP    0       /* no drop */
#define DTYPE_FORCED    1       /* a "forced" drop */
#define DTYPE_EARLY     2       /* an "unforced" (early) drop */

void
fq_codel_init(void)
{
	if (flowq_cache != NULL) {
		return;
	}

	flowq_size = sizeof(fq_t);
	flowq_cache = mcache_create("fq.flowq", flowq_size, sizeof(uint64_t),
	    0, MCR_SLEEP);
	if (flowq_cache == NULL) {
		panic("%s: failed to allocate flowq_cache", __func__);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

void
fq_codel_reap_caches(boolean_t purge)
{
	mcache_reap_now(flowq_cache, purge);
}

fq_t *
fq_alloc(classq_pkt_type_t ptype)
{
	fq_t *fq = NULL;
	fq = mcache_alloc(flowq_cache, MCR_SLEEP);
	if (fq == NULL) {
		log(LOG_ERR, "%s: unable to allocate from flowq_cache\n", __func__);
		return NULL;
	}

	bzero(fq, flowq_size);
	fq->fq_ptype = ptype;
	if (ptype == QP_MBUF) {
		MBUFQ_INIT(&fq->fq_mbufq);
	}
	return fq;
}

void
fq_destroy(fq_t *fq)
{
	VERIFY(fq_empty(fq));
	VERIFY(!(fq->fq_flags & (FQF_NEW_FLOW | FQF_OLD_FLOW)));
	VERIFY(fq->fq_bytes == 0);
	mcache_free(flowq_cache, fq);
}

static inline void
fq_detect_dequeue_stall(fq_if_t *fqs, fq_t *flowq, fq_if_classq_t *fq_cl,
    u_int64_t *now)
{
	u_int64_t maxgetqtime;
	if (FQ_IS_DELAYHIGH(flowq) || flowq->fq_getqtime == 0 ||
	    fq_empty(flowq) ||
	    flowq->fq_bytes < FQ_MIN_FC_THRESHOLD_BYTES) {
		return;
	}
	maxgetqtime = flowq->fq_getqtime + fqs->fqs_update_interval;
	if ((*now) > maxgetqtime) {
		/*
		 * there was no dequeue in an update interval worth of
		 * time. It means that the queue is stalled.
		 */
		FQ_SET_DELAY_HIGH(flowq);
		fq_cl->fcl_stat.fcl_dequeue_stall++;
	}
}

void
fq_head_drop(fq_if_t *fqs, fq_t *fq)
{
	pktsched_pkt_t pkt;
	volatile uint32_t *pkt_flags;
	uint64_t *pkt_timestamp;
	struct ifclassq *ifq = fqs->fqs_ifq;

	_PKTSCHED_PKT_INIT(&pkt);
	fq_getq_flow_internal(fqs, fq, &pkt);
	if (pkt.pktsched_pkt_mbuf == NULL) {
		return;
	}

	pktsched_get_pkt_vars(&pkt, &pkt_flags, &pkt_timestamp, NULL, NULL,
	    NULL, NULL);

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

	IFCQ_DROP_ADD(ifq, 1, pktsched_get_pkt_len(&pkt));
	IFCQ_CONVERT_LOCK(ifq);
	pktsched_free_pkt(&pkt);
}


static int
fq_compressor(fq_if_t *fqs, fq_t *fq, fq_if_classq_t *fq_cl,
    pktsched_pkt_t *pkt)
{
	classq_pkt_type_t ptype = fq->fq_ptype;
	uint32_t comp_gencnt = 0;
	uint64_t *pkt_timestamp;
	uint64_t old_timestamp = 0;
	uint32_t old_pktlen = 0;
	struct ifclassq *ifq = fqs->fqs_ifq;

	if (__improbable(!tcp_do_ack_compression)) {
		return 0;
	}

	pktsched_get_pkt_vars(pkt, NULL, &pkt_timestamp, NULL, NULL, NULL,
	    &comp_gencnt);

	if (comp_gencnt == 0) {
		return 0;
	}

	fq_cl->fcl_stat.fcl_pkts_compressible++;

	if (fq_empty(fq)) {
		return 0;
	}

	if (ptype == QP_MBUF) {
		struct mbuf *m = MBUFQ_LAST(&fq->fq_mbufq);

		if (comp_gencnt != m->m_pkthdr.comp_gencnt) {
			return 0;
		}

		/* If we got until here, we should merge/replace the segment */
		MBUFQ_REMOVE(&fq->fq_mbufq, m);
		old_pktlen = m_pktlen(m);
		old_timestamp = m->m_pkthdr.pkt_timestamp;

		IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
		m_freem(m);
	}

	fq->fq_bytes -= old_pktlen;
	fq_cl->fcl_stat.fcl_byte_cnt -= old_pktlen;
	fq_cl->fcl_stat.fcl_pkt_cnt--;
	IFCQ_DEC_LEN(ifq);
	IFCQ_DEC_BYTES(ifq, old_pktlen);

	*pkt_timestamp = old_timestamp;

	return CLASSQEQ_COMPRESSED;
}

int
fq_addq(fq_if_t *fqs, pktsched_pkt_t *pkt, fq_if_classq_t *fq_cl)
{
	int droptype = DTYPE_NODROP, fc_adv = 0, ret = CLASSQEQ_SUCCESS;
	u_int64_t now;
	fq_t *fq = NULL;
	uint64_t *pkt_timestamp;
	volatile uint32_t *pkt_flags;
	uint32_t pkt_flowid, cnt;
	uint8_t pkt_proto, pkt_flowsrc;

	cnt = pkt->pktsched_pcnt;
	pktsched_get_pkt_vars(pkt, &pkt_flags, &pkt_timestamp, &pkt_flowid,
	    &pkt_flowsrc, &pkt_proto, NULL);

	/*
	 * XXX Not walking the chain to set this flag on every packet.
	 * This flag is only used for debugging. Nothing is affected if it's
	 * not set.
	 */
	switch (pkt->pktsched_ptype) {
	case QP_MBUF:
		/* See comments in <rdar://problem/14040693> */
		VERIFY(!(*pkt_flags & PKTF_PRIV_GUARDED));
		*pkt_flags |= PKTF_PRIV_GUARDED;
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/*
	 * Timestamps for every packet must be set prior to entering this path.
	 */
	now = *pkt_timestamp;
	ASSERT(now > 0);

	/* find the flowq for this packet */
	fq = fq_if_hash_pkt(fqs, pkt_flowid, pktsched_get_pkt_svc(pkt),
	    now, TRUE, pkt->pktsched_ptype);
	if (__improbable(fq == NULL)) {
		DTRACE_IP1(memfail__drop, fq_if_t *, fqs);
		/* drop the packet if we could not allocate a flow queue */
		fq_cl->fcl_stat.fcl_drop_memfailure += cnt;
		return CLASSQEQ_DROP;
	}
	VERIFY(fq->fq_ptype == pkt->pktsched_ptype);

	fq_detect_dequeue_stall(fqs, fq, fq_cl, &now);

	if (__improbable(FQ_IS_DELAYHIGH(fq))) {
		if ((fq->fq_flags & FQF_FLOWCTL_CAPABLE) &&
		    (*pkt_flags & PKTF_FLOW_ADV)) {
			fc_adv = 1;
			/*
			 * If the flow is suspended or it is not
			 * TCP/QUIC, drop the chain.
			 */
			if ((pkt_proto != IPPROTO_TCP) &&
			    (pkt_proto != IPPROTO_QUIC)) {
				droptype = DTYPE_EARLY;
				fq_cl->fcl_stat.fcl_drop_early += cnt;
			}
			DTRACE_IP6(flow__adv, fq_if_t *, fqs,
			    fq_if_classq_t *, fq_cl, fq_t *, fq,
			    int, droptype, pktsched_pkt_t *, pkt,
			    uint32_t, cnt);
		} else {
			/*
			 * Need to drop packets to make room for the new
			 * ones. Try to drop from the head of the queue
			 * instead of the latest packets.
			 */
			if (!fq_empty(fq)) {
				uint32_t i;

				for (i = 0; i < cnt; i++) {
					fq_head_drop(fqs, fq);
				}
				droptype = DTYPE_NODROP;
			} else {
				droptype = DTYPE_EARLY;
			}
			fq_cl->fcl_stat.fcl_drop_early += cnt;

			DTRACE_IP6(no__flow__adv, fq_if_t *, fqs,
			    fq_if_classq_t *, fq_cl, fq_t *, fq,
			    int, droptype, pktsched_pkt_t *, pkt,
			    uint32_t, cnt);
		}
	}

	/* Set the return code correctly */
	if (__improbable(fc_adv == 1 && droptype != DTYPE_FORCED)) {
		if (fq_if_add_fcentry(fqs, pkt, pkt_flowid, pkt_flowsrc,
		    fq_cl)) {
			fq->fq_flags |= FQF_FLOWCTL_ON;
			/* deliver flow control advisory error */
			if (droptype == DTYPE_NODROP) {
				ret = CLASSQEQ_SUCCESS_FC;
			} else {
				/* dropped due to flow control */
				ret = CLASSQEQ_DROP_FC;
			}
		} else {
			/*
			 * if we could not flow control the flow, it is
			 * better to drop
			 */
			droptype = DTYPE_FORCED;
			ret = CLASSQEQ_DROP_FC;
			fq_cl->fcl_stat.fcl_flow_control_fail++;
		}
		DTRACE_IP3(fc__ret, fq_if_t *, fqs, int, droptype, int, ret);
	}

	/*
	 * If the queue length hits the queue limit, drop a chain with the
	 * same number of packets from the front of the queue for a flow with
	 * maximum number of bytes. This will penalize heavy and unresponsive
	 * flows. It will also avoid a tail drop.
	 */
	if (__improbable(droptype == DTYPE_NODROP &&
	    fq_if_at_drop_limit(fqs))) {
		uint32_t i;

		if (fqs->fqs_large_flow == fq) {
			/*
			 * Drop from the head of the current fq. Since a
			 * new packet will be added to the tail, it is ok
			 * to leave fq in place.
			 */
			DTRACE_IP5(large__flow, fq_if_t *, fqs,
			    fq_if_classq_t *, fq_cl, fq_t *, fq,
			    pktsched_pkt_t *, pkt, uint32_t, cnt);

			for (i = 0; i < cnt; i++) {
				fq_head_drop(fqs, fq);
			}
		} else {
			if (fqs->fqs_large_flow == NULL) {
				droptype = DTYPE_FORCED;
				fq_cl->fcl_stat.fcl_drop_overflow += cnt;
				ret = CLASSQEQ_DROP;

				DTRACE_IP5(no__large__flow, fq_if_t *, fqs,
				    fq_if_classq_t *, fq_cl, fq_t *, fq,
				    pktsched_pkt_t *, pkt, uint32_t, cnt);

				/*
				 * if this fq was freshly created and there
				 * is nothing to enqueue, free it
				 */
				if (fq_empty(fq) && !(fq->fq_flags &
				    (FQF_NEW_FLOW | FQF_OLD_FLOW))) {
					fq_if_destroy_flow(fqs, fq_cl, fq);
					fq = NULL;
				}
			} else {
				DTRACE_IP5(different__large__flow,
				    fq_if_t *, fqs, fq_if_classq_t *, fq_cl,
				    fq_t *, fq, pktsched_pkt_t *, pkt,
				    uint32_t, cnt);

				for (i = 0; i < cnt; i++) {
					fq_if_drop_packet(fqs);
				}
			}
		}
	}

	if (__probable(droptype == DTYPE_NODROP)) {
		uint32_t chain_len = pktsched_get_pkt_len(pkt);

		/*
		 * We do not compress if we are enqueuing a chain.
		 * Traversing the chain to look for acks would defeat the
		 * purpose of batch enqueueing.
		 */
		if (cnt == 1) {
			ret = fq_compressor(fqs, fq, fq_cl, pkt);
			if (ret != CLASSQEQ_COMPRESSED) {
				ret = CLASSQEQ_SUCCESS;
			} else {
				fq_cl->fcl_stat.fcl_pkts_compressed++;
			}
		}
		DTRACE_IP5(fq_enqueue, fq_if_t *, fqs, fq_if_classq_t *, fq_cl,
		    fq_t *, fq, pktsched_pkt_t *, pkt, uint32_t, cnt);
		fq_enqueue(fq, pkt->pktsched_pkt, pkt->pktsched_tail, cnt);

		fq->fq_bytes += chain_len;
		fq_cl->fcl_stat.fcl_byte_cnt += chain_len;
		fq_cl->fcl_stat.fcl_pkt_cnt += cnt;

		/*
		 * check if this queue will qualify to be the next
		 * victim queue
		 */
		fq_if_is_flow_heavy(fqs, fq);
	} else {
		DTRACE_IP3(fq_drop, fq_if_t *, fqs, int, droptype, int, ret);
		return (ret != CLASSQEQ_SUCCESS) ? ret : CLASSQEQ_DROP;
	}

	/*
	 * If the queue is not currently active, add it to the end of new
	 * flows list for that service class.
	 */
	if ((fq->fq_flags & (FQF_NEW_FLOW | FQF_OLD_FLOW)) == 0) {
		VERIFY(STAILQ_NEXT(fq, fq_actlink) == NULL);
		STAILQ_INSERT_TAIL(&fq_cl->fcl_new_flows, fq, fq_actlink);
		fq->fq_flags |= FQF_NEW_FLOW;

		fq_cl->fcl_stat.fcl_newflows_cnt++;

		fq->fq_deficit = fq_cl->fcl_quantum;
	}
	return ret;
}

void
fq_getq_flow_internal(fq_if_t *fqs, fq_t *fq, pktsched_pkt_t *pkt)
{
	classq_pkt_t p = CLASSQ_PKT_INITIALIZER(p);
	uint32_t plen;
	fq_if_classq_t *fq_cl;
	struct ifclassq *ifq = fqs->fqs_ifq;

	fq_dequeue(fq, &p);
	if (p.cp_ptype == QP_INVALID) {
		VERIFY(p.cp_mbuf == NULL);
		return;
	}

	pktsched_pkt_encap(pkt, &p);
	plen = pktsched_get_pkt_len(pkt);

	VERIFY(fq->fq_bytes >= plen);
	fq->fq_bytes -= plen;

	fq_cl = &fqs->fqs_classq[fq->fq_sc_index];
	fq_cl->fcl_stat.fcl_byte_cnt -= plen;
	fq_cl->fcl_stat.fcl_pkt_cnt--;
	IFCQ_DEC_LEN(ifq);
	IFCQ_DEC_BYTES(ifq, plen);

	/* Reset getqtime so that we don't count idle times */
	if (fq_empty(fq)) {
		fq->fq_getqtime = 0;
	}
}

void
fq_getq_flow(fq_if_t *fqs, fq_t *fq, pktsched_pkt_t *pkt)
{
	fq_if_classq_t *fq_cl;
	u_int64_t now;
	int64_t qdelay = 0;
	struct timespec now_ts;
	volatile uint32_t *pkt_flags;
	uint64_t *pkt_timestamp;

	fq_getq_flow_internal(fqs, fq, pkt);
	if (pkt->pktsched_ptype == QP_INVALID) {
		VERIFY(pkt->pktsched_pkt_mbuf == NULL);
		return;
	}

	pktsched_get_pkt_vars(pkt, &pkt_flags, &pkt_timestamp, NULL, NULL,
	    NULL, NULL);

	nanouptime(&now_ts);
	now = (now_ts.tv_sec * NSEC_PER_SEC) + now_ts.tv_nsec;

	/* this will compute qdelay in nanoseconds */
	if (now > *pkt_timestamp) {
		qdelay = now - *pkt_timestamp;
	}
	fq_cl = &fqs->fqs_classq[fq->fq_sc_index];

	if (fq->fq_min_qdelay == 0 ||
	    (qdelay > 0 && (u_int64_t)qdelay < fq->fq_min_qdelay)) {
		fq->fq_min_qdelay = qdelay;
	}
	if (now >= fq->fq_updatetime) {
		if (fq->fq_min_qdelay > fqs->fqs_target_qdelay) {
			if (!FQ_IS_DELAYHIGH(fq)) {
				FQ_SET_DELAY_HIGH(fq);
			}
		} else {
			FQ_CLEAR_DELAY_HIGH(fq);
		}
		/* Reset measured queue delay and update time */
		fq->fq_updatetime = now + fqs->fqs_update_interval;
		fq->fq_min_qdelay = 0;
	}
	if (!FQ_IS_DELAYHIGH(fq) || fq_empty(fq)) {
		FQ_CLEAR_DELAY_HIGH(fq);
		if (fq->fq_flags & FQF_FLOWCTL_ON) {
			fq_if_flow_feedback(fqs, fq, fq_cl);
		}
	}

	if (fq_empty(fq)) {
		/* Reset getqtime so that we don't count idle times */
		fq->fq_getqtime = 0;
	} else {
		fq->fq_getqtime = now;
	}
	fq_if_is_flow_heavy(fqs, fq);

	*pkt_timestamp = 0;
	switch (pkt->pktsched_ptype) {
	case QP_MBUF:
		*pkt_flags &= ~PKTF_PRIV_GUARDED;
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}
