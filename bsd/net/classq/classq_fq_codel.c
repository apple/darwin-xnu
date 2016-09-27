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
#include <kern/zalloc.h>
#include <netinet/in.h>

#include <net/pktsched/pktsched_fq_codel.h>
#include <net/classq/classq_fq_codel.h>

static struct zone *flowq_zone = NULL;
static size_t flowq_size;

#define	FQ_ZONE_MAX	(32 * 1024)	/* across all interfaces */
#define	FQ_SEQ_LT(a,b)	((int)((a)-(b)) < 0)
#define	FQ_SEQ_GT(a,b)	((int)((a)-(b)) > 0)

void
fq_codel_init(void)
{
	if (flowq_zone != NULL)
		return;

	flowq_size = sizeof (fq_t);
	flowq_zone = zinit(flowq_size, FQ_ZONE_MAX * flowq_size,
	    0, "flowq_zone");
	if (flowq_zone == NULL) {
		panic("%s: failed to allocate flowq_zone", __func__);
		/* NOTREACHED */
	}
	zone_change(flowq_zone, Z_EXPAND, TRUE);
	zone_change(flowq_zone, Z_CALLERACCT, TRUE);
}

fq_t *
fq_alloc(int how)
{
	fq_t *fq = NULL;
	fq = (how == M_WAITOK) ? zalloc(flowq_zone) :
	    zalloc_noblock(flowq_zone);
	if (fq == NULL) {
		log(LOG_ERR, "%s: unable to allocate from flowq_zone\n");
		return (NULL);
	}

	bzero(fq, flowq_size);
	MBUFQ_INIT(&fq->fq_mbufq);
	return (fq);
}

void
fq_destroy(fq_t *fq)
{
	VERIFY(MBUFQ_EMPTY(&fq->fq_mbufq));
	VERIFY(!(fq->fq_flags & (FQF_NEW_FLOW | FQF_OLD_FLOW)));
	bzero(fq, flowq_size);
	zfree(flowq_zone, fq);
}

static void
fq_detect_dequeue_stall(fq_if_t *fqs, fq_t *flowq, fq_if_classq_t *fq_cl,
    u_int64_t *now)
{
	u_int64_t maxgetqtime;
	if (FQ_IS_DELAYHIGH(flowq) || flowq->fq_getqtime == 0 ||
	    MBUFQ_EMPTY(&flowq->fq_mbufq) ||
	    flowq->fq_bytes < FQ_MIN_FC_THRESHOLD_BYTES)
		return;
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
	struct mbuf *m = NULL;
	struct ifclassq *ifq = fqs->fqs_ifq;

	m = fq_getq_flow(fqs, fq);
	if (m == NULL)
		return;

	IFCQ_DROP_ADD(ifq, 1, m_length(m));
	IFCQ_CONVERT_LOCK(ifq);
	m_freem(m);
}

int
fq_addq(fq_if_t *fqs, struct mbuf *m, fq_if_classq_t *fq_cl)
{
	struct pkthdr *pkt = &m->m_pkthdr;
	int droptype = DTYPE_NODROP, fc_adv = 0, ret = CLASSQEQ_SUCCESS;
	u_int64_t now;
	fq_t *fq = NULL;

	VERIFY(!(pkt->pkt_flags & PKTF_PRIV_GUARDED));
	pkt->pkt_flags |= PKTF_PRIV_GUARDED;

	if (pkt->pkt_timestamp > 0) {
		now = pkt->pkt_timestamp;
	} else {
		now = mach_absolute_time();
		pkt->pkt_timestamp = now;
	}

	/* find the flowq for this packet */
	fq = fq_if_hash_pkt(fqs, pkt->pkt_flowid, m_get_service_class(m),
	    now, TRUE);
	if (fq == NULL) {
		/* drop the packet if we could not allocate a flow queue */
		fq_cl->fcl_stat.fcl_drop_memfailure++;
		IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
		m_freem(m);
		return (CLASSQEQ_DROPPED);
	}

	VERIFY(fq_cl->fcl_service_class ==
	    (u_int32_t)mbuf_get_service_class(m));

	fq_detect_dequeue_stall(fqs, fq, fq_cl, &now);

	if (FQ_IS_DELAYHIGH(fq)) {
		if ((fq->fq_flags & FQF_FLOWCTL_CAPABLE) &&
		    (pkt->pkt_flags & PKTF_FLOW_ADV)) {
			fc_adv = 1;
			/*
			 * If the flow is suspended or it is not
			 * TCP, drop the packet
			 */
			if (pkt->pkt_proto != IPPROTO_TCP) {
				droptype = DTYPE_EARLY;
				fq_cl->fcl_stat.fcl_drop_early++;
			}
		} else {
			/*
			 * Need to drop a packet, instead of dropping this
			 * one, try to drop from the head of the queue
			 */
			if (!MBUFQ_EMPTY(&fq->fq_mbufq)) {
				fq_head_drop(fqs, fq);
				droptype = DTYPE_NODROP;
			} else {
				droptype = DTYPE_EARLY;
			}
			fq_cl->fcl_stat.fcl_drop_early++;
		}

	}

	/*
	 * check if this packet is a retransmission of another pkt already
	 * in the queue
	 */
	if ((pkt->pkt_flags & (PKTF_TCP_REXMT|PKTF_START_SEQ)) ==
	    (PKTF_TCP_REXMT|PKTF_START_SEQ) && fq->fq_dequeue_seq != 0) {
		if (FQ_SEQ_GT(pkt->tx_start_seq, fq->fq_dequeue_seq)) {
			fq_cl->fcl_stat.fcl_dup_rexmts++;
			droptype = DTYPE_FORCED;
		}
	}

	/* Set the return code correctly */
	if (fc_adv == 1 && droptype != DTYPE_FORCED) {
		if (fq_if_add_fcentry(fqs, pkt, fq_cl)) {
			fq->fq_flags |= FQF_FLOWCTL_ON;
			/* deliver flow control advisory error */
			if (droptype == DTYPE_NODROP) {
				ret = CLASSQEQ_SUCCESS_FC;
			} else {
				/* dropped due to flow control */
				ret = CLASSQEQ_DROPPED_FC;
			}
		} else {
			/*
			 * if we could not flow control the flow, it is
			 * better to drop
			 */
			droptype = DTYPE_FORCED;
			ret = CLASSQEQ_DROPPED_FC;
			fq_cl->fcl_stat.fcl_flow_control_fail++;
		}
	}

	/*
	 * If the queue length hits the queue limit, drop a packet from the
	 * front of the queue for a flow with maximum number of bytes. This
	 * will penalize heavy and unresponsive flows. It will also avoid a
	 * tail drop.
	 */
	if (droptype == DTYPE_NODROP && fq_if_at_drop_limit(fqs)) {
		fq_if_drop_packet(fqs);
	}

	if (droptype == DTYPE_NODROP) {
		MBUFQ_ENQUEUE(&fq->fq_mbufq, m);
		fq->fq_bytes += m_length(m);
		fq_cl->fcl_stat.fcl_byte_cnt += m_length(m);
		fq_cl->fcl_stat.fcl_pkt_cnt++;

		/*
		 * check if this queue will qualify to be the next
		 * victim queue
		 */
		fq_if_is_flow_heavy(fqs, fq);
	} else {
		IFCQ_CONVERT_LOCK(fqs->fqs_ifq);
		m_freem(m);
		return ((ret != CLASSQEQ_SUCCESS) ? ret : CLASSQEQ_DROPPED);
	}

	/*
	 * If the queue is not currently active, add it to the end of new
	 * flows list for that service class.
	 */
	if ((fq->fq_flags & (FQF_NEW_FLOW|FQF_OLD_FLOW)) == 0) {
		VERIFY(STAILQ_NEXT(fq, fq_actlink) == NULL);
		STAILQ_INSERT_TAIL(&fq_cl->fcl_new_flows, fq, fq_actlink);
		fq->fq_flags |= FQF_NEW_FLOW;

		fq_cl->fcl_stat.fcl_newflows_cnt++;

		fq->fq_deficit = fq_cl->fcl_quantum;
	}
	return (ret);
}

struct mbuf *
fq_getq_flow(fq_if_t *fqs, fq_t *fq)
{
	struct mbuf *m = NULL;
	struct ifclassq *ifq = fqs->fqs_ifq;
	fq_if_classq_t *fq_cl;
	u_int64_t now;
	int64_t qdelay;
	struct pkthdr *pkt;
	u_int32_t mlen;

	MBUFQ_DEQUEUE(&fq->fq_mbufq, m);
	if (m == NULL)
		return (NULL);

	mlen = m_length(m);

	VERIFY(fq->fq_bytes >= mlen);
	fq->fq_bytes -= mlen;

	fq_cl = &fqs->fqs_classq[fq->fq_sc_index];
	fq_cl->fcl_stat.fcl_byte_cnt -= mlen;
	fq_cl->fcl_stat.fcl_pkt_cnt--;
	IFCQ_DEC_LEN(ifq);
	IFCQ_DEC_BYTES(ifq, mlen);

	pkt = &m->m_pkthdr;
	now = mach_absolute_time();

	/* this will compute qdelay in nanoseconds */
	qdelay = now - pkt->pkt_timestamp;

	if (fq->fq_min_qdelay == 0 ||
	    (qdelay > 0 && (u_int64_t)qdelay < fq->fq_min_qdelay))
		fq->fq_min_qdelay = qdelay;
	if (now >= fq->fq_updatetime || MBUFQ_EMPTY(&fq->fq_mbufq)) {
		if (fq->fq_min_qdelay >= fqs->fqs_target_qdelay) {
			if (!FQ_IS_DELAYHIGH(fq))
				FQ_SET_DELAY_HIGH(fq);
		}

		if (!FQ_IS_DELAYHIGH(fq) || MBUFQ_EMPTY(&fq->fq_mbufq)) {
			FQ_CLEAR_DELAY_HIGH(fq);
			if (fq->fq_flags & FQF_FLOWCTL_ON) {
				fq_if_flow_feedback(fqs, fq, fq_cl);
			}
		}

		/* Reset measured queue delay and update time */
		fq->fq_updatetime = now + fqs->fqs_update_interval;
		fq->fq_min_qdelay = 0;
	}

	if ((pkt->pkt_flags & PKTF_START_SEQ) && (fq->fq_dequeue_seq == 0 ||
	    (FQ_SEQ_LT(fq->fq_dequeue_seq, pkt->tx_start_seq))))
		fq->fq_dequeue_seq = pkt->tx_start_seq;

	pkt->pkt_timestamp = 0;
	pkt->pkt_flags &= ~PKTF_PRIV_GUARDED;

	if (MBUFQ_EMPTY(&fq->fq_mbufq)) {
		/*
		 * Remove from large_flow field, if this happened to be
		 * the one that is tagged.
		 */
		if (fqs->fqs_large_flow == fq)
			fqs->fqs_large_flow = NULL;

		/* Reset getqtime so that we don't count idle times */
		fq->fq_getqtime = 0;
	} else {
		fq->fq_getqtime = now;
	}

	return (m);
}
