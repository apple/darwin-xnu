/*
 * Copyright (c) 2007-2019 Apple Inc. All rights reserved.
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

/*
 * Copyright (c) 1991-1997 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the Network Research
 *      Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
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
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/random.h>
#include <sys/kernel_types.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/net_osdep.h>
#include <net/classq/classq.h>

#include <libkern/libkern.h>


u_int32_t classq_verbose = 0;   /* more noise if greater than 1 */

SYSCTL_NODE(_net, OID_AUTO, classq, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "classq");

SYSCTL_UINT(_net_classq, OID_AUTO, verbose, CTLFLAG_RW | CTLFLAG_LOCKED,
    &classq_verbose, 0, "Class queue verbosity level");

void
_qinit(class_queue_t *q, int type, int lim, classq_pkt_type_t ptype)
{
	switch (ptype) {
	case QP_MBUF:
		MBUFQ_INIT(&qmbufq(q));
		break;


	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	qlimit(q) = lim;
	qlen(q) = 0;
	qsize(q) = 0;
	qtype(q) = type;
	qptype(q) = ptype;
	qstate(q) = QS_RUNNING;
}

/* add a packet at the tail of the queue */
void
_addq(class_queue_t *q, classq_pkt_t *pkt)
{
	uint32_t size = 0;

	ASSERT(pkt->cp_ptype == qptype(q));

	switch (qptype(q)) {
	case QP_MBUF: {
		struct mbuf *m = pkt->cp_mbuf;
		MBUFQ_ENQUEUE(&qmbufq(q), m);
		size = m_length(m);
		break;
	}


	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	qlen(q)++;
	VERIFY(qlen(q) != 0);
	qsize(q) += size;
}

/* add one or more packets at the tail of the queue */
void
_addq_multi(class_queue_t *q, classq_pkt_t *pkt_head, classq_pkt_t *pkt_tail,
    u_int32_t cnt, u_int64_t size)
{
	ASSERT(pkt_head->cp_ptype == qptype(q));
	ASSERT(pkt_tail->cp_ptype == qptype(q));
	switch (qptype(q)) {
	case QP_MBUF: {
		struct mbuf *m_head = pkt_head->cp_mbuf;
		struct mbuf *m_tail = pkt_tail->cp_mbuf;
		MBUFQ_ENQUEUE_MULTI(&qmbufq(q), m_head, m_tail);
		break;
	}


	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	qlen(q) += cnt;
	qsize(q) += size;
}

/* get a packet at the head of the queue */
void
_getq(class_queue_t *q, classq_pkt_t *pkt)
{
	uint32_t pkt_len;

	switch (qptype(q)) {
	case QP_MBUF: {
		MBUFQ_DEQUEUE(&qmbufq(q), pkt->cp_mbuf);
		if (__probable(pkt->cp_mbuf != NULL)) {
			CLASSQ_PKT_INIT_MBUF(pkt, pkt->cp_mbuf);
			pkt_len = m_length(pkt->cp_mbuf);
		}
		break;
	}


	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (pkt->cp_mbuf == NULL) {
		VERIFY(qlen(q) == 0);
		if (qsize(q) > 0) {
			qsize(q) = 0;
		}
		return;
	}
	VERIFY(qlen(q) > 0);
	qlen(q)--;

	/* qsize is an approximation, so adjust if necessary */
	if (((int)qsize(q) - pkt_len) > 0) {
		qsize(q) -= pkt_len;
	} else if (qsize(q) != 0) {
		qsize(q) = 0;
	}
}

static void
_getq_flow_or_scidx(class_queue_t *q, classq_pkt_t *pkt, u_int32_t val,
    boolean_t isflowid)
{
	uint32_t pkt_len;

	switch (qptype(q)) {
	case QP_MBUF: {
		struct mbuf *m, *m_tmp;

		MBUFQ_FOREACH_SAFE(m, &qmbufq(q), m_tmp) {
			if ((isflowid && (val == 0 ||
			    ((m->m_flags & M_PKTHDR) &&
			    m->m_pkthdr.pkt_flowid == val))) ||
			    (!isflowid &&
			    MBUF_SCIDX(mbuf_get_service_class(m)) < val)) {
				/* remove it from the class queue */
				MBUFQ_REMOVE(&qmbufq(q), m);
				MBUFQ_NEXT(m) = NULL;
				break;
			}
		}
		if (__probable(m != NULL)) {
			CLASSQ_PKT_INIT_MBUF(pkt, m);
			pkt_len = m_length(m);
		}
		break;
	}


	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (pkt->cp_mbuf != NULL) {
		VERIFY(qlen(q) > 0);
		qlen(q)--;

		/* qsize is an approximation, so adjust if necessary */
		if (((int)qsize(q) - pkt_len) > 0) {
			qsize(q) -= pkt_len;
		} else if (qsize(q) != 0) {
			qsize(q) = 0;
		}
	}
}

/* get a packet of a specific flow beginning from the head of the queue */
void
_getq_flow(class_queue_t *q, classq_pkt_t *pkt, u_int32_t flow)
{
	return _getq_flow_or_scidx(q, pkt, flow, TRUE);
}

/* Get a packet whose MBUF_SCIDX() < scidx from head of queue */
void
_getq_scidx_lt(class_queue_t *q, classq_pkt_t *pkt, u_int32_t scidx)
{
	return _getq_flow_or_scidx(q, pkt, scidx, FALSE);
}

/* get all packets (chained) starting from the head of the queue */
void
_getq_all(class_queue_t *q, classq_pkt_t *first, classq_pkt_t *last,
    u_int32_t *qlenp, u_int64_t *qsizep)
{
	switch (qptype(q)) {
	case QP_MBUF:
		first->cp_mbuf = MBUFQ_FIRST(&qmbufq(q));
		if (__probable(first->cp_mbuf != NULL)) {
			CLASSQ_PKT_INIT_MBUF(first, first->cp_mbuf);
		}
		if (last != NULL) {
			last->cp_mbuf = MBUFQ_LAST(&qmbufq(q));
			if (__probable(last->cp_mbuf != NULL)) {
				CLASSQ_PKT_INIT_MBUF(last, last->cp_mbuf);
			}
		}
		MBUFQ_INIT(&qmbufq(q));
		break;


	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (qlenp != NULL) {
		*qlenp = qlen(q);
	}
	if (qsizep != NULL) {
		*qsizep = qsize(q);
	}

	qlen(q) = 0;
	qsize(q) = 0;
}

static inline struct mbuf *
_getq_tail_mbuf(class_queue_t *q)
{
	struct mq_head *head = &qmbufq(q);
	struct mbuf *m = MBUFQ_LAST(head);

	if (m != NULL) {
		struct mbuf *n = MBUFQ_FIRST(head);

		while (n != NULL) {
			struct mbuf *next = MBUFQ_NEXT(n);
			if (next == m) {
				MBUFQ_NEXT(n) = NULL;
				break;
			}
			n = next;
		}
		VERIFY(n != NULL ||
		    (qlen(q) == 1 && m == MBUFQ_FIRST(head)));
		VERIFY(qlen(q) > 0);
		--qlen(q);

		/* qsize is an approximation, so adjust if necessary */
		if (((int)qsize(q) - m_length(m)) > 0) {
			qsize(q) -= m_length(m);
		} else if (qsize(q) != 0) {
			qsize(q) = 0;
		}

		if (qempty(q)) {
			VERIFY(m == MBUFQ_FIRST(head));
			MBUFQ_INIT(head);
		} else {
			VERIFY(n != NULL);
			head->mq_last = &MBUFQ_NEXT(n);
		}
	}
	return m;
}

/* drop a packet at the tail of the queue */
void
_getq_tail(class_queue_t *q, classq_pkt_t *pkt)
{
	switch (qptype(q)) {
	case QP_MBUF:
		pkt->cp_mbuf = _getq_tail_mbuf(q);
		if (__probable(pkt->cp_mbuf != NULL)) {
			CLASSQ_PKT_INIT_MBUF(pkt, pkt->cp_mbuf);
		}
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

static inline struct mbuf *
_getq_random_mbuf(class_queue_t *q)
{
	struct mq_head *head = &qmbufq(q);
	struct mbuf *m = NULL;
	unsigned int n;
	u_int32_t rnd;

	/* XXX: Add support for Kernel packet when needed */
	VERIFY((qptype(q) == QP_MBUF));

	n = qlen(q);
	if (n == 0) {
		VERIFY(MBUFQ_EMPTY(head));
		if (qsize(q) > 0) {
			qsize(q) = 0;
		}
		return NULL;
	}

	m = MBUFQ_FIRST(head);
	read_frandom(&rnd, sizeof(rnd));
	n = (rnd % n) + 1;

	if (n == 1) {
		if ((MBUFQ_FIRST(head) = MBUFQ_NEXT(m)) == NULL) {
			(head)->mq_last = &MBUFQ_FIRST(head);
		}
	} else {
		struct mbuf *p = NULL;

		VERIFY(n > 1);
		while (n--) {
			if (MBUFQ_NEXT(m) == NULL) {
				break;
			}
			p = m;
			m = MBUFQ_NEXT(m);
		}
		VERIFY(p != NULL && MBUFQ_NEXT(p) == m);

		if ((MBUFQ_NEXT(p) = MBUFQ_NEXT(m)) == NULL) {
			(head)->mq_last = &MBUFQ_NEXT(p);
		}
	}

	VERIFY(qlen(q) > 0);
	--qlen(q);

	/* qsize is an approximation, so adjust if necessary */
	if (((int)qsize(q) - m_length(m)) > 0) {
		qsize(q) -= m_length(m);
	} else if (qsize(q) != 0) {
		qsize(q) = 0;
	}

	MBUFQ_NEXT(m) = NULL;

	return m;
}

/* randomly select a packet in the queue */
void
_getq_random(class_queue_t *q, classq_pkt_t *pkt)
{
	switch (qptype(q)) {
	case QP_MBUF:
		pkt->cp_mbuf = _getq_random_mbuf(q);
		if (__probable(pkt->cp_mbuf != NULL)) {
			CLASSQ_PKT_INIT_MBUF(pkt, pkt->cp_mbuf);
		}
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

static inline void
_removeq_mbuf(class_queue_t *q, struct mbuf *m)
{
	struct mq_head *head = &qmbufq(q);
	struct mbuf *m0, **mtail;

	m0 = MBUFQ_FIRST(head);
	if (m0 == NULL) {
		return;
	}

	if (m0 != m) {
		while (m0 != NULL && MBUFQ_NEXT(m0) != m) {
			m0 = MBUFQ_NEXT(m0);
		}
		if (m0 == NULL) {
			return;
		}

		mtail = &MBUFQ_NEXT(m0);
	} else {
		mtail = &MBUFQ_FIRST(head);
	}

	*mtail = MBUFQ_NEXT(m);
	if (*mtail == NULL) {
		head->mq_last = mtail;
	}

	VERIFY(qlen(q) > 0);
	--qlen(q);

	/* qsize is an approximation, so adjust if necessary */
	if (((int)qsize(q) - m_length(m)) > 0) {
		qsize(q) -= m_length(m);
	} else if (qsize(q) != 0) {
		qsize(q) = 0;
	}

	MBUFQ_NEXT(m) = NULL;
}

/* remove a packet from the queue */
void
_removeq(class_queue_t *q, classq_pkt_t *pkt)
{
	switch (qptype(q)) {
	case QP_MBUF:
		ASSERT(pkt->cp_ptype == QP_MBUF);
		_removeq_mbuf(q, pkt->cp_mbuf);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

void
_flushq(class_queue_t *q)
{
	(void) _flushq_flow(q, 0, NULL, NULL);
}

static inline void
_flushq_flow_mbuf(class_queue_t *q, u_int32_t flow, u_int32_t *cnt,
    u_int32_t *len)
{
	MBUFQ_HEAD(mq_freeq) freeq;
	struct mbuf *m, *m_tmp;
	u_int32_t c = 0, l = 0;

	MBUFQ_INIT(&freeq);

	MBUFQ_FOREACH_SAFE(m, &qmbufq(q), m_tmp) {
		if (flow == 0 || ((m->m_flags & M_PKTHDR) &&
		    m->m_pkthdr.pkt_flowid == flow)) {
			/* remove it from the class queue */
			MBUFQ_REMOVE(&qmbufq(q), m);
			MBUFQ_NEXT(m) = NULL;

			/* and add it to the free queue */
			MBUFQ_ENQUEUE(&freeq, m);

			l += m_length(m);
			c++;
		}
	}
	VERIFY(c == 0 || !MBUFQ_EMPTY(&freeq));

	if (c > 0) {
		VERIFY(qlen(q) >= c);
		qlen(q) -= c;

		/* qsize is an approximation, so adjust if necessary */
		if (((int)qsize(q) - l) > 0) {
			qsize(q) -= l;
		} else if (qsize(q) != 0) {
			qsize(q) = 0;
		}
	}

	if (!MBUFQ_EMPTY(&freeq)) {
		m_freem_list(MBUFQ_FIRST(&freeq));
	}

	if (cnt != NULL) {
		*cnt = c;
	}
	if (len != NULL) {
		*len = l;
	}
}


void
_flushq_flow(class_queue_t *q, u_int32_t flow, u_int32_t *cnt, u_int32_t *len)
{
	switch (qptype(q)) {
	case QP_MBUF:
		_flushq_flow_mbuf(q, flow, cnt, len);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}
