/*
 * Copyright (c) 2008-2012 Apple Inc. All rights reserved.
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
/*	$OpenBSD: if_altq.h,v 1.11 2007/11/18 12:51:48 mpf Exp $	*/
/*	$KAME: if_altq.h,v 1.6 2001/01/29 19:59:09 itojun Exp $	*/

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
#ifndef _NET_ALTQ_IF_ALTQ_H_
#define	_NET_ALTQ_IF_ALTQ_H_

#ifdef BSD_KERNEL_PRIVATE
#if PF_ALTQ
#include <net/classq/if_classq.h>

/* altq request types */
typedef enum altrq {
	ALTRQ_PURGE =		CLASSQRQ_PURGE,		/* purge all packets */
	ALTRQ_PURGE_SC =	CLASSQRQ_PURGE_SC,	/* purge SC flow */
	ALTRQ_EVENT =		CLASSQRQ_EVENT,		/* interface events */
	ALTRQ_THROTTLE =	CLASSQRQ_THROTTLE,	/* throttle packets */
} altrq_t;

struct ifaltq;
enum altdq_op;

typedef	int (*altq_enq_func)(struct ifaltq *, struct mbuf *);
typedef	struct mbuf *(*altq_deq_func)(struct ifaltq *, enum altdq_op);
typedef	struct mbuf *(*altq_deq_sc_func)(struct ifaltq *,
    mbuf_svc_class_t, enum altdq_op);
typedef	int (*altq_req_func)(struct ifaltq *, enum altrq, void *);

/*
 * Structure defining a queue for a network interface.
 */
struct ifaltq {
	struct ifclassq	*altq_ifcq;	/* back pointer to interface queue */

	/* alternate queueing related fields */
	u_int32_t	altq_type;	/* discipline type */
	u_int32_t	altq_flags;	/* flags (e.g. ready, in-use) */
	void		*altq_disc;	/* for discipline-specific use */

	altq_enq_func	altq_enqueue;
	altq_deq_func	altq_dequeue;
	altq_deq_sc_func altq_dequeue_sc;
	altq_req_func	altq_request;
};

/* altq_flags */
#define	ALTQF_READY	 0x01	/* driver supports alternate queueing */
#define	ALTQF_ENABLED	 0x02	/* altq is in use */
#define	ALTQF_DRIVER1	 0x40	/* driver specific */

/* altq_flags set internally only: */
#define	ALTQF_CANTCHANGE	(ALTQF_READY)

/* altq_dequeue op arg */
typedef enum altdq_op {
	ALTDQ_REMOVE = CLASSQDQ_REMOVE,	/* dequeue mbuf from the queue */
	ALTDQ_POLL = CLASSQDQ_POLL,	/* don't dequeue mbuf from the queue */
} altdq_op_t;

#define	ALTQ_IS_READY(_altq)		((_altq)->altq_flags & ALTQF_READY)
#define	ALTQ_IS_ENABLED(_altq)		((_altq)->altq_flags & ALTQF_ENABLED)
#define	ALTQ_IS_ATTACHED(_altq)		((_altq)->altq_disc != NULL)

#define	ALTQ_ENQUEUE(_altq, _m, _err) do {				\
	(_err) = (*(_altq)->altq_enqueue)(_altq, _m);			\
} while (0)

#define	ALTQ_DEQUEUE(_altq, _m) do {					\
	(_m) = (*(_altq)->altq_dequeue)(_altq, ALTDQ_REMOVE);		\
} while (0)

#define	ALTQ_DEQUEUE_SC(_altq, _sc, _m) do {				\
	(_m) = (*(_altq)->altq_dequeue_sc)(_altq, _sc, ALTDQ_REMOVE);	\
} while (0)

#define	ALTQ_POLL(_altq, _m) do {					\
	(_m) = (*(_altq)->altq_dequeue)(_altq, ALTDQ_POLL);		\
} while (0)

#define	ALTQ_POLL_SC(_altq, _sc, _m) do {				\
	(_m) = (*(_altq)->altq_dequeue_sc)(_altq, _sc, ALTDQ_POLL);	\
} while (0)

#define	ALTQ_PURGE(_altq) do {						\
	(void) (*(_altq)->altq_request)(_altq, ALTRQ_PURGE, NULL);	\
} while (0)

#define	ALTQ_PURGE_SC(_altq, _sc, _flow, _packets, _bytes) do {		\
	cqrq_purge_sc_t _req = { _sc, _flow, 0, 0 };			\
	(void) (*(_altq)->altq_request)(_altq, ALTRQ_PURGE_SC, &_req);	\
	(_packets) = _req.packets;					\
	(_bytes) = _req.bytes;						\
} while (0)

#define	ALTQ_UPDATE(_altq, _ev) do {					\
	(void) (*(_altq)->altq_request)(_altq, ALTRQ_EVENT,		\
	    (void *)(_ev));						\
} while (0)

#define	ALTQ_SET_READY(_altq) do {					\
	IFCQ_LOCK_ASSERT_HELD((_altq)->altq_ifcq);			\
	(_altq)->altq_flags |= ALTQF_READY;				\
} while (0)

#define	ALTQ_CLEAR_READY(_altq) do {					\
	IFCQ_LOCK_ASSERT_HELD((_altq)->altq_ifcq);			\
	(_altq)->altq_flags &= ~ALTQF_READY;				\
} while (0)

extern int altq_attach(struct ifaltq *, u_int32_t, void *,
    altq_enq_func, altq_deq_func, altq_deq_sc_func, altq_req_func);
extern int altq_detach(struct ifaltq *);
extern int altq_enable(struct ifaltq *);
extern int altq_disable(struct ifaltq *);
#endif /* PF_ALTQ */
#endif /* BSD_KERNEL_PRIVATE */
#endif /* _NET_ALTQ_IF_ALTQ_H_ */
