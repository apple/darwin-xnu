/*
 * Copyright (c) 2007-2012 Apple Inc. All rights reserved.
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

/*	$OpenBSD: altq_cbq.c,v 1.23 2007/09/13 20:40:02 chl Exp $	*/
/*	$KAME: altq_cbq.c,v 1.9 2000/12/14 08:12:45 thorpej Exp $	*/

/*
 * Copyright (c) Sun Microsystems, Inc. 1993-1998 All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the SMCC Technology
 *      Development Group at Sun Microsystems, Inc.
 *
 * 4. The name of the Sun Microsystems, Inc nor may not be used to endorse or
 *      promote products derived from this software without specific prior
 *      written permission.
 *
 * SUN MICROSYSTEMS DOES NOT CLAIM MERCHANTABILITY OF THIS SOFTWARE OR THE
 * SUITABILITY OF THIS SOFTWARE FOR ANY PARTICULAR PURPOSE.  The software is
 * provided "as is" without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this software.
 */

#if PKTSCHED_CBQ

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kernel.h>
#include <sys/syslog.h>

#include <kern/zalloc.h>

#include <net/if.h>
#include <net/net_osdep.h>

#include <net/pktsched/pktsched_cbq.h>
#include <netinet/in.h>

/*
 * Forward Declarations.
 */
#if 0
static int cbq_enqueue_ifclassq(struct ifclassq *, struct mbuf *);
static struct mbuf *cbq_dequeue_ifclassq(struct ifclassq *, cqdq_op_t);
static int cbq_request_ifclassq(struct ifclassq *, cqrq_t, void *);
#endif
static int cbq_class_destroy(cbq_state_t *, struct rm_class *);
static int cbq_destroy_locked(cbq_state_t *);
static struct rm_class *cbq_clh_to_clp(cbq_state_t *, u_int32_t);
static const char *cbq_style(cbq_state_t *);
static int cbq_clear_interface(cbq_state_t *);
static void cbqrestart(struct ifclassq *);

#define	CBQ_ZONE_MAX	32		/* maximum elements in zone */
#define	CBQ_ZONE_NAME	"pktsched_cbq"	/* zone name */

static unsigned int cbq_size;		/* size of zone element */
static struct zone *cbq_zone;		/* zone for cbq */

void
cbq_init(void)
{
	_CASSERT(CBQCLF_RED == RMCF_RED);
	_CASSERT(CBQCLF_ECN == RMCF_ECN);
	_CASSERT(CBQCLF_RIO == RMCF_RIO);
	_CASSERT(CBQCLF_FLOWVALVE == RMCF_FLOWVALVE);
	_CASSERT(CBQCLF_CLEARDSCP == RMCF_CLEARDSCP);
	_CASSERT(CBQCLF_WRR == RMCF_WRR);
	_CASSERT(CBQCLF_EFFICIENT == RMCF_EFFICIENT);
	_CASSERT(CBQCLF_BLUE == RMCF_BLUE);
	_CASSERT(CBQCLF_SFB == RMCF_SFB);
	_CASSERT(CBQCLF_FLOWCTL == RMCF_FLOWCTL);
	_CASSERT(CBQCLF_LAZY == RMCF_LAZY);

	cbq_size = sizeof (cbq_state_t);
	cbq_zone = zinit(cbq_size, CBQ_ZONE_MAX * cbq_size, 0, CBQ_ZONE_NAME);
	if (cbq_zone == NULL) {
		panic("%s: failed allocating %s", __func__, CBQ_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(cbq_zone, Z_EXPAND, TRUE);
	zone_change(cbq_zone, Z_CALLERACCT, TRUE);

	rmclass_init();
}

cbq_state_t *
cbq_alloc(struct ifnet *ifp, int how, boolean_t altq)
{
	cbq_state_t	*cbqp;

	/* allocate and initialize cbq_state_t */
	cbqp = (how == M_WAITOK) ? zalloc(cbq_zone) : zalloc_noblock(cbq_zone);
	if (cbqp == NULL)
		return (NULL);

	bzero(cbqp, cbq_size);
	CALLOUT_INIT(&cbqp->cbq_callout);
	cbqp->cbq_qlen = 0;
	cbqp->ifnp.ifq_ = &ifp->if_snd;		/* keep the ifclassq */
	if (altq)
		cbqp->cbq_flags |= CBQSF_ALTQ;

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s scheduler allocated\n",
		    if_name(ifp), cbq_style(cbqp));
	}

	return (cbqp);
}

int
cbq_destroy(cbq_state_t *cbqp)
{
	struct ifclassq *ifq = cbqp->ifnp.ifq_;
	int err;

	IFCQ_LOCK(ifq);
	err = cbq_destroy_locked(cbqp);
	IFCQ_UNLOCK(ifq);

	return (err);
}

static int
cbq_destroy_locked(cbq_state_t *cbqp)
{
	IFCQ_LOCK_ASSERT_HELD(cbqp->ifnp.ifq_);

	(void) cbq_clear_interface(cbqp);

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s scheduler destroyed\n",
		    if_name(CBQS_IFP(cbqp)), cbq_style(cbqp));
	}

	if (cbqp->ifnp.default_)
		cbq_class_destroy(cbqp, cbqp->ifnp.default_);
	if (cbqp->ifnp.root_)
		cbq_class_destroy(cbqp, cbqp->ifnp.root_);

	/* deallocate cbq_state_t */
	zfree(cbq_zone, cbqp);

	return (0);
}

int
cbq_add_queue(cbq_state_t *cbqp, u_int32_t qlimit, u_int32_t priority,
    u_int32_t minburst, u_int32_t maxburst, u_int32_t pktsize,
    u_int32_t maxpktsize, u_int32_t ns_per_byte, u_int32_t maxidle, int minidle,
    u_int32_t offtime, u_int32_t flags, u_int32_t parent_qid, u_int32_t qid,
    struct rm_class **clp)
{
#pragma unused(minburst, maxburst, maxpktsize)
	struct rm_class	*borrow, *parent;
	struct rm_class	*cl;
	int i, error;

	IFCQ_LOCK_ASSERT_HELD(cbqp->ifnp.ifq_);

	/* Sanitize flags unless internally configured */
	if (cbqp->cbq_flags & CBQSF_ALTQ)
		flags &= CBQCLF_USERFLAGS;

	/*
	 * find a free slot in the class table.  if the slot matching
	 * the lower bits of qid is free, use this slot.  otherwise,
	 * use the first free slot.
	 */
	i = qid % CBQ_MAX_CLASSES;
	if (cbqp->cbq_class_tbl[i] != NULL) {
		for (i = 0; i < CBQ_MAX_CLASSES; i++)
			if (cbqp->cbq_class_tbl[i] == NULL)
				break;
		if (i == CBQ_MAX_CLASSES)
			return (EINVAL);
	}

	/* check parameters */
	if (priority >= CBQ_MAXPRI)
		return (EINVAL);

	if (ns_per_byte == 0) {
		log(LOG_ERR, "%s: %s invalid inverse data rate\n",
		    if_name(CBQS_IFP(cbqp)), cbq_style(cbqp));
		return (EINVAL);
	}

	/* Get pointers to parent and borrow classes.  */
	parent = cbq_clh_to_clp(cbqp, parent_qid);
	if (flags & CBQCLF_BORROW)
		borrow = parent;
	else
		borrow = NULL;

	/*
	 * A class must borrow from its parent or it can not
	 * borrow at all.  Hence, borrow can be null.
	 */
	if (parent == NULL && (flags & CBQCLF_ROOTCLASS) == 0) {
		log(LOG_ERR, "%s: %s no parent class!\n",
		    if_name(CBQS_IFP(cbqp)), cbq_style(cbqp));
		return (EINVAL);
	}

	if ((borrow != parent) && (borrow != NULL)) {
		log(LOG_ERR, "%s: %s borrow class != parent\n",
		    if_name(CBQS_IFP(cbqp)), cbq_style(cbqp));
		return (EINVAL);
	}

	/*
	 * check parameters
	 */
	switch (flags & CBQCLF_CLASSMASK) {
	case CBQCLF_ROOTCLASS:
		if (parent != NULL) {
			log(LOG_ERR, "%s: %s parent exists\n",
			    if_name(CBQS_IFP(cbqp)), cbq_style(cbqp));
			return (EINVAL);
		}
		if (cbqp->ifnp.root_) {
			log(LOG_ERR, "%s: %s root class exists\n",
			    if_name(CBQS_IFP(cbqp)), cbq_style(cbqp));
			return (EINVAL);
		}
		break;
	case CBQCLF_DEFCLASS:
		if (cbqp->ifnp.default_) {
			log(LOG_ERR, "%s: %s default class exists\n",
			    if_name(CBQS_IFP(cbqp)), cbq_style(cbqp));
			return (EINVAL);
		}
		break;
	case 0:
		break;
	default:
		/* more than two flags bits set */
		log(LOG_ERR, "%s: %s invalid class flags 0x%x\n",
		    if_name(CBQS_IFP(cbqp)), cbq_style(cbqp),
		    (flags & CBQCLF_CLASSMASK));
		return (EINVAL);
	}

	/*
	 * create a class.  if this is a root class, initialize the
	 * interface.
	 */
	if ((flags & CBQCLF_CLASSMASK) == CBQCLF_ROOTCLASS) {
		error = rmc_init(cbqp->ifnp.ifq_, &cbqp->ifnp, ns_per_byte,
		    cbqrestart, qid, qlimit, RM_MAXQUEUED, maxidle, minidle,
		    offtime, flags);
		if (error != 0)
			return (error);
		cl = cbqp->ifnp.root_;
	} else {
		cl = rmc_newclass(priority, &cbqp->ifnp, ns_per_byte,
		    rmc_delay_action, qid, qlimit, parent, borrow, maxidle,
		    minidle, offtime, pktsize, flags);
	}
	if (cl == NULL)
		return (ENOMEM);

	/* return handle to user space. */
	cl->stats_.handle = qid;
	cl->stats_.depth = cl->depth_;

	/* save the allocated class */
	cbqp->cbq_class_tbl[i] = cl;

	if ((flags & CBQCLF_CLASSMASK) == CBQCLF_DEFCLASS)
		cbqp->ifnp.default_ = cl;

	if (clp != NULL)
		*clp = cl;

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s created qid=%d pri=%d qlimit=%d "
		    "flags=%b\n", if_name(CBQS_IFP(cbqp)), cbq_style(cbqp),
		    qid, priority, qlimit, flags, CBQCLF_BITS);
	}

	return (0);
}

int
cbq_remove_queue(cbq_state_t *cbqp, u_int32_t qid)
{
	struct rm_class	*cl;
	int i;

	IFCQ_LOCK_ASSERT_HELD(cbqp->ifnp.ifq_);

	if ((cl = cbq_clh_to_clp(cbqp, qid)) == NULL)
		return (EINVAL);

	/* if we are a parent class, then return an error. */
	if (RMC_IS_A_PARENT_CLASS(cl))
		return (EINVAL);

	/* delete the class */
	rmc_delete_class(&cbqp->ifnp, cl);

	/*
	 * free the class handle
	 */
	for (i = 0; i < CBQ_MAX_CLASSES; i++) {
		if (cbqp->cbq_class_tbl[i] == cl) {
			cbqp->cbq_class_tbl[i] = NULL;
			if (cl == cbqp->ifnp.root_)
				cbqp->ifnp.root_ = NULL;
			if (cl == cbqp->ifnp.default_)
				cbqp->ifnp.default_ = NULL;
			break;
		}
	}
	return (0);
}

/*
 * int
 * cbq_class_destroy(cbq_mod_state_t *, struct rm_class *) - This
 *	function destroys a given traffic class.  Before destroying
 *	the class, all traffic for that class is released.
 */
static int
cbq_class_destroy(cbq_state_t *cbqp, struct rm_class *cl)
{
	int	i;

	IFCQ_LOCK_ASSERT_HELD(cbqp->ifnp.ifq_);

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s destroyed qid=%d pri=%d\n",
		    if_name(CBQS_IFP(cbqp)), cbq_style(cbqp),
		    cl->stats_.handle, cl->pri_);
	}

	/* delete the class */
	rmc_delete_class(&cbqp->ifnp, cl);

	/*
	 * free the class handle
	 */
	for (i = 0; i < CBQ_MAX_CLASSES; i++)
		if (cbqp->cbq_class_tbl[i] == cl)
			cbqp->cbq_class_tbl[i] = NULL;

	if (cl == cbqp->ifnp.root_)
		cbqp->ifnp.root_ = NULL;
	if (cl == cbqp->ifnp.default_)
		cbqp->ifnp.default_ = NULL;

	return (0);
}

/* convert class handle to class pointer */
static struct rm_class *
cbq_clh_to_clp(cbq_state_t *cbqp, u_int32_t chandle)
{
	int i;
	struct rm_class *cl;

	IFCQ_LOCK_ASSERT_HELD(cbqp->ifnp.ifq_);

	/*
	 * first, try optimistically the slot matching the lower bits of
	 * the handle.  if it fails, do the linear table search.
	 */
	i = chandle % CBQ_MAX_CLASSES;
	if ((cl = cbqp->cbq_class_tbl[i]) != NULL &&
	    cl->stats_.handle == chandle)
		return (cl);
	for (i = 0; i < CBQ_MAX_CLASSES; i++)
		if ((cl = cbqp->cbq_class_tbl[i]) != NULL &&
		    cl->stats_.handle == chandle)
			return (cl);
	return (NULL);
}

static const char *
cbq_style(cbq_state_t *cbqp)
{
	return ((cbqp->cbq_flags & CBQSF_ALTQ) ? "ALTQ_CBQ" : "CBQ");
}

static int
cbq_clear_interface(cbq_state_t *cbqp)
{
	int		 again, i;
	struct rm_class	*cl;

	IFCQ_LOCK_ASSERT_HELD(cbqp->ifnp.ifq_);

	/* clear out the classes now */
	do {
		again = 0;
		for (i = 0; i < CBQ_MAX_CLASSES; i++) {
			if ((cl = cbqp->cbq_class_tbl[i]) != NULL) {
				if (RMC_IS_A_PARENT_CLASS(cl))
					again++;
				else {
					cbq_class_destroy(cbqp, cl);
					cbqp->cbq_class_tbl[i] = NULL;
					if (cl == cbqp->ifnp.root_)
						cbqp->ifnp.root_ = NULL;
					if (cl == cbqp->ifnp.default_)
						cbqp->ifnp.default_ = NULL;
				}
			}
		}
	} while (again);

	return (0);
}

/* copy the stats info in rm_class to class_states_t */
int
cbq_get_class_stats(cbq_state_t *cbqp, u_int32_t qid, class_stats_t *statsp)
{
	struct rm_class	*cl;

	IFCQ_LOCK_ASSERT_HELD(cbqp->ifnp.ifq_);

	if ((cl = cbq_clh_to_clp(cbqp, qid)) == NULL)
		return (EINVAL);

	statsp->xmit_cnt	= cl->stats_.xmit_cnt;
	statsp->drop_cnt	= cl->stats_.drop_cnt;
	statsp->over		= cl->stats_.over;
	statsp->borrows		= cl->stats_.borrows;
	statsp->overactions	= cl->stats_.overactions;
	statsp->delays		= cl->stats_.delays;

	statsp->depth		= cl->depth_;
	statsp->priority	= cl->pri_;
	statsp->maxidle		= cl->maxidle_;
	statsp->minidle		= cl->minidle_;
	statsp->offtime		= cl->offtime_;
	statsp->qmax		= qlimit(&cl->q_);
	statsp->ns_per_byte	= cl->ns_per_byte_;
	statsp->wrr_allot	= cl->w_allotment_;
	statsp->qcnt		= qlen(&cl->q_);
	statsp->avgidle		= cl->avgidle_;

	statsp->qtype		= qtype(&cl->q_);
	statsp->qstate		= qstate(&cl->q_);
#if CLASSQ_RED
	if (q_is_red(&cl->q_))
		red_getstats(cl->red_, &statsp->red[0]);
#endif /* CLASSQ_RED */
#if CLASSQ_RIO
	if (q_is_rio(&cl->q_))
		rio_getstats(cl->rio_, &statsp->red[0]);
#endif /* CLASSQ_RIO */
#if CLASSQ_BLUE
	if (q_is_blue(&cl->q_))
		blue_getstats(cl->blue_, &statsp->blue);
#endif /* CLASSQ_BLUE */
	if (q_is_sfb(&cl->q_) && cl->sfb_ != NULL)
		sfb_getstats(cl->sfb_, &statsp->sfb);

	return (0);
}

int
cbq_enqueue(cbq_state_t *cbqp, struct rm_class *cl, struct mbuf *m,
    struct pf_mtag *t)
{
	struct ifclassq *ifq = cbqp->ifnp.ifq_;
	int len, ret;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	/* grab class set by classifier */
	if (!(m->m_flags & M_PKTHDR)) {
		/* should not happen */
		log(LOG_ERR, "%s: packet for %s does not have pkthdr\n",
		    if_name(ifq->ifcq_ifp));
		IFCQ_CONVERT_LOCK(ifq);
		m_freem(m);
		return (ENOBUFS);
	}

	if (cl == NULL) {
#if PF_ALTQ
		cl = cbq_clh_to_clp(cbqp, t->pftag_qid);
#else /* !PF_ALTQ */
		cl = cbq_clh_to_clp(cbqp, 0);
#endif /* !PF_ALTQ */
		if (cl == NULL) {
			cl = cbqp->ifnp.default_;
			if (cl == NULL) {
				IFCQ_CONVERT_LOCK(ifq);
				m_freem(m);
				return (ENOBUFS);
			}
		}
	}

	len = m_pktlen(m);

	ret = rmc_queue_packet(cl, m, t);
	if (ret != 0) {
		if (ret == CLASSQEQ_SUCCESS_FC) {
			/* packet enqueued, return advisory feedback */
			ret = EQFULL;
		} else {
			VERIFY(ret == CLASSQEQ_DROPPED ||
			    ret == CLASSQEQ_DROPPED_FC ||
			    ret == CLASSQEQ_DROPPED_SP);
			/* packet has been freed in rmc_queue_packet */
			PKTCNTR_ADD(&cl->stats_.drop_cnt, 1, len);
			IFCQ_DROP_ADD(ifq, 1, len);
			switch (ret) {
			case CLASSQEQ_DROPPED:
				return (ENOBUFS);
			case CLASSQEQ_DROPPED_FC:
				return (EQFULL);
			case CLASSQEQ_DROPPED_SP:
				return (EQSUSPENDED);
			}
			/* NOT REACHED */
		}
	}

	/* successfully queued. */
	++cbqp->cbq_qlen;
	IFCQ_INC_LEN(ifq);
	IFCQ_INC_BYTES(ifq, len);

	return (ret);
}

struct mbuf *
cbq_dequeue(cbq_state_t *cbqp, cqdq_op_t op)
{
	struct ifclassq *ifq = cbqp->ifnp.ifq_;
	struct mbuf *m;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	m = rmc_dequeue_next(&cbqp->ifnp, op);

	if (m && op == CLASSQDQ_REMOVE) {
		--cbqp->cbq_qlen;  /* decrement # of packets in cbq */
		IFCQ_DEC_LEN(ifq);
		IFCQ_DEC_BYTES(ifq, m_pktlen(m));
		IFCQ_XMIT_ADD(ifq, 1, m_pktlen(m));

		/* Update the class. */
		rmc_update_class_util(&cbqp->ifnp);
	}
	return (m);
}

/*
 * void
 * cbqrestart(queue_t *) - Restart sending of data.
 * called from rmc_restart via timeout after waking up
 * a suspended class.
 *	Returns:	NONE
 */

static void
cbqrestart(struct ifclassq *ifq)
{
	u_int32_t qlen;

	IFCQ_LOCK(ifq);
	qlen = IFCQ_LEN(ifq);
	IFCQ_UNLOCK(ifq);

	if (qlen > 0)
		ifnet_start(ifq->ifcq_ifp);
}

void
cbq_purge(cbq_state_t *cbqp)
{
	struct rm_class	*cl;
	int		 i;

	IFCQ_LOCK_ASSERT_HELD(cbqp->ifnp.ifq_);

	for (i = 0; i < CBQ_MAX_CLASSES; i++) {
		if ((cl = cbqp->cbq_class_tbl[i]) != NULL) {
			if (!qempty(&cl->q_) && pktsched_verbose) {
				log(LOG_DEBUG, "%s: %s purge qid=%d pri=%d "
				    "qlen=%d\n", if_name(CBQS_IFP(cbqp)),
				    cbq_style(cbqp), cl->stats_.handle,
				    cl->pri_, qlen(&cl->q_));
			}
			rmc_dropall(cl);
		}
	}
}

void
cbq_event(cbq_state_t *cbqp, cqev_t ev)
{
	struct rm_class	*cl;
	int		 i;

	IFCQ_LOCK_ASSERT_HELD(cbqp->ifnp.ifq_);

	for (i = 0; i < CBQ_MAX_CLASSES; i++) {
		if ((cl = cbqp->cbq_class_tbl[i]) != NULL) {
			if (pktsched_verbose) {
				log(LOG_DEBUG, "%s: %s update qid=%d pri=%d "
				    "event=%s\n", if_name(CBQS_IFP(cbqp)),
				    cbq_style(cbqp), cl->stats_.handle,
				    cl->pri_, ifclassq_ev2str(ev));
			}
			rmc_updateq(cl, ev);
		}
	}
}

int
cqb_setup_ifclassq(struct ifclassq *ifq, u_int32_t flags)
{
#pragma unused(ifq, flags)
	return (ENXIO);		/* not yet */
}

int
cbq_teardown_ifclassq(struct ifclassq *ifq)
{
	cbq_state_t *cbqp = ifq->ifcq_disc;
	int i;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(cbqp != NULL && ifq->ifcq_type == PKTSCHEDT_CBQ);

	(void) cbq_destroy_locked(cbqp);

	ifq->ifcq_disc = NULL;
	for (i = 0; i < IFCQ_SC_MAX; i++) {
		ifq->ifcq_disc_slots[i].qid = 0;
		ifq->ifcq_disc_slots[i].cl = NULL;
	}

	return (ifclassq_detach(ifq));
}

int
cbq_getqstats_ifclassq(struct ifclassq *ifq, u_int32_t slot,
    struct if_ifclassq_stats *ifqs)
{
	cbq_state_t *cbqp = ifq->ifcq_disc;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_type == PKTSCHEDT_CBQ);

	if (slot >= IFCQ_SC_MAX)
		return (EINVAL);

	return (cbq_get_class_stats(cbqp, ifq->ifcq_disc_slots[slot].qid,
	    &ifqs->ifqs_cbq_stats));
}
#endif /* PKTSCHED_CBQ */
