/*
 * Copyright (c) 2011-2012 Apple Inc. All rights reserved.
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
 * Copyright (c) 2010 Fabio Checconi, Luigi Rizzo, Paolo Valente
 * All rights reserved
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Quick Fair Queueing is described in
 * "QFQ: Efficient Packet Scheduling with Tight Bandwidth Distribution
 * Guarantees" by Fabio Checconi, Paolo Valente, and Luigi Rizzo.
 *
 * This code is ported from the dummynet(4) QFQ implementation.
 * See also http://info.iet.unipi.it/~luigi/qfq/
 */

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

#include <net/pktsched/pktsched_qfq.h>
#include <netinet/in.h>

/*
 * function prototypes
 */
static int qfq_enqueue_ifclassq(struct ifclassq *, struct mbuf *);
static struct mbuf *qfq_dequeue_ifclassq(struct ifclassq *, cqdq_op_t);
static int qfq_request_ifclassq(struct ifclassq *, cqrq_t, void *);
static int qfq_clear_interface(struct qfq_if *);
static struct qfq_class *qfq_class_create(struct qfq_if *, u_int32_t,
    u_int32_t, u_int32_t, u_int32_t, u_int32_t);
static int qfq_class_destroy(struct qfq_if *, struct qfq_class *);
static int qfq_destroy_locked(struct qfq_if *);
static inline int qfq_addq(struct qfq_class *, struct mbuf *, struct pf_mtag *);
static inline struct mbuf *qfq_getq(struct qfq_class *);
static inline struct mbuf *qfq_pollq(struct qfq_class *);
static void qfq_purgeq(struct qfq_if *, struct qfq_class *, u_int32_t,
    u_int32_t *, u_int32_t *);
static void qfq_purge_sc(struct qfq_if *, cqrq_purge_sc_t *);
static void qfq_updateq(struct qfq_if *, struct qfq_class *, cqev_t);
static int qfq_throttle(struct qfq_if *, cqrq_throttle_t *);
static int qfq_resumeq(struct qfq_if *, struct qfq_class *);
static int qfq_suspendq(struct qfq_if *, struct qfq_class *);
static int qfq_stat_sc(struct qfq_if *, cqrq_stat_sc_t *);
static inline struct qfq_class *qfq_clh_to_clp(struct qfq_if *, u_int32_t);
static const char *qfq_style(struct qfq_if *);

static inline int qfq_gt(u_int64_t, u_int64_t);
static inline u_int64_t qfq_round_down(u_int64_t, u_int32_t);
static inline struct qfq_group *qfq_ffs(struct qfq_if *, pktsched_bitmap_t);
static int qfq_calc_index(struct qfq_class *, u_int32_t, u_int32_t);
static inline pktsched_bitmap_t mask_from(pktsched_bitmap_t, int);
static inline u_int32_t qfq_calc_state(struct qfq_if *, struct qfq_group *);
static inline void qfq_move_groups(struct qfq_if *, pktsched_bitmap_t,
    int, int);
static inline void qfq_unblock_groups(struct qfq_if *, int, u_int64_t);
static inline void qfq_make_eligible(struct qfq_if *, u_int64_t);
static inline void qfq_slot_insert(struct qfq_if *, struct qfq_group *,
    struct qfq_class *, u_int64_t);
static inline void qfq_front_slot_remove(struct qfq_group *);
static inline struct qfq_class *qfq_slot_scan(struct qfq_if *,
    struct qfq_group *);
static inline void qfq_slot_rotate(struct qfq_if *, struct qfq_group *,
    u_int64_t);
static inline void qfq_update_eligible(struct qfq_if *, u_int64_t);
static inline int qfq_update_class(struct qfq_if *, struct qfq_group *,
    struct qfq_class *);
static inline void qfq_update_start(struct qfq_if *, struct qfq_class *);
static inline void qfq_slot_remove(struct qfq_if *, struct qfq_group *,
    struct qfq_class *);
static void qfq_deactivate_class(struct qfq_if *, struct qfq_class *);
static const char *qfq_state2str(int);
#if QFQ_DEBUG
static void qfq_dump_groups(struct qfq_if *, u_int32_t);
static void qfq_dump_sched(struct qfq_if *, const char *);
#endif /* QFQ_DEBUG */

#define	QFQ_ZONE_MAX	32		/* maximum elements in zone */
#define	QFQ_ZONE_NAME	"pktsched_qfq"	/* zone name */

static unsigned int qfq_size;		/* size of zone element */
static struct zone *qfq_zone;		/* zone for qfq */

#define	QFQ_CL_ZONE_MAX	32	/* maximum elements in zone */
#define	QFQ_CL_ZONE_NAME	"pktsched_qfq_cl" /* zone name */

static unsigned int qfq_cl_size;	/* size of zone element */
static struct zone *qfq_cl_zone;	/* zone for qfq_class */

/*
 * Maximum number of consecutive slots occupied by backlogged classes
 * inside a group.  This is approx lmax/lmin + 5.  Used when ALTQ is
 * available.
 *
 * XXX check because it poses constraints on MAX_INDEX
 */
#define	QFQ_MAX_SLOTS	32	/* default when ALTQ is available */

void
qfq_init(void)
{
	qfq_size = sizeof (struct qfq_if);
	qfq_zone = zinit(qfq_size, QFQ_ZONE_MAX * qfq_size,
	    0, QFQ_ZONE_NAME);
	if (qfq_zone == NULL) {
		panic("%s: failed allocating %s", __func__, QFQ_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(qfq_zone, Z_EXPAND, TRUE);
	zone_change(qfq_zone, Z_CALLERACCT, TRUE);

	qfq_cl_size = sizeof (struct qfq_class);
	qfq_cl_zone = zinit(qfq_cl_size, QFQ_CL_ZONE_MAX * qfq_cl_size,
	    0, QFQ_CL_ZONE_NAME);
	if (qfq_cl_zone == NULL) {
		panic("%s: failed allocating %s", __func__, QFQ_CL_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(qfq_cl_zone, Z_EXPAND, TRUE);
	zone_change(qfq_cl_zone, Z_CALLERACCT, TRUE);
}

struct qfq_if *
qfq_alloc(struct ifnet *ifp, int how, boolean_t altq)
{
	struct qfq_if	*qif;

	qif = (how == M_WAITOK) ? zalloc(qfq_zone) : zalloc_noblock(qfq_zone);
	if (qif == NULL)
		return (NULL);

	bzero(qif, qfq_size);
	qif->qif_ifq = &ifp->if_snd;
	if (altq) {
		qif->qif_maxclasses = QFQ_MAX_CLASSES;
		qif->qif_maxslots = QFQ_MAX_SLOTS;
		qif->qif_flags |= QFQIFF_ALTQ;
	} else {
		qif->qif_maxclasses = IFCQ_SC_MAX;
		/*
		 * TODO: adi@apple.com
		 *
		 * Ideally I would like to have the following
		 * but QFQ needs further modifications.
		 *
		 *	qif->qif_maxslots = IFCQ_SC_MAX;
		 */
		qif->qif_maxslots = QFQ_MAX_SLOTS;
	}

	if ((qif->qif_class_tbl = _MALLOC(sizeof (struct qfq_class *) *
	    qif->qif_maxclasses, M_DEVBUF, M_WAITOK|M_ZERO)) == NULL) {
		log(LOG_ERR, "%s: %s unable to allocate class table array\n",
		    if_name(ifp), qfq_style(qif));
		goto error;
	}

	if ((qif->qif_groups = _MALLOC(sizeof (struct qfq_group *) *
	    (QFQ_MAX_INDEX + 1), M_DEVBUF, M_WAITOK|M_ZERO)) == NULL) {
		log(LOG_ERR, "%s: %s unable to allocate group array\n",
		    if_name(ifp), qfq_style(qif));
		goto error;
	}

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s scheduler allocated\n",
		    if_name(ifp), qfq_style(qif));
	}

	return (qif);

error:
	if (qif->qif_class_tbl != NULL) {
		_FREE(qif->qif_class_tbl, M_DEVBUF);
		qif->qif_class_tbl = NULL;
	}
	if (qif->qif_groups != NULL) {
		_FREE(qif->qif_groups, M_DEVBUF);
		qif->qif_groups = NULL;
	}
	zfree(qfq_zone, qif);

	return (NULL);
}

int
qfq_destroy(struct qfq_if *qif)
{
	struct ifclassq *ifq = qif->qif_ifq;
	int err;

	IFCQ_LOCK(ifq);
	err = qfq_destroy_locked(qif);
	IFCQ_UNLOCK(ifq);

	return (err);
}

static int
qfq_destroy_locked(struct qfq_if *qif)
{
	int i;

	IFCQ_LOCK_ASSERT_HELD(qif->qif_ifq);

	(void) qfq_clear_interface(qif);

	VERIFY(qif->qif_class_tbl != NULL);
	_FREE(qif->qif_class_tbl, M_DEVBUF);
	qif->qif_class_tbl = NULL;

	VERIFY(qif->qif_groups != NULL);
	for (i = 0; i <= QFQ_MAX_INDEX; i++) {
		struct qfq_group *grp = qif->qif_groups[i];

		if (grp != NULL) {
			VERIFY(grp->qfg_slots != NULL);
			_FREE(grp->qfg_slots, M_DEVBUF);
			grp->qfg_slots = NULL;
			_FREE(grp, M_DEVBUF);
			qif->qif_groups[i] = NULL;
		}
	}
	_FREE(qif->qif_groups, M_DEVBUF);
	qif->qif_groups = NULL;

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s scheduler destroyed\n",
		    if_name(QFQIF_IFP(qif)), qfq_style(qif));
	}

	zfree(qfq_zone, qif);

	return (0);
}

/*
 * bring the interface back to the initial state by discarding
 * all the filters and classes.
 */
static int
qfq_clear_interface(struct qfq_if *qif)
{
	struct qfq_class *cl;
	int i;

	IFCQ_LOCK_ASSERT_HELD(qif->qif_ifq);

	/* clear out the classes */
	for (i = 0; i < qif->qif_maxclasses; i++)
		if ((cl = qif->qif_class_tbl[i]) != NULL)
			qfq_class_destroy(qif, cl);

	return (0);
}

/* discard all the queued packets on the interface */
void
qfq_purge(struct qfq_if *qif)
{
	struct qfq_class *cl;
	int i;

	IFCQ_LOCK_ASSERT_HELD(qif->qif_ifq);

	for (i = 0; i < qif->qif_maxclasses; i++) {
		if ((cl = qif->qif_class_tbl[i]) != NULL)
			qfq_purgeq(qif, cl, 0, NULL, NULL);
	}
#if !PF_ALTQ
	/*
	 * This assertion is safe to be made only when PF_ALTQ is not
	 * configured; otherwise, IFCQ_LEN represents the sum of the
	 * packets managed by ifcq_disc and altq_disc instances, which
	 * is possible when transitioning between the two.
	 */
	VERIFY(IFCQ_LEN(qif->qif_ifq) == 0);
#endif /* !PF_ALTQ */
}

static void
qfq_purge_sc(struct qfq_if *qif, cqrq_purge_sc_t *pr)
{
	struct ifclassq *ifq = qif->qif_ifq;
	u_int32_t i;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	VERIFY(pr->sc == MBUF_SC_UNSPEC || MBUF_VALID_SC(pr->sc));
	VERIFY(pr->flow != 0);

	if (pr->sc != MBUF_SC_UNSPEC) {
		i = MBUF_SCIDX(pr->sc);
		VERIFY(i < IFCQ_SC_MAX);

		qfq_purgeq(qif, ifq->ifcq_disc_slots[i].cl,
		    pr->flow, &pr->packets, &pr->bytes);
	} else {
		u_int32_t cnt, len;

		pr->packets = 0;
		pr->bytes = 0;

		for (i = 0; i < IFCQ_SC_MAX; i++) {
			qfq_purgeq(qif, ifq->ifcq_disc_slots[i].cl,
			    pr->flow, &cnt, &len);
			pr->packets += cnt;
			pr->bytes += len;
		}
	}
}

void
qfq_event(struct qfq_if *qif, cqev_t ev)
{
	struct qfq_class *cl;
	int i;

	IFCQ_LOCK_ASSERT_HELD(qif->qif_ifq);

	for (i = 0; i < qif->qif_maxclasses; i++)
		if ((cl = qif->qif_class_tbl[i]) != NULL)
			qfq_updateq(qif, cl, ev);
}

int
qfq_add_queue(struct qfq_if *qif, u_int32_t qlimit, u_int32_t weight,
    u_int32_t maxsz, u_int32_t flags, u_int32_t qid, struct qfq_class **clp)
{
	struct qfq_class *cl;
	u_int32_t w;

	IFCQ_LOCK_ASSERT_HELD(qif->qif_ifq);

	if (qfq_clh_to_clp(qif, qid) != NULL)
		return (EBUSY);

	/* check parameters */
	if (weight == 0 || weight > QFQ_MAX_WEIGHT)
		return (EINVAL);

	w = (QFQ_ONE_FP / (QFQ_ONE_FP / weight));
	if (qif->qif_wsum + w > QFQ_MAX_WSUM)
		return (EINVAL);

	if (maxsz == 0 || maxsz > (1 << QFQ_MTU_SHIFT))
		return (EINVAL);

	cl = qfq_class_create(qif, weight, qlimit, flags, maxsz, qid);
	if (cl == NULL)
		return (ENOMEM);

	if (clp != NULL)
		*clp = cl;

	return (0);
}

static struct qfq_class *
qfq_class_create(struct qfq_if *qif, u_int32_t weight, u_int32_t qlimit,
    u_int32_t flags, u_int32_t maxsz, u_int32_t qid)
{
	struct ifnet *ifp;
	struct ifclassq *ifq;
	struct qfq_group *grp;
	struct qfq_class *cl;
	u_int32_t w;			/* approximated weight */
	int i;

	IFCQ_LOCK_ASSERT_HELD(qif->qif_ifq);

	/* Sanitize flags unless internally configured */
	if (qif->qif_flags & QFQIFF_ALTQ)
		flags &= QFCF_USERFLAGS;

	if (qif->qif_classes >= qif->qif_maxclasses) {
		log(LOG_ERR, "%s: %s out of classes! (max %d)\n",
		    if_name(QFQIF_IFP(qif)), qfq_style(qif),
		    qif->qif_maxclasses);
		return (NULL);
	}

#if !CLASSQ_RED
	if (flags & QFCF_RED) {
		log(LOG_ERR, "%s: %s RED not available!\n",
		    if_name(QFQIF_IFP(qif)), qfq_style(qif));
		return (NULL);
	}
#endif /* !CLASSQ_RED */

#if !CLASSQ_RIO
	if (flags & QFCF_RIO) {
		log(LOG_ERR, "%s: %s RIO not available!\n",
		    if_name(QFQIF_IFP(qif)), qfq_style(qif));
		return (NULL);
	}
#endif /* CLASSQ_RIO */

#if !CLASSQ_BLUE
	if (flags & QFCF_BLUE) {
		log(LOG_ERR, "%s: %s BLUE not available!\n",
		    if_name(QFQIF_IFP(qif)), qfq_style(qif));
		return (NULL);
	}
#endif /* CLASSQ_BLUE */

	/* These are mutually exclusive */
	if ((flags & (QFCF_RED|QFCF_RIO|QFCF_BLUE|QFCF_SFB)) &&
	    (flags & (QFCF_RED|QFCF_RIO|QFCF_BLUE|QFCF_SFB)) != QFCF_RED &&
	    (flags & (QFCF_RED|QFCF_RIO|QFCF_BLUE|QFCF_SFB)) != QFCF_RIO &&
	    (flags & (QFCF_RED|QFCF_RIO|QFCF_BLUE|QFCF_SFB)) != QFCF_BLUE &&
	    (flags & (QFCF_RED|QFCF_RIO|QFCF_BLUE|QFCF_SFB)) != QFCF_SFB) {
		log(LOG_ERR, "%s: %s more than one RED|RIO|BLUE|SFB\n",
		    if_name(QFQIF_IFP(qif)), qfq_style(qif));
		return (NULL);
	}

	ifq = qif->qif_ifq;
	ifp = QFQIF_IFP(qif);

	cl = zalloc(qfq_cl_zone);
	if (cl == NULL)
		return (NULL);

	bzero(cl, qfq_cl_size);

	if (qlimit == 0 || qlimit > IFCQ_MAXLEN(ifq)) {
		qlimit = IFCQ_MAXLEN(ifq);
		if (qlimit == 0)
			qlimit = DEFAULT_QLIMIT;  /* use default */
	}
	_qinit(&cl->cl_q, Q_DROPTAIL, qlimit);
	cl->cl_qif = qif;
	cl->cl_flags = flags;
	cl->cl_handle = qid;

	/*
	 * Find a free slot in the class table.  If the slot matching
	 * the lower bits of qid is free, use this slot.  Otherwise,
	 * use the first free slot.
	 */
	i = qid % qif->qif_maxclasses;
	if (qif->qif_class_tbl[i] == NULL) {
		qif->qif_class_tbl[i] = cl;
	} else {
		for (i = 0; i < qif->qif_maxclasses; i++) {
			if (qif->qif_class_tbl[i] == NULL) {
				qif->qif_class_tbl[i] = cl;
				break;
			}
		}
		if (i == qif->qif_maxclasses) {
			zfree(qfq_cl_zone, cl);
			return (NULL);
		}
	}

	w = weight;
	VERIFY(w > 0 && w <= QFQ_MAX_WEIGHT);
	cl->cl_lmax = maxsz;
	cl->cl_inv_w = (QFQ_ONE_FP / w);
	w = (QFQ_ONE_FP / cl->cl_inv_w);
	VERIFY(qif->qif_wsum + w <= QFQ_MAX_WSUM);

	i = qfq_calc_index(cl, cl->cl_inv_w, cl->cl_lmax);
	VERIFY(i <= QFQ_MAX_INDEX);
	grp = qif->qif_groups[i];
	if (grp == NULL) {
		grp = _MALLOC(sizeof (*grp), M_DEVBUF, M_WAITOK|M_ZERO);
		if (grp != NULL) {
			grp->qfg_index = i;
			grp->qfg_slot_shift =
			    QFQ_MTU_SHIFT + QFQ_FRAC_BITS - (QFQ_MAX_INDEX - i);
			grp->qfg_slots = _MALLOC(sizeof (struct qfq_class *) *
			    qif->qif_maxslots, M_DEVBUF, M_WAITOK|M_ZERO);
			if (grp->qfg_slots == NULL) {
				log(LOG_ERR, "%s: %s unable to allocate group "
				    "slots for index %d\n", if_name(ifp),
				    qfq_style(qif), i);
			}
		} else {
			log(LOG_ERR, "%s: %s unable to allocate group for "
			    "qid=%d\n", if_name(ifp), qfq_style(qif),
			    cl->cl_handle);
		}
		if (grp == NULL || grp->qfg_slots == NULL) {
			qif->qif_class_tbl[qid % qif->qif_maxclasses] = NULL;
			if (grp != NULL)
				_FREE(grp, M_DEVBUF);
			zfree(qfq_cl_zone, cl);
			return (NULL);
		} else {
			qif->qif_groups[i] = grp;
		}
	}
	cl->cl_grp = grp;
	qif->qif_wsum += w;
	/* XXX cl->cl_S = qif->qif_V; ? */
	/* XXX compute qif->qif_i_wsum */

	qif->qif_classes++;

	if (flags & QFCF_DEFAULTCLASS)
		qif->qif_default = cl;

	if (flags & (QFCF_RED|QFCF_RIO|QFCF_BLUE|QFCF_SFB)) {
#if CLASSQ_RED || CLASSQ_RIO
		u_int64_t ifbandwidth = ifnet_output_linkrate(ifp);
		int pkttime;
#endif /* CLASSQ_RED || CLASSQ_RIO */

		cl->cl_qflags = 0;
		if (flags & QFCF_ECN) {
			if (flags & QFCF_BLUE)
				cl->cl_qflags |= BLUEF_ECN;
			else if (flags & QFCF_SFB)
				cl->cl_qflags |= SFBF_ECN;
			else if (flags & QFCF_RED)
				cl->cl_qflags |= REDF_ECN;
			else if (flags & QFCF_RIO)
				cl->cl_qflags |= RIOF_ECN;
		}
		if (flags & QFCF_FLOWCTL) {
			if (flags & QFCF_SFB)
				cl->cl_qflags |= SFBF_FLOWCTL;
		}
		if (flags & QFCF_DELAYBASED) {
			if (flags & QFCF_SFB)
				cl->cl_qflags |= SFBF_DELAYBASED;
		}
		if (flags & QFCF_CLEARDSCP) {
			if (flags & QFCF_RIO)
				cl->cl_qflags |= RIOF_CLEARDSCP;
		}
#if CLASSQ_RED || CLASSQ_RIO
		/*
		 * XXX: RED & RIO should be watching link speed and MTU
		 *	events and recompute pkttime accordingly.
		 */
		if (ifbandwidth < 8)
			pkttime = 1000 * 1000 * 1000; /* 1 sec */
		else
			pkttime = (int64_t)ifp->if_mtu * 1000 * 1000 * 1000 /
			    (ifbandwidth / 8);

		/* Test for exclusivity {RED,RIO,BLUE,SFB} was done above */
#if CLASSQ_RED
		if (flags & QFCF_RED) {
			cl->cl_red = red_alloc(ifp, 0, 0,
			    qlimit(&cl->cl_q) * 10/100,
			    qlimit(&cl->cl_q) * 30/100,
			    cl->cl_qflags, pkttime);
			if (cl->cl_red != NULL)
				qtype(&cl->cl_q) = Q_RED;
		}
#endif /* CLASSQ_RED */
#if CLASSQ_RIO
		if (flags & QFCF_RIO) {
			cl->cl_rio =
			    rio_alloc(ifp, 0, NULL, cl->cl_qflags, pkttime);
			if (cl->cl_rio != NULL)
				qtype(&cl->cl_q) = Q_RIO;
		}
#endif /* CLASSQ_RIO */
#endif /* CLASSQ_RED || CLASSQ_RIO */
#if CLASSQ_BLUE
		if (flags & QFCF_BLUE) {
			cl->cl_blue = blue_alloc(ifp, 0, 0, cl->cl_qflags);
			if (cl->cl_blue != NULL)
				qtype(&cl->cl_q) = Q_BLUE;
		}
#endif /* CLASSQ_BLUE */
		if (flags & QFCF_SFB) {
			if (!(cl->cl_flags & QFCF_LAZY))
				cl->cl_sfb = sfb_alloc(ifp, cl->cl_handle,
				    qlimit(&cl->cl_q), cl->cl_qflags);
			if (cl->cl_sfb != NULL || (cl->cl_flags & QFCF_LAZY))
				qtype(&cl->cl_q) = Q_SFB;
		}
	}

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s created qid=%d grp=%d weight=%d "
		    "qlimit=%d flags=%b\n", if_name(ifp), qfq_style(qif),
		    cl->cl_handle, cl->cl_grp->qfg_index, weight, qlimit,
		    flags, QFCF_BITS);
	}

	return (cl);
}

int
qfq_remove_queue(struct qfq_if *qif, u_int32_t qid)
{
	struct qfq_class *cl;

	IFCQ_LOCK_ASSERT_HELD(qif->qif_ifq);

	if ((cl = qfq_clh_to_clp(qif, qid)) == NULL)
		return (EINVAL);

	return (qfq_class_destroy(qif, cl));
}

static int
qfq_class_destroy(struct qfq_if *qif, struct qfq_class *cl)
{
	struct ifclassq *ifq = qif->qif_ifq;
	int i;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	qfq_purgeq(qif, cl, 0, NULL, NULL);

	if (cl->cl_inv_w != 0) {
		qif->qif_wsum -= (QFQ_ONE_FP / cl->cl_inv_w);
		cl->cl_inv_w = 0;	/* reset weight to avoid run twice */
	}

	for (i = 0; i < qif->qif_maxclasses; i++) {
		if (qif->qif_class_tbl[i] == cl) {
			qif->qif_class_tbl[i] = NULL;
			break;
		}
	}
	qif->qif_classes--;

	if (cl->cl_qalg.ptr != NULL) {
#if CLASSQ_RIO
		if (q_is_rio(&cl->cl_q))
			rio_destroy(cl->cl_rio);
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
		if (q_is_red(&cl->cl_q))
			red_destroy(cl->cl_red);
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
		if (q_is_blue(&cl->cl_q))
			blue_destroy(cl->cl_blue);
#endif /* CLASSQ_BLUE */
		if (q_is_sfb(&cl->cl_q) && cl->cl_sfb != NULL)
			sfb_destroy(cl->cl_sfb);
		cl->cl_qalg.ptr = NULL;
		qtype(&cl->cl_q) = Q_DROPTAIL;
		qstate(&cl->cl_q) = QS_RUNNING;
	}

	if (qif->qif_default == cl)
		qif->qif_default = NULL;

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s destroyed qid=%d\n",
		    if_name(QFQIF_IFP(qif)), qfq_style(qif), cl->cl_handle);
	}

	zfree(qfq_cl_zone, cl);

	return (0);
}

/*
 * Calculate a mask to mimic what would be ffs_from()
 */
static inline pktsched_bitmap_t
mask_from(pktsched_bitmap_t bitmap, int from)
{
	return (bitmap & ~((1UL << from) - 1));
}

/*
 * The state computation relies on ER=0, IR=1, EB=2, IB=3
 * First compute eligibility comparing grp->qfg_S, qif->qif_V,
 * then check if someone is blocking us and possibly add EB
 */
static inline u_int32_t
qfq_calc_state(struct qfq_if *qif, struct qfq_group *grp)
{
	/* if S > V we are not eligible */
	u_int32_t state = qfq_gt(grp->qfg_S, qif->qif_V);
	pktsched_bitmap_t mask = mask_from(qif->qif_bitmaps[ER],
	    grp->qfg_index);
	struct qfq_group *next;

	if (mask) {
		next = qfq_ffs(qif, mask);
		if (qfq_gt(grp->qfg_F, next->qfg_F))
			state |= EB;
	}

	return (state);
}

/*
 * In principle
 *	qif->qif_bitmaps[dst] |= qif->qif_bitmaps[src] & mask;
 *	qif->qif_bitmaps[src] &= ~mask;
 * but we should make sure that src != dst
 */
static inline void
qfq_move_groups(struct qfq_if *qif, pktsched_bitmap_t mask, int src, int dst)
{
	qif->qif_bitmaps[dst] |= qif->qif_bitmaps[src] & mask;
	qif->qif_bitmaps[src] &= ~mask;
}

static inline void
qfq_unblock_groups(struct qfq_if *qif, int index, u_int64_t old_finish)
{
	pktsched_bitmap_t mask = mask_from(qif->qif_bitmaps[ER], index + 1);
	struct qfq_group *next;

	if (mask) {
		next = qfq_ffs(qif, mask);
		if (!qfq_gt(next->qfg_F, old_finish))
			return;
	}

	mask = (1UL << index) - 1;
	qfq_move_groups(qif, mask, EB, ER);
	qfq_move_groups(qif, mask, IB, IR);
}

/*
 * perhaps
 *
 *	old_V ^= qif->qif_V;
 *	old_V >>= QFQ_MIN_SLOT_SHIFT;
 *	if (old_V) {
 *		...
 *	}
 */
static inline void
qfq_make_eligible(struct qfq_if *qif, u_int64_t old_V)
{
	pktsched_bitmap_t mask, vslot, old_vslot;

	vslot = qif->qif_V >> QFQ_MIN_SLOT_SHIFT;
	old_vslot = old_V >> QFQ_MIN_SLOT_SHIFT;

	if (vslot != old_vslot) {
		mask = (2UL << (__fls(vslot ^ old_vslot))) - 1;
		qfq_move_groups(qif, mask, IR, ER);
		qfq_move_groups(qif, mask, IB, EB);
	}
}

/*
 * XXX we should make sure that slot becomes less than 32.
 * This is guaranteed by the input values.
 * roundedS is always cl->qfg_S rounded on grp->qfg_slot_shift bits.
 */
static inline void
qfq_slot_insert(struct qfq_if *qif, struct qfq_group *grp,
    struct qfq_class *cl, u_int64_t roundedS)
{
	u_int64_t slot = (roundedS - grp->qfg_S) >> grp->qfg_slot_shift;
	u_int32_t i = (grp->qfg_front + slot) % qif->qif_maxslots;

	cl->cl_next = grp->qfg_slots[i];
	grp->qfg_slots[i] = cl;
	pktsched_bit_set(slot, &grp->qfg_full_slots);
}

/*
 * remove the entry from the slot
 */
static inline void
qfq_front_slot_remove(struct qfq_group *grp)
{
	struct qfq_class **h = &grp->qfg_slots[grp->qfg_front];

	*h = (*h)->cl_next;
	if (!*h)
		pktsched_bit_clr(0, &grp->qfg_full_slots);
}

/*
 * Returns the first full queue in a group. As a side effect,
 * adjust the bucket list so the first non-empty bucket is at
 * position 0 in qfg_full_slots.
 */
static inline struct qfq_class *
qfq_slot_scan(struct qfq_if *qif, struct qfq_group *grp)
{
	int i;

	if (pktsched_verbose > 2) {
		log(LOG_DEBUG, "%s: %s grp=%d full_slots=0x%x\n",
		    if_name(QFQIF_IFP(qif)), qfq_style(qif), grp->qfg_index,
		    grp->qfg_full_slots);
	}

	if (grp->qfg_full_slots == 0)
		return (NULL);

	i = pktsched_ffs(grp->qfg_full_slots) - 1; /* zero-based */
	if (i > 0) {
		grp->qfg_front = (grp->qfg_front + i) % qif->qif_maxslots;
		grp->qfg_full_slots >>= i;
	}

	return (grp->qfg_slots[grp->qfg_front]);
}

/*
 * adjust the bucket list. When the start time of a group decreases,
 * we move the index down (modulo qif->qif_maxslots) so we don't need to
 * move the objects. The mask of occupied slots must be shifted
 * because we use ffs() to find the first non-empty slot.
 * This covers decreases in the group's start time, but what about
 * increases of the start time ?
 * Here too we should make sure that i is less than 32
 */
static inline void
qfq_slot_rotate(struct qfq_if *qif, struct qfq_group *grp, u_int64_t roundedS)
{
#pragma unused(qif)
	u_int32_t i = (grp->qfg_S - roundedS) >> grp->qfg_slot_shift;

	grp->qfg_full_slots <<= i;
	grp->qfg_front = (grp->qfg_front - i) % qif->qif_maxslots;
}

static inline void
qfq_update_eligible(struct qfq_if *qif, u_int64_t old_V)
{
	pktsched_bitmap_t ineligible;

	ineligible = qif->qif_bitmaps[IR] | qif->qif_bitmaps[IB];
	if (ineligible) {
		if (!qif->qif_bitmaps[ER]) {
			struct qfq_group *grp;
			grp = qfq_ffs(qif, ineligible);
			if (qfq_gt(grp->qfg_S, qif->qif_V))
				qif->qif_V = grp->qfg_S;
		}
		qfq_make_eligible(qif, old_V);
	}
}

/*
 * Updates the class, returns true if also the group needs to be updated.
 */
static inline int
qfq_update_class(struct qfq_if *qif, struct qfq_group *grp,
    struct qfq_class *cl)
{
#pragma unused(qif)
	cl->cl_S = cl->cl_F;
	if (qempty(&cl->cl_q))  {
		qfq_front_slot_remove(grp);
	} else {
		u_int32_t len;
		u_int64_t roundedS;

		len = m_pktlen(qhead(&cl->cl_q));
		cl->cl_F = cl->cl_S + (u_int64_t)len * cl->cl_inv_w;
		roundedS = qfq_round_down(cl->cl_S, grp->qfg_slot_shift);
		if (roundedS == grp->qfg_S)
			return (0);

		qfq_front_slot_remove(grp);
		qfq_slot_insert(qif, grp, cl, roundedS);
	}
	return (1);
}

/*
 * note: CLASSQDQ_POLL returns the next packet without removing the packet
 *	from the queue.  CLASSQDQ_REMOVE is a normal dequeue operation.
 *	CLASSQDQ_REMOVE must return the same packet if called immediately
 *	after CLASSQDQ_POLL.
 */
struct mbuf *
qfq_dequeue(struct qfq_if *qif, cqdq_op_t op)
{
	pktsched_bitmap_t er_bits = qif->qif_bitmaps[ER];
	struct ifclassq *ifq = qif->qif_ifq;
	struct qfq_group *grp;
	struct qfq_class *cl;
	struct mbuf *m;
	u_int64_t old_V;
	u_int32_t len;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	for (;;) {
		if (er_bits == 0) {
#if QFQ_DEBUG
			if (qif->qif_queued && pktsched_verbose > 1)
				qfq_dump_sched(qif, "start dequeue");
#endif /* QFQ_DEBUG */
			/* no eligible and ready packet */
			return (NULL);
		}
		grp = qfq_ffs(qif, er_bits);
		/* if group is non-empty, use it */
		if (grp->qfg_full_slots != 0)
			break;
		pktsched_bit_clr(grp->qfg_index, &er_bits);
#if QFQ_DEBUG
		qif->qif_emptygrp++;
#endif /* QFQ_DEBUG */
	}
	VERIFY(!IFCQ_IS_EMPTY(ifq));

	cl = grp->qfg_slots[grp->qfg_front];
	VERIFY(cl != NULL && !qempty(&cl->cl_q));

	if (op == CLASSQDQ_POLL)
		return (qfq_pollq(cl));

	m = qfq_getq(cl);
	VERIFY(m != NULL);	/* qalg must be work conserving */
	len = m_pktlen(m);

#if QFQ_DEBUG
	qif->qif_queued--;
#endif /* QFQ_DEBUG */

	IFCQ_DEC_LEN(ifq);
	IFCQ_DEC_BYTES(ifq, len);
	if (qempty(&cl->cl_q))
		cl->cl_period++;
	PKTCNTR_ADD(&cl->cl_xmitcnt, 1, len);
	IFCQ_XMIT_ADD(ifq, 1, len);

	old_V = qif->qif_V;
	qif->qif_V += (u_int64_t)len * QFQ_IWSUM;

	if (pktsched_verbose > 2) {
		log(LOG_DEBUG, "%s: %s qid=%d dequeue m=0x%llx F=0x%llx "
		    "V=0x%llx", if_name(QFQIF_IFP(qif)), qfq_style(qif),
		    cl->cl_handle, (uint64_t)VM_KERNEL_ADDRPERM(m), cl->cl_F,
		    qif->qif_V);
	}

	if (qfq_update_class(qif, grp, cl)) {
		u_int64_t old_F = grp->qfg_F;

		cl = qfq_slot_scan(qif, grp);
		if (!cl) { /* group gone, remove from ER */
			pktsched_bit_clr(grp->qfg_index, &qif->qif_bitmaps[ER]);
		} else {
			u_int32_t s;
			u_int64_t roundedS =
			    qfq_round_down(cl->cl_S, grp->qfg_slot_shift);

			if (grp->qfg_S == roundedS)
				goto skip_unblock;

			grp->qfg_S = roundedS;
			grp->qfg_F = roundedS + (2ULL << grp->qfg_slot_shift);

			/* remove from ER and put in the new set */
			pktsched_bit_clr(grp->qfg_index, &qif->qif_bitmaps[ER]);
			s = qfq_calc_state(qif, grp);
			pktsched_bit_set(grp->qfg_index, &qif->qif_bitmaps[s]);
		}
		/* we need to unblock even if the group has gone away */
		qfq_unblock_groups(qif, grp->qfg_index, old_F);
	}

skip_unblock:
	qfq_update_eligible(qif, old_V);

#if QFQ_DEBUG
	if (!qif->qif_bitmaps[ER] && qif->qif_queued && pktsched_verbose > 1)
		qfq_dump_sched(qif, "end dequeue");
#endif /* QFQ_DEBUG */

	return (m);
}

/*
 * Assign a reasonable start time for a new flow k in group i.
 * Admissible values for hat(F) are multiples of sigma_i
 * no greater than V+sigma_i . Larger values mean that
 * we had a wraparound so we consider the timestamp to be stale.
 *
 * If F is not stale and F >= V then we set S = F.
 * Otherwise we should assign S = V, but this may violate
 * the ordering in ER. So, if we have groups in ER, set S to
 * the F_j of the first group j which would be blocking us.
 * We are guaranteed not to move S backward because
 * otherwise our group i would still be blocked.
 */
static inline void
qfq_update_start(struct qfq_if *qif, struct qfq_class *cl)
{
	pktsched_bitmap_t mask;
	u_int64_t limit, roundedF;
	int slot_shift = cl->cl_grp->qfg_slot_shift;

	roundedF = qfq_round_down(cl->cl_F, slot_shift);
	limit = qfq_round_down(qif->qif_V, slot_shift) + (1UL << slot_shift);

	if (!qfq_gt(cl->cl_F, qif->qif_V) || qfq_gt(roundedF, limit)) {
		/* timestamp was stale */
		mask = mask_from(qif->qif_bitmaps[ER], cl->cl_grp->qfg_index);
		if (mask) {
			struct qfq_group *next = qfq_ffs(qif, mask);
			if (qfq_gt(roundedF, next->qfg_F)) {
				cl->cl_S = next->qfg_F;
				return;
			}
		}
		cl->cl_S = qif->qif_V;
	} else { /* timestamp is not stale */
		cl->cl_S = cl->cl_F;
	}
}

int
qfq_enqueue(struct qfq_if *qif, struct qfq_class *cl, struct mbuf *m,
    struct pf_mtag *t)
{
	struct ifclassq *ifq = qif->qif_ifq;
	struct qfq_group *grp;
	u_int64_t roundedS;
	int len, ret, s;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(cl == NULL || cl->cl_qif == qif);

	if (cl == NULL) {
#if PF_ALTQ
		cl = qfq_clh_to_clp(qif, t->pftag_qid);
#else /* !PF_ALTQ */
		cl = qfq_clh_to_clp(qif, 0);
#endif /* !PF_ALTQ */
		if (cl == NULL) {
			cl = qif->qif_default;
			if (cl == NULL) {
				IFCQ_CONVERT_LOCK(ifq);
				m_freem(m);
				return (ENOBUFS);
			}
		}
	}

	len = m_pktlen(m);

	ret = qfq_addq(cl, m, t);
	if (ret != 0) {
		if (ret == CLASSQEQ_SUCCESS_FC) {
			/* packet enqueued, return advisory feedback */
			ret = EQFULL;
		} else {
			VERIFY(ret == CLASSQEQ_DROPPED ||
			    ret == CLASSQEQ_DROPPED_FC ||
			    ret == CLASSQEQ_DROPPED_SP);
			/* packet has been freed in qfq_addq */
			PKTCNTR_ADD(&cl->cl_dropcnt, 1, len);
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
	IFCQ_INC_LEN(ifq);
	IFCQ_INC_BYTES(ifq, len);

#if QFQ_DEBUG
	qif->qif_queued++;
#endif /* QFQ_DEBUG */

	/* queue was not idle, we're done */
	if (qlen(&cl->cl_q) > 1)
		goto done;

	/* queue was idle */
	grp = cl->cl_grp;
	qfq_update_start(qif, cl);	/* adjust start time */

	/* compute new finish time and rounded start */
	cl->cl_F = cl->cl_S + (u_int64_t)len * cl->cl_inv_w;
	roundedS = qfq_round_down(cl->cl_S, grp->qfg_slot_shift);

	/*
	 * Insert cl in the correct bucket.
	 *
	 * If cl->cl_S >= grp->qfg_S we don't need to adjust the bucket list
	 * and simply go to the insertion phase.  Otherwise grp->qfg_S is
	 * decreasing, we must make room in the bucket list, and also
	 * recompute the group state.  Finally, if there were no flows
	 * in this group and nobody was in ER make sure to adjust V.
	 */
	if (grp->qfg_full_slots != 0) {
		if (!qfq_gt(grp->qfg_S, cl->cl_S))
			goto skip_update;

		/* create a slot for this cl->cl_S */
		qfq_slot_rotate(qif, grp, roundedS);

		/* group was surely ineligible, remove */
		pktsched_bit_clr(grp->qfg_index, &qif->qif_bitmaps[IR]);
		pktsched_bit_clr(grp->qfg_index, &qif->qif_bitmaps[IB]);
	} else if (!qif->qif_bitmaps[ER] && qfq_gt(roundedS, qif->qif_V)) {
		qif->qif_V = roundedS;
	}

	grp->qfg_S = roundedS;
	grp->qfg_F =
	    roundedS + (2ULL << grp->qfg_slot_shift); /* i.e. 2 sigma_i */
	s = qfq_calc_state(qif, grp);
	pktsched_bit_set(grp->qfg_index, &qif->qif_bitmaps[s]);

	if (pktsched_verbose > 2) {
		log(LOG_DEBUG, "%s: %s qid=%d enqueue m=0x%llx state=%s 0x%x "
		    "S=0x%llx F=0x%llx V=0x%llx\n", if_name(QFQIF_IFP(qif)),
		    qfq_style(qif), cl->cl_handle,
		    (uint64_t)VM_KERNEL_ADDRPERM(m), qfq_state2str(s),
		    qif->qif_bitmaps[s], cl->cl_S, cl->cl_F, qif->qif_V);
	}

skip_update:
	qfq_slot_insert(qif, grp, cl, roundedS);

done:
	/* successfully queued. */
	return (ret);
}

static inline void
qfq_slot_remove(struct qfq_if *qif, struct qfq_group *grp,
    struct qfq_class *cl)
{
#pragma unused(qif)
	struct qfq_class **pprev;
	u_int32_t i, offset;
	u_int64_t roundedS;

	roundedS = qfq_round_down(cl->cl_S, grp->qfg_slot_shift);
	offset = (roundedS - grp->qfg_S) >> grp->qfg_slot_shift;
	i = (grp->qfg_front + offset) % qif->qif_maxslots;

	pprev = &grp->qfg_slots[i];
	while (*pprev && *pprev != cl)
		pprev = &(*pprev)->cl_next;

	*pprev = cl->cl_next;
	if (!grp->qfg_slots[i])
		pktsched_bit_clr(offset, &grp->qfg_full_slots);
}

/*
 * Called to forcibly destroy a queue.
 * If the queue is not in the front bucket, or if it has
 * other queues in the front bucket, we can simply remove
 * the queue with no other side effects.
 * Otherwise we must propagate the event up.
 * XXX description to be completed.
 */
static void
qfq_deactivate_class(struct qfq_if *qif, struct qfq_class *cl)
{
	struct qfq_group *grp = cl->cl_grp;
	pktsched_bitmap_t mask;
	u_int64_t roundedS;
	int s;

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s deactivate qid=%d grp=%d "
		    "full_slots=0x%x front=%d bitmaps={ER=0x%x,EB=0x%x,"
		    "IR=0x%x,IB=0x%x}\n",
		    if_name(QFQIF_IFP(cl->cl_qif)), qfq_style(cl->cl_qif),
		    cl->cl_handle, grp->qfg_index, grp->qfg_full_slots,
		    grp->qfg_front, qif->qif_bitmaps[ER], qif->qif_bitmaps[EB],
		    qif->qif_bitmaps[IR], qif->qif_bitmaps[IB]);
#if QFQ_DEBUG
		if (pktsched_verbose > 1)
			qfq_dump_sched(qif, "start deactivate");
#endif /* QFQ_DEBUG */
	}

	cl->cl_F = cl->cl_S;	/* not needed if the class goes away */
	qfq_slot_remove(qif, grp, cl);

	if (grp->qfg_full_slots == 0) {
		/*
		 * Nothing left in the group, remove from all sets.
		 * Do ER last because if we were blocking other groups
		 * we must unblock them.
		 */
		pktsched_bit_clr(grp->qfg_index, &qif->qif_bitmaps[IR]);
		pktsched_bit_clr(grp->qfg_index, &qif->qif_bitmaps[EB]);
		pktsched_bit_clr(grp->qfg_index, &qif->qif_bitmaps[IB]);

		if (pktsched_bit_tst(grp->qfg_index, &qif->qif_bitmaps[ER]) &&
		    !(qif->qif_bitmaps[ER] & ~((1UL << grp->qfg_index) - 1))) {
			mask = qif->qif_bitmaps[ER] &
			    ((1UL << grp->qfg_index) - 1);
			if (mask)
				mask = ~((1UL << __fls(mask)) - 1);
			else
				mask = (pktsched_bitmap_t)~0UL;
			qfq_move_groups(qif, mask, EB, ER);
			qfq_move_groups(qif, mask, IB, IR);
		}
		pktsched_bit_clr(grp->qfg_index, &qif->qif_bitmaps[ER]);
	} else if (!grp->qfg_slots[grp->qfg_front]) {
		cl = qfq_slot_scan(qif, grp);
		roundedS = qfq_round_down(cl->cl_S, grp->qfg_slot_shift);
		if (grp->qfg_S != roundedS) {
			pktsched_bit_clr(grp->qfg_index, &qif->qif_bitmaps[ER]);
			pktsched_bit_clr(grp->qfg_index, &qif->qif_bitmaps[IR]);
			pktsched_bit_clr(grp->qfg_index, &qif->qif_bitmaps[EB]);
			pktsched_bit_clr(grp->qfg_index, &qif->qif_bitmaps[IB]);
			grp->qfg_S = roundedS;
			grp->qfg_F = roundedS + (2ULL << grp->qfg_slot_shift);
			s = qfq_calc_state(qif, grp);
			pktsched_bit_set(grp->qfg_index, &qif->qif_bitmaps[s]);
		}
	}
	qfq_update_eligible(qif, qif->qif_V);

#if QFQ_DEBUG
	if (pktsched_verbose > 1)
		qfq_dump_sched(qif, "end deactivate");
#endif /* QFQ_DEBUG */
}

static const char *
qfq_state2str(int s)
{
	const char *c;

	switch (s) {
	case ER:
		c = "ER";
		break;
	case IR:
		c = "IR";
		break;
	case EB:
		c = "EB";
		break;
	case IB:
		c = "IB";
		break;
	default:
		c = "?";
		break;
	}
	return (c);
}

static inline int
qfq_addq(struct qfq_class *cl, struct mbuf *m, struct pf_mtag *t)
{
	struct qfq_if	*qif = cl->cl_qif;
	struct ifclassq *ifq = qif->qif_ifq;

	IFCQ_LOCK_ASSERT_HELD(ifq);

#if CLASSQ_RIO
	if (q_is_rio(&cl->cl_q))
		return (rio_addq(cl->cl_rio, &cl->cl_q, m, t));
	else
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
	if (q_is_red(&cl->cl_q))
		return (red_addq(cl->cl_red, &cl->cl_q, m, t));
	else
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
	if (q_is_blue(&cl->cl_q))
		return (blue_addq(cl->cl_blue, &cl->cl_q, m, t));
	else
#endif /* CLASSQ_BLUE */
	if (q_is_sfb(&cl->cl_q)) {
		if (cl->cl_sfb == NULL) {
			struct ifnet *ifp = QFQIF_IFP(qif);

			VERIFY(cl->cl_flags & QFCF_LAZY);
			cl->cl_flags &= ~QFCF_LAZY;
			IFCQ_CONVERT_LOCK(ifq);

			cl->cl_sfb = sfb_alloc(ifp, cl->cl_handle,
			    qlimit(&cl->cl_q), cl->cl_qflags);
			if (cl->cl_sfb == NULL) {
				/* fall back to droptail */
				qtype(&cl->cl_q) = Q_DROPTAIL;
				cl->cl_flags &= ~QFCF_SFB;
				cl->cl_qflags &= ~(SFBF_ECN | SFBF_FLOWCTL);

				log(LOG_ERR, "%s: %s SFB lazy allocation "
				    "failed for qid=%d grp=%d, falling back "
				    "to DROPTAIL\n", if_name(ifp),
				    qfq_style(qif), cl->cl_handle,
				    cl->cl_grp->qfg_index);
			} else if (qif->qif_throttle != IFNET_THROTTLE_OFF) {
				/* if there's pending throttling, set it */
				cqrq_throttle_t tr = { 1, qif->qif_throttle };
				int err = qfq_throttle(qif, &tr);

				if (err == EALREADY)
					err = 0;
				if (err != 0) {
					tr.level = IFNET_THROTTLE_OFF;
					(void) qfq_throttle(qif, &tr);
				}
			}
		}
		if (cl->cl_sfb != NULL)
			return (sfb_addq(cl->cl_sfb, &cl->cl_q, m, t));
	} else if (qlen(&cl->cl_q) >= qlimit(&cl->cl_q)) {
		IFCQ_CONVERT_LOCK(ifq);
		m_freem(m);
		return (CLASSQEQ_DROPPED);
	}

#if PF_ECN
	if (cl->cl_flags & QFCF_CLEARDSCP)
		write_dsfield(m, t, 0);
#endif /* PF_ECN */

	_addq(&cl->cl_q, m);

	return (0);
}

static inline struct mbuf *
qfq_getq(struct qfq_class *cl)
{
	IFCQ_LOCK_ASSERT_HELD(cl->cl_qif->qif_ifq);

#if CLASSQ_RIO
	if (q_is_rio(&cl->cl_q))
		return (rio_getq(cl->cl_rio, &cl->cl_q));
	else
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
	if (q_is_red(&cl->cl_q))
		return (red_getq(cl->cl_red, &cl->cl_q));
	else
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
	if (q_is_blue(&cl->cl_q))
		return (blue_getq(cl->cl_blue, &cl->cl_q));
	else
#endif /* CLASSQ_BLUE */
	if (q_is_sfb(&cl->cl_q) && cl->cl_sfb != NULL)
		return (sfb_getq(cl->cl_sfb, &cl->cl_q));

	return (_getq(&cl->cl_q));
}

static inline struct mbuf *
qfq_pollq(struct qfq_class *cl)
{
	IFCQ_LOCK_ASSERT_HELD(cl->cl_qif->qif_ifq);

	return (qhead(&cl->cl_q));
}

static void
qfq_purgeq(struct qfq_if *qif, struct qfq_class *cl, u_int32_t flow,
    u_int32_t *packets, u_int32_t *bytes)
{
	struct ifclassq *ifq = qif->qif_ifq;
	u_int32_t cnt = 0, len = 0, qlen;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if ((qlen = qlen(&cl->cl_q)) == 0)
		goto done;

	/* become regular mutex before freeing mbufs */
	IFCQ_CONVERT_LOCK(ifq);

#if CLASSQ_RIO
	if (q_is_rio(&cl->cl_q))
		rio_purgeq(cl->cl_rio, &cl->cl_q, flow, &cnt, &len);
	else
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
	if (q_is_red(&cl->cl_q))
		red_purgeq(cl->cl_red, &cl->cl_q, flow, &cnt, &len);
	else
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
	if (q_is_blue(&cl->cl_q))
		blue_purgeq(cl->cl_blue, &cl->cl_q, flow, &cnt, &len);
	else
#endif /* CLASSQ_BLUE */
	if (q_is_sfb(&cl->cl_q) && cl->cl_sfb != NULL)
		sfb_purgeq(cl->cl_sfb, &cl->cl_q, flow, &cnt, &len);
	else
		_flushq_flow(&cl->cl_q, flow, &cnt, &len);

	if (cnt > 0) {
		VERIFY(qlen(&cl->cl_q) == (qlen - cnt));
#if QFQ_DEBUG
		VERIFY(qif->qif_queued >= cnt);
		qif->qif_queued -= cnt;
#endif /* QFQ_DEBUG */

		PKTCNTR_ADD(&cl->cl_dropcnt, cnt, len);
		IFCQ_DROP_ADD(ifq, cnt, len);

		VERIFY(((signed)IFCQ_LEN(ifq) - cnt) >= 0);
		IFCQ_LEN(ifq) -= cnt;

		if (qempty(&cl->cl_q))
			qfq_deactivate_class(qif, cl);

		if (pktsched_verbose) {
			log(LOG_DEBUG, "%s: %s purge qid=%d weight=%d "
			    "qlen=[%d,%d] cnt=%d len=%d flow=0x%x\n",
			    if_name(QFQIF_IFP(qif)),
			    qfq_style(qif), cl->cl_handle,
			    (u_int32_t)(QFQ_ONE_FP / cl->cl_inv_w), qlen,
			    qlen(&cl->cl_q), cnt, len, flow);
		}
	}
done:
	if (packets != NULL)
		*packets = cnt;
	if (bytes != NULL)
		*bytes = len;
}

static void
qfq_updateq(struct qfq_if *qif, struct qfq_class *cl, cqev_t ev)
{
	IFCQ_LOCK_ASSERT_HELD(qif->qif_ifq);

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s update qid=%d weight=%d event=%s\n",
		    if_name(QFQIF_IFP(qif)), qfq_style(qif),
		    cl->cl_handle, (u_int32_t)(QFQ_ONE_FP / cl->cl_inv_w),
		    ifclassq_ev2str(ev));
	}

#if CLASSQ_RIO
	if (q_is_rio(&cl->cl_q))
		return (rio_updateq(cl->cl_rio, ev));
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
	if (q_is_red(&cl->cl_q))
		return (red_updateq(cl->cl_red, ev));
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
	if (q_is_blue(&cl->cl_q))
		return (blue_updateq(cl->cl_blue, ev));
#endif /* CLASSQ_BLUE */
	if (q_is_sfb(&cl->cl_q) && cl->cl_sfb != NULL)
		return (sfb_updateq(cl->cl_sfb, ev));
}

int
qfq_get_class_stats(struct qfq_if *qif, u_int32_t qid,
    struct qfq_classstats *sp)
{
	struct qfq_class *cl;

	IFCQ_LOCK_ASSERT_HELD(qif->qif_ifq);

	if ((cl = qfq_clh_to_clp(qif, qid)) == NULL)
		return (EINVAL);

	sp->class_handle = cl->cl_handle;
	sp->index = cl->cl_grp->qfg_index;
	sp->weight = (QFQ_ONE_FP / cl->cl_inv_w);
	sp->lmax = cl->cl_lmax;
	sp->qlength = qlen(&cl->cl_q);
	sp->qlimit = qlimit(&cl->cl_q);
	sp->period = cl->cl_period;
	sp->xmitcnt = cl->cl_xmitcnt;
	sp->dropcnt = cl->cl_dropcnt;

	sp->qtype = qtype(&cl->cl_q);
	sp->qstate = qstate(&cl->cl_q);
#if CLASSQ_RED
	if (q_is_red(&cl->cl_q))
		red_getstats(cl->cl_red, &sp->red[0]);
#endif /* CLASSQ_RED */
#if CLASSQ_RIO
	if (q_is_rio(&cl->cl_q))
		rio_getstats(cl->cl_rio, &sp->red[0]);
#endif /* CLASSQ_RIO */
#if CLASSQ_BLUE
	if (q_is_blue(&cl->cl_q))
		blue_getstats(cl->cl_blue, &sp->blue);
#endif /* CLASSQ_BLUE */
	if (q_is_sfb(&cl->cl_q) && cl->cl_sfb != NULL)
		sfb_getstats(cl->cl_sfb, &sp->sfb);

	return (0);
}

static int
qfq_stat_sc(struct qfq_if *qif, cqrq_stat_sc_t *sr)
{
	struct ifclassq *ifq = qif->qif_ifq;
	struct qfq_class *cl;
	u_int32_t i;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	VERIFY(sr->sc == MBUF_SC_UNSPEC || MBUF_VALID_SC(sr->sc));

	i = MBUF_SCIDX(sr->sc);
	VERIFY(i < IFCQ_SC_MAX);

	cl = ifq->ifcq_disc_slots[i].cl;
	sr->packets = qlen(&cl->cl_q);
	sr->bytes = qsize(&cl->cl_q);

	return (0);
}

/* convert a class handle to the corresponding class pointer */
static inline struct qfq_class *
qfq_clh_to_clp(struct qfq_if *qif, u_int32_t chandle)
{
	struct qfq_class *cl;
	int i;

	IFCQ_LOCK_ASSERT_HELD(qif->qif_ifq);

	/*
	 * First, try optimistically the slot matching the lower bits of
	 * the handle.  If it fails, do the linear table search.
	 */
	i = chandle % qif->qif_maxclasses;
	if ((cl = qif->qif_class_tbl[i]) != NULL && cl->cl_handle == chandle)
		return (cl);
	for (i = 0; i < qif->qif_maxclasses; i++)
		if ((cl = qif->qif_class_tbl[i]) != NULL &&
		    cl->cl_handle == chandle)
			return (cl);

	return (NULL);
}

static const char *
qfq_style(struct qfq_if *qif)
{
	return ((qif->qif_flags & QFQIFF_ALTQ) ? "ALTQ_QFQ" : "QFQ");
}

/*
 * Generic comparison function, handling wraparound
 */
static inline int
qfq_gt(u_int64_t a, u_int64_t b)
{
	return ((int64_t)(a - b) > 0);
}

/*
 * Round a precise timestamp to its slotted value
 */
static inline u_int64_t
qfq_round_down(u_int64_t ts, u_int32_t shift)
{
	return (ts & ~((1ULL << shift) - 1));
}

/*
 * Return the pointer to the group with lowest index in the bitmap
 */
static inline struct qfq_group *
qfq_ffs(struct qfq_if *qif, pktsched_bitmap_t bitmap)
{
	int index = pktsched_ffs(bitmap) - 1;	/* zero-based */
	VERIFY(index >= 0 && index <= QFQ_MAX_INDEX &&
	    qif->qif_groups[index] != NULL);
	return (qif->qif_groups[index]);
}

/*
 * Calculate a flow index, given its weight and maximum packet length.
 * index = log_2(maxlen/weight) but we need to apply the scaling.
 * This is used only once at flow creation.
 */
static int
qfq_calc_index(struct qfq_class *cl, u_int32_t inv_w, u_int32_t maxlen)
{
	u_int64_t slot_size = (u_int64_t)maxlen *inv_w;
	pktsched_bitmap_t size_map;
	int index = 0;

	size_map = (pktsched_bitmap_t)(slot_size >> QFQ_MIN_SLOT_SHIFT);
	if (!size_map)
		goto out;

	index = __fls(size_map) + 1;	/* basically a log_2() */
	index -= !(slot_size - (1ULL << (index + QFQ_MIN_SLOT_SHIFT - 1)));

	if (index < 0)
		index = 0;
out:
	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s qid=%d grp=%d W=%u, L=%u, I=%d\n",
		    if_name(QFQIF_IFP(cl->cl_qif)), qfq_style(cl->cl_qif),
		    cl->cl_handle, index, (u_int32_t)(QFQ_ONE_FP/inv_w),
		    maxlen, index);
	}
	return (index);
}

#if QFQ_DEBUG
static void
qfq_dump_groups(struct qfq_if *qif, u_int32_t mask)
{
	int i, j;

	for (i = 0; i < QFQ_MAX_INDEX + 1; i++) {
		struct qfq_group *g = qif->qif_groups[i];

		if (0 == (mask & (1 << i)))
			continue;
		if (g == NULL)
			continue;

		log(LOG_DEBUG, "%s: %s [%2d] full_slots 0x%x\n",
		    if_name(QFQIF_IFP(qif)), qfq_style(qif), i,
		    g->qfg_full_slots);
		log(LOG_DEBUG, "%s: %s             S 0x%20llx F 0x%llx %c\n",
		    if_name(QFQIF_IFP(qif)), qfq_style(qif),
		    g->qfg_S, g->qfg_F, mask & (1 << i) ? '1' : '0');

		for (j = 0; j < qif->qif_maxslots; j++) {
			if (g->qfg_slots[j]) {
				log(LOG_DEBUG, "%s: %s      bucket %d 0x%llx "
				    "qid %d\n", if_name(QFQIF_IFP(qif)),
				    qfq_style(qif), j,
				    (uint64_t)VM_KERNEL_ADDRPERM(
				    g->qfg_slots[j]),
				    g->qfg_slots[j]->cl_handle);
			}
		}
	}
}

static void
qfq_dump_sched(struct qfq_if *qif, const char *msg)
{
	log(LOG_DEBUG, "%s: %s --- in %s: ---\n",
	    if_name(QFQIF_IFP(qif)), qfq_style(qif), msg);
	log(LOG_DEBUG, "%s: %s emptygrp %d queued %d V 0x%llx\n",
	    if_name(QFQIF_IFP(qif)), qfq_style(qif), qif->qif_emptygrp,
	    qif->qif_queued, qif->qif_V);
	log(LOG_DEBUG, "%s: %s      ER 0x%08x\n",
	    if_name(QFQIF_IFP(qif)), qfq_style(qif), qif->qif_bitmaps[ER]);
	log(LOG_DEBUG, "%s: %s      EB 0x%08x\n",
	    if_name(QFQIF_IFP(qif)), qfq_style(qif), qif->qif_bitmaps[EB]);
	log(LOG_DEBUG, "%s: %s      IR 0x%08x\n",
	    if_name(QFQIF_IFP(qif)), qfq_style(qif), qif->qif_bitmaps[IR]);
	log(LOG_DEBUG, "%s: %s      IB 0x%08x\n",
	    if_name(QFQIF_IFP(qif)), qfq_style(qif), qif->qif_bitmaps[IB]);
	qfq_dump_groups(qif, 0xffffffff);
};
#endif /* QFQ_DEBUG */

/*
 * qfq_enqueue_ifclassq is an enqueue function to be registered to
 * (*ifcq_enqueue) in struct ifclassq.
 */
static int
qfq_enqueue_ifclassq(struct ifclassq *ifq, struct mbuf *m)
{
	u_int32_t i;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (!(m->m_flags & M_PKTHDR)) {
		/* should not happen */
		log(LOG_ERR, "%s: packet does not have pkthdr\n",
		    if_name(ifq->ifcq_ifp));
		IFCQ_CONVERT_LOCK(ifq);
		m_freem(m);
		return (ENOBUFS);
	}

	i = MBUF_SCIDX(mbuf_get_service_class(m));
	VERIFY((u_int32_t)i < IFCQ_SC_MAX);

	return (qfq_enqueue(ifq->ifcq_disc,
	    ifq->ifcq_disc_slots[i].cl, m, m_pftag(m)));
}

/*
 * qfq_dequeue_ifclassq is a dequeue function to be registered to
 * (*ifcq_dequeue) in struct ifclass.
 *
 * note: CLASSQDQ_POLL returns the next packet without removing the packet
 *	from the queue.  CLASSQDQ_REMOVE is a normal dequeue operation.
 *	CLASSQDQ_REMOVE must return the same packet if called immediately
 *	after CLASSQDQ_POLL.
 */
static struct mbuf *
qfq_dequeue_ifclassq(struct ifclassq *ifq, cqdq_op_t op)
{
	return (qfq_dequeue(ifq->ifcq_disc, op));
}

static int
qfq_request_ifclassq(struct ifclassq *ifq, cqrq_t req, void *arg)
{
	struct qfq_if *qif = (struct qfq_if *)ifq->ifcq_disc;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	switch (req) {
	case CLASSQRQ_PURGE:
		qfq_purge(qif);
		break;

	case CLASSQRQ_PURGE_SC:
		qfq_purge_sc(qif, (cqrq_purge_sc_t *)arg);
		break;

	case CLASSQRQ_EVENT:
		qfq_event(qif, (cqev_t)arg);
		break;

	case CLASSQRQ_THROTTLE:
		err = qfq_throttle(qif, (cqrq_throttle_t *)arg);
		break;
	case CLASSQRQ_STAT_SC:
		err = qfq_stat_sc(qif, (cqrq_stat_sc_t *)arg);
		break;
	}
	return (err);
}

int
qfq_setup_ifclassq(struct ifclassq *ifq, u_int32_t flags)
{
	struct ifnet *ifp = ifq->ifcq_ifp;
	struct qfq_class *cl0, *cl1, *cl2, *cl3, *cl4;
	struct qfq_class *cl5, *cl6, *cl7, *cl8, *cl9;
	struct qfq_if *qif;
	u_int32_t maxlen = 0, qflags = 0;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_disc == NULL);
	VERIFY(ifq->ifcq_type == PKTSCHEDT_NONE);

	if (flags & PKTSCHEDF_QALG_RED)
		qflags |= QFCF_RED;
	if (flags & PKTSCHEDF_QALG_RIO)
		qflags |= QFCF_RIO;
	if (flags & PKTSCHEDF_QALG_BLUE)
		qflags |= QFCF_BLUE;
	if (flags & PKTSCHEDF_QALG_SFB)
		qflags |= QFCF_SFB;
	if (flags & PKTSCHEDF_QALG_ECN)
		qflags |= QFCF_ECN;
	if (flags & PKTSCHEDF_QALG_FLOWCTL)
		qflags |= QFCF_FLOWCTL;
	if (flags & PKTSCHEDF_QALG_DELAYBASED)
		qflags |= QFCF_DELAYBASED;

	qif = qfq_alloc(ifp, M_WAITOK, FALSE);
	if (qif == NULL)
		return (ENOMEM);

	if ((maxlen = IFCQ_MAXLEN(ifq)) == 0)
		maxlen = if_sndq_maxlen;

	if ((err = qfq_add_queue(qif, maxlen, 300, 1200,
	    qflags | QFCF_LAZY, SCIDX_BK_SYS, &cl0)) != 0)
		goto cleanup;

	if ((err = qfq_add_queue(qif, maxlen, 600, 1400,
	    qflags | QFCF_LAZY, SCIDX_BK, &cl1)) != 0)
		goto cleanup;

	if ((err = qfq_add_queue(qif, maxlen, 2400, 600,
	    qflags | QFCF_DEFAULTCLASS, SCIDX_BE, &cl2)) != 0)
		goto cleanup;

	if ((err = qfq_add_queue(qif, maxlen, 2700, 600,
	    qflags | QFCF_LAZY, SCIDX_RD, &cl3)) != 0)
		goto cleanup;

	if ((err = qfq_add_queue(qif, maxlen, 3000, 400,
	    qflags | QFCF_LAZY, SCIDX_OAM, &cl4)) != 0)
		goto cleanup;

	if ((err = qfq_add_queue(qif, maxlen, 8000, 1000,
	    qflags | QFCF_LAZY, SCIDX_AV, &cl5)) != 0)
		goto cleanup;

	if ((err = qfq_add_queue(qif, maxlen, 15000, 1200,
	    qflags | QFCF_LAZY, SCIDX_RV, &cl6)) != 0)
		goto cleanup;

	if ((err = qfq_add_queue(qif, maxlen, 20000, 1400,
	    qflags | QFCF_LAZY, SCIDX_VI, &cl7)) != 0)
		goto cleanup;

	if ((err = qfq_add_queue(qif, maxlen, 23000, 200,
	    qflags | QFCF_LAZY, SCIDX_VO, &cl8)) != 0)
		goto cleanup;

	if ((err = qfq_add_queue(qif, maxlen, 25000, 200,
	    qflags, SCIDX_CTL, &cl9)) != 0)
		goto cleanup;

	err = ifclassq_attach(ifq, PKTSCHEDT_QFQ, qif,
	    qfq_enqueue_ifclassq, qfq_dequeue_ifclassq, NULL,
	    qfq_request_ifclassq);

	/* cache these for faster lookup */
	if (err == 0) {
		ifq->ifcq_disc_slots[SCIDX_BK_SYS].qid = SCIDX_BK_SYS;
		ifq->ifcq_disc_slots[SCIDX_BK_SYS].cl = cl0;

		ifq->ifcq_disc_slots[SCIDX_BK].qid = SCIDX_BK;
		ifq->ifcq_disc_slots[SCIDX_BK].cl = cl1;

		ifq->ifcq_disc_slots[SCIDX_BE].qid = SCIDX_BE;
		ifq->ifcq_disc_slots[SCIDX_BE].cl = cl2;

		ifq->ifcq_disc_slots[SCIDX_RD].qid = SCIDX_RD;
		ifq->ifcq_disc_slots[SCIDX_RD].cl = cl3;

		ifq->ifcq_disc_slots[SCIDX_OAM].qid = SCIDX_OAM;
		ifq->ifcq_disc_slots[SCIDX_OAM].cl = cl4;

		ifq->ifcq_disc_slots[SCIDX_AV].qid = SCIDX_AV;
		ifq->ifcq_disc_slots[SCIDX_AV].cl = cl5;

		ifq->ifcq_disc_slots[SCIDX_RV].qid = SCIDX_RV;
		ifq->ifcq_disc_slots[SCIDX_RV].cl = cl6;

		ifq->ifcq_disc_slots[SCIDX_VI].qid = SCIDX_VI;
		ifq->ifcq_disc_slots[SCIDX_VI].cl = cl7;

		ifq->ifcq_disc_slots[SCIDX_VO].qid = SCIDX_VO;
		ifq->ifcq_disc_slots[SCIDX_VO].cl = cl8;

		ifq->ifcq_disc_slots[SCIDX_CTL].qid = SCIDX_CTL;
		ifq->ifcq_disc_slots[SCIDX_CTL].cl = cl9;
	}

cleanup:
	if (err != 0)
		(void) qfq_destroy_locked(qif);

	return (err);
}

int
qfq_teardown_ifclassq(struct ifclassq *ifq)
{
	struct qfq_if *qif = ifq->ifcq_disc;
	int i;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(qif != NULL && ifq->ifcq_type == PKTSCHEDT_QFQ);

	(void) qfq_destroy_locked(qif);

	ifq->ifcq_disc = NULL;
	for (i = 0; i < IFCQ_SC_MAX; i++) {
		ifq->ifcq_disc_slots[i].qid = 0;
		ifq->ifcq_disc_slots[i].cl = NULL;
	}

	return (ifclassq_detach(ifq));
}

int
qfq_getqstats_ifclassq(struct ifclassq *ifq, u_int32_t slot,
    struct if_ifclassq_stats *ifqs)
{
	struct qfq_if *qif = ifq->ifcq_disc;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_type == PKTSCHEDT_QFQ);

	if (slot >= IFCQ_SC_MAX)
		return (EINVAL);

	return (qfq_get_class_stats(qif, ifq->ifcq_disc_slots[slot].qid,
	    &ifqs->ifqs_qfq_stats));
}

static int
qfq_throttle(struct qfq_if *qif, cqrq_throttle_t *tr)
{
	struct ifclassq *ifq = qif->qif_ifq;
	struct qfq_class *cl;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(!(qif->qif_flags & QFQIFF_ALTQ));

	if (!tr->set) {
		tr->level = qif->qif_throttle;
		return (0);
	}

	if (tr->level == qif->qif_throttle)
		return (EALREADY);

	/* Current throttling levels only involve BK_SYS class */
	cl = ifq->ifcq_disc_slots[SCIDX_BK_SYS].cl;

	switch (tr->level) {
	case IFNET_THROTTLE_OFF:
		err = qfq_resumeq(qif, cl);
		break;

	case IFNET_THROTTLE_OPPORTUNISTIC:
		err = qfq_suspendq(qif, cl);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	if (err == 0 || err == ENXIO) {
		if (pktsched_verbose) {
			log(LOG_DEBUG, "%s: %s throttling level %sset %d->%d\n",
			    if_name(QFQIF_IFP(qif)), qfq_style(qif),
			    (err == 0) ? "" : "lazy ", qif->qif_throttle,
			    tr->level);
		}
		qif->qif_throttle = tr->level;
		if (err != 0)
			err = 0;
		else
			qfq_purgeq(qif, cl, 0, NULL, NULL);
	} else {
		log(LOG_ERR, "%s: %s unable to set throttling level "
		    "%d->%d [error=%d]\n", if_name(QFQIF_IFP(qif)),
		    qfq_style(qif), qif->qif_throttle, tr->level, err);
	}

	return (err);
}

static int
qfq_resumeq(struct qfq_if *qif, struct qfq_class *cl)
{
	struct ifclassq *ifq = qif->qif_ifq;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);

#if CLASSQ_RIO
	if (q_is_rio(&cl->cl_q))
		err = rio_suspendq(cl->cl_rio, &cl->cl_q, FALSE);
	else
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
	if (q_is_red(&cl->cl_q))
		err = red_suspendq(cl->cl_red, &cl->cl_q, FALSE);
	else
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
	if (q_is_blue(&cl->cl_q))
		err = blue_suspendq(cl->cl_blue, &cl->cl_q, FALSE);
	else
#endif /* CLASSQ_BLUE */
	if (q_is_sfb(&cl->cl_q) && cl->cl_sfb != NULL)
		err = sfb_suspendq(cl->cl_sfb, &cl->cl_q, FALSE);

	if (err == 0)
		qstate(&cl->cl_q) = QS_RUNNING;

	return (err);
}

static int
qfq_suspendq(struct qfq_if *qif, struct qfq_class *cl)
{
	struct ifclassq *ifq = qif->qif_ifq;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);

#if CLASSQ_RIO
	if (q_is_rio(&cl->cl_q))
		err = rio_suspendq(cl->cl_rio, &cl->cl_q, TRUE);
	else
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
	if (q_is_red(&cl->cl_q))
		err = red_suspendq(cl->cl_red, &cl->cl_q, TRUE);
	else
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
	if (q_is_blue(&cl->cl_q))
		err = blue_suspendq(cl->cl_blue, &cl->cl_q, TRUE);
	else
#endif /* CLASSQ_BLUE */
	if (q_is_sfb(&cl->cl_q)) {
		if (cl->cl_sfb != NULL) {
			err = sfb_suspendq(cl->cl_sfb, &cl->cl_q, TRUE);
		} else {
			VERIFY(cl->cl_flags & QFCF_LAZY);
			err = ENXIO;	/* delayed throttling */
		}
	}

	if (err == 0 || err == ENXIO)
		qstate(&cl->cl_q) = QS_SUSPENDED;

	return (err);
}
