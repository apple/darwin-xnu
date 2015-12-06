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
 * traffic class queue
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

#include <net/pktsched/pktsched_tcq.h>
#include <netinet/in.h>

/*
 * function prototypes
 */
static int tcq_enqueue_ifclassq(struct ifclassq *, struct mbuf *);
static struct mbuf *tcq_dequeue_tc_ifclassq(struct ifclassq *,
    mbuf_svc_class_t, cqdq_op_t);
static int tcq_request_ifclassq(struct ifclassq *, cqrq_t, void *);
static int tcq_clear_interface(struct tcq_if *);
static struct tcq_class *tcq_class_create(struct tcq_if *, int, u_int32_t,
    int, u_int32_t);
static int tcq_class_destroy(struct tcq_if *, struct tcq_class *);
static int tcq_destroy_locked(struct tcq_if *);
static inline int tcq_addq(struct tcq_class *, struct mbuf *,
    struct pf_mtag *);
static inline struct mbuf *tcq_getq(struct tcq_class *);
static inline struct mbuf *tcq_pollq(struct tcq_class *);
static void tcq_purgeq(struct tcq_if *, struct tcq_class *, u_int32_t,
    u_int32_t *, u_int32_t *);
static void tcq_purge_sc(struct tcq_if *, cqrq_purge_sc_t *);
static void tcq_updateq(struct tcq_if *, struct tcq_class *, cqev_t);
static int tcq_throttle(struct tcq_if *, cqrq_throttle_t *);
static int tcq_resumeq(struct tcq_if *, struct tcq_class *);
static int tcq_suspendq(struct tcq_if *, struct tcq_class *);
static int tcq_stat_sc(struct tcq_if *, cqrq_stat_sc_t *);
static struct mbuf *tcq_dequeue_cl(struct tcq_if *, struct tcq_class *,
    mbuf_svc_class_t, cqdq_op_t);
static inline struct tcq_class *tcq_clh_to_clp(struct tcq_if *, u_int32_t);
static const char *tcq_style(struct tcq_if *);

#define	TCQ_ZONE_MAX	32		/* maximum elements in zone */
#define	TCQ_ZONE_NAME	"pktsched_tcq"	/* zone name */

static unsigned int tcq_size;		/* size of zone element */
static struct zone *tcq_zone;		/* zone for tcq */

#define	TCQ_CL_ZONE_MAX	32		/* maximum elements in zone */
#define	TCQ_CL_ZONE_NAME "pktsched_tcq_cl" /* zone name */

static unsigned int tcq_cl_size;	/* size of zone element */
static struct zone *tcq_cl_zone;	/* zone for tcq_class */

void
tcq_init(void)
{
	tcq_size = sizeof (struct tcq_if);
	tcq_zone = zinit(tcq_size, TCQ_ZONE_MAX * tcq_size,
	    0, TCQ_ZONE_NAME);
	if (tcq_zone == NULL) {
		panic("%s: failed allocating %s", __func__, TCQ_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(tcq_zone, Z_EXPAND, TRUE);
	zone_change(tcq_zone, Z_CALLERACCT, TRUE);

	tcq_cl_size = sizeof (struct tcq_class);
	tcq_cl_zone = zinit(tcq_cl_size, TCQ_CL_ZONE_MAX * tcq_cl_size,
	    0, TCQ_CL_ZONE_NAME);
	if (tcq_cl_zone == NULL) {
		panic("%s: failed allocating %s", __func__, TCQ_CL_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(tcq_cl_zone, Z_EXPAND, TRUE);
	zone_change(tcq_cl_zone, Z_CALLERACCT, TRUE);
}

struct tcq_if *
tcq_alloc(struct ifnet *ifp, int how, boolean_t altq)
{
	struct tcq_if	*tif;

	tif = (how == M_WAITOK) ? zalloc(tcq_zone) : zalloc_noblock(tcq_zone);
	if (tif == NULL)
		return (NULL);

	bzero(tif, tcq_size);
	tif->tif_maxpri = -1;
	tif->tif_ifq = &ifp->if_snd;
	if (altq)
		tif->tif_flags |= TCQIFF_ALTQ;

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s scheduler allocated\n",
		    if_name(ifp), tcq_style(tif));
	}

	return (tif);
}

int
tcq_destroy(struct tcq_if *tif)
{
	struct ifclassq *ifq = tif->tif_ifq;
	int err;

	IFCQ_LOCK(ifq);
	err = tcq_destroy_locked(tif);
	IFCQ_UNLOCK(ifq);

	return (err);
}

static int
tcq_destroy_locked(struct tcq_if *tif)
{
	IFCQ_LOCK_ASSERT_HELD(tif->tif_ifq);

	(void) tcq_clear_interface(tif);

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s scheduler destroyed\n",
		    if_name(TCQIF_IFP(tif)), tcq_style(tif));
	}

	zfree(tcq_zone, tif);

	return (0);
}

/*
 * bring the interface back to the initial state by discarding
 * all the filters and classes.
 */
static int
tcq_clear_interface(struct tcq_if *tif)
{
	struct tcq_class	*cl;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(tif->tif_ifq);

	/* clear out the classes */
	for (pri = 0; pri <= tif->tif_maxpri; pri++)
		if ((cl = tif->tif_classes[pri]) != NULL)
			tcq_class_destroy(tif, cl);

	return (0);
}

/* discard all the queued packets on the interface */
void
tcq_purge(struct tcq_if *tif)
{
	struct tcq_class *cl;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(tif->tif_ifq);

	for (pri = 0; pri <= tif->tif_maxpri; pri++) {
		if ((cl = tif->tif_classes[pri]) != NULL && !qempty(&cl->cl_q))
			tcq_purgeq(tif, cl, 0, NULL, NULL);
	}
#if !PF_ALTQ
	/*
	 * This assertion is safe to be made only when PF_ALTQ is not
	 * configured; otherwise, IFCQ_LEN represents the sum of the
	 * packets managed by ifcq_disc and altq_disc instances, which
	 * is possible when transitioning between the two.
	 */
	VERIFY(IFCQ_LEN(tif->tif_ifq) == 0);
#endif /* !PF_ALTQ */
}

static void
tcq_purge_sc(struct tcq_if *tif, cqrq_purge_sc_t *pr)
{
	struct ifclassq *ifq = tif->tif_ifq;
	u_int32_t i;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	VERIFY(pr->sc == MBUF_SC_UNSPEC || MBUF_VALID_SC(pr->sc));
	VERIFY(pr->flow != 0);

	if (pr->sc != MBUF_SC_UNSPEC) {
		i = MBUF_SCIDX(pr->sc);
		VERIFY(i < IFCQ_SC_MAX);

		tcq_purgeq(tif, ifq->ifcq_disc_slots[i].cl,
		    pr->flow, &pr->packets, &pr->bytes);
	} else {
		u_int32_t cnt, len;

		pr->packets = 0;
		pr->bytes = 0;

		for (i = 0; i < IFCQ_SC_MAX; i++) {
			tcq_purgeq(tif, ifq->ifcq_disc_slots[i].cl,
			    pr->flow, &cnt, &len);
			pr->packets += cnt;
			pr->bytes += len;
		}
	}
}

void
tcq_event(struct tcq_if *tif, cqev_t ev)
{
	struct tcq_class *cl;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(tif->tif_ifq);

	for (pri = 0; pri <= tif->tif_maxpri; pri++)
		if ((cl = tif->tif_classes[pri]) != NULL)
			tcq_updateq(tif, cl, ev);
}

int
tcq_add_queue(struct tcq_if *tif, int priority, u_int32_t qlimit,
    int flags, u_int32_t qid, struct tcq_class **clp)
{
	struct tcq_class *cl;

	IFCQ_LOCK_ASSERT_HELD(tif->tif_ifq);

	/* check parameters */
	if (priority >= TCQ_MAXPRI)
		return (EINVAL);
	if (tif->tif_classes[priority] != NULL)
		return (EBUSY);
	if (tcq_clh_to_clp(tif, qid) != NULL)
		return (EBUSY);

	cl = tcq_class_create(tif, priority, qlimit, flags, qid);
	if (cl == NULL)
		return (ENOMEM);

	if (clp != NULL)
		*clp = cl;

	return (0);
}

static struct tcq_class *
tcq_class_create(struct tcq_if *tif, int pri, u_int32_t qlimit,
    int flags, u_int32_t qid)
{
	struct ifnet *ifp;
	struct ifclassq *ifq;
	struct tcq_class *cl;

	IFCQ_LOCK_ASSERT_HELD(tif->tif_ifq);

	/* Sanitize flags unless internally configured */
	if (tif->tif_flags & TCQIFF_ALTQ)
		flags &= TQCF_USERFLAGS;

#if !CLASSQ_RED
	if (flags & TQCF_RED) {
		log(LOG_ERR, "%s: %s RED not available!\n",
		    if_name(TCQIF_IFP(tif)), tcq_style(tif));
		return (NULL);
	}
#endif /* !CLASSQ_RED */

#if !CLASSQ_RIO
	if (flags & TQCF_RIO) {
		log(LOG_ERR, "%s: %s RIO not available!\n",
		    if_name(TCQIF_IFP(tif)), tcq_style(tif));
		return (NULL);
	}
#endif /* CLASSQ_RIO */

#if !CLASSQ_BLUE
	if (flags & TQCF_BLUE) {
		log(LOG_ERR, "%s: %s BLUE not available!\n",
		    if_name(TCQIF_IFP(tif)), tcq_style(tif));
		return (NULL);
	}
#endif /* CLASSQ_BLUE */

	/* These are mutually exclusive */
	if ((flags & (TQCF_RED|TQCF_RIO|TQCF_BLUE|TQCF_SFB)) &&
	    (flags & (TQCF_RED|TQCF_RIO|TQCF_BLUE|TQCF_SFB)) != TQCF_RED &&
	    (flags & (TQCF_RED|TQCF_RIO|TQCF_BLUE|TQCF_SFB)) != TQCF_RIO &&
	    (flags & (TQCF_RED|TQCF_RIO|TQCF_BLUE|TQCF_SFB)) != TQCF_BLUE &&
	    (flags & (TQCF_RED|TQCF_RIO|TQCF_BLUE|TQCF_SFB)) != TQCF_SFB) {
		log(LOG_ERR, "%s: %s more than one RED|RIO|BLUE|SFB\n",
		    if_name(TCQIF_IFP(tif)), tcq_style(tif));
		return (NULL);
	}

	ifq = tif->tif_ifq;
	ifp = TCQIF_IFP(tif);

	if ((cl = tif->tif_classes[pri]) != NULL) {
		/* modify the class instead of creating a new one */
		if (!qempty(&cl->cl_q))
			tcq_purgeq(tif, cl, 0, NULL, NULL);
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
	} else {
		cl = zalloc(tcq_cl_zone);
		if (cl == NULL)
			return (NULL);

		bzero(cl, tcq_cl_size);
	}

	tif->tif_classes[pri] = cl;
	if (flags & TQCF_DEFAULTCLASS)
		tif->tif_default = cl;
	if (qlimit == 0 || qlimit > IFCQ_MAXLEN(ifq)) {
		qlimit = IFCQ_MAXLEN(ifq);
		if (qlimit == 0)
			qlimit = DEFAULT_QLIMIT;  /* use default */
	}
	_qinit(&cl->cl_q, Q_DROPTAIL, qlimit);
	cl->cl_flags = flags;
	cl->cl_pri = pri;
	if (pri > tif->tif_maxpri)
		tif->tif_maxpri = pri;
	cl->cl_tif = tif;
	cl->cl_handle = qid;

	if (flags & (TQCF_RED|TQCF_RIO|TQCF_BLUE|TQCF_SFB)) {
#if CLASSQ_RED || CLASSQ_RIO
		u_int64_t ifbandwidth = ifnet_output_linkrate(ifp);
		int pkttime;
#endif /* CLASSQ_RED || CLASSQ_RIO */

		cl->cl_qflags = 0;
		if (flags & TQCF_ECN) {
			if (flags & TQCF_BLUE)
				cl->cl_qflags |= BLUEF_ECN;
			else if (flags & TQCF_SFB)
				cl->cl_qflags |= SFBF_ECN;
			else if (flags & TQCF_RED)
				cl->cl_qflags |= REDF_ECN;
			else if (flags & TQCF_RIO)
				cl->cl_qflags |= RIOF_ECN;
		}
		if (flags & TQCF_FLOWCTL) {
			if (flags & TQCF_SFB)
				cl->cl_qflags |= SFBF_FLOWCTL;
		}
		if (flags & TQCF_DELAYBASED) {
			if (flags & TQCF_SFB)
				cl->cl_qflags |= SFBF_DELAYBASED;
		}
		if (flags & TQCF_CLEARDSCP) {
			if (flags & TQCF_RIO)
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
		if (flags & TQCF_RED) {
			cl->cl_red = red_alloc(ifp, 0, 0,
			    qlimit(&cl->cl_q) * 10/100,
			    qlimit(&cl->cl_q) * 30/100,
			    cl->cl_qflags, pkttime);
			if (cl->cl_red != NULL)
				qtype(&cl->cl_q) = Q_RED;
		}
#endif /* CLASSQ_RED */
#if CLASSQ_RIO
		if (flags & TQCF_RIO) {
			cl->cl_rio =
			    rio_alloc(ifp, 0, NULL, cl->cl_qflags, pkttime);
			if (cl->cl_rio != NULL)
				qtype(&cl->cl_q) = Q_RIO;
		}
#endif /* CLASSQ_RIO */
#endif /* CLASSQ_RED || CLASSQ_RIO */
#if CLASSQ_BLUE
		if (flags & TQCF_BLUE) {
			cl->cl_blue = blue_alloc(ifp, 0, 0, cl->cl_qflags);
			if (cl->cl_blue != NULL)
				qtype(&cl->cl_q) = Q_BLUE;
		}
#endif /* CLASSQ_BLUE */
		if (flags & TQCF_SFB) {
			if (!(cl->cl_flags & TQCF_LAZY))
				cl->cl_sfb = sfb_alloc(ifp, cl->cl_handle,
				    qlimit(&cl->cl_q), cl->cl_qflags);
			if (cl->cl_sfb != NULL || (cl->cl_flags & TQCF_LAZY))
				qtype(&cl->cl_q) = Q_SFB;
		}
	}

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s created qid=%d pri=%d qlimit=%d "
		    "flags=%b\n", if_name(ifp), tcq_style(tif),
		    cl->cl_handle, cl->cl_pri, qlimit, flags, TQCF_BITS);
	}

	return (cl);
}

int
tcq_remove_queue(struct tcq_if *tif, u_int32_t qid)
{
	struct tcq_class *cl;

	IFCQ_LOCK_ASSERT_HELD(tif->tif_ifq);

	if ((cl = tcq_clh_to_clp(tif, qid)) == NULL)
		return (EINVAL);

	return (tcq_class_destroy(tif, cl));
}

static int
tcq_class_destroy(struct tcq_if *tif, struct tcq_class *cl)
{
	struct ifclassq *ifq = tif->tif_ifq;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (!qempty(&cl->cl_q))
		tcq_purgeq(tif, cl, 0, NULL, NULL);

	tif->tif_classes[cl->cl_pri] = NULL;
	if (tif->tif_maxpri == cl->cl_pri) {
		for (pri = cl->cl_pri; pri >= 0; pri--)
			if (tif->tif_classes[pri] != NULL) {
				tif->tif_maxpri = pri;
				break;
			}
		if (pri < 0)
			tif->tif_maxpri = -1;
	}

	if (tif->tif_default == cl)
		tif->tif_default = NULL;

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

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s destroyed qid=%d pri=%d\n",
		    if_name(TCQIF_IFP(tif)), tcq_style(tif),
		    cl->cl_handle, cl->cl_pri);
	}

	zfree(tcq_cl_zone, cl);
	return (0);
}

int
tcq_enqueue(struct tcq_if *tif, struct tcq_class *cl, struct mbuf *m,
    struct pf_mtag *t)
{
	struct ifclassq *ifq = tif->tif_ifq;
	int len, ret;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(cl == NULL || cl->cl_tif == tif);

	if (cl == NULL) {
#if PF_ALTQ
		cl = tcq_clh_to_clp(tif, t->pftag_qid);
#else /* !PF_ALTQ */
		cl = tcq_clh_to_clp(tif, 0);
#endif /* !PF_ALTQ */
		if (cl == NULL) {
			cl = tif->tif_default;
			if (cl == NULL) {
				IFCQ_CONVERT_LOCK(ifq);
				m_freem(m);
				return (ENOBUFS);
			}
		}
	}

	len = m_pktlen(m);

	ret = tcq_addq(cl, m, t);
	if (ret != 0) {
		if (ret == CLASSQEQ_SUCCESS_FC) {
			/* packet enqueued, return advisory feedback */
			ret = EQFULL;
		} else {
			VERIFY(ret == CLASSQEQ_DROPPED ||
			    ret == CLASSQEQ_DROPPED_FC ||
			    ret == CLASSQEQ_DROPPED_SP);
			/* packet has been freed in tcq_addq */
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

	/* successfully queued. */
	return (ret);
}

/*
 * note: CLASSQDQ_POLL returns the next packet without removing the packet
 *	from the queue.  CLASSQDQ_REMOVE is a normal dequeue operation.
 *	CLASSQDQ_REMOVE must return the same packet if called immediately
 *	after CLASSQDQ_POLL.
 */
struct mbuf *
tcq_dequeue_tc(struct tcq_if *tif, mbuf_svc_class_t sc, cqdq_op_t op)
{
	return (tcq_dequeue_cl(tif, NULL, sc, op));
}

static struct mbuf *
tcq_dequeue_cl(struct tcq_if *tif, struct tcq_class *cl,
    mbuf_svc_class_t sc, cqdq_op_t op)
{
	struct ifclassq *ifq = tif->tif_ifq;
	struct mbuf *m;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (cl == NULL) {
		cl = tcq_clh_to_clp(tif, MBUF_SCIDX(sc));
		if (cl == NULL)
			return (NULL);
	}

	if (qempty(&cl->cl_q))
		return (NULL);

	VERIFY(!IFCQ_IS_EMPTY(ifq));

	if (op == CLASSQDQ_POLL)
		return (tcq_pollq(cl));

	m = tcq_getq(cl);
	if (m != NULL) {
		IFCQ_DEC_LEN(ifq);
		IFCQ_DEC_BYTES(ifq, m_pktlen(m));
		if (qempty(&cl->cl_q))
			cl->cl_period++;
		PKTCNTR_ADD(&cl->cl_xmitcnt, 1, m_pktlen(m));
		IFCQ_XMIT_ADD(ifq, 1, m_pktlen(m));
	}
	return (m);
}

static inline int
tcq_addq(struct tcq_class *cl, struct mbuf *m, struct pf_mtag *t)
{
	struct tcq_if *tif = cl->cl_tif;
	struct ifclassq *ifq = tif->tif_ifq;

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
			struct ifnet *ifp = TCQIF_IFP(tif);

			VERIFY(cl->cl_flags & TQCF_LAZY);
			cl->cl_flags &= ~TQCF_LAZY;
			IFCQ_CONVERT_LOCK(ifq);

			cl->cl_sfb = sfb_alloc(ifp, cl->cl_handle,
			    qlimit(&cl->cl_q), cl->cl_qflags);
			if (cl->cl_sfb == NULL) {
				/* fall back to droptail */
				qtype(&cl->cl_q) = Q_DROPTAIL;
				cl->cl_flags &= ~TQCF_SFB;
				cl->cl_qflags &= ~(SFBF_ECN | SFBF_FLOWCTL);

				log(LOG_ERR, "%s: %s SFB lazy allocation "
				    "failed for qid=%d pri=%d, falling back "
				    "to DROPTAIL\n", if_name(ifp),
				    tcq_style(tif), cl->cl_handle,
				    cl->cl_pri);
			} else if (tif->tif_throttle != IFNET_THROTTLE_OFF) {
				/* if there's pending throttling, set it */
				cqrq_throttle_t tr = { 1, tif->tif_throttle };
				int err = tcq_throttle(tif, &tr);

				if (err == EALREADY)
					err = 0;
				if (err != 0) {
					tr.level = IFNET_THROTTLE_OFF;
					(void) tcq_throttle(tif, &tr);
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
	if (cl->cl_flags & TQCF_CLEARDSCP)
		write_dsfield(m, t, 0);
#endif /* PF_ECN */

	_addq(&cl->cl_q, m);

	return (0);
}

static inline struct mbuf *
tcq_getq(struct tcq_class *cl)
{
	IFCQ_LOCK_ASSERT_HELD(cl->cl_tif->tif_ifq);

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
tcq_pollq(struct tcq_class *cl)
{
	IFCQ_LOCK_ASSERT_HELD(cl->cl_tif->tif_ifq);

	return (qhead(&cl->cl_q));
}

static void
tcq_purgeq(struct tcq_if *tif, struct tcq_class *cl, u_int32_t flow,
    u_int32_t *packets, u_int32_t *bytes)
{
	struct ifclassq *ifq = tif->tif_ifq;
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

		PKTCNTR_ADD(&cl->cl_dropcnt, cnt, len);
		IFCQ_DROP_ADD(ifq, cnt, len);

		VERIFY(((signed)IFCQ_LEN(ifq) - cnt) >= 0);
		IFCQ_LEN(ifq) -= cnt;

		if (pktsched_verbose) {
			log(LOG_DEBUG, "%s: %s purge qid=%d pri=%d "
			    "qlen=[%d,%d] cnt=%d len=%d flow=0x%x\n",
			    if_name(TCQIF_IFP(tif)), tcq_style(tif),
			    cl->cl_handle, cl->cl_pri, qlen, qlen(&cl->cl_q),
			    cnt, len, flow);
		}
	}
done:
	if (packets != NULL)
		*packets = cnt;
	if (bytes != NULL)
		*bytes = len;
}

static void
tcq_updateq(struct tcq_if *tif, struct tcq_class *cl, cqev_t ev)
{
	IFCQ_LOCK_ASSERT_HELD(tif->tif_ifq);

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s update qid=%d pri=%d event=%s\n",
		    if_name(TCQIF_IFP(tif)), tcq_style(tif),
		    cl->cl_handle, cl->cl_pri, ifclassq_ev2str(ev));
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
tcq_get_class_stats(struct tcq_if *tif, u_int32_t qid,
    struct tcq_classstats *sp)
{
	struct tcq_class *cl;

	IFCQ_LOCK_ASSERT_HELD(tif->tif_ifq);

	if ((cl = tcq_clh_to_clp(tif, qid)) == NULL)
		return (EINVAL);

	sp->class_handle = cl->cl_handle;
	sp->priority = cl->cl_pri;
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
tcq_stat_sc(struct tcq_if *tif, cqrq_stat_sc_t *sr)
{
	struct ifclassq *ifq = tif->tif_ifq;
	struct tcq_class *cl;
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
static inline struct tcq_class *
tcq_clh_to_clp(struct tcq_if *tif, u_int32_t chandle)
{
	struct tcq_class *cl;
	int idx;

	IFCQ_LOCK_ASSERT_HELD(tif->tif_ifq);

	for (idx = tif->tif_maxpri; idx >= 0; idx--)
		if ((cl = tif->tif_classes[idx]) != NULL &&
		    cl->cl_handle == chandle)
			return (cl);

	return (NULL);
}

static const char *
tcq_style(struct tcq_if *tif)
{
	return ((tif->tif_flags & TCQIFF_ALTQ) ? "ALTQ_TCQ" : "TCQ");
}

/*
 * tcq_enqueue_ifclassq is an enqueue function to be registered to
 * (*ifcq_enqueue) in struct ifclassq.
 */
static int
tcq_enqueue_ifclassq(struct ifclassq *ifq, struct mbuf *m)
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

	return (tcq_enqueue(ifq->ifcq_disc,
	    ifq->ifcq_disc_slots[i].cl, m, m_pftag(m)));
}

/*
 * tcq_dequeue_tc_ifclassq is a dequeue function to be registered to
 * (*ifcq_dequeue) in struct ifclass.
 *
 * note: CLASSQDQ_POLL returns the next packet without removing the packet
 *	from the queue.  CLASSQDQ_REMOVE is a normal dequeue operation.
 *	CLASSQDQ_REMOVE must return the same packet if called immediately
 *	after CLASSQDQ_POLL.
 */
static struct mbuf *
tcq_dequeue_tc_ifclassq(struct ifclassq *ifq, mbuf_svc_class_t sc,
    cqdq_op_t op)
{
	u_int32_t i = MBUF_SCIDX(sc);

	VERIFY((u_int32_t)i < IFCQ_SC_MAX);

	return (tcq_dequeue_cl(ifq->ifcq_disc,
	    ifq->ifcq_disc_slots[i].cl, sc, op));
}

static int
tcq_request_ifclassq(struct ifclassq *ifq, cqrq_t req, void *arg)
{
	struct tcq_if	*tif = (struct tcq_if *)ifq->ifcq_disc;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	switch (req) {
	case CLASSQRQ_PURGE:
		tcq_purge(tif);
		break;

	case CLASSQRQ_PURGE_SC:
		tcq_purge_sc(tif, (cqrq_purge_sc_t *)arg);
		break;

	case CLASSQRQ_EVENT:
		tcq_event(tif, (cqev_t)arg);
		break;

	case CLASSQRQ_THROTTLE:
		err = tcq_throttle(tif, (cqrq_throttle_t *)arg);
		break;

	case CLASSQRQ_STAT_SC:
		err = tcq_stat_sc(tif, (cqrq_stat_sc_t *)arg);
		break;
	}
	return (err);
}

int
tcq_setup_ifclassq(struct ifclassq *ifq, u_int32_t flags)
{
	struct ifnet *ifp = ifq->ifcq_ifp;
	struct tcq_class *cl0, *cl1, *cl2, *cl3;
	struct tcq_if *tif;
	u_int32_t maxlen = 0, qflags = 0;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_disc == NULL);
	VERIFY(ifq->ifcq_type == PKTSCHEDT_NONE);

	if (flags & PKTSCHEDF_QALG_RED)
		qflags |= TQCF_RED;
	if (flags & PKTSCHEDF_QALG_RIO)
		qflags |= TQCF_RIO;
	if (flags & PKTSCHEDF_QALG_BLUE)
		qflags |= TQCF_BLUE;
	if (flags & PKTSCHEDF_QALG_SFB)
		qflags |= TQCF_SFB;
	if (flags & PKTSCHEDF_QALG_ECN)
		qflags |= TQCF_ECN;
	if (flags & PKTSCHEDF_QALG_FLOWCTL)
		qflags |= TQCF_FLOWCTL;
	if (flags & PKTSCHEDF_QALG_DELAYBASED)
		qflags |= TQCF_DELAYBASED;

	tif = tcq_alloc(ifp, M_WAITOK, FALSE);
	if (tif == NULL)
		return (ENOMEM);

	if ((maxlen = IFCQ_MAXLEN(ifq)) == 0)
		maxlen = if_sndq_maxlen;

	if ((err = tcq_add_queue(tif, 0, maxlen,
	    qflags | PRCF_LAZY, SCIDX_BK, &cl0)) != 0)
		goto cleanup;

	if ((err = tcq_add_queue(tif, 1, maxlen,
	    qflags | TQCF_DEFAULTCLASS, SCIDX_BE, &cl1)) != 0)
		goto cleanup;

	if ((err = tcq_add_queue(tif, 2, maxlen,
	    qflags | PRCF_LAZY, SCIDX_VI, &cl2)) != 0)
		goto cleanup;

	if ((err = tcq_add_queue(tif, 3, maxlen,
	    qflags, SCIDX_VO, &cl3)) != 0)
		goto cleanup;

	err = ifclassq_attach(ifq, PKTSCHEDT_TCQ, tif,
	    tcq_enqueue_ifclassq, NULL, tcq_dequeue_tc_ifclassq,
	    tcq_request_ifclassq);

	/* cache these for faster lookup */
	if (err == 0) {
		/* Map {BK_SYS,BK} to TC_BK */
		ifq->ifcq_disc_slots[SCIDX_BK_SYS].qid = SCIDX_BK;
		ifq->ifcq_disc_slots[SCIDX_BK_SYS].cl = cl0;

		ifq->ifcq_disc_slots[SCIDX_BK].qid = SCIDX_BK;
		ifq->ifcq_disc_slots[SCIDX_BK].cl = cl0;

		/* Map {BE,RD,OAM} to TC_BE */
		ifq->ifcq_disc_slots[SCIDX_BE].qid = SCIDX_BE;
		ifq->ifcq_disc_slots[SCIDX_BE].cl = cl1;

		ifq->ifcq_disc_slots[SCIDX_RD].qid = SCIDX_BE;
		ifq->ifcq_disc_slots[SCIDX_RD].cl = cl1;

		ifq->ifcq_disc_slots[SCIDX_OAM].qid = SCIDX_BE;
		ifq->ifcq_disc_slots[SCIDX_OAM].cl = cl1;

		/* Map {AV,RV,VI} to TC_VI */
		ifq->ifcq_disc_slots[SCIDX_AV].qid = SCIDX_VI;
		ifq->ifcq_disc_slots[SCIDX_AV].cl = cl2;

		ifq->ifcq_disc_slots[SCIDX_RV].qid = SCIDX_VI;
		ifq->ifcq_disc_slots[SCIDX_RV].cl = cl2;

		ifq->ifcq_disc_slots[SCIDX_VI].qid = SCIDX_VI;
		ifq->ifcq_disc_slots[SCIDX_VI].cl = cl2;

		/* Map {VO,CTL} to TC_VO */
		ifq->ifcq_disc_slots[SCIDX_VO].qid = SCIDX_VO;
		ifq->ifcq_disc_slots[SCIDX_VO].cl = cl3;

		ifq->ifcq_disc_slots[SCIDX_CTL].qid = SCIDX_VO;
		ifq->ifcq_disc_slots[SCIDX_CTL].cl = cl3;
	}

cleanup:
	if (err != 0)
		(void) tcq_destroy_locked(tif);

	return (err);
}

int
tcq_teardown_ifclassq(struct ifclassq *ifq)
{
	struct tcq_if *tif = ifq->ifcq_disc;
	int i;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(tif != NULL && ifq->ifcq_type == PKTSCHEDT_TCQ);

	(void) tcq_destroy_locked(tif);

	ifq->ifcq_disc = NULL;
	for (i = 0; i < IFCQ_SC_MAX; i++) {
		ifq->ifcq_disc_slots[i].qid = 0;
		ifq->ifcq_disc_slots[i].cl = NULL;
	}

	return (ifclassq_detach(ifq));
}

int
tcq_getqstats_ifclassq(struct ifclassq *ifq, u_int32_t slot,
    struct if_ifclassq_stats *ifqs)
{
	struct tcq_if *tif = ifq->ifcq_disc;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_type == PKTSCHEDT_TCQ);

	if (slot >= IFCQ_SC_MAX)
		return (EINVAL);

	return (tcq_get_class_stats(tif, ifq->ifcq_disc_slots[slot].qid,
	    &ifqs->ifqs_tcq_stats));
}

static int
tcq_throttle(struct tcq_if *tif, cqrq_throttle_t *tr)
{
	struct ifclassq *ifq = tif->tif_ifq;
	struct tcq_class *cl;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(!(tif->tif_flags & TCQIFF_ALTQ));

	if (!tr->set) {
		tr->level = tif->tif_throttle;
		return (0);
	}

	if (tr->level == tif->tif_throttle)
		return (EALREADY);

	/* Current throttling levels only involve BK_SYS class */
	cl = ifq->ifcq_disc_slots[SCIDX_BK_SYS].cl;

	switch (tr->level) {
	case IFNET_THROTTLE_OFF:
		err = tcq_resumeq(tif, cl);
		break;

	case IFNET_THROTTLE_OPPORTUNISTIC:
		err = tcq_suspendq(tif, cl);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	if (err == 0 || err == ENXIO) {
		if (pktsched_verbose) {
			log(LOG_DEBUG, "%s: %s throttling %slevel set %d->%d\n",
			    if_name(TCQIF_IFP(tif)), tcq_style(tif),
			    (err == 0) ? "" : "lazy ", tif->tif_throttle,
			    tr->level);
		}
		tif->tif_throttle = tr->level;
		if (err != 0)
			err = 0;
		else
			tcq_purgeq(tif, cl, 0, NULL, NULL);
	} else {
		log(LOG_ERR, "%s: %s unable to set throttling level "
		    "%d->%d [error=%d]\n", if_name(TCQIF_IFP(tif)),
		    tcq_style(tif), tif->tif_throttle, tr->level, err);
	}

	return (err);
}

static int
tcq_resumeq(struct tcq_if *tif, struct tcq_class *cl)
{
	struct ifclassq *ifq = tif->tif_ifq;
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
tcq_suspendq(struct tcq_if *tif, struct tcq_class *cl)
{
	struct ifclassq *ifq = tif->tif_ifq;
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
			VERIFY(cl->cl_flags & TQCF_LAZY);
			err = ENXIO;	/* delayed throttling */
		}
	}

	if (err == 0 || err == ENXIO)
		qstate(&cl->cl_q) = QS_SUSPENDED;

	return (err);
}
