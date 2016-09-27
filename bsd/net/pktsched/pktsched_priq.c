/*
 * Copyright (c) 2007-2013 Apple Inc. All rights reserved.
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

/*	$OpenBSD: altq_priq.c,v 1.21 2007/09/13 20:40:02 chl Exp $	*/
/*	$KAME: altq_priq.c,v 1.1 2000/10/18 09:15:23 kjc Exp $	*/

/*
 * Copyright (C) 2000-2003
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

/*
 * priority queue
 */

#if PKTSCHED_PRIQ

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

#include <net/pktsched/pktsched_priq.h>
#include <netinet/in.h>

/*
 * function prototypes
 */
static int priq_enqueue_ifclassq(struct ifclassq *, struct mbuf *);
static struct mbuf *priq_dequeue_ifclassq(struct ifclassq *, cqdq_op_t);
static int priq_request_ifclassq(struct ifclassq *, cqrq_t, void *);
static int priq_clear_interface(struct priq_if *);
static struct priq_class *priq_class_create(struct priq_if *, int, u_int32_t,
    int, u_int32_t);
static int priq_class_destroy(struct priq_if *, struct priq_class *);
static int priq_destroy_locked(struct priq_if *);
static inline int priq_addq(struct priq_class *, struct mbuf *,
    struct pf_mtag *);
static inline struct mbuf *priq_getq(struct priq_class *);
static inline struct mbuf *priq_pollq(struct priq_class *);
static void priq_purgeq(struct priq_if *, struct priq_class *, u_int32_t,
    u_int32_t *, u_int32_t *);
static void priq_purge_sc(struct priq_if *, cqrq_purge_sc_t *);
static void priq_updateq(struct priq_if *, struct priq_class *, cqev_t);
static int priq_throttle(struct priq_if *, cqrq_throttle_t *);
static int priq_resumeq(struct priq_if *, struct priq_class *);
static int priq_suspendq(struct priq_if *, struct priq_class *);
static int priq_stat_sc(struct priq_if *, cqrq_stat_sc_t *);
static inline struct priq_class *priq_clh_to_clp(struct priq_if *, u_int32_t);
static const char *priq_style(struct priq_if *);

#define	PRIQ_ZONE_MAX	32		/* maximum elements in zone */
#define	PRIQ_ZONE_NAME	"pktsched_priq"	/* zone name */

static unsigned int priq_size;		/* size of zone element */
static struct zone *priq_zone;		/* zone for priq */

#define	PRIQ_CL_ZONE_MAX	32	/* maximum elements in zone */
#define	PRIQ_CL_ZONE_NAME	"pktsched_priq_cl" /* zone name */

static unsigned int priq_cl_size;	/* size of zone element */
static struct zone *priq_cl_zone;	/* zone for priq_class */

void
priq_init(void)
{
	priq_size = sizeof (struct priq_if);
	priq_zone = zinit(priq_size, PRIQ_ZONE_MAX * priq_size,
	    0, PRIQ_ZONE_NAME);
	if (priq_zone == NULL) {
		panic("%s: failed allocating %s", __func__, PRIQ_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(priq_zone, Z_EXPAND, TRUE);
	zone_change(priq_zone, Z_CALLERACCT, TRUE);

	priq_cl_size = sizeof (struct priq_class);
	priq_cl_zone = zinit(priq_cl_size, PRIQ_CL_ZONE_MAX * priq_cl_size,
	    0, PRIQ_CL_ZONE_NAME);
	if (priq_cl_zone == NULL) {
		panic("%s: failed allocating %s", __func__, PRIQ_CL_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(priq_cl_zone, Z_EXPAND, TRUE);
	zone_change(priq_cl_zone, Z_CALLERACCT, TRUE);
}

struct priq_if *
priq_alloc(struct ifnet *ifp, int how, boolean_t altq)
{
	struct priq_if	*pif;

	pif = (how == M_WAITOK) ? zalloc(priq_zone) : zalloc_noblock(priq_zone);
	if (pif == NULL)
		return (NULL);

	bzero(pif, priq_size);
	pif->pif_maxpri = -1;
	pif->pif_ifq = &ifp->if_snd;
	if (altq)
		pif->pif_flags |= PRIQIFF_ALTQ;

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s scheduler allocated\n",
		    if_name(ifp), priq_style(pif));
	}

	return (pif);
}

int
priq_destroy(struct priq_if *pif)
{
	struct ifclassq *ifq = pif->pif_ifq;
	int err;

	IFCQ_LOCK(ifq);
	err = priq_destroy_locked(pif);
	IFCQ_UNLOCK(ifq);

	return (err);
}

static int
priq_destroy_locked(struct priq_if *pif)
{
	IFCQ_LOCK_ASSERT_HELD(pif->pif_ifq);

	(void) priq_clear_interface(pif);

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s scheduler destroyed\n",
		    if_name(PRIQIF_IFP(pif)), priq_style(pif));
	}

	zfree(priq_zone, pif);

	return (0);
}

/*
 * bring the interface back to the initial state by discarding
 * all the filters and classes.
 */
static int
priq_clear_interface(struct priq_if *pif)
{
	struct priq_class	*cl;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(pif->pif_ifq);

	/* clear out the classes */
	for (pri = 0; pri <= pif->pif_maxpri; pri++)
		if ((cl = pif->pif_classes[pri]) != NULL)
			priq_class_destroy(pif, cl);

	return (0);
}

/* discard all the queued packets on the interface */
void
priq_purge(struct priq_if *pif)
{
	struct priq_class *cl;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(pif->pif_ifq);

	for (pri = 0; pri <= pif->pif_maxpri; pri++) {
		if ((cl = pif->pif_classes[pri]) != NULL && !qempty(&cl->cl_q))
			priq_purgeq(pif, cl, 0, NULL, NULL);
	}
#if !PF_ALTQ
	/*
	 * This assertion is safe to be made only when PF_ALTQ is not
	 * configured; otherwise, IFCQ_LEN represents the sum of the
	 * packets managed by ifcq_disc and altq_disc instances, which
	 * is possible when transitioning between the two.
	 */
	VERIFY(IFCQ_LEN(pif->pif_ifq) == 0);
#endif /* !PF_ALTQ */
}

static void
priq_purge_sc(struct priq_if *pif, cqrq_purge_sc_t *pr)
{
	struct ifclassq *ifq = pif->pif_ifq;
	u_int32_t i;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	VERIFY(pr->sc == MBUF_SC_UNSPEC || MBUF_VALID_SC(pr->sc));
	VERIFY(pr->flow != 0);

	if (pr->sc != MBUF_SC_UNSPEC) {
		i = MBUF_SCIDX(pr->sc);
		VERIFY(i < IFCQ_SC_MAX);

		priq_purgeq(pif, ifq->ifcq_disc_slots[i].cl,
		    pr->flow, &pr->packets, &pr->bytes);
	} else {
		u_int32_t cnt, len;

		pr->packets = 0;
		pr->bytes = 0;

		for (i = 0; i < IFCQ_SC_MAX; i++) {
			priq_purgeq(pif, ifq->ifcq_disc_slots[i].cl,
			    pr->flow, &cnt, &len);
			pr->packets += cnt;
			pr->bytes += len;
		}
	}
}

void
priq_event(struct priq_if *pif, cqev_t ev)
{
	struct priq_class *cl;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(pif->pif_ifq);

	for (pri = 0; pri <= pif->pif_maxpri; pri++)
		if ((cl = pif->pif_classes[pri]) != NULL)
			priq_updateq(pif, cl, ev);
}

int
priq_add_queue(struct priq_if *pif, int priority, u_int32_t qlimit,
    int flags, u_int32_t qid, struct priq_class **clp)
{
	struct priq_class *cl;

	IFCQ_LOCK_ASSERT_HELD(pif->pif_ifq);

	/* check parameters */
	if (priority >= PRIQ_MAXPRI)
		return (EINVAL);
	if (pif->pif_classes[priority] != NULL)
		return (EBUSY);
	if (priq_clh_to_clp(pif, qid) != NULL)
		return (EBUSY);

	cl = priq_class_create(pif, priority, qlimit, flags, qid);
	if (cl == NULL)
		return (ENOMEM);

	if (clp != NULL)
		*clp = cl;

	return (0);
}

static struct priq_class *
priq_class_create(struct priq_if *pif, int pri, u_int32_t qlimit,
    int flags, u_int32_t qid)
{
	struct ifnet *ifp;
	struct ifclassq *ifq;
	struct priq_class *cl;

	IFCQ_LOCK_ASSERT_HELD(pif->pif_ifq);

	/* Sanitize flags unless internally configured */
	if (pif->pif_flags & PRIQIFF_ALTQ)
		flags &= PRCF_USERFLAGS;

#if !CLASSQ_RED
	if (flags & PRCF_RED) {
		log(LOG_ERR, "%s: %s RED not available!\n",
		    if_name(PRIQIF_IFP(pif)), priq_style(pif));
		return (NULL);
	}
#endif /* !CLASSQ_RED */

#if !CLASSQ_RIO
	if (flags & PRCF_RIO) {
		log(LOG_ERR, "%s: %s RIO not available!\n",
		    if_name(PRIQIF_IFP(pif)), priq_style(pif));
		return (NULL);
	}
#endif /* CLASSQ_RIO */

#if !CLASSQ_BLUE
	if (flags & PRCF_BLUE) {
		log(LOG_ERR, "%s: %s BLUE not available!\n",
		    if_name(PRIQIF_IFP(pif)), priq_style(pif));
		return (NULL);
	}
#endif /* CLASSQ_BLUE */

	/* These are mutually exclusive */
	if ((flags & (PRCF_RED|PRCF_RIO|PRCF_BLUE|PRCF_SFB)) &&
	    (flags & (PRCF_RED|PRCF_RIO|PRCF_BLUE|PRCF_SFB)) != PRCF_RED &&
	    (flags & (PRCF_RED|PRCF_RIO|PRCF_BLUE|PRCF_SFB)) != PRCF_RIO &&
	    (flags & (PRCF_RED|PRCF_RIO|PRCF_BLUE|PRCF_SFB)) != PRCF_BLUE &&
	    (flags & (PRCF_RED|PRCF_RIO|PRCF_BLUE|PRCF_SFB)) != PRCF_SFB) {
		log(LOG_ERR, "%s: %s more than one RED|RIO|BLUE|SFB\n",
		    if_name(PRIQIF_IFP(pif)), priq_style(pif));
		return (NULL);
	}

	ifq = pif->pif_ifq;
	ifp = PRIQIF_IFP(pif);

	if ((cl = pif->pif_classes[pri]) != NULL) {
		/* modify the class instead of creating a new one */
		if (!qempty(&cl->cl_q))
			priq_purgeq(pif, cl, 0, NULL, NULL);
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
		cl = zalloc(priq_cl_zone);
		if (cl == NULL)
			return (NULL);

		bzero(cl, priq_cl_size);
	}

	pif->pif_classes[pri] = cl;
	if (flags & PRCF_DEFAULTCLASS)
		pif->pif_default = cl;
	if (qlimit == 0 || qlimit > IFCQ_MAXLEN(ifq)) {
		qlimit = IFCQ_MAXLEN(ifq);
		if (qlimit == 0)
			qlimit = DEFAULT_QLIMIT;  /* use default */
	}
	_qinit(&cl->cl_q, Q_DROPTAIL, qlimit);
	cl->cl_flags = flags;
	cl->cl_pri = pri;
	if (pri > pif->pif_maxpri)
		pif->pif_maxpri = pri;
	cl->cl_pif = pif;
	cl->cl_handle = qid;

	if (flags & (PRCF_RED|PRCF_RIO|PRCF_BLUE|PRCF_SFB)) {
#if CLASSQ_RED || CLASSQ_RIO
		u_int64_t ifbandwidth = ifnet_output_linkrate(ifp);
		int pkttime;
#endif /* CLASSQ_RED || CLASSQ_RIO */

		cl->cl_qflags = 0;
		if (flags & PRCF_ECN) {
			if (flags & PRCF_BLUE)
				cl->cl_qflags |= BLUEF_ECN;
			else if (flags & PRCF_SFB)
				cl->cl_qflags |= SFBF_ECN;
			else if (flags & PRCF_RED)
				cl->cl_qflags |= REDF_ECN;
			else if (flags & PRCF_RIO)
				cl->cl_qflags |= RIOF_ECN;
		}
		if (flags & PRCF_FLOWCTL) {
			if (flags & PRCF_SFB)
				cl->cl_qflags |= SFBF_FLOWCTL;
		}
		if (flags & PRCF_CLEARDSCP) {
			if (flags & PRCF_RIO)
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
		if (flags & PRCF_RED) {
			cl->cl_red = red_alloc(ifp, 0, 0,
			    qlimit(&cl->cl_q) * 10/100,
			    qlimit(&cl->cl_q) * 30/100,
			    cl->cl_qflags, pkttime);
			if (cl->cl_red != NULL)
				qtype(&cl->cl_q) = Q_RED;
		}
#endif /* CLASSQ_RED */
#if CLASSQ_RIO
		if (flags & PRCF_RIO) {
			cl->cl_rio =
			    rio_alloc(ifp, 0, NULL, cl->cl_qflags, pkttime);
			if (cl->cl_rio != NULL)
				qtype(&cl->cl_q) = Q_RIO;
		}
#endif /* CLASSQ_RIO */
#endif /* CLASSQ_RED || CLASSQ_RIO */
#if CLASSQ_BLUE
		if (flags & PRCF_BLUE) {
			cl->cl_blue = blue_alloc(ifp, 0, 0, cl->cl_qflags);
			if (cl->cl_blue != NULL)
				qtype(&cl->cl_q) = Q_BLUE;
		}
#endif /* CLASSQ_BLUE */
		if (flags & PRCF_SFB) {
			if (!(cl->cl_flags & PRCF_LAZY))
				cl->cl_sfb = sfb_alloc(ifp, cl->cl_handle,
				    qlimit(&cl->cl_q), cl->cl_qflags);
			if (cl->cl_sfb != NULL || (cl->cl_flags & PRCF_LAZY))
				qtype(&cl->cl_q) = Q_SFB;
		}
	}

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s created qid=%d pri=%d qlimit=%d "
		    "flags=%b\n", if_name(ifp), priq_style(pif),
		    cl->cl_handle, cl->cl_pri, qlimit, flags, PRCF_BITS);
	}

	return (cl);
}

int
priq_remove_queue(struct priq_if *pif, u_int32_t qid)
{
	struct priq_class *cl;

	IFCQ_LOCK_ASSERT_HELD(pif->pif_ifq);

	if ((cl = priq_clh_to_clp(pif, qid)) == NULL)
		return (EINVAL);

	return (priq_class_destroy(pif, cl));
}

static int
priq_class_destroy(struct priq_if *pif, struct priq_class *cl)
{
	struct ifclassq *ifq = pif->pif_ifq;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (!qempty(&cl->cl_q))
		priq_purgeq(pif, cl, 0, NULL, NULL);

	VERIFY(cl->cl_pri < PRIQ_MAXPRI);
	VERIFY(!pktsched_bit_tst(cl->cl_pri, &pif->pif_bitmap));

	pif->pif_classes[cl->cl_pri] = NULL;
	if (pif->pif_maxpri == cl->cl_pri) {
		for (pri = cl->cl_pri; pri >= 0; pri--)
			if (pif->pif_classes[pri] != NULL) {
				pif->pif_maxpri = pri;
				break;
			}
		if (pri < 0)
			pif->pif_maxpri = -1;
	}

	if (pif->pif_default == cl)
		pif->pif_default = NULL;

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
		    if_name(PRIQIF_IFP(pif)), priq_style(pif),
		    cl->cl_handle, cl->cl_pri);
	}

	zfree(priq_cl_zone, cl);

	return (0);
}

int
priq_enqueue(struct priq_if *pif, struct priq_class *cl, struct mbuf *m,
    struct pf_mtag *t)
{
	struct ifclassq *ifq = pif->pif_ifq;
	u_int32_t pri;
	int len, ret;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(cl == NULL || cl->cl_pif == pif);

	if (cl == NULL) {
#if PF_ALTQ
		cl = priq_clh_to_clp(pif, t->pftag_qid);
#else /* !PF_ALTQ */
		cl = priq_clh_to_clp(pif, 0);
#endif /* !PF_ALTQ */
		if (cl == NULL) {
			cl = pif->pif_default;
			if (cl == NULL) {
				IFCQ_CONVERT_LOCK(ifq);
				m_freem(m);
				return (ENOBUFS);
			}
		}
	}
	pri = cl->cl_pri;
	VERIFY(pri < PRIQ_MAXPRI);

	len = m_pktlen(m);

	ret = priq_addq(cl, m, t);
	if (ret != 0) {
		if (ret == CLASSQEQ_SUCCESS_FC) {
			/* packet enqueued, return advisory feedback */
			ret = EQFULL;
		} else {
			VERIFY(ret == CLASSQEQ_DROPPED ||
			    ret == CLASSQEQ_DROPPED_FC ||
			    ret == CLASSQEQ_DROPPED_SP);
			/* packet has been freed in priq_addq */
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

	/* class is now active; indicate it as such */
	if (!pktsched_bit_tst(pri, &pif->pif_bitmap))
		pktsched_bit_set(pri, &pif->pif_bitmap);

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
priq_dequeue(struct priq_if *pif, cqdq_op_t op)
{
	struct ifclassq *ifq = pif->pif_ifq;
	struct priq_class *cl;
	struct mbuf *m;
	u_int32_t pri, len;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (pif->pif_bitmap == 0) {
		/* no active class; nothing to dequeue */
		return (NULL);
	}
	VERIFY(!IFCQ_IS_EMPTY(ifq));

	pri = pktsched_fls(pif->pif_bitmap) - 1;	/* zero based */
	VERIFY(pri < PRIQ_MAXPRI);
	cl = pif->pif_classes[pri];
	VERIFY(cl != NULL && !qempty(&cl->cl_q));

	if (op == CLASSQDQ_POLL)
		return (priq_pollq(cl));

	m = priq_getq(cl);
	VERIFY(m != NULL);	/* qalg must be work conserving */
	len = m_pktlen(m);

	IFCQ_DEC_LEN(ifq);
	IFCQ_DEC_BYTES(ifq, len);
	if (qempty(&cl->cl_q)) {
		cl->cl_period++;
		/* class is now inactive; indicate it as such */
		pktsched_bit_clr(pri, &pif->pif_bitmap);
	}
	PKTCNTR_ADD(&cl->cl_xmitcnt, 1, len);
	IFCQ_XMIT_ADD(ifq, 1, len);

	return (m);
}

static inline int
priq_addq(struct priq_class *cl, struct mbuf *m, struct pf_mtag *t)
{
	struct priq_if *pif = cl->cl_pif;
	struct ifclassq *ifq = pif->pif_ifq;

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
			struct ifnet *ifp = PRIQIF_IFP(pif);

			VERIFY(cl->cl_flags & PRCF_LAZY);
			cl->cl_flags &= ~PRCF_LAZY;
			IFCQ_CONVERT_LOCK(ifq);

			cl->cl_sfb = sfb_alloc(ifp, cl->cl_handle,
			    qlimit(&cl->cl_q), cl->cl_qflags);
			if (cl->cl_sfb == NULL) {
				/* fall back to droptail */
				qtype(&cl->cl_q) = Q_DROPTAIL;
				cl->cl_flags &= ~PRCF_SFB;
				cl->cl_qflags &= ~(SFBF_ECN | SFBF_FLOWCTL);

				log(LOG_ERR, "%s: %s SFB lazy allocation "
				    "failed for qid=%d pri=%d, falling back "
				    "to DROPTAIL\n", if_name(ifp),
				    priq_style(pif), cl->cl_handle,
				    cl->cl_pri);
			} else if (pif->pif_throttle != IFNET_THROTTLE_OFF) {
				/* if there's pending throttling, set it */
				cqrq_throttle_t tr = { 1, pif->pif_throttle };
				int err = priq_throttle(pif, &tr);

				if (err == EALREADY)
					err = 0;
				if (err != 0) {
					tr.level = IFNET_THROTTLE_OFF;
					(void) priq_throttle(pif, &tr);
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
	if (cl->cl_flags & PRCF_CLEARDSCP)
		write_dsfield(m, t, 0);
#endif /* PF_ECN */

	_addq(&cl->cl_q, m);

	return (0);
}

static inline struct mbuf *
priq_getq(struct priq_class *cl)
{
	IFCQ_LOCK_ASSERT_HELD(cl->cl_pif->pif_ifq);

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
priq_pollq(struct priq_class *cl)
{
	IFCQ_LOCK_ASSERT_HELD(cl->cl_pif->pif_ifq);

	return (qhead(&cl->cl_q));
}

static void
priq_purgeq(struct priq_if *pif, struct priq_class *cl, u_int32_t flow,
    u_int32_t *packets, u_int32_t *bytes)
{
	struct ifclassq *ifq = pif->pif_ifq;
	u_int32_t cnt = 0, len = 0, qlen;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if ((qlen = qlen(&cl->cl_q)) == 0) {
		VERIFY(!pktsched_bit_tst(cl->cl_pri, &pif->pif_bitmap));
		goto done;
	}

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

		if (qempty(&cl->cl_q))
			pktsched_bit_clr(cl->cl_pri, &pif->pif_bitmap);

		if (pktsched_verbose) {
			log(LOG_DEBUG, "%s: %s purge qid=%d pri=%d "
			    "qlen=[%d,%d] cnt=%d len=%d flow=0x%x\n",
			    if_name(PRIQIF_IFP(pif)), priq_style(pif),
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
priq_updateq(struct priq_if *pif, struct priq_class *cl, cqev_t ev)
{
	IFCQ_LOCK_ASSERT_HELD(pif->pif_ifq);

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s update qid=%d pri=%d event=%s\n",
		    if_name(PRIQIF_IFP(pif)), priq_style(pif),
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
priq_get_class_stats(struct priq_if *pif, u_int32_t qid,
    struct priq_classstats *sp)
{
	struct priq_class *cl;

	IFCQ_LOCK_ASSERT_HELD(pif->pif_ifq);

	if ((cl = priq_clh_to_clp(pif, qid)) == NULL)
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
priq_stat_sc(struct priq_if *pif, cqrq_stat_sc_t *sr)
{
	struct ifclassq *ifq = pif->pif_ifq;
	struct priq_class *cl;
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
static inline struct priq_class *
priq_clh_to_clp(struct priq_if *pif, u_int32_t chandle)
{
	struct priq_class *cl;
	int idx;

	IFCQ_LOCK_ASSERT_HELD(pif->pif_ifq);

	for (idx = pif->pif_maxpri; idx >= 0; idx--)
		if ((cl = pif->pif_classes[idx]) != NULL &&
		    cl->cl_handle == chandle)
			return (cl);

	return (NULL);
}

static const char *
priq_style(struct priq_if *pif)
{
	return ((pif->pif_flags & PRIQIFF_ALTQ) ? "ALTQ_PRIQ" : "PRIQ");
}

/*
 * priq_enqueue_ifclassq is an enqueue function to be registered to
 * (*ifcq_enqueue) in struct ifclassq.
 */
static int
priq_enqueue_ifclassq(struct ifclassq *ifq, struct mbuf *m)
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

	return (priq_enqueue(ifq->ifcq_disc,
	    ifq->ifcq_disc_slots[i].cl, m, m_pftag(m)));
}

/*
 * priq_dequeue_ifclassq is a dequeue function to be registered to
 * (*ifcq_dequeue) in struct ifclass.
 *
 * note: CLASSQDQ_POLL returns the next packet without removing the packet
 *	from the queue.  CLASSQDQ_REMOVE is a normal dequeue operation.
 *	CLASSQDQ_REMOVE must return the same packet if called immediately
 *	after CLASSQDQ_POLL.
 */
static struct mbuf *
priq_dequeue_ifclassq(struct ifclassq *ifq, cqdq_op_t op)
{
	return (priq_dequeue(ifq->ifcq_disc, op));
}

static int
priq_request_ifclassq(struct ifclassq *ifq, cqrq_t req, void *arg)
{
	struct priq_if *pif = (struct priq_if *)ifq->ifcq_disc;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	switch (req) {
	case CLASSQRQ_PURGE:
		priq_purge(pif);
		break;

	case CLASSQRQ_PURGE_SC:
		priq_purge_sc(pif, (cqrq_purge_sc_t *)arg);
		break;

	case CLASSQRQ_EVENT:
		priq_event(pif, (cqev_t)arg);
		break;

	case CLASSQRQ_THROTTLE:
		err = priq_throttle(pif, (cqrq_throttle_t *)arg);
		break;

	case CLASSQRQ_STAT_SC:
		err = priq_stat_sc(pif, (cqrq_stat_sc_t *)arg);
		break;
	}
	return (err);
}

int
priq_setup_ifclassq(struct ifclassq *ifq, u_int32_t flags)
{
	struct ifnet *ifp = ifq->ifcq_ifp;
	struct priq_class *cl0, *cl1, *cl2, *cl3, *cl4;
	struct priq_class *cl5, *cl6, *cl7, *cl8, *cl9;
	struct priq_if *pif;
	u_int32_t maxlen = 0, qflags = 0;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_disc == NULL);
	VERIFY(ifq->ifcq_type == PKTSCHEDT_NONE);

	if (flags & PKTSCHEDF_QALG_RED)
		qflags |= PRCF_RED;
	if (flags & PKTSCHEDF_QALG_RIO)
		qflags |= PRCF_RIO;
	if (flags & PKTSCHEDF_QALG_BLUE)
		qflags |= PRCF_BLUE;
	if (flags & PKTSCHEDF_QALG_SFB)
		qflags |= PRCF_SFB;
	if (flags & PKTSCHEDF_QALG_ECN)
		qflags |= PRCF_ECN;
	if (flags & PKTSCHEDF_QALG_FLOWCTL)
		qflags |= PRCF_FLOWCTL;

	pif = priq_alloc(ifp, M_WAITOK, FALSE);
	if (pif == NULL)
		return (ENOMEM);

	if ((maxlen = IFCQ_MAXLEN(ifq)) == 0)
		maxlen = if_sndq_maxlen;

	if ((err = priq_add_queue(pif, 0, maxlen,
	    qflags | PRCF_LAZY, SCIDX_BK_SYS, &cl0)) != 0)
		goto cleanup;

	if ((err = priq_add_queue(pif, 1, maxlen,
	    qflags | PRCF_LAZY, SCIDX_BK, &cl1)) != 0)
		goto cleanup;

	if ((err = priq_add_queue(pif, 2, maxlen,
	    qflags | PRCF_DEFAULTCLASS, SCIDX_BE, &cl2)) != 0)
		goto cleanup;

	if ((err = priq_add_queue(pif, 3, maxlen,
	    qflags | PRCF_LAZY, SCIDX_RD, &cl3)) != 0)
		goto cleanup;

	if ((err = priq_add_queue(pif, 4, maxlen,
	    qflags | PRCF_LAZY, SCIDX_OAM, &cl4)) != 0)
		goto cleanup;

	if ((err = priq_add_queue(pif, 5, maxlen,
	    qflags | PRCF_LAZY, SCIDX_AV, &cl5)) != 0)
		goto cleanup;

	if ((err = priq_add_queue(pif, 6, maxlen,
	    qflags | PRCF_LAZY, SCIDX_RV, &cl6)) != 0)
		goto cleanup;

	if ((err = priq_add_queue(pif, 7, maxlen,
	    qflags | PRCF_LAZY, SCIDX_VI, &cl7)) != 0)
		goto cleanup;

	if ((err = priq_add_queue(pif, 8, maxlen,
	    qflags | PRCF_LAZY, SCIDX_VO, &cl8)) != 0)
		goto cleanup;

	if ((err = priq_add_queue(pif, 9, maxlen,
	    qflags, SCIDX_CTL, &cl9)) != 0)
		goto cleanup;

	err = ifclassq_attach(ifq, PKTSCHEDT_PRIQ, pif,
	    priq_enqueue_ifclassq, priq_dequeue_ifclassq, NULL,
	    NULL, priq_request_ifclassq);

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
		(void) priq_destroy_locked(pif);

	return (err);
}

int
priq_teardown_ifclassq(struct ifclassq *ifq)
{
	struct priq_if *pif = ifq->ifcq_disc;
	int i;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(pif != NULL && ifq->ifcq_type == PKTSCHEDT_PRIQ);

	(void) priq_destroy_locked(pif);

	ifq->ifcq_disc = NULL;
	for (i = 0; i < IFCQ_SC_MAX; i++) {
		ifq->ifcq_disc_slots[i].qid = 0;
		ifq->ifcq_disc_slots[i].cl = NULL;
	}

	return (ifclassq_detach(ifq));
}

int
priq_getqstats_ifclassq(struct ifclassq *ifq, u_int32_t slot,
    struct if_ifclassq_stats *ifqs)
{
	struct priq_if *pif = ifq->ifcq_disc;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_type == PKTSCHEDT_PRIQ);

	if (slot >= IFCQ_SC_MAX)
		return (EINVAL);

	return (priq_get_class_stats(pif, ifq->ifcq_disc_slots[slot].qid,
	    &ifqs->ifqs_priq_stats));
}

static int
priq_throttle(struct priq_if *pif, cqrq_throttle_t *tr)
{
	struct ifclassq *ifq = pif->pif_ifq;
	struct priq_class *cl;
	int err = 0;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(!(pif->pif_flags & PRIQIFF_ALTQ));

	if (!tr->set) {
		tr->level = pif->pif_throttle;
		return (0);
	}

	if (tr->level == pif->pif_throttle)
		return (EALREADY);

	/* Current throttling levels only involve BK_SYS class */
	cl = ifq->ifcq_disc_slots[SCIDX_BK_SYS].cl;

	switch (tr->level) {
	case IFNET_THROTTLE_OFF:
		err = priq_resumeq(pif, cl);
		break;

	case IFNET_THROTTLE_OPPORTUNISTIC:
		err = priq_suspendq(pif, cl);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}

	if (err == 0 || err == ENXIO) {
		if (pktsched_verbose) {
			log(LOG_DEBUG, "%s: %s throttling level %sset %d->%d\n",
			    if_name(PRIQIF_IFP(pif)), priq_style(pif),
			    (err == 0) ? "" : "lazy ", pif->pif_throttle,
			    tr->level);
		}
		pif->pif_throttle = tr->level;
		if (err != 0)
			err = 0;
		else
			priq_purgeq(pif, cl, 0, NULL, NULL);
	} else {
		log(LOG_ERR, "%s: %s unable to set throttling level "
		    "%d->%d [error=%d]\n", if_name(PRIQIF_IFP(pif)),
		    priq_style(pif), pif->pif_throttle, tr->level, err);
	}

	return (err);
}

static int
priq_resumeq(struct priq_if *pif, struct priq_class *cl)
{
	struct ifclassq *ifq = pif->pif_ifq;
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
priq_suspendq(struct priq_if *pif, struct priq_class *cl)
{
	struct ifclassq *ifq = pif->pif_ifq;
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
			VERIFY(cl->cl_flags & PRCF_LAZY);
			err = ENXIO;	/* delayed throttling */
		}
	}

	if (err == 0 || err == ENXIO)
		qstate(&cl->cl_q) = QS_SUSPENDED;

	return (err);
}
#endif /* PKTSCHED_PRIQ */
