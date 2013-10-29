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

/*	$OpenBSD: altq_hfsc.c,v 1.25 2007/09/13 20:40:02 chl Exp $	*/
/*	$KAME: altq_hfsc.c,v 1.17 2002/11/29 07:48:33 kjc Exp $	*/

/*
 * Copyright (c) 1997-1999 Carnegie Mellon University. All Rights Reserved.
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation is hereby granted (including for commercial or
 * for-profit use), provided that both the copyright notice and this
 * permission notice appear in all copies of the software, derivative
 * works, or modified versions, and any portions thereof.
 *
 * THIS SOFTWARE IS EXPERIMENTAL AND IS KNOWN TO HAVE BUGS, SOME OF
 * WHICH MAY HAVE SERIOUS CONSEQUENCES.  CARNEGIE MELLON PROVIDES THIS
 * SOFTWARE IN ITS ``AS IS'' CONDITION, AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Carnegie Mellon encourages (but does not require) users of this
 * software to return any improvements or extensions that they make,
 * and to grant Carnegie Mellon the rights to redistribute these
 * changes without encumbrance.
 */
/*
 * H-FSC is described in Proceedings of SIGCOMM'97,
 * "A Hierarchical Fair Service Curve Algorithm for Link-Sharing,
 * Real-Time and Priority Service"
 * by Ion Stoica, Hui Zhang, and T. S. Eugene Ng.
 *
 * Oleg Cherevko <olwi@aq.ml.com.ua> added the upperlimit for link-sharing.
 * when a class has an upperlimit, the fit-time is computed from the
 * upperlimit service curve.  the link-sharing scheduler does not schedule
 * a class whose fit-time exceeds the current time.
 */

#if PKTSCHED_HFSC

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

#include <net/pktsched/pktsched_hfsc.h>
#include <netinet/in.h>

/*
 * function prototypes
 */
#if 0
static int hfsc_enqueue_ifclassq(struct ifclassq *, struct mbuf *);
static struct mbuf *hfsc_dequeue_ifclassq(struct ifclassq *, cqdq_op_t);
static int hfsc_request_ifclassq(struct ifclassq *, cqrq_t, void *);
#endif
static int hfsc_addq(struct hfsc_class *, struct mbuf *, struct pf_mtag *);
static struct mbuf *hfsc_getq(struct hfsc_class *);
static struct mbuf *hfsc_pollq(struct hfsc_class *);
static void hfsc_purgeq(struct hfsc_if *, struct hfsc_class *, u_int32_t,
    u_int32_t *, u_int32_t *);
static void hfsc_print_sc(struct hfsc_if *, u_int32_t, u_int64_t,
    struct service_curve *, struct internal_sc *, const char *);
static void hfsc_updateq_linkrate(struct hfsc_if *, struct hfsc_class *);
static void hfsc_updateq(struct hfsc_if *, struct hfsc_class *, cqev_t);

static int hfsc_clear_interface(struct hfsc_if *);
static struct hfsc_class *hfsc_class_create(struct hfsc_if *,
    struct service_curve *, struct service_curve *, struct service_curve *,
    struct hfsc_class *, u_int32_t, int, u_int32_t);
static int hfsc_class_destroy(struct hfsc_if *, struct hfsc_class *);
static int hfsc_destroy_locked(struct hfsc_if *);
static struct hfsc_class *hfsc_nextclass(struct hfsc_class *);
static struct hfsc_class *hfsc_clh_to_clp(struct hfsc_if *, u_int32_t);
static const char *hfsc_style(struct hfsc_if *);

static void set_active(struct hfsc_class *, u_int32_t);
static void set_passive(struct hfsc_class *);

static void init_ed(struct hfsc_class *, u_int32_t);
static void update_ed(struct hfsc_class *, u_int32_t);
static void update_d(struct hfsc_class *, u_int32_t);
static void init_vf(struct hfsc_class *, u_int32_t);
static void update_vf(struct hfsc_class *, u_int32_t, u_int64_t);
static void update_cfmin(struct hfsc_class *);
static void ellist_insert(struct hfsc_class *);
static void ellist_remove(struct hfsc_class *);
static void ellist_update(struct hfsc_class *);
static struct hfsc_class *ellist_get_mindl(ellist_t *, u_int64_t);
static void actlist_insert(struct hfsc_class *);
static void actlist_remove(struct hfsc_class *);
static void actlist_update(struct hfsc_class *);
static struct hfsc_class *actlist_firstfit(struct hfsc_class *, u_int64_t);

static inline u_int64_t	seg_x2y(u_int64_t, u_int64_t);
static inline u_int64_t	seg_y2x(u_int64_t, u_int64_t);
static inline u_int64_t	m2sm(u_int64_t);
static inline u_int64_t	m2ism(u_int64_t);
static inline u_int64_t	d2dx(u_int64_t);
static u_int64_t sm2m(u_int64_t);
static u_int64_t dx2d(u_int64_t);

static boolean_t sc2isc(struct hfsc_class *, struct service_curve *,
    struct internal_sc *, u_int64_t);
static void rtsc_init(struct runtime_sc *, struct internal_sc *,
    u_int64_t, u_int64_t);
static u_int64_t rtsc_y2x(struct runtime_sc *, u_int64_t);
static u_int64_t rtsc_x2y(struct runtime_sc *, u_int64_t);
static void rtsc_min(struct runtime_sc *, struct internal_sc *,
    u_int64_t, u_int64_t);

#define	HFSC_ZONE_MAX	32		/* maximum elements in zone */
#define	HFSC_ZONE_NAME	"pktsched_hfsc"	/* zone name */

static unsigned int hfsc_size;		/* size of zone element */
static struct zone *hfsc_zone;		/* zone for hfsc_if */

#define	HFSC_CL_ZONE_MAX	32	/* maximum elements in zone */
#define	HFSC_CL_ZONE_NAME	"pktsched_hfsc_cl" /* zone name */

static unsigned int hfsc_cl_size;	/* size of zone element */
static struct zone *hfsc_cl_zone;	/* zone for hfsc_class */

/*
 * macros
 */
#define	HFSC_IS_A_PARENT_CLASS(cl)	((cl)->cl_children != NULL)

#define	HT_INFINITY	0xffffffffffffffffLL	/* infinite time value */

void
hfsc_init(void)
{
	hfsc_size = sizeof (struct hfsc_if);
	hfsc_zone = zinit(hfsc_size, HFSC_ZONE_MAX * hfsc_size,
	    0, HFSC_ZONE_NAME);
	if (hfsc_zone == NULL) {
		panic("%s: failed allocating %s", __func__, HFSC_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(hfsc_zone, Z_EXPAND, TRUE);
	zone_change(hfsc_zone, Z_CALLERACCT, TRUE);

	hfsc_cl_size = sizeof (struct hfsc_class);
	hfsc_cl_zone = zinit(hfsc_cl_size, HFSC_CL_ZONE_MAX * hfsc_cl_size,
	    0, HFSC_CL_ZONE_NAME);
	if (hfsc_cl_zone == NULL) {
		panic("%s: failed allocating %s", __func__, HFSC_CL_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(hfsc_cl_zone, Z_EXPAND, TRUE);
	zone_change(hfsc_cl_zone, Z_CALLERACCT, TRUE);
}

struct hfsc_if *
hfsc_alloc(struct ifnet *ifp, int how, boolean_t altq)
{
	struct hfsc_if *hif;

	hif = (how == M_WAITOK) ? zalloc(hfsc_zone) : zalloc_noblock(hfsc_zone);
	if (hif == NULL)
		return (NULL);

	bzero(hif, hfsc_size);
	TAILQ_INIT(&hif->hif_eligible);
	hif->hif_ifq = &ifp->if_snd;
	if (altq) {
		hif->hif_maxclasses = HFSC_MAX_CLASSES;
		hif->hif_flags |= HFSCIFF_ALTQ;
	} else {
		hif->hif_maxclasses = IFCQ_SC_MAX + 1;	/* incl. root class */
	}

	if ((hif->hif_class_tbl = _MALLOC(sizeof (struct hfsc_class *) *
	    hif->hif_maxclasses, M_DEVBUF, M_WAITOK|M_ZERO)) == NULL) {
		log(LOG_ERR, "%s: %s unable to allocate class table array\n",
		    if_name(ifp), hfsc_style(hif));
		goto error;
	}

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s scheduler allocated\n",
		    if_name(ifp), hfsc_style(hif));
	}

	return (hif);

error:
	if (hif->hif_class_tbl != NULL) {
		_FREE(hif->hif_class_tbl, M_DEVBUF);
		hif->hif_class_tbl = NULL;
	}
	zfree(hfsc_zone, hif);

	return (NULL);
}

int
hfsc_destroy(struct hfsc_if *hif)
{
	struct ifclassq *ifq = hif->hif_ifq;
	int err;

	IFCQ_LOCK(ifq);
	err = hfsc_destroy_locked(hif);
	IFCQ_UNLOCK(ifq);

	return (err);
}

static int
hfsc_destroy_locked(struct hfsc_if *hif)
{
	IFCQ_LOCK_ASSERT_HELD(hif->hif_ifq);

	(void) hfsc_clear_interface(hif);
	(void) hfsc_class_destroy(hif, hif->hif_rootclass);

	VERIFY(hif->hif_class_tbl != NULL);
	_FREE(hif->hif_class_tbl, M_DEVBUF);
	hif->hif_class_tbl = NULL;

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s scheduler destroyed\n",
		    if_name(HFSCIF_IFP(hif)), hfsc_style(hif));
	}

	zfree(hfsc_zone, hif);

	return (0);
}

/*
 * bring the interface back to the initial state by discarding
 * all the filters and classes except the root class.
 */
static int
hfsc_clear_interface(struct hfsc_if *hif)
{
	struct hfsc_class	*cl;

	IFCQ_LOCK_ASSERT_HELD(hif->hif_ifq);

	/* clear out the classes */
	while (hif->hif_rootclass != NULL &&
	    (cl = hif->hif_rootclass->cl_children) != NULL) {
		/*
		 * remove the first leaf class found in the hierarchy
		 * then start over
		 */
		for (; cl != NULL; cl = hfsc_nextclass(cl)) {
			if (!HFSC_IS_A_PARENT_CLASS(cl)) {
				(void) hfsc_class_destroy(hif, cl);
				break;
			}
		}
	}

	return (0);
}

/* discard all the queued packets on the interface */
void
hfsc_purge(struct hfsc_if *hif)
{
	struct hfsc_class *cl;

	IFCQ_LOCK_ASSERT_HELD(hif->hif_ifq);

	for (cl = hif->hif_rootclass; cl != NULL; cl = hfsc_nextclass(cl)) {
		if (!qempty(&cl->cl_q))
			hfsc_purgeq(hif, cl, 0, NULL, NULL);
	}
#if !PF_ALTQ
	/*
	 * This assertion is safe to be made only when PF_ALTQ is not
	 * configured; otherwise, IFCQ_LEN represents the sum of the
	 * packets managed by ifcq_disc and altq_disc instances, which
	 * is possible when transitioning between the two.
	 */
	VERIFY(IFCQ_LEN(hif->hif_ifq) == 0);
#endif /* !PF_ALTQ */
}

void
hfsc_event(struct hfsc_if *hif, cqev_t ev)
{
	struct hfsc_class *cl;

	IFCQ_LOCK_ASSERT_HELD(hif->hif_ifq);

	for (cl = hif->hif_rootclass; cl != NULL; cl = hfsc_nextclass(cl))
		hfsc_updateq(hif, cl, ev);
}

int
hfsc_add_queue(struct hfsc_if *hif, struct service_curve *rtsc,
    struct service_curve *lssc, struct service_curve *ulsc,
    u_int32_t qlimit, int flags, u_int32_t parent_qid, u_int32_t qid,
    struct hfsc_class **clp)
{
	struct hfsc_class *cl = NULL, *parent;

	IFCQ_LOCK_ASSERT_HELD(hif->hif_ifq);

	if (parent_qid == HFSC_NULLCLASS_HANDLE && hif->hif_rootclass == NULL)
		parent = NULL;
	else if ((parent = hfsc_clh_to_clp(hif, parent_qid)) == NULL)
		return (EINVAL);

	if (hfsc_clh_to_clp(hif, qid) != NULL)
		return (EBUSY);

	cl = hfsc_class_create(hif, rtsc, lssc, ulsc, parent,
	    qlimit, flags, qid);
	if (cl == NULL)
		return (ENOMEM);

	if (clp != NULL)
		*clp = cl;

	return (0);
}

static struct hfsc_class *
hfsc_class_create(struct hfsc_if *hif, struct service_curve *rsc,
    struct service_curve *fsc, struct service_curve *usc,
    struct hfsc_class *parent, u_int32_t qlimit, int flags, u_int32_t qid)
{
	struct ifnet *ifp;
	struct ifclassq *ifq;
	struct hfsc_class *cl, *p;
	u_int64_t eff_rate;
	u_int32_t i;

	IFCQ_LOCK_ASSERT_HELD(hif->hif_ifq);

	/* Sanitize flags unless internally configured */
	if (hif->hif_flags & HFSCIFF_ALTQ)
		flags &= HFCF_USERFLAGS;

	if (hif->hif_classes >= hif->hif_maxclasses) {
		log(LOG_ERR, "%s: %s out of classes! (max %d)\n",
		    if_name(HFSCIF_IFP(hif)), hfsc_style(hif),
		    hif->hif_maxclasses);
		return (NULL);
	}

#if !CLASSQ_RED
	if (flags & HFCF_RED) {
		log(LOG_ERR, "%s: %s RED not available!\n",
		    if_name(HFSCIF_IFP(hif)), hfsc_style(hif));
		return (NULL);
	}
#endif /* !CLASSQ_RED */

#if !CLASSQ_RIO
	if (flags & HFCF_RIO) {
		log(LOG_ERR, "%s: %s RIO not available!\n",
		    if_name(HFSCIF_IFP(hif)), hfsc_style(hif));
		return (NULL);
	}
#endif /* CLASSQ_RIO */

#if !CLASSQ_BLUE
	if (flags & HFCF_BLUE) {
		log(LOG_ERR, "%s: %s BLUE not available!\n",
		    if_name(HFSCIF_IFP(hif)), hfsc_style(hif));
		return (NULL);
	}
#endif /* CLASSQ_BLUE */

	/* These are mutually exclusive */
	if ((flags & (HFCF_RED|HFCF_RIO|HFCF_BLUE|HFCF_SFB)) &&
	    (flags & (HFCF_RED|HFCF_RIO|HFCF_BLUE|HFCF_SFB)) != HFCF_RED &&
	    (flags & (HFCF_RED|HFCF_RIO|HFCF_BLUE|HFCF_SFB)) != HFCF_RIO &&
	    (flags & (HFCF_RED|HFCF_RIO|HFCF_BLUE|HFCF_SFB)) != HFCF_BLUE &&
	    (flags & (HFCF_RED|HFCF_RIO|HFCF_BLUE|HFCF_SFB)) != HFCF_SFB) {
		log(LOG_ERR, "%s: %s more than one RED|RIO|BLUE|SFB\n",
		    if_name(HFSCIF_IFP(hif)), hfsc_style(hif));
		return (NULL);
	}

	cl = zalloc(hfsc_cl_zone);
	if (cl == NULL)
		return (NULL);

	bzero(cl, hfsc_cl_size);
	TAILQ_INIT(&cl->cl_actc);
	ifq = hif->hif_ifq;
	ifp = HFSCIF_IFP(hif);

	if (qlimit == 0 || qlimit > IFCQ_MAXLEN(ifq)) {
		qlimit = IFCQ_MAXLEN(ifq);
		if (qlimit == 0)
			qlimit = DEFAULT_QLIMIT;  /* use default */
	}
	_qinit(&cl->cl_q, Q_DROPTAIL, qlimit);

	cl->cl_flags = flags;
	if (flags & (HFCF_RED|HFCF_RIO|HFCF_BLUE|HFCF_SFB)) {
#if CLASSQ_RED || CLASSQ_RIO
		int pkttime;
#endif /* CLASSQ_RED || CLASSQ_RIO */
		u_int64_t m2;

		m2 = 0;
		if (rsc != NULL && rsc->m2 > m2)
			m2 = rsc->m2;
		if (fsc != NULL && fsc->m2 > m2)
			m2 = fsc->m2;
		if (usc != NULL && usc->m2 > m2)
			m2 = usc->m2;

		cl->cl_qflags = 0;
		if (flags & HFCF_ECN) {
			if (flags & HFCF_BLUE)
				cl->cl_qflags |= BLUEF_ECN;
			else if (flags & HFCF_SFB)
				cl->cl_qflags |= SFBF_ECN;
			else if (flags & HFCF_RED)
				cl->cl_qflags |= REDF_ECN;
			else if (flags & HFCF_RIO)
				cl->cl_qflags |= RIOF_ECN;
		}
		if (flags & HFCF_FLOWCTL) {
			if (flags & HFCF_SFB)
				cl->cl_qflags |= SFBF_FLOWCTL;
		}
		if (flags & HFCF_CLEARDSCP) {
			if (flags & HFCF_RIO)
				cl->cl_qflags |= RIOF_CLEARDSCP;
		}
#if CLASSQ_RED || CLASSQ_RIO
		/*
		 * XXX: RED & RIO should be watching link speed and MTU
		 *	events and recompute pkttime accordingly.
		 */
		if (m2 < 8)
			pkttime = 1000 * 1000 * 1000; /* 1 sec */
		else
			pkttime = (int64_t)ifp->if_mtu * 1000 * 1000 * 1000 /
			    (m2 / 8);

		/* Test for exclusivity {RED,RIO,BLUE,SFB} was done above */
#if CLASSQ_RED
		if (flags & HFCF_RED) {
			cl->cl_red = red_alloc(ifp, 0, 0,
			    qlimit(&cl->cl_q) * 10/100,
			    qlimit(&cl->cl_q) * 30/100,
			    cl->cl_qflags, pkttime);
			if (cl->cl_red != NULL)
				qtype(&cl->cl_q) = Q_RED;
		}
#endif /* CLASSQ_RED */
#if CLASSQ_RIO
		if (flags & HFCF_RIO) {
			cl->cl_rio =
			    rio_alloc(ifp, 0, NULL, cl->cl_qflags, pkttime);
			if (cl->cl_rio != NULL)
				qtype(&cl->cl_q) = Q_RIO;
		}
#endif /* CLASSQ_RIO */
#endif /* CLASSQ_RED || CLASSQ_RIO */
#if CLASSQ_BLUE
		if (flags & HFCF_BLUE) {
			cl->cl_blue = blue_alloc(ifp, 0, 0, cl->cl_qflags);
			if (cl->cl_blue != NULL)
				qtype(&cl->cl_q) = Q_BLUE;
		}
#endif /* CLASSQ_BLUE */
		if (flags & HFCF_SFB) {
			if (!(cl->cl_flags & HFCF_LAZY))
				cl->cl_sfb = sfb_alloc(ifp, qid,
				    qlimit(&cl->cl_q), cl->cl_qflags);
			if (cl->cl_sfb != NULL || (cl->cl_flags & HFCF_LAZY))
				qtype(&cl->cl_q) = Q_SFB;
		}
	}

	cl->cl_id = hif->hif_classid++;
	cl->cl_handle = qid;
	cl->cl_hif = hif;
	cl->cl_parent = parent;

	eff_rate = ifnet_output_linkrate(HFSCIF_IFP(hif));
	hif->hif_eff_rate = eff_rate;

	if (rsc != NULL && (rsc->m1 != 0 || rsc->m2 != 0) &&
	    (!(rsc->fl & HFSCF_M1_PCT) || (rsc->m1 > 0 && rsc->m1 <= 100)) &&
	    (!(rsc->fl & HFSCF_M2_PCT) || (rsc->m2 > 0 && rsc->m2 <= 100))) {
		rsc->fl &= HFSCF_USERFLAGS;
		cl->cl_flags |= HFCF_RSC;
		cl->cl_rsc0 = *rsc;
		(void) sc2isc(cl, &cl->cl_rsc0, &cl->cl_rsc, eff_rate);
		rtsc_init(&cl->cl_deadline, &cl->cl_rsc, 0, 0);
		rtsc_init(&cl->cl_eligible, &cl->cl_rsc, 0, 0);
	}
	if (fsc != NULL && (fsc->m1 != 0 || fsc->m2 != 0) &&
	    (!(fsc->fl & HFSCF_M1_PCT) || (fsc->m1 > 0 && fsc->m1 <= 100)) &&
	    (!(fsc->fl & HFSCF_M2_PCT) || (fsc->m2 > 0 && fsc->m2 <= 100))) {
		fsc->fl &= HFSCF_USERFLAGS;
		cl->cl_flags |= HFCF_FSC;
		cl->cl_fsc0 = *fsc;
		(void) sc2isc(cl, &cl->cl_fsc0, &cl->cl_fsc, eff_rate);
		rtsc_init(&cl->cl_virtual, &cl->cl_fsc, 0, 0);
	}
	if (usc != NULL && (usc->m1 != 0 || usc->m2 != 0) &&
	    (!(usc->fl & HFSCF_M1_PCT) || (usc->m1 > 0 && usc->m1 <= 100)) &&
	    (!(usc->fl & HFSCF_M2_PCT) || (usc->m2 > 0 && usc->m2 <= 100))) {
		usc->fl &= HFSCF_USERFLAGS;
		cl->cl_flags |= HFCF_USC;
		cl->cl_usc0 = *usc;
		(void) sc2isc(cl, &cl->cl_usc0, &cl->cl_usc, eff_rate);
		rtsc_init(&cl->cl_ulimit, &cl->cl_usc, 0, 0);
	}

	/*
	 * find a free slot in the class table.  if the slot matching
	 * the lower bits of qid is free, use this slot.  otherwise,
	 * use the first free slot.
	 */
	i = qid % hif->hif_maxclasses;
	if (hif->hif_class_tbl[i] == NULL) {
		hif->hif_class_tbl[i] = cl;
	} else {
		for (i = 0; i < hif->hif_maxclasses; i++)
			if (hif->hif_class_tbl[i] == NULL) {
				hif->hif_class_tbl[i] = cl;
				break;
			}
		if (i == hif->hif_maxclasses) {
			goto err_ret;
		}
	}
	hif->hif_classes++;

	if (flags & HFCF_DEFAULTCLASS)
		hif->hif_defaultclass = cl;

	if (parent == NULL) {
		/* this is root class */
		hif->hif_rootclass = cl;
	} else {
		/* add this class to the children list of the parent */
		if ((p = parent->cl_children) == NULL)
			parent->cl_children = cl;
		else {
			while (p->cl_siblings != NULL)
				p = p->cl_siblings;
			p->cl_siblings = cl;
		}
	}

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s created qid=%d pqid=%d qlimit=%d "
		    "flags=%b\n", if_name(ifp), hfsc_style(hif), cl->cl_handle,
		    (cl->cl_parent != NULL) ? cl->cl_parent->cl_handle : 0,
		    qlimit(&cl->cl_q), cl->cl_flags, HFCF_BITS);
		if (cl->cl_flags & HFCF_RSC) {
			hfsc_print_sc(hif, cl->cl_handle, eff_rate,
			    &cl->cl_rsc0, &cl->cl_rsc, "rsc");
		}
		if (cl->cl_flags & HFCF_FSC) {
			hfsc_print_sc(hif, cl->cl_handle, eff_rate,
			    &cl->cl_fsc0, &cl->cl_fsc, "fsc");
		}
		if (cl->cl_flags & HFCF_USC) {
			hfsc_print_sc(hif, cl->cl_handle, eff_rate,
			    &cl->cl_usc0, &cl->cl_usc, "usc");
		}
	}

	return (cl);

err_ret:
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
	zfree(hfsc_cl_zone, cl);
	return (NULL);
}

int
hfsc_remove_queue(struct hfsc_if *hif, u_int32_t qid)
{
	struct hfsc_class *cl;

	IFCQ_LOCK_ASSERT_HELD(hif->hif_ifq);

	if ((cl = hfsc_clh_to_clp(hif, qid)) == NULL)
		return (EINVAL);

	return (hfsc_class_destroy(hif, cl));
}

static int
hfsc_class_destroy(struct hfsc_if *hif, struct hfsc_class *cl)
{
	u_int32_t i;

	if (cl == NULL)
		return (0);

	if (HFSC_IS_A_PARENT_CLASS(cl))
		return (EBUSY);

	IFCQ_LOCK_ASSERT_HELD(hif->hif_ifq);

	if (!qempty(&cl->cl_q))
		hfsc_purgeq(hif, cl, 0, NULL, NULL);

	if (cl->cl_parent == NULL) {
		/* this is root class */
	} else {
		struct hfsc_class *p = cl->cl_parent->cl_children;

		if (p == cl)
			cl->cl_parent->cl_children = cl->cl_siblings;
		else do {
			if (p->cl_siblings == cl) {
				p->cl_siblings = cl->cl_siblings;
				break;
			}
		} while ((p = p->cl_siblings) != NULL);
		VERIFY(p != NULL);
	}

	for (i = 0; i < hif->hif_maxclasses; i++)
		if (hif->hif_class_tbl[i] == cl) {
			hif->hif_class_tbl[i] = NULL;
			break;
		}

	hif->hif_classes--;

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

	if (cl == hif->hif_rootclass)
		hif->hif_rootclass = NULL;
	if (cl == hif->hif_defaultclass)
		hif->hif_defaultclass = NULL;

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s destroyed qid=%d slot=%d\n",
		    if_name(HFSCIF_IFP(hif)), hfsc_style(hif),
		    cl->cl_handle, cl->cl_id);
	}

	zfree(hfsc_cl_zone, cl);

	return (0);
}

/*
 * hfsc_nextclass returns the next class in the tree.
 *   usage:
 *	for (cl = hif->hif_rootclass; cl != NULL; cl = hfsc_nextclass(cl))
 *		do_something;
 */
static struct hfsc_class *
hfsc_nextclass(struct hfsc_class *cl)
{
	IFCQ_LOCK_ASSERT_HELD(cl->cl_hif->hif_ifq);

	if (cl->cl_children != NULL)
		cl = cl->cl_children;
	else if (cl->cl_siblings != NULL)
		cl = cl->cl_siblings;
	else {
		while ((cl = cl->cl_parent) != NULL)
			if (cl->cl_siblings) {
				cl = cl->cl_siblings;
				break;
			}
	}

	return (cl);
}

int
hfsc_enqueue(struct hfsc_if *hif, struct hfsc_class *cl, struct mbuf *m,
    struct pf_mtag *t)
{
	struct ifclassq *ifq = hif->hif_ifq;
	u_int32_t len;
	int ret;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(cl == NULL || cl->cl_hif == hif);

	if (cl == NULL) {
#if PF_ALTQ
		cl = hfsc_clh_to_clp(hif, t->pftag_qid);
#else /* !PF_ALTQ */
		cl = hfsc_clh_to_clp(hif, 0);
#endif /* !PF_ALTQ */
		if (cl == NULL || HFSC_IS_A_PARENT_CLASS(cl)) {
			cl = hif->hif_defaultclass;
			if (cl == NULL) {
				IFCQ_CONVERT_LOCK(ifq);
				m_freem(m);
				return (ENOBUFS);
			}
		}
	}

	len = m_pktlen(m);

	ret = hfsc_addq(cl, m, t);
	if (ret != 0) {
		if (ret == CLASSQEQ_SUCCESS_FC) {
			/* packet enqueued, return advisory feedback */
			ret = EQFULL;
		} else {
			VERIFY(ret == CLASSQEQ_DROPPED ||
			    ret == CLASSQEQ_DROPPED_FC ||
			    ret == CLASSQEQ_DROPPED_SP);
			/* packet has been freed in hfsc_addq */
			PKTCNTR_ADD(&cl->cl_stats.drop_cnt, 1, len);
			IFCQ_DROP_ADD(ifq, 1, len);
			switch (ret) {
			case CLASSQEQ_DROPPED:
				return (ENOBUFS);
			case CLASSQEQ_DROPPED_FC:
				return (EQFULL);
			case CLASSQEQ_DROPPED_SP:
				return (EQSUSPENDED);
			}
			/* NOT_REACHED */
		}
	}
	IFCQ_INC_LEN(ifq);
	cl->cl_hif->hif_packets++;

	/* successfully queued. */
	if (qlen(&cl->cl_q) == 1)
		set_active(cl, len);

	return (ret);
}

/*
 * note: CLASSQDQ_POLL returns the next packet without removing the packet
 *	from the queue.  CLASSQDQ_REMOVE is a normal dequeue operation.
 *	CLASSQDQ_REMOVE must return the same packet if called immediately
 *	after CLASSQDQ_POLL.
 */
struct mbuf *
hfsc_dequeue(struct hfsc_if *hif, cqdq_op_t op)
{
	struct ifclassq *ifq = hif->hif_ifq;
	struct hfsc_class *cl;
	struct mbuf *m;
	u_int32_t len, next_len;
	int realtime = 0;
	u_int64_t cur_time;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (hif->hif_packets == 0)
		/* no packet in the tree */
		return (NULL);

	cur_time = read_machclk();

	if (op == CLASSQDQ_REMOVE && hif->hif_pollcache != NULL) {

		cl = hif->hif_pollcache;
		hif->hif_pollcache = NULL;
		/* check if the class was scheduled by real-time criteria */
		if (cl->cl_flags & HFCF_RSC)
			realtime = (cl->cl_e <= cur_time);
	} else {
		/*
		 * if there are eligible classes, use real-time criteria.
		 * find the class with the minimum deadline among
		 * the eligible classes.
		 */
		if ((cl = ellist_get_mindl(&hif->hif_eligible, cur_time))
		    != NULL) {
			realtime = 1;
		} else {
			int fits = 0;
			/*
			 * use link-sharing criteria
			 * get the class with the minimum vt in the hierarchy
			 */
			cl = hif->hif_rootclass;
			while (HFSC_IS_A_PARENT_CLASS(cl)) {

				cl = actlist_firstfit(cl, cur_time);
				if (cl == NULL) {
					if (fits > 0)
						log(LOG_ERR, "%s: %s "
						    "%d fit but none found\n",
						    if_name(HFSCIF_IFP(hif)),
						    hfsc_style(hif), fits);
					return (NULL);
				}
				/*
				 * update parent's cl_cvtmin.
				 * don't update if the new vt is smaller.
				 */
				if (cl->cl_parent->cl_cvtmin < cl->cl_vt)
					cl->cl_parent->cl_cvtmin = cl->cl_vt;
				fits++;
			}
		}

		if (op == CLASSQDQ_POLL) {
			hif->hif_pollcache = cl;
			m = hfsc_pollq(cl);
			return (m);
		}
	}

	m = hfsc_getq(cl);
	VERIFY(m != NULL);
	len = m_pktlen(m);
	cl->cl_hif->hif_packets--;
	IFCQ_DEC_LEN(ifq);
	IFCQ_XMIT_ADD(ifq, 1, len);
	PKTCNTR_ADD(&cl->cl_stats.xmit_cnt, 1, len);

	update_vf(cl, len, cur_time);
	if (realtime)
		cl->cl_cumul += len;

	if (!qempty(&cl->cl_q)) {
		if (cl->cl_flags & HFCF_RSC) {
			/* update ed */
			next_len = m_pktlen(qhead(&cl->cl_q));

			if (realtime)
				update_ed(cl, next_len);
			else
				update_d(cl, next_len);
		}
	} else {
		/* the class becomes passive */
		set_passive(cl);
	}

	return (m);

}

static int
hfsc_addq(struct hfsc_class *cl, struct mbuf *m, struct pf_mtag *t)
{
	struct ifclassq *ifq = cl->cl_hif->hif_ifq;

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
			struct ifnet *ifp = HFSCIF_IFP(cl->cl_hif);

			VERIFY(cl->cl_flags & HFCF_LAZY);
			IFCQ_CONVERT_LOCK(ifq);

			cl->cl_sfb = sfb_alloc(ifp, cl->cl_handle,
			    qlimit(&cl->cl_q), cl->cl_qflags);
			if (cl->cl_sfb == NULL) {
				/* fall back to droptail */
				qtype(&cl->cl_q) = Q_DROPTAIL;
				cl->cl_flags &= ~HFCF_SFB;
				cl->cl_qflags &= ~(SFBF_ECN | SFBF_FLOWCTL);

				log(LOG_ERR, "%s: %s SFB lazy allocation "
				    "failed for qid=%d slot=%d, falling back "
				    "to DROPTAIL\n", if_name(ifp),
				    hfsc_style(cl->cl_hif), cl->cl_handle,
				    cl->cl_id);
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
	if (cl->cl_flags & HFCF_CLEARDSCP)
		write_dsfield(m, t, 0);
#endif /* PF_ECN */

	_addq(&cl->cl_q, m);

	return (0);
}

static struct mbuf *
hfsc_getq(struct hfsc_class *cl)
{
	IFCQ_LOCK_ASSERT_HELD(cl->cl_hif->hif_ifq);

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

static struct mbuf *
hfsc_pollq(struct hfsc_class *cl)
{
	IFCQ_LOCK_ASSERT_HELD(cl->cl_hif->hif_ifq);

	return (qhead(&cl->cl_q));
}

static void
hfsc_purgeq(struct hfsc_if *hif, struct hfsc_class *cl, u_int32_t flow,
    u_int32_t *packets, u_int32_t *bytes)
{
	struct ifclassq *ifq = hif->hif_ifq;
	u_int32_t cnt = 0, len = 0, qlen;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if ((qlen = qlen(&cl->cl_q)) == 0) {
		VERIFY(hif->hif_packets == 0);
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

		PKTCNTR_ADD(&cl->cl_stats.drop_cnt, cnt, len);
		IFCQ_DROP_ADD(ifq, cnt, len);

		VERIFY(hif->hif_packets >= cnt);
		hif->hif_packets -= cnt;

		VERIFY(((signed)IFCQ_LEN(ifq) - cnt) >= 0);
		IFCQ_LEN(ifq) -= cnt;

		if (qempty(&cl->cl_q)) {
			update_vf(cl, 0, 0);	/* remove cl from the actlist */
			set_passive(cl);
		}

		if (pktsched_verbose) {
			log(LOG_DEBUG, "%s: %s purge qid=%d slot=%d "
			    "qlen=[%d,%d] cnt=%d len=%d flow=0x%x\n",
			    if_name(HFSCIF_IFP(hif)), hfsc_style(hif),
			    cl->cl_handle, cl->cl_id, qlen, qlen(&cl->cl_q),
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
hfsc_print_sc(struct hfsc_if *hif, u_int32_t qid, u_int64_t eff_rate,
    struct service_curve *sc, struct internal_sc *isc, const char *which)
{
	struct ifnet *ifp = HFSCIF_IFP(hif);

	log(LOG_DEBUG, "%s: %s   qid=%d {%s_m1=%llu%s [%llu], "
	    "%s_d=%u msec, %s_m2=%llu%s [%llu]} linkrate=%llu bps\n",
	    if_name(ifp), hfsc_style(hif), qid,
	    which, sc->m1, (sc->fl & HFSCF_M1_PCT) ? "%" : " bps", isc->sm1,
	    which, sc->d,
	    which, sc->m2, (sc->fl & HFSCF_M2_PCT) ? "%" : " bps", isc->sm2,
	    eff_rate);
}

static void
hfsc_updateq_linkrate(struct hfsc_if *hif, struct hfsc_class *cl)
{
	u_int64_t eff_rate = ifnet_output_linkrate(HFSCIF_IFP(hif));
	struct service_curve *sc;
	struct internal_sc *isc;

	/* Update parameters only if rate has changed */
	if (eff_rate == hif->hif_eff_rate)
		return;

	sc = &cl->cl_rsc0;
	isc = &cl->cl_rsc;
	if ((cl->cl_flags & HFCF_RSC) && sc2isc(cl, sc, isc, eff_rate)) {
		rtsc_init(&cl->cl_deadline, isc, 0, 0);
		rtsc_init(&cl->cl_eligible, isc, 0, 0);
		if (pktsched_verbose) {
			hfsc_print_sc(hif, cl->cl_handle, eff_rate,
			    sc, isc, "rsc");
		}
	}
	sc = &cl->cl_fsc0;
	isc = &cl->cl_fsc;
	if ((cl->cl_flags & HFCF_FSC) && sc2isc(cl, sc, isc, eff_rate)) {
		rtsc_init(&cl->cl_virtual, isc, 0, 0);
		if (pktsched_verbose) {
			hfsc_print_sc(hif, cl->cl_handle, eff_rate,
			    sc, isc, "fsc");
		}
	}
	sc = &cl->cl_usc0;
	isc = &cl->cl_usc;
	if ((cl->cl_flags & HFCF_USC) && sc2isc(cl, sc, isc, eff_rate)) {
		rtsc_init(&cl->cl_ulimit, isc, 0, 0);
		if (pktsched_verbose) {
			hfsc_print_sc(hif, cl->cl_handle, eff_rate,
			    sc, isc, "usc");
		}
	}
}

static void
hfsc_updateq(struct hfsc_if *hif, struct hfsc_class *cl, cqev_t ev)
{
	IFCQ_LOCK_ASSERT_HELD(hif->hif_ifq);

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s update qid=%d slot=%d event=%s\n",
		    if_name(HFSCIF_IFP(hif)), hfsc_style(hif),
		    cl->cl_handle, cl->cl_id, ifclassq_ev2str(ev));
	}

	if (ev == CLASSQ_EV_LINK_BANDWIDTH)
		hfsc_updateq_linkrate(hif, cl);

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

static void
set_active(struct hfsc_class *cl, u_int32_t len)
{
	if (cl->cl_flags & HFCF_RSC)
		init_ed(cl, len);
	if (cl->cl_flags & HFCF_FSC)
		init_vf(cl, len);

	cl->cl_stats.period++;
}

static void
set_passive(struct hfsc_class *cl)
{
	if (cl->cl_flags & HFCF_RSC)
		ellist_remove(cl);

	/*
	 * actlist is now handled in update_vf() so that update_vf(cl, 0, 0)
	 * needs to be called explicitly to remove a class from actlist
	 */
}

static void
init_ed(struct hfsc_class *cl, u_int32_t next_len)
{
	u_int64_t cur_time;

	cur_time = read_machclk();

	/* update the deadline curve */
	rtsc_min(&cl->cl_deadline, &cl->cl_rsc, cur_time, cl->cl_cumul);

	/*
	 * update the eligible curve.
	 * for concave, it is equal to the deadline curve.
	 * for convex, it is a linear curve with slope m2.
	 */
	cl->cl_eligible = cl->cl_deadline;
	if (cl->cl_rsc.sm1 <= cl->cl_rsc.sm2) {
		cl->cl_eligible.dx = 0;
		cl->cl_eligible.dy = 0;
	}

	/* compute e and d */
	cl->cl_e = rtsc_y2x(&cl->cl_eligible, cl->cl_cumul);
	cl->cl_d = rtsc_y2x(&cl->cl_deadline, cl->cl_cumul + next_len);

	ellist_insert(cl);
}

static void
update_ed(struct hfsc_class *cl, u_int32_t next_len)
{
	cl->cl_e = rtsc_y2x(&cl->cl_eligible, cl->cl_cumul);
	cl->cl_d = rtsc_y2x(&cl->cl_deadline, cl->cl_cumul + next_len);

	ellist_update(cl);
}

static void
update_d(struct hfsc_class *cl, u_int32_t next_len)
{
	cl->cl_d = rtsc_y2x(&cl->cl_deadline, cl->cl_cumul + next_len);
}

static void
init_vf(struct hfsc_class *cl, u_int32_t len)
{
#pragma unused(len)
	struct hfsc_class *max_cl, *p;
	u_int64_t vt, f, cur_time;
	int go_active;

	cur_time = 0;
	go_active = 1;
	for (; cl->cl_parent != NULL; cl = cl->cl_parent) {

		if (go_active && cl->cl_nactive++ == 0)
			go_active = 1;
		else
			go_active = 0;

		if (go_active) {
			max_cl = actlist_last(&cl->cl_parent->cl_actc);
			if (max_cl != NULL) {
				/*
				 * set vt to the average of the min and max
				 * classes.  if the parent's period didn't
				 * change, don't decrease vt of the class.
				 */
				vt = max_cl->cl_vt;
				if (cl->cl_parent->cl_cvtmin != 0)
					vt = (cl->cl_parent->cl_cvtmin + vt)/2;

				if (cl->cl_parent->cl_vtperiod !=
				    cl->cl_parentperiod || vt > cl->cl_vt)
					cl->cl_vt = vt;
			} else {
				/*
				 * first child for a new parent backlog period.
				 * add parent's cvtmax to vtoff of children
				 * to make a new vt (vtoff + vt) larger than
				 * the vt in the last period for all children.
				 */
				vt = cl->cl_parent->cl_cvtmax;
				for (p = cl->cl_parent->cl_children; p != NULL;
				    p = p->cl_siblings)
					p->cl_vtoff += vt;
				cl->cl_vt = 0;
				cl->cl_parent->cl_cvtmax = 0;
				cl->cl_parent->cl_cvtmin = 0;
			}
			cl->cl_initvt = cl->cl_vt;

			/* update the virtual curve */
			vt = cl->cl_vt + cl->cl_vtoff;
			rtsc_min(&cl->cl_virtual, &cl->cl_fsc,
			    vt, cl->cl_total);
			if (cl->cl_virtual.x == vt) {
				cl->cl_virtual.x -= cl->cl_vtoff;
				cl->cl_vtoff = 0;
			}
			cl->cl_vtadj = 0;

			cl->cl_vtperiod++;  /* increment vt period */
			cl->cl_parentperiod = cl->cl_parent->cl_vtperiod;
			if (cl->cl_parent->cl_nactive == 0)
				cl->cl_parentperiod++;
			cl->cl_f = 0;

			actlist_insert(cl);

			if (cl->cl_flags & HFCF_USC) {
				/* class has upper limit curve */
				if (cur_time == 0)
					cur_time = read_machclk();

				/* update the ulimit curve */
				rtsc_min(&cl->cl_ulimit, &cl->cl_usc, cur_time,
				    cl->cl_total);
				/* compute myf */
				cl->cl_myf = rtsc_y2x(&cl->cl_ulimit,
				    cl->cl_total);
				cl->cl_myfadj = 0;
			}
		}

		if (cl->cl_myf > cl->cl_cfmin)
			f = cl->cl_myf;
		else
			f = cl->cl_cfmin;
		if (f != cl->cl_f) {
			cl->cl_f = f;
			update_cfmin(cl->cl_parent);
		}
	}
}

static void
update_vf(struct hfsc_class *cl, u_int32_t len, u_int64_t cur_time)
{
#pragma unused(cur_time)
#if 0
	u_int64_t myf_bound, delta;
#endif
	u_int64_t f;
	int go_passive;

	go_passive = (qempty(&cl->cl_q) && (cl->cl_flags & HFCF_FSC));

	for (; cl->cl_parent != NULL; cl = cl->cl_parent) {

		cl->cl_total += len;

		if (!(cl->cl_flags & HFCF_FSC) || cl->cl_nactive == 0)
			continue;

		if (go_passive && --cl->cl_nactive == 0)
			go_passive = 1;
		else
			go_passive = 0;

		if (go_passive) {
			/* no more active child, going passive */

			/* update cvtmax of the parent class */
			if (cl->cl_vt > cl->cl_parent->cl_cvtmax)
				cl->cl_parent->cl_cvtmax = cl->cl_vt;

			/* remove this class from the vt list */
			actlist_remove(cl);

			update_cfmin(cl->cl_parent);

			continue;
		}

		/*
		 * update vt and f
		 */
		cl->cl_vt = rtsc_y2x(&cl->cl_virtual, cl->cl_total)
		    - cl->cl_vtoff + cl->cl_vtadj;

		/*
		 * if vt of the class is smaller than cvtmin,
		 * the class was skipped in the past due to non-fit.
		 * if so, we need to adjust vtadj.
		 */
		if (cl->cl_vt < cl->cl_parent->cl_cvtmin) {
			cl->cl_vtadj += cl->cl_parent->cl_cvtmin - cl->cl_vt;
			cl->cl_vt = cl->cl_parent->cl_cvtmin;
		}

		/* update the vt list */
		actlist_update(cl);

		if (cl->cl_flags & HFCF_USC) {
			cl->cl_myf = cl->cl_myfadj +
			    rtsc_y2x(&cl->cl_ulimit, cl->cl_total);
#if 0
			/*
			 * if myf lags behind by more than one clock tick
			 * from the current time, adjust myfadj to prevent
			 * a rate-limited class from going greedy.
			 * in a steady state under rate-limiting, myf
			 * fluctuates within one clock tick.
			 */
			myf_bound = cur_time - machclk_per_tick;
			if (cl->cl_myf < myf_bound) {
				delta = cur_time - cl->cl_myf;
				cl->cl_myfadj += delta;
				cl->cl_myf += delta;
			}
#endif
		}

		/* cl_f is max(cl_myf, cl_cfmin) */
		if (cl->cl_myf > cl->cl_cfmin)
			f = cl->cl_myf;
		else
			f = cl->cl_cfmin;
		if (f != cl->cl_f) {
			cl->cl_f = f;
			update_cfmin(cl->cl_parent);
		}
	}
}

static void
update_cfmin(struct hfsc_class *cl)
{
	struct hfsc_class *p;
	u_int64_t cfmin;

	if (TAILQ_EMPTY(&cl->cl_actc)) {
		cl->cl_cfmin = 0;
		return;
	}
	cfmin = HT_INFINITY;
	TAILQ_FOREACH(p, &cl->cl_actc, cl_actlist) {
		if (p->cl_f == 0) {
			cl->cl_cfmin = 0;
			return;
		}
		if (p->cl_f < cfmin)
			cfmin = p->cl_f;
	}
	cl->cl_cfmin = cfmin;
}

/*
 * TAILQ based ellist and actlist implementation
 * (ion wanted to make a calendar queue based implementation)
 */
/*
 * eligible list holds backlogged classes being sorted by their eligible times.
 * there is one eligible list per interface.
 */

static void
ellist_insert(struct hfsc_class *cl)
{
	struct hfsc_if	*hif = cl->cl_hif;
	struct hfsc_class *p;

	/* check the last entry first */
	if ((p = TAILQ_LAST(&hif->hif_eligible, _eligible)) == NULL ||
	    p->cl_e <= cl->cl_e) {
		TAILQ_INSERT_TAIL(&hif->hif_eligible, cl, cl_ellist);
		return;
	}

	TAILQ_FOREACH(p, &hif->hif_eligible, cl_ellist) {
		if (cl->cl_e < p->cl_e) {
			TAILQ_INSERT_BEFORE(p, cl, cl_ellist);
			return;
		}
	}
	VERIFY(0); /* should not reach here */
}

static void
ellist_remove(struct hfsc_class *cl)
{
	struct hfsc_if	*hif = cl->cl_hif;

	TAILQ_REMOVE(&hif->hif_eligible, cl, cl_ellist);
}

static void
ellist_update(struct hfsc_class *cl)
{
	struct hfsc_if	*hif = cl->cl_hif;
	struct hfsc_class *p, *last;

	/*
	 * the eligible time of a class increases monotonically.
	 * if the next entry has a larger eligible time, nothing to do.
	 */
	p = TAILQ_NEXT(cl, cl_ellist);
	if (p == NULL || cl->cl_e <= p->cl_e)
		return;

	/* check the last entry */
	last = TAILQ_LAST(&hif->hif_eligible, _eligible);
	VERIFY(last != NULL);
	if (last->cl_e <= cl->cl_e) {
		TAILQ_REMOVE(&hif->hif_eligible, cl, cl_ellist);
		TAILQ_INSERT_TAIL(&hif->hif_eligible, cl, cl_ellist);
		return;
	}

	/*
	 * the new position must be between the next entry
	 * and the last entry
	 */
	while ((p = TAILQ_NEXT(p, cl_ellist)) != NULL) {
		if (cl->cl_e < p->cl_e) {
			TAILQ_REMOVE(&hif->hif_eligible, cl, cl_ellist);
			TAILQ_INSERT_BEFORE(p, cl, cl_ellist);
			return;
		}
	}
	VERIFY(0); /* should not reach here */
}

/* find the class with the minimum deadline among the eligible classes */
static struct hfsc_class *
ellist_get_mindl(ellist_t *head, u_int64_t cur_time)
{
	struct hfsc_class *p, *cl = NULL;

	TAILQ_FOREACH(p, head, cl_ellist) {
		if (p->cl_e > cur_time)
			break;
		if (cl == NULL || p->cl_d < cl->cl_d)
			cl = p;
	}
	return (cl);
}

/*
 * active children list holds backlogged child classes being sorted
 * by their virtual time.
 * each intermediate class has one active children list.
 */

static void
actlist_insert(struct hfsc_class *cl)
{
	struct hfsc_class *p;

	/* check the last entry first */
	if ((p = TAILQ_LAST(&cl->cl_parent->cl_actc, _active)) == NULL ||
	    p->cl_vt <= cl->cl_vt) {
		TAILQ_INSERT_TAIL(&cl->cl_parent->cl_actc, cl, cl_actlist);
		return;
	}

	TAILQ_FOREACH(p, &cl->cl_parent->cl_actc, cl_actlist) {
		if (cl->cl_vt < p->cl_vt) {
			TAILQ_INSERT_BEFORE(p, cl, cl_actlist);
			return;
		}
	}
	VERIFY(0); /* should not reach here */
}

static void
actlist_remove(struct hfsc_class *cl)
{
	TAILQ_REMOVE(&cl->cl_parent->cl_actc, cl, cl_actlist);
}

static void
actlist_update(struct hfsc_class *cl)
{
	struct hfsc_class *p, *last;

	/*
	 * the virtual time of a class increases monotonically during its
	 * backlogged period.
	 * if the next entry has a larger virtual time, nothing to do.
	 */
	p = TAILQ_NEXT(cl, cl_actlist);
	if (p == NULL || cl->cl_vt < p->cl_vt)
		return;

	/* check the last entry */
	last = TAILQ_LAST(&cl->cl_parent->cl_actc, _active);
	VERIFY(last != NULL);
	if (last->cl_vt <= cl->cl_vt) {
		TAILQ_REMOVE(&cl->cl_parent->cl_actc, cl, cl_actlist);
		TAILQ_INSERT_TAIL(&cl->cl_parent->cl_actc, cl, cl_actlist);
		return;
	}

	/*
	 * the new position must be between the next entry
	 * and the last entry
	 */
	while ((p = TAILQ_NEXT(p, cl_actlist)) != NULL) {
		if (cl->cl_vt < p->cl_vt) {
			TAILQ_REMOVE(&cl->cl_parent->cl_actc, cl, cl_actlist);
			TAILQ_INSERT_BEFORE(p, cl, cl_actlist);
			return;
		}
	}
	VERIFY(0); /* should not reach here */
}

static struct hfsc_class *
actlist_firstfit(struct hfsc_class *cl, u_int64_t cur_time)
{
	struct hfsc_class *p;

	TAILQ_FOREACH(p, &cl->cl_actc, cl_actlist) {
		if (p->cl_f <= cur_time)
			return (p);
	}
	return (NULL);
}

/*
 * service curve support functions
 *
 *  external service curve parameters
 *	m: bits/sec
 *	d: msec
 *  internal service curve parameters
 *	sm: (bytes/tsc_interval) << SM_SHIFT
 *	ism: (tsc_count/byte) << ISM_SHIFT
 *	dx: tsc_count
 *
 * SM_SHIFT and ISM_SHIFT are scaled in order to keep effective digits.
 * we should be able to handle 100K-1Gbps linkspeed with 200Hz-1GHz CPU
 * speed.  SM_SHIFT and ISM_SHIFT are selected to have at least 3 effective
 * digits in decimal using the following table.
 *
 *  bits/sec    100Kbps     1Mbps     10Mbps     100Mbps    1Gbps
 *  ----------+-------------------------------------------------------
 *  bytes/nsec  12.5e-6    125e-6     1250e-6    12500e-6   125000e-6
 *  sm(500MHz)  25.0e-6    250e-6     2500e-6    25000e-6   250000e-6
 *  sm(200MHz)  62.5e-6    625e-6     6250e-6    62500e-6   625000e-6
 *
 *  nsec/byte   80000      8000       800        80         8
 *  ism(500MHz) 40000      4000       400        40         4
 *  ism(200MHz) 16000      1600       160        16         1.6
 */
#define	SM_SHIFT	24
#define	ISM_SHIFT	10

#define	SM_MASK		((1LL << SM_SHIFT) - 1)
#define	ISM_MASK	((1LL << ISM_SHIFT) - 1)

static inline u_int64_t
seg_x2y(u_int64_t x, u_int64_t sm)
{
	u_int64_t y;

	/*
	 * compute
	 *	y = x * sm >> SM_SHIFT
	 * but divide it for the upper and lower bits to avoid overflow
	 */
	y = (x >> SM_SHIFT) * sm + (((x & SM_MASK) * sm) >> SM_SHIFT);
	return (y);
}

static inline u_int64_t
seg_y2x(u_int64_t y, u_int64_t ism)
{
	u_int64_t x;

	if (y == 0)
		x = 0;
	else if (ism == HT_INFINITY)
		x = HT_INFINITY;
	else {
		x = (y >> ISM_SHIFT) * ism
		    + (((y & ISM_MASK) * ism) >> ISM_SHIFT);
	}
	return (x);
}

static inline u_int64_t
m2sm(u_int64_t m)
{
	u_int64_t sm;

	sm = (m << SM_SHIFT) / 8 / machclk_freq;
	return (sm);
}

static inline u_int64_t
m2ism(u_int64_t m)
{
	u_int64_t ism;

	if (m == 0)
		ism = HT_INFINITY;
	else
		ism = ((u_int64_t)machclk_freq << ISM_SHIFT) * 8 / m;
	return (ism);
}

static inline u_int64_t
d2dx(u_int64_t d)
{
	u_int64_t dx;

	dx = (d * machclk_freq) / 1000;
	return (dx);
}

static u_int64_t
sm2m(u_int64_t sm)
{
	u_int64_t m;

	m = (sm * 8 * machclk_freq) >> SM_SHIFT;
	return (m);
}

static u_int64_t
dx2d(u_int64_t dx)
{
	u_int64_t d;

	d = dx * 1000 / machclk_freq;
	return (d);
}

static boolean_t
sc2isc(struct hfsc_class *cl, struct service_curve *sc, struct internal_sc *isc,
    u_int64_t eff_rate)
{
	struct hfsc_if *hif = cl->cl_hif;
	struct internal_sc oisc = *isc;
	u_int64_t m1, m2;

	if (eff_rate == 0 && (sc->fl & (HFSCF_M1_PCT | HFSCF_M2_PCT))) {
		/*
		 * If service curve is configured with percentage and the
		 * effective uplink rate is not known, assume this is a
		 * transient case, and that the rate will be updated in
		 * the near future via CLASSQ_EV_LINK_SPEED.  Pick a
		 * reasonable number for now, e.g. 10 Mbps.
		 */
		eff_rate = (10 * 1000 * 1000);

		log(LOG_WARNING, "%s: %s qid=%d slot=%d eff_rate unknown; "
		    "using temporary rate %llu bps\n", if_name(HFSCIF_IFP(hif)),
		    hfsc_style(hif), cl->cl_handle, cl->cl_id, eff_rate);
	}

	m1 = sc->m1;
	if (sc->fl & HFSCF_M1_PCT) {
		VERIFY(m1 > 0 && m1 <= 100);
		m1 = (eff_rate * m1) / 100;
	}

	m2 = sc->m2;
	if (sc->fl & HFSCF_M2_PCT) {
		VERIFY(m2 > 0 && m2 <= 100);
		m2 = (eff_rate * m2) / 100;
	}

	isc->sm1 = m2sm(m1);
	isc->ism1 = m2ism(m1);
	isc->dx = d2dx(sc->d);
	isc->dy = seg_x2y(isc->dx, isc->sm1);
	isc->sm2 = m2sm(m2);
	isc->ism2 = m2ism(m2);

	/* return non-zero if there's any change */
	return (bcmp(&oisc, isc, sizeof (*isc)));
}

/*
 * initialize the runtime service curve with the given internal
 * service curve starting at (x, y).
 */
static void
rtsc_init(struct runtime_sc *rtsc, struct internal_sc *isc, u_int64_t x,
    u_int64_t y)
{
	rtsc->x =	x;
	rtsc->y =	y;
	rtsc->sm1 =	isc->sm1;
	rtsc->ism1 =	isc->ism1;
	rtsc->dx =	isc->dx;
	rtsc->dy =	isc->dy;
	rtsc->sm2 =	isc->sm2;
	rtsc->ism2 =	isc->ism2;
}

/*
 * calculate the y-projection of the runtime service curve by the
 * given x-projection value
 */
static u_int64_t
rtsc_y2x(struct runtime_sc *rtsc, u_int64_t y)
{
	u_int64_t	x;

	if (y < rtsc->y)
		x = rtsc->x;
	else if (y <= rtsc->y + rtsc->dy) {
		/* x belongs to the 1st segment */
		if (rtsc->dy == 0)
			x = rtsc->x + rtsc->dx;
		else
			x = rtsc->x + seg_y2x(y - rtsc->y, rtsc->ism1);
	} else {
		/* x belongs to the 2nd segment */
		x = rtsc->x + rtsc->dx
		    + seg_y2x(y - rtsc->y - rtsc->dy, rtsc->ism2);
	}
	return (x);
}

static u_int64_t
rtsc_x2y(struct runtime_sc *rtsc, u_int64_t x)
{
	u_int64_t	y;

	if (x <= rtsc->x)
		y = rtsc->y;
	else if (x <= rtsc->x + rtsc->dx)
		/* y belongs to the 1st segment */
		y = rtsc->y + seg_x2y(x - rtsc->x, rtsc->sm1);
	else
		/* y belongs to the 2nd segment */
		y = rtsc->y + rtsc->dy
		    + seg_x2y(x - rtsc->x - rtsc->dx, rtsc->sm2);
	return (y);
}

/*
 * update the runtime service curve by taking the minimum of the current
 * runtime service curve and the service curve starting at (x, y).
 */
static void
rtsc_min(struct runtime_sc *rtsc, struct internal_sc *isc, u_int64_t x,
    u_int64_t y)
{
	u_int64_t	y1, y2, dx, dy;

	if (isc->sm1 <= isc->sm2) {
		/* service curve is convex */
		y1 = rtsc_x2y(rtsc, x);
		if (y1 < y)
			/* the current rtsc is smaller */
			return;
		rtsc->x = x;
		rtsc->y = y;
		return;
	}

	/*
	 * service curve is concave
	 * compute the two y values of the current rtsc
	 *	y1: at x
	 *	y2: at (x + dx)
	 */
	y1 = rtsc_x2y(rtsc, x);
	if (y1 <= y) {
		/* rtsc is below isc, no change to rtsc */
		return;
	}

	y2 = rtsc_x2y(rtsc, x + isc->dx);
	if (y2 >= y + isc->dy) {
		/* rtsc is above isc, replace rtsc by isc */
		rtsc->x = x;
		rtsc->y = y;
		rtsc->dx = isc->dx;
		rtsc->dy = isc->dy;
		return;
	}

	/*
	 * the two curves intersect
	 * compute the offsets (dx, dy) using the reverse
	 * function of seg_x2y()
	 *	seg_x2y(dx, sm1) == seg_x2y(dx, sm2) + (y1 - y)
	 */
	dx = ((y1 - y) << SM_SHIFT) / (isc->sm1 - isc->sm2);
	/*
	 * check if (x, y1) belongs to the 1st segment of rtsc.
	 * if so, add the offset.
	 */
	if (rtsc->x + rtsc->dx > x)
		dx += rtsc->x + rtsc->dx - x;
	dy = seg_x2y(dx, isc->sm1);

	rtsc->x = x;
	rtsc->y = y;
	rtsc->dx = dx;
	rtsc->dy = dy;
}

int
hfsc_get_class_stats(struct hfsc_if *hif, u_int32_t qid,
    struct hfsc_classstats *sp)
{
	struct hfsc_class *cl;

	IFCQ_LOCK_ASSERT_HELD(hif->hif_ifq);

	if ((cl = hfsc_clh_to_clp(hif, qid)) == NULL)
		return (EINVAL);

	sp->class_id = cl->cl_id;
	sp->class_handle = cl->cl_handle;

	if (cl->cl_flags & HFCF_RSC) {
		sp->rsc.m1 = sm2m(cl->cl_rsc.sm1);
		sp->rsc.d = dx2d(cl->cl_rsc.dx);
		sp->rsc.m2 = sm2m(cl->cl_rsc.sm2);
	} else {
		sp->rsc.m1 = 0;
		sp->rsc.d = 0;
		sp->rsc.m2 = 0;
	}
	if (cl->cl_flags & HFCF_FSC) {
		sp->fsc.m1 = sm2m(cl->cl_fsc.sm1);
		sp->fsc.d = dx2d(cl->cl_fsc.dx);
		sp->fsc.m2 = sm2m(cl->cl_fsc.sm2);
	} else {
		sp->fsc.m1 = 0;
		sp->fsc.d = 0;
		sp->fsc.m2 = 0;
	}
	if (cl->cl_flags & HFCF_USC) {
		sp->usc.m1 = sm2m(cl->cl_usc.sm1);
		sp->usc.d = dx2d(cl->cl_usc.dx);
		sp->usc.m2 = sm2m(cl->cl_usc.sm2);
	} else {
		sp->usc.m1 = 0;
		sp->usc.d = 0;
		sp->usc.m2 = 0;
	}

	sp->total = cl->cl_total;
	sp->cumul = cl->cl_cumul;

	sp->d = cl->cl_d;
	sp->e = cl->cl_e;
	sp->vt = cl->cl_vt;
	sp->f = cl->cl_f;

	sp->initvt = cl->cl_initvt;
	sp->vtperiod = cl->cl_vtperiod;
	sp->parentperiod = cl->cl_parentperiod;
	sp->nactive = cl->cl_nactive;
	sp->vtoff = cl->cl_vtoff;
	sp->cvtmax = cl->cl_cvtmax;
	sp->myf = cl->cl_myf;
	sp->cfmin = cl->cl_cfmin;
	sp->cvtmin = cl->cl_cvtmin;
	sp->myfadj = cl->cl_myfadj;
	sp->vtadj = cl->cl_vtadj;

	sp->cur_time = read_machclk();
	sp->machclk_freq = machclk_freq;

	sp->qlength = qlen(&cl->cl_q);
	sp->qlimit = qlimit(&cl->cl_q);
	sp->xmit_cnt = cl->cl_stats.xmit_cnt;
	sp->drop_cnt = cl->cl_stats.drop_cnt;
	sp->period = cl->cl_stats.period;

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

/* convert a class handle to the corresponding class pointer */
static struct hfsc_class *
hfsc_clh_to_clp(struct hfsc_if *hif, u_int32_t chandle)
{
	u_int32_t i;
	struct hfsc_class *cl;

	IFCQ_LOCK_ASSERT_HELD(hif->hif_ifq);

	/*
	 * first, try optimistically the slot matching the lower bits of
	 * the handle.  if it fails, do the linear table search.
	 */
	i = chandle % hif->hif_maxclasses;
	if ((cl = hif->hif_class_tbl[i]) != NULL && cl->cl_handle == chandle)
		return (cl);
	for (i = 0; i < hif->hif_maxclasses; i++)
		if ((cl = hif->hif_class_tbl[i]) != NULL &&
		    cl->cl_handle == chandle)
			return (cl);
	return (NULL);
}

static const char *
hfsc_style(struct hfsc_if *hif)
{
	return ((hif->hif_flags & HFSCIFF_ALTQ) ? "ALTQ_HFSC" : "HFSC");
}

int
hfsc_setup_ifclassq(struct ifclassq *ifq, u_int32_t flags)
{
#pragma unused(ifq, flags)
	return (ENXIO);		/* not yet */
}

int
hfsc_teardown_ifclassq(struct ifclassq *ifq)
{
	struct hfsc_if *hif = ifq->ifcq_disc;
	int i;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(hif != NULL && ifq->ifcq_type == PKTSCHEDT_HFSC);

	(void) hfsc_destroy_locked(hif);

	ifq->ifcq_disc = NULL;
	for (i = 0; i < IFCQ_SC_MAX; i++) {
		ifq->ifcq_disc_slots[i].qid = 0;
		ifq->ifcq_disc_slots[i].cl = NULL;
	}

	return (ifclassq_detach(ifq));
}

int
hfsc_getqstats_ifclassq(struct ifclassq *ifq, u_int32_t slot,
    struct if_ifclassq_stats *ifqs)
{
	struct hfsc_if *hif = ifq->ifcq_disc;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_type == PKTSCHEDT_HFSC);

	if (slot >= IFCQ_SC_MAX)
		return (EINVAL);

	return (hfsc_get_class_stats(hif, ifq->ifcq_disc_slots[slot].qid,
	    &ifqs->ifqs_hfsc_stats));
}
#endif /* PKTSCHED_HFSC */
