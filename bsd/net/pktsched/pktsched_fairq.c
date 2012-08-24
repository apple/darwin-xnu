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
 * Copyright (c) 2008 The DragonFly Project.  All rights reserved.
 * 
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@backplane.com>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * $DragonFly: src/sys/net/altq/altq_fairq.c,v 1.2 2008/05/14 11:59:23 sephe Exp $
 */
/*
 * Matt: I gutted altq_priq.c and used it as a skeleton on which to build
 * fairq.  The fairq algorithm is completely different then priq, of course,
 * but because I used priq's skeleton I believe I should include priq's
 * copyright.
 *
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
 * FAIRQ - take traffic classified by keep state (hashed into
 *	   pf->pftag_flowhash) and bucketize it.  Fairly extract
 *	   the first packet from each bucket in a round-robin fashion.
 *
 * TODO - better overall qlimit support (right now it is per-bucket).
 *	- NOTE: red etc is per bucket, not overall.
 *	- better service curve support.
 *
 * EXAMPLE:
 *
 *  altq on em0 fairq bandwidth 650Kb queue { std, bulk }
 *  queue std  priority 3 bandwidth 200Kb \
 *	fairq (buckets 64, default, hogs 1Kb) qlimit 50
 *  queue bulk priority 2 bandwidth 100Kb \
 *	fairq (buckets 64, hogs 1Kb) qlimit 50
 *
 *	NOTE: When the aggregate bandwidth is less than the link bandwidth
 *	      any remaining bandwidth is dynamically assigned using the
 *	      existing bandwidth specs as weightings.
 *
 *  pass out on em0 from any to any keep state queue std
 *  pass out on em0 inet proto tcp ..... port ... keep state queue bulk
 */

#if PKTSCHED_FAIRQ

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

#include <net/pktsched/pktsched_fairq.h>
#include <netinet/in.h>

/*
 * function prototypes
 */
#if 0
static int fairq_enqueue_ifclassq(struct ifclassq *, struct mbuf *);
static struct mbuf *fairq_dequeue_ifclassq(struct ifclassq *, cqdq_op_t);
static int fairq_request_ifclassq(struct ifclassq *, cqrq_t, void *);
#endif
static int fairq_clear_interface(struct fairq_if *);
static inline int fairq_addq(struct fairq_class *, struct mbuf *,
    struct pf_mtag *);
static inline struct mbuf *fairq_getq(struct fairq_class *, u_int64_t);
static inline struct mbuf *fairq_pollq(struct fairq_class *, u_int64_t, int *);
static fairq_bucket_t *fairq_selectq(struct fairq_class *, int);
static void fairq_purgeq(struct fairq_if *, struct fairq_class *, u_int32_t,
    u_int32_t *, u_int32_t *);
static void fairq_updateq(struct fairq_if *, struct fairq_class *, cqev_t);
static struct fairq_class *fairq_class_create(struct fairq_if *, int, u_int32_t,
    u_int64_t, u_int32_t, int, u_int64_t, u_int64_t, u_int64_t, u_int64_t,
    u_int32_t);
static int fairq_class_destroy(struct fairq_if *, struct fairq_class *);
static int fairq_destroy_locked(struct fairq_if *);
static inline struct fairq_class *fairq_clh_to_clp(struct fairq_if *,
    u_int32_t);
static const char *fairq_style(struct fairq_if *);

#define	FAIRQ_ZONE_MAX	32		/* maximum elements in zone */
#define	FAIRQ_ZONE_NAME	"pktsched_fairq" /* zone name */

static unsigned int fairq_size;		/* size of zone element */
static struct zone *fairq_zone;		/* zone for fairq */

#define	FAIRQ_CL_ZONE_MAX	32	/* maximum elements in zone */
#define	FAIRQ_CL_ZONE_NAME	"pktsched_fairq_cl" /* zone name */

static unsigned int fairq_cl_size;	/* size of zone element */
static struct zone *fairq_cl_zone;	/* zone for fairq */

void
fairq_init(void)
{
	fairq_size = sizeof (struct fairq_if);
	fairq_zone = zinit(fairq_size, FAIRQ_ZONE_MAX * fairq_size,
	    0, FAIRQ_ZONE_NAME);
	if (fairq_zone == NULL) {
		panic("%s: failed allocating %s", __func__, FAIRQ_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(fairq_zone, Z_EXPAND, TRUE);
	zone_change(fairq_zone, Z_CALLERACCT, TRUE);

	fairq_cl_size = sizeof (struct fairq_class);
	fairq_cl_zone = zinit(fairq_cl_size, FAIRQ_CL_ZONE_MAX * fairq_cl_size,
	    0, FAIRQ_CL_ZONE_NAME);
	if (fairq_cl_zone == NULL) {
		panic("%s: failed allocating %s", __func__, FAIRQ_CL_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(fairq_cl_zone, Z_EXPAND, TRUE);
	zone_change(fairq_cl_zone, Z_CALLERACCT, TRUE);
}

struct fairq_if *
fairq_alloc(struct ifnet *ifp, int how, boolean_t altq)
{
	struct fairq_if *fif;

	fif = (how == M_WAITOK) ?
	    zalloc(fairq_zone) : zalloc_noblock(fairq_zone);
	if (fif == NULL)
		return (NULL);

	bzero(fif, fairq_size);
	fif->fif_maxpri = -1;
	fif->fif_ifq = &ifp->if_snd;
	if (altq)
		fif->fif_flags |= FAIRQIFF_ALTQ;

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s scheduler allocated\n",
		    if_name(ifp), fairq_style(fif));
	}

	return (fif);
}

int
fairq_destroy(struct fairq_if *fif)
{
	struct ifclassq *ifq = fif->fif_ifq;
	int err;

	IFCQ_LOCK(ifq);
	err = fairq_destroy_locked(fif);
	IFCQ_UNLOCK(ifq);

	return (err);
}

static int
fairq_destroy_locked(struct fairq_if *fif)
{
	IFCQ_LOCK_ASSERT_HELD(fif->fif_ifq);

	(void) fairq_clear_interface(fif);

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s scheduler destroyed\n",
		    if_name(FAIRQIF_IFP(fif)), fairq_style(fif));
	}

	zfree(fairq_zone, fif);

	return (0);
}

/*
 * bring the interface back to the initial state by discarding
 * all the filters and classes.
 */
static int
fairq_clear_interface(struct fairq_if *fif)
{
	struct fairq_class *cl;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(fif->fif_ifq);

	/* clear out the classes */
	for (pri = 0; pri <= fif->fif_maxpri; pri++)
		if ((cl = fif->fif_classes[pri]) != NULL)
			fairq_class_destroy(fif, cl);

	return (0);
}

/* discard all the queued packets on the interface */
void
fairq_purge(struct fairq_if *fif)
{
	struct fairq_class *cl;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(fif->fif_ifq);

	for (pri = 0; pri <= fif->fif_maxpri; pri++) {
		if ((cl = fif->fif_classes[pri]) != NULL && cl->cl_head)
			fairq_purgeq(fif, cl, 0, NULL, NULL);
	}
#if !PF_ALTQ
	/*
	 * This assertion is safe to be made only when PF_ALTQ is not
	 * configured; otherwise, IFCQ_LEN represents the sum of the
	 * packets managed by ifcq_disc and altq_disc instances, which
	 * is possible when transitioning between the two.
	 */
	VERIFY(IFCQ_LEN(fif->fif_ifq) == 0);
#endif /* !PF_ALTQ */
}

void
fairq_event(struct fairq_if *fif, cqev_t ev)
{
	struct fairq_class *cl;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(fif->fif_ifq);

	for (pri = 0; pri <= fif->fif_maxpri; pri++)
		if ((cl = fif->fif_classes[pri]) != NULL)
			fairq_updateq(fif, cl, ev);
}

int
fairq_add_queue(struct fairq_if *fif, int priority, u_int32_t qlimit,
    u_int64_t bandwidth, u_int32_t nbuckets, int flags, u_int64_t hogs_m1,
    u_int64_t lssc_m1, u_int64_t lssc_d, u_int64_t lssc_m2, u_int32_t qid,
    struct fairq_class **clp)
{
	struct fairq_class *cl;

	IFCQ_LOCK_ASSERT_HELD(fif->fif_ifq);

	/* check parameters */
	if (priority >= FAIRQ_MAXPRI)
		return (EINVAL);
	if (bandwidth == 0 || (bandwidth / 8) == 0)
		return (EINVAL);
	if (fif->fif_classes[priority] != NULL)
		return (EBUSY);
	if (fairq_clh_to_clp(fif, qid) != NULL)
		return (EBUSY);

	cl = fairq_class_create(fif, priority, qlimit, bandwidth,
	    nbuckets, flags, hogs_m1, lssc_m1, lssc_d, lssc_m2, qid);
	if (cl == NULL)
		return (ENOMEM);

	if (clp != NULL)
		*clp = cl;

	return (0);
}

static struct fairq_class *
fairq_class_create(struct fairq_if *fif, int pri, u_int32_t qlimit,
    u_int64_t bandwidth, u_int32_t nbuckets, int flags, u_int64_t hogs_m1,
    u_int64_t lssc_m1, u_int64_t lssc_d, u_int64_t lssc_m2, u_int32_t qid)
{
#pragma unused(lssc_d, lssc_m2)
	struct ifnet *ifp;
	struct ifclassq *ifq;
	struct fairq_class *cl;
	u_int32_t i;

	IFCQ_LOCK_ASSERT_HELD(fif->fif_ifq);

	/* Sanitize flags unless internally configured */
	if (fif->fif_flags & FAIRQIFF_ALTQ)
		flags &= FARF_USERFLAGS;

#if !CLASSQ_RED
	if (flags & FARF_RED) {
		log(LOG_ERR, "%s: %s RED not available!\n",
		    if_name(FAIRQIF_IFP(fif)), fairq_style(fif));
		return (NULL);
	}
#endif /* !CLASSQ_RED */

#if !CLASSQ_RIO
	if (flags & FARF_RIO) {
		log(LOG_ERR, "%s: %s RIO not available!\n",
		    if_name(FAIRQIF_IFP(fif)), fairq_style(fif));
		return (NULL);
	}
#endif /* CLASSQ_RIO */

#if !CLASSQ_BLUE
	if (flags & FARF_BLUE) {
		log(LOG_ERR, "%s: %s BLUE not available!\n",
		    if_name(FAIRQIF_IFP(fif)), fairq_style(fif));
		return (NULL);
	}
#endif /* CLASSQ_BLUE */

	/* These are mutually exclusive */
	if ((flags & (FARF_RED|FARF_RIO|FARF_BLUE|FARF_SFB)) &&
	    (flags & (FARF_RED|FARF_RIO|FARF_BLUE|FARF_SFB)) != FARF_RED &&
	    (flags & (FARF_RED|FARF_RIO|FARF_BLUE|FARF_SFB)) != FARF_RIO &&
	    (flags & (FARF_RED|FARF_RIO|FARF_BLUE|FARF_SFB)) != FARF_BLUE &&
	    (flags & (FARF_RED|FARF_RIO|FARF_BLUE|FARF_SFB)) != FARF_SFB) {
		log(LOG_ERR, "%s: %s more than one RED|RIO|BLUE|SFB\n",
		    if_name(FAIRQIF_IFP(fif)), fairq_style(fif));
		return (NULL);
	}

	if (bandwidth == 0 || (bandwidth / 8) == 0) {
		log(LOG_ERR, "%s: %s invalid data rate %llu\n",
		    if_name(FAIRQIF_IFP(fif)), fairq_style(fif), bandwidth);
		return (NULL);
	}

	if (nbuckets == 0)
		nbuckets = 256;
	if (nbuckets > FAIRQ_MAX_BUCKETS)
		nbuckets = FAIRQ_MAX_BUCKETS;
	/* enforce power-of-2 size */
	while ((nbuckets ^ (nbuckets - 1)) != ((nbuckets << 1) - 1))
		++nbuckets;

	ifq = fif->fif_ifq;
	ifp = FAIRQIF_IFP(fif);

	if ((cl = fif->fif_classes[pri]) != NULL) {
		/* modify the class instead of creating a new one */
		if (cl->cl_head)
			fairq_purgeq(fif, cl, 0, NULL, NULL);
#if CLASSQ_RIO
		if (cl->cl_qtype == Q_RIO)
			rio_destroy(cl->cl_rio);
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
		if (cl->cl_qtype == Q_RED)
			red_destroy(cl->cl_red);
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
		if (cl->cl_qtype == Q_BLUE)
			blue_destroy(cl->cl_blue);
#endif /* CLASSQ_BLUE */
		if (cl->cl_qtype == Q_SFB && cl->cl_sfb != NULL)
			sfb_destroy(cl->cl_sfb);
		cl->cl_qalg.ptr = NULL;
		cl->cl_qtype = Q_DROPTAIL;
		cl->cl_qstate = QS_RUNNING;
	} else {
		cl = zalloc(fairq_cl_zone);
		if (cl == NULL)
			goto err_ret;
		bzero(cl, fairq_cl_size);
		cl->cl_nbuckets = nbuckets;
		cl->cl_nbucket_mask = nbuckets - 1;

		cl->cl_buckets = _MALLOC(sizeof (struct fairq_bucket) *
		    cl->cl_nbuckets, M_DEVBUF, M_WAITOK|M_ZERO);
		if (cl->cl_buckets == NULL)
			goto err_buckets;
		cl->cl_head = NULL;
	}

	fif->fif_classes[pri] = cl;
	if (flags & FARF_DEFAULTCLASS)
		fif->fif_default = cl;
	if (qlimit == 0 || qlimit > IFCQ_MAXLEN(ifq)) {
		qlimit = IFCQ_MAXLEN(ifq);
		if (qlimit == 0)
			qlimit = DEFAULT_QLIMIT;	/* use default */
	}
	cl->cl_qlimit = qlimit;
	for (i = 0; i < cl->cl_nbuckets; ++i) {
		_qinit(&cl->cl_buckets[i].queue, Q_DROPTAIL, qlimit);
	}
	cl->cl_bandwidth = bandwidth / 8;	/* cvt to bytes per second */
	cl->cl_qtype = Q_DROPTAIL;
	cl->cl_qstate = QS_RUNNING;
	cl->cl_flags = flags;
	cl->cl_pri = pri;
	if (pri > fif->fif_maxpri)
		fif->fif_maxpri = pri;
	cl->cl_fif = fif;
	cl->cl_handle = qid;
	cl->cl_hogs_m1 = hogs_m1 / 8;
	cl->cl_lssc_m1 = lssc_m1 / 8;	/* NOT YET USED */
	cl->cl_bw_current = 0;

	if (flags & (FARF_RED|FARF_RIO|FARF_BLUE|FARF_SFB)) {
#if CLASSQ_RED || CLASSQ_RIO
		u_int64_t ifbandwidth = ifnet_output_linkrate(ifp);
		int pkttime;
#endif /* CLASSQ_RED || CLASSQ_RIO */

		cl->cl_qflags = 0;
		if (flags & FARF_ECN) {
			if (flags & FARF_BLUE)
				cl->cl_qflags |= BLUEF_ECN;
			else if (flags & FARF_SFB)
				cl->cl_qflags |= SFBF_ECN;
			else if (flags & FARF_RED)
				cl->cl_qflags |= REDF_ECN;
			else if (flags & FARF_RIO)
				cl->cl_qflags |= RIOF_ECN;
		}
		if (flags & FARF_FLOWCTL) {
			if (flags & FARF_SFB)
				cl->cl_qflags |= SFBF_FLOWCTL;
		}
		if (flags & FARF_CLEARDSCP) {
			if (flags & FARF_RIO)
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
#if CLASSQ_RIO
		if (flags & FARF_RIO) {
			cl->cl_rio =
			    rio_alloc(ifp, 0, NULL, cl->cl_qflags, pkttime);
			if (cl->cl_rio != NULL)
				cl->cl_qtype = Q_RIO;
		}
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
		if (flags & FARF_RED) {
			cl->cl_red = red_alloc(ifp, 0, 0,
			    cl->cl_qlimit * 10/100,
			    cl->cl_qlimit * 30/100,
			    cl->cl_qflags, pkttime);
			if (cl->cl_red != NULL)
				cl->cl_qtype = Q_RED;
		}
#endif /* CLASSQ_RED */
#endif /* CLASSQ_RED || CLASSQ_RIO */
#if CLASSQ_BLUE
		if (flags & FARF_BLUE) {
			cl->cl_blue = blue_alloc(ifp, 0, 0, cl->cl_qflags);
			if (cl->cl_blue != NULL)
				cl->cl_qtype = Q_BLUE;
		}
#endif /* CLASSQ_BLUE */
		if (flags & FARF_SFB) {
			if (!(cl->cl_flags & FARF_LAZY))
				cl->cl_sfb = sfb_alloc(ifp, cl->cl_handle,
				    cl->cl_qlimit, cl->cl_qflags);
			if (cl->cl_sfb != NULL || (cl->cl_flags & FARF_LAZY))
				cl->cl_qtype = Q_SFB;
		}
	}

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s created qid=%d pri=%d qlimit=%d "
		    "flags=%b\n", if_name(ifp), fairq_style(fif),
		    cl->cl_handle, cl->cl_pri, cl->cl_qlimit, flags, FARF_BITS);
	}

	return (cl);

err_buckets:
	if (cl->cl_buckets != NULL)
		_FREE(cl->cl_buckets, M_DEVBUF);
err_ret:
	if (cl != NULL) {
		if (cl->cl_qalg.ptr != NULL) {
#if CLASSQ_RIO
			if (cl->cl_qtype == Q_RIO)
				rio_destroy(cl->cl_rio);
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
			if (cl->cl_qtype == Q_RED)
				red_destroy(cl->cl_red);
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
			if (cl->cl_qtype == Q_BLUE)
				blue_destroy(cl->cl_blue);
#endif /* CLASSQ_BLUE */
			if (cl->cl_qtype == Q_SFB && cl->cl_sfb != NULL)
				sfb_destroy(cl->cl_sfb);
			cl->cl_qalg.ptr = NULL;
			cl->cl_qtype = Q_DROPTAIL;
			cl->cl_qstate = QS_RUNNING;
		}
		zfree(fairq_cl_zone, cl);
	}
	return (NULL);
}

int
fairq_remove_queue(struct fairq_if *fif, u_int32_t qid)
{
	struct fairq_class *cl;

	IFCQ_LOCK_ASSERT_HELD(fif->fif_ifq);

	if ((cl = fairq_clh_to_clp(fif, qid)) == NULL)
		return (EINVAL);

	return (fairq_class_destroy(fif, cl));
}

static int
fairq_class_destroy(struct fairq_if *fif, struct fairq_class *cl)
{
	struct ifclassq *ifq = fif->fif_ifq;
	int pri;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (cl->cl_head)
		fairq_purgeq(fif, cl, 0, NULL, NULL);

	fif->fif_classes[cl->cl_pri] = NULL;
	if (fif->fif_poll_cache == cl)
		fif->fif_poll_cache = NULL;
	if (fif->fif_maxpri == cl->cl_pri) {
		for (pri = cl->cl_pri; pri >= 0; pri--)
			if (fif->fif_classes[pri] != NULL) {
				fif->fif_maxpri = pri;
				break;
			}
		if (pri < 0)
			fif->fif_maxpri = -1;
	}

	if (cl->cl_qalg.ptr != NULL) {
#if CLASSQ_RIO
		if (cl->cl_qtype == Q_RIO)
			rio_destroy(cl->cl_rio);
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
		if (cl->cl_qtype == Q_RED)
			red_destroy(cl->cl_red);
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
		if (cl->cl_qtype == Q_BLUE)
			blue_destroy(cl->cl_blue);
#endif /* CLASSQ_BLUE */
		if (cl->cl_qtype == Q_SFB && cl->cl_sfb != NULL)
			sfb_destroy(cl->cl_sfb);
		cl->cl_qalg.ptr = NULL;
		cl->cl_qtype = Q_DROPTAIL;
		cl->cl_qstate = QS_RUNNING;
	}

	if (fif->fif_default == cl)
		fif->fif_default = NULL;

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s destroyed qid=%d pri=%d\n",
		    if_name(FAIRQIF_IFP(fif)), fairq_style(fif),
		    cl->cl_handle, cl->cl_pri);
	}

	_FREE(cl->cl_buckets, M_DEVBUF);
	cl->cl_head = NULL;	/* sanity */
	cl->cl_polled = NULL;	/* sanity */
	cl->cl_buckets = NULL;	/* sanity */

	zfree(fairq_cl_zone, cl);

	return (0);
}

int
fairq_enqueue(struct fairq_if *fif, struct fairq_class *cl, struct mbuf *m,
    struct pf_mtag *t)
{
	struct ifclassq *ifq = fif->fif_ifq;
	int len, ret;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(cl == NULL || cl->cl_fif == fif);

	if (cl == NULL) {
		cl = fairq_clh_to_clp(fif, t->pftag_qid);
		if (cl == NULL) {
			cl = fif->fif_default;
			if (cl == NULL) {
				IFCQ_CONVERT_LOCK(ifq);
				m_freem(m);
				return (ENOBUFS);
			}
		}
	}

	cl->cl_flags |= FARF_HAS_PACKETS;
	len = m_pktlen(m);

	ret = fairq_addq(cl, m, t);
	if (ret != 0) {
		if (ret == CLASSQEQ_SUCCESS_FC) {
			/* packet enqueued, return advisory feedback */
			ret = EQFULL;
		} else {
			VERIFY(ret == CLASSQEQ_DROPPED ||
			    ret == CLASSQEQ_DROPPED_FC ||
			    ret == CLASSQEQ_DROPPED_SP);

			/* packet has been freed in fairq_addq */
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
fairq_dequeue(struct fairq_if *fif, cqdq_op_t op)
{
	struct ifclassq *ifq = fif->fif_ifq;
	struct fairq_class *cl;
	struct fairq_class *best_cl;
	struct mbuf *best_m;
	struct mbuf *m;
	u_int64_t cur_time = read_machclk();
	u_int32_t best_scale;
	u_int32_t scale;
	int pri;
	int hit_limit;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	if (IFCQ_IS_EMPTY(ifq)) {
		/* no packet in the queue */
		return (NULL);
	}

	if (fif->fif_poll_cache && op == CLASSQDQ_REMOVE) {
		best_cl = fif->fif_poll_cache;
		m = fairq_getq(best_cl, cur_time);
		fif->fif_poll_cache = NULL;
		if (m != NULL) {
			IFCQ_DEC_LEN(ifq);
			IFCQ_XMIT_ADD(ifq, 1, m_pktlen(m));
			PKTCNTR_ADD(&best_cl->cl_xmitcnt, 1, m_pktlen(m));
		}
	} else {
		best_cl = NULL;
		best_m = NULL;
		best_scale = 0xFFFFFFFFU;

		for (pri = fif->fif_maxpri;  pri >= 0; pri--) {
			if ((cl = fif->fif_classes[pri]) == NULL)
				continue;
			if ((cl->cl_flags & FARF_HAS_PACKETS) == 0)
				continue;
			m = fairq_pollq(cl, cur_time, &hit_limit);
			if (m == NULL) {
				cl->cl_flags &= ~FARF_HAS_PACKETS;
				continue;
			}

			/*
			 * We can halt the search immediately if the queue
			 * did not hit its bandwidth limit.
			 */
			if (hit_limit == 0) {
				best_cl = cl;
				best_m = m;
				break;
			}

			/*
			 * Otherwise calculate the scale factor and select
			 * the queue with the lowest scale factor.  This
			 * apportions any unused bandwidth weighted by
			 * the relative bandwidth specification.
			 */
			scale = cl->cl_bw_current * 100 / cl->cl_bandwidth;
			if (scale < best_scale) {
				best_cl = cl;
				best_m = m;
				best_scale = scale;
			}
		}

		if (op == CLASSQDQ_POLL) {
			fif->fif_poll_cache = best_cl;
			m = best_m;
		} else if (best_cl != NULL) {
			m = fairq_getq(best_cl, cur_time);
			if (m != NULL) {
				IFCQ_DEC_LEN(ifq);
				IFCQ_XMIT_ADD(ifq, 1, m_pktlen(m));
				PKTCNTR_ADD(&best_cl->cl_xmitcnt, 1,
				    m_pktlen(m));
			}
		} else {
			m = NULL;
		}
	}
	return (m);
}

static inline int
fairq_addq(struct fairq_class *cl, struct mbuf *m, struct pf_mtag *t)
{
	struct ifclassq *ifq = cl->cl_fif->fif_ifq;
	fairq_bucket_t *b;
	u_int32_t hash = t->pftag_flowhash;
	u_int32_t hindex;
	u_int64_t bw;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	/*
	 * If the packet doesn't have any keep state put it on the end of
	 * our queue.  XXX this can result in out of order delivery.
	 */
	if (hash == 0) {
		if (cl->cl_head)
			b = cl->cl_head->prev;
		else
			b = &cl->cl_buckets[0];
	} else {
		hindex = (hash & cl->cl_nbucket_mask);
		b = &cl->cl_buckets[hindex];
	}

	/*
	 * Add the bucket to the end of the circular list of active buckets.
	 *
	 * As a special case we add the bucket to the beginning of the list
	 * instead of the end if it was not previously on the list and if
	 * its traffic is less then the hog level.
	 */
	if (b->in_use == 0) {
		b->in_use = 1;
		if (cl->cl_head == NULL) {
			cl->cl_head = b;
			b->next = b;
			b->prev = b;
		} else {
			b->next = cl->cl_head;
			b->prev = cl->cl_head->prev;
			b->prev->next = b;
			b->next->prev = b;

			if (b->bw_delta && cl->cl_hogs_m1) {
				bw = b->bw_bytes * machclk_freq / b->bw_delta;
				if (bw < cl->cl_hogs_m1)
					cl->cl_head = b;
			}
		}
	}

#if CLASSQ_RIO
	if (cl->cl_qtype == Q_RIO)
		return (rio_addq(cl->cl_rio, &b->queue, m, t));
	else
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
	if (cl->cl_qtype == Q_RED)
		return (red_addq(cl->cl_red, &b->queue, m, t));
	else
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
	if (cl->cl_qtype == Q_BLUE)
		return (blue_addq(cl->cl_blue, &b->queue, m, t));
	else
#endif /* CLASSQ_BLUE */
	if (cl->cl_qtype == Q_SFB) {
		if (cl->cl_sfb == NULL) {
			struct ifnet *ifp = FAIRQIF_IFP(cl->cl_fif);

			VERIFY(cl->cl_flags & FARF_LAZY);
			IFCQ_CONVERT_LOCK(ifq);

			cl->cl_sfb = sfb_alloc(ifp, cl->cl_handle,
			    cl->cl_qlimit, cl->cl_qflags);
			if (cl->cl_sfb == NULL) {
				/* fall back to droptail */
				cl->cl_qtype = Q_DROPTAIL;
				cl->cl_flags &= ~FARF_SFB;
				cl->cl_qflags &= ~(SFBF_ECN | SFBF_FLOWCTL);

				log(LOG_ERR, "%s: %s SFB lazy allocation "
				    "failed for qid=%d pri=%d, falling back "
				    "to DROPTAIL\n", if_name(ifp),
				    fairq_style(cl->cl_fif), cl->cl_handle,
				    cl->cl_pri);
			}
		}
		if (cl->cl_sfb != NULL)
			return (sfb_addq(cl->cl_sfb, &b->queue, m, t));
	} else if (qlen(&b->queue) >= qlimit(&b->queue)) {
		IFCQ_CONVERT_LOCK(ifq);
		m_freem(m);
		return (CLASSQEQ_DROPPED);
	}

	if (cl->cl_flags & FARF_CLEARDSCP)
		write_dsfield(m, t, 0);

	_addq(&b->queue, m);

	return (0);
}

static inline struct mbuf *
fairq_getq(struct fairq_class *cl, u_int64_t cur_time)
{
	fairq_bucket_t *b;
	struct mbuf *m;

	IFCQ_LOCK_ASSERT_HELD(cl->cl_fif->fif_ifq);

	b = fairq_selectq(cl, 0);
	if (b == NULL)
		m = NULL;
#if CLASSQ_RIO
	else if (cl->cl_qtype == Q_RIO)
		m = rio_getq(cl->cl_rio, &b->queue);
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
	else if (cl->cl_qtype == Q_RED)
		m = red_getq(cl->cl_red, &b->queue);
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
	else if (cl->cl_qtype == Q_BLUE)
		m = blue_getq(cl->cl_blue, &b->queue);
#endif /* CLASSQ_BLUE */
	else if (cl->cl_qtype == Q_SFB && cl->cl_sfb != NULL)
		m = sfb_getq(cl->cl_sfb, &b->queue);
	else
		m = _getq(&b->queue);

	/*
	 * Calculate the BW change
	 */
	if (m != NULL) {
		u_int64_t delta;

		/*
		 * Per-class bandwidth calculation
		 */
		delta = (cur_time - cl->cl_last_time);
		if (delta > machclk_freq * 8)
			delta = machclk_freq * 8;
		cl->cl_bw_delta += delta;
		cl->cl_bw_bytes += m->m_pkthdr.len;
		cl->cl_last_time = cur_time;
		if (cl->cl_bw_delta > machclk_freq) {
			cl->cl_bw_delta -= cl->cl_bw_delta >> 2;
			cl->cl_bw_bytes -= cl->cl_bw_bytes >> 2;
		}

		/*
		 * Per-bucket bandwidth calculation
		 */
		delta = (cur_time - b->last_time);
		if (delta > machclk_freq * 8)
			delta = machclk_freq * 8;
		b->bw_delta += delta;
		b->bw_bytes += m->m_pkthdr.len;
		b->last_time = cur_time;
		if (b->bw_delta > machclk_freq) {
			b->bw_delta -= b->bw_delta >> 2;
			b->bw_bytes -= b->bw_bytes >> 2;
		}
	}
	return (m);
}

/*
 * Figure out what the next packet would be if there were no limits.  If
 * this class hits its bandwidth limit *hit_limit is set to no-zero, otherwise
 * it is set to 0.  A non-NULL mbuf is returned either way.
 */
static inline struct mbuf *
fairq_pollq(struct fairq_class *cl, u_int64_t cur_time, int *hit_limit)
{
	fairq_bucket_t *b;
	struct mbuf *m;
	u_int64_t delta;
	u_int64_t bw;

	IFCQ_LOCK_ASSERT_HELD(cl->cl_fif->fif_ifq);

	*hit_limit = 0;
	b = fairq_selectq(cl, 1);
	if (b == NULL)
		return (NULL);
	m = qhead(&b->queue);

	/*
	 * Did this packet exceed the class bandwidth?  Calculate the
	 * bandwidth component of the packet.
	 *
	 * - Calculate bytes per second
	 */
	delta = cur_time - cl->cl_last_time;
	if (delta > machclk_freq * 8)
		delta = machclk_freq * 8;
	cl->cl_bw_delta += delta;
	cl->cl_last_time = cur_time;
	if (cl->cl_bw_delta) {
		bw = cl->cl_bw_bytes * machclk_freq / cl->cl_bw_delta;

		if (bw > cl->cl_bandwidth)
			*hit_limit = 1;
		cl->cl_bw_current = bw;
#if 0
		printf("BW %6lld relative to %6u %d queue %p\n",
		    bw, cl->cl_bandwidth, *hit_limit, b);
#endif
	}
	return (m);
}

/*
 * Locate the next queue we want to pull a packet out of.  This code
 * is also responsible for removing empty buckets from the circular list.
 */
static fairq_bucket_t *
fairq_selectq(struct fairq_class *cl, int ispoll)
{
	fairq_bucket_t *b;
	u_int64_t bw;

	IFCQ_LOCK_ASSERT_HELD(cl->cl_fif->fif_ifq);

	if (ispoll == 0 && cl->cl_polled) {
		b = cl->cl_polled;
		cl->cl_polled = NULL;
		return (b);
	}

	while ((b = cl->cl_head) != NULL) {
		/*
		 * Remove empty queues from consideration
		 */
		if (qempty(&b->queue)) {
			b->in_use = 0;
			cl->cl_head = b->next;
			if (cl->cl_head == b) {
				cl->cl_head = NULL;
			} else {
				b->next->prev = b->prev;
				b->prev->next = b->next;
			}
			continue;
		}

		/*
		 * Advance the round robin.  Queues with bandwidths less
		 * then the hog bandwidth are allowed to burst.
		 */
		if (cl->cl_hogs_m1 == 0) {
			cl->cl_head = b->next;
		} else if (b->bw_delta) {
			bw = b->bw_bytes * machclk_freq / b->bw_delta;
			if (bw >= cl->cl_hogs_m1) {
				cl->cl_head = b->next;
			}
			/*
			 * XXX TODO -
			 */
		}

		/*
		 * Return bucket b.
		 */
		break;
	}
	if (ispoll)
		cl->cl_polled = b;
	return (b);
}

static void
fairq_purgeq(struct fairq_if *fif, struct fairq_class *cl, u_int32_t flow,
    u_int32_t *packets, u_int32_t *bytes)
{
	struct ifclassq *ifq = fif->fif_ifq;
	u_int32_t _cnt = 0, _len = 0;
	fairq_bucket_t *b;

	IFCQ_LOCK_ASSERT_HELD(ifq);

	/* become regular mutex before freeing mbufs */
	IFCQ_CONVERT_LOCK(ifq);

	while ((b = fairq_selectq(cl, 0)) != NULL) {
		u_int32_t cnt, len, qlen;

		if ((qlen = qlen(&b->queue)) == 0)
			continue;

#if CLASSQ_RIO
		if (cl->cl_qtype == Q_RIO)
			rio_purgeq(cl->cl_rio, &b->queue, flow, &cnt, &len);
		else
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
		if (cl->cl_qtype == Q_RED)
			red_purgeq(cl->cl_red, &b->queue, flow, &cnt, &len);
		else
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
		if (cl->cl_qtype == Q_BLUE)
			blue_purgeq(cl->cl_blue, &b->queue, flow, &cnt, &len);
		else
#endif /* CLASSQ_BLUE */
		if (cl->cl_qtype == Q_SFB && cl->cl_sfb != NULL)
			sfb_purgeq(cl->cl_sfb, &b->queue, flow, &cnt, &len);
		else
			_flushq_flow(&b->queue, flow, &cnt, &len);

		if (cnt == 0)
			continue;

		VERIFY(qlen(&b->queue) == (qlen - cnt));

		PKTCNTR_ADD(&cl->cl_dropcnt, cnt, len);
		IFCQ_DROP_ADD(ifq, cnt, len);

		VERIFY(((signed)IFCQ_LEN(ifq) - cnt) >= 0);
		IFCQ_LEN(ifq) -= cnt;

		_cnt += cnt;
		_len += len;

		if (pktsched_verbose) {
			log(LOG_DEBUG, "%s: %s purge qid=%d pri=%d "
			    "qlen=[%d,%d] cnt=%d len=%d flow=0x%x\n",
			    if_name(FAIRQIF_IFP(fif)), fairq_style(fif),
			    cl->cl_handle, cl->cl_pri, qlen, qlen(&b->queue),
			    cnt, len, flow);
		}
	}

	if (packets != NULL)
		*packets = _cnt;
	if (bytes != NULL)
		*bytes = _len;
}

static void
fairq_updateq(struct fairq_if *fif, struct fairq_class *cl, cqev_t ev)
{
	IFCQ_LOCK_ASSERT_HELD(fif->fif_ifq);

	if (pktsched_verbose) {
		log(LOG_DEBUG, "%s: %s update qid=%d pri=%d event=%s\n",
		    if_name(FAIRQIF_IFP(fif)), fairq_style(fif),
		    cl->cl_handle, cl->cl_pri, ifclassq_ev2str(ev));
	}

#if CLASSQ_RIO
	if (cl->cl_qtype == Q_RIO)
		return (rio_updateq(cl->cl_rio, ev));
#endif /* CLASSQ_RIO */
#if CLASSQ_RED
	if (cl->cl_qtype == Q_RED)
		return (red_updateq(cl->cl_red, ev));
#endif /* CLASSQ_RED */
#if CLASSQ_BLUE
	if (cl->cl_qtype == Q_BLUE)
		return (blue_updateq(cl->cl_blue, ev));
#endif /* CLASSQ_BLUE */
	if (cl->cl_qtype == Q_SFB && cl->cl_sfb != NULL)
		return (sfb_updateq(cl->cl_sfb, ev));
}

int
fairq_get_class_stats(struct fairq_if *fif, u_int32_t qid,
    struct fairq_classstats *sp)
{
	struct fairq_class *cl;
	fairq_bucket_t *b;

	IFCQ_LOCK_ASSERT_HELD(fif->fif_ifq);

	if ((cl = fairq_clh_to_clp(fif, qid)) == NULL)
		return (EINVAL);

	sp->class_handle = cl->cl_handle;
	sp->priority = cl->cl_pri;
	sp->qlimit = cl->cl_qlimit;
	sp->xmit_cnt = cl->cl_xmitcnt;
	sp->drop_cnt = cl->cl_dropcnt;
	sp->qtype = cl->cl_qtype;
	sp->qstate = cl->cl_qstate;
	sp->qlength = 0;

	if (cl->cl_head) {
		b = cl->cl_head;
		do {
			sp->qlength += qlen(&b->queue);
			b = b->next;
		} while (b != cl->cl_head);
	}

#if CLASSQ_RED
	if (cl->cl_qtype == Q_RED)
		red_getstats(cl->cl_red, &sp->red[0]);
#endif /* CLASSQ_RED */
#if CLASSQ_RIO
	if (cl->cl_qtype == Q_RIO)
		rio_getstats(cl->cl_rio, &sp->red[0]);
#endif /* CLASSQ_RIO */
#if CLASSQ_BLUE
	if (cl->cl_qtype == Q_BLUE)
		blue_getstats(cl->cl_blue, &sp->blue);
#endif /* CLASSQ_BLUE */
	if (cl->cl_qtype == Q_SFB && cl->cl_sfb != NULL)
		sfb_getstats(cl->cl_sfb, &sp->sfb);

	return (0);
}

/* convert a class handle to the corresponding class pointer */
static inline struct fairq_class *
fairq_clh_to_clp(struct fairq_if *fif, u_int32_t chandle)
{
	struct fairq_class *cl;
	int idx;

	IFCQ_LOCK_ASSERT_HELD(fif->fif_ifq);

	for (idx = fif->fif_maxpri; idx >= 0; idx--)
		if ((cl = fif->fif_classes[idx]) != NULL &&
		    cl->cl_handle == chandle)
			return (cl);

	return (NULL);
}

static const char *
fairq_style(struct fairq_if *fif)
{
	return ((fif->fif_flags & FAIRQIFF_ALTQ) ? "ALTQ_FAIRQ" : "FAIRQ");
}

int
fairq_setup_ifclassq(struct ifclassq *ifq, u_int32_t flags)
{
#pragma unused(ifq, flags)
	return (ENXIO);		/* not yet */
}

int
fairq_teardown_ifclassq(struct ifclassq *ifq)
{
	struct fairq_if *fif = ifq->ifcq_disc;
	int i;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(fif != NULL && ifq->ifcq_type == PKTSCHEDT_FAIRQ);

	(void) fairq_destroy_locked(fif);

	ifq->ifcq_disc = NULL;
	for (i = 0; i < IFCQ_SC_MAX; i++) {
		ifq->ifcq_disc_slots[i].qid = 0;
		ifq->ifcq_disc_slots[i].cl = NULL;
	}

	return (ifclassq_detach(ifq));
}

int
fairq_getqstats_ifclassq(struct ifclassq *ifq, u_int32_t slot,
    struct if_ifclassq_stats *ifqs)
{
	struct fairq_if *fif = ifq->ifcq_disc;

	IFCQ_LOCK_ASSERT_HELD(ifq);
	VERIFY(ifq->ifcq_type == PKTSCHEDT_FAIRQ);

	if (slot >= IFCQ_SC_MAX)
		return (EINVAL);

	return (fairq_get_class_stats(fif, ifq->ifcq_disc_slots[slot].qid,
	    &ifqs->ifqs_fairq_stats));
}
#endif /* PKTSCHED_FAIRQ */
