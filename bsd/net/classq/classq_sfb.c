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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/malloc.h>
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

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/dlil.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if INET6
#include <netinet/ip6.h>
#endif

#include <net/classq/classq_sfb.h>
#include <net/flowhash.h>
#include <net/net_osdep.h>

/*
 * Stochastic Fair Blue
 *
 * Wu-chang Feng, Dilip D. Kandlur, Debanjan Saha, Kang G. Shin
 * http://www.thefengs.com/wuchang/blue/CSE-TR-387-99.pdf
 *
 * Based on the NS code with the following parameters:
 *
 *   bytes:	false
 *   decrement:	0.001
 *   increment:	0.005
 *   hold-time:	10ms-50ms (randomized)
 *   algorithm:	0
 *   pbox:	1
 *   pbox-time:	50-100ms (randomized)
 *   hinterval:	11-23 (randomized)
 *
 * This implementation uses L = 2 and N = 32 for 2 sets of:
 *
 *	B[L][N]: L x N array of bins (L levels, N bins per level)
 *
 * Each set effectively creates 32^2 virtual buckets (bin combinations)
 * while using only O(32*2) states.
 *
 * Given a 32-bit hash value, we divide it such that octets [0,1,2,3] are
 * used as index for the bins across the 2 levels, where level 1 uses [0,2]
 * and level 2 uses [1,3].  The 2 values per level correspond to the indices
 * for the current and warm-up sets (section 4.4. in the SFB paper regarding
 * Moving Hash Functions explains the purposes of these 2 sets.)
 */

/*
 * Use Murmur3A_x86_32 for hash function.  It seems to perform consistently
 * across platforms for 1-word key (32-bit flowhash value).  See flowhash.h
 * for other alternatives.  We only need 16-bit hash output.
 */
#define	SFB_HASH	net_flowhash_mh3_x86_32
#define	SFB_HASHMASK	HASHMASK(16)

#define	SFB_BINMASK(_x) \
	((_x) & HASHMASK(SFB_BINS_SHIFT))

#define	SFB_BINST(_sp, _l, _n, _c) \
	(&(*(_sp)->sfb_bins)[_c].stats[_l][_n])

#define	SFB_BINFT(_sp, _l, _n, _c) \
	(&(*(_sp)->sfb_bins)[_c].freezetime[_l][_n])

#define	SFB_FC_LIST(_sp, _n) \
	(&(*(_sp)->sfb_fc_lists)[_n])

/*
 * The holdtime parameter determines the minimum time interval between
 * two successive updates of the marking probability.  In the event the
 * uplink speed is not known, a default value is chosen and is randomized
 * to be within the following range.
 */
#define	HOLDTIME_BASE	(100ULL * 1000 * 1000)	/* 100ms */
#define	HOLDTIME_MIN	(10ULL * 1000 * 1000)	/* 10ms */
#define	HOLDTIME_MAX	(100ULL * 1000 * 1000)	/* 100ms */

/*
 * The pboxtime parameter determines the bandwidth allocated for rogue
 * flows, i.e. the rate limiting bandwidth.  In the event the uplink speed
 * is not known, a default value is chosen and is randomized to be within
 * the following range.
 */
#define	PBOXTIME_BASE	(300ULL * 1000 * 1000)	/* 300ms */
#define	PBOXTIME_MIN	(30ULL * 1000 * 1000)	/* 30ms */
#define	PBOXTIME_MAX	(300ULL * 1000 * 1000)	/* 300ms */

#define	SFB_RANDOM(sp, tmin, tmax)	((sfb_random(sp) % (tmax)) + (tmin))

#define	SFB_PKT_PBOX PF_TAG_QUEUE1	/* in penalty box */

/* The following mantissa values are in SFB_FP_SHIFT Q format */
#define	SFB_MAX_PMARK	(1 << SFB_FP_SHIFT) /* Q14 representation of 1.00 */

/*
 * These are d1 (increment) and d2 (decrement) parameters, used to determine
 * the amount by which the marking probability is incremented when the queue
 * overflows, or is decremented when the link is idle.  d1 is set higher than
 * d2, because link underutilization can occur when congestion management is
 * either too conservative or too aggressive, but packet loss occurs only
 * when congestion management is too conservative.  By weighing heavily
 * against packet loss, it can quickly reach to a substantial increase in
 * traffic load.
 */
#define	SFB_INCREMENT	82		/* Q14 representation of 0.005 */
#define	SFB_DECREMENT	16		/* Q14 representation of 0.001 */

#define	SFB_PMARK_TH	16056		/* Q14 representation of 0.98 */
#define	SFB_PMARK_WARM	3276		/* Q14 representation of 0.2 */

#define	SFB_PMARK_INC(_bin) do {					\
	(_bin)->pmark += sfb_increment;					\
	if ((_bin)->pmark > SFB_MAX_PMARK)				\
		(_bin)->pmark = SFB_MAX_PMARK;				\
} while (0)

#define	SFB_PMARK_DEC(_bin) do {					\
	if ((_bin)->pmark > 0) {					\
		(_bin)->pmark -= sfb_decrement;				\
		if ((_bin)->pmark < 0)					\
			(_bin)->pmark = 0;				\
	}								\
} while (0)

#define	HINTERVAL_MIN	(10)	/* 10 seconds */
#define	HINTERVAL_MAX	(20)	/* 20 seconds */
#define	SFB_HINTERVAL(sp) ((sfb_random(sp) % HINTERVAL_MAX) + HINTERVAL_MIN)

#define	DEQUEUE_DECAY	7		/* ilog2 of EWMA decay rate, (128) */
#define	DEQUEUE_SPIKE(_new, _old)	\
	((u_int64_t)ABS((int64_t)(_new) - (int64_t)(_old)) > ((_old) << 11))

#define	ABS(v)  (((v) > 0) ? (v) : -(v))

#define	SFB_ZONE_MAX	32		/* maximum elements in zone */
#define	SFB_ZONE_NAME	"classq_sfb"	/* zone name */

/* Place the flow control entries in current bin on level 0 */
#define	SFB_FC_LEVEL	0

static unsigned int sfb_size;		/* size of zone element */
static struct zone *sfb_zone;		/* zone for sfb */

/* internal function prototypes */
static u_int32_t sfb_random(struct sfb *);
static struct mbuf *sfb_getq_flow(struct sfb *, class_queue_t *, u_int32_t,
    boolean_t);
static void sfb_resetq(struct sfb *, cqev_t);
static void sfb_calc_holdtime(struct sfb *, u_int64_t);
static void sfb_calc_pboxtime(struct sfb *, u_int64_t);
static void sfb_calc_hinterval(struct sfb *, u_int64_t *);
static void sfb_swap_bins(struct sfb *, u_int32_t);
static inline int sfb_pcheck(struct sfb *, struct pf_mtag *);
static int sfb_penalize(struct sfb *, struct pf_mtag *, struct timespec *);
static void sfb_adjust_bin(struct sfb *, struct sfbbinstats *,
    struct timespec *, struct timespec *, boolean_t);
static void sfb_decrement_bin(struct sfb *, struct sfbbinstats *,
    struct timespec *, struct timespec *);
static void sfb_increment_bin(struct sfb *, struct sfbbinstats *,
    struct timespec *, struct timespec *);
static inline void sfb_dq_update_bins(struct sfb *, struct pf_mtag *,
    struct timespec *);
static inline void sfb_eq_update_bins(struct sfb *, struct pf_mtag *);
static int sfb_drop_early(struct sfb *, struct pf_mtag *, u_int16_t *,
    struct timespec *);
static boolean_t sfb_bin_addfcentry(struct sfb *, struct pf_mtag *);
static void sfb_fclist_append(struct sfb *, struct sfb_fc_list *);
static void sfb_fclists_clean(struct sfb *sp);

SYSCTL_NODE(_net_classq, OID_AUTO, sfb, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "SFB");

static u_int64_t sfb_holdtime = 0;	/* 0 indicates "automatic" */
SYSCTL_QUAD(_net_classq_sfb, OID_AUTO, holdtime, CTLFLAG_RW|CTLFLAG_LOCKED,
    &sfb_holdtime, "SFB freeze time in nanoseconds");

static u_int64_t sfb_pboxtime = 0;	/* 0 indicates "automatic" */
SYSCTL_QUAD(_net_classq_sfb, OID_AUTO, pboxtime, CTLFLAG_RW|CTLFLAG_LOCKED,
    &sfb_pboxtime, "SFB penalty box time in nanoseconds");

static u_int64_t sfb_hinterval;
SYSCTL_QUAD(_net_classq_sfb, OID_AUTO, hinterval, CTLFLAG_RW|CTLFLAG_LOCKED,
    &sfb_hinterval, "SFB hash interval in nanoseconds");

static u_int32_t sfb_increment = SFB_INCREMENT;
SYSCTL_UINT(_net_classq_sfb, OID_AUTO, increment, CTLFLAG_RW|CTLFLAG_LOCKED,
    &sfb_increment, SFB_INCREMENT, "SFB increment [d1]");

static u_int32_t sfb_decrement = SFB_DECREMENT;
SYSCTL_UINT(_net_classq_sfb, OID_AUTO, decrement, CTLFLAG_RW|CTLFLAG_LOCKED,
    &sfb_decrement, SFB_DECREMENT, "SFB decrement [d2]");

static u_int32_t sfb_allocation = 0;	/* 0 means "automatic" */
SYSCTL_UINT(_net_classq_sfb, OID_AUTO, allocation, CTLFLAG_RW|CTLFLAG_LOCKED,
    &sfb_allocation, 0, "SFB bin allocation");

static u_int32_t sfb_ratelimit = 0;
SYSCTL_UINT(_net_classq_sfb, OID_AUTO, ratelimit, CTLFLAG_RW|CTLFLAG_LOCKED,
	&sfb_ratelimit, 0, "SFB rate limit");

#define	MBPS	(1ULL * 1000 * 1000)
#define	GBPS	(MBPS * 1000)

struct sfb_time_tbl {
	u_int64_t	speed;		/* uplink speed */
	u_int64_t	holdtime;	/* hold time */
	u_int64_t	pboxtime;	/* penalty box time */
};

static struct sfb_time_tbl sfb_ttbl[] = {
	{   1 * MBPS,	HOLDTIME_BASE * 1000,	PBOXTIME_BASE * 1000	},
	{  10 * MBPS,	HOLDTIME_BASE * 100,	PBOXTIME_BASE * 100	},
	{ 100 * MBPS,	HOLDTIME_BASE * 10,	PBOXTIME_BASE * 10	},
	{   1 * GBPS,	HOLDTIME_BASE,		PBOXTIME_BASE		},
	{  10 * GBPS,	HOLDTIME_BASE / 10,	PBOXTIME_BASE / 10	},
	{ 100 * GBPS,	HOLDTIME_BASE / 100,	PBOXTIME_BASE / 100	},
	{ 0, 0, 0 }
};

void
sfb_init(void)
{
	_CASSERT(SFBF_ECN4 == CLASSQF_ECN4);
	_CASSERT(SFBF_ECN6 == CLASSQF_ECN6);

	sfb_size = sizeof (struct sfb);
	sfb_zone = zinit(sfb_size, SFB_ZONE_MAX * sfb_size,
	    0, SFB_ZONE_NAME);
	if (sfb_zone == NULL) {
		panic("%s: failed allocating %s", __func__, SFB_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(sfb_zone, Z_EXPAND, TRUE);
	zone_change(sfb_zone, Z_CALLERACCT, TRUE);
}

static u_int32_t
sfb_random(struct sfb *sp)
{
	IFCQ_CONVERT_LOCK(&sp->sfb_ifp->if_snd);
	return (random());
}

static void
sfb_calc_holdtime(struct sfb *sp, u_int64_t outbw)
{
	u_int64_t holdtime;

	if (sfb_holdtime != 0) {
		holdtime = sfb_holdtime;
	} else if (outbw == 0) {
		holdtime = SFB_RANDOM(sp, HOLDTIME_MIN, HOLDTIME_MAX);
	} else {
		unsigned int n, i;

		n = sfb_ttbl[0].holdtime;
		for (i = 0; sfb_ttbl[i].speed != 0; i++) {
			if (outbw < sfb_ttbl[i].speed)
				break;
			n = sfb_ttbl[i].holdtime;
		}
		holdtime = n;
	}
	net_nsectimer(&holdtime, &sp->sfb_holdtime);
}

static void
sfb_calc_pboxtime(struct sfb *sp, u_int64_t outbw)
{
	u_int64_t pboxtime;

	if (sfb_pboxtime != 0) {
		pboxtime = sfb_pboxtime;
	} else if (outbw == 0) {
		pboxtime = SFB_RANDOM(sp, PBOXTIME_MIN, PBOXTIME_MAX);
	} else {
		unsigned int n, i;

		n = sfb_ttbl[0].pboxtime;
		for (i = 0; sfb_ttbl[i].speed != 0; i++) {
			if (outbw < sfb_ttbl[i].speed)
				break;
			n = sfb_ttbl[i].pboxtime;
		}
		pboxtime = n;
	}
	net_nsectimer(&pboxtime, &sp->sfb_pboxtime);
	net_timerclear(&sp->sfb_pboxfreeze);
}

static void
sfb_calc_hinterval(struct sfb *sp, u_int64_t *t)
{
	u_int64_t hinterval;
	struct timespec now;

	if (t != NULL) {
		/*
		 * TODO adi@apple.com: use dq_avg to derive hinterval.
		 */
		hinterval = *t;
	}

	if (sfb_hinterval != 0)
		hinterval = sfb_hinterval;
	else if (t == NULL || hinterval == 0)
		hinterval = ((u_int64_t)SFB_HINTERVAL(sp) * NSEC_PER_SEC);

	net_nsectimer(&hinterval, &sp->sfb_hinterval);

	nanouptime(&now);
	net_timeradd(&now, &sp->sfb_hinterval, &sp->sfb_nextreset);
}

/*
 * sfb support routines
 */
struct sfb *
sfb_alloc(struct ifnet *ifp, u_int32_t qid, u_int32_t qlim, u_int32_t flags)
{
	struct sfb *sp;

	VERIFY(ifp != NULL && qlim > 0);

	sp = zalloc(sfb_zone);
	if (sp == NULL) {
		log(LOG_ERR, "%s: SFB unable to allocate\n", if_name(ifp));
		return (NULL);
	}

	bzero(sp, sfb_size);
	if ((sp->sfb_bins = _MALLOC(sizeof (*sp->sfb_bins), M_DEVBUF,
	    M_WAITOK|M_ZERO)) == NULL) {
		log(LOG_ERR, "%s: SFB unable to allocate bins\n", if_name(ifp));
		sfb_destroy(sp);
		return (NULL);
	}

	if ((sp->sfb_fc_lists = _MALLOC(sizeof (*sp->sfb_fc_lists), M_DEVBUF,
	    M_WAITOK|M_ZERO)) == NULL) {
		log(LOG_ERR, "%s: SFB unable to allocate flow control lists\n",
		    if_name(ifp));
		sfb_destroy(sp);
		return(NULL);
	}

	sp->sfb_flags = (flags & SFBF_USERFLAGS);
	sp->sfb_ifp = ifp;
	sp->sfb_qlim = qlim;
	sp->sfb_qid = qid;

	sfb_resetq(sp, -1);

	return (sp);
}

static void
sfb_fclist_append(struct sfb *sp, struct sfb_fc_list *fcl)
{
	IFCQ_CONVERT_LOCK(&sp->sfb_ifp->if_snd);
	ifnet_fclist_append(sp, fcl);
}

static void
sfb_fclists_clean(struct sfb *sp)
{
	int i;

	/* Move all the flow control entries to the ifnet list */
	for (i = 0; i < SFB_BINS; ++i) {
		struct sfb_fc_list *fcl = SFB_FC_LIST(sp, i);
		if (!SLIST_EMPTY(fcl))
			sfb_fclist_append(sp, fcl);
	}
}

void
sfb_destroy(struct sfb *sp)
{
	sfb_fclists_clean(sp);
	if (sp->sfb_bins != NULL) {
		_FREE(sp->sfb_bins, M_DEVBUF);
		sp->sfb_bins = NULL;
	}
	if (sp->sfb_fc_lists != NULL) {
		_FREE(sp->sfb_fc_lists, M_DEVBUF);
		sp->sfb_fc_lists = NULL;
	}
	zfree(sfb_zone, sp);
}

static void
sfb_resetq(struct sfb *sp, cqev_t ev)
{
	struct ifnet *ifp = sp->sfb_ifp;
	u_int64_t eff_rate;

	VERIFY(ifp != NULL);

	if (ev != CLASSQ_EV_LINK_DOWN) {
		(*sp->sfb_bins)[0].fudge = sfb_random(sp);
		(*sp->sfb_bins)[1].fudge = sfb_random(sp);
		sp->sfb_allocation = ((sfb_allocation == 0) ?
		    (sp->sfb_qlim / 3) : sfb_allocation);
		sp->sfb_drop_thresh = sp->sfb_allocation +
		    (sp->sfb_allocation >> 1);
	}

	sp->sfb_clearpkts = 0;
	sp->sfb_current = 0;

	eff_rate = ifnet_output_linkrate(ifp);
	sp->sfb_eff_rate = eff_rate;

	sfb_calc_holdtime(sp, eff_rate);
	sfb_calc_pboxtime(sp, eff_rate);
	sfb_calc_hinterval(sp, NULL);

	if (ev == CLASSQ_EV_LINK_DOWN ||
		ev == CLASSQ_EV_LINK_UP)
		sfb_fclists_clean(sp);

	bzero(sp->sfb_bins, sizeof (*sp->sfb_bins));
	bzero(&sp->sfb_stats, sizeof (sp->sfb_stats));

	if (ev == CLASSQ_EV_LINK_DOWN || !classq_verbose)
		return;

	log(LOG_DEBUG, "%s: SFB qid=%d, holdtime=%llu nsec, "
	    "pboxtime=%llu nsec, allocation=%d, drop_thresh=%d, "
	    "hinterval=%d sec, sfb_bins=%d bytes, eff_rate=%llu bps\n",
	    if_name(ifp), sp->sfb_qid, (u_int64_t)sp->sfb_holdtime.tv_nsec,
	    (u_int64_t)sp->sfb_pboxtime.tv_nsec,
	    (u_int32_t)sp->sfb_allocation, (u_int32_t)sp->sfb_drop_thresh,
	    (int)sp->sfb_hinterval.tv_sec, (int)sizeof (*sp->sfb_bins),
	    eff_rate);
}

void
sfb_getstats(struct sfb *sp, struct sfb_stats *sps)
{
	sps->allocation = sp->sfb_allocation;
	sps->dropthresh = sp->sfb_drop_thresh;
	sps->clearpkts = sp->sfb_clearpkts;
	sps->current = sp->sfb_current;

	net_timernsec(&sp->sfb_holdtime, &sp->sfb_stats.hold_time);
	net_timernsec(&sp->sfb_pboxtime, &sp->sfb_stats.pbox_time);
	net_timernsec(&sp->sfb_hinterval, &sp->sfb_stats.rehash_intval);
	*(&(sps->sfbstats)) = *(&(sp->sfb_stats));

	_CASSERT(sizeof ((*sp->sfb_bins)[0].stats) ==
	    sizeof (sps->binstats[0].stats));

	bcopy(&(*sp->sfb_bins)[0].stats, &sps->binstats[0].stats,
	    sizeof (sps->binstats[0].stats));
	bcopy(&(*sp->sfb_bins)[1].stats, &sps->binstats[1].stats,
	    sizeof (sps->binstats[1].stats));
}

static void
sfb_swap_bins(struct sfb *sp, u_int32_t len)
{
	int i, j, s;

	if (sp->sfb_flags & SFBF_SUSPENDED)
		return;

	s = sp->sfb_current;
	VERIFY((s + (s ^ 1)) == 1);

	(*sp->sfb_bins)[s].fudge = sfb_random(sp); /* recompute perturbation */
	sp->sfb_clearpkts = len;
	sp->sfb_stats.num_rehash++;

	s = (sp->sfb_current ^= 1);	/* flip the bit (swap current) */

	if (classq_verbose) {
		log(LOG_DEBUG, "%s: SFB qid=%d, set %d is now current, "
		    "qlen=%d\n", if_name(sp->sfb_ifp), sp->sfb_qid, s, len);
	}

	/* clear freezetime for all current bins */
	bzero(&(*sp->sfb_bins)[s].freezetime,
	    sizeof ((*sp->sfb_bins)[s].freezetime));

	/* clear/adjust bin statistics and flow control lists */
	for (i = 0; i < SFB_BINS; i++) {
		struct sfb_fc_list *fcl = SFB_FC_LIST(sp, i);

		if (!SLIST_EMPTY(fcl))
			sfb_fclist_append(sp, fcl);

		for (j = 0; j < SFB_LEVELS; j++) {
			struct sfbbinstats *cbin, *wbin;

			cbin = SFB_BINST(sp, j, i, s);		/* current */
			wbin = SFB_BINST(sp, j, i, s ^ 1);	/* warm-up */

			cbin->pkts = 0;
			if (cbin->pmark > SFB_MAX_PMARK)
				cbin->pmark = SFB_MAX_PMARK;
			if (cbin->pmark < 0)
				cbin->pmark = 0;

			/*
			 * Keep pmark from before to identify
			 * non-responsives immediately.
			 */
			if (wbin->pmark > SFB_PMARK_WARM)
				wbin->pmark = SFB_PMARK_WARM;
		}
	}
}

static inline int
sfb_pcheck(struct sfb *sp, struct pf_mtag *t)
{
#if SFB_LEVELS != 2
	int i, n;
#endif /* SFB_LEVELS != 2 */
	int s;

	s = sp->sfb_current;
	VERIFY((s + (s ^ 1)) == 1);

	/*
	 * For current bins, returns 1 if all pmark >= SFB_PMARK_TH,
	 * 0 otherwise; optimize for SFB_LEVELS=2.
	 */
#if SFB_LEVELS == 2
	/*
	 * Level 0: bin index at [0] for set 0; [2] for set 1
	 * Level 1: bin index at [1] for set 0; [3] for set 1
	 */
	if (SFB_BINST(sp, 0, SFB_BINMASK(t->pftag_qpriv8[(s << 1)]),
	    s)->pmark < SFB_PMARK_TH ||
	    SFB_BINST(sp, 1, SFB_BINMASK(t->pftag_qpriv8[(s << 1) + 1]),
	    s)->pmark < SFB_PMARK_TH)
		return (0);
#else /* SFB_LEVELS != 2 */
	for (i = 0; i < SFB_LEVELS; i++) {
		if (s == 0)		/* set 0, bin index [0,1] */
			n = SFB_BINMASK(t->pftag_qpriv8[i]);
		else			/* set 1, bin index [2,3] */
			n = SFB_BINMASK(t->pftag_qpriv8[i + 2]);

		if (SFB_BINST(sp, i, n, s)->pmark < SFB_PMARK_TH)
			return (0);
	}
#endif /* SFB_LEVELS != 2 */
	return (1);
}

static int
sfb_penalize(struct sfb *sp, struct pf_mtag *t, struct timespec *now)
{
	struct timespec delta = { 0, 0 };

	/* If minimum pmark of current bins is < SFB_PMARK_TH, we're done */
	if (!sfb_ratelimit || !sfb_pcheck(sp, t))
		return (0);

	net_timersub(now, &sp->sfb_pboxfreeze, &delta);
	if (net_timercmp(&delta, &sp->sfb_pboxtime, <)) {
#if SFB_LEVELS != 2
		int i;
#endif /* SFB_LEVELS != 2 */
		struct sfbbinstats *bin;
		int n, w;

		w = sp->sfb_current ^ 1;
		VERIFY((w + (w ^ 1)) == 1);

		/*
		 * Update warm-up bins; optimize for SFB_LEVELS=2
		 */
#if SFB_LEVELS == 2
		/* Level 0: bin index at [0] for set 0; [2] for set 1 */
		n = SFB_BINMASK(t->pftag_qpriv8[(w << 1)]);
		bin = SFB_BINST(sp, 0, n, w);
		if (bin->pkts >= sp->sfb_allocation)
			sfb_increment_bin(sp, bin, SFB_BINFT(sp, 0, n, w), now);

		/* Level 0: bin index at [1] for set 0; [3] for set 1 */
		n = SFB_BINMASK(t->pftag_qpriv8[(w << 1) + 1]);
		bin = SFB_BINST(sp, 1, n, w);
		if (bin->pkts >= sp->sfb_allocation)
			sfb_increment_bin(sp, bin, SFB_BINFT(sp, 1, n, w), now);
#else /* SFB_LEVELS != 2 */
		for (i = 0; i < SFB_LEVELS; i++) {
			if (w == 0)	/* set 0, bin index [0,1] */
				n = SFB_BINMASK(t->pftag_qpriv8[i]);
			else		/* set 1, bin index [2,3] */
				n = SFB_BINMASK(t->pftag_qpriv8[i + 2]);

			bin = SFB_BINST(sp, i, n, w);
			if (bin->pkts >= sp->sfb_allocation) {
				sfb_increment_bin(sp, bin,
				    SFB_BINFT(sp, i, n, w), now);
			}
		}
#endif /* SFB_LEVELS != 2 */
		return (1);
	}

	/* non-conformant or else misclassified flow; queue it anyway */
	t->pftag_flags |= SFB_PKT_PBOX;
	*(&sp->sfb_pboxfreeze) = *now;

	return (0);
}

static void
sfb_adjust_bin(struct sfb *sp, struct sfbbinstats *bin, struct timespec *ft,
    struct timespec *now, boolean_t inc)
{
	struct timespec delta;

	net_timersub(now, ft, &delta);
	if (net_timercmp(&delta, &sp->sfb_holdtime, <)) {
		if (classq_verbose > 1) {
			log(LOG_DEBUG, "%s: SFB qid=%d, %s update frozen "
			    "(delta=%llu nsec)\n", if_name(sp->sfb_ifp),
			    sp->sfb_qid, inc ?  "increment" : "decrement",
			    (u_int64_t)delta.tv_nsec);
		}
		return;
	}

	/* increment/decrement marking probability */
	*ft = *now;
	if (inc)
		SFB_PMARK_INC(bin);
	else
		SFB_PMARK_DEC(bin);
}

static void
sfb_decrement_bin(struct sfb *sp, struct sfbbinstats *bin, struct timespec *ft,
    struct timespec *now)
{
	return (sfb_adjust_bin(sp, bin, ft, now, FALSE));
}

static void
sfb_increment_bin(struct sfb *sp, struct sfbbinstats *bin, struct timespec *ft,
    struct timespec *now)
{
	return (sfb_adjust_bin(sp, bin, ft, now, TRUE));
}

static inline void
sfb_dq_update_bins(struct sfb *sp, struct pf_mtag *t, struct timespec *now)
{
#if SFB_LEVELS != 2 || SFB_FC_LEVEL != 0
	int i;
#endif /* SFB_LEVELS != 2 || SFB_FC_LEVEL != 0 */
	struct sfbbinstats *bin;
	int s, n;
	struct sfb_fc_list *fcl = NULL;

	s = sp->sfb_current;
	VERIFY((s + (s ^ 1)) == 1);

	/*
	 * Update current bins; optimize for SFB_LEVELS=2 and SFB_FC_LEVEL=0
	 */
#if SFB_LEVELS == 2 && SFB_FC_LEVEL == 0
	/* Level 0: bin index at [0] for set 0; [2] for set 1 */
	n = SFB_BINMASK(t->pftag_qpriv8[(s << 1)]);
	bin = SFB_BINST(sp, 0, n, s);

	VERIFY(bin->pkts > 0);
	if (--bin->pkts == 0) {
		sfb_decrement_bin(sp, bin, SFB_BINFT(sp, 0, n, s), now);
	}
	if (bin->pkts <= (sp->sfb_allocation >> 2)) {
		/* deliver flow control feedback to the sockets */
		fcl = SFB_FC_LIST(sp, n);
		if (!SLIST_EMPTY(fcl))
			sfb_fclist_append(sp, fcl);
	}

	/* Level 1: bin index at [1] for set 0; [3] for set 1 */
	n = SFB_BINMASK(t->pftag_qpriv8[(s << 1) + 1]);
	bin = SFB_BINST(sp, 1, n, s);

	VERIFY(bin->pkts > 0);
	if (--bin->pkts == 0)
		sfb_decrement_bin(sp, bin, SFB_BINFT(sp, 1, n, s), now);
#else /* SFB_LEVELS != 2 || SFB_FC_LEVEL != 0 */
	for (i = 0; i < SFB_LEVELS; i++) {
		if (s == 0)		/* set 0, bin index [0,1] */
			n = SFB_BINMASK(t->pftag_qpriv8[i]);
		else			/* set 1, bin index [2,3] */
			n = SFB_BINMASK(t->pftag_qpriv8[i + 2]);

		bin = SFB_BINST(sp, i, n, s);

		VERIFY(bin->pkts > 0);
		if (--bin->pkts == 0) {
			sfb_decrement_bin(sp, bin,
			    SFB_BINFT(sp, i, n, s), now);
		}
		if (bin->pkts <= (sp->sfb_allocation >> 2)) {
			/* deliver flow control feedback to the sockets */
			if (i == SFB_FC_LEVEL) {
				fcl = SFB_FC_LIST(sp, n);
				if (!SLIST_EMPTY(fcl))
					sfb_fclist_append(sp, fcl);
			}
		}
	}
#endif /* SFB_LEVELS != 2 || SFB_FC_LEVEL != 0 */
}

static inline void
sfb_eq_update_bins(struct sfb *sp, struct pf_mtag *t)
{
#if SFB_LEVELS != 2
	int i, n;
#endif /* SFB_LEVELS != 2 */
	int s;

	s = sp->sfb_current;
	VERIFY((s + (s ^ 1)) == 1);

	/*
	 * Update current bins; optimize for SFB_LEVELS=2
	 */
#if SFB_LEVELS == 2
	/* Level 0: bin index at [0] for set 0; [2] for set 1 */
	SFB_BINST(sp, 0, SFB_BINMASK(t->pftag_qpriv8[(s << 1)]), s)->pkts++;

	/* Level 1: bin index at [1] for set 0; [3] for set 1 */
	SFB_BINST(sp, 1, SFB_BINMASK(t->pftag_qpriv8[(s << 1) + 1]), s)->pkts++;
#else /* SFB_LEVELS != 2 */
	for (i = 0; i < SFB_LEVELS; i++) {
		if (s == 0)		/* set 0, bin index [0,1] */
			n = SFB_BINMASK(t->pftag_qpriv8[i]);
		else			/* set 1, bin index [2,3] */
			n = SFB_BINMASK(t->pftag_qpriv8[i + 2]);

		SFB_BINST(sp, i, n, s)->pkts++;
	}
#endif /* SFB_LEVELS != 2 */
}

static boolean_t
sfb_bin_addfcentry(struct sfb *sp, struct pf_mtag *t)
{
	struct sfb_bin_fcentry *fce;
	u_int32_t flowhash;
	struct sfb_fc_list *fcl;
	int s;

	s = sp->sfb_current;
	VERIFY((s + (s ^ 1)) == 1);

	flowhash = t->pftag_flowhash;

	if (flowhash == 0) {
		sp->sfb_stats.null_flowhash++;
		return (FALSE);
	}

	/*
	 * Use value at index 0 for set 0 and
	 * value at index 2 for set 1
	 */
	fcl = SFB_FC_LIST(sp, SFB_BINMASK(t->pftag_qpriv8[(s << 1)]));
	SLIST_FOREACH(fce, fcl, fce_link) {
		if (fce->fce_flowhash == flowhash) {
			/* Already on flow control list; just return */
			return (TRUE);
		}
	}

	IFCQ_CONVERT_LOCK(&sp->sfb_ifp->if_snd);
	fce = ifnet_fce_alloc(M_WAITOK);
	if (fce != NULL) {
		fce->fce_flowhash = flowhash;
		SLIST_INSERT_HEAD(fcl, fce, fce_link);
		sp->sfb_stats.flow_controlled++;
	}

	return (fce != NULL);
}

/*
 * early-drop probability is kept in pmark of each bin of the flow
 */
static int
sfb_drop_early(struct sfb *sp, struct pf_mtag *t, u_int16_t *pmin,
    struct timespec *now)
{
#if SFB_LEVELS != 2
	int i;
#endif /* SFB_LEVELS != 2 */
	struct sfbbinstats *bin;
	int s, n, ret = 0;

	s = sp->sfb_current;
	VERIFY((s + (s ^ 1)) == 1);

	*pmin = (u_int16_t)-1;

	/*
	 * Update current bins; optimize for SFB_LEVELS=2
	 */
#if SFB_LEVELS == 2
	/* Level 0: bin index at [0] for set 0; [2] for set 1 */
	n = SFB_BINMASK(t->pftag_qpriv8[(s << 1)]);
	bin = SFB_BINST(sp, 0, n, s);
	if (*pmin > (u_int16_t)bin->pmark)
		*pmin = (u_int16_t)bin->pmark;

	if (bin->pkts >= sp->sfb_allocation) {
		if (bin->pkts >= sp->sfb_drop_thresh)
			ret = 1;	/* drop or mark */
		sfb_increment_bin(sp, bin, SFB_BINFT(sp, 0, n, s), now);
	}

	/* Level 1: bin index at [1] for set 0; [3] for set 1 */
	n = SFB_BINMASK(t->pftag_qpriv8[(s << 1) + 1]);
	bin = SFB_BINST(sp, 1, n, s);
	if (*pmin > (u_int16_t)bin->pmark)
		*pmin = (u_int16_t)bin->pmark;

	if (bin->pkts >= sp->sfb_allocation) {
		if (bin->pkts >= sp->sfb_drop_thresh)
			ret = 1;	/* drop or mark */
		sfb_increment_bin(sp, bin, SFB_BINFT(sp, 1, n, s), now);
	}
#else /* SFB_LEVELS != 2 */
	for (i = 0; i < SFB_LEVELS; i++) {
		if (s == 0)		/* set 0, bin index [0,1] */
			n = SFB_BINMASK(t->pftag_qpriv8[i]);
		else			/* set 1, bin index [2,3] */
			n = SFB_BINMASK(t->pftag_qpriv8[i + 2]);

		bin = SFB_BINST(sp, i, n, s);
		if (*pmin > (u_int16_t)bin->pmark)
			*pmin = (u_int16_t)bin->pmark;

		if (bin->pkts >= sp->sfb_allocation) {
			if (bin->pkts >= sp->sfb_drop_thresh)
				ret = 1;	/* drop or mark */
			sfb_increment_bin(sp, bin,
			    SFB_BINFT(sp, i, n, s), now);
		}
	}
#endif /* SFB_LEVELS != 2 */

	if (sp->sfb_flags & SFBF_SUSPENDED)
		ret = 1;	/* drop or mark */

	return (ret);
}

#define	DTYPE_NODROP	0	/* no drop */
#define	DTYPE_FORCED	1	/* a "forced" drop */
#define	DTYPE_EARLY	2	/* an "unforced" (early) drop */

int
sfb_addq(struct sfb *sp, class_queue_t *q, struct mbuf *m, struct pf_mtag *t)
{
	struct timespec now;
	int droptype, s;
	u_int16_t pmin;
	int fc_adv = 0;
	int ret = CLASSQEQ_SUCCESS;

	nanouptime(&now);

	s = sp->sfb_current;
	VERIFY((s + (s ^ 1)) == 1);

	/* time to swap the bins? */
	if (net_timercmp(&now, &sp->sfb_nextreset, >=)) {
		net_timeradd(&now, &sp->sfb_hinterval, &sp->sfb_nextreset);
		sfb_swap_bins(sp, qlen(q));
		s = sp->sfb_current;
		VERIFY((s + (s ^ 1)) == 1);
	}

	t->pftag_flags &= ~SFB_PKT_PBOX;
	t->pftag_qpriv16[s] =
	    (SFB_HASH(&t->pftag_flowhash, sizeof (t->pftag_flowhash),
	    (*sp->sfb_bins)[s].fudge) & SFB_HASHMASK);
	t->pftag_qpriv16[s ^ 1] =
	    (SFB_HASH(&t->pftag_flowhash, sizeof (t->pftag_flowhash),
	    (*sp->sfb_bins)[s ^ 1].fudge) & SFB_HASHMASK);

	/* see if we drop early */
	droptype = DTYPE_NODROP;
	if (sfb_drop_early(sp, t, &pmin, &now)) {
		/* flow control, mark or drop by sfb */
		if ((sp->sfb_flags & SFBF_FLOWCTL) &&
		    (t->pftag_flags & PF_TAG_FLOWADV)) {
			fc_adv = 1;
			/* drop all during suspension or for non-TCP */
			if ((sp->sfb_flags & SFBF_SUSPENDED) ||
			    !(t->pftag_flags & PF_TAG_TCP)) {
				droptype = DTYPE_EARLY;
				sp->sfb_stats.drop_early++;
			}
		} else if ((sp->sfb_flags & SFBF_ECN) &&
		    (t->pftag_flags & PF_TAG_TCP) &&	/* only for TCP */
		    ((sfb_random(sp) & SFB_MAX_PMARK) <= pmin) &&
		    mark_ecn(m, t, sp->sfb_flags) &&
		    !(sp->sfb_flags & SFBF_SUSPENDED)) {
			/* successfully marked; do not drop. */
			sp->sfb_stats.marked_packets++;
		} else {
			/* unforced drop by sfb */
			droptype = DTYPE_EARLY;
			sp->sfb_stats.drop_early++;
		}
	}

	/* non-responsive flow penalty? */
	if (droptype == DTYPE_NODROP && sfb_penalize(sp, t, &now)) {
		droptype = DTYPE_FORCED;
		sp->sfb_stats.drop_pbox++;
	}

	/* if the queue length hits the hard limit, it's a forced drop */
	if (droptype == DTYPE_NODROP && qlen(q) >= qlimit(q)) {
		droptype = DTYPE_FORCED;
		sp->sfb_stats.drop_queue++;
	}

	if (fc_adv == 1 && droptype != DTYPE_FORCED &&
	    sfb_bin_addfcentry(sp, t)) {
		/* deliver flow control advisory error */
		if (droptype == DTYPE_NODROP) {
			ret = CLASSQEQ_SUCCESS_FC;
			VERIFY(!(sp->sfb_flags & SFBF_SUSPENDED));
		} else if (sp->sfb_flags & SFBF_SUSPENDED) {
			/* dropped due to suspension */
			ret = CLASSQEQ_DROPPED_SP;
		} else {
			/* dropped due to flow-control */
			ret = CLASSQEQ_DROPPED_FC;
		}
	}

	/* if successful enqueue this packet, else drop it */
	if (droptype == DTYPE_NODROP) {
		_addq(q, m);
	} else {
		IFCQ_CONVERT_LOCK(&sp->sfb_ifp->if_snd);
		m_freem(m);
		return ((ret != CLASSQEQ_SUCCESS) ? ret : CLASSQEQ_DROPPED);
	}

	if (!(t->pftag_flags & SFB_PKT_PBOX))
		sfb_eq_update_bins(sp, t);
	else
		sp->sfb_stats.pbox_packets++;

	/* successfully queued */
	return (ret);
}

static struct mbuf *
sfb_getq_flow(struct sfb *sp, class_queue_t *q, u_int32_t flow, boolean_t purge)
{
	struct timespec now;
	struct mbuf *m;
	struct pf_mtag *t;

	if (!purge && (sp->sfb_flags & SFBF_SUSPENDED))
		return (NULL);

	nanouptime(&now);

	/* flow of 0 means head of queue */
	if ((m = ((flow == 0) ? _getq(q) : _getq_flow(q, flow))) == NULL) {
		if (!purge)
			net_timerclear(&sp->sfb_getqtime);
		return (NULL);
	}

	VERIFY(m->m_flags & M_PKTHDR);

	t = m_pftag(m);

	if (!purge) {
		/* calculate EWMA of dequeues */
		if (net_timerisset(&sp->sfb_getqtime)) {
			struct timespec delta;
			u_int64_t avg, new;

			net_timersub(&now, &sp->sfb_getqtime, &delta);
			net_timernsec(&delta, &new);
			avg = sp->sfb_stats.dequeue_avg;
			if (avg > 0) {
				int decay = DEQUEUE_DECAY;
				/*
				 * If the time since last dequeue is
				 * significantly greater than the current
				 * average, weight the average more against
				 * the old value.
				 */
				if (DEQUEUE_SPIKE(new, avg))
					decay += 5;
				avg = (((avg << decay) - avg) + new) >> decay;
			} else {
				avg = new;
			}
			sp->sfb_stats.dequeue_avg = avg;
		}
		*(&sp->sfb_getqtime) = *(&now);
	}

	/*
	 * Clearpkts are the ones which were in the queue when the hash
	 * function was perturbed.  Since the perturbation value (fudge),
	 * and thus bin information for these packets is not known, we do
	 * not change accounting information while dequeuing these packets.
	 * It is important not to set the hash interval too small due to
	 * this reason.  A rule of thumb is to set it to K*D, where D is
	 * the time taken to drain queue.
	 */
	if (t->pftag_flags & SFB_PKT_PBOX) {
		t->pftag_flags &= ~SFB_PKT_PBOX;
		if (sp->sfb_clearpkts > 0)
			sp->sfb_clearpkts--;
	} else if (sp->sfb_clearpkts > 0) {
		sp->sfb_clearpkts--;
	} else {
		sfb_dq_update_bins(sp, t, &now);
	}

	return (m);
}

struct mbuf *
sfb_getq(struct sfb *sp, class_queue_t *q)
{
	return (sfb_getq_flow(sp, q, 0, FALSE));
}

void
sfb_purgeq(struct sfb *sp, class_queue_t *q, u_int32_t flow, u_int32_t *packets,
    u_int32_t *bytes)
{
	u_int32_t cnt = 0, len = 0;
	struct mbuf *m;

	IFCQ_CONVERT_LOCK(&sp->sfb_ifp->if_snd);

	while ((m = sfb_getq_flow(sp, q, flow, TRUE)) != NULL) {
		cnt++;
		len += m_pktlen(m);
		m_freem(m);
	}

	if (packets != NULL)
		*packets = cnt;
	if (bytes != NULL)
		*bytes = len;
}

void
sfb_updateq(struct sfb *sp, cqev_t ev)
{
	struct ifnet *ifp = sp->sfb_ifp;

	VERIFY(ifp != NULL);

	switch (ev) {
	case CLASSQ_EV_LINK_SPEED: {
		u_int64_t eff_rate = ifnet_output_linkrate(ifp);

		/* update parameters only if rate has changed */
		if (eff_rate == sp->sfb_eff_rate)
			break;

		if (classq_verbose) {
			log(LOG_DEBUG, "%s: SFB qid=%d, adapting to new "
			    "eff_rate=%llu bps\n", if_name(ifp), sp->sfb_qid,
			    eff_rate);
		}
		sfb_calc_holdtime(sp, eff_rate);
		sfb_calc_pboxtime(sp, eff_rate);
		break;
	}

	case CLASSQ_EV_LINK_UP:
	case CLASSQ_EV_LINK_DOWN:
		if (classq_verbose) {
			log(LOG_DEBUG, "%s: SFB qid=%d, resetting due to "
			    "link %s\n", if_name(ifp), sp->sfb_qid,
			    (ev == CLASSQ_EV_LINK_UP) ? "UP" : "DOWN");
		}
		sfb_resetq(sp, ev);
		break;

	case CLASSQ_EV_LINK_MTU:
	default:
		break;
	}
}

int
sfb_suspendq(struct sfb *sp, class_queue_t *q, boolean_t on)
{
#pragma unused(q)
	struct ifnet *ifp = sp->sfb_ifp;

	VERIFY(ifp != NULL);

	if ((on && (sp->sfb_flags & SFBF_SUSPENDED)) ||
	    (!on && !(sp->sfb_flags & SFBF_SUSPENDED)))
		return (0);

	if (!(sp->sfb_flags & SFBF_FLOWCTL)) {
		log(LOG_ERR, "%s: SFB qid=%d, unable to %s queue since "
		    "flow-control is not enabled", if_name(ifp), sp->sfb_qid,
		    (on ? "suspend" : "resume"));
		return (ENOTSUP);
	}

	if (classq_verbose) {
		log(LOG_DEBUG, "%s: SFB qid=%d, setting state to %s",
		    if_name(ifp), sp->sfb_qid, (on ? "SUSPENDED" : "RUNNING"));
	}

	if (on) {
		sp->sfb_flags |= SFBF_SUSPENDED;
	} else {
		sp->sfb_flags &= ~SFBF_SUSPENDED;
		sfb_swap_bins(sp, qlen(q));
	}

	return (0);
}
