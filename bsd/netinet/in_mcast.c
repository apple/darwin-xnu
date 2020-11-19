/*
 * Copyright (c) 2010-2020 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 2007-2009 Bruce Simpson.
 * Copyright (c) 2005 Robert N. M. Watson.
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
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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
 * IPv4 multicast socket, group, and socket option processing module.
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/sysctl.h>
#include <sys/tree.h>
#include <sys/mcache.h>

#include <kern/zalloc.h>

#include <pexpert/pexpert.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/net_api_stats.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/igmp_var.h>

/*
 * Functions with non-static linkage defined in this file should be
 * declared in in_var.h:
 *  imo_multi_filter()
 *  in_addmulti()
 *  in_delmulti()
 *  in_joingroup()
 *  in_leavegroup()
 * and ip_var.h:
 *  inp_freemoptions()
 *  inp_getmoptions()
 *  inp_setmoptions()
 *
 * XXX: Both carp and pf need to use the legacy (*,G) KPIs in_addmulti()
 * and in_delmulti().
 */
static void     imf_commit(struct in_mfilter *);
static int      imf_get_source(struct in_mfilter *imf,
    const struct sockaddr_in *psin,
    struct in_msource **);
static struct in_msource *
imf_graft(struct in_mfilter *, const uint8_t,
    const struct sockaddr_in *);
static int      imf_prune(struct in_mfilter *, const struct sockaddr_in *);
static void     imf_rollback(struct in_mfilter *);
static void     imf_reap(struct in_mfilter *);
static int      imo_grow(struct ip_moptions *, uint16_t);
static size_t   imo_match_group(const struct ip_moptions *,
    const struct ifnet *, const struct sockaddr_in *);
static struct in_msource *
imo_match_source(const struct ip_moptions *, const size_t,
    const struct sockaddr_in *);
static void     ims_merge(struct ip_msource *ims,
    const struct in_msource *lims, const int rollback);
static int      in_getmulti(struct ifnet *, const struct in_addr *,
    struct in_multi **);
static int      in_joingroup(struct ifnet *, const struct in_addr *,
    struct in_mfilter *, struct in_multi **);
static int      inm_get_source(struct in_multi *inm, const in_addr_t haddr,
    const int noalloc, struct ip_msource **pims);
static int      inm_is_ifp_detached(const struct in_multi *);
static int      inm_merge(struct in_multi *, /*const*/ struct in_mfilter *);
static void     inm_reap(struct in_multi *);
static struct ip_moptions *
inp_findmoptions(struct inpcb *);
static int      inp_get_source_filters(struct inpcb *, struct sockopt *);
static struct ifnet *
inp_lookup_mcast_ifp(const struct inpcb *,
    const struct sockaddr_in *, const struct in_addr);
static int      inp_block_unblock_source(struct inpcb *, struct sockopt *);
static int      inp_set_multicast_if(struct inpcb *, struct sockopt *);
static int      inp_set_source_filters(struct inpcb *, struct sockopt *);
static int      sysctl_ip_mcast_filters SYSCTL_HANDLER_ARGS;
static struct ifnet * ip_multicast_if(struct in_addr *, unsigned int *);
static __inline__ int ip_msource_cmp(const struct ip_msource *,
    const struct ip_msource *);

SYSCTL_NODE(_net_inet_ip, OID_AUTO, mcast, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "IPv4 multicast");

static u_long in_mcast_maxgrpsrc = IP_MAX_GROUP_SRC_FILTER;
SYSCTL_LONG(_net_inet_ip_mcast, OID_AUTO, maxgrpsrc,
    CTLFLAG_RW | CTLFLAG_LOCKED, &in_mcast_maxgrpsrc, "Max source filters per group");

static u_int in_mcast_maxsocksrc = IP_MAX_SOCK_SRC_FILTER;
SYSCTL_UINT(_net_inet_ip_mcast, OID_AUTO, maxsocksrc,
    CTLFLAG_RW | CTLFLAG_LOCKED, &in_mcast_maxsocksrc, IP_MAX_SOCK_SRC_FILTER,
    "Max source filters per socket");

int in_mcast_loop = IP_DEFAULT_MULTICAST_LOOP;
SYSCTL_INT(_net_inet_ip_mcast, OID_AUTO, loop, CTLFLAG_RW | CTLFLAG_LOCKED,
    &in_mcast_loop, 0, "Loopback multicast datagrams by default");

SYSCTL_NODE(_net_inet_ip_mcast, OID_AUTO, filters,
    CTLFLAG_RD | CTLFLAG_LOCKED, sysctl_ip_mcast_filters,
    "Per-interface stack-wide source filters");

RB_GENERATE_PREV(ip_msource_tree, ip_msource, ims_link, ip_msource_cmp);

#define INM_TRACE_HIST_SIZE     32      /* size of trace history */

/* For gdb */
__private_extern__ unsigned int inm_trace_hist_size = INM_TRACE_HIST_SIZE;

struct in_multi_dbg {
	struct in_multi         inm;                    /* in_multi */
	u_int16_t               inm_refhold_cnt;        /* # of ref */
	u_int16_t               inm_refrele_cnt;        /* # of rele */
	/*
	 * Circular lists of inm_addref and inm_remref callers.
	 */
	ctrace_t                inm_refhold[INM_TRACE_HIST_SIZE];
	ctrace_t                inm_refrele[INM_TRACE_HIST_SIZE];
	/*
	 * Trash list linkage
	 */
	TAILQ_ENTRY(in_multi_dbg) inm_trash_link;
};

/* List of trash in_multi entries protected by inm_trash_lock */
static TAILQ_HEAD(, in_multi_dbg) inm_trash_head;
static decl_lck_mtx_data(, inm_trash_lock);


#if DEBUG
static unsigned int inm_debug = 1;              /* debugging (enabled) */
#else
static unsigned int inm_debug;                  /* debugging (disabled) */
#endif /* !DEBUG */
#define INM_ZONE_NAME           "in_multi"      /* zone name */
static struct zone *inm_zone;                   /* zone for in_multi */

static ZONE_DECLARE(ipms_zone, "ip_msource", sizeof(struct ip_msource),
    ZC_ZFREE_CLEARMEM);
static ZONE_DECLARE(inms_zone, "in_msource", sizeof(struct in_msource),
    ZC_ZFREE_CLEARMEM);

/* Lock group and attribute for in_multihead_lock lock */
static lck_attr_t       *in_multihead_lock_attr;
static lck_grp_t        *in_multihead_lock_grp;
static lck_grp_attr_t   *in_multihead_lock_grp_attr;

static decl_lck_rw_data(, in_multihead_lock);
struct in_multihead in_multihead;

static struct in_multi *in_multi_alloc(zalloc_flags_t);
static void in_multi_free(struct in_multi *);
static void in_multi_attach(struct in_multi *);
static void inm_trace(struct in_multi *, int);

static struct ip_msource *ipms_alloc(zalloc_flags_t);
static void ipms_free(struct ip_msource *);
static struct in_msource *inms_alloc(zalloc_flags_t);
static void inms_free(struct in_msource *);

static __inline int
ip_msource_cmp(const struct ip_msource *a, const struct ip_msource *b)
{
	if (a->ims_haddr < b->ims_haddr) {
		return -1;
	}
	if (a->ims_haddr == b->ims_haddr) {
		return 0;
	}
	return 1;
}

/*
 * Inline function which wraps assertions for a valid ifp.
 */
static __inline__ int
inm_is_ifp_detached(const struct in_multi *inm)
{
	VERIFY(inm->inm_ifma != NULL);
	VERIFY(inm->inm_ifp == inm->inm_ifma->ifma_ifp);

	return !ifnet_is_attached(inm->inm_ifp, 0);
}

/*
 * Initialize an in_mfilter structure to a known state at t0, t1
 * with an empty source filter list.
 */
static __inline__ void
imf_init(struct in_mfilter *imf, const uint8_t st0, const uint8_t st1)
{
	memset(imf, 0, sizeof(struct in_mfilter));
	RB_INIT(&imf->imf_sources);
	imf->imf_st[0] = st0;
	imf->imf_st[1] = st1;
}

/*
 * Resize the ip_moptions vector to the next power-of-two minus 1.
 */
static int
imo_grow(struct ip_moptions *imo, uint16_t newmax)
{
	struct in_multi         **nmships;
	struct in_multi         **omships;
	struct in_mfilter        *nmfilters;
	struct in_mfilter        *omfilters;
	uint16_t                  idx;
	uint16_t                  oldmax;

	IMO_LOCK_ASSERT_HELD(imo);

	nmships = NULL;
	nmfilters = NULL;
	omships = imo->imo_membership;
	omfilters = imo->imo_mfilters;
	oldmax = imo->imo_max_memberships;
	if (newmax == 0) {
		newmax = ((oldmax + 1) * 2) - 1;
	}

	if (newmax > IP_MAX_MEMBERSHIPS) {
		return ETOOMANYREFS;
	}

	if ((nmships = (struct in_multi **)_REALLOC(omships,
	    sizeof(struct in_multi *) * newmax, M_IPMOPTS,
	    M_WAITOK | M_ZERO)) == NULL) {
		return ENOMEM;
	}

	imo->imo_membership = nmships;

	if ((nmfilters = (struct in_mfilter *)_REALLOC(omfilters,
	    sizeof(struct in_mfilter) * newmax, M_INMFILTER,
	    M_WAITOK | M_ZERO)) == NULL) {
		return ENOMEM;
	}

	imo->imo_mfilters = nmfilters;

	/* Initialize newly allocated source filter heads. */
	for (idx = oldmax; idx < newmax; idx++) {
		imf_init(&nmfilters[idx], MCAST_UNDEFINED, MCAST_EXCLUDE);
	}

	imo->imo_max_memberships = newmax;

	return 0;
}

/*
 * Find an IPv4 multicast group entry for this ip_moptions instance
 * which matches the specified group, and optionally an interface.
 * Return its index into the array, or -1 if not found.
 */
static size_t
imo_match_group(const struct ip_moptions *imo, const struct ifnet *ifp,
    const struct sockaddr_in *group)
{
	struct in_multi *pinm;
	int               idx;
	int               nmships;

	IMO_LOCK_ASSERT_HELD(__DECONST(struct ip_moptions *, imo));


	/* The imo_membership array may be lazy allocated. */
	if (imo->imo_membership == NULL || imo->imo_num_memberships == 0) {
		return -1;
	}

	nmships = imo->imo_num_memberships;
	for (idx = 0; idx < nmships; idx++) {
		pinm = imo->imo_membership[idx];
		if (pinm == NULL) {
			continue;
		}
		INM_LOCK(pinm);
		if ((ifp == NULL || (pinm->inm_ifp == ifp)) &&
		    in_hosteq(pinm->inm_addr, group->sin_addr)) {
			INM_UNLOCK(pinm);
			break;
		}
		INM_UNLOCK(pinm);
	}
	if (idx >= nmships) {
		idx = -1;
	}

	return idx;
}

/*
 * Find an IPv4 multicast source entry for this imo which matches
 * the given group index for this socket, and source address.
 *
 * NOTE: This does not check if the entry is in-mode, merely if
 * it exists, which may not be the desired behaviour.
 */
static struct in_msource *
imo_match_source(const struct ip_moptions *imo, const size_t gidx,
    const struct sockaddr_in *src)
{
	struct ip_msource        find;
	struct in_mfilter       *imf;
	struct ip_msource       *ims;

	IMO_LOCK_ASSERT_HELD(__DECONST(struct ip_moptions *, imo));

	VERIFY(src->sin_family == AF_INET);
	VERIFY(gidx != (size_t)-1 && gidx < imo->imo_num_memberships);

	/* The imo_mfilters array may be lazy allocated. */
	if (imo->imo_mfilters == NULL) {
		return NULL;
	}
	imf = &imo->imo_mfilters[gidx];

	/* Source trees are keyed in host byte order. */
	find.ims_haddr = ntohl(src->sin_addr.s_addr);
	ims = RB_FIND(ip_msource_tree, &imf->imf_sources, &find);

	return (struct in_msource *)ims;
}

/*
 * Perform filtering for multicast datagrams on a socket by group and source.
 *
 * Returns 0 if a datagram should be allowed through, or various error codes
 * if the socket was not a member of the group, or the source was muted, etc.
 */
int
imo_multi_filter(const struct ip_moptions *imo, const struct ifnet *ifp,
    const struct sockaddr_in *group, const struct sockaddr_in *src)
{
	size_t gidx;
	struct in_msource *ims;
	int mode;

	IMO_LOCK_ASSERT_HELD(__DECONST(struct ip_moptions *, imo));
	VERIFY(ifp != NULL);

	gidx = imo_match_group(imo, ifp, group);
	if (gidx == (size_t)-1) {
		return MCAST_NOTGMEMBER;
	}

	/*
	 * Check if the source was included in an (S,G) join.
	 * Allow reception on exclusive memberships by default,
	 * reject reception on inclusive memberships by default.
	 * Exclude source only if an in-mode exclude filter exists.
	 * Include source only if an in-mode include filter exists.
	 * NOTE: We are comparing group state here at IGMP t1 (now)
	 * with socket-layer t0 (since last downcall).
	 */
	mode = imo->imo_mfilters[gidx].imf_st[1];
	ims = imo_match_source(imo, gidx, src);

	if ((ims == NULL && mode == MCAST_INCLUDE) ||
	    (ims != NULL && ims->imsl_st[0] != mode)) {
		return MCAST_NOTSMEMBER;
	}

	return MCAST_PASS;
}

int
imo_clone(struct inpcb *from_inp, struct inpcb *to_inp)
{
	int i, err = 0;
	struct ip_moptions *from;
	struct ip_moptions *to;

	from = inp_findmoptions(from_inp);
	if (from == NULL) {
		return ENOMEM;
	}

	to = inp_findmoptions(to_inp);
	if (to == NULL) {
		IMO_REMREF(from);
		return ENOMEM;
	}

	IMO_LOCK(from);
	IMO_LOCK(to);

	to->imo_multicast_ifp = from->imo_multicast_ifp;
	to->imo_multicast_vif = from->imo_multicast_vif;
	to->imo_multicast_ttl = from->imo_multicast_ttl;
	to->imo_multicast_loop = from->imo_multicast_loop;

	/*
	 * We're cloning, so drop any existing memberships and source
	 * filters on the destination ip_moptions.
	 */
	for (i = 0; i < to->imo_num_memberships; ++i) {
		struct in_mfilter *imf;

		imf = to->imo_mfilters ? &to->imo_mfilters[i] : NULL;
		if (imf != NULL) {
			imf_leave(imf);
		}

		(void) in_leavegroup(to->imo_membership[i], imf);

		if (imf != NULL) {
			imf_purge(imf);
		}

		INM_REMREF(to->imo_membership[i]);
		to->imo_membership[i] = NULL;
	}
	to->imo_num_memberships = 0;

	VERIFY(to->imo_max_memberships != 0 && from->imo_max_memberships != 0);
	if (to->imo_max_memberships < from->imo_max_memberships) {
		/*
		 * Ensure source and destination ip_moptions memberships
		 * and source filters arrays are at least equal in size.
		 */
		err = imo_grow(to, from->imo_max_memberships);
		if (err != 0) {
			goto done;
		}
	}
	VERIFY(to->imo_max_memberships >= from->imo_max_memberships);

	/*
	 * Source filtering doesn't apply to OpenTransport socket,
	 * so simply hold additional reference count per membership.
	 */
	for (i = 0; i < from->imo_num_memberships; i++) {
		to->imo_membership[i] =
		    in_addmulti(&from->imo_membership[i]->inm_addr,
		    from->imo_membership[i]->inm_ifp);
		if (to->imo_membership[i] == NULL) {
			break;
		}
		to->imo_num_memberships++;
	}
	VERIFY(to->imo_num_memberships == from->imo_num_memberships);

done:
	IMO_UNLOCK(to);
	IMO_REMREF(to);
	IMO_UNLOCK(from);
	IMO_REMREF(from);

	return err;
}

/*
 * Find and return a reference to an in_multi record for (ifp, group),
 * and bump its reference count.
 * If one does not exist, try to allocate it, and update link-layer multicast
 * filters on ifp to listen for group.
 * Return 0 if successful, otherwise return an appropriate error code.
 */
static int
in_getmulti(struct ifnet *ifp, const struct in_addr *group,
    struct in_multi **pinm)
{
	struct sockaddr_in       gsin;
	struct ifmultiaddr      *ifma;
	struct in_multi         *inm;
	int                     error;

	in_multihead_lock_shared();
	IN_LOOKUP_MULTI(group, ifp, inm);
	if (inm != NULL) {
		INM_LOCK(inm);
		VERIFY(inm->inm_reqcnt >= 1);
		inm->inm_reqcnt++;
		VERIFY(inm->inm_reqcnt != 0);
		*pinm = inm;
		INM_UNLOCK(inm);
		in_multihead_lock_done();
		/*
		 * We already joined this group; return the inm
		 * with a refcount held (via lookup) for caller.
		 */
		return 0;
	}
	in_multihead_lock_done();

	bzero(&gsin, sizeof(gsin));
	gsin.sin_family = AF_INET;
	gsin.sin_len = sizeof(struct sockaddr_in);
	gsin.sin_addr = *group;

	/*
	 * Check if a link-layer group is already associated
	 * with this network-layer group on the given ifnet.
	 */
	error = if_addmulti(ifp, (struct sockaddr *)&gsin, &ifma);
	if (error != 0) {
		return error;
	}

	/*
	 * See comments in inm_remref() for access to ifma_protospec.
	 */
	in_multihead_lock_exclusive();
	IFMA_LOCK(ifma);
	if ((inm = ifma->ifma_protospec) != NULL) {
		VERIFY(ifma->ifma_addr != NULL);
		VERIFY(ifma->ifma_addr->sa_family == AF_INET);
		INM_ADDREF(inm);        /* for caller */
		IFMA_UNLOCK(ifma);
		INM_LOCK(inm);
		VERIFY(inm->inm_ifma == ifma);
		VERIFY(inm->inm_ifp == ifp);
		VERIFY(in_hosteq(inm->inm_addr, *group));
		if (inm->inm_debug & IFD_ATTACHED) {
			VERIFY(inm->inm_reqcnt >= 1);
			inm->inm_reqcnt++;
			VERIFY(inm->inm_reqcnt != 0);
			*pinm = inm;
			INM_UNLOCK(inm);
			in_multihead_lock_done();
			IFMA_REMREF(ifma);
			/*
			 * We lost the race with another thread doing
			 * in_getmulti(); since this group has already
			 * been joined; return the inm with a refcount
			 * held for caller.
			 */
			return 0;
		}
		/*
		 * We lost the race with another thread doing in_delmulti();
		 * the inm referring to the ifma has been detached, thus we
		 * reattach it back to the in_multihead list and return the
		 * inm with a refcount held for the caller.
		 */
		in_multi_attach(inm);
		VERIFY((inm->inm_debug &
		    (IFD_ATTACHED | IFD_TRASHED)) == IFD_ATTACHED);
		*pinm = inm;
		INM_UNLOCK(inm);
		in_multihead_lock_done();
		IFMA_REMREF(ifma);
		return 0;
	}
	IFMA_UNLOCK(ifma);

	/*
	 * A new in_multi record is needed; allocate and initialize it.
	 * We DO NOT perform an IGMP join as the in_ layer may need to
	 * push an initial source list down to IGMP to support SSM.
	 *
	 * The initial source filter state is INCLUDE, {} as per the RFC.
	 */
	inm = in_multi_alloc(Z_WAITOK);

	INM_LOCK(inm);
	inm->inm_addr = *group;
	inm->inm_ifp = ifp;
	inm->inm_igi = IGMP_IFINFO(ifp);
	VERIFY(inm->inm_igi != NULL);
	IGI_ADDREF(inm->inm_igi);
	inm->inm_ifma = ifma;           /* keep refcount from if_addmulti() */
	inm->inm_state = IGMP_NOT_MEMBER;
	/*
	 * Pending state-changes per group are subject to a bounds check.
	 */
	inm->inm_scq.ifq_maxlen = IGMP_MAX_STATE_CHANGES;
	inm->inm_st[0].iss_fmode = MCAST_UNDEFINED;
	inm->inm_st[1].iss_fmode = MCAST_UNDEFINED;
	RB_INIT(&inm->inm_srcs);
	*pinm = inm;
	in_multi_attach(inm);
	VERIFY((inm->inm_debug & (IFD_ATTACHED | IFD_TRASHED)) == IFD_ATTACHED);
	INM_ADDREF_LOCKED(inm);         /* for caller */
	INM_UNLOCK(inm);

	IFMA_LOCK(ifma);
	VERIFY(ifma->ifma_protospec == NULL);
	ifma->ifma_protospec = inm;
	IFMA_UNLOCK(ifma);
	in_multihead_lock_done();

	return 0;
}

/*
 * Clear recorded source entries for a group.
 * Used by the IGMP code.
 * FIXME: Should reap.
 */
void
inm_clear_recorded(struct in_multi *inm)
{
	struct ip_msource       *ims;

	INM_LOCK_ASSERT_HELD(inm);

	RB_FOREACH(ims, ip_msource_tree, &inm->inm_srcs) {
		if (ims->ims_stp) {
			ims->ims_stp = 0;
			--inm->inm_st[1].iss_rec;
		}
	}
	VERIFY(inm->inm_st[1].iss_rec == 0);
}

/*
 * Record a source as pending for a Source-Group IGMPv3 query.
 * This lives here as it modifies the shared tree.
 *
 * inm is the group descriptor.
 * naddr is the address of the source to record in network-byte order.
 *
 * If the net.inet.igmp.sgalloc sysctl is non-zero, we will
 * lazy-allocate a source node in response to an SG query.
 * Otherwise, no allocation is performed. This saves some memory
 * with the trade-off that the source will not be reported to the
 * router if joined in the window between the query response and
 * the group actually being joined on the local host.
 *
 * Return 0 if the source didn't exist or was already marked as recorded.
 * Return 1 if the source was marked as recorded by this function.
 * Return <0 if any error occured (negated errno code).
 */
int
inm_record_source(struct in_multi *inm, const in_addr_t naddr)
{
	struct ip_msource        find;
	struct ip_msource       *ims, *nims;

	INM_LOCK_ASSERT_HELD(inm);

	find.ims_haddr = ntohl(naddr);
	ims = RB_FIND(ip_msource_tree, &inm->inm_srcs, &find);
	if (ims && ims->ims_stp) {
		return 0;
	}
	if (ims == NULL) {
		if (inm->inm_nsrc == in_mcast_maxgrpsrc) {
			return -ENOSPC;
		}
		nims = ipms_alloc(Z_WAITOK);
		nims->ims_haddr = find.ims_haddr;
		RB_INSERT(ip_msource_tree, &inm->inm_srcs, nims);
		++inm->inm_nsrc;
		ims = nims;
	}

	/*
	 * Mark the source as recorded and update the recorded
	 * source count.
	 */
	++ims->ims_stp;
	++inm->inm_st[1].iss_rec;

	return 1;
}

/*
 * Return a pointer to an in_msource owned by an in_mfilter,
 * given its source address.
 * Lazy-allocate if needed. If this is a new entry its filter state is
 * undefined at t0.
 *
 * imf is the filter set being modified.
 * haddr is the source address in *host* byte-order.
 *
 * Caller is expected to be holding imo_lock.
 */
static int
imf_get_source(struct in_mfilter *imf, const struct sockaddr_in *psin,
    struct in_msource **plims)
{
	struct ip_msource        find;
	struct ip_msource       *ims;
	struct in_msource       *lims;
	int                      error;

	error = 0;
	ims = NULL;
	lims = NULL;

	/* key is host byte order */
	find.ims_haddr = ntohl(psin->sin_addr.s_addr);
	ims = RB_FIND(ip_msource_tree, &imf->imf_sources, &find);
	lims = (struct in_msource *)ims;
	if (lims == NULL) {
		if (imf->imf_nsrc == in_mcast_maxsocksrc) {
			return ENOSPC;
		}
		lims = inms_alloc(Z_WAITOK);
		lims->ims_haddr = find.ims_haddr;
		lims->imsl_st[0] = MCAST_UNDEFINED;
		RB_INSERT(ip_msource_tree, &imf->imf_sources,
		    (struct ip_msource *)lims);
		++imf->imf_nsrc;
	}

	*plims = lims;

	return error;
}

/*
 * Graft a source entry into an existing socket-layer filter set,
 * maintaining any required invariants and checking allocations.
 *
 * The source is marked as being in the new filter mode at t1.
 *
 * Return the pointer to the new node, otherwise return NULL.
 *
 * Caller is expected to be holding imo_lock.
 */
static struct in_msource *
imf_graft(struct in_mfilter *imf, const uint8_t st1,
    const struct sockaddr_in *psin)
{
	struct in_msource       *lims;

	lims = inms_alloc(Z_WAITOK);
	lims->ims_haddr = ntohl(psin->sin_addr.s_addr);
	lims->imsl_st[0] = MCAST_UNDEFINED;
	lims->imsl_st[1] = st1;
	RB_INSERT(ip_msource_tree, &imf->imf_sources,
	    (struct ip_msource *)lims);
	++imf->imf_nsrc;

	return lims;
}

/*
 * Prune a source entry from an existing socket-layer filter set,
 * maintaining any required invariants and checking allocations.
 *
 * The source is marked as being left at t1, it is not freed.
 *
 * Return 0 if no error occurred, otherwise return an errno value.
 *
 * Caller is expected to be holding imo_lock.
 */
static int
imf_prune(struct in_mfilter *imf, const struct sockaddr_in *psin)
{
	struct ip_msource        find;
	struct ip_msource       *ims;
	struct in_msource       *lims;

	/* key is host byte order */
	find.ims_haddr = ntohl(psin->sin_addr.s_addr);
	ims = RB_FIND(ip_msource_tree, &imf->imf_sources, &find);
	if (ims == NULL) {
		return ENOENT;
	}
	lims = (struct in_msource *)ims;
	lims->imsl_st[1] = MCAST_UNDEFINED;
	return 0;
}

/*
 * Revert socket-layer filter set deltas at t1 to t0 state.
 *
 * Caller is expected to be holding imo_lock.
 */
static void
imf_rollback(struct in_mfilter *imf)
{
	struct ip_msource       *ims, *tims;
	struct in_msource       *lims;

	RB_FOREACH_SAFE(ims, ip_msource_tree, &imf->imf_sources, tims) {
		lims = (struct in_msource *)ims;
		if (lims->imsl_st[0] == lims->imsl_st[1]) {
			/* no change at t1 */
			continue;
		} else if (lims->imsl_st[0] != MCAST_UNDEFINED) {
			/* revert change to existing source at t1 */
			lims->imsl_st[1] = lims->imsl_st[0];
		} else {
			/* revert source added t1 */
			IGMP_PRINTF(("%s: free inms 0x%llx\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(lims)));
			RB_REMOVE(ip_msource_tree, &imf->imf_sources, ims);
			inms_free(lims);
			imf->imf_nsrc--;
		}
	}
	imf->imf_st[1] = imf->imf_st[0];
}

/*
 * Mark socket-layer filter set as INCLUDE {} at t1.
 *
 * Caller is expected to be holding imo_lock.
 */
void
imf_leave(struct in_mfilter *imf)
{
	struct ip_msource       *ims;
	struct in_msource       *lims;

	RB_FOREACH(ims, ip_msource_tree, &imf->imf_sources) {
		lims = (struct in_msource *)ims;
		lims->imsl_st[1] = MCAST_UNDEFINED;
	}
	imf->imf_st[1] = MCAST_INCLUDE;
}

/*
 * Mark socket-layer filter set deltas as committed.
 *
 * Caller is expected to be holding imo_lock.
 */
static void
imf_commit(struct in_mfilter *imf)
{
	struct ip_msource       *ims;
	struct in_msource       *lims;

	RB_FOREACH(ims, ip_msource_tree, &imf->imf_sources) {
		lims = (struct in_msource *)ims;
		lims->imsl_st[0] = lims->imsl_st[1];
	}
	imf->imf_st[0] = imf->imf_st[1];
}

/*
 * Reap unreferenced sources from socket-layer filter set.
 *
 * Caller is expected to be holding imo_lock.
 */
static void
imf_reap(struct in_mfilter *imf)
{
	struct ip_msource       *ims, *tims;
	struct in_msource       *lims;

	RB_FOREACH_SAFE(ims, ip_msource_tree, &imf->imf_sources, tims) {
		lims = (struct in_msource *)ims;
		if ((lims->imsl_st[0] == MCAST_UNDEFINED) &&
		    (lims->imsl_st[1] == MCAST_UNDEFINED)) {
			IGMP_PRINTF(("%s: free inms 0x%llx\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(lims)));
			RB_REMOVE(ip_msource_tree, &imf->imf_sources, ims);
			inms_free(lims);
			imf->imf_nsrc--;
		}
	}
}

/*
 * Purge socket-layer filter set.
 *
 * Caller is expected to be holding imo_lock.
 */
void
imf_purge(struct in_mfilter *imf)
{
	struct ip_msource       *ims, *tims;
	struct in_msource       *lims;

	RB_FOREACH_SAFE(ims, ip_msource_tree, &imf->imf_sources, tims) {
		lims = (struct in_msource *)ims;
		IGMP_PRINTF(("%s: free inms 0x%llx\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(lims)));
		RB_REMOVE(ip_msource_tree, &imf->imf_sources, ims);
		inms_free(lims);
		imf->imf_nsrc--;
	}
	imf->imf_st[0] = imf->imf_st[1] = MCAST_UNDEFINED;
	VERIFY(RB_EMPTY(&imf->imf_sources));
}

/*
 * Look up a source filter entry for a multicast group.
 *
 * inm is the group descriptor to work with.
 * haddr is the host-byte-order IPv4 address to look up.
 * noalloc may be non-zero to suppress allocation of sources.
 * *pims will be set to the address of the retrieved or allocated source.
 *
 * Return 0 if successful, otherwise return a non-zero error code.
 */
static int
inm_get_source(struct in_multi *inm, const in_addr_t haddr,
    const int noalloc, struct ip_msource **pims)
{
	struct ip_msource        find;
	struct ip_msource       *ims, *nims;
#ifdef IGMP_DEBUG
	struct in_addr ia;
	char buf[MAX_IPv4_STR_LEN];
#endif
	INM_LOCK_ASSERT_HELD(inm);

	find.ims_haddr = haddr;
	ims = RB_FIND(ip_msource_tree, &inm->inm_srcs, &find);
	if (ims == NULL && !noalloc) {
		if (inm->inm_nsrc == in_mcast_maxgrpsrc) {
			return ENOSPC;
		}
		nims = ipms_alloc(Z_WAITOK);
		nims->ims_haddr = haddr;
		RB_INSERT(ip_msource_tree, &inm->inm_srcs, nims);
		++inm->inm_nsrc;
		ims = nims;
#ifdef IGMP_DEBUG
		ia.s_addr = htonl(haddr);
		inet_ntop(AF_INET, &ia, buf, sizeof(buf));
		IGMP_PRINTF(("%s: allocated %s as 0x%llx\n", __func__,
		    buf, (uint64_t)VM_KERNEL_ADDRPERM(ims)));
#endif
	}

	*pims = ims;
	return 0;
}

/*
 * Helper function to derive the filter mode on a source entry
 * from its internal counters. Predicates are:
 *  A source is only excluded if all listeners exclude it.
 *  A source is only included if no listeners exclude it,
 *  and at least one listener includes it.
 * May be used by ifmcstat(8).
 */
uint8_t
ims_get_mode(const struct in_multi *inm, const struct ip_msource *ims,
    uint8_t t)
{
	INM_LOCK_ASSERT_HELD(__DECONST(struct in_multi *, inm));

	t = !!t;
	if (inm->inm_st[t].iss_ex > 0 &&
	    inm->inm_st[t].iss_ex == ims->ims_st[t].ex) {
		return MCAST_EXCLUDE;
	} else if (ims->ims_st[t].in > 0 && ims->ims_st[t].ex == 0) {
		return MCAST_INCLUDE;
	}
	return MCAST_UNDEFINED;
}

/*
 * Merge socket-layer source into IGMP-layer source.
 * If rollback is non-zero, perform the inverse of the merge.
 */
static void
ims_merge(struct ip_msource *ims, const struct in_msource *lims,
    const int rollback)
{
	int n = rollback ? -1 : 1;
#ifdef IGMP_DEBUG
	struct in_addr ia;

	ia.s_addr = htonl(ims->ims_haddr);
#endif

	if (lims->imsl_st[0] == MCAST_EXCLUDE) {
		IGMP_INET_PRINTF(ia,
		    ("%s: t1 ex -= %d on %s\n",
		    __func__, n, _igmp_inet_buf));
		ims->ims_st[1].ex -= n;
	} else if (lims->imsl_st[0] == MCAST_INCLUDE) {
		IGMP_INET_PRINTF(ia,
		    ("%s: t1 in -= %d on %s\n",
		    __func__, n, _igmp_inet_buf));
		ims->ims_st[1].in -= n;
	}

	if (lims->imsl_st[1] == MCAST_EXCLUDE) {
		IGMP_INET_PRINTF(ia,
		    ("%s: t1 ex += %d on %s\n",
		    __func__, n, _igmp_inet_buf));
		ims->ims_st[1].ex += n;
	} else if (lims->imsl_st[1] == MCAST_INCLUDE) {
		IGMP_INET_PRINTF(ia,
		    ("%s: t1 in += %d on %s\n",
		    __func__, n, _igmp_inet_buf));
		ims->ims_st[1].in += n;
	}
}

/*
 * Atomically update the global in_multi state, when a membership's
 * filter list is being updated in any way.
 *
 * imf is the per-inpcb-membership group filter pointer.
 * A fake imf may be passed for in-kernel consumers.
 *
 * XXX This is a candidate for a set-symmetric-difference style loop
 * which would eliminate the repeated lookup from root of ims nodes,
 * as they share the same key space.
 *
 * If any error occurred this function will back out of refcounts
 * and return a non-zero value.
 */
static int
inm_merge(struct in_multi *inm, /*const*/ struct in_mfilter *imf)
{
	struct ip_msource       *ims, *nims = NULL;
	struct in_msource       *lims;
	int                      schanged, error;
	int                      nsrc0, nsrc1;

	INM_LOCK_ASSERT_HELD(inm);

	schanged = 0;
	error = 0;
	nsrc1 = nsrc0 = 0;

	/*
	 * Update the source filters first, as this may fail.
	 * Maintain count of in-mode filters at t0, t1. These are
	 * used to work out if we transition into ASM mode or not.
	 * Maintain a count of source filters whose state was
	 * actually modified by this operation.
	 */
	RB_FOREACH(ims, ip_msource_tree, &imf->imf_sources) {
		lims = (struct in_msource *)ims;
		if (lims->imsl_st[0] == imf->imf_st[0]) {
			nsrc0++;
		}
		if (lims->imsl_st[1] == imf->imf_st[1]) {
			nsrc1++;
		}
		if (lims->imsl_st[0] == lims->imsl_st[1]) {
			continue;
		}
		error = inm_get_source(inm, lims->ims_haddr, 0, &nims);
		++schanged;
		if (error) {
			break;
		}
		ims_merge(nims, lims, 0);
	}
	if (error) {
		struct ip_msource *bims;

		RB_FOREACH_REVERSE_FROM(ims, ip_msource_tree, nims) {
			lims = (struct in_msource *)ims;
			if (lims->imsl_st[0] == lims->imsl_st[1]) {
				continue;
			}
			(void) inm_get_source(inm, lims->ims_haddr, 1, &bims);
			if (bims == NULL) {
				continue;
			}
			ims_merge(bims, lims, 1);
		}
		goto out_reap;
	}

	IGMP_PRINTF(("%s: imf filters in-mode: %d at t0, %d at t1\n",
	    __func__, nsrc0, nsrc1));

	/* Handle transition between INCLUDE {n} and INCLUDE {} on socket. */
	if (imf->imf_st[0] == imf->imf_st[1] &&
	    imf->imf_st[1] == MCAST_INCLUDE) {
		if (nsrc1 == 0) {
			IGMP_PRINTF(("%s: --in on inm at t1\n", __func__));
			--inm->inm_st[1].iss_in;
		}
	}

	/* Handle filter mode transition on socket. */
	if (imf->imf_st[0] != imf->imf_st[1]) {
		IGMP_PRINTF(("%s: imf transition %d to %d\n",
		    __func__, imf->imf_st[0], imf->imf_st[1]));

		if (imf->imf_st[0] == MCAST_EXCLUDE) {
			IGMP_PRINTF(("%s: --ex on inm at t1\n", __func__));
			--inm->inm_st[1].iss_ex;
		} else if (imf->imf_st[0] == MCAST_INCLUDE) {
			IGMP_PRINTF(("%s: --in on inm at t1\n", __func__));
			--inm->inm_st[1].iss_in;
		}

		if (imf->imf_st[1] == MCAST_EXCLUDE) {
			IGMP_PRINTF(("%s: ex++ on inm at t1\n", __func__));
			inm->inm_st[1].iss_ex++;
		} else if (imf->imf_st[1] == MCAST_INCLUDE && nsrc1 > 0) {
			IGMP_PRINTF(("%s: in++ on inm at t1\n", __func__));
			inm->inm_st[1].iss_in++;
		}
	}

	/*
	 * Track inm filter state in terms of listener counts.
	 * If there are any exclusive listeners, stack-wide
	 * membership is exclusive.
	 * Otherwise, if only inclusive listeners, stack-wide is inclusive.
	 * If no listeners remain, state is undefined at t1,
	 * and the IGMP lifecycle for this group should finish.
	 */
	if (inm->inm_st[1].iss_ex > 0) {
		IGMP_PRINTF(("%s: transition to EX\n", __func__));
		inm->inm_st[1].iss_fmode = MCAST_EXCLUDE;
	} else if (inm->inm_st[1].iss_in > 0) {
		IGMP_PRINTF(("%s: transition to IN\n", __func__));
		inm->inm_st[1].iss_fmode = MCAST_INCLUDE;
	} else {
		IGMP_PRINTF(("%s: transition to UNDEF\n", __func__));
		inm->inm_st[1].iss_fmode = MCAST_UNDEFINED;
	}

	/* Decrement ASM listener count on transition out of ASM mode. */
	if (imf->imf_st[0] == MCAST_EXCLUDE && nsrc0 == 0) {
		if ((imf->imf_st[1] != MCAST_EXCLUDE) ||
		    (imf->imf_st[1] == MCAST_EXCLUDE && nsrc1 > 0)) {
			IGMP_PRINTF(("%s: --asm on inm at t1\n", __func__));
			--inm->inm_st[1].iss_asm;
		}
	}

	/* Increment ASM listener count on transition to ASM mode. */
	if (imf->imf_st[1] == MCAST_EXCLUDE && nsrc1 == 0) {
		IGMP_PRINTF(("%s: asm++ on inm at t1\n", __func__));
		inm->inm_st[1].iss_asm++;
	}

	IGMP_PRINTF(("%s: merged imf 0x%llx to inm 0x%llx\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(imf),
	    (uint64_t)VM_KERNEL_ADDRPERM(inm)));
	inm_print(inm);

out_reap:
	if (schanged > 0) {
		IGMP_PRINTF(("%s: sources changed; reaping\n", __func__));
		inm_reap(inm);
	}
	return error;
}

/*
 * Mark an in_multi's filter set deltas as committed.
 * Called by IGMP after a state change has been enqueued.
 */
void
inm_commit(struct in_multi *inm)
{
	struct ip_msource       *ims;

	INM_LOCK_ASSERT_HELD(inm);

	IGMP_PRINTF(("%s: commit inm 0x%llx\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(inm)));
	IGMP_PRINTF(("%s: pre commit:\n", __func__));
	inm_print(inm);

	RB_FOREACH(ims, ip_msource_tree, &inm->inm_srcs) {
		ims->ims_st[0] = ims->ims_st[1];
	}
	inm->inm_st[0] = inm->inm_st[1];
}

/*
 * Reap unreferenced nodes from an in_multi's filter set.
 */
static void
inm_reap(struct in_multi *inm)
{
	struct ip_msource       *ims, *tims;

	INM_LOCK_ASSERT_HELD(inm);

	RB_FOREACH_SAFE(ims, ip_msource_tree, &inm->inm_srcs, tims) {
		if (ims->ims_st[0].ex > 0 || ims->ims_st[0].in > 0 ||
		    ims->ims_st[1].ex > 0 || ims->ims_st[1].in > 0 ||
		    ims->ims_stp != 0) {
			continue;
		}
		IGMP_PRINTF(("%s: free ims 0x%llx\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(ims)));
		RB_REMOVE(ip_msource_tree, &inm->inm_srcs, ims);
		ipms_free(ims);
		inm->inm_nsrc--;
	}
}

/*
 * Purge all source nodes from an in_multi's filter set.
 */
void
inm_purge(struct in_multi *inm)
{
	struct ip_msource       *ims, *tims;

	INM_LOCK_ASSERT_HELD(inm);

	RB_FOREACH_SAFE(ims, ip_msource_tree, &inm->inm_srcs, tims) {
		IGMP_PRINTF(("%s: free ims 0x%llx\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(ims)));
		RB_REMOVE(ip_msource_tree, &inm->inm_srcs, ims);
		ipms_free(ims);
		inm->inm_nsrc--;
	}
}

/*
 * Join a multicast group; real entry point.
 *
 * Only preserves atomicity at inm level.
 * NOTE: imf argument cannot be const due to sys/tree.h limitations.
 *
 * If the IGMP downcall fails, the group is not joined, and an error
 * code is returned.
 */
static int
in_joingroup(struct ifnet *ifp, const struct in_addr *gina,
    /*const*/ struct in_mfilter *imf, struct in_multi **pinm)
{
	struct in_mfilter        timf;
	struct in_multi         *inm = NULL;
	int                      error = 0;
	struct igmp_tparams      itp;

	IGMP_INET_PRINTF(*gina, ("%s: join %s on 0x%llx(%s))\n", __func__,
	    _igmp_inet_buf, (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));

	bzero(&itp, sizeof(itp));
	*pinm = NULL;

	/*
	 * If no imf was specified (i.e. kernel consumer),
	 * fake one up and assume it is an ASM join.
	 */
	if (imf == NULL) {
		imf_init(&timf, MCAST_UNDEFINED, MCAST_EXCLUDE);
		imf = &timf;
	}

	error = in_getmulti(ifp, gina, &inm);
	if (error) {
		IGMP_PRINTF(("%s: in_getmulti() failure\n", __func__));
		return error;
	}

	IGMP_PRINTF(("%s: merge inm state\n", __func__));

	INM_LOCK(inm);
	error = inm_merge(inm, imf);
	if (error) {
		IGMP_PRINTF(("%s: failed to merge inm state\n", __func__));
		goto out_inm_release;
	}

	IGMP_PRINTF(("%s: doing igmp downcall\n", __func__));
	error = igmp_change_state(inm, &itp);
	if (error) {
		IGMP_PRINTF(("%s: failed to update source\n", __func__));
		imf_rollback(imf);
		goto out_inm_release;
	}

out_inm_release:
	if (error) {
		IGMP_PRINTF(("%s: dropping ref on 0x%llx\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(inm)));
		INM_UNLOCK(inm);
		INM_REMREF(inm);
	} else {
		INM_UNLOCK(inm);
		*pinm = inm;    /* keep refcount from in_getmulti() */
	}

	/* schedule timer now that we've dropped the lock(s) */
	igmp_set_timeout(&itp);

	return error;
}

/*
 * Leave a multicast group; real entry point.
 * All source filters will be expunged.
 *
 * Only preserves atomicity at inm level.
 *
 * Note: This is not the same as inm_release(*) as this function also
 * makes a state change downcall into IGMP.
 */
int
in_leavegroup(struct in_multi *inm, /*const*/ struct in_mfilter *imf)
{
	struct in_mfilter        timf;
	int                      error, lastref;
	struct igmp_tparams      itp;

	bzero(&itp, sizeof(itp));
	error = 0;

	INM_LOCK_ASSERT_NOTHELD(inm);

	in_multihead_lock_exclusive();
	INM_LOCK(inm);

	IGMP_INET_PRINTF(inm->inm_addr,
	    ("%s: leave inm 0x%llx, %s/%s%d, imf 0x%llx\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(inm), _igmp_inet_buf,
	    (inm_is_ifp_detached(inm) ? "null" : inm->inm_ifp->if_name),
	    inm->inm_ifp->if_unit, (uint64_t)VM_KERNEL_ADDRPERM(imf)));

	/*
	 * If no imf was specified (i.e. kernel consumer),
	 * fake one up and assume it is an ASM join.
	 */
	if (imf == NULL) {
		imf_init(&timf, MCAST_EXCLUDE, MCAST_UNDEFINED);
		imf = &timf;
	}

	/*
	 * Begin state merge transaction at IGMP layer.
	 *
	 * As this particular invocation should not cause any memory
	 * to be allocated, and there is no opportunity to roll back
	 * the transaction, it MUST NOT fail.
	 */
	IGMP_PRINTF(("%s: merge inm state\n", __func__));

	error = inm_merge(inm, imf);
	KASSERT(error == 0, ("%s: failed to merge inm state\n", __func__));

	IGMP_PRINTF(("%s: doing igmp downcall\n", __func__));
	error = igmp_change_state(inm, &itp);
#if IGMP_DEBUG
	if (error) {
		IGMP_PRINTF(("%s: failed igmp downcall\n", __func__));
	}
#endif
	lastref = in_multi_detach(inm);
	VERIFY(!lastref || (!(inm->inm_debug & IFD_ATTACHED) &&
	    inm->inm_reqcnt == 0));
	INM_UNLOCK(inm);
	in_multihead_lock_done();

	if (lastref) {
		INM_REMREF(inm);        /* for in_multihead list */
	}
	/* schedule timer now that we've dropped the lock(s) */
	igmp_set_timeout(&itp);

	return error;
}

/*
 * Join an IPv4 multicast group in (*,G) exclusive mode.
 * The group must be a 224.0.0.0/24 link-scope group.
 * This KPI is for legacy kernel consumers only.
 */
struct in_multi *
in_addmulti(struct in_addr *ap, struct ifnet *ifp)
{
	struct in_multi *pinm = NULL;
	int error;

	KASSERT(IN_LOCAL_GROUP(ntohl(ap->s_addr)),
	    ("%s: %s not in 224.0.0.0/24\n", __func__, inet_ntoa(*ap)));

	error = in_joingroup(ifp, ap, NULL, &pinm);
	VERIFY(pinm != NULL || error != 0);

	return pinm;
}

/*
 * Leave an IPv4 multicast group, assumed to be in exclusive (*,G) mode.
 * This KPI is for legacy kernel consumers only.
 */
void
in_delmulti(struct in_multi *inm)
{
	(void) in_leavegroup(inm, NULL);
}

/*
 * Block or unblock an ASM multicast source on an inpcb.
 * This implements the delta-based API described in RFC 3678.
 *
 * The delta-based API applies only to exclusive-mode memberships.
 * An IGMP downcall will be performed.
 *
 * Return 0 if successful, otherwise return an appropriate error code.
 */
static int
inp_block_unblock_source(struct inpcb *inp, struct sockopt *sopt)
{
	struct group_source_req          gsr;
	struct sockaddr_in              *gsa, *ssa;
	struct ifnet                    *ifp;
	struct in_mfilter               *imf;
	struct ip_moptions              *imo;
	struct in_msource               *ims;
	struct in_multi                 *inm;
	size_t                           idx;
	uint8_t                          fmode;
	int                              error, doblock;
	unsigned int                     ifindex = 0;
	struct igmp_tparams              itp;

	bzero(&itp, sizeof(itp));
	ifp = NULL;
	error = 0;
	doblock = 0;

	memset(&gsr, 0, sizeof(struct group_source_req));
	gsa = (struct sockaddr_in *)&gsr.gsr_group;
	ssa = (struct sockaddr_in *)&gsr.gsr_source;

	switch (sopt->sopt_name) {
	case IP_BLOCK_SOURCE:
	case IP_UNBLOCK_SOURCE: {
		struct ip_mreq_source    mreqs;

		error = sooptcopyin(sopt, &mreqs,
		    sizeof(struct ip_mreq_source),
		    sizeof(struct ip_mreq_source));
		if (error) {
			return error;
		}

		gsa->sin_family = AF_INET;
		gsa->sin_len = sizeof(struct sockaddr_in);
		gsa->sin_addr = mreqs.imr_multiaddr;

		ssa->sin_family = AF_INET;
		ssa->sin_len = sizeof(struct sockaddr_in);
		ssa->sin_addr = mreqs.imr_sourceaddr;

		if (!in_nullhost(mreqs.imr_interface)) {
			ifp = ip_multicast_if(&mreqs.imr_interface, &ifindex);
		}

		if (sopt->sopt_name == IP_BLOCK_SOURCE) {
			doblock = 1;
		}

		IGMP_INET_PRINTF(mreqs.imr_interface,
		    ("%s: imr_interface = %s, ifp = 0x%llx\n", __func__,
		    _igmp_inet_buf, (uint64_t)VM_KERNEL_ADDRPERM(ifp)));
		break;
	}

	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
		error = sooptcopyin(sopt, &gsr,
		    sizeof(struct group_source_req),
		    sizeof(struct group_source_req));
		if (error) {
			return error;
		}

		if (gsa->sin_family != AF_INET ||
		    gsa->sin_len != sizeof(struct sockaddr_in)) {
			return EINVAL;
		}

		if (ssa->sin_family != AF_INET ||
		    ssa->sin_len != sizeof(struct sockaddr_in)) {
			return EINVAL;
		}

		ifnet_head_lock_shared();
		if (gsr.gsr_interface == 0 ||
		    (u_int)if_index < gsr.gsr_interface) {
			ifnet_head_done();
			return EADDRNOTAVAIL;
		}

		ifp = ifindex2ifnet[gsr.gsr_interface];
		ifnet_head_done();

		if (ifp == NULL) {
			return EADDRNOTAVAIL;
		}

		if (sopt->sopt_name == MCAST_BLOCK_SOURCE) {
			doblock = 1;
		}
		break;

	default:
		IGMP_PRINTF(("%s: unknown sopt_name %d\n",
		    __func__, sopt->sopt_name));
		return EOPNOTSUPP;
	}

	if (!IN_MULTICAST(ntohl(gsa->sin_addr.s_addr))) {
		return EINVAL;
	}

	/*
	 * Check if we are actually a member of this group.
	 */
	imo = inp_findmoptions(inp);
	if (imo == NULL) {
		return ENOMEM;
	}

	IMO_LOCK(imo);
	idx = imo_match_group(imo, ifp, gsa);
	if (idx == (size_t)-1 || imo->imo_mfilters == NULL) {
		error = EADDRNOTAVAIL;
		goto out_imo_locked;
	}

	VERIFY(imo->imo_mfilters != NULL);
	imf = &imo->imo_mfilters[idx];
	inm = imo->imo_membership[idx];

	/*
	 * Attempting to use the delta-based API on an
	 * non exclusive-mode membership is an error.
	 */
	fmode = imf->imf_st[0];
	if (fmode != MCAST_EXCLUDE) {
		error = EINVAL;
		goto out_imo_locked;
	}

	/*
	 * Deal with error cases up-front:
	 *  Asked to block, but already blocked; or
	 *  Asked to unblock, but nothing to unblock.
	 * If adding a new block entry, allocate it.
	 */
	ims = imo_match_source(imo, idx, ssa);
	if ((ims != NULL && doblock) || (ims == NULL && !doblock)) {
		IGMP_INET_PRINTF(ssa->sin_addr,
		    ("%s: source %s %spresent\n", __func__,
		    _igmp_inet_buf, doblock ? "" : "not "));
		error = EADDRNOTAVAIL;
		goto out_imo_locked;
	}

	/*
	 * Begin state merge transaction at socket layer.
	 */
	if (doblock) {
		IGMP_PRINTF(("%s: %s source\n", __func__, "block"));
		ims = imf_graft(imf, fmode, ssa);
		if (ims == NULL) {
			error = ENOMEM;
		}
	} else {
		IGMP_PRINTF(("%s: %s source\n", __func__, "allow"));
		error = imf_prune(imf, ssa);
	}

	if (error) {
		IGMP_PRINTF(("%s: merge imf state failed\n", __func__));
		goto out_imf_rollback;
	}

	/*
	 * Begin state merge transaction at IGMP layer.
	 */
	INM_LOCK(inm);
	IGMP_PRINTF(("%s: merge inm state\n", __func__));
	error = inm_merge(inm, imf);
	if (error) {
		IGMP_PRINTF(("%s: failed to merge inm state\n", __func__));
		INM_UNLOCK(inm);
		goto out_imf_rollback;
	}

	IGMP_PRINTF(("%s: doing igmp downcall\n", __func__));
	error = igmp_change_state(inm, &itp);
	INM_UNLOCK(inm);
#if IGMP_DEBUG
	if (error) {
		IGMP_PRINTF(("%s: failed igmp downcall\n", __func__));
	}
#endif

out_imf_rollback:
	if (error) {
		imf_rollback(imf);
	} else {
		imf_commit(imf);
	}

	imf_reap(imf);

out_imo_locked:
	IMO_UNLOCK(imo);
	IMO_REMREF(imo);        /* from inp_findmoptions() */

	/* schedule timer now that we've dropped the lock(s) */
	igmp_set_timeout(&itp);

	return error;
}

/*
 * Given an inpcb, return its multicast options structure pointer.
 *
 * Caller is responsible for locking the inpcb, and releasing the
 * extra reference held on the imo, upon a successful return.
 */
static struct ip_moptions *
inp_findmoptions(struct inpcb *inp)
{
	struct ip_moptions       *imo;
	struct in_multi         **immp;
	struct in_mfilter        *imfp;
	size_t                    idx;

	if ((imo = inp->inp_moptions) != NULL) {
		IMO_ADDREF(imo);        /* for caller */
		return imo;
	}

	imo = ip_allocmoptions(Z_WAITOK);
	if (imo == NULL) {
		return NULL;
	}

	immp = _MALLOC(sizeof(*immp) * IP_MIN_MEMBERSHIPS, M_IPMOPTS,
	    M_WAITOK | M_ZERO);
	if (immp == NULL) {
		IMO_REMREF(imo);
		return NULL;
	}

	imfp = _MALLOC(sizeof(struct in_mfilter) * IP_MIN_MEMBERSHIPS,
	    M_INMFILTER, M_WAITOK | M_ZERO);
	if (imfp == NULL) {
		_FREE(immp, M_IPMOPTS);
		IMO_REMREF(imo);
		return NULL;
	}

	imo->imo_multicast_ifp = NULL;
	imo->imo_multicast_addr.s_addr = INADDR_ANY;
	imo->imo_multicast_vif = -1;
	imo->imo_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;
	imo->imo_multicast_loop = !!in_mcast_loop;
	imo->imo_num_memberships = 0;
	imo->imo_max_memberships = IP_MIN_MEMBERSHIPS;
	imo->imo_membership = immp;

	/* Initialize per-group source filters. */
	for (idx = 0; idx < IP_MIN_MEMBERSHIPS; idx++) {
		imf_init(&imfp[idx], MCAST_UNDEFINED, MCAST_EXCLUDE);
	}

	imo->imo_mfilters = imfp;
	inp->inp_moptions = imo; /* keep reference from ip_allocmoptions() */
	IMO_ADDREF(imo);        /* for caller */

	return imo;
}
/*
 * Atomically get source filters on a socket for an IPv4 multicast group.
 */
static int
inp_get_source_filters(struct inpcb *inp, struct sockopt *sopt)
{
	struct __msfilterreq64  msfr = {}, msfr64;
	struct __msfilterreq32  msfr32;
	struct sockaddr_in      *gsa;
	struct ifnet            *ifp;
	struct ip_moptions      *imo;
	struct in_mfilter       *imf;
	struct ip_msource       *ims;
	struct in_msource       *lims;
	struct sockaddr_in      *psin;
	struct sockaddr_storage *ptss;
	struct sockaddr_storage *tss;
	int                      error;
	size_t                   idx;
	uint32_t                 nsrcs, ncsrcs;
	user_addr_t              tmp_ptr;

	imo = inp->inp_moptions;
	VERIFY(imo != NULL);

	if (IS_64BIT_PROCESS(current_proc())) {
		error = sooptcopyin(sopt, &msfr64,
		    sizeof(struct __msfilterreq64),
		    sizeof(struct __msfilterreq64));
		if (error) {
			return error;
		}
		/* we never use msfr.msfr_srcs; */
		memcpy(&msfr, &msfr64, sizeof(msfr64));
	} else {
		error = sooptcopyin(sopt, &msfr32,
		    sizeof(struct __msfilterreq32),
		    sizeof(struct __msfilterreq32));
		if (error) {
			return error;
		}
		/* we never use msfr.msfr_srcs; */
		memcpy(&msfr, &msfr32, sizeof(msfr32));
	}

	ifnet_head_lock_shared();
	if (msfr.msfr_ifindex == 0 || (u_int)if_index < msfr.msfr_ifindex) {
		ifnet_head_done();
		return EADDRNOTAVAIL;
	}

	ifp = ifindex2ifnet[msfr.msfr_ifindex];
	ifnet_head_done();

	if (ifp == NULL) {
		return EADDRNOTAVAIL;
	}

	if ((size_t) msfr.msfr_nsrcs >
	    UINT32_MAX / sizeof(struct sockaddr_storage)) {
		msfr.msfr_nsrcs = UINT32_MAX / sizeof(struct sockaddr_storage);
	}

	if (msfr.msfr_nsrcs > in_mcast_maxsocksrc) {
		msfr.msfr_nsrcs = in_mcast_maxsocksrc;
	}

	IMO_LOCK(imo);
	/*
	 * Lookup group on the socket.
	 */
	gsa = (struct sockaddr_in *)&msfr.msfr_group;

	idx = imo_match_group(imo, ifp, gsa);
	if (idx == (size_t)-1 || imo->imo_mfilters == NULL) {
		IMO_UNLOCK(imo);
		return EADDRNOTAVAIL;
	}
	imf = &imo->imo_mfilters[idx];

	/*
	 * Ignore memberships which are in limbo.
	 */
	if (imf->imf_st[1] == MCAST_UNDEFINED) {
		IMO_UNLOCK(imo);
		return EAGAIN;
	}
	msfr.msfr_fmode = imf->imf_st[1];

	/*
	 * If the user specified a buffer, copy out the source filter
	 * entries to userland gracefully.
	 * We only copy out the number of entries which userland
	 * has asked for, but we always tell userland how big the
	 * buffer really needs to be.
	 */

	if (IS_64BIT_PROCESS(current_proc())) {
		tmp_ptr = CAST_USER_ADDR_T(msfr64.msfr_srcs);
	} else {
		tmp_ptr = CAST_USER_ADDR_T(msfr32.msfr_srcs);
	}

	tss = NULL;
	if (tmp_ptr != USER_ADDR_NULL && msfr.msfr_nsrcs > 0) {
		tss = _MALLOC((size_t) msfr.msfr_nsrcs * sizeof(*tss),
		    M_TEMP, M_WAITOK | M_ZERO);
		if (tss == NULL) {
			IMO_UNLOCK(imo);
			return ENOBUFS;
		}
	}

	/*
	 * Count number of sources in-mode at t0.
	 * If buffer space exists and remains, copy out source entries.
	 */
	nsrcs = msfr.msfr_nsrcs;
	ncsrcs = 0;
	ptss = tss;
	RB_FOREACH(ims, ip_msource_tree, &imf->imf_sources) {
		lims = (struct in_msource *)ims;
		if (lims->imsl_st[0] == MCAST_UNDEFINED ||
		    lims->imsl_st[0] != imf->imf_st[0]) {
			continue;
		}
		if (tss != NULL && nsrcs > 0) {
			psin = (struct sockaddr_in *)ptss;
			psin->sin_family = AF_INET;
			psin->sin_len = sizeof(struct sockaddr_in);
			psin->sin_addr.s_addr = htonl(lims->ims_haddr);
			psin->sin_port = 0;
			++ptss;
			--nsrcs;
			++ncsrcs;
		}
	}

	IMO_UNLOCK(imo);

	if (tss != NULL) {
		error = copyout(tss, CAST_USER_ADDR_T(tmp_ptr), ncsrcs * sizeof(*tss));
		FREE(tss, M_TEMP);
		if (error) {
			return error;
		}
	}

	msfr.msfr_nsrcs = ncsrcs;
	if (IS_64BIT_PROCESS(current_proc())) {
		msfr64.msfr_ifindex = msfr.msfr_ifindex;
		msfr64.msfr_fmode   = msfr.msfr_fmode;
		msfr64.msfr_nsrcs   = msfr.msfr_nsrcs;
		memcpy(&msfr64.msfr_group, &msfr.msfr_group,
		    sizeof(struct sockaddr_storage));
		error = sooptcopyout(sopt, &msfr64,
		    sizeof(struct __msfilterreq64));
	} else {
		msfr32.msfr_ifindex = msfr.msfr_ifindex;
		msfr32.msfr_fmode   = msfr.msfr_fmode;
		msfr32.msfr_nsrcs   = msfr.msfr_nsrcs;
		memcpy(&msfr32.msfr_group, &msfr.msfr_group,
		    sizeof(struct sockaddr_storage));
		error = sooptcopyout(sopt, &msfr32,
		    sizeof(struct __msfilterreq32));
	}

	return error;
}

/*
 * Return the IP multicast options in response to user getsockopt().
 */
int
inp_getmoptions(struct inpcb *inp, struct sockopt *sopt)
{
	struct ip_mreqn          mreqn;
	struct ip_moptions      *imo;
	struct ifnet            *ifp;
	struct in_ifaddr        *ia;
	int                      error, optval;
	unsigned int             ifindex;
	u_char                   coptval;

	imo = inp->inp_moptions;
	/*
	 * If socket is neither of type SOCK_RAW or SOCK_DGRAM,
	 * or is a divert socket, reject it.
	 */
	if (SOCK_PROTO(inp->inp_socket) == IPPROTO_DIVERT ||
	    (SOCK_TYPE(inp->inp_socket) != SOCK_RAW &&
	    SOCK_TYPE(inp->inp_socket) != SOCK_DGRAM)) {
		return EOPNOTSUPP;
	}

	error = 0;
	switch (sopt->sopt_name) {
	case IP_MULTICAST_IF:
		memset(&mreqn, 0, sizeof(struct ip_mreqn));
		if (imo != NULL) {
			IMO_LOCK(imo);
			ifp = imo->imo_multicast_ifp;
			if (!in_nullhost(imo->imo_multicast_addr)) {
				mreqn.imr_address = imo->imo_multicast_addr;
			} else if (ifp != NULL) {
				mreqn.imr_ifindex = ifp->if_index;
				IFP_TO_IA(ifp, ia);
				if (ia != NULL) {
					IFA_LOCK_SPIN(&ia->ia_ifa);
					mreqn.imr_address =
					    IA_SIN(ia)->sin_addr;
					IFA_UNLOCK(&ia->ia_ifa);
					IFA_REMREF(&ia->ia_ifa);
				}
			}
			IMO_UNLOCK(imo);
		}
		if (sopt->sopt_valsize == sizeof(struct ip_mreqn)) {
			error = sooptcopyout(sopt, &mreqn,
			    sizeof(struct ip_mreqn));
		} else {
			error = sooptcopyout(sopt, &mreqn.imr_address,
			    sizeof(struct in_addr));
		}
		break;

	case IP_MULTICAST_IFINDEX:
		if (imo != NULL) {
			IMO_LOCK(imo);
		}
		if (imo == NULL || imo->imo_multicast_ifp == NULL) {
			ifindex = 0;
		} else {
			ifindex = imo->imo_multicast_ifp->if_index;
		}
		if (imo != NULL) {
			IMO_UNLOCK(imo);
		}
		error = sooptcopyout(sopt, &ifindex, sizeof(ifindex));
		break;

	case IP_MULTICAST_TTL:
		if (imo == NULL) {
			optval = coptval = IP_DEFAULT_MULTICAST_TTL;
		} else {
			IMO_LOCK(imo);
			optval = coptval = imo->imo_multicast_ttl;
			IMO_UNLOCK(imo);
		}
		if (sopt->sopt_valsize == sizeof(u_char)) {
			error = sooptcopyout(sopt, &coptval, sizeof(u_char));
		} else {
			error = sooptcopyout(sopt, &optval, sizeof(int));
		}
		break;

	case IP_MULTICAST_LOOP:
		if (imo == 0) {
			optval = coptval = IP_DEFAULT_MULTICAST_LOOP;
		} else {
			IMO_LOCK(imo);
			optval = coptval = imo->imo_multicast_loop;
			IMO_UNLOCK(imo);
		}
		if (sopt->sopt_valsize == sizeof(u_char)) {
			error = sooptcopyout(sopt, &coptval, sizeof(u_char));
		} else {
			error = sooptcopyout(sopt, &optval, sizeof(int));
		}
		break;

	case IP_MSFILTER:
		if (imo == NULL) {
			error = EADDRNOTAVAIL;
		} else {
			error = inp_get_source_filters(inp, sopt);
		}
		break;

	default:
		error = ENOPROTOOPT;
		break;
	}

	return error;
}

/*
 * Look up the ifnet to use for a multicast group membership,
 * given the IPv4 address of an interface, and the IPv4 group address.
 *
 * This routine exists to support legacy multicast applications
 * which do not understand that multicast memberships are scoped to
 * specific physical links in the networking stack, or which need
 * to join link-scope groups before IPv4 addresses are configured.
 *
 * If inp is non-NULL and is bound to an interface, use this socket's
 * inp_boundif for any required routing table lookup.
 *
 * If the route lookup fails, attempt to use the first non-loopback
 * interface with multicast capability in the system as a
 * last resort. The legacy IPv4 ASM API requires that we do
 * this in order to allow groups to be joined when the routing
 * table has not yet been populated during boot.
 *
 * Returns NULL if no ifp could be found.
 *
 */
static struct ifnet *
inp_lookup_mcast_ifp(const struct inpcb *inp,
    const struct sockaddr_in *gsin, const struct in_addr ina)
{
	struct ifnet    *ifp;
	unsigned int     ifindex = 0;

	VERIFY(gsin->sin_family == AF_INET);
	VERIFY(IN_MULTICAST(ntohl(gsin->sin_addr.s_addr)));

	ifp = NULL;
	if (!in_nullhost(ina)) {
		struct in_addr new_ina;
		memcpy(&new_ina, &ina, sizeof(struct in_addr));
		ifp = ip_multicast_if(&new_ina, &ifindex);
	} else {
		struct route ro;
		unsigned int ifscope = IFSCOPE_NONE;

		if (inp != NULL && (inp->inp_flags & INP_BOUND_IF)) {
			ifscope = inp->inp_boundifp->if_index;
		}

		bzero(&ro, sizeof(ro));
		memcpy(&ro.ro_dst, gsin, sizeof(struct sockaddr_in));
		rtalloc_scoped_ign(&ro, 0, ifscope);
		if (ro.ro_rt != NULL) {
			ifp = ro.ro_rt->rt_ifp;
			VERIFY(ifp != NULL);
		} else {
			struct in_ifaddr *ia;
			struct ifnet *mifp;

			mifp = NULL;
			lck_rw_lock_shared(in_ifaddr_rwlock);
			TAILQ_FOREACH(ia, &in_ifaddrhead, ia_link) {
				IFA_LOCK_SPIN(&ia->ia_ifa);
				mifp = ia->ia_ifp;
				IFA_UNLOCK(&ia->ia_ifa);
				if (!(mifp->if_flags & IFF_LOOPBACK) &&
				    (mifp->if_flags & IFF_MULTICAST)) {
					ifp = mifp;
					break;
				}
			}
			lck_rw_done(in_ifaddr_rwlock);
		}
		ROUTE_RELEASE(&ro);
	}

	return ifp;
}

/*
 * Join an IPv4 multicast group, possibly with a source.
 *
 * NB: sopt->sopt_val might point to the kernel address space. This means that
 * we were called by the IPv6 stack due to the presence of an IPv6 v4 mapped
 * address. In this scenario, sopt_p points to kernproc and sooptcopyin() will
 * just issue an in-kernel memcpy.
 */
int
inp_join_group(struct inpcb *inp, struct sockopt *sopt)
{
	struct group_source_req          gsr;
	struct sockaddr_in              *gsa, *ssa;
	struct ifnet                    *ifp;
	struct in_mfilter               *imf;
	struct ip_moptions              *imo;
	struct in_multi                 *inm = NULL;
	struct in_msource               *lims;
	size_t                           idx;
	int                              error, is_new;
	struct igmp_tparams              itp;

	bzero(&itp, sizeof(itp));
	ifp = NULL;
	imf = NULL;
	error = 0;
	is_new = 0;

	memset(&gsr, 0, sizeof(struct group_source_req));
	gsa = (struct sockaddr_in *)&gsr.gsr_group;
	gsa->sin_family = AF_UNSPEC;
	ssa = (struct sockaddr_in *)&gsr.gsr_source;
	ssa->sin_family = AF_UNSPEC;

	switch (sopt->sopt_name) {
	case IP_ADD_MEMBERSHIP:
	case IP_ADD_SOURCE_MEMBERSHIP: {
		struct ip_mreq_source    mreqs;

		if (sopt->sopt_name == IP_ADD_MEMBERSHIP) {
			error = sooptcopyin(sopt, &mreqs,
			    sizeof(struct ip_mreq),
			    sizeof(struct ip_mreq));
			/*
			 * Do argument switcharoo from ip_mreq into
			 * ip_mreq_source to avoid using two instances.
			 */
			mreqs.imr_interface = mreqs.imr_sourceaddr;
			mreqs.imr_sourceaddr.s_addr = INADDR_ANY;
		} else if (sopt->sopt_name == IP_ADD_SOURCE_MEMBERSHIP) {
			error = sooptcopyin(sopt, &mreqs,
			    sizeof(struct ip_mreq_source),
			    sizeof(struct ip_mreq_source));
		}
		if (error) {
			IGMP_PRINTF(("%s: error copyin IP_ADD_MEMBERSHIP/"
			    "IP_ADD_SOURCE_MEMBERSHIP %d err=%d\n",
			    __func__, sopt->sopt_name, error));
			return error;
		}

		gsa->sin_family = AF_INET;
		gsa->sin_len = sizeof(struct sockaddr_in);
		gsa->sin_addr = mreqs.imr_multiaddr;

		if (sopt->sopt_name == IP_ADD_SOURCE_MEMBERSHIP) {
			ssa->sin_family = AF_INET;
			ssa->sin_len = sizeof(struct sockaddr_in);
			ssa->sin_addr = mreqs.imr_sourceaddr;
		}

		if (!IN_MULTICAST(ntohl(gsa->sin_addr.s_addr))) {
			return EINVAL;
		}

		ifp = inp_lookup_mcast_ifp(inp, gsa, mreqs.imr_interface);
		IGMP_INET_PRINTF(mreqs.imr_interface,
		    ("%s: imr_interface = %s, ifp = 0x%llx\n", __func__,
		    _igmp_inet_buf, (uint64_t)VM_KERNEL_ADDRPERM(ifp)));
		break;
	}

	case MCAST_JOIN_GROUP:
	case MCAST_JOIN_SOURCE_GROUP:
		if (sopt->sopt_name == MCAST_JOIN_GROUP) {
			error = sooptcopyin(sopt, &gsr,
			    sizeof(struct group_req),
			    sizeof(struct group_req));
		} else if (sopt->sopt_name == MCAST_JOIN_SOURCE_GROUP) {
			error = sooptcopyin(sopt, &gsr,
			    sizeof(struct group_source_req),
			    sizeof(struct group_source_req));
		}
		if (error) {
			return error;
		}

		if (gsa->sin_family != AF_INET ||
		    gsa->sin_len != sizeof(struct sockaddr_in)) {
			return EINVAL;
		}

		/*
		 * Overwrite the port field if present, as the sockaddr
		 * being copied in may be matched with a binary comparison.
		 */
		gsa->sin_port = 0;
		if (sopt->sopt_name == MCAST_JOIN_SOURCE_GROUP) {
			if (ssa->sin_family != AF_INET ||
			    ssa->sin_len != sizeof(struct sockaddr_in)) {
				return EINVAL;
			}
			ssa->sin_port = 0;
		}

		if (!IN_MULTICAST(ntohl(gsa->sin_addr.s_addr))) {
			return EINVAL;
		}

		ifnet_head_lock_shared();
		if (gsr.gsr_interface == 0 ||
		    (u_int)if_index < gsr.gsr_interface) {
			ifnet_head_done();
			return EADDRNOTAVAIL;
		}
		ifp = ifindex2ifnet[gsr.gsr_interface];
		ifnet_head_done();

		break;

	default:
		IGMP_PRINTF(("%s: unknown sopt_name %d\n",
		    __func__, sopt->sopt_name));
		return EOPNOTSUPP;
	}

	if (ifp == NULL || (ifp->if_flags & IFF_MULTICAST) == 0) {
		return EADDRNOTAVAIL;
	}

	INC_ATOMIC_INT64_LIM(net_api_stats.nas_socket_mcast_join_total);
	/*
	 * TBD: revisit the criteria for non-OS initiated joins
	 */
	if (inp->inp_lport == htons(5353)) {
		INC_ATOMIC_INT64_LIM(net_api_stats.nas_socket_mcast_join_os_total);
	}

	imo = inp_findmoptions(inp);
	if (imo == NULL) {
		return ENOMEM;
	}

	IMO_LOCK(imo);
	idx = imo_match_group(imo, ifp, gsa);
	if (idx == (size_t)-1) {
		is_new = 1;
	} else {
		inm = imo->imo_membership[idx];
		imf = &imo->imo_mfilters[idx];
		if (ssa->sin_family != AF_UNSPEC) {
			/*
			 * MCAST_JOIN_SOURCE_GROUP on an exclusive membership
			 * is an error. On an existing inclusive membership,
			 * it just adds the source to the filter list.
			 */
			if (imf->imf_st[1] != MCAST_INCLUDE) {
				error = EINVAL;
				goto out_imo_locked;
			}
			/*
			 * Throw out duplicates.
			 *
			 * XXX FIXME: This makes a naive assumption that
			 * even if entries exist for *ssa in this imf,
			 * they will be rejected as dupes, even if they
			 * are not valid in the current mode (in-mode).
			 *
			 * in_msource is transactioned just as for anything
			 * else in SSM -- but note naive use of inm_graft()
			 * below for allocating new filter entries.
			 *
			 * This is only an issue if someone mixes the
			 * full-state SSM API with the delta-based API,
			 * which is discouraged in the relevant RFCs.
			 */
			lims = imo_match_source(imo, idx, ssa);
			if (lims != NULL /*&&
			                  *  lims->imsl_st[1] == MCAST_INCLUDE*/) {
				error = EADDRNOTAVAIL;
				goto out_imo_locked;
			}
		} else {
			/*
			 * MCAST_JOIN_GROUP on an existing exclusive
			 * membership is an error; return EADDRINUSE
			 * to preserve 4.4BSD API idempotence, and
			 * avoid tedious detour to code below.
			 * NOTE: This is bending RFC 3678 a bit.
			 *
			 * On an existing inclusive membership, this is also
			 * an error; if you want to change filter mode,
			 * you must use the userland API setsourcefilter().
			 * XXX We don't reject this for imf in UNDEFINED
			 * state at t1, because allocation of a filter
			 * is atomic with allocation of a membership.
			 */
			error = EINVAL;
			/* See comments above for EADDRINUSE */
			if (imf->imf_st[1] == MCAST_EXCLUDE) {
				error = EADDRINUSE;
			}
			goto out_imo_locked;
		}
	}

	/*
	 * Begin state merge transaction at socket layer.
	 */

	if (is_new) {
		if (imo->imo_num_memberships == imo->imo_max_memberships) {
			error = imo_grow(imo, 0);
			if (error) {
				goto out_imo_locked;
			}
		}
		/*
		 * Allocate the new slot upfront so we can deal with
		 * grafting the new source filter in same code path
		 * as for join-source on existing membership.
		 */
		idx = imo->imo_num_memberships;
		imo->imo_membership[idx] = NULL;
		imo->imo_num_memberships++;
		VERIFY(imo->imo_mfilters != NULL);
		imf = &imo->imo_mfilters[idx];
		VERIFY(RB_EMPTY(&imf->imf_sources));
	}

	/*
	 * Graft new source into filter list for this inpcb's
	 * membership of the group. The in_multi may not have
	 * been allocated yet if this is a new membership, however,
	 * the in_mfilter slot will be allocated and must be initialized.
	 */
	if (ssa->sin_family != AF_UNSPEC) {
		/* Membership starts in IN mode */
		if (is_new) {
			IGMP_PRINTF(("%s: new join w/source\n", __func__));
			imf_init(imf, MCAST_UNDEFINED, MCAST_INCLUDE);
		} else {
			IGMP_PRINTF(("%s: %s source\n", __func__, "allow"));
		}
		lims = imf_graft(imf, MCAST_INCLUDE, ssa);
		if (lims == NULL) {
			IGMP_PRINTF(("%s: merge imf state failed\n",
			    __func__));
			error = ENOMEM;
			goto out_imo_free;
		}
	} else {
		/* No address specified; Membership starts in EX mode */
		if (is_new) {
			IGMP_PRINTF(("%s: new join w/o source\n", __func__));
			imf_init(imf, MCAST_UNDEFINED, MCAST_EXCLUDE);
		}
	}

	/*
	 * Begin state merge transaction at IGMP layer.
	 */
	if (is_new) {
		/*
		 * Unlock socket as we may end up calling ifnet_ioctl() to join (or leave)
		 * the multicast group and we run the risk of a lock ordering issue
		 * if the ifnet thread calls into the socket layer to acquire the pcb list
		 * lock while the input thread delivers multicast packets
		 */
		IMO_ADDREF_LOCKED(imo);
		IMO_UNLOCK(imo);
		socket_unlock(inp->inp_socket, 0);

		VERIFY(inm == NULL);
		error = in_joingroup(ifp, &gsa->sin_addr, imf, &inm);

		socket_lock(inp->inp_socket, 0);
		IMO_REMREF(imo);
		IMO_LOCK(imo);

		VERIFY(inm != NULL || error != 0);
		if (error) {
			goto out_imo_free;
		}
		imo->imo_membership[idx] = inm; /* from in_joingroup() */
	} else {
		IGMP_PRINTF(("%s: merge inm state\n", __func__));
		INM_LOCK(inm);
		error = inm_merge(inm, imf);
		if (error) {
			IGMP_PRINTF(("%s: failed to merge inm state\n",
			    __func__));
			INM_UNLOCK(inm);
			goto out_imf_rollback;
		}
		IGMP_PRINTF(("%s: doing igmp downcall\n", __func__));
		error = igmp_change_state(inm, &itp);
		INM_UNLOCK(inm);
		if (error) {
			IGMP_PRINTF(("%s: failed igmp downcall\n",
			    __func__));
			goto out_imf_rollback;
		}
	}

out_imf_rollback:
	if (error) {
		imf_rollback(imf);
		if (is_new) {
			imf_purge(imf);
		} else {
			imf_reap(imf);
		}
	} else {
		imf_commit(imf);
	}

out_imo_free:
	if (error && is_new) {
		VERIFY(inm == NULL);
		imo->imo_membership[idx] = NULL;
		--imo->imo_num_memberships;
	}

out_imo_locked:
	IMO_UNLOCK(imo);
	IMO_REMREF(imo);        /* from inp_findmoptions() */

	/* schedule timer now that we've dropped the lock(s) */
	igmp_set_timeout(&itp);

	return error;
}

/*
 * Leave an IPv4 multicast group on an inpcb, possibly with a source.
 *
 * NB: sopt->sopt_val might point to the kernel address space. Refer to the
 * block comment on top of inp_join_group() for more information.
 */
int
inp_leave_group(struct inpcb *inp, struct sockopt *sopt)
{
	struct group_source_req          gsr;
	struct ip_mreq_source            mreqs;
	struct sockaddr_in              *gsa, *ssa;
	struct ifnet                    *ifp;
	struct in_mfilter               *imf;
	struct ip_moptions              *imo;
	struct in_msource               *ims;
	struct in_multi                 *inm = NULL;
	size_t                           idx;
	int                              error, is_final;
	unsigned int                     ifindex = 0;
	struct igmp_tparams              itp;

	bzero(&itp, sizeof(itp));
	ifp = NULL;
	error = 0;
	is_final = 1;

	memset(&gsr, 0, sizeof(struct group_source_req));
	gsa = (struct sockaddr_in *)&gsr.gsr_group;
	ssa = (struct sockaddr_in *)&gsr.gsr_source;

	switch (sopt->sopt_name) {
	case IP_DROP_MEMBERSHIP:
	case IP_DROP_SOURCE_MEMBERSHIP:
		if (sopt->sopt_name == IP_DROP_MEMBERSHIP) {
			error = sooptcopyin(sopt, &mreqs,
			    sizeof(struct ip_mreq),
			    sizeof(struct ip_mreq));
			/*
			 * Swap interface and sourceaddr arguments,
			 * as ip_mreq and ip_mreq_source are laid
			 * out differently.
			 */
			mreqs.imr_interface = mreqs.imr_sourceaddr;
			mreqs.imr_sourceaddr.s_addr = INADDR_ANY;
		} else if (sopt->sopt_name == IP_DROP_SOURCE_MEMBERSHIP) {
			error = sooptcopyin(sopt, &mreqs,
			    sizeof(struct ip_mreq_source),
			    sizeof(struct ip_mreq_source));
		}
		if (error) {
			return error;
		}

		gsa->sin_family = AF_INET;
		gsa->sin_len = sizeof(struct sockaddr_in);
		gsa->sin_addr = mreqs.imr_multiaddr;

		if (sopt->sopt_name == IP_DROP_SOURCE_MEMBERSHIP) {
			ssa->sin_family = AF_INET;
			ssa->sin_len = sizeof(struct sockaddr_in);
			ssa->sin_addr = mreqs.imr_sourceaddr;
		}
		/*
		 * Attempt to look up hinted ifp from interface address.
		 * Fallthrough with null ifp iff lookup fails, to
		 * preserve 4.4BSD mcast API idempotence.
		 * XXX NOTE WELL: The RFC 3678 API is preferred because
		 * using an IPv4 address as a key is racy.
		 */
		if (!in_nullhost(mreqs.imr_interface)) {
			ifp = ip_multicast_if(&mreqs.imr_interface, &ifindex);
		}

		IGMP_INET_PRINTF(mreqs.imr_interface,
		    ("%s: imr_interface = %s, ifp = 0x%llx\n", __func__,
		    _igmp_inet_buf, (uint64_t)VM_KERNEL_ADDRPERM(ifp)));

		break;

	case MCAST_LEAVE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
		if (sopt->sopt_name == MCAST_LEAVE_GROUP) {
			error = sooptcopyin(sopt, &gsr,
			    sizeof(struct group_req),
			    sizeof(struct group_req));
		} else if (sopt->sopt_name == MCAST_LEAVE_SOURCE_GROUP) {
			error = sooptcopyin(sopt, &gsr,
			    sizeof(struct group_source_req),
			    sizeof(struct group_source_req));
		}
		if (error) {
			return error;
		}

		if (gsa->sin_family != AF_INET ||
		    gsa->sin_len != sizeof(struct sockaddr_in)) {
			return EINVAL;
		}

		if (sopt->sopt_name == MCAST_LEAVE_SOURCE_GROUP) {
			if (ssa->sin_family != AF_INET ||
			    ssa->sin_len != sizeof(struct sockaddr_in)) {
				return EINVAL;
			}
		}

		ifnet_head_lock_shared();
		if (gsr.gsr_interface == 0 ||
		    (u_int)if_index < gsr.gsr_interface) {
			ifnet_head_done();
			return EADDRNOTAVAIL;
		}

		ifp = ifindex2ifnet[gsr.gsr_interface];
		ifnet_head_done();
		break;

	default:
		IGMP_PRINTF(("%s: unknown sopt_name %d\n",
		    __func__, sopt->sopt_name));
		return EOPNOTSUPP;
	}

	if (!IN_MULTICAST(ntohl(gsa->sin_addr.s_addr))) {
		return EINVAL;
	}

	/*
	 * Find the membership in the membership array.
	 */
	imo = inp_findmoptions(inp);
	if (imo == NULL) {
		return ENOMEM;
	}

	IMO_LOCK(imo);
	idx = imo_match_group(imo, ifp, gsa);
	if (idx == (size_t)-1) {
		error = EADDRNOTAVAIL;
		goto out_locked;
	}
	inm = imo->imo_membership[idx];
	imf = &imo->imo_mfilters[idx];

	if (ssa->sin_family != AF_UNSPEC) {
		IGMP_PRINTF(("%s: opt=%d is_final=0\n", __func__,
		    sopt->sopt_name));
		is_final = 0;
	}

	/*
	 * Begin state merge transaction at socket layer.
	 */

	/*
	 * If we were instructed only to leave a given source, do so.
	 * MCAST_LEAVE_SOURCE_GROUP is only valid for inclusive memberships.
	 */
	if (is_final) {
		imf_leave(imf);
	} else {
		if (imf->imf_st[0] == MCAST_EXCLUDE) {
			error = EADDRNOTAVAIL;
			goto out_locked;
		}
		ims = imo_match_source(imo, idx, ssa);
		if (ims == NULL) {
			IGMP_INET_PRINTF(ssa->sin_addr,
			    ("%s: source %s %spresent\n", __func__,
			    _igmp_inet_buf, "not "));
			error = EADDRNOTAVAIL;
			goto out_locked;
		}
		IGMP_PRINTF(("%s: %s source\n", __func__, "block"));
		error = imf_prune(imf, ssa);
		if (error) {
			IGMP_PRINTF(("%s: merge imf state failed\n",
			    __func__));
			goto out_locked;
		}
	}

	/*
	 * Begin state merge transaction at IGMP layer.
	 */


	if (is_final) {
		/*
		 * Give up the multicast address record to which
		 * the membership points.  Reference held in imo
		 * will be released below.
		 */
		(void) in_leavegroup(inm, imf);
	} else {
		IGMP_PRINTF(("%s: merge inm state\n", __func__));
		INM_LOCK(inm);
		error = inm_merge(inm, imf);
		if (error) {
			IGMP_PRINTF(("%s: failed to merge inm state\n",
			    __func__));
			INM_UNLOCK(inm);
			goto out_imf_rollback;
		}

		IGMP_PRINTF(("%s: doing igmp downcall\n", __func__));
		error = igmp_change_state(inm, &itp);
		if (error) {
			IGMP_PRINTF(("%s: failed igmp downcall\n", __func__));
		}
		INM_UNLOCK(inm);
	}

out_imf_rollback:
	if (error) {
		imf_rollback(imf);
	} else {
		imf_commit(imf);
	}

	imf_reap(imf);

	if (is_final) {
		/* Remove the gap in the membership array. */
		VERIFY(inm == imo->imo_membership[idx]);
		imo->imo_membership[idx] = NULL;

		/*
		 * See inp_join_group() for why we need to unlock
		 */
		IMO_ADDREF_LOCKED(imo);
		IMO_UNLOCK(imo);
		socket_unlock(inp->inp_socket, 0);

		INM_REMREF(inm);

		socket_lock(inp->inp_socket, 0);
		IMO_REMREF(imo);
		IMO_LOCK(imo);

		for (++idx; idx < imo->imo_num_memberships; ++idx) {
			imo->imo_membership[idx - 1] = imo->imo_membership[idx];
			imo->imo_mfilters[idx - 1] = imo->imo_mfilters[idx];
		}
		imo->imo_num_memberships--;
	}

out_locked:
	IMO_UNLOCK(imo);
	IMO_REMREF(imo);        /* from inp_findmoptions() */

	/* schedule timer now that we've dropped the lock(s) */
	igmp_set_timeout(&itp);

	return error;
}

/*
 * Select the interface for transmitting IPv4 multicast datagrams.
 *
 * Either an instance of struct in_addr or an instance of struct ip_mreqn
 * may be passed to this socket option. An address of INADDR_ANY or an
 * interface index of 0 is used to remove a previous selection.
 * When no interface is selected, one is chosen for every send.
 */
static int
inp_set_multicast_if(struct inpcb *inp, struct sockopt *sopt)
{
	struct in_addr           addr;
	struct ip_mreqn          mreqn;
	struct ifnet            *ifp;
	struct ip_moptions      *imo;
	int                      error = 0;
	unsigned int             ifindex = 0;

	bzero(&addr, sizeof(addr));
	if (sopt->sopt_valsize == sizeof(struct ip_mreqn)) {
		/*
		 * An interface index was specified using the
		 * Linux-derived ip_mreqn structure.
		 */
		error = sooptcopyin(sopt, &mreqn, sizeof(struct ip_mreqn),
		    sizeof(struct ip_mreqn));
		if (error) {
			return error;
		}

		ifnet_head_lock_shared();
		if (mreqn.imr_ifindex < 0 || if_index < mreqn.imr_ifindex) {
			ifnet_head_done();
			return EINVAL;
		}

		if (mreqn.imr_ifindex == 0) {
			ifp = NULL;
		} else {
			ifp = ifindex2ifnet[mreqn.imr_ifindex];
			if (ifp == NULL) {
				ifnet_head_done();
				return EADDRNOTAVAIL;
			}
		}
		ifnet_head_done();
	} else {
		/*
		 * An interface was specified by IPv4 address.
		 * This is the traditional BSD usage.
		 */
		error = sooptcopyin(sopt, &addr, sizeof(struct in_addr),
		    sizeof(struct in_addr));
		if (error) {
			return error;
		}
		if (in_nullhost(addr)) {
			ifp = NULL;
		} else {
			ifp = ip_multicast_if(&addr, &ifindex);
			if (ifp == NULL) {
				IGMP_INET_PRINTF(addr,
				    ("%s: can't find ifp for addr=%s\n",
				    __func__, _igmp_inet_buf));
				return EADDRNOTAVAIL;
			}
		}
	}

	/* Reject interfaces which do not support multicast. */
	if (ifp != NULL && (ifp->if_flags & IFF_MULTICAST) == 0) {
		return EOPNOTSUPP;
	}

	imo = inp_findmoptions(inp);
	if (imo == NULL) {
		return ENOMEM;
	}

	IMO_LOCK(imo);
	imo->imo_multicast_ifp = ifp;
	if (ifindex) {
		imo->imo_multicast_addr = addr;
	} else {
		imo->imo_multicast_addr.s_addr = INADDR_ANY;
	}
	IMO_UNLOCK(imo);
	IMO_REMREF(imo);        /* from inp_findmoptions() */

	return 0;
}

/*
 * Atomically set source filters on a socket for an IPv4 multicast group.
 */
static int
inp_set_source_filters(struct inpcb *inp, struct sockopt *sopt)
{
	struct __msfilterreq64   msfr = {}, msfr64;
	struct __msfilterreq32   msfr32;
	struct sockaddr_in      *gsa;
	struct ifnet            *ifp;
	struct in_mfilter       *imf;
	struct ip_moptions      *imo;
	struct in_multi         *inm;
	size_t                   idx;
	int                      error;
	uint64_t                 tmp_ptr;
	struct igmp_tparams      itp;

	bzero(&itp, sizeof(itp));

	if (IS_64BIT_PROCESS(current_proc())) {
		error = sooptcopyin(sopt, &msfr64,
		    sizeof(struct __msfilterreq64),
		    sizeof(struct __msfilterreq64));
		if (error) {
			return error;
		}
		/* we never use msfr.msfr_srcs; */
		memcpy(&msfr, &msfr64, sizeof(msfr64));
	} else {
		error = sooptcopyin(sopt, &msfr32,
		    sizeof(struct __msfilterreq32),
		    sizeof(struct __msfilterreq32));
		if (error) {
			return error;
		}
		/* we never use msfr.msfr_srcs; */
		memcpy(&msfr, &msfr32, sizeof(msfr32));
	}

	if ((size_t) msfr.msfr_nsrcs >
	    UINT32_MAX / sizeof(struct sockaddr_storage)) {
		msfr.msfr_nsrcs = UINT32_MAX / sizeof(struct sockaddr_storage);
	}

	if (msfr.msfr_nsrcs > in_mcast_maxsocksrc) {
		return ENOBUFS;
	}

	if ((msfr.msfr_fmode != MCAST_EXCLUDE &&
	    msfr.msfr_fmode != MCAST_INCLUDE)) {
		return EINVAL;
	}

	if (msfr.msfr_group.ss_family != AF_INET ||
	    msfr.msfr_group.ss_len != sizeof(struct sockaddr_in)) {
		return EINVAL;
	}

	gsa = (struct sockaddr_in *)&msfr.msfr_group;
	if (!IN_MULTICAST(ntohl(gsa->sin_addr.s_addr))) {
		return EINVAL;
	}

	gsa->sin_port = 0;      /* ignore port */

	ifnet_head_lock_shared();
	if (msfr.msfr_ifindex == 0 || (u_int)if_index < msfr.msfr_ifindex) {
		ifnet_head_done();
		return EADDRNOTAVAIL;
	}

	ifp = ifindex2ifnet[msfr.msfr_ifindex];
	ifnet_head_done();
	if (ifp == NULL) {
		return EADDRNOTAVAIL;
	}

	/*
	 * Check if this socket is a member of this group.
	 */
	imo = inp_findmoptions(inp);
	if (imo == NULL) {
		return ENOMEM;
	}

	IMO_LOCK(imo);
	idx = imo_match_group(imo, ifp, gsa);
	if (idx == (size_t)-1 || imo->imo_mfilters == NULL) {
		error = EADDRNOTAVAIL;
		goto out_imo_locked;
	}
	inm = imo->imo_membership[idx];
	imf = &imo->imo_mfilters[idx];

	/*
	 * Begin state merge transaction at socket layer.
	 */

	imf->imf_st[1] = (uint8_t)msfr.msfr_fmode;

	/*
	 * Apply any new source filters, if present.
	 * Make a copy of the user-space source vector so
	 * that we may copy them with a single copyin. This
	 * allows us to deal with page faults up-front.
	 */
	if (msfr.msfr_nsrcs > 0) {
		struct in_msource       *lims;
		struct sockaddr_in      *psin;
		struct sockaddr_storage *kss, *pkss;
		int                      i;

		if (IS_64BIT_PROCESS(current_proc())) {
			tmp_ptr = msfr64.msfr_srcs;
		} else {
			tmp_ptr = CAST_USER_ADDR_T(msfr32.msfr_srcs);
		}

		IGMP_PRINTF(("%s: loading %lu source list entries\n",
		    __func__, (unsigned long)msfr.msfr_nsrcs));
		kss = _MALLOC((size_t) msfr.msfr_nsrcs * sizeof(*kss),
		    M_TEMP, M_WAITOK);
		if (kss == NULL) {
			error = ENOMEM;
			goto out_imo_locked;
		}
		error = copyin(CAST_USER_ADDR_T(tmp_ptr), kss,
		    (size_t) msfr.msfr_nsrcs * sizeof(*kss));
		if (error) {
			FREE(kss, M_TEMP);
			goto out_imo_locked;
		}

		/*
		 * Mark all source filters as UNDEFINED at t1.
		 * Restore new group filter mode, as imf_leave()
		 * will set it to INCLUDE.
		 */
		imf_leave(imf);
		imf->imf_st[1] = (uint8_t)msfr.msfr_fmode;

		/*
		 * Update socket layer filters at t1, lazy-allocating
		 * new entries. This saves a bunch of memory at the
		 * cost of one RB_FIND() per source entry; duplicate
		 * entries in the msfr_nsrcs vector are ignored.
		 * If we encounter an error, rollback transaction.
		 *
		 * XXX This too could be replaced with a set-symmetric
		 * difference like loop to avoid walking from root
		 * every time, as the key space is common.
		 */
		for (i = 0, pkss = kss; (u_int)i < msfr.msfr_nsrcs;
		    i++, pkss++) {
			psin = (struct sockaddr_in *)pkss;
			if (psin->sin_family != AF_INET) {
				error = EAFNOSUPPORT;
				break;
			}
			if (psin->sin_len != sizeof(struct sockaddr_in)) {
				error = EINVAL;
				break;
			}
			error = imf_get_source(imf, psin, &lims);
			if (error) {
				break;
			}
			lims->imsl_st[1] = imf->imf_st[1];
		}
		FREE(kss, M_TEMP);
	}

	if (error) {
		goto out_imf_rollback;
	}

	/*
	 * Begin state merge transaction at IGMP layer.
	 */
	INM_LOCK(inm);
	IGMP_PRINTF(("%s: merge inm state\n", __func__));
	error = inm_merge(inm, imf);
	if (error) {
		IGMP_PRINTF(("%s: failed to merge inm state\n", __func__));
		INM_UNLOCK(inm);
		goto out_imf_rollback;
	}

	IGMP_PRINTF(("%s: doing igmp downcall\n", __func__));
	error = igmp_change_state(inm, &itp);
	INM_UNLOCK(inm);
#ifdef IGMP_DEBUG
	if (error) {
		IGMP_PRINTF(("%s: failed igmp downcall\n", __func__));
	}
#endif

out_imf_rollback:
	if (error) {
		imf_rollback(imf);
	} else {
		imf_commit(imf);
	}

	imf_reap(imf);

out_imo_locked:
	IMO_UNLOCK(imo);
	IMO_REMREF(imo);        /* from inp_findmoptions() */

	/* schedule timer now that we've dropped the lock(s) */
	igmp_set_timeout(&itp);

	return error;
}

/*
 * Set the IP multicast options in response to user setsockopt().
 *
 * Many of the socket options handled in this function duplicate the
 * functionality of socket options in the regular unicast API. However,
 * it is not possible to merge the duplicate code, because the idempotence
 * of the IPv4 multicast part of the BSD Sockets API must be preserved;
 * the effects of these options must be treated as separate and distinct.
 */
int
inp_setmoptions(struct inpcb *inp, struct sockopt *sopt)
{
	struct ip_moptions      *imo;
	int                      error;
	unsigned int             ifindex;
	struct ifnet            *ifp;

	error = 0;

	/*
	 * If socket is neither of type SOCK_RAW or SOCK_DGRAM,
	 * or is a divert socket, reject it.
	 */
	if (SOCK_PROTO(inp->inp_socket) == IPPROTO_DIVERT ||
	    (SOCK_TYPE(inp->inp_socket) != SOCK_RAW &&
	    SOCK_TYPE(inp->inp_socket) != SOCK_DGRAM)) {
		return EOPNOTSUPP;
	}

	switch (sopt->sopt_name) {
	case IP_MULTICAST_IF:
		error = inp_set_multicast_if(inp, sopt);
		break;

	case IP_MULTICAST_IFINDEX:
		/*
		 * Select the interface for outgoing multicast packets.
		 */
		error = sooptcopyin(sopt, &ifindex, sizeof(ifindex),
		    sizeof(ifindex));
		if (error) {
			break;
		}

		imo = inp_findmoptions(inp);
		if (imo == NULL) {
			error = ENOMEM;
			break;
		}
		/*
		 * Index 0 is used to remove a previous selection.
		 * When no interface is selected, a default one is
		 * chosen every time a multicast packet is sent.
		 */
		if (ifindex == 0) {
			IMO_LOCK(imo);
			imo->imo_multicast_ifp = NULL;
			IMO_UNLOCK(imo);
			IMO_REMREF(imo);        /* from inp_findmoptions() */
			break;
		}

		ifnet_head_lock_shared();
		/* Don't need to check is ifindex is < 0 since it's unsigned */
		if ((unsigned int)if_index < ifindex) {
			ifnet_head_done();
			IMO_REMREF(imo);        /* from inp_findmoptions() */
			error = ENXIO;  /* per IPV6_MULTICAST_IF */
			break;
		}
		ifp = ifindex2ifnet[ifindex];
		ifnet_head_done();

		/* If it's detached or isn't a multicast interface, bail out */
		if (ifp == NULL || !(ifp->if_flags & IFF_MULTICAST)) {
			IMO_REMREF(imo);        /* from inp_findmoptions() */
			error = EADDRNOTAVAIL;
			break;
		}
		IMO_LOCK(imo);
		imo->imo_multicast_ifp = ifp;
		/*
		 * Clear out any remnants of past IP_MULTICAST_IF.  The addr
		 * isn't really used anywhere in the kernel; we could have
		 * iterated thru the addresses of the interface and pick one
		 * here, but that is redundant since ip_getmoptions() already
		 * takes care of that for INADDR_ANY.
		 */
		imo->imo_multicast_addr.s_addr = INADDR_ANY;
		IMO_UNLOCK(imo);
		IMO_REMREF(imo);        /* from inp_findmoptions() */
		break;

	case IP_MULTICAST_TTL: {
		u_char ttl;

		/*
		 * Set the IP time-to-live for outgoing multicast packets.
		 * The original multicast API required a char argument,
		 * which is inconsistent with the rest of the socket API.
		 * We allow either a char or an int.
		 */
		if (sopt->sopt_valsize == sizeof(u_char)) {
			error = sooptcopyin(sopt, &ttl, sizeof(u_char),
			    sizeof(u_char));
			if (error) {
				break;
			}
		} else {
			u_int ittl;

			error = sooptcopyin(sopt, &ittl, sizeof(u_int),
			    sizeof(u_int));
			if (error) {
				break;
			}
			if (ittl > 255) {
				error = EINVAL;
				break;
			}
			ttl = (u_char)ittl;
		}
		imo = inp_findmoptions(inp);
		if (imo == NULL) {
			error = ENOMEM;
			break;
		}
		IMO_LOCK(imo);
		imo->imo_multicast_ttl = ttl;
		IMO_UNLOCK(imo);
		IMO_REMREF(imo);        /* from inp_findmoptions() */
		break;
	}

	case IP_MULTICAST_LOOP: {
		u_char loop;

		/*
		 * Set the loopback flag for outgoing multicast packets.
		 * Must be zero or one.  The original multicast API required a
		 * char argument, which is inconsistent with the rest
		 * of the socket API.  We allow either a char or an int.
		 */
		if (sopt->sopt_valsize == sizeof(u_char)) {
			error = sooptcopyin(sopt, &loop, sizeof(u_char),
			    sizeof(u_char));
			if (error) {
				break;
			}
		} else {
			u_int iloop;

			error = sooptcopyin(sopt, &iloop, sizeof(u_int),
			    sizeof(u_int));
			if (error) {
				break;
			}
			loop = (u_char)iloop;
		}
		imo = inp_findmoptions(inp);
		if (imo == NULL) {
			error = ENOMEM;
			break;
		}
		IMO_LOCK(imo);
		imo->imo_multicast_loop = !!loop;
		IMO_UNLOCK(imo);
		IMO_REMREF(imo);        /* from inp_findmoptions() */
		break;
	}

	case IP_ADD_MEMBERSHIP:
	case IP_ADD_SOURCE_MEMBERSHIP:
	case MCAST_JOIN_GROUP:
	case MCAST_JOIN_SOURCE_GROUP:
		error = inp_join_group(inp, sopt);
		break;

	case IP_DROP_MEMBERSHIP:
	case IP_DROP_SOURCE_MEMBERSHIP:
	case MCAST_LEAVE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
		error = inp_leave_group(inp, sopt);
		break;

	case IP_BLOCK_SOURCE:
	case IP_UNBLOCK_SOURCE:
	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
		error = inp_block_unblock_source(inp, sopt);
		break;

	case IP_MSFILTER:
		error = inp_set_source_filters(inp, sopt);
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return error;
}

/*
 * Expose IGMP's multicast filter mode and source list(s) to userland,
 * keyed by (ifindex, group).
 * The filter mode is written out as a uint32_t, followed by
 * 0..n of struct in_addr.
 * For use by ifmcstat(8).
 */
static int
sysctl_ip_mcast_filters SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp)

	struct in_addr                   src = {}, group;
	struct ifnet                    *ifp;
	struct in_multi                 *inm;
	struct in_multistep             step;
	struct ip_msource               *ims;
	int                             *name;
	int                              retval = 0;
	u_int                            namelen;
	uint32_t                         fmode, ifindex;

	name = (int *)arg1;
	namelen = (u_int)arg2;

	if (req->newptr != USER_ADDR_NULL) {
		return EPERM;
	}

	if (namelen != 2) {
		return EINVAL;
	}

	ifindex = name[0];
	ifnet_head_lock_shared();
	if (ifindex <= 0 || ifindex > (u_int)if_index) {
		IGMP_PRINTF(("%s: ifindex %u out of range\n",
		    __func__, ifindex));
		ifnet_head_done();
		return ENOENT;
	}

	group.s_addr = name[1];
	if (!IN_MULTICAST(ntohl(group.s_addr))) {
		IGMP_INET_PRINTF(group,
		    ("%s: group %s is not multicast\n",
		    __func__, _igmp_inet_buf));
		ifnet_head_done();
		return EINVAL;
	}

	ifp = ifindex2ifnet[ifindex];
	ifnet_head_done();
	if (ifp == NULL) {
		IGMP_PRINTF(("%s: no ifp for ifindex %u\n", __func__, ifindex));
		return ENOENT;
	}

	in_multihead_lock_shared();
	IN_FIRST_MULTI(step, inm);
	while (inm != NULL) {
		INM_LOCK(inm);
		if (inm->inm_ifp != ifp) {
			goto next;
		}

		if (!in_hosteq(inm->inm_addr, group)) {
			goto next;
		}

		fmode = inm->inm_st[1].iss_fmode;
		retval = SYSCTL_OUT(req, &fmode, sizeof(uint32_t));
		if (retval != 0) {
			INM_UNLOCK(inm);
			break;          /* abort */
		}
		RB_FOREACH(ims, ip_msource_tree, &inm->inm_srcs) {
#ifdef IGMP_DEBUG
			struct in_addr ina;
			ina.s_addr = htonl(ims->ims_haddr);
			IGMP_INET_PRINTF(ina,
			    ("%s: visit node %s\n", __func__, _igmp_inet_buf));
#endif
			/*
			 * Only copy-out sources which are in-mode.
			 */
			if (fmode != ims_get_mode(inm, ims, 1)) {
				IGMP_PRINTF(("%s: skip non-in-mode\n",
				    __func__));
				continue; /* process next source */
			}
			src.s_addr = htonl(ims->ims_haddr);
			retval = SYSCTL_OUT(req, &src, sizeof(struct in_addr));
			if (retval != 0) {
				break;  /* process next inm */
			}
		}
next:
		INM_UNLOCK(inm);
		IN_NEXT_MULTI(step, inm);
	}
	in_multihead_lock_done();

	return retval;
}

/*
 * XXX
 * The whole multicast option thing needs to be re-thought.
 * Several of these options are equally applicable to non-multicast
 * transmission, and one (IP_MULTICAST_TTL) totally duplicates a
 * standard option (IP_TTL).
 */
/*
 * following RFC1724 section 3.3, 0.0.0.0/8 is interpreted as interface index.
 */
static struct ifnet *
ip_multicast_if(struct in_addr *a, unsigned int *ifindexp)
{
	unsigned int ifindex;
	struct ifnet *ifp;

	if (ifindexp != NULL) {
		*ifindexp = 0;
	}
	if (ntohl(a->s_addr) >> 24 == 0) {
		ifindex = ntohl(a->s_addr) & 0xffffff;
		ifnet_head_lock_shared();
		/* Don't need to check is ifindex is < 0 since it's unsigned */
		if ((unsigned int)if_index < ifindex) {
			ifnet_head_done();
			return NULL;
		}
		ifp = ifindex2ifnet[ifindex];
		ifnet_head_done();
		if (ifp != NULL && ifindexp != NULL) {
			*ifindexp = ifindex;
		}
	} else {
		INADDR_TO_IFP(*a, ifp);
	}
	return ifp;
}

void
in_multi_init(void)
{
	PE_parse_boot_argn("ifa_debug", &inm_debug, sizeof(inm_debug));

	/* Setup lock group and attribute for in_multihead */
	in_multihead_lock_grp_attr = lck_grp_attr_alloc_init();
	in_multihead_lock_grp = lck_grp_alloc_init("in_multihead",
	    in_multihead_lock_grp_attr);
	in_multihead_lock_attr = lck_attr_alloc_init();
	lck_rw_init(&in_multihead_lock, in_multihead_lock_grp,
	    in_multihead_lock_attr);

	lck_mtx_init(&inm_trash_lock, in_multihead_lock_grp,
	    in_multihead_lock_attr);
	TAILQ_INIT(&inm_trash_head);

	vm_size_t inm_size = (inm_debug == 0) ? sizeof(struct in_multi) :
	    sizeof(struct in_multi_dbg);
	inm_zone = zone_create(INM_ZONE_NAME, inm_size, ZC_ZFREE_CLEARMEM);
}

static struct in_multi *
in_multi_alloc(zalloc_flags_t how)
{
	struct in_multi *inm;

	inm = zalloc_flags(inm_zone, how | Z_ZERO);
	if (inm != NULL) {
		lck_mtx_init(&inm->inm_lock, in_multihead_lock_grp,
		    in_multihead_lock_attr);
		inm->inm_debug |= IFD_ALLOC;
		if (inm_debug != 0) {
			inm->inm_debug |= IFD_DEBUG;
			inm->inm_trace = inm_trace;
		}
	}
	return inm;
}

static void
in_multi_free(struct in_multi *inm)
{
	INM_LOCK(inm);
	if (inm->inm_debug & IFD_ATTACHED) {
		panic("%s: attached inm=%p is being freed", __func__, inm);
		/* NOTREACHED */
	} else if (inm->inm_ifma != NULL) {
		panic("%s: ifma not NULL for inm=%p", __func__, inm);
		/* NOTREACHED */
	} else if (!(inm->inm_debug & IFD_ALLOC)) {
		panic("%s: inm %p cannot be freed", __func__, inm);
		/* NOTREACHED */
	} else if (inm->inm_refcount != 0) {
		panic("%s: non-zero refcount inm=%p", __func__, inm);
		/* NOTREACHED */
	} else if (inm->inm_reqcnt != 0) {
		panic("%s: non-zero reqcnt inm=%p", __func__, inm);
		/* NOTREACHED */
	}

	/* Free any pending IGMPv3 state-change records */
	IF_DRAIN(&inm->inm_scq);

	inm->inm_debug &= ~IFD_ALLOC;
	if ((inm->inm_debug & (IFD_DEBUG | IFD_TRASHED)) ==
	    (IFD_DEBUG | IFD_TRASHED)) {
		lck_mtx_lock(&inm_trash_lock);
		TAILQ_REMOVE(&inm_trash_head, (struct in_multi_dbg *)inm,
		    inm_trash_link);
		lck_mtx_unlock(&inm_trash_lock);
		inm->inm_debug &= ~IFD_TRASHED;
	}
	INM_UNLOCK(inm);

	lck_mtx_destroy(&inm->inm_lock, in_multihead_lock_grp);
	zfree(inm_zone, inm);
}

static void
in_multi_attach(struct in_multi *inm)
{
	in_multihead_lock_assert(LCK_RW_ASSERT_EXCLUSIVE);
	INM_LOCK_ASSERT_HELD(inm);

	if (inm->inm_debug & IFD_ATTACHED) {
		panic("%s: Attempt to attach an already attached inm=%p",
		    __func__, inm);
		/* NOTREACHED */
	} else if (inm->inm_debug & IFD_TRASHED) {
		panic("%s: Attempt to reattach a detached inm=%p",
		    __func__, inm);
		/* NOTREACHED */
	}

	inm->inm_reqcnt++;
	VERIFY(inm->inm_reqcnt == 1);
	INM_ADDREF_LOCKED(inm);
	inm->inm_debug |= IFD_ATTACHED;
	/*
	 * Reattach case:  If debugging is enabled, take it
	 * out of the trash list and clear IFD_TRASHED.
	 */
	if ((inm->inm_debug & (IFD_DEBUG | IFD_TRASHED)) ==
	    (IFD_DEBUG | IFD_TRASHED)) {
		/* Become a regular mutex, just in case */
		INM_CONVERT_LOCK(inm);
		lck_mtx_lock(&inm_trash_lock);
		TAILQ_REMOVE(&inm_trash_head, (struct in_multi_dbg *)inm,
		    inm_trash_link);
		lck_mtx_unlock(&inm_trash_lock);
		inm->inm_debug &= ~IFD_TRASHED;
	}

	LIST_INSERT_HEAD(&in_multihead, inm, inm_link);
}

int
in_multi_detach(struct in_multi *inm)
{
	in_multihead_lock_assert(LCK_RW_ASSERT_EXCLUSIVE);
	INM_LOCK_ASSERT_HELD(inm);

	if (inm->inm_reqcnt == 0) {
		panic("%s: inm=%p negative reqcnt", __func__, inm);
		/* NOTREACHED */
	}

	--inm->inm_reqcnt;
	if (inm->inm_reqcnt > 0) {
		return 0;
	}

	if (!(inm->inm_debug & IFD_ATTACHED)) {
		panic("%s: Attempt to detach an unattached record inm=%p",
		    __func__, inm);
		/* NOTREACHED */
	} else if (inm->inm_debug & IFD_TRASHED) {
		panic("%s: inm %p is already in trash list", __func__, inm);
		/* NOTREACHED */
	}

	/*
	 * NOTE: Caller calls IFMA_REMREF
	 */
	inm->inm_debug &= ~IFD_ATTACHED;
	LIST_REMOVE(inm, inm_link);

	if (inm->inm_debug & IFD_DEBUG) {
		/* Become a regular mutex, just in case */
		INM_CONVERT_LOCK(inm);
		lck_mtx_lock(&inm_trash_lock);
		TAILQ_INSERT_TAIL(&inm_trash_head,
		    (struct in_multi_dbg *)inm, inm_trash_link);
		lck_mtx_unlock(&inm_trash_lock);
		inm->inm_debug |= IFD_TRASHED;
	}

	return 1;
}

void
inm_addref(struct in_multi *inm, int locked)
{
	if (!locked) {
		INM_LOCK_SPIN(inm);
	} else {
		INM_LOCK_ASSERT_HELD(inm);
	}

	if (++inm->inm_refcount == 0) {
		panic("%s: inm=%p wraparound refcnt", __func__, inm);
		/* NOTREACHED */
	} else if (inm->inm_trace != NULL) {
		(*inm->inm_trace)(inm, TRUE);
	}
	if (!locked) {
		INM_UNLOCK(inm);
	}
}

void
inm_remref(struct in_multi *inm, int locked)
{
	struct ifmultiaddr *ifma;
	struct igmp_ifinfo *igi;

	if (!locked) {
		INM_LOCK_SPIN(inm);
	} else {
		INM_LOCK_ASSERT_HELD(inm);
	}

	if (inm->inm_refcount == 0 || (inm->inm_refcount == 1 && locked)) {
		panic("%s: inm=%p negative/missing refcnt", __func__, inm);
		/* NOTREACHED */
	} else if (inm->inm_trace != NULL) {
		(*inm->inm_trace)(inm, FALSE);
	}

	--inm->inm_refcount;
	if (inm->inm_refcount > 0) {
		if (!locked) {
			INM_UNLOCK(inm);
		}
		return;
	}

	/*
	 * Synchronization with in_getmulti().  In the event the inm has been
	 * detached, the underlying ifma would still be in the if_multiaddrs
	 * list, and thus can be looked up via if_addmulti().  At that point,
	 * the only way to find this inm is via ifma_protospec.  To avoid
	 * race conditions between the last inm_remref() of that inm and its
	 * use via ifma_protospec, in_multihead lock is used for serialization.
	 * In order to avoid violating the lock order, we must drop inm_lock
	 * before acquiring in_multihead lock.  To prevent the inm from being
	 * freed prematurely, we hold an extra reference.
	 */
	++inm->inm_refcount;
	INM_UNLOCK(inm);
	in_multihead_lock_shared();
	INM_LOCK_SPIN(inm);
	--inm->inm_refcount;
	if (inm->inm_refcount > 0) {
		/* We've lost the race, so abort since inm is still in use */
		INM_UNLOCK(inm);
		in_multihead_lock_done();
		/* If it was locked, return it as such */
		if (locked) {
			INM_LOCK(inm);
		}
		return;
	}
	inm_purge(inm);
	ifma = inm->inm_ifma;
	inm->inm_ifma = NULL;
	inm->inm_ifp = NULL;
	igi = inm->inm_igi;
	inm->inm_igi = NULL;
	INM_UNLOCK(inm);
	IFMA_LOCK_SPIN(ifma);
	ifma->ifma_protospec = NULL;
	IFMA_UNLOCK(ifma);
	in_multihead_lock_done();

	in_multi_free(inm);
	if_delmulti_ifma(ifma);
	/* Release reference held to the underlying ifmultiaddr */
	IFMA_REMREF(ifma);

	if (igi != NULL) {
		IGI_REMREF(igi);
	}
}

static void
inm_trace(struct in_multi *inm, int refhold)
{
	struct in_multi_dbg *inm_dbg = (struct in_multi_dbg *)inm;
	ctrace_t *tr;
	u_int32_t idx;
	u_int16_t *cnt;

	if (!(inm->inm_debug & IFD_DEBUG)) {
		panic("%s: inm %p has no debug structure", __func__, inm);
		/* NOTREACHED */
	}
	if (refhold) {
		cnt = &inm_dbg->inm_refhold_cnt;
		tr = inm_dbg->inm_refhold;
	} else {
		cnt = &inm_dbg->inm_refrele_cnt;
		tr = inm_dbg->inm_refrele;
	}

	idx = atomic_add_16_ov(cnt, 1) % INM_TRACE_HIST_SIZE;
	ctrace_record(&tr[idx]);
}

void
in_multihead_lock_exclusive(void)
{
	lck_rw_lock_exclusive(&in_multihead_lock);
}

void
in_multihead_lock_shared(void)
{
	lck_rw_lock_shared(&in_multihead_lock);
}

void
in_multihead_lock_assert(int what)
{
#if !MACH_ASSERT
#pragma unused(what)
#endif
	LCK_RW_ASSERT(&in_multihead_lock, what);
}

void
in_multihead_lock_done(void)
{
	lck_rw_done(&in_multihead_lock);
}

static struct ip_msource *
ipms_alloc(zalloc_flags_t how)
{
	return zalloc_flags(ipms_zone, how | Z_ZERO);
}

static void
ipms_free(struct ip_msource *ims)
{
	zfree(ipms_zone, ims);
}

static struct in_msource *
inms_alloc(zalloc_flags_t how)
{
	return zalloc_flags(inms_zone, how | Z_ZERO);
}

static void
inms_free(struct in_msource *inms)
{
	zfree(inms_zone, inms);
}

#ifdef IGMP_DEBUG

static const char *inm_modestrs[] = { "un\n", "in", "ex" };

static const char *
inm_mode_str(const int mode)
{
	if (mode >= MCAST_UNDEFINED && mode <= MCAST_EXCLUDE) {
		return inm_modestrs[mode];
	}
	return "??";
}

static const char *inm_statestrs[] = {
	"not-member\n",
	"silent\n",
	"reporting\n",
	"idle\n",
	"lazy\n",
	"sleeping\n",
	"awakening\n",
	"query-pending\n",
	"sg-query-pending\n",
	"leaving"
};

static const char *
inm_state_str(const int state)
{
	if (state >= IGMP_NOT_MEMBER && state <= IGMP_LEAVING_MEMBER) {
		return inm_statestrs[state];
	}
	return "??";
}

/*
 * Dump an in_multi structure to the console.
 */
void
inm_print(const struct in_multi *inm)
{
	int t;
	char buf[MAX_IPv4_STR_LEN];

	INM_LOCK_ASSERT_HELD(__DECONST(struct in_multi *, inm));

	if (igmp_debug == 0) {
		return;
	}

	inet_ntop(AF_INET, &inm->inm_addr, buf, sizeof(buf));
	printf("%s: --- begin inm 0x%llx ---\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(inm));
	printf("addr %s ifp 0x%llx(%s) ifma 0x%llx\n",
	    buf,
	    (uint64_t)VM_KERNEL_ADDRPERM(inm->inm_ifp),
	    if_name(inm->inm_ifp),
	    (uint64_t)VM_KERNEL_ADDRPERM(inm->inm_ifma));
	printf("timer %u state %s refcount %u scq.len %u\n",
	    inm->inm_timer,
	    inm_state_str(inm->inm_state),
	    inm->inm_refcount,
	    inm->inm_scq.ifq_len);
	printf("igi 0x%llx nsrc %lu sctimer %u scrv %u\n",
	    (uint64_t)VM_KERNEL_ADDRPERM(inm->inm_igi),
	    inm->inm_nsrc,
	    inm->inm_sctimer,
	    inm->inm_scrv);
	for (t = 0; t < 2; t++) {
		printf("t%d: fmode %s asm %u ex %u in %u rec %u\n", t,
		    inm_mode_str(inm->inm_st[t].iss_fmode),
		    inm->inm_st[t].iss_asm,
		    inm->inm_st[t].iss_ex,
		    inm->inm_st[t].iss_in,
		    inm->inm_st[t].iss_rec);
	}
	printf("%s: --- end inm 0x%llx ---\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(inm));
}

#else

void
inm_print(__unused const struct in_multi *inm)
{
}

#endif
