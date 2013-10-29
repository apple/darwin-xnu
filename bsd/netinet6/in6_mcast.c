/*
 * Copyright (c) 2010-2013 Apple Inc. All rights reserved.
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
 * Copyright (c) 2009 Bruce Simpson.
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
 * IPv6 multicast socket, group, and socket option processing module.
 * Normative references: RFC 2292, RFC 3492, RFC 3542, RFC 3678, RFC 3810.
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
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet6/ip6_var.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <netinet6/nd6.h>
#include <netinet6/mld6_var.h>
#include <netinet6/scope6_var.h>

#ifndef __SOCKUNION_DECLARED
union sockunion {
	struct sockaddr_storage	ss;
	struct sockaddr		sa;
	struct sockaddr_dl	sdl;
	struct sockaddr_in6	sin6;
};
typedef union sockunion sockunion_t;
#define __SOCKUNION_DECLARED
#endif /* __SOCKUNION_DECLARED */

static void	im6f_commit(struct in6_mfilter *);
static int	im6f_get_source(struct in6_mfilter *imf,
		    const struct sockaddr_in6 *psin,
		    struct in6_msource **);
static struct in6_msource *
		im6f_graft(struct in6_mfilter *, const uint8_t,
		    const struct sockaddr_in6 *);
static int	im6f_prune(struct in6_mfilter *, const struct sockaddr_in6 *);
static void	im6f_rollback(struct in6_mfilter *);
static void	im6f_reap(struct in6_mfilter *);
static int	im6o_grow(struct ip6_moptions *, size_t);
static size_t	im6o_match_group(const struct ip6_moptions *,
		    const struct ifnet *, const struct sockaddr *);
static struct in6_msource *
		im6o_match_source(const struct ip6_moptions *, const size_t,
		    const struct sockaddr *);
static void	im6s_merge(struct ip6_msource *ims,
		    const struct in6_msource *lims, const int rollback);
static int	in6_mc_get(struct ifnet *, const struct in6_addr *,
		    struct in6_multi **);
static int	in6m_get_source(struct in6_multi *inm,
		    const struct in6_addr *addr, const int noalloc,
		    struct ip6_msource **pims);
static int	in6m_is_ifp_detached(const struct in6_multi *);
static int	in6m_merge(struct in6_multi *, /*const*/ struct in6_mfilter *);
static void	in6m_reap(struct in6_multi *);
static struct ip6_moptions *
		in6p_findmoptions(struct inpcb *);
static int	in6p_get_source_filters(struct inpcb *, struct sockopt *);
static int	in6p_lookup_v4addr(struct ipv6_mreq *, struct ip_mreq *);
static int	in6p_join_group(struct inpcb *, struct sockopt *);
static int	in6p_leave_group(struct inpcb *, struct sockopt *);
static struct ifnet *
		in6p_lookup_mcast_ifp(const struct inpcb *,
		    const struct sockaddr_in6 *);
static int	in6p_block_unblock_source(struct inpcb *, struct sockopt *);
static int	in6p_set_multicast_if(struct inpcb *, struct sockopt *);
static int	in6p_set_source_filters(struct inpcb *, struct sockopt *);
static int	sysctl_ip6_mcast_filters SYSCTL_HANDLER_ARGS;
static __inline__ int ip6_msource_cmp(const struct ip6_msource *,
		    const struct ip6_msource *);

SYSCTL_DECL(_net_inet6_ip6);	/* XXX Not in any common header. */

SYSCTL_NODE(_net_inet6_ip6, OID_AUTO, mcast, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "IPv6 multicast");

static unsigned long in6_mcast_maxgrpsrc = IPV6_MAX_GROUP_SRC_FILTER;
SYSCTL_LONG(_net_inet6_ip6_mcast, OID_AUTO, maxgrpsrc,
    CTLFLAG_RW | CTLFLAG_LOCKED, &in6_mcast_maxgrpsrc, 
    "Max source filters per group");

static unsigned long in6_mcast_maxsocksrc = IPV6_MAX_SOCK_SRC_FILTER;
SYSCTL_LONG(_net_inet6_ip6_mcast, OID_AUTO, maxsocksrc,
    CTLFLAG_RW | CTLFLAG_LOCKED, &in6_mcast_maxsocksrc, 
    "Max source filters per socket");

int in6_mcast_loop = IPV6_DEFAULT_MULTICAST_LOOP;
SYSCTL_INT(_net_inet6_ip6_mcast, OID_AUTO, loop, CTLFLAG_RW | CTLFLAG_LOCKED,
    &in6_mcast_loop, 0, "Loopback multicast datagrams by default");

SYSCTL_NODE(_net_inet6_ip6_mcast, OID_AUTO, filters,
    CTLFLAG_RD | CTLFLAG_LOCKED, sysctl_ip6_mcast_filters,
    "Per-interface stack-wide source filters");

RB_GENERATE_PREV(ip6_msource_tree, ip6_msource, im6s_link, ip6_msource_cmp);

#define	IN6M_TRACE_HIST_SIZE	32	/* size of trace history */

/* For gdb */
__private_extern__ unsigned int in6m_trace_hist_size = IN6M_TRACE_HIST_SIZE;

struct in6_multi_dbg {
	struct in6_multi	in6m;			/* in6_multi */
	u_int16_t		in6m_refhold_cnt;	/* # of ref */
	u_int16_t		in6m_refrele_cnt;	/* # of rele */
	/*
	 * Circular lists of in6m_addref and in6m_remref callers.
	 */
	ctrace_t		in6m_refhold[IN6M_TRACE_HIST_SIZE];
	ctrace_t		in6m_refrele[IN6M_TRACE_HIST_SIZE];
	/*
	 * Trash list linkage
	 */
	TAILQ_ENTRY(in6_multi_dbg) in6m_trash_link;
};

/* List of trash in6_multi entries protected by in6m_trash_lock */
static TAILQ_HEAD(, in6_multi_dbg) in6m_trash_head;
static decl_lck_mtx_data(, in6m_trash_lock);

#if DEBUG
static unsigned int in6m_debug = 1;		/* debugging (enabled) */
#else
static unsigned int in6m_debug;			/* debugging (disabled) */
#endif /* !DEBUG */
static unsigned int in6m_size;			/* size of zone element */
static struct zone *in6m_zone;			/* zone for in6_multi */

#define	IN6M_ZONE_MAX		64		/* maximum elements in zone */
#define	IN6M_ZONE_NAME		"in6_multi"	/* zone name */

static unsigned int imm_size;			/* size of zone element */
static struct zone *imm_zone;			/* zone for in6_multi_mship */

#define	IMM_ZONE_MAX		64		/* maximum elements in zone */
#define	IMM_ZONE_NAME		"in6_multi_mship" /* zone name */

#define	IP6MS_ZONE_MAX		64		/* maximum elements in zone */
#define	IP6MS_ZONE_NAME		"ip6_msource"	/* zone name */

static unsigned int ip6ms_size;			/* size of zone element */
static struct zone *ip6ms_zone;			/* zone for ip6_msource */

#define	IN6MS_ZONE_MAX		64		/* maximum elements in zone */
#define	IN6MS_ZONE_NAME		"in6_msource"	/* zone name */

static unsigned int in6ms_size;			/* size of zone element */
static struct zone *in6ms_zone;			/* zone for in6_msource */

/* Lock group and attribute for in6_multihead_lock lock */
static lck_attr_t	*in6_multihead_lock_attr;
static lck_grp_t	*in6_multihead_lock_grp;
static lck_grp_attr_t	*in6_multihead_lock_grp_attr;

static decl_lck_rw_data(, in6_multihead_lock);
struct in6_multihead in6_multihead;

static struct in6_multi *in6_multi_alloc(int);
static void in6_multi_free(struct in6_multi *);
static void in6_multi_attach(struct in6_multi *);
static struct in6_multi_mship *in6_multi_mship_alloc(int);
static void in6_multi_mship_free(struct in6_multi_mship *);
static void in6m_trace(struct in6_multi *, int);

static struct ip6_msource *ip6ms_alloc(int);
static void ip6ms_free(struct ip6_msource *);
static struct in6_msource *in6ms_alloc(int);
static void in6ms_free(struct in6_msource *);

/*
 * IPv6 source tree comparison function.
 *
 * An ordered predicate is necessary; bcmp() is not documented to return
 * an indication of order, memcmp() is, and is an ISO C99 requirement.
 */
static __inline int
ip6_msource_cmp(const struct ip6_msource *a, const struct ip6_msource *b)
{
	return (memcmp(&a->im6s_addr, &b->im6s_addr, sizeof(struct in6_addr)));
}

/*
 * Inline function which wraps assertions for a valid ifp.
 */
static __inline__ int
in6m_is_ifp_detached(const struct in6_multi *inm)
{
	VERIFY(inm->in6m_ifma != NULL);
	VERIFY(inm->in6m_ifp == inm->in6m_ifma->ifma_ifp);

	return (!ifnet_is_attached(inm->in6m_ifp, 0));
}

/*
 * Initialize an in6_mfilter structure to a known state at t0, t1
 * with an empty source filter list.
 */
static __inline__ void
im6f_init(struct in6_mfilter *imf, const int st0, const int st1)
{
	memset(imf, 0, sizeof(struct in6_mfilter));
	RB_INIT(&imf->im6f_sources);
	imf->im6f_st[0] = st0;
	imf->im6f_st[1] = st1;
}

/*
 * Resize the ip6_moptions vector to the next power-of-two minus 1.
 */
static int
im6o_grow(struct ip6_moptions *imo, size_t newmax)
{
	struct in6_multi	**nmships;
	struct in6_multi	**omships;
	struct in6_mfilter	 *nmfilters;
	struct in6_mfilter	 *omfilters;
	size_t			  idx;
	size_t			  oldmax;

	IM6O_LOCK_ASSERT_HELD(imo);

	nmships = NULL;
	nmfilters = NULL;
	omships = imo->im6o_membership;
	omfilters = imo->im6o_mfilters;
	oldmax = imo->im6o_max_memberships;
	if (newmax == 0)
		newmax = ((oldmax + 1) * 2) - 1;

	if (newmax > IPV6_MAX_MEMBERSHIPS)
		return (ETOOMANYREFS);

	if ((nmships = (struct in6_multi **)_REALLOC(omships,
	    sizeof (struct in6_multi *) * newmax, M_IP6MOPTS,
	    M_WAITOK | M_ZERO)) == NULL)
		return (ENOMEM);

	imo->im6o_membership = nmships;

	if ((nmfilters = (struct in6_mfilter *)_REALLOC(omfilters,
	    sizeof (struct in6_mfilter) * newmax, M_IN6MFILTER,
	    M_WAITOK | M_ZERO)) == NULL)
		return (ENOMEM);

	imo->im6o_mfilters = nmfilters;

	/* Initialize newly allocated source filter heads. */
	for (idx = oldmax; idx < newmax; idx++)
		im6f_init(&nmfilters[idx], MCAST_UNDEFINED, MCAST_EXCLUDE);

	imo->im6o_max_memberships = newmax;

	return (0);
}

/*
 * Find an IPv6 multicast group entry for this ip6_moptions instance
 * which matches the specified group, and optionally an interface.
 * Return its index into the array, or -1 if not found.
 */
static size_t
im6o_match_group(const struct ip6_moptions *imo, const struct ifnet *ifp,
    const struct sockaddr *group)
{
	const struct sockaddr_in6 *gsin6;
	struct in6_multi *pinm;
	int		  idx;
	int		  nmships;

	IM6O_LOCK_ASSERT_HELD(__DECONST(struct ip6_moptions *, imo));

	gsin6 = (struct sockaddr_in6 *)(uintptr_t)(size_t)group;

	/* The im6o_membership array may be lazy allocated. */
	if (imo->im6o_membership == NULL || imo->im6o_num_memberships == 0)
		return (-1);

	nmships = imo->im6o_num_memberships;
	for (idx = 0; idx < nmships; idx++) {
		pinm = imo->im6o_membership[idx];
		if (pinm == NULL)
			continue;
		IN6M_LOCK(pinm);
		if ((ifp == NULL || (pinm->in6m_ifp == ifp)) &&
		    IN6_ARE_ADDR_EQUAL(&pinm->in6m_addr,
		    &gsin6->sin6_addr)) {
			IN6M_UNLOCK(pinm);
			break;
		}
		IN6M_UNLOCK(pinm);
	}
	if (idx >= nmships)
		idx = -1;

	return (idx);
}

/*
 * Find an IPv6 multicast source entry for this imo which matches
 * the given group index for this socket, and source address.
 *
 * XXX TODO: The scope ID, if present in src, is stripped before
 * any comparison. We SHOULD enforce scope/zone checks where the source
 * filter entry has a link scope.
 *
 * NOTE: This does not check if the entry is in-mode, merely if
 * it exists, which may not be the desired behaviour.
 */
static struct in6_msource *
im6o_match_source(const struct ip6_moptions *imo, const size_t gidx,
    const struct sockaddr *src)
{
	struct ip6_msource	 find;
	struct in6_mfilter	*imf;
	struct ip6_msource	*ims;
	const sockunion_t	*psa;

	IM6O_LOCK_ASSERT_HELD(__DECONST(struct ip6_moptions *, imo));

	VERIFY(src->sa_family == AF_INET6);
	VERIFY(gidx != (size_t)-1 && gidx < imo->im6o_num_memberships);

	/* The im6o_mfilters array may be lazy allocated. */
	if (imo->im6o_mfilters == NULL)
		return (NULL);
	imf = &imo->im6o_mfilters[gidx];

	psa = (sockunion_t *)(uintptr_t)(size_t)src;
	find.im6s_addr = psa->sin6.sin6_addr;
	in6_clearscope(&find.im6s_addr);		/* XXX */
	ims = RB_FIND(ip6_msource_tree, &imf->im6f_sources, &find);

	return ((struct in6_msource *)ims);
}

/*
 * Perform filtering for multicast datagrams on a socket by group and source.
 *
 * Returns 0 if a datagram should be allowed through, or various error codes
 * if the socket was not a member of the group, or the source was muted, etc.
 */
int
im6o_mc_filter(const struct ip6_moptions *imo, const struct ifnet *ifp,
    const struct sockaddr *group, const struct sockaddr *src)
{
	size_t gidx;
	struct in6_msource *ims;
	int mode;

	IM6O_LOCK_ASSERT_HELD(__DECONST(struct ip6_moptions *, imo));
	VERIFY(ifp != NULL);

	gidx = im6o_match_group(imo, ifp, group);
	if (gidx == (size_t)-1)
		return (MCAST_NOTGMEMBER);

	/*
	 * Check if the source was included in an (S,G) join.
	 * Allow reception on exclusive memberships by default,
	 * reject reception on inclusive memberships by default.
	 * Exclude source only if an in-mode exclude filter exists.
	 * Include source only if an in-mode include filter exists.
	 * NOTE: We are comparing group state here at MLD t1 (now)
	 * with socket-layer t0 (since last downcall).
	 */
	mode = imo->im6o_mfilters[gidx].im6f_st[1];
	ims = im6o_match_source(imo, gidx, src);

	if ((ims == NULL && mode == MCAST_INCLUDE) ||
	    (ims != NULL && ims->im6sl_st[0] != mode))
		return (MCAST_NOTSMEMBER);

	return (MCAST_PASS);
}

/*
 * Find and return a reference to an in6_multi record for (ifp, group),
 * and bump its reference count.
 * If one does not exist, try to allocate it, and update link-layer multicast
 * filters on ifp to listen for group.
 * Assumes the IN6_MULTI lock is held across the call.
 * Return 0 if successful, otherwise return an appropriate error code.
 */
static int
in6_mc_get(struct ifnet *ifp, const struct in6_addr *group,
    struct in6_multi **pinm)
{
	struct sockaddr_in6	 gsin6;
	struct ifmultiaddr	*ifma;
	struct in6_multi	*inm;
	int			 error;

	*pinm = NULL;

	in6_multihead_lock_shared();
	IN6_LOOKUP_MULTI(group, ifp, inm);
	if (inm != NULL) {
		IN6M_LOCK(inm);
		VERIFY(inm->in6m_reqcnt >= 1);
		inm->in6m_reqcnt++;
		VERIFY(inm->in6m_reqcnt != 0);
		*pinm = inm;
		IN6M_UNLOCK(inm);
		in6_multihead_lock_done();
		/*
		 * We already joined this group; return the in6m
		 * with a refcount held (via lookup) for caller.
		 */
		return (0);
	}
	in6_multihead_lock_done();

	memset(&gsin6, 0, sizeof(gsin6));
	gsin6.sin6_family = AF_INET6;
	gsin6.sin6_len = sizeof(struct sockaddr_in6);
	gsin6.sin6_addr = *group;

	/*
	 * Check if a link-layer group is already associated
	 * with this network-layer group on the given ifnet.
	 */
	error = if_addmulti(ifp, (struct sockaddr *)&gsin6, &ifma);
	if (error != 0)
		return (error);

	/*
	 * See comments in in6m_remref() for access to ifma_protospec.
	 */
	in6_multihead_lock_exclusive();
	IFMA_LOCK(ifma);
	if ((inm = ifma->ifma_protospec) != NULL) {
		VERIFY(ifma->ifma_addr != NULL);
		VERIFY(ifma->ifma_addr->sa_family == AF_INET6);
		IN6M_ADDREF(inm);	/* for caller */
		IFMA_UNLOCK(ifma);
		IN6M_LOCK(inm);
		VERIFY(inm->in6m_ifma == ifma);
		VERIFY(inm->in6m_ifp == ifp);
		VERIFY(IN6_ARE_ADDR_EQUAL(&inm->in6m_addr, group));
		if (inm->in6m_debug & IFD_ATTACHED) {
			VERIFY(inm->in6m_reqcnt >= 1);
			inm->in6m_reqcnt++;
			VERIFY(inm->in6m_reqcnt != 0);
			*pinm = inm;
			IN6M_UNLOCK(inm);
			in6_multihead_lock_done();
			IFMA_REMREF(ifma);
			/*
			 * We lost the race with another thread doing
			 * in6_mc_get(); since this group has already
			 * been joined; return the inm with a refcount
			 * held for caller.
			 */
			return (0);
		}
		/*
		 * We lost the race with another thread doing in6_delmulti();
		 * the inm referring to the ifma has been detached, thus we
		 * reattach it back to the in6_multihead list, and return the
		 * inm with a refcount held for the caller.
		 */
		in6_multi_attach(inm);
		VERIFY((inm->in6m_debug &
		    (IFD_ATTACHED | IFD_TRASHED)) == IFD_ATTACHED);
		*pinm = inm;
		IN6M_UNLOCK(inm);
		in6_multihead_lock_done();
		IFMA_REMREF(ifma);
		return (0);
	}
	IFMA_UNLOCK(ifma);

	/*
	 * A new in6_multi record is needed; allocate and initialize it.
	 * We DO NOT perform an MLD join as the in6_ layer may need to
	 * push an initial source list down to MLD to support SSM.
	 *
	 * The initial source filter state is INCLUDE, {} as per the RFC.
	 * Pending state-changes per group are subject to a bounds check.
	 */
	inm = in6_multi_alloc(M_WAITOK);
	if (inm == NULL) {
		in6_multihead_lock_done();
		IFMA_REMREF(ifma);
		return (ENOMEM);
	}
	IN6M_LOCK(inm);
	inm->in6m_addr = *group;
	inm->in6m_ifp = ifp;
	inm->in6m_mli = MLD_IFINFO(ifp);
	VERIFY(inm->in6m_mli != NULL);
	MLI_ADDREF(inm->in6m_mli);
	inm->in6m_ifma = ifma;		/* keep refcount from if_addmulti() */
	inm->in6m_state = MLD_NOT_MEMBER;
	/*
	 * Pending state-changes per group are subject to a bounds check.
	 */
	inm->in6m_scq.ifq_maxlen = MLD_MAX_STATE_CHANGES;
	inm->in6m_st[0].iss_fmode = MCAST_UNDEFINED;
	inm->in6m_st[1].iss_fmode = MCAST_UNDEFINED;
	RB_INIT(&inm->in6m_srcs);
	*pinm = inm;
	in6_multi_attach(inm);
	VERIFY((inm->in6m_debug &
	    (IFD_ATTACHED | IFD_TRASHED)) == IFD_ATTACHED);
	IN6M_ADDREF_LOCKED(inm);	/* for caller */
	IN6M_UNLOCK(inm);

	IFMA_LOCK(ifma);
	VERIFY(ifma->ifma_protospec == NULL);
	ifma->ifma_protospec = inm;
	IFMA_UNLOCK(ifma);
	in6_multihead_lock_done();

	return (0);
}

/*
 * Clear recorded source entries for a group.
 * Used by the MLD code. Caller must hold the IN6_MULTI lock.
 * FIXME: Should reap.
 */
void
in6m_clear_recorded(struct in6_multi *inm)
{
	struct ip6_msource	*ims;

	IN6M_LOCK_ASSERT_HELD(inm);

	RB_FOREACH(ims, ip6_msource_tree, &inm->in6m_srcs) {
		if (ims->im6s_stp) {
			ims->im6s_stp = 0;
			--inm->in6m_st[1].iss_rec;
		}
	}
	VERIFY(inm->in6m_st[1].iss_rec == 0);
}

/*
 * Record a source as pending for a Source-Group MLDv2 query.
 * This lives here as it modifies the shared tree.
 *
 * inm is the group descriptor.
 * naddr is the address of the source to record in network-byte order.
 *
 * If the net.inet6.mld.sgalloc sysctl is non-zero, we will
 * lazy-allocate a source node in response to an SG query.
 * Otherwise, no allocation is performed. This saves some memory
 * with the trade-off that the source will not be reported to the
 * router if joined in the window between the query response and
 * the group actually being joined on the local host.
 *
 * VIMAGE: XXX: Currently the mld_sgalloc feature has been removed.
 * This turns off the allocation of a recorded source entry if
 * the group has not been joined.
 *
 * Return 0 if the source didn't exist or was already marked as recorded.
 * Return 1 if the source was marked as recorded by this function.
 * Return <0 if any error occured (negated errno code).
 */
int
in6m_record_source(struct in6_multi *inm, const struct in6_addr *addr)
{
	struct ip6_msource	 find;
	struct ip6_msource	*ims, *nims;

	IN6M_LOCK_ASSERT_HELD(inm);

	find.im6s_addr = *addr;
	ims = RB_FIND(ip6_msource_tree, &inm->in6m_srcs, &find);
	if (ims && ims->im6s_stp)
		return (0);
	if (ims == NULL) {
		if (inm->in6m_nsrc == in6_mcast_maxgrpsrc)
			return (-ENOSPC);
		nims = ip6ms_alloc(M_WAITOK);
		if (nims == NULL)
			return (-ENOMEM);
		nims->im6s_addr = find.im6s_addr;
		RB_INSERT(ip6_msource_tree, &inm->in6m_srcs, nims);
		++inm->in6m_nsrc;
		ims = nims;
	}

	/*
	 * Mark the source as recorded and update the recorded
	 * source count.
	 */
	++ims->im6s_stp;
	++inm->in6m_st[1].iss_rec;

	return (1);
}

/*
 * Return a pointer to an in6_msource owned by an in6_mfilter,
 * given its source address.
 * Lazy-allocate if needed. If this is a new entry its filter state is
 * undefined at t0.
 *
 * imf is the filter set being modified.
 * addr is the source address.
 *
 * Caller is expected to be holding im6o_lock.
 */
static int
im6f_get_source(struct in6_mfilter *imf, const struct sockaddr_in6 *psin,
    struct in6_msource **plims)
{
	struct ip6_msource	 find;
	struct ip6_msource	*ims;
	struct in6_msource	*lims;
	int			 error;

	error = 0;
	ims = NULL;
	lims = NULL;

	find.im6s_addr = psin->sin6_addr;
	ims = RB_FIND(ip6_msource_tree, &imf->im6f_sources, &find);
	lims = (struct in6_msource *)ims;
	if (lims == NULL) {
		if (imf->im6f_nsrc == in6_mcast_maxsocksrc)
			return (ENOSPC);
		lims = in6ms_alloc(M_WAITOK);
		if (lims == NULL)
			return (ENOMEM);
		lims->im6s_addr = find.im6s_addr;
		lims->im6sl_st[0] = MCAST_UNDEFINED;
		RB_INSERT(ip6_msource_tree, &imf->im6f_sources,
		    (struct ip6_msource *)lims);
		++imf->im6f_nsrc;
	}

	*plims = lims;

	return (error);
}

/*
 * Graft a source entry into an existing socket-layer filter set,
 * maintaining any required invariants and checking allocations.
 *
 * The source is marked as being in the new filter mode at t1.
 *
 * Return the pointer to the new node, otherwise return NULL.
 *
 * Caller is expected to be holding im6o_lock.
 */
static struct in6_msource *
im6f_graft(struct in6_mfilter *imf, const uint8_t st1,
    const struct sockaddr_in6 *psin)
{
	struct in6_msource	*lims;

	lims = in6ms_alloc(M_WAITOK);
	if (lims == NULL)
		return (NULL);
	lims->im6s_addr = psin->sin6_addr;
	lims->im6sl_st[0] = MCAST_UNDEFINED;
	lims->im6sl_st[1] = st1;
	RB_INSERT(ip6_msource_tree, &imf->im6f_sources,
	    (struct ip6_msource *)lims);
	++imf->im6f_nsrc;

	return (lims);
}

/*
 * Prune a source entry from an existing socket-layer filter set,
 * maintaining any required invariants and checking allocations.
 *
 * The source is marked as being left at t1, it is not freed.
 *
 * Return 0 if no error occurred, otherwise return an errno value.
 *
 * Caller is expected to be holding im6o_lock.
 */
static int
im6f_prune(struct in6_mfilter *imf, const struct sockaddr_in6 *psin)
{
	struct ip6_msource	 find;
	struct ip6_msource	*ims;
	struct in6_msource	*lims;

	find.im6s_addr = psin->sin6_addr;
	ims = RB_FIND(ip6_msource_tree, &imf->im6f_sources, &find);
	if (ims == NULL)
		return (ENOENT);
	lims = (struct in6_msource *)ims;
	lims->im6sl_st[1] = MCAST_UNDEFINED;
	return (0);
}

/*
 * Revert socket-layer filter set deltas at t1 to t0 state.
 *
 * Caller is expected to be holding im6o_lock.
 */
static void
im6f_rollback(struct in6_mfilter *imf)
{
	struct ip6_msource	*ims, *tims;
	struct in6_msource	*lims;

	RB_FOREACH_SAFE(ims, ip6_msource_tree, &imf->im6f_sources, tims) {
		lims = (struct in6_msource *)ims;
		if (lims->im6sl_st[0] == lims->im6sl_st[1]) {
			/* no change at t1 */
			continue;
		} else if (lims->im6sl_st[0] != MCAST_UNDEFINED) {
			/* revert change to existing source at t1 */
			lims->im6sl_st[1] = lims->im6sl_st[0];
		} else {
			/* revert source added t1 */
			MLD_PRINTF(("%s: free in6ms 0x%llx\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(lims)));
			RB_REMOVE(ip6_msource_tree, &imf->im6f_sources, ims);
			in6ms_free(lims);
			imf->im6f_nsrc--;
		}
	}
	imf->im6f_st[1] = imf->im6f_st[0];
}

/*
 * Mark socket-layer filter set as INCLUDE {} at t1.
 *
 * Caller is expected to be holding im6o_lock.
 */
void
im6f_leave(struct in6_mfilter *imf)
{
	struct ip6_msource	*ims;
	struct in6_msource	*lims;

	RB_FOREACH(ims, ip6_msource_tree, &imf->im6f_sources) {
		lims = (struct in6_msource *)ims;
		lims->im6sl_st[1] = MCAST_UNDEFINED;
	}
	imf->im6f_st[1] = MCAST_INCLUDE;
}

/*
 * Mark socket-layer filter set deltas as committed.
 *
 * Caller is expected to be holding im6o_lock.
 */
static void
im6f_commit(struct in6_mfilter *imf)
{
	struct ip6_msource	*ims;
	struct in6_msource	*lims;

	RB_FOREACH(ims, ip6_msource_tree, &imf->im6f_sources) {
		lims = (struct in6_msource *)ims;
		lims->im6sl_st[0] = lims->im6sl_st[1];
	}
	imf->im6f_st[0] = imf->im6f_st[1];
}

/*
 * Reap unreferenced sources from socket-layer filter set.
 *
 * Caller is expected to be holding im6o_lock.
 */
static void
im6f_reap(struct in6_mfilter *imf)
{
	struct ip6_msource	*ims, *tims;
	struct in6_msource	*lims;

	RB_FOREACH_SAFE(ims, ip6_msource_tree, &imf->im6f_sources, tims) {
		lims = (struct in6_msource *)ims;
		if ((lims->im6sl_st[0] == MCAST_UNDEFINED) &&
		    (lims->im6sl_st[1] == MCAST_UNDEFINED)) {
			MLD_PRINTF(("%s: free in6ms 0x%llx\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(lims)));
			RB_REMOVE(ip6_msource_tree, &imf->im6f_sources, ims);
			in6ms_free(lims);
			imf->im6f_nsrc--;
		}
	}
}

/*
 * Purge socket-layer filter set.
 *
 * Caller is expected to be holding im6o_lock.
 */
void
im6f_purge(struct in6_mfilter *imf)
{
	struct ip6_msource	*ims, *tims;
	struct in6_msource	*lims;

	RB_FOREACH_SAFE(ims, ip6_msource_tree, &imf->im6f_sources, tims) {
		lims = (struct in6_msource *)ims;
		MLD_PRINTF(("%s: free in6ms 0x%llx\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(lims)));
		RB_REMOVE(ip6_msource_tree, &imf->im6f_sources, ims);
		in6ms_free(lims);
		imf->im6f_nsrc--;
	}
	imf->im6f_st[0] = imf->im6f_st[1] = MCAST_UNDEFINED;
	VERIFY(RB_EMPTY(&imf->im6f_sources));
}

/*
 * Look up a source filter entry for a multicast group.
 *
 * inm is the group descriptor to work with.
 * addr is the IPv6 address to look up.
 * noalloc may be non-zero to suppress allocation of sources.
 * *pims will be set to the address of the retrieved or allocated source.
 *
 * Return 0 if successful, otherwise return a non-zero error code.
 */
static int
in6m_get_source(struct in6_multi *inm, const struct in6_addr *addr,
    const int noalloc, struct ip6_msource **pims)
{
	struct ip6_msource	 find;
	struct ip6_msource	*ims, *nims;

	IN6M_LOCK_ASSERT_HELD(inm);

	find.im6s_addr = *addr;
	ims = RB_FIND(ip6_msource_tree, &inm->in6m_srcs, &find);
	if (ims == NULL && !noalloc) {
		if (inm->in6m_nsrc == in6_mcast_maxgrpsrc)
			return (ENOSPC);
		nims = ip6ms_alloc(M_WAITOK);
		if (nims == NULL)
			return (ENOMEM);
		nims->im6s_addr = *addr;
		RB_INSERT(ip6_msource_tree, &inm->in6m_srcs, nims);
		++inm->in6m_nsrc;
		ims = nims;
		MLD_PRINTF(("%s: allocated %s as 0x%llx\n", __func__,
		    ip6_sprintf(addr), (uint64_t)VM_KERNEL_ADDRPERM(ims)));
	}

	*pims = ims;
	return (0);
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
im6s_get_mode(const struct in6_multi *inm, const struct ip6_msource *ims,
    uint8_t t)
{
	IN6M_LOCK_ASSERT_HELD(__DECONST(struct in6_multi *, inm));

	t = !!t;
	if (inm->in6m_st[t].iss_ex > 0 &&
	    inm->in6m_st[t].iss_ex == ims->im6s_st[t].ex)
		return (MCAST_EXCLUDE);
	else if (ims->im6s_st[t].in > 0 && ims->im6s_st[t].ex == 0)
		return (MCAST_INCLUDE);
	return (MCAST_UNDEFINED);
}

/*
 * Merge socket-layer source into MLD-layer source.
 * If rollback is non-zero, perform the inverse of the merge.
 */
static void
im6s_merge(struct ip6_msource *ims, const struct in6_msource *lims,
    const int rollback)
{
	int n = rollback ? -1 : 1;

	if (lims->im6sl_st[0] == MCAST_EXCLUDE) {
		MLD_PRINTF(("%s: t1 ex -= %d on %s\n", __func__, n,
		    ip6_sprintf(&lims->im6s_addr)));
		ims->im6s_st[1].ex -= n;
	} else if (lims->im6sl_st[0] == MCAST_INCLUDE) {
		MLD_PRINTF(("%s: t1 in -= %d on %s\n", __func__, n,
		    ip6_sprintf(&lims->im6s_addr)));
		ims->im6s_st[1].in -= n;
	}

	if (lims->im6sl_st[1] == MCAST_EXCLUDE) {
		MLD_PRINTF(("%s: t1 ex += %d on %s\n", __func__, n,
		    ip6_sprintf(&lims->im6s_addr)));
		ims->im6s_st[1].ex += n;
	} else if (lims->im6sl_st[1] == MCAST_INCLUDE) {
		MLD_PRINTF(("%s: t1 in += %d on %s\n", __func__, n,
		    ip6_sprintf(&lims->im6s_addr)));
		ims->im6s_st[1].in += n;
	}
}

/*
 * Atomically update the global in6_multi state, when a membership's
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
in6m_merge(struct in6_multi *inm, /*const*/ struct in6_mfilter *imf)
{
	struct ip6_msource	*ims, *nims;
	struct in6_msource	*lims;
	int			 schanged, error;
	int			 nsrc0, nsrc1;

	IN6M_LOCK_ASSERT_HELD(inm);

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
	RB_FOREACH(ims, ip6_msource_tree, &imf->im6f_sources) {
		lims = (struct in6_msource *)ims;
		if (lims->im6sl_st[0] == imf->im6f_st[0]) nsrc0++;
		if (lims->im6sl_st[1] == imf->im6f_st[1]) nsrc1++;
		if (lims->im6sl_st[0] == lims->im6sl_st[1]) continue;
		error = in6m_get_source(inm, &lims->im6s_addr, 0, &nims);
		++schanged;
		if (error)
			break;
		im6s_merge(nims, lims, 0);
	}
	if (error) {
		struct ip6_msource *bims;

		RB_FOREACH_REVERSE_FROM(ims, ip6_msource_tree, nims) {
			lims = (struct in6_msource *)ims;
			if (lims->im6sl_st[0] == lims->im6sl_st[1])
				continue;
			(void) in6m_get_source(inm, &lims->im6s_addr, 1, &bims);
			if (bims == NULL)
				continue;
			im6s_merge(bims, lims, 1);
		}
		goto out_reap;
	}

	MLD_PRINTF(("%s: imf filters in-mode: %d at t0, %d at t1\n",
	    __func__, nsrc0, nsrc1));

	/* Handle transition between INCLUDE {n} and INCLUDE {} on socket. */
	if (imf->im6f_st[0] == imf->im6f_st[1] &&
	    imf->im6f_st[1] == MCAST_INCLUDE) {
		if (nsrc1 == 0) {
			MLD_PRINTF(("%s: --in on inm at t1\n", __func__));
			--inm->in6m_st[1].iss_in;
		}
	}

	/* Handle filter mode transition on socket. */
	if (imf->im6f_st[0] != imf->im6f_st[1]) {
		MLD_PRINTF(("%s: imf transition %d to %d\n",
		    __func__, imf->im6f_st[0], imf->im6f_st[1]));

		if (imf->im6f_st[0] == MCAST_EXCLUDE) {
			MLD_PRINTF(("%s: --ex on inm at t1\n", __func__));
			--inm->in6m_st[1].iss_ex;
		} else if (imf->im6f_st[0] == MCAST_INCLUDE) {
			MLD_PRINTF(("%s: --in on inm at t1\n", __func__));
			--inm->in6m_st[1].iss_in;
		}

		if (imf->im6f_st[1] == MCAST_EXCLUDE) {
			MLD_PRINTF(("%s: ex++ on inm at t1\n", __func__));
			inm->in6m_st[1].iss_ex++;
		} else if (imf->im6f_st[1] == MCAST_INCLUDE && nsrc1 > 0) {
			MLD_PRINTF(("%s: in++ on inm at t1\n", __func__));
			inm->in6m_st[1].iss_in++;
		}
	}

	/*
	 * Track inm filter state in terms of listener counts.
	 * If there are any exclusive listeners, stack-wide
	 * membership is exclusive.
	 * Otherwise, if only inclusive listeners, stack-wide is inclusive.
	 * If no listeners remain, state is undefined at t1,
	 * and the MLD lifecycle for this group should finish.
	 */
	if (inm->in6m_st[1].iss_ex > 0) {
		MLD_PRINTF(("%s: transition to EX\n", __func__));
		inm->in6m_st[1].iss_fmode = MCAST_EXCLUDE;
	} else if (inm->in6m_st[1].iss_in > 0) {
		MLD_PRINTF(("%s: transition to IN\n", __func__));
		inm->in6m_st[1].iss_fmode = MCAST_INCLUDE;
	} else {
		MLD_PRINTF(("%s: transition to UNDEF\n", __func__));
		inm->in6m_st[1].iss_fmode = MCAST_UNDEFINED;
	}

	/* Decrement ASM listener count on transition out of ASM mode. */
	if (imf->im6f_st[0] == MCAST_EXCLUDE && nsrc0 == 0) {
		if ((imf->im6f_st[1] != MCAST_EXCLUDE) ||
		    (imf->im6f_st[1] == MCAST_EXCLUDE && nsrc1 > 0)) {
			MLD_PRINTF(("%s: --asm on inm at t1\n", __func__));
			--inm->in6m_st[1].iss_asm;
		}
	}

	/* Increment ASM listener count on transition to ASM mode. */
	if (imf->im6f_st[1] == MCAST_EXCLUDE && nsrc1 == 0) {
		MLD_PRINTF(("%s: asm++ on inm at t1\n", __func__));
		inm->in6m_st[1].iss_asm++;
	}

	MLD_PRINTF(("%s: merged imf 0x%llx to inm 0x%llx\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(imf),
	    (uint64_t)VM_KERNEL_ADDRPERM(inm)));
	in6m_print(inm);

out_reap:
	if (schanged > 0) {
		MLD_PRINTF(("%s: sources changed; reaping\n", __func__));
		in6m_reap(inm);
	}
	return (error);
}

/*
 * Mark an in6_multi's filter set deltas as committed.
 * Called by MLD after a state change has been enqueued.
 */
void
in6m_commit(struct in6_multi *inm)
{
	struct ip6_msource	*ims;

	IN6M_LOCK_ASSERT_HELD(inm);

	MLD_PRINTF(("%s: commit inm 0x%llx\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(inm)));
	MLD_PRINTF(("%s: pre commit:\n", __func__));
	in6m_print(inm);

	RB_FOREACH(ims, ip6_msource_tree, &inm->in6m_srcs) {
		ims->im6s_st[0] = ims->im6s_st[1];
	}
	inm->in6m_st[0] = inm->in6m_st[1];
}

/*
 * Reap unreferenced nodes from an in6_multi's filter set.
 */
static void
in6m_reap(struct in6_multi *inm)
{
	struct ip6_msource	*ims, *tims;

	IN6M_LOCK_ASSERT_HELD(inm);

	RB_FOREACH_SAFE(ims, ip6_msource_tree, &inm->in6m_srcs, tims) {
		if (ims->im6s_st[0].ex > 0 || ims->im6s_st[0].in > 0 ||
		    ims->im6s_st[1].ex > 0 || ims->im6s_st[1].in > 0 ||
		    ims->im6s_stp != 0)
			continue;
		MLD_PRINTF(("%s: free ims 0x%llx\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(ims)));
		RB_REMOVE(ip6_msource_tree, &inm->in6m_srcs, ims);
		ip6ms_free(ims);
		inm->in6m_nsrc--;
	}
}

/*
 * Purge all source nodes from an in6_multi's filter set.
 */
void
in6m_purge(struct in6_multi *inm)
{
	struct ip6_msource	*ims, *tims;

	IN6M_LOCK_ASSERT_HELD(inm);

	RB_FOREACH_SAFE(ims, ip6_msource_tree, &inm->in6m_srcs, tims) {
		MLD_PRINTF(("%s: free ims 0x%llx\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(ims)));
		RB_REMOVE(ip6_msource_tree, &inm->in6m_srcs, ims);
		ip6ms_free(ims);
		inm->in6m_nsrc--;
	}
}

/*
 * Join a multicast address w/o sources.
 * KAME compatibility entry point.
 *
 */
struct in6_multi_mship *
in6_joingroup(struct ifnet *ifp, struct in6_addr *mcaddr,
    int *errorp, int delay)
{
	struct in6_multi_mship *imm;
	int error;

	*errorp = 0;

	imm = in6_multi_mship_alloc(M_WAITOK);
	if (imm == NULL) {
		*errorp = ENOBUFS;
		return (NULL);
	}

	error = in6_mc_join(ifp, mcaddr, NULL, &imm->i6mm_maddr, delay);
	if (error) {
		*errorp = error;
		in6_multi_mship_free(imm);
		return (NULL);
	}

	return (imm);
}

/*
 * Leave a multicast address w/o sources.
 * KAME compatibility entry point.
 */
int
in6_leavegroup(struct in6_multi_mship *imm)
{
	if (imm->i6mm_maddr != NULL) {
		in6_mc_leave(imm->i6mm_maddr, NULL);
		IN6M_REMREF(imm->i6mm_maddr);
		imm->i6mm_maddr = NULL;
	}
	in6_multi_mship_free(imm);
	return 0;
}

/*
 * Join a multicast group; real entry point.
 *
 * Only preserves atomicity at inm level.
 * NOTE: imf argument cannot be const due to sys/tree.h limitations.
 *
 * If the MLD downcall fails, the group is not joined, and an error
 * code is returned.
 */
int
in6_mc_join(struct ifnet *ifp, const struct in6_addr *mcaddr,
    /*const*/ struct in6_mfilter *imf, struct in6_multi **pinm,
    const int delay)
{
	struct in6_mfilter	 timf;
	struct in6_multi	*inm = NULL;
	int			 error = 0;
	struct mld_tparams	 mtp;

	/*
	 * Sanity: Check scope zone ID was set for ifp, if and
	 * only if group is scoped to an interface.
	 */
	VERIFY(IN6_IS_ADDR_MULTICAST(mcaddr));
	if (IN6_IS_ADDR_MC_LINKLOCAL(mcaddr) ||
	    IN6_IS_ADDR_MC_INTFACELOCAL(mcaddr)) {
		VERIFY(mcaddr->s6_addr16[1] != 0);
	}

	MLD_PRINTF(("%s: join %s on 0x%llx(%s))\n", __func__,
	    ip6_sprintf(mcaddr), (uint64_t)VM_KERNEL_ADDRPERM(ifp),
	    if_name(ifp)));

	bzero(&mtp, sizeof (mtp));
	*pinm = NULL;

	/*
	 * If no imf was specified (i.e. kernel consumer),
	 * fake one up and assume it is an ASM join.
	 */
	if (imf == NULL) {
		im6f_init(&timf, MCAST_UNDEFINED, MCAST_EXCLUDE);
		imf = &timf;
	}

	error = in6_mc_get(ifp, mcaddr, &inm);
	if (error) {
		MLD_PRINTF(("%s: in6_mc_get() failure\n", __func__));
		return (error);
	}

	MLD_PRINTF(("%s: merge inm state\n", __func__));

	IN6M_LOCK(inm);
	error = in6m_merge(inm, imf);
	if (error) {
		MLD_PRINTF(("%s: failed to merge inm state\n", __func__));
		goto out_in6m_release;
	}

	MLD_PRINTF(("%s: doing mld downcall\n", __func__));
	error = mld_change_state(inm, &mtp, delay);
	if (error) {
		MLD_PRINTF(("%s: failed to update source\n", __func__));
		im6f_rollback(imf);
		goto out_in6m_release;
	}

out_in6m_release:
	if (error) {
		MLD_PRINTF(("%s: dropping ref on 0x%llx\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(inm)));
		IN6M_UNLOCK(inm);
		IN6M_REMREF(inm);
	} else {
		IN6M_UNLOCK(inm);
		*pinm = inm;	/* keep refcount from in6_mc_get() */
	}

	/* schedule timer now that we've dropped the lock(s) */
	mld_set_timeout(&mtp);

	return (error);
}

/*
 * Leave a multicast group; real entry point.
 * All source filters will be expunged.
 *
 * Only preserves atomicity at inm level.
 *
 * Holding the write lock for the INP which contains imf
 * is highly advisable. We can't assert for it as imf does not
 * contain a back-pointer to the owning inp.
 *
 * Note: This is not the same as in6m_release(*) as this function also
 * makes a state change downcall into MLD.
 */
int
in6_mc_leave(struct in6_multi *inm, /*const*/ struct in6_mfilter *imf)
{
	struct in6_mfilter	 timf;
	int			 error, lastref;
	struct mld_tparams	 mtp;

	bzero(&mtp, sizeof (mtp));
	error = 0;

	IN6M_LOCK_ASSERT_NOTHELD(inm);

	in6_multihead_lock_exclusive();
	IN6M_LOCK(inm);

	MLD_PRINTF(("%s: leave inm 0x%llx, %s/%s%d, imf 0x%llx\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(inm), ip6_sprintf(&inm->in6m_addr),
	    (in6m_is_ifp_detached(inm) ? "null" : inm->in6m_ifp->if_name),
	    inm->in6m_ifp->if_unit, (uint64_t)VM_KERNEL_ADDRPERM(imf)));

	/*
	 * If no imf was specified (i.e. kernel consumer),
	 * fake one up and assume it is an ASM join.
	 */
	if (imf == NULL) {
		im6f_init(&timf, MCAST_EXCLUDE, MCAST_UNDEFINED);
		imf = &timf;
	}

	/*
	 * Begin state merge transaction at MLD layer.
	 *
	 * As this particular invocation should not cause any memory
	 * to be allocated, and there is no opportunity to roll back
	 * the transaction, it MUST NOT fail.
	 */
	MLD_PRINTF(("%s: merge inm state\n", __func__));

	error = in6m_merge(inm, imf);
	KASSERT(error == 0, ("%s: failed to merge inm state\n", __func__));

	MLD_PRINTF(("%s: doing mld downcall\n", __func__));
	error = mld_change_state(inm, &mtp, 0);
#if MLD_DEBUG
	if (error)
		MLD_PRINTF(("%s: failed mld downcall\n", __func__));
#endif
	lastref = in6_multi_detach(inm);
	VERIFY(!lastref || (!(inm->in6m_debug & IFD_ATTACHED) &&
	    inm->in6m_reqcnt == 0));
	IN6M_UNLOCK(inm);
	in6_multihead_lock_done();

	if (lastref)
		IN6M_REMREF(inm);	/* for in6_multihead list */

	/* schedule timer now that we've dropped the lock(s) */
	mld_set_timeout(&mtp);

	return (error);
}

/*
 * Block or unblock an ASM multicast source on an inpcb.
 * This implements the delta-based API described in RFC 3678.
 *
 * The delta-based API applies only to exclusive-mode memberships.
 * An MLD downcall will be performed.
 *
 * Return 0 if successful, otherwise return an appropriate error code.
 */
static int
in6p_block_unblock_source(struct inpcb *inp, struct sockopt *sopt)
{
	struct group_source_req		 gsr;
	sockunion_t			*gsa, *ssa;
	struct ifnet			*ifp;
	struct in6_mfilter		*imf;
	struct ip6_moptions		*imo;
	struct in6_msource		*ims;
	struct in6_multi		*inm;
	size_t				 idx;
	uint16_t			 fmode;
	int				 error, doblock;
	struct mld_tparams		 mtp;

	bzero(&mtp, sizeof (mtp));
	ifp = NULL;
	error = 0;
	doblock = 0;

	memset(&gsr, 0, sizeof(struct group_source_req));
	gsa = (sockunion_t *)&gsr.gsr_group;
	ssa = (sockunion_t *)&gsr.gsr_source;

	switch (sopt->sopt_name) {
	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
		error = sooptcopyin(sopt, &gsr,
		    sizeof(struct group_source_req),
		    sizeof(struct group_source_req));
		if (error)
			return (error);

		if (gsa->sin6.sin6_family != AF_INET6 ||
		    gsa->sin6.sin6_len != sizeof(struct sockaddr_in6))
			return (EINVAL);

		if (ssa->sin6.sin6_family != AF_INET6 ||
		    ssa->sin6.sin6_len != sizeof(struct sockaddr_in6))
			return (EINVAL);

		ifnet_head_lock_shared();
		if (gsr.gsr_interface == 0 ||
		    (u_int)if_index < gsr.gsr_interface) {
			ifnet_head_done();
			return (EADDRNOTAVAIL);
		}

		ifp = ifindex2ifnet[gsr.gsr_interface];
		ifnet_head_done();

		if (ifp == NULL)
			return (EADDRNOTAVAIL);

		if (sopt->sopt_name == MCAST_BLOCK_SOURCE)
			doblock = 1;
		break;

	default:
		MLD_PRINTF(("%s: unknown sopt_name %d\n",
		    __func__, sopt->sopt_name));
		return (EOPNOTSUPP);
		break;
	}

	if (!IN6_IS_ADDR_MULTICAST(&gsa->sin6.sin6_addr))
		return (EINVAL);

	(void) in6_setscope(&gsa->sin6.sin6_addr, ifp, NULL);

	/*
	 * Check if we are actually a member of this group.
	 */
	imo = in6p_findmoptions(inp);
	if (imo == NULL)
		return (ENOMEM);

	IM6O_LOCK(imo);
	idx = im6o_match_group(imo, ifp, &gsa->sa);
	if (idx == (size_t)-1 || imo->im6o_mfilters == NULL) {
		error = EADDRNOTAVAIL;
		goto out_imo_locked;
	}

	VERIFY(imo->im6o_mfilters != NULL);
	imf = &imo->im6o_mfilters[idx];
	inm = imo->im6o_membership[idx];

	/*
	 * Attempting to use the delta-based API on an
	 * non exclusive-mode membership is an error.
	 */
	fmode = imf->im6f_st[0];
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
	ims = im6o_match_source(imo, idx, &ssa->sa);
	if ((ims != NULL && doblock) || (ims == NULL && !doblock)) {
		MLD_PRINTF(("%s: source %s %spresent\n", __func__,
		    ip6_sprintf(&ssa->sin6.sin6_addr),
		    doblock ? "" : "not "));
		error = EADDRNOTAVAIL;
		goto out_imo_locked;
	}

	/*
	 * Begin state merge transaction at socket layer.
	 */
	if (doblock) {
		MLD_PRINTF(("%s: %s source\n", __func__, "block"));
		ims = im6f_graft(imf, fmode, &ssa->sin6);
		if (ims == NULL)
			error = ENOMEM;
	} else {
		MLD_PRINTF(("%s: %s source\n", __func__, "allow"));
		error = im6f_prune(imf, &ssa->sin6);
	}

	if (error) {
		MLD_PRINTF(("%s: merge imf state failed\n", __func__));
		goto out_im6f_rollback;
	}

	/*
	 * Begin state merge transaction at MLD layer.
	 */
	IN6M_LOCK(inm);
	MLD_PRINTF(("%s: merge inm state\n", __func__));
	error = in6m_merge(inm, imf);
	if (error) {
		MLD_PRINTF(("%s: failed to merge inm state\n", __func__));
		IN6M_UNLOCK(inm);
		goto out_im6f_rollback;
	}

	MLD_PRINTF(("%s: doing mld downcall\n", __func__));
	error = mld_change_state(inm, &mtp, 0);
	IN6M_UNLOCK(inm);
#if MLD_DEBUG
	if (error)
		MLD_PRINTF(("%s: failed mld downcall\n", __func__));
#endif

out_im6f_rollback:
	if (error)
		im6f_rollback(imf);
	else
		im6f_commit(imf);

	im6f_reap(imf);

out_imo_locked:
	IM6O_UNLOCK(imo);
	IM6O_REMREF(imo);	/* from in6p_findmoptions() */

	/* schedule timer now that we've dropped the lock(s) */
	mld_set_timeout(&mtp);

	return (error);
}

/*
 * Given an inpcb, return its multicast options structure pointer.  Accepts
 * an unlocked inpcb pointer, but will return it locked.  May sleep.
 *
 */
static struct ip6_moptions *
in6p_findmoptions(struct inpcb *inp)
{
	struct ip6_moptions	 *imo;
	struct in6_multi	**immp;
	struct in6_mfilter	 *imfp;
	size_t			  idx;

	if ((imo = inp->in6p_moptions) != NULL) {
		IM6O_ADDREF(imo);	/* for caller */
		return (imo);
	}

	imo = ip6_allocmoptions(M_WAITOK);
	if (imo == NULL)
		return (NULL);

	immp = _MALLOC(sizeof (*immp) * IPV6_MIN_MEMBERSHIPS, M_IP6MOPTS,
	    M_WAITOK | M_ZERO);
	if (immp == NULL) {
		IM6O_REMREF(imo);
		return (NULL);
	}

	imfp = _MALLOC(sizeof (struct in6_mfilter) * IPV6_MIN_MEMBERSHIPS,
	    M_IN6MFILTER, M_WAITOK | M_ZERO);
	if (imfp == NULL) {
		_FREE(immp, M_IP6MOPTS);
		IM6O_REMREF(imo);
		return (NULL);
	}

	imo->im6o_multicast_ifp = NULL;
	imo->im6o_multicast_hlim = ip6_defmcasthlim;
	imo->im6o_multicast_loop = in6_mcast_loop;
	imo->im6o_num_memberships = 0;
	imo->im6o_max_memberships = IPV6_MIN_MEMBERSHIPS;
	imo->im6o_membership = immp;

	/* Initialize per-group source filters. */
	for (idx = 0; idx < IPV6_MIN_MEMBERSHIPS; idx++)
		im6f_init(&imfp[idx], MCAST_UNDEFINED, MCAST_EXCLUDE);

	imo->im6o_mfilters = imfp;
	inp->in6p_moptions = imo; /* keep reference from ip6_allocmoptions() */
	IM6O_ADDREF(imo);	/* for caller */

	return (imo);
}

/*
 * Atomically get source filters on a socket for an IPv6 multicast group.
 * Called with INP lock held; returns with lock released.
 */
static int
in6p_get_source_filters(struct inpcb *inp, struct sockopt *sopt)
{
	struct __msfilterreq64	msfr, msfr64;
	struct __msfilterreq32	msfr32;
	sockunion_t		*gsa;
	struct ifnet		*ifp;
	struct ip6_moptions	*imo;
	struct in6_mfilter	*imf;
	struct ip6_msource	*ims;
	struct in6_msource	*lims;
	struct sockaddr_in6	*psin;
	struct sockaddr_storage	*ptss;
	struct sockaddr_storage	*tss;
	int	 		 error;
	size_t		 	 idx, nsrcs, ncsrcs;
	user_addr_t 		 tmp_ptr;

	imo = inp->in6p_moptions;
	VERIFY(imo != NULL);

	if (IS_64BIT_PROCESS(current_proc())) {
		error = sooptcopyin(sopt, &msfr64,
		    sizeof(struct __msfilterreq64),
		    sizeof(struct __msfilterreq64));
		if (error)
			return (error);
		/* we never use msfr.msfr_srcs; */
		memcpy(&msfr, &msfr64, sizeof(msfr));
	} else {
		error = sooptcopyin(sopt, &msfr32,
		    sizeof(struct __msfilterreq32),
		    sizeof(struct __msfilterreq32));
		if (error)
			return (error);
		/* we never use msfr.msfr_srcs; */
		memcpy(&msfr, &msfr32, sizeof(msfr));
	}

	if (msfr.msfr_group.ss_family != AF_INET6 ||
	    msfr.msfr_group.ss_len != sizeof(struct sockaddr_in6))
		return (EINVAL);

	gsa = (sockunion_t *)&msfr.msfr_group;
	if (!IN6_IS_ADDR_MULTICAST(&gsa->sin6.sin6_addr))
		return (EINVAL);

	ifnet_head_lock_shared();
	if (msfr.msfr_ifindex == 0 || (u_int)if_index < msfr.msfr_ifindex) {
		ifnet_head_done();
		return (EADDRNOTAVAIL);
	}
	ifp = ifindex2ifnet[msfr.msfr_ifindex];
	ifnet_head_done();

	if (ifp == NULL)
		return (EADDRNOTAVAIL);

	if ((size_t) msfr.msfr_nsrcs >
	    UINT32_MAX / sizeof(struct sockaddr_storage))
		msfr.msfr_nsrcs = UINT32_MAX / sizeof(struct sockaddr_storage);

	if (msfr.msfr_nsrcs > in6_mcast_maxsocksrc)
		msfr.msfr_nsrcs = in6_mcast_maxsocksrc;

	(void)in6_setscope(&gsa->sin6.sin6_addr, ifp, NULL);

	IM6O_LOCK(imo);
	/*
	 * Lookup group on the socket.
	 */
	idx = im6o_match_group(imo, ifp, &gsa->sa);
	if (idx == (size_t)-1 || imo->im6o_mfilters == NULL) {
		IM6O_UNLOCK(imo);
		return (EADDRNOTAVAIL);
	}
	imf = &imo->im6o_mfilters[idx];

	/*
	 * Ignore memberships which are in limbo.
	 */
	if (imf->im6f_st[1] == MCAST_UNDEFINED) {
		IM6O_UNLOCK(imo);
		return (EAGAIN);
	}
	msfr.msfr_fmode = imf->im6f_st[1];

	/*
	 * If the user specified a buffer, copy out the source filter
	 * entries to userland gracefully.
	 * We only copy out the number of entries which userland
	 * has asked for, but we always tell userland how big the
	 * buffer really needs to be.
	 */
	tss = NULL;

	if (IS_64BIT_PROCESS(current_proc())) 
		tmp_ptr = msfr64.msfr_srcs;
	else
		tmp_ptr = CAST_USER_ADDR_T(msfr32.msfr_srcs);

	if (tmp_ptr != USER_ADDR_NULL && msfr.msfr_nsrcs > 0) {
		tss = _MALLOC((size_t) msfr.msfr_nsrcs * sizeof(*tss),
		    M_TEMP, M_WAITOK | M_ZERO);
		if (tss == NULL) {
			IM6O_UNLOCK(imo);
			return (ENOBUFS);
		}
		bzero(tss, (size_t) msfr.msfr_nsrcs * sizeof(*tss));
	}

	/*
	 * Count number of sources in-mode at t0.
	 * If buffer space exists and remains, copy out source entries.
	 */
	nsrcs = msfr.msfr_nsrcs;
	ncsrcs = 0;
	ptss = tss;
	RB_FOREACH(ims, ip6_msource_tree, &imf->im6f_sources) {
		lims = (struct in6_msource *)ims;
		if (lims->im6sl_st[0] == MCAST_UNDEFINED ||
		    lims->im6sl_st[0] != imf->im6f_st[0])
			continue;
		if (tss != NULL && nsrcs > 0) {
			psin = (struct sockaddr_in6 *)ptss;
			psin->sin6_family = AF_INET6;
			psin->sin6_len = sizeof(struct sockaddr_in6);
			psin->sin6_addr = lims->im6s_addr;
			psin->sin6_port = 0;
			--nsrcs;
			++ptss;
			++ncsrcs;
		}
	}

	IM6O_UNLOCK(imo);

	if (tss != NULL) {
		error = copyout(tss, tmp_ptr, ncsrcs * sizeof(*tss));
		FREE(tss, M_TEMP);
		if (error)
			return (error);
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
		memcpy(&msfr64.msfr_group, &msfr.msfr_group,
		    sizeof(struct sockaddr_storage));
		error = sooptcopyout(sopt, &msfr32,
		    sizeof(struct __msfilterreq32));
	}

	return (error);
}

/*
 * Return the IP multicast options in response to user getsockopt().
 */
int
ip6_getmoptions(struct inpcb *inp, struct sockopt *sopt)
{
	struct ip6_moptions	*im6o;
	int			 error;
	u_int			 optval;

	im6o = inp->in6p_moptions;
	/*
	 * If socket is neither of type SOCK_RAW or SOCK_DGRAM,
	 * or is a divert socket, reject it.
	 */
	if (SOCK_PROTO(inp->inp_socket) == IPPROTO_DIVERT ||
	    (SOCK_TYPE(inp->inp_socket) != SOCK_RAW &&
	    SOCK_TYPE(inp->inp_socket) != SOCK_DGRAM)) {
		return (EOPNOTSUPP);
	}

	error = 0;
	switch (sopt->sopt_name) {
	case IPV6_MULTICAST_IF:
		if (im6o != NULL)
			IM6O_LOCK(im6o);
		if (im6o == NULL || im6o->im6o_multicast_ifp == NULL) {
			optval = 0;
		} else {
			optval = im6o->im6o_multicast_ifp->if_index;
		}
		if (im6o != NULL)
			IM6O_UNLOCK(im6o);
		error = sooptcopyout(sopt, &optval, sizeof(u_int));
		break;

	case IPV6_MULTICAST_HOPS:
		if (im6o == NULL) {
			optval = ip6_defmcasthlim;
		} else {
			IM6O_LOCK(im6o);
			optval = im6o->im6o_multicast_hlim;
			IM6O_UNLOCK(im6o);
		}
		error = sooptcopyout(sopt, &optval, sizeof(u_int));
		break;

	case IPV6_MULTICAST_LOOP:
		if (im6o == NULL) {
			optval = in6_mcast_loop; /* XXX VIMAGE */
		} else {
			IM6O_LOCK(im6o);
			optval = im6o->im6o_multicast_loop;
			IM6O_UNLOCK(im6o);
		}
		error = sooptcopyout(sopt, &optval, sizeof(u_int));
		break;

	case IPV6_MSFILTER:
		if (im6o == NULL) {
			error = EADDRNOTAVAIL;
		} else {
			error = in6p_get_source_filters(inp, sopt);
		}
		break;

	default:
		error = ENOPROTOOPT;
		break;
	}

	return (error);
}

/*
 * Look up the ifnet to use for a multicast group membership,
 * given the address of an IPv6 group.
 *
 * This routine exists to support legacy IPv6 multicast applications.
 *
 * If inp is non-NULL and is bound to an interface, use this socket's
 * inp_boundif for any required routing table lookup.
 *
 * If the route lookup fails, return NULL.
 *
 * FUTURE: Support multiple forwarding tables for IPv6.
 *
 * Returns NULL if no ifp could be found.
 */
static struct ifnet *
in6p_lookup_mcast_ifp(const struct inpcb *in6p,
    const struct sockaddr_in6 *gsin6)
{
	struct route_in6	 ro6;
	struct ifnet		*ifp;
	unsigned int		ifscope = IFSCOPE_NONE;

	VERIFY(in6p == NULL || (in6p->inp_vflag & INP_IPV6));
	VERIFY(gsin6->sin6_family == AF_INET6);
	if (IN6_IS_ADDR_MULTICAST(&gsin6->sin6_addr) == 0)  
		return NULL;

	if (in6p != NULL && (in6p->inp_flags & INP_BOUND_IF))
		ifscope = in6p->inp_boundifp->if_index;

	ifp = NULL;
	memset(&ro6, 0, sizeof(struct route_in6));
	memcpy(&ro6.ro_dst, gsin6, sizeof(struct sockaddr_in6));
	rtalloc_scoped_ign((struct route *)&ro6, 0, ifscope);
	if (ro6.ro_rt != NULL) {
		ifp = ro6.ro_rt->rt_ifp;
		VERIFY(ifp != NULL);
	}
	ROUTE_RELEASE(&ro6);

	return (ifp);
}

/*
 * Since ipv6_mreq contains an ifindex and ip_mreq contains an AF_INET
 * address, we need to lookup the AF_INET address when translating an
 * ipv6_mreq structure into an ipmreq structure.
 * This is used when userland performs multicast setsockopt() on AF_INET6
 * sockets with AF_INET multicast addresses (IPv6 v4 mapped addresses).
 */
static int
in6p_lookup_v4addr(struct ipv6_mreq *mreq, struct ip_mreq *v4mreq)
{
	struct ifnet *ifp;
	struct ifaddr *ifa;
	struct sockaddr_in *sin;

	ifnet_head_lock_shared();
	if (mreq->ipv6mr_interface > (unsigned int)if_index) {
		ifnet_head_done();
		return (EADDRNOTAVAIL);
	} else
		ifp = ifindex2ifnet[mreq->ipv6mr_interface];
	ifnet_head_done();
	if (ifp == NULL)
		return (EADDRNOTAVAIL);
	ifa = ifa_ifpgetprimary(ifp, AF_INET);
	if (ifa == NULL)
		return (EADDRNOTAVAIL);
	sin = (struct sockaddr_in *)(uintptr_t)(size_t)ifa->ifa_addr;
	v4mreq->imr_interface.s_addr = sin->sin_addr.s_addr;
	IFA_REMREF(ifa);

	return (0);
}

/*
 * Join an IPv6 multicast group, possibly with a source.
 *
 * FIXME: The KAME use of the unspecified address (::)
 * to join *all* multicast groups is currently unsupported.
 */
static int
in6p_join_group(struct inpcb *inp, struct sockopt *sopt)
{
	struct group_source_req		 gsr;
	sockunion_t			*gsa, *ssa;
	struct ifnet			*ifp;
	struct in6_mfilter		*imf;
	struct ip6_moptions		*imo;
	struct in6_multi		*inm = NULL;
	struct in6_msource		*lims = NULL;
	size_t				 idx;
	int				 error, is_new;
	uint32_t			scopeid = 0;
	struct mld_tparams		mtp;

	bzero(&mtp, sizeof (mtp));
	ifp = NULL;
	imf = NULL;
	error = 0;
	is_new = 0;

	memset(&gsr, 0, sizeof(struct group_source_req));
	gsa = (sockunion_t *)&gsr.gsr_group;
	gsa->ss.ss_family = AF_UNSPEC;
	ssa = (sockunion_t *)&gsr.gsr_source;
	ssa->ss.ss_family = AF_UNSPEC;

	/*
	 * Chew everything into struct group_source_req.
	 * Overwrite the port field if present, as the sockaddr
	 * being copied in may be matched with a binary comparison.
	 * Ignore passed-in scope ID.
	 */
	switch (sopt->sopt_name) {
	case IPV6_JOIN_GROUP: {
		struct ipv6_mreq mreq;
    		struct sockaddr_in6 *gsin6;

		error = sooptcopyin(sopt, &mreq, sizeof(struct ipv6_mreq),
		    sizeof(struct ipv6_mreq));
		if (error)
			return (error);
		if (IN6_IS_ADDR_V4MAPPED(&mreq.ipv6mr_multiaddr)) {
			struct ip_mreq v4mreq;
			struct sockopt v4sopt;

			v4mreq.imr_multiaddr.s_addr =
			    mreq.ipv6mr_multiaddr.s6_addr32[3];
			if (mreq.ipv6mr_interface == 0) 
				v4mreq.imr_interface.s_addr = INADDR_ANY;
			else
				error = in6p_lookup_v4addr(&mreq, &v4mreq);
			if (error)
				return (error);
			v4sopt.sopt_dir     = SOPT_SET;
			v4sopt.sopt_level   = sopt->sopt_level; 
			v4sopt.sopt_name    = IP_ADD_MEMBERSHIP;
			v4sopt.sopt_val     = CAST_USER_ADDR_T(&v4mreq);
			v4sopt.sopt_valsize = sizeof(v4mreq);
			v4sopt.sopt_p       = kernproc;

			return (inp_join_group(inp, &v4sopt));
		}
		gsa->sin6.sin6_family = AF_INET6;
		gsa->sin6.sin6_len = sizeof(struct sockaddr_in6);
		gsa->sin6.sin6_addr = mreq.ipv6mr_multiaddr;

		gsin6 = &gsa->sin6;

		/* Only allow IPv6 multicast addresses */	
		if (IN6_IS_ADDR_MULTICAST(&gsin6->sin6_addr) == 0) {  
			return (EINVAL);
		}

		if (mreq.ipv6mr_interface == 0) {
			ifp = in6p_lookup_mcast_ifp(inp, gsin6);
		} else {
			ifnet_head_lock_shared();
			if ((u_int)if_index < mreq.ipv6mr_interface) {
				ifnet_head_done();
				return (EADDRNOTAVAIL);
			    }
			ifp = ifindex2ifnet[mreq.ipv6mr_interface];
			ifnet_head_done();
		}
		MLD_PRINTF(("%s: ipv6mr_interface = %d, ifp = 0x%llx\n",
		    __func__, mreq.ipv6mr_interface,
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp)));
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
		if (error)
			return (error);

		if (gsa->sin6.sin6_family != AF_INET6 ||
		    gsa->sin6.sin6_len != sizeof(struct sockaddr_in6))
			return (EINVAL);

		if (sopt->sopt_name == MCAST_JOIN_SOURCE_GROUP) {
			if (ssa->sin6.sin6_family != AF_INET6 ||
			    ssa->sin6.sin6_len != sizeof(struct sockaddr_in6))
				return (EINVAL);
			if (IN6_IS_ADDR_MULTICAST(&ssa->sin6.sin6_addr))
				return (EINVAL);
			/*
			 * TODO: Validate embedded scope ID in source
			 * list entry against passed-in ifp, if and only
			 * if source list filter entry is iface or node local.
			 */
			in6_clearscope(&ssa->sin6.sin6_addr);
			ssa->sin6.sin6_port = 0;
			ssa->sin6.sin6_scope_id = 0;
		}

		ifnet_head_lock_shared();
		if (gsr.gsr_interface == 0 ||
		    (u_int)if_index < gsr.gsr_interface) {
			ifnet_head_done();
			return (EADDRNOTAVAIL);
		}
		ifp = ifindex2ifnet[gsr.gsr_interface];
		ifnet_head_done();
		break;

	default:
		MLD_PRINTF(("%s: unknown sopt_name %d\n",
		    __func__, sopt->sopt_name));
		return (EOPNOTSUPP);
		break;
	}

	if (!IN6_IS_ADDR_MULTICAST(&gsa->sin6.sin6_addr))
		return (EINVAL);

	if (ifp == NULL || (ifp->if_flags & IFF_MULTICAST) == 0)
		return (EADDRNOTAVAIL);

	gsa->sin6.sin6_port = 0;
	gsa->sin6.sin6_scope_id = 0;

	/*
	 * Always set the scope zone ID on memberships created from userland.
	 * Use the passed-in ifp to do this.
	 */
	(void)in6_setscope(&gsa->sin6.sin6_addr, ifp, &scopeid);
	/*
	 * Some addresses are not valid without an embedded scopeid.
	 * This check must be present because otherwise we will later hit
	 * a VERIFY() in in6_mc_join().
	 */
	if ((IN6_IS_ADDR_MC_LINKLOCAL(&gsa->sin6.sin6_addr) ||
	    IN6_IS_ADDR_MC_INTFACELOCAL(&gsa->sin6.sin6_addr)) &&
	    (scopeid == 0 || gsa->sin6.sin6_addr.s6_addr16[1] == 0))
		return (EINVAL);

	imo = in6p_findmoptions(inp);
	if (imo == NULL)
		return (ENOMEM);

	IM6O_LOCK(imo);
	idx = im6o_match_group(imo, ifp, &gsa->sa);
	if (idx == (size_t)-1) {
		is_new = 1;
	} else {
		inm = imo->im6o_membership[idx];
		imf = &imo->im6o_mfilters[idx];
		if (ssa->ss.ss_family != AF_UNSPEC) {
			/*
			 * MCAST_JOIN_SOURCE_GROUP on an exclusive membership
			 * is an error. On an existing inclusive membership,
			 * it just adds the source to the filter list.
			 */
			if (imf->im6f_st[1] != MCAST_INCLUDE) {
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
			 * in6_msource is transactioned just as for anything
			 * else in SSM -- but note naive use of in6m_graft()
			 * below for allocating new filter entries.
			 *
			 * This is only an issue if someone mixes the
			 * full-state SSM API with the delta-based API,
			 * which is discouraged in the relevant RFCs.
			 */
			lims = im6o_match_source(imo, idx, &ssa->sa);
			if (lims != NULL /*&&
			    lims->im6sl_st[1] == MCAST_INCLUDE*/) {
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
			if (imf->im6f_st[1] == MCAST_EXCLUDE)
				error = EADDRINUSE;
			goto out_imo_locked;
		}
	}

	/*
	 * Begin state merge transaction at socket layer.
	 */

	if (is_new) {
		if (imo->im6o_num_memberships == imo->im6o_max_memberships) {
			error = im6o_grow(imo, 0);
			if (error)
				goto out_imo_locked;
		}
		/*
		 * Allocate the new slot upfront so we can deal with
		 * grafting the new source filter in same code path
		 * as for join-source on existing membership.
		 */
		idx = imo->im6o_num_memberships;
		imo->im6o_membership[idx] = NULL;
		imo->im6o_num_memberships++;
		VERIFY(imo->im6o_mfilters != NULL);
		imf = &imo->im6o_mfilters[idx];
		VERIFY(RB_EMPTY(&imf->im6f_sources));
	}

	/*
	 * Graft new source into filter list for this inpcb's
	 * membership of the group. The in6_multi may not have
	 * been allocated yet if this is a new membership, however,
	 * the in_mfilter slot will be allocated and must be initialized.
	 *
	 * Note: Grafting of exclusive mode filters doesn't happen
	 * in this path.
	 * XXX: Should check for non-NULL lims (node exists but may
	 * not be in-mode) for interop with full-state API.
	 */
	if (ssa->ss.ss_family != AF_UNSPEC) {
		/* Membership starts in IN mode */
		if (is_new) {
			MLD_PRINTF(("%s: new join w/source\n", __func__);
			im6f_init(imf, MCAST_UNDEFINED, MCAST_INCLUDE));
		} else {
			MLD_PRINTF(("%s: %s source\n", __func__, "allow"));
		}
		lims = im6f_graft(imf, MCAST_INCLUDE, &ssa->sin6);
		if (lims == NULL) {
			MLD_PRINTF(("%s: merge imf state failed\n",
			    __func__));
			error = ENOMEM;
			goto out_im6o_free;
		}
	} else {
		/* No address specified; Membership starts in EX mode */
		if (is_new) {
			MLD_PRINTF(("%s: new join w/o source", __func__));
			im6f_init(imf, MCAST_UNDEFINED, MCAST_EXCLUDE);
		}
	}

	/*
	 * Begin state merge transaction at MLD layer.
	 */

	if (is_new) {
		VERIFY(inm == NULL);
		error = in6_mc_join(ifp, &gsa->sin6.sin6_addr, imf, &inm, 0);
		VERIFY(inm != NULL || error != 0);
		if (error)
			goto out_im6o_free;
		imo->im6o_membership[idx] = inm; /* from in6_mc_join() */
	} else {
		MLD_PRINTF(("%s: merge inm state\n", __func__));
		IN6M_LOCK(inm);
		error = in6m_merge(inm, imf);
		if (error) {
			MLD_PRINTF(("%s: failed to merge inm state\n",
			    __func__));
			IN6M_UNLOCK(inm);
			goto out_im6f_rollback;
		}
		MLD_PRINTF(("%s: doing mld downcall\n", __func__));
		error = mld_change_state(inm, &mtp, 0);
		IN6M_UNLOCK(inm);
		if (error) {
			MLD_PRINTF(("%s: failed mld downcall\n",
			    __func__));
			goto out_im6f_rollback;
		}
	}

out_im6f_rollback:
	if (error) {
		im6f_rollback(imf);
		if (is_new)
			im6f_purge(imf);
		else
			im6f_reap(imf);
	} else {
		im6f_commit(imf);
	}

out_im6o_free:
	if (error && is_new) {
		VERIFY(inm == NULL);
		imo->im6o_membership[idx] = NULL;
		--imo->im6o_num_memberships;
	}

out_imo_locked:
	IM6O_UNLOCK(imo);
	IM6O_REMREF(imo);	/* from in6p_findmoptions() */

	/* schedule timer now that we've dropped the lock(s) */
	mld_set_timeout(&mtp);

	return (error);
}

/*
 * Leave an IPv6 multicast group on an inpcb, possibly with a source.
 */
static int
in6p_leave_group(struct inpcb *inp, struct sockopt *sopt)
{
	struct ipv6_mreq		 mreq;
	struct group_source_req		 gsr;
	sockunion_t			*gsa, *ssa;
	struct ifnet			*ifp;
	struct in6_mfilter		*imf;
	struct ip6_moptions		*imo;
	struct in6_msource		*ims;
	struct in6_multi		*inm = NULL;
	uint32_t			 ifindex = 0;
	size_t				 idx;
	int				 error, is_final;
	struct mld_tparams		 mtp;

	bzero(&mtp, sizeof (mtp));
	ifp = NULL;
	error = 0;
	is_final = 1;

	memset(&gsr, 0, sizeof(struct group_source_req));
	gsa = (sockunion_t *)&gsr.gsr_group;
	gsa->ss.ss_family = AF_UNSPEC;
	ssa = (sockunion_t *)&gsr.gsr_source;
	ssa->ss.ss_family = AF_UNSPEC;

	/*
	 * Chew everything passed in up into a struct group_source_req
	 * as that is easier to process.
	 * Note: Any embedded scope ID in the multicast group passed
	 * in by userland is ignored, the interface index is the recommended
	 * mechanism to specify an interface; see below.
	 */
	switch (sopt->sopt_name) {
	case IPV6_LEAVE_GROUP: {
    		struct sockaddr_in6 *gsin6;

		error = sooptcopyin(sopt, &mreq, sizeof(struct ipv6_mreq),
		    sizeof(struct ipv6_mreq));
		if (error)
			return (error);
		if (IN6_IS_ADDR_V4MAPPED(&mreq.ipv6mr_multiaddr)) {
			struct ip_mreq v4mreq;
			struct sockopt v4sopt;

			v4mreq.imr_multiaddr.s_addr =
			    mreq.ipv6mr_multiaddr.s6_addr32[3];
			if (mreq.ipv6mr_interface == 0) 
				v4mreq.imr_interface.s_addr = INADDR_ANY;
			else
				error = in6p_lookup_v4addr(&mreq, &v4mreq);
			if (error)
				return (error);
			v4sopt.sopt_dir     = SOPT_SET;
			v4sopt.sopt_level   = sopt->sopt_level; 
			v4sopt.sopt_name    = IP_DROP_MEMBERSHIP;
			v4sopt.sopt_val     = CAST_USER_ADDR_T(&v4mreq);
			v4sopt.sopt_valsize = sizeof(v4mreq);
			v4sopt.sopt_p       = kernproc;

			return (inp_leave_group(inp, &v4sopt));
		}
		gsa->sin6.sin6_family = AF_INET6;
		gsa->sin6.sin6_len = sizeof(struct sockaddr_in6);
		gsa->sin6.sin6_addr = mreq.ipv6mr_multiaddr;
		gsa->sin6.sin6_port = 0;
		gsa->sin6.sin6_scope_id = 0;
		ifindex = mreq.ipv6mr_interface;
		gsin6 = &gsa->sin6;
		/* Only allow IPv6 multicast addresses */	
		if (IN6_IS_ADDR_MULTICAST(&gsin6->sin6_addr) == 0) {  
			return (EINVAL);
		}
		break;
	}

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
		if (error)
			return (error);

		if (gsa->sin6.sin6_family != AF_INET6 ||
		    gsa->sin6.sin6_len != sizeof(struct sockaddr_in6))
			return (EINVAL);
		if (sopt->sopt_name == MCAST_LEAVE_SOURCE_GROUP) {
			if (ssa->sin6.sin6_family != AF_INET6 ||
			    ssa->sin6.sin6_len != sizeof(struct sockaddr_in6))
				return (EINVAL);
			if (IN6_IS_ADDR_MULTICAST(&ssa->sin6.sin6_addr))
				return (EINVAL);
			/*
			 * TODO: Validate embedded scope ID in source
			 * list entry against passed-in ifp, if and only
			 * if source list filter entry is iface or node local.
			 */
			in6_clearscope(&ssa->sin6.sin6_addr);
		}
		gsa->sin6.sin6_port = 0;
		gsa->sin6.sin6_scope_id = 0;
		ifindex = gsr.gsr_interface;
		break;

	default:
		MLD_PRINTF(("%s: unknown sopt_name %d\n",
		    __func__, sopt->sopt_name));
		return (EOPNOTSUPP);
		break;
	}

	if (!IN6_IS_ADDR_MULTICAST(&gsa->sin6.sin6_addr))
		return (EINVAL);

	/*
	 * Validate interface index if provided. If no interface index
	 * was provided separately, attempt to look the membership up
	 * from the default scope as a last resort to disambiguate
	 * the membership we are being asked to leave.
	 * XXX SCOPE6 lock potentially taken here.
	 */
	if (ifindex != 0) {
		ifnet_head_lock_shared();
		if ((u_int)if_index < ifindex) {
			ifnet_head_done();
			return (EADDRNOTAVAIL);
		}
		ifp = ifindex2ifnet[ifindex];
		ifnet_head_done();
		if (ifp == NULL)
			return (EADDRNOTAVAIL);
		(void) in6_setscope(&gsa->sin6.sin6_addr, ifp, NULL);
	} else {
		error = sa6_embedscope(&gsa->sin6, ip6_use_defzone);
		if (error)
			return (EADDRNOTAVAIL);
		/*
		 * Some badly behaved applications don't pass an ifindex
		 * or a scope ID, which is an API violation. In this case,
		 * perform a lookup as per a v6 join.
		 *
		 * XXX For now, stomp on zone ID for the corner case.
		 * This is not the 'KAME way', but we need to see the ifp
		 * directly until such time as this implementation is
		 * refactored, assuming the scope IDs are the way to go.
		 */
		ifindex = ntohs(gsa->sin6.sin6_addr.s6_addr16[1]);
		if (ifindex == 0) {
			MLD_PRINTF(("%s: warning: no ifindex, looking up "
			    "ifp for group %s.\n", __func__,
			    ip6_sprintf(&gsa->sin6.sin6_addr)));
			ifp = in6p_lookup_mcast_ifp(inp, &gsa->sin6);
		} else {
			ifnet_head_lock_shared();
			ifp = ifindex2ifnet[ifindex];
			ifnet_head_done();
		}
		if (ifp == NULL)
			return (EADDRNOTAVAIL);
	}

	VERIFY(ifp != NULL);
	MLD_PRINTF(("%s: ifp = 0x%llx\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(ifp)));

	/*
	 * Find the membership in the membership array.
	 */
	imo = in6p_findmoptions(inp);
	if (imo == NULL)
		return (ENOMEM);

	IM6O_LOCK(imo);
	idx = im6o_match_group(imo, ifp, &gsa->sa);
	if (idx == (size_t)-1) {
		error = EADDRNOTAVAIL;
		goto out_locked;
	}
	inm = imo->im6o_membership[idx];
	imf = &imo->im6o_mfilters[idx];

	if (ssa->ss.ss_family != AF_UNSPEC)
		is_final = 0;

	/*
	 * Begin state merge transaction at socket layer.
	 */

	/*
	 * If we were instructed only to leave a given source, do so.
	 * MCAST_LEAVE_SOURCE_GROUP is only valid for inclusive memberships.
	 */
	if (is_final) {
		im6f_leave(imf);
	} else {
		if (imf->im6f_st[0] == MCAST_EXCLUDE) {
			error = EADDRNOTAVAIL;
			goto out_locked;
		}
		ims = im6o_match_source(imo, idx, &ssa->sa);
		if (ims == NULL) {
			MLD_PRINTF(("%s: source %s %spresent\n", __func__,
			    ip6_sprintf(&ssa->sin6.sin6_addr),
			    "not "));
			error = EADDRNOTAVAIL;
			goto out_locked;
		}
		MLD_PRINTF(("%s: %s source\n", __func__, "block"));
		error = im6f_prune(imf, &ssa->sin6);
		if (error) {
			MLD_PRINTF(("%s: merge imf state failed\n",
			    __func__));
			goto out_locked;
		}
	}

	/*
	 * Begin state merge transaction at MLD layer.
	 */

	if (is_final) {
		/*
		 * Give up the multicast address record to which
		 * the membership points.  Reference held in im6o
		 * will be released below.
		 */
		(void) in6_mc_leave(inm, imf);
	} else {
		MLD_PRINTF(("%s: merge inm state\n", __func__));
		IN6M_LOCK(inm);
		error = in6m_merge(inm, imf);
		if (error) {
			MLD_PRINTF(("%s: failed to merge inm state\n",
			    __func__));
			IN6M_UNLOCK(inm);
			goto out_im6f_rollback;
		}

		MLD_PRINTF(("%s: doing mld downcall\n", __func__));
		error = mld_change_state(inm, &mtp, 0);
		if (error) {
			MLD_PRINTF(("%s: failed mld downcall\n", __func__));
		}
		IN6M_UNLOCK(inm);
	}

out_im6f_rollback:
	if (error)
		im6f_rollback(imf);
	else
		im6f_commit(imf);

	im6f_reap(imf);

	if (is_final) {
		/* Remove the gap in the membership array. */
		VERIFY(inm == imo->im6o_membership[idx]);
		imo->im6o_membership[idx] = NULL;
		IN6M_REMREF(inm);
		for (++idx; idx < imo->im6o_num_memberships; ++idx) {
			imo->im6o_membership[idx-1] = imo->im6o_membership[idx];
			imo->im6o_mfilters[idx-1] = imo->im6o_mfilters[idx];
		}
		imo->im6o_num_memberships--;
	}

out_locked:
	IM6O_UNLOCK(imo);
	IM6O_REMREF(imo);	/* from in6p_findmoptions() */

	/* schedule timer now that we've dropped the lock(s) */
	mld_set_timeout(&mtp);

	return (error);
}

/*
 * Select the interface for transmitting IPv6 multicast datagrams.
 *
 * Either an instance of struct in6_addr or an instance of struct ipv6_mreqn
 * may be passed to this socket option. An address of in6addr_any or an
 * interface index of 0 is used to remove a previous selection.
 * When no interface is selected, one is chosen for every send.
 */
static int
in6p_set_multicast_if(struct inpcb *inp, struct sockopt *sopt)
{
	struct ifnet		*ifp;
	struct ip6_moptions	*imo;
	u_int			 ifindex;
	int			 error;

	if (sopt->sopt_valsize != sizeof(u_int))
		return (EINVAL);

	error = sooptcopyin(sopt, &ifindex, sizeof(u_int), sizeof(u_int));
	if (error)
		return (error);

	ifnet_head_lock_shared();
	if ((u_int)if_index < ifindex) {
		ifnet_head_done();
		return (EINVAL);
	}

	ifp = ifindex2ifnet[ifindex];
	ifnet_head_done();
	if (ifp == NULL || (ifp->if_flags & IFF_MULTICAST) == 0)
		return (EADDRNOTAVAIL);

	imo = in6p_findmoptions(inp);
	if (imo == NULL)
		return (ENOMEM);

	IM6O_LOCK(imo);
	imo->im6o_multicast_ifp = ifp;
	IM6O_UNLOCK(imo);
	IM6O_REMREF(imo);	/* from in6p_findmoptions() */

	return (0);
}

/*
 * Atomically set source filters on a socket for an IPv6 multicast group.
 *
 */
static int
in6p_set_source_filters(struct inpcb *inp, struct sockopt *sopt)
{
	struct __msfilterreq64	 msfr, msfr64;
	struct __msfilterreq32	 msfr32;
	sockunion_t		*gsa;
	struct ifnet		*ifp;
	struct in6_mfilter	*imf;
	struct ip6_moptions	*imo;
	struct in6_multi	*inm;
	size_t			 idx;
	int			 error;
	user_addr_t		 tmp_ptr;
	struct mld_tparams	 mtp;

	bzero(&mtp, sizeof (mtp));

	if (IS_64BIT_PROCESS(current_proc())) {
		error = sooptcopyin(sopt, &msfr64,
		    sizeof(struct __msfilterreq64),
		    sizeof(struct __msfilterreq64));
		if (error)
			return (error);
		/* we never use msfr.msfr_srcs; */
		memcpy(&msfr, &msfr64, sizeof(msfr));
	} else {
		error = sooptcopyin(sopt, &msfr32,
		    sizeof(struct __msfilterreq32),
		    sizeof(struct __msfilterreq32));
		if (error)
			return (error);
		/* we never use msfr.msfr_srcs; */
		memcpy(&msfr, &msfr32, sizeof(msfr));
	}

	if ((size_t) msfr.msfr_nsrcs >
	    UINT32_MAX / sizeof(struct sockaddr_storage))
		msfr.msfr_nsrcs = UINT32_MAX / sizeof(struct sockaddr_storage);

	if (msfr.msfr_nsrcs > in6_mcast_maxsocksrc)
		return (ENOBUFS);

	if (msfr.msfr_fmode != MCAST_EXCLUDE &&
	     msfr.msfr_fmode != MCAST_INCLUDE)
		return (EINVAL);

	if (msfr.msfr_group.ss_family != AF_INET6 ||
	    msfr.msfr_group.ss_len != sizeof(struct sockaddr_in6))
		return (EINVAL);

	gsa = (sockunion_t *)&msfr.msfr_group;
	if (!IN6_IS_ADDR_MULTICAST(&gsa->sin6.sin6_addr))
		return (EINVAL);

	gsa->sin6.sin6_port = 0;	/* ignore port */

	ifnet_head_lock_shared();
	if (msfr.msfr_ifindex == 0 || (u_int)if_index < msfr.msfr_ifindex) {
		ifnet_head_done();
		return (EADDRNOTAVAIL);
	}
	ifp = ifindex2ifnet[msfr.msfr_ifindex];
	ifnet_head_done();
	if (ifp == NULL)
		return (EADDRNOTAVAIL);

	(void)in6_setscope(&gsa->sin6.sin6_addr, ifp, NULL);

	/*
	 * Take the INP write lock.
	 * Check if this socket is a member of this group.
	 */
	imo = in6p_findmoptions(inp);
	if (imo == NULL)
		return (ENOMEM);

	IM6O_LOCK(imo);
	idx = im6o_match_group(imo, ifp, &gsa->sa);
	if (idx == (size_t)-1 || imo->im6o_mfilters == NULL) {
		error = EADDRNOTAVAIL;
		goto out_imo_locked;
	}
	inm = imo->im6o_membership[idx];
	imf = &imo->im6o_mfilters[idx];

	/*
	 * Begin state merge transaction at socket layer.
	 */

	imf->im6f_st[1] = msfr.msfr_fmode;

	/*
	 * Apply any new source filters, if present.
	 * Make a copy of the user-space source vector so
	 * that we may copy them with a single copyin. This
	 * allows us to deal with page faults up-front.
	 */
	if (msfr.msfr_nsrcs > 0) {
		struct in6_msource	*lims;
		struct sockaddr_in6	*psin;
		struct sockaddr_storage	*kss, *pkss;
		unsigned int		 i;

		if (IS_64BIT_PROCESS(current_proc())) 
			tmp_ptr = msfr64.msfr_srcs;
		else
			tmp_ptr = CAST_USER_ADDR_T(msfr32.msfr_srcs);

		MLD_PRINTF(("%s: loading %lu source list entries\n",
		    __func__, (unsigned long)msfr.msfr_nsrcs));
		kss = _MALLOC((size_t) msfr.msfr_nsrcs * sizeof(*kss),
		    M_TEMP, M_WAITOK);
		if (kss == NULL) {
			error = ENOMEM;
			goto out_imo_locked;
		}

		error = copyin(tmp_ptr, kss,
		    (size_t) msfr.msfr_nsrcs * sizeof(*kss));
		if (error) {
			FREE(kss, M_TEMP);
			goto out_imo_locked;
		}

		/*
		 * Mark all source filters as UNDEFINED at t1.
		 * Restore new group filter mode, as im6f_leave()
		 * will set it to INCLUDE.
		 */
		im6f_leave(imf);
		imf->im6f_st[1] = msfr.msfr_fmode;

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
		for (i = 0, pkss = kss; i < msfr.msfr_nsrcs; i++, pkss++) {
			psin = (struct sockaddr_in6 *)pkss;
			if (psin->sin6_family != AF_INET6) {
				error = EAFNOSUPPORT;
				break;
			}
			if (psin->sin6_len != sizeof(struct sockaddr_in6)) {
				error = EINVAL;
				break;
			}
			if (IN6_IS_ADDR_MULTICAST(&psin->sin6_addr)) {
				error = EINVAL;
				break;
			}
			/*
			 * TODO: Validate embedded scope ID in source
			 * list entry against passed-in ifp, if and only
			 * if source list filter entry is iface or node local.
			 */
			in6_clearscope(&psin->sin6_addr);
			error = im6f_get_source(imf, psin, &lims);
			if (error)
				break;
			lims->im6sl_st[1] = imf->im6f_st[1];
		}
		FREE(kss, M_TEMP);
	}

	if (error)
		goto out_im6f_rollback;

	/*
	 * Begin state merge transaction at MLD layer.
	 */
	IN6M_LOCK(inm);
	MLD_PRINTF(("%s: merge inm state\n", __func__));
	error = in6m_merge(inm, imf);
	if (error) {
		MLD_PRINTF(("%s: failed to merge inm state\n", __func__));
		IN6M_UNLOCK(inm);
		goto out_im6f_rollback;
	}

	MLD_PRINTF(("%s: doing mld downcall\n", __func__));
	error = mld_change_state(inm, &mtp, 0);
	IN6M_UNLOCK(inm);
#if MLD_DEBUG
	if (error)
		MLD_PRINTF(("%s: failed mld downcall\n", __func__));
#endif

out_im6f_rollback:
	if (error)
		im6f_rollback(imf);
	else
		im6f_commit(imf);

	im6f_reap(imf);

out_imo_locked:
	IM6O_UNLOCK(imo);
	IM6O_REMREF(imo);	/* from in6p_findmoptions() */

	/* schedule timer now that we've dropped the lock(s) */
	mld_set_timeout(&mtp);

	return (error);
}

/*
 * Set the IP multicast options in response to user setsockopt().
 *
 * Many of the socket options handled in this function duplicate the
 * functionality of socket options in the regular unicast API. However,
 * it is not possible to merge the duplicate code, because the idempotence
 * of the IPv6 multicast part of the BSD Sockets API must be preserved;
 * the effects of these options must be treated as separate and distinct.
 *
 */
int
ip6_setmoptions(struct inpcb *inp, struct sockopt *sopt)
{
	struct ip6_moptions	*im6o;
	int			 error;

	error = 0;

	/*
	 * If socket is neither of type SOCK_RAW or SOCK_DGRAM,
	 * or is a divert socket, reject it.
	 */
	if (SOCK_PROTO(inp->inp_socket) == IPPROTO_DIVERT ||
	    (SOCK_TYPE(inp->inp_socket) != SOCK_RAW &&
	     SOCK_TYPE(inp->inp_socket) != SOCK_DGRAM))
		return (EOPNOTSUPP);

	switch (sopt->sopt_name) {
	case IPV6_MULTICAST_IF:
		error = in6p_set_multicast_if(inp, sopt);
		break;

	case IPV6_MULTICAST_HOPS: {
		int hlim;

		if (sopt->sopt_valsize != sizeof(int)) {
			error = EINVAL;
			break;
		}
		error = sooptcopyin(sopt, &hlim, sizeof(hlim), sizeof(int));
		if (error)
			break;
		if (hlim < -1 || hlim > 255) {
			error = EINVAL;
			break;
		} else if (hlim == -1) {
			hlim = ip6_defmcasthlim;
		}
		im6o = in6p_findmoptions(inp);
		if (im6o == NULL) {
			error = ENOMEM;
			break;
		}
		IM6O_LOCK(im6o);
		im6o->im6o_multicast_hlim = hlim;
		IM6O_UNLOCK(im6o);
		IM6O_REMREF(im6o);	/* from in6p_findmoptions() */
		break;
	}

	case IPV6_MULTICAST_LOOP: {
		u_int loop;

		/*
		 * Set the loopback flag for outgoing multicast packets.
		 * Must be zero or one.
		 */
		if (sopt->sopt_valsize != sizeof(u_int)) {
			error = EINVAL;
			break;
		}
		error = sooptcopyin(sopt, &loop, sizeof(u_int), sizeof(u_int));
		if (error)
			break;
		if (loop > 1) {
			error = EINVAL;
			break;
		}
		im6o = in6p_findmoptions(inp);
		if (im6o == NULL) {
			error = ENOMEM;
			break;
		}
		IM6O_LOCK(im6o);
		im6o->im6o_multicast_loop = loop;
		IM6O_UNLOCK(im6o);
		IM6O_REMREF(im6o);	/* from in6p_findmoptions() */
		break;
	}

	case IPV6_JOIN_GROUP:
	case MCAST_JOIN_GROUP:
	case MCAST_JOIN_SOURCE_GROUP:
		error = in6p_join_group(inp, sopt);
		break;

	case IPV6_LEAVE_GROUP:
	case MCAST_LEAVE_GROUP:
	case MCAST_LEAVE_SOURCE_GROUP:
		error = in6p_leave_group(inp, sopt);
		break;

	case MCAST_BLOCK_SOURCE:
	case MCAST_UNBLOCK_SOURCE:
		error = in6p_block_unblock_source(inp, sopt);
		break;

	case IPV6_MSFILTER:
		error = in6p_set_source_filters(inp, sopt);
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}
/*
 * Expose MLD's multicast filter mode and source list(s) to userland,
 * keyed by (ifindex, group).
 * The filter mode is written out as a uint32_t, followed by
 * 0..n of struct in6_addr.
 * For use by ifmcstat(8).
 */
static int
sysctl_ip6_mcast_filters SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp)

	struct in6_addr			 mcaddr;
	struct in6_addr			 src;
	struct ifnet			*ifp;
	struct in6_multi		*inm;
	struct in6_multistep		step;
	struct ip6_msource		*ims;
	int				*name;
	int				 retval = 0;
	u_int				 namelen;
	uint32_t			 fmode, ifindex;

	name = (int *)arg1;
	namelen = arg2;

	if (req->newptr != USER_ADDR_NULL)
		return (EPERM);

	/* int: ifindex + 4 * 32 bits of IPv6 address */
	if (namelen != 5)
		return (EINVAL);

	ifindex = name[0];
	ifnet_head_lock_shared();
	if (ifindex <= 0 || ifindex > (u_int)if_index) {
		MLD_PRINTF(("%s: ifindex %u out of range\n",
		    __func__, ifindex));
		ifnet_head_done();
		return (ENOENT);
	}

	memcpy(&mcaddr, &name[1], sizeof(struct in6_addr));
	if (!IN6_IS_ADDR_MULTICAST(&mcaddr)) {
		MLD_PRINTF(("%s: group %s is not multicast\n",
		    __func__, ip6_sprintf(&mcaddr)));
		ifnet_head_done();
		return (EINVAL);
	}

	ifp = ifindex2ifnet[ifindex];
	ifnet_head_done();
	if (ifp == NULL) {
		MLD_PRINTF(("%s: no ifp for ifindex %u\n", __func__, ifindex));
		return (ENOENT);
	}
	/*
	 * Internal MLD lookups require that scope/zone ID is set.
	 */
	(void)in6_setscope(&mcaddr, ifp, NULL);

	in6_multihead_lock_shared();
	IN6_FIRST_MULTI(step, inm);
	while (inm != NULL) {
		IN6M_LOCK(inm);
		if (inm->in6m_ifp != ifp)
			goto next;

		if (!IN6_ARE_ADDR_EQUAL(&inm->in6m_addr, &mcaddr))
			goto next;

		fmode = inm->in6m_st[1].iss_fmode;
		retval = SYSCTL_OUT(req, &fmode, sizeof(uint32_t));
		if (retval != 0) {
			IN6M_UNLOCK(inm);
			break;		/* abort */
		}
		RB_FOREACH(ims, ip6_msource_tree, &inm->in6m_srcs) {
			MLD_PRINTF(("%s: visit node 0x%llx\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(ims)));
			/*
			 * Only copy-out sources which are in-mode.
			 */
			if (fmode != im6s_get_mode(inm, ims, 1)) {
				MLD_PRINTF(("%s: skip non-in-mode\n",
				    __func__));
				continue; /* process next source */
			}
			src = ims->im6s_addr;
			retval = SYSCTL_OUT(req, &src, sizeof(struct in6_addr));
			if (retval != 0)
				break;	/* process next inm */
		}
next:
		IN6M_UNLOCK(inm);
		IN6_NEXT_MULTI(step, inm);
	}
	in6_multihead_lock_done();

	return (retval);
}

void
in6_multi_init(void)
{
	PE_parse_boot_argn("ifa_debug", &in6m_debug, sizeof (in6m_debug));

	/* Setup lock group and attribute for in6_multihead */
	in6_multihead_lock_grp_attr = lck_grp_attr_alloc_init();
	in6_multihead_lock_grp = lck_grp_alloc_init("in6_multihead",
	    in6_multihead_lock_grp_attr);
	in6_multihead_lock_attr = lck_attr_alloc_init();
	lck_rw_init(&in6_multihead_lock, in6_multihead_lock_grp,
	    in6_multihead_lock_attr);

	lck_mtx_init(&in6m_trash_lock, in6_multihead_lock_grp,
	    in6_multihead_lock_attr);
	TAILQ_INIT(&in6m_trash_head);

	in6m_size = (in6m_debug == 0) ? sizeof (struct in6_multi) :
	    sizeof (struct in6_multi_dbg);
	in6m_zone = zinit(in6m_size, IN6M_ZONE_MAX * in6m_size,
	    0, IN6M_ZONE_NAME);
	if (in6m_zone == NULL) {
		panic("%s: failed allocating %s", __func__, IN6M_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(in6m_zone, Z_EXPAND, TRUE);

	imm_size = sizeof (struct in6_multi_mship);
	imm_zone = zinit(imm_size, IMM_ZONE_MAX * imm_size, 0, IMM_ZONE_NAME);
	if (imm_zone == NULL) {
		panic("%s: failed allocating %s", __func__, IMM_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(imm_zone, Z_EXPAND, TRUE);

	ip6ms_size = sizeof (struct ip6_msource);
	ip6ms_zone = zinit(ip6ms_size, IP6MS_ZONE_MAX * ip6ms_size,
	    0, IP6MS_ZONE_NAME);
	if (ip6ms_zone == NULL) {
		panic("%s: failed allocating %s", __func__, IP6MS_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(ip6ms_zone, Z_EXPAND, TRUE);

	in6ms_size = sizeof (struct in6_msource);
	in6ms_zone = zinit(in6ms_size, IN6MS_ZONE_MAX * in6ms_size,
	    0, IN6MS_ZONE_NAME);
	if (in6ms_zone == NULL) {
		panic("%s: failed allocating %s", __func__, IN6MS_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(in6ms_zone, Z_EXPAND, TRUE);
}

static struct in6_multi *
in6_multi_alloc(int how)
{
	struct in6_multi *in6m;

	in6m = (how == M_WAITOK) ? zalloc(in6m_zone) :
	    zalloc_noblock(in6m_zone);
	if (in6m != NULL) {
		bzero(in6m, in6m_size);
		lck_mtx_init(&in6m->in6m_lock, in6_multihead_lock_grp,
		    in6_multihead_lock_attr);
		in6m->in6m_debug |= IFD_ALLOC;
		if (in6m_debug != 0) {
			in6m->in6m_debug |= IFD_DEBUG;
			in6m->in6m_trace = in6m_trace;
		}
	}
	return (in6m);
}

static void
in6_multi_free(struct in6_multi *in6m)
{
	IN6M_LOCK(in6m);
	if (in6m->in6m_debug & IFD_ATTACHED) {
		panic("%s: attached in6m=%p is being freed", __func__, in6m);
		/* NOTREACHED */
	} else if (in6m->in6m_ifma != NULL) {
		panic("%s: ifma not NULL for in6m=%p", __func__, in6m);
		/* NOTREACHED */
	} else if (!(in6m->in6m_debug & IFD_ALLOC)) {
		panic("%s: in6m %p cannot be freed", __func__, in6m);
		/* NOTREACHED */
	} else if (in6m->in6m_refcount != 0) {
		panic("%s: non-zero refcount in6m=%p", __func__, in6m);
		/* NOTREACHED */
	} else if (in6m->in6m_reqcnt != 0) {
		panic("%s: non-zero reqcnt in6m=%p", __func__, in6m);
		/* NOTREACHED */
	}

	/* Free any pending MLDv2 state-change records */
	IF_DRAIN(&in6m->in6m_scq);

	in6m->in6m_debug &= ~IFD_ALLOC;
	if ((in6m->in6m_debug & (IFD_DEBUG | IFD_TRASHED)) ==
	    (IFD_DEBUG | IFD_TRASHED)) {
		lck_mtx_lock(&in6m_trash_lock);
		TAILQ_REMOVE(&in6m_trash_head, (struct in6_multi_dbg *)in6m,
		    in6m_trash_link);
		lck_mtx_unlock(&in6m_trash_lock);
		in6m->in6m_debug &= ~IFD_TRASHED;
	}
	IN6M_UNLOCK(in6m);

	lck_mtx_destroy(&in6m->in6m_lock, in6_multihead_lock_grp);
	zfree(in6m_zone, in6m);
}

static void
in6_multi_attach(struct in6_multi *in6m)
{
	in6_multihead_lock_assert(LCK_RW_ASSERT_EXCLUSIVE);
	IN6M_LOCK_ASSERT_HELD(in6m);

	if (in6m->in6m_debug & IFD_ATTACHED) {
		panic("%s: Attempt to attach an already attached in6m=%p",
		    __func__, in6m);
		/* NOTREACHED */
	} else if (in6m->in6m_debug & IFD_TRASHED) {
		panic("%s: Attempt to reattach a detached in6m=%p",
		    __func__, in6m);
		/* NOTREACHED */
	}

	in6m->in6m_reqcnt++;
	VERIFY(in6m->in6m_reqcnt == 1);
	IN6M_ADDREF_LOCKED(in6m);
	in6m->in6m_debug |= IFD_ATTACHED;
	/*
	 * Reattach case:  If debugging is enabled, take it
	 * out of the trash list and clear IFD_TRASHED.
	 */
	if ((in6m->in6m_debug & (IFD_DEBUG | IFD_TRASHED)) ==
	    (IFD_DEBUG | IFD_TRASHED)) {
		/* Become a regular mutex, just in case */
		IN6M_CONVERT_LOCK(in6m);
		lck_mtx_lock(&in6m_trash_lock);
		TAILQ_REMOVE(&in6m_trash_head, (struct in6_multi_dbg *)in6m,
		    in6m_trash_link);
		lck_mtx_unlock(&in6m_trash_lock);
		in6m->in6m_debug &= ~IFD_TRASHED;
	}

	LIST_INSERT_HEAD(&in6_multihead, in6m, in6m_entry);
}

int
in6_multi_detach(struct in6_multi *in6m)
{
	in6_multihead_lock_assert(LCK_RW_ASSERT_EXCLUSIVE);
	IN6M_LOCK_ASSERT_HELD(in6m);

	if (in6m->in6m_reqcnt == 0) {
		panic("%s: in6m=%p negative reqcnt", __func__, in6m);
		/* NOTREACHED */
	}

	--in6m->in6m_reqcnt;
	if (in6m->in6m_reqcnt > 0)
		return (0);

	if (!(in6m->in6m_debug & IFD_ATTACHED)) {
		panic("%s: Attempt to detach an unattached record in6m=%p",
		    __func__, in6m);
		/* NOTREACHED */
	} else if (in6m->in6m_debug & IFD_TRASHED) {
		panic("%s: in6m %p is already in trash list", __func__, in6m);
		/* NOTREACHED */
	}

	/*
	 * NOTE: Caller calls IFMA_REMREF
	 */
	in6m->in6m_debug &= ~IFD_ATTACHED;
	LIST_REMOVE(in6m, in6m_entry);

	if (in6m->in6m_debug & IFD_DEBUG) {
		/* Become a regular mutex, just in case */
		IN6M_CONVERT_LOCK(in6m);
		lck_mtx_lock(&in6m_trash_lock);
		TAILQ_INSERT_TAIL(&in6m_trash_head,
		    (struct in6_multi_dbg *)in6m, in6m_trash_link);
		lck_mtx_unlock(&in6m_trash_lock);
		in6m->in6m_debug |= IFD_TRASHED;
	}

	return (1);
}

void
in6m_addref(struct in6_multi *in6m, int locked)
{
	if (!locked)
		IN6M_LOCK_SPIN(in6m);
	else
		IN6M_LOCK_ASSERT_HELD(in6m);

	if (++in6m->in6m_refcount == 0) {
		panic("%s: in6m=%p wraparound refcnt", __func__, in6m);
		/* NOTREACHED */
	} else if (in6m->in6m_trace != NULL) {
		(*in6m->in6m_trace)(in6m, TRUE);
	}
	if (!locked)
		IN6M_UNLOCK(in6m);
}

void
in6m_remref(struct in6_multi *in6m, int locked)
{
	struct ifmultiaddr *ifma;
	struct mld_ifinfo *mli;

	if (!locked)
		IN6M_LOCK_SPIN(in6m);
	else
		IN6M_LOCK_ASSERT_HELD(in6m);

	if (in6m->in6m_refcount == 0 || (in6m->in6m_refcount == 1 && locked)) {
		panic("%s: in6m=%p negative refcnt", __func__, in6m);
		/* NOTREACHED */
	} else if (in6m->in6m_trace != NULL) {
		(*in6m->in6m_trace)(in6m, FALSE);
	}

	--in6m->in6m_refcount;
	if (in6m->in6m_refcount > 0) {
		if (!locked)
			IN6M_UNLOCK(in6m);
		return;
	}

	/*
	 * Synchronization with in6_mc_get().  In the event the in6m has been
	 * detached, the underlying ifma would still be in the if_multiaddrs
	 * list, and thus can be looked up via if_addmulti().  At that point,
	 * the only way to find this in6m is via ifma_protospec.  To avoid
	 * race conditions between the last in6m_remref() of that in6m and its
	 * use via ifma_protospec, in6_multihead lock is used for serialization.
	 * In order to avoid violating the lock order, we must drop in6m_lock
	 * before acquiring in6_multihead lock.  To prevent the in6m from being
	 * freed prematurely, we hold an extra reference.
	 */
	++in6m->in6m_refcount;
	IN6M_UNLOCK(in6m);
	in6_multihead_lock_shared();
	IN6M_LOCK_SPIN(in6m);
	--in6m->in6m_refcount;
	if (in6m->in6m_refcount > 0) {
		/* We've lost the race, so abort since in6m is still in use */
		IN6M_UNLOCK(in6m);
		in6_multihead_lock_done();
		/* If it was locked, return it as such */
		if (locked)
			IN6M_LOCK(in6m);
		return;
	}
	in6m_purge(in6m);
	ifma = in6m->in6m_ifma;
	in6m->in6m_ifma = NULL;
	in6m->in6m_ifp = NULL;
	mli = in6m->in6m_mli;
	in6m->in6m_mli = NULL;
	IN6M_UNLOCK(in6m);
	IFMA_LOCK_SPIN(ifma);
	ifma->ifma_protospec = NULL;
	IFMA_UNLOCK(ifma);
	in6_multihead_lock_done();

	in6_multi_free(in6m);
	if_delmulti_ifma(ifma);
	/* Release reference held to the underlying ifmultiaddr */
	IFMA_REMREF(ifma);

	if (mli != NULL)
		MLI_REMREF(mli);
}

static void
in6m_trace(struct in6_multi *in6m, int refhold)
{
	struct in6_multi_dbg *in6m_dbg = (struct in6_multi_dbg *)in6m;
	ctrace_t *tr;
	u_int32_t idx;
	u_int16_t *cnt;

	if (!(in6m->in6m_debug & IFD_DEBUG)) {
		panic("%s: in6m %p has no debug structure", __func__, in6m);
		/* NOTREACHED */
	}
	if (refhold) {
		cnt = &in6m_dbg->in6m_refhold_cnt;
		tr = in6m_dbg->in6m_refhold;
	} else {
		cnt = &in6m_dbg->in6m_refrele_cnt;
		tr = in6m_dbg->in6m_refrele;
	}

	idx = atomic_add_16_ov(cnt, 1) % IN6M_TRACE_HIST_SIZE;
	ctrace_record(&tr[idx]);
}

static struct in6_multi_mship *
in6_multi_mship_alloc(int how)
{
	struct in6_multi_mship *imm;

	imm = (how == M_WAITOK) ? zalloc(imm_zone) : zalloc_noblock(imm_zone);
	if (imm != NULL)
		bzero(imm, imm_size);

	return (imm);
}

static void
in6_multi_mship_free(struct in6_multi_mship *imm)
{
	if (imm->i6mm_maddr != NULL) {
		panic("%s: i6mm_maddr not NULL for imm=%p", __func__, imm);
		/* NOTREACHED */
	}
	zfree(imm_zone, imm);
}

void
in6_multihead_lock_exclusive(void)
{
	lck_rw_lock_exclusive(&in6_multihead_lock);
}

void
in6_multihead_lock_shared(void)
{
	lck_rw_lock_shared(&in6_multihead_lock);
}

void
in6_multihead_lock_assert(int what)
{
	lck_rw_assert(&in6_multihead_lock, what);
}

void
in6_multihead_lock_done(void)
{
	lck_rw_done(&in6_multihead_lock);
}

static struct ip6_msource *
ip6ms_alloc(int how)
{
	struct ip6_msource *i6ms;

	i6ms = (how == M_WAITOK) ? zalloc(ip6ms_zone) :
	    zalloc_noblock(ip6ms_zone);
	if (i6ms != NULL)
		bzero(i6ms, ip6ms_size);

	return (i6ms);
}

static void
ip6ms_free(struct ip6_msource *i6ms)
{
	zfree(ip6ms_zone, i6ms);
}

static struct in6_msource *
in6ms_alloc(int how)
{
	struct in6_msource *in6ms;

	in6ms = (how == M_WAITOK) ? zalloc(in6ms_zone) :
	    zalloc_noblock(in6ms_zone);
	if (in6ms != NULL)
		bzero(in6ms, in6ms_size);

	return (in6ms);
}

static void
in6ms_free(struct in6_msource *in6ms)
{
	zfree(in6ms_zone, in6ms);
}

#ifdef MLD_DEBUG

static const char *in6m_modestrs[] = { "un\n", "in", "ex" };

static const char *
in6m_mode_str(const int mode)
{
	if (mode >= MCAST_UNDEFINED && mode <= MCAST_EXCLUDE)
		return (in6m_modestrs[mode]);
	return ("??");
}

static const char *in6m_statestrs[] = {
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
in6m_state_str(const int state)
{
	if (state >= MLD_NOT_MEMBER && state <= MLD_LEAVING_MEMBER)
		return (in6m_statestrs[state]);
	return ("??");
}

/*
 * Dump an in6_multi structure to the console.
 */
void
in6m_print(const struct in6_multi *inm)
{
	int t;

	IN6M_LOCK_ASSERT_HELD(__DECONST(struct in6_multi *, inm));

	if (mld_debug == 0)
		return;

	printf("%s: --- begin in6m 0x%llx ---\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(inm));
	printf("addr %s ifp 0x%llx(%s) ifma 0x%llx\n",
	    ip6_sprintf(&inm->in6m_addr),
	    (uint64_t)VM_KERNEL_ADDRPERM(inm->in6m_ifp),
	    if_name(inm->in6m_ifp),
	    (uint64_t)VM_KERNEL_ADDRPERM(inm->in6m_ifma));
	printf("timer %u state %s refcount %u scq.len %u\n",
	    inm->in6m_timer,
	    in6m_state_str(inm->in6m_state),
	    inm->in6m_refcount,
	    inm->in6m_scq.ifq_len);
	printf("mli 0x%llx nsrc %lu sctimer %u scrv %u\n",
	    (uint64_t)VM_KERNEL_ADDRPERM(inm->in6m_mli),
	    inm->in6m_nsrc,
	    inm->in6m_sctimer,
	    inm->in6m_scrv);
	for (t = 0; t < 2; t++) {
		printf("t%d: fmode %s asm %u ex %u in %u rec %u\n", t,
		    in6m_mode_str(inm->in6m_st[t].iss_fmode),
		    inm->in6m_st[t].iss_asm,
		    inm->in6m_st[t].iss_ex,
		    inm->in6m_st[t].iss_in,
		    inm->in6m_st[t].iss_rec);
	}
	printf("%s: --- end in6m 0x%llx ---\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(inm));
}

#else 

void
in6m_print(__unused const struct in6_multi *inm)
{

}

#endif
