/*
 * Copyright (c) 2000-2017 Apple Inc. All rights reserved.
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
 * Copyright (c) 2009 Bruce Simpson.
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
 * Copyright (c) 1988 Stephen Deering.
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Stephen Deering of Stanford University.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)igmp.c	8.1 (Berkeley) 7/19/93
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/sysctl.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mcache.h>

#include <dev/random/randomdev.h>

#include <kern/zalloc.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/scope6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/mld6.h>
#include <netinet6/mld6_var.h>

/* Lock group and attribute for mld_mtx */
static lck_attr_t       *mld_mtx_attr;
static lck_grp_t        *mld_mtx_grp;
static lck_grp_attr_t   *mld_mtx_grp_attr;

/*
 * Locking and reference counting:
 *
 * mld_mtx mainly protects mli_head.  In cases where both mld_mtx and
 * in6_multihead_lock must be held, the former must be acquired first in order
 * to maintain lock ordering.  It is not a requirement that mld_mtx be
 * acquired first before in6_multihead_lock, but in case both must be acquired
 * in succession, the correct lock ordering must be followed.
 *
 * Instead of walking the if_multiaddrs list at the interface and returning
 * the ifma_protospec value of a matching entry, we search the global list
 * of in6_multi records and find it that way; this is done with in6_multihead
 * lock held.  Doing so avoids the race condition issues that many other BSDs
 * suffer from (therefore in our implementation, ifma_protospec will never be
 * NULL for as long as the in6_multi is valid.)
 *
 * The above creates a requirement for the in6_multi to stay in in6_multihead
 * list even after the final MLD leave (in MLDv2 mode) until no longer needs
 * be retransmitted (this is not required for MLDv1.)  In order to handle
 * this, the request and reference counts of the in6_multi are bumped up when
 * the state changes to MLD_LEAVING_MEMBER, and later dropped in the timeout
 * handler.  Each in6_multi holds a reference to the underlying mld_ifinfo.
 *
 * Thus, the permitted lock order is:
 *
 *	mld_mtx, in6_multihead_lock, inm6_lock, mli_lock
 *
 * Any may be taken independently, but if any are held at the same time,
 * the above lock order must be followed.
 */
static decl_lck_mtx_data(, mld_mtx);

SLIST_HEAD(mld_in6m_relhead, in6_multi);

static void	mli_initvar(struct mld_ifinfo *, struct ifnet *, int);
static struct mld_ifinfo *mli_alloc(int);
static void	mli_free(struct mld_ifinfo *);
static void	mli_delete(const struct ifnet *, struct mld_in6m_relhead *);
static void	mld_dispatch_packet(struct mbuf *);
static void	mld_final_leave(struct in6_multi *, struct mld_ifinfo *,
		    struct mld_tparams *);
static int	mld_handle_state_change(struct in6_multi *, struct mld_ifinfo *,
		    struct mld_tparams *);
static int	mld_initial_join(struct in6_multi *, struct mld_ifinfo *,
		    struct mld_tparams *, const int);
#ifdef MLD_DEBUG
static const char *	mld_rec_type_to_str(const int);
#endif
static uint32_t	mld_set_version(struct mld_ifinfo *, const int);
static void	mld_flush_relq(struct mld_ifinfo *, struct mld_in6m_relhead *);
static void	mld_dispatch_queue_locked(struct mld_ifinfo *, struct ifqueue *, int);
static int	mld_v1_input_query(struct ifnet *, const struct ip6_hdr *,
		    /*const*/ struct mld_hdr *);
static int	mld_v1_input_report(struct ifnet *, struct mbuf *,
		    const struct ip6_hdr *, /*const*/ struct mld_hdr *);
static void	mld_v1_process_group_timer(struct in6_multi *, const int);
static void	mld_v1_process_querier_timers(struct mld_ifinfo *);
static int	mld_v1_transmit_report(struct in6_multi *, const int);
static uint32_t	mld_v1_update_group(struct in6_multi *, const int);
static void	mld_v2_cancel_link_timers(struct mld_ifinfo *);
static uint32_t	mld_v2_dispatch_general_query(struct mld_ifinfo *);
static struct mbuf *
		mld_v2_encap_report(struct ifnet *, struct mbuf *);
static int	mld_v2_enqueue_filter_change(struct ifqueue *,
		    struct in6_multi *);
static int	mld_v2_enqueue_group_record(struct ifqueue *,
		    struct in6_multi *, const int, const int, const int,
		    const int);
static int	mld_v2_input_query(struct ifnet *, const struct ip6_hdr *,
		    struct mbuf *, const int, const int);
static int	mld_v2_merge_state_changes(struct in6_multi *,
		    struct ifqueue *);
static void	mld_v2_process_group_timers(struct mld_ifinfo *,
		    struct ifqueue *, struct ifqueue *,
		    struct in6_multi *, const int);
static int	mld_v2_process_group_query(struct in6_multi *,
		    int, struct mbuf *, const int);
static int	sysctl_mld_gsr SYSCTL_HANDLER_ARGS;
static int	sysctl_mld_ifinfo SYSCTL_HANDLER_ARGS;
static int	sysctl_mld_v2enable SYSCTL_HANDLER_ARGS;

static int mld_timeout_run;		/* MLD timer is scheduled to run */
static void mld_timeout(void *);
static void mld_sched_timeout(void);

/*
 * Normative references: RFC 2710, RFC 3590, RFC 3810.
 */
static struct timeval mld_gsrdelay = {10, 0};
static LIST_HEAD(, mld_ifinfo) mli_head;

static int querier_present_timers_running6;
static int interface_timers_running6;
static int state_change_timers_running6;
static int current_state_timers_running6;

static unsigned int mld_mli_list_genid;
/*
 * Subsystem lock macros.
 */
#define	MLD_LOCK()			\
	lck_mtx_lock(&mld_mtx)
#define	MLD_LOCK_ASSERT_HELD()		\
	LCK_MTX_ASSERT(&mld_mtx, LCK_MTX_ASSERT_OWNED)
#define	MLD_LOCK_ASSERT_NOTHELD()	\
	LCK_MTX_ASSERT(&mld_mtx, LCK_MTX_ASSERT_NOTOWNED)
#define	MLD_UNLOCK()			\
	lck_mtx_unlock(&mld_mtx)

#define	MLD_ADD_DETACHED_IN6M(_head, _in6m) {				\
	SLIST_INSERT_HEAD(_head, _in6m, in6m_dtle);			\
}

#define	MLD_REMOVE_DETACHED_IN6M(_head) {				\
	struct in6_multi *_in6m, *_inm_tmp;				\
	SLIST_FOREACH_SAFE(_in6m, _head, in6m_dtle, _inm_tmp) {		\
		SLIST_REMOVE(_head, _in6m, in6_multi, in6m_dtle);	\
		IN6M_REMREF(_in6m);					\
	}								\
	VERIFY(SLIST_EMPTY(_head));					\
}

#define	MLI_ZONE_MAX		64		/* maximum elements in zone */
#define	MLI_ZONE_NAME		"mld_ifinfo"	/* zone name */

static unsigned int mli_size;			/* size of zone element */
static struct zone *mli_zone;			/* zone for mld_ifinfo */

SYSCTL_DECL(_net_inet6);	/* Note: Not in any common header. */

SYSCTL_NODE(_net_inet6, OID_AUTO, mld, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "IPv6 Multicast Listener Discovery");
SYSCTL_PROC(_net_inet6_mld, OID_AUTO, gsrdelay,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &mld_gsrdelay.tv_sec, 0, sysctl_mld_gsr, "I",
    "Rate limit for MLDv2 Group-and-Source queries in seconds");

SYSCTL_NODE(_net_inet6_mld, OID_AUTO, ifinfo, CTLFLAG_RD | CTLFLAG_LOCKED,
   sysctl_mld_ifinfo, "Per-interface MLDv2 state");

static int	mld_v1enable = 1;
SYSCTL_INT(_net_inet6_mld, OID_AUTO, v1enable, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mld_v1enable, 0, "Enable fallback to MLDv1");

static int	mld_v2enable = 1;
SYSCTL_PROC(_net_inet6_mld, OID_AUTO, v2enable,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &mld_v2enable, 0, sysctl_mld_v2enable, "I",
    "Enable MLDv2 (debug purposes only)");

static int	mld_use_allow = 1;
SYSCTL_INT(_net_inet6_mld, OID_AUTO, use_allow, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mld_use_allow, 0, "Use ALLOW/BLOCK for RFC 4604 SSM joins/leaves");

#ifdef MLD_DEBUG
int mld_debug = 0;
SYSCTL_INT(_net_inet6_mld, OID_AUTO,
	debug, CTLFLAG_RW | CTLFLAG_LOCKED,	&mld_debug, 0, "");
#endif
/*
 * Packed Router Alert option structure declaration.
 */
struct mld_raopt {
	struct ip6_hbh		hbh;
	struct ip6_opt		pad;
	struct ip6_opt_router	ra;
} __packed;

/*
 * Router Alert hop-by-hop option header.
 */
static struct mld_raopt mld_ra = {
	.hbh = { 0, 0 },
	.pad = { .ip6o_type = IP6OPT_PADN, 0 },
	.ra = {
	    .ip6or_type = (u_int8_t)IP6OPT_ROUTER_ALERT,
	    .ip6or_len = (u_int8_t)(IP6OPT_RTALERT_LEN - 2),
	    .ip6or_value =  {((IP6OPT_RTALERT_MLD >> 8) & 0xFF),
	        (IP6OPT_RTALERT_MLD & 0xFF) }
	}
};
static struct ip6_pktopts mld_po;

/* Store MLDv2 record count in the module private scratch space */
#define	vt_nrecs	pkt_mpriv.__mpriv_u.__mpriv32[0].__mpriv32_u.__val16[0]

static __inline void
mld_save_context(struct mbuf *m, struct ifnet *ifp)
{
	m->m_pkthdr.rcvif = ifp;
}

static __inline void
mld_scrub_context(struct mbuf *m)
{
	m->m_pkthdr.rcvif = NULL;
}

/*
 * Restore context from a queued output chain.
 * Return saved ifp.
 */
static __inline struct ifnet *
mld_restore_context(struct mbuf *m)
{
        return (m->m_pkthdr.rcvif);
}

/*
 * Retrieve or set threshold between group-source queries in seconds.
 */
static int
sysctl_mld_gsr SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error;
	int i;

	MLD_LOCK();

	i = mld_gsrdelay.tv_sec;

	error = sysctl_handle_int(oidp, &i, 0, req);
	if (error || !req->newptr)
		goto out_locked;

	if (i < -1 || i >= 60) {
		error = EINVAL;
		goto out_locked;
	}

	mld_gsrdelay.tv_sec = i;

out_locked:
	MLD_UNLOCK();
	return (error);
}
/*
 * Expose struct mld_ifinfo to userland, keyed by ifindex.
 * For use by ifmcstat(8).
 *
 */
static int
sysctl_mld_ifinfo SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp)
	int			*name;
	int			 error;
	u_int			 namelen;
	struct ifnet		*ifp;
	struct mld_ifinfo	*mli;
	struct mld_ifinfo_u	mli_u;

	name = (int *)arg1;
	namelen = arg2;

	if (req->newptr != USER_ADDR_NULL)
		return (EPERM);

	if (namelen != 1)
		return (EINVAL);

	MLD_LOCK();

	if (name[0] <= 0 || name[0] > (u_int)if_index) {
		error = ENOENT;
		goto out_locked;
	}

	error = ENOENT;

	ifnet_head_lock_shared();
	ifp = ifindex2ifnet[name[0]];
	ifnet_head_done();
	if (ifp == NULL)
		goto out_locked;

	bzero(&mli_u, sizeof (mli_u));

	LIST_FOREACH(mli, &mli_head, mli_link) {
		MLI_LOCK(mli);
		if (ifp != mli->mli_ifp) {
			MLI_UNLOCK(mli);
			continue;
		}

		mli_u.mli_ifindex = mli->mli_ifp->if_index;
		mli_u.mli_version = mli->mli_version;
		mli_u.mli_v1_timer = mli->mli_v1_timer;
		mli_u.mli_v2_timer = mli->mli_v2_timer;
		mli_u.mli_flags = mli->mli_flags;
		mli_u.mli_rv = mli->mli_rv;
		mli_u.mli_qi = mli->mli_qi;
		mli_u.mli_qri = mli->mli_qri;
		mli_u.mli_uri = mli->mli_uri;
		MLI_UNLOCK(mli);

		error = SYSCTL_OUT(req, &mli_u, sizeof (mli_u));
		break;
	}

out_locked:
	MLD_UNLOCK();
	return (error);
}

static int
sysctl_mld_v2enable SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error;
	int i;
	struct mld_ifinfo *mli;
	struct mld_tparams mtp = { 0, 0, 0, 0 };

	MLD_LOCK();

	i = mld_v2enable;

	error = sysctl_handle_int(oidp, &i, 0, req);
	if (error || !req->newptr)
		goto out_locked;

	if (i < 0 || i > 1) {
		error = EINVAL;
		goto out_locked;
	}

	mld_v2enable = i;
	/*
	 * If we enabled v2, the state transition will take care of upgrading
	 * the MLD version back to v2. Otherwise, we have to explicitly
	 * downgrade. Note that this functionality is to be used for debugging.
	 */
	if (mld_v2enable == 1)
		goto out_locked;

	LIST_FOREACH(mli, &mli_head, mli_link) {
		MLI_LOCK(mli);
		if (mld_set_version(mli, MLD_VERSION_1) > 0)
			mtp.qpt = 1;
		MLI_UNLOCK(mli);
	}

out_locked:
	MLD_UNLOCK();

	mld_set_timeout(&mtp);

	return (error);
}

/*
 * Dispatch an entire queue of pending packet chains.
 *
 * Must not be called with in6m_lock held.
 * XXX This routine unlocks MLD global lock and also mli locks.
 * Make sure that the calling routine takes reference on the mli
 * before calling this routine.
 * Also if we are traversing mli_head, remember to check for
 * mli list generation count and restart the loop if generation count
 * has changed.
 */
static void
mld_dispatch_queue_locked(struct mld_ifinfo *mli, struct ifqueue *ifq, int limit)
{
	struct mbuf *m;

	MLD_LOCK_ASSERT_HELD();

	if (mli != NULL)
		MLI_LOCK_ASSERT_HELD(mli);

	for (;;) {
		IF_DEQUEUE(ifq, m);
		if (m == NULL)
			break;
		MLD_PRINTF(("%s: dispatch 0x%llx from 0x%llx\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(ifq),
		    (uint64_t)VM_KERNEL_ADDRPERM(m)));

		if (mli != NULL)
			MLI_UNLOCK(mli);
		MLD_UNLOCK();

		mld_dispatch_packet(m);

		MLD_LOCK();
		if (mli != NULL)
			MLI_LOCK(mli);

		if (--limit == 0)
			break;
	}

	if (mli != NULL)
		MLI_LOCK_ASSERT_HELD(mli);
}

/*
 * Filter outgoing MLD report state by group.
 *
 * Reports are ALWAYS suppressed for ALL-HOSTS (ff02::1)
 * and node-local addresses. However, kernel and socket consumers
 * always embed the KAME scope ID in the address provided, so strip it
 * when performing comparison.
 * Note: This is not the same as the *multicast* scope.
 *
 * Return zero if the given group is one for which MLD reports
 * should be suppressed, or non-zero if reports should be issued.
 */
static __inline__ int
mld_is_addr_reported(const struct in6_addr *addr)
{

	VERIFY(IN6_IS_ADDR_MULTICAST(addr));

	if (IPV6_ADDR_MC_SCOPE(addr) == IPV6_ADDR_SCOPE_NODELOCAL)
		return (0);

	if (IPV6_ADDR_MC_SCOPE(addr) == IPV6_ADDR_SCOPE_LINKLOCAL) {
		struct in6_addr tmp = *addr;
		in6_clearscope(&tmp);
		if (IN6_ARE_ADDR_EQUAL(&tmp, &in6addr_linklocal_allnodes))
			return (0);
	}

	return (1);
}

/*
 * Attach MLD when PF_INET6 is attached to an interface.
 */
struct mld_ifinfo *
mld_domifattach(struct ifnet *ifp, int how)
{
	struct mld_ifinfo *mli;

	MLD_PRINTF(("%s: called for ifp 0x%llx(%s)\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));

	mli = mli_alloc(how);
	if (mli == NULL)
		return (NULL);

	MLD_LOCK();

	MLI_LOCK(mli);
	mli_initvar(mli, ifp, 0);
	mli->mli_debug |= IFD_ATTACHED;
	MLI_ADDREF_LOCKED(mli); /* hold a reference for mli_head */
	MLI_ADDREF_LOCKED(mli); /* hold a reference for caller */
	MLI_UNLOCK(mli);
	ifnet_lock_shared(ifp);
	mld6_initsilent(ifp, mli);
	ifnet_lock_done(ifp);

	LIST_INSERT_HEAD(&mli_head, mli, mli_link);
	mld_mli_list_genid++;

	MLD_UNLOCK();

	MLD_PRINTF(("%s: allocate mld_ifinfo for ifp 0x%llx(%s)\n",
	    __func__, (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));

	return (mli);
}

/*
 * Attach MLD when PF_INET6 is reattached to an interface.  Caller is
 * expected to have an outstanding reference to the mli.
 */
void
mld_domifreattach(struct mld_ifinfo *mli)
{
	struct ifnet *ifp;

	MLD_LOCK();

	MLI_LOCK(mli);
	VERIFY(!(mli->mli_debug & IFD_ATTACHED));
	ifp = mli->mli_ifp;
	VERIFY(ifp != NULL);
	mli_initvar(mli, ifp, 1);
	mli->mli_debug |= IFD_ATTACHED;
	MLI_ADDREF_LOCKED(mli); /* hold a reference for mli_head */
	MLI_UNLOCK(mli);
	ifnet_lock_shared(ifp);
	mld6_initsilent(ifp, mli);
	ifnet_lock_done(ifp);

	LIST_INSERT_HEAD(&mli_head, mli, mli_link);
	mld_mli_list_genid++;

	MLD_UNLOCK();

	MLD_PRINTF(("%s: reattached mld_ifinfo for ifp 0x%llx(%s)\n",
	    __func__, (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
}

/*
 * Hook for domifdetach.
 */
void
mld_domifdetach(struct ifnet *ifp)
{
	SLIST_HEAD(, in6_multi)	in6m_dthead;

	SLIST_INIT(&in6m_dthead);

	MLD_PRINTF(("%s: called for ifp 0x%llx(%s)\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));

	MLD_LOCK();
	mli_delete(ifp, (struct mld_in6m_relhead *)&in6m_dthead);
	MLD_UNLOCK();

	/* Now that we're dropped all locks, release detached records */
	MLD_REMOVE_DETACHED_IN6M(&in6m_dthead);
}

/*
 * Called at interface detach time.  Note that we only flush all deferred
 * responses and record releases; all remaining inm records and their source
 * entries related to this interface are left intact, in order to handle
 * the reattach case.
 */
static void
mli_delete(const struct ifnet *ifp, struct mld_in6m_relhead *in6m_dthead)
{
	struct mld_ifinfo *mli, *tmli;

	MLD_LOCK_ASSERT_HELD();

	LIST_FOREACH_SAFE(mli, &mli_head, mli_link, tmli) {
		MLI_LOCK(mli);
		if (mli->mli_ifp == ifp) {
			/*
			 * Free deferred General Query responses.
			 */
			IF_DRAIN(&mli->mli_gq);
			IF_DRAIN(&mli->mli_v1q);
			mld_flush_relq(mli, in6m_dthead);
			VERIFY(SLIST_EMPTY(&mli->mli_relinmhead));
			mli->mli_debug &= ~IFD_ATTACHED;
			MLI_UNLOCK(mli);

			LIST_REMOVE(mli, mli_link);
			MLI_REMREF(mli); /* release mli_head reference */
			mld_mli_list_genid++;
			return;
		}
		MLI_UNLOCK(mli);
	}
	panic("%s: mld_ifinfo not found for ifp %p(%s)\n", __func__,
	    ifp, ifp->if_xname);
}

__private_extern__ void
mld6_initsilent(struct ifnet *ifp, struct mld_ifinfo *mli)
{
	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_OWNED);

	MLI_LOCK_ASSERT_NOTHELD(mli);
	MLI_LOCK(mli);
	if (!(ifp->if_flags & IFF_MULTICAST) &&
	    (ifp->if_eflags & (IFEF_IPV6_ND6ALT|IFEF_LOCALNET_PRIVATE)))
		mli->mli_flags |= MLIF_SILENT;
	else
		mli->mli_flags &= ~MLIF_SILENT;
	MLI_UNLOCK(mli);
}

static void
mli_initvar(struct mld_ifinfo *mli, struct ifnet *ifp, int reattach)
{
	MLI_LOCK_ASSERT_HELD(mli);

	mli->mli_ifp = ifp;
	if (mld_v2enable)
		mli->mli_version = MLD_VERSION_2;
	else
		mli->mli_version = MLD_VERSION_1;
	mli->mli_flags = 0;
	mli->mli_rv = MLD_RV_INIT;
	mli->mli_qi = MLD_QI_INIT;
	mli->mli_qri = MLD_QRI_INIT;
	mli->mli_uri = MLD_URI_INIT;

	if (mld_use_allow)
		mli->mli_flags |= MLIF_USEALLOW;
	if (!reattach)
		SLIST_INIT(&mli->mli_relinmhead);

	/*
	 * Responses to general queries are subject to bounds.
	 */
	mli->mli_gq.ifq_maxlen = MLD_MAX_RESPONSE_PACKETS;
	mli->mli_v1q.ifq_maxlen = MLD_MAX_RESPONSE_PACKETS;
}

static struct mld_ifinfo *
mli_alloc(int how)
{
	struct mld_ifinfo *mli;

	mli = (how == M_WAITOK) ? zalloc(mli_zone) : zalloc_noblock(mli_zone);
	if (mli != NULL) {
		bzero(mli, mli_size);
		lck_mtx_init(&mli->mli_lock, mld_mtx_grp, mld_mtx_attr);
		mli->mli_debug |= IFD_ALLOC;
	}
	return (mli);
}

static void
mli_free(struct mld_ifinfo *mli)
{
	MLI_LOCK(mli);
	if (mli->mli_debug & IFD_ATTACHED) {
		panic("%s: attached mli=%p is being freed", __func__, mli);
		/* NOTREACHED */
	} else if (mli->mli_ifp != NULL) {
		panic("%s: ifp not NULL for mli=%p", __func__, mli);
		/* NOTREACHED */
	} else if (!(mli->mli_debug & IFD_ALLOC)) {
		panic("%s: mli %p cannot be freed", __func__, mli);
		/* NOTREACHED */
	} else if (mli->mli_refcnt != 0) {
		panic("%s: non-zero refcnt mli=%p", __func__, mli);
		/* NOTREACHED */
	}
	mli->mli_debug &= ~IFD_ALLOC;
	MLI_UNLOCK(mli);

	lck_mtx_destroy(&mli->mli_lock, mld_mtx_grp);
	zfree(mli_zone, mli);
}

void
mli_addref(struct mld_ifinfo *mli, int locked)
{
	if (!locked)
		MLI_LOCK_SPIN(mli);
	else
		MLI_LOCK_ASSERT_HELD(mli);

	if (++mli->mli_refcnt == 0) {
		panic("%s: mli=%p wraparound refcnt", __func__, mli);
		/* NOTREACHED */
	}
	if (!locked)
		MLI_UNLOCK(mli);
}

void
mli_remref(struct mld_ifinfo *mli)
{
	SLIST_HEAD(, in6_multi)	in6m_dthead;
	struct ifnet *ifp;

	MLI_LOCK_SPIN(mli);

	if (mli->mli_refcnt == 0) {
		panic("%s: mli=%p negative refcnt", __func__, mli);
		/* NOTREACHED */
	}

	--mli->mli_refcnt;
	if (mli->mli_refcnt > 0) {
		MLI_UNLOCK(mli);
		return;
	}

	ifp = mli->mli_ifp;
	mli->mli_ifp = NULL;
	IF_DRAIN(&mli->mli_gq);
	IF_DRAIN(&mli->mli_v1q);
	SLIST_INIT(&in6m_dthead);
	mld_flush_relq(mli, (struct mld_in6m_relhead *)&in6m_dthead);
	VERIFY(SLIST_EMPTY(&mli->mli_relinmhead));
	MLI_UNLOCK(mli);

	/* Now that we're dropped all locks, release detached records */
	MLD_REMOVE_DETACHED_IN6M(&in6m_dthead);

	MLD_PRINTF(("%s: freeing mld_ifinfo for ifp 0x%llx(%s)\n",
	    __func__, (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));

	mli_free(mli);
}

/*
 * Process a received MLDv1 general or address-specific query.
 * Assumes that the query header has been pulled up to sizeof(mld_hdr).
 *
 * NOTE: Can't be fully const correct as we temporarily embed scope ID in
 * mld_addr. This is OK as we own the mbuf chain.
 */
static int
mld_v1_input_query(struct ifnet *ifp, const struct ip6_hdr *ip6,
    /*const*/ struct mld_hdr *mld)
{
	struct mld_ifinfo	*mli;
	struct in6_multi	*inm;
	int			 err = 0, is_general_query;
	uint16_t		 timer;
	struct mld_tparams	 mtp = { 0, 0, 0, 0 };

	MLD_LOCK_ASSERT_NOTHELD();

	is_general_query = 0;

	if (!mld_v1enable) {
		MLD_PRINTF(("%s: ignore v1 query %s on ifp 0x%llx(%s)\n",
		    __func__, ip6_sprintf(&mld->mld_addr),
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		goto done;
	}

	/*
	 * RFC3810 Section 6.2: MLD queries must originate from
	 * a router's link-local address.
	 */
	if (!IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src)) {
		MLD_PRINTF(("%s: ignore v1 query src %s on ifp 0x%llx(%s)\n",
		    __func__, ip6_sprintf(&ip6->ip6_src),
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		goto done;
	}

	/*
	 * Do address field validation upfront before we accept
	 * the query.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&mld->mld_addr)) {
		/*
		 * MLDv1 General Query.
		 * If this was not sent to the all-nodes group, ignore it.
		 */
		struct in6_addr		 dst;

		dst = ip6->ip6_dst;
		in6_clearscope(&dst);
		if (!IN6_ARE_ADDR_EQUAL(&dst, &in6addr_linklocal_allnodes)) {
			err = EINVAL;
			goto done;
		}
		is_general_query = 1;
	} else {
		/*
		 * Embed scope ID of receiving interface in MLD query for
		 * lookup whilst we don't hold other locks.
		 */
		in6_setscope(&mld->mld_addr, ifp, NULL);
	}

	/*
	 * Switch to MLDv1 host compatibility mode.
	 */
	mli = MLD_IFINFO(ifp);
	VERIFY(mli != NULL);

	MLI_LOCK(mli);
	mtp.qpt = mld_set_version(mli, MLD_VERSION_1);
	MLI_UNLOCK(mli);

	timer = ntohs(mld->mld_maxdelay) / MLD_TIMER_SCALE;
	if (timer == 0)
		timer = 1;

	if (is_general_query) {
		struct in6_multistep step;

		MLD_PRINTF(("%s: process v1 general query on ifp 0x%llx(%s)\n",
		    __func__, (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		/*
		 * For each reporting group joined on this
		 * interface, kick the report timer.
		 */
		in6_multihead_lock_shared();
		IN6_FIRST_MULTI(step, inm);
		while (inm != NULL) {
			IN6M_LOCK(inm);
			if (inm->in6m_ifp == ifp)
				mtp.cst += mld_v1_update_group(inm, timer);
			IN6M_UNLOCK(inm);
			IN6_NEXT_MULTI(step, inm);
		}
		in6_multihead_lock_done();
	} else {
		/*
		 * MLDv1 Group-Specific Query.
		 * If this is a group-specific MLDv1 query, we need only
		 * look up the single group to process it.
		 */
		in6_multihead_lock_shared();
		IN6_LOOKUP_MULTI(&mld->mld_addr, ifp, inm);
		in6_multihead_lock_done();

		if (inm != NULL) {
			IN6M_LOCK(inm);
			MLD_PRINTF(("%s: process v1 query %s on "
			    "ifp 0x%llx(%s)\n", __func__,
			    ip6_sprintf(&mld->mld_addr),
			    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
			mtp.cst = mld_v1_update_group(inm, timer);
			IN6M_UNLOCK(inm);
			IN6M_REMREF(inm); /* from IN6_LOOKUP_MULTI */
		}
		/* XXX Clear embedded scope ID as userland won't expect it. */
		in6_clearscope(&mld->mld_addr);
	}
done:
	mld_set_timeout(&mtp);

	return (err);
}

/*
 * Update the report timer on a group in response to an MLDv1 query.
 *
 * If we are becoming the reporting member for this group, start the timer.
 * If we already are the reporting member for this group, and timer is
 * below the threshold, reset it.
 *
 * We may be updating the group for the first time since we switched
 * to MLDv2. If we are, then we must clear any recorded source lists,
 * and transition to REPORTING state; the group timer is overloaded
 * for group and group-source query responses. 
 *
 * Unlike MLDv2, the delay per group should be jittered
 * to avoid bursts of MLDv1 reports.
 */
static uint32_t
mld_v1_update_group(struct in6_multi *inm, const int timer)
{
	IN6M_LOCK_ASSERT_HELD(inm);

	MLD_PRINTF(("%s: %s/%s timer=%d\n", __func__,
	    ip6_sprintf(&inm->in6m_addr),
	    if_name(inm->in6m_ifp), timer));

	switch (inm->in6m_state) {
	case MLD_NOT_MEMBER:
	case MLD_SILENT_MEMBER:
		break;
	case MLD_REPORTING_MEMBER:
		if (inm->in6m_timer != 0 &&
		    inm->in6m_timer <= timer) {
			MLD_PRINTF(("%s: REPORTING and timer running, "
			    "skipping.\n", __func__));
			break;
		}
		/* FALLTHROUGH */
	case MLD_SG_QUERY_PENDING_MEMBER:
	case MLD_G_QUERY_PENDING_MEMBER:
	case MLD_IDLE_MEMBER:
	case MLD_LAZY_MEMBER:
	case MLD_AWAKENING_MEMBER:
		MLD_PRINTF(("%s: ->REPORTING\n", __func__));
		inm->in6m_state = MLD_REPORTING_MEMBER;
		inm->in6m_timer = MLD_RANDOM_DELAY(timer);
		break;
	case MLD_SLEEPING_MEMBER:
		MLD_PRINTF(("%s: ->AWAKENING\n", __func__));
		inm->in6m_state = MLD_AWAKENING_MEMBER;
		break;
	case MLD_LEAVING_MEMBER:
		break;
	}

	return (inm->in6m_timer);
}

/*
 * Process a received MLDv2 general, group-specific or
 * group-and-source-specific query.
 *
 * Assumes that the query header has been pulled up to sizeof(mldv2_query).
 *
 * Return 0 if successful, otherwise an appropriate error code is returned.
 */
static int
mld_v2_input_query(struct ifnet *ifp, const struct ip6_hdr *ip6,
    struct mbuf *m, const int off, const int icmp6len)
{
	struct mld_ifinfo	*mli;
	struct mldv2_query	*mld;
	struct in6_multi	*inm;
	uint32_t		 maxdelay, nsrc, qqi;
	int			 err = 0, is_general_query;
	uint16_t		 timer;
	uint8_t			 qrv;
	struct mld_tparams	 mtp = { 0, 0, 0, 0 };

	MLD_LOCK_ASSERT_NOTHELD();

	is_general_query = 0;

	if (!mld_v2enable) {
		MLD_PRINTF(("%s: ignore v2 query %s on ifp 0x%llx(%s)\n",
		    __func__, ip6_sprintf(&ip6->ip6_src),
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		goto done;
	}

	/*
	 * RFC3810 Section 6.2: MLD queries must originate from
	 * a router's link-local address.
	 */
	if (!IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_src)) {
		MLD_PRINTF(("%s: ignore v1 query src %s on ifp 0x%llx(%s)\n",
		    __func__, ip6_sprintf(&ip6->ip6_src),
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		goto done;
	}

	MLD_PRINTF(("%s: input v2 query on ifp 0x%llx(%s)\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));

	mld = (struct mldv2_query *)(mtod(m, uint8_t *) + off);

	maxdelay = ntohs(mld->mld_maxdelay);	/* in 1/10ths of a second */
	if (maxdelay >= 32768) {
		maxdelay = (MLD_MRC_MANT(maxdelay) | 0x1000) <<
			   (MLD_MRC_EXP(maxdelay) + 3);
	}
	timer = maxdelay / MLD_TIMER_SCALE;
	if (timer == 0)
		timer = 1;

	qrv = MLD_QRV(mld->mld_misc);
	if (qrv < 2) {
		MLD_PRINTF(("%s: clamping qrv %d to %d\n", __func__,
		    qrv, MLD_RV_INIT));
		qrv = MLD_RV_INIT;
	}

	qqi = mld->mld_qqi;
	if (qqi >= 128) {
		qqi = MLD_QQIC_MANT(mld->mld_qqi) <<
		     (MLD_QQIC_EXP(mld->mld_qqi) + 3);
	}

	nsrc = ntohs(mld->mld_numsrc);
	if (nsrc > MLD_MAX_GS_SOURCES) {
		err = EMSGSIZE;
		goto done;
	}
	if (icmp6len < sizeof(struct mldv2_query) +
	    (nsrc * sizeof(struct in6_addr))) {
		err = EMSGSIZE;
		goto done;
	}

	/*
	 * Do further input validation upfront to avoid resetting timers
	 * should we need to discard this query.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&mld->mld_addr)) {
		/*
		 * A general query with a source list has undefined
		 * behaviour; discard it.
		 */
		if (nsrc > 0) {
			err = EINVAL;
			goto done;
		}
		is_general_query = 1;
	} else {
		/*
		 * Embed scope ID of receiving interface in MLD query for
		 * lookup whilst we don't hold other locks (due to KAME
		 * locking lameness). We own this mbuf chain just now.
		 */
		in6_setscope(&mld->mld_addr, ifp, NULL);
	}

	mli = MLD_IFINFO(ifp);
	VERIFY(mli != NULL);

	MLI_LOCK(mli);
	/*
	 * Discard the v2 query if we're in Compatibility Mode.
	 * The RFC is pretty clear that hosts need to stay in MLDv1 mode
	 * until the Old Version Querier Present timer expires.
	 */
	if (mli->mli_version != MLD_VERSION_2) {
		MLI_UNLOCK(mli);
		goto done;
	}

	mtp.qpt = mld_set_version(mli, MLD_VERSION_2);
	mli->mli_rv = qrv;
	mli->mli_qi = qqi;
	mli->mli_qri = MAX(timer, MLD_QRI_MIN);

	MLD_PRINTF(("%s: qrv %d qi %d qri %d\n", __func__, mli->mli_rv,
	    mli->mli_qi, mli->mli_qri));

	if (is_general_query) {
		/*
		 * MLDv2 General Query.
		 *
		 * Schedule a current-state report on this ifp for
		 * all groups, possibly containing source lists.
		 *
		 * If there is a pending General Query response
		 * scheduled earlier than the selected delay, do
		 * not schedule any other reports.
		 * Otherwise, reset the interface timer.
		 */
		MLD_PRINTF(("%s: process v2 general query on ifp 0x%llx(%s)\n",
		    __func__, (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		if (mli->mli_v2_timer == 0 || mli->mli_v2_timer >= timer) {
			mtp.it = mli->mli_v2_timer = MLD_RANDOM_DELAY(timer);
		}
		MLI_UNLOCK(mli);
	} else {
		MLI_UNLOCK(mli);
		/*
		 * MLDv2 Group-specific or Group-and-source-specific Query.
		 *
		 * Group-source-specific queries are throttled on
		 * a per-group basis to defeat denial-of-service attempts.
		 * Queries for groups we are not a member of on this
		 * link are simply ignored.
		 */
		in6_multihead_lock_shared();
		IN6_LOOKUP_MULTI(&mld->mld_addr, ifp, inm);
		in6_multihead_lock_done();
		if (inm == NULL)
			goto done;

		IN6M_LOCK(inm);
		if (nsrc > 0) {
			if (!ratecheck(&inm->in6m_lastgsrtv,
			    &mld_gsrdelay)) {
				MLD_PRINTF(("%s: GS query throttled.\n",
				    __func__));
				IN6M_UNLOCK(inm);
				IN6M_REMREF(inm); /* from IN6_LOOKUP_MULTI */
				goto done;
			}
		}
		MLD_PRINTF(("%s: process v2 group query on ifp 0x%llx(%s)\n",
		    __func__, (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		/*
		 * If there is a pending General Query response
		 * scheduled sooner than the selected delay, no
		 * further report need be scheduled.
		 * Otherwise, prepare to respond to the
		 * group-specific or group-and-source query.
		 */
		MLI_LOCK(mli);
		mtp.it = mli->mli_v2_timer;
		MLI_UNLOCK(mli);
		if (mtp.it == 0 || mtp.it >= timer) {
			(void) mld_v2_process_group_query(inm, timer, m, off);
			mtp.cst = inm->in6m_timer;
		}
		IN6M_UNLOCK(inm);
		IN6M_REMREF(inm); /* from IN6_LOOKUP_MULTI */
		/* XXX Clear embedded scope ID as userland won't expect it. */
		in6_clearscope(&mld->mld_addr);
	}
done:
	if (mtp.it > 0) {
		MLD_PRINTF(("%s: v2 general query response scheduled in "
		    "T+%d seconds on ifp 0x%llx(%s)\n", __func__, mtp.it,
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
	}
	mld_set_timeout(&mtp);

	return (err);
}

/*
 * Process a recieved MLDv2 group-specific or group-and-source-specific
 * query.
 * Return <0 if any error occured. Currently this is ignored.
 */
static int
mld_v2_process_group_query(struct in6_multi *inm, int timer, struct mbuf *m0,
    const int off)
{
	struct mldv2_query	*mld;
	int			 retval;
	uint16_t		 nsrc;

	IN6M_LOCK_ASSERT_HELD(inm);

	retval = 0;
	mld = (struct mldv2_query *)(mtod(m0, uint8_t *) + off);

	switch (inm->in6m_state) {
	case MLD_NOT_MEMBER:
	case MLD_SILENT_MEMBER:
	case MLD_SLEEPING_MEMBER:
	case MLD_LAZY_MEMBER:
	case MLD_AWAKENING_MEMBER:
	case MLD_IDLE_MEMBER:
	case MLD_LEAVING_MEMBER:
		return (retval);
	case MLD_REPORTING_MEMBER:
	case MLD_G_QUERY_PENDING_MEMBER:
	case MLD_SG_QUERY_PENDING_MEMBER:
		break;
	}

	nsrc = ntohs(mld->mld_numsrc);

	/*
	 * Deal with group-specific queries upfront.
	 * If any group query is already pending, purge any recorded
	 * source-list state if it exists, and schedule a query response
	 * for this group-specific query.
	 */
	if (nsrc == 0) {
		if (inm->in6m_state == MLD_G_QUERY_PENDING_MEMBER ||
		    inm->in6m_state == MLD_SG_QUERY_PENDING_MEMBER) {
			in6m_clear_recorded(inm);
			timer = min(inm->in6m_timer, timer);
		}
		inm->in6m_state = MLD_G_QUERY_PENDING_MEMBER;
		inm->in6m_timer = MLD_RANDOM_DELAY(timer);
		return (retval);
	}

	/*
	 * Deal with the case where a group-and-source-specific query has
	 * been received but a group-specific query is already pending.
	 */
	if (inm->in6m_state == MLD_G_QUERY_PENDING_MEMBER) {
		timer = min(inm->in6m_timer, timer);
		inm->in6m_timer = MLD_RANDOM_DELAY(timer);
		return (retval);
	}

	/*
	 * Finally, deal with the case where a group-and-source-specific
	 * query has been received, where a response to a previous g-s-r
	 * query exists, or none exists.
	 * In this case, we need to parse the source-list which the Querier
	 * has provided us with and check if we have any source list filter
	 * entries at T1 for these sources. If we do not, there is no need
	 * schedule a report and the query may be dropped.
	 * If we do, we must record them and schedule a current-state
	 * report for those sources.
	 */
	if (inm->in6m_nsrc > 0) {
		struct mbuf		*m;
		uint8_t			*sp;
		int			 i, nrecorded;
		int			 soff;

		m = m0;
		soff = off + sizeof(struct mldv2_query);
		nrecorded = 0;
		for (i = 0; i < nsrc; i++) {
			sp = mtod(m, uint8_t *) + soff;
			retval = in6m_record_source(inm,
			    (const struct in6_addr *)(void *)sp);
			if (retval < 0)
				break;
			nrecorded += retval;
			soff += sizeof(struct in6_addr);
			if (soff >= m->m_len) {
				soff = soff - m->m_len;
				m = m->m_next;
				if (m == NULL)
					break;
			}
		}
		if (nrecorded > 0) {
			MLD_PRINTF(( "%s: schedule response to SG query\n",
			    __func__));
			inm->in6m_state = MLD_SG_QUERY_PENDING_MEMBER;
			inm->in6m_timer = MLD_RANDOM_DELAY(timer);
		}
	}

	return (retval);
}

/*
 * Process a received MLDv1 host membership report.
 * Assumes mld points to mld_hdr in pulled up mbuf chain.
 *
 * NOTE: Can't be fully const correct as we temporarily embed scope ID in
 * mld_addr. This is OK as we own the mbuf chain.
 */
static int
mld_v1_input_report(struct ifnet *ifp, struct mbuf *m,
    const struct ip6_hdr *ip6, /*const*/ struct mld_hdr *mld)
{
	struct in6_addr		 src, dst;
	struct in6_ifaddr	*ia;
	struct in6_multi	*inm;

	if (!mld_v1enable) {
		MLD_PRINTF(("%s: ignore v1 report %s on ifp 0x%llx(%s)\n",
		    __func__, ip6_sprintf(&mld->mld_addr),
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		return (0);
	}

	if ((ifp->if_flags & IFF_LOOPBACK) ||
	    (m->m_pkthdr.pkt_flags & PKTF_LOOP))
		return (0);

	/*
	 * MLDv1 reports must originate from a host's link-local address,
	 * or the unspecified address (when booting).
	 */
	src = ip6->ip6_src;
	in6_clearscope(&src);
	if (!IN6_IS_SCOPE_LINKLOCAL(&src) && !IN6_IS_ADDR_UNSPECIFIED(&src)) {
		MLD_PRINTF(("%s: ignore v1 query src %s on ifp 0x%llx(%s)\n",
		    __func__, ip6_sprintf(&ip6->ip6_src),
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		return (EINVAL);
	}

	/*
	 * RFC2710 Section 4: MLDv1 reports must pertain to a multicast
	 * group, and must be directed to the group itself.
	 */
	dst = ip6->ip6_dst;
	in6_clearscope(&dst);
	if (!IN6_IS_ADDR_MULTICAST(&mld->mld_addr) ||
	    !IN6_ARE_ADDR_EQUAL(&mld->mld_addr, &dst)) {
		MLD_PRINTF(("%s: ignore v1 query dst %s on ifp 0x%llx(%s)\n",
		    __func__, ip6_sprintf(&ip6->ip6_dst),
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		return (EINVAL);
	}

	/*
	 * Make sure we don't hear our own membership report, as fast
	 * leave requires knowing that we are the only member of a
	 * group. Assume we used the link-local address if available,
	 * otherwise look for ::.
	 *
	 * XXX Note that scope ID comparison is needed for the address
	 * returned by in6ifa_ifpforlinklocal(), but SHOULD NOT be
	 * performed for the on-wire address.
	 */
	ia = in6ifa_ifpforlinklocal(ifp, IN6_IFF_NOTREADY|IN6_IFF_ANYCAST);
	if (ia != NULL) {
		IFA_LOCK(&ia->ia_ifa);
		if ((IN6_ARE_ADDR_EQUAL(&ip6->ip6_src, IA6_IN6(ia)))){
			IFA_UNLOCK(&ia->ia_ifa);
			IFA_REMREF(&ia->ia_ifa);
			return (0);
		}
		IFA_UNLOCK(&ia->ia_ifa);
		IFA_REMREF(&ia->ia_ifa);
	} else if (IN6_IS_ADDR_UNSPECIFIED(&src)) {
		return (0);
	}

	MLD_PRINTF(("%s: process v1 report %s on ifp 0x%llx(%s)\n",
	    __func__, ip6_sprintf(&mld->mld_addr),
	    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));

	/*
	 * Embed scope ID of receiving interface in MLD query for lookup
	 * whilst we don't hold other locks (due to KAME locking lameness).
	 */
	if (!IN6_IS_ADDR_UNSPECIFIED(&mld->mld_addr))
		in6_setscope(&mld->mld_addr, ifp, NULL);

	/*
	 * MLDv1 report suppression.
	 * If we are a member of this group, and our membership should be
	 * reported, and our group timer is pending or about to be reset,
	 * stop our group timer by transitioning to the 'lazy' state.
	 */
	in6_multihead_lock_shared();
	IN6_LOOKUP_MULTI(&mld->mld_addr, ifp, inm);
	in6_multihead_lock_done();

	if (inm != NULL) {
		struct mld_ifinfo *mli;

		IN6M_LOCK(inm);
		mli = inm->in6m_mli;
		VERIFY(mli != NULL);

		MLI_LOCK(mli);
		/*
		 * If we are in MLDv2 host mode, do not allow the
		 * other host's MLDv1 report to suppress our reports.
		 */
		if (mli->mli_version == MLD_VERSION_2) {
			MLI_UNLOCK(mli);
			IN6M_UNLOCK(inm);
			IN6M_REMREF(inm); /* from IN6_LOOKUP_MULTI */
			goto out;
		}
		MLI_UNLOCK(mli);

		inm->in6m_timer = 0;

		switch (inm->in6m_state) {
		case MLD_NOT_MEMBER:
		case MLD_SILENT_MEMBER:
		case MLD_SLEEPING_MEMBER:
			break;
		case MLD_REPORTING_MEMBER:
		case MLD_IDLE_MEMBER:
		case MLD_AWAKENING_MEMBER:
			MLD_PRINTF(("%s: report suppressed for %s on "
			    "ifp 0x%llx(%s)\n", __func__,
			    ip6_sprintf(&mld->mld_addr),
			    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		case MLD_LAZY_MEMBER:
			inm->in6m_state = MLD_LAZY_MEMBER;
			break;
		case MLD_G_QUERY_PENDING_MEMBER:
		case MLD_SG_QUERY_PENDING_MEMBER:
		case MLD_LEAVING_MEMBER:
			break;
		}
		IN6M_UNLOCK(inm);
		IN6M_REMREF(inm); /* from IN6_LOOKUP_MULTI */
	}

out:
	/* XXX Clear embedded scope ID as userland won't expect it. */
	in6_clearscope(&mld->mld_addr);

	return (0);
}

/*
 * MLD input path.
 *
 * Assume query messages which fit in a single ICMPv6 message header
 * have been pulled up.
 * Assume that userland will want to see the message, even if it
 * otherwise fails kernel input validation; do not free it.
 * Pullup may however free the mbuf chain m if it fails.
 *
 * Return IPPROTO_DONE if we freed m. Otherwise, return 0.
 */
int
mld_input(struct mbuf *m, int off, int icmp6len)
{
	struct ifnet	*ifp;
	struct ip6_hdr	*ip6;
	struct mld_hdr	*mld;
	int		 mldlen;

	MLD_PRINTF(("%s: called w/mbuf (0x%llx,%d)\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(m), off));

	ifp = m->m_pkthdr.rcvif;

	ip6 = mtod(m, struct ip6_hdr *);

	/* Pullup to appropriate size. */
	mld = (struct mld_hdr *)(mtod(m, uint8_t *) + off);
	if (mld->mld_type == MLD_LISTENER_QUERY &&
	    icmp6len >= sizeof(struct mldv2_query)) {
		mldlen = sizeof(struct mldv2_query);
	} else {
		mldlen = sizeof(struct mld_hdr);
	}
	IP6_EXTHDR_GET(mld, struct mld_hdr *, m, off, mldlen);
	if (mld == NULL) {
		icmp6stat.icp6s_badlen++;
		return (IPPROTO_DONE);
	}

	/*
	 * Userland needs to see all of this traffic for implementing
	 * the endpoint discovery portion of multicast routing.
	 */
	switch (mld->mld_type) {
	case MLD_LISTENER_QUERY:
		icmp6_ifstat_inc(ifp, ifs6_in_mldquery);
		if (icmp6len == sizeof(struct mld_hdr)) {
			if (mld_v1_input_query(ifp, ip6, mld) != 0)
				return (0);
		} else if (icmp6len >= sizeof(struct mldv2_query)) {
			if (mld_v2_input_query(ifp, ip6, m, off,
			    icmp6len) != 0)
				return (0);
		}
		break;
	case MLD_LISTENER_REPORT:
		icmp6_ifstat_inc(ifp, ifs6_in_mldreport);
		if (mld_v1_input_report(ifp, m, ip6, mld) != 0)
			return (0);
		break;
	case MLDV2_LISTENER_REPORT:
		icmp6_ifstat_inc(ifp, ifs6_in_mldreport);
		break;
	case MLD_LISTENER_DONE:
		icmp6_ifstat_inc(ifp, ifs6_in_mlddone);
		break;
	default:
		break;
	}

	return (0);
}

/*
 * Schedule MLD timer based on various parameters; caller must ensure that
 * lock ordering is maintained as this routine acquires MLD global lock.
 */
void
mld_set_timeout(struct mld_tparams *mtp)
{
	MLD_LOCK_ASSERT_NOTHELD();
	VERIFY(mtp != NULL);

	if (mtp->qpt != 0 || mtp->it != 0 || mtp->cst != 0 || mtp->sct != 0) {
		MLD_LOCK();
		if (mtp->qpt != 0)
			querier_present_timers_running6 = 1;
		if (mtp->it != 0)
			interface_timers_running6 = 1;
		if (mtp->cst != 0)
			current_state_timers_running6 = 1;
		if (mtp->sct != 0)
			state_change_timers_running6 = 1;
		mld_sched_timeout();
		MLD_UNLOCK();
	}
}

/*
 * MLD6 timer handler (per 1 second).
 */
static void
mld_timeout(void *arg)
{
#pragma unused(arg)
	struct ifqueue		 scq;	/* State-change packets */
	struct ifqueue		 qrq;	/* Query response packets */
	struct ifnet		*ifp;
	struct mld_ifinfo	*mli;
	struct in6_multi	*inm;
	int			 uri_sec = 0;
	unsigned int genid = mld_mli_list_genid;

	SLIST_HEAD(, in6_multi)	in6m_dthead;

	SLIST_INIT(&in6m_dthead);

	/*
	 * Update coarse-grained networking timestamp (in sec.); the idea
	 * is to piggy-back on the timeout callout to update the counter
	 * returnable via net_uptime().
	 */
	net_update_uptime();

	MLD_LOCK();

	MLD_PRINTF(("%s: qpt %d, it %d, cst %d, sct %d\n", __func__,
	    querier_present_timers_running6, interface_timers_running6,
	    current_state_timers_running6, state_change_timers_running6));

	/*
	 * MLDv1 querier present timer processing.
	 */
	if (querier_present_timers_running6) {
		querier_present_timers_running6 = 0;
		LIST_FOREACH(mli, &mli_head, mli_link) {
			MLI_LOCK(mli);
			mld_v1_process_querier_timers(mli);
			if (mli->mli_v1_timer > 0)
				querier_present_timers_running6 = 1;
			MLI_UNLOCK(mli);
		}
	}

	/*
	 * MLDv2 General Query response timer processing.
	 */
	if (interface_timers_running6) {
		MLD_PRINTF(("%s: interface timers running\n", __func__));
		interface_timers_running6 = 0;
		mli = LIST_FIRST(&mli_head);

		while (mli != NULL) {
			if (mli->mli_flags & MLIF_PROCESSED) {
				mli = LIST_NEXT(mli, mli_link);
				continue;
			}

			MLI_LOCK(mli);
			if (mli->mli_version != MLD_VERSION_2) {
				MLI_UNLOCK(mli);
				mli = LIST_NEXT(mli, mli_link);
				continue;
			}
			/*
			 * XXX The logic below ends up calling
			 * mld_dispatch_packet which can unlock mli
			 * and the global MLD lock.
			 * Therefore grab a reference on MLI and also
			 * check for generation count to see if we should
			 * iterate the list again.
			 */
			MLI_ADDREF_LOCKED(mli);

			if (mli->mli_v2_timer == 0) {
				/* Do nothing. */
			} else if (--mli->mli_v2_timer == 0) {
				if (mld_v2_dispatch_general_query(mli) > 0)
					interface_timers_running6 = 1;
			} else {
				interface_timers_running6 = 1;
			}
			mli->mli_flags |= MLIF_PROCESSED;
			MLI_UNLOCK(mli);
			MLI_REMREF(mli);

			if (genid != mld_mli_list_genid) {
				MLD_PRINTF(("%s: MLD information list changed "
				    "in the middle of iteration! Restart iteration.\n",
				    __func__));
				mli = LIST_FIRST(&mli_head);
				genid = mld_mli_list_genid;
			} else {
				mli = LIST_NEXT(mli, mli_link);
			}
		}

		LIST_FOREACH(mli, &mli_head, mli_link)
			mli->mli_flags &= ~MLIF_PROCESSED;
	}



	if (!current_state_timers_running6 &&
	    !state_change_timers_running6)
		goto out_locked;

	current_state_timers_running6 = 0;
	state_change_timers_running6 = 0;

	MLD_PRINTF(("%s: state change timers running\n", __func__));

	memset(&qrq, 0, sizeof(struct ifqueue));
	qrq.ifq_maxlen = MLD_MAX_G_GS_PACKETS;

	memset(&scq, 0, sizeof(struct ifqueue));
	scq.ifq_maxlen = MLD_MAX_STATE_CHANGE_PACKETS;

	/*
	 * MLD host report and state-change timer processing.
	 * Note: Processing a v2 group timer may remove a node.
	 */
	mli = LIST_FIRST(&mli_head);

	while (mli != NULL) {
		struct in6_multistep step;

		if (mli->mli_flags & MLIF_PROCESSED) {
			mli = LIST_NEXT(mli, mli_link);
			continue;
		}

		MLI_LOCK(mli);
		ifp = mli->mli_ifp;
		uri_sec = MLD_RANDOM_DELAY(mli->mli_uri);
		MLI_UNLOCK(mli);

		in6_multihead_lock_shared();
		IN6_FIRST_MULTI(step, inm);
		while (inm != NULL) {
			IN6M_LOCK(inm);
			if (inm->in6m_ifp != ifp)
				goto next;

			MLI_LOCK(mli);
			switch (mli->mli_version) {
			case MLD_VERSION_1:
				mld_v1_process_group_timer(inm,
				    mli->mli_version);
				break;
			case MLD_VERSION_2:
				mld_v2_process_group_timers(mli, &qrq,
				    &scq, inm, uri_sec);
				break;
			}
			MLI_UNLOCK(mli);
next:
			IN6M_UNLOCK(inm);
			IN6_NEXT_MULTI(step, inm);
		}
		in6_multihead_lock_done();

		/*
		 * XXX The logic below ends up calling
		 * mld_dispatch_packet which can unlock mli
		 * and the global MLD lock.
		 * Therefore grab a reference on MLI and also
		 * check for generation count to see if we should
		 * iterate the list again.
		 */
		MLI_LOCK(mli);
		MLI_ADDREF_LOCKED(mli);
		if (mli->mli_version == MLD_VERSION_1) {
			mld_dispatch_queue_locked(mli, &mli->mli_v1q, 0);
		} else if (mli->mli_version == MLD_VERSION_2) {
			MLI_UNLOCK(mli);
			mld_dispatch_queue_locked(NULL, &qrq, 0);
			mld_dispatch_queue_locked(NULL, &scq, 0);
			VERIFY(qrq.ifq_len == 0);
			VERIFY(scq.ifq_len == 0);
			MLI_LOCK(mli);
		}
		/*
		 * In case there are still any pending membership reports
		 * which didn't get drained at version change time.
		 */
		IF_DRAIN(&mli->mli_v1q);
		/*
		 * Release all deferred inm records, and drain any locally
		 * enqueued packets; do it even if the current MLD version
		 * for the link is no longer MLDv2, in order to handle the
		 * version change case.
		 */
		mld_flush_relq(mli, (struct mld_in6m_relhead *)&in6m_dthead);
		VERIFY(SLIST_EMPTY(&mli->mli_relinmhead));
		mli->mli_flags |= MLIF_PROCESSED;
		MLI_UNLOCK(mli);
		MLI_REMREF(mli);

		IF_DRAIN(&qrq);
		IF_DRAIN(&scq);

		if (genid != mld_mli_list_genid) {
			MLD_PRINTF(("%s: MLD information list changed "
			    "in the middle of iteration! Restart iteration.\n",
			    __func__));
			mli = LIST_FIRST(&mli_head);
			genid = mld_mli_list_genid;
		} else {
			mli = LIST_NEXT(mli, mli_link);
		}
	}

	LIST_FOREACH(mli, &mli_head, mli_link)
		mli->mli_flags &= ~MLIF_PROCESSED;

out_locked:
	/* re-arm the timer if there's work to do */
	mld_timeout_run = 0;
	mld_sched_timeout();
	MLD_UNLOCK();

	/* Now that we're dropped all locks, release detached records */
	MLD_REMOVE_DETACHED_IN6M(&in6m_dthead);
}

static void
mld_sched_timeout(void)
{
	MLD_LOCK_ASSERT_HELD();

	if (!mld_timeout_run &&
	    (querier_present_timers_running6 || current_state_timers_running6 ||
	    interface_timers_running6 || state_change_timers_running6)) {
		mld_timeout_run = 1;
		timeout(mld_timeout, NULL, hz);
	}
}

/*
 * Free the in6_multi reference(s) for this MLD lifecycle.
 *
 * Caller must be holding mli_lock.
 */
static void
mld_flush_relq(struct mld_ifinfo *mli, struct mld_in6m_relhead *in6m_dthead)
{
	struct in6_multi *inm;

again:
	MLI_LOCK_ASSERT_HELD(mli);
	inm = SLIST_FIRST(&mli->mli_relinmhead);
	if (inm != NULL) {
		int lastref;

		SLIST_REMOVE_HEAD(&mli->mli_relinmhead, in6m_nrele);
		MLI_UNLOCK(mli);

		in6_multihead_lock_exclusive();
		IN6M_LOCK(inm);
		VERIFY(inm->in6m_nrelecnt != 0);
		inm->in6m_nrelecnt--;
		lastref = in6_multi_detach(inm);
		VERIFY(!lastref || (!(inm->in6m_debug & IFD_ATTACHED) &&
		    inm->in6m_reqcnt == 0));
		IN6M_UNLOCK(inm);
		in6_multihead_lock_done();
		/* from mli_relinmhead */
		IN6M_REMREF(inm);
		/* from in6_multihead_list */
		if (lastref) {
			/*
			 * Defer releasing our final reference, as we
			 * are holding the MLD lock at this point, and
			 * we could end up with locking issues later on
			 * (while issuing SIOCDELMULTI) when this is the
			 * final reference count.  Let the caller do it
			 * when it is safe.
			 */
			MLD_ADD_DETACHED_IN6M(in6m_dthead, inm);
		}
		MLI_LOCK(mli);
		goto again;
	}
}

/*
 * Update host report group timer.
 * Will update the global pending timer flags.
 */
static void
mld_v1_process_group_timer(struct in6_multi *inm, const int mld_version)
{
#pragma unused(mld_version)
	int report_timer_expired;

	MLD_LOCK_ASSERT_HELD();
	IN6M_LOCK_ASSERT_HELD(inm);
	MLI_LOCK_ASSERT_HELD(inm->in6m_mli);

	if (inm->in6m_timer == 0) {
		report_timer_expired = 0;
	} else if (--inm->in6m_timer == 0) {
		report_timer_expired = 1;
	} else {
		current_state_timers_running6 = 1;
		/* caller will schedule timer */
		return;
	}

	switch (inm->in6m_state) {
	case MLD_NOT_MEMBER:
	case MLD_SILENT_MEMBER:
	case MLD_IDLE_MEMBER:
	case MLD_LAZY_MEMBER:
	case MLD_SLEEPING_MEMBER:
	case MLD_AWAKENING_MEMBER:
		break;
	case MLD_REPORTING_MEMBER:
		if (report_timer_expired) {
			inm->in6m_state = MLD_IDLE_MEMBER;
			(void) mld_v1_transmit_report(inm,
			     MLD_LISTENER_REPORT);
			IN6M_LOCK_ASSERT_HELD(inm);
			MLI_LOCK_ASSERT_HELD(inm->in6m_mli);
		}
		break;
	case MLD_G_QUERY_PENDING_MEMBER:
	case MLD_SG_QUERY_PENDING_MEMBER:
	case MLD_LEAVING_MEMBER:
		break;
	}
}

/*
 * Update a group's timers for MLDv2.
 * Will update the global pending timer flags.
 * Note: Unlocked read from mli.
 */
static void
mld_v2_process_group_timers(struct mld_ifinfo *mli,
    struct ifqueue *qrq, struct ifqueue *scq,
    struct in6_multi *inm, const int uri_sec)
{
	int query_response_timer_expired;
	int state_change_retransmit_timer_expired;

	MLD_LOCK_ASSERT_HELD();
	IN6M_LOCK_ASSERT_HELD(inm);
	MLI_LOCK_ASSERT_HELD(mli);
	VERIFY(mli == inm->in6m_mli);

	query_response_timer_expired = 0;
	state_change_retransmit_timer_expired = 0;

	/*
	 * During a transition from compatibility mode back to MLDv2,
	 * a group record in REPORTING state may still have its group
	 * timer active. This is a no-op in this function; it is easier
	 * to deal with it here than to complicate the timeout path.
	 */
	if (inm->in6m_timer == 0) {
		query_response_timer_expired = 0;
	} else if (--inm->in6m_timer == 0) {
		query_response_timer_expired = 1;
	} else {
		current_state_timers_running6 = 1;
		/* caller will schedule timer */
	}

	if (inm->in6m_sctimer == 0) {
		state_change_retransmit_timer_expired = 0;
	} else if (--inm->in6m_sctimer == 0) {
		state_change_retransmit_timer_expired = 1;
	} else {
		state_change_timers_running6 = 1;
		/* caller will schedule timer */
	}

	/* We are in timer callback, so be quick about it. */
	if (!state_change_retransmit_timer_expired &&
	    !query_response_timer_expired)
		return;

	switch (inm->in6m_state) {
	case MLD_NOT_MEMBER:
	case MLD_SILENT_MEMBER:
	case MLD_SLEEPING_MEMBER:
	case MLD_LAZY_MEMBER:
	case MLD_AWAKENING_MEMBER:
	case MLD_IDLE_MEMBER:
		break;
	case MLD_G_QUERY_PENDING_MEMBER:
	case MLD_SG_QUERY_PENDING_MEMBER:
		/*
		 * Respond to a previously pending Group-Specific
		 * or Group-and-Source-Specific query by enqueueing
		 * the appropriate Current-State report for
		 * immediate transmission.
		 */
		if (query_response_timer_expired) {
			int retval;

			retval = mld_v2_enqueue_group_record(qrq, inm, 0, 1,
			    (inm->in6m_state == MLD_SG_QUERY_PENDING_MEMBER),
			    0);
			MLD_PRINTF(("%s: enqueue record = %d\n",
			    __func__, retval));
			inm->in6m_state = MLD_REPORTING_MEMBER;
			in6m_clear_recorded(inm);
		}
		/* FALLTHROUGH */
	case MLD_REPORTING_MEMBER:
	case MLD_LEAVING_MEMBER:
		if (state_change_retransmit_timer_expired) {
			/*
			 * State-change retransmission timer fired.
			 * If there are any further pending retransmissions,
			 * set the global pending state-change flag, and
			 * reset the timer.
			 */
			if (--inm->in6m_scrv > 0) {
				inm->in6m_sctimer = uri_sec;
				state_change_timers_running6 = 1;
				/* caller will schedule timer */
			}
			/*
			 * Retransmit the previously computed state-change
			 * report. If there are no further pending
			 * retransmissions, the mbuf queue will be consumed.
			 * Update T0 state to T1 as we have now sent
			 * a state-change.
			 */
			(void) mld_v2_merge_state_changes(inm, scq);

			in6m_commit(inm);
			MLD_PRINTF(("%s: T1 -> T0 for %s/%s\n", __func__,
			    ip6_sprintf(&inm->in6m_addr),
			    if_name(inm->in6m_ifp)));

			/*
			 * If we are leaving the group for good, make sure
			 * we release MLD's reference to it.
			 * This release must be deferred using a SLIST,
			 * as we are called from a loop which traverses
			 * the in_ifmultiaddr TAILQ.
			 */
			if (inm->in6m_state == MLD_LEAVING_MEMBER &&
			    inm->in6m_scrv == 0) {
				inm->in6m_state = MLD_NOT_MEMBER;
				/*
				 * A reference has already been held in
				 * mld_final_leave() for this inm, so
				 * no need to hold another one.  We also
				 * bumped up its request count then, so
				 * that it stays in in6_multihead.  Both
				 * of them will be released when it is
				 * dequeued later on.
				 */
				VERIFY(inm->in6m_nrelecnt != 0);
				SLIST_INSERT_HEAD(&mli->mli_relinmhead,
				    inm, in6m_nrele);
			}
		}
		break;
	}
}

/*
 * Switch to a different version on the given interface,
 * as per Section 9.12.
 */
static uint32_t
mld_set_version(struct mld_ifinfo *mli, const int mld_version)
{
	int old_version_timer;

	MLI_LOCK_ASSERT_HELD(mli);

	MLD_PRINTF(("%s: switching to v%d on ifp 0x%llx(%s)\n", __func__,
	    mld_version, (uint64_t)VM_KERNEL_ADDRPERM(mli->mli_ifp),
	    if_name(mli->mli_ifp)));

	if (mld_version == MLD_VERSION_1) {
		/*
		 * Compute the "Older Version Querier Present" timer as per
		 * Section 9.12, in seconds.
		 */
		old_version_timer = (mli->mli_rv * mli->mli_qi) + mli->mli_qri;
		mli->mli_v1_timer = old_version_timer;
	}

	if (mli->mli_v1_timer > 0 && mli->mli_version != MLD_VERSION_1) {
		mli->mli_version = MLD_VERSION_1;
		mld_v2_cancel_link_timers(mli);
	}

	MLI_LOCK_ASSERT_HELD(mli);

	return (mli->mli_v1_timer);
}

/*
 * Cancel pending MLDv2 timers for the given link and all groups
 * joined on it; state-change, general-query, and group-query timers.
 *
 * Only ever called on a transition from v2 to Compatibility mode. Kill
 * the timers stone dead (this may be expensive for large N groups), they
 * will be restarted if Compatibility Mode deems that they must be due to
 * query processing.
 */
static void
mld_v2_cancel_link_timers(struct mld_ifinfo *mli)
{
	struct ifnet		*ifp;
	struct in6_multi	*inm;
	struct in6_multistep	step;

	MLI_LOCK_ASSERT_HELD(mli);

	MLD_PRINTF(("%s: cancel v2 timers on ifp 0x%llx(%s)\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(mli->mli_ifp), if_name(mli->mli_ifp)));

	/*
	 * Stop the v2 General Query Response on this link stone dead.
	 * If timer is woken up due to interface_timers_running6,
	 * the flag will be cleared if there are no pending link timers.
	 */
	mli->mli_v2_timer = 0;

	/*
	 * Now clear the current-state and state-change report timers
	 * for all memberships scoped to this link.
	 */
	ifp = mli->mli_ifp;
	MLI_UNLOCK(mli);

	in6_multihead_lock_shared();
	IN6_FIRST_MULTI(step, inm);
	while (inm != NULL) {
		IN6M_LOCK(inm);
		if (inm->in6m_ifp != ifp)
			goto next;

		switch (inm->in6m_state) {
		case MLD_NOT_MEMBER:
		case MLD_SILENT_MEMBER:
		case MLD_IDLE_MEMBER:
		case MLD_LAZY_MEMBER:
		case MLD_SLEEPING_MEMBER:
		case MLD_AWAKENING_MEMBER:
			/*
			 * These states are either not relevant in v2 mode,
			 * or are unreported. Do nothing.
			 */
			break;
		case MLD_LEAVING_MEMBER:
			/*
			 * If we are leaving the group and switching
			 * version, we need to release the final
			 * reference held for issuing the INCLUDE {}.
			 * During mld_final_leave(), we bumped up both the
			 * request and reference counts.  Since we cannot
			 * call in6_multi_detach() here, defer this task to
			 * the timer routine.
			 */
			VERIFY(inm->in6m_nrelecnt != 0);
			MLI_LOCK(mli);
			SLIST_INSERT_HEAD(&mli->mli_relinmhead, inm,
			    in6m_nrele);
			MLI_UNLOCK(mli);
			/* FALLTHROUGH */
		case MLD_G_QUERY_PENDING_MEMBER:
		case MLD_SG_QUERY_PENDING_MEMBER:
			in6m_clear_recorded(inm);
			/* FALLTHROUGH */
		case MLD_REPORTING_MEMBER:
			inm->in6m_state = MLD_REPORTING_MEMBER;
			break;
		}
		/*
		 * Always clear state-change and group report timers.
		 * Free any pending MLDv2 state-change records.
		 */
		inm->in6m_sctimer = 0;
		inm->in6m_timer = 0;
		IF_DRAIN(&inm->in6m_scq);
next:
		IN6M_UNLOCK(inm);
		IN6_NEXT_MULTI(step, inm);
	}
	in6_multihead_lock_done();

	MLI_LOCK(mli);
}

/*
 * Update the Older Version Querier Present timers for a link.
 * See Section 9.12 of RFC 3810.
 */
static void
mld_v1_process_querier_timers(struct mld_ifinfo *mli)
{
	MLI_LOCK_ASSERT_HELD(mli);

	if (mld_v2enable && mli->mli_version != MLD_VERSION_2 &&
	    --mli->mli_v1_timer == 0) {
		/*
		 * MLDv1 Querier Present timer expired; revert to MLDv2.
		 */
		MLD_PRINTF(("%s: transition from v%d -> v%d on 0x%llx(%s)\n",
		    __func__, mli->mli_version, MLD_VERSION_2,
		    (uint64_t)VM_KERNEL_ADDRPERM(mli->mli_ifp),
		    if_name(mli->mli_ifp)));
		mli->mli_version = MLD_VERSION_2;
	}
}

/*
 * Transmit an MLDv1 report immediately.
 */
static int
mld_v1_transmit_report(struct in6_multi *in6m, const int type)
{
	struct ifnet		*ifp;
	struct in6_ifaddr	*ia;
	struct ip6_hdr		*ip6;
	struct mbuf		*mh, *md;
	struct mld_hdr		*mld;
	int			error = 0;

	IN6M_LOCK_ASSERT_HELD(in6m);
	MLI_LOCK_ASSERT_HELD(in6m->in6m_mli);

	ifp = in6m->in6m_ifp;
	/* ia may be NULL if link-local address is tentative. */
	ia = in6ifa_ifpforlinklocal(ifp, IN6_IFF_NOTREADY|IN6_IFF_ANYCAST);

	MGETHDR(mh, M_DONTWAIT, MT_HEADER);
	if (mh == NULL) {
		if (ia != NULL)
			IFA_REMREF(&ia->ia_ifa);
		return (ENOMEM);
	}
	MGET(md, M_DONTWAIT, MT_DATA);
	if (md == NULL) {
		m_free(mh);
		if (ia != NULL)
			IFA_REMREF(&ia->ia_ifa);
		return (ENOMEM);
	}
	mh->m_next = md;

	/*
	 * FUTURE: Consider increasing alignment by ETHER_HDR_LEN, so
	 * that ether_output() does not need to allocate another mbuf
	 * for the header in the most common case.
	 */
	MH_ALIGN(mh, sizeof(struct ip6_hdr));
	mh->m_pkthdr.len = sizeof(struct ip6_hdr) + sizeof(struct mld_hdr);
	mh->m_len = sizeof(struct ip6_hdr);

	ip6 = mtod(mh, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	if (ia != NULL)
		IFA_LOCK(&ia->ia_ifa);
	ip6->ip6_src = ia ? ia->ia_addr.sin6_addr : in6addr_any;
	if (ia != NULL) {
		IFA_UNLOCK(&ia->ia_ifa);
		IFA_REMREF(&ia->ia_ifa);
		ia = NULL;
	}
	ip6->ip6_dst = in6m->in6m_addr;

	md->m_len = sizeof(struct mld_hdr);
	mld = mtod(md, struct mld_hdr *);
	mld->mld_type = type;
	mld->mld_code = 0;
	mld->mld_cksum = 0;
	mld->mld_maxdelay = 0;
	mld->mld_reserved = 0;
	mld->mld_addr = in6m->in6m_addr;
	in6_clearscope(&mld->mld_addr);
	mld->mld_cksum = in6_cksum(mh, IPPROTO_ICMPV6,
	    sizeof(struct ip6_hdr), sizeof(struct mld_hdr));

	mld_save_context(mh, ifp);
	mh->m_flags |= M_MLDV1;

	/*
	 * Due to the fact that at this point we are possibly holding
	 * in6_multihead_lock in shared or exclusive mode, we can't call
	 * mld_dispatch_packet() here since that will eventually call
	 * ip6_output(), which will try to lock in6_multihead_lock and cause
	 * a deadlock.
	 * Instead we defer the work to the mld_timeout() thread, thus
	 * avoiding unlocking in_multihead_lock here.
	 */
        if (IF_QFULL(&in6m->in6m_mli->mli_v1q)) {
                MLD_PRINTF(("%s: v1 outbound queue full\n", __func__));
                error = ENOMEM;
                m_freem(mh);
        } else {
                IF_ENQUEUE(&in6m->in6m_mli->mli_v1q, mh);
		VERIFY(error == 0);
	}

	return (error);
}

/*
 * Process a state change from the upper layer for the given IPv6 group.
 *
 * Each socket holds a reference on the in6_multi in its own ip_moptions.
 * The socket layer will have made the necessary updates to.the group
 * state, it is now up to MLD to issue a state change report if there
 * has been any change between T0 (when the last state-change was issued)
 * and T1 (now).
 *
 * We use the MLDv2 state machine at group level. The MLd module
 * however makes the decision as to which MLD protocol version to speak.
 * A state change *from* INCLUDE {} always means an initial join.
 * A state change *to* INCLUDE {} always means a final leave.
 *
 * If delay is non-zero, and the state change is an initial multicast
 * join, the state change report will be delayed by 'delay' ticks
 * in units of seconds if MLDv1 is active on the link; otherwise
 * the initial MLDv2 state change report will be delayed by whichever
 * is sooner, a pending state-change timer or delay itself.
 */
int
mld_change_state(struct in6_multi *inm, struct mld_tparams *mtp,
    const int delay)
{
	struct mld_ifinfo *mli;
	struct ifnet *ifp;
	int error = 0;

	VERIFY(mtp != NULL);
	bzero(mtp, sizeof (*mtp));

	IN6M_LOCK_ASSERT_HELD(inm);
	VERIFY(inm->in6m_mli != NULL);
	MLI_LOCK_ASSERT_NOTHELD(inm->in6m_mli);

	/*
	 * Try to detect if the upper layer just asked us to change state
	 * for an interface which has now gone away.
	 */
	VERIFY(inm->in6m_ifma != NULL);
	ifp = inm->in6m_ifma->ifma_ifp;
	/*
	 * Sanity check that netinet6's notion of ifp is the same as net's.
	 */
	VERIFY(inm->in6m_ifp == ifp);

	mli = MLD_IFINFO(ifp);
	VERIFY(mli != NULL);

	/*
	 * If we detect a state transition to or from MCAST_UNDEFINED
	 * for this group, then we are starting or finishing an MLD
	 * life cycle for this group.
	 */
	if (inm->in6m_st[1].iss_fmode != inm->in6m_st[0].iss_fmode) {
		MLD_PRINTF(("%s: inm transition %d -> %d\n", __func__,
		    inm->in6m_st[0].iss_fmode, inm->in6m_st[1].iss_fmode));
		if (inm->in6m_st[0].iss_fmode == MCAST_UNDEFINED) {
			MLD_PRINTF(("%s: initial join\n", __func__));
			error = mld_initial_join(inm, mli, mtp, delay);
			goto out;
		} else if (inm->in6m_st[1].iss_fmode == MCAST_UNDEFINED) {
			MLD_PRINTF(("%s: final leave\n", __func__));
			mld_final_leave(inm, mli, mtp);
			goto out;
		}
	} else {
		MLD_PRINTF(("%s: filter set change\n", __func__));
	}

	error = mld_handle_state_change(inm, mli, mtp);
out:
	return (error);
}

/*
 * Perform the initial join for an MLD group.
 *
 * When joining a group:
 *  If the group should have its MLD traffic suppressed, do nothing.
 *  MLDv1 starts sending MLDv1 host membership reports.
 *  MLDv2 will schedule an MLDv2 state-change report containing the
 *  initial state of the membership.
 *
 * If the delay argument is non-zero, then we must delay sending the
 * initial state change for delay ticks (in units of seconds).
 */
static int
mld_initial_join(struct in6_multi *inm, struct mld_ifinfo *mli,
    struct mld_tparams *mtp, const int delay)
{
	struct ifnet		*ifp;
	struct ifqueue		*ifq;
	int			 error, retval, syncstates;
	int			 odelay;

	IN6M_LOCK_ASSERT_HELD(inm);
	MLI_LOCK_ASSERT_NOTHELD(mli);
	VERIFY(mtp != NULL);

	MLD_PRINTF(("%s: initial join %s on ifp 0x%llx(%s)\n",
	    __func__, ip6_sprintf(&inm->in6m_addr),
	    (uint64_t)VM_KERNEL_ADDRPERM(inm->in6m_ifp),
	    if_name(inm->in6m_ifp)));

	error = 0;
	syncstates = 1;

	ifp = inm->in6m_ifp;

	MLI_LOCK(mli);
	VERIFY(mli->mli_ifp == ifp);

	/*
	 * Avoid MLD if group is :
	 * 1. Joined on loopback, OR
	 * 2. On a link that is marked MLIF_SILENT
	 * 3. rdar://problem/19227650 Is link local scoped and
	 *    on cellular interface
	 * 4. Is a type that should not be reported (node local
	 *    or all node link local multicast.
	 * All other groups enter the appropriate state machine
	 * for the version in use on this link.
	 */
	if ((ifp->if_flags & IFF_LOOPBACK) ||
	    (mli->mli_flags & MLIF_SILENT) ||
	    (IFNET_IS_CELLULAR(ifp) &&
	     IN6_IS_ADDR_MC_LINKLOCAL(&inm->in6m_addr)) ||
	    !mld_is_addr_reported(&inm->in6m_addr)) {
		MLD_PRINTF(("%s: not kicking state machine for silent group\n",
		    __func__));
		inm->in6m_state = MLD_SILENT_MEMBER;
		inm->in6m_timer = 0;
	} else {
		/*
		 * Deal with overlapping in6_multi lifecycle.
		 * If this group was LEAVING, then make sure
		 * we drop the reference we picked up to keep the
		 * group around for the final INCLUDE {} enqueue.
		 * Since we cannot call in6_multi_detach() here,
		 * defer this task to the timer routine.
		 */
		if (mli->mli_version == MLD_VERSION_2 &&
		    inm->in6m_state == MLD_LEAVING_MEMBER) {
			VERIFY(inm->in6m_nrelecnt != 0);
			SLIST_INSERT_HEAD(&mli->mli_relinmhead, inm,
			    in6m_nrele);
		}

		inm->in6m_state = MLD_REPORTING_MEMBER;

		switch (mli->mli_version) {
		case MLD_VERSION_1:
			/*
			 * If a delay was provided, only use it if
			 * it is greater than the delay normally
			 * used for an MLDv1 state change report,
			 * and delay sending the initial MLDv1 report
			 * by not transitioning to the IDLE state.
			 */
			odelay = MLD_RANDOM_DELAY(MLD_V1_MAX_RI);
			if (delay) {
				inm->in6m_timer = max(delay, odelay);
				mtp->cst = 1;
			} else {
				inm->in6m_state = MLD_IDLE_MEMBER;
				error = mld_v1_transmit_report(inm,
				     MLD_LISTENER_REPORT);

				IN6M_LOCK_ASSERT_HELD(inm);
				MLI_LOCK_ASSERT_HELD(mli);

				if (error == 0) {
					inm->in6m_timer = odelay;
					mtp->cst = 1;
				}
			}
			break;

		case MLD_VERSION_2:
			/*
			 * Defer update of T0 to T1, until the first copy
			 * of the state change has been transmitted.
			 */
			syncstates = 0;

			/*
			 * Immediately enqueue a State-Change Report for
			 * this interface, freeing any previous reports.
			 * Don't kick the timers if there is nothing to do,
			 * or if an error occurred.
			 */
			ifq = &inm->in6m_scq;
			IF_DRAIN(ifq);
			retval = mld_v2_enqueue_group_record(ifq, inm, 1,
			    0, 0, (mli->mli_flags & MLIF_USEALLOW));
			mtp->cst = (ifq->ifq_len > 0);
			MLD_PRINTF(("%s: enqueue record = %d\n",
			    __func__, retval));
			if (retval <= 0) {
				error = retval * -1;
				break;
			}

			/*
			 * Schedule transmission of pending state-change
			 * report up to RV times for this link. The timer
			 * will fire at the next mld_timeout (1 second)),
			 * giving us an opportunity to merge the reports.
			 *
			 * If a delay was provided to this function, only
			 * use this delay if sooner than the existing one.
			 */
			VERIFY(mli->mli_rv > 1);
			inm->in6m_scrv = mli->mli_rv;
			if (delay) {
				if (inm->in6m_sctimer > 1) {
					inm->in6m_sctimer =
					    min(inm->in6m_sctimer, delay);
				} else
					inm->in6m_sctimer = delay;
			} else {
				inm->in6m_sctimer = 1;
			}
			mtp->sct = 1;
			error = 0;
			break;
		}
	}
	MLI_UNLOCK(mli);

	/*
	 * Only update the T0 state if state change is atomic,
	 * i.e. we don't need to wait for a timer to fire before we
	 * can consider the state change to have been communicated.
	 */
	if (syncstates) {
		in6m_commit(inm);
		MLD_PRINTF(("%s: T1 -> T0 for %s/%s\n", __func__,
		    ip6_sprintf(&inm->in6m_addr),
		    if_name(inm->in6m_ifp)));
	}

	return (error);
}

/*
 * Issue an intermediate state change during the life-cycle.
 */
static int
mld_handle_state_change(struct in6_multi *inm, struct mld_ifinfo *mli,
    struct mld_tparams *mtp)
{
	struct ifnet		*ifp;
	int			 retval = 0;

	IN6M_LOCK_ASSERT_HELD(inm);
	MLI_LOCK_ASSERT_NOTHELD(mli);
	VERIFY(mtp != NULL);

	MLD_PRINTF(("%s: state change for %s on ifp 0x%llx(%s)\n",
	    __func__, ip6_sprintf(&inm->in6m_addr),
	    (uint64_t)VM_KERNEL_ADDRPERM(inm->in6m_ifp),
	    if_name(inm->in6m_ifp)));

	ifp = inm->in6m_ifp;

	MLI_LOCK(mli);
	VERIFY(mli->mli_ifp == ifp);

	if ((ifp->if_flags & IFF_LOOPBACK) ||
	    (mli->mli_flags & MLIF_SILENT) ||
	    !mld_is_addr_reported(&inm->in6m_addr) ||
	    (mli->mli_version != MLD_VERSION_2)) {
		MLI_UNLOCK(mli);
		if (!mld_is_addr_reported(&inm->in6m_addr)) {
			MLD_PRINTF(("%s: not kicking state machine for silent "
			    "group\n", __func__));
		}
		MLD_PRINTF(("%s: nothing to do\n", __func__));
		in6m_commit(inm);
		MLD_PRINTF(("%s: T1 -> T0 for %s/%s\n", __func__,
		    ip6_sprintf(&inm->in6m_addr),
		    if_name(inm->in6m_ifp)));
		goto done;
	}

	IF_DRAIN(&inm->in6m_scq);

	retval = mld_v2_enqueue_group_record(&inm->in6m_scq, inm, 1, 0, 0,
	    (mli->mli_flags & MLIF_USEALLOW));
	mtp->cst = (inm->in6m_scq.ifq_len > 0);
	MLD_PRINTF(("%s: enqueue record = %d\n", __func__, retval));
	if (retval <= 0) {
		MLI_UNLOCK(mli);
		retval *= -1;
		goto done;
	} else {
		retval = 0;
	}

	/*
	 * If record(s) were enqueued, start the state-change
	 * report timer for this group.
	 */
	inm->in6m_scrv = mli->mli_rv;
	inm->in6m_sctimer = 1;
	mtp->sct = 1;
	MLI_UNLOCK(mli);

done:
	return (retval);
}

/*
 * Perform the final leave for a multicast address.
 *
 * When leaving a group:
 *  MLDv1 sends a DONE message, if and only if we are the reporter.
 *  MLDv2 enqueues a state-change report containing a transition
 *  to INCLUDE {} for immediate transmission.
 */
static void
mld_final_leave(struct in6_multi *inm, struct mld_ifinfo *mli,
    struct mld_tparams *mtp)
{
	int syncstates = 1;

	IN6M_LOCK_ASSERT_HELD(inm);
	MLI_LOCK_ASSERT_NOTHELD(mli);
	VERIFY(mtp != NULL);

	MLD_PRINTF(("%s: final leave %s on ifp 0x%llx(%s)\n",
	    __func__, ip6_sprintf(&inm->in6m_addr),
	    (uint64_t)VM_KERNEL_ADDRPERM(inm->in6m_ifp),
	    if_name(inm->in6m_ifp)));

	switch (inm->in6m_state) {
	case MLD_NOT_MEMBER:
	case MLD_SILENT_MEMBER:
	case MLD_LEAVING_MEMBER:
		/* Already leaving or left; do nothing. */
		MLD_PRINTF(("%s: not kicking state machine for silent group\n",
		    __func__));
		break;
	case MLD_REPORTING_MEMBER:
	case MLD_IDLE_MEMBER:
	case MLD_G_QUERY_PENDING_MEMBER:
	case MLD_SG_QUERY_PENDING_MEMBER:
		MLI_LOCK(mli);
		if (mli->mli_version == MLD_VERSION_1) {
			if (inm->in6m_state == MLD_G_QUERY_PENDING_MEMBER ||
			    inm->in6m_state == MLD_SG_QUERY_PENDING_MEMBER) {
				panic("%s: MLDv2 state reached, not MLDv2 "
				    "mode\n", __func__);
				/* NOTREACHED */
			}
			/* scheduler timer if enqueue is successful */
			mtp->cst = (mld_v1_transmit_report(inm,
			    MLD_LISTENER_DONE) == 0);

			IN6M_LOCK_ASSERT_HELD(inm);
			MLI_LOCK_ASSERT_HELD(mli);

			inm->in6m_state = MLD_NOT_MEMBER;
		} else if (mli->mli_version == MLD_VERSION_2) {
			/*
			 * Stop group timer and all pending reports.
			 * Immediately enqueue a state-change report
			 * TO_IN {} to be sent on the next timeout,
			 * giving us an opportunity to merge reports.
			 */
			IF_DRAIN(&inm->in6m_scq);
			inm->in6m_timer = 0;
			inm->in6m_scrv = mli->mli_rv;
			MLD_PRINTF(("%s: Leaving %s/%s with %d "
			    "pending retransmissions.\n", __func__,
			    ip6_sprintf(&inm->in6m_addr),
			    if_name(inm->in6m_ifp),
			    inm->in6m_scrv));
			if (inm->in6m_scrv == 0) {
				inm->in6m_state = MLD_NOT_MEMBER;
				inm->in6m_sctimer = 0;
			} else {
				int retval;
				/*
				 * Stick around in the in6_multihead list;
				 * the final detach will be issued by
				 * mld_v2_process_group_timers() when
				 * the retransmit timer expires.
				 */
				IN6M_ADDREF_LOCKED(inm);
				VERIFY(inm->in6m_debug & IFD_ATTACHED);
				inm->in6m_reqcnt++;
				VERIFY(inm->in6m_reqcnt >= 1);
				inm->in6m_nrelecnt++;
				VERIFY(inm->in6m_nrelecnt != 0);

				retval = mld_v2_enqueue_group_record(
				    &inm->in6m_scq, inm, 1, 0, 0,
				    (mli->mli_flags & MLIF_USEALLOW));
				mtp->cst = (inm->in6m_scq.ifq_len > 0);
				KASSERT(retval != 0,
				    ("%s: enqueue record = %d\n", __func__,
				     retval));

				inm->in6m_state = MLD_LEAVING_MEMBER;
				inm->in6m_sctimer = 1;
				mtp->sct = 1;
				syncstates = 0;
			}
		}
		MLI_UNLOCK(mli);
		break;
	case MLD_LAZY_MEMBER:
	case MLD_SLEEPING_MEMBER:
	case MLD_AWAKENING_MEMBER:
		/* Our reports are suppressed; do nothing. */
		break;
	}

	if (syncstates) {
		in6m_commit(inm);
		MLD_PRINTF(("%s: T1 -> T0 for %s/%s\n", __func__,
		    ip6_sprintf(&inm->in6m_addr),
		    if_name(inm->in6m_ifp)));
		inm->in6m_st[1].iss_fmode = MCAST_UNDEFINED;
		MLD_PRINTF(("%s: T1 now MCAST_UNDEFINED for 0x%llx/%s\n",
		    __func__, (uint64_t)VM_KERNEL_ADDRPERM(&inm->in6m_addr),
		    if_name(inm->in6m_ifp)));
	}
}

/*
 * Enqueue an MLDv2 group record to the given output queue.
 *
 * If is_state_change is zero, a current-state record is appended.
 * If is_state_change is non-zero, a state-change report is appended.
 *
 * If is_group_query is non-zero, an mbuf packet chain is allocated.
 * If is_group_query is zero, and if there is a packet with free space
 * at the tail of the queue, it will be appended to providing there
 * is enough free space.
 * Otherwise a new mbuf packet chain is allocated.
 *
 * If is_source_query is non-zero, each source is checked to see if
 * it was recorded for a Group-Source query, and will be omitted if
 * it is not both in-mode and recorded.
 *
 * If use_block_allow is non-zero, state change reports for initial join
 * and final leave, on an inclusive mode group with a source list, will be
 * rewritten to use the ALLOW_NEW and BLOCK_OLD record types, respectively.
 *
 * The function will attempt to allocate leading space in the packet
 * for the IPv6+ICMP headers to be prepended without fragmenting the chain.
 *
 * If successful the size of all data appended to the queue is returned,
 * otherwise an error code less than zero is returned, or zero if
 * no record(s) were appended.
 */
static int
mld_v2_enqueue_group_record(struct ifqueue *ifq, struct in6_multi *inm,
    const int is_state_change, const int is_group_query,
    const int is_source_query, const int use_block_allow)
{
	struct mldv2_record	 mr;
	struct mldv2_record	*pmr;
	struct ifnet		*ifp;
	struct ip6_msource	*ims, *nims;
	struct mbuf		*m0, *m, *md;
	int			 error, is_filter_list_change;
	int			 minrec0len, m0srcs, msrcs, nbytes, off;
	int			 record_has_sources;
	int			 now;
	int			 type;
	uint8_t			 mode;

	IN6M_LOCK_ASSERT_HELD(inm);
	MLI_LOCK_ASSERT_HELD(inm->in6m_mli);

	error = 0;
	ifp = inm->in6m_ifp;
	is_filter_list_change = 0;
	m = NULL;
	m0 = NULL;
	m0srcs = 0;
	msrcs = 0;
	nbytes = 0;
	nims = NULL;
	record_has_sources = 1;
	pmr = NULL;
	type = MLD_DO_NOTHING;
	mode = inm->in6m_st[1].iss_fmode;

	/*
	 * If we did not transition out of ASM mode during t0->t1,
	 * and there are no source nodes to process, we can skip
	 * the generation of source records.
	 */
	if (inm->in6m_st[0].iss_asm > 0 && inm->in6m_st[1].iss_asm > 0 &&
	    inm->in6m_nsrc == 0)
		record_has_sources = 0;

	if (is_state_change) {
		/*
		 * Queue a state change record.
		 * If the mode did not change, and there are non-ASM
		 * listeners or source filters present,
		 * we potentially need to issue two records for the group.
		 * If there are ASM listeners, and there was no filter
		 * mode transition of any kind, do nothing.
		 *
		 * If we are transitioning to MCAST_UNDEFINED, we need
		 * not send any sources. A transition to/from this state is
		 * considered inclusive with some special treatment.
		 *
		 * If we are rewriting initial joins/leaves to use
		 * ALLOW/BLOCK, and the group's membership is inclusive,
		 * we need to send sources in all cases.
		 */
		if (mode != inm->in6m_st[0].iss_fmode) {
			if (mode == MCAST_EXCLUDE) {
				MLD_PRINTF(("%s: change to EXCLUDE\n",
				    __func__));
				type = MLD_CHANGE_TO_EXCLUDE_MODE;
			} else {
				MLD_PRINTF(("%s: change to INCLUDE\n",
				    __func__));
				if (use_block_allow) {
					/*
					 * XXX
					 * Here we're interested in state
					 * edges either direction between
					 * MCAST_UNDEFINED and MCAST_INCLUDE.
					 * Perhaps we should just check
					 * the group state, rather than
					 * the filter mode.
					 */
					if (mode == MCAST_UNDEFINED) {
						type = MLD_BLOCK_OLD_SOURCES;
					} else {
						type = MLD_ALLOW_NEW_SOURCES;
					}
				} else {
					type = MLD_CHANGE_TO_INCLUDE_MODE;
					if (mode == MCAST_UNDEFINED)
						record_has_sources = 0;
				}
			}
		} else {
			if (record_has_sources) {
				is_filter_list_change = 1;
			} else {
				type = MLD_DO_NOTHING;
			}
		}
	} else {
		/*
		 * Queue a current state record.
		 */
		if (mode == MCAST_EXCLUDE) {
			type = MLD_MODE_IS_EXCLUDE;
		} else if (mode == MCAST_INCLUDE) {
			type = MLD_MODE_IS_INCLUDE;
			VERIFY(inm->in6m_st[1].iss_asm == 0);
		}
	}

	/*
	 * Generate the filter list changes using a separate function.
	 */
	if (is_filter_list_change)
		return (mld_v2_enqueue_filter_change(ifq, inm));

	if (type == MLD_DO_NOTHING) {
		MLD_PRINTF(("%s: nothing to do for %s/%s\n",
		    __func__, ip6_sprintf(&inm->in6m_addr),
		    if_name(inm->in6m_ifp)));
		return (0);
	}

	/*
	 * If any sources are present, we must be able to fit at least
	 * one in the trailing space of the tail packet's mbuf,
	 * ideally more.
	 */
	minrec0len = sizeof(struct mldv2_record);
	if (record_has_sources)
		minrec0len += sizeof(struct in6_addr);
	MLD_PRINTF(("%s: queueing %s for %s/%s\n", __func__,
	    mld_rec_type_to_str(type),
	    ip6_sprintf(&inm->in6m_addr),
	    if_name(inm->in6m_ifp)));

	/*
	 * Check if we have a packet in the tail of the queue for this
	 * group into which the first group record for this group will fit.
	 * Otherwise allocate a new packet.
	 * Always allocate leading space for IP6+RA+ICMPV6+REPORT.
	 * Note: Group records for G/GSR query responses MUST be sent
	 * in their own packet.
	 */
	m0 = ifq->ifq_tail;
	if (!is_group_query &&
	    m0 != NULL &&
	    (m0->m_pkthdr.vt_nrecs + 1 <= MLD_V2_REPORT_MAXRECS) &&
	    (m0->m_pkthdr.len + minrec0len) <
	     (ifp->if_mtu - MLD_MTUSPACE)) {
		m0srcs = (ifp->if_mtu - m0->m_pkthdr.len -
			    sizeof(struct mldv2_record)) /
			    sizeof(struct in6_addr);
		m = m0;
		MLD_PRINTF(("%s: use existing packet\n", __func__));
	} else {
		if (IF_QFULL(ifq)) {
			MLD_PRINTF(("%s: outbound queue full\n", __func__));
			return (-ENOMEM);
		}
		m = NULL;
		m0srcs = (ifp->if_mtu - MLD_MTUSPACE -
		    sizeof(struct mldv2_record)) / sizeof(struct in6_addr);
		if (!is_state_change && !is_group_query)
			m = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);
		if (m == NULL)
			m = m_gethdr(M_DONTWAIT, MT_DATA);
		if (m == NULL)
			return (-ENOMEM);

		mld_save_context(m, ifp);

		MLD_PRINTF(("%s: allocated first packet\n", __func__));
	}

	/*
	 * Append group record.
	 * If we have sources, we don't know how many yet.
	 */
	mr.mr_type = type;
	mr.mr_datalen = 0;
	mr.mr_numsrc = 0;
	mr.mr_addr = inm->in6m_addr;
	in6_clearscope(&mr.mr_addr);
	if (!m_append(m, sizeof(struct mldv2_record), (void *)&mr)) {
		if (m != m0)
			m_freem(m);
		MLD_PRINTF(("%s: m_append() failed.\n", __func__));
		return (-ENOMEM);
	}
	nbytes += sizeof(struct mldv2_record);

	/*
	 * Append as many sources as will fit in the first packet.
	 * If we are appending to a new packet, the chain allocation
	 * may potentially use clusters; use m_getptr() in this case.
	 * If we are appending to an existing packet, we need to obtain
	 * a pointer to the group record after m_append(), in case a new
	 * mbuf was allocated.
	 *
	 * Only append sources which are in-mode at t1. If we are
	 * transitioning to MCAST_UNDEFINED state on the group, and
	 * use_block_allow is zero, do not include source entries.
	 * Otherwise, we need to include this source in the report.
	 *
	 * Only report recorded sources in our filter set when responding
	 * to a group-source query.
	 */
	if (record_has_sources) {
		if (m == m0) {
			md = m_last(m);
			pmr = (struct mldv2_record *)(mtod(md, uint8_t *) +
			    md->m_len - nbytes);
		} else {
			md = m_getptr(m, 0, &off);
			pmr = (struct mldv2_record *)(mtod(md, uint8_t *) +
			    off);
		}
		msrcs = 0;
		RB_FOREACH_SAFE(ims, ip6_msource_tree, &inm->in6m_srcs,
		    nims) {
			MLD_PRINTF(("%s: visit node %s\n", __func__,
			    ip6_sprintf(&ims->im6s_addr)));
			now = im6s_get_mode(inm, ims, 1);
			MLD_PRINTF(("%s: node is %d\n", __func__, now));
			if ((now != mode) ||
			    (now == mode &&
			     (!use_block_allow && mode == MCAST_UNDEFINED))) {
				MLD_PRINTF(("%s: skip node\n", __func__));
				continue;
			}
			if (is_source_query && ims->im6s_stp == 0) {
				MLD_PRINTF(("%s: skip unrecorded node\n",
				    __func__));
				continue;
			}
			MLD_PRINTF(("%s: append node\n", __func__));
			if (!m_append(m, sizeof(struct in6_addr),
			    (void *)&ims->im6s_addr)) {
				if (m != m0)
					m_freem(m);
				MLD_PRINTF(("%s: m_append() failed.\n",
				    __func__));
				return (-ENOMEM);
			}
			nbytes += sizeof(struct in6_addr);
			++msrcs;
			if (msrcs == m0srcs)
				break;
		}
		MLD_PRINTF(("%s: msrcs is %d this packet\n", __func__,
		    msrcs));
		pmr->mr_numsrc = htons(msrcs);
		nbytes += (msrcs * sizeof(struct in6_addr));
	}

	if (is_source_query && msrcs == 0) {
		MLD_PRINTF(("%s: no recorded sources to report\n", __func__));
		if (m != m0)
			m_freem(m);
		return (0);
	}

	/*
	 * We are good to go with first packet.
	 */
	if (m != m0) {
		MLD_PRINTF(("%s: enqueueing first packet\n", __func__));
		m->m_pkthdr.vt_nrecs = 1;
		IF_ENQUEUE(ifq, m);
	} else {
		m->m_pkthdr.vt_nrecs++;
	}
	/*
	 * No further work needed if no source list in packet(s).
	 */
	if (!record_has_sources)
		return (nbytes);

	/*
	 * Whilst sources remain to be announced, we need to allocate
	 * a new packet and fill out as many sources as will fit.
	 * Always try for a cluster first.
	 */
	while (nims != NULL) {
		if (IF_QFULL(ifq)) {
			MLD_PRINTF(("%s: outbound queue full\n", __func__));
			return (-ENOMEM);
		}
		m = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);
		if (m == NULL)
			m = m_gethdr(M_DONTWAIT, MT_DATA);
		if (m == NULL)
			return (-ENOMEM);
		mld_save_context(m, ifp);
		md = m_getptr(m, 0, &off);
		pmr = (struct mldv2_record *)(mtod(md, uint8_t *) + off);
		MLD_PRINTF(("%s: allocated next packet\n", __func__));

		if (!m_append(m, sizeof(struct mldv2_record), (void *)&mr)) {
			if (m != m0)
				m_freem(m);
			MLD_PRINTF(("%s: m_append() failed.\n", __func__));
			return (-ENOMEM);
		}
		m->m_pkthdr.vt_nrecs = 1;
		nbytes += sizeof(struct mldv2_record);

		m0srcs = (ifp->if_mtu - MLD_MTUSPACE -
		    sizeof(struct mldv2_record)) / sizeof(struct in6_addr);

		msrcs = 0;
		RB_FOREACH_FROM(ims, ip6_msource_tree, nims) {
			MLD_PRINTF(("%s: visit node %s\n",
			    __func__, ip6_sprintf(&ims->im6s_addr)));
			now = im6s_get_mode(inm, ims, 1);
			if ((now != mode) ||
			    (now == mode &&
			     (!use_block_allow && mode == MCAST_UNDEFINED))) {
				MLD_PRINTF(("%s: skip node\n", __func__));
				continue;
			}
			if (is_source_query && ims->im6s_stp == 0) {
				MLD_PRINTF(("%s: skip unrecorded node\n",
				    __func__));
				continue;
			}
			MLD_PRINTF(("%s: append node\n", __func__));
			if (!m_append(m, sizeof(struct in6_addr),
			    (void *)&ims->im6s_addr)) {
				if (m != m0)
					m_freem(m);
				MLD_PRINTF(("%s: m_append() failed.\n",
				    __func__));
				return (-ENOMEM);
			}
			++msrcs;
			if (msrcs == m0srcs)
				break;
		}
		pmr->mr_numsrc = htons(msrcs);
		nbytes += (msrcs * sizeof(struct in6_addr));

		MLD_PRINTF(("%s: enqueueing next packet\n", __func__));
		IF_ENQUEUE(ifq, m);
	}

	return (nbytes);
}

/*
 * Type used to mark record pass completion.
 * We exploit the fact we can cast to this easily from the
 * current filter modes on each ip_msource node.
 */
typedef enum {
	REC_NONE = 0x00,	/* MCAST_UNDEFINED */
	REC_ALLOW = 0x01,	/* MCAST_INCLUDE */
	REC_BLOCK = 0x02,	/* MCAST_EXCLUDE */
	REC_FULL = REC_ALLOW | REC_BLOCK
} rectype_t;

/*
 * Enqueue an MLDv2 filter list change to the given output queue.
 *
 * Source list filter state is held in an RB-tree. When the filter list
 * for a group is changed without changing its mode, we need to compute
 * the deltas between T0 and T1 for each source in the filter set,
 * and enqueue the appropriate ALLOW_NEW/BLOCK_OLD records.
 *
 * As we may potentially queue two record types, and the entire R-B tree
 * needs to be walked at once, we break this out into its own function
 * so we can generate a tightly packed queue of packets.
 *
 * XXX This could be written to only use one tree walk, although that makes
 * serializing into the mbuf chains a bit harder. For now we do two walks
 * which makes things easier on us, and it may or may not be harder on
 * the L2 cache.
 *
 * If successful the size of all data appended to the queue is returned,
 * otherwise an error code less than zero is returned, or zero if
 * no record(s) were appended.
 */
static int
mld_v2_enqueue_filter_change(struct ifqueue *ifq, struct in6_multi *inm)
{
	static const int MINRECLEN =
	    sizeof(struct mldv2_record) + sizeof(struct in6_addr);
	struct ifnet		*ifp;
	struct mldv2_record	 mr;
	struct mldv2_record	*pmr;
	struct ip6_msource	*ims, *nims;
	struct mbuf		*m, *m0, *md;
	int			 m0srcs, nbytes, npbytes, off, rsrcs, schanged;
	int			 nallow, nblock;
	uint8_t			 mode, now, then;
	rectype_t		 crt, drt, nrt;

	IN6M_LOCK_ASSERT_HELD(inm);

	if (inm->in6m_nsrc == 0 ||
	    (inm->in6m_st[0].iss_asm > 0 && inm->in6m_st[1].iss_asm > 0))
		return (0);

	ifp = inm->in6m_ifp;			/* interface */
	mode = inm->in6m_st[1].iss_fmode;	/* filter mode at t1 */
	crt = REC_NONE;	/* current group record type */
	drt = REC_NONE;	/* mask of completed group record types */
	nrt = REC_NONE;	/* record type for current node */
	m0srcs = 0;	/* # source which will fit in current mbuf chain */
	npbytes = 0;	/* # of bytes appended this packet */
	nbytes = 0;	/* # of bytes appended to group's state-change queue */
	rsrcs = 0;	/* # sources encoded in current record */
	schanged = 0;	/* # nodes encoded in overall filter change */
	nallow = 0;	/* # of source entries in ALLOW_NEW */
	nblock = 0;	/* # of source entries in BLOCK_OLD */
	nims = NULL;	/* next tree node pointer */

	/*
	 * For each possible filter record mode.
	 * The first kind of source we encounter tells us which
	 * is the first kind of record we start appending.
	 * If a node transitioned to UNDEFINED at t1, its mode is treated
	 * as the inverse of the group's filter mode.
	 */
	while (drt != REC_FULL) {
		do {
			m0 = ifq->ifq_tail;
			if (m0 != NULL &&
			    (m0->m_pkthdr.vt_nrecs + 1 <=
			     MLD_V2_REPORT_MAXRECS) &&
			    (m0->m_pkthdr.len + MINRECLEN) <
			     (ifp->if_mtu - MLD_MTUSPACE)) {
				m = m0;
				m0srcs = (ifp->if_mtu - m0->m_pkthdr.len -
					    sizeof(struct mldv2_record)) /
					    sizeof(struct in6_addr);
				MLD_PRINTF(("%s: use previous packet\n",
				    __func__));
			} else {
				m = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);
				if (m == NULL)
					m = m_gethdr(M_DONTWAIT, MT_DATA);
				if (m == NULL) {
					MLD_PRINTF(("%s: m_get*() failed\n",
					    __func__));
					return (-ENOMEM);
				}
				m->m_pkthdr.vt_nrecs = 0;
				mld_save_context(m, ifp);
				m0srcs = (ifp->if_mtu - MLD_MTUSPACE -
				    sizeof(struct mldv2_record)) /
				    sizeof(struct in6_addr);
				npbytes = 0;
				MLD_PRINTF(("%s: allocated new packet\n",
				    __func__));
			}
			/*
			 * Append the MLD group record header to the
			 * current packet's data area.
			 * Recalculate pointer to free space for next
			 * group record, in case m_append() allocated
			 * a new mbuf or cluster.
			 */
			memset(&mr, 0, sizeof(mr));
			mr.mr_addr = inm->in6m_addr;
			in6_clearscope(&mr.mr_addr);
			if (!m_append(m, sizeof(mr), (void *)&mr)) {
				if (m != m0)
					m_freem(m);
				MLD_PRINTF(("%s: m_append() failed\n",
				    __func__));
				return (-ENOMEM);
			}
			npbytes += sizeof(struct mldv2_record);
			if (m != m0) {
				/* new packet; offset in chain */
				md = m_getptr(m, npbytes -
				    sizeof(struct mldv2_record), &off);
				pmr = (struct mldv2_record *)(mtod(md,
				    uint8_t *) + off);
			} else {
				/* current packet; offset from last append */
				md = m_last(m);
				pmr = (struct mldv2_record *)(mtod(md,
				    uint8_t *) + md->m_len -
				    sizeof(struct mldv2_record));
			}
			/*
			 * Begin walking the tree for this record type
			 * pass, or continue from where we left off
			 * previously if we had to allocate a new packet.
			 * Only report deltas in-mode at t1.
			 * We need not report included sources as allowed
			 * if we are in inclusive mode on the group,
			 * however the converse is not true.
			 */
			rsrcs = 0;
			if (nims == NULL) {
				nims = RB_MIN(ip6_msource_tree,
				    &inm->in6m_srcs);
			}
			RB_FOREACH_FROM(ims, ip6_msource_tree, nims) {
				MLD_PRINTF(("%s: visit node %s\n", __func__,
				    ip6_sprintf(&ims->im6s_addr)));
				now = im6s_get_mode(inm, ims, 1);
				then = im6s_get_mode(inm, ims, 0);
				MLD_PRINTF(("%s: mode: t0 %d, t1 %d\n",
				    __func__, then, now));
				if (now == then) {
					MLD_PRINTF(("%s: skip unchanged\n",
					    __func__));
					continue;
				}
				if (mode == MCAST_EXCLUDE &&
				    now == MCAST_INCLUDE) {
					MLD_PRINTF(("%s: skip IN src on EX "
					    "group\n", __func__));
					continue;
				}
				nrt = (rectype_t)now;
				if (nrt == REC_NONE)
					nrt = (rectype_t)(~mode & REC_FULL);
				if (schanged++ == 0) {
					crt = nrt;
				} else if (crt != nrt)
					continue;
				if (!m_append(m, sizeof(struct in6_addr),
				    (void *)&ims->im6s_addr)) {
					if (m != m0)
						m_freem(m);
					MLD_PRINTF(("%s: m_append() failed\n",
					    __func__));
					return (-ENOMEM);
				}
				nallow += !!(crt == REC_ALLOW);
				nblock += !!(crt == REC_BLOCK);
				if (++rsrcs == m0srcs)
					break;
			}
			/*
			 * If we did not append any tree nodes on this
			 * pass, back out of allocations.
			 */
			if (rsrcs == 0) {
				npbytes -= sizeof(struct mldv2_record);
				if (m != m0) {
					MLD_PRINTF(("%s: m_free(m)\n",
					    __func__));
					m_freem(m);
				} else {
					MLD_PRINTF(("%s: m_adj(m, -mr)\n",
					    __func__));
					m_adj(m, -((int)sizeof(
					    struct mldv2_record)));
				}
				continue;
			}
			npbytes += (rsrcs * sizeof(struct in6_addr));
			if (crt == REC_ALLOW)
				pmr->mr_type = MLD_ALLOW_NEW_SOURCES;
			else if (crt == REC_BLOCK)
				pmr->mr_type = MLD_BLOCK_OLD_SOURCES;
			pmr->mr_numsrc = htons(rsrcs);
			/*
			 * Count the new group record, and enqueue this
			 * packet if it wasn't already queued.
			 */
			m->m_pkthdr.vt_nrecs++;
			if (m != m0)
				IF_ENQUEUE(ifq, m);
			nbytes += npbytes;
		} while (nims != NULL);
		drt |= crt;
		crt = (~crt & REC_FULL);
	}

	MLD_PRINTF(("%s: queued %d ALLOW_NEW, %d BLOCK_OLD\n", __func__,
	    nallow, nblock));

	return (nbytes);
}

static int
mld_v2_merge_state_changes(struct in6_multi *inm, struct ifqueue *ifscq)
{
	struct ifqueue	*gq;
	struct mbuf	*m;		/* pending state-change */
	struct mbuf	*m0;		/* copy of pending state-change */
	struct mbuf	*mt;		/* last state-change in packet */
	struct mbuf	*n;
	int		 docopy, domerge;
	u_int		 recslen;

	IN6M_LOCK_ASSERT_HELD(inm);

	docopy = 0;
	domerge = 0;
	recslen = 0;

	/*
	 * If there are further pending retransmissions, make a writable
	 * copy of each queued state-change message before merging.
	 */
	if (inm->in6m_scrv > 0)
		docopy = 1;

	gq = &inm->in6m_scq;
#ifdef MLD_DEBUG
	if (gq->ifq_head == NULL) {
		MLD_PRINTF(("%s: WARNING: queue for inm 0x%llx is empty\n",
		    __func__, (uint64_t)VM_KERNEL_ADDRPERM(inm)));
	}
#endif

	/*
	 * Use IF_REMQUEUE() instead of IF_DEQUEUE() below, since the
	 * packet might not always be at the head of the ifqueue.
	 */
	m = gq->ifq_head;
	while (m != NULL) {
		/*
		 * Only merge the report into the current packet if
		 * there is sufficient space to do so; an MLDv2 report
		 * packet may only contain 65,535 group records.
		 * Always use a simple mbuf chain concatentation to do this,
		 * as large state changes for single groups may have
		 * allocated clusters.
		 */
		domerge = 0;
		mt = ifscq->ifq_tail;
		if (mt != NULL) {
			recslen = m_length(m);

			if ((mt->m_pkthdr.vt_nrecs +
			    m->m_pkthdr.vt_nrecs <=
			    MLD_V2_REPORT_MAXRECS) &&
			    (mt->m_pkthdr.len + recslen <=
			    (inm->in6m_ifp->if_mtu - MLD_MTUSPACE)))
				domerge = 1;
		}

		if (!domerge && IF_QFULL(gq)) {
			MLD_PRINTF(("%s: outbound queue full, skipping whole "
			    "packet 0x%llx\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(m)));
			n = m->m_nextpkt;
			if (!docopy) {
				IF_REMQUEUE(gq, m);
				m_freem(m);
			}
			m = n;
			continue;
		}

		if (!docopy) {
			MLD_PRINTF(("%s: dequeueing 0x%llx\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(m)));
			n = m->m_nextpkt;
			IF_REMQUEUE(gq, m);
			m0 = m;
			m = n;
		} else {
			MLD_PRINTF(("%s: copying 0x%llx\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(m)));
			m0 = m_dup(m, M_NOWAIT);
			if (m0 == NULL)
				return (ENOMEM);
			m0->m_nextpkt = NULL;
			m = m->m_nextpkt;
		}

		if (!domerge) {
			MLD_PRINTF(("%s: queueing 0x%llx to ifscq 0x%llx)\n",
			    __func__, (uint64_t)VM_KERNEL_ADDRPERM(m0),
			    (uint64_t)VM_KERNEL_ADDRPERM(ifscq)));
			IF_ENQUEUE(ifscq, m0);
		} else {
			struct mbuf *mtl;	/* last mbuf of packet mt */

			MLD_PRINTF(("%s: merging 0x%llx with ifscq tail "
			    "0x%llx)\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(m0),
			    (uint64_t)VM_KERNEL_ADDRPERM(mt)));

			mtl = m_last(mt);
			m0->m_flags &= ~M_PKTHDR;
			mt->m_pkthdr.len += recslen;
			mt->m_pkthdr.vt_nrecs +=
			    m0->m_pkthdr.vt_nrecs;

			mtl->m_next = m0;
		}
	}

	return (0);
}

/*
 * Respond to a pending MLDv2 General Query.
 */
static uint32_t
mld_v2_dispatch_general_query(struct mld_ifinfo *mli)
{
	struct ifnet		*ifp;
	struct in6_multi	*inm;
	struct in6_multistep	step;
	int			 retval;

	MLI_LOCK_ASSERT_HELD(mli);

	VERIFY(mli->mli_version == MLD_VERSION_2);

	ifp = mli->mli_ifp;
	MLI_UNLOCK(mli);

	in6_multihead_lock_shared();
	IN6_FIRST_MULTI(step, inm);
	while (inm != NULL) {
		IN6M_LOCK(inm);
		if (inm->in6m_ifp != ifp)
			goto next;

		switch (inm->in6m_state) {
		case MLD_NOT_MEMBER:
		case MLD_SILENT_MEMBER:
			break;
		case MLD_REPORTING_MEMBER:
		case MLD_IDLE_MEMBER:
		case MLD_LAZY_MEMBER:
		case MLD_SLEEPING_MEMBER:
		case MLD_AWAKENING_MEMBER:
			inm->in6m_state = MLD_REPORTING_MEMBER;
			MLI_LOCK(mli);
			retval = mld_v2_enqueue_group_record(&mli->mli_gq,
			    inm, 0, 0, 0, 0);
			MLI_UNLOCK(mli);
			MLD_PRINTF(("%s: enqueue record = %d\n",
			    __func__, retval));
			break;
		case MLD_G_QUERY_PENDING_MEMBER:
		case MLD_SG_QUERY_PENDING_MEMBER:
		case MLD_LEAVING_MEMBER:
			break;
		}
next:
		IN6M_UNLOCK(inm);
		IN6_NEXT_MULTI(step, inm);
	}
	in6_multihead_lock_done();

	MLI_LOCK(mli);
	mld_dispatch_queue_locked(mli, &mli->mli_gq, MLD_MAX_RESPONSE_BURST);
	MLI_LOCK_ASSERT_HELD(mli);

	/*
	 * Slew transmission of bursts over 1 second intervals.
	 */
	if (mli->mli_gq.ifq_head != NULL) {
		mli->mli_v2_timer = 1 + MLD_RANDOM_DELAY(
		    MLD_RESPONSE_BURST_INTERVAL);
	}

	return (mli->mli_v2_timer);
}

/*
 * Transmit the next pending message in the output queue.
 *
 * Must not be called with in6m_lockm or mli_lock held.
 */
static void
mld_dispatch_packet(struct mbuf *m)
{
	struct ip6_moptions	*im6o;
	struct ifnet		*ifp;
	struct ifnet		*oifp = NULL;
	struct mbuf		*m0;
	struct mbuf		*md;
	struct ip6_hdr		*ip6;
	struct mld_hdr		*mld;
	int			 error;
	int			 off;
	int			 type;

	MLD_PRINTF(("%s: transmit 0x%llx\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(m)));

	/*
	 * Check if the ifnet is still attached.
	 */
	ifp = mld_restore_context(m);
	if (ifp == NULL || !ifnet_is_attached(ifp, 0)) {
		MLD_PRINTF(("%s: dropped 0x%llx as ifindex %u went away.\n",
		    __func__, (uint64_t)VM_KERNEL_ADDRPERM(m),
		    (u_int)if_index));
		m_freem(m);
		ip6stat.ip6s_noroute++;
		return;
	}

	im6o = ip6_allocmoptions(M_WAITOK);
	if (im6o == NULL) {
		m_freem(m);
		return;
	}

	im6o->im6o_multicast_hlim  = 1;
	im6o->im6o_multicast_loop = 0;
	im6o->im6o_multicast_ifp = ifp;

	if (m->m_flags & M_MLDV1) {
		m0 = m;
	} else {
		m0 = mld_v2_encap_report(ifp, m);
		if (m0 == NULL) {
			MLD_PRINTF(("%s: dropped 0x%llx\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(m)));
			/*
			 * mld_v2_encap_report() has already freed our mbuf.
			 */
			IM6O_REMREF(im6o);
			ip6stat.ip6s_odropped++;
			return;
		}
	}

	mld_scrub_context(m0);
	m->m_flags &= ~(M_PROTOFLAGS);
	m0->m_pkthdr.rcvif = lo_ifp;

	ip6 = mtod(m0, struct ip6_hdr *);
	(void) in6_setscope(&ip6->ip6_dst, ifp, NULL);

	/*
	 * Retrieve the ICMPv6 type before handoff to ip6_output(),
	 * so we can bump the stats.
	 */
	md = m_getptr(m0, sizeof(struct ip6_hdr), &off);
	mld = (struct mld_hdr *)(mtod(md, uint8_t *) + off);
	type = mld->mld_type;

	if (ifp->if_eflags & IFEF_TXSTART) {
		/* 
		 * Use control service class if the outgoing 
		 * interface supports transmit-start model.
		 */
		(void) m_set_service_class(m0, MBUF_SC_CTL);
	}

	error = ip6_output(m0, &mld_po, NULL, IPV6_UNSPECSRC, im6o,
	    &oifp, NULL);

	IM6O_REMREF(im6o);

	if (error) {
		MLD_PRINTF(("%s: ip6_output(0x%llx) = %d\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(m0), error));
		if (oifp != NULL)
			ifnet_release(oifp);
		return;
	}

	icmp6stat.icp6s_outhist[type]++;
	if (oifp != NULL) {
		icmp6_ifstat_inc(oifp, ifs6_out_msg);
		switch (type) {
		case MLD_LISTENER_REPORT:
		case MLDV2_LISTENER_REPORT:
			icmp6_ifstat_inc(oifp, ifs6_out_mldreport);
			break;
		case MLD_LISTENER_DONE:
			icmp6_ifstat_inc(oifp, ifs6_out_mlddone);
			break;
		}
		ifnet_release(oifp);
	}
}

/*
 * Encapsulate an MLDv2 report.
 *
 * KAME IPv6 requires that hop-by-hop options be passed separately,
 * and that the IPv6 header be prepended in a separate mbuf.
 *
 * Returns a pointer to the new mbuf chain head, or NULL if the
 * allocation failed.
 */
static struct mbuf *
mld_v2_encap_report(struct ifnet *ifp, struct mbuf *m)
{
	struct mbuf		*mh;
	struct mldv2_report	*mld;
	struct ip6_hdr		*ip6;
	struct in6_ifaddr	*ia;
	int			 mldreclen;

	VERIFY(m->m_flags & M_PKTHDR);

	/*
	 * RFC3590: OK to send as :: or tentative during DAD.
	 */
	ia = in6ifa_ifpforlinklocal(ifp, IN6_IFF_NOTREADY|IN6_IFF_ANYCAST);
	if (ia == NULL)
		MLD_PRINTF(("%s: warning: ia is NULL\n", __func__));

	MGETHDR(mh, M_DONTWAIT, MT_HEADER);
	if (mh == NULL) {
		if (ia != NULL)
			IFA_REMREF(&ia->ia_ifa);
		m_freem(m);
		return (NULL);
	}
	MH_ALIGN(mh, sizeof(struct ip6_hdr) + sizeof(struct mldv2_report));

	mldreclen = m_length(m);
	MLD_PRINTF(("%s: mldreclen is %d\n", __func__, mldreclen));

	mh->m_len = sizeof(struct ip6_hdr) + sizeof(struct mldv2_report);
	mh->m_pkthdr.len = sizeof(struct ip6_hdr) +
	    sizeof(struct mldv2_report) + mldreclen;

	ip6 = mtod(mh, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	if (ia != NULL)
		IFA_LOCK(&ia->ia_ifa);
	ip6->ip6_src = ia ? ia->ia_addr.sin6_addr : in6addr_any;
	if (ia != NULL) {
		IFA_UNLOCK(&ia->ia_ifa);
		IFA_REMREF(&ia->ia_ifa);
		ia = NULL;
	}
	ip6->ip6_dst = in6addr_linklocal_allv2routers;
	/* scope ID will be set in netisr */

	mld = (struct mldv2_report *)(ip6 + 1);
	mld->mld_type = MLDV2_LISTENER_REPORT;
	mld->mld_code = 0;
	mld->mld_cksum = 0;
	mld->mld_v2_reserved = 0;
	mld->mld_v2_numrecs = htons(m->m_pkthdr.vt_nrecs);
	m->m_pkthdr.vt_nrecs = 0;
	m->m_flags &= ~M_PKTHDR;

	mh->m_next = m;
	mld->mld_cksum = in6_cksum(mh, IPPROTO_ICMPV6,
	    sizeof(struct ip6_hdr), sizeof(struct mldv2_report) + mldreclen);
	return (mh);
}

#ifdef MLD_DEBUG
static const char *
mld_rec_type_to_str(const int type)
{
	switch (type) {
		case MLD_CHANGE_TO_EXCLUDE_MODE:
			return "TO_EX";
		case MLD_CHANGE_TO_INCLUDE_MODE:
			return "TO_IN";
		case MLD_MODE_IS_EXCLUDE:
			return "MODE_EX";
		case MLD_MODE_IS_INCLUDE:
			return "MODE_IN";
		case MLD_ALLOW_NEW_SOURCES:
			return "ALLOW_NEW";
		case MLD_BLOCK_OLD_SOURCES:
			return "BLOCK_OLD";
		default:
			break;
	}
	return "unknown";
}
#endif

void
mld_init(void)
{

	MLD_PRINTF(("%s: initializing\n", __func__));

        /* Setup lock group and attribute for mld_mtx */
        mld_mtx_grp_attr = lck_grp_attr_alloc_init();
        mld_mtx_grp = lck_grp_alloc_init("mld_mtx\n", mld_mtx_grp_attr);
        mld_mtx_attr = lck_attr_alloc_init();
        lck_mtx_init(&mld_mtx, mld_mtx_grp, mld_mtx_attr);

	ip6_initpktopts(&mld_po);
	mld_po.ip6po_hlim = 1;
	mld_po.ip6po_hbh = &mld_ra.hbh;
	mld_po.ip6po_prefer_tempaddr = IP6PO_TEMPADDR_NOTPREFER;
	mld_po.ip6po_flags = IP6PO_DONTFRAG;
	LIST_INIT(&mli_head);

	mli_size = sizeof (struct mld_ifinfo);
	mli_zone = zinit(mli_size, MLI_ZONE_MAX * mli_size,
	    0, MLI_ZONE_NAME);
	if (mli_zone == NULL) {
		panic("%s: failed allocating %s", __func__, MLI_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(mli_zone, Z_EXPAND, TRUE);
	zone_change(mli_zone, Z_CALLERACCT, FALSE);
}
