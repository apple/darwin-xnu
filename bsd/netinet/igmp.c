/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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

/*
 * Internet Group Management Protocol (IGMP) routines.
 * [RFC1112, RFC2236, RFC3376]
 *
 * Written by Steve Deering, Stanford, May 1988.
 * Modified by Rosen Sharma, Stanford, Aug 1994.
 * Modified by Bill Fenner, Xerox PARC, Feb 1995.
 * Modified to fully comply to IGMPv2 by Bill Fenner, Oct 1995.
 * Significantly rewritten for IGMPv3, VIMAGE, and SMP by Bruce Simpson.
 *
 * MULTICAST Revision: 3.5.1.4
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/mcache.h>

#include <libkern/libkern.h>
#include <kern/zalloc.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/igmp.h>
#include <netinet/igmp_var.h>
#include <netinet/kpi_ipfilter_var.h>

SLIST_HEAD(igmp_inm_relhead, in_multi);

static void	igi_initvar(struct igmp_ifinfo *, struct ifnet *, int);
static struct igmp_ifinfo *igi_alloc(int);
static void	igi_free(struct igmp_ifinfo *);
static void	igi_delete(const struct ifnet *, struct igmp_inm_relhead *);
static void	igmp_dispatch_queue(struct igmp_ifinfo *, struct ifqueue *,
    int, const int);
static void	igmp_final_leave(struct in_multi *, struct igmp_ifinfo *,
		    struct igmp_tparams *);
static int	igmp_handle_state_change(struct in_multi *,
		    struct igmp_ifinfo *, struct igmp_tparams *);
static int	igmp_initial_join(struct in_multi *, struct igmp_ifinfo *,
		    struct igmp_tparams *);
static int	igmp_input_v1_query(struct ifnet *, const struct ip *,
		    const struct igmp *);
static int	igmp_input_v2_query(struct ifnet *, const struct ip *,
		    const struct igmp *);
static int	igmp_input_v3_query(struct ifnet *, const struct ip *,
		    /*const*/ struct igmpv3 *);
static int	igmp_input_v3_group_query(struct in_multi *,
		     int, /*const*/ struct igmpv3 *);
static int	igmp_input_v1_report(struct ifnet *, struct mbuf *,
		    /*const*/ struct ip *, /*const*/ struct igmp *);
static int	igmp_input_v2_report(struct ifnet *, struct mbuf *,
		    /*const*/ struct ip *, /*const*/ struct igmp *);
static void	igmp_sendpkt(struct mbuf *);
static __inline__ int	igmp_isgroupreported(const struct in_addr);
static struct mbuf *igmp_ra_alloc(void);
#ifdef IGMP_DEBUG
static const char *igmp_rec_type_to_str(const int);
#endif
static uint32_t	igmp_set_version(struct igmp_ifinfo *, const int);
static void	igmp_flush_relq(struct igmp_ifinfo *,
    struct igmp_inm_relhead *);
static int	igmp_v1v2_queue_report(struct in_multi *, const int);
static void	igmp_v1v2_process_group_timer(struct in_multi *, const int);
static void	igmp_v1v2_process_querier_timers(struct igmp_ifinfo *);
static uint32_t	igmp_v2_update_group(struct in_multi *, const int);
static void	igmp_v3_cancel_link_timers(struct igmp_ifinfo *);
static uint32_t	igmp_v3_dispatch_general_query(struct igmp_ifinfo *);
static struct mbuf *
		igmp_v3_encap_report(struct ifnet *, struct mbuf *);
static int	igmp_v3_enqueue_group_record(struct ifqueue *,
		    struct in_multi *, const int, const int, const int);
static int	igmp_v3_enqueue_filter_change(struct ifqueue *,
		    struct in_multi *);
static void	igmp_v3_process_group_timers(struct igmp_ifinfo *,
		    struct ifqueue *, struct ifqueue *, struct in_multi *,
		    const int);
static int	igmp_v3_merge_state_changes(struct in_multi *,
		    struct ifqueue *);
static void	igmp_v3_suppress_group_record(struct in_multi *);
static int	sysctl_igmp_ifinfo SYSCTL_HANDLER_ARGS;
static int	sysctl_igmp_gsr SYSCTL_HANDLER_ARGS;
static int	sysctl_igmp_default_version SYSCTL_HANDLER_ARGS;

static int igmp_timeout_run;		/* IGMP timer is scheduled to run */
static void igmp_timeout(void *);
static void igmp_sched_timeout(void);

static struct mbuf *m_raopt;		/* Router Alert option */

static int querier_present_timers_running;	/* IGMPv1/v2 older version
						 * querier present */
static int interface_timers_running;		/* IGMPv3 general
						 * query response */
static int state_change_timers_running;		/* IGMPv3 state-change
						 * retransmit */
static int current_state_timers_running;	/* IGMPv1/v2 host
						 * report; IGMPv3 g/sg
						 * query response */

/*
 * Subsystem lock macros.
 */
#define	IGMP_LOCK()			\
	lck_mtx_lock(&igmp_mtx)
#define	IGMP_LOCK_ASSERT_HELD()		\
	lck_mtx_assert(&igmp_mtx, LCK_MTX_ASSERT_OWNED)
#define	IGMP_LOCK_ASSERT_NOTHELD()	\
	lck_mtx_assert(&igmp_mtx, LCK_MTX_ASSERT_NOTOWNED)
#define	IGMP_UNLOCK()			\
	lck_mtx_unlock(&igmp_mtx)

static LIST_HEAD(, igmp_ifinfo) igi_head;
static struct igmpstat_v3 igmpstat_v3 = {
	.igps_version = IGPS_VERSION_3,
	.igps_len = sizeof(struct igmpstat_v3),
};
static struct igmpstat igmpstat; /* old IGMPv2 stats structure */
static struct timeval igmp_gsrdelay = {10, 0};

static int igmp_recvifkludge = 1;
static int igmp_sendra = 1;
static int igmp_sendlocal = 1;
static int igmp_v1enable = 1;
static int igmp_v2enable = 1;
static int igmp_legacysupp = 0;
static int igmp_default_version = IGMP_VERSION_3;

SYSCTL_STRUCT(_net_inet_igmp, IGMPCTL_STATS, stats, CTLFLAG_RD | CTLFLAG_LOCKED,
    &igmpstat, igmpstat, "");
SYSCTL_STRUCT(_net_inet_igmp, OID_AUTO, v3stats,
    CTLFLAG_RD | CTLFLAG_LOCKED, &igmpstat_v3, igmpstat_v3, "");
SYSCTL_INT(_net_inet_igmp, OID_AUTO, recvifkludge, CTLFLAG_RW | CTLFLAG_LOCKED,
    &igmp_recvifkludge, 0,
    "Rewrite IGMPv1/v2 reports from 0.0.0.0 to contain subnet address");
SYSCTL_INT(_net_inet_igmp, OID_AUTO, sendra, CTLFLAG_RW | CTLFLAG_LOCKED,
    &igmp_sendra, 0,
    "Send IP Router Alert option in IGMPv2/v3 messages");
SYSCTL_INT(_net_inet_igmp, OID_AUTO, sendlocal, CTLFLAG_RW | CTLFLAG_LOCKED,
    &igmp_sendlocal, 0,
    "Send IGMP membership reports for 224.0.0.0/24 groups");
SYSCTL_INT(_net_inet_igmp, OID_AUTO, v1enable, CTLFLAG_RW | CTLFLAG_LOCKED,
    &igmp_v1enable, 0,
    "Enable backwards compatibility with IGMPv1");
SYSCTL_INT(_net_inet_igmp, OID_AUTO, v2enable, CTLFLAG_RW | CTLFLAG_LOCKED,
    &igmp_v2enable, 0,
    "Enable backwards compatibility with IGMPv2");
SYSCTL_INT(_net_inet_igmp, OID_AUTO, legacysupp, CTLFLAG_RW | CTLFLAG_LOCKED,
    &igmp_legacysupp, 0,
    "Allow v1/v2 reports to suppress v3 group responses");
SYSCTL_PROC(_net_inet_igmp, OID_AUTO, default_version,
  CTLTYPE_INT | CTLFLAG_RW,
  &igmp_default_version, 0, sysctl_igmp_default_version, "I",
    "Default version of IGMP to run on each interface");
SYSCTL_PROC(_net_inet_igmp, OID_AUTO, gsrdelay,
    CTLTYPE_INT | CTLFLAG_RW,
    &igmp_gsrdelay.tv_sec, 0, sysctl_igmp_gsr, "I",
    "Rate limit for IGMPv3 Group-and-Source queries in seconds");
#ifdef IGMP_DEBUG
int igmp_debug = 0;
SYSCTL_INT(_net_inet_igmp, OID_AUTO,
	debug, CTLFLAG_RW | CTLFLAG_LOCKED, &igmp_debug, 0, "");
#endif

SYSCTL_NODE(_net_inet_igmp, OID_AUTO, ifinfo, CTLFLAG_RD | CTLFLAG_LOCKED,
    sysctl_igmp_ifinfo, "Per-interface IGMPv3 state");

/* Lock group and attribute for igmp_mtx */
static lck_attr_t	*igmp_mtx_attr;
static lck_grp_t	*igmp_mtx_grp;
static lck_grp_attr_t	*igmp_mtx_grp_attr;

/*
 * Locking and reference counting:
 *
 * igmp_mtx mainly protects igi_head.  In cases where both igmp_mtx and
 * in_multihead_lock must be held, the former must be acquired first in order
 * to maintain lock ordering.  It is not a requirement that igmp_mtx be
 * acquired first before in_multihead_lock, but in case both must be acquired
 * in succession, the correct lock ordering must be followed.
 *
 * Instead of walking the if_multiaddrs list at the interface and returning
 * the ifma_protospec value of a matching entry, we search the global list
 * of in_multi records and find it that way; this is done with in_multihead
 * lock held.  Doing so avoids the race condition issues that many other BSDs
 * suffer from (therefore in our implementation, ifma_protospec will never be
 * NULL for as long as the in_multi is valid.)
 *
 * The above creates a requirement for the in_multi to stay in in_multihead
 * list even after the final IGMP leave (in IGMPv3 mode) until no longer needs
 * be retransmitted (this is not required for IGMPv1/v2.)  In order to handle
 * this, the request and reference counts of the in_multi are bumped up when
 * the state changes to IGMP_LEAVING_MEMBER, and later dropped in the timeout
 * handler.  Each in_multi holds a reference to the underlying igmp_ifinfo.
 *
 * Thus, the permitted lock oder is:
 *
 *	igmp_mtx, in_multihead_lock, inm_lock, igi_lock
 *
 * Any may be taken independently, but if any are held at the same time,
 * the above lock order must be followed.
 */
static decl_lck_mtx_data(, igmp_mtx);
static int igmp_timers_are_running;

#define	IGMP_ADD_DETACHED_INM(_head, _inm) {				\
	SLIST_INSERT_HEAD(_head, _inm, inm_dtle);			\
}

#define	IGMP_REMOVE_DETACHED_INM(_head) {				\
	struct in_multi *_inm, *_inm_tmp;				\
	SLIST_FOREACH_SAFE(_inm, _head, inm_dtle, _inm_tmp) {		\
		SLIST_REMOVE(_head, _inm, in_multi, inm_dtle);		\
		INM_REMREF(_inm);					\
	}								\
	VERIFY(SLIST_EMPTY(_head));					\
}

#define	IGI_ZONE_MAX		64		/* maximum elements in zone */
#define	IGI_ZONE_NAME		"igmp_ifinfo"	/* zone name */

static unsigned int igi_size;			/* size of zone element */
static struct zone *igi_zone;			/* zone for igmp_ifinfo */

/* Store IGMPv3 record count in the module private scratch space */
#define	vt_nrecs	pkt_mpriv.__mpriv_u.__mpriv32[0].__mpriv32_u.__val16[0]

static __inline void
igmp_save_context(struct mbuf *m, struct ifnet *ifp)
{
        m->m_pkthdr.rcvif = ifp;
}

static __inline void
igmp_scrub_context(struct mbuf *m)
{
        m->m_pkthdr.rcvif = NULL;
}

#ifdef IGMP_DEBUG
static __inline const char *
inet_ntop_haddr(in_addr_t haddr, char *buf, socklen_t size)
{
	struct in_addr ia;

	ia.s_addr = htonl(haddr);
	return (inet_ntop(AF_INET, &ia, buf, size));
}
#endif

/*
 * Restore context from a queued IGMP output chain.
 * Return saved ifp.
 */
static __inline struct ifnet *
igmp_restore_context(struct mbuf *m)
{
        return (m->m_pkthdr.rcvif);
}

/*
 * Retrieve or set default IGMP version.
 */
static int
sysctl_igmp_default_version SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int	 error;
	int	 new;

	IGMP_LOCK();

	error = SYSCTL_OUT(req, arg1, sizeof(int));
	if (error || !req->newptr)
		goto out_locked;

	new = igmp_default_version;

	error = SYSCTL_IN(req, &new, sizeof(int));
	if (error)
		goto out_locked;

	if (new < IGMP_VERSION_1 || new > IGMP_VERSION_3) {
		error = EINVAL;
		goto out_locked;
	}

	IGMP_PRINTF(("%s: change igmp_default_version from %d to %d\n",
	    __func__, igmp_default_version, new));

	igmp_default_version = new;

out_locked:
	IGMP_UNLOCK();
	return (error);
}

/*
 * Retrieve or set threshold between group-source queries in seconds.
 *
 */
static int
sysctl_igmp_gsr SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error;
	int i;

	IGMP_LOCK();

	i = igmp_gsrdelay.tv_sec;

	error = sysctl_handle_int(oidp, &i, 0, req);
	if (error || !req->newptr)
		goto out_locked;

	if (i < -1 || i >= 60) {
		error = EINVAL;
		goto out_locked;
	}

	igmp_gsrdelay.tv_sec = i;

out_locked:
	IGMP_UNLOCK();
	return (error);
}

/*
 * Expose struct igmp_ifinfo to userland, keyed by ifindex.
 * For use by ifmcstat(8).
 *
 */
static int
sysctl_igmp_ifinfo SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp)
	int			*name;
	int			 error;
	u_int			 namelen;
	struct ifnet		*ifp;
	struct igmp_ifinfo	*igi;
	struct igmp_ifinfo_u	igi_u;

	name = (int *)arg1;
	namelen = arg2;

	if (req->newptr != USER_ADDR_NULL)
		return (EPERM);

	if (namelen != 1)
		return (EINVAL);

	IGMP_LOCK();

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

	bzero(&igi_u, sizeof (igi_u));

	LIST_FOREACH(igi, &igi_head, igi_link) {
		IGI_LOCK(igi);
		if (ifp != igi->igi_ifp) {
			IGI_UNLOCK(igi);
			continue;
		}
		igi_u.igi_ifindex = igi->igi_ifp->if_index;
		igi_u.igi_version = igi->igi_version;
		igi_u.igi_v1_timer = igi->igi_v1_timer;
		igi_u.igi_v2_timer = igi->igi_v2_timer;
		igi_u.igi_v3_timer = igi->igi_v3_timer;
		igi_u.igi_flags = igi->igi_flags;
		igi_u.igi_rv = igi->igi_rv;
		igi_u.igi_qi = igi->igi_qi;
		igi_u.igi_qri = igi->igi_qri;
		igi_u.igi_uri = igi->igi_uri;
		IGI_UNLOCK(igi);

		error = SYSCTL_OUT(req, &igi_u, sizeof (igi_u));
		break;
	}

out_locked:
	IGMP_UNLOCK();
	return (error);
}

/*
 * Dispatch an entire queue of pending packet chains
 *
 * Must not be called with inm_lock held.
 */
static void
igmp_dispatch_queue(struct igmp_ifinfo *igi, struct ifqueue *ifq, int limit,
    const int loop)
{
	struct mbuf *m;
	struct ip *ip;

	if (igi != NULL)
		IGI_LOCK_ASSERT_HELD(igi);

	for (;;) {
		IF_DEQUEUE(ifq, m);
		if (m == NULL)
			break;
		IGMP_PRINTF(("%s: dispatch 0x%llx from 0x%llx\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(ifq),
		    (uint64_t)VM_KERNEL_ADDRPERM(m)));
		ip = mtod(m, struct ip *);
		if (loop)
			m->m_flags |= M_IGMP_LOOP;
		if (igi != NULL)
			IGI_UNLOCK(igi);
		igmp_sendpkt(m);
		if (igi != NULL)
			IGI_LOCK(igi);
		if (--limit == 0)
			break;
	}

	if (igi != NULL)
		IGI_LOCK_ASSERT_HELD(igi);
}

/*
 * Filter outgoing IGMP report state by group.
 *
 * Reports are ALWAYS suppressed for ALL-HOSTS (224.0.0.1).
 * If the net.inet.igmp.sendlocal sysctl is 0, then IGMP reports are
 * disabled for all groups in the 224.0.0.0/24 link-local scope. However,
 * this may break certain IGMP snooping switches which rely on the old
 * report behaviour.
 *
 * Return zero if the given group is one for which IGMP reports
 * should be suppressed, or non-zero if reports should be issued.
 */

static __inline__
int igmp_isgroupreported(const struct in_addr addr)
{

	if (in_allhosts(addr) ||
	    ((!igmp_sendlocal && IN_LOCAL_GROUP(ntohl(addr.s_addr)))))
		return (0);

	return (1);
}

/*
 * Construct a Router Alert option to use in outgoing packets.
 */
static struct mbuf *
igmp_ra_alloc(void)
{
	struct mbuf	*m;
	struct ipoption	*p;

	MGET(m, M_WAITOK, MT_DATA);
	p = mtod(m, struct ipoption *);
	p->ipopt_dst.s_addr = INADDR_ANY;
	p->ipopt_list[0] = IPOPT_RA;	/* Router Alert Option */
	p->ipopt_list[1] = 0x04;	/* 4 bytes long */
	p->ipopt_list[2] = IPOPT_EOL;	/* End of IP option list */
	p->ipopt_list[3] = 0x00;	/* pad byte */
	m->m_len = sizeof(p->ipopt_dst) + p->ipopt_list[1];

	return (m);
}

/*
 * Attach IGMP when PF_INET is attached to an interface.
 */
struct igmp_ifinfo *
igmp_domifattach(struct ifnet *ifp, int how)
{
	struct igmp_ifinfo *igi;

	IGMP_PRINTF(("%s: called for ifp 0x%llx(%s)\n",
	    __func__, (uint64_t)VM_KERNEL_ADDRPERM(ifp), ifp->if_name));

	igi = igi_alloc(how);
	if (igi == NULL)
		return (NULL);

	IGMP_LOCK();

	IGI_LOCK(igi);
	igi_initvar(igi, ifp, 0);
	igi->igi_debug |= IFD_ATTACHED;
	IGI_ADDREF_LOCKED(igi); /* hold a reference for igi_head */
	IGI_ADDREF_LOCKED(igi); /* hold a reference for caller */
	IGI_UNLOCK(igi);
	ifnet_lock_shared(ifp);
	igmp_initsilent(ifp, igi);
	ifnet_lock_done(ifp);

	LIST_INSERT_HEAD(&igi_head, igi, igi_link);

	IGMP_UNLOCK();

	IGMP_PRINTF(("%s: allocate igmp_ifinfo for ifp 0x%llx(%s)\n", __func__,
	     (uint64_t)VM_KERNEL_ADDRPERM(ifp), ifp->if_name));

	return (igi);
}

/*
 * Attach IGMP when PF_INET is reattached to an interface.  Caller is
 * expected to have an outstanding reference to the igi.
 */
void
igmp_domifreattach(struct igmp_ifinfo *igi)
{
	struct ifnet *ifp;

	IGMP_LOCK();

	IGI_LOCK(igi);
	VERIFY(!(igi->igi_debug & IFD_ATTACHED));
	ifp = igi->igi_ifp;
	VERIFY(ifp != NULL);
	igi_initvar(igi, ifp, 1);
	igi->igi_debug |= IFD_ATTACHED;
	IGI_ADDREF_LOCKED(igi); /* hold a reference for igi_head */
	IGI_UNLOCK(igi);
	ifnet_lock_shared(ifp);
	igmp_initsilent(ifp, igi);
	ifnet_lock_done(ifp);

	LIST_INSERT_HEAD(&igi_head, igi, igi_link);

	IGMP_UNLOCK();

	IGMP_PRINTF(("%s: reattached igmp_ifinfo for ifp 0x%llx(%s)\n",
	    __func__, (uint64_t)VM_KERNEL_ADDRPERM(ifp), ifp->if_name));
}

/*
 * Hook for domifdetach.
 */
void
igmp_domifdetach(struct ifnet *ifp)
{
	SLIST_HEAD(, in_multi) inm_dthead;

	SLIST_INIT(&inm_dthead);

	IGMP_PRINTF(("%s: called for ifp 0x%llx(%s%d)\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(ifp), ifp->if_name, ifp->if_unit));

	IGMP_LOCK();
	igi_delete(ifp, (struct igmp_inm_relhead *)&inm_dthead);
	IGMP_UNLOCK();

	/* Now that we're dropped all locks, release detached records */
	IGMP_REMOVE_DETACHED_INM(&inm_dthead);
}

/*
 * Called at interface detach time.  Note that we only flush all deferred
 * responses and record releases; all remaining inm records and their source
 * entries related to this interface are left intact, in order to handle
 * the reattach case.
 */
static void
igi_delete(const struct ifnet *ifp, struct igmp_inm_relhead *inm_dthead)
{
	struct igmp_ifinfo *igi, *tigi;

	IGMP_LOCK_ASSERT_HELD();

	LIST_FOREACH_SAFE(igi, &igi_head, igi_link, tigi) {
		IGI_LOCK(igi);
		if (igi->igi_ifp == ifp) {
			/*
			 * Free deferred General Query responses.
			 */
			IF_DRAIN(&igi->igi_gq);
			IF_DRAIN(&igi->igi_v2q);
			igmp_flush_relq(igi, inm_dthead);
			VERIFY(SLIST_EMPTY(&igi->igi_relinmhead));
			igi->igi_debug &= ~IFD_ATTACHED;
			IGI_UNLOCK(igi);

			LIST_REMOVE(igi, igi_link);
			IGI_REMREF(igi); /* release igi_head reference */
			return;
		}
		IGI_UNLOCK(igi);
	}
	panic("%s: igmp_ifinfo not found for ifp %p(%s)\n", __func__,
	    ifp, ifp->if_xname);
}

__private_extern__ void
igmp_initsilent(struct ifnet *ifp, struct igmp_ifinfo *igi)
{
	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_OWNED);

	IGI_LOCK_ASSERT_NOTHELD(igi);
	IGI_LOCK(igi);
	if (!(ifp->if_flags & IFF_MULTICAST))
		igi->igi_flags |= IGIF_SILENT;
	else
		igi->igi_flags &= ~IGIF_SILENT;
	IGI_UNLOCK(igi);
}

static void
igi_initvar(struct igmp_ifinfo *igi, struct ifnet *ifp, int reattach)
{
	IGI_LOCK_ASSERT_HELD(igi);

	igi->igi_ifp = ifp;
	igi->igi_version = igmp_default_version;
	igi->igi_flags = 0;
	igi->igi_rv = IGMP_RV_INIT;
	igi->igi_qi = IGMP_QI_INIT;
	igi->igi_qri = IGMP_QRI_INIT;
	igi->igi_uri = IGMP_URI_INIT;

	if (!reattach)
		SLIST_INIT(&igi->igi_relinmhead);

	/*
	 * Responses to general queries are subject to bounds.
	 */
	igi->igi_gq.ifq_maxlen =  IGMP_MAX_RESPONSE_PACKETS;
	igi->igi_v2q.ifq_maxlen = IGMP_MAX_RESPONSE_PACKETS;
}

static struct igmp_ifinfo *
igi_alloc(int how)
{
	struct igmp_ifinfo *igi;

	igi = (how == M_WAITOK) ? zalloc(igi_zone) : zalloc_noblock(igi_zone);
	if (igi != NULL) {
		bzero(igi, igi_size);
		lck_mtx_init(&igi->igi_lock, igmp_mtx_grp, igmp_mtx_attr);
		igi->igi_debug |= IFD_ALLOC;
	}
	return (igi);
}

static void
igi_free(struct igmp_ifinfo *igi)
{
	IGI_LOCK(igi);
	if (igi->igi_debug & IFD_ATTACHED) {
		panic("%s: attached igi=%p is being freed", __func__, igi);
		/* NOTREACHED */
	} else if (igi->igi_ifp != NULL) {
		panic("%s: ifp not NULL for igi=%p", __func__, igi);
		/* NOTREACHED */
	} else if (!(igi->igi_debug & IFD_ALLOC)) {
		panic("%s: igi %p cannot be freed", __func__, igi);
		/* NOTREACHED */
	} else if (igi->igi_refcnt != 0) {
		panic("%s: non-zero refcnt igi=%p", __func__, igi);
		/* NOTREACHED */
	}
	igi->igi_debug &= ~IFD_ALLOC;
	IGI_UNLOCK(igi);

	lck_mtx_destroy(&igi->igi_lock, igmp_mtx_grp);
	zfree(igi_zone, igi);
}

void
igi_addref(struct igmp_ifinfo *igi, int locked)
{
	if (!locked)
		IGI_LOCK_SPIN(igi);
	else
		IGI_LOCK_ASSERT_HELD(igi);

	if (++igi->igi_refcnt == 0) {
		panic("%s: igi=%p wraparound refcnt", __func__, igi);
		/* NOTREACHED */
	}
	if (!locked)
		IGI_UNLOCK(igi);
}

void
igi_remref(struct igmp_ifinfo *igi)
{
	SLIST_HEAD(, in_multi) inm_dthead;
	struct ifnet *ifp;

	IGI_LOCK_SPIN(igi);

	if (igi->igi_refcnt == 0) {
		panic("%s: igi=%p negative refcnt", __func__, igi);
		/* NOTREACHED */
	}

	--igi->igi_refcnt;
	if (igi->igi_refcnt > 0) {
		IGI_UNLOCK(igi);
		return;
	}

	ifp = igi->igi_ifp;
	igi->igi_ifp = NULL;
	IF_DRAIN(&igi->igi_gq);
	IF_DRAIN(&igi->igi_v2q);
	SLIST_INIT(&inm_dthead);
	igmp_flush_relq(igi, (struct igmp_inm_relhead *)&inm_dthead);
	VERIFY(SLIST_EMPTY(&igi->igi_relinmhead));
	IGI_UNLOCK(igi);

	/* Now that we're dropped all locks, release detached records */
	IGMP_REMOVE_DETACHED_INM(&inm_dthead);

	IGMP_PRINTF(("%s: freeing igmp_ifinfo for ifp 0x%llx(%s)\n",
	    __func__, (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));

	igi_free(igi);
}

/*
 * Process a received IGMPv1 query.
 * Return non-zero if the message should be dropped.
 */
static int
igmp_input_v1_query(struct ifnet *ifp, const struct ip *ip,
    const struct igmp *igmp)
{
	struct igmp_ifinfo	*igi;
	struct in_multi		*inm;
	struct in_multistep	step;
	struct igmp_tparams	itp = { 0, 0, 0, 0 };

	IGMP_LOCK_ASSERT_NOTHELD();

	/*
	 * IGMPv1 Host Membership Queries SHOULD always be addressed to
	 * 224.0.0.1. They are always treated as General Queries.
	 * igmp_group is always ignored. Do not drop it as a userland
	 * daemon may wish to see it.
	 */
	if (!in_allhosts(ip->ip_dst) || !in_nullhost(igmp->igmp_group)) {
		IGMPSTAT_INC(igps_rcv_badqueries);
		OIGMPSTAT_INC(igps_rcv_badqueries);
		goto done;
	}
	IGMPSTAT_INC(igps_rcv_gen_queries);

	igi = IGMP_IFINFO(ifp);
	VERIFY(igi != NULL);

	IGI_LOCK(igi);
	if (igi->igi_flags & IGIF_LOOPBACK) {
		IGMP_PRINTF(("%s: ignore v1 query on IGIF_LOOPBACK "
		    "ifp 0x%llx(%s)\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		IGI_UNLOCK(igi);
		goto done;
	}
	/*
	 * Switch to IGMPv1 host compatibility mode.
	 */
	itp.qpt = igmp_set_version(igi, IGMP_VERSION_1);
	IGI_UNLOCK(igi);

	IGMP_PRINTF(("%s: process v1 query on ifp 0x%llx(%s)\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));

	/*
	 * Start the timers in all of our group records
	 * for the interface on which the query arrived,
	 * except those which are already running.
	 */
	in_multihead_lock_shared();
	IN_FIRST_MULTI(step, inm);
	while (inm != NULL) {
		INM_LOCK(inm);
		if (inm->inm_ifp != ifp || inm->inm_timer != 0)
			goto next;

		switch (inm->inm_state) {
		case IGMP_NOT_MEMBER:
		case IGMP_SILENT_MEMBER:
			break;
		case IGMP_G_QUERY_PENDING_MEMBER:
		case IGMP_SG_QUERY_PENDING_MEMBER:
		case IGMP_REPORTING_MEMBER:
		case IGMP_IDLE_MEMBER:
		case IGMP_LAZY_MEMBER:
		case IGMP_SLEEPING_MEMBER:
		case IGMP_AWAKENING_MEMBER:
			inm->inm_state = IGMP_REPORTING_MEMBER;
			inm->inm_timer = IGMP_RANDOM_DELAY(IGMP_V1V2_MAX_RI);
			itp.cst = 1;
			break;
		case IGMP_LEAVING_MEMBER:
			break;
		}
next:
		INM_UNLOCK(inm);
		IN_NEXT_MULTI(step, inm);
	}
	in_multihead_lock_done();
done:
	igmp_set_timeout(&itp);

	return (0);
}

/*
 * Process a received IGMPv2 general or group-specific query.
 */
static int
igmp_input_v2_query(struct ifnet *ifp, const struct ip *ip,
    const struct igmp *igmp)
{
	struct igmp_ifinfo	*igi;
	struct in_multi		*inm;
	int			 is_general_query;
	uint16_t		 timer;
	struct igmp_tparams	 itp = { 0, 0, 0, 0 };

	IGMP_LOCK_ASSERT_NOTHELD();

	is_general_query = 0;

	/*
	 * Validate address fields upfront.
	 */
	if (in_nullhost(igmp->igmp_group)) {
		/*
		 * IGMPv2 General Query.
		 * If this was not sent to the all-hosts group, ignore it.
		 */
		if (!in_allhosts(ip->ip_dst))
			goto done;
		IGMPSTAT_INC(igps_rcv_gen_queries);
		is_general_query = 1;
	} else {
		/* IGMPv2 Group-Specific Query. */
		IGMPSTAT_INC(igps_rcv_group_queries);
	}

	igi = IGMP_IFINFO(ifp);
	VERIFY(igi != NULL);

	IGI_LOCK(igi);
	if (igi->igi_flags & IGIF_LOOPBACK) {
		IGMP_PRINTF(("%s: ignore v2 query on IGIF_LOOPBACK "
		    "ifp 0x%llx(%s)\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		IGI_UNLOCK(igi);
		goto done;
	}
	/*
	 * Ignore v2 query if in v1 Compatibility Mode.
	 */
	if (igi->igi_version == IGMP_VERSION_1) {
		IGI_UNLOCK(igi);
		goto done;
	}
	itp.qpt = igmp_set_version(igi, IGMP_VERSION_2);
	IGI_UNLOCK(igi);

	timer = igmp->igmp_code / IGMP_TIMER_SCALE;
	if (timer == 0)
		timer = 1;

	if (is_general_query) {
		struct in_multistep step;

		IGMP_PRINTF(("%s: process v2 general query on ifp 0x%llx(%s)\n",
		    __func__, (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		/*
		 * For each reporting group joined on this
		 * interface, kick the report timer.
		 */
		in_multihead_lock_shared();
		IN_FIRST_MULTI(step, inm);
		while (inm != NULL) {
			INM_LOCK(inm);
			if (inm->inm_ifp == ifp)
				itp.cst += igmp_v2_update_group(inm, timer);
			INM_UNLOCK(inm);
			IN_NEXT_MULTI(step, inm);
		}
		in_multihead_lock_done();
	} else {
		/*
		 * Group-specific IGMPv2 query, we need only
		 * look up the single group to process it.
		 */
		in_multihead_lock_shared();
		IN_LOOKUP_MULTI(&igmp->igmp_group, ifp, inm);
		in_multihead_lock_done();
		if (inm != NULL) {
			INM_LOCK(inm);
			IGMP_INET_PRINTF(igmp->igmp_group,
			    ("process v2 query %s on ifp 0x%llx(%s)\n",
			    _igmp_inet_buf,
			    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
			itp.cst = igmp_v2_update_group(inm, timer);
			INM_UNLOCK(inm);
			INM_REMREF(inm); /* from IN_LOOKUP_MULTI */
		}
	}
done:
	igmp_set_timeout(&itp);

	return (0);
}

/*
 * Update the report timer on a group in response to an IGMPv2 query.
 *
 * If we are becoming the reporting member for this group, start the timer.
 * If we already are the reporting member for this group, and timer is
 * below the threshold, reset it.
 *
 * We may be updating the group for the first time since we switched
 * to IGMPv3. If we are, then we must clear any recorded source lists,
 * and transition to REPORTING state; the group timer is overloaded
 * for group and group-source query responses. 
 *
 * Unlike IGMPv3, the delay per group should be jittered
 * to avoid bursts of IGMPv2 reports.
 */
static uint32_t
igmp_v2_update_group(struct in_multi *inm, const int timer)
{

	IGMP_INET_PRINTF(inm->inm_addr, ("%s: %s/%s timer=%d\n",
	    __func__, _igmp_inet_buf, if_name(inm->inm_ifp),
	    timer));

	INM_LOCK_ASSERT_HELD(inm);

	switch (inm->inm_state) {
	case IGMP_NOT_MEMBER:
	case IGMP_SILENT_MEMBER:
		break;
	case IGMP_REPORTING_MEMBER:
		if (inm->inm_timer != 0 &&
		    inm->inm_timer <= timer) {
			IGMP_PRINTF(("%s: REPORTING and timer running, "
			    "skipping.\n", __func__));
			break;
		}
		/* FALLTHROUGH */
	case IGMP_SG_QUERY_PENDING_MEMBER:
	case IGMP_G_QUERY_PENDING_MEMBER:
	case IGMP_IDLE_MEMBER:
	case IGMP_LAZY_MEMBER:
	case IGMP_AWAKENING_MEMBER:
		IGMP_PRINTF(("%s: ->REPORTING\n", __func__));
		inm->inm_state = IGMP_REPORTING_MEMBER;
		inm->inm_timer = IGMP_RANDOM_DELAY(timer);
		break;
	case IGMP_SLEEPING_MEMBER:
		IGMP_PRINTF(("%s: ->AWAKENING\n", __func__));
		inm->inm_state = IGMP_AWAKENING_MEMBER;
		break;
	case IGMP_LEAVING_MEMBER:
		break;
	}

	return (inm->inm_timer);
}

/*
 * Process a received IGMPv3 general, group-specific or
 * group-and-source-specific query.
 * Assumes m has already been pulled up to the full IGMP message length.
 * Return 0 if successful, otherwise an appropriate error code is returned.
 */
static int
igmp_input_v3_query(struct ifnet *ifp, const struct ip *ip,
    /*const*/ struct igmpv3 *igmpv3)
{
	struct igmp_ifinfo	*igi;
	struct in_multi		*inm;
	int			 is_general_query;
	uint32_t		 maxresp, nsrc, qqi;
	uint16_t		 timer;
	uint8_t			 qrv;
	struct igmp_tparams	 itp = { 0, 0, 0, 0 };

	IGMP_LOCK_ASSERT_NOTHELD();

	is_general_query = 0;

	IGMP_PRINTF(("%s: process v3 query on ifp 0x%llx(%s)\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));

	maxresp = igmpv3->igmp_code;	/* in 1/10ths of a second */
	if (maxresp >= 128) {
		maxresp = IGMP_MANT(igmpv3->igmp_code) <<
			  (IGMP_EXP(igmpv3->igmp_code) + 3);
	}

	/*
	 * Robustness must never be less than 2 for on-wire IGMPv3.
	 * FUTURE: Check if ifp has IGIF_LOOPBACK set, as we will make
	 * an exception for interfaces whose IGMPv3 state changes
	 * are redirected to loopback (e.g. MANET).
	 */
	qrv = IGMP_QRV(igmpv3->igmp_misc);
	if (qrv < 2) {
		IGMP_PRINTF(("%s: clamping qrv %d to %d\n", __func__,
		    qrv, IGMP_RV_INIT));
		qrv = IGMP_RV_INIT;
	}

	qqi = igmpv3->igmp_qqi;
	if (qqi >= 128) {
		qqi = IGMP_MANT(igmpv3->igmp_qqi) <<
		     (IGMP_EXP(igmpv3->igmp_qqi) + 3);
	}

	timer = maxresp / IGMP_TIMER_SCALE;
	if (timer == 0)
		timer = 1;

	nsrc = ntohs(igmpv3->igmp_numsrc);

	/*
	 * Validate address fields and versions upfront before
	 * accepting v3 query.
	 */
	if (in_nullhost(igmpv3->igmp_group)) {
		/*
		 * IGMPv3 General Query.
		 *
		 * General Queries SHOULD be directed to 224.0.0.1.
		 * A general query with a source list has undefined
		 * behaviour; discard it.
		 */
		IGMPSTAT_INC(igps_rcv_gen_queries);
		if (!in_allhosts(ip->ip_dst) || nsrc > 0) {
			IGMPSTAT_INC(igps_rcv_badqueries);
			OIGMPSTAT_INC(igps_rcv_badqueries);
			goto done;
		}
		is_general_query = 1;
	} else {
		/* Group or group-source specific query. */
		if (nsrc == 0)
			IGMPSTAT_INC(igps_rcv_group_queries);
		else
			IGMPSTAT_INC(igps_rcv_gsr_queries);
	}

	igi = IGMP_IFINFO(ifp);
	VERIFY(igi != NULL);

	IGI_LOCK(igi);
	if (igi->igi_flags & IGIF_LOOPBACK) {
		IGMP_PRINTF(("%s: ignore v3 query on IGIF_LOOPBACK "
		    "ifp 0x%llx(%s)\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		IGI_UNLOCK(igi);
		goto done;
	}

	/*
	 * Discard the v3 query if we're in Compatibility Mode.
	 * The RFC is not obviously worded that hosts need to stay in
	 * compatibility mode until the Old Version Querier Present
	 * timer expires.
	 */
	if (igi->igi_version != IGMP_VERSION_3) {
		IGMP_PRINTF(("%s: ignore v3 query in v%d mode on "
		    "ifp 0x%llx(%s)\n", __func__, igi->igi_version,
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		IGI_UNLOCK(igi);
		goto done;
	}

	itp.qpt = igmp_set_version(igi, IGMP_VERSION_3);
	igi->igi_rv = qrv;
	igi->igi_qi = qqi;
	igi->igi_qri = MAX(timer, IGMP_QRI_MIN);

	IGMP_PRINTF(("%s: qrv %d qi %d qri %d\n", __func__, igi->igi_rv,
	    igi->igi_qi, igi->igi_qri));

	if (is_general_query) {
		/*
		 * Schedule a current-state report on this ifp for
		 * all groups, possibly containing source lists.
		 * If there is a pending General Query response
		 * scheduled earlier than the selected delay, do
		 * not schedule any other reports.
		 * Otherwise, reset the interface timer.
		 */
		IGMP_PRINTF(("%s: process v3 general query on ifp 0x%llx(%s)\n",
		    __func__, (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		if (igi->igi_v3_timer == 0 || igi->igi_v3_timer >= timer) {
			itp.it = igi->igi_v3_timer = IGMP_RANDOM_DELAY(timer);
		}
		IGI_UNLOCK(igi);
	} else {
		IGI_UNLOCK(igi);
		/*
		 * Group-source-specific queries are throttled on
		 * a per-group basis to defeat denial-of-service attempts.
		 * Queries for groups we are not a member of on this
		 * link are simply ignored.
		 */
		in_multihead_lock_shared();
		IN_LOOKUP_MULTI(&igmpv3->igmp_group, ifp, inm);
		in_multihead_lock_done();
		if (inm == NULL)
			goto done;

		INM_LOCK(inm);
		if (nsrc > 0) {
			if (!ratecheck(&inm->inm_lastgsrtv,
			    &igmp_gsrdelay)) {
				IGMP_PRINTF(("%s: GS query throttled.\n",
				    __func__));
				IGMPSTAT_INC(igps_drop_gsr_queries);
				INM_UNLOCK(inm);
				INM_REMREF(inm); /* from IN_LOOKUP_MULTI */
				goto done;
			}
		}
		IGMP_INET_PRINTF(igmpv3->igmp_group,
		    ("process v3 %s query on ifp 0x%llx(%s)\n", _igmp_inet_buf,
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		/*
		 * If there is a pending General Query response
		 * scheduled sooner than the selected delay, no
		 * further report need be scheduled.
		 * Otherwise, prepare to respond to the
		 * group-specific or group-and-source query.
		 */
		IGI_LOCK(igi);
		itp.it = igi->igi_v3_timer;
		IGI_UNLOCK(igi);
		if (itp.it == 0 || itp.it >= timer) {
			(void) igmp_input_v3_group_query(inm, timer, igmpv3);
			itp.cst = inm->inm_timer;
		}
		INM_UNLOCK(inm);
		INM_REMREF(inm); /* from IN_LOOKUP_MULTI */
	}
done:
	if (itp.it > 0) {
		IGMP_PRINTF(("%s: v3 general query response scheduled in "
		    "T+%d seconds on ifp 0x%llx(%s)\n", __func__, itp.it,
		    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
	}
	igmp_set_timeout(&itp);

	return (0);
}

/*
 * Process a recieved IGMPv3 group-specific or group-and-source-specific
 * query.
 * Return <0 if any error occured. Currently this is ignored.
 */
static int
igmp_input_v3_group_query(struct in_multi *inm,
    int timer, /*const*/ struct igmpv3 *igmpv3)
{
	int			 retval;
	uint16_t		 nsrc;

	INM_LOCK_ASSERT_HELD(inm);

	retval = 0;

	switch (inm->inm_state) {
	case IGMP_NOT_MEMBER:
	case IGMP_SILENT_MEMBER:
	case IGMP_SLEEPING_MEMBER:
	case IGMP_LAZY_MEMBER:
	case IGMP_AWAKENING_MEMBER:
	case IGMP_IDLE_MEMBER:
	case IGMP_LEAVING_MEMBER:
		return (retval);
	case IGMP_REPORTING_MEMBER:
	case IGMP_G_QUERY_PENDING_MEMBER:
	case IGMP_SG_QUERY_PENDING_MEMBER:
		break;
	}

	nsrc = ntohs(igmpv3->igmp_numsrc);

	/*
	 * Deal with group-specific queries upfront.
	 * If any group query is already pending, purge any recorded
	 * source-list state if it exists, and schedule a query response
	 * for this group-specific query.
	 */
	if (nsrc == 0) {
		if (inm->inm_state == IGMP_G_QUERY_PENDING_MEMBER ||
		    inm->inm_state == IGMP_SG_QUERY_PENDING_MEMBER) {
			inm_clear_recorded(inm);
			timer = min(inm->inm_timer, timer);
		}
		inm->inm_state = IGMP_G_QUERY_PENDING_MEMBER;
		inm->inm_timer = IGMP_RANDOM_DELAY(timer);
		return (retval);
	}

	/*
	 * Deal with the case where a group-and-source-specific query has
	 * been received but a group-specific query is already pending.
	 */
	if (inm->inm_state == IGMP_G_QUERY_PENDING_MEMBER) {
		timer = min(inm->inm_timer, timer);
		inm->inm_timer = IGMP_RANDOM_DELAY(timer);
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
	 * FIXME: Handling source lists larger than 1 mbuf requires that
	 * we pass the mbuf chain pointer down to this function, and use
	 * m_getptr() to walk the chain.
	 */
	if (inm->inm_nsrc > 0) {
		const struct in_addr	*ap;
		int			 i, nrecorded;

		ap = (const struct in_addr *)(igmpv3 + 1);
		nrecorded = 0;
		for (i = 0; i < nsrc; i++, ap++) {
			retval = inm_record_source(inm, ap->s_addr);
			if (retval < 0)
				break;
			nrecorded += retval;
		}
		if (nrecorded > 0) {
			IGMP_PRINTF(("%s: schedule response to SG query\n",
			    __func__));
			inm->inm_state = IGMP_SG_QUERY_PENDING_MEMBER;
			inm->inm_timer = IGMP_RANDOM_DELAY(timer);
		}
	}

	return (retval);
}

/*
 * Process a received IGMPv1 host membership report.
 *
 * NOTE: 0.0.0.0 workaround breaks const correctness.
 */
static int
igmp_input_v1_report(struct ifnet *ifp, struct mbuf *m, /*const*/ struct ip *ip,
    /*const*/ struct igmp *igmp)
{
	struct in_ifaddr *ia;
	struct in_multi *inm;

	IGMPSTAT_INC(igps_rcv_reports);
	OIGMPSTAT_INC(igps_rcv_reports);

	if ((ifp->if_flags & IFF_LOOPBACK) ||
	    (m->m_pkthdr.pkt_flags & PKTF_LOOP))
		return (0);

	if (!IN_MULTICAST(ntohl(igmp->igmp_group.s_addr) ||
	    !in_hosteq(igmp->igmp_group, ip->ip_dst))) {
		IGMPSTAT_INC(igps_rcv_badreports);
		OIGMPSTAT_INC(igps_rcv_badreports);
		return (EINVAL);
	}

	/*
	 * RFC 3376, Section 4.2.13, 9.2, 9.3:
	 * Booting clients may use the source address 0.0.0.0. Some
	 * IGMP daemons may not know how to use IP_RECVIF to determine
	 * the interface upon which this message was received.
	 * Replace 0.0.0.0 with the subnet address if told to do so.
	 */
	if (igmp_recvifkludge && in_nullhost(ip->ip_src)) {
		IFP_TO_IA(ifp, ia);
		if (ia != NULL) {
			IFA_LOCK(&ia->ia_ifa);
			ip->ip_src.s_addr = htonl(ia->ia_subnet);
			IFA_UNLOCK(&ia->ia_ifa);
			IFA_REMREF(&ia->ia_ifa);
		}
	}

	IGMP_INET_PRINTF(igmp->igmp_group,
	    ("process v1 report %s on ifp 0x%llx(%s)\n", _igmp_inet_buf,
	    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));

	/*
	 * IGMPv1 report suppression.
	 * If we are a member of this group, and our membership should be
	 * reported, stop our group timer and transition to the 'lazy' state.
	 */
	in_multihead_lock_shared();
	IN_LOOKUP_MULTI(&igmp->igmp_group, ifp, inm);
	in_multihead_lock_done();
	if (inm != NULL) {
		struct igmp_ifinfo *igi;

		INM_LOCK(inm);

		igi = inm->inm_igi;
		VERIFY(igi != NULL);

		IGMPSTAT_INC(igps_rcv_ourreports);
		OIGMPSTAT_INC(igps_rcv_ourreports);

		/*
		 * If we are in IGMPv3 host mode, do not allow the
		 * other host's IGMPv1 report to suppress our reports
		 * unless explicitly configured to do so.
		 */
		IGI_LOCK(igi);
		if (igi->igi_version == IGMP_VERSION_3) {
			if (igmp_legacysupp)
				igmp_v3_suppress_group_record(inm);
			IGI_UNLOCK(igi);
			INM_UNLOCK(inm);
			INM_REMREF(inm); /* from IN_LOOKUP_MULTI */
			return (0);
		}

		INM_LOCK_ASSERT_HELD(inm);
		inm->inm_timer = 0;

		switch (inm->inm_state) {
		case IGMP_NOT_MEMBER:
		case IGMP_SILENT_MEMBER:
			break;
		case IGMP_IDLE_MEMBER:
		case IGMP_LAZY_MEMBER:
		case IGMP_AWAKENING_MEMBER:
			IGMP_INET_PRINTF(igmp->igmp_group,
			    ("report suppressed for %s on ifp 0x%llx(%s)\n",
			    _igmp_inet_buf,
			    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
		case IGMP_SLEEPING_MEMBER:
			inm->inm_state = IGMP_SLEEPING_MEMBER;
			break;
		case IGMP_REPORTING_MEMBER:
			IGMP_INET_PRINTF(igmp->igmp_group,
			    ("report suppressed for %s on ifp 0x%llx(%s)\n",
			    _igmp_inet_buf,
			    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));
			if (igi->igi_version == IGMP_VERSION_1)
				inm->inm_state = IGMP_LAZY_MEMBER;
			else if (igi->igi_version == IGMP_VERSION_2)
				inm->inm_state = IGMP_SLEEPING_MEMBER;
			break;
		case IGMP_G_QUERY_PENDING_MEMBER:
		case IGMP_SG_QUERY_PENDING_MEMBER:
		case IGMP_LEAVING_MEMBER:
			break;
		}
		IGI_UNLOCK(igi);
		INM_UNLOCK(inm);
		INM_REMREF(inm); /* from IN_LOOKUP_MULTI */
	}

	return (0);
}

/*
 * Process a received IGMPv2 host membership report.
 *
 * NOTE: 0.0.0.0 workaround breaks const correctness.
 */
static int
igmp_input_v2_report(struct ifnet *ifp, struct mbuf *m, /*const*/ struct ip *ip,
    /*const*/ struct igmp *igmp)
{
	struct in_ifaddr *ia;
	struct in_multi *inm;

	/*
	 * Make sure we don't hear our own membership report.  Fast
	 * leave requires knowing that we are the only member of a
	 * group.
	 */
	IFP_TO_IA(ifp, ia);
	if (ia != NULL) {
		IFA_LOCK(&ia->ia_ifa);
		if (in_hosteq(ip->ip_src, IA_SIN(ia)->sin_addr)) {
			IFA_UNLOCK(&ia->ia_ifa);
			IFA_REMREF(&ia->ia_ifa);
			return (0);
		}
		IFA_UNLOCK(&ia->ia_ifa);
	}

	IGMPSTAT_INC(igps_rcv_reports);
	OIGMPSTAT_INC(igps_rcv_reports);

	if ((ifp->if_flags & IFF_LOOPBACK) ||
	    (m->m_pkthdr.pkt_flags & PKTF_LOOP)) {
		if (ia != NULL)
			IFA_REMREF(&ia->ia_ifa);
		return (0);
	}

	if (!IN_MULTICAST(ntohl(igmp->igmp_group.s_addr)) ||
	    !in_hosteq(igmp->igmp_group, ip->ip_dst)) {
		if (ia != NULL)
			IFA_REMREF(&ia->ia_ifa);
		IGMPSTAT_INC(igps_rcv_badreports);
		OIGMPSTAT_INC(igps_rcv_badreports);
		return (EINVAL);
	}

	/*
	 * RFC 3376, Section 4.2.13, 9.2, 9.3:
	 * Booting clients may use the source address 0.0.0.0. Some
	 * IGMP daemons may not know how to use IP_RECVIF to determine
	 * the interface upon which this message was received.
	 * Replace 0.0.0.0 with the subnet address if told to do so.
	 */
	if (igmp_recvifkludge && in_nullhost(ip->ip_src)) {
		if (ia != NULL) {
			IFA_LOCK(&ia->ia_ifa);
			ip->ip_src.s_addr = htonl(ia->ia_subnet);
			IFA_UNLOCK(&ia->ia_ifa);
		}
	}
	if (ia != NULL)
		IFA_REMREF(&ia->ia_ifa);

	IGMP_INET_PRINTF(igmp->igmp_group,
	    ("process v2 report %s on ifp 0x%llx(%s)\n", _igmp_inet_buf,
	    (uint64_t)VM_KERNEL_ADDRPERM(ifp), if_name(ifp)));

	/*
	 * IGMPv2 report suppression.
	 * If we are a member of this group, and our membership should be
	 * reported, and our group timer is pending or about to be reset,
	 * stop our group timer by transitioning to the 'lazy' state.
	 */
	in_multihead_lock_shared();
	IN_LOOKUP_MULTI(&igmp->igmp_group, ifp, inm);
	in_multihead_lock_done();
	if (inm != NULL) {
		struct igmp_ifinfo *igi;

		INM_LOCK(inm);
		igi = inm->inm_igi;
		VERIFY(igi != NULL);

		IGMPSTAT_INC(igps_rcv_ourreports);
		OIGMPSTAT_INC(igps_rcv_ourreports);

		/*
		 * If we are in IGMPv3 host mode, do not allow the
		 * other host's IGMPv1 report to suppress our reports
		 * unless explicitly configured to do so.
		 */
		IGI_LOCK(igi);
		if (igi->igi_version == IGMP_VERSION_3) {
			if (igmp_legacysupp)
				igmp_v3_suppress_group_record(inm);
			IGI_UNLOCK(igi);
			INM_UNLOCK(inm);
			INM_REMREF(inm);
			return (0);
		}

		inm->inm_timer = 0;

		switch (inm->inm_state) {
		case IGMP_NOT_MEMBER:
		case IGMP_SILENT_MEMBER:
		case IGMP_SLEEPING_MEMBER:
			break;
		case IGMP_REPORTING_MEMBER:
		case IGMP_IDLE_MEMBER:
		case IGMP_AWAKENING_MEMBER:
			IGMP_INET_PRINTF(igmp->igmp_group,
			    ("report suppressed for %s on ifp 0x%llx(%s)\n",
			    _igmp_inet_buf, (uint64_t)VM_KERNEL_ADDRPERM(ifp),
			    if_name(ifp)));
		case IGMP_LAZY_MEMBER:
			inm->inm_state = IGMP_LAZY_MEMBER;
			break;
		case IGMP_G_QUERY_PENDING_MEMBER:
		case IGMP_SG_QUERY_PENDING_MEMBER:
		case IGMP_LEAVING_MEMBER:
			break;
		}
		IGI_UNLOCK(igi);
		INM_UNLOCK(inm);
		INM_REMREF(inm);
	}

	return (0);
}

void
igmp_input(struct mbuf *m, int off)
{
	int iphlen;
	struct ifnet *ifp;
	struct igmp *igmp;
	struct ip *ip;
	int igmplen;
	int minlen;
	int queryver;

	IGMP_PRINTF(("%s: called w/mbuf (0x%llx,%d)\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(m), off));

	ifp = m->m_pkthdr.rcvif;

	IGMPSTAT_INC(igps_rcv_total);
	OIGMPSTAT_INC(igps_rcv_total);

	/* Expect 32-bit aligned data pointer on strict-align platforms */
	MBUF_STRICT_DATA_ALIGNMENT_CHECK_32(m);

	ip = mtod(m, struct ip *);
	iphlen = off;

	/* By now, ip_len no longer contains the length of IP header */
	igmplen = ip->ip_len;

	/*
	 * Validate lengths.
	 */
	if (igmplen < IGMP_MINLEN) {
		IGMPSTAT_INC(igps_rcv_tooshort);
		OIGMPSTAT_INC(igps_rcv_tooshort);
		m_freem(m);
		return;
	}

	/*
	 * Always pullup to the minimum size for v1/v2 or v3
	 * to amortize calls to m_pulldown().
	 */
	if (igmplen >= IGMP_V3_QUERY_MINLEN)
		minlen = IGMP_V3_QUERY_MINLEN;
	else
		minlen = IGMP_MINLEN;

	/* A bit more expensive than M_STRUCT_GET, but ensures alignment */
	M_STRUCT_GET0(igmp, struct igmp *, m, off, minlen);
	if (igmp == NULL) {
		IGMPSTAT_INC(igps_rcv_tooshort);
		OIGMPSTAT_INC(igps_rcv_tooshort);
		return;
	}
	/* N.B.: we assume the packet was correctly aligned in ip_input. */

	/*
	 * Validate checksum.
	 */
	m->m_data += iphlen;
	m->m_len -= iphlen;
	if (in_cksum(m, igmplen)) {
		IGMPSTAT_INC(igps_rcv_badsum);
		OIGMPSTAT_INC(igps_rcv_badsum);
		m_freem(m);
		return;
	}
	m->m_data -= iphlen;
	m->m_len += iphlen;

	/*
	 * IGMP control traffic is link-scope, and must have a TTL of 1.
	 * DVMRP traffic (e.g. mrinfo, mtrace) is an exception;
	 * probe packets may come from beyond the LAN.
	 */
	if (igmp->igmp_type != IGMP_DVMRP && ip->ip_ttl != 1) {
		IGMPSTAT_INC(igps_rcv_badttl);
		m_freem(m);
		return;
	}

	switch (igmp->igmp_type) {
	case IGMP_HOST_MEMBERSHIP_QUERY:
		if (igmplen == IGMP_MINLEN) {
			if (igmp->igmp_code == 0)
				queryver = IGMP_VERSION_1;
			else
				queryver = IGMP_VERSION_2;
		} else if (igmplen >= IGMP_V3_QUERY_MINLEN) {
			queryver = IGMP_VERSION_3;
		} else {
			IGMPSTAT_INC(igps_rcv_tooshort);
			OIGMPSTAT_INC(igps_rcv_tooshort);
			m_freem(m);
			return;
		}

		OIGMPSTAT_INC(igps_rcv_queries);

		switch (queryver) {
		case IGMP_VERSION_1:
			IGMPSTAT_INC(igps_rcv_v1v2_queries);
			if (!igmp_v1enable)
				break;
			if (igmp_input_v1_query(ifp, ip, igmp) != 0) {
				m_freem(m);
				return;
			}
			break;

		case IGMP_VERSION_2:
			IGMPSTAT_INC(igps_rcv_v1v2_queries);
			if (!igmp_v2enable)
				break;
			if (igmp_input_v2_query(ifp, ip, igmp) != 0) {
				m_freem(m);
				return;
			}
			break;

		case IGMP_VERSION_3: {
				struct igmpv3 *igmpv3;
				uint16_t igmpv3len;
				uint16_t srclen;
				int nsrc;

				IGMPSTAT_INC(igps_rcv_v3_queries);
				igmpv3 = (struct igmpv3 *)igmp;
				/*
				 * Validate length based on source count.
				 */
				nsrc = ntohs(igmpv3->igmp_numsrc);
				srclen = sizeof(struct in_addr) * nsrc;
				if (igmplen < (IGMP_V3_QUERY_MINLEN + srclen)) {
					IGMPSTAT_INC(igps_rcv_tooshort);
					OIGMPSTAT_INC(igps_rcv_tooshort);
					m_freem(m);
					return;
				}
				igmpv3len = IGMP_V3_QUERY_MINLEN + srclen;
				/*
				 * A bit more expensive than M_STRUCT_GET,
				 * but ensures alignment.
				 */
				M_STRUCT_GET0(igmpv3, struct igmpv3 *, m,
				    off, igmpv3len);
				if (igmpv3 == NULL) {
					IGMPSTAT_INC(igps_rcv_tooshort);
					OIGMPSTAT_INC(igps_rcv_tooshort);
					return;
				}
				/* 
				 * N.B.: we assume the packet was correctly
				 * aligned in ip_input.
				 */
				if (igmp_input_v3_query(ifp, ip, igmpv3) != 0) {
					m_freem(m);
					return;
				}
			}
			break;
		}
		break;

	case IGMP_v1_HOST_MEMBERSHIP_REPORT:
		if (!igmp_v1enable)
			break;
		if (igmp_input_v1_report(ifp, m, ip, igmp) != 0) {
			m_freem(m);
			return;
		}
		break;

	case IGMP_v2_HOST_MEMBERSHIP_REPORT:
		if (!igmp_v2enable)
			break;
		if (!ip_checkrouteralert(m))
			IGMPSTAT_INC(igps_rcv_nora);
		if (igmp_input_v2_report(ifp, m, ip, igmp) != 0) {
			m_freem(m);
			return;
		}
		break;

	case IGMP_v3_HOST_MEMBERSHIP_REPORT:
		/*
		 * Hosts do not need to process IGMPv3 membership reports,
		 * as report suppression is no longer required.
		 */
		if (!ip_checkrouteralert(m))
			IGMPSTAT_INC(igps_rcv_nora);
		break;

	default:
		break;
	}

	IGMP_LOCK_ASSERT_NOTHELD();
	/*
	 * Pass all valid IGMP packets up to any process(es) listening on a
	 * raw IGMP socket.
	 */
	rip_input(m, off);
}

/*
 * Schedule IGMP timer based on various parameters; caller must ensure that
 * lock ordering is maintained as this routine acquires IGMP global lock.
 */
void
igmp_set_timeout(struct igmp_tparams *itp)
{
	IGMP_LOCK_ASSERT_NOTHELD();
	VERIFY(itp != NULL);

	if (itp->qpt != 0 || itp->it != 0 || itp->cst != 0 || itp->sct != 0) {
		IGMP_LOCK();
		if (itp->qpt != 0)
			querier_present_timers_running = 1;
		if (itp->it != 0)
			interface_timers_running = 1;
		if (itp->cst != 0)
			current_state_timers_running = 1;
		if (itp->sct != 0)
			state_change_timers_running = 1;
		igmp_sched_timeout();
		IGMP_UNLOCK();
	}
}

/*
 * IGMP timer handler (per 1 second).
 */
static void
igmp_timeout(void *arg)
{
#pragma unused(arg)
	struct ifqueue		 scq;	/* State-change packets */
	struct ifqueue		 qrq;	/* Query response packets */
	struct ifnet		*ifp;
	struct igmp_ifinfo	*igi;
	struct in_multi		*inm;
	int			 loop = 0, uri_sec = 0;
	SLIST_HEAD(, in_multi)	inm_dthead;

	SLIST_INIT(&inm_dthead);

	/*
	 * Update coarse-grained networking timestamp (in sec.); the idea
	 * is to piggy-back on the timeout callout to update the counter
	 * returnable via net_uptime().
	 */
	net_update_uptime();

	IGMP_LOCK();

	IGMP_PRINTF(("%s: qpt %d, it %d, cst %d, sct %d\n", __func__,
	    querier_present_timers_running, interface_timers_running,
	    current_state_timers_running, state_change_timers_running));

	/*
	 * IGMPv1/v2 querier present timer processing.
	 */
	if (querier_present_timers_running) {
		querier_present_timers_running = 0;
		LIST_FOREACH(igi, &igi_head, igi_link) {
			IGI_LOCK(igi);
			igmp_v1v2_process_querier_timers(igi);
			if (igi->igi_v1_timer > 0 || igi->igi_v2_timer > 0)
				querier_present_timers_running = 1;
			IGI_UNLOCK(igi);
		}
	}

	/*
	 * IGMPv3 General Query response timer processing.
	 */
	if (interface_timers_running) {
		IGMP_PRINTF(("%s: interface timers running\n", __func__));
		interface_timers_running = 0;
		LIST_FOREACH(igi, &igi_head, igi_link) {
			IGI_LOCK(igi);
			if (igi->igi_version != IGMP_VERSION_3) {
				IGI_UNLOCK(igi);
				continue;
			}
			if (igi->igi_v3_timer == 0) {
				/* Do nothing. */
			} else if (--igi->igi_v3_timer == 0) {
				if (igmp_v3_dispatch_general_query(igi) > 0)
					interface_timers_running = 1;
			} else {
				interface_timers_running = 1;
			}
			IGI_UNLOCK(igi);
		}
	}

	if (!current_state_timers_running &&
	    !state_change_timers_running)
		goto out_locked;

	current_state_timers_running = 0;
	state_change_timers_running = 0;

	memset(&qrq, 0, sizeof(struct ifqueue));
	qrq.ifq_maxlen = IGMP_MAX_G_GS_PACKETS;

	memset(&scq, 0, sizeof(struct ifqueue));
	scq.ifq_maxlen =  IGMP_MAX_STATE_CHANGE_PACKETS;

	IGMP_PRINTF(("%s: state change timers running\n", __func__));

	/*
	 * IGMPv1/v2/v3 host report and state-change timer processing.
	 * Note: Processing a v3 group timer may remove a node.
	 */
	LIST_FOREACH(igi, &igi_head, igi_link) {
		struct in_multistep step;

		IGI_LOCK(igi);
		ifp = igi->igi_ifp;
		loop = (igi->igi_flags & IGIF_LOOPBACK) ? 1 : 0;
		uri_sec = IGMP_RANDOM_DELAY(igi->igi_uri);
		IGI_UNLOCK(igi);

		in_multihead_lock_shared();
		IN_FIRST_MULTI(step, inm);
		while (inm != NULL) {
			INM_LOCK(inm);
			if (inm->inm_ifp != ifp)
				goto next;

			IGI_LOCK(igi);
			switch (igi->igi_version) {
				case IGMP_VERSION_1:
				case IGMP_VERSION_2:
					igmp_v1v2_process_group_timer(inm,
					    igi->igi_version);
					break;
				case IGMP_VERSION_3:
					igmp_v3_process_group_timers(igi, &qrq,
					    &scq, inm, uri_sec);
					break;
			}
			IGI_UNLOCK(igi);
next:
			INM_UNLOCK(inm);
			IN_NEXT_MULTI(step, inm);
		}
		in_multihead_lock_done();

		IGI_LOCK(igi);
		if (igi->igi_version == IGMP_VERSION_1 ||
		    igi->igi_version == IGMP_VERSION_2) {
			igmp_dispatch_queue(igi, &igi->igi_v2q, 0, loop);
		} else if (igi->igi_version == IGMP_VERSION_3) {
			IGI_UNLOCK(igi);
			igmp_dispatch_queue(NULL, &qrq, 0, loop);
			igmp_dispatch_queue(NULL, &scq, 0, loop);
			VERIFY(qrq.ifq_len == 0);
			VERIFY(scq.ifq_len == 0);
			IGI_LOCK(igi);
		}
		/*
		 * In case there are still any pending membership reports
		 * which didn't get drained at version change time.
		 */
		IF_DRAIN(&igi->igi_v2q);
		/*
		 * Release all deferred inm records, and drain any locally
		 * enqueued packets; do it even if the current IGMP version
		 * for the link is no longer IGMPv3, in order to handle the
		 * version change case.
		 */
		igmp_flush_relq(igi, (struct igmp_inm_relhead *)&inm_dthead);
		VERIFY(SLIST_EMPTY(&igi->igi_relinmhead));
		IGI_UNLOCK(igi);

		IF_DRAIN(&qrq);
		IF_DRAIN(&scq);
	}

out_locked:
	/* re-arm the timer if there's work to do */
	igmp_timeout_run = 0;
	igmp_sched_timeout();
	IGMP_UNLOCK();

	/* Now that we're dropped all locks, release detached records */
	IGMP_REMOVE_DETACHED_INM(&inm_dthead);
}

static void
igmp_sched_timeout(void)
{
	IGMP_LOCK_ASSERT_HELD();

	if (!igmp_timeout_run &&
	    (querier_present_timers_running || current_state_timers_running ||
	    interface_timers_running || state_change_timers_running)) {
		igmp_timeout_run = 1;
		timeout(igmp_timeout, NULL, hz);
	}
}

/*
 * Free the in_multi reference(s) for this IGMP lifecycle.
 *
 * Caller must be holding igi_lock.
 */
static void
igmp_flush_relq(struct igmp_ifinfo *igi, struct igmp_inm_relhead *inm_dthead)
{
	struct in_multi *inm;

again:
	IGI_LOCK_ASSERT_HELD(igi);
	inm = SLIST_FIRST(&igi->igi_relinmhead);
	if (inm != NULL) {
		int lastref;

		SLIST_REMOVE_HEAD(&igi->igi_relinmhead, inm_nrele);
		IGI_UNLOCK(igi);

		in_multihead_lock_exclusive();
		INM_LOCK(inm);
		VERIFY(inm->inm_nrelecnt != 0);
		inm->inm_nrelecnt--;
		lastref = in_multi_detach(inm);
		VERIFY(!lastref || (!(inm->inm_debug & IFD_ATTACHED) &&
		    inm->inm_reqcnt == 0));
		INM_UNLOCK(inm);
		in_multihead_lock_done();
		/* from igi_relinmhead */
		INM_REMREF(inm);
		/* from in_multihead list */
		if (lastref) {
			/*
			 * Defer releasing our final reference, as we
			 * are holding the IGMP lock at this point, and
			 * we could end up with locking issues later on
			 * (while issuing SIOCDELMULTI) when this is the
			 * final reference count.  Let the caller do it
			 * when it is safe.
			 */
			IGMP_ADD_DETACHED_INM(inm_dthead, inm);
		}
		IGI_LOCK(igi);
		goto again;
	}
}

/*
 * Update host report group timer for IGMPv1/v2.
 * Will update the global pending timer flags.
 */
static void
igmp_v1v2_process_group_timer(struct in_multi *inm, const int igmp_version)
{
	int report_timer_expired;

	IGMP_LOCK_ASSERT_HELD();
	INM_LOCK_ASSERT_HELD(inm);
	IGI_LOCK_ASSERT_HELD(inm->inm_igi);

	if (inm->inm_timer == 0) {
		report_timer_expired = 0;
	} else if (--inm->inm_timer == 0) {
		report_timer_expired = 1;
	} else {
		current_state_timers_running = 1;
		/* caller will schedule timer */
		return;
	}

	switch (inm->inm_state) {
	case IGMP_NOT_MEMBER:
	case IGMP_SILENT_MEMBER:
	case IGMP_IDLE_MEMBER:
	case IGMP_LAZY_MEMBER:
	case IGMP_SLEEPING_MEMBER:
	case IGMP_AWAKENING_MEMBER:
		break;
	case IGMP_REPORTING_MEMBER:
		if (report_timer_expired) {
			inm->inm_state = IGMP_IDLE_MEMBER;
			(void) igmp_v1v2_queue_report(inm,
			    (igmp_version == IGMP_VERSION_2) ?
			     IGMP_v2_HOST_MEMBERSHIP_REPORT :
			     IGMP_v1_HOST_MEMBERSHIP_REPORT);
			INM_LOCK_ASSERT_HELD(inm);
			IGI_LOCK_ASSERT_HELD(inm->inm_igi);
		}
		break;
	case IGMP_G_QUERY_PENDING_MEMBER:
	case IGMP_SG_QUERY_PENDING_MEMBER:
	case IGMP_LEAVING_MEMBER:
		break;
	}
}

/*
 * Update a group's timers for IGMPv3.
 * Will update the global pending timer flags.
 * Note: Unlocked read from igi.
 */
static void
igmp_v3_process_group_timers(struct igmp_ifinfo *igi,
    struct ifqueue *qrq, struct ifqueue *scq,
    struct in_multi *inm, const int uri_sec)
{
	int query_response_timer_expired;
	int state_change_retransmit_timer_expired;

	IGMP_LOCK_ASSERT_HELD();
	INM_LOCK_ASSERT_HELD(inm);
	IGI_LOCK_ASSERT_HELD(igi);
	VERIFY(igi == inm->inm_igi);

	query_response_timer_expired = 0;
	state_change_retransmit_timer_expired = 0;

	/*
	 * During a transition from v1/v2 compatibility mode back to v3,
	 * a group record in REPORTING state may still have its group
	 * timer active. This is a no-op in this function; it is easier
	 * to deal with it here than to complicate the timeout path.
	 */
	if (inm->inm_timer == 0) {
		query_response_timer_expired = 0;
	} else if (--inm->inm_timer == 0) {
		query_response_timer_expired = 1;
	} else {
		current_state_timers_running = 1;
		/* caller will schedule timer */
	}

	if (inm->inm_sctimer == 0) {
		state_change_retransmit_timer_expired = 0;
	} else if (--inm->inm_sctimer == 0) {
		state_change_retransmit_timer_expired = 1;
	} else {
		state_change_timers_running = 1;
		/* caller will schedule timer */
	}

	/* We are in timer callback, so be quick about it. */
	if (!state_change_retransmit_timer_expired &&
	    !query_response_timer_expired)
		return;

	switch (inm->inm_state) {
	case IGMP_NOT_MEMBER:
	case IGMP_SILENT_MEMBER:
	case IGMP_SLEEPING_MEMBER:
	case IGMP_LAZY_MEMBER:
	case IGMP_AWAKENING_MEMBER:
	case IGMP_IDLE_MEMBER:
		break;
	case IGMP_G_QUERY_PENDING_MEMBER:
	case IGMP_SG_QUERY_PENDING_MEMBER:
		/*
		 * Respond to a previously pending Group-Specific
		 * or Group-and-Source-Specific query by enqueueing
		 * the appropriate Current-State report for
		 * immediate transmission.
		 */
		if (query_response_timer_expired) {
			int retval;

			retval = igmp_v3_enqueue_group_record(qrq, inm, 0, 1,
			    (inm->inm_state == IGMP_SG_QUERY_PENDING_MEMBER));
			IGMP_PRINTF(("%s: enqueue record = %d\n",
			    __func__, retval));
			inm->inm_state = IGMP_REPORTING_MEMBER;
			/* XXX Clear recorded sources for next time. */
			inm_clear_recorded(inm);
		}
		/* FALLTHROUGH */
	case IGMP_REPORTING_MEMBER:
	case IGMP_LEAVING_MEMBER:
		if (state_change_retransmit_timer_expired) {
			/*
			 * State-change retransmission timer fired.
			 * If there are any further pending retransmissions,
			 * set the global pending state-change flag, and
			 * reset the timer.
			 */
			if (--inm->inm_scrv > 0) {
				inm->inm_sctimer = uri_sec;
				state_change_timers_running = 1;
				/* caller will schedule timer */
			}
			/*
			 * Retransmit the previously computed state-change
			 * report. If there are no further pending
			 * retransmissions, the mbuf queue will be consumed.
			 * Update T0 state to T1 as we have now sent
			 * a state-change.
			 */
			(void) igmp_v3_merge_state_changes(inm, scq);

			inm_commit(inm);
			IGMP_INET_PRINTF(inm->inm_addr,
			    ("%s: T1 -> T0 for %s/%s\n", __func__,
			    _igmp_inet_buf, if_name(inm->inm_ifp)));

			/*
			 * If we are leaving the group for good, make sure
			 * we release IGMP's reference to it.
			 * This release must be deferred using a SLIST,
			 * as we are called from a loop which traverses
			 * the in_multihead list.
			 */
			if (inm->inm_state == IGMP_LEAVING_MEMBER &&
			    inm->inm_scrv == 0) {
				inm->inm_state = IGMP_NOT_MEMBER;
				/*
				 * A reference has already been held in
				 * igmp_final_leave() for this inm, so
				 * no need to hold another one.  We also
				 * bumped up its request count then, so
				 * that it stays in in_multihead.  Both
				 * of them will be released when it is
				 * dequeued later on.
				 */
				VERIFY(inm->inm_nrelecnt != 0);
				SLIST_INSERT_HEAD(&igi->igi_relinmhead,
				    inm, inm_nrele);
			}
		}
		break;
	}
}

/*
 * Suppress a group's pending response to a group or source/group query.
 *
 * Do NOT suppress state changes. This leads to IGMPv3 inconsistency.
 * Do NOT update ST1/ST0 as this operation merely suppresses
 * the currently pending group record.
 * Do NOT suppress the response to a general query. It is possible but
 * it would require adding another state or flag.
 */
static void
igmp_v3_suppress_group_record(struct in_multi *inm)
{

	INM_LOCK_ASSERT_HELD(inm);
	IGI_LOCK_ASSERT_HELD(inm->inm_igi);

	VERIFY(inm->inm_igi->igi_version == IGMP_VERSION_3);

	if (inm->inm_state != IGMP_G_QUERY_PENDING_MEMBER ||
	    inm->inm_state != IGMP_SG_QUERY_PENDING_MEMBER)
		return;

	if (inm->inm_state == IGMP_SG_QUERY_PENDING_MEMBER)
		inm_clear_recorded(inm);

	inm->inm_timer = 0;
	inm->inm_state = IGMP_REPORTING_MEMBER;
}

/*
 * Switch to a different IGMP version on the given interface,
 * as per Section 7.2.1.
 */
static uint32_t
igmp_set_version(struct igmp_ifinfo *igi, const int igmp_version)
{
	int old_version_timer;

	IGI_LOCK_ASSERT_HELD(igi);

	IGMP_PRINTF(("%s: switching to v%d on ifp 0x%llx(%s)\n", __func__,
	    igmp_version, (uint64_t)VM_KERNEL_ADDRPERM(igi->igi_ifp),
	    if_name(igi->igi_ifp)));

	if (igmp_version == IGMP_VERSION_1 || igmp_version == IGMP_VERSION_2) {
		/*
		 * Compute the "Older Version Querier Present" timer as per
		 * Section 8.12, in seconds.
		 */
		old_version_timer = igi->igi_rv * igi->igi_qi + igi->igi_qri;

		if (igmp_version == IGMP_VERSION_1) {
			igi->igi_v1_timer = old_version_timer;
			igi->igi_v2_timer = 0;
		} else if (igmp_version == IGMP_VERSION_2) {
			igi->igi_v1_timer = 0;
			igi->igi_v2_timer = old_version_timer;
		}
	}

	if (igi->igi_v1_timer == 0 && igi->igi_v2_timer > 0) {
		if (igi->igi_version != IGMP_VERSION_2) {
			igi->igi_version = IGMP_VERSION_2;
			igmp_v3_cancel_link_timers(igi);
		}
	} else if (igi->igi_v1_timer > 0) {
		if (igi->igi_version != IGMP_VERSION_1) {
			igi->igi_version = IGMP_VERSION_1;
			igmp_v3_cancel_link_timers(igi);
		}
	}

	IGI_LOCK_ASSERT_HELD(igi);

	return (MAX(igi->igi_v1_timer, igi->igi_v2_timer));
}

/*
 * Cancel pending IGMPv3 timers for the given link and all groups
 * joined on it; state-change, general-query, and group-query timers.
 *
 * Only ever called on a transition from v3 to Compatibility mode. Kill
 * the timers stone dead (this may be expensive for large N groups), they
 * will be restarted if Compatibility Mode deems that they must be due to
 * query processing.
 */
static void
igmp_v3_cancel_link_timers(struct igmp_ifinfo *igi)
{
	struct ifnet		*ifp;
	struct in_multi		*inm;
	struct in_multistep	step;

	IGI_LOCK_ASSERT_HELD(igi);

	IGMP_PRINTF(("%s: cancel v3 timers on ifp 0x%llx(%s)\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(igi->igi_ifp), if_name(igi->igi_ifp)));

	/*
	 * Stop the v3 General Query Response on this link stone dead.
	 * If timer is woken up due to interface_timers_running,
	 * the flag will be cleared if there are no pending link timers.
	 */
	igi->igi_v3_timer = 0;

	/*
	 * Now clear the current-state and state-change report timers
	 * for all memberships scoped to this link.
	 */
	ifp = igi->igi_ifp;
	IGI_UNLOCK(igi);

	in_multihead_lock_shared();
	IN_FIRST_MULTI(step, inm);
	while (inm != NULL) {
		INM_LOCK(inm);
		if (inm->inm_ifp != ifp)
			goto next;

		switch (inm->inm_state) {
		case IGMP_NOT_MEMBER:
		case IGMP_SILENT_MEMBER:
		case IGMP_IDLE_MEMBER:
		case IGMP_LAZY_MEMBER:
		case IGMP_SLEEPING_MEMBER:
		case IGMP_AWAKENING_MEMBER:
			/*
			 * These states are either not relevant in v3 mode,
			 * or are unreported. Do nothing.
			 */
			break;
		case IGMP_LEAVING_MEMBER:
			/*
			 * If we are leaving the group and switching to
			 * compatibility mode, we need to release the final
			 * reference held for issuing the INCLUDE {}, and
			 * transition to REPORTING to ensure the host leave
			 * message is sent upstream to the old querier --
			 * transition to NOT would lose the leave and race.
			 * During igmp_final_leave(), we bumped up both the
			 * request and reference counts.  Since we cannot
			 * call in_multi_detach() here, defer this task to
			 * the timer routine.
			 */
			VERIFY(inm->inm_nrelecnt != 0);
			IGI_LOCK(igi);
			SLIST_INSERT_HEAD(&igi->igi_relinmhead, inm, inm_nrele);
			IGI_UNLOCK(igi);
			/* FALLTHROUGH */
		case IGMP_G_QUERY_PENDING_MEMBER:
		case IGMP_SG_QUERY_PENDING_MEMBER:
			inm_clear_recorded(inm);
			/* FALLTHROUGH */
		case IGMP_REPORTING_MEMBER:
			inm->inm_state = IGMP_REPORTING_MEMBER;
			break;
		}
		/*
		 * Always clear state-change and group report timers.
		 * Free any pending IGMPv3 state-change records.
		 */
		inm->inm_sctimer = 0;
		inm->inm_timer = 0;
		IF_DRAIN(&inm->inm_scq);
next:
		INM_UNLOCK(inm);
		IN_NEXT_MULTI(step, inm);
	}
	in_multihead_lock_done();

	IGI_LOCK(igi);
}

/*
 * Update the Older Version Querier Present timers for a link.
 * See Section 7.2.1 of RFC 3376.
 */
static void
igmp_v1v2_process_querier_timers(struct igmp_ifinfo *igi)
{
	IGI_LOCK_ASSERT_HELD(igi);

	if (igi->igi_v1_timer == 0 && igi->igi_v2_timer == 0) {
		/*
		 * IGMPv1 and IGMPv2 Querier Present timers expired.
		 *
		 * Revert to IGMPv3.
		 */
		if (igi->igi_version != IGMP_VERSION_3) {
			IGMP_PRINTF(("%s: transition from v%d -> v%d "
			    "on 0x%llx(%s)\n", __func__,
			    igi->igi_version, IGMP_VERSION_3,
			    (uint64_t)VM_KERNEL_ADDRPERM(igi->igi_ifp),
			    if_name(igi->igi_ifp)));
			igi->igi_version = IGMP_VERSION_3;
			IF_DRAIN(&igi->igi_v2q);
		}
	} else if (igi->igi_v1_timer == 0 && igi->igi_v2_timer > 0) {
		/*
		 * IGMPv1 Querier Present timer expired,
		 * IGMPv2 Querier Present timer running.
		 * If IGMPv2 was disabled since last timeout,
		 * revert to IGMPv3.
		 * If IGMPv2 is enabled, revert to IGMPv2.
		 */
		if (!igmp_v2enable) {
			IGMP_PRINTF(("%s: transition from v%d -> v%d "
			    "on 0x%llx(%s%d)\n", __func__,
			    igi->igi_version, IGMP_VERSION_3,
			    (uint64_t)VM_KERNEL_ADDRPERM(igi->igi_ifp),
			    igi->igi_ifp->if_name, igi->igi_ifp->if_unit));
			igi->igi_v2_timer = 0;
			igi->igi_version = IGMP_VERSION_3;
			IF_DRAIN(&igi->igi_v2q);
		} else {
			--igi->igi_v2_timer;
			if (igi->igi_version != IGMP_VERSION_2) {
				IGMP_PRINTF(("%s: transition from v%d -> v%d "
				    "on 0x%llx(%s)\n", __func__,
				    igi->igi_version, IGMP_VERSION_2,
				    (uint64_t)VM_KERNEL_ADDRPERM(igi->igi_ifp),
				    if_name(igi->igi_ifp)));
				igi->igi_version = IGMP_VERSION_2;
				IF_DRAIN(&igi->igi_gq);
				igmp_v3_cancel_link_timers(igi);
			}
		}
	} else if (igi->igi_v1_timer > 0) {
		/*
		 * IGMPv1 Querier Present timer running.
		 * Stop IGMPv2 timer if running.
		 *
		 * If IGMPv1 was disabled since last timeout,
		 * revert to IGMPv3.
		 * If IGMPv1 is enabled, reset IGMPv2 timer if running.
		 */
		if (!igmp_v1enable) {
			IGMP_PRINTF(("%s: transition from v%d -> v%d "
			    "on 0x%llx(%s%d)\n", __func__,
			    igi->igi_version, IGMP_VERSION_3,
			    (uint64_t)VM_KERNEL_ADDRPERM(igi->igi_ifp),
			    igi->igi_ifp->if_name, igi->igi_ifp->if_unit));
			igi->igi_v1_timer = 0;
			igi->igi_version = IGMP_VERSION_3;
			IF_DRAIN(&igi->igi_v2q);
		} else {
			--igi->igi_v1_timer;
		}
		if (igi->igi_v2_timer > 0) {
			IGMP_PRINTF(("%s: cancel v2 timer on 0x%llx(%s%d)\n",
			    __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(igi->igi_ifp),
			    igi->igi_ifp->if_name, igi->igi_ifp->if_unit));
			igi->igi_v2_timer = 0;
		}
	}
}

/*
 * Dispatch an IGMPv1/v2 host report or leave message.
 * These are always small enough to fit inside a single mbuf.
 */
static int
igmp_v1v2_queue_report(struct in_multi *inm, const int type)
{
	struct ifnet		*ifp;
	struct igmp		*igmp;
	struct ip		*ip;
	struct mbuf		*m;
	int			error = 0;

	INM_LOCK_ASSERT_HELD(inm);
	IGI_LOCK_ASSERT_HELD(inm->inm_igi);

	ifp = inm->inm_ifp;

	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if (m == NULL)
		return (ENOMEM);
	MH_ALIGN(m, sizeof(struct ip) + sizeof(struct igmp));

	m->m_pkthdr.len = sizeof(struct ip) + sizeof(struct igmp);

	m->m_data += sizeof(struct ip);
	m->m_len = sizeof(struct igmp);

	igmp = mtod(m, struct igmp *);
	igmp->igmp_type = type;
	igmp->igmp_code = 0;
	igmp->igmp_group = inm->inm_addr;
	igmp->igmp_cksum = 0;
	igmp->igmp_cksum = in_cksum(m, sizeof(struct igmp));

	m->m_data -= sizeof(struct ip);
	m->m_len += sizeof(struct ip);

	ip = mtod(m, struct ip *);
	ip->ip_tos = 0;
	ip->ip_len = sizeof(struct ip) + sizeof(struct igmp);
	ip->ip_off = 0;
	ip->ip_p = IPPROTO_IGMP;
	ip->ip_src.s_addr = INADDR_ANY;

	if (type == IGMP_HOST_LEAVE_MESSAGE)
		ip->ip_dst.s_addr = htonl(INADDR_ALLRTRS_GROUP);
	else
		ip->ip_dst = inm->inm_addr;

	igmp_save_context(m, ifp);

	m->m_flags |= M_IGMPV2;
	if (inm->inm_igi->igi_flags & IGIF_LOOPBACK)
		m->m_flags |= M_IGMP_LOOP;

	/*
	 * Due to the fact that at this point we are possibly holding
	 * in_multihead_lock in shared or exclusive mode, we can't call
	 * igmp_sendpkt() here since that will eventually call ip_output(),
	 * which will try to lock in_multihead_lock and cause a deadlock.
	 * Instead we defer the work to the igmp_timeout() thread, thus
	 * avoiding unlocking in_multihead_lock here.
	 */
	if (IF_QFULL(&inm->inm_igi->igi_v2q)) {
		IGMP_PRINTF(("%s: v1/v2 outbound queue full\n", __func__));
		error = ENOMEM;
		m_freem(m);
	} else {
		IF_ENQUEUE(&inm->inm_igi->igi_v2q, m);
		VERIFY(error == 0);
	}
	return (error);
}

/*
 * Process a state change from the upper layer for the given IPv4 group.
 *
 * Each socket holds a reference on the in_multi in its own ip_moptions.
 * The socket layer will have made the necessary updates to the group
 * state, it is now up to IGMP to issue a state change report if there
 * has been any change between T0 (when the last state-change was issued)
 * and T1 (now).
 *
 * We use the IGMPv3 state machine at group level. The IGMP module
 * however makes the decision as to which IGMP protocol version to speak.
 * A state change *from* INCLUDE {} always means an initial join.
 * A state change *to* INCLUDE {} always means a final leave.
 *
 * FUTURE: If IGIF_V3LITE is enabled for this interface, then we can
 * save ourselves a bunch of work; any exclusive mode groups need not
 * compute source filter lists.
 */
int
igmp_change_state(struct in_multi *inm, struct igmp_tparams *itp)
{
	struct igmp_ifinfo *igi;
	struct ifnet *ifp;
	int error = 0;

	VERIFY(itp != NULL);
	bzero(itp, sizeof (*itp));

	INM_LOCK_ASSERT_HELD(inm);
	VERIFY(inm->inm_igi != NULL);
	IGI_LOCK_ASSERT_NOTHELD(inm->inm_igi);

	/*
	 * Try to detect if the upper layer just asked us to change state
	 * for an interface which has now gone away.
	 */
	VERIFY(inm->inm_ifma != NULL);
	ifp = inm->inm_ifma->ifma_ifp;
	/*
	 * Sanity check that netinet's notion of ifp is the same as net's.
	 */
	VERIFY(inm->inm_ifp == ifp);

	igi = IGMP_IFINFO(ifp);
	VERIFY(igi != NULL);

	/*
	 * If we detect a state transition to or from MCAST_UNDEFINED
	 * for this group, then we are starting or finishing an IGMP
	 * life cycle for this group.
	 */
	if (inm->inm_st[1].iss_fmode != inm->inm_st[0].iss_fmode) {
		IGMP_PRINTF(("%s: inm transition %d -> %d\n", __func__,
		    inm->inm_st[0].iss_fmode, inm->inm_st[1].iss_fmode));
		if (inm->inm_st[0].iss_fmode == MCAST_UNDEFINED) {
			IGMP_PRINTF(("%s: initial join\n", __func__));
			error = igmp_initial_join(inm, igi, itp);
			goto out;
		} else if (inm->inm_st[1].iss_fmode == MCAST_UNDEFINED) {
			IGMP_PRINTF(("%s: final leave\n", __func__));
			igmp_final_leave(inm, igi, itp);
			goto out;
		}
	} else {
		IGMP_PRINTF(("%s: filter set change\n", __func__));
	}

	error = igmp_handle_state_change(inm, igi, itp);
out:
	return (error);
}

/*
 * Perform the initial join for an IGMP group.
 *
 * When joining a group:
 *  If the group should have its IGMP traffic suppressed, do nothing.
 *  IGMPv1 starts sending IGMPv1 host membership reports.
 *  IGMPv2 starts sending IGMPv2 host membership reports.
 *  IGMPv3 will schedule an IGMPv3 state-change report containing the
 *  initial state of the membership.
 */
static int
igmp_initial_join(struct in_multi *inm, struct igmp_ifinfo *igi,
    struct igmp_tparams *itp)
{
	struct ifnet		*ifp;
	struct ifqueue		*ifq;
	int			 error, retval, syncstates;

	INM_LOCK_ASSERT_HELD(inm);
	IGI_LOCK_ASSERT_NOTHELD(igi);
	VERIFY(itp != NULL);

	IGMP_INET_PRINTF(inm->inm_addr,
	    ("%s: initial join %s on ifp 0x%llx(%s)\n", __func__,
	    _igmp_inet_buf, (uint64_t)VM_KERNEL_ADDRPERM(inm->inm_ifp),
	    if_name(inm->inm_ifp)));

	error = 0;
	syncstates = 1;

	ifp = inm->inm_ifp;

	IGI_LOCK(igi);
	VERIFY(igi->igi_ifp == ifp);

	/*
	 * Groups joined on loopback or marked as 'not reported',
	 * e.g. 224.0.0.1, enter the IGMP_SILENT_MEMBER state and
	 * are never reported in any IGMP protocol exchanges.
	 * All other groups enter the appropriate IGMP state machine
	 * for the version in use on this link.
	 * A link marked as IGIF_SILENT causes IGMP to be completely
	 * disabled for the link.
	 */
	if ((ifp->if_flags & IFF_LOOPBACK) ||
	    (igi->igi_flags & IGIF_SILENT) ||
	    !igmp_isgroupreported(inm->inm_addr)) {
		IGMP_PRINTF(("%s: not kicking state machine for silent group\n",
		    __func__));
		inm->inm_state = IGMP_SILENT_MEMBER;
		inm->inm_timer = 0;
	} else {
		/*
		 * Deal with overlapping in_multi lifecycle.
		 * If this group was LEAVING, then make sure
		 * we drop the reference we picked up to keep the
		 * group around for the final INCLUDE {} enqueue.
		 * Since we cannot call in_multi_detach() here,
		 * defer this task to the timer routine.
		 */
		if (igi->igi_version == IGMP_VERSION_3 &&
		    inm->inm_state == IGMP_LEAVING_MEMBER) {
			VERIFY(inm->inm_nrelecnt != 0);
			SLIST_INSERT_HEAD(&igi->igi_relinmhead, inm, inm_nrele);
		}

		inm->inm_state = IGMP_REPORTING_MEMBER;

		switch (igi->igi_version) {
		case IGMP_VERSION_1:
		case IGMP_VERSION_2:
			inm->inm_state = IGMP_IDLE_MEMBER;
			error = igmp_v1v2_queue_report(inm,
			    (igi->igi_version == IGMP_VERSION_2) ?
			     IGMP_v2_HOST_MEMBERSHIP_REPORT :
			     IGMP_v1_HOST_MEMBERSHIP_REPORT);

			INM_LOCK_ASSERT_HELD(inm);
			IGI_LOCK_ASSERT_HELD(igi);

			if (error == 0) {
				inm->inm_timer =
				    IGMP_RANDOM_DELAY(IGMP_V1V2_MAX_RI);
				itp->cst = 1;
			}
			break;

		case IGMP_VERSION_3:
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
			ifq = &inm->inm_scq;
			IF_DRAIN(ifq);
			retval = igmp_v3_enqueue_group_record(ifq, inm, 1,
			    0, 0);
			itp->cst = (ifq->ifq_len > 0);
			IGMP_PRINTF(("%s: enqueue record = %d\n",
			    __func__, retval));
			if (retval <= 0) {
				error = retval * -1;
				break;
			}

			/*
			 * Schedule transmission of pending state-change
			 * report up to RV times for this link. The timer
			 * will fire at the next igmp_timeout (1 second),
			 * giving us an opportunity to merge the reports.
			 */
			if (igi->igi_flags & IGIF_LOOPBACK) {
				inm->inm_scrv = 1;
			} else {
				VERIFY(igi->igi_rv > 1);
				inm->inm_scrv = igi->igi_rv;
			}
			inm->inm_sctimer = 1;
			itp->sct = 1;

			error = 0;
			break;
		}
	}
	IGI_UNLOCK(igi);

	/*
	 * Only update the T0 state if state change is atomic,
	 * i.e. we don't need to wait for a timer to fire before we
	 * can consider the state change to have been communicated.
	 */
	if (syncstates) {
		inm_commit(inm);
		IGMP_INET_PRINTF(inm->inm_addr,
		    ("%s: T1 -> T0 for %s/%s\n", __func__,
		    _igmp_inet_buf, if_name(inm->inm_ifp)));
	}

	return (error);
}

/*
 * Issue an intermediate state change during the IGMP life-cycle.
 */
static int
igmp_handle_state_change(struct in_multi *inm, struct igmp_ifinfo *igi,
    struct igmp_tparams *itp)
{
	struct ifnet		*ifp;
	int			 retval = 0;

	INM_LOCK_ASSERT_HELD(inm);
	IGI_LOCK_ASSERT_NOTHELD(igi);
	VERIFY(itp != NULL);

	IGMP_INET_PRINTF(inm->inm_addr,
	    ("%s: state change for %s on ifp 0x%llx(%s)\n", __func__,
	    _igmp_inet_buf, (uint64_t)VM_KERNEL_ADDRPERM(inm->inm_ifp),
	    if_name(inm->inm_ifp)));

	ifp = inm->inm_ifp;

	IGI_LOCK(igi);
	VERIFY(igi->igi_ifp == ifp);

	if ((ifp->if_flags & IFF_LOOPBACK) ||
	    (igi->igi_flags & IGIF_SILENT) ||
	    !igmp_isgroupreported(inm->inm_addr) ||
	    (igi->igi_version != IGMP_VERSION_3)) {
		IGI_UNLOCK(igi);
		if (!igmp_isgroupreported(inm->inm_addr)) {
			IGMP_PRINTF(("%s: not kicking state "
			    "machine for silent group\n", __func__));
		}
		IGMP_PRINTF(("%s: nothing to do\n", __func__));
		inm_commit(inm);
		IGMP_INET_PRINTF(inm->inm_addr,
		    ("%s: T1 -> T0 for %s/%s\n", __func__,
		    _igmp_inet_buf, inm->inm_ifp->if_name));
		goto done;
	}

	IF_DRAIN(&inm->inm_scq);

	retval = igmp_v3_enqueue_group_record(&inm->inm_scq, inm, 1, 0, 0);
	itp->cst = (inm->inm_scq.ifq_len > 0);
	IGMP_PRINTF(("%s: enqueue record = %d\n", __func__, retval));
	if (retval <= 0) {
		IGI_UNLOCK(igi);
		retval *= -1;
		goto done;
	}
	/*
	 * If record(s) were enqueued, start the state-change
	 * report timer for this group.
	 */
	inm->inm_scrv = ((igi->igi_flags & IGIF_LOOPBACK) ? 1 : igi->igi_rv);
	inm->inm_sctimer = 1;
	itp->sct = 1;
	IGI_UNLOCK(igi);
done:
	return (retval);
}

/*
 * Perform the final leave for an IGMP group.
 *
 * When leaving a group:
 *  IGMPv1 does nothing.
 *  IGMPv2 sends a host leave message, if and only if we are the reporter.
 *  IGMPv3 enqueues a state-change report containing a transition
 *  to INCLUDE {} for immediate transmission.
 */
static void
igmp_final_leave(struct in_multi *inm, struct igmp_ifinfo *igi,
    struct igmp_tparams *itp)
{
	int syncstates = 1;

	INM_LOCK_ASSERT_HELD(inm);
	IGI_LOCK_ASSERT_NOTHELD(igi);
	VERIFY(itp != NULL);

	IGMP_INET_PRINTF(inm->inm_addr,
	    ("%s: final leave %s on ifp 0x%llx(%s)\n", __func__,
	    _igmp_inet_buf, (uint64_t)VM_KERNEL_ADDRPERM(inm->inm_ifp),
	    if_name(inm->inm_ifp)));

	switch (inm->inm_state) {
	case IGMP_NOT_MEMBER:
	case IGMP_SILENT_MEMBER:
	case IGMP_LEAVING_MEMBER:
		/* Already leaving or left; do nothing. */
		IGMP_PRINTF(("%s: not kicking state machine for silent group\n",
		    __func__));
		break;
	case IGMP_REPORTING_MEMBER:
	case IGMP_IDLE_MEMBER:
	case IGMP_G_QUERY_PENDING_MEMBER:
	case IGMP_SG_QUERY_PENDING_MEMBER:
		IGI_LOCK(igi);
		if (igi->igi_version == IGMP_VERSION_2) {
			if (inm->inm_state == IGMP_G_QUERY_PENDING_MEMBER ||
			    inm->inm_state == IGMP_SG_QUERY_PENDING_MEMBER) {
				panic("%s: IGMPv3 state reached, not IGMPv3 "
				    "mode\n", __func__);
				/* NOTREACHED */
			}
			/* scheduler timer if enqueue is successful */
			itp->cst = (igmp_v1v2_queue_report(inm,
			    IGMP_HOST_LEAVE_MESSAGE) == 0);

			INM_LOCK_ASSERT_HELD(inm);
			IGI_LOCK_ASSERT_HELD(igi);

			inm->inm_state = IGMP_NOT_MEMBER;
		} else if (igi->igi_version == IGMP_VERSION_3) {
			/*
			 * Stop group timer and all pending reports.
			 * Immediately enqueue a state-change report
			 * TO_IN {} to be sent on the next timeout,
			 * giving us an opportunity to merge reports.
			 */
			IF_DRAIN(&inm->inm_scq);
			inm->inm_timer = 0;
			if (igi->igi_flags & IGIF_LOOPBACK) {
				inm->inm_scrv = 1;
			} else {
				inm->inm_scrv = igi->igi_rv;
			}
			IGMP_INET_PRINTF(inm->inm_addr,
			    ("%s: Leaving %s/%s with %d "
			    "pending retransmissions.\n", __func__,
			    _igmp_inet_buf, if_name(inm->inm_ifp),
			    inm->inm_scrv));
			if (inm->inm_scrv == 0) {
				inm->inm_state = IGMP_NOT_MEMBER;
				inm->inm_sctimer = 0;
			} else {
				int retval;
				/*
				 * Stick around in the in_multihead list;
				 * the final detach will be issued by
				 * igmp_v3_process_group_timers() when
				 * the retransmit timer expires.
				 */
				INM_ADDREF_LOCKED(inm);
				VERIFY(inm->inm_debug & IFD_ATTACHED);
				inm->inm_reqcnt++;
				VERIFY(inm->inm_reqcnt >= 1);
				inm->inm_nrelecnt++;
				VERIFY(inm->inm_nrelecnt != 0);

				retval = igmp_v3_enqueue_group_record(
				    &inm->inm_scq, inm, 1, 0, 0);
				itp->cst = (inm->inm_scq.ifq_len > 0);
				KASSERT(retval != 0,
				    ("%s: enqueue record = %d\n", __func__,
				     retval));

				inm->inm_state = IGMP_LEAVING_MEMBER;
				inm->inm_sctimer = 1;
				itp->sct = 1;
				syncstates = 0;
			}
		}
		IGI_UNLOCK(igi);
		break;
	case IGMP_LAZY_MEMBER:
	case IGMP_SLEEPING_MEMBER:
	case IGMP_AWAKENING_MEMBER:
		/* Our reports are suppressed; do nothing. */
		break;
	}

	if (syncstates) {
		inm_commit(inm);
		IGMP_INET_PRINTF(inm->inm_addr,
		    ("%s: T1 -> T0 for %s/%s\n", __func__,
		    _igmp_inet_buf, if_name(inm->inm_ifp)));
		inm->inm_st[1].iss_fmode = MCAST_UNDEFINED;
		IGMP_INET_PRINTF(inm->inm_addr,
		    ("%s: T1 now MCAST_UNDEFINED for %s/%s\n",
		    __func__, _igmp_inet_buf, if_name(inm->inm_ifp)));
	}
}

/*
 * Enqueue an IGMPv3 group record to the given output queue.
 *
 * XXX This function could do with having the allocation code
 * split out, and the multiple-tree-walks coalesced into a single
 * routine as has been done in igmp_v3_enqueue_filter_change().
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
 * The function will attempt to allocate leading space in the packet
 * for the IP/IGMP header to be prepended without fragmenting the chain.
 *
 * If successful the size of all data appended to the queue is returned,
 * otherwise an error code less than zero is returned, or zero if
 * no record(s) were appended.
 */
static int
igmp_v3_enqueue_group_record(struct ifqueue *ifq, struct in_multi *inm,
    const int is_state_change, const int is_group_query,
    const int is_source_query)
{
	struct igmp_grouprec	 ig;
	struct igmp_grouprec	*pig;
	struct ifnet		*ifp;
	struct ip_msource	*ims, *nims;
	struct mbuf		*m0, *m, *md;
	int			 error, is_filter_list_change;
	int			 minrec0len, m0srcs, msrcs, nbytes, off;
	int			 record_has_sources;
	int			 now;
	int			 type;
	in_addr_t		 naddr;
	uint8_t			 mode;
	u_int16_t		 ig_numsrc;

	INM_LOCK_ASSERT_HELD(inm);
	IGI_LOCK_ASSERT_HELD(inm->inm_igi);

	error = 0;
	ifp = inm->inm_ifp;
	is_filter_list_change = 0;
	m = NULL;
	m0 = NULL;
	m0srcs = 0;
	msrcs = 0;
	nbytes = 0;
	nims = NULL;
	record_has_sources = 1;
	pig = NULL;
	type = IGMP_DO_NOTHING;
	mode = inm->inm_st[1].iss_fmode;

	/*
	 * If we did not transition out of ASM mode during t0->t1,
	 * and there are no source nodes to process, we can skip
	 * the generation of source records.
	 */
	if (inm->inm_st[0].iss_asm > 0 && inm->inm_st[1].iss_asm > 0 &&
	    inm->inm_nsrc == 0)
		record_has_sources = 0;

	if (is_state_change) {
		/*
		 * Queue a state change record.
		 * If the mode did not change, and there are non-ASM
		 * listeners or source filters present,
		 * we potentially need to issue two records for the group.
		 * If we are transitioning to MCAST_UNDEFINED, we need
		 * not send any sources.
		 * If there are ASM listeners, and there was no filter
		 * mode transition of any kind, do nothing.
		 */
		if (mode != inm->inm_st[0].iss_fmode) {
			if (mode == MCAST_EXCLUDE) {
				IGMP_PRINTF(("%s: change to EXCLUDE\n",
				    __func__));
				type = IGMP_CHANGE_TO_EXCLUDE_MODE;
			} else {
				IGMP_PRINTF(("%s: change to INCLUDE\n",
				    __func__));
				type = IGMP_CHANGE_TO_INCLUDE_MODE;
				if (mode == MCAST_UNDEFINED)
					record_has_sources = 0;
			}
		} else {
			if (record_has_sources) {
				is_filter_list_change = 1;
			} else {
				type = IGMP_DO_NOTHING;
			}
		}
	} else {
		/*
		 * Queue a current state record.
		 */
		if (mode == MCAST_EXCLUDE) {
			type = IGMP_MODE_IS_EXCLUDE;
		} else if (mode == MCAST_INCLUDE) {
			type = IGMP_MODE_IS_INCLUDE;
			VERIFY(inm->inm_st[1].iss_asm == 0);
		}
	}

	/*
	 * Generate the filter list changes using a separate function.
	 */
	if (is_filter_list_change)
		return (igmp_v3_enqueue_filter_change(ifq, inm));

	if (type == IGMP_DO_NOTHING) {
		IGMP_INET_PRINTF(inm->inm_addr,
		    ("%s: nothing to do for %s/%s\n",
		    __func__, _igmp_inet_buf,
		    if_name(inm->inm_ifp)));
		return (0);
	}

	/*
	 * If any sources are present, we must be able to fit at least
	 * one in the trailing space of the tail packet's mbuf,
	 * ideally more.
	 */
	minrec0len = sizeof(struct igmp_grouprec);
	if (record_has_sources)
		minrec0len += sizeof(in_addr_t);

	IGMP_INET_PRINTF(inm->inm_addr,
	    ("%s: queueing %s for %s/%s\n", __func__,
	    igmp_rec_type_to_str(type), _igmp_inet_buf,
	    if_name(inm->inm_ifp)));

	/*
	 * Check if we have a packet in the tail of the queue for this
	 * group into which the first group record for this group will fit.
	 * Otherwise allocate a new packet.
	 * Always allocate leading space for IP+RA_OPT+IGMP+REPORT.
	 * Note: Group records for G/GSR query responses MUST be sent
	 * in their own packet.
	 */
	m0 = ifq->ifq_tail;
	if (!is_group_query &&
	    m0 != NULL &&
	    (m0->m_pkthdr.vt_nrecs + 1 <= IGMP_V3_REPORT_MAXRECS) &&
	    (m0->m_pkthdr.len + minrec0len) <
	     (ifp->if_mtu - IGMP_LEADINGSPACE)) {
		m0srcs = (ifp->if_mtu - m0->m_pkthdr.len -
			    sizeof(struct igmp_grouprec)) / sizeof(in_addr_t);
		m = m0;
		IGMP_PRINTF(("%s: use existing packet\n", __func__));
	} else {
		if (IF_QFULL(ifq)) {
			IGMP_PRINTF(("%s: outbound queue full\n", __func__));
			return (-ENOMEM);
		}
		m = NULL;
		m0srcs = (ifp->if_mtu - IGMP_LEADINGSPACE -
		    sizeof(struct igmp_grouprec)) / sizeof(in_addr_t);
		if (!is_state_change && !is_group_query) {
			m = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);
			if (m)
				m->m_data += IGMP_LEADINGSPACE;
		}
		if (m == NULL) {
			m = m_gethdr(M_DONTWAIT, MT_DATA);
			if (m)
				MH_ALIGN(m, IGMP_LEADINGSPACE);
		}
		if (m == NULL)
			return (-ENOMEM);

		igmp_save_context(m, ifp);

		IGMP_PRINTF(("%s: allocated first packet\n", __func__));
	}

	/*
	 * Append group record.
	 * If we have sources, we don't know how many yet.
	 */
	ig.ig_type = type;
	ig.ig_datalen = 0;
	ig.ig_numsrc = 0;
	ig.ig_group = inm->inm_addr;
	if (!m_append(m, sizeof(struct igmp_grouprec), (void *)&ig)) {
		if (m != m0)
			m_freem(m);
		IGMP_PRINTF(("%s: m_append() failed.\n", __func__));
		return (-ENOMEM);
	}
	nbytes += sizeof(struct igmp_grouprec);

	/*
	 * Append as many sources as will fit in the first packet.
	 * If we are appending to a new packet, the chain allocation
	 * may potentially use clusters; use m_getptr() in this case.
	 * If we are appending to an existing packet, we need to obtain
	 * a pointer to the group record after m_append(), in case a new
	 * mbuf was allocated.
	 * Only append sources which are in-mode at t1. If we are
	 * transitioning to MCAST_UNDEFINED state on the group, do not
	 * include source entries.
	 * Only report recorded sources in our filter set when responding
	 * to a group-source query.
	 */
	if (record_has_sources) {
		if (m == m0) {
			md = m_last(m);
			pig = (struct igmp_grouprec *)(void *)
			    (mtod(md, uint8_t *) + md->m_len - nbytes);
		} else {
			md = m_getptr(m, 0, &off);
			pig = (struct igmp_grouprec *)(void *)
			    (mtod(md, uint8_t *) + off);
		}
		msrcs = 0;
		RB_FOREACH_SAFE(ims, ip_msource_tree, &inm->inm_srcs, nims) {
#ifdef IGMP_DEBUG
			char buf[MAX_IPv4_STR_LEN];

			inet_ntop_haddr(ims->ims_haddr, buf, sizeof(buf));
			IGMP_PRINTF(("%s: visit node %s\n", __func__, buf));
#endif
			now = ims_get_mode(inm, ims, 1);
			IGMP_PRINTF(("%s: node is %d\n", __func__, now));
			if ((now != mode) ||
			    (now == mode && mode == MCAST_UNDEFINED)) {
				IGMP_PRINTF(("%s: skip node\n", __func__));
				continue;
			}
			if (is_source_query && ims->ims_stp == 0) {
				IGMP_PRINTF(("%s: skip unrecorded node\n",
				    __func__));
				continue;
			}
			IGMP_PRINTF(("%s: append node\n", __func__));
			naddr = htonl(ims->ims_haddr);
			if (!m_append(m, sizeof(in_addr_t), (void *)&naddr)) {
				if (m != m0)
					m_freem(m);
				IGMP_PRINTF(("%s: m_append() failed.\n",
				    __func__));
				return (-ENOMEM);
			}
			nbytes += sizeof(in_addr_t);
			++msrcs;
			if (msrcs == m0srcs)
				break;
		}
		IGMP_PRINTF(("%s: msrcs is %d this packet\n", __func__,
		    msrcs));
		ig_numsrc = htons(msrcs);
		bcopy(&ig_numsrc, &pig->ig_numsrc, sizeof (ig_numsrc));
		nbytes += (msrcs * sizeof(in_addr_t));
	}

	if (is_source_query && msrcs == 0) {
		IGMP_PRINTF(("%s: no recorded sources to report\n", __func__));
		if (m != m0)
			m_freem(m);
		return (0);
	}

	/*
	 * We are good to go with first packet.
	 */
	if (m != m0) {
		IGMP_PRINTF(("%s: enqueueing first packet\n", __func__));
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
			IGMP_PRINTF(("%s: outbound queue full\n", __func__));
			return (-ENOMEM);
		}
		m = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);
		if (m)
			m->m_data += IGMP_LEADINGSPACE;
		if (m == NULL) {
			m = m_gethdr(M_DONTWAIT, MT_DATA);
			if (m)
				MH_ALIGN(m, IGMP_LEADINGSPACE);
		}
		if (m == NULL)
			return (-ENOMEM);
		igmp_save_context(m, ifp);
		md = m_getptr(m, 0, &off);
		pig = (struct igmp_grouprec *)(void *)
		    (mtod(md, uint8_t *) + off);
		IGMP_PRINTF(("%s: allocated next packet\n", __func__));

		if (!m_append(m, sizeof(struct igmp_grouprec), (void *)&ig)) {
			if (m != m0)
				m_freem(m);
			IGMP_PRINTF(("%s: m_append() failed.\n", __func__));
			return (-ENOMEM);
		}
		m->m_pkthdr.vt_nrecs = 1;
		nbytes += sizeof(struct igmp_grouprec);

		m0srcs = (ifp->if_mtu - IGMP_LEADINGSPACE -
		    sizeof(struct igmp_grouprec)) / sizeof(in_addr_t);

		msrcs = 0;
		RB_FOREACH_FROM(ims, ip_msource_tree, nims) {
#ifdef IGMP_DEBUG
			char buf[MAX_IPv4_STR_LEN];

			inet_ntop_haddr(ims->ims_haddr, buf, sizeof(buf));
			IGMP_PRINTF(("%s: visit node %s\n", __func__, buf));
#endif
			now = ims_get_mode(inm, ims, 1);
			if ((now != mode) ||
			    (now == mode && mode == MCAST_UNDEFINED)) {
				IGMP_PRINTF(("%s: skip node\n", __func__));
				continue;
			}
			if (is_source_query && ims->ims_stp == 0) {
				IGMP_PRINTF(("%s: skip unrecorded node\n",
				    __func__));
				continue;
			}
			IGMP_PRINTF(("%s: append node\n", __func__));
			naddr = htonl(ims->ims_haddr);
			if (!m_append(m, sizeof(in_addr_t), (void *)&naddr)) {
				if (m != m0)
					m_freem(m);
				IGMP_PRINTF(("%s: m_append() failed.\n",
				    __func__));
				return (-ENOMEM);
			}
			++msrcs;
			if (msrcs == m0srcs)
				break;
		}
		ig_numsrc = htons(msrcs);
		bcopy(&ig_numsrc, &pig->ig_numsrc, sizeof (ig_numsrc));
		nbytes += (msrcs * sizeof(in_addr_t));

		IGMP_PRINTF(("%s: enqueueing next packet\n", __func__));
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
 * Enqueue an IGMPv3 filter list change to the given output queue.
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
igmp_v3_enqueue_filter_change(struct ifqueue *ifq, struct in_multi *inm)
{
	static const int MINRECLEN =
	    sizeof(struct igmp_grouprec) + sizeof(in_addr_t);
	struct ifnet		*ifp;
	struct igmp_grouprec	 ig;
	struct igmp_grouprec	*pig;
	struct ip_msource	*ims, *nims;
	struct mbuf		*m, *m0, *md;
	in_addr_t		 naddr;
	int			 m0srcs, nbytes, npbytes, off, rsrcs, schanged;
	int			 nallow, nblock;
	uint8_t			 mode, now, then;
	rectype_t		 crt, drt, nrt;
	u_int16_t		 ig_numsrc;

	INM_LOCK_ASSERT_HELD(inm);

	if (inm->inm_nsrc == 0 ||
	    (inm->inm_st[0].iss_asm > 0 && inm->inm_st[1].iss_asm > 0))
		return (0);

	ifp = inm->inm_ifp;			/* interface */
	mode = inm->inm_st[1].iss_fmode;	/* filter mode at t1 */
	crt = REC_NONE;	/* current group record type */
	drt = REC_NONE;	/* mask of completed group record types */
	nrt = REC_NONE;	/* record type for current node */
	m0srcs = 0;	/* # source which will fit in current mbuf chain */
	nbytes = 0;	/* # of bytes appended to group's state-change queue */
	npbytes = 0;	/* # of bytes appended this packet */
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
			     IGMP_V3_REPORT_MAXRECS) &&
			    (m0->m_pkthdr.len + MINRECLEN) <
			     (ifp->if_mtu - IGMP_LEADINGSPACE)) {
				m = m0;
				m0srcs = (ifp->if_mtu - m0->m_pkthdr.len -
					    sizeof(struct igmp_grouprec)) /
				    sizeof(in_addr_t);
				IGMP_PRINTF(("%s: use previous packet\n",
				    __func__));
			} else {
				m = m_getcl(M_DONTWAIT, MT_DATA, M_PKTHDR);
				if (m)
					m->m_data += IGMP_LEADINGSPACE;
				if (m == NULL) {
					m = m_gethdr(M_DONTWAIT, MT_DATA);
					if (m)
						MH_ALIGN(m, IGMP_LEADINGSPACE);
				}
				if (m == NULL) {
					IGMP_PRINTF(("%s: m_get*() failed\n",
					    __func__));
					return (-ENOMEM);
				}
				m->m_pkthdr.vt_nrecs = 0;
				igmp_save_context(m, ifp);
				m0srcs = (ifp->if_mtu - IGMP_LEADINGSPACE -
				    sizeof(struct igmp_grouprec)) /
				    sizeof(in_addr_t);
				npbytes = 0;
				IGMP_PRINTF(("%s: allocated new packet\n",
				    __func__));
			}
			/*
			 * Append the IGMP group record header to the
			 * current packet's data area.
			 * Recalculate pointer to free space for next
			 * group record, in case m_append() allocated
			 * a new mbuf or cluster.
			 */
			memset(&ig, 0, sizeof(ig));
			ig.ig_group = inm->inm_addr;
			if (!m_append(m, sizeof(ig), (void *)&ig)) {
				if (m != m0)
					m_freem(m);
				IGMP_PRINTF(("%s: m_append() failed\n",
				    __func__));
				return (-ENOMEM);
			}
			npbytes += sizeof(struct igmp_grouprec);
			if (m != m0) {
				/* new packet; offset in c hain */
				md = m_getptr(m, npbytes -
				    sizeof(struct igmp_grouprec), &off);
				pig = (struct igmp_grouprec *)(void *)(mtod(md,
				    uint8_t *) + off);
			} else {
				/* current packet; offset from last append */
				md = m_last(m);
				pig = (struct igmp_grouprec *)(void *)(mtod(md,
				    uint8_t *) + md->m_len -
				    sizeof(struct igmp_grouprec));
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
			if (nims == NULL)
				nims = RB_MIN(ip_msource_tree, &inm->inm_srcs);
			RB_FOREACH_FROM(ims, ip_msource_tree, nims) {
#ifdef IGMP_DEBUG
				char buf[MAX_IPv4_STR_LEN];

				inet_ntop_haddr(ims->ims_haddr, buf, sizeof(buf));
				IGMP_PRINTF(("%s: visit node %s\n", __func__, buf));
#endif
				now = ims_get_mode(inm, ims, 1);
				then = ims_get_mode(inm, ims, 0);
				IGMP_PRINTF(("%s: mode: t0 %d, t1 %d\n",
				    __func__, then, now));
				if (now == then) {
					IGMP_PRINTF(("%s: skip unchanged\n",
					    __func__));
					continue;
				}
				if (mode == MCAST_EXCLUDE &&
				    now == MCAST_INCLUDE) {
					IGMP_PRINTF(("%s: skip IN src on EX "
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
				naddr = htonl(ims->ims_haddr);
				if (!m_append(m, sizeof(in_addr_t),
				    (void *)&naddr)) {
					if (m != m0)
						m_freem(m);
					IGMP_PRINTF(("%s: m_append() failed\n",
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
				npbytes -= sizeof(struct igmp_grouprec);
				if (m != m0) {
					IGMP_PRINTF(("%s: m_free(m)\n",
					    __func__));
					m_freem(m);
				} else {
					IGMP_PRINTF(("%s: m_adj(m, -ig)\n",
					    __func__));
					m_adj(m, -((int)sizeof(
					    struct igmp_grouprec)));
				}
				continue;
			}
			npbytes += (rsrcs * sizeof(in_addr_t));
			if (crt == REC_ALLOW)
				pig->ig_type = IGMP_ALLOW_NEW_SOURCES;
			else if (crt == REC_BLOCK)
				pig->ig_type = IGMP_BLOCK_OLD_SOURCES;
			ig_numsrc = htons(rsrcs);
			bcopy(&ig_numsrc, &pig->ig_numsrc, sizeof (ig_numsrc));
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

	IGMP_PRINTF(("%s: queued %d ALLOW_NEW, %d BLOCK_OLD\n", __func__,
	    nallow, nblock));

	return (nbytes);
}

static int
igmp_v3_merge_state_changes(struct in_multi *inm, struct ifqueue *ifscq)
{
	struct ifqueue	*gq;
	struct mbuf	*m;		/* pending state-change */
	struct mbuf	*m0;		/* copy of pending state-change */
	struct mbuf	*mt;		/* last state-change in packet */
	struct mbuf	*n;
	int		 docopy, domerge;
	u_int		 recslen;

	INM_LOCK_ASSERT_HELD(inm);

	docopy = 0;
	domerge = 0;
	recslen = 0;

	/*
	 * If there are further pending retransmissions, make a writable
	 * copy of each queued state-change message before merging.
	 */
	if (inm->inm_scrv > 0)
		docopy = 1;

	gq = &inm->inm_scq;
#ifdef IGMP_DEBUG
	if (gq->ifq_head == NULL) {
		IGMP_PRINTF(("%s: WARNING: queue for inm 0x%llx is empty\n",
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
		 * there is sufficient space to do so; an IGMPv3 report
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
			    IGMP_V3_REPORT_MAXRECS) &&
			    (mt->m_pkthdr.len + recslen <=
			    (inm->inm_ifp->if_mtu - IGMP_LEADINGSPACE)))
				domerge = 1;
		}

		if (!domerge && IF_QFULL(gq)) {
			IGMP_PRINTF(("%s: outbound queue full, skipping whole "
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
			IGMP_PRINTF(("%s: dequeueing 0x%llx\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(m)));
			n = m->m_nextpkt;
			IF_REMQUEUE(gq, m);
			m0 = m;
			m = n;
		} else {
			IGMP_PRINTF(("%s: copying 0x%llx\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(m)));
			m0 = m_dup(m, M_NOWAIT);
			if (m0 == NULL)
				return (ENOMEM);
			m0->m_nextpkt = NULL;
			m = m->m_nextpkt;
		}

		if (!domerge) {
			IGMP_PRINTF(("%s: queueing 0x%llx to ifscq 0x%llx)\n",
			    __func__, (uint64_t)VM_KERNEL_ADDRPERM(m0),
			    (uint64_t)VM_KERNEL_ADDRPERM(ifscq)));
			IF_ENQUEUE(ifscq, m0);
		} else {
			struct mbuf *mtl;	/* last mbuf of packet mt */

			IGMP_PRINTF(("%s: merging 0x%llx with ifscq tail "
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
 * Respond to a pending IGMPv3 General Query.
 */
static uint32_t
igmp_v3_dispatch_general_query(struct igmp_ifinfo *igi)
{
	struct ifnet		*ifp;
	struct in_multi		*inm;
	struct in_multistep	step;
	int			 retval, loop;

	IGI_LOCK_ASSERT_HELD(igi);

	VERIFY(igi->igi_version == IGMP_VERSION_3);

	ifp = igi->igi_ifp;
	IGI_UNLOCK(igi);

	in_multihead_lock_shared();
	IN_FIRST_MULTI(step, inm);
	while (inm != NULL) {
		INM_LOCK(inm);
		if (inm->inm_ifp != ifp)
			goto next;

		switch (inm->inm_state) {
		case IGMP_NOT_MEMBER:
		case IGMP_SILENT_MEMBER:
			break;
		case IGMP_REPORTING_MEMBER:
		case IGMP_IDLE_MEMBER:
		case IGMP_LAZY_MEMBER:
		case IGMP_SLEEPING_MEMBER:
		case IGMP_AWAKENING_MEMBER:
			inm->inm_state = IGMP_REPORTING_MEMBER;
			IGI_LOCK(igi);
			retval = igmp_v3_enqueue_group_record(&igi->igi_gq,
			    inm, 0, 0, 0);
			IGI_UNLOCK(igi);
			IGMP_PRINTF(("%s: enqueue record = %d\n",
			    __func__, retval));
			break;
		case IGMP_G_QUERY_PENDING_MEMBER:
		case IGMP_SG_QUERY_PENDING_MEMBER:
		case IGMP_LEAVING_MEMBER:
			break;
		}
next:
		INM_UNLOCK(inm);
		IN_NEXT_MULTI(step, inm);
	}
	in_multihead_lock_done();

	IGI_LOCK(igi);
	loop = (igi->igi_flags & IGIF_LOOPBACK) ? 1 : 0;
	igmp_dispatch_queue(igi, &igi->igi_gq, IGMP_MAX_RESPONSE_BURST,
	    loop);
	IGI_LOCK_ASSERT_HELD(igi);
	/*
	 * Slew transmission of bursts over 1 second intervals.
	 */
	if (igi->igi_gq.ifq_head != NULL) {
		igi->igi_v3_timer = 1 + IGMP_RANDOM_DELAY(
		    IGMP_RESPONSE_BURST_INTERVAL);
	}

	return (igi->igi_v3_timer);
}

/*
 * Transmit the next pending IGMP message in the output queue.
 *
 * Must not be called with inm_lock or igi_lock held.
 */
static void
igmp_sendpkt(struct mbuf *m)
{
	struct ip_moptions	*imo;
	struct mbuf		*ipopts, *m0;
	int			error;
	struct route		ro;
	struct ifnet		*ifp;

	IGMP_PRINTF(("%s: transmit 0x%llx\n", __func__,
	    (uint64_t)VM_KERNEL_ADDRPERM(m)));

	ifp = igmp_restore_context(m);
	/*
	 * Check if the ifnet is still attached.
	 */
	if (ifp == NULL || !ifnet_is_attached(ifp, 0)) {
		IGMP_PRINTF(("%s: dropped 0x%llx as ifp went away.\n",
		    __func__, (uint64_t)VM_KERNEL_ADDRPERM(m)));
		m_freem(m);
		OSAddAtomic(1, &ipstat.ips_noroute);
		return;
	}

	ipopts = igmp_sendra ? m_raopt : NULL;

	imo = ip_allocmoptions(M_WAITOK);
	if (imo == NULL) {
		m_freem(m);
		return;
	}

	imo->imo_multicast_ttl  = 1;
	imo->imo_multicast_vif  = -1;
	imo->imo_multicast_loop = 0;

	/*
	 * If the user requested that IGMP traffic be explicitly
	 * redirected to the loopback interface (e.g. they are running a
	 * MANET interface and the routing protocol needs to see the
	 * updates), handle this now.
	 */
	if (m->m_flags & M_IGMP_LOOP)
		imo->imo_multicast_ifp = lo_ifp;
	else
		imo->imo_multicast_ifp = ifp;

	if (m->m_flags & M_IGMPV2) {
		m0 = m;
	} else {
		m0 = igmp_v3_encap_report(ifp, m);
		if (m0 == NULL) {
			/*
			 * If igmp_v3_encap_report() failed, then M_PREPEND()
			 * already freed the original mbuf chain.
			 * This means that we don't have to m_freem(m) here.
			 */
			IGMP_PRINTF(("%s: dropped 0x%llx\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(m)));
			IMO_REMREF(imo);
			atomic_add_32(&ipstat.ips_odropped, 1);
			return;
		}
	}

	igmp_scrub_context(m0);
	m->m_flags &= ~(M_PROTOFLAGS | M_IGMP_LOOP);
	m0->m_pkthdr.rcvif = lo_ifp;
#ifdef MAC
	mac_netinet_igmp_send(ifp, m0);
#endif

	if (ifp->if_eflags & IFEF_TXSTART) {
		/*
		 * Use control service class if the interface supports
		 * transmit-start model.
		 */
		(void) m_set_service_class(m0, MBUF_SC_CTL);
	}
	bzero(&ro, sizeof (ro));
	error = ip_output(m0, ipopts, &ro, 0, imo, NULL);
	ROUTE_RELEASE(&ro);

	IMO_REMREF(imo);

	if (error) {
		IGMP_PRINTF(("%s: ip_output(0x%llx) = %d\n", __func__,
		    (uint64_t)VM_KERNEL_ADDRPERM(m0), error));
		return;
	}

	IGMPSTAT_INC(igps_snd_reports);
	OIGMPSTAT_INC(igps_snd_reports);
}
/*
 * Encapsulate an IGMPv3 report.
 *
 * The internal mbuf flag M_IGMPV3_HDR is used to indicate that the mbuf
 * chain has already had its IP/IGMPv3 header prepended. In this case
 * the function will not attempt to prepend; the lengths and checksums
 * will however be re-computed.
 *
 * Returns a pointer to the new mbuf chain head, or NULL if the
 * allocation failed.
 */
static struct mbuf *
igmp_v3_encap_report(struct ifnet *ifp, struct mbuf *m)
{
	struct igmp_report	*igmp;
	struct ip		*ip;
	int			 hdrlen, igmpreclen;

	VERIFY((m->m_flags & M_PKTHDR));

	igmpreclen = m_length(m);
	hdrlen = sizeof(struct ip) + sizeof(struct igmp_report);

	if (m->m_flags & M_IGMPV3_HDR) {
		igmpreclen -= hdrlen;
	} else {
		M_PREPEND(m, hdrlen, M_DONTWAIT, 1);
		if (m == NULL)
			return (NULL);
		m->m_flags |= M_IGMPV3_HDR;
	}

	IGMP_PRINTF(("%s: igmpreclen is %d\n", __func__, igmpreclen));

	m->m_data += sizeof(struct ip);
	m->m_len -= sizeof(struct ip);

	igmp = mtod(m, struct igmp_report *);
	igmp->ir_type = IGMP_v3_HOST_MEMBERSHIP_REPORT;
	igmp->ir_rsv1 = 0;
	igmp->ir_rsv2 = 0;
	igmp->ir_numgrps = htons(m->m_pkthdr.vt_nrecs);
	igmp->ir_cksum = 0;
	igmp->ir_cksum = in_cksum(m, sizeof(struct igmp_report) + igmpreclen);
	m->m_pkthdr.vt_nrecs = 0;

	m->m_data -= sizeof(struct ip);
	m->m_len += sizeof(struct ip);

	ip = mtod(m, struct ip *);
	ip->ip_tos = IPTOS_PREC_INTERNETCONTROL;
	ip->ip_len = hdrlen + igmpreclen;
	ip->ip_off = IP_DF;
	ip->ip_p = IPPROTO_IGMP;
	ip->ip_sum = 0;

	ip->ip_src.s_addr = INADDR_ANY;

	if (m->m_flags & M_IGMP_LOOP) {
		struct in_ifaddr *ia;

		IFP_TO_IA(ifp, ia);
		if (ia != NULL) {
			IFA_LOCK(&ia->ia_ifa);
			ip->ip_src = ia->ia_addr.sin_addr;
			IFA_UNLOCK(&ia->ia_ifa);
			IFA_REMREF(&ia->ia_ifa);
		}
	}

	ip->ip_dst.s_addr = htonl(INADDR_ALLRPTS_GROUP);

	return (m);
}

#ifdef IGMP_DEBUG
static const char *
igmp_rec_type_to_str(const int type)
{
	switch (type) {
		case IGMP_CHANGE_TO_EXCLUDE_MODE:
			return "TO_EX";
		case IGMP_CHANGE_TO_INCLUDE_MODE:
			return "TO_IN";
		case IGMP_MODE_IS_EXCLUDE:
			return "MODE_EX";
		case IGMP_MODE_IS_INCLUDE:
			return "MODE_IN";
		case IGMP_ALLOW_NEW_SOURCES:
			return "ALLOW_NEW";
		case IGMP_BLOCK_OLD_SOURCES:
			return "BLOCK_OLD";
		default:
			break;
	}
	return "unknown";
}
#endif

void
igmp_init(struct protosw *pp, struct domain *dp)
{
#pragma unused(dp)
	static int igmp_initialized = 0;

	VERIFY((pp->pr_flags & (PR_INITIALIZED|PR_ATTACHED)) == PR_ATTACHED);

	if (igmp_initialized)
		return;
	igmp_initialized = 1;

	IGMP_PRINTF(("%s: initializing\n", __func__));

	igmp_timers_are_running = 0;

	/* Setup lock group and attribute for igmp_mtx */
	igmp_mtx_grp_attr = lck_grp_attr_alloc_init();
	igmp_mtx_grp = lck_grp_alloc_init("igmp_mtx", igmp_mtx_grp_attr);
	igmp_mtx_attr = lck_attr_alloc_init();
	lck_mtx_init(&igmp_mtx, igmp_mtx_grp, igmp_mtx_attr);

	LIST_INIT(&igi_head);
	m_raopt = igmp_ra_alloc();

	igi_size = sizeof (struct igmp_ifinfo);
	igi_zone = zinit(igi_size, IGI_ZONE_MAX * igi_size,
	    0, IGI_ZONE_NAME);
	if (igi_zone == NULL) {
		panic("%s: failed allocating %s", __func__, IGI_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(igi_zone, Z_EXPAND, TRUE);
	zone_change(igi_zone, Z_CALLERACCT, FALSE);
}
