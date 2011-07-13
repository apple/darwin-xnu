/*
 * Copyright (c) 2011 Apple Inc. All rights reserved.
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
 * Link-layer Reachability Record
 *
 * Each interface maintains a red-black tree which contains records related
 * to the on-link nodes which we are interested in communicating with.  Each
 * record gets allocated and inserted into the tree in the following manner:
 * upon processing an ARP announcement or reply from a known node (i.e. there
 * exists a ARP route entry for the node), and if a link-layer reachability
 * record for the node doesn't yet exist; and, upon processing a ND6 RS/RA/
 * NS/NA/redirect from a node, and if a link-layer reachability record for the
 * node doesn't yet exist.
 *
 * Each newly created record is then referred to by the resolver route entry;
 * if a record already exists, its reference count gets increased for the new
 * resolver entry which now refers to it.  A record gets removed from the tree
 * and freed once its reference counts drops to zero, i.e. when there is no
 * more resolver entry referring to it.
 *
 * A record contains the link-layer protocol (e.g. Ethertype IP/IPv6), the
 * HW address of the sender, the "last heard from" timestamp (lr_lastrcvd) and
 * the number of references made to it (lr_reqcnt).  Because the key for each
 * record in the red-black tree consists of the link-layer protocol, therefore
 * the namespace for the records is partitioned based on the type of link-layer
 * protocol, i.e. an Ethertype IP link-layer record is only referred to by one
 * or more ARP entries; an Ethernet IPv6 link-layer record is only referred to
 * by one or more ND6 entries.  Therefore, lr_reqcnt represents the number of
 * resolver entry references to the record for the same protocol family.
 *
 * Upon receiving packets from the network, the protocol's input callback
 * (e.g. ether_inet{6}_input) informs the corresponding resolver (ARP/ND6)
 * about the (link-layer) origin of the packet.  This results in searching
 * for a matching record in the red-black tree for the interface where the
 * packet arrived on.  If there's no match, no further processing takes place.
 * Otherwise, the lr_lastrcvd timestamp of the record is updated.
 *
 * When an IP/IPv6 packet is transmitted to the resolver (i.e. the destination
 * is on-link), ARP/ND6 records the "last spoken to" timestamp in the route
 * entry ({la,ln}_lastused).
 *
 * The reachability of the on-link node is determined by the following logic,
 * upon sending a packet thru the resolver:
 *
 *   a) If the record is only used by exactly one resolver entry (lr_reqcnt
 *	is 1), i.e. the target host does not have IP/IPv6 aliases that we know
 *	of, check if lr_lastrcvd is "recent."  If so, simply send the packet;
 *	otherwise, re-resolve the target node.
 *
 *   b) If the record is shared by multiple resolver entries (lr_reqcnt is
 *	greater than 1), i.e. the target host has more than one IP/IPv6 aliases
 *	on the same network interface, we can't rely on lr_lastrcvd alone, as
 *	one of the IP/IPv6 aliases could have been silently moved to another
 *	node for which we don't have a link-layer record.  If lr_lastrcvd is
 *	not "recent", we re-resolve the target node.  Otherwise, we perform
 *	an additional check against {la,ln}_lastused to see whether it is also
 *	"recent", relative to lr_lastrcvd.  If so, simply send the packet;
 *	otherwise, re-resolve the target node.
 *
 * The value for "recent" is configurable by adjusting the basetime value for
 * net.link.ether.inet.arp_llreach_base or net.inet6.icmp6.nd6_llreach_base.
 * The default basetime value is 30 seconds, and the actual expiration time
 * is calculated by multiplying the basetime value with some random factor,
 * which results in a number between 15 to 45 seconds.  Setting the basetime
 * value to 0 effectively disables this feature for the corresponding resolver.
 *
 * Assumptions:
 *
 * The above logic is based upon the following assumptions:
 *
 *   i) Network traffics are mostly bi-directional, i.e. the act of sending
 *	packets to an on-link node would most likely cause us to receive
 *	packets from that node.
 *
 *  ii) If the on-link node's IP/IPv6 address silently moves to another
 *	on-link node for which we are not aware of, non-unicast packets
 *	from the old node would trigger the record's lr_lastrcvd to be
 *	kept recent.
 *
 * We can mitigate the above by having the resolver check its {la,ln}_lastused
 * timestamp at all times, i.e. not only when lr_reqcnt is greater than 1; but
 * we currently optimize for the common cases.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/tree.h>
#include <sys/sysctl.h>
#include <sys/mcache.h>
#include <sys/protosw.h>

#include <net/if_dl.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_llreach.h>
#include <net/dlil.h>

#include <kern/assert.h>
#include <kern/locks.h>
#include <kern/zalloc.h>

#if INET6
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#endif /* INET6 */

static unsigned int iflr_size;		/* size of if_llreach */
static struct zone *iflr_zone;		/* zone for if_llreach */

#define	IFLR_ZONE_MAX		128		/* maximum elements in zone */
#define	IFLR_ZONE_NAME		"if_llreach"	/* zone name */

static struct if_llreach *iflr_alloc(int);
static void iflr_free(struct if_llreach *);
static __inline int iflr_cmp(const struct if_llreach *,
    const struct if_llreach *);
static __inline int iflr_reachable(struct if_llreach *, int, u_int64_t);
static int sysctl_llreach_ifinfo SYSCTL_HANDLER_ARGS;

/* The following is protected by if_llreach_lock */
RB_GENERATE_PREV(ll_reach_tree, if_llreach, lr_link, iflr_cmp);

SYSCTL_DECL(_net_link_generic_system);

SYSCTL_NODE(_net_link_generic_system, OID_AUTO, llreach_info,
    CTLFLAG_RD | CTLFLAG_LOCKED, sysctl_llreach_ifinfo,
    "Per-interface tree of source link-layer reachability records");

/*
 * Link-layer reachability is based off node constants in RFC4861.
 */
#if INET6
#define	LL_COMPUTE_RTIME(x)	ND_COMPUTE_RTIME(x)
#else
#define LL_MIN_RANDOM_FACTOR	512	/* 1024 * 0.5 */
#define LL_MAX_RANDOM_FACTOR	1536	/* 1024 * 1.5 */
#define LL_COMPUTE_RTIME(x)						\
	(((LL_MIN_RANDOM_FACTOR * (x >> 10)) + (random() &		\
	((LL_MAX_RANDOM_FACTOR - LL_MIN_RANDOM_FACTOR) * (x >> 10)))) / 1000)
#endif /* !INET6 */

void
ifnet_llreach_init(void)
{
	iflr_size = sizeof (struct if_llreach);
	iflr_zone = zinit(iflr_size,
	    IFLR_ZONE_MAX * iflr_size, 0, IFLR_ZONE_NAME);
	if (iflr_zone == NULL) {
		panic("%s: failed allocating %s", __func__, IFLR_ZONE_NAME);
		/* NOTREACHED */
	}
	zone_change(iflr_zone, Z_EXPAND, TRUE);
	zone_change(iflr_zone, Z_CALLERACCT, FALSE);
}

void
ifnet_llreach_ifattach(struct ifnet *ifp, boolean_t reuse)
{
	lck_rw_lock_exclusive(&ifp->if_llreach_lock);
	/* Initialize link-layer source tree (if not already) */
	if (!reuse)
		RB_INIT(&ifp->if_ll_srcs);
	lck_rw_done(&ifp->if_llreach_lock);
}

void
ifnet_llreach_ifdetach(struct ifnet *ifp)
{
#pragma unused(ifp)
	/*
	 * Nothing to do for now; the link-layer source tree might
	 * contain entries at this point, that are still referred
	 * to by route entries pointing to this ifp.
	 */
}

/*
 * Link-layer source tree comparison function.
 *
 * An ordered predicate is necessary; bcmp() is not documented to return
 * an indication of order, memcmp() is, and is an ISO C99 requirement.
 */
static __inline int
iflr_cmp(const struct if_llreach *a, const struct if_llreach *b)
{
	return (memcmp(&a->lr_key, &b->lr_key, sizeof (a->lr_key)));
}

static __inline int
iflr_reachable(struct if_llreach *lr, int cmp_delta, u_int64_t tval)
{
	u_int64_t now;
	u_int64_t expire;

	now = net_uptime();		/* current approx. uptime */
	/*
	 * No need for lr_lock; atomically read the last rcvd uptime.
	 */
	expire = lr->lr_lastrcvd + lr->lr_reachable;
	/*
	 * If we haven't heard back from the local host for over
	 * lr_reachable seconds, consider that the host is no
	 * longer reachable.
	 */
	if (!cmp_delta)
		return (expire >= now);
	/*
	 * If the caller supplied a reference time, consider the
	 * host is reachable if the record hasn't expired (see above)
	 * and if the reference time is within the past lr_reachable
	 * seconds.
	 */
	return ((expire >= now) && (now - tval) < lr->lr_reachable);
}

int
ifnet_llreach_reachable(struct if_llreach *lr)
{
	/*
	 * Check whether the cache is too old to be trusted.
	 */
	return (iflr_reachable(lr, 0, 0));
}

int
ifnet_llreach_reachable_delta(struct if_llreach *lr, u_int64_t tval)
{
	/*
	 * Check whether the cache is too old to be trusted.
	 */
	return (iflr_reachable(lr, 1, tval));
}

void
ifnet_llreach_set_reachable(struct ifnet *ifp, u_int16_t llproto, void *addr,
    unsigned int alen)
{
	struct if_llreach find, *lr;

	VERIFY(alen == IF_LLREACH_MAXLEN);	/* for now */

	find.lr_key.proto = llproto;
	bcopy(addr, &find.lr_key.addr, IF_LLREACH_MAXLEN);

	lck_rw_lock_shared(&ifp->if_llreach_lock);
	lr = RB_FIND(ll_reach_tree, &ifp->if_ll_srcs, &find);
	if (lr == NULL) {
		lck_rw_done(&ifp->if_llreach_lock);
		return;
	}
	/*
	 * No need for lr_lock; atomically update the last rcvd uptime.
	 */
	lr->lr_lastrcvd = net_uptime();
	lck_rw_done(&ifp->if_llreach_lock);
}

struct if_llreach *
ifnet_llreach_alloc(struct ifnet *ifp, u_int16_t llproto, void *addr,
    unsigned int alen, u_int64_t llreach_base)
{
	struct if_llreach find, *lr;
	struct timeval now;

	if (llreach_base == 0)
		return (NULL);

	VERIFY(alen == IF_LLREACH_MAXLEN);	/* for now */

	find.lr_key.proto = llproto;
	bcopy(addr, &find.lr_key.addr, IF_LLREACH_MAXLEN);

	lck_rw_lock_shared(&ifp->if_llreach_lock);
	lr = RB_FIND(ll_reach_tree, &ifp->if_ll_srcs, &find);
	if (lr != NULL) {
found:
		IFLR_LOCK(lr);
		VERIFY(lr->lr_reqcnt >= 1);
		lr->lr_reqcnt++;
		VERIFY(lr->lr_reqcnt != 0);
		IFLR_ADDREF_LOCKED(lr);		/* for caller */
		lr->lr_lastrcvd = net_uptime();	/* current approx. uptime */
		IFLR_UNLOCK(lr);
		lck_rw_done(&ifp->if_llreach_lock);
		return (lr);
	}

	if (!lck_rw_lock_shared_to_exclusive(&ifp->if_llreach_lock))
		lck_rw_lock_exclusive(&ifp->if_llreach_lock);

	lck_rw_assert(&ifp->if_llreach_lock, LCK_RW_ASSERT_EXCLUSIVE);

	/* in case things have changed while becoming writer */
	lr = RB_FIND(ll_reach_tree, &ifp->if_ll_srcs, &find);
	if (lr != NULL)
		goto found;

	lr = iflr_alloc(M_WAITOK);
	if (lr == NULL) {
		lck_rw_done(&ifp->if_llreach_lock);
		return (NULL);
	}
	IFLR_LOCK(lr);
	lr->lr_reqcnt++;
	VERIFY(lr->lr_reqcnt == 1);
	IFLR_ADDREF_LOCKED(lr);			/* for RB tree */
	IFLR_ADDREF_LOCKED(lr);			/* for caller */
	lr->lr_lastrcvd = net_uptime();		/* current approx. uptime */
	lr->lr_baseup = lr->lr_lastrcvd;	/* base uptime */
	microtime(&now);
	lr->lr_basecal = now.tv_sec;		/* base calendar time */
	lr->lr_basereachable = llreach_base;
	lr->lr_reachable = LL_COMPUTE_RTIME(lr->lr_basereachable * 1000);
	lr->lr_debug |= IFD_ATTACHED;
	lr->lr_ifp = ifp;
	lr->lr_key.proto = llproto;
	bcopy(addr, &lr->lr_key.addr, IF_LLREACH_MAXLEN);
	RB_INSERT(ll_reach_tree, &ifp->if_ll_srcs, lr);
	IFLR_UNLOCK(lr);
	lck_rw_done(&ifp->if_llreach_lock);

	return (lr);
}

void
ifnet_llreach_free(struct if_llreach *lr)
{
	struct ifnet *ifp;

	/* no need to lock here; lr_ifp never changes */
	ifp = lr->lr_ifp;

	lck_rw_lock_exclusive(&ifp->if_llreach_lock);
	IFLR_LOCK(lr);
	if (lr->lr_reqcnt == 0) {
		panic("%s: lr=%p negative reqcnt", __func__, lr);
		/* NOTREACHED */
	}
	--lr->lr_reqcnt;
	if (lr->lr_reqcnt > 0) {
		IFLR_UNLOCK(lr);
		lck_rw_done(&ifp->if_llreach_lock);
		IFLR_REMREF(lr);		/* for caller */
		return;
	}
	if (!(lr->lr_debug & IFD_ATTACHED)) {
		panic("%s: Attempt to detach an unattached llreach lr=%p",
		    __func__, lr);
		/* NOTREACHED */
	}
	lr->lr_debug &= ~IFD_ATTACHED;
	RB_REMOVE(ll_reach_tree, &ifp->if_ll_srcs, lr);
	IFLR_UNLOCK(lr);
	lck_rw_done(&ifp->if_llreach_lock);

	IFLR_REMREF(lr);			/* for RB tree */
	IFLR_REMREF(lr);			/* for caller */
}

u_int64_t
ifnet_llreach_up2cal(struct if_llreach *lr, u_int64_t uptime)
{
	u_int64_t calendar = 0;

	if (uptime != 0) {
		struct timeval cnow;
		u_int64_t unow;

		getmicrotime(&cnow);	/* current calendar time */
		unow = net_uptime();	/* current approx. uptime */
		/*
		 * Take into account possible calendar time changes;
		 * adjust base calendar value if necessary, i.e.
		 * the calendar skew should equate to the uptime skew.
		 */
		lr->lr_basecal += (cnow.tv_sec - lr->lr_basecal) -
		    (unow - lr->lr_baseup);

		calendar = lr->lr_basecal + lr->lr_reachable +
		    (uptime - lr->lr_baseup);
	}

	return (calendar);
}

static struct if_llreach *
iflr_alloc(int how)
{
	struct if_llreach *lr;

	lr = (how == M_WAITOK) ? zalloc(iflr_zone) : zalloc_noblock(iflr_zone);
	if (lr != NULL) {
		bzero(lr, iflr_size);
		lck_mtx_init(&lr->lr_lock, ifnet_lock_group, ifnet_lock_attr);
		lr->lr_debug |= IFD_ALLOC;
	}
	return (lr);
}

static void
iflr_free(struct if_llreach *lr)
{
	IFLR_LOCK(lr);
	if (lr->lr_debug & IFD_ATTACHED) {
		panic("%s: attached lr=%p is being freed", __func__, lr);
		/* NOTREACHED */
	} else if (!(lr->lr_debug & IFD_ALLOC)) {
		panic("%s: lr %p cannot be freed", __func__, lr);
		/* NOTREACHED */
	} else if (lr->lr_refcnt != 0) {
		panic("%s: non-zero refcount lr=%p", __func__, lr);
		/* NOTREACHED */
	} else if (lr->lr_reqcnt != 0) {
		panic("%s: non-zero reqcnt lr=%p", __func__, lr);
		/* NOTREACHED */
	}
	lr->lr_debug &= ~IFD_ALLOC;
	IFLR_UNLOCK(lr);

	lck_mtx_destroy(&lr->lr_lock, ifnet_lock_group);
	zfree(iflr_zone, lr);
}

void
iflr_addref(struct if_llreach *lr, int locked)
{
	if (!locked)
		IFLR_LOCK(lr);
	else
		IFLR_LOCK_ASSERT_HELD(lr);

	if (++lr->lr_refcnt == 0) {
		panic("%s: lr=%p wraparound refcnt", __func__, lr);
		/* NOTREACHED */
	}
	if (!locked)
		IFLR_UNLOCK(lr);
}

void
iflr_remref(struct if_llreach *lr)
{
	IFLR_LOCK(lr);
	if (lr->lr_refcnt == 0) {
		panic("%s: lr=%p negative refcnt", __func__, lr);
		/* NOTREACHED */
	}
	--lr->lr_refcnt;
	if (lr->lr_refcnt > 0) {
		IFLR_UNLOCK(lr);
		return;
	}
	IFLR_UNLOCK(lr);

	iflr_free(lr);	/* deallocate it */
}

void
ifnet_lr2ri(struct if_llreach *lr, struct rt_reach_info *ri)
{
	struct if_llreach_info lri;

	IFLR_LOCK_ASSERT_HELD(lr);

	bzero(ri, sizeof (*ri));
	ifnet_lr2lri(lr, &lri);
	ri->ri_refcnt = lri.lri_refcnt;
	ri->ri_probes = lri.lri_probes;
	ri->ri_rcv_expire = lri.lri_expire;
}

void
ifnet_lr2lri(struct if_llreach *lr, struct if_llreach_info *lri)
{
	IFLR_LOCK_ASSERT_HELD(lr);

	bzero(lri, sizeof (*lri));
	/*
	 * Note here we return request count, not actual memory refcnt.
	 */
	lri->lri_refcnt	= lr->lr_reqcnt;
	lri->lri_ifindex = lr->lr_ifp->if_index;
	lri->lri_probes	= lr->lr_probes;
	lri->lri_expire = ifnet_llreach_up2cal(lr, lr->lr_lastrcvd);
	lri->lri_proto = lr->lr_key.proto;
	bcopy(&lr->lr_key.addr, &lri->lri_addr, IF_LLREACH_MAXLEN);
}

static int
sysctl_llreach_ifinfo SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp)
	int		*name, retval = 0;
	unsigned int	namelen;
	uint32_t	ifindex;
	struct if_llreach *lr;
	struct if_llreach_info lri;
	struct ifnet	*ifp;

	name = (int *)arg1;
	namelen = (unsigned int)arg2;

	if (req->newptr != USER_ADDR_NULL)
		return (EPERM);

	if (namelen != 1)
		return (EINVAL);

	ifindex = name[0];
	ifnet_head_lock_shared();
	if (ifindex <= 0 || ifindex > (u_int)if_index) {
		printf("%s: ifindex %u out of range\n", __func__, ifindex);
		ifnet_head_done();
		return (ENOENT);
	}

	ifp = ifindex2ifnet[ifindex];
	ifnet_head_done();
	if (ifp == NULL) {
		printf("%s: no ifp for ifindex %u\n", __func__, ifindex);
		return (ENOENT);
	}

	lck_rw_lock_shared(&ifp->if_llreach_lock);
	RB_FOREACH(lr, ll_reach_tree, &ifp->if_ll_srcs) {
		/* Export to if_llreach_info structure */
		IFLR_LOCK(lr);
		ifnet_lr2lri(lr, &lri);
		IFLR_UNLOCK(lr);

		if ((retval = SYSCTL_OUT(req, &lri, sizeof (lri))) != 0)
			break;
	}
	lck_rw_done(&ifp->if_llreach_lock);

	return (retval);
}
