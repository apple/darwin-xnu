/*
 * Copyright (c) 2011-2017 Apple Inc. All rights reserved.
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

// Include netinet/in.h first. net/netsrc.h depends on netinet/in.h but
// netinet/in.h doesn't work with -Wpadded, -Wpacked.
#include <netinet/in.h>

#pragma clang diagnostic push
#pragma clang diagnostic error "-Wpadded"
#pragma clang diagnostic error "-Wpacked"
// This header defines structures shared with user space, so we need to ensure there is
// no compiler inserted padding in case the user space process isn't using the same
// architecture as the kernel (example: i386 process with x86_64 kernel).
#include <net/netsrc.h>
#pragma clang diagnostic pop

#include <sys/param.h>
#include <sys/types.h>
#include <sys/kpi_mbuf.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/mcache.h>
#include <sys/socketvar.h>

#include <kern/debug.h>

#include <libkern/libkern.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/in_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>

#include <net/ntstat.h>

static errno_t
netsrc_ctlconnect(kern_ctl_ref kctl, struct sockaddr_ctl *sac, void **uinfo)
{
#pragma unused(kctl, sac, uinfo)

	/*
	 * We don't need to do anything here. This callback is only necessary
	 * for ctl_register() to succeed.
	 */
	return (0);
}

static errno_t
netsrc_reply(kern_ctl_ref kctl, uint32_t unit, uint16_t version,
			 struct netsrc_rep *reply)
{
	switch (version) {
		case NETSRC_CURVERS:
			return ctl_enqueuedata(kctl, unit, reply,
								   sizeof(*reply), CTL_DATA_EOR);
		case NETSRC_VERSION1: {
			if ((reply->nrp_flags & NETSRC_FLAG_ROUTEABLE) == 0) {
				return EHOSTUNREACH;
			}
#define NETSRC_FLAG_V1_MASK (NETSRC_IP6_FLAG_TENTATIVE | \
							 NETSRC_IP6_FLAG_TEMPORARY | \
							 NETSRC_IP6_FLAG_DEPRECATED | \
							 NETSRC_IP6_FLAG_OPTIMISTIC | \
							 NETSRC_IP6_FLAG_SECURED)
			struct netsrc_repv1 v1 = {
				.nrp_src = reply->nrp_src,
				.nrp_flags = (reply->nrp_flags & NETSRC_FLAG_V1_MASK),
				.nrp_label = reply->nrp_label,
				.nrp_precedence = reply->nrp_precedence,
				.nrp_dstlabel = reply->nrp_dstlabel,
				.nrp_dstprecedence = reply->nrp_dstprecedence
			};
			return ctl_enqueuedata(kctl, unit, &v1, sizeof(v1), CTL_DATA_EOR);
		}
	}
	return EINVAL;
}

static void
netsrc_common(struct rtentry *rt, struct netsrc_rep *reply)
{
	if (!rt) {
		return;
	}

	// Gather statistics information
	struct nstat_counts	*rt_stats = rt->rt_stats;
	if (rt_stats) {
		reply->nrp_min_rtt = rt_stats->nstat_min_rtt;
		reply->nrp_connection_attempts = rt_stats->nstat_connectattempts;
		reply->nrp_connection_successes = rt_stats->nstat_connectsuccesses;
	}

	// If this route didn't have any stats, check its parent
	if (reply->nrp_min_rtt == 0) {
		// Is this lock necessary?
		RT_LOCK(rt);
		if (rt->rt_parent) {
			rt_stats = rt->rt_parent->rt_stats;
			if (rt_stats) {
				reply->nrp_min_rtt = rt_stats->nstat_min_rtt;
				reply->nrp_connection_attempts = rt_stats->nstat_connectattempts;
				reply->nrp_connection_successes = rt_stats->nstat_connectsuccesses;
			}
		}
		RT_UNLOCK(rt);
	}
	reply->nrp_ifindex = rt->rt_ifp ? rt->rt_ifp->if_index : 0;

	if (rt->rt_ifp->if_eflags & IFEF_AWDL) {
		reply->nrp_flags |= NETSRC_FLAG_AWDL;
	}
	if (rt->rt_flags & RTF_LOCAL) {
		reply->nrp_flags |= NETSRC_FLAG_DIRECT;
	} else if (!(rt->rt_flags & RTF_GATEWAY) &&
			   (rt->rt_ifa && rt->rt_ifa->ifa_ifp &&
			   !(rt->rt_ifa->ifa_ifp->if_flags & IFF_POINTOPOINT))) {
		reply->nrp_flags |= NETSRC_FLAG_DIRECT;
	}
}

static struct in6_addrpolicy *
lookup_policy(struct sockaddr* sa)
{
	// alignment fun - if sa_family is AF_INET or AF_INET6, this is one of those
	// addresses and it should be aligned, so this should be safe.
	union sockaddr_in_4_6 *addr = (union sockaddr_in_4_6 *)(void*)sa;
	if (addr->sa.sa_family == AF_INET6) {
		return in6_addrsel_lookup_policy(&addr->sin6);
	} else if (sa->sa_family == AF_INET) {
		struct sockaddr_in6 mapped = {
			.sin6_family = AF_INET6,
			.sin6_len = sizeof(mapped),
			.sin6_addr = IN6ADDR_V4MAPPED_INIT,
		};
		mapped.sin6_addr.s6_addr32[3] = addr->sin.sin_addr.s_addr;
		return in6_addrsel_lookup_policy(&mapped);
	}
	return NULL;
}

static void
netsrc_policy_common(struct netsrc_req *request, struct netsrc_rep *reply)
{
	// Destination policy
	struct in6_addrpolicy *policy = lookup_policy(&request->nrq_dst.sa);
	if (policy != NULL && policy->label != -1) {
		reply->nrp_dstlabel = policy->label;
		reply->nrp_dstprecedence = policy->preced;
	}

	// Source policy
	policy = lookup_policy(&reply->nrp_src.sa);
	if (policy != NULL && policy->label != -1) {
		reply->nrp_label = policy->label;
		reply->nrp_precedence = policy->preced;
	}
}

static errno_t
netsrc_ipv6(kern_ctl_ref kctl, uint32_t unit, struct netsrc_req *request)
{
	struct route_in6 ro = {
		.ro_dst = request->nrq_sin6,
	};

	int error = 0;
	struct in6_addr storage, *in6 = in6_selectsrc(&request->nrq_sin6, NULL,
												  NULL, &ro, NULL, &storage,
												  request->nrq_ifscope, &error);
	struct netsrc_rep reply = {
		.nrp_sin6.sin6_family = AF_INET6,
		.nrp_sin6.sin6_len = sizeof(reply.nrp_sin6),
		.nrp_sin6.sin6_addr = in6 ? *in6 : (struct in6_addr){},
	};
	netsrc_common(ro.ro_rt, &reply);
	if (ro.ro_srcia == NULL && in6 != NULL) {
		ro.ro_srcia = (struct ifaddr *)ifa_foraddr6_scoped(in6, reply.nrp_ifindex);
	}
	if (ro.ro_srcia) {
		struct in6_ifaddr *ia = (struct in6_ifaddr *)ro.ro_srcia;
#define IA_TO_NRP_FLAG(flag)	\
		if (ia->ia6_flags & IN6_IFF_##flag) {			\
			reply.nrp_flags |= NETSRC_FLAG_IP6_##flag;	\
		}
		IA_TO_NRP_FLAG(TENTATIVE);
		IA_TO_NRP_FLAG(TEMPORARY);
		IA_TO_NRP_FLAG(DEPRECATED);
		IA_TO_NRP_FLAG(OPTIMISTIC);
		IA_TO_NRP_FLAG(SECURED);
		IA_TO_NRP_FLAG(DYNAMIC);
		IA_TO_NRP_FLAG(AUTOCONF);
#undef IA_TO_NRP_FLAG
		reply.nrp_flags |= NETSRC_FLAG_ROUTEABLE;
	}
	ROUTE_RELEASE(&ro);
	netsrc_policy_common(request, &reply);
	return netsrc_reply(kctl, unit, request->nrq_ver, &reply);
}

static errno_t
netsrc_ipv4(kern_ctl_ref kctl, uint32_t unit, struct netsrc_req *request)
{
	// Unfortunately, IPv4 doesn't have a function like in6_selectsrc
	// Look up the route
	lck_mtx_lock(rnh_lock);
	struct rtentry *rt = rt_lookup(TRUE, &request->nrq_dst.sa,
								   NULL, rt_tables[AF_INET],
								   request->nrq_ifscope);
	lck_mtx_unlock(rnh_lock);

	// Look up the ifa
	struct netsrc_rep reply = {};
	if (rt) {
		struct in_ifaddr *ia = NULL;
		lck_rw_lock_shared(in_ifaddr_rwlock);
		TAILQ_FOREACH(ia, &in_ifaddrhead, ia_link) {
			IFA_LOCK_SPIN(&ia->ia_ifa);
			if (ia->ia_ifp == rt->rt_ifp) {
				IFA_ADDREF_LOCKED(&ia->ia_ifa);
				break;
			}
			IFA_UNLOCK(&ia->ia_ifa);
		}
		lck_rw_done(in_ifaddr_rwlock);

		if (ia) {
			reply.nrp_sin = *IA_SIN(ia);
			IFA_REMREF_LOCKED(&ia->ia_ifa);
			IFA_UNLOCK(&ia->ia_ifa);
			reply.nrp_flags |= NETSRC_FLAG_ROUTEABLE;
		}
		netsrc_common(rt, &reply);
		rtfree(rt);
	}
	netsrc_policy_common(request, &reply);
	return netsrc_reply(kctl, unit, request->nrq_ver, &reply);
}

static errno_t
netsrc_ctlsend(kern_ctl_ref kctl, uint32_t unit, void *uinfo, mbuf_t m,
    int flags)
{
#pragma unused(uinfo, flags)
	errno_t error;
	struct netsrc_req *nrq, storage;

	if (mbuf_pkthdr_len(m) < sizeof(*nrq)) {
		error = EINVAL;
		goto out;
	}
	if (mbuf_len(m) >= sizeof(*nrq))
		nrq = mbuf_data(m);
	else {
		mbuf_copydata(m, 0, sizeof(storage), &storage);
		nrq = &storage;
	}
	if (nrq->nrq_ver > NETSRC_CURVERS) {
		error = EINVAL;
		goto out;
	}
	switch (nrq->nrq_sin.sin_family) {
	case AF_INET:
		if (nrq->nrq_sin.sin_len < sizeof (nrq->nrq_sin) ||
			nrq->nrq_sin.sin_addr.s_addr == INADDR_ANY) {
			error = EINVAL;
		} else {
			error = netsrc_ipv4(kctl, unit, nrq);
		}
		break;
	case AF_INET6:
		if (nrq->nrq_sin6.sin6_len < sizeof(nrq->nrq_sin6) ||
			IN6_IS_ADDR_UNSPECIFIED(&nrq->nrq_sin6.sin6_addr)) {
			error = EINVAL;
		} else {
			error = netsrc_ipv6(kctl, unit, nrq);
		}
		break;
	default:
		printf("%s: invalid family\n", __func__);
		error = EINVAL;
	}
out:
	mbuf_freem(m);

	return (error);

}

__private_extern__ void
netsrc_init(void)
{
	struct kern_ctl_reg netsrc_ctl = {
		.ctl_connect = netsrc_ctlconnect,
		.ctl_send    = netsrc_ctlsend,
	};

	strlcpy(netsrc_ctl.ctl_name, NETSRC_CTLNAME, sizeof(netsrc_ctl.ctl_name));

	static kern_ctl_ref	netsrc_ctlref = NULL;
	errno_t error = ctl_register(&netsrc_ctl, &netsrc_ctlref);
	if (error != 0) {
		printf("%s: ctl_register failed %d\n", __func__, error);
	}
}
