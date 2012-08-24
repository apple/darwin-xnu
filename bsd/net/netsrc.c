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

#include <net/netsrc.h>

static errno_t	netsrc_ctlsend(kern_ctl_ref, uint32_t, void *, mbuf_t, int);
static errno_t	netsrc_ctlconnect(kern_ctl_ref, struct sockaddr_ctl *, void **);
static errno_t	netsrc_ipv4(kern_ctl_ref, uint32_t, struct netsrc_req *); 
static errno_t	netsrc_ipv6(kern_ctl_ref, uint32_t, struct netsrc_req *);

static kern_ctl_ref	netsrc_ctlref = NULL;

__private_extern__ void
netsrc_init(void)
{
	errno_t error;
	struct kern_ctl_reg netsrc_ctl = {
		.ctl_connect = netsrc_ctlconnect,
		.ctl_send    = netsrc_ctlsend,
	};

	strlcpy(netsrc_ctl.ctl_name, NETSRC_CTLNAME, sizeof(NETSRC_CTLNAME));

	if ((error = ctl_register(&netsrc_ctl, &netsrc_ctlref)))
		printf("%s: ctl_register failed %d\n", __func__, error);
}

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
	/* We only have one version right now. */
	if (nrq->nrq_ver != NETSRC_VERSION1) {
		error = EINVAL;
		goto out;
	}
	switch (nrq->nrq_sin.sin_family) {
	case AF_INET:
		error = netsrc_ipv4(kctl, unit, nrq);
		break;
	case AF_INET6:
		error = netsrc_ipv6(kctl, unit, nrq);
		break;
	default:
		printf("%s: invalid family\n", __func__);
		error = EINVAL;
	}
out:
	mbuf_freem(m);

	return (error);

}

static errno_t
netsrc_ipv4(kern_ctl_ref kctl, uint32_t unit, struct netsrc_req *nrq)
{
	errno_t error = EHOSTUNREACH;
	struct sockaddr_in *dstsin;
	struct rtentry *rt;
	struct in_ifaddr *ia;
	struct netsrc_rep nrp;
	struct sockaddr_in6 v4entry = {
		.sin6_family = AF_INET6,
		.sin6_len = sizeof(struct sockaddr_in6),
		.sin6_addr = IN6ADDR_V4MAPPED_INIT,
	};
	struct in6_addrpolicy *policy;

	dstsin = &nrq->nrq_sin;

	if (dstsin->sin_len < sizeof (*dstsin) ||
	    dstsin->sin_addr.s_addr == INADDR_ANY)
		return (EINVAL);

	lck_mtx_lock(rnh_lock);
	rt = rt_lookup(TRUE, (struct sockaddr *)dstsin, NULL,
	    rt_tables[AF_INET], nrq->nrq_ifscope);
	lck_mtx_unlock(rnh_lock);
	if (!rt)
		return (EHOSTUNREACH);
	lck_rw_lock_shared(in_ifaddr_rwlock);
	TAILQ_FOREACH(ia, &in_ifaddrhead, ia_link) {
		IFA_LOCK_SPIN(&ia->ia_ifa);
		if (ia->ia_ifp == rt->rt_ifp) {
			memset(&nrp, 0, sizeof(nrp));
			memcpy(&nrp.nrp_sin, IA_SIN(ia), sizeof(nrp.nrp_sin));
			IFA_UNLOCK(&ia->ia_ifa);
			v4entry.sin6_addr.s6_addr32[3] =
			    nrp.nrp_sin.sin_addr.s_addr;
			policy = in6_addrsel_lookup_policy(&v4entry);
			if (policy->label != -1) {
				nrp.nrp_label = policy->label;
				nrp.nrp_precedence = policy->preced;
				/* XXX might not be true */
				nrp.nrp_dstlabel = policy->label;
				nrp.nrp_dstprecedence = policy->preced;
			}
			error = ctl_enqueuedata(kctl, unit, &nrp,
			    sizeof(nrp), CTL_DATA_EOR);
			break;
		}
		IFA_UNLOCK(&ia->ia_ifa);
	}
	lck_rw_done(in_ifaddr_rwlock);
	if (rt)
		rtfree(rt);

	return (error);
}

static errno_t
netsrc_ipv6(kern_ctl_ref kctl, uint32_t unit, struct netsrc_req *nrq)
{
	struct sockaddr_in6 *dstsin6;
	struct in6_addr *in6, storage;
	struct in6_ifaddr *ia;
	struct route_in6 ro;
	int error = EHOSTUNREACH;
	struct netsrc_rep nrp;

	dstsin6 = &nrq->nrq_sin6;

	if (dstsin6->sin6_len < sizeof (*dstsin6) ||
	    IN6_IS_ADDR_UNSPECIFIED(&dstsin6->sin6_addr))
		return (EINVAL);

	memset(&ro, 0, sizeof(ro));
	lck_mtx_lock(rnh_lock);
	ro.ro_rt = rt_lookup(TRUE, (struct sockaddr *)dstsin6, NULL,
	    rt_tables[AF_INET6], nrq->nrq_ifscope);
	lck_mtx_unlock(rnh_lock);
	if (!ro.ro_rt)
		return (EHOSTUNREACH);
	in6 = in6_selectsrc(dstsin6, NULL, NULL, &ro, NULL, &storage,
	    nrq->nrq_ifscope, &error);
	if (ro.ro_rt)
		rtfree(ro.ro_rt);
	if (!in6 || error)
		return (error);
	memset(&nrp, 0, sizeof(nrp));
	nrp.nrp_sin6.sin6_family = AF_INET6;
	nrp.nrp_sin6.sin6_len    = sizeof(nrp.nrp_sin6);
	memcpy(&nrp.nrp_sin6.sin6_addr, in6, sizeof(nrp.nrp_sin6.sin6_addr));
	lck_rw_lock_shared(&in6_ifaddr_rwlock);
	for (ia = in6_ifaddrs; ia; ia = ia->ia_next) {
		if (memcmp(&ia->ia_addr.sin6_addr, in6, sizeof(*in6)) == 0) {
			struct sockaddr_in6 sin6;
			struct in6_addrpolicy *policy;

			if (ia->ia6_flags & IN6_IFF_TEMPORARY)
				nrp.nrp_flags |= NETSRC_IP6_FLAG_TEMPORARY;
			if (ia->ia6_flags & IN6_IFF_TENTATIVE)
				nrp.nrp_flags |= NETSRC_IP6_FLAG_TENTATIVE;
			if (ia->ia6_flags & IN6_IFF_DEPRECATED)
				nrp.nrp_flags |= NETSRC_IP6_FLAG_DEPRECATED;
			if (ia->ia6_flags & IN6_IFF_OPTIMISTIC)
				nrp.nrp_flags |= NETSRC_IP6_FLAG_OPTIMISTIC;
			sin6.sin6_family = AF_INET6;
			sin6.sin6_len    = sizeof(sin6);
			memcpy(&sin6.sin6_addr, in6, sizeof(*in6));
			policy = in6_addrsel_lookup_policy(&sin6);
			if (policy->label != -1) {
				nrp.nrp_label = policy->label;
				nrp.nrp_precedence = policy->preced;
			}
			memcpy(&sin6.sin6_addr, &dstsin6->sin6_addr,
			    sizeof(dstsin6->sin6_addr));
			policy = in6_addrsel_lookup_policy(&sin6);
			if (policy->label != -1) {
				nrp.nrp_dstlabel = policy->label;
				nrp.nrp_dstprecedence = policy->preced;
			}
			break;
		}
	}
	lck_rw_done(&in6_ifaddr_rwlock);
	error = ctl_enqueuedata(kctl, unit, &nrp, sizeof(nrp),
	    CTL_DATA_EOR);

	return (error);
}
