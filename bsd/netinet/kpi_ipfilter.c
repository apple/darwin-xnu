/*
 * Copyright (c) 2004-2018 Apple Inc. All rights reserved.
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

#include <sys/param.h>	/* for definition of NULL */
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <libkern/OSAtomic.h>

#include <machine/endian.h>

#define	_IP_VHL
#include <net/if_var.h>
#include <net/route.h>
#include <net/kpi_protocol.h>
#include <net/net_api_stats.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>
#include <netinet/kpi_ipfilter_var.h>

#include <stdbool.h>

/*
 * kipf_lock and kipf_ref protect the linkage of the list of IP filters
 * An IP filter can be removed only when kipf_ref is zero
 * If an IP filter cannot be removed because kipf_ref is not null, then
 * the IP filter is marjed and kipf_delayed_remove is set so that when
 * kipf_ref eventually goes down to zero, the IP filter is removed
 */
decl_lck_mtx_data(static, kipf_lock_data);
static lck_mtx_t *kipf_lock = &kipf_lock_data;
static u_int32_t kipf_ref = 0;
static u_int32_t kipf_delayed_remove = 0;
u_int32_t kipf_count = 0;

__private_extern__ struct ipfilter_list	ipv4_filters = TAILQ_HEAD_INITIALIZER(ipv4_filters);
__private_extern__ struct ipfilter_list	ipv6_filters = TAILQ_HEAD_INITIALIZER(ipv6_filters);
__private_extern__ struct ipfilter_list	tbr_filters = TAILQ_HEAD_INITIALIZER(tbr_filters);

#undef ipf_addv4
#undef ipf_addv6
extern errno_t ipf_addv4(const struct ipf_filter *filter,
    ipfilter_t *filter_ref);
extern errno_t ipf_addv6(const struct ipf_filter *filter,
    ipfilter_t *filter_ref);

static errno_t ipf_add(const struct ipf_filter *filter,
    ipfilter_t *filter_ref, struct ipfilter_list *head, bool is_internal);

__private_extern__ void
ipf_ref(void)
{
	lck_mtx_lock(kipf_lock);
	kipf_ref++;
	lck_mtx_unlock(kipf_lock);
}

__private_extern__ void
ipf_unref(void)
{
	lck_mtx_lock(kipf_lock);

	if (kipf_ref == 0)
		panic("ipf_unref: kipf_ref == 0\n");

	kipf_ref--;
	if (kipf_ref == 0 && kipf_delayed_remove != 0) {
		struct ipfilter *filter;

		while ((filter = TAILQ_FIRST(&tbr_filters))) {
			VERIFY(OSDecrementAtomic64(&net_api_stats.nas_ipf_add_count) > 0);

			ipf_detach_func ipf_detach = filter->ipf_filter.ipf_detach;
			void* cookie = filter->ipf_filter.cookie;

			TAILQ_REMOVE(filter->ipf_head, filter, ipf_link);
			TAILQ_REMOVE(&tbr_filters, filter, ipf_tbr);
			kipf_delayed_remove--;

			if (ipf_detach) {
				lck_mtx_unlock(kipf_lock);
				ipf_detach(cookie);
				lck_mtx_lock(kipf_lock);
				/* In case some filter got to run while we released the lock */
				if (kipf_ref != 0)
					break;
			}
		}
	}
	lck_mtx_unlock(kipf_lock);
}

static errno_t
ipf_add(
	const struct ipf_filter *filter,
	ipfilter_t *filter_ref,
	struct ipfilter_list *head,
	bool is_internal)
{
	struct ipfilter	*new_filter;
	if (filter->name == NULL || (filter->ipf_input == NULL && filter->ipf_output == NULL))
		return (EINVAL);

	MALLOC(new_filter, struct ipfilter *, sizeof(*new_filter), M_IFADDR, M_WAITOK);
	if (new_filter == NULL)
		return (ENOMEM);

	lck_mtx_lock(kipf_lock);
	new_filter->ipf_filter = *filter;
	new_filter->ipf_head = head;

	TAILQ_INSERT_HEAD(head, new_filter, ipf_link);

	OSIncrementAtomic64(&net_api_stats.nas_ipf_add_count);
	INC_ATOMIC_INT64_LIM(net_api_stats.nas_ipf_add_total);
	if (is_internal) {
		INC_ATOMIC_INT64_LIM(net_api_stats.nas_ipf_add_os_total);
	}

	lck_mtx_unlock(kipf_lock);

	*filter_ref = (ipfilter_t)new_filter;

	/* This will force TCP to re-evaluate its use of TSO */
	OSAddAtomic(1, &kipf_count);
	routegenid_update();

	return (0);
}

errno_t
ipf_addv4_internal(
	const struct ipf_filter *filter,
	ipfilter_t *filter_ref)
{
	return (ipf_add(filter, filter_ref, &ipv4_filters, true));
}

errno_t
ipf_addv4(
	const struct ipf_filter *filter,
	ipfilter_t *filter_ref)
{
	return (ipf_add(filter, filter_ref, &ipv4_filters, false));
}

errno_t
ipf_addv6_internal(
	const struct ipf_filter *filter,
	ipfilter_t *filter_ref)
{
	return (ipf_add(filter, filter_ref, &ipv6_filters, true));
}

errno_t
ipf_addv6(
	const struct ipf_filter *filter,
	ipfilter_t *filter_ref)
{
	return (ipf_add(filter, filter_ref, &ipv6_filters, false));
}

static errno_t
ipf_input_detached(void *cookie, mbuf_t *data, int offset, u_int8_t protocol)
{
#pragma unused(cookie, data, offset, protocol)

#if DEBUG
	printf("ipf_input_detached\n");
#endif /* DEBUG */

	return (0);
}

static errno_t
ipf_output_detached(void *cookie, mbuf_t *data, ipf_pktopts_t options)
{
#pragma unused(cookie, data, options)

#if DEBUG
	printf("ipf_output_detached\n");
#endif /* DEBUG */

	return (0);
}

errno_t
ipf_remove(
	ipfilter_t filter_ref)
{
	struct ipfilter	*match = (struct ipfilter *)filter_ref;
	struct ipfilter_list *head;

	if (match == 0 || (match->ipf_head != &ipv4_filters && match->ipf_head != &ipv6_filters))
		return (EINVAL);

	head = match->ipf_head;

	lck_mtx_lock(kipf_lock);
	TAILQ_FOREACH(match, head, ipf_link) {
		if (match == (struct ipfilter *)filter_ref) {
			ipf_detach_func ipf_detach = match->ipf_filter.ipf_detach;
			void* cookie = match->ipf_filter.cookie;

			/*
			 * Cannot detach when they are filters running
			 */
			if (kipf_ref) {
				kipf_delayed_remove++;
				TAILQ_INSERT_TAIL(&tbr_filters, match, ipf_tbr);
				match->ipf_filter.ipf_input = ipf_input_detached;
				match->ipf_filter.ipf_output = ipf_output_detached;
				lck_mtx_unlock(kipf_lock);
			} else {
				VERIFY(OSDecrementAtomic64(&net_api_stats.nas_ipf_add_count) > 0);

				TAILQ_REMOVE(head, match, ipf_link);
				lck_mtx_unlock(kipf_lock);

				if (ipf_detach)
					ipf_detach(cookie);
				FREE(match, M_IFADDR);

				/* This will force TCP to re-evaluate its use of TSO */
				OSAddAtomic(-1, &kipf_count);
				routegenid_update();

			}
			return (0);
		}
	}
	lck_mtx_unlock(kipf_lock);

	return (ENOENT);
}

int log_for_en1 = 0;

errno_t
ipf_inject_input(
	mbuf_t data,
	ipfilter_t filter_ref)
{
	struct mbuf *m = (struct mbuf *)data;
	struct m_tag *mtag = 0;
	struct ip *ip = mtod(m, struct ip *);
	struct ip6_hdr *ip6;
	u_int8_t	vers;
	int hlen;
	errno_t error = 0;
	protocol_family_t proto;
	struct in_ifaddr *ia = NULL;
	struct in_addr *pkt_dst = NULL;
	struct in6_ifaddr *ia6 = NULL;
	struct sockaddr_in6 pkt_dst6;

	vers = IP_VHL_V(ip->ip_vhl);

	switch (vers) {
		case 4:
			proto = PF_INET;
			break;
		case 6:
			proto = PF_INET6;
			break;
		default:
			error = ENOTSUP;
			goto done;
	}

	if (filter_ref == 0 && m->m_pkthdr.rcvif == 0) {
		/*
		 * Search for interface with the local address
		 */
		switch (proto) {
			case PF_INET:
				pkt_dst = &ip->ip_dst;
				lck_rw_lock_shared(in_ifaddr_rwlock);
				TAILQ_FOREACH(ia, INADDR_HASH(pkt_dst->s_addr), ia_hash) {
					if (IA_SIN(ia)->sin_addr.s_addr == pkt_dst->s_addr) {
						m->m_pkthdr.rcvif = ia->ia_ifp;
						break;
					}
				}
				lck_rw_done(in_ifaddr_rwlock);
				break;

			case PF_INET6:
				ip6 = mtod(m, struct ip6_hdr *);
				pkt_dst6.sin6_addr = ip6->ip6_dst;
				lck_rw_lock_shared(&in6_ifaddr_rwlock);
				for (ia6 = in6_ifaddrs; ia6 != NULL; ia6 = ia6->ia_next) {
					if (IN6_ARE_ADDR_EQUAL(&ia6->ia_addr.sin6_addr, &pkt_dst6.sin6_addr)) {
						m->m_pkthdr.rcvif = ia6->ia_ifp;
						break;
					}
				}
				lck_rw_done(&in6_ifaddr_rwlock);
				break;

			default:
				break;
		}

		/*
		 * If none found, fallback to loopback
		 */
		if (m->m_pkthdr.rcvif == NULL) {
			m->m_pkthdr.rcvif = lo_ifp;
		}

		m->m_pkthdr.csum_data = 0;
		m->m_pkthdr.csum_flags = 0;
		if (vers == 4) {
			hlen = IP_VHL_HL(ip->ip_vhl) << 2;
			ip->ip_sum = 0;
			ip->ip_sum = in_cksum(m, hlen);
		}
	}
	if (filter_ref != 0) {
		mtag = m_tag_create(KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_IPFILT,
		    sizeof (ipfilter_t), M_NOWAIT, m);
		if (mtag == NULL) {
			error = ENOMEM;
			goto done;
		}
		*(ipfilter_t *)(mtag+1) = filter_ref;
		m_tag_prepend(m, mtag);
	}

	error = proto_inject(proto, data);

done:
	return (error);
}

static errno_t
ipf_injectv4_out(mbuf_t data, ipfilter_t filter_ref, ipf_pktopts_t options)
{
	struct route ro;
	struct ip *ip;
	struct mbuf *m = (struct mbuf *)data;
	errno_t error = 0;
	struct m_tag *mtag = NULL;
	struct ip_moptions *imo = NULL;
	struct ip_out_args ipoa;

	bzero(&ipoa, sizeof(ipoa));
	ipoa.ipoa_boundif = IFSCOPE_NONE;
	ipoa.ipoa_sotc = SO_TC_UNSPEC;
	ipoa.ipoa_netsvctype = _NET_SERVICE_TYPE_UNSPEC;

	/* Make the IP header contiguous in the mbuf */
	if ((size_t)m->m_len < sizeof (struct ip)) {
		m = m_pullup(m, sizeof (struct ip));
		if (m == NULL)
			return (ENOMEM);
	}
	ip = (struct ip *)m_mtod(m);

	if (filter_ref != 0) {
		mtag = m_tag_create(KERNEL_MODULE_TAG_ID,
		    KERNEL_TAG_TYPE_IPFILT, sizeof (ipfilter_t), M_NOWAIT, m);
		if (mtag == NULL) {
			m_freem(m);
			return (ENOMEM);
		}
		*(ipfilter_t *)(mtag + 1) = filter_ref;
		m_tag_prepend(m, mtag);
	}

	if (options != NULL && (options->ippo_flags & IPPOF_MCAST_OPTS) &&
	    (imo = ip_allocmoptions(M_DONTWAIT)) != NULL) {
		imo->imo_multicast_ifp = options->ippo_mcast_ifnet;
		imo->imo_multicast_ttl = options->ippo_mcast_ttl;
		imo->imo_multicast_loop = options->ippo_mcast_loop;
	}

	if (options != NULL) {
		if (options->ippo_flags & IPPOF_SELECT_SRCIF)
			ipoa.ipoa_flags |= IPOAF_SELECT_SRCIF;
		if (options->ippo_flags & IPPOF_BOUND_IF) {
			ipoa.ipoa_flags |= IPOAF_BOUND_IF;
			ipoa.ipoa_boundif = options->ippo_flags >>
			    IPPOF_SHIFT_IFSCOPE;
		}
		if (options->ippo_flags & IPPOF_NO_IFT_CELLULAR)
			ipoa.ipoa_flags |= IPOAF_NO_CELLULAR;
		if (options->ippo_flags & IPPOF_BOUND_SRCADDR)
			ipoa.ipoa_flags |= IPOAF_BOUND_SRCADDR;
		if (options->ippo_flags & IPPOF_NO_IFF_EXPENSIVE)
			ipoa.ipoa_flags |= IPOAF_NO_EXPENSIVE;
	}

	bzero(&ro, sizeof(struct route));

	/* Put ip_len and ip_off in host byte order, ip_output expects that */

#if BYTE_ORDER != BIG_ENDIAN
	NTOHS(ip->ip_len);
	NTOHS(ip->ip_off);
#endif

	/* Send; enforce source interface selection via IP_OUTARGS flag */
	error = ip_output(m, NULL, &ro,
	    IP_ALLOWBROADCAST | IP_RAWOUTPUT | IP_OUTARGS, imo, &ipoa);

	/* Release the route */
	ROUTE_RELEASE(&ro);

	if (imo != NULL)
		IMO_REMREF(imo);

	return (error);
}

#if INET6
static errno_t
ipf_injectv6_out(mbuf_t data, ipfilter_t filter_ref, ipf_pktopts_t options)
{
	struct route_in6 ro;
	struct ip6_hdr *ip6;
	struct mbuf *m = (struct mbuf *)data;
	errno_t error = 0;
	struct m_tag *mtag = NULL;
	struct ip6_moptions *im6o = NULL;
	struct ip6_out_args ip6oa;

	bzero(&ip6oa, sizeof(ip6oa));
	ip6oa.ip6oa_boundif = IFSCOPE_NONE;
	ip6oa.ip6oa_sotc = SO_TC_UNSPEC;
	ip6oa.ip6oa_netsvctype = _NET_SERVICE_TYPE_UNSPEC;

	/* Make the IP header contiguous in the mbuf */
	if ((size_t)m->m_len < sizeof(struct ip6_hdr)) {
		m = m_pullup(m, sizeof(struct ip6_hdr));
		if (m == NULL)
			return (ENOMEM);
	}
	ip6 = (struct ip6_hdr *)m_mtod(m);

	if (filter_ref != 0) {
		mtag = m_tag_create(KERNEL_MODULE_TAG_ID,
		    KERNEL_TAG_TYPE_IPFILT, sizeof (ipfilter_t), M_NOWAIT, m);
		if (mtag == NULL) {
			m_freem(m);
			return (ENOMEM);
		}
		*(ipfilter_t *)(mtag + 1) = filter_ref;
		m_tag_prepend(m, mtag);
	}

	if (options != NULL && (options->ippo_flags & IPPOF_MCAST_OPTS) &&
	    (im6o = ip6_allocmoptions(M_DONTWAIT)) != NULL) {
		im6o->im6o_multicast_ifp = options->ippo_mcast_ifnet;
		im6o->im6o_multicast_hlim = options->ippo_mcast_ttl;
		im6o->im6o_multicast_loop = options->ippo_mcast_loop;
	}

	if (options != NULL) {
		if (options->ippo_flags & IPPOF_SELECT_SRCIF)
			ip6oa.ip6oa_flags |= IP6OAF_SELECT_SRCIF;
		if (options->ippo_flags & IPPOF_BOUND_IF) {
			ip6oa.ip6oa_flags |= IP6OAF_BOUND_IF;
			ip6oa.ip6oa_boundif = options->ippo_flags >>
			    IPPOF_SHIFT_IFSCOPE;
		}
		if (options->ippo_flags & IPPOF_NO_IFT_CELLULAR)
			ip6oa.ip6oa_flags |= IP6OAF_NO_CELLULAR;
		if (options->ippo_flags & IPPOF_BOUND_SRCADDR)
			ip6oa.ip6oa_flags |= IP6OAF_BOUND_SRCADDR;
		if (options->ippo_flags & IPPOF_NO_IFF_EXPENSIVE)
			ip6oa.ip6oa_flags |= IP6OAF_NO_EXPENSIVE;
	}

	bzero(&ro, sizeof(struct route_in6));

	/*
	 * Send  mbuf and ifscope information. Check for correctness
	 * of ifscope information is done while searching for a route in
	 * ip6_output.
	 */
	error = ip6_output(m, NULL, &ro, IPV6_OUTARGS, im6o, NULL, &ip6oa);

	/* Release the route */
	ROUTE_RELEASE(&ro);

	if (im6o != NULL)
		IM6O_REMREF(im6o);

	return (error);
}
#endif /* INET6 */

errno_t
ipf_inject_output(
	mbuf_t data,
	ipfilter_t filter_ref,
	ipf_pktopts_t options)
{
	struct mbuf	*m = (struct mbuf *)data;
	u_int8_t	vers;
	errno_t		error = 0;

	/* Make one byte of the header contiguous in the mbuf */
	if (m->m_len < 1) {
		m = m_pullup(m, 1);
		if (m == NULL)
			goto done;
	}

	vers = (*(u_int8_t *)m_mtod(m)) >> 4;
	switch (vers) {
		case 4:
			error = ipf_injectv4_out(data, filter_ref, options);
			break;
#if INET6
		case 6:
			error = ipf_injectv6_out(data, filter_ref, options);
			break;
#endif
		default:
			m_freem(m);
			error = ENOTSUP;
			break;
	}

done:
	return (error);
}

__private_extern__ ipfilter_t
ipf_get_inject_filter(struct mbuf *m)
{
	ipfilter_t filter_ref = 0;
	struct m_tag *mtag;

	mtag = m_tag_locate(m, KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_IPFILT, NULL);
	if (mtag) {
		filter_ref = *(ipfilter_t *)(mtag+1);

		m_tag_delete(m, mtag);
	}
	return (filter_ref);
}

__private_extern__ int
ipf_init(void)
{
	int error = 0;
	lck_grp_attr_t *grp_attributes = 0;
	lck_attr_t *lck_attributes = 0;
	lck_grp_t *lck_grp = 0;

	grp_attributes = lck_grp_attr_alloc_init();
	if (grp_attributes == 0) {
		printf("ipf_init: lck_grp_attr_alloc_init failed\n");
		error = ENOMEM;
		goto done;
	}

	lck_grp = lck_grp_alloc_init("IP Filter", grp_attributes);
	if (lck_grp == 0) {
		printf("ipf_init: lck_grp_alloc_init failed\n");
		error = ENOMEM;
		goto done;
	}

	lck_attributes = lck_attr_alloc_init();
	if (lck_attributes == 0) {
		printf("ipf_init: lck_attr_alloc_init failed\n");
		error = ENOMEM;
		goto done;
	}

	lck_mtx_init(kipf_lock, lck_grp, lck_attributes);

	done:
	if (lck_grp) {
		lck_grp_free(lck_grp);
		lck_grp = 0;
	}
	if (grp_attributes) {
		lck_grp_attr_free(grp_attributes);
		grp_attributes = 0;
	}
	if (lck_attributes) {
		lck_attr_free(lck_attributes);
		lck_attributes = 0;
	}

	return (error);
}
