/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#define _IP_VHL
#include <net/if_var.h>
#include <net/route.h>
#include <net/kpi_protocol.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>
#include <netinet/kpi_ipfilter_var.h>

/*
 * kipf_lock and kipf_ref protect the linkage of the list of IP filters
 * An IP filter can be removed only when kipf_ref is zero
 * If an IP filter cannot be removed because kipf_ref is not null, then 
 * the IP filter is marjed and kipf_delayed_remove is set so that when 
 * kipf_ref eventually goes down to zero, the IP filter is removed
 */
static lck_mtx_t *kipf_lock = 0;
static unsigned long kipf_ref = 0;
static unsigned long kipf_delayed_remove = 0;

__private_extern__ struct ipfilter_list	ipv4_filters = TAILQ_HEAD_INITIALIZER(ipv4_filters);
__private_extern__ struct ipfilter_list	ipv6_filters = TAILQ_HEAD_INITIALIZER(ipv6_filters);
__private_extern__ struct ipfilter_list	tbr_filters = TAILQ_HEAD_INITIALIZER(tbr_filters);

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
	const struct ipf_filter* filter,
	ipfilter_t *filter_ref,
	struct ipfilter_list *head)
{
	struct ipfilter	*new_filter;
	if (filter->name == NULL || (filter->ipf_input == NULL && filter->ipf_output == NULL))
		return EINVAL;
	
	MALLOC(new_filter, struct ipfilter*, sizeof(*new_filter), M_IFADDR, M_WAITOK);
	if (new_filter == NULL)
		return ENOMEM;
	
	lck_mtx_lock(kipf_lock);
	new_filter->ipf_filter = *filter;
	new_filter->ipf_head = head;
	
	/*
	 * 3957298
	 * Make sure third parties have a chance to filter packets before
	 * SharedIP. Always SharedIP at the end of the list.
	 */
	if (filter->name != NULL &&
		strcmp(filter->name, "com.apple.nke.SharedIP") == 0) {
		TAILQ_INSERT_TAIL(head, new_filter, ipf_link);
	}
	else {
		TAILQ_INSERT_HEAD(head, new_filter, ipf_link);
	}
	
	lck_mtx_unlock(kipf_lock);
	
	*filter_ref = (ipfilter_t)new_filter;
	return 0;
}

errno_t
ipf_addv4(
	const struct ipf_filter* filter,
	ipfilter_t *filter_ref)
{
	return ipf_add(filter, filter_ref, &ipv4_filters);
}

errno_t
ipf_addv6(
	const struct ipf_filter* filter,
	ipfilter_t *filter_ref)
{
	return ipf_add(filter, filter_ref, &ipv6_filters);
}

errno_t
ipf_remove(
	ipfilter_t filter_ref)
{
	struct ipfilter	*match = (struct ipfilter*)filter_ref;
	struct ipfilter_list *head;
	
	if (match == 0 || (match->ipf_head != &ipv4_filters && match->ipf_head != &ipv6_filters))
		return EINVAL;
	
	head = match->ipf_head;
	
	lck_mtx_lock(kipf_lock);
	TAILQ_FOREACH(match, head, ipf_link) {
		if (match == (struct ipfilter*)filter_ref) {
			ipf_detach_func ipf_detach = match->ipf_filter.ipf_detach;
			void* cookie = match->ipf_filter.cookie;
			
			/*
			 * Cannot detach when they are filters running
			 */
			if (kipf_ref) {
				kipf_delayed_remove++;
				TAILQ_INSERT_TAIL(&tbr_filters, match, ipf_tbr);
				match->ipf_filter.ipf_input = 0;
				match->ipf_filter.ipf_output = 0;
				lck_mtx_unlock(kipf_lock);
			} else {
				TAILQ_REMOVE(head, match, ipf_link);
				lck_mtx_unlock(kipf_lock);
				if (ipf_detach)
					ipf_detach(cookie);
				FREE(match, M_IFADDR);
			}
			return 0;
		}
	}
	lck_mtx_unlock(kipf_lock);
	
	return ENOENT;
}

int log_for_en1 = 0;

errno_t
ipf_inject_input(
	mbuf_t data,
	ipfilter_t filter_ref)
{
	struct mbuf	*m = (struct mbuf*)data;
	struct m_tag *mtag = 0;
	struct ip *ip = mtod(m, struct ip *);
	u_int8_t	vers;
	int hlen;
	errno_t error = 0;
	protocol_family_t proto;

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
		m->m_pkthdr.rcvif = ifunit("lo0");
		m->m_pkthdr.csum_data = 0;
		m->m_pkthdr.csum_flags = 0;
		if (vers == 4) {
			hlen = IP_VHL_HL(ip->ip_vhl) << 2;
			ip->ip_sum = 0;
			ip->ip_sum = in_cksum(m, hlen);
		}
	}
	if (filter_ref != 0) {
		mtag = m_tag_alloc(KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_IPFILT,
					 	   sizeof (ipfilter_t), M_NOWAIT);
		if (mtag == NULL) {
			error = ENOMEM;
			goto done;
		}	
		*(ipfilter_t*)(mtag+1) = filter_ref;
		m_tag_prepend(m, mtag);
	}
	
	error = proto_inject(proto, data);

done:
	return error;
}

static errno_t
ipf_injectv4_out(
	mbuf_t data,
	ipfilter_t filter_ref,
	ipf_pktopts_t options)
{
	struct route ro;
	struct sockaddr_in	*sin = (struct sockaddr_in*)&ro.ro_dst;
	struct ip	*ip;
	struct mbuf	*m = (struct mbuf*)data;
	errno_t error = 0;
	struct m_tag *mtag = 0;
	struct ip_moptions *imo = 0, ip_moptions;
	
	/* Make the IP header contiguous in the mbuf */
	if ((size_t)m->m_len < sizeof(struct ip)) {
		m = m_pullup(m, sizeof(struct ip));
		if (m == NULL) return ENOMEM;
	}
	ip = (struct ip*)m_mtod(m);
	
	if (filter_ref != 0) {
		mtag = m_tag_alloc(KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_IPFILT,
					 	   sizeof (ipfilter_t), M_NOWAIT);
		if (mtag == NULL) {
			m_freem(m);
			return ENOMEM;
		}
		*(ipfilter_t*)(mtag+1) = filter_ref;
		m_tag_prepend(m, mtag);
	}
	
	if (options && (options->ippo_flags & IPPOF_MCAST_OPTS)) {
		imo = &ip_moptions;
		
		bzero(imo, sizeof(struct ip6_moptions));
		imo->imo_multicast_ifp = options->ippo_mcast_ifnet;
		imo->imo_multicast_ttl = options->ippo_mcast_ttl;
		imo->imo_multicast_loop = options->ippo_mcast_loop;
	}
	
	/* Fill out a route structure and get a route */
	bzero(&ro, sizeof(struct route));
	sin->sin_len = sizeof(struct sockaddr_in);
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr = ip->ip_dst;
	rtalloc(&ro);
	if (ro.ro_rt == NULL) {
		m_freem(m);
		return ENETUNREACH;
	}
	
	/* Put ip_len and ip_off in host byte order, ip_output expects that */
	NTOHS(ip->ip_len);
	NTOHS(ip->ip_off);
	
	/* Send  */
	error = ip_output(m, NULL, &ro, IP_ALLOWBROADCAST | IP_RAWOUTPUT, imo);
	
	/* Release the route */
	if (ro.ro_rt)
		rtfree(ro.ro_rt);
	
	return error;
}

static errno_t
ipf_injectv6_out(
	mbuf_t data,
	ipfilter_t filter_ref,
	ipf_pktopts_t options)
{
	struct route_in6 ro;
	struct sockaddr_in6	*sin6 = &ro.ro_dst;
	struct ip6_hdr	*ip6;
	struct mbuf	*m = (struct mbuf*)data;
	errno_t error = 0;
	struct m_tag *mtag = 0;
	struct ip6_moptions *im6o = 0, ip6_moptions;
	
	/* Make the IP header contiguous in the mbuf */
	if ((size_t)m->m_len < sizeof(struct ip6_hdr)) {
		m = m_pullup(m, sizeof(struct ip6_hdr));
		if (m == NULL) return ENOMEM;
	}
	ip6 = (struct ip6_hdr*)m_mtod(m);

	if (filter_ref != 0) {
		mtag = m_tag_alloc(KERNEL_MODULE_TAG_ID, KERNEL_TAG_TYPE_IPFILT,
					 	   sizeof (ipfilter_t), M_NOWAIT);
		if (mtag == NULL) {
			m_freem(m);
			return ENOMEM;
		}
		*(ipfilter_t*)(mtag+1) = filter_ref;
		m_tag_prepend(m, mtag);
	}
	
	if (options && (options->ippo_flags & IPPOF_MCAST_OPTS)) {
		im6o = &ip6_moptions;
		
		bzero(im6o, sizeof(struct ip6_moptions));
		im6o->im6o_multicast_ifp = options->ippo_mcast_ifnet;
		im6o->im6o_multicast_hlim = options->ippo_mcast_ttl;
		im6o->im6o_multicast_loop = options->ippo_mcast_loop;
	}
	
	
	/* Fill out a route structure and get a route */
	bzero(&ro, sizeof(struct route_in6));
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr = ip6->ip6_dst;
#if 0
	/* This is breaks loopback multicast! */
	/* The scope ID should already at s6_addr16[1] */
	if (IN6_IS_SCOPE_LINKLOCAL(&ip6->ip6_dst)) {
		/* Hack, pull the scope_id out of the dest addr */
		sin6->sin6_scope_id = ntohs(ip6->ip6_dst.s6_addr16[1]);
		ip6->ip6_dst.s6_addr16[1] = 0;
	} else
		sin6->sin6_scope_id = 0;
#endif
	rtalloc((struct route*)&ro);
	if (ro.ro_rt == NULL) {
		m_freem(m);
		return ENETUNREACH;
	}
	
	/* Send  */
	error = ip6_output(m, NULL, &ro, 0, im6o, NULL, 0);
	
	/* Release the route */
	if (ro.ro_rt)
		rtfree(ro.ro_rt);
	
	return error;
}

errno_t
ipf_inject_output(
	mbuf_t data,
	ipfilter_t filter_ref,
	ipf_pktopts_t options)
{
	struct mbuf	*m = (struct mbuf*)data;
	u_int8_t	vers;
	errno_t		error = 0;

	/* Make one byte of the header contiguous in the mbuf */
	if (m->m_len < 1) {
		m = m_pullup(m, 1);
		if (m == NULL) 
			goto done;
	}
	
	vers = (*(u_int8_t*)m_mtod(m)) >> 4;
	switch (vers)
	{
		case 4:
			error = ipf_injectv4_out(data, filter_ref, options);
			break;
		case 6:
			error = ipf_injectv6_out(data, filter_ref, options);
			break;
		default:
			m_freem(m);
			error = ENOTSUP;
			break;
	}

done:	
	return error;
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
	return filter_ref;
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
	
	kipf_lock = lck_mtx_alloc_init(lck_grp, lck_attributes);
	if (kipf_lock == 0) {
		printf("ipf_init: lck_mtx_alloc_init failed\n");
		error = ENOMEM;
		goto done;
	}
	done:
	if (error != 0) {
		if (kipf_lock) {
			lck_mtx_free(kipf_lock, lck_grp);
			kipf_lock = 0;
		}
	}
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
	
	return error;
}
