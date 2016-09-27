/*
 * Copyright (c) 2010-2016 Apple Inc. All rights reserved.
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
#include <sys/sysctl.h>
#include <sys/queue.h>
#include <sys/priv.h>
#include <sys/protosw.h>

#include <kern/clock.h>
#include <kern/debug.h>

#include <libkern/libkern.h>
#include <libkern/OSMalloc.h>
#include <libkern/OSAtomic.h>
#include <libkern/locks.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/ntstat.h>

#include <netinet/ip_var.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_cc.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet6/in6_pcb.h>
#include <netinet6/in6_var.h>

__private_extern__ int	nstat_collect = 1;
SYSCTL_INT(_net, OID_AUTO, statistics, CTLFLAG_RW | CTLFLAG_LOCKED,
    &nstat_collect, 0, "Collect detailed statistics");

static int nstat_privcheck = 0;
SYSCTL_INT(_net, OID_AUTO, statistics_privcheck, CTLFLAG_RW | CTLFLAG_LOCKED,
    &nstat_privcheck, 0, "Entitlement check");

SYSCTL_NODE(_net, OID_AUTO, stats,
    CTLFLAG_RW|CTLFLAG_LOCKED, 0, "network statistics");

static int nstat_debug = 0;
SYSCTL_INT(_net_stats, OID_AUTO, debug, CTLFLAG_RW | CTLFLAG_LOCKED,
    &nstat_debug, 0, "");

static int nstat_sendspace = 2048;
SYSCTL_INT(_net_stats, OID_AUTO, sendspace, CTLFLAG_RW | CTLFLAG_LOCKED,
    &nstat_sendspace, 0, "");

static int nstat_recvspace = 8192;
SYSCTL_INT(_net_stats, OID_AUTO, recvspace, CTLFLAG_RW | CTLFLAG_LOCKED,
    &nstat_recvspace, 0, "");

static struct nstat_stats nstat_stats;
SYSCTL_STRUCT(_net_stats, OID_AUTO, stats, CTLFLAG_RD | CTLFLAG_LOCKED,
    &nstat_stats, nstat_stats, "");

enum
{
	NSTAT_FLAG_CLEANUP				= (1 << 0),
	NSTAT_FLAG_REQCOUNTS			= (1 << 1),
	NSTAT_FLAG_SUPPORTS_UPDATES		= (1 << 2),
	NSTAT_FLAG_SYSINFO_SUBSCRIBED	= (1 << 3),
};

#define QUERY_CONTINUATION_SRC_COUNT 100

typedef struct nstat_provider_filter
{
	u_int64_t			npf_flags;
	u_int64_t			npf_events;
	pid_t				npf_pid;
	uuid_t				npf_uuid;
} nstat_provider_filter;


typedef struct nstat_control_state
{
	struct nstat_control_state	*ncs_next;
	u_int32_t				ncs_watching;
	decl_lck_mtx_data(, mtx);
	kern_ctl_ref			ncs_kctl;
	u_int32_t				ncs_unit;
	nstat_src_ref_t			ncs_next_srcref;
	struct nstat_src		*ncs_srcs;
	mbuf_t					ncs_accumulated;
	u_int32_t				ncs_flags;
	nstat_provider_filter	ncs_provider_filters[NSTAT_PROVIDER_COUNT];
	/* state maintained for partial query requests */
	u_int64_t				ncs_context;
	u_int64_t				ncs_seq;
} nstat_control_state;

typedef struct nstat_provider
{
	struct nstat_provider	*next;
	nstat_provider_id_t		nstat_provider_id;
	size_t					nstat_descriptor_length;
	errno_t					(*nstat_lookup)(const void *data, u_int32_t length, nstat_provider_cookie_t *out_cookie);
	int						(*nstat_gone)(nstat_provider_cookie_t cookie);
	errno_t					(*nstat_counts)(nstat_provider_cookie_t cookie, struct nstat_counts *out_counts, int *out_gone);
	errno_t					(*nstat_watcher_add)(nstat_control_state *state);
	void					(*nstat_watcher_remove)(nstat_control_state *state);
	errno_t					(*nstat_copy_descriptor)(nstat_provider_cookie_t cookie, void *data, u_int32_t len);
	void					(*nstat_release)(nstat_provider_cookie_t cookie, boolean_t locked);
	bool    				(*nstat_reporting_allowed)(nstat_provider_cookie_t cookie, nstat_provider_filter *filter);
} nstat_provider;

typedef STAILQ_HEAD(, nstat_src)		stailq_head_nstat_src;
typedef STAILQ_ENTRY(nstat_src)			stailq_entry_nstat_src;

typedef TAILQ_HEAD(, nstat_tu_shadow)	tailq_head_tu_shadow;
typedef TAILQ_ENTRY(nstat_tu_shadow)	tailq_entry_tu_shadow;

typedef struct nstat_src
{
	struct nstat_src		*next;
	nstat_src_ref_t			srcref;
	nstat_provider			*provider;
	nstat_provider_cookie_t		cookie;
	uint32_t			filter;
	uint64_t			seq;
} nstat_src;

static errno_t		nstat_control_send_counts(nstat_control_state *,
			    nstat_src *, unsigned long long, u_int16_t, int *);
static int		nstat_control_send_description(nstat_control_state *state, nstat_src *src, u_int64_t context, u_int16_t hdr_flags);
static int nstat_control_send_update(nstat_control_state *state, nstat_src *src, u_int64_t context, u_int16_t hdr_flags, int *gone);
static errno_t		nstat_control_send_removed(nstat_control_state *, nstat_src *);
static errno_t		nstat_control_send_goodbye(nstat_control_state	*state, nstat_src *src);
static void		nstat_control_cleanup_source(nstat_control_state *state, nstat_src *src, boolean_t);
static bool		nstat_control_reporting_allowed(nstat_control_state *state, nstat_src *src);
static boolean_t	nstat_control_begin_query(nstat_control_state *state, const nstat_msg_hdr *hdrp);
static u_int16_t	nstat_control_end_query(nstat_control_state *state, nstat_src *last_src, boolean_t partial);
static void		nstat_ifnet_report_ecn_stats(void);

static u_int32_t	nstat_udp_watchers = 0;
static u_int32_t	nstat_userland_udp_watchers = 0;
static u_int32_t	nstat_tcp_watchers = 0;
static u_int32_t	nstat_userland_tcp_watchers = 0;

static void nstat_control_register(void);

/*
 * The lock order is as follows:
 *
 * socket_lock (inpcb)
 *     nstat_mtx
 *         state->mtx
 */
static volatile OSMallocTag	nstat_malloc_tag = NULL;
static nstat_control_state	*nstat_controls = NULL;
static uint64_t				nstat_idle_time = 0;
static decl_lck_mtx_data(, nstat_mtx);

/* some extern definitions */
extern void mbuf_report_peak_usage(void);
extern void tcp_report_stats(void);

static void
nstat_copy_sa_out(
	const struct sockaddr	*src,
	struct sockaddr			*dst,
	int						maxlen)
{
	if (src->sa_len > maxlen) return;

	bcopy(src, dst, src->sa_len);
	if (src->sa_family == AF_INET6 &&
		src->sa_len >= sizeof(struct sockaddr_in6))
	{
		struct sockaddr_in6	*sin6 = (struct sockaddr_in6*)(void *)dst;
		if (IN6_IS_SCOPE_EMBED(&sin6->sin6_addr))
		{
			if (sin6->sin6_scope_id == 0)
				sin6->sin6_scope_id = ntohs(sin6->sin6_addr.s6_addr16[1]);
			sin6->sin6_addr.s6_addr16[1] = 0;
		}
	}
}

static void
nstat_ip_to_sockaddr(
	const struct in_addr	*ip,
	u_int16_t				port,
	struct sockaddr_in		*sin,
	u_int32_t				maxlen)
{
	if (maxlen < sizeof(struct sockaddr_in))
		return;

	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);
	sin->sin_port = port;
	sin->sin_addr = *ip;
}

static void
nstat_ip6_to_sockaddr(
	const struct in6_addr	*ip6,
	u_int16_t				port,
	struct sockaddr_in6		*sin6,
	u_int32_t				maxlen)
{
	if (maxlen < sizeof(struct sockaddr_in6))
		return;

	sin6->sin6_family = AF_INET6;
	sin6->sin6_len = sizeof(*sin6);
	sin6->sin6_port = port;
	sin6->sin6_addr = *ip6;
	if (IN6_IS_SCOPE_EMBED(&sin6->sin6_addr))
	{
		sin6->sin6_scope_id = ntohs(sin6->sin6_addr.s6_addr16[1]);
		sin6->sin6_addr.s6_addr16[1] = 0;
	}
}

static u_int16_t
nstat_ifnet_to_flags(
	struct ifnet *ifp)
{
	u_int16_t flags = 0;
	u_int32_t functional_type = if_functional_type(ifp, FALSE);

	/* Panic if someone adds a functional type without updating ntstat. */
	VERIFY(0 <= functional_type && functional_type <= IFRTYPE_FUNCTIONAL_LAST);

	switch (functional_type)
	{
	case IFRTYPE_FUNCTIONAL_UNKNOWN:
		flags |= NSTAT_IFNET_IS_UNKNOWN_TYPE;
		break;
	case IFRTYPE_FUNCTIONAL_LOOPBACK:
		flags |= NSTAT_IFNET_IS_LOOPBACK;
		break;
	case IFRTYPE_FUNCTIONAL_WIRED:
		flags |= NSTAT_IFNET_IS_WIRED;
		break;
	case IFRTYPE_FUNCTIONAL_WIFI_INFRA:
		flags |= NSTAT_IFNET_IS_WIFI;
		break;
	case IFRTYPE_FUNCTIONAL_WIFI_AWDL:
		flags |= NSTAT_IFNET_IS_WIFI;
		flags |= NSTAT_IFNET_IS_AWDL;
		break;
	case IFRTYPE_FUNCTIONAL_CELLULAR:
		flags |= NSTAT_IFNET_IS_CELLULAR;
		break;
	}

	if (IFNET_IS_EXPENSIVE(ifp))
	{
		flags |= NSTAT_IFNET_IS_EXPENSIVE;
	}

	return flags;
}

static u_int16_t
nstat_inpcb_to_flags(
	const struct inpcb *inp)
{
	u_int16_t flags = 0;

	if ((inp != NULL ) && (inp->inp_last_outifp != NULL))
	{
		struct ifnet *ifp = inp->inp_last_outifp;
		flags = nstat_ifnet_to_flags(ifp);

		if (flags & NSTAT_IFNET_IS_CELLULAR)
		{
			if (inp->inp_socket != NULL &&
			    (inp->inp_socket->so_flags1 & SOF1_CELLFALLBACK))
				flags |= NSTAT_IFNET_VIA_CELLFALLBACK;
		}
	}
	else
	{
		flags = NSTAT_IFNET_IS_UNKNOWN_TYPE;
	}

	return flags;
}

#pragma mark -- Network Statistic Providers --

static errno_t nstat_control_source_add(u_int64_t context, nstat_control_state *state, nstat_provider *provider, nstat_provider_cookie_t cookie);
struct nstat_provider	*nstat_providers = NULL;

static struct nstat_provider*
nstat_find_provider_by_id(
	nstat_provider_id_t	id)
{
	struct nstat_provider	*provider;

	for (provider = nstat_providers; provider != NULL; provider = provider->next)
	{
		if (provider->nstat_provider_id == id)
			break;
	}

	return provider;
}

static errno_t
nstat_lookup_entry(
	nstat_provider_id_t		id,
	const void				*data,
	u_int32_t				length,
	nstat_provider			**out_provider,
	nstat_provider_cookie_t	*out_cookie)
{
	*out_provider = nstat_find_provider_by_id(id);
	if (*out_provider == NULL)
	{
		return ENOENT;
	}

	return (*out_provider)->nstat_lookup(data, length, out_cookie);
}

static void nstat_init_route_provider(void);
static void nstat_init_tcp_provider(void);
static void nstat_init_userland_tcp_provider(void);
static void nstat_init_udp_provider(void);
static void nstat_init_userland_udp_provider(void);
static void nstat_init_ifnet_provider(void);

__private_extern__ void
nstat_init(void)
{
	if (nstat_malloc_tag != NULL) return;

	OSMallocTag tag = OSMalloc_Tagalloc(NET_STAT_CONTROL_NAME, OSMT_DEFAULT);
	if (!OSCompareAndSwapPtr(NULL, tag, &nstat_malloc_tag))
	{
		OSMalloc_Tagfree(tag);
		tag = nstat_malloc_tag;
	}
	else
	{
		// we need to initialize other things, we do it here as this code path will only be hit once;
		nstat_init_route_provider();
		nstat_init_tcp_provider();
		nstat_init_userland_tcp_provider();
		nstat_init_udp_provider();
		nstat_init_userland_udp_provider();
		nstat_init_ifnet_provider();
		nstat_control_register();
	}
}

#pragma mark -- Aligned Buffer Allocation --

struct align_header
{
	u_int32_t	offset;
	u_int32_t	length;
};

static void*
nstat_malloc_aligned(
	u_int32_t	length,
	u_int8_t	alignment,
	OSMallocTag	tag)
{
	struct align_header	*hdr = NULL;
	u_int32_t	size = length + sizeof(*hdr) + alignment - 1;

	u_int8_t	*buffer = OSMalloc(size, tag);
	if (buffer == NULL) return NULL;

	u_int8_t	*aligned = buffer + sizeof(*hdr);
	aligned = (u_int8_t*)P2ROUNDUP(aligned, alignment);

	hdr = (struct align_header*)(void *)(aligned - sizeof(*hdr));
	hdr->offset = aligned - buffer;
	hdr->length = size;

	return aligned;
}

static void
nstat_free_aligned(
	void		*buffer,
	OSMallocTag	tag)
{
	struct align_header *hdr = (struct align_header*)(void *)((u_int8_t*)buffer - sizeof(*hdr));
	OSFree(((char*)buffer) - hdr->offset, hdr->length, tag);
}

#pragma mark -- Route Provider --

static nstat_provider	nstat_route_provider;

static errno_t
nstat_route_lookup(
	const void				*data,
	u_int32_t 				length,
	nstat_provider_cookie_t	*out_cookie)
{
	// rt_lookup doesn't take const params but it doesn't modify the parameters for
	// the lookup. So...we use a union to eliminate the warning.
	union
	{
		struct sockaddr *sa;
		const struct sockaddr *const_sa;
	} dst, mask;

	const nstat_route_add_param	*param = (const nstat_route_add_param*)data;
	*out_cookie = NULL;

	if (length < sizeof(*param))
	{
		return EINVAL;
	}

	if (param->dst.v4.sin_family == 0 ||
		param->dst.v4.sin_family > AF_MAX ||
		(param->mask.v4.sin_family != 0 && param->mask.v4.sin_family != param->dst.v4.sin_family))
	{
		return EINVAL;
	}

	if (param->dst.v4.sin_len > sizeof(param->dst) ||
		(param->mask.v4.sin_family && param->mask.v4.sin_len > sizeof(param->mask.v4.sin_len)))
	{
		return EINVAL;
	}
	if ((param->dst.v4.sin_family == AF_INET &&
	    param->dst.v4.sin_len < sizeof(struct sockaddr_in)) ||
	    (param->dst.v6.sin6_family == AF_INET6 &&
	    param->dst.v6.sin6_len < sizeof(struct sockaddr_in6)))
	{
		return EINVAL;
	}

	dst.const_sa = (const struct sockaddr*)&param->dst;
	mask.const_sa = param->mask.v4.sin_family ? (const struct sockaddr*)&param->mask : NULL;

	struct radix_node_head	*rnh = rt_tables[dst.sa->sa_family];
	if (rnh == NULL) return EAFNOSUPPORT;

	lck_mtx_lock(rnh_lock);
	struct rtentry *rt = rt_lookup(TRUE, dst.sa, mask.sa, rnh, param->ifindex);
	lck_mtx_unlock(rnh_lock);

	if (rt) *out_cookie = (nstat_provider_cookie_t)rt;

	return rt ? 0 : ENOENT;
}

static int
nstat_route_gone(
	nstat_provider_cookie_t	cookie)
{
	struct rtentry		*rt = (struct rtentry*)cookie;
	return ((rt->rt_flags & RTF_UP) == 0) ? 1 : 0;
}

static errno_t
nstat_route_counts(
	nstat_provider_cookie_t	cookie,
	struct nstat_counts		*out_counts,
	int						*out_gone)
{
	struct rtentry		*rt = (struct rtentry*)cookie;
	struct nstat_counts	*rt_stats = rt->rt_stats;

	if (out_gone) *out_gone = 0;

	if (out_gone && (rt->rt_flags & RTF_UP) == 0) *out_gone = 1;

	if (rt_stats)
	{
		atomic_get_64(out_counts->nstat_rxpackets, &rt_stats->nstat_rxpackets);
		atomic_get_64(out_counts->nstat_rxbytes, &rt_stats->nstat_rxbytes);
		atomic_get_64(out_counts->nstat_txpackets, &rt_stats->nstat_txpackets);
		atomic_get_64(out_counts->nstat_txbytes, &rt_stats->nstat_txbytes);
		out_counts->nstat_rxduplicatebytes = rt_stats->nstat_rxduplicatebytes;
		out_counts->nstat_rxoutoforderbytes = rt_stats->nstat_rxoutoforderbytes;
		out_counts->nstat_txretransmit = rt_stats->nstat_txretransmit;
		out_counts->nstat_connectattempts = rt_stats->nstat_connectattempts;
		out_counts->nstat_connectsuccesses = rt_stats->nstat_connectsuccesses;
		out_counts->nstat_min_rtt = rt_stats->nstat_min_rtt;
		out_counts->nstat_avg_rtt = rt_stats->nstat_avg_rtt;
		out_counts->nstat_var_rtt = rt_stats->nstat_var_rtt;
		out_counts->nstat_cell_rxbytes = out_counts->nstat_cell_txbytes = 0;
	}
	else
	{
		bzero(out_counts, sizeof(*out_counts));
	}

	return 0;
}

static void
nstat_route_release(
	nstat_provider_cookie_t cookie,
	__unused int locked)
{
	rtfree((struct rtentry*)cookie);
}

static u_int32_t	nstat_route_watchers = 0;

static int
nstat_route_walktree_add(
	struct radix_node	*rn,
	void				*context)
{
	errno_t	result = 0;
	struct rtentry *rt = (struct rtentry *)rn;
	nstat_control_state	*state	= (nstat_control_state*)context;

	lck_mtx_assert(rnh_lock, LCK_MTX_ASSERT_OWNED);

	/* RTF_UP can't change while rnh_lock is held */
	if ((rt->rt_flags & RTF_UP) != 0)
	{
		/* Clear RTPRF_OURS if the route is still usable */
		RT_LOCK(rt);
		if (rt_validate(rt)) {
			RT_ADDREF_LOCKED(rt);
			RT_UNLOCK(rt);
		} else {
			RT_UNLOCK(rt);
			rt = NULL;
		}

		/* Otherwise if RTF_CONDEMNED, treat it as if it were down */
		if (rt == NULL)
			return (0);

		result = nstat_control_source_add(0, state, &nstat_route_provider, rt);
		if (result != 0)
			rtfree_locked(rt);
	}

	return result;
}

static errno_t
nstat_route_add_watcher(
	nstat_control_state	*state)
{
	int i;
	errno_t result = 0;
	OSIncrementAtomic(&nstat_route_watchers);

	lck_mtx_lock(rnh_lock);
	for (i = 1; i < AF_MAX; i++)
	{
		struct radix_node_head *rnh;
		rnh = rt_tables[i];
		if (!rnh) continue;

		result = rnh->rnh_walktree(rnh, nstat_route_walktree_add, state);
		if (result != 0)
		{
			break;
		}
	}
	lck_mtx_unlock(rnh_lock);

	return result;
}

__private_extern__ void
nstat_route_new_entry(
	struct rtentry	*rt)
{
	if (nstat_route_watchers == 0)
		return;

	lck_mtx_lock(&nstat_mtx);
	if ((rt->rt_flags & RTF_UP) != 0)
	{
		nstat_control_state	*state;
		for (state = nstat_controls; state; state = state->ncs_next)
		{
			if ((state->ncs_watching & (1 << NSTAT_PROVIDER_ROUTE)) != 0)
			{
				// this client is watching routes
				// acquire a reference for the route
				RT_ADDREF(rt);

				// add the source, if that fails, release the reference
				if (nstat_control_source_add(0, state, &nstat_route_provider, rt) != 0)
					RT_REMREF(rt);
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);
}

static void
nstat_route_remove_watcher(
	__unused nstat_control_state	*state)
{
	OSDecrementAtomic(&nstat_route_watchers);
}

static errno_t
nstat_route_copy_descriptor(
	nstat_provider_cookie_t	cookie,
	void					*data,
	u_int32_t				len)
{
	nstat_route_descriptor	*desc = (nstat_route_descriptor*)data;
	if (len < sizeof(*desc))
	{
		return EINVAL;
	}
	bzero(desc, sizeof(*desc));

	struct rtentry	*rt = (struct rtentry*)cookie;
	desc->id = (uint64_t)VM_KERNEL_ADDRPERM(rt);
	desc->parent_id = (uint64_t)VM_KERNEL_ADDRPERM(rt->rt_parent);
	desc->gateway_id = (uint64_t)VM_KERNEL_ADDRPERM(rt->rt_gwroute);


	// key/dest
	struct sockaddr	*sa;
	if ((sa = rt_key(rt)))
		nstat_copy_sa_out(sa, &desc->dst.sa, sizeof(desc->dst));

	// mask
	if ((sa = rt_mask(rt)) && sa->sa_len <= sizeof(desc->mask))
		memcpy(&desc->mask, sa, sa->sa_len);

	// gateway
	if ((sa = rt->rt_gateway))
		nstat_copy_sa_out(sa, &desc->gateway.sa, sizeof(desc->gateway));

	if (rt->rt_ifp)
		desc->ifindex = rt->rt_ifp->if_index;

	desc->flags = rt->rt_flags;

	return 0;
}

static bool
nstat_route_reporting_allowed(nstat_provider_cookie_t cookie, nstat_provider_filter *filter)
{
	bool retval = true;

	if ((filter->npf_flags & NSTAT_FILTER_IFNET_FLAGS) != 0)
	{
		struct rtentry	*rt = (struct rtentry*)cookie;
		struct ifnet *ifp = rt->rt_ifp;

		if (ifp)
		{
			uint16_t interface_properties = nstat_ifnet_to_flags(ifp);

			if ((filter->npf_flags & interface_properties) == 0)
			{
				retval = false;
			}
		}
	}
	return retval;
}

static void
nstat_init_route_provider(void)
{
	bzero(&nstat_route_provider, sizeof(nstat_route_provider));
	nstat_route_provider.nstat_descriptor_length = sizeof(nstat_route_descriptor);
	nstat_route_provider.nstat_provider_id = NSTAT_PROVIDER_ROUTE;
	nstat_route_provider.nstat_lookup = nstat_route_lookup;
	nstat_route_provider.nstat_gone = nstat_route_gone;
	nstat_route_provider.nstat_counts = nstat_route_counts;
	nstat_route_provider.nstat_release = nstat_route_release;
	nstat_route_provider.nstat_watcher_add = nstat_route_add_watcher;
	nstat_route_provider.nstat_watcher_remove = nstat_route_remove_watcher;
	nstat_route_provider.nstat_copy_descriptor = nstat_route_copy_descriptor;
	nstat_route_provider.nstat_reporting_allowed = nstat_route_reporting_allowed;
	nstat_route_provider.next = nstat_providers;
	nstat_providers = &nstat_route_provider;
}

#pragma mark -- Route Collection --

static struct nstat_counts*
nstat_route_attach(
	struct rtentry	*rte)
{
	struct nstat_counts *result = rte->rt_stats;
	if (result) return result;

	if (nstat_malloc_tag == NULL) nstat_init();

	result = nstat_malloc_aligned(sizeof(*result), sizeof(u_int64_t), nstat_malloc_tag);
	if (!result) return result;

	bzero(result, sizeof(*result));

	if (!OSCompareAndSwapPtr(NULL, result, &rte->rt_stats))
	{
		nstat_free_aligned(result, nstat_malloc_tag);
		result = rte->rt_stats;
	}

	return result;
}

__private_extern__ void
nstat_route_detach(
	struct rtentry	*rte)
{
	if (rte->rt_stats)
	{
		nstat_free_aligned(rte->rt_stats, nstat_malloc_tag);
		rte->rt_stats = NULL;
	}
}

__private_extern__ void
nstat_route_connect_attempt(
	struct rtentry	*rte)
{
	while (rte)
	{
		struct nstat_counts*	stats = nstat_route_attach(rte);
		if (stats)
		{
			OSIncrementAtomic(&stats->nstat_connectattempts);
		}

		rte = rte->rt_parent;
	}
}

__private_extern__ void
nstat_route_connect_success(
	struct rtentry	*rte)
{
	// This route
	while (rte)
	{
		struct nstat_counts*	stats = nstat_route_attach(rte);
		if (stats)
		{
			OSIncrementAtomic(&stats->nstat_connectsuccesses);
		}

		rte = rte->rt_parent;
	}
}

__private_extern__ void
nstat_route_tx(
	struct rtentry	*rte,
	u_int32_t		packets,
	u_int32_t		bytes,
	u_int32_t		flags)
{
	while (rte)
	{
		struct nstat_counts*	stats = nstat_route_attach(rte);
		if (stats)
		{
			if ((flags & NSTAT_TX_FLAG_RETRANSMIT) != 0)
			{
				OSAddAtomic(bytes, &stats->nstat_txretransmit);
			}
			else
			{
				OSAddAtomic64((SInt64)packets, (SInt64*)&stats->nstat_txpackets);
				OSAddAtomic64((SInt64)bytes, (SInt64*)&stats->nstat_txbytes);
			}
		}

		rte = rte->rt_parent;
	}
}

__private_extern__ void
nstat_route_rx(
	struct rtentry	*rte,
	u_int32_t		packets,
	u_int32_t		bytes,
	u_int32_t		flags)
{
	while (rte)
	{
		struct nstat_counts*	stats = nstat_route_attach(rte);
		if (stats)
		{
			if (flags == 0)
			{
				OSAddAtomic64((SInt64)packets, (SInt64*)&stats->nstat_rxpackets);
				OSAddAtomic64((SInt64)bytes, (SInt64*)&stats->nstat_rxbytes);
			}
			else
			{
				if (flags & NSTAT_RX_FLAG_OUT_OF_ORDER)
					OSAddAtomic(bytes, &stats->nstat_rxoutoforderbytes);
				if (flags & NSTAT_RX_FLAG_DUPLICATE)
					OSAddAtomic(bytes, &stats->nstat_rxduplicatebytes);
			}
		}

		rte = rte->rt_parent;
	}
}

__private_extern__ void
nstat_route_rtt(
	struct rtentry	*rte,
	u_int32_t		rtt,
	u_int32_t		rtt_var)
{
	const int32_t	factor = 8;

	while (rte)
	{
		struct nstat_counts*	stats = nstat_route_attach(rte);
		if (stats)
		{
			int32_t	oldrtt;
			int32_t	newrtt;

			// average
			do
			{
				oldrtt = stats->nstat_avg_rtt;
				if (oldrtt == 0)
				{
					newrtt = rtt;
				}
				else
				{
					newrtt = oldrtt - (oldrtt - (int32_t)rtt) / factor;
				}
				if (oldrtt == newrtt) break;
			} while (!OSCompareAndSwap(oldrtt, newrtt, &stats->nstat_avg_rtt));

			// minimum
			do
			{
				oldrtt = stats->nstat_min_rtt;
				if (oldrtt != 0 && oldrtt < (int32_t)rtt)
				{
					break;
				}
			} while (!OSCompareAndSwap(oldrtt, rtt, &stats->nstat_min_rtt));

			// variance
			do
			{
				oldrtt = stats->nstat_var_rtt;
				if (oldrtt == 0)
				{
					newrtt = rtt_var;
				}
				else
				{
					newrtt = oldrtt - (oldrtt - (int32_t)rtt_var) / factor;
				}
				if (oldrtt == newrtt) break;
			} while (!OSCompareAndSwap(oldrtt, newrtt, &stats->nstat_var_rtt));
		}

		rte = rte->rt_parent;
	}
}


#pragma mark -- TCP Kernel Provider --

/*
 * Due to the way the kernel deallocates a process (the process structure
 * might be gone by the time we get the PCB detach notification),
 * we need to cache the process name. Without this, proc_name() would
 * return null and the process name would never be sent to userland.
 *
 * For UDP sockets, we also store the cached the connection tuples along with
 * the interface index. This is necessary because when UDP sockets are
 * disconnected, the connection tuples are forever lost from the inpcb, thus
 * we need to keep track of the last call to connect() in ntstat.
 */
struct nstat_tucookie {
	struct inpcb 	*inp;
	char		pname[MAXCOMLEN+1];
	bool		cached;
	union
	{
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} local;
	union
	{
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} remote;
	unsigned int	if_index;
	uint16_t	ifnet_properties;
};

static struct nstat_tucookie *
nstat_tucookie_alloc_internal(
    struct inpcb *inp,
    bool	  ref,
    bool	  locked)
{
	struct nstat_tucookie *cookie;

	cookie = OSMalloc(sizeof(*cookie), nstat_malloc_tag);
	if (cookie == NULL)
		return NULL;
	if (!locked)
		lck_mtx_assert(&nstat_mtx, LCK_MTX_ASSERT_NOTOWNED);
	if (ref && in_pcb_checkstate(inp, WNT_ACQUIRE, locked) == WNT_STOPUSING)
	{
		OSFree(cookie, sizeof(*cookie), nstat_malloc_tag);
		return NULL;
	}
	bzero(cookie, sizeof(*cookie));
	cookie->inp = inp;
	proc_name(inp->inp_socket->last_pid, cookie->pname,
	    sizeof(cookie->pname));
	/*
	 * We only increment the reference count for UDP sockets because we
	 * only cache UDP socket tuples.
	 */
	if (SOCK_PROTO(inp->inp_socket) == IPPROTO_UDP)
		OSIncrementAtomic(&inp->inp_nstat_refcnt);

	return cookie;
}

static struct nstat_tucookie *
nstat_tucookie_alloc(
    struct inpcb *inp)
{
	return nstat_tucookie_alloc_internal(inp, false, false);
}

static struct nstat_tucookie *
nstat_tucookie_alloc_ref(
    struct inpcb *inp)
{
	return nstat_tucookie_alloc_internal(inp, true, false);
}

static struct nstat_tucookie *
nstat_tucookie_alloc_ref_locked(
    struct inpcb *inp)
{
	return nstat_tucookie_alloc_internal(inp, true, true);
}

static void
nstat_tucookie_release_internal(
    struct nstat_tucookie *cookie,
    int				inplock)
{
	if (SOCK_PROTO(cookie->inp->inp_socket) == IPPROTO_UDP)
		OSDecrementAtomic(&cookie->inp->inp_nstat_refcnt);
	in_pcb_checkstate(cookie->inp, WNT_RELEASE, inplock);
	OSFree(cookie, sizeof(*cookie), nstat_malloc_tag);
}

static void
nstat_tucookie_release(
    struct nstat_tucookie *cookie)
{
	nstat_tucookie_release_internal(cookie, false);
}

static void
nstat_tucookie_release_locked(
    struct nstat_tucookie *cookie)
{
	nstat_tucookie_release_internal(cookie, true);
}


static nstat_provider	nstat_tcp_provider;

static errno_t
nstat_tcpudp_lookup(
	struct inpcbinfo	*inpinfo,
	const void		*data,
	u_int32_t 		length,
	nstat_provider_cookie_t	*out_cookie)
{
	struct inpcb *inp = NULL;

	// parameter validation
	const nstat_tcp_add_param	*param = (const nstat_tcp_add_param*)data;
	if (length < sizeof(*param))
	{
		return EINVAL;
	}

	// src and dst must match
	if (param->remote.v4.sin_family != 0 &&
		param->remote.v4.sin_family != param->local.v4.sin_family)
	{
		return EINVAL;
	}


	switch (param->local.v4.sin_family)
	{
		case AF_INET:
		{
			if (param->local.v4.sin_len != sizeof(param->local.v4) ||
		  		(param->remote.v4.sin_family != 0 &&
		  		 param->remote.v4.sin_len != sizeof(param->remote.v4)))
		  	{
				return EINVAL;
		  	}

			inp = in_pcblookup_hash(inpinfo, param->remote.v4.sin_addr, param->remote.v4.sin_port,
						param->local.v4.sin_addr, param->local.v4.sin_port, 1, NULL);
		}
		break;

#if INET6
		case AF_INET6:
		{
			union
			{
				const struct in6_addr 	*in6c;
				struct in6_addr			*in6;
			} local, remote;

			if (param->local.v6.sin6_len != sizeof(param->local.v6) ||
		  		(param->remote.v6.sin6_family != 0 &&
				 param->remote.v6.sin6_len != sizeof(param->remote.v6)))
			{
				return EINVAL;
			}

			local.in6c = &param->local.v6.sin6_addr;
			remote.in6c = &param->remote.v6.sin6_addr;

			inp = in6_pcblookup_hash(inpinfo, remote.in6, param->remote.v6.sin6_port,
						local.in6, param->local.v6.sin6_port, 1, NULL);
		}
		break;
#endif

		default:
			return EINVAL;
	}

	if (inp == NULL)
		return ENOENT;

	// At this point we have a ref to the inpcb
	*out_cookie = nstat_tucookie_alloc(inp);
	if (*out_cookie == NULL)
		in_pcb_checkstate(inp, WNT_RELEASE, 0);

	return 0;
}

static errno_t
nstat_tcp_lookup(
	const void				*data,
	u_int32_t 				length,
	nstat_provider_cookie_t	*out_cookie)
{
	return nstat_tcpudp_lookup(&tcbinfo, data, length, out_cookie);
}

static int
nstat_tcp_gone(
	nstat_provider_cookie_t	cookie)
{
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;
	struct inpcb *inp;
	struct tcpcb *tp;

	return (!(inp = tucookie->inp) ||
	    !(tp = intotcpcb(inp)) ||
	    inp->inp_state == INPCB_STATE_DEAD) ? 1 : 0;
}

static errno_t
nstat_tcp_counts(
	nstat_provider_cookie_t	cookie,
	struct nstat_counts		*out_counts,
	int						*out_gone)
{
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;
	struct inpcb *inp;

	bzero(out_counts, sizeof(*out_counts));

	if (out_gone) *out_gone = 0;

	// if the pcb is in the dead state, we should stop using it
	if (nstat_tcp_gone(cookie))
	{
		if (out_gone) *out_gone = 1;
		if (!(inp = tucookie->inp) || !intotcpcb(inp))
			return EINVAL;
	}
	inp = tucookie->inp;
	struct tcpcb *tp = intotcpcb(inp);

	atomic_get_64(out_counts->nstat_rxpackets, &inp->inp_stat->rxpackets);
	atomic_get_64(out_counts->nstat_rxbytes, &inp->inp_stat->rxbytes);
	atomic_get_64(out_counts->nstat_txpackets, &inp->inp_stat->txpackets);
	atomic_get_64(out_counts->nstat_txbytes, &inp->inp_stat->txbytes);
	out_counts->nstat_rxduplicatebytes = tp->t_stat.rxduplicatebytes;
	out_counts->nstat_rxoutoforderbytes = tp->t_stat.rxoutoforderbytes;
	out_counts->nstat_txretransmit = tp->t_stat.txretransmitbytes;
	out_counts->nstat_connectattempts = tp->t_state >= TCPS_SYN_SENT ? 1 : 0;
	out_counts->nstat_connectsuccesses = tp->t_state >= TCPS_ESTABLISHED ? 1 : 0;
	out_counts->nstat_avg_rtt = tp->t_srtt;
	out_counts->nstat_min_rtt = tp->t_rttbest;
	out_counts->nstat_var_rtt = tp->t_rttvar;
	if (out_counts->nstat_avg_rtt < out_counts->nstat_min_rtt)
		out_counts->nstat_min_rtt = out_counts->nstat_avg_rtt;
	atomic_get_64(out_counts->nstat_cell_rxbytes, &inp->inp_cstat->rxbytes);
	atomic_get_64(out_counts->nstat_cell_txbytes, &inp->inp_cstat->txbytes);
	atomic_get_64(out_counts->nstat_wifi_rxbytes, &inp->inp_wstat->rxbytes);
	atomic_get_64(out_counts->nstat_wifi_txbytes, &inp->inp_wstat->txbytes);
	atomic_get_64(out_counts->nstat_wired_rxbytes, &inp->inp_Wstat->rxbytes);
	atomic_get_64(out_counts->nstat_wired_txbytes, &inp->inp_Wstat->txbytes);

	return 0;
}

static void
nstat_tcp_release(
	nstat_provider_cookie_t	cookie,
	int locked)
{
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;

	nstat_tucookie_release_internal(tucookie, locked);
}

static errno_t
nstat_tcp_add_watcher(
	nstat_control_state	*state)
{
	OSIncrementAtomic(&nstat_tcp_watchers);

	lck_rw_lock_shared(tcbinfo.ipi_lock);

	// Add all current tcp inpcbs. Ignore those in timewait
	struct inpcb *inp;
	struct nstat_tucookie *cookie;
	LIST_FOREACH(inp, tcbinfo.ipi_listhead, inp_list)
	{
		cookie = nstat_tucookie_alloc_ref(inp);
		if (cookie == NULL)
			continue;
		if (nstat_control_source_add(0, state, &nstat_tcp_provider,
		    cookie) != 0)
		{
			nstat_tucookie_release(cookie);
			break;
		}
	}

	lck_rw_done(tcbinfo.ipi_lock);

	return 0;
}

static void
nstat_tcp_remove_watcher(
	__unused nstat_control_state	*state)
{
	OSDecrementAtomic(&nstat_tcp_watchers);
}

__private_extern__ void
nstat_tcp_new_pcb(
	struct inpcb	*inp)
{
	struct nstat_tucookie *cookie;

	if (nstat_tcp_watchers == 0)
		return;

	socket_lock(inp->inp_socket, 0);
	lck_mtx_lock(&nstat_mtx);
	nstat_control_state	*state;
	for (state = nstat_controls; state; state = state->ncs_next)
	{
		if ((state->ncs_watching & (1 << NSTAT_PROVIDER_TCP_KERNEL)) != 0)
		{
			// this client is watching tcp
			// acquire a reference for it
			cookie = nstat_tucookie_alloc_ref_locked(inp);
			if (cookie == NULL)
				continue;
			// add the source, if that fails, release the reference
			if (nstat_control_source_add(0, state,
			    &nstat_tcp_provider, cookie) != 0)
			{
				nstat_tucookie_release_locked(cookie);
				break;
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);
	socket_unlock(inp->inp_socket, 0);
}

__private_extern__ void
nstat_pcb_detach(struct inpcb *inp)
{
	nstat_control_state *state;
	nstat_src *src, *prevsrc;
	nstat_src *dead_list = NULL;
	struct nstat_tucookie *tucookie;
	errno_t result;

	if (inp == NULL || (nstat_tcp_watchers == 0 && nstat_udp_watchers == 0))
		return;

	lck_mtx_lock(&nstat_mtx);
	for (state = nstat_controls; state; state = state->ncs_next)
	{
		lck_mtx_lock(&state->mtx);
		for (prevsrc = NULL, src = state->ncs_srcs; src;
		    prevsrc = src, src = src->next)
		{
			tucookie = (struct nstat_tucookie *)src->cookie;
			if (tucookie->inp == inp)
				break;
		}

		if (src)
		{
			result = nstat_control_send_goodbye(state, src);

			if (prevsrc)
				prevsrc->next = src->next;
			else
				state->ncs_srcs = src->next;

			src->next = dead_list;
			dead_list = src;
		}
		lck_mtx_unlock(&state->mtx);
	}
	lck_mtx_unlock(&nstat_mtx);

	while (dead_list) {
		src = dead_list;
		dead_list = src->next;

		nstat_control_cleanup_source(NULL, src, TRUE);
	}
}

__private_extern__ void
nstat_pcb_cache(struct inpcb *inp)
{
	nstat_control_state *state;
	nstat_src *src;
	struct nstat_tucookie *tucookie;

	if (inp == NULL || nstat_udp_watchers == 0 ||
	    inp->inp_nstat_refcnt == 0)
		return;
	VERIFY(SOCK_PROTO(inp->inp_socket) == IPPROTO_UDP);
	lck_mtx_lock(&nstat_mtx);
	for (state = nstat_controls; state; state = state->ncs_next) {
		lck_mtx_lock(&state->mtx);
		for (src = state->ncs_srcs; src; src = src->next)
		{
			tucookie = (struct nstat_tucookie *)src->cookie;
			if (tucookie->inp == inp)
			{
				if (inp->inp_vflag & INP_IPV6)
				{
					nstat_ip6_to_sockaddr(&inp->in6p_laddr,
					    inp->inp_lport,
					    &tucookie->local.v6,
					    sizeof(tucookie->local));
					nstat_ip6_to_sockaddr(&inp->in6p_faddr,
					    inp->inp_fport,
					    &tucookie->remote.v6,
					    sizeof(tucookie->remote));
				}
				else if (inp->inp_vflag & INP_IPV4)
				{
					nstat_ip_to_sockaddr(&inp->inp_laddr,
					    inp->inp_lport,
					    &tucookie->local.v4,
					    sizeof(tucookie->local));
					nstat_ip_to_sockaddr(&inp->inp_faddr,
					    inp->inp_fport,
					    &tucookie->remote.v4,
					    sizeof(tucookie->remote));
				}
				if (inp->inp_last_outifp)
					tucookie->if_index =
					    inp->inp_last_outifp->if_index;

				tucookie->ifnet_properties = nstat_inpcb_to_flags(inp);
				tucookie->cached = true;
				break;
			}
		}
		lck_mtx_unlock(&state->mtx);
	}
	lck_mtx_unlock(&nstat_mtx);
}

__private_extern__ void
nstat_pcb_invalidate_cache(struct inpcb *inp)
{
	nstat_control_state *state;
	nstat_src *src;
	struct nstat_tucookie *tucookie;

	if (inp == NULL || nstat_udp_watchers == 0 ||
	    inp->inp_nstat_refcnt == 0)
		return;
	VERIFY(SOCK_PROTO(inp->inp_socket) == IPPROTO_UDP);
	lck_mtx_lock(&nstat_mtx);
	for (state = nstat_controls; state; state = state->ncs_next) {
		lck_mtx_lock(&state->mtx);
		for (src = state->ncs_srcs; src; src = src->next)
		{
			tucookie = (struct nstat_tucookie *)src->cookie;
			if (tucookie->inp == inp)
			{
				tucookie->cached = false;
				break;
			}
		}
		lck_mtx_unlock(&state->mtx);
	}
	lck_mtx_unlock(&nstat_mtx);
}

static errno_t
nstat_tcp_copy_descriptor(
	nstat_provider_cookie_t	cookie,
	void			*data,
	u_int32_t		len)
{
	if (len < sizeof(nstat_tcp_descriptor))
	{
		return EINVAL;
	}

	if (nstat_tcp_gone(cookie))
		return EINVAL;

	nstat_tcp_descriptor	*desc = (nstat_tcp_descriptor*)data;
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;
	struct inpcb		*inp = tucookie->inp;
	struct tcpcb		*tp = intotcpcb(inp);
	bzero(desc, sizeof(*desc));

	if (inp->inp_vflag & INP_IPV6)
	{
		nstat_ip6_to_sockaddr(&inp->in6p_laddr, inp->inp_lport,
			&desc->local.v6, sizeof(desc->local));
		nstat_ip6_to_sockaddr(&inp->in6p_faddr, inp->inp_fport,
			&desc->remote.v6, sizeof(desc->remote));
	}
	else if (inp->inp_vflag & INP_IPV4)
	{
		nstat_ip_to_sockaddr(&inp->inp_laddr, inp->inp_lport,
			&desc->local.v4, sizeof(desc->local));
		nstat_ip_to_sockaddr(&inp->inp_faddr, inp->inp_fport,
			&desc->remote.v4, sizeof(desc->remote));
	}

	desc->state = intotcpcb(inp)->t_state;
	desc->ifindex = (inp->inp_last_outifp == NULL) ? 0 :
	    inp->inp_last_outifp->if_index;

	// danger - not locked, values could be bogus
	desc->txunacked = tp->snd_max - tp->snd_una;
	desc->txwindow = tp->snd_wnd;
	desc->txcwindow = tp->snd_cwnd;

	if (CC_ALGO(tp)->name != NULL) {
		strlcpy(desc->cc_algo, CC_ALGO(tp)->name,
		    sizeof(desc->cc_algo));
	}

	struct socket *so = inp->inp_socket;
	if (so)
	{
		// TBD - take the socket lock around these to make sure
		// they're in sync?
		desc->upid = so->last_upid;
		desc->pid = so->last_pid;
		desc->traffic_class = so->so_traffic_class;
		if ((so->so_flags1 & SOF1_TRAFFIC_MGT_SO_BACKGROUND))
			desc->traffic_mgt_flags |= TRAFFIC_MGT_SO_BACKGROUND;
		if ((so->so_flags1 & SOF1_TRAFFIC_MGT_TCP_RECVBG))
			desc->traffic_mgt_flags |= TRAFFIC_MGT_TCP_RECVBG;
		proc_name(desc->pid, desc->pname, sizeof(desc->pname));
		if (desc->pname[0] == 0)
		{
			strlcpy(desc->pname, tucookie->pname,
			    sizeof(desc->pname));
		}
		else
		{
			desc->pname[sizeof(desc->pname) - 1] = 0;
			strlcpy(tucookie->pname, desc->pname,
			    sizeof(tucookie->pname));
		}
		memcpy(desc->uuid, so->last_uuid, sizeof(so->last_uuid));
		memcpy(desc->vuuid, so->so_vuuid, sizeof(so->so_vuuid));
		if (so->so_flags & SOF_DELEGATED) {
			desc->eupid = so->e_upid;
			desc->epid = so->e_pid;
			memcpy(desc->euuid, so->e_uuid, sizeof(so->e_uuid));
		} else {
			desc->eupid = desc->upid;
			desc->epid = desc->pid;
			memcpy(desc->euuid, desc->uuid, sizeof(desc->uuid));
		}
		desc->sndbufsize = so->so_snd.sb_hiwat;
		desc->sndbufused = so->so_snd.sb_cc;
		desc->rcvbufsize = so->so_rcv.sb_hiwat;
		desc->rcvbufused = so->so_rcv.sb_cc;
	}

	tcp_get_connectivity_status(tp, &desc->connstatus);
	desc->ifnet_properties = nstat_inpcb_to_flags(inp);
	return 0;
}

static bool
nstat_tcpudp_reporting_allowed(nstat_provider_cookie_t cookie, nstat_provider_filter *filter, bool is_UDP)
{
	bool retval = true;

	if ((filter->npf_flags & (NSTAT_FILTER_IFNET_FLAGS|NSTAT_FILTER_SPECIFIC_USER)) != 0)
	{
		struct nstat_tucookie *tucookie = (struct nstat_tucookie *)cookie;
		struct inpcb *inp = tucookie->inp;

		/* Only apply interface filter if at least one is allowed. */
		if ((filter->npf_flags & NSTAT_FILTER_IFNET_FLAGS) != 0)
		{
			uint16_t interface_properties = nstat_inpcb_to_flags(inp);

			if ((filter->npf_flags & interface_properties) == 0)
			{
				// For UDP, we could have an undefined interface and yet transfers may have occurred.
				// We allow reporting if there have been transfers of the requested kind.
				// This is imperfect as we cannot account for the expensive attribute over wifi.
				// We also assume that cellular is expensive and we have no way to select for AWDL
				if (is_UDP)
				{
					do
					{
						if ((filter->npf_flags & (NSTAT_FILTER_ACCEPT_CELLULAR|NSTAT_FILTER_ACCEPT_EXPENSIVE)) &&
							(inp->inp_cstat->rxbytes || inp->inp_cstat->txbytes))
						{
							break;
						}
						if ((filter->npf_flags & NSTAT_FILTER_ACCEPT_WIFI) &&
							(inp->inp_wstat->rxbytes || inp->inp_wstat->txbytes))
						{
							break;
						}
						if ((filter->npf_flags & NSTAT_FILTER_ACCEPT_WIRED) &&
							(inp->inp_Wstat->rxbytes || inp->inp_Wstat->txbytes))
						{
							break;
						}
						return false;
					} while (0);
				}
				else
				{
					return false;
				}
			}
		}

		if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER) != 0) && (retval))
		{
			struct socket *so = inp->inp_socket;
			retval = false;

			if (so)
			{
				if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_PID) != 0) &&
					(filter->npf_pid == so->last_pid))
				{
					retval = true;
				}
				else if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_EPID) != 0) &&
					(filter->npf_pid == (so->so_flags & SOF_DELEGATED)? so->e_upid : so->last_pid))
				{
					retval = true;
				}
				else if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_UUID) != 0) &&
					(memcmp(filter->npf_uuid, so->last_uuid, sizeof(so->last_uuid)) == 0))
				{
					retval = true;
				}
				else if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_EUUID) != 0) &&
					(memcmp(filter->npf_uuid, (so->so_flags & SOF_DELEGATED)? so->e_uuid : so->last_uuid,
						sizeof(so->last_uuid)) == 0))
				{
					retval = true;
				}
			}
		}
	}
	return retval;
}

static bool
nstat_tcp_reporting_allowed(nstat_provider_cookie_t cookie, nstat_provider_filter *filter)
{
	return nstat_tcpudp_reporting_allowed(cookie, filter, FALSE);
}

static void
nstat_init_tcp_provider(void)
{
	bzero(&nstat_tcp_provider, sizeof(nstat_tcp_provider));
	nstat_tcp_provider.nstat_descriptor_length = sizeof(nstat_tcp_descriptor);
	nstat_tcp_provider.nstat_provider_id = NSTAT_PROVIDER_TCP_KERNEL;
	nstat_tcp_provider.nstat_lookup = nstat_tcp_lookup;
	nstat_tcp_provider.nstat_gone = nstat_tcp_gone;
	nstat_tcp_provider.nstat_counts = nstat_tcp_counts;
	nstat_tcp_provider.nstat_release = nstat_tcp_release;
	nstat_tcp_provider.nstat_watcher_add = nstat_tcp_add_watcher;
	nstat_tcp_provider.nstat_watcher_remove = nstat_tcp_remove_watcher;
	nstat_tcp_provider.nstat_copy_descriptor = nstat_tcp_copy_descriptor;
	nstat_tcp_provider.nstat_reporting_allowed = nstat_tcp_reporting_allowed;
	nstat_tcp_provider.next = nstat_providers;
	nstat_providers = &nstat_tcp_provider;
}

#pragma mark -- UDP Provider --

static nstat_provider	nstat_udp_provider;

static errno_t
nstat_udp_lookup(
	const void				*data,
	u_int32_t 				length,
	nstat_provider_cookie_t	*out_cookie)
{
	return nstat_tcpudp_lookup(&udbinfo, data, length, out_cookie);
}

static int
nstat_udp_gone(
	nstat_provider_cookie_t	cookie)
{
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;
	struct inpcb *inp;

	return (!(inp = tucookie->inp) ||
		inp->inp_state == INPCB_STATE_DEAD) ? 1 : 0;
}

static errno_t
nstat_udp_counts(
	nstat_provider_cookie_t	cookie,
	struct nstat_counts	*out_counts,
	int			*out_gone)
{
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;

	if (out_gone) *out_gone = 0;

	// if the pcb is in the dead state, we should stop using it
	if (nstat_udp_gone(cookie))
	{
		if (out_gone) *out_gone = 1;
		if (!tucookie->inp)
			return EINVAL;
	}
	struct inpcb *inp = tucookie->inp;

	atomic_get_64(out_counts->nstat_rxpackets, &inp->inp_stat->rxpackets);
	atomic_get_64(out_counts->nstat_rxbytes, &inp->inp_stat->rxbytes);
	atomic_get_64(out_counts->nstat_txpackets, &inp->inp_stat->txpackets);
	atomic_get_64(out_counts->nstat_txbytes, &inp->inp_stat->txbytes);
	atomic_get_64(out_counts->nstat_cell_rxbytes, &inp->inp_cstat->rxbytes);
	atomic_get_64(out_counts->nstat_cell_txbytes, &inp->inp_cstat->txbytes);
	atomic_get_64(out_counts->nstat_wifi_rxbytes, &inp->inp_wstat->rxbytes);
	atomic_get_64(out_counts->nstat_wifi_txbytes, &inp->inp_wstat->txbytes);
	atomic_get_64(out_counts->nstat_wired_rxbytes, &inp->inp_Wstat->rxbytes);
	atomic_get_64(out_counts->nstat_wired_txbytes, &inp->inp_Wstat->txbytes);

	return 0;
}

static void
nstat_udp_release(
	nstat_provider_cookie_t	cookie,
	int locked)
{
	struct nstat_tucookie *tucookie =
	    (struct nstat_tucookie *)cookie;

	nstat_tucookie_release_internal(tucookie, locked);
}

static errno_t
nstat_udp_add_watcher(
	nstat_control_state	*state)
{
	struct inpcb *inp;
	struct nstat_tucookie *cookie;

	OSIncrementAtomic(&nstat_udp_watchers);

	lck_rw_lock_shared(udbinfo.ipi_lock);
	// Add all current UDP inpcbs.
	LIST_FOREACH(inp, udbinfo.ipi_listhead, inp_list)
	{
		cookie = nstat_tucookie_alloc_ref(inp);
		if (cookie == NULL)
			continue;
		if (nstat_control_source_add(0, state, &nstat_udp_provider,
		    cookie) != 0)
		{
			nstat_tucookie_release(cookie);
			break;
		}
	}

	lck_rw_done(udbinfo.ipi_lock);

	return 0;
}

static void
nstat_udp_remove_watcher(
	__unused nstat_control_state	*state)
{
	OSDecrementAtomic(&nstat_udp_watchers);
}

__private_extern__ void
nstat_udp_new_pcb(
	struct inpcb	*inp)
{
	struct nstat_tucookie *cookie;

	if (nstat_udp_watchers == 0)
		return;

	socket_lock(inp->inp_socket, 0);
	lck_mtx_lock(&nstat_mtx);
	nstat_control_state	*state;
	for (state = nstat_controls; state; state = state->ncs_next)
	{
		if ((state->ncs_watching & (1 << NSTAT_PROVIDER_UDP_KERNEL)) != 0)
		{
			// this client is watching tcp
			// acquire a reference for it
			cookie = nstat_tucookie_alloc_ref_locked(inp);
			if (cookie == NULL)
				continue;
			// add the source, if that fails, release the reference
			if (nstat_control_source_add(0, state,
			    &nstat_udp_provider, cookie) != 0)
			{
				nstat_tucookie_release_locked(cookie);
				break;
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);
	socket_unlock(inp->inp_socket, 0);
}

static errno_t
nstat_udp_copy_descriptor(
	nstat_provider_cookie_t	cookie,
	void					*data,
	u_int32_t				len)
{
	if (len < sizeof(nstat_udp_descriptor))
	{
		return EINVAL;
	}

	if (nstat_udp_gone(cookie))
		return EINVAL;

	struct nstat_tucookie	*tucookie =
	    (struct nstat_tucookie *)cookie;
	nstat_udp_descriptor		*desc = (nstat_udp_descriptor*)data;
	struct inpcb 			*inp = tucookie->inp;

	bzero(desc, sizeof(*desc));

	if (tucookie->cached == false) {
		if (inp->inp_vflag & INP_IPV6)
		{
			nstat_ip6_to_sockaddr(&inp->in6p_laddr, inp->inp_lport,
				&desc->local.v6, sizeof(desc->local.v6));
			nstat_ip6_to_sockaddr(&inp->in6p_faddr, inp->inp_fport,
				&desc->remote.v6, sizeof(desc->remote.v6));
		}
		else if (inp->inp_vflag & INP_IPV4)
		{
			nstat_ip_to_sockaddr(&inp->inp_laddr, inp->inp_lport,
				&desc->local.v4, sizeof(desc->local.v4));
			nstat_ip_to_sockaddr(&inp->inp_faddr, inp->inp_fport,
				&desc->remote.v4, sizeof(desc->remote.v4));
		}
		desc->ifnet_properties = nstat_inpcb_to_flags(inp);
	}
	else
	{
		if (inp->inp_vflag & INP_IPV6)
		{
			memcpy(&desc->local.v6, &tucookie->local.v6,
			    sizeof(desc->local.v6));
			memcpy(&desc->remote.v6, &tucookie->remote.v6,
			    sizeof(desc->remote.v6));
		}
		else if (inp->inp_vflag & INP_IPV4)
		{
			memcpy(&desc->local.v4, &tucookie->local.v4,
			    sizeof(desc->local.v4));
			memcpy(&desc->remote.v4, &tucookie->remote.v4,
			    sizeof(desc->remote.v4));
		}
		desc->ifnet_properties = tucookie->ifnet_properties;
	}

	if (inp->inp_last_outifp)
		desc->ifindex = inp->inp_last_outifp->if_index;
	else
		desc->ifindex = tucookie->if_index;

	struct socket *so = inp->inp_socket;
	if (so)
	{
		// TBD - take the socket lock around these to make sure
		// they're in sync?
		desc->upid = so->last_upid;
		desc->pid = so->last_pid;
		proc_name(desc->pid, desc->pname, sizeof(desc->pname));
		if (desc->pname[0] == 0)
		{
			strlcpy(desc->pname, tucookie->pname,
			    sizeof(desc->pname));
		}
		else
		{
			desc->pname[sizeof(desc->pname) - 1] = 0;
			strlcpy(tucookie->pname, desc->pname,
			    sizeof(tucookie->pname));
		}
		memcpy(desc->uuid, so->last_uuid, sizeof(so->last_uuid));
		memcpy(desc->vuuid, so->so_vuuid, sizeof(so->so_vuuid));
		if (so->so_flags & SOF_DELEGATED) {
			desc->eupid = so->e_upid;
			desc->epid = so->e_pid;
			memcpy(desc->euuid, so->e_uuid, sizeof(so->e_uuid));
		} else {
			desc->eupid = desc->upid;
			desc->epid = desc->pid;
			memcpy(desc->euuid, desc->uuid, sizeof(desc->uuid));
		}
		desc->rcvbufsize = so->so_rcv.sb_hiwat;
		desc->rcvbufused = so->so_rcv.sb_cc;
		desc->traffic_class = so->so_traffic_class;
	}

	return 0;
}

static bool
nstat_udp_reporting_allowed(nstat_provider_cookie_t cookie, nstat_provider_filter *filter)
{
	return nstat_tcpudp_reporting_allowed(cookie, filter, TRUE);
}


static void
nstat_init_udp_provider(void)
{
	bzero(&nstat_udp_provider, sizeof(nstat_udp_provider));
	nstat_udp_provider.nstat_provider_id = NSTAT_PROVIDER_UDP_KERNEL;
	nstat_udp_provider.nstat_descriptor_length = sizeof(nstat_udp_descriptor);
	nstat_udp_provider.nstat_lookup = nstat_udp_lookup;
	nstat_udp_provider.nstat_gone = nstat_udp_gone;
	nstat_udp_provider.nstat_counts = nstat_udp_counts;
	nstat_udp_provider.nstat_watcher_add = nstat_udp_add_watcher;
	nstat_udp_provider.nstat_watcher_remove = nstat_udp_remove_watcher;
	nstat_udp_provider.nstat_copy_descriptor = nstat_udp_copy_descriptor;
	nstat_udp_provider.nstat_release = nstat_udp_release;
	nstat_udp_provider.nstat_reporting_allowed = nstat_udp_reporting_allowed;
	nstat_udp_provider.next = nstat_providers;
	nstat_providers = &nstat_udp_provider;
}

#pragma mark -- TCP/UDP Userland

// Almost all of this infrastucture is common to both TCP and UDP

static nstat_provider	nstat_userland_tcp_provider;
static nstat_provider	nstat_userland_udp_provider;


struct nstat_tu_shadow {
	tailq_entry_tu_shadow			shad_link;
	userland_stats_request_vals_fn	*shad_getvals_fn;
	userland_stats_provider_context	*shad_provider_context;
	u_int64_t						shad_properties;
	int								shad_provider;
	uint32_t						shad_magic;
};

// Magic number checking should remain in place until the userland provider has been fully proven
#define TU_SHADOW_MAGIC			0xfeedf00d
#define TU_SHADOW_UNMAGIC		0xdeaddeed

static tailq_head_tu_shadow nstat_userprot_shad_head = TAILQ_HEAD_INITIALIZER(nstat_userprot_shad_head);

static errno_t
nstat_userland_tu_lookup(
	__unused const void				*data,
	__unused u_int32_t 				length,
	__unused nstat_provider_cookie_t	*out_cookie)
{
	// Looking up a specific connection is not supported
	return ENOTSUP;
}

static int
nstat_userland_tu_gone(
	__unused nstat_provider_cookie_t	cookie)
{
	// Returns non-zero if the source has gone.
	// We don't keep a source hanging around, so the answer is always 0
	return 0;
}

static errno_t
nstat_userland_tu_counts(
	nstat_provider_cookie_t	cookie,
	struct nstat_counts		*out_counts,
	int						*out_gone)
 {
	struct nstat_tu_shadow *shad = (struct nstat_tu_shadow *)cookie;
	assert(shad->shad_magic == TU_SHADOW_MAGIC);

	bool result = (*shad->shad_getvals_fn)(shad->shad_provider_context, out_counts, NULL);

	if (out_gone) *out_gone = 0;

	return (result)? 0 : EIO;
}


static errno_t
nstat_userland_tu_copy_descriptor(
	nstat_provider_cookie_t	cookie,
	void					*data,
	__unused u_int32_t		len)
{
	struct nstat_tu_shadow *shad = (struct nstat_tu_shadow *)cookie;
	assert(shad->shad_magic == TU_SHADOW_MAGIC);

	bool result = (*shad->shad_getvals_fn)(shad->shad_provider_context, NULL, data);

	return (result)? 0 : EIO;
}

static void
nstat_userland_tu_release(
	__unused nstat_provider_cookie_t	cookie,
	__unused int locked)
{
	// Called when a nstat_src is detached.
	// We don't reference count or ask for delayed release so nothing to do here.
}

static bool
check_reporting_for_user(nstat_provider_filter *filter, pid_t pid, pid_t epid, uuid_t *uuid, uuid_t *euuid)
{
	bool retval = true;

	if ((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER) != 0)
	{
		retval = false;

		if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_PID) != 0) &&
			(filter->npf_pid == pid))
		{
			retval = true;
		}
		else if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_EPID) != 0) &&
			(filter->npf_pid == epid))
		{
			retval = true;
		}
		else if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_UUID) != 0) &&
			(memcmp(filter->npf_uuid, uuid, sizeof(*uuid)) == 0))
		{
			retval = true;
		}
		else if (((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER_BY_EUUID) != 0) &&
			(memcmp(filter->npf_uuid, euuid, sizeof(*euuid)) == 0))
		{
			retval = true;
		}
	}
	return retval;
}

static bool
nstat_userland_tcp_reporting_allowed(nstat_provider_cookie_t cookie, nstat_provider_filter *filter)
{
	bool retval = true;

	if ((filter->npf_flags & (NSTAT_FILTER_IFNET_FLAGS|NSTAT_FILTER_SPECIFIC_USER)) != 0)
	{
		nstat_tcp_descriptor tcp_desc;	// Stack allocation - OK or pushing the limits too far?
		struct nstat_tu_shadow *shad = (struct nstat_tu_shadow *)cookie;

		assert(shad->shad_magic == TU_SHADOW_MAGIC);

		if ((*shad->shad_getvals_fn)(shad->shad_provider_context, NULL, &tcp_desc))
		{
			if ((filter->npf_flags & NSTAT_FILTER_IFNET_FLAGS) != 0)
			{
				if ((filter->npf_flags & tcp_desc.ifnet_properties) == 0)
				{
					return false;
				}
			}
			if ((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER) != 0)
			{
				retval = check_reporting_for_user(filter, (pid_t)tcp_desc.pid, (pid_t)tcp_desc.epid,
												  &tcp_desc.uuid, &tcp_desc.euuid);
			}
		}
		else
		{
			retval = false;	// No further information, so might as well give up now.
		}
	}
	return retval;
}

static bool
nstat_userland_udp_reporting_allowed(nstat_provider_cookie_t cookie, nstat_provider_filter *filter)
{
	bool retval = true;

	if ((filter->npf_flags & (NSTAT_FILTER_IFNET_FLAGS|NSTAT_FILTER_SPECIFIC_USER)) != 0)
	{
		nstat_udp_descriptor udp_desc;	// Stack allocation - OK or pushing the limits too far?
		struct nstat_tu_shadow *shad = (struct nstat_tu_shadow *)cookie;

		assert(shad->shad_magic == TU_SHADOW_MAGIC);

		if ((*shad->shad_getvals_fn)(shad->shad_provider_context, NULL, &udp_desc))
		{
			if ((filter->npf_flags & NSTAT_FILTER_IFNET_FLAGS) != 0)
			{
				if ((filter->npf_flags & udp_desc.ifnet_properties) == 0)
				{
					return false;
				}
			}
			if ((filter->npf_flags & NSTAT_FILTER_SPECIFIC_USER) != 0)
			{
				retval = check_reporting_for_user(filter, (pid_t)udp_desc.pid, (pid_t)udp_desc.epid,
												  &udp_desc.uuid, &udp_desc.euuid);
			}
		}
		else
		{
			retval = false;	// No further information, so might as well give up now.
		}
	}
	return retval;
}



static errno_t
nstat_userland_tcp_add_watcher(
	nstat_control_state	*state)
{
	struct nstat_tu_shadow *shad;

	OSIncrementAtomic(&nstat_userland_tcp_watchers);

	lck_mtx_lock(&nstat_mtx);

	TAILQ_FOREACH(shad, &nstat_userprot_shad_head, shad_link) {
		assert(shad->shad_magic == TU_SHADOW_MAGIC);

		if (shad->shad_provider == NSTAT_PROVIDER_TCP_USERLAND)
		{
			int result = nstat_control_source_add(0, state, &nstat_userland_tcp_provider, shad);
			if (result != 0)
			{
				printf("%s - nstat_control_source_add returned %d\n", __func__, result);
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);

	return 0;
}

static errno_t
nstat_userland_udp_add_watcher(
	nstat_control_state	*state)
{
	struct nstat_tu_shadow *shad;

	OSIncrementAtomic(&nstat_userland_udp_watchers);

	lck_mtx_lock(&nstat_mtx);

	TAILQ_FOREACH(shad, &nstat_userprot_shad_head, shad_link) {
		assert(shad->shad_magic == TU_SHADOW_MAGIC);

		if (shad->shad_provider == NSTAT_PROVIDER_UDP_USERLAND)
		{
			int result = nstat_control_source_add(0, state, &nstat_userland_udp_provider, shad);
			if (result != 0)
			{
				printf("%s - nstat_control_source_add returned %d\n", __func__, result);
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);

	return 0;
}


static void
nstat_userland_tcp_remove_watcher(
	__unused nstat_control_state	*state)
{
	OSDecrementAtomic(&nstat_userland_tcp_watchers);
}

static void
nstat_userland_udp_remove_watcher(
	__unused nstat_control_state	*state)
{
	OSDecrementAtomic(&nstat_userland_udp_watchers);
}

static void
nstat_init_userland_tcp_provider(void)
{
	bzero(&nstat_userland_tcp_provider, sizeof(nstat_tcp_provider));
	nstat_userland_tcp_provider.nstat_descriptor_length = sizeof(nstat_tcp_descriptor);
	nstat_userland_tcp_provider.nstat_provider_id = NSTAT_PROVIDER_TCP_USERLAND;
	nstat_userland_tcp_provider.nstat_lookup = nstat_userland_tu_lookup;
	nstat_userland_tcp_provider.nstat_gone = nstat_userland_tu_gone;
	nstat_userland_tcp_provider.nstat_counts = nstat_userland_tu_counts;
	nstat_userland_tcp_provider.nstat_release = nstat_userland_tu_release;
	nstat_userland_tcp_provider.nstat_watcher_add = nstat_userland_tcp_add_watcher;
	nstat_userland_tcp_provider.nstat_watcher_remove = nstat_userland_tcp_remove_watcher;
	nstat_userland_tcp_provider.nstat_copy_descriptor = nstat_userland_tu_copy_descriptor;
	nstat_userland_tcp_provider.nstat_reporting_allowed = nstat_userland_tcp_reporting_allowed;
	nstat_userland_tcp_provider.next = nstat_providers;
	nstat_providers = &nstat_userland_tcp_provider;
}


static void
nstat_init_userland_udp_provider(void)
{
	bzero(&nstat_userland_udp_provider, sizeof(nstat_udp_provider));
	nstat_userland_udp_provider.nstat_descriptor_length = sizeof(nstat_udp_descriptor);
	nstat_userland_udp_provider.nstat_provider_id = NSTAT_PROVIDER_UDP_USERLAND;
	nstat_userland_udp_provider.nstat_lookup = nstat_userland_tu_lookup;
	nstat_userland_udp_provider.nstat_gone = nstat_userland_tu_gone;
	nstat_userland_udp_provider.nstat_counts = nstat_userland_tu_counts;
	nstat_userland_udp_provider.nstat_release = nstat_userland_tu_release;
	nstat_userland_udp_provider.nstat_watcher_add = nstat_userland_udp_add_watcher;
	nstat_userland_udp_provider.nstat_watcher_remove = nstat_userland_udp_remove_watcher;
	nstat_userland_udp_provider.nstat_copy_descriptor = nstat_userland_tu_copy_descriptor;
	nstat_userland_udp_provider.nstat_reporting_allowed = nstat_userland_udp_reporting_allowed;
	nstat_userland_udp_provider.next = nstat_providers;
	nstat_providers = &nstat_userland_udp_provider;
}



// Things get started with a call to netstats to say that there’s a new connection:
__private_extern__ nstat_userland_context
ntstat_userland_stats_open(userland_stats_provider_context *ctx,
						   int provider_id,
						   u_int64_t properties,
						   userland_stats_request_vals_fn req_fn)
{
	struct nstat_tu_shadow *shad;

	if ((provider_id != NSTAT_PROVIDER_TCP_USERLAND) && (provider_id != NSTAT_PROVIDER_UDP_USERLAND))
	{
		printf("%s - incorrect provider is supplied, %d\n", __func__, provider_id);
		return NULL;
	}

	shad = OSMalloc(sizeof(*shad), nstat_malloc_tag);
	if (shad == NULL)
		return NULL;

	shad->shad_getvals_fn		= req_fn;
	shad->shad_provider_context	= ctx;
	shad->shad_provider			= provider_id;
	shad->shad_properties		= properties;
	shad->shad_magic			= TU_SHADOW_MAGIC;

	lck_mtx_lock(&nstat_mtx);
	nstat_control_state	*state;

	// Even if there are no watchers, we save the shadow structure
	TAILQ_INSERT_HEAD(&nstat_userprot_shad_head, shad, shad_link);

	for (state = nstat_controls; state; state = state->ncs_next)
	{
		if ((state->ncs_watching & (1 << provider_id)) != 0)
		{
			// this client is watching tcp/udp userland
			// Link to it.
			int result = nstat_control_source_add(0, state, &nstat_userland_tcp_provider, shad);
			if (result != 0)
			{
				printf("%s - nstat_control_source_add returned %d\n", __func__, result);
			}
		}
	}
	lck_mtx_unlock(&nstat_mtx);

	return (nstat_userland_context)shad;
}


__private_extern__ void
ntstat_userland_stats_close(nstat_userland_context nstat_ctx)
{
	struct nstat_tu_shadow *shad = (struct nstat_tu_shadow *)nstat_ctx;
	nstat_src *dead_list = NULL;

	if (shad == NULL)
		return;

	assert(shad->shad_magic == TU_SHADOW_MAGIC);

	lck_mtx_lock(&nstat_mtx);
	if (nstat_userland_udp_watchers != 0 || nstat_userland_tcp_watchers != 0)
	{
		nstat_control_state	*state;
		nstat_src *src, *prevsrc;
		errno_t result;

		for (state = nstat_controls; state; state = state->ncs_next)
		{
			lck_mtx_lock(&state->mtx);
			for (prevsrc = NULL, src = state->ncs_srcs; src;
				prevsrc = src, src = src->next)
			{
				if (shad == (struct nstat_tu_shadow *)src->cookie)
					break;
			}

			if (src)
			{
				result = nstat_control_send_goodbye(state, src);

				if (prevsrc)
					prevsrc->next = src->next;
				else
					state->ncs_srcs = src->next;

				src->next = dead_list;
				dead_list = src;
			}
			lck_mtx_unlock(&state->mtx);
		}
	}
	TAILQ_REMOVE(&nstat_userprot_shad_head, shad, shad_link);

	lck_mtx_unlock(&nstat_mtx);

	while (dead_list)
	{
		nstat_src *src;
		src = dead_list;
		dead_list = src->next;

		nstat_control_cleanup_source(NULL, src, TRUE);
	}

	shad->shad_magic = TU_SHADOW_UNMAGIC;

	OSFree(shad, sizeof(*shad), nstat_malloc_tag);
}


__private_extern__ void
ntstat_userland_stats_event(
	__unused nstat_userland_context context,
	__unused userland_stats_event_t event)
{
	// This is a dummy for when we hook up event reporting to NetworkStatistics.
	// See <rdar://problem/23022832> NetworkStatistics should provide opt-in notifications
}




#pragma mark -- ifnet Provider --

static nstat_provider	nstat_ifnet_provider;

/*
 * We store a pointer to the ifnet and the original threshold
 * requested by the client.
 */
struct nstat_ifnet_cookie
{
	struct ifnet 	*ifp;
	uint64_t	threshold;
};

static errno_t
nstat_ifnet_lookup(
	const void		*data,
	u_int32_t 		length,
	nstat_provider_cookie_t	*out_cookie)
{
	const nstat_ifnet_add_param *param = (const nstat_ifnet_add_param *)data;
	struct ifnet *ifp;
	boolean_t changed = FALSE;
	nstat_control_state *state;
	nstat_src *src;
	struct nstat_ifnet_cookie *cookie;

	if (length < sizeof(*param) || param->threshold < 1024*1024)
		return EINVAL;
	if (nstat_privcheck != 0) {
		errno_t result = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0);
		if (result != 0)
			return result;
	}
	cookie = OSMalloc(sizeof(*cookie), nstat_malloc_tag);
	if (cookie == NULL)
		return ENOMEM;
	bzero(cookie, sizeof(*cookie));

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link)
	{
		ifnet_lock_exclusive(ifp);
		if (ifp->if_index == param->ifindex)
		{
			cookie->ifp = ifp;
			cookie->threshold = param->threshold;
			*out_cookie = cookie;
			if (!ifp->if_data_threshold ||
			    ifp->if_data_threshold > param->threshold)
			{
				changed = TRUE;
				ifp->if_data_threshold = param->threshold;
			}
			ifnet_lock_done(ifp);
			ifnet_reference(ifp);
			break;
		}
		ifnet_lock_done(ifp);
	}
	ifnet_head_done();

	/*
	 * When we change the threshold to something smaller, we notify
	 * all of our clients with a description message.
	 * We won't send a message to the client we are currently serving
	 * because it has no `ifnet source' yet.
	 */
	if (changed)
	{
		lck_mtx_lock(&nstat_mtx);
		for (state = nstat_controls; state; state = state->ncs_next)
		{
			lck_mtx_lock(&state->mtx);
			for (src = state->ncs_srcs; src; src = src->next)
			{
				if (src->provider != &nstat_ifnet_provider)
					continue;
				nstat_control_send_description(state, src, 0, 0);
			}
			lck_mtx_unlock(&state->mtx);
		}
		lck_mtx_unlock(&nstat_mtx);
	}
	if (cookie->ifp == NULL)
		OSFree(cookie, sizeof(*cookie), nstat_malloc_tag);

	return ifp ? 0 : EINVAL;
}

static int
nstat_ifnet_gone(
	nstat_provider_cookie_t	cookie)
{
	struct ifnet *ifp;
	struct nstat_ifnet_cookie *ifcookie =
	    (struct nstat_ifnet_cookie *)cookie;

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link)
	{
		if (ifp == ifcookie->ifp)
			break;
	}
	ifnet_head_done();

	return ifp ? 0 : 1;
}

static errno_t
nstat_ifnet_counts(
	nstat_provider_cookie_t	cookie,
	struct nstat_counts	*out_counts,
	int			*out_gone)
{
	struct nstat_ifnet_cookie *ifcookie =
	    (struct nstat_ifnet_cookie *)cookie;
	struct ifnet *ifp = ifcookie->ifp;

	if (out_gone) *out_gone = 0;

	// if the ifnet is gone, we should stop using it
	if (nstat_ifnet_gone(cookie))
	{
		if (out_gone) *out_gone = 1;
		return EINVAL;
	}

	bzero(out_counts, sizeof(*out_counts));
	out_counts->nstat_rxpackets = ifp->if_ipackets;
	out_counts->nstat_rxbytes = ifp->if_ibytes;
	out_counts->nstat_txpackets = ifp->if_opackets;
	out_counts->nstat_txbytes = ifp->if_obytes;
	out_counts->nstat_cell_rxbytes = out_counts->nstat_cell_txbytes = 0;
	return 0;
}

static void
nstat_ifnet_release(
	nstat_provider_cookie_t	cookie,
	__unused int 		locked)
{
	struct nstat_ifnet_cookie *ifcookie;
	struct ifnet *ifp;
	nstat_control_state *state;
	nstat_src *src;
	uint64_t minthreshold = UINT64_MAX;

	/*
	 * Find all the clients that requested a threshold
	 * for this ifnet and re-calculate if_data_threshold.
	 */
	lck_mtx_lock(&nstat_mtx);
	for (state = nstat_controls; state; state = state->ncs_next)
	{
		lck_mtx_lock(&state->mtx);
		for (src = state->ncs_srcs; src; src = src->next)
		{
			/* Skip the provider we are about to detach. */
			if (src->provider != &nstat_ifnet_provider ||
			    src->cookie == cookie)
				continue;
	    		ifcookie = (struct nstat_ifnet_cookie *)src->cookie;
			if (ifcookie->threshold < minthreshold)
				minthreshold = ifcookie->threshold;
		}
		lck_mtx_unlock(&state->mtx);
	}
	lck_mtx_unlock(&nstat_mtx);
	/*
	 * Reset if_data_threshold or disable it.
	 */
	ifcookie = (struct nstat_ifnet_cookie *)cookie;
	ifp = ifcookie->ifp;
	if (ifnet_is_attached(ifp, 1)) {
		ifnet_lock_exclusive(ifp);
		if (minthreshold == UINT64_MAX)
			ifp->if_data_threshold = 0;
		else
			ifp->if_data_threshold = minthreshold;
		ifnet_lock_done(ifp);
		ifnet_decr_iorefcnt(ifp);
	}
	ifnet_release(ifp);
	OSFree(ifcookie, sizeof(*ifcookie), nstat_malloc_tag);
}

static void
nstat_ifnet_copy_link_status(
	struct ifnet			*ifp,
	struct nstat_ifnet_descriptor	*desc)
{
	struct if_link_status *ifsr = ifp->if_link_status;
	nstat_ifnet_desc_link_status *link_status = &desc->link_status;

	link_status->link_status_type = NSTAT_IFNET_DESC_LINK_STATUS_TYPE_NONE;
	if (ifsr == NULL)
		return;

	lck_rw_lock_shared(&ifp->if_link_status_lock);

	if (ifp->if_type == IFT_CELLULAR) {

		nstat_ifnet_desc_cellular_status *cell_status = &link_status->u.cellular;
		struct if_cellular_status_v1 *if_cell_sr =
			&ifsr->ifsr_u.ifsr_cell.if_cell_u.if_status_v1;

		if (ifsr->ifsr_version != IF_CELLULAR_STATUS_REPORT_VERSION_1)
			goto done;

		link_status->link_status_type = NSTAT_IFNET_DESC_LINK_STATUS_TYPE_CELLULAR;

		if (if_cell_sr->valid_bitmask & IF_CELL_LINK_QUALITY_METRIC_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_LINK_QUALITY_METRIC_VALID;
			cell_status->link_quality_metric = if_cell_sr->link_quality_metric;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_EFFECTIVE_BANDWIDTH_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_EFFECTIVE_BANDWIDTH_VALID;
			cell_status->ul_effective_bandwidth = if_cell_sr->ul_effective_bandwidth;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_MAX_BANDWIDTH_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_MAX_BANDWIDTH_VALID;
			cell_status->ul_max_bandwidth = if_cell_sr->ul_max_bandwidth;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_MIN_LATENCY_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_MIN_LATENCY_VALID;
			cell_status->ul_min_latency = if_cell_sr->ul_min_latency;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_EFFECTIVE_LATENCY_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_EFFECTIVE_LATENCY_VALID;
			cell_status->ul_effective_latency = if_cell_sr->ul_effective_latency;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_MAX_LATENCY_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_MAX_LATENCY_VALID;
			cell_status->ul_max_latency = if_cell_sr->ul_max_latency;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_RETXT_LEVEL_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_VALID;
			if (if_cell_sr->ul_retxt_level == IF_CELL_UL_RETXT_LEVEL_NONE)
				cell_status->ul_retxt_level = NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_NONE;
			else if (if_cell_sr->ul_retxt_level == IF_CELL_UL_RETXT_LEVEL_LOW)
				cell_status->ul_retxt_level = NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_LOW;
			else if (if_cell_sr->ul_retxt_level == IF_CELL_UL_RETXT_LEVEL_MEDIUM)
				cell_status->ul_retxt_level = NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_MEDIUM;
			else if (if_cell_sr->ul_retxt_level == IF_CELL_UL_RETXT_LEVEL_HIGH)
				cell_status->ul_retxt_level = NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_HIGH;
			else
				cell_status->valid_bitmask &= ~NSTAT_IFNET_DESC_CELL_UL_RETXT_LEVEL_VALID;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_BYTES_LOST_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_BYTES_LOST_VALID;
			cell_status->ul_bytes_lost = if_cell_sr->ul_bytes_lost;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_MIN_QUEUE_SIZE_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_MIN_QUEUE_SIZE_VALID;
			cell_status->ul_min_queue_size = if_cell_sr->ul_min_queue_size;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_AVG_QUEUE_SIZE_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_AVG_QUEUE_SIZE_VALID;
			cell_status->ul_avg_queue_size = if_cell_sr->ul_avg_queue_size;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_MAX_QUEUE_SIZE_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_UL_MAX_QUEUE_SIZE_VALID;
			cell_status->ul_max_queue_size = if_cell_sr->ul_max_queue_size;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_DL_EFFECTIVE_BANDWIDTH_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_DL_EFFECTIVE_BANDWIDTH_VALID;
			cell_status->dl_effective_bandwidth = if_cell_sr->dl_effective_bandwidth;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_DL_MAX_BANDWIDTH_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_DL_MAX_BANDWIDTH_VALID;
			cell_status->dl_max_bandwidth = if_cell_sr->dl_max_bandwidth;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_CONFIG_INACTIVITY_TIME_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_CONFIG_INACTIVITY_TIME_VALID;
			cell_status->config_inactivity_time = if_cell_sr->config_inactivity_time;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_CONFIG_BACKOFF_TIME_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_CONFIG_BACKOFF_TIME_VALID;
			cell_status->config_backoff_time = if_cell_sr->config_backoff_time;
		}
		if (if_cell_sr->valid_bitmask & IF_CELL_UL_MSS_RECOMMENDED_VALID) {
			cell_status->valid_bitmask |= NSTAT_IFNET_DESC_CELL_MSS_RECOMMENDED_VALID;
			cell_status->mss_recommended = if_cell_sr->mss_recommended;
		}
	} else if (ifp->if_subfamily == IFNET_SUBFAMILY_WIFI) {

		nstat_ifnet_desc_wifi_status *wifi_status = &link_status->u.wifi;
		struct if_wifi_status_v1 *if_wifi_sr =
			&ifsr->ifsr_u.ifsr_wifi.if_wifi_u.if_status_v1;

		if (ifsr->ifsr_version != IF_WIFI_STATUS_REPORT_VERSION_1)
			goto done;

		link_status->link_status_type = NSTAT_IFNET_DESC_LINK_STATUS_TYPE_WIFI;

		if (if_wifi_sr->valid_bitmask & IF_WIFI_LINK_QUALITY_METRIC_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_LINK_QUALITY_METRIC_VALID;
			wifi_status->link_quality_metric = if_wifi_sr->link_quality_metric;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_EFFECTIVE_BANDWIDTH_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_EFFECTIVE_BANDWIDTH_VALID;
			wifi_status->ul_effective_bandwidth = if_wifi_sr->ul_effective_bandwidth;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_MAX_BANDWIDTH_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_MAX_BANDWIDTH_VALID;
			wifi_status->ul_max_bandwidth = if_wifi_sr->ul_max_bandwidth;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_MIN_LATENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_MIN_LATENCY_VALID;
			wifi_status->ul_min_latency = if_wifi_sr->ul_min_latency;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_EFFECTIVE_LATENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_EFFECTIVE_LATENCY_VALID;
			wifi_status->ul_effective_latency = if_wifi_sr->ul_effective_latency;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_MAX_LATENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_MAX_LATENCY_VALID;
			wifi_status->ul_max_latency = if_wifi_sr->ul_max_latency;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_RETXT_LEVEL_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_VALID;
			if (if_wifi_sr->ul_retxt_level == IF_WIFI_UL_RETXT_LEVEL_NONE)
				wifi_status->ul_retxt_level = NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_NONE;
			else if (if_wifi_sr->ul_retxt_level == IF_WIFI_UL_RETXT_LEVEL_LOW)
				wifi_status->ul_retxt_level = NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_LOW;
			else if (if_wifi_sr->ul_retxt_level == IF_WIFI_UL_RETXT_LEVEL_MEDIUM)
				wifi_status->ul_retxt_level = NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_MEDIUM;
			else if (if_wifi_sr->ul_retxt_level == IF_WIFI_UL_RETXT_LEVEL_HIGH)
				wifi_status->ul_retxt_level = NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_HIGH;
			else
				wifi_status->valid_bitmask &= ~NSTAT_IFNET_DESC_WIFI_UL_RETXT_LEVEL_VALID;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_BYTES_LOST_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_BYTES_LOST_VALID;
			wifi_status->ul_bytes_lost = if_wifi_sr->ul_bytes_lost;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_UL_ERROR_RATE_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_UL_ERROR_RATE_VALID;
			wifi_status->ul_error_rate = if_wifi_sr->ul_error_rate;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_DL_EFFECTIVE_BANDWIDTH_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_DL_EFFECTIVE_BANDWIDTH_VALID;
			wifi_status->dl_effective_bandwidth = if_wifi_sr->dl_effective_bandwidth;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_DL_MAX_BANDWIDTH_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_DL_MAX_BANDWIDTH_VALID;
			wifi_status->dl_max_bandwidth = if_wifi_sr->dl_max_bandwidth;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_DL_MIN_LATENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_DL_MIN_LATENCY_VALID;
			wifi_status->dl_min_latency = if_wifi_sr->dl_min_latency;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_DL_EFFECTIVE_LATENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_DL_EFFECTIVE_LATENCY_VALID;
			wifi_status->dl_effective_latency = if_wifi_sr->dl_effective_latency;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_DL_MAX_LATENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_DL_MAX_LATENCY_VALID;
			wifi_status->dl_max_latency = if_wifi_sr->dl_max_latency;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_DL_ERROR_RATE_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_DL_ERROR_RATE_VALID;
			wifi_status->dl_error_rate = if_wifi_sr->dl_error_rate;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_CONFIG_FREQUENCY_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_CONFIG_FREQUENCY_VALID;
			if (if_wifi_sr->config_frequency == IF_WIFI_CONFIG_FREQUENCY_2_4_GHZ)
				wifi_status->config_frequency = NSTAT_IFNET_DESC_WIFI_CONFIG_FREQUENCY_2_4_GHZ;
			else if (if_wifi_sr->config_frequency == IF_WIFI_CONFIG_FREQUENCY_5_0_GHZ)
				wifi_status->config_frequency = NSTAT_IFNET_DESC_WIFI_CONFIG_FREQUENCY_5_0_GHZ;
			else
				wifi_status->valid_bitmask &= ~NSTAT_IFNET_DESC_WIFI_CONFIG_FREQUENCY_VALID;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_CONFIG_MULTICAST_RATE_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_CONFIG_MULTICAST_RATE_VALID;
			wifi_status->config_multicast_rate = if_wifi_sr->config_multicast_rate;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_CONFIG_SCAN_COUNT_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_CONFIG_SCAN_COUNT_VALID;
			wifi_status->scan_count = if_wifi_sr->scan_count;
		}
		if (if_wifi_sr->valid_bitmask & IF_WIFI_CONFIG_SCAN_DURATION_VALID) {
			wifi_status->valid_bitmask |= NSTAT_IFNET_DESC_WIFI_CONFIG_SCAN_DURATION_VALID;
			wifi_status->scan_duration = if_wifi_sr->scan_duration;
		}
	}

done:
	lck_rw_done(&ifp->if_link_status_lock);
}

static u_int64_t nstat_ifnet_last_report_time = 0;
extern int tcp_report_stats_interval;

static void
nstat_ifnet_compute_percentages(struct if_tcp_ecn_perf_stat *ifst)
{
	/* Retransmit percentage */
	if (ifst->total_rxmitpkts > 0 && ifst->total_txpkts > 0) {
		/* shift by 10 for precision */
		ifst->rxmit_percent =
		    ((ifst->total_rxmitpkts << 10) * 100) / ifst->total_txpkts;
	} else {
		ifst->rxmit_percent = 0;
	}

	/* Out-of-order percentage */
	if (ifst->total_oopkts > 0 && ifst->total_rxpkts > 0) {
		/* shift by 10 for precision */
		ifst->oo_percent =
		    ((ifst->total_oopkts << 10) * 100) / ifst->total_rxpkts;
	} else {
		ifst->oo_percent = 0;
	}

	/* Reorder percentage */
	if (ifst->total_reorderpkts > 0 &&
	    (ifst->total_txpkts + ifst->total_rxpkts) > 0) {
		/* shift by 10 for precision */
		ifst->reorder_percent =
		    ((ifst->total_reorderpkts << 10) * 100) /
		    (ifst->total_txpkts + ifst->total_rxpkts);
	} else {
		ifst->reorder_percent = 0;
	}
}

static void
nstat_ifnet_normalize_counter(struct if_tcp_ecn_stat *if_st)
{
	u_int64_t ecn_on_conn, ecn_off_conn;

	if (if_st == NULL)
		return;
	ecn_on_conn = if_st->ecn_client_success +
	    if_st->ecn_server_success;
	ecn_off_conn = if_st->ecn_off_conn +
	    (if_st->ecn_client_setup - if_st->ecn_client_success) +
	    (if_st->ecn_server_setup - if_st->ecn_server_success);

	/*
	 * report sack episodes, rst_drop and rxmit_drop
	 *  as a ratio per connection, shift by 10 for precision
	 */
	if (ecn_on_conn > 0) {
		if_st->ecn_on.sack_episodes =
		    (if_st->ecn_on.sack_episodes << 10) / ecn_on_conn;
		if_st->ecn_on.rst_drop =
		    (if_st->ecn_on.rst_drop << 10) * 100 / ecn_on_conn;
		if_st->ecn_on.rxmit_drop =
		    (if_st->ecn_on.rxmit_drop << 10) * 100 / ecn_on_conn;
	} else {
		/* set to zero, just in case */
		if_st->ecn_on.sack_episodes = 0;
		if_st->ecn_on.rst_drop = 0;
		if_st->ecn_on.rxmit_drop = 0;
	}

	if (ecn_off_conn > 0) {
		if_st->ecn_off.sack_episodes =
		    (if_st->ecn_off.sack_episodes << 10) / ecn_off_conn;
		if_st->ecn_off.rst_drop =
		    (if_st->ecn_off.rst_drop << 10) * 100 / ecn_off_conn;
		if_st->ecn_off.rxmit_drop =
		    (if_st->ecn_off.rxmit_drop << 10) * 100 / ecn_off_conn;
	} else {
		if_st->ecn_off.sack_episodes = 0;
		if_st->ecn_off.rst_drop = 0;
		if_st->ecn_off.rxmit_drop = 0;
	}
	if_st->ecn_total_conn = ecn_off_conn + ecn_on_conn;
}

static void
nstat_ifnet_report_ecn_stats(void)
{
	u_int64_t uptime, last_report_time;
	struct nstat_sysinfo_data data;
	struct nstat_sysinfo_ifnet_ecn_stats *st;
	struct ifnet *ifp;

	uptime = net_uptime();

	if ((int)(uptime - nstat_ifnet_last_report_time) <
	    tcp_report_stats_interval)
		return;

	last_report_time = nstat_ifnet_last_report_time;
	nstat_ifnet_last_report_time = uptime;
	data.flags = NSTAT_SYSINFO_IFNET_ECN_STATS;
	st = &data.u.ifnet_ecn_stats;

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		if (ifp->if_ipv4_stat == NULL || ifp->if_ipv6_stat == NULL)
			continue;

		if ((ifp->if_refflags & (IFRF_ATTACHED | IFRF_DETACHING)) !=
		    IFRF_ATTACHED)
			continue;

		/* Limit reporting to Wifi, Ethernet and cellular. */
		if (!(IFNET_IS_ETHERNET(ifp) || IFNET_IS_CELLULAR(ifp)))
			continue;

		bzero(st, sizeof(*st));
		if (IFNET_IS_CELLULAR(ifp)) {
			st->ifnet_type = NSTAT_IFNET_ECN_TYPE_CELLULAR;
		} else if (IFNET_IS_WIFI(ifp)) {
			st->ifnet_type = NSTAT_IFNET_ECN_TYPE_WIFI;
		} else {
			st->ifnet_type = NSTAT_IFNET_ECN_TYPE_ETHERNET;
		}
		data.unsent_data_cnt = ifp->if_unsent_data_cnt;
		/* skip if there was no update since last report */
		if (ifp->if_ipv4_stat->timestamp <= 0 ||
		    ifp->if_ipv4_stat->timestamp < last_report_time)
			goto v6;
		st->ifnet_proto = NSTAT_IFNET_ECN_PROTO_IPV4;
		/* compute percentages using packet counts */
		nstat_ifnet_compute_percentages(&ifp->if_ipv4_stat->ecn_on);
		nstat_ifnet_compute_percentages(&ifp->if_ipv4_stat->ecn_off);
		nstat_ifnet_normalize_counter(ifp->if_ipv4_stat);
		bcopy(ifp->if_ipv4_stat, &st->ecn_stat,
		    sizeof(st->ecn_stat));
		nstat_sysinfo_send_data(&data);
		bzero(ifp->if_ipv4_stat, sizeof(*ifp->if_ipv4_stat));

v6:
		/* skip if there was no update since last report */
		if (ifp->if_ipv6_stat->timestamp <= 0 ||
		    ifp->if_ipv6_stat->timestamp < last_report_time)
			continue;
		st->ifnet_proto = NSTAT_IFNET_ECN_PROTO_IPV6;

		/* compute percentages using packet counts */
		nstat_ifnet_compute_percentages(&ifp->if_ipv6_stat->ecn_on);
		nstat_ifnet_compute_percentages(&ifp->if_ipv6_stat->ecn_off);
		nstat_ifnet_normalize_counter(ifp->if_ipv6_stat);
		bcopy(ifp->if_ipv6_stat, &st->ecn_stat,
		    sizeof(st->ecn_stat));
		nstat_sysinfo_send_data(&data);

		/* Zero the stats in ifp */
		bzero(ifp->if_ipv6_stat, sizeof(*ifp->if_ipv6_stat));
	}
	ifnet_head_done();

}

static errno_t
nstat_ifnet_copy_descriptor(
	nstat_provider_cookie_t	cookie,
	void			*data,
	u_int32_t		len)
{
	nstat_ifnet_descriptor *desc = (nstat_ifnet_descriptor *)data;
	struct nstat_ifnet_cookie *ifcookie =
	    (struct nstat_ifnet_cookie *)cookie;
	struct ifnet *ifp = ifcookie->ifp;

	if (len < sizeof(nstat_ifnet_descriptor))
		return EINVAL;

	if (nstat_ifnet_gone(cookie))
		return EINVAL;

	bzero(desc, sizeof(*desc));
	ifnet_lock_shared(ifp);
	strlcpy(desc->name, ifp->if_xname, sizeof(desc->name));
	desc->ifindex = ifp->if_index;
	desc->threshold = ifp->if_data_threshold;
	desc->type = ifp->if_type;
	if (ifp->if_desc.ifd_len < sizeof(desc->description))
		memcpy(desc->description, ifp->if_desc.ifd_desc,
	    	    sizeof(desc->description));
	nstat_ifnet_copy_link_status(ifp, desc);
	ifnet_lock_done(ifp);
	return 0;
}

static void
nstat_init_ifnet_provider(void)
{
	bzero(&nstat_ifnet_provider, sizeof(nstat_ifnet_provider));
	nstat_ifnet_provider.nstat_provider_id = NSTAT_PROVIDER_IFNET;
	nstat_ifnet_provider.nstat_descriptor_length = sizeof(nstat_ifnet_descriptor);
	nstat_ifnet_provider.nstat_lookup = nstat_ifnet_lookup;
	nstat_ifnet_provider.nstat_gone = nstat_ifnet_gone;
	nstat_ifnet_provider.nstat_counts = nstat_ifnet_counts;
	nstat_ifnet_provider.nstat_watcher_add = NULL;
	nstat_ifnet_provider.nstat_watcher_remove = NULL;
	nstat_ifnet_provider.nstat_copy_descriptor = nstat_ifnet_copy_descriptor;
	nstat_ifnet_provider.nstat_release = nstat_ifnet_release;
	nstat_ifnet_provider.next = nstat_providers;
	nstat_providers = &nstat_ifnet_provider;
}

__private_extern__ void
nstat_ifnet_threshold_reached(unsigned int ifindex)
{
	nstat_control_state *state;
	nstat_src *src;
	struct ifnet *ifp;
	struct nstat_ifnet_cookie *ifcookie;

	lck_mtx_lock(&nstat_mtx);
	for (state = nstat_controls; state; state = state->ncs_next)
	{
		lck_mtx_lock(&state->mtx);
		for (src = state->ncs_srcs; src; src = src->next)
		{
			if (src->provider != &nstat_ifnet_provider)
				continue;
			ifcookie = (struct nstat_ifnet_cookie *)src->cookie;
			ifp = ifcookie->ifp;
			if (ifp->if_index != ifindex)
				continue;
			nstat_control_send_counts(state, src, 0, 0, NULL);
		}
		lck_mtx_unlock(&state->mtx);
	}
	lck_mtx_unlock(&nstat_mtx);
}

#pragma mark -- Sysinfo --
static void
nstat_set_keyval_scalar(nstat_sysinfo_keyval *kv, int key, u_int32_t val)
{
	kv->nstat_sysinfo_key = key;
	kv->nstat_sysinfo_flags = NSTAT_SYSINFO_FLAG_SCALAR;
	kv->u.nstat_sysinfo_scalar = val;
}

static void
nstat_sysinfo_send_data_internal(
	nstat_control_state *control,
	nstat_sysinfo_data *data)
{
	nstat_msg_sysinfo_counts *syscnt = NULL;
	size_t allocsize = 0, countsize = 0, nkeyvals = 0, finalsize = 0;
	nstat_sysinfo_keyval *kv;
	errno_t result = 0;
	size_t i = 0;

	allocsize = offsetof(nstat_msg_sysinfo_counts, counts);
	countsize = offsetof(nstat_sysinfo_counts, nstat_sysinfo_keyvals);
	finalsize = allocsize;

	/* get number of key-vals for each kind of stat */
	switch (data->flags)
	{
		case NSTAT_SYSINFO_MBUF_STATS:
			nkeyvals = sizeof(struct nstat_sysinfo_mbuf_stats) /
			    sizeof(u_int32_t);
			break;
		case NSTAT_SYSINFO_TCP_STATS:
			nkeyvals = sizeof(struct nstat_sysinfo_tcp_stats) /
			    sizeof(u_int32_t);
			break;
		case NSTAT_SYSINFO_IFNET_ECN_STATS:
			nkeyvals = (sizeof(struct if_tcp_ecn_stat) /
			    sizeof(u_int64_t));

			/* Two more keys for ifnet type and proto */
			nkeyvals += 2;

			/* One key for unsent data. */
			nkeyvals++;
			break;
		default:
			return;
	}
	countsize += sizeof(nstat_sysinfo_keyval) * nkeyvals;
	allocsize += countsize;

	syscnt = OSMalloc(allocsize, nstat_malloc_tag);
	if (syscnt == NULL)
		return;
	bzero(syscnt, allocsize);

	kv = (nstat_sysinfo_keyval *) &syscnt->counts.nstat_sysinfo_keyvals;
	switch (data->flags)
	{
		case NSTAT_SYSINFO_MBUF_STATS:
		{
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_KEY_MBUF_256B_TOTAL,
			    data->u.mb_stats.total_256b);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_KEY_MBUF_2KB_TOTAL,
			    data->u.mb_stats.total_2kb);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_KEY_MBUF_4KB_TOTAL,
			    data->u.mb_stats.total_4kb);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_MBUF_16KB_TOTAL,
			    data->u.mb_stats.total_16kb);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_KEY_SOCK_MBCNT,
			    data->u.mb_stats.sbmb_total);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_KEY_SOCK_ATMBLIMIT,
			    data->u.mb_stats.sb_atmbuflimit);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_MBUF_DRAIN_CNT,
			    data->u.mb_stats.draincnt);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_MBUF_MEM_RELEASED,
			    data->u.mb_stats.memreleased);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_KEY_SOCK_MBFLOOR,
			    data->u.mb_stats.sbmb_floor);
			VERIFY(i == nkeyvals);
			break;
		}
		case NSTAT_SYSINFO_TCP_STATS:
		{
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_KEY_IPV4_AVGRTT,
			    data->u.tcp_stats.ipv4_avgrtt);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_KEY_IPV6_AVGRTT,
			    data->u.tcp_stats.ipv6_avgrtt);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_KEY_SEND_PLR,
			    data->u.tcp_stats.send_plr);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_KEY_RECV_PLR,
			    data->u.tcp_stats.recv_plr);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_KEY_SEND_TLRTO,
			    data->u.tcp_stats.send_tlrto_rate);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_KEY_SEND_REORDERRATE,
			    data->u.tcp_stats.send_reorder_rate);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_CONNECTION_ATTEMPTS,
			    data->u.tcp_stats.connection_attempts);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_CONNECTION_ACCEPTS,
			    data->u.tcp_stats.connection_accepts);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_CLIENT_ENABLED,
			    data->u.tcp_stats.ecn_client_enabled);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_SERVER_ENABLED,
			    data->u.tcp_stats.ecn_server_enabled);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_CLIENT_SETUP,
			    data->u.tcp_stats.ecn_client_setup);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_SERVER_SETUP,
			    data->u.tcp_stats.ecn_server_setup);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_CLIENT_SUCCESS,
			    data->u.tcp_stats.ecn_client_success);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_SERVER_SUCCESS,
			    data->u.tcp_stats.ecn_server_success);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_NOT_SUPPORTED,
			    data->u.tcp_stats.ecn_not_supported);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_LOST_SYN,
			    data->u.tcp_stats.ecn_lost_syn);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_LOST_SYNACK,
			    data->u.tcp_stats.ecn_lost_synack);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_RECV_CE,
			    data->u.tcp_stats.ecn_recv_ce);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_RECV_ECE,
			    data->u.tcp_stats.ecn_recv_ece);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_SENT_ECE,
			    data->u.tcp_stats.ecn_sent_ece);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_CONN_RECV_CE,
			    data->u.tcp_stats.ecn_conn_recv_ce);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_CONN_RECV_ECE,
			    data->u.tcp_stats.ecn_conn_recv_ece);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_CONN_PLNOCE,
			    data->u.tcp_stats.ecn_conn_plnoce);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_CONN_PL_CE,
			    data->u.tcp_stats.ecn_conn_pl_ce);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_CONN_NOPL_CE,
			    data->u.tcp_stats.ecn_conn_nopl_ce);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_FALLBACK_SYNLOSS,
			    data->u.tcp_stats.ecn_fallback_synloss);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_FALLBACK_REORDER,
			    data->u.tcp_stats.ecn_fallback_reorder);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_FALLBACK_CE,
			    data->u.tcp_stats.ecn_fallback_ce);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_SYN_DATA_RCV,
			    data->u.tcp_stats.tfo_syn_data_rcv);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_COOKIE_REQ_RCV,
			    data->u.tcp_stats.tfo_cookie_req_rcv);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_COOKIE_SENT,
			    data->u.tcp_stats.tfo_cookie_sent);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_COOKIE_INVALID,
			    data->u.tcp_stats.tfo_cookie_invalid);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_COOKIE_REQ,
			    data->u.tcp_stats.tfo_cookie_req);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_COOKIE_RCV,
			    data->u.tcp_stats.tfo_cookie_rcv);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_SYN_DATA_SENT,
			    data->u.tcp_stats.tfo_syn_data_sent);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_SYN_DATA_ACKED,
			    data->u.tcp_stats.tfo_syn_data_acked);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_SYN_LOSS,
			    data->u.tcp_stats.tfo_syn_loss);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_BLACKHOLE,
			    data->u.tcp_stats.tfo_blackhole);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_COOKIE_WRONG,
			    data->u.tcp_stats.tfo_cookie_wrong);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_NO_COOKIE_RCV,
			    data->u.tcp_stats.tfo_no_cookie_rcv);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_HEURISTICS_DISABLE,
			    data->u.tcp_stats.tfo_heuristics_disable);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_TFO_SEND_BLACKHOLE,
			    data->u.tcp_stats.tfo_sndblackhole);
			VERIFY(i == nkeyvals);
			break;
		}
		case NSTAT_SYSINFO_IFNET_ECN_STATS:
		{
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_TYPE,
			    data->u.ifnet_ecn_stats.ifnet_type);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_PROTO,
			    data->u.ifnet_ecn_stats.ifnet_proto);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_CLIENT_SETUP,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_client_setup);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_SERVER_SETUP,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_server_setup);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_CLIENT_SUCCESS,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_client_success);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_SERVER_SUCCESS,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_server_success);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_PEER_NOSUPPORT,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_peer_nosupport);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_SYN_LOST,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_syn_lost);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_SYNACK_LOST,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_synack_lost);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_RECV_CE,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_recv_ce);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_RECV_ECE,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_recv_ece);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_CONN_RECV_CE,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_conn_recv_ce);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_CONN_RECV_ECE,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_conn_recv_ece);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_CONN_PLNOCE,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_conn_plnoce);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_CONN_PLCE,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_conn_plce);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_CONN_NOPLCE,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_conn_noplce);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_FALLBACK_SYNLOSS,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_fallback_synloss);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_FALLBACK_REORDER,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_fallback_reorder);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_FALLBACK_CE,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_fallback_ce);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_ON_RTT_AVG,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.rtt_avg);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_ON_RTT_VAR,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.rtt_var);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_ON_OOPERCENT,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.oo_percent);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_ON_SACK_EPISODE,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.sack_episodes);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_ON_REORDER_PERCENT,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.reorder_percent);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_ON_RXMIT_PERCENT,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.rxmit_percent);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_ON_RXMIT_DROP,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.rxmit_drop);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_OFF_RTT_AVG,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.rtt_avg);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_OFF_RTT_VAR,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.rtt_var);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_OFF_OOPERCENT,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.oo_percent);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_OFF_SACK_EPISODE,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.sack_episodes);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_OFF_REORDER_PERCENT,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.reorder_percent);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_OFF_RXMIT_PERCENT,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.rxmit_percent);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_OFF_RXMIT_DROP,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.rxmit_drop);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_ON_TOTAL_TXPKTS,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.total_txpkts);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_ON_TOTAL_RXMTPKTS,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.total_rxmitpkts);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_ON_TOTAL_RXPKTS,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.total_rxpkts);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_ON_TOTAL_OOPKTS,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.total_oopkts);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_ON_DROP_RST,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_on.rst_drop);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_OFF_TOTAL_TXPKTS,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.total_txpkts);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_OFF_TOTAL_RXMTPKTS,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.total_rxmitpkts);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_OFF_TOTAL_RXPKTS,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.total_rxpkts);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_OFF_TOTAL_OOPKTS,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.total_oopkts);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_OFF_DROP_RST,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_off.rst_drop);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_TOTAL_CONN,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_total_conn);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_IFNET_UNSENT_DATA,
			    data->unsent_data_cnt);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_FALLBACK_DROPRST,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_fallback_droprst);
			nstat_set_keyval_scalar(&kv[i++],
			    NSTAT_SYSINFO_ECN_IFNET_FALLBACK_DROPRXMT,
			    data->u.ifnet_ecn_stats.ecn_stat.ecn_fallback_droprxmt);
			break;
		}
	}
	if (syscnt != NULL)
	{
		VERIFY(i > 0 && i <= nkeyvals);
		countsize = offsetof(nstat_sysinfo_counts,
		    nstat_sysinfo_keyvals) +
		    sizeof(nstat_sysinfo_keyval) * i;
		finalsize += countsize;
		syscnt->hdr.type = NSTAT_MSG_TYPE_SYSINFO_COUNTS;
		syscnt->hdr.length = finalsize;
		syscnt->counts.nstat_sysinfo_len = countsize;

		result = ctl_enqueuedata(control->ncs_kctl,
		    control->ncs_unit, syscnt, finalsize, CTL_DATA_EOR);
		if (result != 0)
		{
			nstat_stats.nstat_sysinfofailures += 1;
		}
		OSFree(syscnt, allocsize, nstat_malloc_tag);
	}
	return;
}

__private_extern__ void
nstat_sysinfo_send_data(
	nstat_sysinfo_data *data)
{
	nstat_control_state *control;

	lck_mtx_lock(&nstat_mtx);
	for (control = nstat_controls; control; control = control->ncs_next)
	{
		lck_mtx_lock(&control->mtx);
		if ((control->ncs_flags & NSTAT_FLAG_SYSINFO_SUBSCRIBED) != 0)
		{
			nstat_sysinfo_send_data_internal(control, data);
		}
		lck_mtx_unlock(&control->mtx);
	}
	lck_mtx_unlock(&nstat_mtx);
}

static void
nstat_sysinfo_generate_report(void)
{
	mbuf_report_peak_usage();
	tcp_report_stats();
	nstat_ifnet_report_ecn_stats();
}

#pragma mark -- Kernel Control Socket --

static kern_ctl_ref	nstat_ctlref = NULL;
static lck_grp_t	*nstat_lck_grp = NULL;

static errno_t	nstat_control_connect(kern_ctl_ref kctl, struct sockaddr_ctl *sac, void **uinfo);
static errno_t	nstat_control_disconnect(kern_ctl_ref kctl, u_int32_t unit, void *uinfo);
static errno_t	nstat_control_send(kern_ctl_ref kctl, u_int32_t unit, void *uinfo, mbuf_t m, int flags);

static errno_t
nstat_enqueue_success(
    uint64_t context,
    nstat_control_state	*state,
    u_int16_t flags)
{
	nstat_msg_hdr success;
	errno_t result;

	bzero(&success, sizeof(success));
	success.context = context;
	success.type = NSTAT_MSG_TYPE_SUCCESS;
	success.length = sizeof(success);
	success.flags = flags;
	result = ctl_enqueuedata(state->ncs_kctl, state->ncs_unit, &success,
	    sizeof(success), CTL_DATA_EOR | CTL_DATA_CRIT);
	if (result != 0) {
		if (nstat_debug != 0)
			printf("%s: could not enqueue success message %d\n",
			    __func__, result);
		nstat_stats.nstat_successmsgfailures += 1;
	}
	return result;
}

static errno_t
nstat_control_send_goodbye(
	nstat_control_state	*state,
	nstat_src			*src)
{
	errno_t result = 0;
	int failed = 0;

	if (nstat_control_reporting_allowed(state, src))
	{
		if ((state->ncs_flags & NSTAT_FLAG_SUPPORTS_UPDATES) != 0)
		{
			result = nstat_control_send_update(state, src, 0, NSTAT_MSG_HDR_FLAG_CLOSING, NULL);
			if (result != 0)
			{
				failed = 1;
				if (nstat_debug != 0)
					printf("%s - nstat_control_send_update() %d\n", __func__, result);
			}
		}
		else
		{
			// send one last counts notification
			result = nstat_control_send_counts(state, src, 0, NSTAT_MSG_HDR_FLAG_CLOSING, NULL);
			if (result != 0)
			{
				failed = 1;
				if (nstat_debug != 0)
					printf("%s - nstat_control_send_counts() %d\n", __func__, result);
			}

			// send a last description
			result = nstat_control_send_description(state, src, 0, NSTAT_MSG_HDR_FLAG_CLOSING);
			if (result != 0)
			{
				failed = 1;
				if (nstat_debug != 0)
					printf("%s - nstat_control_send_description() %d\n", __func__, result);
			}
		}
	}

	// send the source removed notification
	result = nstat_control_send_removed(state, src);
	if (result != 0 && nstat_debug)
	{
		failed = 1;
		if (nstat_debug != 0)
			printf("%s - nstat_control_send_removed() %d\n", __func__, result);
	}

	if (failed != 0)
		nstat_stats.nstat_control_send_goodbye_failures++;


	return result;
}

static errno_t
nstat_flush_accumulated_msgs(
	nstat_control_state	*state)
{
	errno_t result = 0;
	if (state->ncs_accumulated != NULL && mbuf_len(state->ncs_accumulated) > 0)
	{
		mbuf_pkthdr_setlen(state->ncs_accumulated, mbuf_len(state->ncs_accumulated));
		result = ctl_enqueuembuf(state->ncs_kctl, state->ncs_unit, state->ncs_accumulated, CTL_DATA_EOR);
		if (result != 0)
		{
			nstat_stats.nstat_flush_accumulated_msgs_failures++;
			if (nstat_debug != 0)
				printf("%s - ctl_enqueuembuf failed: %d\n", __func__, result);
			mbuf_freem(state->ncs_accumulated);
		}
		state->ncs_accumulated = NULL;
	}
	return result;
}

static errno_t
nstat_accumulate_msg(
	nstat_control_state	*state,
	nstat_msg_hdr		*hdr,
	size_t				length)
{
	if (state->ncs_accumulated && mbuf_trailingspace(state->ncs_accumulated) < length)
	{
		// Will send the current mbuf
		nstat_flush_accumulated_msgs(state);
	}

	errno_t result = 0;

	if (state->ncs_accumulated == NULL)
	{
		unsigned int one = 1;
		if (mbuf_allocpacket(MBUF_DONTWAIT, NSTAT_MAX_MSG_SIZE, &one, &state->ncs_accumulated) != 0)
		{
			if (nstat_debug != 0)
				printf("%s - mbuf_allocpacket failed\n", __func__);
			result = ENOMEM;
		}
		else
		{
			mbuf_setlen(state->ncs_accumulated, 0);
		}
	}

	if (result == 0)
	{
		hdr->length = length;
		result = mbuf_copyback(state->ncs_accumulated, mbuf_len(state->ncs_accumulated),
							   length, hdr, MBUF_DONTWAIT);
	}

	if (result != 0)
	{
		nstat_flush_accumulated_msgs(state);
		if (nstat_debug != 0)
			printf("%s - resorting to ctl_enqueuedata\n", __func__);
		result = ctl_enqueuedata(state->ncs_kctl, state->ncs_unit, hdr, length, CTL_DATA_EOR);
	}

	if (result != 0)
		nstat_stats.nstat_accumulate_msg_failures++;

	return result;
}

static void*
nstat_idle_check(
	__unused thread_call_param_t p0,
	__unused thread_call_param_t p1)
{
	lck_mtx_lock(&nstat_mtx);

	nstat_idle_time = 0;

	nstat_control_state *control;
	nstat_src	*dead = NULL;
	nstat_src	*dead_list = NULL;
	for (control = nstat_controls; control; control = control->ncs_next)
	{
		lck_mtx_lock(&control->mtx);
		nstat_src	**srcpp = &control->ncs_srcs;

		if (!(control->ncs_flags & NSTAT_FLAG_REQCOUNTS))
		{
			while(*srcpp != NULL)
			{
				if ((*srcpp)->provider->nstat_gone((*srcpp)->cookie))
				{
					errno_t result;

					// Pull it off the list
					dead = *srcpp;
					*srcpp = (*srcpp)->next;

					result = nstat_control_send_goodbye(control, dead);

					// Put this on the list to release later
					dead->next = dead_list;
					dead_list = dead;
				}
				else
				{
					srcpp = &(*srcpp)->next;
				}
			}
		}
		control->ncs_flags &= ~NSTAT_FLAG_REQCOUNTS;
		lck_mtx_unlock(&control->mtx);
	}

	if (nstat_controls)
	{
		clock_interval_to_deadline(60, NSEC_PER_SEC, &nstat_idle_time);
		thread_call_func_delayed((thread_call_func_t)nstat_idle_check, NULL, nstat_idle_time);
	}

	lck_mtx_unlock(&nstat_mtx);

	/* Generate any system level reports, if needed */
	nstat_sysinfo_generate_report();

	// Release the sources now that we aren't holding lots of locks
	while (dead_list)
	{
		dead = dead_list;
		dead_list = dead->next;

		nstat_control_cleanup_source(NULL, dead, FALSE);
	}

	return NULL;
}

static void
nstat_control_register(void)
{
	// Create our lock group first
	lck_grp_attr_t	*grp_attr = lck_grp_attr_alloc_init();
	lck_grp_attr_setdefault(grp_attr);
	nstat_lck_grp = lck_grp_alloc_init("network statistics kctl", grp_attr);
	lck_grp_attr_free(grp_attr);

	lck_mtx_init(&nstat_mtx, nstat_lck_grp, NULL);

	// Register the control
	struct kern_ctl_reg	nstat_control;
	bzero(&nstat_control, sizeof(nstat_control));
	strlcpy(nstat_control.ctl_name, NET_STAT_CONTROL_NAME, sizeof(nstat_control.ctl_name));
	nstat_control.ctl_flags = CTL_FLAG_REG_EXTENDED | CTL_FLAG_REG_CRIT;
	nstat_control.ctl_sendsize = nstat_sendspace;
	nstat_control.ctl_recvsize = nstat_recvspace;
	nstat_control.ctl_connect = nstat_control_connect;
	nstat_control.ctl_disconnect = nstat_control_disconnect;
	nstat_control.ctl_send = nstat_control_send;

	ctl_register(&nstat_control, &nstat_ctlref);
}

static void
nstat_control_cleanup_source(
	nstat_control_state	*state,
	struct nstat_src	*src,
	boolean_t 		locked)
{
	errno_t result;

	if (state)
	{
		result = nstat_control_send_removed(state, src);
		if (result != 0)
		{
			nstat_stats.nstat_control_cleanup_source_failures++;
			if (nstat_debug != 0)
				printf("%s - nstat_control_send_removed() %d\n",
				    __func__, result);
		}
	}
	// Cleanup the source if we found it.
	src->provider->nstat_release(src->cookie, locked);
	OSFree(src, sizeof(*src), nstat_malloc_tag);
}


static bool
nstat_control_reporting_allowed(
	nstat_control_state *state,
	nstat_src *src)
{
	if (src->provider->nstat_reporting_allowed == NULL)
		return TRUE;

	return (
	    src->provider->nstat_reporting_allowed(src->cookie,
		&state->ncs_provider_filters[src->provider->nstat_provider_id])
	);
}


static errno_t
nstat_control_connect(
	kern_ctl_ref		kctl,
	struct sockaddr_ctl	*sac,
	void				**uinfo)
{
	nstat_control_state	*state = OSMalloc(sizeof(*state), nstat_malloc_tag);
	if (state == NULL) return ENOMEM;

	bzero(state, sizeof(*state));
	lck_mtx_init(&state->mtx, nstat_lck_grp, NULL);
	state->ncs_kctl = kctl;
	state->ncs_unit = sac->sc_unit;
	state->ncs_flags = NSTAT_FLAG_REQCOUNTS;
	*uinfo = state;

	lck_mtx_lock(&nstat_mtx);
	state->ncs_next = nstat_controls;
	nstat_controls = state;

	if (nstat_idle_time == 0)
	{
		clock_interval_to_deadline(60, NSEC_PER_SEC, &nstat_idle_time);
		thread_call_func_delayed((thread_call_func_t)nstat_idle_check, NULL, nstat_idle_time);
	}

	lck_mtx_unlock(&nstat_mtx);

	return 0;
}

static errno_t
nstat_control_disconnect(
	__unused kern_ctl_ref	kctl,
	__unused u_int32_t		unit,
	void					*uinfo)
{
	u_int32_t	watching;
	nstat_control_state	*state = (nstat_control_state*)uinfo;

	// pull it out of the global list of states
	lck_mtx_lock(&nstat_mtx);
	nstat_control_state	**statepp;
	for (statepp = &nstat_controls; *statepp; statepp = &(*statepp)->ncs_next)
	{
		if (*statepp == state)
		{
			*statepp = state->ncs_next;
			break;
		}
	}
	lck_mtx_unlock(&nstat_mtx);

	lck_mtx_lock(&state->mtx);
	// Stop watching for sources
	nstat_provider	*provider;
	watching = state->ncs_watching;
	state->ncs_watching = 0;
	for (provider = nstat_providers; provider && watching;  provider = provider->next)
	{
		if ((watching & (1 << provider->nstat_provider_id)) != 0)
		{
			watching &= ~(1 << provider->nstat_provider_id);
			provider->nstat_watcher_remove(state);
		}
	}

	// set cleanup flags
	state->ncs_flags |= NSTAT_FLAG_CLEANUP;

	if (state->ncs_accumulated)
	{
		mbuf_freem(state->ncs_accumulated);
		state->ncs_accumulated = NULL;
	}

	// Copy out the list of sources
	nstat_src	*srcs = state->ncs_srcs;
	state->ncs_srcs = NULL;
	lck_mtx_unlock(&state->mtx);

	while (srcs)
	{
		nstat_src	*src;

		// pull it out of the list
		src = srcs;
		srcs = src->next;

		// clean it up
		nstat_control_cleanup_source(NULL, src, FALSE);
	}
	lck_mtx_destroy(&state->mtx, nstat_lck_grp);
	OSFree(state, sizeof(*state), nstat_malloc_tag);

	return 0;
}

static nstat_src_ref_t
nstat_control_next_src_ref(
	nstat_control_state	*state)
{
	return ++state->ncs_next_srcref;
}

static errno_t
nstat_control_send_counts(
	nstat_control_state	*state,
	nstat_src		*src,
	unsigned long long	context,
	u_int16_t hdr_flags,
	int *gone)
{
	nstat_msg_src_counts counts;
	errno_t result = 0;

	/* Some providers may not have any counts to send */
	if (src->provider->nstat_counts == NULL)
		return (0);

	bzero(&counts, sizeof(counts));
	counts.hdr.type = NSTAT_MSG_TYPE_SRC_COUNTS;
	counts.hdr.length = sizeof(counts);
	counts.hdr.flags = hdr_flags;
	counts.hdr.context = context;
	counts.srcref = src->srcref;
	counts.event_flags = 0;

	if (src->provider->nstat_counts(src->cookie, &counts.counts, gone) == 0)
	{
		if ((src->filter & NSTAT_FILTER_NOZEROBYTES) &&
		    counts.counts.nstat_rxbytes == 0 &&
		    counts.counts.nstat_txbytes == 0)
		{
			result = EAGAIN;
		}
		else
		{
			result = ctl_enqueuedata(state->ncs_kctl,
			    state->ncs_unit, &counts, sizeof(counts),
			    CTL_DATA_EOR);
			if (result != 0)
				nstat_stats.nstat_sendcountfailures += 1;
		}
	}
	return result;
}

static errno_t
nstat_control_append_counts(
	nstat_control_state	*state,
	nstat_src			*src,
	int					*gone)
{
	/* Some providers may not have any counts to send */
	if (!src->provider->nstat_counts) return 0;

	nstat_msg_src_counts counts;
	bzero(&counts, sizeof(counts));
	counts.hdr.type = NSTAT_MSG_TYPE_SRC_COUNTS;
	counts.hdr.length = sizeof(counts);
	counts.srcref = src->srcref;
	counts.event_flags = 0;

	errno_t	result = 0;
	result = src->provider->nstat_counts(src->cookie, &counts.counts, gone);
	if (result != 0)
	{
		return result;
	}

	if ((src->filter & NSTAT_FILTER_NOZEROBYTES) == NSTAT_FILTER_NOZEROBYTES &&
		counts.counts.nstat_rxbytes == 0 && counts.counts.nstat_txbytes == 0)
	{
		return EAGAIN;
	}

	return nstat_accumulate_msg(state, &counts.hdr, counts.hdr.length);
}

static int
nstat_control_send_description(
	nstat_control_state	*state,
	nstat_src			*src,
	u_int64_t			context,
	u_int16_t			hdr_flags)
{
	// Provider doesn't support getting the descriptor? Done.
	if (src->provider->nstat_descriptor_length == 0 ||
		src->provider->nstat_copy_descriptor == NULL)
	{
		return EOPNOTSUPP;
	}

	// Allocate storage for the descriptor message
	mbuf_t			msg;
	unsigned int	one = 1;
	u_int32_t		size = offsetof(nstat_msg_src_description, data) + src->provider->nstat_descriptor_length;
	if (mbuf_allocpacket(MBUF_DONTWAIT, size, &one, &msg) != 0)
	{
		return ENOMEM;
	}

	nstat_msg_src_description	*desc = (nstat_msg_src_description*)mbuf_data(msg);
	bzero(desc, size);
	mbuf_setlen(msg, size);
	mbuf_pkthdr_setlen(msg, mbuf_len(msg));

	// Query the provider for the provider specific bits
	errno_t	result = src->provider->nstat_copy_descriptor(src->cookie, desc->data, src->provider->nstat_descriptor_length);

	if (result != 0)
	{
		mbuf_freem(msg);
		return result;
	}

	desc->hdr.context = context;
	desc->hdr.type = NSTAT_MSG_TYPE_SRC_DESC;
	desc->hdr.length = size;
	desc->hdr.flags = hdr_flags;
	desc->srcref = src->srcref;
	desc->event_flags = 0;
	desc->provider = src->provider->nstat_provider_id;

	result = ctl_enqueuembuf(state->ncs_kctl, state->ncs_unit, msg, CTL_DATA_EOR);
	if (result != 0)
	{
		nstat_stats.nstat_descriptionfailures += 1;
		mbuf_freem(msg);
	}

	return result;
}

static errno_t
nstat_control_append_description(
	nstat_control_state	*state,
	nstat_src			*src)
{
	size_t	size = offsetof(nstat_msg_src_description, data) + src->provider->nstat_descriptor_length;
	if (size > 512 || src->provider->nstat_descriptor_length == 0 ||
		src->provider->nstat_copy_descriptor == NULL)
	{
		return EOPNOTSUPP;
	}

	// Fill out a buffer on the stack, we will copy to the mbuf later
	u_int64_t buffer[size/sizeof(u_int64_t)  + 1]; // u_int64_t to ensure alignment
	bzero(buffer, size);

	nstat_msg_src_description	*desc = (nstat_msg_src_description*)buffer;
	desc->hdr.type = NSTAT_MSG_TYPE_SRC_DESC;
	desc->hdr.length = size;
	desc->srcref = src->srcref;
	desc->event_flags = 0;
	desc->provider = src->provider->nstat_provider_id;

	errno_t	result = 0;
	// Fill in the description
	// Query the provider for the provider specific bits
	result = src->provider->nstat_copy_descriptor(src->cookie, desc->data,
				src->provider->nstat_descriptor_length);
	if (result != 0)
	{
		return result;
	}

	return nstat_accumulate_msg(state, &desc->hdr, size);
}

static int
nstat_control_send_update(
	nstat_control_state	*state,
	nstat_src			*src,
	u_int64_t			context,
	u_int16_t		hdr_flags,
	int					*gone)
{
	// Provider doesn't support getting the descriptor or counts? Done.
	if ((src->provider->nstat_descriptor_length == 0 ||
		 src->provider->nstat_copy_descriptor == NULL) &&
		src->provider->nstat_counts == NULL)
	{
		return EOPNOTSUPP;
	}

	// Allocate storage for the descriptor message
	mbuf_t			msg;
	unsigned int	one = 1;
	u_int32_t		size = offsetof(nstat_msg_src_update, data) +
						   src->provider->nstat_descriptor_length;
	if (mbuf_allocpacket(MBUF_DONTWAIT, size, &one, &msg) != 0)
	{
		return ENOMEM;
	}

	nstat_msg_src_update	*desc = (nstat_msg_src_update*)mbuf_data(msg);
	bzero(desc, size);
	desc->hdr.context = context;
	desc->hdr.type = NSTAT_MSG_TYPE_SRC_UPDATE;
	desc->hdr.length = size;
	desc->hdr.flags = hdr_flags;
	desc->srcref = src->srcref;
	desc->event_flags = 0;
	desc->provider = src->provider->nstat_provider_id;

	mbuf_setlen(msg, size);
	mbuf_pkthdr_setlen(msg, mbuf_len(msg));

	errno_t	result = 0;
	if (src->provider->nstat_descriptor_length != 0 && src->provider->nstat_copy_descriptor)
	{
		// Query the provider for the provider specific bits
		result = src->provider->nstat_copy_descriptor(src->cookie, desc->data,
							src->provider->nstat_descriptor_length);
		if (result != 0)
		{
			mbuf_freem(msg);
			return result;
		}
	}

	if (src->provider->nstat_counts)
	{
		result = src->provider->nstat_counts(src->cookie, &desc->counts, gone);
		if (result == 0)
		{
			if ((src->filter & NSTAT_FILTER_NOZEROBYTES) == NSTAT_FILTER_NOZEROBYTES &&
				desc->counts.nstat_rxbytes == 0 && desc->counts.nstat_txbytes == 0)
			{
				result = EAGAIN;
			}
			else
			{
				result = ctl_enqueuembuf(state->ncs_kctl, state->ncs_unit, msg, CTL_DATA_EOR);
			}
		}
	}

	if (result != 0)
	{
		nstat_stats.nstat_srcupatefailures += 1;
		mbuf_freem(msg);
	}

	return result;
}

static errno_t
nstat_control_append_update(
	nstat_control_state	*state,
	nstat_src			*src,
	int					*gone)
{
	size_t	size = offsetof(nstat_msg_src_update, data) + src->provider->nstat_descriptor_length;
	if (size > 512 || ((src->provider->nstat_descriptor_length == 0 ||
		src->provider->nstat_copy_descriptor == NULL) &&
		src->provider->nstat_counts == NULL))
	{
		return EOPNOTSUPP;
	}

	// Fill out a buffer on the stack, we will copy to the mbuf later
	u_int64_t buffer[size/sizeof(u_int64_t)  + 1]; // u_int64_t to ensure alignment
	bzero(buffer, size);

	nstat_msg_src_update	*desc = (nstat_msg_src_update*)buffer;
	desc->hdr.type = NSTAT_MSG_TYPE_SRC_UPDATE;
	desc->hdr.length = size;
	desc->srcref = src->srcref;
	desc->event_flags = 0;
	desc->provider = src->provider->nstat_provider_id;

	errno_t	result = 0;
	// Fill in the description
	if (src->provider->nstat_descriptor_length != 0 && src->provider->nstat_copy_descriptor)
	{
		// Query the provider for the provider specific bits
		result = src->provider->nstat_copy_descriptor(src->cookie, desc->data,
					src->provider->nstat_descriptor_length);
		if (result != 0)
		{
			nstat_stats.nstat_copy_descriptor_failures++;
			if (nstat_debug != 0)
				printf("%s: src->provider->nstat_copy_descriptor: %d\n", __func__, result);
			return result;
		}
	}

	if (src->provider->nstat_counts)
	{
		result = src->provider->nstat_counts(src->cookie, &desc->counts, gone);
		if (result != 0)
		{
			nstat_stats.nstat_provider_counts_failures++;
			if (nstat_debug != 0)
				printf("%s: src->provider->nstat_counts: %d\n", __func__, result);
			return result;
		}

		if ((src->filter & NSTAT_FILTER_NOZEROBYTES) == NSTAT_FILTER_NOZEROBYTES &&
			desc->counts.nstat_rxbytes == 0 && desc->counts.nstat_txbytes == 0)
		{
			return EAGAIN;
		}
	}

	return nstat_accumulate_msg(state, &desc->hdr, size);
}

static errno_t
nstat_control_send_removed(
	nstat_control_state	*state,
	nstat_src		*src)
{
	nstat_msg_src_removed removed;
	errno_t result;

	bzero(&removed, sizeof(removed));
	removed.hdr.type = NSTAT_MSG_TYPE_SRC_REMOVED;
	removed.hdr.length = sizeof(removed);
	removed.hdr.context = 0;
	removed.srcref = src->srcref;
	result = ctl_enqueuedata(state->ncs_kctl, state->ncs_unit, &removed,
	    sizeof(removed), CTL_DATA_EOR | CTL_DATA_CRIT);
	if (result != 0)
		nstat_stats.nstat_msgremovedfailures += 1;

	return result;
}

static errno_t
nstat_control_handle_add_request(
	nstat_control_state	*state,
	mbuf_t				m)
{
	errno_t	result;

	// Verify the header fits in the first mbuf
	if (mbuf_len(m) < offsetof(nstat_msg_add_src_req, param))
	{
		return EINVAL;
	}

	// Calculate the length of the parameter field
	int32_t	paramlength = mbuf_pkthdr_len(m) - offsetof(nstat_msg_add_src_req, param);
	if (paramlength < 0 || paramlength > 2 * 1024)
	{
		return EINVAL;
	}

	nstat_provider			*provider;
	nstat_provider_cookie_t	cookie;
	nstat_msg_add_src_req	*req = mbuf_data(m);
	if (mbuf_pkthdr_len(m) > mbuf_len(m))
	{
		// parameter is too large, we need to make a contiguous copy
		void	*data = OSMalloc(paramlength, nstat_malloc_tag);

		if (!data) return ENOMEM;
		result = mbuf_copydata(m, offsetof(nstat_msg_add_src_req, param), paramlength, data);
		if (result == 0)
			result = nstat_lookup_entry(req->provider, data, paramlength, &provider, &cookie);
		OSFree(data, paramlength, nstat_malloc_tag);
	}
	else
	{
		result = nstat_lookup_entry(req->provider, (void*)&req->param, paramlength, &provider, &cookie);
	}

	if (result != 0)
	{
		return result;
	}

	result = nstat_control_source_add(req->hdr.context, state, provider, cookie);
	if (result != 0)
		provider->nstat_release(cookie, 0);

	return result;
}

static errno_t
nstat_control_handle_add_all(
	nstat_control_state	*state,
	mbuf_t				m)
{
	errno_t	result = 0;

	// Verify the header fits in the first mbuf
	if (mbuf_len(m) < sizeof(nstat_msg_add_all_srcs))
	{
		return EINVAL;
	}


	nstat_msg_add_all_srcs	*req = mbuf_data(m);
	if (req->provider > NSTAT_PROVIDER_LAST) return ENOENT;

	nstat_provider			*provider = nstat_find_provider_by_id(req->provider);

	if (!provider) return ENOENT;
	if (provider->nstat_watcher_add == NULL) return ENOTSUP;

	if (nstat_privcheck != 0) {
		result = priv_check_cred(kauth_cred_get(),
		    PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0);
		if (result != 0)
			return result;
	}

	// Make sure we don't add the provider twice
	lck_mtx_lock(&state->mtx);
	if ((state->ncs_watching & (1 << provider->nstat_provider_id)) != 0)
		result = EALREADY;
	state->ncs_watching |= (1 << provider->nstat_provider_id);
	lck_mtx_unlock(&state->mtx);
	if (result != 0) return result;

	state->ncs_provider_filters[req->provider].npf_flags  = req->filter;
	state->ncs_provider_filters[req->provider].npf_events = req->events;
	state->ncs_provider_filters[req->provider].npf_pid    = req->target_pid;
	memcpy(state->ncs_provider_filters[req->provider].npf_uuid, req->target_uuid,
		   sizeof(state->ncs_provider_filters[req->provider].npf_uuid));

	result = provider->nstat_watcher_add(state);
	if (result != 0)
	{
		state->ncs_provider_filters[req->provider].npf_flags  = 0;
		state->ncs_provider_filters[req->provider].npf_events = 0;
		state->ncs_provider_filters[req->provider].npf_pid    = 0;
		bzero(state->ncs_provider_filters[req->provider].npf_uuid,
			  sizeof(state->ncs_provider_filters[req->provider].npf_uuid));

		lck_mtx_lock(&state->mtx);
		state->ncs_watching &= ~(1 << provider->nstat_provider_id);
		lck_mtx_unlock(&state->mtx);
	}
	if (result == 0)
		nstat_enqueue_success(req->hdr.context, state, 0);

	return result;
}

static errno_t
nstat_control_source_add(
	u_int64_t			context,
	nstat_control_state		*state,
	nstat_provider			*provider,
	nstat_provider_cookie_t		cookie)
{
	// Fill out source added message if appropriate
	mbuf_t			msg = NULL;
	nstat_src_ref_t		*srcrefp = NULL;

	u_int64_t		provider_filter_flagss =
	    state->ncs_provider_filters[provider->nstat_provider_id].npf_flags;
	boolean_t		tell_user =
	    ((provider_filter_flagss & NSTAT_FILTER_SUPPRESS_SRC_ADDED) == 0);
	u_int32_t		src_filter =
	    (provider_filter_flagss & NSTAT_FILTER_PROVIDER_NOZEROBYTES)
		? NSTAT_FILTER_NOZEROBYTES : 0;

	if (tell_user)
	{
		unsigned int one = 1;

		if (mbuf_allocpacket(MBUF_DONTWAIT, sizeof(nstat_msg_src_added),
		    &one, &msg) != 0)
			return ENOMEM;

		mbuf_setlen(msg, sizeof(nstat_msg_src_added));
		mbuf_pkthdr_setlen(msg, mbuf_len(msg));
		nstat_msg_src_added	*add = mbuf_data(msg);
		bzero(add, sizeof(*add));
		add->hdr.type = NSTAT_MSG_TYPE_SRC_ADDED;
		add->hdr.length = mbuf_len(msg);
		add->hdr.context = context;
		add->provider = provider->nstat_provider_id;
		srcrefp = &add->srcref;
	}

	// Allocate storage for the source
	nstat_src	*src = OSMalloc(sizeof(*src), nstat_malloc_tag);
	if (src == NULL)
	{
		if (msg) mbuf_freem(msg);
		return ENOMEM;
	}

	// Fill in the source, including picking an unused source ref
	lck_mtx_lock(&state->mtx);

	src->srcref = nstat_control_next_src_ref(state);
	if (srcrefp)
		*srcrefp = src->srcref;

	if (state->ncs_flags & NSTAT_FLAG_CLEANUP || src->srcref == NSTAT_SRC_REF_INVALID)
	{
		lck_mtx_unlock(&state->mtx);
		OSFree(src, sizeof(*src), nstat_malloc_tag);
		if (msg) mbuf_freem(msg);
		return EINVAL;
	}
	src->provider = provider;
	src->cookie = cookie;
	src->filter = src_filter;

	if (msg)
	{
		// send the source added message if appropriate
		errno_t result = ctl_enqueuembuf(state->ncs_kctl, state->ncs_unit, msg,
						CTL_DATA_EOR);
		if (result != 0)
		{
			nstat_stats.nstat_srcaddedfailures += 1;
			lck_mtx_unlock(&state->mtx);
			OSFree(src, sizeof(*src), nstat_malloc_tag);
			mbuf_freem(msg);
			return result;
		}
	}
	// Put the source in the list
	src->next = state->ncs_srcs;
	state->ncs_srcs = src;

	lck_mtx_unlock(&state->mtx);

	return 0;
}

static errno_t
nstat_control_handle_remove_request(
	nstat_control_state	*state,
	mbuf_t				m)
{
	nstat_src_ref_t			srcref = NSTAT_SRC_REF_INVALID;

	if (mbuf_copydata(m, offsetof(nstat_msg_rem_src_req, srcref), sizeof(srcref), &srcref) != 0)
	{
		return EINVAL;
	}

	lck_mtx_lock(&state->mtx);

	// Remove this source as we look for it
	nstat_src	**nextp;
	nstat_src	*src = NULL;
	for (nextp = &state->ncs_srcs; *nextp; nextp = &(*nextp)->next)
	{
		if ((*nextp)->srcref == srcref)
		{
			src = *nextp;
			*nextp = src->next;
			break;
		}
	}

	lck_mtx_unlock(&state->mtx);

	if (src) nstat_control_cleanup_source(state, src, FALSE);

	return src ? 0 : ENOENT;
}

static errno_t
nstat_control_handle_query_request(
	nstat_control_state	*state,
	mbuf_t				m)
{
	// TBD: handle this from another thread so we can enqueue a lot of data
	// As written, if a client requests query all, this function will be
	// called from their send of the request message. We will attempt to write
	// responses and succeed until the buffer fills up. Since the clients thread
	// is blocked on send, it won't be reading unless the client has two threads
	// using this socket, one for read and one for write. Two threads probably
	// won't work with this code anyhow since we don't have proper locking in
	// place yet.
	nstat_src				*dead_srcs = NULL;
	errno_t					result = ENOENT;
	nstat_msg_query_src_req	req;

	if (mbuf_copydata(m, 0, sizeof(req), &req) != 0)
	{
		return EINVAL;
	}

	const boolean_t all_srcs = (req.srcref == NSTAT_SRC_REF_ALL);

	lck_mtx_lock(&state->mtx);

	if (all_srcs)
	{
		state->ncs_flags |= NSTAT_FLAG_REQCOUNTS;
	}
	nstat_src	**srcpp = &state->ncs_srcs;
	u_int64_t	src_count = 0;
	boolean_t	partial = FALSE;

	/*
	 * Error handling policy and sequence number generation is folded into
	 * nstat_control_begin_query.
	 */
	partial = nstat_control_begin_query(state, &req.hdr);

	while (*srcpp != NULL
		&& (!partial || src_count < QUERY_CONTINUATION_SRC_COUNT))
	{
		nstat_src	*src = NULL;
		int			gone;

		src = *srcpp;
		gone = 0;
		// XXX ignore IFACE types?
		if (all_srcs || src->srcref == req.srcref)
		{
			if (nstat_control_reporting_allowed(state, src)
			    && (!partial || !all_srcs || src->seq != state->ncs_seq))
			{
				if (all_srcs &&
					(req.hdr.flags & NSTAT_MSG_HDR_FLAG_SUPPORTS_AGGREGATE) != 0)
				{
					result = nstat_control_append_counts(state, src, &gone);
				}
				else
				{
					result = nstat_control_send_counts(state, src, req.hdr.context, 0, &gone);
				}

				if (ENOMEM == result || ENOBUFS == result)
				{
					/*
					 * If the counts message failed to
					 * enqueue then we should clear our flag so
					 * that a client doesn't miss anything on
					 * idle cleanup.  We skip the "gone"
					 * processing in the hope that we may
					 * catch it another time.
					 */
					state->ncs_flags &= ~NSTAT_FLAG_REQCOUNTS;
					break;
				}
				if (partial)
				{
					/*
					 * We skip over hard errors and
					 * filtered sources.
					 */
					src->seq = state->ncs_seq;
					src_count++;
				}
			}
		}

		if (gone)
		{
			// send one last descriptor message so client may see last state
			// If we can't send the notification now, it
			// will be sent in the idle cleanup.
			result = nstat_control_send_description(state, *srcpp, 0, 0);
			if (result != 0)
			{
				nstat_stats.nstat_control_send_description_failures++;
				if (nstat_debug != 0)
					printf("%s - nstat_control_send_description() %d\n", __func__, result);
				state->ncs_flags &= ~NSTAT_FLAG_REQCOUNTS;
				break;
			}

			// pull src out of the list
			*srcpp = src->next;

			src->next = dead_srcs;
			dead_srcs = src;
		}
		else
		{
			srcpp = &(*srcpp)->next;
		}

		if (!all_srcs && req.srcref == src->srcref)
		{
			break;
		}
	}
	nstat_flush_accumulated_msgs(state);

	u_int16_t flags = 0;
	if (req.srcref == NSTAT_SRC_REF_ALL)
		flags = nstat_control_end_query(state, *srcpp, partial);

	lck_mtx_unlock(&state->mtx);

	/*
	 * If an error occurred enqueueing data, then allow the error to
	 * propagate to nstat_control_send. This way, the error is sent to
	 * user-level.
	 */
	if (all_srcs && ENOMEM != result && ENOBUFS != result)
	{
		nstat_enqueue_success(req.hdr.context, state, flags);
		result = 0;
	}

	while (dead_srcs)
	{
		nstat_src	*src;

		src = dead_srcs;
		dead_srcs = src->next;

		// release src and send notification
		nstat_control_cleanup_source(state, src, FALSE);
	}

	return result;
}

static errno_t
nstat_control_handle_get_src_description(
	nstat_control_state	*state,
	mbuf_t				m)
{
	nstat_msg_get_src_description	req;
	errno_t result = ENOENT;
	nstat_src *src;

	if (mbuf_copydata(m, 0, sizeof(req), &req) != 0)
	{
		return EINVAL;
	}

	lck_mtx_lock(&state->mtx);
	u_int64_t src_count = 0;
	boolean_t partial = FALSE;
	const boolean_t all_srcs = (req.srcref == NSTAT_SRC_REF_ALL);

	/*
	 * Error handling policy and sequence number generation is folded into
	 * nstat_control_begin_query.
	 */
	partial = nstat_control_begin_query(state, &req.hdr);

	for (src = state->ncs_srcs;
	     src && (!partial || src_count < QUERY_CONTINUATION_SRC_COUNT);
	     src = src->next)
	{
		if (all_srcs || src->srcref == req.srcref)
		{
			if (nstat_control_reporting_allowed(state, src)
			    && (!all_srcs || !partial ||  src->seq != state->ncs_seq))
			{
				if ((req.hdr.flags & NSTAT_MSG_HDR_FLAG_SUPPORTS_AGGREGATE) != 0 && all_srcs)
				{
					result = nstat_control_append_description(state, src);
				}
				else
				{
					result = nstat_control_send_description(state, src, req.hdr.context, 0);
				}

				if (ENOMEM == result || ENOBUFS == result)
				{
					/*
					 * If the description message failed to
					 * enqueue then we give up for now.
					 */
					break;
				}
				if (partial)
				{
					/*
					 * Note, we skip over hard errors and
					 * filtered sources.
					 */
					src->seq = state->ncs_seq;
					src_count++;
				}
			}

			if (!all_srcs)
			{
				break;
			}
		}
	}
	nstat_flush_accumulated_msgs(state);

	u_int16_t flags = 0;
	if (req.srcref == NSTAT_SRC_REF_ALL)
		flags = nstat_control_end_query(state, src, partial);

	lck_mtx_unlock(&state->mtx);
	/*
	 * If an error occurred enqueueing data, then allow the error to
	 * propagate to nstat_control_send. This way, the error is sent to
	 * user-level.
	 */
	if (all_srcs && ENOMEM != result && ENOBUFS != result)
	{
		nstat_enqueue_success(req.hdr.context, state, flags);
		result = 0;
	}

	return result;
}

static errno_t
nstat_control_handle_set_filter(
    nstat_control_state		*state,
    mbuf_t			m)
{
	nstat_msg_set_filter req;
	nstat_src *src;

	if (mbuf_copydata(m, 0, sizeof(req), &req) != 0)
		return EINVAL;
	if (req.srcref == NSTAT_SRC_REF_ALL ||
	    req.srcref == NSTAT_SRC_REF_INVALID)
		return EINVAL;

	lck_mtx_lock(&state->mtx);
	for (src = state->ncs_srcs; src; src = src->next)
		if (req.srcref == src->srcref)
		{
			src->filter = req.filter;
			break;
		}
	lck_mtx_unlock(&state->mtx);
	if (src == NULL)
		return ENOENT;

	return 0;
}

static void
nstat_send_error(
    nstat_control_state *state,
    u_int64_t context,
    u_int32_t error)
{
	errno_t result;
	struct nstat_msg_error	err;

	bzero(&err, sizeof(err));
	err.hdr.type = NSTAT_MSG_TYPE_ERROR;
	err.hdr.length = sizeof(err);
	err.hdr.context = context;
	err.error = error;

	result = ctl_enqueuedata(state->ncs_kctl, state->ncs_unit, &err,
				    sizeof(err), CTL_DATA_EOR | CTL_DATA_CRIT);
	if (result != 0)
		nstat_stats.nstat_msgerrorfailures++;
}

static boolean_t
nstat_control_begin_query(
    nstat_control_state *state,
    const nstat_msg_hdr *hdrp)
{
	boolean_t partial = FALSE;

	if (hdrp->flags & NSTAT_MSG_HDR_FLAG_CONTINUATION)
	{
		/* A partial query all has been requested. */
		partial = TRUE;

		if (state->ncs_context != hdrp->context)
		{
			if (state->ncs_context != 0)
				nstat_send_error(state, state->ncs_context, EAGAIN);

			/* Initialize state for a partial query all. */
			state->ncs_context = hdrp->context;
			state->ncs_seq++;
		}
	}
	else if (state->ncs_context != 0)
	{
		/*
		 * A continuation of a paced-query was in progress. Send that
		 * context an error and reset the state.  If the same context
		 * has changed its mind, just send the full query results.
		 */
		if (state->ncs_context != hdrp->context)
			nstat_send_error(state, state->ncs_context, EAGAIN);
	}

	return partial;
}

static u_int16_t
nstat_control_end_query(
    nstat_control_state *state,
    nstat_src *last_src,
    boolean_t partial)
{
	u_int16_t flags = 0;

	if (last_src == NULL || !partial)
	{
		/*
		 * We iterated through the entire srcs list or exited early
		 * from the loop when a partial update was not requested (an
		 * error occurred), so clear context to indicate internally
		 * that the query is finished.
		 */
		state->ncs_context = 0;
	}
	else
	{
		/*
		 * Indicate to userlevel to make another partial request as
		 * there are still sources left to be reported.
		 */
		flags |= NSTAT_MSG_HDR_FLAG_CONTINUATION;
	}

	return flags;
}

static errno_t
nstat_control_handle_get_update(
    nstat_control_state		*state,
    mbuf_t					m)
{
	nstat_msg_query_src_req	req;

	if (mbuf_copydata(m, 0, sizeof(req), &req) != 0)
	{
		return EINVAL;
	}

	lck_mtx_lock(&state->mtx);

	state->ncs_flags |= NSTAT_FLAG_SUPPORTS_UPDATES;

	errno_t		result = ENOENT;
	nstat_src	*src;
	nstat_src	*dead_srcs = NULL;
	nstat_src	**srcpp = &state->ncs_srcs;
	u_int64_t src_count = 0;
	boolean_t partial = FALSE;

	/*
	 * Error handling policy and sequence number generation is folded into
	 * nstat_control_begin_query.
	 */
	partial = nstat_control_begin_query(state, &req.hdr);

	while (*srcpp != NULL
	    && (FALSE == partial
		|| src_count < QUERY_CONTINUATION_SRC_COUNT))
	{
		int			gone;

		gone = 0;
		src = *srcpp;
		if (nstat_control_reporting_allowed(state, src))
		{
			/* skip this source if it has the current state
			 * sequence number as it's already been reported in
			 * this query-all partial sequence. */
			if (req.srcref == NSTAT_SRC_REF_ALL
			    && (FALSE == partial || src->seq != state->ncs_seq))
			{
				result = nstat_control_append_update(state, src, &gone);
				if (ENOMEM == result || ENOBUFS == result)
				{
					/*
					 * If the update message failed to
					 * enqueue then give up.
					 */
					break;
				}
				if (partial)
				{
					/*
					 * We skip over hard errors and
					 * filtered sources.
					 */
					src->seq = state->ncs_seq;
					src_count++;
				}
			}
			else if (src->srcref == req.srcref)
			{
				result = nstat_control_send_update(state, src, req.hdr.context, 0, &gone);
			}
		}

		if (gone)
		{
			// pull src out of the list
			*srcpp = src->next;

			src->next = dead_srcs;
			dead_srcs = src;
		}
		else
		{
			srcpp = &(*srcpp)->next;
		}

		if (req.srcref != NSTAT_SRC_REF_ALL && req.srcref == src->srcref)
		{
			break;
		}
	}

	nstat_flush_accumulated_msgs(state);


	u_int16_t flags = 0;
	if (req.srcref == NSTAT_SRC_REF_ALL)
		flags = nstat_control_end_query(state, *srcpp, partial);

	lck_mtx_unlock(&state->mtx);
	/*
	 * If an error occurred enqueueing data, then allow the error to
	 * propagate to nstat_control_send. This way, the error is sent to
	 * user-level.
	 */
	if (req.srcref == NSTAT_SRC_REF_ALL && ENOMEM != result && ENOBUFS != result)
	{
		nstat_enqueue_success(req.hdr.context, state, flags);
		result = 0;
	}

	while (dead_srcs)
	{
		src = dead_srcs;
		dead_srcs = src->next;

		// release src and send notification
		nstat_control_cleanup_source(state, src, FALSE);
	}

	return result;
}

static errno_t
nstat_control_handle_subscribe_sysinfo(
    nstat_control_state		*state)
{
	errno_t result = priv_check_cred(kauth_cred_get(), PRIV_NET_PRIVILEGED_NETWORK_STATISTICS, 0);

	if (result != 0)
	{
		return result;
	}

	lck_mtx_lock(&state->mtx);
	state->ncs_flags |= NSTAT_FLAG_SYSINFO_SUBSCRIBED;
	lck_mtx_unlock(&state->mtx);

	return 0;
}

static errno_t
nstat_control_send(
	kern_ctl_ref	kctl,
	u_int32_t		unit,
	void	*uinfo,
	mbuf_t			m,
	__unused int	flags)
{
	nstat_control_state	*state = (nstat_control_state*)uinfo;
	struct nstat_msg_hdr	*hdr;
	struct nstat_msg_hdr	storage;
	errno_t					result = 0;

	if (mbuf_pkthdr_len(m) < sizeof(*hdr))
	{
		// Is this the right thing to do?
		mbuf_freem(m);
		return EINVAL;
	}

	if (mbuf_len(m) >= sizeof(*hdr))
	{
		hdr = mbuf_data(m);
	}
	else
	{
		mbuf_copydata(m, 0, sizeof(storage), &storage);
		hdr = &storage;
	}

	// Legacy clients may not set the length
	// Those clients are likely not setting the flags either
	// Fix everything up so old clients continue to work
	if (hdr->length != mbuf_pkthdr_len(m))
	{
		hdr->flags = 0;
		hdr->length = mbuf_pkthdr_len(m);
		if (hdr == &storage)
		{
			mbuf_copyback(m, 0, sizeof(*hdr), hdr, MBUF_DONTWAIT);
		}
	}

	switch (hdr->type)
	{
		case NSTAT_MSG_TYPE_ADD_SRC:
			result = nstat_control_handle_add_request(state, m);
			break;

		case NSTAT_MSG_TYPE_ADD_ALL_SRCS:
			result = nstat_control_handle_add_all(state, m);
			break;

		case NSTAT_MSG_TYPE_REM_SRC:
			result = nstat_control_handle_remove_request(state, m);
			break;

		case NSTAT_MSG_TYPE_QUERY_SRC:
			result = nstat_control_handle_query_request(state, m);
			break;

		case NSTAT_MSG_TYPE_GET_SRC_DESC:
			result = nstat_control_handle_get_src_description(state, m);
			break;

		case NSTAT_MSG_TYPE_SET_FILTER:
			result = nstat_control_handle_set_filter(state, m);
			break;

		case NSTAT_MSG_TYPE_GET_UPDATE:
			result = nstat_control_handle_get_update(state, m);
			break;

		case NSTAT_MSG_TYPE_SUBSCRIBE_SYSINFO:
			result = nstat_control_handle_subscribe_sysinfo(state);
			break;

		default:
			result = EINVAL;
			break;
	}

	if (result != 0)
	{
		struct nstat_msg_error	err;

		bzero(&err, sizeof(err));
		err.hdr.type = NSTAT_MSG_TYPE_ERROR;
		err.hdr.length = sizeof(err) + mbuf_pkthdr_len(m);
		err.hdr.context = hdr->context;
		err.error = result;

		if (mbuf_prepend(&m, sizeof(err), MBUF_DONTWAIT) == 0 &&
			mbuf_copyback(m, 0, sizeof(err), &err, MBUF_DONTWAIT) == 0)
		{
			result = ctl_enqueuembuf(kctl, unit, m, CTL_DATA_EOR | CTL_DATA_CRIT);
			if (result != 0)
			{
				mbuf_freem(m);
			}
			m = NULL;
		}

		if (result != 0)
		{
			// Unable to prepend the error to the request - just send the error
			err.hdr.length = sizeof(err);
			result = ctl_enqueuedata(kctl, unit, &err, sizeof(err),
						CTL_DATA_EOR | CTL_DATA_CRIT);
			if (result != 0)
				nstat_stats.nstat_msgerrorfailures += 1;
		}
		nstat_stats.nstat_handle_msg_failures += 1;
	}

	if (m) mbuf_freem(m);

	return result;
}
