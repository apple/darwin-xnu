/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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
#include <kern/zalloc.h>
#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet6/in6_ifattach.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/scope6_var.h>
#include <sys/mcache.h>

#define NDRTI_ZONE_NAME "nd6_route_info"        /* zone name */

extern lck_mtx_t *nd6_mutex;
static struct nd_route_info *nd6_rti_lookup(struct nd_route_info *);

static ZONE_DECLARE(ndrti_zone, "nd6_route_info",
    sizeof(struct nd_route_info), ZC_ZFREE_CLEARMEM);

static boolean_t nd6_rti_list_busy = FALSE;             /* protected by nd6_mutex */


void
nd6_rti_list_wait(const char *func)
{
	LCK_MTX_ASSERT(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	while (nd6_rti_list_busy) {
		nd6log2(debug, "%s: someone else is operating "
		    "on rti list. Entering sleep.\n", func);
		(void) msleep(&nd6_rti_list_busy, nd6_mutex, (PZERO - 1),
		    func, NULL);
		LCK_MTX_ASSERT(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	}
	nd6_rti_list_busy = TRUE;
}

void
nd6_rti_list_signal_done(void)
{
	LCK_MTX_ASSERT(nd6_mutex, LCK_MTX_ASSERT_OWNED);
	nd6_rti_list_busy = FALSE;
	wakeup(&nd6_rti_list_busy);
}

struct nd_route_info *
ndrti_alloc(void)
{
	return zalloc_flags(ndrti_zone, Z_WAITOK | Z_ZERO);
}

void
ndrti_free(struct nd_route_info *rti)
{
	if (!TAILQ_EMPTY(&rti->nd_rti_router_list)) {
		panic("%s: rti freed with non-empty router list", __func__);
	}
	zfree(ndrti_zone, rti);
}

static struct nd_route_info *
nd6_rti_lookup(struct nd_route_info *rti)
{
	struct nd_route_info *tmp_rti = NULL;

	LCK_MTX_ASSERT(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	TAILQ_FOREACH(tmp_rti, &nd_rti_list, nd_rti_entry) {
		if (IN6_ARE_ADDR_EQUAL(&tmp_rti->nd_rti_prefix, &rti->nd_rti_prefix) &&
		    tmp_rti->nd_rti_prefixlen == rti->nd_rti_prefixlen) {
			break;
		}
	}
	return tmp_rti;
}

void
nd6_rtilist_update(struct nd_route_info *new_rti, struct nd_defrouter *dr)
{
	struct nd_route_info *rti = NULL;

	lck_mtx_lock(nd6_mutex);
	VERIFY(new_rti != NULL && dr != NULL);
	nd6_rti_list_wait(__func__);

	if ((rti = nd6_rti_lookup(new_rti)) != NULL) {
		(void)defrtrlist_update(dr, &rti->nd_rti_router_list);
		/*
		 * The above may have removed an entry from default router list.
		 * If it did and the list is now empty, remove the rti as well.
		 */
		if (TAILQ_EMPTY(&rti->nd_rti_router_list)) {
			TAILQ_REMOVE(&nd_rti_list, rti, nd_rti_entry);
			ndrti_free(rti);
		}
	} else if (dr->rtlifetime != 0) {
		rti = ndrti_alloc();
		TAILQ_INIT(&rti->nd_rti_router_list);
		rti->nd_rti_prefix = new_rti->nd_rti_prefix;
		rti->nd_rti_prefixlen = new_rti->nd_rti_prefixlen;
		(void)defrtrlist_update(dr, &rti->nd_rti_router_list);
		TAILQ_INSERT_HEAD(&nd_rti_list, rti, nd_rti_entry);
	}
	/* If rti doesn't exist and lifetime is 0, simply ignore */
	nd6_rti_list_signal_done();
	lck_mtx_unlock(nd6_mutex);
}

void
nd6_rti_purge(struct nd_route_info *new_rti)
{
	VERIFY(new_rti != NULL);
	LCK_MTX_ASSERT(nd6_mutex, LCK_MTX_ASSERT_OWNED);

	struct nd_route_info *rti = NULL;
	nd6_rti_list_wait(__func__);

	if ((rti = nd6_rti_lookup(new_rti)) != NULL) {
		struct nd_defrouter *dr = NULL;
		struct nd_defrouter *ndr = NULL;

		TAILQ_FOREACH_SAFE(dr, &rti->nd_rti_router_list, dr_entry, ndr) {
			TAILQ_REMOVE(&rti->nd_rti_router_list, dr, dr_entry);
			defrtrlist_del(dr, &rti->nd_rti_router_list);
			NDDR_REMREF(dr);
		}
		TAILQ_REMOVE(&nd_rti_list, rti, nd_rti_entry);
		ndrti_free(rti);
	}
	nd6_rti_list_signal_done();
}
