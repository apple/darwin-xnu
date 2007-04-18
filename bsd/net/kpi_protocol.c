/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

#include "kpi_protocol.h"

#include <sys/param.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/kpi_mbuf.h>
#include <sys/domain.h>
#include <net/if.h>
#include <net/dlil.h>
#include <libkern/OSAtomic.h>

void proto_kpi_init(void);
void proto_input_run(void);

typedef int (*attach_t)(struct ifnet *ifp, u_long protocol_family);
typedef int (*detach_t)(struct ifnet *ifp, u_long protocol_family);

/****************************************************************************/
/* WARNING: Big assumption made here - there can be only one input thread	*/
struct proto_input_entry {
	struct proto_input_entry		*next;
	int								detach;
	struct domain					*domain;
	
	protocol_family_t				protocol;
	proto_input_handler				input;
	proto_input_detached_handler	detached;
	
	mbuf_t							first_packet;
	mbuf_t							last_packet;
};

#define PROTO_HASH_SLOTS	5

static struct proto_input_entry	*proto_hash[PROTO_HASH_SLOTS];
static struct proto_input_entry *proto_input_add_list;
static lck_mtx_t				*proto_input_lock = 0;
__private_extern__ u_int32_t	inject_buckets = 0;

extern thread_t	dlil_input_thread_ptr;
extern int		dlil_input_thread_wakeup;

static int
proto_hash_value(
	protocol_family_t protocol)
{
	switch(protocol) {
		case PF_INET:
			return 0;
		case PF_INET6:
			return 1;
		case PF_APPLETALK:
			return 2;
		case PF_VLAN:
			return 3;
	}
	return 4;
}

__private_extern__ void
proto_kpi_init(void)
{
	lck_grp_attr_t	*grp_attrib = 0;
	lck_attr_t		*lck_attrib = 0;
	lck_grp_t		*lck_group = 0;
	
	/* Allocate a mtx lock */
	grp_attrib = lck_grp_attr_alloc_init();
	lck_group = lck_grp_alloc_init("protocol kpi", grp_attrib);
	lck_grp_attr_free(grp_attrib);
	lck_attrib = lck_attr_alloc_init();
	proto_input_lock = lck_mtx_alloc_init(lck_group, lck_attrib);
	lck_grp_free(lck_group);
	lck_attr_free(lck_attrib);
}

__private_extern__ errno_t
proto_register_input(
	protocol_family_t protocol,
	proto_input_handler input,
	proto_input_detached_handler detached)
{
	
	struct proto_input_entry *entry;
	
	entry = _MALLOC(sizeof(*entry), M_IFADDR, M_WAITOK);
	
	if (entry == NULL)
		return ENOMEM;
	
	bzero(entry, sizeof(*entry));
	entry->protocol = protocol;
	entry->input = input;
	entry->detached = detached;
	
	{
		struct domain *dp = domains;
		extern lck_mtx_t *domain_proto_mtx;

		lck_mtx_assert(domain_proto_mtx, LCK_MTX_ASSERT_NOTOWNED);
         	lck_mtx_lock(domain_proto_mtx);
		while (dp && dp->dom_family != protocol)
			dp = dp->dom_next;
		entry->domain = dp;
         	lck_mtx_unlock(domain_proto_mtx);	
	}

	
	do {
		entry->next = proto_input_add_list;
	} while(!OSCompareAndSwap((UInt32)entry->next, (UInt32)entry, (UInt32*)&proto_input_add_list));
	
	wakeup((caddr_t)&dlil_input_thread_wakeup);
	
	return 0;
}


__private_extern__ void
proto_unregister_input(
	protocol_family_t	protocol)
{
	struct proto_input_entry *entry = NULL;
	
	for (entry = proto_hash[proto_hash_value(protocol)]; entry; entry = entry->next)
		if (entry->protocol == protocol)
			break;
	
	if (entry)
		entry->detach = 1;
}


static void
proto_delayed_attach(
	struct proto_input_entry *entry)
{
	struct proto_input_entry *next_entry;
	for (next_entry = entry->next; entry; entry = next_entry) {
		struct proto_input_entry *exist;
		int hash_slot;
		
		hash_slot = proto_hash_value(entry->protocol);
		next_entry = entry->next;
		
		for (exist = proto_hash[hash_slot]; exist; exist = exist->next)
			if (exist->protocol == entry->protocol)
				break;
		
		/* If the entry already exists, call detached and dispose */
		if (exist) {
			if (entry->detached)
				entry->detached(entry->protocol);
			FREE(entry, M_IFADDR);
		}
		else {
			entry->next = proto_hash[hash_slot];
			proto_hash[hash_slot] = entry;
		}
	}
}

static void
proto_delayed_inject(
	struct proto_input_entry *entry)
{
	mbuf_t	packet_list;
	mbuf_t	packet;
	int		locked = 0;
	
	lck_mtx_lock(proto_input_lock);
	packet_list = entry->first_packet;
	entry->first_packet = entry->last_packet = 0;
	lck_mtx_unlock(proto_input_lock);
	
	if (packet_list == NULL)
		return;
	
	if (entry->domain && (entry->domain->dom_flags & DOM_REENTRANT) == 0) {
		lck_mtx_lock(entry->domain->dom_mtx);
		locked = 1;
	}
	
	for (packet = packet_list; packet; packet = packet_list) {
		packet_list = mbuf_nextpkt(packet);
		mbuf_setnextpkt(packet, NULL);
		entry->input(entry->protocol, packet);
	}
	
	if (locked) {
		lck_mtx_unlock(entry->domain->dom_mtx);
	}
}

/* This function must be called from a single dlil input thread */
__private_extern__ void
proto_input_run(void)
{
	struct proto_input_entry	*entry;
	u_int32_t					inject;
	int							i;
	
	if (current_thread() != dlil_input_thread_ptr)
		panic("proto_input_run called from a thread other than dlil_input_thread!\n");

	do {
		entry = proto_input_add_list;
	} while (entry && !OSCompareAndSwap((UInt32)entry, 0, (UInt32*)&proto_input_add_list));
	
	if (entry)
		proto_delayed_attach(entry);
	
	do {
		inject = inject_buckets;
	} while (inject && !OSCompareAndSwap(inject, 0, (UInt32*)&inject_buckets));
	
	if (inject) {
		for (i = 0; i < PROTO_HASH_SLOTS; i++) {
			if ((inject & (1L << i)) != 0) {
				for (entry = proto_hash[i]; entry; entry = entry->next) {
					if (entry->first_packet) {
						proto_delayed_inject(entry);
					}
				}
			}
		}
	}
}

errno_t
proto_input(
	protocol_family_t	protocol,
	mbuf_t				packet_list)
{
	struct proto_input_entry *entry;
	
	if (current_thread() != dlil_input_thread_ptr)
		panic("proto_input called from a thread other than dlil_input_thread!\n");
	
	for (entry = proto_hash[proto_hash_value(protocol)]; entry; entry = entry->next) {
		if (entry->protocol == protocol)
			break;
	}

	if (entry) {
		mbuf_t	packet;
#if DIRECT_PROTO_INPUT
		// See <rdar://problem/3687868> for why this is disabled
		// We need to release the dlil lock before taking the protocol lock
		for (packet = packet_list; packet; packet = packet_list) {
			packet_list = mbuf_nextpkt(packet);
			mbuf_setnextpkt(packet, NULL);
			entry->input(entry->protocol, packet);
		}
#else
		mbuf_t	last_packet;
		int		hash_slot = proto_hash_value(protocol);
		
		for (last_packet = packet_list; mbuf_nextpkt(last_packet);
			 last_packet = mbuf_nextpkt(last_packet))
			/* find the last packet */;
		
		lck_mtx_lock(proto_input_lock);
		if (entry->first_packet == NULL) {
			entry->first_packet = packet_list;
		}
		else {
			mbuf_setnextpkt(entry->last_packet, packet_list);
		}
		entry->last_packet = last_packet;
		lck_mtx_unlock(proto_input_lock);
	
		OSBitOrAtomic((1L << hash_slot), (UInt32*)&inject_buckets);
#endif
	}
	else
	{
		return ENOENT;
	}
	
	return 0;
}

errno_t
proto_inject(
	protocol_family_t	protocol,
	mbuf_t				packet_list)
{
	struct proto_input_entry	*entry;
	mbuf_t						last_packet;
	int							hash_slot = proto_hash_value(protocol);
	
	for (last_packet = packet_list; mbuf_nextpkt(last_packet);
		 last_packet = mbuf_nextpkt(last_packet))
		/* find the last packet */;
	
	for (entry = proto_hash[hash_slot]; entry; entry = entry->next) {
		if (entry->protocol == protocol)
			break;
	}
	
	if (entry) {
		lck_mtx_lock(proto_input_lock);
		if (entry->first_packet == NULL) {
			entry->first_packet = packet_list;
		}
		else {
			mbuf_setnextpkt(entry->last_packet, packet_list);
		}
		entry->last_packet = last_packet;
		lck_mtx_unlock(proto_input_lock);
	
		OSBitOrAtomic((1L << hash_slot), (UInt32*)&inject_buckets);
		
		wakeup((caddr_t)&dlil_input_thread_wakeup);
	}
	else
	{
		return ENOENT;
	}

	return 0;
}

errno_t
proto_register_plumber(
	protocol_family_t proto_fam,
	ifnet_family_t if_fam,
	proto_plumb_handler plumb,
	proto_unplumb_handler unplumb)
{
	return dlil_reg_proto_module(proto_fam, if_fam, (attach_t)plumb, (detach_t)unplumb);
}

void
proto_unregister_plumber(
	protocol_family_t proto_fam,
	ifnet_family_t if_fam)
{
	(void)dlil_dereg_proto_module(proto_fam, if_fam);
}
