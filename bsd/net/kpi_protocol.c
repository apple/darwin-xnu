/*
 * Copyright (c) 2004-2010 Apple Inc. All rights reserved.
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

void proto_input_run(void);

typedef int (*attach_t)(struct ifnet *ifp, uint32_t protocol_family);
typedef int (*detach_t)(struct ifnet *ifp, uint32_t protocol_family);

struct proto_input_entry {
	struct proto_input_entry		*next;
	int								detach;
	struct domain					*domain;
	int								hash;
	int								chain;
	
	protocol_family_t				protocol;
	proto_input_handler				input;
	proto_input_detached_handler	detached;
	
	mbuf_t							inject_first;
	mbuf_t							inject_last;
	
	struct proto_input_entry		*input_next;
	mbuf_t							input_first;
	mbuf_t							input_last;
};


struct proto_family_str {
	TAILQ_ENTRY(proto_family_str)	proto_fam_next;
	protocol_family_t				proto_family;
	ifnet_family_t					if_family;
	proto_plumb_handler				attach_proto;
	proto_unplumb_handler			detach_proto;
};

#define PROTO_HASH_SLOTS	5

static struct proto_input_entry			*proto_hash[PROTO_HASH_SLOTS];
static int								proto_total_waiting = 0;
static struct proto_input_entry 		*proto_input_add_list = NULL;
static lck_mtx_t						*proto_family_mutex = 0;
static TAILQ_HEAD(, proto_family_str)	proto_family_head =
			TAILQ_HEAD_INITIALIZER(proto_family_head);

extern lck_mtx_t	*domain_proto_mtx;
extern struct dlil_threading_info *dlil_lo_thread_ptr;

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
	proto_family_mutex = lck_mtx_alloc_init(lck_group, lck_attrib);
	lck_grp_free(lck_group);
	lck_attr_free(lck_attrib);
	
	bzero(proto_hash, sizeof(proto_hash));
}

__private_extern__ errno_t
proto_register_input(
	protocol_family_t protocol,
	proto_input_handler input,
	proto_input_detached_handler detached,
	int	chains)
{
	
	struct proto_input_entry *entry;
	struct dlil_threading_info *thread = dlil_lo_thread_ptr;
	
	entry = _MALLOC(sizeof(*entry), M_IFADDR, M_WAITOK);
	
	if (entry == NULL)
		return ENOMEM;
	
	bzero(entry, sizeof(*entry));
	entry->protocol = protocol;
	entry->input = input;
	entry->detached = detached;
	entry->hash = proto_hash_value(protocol);
	entry->chain = chains;
	
	{
		struct domain *dp = domains;

		lck_mtx_assert(domain_proto_mtx, LCK_MTX_ASSERT_NOTOWNED);
         	lck_mtx_lock(domain_proto_mtx);
		while (dp && (protocol_family_t)dp->dom_family != protocol)
			dp = dp->dom_next;
		entry->domain = dp;
         	lck_mtx_unlock(domain_proto_mtx);	
	}

	
	lck_mtx_lock(&thread->input_lck);
	entry->next = proto_input_add_list;
	proto_input_add_list = entry;
	
	thread->input_waiting |= DLIL_PROTO_REGISTER;
	if ((thread->input_waiting & DLIL_INPUT_RUNNING) == 0)
		wakeup((caddr_t)&thread->input_waiting);
	lck_mtx_unlock(&thread->input_lck);
	
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

__private_extern__ void
proto_input_run(void)
{
	struct proto_input_entry	*entry;
	struct dlil_threading_info *thread = dlil_lo_thread_ptr;
	mbuf_t packet_list;
	int i, locked = 0;

	lck_mtx_assert(&thread->input_lck,  LCK_MTX_ASSERT_NOTOWNED);

	if ((thread->input_waiting & DLIL_PROTO_REGISTER) != 0) {
		lck_mtx_lock_spin(&thread->input_lck);
		entry = proto_input_add_list;
		proto_input_add_list = NULL;
		thread->input_waiting &= ~DLIL_PROTO_REGISTER;
		lck_mtx_unlock(&thread->input_lck);
		proto_delayed_attach(entry);
	}
	/*
	  Move everything from the lock protected list to the thread
	  specific list.
	 */
	for (i = 0; proto_total_waiting != 0 && i < PROTO_HASH_SLOTS; i++) {
		for (entry = proto_hash[i]; entry && proto_total_waiting;
			 entry = entry->next) {
			if (entry->inject_first) {
				lck_mtx_lock_spin(&thread->input_lck);
				thread->input_waiting &= ~DLIL_PROTO_WAITING;

				packet_list = entry->inject_first;

				entry->inject_first = NULL;
				entry->inject_last = NULL;
				proto_total_waiting--;

				lck_mtx_unlock(&thread->input_lck);

				if (entry->domain && (entry->domain->dom_flags & DOM_REENTRANT) == 0) {
					lck_mtx_lock(entry->domain->dom_mtx);
					locked = 1;
				}
		
				if (entry->chain) {
					entry->input(entry->protocol, packet_list);
				}
				else {
					mbuf_t	packet;
				
					for (packet = packet_list; packet; packet = packet_list) {
						packet_list = mbuf_nextpkt(packet);
						mbuf_setnextpkt(packet, NULL);
						entry->input(entry->protocol, packet);
					}
				}
				if (locked) {
					locked = 0;
					lck_mtx_unlock(entry->domain->dom_mtx);
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
	struct proto_input_entry	*entry;
	errno_t				locked =0, result = 0;

	for (entry = proto_hash[proto_hash_value(protocol)]; entry;
		 entry = entry->next) {
		if (entry->protocol == protocol)
			break;
	}

	if (entry->domain && (entry->domain->dom_flags & DOM_REENTRANT) == 0) {
		lck_mtx_lock(entry->domain->dom_mtx);
		locked = 1;
	}
	
	if (entry->chain) {
		entry->input(entry->protocol, packet_list);
	}
	else {
		mbuf_t	packet;
		
		for (packet = packet_list; packet; packet = packet_list) {
			packet_list = mbuf_nextpkt(packet);
			mbuf_setnextpkt(packet, NULL);
			entry->input(entry->protocol, packet);
		}
	}
	
	if (locked) {
		lck_mtx_unlock(entry->domain->dom_mtx);
	}	
	return result;
}

errno_t
proto_inject(
	protocol_family_t	protocol,
	mbuf_t				packet_list)
{
	struct proto_input_entry	*entry;
	mbuf_t				last_packet;
	int				hash_slot = proto_hash_value(protocol);
	struct dlil_threading_info 	*thread = dlil_lo_thread_ptr;
	
	for (last_packet = packet_list; mbuf_nextpkt(last_packet);
		 last_packet = mbuf_nextpkt(last_packet))
		/* find the last packet */;
	
	for (entry = proto_hash[hash_slot]; entry; entry = entry->next) {
		if (entry->protocol == protocol)
			break;
	}
	
	if (entry) {
		lck_mtx_lock(&thread->input_lck);
		if (entry->inject_first == NULL) {
			proto_total_waiting++;
			thread->input_waiting |= DLIL_PROTO_WAITING;
			entry->inject_first = packet_list;
		}
		else {
			mbuf_setnextpkt(entry->inject_last, packet_list);
		}
		entry->inject_last = last_packet;
		if ((thread->input_waiting & DLIL_INPUT_RUNNING) == 0) {
			wakeup((caddr_t)&thread->input_waiting);
		}
		lck_mtx_unlock(&thread->input_lck);
	}
	else
	{
		return ENOENT;
	}

	return 0;
}

static struct proto_family_str*
proto_plumber_find(
	protocol_family_t	proto_family,
	ifnet_family_t		if_family)
{
	struct proto_family_str  *mod = NULL;

	TAILQ_FOREACH(mod, &proto_family_head, proto_fam_next) {
		if ((mod->proto_family == (proto_family & 0xffff)) 
			&& (mod->if_family == (if_family & 0xffff))) 
			break;
		}

	return mod;
}

errno_t
proto_register_plumber(
	protocol_family_t		protocol_family,
	ifnet_family_t 			interface_family, 
	proto_plumb_handler		attach,
	proto_unplumb_handler	detach)
{
	struct proto_family_str *proto_family;

	if (attach == NULL) return EINVAL;

	lck_mtx_lock(proto_family_mutex);
	
	TAILQ_FOREACH(proto_family, &proto_family_head, proto_fam_next) {
		if (proto_family->proto_family == protocol_family &&
			proto_family->if_family == interface_family) {
			lck_mtx_unlock(proto_family_mutex);
			return EEXIST;
		}
	}

	proto_family = (struct proto_family_str *) _MALLOC(sizeof(struct proto_family_str), M_IFADDR, M_WAITOK);
	if (!proto_family) {
		lck_mtx_unlock(proto_family_mutex);
		return ENOMEM;
	}

	bzero(proto_family, sizeof(struct proto_family_str));
	proto_family->proto_family	= protocol_family;
	proto_family->if_family		= interface_family & 0xffff;
	proto_family->attach_proto	= attach;
	proto_family->detach_proto	= detach;

	TAILQ_INSERT_TAIL(&proto_family_head, proto_family, proto_fam_next);
	lck_mtx_unlock(proto_family_mutex);
	return 0;
}

void
proto_unregister_plumber(
	protocol_family_t	protocol_family,
	ifnet_family_t		interface_family)
{
	struct proto_family_str  *proto_family;

	lck_mtx_lock(proto_family_mutex);

	proto_family = proto_plumber_find(protocol_family, interface_family);
	if (proto_family == 0) {
		lck_mtx_unlock(proto_family_mutex);
		return;
	}

	TAILQ_REMOVE(&proto_family_head, proto_family, proto_fam_next);
	FREE(proto_family, M_IFADDR);
	
	lck_mtx_unlock(proto_family_mutex);
	return;
}

__private_extern__ errno_t
proto_plumb(
	protocol_family_t	protocol_family,
	ifnet_t				ifp)
{
	struct proto_family_str  *proto_family;
	int ret = 0;

	lck_mtx_lock(proto_family_mutex);
	proto_family = proto_plumber_find(protocol_family, ifp->if_family);
	if (proto_family == 0) {
		lck_mtx_unlock(proto_family_mutex);
		return ENXIO;
	}

	ret = proto_family->attach_proto(ifp, protocol_family);

	lck_mtx_unlock(proto_family_mutex);
   	return ret;
}


__private_extern__ errno_t
proto_unplumb(
	protocol_family_t	protocol_family,
	ifnet_t				ifp)
{
	struct proto_family_str  *proto_family;
	int ret = 0;

	lck_mtx_lock(proto_family_mutex);

	proto_family = proto_plumber_find(protocol_family, ifp->if_family);
	if (proto_family && proto_family->detach_proto)
		proto_family->detach_proto(ifp, protocol_family);
	else
		ret = ifnet_detach_protocol(ifp, protocol_family);
    
	lck_mtx_unlock(proto_family_mutex);
	return ret;
}
