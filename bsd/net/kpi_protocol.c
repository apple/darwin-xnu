/*
 * Copyright (c) 2004-2013 Apple Inc. All rights reserved.
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
	struct proto_input_entry	*next;
	int				detach;
	struct domain			*domain;
	int				hash;
	int				chain;

	protocol_family_t		protocol;
	proto_input_handler		input;
	proto_input_detached_handler	detached;

	mbuf_t				inject_first;
	mbuf_t				inject_last;

	struct proto_input_entry	*input_next;
	mbuf_t				input_first;
	mbuf_t				input_last;
};


struct proto_family_str {
	TAILQ_ENTRY(proto_family_str)	proto_fam_next;
	protocol_family_t		proto_family;
	ifnet_family_t			if_family;
	proto_plumb_handler		attach_proto;
	proto_unplumb_handler		detach_proto;
};

static struct proto_input_entry *proto_hash[PROTO_HASH_SLOTS];
static int proto_total_waiting = 0;
static struct proto_input_entry	*proto_input_add_list = NULL;
decl_lck_mtx_data(static, proto_family_mutex_data);
static lck_mtx_t *proto_family_mutex = &proto_family_mutex_data;
static TAILQ_HEAD(, proto_family_str) proto_family_head =
    TAILQ_HEAD_INITIALIZER(proto_family_head);

__private_extern__ void
proto_kpi_init(void)
{
	lck_grp_attr_t	*grp_attrib = NULL;
	lck_attr_t	*lck_attrib = NULL;
	lck_grp_t	*lck_group = NULL;

	/* Allocate a mtx lock */
	grp_attrib = lck_grp_attr_alloc_init();
	lck_group = lck_grp_alloc_init("protocol kpi", grp_attrib);
	lck_grp_attr_free(grp_attrib);
	lck_attrib = lck_attr_alloc_init();
	lck_mtx_init(proto_family_mutex, lck_group, lck_attrib);
	lck_grp_free(lck_group);
	lck_attr_free(lck_attrib);

	bzero(proto_hash, sizeof (proto_hash));
}

__private_extern__ errno_t
proto_register_input(protocol_family_t protocol, proto_input_handler input,
    proto_input_detached_handler detached, int	chains)
{
	struct proto_input_entry *entry;
	struct dlil_threading_info *inp = dlil_main_input_thread;
	struct domain *dp;
	domain_guard_t guard;

	entry = _MALLOC(sizeof (*entry), M_IFADDR, M_WAITOK | M_ZERO);
	if (entry == NULL)
		return (ENOMEM);

	entry->protocol = protocol;
	entry->input = input;
	entry->detached = detached;
	entry->hash = proto_hash_value(protocol);
	entry->chain = chains;

	guard = domain_guard_deploy();
	TAILQ_FOREACH(dp, &domains, dom_entry) {
		if (dp->dom_family == (int)protocol)
			break;
	}
	domain_guard_release(guard);
	if (dp == NULL)
		return (EINVAL);

	entry->domain = dp;

	lck_mtx_lock(&inp->input_lck);
	entry->next = proto_input_add_list;
	proto_input_add_list = entry;

	inp->input_waiting |= DLIL_PROTO_REGISTER;
	if ((inp->input_waiting & DLIL_INPUT_RUNNING) == 0)
		wakeup((caddr_t)&inp->input_waiting);
	lck_mtx_unlock(&inp->input_lck);

	return (0);
}

__private_extern__ void
proto_unregister_input(protocol_family_t protocol)
{
	struct proto_input_entry *entry = NULL;

	for (entry = proto_hash[proto_hash_value(protocol)]; entry != NULL;
	    entry = entry->next) {
		if (entry->protocol == protocol)
			break;
	}

	if (entry != NULL)
		entry->detach = 1;
}

static void
proto_delayed_attach(struct proto_input_entry *entry)
{
	struct proto_input_entry *next_entry;

	for (next_entry = entry->next; entry != NULL; entry = next_entry) {
		struct proto_input_entry *exist;
		int hash_slot;

		hash_slot = proto_hash_value(entry->protocol);
		next_entry = entry->next;

		for (exist = proto_hash[hash_slot]; exist != NULL;
		    exist = exist->next) {
			if (exist->protocol == entry->protocol)
				break;
		}

		/* If the entry already exists, call detached and dispose */
		if (exist != NULL) {
			if (entry->detached)
				entry->detached(entry->protocol);
			FREE(entry, M_IFADDR);
		} else {
			entry->next = proto_hash[hash_slot];
			proto_hash[hash_slot] = entry;
		}
	}
}

__private_extern__ void
proto_input_run(void)
{
	struct proto_input_entry *entry;
	struct dlil_threading_info *inp = dlil_main_input_thread;
	mbuf_t packet_list;
	int i, locked = 0;

	LCK_MTX_ASSERT(&inp->input_lck, LCK_MTX_ASSERT_NOTOWNED);

	if (inp->input_waiting & DLIL_PROTO_REGISTER) {
		lck_mtx_lock_spin(&inp->input_lck);
		entry = proto_input_add_list;
		proto_input_add_list = NULL;
		inp->input_waiting &= ~DLIL_PROTO_REGISTER;
		lck_mtx_unlock(&inp->input_lck);
		proto_delayed_attach(entry);
	}

	/*
	 * Move everything from the lock protected list to the thread
	 * specific list.
	 */
	for (i = 0; proto_total_waiting != 0 && i < PROTO_HASH_SLOTS; i++) {
		for (entry = proto_hash[i];
		    entry != NULL && proto_total_waiting; entry = entry->next) {
			if (entry->inject_first != NULL) {
				lck_mtx_lock_spin(&inp->input_lck);
				inp->input_waiting &= ~DLIL_PROTO_WAITING;

				packet_list = entry->inject_first;

				entry->inject_first = NULL;
				entry->inject_last = NULL;
				proto_total_waiting--;

				lck_mtx_unlock(&inp->input_lck);

				if (entry->domain != NULL && !(entry->domain->
				    dom_flags & DOM_REENTRANT)) {
					lck_mtx_lock(entry->domain->dom_mtx);
					locked = 1;
				}

				if (entry->chain) {
					entry->input(entry->protocol,
					    packet_list);
				} else {
					mbuf_t	packet;

					for (packet = packet_list;
					    packet != NULL;
					    packet = packet_list) {
						packet_list =
						    mbuf_nextpkt(packet);
						mbuf_setnextpkt(packet, NULL);
						entry->input(entry->protocol,
						    packet);
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
proto_input(protocol_family_t protocol, mbuf_t packet_list)
{
	struct proto_input_entry *entry;
	errno_t locked = 0, result = 0;

	for (entry = proto_hash[proto_hash_value(protocol)]; entry != NULL;
	    entry = entry->next) {
		if (entry->protocol == protocol)
			break;
	}

	if (entry == NULL)
		return (-1);

	if (entry->domain && !(entry->domain->dom_flags & DOM_REENTRANT)) {
		lck_mtx_lock(entry->domain->dom_mtx);
		locked = 1;
	}

	if (entry->chain) {
		entry->input(entry->protocol, packet_list);
	} else {
		mbuf_t	packet;

		for (packet = packet_list; packet != NULL;
		    packet = packet_list) {
			packet_list = mbuf_nextpkt(packet);
			mbuf_setnextpkt(packet, NULL);
			entry->input(entry->protocol, packet);
		}
	}

	if (locked) {
		lck_mtx_unlock(entry->domain->dom_mtx);
	}
	return (result);
}

errno_t
proto_inject(protocol_family_t protocol, mbuf_t packet_list)
{
	struct proto_input_entry *entry;
	mbuf_t last_packet;
	int hash_slot = proto_hash_value(protocol);
	struct dlil_threading_info *inp = dlil_main_input_thread;

	for (last_packet = packet_list; mbuf_nextpkt(last_packet) != NULL;
	    last_packet = mbuf_nextpkt(last_packet))
		/* find the last packet */;

	for (entry = proto_hash[hash_slot]; entry != NULL;
	    entry = entry->next) {
		if (entry->protocol == protocol)
			break;
	}

	if (entry != NULL) {
		lck_mtx_lock(&inp->input_lck);
		if (entry->inject_first == NULL) {
			proto_total_waiting++;
			inp->input_waiting |= DLIL_PROTO_WAITING;
			entry->inject_first = packet_list;
		} else {
			mbuf_setnextpkt(entry->inject_last, packet_list);
		}
		entry->inject_last = last_packet;
		if ((inp->input_waiting & DLIL_INPUT_RUNNING) == 0) {
			wakeup((caddr_t)&inp->input_waiting);
		}
		lck_mtx_unlock(&inp->input_lck);
	} else {
		return (ENOENT);
	}

	return (0);
}

static struct proto_family_str *
proto_plumber_find(protocol_family_t proto_family, ifnet_family_t if_family)
{
	struct proto_family_str  *mod = NULL;

	TAILQ_FOREACH(mod, &proto_family_head, proto_fam_next) {
		if ((mod->proto_family == (proto_family & 0xffff)) &&
		    (mod->if_family == (if_family & 0xffff)))
			break;
	}

	return (mod);
}

errno_t
proto_register_plumber(protocol_family_t protocol_family,
    ifnet_family_t interface_family, proto_plumb_handler attach,
    proto_unplumb_handler detach)
{
	struct proto_family_str *proto_family;

	if (attach == NULL)
		return (EINVAL);

	lck_mtx_lock(proto_family_mutex);

	TAILQ_FOREACH(proto_family, &proto_family_head, proto_fam_next) {
		if (proto_family->proto_family == protocol_family &&
		    proto_family->if_family == interface_family) {
			lck_mtx_unlock(proto_family_mutex);
			return (EEXIST);
		}
	}

	proto_family = (struct proto_family_str *)
	    _MALLOC(sizeof (struct proto_family_str), M_IFADDR,
	    M_WAITOK | M_ZERO);
	if (!proto_family) {
		lck_mtx_unlock(proto_family_mutex);
		return (ENOMEM);
	}

	proto_family->proto_family	= protocol_family;
	proto_family->if_family		= interface_family & 0xffff;
	proto_family->attach_proto	= attach;
	proto_family->detach_proto	= detach;

	TAILQ_INSERT_TAIL(&proto_family_head, proto_family, proto_fam_next);
	lck_mtx_unlock(proto_family_mutex);
	return (0);
}

void
proto_unregister_plumber(protocol_family_t protocol_family,
    ifnet_family_t interface_family)
{
	struct proto_family_str  *proto_family;

	lck_mtx_lock(proto_family_mutex);

	proto_family = proto_plumber_find(protocol_family, interface_family);
	if (proto_family == NULL) {
		lck_mtx_unlock(proto_family_mutex);
		return;
	}

	TAILQ_REMOVE(&proto_family_head, proto_family, proto_fam_next);
	FREE(proto_family, M_IFADDR);

	lck_mtx_unlock(proto_family_mutex);
}

__private_extern__ errno_t
proto_plumb(protocol_family_t protocol_family, ifnet_t ifp)
{
	struct proto_family_str  *proto_family;
	int ret = 0;

	lck_mtx_lock(proto_family_mutex);
	proto_family = proto_plumber_find(protocol_family, ifp->if_family);
	if (proto_family == NULL) {
		lck_mtx_unlock(proto_family_mutex);
		return (ENXIO);
	}

	ret = proto_family->attach_proto(ifp, protocol_family);

	lck_mtx_unlock(proto_family_mutex);
	return (ret);
}


__private_extern__ errno_t
proto_unplumb(protocol_family_t protocol_family, ifnet_t ifp)
{
	struct proto_family_str  *proto_family;
	int ret = 0;

	lck_mtx_lock(proto_family_mutex);

	proto_family = proto_plumber_find(protocol_family, ifp->if_family);
	if (proto_family != NULL && proto_family->detach_proto)
		proto_family->detach_proto(ifp, protocol_family);
	else
		ret = ifnet_detach_protocol(ifp, protocol_family);

	lck_mtx_unlock(proto_family_mutex);
	return (ret);
}
