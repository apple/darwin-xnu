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

#include <kern/hv_support.h>
#include <kern/ipc_mig.h>
#include <kern/kalloc.h>
#include <kern/locks.h>
#include <mach/port.h>
#include <sys/queue.h>
#include <ipc/ipc_port.h>

#include <stdbool.h>

#include "hv_io_notifier.h"

static LCK_GRP_DECLARE(ion_lock_grp, "io notifier");

typedef struct hv_ion_entry {
	LIST_ENTRY(hv_ion_entry) list;

	uint64_t           addr;
	size_t             size;
	uint64_t           value;
	uint32_t           flags;

	mach_port_t        port;
	mach_port_name_t   port_name;
} hv_ion_entry_t;

LIST_HEAD(io_notifier_list, hv_ion_entry);

struct hv_ion_grp {
	struct io_notifier_list list;
	lck_rw_t lock;
};

/*
 * Lookup a matching notifier and return it.
 */
static hv_ion_entry_t *
hv_io_notifier_grp_lookup(const hv_ion_grp_t *grp, const hv_ion_entry_t *key)
{
	hv_ion_entry_t *ion = NULL;

	LIST_FOREACH(ion, &grp->list, list) {
		if (ion->addr != key->addr) {
			continue;
		}

		if (!(ion->flags & kHV_ION_ANY_SIZE) && ion->size != key->size) {
			continue;
		}

		if (!(ion->flags & kHV_ION_ANY_VALUE) && ion->value != key->value) {
			continue;
		}

		if (ion->port_name != key->port_name) {
			continue;
		}

		if (ion->flags != key->flags) {
			continue;
		}

		return ion;
	}

	return NULL;
}

/*
 * Add a new notifier.
 * Return KERN_SUCCESS if the notifier was added, an error otherwise.
 */
kern_return_t
hv_io_notifier_grp_add(hv_ion_grp_t *grp, const hv_ion_t *notifier)
{
	hv_ion_entry_t *ion = NULL;

	ion = kalloc(sizeof(*ion));
	if (ion == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	ion->addr = notifier->addr;
	ion->size = notifier->size;
	ion->value = notifier->value;
	ion->flags = notifier->flags;
	ion->port_name = notifier->port_name;

	kern_return_t ret = ipc_object_copyin(current_task()->itk_space,
	    ion->port_name, MACH_MSG_TYPE_COPY_SEND, (ipc_object_t *)&ion->port, 0,
	    NULL, IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND);
	if (ret != KERN_SUCCESS) {
		kfree(ion, sizeof(*ion));
		return ret;
	}

	lck_rw_lock_exclusive(&grp->lock);

	if (hv_io_notifier_grp_lookup(grp, ion) != NULL) {
		lck_rw_done(&grp->lock);
		ipc_port_release_send(ion->port);
		kfree(ion, sizeof(*ion));
		return KERN_FAILURE;
	}

	LIST_INSERT_HEAD(&grp->list, ion, list);

	lck_rw_done(&grp->lock);

	return KERN_SUCCESS;
}

/*
 * Remove and free a notifier.
 * Return KERN_SUCCESS if the notifier was removed, an error otherwise.
 */
kern_return_t
hv_io_notifier_grp_remove(hv_ion_grp_t *grp, const hv_ion_t *notifier)
{
	hv_ion_entry_t ion = {};
	hv_ion_entry_t *entry = NULL;

	ion.addr = notifier->addr;
	ion.size = notifier->size;
	ion.value = notifier->value;
	ion.flags = notifier->flags;
	ion.port_name = notifier->port_name;

	lck_rw_lock_exclusive(&grp->lock);

	entry = hv_io_notifier_grp_lookup(grp, &ion);
	if (entry == NULL) {
		lck_rw_done(&grp->lock);
		return KERN_FAILURE;
	}

	LIST_REMOVE(entry, list);

	lck_rw_done(&grp->lock);

	ipc_port_release_send(entry->port);
	kfree(entry, sizeof(*entry));

	return KERN_SUCCESS;
}

/*
 * Find matching notifiers and notify the port.
 * Returns KERN_SUCCESS if no errors occurred when sending notifications and at
 * least one notification was sent.
 */
kern_return_t
hv_io_notifier_grp_fire(hv_ion_grp_t *grp, uint64_t addr, size_t size,
    uint64_t value)
{
	kern_return_t kr = KERN_FAILURE;
	hv_ion_entry_t *ion = NULL;
	bool fired = false;

	lck_rw_lock_shared(&grp->lock);

	LIST_FOREACH(ion, &grp->list, list) {
		if (ion->addr != addr) {
			continue;
		}

		if (!(ion->flags & kHV_ION_ANY_SIZE) && ion->size != size) {
			continue;
		}

		if (!(ion->flags & kHV_ION_ANY_VALUE) && ion->value != value) {
			continue;
		}

		hv_ion_message_t msg = {
			.header.msgh_bits         = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0),
			.header.msgh_size         = sizeof(msg),
			.header.msgh_remote_port  = ion->port,
			.header.msgh_local_port   = MACH_PORT_NULL,
			.header.msgh_voucher_port = MACH_PORT_NULL,
			.header.msgh_id           = 0,

			.addr = addr,
			.size = size,
			.value = value,
		};

		kr = mach_msg_send_from_kernel_with_options(&msg.header, sizeof(msg),
		    MACH_SEND_TIMEOUT, MACH_MSG_TIMEOUT_NONE);

		/*
		 * A timeout will occur when the queue is full. Ignore it if so
		 * configured.
		 */
		if (kr == MACH_SEND_TIMED_OUT && !(ion->flags & kHV_ION_EXIT_FULL)) {
			kr = MACH_MSG_SUCCESS;
		}

		if (kr != MACH_MSG_SUCCESS) {
			fired = false;
			break;
		}

		fired = true;
	}

	lck_rw_done(&grp->lock);
	return fired ? KERN_SUCCESS : KERN_FAILURE;
}

kern_return_t
hv_io_notifier_grp_alloc(hv_ion_grp_t **grp_p )
{
	hv_ion_grp_t *grp = kalloc(sizeof(*grp));

	if (grp == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}
	bzero(grp, sizeof(*grp));

	lck_rw_init(&grp->lock, &ion_lock_grp, LCK_ATTR_NULL);

	*grp_p = grp;
	return KERN_SUCCESS;
}

void
hv_io_notifier_grp_free(hv_ion_grp_t **grp_p)
{
	hv_ion_grp_t *grp = *grp_p;

	while (!LIST_EMPTY(&grp->list)) {
		hv_ion_entry_t *ion = LIST_FIRST(&grp->list);

		LIST_REMOVE(ion, list);

		ipc_port_release_send(ion->port);
		kfree(ion, sizeof(*ion));
	}

	lck_rw_destroy(&grp->lock, &ion_lock_grp);

	kfree(grp, sizeof(*grp));

	*grp_p = NULL;
}
