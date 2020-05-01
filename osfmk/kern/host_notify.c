/*
 * Copyright (c) 2003-2019 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/mach_host.h>

#include <kern/kern_types.h>
#include <kern/ipc_kobject.h>
#include <kern/host_notify.h>

#include <kern/queue.h>

#include "mach/host_notify_reply.h"

decl_lck_mtx_data(, host_notify_lock);

lck_mtx_ext_t                   host_notify_lock_ext;
lck_grp_t                               host_notify_lock_grp;
lck_attr_t                              host_notify_lock_attr;
static lck_grp_attr_t   host_notify_lock_grp_attr;
static zone_t                   host_notify_zone;

static queue_head_t             host_notify_queue[HOST_NOTIFY_TYPE_MAX + 1];

static mach_msg_id_t    host_notify_replyid[HOST_NOTIFY_TYPE_MAX + 1] =
{ HOST_CALENDAR_CHANGED_REPLYID,
  HOST_CALENDAR_SET_REPLYID };

struct host_notify_entry {
	queue_chain_t           entries;
	ipc_port_t                      port;
};

typedef struct host_notify_entry        *host_notify_t;

void
host_notify_init(void)
{
	int             i;

	for (i = 0; i <= HOST_NOTIFY_TYPE_MAX; i++) {
		queue_init(&host_notify_queue[i]);
	}

	lck_grp_attr_setdefault(&host_notify_lock_grp_attr);
	lck_grp_init(&host_notify_lock_grp, "host_notify", &host_notify_lock_grp_attr);
	lck_attr_setdefault(&host_notify_lock_attr);

	lck_mtx_init_ext(&host_notify_lock, &host_notify_lock_ext, &host_notify_lock_grp, &host_notify_lock_attr);

	i = sizeof(struct host_notify_entry);
	host_notify_zone =
	    zinit(i, (4096 * i), (16 * i), "host_notify");
}

kern_return_t
host_request_notification(
	host_t                                  host,
	host_flavor_t                   notify_type,
	ipc_port_t                              port)
{
	host_notify_t           entry;

	if (host == HOST_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (!IP_VALID(port)) {
		return KERN_INVALID_CAPABILITY;
	}

	if (notify_type > HOST_NOTIFY_TYPE_MAX || notify_type < 0) {
		return KERN_INVALID_ARGUMENT;
	}

	entry = (host_notify_t)zalloc(host_notify_zone);
	if (entry == NULL) {
		return KERN_RESOURCE_SHORTAGE;
	}

	lck_mtx_lock(&host_notify_lock);

	ip_lock(port);
	if (!ip_active(port) || port->ip_tempowner || ip_kotype(port) != IKOT_NONE) {
		ip_unlock(port);

		lck_mtx_unlock(&host_notify_lock);
		zfree(host_notify_zone, entry);

		return KERN_FAILURE;
	}

	entry->port = port;
	ipc_kobject_set_atomically(port, (ipc_kobject_t)entry, IKOT_HOST_NOTIFY);
	ip_unlock(port);

	enqueue_tail(&host_notify_queue[notify_type], (queue_entry_t)entry);
	lck_mtx_unlock(&host_notify_lock);

	return KERN_SUCCESS;
}

void
host_notify_port_destroy(
	ipc_port_t                      port)
{
	host_notify_t           entry;

	lck_mtx_lock(&host_notify_lock);

	ip_lock(port);
	if (ip_kotype(port) == IKOT_HOST_NOTIFY) {
		entry = (host_notify_t)ip_get_kobject(port);
		assert(entry != NULL);
		ipc_kobject_set_atomically(port, IKO_NULL, IKOT_NONE);
		ip_unlock(port);

		assert(entry->port == port);
		remqueue((queue_entry_t)entry);
		lck_mtx_unlock(&host_notify_lock);
		zfree(host_notify_zone, entry);

		ipc_port_release_sonce(port);
		return;
	}
	ip_unlock(port);

	lck_mtx_unlock(&host_notify_lock);
}

static void
host_notify_all(
	host_flavor_t           notify_type,
	mach_msg_header_t       *msg,
	mach_msg_size_t         msg_size)
{
	queue_t         notify_queue = &host_notify_queue[notify_type];

	lck_mtx_lock(&host_notify_lock);

	if (!queue_empty(notify_queue)) {
		queue_head_t            send_queue;
		host_notify_t           entry;

		send_queue = *notify_queue;
		queue_init(notify_queue);

		send_queue.next->prev = &send_queue;
		send_queue.prev->next = &send_queue;

		msg->msgh_bits =
		    MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0, 0, 0);
		msg->msgh_local_port = MACH_PORT_NULL;
		msg->msgh_voucher_port = MACH_PORT_NULL;
		msg->msgh_id = host_notify_replyid[notify_type];

		while ((entry = (host_notify_t)dequeue(&send_queue)) != NULL) {
			ipc_port_t              port;

			port = entry->port;
			assert(port != IP_NULL);

			ip_lock(port);
			assert(ip_kotype(port) == IKOT_HOST_NOTIFY);
			assert(ip_get_kobject(port) == (ipc_kobject_t)entry);
			ipc_kobject_set_atomically(port, IKO_NULL, IKOT_NONE);
			ip_unlock(port);

			lck_mtx_unlock(&host_notify_lock);
			zfree(host_notify_zone, entry);

			msg->msgh_remote_port = port;

			(void) mach_msg_send_from_kernel_proper(msg, msg_size);

			lck_mtx_lock(&host_notify_lock);
		}
	}

	lck_mtx_unlock(&host_notify_lock);
}

void
host_notify_calendar_change(void)
{
	__Request__host_calendar_changed_t      msg;

	host_notify_all(HOST_NOTIFY_CALENDAR_CHANGE, &msg.Head, sizeof(msg));
}

void
host_notify_calendar_set(void)
{
	__Request__host_calendar_set_t  msg;

	host_notify_all(HOST_NOTIFY_CALENDAR_SET, &msg.Head, sizeof(msg));
}
