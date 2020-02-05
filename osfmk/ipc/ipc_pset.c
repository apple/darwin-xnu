/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	ipc/ipc_pset.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to manipulate IPC port sets.
 */

#include <mach/port.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <ipc/ipc_mqueue.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>

#include <kern/kern_types.h>

#include <vm/vm_map.h>
#include <libkern/section_keywords.h>

/*
 *	Routine:	ipc_pset_alloc
 *	Purpose:
 *		Allocate a port set.
 *	Conditions:
 *		Nothing locked.  If successful, the port set is returned
 *		locked.  (The caller doesn't have a reference.)
 *	Returns:
 *		KERN_SUCCESS		The port set is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NO_SPACE		No room for an entry in the space.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_pset_alloc(
	ipc_space_t             space,
	mach_port_name_t        *namep,
	ipc_pset_t              *psetp)
{
	ipc_pset_t pset;
	mach_port_name_t name;
	kern_return_t kr;

	kr = ipc_object_alloc(space, IOT_PORT_SET,
	    MACH_PORT_TYPE_PORT_SET, 0,
	    &name, (ipc_object_t *) &pset);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* pset and space are locked */

	ipc_mqueue_init(&pset->ips_messages, TRUE /* set */);
	is_write_unlock(space);

	*namep = name;
	*psetp = pset;
	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_pset_alloc_name
 *	Purpose:
 *		Allocate a port set, with a specific name.
 *	Conditions:
 *		Nothing locked.  If successful, the port set is returned
 *		locked.  (The caller doesn't have a reference.)
 *	Returns:
 *		KERN_SUCCESS		The port set is allocated.
 *		KERN_INVALID_TASK	The space is dead.
 *		KERN_NAME_EXISTS	The name already denotes a right.
 *		KERN_RESOURCE_SHORTAGE	Couldn't allocate memory.
 */

kern_return_t
ipc_pset_alloc_name(
	ipc_space_t             space,
	mach_port_name_t        name,
	ipc_pset_t              *psetp)
{
	ipc_pset_t pset;
	kern_return_t kr;

	kr = ipc_object_alloc_name(space, IOT_PORT_SET,
	    MACH_PORT_TYPE_PORT_SET, 0,
	    name, (ipc_object_t *) &pset);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* pset is locked */

	ipc_mqueue_init(&pset->ips_messages, TRUE /* set */);

	*psetp = pset;
	return KERN_SUCCESS;
}


/*
 *	Routine:	ipc_pset_alloc_special
 *	Purpose:
 *		Allocate a port set in a special space.
 *		The new port set is returned with one ref.
 *		If unsuccessful, IPS_NULL is returned.
 *	Conditions:
 *		Nothing locked.
 */
ipc_pset_t
ipc_pset_alloc_special(
	__assert_only ipc_space_t space)
{
	ipc_pset_t pset;

	assert(space != IS_NULL);
	assert(space->is_table == IE_NULL);
	assert(!is_active(space));

	pset = ips_object_to_pset(io_alloc(IOT_PORT_SET));
	if (pset == IPS_NULL) {
		return IPS_NULL;
	}

	bzero((char *)pset, sizeof(*pset));

	io_lock_init(ips_to_object(pset));
	pset->ips_references = 1;
	pset->ips_object.io_bits = io_makebits(TRUE, IOT_PORT_SET, 0);

	ipc_mqueue_init(&pset->ips_messages, TRUE /* set */);

	return pset;
}


/*
 *	Routine:	ipc_pset_member
 *	Purpose:
 *		Checks to see if a port is a member of a pset
 *	Conditions:
 *		Both port and port set are locked.
 *		The port must be active.
 */
boolean_t
ipc_pset_member(
	ipc_pset_t      pset,
	ipc_port_t      port)
{
	require_ip_active(port);

	return ipc_mqueue_member(&port->ip_messages, &pset->ips_messages);
}


/*
 *	Routine:	ipc_pset_add
 *	Purpose:
 *		Puts a port into a port set.
 *	Conditions:
 *		Both port and port set are locked and active.
 *		The owner of the port set is also receiver for the port.
 */

kern_return_t
ipc_pset_add(
	ipc_pset_t        pset,
	ipc_port_t        port,
	uint64_t         *reserved_link,
	uint64_t         *reserved_prepost)
{
	kern_return_t kr;

	assert(ips_active(pset));
	require_ip_active(port);

	kr = ipc_mqueue_add(&port->ip_messages, &pset->ips_messages,
	    reserved_link, reserved_prepost);

	return kr;
}



/*
 *	Routine:	ipc_pset_remove
 *	Purpose:
 *		Removes a port from a port set.
 *		The port set loses a reference.
 *	Conditions:
 *		Both port and port set are locked.
 *		The port must be active.
 */

kern_return_t
ipc_pset_remove(
	ipc_pset_t        pset,
	ipc_port_t        port)
{
	kern_return_t kr;
	require_ip_active(port);

	if (port->ip_in_pset == 0) {
		return KERN_NOT_IN_SET;
	}

	kr = ipc_mqueue_remove(&port->ip_messages, &pset->ips_messages);

	return kr;
}

/*
 *	Routine:	ipc_pset_lazy_allocate
 *	Purpose:
 *		lazily initialize the wqset of a port set.
 *	Conditions:
 *		Nothing locked.
 */

kern_return_t
ipc_pset_lazy_allocate(
	ipc_space_t space,
	mach_port_name_t psname)
{
	kern_return_t kr;
	ipc_entry_t entry;
	ipc_object_t psobj;
	ipc_pset_t pset;

	kr = ipc_right_lookup_read(space, psname, &entry);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/* space is read-locked and active */
	if ((entry->ie_bits & MACH_PORT_TYPE_PORT_SET) == 0) {
		is_read_unlock(space);
		kr = KERN_INVALID_RIGHT;
		return kr;
	}

	psobj = entry->ie_object;
	pset = ips_object_to_pset(psobj);
	assert(pset != NULL);
	ipc_mqueue_t set_mqueue = &pset->ips_messages;
	struct waitq_set *wqset =  &set_mqueue->imq_set_queue;

	io_reference(psobj);
	is_read_unlock(space);

	/*
	 * lazily initialize the wqset to avoid
	 * possible allocation while linking
	 * under spinlocks.
	 */
	waitq_set_lazy_init_link(wqset);
	io_release(psobj);

	return KERN_SUCCESS;
}

/*
 *	Routine:	ipc_pset_remove_from_all
 *	Purpose:
 *		Removes a port from all it's port sets.
 *	Conditions:
 *		port is locked and active.
 */

kern_return_t
ipc_pset_remove_from_all(
	ipc_port_t      port)
{
	if (port->ip_in_pset == 0) {
		return KERN_NOT_IN_SET;
	}

	/*
	 * Remove the port's mqueue from all sets
	 */
	ipc_mqueue_remove_from_all(&port->ip_messages);
	return KERN_SUCCESS;
}


/*
 *	Routine:	ipc_pset_destroy
 *	Purpose:
 *		Destroys a port_set.
 *	Conditions:
 *		The port_set is locked and alive.
 *		The caller has a reference, which is consumed.
 *		Afterwards, the port_set is unlocked and dead.
 */

void
ipc_pset_destroy(
	ipc_space_t     space,
	ipc_pset_t      pset)
{
	assert(ips_active(pset));

	pset->ips_object.io_bits &= ~IO_BITS_ACTIVE;

	/*
	 * remove all the member message queues
	 * AND remove this message queue from any containing sets
	 */
	ipc_mqueue_remove_all(&pset->ips_messages);

	/*
	 * Set all waiters on the portset running to
	 * discover the change.
	 */
	imq_lock(&pset->ips_messages);
	ipc_mqueue_changed(space, &pset->ips_messages);
	imq_unlock(&pset->ips_messages);

	ipc_mqueue_deinit(&pset->ips_messages);

	ips_unlock(pset);
	ips_release(pset);       /* consume the ref our caller gave us */
}

/*
 * Kqueue EVFILT_MACHPORT support
 *
 * - kn_mqueue points to the monitored mqueue
 *
 * - (in/out) ext[0] holds a mach_vm_address_t to a userspace buffer
 *   that can be used to direct-deliver messages when
 *   MACH_RCV_MSG is set in kn_sfflags
 *
 * - (in/out) ext[1] holds a mach_msg_size_t representing the size
 *   of the userspace buffer held in ext[0].
 *
 * - (out)    ext[2] is used to deliver qos information
 *   about the send queue to userspace.
 *
 * - (abused) ext[3] is used in kernel to hold a reference to the first port
 *   with a turnstile that participate to sync IPC override.
 *
 * - kn_hook is optionally a "knote" turnstile. It is used as the inheritor
 *   of turnstiles for rights copied out as part of direct message delivery
 *   when they can participate to sync IPC override.
 *
 *   It is used to atomically neuter the sync IPC override when the knote is
 *   re-enabled.
 *
 */

#include <sys/event.h>
#include <sys/errno.h>

static int
filt_machport_adjust_qos(struct knote *kn, ipc_kmsg_t first)
{
	if (kn->kn_sfflags & MACH_RCV_MSG) {
		int qos = _pthread_priority_thread_qos(first->ikm_qos_override);
		return FILTER_ADJUST_EVENT_QOS(qos);
	}
	return 0;
}

struct turnstile *
filt_ipc_kqueue_turnstile(struct knote *kn)
{
	assert(kn->kn_filter == EVFILT_MACHPORT || kn->kn_filter == EVFILT_WORKLOOP);
	return kqueue_turnstile(knote_get_kq(kn));
}

bool
filt_machport_kqueue_has_turnstile(struct knote *kn)
{
	assert(kn->kn_filter == EVFILT_MACHPORT);
	return ((kn->kn_sfflags & MACH_RCV_MSG) || (kn->kn_sfflags & MACH_RCV_SYNC_PEEK))
	       && (kn->kn_flags & EV_DISPATCH);
}

/*
 * Stashes a port that participate to sync IPC override until the knote
 * is being re-enabled.
 *
 * It returns:
 * - the turnstile to use as an inheritor for the stashed port
 * - the kind of stash that happened as PORT_SYNC_* value among:
 *   o not stashed (no sync IPC support)
 *   o stashed in the knote (in kn_ext[3])
 *   o to be hooked to the kn_hook knote
 */
struct turnstile *
filt_machport_stash_port(struct knote *kn, ipc_port_t port, int *link)
{
	struct turnstile *ts = TURNSTILE_NULL;

	if (kn->kn_filter == EVFILT_WORKLOOP) {
		assert(kn->kn_mqueue == NULL);
		kn->kn_mqueue = &port->ip_messages;
		ip_reference(port);
		if (link) {
			*link = PORT_SYNC_LINK_WORKLOOP_KNOTE;
		}
		ts = filt_ipc_kqueue_turnstile(kn);
	} else if (!filt_machport_kqueue_has_turnstile(kn)) {
		if (link) {
			*link = PORT_SYNC_LINK_NO_LINKAGE;
		}
	} else if (kn->kn_ext[3] == 0) {
		ip_reference(port);
		kn->kn_ext[3] = (uintptr_t)port;
		ts = filt_ipc_kqueue_turnstile(kn);
		if (link) {
			*link = PORT_SYNC_LINK_WORKLOOP_KNOTE;
		}
	} else {
		ts = (struct turnstile *)kn->kn_hook;
		if (link) {
			*link = PORT_SYNC_LINK_WORKLOOP_STASH;
		}
	}

	return ts;
}

/*
 * Lazily prepare a turnstile so that filt_machport_stash_port()
 * can be called with the mqueue lock held.
 *
 * It will allocate a turnstile in kn_hook if:
 * - the knote supports sync IPC override,
 * - we already stashed a port in kn_ext[3],
 * - the object that will be copied out has a chance to ask to be stashed.
 *
 * It is setup so that its inheritor is the workloop turnstile that has been
 * allocated when this knote was attached.
 */
void
filt_machport_turnstile_prepare_lazily(
	struct knote *kn,
	mach_msg_type_name_t msgt_name,
	ipc_port_t port)
{
	/* This is called from within filt_machportprocess */
	assert((kn->kn_status & KN_SUPPRESSED) && (kn->kn_status & KN_LOCKED));

	if (!filt_machport_kqueue_has_turnstile(kn)) {
		return;
	}

	if (kn->kn_ext[3] == 0 || kn->kn_hook) {
		return;
	}

	struct turnstile *ts = filt_ipc_kqueue_turnstile(kn);
	if ((msgt_name == MACH_MSG_TYPE_PORT_SEND_ONCE && port->ip_specialreply) ||
	    (msgt_name == MACH_MSG_TYPE_PORT_RECEIVE)) {
		struct turnstile *kn_ts = turnstile_alloc();
		kn_ts = turnstile_prepare((uintptr_t)kn,
		    (struct turnstile **)&kn->kn_hook, kn_ts, TURNSTILE_KNOTE);
		turnstile_update_inheritor(kn_ts, ts,
		    TURNSTILE_IMMEDIATE_UPDATE | TURNSTILE_INHERITOR_TURNSTILE);
		turnstile_cleanup();
	}
}

static void
filt_machport_turnstile_complete_port(struct knote *kn, ipc_port_t port,
    ipc_mqueue_t mqueue)
{
	struct turnstile *ts = TURNSTILE_NULL;

	ip_lock(port);
	if (port->ip_specialreply) {
		/*
		 * If the reply has been sent to the special reply port already,
		 * then the special reply port may already be reused to do something
		 * entirely different.
		 *
		 * However, the only reason for it to still point to this knote is
		 * that it's still waiting for a reply, so when this is the case,
		 * neuter the linkage.
		 */
		if (port->ip_sync_link_state == PORT_SYNC_LINK_WORKLOOP_KNOTE &&
		    port->ip_sync_inheritor_knote == kn) {
			ipc_port_adjust_special_reply_port_locked(port, NULL,
			    (IPC_PORT_ADJUST_SR_NONE | IPC_PORT_ADJUST_SR_ENABLE_EVENT), FALSE);
		} else {
			ip_unlock(port);
		}
	} else {
		/*
		 * For receive rights, if their IMQ_KNOTE() is still this
		 * knote, then sever the link.
		 */
		imq_lock(mqueue);
		if (port->ip_sync_link_state == PORT_SYNC_LINK_WORKLOOP_KNOTE &&
		    mqueue->imq_inheritor_knote == kn) {
			ipc_port_adjust_sync_link_state_locked(port, PORT_SYNC_LINK_ANY, NULL);
			ts = port_send_turnstile(port);
		}
		if (ts) {
			turnstile_reference(ts);
			turnstile_update_inheritor(ts, TURNSTILE_INHERITOR_NULL,
			    TURNSTILE_IMMEDIATE_UPDATE);
		}
		imq_unlock(mqueue);
		ip_unlock(port);

		if (ts) {
			turnstile_update_inheritor_complete(ts,
			    TURNSTILE_INTERLOCK_NOT_HELD);
			turnstile_deallocate(ts);
		}
	}

	ip_release(port);
}

void
filt_wldetach_sync_ipc(struct knote *kn)
{
	ipc_mqueue_t mqueue = kn->kn_mqueue;
	filt_machport_turnstile_complete_port(kn, ip_from_mq(mqueue), mqueue);
	kn->kn_mqueue = NULL;
}

/*
 * Other half of filt_machport_turnstile_prepare_lazily()
 *
 * This is serialized by the knote state machine.
 */
static void
filt_machport_turnstile_complete(struct knote *kn)
{
	if (kn->kn_ext[3]) {
		ipc_port_t port = (ipc_port_t)kn->kn_ext[3];
		filt_machport_turnstile_complete_port(kn, port, &port->ip_messages);
		kn->kn_ext[3] = 0;
	}

	if (kn->kn_hook) {
		struct turnstile *ts = kn->kn_hook;

		turnstile_update_inheritor(ts, TURNSTILE_INHERITOR_NULL,
		    TURNSTILE_IMMEDIATE_UPDATE);
		turnstile_update_inheritor_complete(ts, TURNSTILE_INTERLOCK_HELD);

		turnstile_complete((uintptr_t)kn, (struct turnstile **)&kn->kn_hook, &ts, TURNSTILE_KNOTE);
		turnstile_cleanup();

		assert(ts);
		turnstile_deallocate(ts);
	}
}

static void
filt_machport_link(ipc_mqueue_t mqueue, struct knote *kn)
{
	struct knote *hd = SLIST_FIRST(&mqueue->imq_klist);

	if (hd && filt_machport_kqueue_has_turnstile(kn)) {
		SLIST_INSERT_AFTER(hd, kn, kn_selnext);
	} else {
		SLIST_INSERT_HEAD(&mqueue->imq_klist, kn, kn_selnext);
	}
}

static void
filt_machport_unlink(ipc_mqueue_t mqueue, struct knote *kn)
{
	struct knote **knprev;

	KNOTE_DETACH(&mqueue->imq_klist, kn);

	/* make sure the first knote is a knote we can push on */
	SLIST_FOREACH_PREVPTR(kn, knprev, &mqueue->imq_klist, kn_selnext) {
		if (filt_machport_kqueue_has_turnstile(kn)) {
			*knprev = SLIST_NEXT(kn, kn_selnext);
			SLIST_INSERT_HEAD(&mqueue->imq_klist, kn, kn_selnext);
			break;
		}
	}
}

int
filt_wlattach_sync_ipc(struct knote *kn)
{
	mach_port_name_t name = (mach_port_name_t)kn->kn_id;
	ipc_space_t space = current_space();
	ipc_entry_t entry;
	ipc_port_t port = IP_NULL;
	int error = 0;

	if (ipc_right_lookup_read(space, name, &entry) != KERN_SUCCESS) {
		return ENOENT;
	}

	/* space is read-locked */

	if (entry->ie_bits & MACH_PORT_TYPE_RECEIVE) {
		port = ip_object_to_port(entry->ie_object);
		if (port->ip_specialreply) {
			error = ENOENT;
		}
	} else if (entry->ie_bits & MACH_PORT_TYPE_SEND_ONCE) {
		port = ip_object_to_port(entry->ie_object);
		if (!port->ip_specialreply) {
			error = ENOENT;
		}
	} else {
		error = ENOENT;
	}
	if (error) {
		is_read_unlock(space);
		return error;
	}

	ip_lock(port);
	is_read_unlock(space);

	if (port->ip_sync_link_state == PORT_SYNC_LINK_ANY) {
		ip_unlock(port);
		/*
		 * We cannot start a sync IPC inheritance chain, only further one
		 * Note: this can also happen if the inheritance chain broke
		 * because the original requestor died.
		 */
		return ENOENT;
	}

	if (port->ip_specialreply) {
		ipc_port_adjust_special_reply_port_locked(port, kn,
		    IPC_PORT_ADJUST_SR_LINK_WORKLOOP, FALSE);
	} else {
		ipc_port_adjust_port_locked(port, kn, FALSE);
	}

	/* make sure the port was stashed */
	assert(kn->kn_mqueue == &port->ip_messages);

	/* port has been unlocked by ipc_port_adjust_* */

	return 0;
}

static int
filt_machportattach(
	struct knote *kn,
	__unused struct kevent_qos_s *kev)
{
	mach_port_name_t name = (mach_port_name_t)kn->kn_id;
	uint64_t wq_link_id = waitq_link_reserve(NULL);
	ipc_space_t space = current_space();
	ipc_kmsg_t first;
	struct turnstile *send_turnstile = TURNSTILE_NULL;

	int error;
	int result = 0;
	kern_return_t kr;
	ipc_entry_t entry;
	ipc_mqueue_t mqueue;

	kn->kn_flags &= ~EV_EOF;
	kn->kn_ext[3] = 0;

	if (filt_machport_kqueue_has_turnstile(kn)) {
		/*
		 * If the filter is likely to support sync IPC override,
		 * and it happens to be attaching to a workloop,
		 * make sure the workloop has an allocated turnstile.
		 */
		kqueue_alloc_turnstile(knote_get_kq(kn));
	}

lookup_again:
	kr = ipc_right_lookup_read(space, name, &entry);

	if (kr != KERN_SUCCESS) {
		error = ENOENT;
		goto out;
	}

	/* space is read-locked and active */

	if ((entry->ie_bits & MACH_PORT_TYPE_PORT_SET) &&
	    knote_link_waitqset_should_lazy_alloc(kn)) {
		is_read_unlock(space);

		/*
		 * We need to link the portset of the kn,
		 * to insure that the link is allocated before taking
		 * any spinlocks.
		 *
		 * Because we have to drop the space lock so that
		 * knote_link_waitqset_lazy_alloc() can allocate memory,
		 * we will need to redo the lookup.
		 */
		knote_link_waitqset_lazy_alloc(kn);
		goto lookup_again;
	}

	if (entry->ie_bits & MACH_PORT_TYPE_PORT_SET) {
		ipc_pset_t pset;

		pset = ips_object_to_pset(entry->ie_object);
		mqueue = &pset->ips_messages;
		ips_reference(pset);

		imq_lock(mqueue);
		kn->kn_mqueue = mqueue;

		/*
		 * Bind the portset wait queue directly to knote/kqueue.
		 * This allows us to just use wait_queue foo to effect a wakeup,
		 * rather than having to call knote() from the Mach code on each
		 * message.  We still attach the knote to the mqueue klist for
		 * NOTE_REVOKE purposes only.
		 */
		error = knote_link_waitq(kn, &mqueue->imq_wait_queue, &wq_link_id);
		if (!error) {
			filt_machport_link(mqueue, kn);
			imq_unlock(mqueue);
		} else {
			kn->kn_mqueue = IMQ_NULL;
			imq_unlock(mqueue);
			ips_release(pset);
		}

		is_read_unlock(space);

		/*
		 * linked knotes are marked stay-active and therefore don't
		 * need an indication of their fired state to be returned
		 * from the attach operation.
		 */
	} else if (entry->ie_bits & MACH_PORT_TYPE_RECEIVE) {
		ipc_port_t port = ip_object_to_port(entry->ie_object);

		if (port->ip_specialreply) {
			/*
			 * Registering for kevents on special reply ports
			 * isn't supported for two reasons:
			 *
			 * 1. it really makes very little sense for a port that
			 *    is supposed to be used synchronously
			 *
			 * 2. their mqueue's imq_klist field will be used to
			 *    store the receive turnstile, so we can't possibly
			 *    attach them anyway.
			 */
			is_read_unlock(space);
			error = ENOTSUP;
			goto out;
		}

		mqueue = &port->ip_messages;
		ip_reference(port);

		/*
		 * attach knote to port and determine result
		 * If the filter requested direct message receipt,
		 * we may need to adjust the qos of the knote to
		 * reflect the requested and override qos of the
		 * first message in the queue.
		 */
		ip_lock(port);
		imq_lock(mqueue);

		kn->kn_mqueue = mqueue;
		if (port->ip_sync_link_state != PORT_SYNC_LINK_ANY) {
			/*
			 * We're attaching a port that used to have an IMQ_KNOTE,
			 * clobber this state, we'll fixup its turnstile inheritor below.
			 */
			ipc_port_adjust_sync_link_state_locked(port, PORT_SYNC_LINK_ANY, NULL);
		}
		filt_machport_link(mqueue, kn);

		if ((first = ipc_kmsg_queue_first(&mqueue->imq_messages)) != IKM_NULL) {
			result = FILTER_ACTIVE | filt_machport_adjust_qos(kn, first);
		}

		/*
		 * Update the port's turnstile inheritor
		 *
		 * Unlike filt_machportdetach(), we don't have to care about races for
		 * turnstile_workloop_pusher_info(): filt_machport_link() doesn't affect
		 * already pushing knotes, and if the current one becomes the new
		 * pusher, it'll only be visible when turnstile_workloop_pusher_info()
		 * returns.
		 */
		send_turnstile = port_send_turnstile(port);
		if (send_turnstile) {
			turnstile_reference(send_turnstile);
			ipc_port_send_update_inheritor(port, send_turnstile,
			    TURNSTILE_IMMEDIATE_UPDATE);

			/*
			 * rdar://problem/48861190
			 *
			 * When a listener connection resumes a peer,
			 * updating the inheritor above has moved the push
			 * from the current thread to the workloop.
			 *
			 * However, we haven't told the workloop yet
			 * that it needs a thread request, and we risk
			 * to be preeempted as soon as we drop the space
			 * lock below.
			 *
			 * To avoid this disable preemption and let kevent
			 * reenable it after it takes the kqlock.
			 */
			disable_preemption();
			result |= FILTER_THREADREQ_NODEFEER;
		}

		imq_unlock(mqueue);
		ip_unlock(port);

		is_read_unlock(space);
		if (send_turnstile) {
			turnstile_update_inheritor_complete(send_turnstile,
			    TURNSTILE_INTERLOCK_NOT_HELD);
			turnstile_deallocate_safe(send_turnstile);
		}

		error = 0;
	} else {
		is_read_unlock(space);
		error = ENOTSUP;
	}

out:
	waitq_link_release(wq_link_id);

	/* bail out on errors */
	if (error) {
		knote_set_error(kn, error);
		return 0;
	}

	return result;
}

/* Validate imq_to_object implementation "works" */
_Static_assert(offsetof(struct ipc_pset, ips_messages) ==
    offsetof(struct ipc_port, ip_messages),
    "Make sure the mqueue aliases in both ports and psets");

static void
filt_machportdetach(
	struct knote *kn)
{
	ipc_mqueue_t mqueue = kn->kn_mqueue;
	ipc_object_t object = imq_to_object(mqueue);
	struct turnstile *send_turnstile = TURNSTILE_NULL;

	filt_machport_turnstile_complete(kn);

	imq_lock(mqueue);
	if ((kn->kn_status & KN_VANISHED) || (kn->kn_flags & EV_EOF)) {
		/*
		 * ipc_mqueue_changed() already unhooked this knote from the mqueue,
		 */
	} else {
		ipc_port_t port = IP_NULL;

		/*
		 * When the knote being detached is the first one in the list,
		 * then unlinking the knote *and* updating the turnstile inheritor
		 * need to happen atomically with respect to the callers of
		 * turnstile_workloop_pusher_info().
		 *
		 * The caller of turnstile_workloop_pusher_info() will use the kq req
		 * lock (and hence the kqlock), so we just need to hold the kqlock too.
		 */
		if (io_otype(object) == IOT_PORT) {
			port = ip_object_to_port(object);
			assert(port->ip_sync_link_state == PORT_SYNC_LINK_ANY);
			if (kn == SLIST_FIRST(&mqueue->imq_klist)) {
				send_turnstile = port_send_turnstile(port);
			}
		}

		filt_machport_unlink(mqueue, kn);

		if (send_turnstile) {
			turnstile_reference(send_turnstile);
			ipc_port_send_update_inheritor(port, send_turnstile,
			    TURNSTILE_IMMEDIATE_UPDATE);
		}
	}

	/* Clear the knote pointer once the knote has been removed from turnstile */
	kn->kn_mqueue = IMQ_NULL;
	imq_unlock(mqueue);

	if (send_turnstile) {
		turnstile_update_inheritor_complete(send_turnstile,
		    TURNSTILE_INTERLOCK_NOT_HELD);
		turnstile_deallocate(send_turnstile);
	}

	if (io_otype(object) == IOT_PORT_SET) {
		/*
		 * Unlink the portset wait queue from knote/kqueue.
		 * JMM - Does this need to be atomic under the mq lock?
		 */
		(void)knote_unlink_waitq(kn, &mqueue->imq_wait_queue);
	}
	io_release(object);
}

/*
 * filt_machportevent - deliver events into the mach port filter
 *
 * Mach port message arrival events are currently only posted via the
 * kqueue filter routine for ports. Port sets are marked stay-active
 * and the wait queue code will break any kqueue waiters out to go
 * poll the stay-queued knotes again.
 *
 * If there is a message at the head of the queue,
 * we indicate that the knote should go active.  If
 * the message is to be direct-received, we adjust the
 * QoS of the knote according the requested and override
 * QoS of that first message.
 */
static int
filt_machportevent(struct knote *kn, long hint __assert_only)
{
	ipc_mqueue_t mqueue = kn->kn_mqueue;
	ipc_kmsg_t first;
	int result = 0;

	/* mqueue locked by caller */
	assert(imq_held(mqueue));
	assert(hint != NOTE_REVOKE);
	if (imq_is_valid(mqueue)) {
		assert(!imq_is_set(mqueue));
		if ((first = ipc_kmsg_queue_first(&mqueue->imq_messages)) != IKM_NULL) {
			result = FILTER_ACTIVE | filt_machport_adjust_qos(kn, first);
		}
	}

	return result;
}

static int
filt_machporttouch(
	struct knote *kn,
	struct kevent_qos_s *kev)
{
	ipc_mqueue_t mqueue = kn->kn_mqueue;
	ipc_kmsg_t first;
	int result = 0;

	/* copy in new settings and save off new input fflags */
	kn->kn_sfflags = kev->fflags;
	kn->kn_ext[0] = kev->ext[0];
	kn->kn_ext[1] = kev->ext[1];

	if (kev->flags & EV_ENABLE) {
		/*
		 * If the knote is being enabled, make sure there's no lingering
		 * IPC overrides from the previous message delivery.
		 */
		filt_machport_turnstile_complete(kn);
	}

	/*
	 * If the mqueue is a valid port and there is a message
	 * that will be direct-received from the knote, update
	 * the knote qos based on the first message and trigger
	 * the event. If there are no more messages, reset the
	 * QoS to the value provided by the kevent.
	 */
	imq_lock(mqueue);
	if (imq_is_valid(mqueue) && !imq_is_set(mqueue) &&
	    (first = ipc_kmsg_queue_first(&mqueue->imq_messages)) != IKM_NULL) {
		result = FILTER_ACTIVE | filt_machport_adjust_qos(kn, first);
	} else if (kn->kn_sfflags & MACH_RCV_MSG) {
		result = FILTER_RESET_EVENT_QOS;
	}
	imq_unlock(mqueue);

	return result;
}

static int
filt_machportprocess(struct knote *kn, struct kevent_qos_s *kev)
{
	ipc_mqueue_t mqueue = kn->kn_mqueue;
	ipc_object_t object = imq_to_object(mqueue);
	thread_t self = current_thread();
	kevent_ctx_t kectx = NULL;

	wait_result_t wresult;
	mach_msg_option_t option;
	mach_vm_address_t addr;
	mach_msg_size_t size;

	/* Capture current state */
	knote_fill_kevent(kn, kev, MACH_PORT_NULL);
	kev->ext[3] = 0; /* hide our port reference from userspace */

	/* If already deallocated/moved return one last EOF event */
	if (kev->flags & EV_EOF) {
		return FILTER_ACTIVE | FILTER_RESET_EVENT_QOS;
	}

	/*
	 * Only honor supported receive options. If no options are
	 * provided, just force a MACH_RCV_TOO_LARGE to detect the
	 * name of the port and sizeof the waiting message.
	 */
	option = kn->kn_sfflags & (MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY |
	    MACH_RCV_TRAILER_MASK | MACH_RCV_VOUCHER | MACH_MSG_STRICT_REPLY);

	if (option & MACH_RCV_MSG) {
		addr = (mach_vm_address_t) kn->kn_ext[0];
		size = (mach_msg_size_t) kn->kn_ext[1];

		/*
		 * If the kevent didn't specify a buffer and length, carve a buffer
		 * from the filter processing data according to the flags.
		 */
		if (size == 0) {
			kectx = kevent_get_context(self);
			addr  = (mach_vm_address_t)kectx->kec_data_out;
			size  = (mach_msg_size_t)kectx->kec_data_resid;
			option |= (MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY);
			if (kectx->kec_process_flags & KEVENT_FLAG_STACK_DATA) {
				option |= MACH_RCV_STACK;
			}
		}
	} else {
		/* just detect the port name (if a set) and size of the first message */
		option = MACH_RCV_LARGE;
		addr = 0;
		size = 0;
	}

	imq_lock(mqueue);

	/* just use the reference from here on out */
	io_reference(object);

	/*
	 * Set up to receive a message or the notification of a
	 * too large message.  But never allow this call to wait.
	 * If the user provided aditional options, like trailer
	 * options, pass those through here.  But we don't support
	 * scatter lists through this interface.
	 */
	self->ith_object = object;
	self->ith_msg_addr = addr;
	self->ith_rsize = size;
	self->ith_msize = 0;
	self->ith_option = option;
	self->ith_receiver_name = MACH_PORT_NULL;
	self->ith_continuation = NULL;
	option |= MACH_RCV_TIMEOUT; // never wait
	self->ith_state = MACH_RCV_IN_PROGRESS;
	self->ith_knote = kn;

	wresult = ipc_mqueue_receive_on_thread(
		mqueue,
		option,
		size,         /* max_size */
		0,         /* immediate timeout */
		THREAD_INTERRUPTIBLE,
		self);
	/* mqueue unlocked */

	/*
	 * If we timed out, or the process is exiting, just release the
	 * reference on the ipc_object and return zero.
	 */
	if (wresult == THREAD_RESTART || self->ith_state == MACH_RCV_TIMED_OUT) {
		assert(self->turnstile != TURNSTILE_NULL);
		io_release(object);
		return 0;
	}

	assert(wresult == THREAD_NOT_WAITING);
	assert(self->ith_state != MACH_RCV_IN_PROGRESS);

	/*
	 * If we weren't attempting to receive a message
	 * directly, we need to return the port name in
	 * the kevent structure.
	 */
	if ((option & MACH_RCV_MSG) != MACH_RCV_MSG) {
		assert(self->ith_state == MACH_RCV_TOO_LARGE);
		assert(self->ith_kmsg == IKM_NULL);
		kev->data = self->ith_receiver_name;
		io_release(object);
		return FILTER_ACTIVE;
	}

	/*
	 * Attempt to receive the message directly, returning
	 * the results in the fflags field.
	 */
	kev->fflags = mach_msg_receive_results(&size);

	/* kmsg and object reference consumed */

	/*
	 * if the user asked for the identity of ports containing a
	 * a too-large message, return it in the data field (as we
	 * do for messages we didn't try to receive).
	 */
	if (kev->fflags == MACH_RCV_TOO_LARGE) {
		kev->ext[1] = self->ith_msize;
		if (option & MACH_RCV_LARGE_IDENTITY) {
			kev->data = self->ith_receiver_name;
		} else {
			kev->data = MACH_PORT_NULL;
		}
	} else {
		kev->ext[1] = size;
		kev->data = MACH_PORT_NULL;
	}

	/*
	 * If we used a data buffer carved out from the filt_process data,
	 * store the address used in the knote and adjust the residual and
	 * other parameters for future use.
	 */
	if (kectx) {
		assert(kectx->kec_data_resid >= size);
		kectx->kec_data_resid -= size;
		if ((kectx->kec_process_flags & KEVENT_FLAG_STACK_DATA) == 0) {
			kev->ext[0] = kectx->kec_data_out;
			kectx->kec_data_out += size;
		} else {
			assert(option & MACH_RCV_STACK);
			kev->ext[0] = kectx->kec_data_out + kectx->kec_data_resid;
		}
	}

	/*
	 * Apply message-based QoS values to output kevent as prescribed.
	 * The kev->ext[2] field gets (msg-qos << 32) | (override-qos).
	 *
	 * The mach_msg_receive_results() call saved off the message
	 * QoS values in the continuation save area on successful receive.
	 */
	if (kev->fflags == MACH_MSG_SUCCESS) {
		kev->ext[2] = ((uint64_t)self->ith_qos << 32) |
		    (uint64_t)self->ith_qos_override;
	}

	return FILTER_ACTIVE;
}

/*
 * Peek to see if the message queue associated with the knote has any
 * events. This pre-hook is called when a filter uses the stay-
 * on-queue mechanism (as the knote_link_waitq mechanism does for
 * portsets) and someone calls select() against the containing kqueue.
 *
 * Just peek at the pre-post status of the portset's wait queue
 * to determine if it has anything interesting.  We can do it
 * without holding the lock, as it is just a snapshot in time
 * (if this is used as part of really waiting for events, we
 * will catch changes in this status when the event gets posted
 * up to the knote's kqueue).
 */
static int
filt_machportpeek(struct knote *kn)
{
	ipc_mqueue_t mqueue = kn->kn_mqueue;

	return ipc_mqueue_set_peek(mqueue) ? FILTER_ACTIVE : 0;
}

SECURITY_READ_ONLY_EARLY(struct filterops) machport_filtops = {
	.f_adjusts_qos = true,
	.f_extended_codes = true,
	.f_attach = filt_machportattach,
	.f_detach = filt_machportdetach,
	.f_event = filt_machportevent,
	.f_touch = filt_machporttouch,
	.f_process = filt_machportprocess,
	.f_peek = filt_machportpeek,
};
