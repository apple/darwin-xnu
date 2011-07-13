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
#include <ipc/ipc_print.h>

#include <kern/kern_types.h>
#include <kern/spl.h>

#include <vm/vm_map.h>

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
	ipc_space_t		space,
	mach_port_name_t	*namep,
	ipc_pset_t		*psetp)
{
	ipc_pset_t pset;
	mach_port_name_t name;
	kern_return_t kr;

	kr = ipc_object_alloc(space, IOT_PORT_SET,
			      MACH_PORT_TYPE_PORT_SET, 0,
			      &name, (ipc_object_t *) &pset);
	if (kr != KERN_SUCCESS)
		return kr;
	/* pset is locked */

	pset->ips_local_name = name;
	ipc_mqueue_init(&pset->ips_messages, TRUE /* set */);

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
	ipc_space_t		space,
	mach_port_name_t	name,
	ipc_pset_t		*psetp)
{
	ipc_pset_t pset;
	kern_return_t kr;


	kr = ipc_object_alloc_name(space, IOT_PORT_SET,
				   MACH_PORT_TYPE_PORT_SET, 0,
				   name, (ipc_object_t *) &pset);
	if (kr != KERN_SUCCESS)
		return kr;
	/* pset is locked */

	pset->ips_local_name = name;
	ipc_mqueue_init(&pset->ips_messages, TRUE /* set */);

	*psetp = pset;
	return KERN_SUCCESS;
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
	ipc_pset_t	pset,
	ipc_port_t	port)
{
	assert(ip_active(port));

	return (ipc_mqueue_member(&port->ip_messages, &pset->ips_messages));
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
	ipc_pset_t	pset,
	ipc_port_t	port)
{
	kern_return_t kr;

	assert(ips_active(pset));
	assert(ip_active(port));
	
	kr = ipc_mqueue_add(&port->ip_messages, &pset->ips_messages);

	if (kr == KERN_SUCCESS)
		port->ip_pset_count++;

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
	ipc_pset_t	pset,
	ipc_port_t	port)
{
	kern_return_t kr;

	assert(ip_active(port));
	
	if (port->ip_pset_count == 0)
		return KERN_NOT_IN_SET;

	kr = ipc_mqueue_remove(&port->ip_messages, &pset->ips_messages);

	if (kr == KERN_SUCCESS)
		port->ip_pset_count--;

	return kr;
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
	ipc_port_t	port)
{
	assert(ip_active(port));
	
	if (port->ip_pset_count == 0)
		return KERN_NOT_IN_SET;

	/* 
	 * Remove the port's mqueue from all sets
	 */
	ipc_mqueue_remove_from_all(&port->ip_messages);
	port->ip_pset_count = 0;
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
	ipc_pset_t	pset)
{
	spl_t		s;

	assert(ips_active(pset));

	pset->ips_object.io_bits &= ~IO_BITS_ACTIVE;

	/*
	 * remove all the member message queues
	 */
	ipc_mqueue_remove_all(&pset->ips_messages);
	
	/*
	 * Set all waiters on the portset running to
	 * discover the change.
	 */
	s = splsched();
	imq_lock(&pset->ips_messages);
	ipc_mqueue_changed(&pset->ips_messages);
	imq_unlock(&pset->ips_messages);
	splx(s);

	ips_release(pset);	/* consume the ref our caller gave us */
	ips_check_unlock(pset);
}

/* Kqueue EVFILT_MACHPORT support */

#include <sys/errno.h>

static int      filt_machportattach(struct knote *kn);
static void	filt_machportdetach(struct knote *kn);
static int	filt_machport(struct knote *kn, long hint);
static void     filt_machporttouch(struct knote *kn, struct kevent64_s *kev, long type);
static unsigned filt_machportpeek(struct knote *kn);
struct filterops machport_filtops = {
        .f_attach = filt_machportattach,
        .f_detach = filt_machportdetach,
        .f_event = filt_machport,
        .f_touch = filt_machporttouch,
	.f_peek = filt_machportpeek,
};

static int
filt_machportattach(
        struct knote *kn)
{
        mach_port_name_t        name = (mach_port_name_t)kn->kn_kevent.ident;
        ipc_pset_t              pset = IPS_NULL;
        int                     result = ENOSYS;
        kern_return_t           kr;

        kr = ipc_object_translate(current_space(), name,
                                  MACH_PORT_RIGHT_PORT_SET,
                                  (ipc_object_t *)&pset);
        if (kr != KERN_SUCCESS) {
                result = (kr == KERN_INVALID_NAME ? ENOENT : ENOTSUP);
                goto done;
        }
        /* We've got a lock on pset */

	/* keep a reference for the knote */
	kn->kn_ptr.p_pset = pset; 
	ips_reference(pset);

	/* 
	 * Bind the portset wait queue directly to knote/kqueue.
	 * This allows us to just use wait_queue foo to effect a wakeup,
	 * rather than having to call knote() from the Mach code on each
	 * message.
	 */
	result = knote_link_wait_queue(kn, &pset->ips_messages.imq_wait_queue);
	ips_unlock(pset);
done:
	return result;
}

static void
filt_machportdetach(
        struct knote *kn)
{
        ipc_pset_t              pset = kn->kn_ptr.p_pset;

	/*
	 * Unlink the portset wait queue from knote/kqueue,
	 * and release our reference on the portset.
	 */
	ips_lock(pset);
	knote_unlink_wait_queue(kn, &pset->ips_messages.imq_wait_queue);
	ips_release(kn->kn_ptr.p_pset);
	kn->kn_ptr.p_pset = IPS_NULL; 
	ips_check_unlock(pset);
}

static int
filt_machport(
        struct knote *kn,
        __unused long hint)
{
        mach_port_name_t        name = (mach_port_name_t)kn->kn_kevent.ident;
        ipc_pset_t              pset = IPS_NULL;
	wait_result_t		wresult;
	thread_t		self = current_thread();
        kern_return_t           kr;
	mach_msg_option_t	option;
	mach_msg_size_t		size;

	/* never called from below */
	assert(hint == 0);

	/*
	 * called from user context. Have to validate the
	 * name.  If it changed, we have an EOF situation.
	 */
	kr = ipc_object_translate(current_space(), name,
				  MACH_PORT_RIGHT_PORT_SET,
				  (ipc_object_t *)&pset);
	if (kr != KERN_SUCCESS || pset != kn->kn_ptr.p_pset || !ips_active(pset)) {
		kn->kn_data = 0;
		kn->kn_flags |= (EV_EOF | EV_ONESHOT);
		if (pset != IPS_NULL)
			ips_check_unlock(pset);
		return(1);
        }

	/* just use the reference from here on out */
	ips_reference(pset);
	ips_unlock(pset); 

	/*
	 * Only honor supported receive options. If no options are
	 * provided, just force a MACH_RCV_TOO_LARGE to detect the
	 * name of the port and sizeof the waiting message.
	 */
	option = kn->kn_sfflags & (MACH_RCV_MSG|MACH_RCV_LARGE|MACH_RCV_TRAILER_MASK);
	if (option & MACH_RCV_MSG) {
		self->ith_msg_addr = (mach_vm_address_t) kn->kn_ext[0];
		size = (mach_msg_size_t)kn->kn_ext[1];
	} else {
		option = MACH_RCV_LARGE;
		self->ith_msg_addr = 0;
		size = 0;
	}

	/*
	 * Set up to receive a message or the notification of a
	 * too large message.  But never allow this call to wait.
	 * If the user provided aditional options, like trailer
	 * options, pass those through here.  But we don't support
	 * scatter lists through this interface.
	 */
	self->ith_object = (ipc_object_t)pset;
	self->ith_msize = size;
	self->ith_option = option;
	self->ith_scatter_list_size = 0;
	self->ith_receiver_name = MACH_PORT_NULL;
	self->ith_continuation = NULL;
	option |= MACH_RCV_TIMEOUT; // never wait
	assert((self->ith_state = MACH_RCV_IN_PROGRESS) == MACH_RCV_IN_PROGRESS);

	wresult = ipc_mqueue_receive_on_thread(
			&pset->ips_messages,
			option,
			size, /* max_size */
			0, /* immediate timeout */
			THREAD_INTERRUPTIBLE,
			self);
	assert(wresult == THREAD_NOT_WAITING);
	assert(self->ith_state != MACH_RCV_IN_PROGRESS);

	/*
	 * If we timed out, just release the reference on the
	 * portset and return zero.
	 */
	if (self->ith_state == MACH_RCV_TIMED_OUT) {
		ipc_pset_release(pset);
		return 0;
	}

	/*
	 * If we weren't attempting to receive a message
	 * directly, we need to return the port name in
	 * the kevent structure.
	 */
	if ((option & MACH_RCV_MSG) != MACH_RCV_MSG) {
		assert(self->ith_state == MACH_RCV_TOO_LARGE);
		assert(self->ith_kmsg == IKM_NULL);
		kn->kn_data = self->ith_receiver_name;
		ipc_pset_release(pset);
		return 1;
	}

	/*
	 * Attempt to receive the message directly, returning
	 * the results in the fflags field.
	 */
	assert(option & MACH_RCV_MSG);
        kn->kn_data = MACH_PORT_NULL;
	kn->kn_ext[1] = self->ith_msize;
	kn->kn_fflags = mach_msg_receive_results();
	/* kmsg and pset reference consumed */
	return 1;
}

static void
filt_machporttouch(struct knote *kn, struct kevent64_s *kev, long type)
{
        switch (type) {
        case EVENT_REGISTER:
                kn->kn_sfflags = kev->fflags;
                kn->kn_sdata = kev->data;
                break;
        case EVENT_PROCESS:
                *kev = kn->kn_kevent;
                if (kn->kn_flags & EV_CLEAR) {
			kn->kn_data = 0;
			kn->kn_fflags = 0;
		}
                break;
        default:
                panic("filt_machporttouch() - invalid type (%ld)", type);
                break;
        }
}

/*
 * Peek to see if the portset associated with the knote has any
 * events. This pre-hook is called when a filter uses the stay-
 * on-queue mechanism (as the knote_link_wait_queue mechanism
 * does).
 *
 * This is called with the kqueue that the knote belongs to still
 * locked (thus holding a reference on the knote, but restricting
 * also restricting our ability to take other locks).
 *
 * Just peek at the pre-post status of the portset's wait queue
 * to determine if it has anything interesting.  We can do it
 * without holding the lock, as it is just a snapshot in time
 * (if this is used as part of really waiting for events, we
 * will catch changes in this status when the event gets posted
 * up to the knote's kqueue).
 */
static unsigned
filt_machportpeek(struct knote *kn)
{
        ipc_pset_t              pset = kn->kn_ptr.p_pset;
	ipc_mqueue_t		set_mq = &pset->ips_messages;

	return (ipc_mqueue_peek(set_mq));
}


#include <mach_kdb.h>
#if	MACH_KDB

#include <ddb/db_output.h>

#define	printf	kdbprintf

int
ipc_list_count(
	struct ipc_kmsg *base)
{
	register int count = 0;

	if (base) {
		struct ipc_kmsg *kmsg = base;

		++count;
		while (kmsg && kmsg->ikm_next != base
			    && kmsg->ikm_next != IKM_BOGUS){
			kmsg = kmsg->ikm_next;
			++count;
		}
	}
	return(count);
}

/*
 *	Routine:	ipc_pset_print
 *	Purpose:
 *		Pretty-print a port set for kdb.
 */
void
ipc_pset_print(
	ipc_pset_t	pset)
{
	printf("pset 0x%x\n", pset);

	db_indent += 2;

	ipc_object_print(&pset->ips_object);
	iprintf("local_name = 0x%x\n", pset->ips_local_name);
	iprintf("%d kmsgs => 0x%x",
		ipc_list_count(pset->ips_messages.imq_messages.ikmq_base),
		pset->ips_messages.imq_messages.ikmq_base);
	printf(",rcvrs queue= 0x%x\n", &pset->ips_messages.imq_wait_queue);

	db_indent -=2;
}

#endif	/* MACH_KDB */
