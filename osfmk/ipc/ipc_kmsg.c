/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
 *	File:	ipc/ipc_kmsg.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Operations on kernel messages.
 */

#include <norma_vm.h>

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <mach/vm_statistics.h>

#include <kern/kern_types.h>
#include <kern/assert.h>
#include <kern/ipc_kobject.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/spl.h>
#include <kern/misc_protos.h>
#include <kern/counters.h>
#include <kern/cpu_data.h>

#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_kern.h>

#include <ipc/port.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_table.h>

#include <string.h>

#ifdef ppc
#include <ppc/Firmware.h>
#include <ppc/low_trace.h>
#endif


extern vm_map_t		ipc_kernel_copy_map;
extern vm_size_t	ipc_kmsg_max_vm_space;
extern vm_size_t	msg_ool_size_small;

#define MSG_OOL_SIZE_SMALL	msg_ool_size_small

#if defined(__LP64__)
#define MAP_SIZE_DIFFERS(map)	(map->max_offset < MACH_VM_MAX_ADDRESS)
#define OTHER_OOL_DESCRIPTOR	mach_msg_ool_descriptor32_t
#define OTHER_OOL_PORTS_DESCRIPTOR	mach_msg_ool_ports_descriptor32_t
#else
#define MAP_SIZE_DIFFERS(map)	(map->max_offset > VM_MAX_ADDRESS)
#define OTHER_OOL_DESCRIPTOR	mach_msg_ool_descriptor64_t
#define OTHER_OOL_PORTS_DESCRIPTOR	mach_msg_ool_ports_descriptor64_t
#endif

#define DESC_SIZE_ADJUSTMENT	(sizeof(OTHER_OOL_DESCRIPTOR) - \
				 sizeof(mach_msg_ool_descriptor_t))

/* scatter list macros */

#define SKIP_PORT_DESCRIPTORS(s, c)					\
MACRO_BEGIN								\
	if ((s) != MACH_MSG_DESCRIPTOR_NULL) {				\
		while ((c) > 0) {					\
			if ((s)->type.type != MACH_MSG_PORT_DESCRIPTOR)	\
				break;					\
			(s)++; (c)--;					\
		}							\
		if (c == 0)						\
			(s) = MACH_MSG_DESCRIPTOR_NULL;			\
	}								\
MACRO_END

#define INCREMENT_SCATTER(s, c, d)					\
MACRO_BEGIN								\
	if ((s) != MACH_MSG_DESCRIPTOR_NULL) {				\
	    s = (d) ? (mach_msg_descriptor_t *)				\
		((OTHER_OOL_DESCRIPTOR *)(s) + 1) :			\
		(s + 1);						\
		(c)--;							\
	}								\
MACRO_END

/* zone for cached ipc_kmsg_t structures */
zone_t			ipc_kmsg_zone;

/*
 * Forward declarations
 */

void ipc_kmsg_clean(
	ipc_kmsg_t	kmsg);

void ipc_kmsg_clean_body(
    	ipc_kmsg_t	kmsg,
    	mach_msg_type_number_t	number,
	mach_msg_descriptor_t	*desc);

void ipc_kmsg_clean_partial(
	ipc_kmsg_t		kmsg,
	mach_msg_type_number_t	number,
	mach_msg_descriptor_t	*desc,
	vm_offset_t		paddr,
	vm_size_t		length);

mach_msg_return_t ipc_kmsg_copyin_body(
	ipc_kmsg_t		kmsg,
	ipc_space_t		space,
	vm_map_t		map);

/*
 *	We keep a per-processor cache of kernel message buffers.
 *	The cache saves the overhead/locking of using kalloc/kfree.
 *	The per-processor cache seems to miss less than a per-thread cache,
 *	and it also uses less memory.  Access to the cache doesn't
 *	require locking.
 */

/*
 *	Routine:	ipc_kmsg_alloc
 *	Purpose:
 *		Allocate a kernel message structure.  If we can get one from
 *		the cache, that is best.  Otherwise, allocate a new one.
 *	Conditions:
 *		Nothing locked.
 */
ipc_kmsg_t
ipc_kmsg_alloc(
	mach_msg_size_t msg_and_trailer_size)
{
	mach_msg_size_t max_expanded_size;
	ipc_kmsg_t kmsg;

#if !defined(__LP64__)
	mach_msg_size_t size = msg_and_trailer_size - MAX_TRAILER_SIZE;

	/*
	 * LP64support -
	 * Pad the allocation in case we need to expand the
	 * message descrptors for user spaces with pointers larger than
	 * the kernel's own.  We don't know how many descriptors
	 * there are yet, so just assume the whole body could be
	 * descriptors (if there could be any at all).
	 *
	 * The expansion space is left in front of the header,
	 * because it is easier to pull the header and descriptors
	 * forward as we process them than it is to push all the
	 * data backwards.
	 */
	max_expanded_size = 
		(size > sizeof(mach_msg_base_t)) ?
		(msg_and_trailer_size + DESC_SIZE_ADJUSTMENT * 
		 ((size - sizeof(mach_msg_base_t)) /
		  (sizeof(mach_msg_ool_descriptor_t))))
		:
		(msg_and_trailer_size);
#else
	max_expanded_size = msg_and_trailer_size;
#endif

	/* round up for ikm_cache */
	if (max_expanded_size < IKM_SAVED_MSG_SIZE)
		max_expanded_size = IKM_SAVED_MSG_SIZE;

	if (max_expanded_size == IKM_SAVED_MSG_SIZE) {
		struct ikm_cache	*cache;
		unsigned int		i;

		disable_preemption();
		cache = &PROCESSOR_DATA(current_processor(), ikm_cache);
		if ((i = cache->avail) > 0) {
			assert(i <= IKM_STASH);
			kmsg = cache->entries[--i];
			cache->avail = i;
			ikm_check_init(kmsg, max_expanded_size);
			enable_preemption();
			kmsg->ikm_header = (mach_msg_header_t *)
			                   ((vm_offset_t)(kmsg + 1) +
					    max_expanded_size -
					    msg_and_trailer_size);
			return (kmsg);
		}
		enable_preemption();
		kmsg = (ipc_kmsg_t)zalloc(ipc_kmsg_zone);
	} else {
		kmsg = (ipc_kmsg_t)kalloc(ikm_plus_overhead(max_expanded_size));
	}

	if (kmsg != IKM_NULL) {
		ikm_init(kmsg, max_expanded_size);
		kmsg->ikm_header = (mach_msg_header_t *)
		                   ((vm_offset_t)(kmsg + 1) +
				    max_expanded_size -
				    msg_and_trailer_size);
	}
	return(kmsg);
}

/*
 *	Routine:	ipc_kmsg_free
 *	Purpose:
 *		Free a kernel message buffer.  If the kms is preallocated
 *		to a port, just "put it back (marked unused)."  We have to
 *		do this with the port locked.  The port may have its hold
 *		on our message released.  In that case, we have to just
 *		revert the message to a traditional one and free it normally.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_kmsg_free(
	ipc_kmsg_t	kmsg)
{
	mach_msg_size_t size = kmsg->ikm_size;
	ipc_port_t port;

	/*
	 * Check to see if the message is bound to the port.  If so,
	 * mark it not in use.  If the port isn't already dead, then
	 * leave the message associated with it.  Otherwise, free it.
	 */
	port = ikm_prealloc_inuse_port(kmsg);
	if (port != IP_NULL) {
		ip_lock(port);
		ikm_prealloc_clear_inuse(kmsg, port);
		if (ip_active(port) && (port->ip_premsg == kmsg)) {
			assert(IP_PREALLOC(port));
			ip_unlock(port);
			return;
		}
		ip_check_unlock(port);  /* May be last reference */
	}

	/*
	 * Peek and see if it has to go back in the cache.
	 */
	if (kmsg->ikm_size == IKM_SAVED_MSG_SIZE) {
		struct ikm_cache	*cache;
		unsigned int		i;

		disable_preemption();
		cache = &PROCESSOR_DATA(current_processor(), ikm_cache);
		if ((i = cache->avail) < IKM_STASH) {
			cache->entries[i] = kmsg;
			cache->avail = i + 1;
			enable_preemption();
			return;
		}
		enable_preemption();
		zfree(ipc_kmsg_zone, kmsg);
		return;
	}
	kfree(kmsg, ikm_plus_overhead(size));
}


/*
 *	Routine:	ipc_kmsg_enqueue
 *	Purpose:
 *		Enqueue a kmsg.
 */

void
ipc_kmsg_enqueue(
	ipc_kmsg_queue_t	queue,
	ipc_kmsg_t		kmsg)
{
	ipc_kmsg_enqueue_macro(queue, kmsg);
}

/*
 *	Routine:	ipc_kmsg_dequeue
 *	Purpose:
 *		Dequeue and return a kmsg.
 */

ipc_kmsg_t
ipc_kmsg_dequeue(
	ipc_kmsg_queue_t	queue)
{
	ipc_kmsg_t first;

	first = ipc_kmsg_queue_first(queue);

	if (first != IKM_NULL)
		ipc_kmsg_rmqueue_first_macro(queue, first);

	return first;
}

/*
 *	Routine:	ipc_kmsg_rmqueue
 *	Purpose:
 *		Pull a kmsg out of a queue.
 */

void
ipc_kmsg_rmqueue(
	ipc_kmsg_queue_t	queue,
	ipc_kmsg_t		kmsg)
{
	ipc_kmsg_t next, prev;

	assert(queue->ikmq_base != IKM_NULL);

	next = kmsg->ikm_next;
	prev = kmsg->ikm_prev;

	if (next == kmsg) {
		assert(prev == kmsg);
		assert(queue->ikmq_base == kmsg);

		queue->ikmq_base = IKM_NULL;
	} else {
		if (queue->ikmq_base == kmsg)
			queue->ikmq_base = next;

		next->ikm_prev = prev;
		prev->ikm_next = next;
	}
	/* XXX Temporary debug logic */
	assert(kmsg->ikm_next = IKM_BOGUS);
	assert(kmsg->ikm_prev = IKM_BOGUS);
}

/*
 *	Routine:	ipc_kmsg_queue_next
 *	Purpose:
 *		Return the kmsg following the given kmsg.
 *		(Or IKM_NULL if it is the last one in the queue.)
 */

ipc_kmsg_t
ipc_kmsg_queue_next(
	ipc_kmsg_queue_t	queue,
	ipc_kmsg_t		kmsg)
{
	ipc_kmsg_t next;

	assert(queue->ikmq_base != IKM_NULL);

	next = kmsg->ikm_next;
	if (queue->ikmq_base == next)
		next = IKM_NULL;

	return next;
}

/*
 *	Routine:	ipc_kmsg_destroy
 *	Purpose:
 *		Destroys a kernel message.  Releases all rights,
 *		references, and memory held by the message.
 *		Frees the message.
 *	Conditions:
 *		No locks held.
 */

void
ipc_kmsg_destroy(
	ipc_kmsg_t	kmsg)
{
	ipc_kmsg_queue_t queue;
	boolean_t empty;

	/*
	 *	ipc_kmsg_clean can cause more messages to be destroyed.
	 *	Curtail recursion by queueing messages.  If a message
	 *	is already queued, then this is a recursive call.
	 */

	queue = &(current_thread()->ith_messages);
	empty = ipc_kmsg_queue_empty(queue);
	ipc_kmsg_enqueue(queue, kmsg);

	if (empty) {
		/* must leave kmsg in queue while cleaning it */

		while ((kmsg = ipc_kmsg_queue_first(queue)) != IKM_NULL) {
			ipc_kmsg_clean(kmsg);
			ipc_kmsg_rmqueue(queue, kmsg);
			ipc_kmsg_free(kmsg);
		}
	}
}

/*
 *	Routine:	ipc_kmsg_destroy_dest
 *	Purpose:
 *		Destroys a kernel message.  Releases all rights,
 *		references, and memory held by the message (including
 *		the destination port reference.
 *		Frees the message.
 *	Conditions:
 *		No locks held.
 */
void
ipc_kmsg_destroy_dest(
	ipc_kmsg_t kmsg)
{
    ipc_port_t port;
	
    port = kmsg->ikm_header->msgh_remote_port;

    ipc_port_release(port);
    kmsg->ikm_header->msgh_remote_port = MACH_PORT_NULL;
    ipc_kmsg_destroy(kmsg);
}

/*
 *	Routine:	ipc_kmsg_clean_body
 *	Purpose:
 *		Cleans the body of a kernel message.
 *		Releases all rights, references, and memory.
 *
 *	Conditions:
 *		No locks held.
 */

void
ipc_kmsg_clean_body(
	__unused ipc_kmsg_t	kmsg,
	mach_msg_type_number_t	number,
	mach_msg_descriptor_t	*saddr)
{
    mach_msg_descriptor_t 	*eaddr;

    if ( number == 0 )
	return;

    eaddr = saddr + number;

    for ( ; saddr < eaddr; saddr++ ) {
	
	switch (saddr->type.type) {
	    
	    case MACH_MSG_PORT_DESCRIPTOR: {
		mach_msg_port_descriptor_t *dsc;

		dsc = &saddr->port;

		/* 
		 * Destroy port rights carried in the message 
		 */
		if (!IO_VALID((ipc_object_t) dsc->name))
		    continue;
		ipc_object_destroy((ipc_object_t) dsc->name, dsc->disposition);
		break;
	    }
	    case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
	    case MACH_MSG_OOL_DESCRIPTOR : {
		mach_msg_ool_descriptor_t *dsc;

		dsc = &saddr->out_of_line;
		
		/* 
		 * Destroy memory carried in the message 
		 */
		if (dsc->size == 0) {
			assert(dsc->address == (void *) 0);
		} else {
		    	vm_map_copy_discard((vm_map_copy_t) dsc->address);
		}
		break;
	    }
	    case MACH_MSG_OOL_PORTS_DESCRIPTOR : {
		ipc_object_t             	*objects;
		mach_msg_type_number_t   	j;
		mach_msg_ool_ports_descriptor_t	*dsc;

		dsc = &saddr->ool_ports;
		objects = (ipc_object_t *) dsc->address;

		if (dsc->count == 0) {
			break;
		}

		assert(objects != (ipc_object_t *) 0);
		
		/* destroy port rights carried in the message */
		
		for (j = 0; j < dsc->count; j++) {
		    ipc_object_t object = objects[j];
		    
		    if (!IO_VALID(object))
			continue;
		    
		    ipc_object_destroy(object, dsc->disposition);
		}

		/* destroy memory carried in the message */

		assert(dsc->count != 0);

		kfree(dsc->address, 
		     (vm_size_t) dsc->count * sizeof(mach_port_name_t));
		break;
	    }
	    default : {
		printf("cleanup: don't understand this type of descriptor\n");
	    }
	}
    }
}

/*
 *	Routine:	ipc_kmsg_clean_partial
 *	Purpose:
 *		Cleans a partially-acquired kernel message.
 *		number is the index of the type descriptor
 *		in the body of the message that contained the error.
 *		If dolast, the memory and port rights in this last
 *		type spec are also cleaned.  In that case, number
 *		specifies the number of port rights to clean.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_kmsg_clean_partial(
	ipc_kmsg_t		kmsg,
	mach_msg_type_number_t	number,
	mach_msg_descriptor_t	*desc,
	vm_offset_t		paddr,
	vm_size_t		length)
{
	ipc_object_t object;
	mach_msg_bits_t mbits = kmsg->ikm_header->msgh_bits;

	object = (ipc_object_t) kmsg->ikm_header->msgh_remote_port;
	assert(IO_VALID(object));
	ipc_object_destroy(object, MACH_MSGH_BITS_REMOTE(mbits));

	object = (ipc_object_t) kmsg->ikm_header->msgh_local_port;
	if (IO_VALID(object))
		ipc_object_destroy(object, MACH_MSGH_BITS_LOCAL(mbits));

	if (paddr) {
		(void) vm_deallocate(ipc_kernel_copy_map, paddr, length);
	}

	ipc_kmsg_clean_body(kmsg, number, desc);
}

/*
 *	Routine:	ipc_kmsg_clean
 *	Purpose:
 *		Cleans a kernel message.  Releases all rights,
 *		references, and memory held by the message.
 *	Conditions:
 *		No locks held.
 */

void
ipc_kmsg_clean(
	ipc_kmsg_t	kmsg)
{
	ipc_object_t object;
	mach_msg_bits_t mbits;

	mbits = kmsg->ikm_header->msgh_bits;
	object = (ipc_object_t) kmsg->ikm_header->msgh_remote_port;
	if (IO_VALID(object))
		ipc_object_destroy(object, MACH_MSGH_BITS_REMOTE(mbits));

	object = (ipc_object_t) kmsg->ikm_header->msgh_local_port;
	if (IO_VALID(object))
		ipc_object_destroy(object, MACH_MSGH_BITS_LOCAL(mbits));

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_body_t *body;

		body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
		ipc_kmsg_clean_body(kmsg, body->msgh_descriptor_count,
				    (mach_msg_descriptor_t *)(body + 1));
	}
}

/*
 *	Routine:	ipc_kmsg_set_prealloc
 *	Purpose:
 *		Assign a kmsg as a preallocated message buffer to a port.
 *	Conditions:
 *		port locked.
 */

void
ipc_kmsg_set_prealloc(
	ipc_kmsg_t		kmsg,
	ipc_port_t		port)
{
	assert(kmsg->ikm_prealloc == IP_NULL);
  
	kmsg->ikm_prealloc = IP_NULL;
	IP_SET_PREALLOC(port, kmsg);
}

/*
 *	Routine:	ipc_kmsg_clear_prealloc
 *	Purpose:
 *		Release the Assignment of a preallocated message buffer from a port.
 *	Conditions:
 *		port locked.
 */
void
ipc_kmsg_clear_prealloc(
	ipc_kmsg_t		kmsg,
	ipc_port_t		port)
{
	assert(kmsg->ikm_prealloc == port);
  
	kmsg->ikm_prealloc = IP_NULL;
	IP_CLEAR_PREALLOC(port, kmsg);
}



/*
 *	Routine:	ipc_kmsg_get
 *	Purpose:
 *		Allocates a kernel message buffer.
 *		Copies a user message to the message buffer.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Acquired a message buffer.
 *		MACH_SEND_MSG_TOO_SMALL	Message smaller than a header.
 *		MACH_SEND_MSG_TOO_SMALL	Message size not long-word multiple.
 *		MACH_SEND_NO_BUFFER	Couldn't allocate a message buffer.
 *		MACH_SEND_INVALID_DATA	Couldn't copy message data.
 */

mach_msg_return_t
ipc_kmsg_get(
	mach_vm_address_t	msg_addr,
	mach_msg_size_t	size,
	ipc_kmsg_t		*kmsgp)
{
	mach_msg_size_t			msg_and_trailer_size;
	ipc_kmsg_t 			kmsg;
	mach_msg_max_trailer_t	 	*trailer;

	if ((size < sizeof(mach_msg_header_t)) || (size & 3))
		return MACH_SEND_MSG_TOO_SMALL;

	msg_and_trailer_size = size + MAX_TRAILER_SIZE;

	kmsg = ipc_kmsg_alloc(msg_and_trailer_size);

	if (kmsg == IKM_NULL)
		return MACH_SEND_NO_BUFFER;

	if (copyinmsg(msg_addr, (char *) kmsg->ikm_header, size)) {
		ipc_kmsg_free(kmsg);
		return MACH_SEND_INVALID_DATA;
	}

	kmsg->ikm_header->msgh_size = size;

	/* 
	 * I reserve for the trailer the largest space (MAX_TRAILER_SIZE)
	 * However, the internal size field of the trailer (msgh_trailer_size)
	 * is initialized to the minimum (sizeof(mach_msg_trailer_t)), to optimize
	 * the cases where no implicit data is requested.
	 */
	trailer = (mach_msg_max_trailer_t *) ((vm_offset_t)kmsg->ikm_header + size);
	trailer->msgh_sender = current_thread()->task->sec_token;
	trailer->msgh_audit = current_thread()->task->audit_token;
	trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
	trailer->msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE;
	
#ifdef ppc
	if(trcWork.traceMask) dbgTrace(0x1100, (unsigned int)kmsg->ikm_header->msgh_id, 
		(unsigned int)kmsg->ikm_header->msgh_remote_port, 
		(unsigned int)kmsg->ikm_header->msgh_local_port, 0); 
#endif
	*kmsgp = kmsg;
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_get_from_kernel
 *	Purpose:
 *		First checks for a preallocated message
 *		reserved for kernel clients.  If not found -
 *		allocates a new kernel message buffer.
 *		Copies a kernel message to the message buffer.
 *		Only resource errors are allowed.
 *	Conditions:
 *		Nothing locked.
 *		Ports in header are ipc_port_t.
 *	Returns:
 *		MACH_MSG_SUCCESS	Acquired a message buffer.
 *		MACH_SEND_NO_BUFFER	Couldn't allocate a message buffer.
 */

mach_msg_return_t
ipc_kmsg_get_from_kernel(
	mach_msg_header_t	*msg,
	mach_msg_size_t	size,
	ipc_kmsg_t		*kmsgp)
{
	ipc_kmsg_t 	kmsg;
	mach_msg_size_t	msg_and_trailer_size;
	mach_msg_max_trailer_t *trailer;
	ipc_port_t	dest_port;

	assert(size >= sizeof(mach_msg_header_t));
//	assert((size & 3) == 0);

	assert(IP_VALID((ipc_port_t) msg->msgh_remote_port));
	dest_port = (ipc_port_t)msg->msgh_remote_port;

	msg_and_trailer_size = size + MAX_TRAILER_SIZE;

	/*
	 * See if the port has a pre-allocated kmsg for kernel
	 * clients.  These are set up for those kernel clients
	 * which cannot afford to wait.
	 */
	if (IP_PREALLOC(dest_port)) {
		ip_lock(dest_port);
		if (!ip_active(dest_port)) {
			ip_unlock(dest_port);
			return MACH_SEND_NO_BUFFER;
		}
		assert(IP_PREALLOC(dest_port));
		kmsg = dest_port->ip_premsg;
		if (msg_and_trailer_size > kmsg->ikm_size) {
			ip_unlock(dest_port);
			return MACH_SEND_TOO_LARGE;
		}
		if (ikm_prealloc_inuse(kmsg)) {
			ip_unlock(dest_port);
			return MACH_SEND_NO_BUFFER;
		}
		ikm_prealloc_set_inuse(kmsg, dest_port);
		ip_unlock(dest_port);
	} else {
		kmsg = ipc_kmsg_alloc(msg_and_trailer_size);
		if (kmsg == IKM_NULL)
			return MACH_SEND_NO_BUFFER;
	}

	(void) memcpy((void *) kmsg->ikm_header, (const void *) msg, size);

	kmsg->ikm_header->msgh_size = size;

	/* 
	 * I reserve for the trailer the largest space (MAX_TRAILER_SIZE)
	 * However, the internal size field of the trailer (msgh_trailer_size)
	 * is initialized to the minimum (sizeof(mach_msg_trailer_t)), to
	 * optimize the cases where no implicit data is requested.
	 */
	trailer = (mach_msg_max_trailer_t *) 
	          ((vm_offset_t)kmsg->ikm_header + size);
	trailer->msgh_sender = KERNEL_SECURITY_TOKEN;
	trailer->msgh_audit = KERNEL_AUDIT_TOKEN;
	trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
	trailer->msgh_trailer_size = MACH_MSG_TRAILER_MINIMUM_SIZE;

	*kmsgp = kmsg;
	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_send
 *	Purpose:
 *		Send a message.  The message holds a reference
 *		for the destination port in the msgh_remote_port field.
 *
 *		If unsuccessful, the caller still has possession of
 *		the message and must do something with it.  If successful,
 *		the message is queued, given to a receiver, destroyed,
 *		or handled directly by the kernel via mach_msg.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	The message was accepted.
 *		MACH_SEND_TIMED_OUT	Caller still has message.
 *		MACH_SEND_INTERRUPTED	Caller still has message.
 */
mach_msg_return_t
ipc_kmsg_send(
	ipc_kmsg_t		kmsg,
	mach_msg_option_t	option,
	mach_msg_timeout_t	send_timeout)
{
	ipc_port_t port;

	port = (ipc_port_t) kmsg->ikm_header->msgh_remote_port;
	assert(IP_VALID(port));

	ip_lock(port);

	if (port->ip_receiver == ipc_space_kernel) {

		/*
		 *	We can check ip_receiver == ipc_space_kernel
		 *	before checking that the port is active because
		 *	ipc_port_dealloc_kernel clears ip_receiver
		 *	before destroying a kernel port.
		 */
		assert(ip_active(port));
		port->ip_messages.imq_seqno++;
		ip_unlock(port);

		current_task()->messages_sent++;

		/*
		 * Call the server routine, and get the reply message to send.
		 */
		kmsg = ipc_kobject_server(kmsg);
		if (kmsg == IKM_NULL)
			return MACH_MSG_SUCCESS;

		port = (ipc_port_t) kmsg->ikm_header->msgh_remote_port;
		assert(IP_VALID(port));
		ip_lock(port);
		/* fall thru with reply - same options */
	}

	/*
	 *	Can't deliver to a dead port.
	 *	However, we can pretend it got sent
	 *	and was then immediately destroyed.
	 */
	if (!ip_active(port)) {
		/*
		 *	We can't let ipc_kmsg_destroy deallocate
		 *	the port right, because we might end up
		 *	in an infinite loop trying to deliver
		 *	a send-once notification.
		 */

		ip_release(port);
		ip_check_unlock(port);
		kmsg->ikm_header->msgh_remote_port = MACH_PORT_NULL;
		ipc_kmsg_destroy(kmsg);
		return MACH_MSG_SUCCESS;
	}

	if (kmsg->ikm_header->msgh_bits & MACH_MSGH_BITS_CIRCULAR) {
		ip_unlock(port);

		/* don't allow the creation of a circular loop */

		ipc_kmsg_destroy(kmsg);
		return MACH_MSG_SUCCESS;
	}

	/*
	 * We have a valid message and a valid reference on the port.
	 * we can unlock the port and call mqueue_send() on it's message
	 * queue.
	 */
	ip_unlock(port);
	return (ipc_mqueue_send(&port->ip_messages, kmsg, option, send_timeout));
}

/*
 *	Routine:	ipc_kmsg_put
 *	Purpose:
 *		Copies a message buffer to a user message.
 *		Copies only the specified number of bytes.
 *		Frees the message buffer.
 *	Conditions:
 *		Nothing locked.  The message buffer must have clean
 *		header fields.
 *	Returns:
 *		MACH_MSG_SUCCESS	Copied data out of message buffer.
 *		MACH_RCV_INVALID_DATA	Couldn't copy to user message.
 */

mach_msg_return_t
ipc_kmsg_put(
	mach_vm_address_t	msg_addr,
	ipc_kmsg_t		kmsg,
	mach_msg_size_t		size)
{
	mach_msg_return_t mr;

	if (copyoutmsg((const char *) kmsg->ikm_header, msg_addr, size))
		mr = MACH_RCV_INVALID_DATA;
	else
		mr = MACH_MSG_SUCCESS;

	ipc_kmsg_free(kmsg);
	return mr;
}

/*
 *	Routine:	ipc_kmsg_put_to_kernel
 *	Purpose:
 *		Copies a message buffer to a kernel message.
 *		Frees the message buffer.
 *		No errors allowed.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_kmsg_put_to_kernel(
	mach_msg_header_t	*msg,
	ipc_kmsg_t		kmsg,
	mach_msg_size_t		size)
{
	(void) memcpy((void *) msg, (const void *) kmsg->ikm_header, size);

	ipc_kmsg_free(kmsg);
}

/*
 *	Routine:	ipc_kmsg_copyin_header
 *	Purpose:
 *		"Copy-in" port rights in the header of a message.
 *		Operates atomically; if it doesn't succeed the
 *		message header and the space are left untouched.
 *		If it does succeed the remote/local port fields
 *		contain object pointers instead of port names,
 *		and the bits field is updated.  The destination port
 *		will be a valid port pointer.
 *
 *		The notify argument implements the MACH_SEND_CANCEL option.
 *		If it is not MACH_PORT_NULL, it should name a receive right.
 *		If the processing of the destination port would generate
 *		a port-deleted notification (because the right for the
 *		destination port is destroyed and it had a request for
 *		a dead-name notification registered), and the port-deleted
 *		notification would be sent to the named receive right,
 *		then it isn't sent and the send-once right for the notify
 *		port is quietly destroyed.
 *
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyin.
 *		MACH_SEND_INVALID_HEADER
 *			Illegal value in the message header bits.
 *		MACH_SEND_INVALID_DEST	The space is dead.
 *		MACH_SEND_INVALID_NOTIFY
 *			Notify is non-null and doesn't name a receive right.
 *			(Either KERN_INVALID_NAME or KERN_INVALID_RIGHT.)
 *		MACH_SEND_INVALID_DEST	Can't copyin destination port.
 *			(Either KERN_INVALID_NAME or KERN_INVALID_RIGHT.)
 *		MACH_SEND_INVALID_REPLY	Can't copyin reply port.
 *			(Either KERN_INVALID_NAME or KERN_INVALID_RIGHT.)
 */

mach_msg_return_t
ipc_kmsg_copyin_header(
	mach_msg_header_t	*msg,
	ipc_space_t		space,
	mach_port_name_t	notify)
{
	mach_msg_bits_t mbits = msg->msgh_bits & MACH_MSGH_BITS_USER;
	mach_port_name_t dest_name = (mach_port_name_t)msg->msgh_remote_port;
	mach_port_name_t reply_name = (mach_port_name_t)msg->msgh_local_port;
	kern_return_t kr;

	mach_msg_type_name_t dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	mach_msg_type_name_t reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	ipc_object_t dest_port, reply_port;
	ipc_port_t dest_soright, reply_soright;
	ipc_port_t notify_port;

	if ((mbits != msg->msgh_bits) ||
	    (!MACH_MSG_TYPE_PORT_ANY_SEND(dest_type)) ||
	    ((reply_type == 0) ?
	     (reply_name != MACH_PORT_NULL) :
	     !MACH_MSG_TYPE_PORT_ANY_SEND(reply_type)))
		return MACH_SEND_INVALID_HEADER;

	reply_soright = IP_NULL; /* in case we go to invalid dest early */

	is_write_lock(space);
	if (!space->is_active)
		goto invalid_dest;

	if (!MACH_PORT_VALID(dest_name))
		goto invalid_dest;

	if (notify != MACH_PORT_NULL) {
		ipc_entry_t entry;

		if ((entry = ipc_entry_lookup(space, notify)) == IE_NULL) {
			is_write_unlock(space);
			return MACH_SEND_INVALID_NOTIFY;
		}
		if((entry->ie_bits & MACH_PORT_TYPE_RECEIVE) == 0) {
			is_write_unlock(space);
			return MACH_SEND_INVALID_NOTIFY;
		}

		notify_port = (ipc_port_t) entry->ie_object;
	} else
		notify_port = IP_NULL;

	if (dest_name == reply_name) {
		ipc_entry_t entry;
		mach_port_name_t name = dest_name;

		/*
		 *	Destination and reply ports are the same!
		 *	This is a little tedious to make atomic, because
		 *	there are 25 combinations of dest_type/reply_type.
		 *	However, most are easy.  If either is move-sonce,
		 *	then there must be an error.  If either are
		 *	make-send or make-sonce, then we must be looking
		 *	at a receive right so the port can't die.
		 *	The hard cases are the combinations of
		 *	copy-send and make-send.
		 */

		entry = ipc_entry_lookup(space, name);
		if (entry == IE_NULL)
			goto invalid_dest;

		assert(reply_type != 0); /* because name not null */

		if (!ipc_right_copyin_check(space, name, entry, reply_type))
			goto invalid_reply;

		if ((dest_type == MACH_MSG_TYPE_MOVE_SEND_ONCE) ||
		    (reply_type == MACH_MSG_TYPE_MOVE_SEND_ONCE)) {
			/*
			 *	Why must there be an error?  To get a valid
			 *	destination, this entry must name a live
			 *	port (not a dead name or dead port).  However
			 *	a successful move-sonce will destroy a
			 *	live entry.  Therefore the other copyin,
			 *	whatever it is, would fail.  We've already
			 *	checked for reply port errors above,
			 *	so report a destination error.
			 */

			goto invalid_dest;
		} else if ((dest_type == MACH_MSG_TYPE_MAKE_SEND) ||
			   (dest_type == MACH_MSG_TYPE_MAKE_SEND_ONCE) ||
			   (reply_type == MACH_MSG_TYPE_MAKE_SEND) ||
			   (reply_type == MACH_MSG_TYPE_MAKE_SEND_ONCE)) {
			kr = ipc_right_copyin(space, name, entry,
					      dest_type, FALSE,
					      &dest_port, &dest_soright);
			if (kr != KERN_SUCCESS)
				goto invalid_dest;

			/*
			 *	Either dest or reply needs a receive right.
			 *	We know the receive right is there, because
			 *	of the copyin_check and copyin calls.  Hence
			 *	the port is not in danger of dying.  If dest
			 *	used the receive right, then the right needed
			 *	by reply (and verified by copyin_check) will
			 *	still be there.
			 */

			assert(IO_VALID(dest_port));
			assert(entry->ie_bits & MACH_PORT_TYPE_RECEIVE);
			assert(dest_soright == IP_NULL);

			kr = ipc_right_copyin(space, name, entry,
					      reply_type, TRUE,
					      &reply_port, &reply_soright);

			assert(kr == KERN_SUCCESS);
			assert(reply_port == dest_port);
			assert(entry->ie_bits & MACH_PORT_TYPE_RECEIVE);
			assert(reply_soright == IP_NULL);
		} else if ((dest_type == MACH_MSG_TYPE_COPY_SEND) &&
			   (reply_type == MACH_MSG_TYPE_COPY_SEND)) {
			/*
			 *	To make this atomic, just do one copy-send,
			 *	and dup the send right we get out.
			 */

			kr = ipc_right_copyin(space, name, entry,
					      dest_type, FALSE,
					      &dest_port, &dest_soright);
			if (kr != KERN_SUCCESS)
				goto invalid_dest;

			assert(entry->ie_bits & MACH_PORT_TYPE_SEND);
			assert(dest_soright == IP_NULL);

			/*
			 *	It's OK if the port we got is dead now,
			 *	so reply_port is IP_DEAD, because the msg
			 *	won't go anywhere anyway.
			 */

			reply_port = (ipc_object_t)
				ipc_port_copy_send((ipc_port_t) dest_port);
			reply_soright = IP_NULL;
		} else if ((dest_type == MACH_MSG_TYPE_MOVE_SEND) &&
			   (reply_type == MACH_MSG_TYPE_MOVE_SEND)) {
			/*
			 *	This is an easy case.  Just use our
			 *	handy-dandy special-purpose copyin call
			 *	to get two send rights for the price of one.
			 */

			kr = ipc_right_copyin_two(space, name, entry,
						  &dest_port, &dest_soright);
			if (kr != KERN_SUCCESS)
				goto invalid_dest;

			/* the entry might need to be deallocated */
			if (IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE)
				ipc_entry_dealloc(space, name, entry);

			reply_port = dest_port;
			reply_soright = IP_NULL;
		} else {
			ipc_port_t soright;

			assert(((dest_type == MACH_MSG_TYPE_COPY_SEND) &&
				(reply_type == MACH_MSG_TYPE_MOVE_SEND)) ||
			       ((dest_type == MACH_MSG_TYPE_MOVE_SEND) &&
				(reply_type == MACH_MSG_TYPE_COPY_SEND)));

			/*
			 *	To make this atomic, just do a move-send,
			 *	and dup the send right we get out.
			 */

			kr = ipc_right_copyin(space, name, entry,
					      MACH_MSG_TYPE_MOVE_SEND, FALSE,
					      &dest_port, &soright);
			if (kr != KERN_SUCCESS)
				goto invalid_dest;

			/* the entry might need to be deallocated */

			if (IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE)
				ipc_entry_dealloc(space, name, entry);

			/*
			 *	It's OK if the port we got is dead now,
			 *	so reply_port is IP_DEAD, because the msg
			 *	won't go anywhere anyway.
			 */

			reply_port = (ipc_object_t)
				ipc_port_copy_send((ipc_port_t) dest_port);

			if (dest_type == MACH_MSG_TYPE_MOVE_SEND) {
				dest_soright = soright;
				reply_soright = IP_NULL;
			} else {
				dest_soright = IP_NULL;
				reply_soright = soright;
			}
		}
	} else if (!MACH_PORT_VALID(reply_name)) {
		ipc_entry_t entry;

		/*
		 *	No reply port!  This is an easy case
		 *	to make atomic.  Just copyin the destination.
		 */

		entry = ipc_entry_lookup(space, dest_name);
		if (entry == IE_NULL)
			goto invalid_dest;

		kr = ipc_right_copyin(space, dest_name, entry,
				      dest_type, FALSE,
				      &dest_port, &dest_soright);
		if (kr != KERN_SUCCESS)
			goto invalid_dest;

		/* the entry might need to be deallocated */

		if (IE_BITS_TYPE(entry->ie_bits) == MACH_PORT_TYPE_NONE)
			ipc_entry_dealloc(space, dest_name, entry);

		reply_port = (ipc_object_t) reply_name;
		reply_soright = IP_NULL;
	} else {
		ipc_entry_t dest_entry, reply_entry;

		/*
		 *	This is the tough case to make atomic.
		 *	The difficult problem is serializing with port death.
		 *	At the time we copyin dest_port, it must be alive.
		 *	If reply_port is alive when we copyin it, then
		 *	we are OK, because we serialize before the death
		 *	of both ports.  Assume reply_port is dead at copyin.
		 *	Then if dest_port dies/died after reply_port died,
		 *	we are OK, because we serialize between the death
		 *	of the two ports.  So the bad case is when dest_port
		 *	dies after its copyin, reply_port dies before its
		 *	copyin, and dest_port dies before reply_port.  Then
		 *	the copyins operated as if dest_port was alive
		 *	and reply_port was dead, which shouldn't have happened
		 *	because they died in the other order.
		 *
		 *	Note that it is easy for a user task to tell if
		 *	a copyin happened before or after a port died.
		 *	For example, suppose both dest and reply are
		 *	send-once rights (types are both move-sonce) and
		 *	both rights have dead-name requests registered.
		 *	If a port dies before copyin, a dead-name notification
		 *	is generated and the dead name's urefs are incremented,
		 *	and if the copyin happens first, a port-deleted
		 *	notification is generated.
		 *
		 *	Note that although the entries are different,
		 *	dest_port and reply_port might still be the same.
		 *
		 * JMM - The code to handle this was too expensive and, anyway,
		 * we intend to separate the dest lookup from the reply copyin
		 * by a wide margin, so the user will have to learn to deal!
		 * I will be making the change soon!
		 */

		dest_entry = ipc_entry_lookup(space, dest_name);
		if (dest_entry == IE_NULL)
			goto invalid_dest;

		reply_entry = ipc_entry_lookup(space, reply_name);
		if (reply_entry == IE_NULL)
			goto invalid_reply;

		assert(dest_entry != reply_entry); /* names are not equal */
		assert(reply_type != 0); /* because reply_name not null */

		if (!ipc_right_copyin_check(space, reply_name, reply_entry,
					    reply_type))
			goto invalid_reply;

		kr = ipc_right_copyin(space, dest_name, dest_entry,
				      dest_type, FALSE,
				      &dest_port, &dest_soright);
		if (kr != KERN_SUCCESS)
			goto invalid_dest;

		assert(IO_VALID(dest_port));

		kr = ipc_right_copyin(space, reply_name, reply_entry,
				      reply_type, TRUE,
				      &reply_port, &reply_soright);

		assert(kr == KERN_SUCCESS);

		/* the entries might need to be deallocated */

		if (IE_BITS_TYPE(reply_entry->ie_bits) == MACH_PORT_TYPE_NONE)
			ipc_entry_dealloc(space, reply_name, reply_entry);

		if (IE_BITS_TYPE(dest_entry->ie_bits) == MACH_PORT_TYPE_NONE)
			ipc_entry_dealloc(space, dest_name, dest_entry);
	}

	/*
	 *	At this point, dest_port, reply_port,
	 *	dest_soright, reply_soright are all initialized.
	 *	Any defunct entries have been deallocated.
	 *	The space is still write-locked, and we need to
	 *	make the MACH_SEND_CANCEL check.  The notify_port pointer
	 *	is still usable, because the copyin code above won't ever
	 *	deallocate a receive right, so its entry still exists
	 *	and holds a ref.  Note notify_port might even equal
	 *	dest_port or reply_port.
	 */

	if ((notify != MACH_PORT_NULL) &&
	    (dest_soright == notify_port)) {
		ipc_port_release_sonce(dest_soright);
		dest_soright = IP_NULL;
	}

	is_write_unlock(space);

	if (dest_soright != IP_NULL)
		ipc_notify_port_deleted(dest_soright, dest_name);

	if (reply_soright != IP_NULL)
		ipc_notify_port_deleted(reply_soright, reply_name);

	dest_type = ipc_object_copyin_type(dest_type);
	reply_type = ipc_object_copyin_type(reply_type);

	msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
			  MACH_MSGH_BITS(dest_type, reply_type));
	msg->msgh_remote_port = (ipc_port_t)dest_port;
	msg->msgh_local_port = (ipc_port_t)reply_port;

	return MACH_MSG_SUCCESS;

invalid_reply:
	is_write_unlock(space);
	return MACH_SEND_INVALID_REPLY;

invalid_dest:
	is_write_unlock(space);
	if (reply_soright != IP_NULL)
		ipc_notify_port_deleted(reply_soright, reply_name);
	return MACH_SEND_INVALID_DEST;
}

/*
 *	Routine:	ipc_kmsg_copyin_body
 *	Purpose:
 *		"Copy-in" port rights and out-of-line memory
 *		in the message body.
 *
 *		In all failure cases, the message is left holding
 *		no rights or memory.  However, the message buffer
 *		is not deallocated.  If successful, the message
 *		contains a valid destination port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyin.
 *		MACH_SEND_INVALID_MEMORY	Can't grab out-of-line memory.
 *		MACH_SEND_INVALID_RIGHT	Can't copyin port right in body.
 *		MACH_SEND_INVALID_TYPE	Bad type specification.
 *		MACH_SEND_MSG_TOO_SMALL	Body is too small for types/data.
 *		MACH_SEND_INVALID_RT_OOL_SIZE OOL Buffer too large for RT
 *		MACH_MSG_INVALID_RT_DESCRIPTOR Dealloc and RT are incompatible
 */

#define DESC_COUNT_SMALL 64

mach_msg_return_t
ipc_kmsg_copyin_body(
	ipc_kmsg_t	kmsg,
	ipc_space_t	space,
	vm_map_t	map)
{
    ipc_object_t       		dest;
    mach_msg_body_t		*body;
    mach_msg_descriptor_t	*daddr, *naddr;
    mach_msg_type_number_t	dsc_count;
    boolean_t			differs = MAP_SIZE_DIFFERS(map);
    boolean_t 			complex = FALSE;
    vm_size_t			space_needed = 0;
    vm_size_t			desc_size_space[DESC_COUNT_SMALL];
    vm_size_t			*user_desc_sizes = NULL;
    vm_offset_t			paddr = 0;
    vm_map_copy_t		copy = VM_MAP_COPY_NULL;
    kern_return_t		kr;
    mach_msg_type_number_t	i;
    mach_msg_return_t		mr = MACH_MSG_SUCCESS;
    
    /*
     * Determine if the target is a kernel port.
     */
    dest = (ipc_object_t) kmsg->ikm_header->msgh_remote_port;
    body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
    naddr = (mach_msg_descriptor_t *) (body + 1);

    dsc_count = body->msgh_descriptor_count;
    if (dsc_count == 0)
	return MACH_MSG_SUCCESS;

    if (differs) {
	user_desc_sizes = (dsc_count <= DESC_COUNT_SMALL) ?
	    &desc_size_space : kalloc(dsc_count * sizeof(vm_size_t));
	if (user_desc_sizes == NULL) {
	    ipc_kmsg_clean_partial(kmsg,0,0,0,0);
	    return KERN_RESOURCE_SHORTAGE;
	}
    }

    /*
     * Make an initial pass to determine kernal VM space requirements for
     * physical copies and possible contraction of the descriptors from
     * processes with pointers larger than the kernel's.
     */
    daddr = 0;
    for (i = 0; i < dsc_count; i++) {
	daddr = naddr;

	/* make sure the descriptor fits in the message */
	if (differs) {
	    switch (daddr->type.type) {
	    case MACH_MSG_OOL_DESCRIPTOR:
	    case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
	    case MACH_MSG_OOL_PORTS_DESCRIPTOR:
		user_desc_sizes[i] = sizeof(OTHER_OOL_DESCRIPTOR);
		break;
	    default:
		user_desc_sizes[i] = sizeof(*daddr);
		break;
	    }
	    naddr = (mach_msg_descriptor_t *)
		    ((vm_offset_t)daddr + user_desc_sizes[i]);
	} else {
	    naddr = daddr + 1;
	}

	if (naddr > (mach_msg_descriptor_t *)
	    ((vm_offset_t)kmsg->ikm_header + kmsg->ikm_header->msgh_size)) {
	    ipc_kmsg_clean_partial(kmsg,0,0,0,0);
	    mr = MACH_SEND_MSG_TOO_SMALL;
	    goto out;
	}

	switch (daddr->type.type) {
	    mach_msg_size_t size;

	case MACH_MSG_OOL_DESCRIPTOR:
	case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
	    size = (differs) ?
		((OTHER_OOL_DESCRIPTOR *)daddr)->size :
	    daddr->out_of_line.size;

	    if (daddr->out_of_line.copy != MACH_MSG_PHYSICAL_COPY &&
		daddr->out_of_line.copy != MACH_MSG_VIRTUAL_COPY) {
		/*
		 * Invalid copy option
		 */
		ipc_kmsg_clean_partial(kmsg,0,0,0,0);
		mr = MACH_SEND_INVALID_TYPE;
		goto out;
	    }
	    
	    if ((size >= MSG_OOL_SIZE_SMALL) &&
		(daddr->out_of_line.copy == MACH_MSG_PHYSICAL_COPY) &&
		!(daddr->out_of_line.deallocate)) {

		/*
		 * Out-of-line memory descriptor, accumulate kernel
		 * memory requirements
		 */
		space_needed += round_page(size);
		if (space_needed > ipc_kmsg_max_vm_space) {
		    
		    /*
		     * Per message kernel memory limit exceeded
		     */
		    ipc_kmsg_clean_partial(kmsg,0,0,0,0);
		    mr = MACH_MSG_VM_KERNEL;
		    goto out;
		}
	    }
	}
    }

    /*
     * Allocate space in the pageable kernel ipc copy map for all the
     * ool data that is to be physically copied.  Map is marked wait for
     * space.
     */
    if (space_needed) {
	if (vm_allocate(ipc_kernel_copy_map, &paddr, space_needed, VM_FLAGS_ANYWHERE) !=
	    KERN_SUCCESS) {
	    ipc_kmsg_clean_partial(kmsg,0,0,0,0);
		mr = MACH_MSG_VM_KERNEL;
		goto out;
	}
    }

    /* 
     * handle the OOL regions and port descriptors.
     * We process them in reverse order starting with the last one
     * scanned above.  That way, we can compact them up against
     * the message body (if the user-descriptor size is larger than
     * the kernel representation).
     */
    naddr -= 1;
    do {

	switch (daddr->type.type) {
	    
	    /* port descriptors are the same size everywhere, how nice */
	    case MACH_MSG_PORT_DESCRIPTOR: {
		mach_msg_type_name_t 		user_disp;
		mach_msg_type_name_t		result_disp;
		mach_port_name_t		name;
		ipc_object_t 			object;
		volatile mach_msg_port_descriptor_t 	*dsc;
		volatile mach_msg_port_descriptor_t	*user_dsc;
		
		user_dsc = &daddr->port;
		dsc = &naddr->port;
		
		user_disp = user_dsc->disposition;
		result_disp = ipc_object_copyin_type(user_disp);
		
		name = (mach_port_name_t)user_dsc->name;
		if (MACH_PORT_VALID(name)) {

		    kr = ipc_object_copyin(space, name, user_disp, &object);
		    if (kr != KERN_SUCCESS) {
			mr = MACH_SEND_INVALID_RIGHT;
			break;
		    }

		    if ((result_disp == MACH_MSG_TYPE_PORT_RECEIVE) &&
			ipc_port_check_circularity((ipc_port_t) object,
						   (ipc_port_t) dest)) {
			kmsg->ikm_header->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
		    }
		    dsc->name = (ipc_port_t) object;
		} else {
		    dsc->name = (mach_port_t)name;
		}
		dsc->disposition = result_disp;
		dsc->type = MACH_MSG_PORT_DESCRIPTOR;
		complex = TRUE;
		break;
	    }

	    /* out of line descriptors differ in size between 32 and 64 bit processes */
	    case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
	    case MACH_MSG_OOL_DESCRIPTOR: {
		vm_size_t            		length;
		boolean_t            		dealloc;
		mach_msg_copy_options_t		copy_options;
		mach_vm_offset_t		addr;
		mach_msg_descriptor_type_t	dsc_type;

		volatile mach_msg_ool_descriptor_t	*dsc;

		if (differs) {
		    volatile OTHER_OOL_DESCRIPTOR	*user_dsc;

		    user_dsc = (OTHER_OOL_DESCRIPTOR *)&daddr->out_of_line;
		    addr = (mach_vm_offset_t) user_dsc->address;
		    length = user_dsc->size;
		    dealloc = user_dsc->deallocate;
		    copy_options = user_dsc->copy;
		    dsc_type = user_dsc->type;
		} else {
		    volatile mach_msg_ool_descriptor_t 	*user_dsc;
		
		    user_dsc = &daddr->out_of_line;
		    addr = CAST_USER_ADDR_T(user_dsc->address);
		    dealloc = user_dsc->deallocate;
		    copy_options = user_dsc->copy;
		    dsc_type = user_dsc->type;
		    length = user_dsc->size;
		}

		dsc = &naddr->out_of_line;
		dsc->size = length;
		dsc->deallocate = dealloc;
		dsc->copy = copy_options;
		dsc->type = dsc_type;

		if (length == 0) {
		    dsc->address = 0;
		} else if ((length >= MSG_OOL_SIZE_SMALL) &&
			   (copy_options == MACH_MSG_PHYSICAL_COPY) && !dealloc) {

		        /*
		         * If the request is a physical copy and the source
		         * is not being deallocated, then allocate space
		         * in the kernel's pageable ipc copy map and copy
		         * the data in.  The semantics guarantee that the
			 * data will have been physically copied before
			 * the send operation terminates.  Thus if the data
			 * is not being deallocated, we must be prepared
			 * to page if the region is sufficiently large.
		         */
		     	if (copyin(addr, (char *) paddr, length)) {
			        mr = MACH_SEND_INVALID_MEMORY;
				break;
		        }	

			/*
			 * The kernel ipc copy map is marked no_zero_fill.
			 * If the transfer is not a page multiple, we need
			 * to zero fill the balance.
			 */
			if (!page_aligned(length)) {
				(void) memset((void *) (paddr + length), 0,
					round_page(length) - length);
			}
			if (vm_map_copyin(ipc_kernel_copy_map, (vm_map_address_t)paddr,
					  (vm_map_size_t)length, TRUE, &copy) != KERN_SUCCESS) {
			    mr = MACH_MSG_VM_KERNEL;
			    break;
		        }
			dsc->address = (void *) copy;
			paddr += round_page(length);
			space_needed -= round_page(length);
		} else {

			/*
			 * Make a vm_map_copy_t of the of the data.  If the
			 * data is small, this will do an optimized physical
			 * copy.  Otherwise, it will do a virtual copy.
			 *
			 * NOTE: A virtual copy is OK if the original is being
			 * deallocted, even if a physical copy was requested.
			 */
		        kr = vm_map_copyin(map, addr, 
					   (vm_map_size_t)length, dealloc, &copy);
			if (kr != KERN_SUCCESS) {
			    mr = (kr == KERN_RESOURCE_SHORTAGE) ?
			           MACH_MSG_VM_KERNEL :
			           MACH_SEND_INVALID_MEMORY;
			    break;
		        }
			dsc->address = (void *) copy;
		}
		complex = TRUE;
		break;
	    }
	    case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
		vm_size_t 				length;
		void					*data;
		ipc_object_t            		*objects;
		unsigned int				j;
		mach_vm_offset_t             		addr;
		mach_msg_type_name_t    		user_disp;
		mach_msg_type_name_t    		result_disp;
		mach_msg_type_number_t			count;
		mach_msg_copy_options_t			copy_option;
		boolean_t				deallocate;

		volatile mach_msg_ool_ports_descriptor_t 	*dsc;

		if (differs) {
		    volatile OTHER_OOL_PORTS_DESCRIPTOR		*user_dsc;
		    
		    user_dsc = (OTHER_OOL_PORTS_DESCRIPTOR *)&daddr->ool_ports;
		    addr = (mach_vm_offset_t)user_dsc->address;
		    count = user_dsc->count;
		    deallocate = user_dsc->deallocate;
		    copy_option = user_dsc->copy;
		    user_disp = user_dsc->disposition;
		} else {
		    volatile mach_msg_ool_ports_descriptor_t	*user_dsc;

		    user_dsc = &daddr->ool_ports;
		    addr = CAST_USER_ADDR_T(user_dsc->address);
		    count = user_dsc->count;
		    deallocate = user_dsc->deallocate;
		    copy_option = user_dsc->copy;
		    user_disp = user_dsc->disposition;
		}

		dsc = &naddr->ool_ports;
		dsc->deallocate = deallocate;
		dsc->copy = copy_option;
		dsc->type = daddr->type.type;
		dsc->count = count;

		/* calculate length of data in bytes, rounding up */
		length = count * sizeof(mach_port_name_t);
		
		if (length == 0) {
		    complex = TRUE;
		    dsc->address = (void *) 0;
		    break;
		}

		data = kalloc(length);

		if (data == NULL) {
		    mr = MACH_SEND_NO_BUFFER;
		    break;
		}
		
		if (copyinmap(map, addr, data, length) != KERN_SUCCESS) {
		    kfree(data, length);
		    mr = MACH_SEND_INVALID_MEMORY;
		    break;
		}

		if (deallocate) {
		    (void) mach_vm_deallocate(map, addr, (mach_vm_size_t)length);
		}
		
		dsc->address = data;
		
		result_disp = ipc_object_copyin_type(user_disp);
		dsc->disposition = result_disp;

		objects = (ipc_object_t *) data;
		
		for ( j = 0; j < count; j++) {
		    mach_port_name_t port = (mach_port_name_t) objects[j];
		    ipc_object_t object;
		    
		    if (!MACH_PORT_VALID(port))
			continue;
		    
		    kr = ipc_object_copyin(space, port, user_disp, &object);

		    if (kr != KERN_SUCCESS) {
			unsigned int k;

			for(k = 0; k < j; k++) {
			    object = objects[k];
		    	    if (IPC_OBJECT_VALID(object))
		    	    	ipc_object_destroy(object, result_disp);
			}
			kfree(data, length);
			mr = MACH_SEND_INVALID_RIGHT;
			break;
		    }
		    
		    if ((dsc->disposition == MACH_MSG_TYPE_PORT_RECEIVE) &&
			ipc_port_check_circularity(
						   (ipc_port_t) object,
						   (ipc_port_t) dest))
			kmsg->ikm_header->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
		    
		    objects[j] = object;
		}
		
		complex = TRUE;
		break;
	    }
	    default: {
		/*
		 * Invalid descriptor
		 */
		mr = MACH_SEND_INVALID_TYPE;
		break;
	    }
	}

	if (MACH_MSG_SUCCESS != mr) {
	    ipc_kmsg_clean_partial(kmsg, dsc_count - i,
				   naddr + 1, paddr, space_needed);
	    goto out;
	}

    } while (--i > 0
	     && 
	     (daddr = (differs) ? (mach_msg_descriptor_t *)((vm_offset_t)(daddr) -
				  user_desc_sizes[i - 1]) : daddr - 1)
	     &&
	     naddr--);
    
    if (!complex) {
	kmsg->ikm_header->msgh_bits &= ~MACH_MSGH_BITS_COMPLEX;
    }

    if (differs && naddr != daddr) {
	mach_msg_base_t *old_base = (mach_msg_base_t *)kmsg->ikm_header;
	mach_msg_base_t *new_base = (mach_msg_base_t *)naddr - 1;

	memmove(new_base, old_base, sizeof(mach_msg_base_t));
	new_base->header.msgh_size -= (vm_offset_t)naddr - (vm_offset_t)daddr;
	kmsg->ikm_header = &new_base->header;
    }

 out:
    if (differs && dsc_count > DESC_COUNT_SMALL)
	kfree(user_desc_sizes, body->msgh_descriptor_count * sizeof(vm_size_t));

    return mr;
}


/*
 *	Routine:	ipc_kmsg_copyin
 *	Purpose:
 *		"Copy-in" port rights and out-of-line memory
 *		in the message.
 *
 *		In all failure cases, the message is left holding
 *		no rights or memory.  However, the message buffer
 *		is not deallocated.  If successful, the message
 *		contains a valid destination port.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyin.
 *		MACH_SEND_INVALID_HEADER
 *			Illegal value in the message header bits.
 *		MACH_SEND_INVALID_NOTIFY	Bad notify port.
 *		MACH_SEND_INVALID_DEST	Can't copyin destination port.
 *		MACH_SEND_INVALID_REPLY	Can't copyin reply port.
 *		MACH_SEND_INVALID_MEMORY	Can't grab out-of-line memory.
 *		MACH_SEND_INVALID_RIGHT	Can't copyin port right in body.
 *		MACH_SEND_INVALID_TYPE	Bad type specification.
 *		MACH_SEND_MSG_TOO_SMALL	Body is too small for types/data.
 */

mach_msg_return_t
ipc_kmsg_copyin(
	ipc_kmsg_t		kmsg,
	ipc_space_t		space,
	vm_map_t		map,
	mach_port_name_t	notify)
{
    mach_msg_return_t 		mr;
    
    mr = ipc_kmsg_copyin_header(kmsg->ikm_header, space, notify);
    if (mr != MACH_MSG_SUCCESS)
	return mr;
    
    if ((kmsg->ikm_header->msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0)
	return MACH_MSG_SUCCESS;
    
    return( ipc_kmsg_copyin_body( kmsg, space, map) );
}

/*
 *	Routine:	ipc_kmsg_copyin_from_kernel
 *	Purpose:
 *		"Copy-in" port rights and out-of-line memory
 *		in a message sent from the kernel.
 *
 *		Because the message comes from the kernel,
 *		the implementation assumes there are no errors
 *		or peculiarities in the message.
 *
 *		Returns TRUE if queueing the message
 *		would result in a circularity.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_kmsg_copyin_from_kernel(
	ipc_kmsg_t	kmsg)
{
	mach_msg_bits_t bits = kmsg->ikm_header->msgh_bits;
	mach_msg_type_name_t rname = MACH_MSGH_BITS_REMOTE(bits);
	mach_msg_type_name_t lname = MACH_MSGH_BITS_LOCAL(bits);
	ipc_object_t remote = (ipc_object_t) kmsg->ikm_header->msgh_remote_port;
	ipc_object_t local = (ipc_object_t) kmsg->ikm_header->msgh_local_port;

	/* translate the destination and reply ports */

	ipc_object_copyin_from_kernel(remote, rname);
	if (IO_VALID(local))
		ipc_object_copyin_from_kernel(local, lname);

	/*
	 *	The common case is a complex message with no reply port,
	 *	because that is what the memory_object interface uses.
	 */

	if (bits == (MACH_MSGH_BITS_COMPLEX |
		     MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0))) {
		bits = (MACH_MSGH_BITS_COMPLEX |
			MACH_MSGH_BITS(MACH_MSG_TYPE_PORT_SEND, 0));

		kmsg->ikm_header->msgh_bits = bits;
	} else {
		bits = (MACH_MSGH_BITS_OTHER(bits) |
			MACH_MSGH_BITS(ipc_object_copyin_type(rname),
				       ipc_object_copyin_type(lname)));

		kmsg->ikm_header->msgh_bits = bits;
		if ((bits & MACH_MSGH_BITS_COMPLEX) == 0)
			return;
	}
    {
    	mach_msg_descriptor_t	*saddr, *eaddr;
    	mach_msg_body_t		*body;

    	body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
    	saddr = (mach_msg_descriptor_t *) (body + 1);
    	eaddr = (mach_msg_descriptor_t *) saddr + body->msgh_descriptor_count;

    	for ( ; saddr <  eaddr; saddr++) {

	    switch (saddr->type.type) {
	    
	        case MACH_MSG_PORT_DESCRIPTOR: {
		    mach_msg_type_name_t 	name;
		    ipc_object_t 		object;
		    mach_msg_port_descriptor_t 	*dsc;
		
		    dsc = &saddr->port;
		
		    /* this is really the type SEND, SEND_ONCE, etc. */
		    name = dsc->disposition;
		    object = (ipc_object_t) dsc->name;
		    dsc->disposition = ipc_object_copyin_type(name);
		
		    if (!IO_VALID(object)) {
		        break;
		    }

		    ipc_object_copyin_from_kernel(object, name);
		    
		    /* CDY avoid circularity when the destination is also */
		    /* the kernel.  This check should be changed into an  */
		    /* assert when the new kobject model is in place since*/
		    /* ports will not be used in kernel to kernel chats   */
			
		    if (((ipc_port_t)remote)->ip_receiver != ipc_space_kernel) {
		       if ((dsc->disposition == MACH_MSG_TYPE_PORT_RECEIVE) &&
		           ipc_port_check_circularity((ipc_port_t) object, 
						(ipc_port_t) remote)) {
		           kmsg->ikm_header->msgh_bits |= 
					MACH_MSGH_BITS_CIRCULAR;
		       }
		    }
		    break;
	        }
		case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
	        case MACH_MSG_OOL_DESCRIPTOR: {
		    /*
		     * The sender should supply ready-made memory, i.e.
		     * a vm_map_copy_t, so we don't need to do anything.
		     */
		    break;
	        }
	        case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
		    ipc_object_t            		*objects;
		    unsigned int			j;
		    mach_msg_type_name_t    		name;
		    mach_msg_ool_ports_descriptor_t 	*dsc;
		
		    dsc = &saddr->ool_ports;

		    /* this is really the type SEND, SEND_ONCE, etc. */
		    name = dsc->disposition;
		    dsc->disposition = ipc_object_copyin_type(name);
	    	
		    objects = (ipc_object_t *) dsc->address;
	    	
		    for ( j = 0; j < dsc->count; j++) {
		        ipc_object_t object = objects[j];
		        
		        if (!IO_VALID(object))
			    continue;
		        
		        ipc_object_copyin_from_kernel(object, name);
    
		        if ((dsc->disposition == MACH_MSG_TYPE_PORT_RECEIVE) &&
			    ipc_port_check_circularity(
						       (ipc_port_t) object,
						       (ipc_port_t) remote))
			    kmsg->ikm_header->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
		    }
		    break;
	        }
	        default: {
#if	MACH_ASSERT
		    panic("ipc_kmsg_copyin_from_kernel:  bad descriptor");
#endif	/* MACH_ASSERT */
		}
	    }
	}
    }
}

/*
 *	Routine:	ipc_kmsg_copyout_header
 *	Purpose:
 *		"Copy-out" port rights in the header of a message.
 *		Operates atomically; if it doesn't succeed the
 *		message header and the space are left untouched.
 *		If it does succeed the remote/local port fields
 *		contain port names instead of object pointers,
 *		and the bits field is updated.
 *
 *		The notify argument implements the MACH_RCV_NOTIFY option.
 *		If it is not MACH_PORT_NULL, it should name a receive right.
 *		If the process of receiving the reply port creates a
 *		new right in the receiving task, then the new right is
 *		automatically registered for a dead-name notification,
 *		with the notify port supplying the send-once right.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Copied out port rights.
 *		MACH_RCV_INVALID_NOTIFY	
 *			Notify is non-null and doesn't name a receive right.
 *			(Either KERN_INVALID_NAME or KERN_INVALID_RIGHT.)
 *		MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_SPACE
 *			The space is dead.
 *		MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_SPACE
 *			No room in space for another name.
 *		MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_KERNEL
 *			Couldn't allocate memory for the reply port.
 *		MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_KERNEL
 *			Couldn't allocate memory for the dead-name request.
 */

mach_msg_return_t
ipc_kmsg_copyout_header(
	mach_msg_header_t	*msg,
	ipc_space_t		space,
	mach_port_name_t	notify)
{
	mach_msg_bits_t mbits = msg->msgh_bits;
	ipc_port_t dest = (ipc_port_t) msg->msgh_remote_port;

	assert(IP_VALID(dest));

    {
	mach_msg_type_name_t dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	mach_msg_type_name_t reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	ipc_port_t reply = (ipc_port_t) msg->msgh_local_port;
	mach_port_name_t dest_name, reply_name;

	if (IP_VALID(reply)) {
		ipc_port_t notify_port;
		ipc_entry_t entry;
		kern_return_t kr;

		/*
		 *	Handling notify (for MACH_RCV_NOTIFY) is tricky.
		 *	The problem is atomically making a send-once right
		 *	from the notify port and installing it for a
		 *	dead-name request in the new entry, because this
		 *	requires two port locks (on the notify port and
		 *	the reply port).  However, we can safely make
		 *	and consume send-once rights for the notify port
		 *	as long as we hold the space locked.  This isn't
		 *	an atomicity problem, because the only way
		 *	to detect that a send-once right has been created
		 *	and then consumed if it wasn't needed is by getting
		 *	at the receive right to look at ip_sorights, and
		 *	because the space is write-locked status calls can't
		 *	lookup the notify port receive right.  When we make
		 *	the send-once right, we lock the notify port,
		 *	so any status calls in progress will be done.
		 */

		is_write_lock(space);

		for (;;) {
			ipc_port_request_index_t request;

			if (!space->is_active) {
				is_write_unlock(space);
				return (MACH_RCV_HEADER_ERROR|
					MACH_MSG_IPC_SPACE);
			}

			if (notify != MACH_PORT_NULL) {
				notify_port = ipc_port_lookup_notify(space,
								     notify);
				if (notify_port == IP_NULL) {
					is_write_unlock(space);
					return MACH_RCV_INVALID_NOTIFY;
				}
			} else
				notify_port = IP_NULL;

			if ((reply_type != MACH_MSG_TYPE_PORT_SEND_ONCE) &&
			    ipc_right_reverse(space, (ipc_object_t) reply,
					      &reply_name, &entry)) {
				/* reply port is locked and active */

				/*
				 *	We don't need the notify_port
				 *	send-once right, but we can't release
				 *	it here because reply port is locked.
				 *	Wait until after the copyout to
				 *	release the notify port right.
				 */

				assert(entry->ie_bits &
				       MACH_PORT_TYPE_SEND_RECEIVE);
				break;
			}

			ip_lock(reply);
			if (!ip_active(reply)) {
				ip_release(reply);
				ip_check_unlock(reply);

				if (notify_port != IP_NULL)
					ipc_port_release_sonce(notify_port);

				ip_lock(dest);
				is_write_unlock(space);

				reply = IP_DEAD;
				reply_name = MACH_PORT_DEAD;
				goto copyout_dest;
			}

			reply_name = (mach_port_name_t)reply;
			kr = ipc_entry_get(space, &reply_name, &entry);
			if (kr != KERN_SUCCESS) {
				ip_unlock(reply);

				if (notify_port != IP_NULL)
					ipc_port_release_sonce(notify_port);

				/* space is locked */
				kr = ipc_entry_grow_table(space,
							  ITS_SIZE_NONE);
				if (kr != KERN_SUCCESS) {
					/* space is unlocked */

					if (kr == KERN_RESOURCE_SHORTAGE)
						return (MACH_RCV_HEADER_ERROR|
							MACH_MSG_IPC_KERNEL);
					else
						return (MACH_RCV_HEADER_ERROR|
							MACH_MSG_IPC_SPACE);
				}
				/* space is locked again; start over */

				continue;
			}
			assert(IE_BITS_TYPE(entry->ie_bits) ==
			       MACH_PORT_TYPE_NONE);
			assert(entry->ie_object == IO_NULL); 

			if (notify_port == IP_NULL) {
				/* not making a dead-name request */

				entry->ie_object = (ipc_object_t) reply;
				break;
			}

			kr = ipc_port_dnrequest(reply, reply_name,
						notify_port, &request);
			if (kr != KERN_SUCCESS) {
				ip_unlock(reply);

				ipc_port_release_sonce(notify_port);

				ipc_entry_dealloc(space, reply_name, entry);
				is_write_unlock(space);

				ip_lock(reply);
				if (!ip_active(reply)) {
					/* will fail next time around loop */

					ip_unlock(reply);
					is_write_lock(space);
					continue;
				}

				kr = ipc_port_dngrow(reply, ITS_SIZE_NONE);
				/* port is unlocked */
				if (kr != KERN_SUCCESS)
					return (MACH_RCV_HEADER_ERROR|
						MACH_MSG_IPC_KERNEL);

				is_write_lock(space);
				continue;
			}

			notify_port = IP_NULL; /* don't release right below */

			entry->ie_object = (ipc_object_t) reply;
			entry->ie_request = request;
			break;
		}

		/* space and reply port are locked and active */

		ip_reference(reply);	/* hold onto the reply port */

		kr = ipc_right_copyout(space, reply_name, entry,
				       reply_type, TRUE, (ipc_object_t) reply);
		/* reply port is unlocked */
		assert(kr == KERN_SUCCESS);

		if (notify_port != IP_NULL)
			ipc_port_release_sonce(notify_port);

		ip_lock(dest);
		is_write_unlock(space);
	} else {
		/*
		 *	No reply port!  This is an easy case.
		 *	We only need to have the space locked
		 *	when checking notify and when locking
		 *	the destination (to ensure atomicity).
		 */

		is_read_lock(space);
		if (!space->is_active) {
			is_read_unlock(space);
			return MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_SPACE;
		}

		if (notify != MACH_PORT_NULL) {
			ipc_entry_t entry;

			/* must check notify even though it won't be used */

			if ((entry = ipc_entry_lookup(space, notify)) == IE_NULL) {
				is_read_unlock(space);
				return MACH_RCV_INVALID_NOTIFY;
			}
	
			if ((entry->ie_bits & MACH_PORT_TYPE_RECEIVE) == 0) {
				is_read_unlock(space);
				return MACH_RCV_INVALID_NOTIFY;
			}
		}

		ip_lock(dest);
		is_read_unlock(space);

		reply_name = (mach_port_name_t) reply;
	}

	/*
	 *	At this point, the space is unlocked and the destination
	 *	port is locked.  (Lock taken while space was locked.)
	 *	reply_name is taken care of; we still need dest_name.
	 *	We still hold a ref for reply (if it is valid).
	 *
	 *	If the space holds receive rights for the destination,
	 *	we return its name for the right.  Otherwise the task
	 *	managed to destroy or give away the receive right between
	 *	receiving the message and this copyout.  If the destination
	 *	is dead, return MACH_PORT_DEAD, and if the receive right
	 *	exists somewhere else (another space, in transit)
	 *	return MACH_PORT_NULL.
	 *
	 *	Making this copyout operation atomic with the previous
	 *	copyout of the reply port is a bit tricky.  If there was
	 *	no real reply port (it wasn't IP_VALID) then this isn't
	 *	an issue.  If the reply port was dead at copyout time,
	 *	then we are OK, because if dest is dead we serialize
	 *	after the death of both ports and if dest is alive
	 *	we serialize after reply died but before dest's (later) death.
	 *	So assume reply was alive when we copied it out.  If dest
	 *	is alive, then we are OK because we serialize before
	 *	the ports' deaths.  So assume dest is dead when we look at it.
	 *	If reply dies/died after dest, then we are OK because
	 *	we serialize after dest died but before reply dies.
	 *	So the hard case is when reply is alive at copyout,
	 *	dest is dead at copyout, and reply died before dest died.
	 *	In this case pretend that dest is still alive, so
	 *	we serialize while both ports are alive.
	 *
	 *	Because the space lock is held across the copyout of reply
	 *	and locking dest, the receive right for dest can't move
	 *	in or out of the space while the copyouts happen, so
	 *	that isn't an atomicity problem.  In the last hard case
	 *	above, this implies that when dest is dead that the
	 *	space couldn't have had receive rights for dest at
	 *	the time reply was copied-out, so when we pretend
	 *	that dest is still alive, we can return MACH_PORT_NULL.
	 *
	 *	If dest == reply, then we have to make it look like
	 *	either both copyouts happened before the port died,
	 *	or both happened after the port died.  This special
	 *	case works naturally if the timestamp comparison
	 *	is done correctly.
	 */

    copyout_dest:

	if (ip_active(dest)) {
		ipc_object_copyout_dest(space, (ipc_object_t) dest,
					dest_type, &dest_name);
		/* dest is unlocked */
	} else {
		ipc_port_timestamp_t timestamp;

		timestamp = dest->ip_timestamp;
		ip_release(dest);
		ip_check_unlock(dest);

		if (IP_VALID(reply)) {
			ip_lock(reply);
			if (ip_active(reply) ||
			    IP_TIMESTAMP_ORDER(timestamp,
					       reply->ip_timestamp))
				dest_name = MACH_PORT_DEAD;
			else
				dest_name = MACH_PORT_NULL;
			ip_unlock(reply);
		} else
			dest_name = MACH_PORT_DEAD;
	}

	if (IP_VALID(reply))
		ipc_port_release(reply);

	msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
			  MACH_MSGH_BITS(reply_type, dest_type));
	msg->msgh_local_port = (ipc_port_t)dest_name;
	msg->msgh_remote_port = (ipc_port_t)reply_name;
    }

	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_copyout_object
 *	Purpose:
 *		Copy-out a port right.  Always returns a name,
 *		even for unsuccessful return codes.  Always
 *		consumes the supplied object.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	The space acquired the right
 *			(name is valid) or the object is dead (MACH_PORT_DEAD).
 *		MACH_MSG_IPC_SPACE	No room in space for the right,
 *			or the space is dead.  (Name is MACH_PORT_NULL.)
 *		MACH_MSG_IPC_KERNEL	Kernel resource shortage.
 *			(Name is MACH_PORT_NULL.)
 */

mach_msg_return_t
ipc_kmsg_copyout_object(
	ipc_space_t		space,
	ipc_object_t		object,
	mach_msg_type_name_t	msgt_name,
	mach_port_name_t	*namep)
{
	kern_return_t kr;

	if (!IO_VALID(object)) {
		*namep = (mach_port_name_t) object;
		return MACH_MSG_SUCCESS;
	}

	kr = ipc_object_copyout(space, object, msgt_name, TRUE, namep);
	if (kr != KERN_SUCCESS) {
		ipc_object_destroy(object, msgt_name);

		if (kr == KERN_INVALID_CAPABILITY)
			*namep = MACH_PORT_DEAD;
		else {
			*namep = MACH_PORT_NULL;

			if (kr == KERN_RESOURCE_SHORTAGE)
				return MACH_MSG_IPC_KERNEL;
			else
				return MACH_MSG_IPC_SPACE;
		}
	}

	return MACH_MSG_SUCCESS;
}

/*
 *	Routine:	ipc_kmsg_copyout_body
 *	Purpose:
 *		"Copy-out" port rights and out-of-line memory
 *		in the body of a message.
 *
 *		The error codes are a combination of special bits.
 *		The copyout proceeds despite errors.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyout.
 *		MACH_MSG_IPC_SPACE	No room for port right in name space.
 *		MACH_MSG_VM_SPACE	No room for memory in address space.
 *		MACH_MSG_IPC_KERNEL	Resource shortage handling port right.
 *		MACH_MSG_VM_KERNEL	Resource shortage handling memory.
 *		MACH_MSG_INVALID_RT_DESCRIPTOR Descriptor incompatible with RT
 */

mach_msg_return_t
ipc_kmsg_copyout_body(
    	ipc_kmsg_t		kmsg,
	ipc_space_t		space,
	vm_map_t		map,
	mach_msg_body_t		*slist)
{
    mach_msg_body_t 		*body;
    mach_msg_descriptor_t 	*daddr, *naddr;
    mach_msg_descriptor_t	*saddr;
    mach_msg_type_number_t	i, dsc_count, sdsc_count;
    mach_msg_return_t 		mr = MACH_MSG_SUCCESS;
    kern_return_t 		kr;
    void			*data;
    boolean_t			differs = MAP_SIZE_DIFFERS(map);

    body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
    dsc_count = body->msgh_descriptor_count;
    daddr = (mach_msg_descriptor_t *) (body + 1);

    /*
     * Do scatter list setup
     */
    if (slist != MACH_MSG_BODY_NULL) {
	saddr = (mach_msg_descriptor_t *) (slist + 1);
	sdsc_count = slist->msgh_descriptor_count;
    }
    else {
	saddr = MACH_MSG_DESCRIPTOR_NULL;
	sdsc_count = 0;
    }

    /*
     * Compute the true size of the resulting descriptors
     * after potential expansion and adjust the header
     * and body location accordingly.
     */
    if (differs) {
	mach_msg_size_t dsc_adjust;

	naddr = daddr;
	dsc_adjust = 0;
	for (i = 0; i < dsc_count; i++, naddr++)
	    switch (naddr->type.type) {
	    case MACH_MSG_OOL_DESCRIPTOR:
	    case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
	    case MACH_MSG_OOL_PORTS_DESCRIPTOR:
		dsc_adjust += DESC_SIZE_ADJUSTMENT;
		break;
	    default:
		break;
	    }
	if (dsc_adjust) {
	    mach_msg_base_t *old_base = (mach_msg_base_t *)kmsg->ikm_header;
	    mach_msg_base_t *new_base;

	    new_base = (mach_msg_base_t *)((vm_offset_t)old_base - dsc_adjust);
	    memmove(new_base, old_base, sizeof(mach_msg_base_t));
	    kmsg->ikm_header = &new_base->header;
	    kmsg->ikm_header->msgh_size += dsc_adjust;
	    naddr = (mach_msg_descriptor_t *)(new_base + 1);
	} else {
	    naddr = daddr;
	}
    } else {
	naddr = daddr;
    }

    /*
     * Now process the descriptors
     */
    for ( i = 0; i < dsc_count; i++, daddr++ ) {
	switch (daddr->type.type) {
	    
	    case MACH_MSG_PORT_DESCRIPTOR: {
		volatile mach_msg_port_descriptor_t *dsc;
		volatile mach_msg_port_descriptor_t *user_dsc;
		mach_port_t			port;
		mach_port_name_t		name;
		mach_msg_type_name_t		disp;
		
		/* 
		 * Copyout port right carried in the message 
		 */
		dsc = &daddr->port;
		user_dsc = &naddr->port;
		port = dsc->name;
		disp = dsc->disposition;
		mr |= ipc_kmsg_copyout_object(space, 
					      (ipc_object_t)port, 
					      disp, 
					      &name);
		user_dsc->name = (mach_port_t)name;
		user_dsc->disposition = disp;
		user_dsc->type = MACH_MSG_PORT_DESCRIPTOR;
		naddr++;
		break;
	    }

	    case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
	    case MACH_MSG_OOL_DESCRIPTOR : {
		vm_map_copy_t			copy;
		mach_vm_offset_t		rcv_addr;
		mach_msg_ool_descriptor_t	*dsc;
		mach_msg_copy_options_t		copy_options;
		mach_msg_size_t			size;
		mach_msg_descriptor_type_t	dsc_type;

		SKIP_PORT_DESCRIPTORS(saddr, sdsc_count);

		dsc = &daddr->out_of_line;
		copy = (vm_map_copy_t) dsc->address;
		size = dsc->size;
		copy_options = dsc->copy;
		assert(copy_options != MACH_MSG_KALLOC_COPY_T);
		dsc_type = dsc->type;

		if (copy != VM_MAP_COPY_NULL) {
		    /*
		     * Check to see if there is an overwrite descriptor
		     * specified in the scatter list for this ool data.
		     * The descriptor has already been verified.
		     */
		    if (saddr != MACH_MSG_DESCRIPTOR_NULL) {
			if (differs) {
			    OTHER_OOL_DESCRIPTOR *scatter_dsc;

			    scatter_dsc = (OTHER_OOL_DESCRIPTOR *)saddr;
			    if (scatter_dsc->copy == MACH_MSG_OVERWRITE) {
				rcv_addr = (mach_vm_offset_t) scatter_dsc->address;
				copy_options = MACH_MSG_OVERWRITE;
			    } else {
				rcv_addr = 0;
				copy_options = MACH_MSG_VIRTUAL_COPY;
			    }
			} else {
			    mach_msg_ool_descriptor_t *scatter_dsc;

			    scatter_dsc = &saddr->out_of_line;
			    if (scatter_dsc->copy == MACH_MSG_OVERWRITE) {
				rcv_addr = CAST_USER_ADDR_T(scatter_dsc->address);
				copy_options = MACH_MSG_OVERWRITE;
			    } else {
				rcv_addr = 0;
				copy_options = MACH_MSG_VIRTUAL_COPY;
			    }
			}
			INCREMENT_SCATTER(saddr, sdsc_count, differs);
		    }


		    /*
		     * Whether the data was virtually or physically
		     * copied we have a vm_map_copy_t for it.
		     * If there's an overwrite region specified
		     * overwrite it, otherwise do a virtual copy out.
		     */
		    if (copy_options == MACH_MSG_OVERWRITE) {
			    kr = vm_map_copy_overwrite(map, rcv_addr,
					    copy, TRUE);
		    } else {
			    kr = vm_map_copyout(map, &rcv_addr, copy);
		    }	
		    if (kr != KERN_SUCCESS) {
		    	    if (kr == KERN_RESOURCE_SHORTAGE)
				    mr |= MACH_MSG_VM_KERNEL;
		    	    else
				    mr |= MACH_MSG_VM_SPACE;
		    	    vm_map_copy_discard(copy);
			    rcv_addr = 0;
			    size = 0;
		    }
		} else {
		    rcv_addr = 0;
		    size = 0;
		}

		/*
		 * Now update the descriptor as the user would see it.
		 * This may require expanding the descriptor to the user
		 * visible size.  There is already space allocated for
		 * this in what naddr points to.
		 */
		if (differs) {
		    volatile OTHER_OOL_DESCRIPTOR *user_dsc;
		    
		    user_dsc = (OTHER_OOL_DESCRIPTOR *)naddr;
		    user_dsc->address = rcv_addr;
		    user_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
					   TRUE : FALSE;
		    user_dsc->copy = copy_options;
		    user_dsc->type = dsc_type;
		    user_dsc->size = size;
		    naddr = (mach_msg_descriptor_t *)((OTHER_OOL_DESCRIPTOR *)naddr + 1);
		} else {
		    volatile mach_msg_ool_descriptor_t *user_dsc;
		    
		    user_dsc = &naddr->out_of_line;
		    user_dsc->address = CAST_DOWN(void *, rcv_addr);
		    user_dsc->size = size;
		    user_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
					   TRUE : FALSE;
		    user_dsc->copy = copy_options;
		    user_dsc->type = dsc_type;
		    naddr++;
		}
		break;
	    }

	    case MACH_MSG_OOL_PORTS_DESCRIPTOR : {
		mach_vm_offset_t		rcv_addr;
		mach_port_name_t       		*objects;
		mach_msg_type_name_t		disp;
		mach_msg_type_number_t 		count, j;
    		vm_size_t           		length;

		volatile mach_msg_ool_ports_descriptor_t	*dsc;
		mach_msg_copy_options_t copy_options = MACH_MSG_VIRTUAL_COPY;

		SKIP_PORT_DESCRIPTORS(saddr, sdsc_count);

		dsc = &daddr->ool_ports;
		count = dsc->count;
		disp = dsc->disposition;
		length = count * sizeof(mach_port_name_t);

		if (length != 0 && dsc->address != 0) {

		    /*
		     * Check to see if there is an overwrite descriptor
		     * specified in the scatter list for this ool data.
		     * The descriptor has already been verified.
		     */
		    if (saddr != MACH_MSG_DESCRIPTOR_NULL) {
			if (differs) {
			    OTHER_OOL_DESCRIPTOR *scatter_dsc;

			    scatter_dsc = (OTHER_OOL_DESCRIPTOR *)saddr;
			    rcv_addr = (mach_vm_offset_t) scatter_dsc->address;
			    copy_options = scatter_dsc->copy;
			} else {
			    mach_msg_ool_descriptor_t *scatter_dsc;

			    scatter_dsc = &saddr->out_of_line;
			    rcv_addr = CAST_USER_ADDR_T(scatter_dsc->address);
			    copy_options = scatter_dsc->copy;
			}
			INCREMENT_SCATTER(saddr, sdsc_count, differs);
		    }

		    if (copy_options == MACH_MSG_VIRTUAL_COPY) {
		   	/*
			 * Dynamically allocate the region
			 */
			int anywhere = VM_MAKE_TAG(VM_MEMORY_MACH_MSG)|
				       VM_FLAGS_ANYWHERE;

		    	if ((kr = mach_vm_allocate(map, &rcv_addr, 
					      (mach_vm_size_t)length,
					      anywhere)) != KERN_SUCCESS) {
			    ipc_kmsg_clean_body(kmsg, 1, daddr);
			    rcv_addr = 0;

			    if (kr == KERN_RESOURCE_SHORTAGE){
			    	mr |= MACH_MSG_VM_KERNEL;
			    } else {
			    	mr |= MACH_MSG_VM_SPACE;
			    }
			}
		    }


		    /*
		     * Handle the port rights and copy out the names
		     * for those rights out to user-space.
		     */
		    if (rcv_addr != 0) {
			objects = (mach_port_name_t *) dsc->address ;
		
			/* copyout port rights carried in the message */
		
			for ( j = 0; j < count ; j++) {
			    ipc_object_t object =
				(ipc_object_t) objects[j];
		    
			    mr |= ipc_kmsg_copyout_object(space, object,
							  disp, &objects[j]);
			}

			/* copyout to memory allocated above */
			data = dsc->address;
			if (copyoutmap(map, data, rcv_addr, length) != KERN_SUCCESS)
			    mr |= MACH_MSG_VM_SPACE;
			kfree(data, length);
		    }
		} else {
		    rcv_addr = 0;
		}

		/*
		 * Now update the descriptor based on the information
		 * calculated above.
		 */
		if (differs) {
		    volatile OTHER_OOL_PORTS_DESCRIPTOR *user_dsc;
		    
		    user_dsc = (OTHER_OOL_PORTS_DESCRIPTOR *)naddr;
		    user_dsc->address = rcv_addr;
		    user_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
			                   TRUE : FALSE;
		    user_dsc->copy = copy_options;
		    user_dsc->disposition = disp;
		    user_dsc->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
		    user_dsc->count = count;
		    naddr = (mach_msg_descriptor_t *)((OTHER_OOL_PORTS_DESCRIPTOR *)naddr + 1);
		} else {
		    volatile mach_msg_ool_ports_descriptor_t *user_dsc;
		    
		    user_dsc = &naddr->ool_ports;
		    user_dsc->address = CAST_DOWN(void *, rcv_addr);
		    user_dsc->count = count;
		    user_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
			                   TRUE : FALSE;
		    user_dsc->copy = copy_options;
		    user_dsc->disposition = disp;
		    user_dsc->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
		    naddr++;
		}
		break;
	    }
	    default : {
		panic("untyped IPC copyout body: invalid message descriptor");
	    }
	}
    }
    return mr;
}

/*
 *	Routine:	ipc_kmsg_copyout_size
 *	Purpose:
 *		Compute the size of the message as copied out to the given
 *		map. If the destination map's pointers are a different size
 *		than the kernel's, we have to allow for expansion/
 *		contraction of the descriptors as appropriate.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		size of the message as it would be received.
 */

mach_msg_size_t
ipc_kmsg_copyout_size(
	ipc_kmsg_t		kmsg,
	vm_map_t		map)
{
	mach_msg_size_t		send_size;

	send_size = kmsg->ikm_header->msgh_size;

	if ((kmsg->ikm_header->msgh_bits & MACH_MSGH_BITS_COMPLEX) &&
	    MAP_SIZE_DIFFERS(map)) {

		mach_msg_body_t *body;
		mach_msg_descriptor_t *saddr, *eaddr;

		body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
		saddr = (mach_msg_descriptor_t *) (body + 1);
		eaddr = saddr + body->msgh_descriptor_count;
		
		for ( ; saddr < eaddr; saddr++ ) {
			switch (saddr->type.type) {

			case MACH_MSG_OOL_DESCRIPTOR:
			case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
			case MACH_MSG_OOL_PORTS_DESCRIPTOR:
				send_size += DESC_SIZE_ADJUSTMENT;
				break;

			default:
				break;
			}
		}
	}
	return send_size;
}

/*
 *	Routine:	ipc_kmsg_copyout
 *	Purpose:
 *		"Copy-out" port rights and out-of-line memory
 *		in the message.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Copied out all rights and memory.
 *		MACH_RCV_INVALID_NOTIFY	Bad notify port.
 *			Rights and memory in the message are intact.
 *		MACH_RCV_HEADER_ERROR + special bits
 *			Rights and memory in the message are intact.
 *		MACH_RCV_BODY_ERROR + special bits
 *			The message header was successfully copied out.
 *			As much of the body was handled as possible.
 */

mach_msg_return_t
ipc_kmsg_copyout(
	ipc_kmsg_t		kmsg,
	ipc_space_t		space,
	vm_map_t		map,
	mach_port_name_t	notify,
	mach_msg_body_t		*slist)
{
	mach_msg_return_t mr;

	mr = ipc_kmsg_copyout_header(kmsg->ikm_header, space, notify);
	if (mr != MACH_MSG_SUCCESS)
		return mr;

	if (kmsg->ikm_header->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
		mr = ipc_kmsg_copyout_body(kmsg, space, map, slist);

		if (mr != MACH_MSG_SUCCESS)
			mr |= MACH_RCV_BODY_ERROR;
	}

	return mr;
}

/*
 *	Routine:	ipc_kmsg_copyout_pseudo
 *	Purpose:
 *		Does a pseudo-copyout of the message.
 *		This is like a regular copyout, except
 *		that the ports in the header are handled
 *		as if they are in the body.  They aren't reversed.
 *
 *		The error codes are a combination of special bits.
 *		The copyout proceeds despite errors.
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyout.
 *		MACH_MSG_IPC_SPACE	No room for port right in name space.
 *		MACH_MSG_VM_SPACE	No room for memory in address space.
 *		MACH_MSG_IPC_KERNEL	Resource shortage handling port right.
 *		MACH_MSG_VM_KERNEL	Resource shortage handling memory.
 */

mach_msg_return_t
ipc_kmsg_copyout_pseudo(
	ipc_kmsg_t		kmsg,
	ipc_space_t		space,
	vm_map_t		map,
	mach_msg_body_t		*slist)
{
	mach_msg_bits_t mbits = kmsg->ikm_header->msgh_bits;
	ipc_object_t dest = (ipc_object_t) kmsg->ikm_header->msgh_remote_port;
	ipc_object_t reply = (ipc_object_t) kmsg->ikm_header->msgh_local_port;
	mach_msg_type_name_t dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	mach_msg_type_name_t reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	mach_port_name_t dest_name, reply_name;
	mach_msg_return_t mr;

	assert(IO_VALID(dest));

	mr = (ipc_kmsg_copyout_object(space, dest, dest_type, &dest_name) |
	      ipc_kmsg_copyout_object(space, reply, reply_type, &reply_name));

	kmsg->ikm_header->msgh_bits = mbits &~ MACH_MSGH_BITS_CIRCULAR;
	kmsg->ikm_header->msgh_remote_port = (ipc_port_t)dest_name;
	kmsg->ikm_header->msgh_local_port = (ipc_port_t)reply_name;

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		mr |= ipc_kmsg_copyout_body(kmsg, space, map, slist);
	}

	return mr;
}

/*
 *	Routine:	ipc_kmsg_copyout_dest
 *	Purpose:
 *		Copies out the destination port in the message.
 *		Destroys all other rights and memory in the message.
 *	Conditions:
 *		Nothing locked.
 */

void
ipc_kmsg_copyout_dest(
	ipc_kmsg_t	kmsg,
	ipc_space_t	space)
{
	mach_msg_bits_t mbits;
	ipc_object_t dest;
	ipc_object_t reply;
	mach_msg_type_name_t dest_type;
	mach_msg_type_name_t reply_type;
	mach_port_name_t dest_name, reply_name;

	mbits = kmsg->ikm_header->msgh_bits;
	dest = (ipc_object_t) kmsg->ikm_header->msgh_remote_port;
	reply = (ipc_object_t) kmsg->ikm_header->msgh_local_port;
	dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	reply_type = MACH_MSGH_BITS_LOCAL(mbits);

	assert(IO_VALID(dest));

	io_lock(dest);
	if (io_active(dest)) {
		ipc_object_copyout_dest(space, dest, dest_type, &dest_name);
		/* dest is unlocked */
	} else {
		io_release(dest);
		io_check_unlock(dest);
		dest_name = MACH_PORT_DEAD;
	}

	if (IO_VALID(reply)) {
		ipc_object_destroy(reply, reply_type);
		reply_name = MACH_PORT_NULL;
	} else
		reply_name = (mach_port_name_t) reply;

	kmsg->ikm_header->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
				      MACH_MSGH_BITS(reply_type, dest_type));
	kmsg->ikm_header->msgh_local_port = (ipc_port_t)dest_name;
	kmsg->ikm_header->msgh_remote_port = (ipc_port_t)reply_name;

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_body_t *body;

		body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
		ipc_kmsg_clean_body(kmsg, body->msgh_descriptor_count, 
				    (mach_msg_descriptor_t *)(body + 1));
	}
}

/*
 *      Routine:        ipc_kmsg_copyin_scatter
 *      Purpose:
 *              allocate and copyin a scatter list
 *      Algorithm:
 *              The gather (kmsg) is valid since it has been copied in.
 *              Gather list descriptors are sequentially paired with scatter
 *              list descriptors, with port descriptors in either list ignored.
 *              Descriptors are consistent if the type fileds match and size
 *              of the scatter descriptor is less than or equal to the
 *              size of the gather descriptor.  A MACH_MSG_ALLOCATE copy
 *              strategy in a scatter descriptor matches any size in the
 *              corresponding gather descriptor assuming they are the same type.
 *              Either list may be larger than the other.  During the
 *              subsequent copy out, excess scatter descriptors are ignored
 *              and excess gather descriptors default to dynamic allocation.
 *
 *              In the case of a size error, the scatter list is released.
 *      Conditions:
 *              Nothing locked.
 *      Returns:
 *              the allocated message body containing the scatter list.
 */

mach_msg_body_t *
ipc_kmsg_get_scatter(
	mach_vm_address_t       msg_addr,
       mach_msg_size_t         slist_size,
	ipc_kmsg_t              kmsg)
{
        mach_msg_body_t         *slist;
        mach_msg_body_t         *body;
        mach_msg_descriptor_t   *gstart, *gend;
        mach_msg_descriptor_t   *sstart, *send;


        if (slist_size < sizeof(mach_msg_base_t))
                return MACH_MSG_BODY_NULL;

        slist_size -= sizeof(mach_msg_header_t);
        slist = (mach_msg_body_t *)kalloc(slist_size);
        if (slist == MACH_MSG_BODY_NULL)
                return slist;

        if (copyin(msg_addr + sizeof(mach_msg_header_t), (char *)slist, slist_size)) {
                kfree(slist, slist_size);
                return MACH_MSG_BODY_NULL;
        }

        if ((slist->msgh_descriptor_count* sizeof(mach_msg_descriptor_t)
             + sizeof(mach_msg_size_t)) > slist_size) {
                kfree(slist, slist_size);
                return MACH_MSG_BODY_NULL;
        }

        body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
        gstart = (mach_msg_descriptor_t *) (body + 1);
        gend = gstart + body->msgh_descriptor_count;

        sstart = (mach_msg_descriptor_t *) (slist + 1);
        send = sstart + slist->msgh_descriptor_count;

        while (gstart < gend) {
            mach_msg_descriptor_type_t  g_type;

            /*
             * Skip port descriptors in gather list.
             */
            g_type = gstart->type.type;

            if (g_type != MACH_MSG_PORT_DESCRIPTOR) {

	      /*
	       * A scatter list with a 0 descriptor count is treated as an
	       * automatic size mismatch.
	       */
	      if (slist->msgh_descriptor_count == 0) {
                        kfree(slist, slist_size);
                        return MACH_MSG_BODY_NULL;
	      }

	      /*
	       * Skip port descriptors in  scatter list.
	       */
	      while (sstart < send) {
                    if (sstart->type.type != MACH_MSG_PORT_DESCRIPTOR)
                        break;
                    sstart++;
	      }

	      /*
	       * No more scatter descriptors, we're done
	       */
	      if (sstart >= send) {
                    break;
	      }

	      /*
	       * Check type, copy and size fields
	       */
                if (g_type == MACH_MSG_OOL_DESCRIPTOR ||
                    g_type == MACH_MSG_OOL_VOLATILE_DESCRIPTOR) {
                    if (sstart->type.type != MACH_MSG_OOL_DESCRIPTOR &&
                        sstart->type.type != MACH_MSG_OOL_VOLATILE_DESCRIPTOR) {
                        kfree(slist, slist_size);
                        return MACH_MSG_BODY_NULL;
                    }
                    if (sstart->out_of_line.copy == MACH_MSG_OVERWRITE &&
                        gstart->out_of_line.size > sstart->out_of_line.size) {
                        kfree(slist, slist_size);
                        return MACH_MSG_BODY_NULL;
                    }
                }
                else {
		  if (sstart->type.type != MACH_MSG_OOL_PORTS_DESCRIPTOR) {
                        kfree(slist, slist_size);
                        return MACH_MSG_BODY_NULL;
		  }
                    if (sstart->ool_ports.copy == MACH_MSG_OVERWRITE &&
                        gstart->ool_ports.count > sstart->ool_ports.count) {
                        kfree(slist, slist_size);
                        return MACH_MSG_BODY_NULL;
                    }
                }
                sstart++;
            }
            gstart++;
        }
        return slist;
}


/*
 *      Routine:        ipc_kmsg_free_scatter
 *      Purpose:
 *              Deallocate a scatter list.  Since we actually allocated
 *              a body without a header, and since the header was originally
 *              accounted for in slist_size, we have to ajust it down
 *              before freeing the scatter list.
 */
void
ipc_kmsg_free_scatter(
        mach_msg_body_t *slist,
        mach_msg_size_t slist_size)
{
        slist_size -= sizeof(mach_msg_header_t);
        kfree(slist, slist_size);
}


/*
 *	Routine:	ipc_kmsg_copyout_to_kernel
 *	Purpose:
 *		Copies out the destination and reply ports in the message.
 *		Leaves all other rights and memory in the message alone.
 *	Conditions:
 *		Nothing locked.
 *
 *	Derived from ipc_kmsg_copyout_dest.
 *	Use by mach_msg_rpc_from_kernel (which used to use copyout_dest).
 *	We really do want to save rights and memory.
 */

void
ipc_kmsg_copyout_to_kernel(
	ipc_kmsg_t	kmsg,
	ipc_space_t	space)
{
	ipc_object_t dest;
	ipc_object_t reply;
	mach_msg_type_name_t dest_type;
	mach_msg_type_name_t reply_type;
	mach_port_name_t dest_name, reply_name;

	dest = (ipc_object_t) kmsg->ikm_header->msgh_remote_port;
	reply = (ipc_object_t) kmsg->ikm_header->msgh_local_port;
	dest_type = MACH_MSGH_BITS_REMOTE(kmsg->ikm_header->msgh_bits);
	reply_type = MACH_MSGH_BITS_LOCAL(kmsg->ikm_header->msgh_bits);

	assert(IO_VALID(dest));

	io_lock(dest);
	if (io_active(dest)) {
		ipc_object_copyout_dest(space, dest, dest_type, &dest_name);
		/* dest is unlocked */
	} else {
		io_release(dest);
		io_check_unlock(dest);
		dest_name = MACH_PORT_DEAD;
	}

	reply_name = (mach_port_name_t) reply;

	kmsg->ikm_header->msgh_bits =
		(MACH_MSGH_BITS_OTHER(kmsg->ikm_header->msgh_bits) |
					MACH_MSGH_BITS(reply_type, dest_type));
	kmsg->ikm_header->msgh_local_port = (ipc_port_t)dest_name;
	kmsg->ikm_header->msgh_remote_port = (ipc_port_t)reply_name;
}

#include <mach_kdb.h>
#if	MACH_KDB

#include <ddb/db_output.h>
#include <ipc/ipc_print.h>
/*
 * Forward declarations
 */
void ipc_msg_print_untyped(
	mach_msg_body_t		*body);

const char * ipc_type_name(
	int		type_name,
	boolean_t	received);

void ipc_print_type_name(
	int	type_name);

const char *
msgh_bit_decode(
	mach_msg_bits_t	bit);

const char *
mm_copy_options_string(
	mach_msg_copy_options_t	option);

void db_print_msg_uid(mach_msg_header_t *);


const char *
ipc_type_name(
	int		type_name,
	boolean_t	received)
{
	switch (type_name) {
		case MACH_MSG_TYPE_PORT_NAME:
		return "port_name";
		
		case MACH_MSG_TYPE_MOVE_RECEIVE:
		if (received) {
			return "port_receive";
		} else {
			return "move_receive";
		}
		
		case MACH_MSG_TYPE_MOVE_SEND:
		if (received) {
			return "port_send";
		} else {
			return "move_send";
		}
		
		case MACH_MSG_TYPE_MOVE_SEND_ONCE:
		if (received) {
			return "port_send_once";
		} else {
			return "move_send_once";
		}
		
		case MACH_MSG_TYPE_COPY_SEND:
		return "copy_send";
		
		case MACH_MSG_TYPE_MAKE_SEND:
		return "make_send";
		
		case MACH_MSG_TYPE_MAKE_SEND_ONCE:
		return "make_send_once";
		
		default:
		return (char *) 0;
	}
}
		
void
ipc_print_type_name(
	int	type_name)
{
	const char *name = ipc_type_name(type_name, TRUE);
	if (name) {
		printf("%s", name);
	} else {
		printf("type%d", type_name);
	}
}

/*
 * ipc_kmsg_print	[ debug ]
 */
void
ipc_kmsg_print(
	ipc_kmsg_t	kmsg)
{
	iprintf("kmsg=0x%x\n", kmsg);
	iprintf("ikm_next=0x%x, prev=0x%x, size=%d",
		kmsg->ikm_next,
		kmsg->ikm_prev,
		kmsg->ikm_size);
	printf("\n");
	ipc_msg_print(kmsg->ikm_header);
}

const char *
msgh_bit_decode(
	mach_msg_bits_t	bit)
{
	switch (bit) {
	    case MACH_MSGH_BITS_COMPLEX:	return "complex";
	    case MACH_MSGH_BITS_CIRCULAR:	return "circular";
	    default:				return (char *) 0;
	}
}

/*
 * ipc_msg_print	[ debug ]
 */
void
ipc_msg_print(
	mach_msg_header_t	*msgh)
{
	mach_msg_bits_t	mbits;
	unsigned int	bit, i;
	const char	*bit_name;
	int		needs_comma;

	mbits = msgh->msgh_bits;
	iprintf("msgh_bits=0x%x:  l=0x%x,r=0x%x\n",
		mbits,
		MACH_MSGH_BITS_LOCAL(msgh->msgh_bits),
		MACH_MSGH_BITS_REMOTE(msgh->msgh_bits));

	mbits = MACH_MSGH_BITS_OTHER(mbits) & MACH_MSGH_BITS_USED;
	db_indent += 2;
	if (mbits)
		iprintf("decoded bits:  ");
	needs_comma = 0;
	for (i = 0, bit = 1; i < sizeof(mbits) * 8; ++i, bit <<= 1) {
		if ((mbits & bit) == 0)
			continue;
		bit_name = msgh_bit_decode((mach_msg_bits_t)bit);
		if (bit_name)
			printf("%s%s", needs_comma ? "," : "", bit_name);
		else
			printf("%sunknown(0x%x),", needs_comma ? "," : "", bit);
		++needs_comma;
	}
	if (msgh->msgh_bits & ~MACH_MSGH_BITS_USED) {
		printf("%sunused=0x%x,", needs_comma ? "," : "",
		       msgh->msgh_bits & ~MACH_MSGH_BITS_USED);
	}
	printf("\n");
	db_indent -= 2;

	needs_comma = 1;
	if (msgh->msgh_remote_port) {
		iprintf("remote=0x%x(", msgh->msgh_remote_port);
		ipc_print_type_name(MACH_MSGH_BITS_REMOTE(msgh->msgh_bits));
		printf(")");
	} else {
		iprintf("remote=null");
	}

	if (msgh->msgh_local_port) {
		printf("%slocal=0x%x(", needs_comma ? "," : "",
		       msgh->msgh_local_port);
		ipc_print_type_name(MACH_MSGH_BITS_LOCAL(msgh->msgh_bits));
		printf(")\n");
	} else {
		printf("local=null\n");
	}

	iprintf("msgh_id=%d, size=%d\n",
		msgh->msgh_id,
		msgh->msgh_size);

	if (mbits & MACH_MSGH_BITS_COMPLEX) {	
		ipc_msg_print_untyped((mach_msg_body_t *) (msgh + 1));
	}
}


const char *
mm_copy_options_string(
	mach_msg_copy_options_t	option)
{
	const char	*name;

	switch (option) {
	    case MACH_MSG_PHYSICAL_COPY:
		name = "PHYSICAL";
		break;
	    case MACH_MSG_VIRTUAL_COPY:
		name = "VIRTUAL";
		break;
	    case MACH_MSG_OVERWRITE:
		name = "OVERWRITE";
		break;
	    case MACH_MSG_ALLOCATE:
		name = "ALLOCATE";
		break;
	    case MACH_MSG_KALLOC_COPY_T:
		name = "KALLOC_COPY_T";
		break;
	    default:
		name = "unknown";
		break;
	}
	return name;
}

void
ipc_msg_print_untyped(
	mach_msg_body_t		*body)
{
    mach_msg_descriptor_t	*saddr, *send;
    mach_msg_descriptor_type_t	type;

    iprintf("%d descriptors %d: \n", body->msgh_descriptor_count);

    saddr = (mach_msg_descriptor_t *) (body + 1);
    send = saddr + body->msgh_descriptor_count;

    for ( ; saddr < send; saddr++ ) {
	
	type = saddr->type.type;

	switch (type) {
	    
	    case MACH_MSG_PORT_DESCRIPTOR: {
		mach_msg_port_descriptor_t *dsc;

		dsc = &saddr->port;
		iprintf("-- PORT name = 0x%x disp = ", dsc->name);
		ipc_print_type_name(dsc->disposition);
		printf("\n");
		break;
	    }
	    case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
	    case MACH_MSG_OOL_DESCRIPTOR: {
		mach_msg_ool_descriptor_t *dsc;
		
		dsc = &saddr->out_of_line;
		iprintf("-- OOL%s addr = 0x%x size = 0x%x copy = %s %s\n",
			type == MACH_MSG_OOL_DESCRIPTOR ? "" : " VOLATILE",
			dsc->address, dsc->size,
			mm_copy_options_string(dsc->copy),
			dsc->deallocate ? "DEALLOC" : "");
		break;
	    } 
	    case MACH_MSG_OOL_PORTS_DESCRIPTOR : {
		mach_msg_ool_ports_descriptor_t *dsc;

		dsc = &saddr->ool_ports;

		iprintf("-- OOL_PORTS addr = 0x%x count = 0x%x ",
		          dsc->address, dsc->count);
		printf("disp = ");
		ipc_print_type_name(dsc->disposition);
		printf(" copy = %s %s\n",
		       mm_copy_options_string(dsc->copy),
		       dsc->deallocate ? "DEALLOC" : "");
		break;
	    }

	    default: {
		iprintf("-- UNKNOWN DESCRIPTOR 0x%x\n", type);
		break;
	    }
	}
    }
}
#endif	/* MACH_KDB */
