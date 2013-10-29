/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 * Copyright (c) 2005 SPARTA, Inc.
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
#include <kern/debug.h>
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

#include <machine/machlimits.h>

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

#include <security/mac_mach_internal.h>

#include <string.h>

#ifdef ppc
#include <ppc/Firmware.h>
#include <ppc/low_trace.h>
#endif

#if DEBUG
#define DEBUG_MSGS_K64 1
#endif

#include <sys/kdebug.h>
#include <libkern/OSAtomic.h>

#pragma pack(4)

typedef	struct 
{
  mach_msg_bits_t	msgh_bits;
  mach_msg_size_t	msgh_size;
  uint32_t		msgh_remote_port;
  uint32_t		msgh_local_port;
  mach_msg_size_t 	msgh_reserved;
  mach_msg_id_t		msgh_id;
} mach_msg_legacy_header_t;

typedef struct
{
        mach_msg_legacy_header_t       header;
        mach_msg_body_t         body;
} mach_msg_legacy_base_t;

typedef struct
{
  mach_port_name_t				name;
  mach_msg_size_t				pad1;
  uint32_t						pad2 : 16;
  mach_msg_type_name_t			disposition : 8;
  mach_msg_descriptor_type_t	type : 8;
} mach_msg_legacy_port_descriptor_t;


typedef union
{
  mach_msg_legacy_port_descriptor_t			port;
  mach_msg_ool_descriptor32_t		out_of_line32;
  mach_msg_ool_ports_descriptor32_t	ool_ports32;
  mach_msg_type_descriptor_t			type;
} mach_msg_legacy_descriptor_t;

#pragma pack()

#define LEGACY_HEADER_SIZE_DELTA ((mach_msg_size_t)(sizeof(mach_msg_header_t) - sizeof(mach_msg_legacy_header_t)))
// END LP64 fixes


#if DEBUG_MSGS_K64
extern void ipc_pset_print64(
			ipc_pset_t	pset);

extern void	ipc_kmsg_print64(
			ipc_kmsg_t      kmsg,
			const char	*str);

extern void	ipc_msg_print64(
		mach_msg_header_t       *msgh);

extern ipc_port_t ipc_name_to_data64(
			task_t			task,
			mach_port_name_t	name);

/*
 * Forward declarations
 */
void ipc_msg_print_untyped64(
	mach_msg_body_t		*body);

const char * ipc_type_name64(
	int		type_name,
	boolean_t	received);

void ipc_print_type_name64(
	int	type_name);

const char *
msgh_bit_decode64(
	mach_msg_bits_t	bit);

const char *
mm_copy_options_string64(
	mach_msg_copy_options_t	option);

void db_print_msg_uid64(mach_msg_header_t *);

static void
ipc_msg_body_print64(void *body, int size)
{
	uint32_t	*word = (uint32_t *) body;
	uint32_t	*end  = (uint32_t *)(((uintptr_t) body) + size
						- sizeof(mach_msg_header_t));
	int		i;

	kprintf("  body(%p-%p):\n    %p: ", body, end, word);
	for (;;) {
		for (i = 0; i < 8; i++, word++) {
			if (word >= end) {
				kprintf("\n");
				return;
			}
			kprintf("%08x ", *word); 
		}
		kprintf("\n    %p: ", word);
	}
}


const char *
ipc_type_name64(
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
ipc_print_type_name64(
	int	type_name)
{
	const char *name = ipc_type_name64(type_name, TRUE);
	if (name) {
		kprintf("%s", name);
	} else {
		kprintf("type%d", type_name);
	}
}

/*
 * ipc_kmsg_print64	[ debug ]
 */
void
ipc_kmsg_print64(
	ipc_kmsg_t	kmsg,
	const char	*str)
{
	kprintf("%s kmsg=%p:\n", str, kmsg);
	kprintf("  next=%p, prev=%p, size=%d",
		kmsg->ikm_next,
		kmsg->ikm_prev,
		kmsg->ikm_size);
	kprintf("\n");
	ipc_msg_print64(kmsg->ikm_header);
}

const char *
msgh_bit_decode64(
	mach_msg_bits_t	bit)
{
	switch (bit) {
	    case MACH_MSGH_BITS_COMPLEX:	return "complex";
	    case MACH_MSGH_BITS_CIRCULAR:	return "circular";
	    default:				return (char *) 0;
	}
}

/*
 * ipc_msg_print64	[ debug ]
 */
void
ipc_msg_print64(
	mach_msg_header_t	*msgh)
{
	mach_msg_bits_t	mbits;
	unsigned int	bit, i;
	const char	*bit_name;
	int		needs_comma;

	mbits = msgh->msgh_bits;
	kprintf("  msgh_bits=0x%x: l=0x%x,r=0x%x\n",
		mbits,
		MACH_MSGH_BITS_LOCAL(msgh->msgh_bits),
		MACH_MSGH_BITS_REMOTE(msgh->msgh_bits));

	mbits = MACH_MSGH_BITS_OTHER(mbits) & MACH_MSGH_BITS_USED;
	kprintf("  decoded bits:  ");
	needs_comma = 0;
	for (i = 0, bit = 1; i < sizeof(mbits) * 8; ++i, bit <<= 1) {
		if ((mbits & bit) == 0)
			continue;
		bit_name = msgh_bit_decode64((mach_msg_bits_t)bit);
		if (bit_name)
			kprintf("%s%s", needs_comma ? "," : "", bit_name);
		else
			kprintf("%sunknown(0x%x),", needs_comma ? "," : "", bit);
		++needs_comma;
	}
	if (msgh->msgh_bits & ~MACH_MSGH_BITS_USED) {
		kprintf("%sunused=0x%x,", needs_comma ? "," : "",
		       msgh->msgh_bits & ~MACH_MSGH_BITS_USED);
	}
	kprintf("\n");

	needs_comma = 1;
	if (msgh->msgh_remote_port) {
		kprintf("  remote=%p(", msgh->msgh_remote_port);
		ipc_print_type_name64(MACH_MSGH_BITS_REMOTE(msgh->msgh_bits));
		kprintf(")");
	} else {
		kprintf("  remote=null");
	}

	if (msgh->msgh_local_port) {
		kprintf("%slocal=%p(", needs_comma ? "," : "",
		       msgh->msgh_local_port);
		ipc_print_type_name64(MACH_MSGH_BITS_LOCAL(msgh->msgh_bits));
		kprintf(")\n");
	} else {
		kprintf("local=null\n");
	}

	kprintf("  msgh_id=%d, size=%d\n",
		msgh->msgh_id,
		msgh->msgh_size);

	if (mbits & MACH_MSGH_BITS_COMPLEX) {	
		ipc_msg_print_untyped64((mach_msg_body_t *) (msgh + 1));
	}

	ipc_msg_body_print64((void *)(msgh + 1), msgh->msgh_size);
}


const char *
mm_copy_options_string64(
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
ipc_msg_print_untyped64(
	mach_msg_body_t		*body)
{
    mach_msg_descriptor_t	*saddr, *send;
    mach_msg_descriptor_type_t	type;

    kprintf("  %d descriptors: \n", body->msgh_descriptor_count);

    saddr = (mach_msg_descriptor_t *) (body + 1);
    send = saddr + body->msgh_descriptor_count;

    for ( ; saddr < send; saddr++ ) {
	
	type = saddr->type.type;

	switch (type) {
	    
	    case MACH_MSG_PORT_DESCRIPTOR: {
		mach_msg_port_descriptor_t *dsc;

		dsc = &saddr->port;
		kprintf("    PORT name = %p disp = ", dsc->name);
		ipc_print_type_name64(dsc->disposition);
		kprintf("\n");
		break;
	    }
	    case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
	    case MACH_MSG_OOL_DESCRIPTOR: {
		mach_msg_ool_descriptor_t *dsc;
		
		dsc = (mach_msg_ool_descriptor_t *) &saddr->out_of_line;
		kprintf("    OOL%s addr = %p size = 0x%x copy = %s %s\n",
			type == MACH_MSG_OOL_DESCRIPTOR ? "" : " VOLATILE",
			dsc->address, dsc->size,
			mm_copy_options_string64(dsc->copy),
			dsc->deallocate ? "DEALLOC" : "");
		break;
	    } 
	    case MACH_MSG_OOL_PORTS_DESCRIPTOR : {
		mach_msg_ool_ports_descriptor_t *dsc;

		dsc = (mach_msg_ool_ports_descriptor_t *) &saddr->ool_ports;

		kprintf("    OOL_PORTS addr = %p count = 0x%x ",
		          dsc->address, dsc->count);
		kprintf("disp = ");
		ipc_print_type_name64(dsc->disposition);
		kprintf(" copy = %s %s\n",
		       mm_copy_options_string64(dsc->copy),
		       dsc->deallocate ? "DEALLOC" : "");
		break;
	    }

	    default: {
		kprintf("    UNKNOWN DESCRIPTOR 0x%x\n", type);
		break;
	    }
	}
    }
}

#define	DEBUG_IPC_KMSG_PRINT(kmsg,string)	\
	if (DEBUG_KPRINT_SYSCALL_PREDICATE(DEBUG_KPRINT_SYSCALL_IPC_MASK)) {	\
		ipc_kmsg_print64(kmsg, string);	\
	}
#define	DEBUG_IPC_MSG_BODY_PRINT(body,size)	\
	if (DEBUG_KPRINT_SYSCALL_PREDICATE(DEBUG_KPRINT_SYSCALL_IPC_MASK)) { 	\
		ipc_msg_body_print64(body,size);\
	}
#else /* !DEBUG_MSGS_K64 */
#define DEBUG_IPC_KMSG_PRINT(kmsg,string)
#define	DEBUG_IPC_MSG_BODY_PRINT(body,size)
#endif  /* !DEBUG_MSGS_K64 */

extern vm_map_t		ipc_kernel_copy_map;
extern vm_size_t	ipc_kmsg_max_space;
extern vm_size_t	ipc_kmsg_max_vm_space;
extern vm_size_t	ipc_kmsg_max_body_space;
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

#define DESC_SIZE_ADJUSTMENT	((mach_msg_size_t)(sizeof(mach_msg_ool_descriptor64_t) - \
				 sizeof(mach_msg_ool_descriptor32_t)))

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

	/*
	 * LP64support -
	 * Pad the allocation in case we need to expand the
	 * message descrptors for user spaces with pointers larger than
	 * the kernel's own, or vice versa.  We don't know how many descriptors
	 * there are yet, so just assume the whole body could be
	 * descriptors (if there could be any at all).
	 *
	 * The expansion space is left in front of the header,
	 * because it is easier to pull the header and descriptors
	 * forward as we process them than it is to push all the
	 * data backwards.
	 */
	mach_msg_size_t size = msg_and_trailer_size - MAX_TRAILER_SIZE;

	/* compare against implementation upper limit for the body */
	if (size > ipc_kmsg_max_body_space)
		return IKM_NULL;

	if (size > sizeof(mach_msg_base_t)) {
		mach_msg_size_t max_desc = (mach_msg_size_t)(((size - sizeof(mach_msg_base_t)) /
				           sizeof(mach_msg_ool_descriptor32_t)) *
				           DESC_SIZE_ADJUSTMENT);

		/* make sure expansion won't cause wrap */
		if (msg_and_trailer_size > MACH_MSG_SIZE_MAX - max_desc)
			return IKM_NULL;

		max_expanded_size = msg_and_trailer_size + max_desc;
	} else
		max_expanded_size = msg_and_trailer_size;

	if (max_expanded_size < IKM_SAVED_MSG_SIZE)
		max_expanded_size = IKM_SAVED_MSG_SIZE; 	/* round up for ikm_cache */

	if (max_expanded_size == IKM_SAVED_MSG_SIZE) {
		struct ikm_cache	*cache;
		unsigned int		i;

		disable_preemption();
		cache = &PROCESSOR_DATA(current_processor(), ikm_cache);
		if ((i = cache->avail) > 0) {
			assert(i <= IKM_STASH);
			kmsg = cache->entries[--i];
			cache->avail = i;
			enable_preemption();
			ikm_check_init(kmsg, max_expanded_size);
			ikm_set_header(kmsg, msg_and_trailer_size);
			return (kmsg);
		}
		enable_preemption();
		kmsg = (ipc_kmsg_t)zalloc(ipc_kmsg_zone);
	} else {
		kmsg = (ipc_kmsg_t)kalloc(ikm_plus_overhead(max_expanded_size));
	}

	if (kmsg != IKM_NULL) {
		ikm_init(kmsg, max_expanded_size);
		ikm_set_header(kmsg, msg_and_trailer_size);
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

#if CONFIG_MACF_MACH
	if (kmsg->ikm_sender != NULL) {
		task_deallocate(kmsg->ikm_sender);
		kmsg->ikm_sender = NULL;
	}
#endif

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
			ip_release(port);
			return;
		}
                ip_unlock(port);
		ip_release(port); /* May be last reference */
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
	assert((kmsg->ikm_next = IKM_BOGUS) == IKM_BOGUS);
	assert((kmsg->ikm_prev = IKM_BOGUS) == IKM_BOGUS);
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
	/*
	 *	Destroying a message can cause more messages to be destroyed.
	 *	Curtail recursion by putting messages on the deferred
	 *	destruction queue.  If this was the first message on the
	 *	queue, this instance must process the full queue.
	 */
	if (ipc_kmsg_delayed_destroy(kmsg))
		ipc_kmsg_reap_delayed();
}

/*
 *	Routine:	ipc_kmsg_delayed_destroy
 *	Purpose:
 *		Enqueues a kernel message for deferred destruction.
 *	Returns:
 *		Boolean indicator that the caller is responsible to reap
 *		deferred messages.
 */

boolean_t ipc_kmsg_delayed_destroy(
	ipc_kmsg_t kmsg)
{
	ipc_kmsg_queue_t queue = &(current_thread()->ith_messages);
	boolean_t first = ipc_kmsg_queue_empty(queue);

	ipc_kmsg_enqueue(queue, kmsg);
	return first;
}

/*
 *	Routine:	ipc_kmsg_destroy_queue
 *	Purpose:
 *		Destroys messages from the per-thread
 *		deferred reaping queue.
 *	Conditions:
 *		No locks held.
 */

void
ipc_kmsg_reap_delayed(void)
{
	ipc_kmsg_queue_t queue = &(current_thread()->ith_messages);
	ipc_kmsg_t kmsg;

	/*
	 * must leave kmsg in queue while cleaning it to assure
	 * no nested calls recurse into here.
	 */
	while ((kmsg = ipc_kmsg_queue_first(queue)) != IKM_NULL) {
		ipc_kmsg_clean(kmsg);
		ipc_kmsg_rmqueue(queue, kmsg);
		ipc_kmsg_free(kmsg);
	}
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
static unsigned int _ipc_kmsg_clean_invalid_desc = 0;
void
ipc_kmsg_clean_body(
	__unused ipc_kmsg_t	kmsg,
	mach_msg_type_number_t	number,
	mach_msg_descriptor_t	*saddr)
{
    mach_msg_type_number_t	i;

    if ( number == 0 )
	return;

    for (i = 0 ; i < number; i++, saddr++ ) {
	
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

		dsc = (mach_msg_ool_descriptor_t *)&saddr->out_of_line;
		
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

		dsc = (mach_msg_ool_ports_descriptor_t	*)&saddr->ool_ports;
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
		     (vm_size_t) dsc->count * sizeof(mach_port_t));
		break;
	    }
	    default : {
		    _ipc_kmsg_clean_invalid_desc++; /* don't understand this type of descriptor */
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
	ipc_object_destroy_dest(object, MACH_MSGH_BITS_REMOTE(mbits));

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
		ipc_object_destroy_dest(object, MACH_MSGH_BITS_REMOTE(mbits));

	object = (ipc_object_t) kmsg->ikm_header->msgh_local_port;
	if (IO_VALID(object))
		ipc_object_destroy(object, MACH_MSGH_BITS_LOCAL(mbits));

	if (mbits & MACH_MSGH_BITS_COMPLEX) {
		mach_msg_body_t *body;

		body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
		ipc_kmsg_clean_body(kmsg, body->msgh_descriptor_count,
				    (mach_msg_descriptor_t *)(body + 1));
	}

#if CONFIG_MACF_MACH
	if (kmsg->ikm_sender != NULL) {
		task_deallocate(kmsg->ikm_sender);
		kmsg->ikm_sender = NULL;
	}
#endif
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
 *	Routine:	ipc_kmsg_prealloc
 *	Purpose:
 *		Wraper to ipc_kmsg_alloc() to account for
 *		header expansion requirements.
 */
ipc_kmsg_t
ipc_kmsg_prealloc(mach_msg_size_t size)
{
#if defined(__LP64__)
	if (size > MACH_MSG_SIZE_MAX - LEGACY_HEADER_SIZE_DELTA)
		return IKM_NULL;

	size += LEGACY_HEADER_SIZE_DELTA;
#endif
	return ipc_kmsg_alloc(size);
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
 *		MACH_SEND_TOO_LARGE	Message too large to ever be sent.
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
	mach_msg_legacy_base_t	    legacy_base;
	mach_msg_size_t             len_copied;
	legacy_base.body.msgh_descriptor_count = 0;

	if ((size < sizeof(mach_msg_legacy_header_t)) || (size & 3))
		return MACH_SEND_MSG_TOO_SMALL;

	if (size > ipc_kmsg_max_body_space)
		return MACH_SEND_TOO_LARGE;

	if(size == sizeof(mach_msg_legacy_header_t))
		len_copied = sizeof(mach_msg_legacy_header_t);
	else
		len_copied = sizeof(mach_msg_legacy_base_t);

	if (copyinmsg(msg_addr, (char *)&legacy_base, len_copied))
		return MACH_SEND_INVALID_DATA;

	msg_addr += sizeof(legacy_base.header);
#if defined(__LP64__)
	size += LEGACY_HEADER_SIZE_DELTA;
#endif
	if (DEBUG_KPRINT_SYSCALL_PREDICATE(DEBUG_KPRINT_SYSCALL_IPC_MASK)) {
		unsigned int j;
		for (j=0; j<sizeof(legacy_base.header); j++) {
			kprintf("%02x\n", ((unsigned char*)&legacy_base.header)[j]);
		}
	}

	msg_and_trailer_size = size + MAX_TRAILER_SIZE;
	kmsg = ipc_kmsg_alloc(msg_and_trailer_size);
	if (kmsg == IKM_NULL)
		return MACH_SEND_NO_BUFFER;

	kmsg->ikm_header->msgh_size			= size;
	kmsg->ikm_header->msgh_bits			= legacy_base.header.msgh_bits;
	kmsg->ikm_header->msgh_remote_port	= CAST_MACH_NAME_TO_PORT(legacy_base.header.msgh_remote_port);
	kmsg->ikm_header->msgh_local_port	= CAST_MACH_NAME_TO_PORT(legacy_base.header.msgh_local_port);
	kmsg->ikm_header->msgh_reserved		= legacy_base.header.msgh_reserved;
	kmsg->ikm_header->msgh_id			= legacy_base.header.msgh_id;

	DEBUG_KPRINT_SYSCALL_IPC("ipc_kmsg_get header:\n"
							 "  size:		0x%.8x\n"
							 "  bits:		0x%.8x\n"
							 "  remote_port:	%p\n"
							 "  local_port:	%p\n"
							 "  reserved:	0x%.8x\n"
							 "  id:		%.8d\n",
							 kmsg->ikm_header->msgh_size,
							 kmsg->ikm_header->msgh_bits,
							 kmsg->ikm_header->msgh_remote_port,
							 kmsg->ikm_header->msgh_local_port,
							 kmsg->ikm_header->msgh_reserved,
							 kmsg->ikm_header->msgh_id);

	if (copyinmsg(msg_addr, (char *)(kmsg->ikm_header + 1), size - (mach_msg_size_t)sizeof(mach_msg_header_t))) {
		ipc_kmsg_free(kmsg);
		return MACH_SEND_INVALID_DATA;
	}

	if (DEBUG_KPRINT_SYSCALL_PREDICATE(DEBUG_KPRINT_SYSCALL_IPC_MASK))
	{
		kprintf("body: size: %lu\n", (size - sizeof(mach_msg_header_t)));
		uint32_t i;
		for(i=0;i*4 < (size - sizeof(mach_msg_header_t));i++)
		{
			kprintf("%.4x\n",((uint32_t *)(kmsg->ikm_header + 1))[i]);
		}
	}
	DEBUG_IPC_KMSG_PRINT(kmsg, "ipc_kmsg_get()");

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

#if CONFIG_MACF_MACH
	/* XXX - why do we zero sender labels here instead of in mach_msg()? */
	task_t cur = current_task();
	if (cur) {
		task_reference(cur);
		kmsg->ikm_sender = cur;
	} else
		trailer->msgh_labels.sender = 0;
#else
	trailer->msgh_labels.sender = 0;
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
	assert((size & 3) == 0);

	dest_port = (ipc_port_t)msg->msgh_remote_port;

	msg_and_trailer_size = size + MAX_TRAILER_SIZE;

	/*
	 * See if the port has a pre-allocated kmsg for kernel
	 * clients.  These are set up for those kernel clients
	 * which cannot afford to wait.
	 */
	if (IP_VALID(dest_port) && IP_PREALLOC(dest_port)) {
		mach_msg_size_t max_desc = 0;

		ip_lock(dest_port);
		if (!ip_active(dest_port)) {
			ip_unlock(dest_port);
			return MACH_SEND_NO_BUFFER;
		}
		assert(IP_PREALLOC(dest_port));
		kmsg = dest_port->ip_premsg;
		if (ikm_prealloc_inuse(kmsg)) {
			ip_unlock(dest_port);
			return MACH_SEND_NO_BUFFER;
		}
#if !defined(__LP64__)
		if (msg->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
			assert(size > sizeof(mach_msg_base_t));
			max_desc = ((mach_msg_base_t *)msg)->body.msgh_descriptor_count *
				DESC_SIZE_ADJUSTMENT;
		}
#endif
		if (msg_and_trailer_size > kmsg->ikm_size - max_desc) {
			ip_unlock(dest_port);
			return MACH_SEND_TOO_LARGE;
		}
		ikm_prealloc_set_inuse(kmsg, dest_port);
		ikm_set_header(kmsg, msg_and_trailer_size);
		ip_unlock(dest_port);
	}
	else
	{
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

	trailer->msgh_labels.sender = 0;

#if CONFIG_MACF_MACH
	kmsg->ikm_sender = NULL;
#endif
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
 *		MACH_SEND_INVALID_DEST	Caller still has message.
 */


mach_msg_return_t
ipc_kmsg_send(
	ipc_kmsg_t		kmsg,
	mach_msg_option_t	option,
	mach_msg_timeout_t	send_timeout)
{
	ipc_port_t port;
	mach_msg_return_t error = MACH_MSG_SUCCESS;
	spl_t s;

#if IMPORTANCE_INHERITANCE
	boolean_t did_importance = FALSE;
#if IMPORTANCE_DEBUG
	mach_msg_id_t imp_msgh_id = -1;
	int           sender_pid  = -1;
#endif /* IMPORTANCE_DEBUG */
#endif /* IMPORTANCE_INHERITANCE */

	/* don't allow the creation of a circular loop */
	if (kmsg->ikm_header->msgh_bits & MACH_MSGH_BITS_CIRCULAR) {
		ipc_kmsg_destroy(kmsg);
		return MACH_MSG_SUCCESS;
	}

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

#if IMPORTANCE_INHERITANCE
 retry:
#endif /* IMPORTANCE_INHERITANCE */

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
		ip_unlock(port);
		ip_release(port);
		kmsg->ikm_header->msgh_remote_port = MACH_PORT_NULL;
		ipc_kmsg_destroy(kmsg);
		return MACH_MSG_SUCCESS;
	}

#if IMPORTANCE_INHERITANCE
	/*
	 * Need to see if this message needs importance donation and/or
	 * propagation.  That routine can drop the port lock.  If it does
	 * we'll have to revalidate the destination.
	 */
	if ((did_importance == FALSE) &&
	    (port->ip_impdonation != 0) &&
	    ((option & MACH_SEND_NOIMPORTANCE) == 0) &&
	    (((option & MACH_SEND_IMPORTANCE) != 0) ||
	     (task_is_importance_donor(current_task())))) {

		did_importance = TRUE;
		kmsg->ikm_header->msgh_bits |= MACH_MSGH_BITS_RAISEIMP;
				
#if IMPORTANCE_DEBUG
		if (kdebug_enable) {
			mach_msg_max_trailer_t *dbgtrailer = (mach_msg_max_trailer_t *)
			        ((vm_offset_t)kmsg->ikm_header + round_msg(kmsg->ikm_header->msgh_size));
			sender_pid = dbgtrailer->msgh_audit.val[5];
			imp_msgh_id = kmsg->ikm_header->msgh_id;

			KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_MSG, IMP_MSG_SEND)) | DBG_FUNC_START,
			                           audit_token_pid_from_task(current_task()), sender_pid, imp_msgh_id, 0, 0);
		}
#endif /* IMPORTANCE_DEBUG */

		if (ipc_port_importance_delta(port, 1) == TRUE) {
			ip_lock(port);
			goto retry;
		}
	}
#endif /* IMPORTANCE_INHERITANCE */

	/*
	 * We have a valid message and a valid reference on the port.
	 * we can unlock the port and call mqueue_send() on its message
	 * queue. Lock message queue while port is locked.
	 */
	s = splsched();
	imq_lock(&port->ip_messages);
	ip_unlock(port);

	error = ipc_mqueue_send(&port->ip_messages, kmsg, option, 
			send_timeout, s);

#if IMPORTANCE_INHERITANCE
	if (did_importance == TRUE) {
		__unused int importance_cleared = 0;
		switch (error) {
			case MACH_SEND_TIMED_OUT:
			case MACH_SEND_NO_BUFFER:
			case MACH_SEND_INTERRUPTED:
				/*
				 * We still have the kmsg and its
				 * reference on the port.  But we
				 * have to back out the importance
				 * boost.
				 *
				 * The port could have changed hands,
				 * be inflight to another destination,
				 * etc...  But in those cases our
				 * back-out will find the new owner
				 * (and all the operations that
				 * transferred the right should have
				 * applied their own boost adjustments
				 * to the old owner(s)).
				 */
				importance_cleared = 1;
				ip_lock(port);
				if (ipc_port_importance_delta(port, -1) == FALSE)
					ip_unlock(port);
				break;

			case MACH_SEND_INVALID_DEST:
 				/*
 				 * In the case that the receive right has
 				 * gone away, the assertion count for the
 				 * message we were trying to enqueue was
 				 * already subtracted from the destination
 				 * task (as part of port destruction).
 				 */
 				break;

			case MACH_MSG_SUCCESS:
			default:
				break;
		}
#if IMPORTANCE_DEBUG
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE, (IMPORTANCE_CODE(IMP_MSG, IMP_MSG_SEND)) | DBG_FUNC_END,
		                          audit_token_pid_from_task(current_task()), sender_pid, imp_msgh_id, importance_cleared, 0);
#endif /* IMPORTANCE_DEBUG */
	}
#endif /* IMPORTANCE_INHERITANCE */

	/*
	 * If the port has been destroyed while we wait, treat the message
	 * as a successful delivery (like we do for an inactive port).
	 */
	if (error == MACH_SEND_INVALID_DEST) {
		kmsg->ikm_header->msgh_remote_port = MACH_PORT_NULL;
		ipc_kmsg_destroy(kmsg);
		return MACH_MSG_SUCCESS;
	}
	return error;
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

	DEBUG_IPC_KMSG_PRINT(kmsg, "ipc_kmsg_put()");


	DEBUG_KPRINT_SYSCALL_IPC("ipc_kmsg_put header:\n"
							 "  size:		0x%.8x\n"
							 "  bits:		0x%.8x\n"
							 "  remote_port:	%p\n"
							 "  local_port:	%p\n"
							 "  reserved:	0x%.8x\n"
							 "  id:		%.8d\n",
							 kmsg->ikm_header->msgh_size,
							 kmsg->ikm_header->msgh_bits,
							 kmsg->ikm_header->msgh_remote_port,
							 kmsg->ikm_header->msgh_local_port,
							 kmsg->ikm_header->msgh_reserved,
							 kmsg->ikm_header->msgh_id);

#if defined(__LP64__)
	if (current_task() != kernel_task) { /* don't if receiver expects fully-cooked in-kernel msg; ux_exception */
		mach_msg_legacy_header_t *legacy_header = 
			(mach_msg_legacy_header_t *)((vm_offset_t)(kmsg->ikm_header) + LEGACY_HEADER_SIZE_DELTA);

		mach_msg_bits_t		bits		= kmsg->ikm_header->msgh_bits;
		mach_msg_size_t		msg_size	= kmsg->ikm_header->msgh_size;
		mach_port_name_t	remote_port	= CAST_MACH_PORT_TO_NAME(kmsg->ikm_header->msgh_remote_port);
		mach_port_name_t	local_port	= CAST_MACH_PORT_TO_NAME(kmsg->ikm_header->msgh_local_port);
		mach_msg_size_t 	reserved	= kmsg->ikm_header->msgh_reserved;
		mach_msg_id_t		id			= kmsg->ikm_header->msgh_id;

		legacy_header->msgh_id			= id;
		legacy_header->msgh_reserved	= reserved;
		legacy_header->msgh_local_port	= local_port;
		legacy_header->msgh_remote_port	= remote_port;
		legacy_header->msgh_size		= msg_size - LEGACY_HEADER_SIZE_DELTA;
		legacy_header->msgh_bits		= bits;

		size -= LEGACY_HEADER_SIZE_DELTA;
		kmsg->ikm_header = (mach_msg_header_t *)legacy_header;
	}
#endif

	if (DEBUG_KPRINT_SYSCALL_PREDICATE(DEBUG_KPRINT_SYSCALL_IPC_MASK)) {
		kprintf("ipc_kmsg_put header+body: %d\n", (size));
		uint32_t i;
		for(i=0;i*4 < size;i++)
		{
			kprintf("%.4x\n",((uint32_t *)kmsg->ikm_header)[i]);
		}
		kprintf("type: %d\n", ((mach_msg_type_descriptor_t *)(((mach_msg_base_t *)kmsg->ikm_header)+1))->type);
	}
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
 *	Conditions:
 *		Nothing locked.
 *	Returns:
 *		MACH_MSG_SUCCESS	Successful copyin.
 *		MACH_SEND_INVALID_HEADER
 *			Illegal value in the message header bits.
 *		MACH_SEND_INVALID_DEST	The space is dead.
 *		MACH_SEND_INVALID_DEST	Can't copyin destination port.
 *			(Either KERN_INVALID_NAME or KERN_INVALID_RIGHT.)
 *		MACH_SEND_INVALID_REPLY	Can't copyin reply port.
 *			(Either KERN_INVALID_NAME or KERN_INVALID_RIGHT.)
 */

mach_msg_return_t
ipc_kmsg_copyin_header(
	mach_msg_header_t	*msg,
	ipc_space_t		space,
	mach_msg_option_t	*optionp)
{
	mach_msg_bits_t mbits = msg->msgh_bits & MACH_MSGH_BITS_USER;
	mach_port_name_t dest_name = CAST_MACH_PORT_TO_NAME(msg->msgh_remote_port);
	mach_port_name_t reply_name = CAST_MACH_PORT_TO_NAME(msg->msgh_local_port);
	kern_return_t kr;

	mach_msg_type_name_t dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	mach_msg_type_name_t reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	ipc_object_t dest_port, reply_port;
	ipc_entry_t dest_entry, reply_entry;
	ipc_port_t dest_soright, reply_soright;
	ipc_port_t release_port = IP_NULL;

#if IMPORTANCE_INHERITANCE
	int assertcnt = 0;
	boolean_t needboost = FALSE;
#endif /* IMPORTANCE_INHERITANCE */

	queue_head_t links_data;
	queue_t links = &links_data;
	wait_queue_link_t wql;

	queue_init(links);

	if ((mbits != msg->msgh_bits) ||
	    (!MACH_MSG_TYPE_PORT_ANY_SEND(dest_type)) ||
	    ((reply_type == 0) ?
	     (reply_name != MACH_PORT_NULL) :
	     !MACH_MSG_TYPE_PORT_ANY_SEND(reply_type)))
		return MACH_SEND_INVALID_HEADER;

	reply_soright = IP_NULL; /* in case we go to invalid dest early */

	is_write_lock(space);
	if (!is_active(space))
		goto invalid_dest;

	if (!MACH_PORT_VALID(dest_name))
		goto invalid_dest;

#if CONFIG_MACF_MACH
	/*
	 * We do the port send check here instead of in ipc_kmsg_send()
	 * because copying the header involves copying the port rights too
	 * and we need to do the send check before anything is actually copied.
	 */
	dest_entry = ipc_entry_lookup(space, dest_name);
	if (dest_entry != IE_NULL) {
		int error = 0;
		ipc_port_t port = (ipc_port_t) dest_entry->ie_object;
		if (port == IP_NULL)
			goto invalid_dest;
		ip_lock(port);
		if (ip_active(port)) {
			task_t self = current_task();
			tasklabel_lock(self);
			error = mac_port_check_send(&self->maclabel,
			    &port->ip_label);
			tasklabel_unlock(self);
		}
		ip_unlock(port);
		if (error != 0)
			goto invalid_dest;
	}
#endif

	if (dest_name == reply_name) {
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

		dest_entry = ipc_entry_lookup(space, name);
		if (dest_entry == IE_NULL)
			goto invalid_dest;

		reply_entry = dest_entry;
		assert(reply_type != 0); /* because name not null */

		if (!ipc_right_copyin_check(space, name, reply_entry, reply_type))
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

#if IMPORTANCE_INHERITANCE
			kr = ipc_right_copyin(space, name, dest_entry,
					      dest_type, FALSE,
					      &dest_port, &dest_soright,
					      &release_port,
					      &assertcnt,
					      links);
			assert(assertcnt == 0);
#else
			kr = ipc_right_copyin(space, name, dest_entry,
					      dest_type, FALSE,
					      &dest_port, &dest_soright,
					      &release_port,
					      links);
#endif /* IMPORTANCE_INHERITANCE */

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
			assert(dest_soright == IP_NULL);

#if IMPORTANCE_INHERITANCE
			kr = ipc_right_copyin(space, name, reply_entry,
					      reply_type, TRUE,
					      &reply_port, &reply_soright,
					      &release_port,
					      &assertcnt,
					      links);
			assert(assertcnt == 0);
#else
			kr = ipc_right_copyin(space, name, reply_entry,
					      reply_type, TRUE,
					      &reply_port, &reply_soright,
					      &release_port,
					      links);
#endif /* IMPORTANCE_INHERITANCE */

			assert(kr == KERN_SUCCESS);
			assert(reply_port == dest_port);
			assert(reply_entry->ie_bits & MACH_PORT_TYPE_RECEIVE);
			assert(reply_soright == IP_NULL);
		} else if ((dest_type == MACH_MSG_TYPE_COPY_SEND) &&
			   (reply_type == MACH_MSG_TYPE_COPY_SEND)) {
			/*
			 *	To make this atomic, just do one copy-send,
			 *	and dup the send right we get out.
			 */

#if IMPORTANCE_INHERITANCE
			kr = ipc_right_copyin(space, name, dest_entry,
					      dest_type, FALSE,
					      &dest_port, &dest_soright,
					      &release_port,
					      &assertcnt,
					      links);
			assert(assertcnt == 0);
#else
			kr = ipc_right_copyin(space, name, dest_entry,
					      dest_type, FALSE,
					      &dest_port, &dest_soright,
					      &release_port,
					      links);
#endif /* IMPORTANCE_INHERITANCE */

			if (kr != KERN_SUCCESS)
				goto invalid_dest;

			assert(dest_entry->ie_bits & MACH_PORT_TYPE_SEND);
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

			kr = ipc_right_copyin_two(space, name, dest_entry,
						  &dest_port, &dest_soright,
						  &release_port);
			if (kr != KERN_SUCCESS)
				goto invalid_dest;

			/* the entry might need to be deallocated */
			if (IE_BITS_TYPE(dest_entry->ie_bits) == MACH_PORT_TYPE_NONE) {
				ipc_entry_dealloc(space, name, dest_entry);
				dest_entry = IE_NULL;
			}

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

#if IMPORTANCE_INHERITANCE
			kr = ipc_right_copyin(space, name, dest_entry,
					      MACH_MSG_TYPE_MOVE_SEND, FALSE,
					      &dest_port, &soright,
					      &release_port,
					      &assertcnt,
					      links);
			assert(assertcnt == 0);
#else
			kr = ipc_right_copyin(space, name, dest_entry,
					      MACH_MSG_TYPE_MOVE_SEND, FALSE,
					      &dest_port, &soright,
					      &release_port,
					      links);
#endif /* IMPORTANCE_INHERITANCE */

			if (kr != KERN_SUCCESS)
				goto invalid_dest;

			/* the entry might need to be deallocated */

			if (IE_BITS_TYPE(dest_entry->ie_bits) == MACH_PORT_TYPE_NONE) {
				ipc_entry_dealloc(space, name, dest_entry);
				dest_entry = IE_NULL;
			}

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
		/*
		 *	No reply port!  This is an easy case
		 *	to make atomic.  Just copyin the destination.
		 */

		dest_entry = ipc_entry_lookup(space, dest_name);
		if (dest_entry == IE_NULL)
			goto invalid_dest;

#if IMPORTANCE_INHERITANCE
		kr = ipc_right_copyin(space, dest_name, dest_entry,
				      dest_type, FALSE,
				      &dest_port, &dest_soright,
				      &release_port,
				      &assertcnt,
				      links);
		assert(assertcnt == 0);
#else
		kr = ipc_right_copyin(space, dest_name, dest_entry,
				      dest_type, FALSE,
				      &dest_port, &dest_soright,
				      &release_port,
				      links);
#endif /* IMPORTANCE_INHERITANCE */

		if (kr != KERN_SUCCESS)
			goto invalid_dest;

		/* the entry might need to be deallocated */
		if (IE_BITS_TYPE(dest_entry->ie_bits) == MACH_PORT_TYPE_NONE) {
			ipc_entry_dealloc(space, dest_name, dest_entry);
			dest_entry = IE_NULL;
		}

		reply_port = (ipc_object_t)CAST_MACH_NAME_TO_PORT(reply_name);
		reply_soright = IP_NULL;
	} else {
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
		 * I will be making the change soon in rdar://problem/6275821.
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

#if IMPORTANCE_INHERITANCE
		kr = ipc_right_copyin(space, dest_name, dest_entry,
				      dest_type, FALSE,
				      &dest_port, &dest_soright,
				      &release_port,
				      &assertcnt,
				      links);
		assert(assertcnt == 0);
#else
		kr = ipc_right_copyin(space, dest_name, dest_entry,
				      dest_type, FALSE,
				      &dest_port, &dest_soright,
				      &release_port,
				      links);
#endif /* IMPORTANCE_INHERITANCE */

		if (kr != KERN_SUCCESS)
			goto invalid_dest;

		assert(IO_VALID(dest_port));

#if IMPORTANCE_INHERITANCE
		kr = ipc_right_copyin(space, reply_name, reply_entry,
				      reply_type, TRUE,
				      &reply_port, &reply_soright,
				      &release_port,
				      &assertcnt,
				      links);
		assert(assertcnt == 0);
#else
		kr = ipc_right_copyin(space, reply_name, reply_entry,
				      reply_type, TRUE,
				      &reply_port, &reply_soright,
				      &release_port,
				      links);
#endif /* IMPORTANCE_INHERITANCE */

		assert(kr == KERN_SUCCESS);

		/* the entries might need to be deallocated */

		if (IE_BITS_TYPE(reply_entry->ie_bits) == MACH_PORT_TYPE_NONE) {
			ipc_entry_dealloc(space, reply_name, reply_entry);
			reply_entry = IE_NULL;
		}

		if (IE_BITS_TYPE(dest_entry->ie_bits) == MACH_PORT_TYPE_NONE) {
			ipc_entry_dealloc(space, dest_name, dest_entry);
			dest_entry = IE_NULL;
		}
	}

	dest_type = ipc_object_copyin_type(dest_type);
	reply_type = ipc_object_copyin_type(reply_type);

	/*
	 * JMM - Without rdar://problem/6275821, this is the last place we can
	 * re-arm the send-possible notifications.  It may trigger unexpectedly
	 * early (send may NOT have failed), but better than missing.  We assure
	 * we won't miss by forcing MACH_SEND_ALWAYS if we got past arming.
	 */
	if (((*optionp & MACH_SEND_NOTIFY) != 0) && 
	    dest_type != MACH_MSG_TYPE_PORT_SEND_ONCE &&
	    dest_entry != IE_NULL && dest_entry->ie_request != IE_REQ_NONE) {
		ipc_port_t dport = (ipc_port_t)dest_port;

		assert(dport != IP_NULL);
		ip_lock(dport);
		if (ip_active(dport) && dport->ip_receiver != ipc_space_kernel) {
			if (ip_full(dport)) {
#if IMPORTANCE_INHERITANCE
				needboost = ipc_port_request_sparm(dport, dest_name, 
							dest_entry->ie_request,
							(*optionp & MACH_SEND_NOIMPORTANCE));
				if (needboost == FALSE)
					ip_unlock(dport);
#else

				ipc_port_request_sparm(dport, dest_name, dest_entry->ie_request);
				ip_unlock(dport);
#endif /* IMPORTANCE_INHERITANCE */
			} else {
				*optionp |= MACH_SEND_ALWAYS;
				ip_unlock(dport);
			}
		} else {
			ip_unlock(dport);
		}
	}

	is_write_unlock(space);

#if IMPORTANCE_INHERITANCE
	/* 
	 * If our request is the first boosting send-possible
	 * notification this cycle, push the boost down the
	 * destination port.
	 */
	if (needboost == TRUE) {
		ipc_port_t dport = (ipc_port_t)dest_port;

		/* dport still locked from above */
		if (ipc_port_importance_delta(dport, 1) == FALSE)
			ip_unlock(dport);
	}
#endif /* IMPORTANCE_INHERITANCE */

	if (dest_soright != IP_NULL)
		ipc_notify_port_deleted(dest_soright, dest_name);

	if (reply_soright != IP_NULL)
		ipc_notify_port_deleted(reply_soright, reply_name);

	msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
			  MACH_MSGH_BITS(dest_type, reply_type));
	msg->msgh_remote_port = (ipc_port_t)dest_port;
	msg->msgh_local_port = (ipc_port_t)reply_port;

	while(!queue_empty(links)) {
		wql = (wait_queue_link_t) dequeue(links);
		wait_queue_link_free(wql);
	}

	if (release_port != IP_NULL)
		ip_release(release_port);


	return MACH_MSG_SUCCESS;

invalid_reply:
	is_write_unlock(space);

	while(!queue_empty(links)) {
		wql = (wait_queue_link_t) dequeue(links);
		wait_queue_link_free(wql);
	}

	if (release_port != IP_NULL)
		ip_release(release_port);

	return MACH_SEND_INVALID_REPLY;

invalid_dest:
	is_write_unlock(space);

	while(!queue_empty(links)) {
		wql = (wait_queue_link_t) dequeue(links);
		wait_queue_link_free(wql);
	}

	if (release_port != IP_NULL)
		ip_release(release_port);

	if (reply_soright != IP_NULL)
		ipc_notify_port_deleted(reply_soright, reply_name);

	return MACH_SEND_INVALID_DEST;
}

mach_msg_descriptor_t *ipc_kmsg_copyin_port_descriptor(
        volatile mach_msg_port_descriptor_t *dsc,
        mach_msg_legacy_port_descriptor_t *user_dsc,
        ipc_space_t space,
        ipc_object_t dest,
        ipc_kmsg_t kmsg,
        mach_msg_return_t *mr);

void ipc_print_type_name(
   int type_name);
mach_msg_descriptor_t *
ipc_kmsg_copyin_port_descriptor(
        volatile mach_msg_port_descriptor_t *dsc,
        mach_msg_legacy_port_descriptor_t *user_dsc_in,
        ipc_space_t space,
        ipc_object_t dest,
        ipc_kmsg_t kmsg,
        mach_msg_return_t *mr)
{
    volatile mach_msg_legacy_port_descriptor_t *user_dsc = user_dsc_in;
    mach_msg_type_name_t 	user_disp;
    mach_msg_type_name_t	result_disp;
    mach_port_name_t		name;
    ipc_object_t 			object;

    user_disp = user_dsc->disposition;
    result_disp = ipc_object_copyin_type(user_disp);

    name = (mach_port_name_t)user_dsc->name;
    if (MACH_PORT_VALID(name)) {

        kern_return_t kr = ipc_object_copyin(space, name, user_disp, &object);
        if (kr != KERN_SUCCESS) {
            *mr = MACH_SEND_INVALID_RIGHT;
            return NULL;
        }

        if ((result_disp == MACH_MSG_TYPE_PORT_RECEIVE) &&
                ipc_port_check_circularity((ipc_port_t) object,
                    (ipc_port_t) dest)) {
            kmsg->ikm_header->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
        }
        dsc->name = (ipc_port_t) object;
    } else {
        dsc->name = CAST_MACH_NAME_TO_PORT(name);
    }
    dsc->disposition = result_disp;
    dsc->type = MACH_MSG_PORT_DESCRIPTOR;

    dsc->pad_end = 0; // debug, unnecessary

    return (mach_msg_descriptor_t *)(user_dsc_in+1);
}

mach_msg_descriptor_t * ipc_kmsg_copyin_ool_descriptor(
        mach_msg_ool_descriptor_t *dsc,
        mach_msg_descriptor_t *user_dsc,
        int is_64bit,
        vm_offset_t *paddr,
        vm_map_copy_t *copy,
        vm_size_t *space_needed,
        vm_map_t map,
        mach_msg_return_t *mr);
mach_msg_descriptor_t *
ipc_kmsg_copyin_ool_descriptor(
        mach_msg_ool_descriptor_t *dsc,
        mach_msg_descriptor_t *user_dsc,
        int is_64bit,
        vm_offset_t *paddr,
        vm_map_copy_t *copy,
        vm_size_t *space_needed,
        vm_map_t map,
        mach_msg_return_t *mr)
{
    vm_size_t            		length;
    boolean_t            		dealloc;
    mach_msg_copy_options_t		copy_options;
    mach_vm_offset_t		addr;
    mach_msg_descriptor_type_t	dsc_type;

    if (is_64bit) {
        mach_msg_ool_descriptor64_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;

        addr = (mach_vm_offset_t) user_ool_dsc->address;
        length = user_ool_dsc->size;
        dealloc = user_ool_dsc->deallocate;
        copy_options = user_ool_dsc->copy;
        dsc_type = user_ool_dsc->type;

        user_dsc = (typeof(user_dsc))(user_ool_dsc+1);
    } else {
        mach_msg_ool_descriptor32_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;

        addr = CAST_USER_ADDR_T(user_ool_dsc->address);
        dealloc = user_ool_dsc->deallocate;
        copy_options = user_ool_dsc->copy;
        dsc_type = user_ool_dsc->type;
        length = user_ool_dsc->size;

        user_dsc = (typeof(user_dsc))(user_ool_dsc+1);
    }

    dsc->size = (mach_msg_size_t)length;
    dsc->deallocate = dealloc;
    dsc->copy = copy_options;
    dsc->type = dsc_type;

    if (length == 0) {
        dsc->address = NULL;
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
        if (copyin(addr, (char *)*paddr, length)) {
            *mr = MACH_SEND_INVALID_MEMORY;
            return NULL;
        }	

        /*
         * The kernel ipc copy map is marked no_zero_fill.
         * If the transfer is not a page multiple, we need
         * to zero fill the balance.
         */
        if (!page_aligned(length)) {
            (void) memset((void *) (*paddr + length), 0,
                    round_page(length) - length);
        }
        if (vm_map_copyin(ipc_kernel_copy_map, (vm_map_address_t)*paddr,
                    (vm_map_size_t)length, TRUE, copy) != KERN_SUCCESS) {
            *mr = MACH_MSG_VM_KERNEL;
            return NULL;
        }
        dsc->address = (void *)*copy;
        *paddr += round_page(length);
        *space_needed -= round_page(length);
    } else {

        /*
         * Make a vm_map_copy_t of the of the data.  If the
         * data is small, this will do an optimized physical
         * copy.  Otherwise, it will do a virtual copy.
         *
         * NOTE: A virtual copy is OK if the original is being
         * deallocted, even if a physical copy was requested.
         */
        kern_return_t kr = vm_map_copyin(map, addr, 
                (vm_map_size_t)length, dealloc, copy);
        if (kr != KERN_SUCCESS) {
            *mr = (kr == KERN_RESOURCE_SHORTAGE) ?
                MACH_MSG_VM_KERNEL :
                MACH_SEND_INVALID_MEMORY;
            return NULL;
        }
        dsc->address = (void *)*copy;
    }
    return user_dsc;
}

mach_msg_descriptor_t * ipc_kmsg_copyin_ool_ports_descriptor(
        mach_msg_ool_ports_descriptor_t *dsc,
        mach_msg_descriptor_t *user_dsc,
        int is_64bit,
        vm_map_t map,
        ipc_space_t space,
        ipc_object_t dest,
        ipc_kmsg_t kmsg,
        mach_msg_return_t *mr);
mach_msg_descriptor_t *
ipc_kmsg_copyin_ool_ports_descriptor(
        mach_msg_ool_ports_descriptor_t *dsc,
        mach_msg_descriptor_t *user_dsc,
        int is_64bit,
        vm_map_t map,
        ipc_space_t space,
        ipc_object_t dest,
        ipc_kmsg_t kmsg,
        mach_msg_return_t *mr)
{
    void					*data;
    ipc_object_t            		*objects;
    unsigned int				i;
    mach_vm_offset_t             		addr;
    mach_msg_type_name_t    		user_disp;
    mach_msg_type_name_t    		result_disp;
    mach_msg_type_number_t			count;
    mach_msg_copy_options_t			copy_option;
    boolean_t				deallocate;
    mach_msg_descriptor_type_t      type;
    vm_size_t 				ports_length, names_length;

    if (is_64bit) {
        mach_msg_ool_ports_descriptor64_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;

        addr = (mach_vm_offset_t)user_ool_dsc->address;
        count = user_ool_dsc->count;
        deallocate = user_ool_dsc->deallocate;
        copy_option = user_ool_dsc->copy;
        user_disp = user_ool_dsc->disposition;
        type = user_ool_dsc->type;

        user_dsc = (typeof(user_dsc))(user_ool_dsc+1);
    } else {
        mach_msg_ool_ports_descriptor32_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;

        addr = CAST_USER_ADDR_T(user_ool_dsc->address);
        count = user_ool_dsc->count;
        deallocate = user_ool_dsc->deallocate;
        copy_option = user_ool_dsc->copy;
        user_disp = user_ool_dsc->disposition;
        type = user_ool_dsc->type;

        user_dsc = (typeof(user_dsc))(user_ool_dsc+1);
    }

    dsc->deallocate = deallocate;
    dsc->copy = copy_option;
    dsc->type = type;
    dsc->count = count;
    dsc->address = NULL;  /* for now */

    result_disp = ipc_object_copyin_type(user_disp);
    dsc->disposition = result_disp;

    if (count > (INT_MAX / sizeof(mach_port_t))) {
        *mr = MACH_SEND_TOO_LARGE;
        return NULL;
    }

    /* calculate length of data in bytes, rounding up */
    ports_length = count * sizeof(mach_port_t);
    names_length = count * sizeof(mach_port_name_t);

    if (ports_length == 0) {
        return user_dsc;
    }

    data = kalloc(ports_length);

    if (data == NULL) {
        *mr = MACH_SEND_NO_BUFFER;
        return NULL;
    }
    
#ifdef __LP64__
    mach_port_name_t *names = &((mach_port_name_t *)data)[count];
#else
    mach_port_name_t *names = ((mach_port_name_t *)data);
#endif

    if (copyinmap(map, addr, names, names_length) != KERN_SUCCESS) {
        kfree(data, ports_length);
        *mr = MACH_SEND_INVALID_MEMORY;
        return NULL;
    }

    if (deallocate) {
        (void) mach_vm_deallocate(map, addr, (mach_vm_size_t)ports_length);
    }

    objects = (ipc_object_t *) data;
    dsc->address = data;

    for ( i = 0; i < count; i++) {
        mach_port_name_t name = names[i];
        ipc_object_t object;

        if (!MACH_PORT_VALID(name)) {
            objects[i] = (ipc_object_t)CAST_MACH_NAME_TO_PORT(name);
            continue;
        }

        kern_return_t kr = ipc_object_copyin(space, name, user_disp, &object);

        if (kr != KERN_SUCCESS) {
            unsigned int j;

            for(j = 0; j < i; j++) {
                object = objects[j];
                if (IPC_OBJECT_VALID(object))
                    ipc_object_destroy(object, result_disp);
            }
            kfree(data, ports_length);
            dsc->address = NULL;
            *mr = MACH_SEND_INVALID_RIGHT;
            return NULL;
        }

        if ((dsc->disposition == MACH_MSG_TYPE_PORT_RECEIVE) &&
                ipc_port_check_circularity(
                    (ipc_port_t) object,
                    (ipc_port_t) dest))
            kmsg->ikm_header->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;

        objects[i] = object;
    }

    return user_dsc;
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

mach_msg_return_t
ipc_kmsg_copyin_body(
	ipc_kmsg_t	kmsg,
	ipc_space_t	space,
	vm_map_t	map)
{
    ipc_object_t       		dest;
    mach_msg_body_t		*body;
    mach_msg_descriptor_t	*daddr, *naddr;
    mach_msg_descriptor_t	*user_addr, *kern_addr;
    mach_msg_type_number_t	dsc_count;
    boolean_t 			is_task_64bit = (map->max_offset > VM_MAX_ADDRESS);
    boolean_t 			complex = FALSE;
    vm_size_t			space_needed = 0;
    vm_offset_t			paddr = 0;
    vm_map_copy_t		copy = VM_MAP_COPY_NULL;
    mach_msg_type_number_t	i;
    mach_msg_return_t		mr = MACH_MSG_SUCCESS;

    vm_size_t           descriptor_size = 0;

    /*
     * Determine if the target is a kernel port.
     */
    dest = (ipc_object_t) kmsg->ikm_header->msgh_remote_port;
    body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
    naddr = (mach_msg_descriptor_t *) (body + 1);

    dsc_count = body->msgh_descriptor_count;
    if (dsc_count == 0)
	return MACH_MSG_SUCCESS;

    /*
     * Make an initial pass to determine kernal VM space requirements for
     * physical copies and possible contraction of the descriptors from
     * processes with pointers larger than the kernel's.
     */
    daddr = NULL;
    for (i = 0; i < dsc_count; i++) {
	daddr = naddr;

	/* make sure the descriptor fits in the message */
	if (is_task_64bit) {
	    switch (daddr->type.type) {
	    case MACH_MSG_OOL_DESCRIPTOR:
	    case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
	    case MACH_MSG_OOL_PORTS_DESCRIPTOR:
		    descriptor_size += 16;
            naddr = (typeof(naddr))((vm_offset_t)daddr + 16);
            break;
	    default:
		    descriptor_size += 12;
            naddr = (typeof(naddr))((vm_offset_t)daddr + 12);
            break;
	    }
	} else {
        descriptor_size += 12;
        naddr = (typeof(naddr))((vm_offset_t)daddr + 12);
	}

	if (naddr > (mach_msg_descriptor_t *)
	    ((vm_offset_t)kmsg->ikm_header + kmsg->ikm_header->msgh_size)) {
	    ipc_kmsg_clean_partial(kmsg, 0, NULL, 0, 0);
	    mr = MACH_SEND_MSG_TOO_SMALL;
	    goto out;
	}

	switch (daddr->type.type) {
	    mach_msg_size_t size;

	case MACH_MSG_OOL_DESCRIPTOR:
	case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
        size = (is_task_64bit) ?
		((mach_msg_ool_descriptor64_t *)daddr)->size :
	    daddr->out_of_line.size;

	    if (daddr->out_of_line.copy != MACH_MSG_PHYSICAL_COPY &&
		daddr->out_of_line.copy != MACH_MSG_VIRTUAL_COPY) {
		/*
		 * Invalid copy option
		 */
		ipc_kmsg_clean_partial(kmsg, 0, NULL, 0, 0);
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
		if (space_needed + round_page(size) <= space_needed) {
		    /* Overflow dectected */
		    ipc_kmsg_clean_partial(kmsg, 0, NULL, 0, 0);
		    mr = MACH_MSG_VM_KERNEL;
		    goto out;
		}		    
		    
		space_needed += round_page(size);
		if (space_needed > ipc_kmsg_max_vm_space) {
		    
		    /*
		     * Per message kernel memory limit exceeded
		     */
		    ipc_kmsg_clean_partial(kmsg, 0, NULL, 0, 0);
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
        if (vm_allocate(ipc_kernel_copy_map, &paddr, space_needed, 
                    VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
            ipc_kmsg_clean_partial(kmsg, 0, NULL, 0, 0);
            mr = MACH_MSG_VM_KERNEL;
            goto out;
        }
    }

    /* user_addr = just after base as it was copied in */
    user_addr = (mach_msg_descriptor_t *)((vm_offset_t)kmsg->ikm_header + sizeof(mach_msg_base_t));
    /* Shift the mach_msg_base_t down to make for dsc_count*16bytes of descriptors */
    if(descriptor_size != 16*dsc_count) {
        vm_offset_t dsc_adjust = 16*dsc_count - descriptor_size;
        memmove((char *)(((vm_offset_t)kmsg->ikm_header) - dsc_adjust), kmsg->ikm_header, sizeof(mach_msg_base_t));
        kmsg->ikm_header = (mach_msg_header_t *)((vm_offset_t)kmsg->ikm_header - dsc_adjust);
        /* Update the message size for the larger in-kernel representation */
        kmsg->ikm_header->msgh_size += (mach_msg_size_t)dsc_adjust;
    }


    /* kern_addr = just after base after it has been (conditionally) moved */
    kern_addr = (mach_msg_descriptor_t *)((vm_offset_t)kmsg->ikm_header + sizeof(mach_msg_base_t));

    /* handle the OOL regions and port descriptors. */
    for(i=0;i<dsc_count;i++) {
        switch (user_addr->type.type) {
            case MACH_MSG_PORT_DESCRIPTOR:
                user_addr = ipc_kmsg_copyin_port_descriptor((mach_msg_port_descriptor_t *)kern_addr, 
                        (mach_msg_legacy_port_descriptor_t *)user_addr, space, dest, kmsg, &mr);
                kern_addr++;
                complex = TRUE;
                break;
            case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
            case MACH_MSG_OOL_DESCRIPTOR: 
                user_addr = ipc_kmsg_copyin_ool_descriptor((mach_msg_ool_descriptor_t *)kern_addr, 
                        user_addr, is_task_64bit, &paddr, &copy, &space_needed, map, &mr);
                kern_addr++;
                complex = TRUE;
                break;
            case MACH_MSG_OOL_PORTS_DESCRIPTOR: 
                user_addr = ipc_kmsg_copyin_ool_ports_descriptor((mach_msg_ool_ports_descriptor_t *)kern_addr, 
                        user_addr, is_task_64bit, map, space, dest, kmsg, &mr);
                kern_addr++;
                complex = TRUE;
                break;
            default:
                /* Invalid descriptor */
                mr = MACH_SEND_INVALID_TYPE;
                break;
        }

        if (MACH_MSG_SUCCESS != mr) {
            /* clean from start of message descriptors to i */
            ipc_kmsg_clean_partial(kmsg, i,
                    (mach_msg_descriptor_t *)((mach_msg_base_t *)kmsg->ikm_header + 1),
                    paddr, space_needed);
            goto out;
        }
    } /* End of loop */ 
    
    if (!complex) {
	kmsg->ikm_header->msgh_bits &= ~MACH_MSGH_BITS_COMPLEX;
    }
 out:
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
	mach_msg_option_t	*optionp)
{
    mach_msg_return_t 		mr;

    kmsg->ikm_header->msgh_bits &= MACH_MSGH_BITS_USER;

    mr = ipc_kmsg_copyin_header(kmsg->ikm_header, space, optionp);

    if (mr != MACH_MSG_SUCCESS)
	return mr;
    
	DEBUG_KPRINT_SYSCALL_IPC("ipc_kmsg_copyin header:\n%.8x\n%.8x\n%p\n%p\n%.8x\n%.8x\n",
							 kmsg->ikm_header->msgh_size,
							 kmsg->ikm_header->msgh_bits,
							 kmsg->ikm_header->msgh_remote_port,
							 kmsg->ikm_header->msgh_local_port,
							 kmsg->ikm_header->msgh_reserved,
							 kmsg->ikm_header->msgh_id);

    if ((kmsg->ikm_header->msgh_bits & MACH_MSGH_BITS_COMPLEX) == 0)
	return MACH_MSG_SUCCESS;
    
	mr = ipc_kmsg_copyin_body( kmsg, space, map);

	if (DEBUG_KPRINT_SYSCALL_PREDICATE(DEBUG_KPRINT_SYSCALL_IPC_MASK))
	{
		kprintf("body:\n");
		uint32_t i;
		for(i=0;i*4 < (kmsg->ikm_header->msgh_size - sizeof(mach_msg_header_t));i++)
		{
			kprintf("%.4x\n",((uint32_t *)(kmsg->ikm_header + 1))[i]);
		}
	}

	return mr;
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
 *	Conditions:
 *		Nothing locked.
 */

mach_msg_return_t
ipc_kmsg_copyin_from_kernel(
	ipc_kmsg_t	kmsg)
{
	mach_msg_bits_t bits = kmsg->ikm_header->msgh_bits;
	mach_msg_type_name_t rname = MACH_MSGH_BITS_REMOTE(bits);
	mach_msg_type_name_t lname = MACH_MSGH_BITS_LOCAL(bits);
	ipc_object_t remote = (ipc_object_t) kmsg->ikm_header->msgh_remote_port;
	ipc_object_t local = (ipc_object_t) kmsg->ikm_header->msgh_local_port;

	/* translate the destination and reply ports */
	if (!IO_VALID(remote))
		return MACH_SEND_INVALID_DEST;

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
			return MACH_MSG_SUCCESS;
	}
    {
    	mach_msg_descriptor_t	*saddr;
    	mach_msg_body_t		*body;
	mach_msg_type_number_t	i, count;

    	body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
    	saddr = (mach_msg_descriptor_t *) (body + 1);
	count = body->msgh_descriptor_count;

    	for (i = 0; i < count; i++, saddr++) {

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
		
		    dsc = (mach_msg_ool_ports_descriptor_t *)&saddr->ool_ports;

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
    return MACH_MSG_SUCCESS;
}

#if IKM_SUPPORT_LEGACY
mach_msg_return_t
ipc_kmsg_copyin_from_kernel_legacy(
	ipc_kmsg_t	kmsg)
{
	mach_msg_bits_t bits = kmsg->ikm_header->msgh_bits;
	mach_msg_type_name_t rname = MACH_MSGH_BITS_REMOTE(bits);
	mach_msg_type_name_t lname = MACH_MSGH_BITS_LOCAL(bits);
	ipc_object_t remote = (ipc_object_t) kmsg->ikm_header->msgh_remote_port;
	ipc_object_t local = (ipc_object_t) kmsg->ikm_header->msgh_local_port;

	/* translate the destination and reply ports */
	if (!IO_VALID(remote))
		return MACH_SEND_INVALID_DEST;

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
			return MACH_MSG_SUCCESS;
	}
    {
    	mach_msg_legacy_descriptor_t	*saddr;
        mach_msg_descriptor_t	*daddr;
    	mach_msg_body_t		*body;
	mach_msg_type_number_t	i, count;

    	body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
    	saddr = (typeof(saddr)) (body + 1);
	count = body->msgh_descriptor_count;

    if(count) {
        vm_offset_t dsc_adjust = 4*count;
        memmove((char *)(((vm_offset_t)kmsg->ikm_header) - dsc_adjust), kmsg->ikm_header, sizeof(mach_msg_base_t));
        kmsg->ikm_header = (mach_msg_header_t *)((vm_offset_t)kmsg->ikm_header - dsc_adjust);
        /* Update the message size for the larger in-kernel representation */
        kmsg->ikm_header->msgh_size += dsc_adjust;
    }
    daddr = (mach_msg_descriptor_t *)((vm_offset_t)kmsg->ikm_header + sizeof(mach_msg_base_t));

    	for (i = 0; i < count; i++, saddr++, daddr++) {
	    switch (saddr->type.type) {
	    
	        case MACH_MSG_PORT_DESCRIPTOR: {
		    mach_msg_type_name_t 	name;
		    ipc_object_t 		object;
		    mach_msg_legacy_port_descriptor_t 	*dsc;
		    mach_msg_port_descriptor_t 	*dest_dsc;
		
		    dsc = (typeof(dsc))&saddr->port;
            dest_dsc = &daddr->port;
		
		    /* this is really the type SEND, SEND_ONCE, etc. */
		    name = dsc->disposition;
		    object = (ipc_object_t) CAST_MACH_NAME_TO_PORT(dsc->name);
		    dest_dsc->disposition = ipc_object_copyin_type(name);
            dest_dsc->name = (mach_port_t)object;
            dest_dsc->type = MACH_MSG_PORT_DESCRIPTOR;
		
		    if (!IO_VALID(object)) {
		        break;
		    }

		    ipc_object_copyin_from_kernel(object, name);
		    
		    /* CDY avoid circularity when the destination is also */
		    /* the kernel.  This check should be changed into an  */
		    /* assert when the new kobject model is in place since*/
		    /* ports will not be used in kernel to kernel chats   */
			
		    if (((ipc_port_t)remote)->ip_receiver != ipc_space_kernel) {
		       if ((dest_dsc->disposition == MACH_MSG_TYPE_PORT_RECEIVE) &&
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
		    /* The sender should supply ready-made memory, i.e. a vm_map_copy_t
             * so we don't need to do anything special. */

		    mach_msg_ool_descriptor32_t	*source_dsc = &saddr->out_of_line32;
		    mach_msg_ool_descriptor_t 	*dest_dsc = (typeof(dest_dsc))&daddr->out_of_line;

            vm_offset_t		    address = source_dsc->address;
            vm_size_t            		size = source_dsc->size;
            boolean_t            		deallocate = source_dsc->deallocate;
            mach_msg_copy_options_t		copy = source_dsc->copy;
            mach_msg_descriptor_type_t  type = source_dsc->type;

            dest_dsc->address = (void *)address;
            dest_dsc->size = size;
            dest_dsc->deallocate = deallocate;
            dest_dsc->copy = copy;
            dest_dsc->type = type;
		    break;
	        }
        case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
		    ipc_object_t            		*objects;
		    unsigned int			j;
		    mach_msg_type_name_t    		name;
		    mach_msg_ool_ports_descriptor_t 	*dest_dsc;
		
		    mach_msg_ool_ports_descriptor32_t	*source_dsc = &saddr->ool_ports32;
            dest_dsc = (typeof(dest_dsc))&daddr->ool_ports;

            boolean_t deallocate = source_dsc->deallocate;
            mach_msg_copy_options_t copy = source_dsc->copy;
            mach_msg_size_t port_count = source_dsc->count;
            mach_msg_type_name_t disposition = source_dsc->disposition;

		    /* this is really the type SEND, SEND_ONCE, etc. */
		    name = disposition;
		    disposition = ipc_object_copyin_type(name);
	    	
		    objects = (ipc_object_t *) (uintptr_t)source_dsc->address;
	    	
		    for ( j = 0; j < port_count; j++) {
		        ipc_object_t object = objects[j];
		        
		        if (!IO_VALID(object))
			    continue;
		        
		        ipc_object_copyin_from_kernel(object, name);
    
		        if ((disposition == MACH_MSG_TYPE_PORT_RECEIVE) &&
			    ipc_port_check_circularity(
						       (ipc_port_t) object,
						       (ipc_port_t) remote))
			    kmsg->ikm_header->msgh_bits |= MACH_MSGH_BITS_CIRCULAR;
		    }

            dest_dsc->address = objects;
            dest_dsc->deallocate = deallocate;
            dest_dsc->copy = copy;
            dest_dsc->disposition = disposition;
            dest_dsc->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
            dest_dsc->count = port_count;
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
    return MACH_MSG_SUCCESS;
}
#endif /* IKM_SUPPORT_LEGACY */

/*
 *	Routine:	ipc_kmsg_copyout_header
 *	Purpose:
 *		"Copy-out" port rights in the header of a message.
 *		Operates atomically; if it doesn't succeed the
 *		message header and the space are left untouched.
 *		If it does succeed the remote/local port fields
 *		contain port names instead of object pointers,
 *		and the bits field is updated.
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
	ipc_space_t		space)
{
	mach_msg_bits_t mbits = msg->msgh_bits;
	ipc_port_t dest = (ipc_port_t) msg->msgh_remote_port;

	assert(IP_VALID(dest));

	/*
	 * While we still hold a reference on the received-from port,
	 * process all send-possible notfications we received along with
	 * the message.
	 */
	ipc_port_spnotify(dest);

    {
	mach_msg_type_name_t dest_type = MACH_MSGH_BITS_REMOTE(mbits);
	mach_msg_type_name_t reply_type = MACH_MSGH_BITS_LOCAL(mbits);
	ipc_port_t reply = (ipc_port_t) msg->msgh_local_port;
	ipc_port_t release_port = IP_NULL;
	mach_port_name_t dest_name, reply_name;

	if (IP_VALID(reply)) {
		ipc_entry_t entry;
		kern_return_t kr;

		/*
		 *	Get reply port entry (if none, skip to dest port
		 *	copyout).  This may require growing the space.
		 */

		is_write_lock(space);

		for (;;) {
			if (!is_active(space)) {
				is_write_unlock(space);
				return (MACH_RCV_HEADER_ERROR|
					MACH_MSG_IPC_SPACE);
			}

			if ((reply_type != MACH_MSG_TYPE_PORT_SEND_ONCE) &&
			    ipc_right_reverse(space, (ipc_object_t) reply,
					      &reply_name, &entry)) {
				/* reply port is locked and active */
				assert(entry->ie_bits &
				       MACH_PORT_TYPE_SEND_RECEIVE);
				break;
			}

			ip_lock(reply);
			if (!ip_active(reply)) {
				ip_unlock(reply);
				ip_lock(dest);
				is_write_unlock(space);

				release_port = reply;
				reply = IP_DEAD;
				reply_name = MACH_PORT_DEAD;
				goto copyout_dest;
			}

			reply_name = CAST_MACH_PORT_TO_NAME(reply);
			kr = ipc_entry_get(space, &reply_name, &entry);
			if (kr != KERN_SUCCESS) {
				ip_unlock(reply);

				/* space is locked */
				kr = ipc_entry_grow_table(space,
							  ITS_SIZE_NONE);
				if (kr != KERN_SUCCESS) {
					return (MACH_RCV_HEADER_ERROR|
						MACH_MSG_IPC_SPACE);
				}
				/* space is locked again; start over */

				continue;
			}
			assert(IE_BITS_TYPE(entry->ie_bits) ==
			       MACH_PORT_TYPE_NONE);
			assert(entry->ie_object == IO_NULL); 

			entry->ie_object = (ipc_object_t) reply;
			break;
		}

		/* space and reply port are locked and active */

		ip_reference(reply);	/* hold onto the reply port */

		kr = ipc_right_copyout(space, reply_name, entry,
				       reply_type, TRUE, (ipc_object_t) reply);

		/* reply port is unlocked */
		assert(kr == KERN_SUCCESS);

		ip_lock(dest);
		is_write_unlock(space);

	} else {
		/*
		 *	No reply port!  This is an easy case.
		 *	We only need to have the space locked
		 *	when locking the destination.
		 */

		is_read_lock(space);
		if (!is_active(space)) {
			is_read_unlock(space);
			return MACH_RCV_HEADER_ERROR|MACH_MSG_IPC_SPACE;
		}

		ip_lock(dest);
		is_read_unlock(space);

		reply_name = CAST_MACH_PORT_TO_NAME(reply);
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
		ip_unlock(dest);
		ip_release(dest);

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
		ip_release(reply);

	if (IP_VALID(release_port))
		ip_release(release_port);

	msg->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
			  MACH_MSGH_BITS(reply_type, dest_type));
	msg->msgh_local_port = CAST_MACH_NAME_TO_PORT(dest_name);
	msg->msgh_remote_port = CAST_MACH_NAME_TO_PORT(reply_name);
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
		*namep = CAST_MACH_PORT_TO_NAME(object);
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

mach_msg_descriptor_t *
ipc_kmsg_copyout_port_descriptor(mach_msg_descriptor_t *dsc,
        mach_msg_descriptor_t *user_dsc,
        ipc_space_t space,
        kern_return_t *mr);
mach_msg_descriptor_t *
ipc_kmsg_copyout_port_descriptor(mach_msg_descriptor_t *dsc,
        mach_msg_descriptor_t *dest_dsc,
        ipc_space_t space, 
        kern_return_t *mr)
{
    mach_port_t			port;
    mach_port_name_t		name;
    mach_msg_type_name_t		disp;


    /* Copyout port right carried in the message */
    port = dsc->port.name;
    disp = dsc->port.disposition;
    *mr |= ipc_kmsg_copyout_object(space, 
            (ipc_object_t)port, 
            disp, 
            &name);

    if(current_task() == kernel_task)
    {
        mach_msg_port_descriptor_t *user_dsc = (typeof(user_dsc))dest_dsc;
        user_dsc--; // point to the start of this port descriptor
        user_dsc->name = CAST_MACH_NAME_TO_PORT(name);
        user_dsc->disposition = disp;
        user_dsc->type = MACH_MSG_PORT_DESCRIPTOR;
        dest_dsc = (typeof(dest_dsc))user_dsc;
    } else {
        mach_msg_legacy_port_descriptor_t *user_dsc = (typeof(user_dsc))dest_dsc;
        user_dsc--; // point to the start of this port descriptor
        user_dsc->name = CAST_MACH_PORT_TO_NAME(name);
        user_dsc->disposition = disp;
        user_dsc->type = MACH_MSG_PORT_DESCRIPTOR;
        dest_dsc = (typeof(dest_dsc))user_dsc;
    }

    return (mach_msg_descriptor_t *)dest_dsc;
}

mach_msg_descriptor_t *
ipc_kmsg_copyout_ool_descriptor(mach_msg_ool_descriptor_t *dsc, mach_msg_descriptor_t *user_dsc, int is_64bit, vm_map_t map, mach_msg_return_t *mr);
mach_msg_descriptor_t *
ipc_kmsg_copyout_ool_descriptor(mach_msg_ool_descriptor_t *dsc, mach_msg_descriptor_t *user_dsc, int is_64bit, vm_map_t map, mach_msg_return_t *mr)
{
    vm_map_copy_t			copy;
    vm_map_address_t			rcv_addr;
    mach_msg_copy_options_t		copy_options;
    mach_msg_size_t			size;
    mach_msg_descriptor_type_t	dsc_type;

    //SKIP_PORT_DESCRIPTORS(saddr, sdsc_count);

    copy = (vm_map_copy_t) dsc->address;
    size = dsc->size;
    copy_options = dsc->copy;
    assert(copy_options != MACH_MSG_KALLOC_COPY_T);
    dsc_type = dsc->type;
    rcv_addr = 0;

    if (copy != VM_MAP_COPY_NULL) {
        /*
         * Check to see if there is an overwrite descriptor
         * specified in the scatter list for this ool data.
         * The descriptor has already been verified.
         */
#if 0
        if (saddr != MACH_MSG_DESCRIPTOR_NULL) {
            if (differs) {
                OTHER_OOL_DESCRIPTOR *scatter_dsc;

                scatter_dsc = (OTHER_OOL_DESCRIPTOR *)saddr;
                if (scatter_dsc->copy == MACH_MSG_OVERWRITE) {
                    rcv_addr = (mach_vm_offset_t) scatter_dsc->address;
                    copy_options = MACH_MSG_OVERWRITE;
                } else {
                    copy_options = MACH_MSG_VIRTUAL_COPY;
                }
            } else {
                mach_msg_ool_descriptor_t *scatter_dsc;

                scatter_dsc = &saddr->out_of_line;
                if (scatter_dsc->copy == MACH_MSG_OVERWRITE) {
                    rcv_addr = CAST_USER_ADDR_T(scatter_dsc->address);
                    copy_options = MACH_MSG_OVERWRITE;
                } else {
                    copy_options = MACH_MSG_VIRTUAL_COPY;
                }
            }
            INCREMENT_SCATTER(saddr, sdsc_count, differs);
        }
#endif


        /*
         * Whether the data was virtually or physically
         * copied we have a vm_map_copy_t for it.
         * If there's an overwrite region specified
         * overwrite it, otherwise do a virtual copy out.
         */
        kern_return_t kr;
        if (copy_options == MACH_MSG_OVERWRITE && rcv_addr != 0) {
            kr = vm_map_copy_overwrite(map, rcv_addr,
                    copy, TRUE);
        } else {
            kr = vm_map_copyout(map, &rcv_addr, copy);
        }	
        if (kr != KERN_SUCCESS) {
            if (kr == KERN_RESOURCE_SHORTAGE)
                *mr |= MACH_MSG_VM_KERNEL;
            else
                *mr |= MACH_MSG_VM_SPACE;
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
    if(current_task() == kernel_task)
    {
        mach_msg_ool_descriptor_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;
        user_ool_dsc--;

        user_ool_dsc->address = (void *)(uintptr_t)rcv_addr;
        user_ool_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
            TRUE : FALSE;
        user_ool_dsc->copy = copy_options;
        user_ool_dsc->type = dsc_type;
        user_ool_dsc->size = size;

        user_dsc = (typeof(user_dsc))user_ool_dsc;
    } else if (is_64bit) {
        mach_msg_ool_descriptor64_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;
        user_ool_dsc--;

        user_ool_dsc->address = rcv_addr;
        user_ool_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
            TRUE : FALSE;
        user_ool_dsc->copy = copy_options;
        user_ool_dsc->type = dsc_type;
        user_ool_dsc->size = size;

        user_dsc = (typeof(user_dsc))user_ool_dsc;
    } else {
        mach_msg_ool_descriptor32_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;
        user_ool_dsc--;

        user_ool_dsc->address = CAST_DOWN_EXPLICIT(uint32_t, rcv_addr);
        user_ool_dsc->size = size;
        user_ool_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
            TRUE : FALSE;
        user_ool_dsc->copy = copy_options;
        user_ool_dsc->type = dsc_type;

        user_dsc = (typeof(user_dsc))user_ool_dsc;
    }
    return user_dsc;
}

mach_msg_descriptor_t *
ipc_kmsg_copyout_ool_ports_descriptor(mach_msg_ool_ports_descriptor_t *dsc,
        mach_msg_descriptor_t *user_dsc,
        int is_64bit,
        vm_map_t map,
        ipc_space_t space,
        ipc_kmsg_t kmsg,
        mach_msg_return_t *mr);
mach_msg_descriptor_t *
ipc_kmsg_copyout_ool_ports_descriptor(mach_msg_ool_ports_descriptor_t *dsc,
        mach_msg_descriptor_t *user_dsc,
        int is_64bit,
        vm_map_t map,
        ipc_space_t space,
        ipc_kmsg_t kmsg,
        mach_msg_return_t *mr)
{
    mach_vm_offset_t		rcv_addr = 0;
    mach_msg_type_name_t		disp;
    mach_msg_type_number_t 		count, i;
    vm_size_t           		ports_length, names_length;

    mach_msg_copy_options_t copy_options = MACH_MSG_VIRTUAL_COPY;

    //SKIP_PORT_DESCRIPTORS(saddr, sdsc_count);

    count = dsc->count;
    disp = dsc->disposition;
    ports_length = count * sizeof(mach_port_t);
    names_length = count * sizeof(mach_port_name_t);

    if (ports_length != 0 && dsc->address != 0) {

        /*
         * Check to see if there is an overwrite descriptor
         * specified in the scatter list for this ool data.
         * The descriptor has already been verified.
         */
#if 0
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
#endif

        if (copy_options == MACH_MSG_VIRTUAL_COPY) {
            /*
             * Dynamically allocate the region
             */
            int anywhere = VM_MAKE_TAG(VM_MEMORY_MACH_MSG)|
                VM_FLAGS_ANYWHERE;

            kern_return_t kr;
            if ((kr = mach_vm_allocate(map, &rcv_addr, 
                            (mach_vm_size_t)names_length,
                            anywhere)) != KERN_SUCCESS) {
                ipc_kmsg_clean_body(kmsg, 1, (mach_msg_descriptor_t *)dsc);
                rcv_addr = 0;

                if (kr == KERN_RESOURCE_SHORTAGE){
                    *mr |= MACH_MSG_VM_KERNEL;
                } else {
                    *mr |= MACH_MSG_VM_SPACE;
                }
            }
        }

        /*
         * Handle the port rights and copy out the names
         * for those rights out to user-space.
         */
        if (rcv_addr != 0) {
            mach_port_t *objects = (mach_port_t *) dsc->address;
            mach_port_name_t *names = (mach_port_name_t *) dsc->address;

            /* copyout port rights carried in the message */

            for ( i = 0; i < count ; i++) {
                ipc_object_t object = (ipc_object_t)objects[i];

                *mr |= ipc_kmsg_copyout_object(space, object,
                        disp, &names[i]);
            }

            /* copyout to memory allocated above */
            void *data = dsc->address;
            if (copyoutmap(map, data, rcv_addr, names_length) != KERN_SUCCESS)
                *mr |= MACH_MSG_VM_SPACE;
            kfree(data, ports_length);
        }
    } else {
        rcv_addr = 0;
    }

    /*
     * Now update the descriptor based on the information
     * calculated above.
     */
    if(current_task() == kernel_task) {
        mach_msg_ool_ports_descriptor_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;
        user_ool_dsc--;

        user_ool_dsc->address = (void *)(uintptr_t)rcv_addr;
        user_ool_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
            TRUE : FALSE;
        user_ool_dsc->copy = copy_options;
        user_ool_dsc->disposition = disp;
        user_ool_dsc->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
        user_ool_dsc->count = count;

        user_dsc = (typeof(user_dsc))user_ool_dsc;
    } if (is_64bit) {
        mach_msg_ool_ports_descriptor64_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;
        user_ool_dsc--;

        user_ool_dsc->address = rcv_addr;
        user_ool_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
            TRUE : FALSE;
        user_ool_dsc->copy = copy_options;
        user_ool_dsc->disposition = disp;
        user_ool_dsc->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
        user_ool_dsc->count = count;

        user_dsc = (typeof(user_dsc))user_ool_dsc;
    } else {
        mach_msg_ool_ports_descriptor32_t *user_ool_dsc = (typeof(user_ool_dsc))user_dsc;
        user_ool_dsc--;

        user_ool_dsc->address = CAST_DOWN_EXPLICIT(uint32_t, rcv_addr);
        user_ool_dsc->count = count;
        user_ool_dsc->deallocate = (copy_options == MACH_MSG_VIRTUAL_COPY) ?
            TRUE : FALSE;
        user_ool_dsc->copy = copy_options;
        user_ool_dsc->disposition = disp;
        user_ool_dsc->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;

        user_dsc = (typeof(user_dsc))user_ool_dsc;
    }
    return user_dsc;
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
    mach_msg_descriptor_t 	*kern_dsc, *user_dsc;
    mach_msg_descriptor_t	*saddr;
    mach_msg_type_number_t	dsc_count, sdsc_count;
    int i;
    mach_msg_return_t 		mr = MACH_MSG_SUCCESS;
    boolean_t 			is_task_64bit = (map->max_offset > VM_MAX_ADDRESS);

    body = (mach_msg_body_t *) (kmsg->ikm_header + 1);
    dsc_count = body->msgh_descriptor_count;
    kern_dsc = (mach_msg_descriptor_t *) (body + 1);
    /* Point user_dsc just after the end of all the descriptors */
    user_dsc = &kern_dsc[dsc_count];

    /* Do scatter list setup */
    if (slist != MACH_MSG_BODY_NULL) {
    panic("Scatter lists disabled");
	saddr = (mach_msg_descriptor_t *) (slist + 1);
	sdsc_count = slist->msgh_descriptor_count;
    }
    else {
	saddr = MACH_MSG_DESCRIPTOR_NULL;
	sdsc_count = 0;
    }

    /* Now process the descriptors */
    for (i = dsc_count-1; i >= 0; i--) {
        switch (kern_dsc[i].type.type) {

            case MACH_MSG_PORT_DESCRIPTOR: 
                user_dsc = ipc_kmsg_copyout_port_descriptor(&kern_dsc[i], user_dsc, space, &mr);
                break;
            case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
            case MACH_MSG_OOL_DESCRIPTOR : 
                user_dsc = ipc_kmsg_copyout_ool_descriptor(
                        (mach_msg_ool_descriptor_t *)&kern_dsc[i], user_dsc, is_task_64bit, map, &mr);
                break;
            case MACH_MSG_OOL_PORTS_DESCRIPTOR : 
                user_dsc = ipc_kmsg_copyout_ool_ports_descriptor(
                        (mach_msg_ool_ports_descriptor_t *)&kern_dsc[i], user_dsc, is_task_64bit, map, space, kmsg, &mr);
                break;
            default : {
                          panic("untyped IPC copyout body: invalid message descriptor");
                      }
        }
    }

    if(user_dsc != kern_dsc) {
        vm_offset_t dsc_adjust = (vm_offset_t)user_dsc - (vm_offset_t)kern_dsc;
        memmove((char *)((vm_offset_t)kmsg->ikm_header + dsc_adjust), kmsg->ikm_header, sizeof(mach_msg_base_t));
        kmsg->ikm_header = (mach_msg_header_t *)((vm_offset_t)kmsg->ikm_header + dsc_adjust);
        /* Update the message size for the smaller user representation */
        kmsg->ikm_header->msgh_size -= (mach_msg_size_t)dsc_adjust;
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

    boolean_t is_task_64bit = (map->max_offset > VM_MAX_ADDRESS);

#if defined(__LP64__)
	send_size -= LEGACY_HEADER_SIZE_DELTA;
#endif

    if (kmsg->ikm_header->msgh_bits & MACH_MSGH_BITS_COMPLEX) {

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
                    if(!is_task_64bit)
                        send_size -= DESC_SIZE_ADJUSTMENT;
                    break;
                case MACH_MSG_PORT_DESCRIPTOR:
                    send_size -= DESC_SIZE_ADJUSTMENT;
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
	mach_msg_body_t		*slist)
{
	mach_msg_return_t mr;

	mr = ipc_kmsg_copyout_header(kmsg->ikm_header, space);
	if (mr != MACH_MSG_SUCCESS) {
		return mr;
	}

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

	kmsg->ikm_header->msgh_bits = mbits & MACH_MSGH_BITS_USER;
	kmsg->ikm_header->msgh_remote_port = CAST_MACH_NAME_TO_PORT(dest_name);
	kmsg->ikm_header->msgh_local_port = CAST_MACH_NAME_TO_PORT(reply_name);

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
		io_unlock(dest);
		io_release(dest);
		dest_name = MACH_PORT_DEAD;
	}

	if (IO_VALID(reply)) {
		ipc_object_destroy(reply, reply_type);
		reply_name = MACH_PORT_NULL;
	} else
		reply_name = CAST_MACH_PORT_TO_NAME(reply);

	kmsg->ikm_header->msgh_bits = (MACH_MSGH_BITS_OTHER(mbits) |
				      MACH_MSGH_BITS(reply_type, dest_type));
	kmsg->ikm_header->msgh_local_port = CAST_MACH_NAME_TO_PORT(dest_name);
	kmsg->ikm_header->msgh_remote_port = CAST_MACH_NAME_TO_PORT(reply_name);

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

#if defined(__LP64__)
        panic("ipc_kmsg_get_scatter called!");
#endif

        if (slist_size < sizeof(mach_msg_base_t))
                return MACH_MSG_BODY_NULL;

        slist_size -= (mach_msg_size_t)sizeof(mach_msg_header_t);
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
#if defined(__LP64__)
        panic("%s called; halting!", __func__);
#endif

        slist_size -= (mach_msg_size_t)sizeof(mach_msg_header_t);
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
		io_unlock(dest);
		io_release(dest);
		dest_name = MACH_PORT_DEAD;
	}

	reply_name = CAST_MACH_PORT_TO_NAME(reply);

	kmsg->ikm_header->msgh_bits =
		(MACH_MSGH_BITS_OTHER(kmsg->ikm_header->msgh_bits) |
					MACH_MSGH_BITS(reply_type, dest_type));
	kmsg->ikm_header->msgh_local_port =  CAST_MACH_NAME_TO_PORT(dest_name);
	kmsg->ikm_header->msgh_remote_port = CAST_MACH_NAME_TO_PORT(reply_name);
}

#if IKM_SUPPORT_LEGACY
void
ipc_kmsg_copyout_to_kernel_legacy(
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
		io_unlock(dest);
		io_release(dest);
		dest_name = MACH_PORT_DEAD;
	}

	reply_name = CAST_MACH_PORT_TO_NAME(reply);

	kmsg->ikm_header->msgh_bits =
		(MACH_MSGH_BITS_OTHER(kmsg->ikm_header->msgh_bits) |
					MACH_MSGH_BITS(reply_type, dest_type));
	kmsg->ikm_header->msgh_local_port =  CAST_MACH_NAME_TO_PORT(dest_name);
	kmsg->ikm_header->msgh_remote_port = CAST_MACH_NAME_TO_PORT(reply_name);

    mach_msg_descriptor_t *saddr;
    mach_msg_legacy_descriptor_t *daddr;
    mach_msg_type_number_t i, count = ((mach_msg_base_t *)kmsg->ikm_header)->body.msgh_descriptor_count;
    saddr = (mach_msg_descriptor_t *) (((mach_msg_base_t *)kmsg->ikm_header) + 1);
    saddr = &saddr[count-1];
    daddr = (mach_msg_legacy_descriptor_t *)&saddr[count];
    daddr--;

    vm_offset_t dsc_adjust = 0;

    for (i = 0; i < count; i++, saddr--, daddr--) {
    switch (saddr->type.type) {
        case MACH_MSG_PORT_DESCRIPTOR: {
        mach_msg_port_descriptor_t *dsc = &saddr->port;
        mach_msg_legacy_port_descriptor_t *dest_dsc = &daddr->port;

        mach_port_t name = dsc->name;
        mach_msg_type_name_t disposition = dsc->disposition;

        dest_dsc->name = CAST_MACH_PORT_TO_NAME(name);
        dest_dsc->disposition = disposition;
        dest_dsc->type = MACH_MSG_PORT_DESCRIPTOR;
        break;
        }
    case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
    case MACH_MSG_OOL_DESCRIPTOR: {
        /* The sender should supply ready-made memory, i.e. a vm_map_copy_t
         * so we don't need to do anything special. */

        mach_msg_ool_descriptor_t 	*source_dsc = (typeof(source_dsc))&saddr->out_of_line;

            mach_msg_ool_descriptor32_t	*dest_dsc = &daddr->out_of_line32;

        vm_offset_t		            address = (vm_offset_t)source_dsc->address;
        vm_size_t            		size = source_dsc->size;
        boolean_t            		deallocate = source_dsc->deallocate;
        mach_msg_copy_options_t		copy = source_dsc->copy;
        mach_msg_descriptor_type_t  type = source_dsc->type;

        dest_dsc->address = address;
        dest_dsc->size = size;
        dest_dsc->deallocate = deallocate;
        dest_dsc->copy = copy;
        dest_dsc->type = type;
        break;
        }
    case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
        mach_msg_ool_ports_descriptor_t 	*source_dsc = (typeof(source_dsc))&saddr->ool_ports;

            mach_msg_ool_ports_descriptor32_t	*dest_dsc = &daddr->ool_ports32;

        vm_offset_t		            address = (vm_offset_t)source_dsc->address;
        vm_size_t            		port_count = source_dsc->count;
        boolean_t            		deallocate = source_dsc->deallocate;
        mach_msg_copy_options_t		copy = source_dsc->copy;
        mach_msg_descriptor_type_t  type = source_dsc->type;

        dest_dsc->address = address;
        dest_dsc->count = port_count;
        dest_dsc->deallocate = deallocate;
        dest_dsc->copy = copy;
        dest_dsc->type = type;
        break;
        }
        default: {
#if	MACH_ASSERT
        panic("ipc_kmsg_copyin_from_kernel:  bad descriptor");
#endif	/* MACH_ASSERT */
                 }
    }
    }

    if(count) {
        dsc_adjust = 4*count;
        memmove((char *)((vm_offset_t)kmsg->ikm_header + dsc_adjust), kmsg->ikm_header, sizeof(mach_msg_base_t));
        kmsg->ikm_header = (mach_msg_header_t *)((vm_offset_t)kmsg->ikm_header + dsc_adjust);
        /* Update the message size for the smaller user representation */
        kmsg->ikm_header->msgh_size -= dsc_adjust;
    }
}
#endif /* IKM_SUPPORT_LEGACY */

mach_msg_trailer_size_t
ipc_kmsg_add_trailer(ipc_kmsg_t kmsg, ipc_space_t space, 
		mach_msg_option_t option, thread_t thread, 
		mach_port_seqno_t seqno, boolean_t minimal_trailer,
		mach_vm_offset_t context)
{
	mach_msg_max_trailer_t *trailer;

	(void)thread;
	trailer = (mach_msg_max_trailer_t *)
		((vm_offset_t)kmsg->ikm_header +
		 round_msg(kmsg->ikm_header->msgh_size));

	if (!(option & MACH_RCV_TRAILER_MASK)) {
		return trailer->msgh_trailer_size;
	}

	trailer->msgh_seqno = seqno;
	trailer->msgh_context = context;
	trailer->msgh_trailer_size = REQUESTED_TRAILER_SIZE(thread_is_64bit(thread), option);

	if (minimal_trailer) { 
		goto done;
	}

	if (MACH_RCV_TRAILER_ELEMENTS(option) >= 
			MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AV)){
#if CONFIG_MACF_MACH
		if (kmsg->ikm_sender != NULL &&
				IP_VALID(kmsg->ikm_header->msgh_remote_port) &&
				mac_port_check_method(kmsg->ikm_sender,
					&kmsg->ikm_sender->maclabel,
					&kmsg->ikm_header->msgh_remote_port->ip_label,
					kmsg->ikm_header->msgh_id) == 0)
			trailer->msgh_ad = 1;
		else
#endif
			trailer->msgh_ad = 0;
	}

	/*
	 * The ipc_kmsg_t holds a reference to the label of a label
	 * handle, not the port. We must get a reference to the port
	 * and a send right to copyout to the receiver.
	 */

	if (option & MACH_RCV_TRAILER_ELEMENTS (MACH_RCV_TRAILER_LABELS)) {
#if CONFIG_MACF_MACH
		if (kmsg->ikm_sender != NULL) {
			ipc_labelh_t  lh = kmsg->ikm_sender->label;
			kern_return_t kr;

			ip_lock(lh->lh_port);
			lh->lh_port->ip_mscount++;
			lh->lh_port->ip_srights++;
			ip_reference(lh->lh_port);
			ip_unlock(lh->lh_port);

			kr = ipc_object_copyout(space, (ipc_object_t)lh->lh_port,
					MACH_MSG_TYPE_PORT_SEND, 0,
					&trailer->msgh_labels.sender);
			if (kr != KERN_SUCCESS) {
				ip_release(lh->lh_port);
				trailer->msgh_labels.sender = 0;
			}
		} else {
			trailer->msgh_labels.sender = 0;
		}
#else
		(void)space;
		trailer->msgh_labels.sender = 0;
#endif
	}


done:

	return trailer->msgh_trailer_size;
}
