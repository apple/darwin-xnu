/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
 *	Default Pager.
 *		Memory Object Management.
 */

#include "default_pager_internal.h"
#include <default_pager/default_pager_object_server.h>
#include <mach/memory_object_default_server.h>
#include <mach/memory_object_control.h>
#include <mach/memory_object_types.h>
#include <mach/memory_object_server.h>
#include <mach/upl.h>
#include <mach/vm_map.h>
#include <vm/memory_object.h>
#include <vm/vm_pageout.h> 
#include <vm/vm_map.h>
#include <vm/vm_protos.h>

/* forward declaration */
vstruct_t vs_object_create(vm_size_t size);

/*
 * List of all vstructs.  A specific vstruct is
 * found directly via its port, this list is
 * only used for monitoring purposes by the
 * default_pager_object* calls and by ps_delete
 * when abstract memory objects must be scanned
 * to remove any live storage on a segment which
 * is to be removed.
 */
struct vstruct_list_head	vstruct_list;

__private_extern__ void
vstruct_list_insert(
	vstruct_t vs)
{
	VSL_LOCK();
	queue_enter(&vstruct_list.vsl_queue, vs, vstruct_t, vs_links);
	vstruct_list.vsl_count++;
	VSL_UNLOCK();
}


__private_extern__ void
vstruct_list_delete(
	vstruct_t vs)
{
	queue_remove(&vstruct_list.vsl_queue, vs, vstruct_t, vs_links);
	vstruct_list.vsl_count--;
}

/*
 * We use the sequence numbers on requests to regulate
 * our parallelism.  In general, we allow multiple reads and writes
 * to proceed in parallel, with the exception that reads must
 * wait for previous writes to finish.  (Because the kernel might
 * generate a data-request for a page on the heels of a data-write
 * for the same page, and we must avoid returning stale data.)
 * terminate requests wait for proceeding reads and writes to finish.
 */

static unsigned int	default_pager_total = 0;		/* debugging */
static unsigned int	default_pager_wait_seqno = 0;		/* debugging */
static unsigned int	default_pager_wait_read = 0;		/* debugging */
static unsigned int	default_pager_wait_write = 0;		/* debugging */

__private_extern__ void
vs_async_wait(
	vstruct_t	vs)
{

	ASSERT(vs->vs_async_pending >= 0);
	while (vs->vs_async_pending > 0) {
		vs->vs_waiting_async = TRUE;
		assert_wait(&vs->vs_async_pending, THREAD_UNINT);
		VS_UNLOCK(vs);
		thread_block(THREAD_CONTINUE_NULL);
		VS_LOCK(vs);
	}
	ASSERT(vs->vs_async_pending == 0);
}


#if	PARALLEL
/* 
 * Waits for correct sequence number.  Leaves pager locked.
 *
 * JMM - Sequence numbers guarantee ordering of requests generated
 *	 by a single thread if the receiver is multithreaded and
 *	 the interfaces are asynchronous (i.e. sender can generate
 *	 more than one request before the first is received in the
 *	 pager).  Normally, IPC would generate these number in that
 *	 case.  But we are trying to avoid using IPC for the in-kernel
 *	 scenario. Since these are actually invoked synchronously
 *	 anyway (in-kernel), we can just fake the sequence number
 *	 generation here (thus avoiding the dependence on IPC).
 */
__private_extern__ void
vs_lock(
	vstruct_t		vs)
{
	mach_port_seqno_t	seqno;

	default_pager_total++;
	VS_LOCK(vs);

	seqno = vs->vs_next_seqno++;

	while (vs->vs_seqno != seqno) {
		default_pager_wait_seqno++;
		vs->vs_waiting_seqno = TRUE;
		assert_wait(&vs->vs_seqno, THREAD_UNINT);
		VS_UNLOCK(vs);
		thread_block(THREAD_CONTINUE_NULL);
		VS_LOCK(vs);
	}
}

/*
 * Increments sequence number and unlocks pager.
 */
__private_extern__ void
vs_unlock(vstruct_t vs)
{
	vs->vs_seqno++;
	if (vs->vs_waiting_seqno) {
		vs->vs_waiting_seqno = FALSE;
		VS_UNLOCK(vs);
		thread_wakeup(&vs->vs_seqno);
		return;
	}
	VS_UNLOCK(vs);
}

/* 
 * Start a read - one more reader.  Pager must be locked.
 */
__private_extern__ void
vs_start_read(
	vstruct_t vs)
{
	vs->vs_readers++;
}

/*
 * Wait for readers.  Unlocks and relocks pager if wait needed.
 */
__private_extern__ void
vs_wait_for_readers(
	vstruct_t vs)
{
	while (vs->vs_readers != 0) {
		default_pager_wait_read++;
		vs->vs_waiting_read = TRUE;
		assert_wait(&vs->vs_readers, THREAD_UNINT);
		VS_UNLOCK(vs);
		thread_block(THREAD_CONTINUE_NULL);
		VS_LOCK(vs);
	}
}

/*
 * Finish a read.  Pager is unlocked and returns unlocked.
 */
__private_extern__ void
vs_finish_read(
	vstruct_t vs)
{
	VS_LOCK(vs);
	if (--vs->vs_readers == 0 && vs->vs_waiting_read) {
		vs->vs_waiting_read = FALSE;
		VS_UNLOCK(vs);
		thread_wakeup(&vs->vs_readers);
		return;
	}
	VS_UNLOCK(vs);
}

/*
 * Start a write - one more writer.  Pager must be locked.
 */
__private_extern__ void
vs_start_write(
	vstruct_t vs)
{
	vs->vs_writers++;
}

/* 
 * Wait for writers.  Unlocks and relocks pager if wait needed.
 */
__private_extern__ void
vs_wait_for_writers(
	vstruct_t vs)
{
	while (vs->vs_writers != 0) {
		default_pager_wait_write++;
		vs->vs_waiting_write = TRUE;
		assert_wait(&vs->vs_writers, THREAD_UNINT);
		VS_UNLOCK(vs);
		thread_block(THREAD_CONTINUE_NULL);
		VS_LOCK(vs);
	}
	vs_async_wait(vs);
}

/* This is to be used for the transfer from segment code ONLY */
/* The transfer code holds off vs destruction by keeping the  */
/* vs_async_wait count non-zero.  It will not ocnflict with   */
/* other writers on an async basis because it only writes on  */
/* a cluster basis into fresh (as of sync time) cluster locations */

__private_extern__ void 
vs_wait_for_sync_writers(
        vstruct_t vs)
{
        while (vs->vs_writers != 0) {
                default_pager_wait_write++;
		vs->vs_waiting_write = TRUE;
                assert_wait(&vs->vs_writers, THREAD_UNINT);
                VS_UNLOCK(vs);
                thread_block(THREAD_CONTINUE_NULL);
                VS_LOCK(vs);
        }
}       


/*
 * Finish a write.  Pager is unlocked and returns unlocked.
 */
__private_extern__ void
vs_finish_write(
	vstruct_t vs)
{
	VS_LOCK(vs);
	if (--vs->vs_writers == 0 && vs->vs_waiting_write) {
		vs->vs_waiting_write = FALSE;
		VS_UNLOCK(vs);
		thread_wakeup(&vs->vs_writers);
		return;
	}
	VS_UNLOCK(vs);
}
#endif	/* PARALLEL */

vstruct_t
vs_object_create(
	vm_size_t size)
{
	vstruct_t	vs;

	/*
	 * Allocate a vstruct. If there are any problems, then report them
	 * to the console.
	 */
	vs = ps_vstruct_create(size);
	if (vs == VSTRUCT_NULL) {
		dprintf(("vs_object_create: unable to allocate %s\n",
			 "-- either run swapon command or reboot"));
		return VSTRUCT_NULL;
	}

	return vs;
}

#if 0
void default_pager_add(vstruct_t, boolean_t);	/* forward */

void
default_pager_add(
	vstruct_t vs,
	boolean_t internal)
{
	memory_object_t		mem_obj = vs->vs_mem_obj;
	mach_port_t		pset;
	mach_port_mscount_t 	sync;
	mach_port_t		previous;
	kern_return_t		kr;
	static char		here[] = "default_pager_add";

	/*
	 * The port currently has a make-send count of zero,
	 * because either we just created the port or we just
	 * received the port in a memory_object_create request.
	 */

	if (internal) {
		/* possibly generate an immediate no-senders notification */
		sync = 0;
		pset = default_pager_internal_set;
	} else {
		/* delay notification till send right is created */
		sync = 1;
		pset = default_pager_external_set;
	}

	ipc_port_make_sonce(mem_obj);
	ip_lock(mem_obj);  /* unlocked in nsrequest below */
	ipc_port_nsrequest(mem_obj, sync, mem_obj, &previous);
}

#endif

const struct memory_object_pager_ops default_pager_ops = {
	dp_memory_object_reference,
	dp_memory_object_deallocate,
	dp_memory_object_init,
	dp_memory_object_terminate,
	dp_memory_object_data_request,
	dp_memory_object_data_return,
	dp_memory_object_data_initialize,
	dp_memory_object_data_unlock,
	dp_memory_object_synchronize,
	dp_memory_object_unmap,
	"default pager"
};

kern_return_t
dp_memory_object_init(
	memory_object_t		mem_obj,
	memory_object_control_t	control,
	__unused vm_size_t pager_page_size)
{
	vstruct_t		vs;

	assert(pager_page_size == vm_page_size);

	memory_object_control_reference(control);

	vs_lookup(mem_obj, vs);
	vs_lock(vs);

	if (vs->vs_control != MEMORY_OBJECT_CONTROL_NULL)
		Panic("bad request");

	vs->vs_control = control;
	vs_unlock(vs);

	return KERN_SUCCESS;
}

kern_return_t
dp_memory_object_synchronize(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	vm_size_t		length,
	__unused vm_sync_t		flags)
{
	vstruct_t	vs;

	vs_lookup(mem_obj, vs);
	vs_lock(vs);
	vs_unlock(vs);

	memory_object_synchronize_completed(vs->vs_control, offset, length);

	return KERN_SUCCESS;
}

kern_return_t
dp_memory_object_unmap(
	__unused memory_object_t		mem_obj)
{
	panic("dp_memory_object_unmap");

	return KERN_FAILURE;
}

kern_return_t
dp_memory_object_terminate(
	memory_object_t		mem_obj)
{
	memory_object_control_t	control;
	vstruct_t		vs;

	/* 
	 * control port is a receive right, not a send right.
	 */

	vs_lookup(mem_obj, vs);
	vs_lock(vs);

	/*
	 * Wait for read and write requests to terminate.
	 */

	vs_wait_for_readers(vs);
	vs_wait_for_writers(vs);

	/*
	 * After memory_object_terminate both memory_object_init
	 * and a no-senders notification are possible, so we need
	 * to clean up our reference to the memory_object_control
	 * to prepare for a new init.
	 */

	control = vs->vs_control;
	vs->vs_control = MEMORY_OBJECT_CONTROL_NULL;

	/* a bit of special case ugliness here.  Wakeup any waiting reads */
	/* these data requests had to be removed from the seqno traffic   */
	/* based on a performance bottleneck with large memory objects    */
	/* the problem will right itself with the new component based     */
	/* synchronous interface.  The new async will be able to return   */
	/* failure during its sync phase.   In the mean time ... */

	thread_wakeup(&vs->vs_writers);
	thread_wakeup(&vs->vs_async_pending);

	vs_unlock(vs);

	/*
	 * Now we deallocate our reference on the control.
	 */
	memory_object_control_deallocate(control);
	return KERN_SUCCESS;
}

void
dp_memory_object_reference(
	memory_object_t		mem_obj)
{
	vstruct_t		vs;

	vs_lookup_safe(mem_obj, vs);
	if (vs == VSTRUCT_NULL)
		return;

	VS_LOCK(vs);
	assert(vs->vs_references > 0);
	vs->vs_references++;
	VS_UNLOCK(vs);
}

void
dp_memory_object_deallocate(
	memory_object_t		mem_obj)
{
	vstruct_t		vs;
	mach_port_seqno_t	seqno;

	/*
	 * Because we don't give out multiple first references
	 * for a memory object, there can't be a race
	 * between getting a deallocate call and creating
	 * a new reference for the object.
	 */

	vs_lookup_safe(mem_obj, vs);
	if (vs == VSTRUCT_NULL)
		return;

	VS_LOCK(vs);
	if (--vs->vs_references > 0) {
		VS_UNLOCK(vs);
		return;
	}

	seqno = vs->vs_next_seqno++;
	while (vs->vs_seqno != seqno) {
		default_pager_wait_seqno++;
		vs->vs_waiting_seqno = TRUE;
		assert_wait(&vs->vs_seqno, THREAD_UNINT);
		VS_UNLOCK(vs);
		thread_block(THREAD_CONTINUE_NULL);
		VS_LOCK(vs);
	}

	vs_async_wait(vs);	/* wait for pending async IO */

	/* do not delete the vs structure until the referencing pointers */
	/* in the vstruct list have been expunged */

	/* get VSL_LOCK out of order by using TRY mechanism */
	while(!VSL_LOCK_TRY()) {
		VS_UNLOCK(vs);
		VSL_LOCK();
		VSL_UNLOCK();
		VS_LOCK(vs);
		vs_async_wait(vs);	/* wait for pending async IO */
	}


	/*
	 * We shouldn't get a deallocation call
	 * when the kernel has the object cached.
	 */
	if (vs->vs_control != MEMORY_OBJECT_CONTROL_NULL)
		Panic("bad request");

	/*
	 * Unlock the pager (though there should be no one
	 * waiting for it).
	 */
	VS_UNLOCK(vs);

	/* Lock out paging segment removal for the duration of this */
	/* call.  We are vulnerable to losing a paging segment we rely */
	/* on as soon as we remove ourselves from the VSL and unlock */

	/* Keep our thread from blocking on attempt to trigger backing */
	/* store release */
	backing_store_release_trigger_disable += 1;

	/*
	 * Remove the memory object port association, and then
	 * the destroy the port itself.  We must remove the object
	 * from the port list before deallocating the pager,
	 * because of default_pager_objects.
	 */
	vstruct_list_delete(vs);
	VSL_UNLOCK();

	ps_vstruct_dealloc(vs);

	VSL_LOCK();
	backing_store_release_trigger_disable -= 1;
	if(backing_store_release_trigger_disable == 0) {
		thread_wakeup((event_t)&backing_store_release_trigger_disable);
	}
	VSL_UNLOCK();
}

kern_return_t
dp_memory_object_data_request(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	vm_size_t		length,
	__unused vm_prot_t		protection_required)
{
	vstruct_t		vs;

	GSTAT(global_stats.gs_pagein_calls++);


	/* CDY at this moment vs_lookup panics when presented with the wrong */
	/* port.  As we are expanding this pager to support user interfaces */
	/* this should be changed to return kern_failure */
	vs_lookup(mem_obj, vs);
	vs_lock(vs);

	/* We are going to relax the strict sequencing here for performance */
	/* reasons.  We can do this because we know that the read and */
	/* write threads are different and we rely on synchronization */
	/* of read and write requests at the cache memory_object level */
	/* break out wait_for_writers, all of this goes away when */
	/* we get real control of seqno with the new component interface */

	if (vs->vs_writers != 0) {
		/* you can't hold on to the seqno and go */
		/* to sleep like that */
		vs_unlock(vs);  /* bump internal count of seqno */
		VS_LOCK(vs);
		while (vs->vs_writers != 0) {
			default_pager_wait_write++;
			vs->vs_waiting_write = TRUE;
			assert_wait(&vs->vs_writers, THREAD_UNINT);
			VS_UNLOCK(vs);
			thread_block(THREAD_CONTINUE_NULL);
			VS_LOCK(vs);
			vs_async_wait(vs);
		}
		if(vs->vs_control == MEMORY_OBJECT_CONTROL_NULL) {
			VS_UNLOCK(vs);
			return KERN_FAILURE;
		}
		vs_start_read(vs);
		VS_UNLOCK(vs);
	} else {
		vs_start_read(vs);
		vs_unlock(vs);
	}

	/*
	 * Request must be on a page boundary and a multiple of pages.
	 */
	if ((offset & vm_page_mask) != 0 || (length & vm_page_mask) != 0)
		Panic("bad alignment");

	pvs_cluster_read(vs, (vm_offset_t)offset, length);

	vs_finish_read(vs);

	return KERN_SUCCESS;
}

/*
 * memory_object_data_initialize: check whether we already have each page, and
 * write it if we do not.  The implementation is far from optimized, and
 * also assumes that the default_pager is single-threaded.
 */
/*  It is questionable whether or not a pager should decide what is relevant */
/* and what is not in data sent from the kernel.  Data initialize has been */
/* changed to copy back all data sent to it in preparation for its eventual */
/* merge with data return.  It is the kernel that should decide what pages */
/* to write back.  As of the writing of this note, this is indeed the case */
/* the kernel writes back one page at a time through this interface */

kern_return_t
dp_memory_object_data_initialize(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	vm_size_t		size)
{
	vstruct_t	vs;

	DP_DEBUG(DEBUG_MO_EXTERNAL,
		 ("mem_obj=0x%x,offset=0x%x,cnt=0x%x\n",
		  (int)mem_obj, (int)offset, (int)size));
	GSTAT(global_stats.gs_pages_init += atop_32(size));

	vs_lookup(mem_obj, vs);
	vs_lock(vs);
	vs_start_write(vs);
	vs_unlock(vs);

	/*
	 * Write the data via clustered writes. vs_cluster_write will
	 * loop if the address range specified crosses cluster
	 * boundaries.
	 */
	vs_cluster_write(vs, 0, (vm_offset_t)offset, size, FALSE, 0);

	vs_finish_write(vs);

	return KERN_SUCCESS;
}

kern_return_t
dp_memory_object_data_unlock(
	__unused memory_object_t		mem_obj,
	__unused memory_object_offset_t	offset,
	__unused vm_size_t		size,
	__unused vm_prot_t		desired_access)
{
	Panic("dp_memory_object_data_unlock: illegal");
	return KERN_FAILURE;
}


/*ARGSUSED8*/
kern_return_t
dp_memory_object_data_return(
	memory_object_t		mem_obj,
	memory_object_offset_t	offset,
	vm_size_t			size,
	__unused memory_object_offset_t	*resid_offset,
	__unused int		*io_error,
	__unused boolean_t	dirty,
	__unused boolean_t	kernel_copy,
	__unused int	upl_flags)
{
	vstruct_t	vs;

	DP_DEBUG(DEBUG_MO_EXTERNAL,
		 ("mem_obj=0x%x,offset=0x%x,size=0x%x\n",
		  (int)mem_obj, (int)offset, (int)size));
	GSTAT(global_stats.gs_pageout_calls++);

	/* This routine is called by the pageout thread.  The pageout thread */
	/* cannot be blocked by read activities unless the read activities   */
	/* Therefore the grant of vs lock must be done on a try versus a      */
	/* blocking basis.  The code below relies on the fact that the       */
	/* interface is synchronous.  Should this interface be again async   */
	/* for some type  of pager in the future the pages will have to be   */
	/* returned through a separate, asynchronous path.		     */

	vs_lookup(mem_obj, vs);

        default_pager_total++;
	if(!VS_TRY_LOCK(vs)) {
		/* the call below will not be done by caller when we have */
		/* a synchronous interface */
		/* return KERN_LOCK_OWNED; */
		upl_t		upl;
		unsigned int	page_list_count = 0;
		memory_object_super_upl_request(vs->vs_control,
					(memory_object_offset_t)offset,
					size, size,
					&upl, NULL, &page_list_count,
					UPL_NOBLOCK | UPL_CLEAN_IN_PLACE 
					| UPL_NO_SYNC | UPL_COPYOUT_FROM);
		upl_abort(upl,0);
		upl_deallocate(upl);
		return KERN_SUCCESS;
	}

	if ((vs->vs_seqno != vs->vs_next_seqno++)
			|| (vs->vs_readers)
			|| (vs->vs_xfer_pending)) {
		upl_t		upl;
		unsigned int	page_list_count = 0;

		vs->vs_next_seqno--;
                VS_UNLOCK(vs);

		/* the call below will not be done by caller when we have */
		/* a synchronous interface */
		/* return KERN_LOCK_OWNED; */
		memory_object_super_upl_request(vs->vs_control,
                                (memory_object_offset_t)offset,
				size, size,
				&upl, NULL, &page_list_count,
				UPL_NOBLOCK | UPL_CLEAN_IN_PLACE 
					| UPL_NO_SYNC | UPL_COPYOUT_FROM);
		upl_abort(upl,0);
		upl_deallocate(upl);
		return KERN_SUCCESS;
	}

	if ((size % vm_page_size) != 0)
		Panic("bad alignment");

	vs_start_write(vs);


        vs->vs_async_pending += 1;  /* protect from backing store contraction */
	vs_unlock(vs);

	/*
	 * Write the data via clustered writes. vs_cluster_write will
	 * loop if the address range specified crosses cluster
	 * boundaries.
	 */
	vs_cluster_write(vs, 0, (vm_offset_t)offset, size, FALSE, 0);

	vs_finish_write(vs);

	/* temporary, need a finer lock based on cluster */

	VS_LOCK(vs);
	vs->vs_async_pending -= 1;  /* release vs_async_wait */
	if (vs->vs_async_pending == 0 && vs->vs_waiting_async) {
		vs->vs_waiting_async = FALSE;
		VS_UNLOCK(vs);
		thread_wakeup(&vs->vs_async_pending);
	} else {
		VS_UNLOCK(vs);
	}


	return KERN_SUCCESS;
}

/*
 * Routine:	default_pager_memory_object_create
 * Purpose:
 * 	Handle requests for memory objects from the
 * 	kernel.
 * Notes:
 * 	Because we only give out the default memory
 * 	manager port to the kernel, we don't have to
 * 	be so paranoid about the contents.
 */
kern_return_t
default_pager_memory_object_create(
	__unused memory_object_default_t	dmm,
	vm_size_t		new_size,
	memory_object_t		*new_mem_obj)
{
	vstruct_t		vs;

	assert(dmm == default_pager_object);

	vs = vs_object_create(new_size);
	if (vs == VSTRUCT_NULL)
		return KERN_RESOURCE_SHORTAGE;

	vs->vs_next_seqno = 0;

	/*
	 * Set up associations between this memory object
	 * and this default_pager structure
	 */

	vs->vs_pager_ops = &default_pager_ops;
	vs->vs_mem_obj_ikot = IKOT_MEMORY_OBJECT;

	/*
	 * After this, other threads might receive requests
	 * for this memory object or find it in the port list.
	 */

	vstruct_list_insert(vs);
	*new_mem_obj = vs_to_mem_obj(vs);
	return KERN_SUCCESS;
}

/*
 * Create an external object.
 */
kern_return_t
default_pager_object_create(
	default_pager_t default_pager,
	vm_size_t	size,
	memory_object_t	*mem_objp)
{
	vstruct_t	vs;

	if (default_pager != default_pager_object)
		return KERN_INVALID_ARGUMENT;

	vs = vs_object_create(size);
	if (vs == VSTRUCT_NULL)
		return KERN_RESOURCE_SHORTAGE;

	/*
	 * Set up associations between the default pager
	 * and this vstruct structure
	 */
	vs->vs_pager_ops = &default_pager_ops;
	vstruct_list_insert(vs);
	*mem_objp = vs_to_mem_obj(vs);
	return KERN_SUCCESS;
}

kern_return_t
default_pager_objects(
	default_pager_t			default_pager,
	default_pager_object_array_t	*objectsp,
	mach_msg_type_number_t		*ocountp,
	mach_port_array_t		*portsp,
	mach_msg_type_number_t		*pcountp)
{
	vm_offset_t		oaddr = 0;	/* memory for objects */
	vm_size_t		osize = 0;	/* current size */
	default_pager_object_t	* objects;
	unsigned int		opotential = 0;

	vm_map_copy_t		pcopy = 0;	/* copy handle for pagers */
	vm_size_t		psize = 0;	/* current size */
	memory_object_t		* pagers;
	unsigned int		ppotential = 0;

	unsigned int		actual;
	unsigned int		num_objects;
	kern_return_t		kr;
	vstruct_t		entry;

	if (default_pager != default_pager_object)
		return KERN_INVALID_ARGUMENT;

	/*
	 * We will send no more than this many
	 */
	actual = vstruct_list.vsl_count;

	/*
	 * Out out-of-line port arrays are simply kalloc'ed.
	 */
	psize = round_page(actual * sizeof * pagers);
	ppotential = psize / sizeof * pagers;
	pagers = (memory_object_t *)kalloc(psize);
	if (0 == pagers)
		return KERN_RESOURCE_SHORTAGE;
		
	/*
	 * returned out of line data must be allocated out
	 * the ipc_kernel_map, wired down, filled in, and
	 * then "copied in" as if it had been sent by a
	 * user process.
	 */
	osize = round_page(actual * sizeof * objects);
	opotential = osize / sizeof * objects;
	kr = kmem_alloc(ipc_kernel_map, &oaddr, osize);
	if (KERN_SUCCESS != kr) {
		kfree(pagers, psize);
		return KERN_RESOURCE_SHORTAGE;
	}
	objects = (default_pager_object_t *)oaddr;


	/*
	 * Now scan the list.
	 */

	VSL_LOCK();

	num_objects = 0;
	queue_iterate(&vstruct_list.vsl_queue, entry, vstruct_t, vs_links) {

		memory_object_t			pager;
		vm_size_t			size;

		if ((num_objects >= opotential) ||
		    (num_objects >= ppotential)) {

			/*
			 * This should be rare.  In any case,
			 * we will only miss recent objects,
			 * because they are added at the end.
			 */
			break;
		}

		/*
		 * Avoid interfering with normal operations
		 */
		if (!VS_MAP_TRY_LOCK(entry))
			goto not_this_one;
		size = ps_vstruct_allocated_size(entry);
		VS_MAP_UNLOCK(entry);

		VS_LOCK(entry);

		/*
		 * We need a reference for our caller.  Adding this
		 * reference through the linked list could race with
		 * destruction of the object.  If we find the object
		 * has no references, just give up on it.
		 */
		VS_LOCK(entry);
		if (entry->vs_references == 0) {
			VS_UNLOCK(entry);
			goto not_this_one;
		}
		pager = vs_to_mem_obj(entry);
		dp_memory_object_reference(pager);
		VS_UNLOCK(entry);

		/* the arrays are wired, so no deadlock worries */

		objects[num_objects].dpo_object = (vm_offset_t) entry;
		objects[num_objects].dpo_size = size;
		pagers [num_objects++] = pager;
		continue;

	    not_this_one:
		/*
		 * Do not return garbage
		 */
		objects[num_objects].dpo_object = (vm_offset_t) 0;
		objects[num_objects].dpo_size = 0;
		pagers[num_objects++] = MEMORY_OBJECT_NULL;

	}

	VSL_UNLOCK();

	/* clear out any excess allocation */
	while (num_objects < opotential) {
		objects[--opotential].dpo_object = (vm_offset_t) 0;
		objects[opotential].dpo_size = 0;
	}
	while (num_objects < ppotential) {
		pagers[--ppotential] = MEMORY_OBJECT_NULL;
	}

	kr = vm_map_unwire(ipc_kernel_map, vm_map_trunc_page(oaddr),
			   vm_map_round_page(oaddr + osize), FALSE);
	assert(KERN_SUCCESS == kr);
	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)oaddr,
			   (vm_map_size_t)osize, TRUE, &pcopy);
	assert(KERN_SUCCESS == kr);

	*objectsp = (default_pager_object_array_t)objects;
	*ocountp = num_objects;
	*portsp = (mach_port_array_t)pcopy;
	*pcountp = num_objects;

	return KERN_SUCCESS;
}

kern_return_t
default_pager_object_pages(
	default_pager_t		default_pager,
	mach_port_t			memory_object,
	default_pager_page_array_t	*pagesp,
	mach_msg_type_number_t		*countp)
{
	vm_offset_t			addr = 0; /* memory for page offsets */
	vm_size_t			size = 0; /* current memory size */
	vm_map_copy_t			copy;
	default_pager_page_t		* pages = 0;
	unsigned int			potential;
	unsigned int			actual;
	kern_return_t			kr;
	memory_object_t			object;

	if (default_pager != default_pager_object)
		return KERN_INVALID_ARGUMENT;

	object = (memory_object_t) memory_object;

	potential = 0;
	for (;;) {
		vstruct_t	entry;

		VSL_LOCK();
		queue_iterate(&vstruct_list.vsl_queue, entry, vstruct_t,
			      vs_links) {
			VS_LOCK(entry);
			if (vs_to_mem_obj(entry) == object) {
				VSL_UNLOCK();
				goto found_object;
			}
			VS_UNLOCK(entry);
		}
		VSL_UNLOCK();

		/* did not find the object */
		if (0 != addr)
			kmem_free(ipc_kernel_map, addr, size);

		return KERN_INVALID_ARGUMENT;

	    found_object:

		if (!VS_MAP_TRY_LOCK(entry)) {
			/* oh well bad luck */
			int wresult;

			VS_UNLOCK(entry);

			assert_wait_timeout((event_t)assert_wait_timeout, THREAD_UNINT, 1, 1000*NSEC_PER_USEC);
			wresult = thread_block(THREAD_CONTINUE_NULL);
			assert(wresult == THREAD_TIMED_OUT);
			continue;
		}

		actual = ps_vstruct_allocated_pages(entry, pages, potential);
		VS_MAP_UNLOCK(entry);
		VS_UNLOCK(entry);

		if (actual <= potential)
			break;

		/* allocate more memory */
		if (0 != addr)
			kmem_free(ipc_kernel_map, addr, size);

		size = round_page(actual * sizeof * pages);
		kr = kmem_alloc(ipc_kernel_map, &addr, size);
		if (KERN_SUCCESS != kr)
			return KERN_RESOURCE_SHORTAGE;

		pages = (default_pager_page_t *)addr;
		potential = size / sizeof * pages;
	}

	/*
	 * Clear unused memory.
	 */
	while (actual < potential)
		pages[--potential].dpp_offset = 0;

	kr = vm_map_unwire(ipc_kernel_map, vm_map_trunc_page(addr),
			   vm_map_round_page(addr + size), FALSE);
	assert(KERN_SUCCESS == kr);
	kr = vm_map_copyin(ipc_kernel_map, (vm_map_address_t)addr,
			   (vm_map_size_t)size, TRUE, &copy);
	assert(KERN_SUCCESS == kr);

	
	*pagesp = (default_pager_page_array_t)copy;
	*countp = actual;
	return KERN_SUCCESS;
}
