/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 *	Default Pager.
 *		Memory Object Management.
 */

#include "default_pager_internal.h"
#include <mach/memory_object_server.h>
#include <vm/vm_pageout.h> /* include for upl_t */


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

void vstruct_list_insert(vstruct_t vs);	/* forward */

void
vstruct_list_insert(
	vstruct_t vs)
{
	VSL_LOCK();
	queue_enter(&vstruct_list.vsl_queue, vs, vstruct_t, vs_links);
	vstruct_list.vsl_count++;
	VSL_UNLOCK();
}

void vstruct_list_delete(vstruct_t vs);	/* forward */

void
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

unsigned int	default_pager_total = 0;		/* debugging */
unsigned int	default_pager_wait_seqno = 0;		/* debugging */
unsigned int	default_pager_wait_read = 0;		/* debugging */
unsigned int	default_pager_wait_write = 0;		/* debugging */
unsigned int	default_pager_wait_refs = 0;		/* debugging */

void vs_async_wait(vstruct_t);	/* forward */

void
vs_async_wait(
	vstruct_t	vs)
{
	static char here[] = "vs_async_wait";

	ASSERT(vs->vs_async_pending >= 0);
	while (vs->vs_async_pending > 0) {
		vs->vs_waiting_async = TRUE;
		assert_wait(&vs->vs_waiting_async, THREAD_UNINT);
		VS_UNLOCK(vs);
		thread_block((void (*)(void))0);
		VS_LOCK(vs);
	}
	ASSERT(vs->vs_async_pending == 0);
}

#if	PARALLEL
void vs_lock(vstruct_t, mach_port_seqno_t);
void vs_unlock(vstruct_t);
void vs_start_read(vstruct_t);
void vs_wait_for_readers(vstruct_t);
void vs_finish_read(vstruct_t);
void vs_start_write(vstruct_t);
void vs_wait_for_writers(vstruct_t);
void vs_finish_write(vstruct_t);
void vs_wait_for_refs(vstruct_t);
void vs_finish_refs(vstruct_t);

/* 
 * Waits for correct sequence number.  Leaves pager locked.
 * JMM - Sequence numbers guarantee ordering, but in a preemptible
 *       kernel, they are generated without locks, and so their
 *       generation order is undefined (and therefore unreliable).
 *	 Since we ned to fix this anyway, and I needed to get rid
 *	 rid of asymmetry in the interface definitions, I have
 *       punted this to here.
 */
void
vs_lock(
	vstruct_t		vs,
	mach_port_seqno_t	seqno)
{
	default_pager_total++;
	VS_LOCK(vs);

	seqno = vs->vs_next_seqno++;

	while (vs->vs_seqno != seqno) {
		default_pager_wait_seqno++;
		vs->vs_waiting_seqno = TRUE;
		assert_wait(&vs->vs_waiting_seqno, THREAD_UNINT);
		VS_UNLOCK(vs);
		thread_block((void (*)(void))0);
		VS_LOCK(vs);
	}
}

/*
 * Increments sequence number and unlocks pager.
 */
void
vs_unlock(vstruct_t vs)
{
	boolean_t need_wakeups = vs->vs_waiting_seqno;

	vs->vs_waiting_seqno = FALSE;
	vs->vs_seqno++;
	VS_UNLOCK(vs);
	if (need_wakeups)
		thread_wakeup(&vs->vs_waiting_seqno);
}

/* 
 * Start a read - one more reader.  Pager must be locked.
 */
void
vs_start_read(
	vstruct_t vs)
{
	vs->vs_readers++;
}

/*
 * Wait for readers.  Unlocks and relocks pager if wait needed.
 */
void
vs_wait_for_readers(
	vstruct_t vs)
{
	while (vs->vs_readers != 0) {
		default_pager_wait_read++;
		vs->vs_waiting_read = TRUE;
		assert_wait(&vs->vs_waiting_read, THREAD_UNINT);
		VS_UNLOCK(vs);
		thread_block((void (*)(void))0);
		VS_LOCK(vs);
	}
}

/*
 * Finish a read.  Pager is unlocked and returns unlocked.
 */
void
vs_finish_read(
	vstruct_t vs)
{
	VS_LOCK(vs);
	if (--vs->vs_readers == 0) {
		boolean_t need_wakeups = vs->vs_waiting_read;

		vs->vs_waiting_read = FALSE;
		VS_UNLOCK(vs);
		if (need_wakeups)
			thread_wakeup(&vs->vs_waiting_read);
	} else
		VS_UNLOCK(vs);
}

/*
 * Start a write - one more writer.  Pager must be locked.
 */
void
vs_start_write(
	vstruct_t vs)
{
	vs->vs_writers++;
}

/* 
 * Wait for writers.  Unlocks and relocks pager if wait needed.
 */
void
vs_wait_for_writers(
	vstruct_t vs)
{
	while (vs->vs_writers != 0) {
		default_pager_wait_write++;
		vs->vs_waiting_write = TRUE;
		assert_wait(&vs->vs_waiting_write, THREAD_UNINT);
		VS_UNLOCK(vs);
		thread_block((void (*)(void))0);
		VS_LOCK(vs);
	}
	vs_async_wait(vs);
}

/* This is to be used for the transfer from segment code ONLY */
/* The transfer code holds off vs destruction by keeping the  */
/* vs_async_wait count non-zero.  It will not ocnflict with   */
/* other writers on an async basis because it only writes on  */
/* a cluster basis into fresh (as of sync time) cluster locations */
void 
vs_wait_for_sync_writers(
        vstruct_t vs)
{
        while (vs->vs_writers != 0) {
                default_pager_wait_write++;
		vs->vs_waiting_write = TRUE;
                assert_wait(&vs->vs_waiting_write, THREAD_UNINT);
                VS_UNLOCK(vs);
                thread_block((void (*)(void))0);
                VS_LOCK(vs);
        }
}       


/*
 * Finish a write.  Pager is unlocked and returns unlocked.
 */
void
vs_finish_write(
	vstruct_t vs)
{
	VS_LOCK(vs);
	if (--vs->vs_writers == 0) {
		boolean_t need_wakeups = vs->vs_waiting_write;

		vs->vs_waiting_write = FALSE;
		VS_UNLOCK(vs);
		if (need_wakeups)
			thread_wakeup(&vs->vs_waiting_write);
	} else
		VS_UNLOCK(vs);
}

/*
 * Wait for concurrent default_pager_objects.
 * Unlocks and relocks pager if wait needed.
 */
void
vs_wait_for_refs(
	vstruct_t vs)
{
	while (vs->vs_name_refs == 0) {
		default_pager_wait_refs++;
		vs->vs_waiting_refs = TRUE;
		assert_wait(&vs->vs_waiting_refs, THREAD_UNINT);
		VS_UNLOCK(vs);
		thread_block((void (*)(void))0);
		VS_LOCK(vs);
	}
}

/*
 * Finished creating name refs - wake up waiters.
 */
void
vs_finish_refs(
	vstruct_t vs)
{
	boolean_t need_wakeups = vs->vs_waiting_refs;
	vs->vs_waiting_refs = FALSE;
	if (need_wakeups)
		thread_wakeup(&vs->vs_waiting_refs);
}

#else	/* PARALLEL */

#define	vs_lock(vs,seqno)
#define	vs_unlock(vs)
#define	vs_start_read(vs)
#define	vs_wait_for_readers(vs)
#define	vs_finish_read(vs)
#define	vs_start_write(vs)
#define	vs_wait_for_writers(vs)
#define	vs_wait_for_sync_writers(vs)
#define	vs_finish_write(vs)
#define vs_wait_for_refs(vs)
#define vs_finish_refs(vs)

#endif	/* PARALLEL */

vstruct_t vs_object_create(vm_size_t);	/* forward */

vstruct_t
vs_object_create(
	vm_size_t size)
{
	vstruct_t	vs;
	static char here[] = "vs_object_create";

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

mach_port_urefs_t default_pager_max_urefs = 10000;

/*
 * Check user reference count on memory object control port.
 * Vstruct must be locked.
 * Unlocks and re-locks vstruct if needs to call kernel.
 */
void vs_check_request(vstruct_t, MACH_PORT_FACE);	/* forward */

void
vs_check_request(
	vstruct_t	vs,
	MACH_PORT_FACE	control_port)
{
	mach_port_delta_t delta;
	kern_return_t	kr;
	static char	here[] = "vs_check_request";

	if (++vs->vs_control_refs > default_pager_max_urefs) {
		delta = 1 - vs->vs_control_refs;
		vs->vs_control_refs = 1;

		VS_UNLOCK(vs);

		/*
		 * Deallocate excess user references.
		 */

		{
/* find a better interface for this, what will we use as a component */
			int i;
			delta = -delta;
			for(i=0; i<delta; i++)
				ipc_port_release_send(control_port);
		}

		VS_LOCK(vs);
	}
}

void default_pager_add(vstruct_t, boolean_t);	/* forward */

void
default_pager_add(
	vstruct_t vs,
	boolean_t internal)
{
	MACH_PORT_FACE		mem_obj = vs->vs_mem_obj_port;
	MACH_PORT_FACE		pset;
	mach_port_mscount_t 	sync;
	MACH_PORT_FACE		previous;
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


/*
 * Routine:	dp_memory_object_create
 * Purpose:
 * 	Handle requests for memory objects from the
 * 	kernel.
 * Notes:
 * 	Because we only give out the default memory
 * 	manager port to the kernel, we don't have to
 * 	be so paranoid about the contents.
 */
kern_return_t
dp_memory_object_create(
	MACH_PORT_FACE		dmm,
	MACH_PORT_FACE		*new_mem_obj,
	vm_size_t		new_size)
{
	mach_port_seqno_t	seqno;
	vstruct_t		vs;
	MACH_PORT_FACE		pager;
	static char		here[] = "memory_object_create";

	assert(dmm == default_pager_default_port);

	vs = vs_object_create(new_size);
	if (vs == VSTRUCT_NULL)
		return KERN_RESOURCE_SHORTAGE;

	pager = *new_mem_obj = ipc_port_alloc_kernel();
	assert (pager != IP_NULL);
	(void) ipc_port_make_send(pager);

	{
	   struct vstruct_alias	*alias_struct;

	   alias_struct = (struct vstruct_alias *)
			kalloc(sizeof(struct vstruct_alias));
	   if(alias_struct != NULL) {
		alias_struct->vs = vs;
		alias_struct->name = ISVS;
		pager->alias = (int) alias_struct;
	   }
	   else Panic("Out of kernel memory");

	   /* JMM - Add binding to this pager under components */
	   pager_mux_hash_insert(pager, &dp_memory_object_subsystem);
	   vs->vs_next_seqno = 0;
	   pager->ip_receiver = ipc_space_kernel;
	}

	/*
	 * Set up associations between this port
	 * and this default_pager structure
	 */

	vs->vs_mem_obj_port = pager;

	/*
	 * After this, other threads might receive requests
	 * for this memory object or find it in the port list.
	 */

	vstruct_list_insert(vs);
	default_pager_add(vs, TRUE);

	return KERN_SUCCESS;
}

kern_return_t
dp_memory_object_init(
	MACH_PORT_FACE		mem_obj,
	MACH_PORT_FACE		control_port,
	vm_size_t		pager_page_size)
{
	mach_port_seqno_t	seqno;
	vstruct_t		vs;
	static char		here[] = "memory_object_init";

	assert(pager_page_size == vm_page_size);

	vs_lookup(mem_obj, vs);
	vs_lock(vs, seqno);

	if (vs->vs_control_port != MACH_PORT_NULL)
		Panic("bad request");

	vs->vs_control_port = control_port;
	vs->vs_control_refs = 1;
	vs->vs_object_name = MACH_PORT_NULL;
	vs->vs_name_refs = 1;

	vs_unlock(vs);

	return KERN_SUCCESS;
}

kern_return_t
dp_memory_object_synchronize(
	MACH_PORT_FACE		mem_obj,
	MACH_PORT_FACE		control_port,
	vm_object_offset_t	offset,
	vm_offset_t		length,
	vm_sync_t		flags)
{
	mach_port_seqno_t	seqno;
	vstruct_t	vs;
	static char	here[] = "memory_object_synchronize";

	vs_lookup(mem_obj, vs);
	vs_lock(vs, seqno);
	vs_check_request(vs, control_port);
	vs_unlock(vs);

	memory_object_synchronize_completed(
				vm_object_lookup(control_port), 
				offset, length);

	return KERN_SUCCESS;
}

kern_return_t
dp_memory_object_terminate(
	MACH_PORT_FACE		mem_obj,
	MACH_PORT_FACE		control_port)
{
	mach_port_seqno_t	seqno;
	vstruct_t		vs;
	mach_port_urefs_t	request_refs;
	kern_return_t		kr;
	static char		here[] = "memory_object_terminate";

	/* 
	 * control port is a receive right, not a send right.
	 */

	vs_lookup(mem_obj, vs);
	vs_lock(vs, seqno);

	/*
	 * Wait for read and write requests to terminate.
	 */

	vs_wait_for_readers(vs);
	vs_wait_for_writers(vs);

	/*
	 * After memory_object_terminate both memory_object_init
	 * and a no-senders notification are possible, so we need
	 * to clean up the request and name ports but leave
	 * the mem_obj port.
	 *
	 * A concurrent default_pager_objects might be allocating
	 * more references for the name port.  In this case,
	 * we must first wait for it to finish.
	 */

	vs_wait_for_refs(vs);

	vs->vs_control_port = MACH_PORT_NULL;

	/* a bit of special case ugliness here.  Wakeup any waiting reads */
	/* these data requests had to be removed from the seqno traffic   */
	/* based on a performance bottleneck with large memory objects    */
	/* the problem will right itself with the new component based     */
	/* synchronous interface.  The new async will be able to return   */
	/* failure during its sync phase.   In the mean time ... */

		thread_wakeup(&vs->vs_waiting_write);
		thread_wakeup(&vs->vs_waiting_async);

	request_refs = vs->vs_control_refs;
	vs->vs_control_refs = 0;

	vs->vs_object_name = MACH_PORT_NULL;

	assert(vs->vs_name_refs != 0);
	vs->vs_name_refs = 0;

	vs_unlock(vs);

	/*
	 * Now we deallocate our various port rights.
	 */

	{
		int i;
		for(i=0; i<request_refs; i++)
			ipc_port_release_send(control_port);
	}
        if(control_port->alias != (int)NULL) 
                kfree((vm_offset_t) (control_port->alias), 
					sizeof(struct vstruct_alias));
	ipc_port_release_receive(control_port);
	return KERN_SUCCESS;
}

void
default_pager_no_senders(
	MACH_PORT_FACE		mem_obj,
	mach_port_seqno_t	seqno,
	mach_port_mscount_t	mscount)
{
	vstruct_t		vs;
	static char		here[] = "default_pager_no_senders";

	/*
	 * Because we don't give out multiple send rights
	 * for a memory object, there can't be a race
	 * between getting a no-senders notification
	 * and creating a new send right for the object.
	 * Hence we don't keep track of mscount.
	 */

	vs_lookup(mem_obj, vs);
	vs_lock(vs, seqno);
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
	 * We shouldn't get a no-senders notification
	 * when the kernel has the object cached.
	 */
	if (vs->vs_control_port != MACH_PORT_NULL)
		Panic("bad request");

	/*
	 * Unlock the pager (though there should be no one
	 * waiting for it).
	 */
	VS_UNLOCK(vs);

	/*
	 * Remove the memory object port association, and then
	 * the destroy the port itself.  We must remove the object
	 * from the port list before deallocating the pager,
	 * because of default_pager_objects.
	 */
	vstruct_list_delete(vs);
	ps_vstruct_dealloc(vs);

	/*
	 * Recover memory that we might have wasted because
	 * of name conflicts
	 */
	while (!queue_empty(&vstruct_list.vsl_leak_queue)) {
		vs = (vstruct_t) queue_first(&vstruct_list.vsl_leak_queue);
		queue_remove_first(&vstruct_list.vsl_leak_queue, vs, vstruct_t,
				   vs_links);
		kfree((vm_offset_t) vs, sizeof *vs);
	}
	VSL_UNLOCK();
}

kern_return_t
dp_memory_object_data_request(
	MACH_PORT_FACE		mem_obj,
	MACH_PORT_FACE		reply_to,
	vm_object_offset_t	offset,
	vm_size_t		length,
	vm_prot_t		protection_required)
{
	mach_port_seqno_t	seqno;
	vstruct_t		vs;
	static char		here[] = "memory_object_data_request";

	GSTAT(global_stats.gs_pagein_calls++);


	/* CDY at this moment vs_lookup panics when presented with the wrong */
	/* port.  As we are expanding this pager to support user interfaces */
	/* this should be changed to return kern_failure */
	vs_lookup(mem_obj, vs);
	vs_lock(vs, seqno);
	vs_check_request(vs, reply_to);

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
			assert_wait(&vs->vs_waiting_write, THREAD_UNINT);
			VS_UNLOCK(vs);
			thread_block((void (*)(void))0);
			VS_LOCK(vs);
			vs_async_wait(vs);
		}
		if(vs->vs_control_port == MACH_PORT_NULL) {
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
	MACH_PORT_FACE		mem_obj,
	MACH_PORT_FACE		control_port,
	vm_object_offset_t	offset,
	pointer_t		addr,
	vm_size_t		data_cnt)
{
	mach_port_seqno_t	seqno;
	vstruct_t	vs;
	static char	here[] = "memory_object_data_initialize";

#ifdef	lint
	control_port++;
#endif	/* lint */

	DEBUG(DEBUG_MO_EXTERNAL,
	      ("mem_obj=0x%x,offset=0x%x,cnt=0x%x\n",
	       (int)mem_obj, (int)offset, (int)data_cnt));
	GSTAT(global_stats.gs_pages_init += atop(data_cnt));

	vs_lookup(mem_obj, vs);
	vs_lock(vs, seqno);
	vs_check_request(vs, control_port);
	vs_start_write(vs);
	vs_unlock(vs);

	/*
	 * Write the data via clustered writes. vs_cluster_write will
	 * loop if the address range specified crosses cluster
	 * boundaries.
	 */
	vs_cluster_write(vs, 0, (vm_offset_t)offset, data_cnt, FALSE, 0);

	vs_finish_write(vs);

	return KERN_SUCCESS;
}

kern_return_t
dp_memory_object_lock_completed(
	memory_object_t		mem_obj,
	MACH_PORT_FACE		control_port,
	vm_object_offset_t	offset,
	vm_size_t		length)
{
	mach_port_seqno_t	seqno;
	static char	here[] = "memory_object_lock_completed";

#ifdef	lint
	mem_obj++; 
	seqno++; 
	control_port++; 
	offset++; 
	length++;
#endif	/* lint */

	Panic("illegal");
	return KERN_FAILURE;
}

kern_return_t
dp_memory_object_data_unlock(
	memory_object_t		mem_obj,
	MACH_PORT_FACE		control_port,
	vm_object_offset_t	offset,
	vm_size_t		data_cnt,
	vm_prot_t		desired_access)
{
	static char	here[] = "memory_object_data_unlock";

	Panic("illegal");
	return KERN_FAILURE;
}


kern_return_t
dp_memory_object_supply_completed(
	memory_object_t		mem_obj,
	MACH_PORT_FACE		control_port,
	vm_object_offset_t	offset,
	vm_size_t		length,
	kern_return_t		result,
	vm_offset_t		error_offset)
{
	static char	here[] = "memory_object_supply_completed";

	Panic("illegal");
	return KERN_FAILURE;
}

kern_return_t
dp_memory_object_data_return(
	MACH_PORT_FACE		mem_obj,
	MACH_PORT_FACE		control_port,
	vm_object_offset_t	offset,
	pointer_t		addr,
	vm_size_t		data_cnt,
	boolean_t		dirty,
	boolean_t		kernel_copy)
{
	mach_port_seqno_t	seqno;
	vstruct_t	vs;
	static char	here[] = "memory_object_data_return";

#ifdef	lint
	control_port++;
	dirty++;
	kernel_copy++;
#endif	/* lint */

	DEBUG(DEBUG_MO_EXTERNAL,
	      ("mem_obj=0x%x,offset=0x%x,addr=0x%xcnt=0x%x\n",
	       (int)mem_obj, (int)offset, (int)addr, (int)data_cnt));
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
		upl_system_list_request((vm_object_t)
                                vs->vs_control_port->ip_kobject,
                                offset, data_cnt, data_cnt, &upl, NULL, 0,
				UPL_NOBLOCK | UPL_CLEAN_IN_PLACE 
					| UPL_NO_SYNC | UPL_COPYOUT_FROM);
		uc_upl_abort(upl,0);
		ipc_port_release_send(control_port);
		return KERN_SUCCESS;
	}

	

	if ((vs->vs_seqno != vs->vs_next_seqno++) || (vs->vs_xfer_pending)) {
		upl_t	upl;
		vs->vs_next_seqno--;
                VS_UNLOCK(vs);
		/* the call below will not be done by caller when we have */
		/* a synchronous interface */
		/* return KERN_LOCK_OWNED; */
		upl_system_list_request((vm_object_t)
                                vs->vs_control_port->ip_kobject,
                                offset, data_cnt, data_cnt, &upl, NULL, 0,
				UPL_NOBLOCK | UPL_CLEAN_IN_PLACE 
					| UPL_NO_SYNC | UPL_COPYOUT_FROM);
		uc_upl_abort(upl,0);
		ipc_port_release_send(control_port);
		return KERN_SUCCESS;
	}

	if ((data_cnt % vm_page_size) != 0)
		Panic("bad alignment");

	vs_start_write(vs);


        vs->vs_async_pending += 1;  /* protect from backing store contraction */

	/* unroll vs_check_request to avoid re-locking vs */

	if (++vs->vs_control_refs > default_pager_max_urefs) {
		mach_port_delta_t delta;

		delta = 1 - vs->vs_control_refs;
		vs->vs_control_refs = 1;

		vs_unlock(vs);

		/*
		 * Deallocate excess user references.
		 */

		{
			int i;
			delta = -delta;
			for(i=0; i<delta; i++)
				ipc_port_release_send(control_port);
		}

	} else {
		vs_unlock(vs);
	}

	/*
	 * Write the data via clustered writes. vs_cluster_write will
	 * loop if the address range specified crosses cluster
	 * boundaries.
	 */
	vs_cluster_write(vs, 0, (vm_offset_t)offset, data_cnt, FALSE, 0);

	vs_finish_write(vs);

	/* temporary, need a finer lock based on cluster */

	VS_LOCK(vs);
	vs->vs_async_pending -= 1;  /* release vs_async_wait */
	if (vs->vs_async_pending == 0) {
		VS_UNLOCK(vs);
		thread_wakeup(&vs->vs_waiting_async);
	} else {
		VS_UNLOCK(vs);
	}


	return KERN_SUCCESS;
}

kern_return_t
dp_memory_object_change_completed(
	memory_object_t		mem_obj,
	memory_object_control_t	memory_control,
	memory_object_flavor_t	flavor)
{
	static char	here[] = "memory_object_change_completed";

	Panic("illegal");
	return KERN_FAILURE;
}

/*
 * Create an external object.
 */
kern_return_t
default_pager_object_create(
	MACH_PORT_FACE	pager,
	MACH_PORT_FACE	*mem_obj,
	vm_size_t	size)
{
	vstruct_t	vs;
	MACH_PORT_FACE	port;
	kern_return_t	result;
	struct vstruct_alias	*alias_struct;
	static char	here[] = "default_pager_object_create";


	if (pager != default_pager_default_port)
		return KERN_INVALID_ARGUMENT;

	vs = vs_object_create(size);

	port = ipc_port_alloc_kernel();
	ipc_port_make_send(port);
	/* register abstract memory object port with pager mux routine */
	/* (directs kernel internal calls to the right pager). */
	alias_struct = (struct vstruct_alias *)
			kalloc(sizeof(struct vstruct_alias));
	if(alias_struct != NULL) {
		alias_struct->vs = vs;
		alias_struct->name = ISVS;
		port->alias = (int) alias_struct;
	}
	else Panic("Out of kernel memory");
		
	/*
	 * Set up associations between these ports
	 * and this vstruct structure
	 */

	vs->vs_mem_obj_port = port;
	vstruct_list_insert(vs);
	default_pager_add(vs, FALSE);

	*mem_obj = port;

	return KERN_SUCCESS;
}

kern_return_t
default_pager_objects(
	MACH_PORT_FACE			pager,
	default_pager_object_array_t	*objectsp,
	mach_msg_type_number_t		*ocountp,
	mach_port_array_t		*portsp,
	mach_msg_type_number_t		*pcountp)
{
	vm_offset_t		oaddr = 0;	/* memory for objects */
	vm_size_t		osize = 0;	/* current size */
	default_pager_object_t	* objects;
	unsigned int		opotential;

	vm_offset_t		paddr = 0;	/* memory for ports */
	vm_size_t		psize = 0;	/* current size */
	MACH_PORT_FACE		 * ports;
	unsigned int		ppotential;

	unsigned int		actual;
	unsigned int		num_objects;
	kern_return_t		kr;
	vstruct_t		entry;
	static char		here[] = "default_pager_objects";
/*
	if (pager != default_pager_default_port)
		return KERN_INVALID_ARGUMENT;
*/

	/* start with the inline memory */

	kr = vm_map_copyout(ipc_kernel_map, (vm_offset_t *)&objects, 
						(vm_map_copy_t) *objectsp);

	if (kr != KERN_SUCCESS)
		return kr;

	osize = round_page(*ocountp * sizeof * objects);
	kr = vm_map_wire(ipc_kernel_map, 
			trunc_page((vm_offset_t)objects),
			round_page(((vm_offset_t)objects) + osize), 
			VM_PROT_READ|VM_PROT_WRITE, FALSE);
	osize=0;

	*objectsp = objects;
	/* we start with the inline space */


	num_objects = 0;
	opotential = *ocountp;

	ports = (MACH_PORT_FACE *) *portsp;
	ppotential = *pcountp;

	VSL_LOCK();

	/*
	 * We will send no more than this many
	 */
	actual = vstruct_list.vsl_count;
	VSL_UNLOCK();

	if (opotential < actual) {
		vm_offset_t	newaddr;
		vm_size_t	newsize;

		newsize = 2 * round_page(actual * sizeof * objects);

		kr = vm_allocate(kernel_map, &newaddr, newsize, TRUE);
		if (kr != KERN_SUCCESS)
			goto nomemory;

		oaddr = newaddr;
		osize = newsize;
		opotential = osize / sizeof * objects;
		objects = (default_pager_object_t *)oaddr;
	}

	if (ppotential < actual) {
		vm_offset_t	newaddr;
		vm_size_t	newsize;

		newsize = 2 * round_page(actual * sizeof * ports);

		kr = vm_allocate(kernel_map, &newaddr, newsize, TRUE);
		if (kr != KERN_SUCCESS)
			goto nomemory;

		paddr = newaddr;
		psize = newsize;
		ppotential = psize / sizeof * ports;
		ports = (MACH_PORT_FACE *)paddr;
	}

	/*
	 * Now scan the list.
	 */

	VSL_LOCK();

	num_objects = 0;
	queue_iterate(&vstruct_list.vsl_queue, entry, vstruct_t, vs_links) {

		MACH_PORT_FACE		port;
		vm_size_t		size;

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

		port = entry->vs_object_name;
		if (port == MACH_PORT_NULL) {

			/*
			 * The object is waiting for no-senders
			 * or memory_object_init.
			 */
			VS_UNLOCK(entry);
			goto not_this_one;
		}

		/*
		 * We need a reference for the reply message.
		 * While we are unlocked, the bucket queue
		 * can change and the object might be terminated.
		 * memory_object_terminate will wait for us,
		 * preventing deallocation of the entry.
		 */

		if (--entry->vs_name_refs == 0) {
			VS_UNLOCK(entry);

			/* keep the list locked, wont take long */

			{
				int i;
				for(i=0; i<default_pager_max_urefs; i++)
					ipc_port_make_send(port);
			}
			VS_LOCK(entry);

			entry->vs_name_refs += default_pager_max_urefs;
			vs_finish_refs(entry);
		}
		VS_UNLOCK(entry);

		/* the arrays are wired, so no deadlock worries */

		objects[num_objects].dpo_object = (vm_offset_t) entry;
		objects[num_objects].dpo_size = size;
		ports  [num_objects++] = port;
		continue;

	    not_this_one:
		/*
		 * Do not return garbage
		 */
		objects[num_objects].dpo_object = (vm_offset_t) 0;
		objects[num_objects].dpo_size = 0;
		ports  [num_objects++] = MACH_PORT_NULL;

	}

	VSL_UNLOCK();

	/*
	 * Deallocate and clear unused memory.
	 * (Returned memory will automagically become pageable.)
	 */

	if (objects == *objectsp) {

		/*
		 * Our returned information fit inline.
		 * Nothing to deallocate.
		 */
		*ocountp = num_objects;
	} else if (actual == 0) {
		(void) vm_deallocate(kernel_map, oaddr, osize);

		/* return zero items inline */
		*ocountp = 0;
	} else {
		vm_offset_t used;

		used = round_page(actual * sizeof * objects);

		if (used != osize)
			(void) vm_deallocate(kernel_map,
					     oaddr + used, osize - used);

		*objectsp = objects;
		*ocountp = num_objects;
	}

	if (ports == (MACH_PORT_FACE *)*portsp) {

		/*
		 * Our returned information fit inline.
		 * Nothing to deallocate.
		 */

		*pcountp = num_objects;
	} else if (actual == 0) {
		(void) vm_deallocate(kernel_map, paddr, psize);

		/* return zero items inline */
		*pcountp = 0;
	} else {
		vm_offset_t used;

		used = round_page(actual * sizeof * ports);

		if (used != psize)
			(void) vm_deallocate(kernel_map,
					     paddr + used, psize - used);

		*portsp = (mach_port_array_t)ports;
		*pcountp = num_objects;
	}
	(void) vm_map_unwire(kernel_map, (vm_offset_t)objects, 
			*ocountp + (vm_offset_t)objects, FALSE); 
	(void) vm_map_copyin(kernel_map, (vm_offset_t)objects, 
			*ocountp, TRUE, (vm_map_copy_t *)objectsp);

	return KERN_SUCCESS;

    nomemory:
	{
		register int	i;
		for (i = 0; i < num_objects; i++)
			ipc_port_dealloc_kernel(ports[i]);
	}

	if (objects != *objectsp)
		(void) vm_deallocate(kernel_map, oaddr, osize);

	if (ports != (MACH_PORT_FACE *)*portsp)
		(void) vm_deallocate(kernel_map, paddr, psize);

	return KERN_RESOURCE_SHORTAGE;
}

kern_return_t
default_pager_object_pages(
	MACH_PORT_FACE			pager,
	MACH_PORT_FACE			object,
	default_pager_page_array_t	*pagesp,
	mach_msg_type_number_t		*countp)
{
	vm_offset_t			addr;	/* memory for page offsets */
	vm_size_t			size = 0; /* current memory size */
	default_pager_page_t		* pages;
	unsigned int			potential, actual;
	kern_return_t			kr;

/*
	if (pager != default_pager_default_port)
		return KERN_INVALID_ARGUMENT;
*/
	kr = vm_map_copyout(ipc_kernel_map, (vm_offset_t *)&pages, 
						(vm_map_copy_t) *pagesp);

	if (kr != KERN_SUCCESS)
		return kr;

	size = round_page(*countp * sizeof * pages);
	kr = vm_map_wire(ipc_kernel_map, 
			trunc_page((vm_offset_t)pages),
			round_page(((vm_offset_t)pages) + size), 
			VM_PROT_READ|VM_PROT_WRITE, FALSE);
	size=0;

	*pagesp = pages;
	/* we start with the inline space */

	addr = (vm_offset_t)pages;
	potential = *countp;

	for (;;) {
		vstruct_t	entry;

		VSL_LOCK();
		queue_iterate(&vstruct_list.vsl_queue, entry, vstruct_t,
			      vs_links) {
			VS_LOCK(entry);
			if (entry->vs_object_name == object) {
				VSL_UNLOCK();
				goto found_object;
			}
			VS_UNLOCK(entry);
		}
		VSL_UNLOCK();

		/* did not find the object */

		if (pages != *pagesp)
			(void) vm_deallocate(kernel_map, addr, size);
		return KERN_INVALID_ARGUMENT;

	    found_object:

		if (!VS_MAP_TRY_LOCK(entry)) {
			/* oh well bad luck */
			int wait_result;

			VS_UNLOCK(entry);

			assert_wait_timeout( 1, THREAD_INTERRUPTIBLE);
			wait_result = thread_block((void (*)(void)) 0);
			if (wait_result != THREAD_TIMED_OUT)
				thread_cancel_timer();
			continue;
		}

		actual = ps_vstruct_allocated_pages(entry, pages, potential);
		VS_MAP_UNLOCK(entry);
		VS_UNLOCK(entry);

		if (actual <= potential)
			break;

		/* allocate more memory */

		if (pages != *pagesp)
			(void) vm_deallocate(kernel_map, addr, size);
		size = round_page(actual * sizeof * pages);
		kr = vm_allocate(kernel_map, &addr, size, TRUE);
		if (kr != KERN_SUCCESS)
			return kr;
		pages = (default_pager_page_t *)addr;
		potential = size / sizeof * pages;
	}

	/*
	 * Deallocate and clear unused memory.
	 * (Returned memory will automagically become pageable.)
	 */

	if (pages == *pagesp) {

		/*
		 * Our returned information fit inline.
		 * Nothing to deallocate.
		 */

		*countp = actual;
	} else if (actual == 0) {
		(void) vm_deallocate(kernel_map, addr, size);

		/* return zero items inline */
		*countp = 0;
	} else {
		vm_offset_t used;

		used = round_page(actual * sizeof * pages);

		if (used != size)
			(void) vm_deallocate(kernel_map,
					     addr + used, size - used);

		*pagesp = pages;
		*countp = actual;
	}
	(void) vm_map_unwire(kernel_map, (vm_offset_t)pages, 
			*countp + (vm_offset_t)pages, FALSE); 
	(void) vm_map_copyin(kernel_map, (vm_offset_t)pages, 
			*countp, TRUE, (vm_map_copy_t *)pagesp);
	return KERN_SUCCESS;
}
