/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
 *	Default Pager.
 *		Paging File Management.
 */

#include <mach/host_priv.h>
#include <mach/memory_object_control.h>
#include <mach/memory_object_server.h>
#include <mach/upl.h>
#include <default_pager/default_pager_internal.h>
#include <default_pager/default_pager_alerts.h>
#include <default_pager/default_pager_object_server.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

#include <kern/kern_types.h>
#include <kern/host.h>
#include <kern/queue.h>
#include <kern/counters.h>
#include <kern/sched_prim.h>

#include <vm/vm_kern.h> 
#include <vm/vm_pageout.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_protos.h>


/* todo - need large internal object support */

/*
 * ALLOC_STRIDE... the maximum number of bytes allocated from
 * a swap file before moving on to the next swap file... if
 * all swap files reside on a single disk, this value should
 * be very large (this is the default assumption)... if the 
 * swap files are spread across multiple disks, than this value
 * should be small (128 * 1024)...
 *
 * This should be determined dynamically in the future
 */

#define ALLOC_STRIDE  (1024 * 1024 * 1024)
int physical_transfer_cluster_count = 0;

#define VM_SUPER_CLUSTER	0x40000
#define VM_SUPER_PAGES          64

/*
 * 0 means no shift to pages, so == 1 page/cluster. 1 would mean
 * 2 pages/cluster, 2 means 4 pages/cluster, and so on.
 */
#define VSTRUCT_DEF_CLSHIFT	2
int vstruct_def_clshift = VSTRUCT_DEF_CLSHIFT;
int default_pager_clsize = 0;

/* statistics */
unsigned int clustered_writes[VM_SUPER_PAGES+1];
unsigned int clustered_reads[VM_SUPER_PAGES+1];

/*
 * Globals used for asynchronous paging operations:
 * 	vs_async_list:	head of list of to-be-completed I/O ops
 *	async_num_queued: number of pages completed, but not yet
 *		processed by async thread.
 *	async_requests_out: number of pages of requests not completed.
 */

#if 0
struct vs_async *vs_async_list;
int	async_num_queued;
int	async_requests_out;
#endif


#define VS_ASYNC_REUSE 1
struct vs_async *vs_async_free_list;

lck_mtx_t	default_pager_async_lock;	/* Protects globals above */


int vs_alloc_async_failed = 0;			/* statistics */
int vs_alloc_async_count = 0;			/* statistics */
struct vs_async *vs_alloc_async(void);		/* forward */
void vs_free_async(struct vs_async *vsa);	/* forward */


#define VS_ALLOC_ASYNC()	vs_alloc_async()
#define VS_FREE_ASYNC(vsa)	vs_free_async(vsa)

#define VS_ASYNC_LOCK()		lck_mtx_lock(&default_pager_async_lock)
#define VS_ASYNC_UNLOCK()	lck_mtx_unlock(&default_pager_async_lock)
#define VS_ASYNC_LOCK_INIT()	lck_mtx_init(&default_pager_async_lock, &default_pager_lck_grp, &default_pager_lck_attr)
#define VS_ASYNC_LOCK_ADDR()	(&default_pager_async_lock)
/*
 *  Paging Space Hysteresis triggers and the target notification port
 *
 */ 
unsigned int	dp_pages_free_drift_count = 0;
unsigned int	dp_pages_free_drifted_max = 0;
unsigned int	minimum_pages_remaining	= 0;
unsigned int	maximum_pages_free = 0;
ipc_port_t	min_pages_trigger_port = NULL;
ipc_port_t	max_pages_trigger_port = NULL;

boolean_t	use_emergency_swap_file_first = FALSE;
boolean_t	bs_low = FALSE;
int		backing_store_release_trigger_disable = 0;
boolean_t	backing_store_stop_compaction = FALSE;


/* Have we decided if swap needs to be encrypted yet ? */
boolean_t	dp_encryption_inited = FALSE;
/* Should we encrypt swap ? */
boolean_t	dp_encryption = FALSE;


/*
 * Object sizes are rounded up to the next power of 2,
 * unless they are bigger than a given maximum size.
 */
vm_size_t	max_doubled_size = 4 * 1024 * 1024;	/* 4 meg */

/*
 * List of all backing store and segments.
 */
MACH_PORT_FACE		emergency_segment_backing_store;
struct backing_store_list_head backing_store_list;
paging_segment_t	paging_segments[MAX_NUM_PAGING_SEGMENTS];
lck_mtx_t			paging_segments_lock;
int			paging_segment_max = 0;
int			paging_segment_count = 0;
int ps_select_array[BS_MAXPRI+1] = { -1,-1,-1,-1,-1 };


/*
 * Total pages free in system
 * This differs from clusters committed/avail which is a measure of the
 * over commitment of paging segments to backing store.  An idea which is
 * likely to be deprecated.
 */
unsigned  int	dp_pages_free = 0;
unsigned  int	dp_pages_reserve = 0;
unsigned  int	cluster_transfer_minimum = 100;

/* forward declarations */
kern_return_t ps_write_file(paging_segment_t, upl_t, upl_offset_t, dp_offset_t, unsigned int, int);	/* forward */
kern_return_t ps_read_file (paging_segment_t, upl_t, upl_offset_t, dp_offset_t, unsigned int, unsigned int *, int);	/* forward */
default_pager_thread_t *get_read_buffer( void );
kern_return_t ps_vstruct_transfer_from_segment(
	vstruct_t	 vs,
	paging_segment_t segment,
	upl_t		 upl);
kern_return_t ps_read_device(paging_segment_t, dp_offset_t, vm_offset_t *, unsigned int, unsigned int *, int);	/* forward */
kern_return_t ps_write_device(paging_segment_t, dp_offset_t, vm_offset_t, unsigned int, struct vs_async *);	/* forward */
kern_return_t vs_cluster_transfer(
	vstruct_t	vs,
	dp_offset_t	offset,
	dp_size_t	cnt,
	upl_t		upl);
vs_map_t vs_get_map_entry(
	vstruct_t	vs, 
	dp_offset_t	offset);

kern_return_t
default_pager_backing_store_delete_internal( MACH_PORT_FACE );

default_pager_thread_t *
get_read_buffer( void )
{
	int	i;

	DPT_LOCK(dpt_lock);
	while(TRUE) {
		for (i=0; i<default_pager_internal_count; i++) {
			if(dpt_array[i]->checked_out == FALSE) {
			  dpt_array[i]->checked_out = TRUE;
			  DPT_UNLOCK(dpt_lock);
			  return  dpt_array[i];
			}
		}
		DPT_SLEEP(dpt_lock, &dpt_array, THREAD_UNINT);
	}
}

void
bs_initialize(void)
{
	int i;

	/*
	 * List of all backing store.
	 */
	BSL_LOCK_INIT();
	queue_init(&backing_store_list.bsl_queue);
	PSL_LOCK_INIT();

	VS_ASYNC_LOCK_INIT();
#if	VS_ASYNC_REUSE
	vs_async_free_list = NULL;
#endif	/* VS_ASYNC_REUSE */

	for (i = 0; i < VM_SUPER_PAGES + 1; i++) {
		clustered_writes[i] = 0;
		clustered_reads[i] = 0;
	}

}

/*
 * When things do not quite workout...
 */
void bs_no_paging_space(boolean_t);	/* forward */

void
bs_no_paging_space(
	boolean_t out_of_memory)
{

	if (out_of_memory)
		dprintf(("*** OUT OF MEMORY ***\n"));
	panic("bs_no_paging_space: NOT ENOUGH PAGING SPACE");
}

void bs_more_space(int);	/* forward */
void bs_commit(int);		/* forward */

boolean_t	user_warned = FALSE;
unsigned int	clusters_committed = 0;
unsigned int	clusters_available = 0;
unsigned int	clusters_committed_peak = 0;

void
bs_more_space(
	int	nclusters)
{
	BSL_LOCK();
	/*
	 * Account for new paging space.
	 */
	clusters_available += nclusters;

	if (clusters_available >= clusters_committed) {
		if (verbose && user_warned) {
			printf("%s%s - %d excess clusters now.\n",
			       my_name,
			       "paging space is OK now",
			       clusters_available - clusters_committed);
			user_warned = FALSE;
			clusters_committed_peak = 0;
		}
	} else {
		if (verbose && user_warned) {
			printf("%s%s - still short of %d clusters.\n",
			       my_name,
			       "WARNING: paging space over-committed",
			       clusters_committed - clusters_available);
			clusters_committed_peak -= nclusters;
		}
	}
	BSL_UNLOCK();

	return;
}

void
bs_commit(
	int	nclusters)
{
	BSL_LOCK();
	clusters_committed += nclusters;
	if (clusters_committed > clusters_available) {
		if (verbose && !user_warned) {
			user_warned = TRUE;
			printf("%s%s - short of %d clusters.\n",
			       my_name,
			       "WARNING: paging space over-committed",
			       clusters_committed - clusters_available);
		}
		if (clusters_committed > clusters_committed_peak) {
			clusters_committed_peak = clusters_committed;
		}
	} else {
		if (verbose && user_warned) {
			printf("%s%s - was short of up to %d clusters.\n",
			       my_name,
			       "paging space is OK now",
			       clusters_committed_peak - clusters_available);
			user_warned = FALSE;
			clusters_committed_peak = 0;
		}
	}
	BSL_UNLOCK();

	return;
}

int default_pager_info_verbose = 1;

void
bs_global_info(
	uint64_t	*totalp,
	uint64_t	*freep)
{
	uint64_t		pages_total, pages_free;
	paging_segment_t	ps;
	int			i;

	PSL_LOCK();
	pages_total = pages_free = 0;
	for (i = 0; i <= paging_segment_max; i++) {
		ps = paging_segments[i];
		if (ps == PAGING_SEGMENT_NULL) 
			continue;

		/*
		 * no need to lock: by the time this data
		 * gets back to any remote requestor it
		 * will be obsolete anyways
		 */
		pages_total += ps->ps_pgnum;
		pages_free += ps->ps_clcount << ps->ps_clshift;
		DP_DEBUG(DEBUG_BS_INTERNAL,
			 ("segment #%d: %d total, %d free\n",
			  i, ps->ps_pgnum, ps->ps_clcount << ps->ps_clshift));
	}
	*totalp = pages_total;
	*freep = pages_free;
	if (verbose && user_warned && default_pager_info_verbose) {
		if (clusters_available < clusters_committed) {
			printf("%s %d clusters committed, %d available.\n",
			       my_name,
			       clusters_committed,
			       clusters_available);
		}
	}
	PSL_UNLOCK();
}

backing_store_t backing_store_alloc(void);	/* forward */

backing_store_t
backing_store_alloc(void)
{
	backing_store_t bs;

	bs = (backing_store_t) kalloc(sizeof (struct backing_store));
	if (bs == BACKING_STORE_NULL)
		panic("backing_store_alloc: no memory");

	BS_LOCK_INIT(bs);
	bs->bs_port = MACH_PORT_NULL;
	bs->bs_priority = 0;
	bs->bs_clsize = 0;
	bs->bs_pages_total = 0;
	bs->bs_pages_in = 0;
	bs->bs_pages_in_fail = 0;
	bs->bs_pages_out = 0;
	bs->bs_pages_out_fail = 0;

	return bs;
}

backing_store_t backing_store_lookup(MACH_PORT_FACE);	/* forward */

/* Even in both the component space and external versions of this pager, */
/* backing_store_lookup will be called from tasks in the application space */
backing_store_t
backing_store_lookup(
	MACH_PORT_FACE port)
{
	backing_store_t	bs;

/*
	port is currently backed with a vs structure in the alias field
	we could create an ISBS alias and a port_is_bs call but frankly
	I see no reason for the test, the bs->port == port check below
	will work properly on junk entries.

	if ((port == MACH_PORT_NULL) || port_is_vs(port))
*/
	if ((port == MACH_PORT_NULL))
		return BACKING_STORE_NULL;

	BSL_LOCK();
	queue_iterate(&backing_store_list.bsl_queue, bs, backing_store_t,
		      bs_links) {
		BS_LOCK(bs);
		if (bs->bs_port == port) {
			BSL_UNLOCK();
			/* Success, return it locked. */
			return bs;
		}
		BS_UNLOCK(bs);
	}
	BSL_UNLOCK();
	return BACKING_STORE_NULL;
}

void backing_store_add(backing_store_t);	/* forward */

void
backing_store_add(
	__unused backing_store_t bs)
{
//	MACH_PORT_FACE		port = bs->bs_port;
//	MACH_PORT_FACE		pset = default_pager_default_set;
	kern_return_t		kr = KERN_SUCCESS;

	if (kr != KERN_SUCCESS)
		panic("backing_store_add: add to set");

}

/*
 * Set up default page shift, but only if not already
 * set and argument is within range.
 */
boolean_t
bs_set_default_clsize(unsigned int npages)
{
	switch(npages){
	    case 1:
	    case 2:
	    case 4:
	    case 8:
		if (default_pager_clsize == 0)	/* if not yet set */
			vstruct_def_clshift = local_log2(npages);
		return(TRUE);
	}
	return(FALSE);
}

int bs_get_global_clsize(int clsize);	/* forward */

int
bs_get_global_clsize(
	int	clsize)
{
	int			i;
	memory_object_default_t	dmm;
	kern_return_t		kr;

	/*
	 * Only allow setting of cluster size once. If called
	 * with no cluster size (default), we use the compiled-in default
	 * for the duration. The same cluster size is used for all
	 * paging segments.
	 */
	if (default_pager_clsize == 0) {
		/*
		 * Keep cluster size in bit shift because it's quicker
		 * arithmetic, and easier to keep at a power of 2.
		 */
		if (clsize != NO_CLSIZE) {
			for (i = 0; (1 << i) < clsize; i++);
			if (i > MAX_CLUSTER_SHIFT)
				i = MAX_CLUSTER_SHIFT;
			vstruct_def_clshift = i;
		}
		default_pager_clsize = (1 << vstruct_def_clshift);

		/*
		 * Let the user know the new (and definitive) cluster size.
		 */
		if (verbose)
			printf("%scluster size = %d page%s\n",
		       		my_name, default_pager_clsize,
		       		(default_pager_clsize == 1) ? "" : "s");

		/*
		 * Let the kernel know too, in case it hasn't used the
		 * default value provided in main() yet.
		 */
		dmm = default_pager_object;
		clsize = default_pager_clsize * vm_page_size;	/* in bytes */
		kr = host_default_memory_manager(host_priv_self(),
						 &dmm,
						 clsize);
		memory_object_default_deallocate(dmm);

		if (kr != KERN_SUCCESS) {
		   panic("bs_get_global_cl_size:host_default_memory_manager");
		}
		if (dmm != default_pager_object) {
		  panic("bs_get_global_cl_size:there is another default pager");
		}
	}
	ASSERT(default_pager_clsize > 0 &&
	       (default_pager_clsize & (default_pager_clsize - 1)) == 0);

	return default_pager_clsize;
}

kern_return_t
default_pager_backing_store_create(
	memory_object_default_t	pager,
	int			priority,
	int			clsize,		/* in bytes */
	MACH_PORT_FACE		*backing_store)
{
	backing_store_t	bs;
	MACH_PORT_FACE	port;
//	kern_return_t	kr;
	struct vstruct_alias *alias_struct;

	if (pager != default_pager_object)
		return KERN_INVALID_ARGUMENT;

	bs = backing_store_alloc();
	port = ipc_port_alloc_kernel();
	ipc_port_make_send(port);
	assert (port != IP_NULL);

	DP_DEBUG(DEBUG_BS_EXTERNAL,
		 ("priority=%d clsize=%d bs_port=0x%x\n",
		  priority, clsize, (int) backing_store));

	alias_struct = (struct vstruct_alias *) 
				kalloc(sizeof (struct vstruct_alias));
	if(alias_struct != NULL) {
		alias_struct->vs = (struct vstruct *)bs;
		alias_struct->name = &default_pager_ops;
		port->alias = (uintptr_t) alias_struct;
	}
	else {
		ipc_port_dealloc_kernel((MACH_PORT_FACE)(port));
		kfree(bs, sizeof (struct backing_store));
		return KERN_RESOURCE_SHORTAGE;
	}

	bs->bs_port = port;
	if (priority == DEFAULT_PAGER_BACKING_STORE_MAXPRI)
		priority = BS_MAXPRI;
	else if (priority == BS_NOPRI)
		priority = BS_MAXPRI;
	else
		priority = BS_MINPRI;
	bs->bs_priority = priority;

	bs->bs_clsize = bs_get_global_clsize(atop_32(clsize));

	BSL_LOCK();
	queue_enter(&backing_store_list.bsl_queue, bs, backing_store_t,
		    bs_links);
	BSL_UNLOCK();

	backing_store_add(bs);

	*backing_store = port;
	return KERN_SUCCESS;
}

kern_return_t
default_pager_backing_store_info(
	MACH_PORT_FACE		backing_store,
	backing_store_flavor_t	flavour,
	backing_store_info_t	info,
	mach_msg_type_number_t	*size)
{
	backing_store_t			bs;
	backing_store_basic_info_t	basic;
	int				i;
	paging_segment_t		ps;

	if (flavour != BACKING_STORE_BASIC_INFO ||
	    *size < BACKING_STORE_BASIC_INFO_COUNT)
		return KERN_INVALID_ARGUMENT;

	basic = (backing_store_basic_info_t)info;
	*size = BACKING_STORE_BASIC_INFO_COUNT;

	VSTATS_LOCK(&global_stats.gs_lock);
	basic->pageout_calls	= global_stats.gs_pageout_calls;
	basic->pagein_calls	= global_stats.gs_pagein_calls;
	basic->pages_in		= global_stats.gs_pages_in;
	basic->pages_out	= global_stats.gs_pages_out;
	basic->pages_unavail	= global_stats.gs_pages_unavail;
	basic->pages_init	= global_stats.gs_pages_init;
	basic->pages_init_writes= global_stats.gs_pages_init_writes;
	VSTATS_UNLOCK(&global_stats.gs_lock);

	if ((bs = backing_store_lookup(backing_store)) == BACKING_STORE_NULL)
		return KERN_INVALID_ARGUMENT;

	basic->bs_pages_total	= bs->bs_pages_total;
	PSL_LOCK();
	bs->bs_pages_free = 0;
	for (i = 0; i <= paging_segment_max; i++) {
		ps = paging_segments[i];
		if (ps != PAGING_SEGMENT_NULL && ps->ps_bs == bs) {
			PS_LOCK(ps);
			bs->bs_pages_free += ps->ps_clcount << ps->ps_clshift;
			PS_UNLOCK(ps);
		}
	}
	PSL_UNLOCK();
	basic->bs_pages_free	= bs->bs_pages_free;
	basic->bs_pages_in	= bs->bs_pages_in;
	basic->bs_pages_in_fail	= bs->bs_pages_in_fail;
	basic->bs_pages_out	= bs->bs_pages_out;
	basic->bs_pages_out_fail= bs->bs_pages_out_fail;

	basic->bs_priority	= bs->bs_priority;
	basic->bs_clsize	= ptoa_32(bs->bs_clsize);	/* in bytes */

	BS_UNLOCK(bs);

	return KERN_SUCCESS;
}

int ps_delete(paging_segment_t);	/* forward */
boolean_t current_thread_aborted(void);

int
ps_delete(
	paging_segment_t ps)
{
	vstruct_t	vs;
	kern_return_t	error = KERN_SUCCESS;
	int		vs_count;
	
	VSL_LOCK();  		/* get the lock on the list of vs's	 */

	/* The lock relationship and sequence is farily complicated  	 */
	/* this code looks at a live list, locking and unlocking the list */
	/* as it traverses it.  It depends on the locking behavior of	 */
	/* default_pager_no_senders.  no_senders always locks the vstruct */
	/* targeted for removal before locking the vstruct list.  However */
	/* it will remove that member of the list without locking its    */
	/* neighbors.  We can be sure when we hold a lock on a vstruct   */
	/* it cannot be removed from the list but we must hold the list  */
	/* lock to be sure that its pointers to its neighbors are valid. */
	/* Also, we can hold off destruction of a vstruct when the list  */
	/* lock and the vs locks are not being held by bumping the 	 */
	/* vs_async_pending count.      */


	while(backing_store_release_trigger_disable != 0) {
		VSL_SLEEP(&backing_store_release_trigger_disable, THREAD_UNINT);
	}

	/* we will choose instead to hold a send right */
	vs_count = vstruct_list.vsl_count;
	vs = (vstruct_t) queue_first((queue_entry_t)&(vstruct_list.vsl_queue));
	if(vs == (vstruct_t)&vstruct_list)  {
		VSL_UNLOCK();
		return KERN_SUCCESS;
	}
	VS_LOCK(vs);
	vs_async_wait(vs);  /* wait for any pending async writes */
	if ((vs_count != 0) && (vs != NULL))
		vs->vs_async_pending += 1;  /* hold parties calling  */
					    /* vs_async_wait */
	VS_UNLOCK(vs);
	VSL_UNLOCK();
	while((vs_count != 0) && (vs != NULL)) {
		/* We take the count of AMO's before beginning the         */
		/* transfer of of the target segment.                      */
		/* We are guaranteed that the target segment cannot get    */
		/* more users.  We also know that queue entries are        */
		/* made at the back of the list.  If some of the entries   */
		/* we would check disappear while we are traversing the    */
		/* list then we will either check new entries which        */
		/* do not have any backing store in the target segment     */
		/* or re-check old entries.  This might not be optimal     */
		/* but it will always be correct. The alternative is to    */
		/* take a snapshot of the list.			   	   */
		vstruct_t	next_vs;
		
		if(dp_pages_free < cluster_transfer_minimum)
			error = KERN_FAILURE;
		else {
			vm_object_t	transfer_object;
			unsigned int	count;
			upl_t		upl;

			transfer_object = vm_object_allocate((vm_object_size_t)VM_SUPER_CLUSTER);
			count = 0;
			error = vm_object_upl_request(transfer_object, 
				(vm_object_offset_t)0, VM_SUPER_CLUSTER,
				&upl, NULL, &count,
				UPL_NO_SYNC | UPL_CLEAN_IN_PLACE | UPL_SET_LITE | UPL_SET_INTERNAL);

			if(error == KERN_SUCCESS) {
				error = ps_vstruct_transfer_from_segment(
							vs, ps, upl);
				upl_commit(upl, NULL, 0);
				upl_deallocate(upl);
			} else {
				error = KERN_FAILURE;
			}
			vm_object_deallocate(transfer_object);
		}
		if(error || current_thread_aborted() || backing_store_stop_compaction) {
			VS_LOCK(vs);
			vs->vs_async_pending -= 1;  /* release vs_async_wait */
			if (vs->vs_async_pending == 0 && vs->vs_waiting_async) {
				vs->vs_waiting_async = FALSE;
				VS_UNLOCK(vs);
				thread_wakeup(&vs->vs_async_pending);
			} else {
				VS_UNLOCK(vs);
			}
			return KERN_FAILURE;
		}

		VSL_LOCK(); 

		while(backing_store_release_trigger_disable != 0) {
			VSL_SLEEP(&backing_store_release_trigger_disable,
				  THREAD_UNINT);
		}

		next_vs = (vstruct_t) queue_next(&(vs->vs_links));
		if((next_vs != (vstruct_t)&vstruct_list) && 
				(vs != next_vs) && (vs_count != 1)) {
			VS_LOCK(next_vs);
			vs_async_wait(next_vs);  /* wait for any  */
						 /* pending async writes */
			next_vs->vs_async_pending += 1; /* hold parties  */
						/* calling vs_async_wait */
			VS_UNLOCK(next_vs);
		}
		VSL_UNLOCK();
		VS_LOCK(vs);
		vs->vs_async_pending -= 1; 
		if (vs->vs_async_pending == 0 && vs->vs_waiting_async) {
			vs->vs_waiting_async = FALSE;
			VS_UNLOCK(vs);
			thread_wakeup(&vs->vs_async_pending);
		} else {
			VS_UNLOCK(vs);
		}
		if((vs == next_vs) || (next_vs == (vstruct_t)&vstruct_list))
			vs = NULL;
		else
			vs = next_vs;
		vs_count--;
	}
	return KERN_SUCCESS;
}


kern_return_t
default_pager_backing_store_delete_internal(
	MACH_PORT_FACE backing_store)
{
	backing_store_t		bs;
	int			i;
	paging_segment_t	ps;
	int			error;
	int			interim_pages_removed = 0;
	boolean_t		dealing_with_emergency_segment = ( backing_store == emergency_segment_backing_store );

	if ((bs = backing_store_lookup(backing_store)) == BACKING_STORE_NULL)
		return KERN_INVALID_ARGUMENT;

restart:
	PSL_LOCK();
	error = KERN_SUCCESS;
	for (i = 0; i <= paging_segment_max; i++) {
		ps = paging_segments[i];
		if (ps != PAGING_SEGMENT_NULL &&
		    ps->ps_bs == bs &&
		    ! IS_PS_GOING_AWAY(ps)) {
			PS_LOCK(ps);
			
			if( IS_PS_GOING_AWAY(ps) || !IS_PS_OK_TO_USE(ps)) {
			/* 
			 * Someone is already busy reclamining this paging segment.
			 * If it's the emergency segment we are looking at then check
			 * that someone has not already recovered it and set the right
			 * state i.e. online but not activated.
			 */
				PS_UNLOCK(ps);
				continue;
			}

			/* disable access to this segment */
			ps->ps_state &= ~PS_CAN_USE;
			ps->ps_state |= PS_GOING_AWAY;
			PS_UNLOCK(ps);
			/*
			 * The "ps" segment is "off-line" now,
			 * we can try and delete it...
			 */
			if(dp_pages_free < (cluster_transfer_minimum
				 			+ ps->ps_pgcount)) {
				error = KERN_FAILURE;
				PSL_UNLOCK();
			}
			else {
				/* remove all pages associated with the  */
				/* segment from the list of free pages   */
				/* when transfer is through, all target  */
				/* segment pages will appear to be free  */
				
				dp_pages_free -=  ps->ps_pgcount;
				interim_pages_removed += ps->ps_pgcount;
				PSL_UNLOCK();
				error = ps_delete(ps);
			}
			if (error != KERN_SUCCESS) {
				/*
				 * We couldn't delete the segment,
				 * probably because there's not enough
				 * virtual memory left.
				 * Re-enable all the segments.
				 */
				PSL_LOCK();
				break;
			}
			goto restart;
		}
	}

	if (error != KERN_SUCCESS) {
		for (i = 0; i <= paging_segment_max; i++) {
			ps = paging_segments[i];
			if (ps != PAGING_SEGMENT_NULL &&
			    ps->ps_bs == bs &&
			    IS_PS_GOING_AWAY(ps)) {
				PS_LOCK(ps);
				
				if( !IS_PS_GOING_AWAY(ps)) {
					PS_UNLOCK(ps);
					continue;
				}
				/* Handle the special clusters that came in while we let go the lock*/	
				if( ps->ps_special_clusters) {
					dp_pages_free += ps->ps_special_clusters << ps->ps_clshift;
					ps->ps_pgcount += ps->ps_special_clusters << ps->ps_clshift;
					ps->ps_clcount += ps->ps_special_clusters;
					if ( ps_select_array[ps->ps_bs->bs_priority] == BS_FULLPRI) {
						ps_select_array[ps->ps_bs->bs_priority] = 0;
					}
					ps->ps_special_clusters = 0;
				}
				/* re-enable access to this segment */
				ps->ps_state &= ~PS_GOING_AWAY;
				ps->ps_state |= PS_CAN_USE;
				PS_UNLOCK(ps);
			}
		}
		dp_pages_free += interim_pages_removed;
		PSL_UNLOCK();
		BS_UNLOCK(bs);
		return error;
	}

	for (i = 0; i <= paging_segment_max; i++) {
		ps = paging_segments[i];
		if (ps != PAGING_SEGMENT_NULL &&
		    ps->ps_bs == bs) { 
			if(IS_PS_GOING_AWAY(ps)) {
				if(IS_PS_EMERGENCY_SEGMENT(ps)) {
					PS_LOCK(ps);
					ps->ps_state &= ~PS_GOING_AWAY;
					ps->ps_special_clusters = 0;
					ps->ps_pgcount = ps->ps_pgnum;
					ps->ps_clcount = ps->ps_ncls = ps->ps_pgcount >> ps->ps_clshift;
					PS_UNLOCK(ps);
					dp_pages_reserve += interim_pages_removed;
				} else {
					paging_segments[i] = PAGING_SEGMENT_NULL;
					paging_segment_count--;
					PS_LOCK(ps);
					kfree(ps->ps_bmap, RMAPSIZE(ps->ps_ncls));
					kfree(ps, sizeof *ps);
				}
			}
		}
	}

	/* Scan the entire ps array separately to make certain we find the */
	/* proper paging_segment_max                                       */
	for (i = 0; i < MAX_NUM_PAGING_SEGMENTS; i++) {
		if(paging_segments[i] != PAGING_SEGMENT_NULL)
		   paging_segment_max = i;
	}

	PSL_UNLOCK();

	if( dealing_with_emergency_segment ) {
		BS_UNLOCK(bs);
		return KERN_SUCCESS;
	}

	/*
	 * All the segments have been deleted.
	 * We can remove the backing store.
	 */

	/*
	 * Disable lookups of this backing store.
	 */
	if((void *)bs->bs_port->alias != NULL)
		kfree((void *) bs->bs_port->alias,
		      sizeof (struct vstruct_alias));
	ipc_port_dealloc_kernel((ipc_port_t) (bs->bs_port));
	bs->bs_port = MACH_PORT_NULL;
	BS_UNLOCK(bs);

	/*
	 * Remove backing store from backing_store list.
	 */
	BSL_LOCK();
	queue_remove(&backing_store_list.bsl_queue, bs, backing_store_t,
		     bs_links);
	BSL_UNLOCK();

	/*
	 * Free the backing store structure.
	 */
	kfree(bs, sizeof *bs);

	return KERN_SUCCESS;
}

kern_return_t
default_pager_backing_store_delete(
	MACH_PORT_FACE backing_store) 
{
	if( backing_store != emergency_segment_backing_store ) {
		default_pager_backing_store_delete_internal(emergency_segment_backing_store);
	}
	return(default_pager_backing_store_delete_internal(backing_store));
}

int	ps_enter(paging_segment_t);	/* forward */

int
ps_enter(
	paging_segment_t ps)
{
	int i;

	PSL_LOCK();

	for (i = 0; i < MAX_NUM_PAGING_SEGMENTS; i++) {
		if (paging_segments[i] == PAGING_SEGMENT_NULL)
			break;
	}

	if (i < MAX_NUM_PAGING_SEGMENTS) {
		paging_segments[i] = ps;
		if (i > paging_segment_max)
			paging_segment_max = i;
		paging_segment_count++;
		if ((ps_select_array[ps->ps_bs->bs_priority] == BS_NOPRI) ||
			(ps_select_array[ps->ps_bs->bs_priority] == BS_FULLPRI))
			ps_select_array[ps->ps_bs->bs_priority] = 0;
		i = 0;
	} else {
		PSL_UNLOCK();
		return KERN_RESOURCE_SHORTAGE;
	}

	PSL_UNLOCK();
	return i;
}

#ifdef DEVICE_PAGING
kern_return_t
default_pager_add_segment(
	MACH_PORT_FACE	backing_store,
	MACH_PORT_FACE	device,
	recnum_t	offset,
	recnum_t	count,
	int		record_size)
{
	backing_store_t		bs;
	paging_segment_t	ps;
	int			i;
	int			error;

	if ((bs = backing_store_lookup(backing_store))
	    == BACKING_STORE_NULL)
		return KERN_INVALID_ARGUMENT;

	PSL_LOCK();
	for (i = 0; i <= paging_segment_max; i++) {
		ps = paging_segments[i];
		if (ps == PAGING_SEGMENT_NULL)
			continue;

		/*
		 * Check for overlap on same device.
		 */
		if (!(ps->ps_device != device
		      || offset >= ps->ps_offset + ps->ps_recnum
		      || offset + count <= ps->ps_offset)) {
			PSL_UNLOCK();
			BS_UNLOCK(bs);
			return KERN_INVALID_ARGUMENT;
		}
	}
	PSL_UNLOCK();

	/*
	 * Set up the paging segment
	 */
	ps = (paging_segment_t) kalloc(sizeof (struct paging_segment));
	if (ps == PAGING_SEGMENT_NULL) {
		BS_UNLOCK(bs);
		return KERN_RESOURCE_SHORTAGE;
	}

	ps->ps_segtype = PS_PARTITION;
	ps->ps_device = device;
	ps->ps_offset = offset;
	ps->ps_record_shift = local_log2(vm_page_size / record_size);
	ps->ps_recnum = count;
	ps->ps_pgnum = count >> ps->ps_record_shift;

	ps->ps_pgcount = ps->ps_pgnum;
	ps->ps_clshift = local_log2(bs->bs_clsize);
	ps->ps_clcount = ps->ps_ncls = ps->ps_pgcount >> ps->ps_clshift;
	ps->ps_hint = 0;

	PS_LOCK_INIT(ps);
	ps->ps_bmap = (unsigned char *) kalloc(RMAPSIZE(ps->ps_ncls));
	if (!ps->ps_bmap) {
		kfree(ps, sizeof *ps);
		BS_UNLOCK(bs);
		return KERN_RESOURCE_SHORTAGE;
	}
	for (i = 0; i < ps->ps_ncls; i++) {
		clrbit(ps->ps_bmap, i);
	}

	if(paging_segment_count == 0) {
		ps->ps_state = PS_EMERGENCY_SEGMENT;
		if(use_emergency_swap_file_first) {
			ps->ps_state |= PS_CAN_USE;
		}
	} else {
		ps->ps_state = PS_CAN_USE;
	}

	ps->ps_bs = bs;

	if ((error = ps_enter(ps)) != 0) {
		kfree(ps->ps_bmap, RMAPSIZE(ps->ps_ncls));
		kfree(ps, sizeof *ps);
		BS_UNLOCK(bs);
		return KERN_RESOURCE_SHORTAGE;
	}

	bs->bs_pages_free += ps->ps_clcount << ps->ps_clshift;
	bs->bs_pages_total += ps->ps_clcount << ps->ps_clshift;
	BS_UNLOCK(bs);

	PSL_LOCK();
	if(IS_PS_OK_TO_USE(ps)) {
		dp_pages_free += ps->ps_pgcount;
	} else {
		dp_pages_reserve += ps->ps_pgcount;
	}
	PSL_UNLOCK();

	bs_more_space(ps->ps_clcount);

	DP_DEBUG(DEBUG_BS_INTERNAL,
		 ("device=0x%x,offset=0x%x,count=0x%x,record_size=0x%x,shift=%d,total_size=0x%x\n",
		  device, offset, count, record_size,
		  ps->ps_record_shift, ps->ps_pgnum));

	return KERN_SUCCESS;
}

boolean_t
bs_add_device(
	char		*dev_name,
	MACH_PORT_FACE	master)
{
	security_token_t	null_security_token = {
		{ 0, 0 }
	};
	MACH_PORT_FACE	device;
	int		info[DEV_GET_SIZE_COUNT];
	mach_msg_type_number_t info_count;
	MACH_PORT_FACE	bs = MACH_PORT_NULL;
	unsigned int	rec_size;
	recnum_t	count;
	int		clsize;
	MACH_PORT_FACE  reply_port;

	if (ds_device_open_sync(master, MACH_PORT_NULL, D_READ | D_WRITE,
			null_security_token, dev_name, &device))
		return FALSE;

	info_count = DEV_GET_SIZE_COUNT;
	if (!ds_device_get_status(device, DEV_GET_SIZE, info, &info_count)) {
		rec_size = info[DEV_GET_SIZE_RECORD_SIZE];
		count = info[DEV_GET_SIZE_DEVICE_SIZE] /  rec_size;
		clsize = bs_get_global_clsize(0);
		if (!default_pager_backing_store_create(
					default_pager_object,
					DEFAULT_PAGER_BACKING_STORE_MAXPRI,
					(clsize * vm_page_size),
					&bs)) {
			if (!default_pager_add_segment(bs, device,
						       0, count, rec_size)) {
				return TRUE;
			}
			ipc_port_release_receive(bs);
		}
	}

	ipc_port_release_send(device);
	return FALSE;
}
#endif /* DEVICE_PAGING */

#if	VS_ASYNC_REUSE

struct vs_async *
vs_alloc_async(void)
{
	struct vs_async	*vsa;
	MACH_PORT_FACE	reply_port;
//	kern_return_t	kr;

	VS_ASYNC_LOCK();
	if (vs_async_free_list == NULL) {
		VS_ASYNC_UNLOCK();
		vsa = (struct vs_async *) kalloc(sizeof (struct vs_async));
		if (vsa != NULL) {
			/*
			 * Try allocating a reply port named after the
			 * address of the vs_async structure.
			 */
			struct vstruct_alias 	*alias_struct;

			reply_port = ipc_port_alloc_kernel();
			alias_struct = (struct vstruct_alias *) 
				kalloc(sizeof (struct vstruct_alias));
			if(alias_struct != NULL) {
				alias_struct->vs = (struct vstruct *)vsa;
				alias_struct->name = &default_pager_ops;
				reply_port->alias = (uintptr_t) alias_struct;
				vsa->reply_port = reply_port;
				vs_alloc_async_count++;
			}
			else {
				vs_alloc_async_failed++;
				ipc_port_dealloc_kernel((MACH_PORT_FACE) 
								(reply_port));
				kfree(vsa, sizeof (struct vs_async));
				vsa = NULL;
			}
		}
	} else {
		vsa = vs_async_free_list;
		vs_async_free_list = vs_async_free_list->vsa_next;
		VS_ASYNC_UNLOCK();
	}

	return vsa;
}

void
vs_free_async(
	struct vs_async *vsa)
{
	VS_ASYNC_LOCK();
	vsa->vsa_next = vs_async_free_list;
	vs_async_free_list = vsa;
	VS_ASYNC_UNLOCK();
}

#else	/* VS_ASYNC_REUSE */

struct vs_async *
vs_alloc_async(void)
{
	struct vs_async	*vsa;
	MACH_PORT_FACE	reply_port;
	kern_return_t	kr;

	vsa = (struct vs_async *) kalloc(sizeof (struct vs_async));
	if (vsa != NULL) {
		/*
		 * Try allocating a reply port named after the
		 * address of the vs_async structure.
		 */
			reply_port = ipc_port_alloc_kernel();
			alias_struct = (vstruct_alias *) 
				kalloc(sizeof (struct vstruct_alias));
			if(alias_struct != NULL) {
				alias_struct->vs = reply_port;
				alias_struct->name = &default_pager_ops;
				reply_port->alias = (int) vsa;
				vsa->reply_port = reply_port;
				vs_alloc_async_count++;
			}
			else {
				vs_alloc_async_failed++;
				ipc_port_dealloc_kernel((MACH_PORT_FACE) 
								(reply_port));
				kfree(vsa, sizeof (struct vs_async));
				vsa = NULL;
			}
	}

	return vsa;
}

void
vs_free_async(
	struct vs_async *vsa)
{
	MACH_PORT_FACE	reply_port;
	kern_return_t	kr;

	reply_port = vsa->reply_port;
	kfree(reply_port->alias, sizeof (struct vstuct_alias));
	kfree(vsa, sizeof (struct vs_async));
	ipc_port_dealloc_kernel((MACH_PORT_FACE) (reply_port));
#if 0
	VS_ASYNC_LOCK();
	vs_alloc_async_count--;
	VS_ASYNC_UNLOCK();
#endif
}

#endif	/* VS_ASYNC_REUSE */

zone_t	vstruct_zone;

vstruct_t
ps_vstruct_create(
	dp_size_t size)
{
	vstruct_t	vs;
	unsigned int	i;

	vs = (vstruct_t) zalloc(vstruct_zone);
	if (vs == VSTRUCT_NULL) {
		return VSTRUCT_NULL;
	}

	VS_LOCK_INIT(vs);

	/*
	 * The following fields will be provided later.
	 */
	vs->vs_pager_ops = NULL;
	vs->vs_control = MEMORY_OBJECT_CONTROL_NULL;
	vs->vs_references = 1;
	vs->vs_seqno = 0;

	vs->vs_waiting_seqno = FALSE;
	vs->vs_waiting_read = FALSE;
	vs->vs_waiting_write = FALSE;
	vs->vs_waiting_async = FALSE;

	vs->vs_readers = 0;
	vs->vs_writers = 0;

	vs->vs_errors = 0;

	vs->vs_clshift = local_log2(bs_get_global_clsize(0));
	vs->vs_size = ((atop_32(round_page_32(size)) - 1) >> vs->vs_clshift) + 1;
	vs->vs_async_pending = 0;

	/*
	 * Allocate the pmap, either CLMAP_SIZE or INDIRECT_CLMAP_SIZE
	 * depending on the size of the memory object.
	 */
	if (INDIRECT_CLMAP(vs->vs_size)) {
		vs->vs_imap = (struct vs_map **)
			kalloc(INDIRECT_CLMAP_SIZE(vs->vs_size));
		vs->vs_indirect = TRUE;
	} else {
		vs->vs_dmap = (struct vs_map *)
			kalloc(CLMAP_SIZE(vs->vs_size));
		vs->vs_indirect = FALSE;
	}
	vs->vs_xfer_pending = FALSE;
	DP_DEBUG(DEBUG_VS_INTERNAL,
		 ("map=0x%x, indirect=%d\n", (int) vs->vs_dmap, vs->vs_indirect));

	/*
	 * Check to see that we got the space.
	 */
	if (!vs->vs_dmap) {
		kfree(vs, sizeof *vs);
		return VSTRUCT_NULL;
	}

	/*
	 * Zero the indirect pointers, or clear the direct pointers.
	 */
	if (vs->vs_indirect)
		memset(vs->vs_imap, 0,
		       INDIRECT_CLMAP_SIZE(vs->vs_size));
	else
		for (i = 0; i < vs->vs_size; i++) 
			VSM_CLR(vs->vs_dmap[i]);

	VS_MAP_LOCK_INIT(vs);

	bs_commit(vs->vs_size);

	return vs;
}

paging_segment_t ps_select_segment(unsigned int, int *);	/* forward */

paging_segment_t
ps_select_segment(
	unsigned int	shift,
	int		*psindex)
{
	paging_segment_t	ps;
	int			i;
	int			j;

	/*
	 * Optimize case where there's only one segment.
	 * paging_segment_max will index the one and only segment.
	 */

	PSL_LOCK();
	if (paging_segment_count == 1) {
		paging_segment_t lps = PAGING_SEGMENT_NULL;	/* used to avoid extra PS_UNLOCK */
		ipc_port_t trigger = IP_NULL;

		ps = paging_segments[paging_segment_max];
		*psindex = paging_segment_max;
		PS_LOCK(ps);
		if( !IS_PS_EMERGENCY_SEGMENT(ps) ) {
			panic("Emergency paging segment missing\n");
		}
		ASSERT(ps->ps_clshift >= shift);
		if(IS_PS_OK_TO_USE(ps)) {
			if (ps->ps_clcount) {
				ps->ps_clcount--;
				dp_pages_free -=  1 << ps->ps_clshift;
				ps->ps_pgcount -=  1 << ps->ps_clshift;
				if(min_pages_trigger_port && 
				  (dp_pages_free < minimum_pages_remaining)) {
					trigger = min_pages_trigger_port;
					min_pages_trigger_port = NULL;
					bs_low = TRUE;
				}
				lps = ps;
			} 
		} 
		PS_UNLOCK(ps);
		
		if( lps == PAGING_SEGMENT_NULL ) {
			if(dp_pages_free) {
				dp_pages_free_drift_count++;
				if(dp_pages_free > dp_pages_free_drifted_max) {
					dp_pages_free_drifted_max = dp_pages_free;
				}
				dprintf(("Emergency swap segment:dp_pages_free before zeroing out: %d\n",dp_pages_free));
			}
	        	dp_pages_free = 0;
		}

		PSL_UNLOCK();

		if (trigger != IP_NULL) {
			default_pager_space_alert(trigger, HI_WAT_ALERT);
			ipc_port_release_send(trigger);
		}
		return lps;
	}

	if (paging_segment_count == 0) {
		if(dp_pages_free) {
			dp_pages_free_drift_count++;
			if(dp_pages_free > dp_pages_free_drifted_max) {
				dp_pages_free_drifted_max = dp_pages_free;
			}
			dprintf(("No paging segments:dp_pages_free before zeroing out: %d\n",dp_pages_free));
		}
	        dp_pages_free = 0;
		PSL_UNLOCK();
		return PAGING_SEGMENT_NULL;
	}

	for (i = BS_MAXPRI;
	     i >= BS_MINPRI; i--) {
		int start_index;

		if ((ps_select_array[i] == BS_NOPRI) ||
				(ps_select_array[i] == BS_FULLPRI))
			continue;
		start_index = ps_select_array[i];

		if(!(paging_segments[start_index])) {
			j = start_index+1;
			physical_transfer_cluster_count = 0;
		}
		else if ((physical_transfer_cluster_count+1) == (ALLOC_STRIDE >> 
				(((paging_segments[start_index])->ps_clshift)
				+ vm_page_shift))) {
			physical_transfer_cluster_count = 0;
			j = start_index + 1;
		} else {
			physical_transfer_cluster_count+=1;
			j = start_index;
			if(start_index == 0)
				start_index = paging_segment_max; 
			else
				start_index = start_index - 1;
		}

		while (1) {
			if (j > paging_segment_max)
				j = 0;
			if ((ps = paging_segments[j]) &&
			    (ps->ps_bs->bs_priority == i)) {
				/*
				 * Force the ps cluster size to be
				 * >= that of the vstruct.
				 */
				PS_LOCK(ps);
				if (IS_PS_OK_TO_USE(ps)) {
					if ((ps->ps_clcount) &&
						   (ps->ps_clshift >= shift)) {
						ipc_port_t trigger = IP_NULL;

						ps->ps_clcount--;
						dp_pages_free -=  1 << ps->ps_clshift;
						ps->ps_pgcount -=  1 << ps->ps_clshift;
						if(min_pages_trigger_port && 
							(dp_pages_free < 
							minimum_pages_remaining)) {
							trigger = min_pages_trigger_port;
							min_pages_trigger_port = NULL;
						}
						PS_UNLOCK(ps);
						/*
						 * found one, quit looking.
						 */
						ps_select_array[i] = j;
						PSL_UNLOCK();
						
						if (trigger != IP_NULL) {
							default_pager_space_alert(
								trigger,
								HI_WAT_ALERT);
							ipc_port_release_send(trigger);
						}
						*psindex = j;
						return ps;
					}
				}
				PS_UNLOCK(ps);
			}
			if (j == start_index) {
				/*
				 * none at this priority -- mark it full
				 */
				ps_select_array[i] = BS_FULLPRI;
				break;
			}
			j++;
		}
	}
	
	if(dp_pages_free) {
		dp_pages_free_drift_count++;
		if(dp_pages_free > dp_pages_free_drifted_max) {
			dp_pages_free_drifted_max = dp_pages_free;
		}
		dprintf(("%d Paging Segments: dp_pages_free before zeroing out: %d\n",paging_segment_count,dp_pages_free));
	}
	dp_pages_free = 0;
	PSL_UNLOCK();
	return PAGING_SEGMENT_NULL;
}

dp_offset_t ps_allocate_cluster(vstruct_t, int *, paging_segment_t); /*forward*/

dp_offset_t
ps_allocate_cluster(
	vstruct_t		vs,
	int			*psindex,
	paging_segment_t	use_ps)
{
	unsigned int		byte_num;
	int			bit_num = 0;
	paging_segment_t	ps;
	dp_offset_t		cluster;
	ipc_port_t		trigger = IP_NULL;

	/*
	 * Find best paging segment.
	 * ps_select_segment will decrement cluster count on ps.
	 * Must pass cluster shift to find the most appropriate segment.
	 */
	/* NOTE:  The addition of paging segment delete capability threatened
	 * to seriously complicate the treatment of paging segments in this
	 * module and the ones that call it (notably ps_clmap), because of the
	 * difficulty in assuring that the paging segment would continue to
	 * exist between being unlocked and locked.   This was
	 * avoided because all calls to this module are based in either
	 * dp_memory_object calls which rely on the vs lock, or by
	 * the transfer function which is part of the segment delete path.
	 * The transfer function which is part of paging segment delete is 
	 * protected from multiple callers by the backing store lock.  
	 * The paging segment delete function treats mappings to a paging 
	 * segment on a vstruct by vstruct basis, locking the vstruct targeted 
	 * while data is transferred to the remaining segments.  This is in
	 * line with the view that incomplete or in-transition mappings between
	 * data, a vstruct, and backing store are protected by the vs lock. 
	 * This and the ordering of the paging segment "going_away" bit setting
	 * protects us.
	 */
retry:
	if (use_ps != PAGING_SEGMENT_NULL) {
		ps = use_ps;
		PSL_LOCK();
		PS_LOCK(ps);

		ASSERT(ps->ps_clcount != 0);

		ps->ps_clcount--;
		dp_pages_free -=  1 << ps->ps_clshift;
		ps->ps_pgcount -=  1 << ps->ps_clshift;
		if(min_pages_trigger_port && 
				(dp_pages_free < minimum_pages_remaining)) {
			trigger = min_pages_trigger_port;
			min_pages_trigger_port = NULL;
		}
		PSL_UNLOCK();
		PS_UNLOCK(ps);
		if (trigger != IP_NULL) {
			default_pager_space_alert(trigger, HI_WAT_ALERT);
			ipc_port_release_send(trigger);
		}

	} else if ((ps = ps_select_segment(vs->vs_clshift, psindex)) ==
		   PAGING_SEGMENT_NULL) {
		static clock_sec_t lastnotify = 0;
		clock_sec_t now;
		clock_nsec_t nanoseconds_dummy;
		
		/* 
		 * Don't immediately jump to the emergency segment. Give the
		 * dynamic pager a chance to create it's first normal swap file.
		 * Unless, of course the very first normal swap file can't be 
		 * created due to some problem and we didn't expect that problem
		 * i.e. use_emergency_swap_file_first was never set to true initially.
		 * It then gets set in the swap file creation error handling.
		 */
		if(paging_segment_count > 1 || use_emergency_swap_file_first == TRUE) {
			
			ps = paging_segments[EMERGENCY_PSEG_INDEX];
			if(IS_PS_EMERGENCY_SEGMENT(ps) && !IS_PS_GOING_AWAY(ps)) {
				PSL_LOCK();
				PS_LOCK(ps);
				
				if(IS_PS_GOING_AWAY(ps)) {
					/* Someone de-activated the emergency paging segment*/
					PS_UNLOCK(ps);
					PSL_UNLOCK();

				} else if(dp_pages_free) {
					/* 
					 * Someone has already activated the emergency paging segment 
					 * OR
					 * Between us having rec'd a NULL segment from ps_select_segment
					 * and reaching here a new normal segment could have been added.
					 * E.g. we get NULL segment and another thread just added the
					 * new swap file. Hence check to see if we have more dp_pages_free
					 * before activating the emergency segment.
					 */
					PS_UNLOCK(ps);
					PSL_UNLOCK();
					goto retry;
				
				} else if(!IS_PS_OK_TO_USE(ps) && ps->ps_clcount) {
					/*
					 * PS_CAN_USE is only reset from the emergency segment when it's
					 * been successfully recovered. So it's legal to have an emergency
					 * segment that has PS_CAN_USE but no clusters because it's recovery
					 * failed.
					 */
					backing_store_t bs = ps->ps_bs;
					ps->ps_state |= PS_CAN_USE;
					if(ps_select_array[bs->bs_priority] == BS_FULLPRI ||
						ps_select_array[bs->bs_priority] == BS_NOPRI) {
						ps_select_array[bs->bs_priority] = 0;
					}
					dp_pages_free += ps->ps_pgcount;
					dp_pages_reserve -= ps->ps_pgcount;
					PS_UNLOCK(ps);
					PSL_UNLOCK();
					dprintf(("Switching ON Emergency paging segment\n"));
					goto retry;
				}

				PS_UNLOCK(ps);
				PSL_UNLOCK();
			}
		}
		
		/*
		 * Emit a notification of the low-paging resource condition
		 * but don't issue it more than once every five seconds.  This
		 * prevents us from overflowing logs with thousands of
		 * repetitions of the message.
		 */
		clock_get_system_nanotime(&now, &nanoseconds_dummy);
		if (paging_segment_count > 1 && (now > lastnotify + 5)) {
			/* With an activated emergency paging segment we still
			 * didn't get any clusters. This could mean that the 
			 * emergency paging segment is exhausted.
 			 */
			dprintf(("System is out of paging space.\n"));
			lastnotify = now;
		}

		PSL_LOCK();
		
		if(min_pages_trigger_port) {
			trigger = min_pages_trigger_port;
			min_pages_trigger_port = NULL;
			bs_low = TRUE;
		}
		PSL_UNLOCK();
		if (trigger != IP_NULL) {
			default_pager_space_alert(trigger, HI_WAT_ALERT);
			ipc_port_release_send(trigger);
		}
		return (dp_offset_t) -1;
	}

	/*
	 * Look for an available cluster.  At the end of the loop,
	 * byte_num is the byte offset and bit_num is the bit offset of the
	 * first zero bit in the paging segment bitmap.
	 */
	PS_LOCK(ps);
	byte_num = ps->ps_hint;
	for (; byte_num < howmany(ps->ps_ncls, NBBY); byte_num++) {
		if (*(ps->ps_bmap + byte_num) != BYTEMASK) {
			for (bit_num = 0; bit_num < NBBY; bit_num++) {
				if (isclr((ps->ps_bmap + byte_num), bit_num))
					break;
			}
			ASSERT(bit_num != NBBY);
			break;
		}
	}
	ps->ps_hint = byte_num;
	cluster = (byte_num*NBBY) + bit_num;

	/* Space was reserved, so this must be true */
	ASSERT(cluster < ps->ps_ncls);

	setbit(ps->ps_bmap, cluster);
	PS_UNLOCK(ps);

	return cluster;
}

void ps_deallocate_cluster(paging_segment_t, dp_offset_t);	/* forward */

void
ps_deallocate_cluster(
	paging_segment_t	ps,
	dp_offset_t		cluster)
{

	if (cluster >= ps->ps_ncls)
		panic("ps_deallocate_cluster: Invalid cluster number");

	/*
	 * Lock the paging segment, clear the cluster's bitmap and increment the
	 * number of free cluster.
	 */
	PSL_LOCK();
	PS_LOCK(ps);
	clrbit(ps->ps_bmap, cluster);
	if( IS_PS_OK_TO_USE(ps)) {
		++ps->ps_clcount;
		ps->ps_pgcount +=  1 << ps->ps_clshift;
		dp_pages_free +=  1 << ps->ps_clshift;
	} else {
		ps->ps_special_clusters += 1;
	}

	/*
	 * Move the hint down to the freed cluster if it is
	 * less than the current hint.
	 */
	if ((cluster/NBBY) < ps->ps_hint) {
		ps->ps_hint = (cluster/NBBY);
	}


	/*
	 * If we're freeing space on a full priority, reset the array.
	 */
	if ( IS_PS_OK_TO_USE(ps) && ps_select_array[ps->ps_bs->bs_priority] == BS_FULLPRI)
		ps_select_array[ps->ps_bs->bs_priority] = 0;
	PS_UNLOCK(ps);
	PSL_UNLOCK();

	return;
}

void ps_dealloc_vsmap(struct vs_map *, dp_size_t);	/* forward */

void
ps_dealloc_vsmap(
	struct vs_map	*vsmap,
	dp_size_t	size)
{
	unsigned int i;
	for (i = 0; i < size; i++)
		if (!VSM_ISCLR(vsmap[i]) && !VSM_ISERR(vsmap[i]))
			ps_deallocate_cluster(VSM_PS(vsmap[i]),
					      VSM_CLOFF(vsmap[i]));
}

void
ps_vstruct_dealloc(
	vstruct_t vs)
{
	unsigned int	i;
//	spl_t	s;

	VS_MAP_LOCK(vs);

	/*
	 * If this is an indirect structure, then we walk through the valid
	 * (non-zero) indirect pointers and deallocate the clusters
	 * associated with each used map entry (via ps_dealloc_vsmap).
	 * When all of the clusters in an indirect block have been
	 * freed, we deallocate the block.  When all of the indirect
	 * blocks have been deallocated we deallocate the memory
	 * holding the indirect pointers.
	 */
	if (vs->vs_indirect) {
		for (i = 0; i < INDIRECT_CLMAP_ENTRIES(vs->vs_size); i++) {
			if (vs->vs_imap[i] != NULL) {
				ps_dealloc_vsmap(vs->vs_imap[i], CLMAP_ENTRIES);
				kfree(vs->vs_imap[i], CLMAP_THRESHOLD);
			}
		}
		kfree(vs->vs_imap, INDIRECT_CLMAP_SIZE(vs->vs_size));
	} else {
		/*
		 * Direct map.  Free used clusters, then memory.
		 */
		ps_dealloc_vsmap(vs->vs_dmap, vs->vs_size);
		kfree(vs->vs_dmap, CLMAP_SIZE(vs->vs_size));
	}
	VS_MAP_UNLOCK(vs);

	bs_commit(- vs->vs_size);

	zfree(vstruct_zone, vs);
}

int ps_map_extend(vstruct_t, unsigned int);	/* forward */

int ps_map_extend(
	vstruct_t	vs,
	unsigned int	new_size)
{
	struct vs_map	**new_imap;
	struct vs_map	*new_dmap = NULL;
	int		newdsize;
	int		i;
	void		*old_map = NULL;
	int		old_map_size = 0;

	if (vs->vs_size >= new_size) {
		/*
		 * Someone has already done the work.
		 */
		return 0;
	}

	/*
	 * If the new size extends into the indirect range, then we have one
	 * of two cases: we are going from indirect to indirect, or we are
	 * going from direct to indirect.  If we are going from indirect to
	 * indirect, then it is possible that the new size will fit in the old
	 * indirect map.  If this is the case, then just reset the size of the
	 * vstruct map and we are done.  If the new size will not
	 * fit into the old indirect map, then we have to allocate a new
	 * indirect map and copy the old map pointers into this new map.
	 *
	 * If we are going from direct to indirect, then we have to allocate a
	 * new indirect map and copy the old direct pages into the first
	 * indirect page of the new map.
	 * NOTE: allocating memory here is dangerous, as we're in the
	 * pageout path.
	 */
	if (INDIRECT_CLMAP(new_size)) {
		int new_map_size = INDIRECT_CLMAP_SIZE(new_size);

		/*
		 * Get a new indirect map and zero it.
		 */
		old_map_size = INDIRECT_CLMAP_SIZE(vs->vs_size);
		if (vs->vs_indirect &&
		    (new_map_size == old_map_size)) {
			bs_commit(new_size - vs->vs_size);
			vs->vs_size = new_size;
			return 0;
		}

		new_imap = (struct vs_map **)kalloc(new_map_size);
		if (new_imap == NULL) {
			return -1;
		}
		memset(new_imap, 0, new_map_size);

		if (vs->vs_indirect) {
			/* Copy old entries into new map */
			memcpy(new_imap, vs->vs_imap, old_map_size);
			/* Arrange to free the old map */
			old_map = (void *) vs->vs_imap;
			newdsize = 0;
		} else {	/* Old map was a direct map */
			/* Allocate an indirect page */
			if ((new_imap[0] = (struct vs_map *)
			     kalloc(CLMAP_THRESHOLD)) == NULL) {
				kfree(new_imap, new_map_size);
				return -1;
			}
			new_dmap = new_imap[0];
			newdsize = CLMAP_ENTRIES;
		}
	} else {
		new_imap = NULL;
		newdsize = new_size;
		/*
		 * If the new map is a direct map, then the old map must
		 * also have been a direct map.  All we have to do is
		 * to allocate a new direct map, copy the old entries
		 * into it and free the old map.
		 */
		if ((new_dmap = (struct vs_map *)
		     kalloc(CLMAP_SIZE(new_size))) == NULL) {
			return -1;
		}
	}
	if (newdsize) {

		/* Free the old map */
		old_map = (void *) vs->vs_dmap;
		old_map_size = CLMAP_SIZE(vs->vs_size);

		/* Copy info from the old map into the new map */
		memcpy(new_dmap, vs->vs_dmap, old_map_size);

		/* Initialize the rest of the new map */
		for (i = vs->vs_size; i < newdsize; i++)
			VSM_CLR(new_dmap[i]);
	}
	if (new_imap) {
		vs->vs_imap = new_imap;
		vs->vs_indirect = TRUE;
	} else
		vs->vs_dmap = new_dmap;
	bs_commit(new_size - vs->vs_size);
	vs->vs_size = new_size;
	if (old_map)
		kfree(old_map, old_map_size);
	return 0;
}

dp_offset_t
ps_clmap(
	vstruct_t	vs,
	dp_offset_t	offset,
	struct clmap	*clmap,
	int		flag,
	dp_size_t	size,
	int		error)
{
	dp_offset_t	cluster;	/* The cluster of offset.	*/
	dp_offset_t	newcl;		/* The new cluster allocated.	*/
	dp_offset_t	newoff;
	unsigned int	i;
	struct vs_map	*vsmap;

	VS_MAP_LOCK(vs);

	ASSERT(vs->vs_dmap);
	cluster = atop_32(offset) >> vs->vs_clshift;

	/*
	 * Initialize cluster error value
	 */
	clmap->cl_error = 0;

	/*
	 * If the object has grown, extend the page map.
	 */
	if (cluster >= vs->vs_size) {
		if (flag == CL_FIND) {
			/* Do not allocate if just doing a lookup */
			VS_MAP_UNLOCK(vs);
			return (dp_offset_t) -1;
		}
		if (ps_map_extend(vs, cluster + 1)) {
			VS_MAP_UNLOCK(vs);
			return (dp_offset_t) -1;
		}
	}

	/*
	 * Look for the desired cluster.  If the map is indirect, then we
	 * have a two level lookup.  First find the indirect block, then
	 * find the actual cluster.  If the indirect block has not yet
	 * been allocated, then do so.  If the cluster has not yet been
	 * allocated, then do so.
	 *
	 * If any of the allocations fail, then return an error.
	 * Don't allocate if just doing a lookup.
	 */
	if (vs->vs_indirect) {
		long	ind_block = cluster/CLMAP_ENTRIES;

		/* Is the indirect block allocated? */
		vsmap = vs->vs_imap[ind_block];
		if (vsmap == NULL) {
			if (flag == CL_FIND) {
				VS_MAP_UNLOCK(vs);
				return (dp_offset_t) -1;
			}

			/* Allocate the indirect block */
			vsmap = (struct vs_map *) kalloc(CLMAP_THRESHOLD);
			if (vsmap == NULL) {
				VS_MAP_UNLOCK(vs);
				return (dp_offset_t) -1;
			}
			/* Initialize the cluster offsets */
			for (i = 0; i < CLMAP_ENTRIES; i++)
				VSM_CLR(vsmap[i]);
			vs->vs_imap[ind_block] = vsmap;
		}
	} else
		vsmap = vs->vs_dmap;

	ASSERT(vsmap);
	vsmap += cluster%CLMAP_ENTRIES;

	/*
	 * At this point, vsmap points to the struct vs_map desired.
	 *
	 * Look in the map for the cluster, if there was an error on a
	 * previous write, flag it and return.  If it is not yet
	 * allocated, then allocate it, if we're writing; if we're
	 * doing a lookup and the cluster's not allocated, return error.
	 */
	if (VSM_ISERR(*vsmap)) {
		clmap->cl_error = VSM_GETERR(*vsmap);
		VS_MAP_UNLOCK(vs);
		return (dp_offset_t) -1;
	} else if (VSM_ISCLR(*vsmap)) {
		int psindex;

		if (flag == CL_FIND) {
			/*
			 * If there's an error and the entry is clear, then
			 * we've run out of swap space.  Record the error
			 * here and return.
			 */
			if (error) {
				VSM_SETERR(*vsmap, error);
			}
			VS_MAP_UNLOCK(vs);
			return (dp_offset_t) -1;
		} else {
			/*
			 * Attempt to allocate a cluster from the paging segment
			 */
			newcl = ps_allocate_cluster(vs, &psindex,
						    PAGING_SEGMENT_NULL);
			if (newcl == (dp_offset_t) -1) {
				VS_MAP_UNLOCK(vs);
				return (dp_offset_t) -1;
			}
			VSM_CLR(*vsmap);
			VSM_SETCLOFF(*vsmap, newcl);
			VSM_SETPS(*vsmap, psindex);
		}
	} else
		newcl = VSM_CLOFF(*vsmap);

	/*
	 * Fill in pertinent fields of the clmap
	 */
	clmap->cl_ps = VSM_PS(*vsmap);
	clmap->cl_numpages = VSCLSIZE(vs);
	clmap->cl_bmap.clb_map = (unsigned int) VSM_BMAP(*vsmap);

	/*
	 * Byte offset in paging segment is byte offset to cluster plus
	 * byte offset within cluster.  It looks ugly, but should be
	 * relatively quick.
	 */
	ASSERT(trunc_page(offset) == offset);
	newcl = ptoa_32(newcl) << vs->vs_clshift;
	newoff = offset & ((1<<(vm_page_shift + vs->vs_clshift)) - 1);
	if (flag == CL_ALLOC) {
		/*
		 * set bits in the allocation bitmap according to which
		 * pages were requested.  size is in bytes.
		 */
		i = atop_32(newoff);
		while ((size > 0) && (i < VSCLSIZE(vs))) {
			VSM_SETALLOC(*vsmap, i);
			i++;
			size -= vm_page_size;
		}
	}
	clmap->cl_alloc.clb_map = (unsigned int) VSM_ALLOC(*vsmap);
	if (newoff) {
		/*
		 * Offset is not cluster aligned, so number of pages
		 * and bitmaps must be adjusted
		 */
		clmap->cl_numpages -= atop_32(newoff);
		CLMAP_SHIFT(clmap, vs);
		CLMAP_SHIFTALLOC(clmap, vs);
	}

	/*
	 *
	 * The setting of valid bits and handling of write errors
	 * must be done here, while we hold the lock on the map.
	 * It logically should be done in ps_vs_write_complete().
	 * The size and error information has been passed from
	 * ps_vs_write_complete().  If the size parameter is non-zero,
	 * then there is work to be done.  If error is also non-zero,
	 * then the error number is recorded in the cluster and the
	 * entire cluster is in error.
	 */
	if (size && flag == CL_FIND) {
		dp_offset_t off = (dp_offset_t) 0;

		if (!error) {
			for (i = VSCLSIZE(vs) - clmap->cl_numpages; size > 0;
			     i++) {
				VSM_SETPG(*vsmap, i);
				size -= vm_page_size;
			}
			ASSERT(i <= VSCLSIZE(vs));
		} else {
			BS_STAT(clmap->cl_ps->ps_bs,
				clmap->cl_ps->ps_bs->bs_pages_out_fail +=
					atop_32(size));
			off = VSM_CLOFF(*vsmap);
			VSM_SETERR(*vsmap, error);
		}
		/*
		 * Deallocate cluster if error, and no valid pages
		 * already present.
		 */
		if (off != (dp_offset_t) 0)
			ps_deallocate_cluster(clmap->cl_ps, off);
		VS_MAP_UNLOCK(vs);
		return (dp_offset_t) 0;
	} else
		VS_MAP_UNLOCK(vs);

	DP_DEBUG(DEBUG_VS_INTERNAL,
		 ("returning 0x%X,vs=0x%X,vsmap=0x%X,flag=%d\n",
		  newcl+newoff, (int) vs, (int) vsmap, flag));
	DP_DEBUG(DEBUG_VS_INTERNAL,
		 ("	clmap->cl_ps=0x%X,cl_numpages=%d,clbmap=0x%x,cl_alloc=%x\n",
		  (int) clmap->cl_ps, clmap->cl_numpages,
		  (int) clmap->cl_bmap.clb_map, (int) clmap->cl_alloc.clb_map));

	return (newcl + newoff);
}

void ps_clunmap(vstruct_t, dp_offset_t, dp_size_t);	/* forward */

void
ps_clunmap(
	vstruct_t	vs,
	dp_offset_t	offset,
	dp_size_t	length)
{
	dp_offset_t		cluster; /* The cluster number of offset */
	struct vs_map		*vsmap;

	VS_MAP_LOCK(vs);

	/*
	 * Loop through all clusters in this range, freeing paging segment
	 * clusters and map entries as encountered.
	 */
	while (length > 0) {
		dp_offset_t 	newoff;
		unsigned int	i;

		cluster = atop_32(offset) >> vs->vs_clshift;
		if (vs->vs_indirect)	/* indirect map */
			vsmap = vs->vs_imap[cluster/CLMAP_ENTRIES];
		else
			vsmap = vs->vs_dmap;
		if (vsmap == NULL) {
			VS_MAP_UNLOCK(vs);
			return;
		}
		vsmap += cluster%CLMAP_ENTRIES;
		if (VSM_ISCLR(*vsmap)) {
			length -= vm_page_size;
			offset += vm_page_size;
			continue;
		}
		/*
		 * We've got a valid mapping.  Clear it and deallocate
		 * paging segment cluster pages.
		 * Optimize for entire cluster cleraing.
		 */
		if ( (newoff = (offset&((1<<(vm_page_shift+vs->vs_clshift))-1))) ) {
			/*
			 * Not cluster aligned.
			 */
			ASSERT(trunc_page(newoff) == newoff);
			i = atop_32(newoff);
		} else
			i = 0;
		while ((i < VSCLSIZE(vs)) && (length > 0)) {
			VSM_CLRPG(*vsmap, i);
			VSM_CLRALLOC(*vsmap, i);
			length -= vm_page_size;
			offset += vm_page_size;
			i++;
		}

		/*
		 * If map entry is empty, clear and deallocate cluster.
		 */
		if (!VSM_ALLOC(*vsmap)) {
			ps_deallocate_cluster(VSM_PS(*vsmap),
					      VSM_CLOFF(*vsmap));
			VSM_CLR(*vsmap);
		}
	}

	VS_MAP_UNLOCK(vs);
}

void ps_vs_write_complete(vstruct_t, dp_offset_t, dp_size_t, int); /* forward */

void
ps_vs_write_complete(
	vstruct_t	vs,
	dp_offset_t	offset,
	dp_size_t	size,
	int		error)
{
	struct clmap	clmap;

	/*
	 * Get the struct vsmap for this cluster.
	 * Use READ, even though it was written, because the
	 * cluster MUST be present, unless there was an error
	 * in the original ps_clmap (e.g. no space), in which
	 * case, nothing happens.
	 *
	 * Must pass enough information to ps_clmap to allow it
	 * to set the vs_map structure bitmap under lock.
	 */
	(void) ps_clmap(vs, offset, &clmap, CL_FIND, size, error);
}

void vs_cl_write_complete(vstruct_t, paging_segment_t, dp_offset_t, vm_offset_t, dp_size_t, boolean_t, int);	/* forward */

void
vs_cl_write_complete(
	vstruct_t			vs,
	__unused paging_segment_t	ps,
	dp_offset_t			offset,
	__unused vm_offset_t		addr,
	dp_size_t			size,
	boolean_t			async,
	int				error)
{
//	kern_return_t	kr;

	if (error) {
		/*
		 * For internal objects, the error is recorded on a
		 * per-cluster basis by ps_clmap() which is called
		 * by ps_vs_write_complete() below.
		 */
		dprintf(("write failed error = 0x%x\n", error));
		/* add upl_abort code here */
	} else
		GSTAT(global_stats.gs_pages_out += atop_32(size));
	/*
	 * Notify the vstruct mapping code, so it can do its accounting.
	 */
	ps_vs_write_complete(vs, offset, size, error);

	if (async) {
		VS_LOCK(vs);
		ASSERT(vs->vs_async_pending > 0);
		vs->vs_async_pending -= size;
		if (vs->vs_async_pending == 0 && vs->vs_waiting_async) {
			vs->vs_waiting_async = FALSE;
			VS_UNLOCK(vs);
			thread_wakeup(&vs->vs_async_pending);
		} else {
			VS_UNLOCK(vs);
		}
	}
}

#ifdef DEVICE_PAGING
kern_return_t device_write_reply(MACH_PORT_FACE, kern_return_t, io_buf_len_t);

kern_return_t
device_write_reply(
	MACH_PORT_FACE	reply_port,
	kern_return_t	device_code,
	io_buf_len_t	bytes_written)
{
	struct vs_async	*vsa;

	vsa = (struct vs_async *)
		((struct vstruct_alias *)(reply_port->alias))->vs;

	if (device_code == KERN_SUCCESS && bytes_written != vsa->vsa_size) {
		device_code = KERN_FAILURE;
	}

	vsa->vsa_error = device_code;


	ASSERT(vsa->vsa_vs != VSTRUCT_NULL);
	if(vsa->vsa_flags & VSA_TRANSFER) {
		/* revisit when async disk segments redone */
		if(vsa->vsa_error) {
		   /* need to consider error condition.  re-write data or */
		   /* throw it away here. */
		   vm_map_copy_discard((vm_map_copy_t)vsa->vsa_addr);
		}
		ps_vs_write_complete(vsa->vsa_vs, vsa->vsa_offset, 
						vsa->vsa_size, vsa->vsa_error);
	} else {
		vs_cl_write_complete(vsa->vsa_vs, vsa->vsa_ps, vsa->vsa_offset,
			     vsa->vsa_addr, vsa->vsa_size, TRUE,
			     vsa->vsa_error);
	}
	VS_FREE_ASYNC(vsa);

	return KERN_SUCCESS;
}

kern_return_t device_write_reply_inband(MACH_PORT_FACE, kern_return_t, io_buf_len_t);
kern_return_t
device_write_reply_inband(
	MACH_PORT_FACE		reply_port,
	kern_return_t		return_code,
	io_buf_len_t		bytes_written)
{
	panic("device_write_reply_inband: illegal");
	return KERN_SUCCESS;
}

kern_return_t device_read_reply(MACH_PORT_FACE, kern_return_t, io_buf_ptr_t, mach_msg_type_number_t);
kern_return_t
device_read_reply(
	MACH_PORT_FACE		reply_port,
	kern_return_t		return_code,
	io_buf_ptr_t		data,
	mach_msg_type_number_t	dataCnt)
{
	struct vs_async	*vsa;
	vsa = (struct vs_async *)
		((struct vstruct_alias *)(reply_port->alias))->vs;
	vsa->vsa_addr = (vm_offset_t)data;
	vsa->vsa_size = (vm_size_t)dataCnt;
	vsa->vsa_error = return_code;
	thread_wakeup(&vsa);
	return KERN_SUCCESS;
}

kern_return_t device_read_reply_inband(MACH_PORT_FACE, kern_return_t, io_buf_ptr_inband_t, mach_msg_type_number_t);
kern_return_t
device_read_reply_inband(
	MACH_PORT_FACE		reply_port,
	kern_return_t		return_code,
	io_buf_ptr_inband_t	data,
	mach_msg_type_number_t	dataCnt)
{
	panic("device_read_reply_inband: illegal");
	return KERN_SUCCESS;
}

kern_return_t device_read_reply_overwrite(MACH_PORT_FACE, kern_return_t, io_buf_len_t);
kern_return_t
device_read_reply_overwrite(
	MACH_PORT_FACE		reply_port,
	kern_return_t		return_code,
	io_buf_len_t		bytes_read)
{
	panic("device_read_reply_overwrite: illegal\n");
	return KERN_SUCCESS;
}

kern_return_t device_open_reply(MACH_PORT_FACE, kern_return_t, MACH_PORT_FACE);
kern_return_t
device_open_reply(
	MACH_PORT_FACE		reply_port,
	kern_return_t		return_code,
	MACH_PORT_FACE		device_port)
{
	panic("device_open_reply: illegal\n");
	return KERN_SUCCESS;
}

kern_return_t
ps_read_device(
	paging_segment_t	ps,
	dp_offset_t		offset,
	vm_offset_t		*bufferp,
	unsigned int		size,
	unsigned int		*residualp,
	int 			flags)
{
	kern_return_t	kr;
	recnum_t	dev_offset;
	unsigned int	bytes_wanted;
	unsigned int	bytes_read;
	unsigned int	total_read;
	vm_offset_t	dev_buffer;
	vm_offset_t	buf_ptr;
	unsigned int	records_read;
	struct vs_async *vsa;	

	device_t	device;
	vm_map_copy_t	device_data = NULL;
	default_pager_thread_t *dpt = NULL;

	device = dev_port_lookup(ps->ps_device);
	clustered_reads[atop_32(size)]++;

	dev_offset = (ps->ps_offset +
		      (offset >> (vm_page_shift - ps->ps_record_shift)));
	bytes_wanted = size;
	total_read = 0;
	*bufferp = (vm_offset_t)NULL;
	
	do {
		vsa = VS_ALLOC_ASYNC();
		if (vsa) {
			vsa->vsa_vs = NULL;
			vsa->vsa_addr = 0;
			vsa->vsa_offset = 0;
			vsa->vsa_size = 0;
			vsa->vsa_ps = NULL;
		}
		ip_lock(vsa->reply_port);
		vsa->reply_port->ip_sorights++;
		ip_reference(vsa->reply_port);
		ip_unlock(vsa->reply_port);
		kr = ds_device_read_common(device,
				 vsa->reply_port,
			         (mach_msg_type_name_t) 
					MACH_MSG_TYPE_MOVE_SEND_ONCE,
				 (dev_mode_t) 0,
				 dev_offset,
				 bytes_wanted,
				 (IO_READ | IO_CALL),
				 (io_buf_ptr_t *) &dev_buffer,
				 (mach_msg_type_number_t *) &bytes_read);
		if(kr == MIG_NO_REPLY) { 
			assert_wait(&vsa, THREAD_UNINT);
			thread_block(THREAD_CONTINUE_NULL);

			dev_buffer = vsa->vsa_addr;
			bytes_read = (unsigned int)vsa->vsa_size;
			kr = vsa->vsa_error;
		} 
		VS_FREE_ASYNC(vsa);
		if (kr != KERN_SUCCESS || bytes_read == 0) {
			break;
		}
		total_read += bytes_read;

		/*
		 * If we got the entire range, use the returned dev_buffer.
		 */
		if (bytes_read == size) {
			*bufferp = (vm_offset_t)dev_buffer;
			break;
		}

#if 1
		dprintf(("read only %d bytes out of %d\n",
			 bytes_read, bytes_wanted));
#endif
		if(dpt == NULL) {
			dpt = get_read_buffer();
			buf_ptr = dpt->dpt_buffer;
			*bufferp = (vm_offset_t)buf_ptr;
		}
		/*
		 * Otherwise, copy the data into the provided buffer (*bufferp)
		 * and append the rest of the range as it comes in.
		 */
		memcpy((void *) buf_ptr, (void *) dev_buffer, bytes_read);
		buf_ptr += bytes_read;
		bytes_wanted -= bytes_read;
		records_read = (bytes_read >>
				(vm_page_shift - ps->ps_record_shift));
		dev_offset += records_read;
		DP_DEBUG(DEBUG_VS_INTERNAL,
			 ("calling vm_deallocate(addr=0x%X,size=0x%X)\n",
			  dev_buffer, bytes_read));
		if (vm_deallocate(kernel_map, dev_buffer, bytes_read)
		    != KERN_SUCCESS)
			Panic("dealloc buf");
	} while (bytes_wanted);

	*residualp = size - total_read;
	if((dev_buffer != *bufferp) && (total_read != 0)) {
		vm_offset_t temp_buffer;
		vm_allocate(kernel_map, &temp_buffer, total_read, VM_FLAGS_ANYWHERE);
		memcpy((void *) temp_buffer, (void *) *bufferp, total_read);
		if(vm_map_copyin_page_list(kernel_map, temp_buffer, total_read, 
			VM_MAP_COPYIN_OPT_SRC_DESTROY | 
			VM_MAP_COPYIN_OPT_STEAL_PAGES | 
			VM_MAP_COPYIN_OPT_PMAP_ENTER,
			(vm_map_copy_t *)&device_data, FALSE))
				panic("ps_read_device: cannot copyin locally provided buffer\n");
	}
	else if((kr == KERN_SUCCESS) && (total_read != 0) && (dev_buffer != 0)){
		if(vm_map_copyin_page_list(kernel_map, dev_buffer, bytes_read, 
			VM_MAP_COPYIN_OPT_SRC_DESTROY | 
			VM_MAP_COPYIN_OPT_STEAL_PAGES | 
			VM_MAP_COPYIN_OPT_PMAP_ENTER,
			(vm_map_copy_t *)&device_data, FALSE))
				panic("ps_read_device: cannot copyin backing store provided buffer\n");
	}
	else {
		device_data = NULL;
	}
	*bufferp = (vm_offset_t)device_data;

	if(dpt != NULL) {
		/* Free the receive buffer */
		dpt->checked_out = 0;	
		thread_wakeup(&dpt_array);
	}
	return KERN_SUCCESS;
}

kern_return_t
ps_write_device(
	paging_segment_t	ps,
	dp_offset_t		offset,
	vm_offset_t		addr,
	unsigned int		size,
	struct vs_async		*vsa)
{
	recnum_t	dev_offset;
	io_buf_len_t	bytes_to_write, bytes_written;
	recnum_t	records_written;
	kern_return_t	kr;
	MACH_PORT_FACE	reply_port;



	clustered_writes[atop_32(size)]++;

	dev_offset = (ps->ps_offset +
		      (offset >> (vm_page_shift - ps->ps_record_shift)));
	bytes_to_write = size;

	if (vsa) {
		/*
		 * Asynchronous write.
		 */
		reply_port = vsa->reply_port;
		ip_lock(reply_port);
		reply_port->ip_sorights++;
		ip_reference(reply_port);
		ip_unlock(reply_port);
		{
		device_t	device;
		device = dev_port_lookup(ps->ps_device);

		vsa->vsa_addr = addr;
		kr=ds_device_write_common(device,
			reply_port,
			(mach_msg_type_name_t) MACH_MSG_TYPE_MOVE_SEND_ONCE,
			(dev_mode_t) 0,
			dev_offset,
			(io_buf_ptr_t)	addr,
			size, 
			(IO_WRITE | IO_CALL),
			&bytes_written);
		}
		if ((kr != KERN_SUCCESS) && (kr != MIG_NO_REPLY)) {
			if (verbose) 
				dprintf(("%s0x%x, addr=0x%x,"
					 "size=0x%x,offset=0x%x\n",
					 "device_write_request returned ",
					 kr, addr, size, offset));
			BS_STAT(ps->ps_bs,
				ps->ps_bs->bs_pages_out_fail += atop_32(size));
			/* do the completion notification to free resources */
			device_write_reply(reply_port, kr, 0);
			return PAGER_ERROR;
		}
	} else do {
		/*
		 * Synchronous write.
		 */
		{
		device_t	device;
		device = dev_port_lookup(ps->ps_device);
		kr=ds_device_write_common(device,
			IP_NULL, 0,
			(dev_mode_t) 0,
			dev_offset,
			(io_buf_ptr_t)	addr,
			size, 
			(IO_WRITE | IO_SYNC | IO_KERNEL_BUF),
			&bytes_written);
		}
		if (kr != KERN_SUCCESS) {
			dprintf(("%s0x%x, addr=0x%x,size=0x%x,offset=0x%x\n",
				 "device_write returned ",
				 kr, addr, size, offset));
			BS_STAT(ps->ps_bs,
				ps->ps_bs->bs_pages_out_fail += atop_32(size));
			return PAGER_ERROR;
		}
		if (bytes_written & ((vm_page_size >> ps->ps_record_shift) - 1))
			Panic("fragmented write");
		records_written = (bytes_written >>
				   (vm_page_shift - ps->ps_record_shift));
		dev_offset += records_written;
#if 1
		if (bytes_written != bytes_to_write) {
			dprintf(("wrote only %d bytes out of %d\n",
				 bytes_written, bytes_to_write));
		}
#endif
		bytes_to_write -= bytes_written;
		addr += bytes_written;
	} while (bytes_to_write > 0);

	return PAGER_SUCCESS;
}


#else /* !DEVICE_PAGING */

kern_return_t
ps_read_device(
	__unused paging_segment_t	ps,
	__unused dp_offset_t		offset,
	__unused vm_offset_t		*bufferp,
	__unused unsigned int		size,
	__unused unsigned int		*residualp,
	__unused int 				flags)
{
  panic("ps_read_device not supported");
  return KERN_FAILURE;
}

kern_return_t
ps_write_device(
	__unused paging_segment_t	ps,
	__unused dp_offset_t		offset,
	__unused vm_offset_t		addr,
	__unused unsigned int		size,
	__unused struct vs_async	*vsa)
{
  panic("ps_write_device not supported");
  return KERN_FAILURE;
}

#endif /* DEVICE_PAGING */
void pvs_object_data_provided(vstruct_t, upl_t, upl_offset_t, upl_size_t);	/* forward */

void
pvs_object_data_provided(
	__unused vstruct_t		vs,
	__unused upl_t			upl,
	__unused upl_offset_t	offset,
	upl_size_t				size)
{

	DP_DEBUG(DEBUG_VS_INTERNAL,
		 ("buffer=0x%x,offset=0x%x,size=0x%x\n",
		  upl, offset, size));

	ASSERT(size > 0);
	GSTAT(global_stats.gs_pages_in += atop_32(size));


#if	USE_PRECIOUS
	ps_clunmap(vs, offset, size);
#endif	/* USE_PRECIOUS */

}

static memory_object_offset_t   last_start;
static vm_size_t		last_length;

kern_return_t
pvs_cluster_read(
	vstruct_t	vs,
	dp_offset_t	vs_offset,
	dp_size_t	cnt,
        void		*fault_info)
{
	kern_return_t		error = KERN_SUCCESS;
	unsigned int		size;
	unsigned int		residual;
	unsigned int		request_flags;
	int			io_flags = 0;
	int			seg_index;
	int			pages_in_cl;
	int	                cl_size;
	int	                cl_mask;
	int			cl_index;
	unsigned int		xfer_size;
	dp_offset_t		orig_vs_offset;
	dp_offset_t       ps_offset[(VM_SUPER_CLUSTER / PAGE_SIZE) >> VSTRUCT_DEF_CLSHIFT];
	paging_segment_t        psp[(VM_SUPER_CLUSTER / PAGE_SIZE) >> VSTRUCT_DEF_CLSHIFT];
	struct clmap		clmap;
	upl_t			upl;
	unsigned int		page_list_count;
	memory_object_offset_t	cluster_start;
	vm_size_t		cluster_length;
	uint32_t		io_streaming;

	pages_in_cl = 1 << vs->vs_clshift;
	cl_size = pages_in_cl * vm_page_size;
	cl_mask = cl_size - 1;

#if	USE_PRECIOUS
	request_flags = UPL_NO_SYNC |  UPL_CLEAN_IN_PLACE | UPL_PRECIOUS | UPL_RET_ONLY_ABSENT | UPL_SET_LITE;
#else
	request_flags = UPL_NO_SYNC |  UPL_CLEAN_IN_PLACE | UPL_RET_ONLY_ABSENT | UPL_SET_LITE;
#endif
	cl_index = (vs_offset & cl_mask) / vm_page_size;

        if ((ps_clmap(vs, vs_offset & ~cl_mask, &clmap, CL_FIND, 0, 0) == (dp_offset_t)-1) ||
	    !CLMAP_ISSET(clmap, cl_index)) {
	        /*
		 * the needed page doesn't exist in the backing store...
		 * we don't want to try to do any I/O, just abort the
		 * page and let the fault handler provide a zero-fill
		 */
		if (cnt == 0) {
			/*
			 * The caller was just poking at us to see if
			 * the page has been paged out.  No need to 
			 * mess with the page at all.
			 * Just let the caller know we don't have that page.
			 */
			return KERN_FAILURE;
		}

		page_list_count = 0;

		memory_object_super_upl_request(vs->vs_control,	(memory_object_offset_t)vs_offset,
						PAGE_SIZE, PAGE_SIZE, 
						&upl, NULL, &page_list_count,
						request_flags);

		if (clmap.cl_error)
		        upl_abort(upl, UPL_ABORT_ERROR);
		else
		        upl_abort(upl, UPL_ABORT_UNAVAILABLE);
		upl_deallocate(upl);

		return KERN_SUCCESS;
	}

	if (cnt == 0) {
		/*
		 * The caller was just poking at us to see if
		 * the page has been paged out.  No need to 
		 * mess with the page at all.
		 * Just let the caller know we do have that page.
		 */
		return KERN_SUCCESS;
	}
		
	assert(dp_encryption_inited);
	if (dp_encryption) {
		/*
		 * ENCRYPTED SWAP:
		 * request that the UPL be prepared for
		 * decryption.
		 */
		request_flags |= UPL_ENCRYPT;
	}
	orig_vs_offset = vs_offset;

	assert(cnt != 0);
	cnt = VM_SUPER_CLUSTER;
	cluster_start = (memory_object_offset_t) vs_offset;
	cluster_length = (vm_size_t) cnt;
	io_streaming = 0;

	/*
	 * determine how big a speculative I/O we should try for...
	 */
	if (memory_object_cluster_size(vs->vs_control, &cluster_start, &cluster_length, &io_streaming, (memory_object_fault_info_t)fault_info) == KERN_SUCCESS) {
		assert(vs_offset >= (dp_offset_t) cluster_start &&
		       vs_offset < (dp_offset_t) (cluster_start + cluster_length));
	        vs_offset = (dp_offset_t) cluster_start;
		cnt = (dp_size_t) cluster_length;
	} else {
		cluster_length = PAGE_SIZE;
	        cnt = PAGE_SIZE;
	}

	if (io_streaming)
                io_flags |= UPL_IOSTREAMING;

	last_start = cluster_start;
	last_length = cluster_length;

	/*
	 * This loop will be executed multiple times until the entire
	 * range has been looked at or we issue an I/O... if the request spans cluster
	 * boundaries, the clusters will be checked for logical continunity,
	 * if contiguous the I/O request will span multiple clusters...
	 * at most only 1 I/O will be issued... it will encompass the original offset
	 */
	while (cnt && error == KERN_SUCCESS) {
	        int     ps_info_valid;

		if ((vs_offset & cl_mask) && (cnt > (VM_SUPER_CLUSTER - (vs_offset & cl_mask)))) {
			size = VM_SUPER_CLUSTER;
			size -= vs_offset & cl_mask;
	        } else if (cnt > VM_SUPER_CLUSTER)
		        size = VM_SUPER_CLUSTER;
		else
		        size = cnt;

		cnt -= size;

		ps_info_valid = 0;
		seg_index     = 0;

		while (size > 0 && error == KERN_SUCCESS) {
		        unsigned int  abort_size;
			int           failed_size;
			int           beg_pseg;
			int           beg_indx;
			dp_offset_t   cur_offset;

			if ( !ps_info_valid) {
			        ps_offset[seg_index] = ps_clmap(vs, vs_offset & ~cl_mask, &clmap, CL_FIND, 0, 0);
				psp[seg_index]       = CLMAP_PS(clmap);
				ps_info_valid = 1;
			}
		        /*
			 * skip over unallocated physical segments 
			 */
			if (ps_offset[seg_index] == (dp_offset_t) -1) {
				abort_size = cl_size - (vs_offset & cl_mask);
				abort_size = MIN(abort_size, size);

				size      -= abort_size;
				vs_offset += abort_size;

				seg_index++;
				ps_info_valid = 0;

				continue;
			}
			cl_index = (vs_offset & cl_mask) / vm_page_size;

			for (abort_size = 0; cl_index < pages_in_cl && abort_size < size; cl_index++) {
			        /*
				 * skip over unallocated pages
				 */
			        if (CLMAP_ISSET(clmap, cl_index))
				        break;
				abort_size += vm_page_size;
			}
			if (abort_size) {
				size      -= abort_size;
				vs_offset += abort_size;

				if (cl_index == pages_in_cl) {
				        /*
					 * if we're at the end of this physical cluster
					 * then bump to the next one and continue looking
					 */
				        seg_index++;
					ps_info_valid = 0;

					continue;
				}
				if (size == 0)
				        break;
			}
			/*
			 * remember the starting point of the first allocated page 
			 * for the I/O we're about to issue
			 */
			beg_pseg   = seg_index;
			beg_indx   = cl_index;
			cur_offset = vs_offset;

			/*
			 * calculate the size of the I/O that we can do...
			 * this may span multiple physical segments if
			 * they are contiguous
			 */
			for (xfer_size = 0; xfer_size < size; ) {

			        while (cl_index < pages_in_cl && xfer_size < size) {
				        /*
					 * accumulate allocated pages within 
					 * a physical segment
					 */
				        if (CLMAP_ISSET(clmap, cl_index)) {
					        xfer_size  += vm_page_size;
						cur_offset += vm_page_size;
						cl_index++;

						BS_STAT(psp[seg_index]->ps_bs,
							psp[seg_index]->ps_bs->bs_pages_in++);
					} else
					        break;
				}
				if (cl_index < pages_in_cl || xfer_size >= size) {
				        /*
					 * we've hit an unallocated page or 
					 * the end of this request... see if
					 * it's time to fire the I/O
					 */
				        break;
				}
				/*
				 * we've hit the end of the current physical
				 * segment and there's more to do, so try 
				 * moving to the next one
				 */
				seg_index++;
				  
				ps_offset[seg_index] = ps_clmap(vs, cur_offset & ~cl_mask, &clmap, CL_FIND, 0, 0);
				psp[seg_index] = CLMAP_PS(clmap);
				ps_info_valid = 1;

				if ((ps_offset[seg_index - 1] != (ps_offset[seg_index] - cl_size)) || (psp[seg_index - 1] != psp[seg_index])) {
				        /*
					 * if the physical segment we're about 
					 * to step into is not contiguous to 
					 * the one we're currently in, or it's 
					 * in a different paging file, or
					 * it hasn't been allocated....
					 * we stop this run and go check
					 * to see if it's time to fire the I/O
					 */
				        break;
				}
				/*
				 * start with first page of the next physical
				 * segment
				 */
				cl_index = 0;
			}
			if (xfer_size == 0) {
			        /*
				 * no I/O to generate for this segment
				 */
			        continue;
			}
			if (cur_offset <= orig_vs_offset) {
			        /*
				 * we've hit a hole in our speculative cluster
				 * before the offset that we're really after...
				 * don't issue the I/O since it doesn't encompass
				 * the original offset and we're looking to only
				 * pull in the speculative pages if they can be
				 * made part of a single I/O
				 */
			        size      -= xfer_size;
				vs_offset += xfer_size;

				continue;
			}
			/*
			 * we have a contiguous range of allocated pages
			 * to read from that encompasses the original offset
			 */
			page_list_count = 0;
			memory_object_super_upl_request(vs->vs_control, (memory_object_offset_t)vs_offset,
							xfer_size, xfer_size, 
							&upl, NULL, &page_list_count,
							request_flags | UPL_SET_INTERNAL | UPL_NOBLOCK);

			error = ps_read_file(psp[beg_pseg], 
					     upl, (upl_offset_t) 0, 
					     ps_offset[beg_pseg] + (beg_indx * vm_page_size), 
					     xfer_size, &residual, io_flags);
			
			failed_size = 0;

			/*
			 * Adjust counts and send response to VM.  Optimize 
			 * for the common case, i.e. no error and/or partial
			 * data. If there was an error, then we need to error
			 * the entire range, even if some data was successfully
			 * read. If there was a partial read we may supply some
			 * data and may error some as well.  In all cases the
			 * VM must receive some notification for every page 
			 * in the range.
			 */
			if ((error == KERN_SUCCESS) && (residual == 0)) {
			        /*
				 * Got everything we asked for, supply the data
				 * to the VM.  Note that as a side effect of 
				 * supplying the data, the buffer holding the 
				 * supplied data is deallocated from the pager's
				 *  address space.
				 */
			        pvs_object_data_provided(vs, upl, vs_offset, xfer_size);
			} else {
			        failed_size = xfer_size;

				if (error == KERN_SUCCESS) {
				        if (residual == xfer_size) {
					        /*
						 * If a read operation returns no error
						 * and no data moved, we turn it into
						 * an error, assuming we're reading at
						 * or beyong EOF.
						 * Fall through and error the entire range.
						 */
					        error = KERN_FAILURE;
					} else {
					        /*
						 * Otherwise, we have partial read. If
						 * the part read is a integral number
						 * of pages supply it. Otherwise round
						 * it up to a page boundary, zero fill
						 * the unread part, and supply it.
						 * Fall through and error the remainder
						 * of the range, if any.
						 */
					        int fill;
						unsigned int lsize;

						fill = residual & ~vm_page_size;
						lsize = (xfer_size - residual) + fill;

						pvs_object_data_provided(vs, upl, vs_offset, lsize);

						if (lsize < xfer_size) {
						        failed_size = xfer_size - lsize;
							error = KERN_FAILURE;
						}
					}
				} 
			}
			if (error != KERN_SUCCESS) {
			        /*
				 * There was an error in some part of the range, tell
				 * the VM. Note that error is explicitly checked again
				 * since it can be modified above.
				 */
				BS_STAT(psp[beg_pseg]->ps_bs,
					psp[beg_pseg]->ps_bs->bs_pages_in_fail += atop_32(failed_size));
			}
			/*
			 * we've issued a single I/O that encompassed the original offset
			 * at this point we either met our speculative request length or 
			 * we ran into a 'hole' (i.e. page not present in the cluster, cluster
			 * not present or not physically contiguous to the previous one), so
			 * we're done issuing I/O at this point
			 */
			return (error);
		}
	}
	return error;
}

int vs_do_async_write = 1;

kern_return_t
vs_cluster_write(
	vstruct_t	vs,
	upl_t		internal_upl,
	upl_offset_t	offset,
	upl_size_t	cnt,
	boolean_t	dp_internal,
	int 		flags)
{
	upl_size_t	transfer_size;
	int		error = 0;
	struct clmap	clmap;

	dp_offset_t	actual_offset;	/* Offset within paging segment */
	paging_segment_t ps;
	dp_offset_t	mobj_base_addr;
	dp_offset_t	mobj_target_addr;

	upl_t		upl;
	upl_page_info_t *pl;
	int		page_index;
	int		list_size;
	int		pages_in_cl;
	unsigned int	cl_size;
	int             base_index;
	unsigned int	seg_size;
	unsigned int	upl_offset_in_object;

	pages_in_cl = 1 << vs->vs_clshift;
	cl_size = pages_in_cl * vm_page_size;
	
	if (!dp_internal) {
		unsigned int page_list_count;
		int	     request_flags;
		unsigned int super_size;
		int          first_dirty;
		int          num_dirty;
		int          num_of_pages;
		int          seg_index;
		upl_offset_t  upl_offset;
		dp_offset_t  seg_offset;
		dp_offset_t  ps_offset[((VM_SUPER_CLUSTER / PAGE_SIZE) >> VSTRUCT_DEF_CLSHIFT) + 1];
		paging_segment_t   psp[((VM_SUPER_CLUSTER / PAGE_SIZE) >> VSTRUCT_DEF_CLSHIFT) + 1];


		if (bs_low) {
			super_size = cl_size;

			request_flags = UPL_NOBLOCK |
				UPL_RET_ONLY_DIRTY | UPL_COPYOUT_FROM | 
				UPL_NO_SYNC | UPL_SET_INTERNAL | UPL_SET_LITE;
		} else {
			super_size = VM_SUPER_CLUSTER;

			request_flags = UPL_NOBLOCK | UPL_CLEAN_IN_PLACE |
				UPL_RET_ONLY_DIRTY | UPL_COPYOUT_FROM | 
				UPL_NO_SYNC | UPL_SET_INTERNAL | UPL_SET_LITE;
		}

		if (!dp_encryption_inited) {
			/*
			 * ENCRYPTED SWAP:
			 * Once we've started using swap, we
			 * can't change our mind on whether
			 * it needs to be encrypted or
			 * not.
			 */
			dp_encryption_inited = TRUE;
		}
		if (dp_encryption) {
			/*
			 * ENCRYPTED SWAP:
			 * request that the UPL be prepared for
			 * encryption.
			 */
			request_flags |= UPL_ENCRYPT;
			flags |= UPL_PAGING_ENCRYPTED;
		}

		page_list_count = 0;
		memory_object_super_upl_request(vs->vs_control,
				(memory_object_offset_t)offset,
				cnt, super_size, 
				&upl, NULL, &page_list_count,
				request_flags | UPL_FOR_PAGEOUT);

		/*
		 * The default pager does not handle objects larger than
		 * 4GB, so it does not deal with offset that don't fit in
		 * 32-bit.  Cast down upl->offset now and make sure we
		 * did not lose any valuable bits.
		 */
		upl_offset_in_object = (unsigned int) upl->offset;
		assert(upl->offset == upl_offset_in_object);

		pl = UPL_GET_INTERNAL_PAGE_LIST(upl);

		seg_size = cl_size - (upl_offset_in_object % cl_size);
		upl_offset = upl_offset_in_object & ~(cl_size - 1);

		for (seg_index = 0, transfer_size = upl->size; 
						transfer_size > 0; ) {
		        ps_offset[seg_index] = 
				ps_clmap(vs, 
					upl_offset,
					&clmap, CL_ALLOC, 
					cl_size, 0); 

			if (ps_offset[seg_index] == (dp_offset_t) -1) {
				upl_abort(upl, 0);
				upl_deallocate(upl);
				
				return KERN_FAILURE;

			}
			psp[seg_index] = CLMAP_PS(clmap);

			if (transfer_size > seg_size) {
			        transfer_size -= seg_size;
				upl_offset += cl_size;
				seg_size    = cl_size;
				seg_index++;
			} else
			        transfer_size = 0;
		}
		/*
		 * Ignore any non-present pages at the end of the
		 * UPL.
		 */
		for (page_index = upl->size / vm_page_size; page_index > 0;) 
			if (UPL_PAGE_PRESENT(pl, --page_index))
				break;
		num_of_pages = page_index + 1;

		base_index = (upl_offset_in_object % cl_size) / PAGE_SIZE;

		for (page_index = 0; page_index < num_of_pages; ) {
			/*
			 * skip over non-dirty pages
			 */
			for ( ; page_index < num_of_pages; page_index++) {
			        if (UPL_DIRTY_PAGE(pl, page_index) 
					|| UPL_PRECIOUS_PAGE(pl, page_index))
				        /*
					 * this is a page we need to write
					 * go see if we can buddy it up with 
					 * others that are contiguous to it
					 */
				        break;
				/*
				 * if the page is not-dirty, but present we 
				 * need to commit it...  This is an unusual 
				 * case since we only asked for dirty pages
				 */
				if (UPL_PAGE_PRESENT(pl, page_index)) {
					boolean_t empty = FALSE;
				        upl_commit_range(upl, 
						 page_index * vm_page_size,
						 vm_page_size, 
						 UPL_COMMIT_NOTIFY_EMPTY,
						 pl,
						 page_list_count,
						 &empty);
					if (empty) {
						assert(page_index == 
						       num_of_pages - 1);
						upl_deallocate(upl);
					}
				}
			}
			if (page_index == num_of_pages)
			        /*
				 * no more pages to look at, we're out of here
				 */
			        break;

			/*
			 * gather up contiguous dirty pages... we have at 
			 * least 1 * otherwise we would have bailed above
			 * make sure that each physical segment that we step
			 * into is contiguous to the one we're currently in
			 * if it's not, we have to stop and write what we have
			 */
			for (first_dirty = page_index; 
					page_index < num_of_pages; ) {
				if ( !UPL_DIRTY_PAGE(pl, page_index) 
					&& !UPL_PRECIOUS_PAGE(pl, page_index))
				        break;
				page_index++;
				/*
				 * if we just looked at the last page in the UPL
				 * we don't need to check for physical segment
				 * continuity
				 */
				if (page_index < num_of_pages) {
				        int cur_seg;
				        int nxt_seg;

				        cur_seg = (base_index + (page_index - 1))/pages_in_cl;
					nxt_seg = (base_index + page_index)/pages_in_cl;

					if (cur_seg != nxt_seg) {
					        if ((ps_offset[cur_seg] != (ps_offset[nxt_seg] - cl_size)) || (psp[cur_seg] != psp[nxt_seg]))
						/*
						 * if the segment we're about 
						 * to step into is not 
						 * contiguous to the one we're 
						 * currently in, or it's in a 
						 * different paging file....
						 * we stop here and generate 
						 * the I/O
						 */
						        break;
					}
				}
			}
			num_dirty = page_index - first_dirty;

			if (num_dirty) {
			        upl_offset = first_dirty * vm_page_size;
				transfer_size = num_dirty * vm_page_size;

				while (transfer_size) {

					if ((seg_size = cl_size - 
						((upl_offset_in_object +
						  upl_offset) % cl_size)) 
							> transfer_size)
					        seg_size = transfer_size;

					ps_vs_write_complete(
						vs, 
						(upl_offset_in_object +
						 upl_offset), 
						seg_size, error);

					transfer_size -= seg_size;
					upl_offset += seg_size;
				}
			        upl_offset = first_dirty * vm_page_size;
				transfer_size = num_dirty * vm_page_size;

			        seg_index  = (base_index + first_dirty) / pages_in_cl;
				seg_offset = (upl_offset_in_object + upl_offset) % cl_size;

				error = ps_write_file(psp[seg_index], 
						upl, upl_offset,
						ps_offset[seg_index] 
								+ seg_offset, 
						transfer_size, flags);
			} else {
				boolean_t empty = FALSE;
			        upl_abort_range(upl,
						first_dirty * vm_page_size, 
						num_dirty   * vm_page_size,
						UPL_ABORT_NOTIFY_EMPTY,
						&empty);
				if (empty) {
					assert(page_index == num_of_pages);
					upl_deallocate(upl);
				}
			}
		}

	} else {
		assert(cnt <= (unsigned) (vm_page_size << vs->vs_clshift));
		list_size = cnt;

		page_index = 0;
		/* The caller provides a mapped_data which is derived  */
		/* from a temporary object.  The targeted pages are    */
		/* guaranteed to be set at offset 0 in the mapped_data */
		/* The actual offset however must still be derived     */
		/* from the offset in the vs in question               */
		mobj_base_addr = offset;
		mobj_target_addr = mobj_base_addr;

		for (transfer_size = list_size; transfer_size != 0;) {
			actual_offset = ps_clmap(vs, mobj_target_addr, 
				&clmap, CL_ALLOC, 
				transfer_size < cl_size ? 
					transfer_size : cl_size, 0);
			if(actual_offset == (dp_offset_t) -1) {
				error = 1;
				break;
			}
			cnt = MIN(transfer_size, 
				  (unsigned) CLMAP_NPGS(clmap) * vm_page_size);
			ps = CLMAP_PS(clmap);
			/* Assume that the caller has given us contiguous */
			/* pages */
	 	   	if(cnt) {
				ps_vs_write_complete(vs, mobj_target_addr, 
								cnt, error);
				error = ps_write_file(ps, internal_upl,
						0, actual_offset,
						cnt, flags);
				if (error)
				        break;
		   	   }
			if (error)
				break;
		   	actual_offset += cnt;
		   	mobj_target_addr += cnt;
			transfer_size -= cnt;
		   	cnt = 0;

			if (error)
				break;
		}
	}
	if(error)
		return KERN_FAILURE;
	else
		return KERN_SUCCESS;
}

vm_size_t
ps_vstruct_allocated_size(
	vstruct_t	vs)
{
	int		num_pages;
	struct vs_map	*vsmap;
	unsigned int	i, j, k;

	num_pages = 0;
	if (vs->vs_indirect) {
		/* loop on indirect maps */
		for (i = 0; i < INDIRECT_CLMAP_ENTRIES(vs->vs_size); i++) {
			vsmap = vs->vs_imap[i];
			if (vsmap == NULL)
				continue;
			/* loop on clusters in this indirect map */
			for (j = 0; j < CLMAP_ENTRIES; j++) {
				if (VSM_ISCLR(vsmap[j]) ||
				    VSM_ISERR(vsmap[j]))
					continue;
				/* loop on pages in this cluster */
				for (k = 0; k < VSCLSIZE(vs); k++) {
					if ((VSM_BMAP(vsmap[j])) & (1 << k))
						num_pages++;
				}
			}
		}
	} else {
		vsmap = vs->vs_dmap;
		if (vsmap == NULL)
			return 0;
		/* loop on clusters in the direct map */
		for (j = 0; j < CLMAP_ENTRIES; j++) {
			if (VSM_ISCLR(vsmap[j]) ||
			    VSM_ISERR(vsmap[j])) 
				continue;
			/* loop on pages in this cluster */
			for (k = 0; k < VSCLSIZE(vs); k++) {
				if ((VSM_BMAP(vsmap[j])) & (1 << k))
					num_pages++;
			}
		}
	}

	return ptoa_32(num_pages);
}

unsigned int
ps_vstruct_allocated_pages(
	vstruct_t		vs,
	default_pager_page_t	*pages,
	unsigned int		pages_size)
{
	unsigned int	num_pages;
	struct vs_map	*vsmap;
	dp_offset_t	offset;
	unsigned int	i, j, k;

	num_pages = 0;
	offset = 0;
	if (vs->vs_indirect) {
		/* loop on indirect maps */
		for (i = 0; i < INDIRECT_CLMAP_ENTRIES(vs->vs_size); i++) {
			vsmap = vs->vs_imap[i];
			if (vsmap == NULL) {
				offset += (vm_page_size * CLMAP_ENTRIES *
					   VSCLSIZE(vs));
				continue;
			}
			/* loop on clusters in this indirect map */
			for (j = 0; j < CLMAP_ENTRIES; j++) {
				if (VSM_ISCLR(vsmap[j]) ||
				    VSM_ISERR(vsmap[j])) {
					offset += vm_page_size * VSCLSIZE(vs);
					continue;
				}
				/* loop on pages in this cluster */
				for (k = 0; k < VSCLSIZE(vs); k++) {
					if ((VSM_BMAP(vsmap[j])) & (1 << k)) {
						num_pages++;
						if (num_pages < pages_size)
							pages++->dpp_offset =
								offset;
					}
					offset += vm_page_size;
				}
			}
		}
	} else {
		vsmap = vs->vs_dmap;
		if (vsmap == NULL)
			return 0;
		/* loop on clusters in the direct map */
		for (j = 0; j < CLMAP_ENTRIES; j++) {
			if (VSM_ISCLR(vsmap[j]) ||
			    VSM_ISERR(vsmap[j])) {
				offset += vm_page_size * VSCLSIZE(vs);
				continue;
			}
			/* loop on pages in this cluster */
			for (k = 0; k < VSCLSIZE(vs); k++) {
				if ((VSM_BMAP(vsmap[j])) & (1 << k)) {
					num_pages++;
					if (num_pages < pages_size)
						pages++->dpp_offset = offset;
				}
				offset += vm_page_size;
			}
		}
	}

	return num_pages;
}


kern_return_t
ps_vstruct_transfer_from_segment(
	vstruct_t	 vs,
	paging_segment_t segment,
	upl_t		 upl)
{
	struct vs_map	*vsmap;
//	struct vs_map	old_vsmap;
//	struct vs_map	new_vsmap;
	unsigned int	i, j;

	VS_LOCK(vs);	/* block all work on this vstruct */
			/* can't allow the normal multiple write */
			/* semantic because writes may conflict */
	vs->vs_xfer_pending = TRUE;
	vs_wait_for_sync_writers(vs);
	vs_start_write(vs);
	vs_wait_for_readers(vs);
	/* we will unlock the vs to allow other writes while transferring */
	/* and will be guaranteed of the persistance of the vs struct     */
	/* because the caller of  ps_vstruct_transfer_from_segment bumped */
	/* vs_async_pending */
	/* OK we now have guaranteed no other parties are accessing this */
	/* vs.  Now that we are also supporting simple lock versions of  */
	/* vs_lock we cannot hold onto VS_LOCK as we may block below.    */
	/* our purpose in holding it before was the multiple write case */
	/* we now use the boolean xfer_pending to do that.  We can use  */
	/* a boolean instead of a count because we have guaranteed single */
	/* file access to this code in its caller */
	VS_UNLOCK(vs);
vs_changed:
	if (vs->vs_indirect) {
		unsigned int	vsmap_size;
		int		clmap_off;
		/* loop on indirect maps */
		for (i = 0; i < INDIRECT_CLMAP_ENTRIES(vs->vs_size); i++) {
			vsmap = vs->vs_imap[i];
			if (vsmap == NULL)
				continue;
			/* loop on clusters in this indirect map */
			clmap_off = (vm_page_size * CLMAP_ENTRIES *
					   VSCLSIZE(vs) * i);
			if(i+1 == INDIRECT_CLMAP_ENTRIES(vs->vs_size))
				vsmap_size = vs->vs_size - (CLMAP_ENTRIES * i);
			else
				vsmap_size = CLMAP_ENTRIES;
			for (j = 0; j < vsmap_size; j++) {
				if (VSM_ISCLR(vsmap[j]) ||
				    VSM_ISERR(vsmap[j]) ||
				    (VSM_PS(vsmap[j]) != segment))
					continue;
				if(vs_cluster_transfer(vs, 
					(vm_page_size * (j << vs->vs_clshift))
					+ clmap_off, 
					vm_page_size << vs->vs_clshift,
					upl)
						!= KERN_SUCCESS) {
				   VS_LOCK(vs);
				   vs->vs_xfer_pending = FALSE;
				   VS_UNLOCK(vs);
				   vs_finish_write(vs);
				   return KERN_FAILURE;
				}
				/* allow other readers/writers during transfer*/
				VS_LOCK(vs);
				vs->vs_xfer_pending = FALSE;
				VS_UNLOCK(vs);
				vs_finish_write(vs);
				VS_LOCK(vs);
				vs->vs_xfer_pending = TRUE;
				vs_wait_for_sync_writers(vs);
				vs_start_write(vs);
				vs_wait_for_readers(vs);
				VS_UNLOCK(vs);
				if (!(vs->vs_indirect)) {
					goto vs_changed;
				}
			}
		}
	} else {
		vsmap = vs->vs_dmap;
		if (vsmap == NULL) {
			VS_LOCK(vs);
			vs->vs_xfer_pending = FALSE;
			VS_UNLOCK(vs);
			vs_finish_write(vs);
			return KERN_SUCCESS;
		}
		/* loop on clusters in the direct map */
		for (j = 0; j < vs->vs_size; j++) {
			if (VSM_ISCLR(vsmap[j]) ||
			    VSM_ISERR(vsmap[j]) ||
			    (VSM_PS(vsmap[j]) != segment))
				continue;
			if(vs_cluster_transfer(vs, 
				vm_page_size * (j << vs->vs_clshift), 
				vm_page_size << vs->vs_clshift,
				upl) != KERN_SUCCESS) {
			   VS_LOCK(vs);
			   vs->vs_xfer_pending = FALSE;
			   VS_UNLOCK(vs);
			   vs_finish_write(vs);
			   return KERN_FAILURE;
			}
			/* allow other readers/writers during transfer*/
			VS_LOCK(vs);
			vs->vs_xfer_pending = FALSE;
			VS_UNLOCK(vs);
			vs_finish_write(vs);
			VS_LOCK(vs);
			vs->vs_xfer_pending = TRUE;
			vs_wait_for_sync_writers(vs);
			vs_start_write(vs);
			vs_wait_for_readers(vs);
			VS_UNLOCK(vs);
			if (vs->vs_indirect) {
				goto vs_changed;
			}
		}
	}

	VS_LOCK(vs);
	vs->vs_xfer_pending = FALSE;
	VS_UNLOCK(vs);
	vs_finish_write(vs);
	return KERN_SUCCESS;
}



vs_map_t
vs_get_map_entry(
	vstruct_t	vs, 
	dp_offset_t	offset)
{
	struct vs_map	*vsmap;
	dp_offset_t	cluster;

	cluster = atop_32(offset) >> vs->vs_clshift;
	if (vs->vs_indirect) {
		long	ind_block = cluster/CLMAP_ENTRIES;

		/* Is the indirect block allocated? */
		vsmap = vs->vs_imap[ind_block];
		if(vsmap == (vs_map_t) NULL)
			return vsmap;
	} else
		vsmap = vs->vs_dmap;
	vsmap += cluster%CLMAP_ENTRIES;
	return vsmap;
}

kern_return_t
vs_cluster_transfer(
	vstruct_t	vs,
	dp_offset_t	offset,
	dp_size_t	cnt,
	upl_t		upl)
{
	dp_offset_t		actual_offset;
	paging_segment_t	ps;
	struct clmap		clmap;
	kern_return_t		error = KERN_SUCCESS;
	unsigned int		size, size_wanted;
	int			i;
	unsigned int		residual = 0;
	unsigned int		unavail_size;
//	default_pager_thread_t	*dpt;
//	boolean_t		dealloc;
	struct	vs_map		*vsmap_ptr = NULL;
	struct	vs_map		read_vsmap;
	struct	vs_map		original_read_vsmap;
	struct	vs_map		write_vsmap;
//	upl_t				sync_upl;
//	vm_offset_t			ioaddr;

	/* vs_cluster_transfer reads in the pages of a cluster and
	 * then writes these pages back to new backing store.  The
	 * segment the pages are being read from is assumed to have
	 * been taken off-line and is no longer considered for new
	 * space requests.
         */

	/*
	 * This loop will be executed once per cluster referenced.
	 * Typically this means once, since it's unlikely that the
	 * VM system will ask for anything spanning cluster boundaries.
	 *
	 * If there are holes in a cluster (in a paging segment), we stop
	 * reading at the hole, then loop again, hoping to
	 * find valid pages later in the cluster.  This continues until
	 * the entire range has been examined, and read, if present.  The
	 * pages are written as they are read.  If a failure occurs after
	 * some pages are written the unmap call at the bottom of the loop
	 * recovers the backing store and the old backing store remains
	 * in effect.
	 */

	VSM_CLR(write_vsmap);
	VSM_CLR(original_read_vsmap);
	/* grab the actual object's pages to sync with I/O */
	while (cnt && (error == KERN_SUCCESS)) {
		vsmap_ptr = vs_get_map_entry(vs, offset);
		actual_offset = ps_clmap(vs, offset, &clmap, CL_FIND, 0, 0);

		if (actual_offset == (dp_offset_t) -1) {

			/*
			 * Nothing left to write in this cluster at least
			 * set write cluster information for any previous
			 * write, clear for next cluster, if there is one
			 */
			unsigned int local_size, clmask, clsize;

			clsize = vm_page_size << vs->vs_clshift;
			clmask = clsize - 1;
			local_size = clsize - (offset & clmask);
			ASSERT(local_size);
			local_size = MIN(local_size, cnt);

			/* This cluster has no data in it beyond what may */
			/* have been found on a previous iteration through */
			/* the loop "write_vsmap" */
			*vsmap_ptr = write_vsmap;
			VSM_CLR(write_vsmap);
			VSM_CLR(original_read_vsmap);

			cnt -= local_size;
			offset += local_size;
			continue;
		}

		/*
		 * Count up contiguous available or unavailable
		 * pages.
		 */
		ps = CLMAP_PS(clmap);
		ASSERT(ps);
		size = 0;
		unavail_size = 0;
		for (i = 0;
		     (size < cnt) && (unavail_size < cnt) &&
		     (i < CLMAP_NPGS(clmap)); i++) {
			if (CLMAP_ISSET(clmap, i)) {
				if (unavail_size != 0)
					break;
				size += vm_page_size;
				BS_STAT(ps->ps_bs,
					ps->ps_bs->bs_pages_in++);
			} else {
				if (size != 0)
					break;
				unavail_size += vm_page_size;
			}
		}

		if (size == 0) {
			ASSERT(unavail_size);
			ps_clunmap(vs, offset, unavail_size);
			cnt -= unavail_size;
			offset += unavail_size;
			if((offset & ((vm_page_size << vs->vs_clshift) - 1)) 
				== 0) {
				/* There is no more to transfer in this
				   cluster
				*/
				*vsmap_ptr = write_vsmap;
				VSM_CLR(write_vsmap);
				VSM_CLR(original_read_vsmap);
			} 
			continue;
		}

		if(VSM_ISCLR(original_read_vsmap))
			original_read_vsmap = *vsmap_ptr;

		if(ps->ps_segtype == PS_PARTITION) {
			panic("swap partition not supported\n");
			/*NOTREACHED*/
			error = KERN_FAILURE;
			residual = size;
/*
			NEED TO ISSUE WITH SYNC & NO COMMIT
			error = ps_read_device(ps, actual_offset, &buffer,
				       size, &residual, flags);
*/
		} else {
			/* NEED TO ISSUE WITH SYNC & NO COMMIT */
			error = ps_read_file(ps, upl, (upl_offset_t) 0, actual_offset, 
					size, &residual, 
					(UPL_IOSYNC | UPL_NOCOMMIT));
		}

		read_vsmap = *vsmap_ptr;


		/*
		 * Adjust counts and put data in new BS.  Optimize for the
		 * common case, i.e. no error and/or partial data.
		 * If there was an error, then we need to error the entire
		 * range, even if some data was successfully read.
		 * 
		 */
		if ((error == KERN_SUCCESS) && (residual == 0)) {

			/*
			 * Got everything we asked for, supply the data to
			 * the new BS.  Note that as a side effect of supplying
			 * the data, the buffer holding the supplied data is
			 * deallocated from the pager's address space unless
			 * the write is unsuccessful.
			 */

			/* note buffer will be cleaned up in all cases by */
			/* internal_cluster_write or if an error on write */
			/* the vm_map_copy_page_discard call              */
			*vsmap_ptr = write_vsmap;

			if(vs_cluster_write(vs, upl, offset, 
					size, TRUE, UPL_IOSYNC | UPL_NOCOMMIT ) != KERN_SUCCESS) {
			 	error = KERN_FAILURE;
				if(!(VSM_ISCLR(*vsmap_ptr))) {
					/* unmap the new backing store object */
					ps_clunmap(vs, offset, size);
				}
				/* original vsmap */
				*vsmap_ptr = original_read_vsmap;
				VSM_CLR(write_vsmap);
			} else {
			       if((offset + size) & 
					((vm_page_size << vs->vs_clshift)
					- 1)) { 
					/* There is more to transfer in this
					   cluster
					*/
					write_vsmap = *vsmap_ptr;
					*vsmap_ptr = read_vsmap;
					ps_clunmap(vs, offset, size);
				} else {
					/* discard the old backing object */
					write_vsmap = *vsmap_ptr;
					*vsmap_ptr = read_vsmap;
					ps_clunmap(vs, offset, size);
					*vsmap_ptr = write_vsmap;
					VSM_CLR(write_vsmap);
					VSM_CLR(original_read_vsmap);
				}
			}
		} else {
			size_wanted = size;
			if (error == KERN_SUCCESS) {
				if (residual == size) {
					/*
					 * If a read operation returns no error
					 * and no data moved, we turn it into
					 * an error, assuming we're reading at
					 * or beyond EOF.
					 * Fall through and error the entire
					 * range.
					 */
					error = KERN_FAILURE;
					*vsmap_ptr = write_vsmap;
					if(!(VSM_ISCLR(*vsmap_ptr))) {
					/* unmap the new backing store object */
					ps_clunmap(vs, offset, size);
					}
					*vsmap_ptr = original_read_vsmap;
					VSM_CLR(write_vsmap);
					continue;
				} else {
					/*
					 * Otherwise, we have partial read. 
					 * This is also considered an error
					 * for the purposes of cluster transfer
					 */
					error = KERN_FAILURE;
					*vsmap_ptr = write_vsmap;
					if(!(VSM_ISCLR(*vsmap_ptr))) {
					/* unmap the new backing store object */
					ps_clunmap(vs, offset, size);
					}
					*vsmap_ptr = original_read_vsmap;
					VSM_CLR(write_vsmap);
					continue;
				}
			}

		}
		cnt -= size;
		offset += size;

	} /* END while (cnt && (error == 0)) */
	if(!VSM_ISCLR(write_vsmap))
		*vsmap_ptr = write_vsmap;

	return error;
}

kern_return_t
default_pager_add_file(
	MACH_PORT_FACE	backing_store,
	vnode_ptr_t	vp,
	int		record_size,
	vm_size_t	size)
{
	backing_store_t		bs;
	paging_segment_t	ps;
	int			i;
	unsigned int		j;
	int			error;

	if ((bs = backing_store_lookup(backing_store))
	    == BACKING_STORE_NULL)
		return KERN_INVALID_ARGUMENT;

	PSL_LOCK();
	for (i = 0; i <= paging_segment_max; i++) {
		ps = paging_segments[i];
		if (ps == PAGING_SEGMENT_NULL)
			continue;
		if (ps->ps_segtype != PS_FILE)
			continue;

		/*
		 * Check for overlap on same device.
		 */
		if (ps->ps_vnode == (struct vnode *)vp) {
			PSL_UNLOCK();
			BS_UNLOCK(bs);
			return KERN_INVALID_ARGUMENT;
		}
	}
	PSL_UNLOCK();

	/*
	 * Set up the paging segment
	 */
	ps = (paging_segment_t) kalloc(sizeof (struct paging_segment));
	if (ps == PAGING_SEGMENT_NULL) {
		BS_UNLOCK(bs);
		return KERN_RESOURCE_SHORTAGE;
	}

	ps->ps_segtype = PS_FILE;
	ps->ps_vnode = (struct vnode *)vp;
	ps->ps_offset = 0;
	ps->ps_record_shift = local_log2(vm_page_size / record_size);
	assert((dp_size_t) size == size);
	ps->ps_recnum = (dp_size_t) size;
	ps->ps_pgnum = ((dp_size_t) size) >> ps->ps_record_shift;

	ps->ps_pgcount = ps->ps_pgnum;
	ps->ps_clshift = local_log2(bs->bs_clsize);
	ps->ps_clcount = ps->ps_ncls = ps->ps_pgcount >> ps->ps_clshift;
	ps->ps_special_clusters = 0;
	ps->ps_hint = 0;

	PS_LOCK_INIT(ps);
	ps->ps_bmap = (unsigned char *) kalloc(RMAPSIZE(ps->ps_ncls));
	if (!ps->ps_bmap) {
		kfree(ps, sizeof *ps);
		BS_UNLOCK(bs);
		return KERN_RESOURCE_SHORTAGE;
	}
	for (j = 0; j < ps->ps_ncls; j++) {
		clrbit(ps->ps_bmap, j);
	}

	if(paging_segment_count == 0) {
		ps->ps_state = PS_EMERGENCY_SEGMENT;
		if(use_emergency_swap_file_first) {
			ps->ps_state |= PS_CAN_USE;
		}
		emergency_segment_backing_store = backing_store;
	} else {
		ps->ps_state = PS_CAN_USE;
	}
	
	ps->ps_bs = bs;

	if ((error = ps_enter(ps)) != 0) {
		kfree(ps->ps_bmap, RMAPSIZE(ps->ps_ncls));
		kfree(ps, sizeof *ps);
		BS_UNLOCK(bs);
		return KERN_RESOURCE_SHORTAGE;
	}

	bs->bs_pages_free += ps->ps_clcount << ps->ps_clshift;
	bs->bs_pages_total += ps->ps_clcount << ps->ps_clshift;
	PSL_LOCK();
	if(IS_PS_OK_TO_USE(ps)) {
		dp_pages_free += ps->ps_pgcount;
	} else {
		dp_pages_reserve += ps->ps_pgcount;
	}
	PSL_UNLOCK();

	BS_UNLOCK(bs);

	bs_more_space(ps->ps_clcount);

	/*
	 * If the paging segment being activated is not the emergency
	 * segment and we notice that the emergency segment is being
	 * used then we help recover it. If all goes well, the
	 * emergency segment will be back to its original state of
	 * online but not activated (till it's needed the next time).
	 */
	ps = paging_segments[EMERGENCY_PSEG_INDEX];
	if(IS_PS_EMERGENCY_SEGMENT(ps) && IS_PS_OK_TO_USE(ps)) {
		if(default_pager_backing_store_delete(emergency_segment_backing_store)) {
			dprintf(("Failed to recover emergency paging segment\n"));
		} else {
			dprintf(("Recovered emergency paging segment\n"));
		}
	}
	
	DP_DEBUG(DEBUG_BS_INTERNAL,
		 ("device=0x%x,offset=0x%x,count=0x%x,record_size=0x%x,shift=%d,total_size=0x%x\n",
		  device, offset, (dp_size_t) size, record_size,
		  ps->ps_record_shift, ps->ps_pgnum));

	return KERN_SUCCESS;
}



kern_return_t
ps_read_file(
	paging_segment_t	ps,
	upl_t			upl,
	upl_offset_t		upl_offset,
	dp_offset_t		offset,
	upl_size_t		size,
	unsigned int		*residualp,
	int			flags)
{
	vm_object_offset_t	f_offset;
	int			error = 0;
	int			result;

	assert(dp_encryption_inited);

	clustered_reads[atop_32(size)]++;

	f_offset = (vm_object_offset_t)(ps->ps_offset + offset);
	
	/*
	 * for transfer case we need to pass uploffset and flags
	 */
	assert((upl_size_t) size == size);
	error = vnode_pagein(ps->ps_vnode, upl, upl_offset, f_offset, (upl_size_t)size, flags, NULL);

	/* The vnode_pagein semantic is somewhat at odds with the existing   */
	/* device_read semantic.  Partial reads are not experienced at this  */
	/* level.  It is up to the bit map code and cluster read code to     */
	/* check that requested data locations are actually backed, and the  */
	/* pagein code to either read all of the requested data or return an */
	/* error. */

	if (error)
		result = KERN_FAILURE;
	else {
		*residualp = 0;
		result = KERN_SUCCESS;
	}
	return result;
}

kern_return_t
ps_write_file(
	paging_segment_t	ps,
	upl_t                   upl,
	upl_offset_t		upl_offset,
	dp_offset_t		offset,
	unsigned int		size,
	int			flags)
{
	vm_object_offset_t	f_offset;
	kern_return_t		result;

	assert(dp_encryption_inited);

	clustered_writes[atop_32(size)]++;
	f_offset = (vm_object_offset_t)(ps->ps_offset + offset);

	if (flags & UPL_PAGING_ENCRYPTED) {
		/*
		 * ENCRYPTED SWAP:
		 * encrypt all the pages that we're going
		 * to pageout.
		 */
		upl_encrypt(upl, upl_offset, size);
	}
	assert((upl_size_t) size == size);
	if (vnode_pageout(ps->ps_vnode,	upl, upl_offset, f_offset, (upl_size_t)size, flags, NULL))
	        result = KERN_FAILURE;
	else
	        result = KERN_SUCCESS;

	return result;
}

kern_return_t
default_pager_triggers( __unused MACH_PORT_FACE default_pager,
	int		hi_wat,
	int		lo_wat,
	int		flags,
	MACH_PORT_FACE  trigger_port)
{
	MACH_PORT_FACE release;
	kern_return_t kr;
	clock_sec_t now;
	clock_nsec_t nanoseconds_dummy;
	static clock_sec_t error_notify = 0;

	PSL_LOCK();
	if (flags == SWAP_ENCRYPT_ON) {
		/* ENCRYPTED SWAP: turn encryption on */
		release = trigger_port;
		if (!dp_encryption_inited) {
			dp_encryption_inited = TRUE;
			dp_encryption = TRUE;
			kr = KERN_SUCCESS;
		} else {
			kr = KERN_FAILURE;
		}
	} else if (flags == SWAP_ENCRYPT_OFF) {
		/* ENCRYPTED SWAP: turn encryption off */
		release = trigger_port;
		if (!dp_encryption_inited) {
			dp_encryption_inited = TRUE;
			dp_encryption = FALSE;
			kr = KERN_SUCCESS;
		} else {
			kr = KERN_FAILURE;
		}
	} else if (flags == HI_WAT_ALERT) {
		release = min_pages_trigger_port;
		min_pages_trigger_port = trigger_port;
		minimum_pages_remaining = hi_wat/vm_page_size;
		bs_low = FALSE;
		kr = KERN_SUCCESS;
	} else if (flags ==  LO_WAT_ALERT) {
		release = max_pages_trigger_port;
		max_pages_trigger_port = trigger_port;
		maximum_pages_free = lo_wat/vm_page_size;
		kr = KERN_SUCCESS;
	} else if (flags == USE_EMERGENCY_SWAP_FILE_FIRST) {
		use_emergency_swap_file_first = TRUE;
		release = trigger_port;
		kr = KERN_SUCCESS;
	} else if (flags == SWAP_FILE_CREATION_ERROR) {
		release = trigger_port;
		kr = KERN_SUCCESS;
		if( paging_segment_count == 1) {
			use_emergency_swap_file_first = TRUE;
		}
		no_paging_space_action();
		clock_get_system_nanotime(&now, &nanoseconds_dummy);
		if (now > error_notify + 5) {
			dprintf(("Swap File Error.\n"));
			error_notify = now;
		}
	} else {
		release = trigger_port;
		kr =  KERN_INVALID_ARGUMENT;
	}
	PSL_UNLOCK();

	if (IP_VALID(release))
		ipc_port_release_send(release);
	
	return kr;
}

/*
 * Monitor the amount of available backing store vs. the amount of
 * required backing store, notify a listener (if present) when 
 * backing store may safely be removed.
 *
 * We attempt to avoid the situation where backing store is 
 * discarded en masse, as this can lead to thrashing as the
 * backing store is compacted.
 */

#define PF_INTERVAL	3	/* time between free level checks */
#define PF_LATENCY	10	/* number of intervals before release */

static int dp_pages_free_low_count = 0;
thread_call_t default_pager_backing_store_monitor_callout;

void
default_pager_backing_store_monitor(__unused thread_call_param_t p1,
									__unused thread_call_param_t p2)
{
//	unsigned long long	average;
	ipc_port_t		trigger;
	uint64_t		deadline;

	/*
	 * We determine whether it will be safe to release some
	 * backing store by watching the free page level.  If
	 * it remains below the maximum_pages_free threshold for
	 * at least PF_LATENCY checks (taken at PF_INTERVAL seconds)
	 * then we deem it safe.
	 *
	 * Note that this establishes a maximum rate at which backing
	 * store will be released, as each notification (currently)
	 * only results in a single backing store object being
	 * released.
	 */
	if (dp_pages_free > maximum_pages_free) {
		dp_pages_free_low_count++;
	} else {
		dp_pages_free_low_count = 0;
	}

	/* decide whether to send notification */
	trigger = IP_NULL;
	if (max_pages_trigger_port &&
	    (backing_store_release_trigger_disable == 0) &&
	    (dp_pages_free_low_count > PF_LATENCY)) {
		trigger = max_pages_trigger_port;
		max_pages_trigger_port = NULL;
	}

	/* send notification */
	if (trigger != IP_NULL) {
		VSL_LOCK();
		if(backing_store_release_trigger_disable != 0) {
			assert_wait((event_t) 
				    &backing_store_release_trigger_disable, 
				    THREAD_UNINT);
			VSL_UNLOCK();
			thread_block(THREAD_CONTINUE_NULL);
		} else {
			VSL_UNLOCK();
		}
		default_pager_space_alert(trigger, LO_WAT_ALERT);
		ipc_port_release_send(trigger);
		dp_pages_free_low_count = 0;
	}

	clock_interval_to_deadline(PF_INTERVAL, NSEC_PER_SEC, &deadline);
	thread_call_enter_delayed(default_pager_backing_store_monitor_callout, deadline);
}
