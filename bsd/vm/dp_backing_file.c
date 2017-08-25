/*
 * Copyright (c) 2000-2010 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/vnode_internal.h>
#include <sys/namei.h>
#include <sys/ubc_internal.h>
#include <sys/malloc.h>
#include <sys/user.h>

#include <default_pager/default_pager_types.h>

#include <security/audit/audit.h>
#include <bsm/audit_kevents.h>

#include <mach/mach_types.h>
#include <mach/host_priv.h>
#include <mach/mach_traps.h>
#include <mach/boolean.h>

#include <kern/kern_types.h>
#include <kern/locks.h>
#include <kern/host.h>
#include <kern/task.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/policy_internal.h>

#include <libkern/libkern.h>

#include <vm/vm_pageout.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vnode_pager.h>
#include <vm/vm_protos.h>
#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include <pexpert/pexpert.h>


/*
 *	Routine:	macx_backing_store_recovery
 *	Function:
 *		Syscall interface to set a tasks privilege
 *		level so that it is not subject to 
 *		macx_backing_store_suspend
 */
int
macx_backing_store_recovery(
	__unused struct macx_backing_store_recovery_args *args)
{
	return ENOTSUP;
}

/*
 *	Routine:	macx_backing_store_suspend
 *	Function:
 *		Syscall interface to stop new demand for 
 *		backing store when backing store is low
 */

int
macx_backing_store_suspend(
	__unused struct macx_backing_store_suspend_args *args)
{
	return ENOTSUP;
}


extern boolean_t compressor_store_stop_compaction;

/*
 *	Routine:	macx_backing_store_compaction
 *	Function:
 *		Turn compaction of swap space on or off.  This is
 *		used during shutdown/restart so	that the kernel 
 *		doesn't waste time compacting swap files that are 
 *		about to be deleted anyway.  Compaction	is always 
 *		on by default when the system comes up and is turned 
 *		off when a shutdown/restart is requested.  It is 
 *		re-enabled if the shutdown/restart is aborted for any reason.
 *
 *  This routine assumes macx_lock has been locked by macx_triggers ->
 *      mach_macx_triggers -> macx_backing_store_compaction
 */

int
macx_backing_store_compaction(int flags)
{
	int error;

	if ((error = suser(kauth_cred_get(), 0)))
		return error;

	if (flags & SWAP_COMPACT_DISABLE) {
		compressor_store_stop_compaction = TRUE;

		kprintf("compressor_store_stop_compaction = TRUE\n");

	} else if (flags & SWAP_COMPACT_ENABLE) {
		compressor_store_stop_compaction = FALSE;

		kprintf("compressor_store_stop_compaction = FALSE\n");
	}

	return 0;
}

/*
 *	Routine:	macx_triggers
 *	Function:
 *		Syscall interface to set the call backs for low and
 *		high water marks.
 */
int
macx_triggers(
	struct macx_triggers_args *args)
{
	int	flags = args->flags;

	if (flags & (SWAP_COMPACT_DISABLE | SWAP_COMPACT_ENABLE))
		return (macx_backing_store_compaction(flags));

	return ENOTSUP;
}


int
macx_swapon(
	__unused struct macx_swapon_args *args)
{
	return ENOTSUP;
}


/*
 *	Routine:	macx_swapoff
 *	Function:
 *		Syscall interface to remove a file from backing store
 */
int
macx_swapoff(
	__unused struct macx_swapoff_args *args)
{
	return ENOTSUP;
}

/*
 *	Routine:	macx_swapinfo
 *	Function:
 *		Syscall interface to get general swap statistics
 */
extern uint64_t vm_swap_get_total_space(void);
extern uint64_t vm_swap_get_free_space(void);
extern boolean_t vm_swap_up;

int
macx_swapinfo(
	memory_object_size_t	*total_p,
	memory_object_size_t	*avail_p,
	vm_size_t		*pagesize_p,
	boolean_t		*encrypted_p)
{
	if (VM_CONFIG_SWAP_IS_PRESENT) {

		*total_p = vm_swap_get_total_space();
		*avail_p = vm_swap_get_free_space();
		*pagesize_p = (vm_size_t)PAGE_SIZE_64;
		*encrypted_p = TRUE;

	} else {
		
		*total_p = 0;
		*avail_p = 0;
		*pagesize_p = 0;
		*encrypted_p = FALSE;
	}
	return 0;
}
