/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 *	File:	ipc/ipc_init.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to initialize the IPC system.
 */

#include <mach_debug.h>
#include <mach_rt.h>

#include <mach/kern_return.h>
#include <kern/mach_param.h>
#include <kern/ipc_host.h>
#include <kern/host_notify.h>
#include <kern/mk_timer.h>
#include <kern/misc_protos.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_pset.h>
#include <ipc/ipc_notify.h>
#include <ipc/ipc_kmsg.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_init.h>
#include <mach/machine/ndr_def.h>   /* NDR_record */

vm_map_t ipc_kernel_map;
vm_size_t ipc_kernel_map_size = 1024 * 1024;

vm_map_t ipc_kernel_copy_map;
#define IPC_KERNEL_COPY_MAP_SIZE (8 * 1024 * 1024)
vm_size_t ipc_kernel_copy_map_size = IPC_KERNEL_COPY_MAP_SIZE;
vm_size_t ipc_kmsg_max_vm_space = (IPC_KERNEL_COPY_MAP_SIZE * 7)/8;

int ipc_space_max = SPACE_MAX;
int ipc_tree_entry_max = ITE_MAX;
int ipc_port_max = PORT_MAX;
int ipc_pset_max = SET_MAX;

extern void mig_init(void);
extern void ikm_cache_init(void);

/*
 *	Routine:	ipc_bootstrap
 *	Purpose:
 *		Initialization needed before the kernel task
 *		can be created.
 */

void
ipc_bootstrap(void)
{
	kern_return_t kr;

	ipc_port_multiple_lock_init();

	ipc_port_timestamp_lock_init();
	ipc_port_timestamp_data = 0;

	/* all IPC zones should be exhaustible */

	ipc_space_zone = zinit(sizeof(struct ipc_space),
			       ipc_space_max * sizeof(struct ipc_space),
			       sizeof(struct ipc_space),
			       "ipc spaces");
#if 0
	/* make it exhaustible */
	zone_change(ipc_space_zone, Z_EXHAUST, TRUE);
#endif

	ipc_tree_entry_zone =
		zinit(sizeof(struct ipc_tree_entry),
			ipc_tree_entry_max * sizeof(struct ipc_tree_entry),
			sizeof(struct ipc_tree_entry),
			"ipc tree entries");
#if 0
	/* make it exhaustible */
	zone_change(ipc_tree_entry_zone, Z_EXHAUST, TRUE);
#endif

	/*
	 * populate all port(set) zones
	 */
	ipc_object_zones[IOT_PORT] =
		zinit(sizeof(struct ipc_port),
		      ipc_port_max * sizeof(struct ipc_port),
		      sizeof(struct ipc_port),
		      "ipc ports");
	/*
	 * XXX  Can't make the port zone exhaustible because the kernel
	 * XXX	panics when port allocation for an internal object fails.
	 *zone_change(ipc_object_zones[IOT_PORT], Z_EXHAUST, TRUE);
	 */

	ipc_object_zones[IOT_PORT_SET] =
		zinit(sizeof(struct ipc_pset),
		      ipc_pset_max * sizeof(struct ipc_pset),
		      sizeof(struct ipc_pset),
		      "ipc port sets");
	/* make it exhaustible */
	zone_change(ipc_object_zones[IOT_PORT_SET], Z_EXHAUST, TRUE);

	/* create special spaces */

	kr = ipc_space_create_special(&ipc_space_kernel);
	assert(kr == KERN_SUCCESS);


	kr = ipc_space_create_special(&ipc_space_reply);
	assert(kr == KERN_SUCCESS);

	/* initialize modules with hidden data structures */

#if	MACH_ASSERT
	ipc_port_debug_init();
#endif
	mig_init();
	ipc_table_init();
	ipc_hash_init();
	ipc_kmsg_init();
	semaphore_init();
	lock_set_init();
	mk_timer_init();
	host_notify_init();
}

/* 
 * XXX tunable, belongs in mach.message.h 
 */
#define MSG_OOL_SIZE_SMALL_MAX 4096
vm_size_t msg_ool_size_small;

/*
 *	Routine:	ipc_init
 *	Purpose:
 *		Final initialization of the IPC system.
 */

void
ipc_init(void)
{
	kern_return_t retval;
	vm_offset_t min, max;
	extern vm_size_t kalloc_max_prerounded;

	retval = kmem_suballoc(kernel_map, &min, ipc_kernel_map_size,
			       TRUE, TRUE, &ipc_kernel_map);
	if (retval != KERN_SUCCESS)
		panic("ipc_init: kmem_suballoc of ipc_kernel_map failed");

	retval = kmem_suballoc(kernel_map, &min, ipc_kernel_copy_map_size,
			       TRUE, TRUE, &ipc_kernel_copy_map);
	if (retval != KERN_SUCCESS)
		panic("ipc_init: kmem_suballoc of ipc_kernel_copy_map failed");

	ipc_kernel_copy_map->no_zero_fill = TRUE;
	ipc_kernel_copy_map->wait_for_space = TRUE;

	/*
	 * As an optimization, 'small' out of line data regions using a 
	 * physical copy strategy are copied into kalloc'ed buffers.
	 * The value of 'small' is determined here.  Requests kalloc()
	 * with sizes greater or equal to kalloc_max_prerounded may fail.
	 */
	if (kalloc_max_prerounded <=  MSG_OOL_SIZE_SMALL_MAX) {
		msg_ool_size_small = kalloc_max_prerounded;
	}
	else {
		msg_ool_size_small = MSG_OOL_SIZE_SMALL_MAX;
	}

	ipc_host_init();
}
