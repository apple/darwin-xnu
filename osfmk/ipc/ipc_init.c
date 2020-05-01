/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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
 *	File:	ipc/ipc_init.c
 *	Author:	Rich Draves
 *	Date:	1989
 *
 *	Functions to initialize the IPC system.
 */

#include <mach_debug.h>

#include <mach/port.h>
#include <mach/message.h>
#include <mach/kern_return.h>

#include <kern/kern_types.h>
#include <kern/arcade.h>
#include <kern/kalloc.h>
#include <kern/simple_lock.h>
#include <kern/mach_param.h>
#include <kern/ipc_host.h>
#include <kern/ipc_kobject.h>
#include <kern/ipc_mig.h>
#include <kern/host_notify.h>
#include <kern/mk_timer.h>
#include <kern/misc_protos.h>
#include <kern/suid_cred.h>
#include <kern/sync_lock.h>
#include <kern/sync_sema.h>
#include <kern/ux_handler.h>
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
#include <ipc/ipc_table.h>
#include <ipc/ipc_voucher.h>
#include <ipc/ipc_importance.h>

#include <mach/machine/ndr_def.h>   /* NDR_record */

vm_map_t ipc_kernel_map;
vm_size_t ipc_kernel_map_size = 1024 * 1024;

/* values to limit physical copy out-of-line memory descriptors */
vm_map_t ipc_kernel_copy_map;
#define IPC_KERNEL_COPY_MAP_SIZE (8 * 1024 * 1024)
vm_size_t ipc_kernel_copy_map_size = IPC_KERNEL_COPY_MAP_SIZE;
vm_size_t ipc_kmsg_max_vm_space = ((IPC_KERNEL_COPY_MAP_SIZE * 7) / 8);

/*
 * values to limit inline message body handling
 * avoid copyin/out limits - even after accounting for maximum descriptor expansion.
 */
#define IPC_KMSG_MAX_SPACE (64 * 1024 * 1024) /* keep in sync with COPYSIZELIMIT_PANIC */
vm_size_t ipc_kmsg_max_body_space = ((IPC_KMSG_MAX_SPACE * 3) / 4 - MAX_TRAILER_SIZE);

int ipc_space_max;
int ipc_port_max;
int ipc_pset_max;
int prioritize_launch = 1;
int enforce_strict_reply = 0;


lck_grp_t               ipc_lck_grp;
lck_attr_t              ipc_lck_attr;

static lck_grp_attr_t   ipc_lck_grp_attr;

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
	int prioritize_launch_bootarg;
	int strict_reply_bootarg;

	lck_grp_attr_setdefault(&ipc_lck_grp_attr);
	lck_grp_init(&ipc_lck_grp, "ipc", &ipc_lck_grp_attr);
	lck_attr_setdefault(&ipc_lck_attr);

	ipc_port_multiple_lock_init();

	ipc_port_timestamp_data = 0;

	/* all IPC zones should be exhaustible */

	ipc_space_zone = zinit(sizeof(struct ipc_space),
	    ipc_space_max * sizeof(struct ipc_space),
	    sizeof(struct ipc_space),
	    "ipc spaces");
	zone_change(ipc_space_zone, Z_NOENCRYPT, TRUE);

	/*
	 * populate all port(set) zones
	 */
	ipc_object_zones[IOT_PORT] =
	    zinit(sizeof(struct ipc_port),
	    ipc_port_max * sizeof(struct ipc_port),
	    sizeof(struct ipc_port),
	    "ipc ports");
	/* cant charge callers for port allocations (references passed) */
	zone_change(ipc_object_zones[IOT_PORT], Z_CALLERACCT, FALSE);
	zone_change(ipc_object_zones[IOT_PORT], Z_NOENCRYPT, TRUE);
	zone_change(ipc_object_zones[IOT_PORT], Z_CLEARMEMORY, TRUE);

	ipc_object_zones[IOT_PORT_SET] =
	    zinit(sizeof(struct ipc_pset),
	    ipc_pset_max * sizeof(struct ipc_pset),
	    sizeof(struct ipc_pset),
	    "ipc port sets");
	zone_change(ipc_object_zones[IOT_PORT_SET], Z_NOENCRYPT, TRUE);
	zone_change(ipc_object_zones[IOT_PORT_SET], Z_CLEARMEMORY, TRUE);

	/*
	 * Create the basic ipc_kmsg_t zone (the one we also cache)
	 * elements at the processor-level to avoid the locking.
	 */
	ipc_kmsg_zone = zinit(IKM_SAVED_KMSG_SIZE,
	    ipc_port_max * MACH_PORT_QLIMIT_DEFAULT *
	    IKM_SAVED_KMSG_SIZE,
	    IKM_SAVED_KMSG_SIZE,
	    "ipc kmsgs");
	zone_change(ipc_kmsg_zone, Z_CALLERACCT, FALSE);
	zone_change(ipc_kmsg_zone, Z_CACHING_ENABLED, TRUE);

	/* create special spaces */

	kr = ipc_space_create_special(&ipc_space_kernel);
	assert(kr == KERN_SUCCESS);


	kr = ipc_space_create_special(&ipc_space_reply);
	assert(kr == KERN_SUCCESS);

	/* initialize modules with hidden data structures */

#if     MACH_ASSERT
	ipc_port_debug_init();
#endif
	ipc_kobject_init();
	ipc_table_init();
	ipc_voucher_init();

#if IMPORTANCE_INHERITANCE
	ipc_importance_init();
#endif

	semaphore_init();
	mk_timer_init();
	host_notify_init();

#if CONFIG_ARCADE
	arcade_init();
#endif

	suid_cred_init();

	if (PE_parse_boot_argn("prioritize_launch", &prioritize_launch_bootarg, sizeof(prioritize_launch_bootarg))) {
		prioritize_launch = !!prioritize_launch_bootarg;
	}
	if (PE_parse_boot_argn("ipc_strict_reply", &strict_reply_bootarg, sizeof(strict_reply_bootarg))) {
		enforce_strict_reply = !!strict_reply_bootarg;
	}
}

/*
 * XXX tunable, belongs in mach.message.h
 */
#define MSG_OOL_SIZE_SMALL_MAX (2*PAGE_SIZE)
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
	vm_offset_t min;

	retval = kmem_suballoc(kernel_map, &min, ipc_kernel_map_size,
	    TRUE,
	    (VM_FLAGS_ANYWHERE),
	    VM_MAP_KERNEL_FLAGS_NONE,
	    VM_KERN_MEMORY_IPC,
	    &ipc_kernel_map);

	if (retval != KERN_SUCCESS) {
		panic("ipc_init: kmem_suballoc of ipc_kernel_map failed");
	}

	retval = kmem_suballoc(kernel_map, &min, ipc_kernel_copy_map_size,
	    TRUE,
	    (VM_FLAGS_ANYWHERE),
	    VM_MAP_KERNEL_FLAGS_NONE,
	    VM_KERN_MEMORY_IPC,
	    &ipc_kernel_copy_map);

	if (retval != KERN_SUCCESS) {
		panic("ipc_init: kmem_suballoc of ipc_kernel_copy_map failed");
	}

	ipc_kernel_copy_map->no_zero_fill = TRUE;
	ipc_kernel_copy_map->wait_for_space = TRUE;

	/*
	 * As an optimization, 'small' out of line data regions using a
	 * physical copy strategy are copied into kalloc'ed buffers.
	 * The value of 'small' is determined here.  Requests kalloc()
	 * with sizes greater or equal to kalloc_max_prerounded may fail.
	 */
	if (kalloc_max_prerounded <= MSG_OOL_SIZE_SMALL_MAX) {
		msg_ool_size_small = kalloc_max_prerounded;
	} else {
		msg_ool_size_small = MSG_OOL_SIZE_SMALL_MAX;
	}
	/* account for overhead to avoid spilling over a page */
	msg_ool_size_small -= cpy_kdata_hdr_sz;

	ipc_host_init();
	ux_handler_init();
}


/*
 *	Routine:	ipc_thread_call_init
 *	Purpose:
 *		Initialize IPC logic that needs thread call support
 */

void
ipc_thread_call_init(void)
{
#if IMPORTANCE_INHERITANCE
	ipc_importance_thread_call_init();
#endif
}
