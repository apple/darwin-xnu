/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
#include <ipc/ipc_eventlink.h>

#include <mach/machine/ndr_def.h>   /* NDR_record */

#define IPC_KERNEL_MAP_SIZE      (1024 * 1024)
SECURITY_READ_ONLY_LATE(vm_map_t) ipc_kernel_map;

/* values to limit physical copy out-of-line memory descriptors */
SECURITY_READ_ONLY_LATE(vm_map_t) ipc_kernel_copy_map;
#define IPC_KERNEL_COPY_MAP_SIZE (8 * 1024 * 1024)
const vm_size_t ipc_kmsg_max_vm_space = ((IPC_KERNEL_COPY_MAP_SIZE * 7) / 8);

/*
 * values to limit inline message body handling
 * avoid copyin/out limits - even after accounting for maximum descriptor expansion.
 */
#define IPC_KMSG_MAX_SPACE (64 * 1024 * 1024) /* keep in sync with COPYSIZELIMIT_PANIC */
const vm_size_t ipc_kmsg_max_body_space = ((IPC_KMSG_MAX_SPACE * 3) / 4 - MAX_TRAILER_SIZE);

LCK_GRP_DECLARE(ipc_lck_grp, "ipc");
LCK_ATTR_DECLARE(ipc_lck_attr, 0, 0);

/*
 * XXX tunable, belongs in mach.message.h
 */
#define MSG_OOL_SIZE_SMALL_MAX (2*PAGE_SIZE)
SECURITY_READ_ONLY_LATE(vm_size_t) msg_ool_size_small;

/*
 *	Routine:	ipc_init
 *	Purpose:
 *		Final initialization
 */
__startup_func
static void
ipc_init(void)
{
	kern_return_t kr;
	vm_offset_t min;

	/* create special spaces */

	kr = ipc_space_create_special(&ipc_space_kernel);
	assert(kr == KERN_SUCCESS);

	kr = ipc_space_create_special(&ipc_space_reply);
	assert(kr == KERN_SUCCESS);

	/* initialize modules with hidden data structures */

#if IMPORTANCE_INHERITANCE
	ipc_importance_init();
#endif
#if CONFIG_ARCADE
	arcade_init();
#endif

	kr = kmem_suballoc(kernel_map, &min, IPC_KERNEL_MAP_SIZE,
	    TRUE,
	    (VM_FLAGS_ANYWHERE),
	    VM_MAP_KERNEL_FLAGS_NONE,
	    VM_KERN_MEMORY_IPC,
	    &ipc_kernel_map);

	if (kr != KERN_SUCCESS) {
		panic("ipc_init: kmem_suballoc of ipc_kernel_map failed");
	}

	kr = kmem_suballoc(kernel_map, &min, IPC_KERNEL_COPY_MAP_SIZE,
	    TRUE,
	    (VM_FLAGS_ANYWHERE),
	    VM_MAP_KERNEL_FLAGS_NONE,
	    VM_KERN_MEMORY_IPC,
	    &ipc_kernel_copy_map);

	if (kr != KERN_SUCCESS) {
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

	ipc_host_init();
	ux_handler_init();
}
STARTUP(MACH_IPC, STARTUP_RANK_LAST, ipc_init);


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
