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
 *	Author: David B. Golub, Carnegie Mellon University
 *	Date:   8/89
 *
 *      Initialize device service as part of kernel task.
 */

#include <mach/mach_types.h>
#include <mach/port.h>

#include <ipc/ipc_types.h>
#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>

#include <kern/kern_types.h>
#include <kern/host.h>
#include <kern/ipc_kobject.h>
#include <kern/startup.h>
#include <kern/task.h>
#include <kern/misc_protos.h>

#include <device/device_types.h>
#include <device/device_port.h>

ipc_port_t      master_device_port;
void           *master_device_kobject;

lck_grp_attr_t * dev_lck_grp_attr;
lck_grp_t * dev_lck_grp;
lck_attr_t * dev_lck_attr;
lck_mtx_t iokit_obj_to_port_binding_lock;

void
device_service_create(void)
{
	master_device_port = ipc_kobject_alloc_port(
		(ipc_kobject_t)&master_device_kobject, IKOT_MASTER_DEVICE,
		IPC_KOBJECT_ALLOC_NONE);

	kernel_set_special_port(host_priv_self(), HOST_IO_MASTER_PORT,
	    ipc_port_make_send(master_device_port));

	/* allocate device lock group attribute and group */
	dev_lck_grp_attr = lck_grp_attr_alloc_init();
	dev_lck_grp = lck_grp_alloc_init("device", dev_lck_grp_attr);

	/* Allocate device lock attribute */
	dev_lck_attr = lck_attr_alloc_init();

	/* Initialize the IOKit object to port binding lock */
	lck_mtx_init(&iokit_obj_to_port_binding_lock, dev_lck_grp, dev_lck_attr);

#if 0
	ds_init();
	net_io_init();
	device_pager_init();
	datadev_init();

	(void) kernel_thread(kernel_task, io_done_thread, (char *)0);
	(void) kernel_thread(kernel_task, net_thread, (char *)0);
#endif
}
