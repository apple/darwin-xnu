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
 * Copyright (c) 1991,1990 Carnegie Mellon University
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

#include <platforms.h>
#include <cpus.h>
#include <mach/boolean.h>
#include <mach/port.h>
#include <kern/thread.h>
#include <kern/task.h>

#include <ipc/ipc_port.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_right.h>
#include <ipc/ipc_object.h>
#include <ipc/ipc_entry.h>

#include <i386/thread.h>
#include <i386/io_port.h>
#include <i386/io_emulate.h>
#include <i386/iopb_entries.h>

int
emulate_io(
	struct i386_saved_state	*regs,
	int			opcode,
	int			io_port)
{
#if 1
	/* At the moment, we are not allowing I/O emulation 
	 *
 	 * FIXME - this should probably change due to 
	 * the Window Server's need to map I/O ports into its space.
	 */

	return EM_IO_ERROR;
#else
	thread_t	thread = current_thread();
	at386_io_lock_state();

	if (iopl_emulate(regs, opcode, io_port))
	    return EM_IO_DONE;

	if (iopb_check_mapping(thread, iopl_device))
	    return EM_IO_ERROR;

	/*
	 *	Check for send rights to the IOPL device port.
	 */
	if (iopl_device_port == IP_NULL)
	    return EM_IO_ERROR;
	{
	    ipc_space_t	space = current_space();
	    mach_port_name_t	name;
	    ipc_entry_t	entry;
	    boolean_t	has_rights = FALSE;
	    ipc_entry_bits_t *capability;

	    is_write_lock(space);
	    assert(space->is_active);

	    if (ipc_right_reverse(space, (ipc_object_t) iopl_device_port,
				  &name, &entry, &capability)) {
		/* iopl_device_port is locked and active */
		if (capability[space->server_id] & MACH_PORT_TYPE_SEND)
		    has_rights = TRUE;
		ip_unlock(iopl_device_port);
	    }

	    is_write_unlock(space);
	    if (!has_rights) {
		return EM_IO_ERROR;
	    }
	}

	/*
	 * Map the IOPL port set into the thread.
	 */

	if (i386_io_port_add(thread, iopl_device)
	    != KERN_SUCCESS) 
		return EM_IO_ERROR;

	/*
	 * Make the thread use its IO_TSS to get the IO permissions;
	 * it may not have had one before this.
	 */
	act_machine_switch_pcb(thread->top_act);

	return EM_IO_RETRY;
#endif
}
