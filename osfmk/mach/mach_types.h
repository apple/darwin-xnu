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
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
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
 *	File:	mach/mach_types.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1986
 *
 *	Mach external interface definitions.
 *
 */

#ifndef	_MACH_MACH_TYPES_H_
#define _MACH_MACH_TYPES_H_

#include <mach/host_info.h>
#include <mach/machine.h>
#include <mach/machine/vm_types.h>
#include <mach/memory_object_types.h>
#include <mach/exception_types.h>
#include <mach/port.h>
#include <mach/processor_info.h>
#include <mach/task_info.h>
#include <mach/task_policy.h>
#include <mach/task_special_ports.h>
#include <mach/thread_info.h>
#include <mach/thread_policy.h>
#include <mach/thread_special_ports.h>
#include <mach/thread_status.h>
#include <mach/time_value.h>
#include <mach/clock_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_inherit.h>
#include <mach/vm_behavior.h>
#include <mach/vm_prot.h>
#include <mach/vm_statistics.h>
#include <mach/vm_sync.h>
#include <mach/vm_types.h>
#include <mach/vm_region.h>
#include <mach/kmod.h>

#ifdef	KERNEL_PRIVATE

#include <mach/vm_param.h>

/*
 * If we are in the kernel, then pick up the kernel definitions for
 * the basic mach types.
 */
#include <kern/kern_types.h> 

extern ledger_t convert_port_to_ledger(ipc_port_t); /* JMM - Hack */

#else	/* !KERNEL_PRIVATE */

/*
 * If we are not in the kernel, then these will all be represented by
 * ports at user-space.
 */
typedef mach_port_t		task_t;
typedef mach_port_t		thread_t;
typedef mach_port_t		ipc_space_t;
typedef mach_port_t		host_t;
typedef mach_port_t		host_priv_t;
typedef mach_port_t		host_security_t;
typedef mach_port_t		processor_set_t;
typedef mach_port_t		processor_set_name_t;
typedef mach_port_t		processor_set_control_t;
typedef mach_port_t		processor_t;
typedef	mach_port_t		thread_act_t;
typedef mach_port_t		subsystem_t;
typedef mach_port_t		semaphore_t;
typedef mach_port_t		lock_set_t;
typedef mach_port_t		ledger_t;
typedef mach_port_t		alarm_t;
typedef mach_port_t		clock_serv_t;
typedef mach_port_t		clock_ctrl_t;
typedef mach_port_t		vm_map_t;
typedef mach_port_t		vm_map_copy_t;
typedef mach_port_t		vm_object_t;

#endif	/* !KERNEL_PRIVATE */


/*
 * JMM - These types are just hard-coded as ports for now
 */
typedef mach_port_t		clock_reply_t;
typedef mach_port_t		bootstrap_t;
typedef	mach_port_t		mem_entry_name_port_t;
typedef mach_port_t		exception_handler_t;
typedef exception_handler_t	*exception_handler_array_t;
typedef mach_port_t		vm_object_entry_t; 
typedef mach_port_t		vm_task_entry_t;
typedef mach_port_t		upl_object_entry_t;
typedef mach_port_t		io_master_t;
typedef mach_port_t		UNDServerRef;

/*
 * JMM - Mig doesn't translate the components of an array.
 * For example, Mig won't use the thread_t translations
 * to translate a thread_array_t argument.  So, these definitions
 * are not completely accurate at the moment for other kernel
 * components. MIG is being fixed.
 */
typedef task_t			*task_array_t;
typedef thread_t		*thread_array_t;
typedef processor_set_t		*processor_set_array_t;
typedef processor_set_t		*processor_set_name_array_t;
typedef processor_t		*processor_array_t;
typedef	thread_act_t		*thread_act_array_t;
typedef ledger_t		*ledger_array_t;

/*
 * However the real mach_types got declared, we also have to declare
 * types with "port" in the name for compatability with the way OSF
 * had declared the user interfaces at one point.  Someday these should
 * go away.
 */
typedef task_t			task_port_t;
typedef	task_array_t		task_port_array_t;
typedef thread_t		thread_port_t;
typedef	thread_array_t		thread_port_array_t;
typedef ipc_space_t		ipc_space_port_t;
typedef host_t			host_name_t;
typedef host_t			host_name_port_t;
typedef processor_set_t		processor_set_port_t;
typedef processor_set_t		processor_set_name_port_t;
typedef processor_set_array_t	processor_set_name_port_array_t;
typedef processor_set_t		processor_set_control_port_t;
typedef processor_t		processor_port_t;
typedef processor_array_t	processor_port_array_t;
typedef thread_act_t		thread_act_port_t;
typedef	thread_act_array_t	thread_act_port_array_t;
typedef semaphore_t		semaphore_port_t;
typedef lock_set_t		lock_set_port_t;
typedef ledger_t		ledger_port_t;
typedef ledger_array_t		ledger_port_array_t;
typedef alarm_t			alarm_port_t;
typedef clock_serv_t		clock_serv_port_t;
typedef clock_ctrl_t		clock_ctrl_port_t;
typedef vm_map_t		vm_map_port_t;
typedef vm_map_copy_t		vm_map_copy_port_t;
typedef exception_handler_t	exception_port_t;
typedef exception_handler_array_t exception_port_arrary_t;

#define TASK_NULL		((task_t) 0)
#define THREAD_NULL		((thread_t) 0)
#define HOST_NULL		((host_t) 0)
#define HOST_PRIV_NULL		((host_priv_t)0)
#define HOST_SECURITY_NULL	((host_security_t)0)
#define PROCESSOR_SET_NULL	((processor_set_t) 0)
#define PROCESSOR_NULL		((processor_t) 0)
#define THR_ACT_NULL 		((thread_act_t) 0)
#define SUBSYSTEM_NULL		((subsystem_t) 0)
#define SEMAPHORE_NULL		((semaphore_t) 0)
#define LOCK_SET_NULL		((lock_set_t) 0)
#define ALARM_NULL		((alarm_t) 0)
#define CLOCK_NULL		((clock_t) 0)
#define	VM_MAP_NULL		((vm_map_t) 0)
#define	VM_MAP_COPY_NULL	((vm_map_copy_t) 0)
#define VM_OBJECT_NULL		((vm_object_t) 0)
#define UND_SERVER_NULL		((UNDServerRef) 0)

typedef integer_t 		ledger_item_t;
typedef vm_offset_t		*emulation_vector_t;
typedef char			*user_subsystem_t;

/*
 *	Backwards compatibility, for those programs written
 *	before mach/{std,mach}_types.{defs,h} were set up.
 */
#include <mach/std_types.h>

#endif	/* _MACH_MACH_TYPES_H_ */
