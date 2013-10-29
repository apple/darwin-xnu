/*
 * Copyright (c) 2011 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/mach_traps.h>
#include <mach/mach_vm_server.h>
#include <mach/mach_port_server.h>
#include <mach/vm_map.h>
#include <kern/task.h>
#include <kern/ipc_tt.h>
#include <vm/vm_protos.h>

int
_kernelrpc_mach_vm_allocate_trap(struct _kernelrpc_mach_vm_allocate_trap_args *args)
{
	mach_vm_offset_t addr;
	task_t task = port_name_to_task(args->target);
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	if (copyin(args->addr, (char *)&addr, sizeof (addr)))
		goto done;

	rv = mach_vm_allocate(task->map, &addr, args->size, args->flags);
	if (rv == KERN_SUCCESS)
		rv = copyout(&addr, args->addr, sizeof (addr));
	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}

int
_kernelrpc_mach_vm_deallocate_trap(struct _kernelrpc_mach_vm_deallocate_args *args)
{
	task_t task = port_name_to_task(args->target);
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	rv = mach_vm_deallocate(task->map, args->address, args->size);
	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}

int
_kernelrpc_mach_vm_protect_trap(struct _kernelrpc_mach_vm_protect_args *args)
{
	task_t task = port_name_to_task(args->target);
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	rv = mach_vm_protect(task->map, args->address, args->size,
	    args->set_maximum, args->new_protection);
	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}

int
_kernelrpc_mach_vm_map_trap(struct _kernelrpc_mach_vm_map_trap_args *args)
{
	mach_vm_offset_t addr;
	task_t task = port_name_to_task(args->target);
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	if (copyin(args->addr, (char *)&addr, sizeof (addr)))
		goto done;

	rv = mach_vm_map(task->map, &addr, args->size, args->mask, args->flags,
			IPC_PORT_NULL, 0, FALSE, args->cur_protection, VM_PROT_ALL,
			VM_INHERIT_DEFAULT);
	if (rv == KERN_SUCCESS)
		rv = copyout(&addr, args->addr, sizeof (addr));

done:
	if (task)
		task_deallocate(task);
	return (rv);
}

int
_kernelrpc_mach_port_allocate_trap(struct _kernelrpc_mach_port_allocate_args *args)
{
	task_t task = port_name_to_task(args->target);
	mach_port_name_t name;
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	rv = mach_port_allocate(task->itk_space, args->right, &name);
	if (rv == KERN_SUCCESS)
		rv = copyout(&name, args->name, sizeof (name));

	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}

int
_kernelrpc_mach_port_destroy_trap(struct _kernelrpc_mach_port_destroy_args *args)
{
	task_t task = port_name_to_task(args->target);
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	rv = mach_port_destroy(task->itk_space, args->name);
	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}

int
_kernelrpc_mach_port_deallocate_trap(struct _kernelrpc_mach_port_deallocate_args *args)
{
	task_t task = port_name_to_task(args->target);
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	rv = mach_port_deallocate(task->itk_space, args->name);
	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}

int
_kernelrpc_mach_port_mod_refs_trap(struct _kernelrpc_mach_port_mod_refs_args *args)
{
	task_t task = port_name_to_task(args->target);
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	rv = mach_port_mod_refs(task->itk_space, args->name, args->right, args->delta);
	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}


int
_kernelrpc_mach_port_move_member_trap(struct _kernelrpc_mach_port_move_member_args *args)
{
	task_t task = port_name_to_task(args->target);
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	rv = mach_port_move_member(task->itk_space, args->member, args->after);
	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}

int
_kernelrpc_mach_port_insert_right_trap(struct _kernelrpc_mach_port_insert_right_args *args)
{
	task_t task = port_name_to_task(args->target);
	ipc_port_t port;
	mach_msg_type_name_t disp;
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	rv = ipc_object_copyin(task->itk_space, args->poly, args->polyPoly,
	    (ipc_object_t *)&port);
	if (rv != KERN_SUCCESS)
		goto done;
	disp = ipc_object_copyin_type(args->polyPoly);

	rv = mach_port_insert_right(task->itk_space, args->name, port, disp);
	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}

int
_kernelrpc_mach_port_insert_member_trap(struct _kernelrpc_mach_port_insert_member_args *args)
{
	task_t task = port_name_to_task(args->target);
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	rv = mach_port_insert_member(task->itk_space, args->name, args->pset);
	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}


int
_kernelrpc_mach_port_extract_member_trap(struct _kernelrpc_mach_port_extract_member_args *args)
{
	task_t task = port_name_to_task(args->target);
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	rv = mach_port_extract_member(task->itk_space, args->name, args->pset);
	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}

int
_kernelrpc_mach_port_construct_trap(struct _kernelrpc_mach_port_construct_args *args)
{
	task_t task = port_name_to_task(args->target);
	mach_port_name_t name;
	int rv = MACH_SEND_INVALID_DEST;
	mach_port_options_t options;

	if (copyin(args->options, (char *)&options, sizeof (options))) {
		rv = MACH_SEND_INVALID_DATA;
		goto done;
	}

	if (task != current_task())
		goto done;

	rv = mach_port_construct(task->itk_space, &options, args->context, &name);
	if (rv == KERN_SUCCESS)
		rv = copyout(&name, args->name, sizeof (name));

done:
	if (task)
		task_deallocate(task);
	return (rv);
}

int
_kernelrpc_mach_port_destruct_trap(struct _kernelrpc_mach_port_destruct_args *args)
{
	task_t task = port_name_to_task(args->target);
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	rv = mach_port_destruct(task->itk_space, args->name, args->srdelta, args->guard);
	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}

int
_kernelrpc_mach_port_guard_trap(struct _kernelrpc_mach_port_guard_args *args)
{
	task_t task = port_name_to_task(args->target);
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	rv = mach_port_guard(task->itk_space, args->name, args->guard, args->strict);
	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}

int
_kernelrpc_mach_port_unguard_trap(struct _kernelrpc_mach_port_unguard_args *args)
{
	task_t task = port_name_to_task(args->target);
	int rv = MACH_SEND_INVALID_DEST;

	if (task != current_task())
		goto done;

	rv = mach_port_unguard(task->itk_space, args->name, args->guard);
	
done:
	if (task)
		task_deallocate(task);
	return (rv);
}

