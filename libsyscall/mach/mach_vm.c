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

/*
 * Make sure we don't accidentally include the external definitions of
 * the routines we're interposing on below.
 */
#define _vm_map_user_
#define _mach_vm_user_
#include <mach/mach.h>
#include <mach/mach_traps.h>
#undef _vm_map_user_
#include <mach/vm_map_internal.h>
#undef _mach_vm_user_
#include <mach/mach_vm_internal.h>

kern_return_t
mach_vm_allocate(
		mach_port_name_t target,
		mach_vm_address_t *address,
		mach_vm_size_t size,
		int flags)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_vm_allocate_trap(target, address, size, flags);

	if (rv == MACH_SEND_INVALID_DEST)
		rv = _kernelrpc_mach_vm_allocate(target, address, size, flags);

	return (rv);
}

kern_return_t
mach_vm_deallocate(
	mach_port_name_t target,
	mach_vm_address_t address,
	mach_vm_size_t size)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_vm_deallocate_trap(target, address, size);

	if (rv == MACH_SEND_INVALID_DEST)
		rv = _kernelrpc_mach_vm_deallocate(target, address, size);

	return (rv);
}

kern_return_t
mach_vm_protect(
	mach_port_name_t task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	boolean_t set_maximum,
	vm_prot_t new_protection)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_vm_protect_trap(task, address, size, set_maximum,
		new_protection);

	if (rv == MACH_SEND_INVALID_DEST)
		rv = _kernelrpc_mach_vm_protect(task, address, size,
			set_maximum, new_protection);

	return (rv);
}

kern_return_t
vm_allocate(
	mach_port_name_t task,
	vm_address_t *address,
	vm_size_t size,
	int flags)
{
	kern_return_t rv;
	mach_vm_address_t mach_addr;

	mach_addr = (mach_vm_address_t)*address;
	rv = mach_vm_allocate(task, &mach_addr, size, flags);
#if defined(__LP64__)
	*address = mach_addr;
#else
	*address = (vm_address_t)(mach_addr & ((vm_address_t)-1));
#endif

	return (rv);
}

kern_return_t
vm_deallocate(
	mach_port_name_t task,
	vm_address_t address,
	vm_size_t size)
{
	kern_return_t rv;

	rv = mach_vm_deallocate(task, address, size);

	return (rv);
}

kern_return_t
vm_protect(
	mach_port_name_t task,
	vm_address_t address,
	vm_size_t size,
	boolean_t set_maximum,
	vm_prot_t new_protection)
{
	kern_return_t rv;

	rv = mach_vm_protect(task, address, size, set_maximum, new_protection);

	return (rv);
}
