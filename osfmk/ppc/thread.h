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
 *	File:	machine/thread.h
 *
 *	This file contains the structure definitions for the thread
 *	state as applied to PPC processors.
 */

#ifndef	_PPC_THREAD_H_
#define _PPC_THREAD_H_

#include <mach/machine/vm_types.h>

/*
 * Return address of the function that called current function, given
 *	address of the first parameter of current function. We can't
 *      do it this way, since parameter was copied from a register
 *      into a local variable. Call an assembly sub-function to 
 *      return this.
 */

extern vm_offset_t getrpc(void);
#define	GET_RETURN_PC(addr)	getrpc()

#define STACK_IKS(stack)		\
	((vm_offset_t)(((vm_offset_t)stack)+KERNEL_STACK_SIZE)-FM_SIZE)

#define syscall_emulation_sync(task) /* do nothing */

/*
 * Defining this indicates that MD code will supply an exception()
 * routine, conformant with kern/exception.c (dependency alert!)
 * but which does wonderfully fast, machine-dependent magic.
 */

#define MACHINE_FAST_EXCEPTION 1

#endif	/* _PPC_THREAD_H_ */


