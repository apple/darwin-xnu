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
#include <pexpert/pexpert.h>
#include <pexpert/protos.h>
#include <machine/machine_routines.h>
#include <i386/machine_cpu.h>
#include <i386/mp.h>
#include <sys/kdebug.h>

struct i386_interrupt_handler {
	IOInterruptHandler	handler;
	void			*nub;
	void			*target;
	void			*refCon;
};

typedef struct i386_interrupt_handler i386_interrupt_handler_t;

i386_interrupt_handler_t	PE_interrupt_handler;

void PE_platform_interrupt_initialize(void)
{
}



void
PE_incoming_interrupt(int interrupt, void *state)
{
	i386_interrupt_handler_t	*vector;

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_INTR, 0) | DBG_FUNC_START,
			      0, ((unsigned int *)state)[5], 0, 0, 0);

	vector = &PE_interrupt_handler;

	switch (interrupt) {
	case APIC_ERROR_INTERRUPT:
	case SPURIOUS_INTERRUPT:
	case INTERPROCESS_INTERRUPT:
		lapic_interrupt(interrupt, state);
		break;
	default:
		vector->handler(vector->target, state, vector->nub, interrupt);
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_EXCP_INTR, 0) | DBG_FUNC_END,
	   0, 0, 0, 0, 0);
}

void PE_install_interrupt_handler(void *nub, int source,
				  void *target,
				  IOInterruptHandler handler,
				  void *refCon)
{
	i386_interrupt_handler_t	*vector;

	vector = &PE_interrupt_handler;

	/*vector->source = source; IGNORED */
	vector->handler = handler;
	vector->nub = nub;
	vector->target = target;
	vector->refCon = refCon;
}
