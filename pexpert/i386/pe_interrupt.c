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
#include <pexpert/pexpert.h>
#include <pexpert/protos.h>
#include <machine/machine_routines.h>
#include <i386/mp.h>
#include <sys/kdebug.h>


void PE_incoming_interrupt(x86_saved_state_t *);


struct i386_interrupt_handler {
	IOInterruptHandler	handler;
	void			*nub;
	void			*target;
	void			*refCon;
};

typedef struct i386_interrupt_handler i386_interrupt_handler_t;

i386_interrupt_handler_t	PE_interrupt_handler;



void
PE_incoming_interrupt(x86_saved_state_t *state)
{
	i386_interrupt_handler_t	*vector;
	uint64_t			rip;
	int				interrupt;
	boolean_t			user_mode = FALSE;

        if (is_saved_state64(state) == TRUE) {
	        x86_saved_state64_t	*state64;

	        state64 = saved_state64(state);
		rip = state64->isf.rip;
		interrupt = state64->isf.trapno;
		user_mode = TRUE;
	} else {
	        x86_saved_state32_t	*state32;

	        state32 = saved_state32(state);
		if (state32->cs & 0x03)
		        user_mode = TRUE;
		rip = state32->eip;
		interrupt = state32->trapno;
	}

	KERNEL_DEBUG_CONSTANT(
		MACHDBG_CODE(DBG_MACH_EXCP_INTR, 0) | DBG_FUNC_START,
		interrupt, (unsigned int)rip, user_mode, 0, 0);

	vector = &PE_interrupt_handler;

	if (!lapic_interrupt(interrupt, state)) {
		vector->handler(vector->target, NULL, vector->nub, interrupt);
	}

	KERNEL_DEBUG_CONSTANT(
		MACHDBG_CODE(DBG_MACH_EXCP_INTR, 0) | DBG_FUNC_END,
		0, 0, 0, 0, 0);
}

void PE_install_interrupt_handler(void *nub,
				  __unused int source,
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
