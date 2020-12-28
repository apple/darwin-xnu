/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
#include <pexpert/pexpert.h>
#include <pexpert/protos.h>
#include <machine/machine_routines.h>

#if CONFIG_DTRACE && DEVELOPMENT
#include <mach/sdt.h>
#endif

void PE_incoming_interrupt(int);


struct i386_interrupt_handler {
	IOInterruptHandler      handler;
	void                    *nub;
	void                    *target;
	void                    *refCon;
};

typedef struct i386_interrupt_handler i386_interrupt_handler_t;

i386_interrupt_handler_t        PE_interrupt_handler;



void
PE_incoming_interrupt(int interrupt)
{
	i386_interrupt_handler_t        *vector;

	vector = &PE_interrupt_handler;

#if CONFIG_DTRACE && DEVELOPMENT
	DTRACE_INT5(interrupt_start, void *, vector->nub, int, 0,
	    void *, vector->target, IOInterruptHandler, vector->handler,
	    void *, vector->refCon);
#endif

	vector->handler(vector->target, NULL, vector->nub, interrupt);

#if CONFIG_DTRACE && DEVELOPMENT
	DTRACE_INT5(interrupt_complete, void *, vector->nub, int, 0,
	    void *, vector->target, IOInterruptHandler, vector->handler,
	    void *, vector->refCon);
#endif
}

void
PE_install_interrupt_handler(void *nub,
    __unused int source,
    void *target,
    IOInterruptHandler handler,
    void *refCon)
{
	i386_interrupt_handler_t        *vector;

	vector = &PE_interrupt_handler;

	/*vector->source = source; IGNORED */
	vector->handler = handler;
	vector->nub = nub;
	vector->target = target;
	vector->refCon = refCon;
}
