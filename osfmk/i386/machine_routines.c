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
#include <i386/machine_routines.h>
#include <i386/io_map_entries.h>
#include <kern/cpu_data.h>

/* IO memory map services */

/* Map memory map IO space */
vm_offset_t ml_io_map(
	vm_offset_t phys_addr, 
	vm_size_t size)
{
	return(io_map(phys_addr,size));
}

/* boot memory allocation */
vm_offset_t ml_static_malloc(
	vm_size_t size)
{
	return((vm_offset_t)NULL);
}

vm_offset_t
ml_static_ptovirt(
	vm_offset_t paddr)
{
	return phystokv(paddr);
} 

void
ml_static_mfree(
        vm_offset_t vaddr,
        vm_size_t size)
{
	return;
}

/* virtual to physical on wired pages */
vm_offset_t ml_vtophys(
	vm_offset_t vaddr)
{
	return	kvtophys(vaddr);
}

/* Interrupt handling */

/* Get Interrupts Enabled */
boolean_t ml_get_interrupts_enabled(void)
{
  unsigned long flags;

  __asm__ volatile("pushf; popl	%0" :  "=r" (flags));
  return (flags & EFL_IF) != 0;
}

/* Set Interrupts Enabled */
boolean_t ml_set_interrupts_enabled(boolean_t enable)
{
  unsigned long flags;

  __asm__ volatile("pushf; popl	%0" :  "=r" (flags));

 if (enable)
	__asm__ volatile("sti");
  else
	__asm__ volatile("cli");

  return (flags & EFL_IF) != 0;
}

/* Check if running at interrupt context */
boolean_t ml_at_interrupt_context(void)
{
	return get_interrupt_level() != 0;
}

/* Generate a fake interrupt */
void ml_cause_interrupt(void)
{
	panic("ml_cause_interrupt not defined yet on Intel");
}

void ml_thread_policy(
	thread_t thread,
	unsigned policy_id,
	unsigned policy_info)
{
	return;
}

/* Initialize Interrupts */
void ml_install_interrupt_handler(
	void *nub,
	int source,
	void *target,
	IOInterruptHandler handler,
	void *refCon)  
{
	boolean_t current_state;

	current_state = ml_get_interrupts_enabled();

	PE_install_interrupt_handler(nub, source, target,
	                             (IOInterruptHandler) handler, refCon);

	(void) ml_set_interrupts_enabled(current_state);
}

void
machine_signal_idle(
        processor_t processor)
{
}

/* Stubs for pc tracing mechanism */

int *pc_trace_buf;
int pc_trace_cnt = 0;

int
set_be_bit()
{
  return(0);
}

int
clr_be_bit()
{
  return(0);
}

int
be_tracing()
{
  return(0);
}
