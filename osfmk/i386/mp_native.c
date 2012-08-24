/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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

#include <mach/vm_types.h>
#include <i386/acpi.h> /* install_real_mode_bootstrap */
#include <i386/mp.h>
#include <i386/lapic.h> /* lapic_* functions */
#include <i386/machine_routines.h>
#include <i386/cpu_data.h>
#include <i386/pmap.h>

/* PAL-related routines */
void i386_cpu_IPI(int cpu);
boolean_t i386_smp_init(int nmi_vector, i386_intr_func_t nmi_handler, 
		int ipi_vector, i386_intr_func_t ipi_handler);
void i386_start_cpu(int lapic_id, int cpu_num);
void i386_send_NMI(int cpu);
void handle_pending_TLB_flushes(void);

extern void	slave_pstart(void);

#ifdef	MP_DEBUG
int	trappedalready = 0;	/* (BRINGUP) */
#endif	/* MP_DEBUG */

boolean_t
i386_smp_init(int nmi_vector, i386_intr_func_t nmi_handler, int ipi_vector, i386_intr_func_t ipi_handler)
{
	/* Local APIC? */
	if (!lapic_probe())
		return FALSE;

	lapic_init();
	lapic_configure();
	lapic_set_intr_func(nmi_vector,  nmi_handler);
	lapic_set_intr_func(ipi_vector, ipi_handler);

	install_real_mode_bootstrap(slave_pstart);

	return TRUE;
}

void
i386_start_cpu(int lapic_id, __unused int cpu_num )
{
	LAPIC_WRITE(ICRD, lapic_id << LAPIC_ICRD_DEST_SHIFT);
	LAPIC_WRITE(ICR, LAPIC_ICR_DM_INIT);
	delay(100);

	LAPIC_WRITE(ICRD, lapic_id << LAPIC_ICRD_DEST_SHIFT);
	LAPIC_WRITE(ICR, LAPIC_ICR_DM_STARTUP|(REAL_MODE_BOOTSTRAP_OFFSET>>12));
}

void
i386_send_NMI(int cpu)
{
	boolean_t state = ml_set_interrupts_enabled(FALSE);
	/* Program the interrupt command register */
	LAPIC_WRITE(ICRD, cpu_to_lapic[cpu] << LAPIC_ICRD_DEST_SHIFT);
	/* The vector is ignored in this case--the target CPU will enter on the
	 * NMI vector.
	 */
	LAPIC_WRITE(ICR, LAPIC_VECTOR(INTERPROCESSOR)|LAPIC_ICR_DM_NMI);
	(void) ml_set_interrupts_enabled(state);
}

void
handle_pending_TLB_flushes(void)
{
	volatile int	*my_word = &current_cpu_datap()->cpu_signals;

	if (i_bit(MP_TLB_FLUSH, my_word)  && (pmap_tlb_flush_timeout == FALSE)) {
		DBGLOG(cpu_handle, cpu_number(), MP_TLB_FLUSH);
		i_bit_clear(MP_TLB_FLUSH, my_word);
		pmap_update_interrupt();
	}
}

void
i386_cpu_IPI(int cpu)
{
#ifdef	MP_DEBUG
	if(cpu_datap(cpu)->cpu_signals & 6) {	/* (BRINGUP) */
		kprintf("i386_cpu_IPI: sending enter debugger signal (%08X) to cpu %d\n", cpu_datap(cpu)->cpu_signals, cpu);
	}
#endif	/* MP_DEBUG */

	lapic_send_ipi(cpu, LAPIC_VECTOR(INTERPROCESSOR));
}
