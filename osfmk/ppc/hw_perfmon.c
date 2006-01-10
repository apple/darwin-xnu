/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#include <kern/thread.h>
#include <ppc/exception.h>
#include <ppc/savearea.h>
#include <ppc/hw_perfmon.h>
#include <ppc/hw_perfmon_mmcr.h>

decl_simple_lock_data(,hw_perfmon_lock)
static task_t hw_perfmon_owner = TASK_NULL;
static int hw_perfmon_thread_count = 0;

/* Notes:
 * -supervisor/user level filtering is unnecessary because of the way PMCs and MMCRs are context switched
 *  (can only count user events anyway)
 * -marked filtering is unnecssary because each thread has its own virtualized set of PMCs and MMCRs
 * -virtual counter PMI is passed up as a breakpoint exception
 */

int perfmon_init(void)
{
	simple_lock_init(&hw_perfmon_lock, FALSE);
	return KERN_SUCCESS;
}

/* PMC Facility Owner:
 * TASK_NULL - no one owns it
 * kernel_task - owned by hw_perfmon
 * other task - owned by another task
 */

int perfmon_acquire_facility(task_t task)
{
	kern_return_t retval = KERN_SUCCESS;
  
	simple_lock(&hw_perfmon_lock);
  
	if(hw_perfmon_owner==task) {
#ifdef HWPERFMON_DEBUG
		kprintf("perfmon_acquire_facility - ACQUIRED: already owner\n");
#endif
		retval = KERN_SUCCESS;
		/* already own it */
	} else if(hw_perfmon_owner==TASK_NULL) { /* no one owns it */
		hw_perfmon_owner = task;
		hw_perfmon_thread_count = 0;
#ifdef HWPERFMON_DEBUG
		kprintf("perfmon_acquire_facility - ACQUIRED: no current owner - made new owner\n");
#endif
		retval = KERN_SUCCESS;
	} else { /* someone already owns it */
		if(hw_perfmon_owner==kernel_task) {
			if(hw_perfmon_thread_count==0) { /* kernel owns it but no threads using it */
				hw_perfmon_owner = task;
				hw_perfmon_thread_count = 0;
#ifdef HWPERFMON_DEBUG
				kprintf("perfmon_acquire_facility - ACQUIRED: kernel is current owner but no threads using it\n");
#endif
				retval = KERN_SUCCESS;
			} else {
#ifdef HWPERFMON_DEBUG
				kprintf("perfmon_acquire_facility - DENIED: kernel is current owner and facility in use\n");
#endif
				retval = KERN_RESOURCE_SHORTAGE;
			}
		} else { /* non-kernel owner */
#ifdef HWPERFMON_DEBUG
			kprintf("perfmon_acquire_facility - DENIED: another active task owns the facility\n");
#endif
			retval = KERN_RESOURCE_SHORTAGE;
		}
	}
  
	simple_unlock(&hw_perfmon_lock);
	return retval;
}

int perfmon_release_facility(task_t task)
{
	kern_return_t retval = KERN_SUCCESS;
	task_t old_perfmon_owner = hw_perfmon_owner;
  
	simple_lock(&hw_perfmon_lock);
  
	if(task!=hw_perfmon_owner) {
		retval = KERN_NO_ACCESS;
	} else {
		if(old_perfmon_owner==kernel_task) {
			if(hw_perfmon_thread_count>0) {
#ifdef HWPERFMON_DEBUG
				kprintf("perfmon_release_facility - NOT RELEASED: kernel task is owner and has active perfmon threads\n");
#endif
				retval = KERN_NO_ACCESS;
			} else {
#ifdef HWPERFMON_DEBUG
				kprintf("perfmon_release_facility - RELEASED: kernel task was owner\n");
#endif
				hw_perfmon_owner = TASK_NULL;
				retval = KERN_SUCCESS;
			}
		} else {
#ifdef HWPERFMON_DEBUG
			kprintf("perfmon_release_facility - RELEASED: user task was owner\n");
#endif
			hw_perfmon_owner = TASK_NULL;
			retval = KERN_SUCCESS;
		}
	}

	simple_unlock(&hw_perfmon_lock);
	return retval;
}

int perfmon_enable(thread_t thread)
{
	struct savearea *sv = thread->machine.pcb;
	kern_return_t kr;
	kern_return_t retval = KERN_SUCCESS;
	int curPMC;
  
	if(thread->machine.specFlags & perfMonitor) {
		return KERN_SUCCESS; /* already enabled */
	} else if(perfmon_acquire_facility(kernel_task)!=KERN_SUCCESS) {
		return KERN_RESOURCE_SHORTAGE; /* facility is in use */
	} else { /* kernel_task owns the faciltity and this thread has not yet been counted */
		simple_lock(&hw_perfmon_lock);
		hw_perfmon_thread_count++;
		simple_unlock(&hw_perfmon_lock);
	}

	sv->save_mmcr1 = 0;
	sv->save_mmcr2 = 0;
	
	switch(PerProcTable[0].ppe_vaddr->cpu_subtype) {
		case CPU_SUBTYPE_POWERPC_750:
		case CPU_SUBTYPE_POWERPC_7400:
		case CPU_SUBTYPE_POWERPC_7450:
			{
				ppc32_mmcr0_reg_t mmcr0_reg;
		
				mmcr0_reg.value = 0;
				mmcr0_reg.field.disable_counters_always = TRUE;
				mmcr0_reg.field.disable_counters_supervisor = TRUE; /* no choice */
				sv->save_mmcr0 = mmcr0_reg.value;
			}
			break;
		case CPU_SUBTYPE_POWERPC_970:
			{
				ppc64_mmcr0_reg_t mmcr0_reg;
		
				mmcr0_reg.value = 0;
				mmcr0_reg.field.disable_counters_always = TRUE;
				mmcr0_reg.field.disable_counters_supervisor = TRUE; /* no choice */
				sv->save_mmcr0 = mmcr0_reg.value;
			}
			break;
		default:
			retval = KERN_FAILURE;
			break;
	}
  
	if(retval==KERN_SUCCESS) {
		for(curPMC=0; curPMC<MAX_CPUPMC_COUNT; curPMC++) {
			sv->save_pmc[curPMC] = 0;
			thread->machine.pmcovfl[curPMC] = 0;
		}
		thread->machine.perfmonFlags = 0;
		thread->machine.specFlags |= perfMonitor; /* enable perf monitor facility for this thread */
		if(thread==current_thread()) {
			getPerProc()->spcFlags |= perfMonitor; /* update per_proc */
		}
	}

#ifdef HWPERFMON_DEBUG  
	kprintf("perfmon_enable - mmcr0=0x%llx mmcr1=0x%llx mmcr2=0x%llx\n", sv->save_mmcr0, sv->save_mmcr1, sv->save_mmcr2);
#endif  

	return retval;
}

int perfmon_disable(thread_t thread)
{
	struct savearea *sv = thread->machine.pcb;
	int curPMC;
  
	if(!(thread->machine.specFlags & perfMonitor)) {
		return KERN_NO_ACCESS; /* not enabled */
	} else {
		simple_lock(&hw_perfmon_lock);
		hw_perfmon_thread_count--;
		simple_unlock(&hw_perfmon_lock);
		perfmon_release_facility(kernel_task); /* will release if hw_perfmon_thread_count is 0 */
	}
  
	thread->machine.specFlags &= ~perfMonitor; /* disable perf monitor facility for this thread */
	if(thread==current_thread()) {
		PerProcTable[cpu_number()].ppe_vaddr->spcFlags &= ~perfMonitor; /* update per_proc */
	}
	sv->save_mmcr0 = 0;
	sv->save_mmcr1 = 0;
	sv->save_mmcr2 = 0;
  
	for(curPMC=0; curPMC<MAX_CPUPMC_COUNT; curPMC++) {
		sv->save_pmc[curPMC] = 0;
		thread->machine.pmcovfl[curPMC] = 0;
		thread->machine.perfmonFlags = 0;
	}
  
#ifdef HWPERFMON_DEBUG
	kprintf("perfmon_disable - mmcr0=0x%llx mmcr1=0x%llx mmcr2=0x%llx\n", sv->save_mmcr0, sv->save_mmcr1, sv->save_mmcr2);
#endif  

	return KERN_SUCCESS;
}

int perfmon_clear_counters(thread_t thread)
{
	struct savearea *sv = thread->machine.pcb;
	int curPMC;

#ifdef HWPERFMON_DEBUG
	kprintf("perfmon_clear_counters (CPU%d)\n", cpu_number());
#endif  

	/* clear thread copy */
	for(curPMC=0; curPMC<MAX_CPUPMC_COUNT; curPMC++) {
		sv->save_pmc[curPMC] = 0;
		thread->machine.pmcovfl[curPMC] = 0;
	}
  
	return KERN_SUCCESS;
}

int perfmon_write_counters(thread_t thread, uint64_t *pmcs)
{
	struct savearea *sv = thread->machine.pcb;
	int curPMC;
  
#ifdef HWPERFMON_DEBUG
	kprintf("perfmon_write_counters (CPU%d): mmcr0 = %016llX, pmc1=%llX pmc2=%llX pmc3=%llX pmc4=%llX pmc5=%llX pmc6=%llX pmc7=%llX pmc8=%llX\n", cpu_number(), sv->save_mmcr0, pmcs[PMC_1], pmcs[PMC_2], pmcs[PMC_3], pmcs[PMC_4], pmcs[PMC_5], pmcs[PMC_6], pmcs[PMC_7], pmcs[PMC_8]);
#endif  

	/* update thread copy */
	for(curPMC=0; curPMC<MAX_CPUPMC_COUNT; curPMC++) {
		sv->save_pmc[curPMC] = pmcs[curPMC] & 0x7FFFFFFF;
		thread->machine.pmcovfl[curPMC] = (pmcs[curPMC]>>31) & 0xFFFFFFFF;
	}
  
	return KERN_SUCCESS;
}

int perfmon_read_counters(thread_t thread, uint64_t *pmcs)
{
	struct savearea *sv = thread->machine.pcb;
	int curPMC;
  
	/* retrieve from thread copy */
	for(curPMC=0; curPMC<MAX_CPUPMC_COUNT; curPMC++) {
		pmcs[curPMC] = thread->machine.pmcovfl[curPMC]; 
		pmcs[curPMC] = pmcs[curPMC]<<31;
		pmcs[curPMC] |= (sv->save_pmc[curPMC] & 0x7FFFFFFF);
	}

	/* zero any unused counters on this platform */
	switch(PerProcTable[0].ppe_vaddr->cpu_subtype) {
		case CPU_SUBTYPE_POWERPC_750:
		case CPU_SUBTYPE_POWERPC_7400:
		case CPU_SUBTYPE_POWERPC_7450:
			pmcs[PMC_7] = 0;
			pmcs[PMC_8] = 0;
			break;
		default:
			break;
	}

#ifdef HWPERFMON_DEBUG
	kprintf("perfmon_read_counters (CPU%d): mmcr0 = %016llX pmc1=%llX pmc2=%llX pmc3=%llX pmc4=%llX pmc5=%llX pmc6=%llX pmc7=%llX pmc8=%llX\n", cpu_number(), sv->save_mmcr0, pmcs[PMC_1], pmcs[PMC_2], pmcs[PMC_3], pmcs[PMC_4], pmcs[PMC_5], pmcs[PMC_6], pmcs[PMC_7], pmcs[PMC_8]);
#endif  

	return KERN_SUCCESS;
}

int perfmon_start_counters(thread_t thread)
{
	struct savearea *sv = thread->machine.pcb;
	kern_return_t retval = KERN_SUCCESS;

	switch(PerProcTable[0].ppe_vaddr->cpu_subtype) {
		case CPU_SUBTYPE_POWERPC_750:
		case CPU_SUBTYPE_POWERPC_7400:
			{
				ppc32_mmcr0_reg_t mmcr0_reg;
				mmcr0_reg.value = sv->save_mmcr0;
				mmcr0_reg.field.disable_counters_always = FALSE;
				/* XXXXX PMI broken on 750, 750CX, 750FX, 7400 and 7410 v1.2 and earlier XXXXX */
				mmcr0_reg.field.on_pmi_stop_counting = FALSE;
				mmcr0_reg.field.enable_pmi = FALSE; 
				mmcr0_reg.field.enable_pmi_on_pmc1 = FALSE;
				mmcr0_reg.field.enable_pmi_on_pmcn = FALSE;
				sv->save_mmcr0 = mmcr0_reg.value;
			}
			break;
		case CPU_SUBTYPE_POWERPC_7450:
			{
				ppc32_mmcr0_reg_t mmcr0_reg;
				mmcr0_reg.value = sv->save_mmcr0;
				mmcr0_reg.field.disable_counters_always = FALSE;
				mmcr0_reg.field.on_pmi_stop_counting = TRUE;
				mmcr0_reg.field.enable_pmi = TRUE;
				mmcr0_reg.field.enable_pmi_on_pmc1 = TRUE;
				mmcr0_reg.field.enable_pmi_on_pmcn = TRUE;
				sv->save_mmcr0 = mmcr0_reg.value;
			}
			break;
		case CPU_SUBTYPE_POWERPC_970:
			{
				ppc64_mmcr0_reg_t mmcr0_reg;
				mmcr0_reg.value = sv->save_mmcr0;
				mmcr0_reg.field.disable_counters_always = FALSE;
				mmcr0_reg.field.on_pmi_stop_counting = TRUE;
				mmcr0_reg.field.enable_pmi = TRUE;
				mmcr0_reg.field.enable_pmi_on_pmc1 = TRUE;
				mmcr0_reg.field.enable_pmi_on_pmcn = TRUE;
				sv->save_mmcr0 = mmcr0_reg.value;
			}
			break;
		default:
			retval = KERN_FAILURE;
			break;
	}

#ifdef HWPERFMON_DEBUG
	kprintf("perfmon_start_counters (CPU%d) - mmcr0=0x%llx mmcr1=0x%llx mmcr2=0x%llx\n", cpu_number(), sv->save_mmcr0, sv->save_mmcr1, sv->save_mmcr2);
#endif

	return retval;
}

int perfmon_stop_counters(thread_t thread)
{
	struct savearea *sv = thread->machine.pcb;
	kern_return_t retval = KERN_SUCCESS;

	switch(PerProcTable[0].ppe_vaddr->cpu_subtype) {
		case CPU_SUBTYPE_POWERPC_750:
		case CPU_SUBTYPE_POWERPC_7400:
		case CPU_SUBTYPE_POWERPC_7450:
			{
				ppc32_mmcr0_reg_t mmcr0_reg;
				mmcr0_reg.value = sv->save_mmcr0;
				mmcr0_reg.field.disable_counters_always = TRUE;
				sv->save_mmcr0 = mmcr0_reg.value;
			}
			break;
		case CPU_SUBTYPE_POWERPC_970:
			{
				ppc64_mmcr0_reg_t mmcr0_reg;
				mmcr0_reg.value = sv->save_mmcr0;
				mmcr0_reg.field.disable_counters_always = TRUE;
				sv->save_mmcr0 = mmcr0_reg.value;
			}
			break;
		default:
			retval = KERN_FAILURE;
			break;
	}

#ifdef HWPERFMON_DEBUG
	kprintf("perfmon_stop_counters (CPU%d) - mmcr0=0x%llx mmcr1=0x%llx mmcr2=0x%llx\n", cpu_number(), sv->save_mmcr0, sv->save_mmcr1, sv->save_mmcr2);
#endif

	return retval;
}

int perfmon_set_event(thread_t thread, int pmc, int event)
{
	struct savearea *sv = thread->machine.pcb;
	kern_return_t retval = KERN_SUCCESS;

#ifdef HWPERFMON_DEBUG
	kprintf("perfmon_set_event b4 (CPU%d) - pmc=%d, event=%d - mmcr0=0x%llx mmcr1=0x%llx mmcr2=0x%llx\n", cpu_number(), pmc, event, sv->save_mmcr0, sv->save_mmcr1, sv->save_mmcr2);
#endif
 
	switch(PerProcTable[0].ppe_vaddr->cpu_subtype) {
		case CPU_SUBTYPE_POWERPC_750:
		case CPU_SUBTYPE_POWERPC_7400:
			{
				ppc32_mmcr0_reg_t mmcr0_reg;
				ppc32_mmcr1_reg_t mmcr1_reg;
		
				mmcr0_reg.value = sv->save_mmcr0;
				mmcr1_reg.value = sv->save_mmcr1;
		
				switch(pmc) {
					case PMC_1:
						mmcr0_reg.field.pmc1_event = event;
						sv->save_mmcr0 = mmcr0_reg.value;
						break;
					case PMC_2:
						mmcr0_reg.field.pmc2_event = event;
						sv->save_mmcr0 = mmcr0_reg.value;
						break;
					case PMC_3:
						mmcr1_reg.field.pmc3_event = event;
						sv->save_mmcr1 = mmcr1_reg.value;
						break;
					case PMC_4:
						mmcr1_reg.field.pmc4_event = event;
						sv->save_mmcr1 = mmcr1_reg.value;
						break;
					default:
						retval = KERN_FAILURE;
						break;
				}
			}
			break;
		case CPU_SUBTYPE_POWERPC_7450:
			{
				ppc32_mmcr0_reg_t mmcr0_reg;
				ppc32_mmcr1_reg_t mmcr1_reg;

				mmcr0_reg.value = sv->save_mmcr0;
				mmcr1_reg.value = sv->save_mmcr1;
 
				switch(pmc) {
					case PMC_1:
						mmcr0_reg.field.pmc1_event = event;
						sv->save_mmcr0 = mmcr0_reg.value;
						break;
					case PMC_2:
						mmcr0_reg.field.pmc2_event = event;
						sv->save_mmcr0 = mmcr0_reg.value;
						break;
					case PMC_3:
						mmcr1_reg.field.pmc3_event = event;
						sv->save_mmcr1 = mmcr1_reg.value;
						break;
					case PMC_4:
						mmcr1_reg.field.pmc4_event = event;
						sv->save_mmcr1 = mmcr1_reg.value;
						break;
					case PMC_5:
						mmcr1_reg.field.pmc5_event = event;
						sv->save_mmcr1 = mmcr1_reg.value;
						break;
					case PMC_6:
						mmcr1_reg.field.pmc6_event = event;
						sv->save_mmcr1 = mmcr1_reg.value;
						break;
					default:
						retval = KERN_FAILURE;
						break;
				}
			}
			break;
		case CPU_SUBTYPE_POWERPC_970:
			{
				ppc64_mmcr0_reg_t mmcr0_reg;
				ppc64_mmcr1_reg_t mmcr1_reg;
	  
				mmcr0_reg.value = sv->save_mmcr0;
				mmcr1_reg.value = sv->save_mmcr1;
	  
				switch(pmc) {
					case PMC_1:
						mmcr0_reg.field.pmc1_event = event;
						sv->save_mmcr0 = mmcr0_reg.value;
						break;
					case PMC_2:
						mmcr0_reg.field.pmc2_event = event;
						sv->save_mmcr0 = mmcr0_reg.value;
						break;
					case PMC_3:
						mmcr1_reg.field.pmc3_event = event;
						sv->save_mmcr1 = mmcr1_reg.value;
						break;
					case PMC_4:
						mmcr1_reg.field.pmc4_event = event;
						sv->save_mmcr1 = mmcr1_reg.value;
						break;
					case PMC_5:
						mmcr1_reg.field.pmc5_event = event;
						sv->save_mmcr1 = mmcr1_reg.value;
						break;
					case PMC_6:
						mmcr1_reg.field.pmc6_event = event;
						sv->save_mmcr1 = mmcr1_reg.value;
						break;
					case PMC_7:
						mmcr1_reg.field.pmc7_event = event;
						sv->save_mmcr1 = mmcr1_reg.value;
						break;
					case PMC_8:
						mmcr1_reg.field.pmc8_event = event;
						sv->save_mmcr1 = mmcr1_reg.value;
						break;
					default:
						retval = KERN_FAILURE;
						break;
				}
			}
			break;
		default:
			retval = KERN_FAILURE;
			break;
	}

#ifdef HWPERFMON_DEBUG
	kprintf("perfmon_set_event (CPU%d) - pmc=%d, event=%d - mmcr0=0x%llx mmcr1=0x%llx mmcr2=0x%llx\n", cpu_number(), pmc, event, sv->save_mmcr0, sv->save_mmcr1, sv->save_mmcr2);
#endif

	return retval;
}

int perfmon_set_event_func(thread_t thread, uint32_t f)
{
	struct savearea *sv = thread->machine.pcb;
	kern_return_t retval = KERN_SUCCESS;

#ifdef HWPERFMON_DEBUG
	kprintf("perfmon_set_event_func - func=%s\n", 
		   f==PPC_PERFMON_FUNC_FPU ? "FUNC" :
		   f==PPC_PERFMON_FUNC_ISU ? "ISU" :
		   f==PPC_PERFMON_FUNC_IFU ? "IFU" :
		   f==PPC_PERFMON_FUNC_VMX ? "VMX" :
		   f==PPC_PERFMON_FUNC_IDU ? "IDU" :
		   f==PPC_PERFMON_FUNC_GPS ? "GPS" :
		   f==PPC_PERFMON_FUNC_LSU0 ? "LSU0" :
		   f==PPC_PERFMON_FUNC_LSU1A ? "LSU1A" :
		   f==PPC_PERFMON_FUNC_LSU1B ? "LSU1B" :
		   f==PPC_PERFMON_FUNC_SPECA ? "SPECA" :
		   f==PPC_PERFMON_FUNC_SPECB ? "SPECB" :
		   f==PPC_PERFMON_FUNC_SPECC ? "SPECC" :
		   "UNKNOWN");
#endif /* HWPERFMON_DEBUG */

	switch(PerProcTable[0].ppe_vaddr->cpu_subtype) {
		case CPU_SUBTYPE_POWERPC_750:
		case CPU_SUBTYPE_POWERPC_7400:
		case CPU_SUBTYPE_POWERPC_7450:
			retval = KERN_FAILURE; /* event functional unit only applies to 970 */
			break;
		case CPU_SUBTYPE_POWERPC_970:
			{
				ppc64_mmcr1_reg_t mmcr1_reg;
				ppc_func_unit_t func_unit;

				func_unit.value = f;
				mmcr1_reg.value = sv->save_mmcr1;

				mmcr1_reg.field.ttm0_select = func_unit.field.TTM0SEL;
				mmcr1_reg.field.ttm1_select = func_unit.field.TTM1SEL;
				mmcr1_reg.field.ttm2_select = 0; /* not used */
				mmcr1_reg.field.ttm3_select = func_unit.field.TTM3SEL;
				mmcr1_reg.field.speculative_event = func_unit.field.SPECSEL;
				mmcr1_reg.field.lane0_select = func_unit.field.TD_CP_DBGxSEL;
				mmcr1_reg.field.lane1_select = func_unit.field.TD_CP_DBGxSEL;
				mmcr1_reg.field.lane2_select = func_unit.field.TD_CP_DBGxSEL;
				mmcr1_reg.field.lane3_select = func_unit.field.TD_CP_DBGxSEL;

				sv->save_mmcr1 = mmcr1_reg.value;
			}
			break;
		default:
			retval = KERN_FAILURE;
			break;
	}

	return retval;
}

int perfmon_set_threshold(thread_t thread, int threshold)
{
	struct savearea *sv = thread->machine.pcb;
	kern_return_t retval = KERN_SUCCESS;

	switch(PerProcTable[0].ppe_vaddr->cpu_subtype) {
		case CPU_SUBTYPE_POWERPC_750:
			{
				ppc32_mmcr0_reg_t mmcr0_reg;

				mmcr0_reg.value = sv->save_mmcr0;

				if(threshold>63) { /* no multiplier on 750 */
					int newThreshold = 63;
#ifdef HWPERFMON_DEBUG
					kprintf("perfmon_set_threshold - WARNING: supplied threshold (%d) exceeds max threshold value - clamping to %d\n", threshold, newThreshold);
#endif
					threshold = newThreshold;
				}
				mmcr0_reg.field.threshold_value = threshold;

				sv->save_mmcr0 = mmcr0_reg.value;
			}
			break;

		case CPU_SUBTYPE_POWERPC_7400:
		case CPU_SUBTYPE_POWERPC_7450:
			{
				ppc32_mmcr0_reg_t mmcr0_reg;
				ppc32_mmcr2_reg_t mmcr2_reg;

				mmcr0_reg.value = sv->save_mmcr0;
				mmcr2_reg.value = sv->save_mmcr2;

				if(threshold<=(2*63)) { /* 2x multiplier */
					if(threshold%2 != 0) {
						int newThreshold = 2*(threshold/2);
#ifdef HWPERFMON_DEBUG
						kprintf("perfmon_set_threshold - WARNING: supplied threshold (%d) is not evenly divisible by 2x multiplier - using threshold of %d instead\n", threshold, newThreshold);
#endif
						threshold = newThreshold;
					}
					mmcr2_reg.field.threshold_multiplier = 0;
				} else if(threshold<=(32*63)) { /* 32x multiplier */
					if(threshold%32 != 0) {
						int newThreshold = 32*(threshold/32);
#ifdef HWPERFMON_DEBUG
						kprintf("perfmon_set_threshold - WARNING: supplied threshold (%d) is not evenly divisible by 32x multiplier - using threshold of %d instead\n", threshold, newThreshold);
#endif
						threshold = newThreshold;
					}
					mmcr2_reg.field.threshold_multiplier = 1;
				} else {
					int newThreshold = 32*63;
#ifdef HWPERFMON_DEBUG
					kprintf("perfmon_set_threshold - WARNING: supplied threshold (%d) exceeds max threshold value - clamping to %d\n", threshold, newThreshold);
#endif
					threshold = newThreshold;
					mmcr2_reg.field.threshold_multiplier = 1;
				}
				mmcr0_reg.field.threshold_value = threshold;

				sv->save_mmcr0 = mmcr0_reg.value;
				sv->save_mmcr2 = mmcr2_reg.value;

			}
			break;
		case CPU_SUBTYPE_POWERPC_970:
			{
				ppc64_mmcr0_reg_t mmcr0_reg;

				mmcr0_reg.value = sv->save_mmcr0;

				if(threshold>63) { /* multiplier is in HID1 on 970 - not context switching HID1 so always 1x */
					int newThreshold = 63;
#ifdef HWPERFMON_DEBUG
					kprintf("perfmon_set_threshold - WARNING: supplied threshold (%d) exceeds max threshold value - clamping to %d\n", threshold, newThreshold);
#endif
					threshold = newThreshold;
				}
				mmcr0_reg.field.threshold_value = threshold;

				sv->save_mmcr0 = mmcr0_reg.value;
			}
			break;
		default:
			retval = KERN_FAILURE;
			break;
	}

#ifdef HWPERFMON_DEBUG
	kprintf("perfmon_set_threshold - threshold=%d - mmcr0=0x%llx mmcr1=0x%llx mmcr2=0x%llx\n", threshold, sv->save_mmcr0, sv->save_mmcr1, sv->save_mmcr2);
#endif

	return retval;
}

int perfmon_set_tbsel(thread_t thread, int tbsel)
{
	struct savearea *sv = thread->machine.pcb;
	kern_return_t retval = KERN_SUCCESS;

	switch(PerProcTable[0].ppe_vaddr->cpu_subtype) {
		case CPU_SUBTYPE_POWERPC_750:
		case CPU_SUBTYPE_POWERPC_7400:
		case CPU_SUBTYPE_POWERPC_7450:
			{
				ppc32_mmcr0_reg_t mmcr0_reg;

				mmcr0_reg.value = sv->save_mmcr0;
				switch(tbsel) {
					case 0x0:
					case 0x1:
					case 0x2:
					case 0x3:
						mmcr0_reg.field.timebase_bit_selector = tbsel;
						break;
					default:
						retval = KERN_FAILURE;
				}
				sv->save_mmcr0 = mmcr0_reg.value;
			}
			break;
		case CPU_SUBTYPE_POWERPC_970:
			{
				ppc64_mmcr0_reg_t mmcr0_reg;

				mmcr0_reg.value = sv->save_mmcr0;
				switch(tbsel) {
					case 0x0:
					case 0x1:
					case 0x2:
					case 0x3:
						mmcr0_reg.field.timebase_bit_selector = tbsel;
						break;
					default:
						retval = KERN_FAILURE;
				}
				sv->save_mmcr0 = mmcr0_reg.value;
			}
			break;
		default:
			retval = KERN_FAILURE;
			break;
	}

#ifdef HWPERFMON_DEBUG
	kprintf("perfmon_set_tbsel - tbsel=%d - mmcr0=0x%llx mmcr1=0x%llx mmcr2=0x%llx\n", tbsel, sv->save_mmcr0, sv->save_mmcr1, sv->save_mmcr2);
#endif

	return retval;
}

int perfmon_control(struct savearea *ssp)
{
	mach_port_t thr_port = CAST_DOWN(mach_port_t, ssp->save_r3); 
	int action = (int)ssp->save_r4;
	int pmc = (int)ssp->save_r5;
	int val = (int)ssp->save_r6;
	uint64_t *usr_pmcs_p = CAST_DOWN(uint64_t *, ssp->save_r7);
	thread_t thread = THREAD_NULL;
	uint64_t kern_pmcs[MAX_CPUPMC_COUNT];
	kern_return_t retval = KERN_SUCCESS;
	int error;  
	boolean_t oldlevel;

	thread = (thread_t) port_name_to_thread(thr_port); // convert user space thread port name to a thread_t
	if(!thread) {
		ssp->save_r3 = KERN_INVALID_ARGUMENT;
		return 1;  /* Return and check for ASTs... */
	}

	if(thread!=current_thread()) {
		thread_suspend(thread);
	}

#ifdef HWPERFMON_DEBUG
	//  kprintf("perfmon_control: action=0x%x pmc=%d val=%d pmcs=0x%x\n", action, pmc, val, usr_pmcs_p);
#endif  

	oldlevel = ml_set_interrupts_enabled(FALSE);
  
	/* individual actions which do not require perfmon facility to be enabled */
	if(action==PPC_PERFMON_DISABLE) {
		retval = perfmon_disable(thread);
	}
	else if(action==PPC_PERFMON_ENABLE) {
		retval = perfmon_enable(thread);
	}
  
	else { /* individual actions which do require perfmon facility to be enabled */
		if(!(thread->machine.specFlags & perfMonitor)) { /* perfmon not enabled */
#ifdef HWPERFMON_DEBUG
			kprintf("perfmon_control: ERROR - perfmon not enabled for this thread\n");
#endif
			retval = KERN_NO_ACCESS;
			goto perfmon_return;
		}
	
		if(action==PPC_PERFMON_SET_EVENT) {
			retval = perfmon_set_event(thread, pmc, val);
		}
		else if(action==PPC_PERFMON_SET_THRESHOLD) {
			retval = perfmon_set_threshold(thread, val);
		}
		else if(action==PPC_PERFMON_SET_TBSEL) {
			retval = perfmon_set_tbsel(thread, val);
		}
		else if(action==PPC_PERFMON_SET_EVENT_FUNC) {
			retval = perfmon_set_event_func(thread, val);
		}
		else if(action==PPC_PERFMON_ENABLE_PMI_BRKPT) {
			if(val) {
				thread->machine.perfmonFlags |= PERFMONFLAG_BREAKPOINT_FOR_PMI;
			} else {
				thread->machine.perfmonFlags &= ~PERFMONFLAG_BREAKPOINT_FOR_PMI;
			}
			retval = KERN_SUCCESS;
		}
	
		/* combinable actions */
		else {
			if(action & PPC_PERFMON_STOP_COUNTERS) {
				error = perfmon_stop_counters(thread);
				if(error!=KERN_SUCCESS) {
					retval = error;
					goto perfmon_return;
				}
			}
			if(action & PPC_PERFMON_CLEAR_COUNTERS) {
				error = perfmon_clear_counters(thread);
				if(error!=KERN_SUCCESS) {
					retval = error;
					goto perfmon_return;
				}
			}
			if(action & PPC_PERFMON_WRITE_COUNTERS) {
				if(error = copyin(CAST_USER_ADDR_T(usr_pmcs_p), (void *)kern_pmcs, MAX_CPUPMC_COUNT*sizeof(uint64_t))) {
					retval = error;
					goto perfmon_return;
				}
				error = perfmon_write_counters(thread, kern_pmcs);
				if(error!=KERN_SUCCESS) {
					retval = error;
					goto perfmon_return;
				}
			}
			if(action & PPC_PERFMON_READ_COUNTERS) {
				error = perfmon_read_counters(thread, kern_pmcs);
				if(error!=KERN_SUCCESS) {
					retval = error;
					goto perfmon_return;
				}
				if(error = copyout((void *)kern_pmcs, CAST_USER_ADDR_T(usr_pmcs_p), MAX_CPUPMC_COUNT*sizeof(uint64_t))) {
					retval = error;
					goto perfmon_return;
				}
			}
			if(action & PPC_PERFMON_START_COUNTERS) {
				error = perfmon_start_counters(thread);
				if(error!=KERN_SUCCESS) {
					retval = error;
					goto perfmon_return;
				}
			}
		}
	}
  
 perfmon_return:
	ml_set_interrupts_enabled(oldlevel);

#ifdef HWPERFMON_DEBUG
	kprintf("perfmon_control (CPU%d): mmcr0 = %016llX, pmc1=%X pmc2=%X pmc3=%X pmc4=%X pmc5=%X pmc6=%X pmc7=%X pmc8=%X\n", cpu_number(), ssp->save_mmcr0, ssp->save_pmc[PMC_1], ssp->save_pmc[PMC_2], ssp->save_pmc[PMC_3], ssp->save_pmc[PMC_4], ssp->save_pmc[PMC_5], ssp->save_pmc[PMC_6], ssp->save_pmc[PMC_7], ssp->save_pmc[PMC_8]);
#endif  
 
	if(thread!=current_thread()) {
		thread_resume(thread);
	}

#ifdef HWPERFMON_DEBUG
	if(retval!=KERN_SUCCESS) {
		kprintf("perfmon_control - ERROR: retval=%d\n", retval);
	}
#endif /* HWPERFMON_DEBUG */

	ssp->save_r3 = retval;
	return 1;  /* Return and check for ASTs... */
}

int perfmon_handle_pmi(struct savearea *ssp)
{
	int curPMC;
	kern_return_t retval = KERN_SUCCESS;
	thread_t thread = current_thread();

#ifdef HWPERFMON_DEBUG
		kprintf("perfmon_handle_pmi: got rupt\n");
#endif

	if(!(thread->machine.specFlags & perfMonitor)) { /* perfmon not enabled */
#ifdef HWPERFMON_DEBUG
		kprintf("perfmon_handle_pmi: ERROR - perfmon not enabled for this thread\n");
#endif
		return KERN_FAILURE;
	}
  
	for(curPMC=0; curPMC<MAX_CPUPMC_COUNT; curPMC++) {
		if(thread->machine.pcb->save_pmc[curPMC] & 0x80000000) {
			if(thread->machine.pmcovfl[curPMC]==0xFFFFFFFF && (thread->machine.perfmonFlags & PERFMONFLAG_BREAKPOINT_FOR_PMI)) {
				doexception(EXC_BREAKPOINT, EXC_PPC_PERFMON, (unsigned int)ssp->save_srr0); // pass up a breakpoint exception
				return KERN_SUCCESS;
			} else {
				thread->machine.pmcovfl[curPMC]++;
				thread->machine.pcb->save_pmc[curPMC] = 0;
			}
		}
	}
  
	if(retval==KERN_SUCCESS) {
		switch(PerProcTable[0].ppe_vaddr->cpu_subtype) {
			case CPU_SUBTYPE_POWERPC_7450:
				{
					ppc32_mmcr0_reg_t mmcr0_reg;
	
					mmcr0_reg.value = thread->machine.pcb->save_mmcr0;
					mmcr0_reg.field.disable_counters_always = FALSE;
					mmcr0_reg.field.enable_pmi = TRUE;
					thread->machine.pcb->save_mmcr0 = mmcr0_reg.value;
				}
				retval = KERN_SUCCESS;
				break;
			case CPU_SUBTYPE_POWERPC_970:
				{
					ppc64_mmcr0_reg_t mmcr0_reg;
	
					mmcr0_reg.value = thread->machine.pcb->save_mmcr0;
					mmcr0_reg.field.disable_counters_always = FALSE;
					mmcr0_reg.field.enable_pmi = TRUE;
					thread->machine.pcb->save_mmcr0 = mmcr0_reg.value;
				}
				retval = KERN_SUCCESS;
				break;
			default:
				retval = KERN_FAILURE;
				break;
		}
	}

	return retval;
}
