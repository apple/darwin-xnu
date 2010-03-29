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

#include <mach/mach_types.h>

#include <ppc/machine_routines.h>
#include <ppc/cpu_internal.h>
#include <ppc/exception.h>
#include <ppc/io_map_entries.h>
#include <ppc/misc_protos.h>
#include <ppc/savearea.h>
#include <ppc/Firmware.h>
#include <ppc/pmap.h>
#include <ppc/mem.h>
#include <ppc/new_screen.h>
#include <ppc/proc_reg.h>
#include <ppc/machine_cpu.h> /* for cpu_signal_handler() */
#include <ppc/fpu_protos.h>
#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/machine.h>

#include <vm/vm_page.h>

unsigned int		LockTimeOut = 1250000000;
unsigned int		MutexSpin = 0;

static int max_cpus_initialized = 0;

uint32_t warFlags = 0;
#define warDisMBpoff	0x80000000
#define	MAX_CPUS_SET	0x01
#define	MAX_CPUS_WAIT	0x02

decl_simple_lock_data(, spsLock);
unsigned int spsLockInit = 0;

extern unsigned int hwllckPatch_isync;
extern unsigned int hwulckPatch_isync;
extern unsigned int hwulckbPatch_isync;
extern unsigned int hwlmlckPatch_isync;
extern unsigned int hwltlckPatch_isync;
extern unsigned int hwcsatomicPatch_isync;
extern unsigned int mlckePatch_isync;
extern unsigned int mlckPatch_isync;
extern unsigned int mltelckPatch_isync;
extern unsigned int mltlckPatch_isync;
extern unsigned int mulckePatch_isync;
extern unsigned int mulckPatch_isync;
extern unsigned int slckPatch_isync;
extern unsigned int stlckPatch_isync;
extern unsigned int sulckPatch_isync;
extern unsigned int rwlePatch_isync;
extern unsigned int rwlsPatch_isync;
extern unsigned int rwlsePatch_isync;
extern unsigned int rwlesPatch_isync;
extern unsigned int rwtlePatch_isync;
extern unsigned int rwtlsPatch_isync;
extern unsigned int rwldPatch_isync;
extern unsigned int hwulckPatch_eieio;
extern unsigned int mulckPatch_eieio;
extern unsigned int mulckePatch_eieio;
extern unsigned int sulckPatch_eieio;
extern unsigned int rwlesPatch_eieio;
extern unsigned int rwldPatch_eieio;

struct patch_up {
        unsigned int    *addr;
        unsigned int    data;
};

typedef struct patch_up patch_up_t;

patch_up_t patch_up_table[] = {
	{&hwllckPatch_isync,		0x60000000},
	{&hwulckPatch_isync,		0x60000000},
	{&hwulckbPatch_isync,		0x60000000},
	{&hwlmlckPatch_isync,		0x60000000},
	{&hwltlckPatch_isync,		0x60000000},
	{&hwcsatomicPatch_isync,	0x60000000},
	{&mlckePatch_isync,		0x60000000},
	{&mlckPatch_isync,		0x60000000},
	{&mltelckPatch_isync,		0x60000000},
	{&mltlckPatch_isync,		0x60000000},
	{&mulckePatch_isync,		0x60000000},
	{&mulckPatch_isync,		0x60000000},
	{&slckPatch_isync,		0x60000000},
	{&stlckPatch_isync,		0x60000000},
	{&sulckPatch_isync,		0x60000000},
	{&rwlePatch_isync,		0x60000000},
	{&rwlsPatch_isync,		0x60000000},
	{&rwlsePatch_isync,		0x60000000},
	{&rwlesPatch_isync,		0x60000000},
	{&rwtlePatch_isync,		0x60000000},
	{&rwtlsPatch_isync,		0x60000000},
	{&rwldPatch_isync,		0x60000000},
	{&hwulckPatch_eieio,		0x60000000},
	{&hwulckPatch_eieio,		0x60000000},
	{&mulckPatch_eieio,		0x60000000},
	{&mulckePatch_eieio,		0x60000000},
	{&sulckPatch_eieio,		0x60000000},
	{&rwlesPatch_eieio,		0x60000000},
	{&rwldPatch_eieio,		0x60000000},
	{NULL,				0x00000000}
};

extern int			forcenap;
extern boolean_t	pmap_initialized;

/* Map memory map IO space */
vm_offset_t 
ml_io_map(
	vm_offset_t phys_addr, 
	vm_size_t size)
{
	return(io_map(phys_addr,size,VM_WIMG_IO));
}


void ml_get_bouncepool_info(vm_offset_t *phys_addr, vm_size_t *size)
{
        *phys_addr = 0;
	*size      = 0;
}


/*
 *	Routine:        ml_static_malloc
 *	Function: 	static memory allocation
 */
vm_offset_t 
ml_static_malloc(
	vm_size_t size)
{
	vm_offset_t vaddr;

	if (pmap_initialized)
		return((vm_offset_t)NULL);
	else {
		vaddr = static_memory_end;
		static_memory_end = round_page(vaddr+size);
		return(vaddr);
	}
}

/*
 *	Routine:        ml_static_ptovirt
 *	Function:
 */
vm_offset_t
ml_static_ptovirt(
	vm_offset_t paddr)
{
	vm_offset_t vaddr;

	/* Static memory is map V=R */
	vaddr = paddr;
	if ( (vaddr < static_memory_end) && (pmap_extract(kernel_pmap, vaddr)==paddr) )
		return(vaddr);
	else
		return((vm_offset_t)NULL);
}

/*
 *	Routine:        ml_static_mfree
 *	Function:
 */
void
ml_static_mfree(
	vm_offset_t vaddr,
	vm_size_t size)
{
	vm_offset_t paddr_cur, vaddr_cur;

	for (vaddr_cur = round_page_32(vaddr);
	     vaddr_cur < trunc_page_32(vaddr+size);
	     vaddr_cur += PAGE_SIZE) {
		paddr_cur = pmap_extract(kernel_pmap, vaddr_cur);
		if (paddr_cur != (vm_offset_t)NULL) {
			vm_page_wire_count--;
			pmap_remove(kernel_pmap, (addr64_t)vaddr_cur, (addr64_t)(vaddr_cur+PAGE_SIZE));
			vm_page_create(paddr_cur>>12,(paddr_cur+PAGE_SIZE)>>12);
		}
	}
}

/*
 *	Routine:        ml_vtophys
 *	Function:	virtual to physical on static pages
 */
vm_offset_t ml_vtophys(
	vm_offset_t vaddr)
{
	return(pmap_extract(kernel_pmap, vaddr));
}

/*
 *	Routine:        ml_install_interrupt_handler
 *	Function:	Initialize Interrupt Handler
 */
void ml_install_interrupt_handler(
	void *nub,
	int source,
	void *target,
	IOInterruptHandler handler,
	void *refCon)
{
	struct per_proc_info	*proc_info;
	boolean_t		current_state;

	current_state = ml_get_interrupts_enabled();
	proc_info = getPerProc();

	proc_info->interrupt_nub     = nub;
	proc_info->interrupt_source  = source;
	proc_info->interrupt_target  = target;
	proc_info->interrupt_handler = handler;
	proc_info->interrupt_refCon  = refCon;

	proc_info->interrupts_enabled = TRUE;  
	(void) ml_set_interrupts_enabled(current_state);

	initialize_screen(NULL, kPEAcquireScreen);
}

/*
 *	Routine:        ml_nofault_copy
 *	Function:	Perform a physical mode copy if the source and
 *			destination have valid translations in the kernel pmap.
 *			If translations are present, they are assumed to
 *			be wired; i.e. no attempt is made to guarantee that the
 *			translations obtained remained valid for
 *			the duration of their use.
 */

vm_size_t ml_nofault_copy(
	vm_offset_t virtsrc, vm_offset_t virtdst, vm_size_t size)
{
	addr64_t cur_phys_dst, cur_phys_src;
	uint32_t count, pindex, nbytes = 0;

	while (size > 0) {
		if (!(cur_phys_src = kvtophys(virtsrc)))
			break;
		if (!(cur_phys_dst = kvtophys(virtdst)))
			break;
		if (!mapping_phys_lookup((cur_phys_src>>12), &pindex) ||
		    !mapping_phys_lookup((cur_phys_dst>>12), &pindex))
			break;
		count = PAGE_SIZE - (cur_phys_src & PAGE_MASK);
		if (count > (PAGE_SIZE - (cur_phys_dst & PAGE_MASK)))
			count = PAGE_SIZE - (cur_phys_dst & PAGE_MASK);
		if (count > size)
			count = size;

		bcopy_phys(cur_phys_src, cur_phys_dst, count);

		nbytes += count;
		virtsrc += count;
		virtdst += count;
		size -= count;
	}

	return nbytes;
}

/*
 *	Routine:        ml_init_interrupt
 *	Function:	Initialize Interrupts
 */
void ml_init_interrupt(void)
{
	boolean_t current_state;

	current_state = ml_get_interrupts_enabled();

	getPerProc()->interrupts_enabled = TRUE;  
	(void) ml_set_interrupts_enabled(current_state);
}

/*
 *	Routine:        ml_get_interrupts_enabled
 *	Function:	Get Interrupts Enabled
 */
boolean_t ml_get_interrupts_enabled(void)
{
	return((mfmsr() & MASK(MSR_EE)) != 0);
}

/*
 *	Routine:        ml_at_interrupt_context
 *	Function:	Check if running at interrupt context
 */
boolean_t ml_at_interrupt_context(void)
{
	boolean_t	ret;
	boolean_t	current_state;

	current_state = ml_set_interrupts_enabled(FALSE);
 	ret = (getPerProc()->istackptr == 0);	
	ml_set_interrupts_enabled(current_state);
	return(ret);
}

/*
 *	Routine:        ml_cause_interrupt
 *	Function:	Generate a fake interrupt
 */
void ml_cause_interrupt(void)
{
	CreateFakeIO();
}

/*
 *	Routine:        ml_thread_policy
 *	Function:
 */
void ml_thread_policy(
	thread_t thread,
__unused	unsigned policy_id,
	unsigned policy_info)
{
	if (policy_info & MACHINE_NETWORK_WORKLOOP) {
		spl_t		s = splsched();

		thread_lock(thread);

		set_priority(thread, thread->priority + 1);

		thread_unlock(thread);
		splx(s);
	}
}

/*
 *	Routine:        machine_signal_idle
 *	Function:
 */
void
machine_signal_idle(
	processor_t processor)
{
	struct per_proc_info	*proc_info;

	proc_info = PROCESSOR_TO_PER_PROC(processor);

	if (proc_info->pf.Available & (pfCanDoze|pfWillNap))
		(void)cpu_signal(proc_info->cpu_number, SIGPwake, 0, 0);
}

/*
 *	Routine:        ml_processor_register
 *	Function:
 */
kern_return_t
ml_processor_register(
	ml_processor_info_t 	*in_processor_info,
	processor_t				*processor_out,
	ipi_handler_t			*ipi_handler)
{
	struct per_proc_info	*proc_info;
	int						donap;
	boolean_t				current_state;
	boolean_t				boot_processor;

	if (in_processor_info->boot_cpu == FALSE) {
		if (spsLockInit == 0) {
			spsLockInit = 1;
			simple_lock_init(&spsLock, 0);
                }
		boot_processor = FALSE;
		proc_info = cpu_per_proc_alloc();
		if (proc_info == (struct per_proc_info *)NULL)
			return KERN_FAILURE;
		proc_info->pp_cbfr = console_per_proc_alloc(FALSE);
		if (proc_info->pp_cbfr == (void *)NULL)
			goto	processor_register_error;
	} else {
		boot_processor = TRUE;
		proc_info =  PerProcTable[master_cpu].ppe_vaddr;
	}

	proc_info->pp_chud = chudxnu_per_proc_alloc(boot_processor);
	if (proc_info->pp_chud == (void *)NULL)
		goto	processor_register_error;

	if (!boot_processor)
		if (cpu_per_proc_register(proc_info) != KERN_SUCCESS)
			goto	processor_register_error;

	proc_info->cpu_id = in_processor_info->cpu_id;
	proc_info->start_paddr = in_processor_info->start_paddr;
	if(in_processor_info->time_base_enable !=  (void(*)(cpu_id_t, boolean_t ))NULL)
		proc_info->time_base_enable = in_processor_info->time_base_enable;
	else
		proc_info->time_base_enable = (void(*)(cpu_id_t, boolean_t ))NULL;

	if((proc_info->pf.pfPowerModes & pmType) == pmPowerTune) {
		proc_info->pf.pfPowerTune0 = in_processor_info->power_mode_0;
		proc_info->pf.pfPowerTune1 = in_processor_info->power_mode_1;
	}

	donap = in_processor_info->supports_nap;	/* Assume we use requested nap */
	if(forcenap) donap = forcenap - 1;		/* If there was an override, use that */

	if((proc_info->pf.Available & pfCanNap)
	   && (donap)) {
		proc_info->pf.Available |= pfWillNap;
		current_state = ml_set_interrupts_enabled(FALSE);
		if(proc_info == getPerProc()) 
			__asm__ volatile("mtsprg 2,%0" : : "r" (proc_info->pf.Available));	/* Set live value */
		(void) ml_set_interrupts_enabled(current_state);
	}

	if (!boot_processor) {
		(void)hw_atomic_add(&saveanchor.savetarget, FreeListMin);   /* saveareas for this processor */
		processor_init((struct processor *)proc_info->processor,
								proc_info->cpu_number, processor_pset(master_processor));
	}

	*processor_out = (struct processor *)proc_info->processor;
	*ipi_handler = cpu_signal_handler;

	return KERN_SUCCESS;

processor_register_error:
	if (proc_info->pp_cbfr != (void *)NULL)
		console_per_proc_free(proc_info->pp_cbfr);
	if (proc_info->pp_chud != (void *)NULL)
		chudxnu_per_proc_free(proc_info->pp_chud);
	if (!boot_processor)
		cpu_per_proc_free(proc_info);
	return KERN_FAILURE;
}

/*
 *	Routine:        ml_enable_nap
 *	Function:
 */
boolean_t
ml_enable_nap(int target_cpu, boolean_t nap_enabled)
{
	struct per_proc_info	*proc_info;
	boolean_t				prev_value;
	boolean_t				current_state;

	proc_info = PerProcTable[target_cpu].ppe_vaddr;

    prev_value = (proc_info->pf.Available & pfCanNap) && (proc_info->pf.Available & pfWillNap);
    
 	if(forcenap) nap_enabled = forcenap - 1;				/* If we are to force nap on or off, do it */
 
 	if(proc_info->pf.Available & pfCanNap) {				/* Can the processor nap? */
		if (nap_enabled) proc_info->pf.Available |= pfWillNap;	/* Is nap supported on this machine? */
		else proc_info->pf.Available &= ~pfWillNap;			/* Clear if not */
	}

	current_state = ml_set_interrupts_enabled(FALSE);
	if(proc_info == getPerProc()) 
		__asm__ volatile("mtsprg 2,%0" : : "r" (proc_info->pf.Available));	/* Set live value */
	(void) ml_set_interrupts_enabled(current_state);
 
    return (prev_value);
}

/*
 *	Routine:        ml_init_max_cpus
 *	Function:
 */
void
ml_init_max_cpus(unsigned int max_cpus)
{
	boolean_t current_state;

	current_state = ml_set_interrupts_enabled(FALSE);
	if (max_cpus_initialized != MAX_CPUS_SET) {
			if (max_cpus > 0 && max_cpus <= MAX_CPUS) {
			/*
			 * Note: max_ncpus is the maximum number
			 * that the kernel supports or that the "cpus="
			 * boot-arg has set. Here we take int minimum.
			 */
			machine_info.max_cpus = MIN(max_cpus, max_ncpus);
			machine_info.physical_cpu_max = max_cpus;
			machine_info.logical_cpu_max = max_cpus;
		}
		if (max_cpus_initialized == MAX_CPUS_WAIT)
			wakeup((event_t)&max_cpus_initialized);
		max_cpus_initialized = MAX_CPUS_SET;
	}
	
	if (machine_info.logical_cpu_max == 1) {
		struct patch_up *patch_up_ptr = &patch_up_table[0];

		while (patch_up_ptr->addr != NULL) {
			/*
			 * Patch for V=R kernel text section
			 */
			bcopy_phys((addr64_t)((unsigned int)(&patch_up_ptr->data)), 
				   (addr64_t)((unsigned int)(patch_up_ptr->addr)), 4);
			sync_cache64((addr64_t)((unsigned int)(patch_up_ptr->addr)),4);
			patch_up_ptr++;
		}
	}
	
	(void) ml_set_interrupts_enabled(current_state);	
}

/*
 *	Routine:        ml_get_max_cpus
 *	Function:
 */
unsigned int
ml_get_max_cpus(void)
{
	boolean_t current_state;

	current_state = ml_set_interrupts_enabled(FALSE);
	if (max_cpus_initialized != MAX_CPUS_SET) {
			max_cpus_initialized = MAX_CPUS_WAIT;
			assert_wait((event_t)&max_cpus_initialized, THREAD_UNINT);
			(void)thread_block(THREAD_CONTINUE_NULL);
	}
	(void) ml_set_interrupts_enabled(current_state);
	return(machine_info.max_cpus);
}

/*
 * This is called from the machine-independent routine cpu_up()
 * to perform machine-dependent info updates.
 */
void
ml_cpu_up(void)
{
	(void)hw_atomic_add(&machine_info.physical_cpu, 1);
	(void)hw_atomic_add(&machine_info.logical_cpu, 1);
}

/*
 * This is called from the machine-independent routine cpu_down()
 * to perform machine-dependent info updates.
 */
void
ml_cpu_down(void)
{
	(void)hw_atomic_sub(&machine_info.physical_cpu, 1);
	(void)hw_atomic_sub(&machine_info.logical_cpu, 1);
}

/*
 *	Routine:        ml_cpu_get_info
 *	Function:
 */
void
ml_cpu_get_info(ml_cpu_info_t *ml_cpu_info)
{
  struct per_proc_info	*proc_info;

  if (ml_cpu_info == 0) return;
  
  proc_info = PerProcTable[master_cpu].ppe_vaddr;
  ml_cpu_info->vector_unit = (proc_info->pf.Available & pfAltivec) != 0;
  ml_cpu_info->cache_line_size = proc_info->pf.lineSize;
  ml_cpu_info->l1_icache_size = proc_info->pf.l1iSize;
  ml_cpu_info->l1_dcache_size = proc_info->pf.l1dSize;
  
  if (proc_info->pf.Available & pfL2) {
    ml_cpu_info->l2_settings = proc_info->pf.l2cr;
    ml_cpu_info->l2_cache_size = proc_info->pf.l2Size;
  } else {
    ml_cpu_info->l2_settings = 0;
    ml_cpu_info->l2_cache_size = 0xFFFFFFFF;
  }
  if (proc_info->pf.Available & pfL3) {
    ml_cpu_info->l3_settings = proc_info->pf.l3cr;
    ml_cpu_info->l3_cache_size = proc_info->pf.l3Size;
  } else {
    ml_cpu_info->l3_settings = 0;
    ml_cpu_info->l3_cache_size = 0xFFFFFFFF;
  }
}

/*
 *	Routine:        ml_enable_cache_level
 *	Function:
 */
#define l2em 0x80000000
#define l3em 0x80000000
int
ml_enable_cache_level(int cache_level, int enable)
{
  int old_mode;
  unsigned long available, ccr;
  struct per_proc_info	*proc_info;
  
  if (real_ncpus != 1) return -1;	/* XXX: This test is not safe */
  
  proc_info = PerProcTable[master_cpu].ppe_vaddr;
  available = proc_info->pf.Available;
  
  if ((cache_level == 2) && (available & pfL2)) {
    ccr = proc_info->pf.l2cr;
    old_mode = (ccr & l2em) ? TRUE : FALSE;
    if (old_mode != enable) {
      if (enable) ccr = proc_info->pf.l2crOriginal;
      else ccr = 0;
      proc_info->pf.l2cr = ccr;
      cacheInit();
    }
    
    return old_mode;
  }
  
  if ((cache_level == 3) && (available & pfL3)) {
    ccr = proc_info->pf.l3cr;
    old_mode = (ccr & l3em) ? TRUE : FALSE;
    if (old_mode != enable) {
      if (enable) ccr = proc_info->pf.l3crOriginal;
      else ccr = 0;
      proc_info->pf.l3cr = ccr;
      cacheInit();
    }
    
    return old_mode;
  }
  
  return -1;
}


/*
 *      Routine:        ml_set_processor_speed
 *      Function:
 */
void
ml_set_processor_speed(unsigned long speed)
{
	struct per_proc_info    *proc_info;
	uint32_t                cpu;
	kern_return_t           result;
 	boolean_t		current_state;
	 unsigned int		i;
  
	proc_info = PerProcTable[master_cpu].ppe_vaddr;

	switch (proc_info->pf.pfPowerModes & pmType) {	/* Figure specific type */
		case pmDualPLL:

			ml_set_processor_speed_dpll(speed);
			break;
			
		case pmDFS:

			for (cpu = 0; cpu < real_ncpus; cpu++) {
				/*
				 * cpu_signal() returns after .5ms if it fails to signal a running cpu
				 * retry cpu_signal() for .1s to deal with long interrupt latency at boot
				 */
				for (i=200; i>0; i--) {
					current_state = ml_set_interrupts_enabled(FALSE);
					if (cpu != (unsigned)cpu_number()) {
							if (PerProcTable[cpu].ppe_vaddr->cpu_flags & SignalReady)
							/*
							 * Target cpu is off-line, skip
							 */
							result = KERN_SUCCESS;
						else {
							simple_lock(&spsLock);
							result = cpu_signal(cpu, SIGPcpureq, CPRQsps, speed);	
							if (result == KERN_SUCCESS) 
								thread_sleep_simple_lock(&spsLock, &spsLock, THREAD_UNINT);
							simple_unlock(&spsLock);
						}
					} else {
						ml_set_processor_speed_dfs(speed);
						result = KERN_SUCCESS;
					}
					(void) ml_set_interrupts_enabled(current_state);
					if (result == KERN_SUCCESS)
						break;
				}
				if (result != KERN_SUCCESS)
					panic("ml_set_processor_speed(): Fail to set cpu%d speed\n", cpu);
			}
			break;
			
		case pmPowerTune:
	
			ml_set_processor_speed_powertune(speed);
			break;
			
		default:					
			break;

	}
	return;
}

/*
 *      Routine:        ml_set_processor_speed_slave
 *      Function:
 */
void
ml_set_processor_speed_slave(unsigned long speed)
{
  ml_set_processor_speed_dfs(speed);
  
  simple_lock(&spsLock);
  thread_wakeup(&spsLock);
  simple_unlock(&spsLock);
}

/*
 *	Routine:        ml_init_lock_timeout
 *	Function:
 */
void
ml_init_lock_timeout(void)
{
	uint64_t	abstime;
	uint32_t	mtxspin; 

	nanoseconds_to_absolutetime(NSEC_PER_SEC>>2, &abstime);
	LockTimeOut = (unsigned int)abstime;

	if (PE_parse_boot_argn("mtxspin", &mtxspin, sizeof (mtxspin))) {
		if (mtxspin > USEC_PER_SEC>>4)
			mtxspin =  USEC_PER_SEC>>4;
		nanoseconds_to_absolutetime(mtxspin*NSEC_PER_USEC, &abstime);
	} else {
		nanoseconds_to_absolutetime(10*NSEC_PER_USEC, &abstime);
	}
	MutexSpin = (unsigned int)abstime;
}

/*
 *	Routine:        init_ast_check
 *	Function:
 */
void
init_ast_check(
	__unused processor_t	processor)
{}

/*
 *	Routine:        cause_ast_check
 *	Function:
 */
void
cause_ast_check(
	processor_t		processor)
{
	struct per_proc_info	*proc_info;

	proc_info = PROCESSOR_TO_PER_PROC(processor);

	if (proc_info != getPerProc()
	    && proc_info->interrupts_enabled == TRUE)
		cpu_signal(proc_info->cpu_number, SIGPast, (unsigned int)NULL, (unsigned int)NULL);
}
              
/*
 *	Routine:        machine_processor_shutdown
 *	Function:
 */
thread_t        
machine_processor_shutdown(
	__unused thread_t		thread,
	__unused void			(*doshutdown)(processor_t),
	__unused processor_t	processor)
{
	CreateShutdownCTX();   
	return((thread_t)(getPerProc()->old_thread));
}


void ml_mem_backoff(void) {

	if(warFlags & warDisMBpoff) return;					/* If backoff disabled, exit */

	__asm__ volatile("sync");
	__asm__ volatile("isync");
	
	return;
}



/*
 * Stubs for CPU Stepper
 */
void
machine_run_count(__unused uint32_t count)
{
}

boolean_t
machine_processor_is_inactive(__unused processor_t processor)
{
    return(FALSE);
}

processor_t
machine_choose_processor(__unused processor_set_t pset, processor_t processor)
{
    return (processor);
}

vm_offset_t ml_stack_remaining(void)
{
	uintptr_t local = (uintptr_t) &local;

	if (ml_at_interrupt_context()) {
	    return (local - (getPerProc()->intstack_top_ss - INTSTACK_SIZE));
	} else {
	    return (local - current_thread()->kernel_stack);
	}
}
