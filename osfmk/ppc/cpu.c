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
/*
 *	File:	ppc/cpu.c
 *
 *	cpu specific  routines
 */

#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <mach/machine.h>
#include <mach/processor_info.h>
#include <mach/mach_types.h>
#include <ppc/proc_reg.h>
#include <ppc/misc_protos.h>
#include <ppc/machine_routines.h>
#include <ppc/machine_cpu.h>
#include <ppc/exception.h>
#include <ppc/asm.h>
#include <ppc/hw_perfmon.h>
#include <pexpert/pexpert.h>
#include <kern/cpu_data.h>
#include <ppc/mappings.h>
#include <ppc/Diagnostics.h>
#include <ppc/trap.h>

/* TODO: BOGUS TO BE REMOVED */
int real_ncpus = 1;

int wncpu = NCPUS;
resethandler_t	resethandler_target;

#define MMCR0_SUPPORT_MASK 0xf83f1fff
#define MMCR1_SUPPORT_MASK 0xffc00000
#define MMCR2_SUPPORT_MASK 0x80000000

extern int debugger_pending[NCPUS];	
extern int debugger_is_slave[NCPUS];
extern int debugger_holdoff[NCPUS];
extern int debugger_sync;

struct SIGtimebase {
	boolean_t	avail;
	boolean_t	ready;
	boolean_t	done;
	uint64_t	abstime;
};

struct per_proc_info	*pper_proc_info = per_proc_info; 
 
extern struct SIGtimebase syncClkSpot;

void cpu_sync_timebase(void);

kern_return_t
cpu_control(
	int			slot_num,
	processor_info_t	info,
	unsigned int    	count)
{
	cpu_type_t        cpu_type;
	cpu_subtype_t     cpu_subtype;
	processor_pm_regs_t  perf_regs;
	processor_control_cmd_t cmd;
	boolean_t oldlevel;

	cpu_type = machine_slot[slot_num].cpu_type;
	cpu_subtype = machine_slot[slot_num].cpu_subtype;
	cmd = (processor_control_cmd_t) info;

	if (count < PROCESSOR_CONTROL_CMD_COUNT)
	  return(KERN_FAILURE);

	if ( cpu_type != cmd->cmd_cpu_type ||
	     cpu_subtype != cmd->cmd_cpu_subtype)
	  return(KERN_FAILURE);

	if (perfmon_acquire_facility(current_task()) != KERN_SUCCESS) {
		return(KERN_RESOURCE_SHORTAGE); /* cpu performance facility in use by another task */
	}

	switch (cmd->cmd_op)
	  {
	  case PROCESSOR_PM_CLR_PMC:       /* Clear Performance Monitor Counters */
	    switch (cpu_subtype)
	      {
	      case CPU_SUBTYPE_POWERPC_750:
	      case CPU_SUBTYPE_POWERPC_7400:
	      case CPU_SUBTYPE_POWERPC_7450:
		{
		  oldlevel = ml_set_interrupts_enabled(FALSE);    /* disable interrupts */
		  mtpmc1(0x0);
		  mtpmc2(0x0);
		  mtpmc3(0x0);
		  mtpmc4(0x0);
		  ml_set_interrupts_enabled(oldlevel);     /* enable interrupts */
		  return(KERN_SUCCESS);
		}
	      default:
		return(KERN_FAILURE);
	      } /* cpu_subtype */
	  case PROCESSOR_PM_SET_REGS:      /* Set Performance Monitor Registors */
	    switch (cpu_subtype)
	      {
	      case CPU_SUBTYPE_POWERPC_750:
		if (count <  (PROCESSOR_CONTROL_CMD_COUNT +
		       PROCESSOR_PM_REGS_COUNT_POWERPC_750))
		  return(KERN_FAILURE);
		else
		  {
		    perf_regs = (processor_pm_regs_t)cmd->cmd_pm_regs;
		    oldlevel = ml_set_interrupts_enabled(FALSE);    /* disable interrupts */
		    mtmmcr0(PERFMON_MMCR0(perf_regs) & MMCR0_SUPPORT_MASK);
		    mtpmc1(PERFMON_PMC1(perf_regs));
		    mtpmc2(PERFMON_PMC2(perf_regs));
		    mtmmcr1(PERFMON_MMCR1(perf_regs) & MMCR1_SUPPORT_MASK);
		    mtpmc3(PERFMON_PMC3(perf_regs));
		    mtpmc4(PERFMON_PMC4(perf_regs));
		    ml_set_interrupts_enabled(oldlevel);     /* enable interrupts */
		    return(KERN_SUCCESS);
		  }
	      case CPU_SUBTYPE_POWERPC_7400:
	      case CPU_SUBTYPE_POWERPC_7450:
		if (count <  (PROCESSOR_CONTROL_CMD_COUNT +
		       PROCESSOR_PM_REGS_COUNT_POWERPC_7400))
		  return(KERN_FAILURE);
		else
		  {
		    perf_regs = (processor_pm_regs_t)cmd->cmd_pm_regs;
		    oldlevel = ml_set_interrupts_enabled(FALSE);    /* disable interrupts */
		    mtmmcr0(PERFMON_MMCR0(perf_regs) & MMCR0_SUPPORT_MASK);
		    mtpmc1(PERFMON_PMC1(perf_regs));
		    mtpmc2(PERFMON_PMC2(perf_regs));
		    mtmmcr1(PERFMON_MMCR1(perf_regs) & MMCR1_SUPPORT_MASK);
		    mtpmc3(PERFMON_PMC3(perf_regs));
		    mtpmc4(PERFMON_PMC4(perf_regs));
		    mtmmcr2(PERFMON_MMCR2(perf_regs) & MMCR2_SUPPORT_MASK);
		    ml_set_interrupts_enabled(oldlevel);     /* enable interrupts */
		    return(KERN_SUCCESS);
		  }
	      default:
		return(KERN_FAILURE);
	      } /* switch cpu_subtype */
	  case PROCESSOR_PM_SET_MMCR:
	    switch (cpu_subtype)
	      {
	      case CPU_SUBTYPE_POWERPC_750:
		if (count < (PROCESSOR_CONTROL_CMD_COUNT +
		      PROCESSOR_PM_REGS_COUNT_POWERPC_750))
		  return(KERN_FAILURE);
		else
		  {
		    perf_regs = (processor_pm_regs_t)cmd->cmd_pm_regs;
		    oldlevel = ml_set_interrupts_enabled(FALSE);    /* disable interrupts */
		    mtmmcr0(PERFMON_MMCR0(perf_regs) & MMCR0_SUPPORT_MASK);
		    mtmmcr1(PERFMON_MMCR1(perf_regs) & MMCR1_SUPPORT_MASK);
		    ml_set_interrupts_enabled(oldlevel);     /* enable interrupts */
		    return(KERN_SUCCESS);
		  }
	      case CPU_SUBTYPE_POWERPC_7400:
	      case CPU_SUBTYPE_POWERPC_7450:
		if (count < (PROCESSOR_CONTROL_CMD_COUNT +
		      PROCESSOR_PM_REGS_COUNT_POWERPC_7400))
		  return(KERN_FAILURE);
		else
		  {
		    perf_regs = (processor_pm_regs_t)cmd->cmd_pm_regs;
		    oldlevel = ml_set_interrupts_enabled(FALSE);    /* disable interrupts */
		    mtmmcr0(PERFMON_MMCR0(perf_regs) & MMCR0_SUPPORT_MASK);
		    mtmmcr1(PERFMON_MMCR1(perf_regs) & MMCR1_SUPPORT_MASK);
		    mtmmcr2(PERFMON_MMCR2(perf_regs) & MMCR2_SUPPORT_MASK);
		    ml_set_interrupts_enabled(oldlevel);     /* enable interrupts */
		    return(KERN_SUCCESS);
		  }
	      default:
		return(KERN_FAILURE);
	      } /* cpu_subtype */
	  default:
	    return(KERN_FAILURE);
	  } /* switch cmd_op */
}

kern_return_t
cpu_info_count(
	processor_flavor_t	flavor,
	unsigned int    	*count)
{
	cpu_subtype_t     cpu_subtype;

	/*
	 * For now, we just assume that all CPUs are of the same type
	 */
	cpu_subtype = machine_slot[0].cpu_subtype;
	switch (flavor) {
		case PROCESSOR_PM_REGS_INFO:
			switch (cpu_subtype) {
				case CPU_SUBTYPE_POWERPC_750:
		
					*count = PROCESSOR_PM_REGS_COUNT_POWERPC_750;
					return(KERN_SUCCESS);

				case CPU_SUBTYPE_POWERPC_7400:
				case CPU_SUBTYPE_POWERPC_7450:
		
					*count = PROCESSOR_PM_REGS_COUNT_POWERPC_7400;
					return(KERN_SUCCESS);

				default:
					*count = 0;
					return(KERN_INVALID_ARGUMENT);
			} /* switch cpu_subtype */

		case PROCESSOR_TEMPERATURE:
			*count = PROCESSOR_TEMPERATURE_COUNT;
			return (KERN_SUCCESS);

		default:
			*count = 0;
			return(KERN_INVALID_ARGUMENT);
			
	}
}

kern_return_t
cpu_info(
	processor_flavor_t	flavor,
	int			slot_num,
	processor_info_t	info,
	unsigned int    	*count)
{
	cpu_subtype_t     cpu_subtype;
	processor_pm_regs_t  perf_regs;
	boolean_t oldlevel;
	unsigned int temp[2];

	cpu_subtype = machine_slot[slot_num].cpu_subtype;

	switch (flavor) {
		case PROCESSOR_PM_REGS_INFO:

			perf_regs = (processor_pm_regs_t) info;

			switch (cpu_subtype) {
				case CPU_SUBTYPE_POWERPC_750:

					if (*count < PROCESSOR_PM_REGS_COUNT_POWERPC_750)
					  return(KERN_FAILURE);
				  
					oldlevel = ml_set_interrupts_enabled(FALSE);    /* disable interrupts */
					PERFMON_MMCR0(perf_regs) = mfmmcr0();
					PERFMON_PMC1(perf_regs)  = mfpmc1();
					PERFMON_PMC2(perf_regs)  = mfpmc2();
					PERFMON_MMCR1(perf_regs) = mfmmcr1();
					PERFMON_PMC3(perf_regs)  = mfpmc3();
					PERFMON_PMC4(perf_regs)  = mfpmc4();
					ml_set_interrupts_enabled(oldlevel);     /* enable interrupts */
		
					*count = PROCESSOR_PM_REGS_COUNT_POWERPC_750;
					return(KERN_SUCCESS);

				case CPU_SUBTYPE_POWERPC_7400:
				case CPU_SUBTYPE_POWERPC_7450:

					if (*count < PROCESSOR_PM_REGS_COUNT_POWERPC_7400)
					  return(KERN_FAILURE);
				  
					oldlevel = ml_set_interrupts_enabled(FALSE);    /* disable interrupts */
					PERFMON_MMCR0(perf_regs) = mfmmcr0();
					PERFMON_PMC1(perf_regs)  = mfpmc1();
					PERFMON_PMC2(perf_regs)  = mfpmc2();
					PERFMON_MMCR1(perf_regs) = mfmmcr1();
					PERFMON_PMC3(perf_regs)  = mfpmc3();
					PERFMON_PMC4(perf_regs)  = mfpmc4();
					PERFMON_MMCR2(perf_regs) = mfmmcr2();
					ml_set_interrupts_enabled(oldlevel);     /* enable interrupts */
		
					*count = PROCESSOR_PM_REGS_COUNT_POWERPC_7400;
					return(KERN_SUCCESS);

				default:
					return(KERN_FAILURE);
			} /* switch cpu_subtype */

		case PROCESSOR_TEMPERATURE:					/* Get the temperature of a processor */

			disable_preemption();					/* Don't move me now */
			
			if(slot_num == cpu_number()) {			/* Is this for the local CPU? */
				*info = ml_read_temp();				/* Get the temperature */
			}
			else {									/* For another CPU */
				temp[0] = -1;						/* Set sync flag */
				eieio();
				sync();									
				temp[1] = -1;						/* Set invalid temperature */
				(void)cpu_signal(slot_num, SIGPcpureq, CPRQtemp ,(unsigned int)&temp);	/* Ask him to take his temperature */
				(void)hw_cpu_sync(temp, LockTimeOut);	/* Wait for the other processor to get its temperature */
				*info = temp[1];					/* Pass it back */
			}
			
			enable_preemption();					/* Ok to move now */
			return(KERN_SUCCESS);

		default:
			return(KERN_INVALID_ARGUMENT);
			
	} /* flavor */
}

void
cpu_init(
	void)
{
	int	cpu;

	cpu = cpu_number();

	machine_slot[cpu].running = TRUE;
	machine_slot[cpu].cpu_type = CPU_TYPE_POWERPC;
	machine_slot[cpu].cpu_subtype = (cpu_subtype_t)per_proc_info[cpu].pf.rptdProc;

}

void
cpu_machine_init(
	void)
{
	struct per_proc_info	*tproc_info;
	volatile struct per_proc_info	*mproc_info;
	int cpu;

	/* TODO: realese mutex lock reset_handler_lock */

	cpu = cpu_number();
	tproc_info = &per_proc_info[cpu];
	mproc_info = &per_proc_info[master_cpu];
	PE_cpu_machine_init(tproc_info->cpu_id, !(tproc_info->cpu_flags & BootDone));
	if (cpu != master_cpu) {
		while (!((mproc_info->cpu_flags) & SignalReady))
			continue;
		cpu_sync_timebase();
	}
	ml_init_interrupt();
	tproc_info->cpu_flags |= BootDone|SignalReady;
}

kern_return_t
cpu_register(
	int *target_cpu
)
{
	int cpu;

	/* 
	 * TODO: 
	 * - Run cpu_register() in exclusion mode 
	 */

	*target_cpu = -1;
	for(cpu=0; cpu < wncpu; cpu++) {
		if(!machine_slot[cpu].is_cpu) {
			machine_slot[cpu].is_cpu = TRUE;
			*target_cpu = cpu;
			break;
		}
	}
	if (*target_cpu != -1) {
		real_ncpus++;
		return KERN_SUCCESS;
	} else
		return KERN_FAILURE;
}

kern_return_t
cpu_start(
	int cpu)
{
	struct per_proc_info	*proc_info;
	kern_return_t		ret;
	mapping *mp;

	extern vm_offset_t	intstack;
	extern vm_offset_t	debstack;

	proc_info = &per_proc_info[cpu];

	if (cpu == cpu_number()) {
 	  PE_cpu_machine_init(proc_info->cpu_id, !(proc_info->cpu_flags & BootDone));
	  ml_init_interrupt();
	  proc_info->cpu_flags |= BootDone|SignalReady;

	  return KERN_SUCCESS;
	} else {
		extern void _start_cpu(void);

		proc_info->cpu_number = cpu;
		proc_info->cpu_flags &= BootDone;
		proc_info->istackptr = (vm_offset_t)&intstack + (INTSTACK_SIZE*(cpu+1)) - FM_SIZE;
		proc_info->intstack_top_ss = proc_info->istackptr;
#if     MACH_KDP || MACH_KDB
		proc_info->debstackptr = (vm_offset_t)&debstack + (KERNEL_STACK_SIZE*(cpu+1)) - FM_SIZE;
		proc_info->debstack_top_ss = proc_info->debstackptr;
#endif  /* MACH_KDP || MACH_KDB */
		proc_info->interrupts_enabled = 0;
		proc_info->need_ast = (unsigned int)&need_ast[cpu];
		proc_info->FPU_owner = 0;
		proc_info->VMX_owner = 0;
		mp = (mapping *)(&proc_info->ppCIOmp);
		mp->mpFlags = 0x01000000 | mpSpecial | 1;
		mp->mpSpace = invalSpace;

		if (proc_info->start_paddr == EXCEPTION_VECTOR(T_RESET)) {

			/* TODO: get mutex lock reset_handler_lock */

			resethandler_target.type = RESET_HANDLER_START;
			resethandler_target.call_paddr = (vm_offset_t)_start_cpu; 	/* Note: these routines are always V=R */
			resethandler_target.arg__paddr = (vm_offset_t)proc_info; 	/* Note: these routines are always V=R */
			
			ml_phys_write((vm_offset_t)&ResetHandler + 0,
				      resethandler_target.type);
			ml_phys_write((vm_offset_t)&ResetHandler + 4,
				      resethandler_target.call_paddr);
			ml_phys_write((vm_offset_t)&ResetHandler + 8,
				      resethandler_target.arg__paddr);
					  
		}
/*
 *		Note: we pass the current time to the other processor here. He will load it
 *		as early as possible so that there is a chance that it is close to accurate.
 *		After the machine is up a while, we will officially resync the clocks so
 *		that all processors are the same.  This is just to get close.
 */

		ml_get_timebase((unsigned long long *)&proc_info->ruptStamp);	/* Pass our current time to the other guy */
		
		__asm__ volatile("sync");				/* Commit to storage */
		__asm__ volatile("isync");				/* Wait a second */
		ret = PE_cpu_start(proc_info->cpu_id, 
					proc_info->start_paddr, (vm_offset_t)proc_info);

		if (ret != KERN_SUCCESS && 
		    proc_info->start_paddr == EXCEPTION_VECTOR(T_RESET)) {

			/* TODO: realese mutex lock reset_handler_lock */
		}
		return(ret);
	}
}

perfTrap perfCpuSigHook = 0;            /* Pointer to CHUD cpu signal hook routine */

/*
 *	Here is where we implement the receiver of the signaling protocol.
 *	We wait for the signal status area to be passed to us. Then we snarf
 *	up the status, the sender, and the 3 potential parms. Next we release
 *	the lock and signal the other guy.
 */

void 
cpu_signal_handler(
	void)
{

	unsigned int holdStat, holdParm0, holdParm1, holdParm2, mtype;
	unsigned int *parmAddr;
	struct per_proc_info *pproc;					/* Area for my per_proc address */
	int cpu;
	struct SIGtimebase *timebaseAddr;
	natural_t tbu, tbu2, tbl;
	
	cpu = cpu_number();								/* Get the CPU number */
	pproc = &per_proc_info[cpu];					/* Point to our block */

/*
 *	Since we've been signaled, wait about 31 ms for the signal lock to pass
 */
	if(!hw_lock_mbits(&pproc->MPsigpStat, (MPsigpMsgp | MPsigpAck), (MPsigpBusy | MPsigpPass),
	  (MPsigpBusy | MPsigpPass | MPsigpAck), (gPEClockFrequencyInfo.timebase_frequency_hz >> 5))) {
		panic("cpu_signal_handler: Lock pass timed out\n");
	}
	
	holdStat = pproc->MPsigpStat;					/* Snarf stat word */
	holdParm0 = pproc->MPsigpParm0;					/* Snarf parameter */
	holdParm1 = pproc->MPsigpParm1;					/* Snarf parameter */
	holdParm2 = pproc->MPsigpParm2;					/* Snarf parameter */
	
	__asm__ volatile("isync");						/* Make sure we don't unlock until memory is in */

	pproc->MPsigpStat = holdStat & ~(MPsigpMsgp | MPsigpAck | MPsigpFunc);	/* Release lock */

	switch ((holdStat & MPsigpFunc) >> 8) {			/* Decode function code */

		case MPsigpIdle:							/* Was function cancelled? */
			return;									/* Yup... */
			
		case MPsigpSigp:							/* Signal Processor message? */
			
			switch (holdParm0) {					/* Decode SIGP message order */

				case SIGPast:						/* Should we do an AST? */
					pproc->hwCtr.numSIGPast++;		/* Count this one */
#if 0
					kprintf("cpu_signal_handler: AST check on cpu %x\n", cpu_number());
#endif
					ast_check(cpu_to_processor(cpu));
					return;							/* All done... */
					
				case SIGPcpureq:					/* CPU specific function? */
				
					pproc->hwCtr.numSIGPcpureq++;	/* Count this one */
					switch (holdParm1) {			/* Select specific function */
					
						case CPRQtemp:				/* Get the temperature */
							parmAddr = (unsigned int *)holdParm2;	/* Get the destination address */
							parmAddr[1] = ml_read_temp();	/* Get the core temperature */
							eieio();				/* Force order */
							sync();					/* Force to memory */
							parmAddr[0] = 0;		/* Show we're done */
							return;
						
						case CPRQtimebase:

							timebaseAddr = (struct SIGtimebase *)holdParm2;
							
							if(pproc->time_base_enable !=  (void(*)(cpu_id_t, boolean_t ))NULL)
								pproc->time_base_enable(pproc->cpu_id, FALSE);

							timebaseAddr->abstime = 0;	/* Touch to force into cache */
							sync();
							
							do {
								asm volatile("	mftbu %0" : "=r" (tbu));
								asm volatile("	mftb %0" : "=r" (tbl));
								asm volatile("	mftbu %0" : "=r" (tbu2));
							} while (tbu != tbu2);
							
							timebaseAddr->abstime = ((uint64_t)tbu << 32) | tbl;
							sync();					/* Force order */
						
							timebaseAddr->avail = TRUE;

							while (*(volatile int *)&(syncClkSpot.ready) == FALSE);

							if(pproc->time_base_enable !=  (void(*)(cpu_id_t, boolean_t ))NULL)
								pproc->time_base_enable(pproc->cpu_id, TRUE);

							timebaseAddr->done = TRUE;

							return;

						case CPRQsegload:
							return;
						
 						case CPRQchud:
 							parmAddr = (unsigned int *)holdParm2;	/* Get the destination address */
 							if(perfCpuSigHook) {
 								struct savearea *ssp = current_act()->mact.pcb;
 								if(ssp) {
 									(perfCpuSigHook)(parmAddr[1] /* request */, ssp, 0, 0);
 								}
   							}
 							parmAddr[1] = 0;
 							parmAddr[0] = 0;		/* Show we're done */
  							return;
						
						case CPRQscom:
							if(((scomcomm *)holdParm2)->scomfunc) {	/* Are we writing */
								((scomcomm *)holdParm2)->scomstat = ml_scom_write(((scomcomm *)holdParm2)->scomreg, ((scomcomm *)holdParm2)->scomdata);	/* Write scom */
							}
							else {					/* No, reading... */
								((scomcomm *)holdParm2)->scomstat = ml_scom_read(((scomcomm *)holdParm2)->scomreg, &((scomcomm *)holdParm2)->scomdata);	/* Read scom */
							}
							return;

						default:
							panic("cpu_signal_handler: unknown CPU request - %08X\n", holdParm1);
							return;
					}
					
	
				case SIGPdebug:						/* Enter the debugger? */		

					pproc->hwCtr.numSIGPdebug++;	/* Count this one */
					debugger_is_slave[cpu]++;		/* Bump up the count to show we're here */
					hw_atomic_sub(&debugger_sync, 1);	/* Show we've received the 'rupt */
					__asm__ volatile("tw 4,r3,r3");	/* Enter the debugger */
					return;							/* All done now... */
					
				case SIGPwake:						/* Wake up CPU */
					pproc->hwCtr.numSIGPwake++;		/* Count this one */
					return;							/* No need to do anything, the interrupt does it all... */
					
				default:
					panic("cpu_signal_handler: unknown SIGP message order - %08X\n", holdParm0);
					return;
			
			}
	
		default:
			panic("cpu_signal_handler: unknown SIGP function - %08X\n", (holdStat & MPsigpFunc) >> 8);
			return;
	
	}
	panic("cpu_signal_handler: we should never get here\n");
}

/*
 *	Here is where we send a message to another processor.  So far we only have two:
 *	SIGPast and SIGPdebug.  SIGPast is used to preempt and kick off threads (this is
 *	currently disabled). SIGPdebug is used to enter the debugger.
 *
 *	We set up the SIGP function to indicate that this is a simple message and set the
 *	order code (MPsigpParm0) to SIGPast or SIGPdebug). After finding the per_processor
 *	block for the target, we lock the message block. Then we set the parameter(s). 
 *	Next we change the lock (also called "busy") to "passing" and finally signal
 *	the other processor. Note that we only wait about 1ms to get the message lock.  
 *	If we time out, we return failure to our caller. It is their responsibility to
 *	recover.
 */

kern_return_t 
cpu_signal(
	int target, 
	int signal, 
	unsigned int p1, 
	unsigned int p2)
{

	unsigned int holdStat, holdParm0, holdParm1, holdParm2, mtype;
	struct per_proc_info *tpproc, *mpproc;			/* Area for per_proc addresses */
	int cpu;
	int busybitset =0;

#if DEBUG
	if(target > NCPUS) panic("cpu_signal: invalid target CPU - %08X\n", target);
#endif

	cpu = cpu_number();								/* Get our CPU number */
	if(target == cpu) return KERN_FAILURE;			/* Don't play with ourselves */
	if(!machine_slot[target].running) return KERN_FAILURE;	/* These guys are too young */	

	mpproc = &per_proc_info[cpu];					/* Point to our block */
	tpproc = &per_proc_info[target];				/* Point to the target's block */

	if (!(tpproc->cpu_flags & SignalReady)) return KERN_FAILURE;
		
	if((tpproc->MPsigpStat & MPsigpMsgp) == MPsigpMsgp) {	/* Is there an unreceived message already pending? */

		if(signal == SIGPwake) {					/* SIGPwake can merge into all others... */
			mpproc->hwCtr.numSIGPmwake++;			/* Account for merged wakes */
			return KERN_SUCCESS;
		}

		if((signal == SIGPast) && (tpproc->MPsigpParm0 == SIGPast)) {	/* We can merge ASTs */
			mpproc->hwCtr.numSIGPmast++;			/* Account for merged ASTs */
			return KERN_SUCCESS;					/* Don't bother to send this one... */
		}

		if (tpproc->MPsigpParm0 == SIGPwake) {
			if (hw_lock_mbits(&tpproc->MPsigpStat, (MPsigpMsgp | MPsigpAck), 
			                  (MPsigpBusy | MPsigpPass ), MPsigpBusy, 0)) {
				busybitset = 1;
				mpproc->hwCtr.numSIGPmwake++;	
			}
		}
	}	
	
	if((busybitset == 0) && 
	   (!hw_lock_mbits(&tpproc->MPsigpStat, MPsigpMsgp, 0, MPsigpBusy, 
	   (gPEClockFrequencyInfo.timebase_frequency_hz >> 11)))) {	/* Try to lock the message block with a .5ms timeout */
		mpproc->hwCtr.numSIGPtimo++;				/* Account for timeouts */
		return KERN_FAILURE;						/* Timed out, take your ball and go home... */
	}

	holdStat = MPsigpBusy | MPsigpPass | (MPsigpSigp << 8) | cpu;	/* Set up the signal status word */
	tpproc->MPsigpParm0 = signal;					/* Set message order */
	tpproc->MPsigpParm1 = p1;						/* Set additional parm */
	tpproc->MPsigpParm2 = p2;						/* Set additional parm */
	
	__asm__ volatile("sync");						/* Make sure it's all there */
	
	tpproc->MPsigpStat = holdStat;					/* Set status and pass the lock */
	__asm__ volatile("eieio");						/* I'm a paraniod freak */
	
	if (busybitset == 0)
		PE_cpu_signal(mpproc->cpu_id, tpproc->cpu_id);	/* Kick the other processor */

	return KERN_SUCCESS;							/* All is goodness and rainbows... */
}

void
cpu_doshutdown(
	void)
{
	enable_preemption();
	processor_offline(current_processor());
}

void
cpu_sleep(
	void)
{
	struct per_proc_info	*proc_info;
	unsigned int	cpu, i;
	unsigned int	wait_ncpus_sleep, ncpus_sleep;
	facility_context *fowner;
	extern vm_offset_t	intstack;
	extern vm_offset_t	debstack;
	extern void _restart_cpu(void);

	cpu = cpu_number();

	proc_info = &per_proc_info[cpu];

	fowner = proc_info->FPU_owner;					/* Cache this */
	if(fowner) fpu_save(fowner);					/* If anyone owns FPU, save it */
	proc_info->FPU_owner = 0;						/* Set no fpu owner now */

	fowner = proc_info->VMX_owner;					/* Cache this */
	if(fowner) vec_save(fowner);					/* If anyone owns vectors, save it */
	proc_info->VMX_owner = 0;						/* Set no vector owner now */

	if (proc_info->cpu_number == 0)  {
		proc_info->cpu_flags &= BootDone;
		proc_info->istackptr = (vm_offset_t)&intstack + (INTSTACK_SIZE*(cpu+1)) - FM_SIZE;
		proc_info->intstack_top_ss = proc_info->istackptr;
#if     MACH_KDP || MACH_KDB
		proc_info->debstackptr = (vm_offset_t)&debstack + (KERNEL_STACK_SIZE*(cpu+1)) - FM_SIZE;
		proc_info->debstack_top_ss = proc_info->debstackptr;
#endif  /* MACH_KDP || MACH_KDB */
		proc_info->interrupts_enabled = 0;

		if (proc_info->start_paddr == EXCEPTION_VECTOR(T_RESET)) {
			extern void _start_cpu(void);
	
			resethandler_target.type = RESET_HANDLER_START;
			resethandler_target.call_paddr = (vm_offset_t)_start_cpu; 	/* Note: these routines are always V=R */
			resethandler_target.arg__paddr = (vm_offset_t)proc_info; 	/* Note: these routines are always V=R */
	
			ml_phys_write((vm_offset_t)&ResetHandler + 0,
					  resethandler_target.type);
			ml_phys_write((vm_offset_t)&ResetHandler + 4,
					  resethandler_target.call_paddr);
			ml_phys_write((vm_offset_t)&ResetHandler + 8,
					  resethandler_target.arg__paddr);
					  
			__asm__ volatile("sync");
			__asm__ volatile("isync");
		}

		wait_ncpus_sleep = real_ncpus-1; 
		ncpus_sleep = 0;
		while (wait_ncpus_sleep != ncpus_sleep) {
			ncpus_sleep = 0;
			for(i=1; i < real_ncpus ; i++) {
				if ((*(volatile short *)&per_proc_info[i].cpu_flags) & SleepState)
					ncpus_sleep++;
			}
		}
	}

	PE_cpu_machine_quiesce(proc_info->cpu_id);
}

void
cpu_sync_timebase(
	void)
{
	natural_t tbu, tbl;
	boolean_t	intr;

	intr = ml_set_interrupts_enabled(FALSE);		/* No interruptions in here */

	/* Note that syncClkSpot is in a cache aligned area */
	syncClkSpot.avail = FALSE;
	syncClkSpot.ready = FALSE;
	syncClkSpot.done = FALSE;

	while (cpu_signal(master_cpu, SIGPcpureq, CPRQtimebase,
							(unsigned int)&syncClkSpot) != KERN_SUCCESS)
		continue;

	while (*(volatile int *)&(syncClkSpot.avail) == FALSE)
		continue;

	isync();

	/*
	 * We do the following to keep the compiler from generating extra stuff 
	 * in tb set part
	 */
	tbu = syncClkSpot.abstime >> 32;
	tbl = (uint32_t)syncClkSpot.abstime;

	mttb(0);
	mttbu(tbu);
	mttb(tbl);

	syncClkSpot.ready = TRUE;

	while (*(volatile int *)&(syncClkSpot.done) == FALSE)
		continue;

	(void)ml_set_interrupts_enabled(intr);
}
