/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
#include <mach/machine.h>
#include <mach/processor_info.h>

#include <kern/kalloc.h>
#include <kern/kern_types.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/timer_queue.h>
#include <kern/processor.h>
#include <kern/pms.h>

#include <vm/pmap.h>
#include <IOKit/IOHibernatePrivate.h>

#include <ppc/proc_reg.h>
#include <ppc/misc_protos.h>
#include <ppc/fpu_protos.h>
#include <ppc/machine_routines.h>
#include <ppc/cpu_internal.h>
#include <ppc/exception.h>
#include <ppc/asm.h>
#include <ppc/hw_perfmon.h>
#include <pexpert/pexpert.h>
#include <kern/cpu_data.h>
#include <ppc/mappings.h>
#include <ppc/Diagnostics.h>
#include <ppc/trap.h>
#include <ppc/machine_cpu.h>
#include <ppc/rtclock.h>

#include <libkern/OSAtomic.h>

unsigned int		real_ncpus = 1;
unsigned int		max_ncpus  = MAX_CPUS;

decl_simple_lock_data(static,rht_lock);

static unsigned int	rht_state = 0;
#define RHT_WAIT	0x01
#define RHT_BUSY	0x02

decl_simple_lock_data(static,SignalReadyLock);

struct SIGtimebase {
	volatile boolean_t	avail;
	volatile boolean_t	ready;
	volatile boolean_t	done;
	uint64_t	abstime;
};

perfCallback	   	perfCpuSigHook;			/* Pointer to CHUD cpu signal hook routine */

extern uint32_t			debugger_sync;

/*
 * Forward definitions
 */

void	cpu_sync_timebase(
			void);

void	cpu_timebase_signal_handler(
			struct per_proc_info    *proc_info,
			struct SIGtimebase		*timebaseAddr);

/*
 *	Routine:	cpu_bootstrap
 *	Function:
 */
void
cpu_bootstrap(
	void)
{
	simple_lock_init(&rht_lock,0);
	simple_lock_init(&SignalReadyLock,0);
}


/*
 *	Routine:	cpu_init
 *	Function:
 */
void
cpu_init(
	void)
{
	struct per_proc_info *proc_info;

	proc_info = getPerProc();

	/*
	 * Restore the TBR.
	 */
	if (proc_info->save_tbu != 0 || proc_info->save_tbl != 0) {
		mttb(0);
		mttbu(proc_info->save_tbu);
		mttb(proc_info->save_tbl);
	}

	proc_info->rtcPop = EndOfAllTime;			/* forget any existing decrementer setting */
	etimer_resync_deadlines();				/* Now that the time base is sort of correct, request the next timer pop */

	proc_info->cpu_type = CPU_TYPE_POWERPC;
	proc_info->cpu_subtype = (cpu_subtype_t)proc_info->pf.rptdProc;
	proc_info->cpu_threadtype = CPU_THREADTYPE_NONE;
	proc_info->running = TRUE;

}

/*
 *	Routine:	cpu_machine_init
 *	Function:
 */
void
cpu_machine_init(
	void)
{
	struct per_proc_info			*proc_info;
	volatile struct per_proc_info	*mproc_info;


	proc_info = getPerProc();
	mproc_info = PerProcTable[master_cpu].ppe_vaddr;

	if (proc_info != mproc_info) {
		simple_lock(&rht_lock);
		if (rht_state & RHT_WAIT)
			thread_wakeup(&rht_state);
		rht_state &= ~(RHT_BUSY|RHT_WAIT);
		simple_unlock(&rht_lock);
	}

	PE_cpu_machine_init(proc_info->cpu_id, !(proc_info->cpu_flags & BootDone));

	if (proc_info->hibernate) {
		uint32_t	tbu, tbl;

		do {
			tbu = mftbu();
			tbl = mftb();
		} while (mftbu() != tbu);

	    proc_info->hibernate = 0;
	    hibernate_machine_init();

		// hibernate_machine_init() could take minutes and we don't want timeouts
		// to fire as soon as scheduling starts. Reset timebase so it appears
		// no time has elapsed, as it would for regular sleep.
		mttb(0);
		mttbu(tbu);
		mttb(tbl);
	}

	if (proc_info != mproc_info) {
	while (!((mproc_info->cpu_flags) & SignalReady)) 
			continue;
		cpu_sync_timebase();
	}

	ml_init_interrupt();
	if (proc_info != mproc_info)
		simple_lock(&SignalReadyLock);
	proc_info->cpu_flags |= BootDone|SignalReady;
	if (proc_info != mproc_info) {
		if (proc_info->ppXFlags & SignalReadyWait) {
			hw_atomic_and_noret(&proc_info->ppXFlags, ~SignalReadyWait);
			thread_wakeup(&proc_info->cpu_flags);
		}
		simple_unlock(&SignalReadyLock);
		pmsPark();						/* Timers should be cool now, park the power management stepper */
	}
}


/*
 *	Routine:	cpu_per_proc_alloc
 *	Function:
 */
struct per_proc_info *
cpu_per_proc_alloc(
		void)
{
	struct per_proc_info	*proc_info = NULL;
	void			*interrupt_stack = NULL;
	void			*debugger_stack = NULL;

	if ((proc_info = (struct per_proc_info*)kalloc(sizeof(struct per_proc_info))) == (struct per_proc_info*)0)
		return (struct per_proc_info *)NULL;
	if ((interrupt_stack = kalloc(INTSTACK_SIZE)) == 0) {
		kfree(proc_info, sizeof(struct per_proc_info));
		return (struct per_proc_info *)NULL;
	}

	if ((debugger_stack = kalloc(kernel_stack_size)) == 0) {
		kfree(proc_info, sizeof(struct per_proc_info));
		kfree(interrupt_stack, INTSTACK_SIZE);
		return (struct per_proc_info *)NULL;
	}

	bzero((void *)proc_info, sizeof(struct per_proc_info));

	/* Set physical address of the second page */
	proc_info->pp2ndPage = (addr64_t)pmap_find_phys(kernel_pmap,
				((addr64_t)(unsigned int)proc_info) + 0x1000)
			       << PAGE_SHIFT;
	proc_info->next_savearea = (uint64_t)save_get_init();
	proc_info->pf = BootProcInfo.pf;
	proc_info->istackptr = (vm_offset_t)interrupt_stack + INTSTACK_SIZE - FM_SIZE;
	proc_info->intstack_top_ss = proc_info->istackptr;
	proc_info->debstackptr = (vm_offset_t)debugger_stack + kernel_stack_size - FM_SIZE;
	proc_info->debstack_top_ss = proc_info->debstackptr;

	queue_init(&proc_info->rtclock_timer.queue);
	proc_info->rtclock_timer.deadline = EndOfAllTime;

	return proc_info;

}


/*
 *	Routine:	cpu_per_proc_free
 *	Function:
 */
void
cpu_per_proc_free(
	struct per_proc_info	*proc_info
)
{
	if (proc_info->cpu_number == master_cpu)
		return;
	kfree((void *)(proc_info->intstack_top_ss - INTSTACK_SIZE + FM_SIZE), INTSTACK_SIZE);
	kfree((void *)(proc_info->debstack_top_ss -  kernel_stack_size + FM_SIZE), kernel_stack_size);
	kfree((void *)proc_info, sizeof(struct per_proc_info));			/* Release the per_proc */
}


/*
 *	Routine:	cpu_per_proc_register
 *	Function:
 */
kern_return_t
cpu_per_proc_register(
	struct per_proc_info	*proc_info
)
{
	int	cpu;
	
	cpu = OSIncrementAtomic(&real_ncpus);
	
	if (real_ncpus > max_ncpus) {
		return KERN_FAILURE;
	}
	
	proc_info->cpu_number = cpu;
	PerProcTable[cpu].ppe_vaddr = proc_info;
	PerProcTable[cpu].ppe_paddr = (addr64_t)pmap_find_phys(kernel_pmap, (addr64_t)(unsigned int)proc_info) << PAGE_SHIFT;
	eieio();
	return KERN_SUCCESS;
}


/*
 *	Routine:	cpu_start
 *	Function:
 */
kern_return_t
cpu_start(
	int cpu)
{
	struct per_proc_info	*proc_info;
	kern_return_t			ret;
	mapping_t				*mp;

	proc_info = PerProcTable[cpu].ppe_vaddr;

	if (cpu == cpu_number()) {
 	  PE_cpu_machine_init(proc_info->cpu_id, !(proc_info->cpu_flags & BootDone));
	  ml_init_interrupt();
	  proc_info->cpu_flags |= BootDone|SignalReady;

	  return KERN_SUCCESS;
	} else {
		proc_info->cpu_flags &= BootDone;
		proc_info->interrupts_enabled = 0;
		proc_info->pending_ast = AST_NONE;
		proc_info->istackptr = proc_info->intstack_top_ss;
		proc_info->rtcPop = EndOfAllTime;
		proc_info->FPU_owner = NULL;
		proc_info->VMX_owner = NULL;
		proc_info->pms.pmsStamp = 0;									/* Dummy transition time */
		proc_info->pms.pmsPop = EndOfAllTime;							/* Set the pop way into the future */
		proc_info->pms.pmsState = pmsParked;							/* Park the stepper */
		proc_info->pms.pmsCSetCmd = pmsCInit;							/* Set dummy initial hardware state */
		mp = (mapping_t *)(&proc_info->ppUMWmp);
		mp->mpFlags = 0x01000000 | mpLinkage | mpPerm | 1;
		mp->mpSpace = invalSpace;

		if (proc_info->start_paddr == EXCEPTION_VECTOR(T_RESET)) {

			simple_lock(&rht_lock);
			while (rht_state & RHT_BUSY) {
				rht_state |= RHT_WAIT;
				thread_sleep_usimple_lock((event_t)&rht_state,
						    &rht_lock, THREAD_UNINT);
			}
			rht_state |= RHT_BUSY;
			simple_unlock(&rht_lock);

			ml_phys_write((vm_offset_t)&ResetHandler + 0,
					  RESET_HANDLER_START);
			ml_phys_write((vm_offset_t)&ResetHandler + 4,
					  (vm_offset_t)_start_cpu);
			ml_phys_write((vm_offset_t)&ResetHandler + 8,
					  (vm_offset_t)&PerProcTable[cpu]);
		}
/*
 *		Note: we pass the current time to the other processor here. He will load it
 *		as early as possible so that there is a chance that it is close to accurate.
 *		After the machine is up a while, we will officially resync the clocks so
 *		that all processors are the same.  This is just to get close.
 */

		ml_get_timebase((unsigned long long *)&proc_info->ruptStamp);
		
		__asm__ volatile("sync");				/* Commit to storage */
		__asm__ volatile("isync");				/* Wait a second */
		ret = PE_cpu_start(proc_info->cpu_id,
						   proc_info->start_paddr, (vm_offset_t)proc_info);

		if (ret != KERN_SUCCESS) {
			if (proc_info->start_paddr == EXCEPTION_VECTOR(T_RESET)) {
				simple_lock(&rht_lock);
				if (rht_state & RHT_WAIT)
					thread_wakeup(&rht_state);
				rht_state &= ~(RHT_BUSY|RHT_WAIT);
				simple_unlock(&rht_lock);
			};
		} else {
			simple_lock(&SignalReadyLock);
			if (!((*(volatile short *)&proc_info->cpu_flags) & SignalReady)) {
				hw_atomic_or_noret(&proc_info->ppXFlags, SignalReadyWait);
				thread_sleep_simple_lock((event_t)&proc_info->cpu_flags,
				                          &SignalReadyLock, THREAD_UNINT);
			}
			simple_unlock(&SignalReadyLock);

		}
		return(ret);
	}
}

/*
 *	Routine:	cpu_exit_wait
 *	Function:
 */
void
cpu_exit_wait(
	int	cpu)
{
	struct per_proc_info	*tpproc;

	if ( cpu != master_cpu) {
		tpproc = PerProcTable[cpu].ppe_vaddr;
		while (!((*(volatile short *)&tpproc->cpu_flags) & SleepState)) {};
	}
}


/*
 *	Routine:	cpu_doshutdown
 *	Function:
 */
void
cpu_doshutdown(
	void)
{
	enable_preemption();
	processor_offline(current_processor());
}


/*
 *	Routine:	cpu_sleep
 *	Function:
 */
void
cpu_sleep(
	void)
{
	struct per_proc_info	*proc_info;
	unsigned int			i;
	unsigned int			wait_ncpus_sleep, ncpus_sleep;
	facility_context		*fowner;

	proc_info = getPerProc();

	proc_info->running = FALSE;

	timer_queue_shutdown(&proc_info->rtclock_timer.queue);
	proc_info->rtclock_timer.deadline = EndOfAllTime;

	fowner = proc_info->FPU_owner;					/* Cache this */
	if(fowner) /* If anyone owns FPU, save it */
		fpu_save(fowner);
	proc_info->FPU_owner = NULL;						/* Set no fpu owner now */

	fowner = proc_info->VMX_owner;					/* Cache this */
	if(fowner) vec_save(fowner);					/* If anyone owns vectors, save it */
	proc_info->VMX_owner = NULL;						/* Set no vector owner now */

	if (proc_info->cpu_number == master_cpu)  {
		proc_info->cpu_flags &= BootDone;
		proc_info->interrupts_enabled = 0;
		proc_info->pending_ast = AST_NONE;

		if (proc_info->start_paddr == EXCEPTION_VECTOR(T_RESET)) {
			ml_phys_write((vm_offset_t)&ResetHandler + 0,
					  RESET_HANDLER_START);
			ml_phys_write((vm_offset_t)&ResetHandler + 4,
					  (vm_offset_t)_start_cpu);
			ml_phys_write((vm_offset_t)&ResetHandler + 8,
					  (vm_offset_t)&PerProcTable[master_cpu]);

			__asm__ volatile("sync");
			__asm__ volatile("isync");
		}

		wait_ncpus_sleep = real_ncpus-1; 
		ncpus_sleep = 0;
		while (wait_ncpus_sleep != ncpus_sleep) {
			ncpus_sleep = 0;
			for(i=1; i < real_ncpus ; i++) {
				if ((*(volatile short *)&(PerProcTable[i].ppe_vaddr->cpu_flags)) & SleepState)
					ncpus_sleep++;
			}
		}

	}

	/*
	 * Save the TBR before stopping.
	 */
	do {
		proc_info->save_tbu = mftbu();
		proc_info->save_tbl = mftb();
	} while (mftbu() != proc_info->save_tbu);

	PE_cpu_machine_quiesce(proc_info->cpu_id);
}


/*
 *	Routine:	cpu_signal
 *	Function:
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

	unsigned int				holdStat;
	struct per_proc_info		*tpproc, *mpproc;
	int							busybitset=0;

#if DEBUG
	if(((unsigned int)target) >= MAX_CPUS) panic("cpu_signal: invalid target CPU - %08X\n", target);
#endif

	mpproc = getPerProc();							/* Point to our block */
	tpproc = PerProcTable[target].ppe_vaddr;		/* Point to the target's block */
	if(mpproc == tpproc) return KERN_FAILURE;		/* Cannot signal ourselves */

	if(!tpproc->running) return KERN_FAILURE;

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

	holdStat = MPsigpBusy | MPsigpPass | (MPsigpSigp << 8) | mpproc->cpu_number;	/* Set up the signal status word */
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


/*
 *	Routine:	cpu_signal_handler
 *	Function:
 *	Here is where we implement the receiver of the signaling protocol.
 *	We wait for the signal status area to be passed to us. Then we snarf
 *	up the status, the sender, and the 3 potential parms. Next we release
 *	the lock and signal the other guy.
 */
void 
cpu_signal_handler(void)
{
	unsigned int holdStat, holdParm0, holdParm1, holdParm2;
	unsigned int *parmAddr;
	struct per_proc_info	*proc_info;
	int cpu;
	broadcastFunc xfunc;
	cpu = cpu_number();								/* Get the CPU number */

	proc_info = getPerProc();

/*
 *	Since we've been signaled, wait about 31 ms for the signal lock to pass
 */
	if(!hw_lock_mbits(&proc_info->MPsigpStat, (MPsigpMsgp | MPsigpAck), (MPsigpBusy | MPsigpPass),
	  (MPsigpBusy | MPsigpPass | MPsigpAck), (gPEClockFrequencyInfo.timebase_frequency_hz >> 5))) {
		panic("cpu_signal_handler: Lock pass timed out\n");
	}
	
	holdStat = proc_info->MPsigpStat;				/* Snarf stat word */
	holdParm0 = proc_info->MPsigpParm0;				/* Snarf parameter */
	holdParm1 = proc_info->MPsigpParm1;				/* Snarf parameter */
	holdParm2 = proc_info->MPsigpParm2;				/* Snarf parameter */
	
	__asm__ volatile("isync");						/* Make sure we don't unlock until memory is in */

	proc_info->MPsigpStat = holdStat & ~(MPsigpMsgp | MPsigpAck | MPsigpFunc);	/* Release lock */

	switch ((holdStat & MPsigpFunc) >> 8) {			/* Decode function code */

		case MPsigpIdle:							/* Was function cancelled? */
			return;									/* Yup... */
			
		case MPsigpSigp:							/* Signal Processor message? */
			
			switch (holdParm0) {					/* Decode SIGP message order */

				case SIGPast:						/* Should we do an AST? */
					proc_info->hwCtr.numSIGPast++;		/* Count this one */
#if 0
					kprintf("cpu_signal_handler: AST check on cpu %x\n", cpu_number());
#endif
					ast_check((processor_t)proc_info->processor);
					return;							/* All done... */
					
				case SIGPcpureq:					/* CPU specific function? */
				
					proc_info->hwCtr.numSIGPcpureq++;	/* Count this one */
					switch (holdParm1) {			/* Select specific function */
					
						case CPRQtimebase:

							cpu_timebase_signal_handler(proc_info, (struct SIGtimebase *)holdParm2);
							return;

						case CPRQsegload:
							return;
						
 						case CPRQchud:
 							parmAddr = (unsigned int *)holdParm2;	/* Get the destination address */
 							if(perfCpuSigHook) {
 								struct savearea *ssp = current_thread()->machine.pcb;
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

						case CPRQsps:
							{
							ml_set_processor_speed_slave(holdParm2);
							return;
						}
						default:
							panic("cpu_signal_handler: unknown CPU request - %08X\n", holdParm1);
							return;
					}
					
	
				case SIGPdebug:						/* Enter the debugger? */		

					proc_info->hwCtr.numSIGPdebug++;	/* Count this one */
					proc_info->debugger_is_slave++;		/* Bump up the count to show we're here */
					(void)hw_atomic_sub(&debugger_sync, 1);	/* Show we've received the 'rupt */
					__asm__ volatile("tw 4,r3,r3");	/* Enter the debugger */
					return;							/* All done now... */
					
				case SIGPwake:						/* Wake up CPU */
					proc_info->hwCtr.numSIGPwake++;		/* Count this one */
					return;							/* No need to do anything, the interrupt does it all... */
					
				case SIGPcall:						/* Call function on CPU */
					proc_info->hwCtr.numSIGPcall++;	/* Count this one */
					xfunc = (broadcastFunc)holdParm1;				/* Do this since I can't seem to figure C out */
					xfunc(holdParm2);				/* Call the passed function */
					return;							/* Done... */
					
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
 *	Routine:	cpu_sync_timebase
 *	Function:
 */
void
cpu_sync_timebase(
	void)
{
	natural_t tbu, tbl;
	boolean_t	intr;
	struct SIGtimebase	syncClkSpot;

	intr = ml_set_interrupts_enabled(FALSE);		/* No interruptions in here */

	syncClkSpot.avail = FALSE;
	syncClkSpot.ready = FALSE;
	syncClkSpot.done = FALSE;

	while (cpu_signal(master_cpu, SIGPcpureq, CPRQtimebase,
							(unsigned int)&syncClkSpot) != KERN_SUCCESS)
		continue;

	while (syncClkSpot.avail == FALSE)
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

	while (syncClkSpot.done == FALSE)
		continue;

	etimer_resync_deadlines();									/* Start the timer */
	(void)ml_set_interrupts_enabled(intr);
}


/*
 *	Routine:	cpu_timebase_signal_handler
 *	Function:
 */
void
cpu_timebase_signal_handler(
	struct per_proc_info    *proc_info,
	struct SIGtimebase		*timebaseAddr)
{
	unsigned int		tbu, tbu2, tbl;

	if(proc_info->time_base_enable !=  (void(*)(cpu_id_t, boolean_t ))NULL)
		proc_info->time_base_enable(proc_info->cpu_id, FALSE);

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

	while (timebaseAddr->ready == FALSE)
		continue;

	if(proc_info->time_base_enable !=  (void(*)(cpu_id_t, boolean_t ))NULL)
		proc_info->time_base_enable(proc_info->cpu_id, TRUE);

	timebaseAddr->done = TRUE;
}


/*
 *	Routine:	cpu_control
 *	Function:
 */
kern_return_t
cpu_control(
	int			slot_num,
	processor_info_t	info,
	unsigned int    	count)
{
	struct per_proc_info	*proc_info;
	cpu_type_t		tcpu_type;
	cpu_subtype_t		tcpu_subtype;
	processor_pm_regs_t	perf_regs;
	processor_control_cmd_t	cmd;
	boolean_t		oldlevel;
#define MMCR0_SUPPORT_MASK	0xf83f1fff
#define MMCR1_SUPPORT_MASK	0xffc00000
#define MMCR2_SUPPORT_MASK	0x80000000

	proc_info = PerProcTable[slot_num].ppe_vaddr;
	tcpu_type = proc_info->cpu_type;
	tcpu_subtype = proc_info->cpu_subtype;
	cmd = (processor_control_cmd_t) info;

	if (count < PROCESSOR_CONTROL_CMD_COUNT)
	  return(KERN_FAILURE);

	if ( tcpu_type != cmd->cmd_cpu_type ||
	     tcpu_subtype != cmd->cmd_cpu_subtype)
	  return(KERN_FAILURE);

	if (perfmon_acquire_facility(current_task()) != KERN_SUCCESS) {
		return(KERN_RESOURCE_SHORTAGE); /* cpu performance facility in use by another task */
	}

	switch (cmd->cmd_op)
	  {
	  case PROCESSOR_PM_CLR_PMC:       /* Clear Performance Monitor Counters */
	    switch (tcpu_subtype)
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
	      } /* tcpu_subtype */
	  case PROCESSOR_PM_SET_REGS:      /* Set Performance Monitor Registors */
	    switch (tcpu_subtype)
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
	      } /* switch tcpu_subtype */
	  case PROCESSOR_PM_SET_MMCR:
	    switch (tcpu_subtype)
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
	      } /* tcpu_subtype */
	  default:
	    return(KERN_FAILURE);
	  } /* switch cmd_op */
}


/*
 *	Routine:	cpu_info_count
 *	Function:
 */
kern_return_t
cpu_info_count(
	processor_flavor_t	flavor,
	unsigned int    	*count)
{
	cpu_subtype_t     tcpu_subtype;

	/*
	 * For now, we just assume that all CPUs are of the same type
	 */
	tcpu_subtype = PerProcTable[master_cpu].ppe_vaddr->cpu_subtype;
	switch (flavor) {
		case PROCESSOR_PM_REGS_INFO:
			switch (tcpu_subtype) {
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
			} /* switch tcpu_subtype */

		case PROCESSOR_TEMPERATURE:
			*count = PROCESSOR_TEMPERATURE_COUNT;
			return (KERN_SUCCESS);

		default:
			*count = 0;
			return(KERN_INVALID_ARGUMENT);
			
	}
}


/*
 *	Routine:	cpu_info
 *	Function:
 */
kern_return_t
cpu_info(
	processor_flavor_t	flavor,
	int			slot_num,
	processor_info_t	info,
	unsigned int    	*count)
{
	cpu_subtype_t     tcpu_subtype;
	processor_pm_regs_t  perf_regs;
	boolean_t oldlevel;

	tcpu_subtype = PerProcTable[slot_num].ppe_vaddr->cpu_subtype;

	switch (flavor) {
		case PROCESSOR_PM_REGS_INFO:

			perf_regs = (processor_pm_regs_t) info;

			switch (tcpu_subtype) {
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
			} /* switch tcpu_subtype */

		case PROCESSOR_TEMPERATURE:					/* Get the temperature of a processor */

			*info = -1;								/* Get the temperature */
			return(KERN_FAILURE);

		default:
			return(KERN_INVALID_ARGUMENT);
			
	} /* flavor */
}


/*
 *	Routine:	cpu_to_processor
 *	Function:
 */
processor_t
cpu_to_processor(
	int			cpu)
{
	return ((processor_t)PerProcTable[cpu].ppe_vaddr->processor);
}


/*
 *	Routine:	slot_type
 *	Function:
 */
cpu_type_t
slot_type(
	int		slot_num)
{
	return (PerProcTable[slot_num].ppe_vaddr->cpu_type);
}


/*
 *	Routine:	slot_subtype
 *	Function:
 */
cpu_subtype_t
slot_subtype(
	int		slot_num)
{
	return (PerProcTable[slot_num].ppe_vaddr->cpu_subtype);
}


/*
 *	Routine:	slot_threadtype
 *	Function:
 */
cpu_threadtype_t
slot_threadtype(
	int		slot_num)
{
	return (PerProcTable[slot_num].ppe_vaddr->cpu_threadtype);
}


/*
 *	Routine:	cpu_type
 *	Function:
 */
cpu_type_t
cpu_type(void)
{
	return (getPerProc()->cpu_type);
}


/*
 *	Routine:	cpu_subtype
 *	Function:
 */
cpu_subtype_t
cpu_subtype(void)
{
	return (getPerProc()->cpu_subtype);
}


/*
 *	Routine:	cpu_threadtype
 *	Function:
 */
cpu_threadtype_t
cpu_threadtype(void)
{
	return (getPerProc()->cpu_threadtype);
}

/*
 *	Call a function on all running processors
 *
 *	Note that the synch paramter is used to wait until all functions are complete.
 *	It is not passed to the other processor and must be known by the called function.
 *	The called function must do a thread_wakeup on the synch if it decrements the
 *	synch count to 0.
 *
 *	We start by initializing the synchronizer to the number of possible cpus.
 *	The we signal each popssible processor.
 *	If the signal fails, we count it.  We also skip our own.
 *	When we are finished signaling, we adjust the syncronizer count down buy the number of failed signals.
 *	Because the signaled processors are also decrementing the synchronizer count, the adjustment may result in a 0
 *	If this happens, all other processors are finished with the function.
 *	If so, we clear the wait and continue
 *	Otherwise, we block waiting for the other processor(s) to finish.
 *
 *	Meanwhile, the other processors are decrementing the synchronizer when they are done
 *	If it goes to zero, thread_wakeup is called to run the broadcaster
 *
 *	Note that because we account for the broadcaster in the synchronization count, we will not get any
 *	premature wakeup calls.
 *
 *	Also note that when we do the adjustment of the synchronization count, it the result is 0, it means that
 *	all of the other processors are finished.  Otherwise, we know that there is at least one more. 
 *	When that thread decrements the synchronizer to zero, it will do a thread_wake.
 *	
 */

int32_t
cpu_broadcast(uint32_t *synch, broadcastFunc func, uint32_t parm)
{
	int failsig;
	unsigned int cpu, ocpu;
	
	cpu = cpu_number();						/* Who are we? */
	failsig = 0;							/* Clear called processor count */
	
	if(real_ncpus > 1) {						/* Are we just a uni? */
		
		*synch = real_ncpus;					/* Set how many we are going to try */
		assert_wait((event_t)synch, THREAD_UNINT);		/* If more than one processor, we may have to wait */
		
		for(ocpu = 0; ocpu < real_ncpus; ocpu++) {		/* Tell everyone to call */
			
			if(ocpu == cpu)	continue;			/* If we talk to ourselves, people will wonder... */
			
			if(KERN_SUCCESS != cpu_signal(ocpu, SIGPcall, (uint32_t)func, parm)) {	/* Call the function on the other processor */
				failsig++;				/* Count failed signals */
			}
		}
		
		if (hw_atomic_sub(synch, failsig + 1) == 0)
			clear_wait(current_thread(), THREAD_AWAKENED);	/* Clear wait if we never signalled or all of the others finished */
		else
			thread_block(THREAD_CONTINUE_NULL);		/* Wait for everyone to get into step... */
	}
	
	return (real_ncpus - failsig - 1);				/* Return the number of guys actually signalled... */
}
