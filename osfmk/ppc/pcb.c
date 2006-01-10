/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Copyright (c) 1990,1991,1992 The University of Utah and
 * the Center for Software Science (CSS).  All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software is hereby
 * granted provided that (1) source code retains these copyright, permission,
 * and disclaimer notices, and (2) redistributions including binaries
 * reproduce the notices in supporting documentation, and (3) all advertising
 * materials mentioning features or use of this software display the following
 * acknowledgement: ``This product includes software developed by the Center
 * for Software Science at the University of Utah.''
 *
 * THE UNIVERSITY OF UTAH AND CSS ALLOW FREE USE OF THIS SOFTWARE IN ITS "AS
 * IS" CONDITION.  THE UNIVERSITY OF UTAH AND CSS DISCLAIM ANY LIABILITY OF
 * ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * CSS requests users of this software to return to css-dist@cs.utah.edu any
 * improvements that they make and grant CSS redistribution rights.
 *
 * 	Utah $Hdr: pcb.c 1.23 92/06/27$
 */

#include <debug.h>

#include <types.h>

#include <mach/mach_types.h>
#include <mach/thread_status.h>

#include <kern/kern_types.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/misc_protos.h>
#include <kern/mach_param.h>
#include <kern/spl.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <ppc/misc_protos.h>
#include <ppc/cpu_internal.h>
#include <ppc/exception.h>
#include <ppc/proc_reg.h>
#include <ppc/pmap.h>
#include <ppc/trap.h>
#include <ppc/mappings.h>
#include <ppc/savearea.h>
#include <ppc/Firmware.h>
#include <ppc/asm.h>
#include <ppc/thread.h>
#include <ppc/vmachmon.h>
#include <ppc/low_trace.h>
#include <ppc/lowglobals.h>

#include <sys/kdebug.h>

void	machine_act_terminate(thread_t);

/*
 * These constants are dumb. They should not be in asm.h!
 */

#define KF_SIZE		(FM_SIZE+ARG_SIZE+FM_REDZONE)

#if DEBUG
int   fpu_trap_count = 0;
int   fpu_switch_count = 0;
int   vec_trap_count = 0;
int   vec_switch_count = 0;
#endif

/*
 * consider_machine_collect: try to collect machine-dependent pages
 */
void
consider_machine_collect()
{
    /*
     * none currently available
     */
	return;
}

void
consider_machine_adjust()
{
        consider_mapping_adjust();
}

/*
 * switch_context: Switch from one thread to another, needed for
 * 		   switching of space
 * 
 */
thread_t
machine_switch_context(
	thread_t			old,
	thread_continue_t	continuation,
	thread_t			new)
{
	register thread_t retval;
	pmap_t	new_pmap;
	facility_context *fowner;
	struct per_proc_info *ppinfo;

	if (old == new)
		panic("machine_switch_context");

	ppinfo = getPerProc();								/* Get our processor block */

	ppinfo->old_thread = (unsigned int)old;
	ppinfo->cpu_flags &= ~traceBE; 						 /* disable branch tracing if on */
	       
	/* Our context might wake up on another processor, so we must
	 * not keep hot state in our FPU, it must go back to the pcb
	 * so that it can be found by the other if needed
	 */
	if(real_ncpus > 1) {								/* This is potentially slow, so only do when actually SMP */
		fowner = ppinfo->FPU_owner;						/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old) {		/* Is it for us? */
				fpu_save(fowner);						/* Yes, save it */
			}
		}
		fowner = ppinfo->VMX_owner;						/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old) {		/* Is it for us? */
				vec_save(fowner);						/* Yes, save it */
			}
		}
	}

	/*
	 * If old thread is running VM, save per proc userProtKey and FamVMmode spcFlags bits in the thread spcFlags
 	 * This bits can be modified in the per proc without updating the thread spcFlags
	 */
	if(old->machine.specFlags & runningVM) {
		old->machine.specFlags &=  ~(userProtKey|FamVMmode);
		old->machine.specFlags |= (ppinfo->spcFlags) & (userProtKey|FamVMmode);
	}
	old->machine.specFlags &= ~OnProc;
	new->machine.specFlags |= OnProc;

	/*
	 * We do not have to worry about the PMAP module, so switch.
	 *
	 * We must not use thread->map since this may not be the actual
	 * task map, but the map being used for a klcopyin/out.
	 */

	if(new->machine.specFlags & runningVM) {			/* Is the new guy running a VM? */
		pmap_switch(new->machine.vmmCEntry->vmmPmap);	/* Switch to the VM's pmap */
		ppinfo->VMMareaPhys = new->machine.vmmCEntry->vmmContextPhys;
		ppinfo->VMMXAFlgs = new->machine.vmmCEntry->vmmXAFlgs;
		ppinfo->FAMintercept = new->machine.vmmCEntry->vmmFAMintercept;
	}
	else {												/* otherwise, we use the task's pmap */
		new_pmap = new->task->map->pmap;
		if ((old->task->map->pmap != new_pmap) || (old->machine.specFlags & runningVM)) {
			pmap_switch(new_pmap);						/* Switch if there is a change */
		}
	}

	if(old->machine.umwSpace != invalSpace) {			/* Does our old guy have an active window? */
		old->machine.umwSpace |= umwSwitchAway;			/* Show we switched away from this guy */
		hw_blow_seg(lowGlo.lgUMWvaddr);					/* Blow off the first segment */
		hw_blow_seg(lowGlo.lgUMWvaddr + 0x10000000ULL);	/* Blow off the second segment */
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_SCHED) | DBG_FUNC_NONE,
		     old->reason, (int)new, old->sched_pri, new->sched_pri, 0);

	retval = Switch_context(old, continuation, new);
	assert(retval != NULL);

	if (branch_tracing_enabled()) {
		ppinfo = getPerProc();							/* Get our processor block */
	  	ppinfo->cpu_flags |= traceBE;  					/* restore branch tracing */
	}

	/* We've returned from having switched context, so we should be
	 * back in the original context.
	 */

	return retval;
}

/*
 * Initialize the machine-dependent state for a new thread.
 */
kern_return_t
machine_thread_create(
	thread_t		thread,
	task_t			task)
{
	savearea		*sv;									/* Pointer to newly allocated savearea */
	unsigned int	*CIsTooLimited, i;

	hw_atomic_add((uint32_t *)&saveanchor.savetarget, 4);	/* Account for the number of saveareas we think we "need"
															   for this activation */
	assert(thread->machine.pcb == (savearea *)0);				/* Make sure there was no previous savearea */
	
	sv = save_alloc();										/* Go get us a savearea */
		
	bzero((char *)((unsigned int)sv + sizeof(savearea_comm)), (sizeof(savearea) - sizeof(savearea_comm)));	/* Clear it */
		
	sv->save_hdr.save_prev = 0;								/* Clear the back pointer */
	sv->save_hdr.save_flags = (sv->save_hdr.save_flags & ~SAVtype) | (SAVgeneral << SAVtypeshft);	/* Mark as in use */
	sv->save_hdr.save_act = thread;	/* Set who owns it */
	thread->machine.pcb = sv;									/* Point to the save area */
	thread->machine.curctx = &thread->machine.facctx;			/* Initialize facility context */
	thread->machine.facctx.facAct = thread;						/* Initialize facility context pointer to activation */
	thread->machine.umwSpace = invalSpace;						/* Initialize user memory window space to invalid */
	thread->machine.preemption_count = 0;						/* Initialize preemption counter */

	/*
	 * User threads will pull their context from the pcb when first
	 * returning to user mode, so fill in all the necessary values.
	 * Kernel threads are initialized from the save state structure 
	 * at the base of the kernel stack (see stack_attach()).
	 */

	thread->machine.upcb = sv;								/* Set user pcb */
	sv->save_srr1 = (uint64_t)MSR_EXPORT_MASK_SET;			/* Set the default user MSR */
	if(task_has_64BitAddr(task)) sv->save_srr1 |= (uint64_t)MASK32(MSR_SF) << 32;	/* If 64-bit task, force 64-bit mode */
	sv->save_fpscr = 0;										/* Clear all floating point exceptions */
	sv->save_vrsave = 0;									/* Set the vector save state */
	sv->save_vscr[0] = 0x00000000;					
	sv->save_vscr[1] = 0x00000000;					
	sv->save_vscr[2] = 0x00000000;					
	sv->save_vscr[3] = 0x00010000;							/* Disable java mode and clear saturated */
	
    return(KERN_SUCCESS);
}

/*
 * Machine-dependent cleanup prior to destroying a thread
 */
void
machine_thread_destroy(
	thread_t		thread)
{
	register savearea *pcb, *ppsv;
	register savearea_vec *vsv, *vpsv;
	register savearea_fpu *fsv, *fpsv;
	register savearea *svp;
	register int i;
 	boolean_t intr;

/*
 *	This function will release all context.
 */

	machine_act_terminate(thread);							/* Make sure all virtual machines are dead first */
 
/*
 *
 *	Walk through and release all floating point and vector contexts. Also kill live context.
 *
 */

	intr = ml_set_interrupts_enabled(FALSE);				/* Disable for interruptions */
 
 	toss_live_vec(thread->machine.curctx);					/* Dump live vectors */

	vsv = thread->machine.curctx->VMXsave;					/* Get the top vector savearea */
	
	while(vsv) {											/* Any VMX saved state? */
		vpsv = vsv;											/* Remember so we can toss this */
		vsv = CAST_DOWN(savearea_vec *, vsv->save_hdr.save_prev);  /* Get one underneath our's */
		save_release((savearea *)vpsv);						/* Release it */
	}
	
	thread->machine.curctx->VMXsave = 0;					/* Kill chain */
 
 	toss_live_fpu(thread->machine.curctx);					/* Dump live float */

	fsv = thread->machine.curctx->FPUsave;					/* Get the top float savearea */
	
	while(fsv) {											/* Any float saved state? */
		fpsv = fsv;											/* Remember so we can toss this */
		fsv = CAST_DOWN(savearea_fpu *, fsv->save_hdr.save_prev);   /* Get one underneath our's */
		save_release((savearea *)fpsv);						/* Release it */
	}
	
	thread->machine.curctx->FPUsave = 0;					/* Kill chain */

/*
 * free all regular saveareas.
 */

	pcb = thread->machine.pcb;								/* Get the general savearea */
	
	while(pcb) {											/* Any float saved state? */
		ppsv = pcb;											/* Remember so we can toss this */
		pcb = CAST_DOWN(savearea *, pcb->save_hdr.save_prev);  /* Get one underneath our's */ 
		save_release(ppsv);									/* Release it */
	}
	
	hw_atomic_sub((uint32_t *)&saveanchor.savetarget, 4);	/* Unaccount for the number of saveareas we think we "need" */

	(void) ml_set_interrupts_enabled(intr);					/* Restore interrupts if enabled */

}

/*
 * act_machine_sv_free
 * release saveareas associated with an act. if flag is true, release
 * user level savearea(s) too, else don't
 *
 * This code must run with interruptions disabled because an interrupt handler could use
 * floating point and/or vectors.  If this happens and the thread we are blowing off owns
 * the facility, we can deadlock.
 */
void
act_machine_sv_free(thread_t act)
{
	register savearea *pcb, *userpcb;
	register savearea_vec *vsv, *vpst, *vsvt;
	register savearea_fpu *fsv, *fpst, *fsvt;
	register savearea *svp;
	register int i;
 	boolean_t intr;

/*
 *	This function will release all non-user state context.
 */
 
/*
 *
 *	Walk through and release all floating point and vector contexts that are not
 *	user state.  We will also blow away live context if it belongs to non-user state.
 *	Note that the level can not change while we are in this code.  Nor can another
 *	context be pushed on the stack.
 *
 *	We do nothing here if the current level is user.  Otherwise,
 *	the live context is cleared.  Then we find the user saved context.
 *	Next,  we take the sync lock (to keep us from munging things in *_switch).
 *	The level is set to 0 and all stacked context other than user is dequeued.
 *	Then we unlock.  Next, all of the old kernel contexts are released.
 *
 */

	intr = ml_set_interrupts_enabled(FALSE);				/* Disable for interruptions */

 	if(act->machine.curctx->VMXlevel) {						/* Is the current level user state? */
 		
 		toss_live_vec(act->machine.curctx);					/* Dump live vectors if is not user */
		
		if(!hw_lock_to((hw_lock_t)&act->machine.curctx->VMXsync, LockTimeOut)) {	/* Get the sync lock */ 
			panic("act_machine_sv_free - timeout getting VMX sync lock\n");	/* Tell all and die */
		}
	
		vsv = act->machine.curctx->VMXsave;					/* Get the top vector savearea */
		while(vsv && vsv->save_hdr.save_level) vsv = (savearea_vec *)vsv->save_hdr.save_prev;	/* Find user context if any */
		
		vsvt = act->machine.curctx->VMXsave;				/* Get the top of the chain */
		act->machine.curctx->VMXsave = vsv;					/* Point to the user context */
		act->machine.curctx->VMXlevel = 0;					/* Set the level to user */
		hw_lock_unlock((hw_lock_t)&act->machine.curctx->VMXsync);	/* Unlock */
		
		while(vsvt) {										/* Clear any VMX saved state */
			if (vsvt == vsv) break;   						/* Done when hit user if any */
			vpst = vsvt;									/* Remember so we can toss this */
			vsvt = (savearea_vec *)vsvt->save_hdr.save_prev;	/* Get one underneath our's */		
			save_ret((savearea *)vpst);						/* Release it */
		}
		
	}
 
 	if(act->machine.curctx->FPUlevel) {						/* Is the current level user state? */
 		
 		toss_live_fpu(act->machine.curctx);					/* Dump live floats if is not user */

		if(!hw_lock_to((hw_lock_t)&act->machine.curctx->FPUsync, LockTimeOut)) {	/* Get the sync lock */ 
			panic("act_machine_sv_free - timeout getting FPU sync lock\n");	/* Tell all and die */
		}
		
		fsv = act->machine.curctx->FPUsave;					/* Get the top floats savearea */
		while(fsv && fsv->save_hdr.save_level) fsv = (savearea_fpu *)fsv->save_hdr.save_prev;	/* Find user context if any */
		
		fsvt = act->machine.curctx->FPUsave;				/* Get the top of the chain */
		act->machine.curctx->FPUsave = fsv;					/* Point to the user context */
		act->machine.curctx->FPUlevel = 0;					/* Set the level to user */
		hw_lock_unlock((hw_lock_t)&act->machine.curctx->FPUsync);	/* Unlock */
		
		while(fsvt) {										/* Clear any VMX saved state */
			if (fsvt == fsv) break;   						/* Done when hit user if any */
			fpst = fsvt;									/* Remember so we can toss this */
			fsvt = (savearea_fpu *)fsvt->save_hdr.save_prev;	/* Get one underneath our's */		
			save_ret((savearea *)fpst);						/* Release it */
		}
		
	}

/*
 * free all regular saveareas except a user savearea, if any
 */

	pcb = act->machine.pcb;									/* Get the general savearea */
	userpcb = 0;											/* Assume no user context for now */
	
	while(pcb) {											/* Any float saved state? */
		if (pcb->save_srr1 & MASK(MSR_PR)) {				/* Is this a user savearea? */
			userpcb = pcb;									/* Remember so we can toss this */
			break;
		}
		svp = pcb;											/* Remember this */
		pcb = CAST_DOWN(savearea *, pcb->save_hdr.save_prev);  /* Get one underneath our's */ 
		save_ret(svp);										/* Release it */
	}
	
	act->machine.pcb = userpcb;								/* Chain in the user if there is one, or 0 if not */
	(void) ml_set_interrupts_enabled(intr);					/* Restore interrupts if enabled */

}

void
machine_act_terminate(
	thread_t	act)
{
	if(act->machine.bbDescAddr) {							/* Check if the Blue box assist is active */
		disable_bluebox_internal(act);						/* Kill off bluebox */
	}
	
	if(act->machine.vmmControl) {							/* Check if VMM is active */
		vmm_tear_down_all(act);								/* Kill off all VMM contexts */
	}
}

void
machine_thread_terminate_self(void)
{
	machine_act_terminate(current_thread());
}

void
machine_thread_init(void)
{
#ifdef	MACHINE_STACK
#if KERNEL_STACK_SIZE > PPC_PGBYTES
	panic("KERNEL_STACK_SIZE can't be greater than PPC_PGBYTES\n");
#endif
#endif
}

#if MACH_ASSERT

void
dump_thread(thread_t th)
{
	printf(" thread @ 0x%x:\n", th);
}

int
    dump_act(thread_t thr_act)
{
    if (!thr_act)
	return(0);

    printf("thread(0x%x)(%d): task=%x(%d)\n",
	   thr_act, thr_act->ref_count,
	   thr_act->task,   thr_act->task   ? thr_act->task->ref_count : 0);

    printf("\tsusp=%x active=%x\n",
	   thr_act->suspend_count, thr_act->active);

    return((int)thr_act);
}

#endif

user_addr_t 
get_useraddr()
{
	return(current_thread()->machine.upcb->save_srr0);
}

/*
 * detach and return a kernel stack from a thread
 */

vm_offset_t
machine_stack_detach(
	thread_t		thread)
{
  vm_offset_t stack;

  KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_DETACH),
											thread, thread->priority,
											thread->sched_pri, 0, 0);

  act_machine_sv_free(thread);

  stack = thread->kernel_stack;
  thread->kernel_stack = 0;
  return(stack);
}

/*
 * attach a kernel stack to a thread and initialize it
 *
 * attaches a stack to a thread. if there is no save
 * area we allocate one.  the top save area is then
 * loaded with the pc (continuation address), the initial
 * stack pointer, and a std kernel MSR. if the top
 * save area is the user save area bad things will 
 * happen
 *
 */

void
machine_stack_attach(
	thread_t		thread,
	vm_offset_t		stack)
{
  unsigned int *kss;
  struct savearea *sv;

        KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_ATTACH),
            thread, thread->priority,
            thread->sched_pri, 0, 0);

  assert(stack);
  kss = (unsigned int *)STACK_IKS(stack);
  thread->kernel_stack = stack;

  /* during initialization we sometimes do not have an
     activation. in that case do not do anything */
  sv = save_get();  /* cannot block */
  sv->save_hdr.save_flags = (sv->save_hdr.save_flags & ~SAVtype) | (SAVgeneral << SAVtypeshft);	/* Mark as in use */
  sv->save_hdr.save_act = thread;
  sv->save_hdr.save_prev = (addr64_t)((uintptr_t)thread->machine.pcb);
  thread->machine.pcb = sv;

  sv->save_srr0 = (unsigned int)thread_continue;
  /* sv->save_r3 = ARG ? */
  sv->save_r1 = (vm_offset_t)((int)kss - KF_SIZE);
  sv->save_srr1 = MSR_SUPERVISOR_INT_OFF;
  sv->save_fpscr = 0;									/* Clear all floating point exceptions */
  sv->save_vrsave = 0;								/* Set the vector save state */
  sv->save_vscr[3] = 0x00010000;						/* Supress java mode */
  *(CAST_DOWN(int *, sv->save_r1)) = 0;

  thread->machine.ksp = 0;			      
}

/*
 * move a stack from old to new thread
 */

void
machine_stack_handoff(
	thread_t		old,
	thread_t		new)
{

	vm_offset_t stack;
	pmap_t new_pmap;
	facility_context *fowner;
	mapping_t *mp;
	struct per_proc_info *ppinfo;
	
	assert(new);
	assert(old);

	if (old == new)
		panic("machine_stack_handoff");
	
	stack = machine_stack_detach(old);
	new->kernel_stack = stack;
	if (stack == old->reserved_stack) {
		assert(new->reserved_stack);
		old->reserved_stack = new->reserved_stack;
		new->reserved_stack = stack;
	}

	ppinfo = getPerProc();								/* Get our processor block */

	ppinfo->cpu_flags &= ~traceBE;						/* Turn off special branch trace */

	if(real_ncpus > 1) {								/* This is potentially slow, so only do when actually SMP */
		fowner = ppinfo->FPU_owner;						/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old) {		/* Is it for us? */
				fpu_save(fowner);						/* Yes, save it */
			}
		}
		fowner = ppinfo->VMX_owner;						/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old) {		/* Is it for us? */
				vec_save(fowner);						/* Yes, save it */
			}
		}
	}

	/*
	 * If old thread is running VM, save per proc userProtKey and FamVMmode spcFlags bits in the thread spcFlags
 	 * This bits can be modified in the per proc without updating the thread spcFlags
	 */
	if(old->machine.specFlags & runningVM) {			/* Is the current thread running a VM? */
		old->machine.specFlags &= ~(userProtKey|FamVMmode);
		old->machine.specFlags |= (ppinfo->spcFlags) & (userProtKey|FamVMmode);
	}
	old->machine.specFlags &= ~OnProc;
	new->machine.specFlags |= OnProc;

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_HANDOFF) | DBG_FUNC_NONE,
		     old->reason, (int)new, old->sched_pri, new->sched_pri, 0);


	if(new->machine.specFlags & runningVM) {	/* Is the new guy running a VM? */
		pmap_switch(new->machine.vmmCEntry->vmmPmap);	/* Switch to the VM's pmap */
		ppinfo->VMMareaPhys = new->machine.vmmCEntry->vmmContextPhys;
		ppinfo->VMMXAFlgs = new->machine.vmmCEntry->vmmXAFlgs;
		ppinfo->FAMintercept = new->machine.vmmCEntry->vmmFAMintercept;
	}
	else {											/* otherwise, we use the task's pmap */
		new_pmap = new->task->map->pmap;
		if ((old->task->map->pmap != new_pmap) || (old->machine.specFlags & runningVM)) {
			pmap_switch(new_pmap);
		}
	}

	machine_set_current_thread(new);
	ppinfo->Uassist = new->machine.cthread_self;

	ppinfo->ppbbTaskEnv = new->machine.bbTaskEnv;
	ppinfo->spcFlags = new->machine.specFlags;
	
	old->machine.umwSpace |= umwSwitchAway;			/* Show we switched away from this guy */
	mp = (mapping_t *)&ppinfo->ppUMWmp;
	mp->mpSpace = invalSpace;						/* Since we can't handoff in the middle of copy in/out, just invalidate */

	if (branch_tracing_enabled()) 
		ppinfo->cpu_flags |= traceBE;
    
	if(trcWork.traceMask) dbgTrace(0x9903, (unsigned int)old, (unsigned int)new, 0, 0);	/* Cut trace entry if tracing */    
    
  return;
}

/*
 * clean and initialize the current kernel stack and go to
 * the given continuation routine
 */

void
call_continuation(
	thread_continue_t	continuation,
	void				*parameter,
	wait_result_t		wresult)
{
	thread_t		self = current_thread();
	unsigned int	*kss;
	vm_offset_t		tsp;

	assert(self->kernel_stack);
	kss = (unsigned int *)STACK_IKS(self->kernel_stack);
	assert(continuation);

	tsp = (vm_offset_t)((int)kss - KF_SIZE);
	assert(tsp);
	*((int *)tsp) = 0;

	Call_continuation(continuation, parameter, wresult, tsp);
}
