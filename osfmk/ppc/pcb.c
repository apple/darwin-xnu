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

#include <cpus.h>
#include <debug.h>

#include <types.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/thread_act.h>
#include <kern/thread_swap.h>
#include <mach/thread_status.h>
#include <vm/vm_kern.h>
#include <kern/mach_param.h>

#include <kern/misc_protos.h>
#include <ppc/misc_protos.h>
#include <ppc/exception.h>
#include <ppc/proc_reg.h>
#include <kern/spl.h>
#include <ppc/pmap.h>
#include <ppc/trap.h>
#include <ppc/mappings.h>
#include <ppc/savearea.h>
#include <ppc/Firmware.h>
#include <ppc/asm.h>
#include <ppc/thread_act.h>
#include <ppc/vmachmon.h>
#include <ppc/low_trace.h>

#include <sys/kdebug.h>

extern int 		real_ncpus;						/* Number of actual CPUs */
extern struct	Saveanchor saveanchor;			/* Aliged savearea anchor */

void	machine_act_terminate(thread_act_t	act);

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
	register thread_act_t old_act = old->top_act, new_act = new->top_act;
	register thread_t retval;
	pmap_t	new_pmap;
	facility_context *fowner;
	struct per_proc_info *ppinfo;

	if (old == new)
		panic("machine_switch_context");

	ppinfo = getPerProc();								/* Get our processor block */

	ppinfo->old_thread = (unsigned int)old;
	ppinfo->cpu_flags &= ~traceBE; 						 /* disable branch tracing if on */
	       
	check_simple_locks();

	/* Our context might wake up on another processor, so we must
	 * not keep hot state in our FPU, it must go back to the pcb
	 * so that it can be found by the other if needed
	 */
	if(real_ncpus > 1) {								/* This is potentially slow, so only do when actually SMP */
		fowner = ppinfo->FPU_owner;						/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old->top_act) {		/* Is it for us? */
				fpu_save(fowner);						/* Yes, save it */
			}
		}
		fowner = ppinfo->VMX_owner;						/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old->top_act) {		/* Is it for us? */
				vec_save(fowner);						/* Yes, save it */
			}
		}
	}

	/*
	 * If old thread is running VM, save per proc userProtKey and FamVMmode spcFlags bits in the thread spcFlags
 	 * This bits can be modified in the per proc without updating the thread spcFlags
	 */
	if(old_act->mact.specFlags & runningVM) {
		old_act->mact.specFlags &=  ~(userProtKey|FamVMmode);
		old_act->mact.specFlags |= (ppinfo->spcFlags) & (userProtKey|FamVMmode);
	}
	old_act->mact.specFlags &= ~OnProc;
	new_act->mact.specFlags |= OnProc;

	/*
	 * We do not have to worry about the PMAP module, so switch.
	 *
	 * We must not use top_act->map since this may not be the actual
	 * task map, but the map being used for a klcopyin/out.
	 */

	if(new_act->mact.specFlags & runningVM) {			/* Is the new guy running a VM? */
		pmap_switch(new_act->mact.vmmCEntry->vmmPmap);	/* Switch to the VM's pmap */
		ppinfo->VMMareaPhys = new_act->mact.vmmCEntry->vmmContextPhys;
		ppinfo->VMMXAFlgs = new_act->mact.vmmCEntry->vmmXAFlgs;
		ppinfo->FAMintercept = new_act->mact.vmmCEntry->vmmFAMintercept;
	}
	else {												/* otherwise, we use the task's pmap */
		new_pmap = new_act->task->map->pmap;
		if ((old_act->task->map->pmap != new_pmap) || (old_act->mact.specFlags & runningVM)) {
			pmap_switch(new_pmap);						/* Switch if there is a change */
		}
	}

	if(old_act->mact.cioSpace != invalSpace) {			/* Does our old guy have an active copyin/out? */
		old_act->mact.cioSpace |= cioSwitchAway;		/* Show we switched away from this guy */
		hw_blow_seg(copyIOaddr);						/* Blow off the first segment */
		hw_blow_seg(copyIOaddr + 0x10000000ULL);		/* Blow off the second segment */
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_SCHED) | DBG_FUNC_NONE,
		     old->reason, (int)new, old->sched_pri, new->sched_pri, 0);

	retval = Switch_context(old, continuation, new);
	assert(retval != (struct thread_shuttle*)NULL);

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
	assert(thread->mact.pcb == (savearea *)0);				/* Make sure there was no previous savearea */
	
	sv = save_alloc();										/* Go get us a savearea */
		
	bzero((char *)((unsigned int)sv + sizeof(savearea_comm)), (sizeof(savearea) - sizeof(savearea_comm)));	/* Clear it */
		
	sv->save_hdr.save_prev = 0;								/* Clear the back pointer */
	sv->save_hdr.save_flags = (sv->save_hdr.save_flags & ~SAVtype) | (SAVgeneral << SAVtypeshft);	/* Mark as in use */
	sv->save_hdr.save_act = (struct thread_activation *)thread;	/* Set who owns it */
	thread->mact.pcb = sv;									/* Point to the save area */
	thread->mact.curctx = &thread->mact.facctx;				/* Initialize facility context */
	thread->mact.facctx.facAct = thread;					/* Initialize facility context pointer to activation */
	thread->mact.cioSpace = invalSpace;						/* Initialize copyin/out space to invalid */
	thread->mact.preemption_count = 0;						/* Initialize preemption counter */

	/*
	 * User threads will pull their context from the pcb when first
	 * returning to user mode, so fill in all the necessary values.
	 * Kernel threads are initialized from the save state structure 
	 * at the base of the kernel stack (see stack_attach()).
	 */

	thread->mact.upcb = sv;									/* Set user pcb */
	sv->save_srr1 = (uint64_t)MSR_EXPORT_MASK_SET;			/* Set the default user MSR */
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

/*
 *	This function will release all context.
 */

	machine_act_terminate(thread);							/* Make sure all virtual machines are dead first */
 
/*
 *
 *	Walk through and release all floating point and vector contexts. Also kill live context.
 *
 */
 
 	toss_live_vec(thread->mact.curctx);						/* Dump live vectors */

	vsv = thread->mact.curctx->VMXsave;						/* Get the top vector savearea */
	
	while(vsv) {											/* Any VMX saved state? */
		vpsv = vsv;											/* Remember so we can toss this */
		vsv = CAST_DOWN(savearea_vec *, vsv->save_hdr.save_prev);  /* Get one underneath our's */
		save_release((savearea *)vpsv);						/* Release it */
	}
	
	thread->mact.curctx->VMXsave = 0;							/* Kill chain */
 
 	toss_live_fpu(thread->mact.curctx);						/* Dump live float */

	fsv = thread->mact.curctx->FPUsave;						/* Get the top float savearea */
	
	while(fsv) {											/* Any float saved state? */
		fpsv = fsv;											/* Remember so we can toss this */
		fsv = CAST_DOWN(savearea_fpu *, fsv->save_hdr.save_prev);   /* Get one underneath our's */
		save_release((savearea *)fpsv);						/* Release it */
	}
	
	thread->mact.curctx->FPUsave = 0;							/* Kill chain */

/*
 * free all regular saveareas.
 */

	pcb = thread->mact.pcb;									/* Get the general savearea */
	
	while(pcb) {											/* Any float saved state? */
		ppsv = pcb;											/* Remember so we can toss this */
		pcb = CAST_DOWN(savearea *, pcb->save_hdr.save_prev);  /* Get one underneath our's */ 
		save_release(ppsv);									/* Release it */
	}
	
	hw_atomic_sub((uint32_t *)&saveanchor.savetarget, 4);	/* Unaccount for the number of saveareas we think we "need" */
}

/*
 * Number of times we needed to swap an activation back in before
 * switching to it.
 */
int switch_act_swapins = 0;

/*
 * machine_switch_act
 *
 * Machine-dependent details of activation switching.  Called with
 * RPC locks held and preemption disabled.
 */
void
machine_switch_act( 
	thread_t		thread,
	thread_act_t	old,
	thread_act_t	new)
{
	pmap_t		new_pmap;
	facility_context *fowner;
	struct per_proc_info *ppinfo;
	
	ppinfo = getPerProc();								/* Get our processor block */

	/* Our context might wake up on another processor, so we must
	 * not keep hot state in our FPU, it must go back to the pcb
	 * so that it can be found by the other if needed
	 */
	if(real_ncpus > 1) {								/* This is potentially slow, so only do when actually SMP */
		fowner = ppinfo->FPU_owner;						/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old) {					/* Is it for us? */
				fpu_save(fowner);						/* Yes, save it */
			}
		}
		fowner = ppinfo->VMX_owner;						/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old) {					/* Is it for us? */
				vec_save(fowner);						/* Yes, save it */
			}
		}
	}

	old->mact.cioSpace |= cioSwitchAway;				/* Show we switched away from this guy */

	ast_context(new, cpu_number());

	/* Activations might have different pmaps 
	 * (process->kernel->server, for example).
	 * Change space if needed
	 */

	if(new->mact.specFlags & runningVM) {			/* Is the new guy running a VM? */
		pmap_switch(new->mact.vmmCEntry->vmmPmap);	/* Switch to the VM's pmap */
	}
	else {												/* otherwise, we use the task's pmap */
		new_pmap = new->task->map->pmap;
		if ((old->task->map->pmap != new_pmap)  || (old->mact.specFlags & runningVM)) {
			pmap_switch(new_pmap);
		}
	}

}

/*
 * act_machine_sv_free
 * release saveareas associated with an act. if flag is true, release
 * user level savearea(s) too, else don't
 *
 * this code cannot block so we call the proper save area free routine
 */
void
act_machine_sv_free(thread_act_t act)
{
	register savearea *pcb, *userpcb;
	register savearea_vec *vsv, *vpst, *vsvt;
	register savearea_fpu *fsv, *fpst, *fsvt;
	register savearea *svp;
	register int i;

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
 
 	if(act->mact.curctx->VMXlevel) {						/* Is the current level user state? */
 		
 		toss_live_vec(act->mact.curctx);					/* Dump live vectors if is not user */

		vsv = act->mact.curctx->VMXsave;					/* Get the top vector savearea */
		
		while(vsv && vsv->save_hdr.save_level) vsv = (savearea_vec *)vsv->save_hdr.save_prev;	/* Find user context if any */
	
		if(!hw_lock_to((hw_lock_t)&act->mact.curctx->VMXsync, LockTimeOut)) {	/* Get the sync lock */ 
			panic("act_machine_sv_free - timeout getting VMX sync lock\n");	/* Tell all and die */
		}
		
		vsvt = act->mact.curctx->VMXsave;					/* Get the top of the chain */
		act->mact.curctx->VMXsave = vsv;					/* Point to the user context */
		act->mact.curctx->VMXlevel = 0;						/* Set the level to user */
		hw_lock_unlock((hw_lock_t)&act->mact.curctx->VMXsync);	/* Unlock */
		
		while(vsvt) {										/* Clear any VMX saved state */
			if (vsvt == vsv) break;   						/* Done when hit user if any */
			vpst = vsvt;									/* Remember so we can toss this */
			vsvt = (savearea_vec *)vsvt->save_hdr.save_prev;	/* Get one underneath our's */		
			save_ret((savearea *)vpst);						/* Release it */
		}
		
	}
 
 	if(act->mact.curctx->FPUlevel) {						/* Is the current level user state? */
 		
 		toss_live_fpu(act->mact.curctx);					/* Dump live floats if is not user */

		fsv = act->mact.curctx->FPUsave;					/* Get the top floats savearea */
		
		while(fsv && fsv->save_hdr.save_level) fsv = (savearea_fpu *)fsv->save_hdr.save_prev;	/* Find user context if any */
	
		if(!hw_lock_to((hw_lock_t)&act->mact.curctx->FPUsync, LockTimeOut)) {	/* Get the sync lock */ 
			panic("act_machine_sv_free - timeout getting FPU sync lock\n");	/* Tell all and die */
		}
		
		fsvt = act->mact.curctx->FPUsave;					/* Get the top of the chain */
		act->mact.curctx->FPUsave = fsv;					/* Point to the user context */
		act->mact.curctx->FPUlevel = 0;						/* Set the level to user */
		hw_lock_unlock((hw_lock_t)&act->mact.curctx->FPUsync);	/* Unlock */
		
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

	pcb = act->mact.pcb;									/* Get the general savearea */
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
	
	act->mact.pcb = userpcb;								/* Chain in the user if there is one, or 0 if not */
	
}

void
machine_thread_set_current(thread_t	thread)
{
    set_machine_current_act(thread->top_act);
}

void
machine_act_terminate(
	thread_act_t	act)
{
	if(act->mact.bbDescAddr) {								/* Check if the Blue box assist is active */
		disable_bluebox_internal(act);						/* Kill off bluebox */
	}
	
	if(act->mact.vmmControl) {								/* Check if VMM is active */
		vmm_tear_down_all(act);								/* Kill off all VMM contexts */
	}
}

void
machine_thread_terminate_self(void)
{
	machine_act_terminate(current_act());
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
    dump_act(thread_act_t thr_act)
{
    if (!thr_act)
	return(0);

    printf("thr_act(0x%x)(%d): thread=%x(%d) task=%x(%d)\n",
	   thr_act, thr_act->ref_count,
	   thr_act->thread, thr_act->thread ? thr_act->thread->ref_count:0,
	   thr_act->task,   thr_act->task   ? thr_act->task->ref_count : 0);

    printf("\tsusp=%x active=%x hi=%x lo=%x\n",
	   0 /*thr_act->alerts*/, 0 /*thr_act->alert_mask*/,
	   thr_act->suspend_count, thr_act->active,
	   thr_act->higher, thr_act->lower);

    return((int)thr_act);
}

#endif

unsigned int 
get_useraddr()
{
	return(current_act()->mact.upcb->save_srr0);
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

  if (thread->top_act)
	  act_machine_sv_free(thread->top_act);

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
	vm_offset_t		stack,
	void			 (*start)(thread_t))
{
  thread_act_t thr_act;
  unsigned int *kss;
  struct savearea *sv;

        KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_ATTACH),
            thread, thread->priority,
            thread->sched_pri, start,
            0);

  assert(stack);
  kss = (unsigned int *)STACK_IKS(stack);
  thread->kernel_stack = stack;

  /* during initialization we sometimes do not have an
     activation. in that case do not do anything */
  if ((thr_act = thread->top_act) != 0) {
    sv = save_get();  /* cannot block */
	sv->save_hdr.save_flags = (sv->save_hdr.save_flags & ~SAVtype) | (SAVgeneral << SAVtypeshft);	/* Mark as in use */
    sv->save_hdr.save_act = (struct thread_activation *)thr_act;
	sv->save_hdr.save_prev = (addr64_t)((uintptr_t)thr_act->mact.pcb);
    thr_act->mact.pcb = sv;

    sv->save_srr0 = (unsigned int) start;
    /* sv->save_r3 = ARG ? */
    sv->save_r1 = (vm_offset_t)((int)kss - KF_SIZE);
	sv->save_srr1 = MSR_SUPERVISOR_INT_OFF;
	sv->save_fpscr = 0;									/* Clear all floating point exceptions */
	sv->save_vrsave = 0;								/* Set the vector save state */
	sv->save_vscr[3] = 0x00010000;						/* Supress java mode */
    *(CAST_DOWN(int *, sv->save_r1)) = 0;
    thr_act->mact.ksp = 0;			      
  }

  return;
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
	mapping *mp;
	struct per_proc_info *ppinfo;
	
	assert(new->top_act);
	assert(old->top_act);

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
			if(fowner->facAct == old->top_act) {		/* Is it for us? */
				fpu_save(fowner);						/* Yes, save it */
			}
		}
		fowner = ppinfo->VMX_owner;						/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old->top_act) {		/* Is it for us? */
				vec_save(fowner);						/* Yes, save it */
			}
		}
	}

	/*
	 * If old thread is running VM, save per proc userProtKey and FamVMmode spcFlags bits in the thread spcFlags
 	 * This bits can be modified in the per proc without updating the thread spcFlags
	 */
	if(old->top_act->mact.specFlags & runningVM) {			/* Is the current thread running a VM? */
		old->top_act->mact.specFlags &= ~(userProtKey|FamVMmode);
		old->top_act->mact.specFlags |= (ppinfo->spcFlags) & (userProtKey|FamVMmode);
	}
	old->top_act->mact.specFlags &= ~OnProc;
	new->top_act->mact.specFlags |= OnProc;

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_HANDOFF) | DBG_FUNC_NONE,
		     old->reason, (int)new, old->sched_pri, new->sched_pri, 0);


	if(new->top_act->mact.specFlags & runningVM) {	/* Is the new guy running a VM? */
		pmap_switch(new->top_act->mact.vmmCEntry->vmmPmap);	/* Switch to the VM's pmap */
		ppinfo->VMMareaPhys = new->top_act->mact.vmmCEntry->vmmContextPhys;
		ppinfo->VMMXAFlgs = new->top_act->mact.vmmCEntry->vmmXAFlgs;
		ppinfo->FAMintercept = new->top_act->mact.vmmCEntry->vmmFAMintercept;
	}
	else {											/* otherwise, we use the task's pmap */
		new_pmap = new->top_act->task->map->pmap;
		if ((old->top_act->task->map->pmap != new_pmap) || (old->top_act->mact.specFlags & runningVM)) {
			pmap_switch(new_pmap);
		}
	}

	machine_thread_set_current(new);
	ppinfo->Uassist = new->top_act->mact.cthread_self;

	ppinfo->ppbbTaskEnv = new->top_act->mact.bbTaskEnv;
	ppinfo->spcFlags = new->top_act->mact.specFlags;
	
	old->top_act->mact.cioSpace |= cioSwitchAway;	/* Show we switched away from this guy */
	mp = (mapping *)&ppinfo->ppCIOmp;
	mp->mpSpace = invalSpace;						/* Since we can't handoff in the middle of copy in/out, just invalidate */

	if (branch_tracing_enabled()) 
		ppinfo->cpu_flags |= traceBE;
    
	if(trcWork.traceMask) dbgTrace(0x12345678, (unsigned int)old->top_act, (unsigned int)new->top_act, 0);	/* Cut trace entry if tracing */    
    
  return;
}

/*
 * clean and initialize the current kernel stack and go to
 * the given continuation routine
 */

void
call_continuation(void (*continuation)(void) )
{

  unsigned int *kss;
  vm_offset_t tsp;

  assert(current_thread()->kernel_stack);
  kss = (unsigned int *)STACK_IKS(current_thread()->kernel_stack);
  assert(continuation);

  tsp = (vm_offset_t)((int)kss - KF_SIZE);
  assert(tsp);
  *((int *)tsp) = 0;

  Call_continuation(continuation, tsp);
  
  return;
}
