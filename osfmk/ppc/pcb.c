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
#include <ppc/fpu_protos.h>
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

#include <sys/kdebug.h>

extern int 		real_ncpus;						/* Number of actual CPUs */
extern struct	Saveanchor saveanchor;			/* Aliged savearea anchor */

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

extern struct thread_shuttle	*Switch_context(
					struct thread_shuttle 	*old,
				       	void	      		(*cont)(void),
					struct thread_shuttle 	*new);


#if	MACH_LDEBUG || MACH_KDB
void		log_thread_action (char *, long, long, long);
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
 * stack_attach: Attach a kernel stack to a thread.
 */
void
machine_kernel_stack_init(
	struct thread_shuttle *thread,
	void		(*start_pos)(thread_t))
{
    vm_offset_t	stack;
    unsigned int			*kss;
	struct savearea 		*sv;

    assert(thread->top_act->mact.pcb);
    assert(thread->kernel_stack);
    stack = thread->kernel_stack;

#if	MACH_ASSERT
    if (watchacts & WA_PCB)
		printf("machine_kernel_stack_init(thr=%x,stk=%x,start_pos=%x)\n", thread,stack,start_pos);
#endif	/* MACH_ASSERT */
	
	kss = (unsigned int *)STACK_IKS(stack);
	sv=(savearea *)(thread->top_act->mact.pcb);			/* This for the sake of C */

	sv->save_lr = (unsigned int) start_pos;			/* Set up the execution address */
	sv->save_srr0 = (unsigned int) start_pos;		/* Here too */
	sv->save_srr1 = MSR_SUPERVISOR_INT_OFF;				/* Set the normal running MSR */
	sv->save_r1 = (vm_offset_t) ((int)kss - KF_SIZE);	/* Point to the top frame on the stack */
	sv->save_xfpscrpad = 0;								/* Start with a clear fpscr */
	sv->save_xfpscr = 0;								/* Start with a clear fpscr */

	*((int *)sv->save_r1) = 0;							/* Zero the frame backpointer */
	thread->top_act->mact.ksp = 0;						/* Show that the kernel stack is in use already */

}

/*
 * switch_context: Switch from one thread to another, needed for
 * 		   switching of space
 * 
 */
struct thread_shuttle*
switch_context(
	struct thread_shuttle *old,
	void (*continuation)(void),
	struct thread_shuttle *new)
{
	register thread_act_t old_act = old->top_act, new_act = new->top_act;
	register struct thread_shuttle* retval;
	pmap_t	new_pmap;
#if	MACH_LDEBUG || MACH_KDB
	log_thread_action("switch", 
			  (long)old, 
			  (long)new, 
			  (long)__builtin_return_address(0));
#endif
	per_proc_info[cpu_number()].old_thread = old;
	assert(old_act->kernel_loaded ||
	       active_stacks[cpu_number()] == old_act->thread->kernel_stack);
	       
	if(get_preemption_level() != 1) {					/* Make sure we are not at wrong preemption level */
		panic("switch_context: Invalid preemption level (%d); old = %08X, cont = %08X, new = %08X\n",
			get_preemption_level(), old, continuation, new);
	}
	check_simple_locks();

	/* Our context might wake up on another processor, so we must
	 * not keep hot state in our FPU, it must go back to the pcb
	 * so that it can be found by the other if needed
	 */
	if(real_ncpus > 1) {	/* This is potentially slow, so only do when actually SMP */
		fpu_save();			/* Save floating point if used */
		vec_save();			/* Save vector if used */
	}

#if DEBUG
	if (watchacts & WA_PCB) {
		printf("switch_context(0x%08x, 0x%x, 0x%08x)\n",
		       old,continuation,new);
	}
#endif /* DEBUG */

	/*
	 * We do not have to worry about the PMAP module, so switch.
	 *
	 * We must not use top_act->map since this may not be the actual
	 * task map, but the map being used for a klcopyin/out.
	 */

	if(new_act->mact.specFlags & runningVM) {			/* Is the new guy running a VM? */
		pmap_switch(new_act->mact.vmmCEntry->vmmPmap);	/* Switch to the VM's pmap */
	}
	else {												/* otherwise, we use the task's pmap */
		new_pmap = new_act->task->map->pmap;
		if ((old_act->task->map->pmap != new_pmap) || (old_act->mact.specFlags & runningVM)) {
			pmap_switch(new_pmap);						/* Switch if there is a change */
		}
	}

	/* Sanity check - is the stack pointer inside the stack that
	 * we're about to switch to? Is the execution address within
	 * the kernel's VM space??
	 */
#if 0
	printf("************* stack=%08X; R1=%08X; LR=%08X; old=%08X; cont=%08X; new=%08X\n",
		new->kernel_stack, new_act->mact.pcb->ss.r1,
		new_act->mact.pcb->ss.lr, old, continuation, new);	/* (TEST/DEBUG) */
	assert((new->kernel_stack < new_act->mact.pcb->ss.r1) &&
	       ((unsigned int)STACK_IKS(new->kernel_stack) >
		new_act->mact.pcb->ss.r1));
	assert(new_act->mact.pcb->ss.lr < VM_MAX_KERNEL_ADDRESS);
#endif


	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_SCHED) | DBG_FUNC_NONE,
		     (int)old, (int)new, old->sched_pri, new->sched_pri, 0);


	retval = Switch_context(old, continuation, new);
	assert(retval != (struct thread_shuttle*)NULL);

	/* We've returned from having switched context, so we should be
	 * back in the original context.
	 */

	return retval;
}

/*
 * Alter the thread's state so that a following thread_exception_return
 * will make the thread return 'retval' from a syscall.
 */
void
thread_set_syscall_return(
	struct thread_shuttle *thread,
	kern_return_t	retval)
{
	struct ppc_saved_state *ssp = &thread->top_act->mact.pcb->ss;

#if	MACH_ASSERT
	if (watchacts & WA_PCB)
		printf("thread_set_syscall_return(thr=%x,retval=%d)\n", thread,retval);
#endif	/* MACH_ASSERT */

        ssp->r3 = retval;
}

/*
 * Initialize the machine-dependent state for a new thread.
 */
kern_return_t
thread_machine_create(
		      struct thread_shuttle *thread,
		      thread_act_t thr_act,
		      void (*start_pos)(thread_t))
{

	savearea		*sv;									/* Pointer to newly allocated savearea */
	unsigned int	*CIsTooLimited, i;


#if	MACH_ASSERT
    if (watchacts & WA_PCB)
	printf("thread_machine_create(thr=%x,thr_act=%x,st=%x)\n", thread, thr_act, start_pos);
#endif	/* MACH_ASSERT */

	hw_atomic_add(&saveanchor.saveneed, 4);					/* Account for the number of saveareas we think we "need"
															   for this activation */
	assert(thr_act->mact.pcb == (pcb_t)0);					/* Make sure there was no previous savearea */
	
	sv = save_alloc();										/* Go get us a savearea */
		
	bzero((char *) sv, sizeof(struct pcb));					/* Clear out the whole shebang */
	
	sv->save_act = thr_act;									/* Set who owns it */
	sv->save_vrsave = 0;
	thr_act->mact.pcb = (pcb_t)sv;							/* Point to the save area */

    thread->kernel_stack = (int)stack_alloc(thread,start_pos);				/* Allocate our kernel stack */
    assert(thread->kernel_stack);							/* Make sure we got it */

#if	MACH_ASSERT
	if (watchacts & WA_PCB)
		printf("pcb_init(%x) pcb=%x\n", thr_act, sv);
#endif	/* MACH_ASSERT */
	/*
	 * User threads will pull their context from the pcb when first
	 * returning to user mode, so fill in all the necessary values.
	 * Kernel threads are initialized from the save state structure 
	 * at the base of the kernel stack (see stack_attach()).
	 */

	sv->save_srr1 = MSR_EXPORT_MASK_SET;					/* Set the default user MSR */
	
	CIsTooLimited = (unsigned int *)(&sv->save_sr0);			/* Make a pointer 'cause C can't cast on the left */
	for(i=0; i<16; i++) {									/* Initialize all SRs */
		CIsTooLimited[i] = SEG_REG_PROT | (i << 20) | thr_act->task->map->pmap->space;	/* Set the SR value */
	}
	sv->save_sr_copyin = SEG_REG_PROT | (SR_COPYIN_NUM<<20) | thr_act->task->map->pmap->space;	/* Default the copyin */

    return(KERN_SUCCESS);
}

/*
 * Machine-dependent cleanup prior to destroying a thread
 */
void
thread_machine_destroy( thread_t thread )
{
	spl_t s;

	if (thread->kernel_stack) {
		s = splsched();
		stack_free(thread);
		splx(s);
	}
}

/*
 * flush out any lazily evaluated HW state in the
 * owning thread's context, before termination.
 */
void
thread_machine_flush( thread_act_t cur_act )
{
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
	thread_t	thread,
	thread_act_t	old,
	thread_act_t	new,
	int				cpu)
{
	pmap_t		new_pmap;

	/* Our context might wake up on another processor, so we must
	 * not keep hot state in our FPU, it must go back to the pcb
	 * so that it can be found by the other if needed
	 */
	if(real_ncpus > 1) {	/* This is potentially slow, so only do when actually SMP */
		fpu_save();			/* Save floating point if used */
		vec_save();			/* Save vector if used */
	}

	active_stacks[cpu] = thread->kernel_stack;

	ast_context(new, cpu);

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

void
pcb_user_to_kernel(thread_act_t act)
{

	return;													/* Not needed, I hope... */
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
	register pcb_t pcb,userpcb,npcb;
	register savearea *svp;
	register int i;

/*
 *	This next bit insures that any live facility context for this thread is discarded on every processor
 *	that may have it.  We go through all per-processor blocks and zero the facility owner if
 *	it is the thread being destroyed. This needs to be done via a compare-and-swap because
 *	some other processor could change the owner while we are clearing it. It turns out that 
 *	this is the only place where we need the interlock, normal use of the owner field is cpu-local
 *	and doesn't need the interlock. Because we are called during termintation, and a thread
 *	terminates itself, the context on other processors has been saved (because we save it as
 *	part of the context switch), even if it is still considered live. Since the dead thread is 
 *	not running elsewhere, and the context is saved, any other processor looking at the owner
 *	field will not attempt to save context again, meaning that it doesn't matter if the owner
 *	changes out from under it.
 */
 
	/* 
	 * free VMX and FPU saveareas.  do not free user save areas.
     * user VMX and FPU saveareas, if any, i'm told are last in
     * the chain so we just stop if we find them
	 * we identify user VMX and FPU saveareas when we find a pcb
	 * with a save level of 0.  we identify user regular save
	 * areas when we find one with MSR_PR set
	 */

	pcb = act->mact.VMX_pcb;								/* Get the top vector savearea */
	while(pcb) {											/* Any VMX saved state? */
		svp = (savearea *)pcb;								/* save lots of casting later */
		if (svp->save_level_vec == 0) break;   /* done when hit user if any */
		pcb = (pcb_t)svp->save_prev_vector;				/* Get one underneath our's */		
		svp->save_flags &= ~SAVvmxvalid;						/* Clear the VMX flag */
		if(!(svp->save_flags & SAVinuse)) {					/* Anyone left with this one? */			

				save_ret(svp);				/* release it */
		}
	}
	act->mact.VMX_pcb = pcb;
	if (act->mact.VMX_lvl != 0) {
	  for(i=0; i < real_ncpus; i++) {							/* Cycle through processors */
		(void)hw_compare_and_store((unsigned int)act, 0, &per_proc_info[i].VMX_thread);	/* Clear if ours */
	  }
	}

	pcb = act->mact.FPU_pcb;								/* Get the top floating point savearea */
	while(pcb) {											/* Any floating point saved state? */
		svp = (savearea *)pcb;
		if (svp->save_level_fp == 0) break;     /* done when hit user if any */
		pcb = (pcb_t)svp->save_prev_float;					/* Get one underneath our's */		
		svp->save_flags &= ~SAVfpuvalid;						/* Clear the floating point flag */
		if(!(svp->save_flags & SAVinuse)) {					/* Anyone left with this one? */			
				save_ret(svp);							/* Nope, release it */
		}
	}
	act->mact.FPU_pcb = pcb;
	if (act->mact.FPU_lvl != 0) {
	  for(i=0; i < real_ncpus; i++) {							/* Cycle through processors */
		(void)hw_compare_and_store((unsigned int)act, 0, &per_proc_info[i].FPU_thread);	/* Clear if ours */
	  }
	}

	/*
	 * free all regular saveareas except a user savearea, if any
	 */

	pcb = act->mact.pcb;
	userpcb = (pcb_t)0;
	while(pcb) {
	  svp = (savearea *)pcb;
	  if ((svp->save_srr1 & MASK(MSR_PR))) {
		assert(userpcb == (pcb_t)0);
		userpcb = pcb;
		svp = (savearea *)userpcb;
		npcb = (pcb_t)svp->save_prev;
		svp->save_prev = (struct savearea *)0;
	  } else {
		svp->save_flags &= ~SAVattach;		/* Clear the attached flag */
		npcb = (pcb_t)svp->save_prev;
		if(!(svp->save_flags & SAVinuse))	/* Anyone left with this one? */
			save_ret(svp);
	  }
	  pcb = npcb;
	}
	act->mact.pcb = userpcb;

}


/*
 * act_virtual_machine_destroy:
 * Shutdown any virtual machines associated with a thread
 */
void
act_virtual_machine_destroy(thread_act_t act)
{
	if(act->mact.bbDescAddr) {								/* Check if the Blue box assist is active */
		disable_bluebox_internal(act);						/* Kill off bluebox */
	}
	
	if(act->mact.vmmControl) {								/* Check if VMM is active */
		vmm_tear_down_all(act);								/* Kill off all VMM contexts */
	}
}

/*
 * act_machine_destroy: Shutdown any state associated with a thread pcb.
 */
void
act_machine_destroy(thread_act_t act)
{
	register pcb_t	pcb, opcb;
	int i;

#if	MACH_ASSERT
	if (watchacts & WA_PCB)
		printf("act_machine_destroy(0x%x)\n", act);
#endif	/* MACH_ASSERT */

	act_virtual_machine_destroy(act);

/*
 *	This next bit insures that any live facility context for this thread is discarded on every processor
 *	that may have it.  We go through all per-processor blocks and zero the facility owner if
 *	it is the thread being destroyed. This needs to be done via a compare-and-swap because
 *	some other processor could change the owner while we are clearing it. It turns out that 
 *	this is the only place where we need the interlock, normal use of the owner field is cpu-local
 *	and doesn't need the interlock. Because we are called during termintation, and a thread
 *	terminates itself, the context on other processors has been saved (because we save it as
 *	part of the context switch), even if it is still considered live. Since the dead thread is 
 *	not running elsewhere, and the context is saved, any other processor looking at the owner
 *	field will not attempt to save context again, meaning that it doesn't matter if the owner
 *	changes out from under it.
 */
 
	for(i=0; i < real_ncpus; i++) {							/* Cycle through processors */
		(void)hw_compare_and_store((unsigned int)act, 0, &per_proc_info[i].FPU_thread);	/* Clear if ours */
		(void)hw_compare_and_store((unsigned int)act, 0, &per_proc_info[i].VMX_thread);	/* Clear if ours */
	}
	
	pcb = act->mact.VMX_pcb;								/* Get the top vector savearea */
	while(pcb) {											/* Any VMX saved state? */
		opcb = pcb;											/* Save current savearea address */
		pcb = (pcb_t)(((savearea *)pcb)->save_prev_vector);	/* Get one underneath our's */		
		((savearea *)opcb)->save_flags &= ~SAVvmxvalid;		/* Clear the VMX flag */
		
		if(!(((savearea *)opcb)->save_flags & SAVinuse)) {	/* Anyone left with this one? */			
			save_release((savearea *)opcb);					/* Nope, release it */
		}
	}
	act->mact.VMX_pcb = (pcb_t)0;							/* Clear pointer */	

	pcb = act->mact.FPU_pcb;								/* Get the top floating point savearea */
	while(pcb) {											/* Any floating point saved state? */
		opcb = pcb;											/* Save current savearea address */
		pcb = (pcb_t)(((savearea *)pcb)->save_prev_float);	/* Get one underneath our's */		
		((savearea *)opcb)->save_flags &= ~SAVfpuvalid;		/* Clear the floating point flag */
		
		if(!(((savearea *)opcb)->save_flags & SAVinuse)) {	/* Anyone left with this one? */			
			save_release((savearea *)opcb);					/* Nope, release it */
		}
	}
	act->mact.FPU_pcb = (pcb_t)0;							/* Clear pointer */	

	pcb = act->mact.pcb;									/* Get the top normal savearea */
	act->mact.pcb = (pcb_t)0;								/* Clear pointer */	
	
	while(pcb) {											/* Any normal saved state left? */
		opcb = pcb;											/* Keep track of what we're working on */
		pcb = (pcb_t)(((savearea *)pcb)->save_prev);		/* Get one underneath our's */
		
		((savearea *)opcb)->save_flags = 0;					/* Clear all flags since we release this in any case */
		save_release((savearea *)opcb);						/* Release this one */
	}

	hw_atomic_sub(&saveanchor.saveneed, 4);					/* Unaccount for the number of saveareas we think we "need"
														  	   for this activation */
}

kern_return_t
act_machine_create(task_t task, thread_act_t thr_act)
{
	/*
	 * Clear & Init the pcb  (sets up user-mode s regs)
	 * We don't use this anymore.
	 */

	register pcb_t pcb;
	register int i;
	unsigned int *CIsTooLimited;
	pmap_t pmap;
	
	return KERN_SUCCESS;
}

void act_machine_init()
{
#if	MACH_ASSERT
    if (watchacts & WA_PCB)
	printf("act_machine_init()\n");
#endif	/* MACH_ASSERT */

    /* Good to verify these once */
    assert( THREAD_MACHINE_STATE_MAX <= THREAD_STATE_MAX );

    assert( THREAD_STATE_MAX >= PPC_THREAD_STATE_COUNT );
    assert( THREAD_STATE_MAX >= PPC_EXCEPTION_STATE_COUNT );
    assert( THREAD_STATE_MAX >= PPC_FLOAT_STATE_COUNT );
    assert( THREAD_STATE_MAX >= sizeof(struct ppc_saved_state)/sizeof(int));

    /*
     * If we start using kernel activations,
     * would normally create kernel_thread_pool here,
     * populating it from the act_zone
     */
}

void
act_machine_return(int code)
{
    thread_act_t thr_act = current_act();

#if	MACH_ASSERT
    if (watchacts & WA_EXIT)
	printf("act_machine_return(0x%x) cur_act=%x(%d) thr=%x(%d)\n",
	       code, thr_act, thr_act->ref_count,
	       thr_act->thread, thr_act->thread->ref_count);
#endif	/* MACH_ASSERT */


	/*
	 * This code is called with nothing locked.
	 * It also returns with nothing locked, if it returns.
	 *
	 * This routine terminates the current thread activation.
	 * If this is the only activation associated with its
	 * thread shuttle, then the entire thread (shuttle plus
	 * activation) is terminated.
	 */
	assert( code == KERN_TERMINATED );
	assert( thr_act );

	act_lock_thread(thr_act);

#ifdef CALLOUT_RPC_MODEL
	/*
	 * JMM - This needs to get cleaned up to work under the much simpler
	 * return (instead of callout model).
	 */
	if (thr_act->thread->top_act != thr_act) {
		/*
		 * this is not the top activation;
		 * if possible, we should clone the shuttle so that
		 * both the root RPC-chain and the soon-to-be-orphaned
		 * RPC-chain have shuttles
		 *
		 * JMM - Cloning is a horrible idea!  Instead we should alert
		 * the pieces upstream to return the shuttle.  We will use
		 * alerts for this.
		 */
		act_unlock_thread(thr_act);
		panic("act_machine_return: ORPHAN CASE NOT YET IMPLEMENTED");
	}

	if (thr_act->lower != THR_ACT_NULL) {
		thread_t	cur_thread = current_thread();
		thread_act_t	cur_act;
		struct ipc_port	*iplock;

		/* terminate the entire thread (shuttle plus activation) */
		/* terminate only this activation, send an appropriate   */
		/* return code back to the activation that invoked us.   */
		iplock = thr_act->pool_port;	/* remember for unlock call */
		thr_act->lower->alerts |= SERVER_TERMINATED;
		install_special_handler(thr_act->lower);
		
		/* Return to previous act with error code */

		act_locked_act_reference(thr_act);	/* keep it around */
		act_switch_swapcheck(cur_thread, (ipc_port_t)0);

		(void) switch_act(THR_ACT_NULL);
		/* assert(thr_act->ref_count == 0); */		/* XXX */
		cur_act = cur_thread->top_act;
		MACH_RPC_RET(cur_act) = KERN_RPC_SERVER_TERMINATED;	    
		machine_kernel_stack_init(cur_thread, mach_rpc_return_error);
		/*
		 * The following unlocks must be done separately since fields 
		 * used by `act_unlock_thread()' have been cleared, meaning
		 * that it would not release all of the appropriate locks.
		 */
		rpc_unlock(cur_thread);
		if (iplock) ip_unlock(iplock);	/* must be done separately */
		act_unlock(thr_act);
		act_deallocate(thr_act);		/* free it */
		Load_context(cur_thread);
		/*NOTREACHED*/
		
		panic("act_machine_return: TALKING ZOMBIE! (2)");
	}

#endif /* CALLOUT_RPC_MODEL */

	/* This is the only activation attached to the shuttle... */

	assert(thr_act->thread->top_act == thr_act);
	act_unlock_thread(thr_act);
	thread_terminate_self();

	/*NOTREACHED*/
	panic("act_machine_return: TALKING ZOMBIE! (1)");
}

void
thread_machine_set_current(struct thread_shuttle *thread)
{
    register int	my_cpu = cpu_number();

    cpu_data[my_cpu].active_thread = thread;
	
    active_kloaded[my_cpu] = thread->top_act->kernel_loaded ? thread->top_act : THR_ACT_NULL;
}

void
thread_machine_init(void)
{
#ifdef	MACHINE_STACK
#if KERNEL_STACK_SIZE > PPC_PGBYTES
	panic("KERNEL_STACK_SIZE can't be greater than PPC_PGBYTES\n");
#endif
#endif
}

#if MACH_ASSERT
void
dump_pcb(pcb_t pcb)
{
	printf("pcb @ %8.8x:\n", pcb);
#if DEBUG
	regDump(&pcb->ss);
#endif /* DEBUG */
}

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

    printf("\talerts=%x mask=%x susp=%x active=%x hi=%x lo=%x\n",
	   thr_act->alerts, thr_act->alert_mask,
	   thr_act->suspend_count, thr_act->active,
	   thr_act->higher, thr_act->lower);

    return((int)thr_act);
}

#endif

unsigned int 
get_useraddr()
{

	thread_act_t thr_act = current_act();

	return(thr_act->mact.pcb->ss.srr0);
}

/*
 * detach and return a kernel stack from a thread
 */

vm_offset_t
stack_detach(thread_t thread)
{
  vm_offset_t stack;

		KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_DETACH),
			thread, thread->priority,
			thread->sched_pri, 0,
			0);

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
stack_attach(struct thread_shuttle *thread,
	     vm_offset_t stack,
	     void (*start_pos)(thread_t))
{
  thread_act_t thr_act;
  unsigned int *kss;
  struct savearea *sv;

        KERNEL_DEBUG(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_ATTACH),
            thread, thread->priority,
            thread->sched_pri, start_pos,
            0);

  assert(stack);
  kss = (unsigned int *)STACK_IKS(stack);
  thread->kernel_stack = stack;

  /* during initialization we sometimes do not have an
     activation. in that case do not do anything */
  if ((thr_act = thread->top_act) != 0) {
    sv = save_get();  /* cannot block */
    //    bzero((char *) sv, sizeof(struct pcb));
    sv->save_act = thr_act;
	sv->save_prev = (struct savearea *)thr_act->mact.pcb;
    thr_act->mact.pcb = (pcb_t)sv;

    sv->save_srr0 = (unsigned int) start_pos;
    /* sv->save_r3 = ARG ? */
    sv->save_r1 = (vm_offset_t)((int)kss - KF_SIZE);
	sv->save_srr1 = MSR_SUPERVISOR_INT_OFF;
	sv->save_xfpscrpad = 0;						/* Start with a clear fpscr */
	sv->save_xfpscr = 0;						/* Start with a clear fpscr */
    *((int *)sv->save_r1) = 0;
    thr_act->mact.ksp = 0;			      
  }

  return;
}

/*
 * move a stack from old to new thread
 */

void
stack_handoff(thread_t old,
	      thread_t new)
{

  vm_offset_t stack;
  pmap_t new_pmap;

  assert(new->top_act);
  assert(old->top_act);

  stack = stack_detach(old);
  new->kernel_stack = stack;

#if NCPUS > 1
  if (real_ncpus > 1) {
	fpu_save();
	vec_save();
  }
#endif

  KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_HANDOFF) | DBG_FUNC_NONE,
		     (int)old, (int)new, old->sched_pri, new->sched_pri, 0);


	if(new->top_act->mact.specFlags & runningVM) {	/* Is the new guy running a VM? */
		pmap_switch(new->top_act->mact.vmmCEntry->vmmPmap);	/* Switch to the VM's pmap */
	}
	else {											/* otherwise, we use the task's pmap */
		new_pmap = new->top_act->task->map->pmap;
		if ((old->top_act->task->map->pmap != new_pmap) || (old->top_act->mact.specFlags & runningVM)) {
			pmap_switch(new_pmap);
		}
	}

  thread_machine_set_current(new);
  active_stacks[cpu_number()] = new->kernel_stack;
  per_proc_info[cpu_number()].Uassist = new->top_act->mact.cthread_self;
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

void
thread_swapin_mach_alloc(thread_t thread)
{
    struct savearea *sv;

	assert(thread->top_act->mact.pcb == 0);

    sv = save_alloc();
	assert(sv);
	//    bzero((char *) sv, sizeof(struct pcb));
    sv->save_act = thread->top_act;
    thread->top_act->mact.pcb = (pcb_t)sv;

}
