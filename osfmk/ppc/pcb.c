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
	sv = thread->top_act->mact.pcb;						/* This for the sake of C */

	sv->save_lr = (unsigned int) start_pos;				/* Set up the execution address */
	sv->save_srr0 = (unsigned int) start_pos;			/* Here too */
	sv->save_srr1  = MSR_SUPERVISOR_INT_OFF;			/* Set the normal running MSR */
	sv->save_r1 = (vm_offset_t) ((int)kss - KF_SIZE);	/* Point to the top frame on the stack */
	sv->save_fpscr = 0;									/* Clear all floating point exceptions */
	sv->save_vrsave = 0;								/* Set the vector save state */
	sv->save_vscr[3] = 0x00010000;						/* Supress java mode */

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
	facility_context *fowner;
	int	my_cpu;
	
#if	MACH_LDEBUG || MACH_KDB
	log_thread_action("switch", 
			  (long)old, 
			  (long)new, 
			  (long)__builtin_return_address(0));
#endif

	my_cpu = cpu_number();
	per_proc_info[my_cpu].old_thread = (unsigned int)old;
	per_proc_info[my_cpu].cpu_flags &= ~traceBE;  /* disable branch tracing if on */
	assert(old_act->kernel_loaded ||
	       active_stacks[my_cpu] == old_act->thread->kernel_stack);
	       
	check_simple_locks();

	/* Our context might wake up on another processor, so we must
	 * not keep hot state in our FPU, it must go back to the pcb
	 * so that it can be found by the other if needed
	 */
	if(real_ncpus > 1) {								/* This is potentially slow, so only do when actually SMP */
		fowner = per_proc_info[my_cpu].FPU_owner;	/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old->top_act) {		/* Is it for us? */
				fpu_save(fowner);						/* Yes, save it */
			}
		}
		fowner = per_proc_info[my_cpu].VMX_owner;	/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old->top_act) {		/* Is it for us? */
				vec_save(fowner);						/* Yes, save it */
			}
		}
	}

#if DEBUG
	if (watchacts & WA_PCB) {
		printf("switch_context(0x%08x, 0x%x, 0x%08x)\n",
		       old,continuation,new);
	}
#endif /* DEBUG */

	/*
	 * If old thread is running VM, save per proc userProtKey and FamVMmode spcFlags bits in the thread spcFlags
 	 * This bits can be modified in the per proc without updating the thread spcFlags
	 */
	if(old_act->mact.specFlags & runningVM) {
		old_act->mact.specFlags &=  ~(userProtKey|FamVMmode);
		old_act->mact.specFlags |= (per_proc_info[my_cpu].spcFlags) & (userProtKey|FamVMmode);
	}

	/*
	 * We do not have to worry about the PMAP module, so switch.
	 *
	 * We must not use top_act->map since this may not be the actual
	 * task map, but the map being used for a klcopyin/out.
	 */

	if(new_act->mact.specFlags & runningVM) {			/* Is the new guy running a VM? */
		pmap_switch(new_act->mact.vmmCEntry->vmmPmap);	/* Switch to the VM's pmap */
		per_proc_info[my_cpu].VMMareaPhys = (vm_offset_t)new_act->mact.vmmCEntry->vmmContextPhys;
		per_proc_info[my_cpu].FAMintercept = new_act->mact.vmmCEntry->vmmFAMintercept;
	}
	else {												/* otherwise, we use the task's pmap */
		new_pmap = new_act->task->map->pmap;
		if ((old_act->task->map->pmap != new_pmap) || (old_act->mact.specFlags & runningVM)) {
			pmap_switch(new_pmap);						/* Switch if there is a change */
		}
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_SCHED) | DBG_FUNC_NONE,
		     (int)old, (int)new, old->sched_pri, new->sched_pri, 0);

	retval = Switch_context(old, continuation, new);
	assert(retval != (struct thread_shuttle*)NULL);

	if (branch_tracing_enabled())
	  per_proc_info[my_cpu].cpu_flags |= traceBE;  /* restore branch tracing */

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

#if	MACH_ASSERT
	if (watchacts & WA_PCB)
		printf("thread_set_syscall_return(thr=%x,retval=%d)\n", thread,retval);
#endif	/* MACH_ASSERT */

        thread->top_act->mact.pcb->save_r3 = retval;
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

	hw_atomic_add(&saveanchor.savetarget, 4);				/* Account for the number of saveareas we think we "need"
															   for this activation */
	assert(thr_act->mact.pcb == (savearea *)0);				/* Make sure there was no previous savearea */
	
	sv = save_alloc();										/* Go get us a savearea */
		
	bzero((char *)((unsigned int)sv + sizeof(savearea_comm)), (sizeof(savearea) - sizeof(savearea_comm)));	/* Clear it */
		
	sv->save_hdr.save_prev = 0;								/* Clear the back pointer */
	sv->save_hdr.save_flags = (sv->save_hdr.save_flags & ~SAVtype) | (SAVgeneral << SAVtypeshft);	/* Mark as in use */
	sv->save_hdr.save_act = thr_act;						/* Set who owns it */
	sv->save_vscr[3] = 0x00010000;							/* Supress java mode */
	thr_act->mact.pcb = sv;									/* Point to the save area */
	thr_act->mact.curctx = &thr_act->mact.facctx;			/* Initialize facility context */
	thr_act->mact.facctx.facAct = thr_act;					/* Initialize facility context pointer to activation */

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
	
	CIsTooLimited = (unsigned int *)(&sv->save_sr0);		/* Make a pointer 'cause C can't cast on the left */
	for(i=0; i<16; i++) {									/* Initialize all SRs */
		CIsTooLimited[i] = SEG_REG_PROT | (i << 20) | thr_act->task->map->pmap->space;	/* Set the SR value */
	}

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
	facility_context *fowner;

	/* Our context might wake up on another processor, so we must
	 * not keep hot state in our FPU, it must go back to the pcb
	 * so that it can be found by the other if needed
	 */
	if(real_ncpus > 1) {								/* This is potentially slow, so only do when actually SMP */
		fowner = per_proc_info[cpu_number()].FPU_owner;	/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old) {					/* Is it for us? */
				fpu_save(fowner);						/* Yes, save it */
			}
		}
		fowner = per_proc_info[cpu_number()].VMX_owner;	/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old) {					/* Is it for us? */
				vec_save(fowner);						/* Yes, save it */
			}
		}
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
	register savearea *pcb, *userpcb;
	register savearea_vec *vsv, *vpsv;
	register savearea_fpu *fsv, *fpsv;
	register savearea *svp;
	register int i;

/*
 *	This function will release all non-user state context.
 */
 
/*
 *
 *	Walk through and release all floating point and vector contexts that are not
 *	user state.  We will also blow away live context if it belongs to non-user state.
 *
 */
 
 	if(act->mact.curctx->VMXlevel) {						/* Is the current level user state? */
 		toss_live_vec(act->mact.curctx);					/* Dump live vectors if is not user */
 		act->mact.curctx->VMXlevel = 0;						/* Mark as user state */
 	}

	vsv = act->mact.curctx->VMXsave;						/* Get the top vector savearea */
 	
	while(vsv) {											/* Any VMX saved state? */
		vpsv = vsv;											/* Remember so we can toss this */
		if (!vsv->save_hdr.save_level) break;   			/* Done when hit user if any */
		vsv = (savearea_vec *)vsv->save_hdr.save_prev;		/* Get one underneath our's */		
		save_ret((savearea *)vpsv);							/* Release it */
	}
	
	act->mact.curctx->VMXsave = vsv;						/* Queue the user context to the top */
 
 	if(act->mact.curctx->FPUlevel) {						/* Is the current level user state? */
 		toss_live_fpu(act->mact.curctx);					/* Dump live float if is not user */
 		act->mact.curctx->FPUlevel = 0;						/* Mark as user state */
 	}

	fsv = act->mact.curctx->FPUsave;						/* Get the top float savearea */
	
	while(fsv) {											/* Any float saved state? */
		fpsv = fsv;											/* Remember so we can toss this */
		if (!fsv->save_hdr.save_level) break;   			/* Done when hit user if any */
		fsv = (savearea_fpu *)fsv->save_hdr.save_prev;		/* Get one underneath our's */		
		save_ret((savearea *)fpsv);							/* Release it */
	}
	
	act->mact.curctx->FPUsave = fsv;						/* Queue the user context to the top */

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
		pcb = pcb->save_hdr.save_prev;						/* Get one underneath our's */		
		save_ret(svp);										/* Release it */
	}
	
	act->mact.pcb = userpcb;								/* Chain in the user if there is one, or 0 if not */
	
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

	register savearea *pcb, *ppsv;
	register savearea_vec *vsv, *vpsv;
	register savearea_fpu *fsv, *fpsv;
	register savearea *svp;
	register int i;

#if	MACH_ASSERT
	if (watchacts & WA_PCB)
		printf("act_machine_destroy(0x%x)\n", act);
#endif	/* MACH_ASSERT */

/*
 *	This function will release all context.
 */

	act_virtual_machine_destroy(act);						/* Make sure all virtual machines are dead first */
 
/*
 *
 *	Walk through and release all floating point and vector contexts. Also kill live context.
 *
 */
 
 	toss_live_vec(act->mact.curctx);						/* Dump live vectors */

	vsv = act->mact.curctx->VMXsave;						/* Get the top vector savearea */
	
	while(vsv) {											/* Any VMX saved state? */
		vpsv = vsv;											/* Remember so we can toss this */
		vsv = (savearea_vec *)vsv->save_hdr.save_prev;		/* Get one underneath our's */		
		save_release((savearea *)vpsv);						/* Release it */
	}
	
	act->mact.curctx->VMXsave = 0;							/* Kill chain */
 
 	toss_live_fpu(act->mact.curctx);						/* Dump live float */

	fsv = act->mact.curctx->FPUsave;						/* Get the top float savearea */
	
	while(fsv) {											/* Any float saved state? */
		fpsv = fsv;											/* Remember so we can toss this */
		fsv = (savearea_fpu *)fsv->save_hdr.save_prev;		/* Get one underneath our's */		
		save_release((savearea *)fpsv);						/* Release it */
	}
	
	act->mact.curctx->FPUsave = 0;							/* Kill chain */

/*
 * free all regular saveareas.
 */

	pcb = act->mact.pcb;									/* Get the general savearea */
	
	while(pcb) {											/* Any float saved state? */
		ppsv = pcb;											/* Remember so we can toss this */
		pcb = pcb->save_hdr.save_prev;						/* Get one underneath our's */		
		save_release(ppsv);									/* Release it */
	}
	
	hw_atomic_sub(&saveanchor.savetarget, 4);				/* Unaccount for the number of saveareas we think we "need" */

}


kern_return_t
act_machine_create(task_t task, thread_act_t thr_act)
{
	/*
	 * Clear & Init the pcb  (sets up user-mode s regs)
	 * We don't use this anymore.
	 */

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
	assert(thr_act->thread->top_act == thr_act);

	/* This is the only activation attached to the shuttle... */

	thread_terminate_self();

	/*NOTREACHED*/
	panic("act_machine_return: TALKING ZOMBIE! (1)");
}

void
thread_machine_set_current(struct thread_shuttle *thread)
{
    register int	my_cpu = cpu_number();

    set_machine_current_thread(thread);
    set_machine_current_act(thread->top_act);
	
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

	return(thr_act->mact.pcb->save_srr0);
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
	sv->save_hdr.save_flags = (sv->save_hdr.save_flags & ~SAVtype) | (SAVgeneral << SAVtypeshft);	/* Mark as in use */
    sv->save_hdr.save_act = thr_act;
	sv->save_hdr.save_prev = thr_act->mact.pcb;
    thr_act->mact.pcb = sv;

    sv->save_srr0 = (unsigned int) start_pos;
    /* sv->save_r3 = ARG ? */
    sv->save_r1 = (vm_offset_t)((int)kss - KF_SIZE);
	sv->save_srr1 = MSR_SUPERVISOR_INT_OFF;
	sv->save_fpscr = 0;									/* Clear all floating point exceptions */
	sv->save_vrsave = 0;								/* Set the vector save state */
	sv->save_vscr[3] = 0x00010000;						/* Supress java mode */
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
	facility_context *fowner;
	int	my_cpu;
	
	assert(new->top_act);
	assert(old->top_act);
	
	my_cpu = cpu_number();
	stack = stack_detach(old);
	new->kernel_stack = stack;
	if (stack == old->stack_privilege) {
		assert(new->stack_privilege);
		old->stack_privilege = new->stack_privilege;
		new->stack_privilege = stack;
	}

	per_proc_info[my_cpu].cpu_flags &= ~traceBE;

	if(real_ncpus > 1) {								/* This is potentially slow, so only do when actually SMP */
		fowner = per_proc_info[my_cpu].FPU_owner;	/* Cache this because it may change */
		if(fowner) {									/* Is there any live context? */
			if(fowner->facAct == old->top_act) {		/* Is it for us? */
				fpu_save(fowner);						/* Yes, save it */
			}
		}
		fowner = per_proc_info[my_cpu].VMX_owner;	/* Cache this because it may change */
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
		old->top_act->mact.specFlags |= (per_proc_info[my_cpu].spcFlags) & (userProtKey|FamVMmode);
	}

	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_SCHED,MACH_STACK_HANDOFF) | DBG_FUNC_NONE,
		     (int)old, (int)new, old->sched_pri, new->sched_pri, 0);


	if(new->top_act->mact.specFlags & runningVM) {	/* Is the new guy running a VM? */
		pmap_switch(new->top_act->mact.vmmCEntry->vmmPmap);	/* Switch to the VM's pmap */
		per_proc_info[my_cpu].VMMareaPhys = (vm_offset_t)new->top_act->mact.vmmCEntry->vmmContextPhys;
		per_proc_info[my_cpu].FAMintercept = new->top_act->mact.vmmCEntry->vmmFAMintercept;
	}
	else {											/* otherwise, we use the task's pmap */
		new_pmap = new->top_act->task->map->pmap;
		if ((old->top_act->task->map->pmap != new_pmap) || (old->top_act->mact.specFlags & runningVM)) {
			pmap_switch(new_pmap);
		}
	}

	thread_machine_set_current(new);
	active_stacks[my_cpu] = new->kernel_stack;
	per_proc_info[my_cpu].Uassist = new->top_act->mact.cthread_self;

	per_proc_info[my_cpu].ppbbTaskEnv = new->top_act->mact.bbTaskEnv;
	per_proc_info[my_cpu].spcFlags = new->top_act->mact.specFlags;

	if (branch_tracing_enabled()) 
		per_proc_info[my_cpu].cpu_flags |= traceBE;
    
	if(trcWork.traceMask) dbgTrace(0x12345678, (unsigned int)old->top_act, (unsigned int)new->top_act);	/* Cut trace entry if tracing */    
    
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
    sv->save_hdr.save_prev = 0;						/* Initialize back chain */
	sv->save_hdr.save_flags = (sv->save_hdr.save_flags & ~SAVtype) | (SAVgeneral << SAVtypeshft);	/* Mark as in use */
    sv->save_hdr.save_act = thread->top_act;		/* Initialize owner */
    thread->top_act->mact.pcb = sv;

}
