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
 * 
 */

#include <kern/thread.h>
#include <kern/thread_act.h>
#include <kern/misc_protos.h>
#include <mach/ppc/thread_status.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>
#include <ppc/fpu_protos.h>
#include <ppc/misc_protos.h>
#include <ppc/savearea.h>
#include <ppc/thread_act.h>
#include <ppc/Firmware.h>

#include <vm/vm_map.h>

extern unsigned int killprint;
extern double FloatInit;
extern unsigned long QNaNbarbarian[4];
extern void thread_bootstrap_return(void);
extern struct   Saveanchor saveanchor;
extern int      real_ncpus;                     /* Number of actual CPUs */


struct ppc_saved_state * get_user_regs(thread_act_t);

#define       USRSTACK        0xc0000000

kern_return_t
thread_userstack(
    thread_t,
    int,
    thread_state_t,
    unsigned int,
    vm_offset_t *,
	int *
);

kern_return_t
thread_entrypoint(
    thread_t,
    int,
    thread_state_t,
    unsigned int,
    vm_offset_t *
); 

unsigned int get_msr_exportmask(void);
unsigned int get_msr_nbits(void);
unsigned int get_msr_rbits(void);
void thread_set_child(thread_act_t child, int pid);
void thread_set_parent(thread_act_t parent, int pid);
		
/*
 * Maps state flavor to number of words in the state:
 */
unsigned int state_count[] = {
	/* FLAVOR_LIST */ 0,
	PPC_THREAD_STATE_COUNT,
	PPC_FLOAT_STATE_COUNT,
	PPC_EXCEPTION_STATE_COUNT,
};

/*
 * thread_getstatus:
 *
 * Get the status of the specified thread.
 */

kern_return_t 
act_machine_get_state(
		      thread_act_t           thr_act,
		      thread_flavor_t        flavor,
		      thread_state_t         tstate,
		      mach_msg_type_number_t *count)
{
	
	register struct savearea *sv;						/* Pointer to the context savearea */
	int i, j;
	unsigned int vrvalidwrk;

	register struct ppc_thread_state *ts;
	register struct ppc_exception_state *es;
	register struct ppc_float_state *fs;
	register struct ppc_vector_state *vs;
	
#if	MACH_ASSERT
    if (watchacts & WA_STATE)
	printf("act_%x act_machine_get_state(thr_act=%x,flav=%x,st=%x,cnt@%x=%x)\n",
	       current_act(), thr_act, flavor, tstate,
	       count, (count ? *count : 0));
#endif	/* MACH_ASSERT */


	switch (flavor) {
		
		case THREAD_STATE_FLAVOR_LIST:
			
			if (*count < 3)  {
				return (KERN_INVALID_ARGUMENT);
			}
		
			tstate[0] = PPC_THREAD_STATE;
			tstate[1] = PPC_FLOAT_STATE;
			tstate[2] = PPC_EXCEPTION_STATE;
			*count = 3;
		
			return KERN_SUCCESS;
	
		case PPC_THREAD_STATE:
	
			if (*count < PPC_THREAD_STATE_COUNT) {			/* Is the count ok? */
				return KERN_INVALID_ARGUMENT;
			}
		
			ts = (struct ppc_thread_state *) tstate;

			sv = (savearea *)(thr_act->mact.pcb);			/* Start with the normal savearea */
			while(sv) {										/* Find the user context */
				if(sv->save_srr1 & MASK(MSR_PR)) {			/* Are we looking at the user context? */
					break;									/* Outta here */
				}
				sv = sv->save_prev;							/* Back chain */
			}
		
			if(sv) {										/* Is there a save area yet? */
				ts->r0	= sv->save_r0;
				ts->r1	= sv->save_r1;
				ts->r2	= sv->save_r2;
				ts->r3	= sv->save_r3;
				ts->r4	= sv->save_r4;
				ts->r5	= sv->save_r5;
				ts->r6	= sv->save_r6;
				ts->r7	= sv->save_r7;
				ts->r8	= sv->save_r8;
				ts->r9	= sv->save_r9;
				ts->r10	= sv->save_r10;
				ts->r11	= sv->save_r11;
				ts->r12	= sv->save_r12;
				ts->r13	= sv->save_r13;
				ts->r14	= sv->save_r14;
				ts->r15	= sv->save_r15;
				ts->r16	= sv->save_r16;
				ts->r17	= sv->save_r17;
				ts->r18	= sv->save_r18;
				ts->r19	= sv->save_r19;
				ts->r20	= sv->save_r20;
				ts->r21	= sv->save_r21;
				ts->r22	= sv->save_r22;
				ts->r23	= sv->save_r23;
				ts->r24	= sv->save_r24;
				ts->r25	= sv->save_r25;
				ts->r26	= sv->save_r26;
				ts->r27	= sv->save_r27;
				ts->r28	= sv->save_r28;
				ts->r29	= sv->save_r29;
				ts->r30	= sv->save_r30;
				ts->r31	= sv->save_r31;
				ts->cr	= sv->save_cr;
				ts->xer	= sv->save_xer;
				ts->lr	= sv->save_lr;
				ts->ctr	= sv->save_ctr;
				ts->srr0 = sv->save_srr0;
				ts->srr1 = sv->save_srr1;
				ts->mq	= sv->save_mq;				/* MQ register (601 only) */
				ts->vrsave	= sv->save_vrsave;		/* VRSAVE register (Altivec only) */
			}
			else {									/* No user state yet. Save seemingly random values. */
						
				for(i=0; i < 32; i+=2) {			/* Fill up with defaults */
					((unsigned int *)&ts->r0)[i] = ((unsigned int *)&FloatInit)[0];
					((unsigned int *)&ts->r0)[i+1] = ((unsigned int *)&FloatInit)[1];
				}
				ts->cr	= 0;
				ts->xer	= 0;
				ts->lr	= ((unsigned int *)&FloatInit)[0];
				ts->ctr	= ((unsigned int *)&FloatInit)[1];
				ts->srr0	= ((unsigned int *)&FloatInit)[0];
				ts->srr1 = MSR_EXPORT_MASK_SET;
				ts->mq	= 0;
				ts->vrsave	= 0;					/* VRSAVE register (Altivec only) */
			}
		
			*count = PPC_THREAD_STATE_COUNT;		/* Pass back the amount we actually copied */
			return KERN_SUCCESS;
	
		case PPC_EXCEPTION_STATE:
	
			if (*count < PPC_EXCEPTION_STATE_COUNT) {
				return KERN_INVALID_ARGUMENT;
			}
		
			es = (struct ppc_exception_state *) tstate;
		
			sv = (savearea *)(thr_act->mact.pcb);			/* Start with the normal savearea */
			while(sv) {										/* Find the user context */
				if(sv->save_srr1 & MASK(MSR_PR)) {			/* Are we looking at the user context? */
					break;									/* Outta here */
				}
				sv = sv->save_prev;							/* Back chain */
			}

			if(sv) {									/* See if valid state yet */
				es->dar = sv->save_dar;
				es->dsisr = sv->save_dsisr;
				es->exception = sv->save_exception;
			}
			else {										/* Nope, not yet */
				es->dar = 0;
				es->dsisr = 0;
				es->exception = ((unsigned int *)&FloatInit)[0];
			}
		
			*count = PPC_EXCEPTION_STATE_COUNT;
			return KERN_SUCCESS;
	
		case PPC_FLOAT_STATE: 
		
			if (*count < PPC_FLOAT_STATE_COUNT)  {
				return KERN_INVALID_ARGUMENT;
			}
		
			fpu_save(thr_act);							/* Just in case it's live, save it */
		
			fs = (struct ppc_float_state *) tstate;		/* Point to destination */
			
			sv = (savearea *)(thr_act->mact.FPU_pcb);	/* Start with the top FPU savearea */
			while(sv) {									/* Find the user context */
				if(!sv->save_level_fp) {				/* Are we looking at the user context? */
					break;								/* Outta here */
				}
				sv = sv->save_prev_float;				/* Back chain */
			}
			
			if(sv) {									/* See if we have any */
				bcopy((char *)&sv->save_fp0, (char *)fs, 33*8); /* 32 registers plus status and pad */
			}
			else {										/* No floating point yet */
			
				for(i=0; i < 32; i++) {					/* Initialize floating points */
					fs->fpregs[i] = FloatInit;			/* Initial value */
				}
				fs->fpscr_pad	= 0;					/* Initial value */
				fs->fpscr 		= 0;					/* Initial value */
			}
			
			*count = PPC_FLOAT_STATE_COUNT;
			
			return KERN_SUCCESS;
	
		case PPC_VECTOR_STATE: 
			
			if (*count < PPC_VECTOR_STATE_COUNT)  {
				return KERN_INVALID_ARGUMENT;
			}
		
			vec_save(thr_act);							/* Just in case it's live, save it */
		
			vs = (struct ppc_vector_state *) tstate;	/* Point to destination */
			
			sv = (savearea *)(thr_act->mact.VMX_pcb);	/* Start with the top FPU savearea */
			while(sv) {									/* Find the user context */
				if(!sv->save_level_vec) {				/* Are we looking at the user context? */
					break;								/* Outta here */
				}
				sv = sv->save_prev_vector;				/* Back chain */
			}
			
			if(sv) {									/* See if we have any */
				
				vrvalidwrk = sv->save_vrvalid;			/* Get the valid flags */
				vs->save_vrvalid = sv->save_vrvalid;	/* Set the valid flags */
				for(j=0; j < 4; j++) vs->save_vscr[j] = sv->save_vscr[j];	/* Set value for vscr */
				
				for(i=0; i < 32; i++) {					/* Copy the saved registers and invalidate the others */
					for(j=0; j < 4; j++) {
						if(vrvalidwrk & 0x80000000) (vs->save_vr)[i][j] = 
							((unsigned int *)&(sv->save_vr0))[(i * 4) + j];	/* We have this register saved */
						else vs->save_vr[i][j] = QNaNbarbarian[j];	/* Set invalid value */
					}
					vrvalidwrk = vrvalidwrk << 1;		/* Shift over to the next */
				}
			}
			else {										/* No vector yet */
			
				for(i=0; i < 32; i++) {					/* Initialize vector registers */
					for(j=0; j < 4; j++) vs->save_vr[i][j] = QNaNbarbarian[j];		/* Initial value */
				}
				for(j=0; j < 4; j++) vs->save_vscr[j] = 0;	/* Initial value */
				vs->save_vrvalid = 0;					/* Clear the valid flags */
			}
			
			for (i=0; i < 4; i++) vs->save_pad5[i] = 0;	/* Clear cruft */
			for (i=0; i < 7; i++) vs->save_pad6[i] = 0;	/* Clear cruft */
			
			*count = PPC_VECTOR_STATE_COUNT;
			return KERN_SUCCESS;
	
		default:
			return KERN_INVALID_ARGUMENT;
	}
}


/*
 * thread_setstatus:
 *
 * Set the status of the specified thread.
 */
kern_return_t 
act_machine_set_state(
		      thread_act_t	     thr_act,
		      thread_flavor_t	     flavor,
		      thread_state_t	     tstate,
		      mach_msg_type_number_t count)
{
  
  	savearea		*sv, *osv, *usv, *ssv;
	unsigned int	spc, i, *srs, isnew, clgn;
	register struct ppc_thread_state *ts;
	register struct ppc_exception_state *es;
	register struct ppc_float_state *fs;
	register struct ppc_vector_state *vs;
	spl_t			spl;
	
    int	kernel_act = thr_act->kernel_loading ||	thr_act->kernel_loaded;

#if	MACH_ASSERT
    if (watchacts & WA_STATE)
	printf("act_%x act_machine_set_state(thr_act=%x,flav=%x,st=%x,cnt=%x)\n",
	       current_act(), thr_act, flavor, tstate, count);
#endif	/* MACH_ASSERT */
		
//	dbgTrace((unsigned int)thr_act, (unsigned int)sv, flavor);	/* (TEST/DEBUG) */

	clgn = count;											/* Get the count */
	
	switch (flavor) {										/* Validate the count before we do anything else */
		case PPC_THREAD_STATE:
			
			if (clgn < PPC_THREAD_STATE_COUNT)  {			/* Is it too short? */
				return KERN_INVALID_ARGUMENT;				/* Yeah, just leave... */
			}
			
			if(clgn > PPC_THREAD_STATE_COUNT) clgn = PPC_THREAD_STATE_COUNT;	/* If too long, pin it at max */
			break;
			
		case PPC_EXCEPTION_STATE:
			
			if (clgn < PPC_EXCEPTION_STATE_COUNT)  {		/* Is it too short? */
				return KERN_INVALID_ARGUMENT;				/* Yeah, just leave... */
			}
			
			if(clgn > PPC_EXCEPTION_STATE_COUNT) clgn = PPC_EXCEPTION_STATE_COUNT;	/* If too long, pin it at max */
			break;
			
		case PPC_FLOAT_STATE:
			
			if (clgn < PPC_FLOAT_STATE_COUNT)  {			/* Is it too short? */
				return KERN_INVALID_ARGUMENT;				/* Yeah, just leave... */
			}
			
			if(clgn > PPC_FLOAT_STATE_COUNT) clgn = PPC_FLOAT_STATE_COUNT;	/* If too long, pin it at max */
			break;
			

		case PPC_VECTOR_STATE:
			
			if (clgn < PPC_VECTOR_STATE_COUNT)  {			/* Is it too short? */
				return KERN_INVALID_ARGUMENT;				/* Yeah, just leave... */
			}
			
			if(clgn > PPC_VECTOR_STATE_COUNT) clgn = PPC_VECTOR_STATE_COUNT;	/* If too long, pin it at max */
			break;
			
		default:
			return KERN_INVALID_ARGUMENT;
	}

    isnew = 0;												/* Remember when we make a new one */
	
	switch (flavor) {
		
		case PPC_THREAD_STATE:
		case PPC_EXCEPTION_STATE:
				
			ts = (struct ppc_thread_state *)tstate;
		
			sv = (savearea *)thr_act->mact.pcb;				/* Get the top savearea on the stack */
			osv = 0;										/* Set no user savearea yet */	
			
			while(sv) {										/* Find the user context */
				if(sv->save_srr1 & MASK(MSR_PR)) {			/* Are we looking at the user context? */
					break;									/* Outta here */
				}
				osv = sv;									/* Save the last one */
				sv = sv->save_prev;							/* Get the previous context */
			}
		
			if(!sv) {										/* We didn't find a user context so allocate and initialize one */
				isnew = 1;									/* Remember we made a new one */
				sv = save_alloc();							/* Get one */
				sv->save_act = thr_act;						/* Point to the activation */
				sv->save_flags |= SAVattach;				/* Say that it is in use  */
				sv->save_srr1 = MSR_EXPORT_MASK_SET & ~MASK(MSR_PR);	/* Assume kernel state */
				sv->save_xfpscrpad = 0;						/* Start with a clear fpscr */
				sv->save_xfpscr = 0;						/* Start with a clear fpscr */
				
				spc = (unsigned int)thr_act->map->pmap->space;	/* Get the space we're in */
				
				srs = (unsigned int *)&sv->save_sr0;		/* Point to the SRs */
				for(i=0; i < 16; i++) {						/* Fill in the SRs for the new context */
					srs[i] = SEG_REG_PROT | (i<<20) | spc;	/* Set the SR */
				}
				
				sv->save_sr_copyin = SEG_REG_PROT | (SR_COPYIN_NUM<<20) | spc;	/* Make sure the copyin is set */
				
				if(osv) {									/* Did we already have one? */
					osv->save_prev = sv;					/* Chain us on the end */
				}
				else {										/* We are the first */
					thr_act->mact.pcb = (pcb_t)sv;			/* Put it there */
				}
				sv->save_prev = 0;							/* Properly terminate the chain */

			}
			
			if(flavor == PPC_THREAD_STATE) {				/* Are we updating plain state? */
			
				sv->save_r0		= ts->r0;
				sv->save_r1		= ts->r1;
				sv->save_r2		= ts->r2;
				sv->save_r3		= ts->r3;
				sv->save_r4		= ts->r4;
				sv->save_r5		= ts->r5;
				sv->save_r6		= ts->r6;
				sv->save_r7		= ts->r7;
				sv->save_r8		= ts->r8;
				sv->save_r9		= ts->r9;
				sv->save_r10	= ts->r10;
				sv->save_r11	= ts->r11;
				sv->save_r12	= ts->r12;
				sv->save_r13	= ts->r13;
				sv->save_r14	= ts->r14;
				sv->save_r15	= ts->r15;
				sv->save_r16	= ts->r16;
				sv->save_r17	= ts->r17;
				sv->save_r18	= ts->r18;
				sv->save_r19	= ts->r19;
				sv->save_r20	= ts->r20;
				sv->save_r21	= ts->r21;
				sv->save_r22	= ts->r22;
				sv->save_r23	= ts->r23;
				sv->save_r24	= ts->r24;
				sv->save_r25	= ts->r25;
				sv->save_r26	= ts->r26;
				sv->save_r27	= ts->r27;
				sv->save_r28	= ts->r28;
				sv->save_r29	= ts->r29;
				sv->save_r30	= ts->r30;
				sv->save_r31	= ts->r31;
			
				sv->save_cr		= ts->cr;
				sv->save_xer	= ts->xer;
				sv->save_lr		= ts->lr;
				sv->save_ctr	= ts->ctr;
				sv->save_srr0	= ts->srr0;
				sv->save_mq		= ts->mq;	
				sv->save_vrsave	= ts->vrsave;					/* VRSAVE register (Altivec only) */

				sv->save_srr1 	= MSR_PREPARE_FOR_IMPORT(sv->save_srr1, ts->srr1);	/* Set the bits we can change */
	
				if(!kernel_act) sv->save_srr1 |= MSR_EXPORT_MASK_SET;	/* If not a kernel guy, force the magic bits on */	
			
				sv->save_srr1 &= ~(MASK(MSR_FP) | MASK(MSR_VEC));	/* Make sure we don't enable the floating point unit */
			
				if(isnew) {										/* Is it a new one? */
					sv->save_dar = 0;							/* Yes, these need initialization also */
					sv->save_dsisr = 0;
					sv->save_exception = 0;
				}
				
				return KERN_SUCCESS;
			}
			else {												/* This must be exception state */
				if(isnew)										/* If new, we need to initialize the normal registers */
					for(i=0; i < 32; i+=2) {					/* Fill up with defaults */
						((unsigned int *)&sv->save_r0)[i] = ((unsigned int *)&FloatInit)[0];
						((unsigned int *)&sv->save_r0)[i+1] = ((unsigned int *)&FloatInit)[1];
					}
					sv->save_cr	= 0;
					sv->save_xer	= 0;
					sv->save_lr	= ((unsigned int *)&FloatInit)[0];
					sv->save_ctr	= ((unsigned int *)&FloatInit)[1];
					sv->save_srr0	= ((unsigned int *)&FloatInit)[0];
					sv->save_srr1 = MSR_EXPORT_MASK_SET;
					sv->save_mq	= 0;
					sv->save_vrsave	= 0;						/* VRSAVE register (Altivec only) */
			}

			es = (struct ppc_exception_state *) tstate;
		
			sv->save_dar = es->dar;
			sv->save_dsisr = es->dsisr;
			sv->save_exception = es->exception;

			return KERN_SUCCESS;
	
		case PPC_FLOAT_STATE:

			spl = splhigh();								/* Don't bother me while I'm zapping the owner stuff */
			
			if (per_proc_info[cpu_number()].FPU_thread == (unsigned int)thr_act)	/* If we own the FPU, and */
				if(!thr_act->mact.FPU_lvl) per_proc_info[cpu_number()].FPU_thread = 0; /* it's user level, say we don't own it any more */
			
			splx(spl);										/* Restore the interrupt level */
			
			sv = (savearea *)thr_act->mact.FPU_pcb;			/* Get the top savearea on the stack */
			osv = 0;										/* Set no user savearea yet */	
			
			if(sv && (sv->save_level_fp == 1)) {			/* Is the first savearea invalid? */
				thr_act->mact.FPU_pcb = (pcb_t)sv->save_prev_float;	/* Yes, clean it out */
				sv->save_flags &= ~SAVfpuvalid;				/* Clear the floating point flag */
				if(!(sv->save_flags & SAVinuse)) {			/* Anyone left with this one? */			
					save_release(sv);						/* Nope, release it */
				}
				sv = (savearea *)thr_act->mact.FPU_pcb;		/* Get the new top savearea on the stack */
			}

			while(sv) {										/* Find the user context */
				if(!(sv->save_level_fp)) {					/* Are we looking at the user context? */
					break;									/* Outta here */
				}
				osv = sv;									/* Save the last one */
				sv = sv->save_prev_float;					/* Get the previous context */
			}
			
			if(!sv) {										/* We didn't find a user context so allocate and initialize one */
	
				sv = (savearea *)thr_act->mact.pcb;			/* Point to the top savearea on the normal stack */
	
				while(sv) {									/* Have we hit the end? */
					if(!(sv->save_flags & SAVfpuvalid)) break;	/* Is floating point in use here? */
					sv = sv->save_prev;						/* Back chain */
				}
	
				if(!sv) {									/* If there wasn't one on the normal chain, check vector */
					sv = (savearea *)thr_act->mact.VMX_pcb;	/* Point to the top savearea on the vector stack */
					while(sv) {								/* Have we hit the end? */
						if(!(sv->save_flags & SAVfpuvalid)) break;	/* Is floating point in use here? */
						sv = sv->save_prev_vector;			/* Back chain */
					}
				}
				
				if(!sv) {									/* Do we have one yet? */
					sv = save_alloc();						/* If we still don't have one, get a new one */
					sv->save_act = thr_act;					/* Point to the activation */
					
					spc=(unsigned int)thr_act->map->pmap->space;	/* Get the space we're in */
					
					srs=(unsigned int *)&sv->save_sr0;		/* Point to the SRs */
					for(i=0; i < 16; i++) {					/* Fill in the SRs for the new context */
						srs[i] = SEG_REG_PROT | (i<<20) | spc;	/* Set the SR */
					}
					
					sv->save_sr_copyin = SEG_REG_PROT | (SR_COPYIN_NUM<<20) | spc;	/* Make sure the copyin is set */
				}
					
				if(osv) {									/* Did we already have one? */
					osv->save_prev_float = sv;				/* Chain us on the end */
				}
				else {										/* We are the first */
					thr_act->mact.FPU_pcb = (pcb_t)sv;		/* Put it there */
				}
				sv->save_prev_float = 0;					/* Properly terminate the chain */
				sv->save_level_fp = 0;						/* Make sure we are for the user level */
				sv->save_flags |= SAVfpuvalid;				/* Say that it is in use by floating point */
			}
			
			fs = (struct ppc_float_state *) tstate;			/* Point to source */

		
			bcopy((char *)fs, (char *)&sv->save_fp0, clgn*4); /* 32 registers plus status and pad */
		
			usv = find_user_regs(thr_act);					/* Find the user registers */
			if(!usv) usv = get_user_regs(thr_act);			/* Didn't find any, allocate and initialize one */
			
			usv->save_xfpscrpad = sv->save_fpscr_pad;		/* Copy the pad value to normal */	
			usv->save_xfpscr = sv->save_fpscr;				/* Copy the fpscr value to normal */	
			
			return KERN_SUCCESS;
			
	
		case PPC_VECTOR_STATE:

			spl = splhigh();								/* Don't bother me while I'm zapping the owner stuff */
			
			if (per_proc_info[cpu_number()].VMX_thread == (unsigned int)thr_act)	/* If we own the vector, and */
				if(!thr_act->mact.VMX_lvl) per_proc_info[cpu_number()].VMX_thread = 0; /* it's user level, say we don't own it any more */
			
			splx(spl);										/* Restore the interrupt level */
			
			sv = (savearea *)thr_act->mact.VMX_pcb;			/* Get the top savearea on the stack */
			osv = 0;										/* Set no user savearea yet */	
			
			if(sv && (sv->save_level_vec == 1)) {			/* Is the first savearea invalid? */
				thr_act->mact.VMX_pcb = (pcb_t)sv->save_prev_vector;	/* Yes, clean it out */
				sv->save_flags &= ~SAVvmxvalid;				/* Clear the floating point flag */
				if(!(sv->save_flags & SAVinuse)) {			/* Anyone left with this one? */			
					save_release(sv);						/* Nope, release it */
				}
				sv = (savearea *)thr_act->mact.VMX_pcb;		/* Get the new top savearea on the stack */
			}
			
			while(sv) {										/* Find the user context */
				if(!(sv->save_level_vec)) {					/* Are we looking at the user context? */
					break;									/* Outta here */
				}
				osv = sv;									/* Save the last one */
				sv = sv->save_prev_vector;					/* Get the previous context */
			}
			
			if(!sv) {										/* We didn't find a user context so allocate and initialize one */
	
				sv = (savearea *)thr_act->mact.pcb;			/* Point to the top savearea on the normal stack */
	
				while(sv) {									/* Have we hit the end? */
					if(!(sv->save_flags & SAVvmxvalid)) break;	/* Is vector in use here? */
					sv = sv->save_prev;						/* Back chain */
				}
	
				if(!sv) {									/* If there wasn't one on the normal chain, check vector */
					sv = (savearea *)thr_act->mact.FPU_pcb;	/* Point to the top savearea on the FPU stack */
					while(sv) {								/* Have we hit the end? */
						if(!(sv->save_flags & SAVvmxvalid)) break;	/* Is vector in use here? */
						sv = sv->save_prev_float;			/* Get the previous context */
					}
				}
				
				if(!sv) {									/* Do we have one yet? */
					sv = save_alloc();						/* If we still don't have one, get a new one */
					sv->save_act = thr_act;					/* Point to the activation */
					
					spc=(unsigned int)thr_act->map->pmap->space;	/* Get the space we're in */
					
					srs=(unsigned int *)&sv->save_sr0;		/* Point to the SRs */
					for(i=0; i < 16; i++) {					/* Fill in the SRs for the new context */
						srs[i] = SEG_REG_PROT | (i<<20) | spc;	/* Set the SR */
					}
					
					sv->save_sr_copyin = SEG_REG_PROT | (SR_COPYIN_NUM<<20) | spc;	/* Make sure the copyin is set */
				}
					
				if(osv) {									/* Did we already have one? */
					osv->save_prev_vector = sv;				/* Chain us on the end */
				}
				else {										/* We are the first */
					thr_act->mact.VMX_pcb = (pcb_t)sv;		/* Put it there */
				}
				sv->save_prev_vector = 0;					/* Properly terminate the chain */
				sv->save_level_vec = 0;						/* Make sure we are for the user level */
				sv->save_flags |= SAVvmxvalid;				/* Say that it is in use by vector */
			}

			
			vs = (struct ppc_vector_state *) tstate;		/* Point to source */
		
			bcopy((char *)vs, (char *)&sv->save_vr0, clgn*4); /* 32 registers plus status and validity and pad */
		
			return KERN_SUCCESS;
			
		
		default:
			return KERN_INVALID_ARGUMENT;
    }
}

/*
 *		Duplicates the context of one thread into a new one.
 *		The new thread is assumed to be new and have no user state contexts.
 *		We also assume that the old thread can't be running anywhere.
 *
 *		We're only going to be duplicating user context here.  That means that we will have to 
 *		eliminate any floating point or vector kernel contexts and carry across the user state ones.
 *		We will optimize and cram all states into one savearea.  Actually that will be the easiest thing
 *		to do.
 */

void act_thread_dup(thread_act_t old, thread_act_t new) {

  	savearea		*sv, *osv, *fsv;
	unsigned int	spc, i, *srs;
	
	fpu_save(old);									/* Make certain floating point state is all saved */
	vec_save(old);									/* Make certain the vector state is all saved */
	
	osv = (savearea *)new->mact.pcb;				/* Get the top savearea on the stack */
	sv = 0;											/* Set no new user savearea yet */	
	
	while(osv) {									/* Find the user context */
		if(osv->save_srr1 & MASK(MSR_PR)) {			/* Are we looking at the user context? */
			sv=osv;									/* Say which to use */
			break;									/* Outta here */
		}
		osv=osv->save_prev;							/* Get the previous context */
	}
	
	if(!sv) {										/* We didn't find a user context so allocate and initialize one */
		osv = (savearea *)new->mact.pcb;			/* Point to the top savearea on the stack */
		sv = save_alloc();							/* Get one */
		sv->save_flags |= SAVattach;				/* Say that it is in use  */
		sv->save_act = new;							/* Point to the activation */
		
		spc=(unsigned int)new->map->pmap->space;	/* Get the space we're in */
		
		srs=(unsigned int *)&sv->save_sr0;			/* Point to the SRs */
		for(i=0; i < 16; i++) {						/* Fill in the SRs for the new context */
			srs[i] = SEG_REG_PROT | (i<<20) | spc;	/* Set the SR */
		}
		
		sv->save_sr_copyin = SEG_REG_PROT | (SR_COPYIN_NUM<<20) | spc;	/* Make sure the copyin is set */
		
		if(osv) {									/* Did we already have one? */
			sv->save_prev = osv->save_prev;			/* Move the back chain of the top savearea */
			osv->save_prev = sv;					/* Chain us just after it */
		}
		else {										/* We are the first */
			new->mact.pcb = (pcb_t)sv;				/* Make it the active one */
		}
		
	}

	osv = (savearea *)(old->mact.pcb);				/* Start with the normal savearea */
	while(osv) {									/* Find the user context */
		if(osv->save_srr1 & MASK(MSR_PR)) {			/* Are we looking at the user context? */
			break;									/* Outta here */
		}
		osv = osv->save_prev;						/* Back chain */
	}

	bcopy((char *)&osv->save_srr0, (char *)&sv->save_srr0, sizeof(struct ppc_thread_state)); /* Copy in normal state stuff */
	
	sv->save_xfpscrpad = osv->save_xfpscrpad;		/* Copy the pad value to old */	
	sv->save_xfpscr = osv->save_xfpscr;				/* Copy the fpscr value to old */	

	new->mact.FPU_pcb = (pcb_t)0 ;					/* Initialize floating point savearea */
	new->mact.FPU_lvl = (pcb_t)0 ;					/* Initialize floating point level */
	new->mact.FPU_cpu = 0 ;							/* Initialize last used cpu (FP not live, so this doesn't really matter) */
	new->mact.VMX_pcb = (pcb_t)0 ;					/* Initialize vector savearea */
	new->mact.VMX_lvl = (pcb_t)0 ;					/* Initialize vector level */
	new->mact.VMX_cpu = 0 ;							/* Initialize last used cpu (vector not live, so this doesn't reall matter) */

	sv->save_prev_float = (savearea *)0;			/* Clear the back chain */
	sv->save_prev_vector = (savearea *)0;			/* Clear the back chain */
	sv->save_level_fp = 0;							/* Set the level for FP */
	sv->save_level_vec = 0;							/* Set the level for vector */
	
	sv->save_srr1 &= ~(MASK(MSR_FP) | MASK(MSR_VEC));	/* Make certain that floating point and vector are turned off */
	
	fsv = (savearea *)old->mact.FPU_pcb;			/* Get the start of the floating point chain */
	while(fsv) {									/* Look until the end or we find it */
		if(!(fsv->save_level_fp)) {					/* Is the the user state stuff? (the level is 0 if so) */	
			sv->save_flags |= SAVfpuvalid;			/* Show we have it */
			bcopy((char *)&osv->save_fp0, (char *)&sv->save_fp0, sizeof(struct ppc_float_state)); /* Copy in floating point state stuff */
			new->mact.FPU_pcb = (pcb_t)sv;			/* Make it the active one */
			break;									/* Done, everything else is all set up... */
		}
		fsv = fsv->save_prev_float;					/* Try the previous one */
	}
	
	fsv = (savearea *)old->mact.VMX_pcb;			/* Get the start of the vector chain */
	while(fsv) {									/* Look until the end or we find it */
		if(!(fsv->save_level_vec)) {				/* Is the the user state stuff? (the level is 0 if so) */	
			sv->save_flags |= SAVvmxvalid;			/* Show we have it */
			bcopy((char *)&osv->save_vr0, (char *)&sv->save_vr0, sizeof(struct ppc_vector_state)); /* Copy in Altivec state stuff */
			new->mact.VMX_pcb = (pcb_t)sv;			/* Make it the active one */
			break;									/* Done, everything else is all set up... */
		}
		fsv = fsv->save_prev_vector;				/* Try the previous one */
	}

	return;											/* Bye bye... */
}

/*
 *		Initializes a fresh set of user state values.  If there is no user state context,
 *		one is created. Floats and VMX are not created. We set initial values for everything.
 */

struct ppc_saved_state * get_user_regs(thread_act_t act) {

  	savearea		*sv, *osv;
	unsigned int	spc, i, *srs;

	sv = (savearea *)act->mact.pcb;					/* Get the top savearea on the stack */
	osv = 0;										/* Set no user savearea yet */	
	
	while(sv) {										/* Find the user context */
		if(sv->save_srr1 & MASK(MSR_PR)) {			/* Are we looking at the user context? */
			break;									/* Outta here */
		}
		osv = sv;									/* Save the last one */
		sv = sv->save_prev;							/* Get the previous context */
	}

	if(!sv) {										/* We didn't find a user context so allocate and initialize one */
		sv = save_alloc();							/* Get one */
		sv->save_flags |= SAVattach;				/* Say that it is in use  */
		sv->save_act = act;							/* Point to the activation */
		
		if(osv) {									/* Did we already have one? */
			osv->save_prev = sv;					/* Chain us on the end */
		}
		else {										/* We are the first */
			act->mact.pcb = (pcb_t)sv;				/* Put it there */
		}
		sv->save_prev = 0;							/* Properly terminate the chain */
	}

	for(i=0; i < 32; i+=2) {						/* Fill up with defaults */
		((unsigned int *)&sv->save_r0)[i] = ((unsigned int *)&FloatInit)[0];
		((unsigned int *)&sv->save_r0)[i+1] = ((unsigned int *)&FloatInit)[1];
	}
	sv->save_cr	= 0;
	sv->save_xer	= 0;
	sv->save_lr	= ((unsigned int *)&FloatInit)[0];
	sv->save_ctr	= ((unsigned int *)&FloatInit)[1];
	sv->save_srr0	= ((unsigned int *)&FloatInit)[0];
	sv->save_srr1 = MSR_EXPORT_MASK_SET;
	sv->save_mq	= 0;
	sv->save_vrsave = 0;							/* VRSAVE register (Altivec only) */
	sv->save_xfpscrpad = 0;							/* Start with a clear fpscr */
	sv->save_xfpscr = 0;							/* Start with a clear fpscr */
	
	spc=(unsigned int)act->map->pmap->space;		/* Get the space we're in */
	
	srs=(unsigned int *)&sv->save_sr0;				/* Point to the SRs */
	for(i=0; i < 16; i++) {							/* Fill in the SRs for the new context */
		srs[i] = SEG_REG_PROT | (i<<20) | spc;		/* Set the SR */
	}
	
	sv->save_sr_copyin = SEG_REG_PROT | (SR_COPYIN_NUM<<20) | spc;	/* Make sure the copyin is set */
	
	return (struct ppc_saved_state *)sv;			/* Bye bye... */
}

/*
 *		Find the user state context.  If there is no user state context,
 *		we just return a 0.
 */

struct ppc_saved_state * find_user_regs(thread_act_t act) {

  	savearea		*sv;

	sv = (savearea *)act->mact.pcb;					/* Get the top savearea on the stack */
	
	while(sv) {										/* Find the user context */
		if(sv->save_srr1 & MASK(MSR_PR)) {			/* Are we looking at the user context? */
			break;									/* Outta here */
		}
		sv = sv->save_prev;							/* Get the previous context */
	}
	
	return (struct ppc_saved_state *)sv;			/* Bye bye... */
}

/*
 *		Find the user state floating pointcontext.  If there is no user state context,
 *		we just return a 0.
 */

struct ppc_float_state * find_user_fpu(thread_act_t act) {

  	savearea		*fsv;

	fsv = (savearea *)act->mact.FPU_pcb;			/* Get the start of the floating point chain */
	while(fsv) {									/* Look until the end or we find it */
		if(!(fsv->save_level_fp)) break;			/* Is the the user state stuff? (the level is 0 if so) */	
		fsv = fsv->save_prev_float;					/* Try the previous one */
	}
	
	return (struct ppc_float_state *)&(fsv->save_fp0);	/* Bye bye... */
}

/*
 * thread_userstack:
 *
 * Return the user stack pointer from the machine
 * dependent thread state info.
 */
kern_return_t
thread_userstack(
    thread_t            thread,
    int                 flavor,
    thread_state_t      tstate,
    unsigned int        count,
    vm_offset_t         *user_stack,
	int					*customstack
)
{
        struct ppc_thread_state *state;

        /*
         * Set a default.
         */
        if (*user_stack == 0)
                *user_stack = USRSTACK;
		if (customstack)
			*customstack = 0;

        switch (flavor) {
        case PPC_THREAD_STATE:
                if (count < PPC_THREAD_STATE_COUNT)
                        return (KERN_INVALID_ARGUMENT);
 
                state = (struct ppc_thread_state *) tstate;
    
                /*
                 * If a valid user stack is specified, use it.
                 */
                *user_stack = state->r1 ? state->r1: USRSTACK;

				if (customstack && state->r1)
					*customstack = 1;
					
                break;
        default :
                return (KERN_INVALID_ARGUMENT);
        }
                
        return (KERN_SUCCESS);
}    

kern_return_t
thread_entrypoint(
    thread_t            thread,
    int                 flavor,
    thread_state_t      tstate,
    unsigned int        count,
    vm_offset_t         *entry_point
)
{ 
    struct ppc_thread_state     *state;
 
    /*
     * Set a default.
     */
    if (*entry_point == 0)
        *entry_point = VM_MIN_ADDRESS;
    
    switch (flavor) {   
    
    case PPC_THREAD_STATE:
        if (count < PPC_THREAD_STATE_COUNT)
            return (KERN_INVALID_ARGUMENT);

        state = (struct ppc_thread_state *) tstate;

        /* 
         * If a valid entry point is specified, use it.
         */     
        *entry_point = state->srr0 ? state->srr0: VM_MIN_ADDRESS;
        break; 
    default: 
        return (KERN_INVALID_ARGUMENT);
    }           
 
    return (KERN_SUCCESS);
}   

unsigned int get_msr_exportmask(void)
{
        return (MSR_EXPORT_MASK_SET);
}

unsigned int get_msr_nbits(void)
{
        return (MASK(MSR_POW)|MASK(MSR_ILE)|MASK(MSR_IP)|MASK(MSR_LE));
}
unsigned int get_msr_rbits(void)
{
	return (MASK(MSR_PR)|MASK(MSR_ME)|MASK(MSR_IR)|MASK(MSR_DR)|MASK(MSR_EE));
}

void  thread_set_child(thread_act_t child, int pid)
{
	struct ppc_saved_state *child_state;
	
	child_state = find_user_regs(child);
	
	child_state->r3 = pid;
	child_state->r4 = 1;
}
void  thread_set_parent(thread_act_t parent, int pid)
{
	struct ppc_saved_state *parent_state;
	
	parent_state = find_user_regs(parent);
	
	parent_state->r3 = pid;
	parent_state->r4 = 0;
}

/*
 *		Saves the complete context (general, floating point, and vector) of the current activation.
 *		We will collect everything into one savearea and pass that back.
 *
 *		The savearea is made to look like it belongs to the source activation.  This needs to 
 *		be adjusted when these contexts are attached to a new activation.
 *
 */

void *act_thread_csave(void) {

  	savearea		*sv, *osv, *fsv;
	unsigned int	spc, i, *srs;
	
	thread_act_t act;	
	
	fpu_save(current_act());						/* Make certain floating point state is all saved */
	vec_save(current_act());						/* Make certain the vector state is all saved */

	sv = save_alloc();								/* Get a fresh save area */
	hw_atomic_add(&saveanchor.saveneed, 1);			/* Account for the extra saveareas "need" */

	act = current_act();							/* Find ourselves */	
	
	sv->save_flags |= SAVattach;					/* Say that it is in use  */
	sv->save_act = act;								/* Point to the activation */
	
	spc=(unsigned int)act->map->pmap->space;		/* Get the space we're in */
	
	srs=(unsigned int *)&sv->save_sr0;				/* Point to the SRs */
	for(i=0; i < 16; i++) {							/* Fill in the SRs for the new context */
		srs[i] = SEG_REG_PROT | (i<<20) | spc;		/* Set the SR */
	}
	
	sv->save_sr_copyin = SEG_REG_PROT | (SR_COPYIN_NUM<<20) | spc;	/* Make sure the copyin is set */

	osv = (savearea *)(act->mact.pcb);				/* Start with the normal savearea */
	fsv = 0;										/* Assume none */
	while(osv) {									/* Find the user context */
		if(osv->save_srr1 & MASK(MSR_PR)) {			/* Are we looking at the user context? */
			fsv = osv;								/* Remember what we found */
			break;									/* Outta here */
		}
		osv = osv->save_prev;						/* Back chain */
	}

	if(!fsv) {										/* Did we find one? */
		for(i=0; i < 32; i+=2) {					/* Fill up with defaults */
			((unsigned int *)&sv->save_r0)[i] = ((unsigned int *)&FloatInit)[0];
			((unsigned int *)&sv->save_r0)[i+1] = ((unsigned int *)&FloatInit)[1];
		}
		sv->save_cr	= 0;
		sv->save_xer	= 0;
		sv->save_lr	= ((unsigned int *)&FloatInit)[0];
		sv->save_ctr	= ((unsigned int *)&FloatInit)[1];
		sv->save_srr0	= ((unsigned int *)&FloatInit)[0];
		sv->save_srr1 = MSR_EXPORT_MASK_SET;
		sv->save_mq	= 0;
		sv->save_vrsave = 0;						/* VRSAVE register (Altivec only) */
		sv->save_xfpscrpad = 0;						/* Start with a clear fpscr */
		sv->save_xfpscr = 0;						/* Start with a clear fpscr */
	}
	else {											/* We did find one, copy it */
		bcopy((char *)&fsv->save_srr0, (char *)&sv->save_srr0, sizeof(struct ppc_thread_state)); /* Copy in normal state stuff */
		sv->save_xfpscrpad = osv->save_xfpscrpad;	/* Copy the pad value to old */	
		sv->save_xfpscr = osv->save_xfpscr;			/* Copy the fpscr value to old */	
	}

	
	sv->save_prev = (savearea *)0xDEBB1ED0;			/* Eye catcher for debug */
	sv->save_prev_float = (savearea *)0xE5DA11A5;	/* Eye catcher for debug */
	sv->save_prev_vector = (savearea *)0;			/* Clear */
	sv->save_level_fp = 0;							/* Set the level for FP */
	sv->save_level_vec = 0;							/* Set the level for vector */
	
	sv->save_srr1 &= ~(MASK(MSR_FP) | MASK(MSR_VEC));	/* Make certain that floating point and vector are turned off */
	
	fsv = (savearea *)act->mact.FPU_pcb;			/* Get the start of the floating point chain */
	while(fsv) {									/* Look until the end or we find it */
		if(!(fsv->save_level_fp)) {					/* Is the the user state stuff? (the level is 0 if so) */	
			sv->save_flags |= SAVfpuvalid;			/* Show we have it */
			bcopy((char *)&fsv->save_fp0, (char *)&sv->save_fp0, sizeof(struct ppc_float_state)); /* Copy in floating point state stuff */
			break;									/* Done, everything else is all set up... */
		}
		fsv = fsv->save_prev_float;					/* Try the previous one */
	}
	
	fsv = (savearea *)act->mact.VMX_pcb;			/* Get the start of the vector chain */
	while(fsv) {									/* Look until the end or we find it */
		if(!(fsv->save_level_vec)) {				/* Is the the user state stuff? (the level is 0 if so) */	
			sv->save_flags |= SAVvmxvalid;			/* Show we have it */
			bcopy((char *)&fsv->save_vr0, (char *)&sv->save_vr0, sizeof(struct ppc_vector_state)); /* Copy in Altivec state stuff */
			break;									/* Done, everything else is all set up... */
		}
		fsv = fsv->save_prev_vector;				/* Try the previous one */
	}

	return (void *)sv;								/* Bye bye... */
}



/*
 *		Attaches saved user state context to an activation.  We will replace any
 *		user state context with what is passed in.  The saved context consists of a
 *		savearea that was setup by 
 *		We will collect everything into one savearea and pass that back.
 *
 *		The savearea is made to look like it belongs to the source activation.  This needs to 
 *		be adjusted when these contexts are attached to a new activation.
 *
 */

void act_thread_catt(void *ctx) {

  	savearea		*sv, *osv, *fsv, *psv;
	unsigned int	spc, i, *srs;
	thread_act_t act;	
	
	sv = (savearea *)ctx;							/* Make this easier for C */
	
	if((sv->save_prev != (savearea *)0xDEBB1ED0) || (sv->save_prev_float != (savearea *)0xE5DA11A5)) {	/* See if valid savearea */
		panic("act_thread_catt: attempt to attach invalid context savearea - %08X\n", sv);	/* Die */
	}

	act = current_act();							/* Find ourselves */	
		
/*
 *	This next bit insures that any live facility context for this thread is discarded on every processor
 *	that may have it. 
 *
 *	Note that this will not be good if the activation has any kernel fp or vec contexts that are live.
 *	We won't worry about it because it would be silly to call this if we are a kernel task using altivec
 *	or floating point......
 */
 
	for(i=0; i < real_ncpus; i++) {							/* Cycle through processors */
		(void)hw_compare_and_store((unsigned int)act, 0, &per_proc_info[i].FPU_thread);	/* Clear if ours */
		(void)hw_compare_and_store((unsigned int)act, 0, &per_proc_info[i].VMX_thread);	/* Clear if ours */
	}


/*
 *	Now we make the savearea look like we own it
 */

	sv->save_prev = (savearea *)0;					/* Clear */
	sv->save_prev_float = (savearea *)0;			/* Clear */
	sv->save_prev_vector = (savearea *)0;			/* Clear */
	sv->save_act = act;								/* Point to the activation */
	
	spc=(unsigned int)act->map->pmap->space;		/* Get the space we're in */
	
	srs=(unsigned int *)&sv->save_sr0;				/* Point to the SRs */
	for(i=0; i < 16; i++) {							/* Fill in the SRs for the new context */
		srs[i] = SEG_REG_PROT | (i<<20) | spc;		/* Set the SRs */
	}
	
	sv->save_sr_copyin = SEG_REG_PROT | (SR_COPYIN_NUM<<20) | spc;	/* Make sure the copyin is set */
	
	osv = (savearea *)act->mact.VMX_pcb;			/* Get the top vector savearea */
	
	if(osv && (osv->save_level_vec == 1)) {			/* Is the first one a special dummy one? */
		psv = osv;									/* Yes, remember it */
		osv = osv->save_prev_vector;				/* Step to the next */
		(savearea *)act->mact.VMX_pcb = osv;		/* Dequeue it */
		psv->save_flags &= ~SAVvmxvalid;			/* Clear the VMX flag */
		if(!(psv->save_flags & SAVinuse)) {			/* Anyone left with this one? */			
			save_release(psv);						/* Nope, release it */
		}
	}
	
	psv = 0;
	while(osv) {									/* Any VMX saved state? */
		if(!(osv->save_level_vec)) break;			/* Leave if this is user state */
		psv = osv;									/* Save previous savearea address */
		osv = osv->save_prev_vector;				/* Get one underneath our's */
	}
	
	if(osv) {										/* Did we find one? */
		if(psv) psv->save_prev_vector = 0;			/* Yes, clear pointer to it (it should always be last) or */	
		else act->mact.VMX_pcb = 0;					/* to the start if the only one */

		osv->save_flags &= ~SAVvmxvalid;			/* Clear the VMX flag */
		if(!(osv->save_flags & SAVinuse)) {			/* Anyone left with this one? */			
			save_release(osv);						/* Nope, release it */
		}
	}
	
	if(sv->save_flags & SAVvmxvalid) {				/* Are we adding Altivec context? */
		if(psv)	psv->save_prev_vector = sv;			/* Yes, chain us to the end or */
		else act->mact.VMX_pcb = (pcb_t)sv;			/* to the start if the only one */
	}
	
	osv = (savearea *)act->mact.FPU_pcb;			/* Get the top floating point savearea */
	
	if(osv && (osv->save_level_fp == 1)) {			/* Is the first one a special dummy one? */
		psv = osv;									/* Yes, remember it */
		osv = osv->save_prev_float;					/* Step to the next */
		(savearea *)act->mact.FPU_pcb = osv;		/* Dequeue it */
		psv->save_flags &= ~SAVfpuvalid;			/* Clear the float flag */
		if(!(psv->save_flags & SAVinuse)) {			/* Anyone left with this one? */			
			save_release(psv);						/* Nope, release it */
		}
	}

	psv = 0;
	while(osv) {									/* Any floating point saved state? */
		if(!(osv->save_level_fp)) break;			/* Leave if this is user state */
		psv = osv;									/* Save previous savearea address */
		osv = osv->save_prev_float;					/* Get one underneath our's */
	}
	
	if(osv) {										/* Did we find one? */
		if(psv) psv->save_prev_float = 0;			/* Yes, clear pointer to it (it should always be last) or */	
		else act->mact.FPU_pcb = 0;					/* to the start if the only one */

		osv->save_flags &= ~SAVfpuvalid;			/* Clear the floating point flag */
		if(!(osv->save_flags & SAVinuse)) {			/* Anyone left with this one? */			
			save_release(osv);						/* Nope, release it */
		}
	}
	
	if(sv->save_flags & SAVfpuvalid) {				/* Are we adding floating point context? */
		if(psv)	psv->save_prev_float = sv;			/* Yes, chain us to the end or */
		else act->mact.FPU_pcb = (pcb_t)sv;			/* to the start if the only one */
	}
	
	osv = (savearea *)act->mact.pcb;				/* Get the top general savearea */
	psv = 0;
	while(osv) {									/* Any floating point saved state? */
		if(osv->save_srr1 & MASK(MSR_PR)) break;	/* Leave if this is user state */
		psv = osv;									/* Save previous savearea address */
		osv = osv->save_prev;						/* Get one underneath our's */
	}
	
	if(osv) {										/* Did we find one? */
		if(psv) psv->save_prev = 0;					/* Yes, clear pointer to it (it should always be last) or */	
		else act->mact.pcb = 0;						/* to the start if the only one */

		osv->save_flags &= ~SAVattach;				/* Clear the attached flag */
		if(!(osv->save_flags & SAVinuse)) {			/* Anyone left with this one? */			
			save_release(osv);						/* Nope, release it */
		}
	}
	
	if(psv)	psv->save_prev = sv;					/* Chain us to the end or */
	else act->mact.pcb = (pcb_t)sv;					/* to the start if the only one */

	hw_atomic_sub(&saveanchor.saveneed, 1);			/* Unaccount for the savearea we think we "need" */
}



/*
 *		Releases saved context.  We need this because the saved context is opague.
 *		be adjusted when these contexts are attached to a new activation.
 *
 */

void act_thread_cfree(void *ctx) {

	if((((savearea *)ctx)->save_prev != (savearea *)0xDEBB1ED0) || 
		(((savearea *)ctx)->save_prev_float != (savearea *)0xE5DA11A5)) {	/* See if valid savearea */
		panic("act_thread_cfree: attempt to free invalid context savearea - %08X\n", ctx);	/* Die */
	}

	((savearea *)ctx)->save_flags = 0;				/* Clear all flags since we release this in any case */
	save_release((savearea *)ctx);					/* Release this one */
	hw_atomic_sub(&saveanchor.saveneed, 1);			/* Unaccount for the savearea we think we "need" */
	
	return;
}
