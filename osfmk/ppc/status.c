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
 * 
 */

#include <kern/thread.h>
#include <kern/thread_act.h>
#include <kern/misc_protos.h>
#include <mach/ppc/thread_status.h>
#include <ppc/proc_reg.h>
#include <ppc/exception.h>
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
	register savearea_fpu *fsv;
	register savearea_vec *vsv;
	savearea *genuser;
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

	genuser = find_user_regs(thr_act);						/* Find the current user general context for this activation */

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

			sv = genuser;									/* Copy this over */
			
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
				ts->mq	= 0;							/* MQ register (601 only) */
				ts->vrsave	= sv->save_vrsave;			/* VRSAVE register (Altivec only) */
			}
			else {										/* No user state yet. Save seemingly random values. */
						
				for(i=0; i < 32; i+=2) {				/* Fill up with defaults */
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
				ts->vrsave	= 0;						/* VRSAVE register (Altivec only) */
			}
		
			*count = PPC_THREAD_STATE_COUNT;			/* Pass back the amount we actually copied */
			return KERN_SUCCESS;
	
		case PPC_EXCEPTION_STATE:
	
			if (*count < PPC_EXCEPTION_STATE_COUNT) {
				return KERN_INVALID_ARGUMENT;
			}
		
			es = (struct ppc_exception_state *) tstate;
		
			sv = thr_act->mact.pcb;						/* Start with the normal savearea */
			while(sv) {									/* Find the user context */
				if(sv->save_srr1 & MASK(MSR_PR)) {		/* Are we looking at the user context? */
					break;								/* Outta here */
				}
				sv = sv->save_hdr.save_prev;			/* Back chain */
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
		
			fpu_save(thr_act->mact.curctx);				/* Just in case it's live, save it */
		
			fs = (struct ppc_float_state *) tstate;		/* Point to destination */
			
			fsv = (savearea_fpu *)thr_act->mact.curctx->FPUsave;	/* Start with the top FPU savearea */
			
			while(fsv) {								/* Find the user context */
				if(!fsv->save_hdr.save_level) {			/* Are we looking at the user context? */
					break;								/* Outta here */
				}
				fsv = (savearea_fpu *)fsv->save_hdr.save_prev;	/* Back chain */
			}
			
			if(fsv) {									/* See if we have any */
				bcopy((char *)&fsv->save_fp0, (char *)fs, 32*8); /* 32 registers  */
				fs->fpscr_pad	= 0;					/* Be clean and tidy */
				if(genuser) fs->fpscr = genuser->save_fpscr;	/* Set the fpscr value to general */
				else fs->fpscr = 0;						/* If no user, initialize this */
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
		
			vec_save(thr_act->mact.curctx);				/* Just in case it's live, save it */
		
			vs = (struct ppc_vector_state *) tstate;	/* Point to destination */
			
			vsv = (savearea_vec *)thr_act->mact.curctx->VMXsave;	/* Start with the top vector savearea */
			
			while(vsv) {								/* Find the user context */
				if(!vsv->save_hdr.save_level) {			/* Are we looking at the user context? */
					break;								/* Outta here */
				}
				vsv = (savearea_vec *)vsv->save_hdr.save_prev;	/* Back chain */
			}
			
			if(vsv) {									/* See if we have any */
				
				vrvalidwrk = vsv->save_vrvalid;			/* Get the valid flags */
				vs->save_vrvalid = vsv->save_vrvalid;	/* Set the valid flags */
				if(genuser) for(j=0; j < 4; j++) vs->save_vscr[j] = genuser->save_vscr[j];	/* Set value for vscr */
				else {
					vs->save_vscr[0] = 0;				/* Set an initial value if no general user yet */
					vs->save_vscr[1] = 0;
					vs->save_vscr[2] = 0;
					vs->save_vscr[3] = 0x00010000;
				}
				for(i=0; i < 32; i++) {					/* Copy the saved registers and invalidate the others */
					for(j=0; j < 4; j++) {
						if(vrvalidwrk & 0x80000000) (vs->save_vr)[i][j] = 
							((unsigned int *)&(vsv->save_vr0))[(i * 4) + j];	/* We have this register saved */
						else vs->save_vr[i][j] = QNaNbarbarian[j];	/* Set invalid value */
					}
					vrvalidwrk = vrvalidwrk << 1;		/* Shift over to the next */
				}
			}
			else {										/* No vector yet */
			
				for(i=0; i < 32; i++) {					/* Initialize vector registers */
					for(j=0; j < 4; j++) vs->save_vr[i][j] = QNaNbarbarian[j];		/* Initial value */
				}
				
				if(genuser) for(j=0; j < 4; j++) vs->save_vscr[j] = genuser->save_vscr[j];	/* Set value for vscr */
				else {
					vs->save_vscr[0] = 0;				/* Set an initial value if no general user yet */
					vs->save_vscr[1] = 0;
					vs->save_vscr[2] = 0;
					vs->save_vscr[3] = 0x00010000;
				}
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
  
  	savearea		*sv, *genuser;
  	savearea_fpu	*fsv, *fsvn, *fsvo;
  	savearea_vec	*vsv, *vsvn, *vsvo;
	unsigned int	i;
	int				clgn;
	register struct ppc_thread_state *ts;
	register struct ppc_exception_state *es;
	register struct ppc_float_state *fs;
	register struct ppc_vector_state *vs;
	
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
			break;
			
		case PPC_EXCEPTION_STATE:
			
			if (clgn < PPC_EXCEPTION_STATE_COUNT)  {		/* Is it too short? */
				return KERN_INVALID_ARGUMENT;				/* Yeah, just leave... */
			}
			
			break;
			
		case PPC_FLOAT_STATE:
			
			if (clgn < PPC_FLOAT_STATE_COUNT)  {			/* Is it too short? */
				return KERN_INVALID_ARGUMENT;				/* Yeah, just leave... */
			}
			
			break;
			

		case PPC_VECTOR_STATE:
			
			if (clgn < PPC_VECTOR_STATE_COUNT)  {			/* Is it too short? */
				return KERN_INVALID_ARGUMENT;				/* Yeah, just leave... */
			}
			
			break;
			
		default:
			return KERN_INVALID_ARGUMENT;
	}
	
	genuser = get_user_regs(thr_act);						/* Find or allocate and initialize one */

	switch (flavor) {
		
		case PPC_THREAD_STATE:
		case PPC_EXCEPTION_STATE:
				
			ts = (struct ppc_thread_state *)tstate;
										
			if(flavor == PPC_THREAD_STATE) {				/* Are we updating plain state? */
			
				genuser->save_r0	= ts->r0;
				genuser->save_r1	= ts->r1;
				genuser->save_r2	= ts->r2;
				genuser->save_r3	= ts->r3;
				genuser->save_r4	= ts->r4;
				genuser->save_r5	= ts->r5;
				genuser->save_r6	= ts->r6;
				genuser->save_r7	= ts->r7;
				genuser->save_r8	= ts->r8;
				genuser->save_r9	= ts->r9;
				genuser->save_r10	= ts->r10;
				genuser->save_r11	= ts->r11;
				genuser->save_r12	= ts->r12;
				genuser->save_r13	= ts->r13;
				genuser->save_r14	= ts->r14;
				genuser->save_r15	= ts->r15;
				genuser->save_r16	= ts->r16;
				genuser->save_r17	= ts->r17;
				genuser->save_r18	= ts->r18;
				genuser->save_r19	= ts->r19;
				genuser->save_r20	= ts->r20;
				genuser->save_r21	= ts->r21;
				genuser->save_r22	= ts->r22;
				genuser->save_r23	= ts->r23;
				genuser->save_r24	= ts->r24;
				genuser->save_r25	= ts->r25;
				genuser->save_r26	= ts->r26;
				genuser->save_r27	= ts->r27;
				genuser->save_r28	= ts->r28;
				genuser->save_r29	= ts->r29;
				genuser->save_r30	= ts->r30;
				genuser->save_r31	= ts->r31;
			
				genuser->save_cr	= ts->cr;
				genuser->save_xer	= ts->xer;
				genuser->save_lr	= ts->lr;
				genuser->save_ctr	= ts->ctr;
				genuser->save_srr0	= ts->srr0;
				genuser->save_vrsave	= ts->vrsave;					/* VRSAVE register (Altivec only) */

				genuser->save_srr1 = MSR_PREPARE_FOR_IMPORT(genuser->save_srr1, ts->srr1);	/* Set the bits we can change */
	
				if(!kernel_act) genuser->save_srr1 |= MSR_EXPORT_MASK_SET;	/* If not a kernel guy, force the magic bits on */	
			
				genuser->save_srr1 &= ~(MASK(MSR_FP) | MASK(MSR_VEC));	/* Make sure we don't enable the floating point unit */
			
				return KERN_SUCCESS;
				
			}

			es = (struct ppc_exception_state *) tstate;
		
			genuser->save_dar = es->dar;
			genuser->save_dsisr = es->dsisr;
			genuser->save_exception = es->exception;

			return KERN_SUCCESS;
	
		case PPC_FLOAT_STATE:

			toss_live_fpu(thr_act->mact.curctx);			/* Toss my floating point if live anywhere */
			
			fsv = find_user_fpu(thr_act);					/* Get the user's floating point context */
		
			if(!fsv) {										/* Do we have one yet? */
				fsv = (savearea_fpu *)save_alloc();			/* If we still don't have one, get a new one */
				fsv->save_hdr.save_flags = (fsv->save_hdr.save_flags & ~SAVtype) | (SAVfloat << SAVtypeshft);	/* Mark as in use as float */
				fsv->save_hdr.save_act = thr_act;			/* Point to the activation */
				fsv->save_hdr.save_prev = 0;				/* Mark no more */
				fsv->save_hdr.save_level = 0;				/* Mark user state */
				
				if(!thr_act->mact.curctx->FPUsave) thr_act->mact.curctx->FPUsave = fsv;	/* If no floating point, chain us first */
				else {
				
					fsvn = fsvo = thr_act->mact.curctx->FPUsave;	/* Remember first one */
					
					while (fsvn) {							/* Go until we hit the end */
						fsvo = fsvn;						/* Remember the previous one */
						fsvn = (savearea_fpu *)fsvo->save_hdr.save_prev;	/* Skip on to the next */
					}
					
					fsvo->save_hdr.save_prev = (savearea *)fsv;		/* Queue us on in */
				}
				
			}
			
			fs = (struct ppc_float_state *) tstate;			/* Point to source */

		
			bcopy((char *)fs, (char *)&fsv->save_fp0, 32*8);	/* Move in the 32 registers */
			
			genuser->save_fpscr = fs->fpscr;				/* Copy the fpscr value to normal */	
			
			return KERN_SUCCESS;
			
	
		case PPC_VECTOR_STATE:

			toss_live_vec(thr_act->mact.curctx);			/* Toss my vector if live anywhere */
			
			vsv = find_user_vec(thr_act);					/* Get the user's vector context */
		
			if(!vsv) {										/* Do we have one yet? */
				vsv = (savearea_vec *)save_alloc();			/* If we still don't have one, get a new one */
				vsv->save_hdr.save_flags = (vsv->save_hdr.save_flags & ~SAVtype) | (SAVvector << SAVtypeshft);	/* Mark as in use as vector */
				vsv->save_hdr.save_act = thr_act;			/* Point to the activation */
				vsv->save_hdr.save_prev = 0;				/* Mark no more */
				vsv->save_hdr.save_level = 0;				/* Mark user state */
				
				if(!thr_act->mact.curctx->VMXsave) thr_act->mact.curctx->VMXsave = vsv;	/* If no vector, chain us first */
				else {
				
					vsvn = vsvo = thr_act->mact.curctx->VMXsave;	/* Remember first one */
					
					while (vsvn) {							/* Go until we hit the end */
						vsvo = vsvn;						/* Remember the previous one */
						vsvn = (savearea_vec *)vsvo->save_hdr.save_prev;	/* Skip on to the next */
					}
					
					vsvo->save_hdr.save_prev = (savearea *)vsv;	/* Queue us on in */
				}
				
			}
			
			vs = (struct ppc_vector_state *) tstate;		/* Point to source */
		
			bcopy((char *)vs, (char *)&vsv->save_vr0, 32*16);	/* 32 registers plus status and validity and pad */
			vsv->save_vrvalid = vs->save_vrvalid;			/* Set validity bits */
			
			
			for(i = 0; i < 4; i++) genuser->save_vscr[i] = vs->save_vscr[i];	/* Set value for vscr */
		
			return KERN_SUCCESS;
			
		
		default:
			return KERN_INVALID_ARGUMENT;
    }
}

/*
 *		Duplicates the context of one thread into a new one.
 *		The new thread is assumed to be new and have no user state contexts except maybe a general one.
 *		We also assume that the old thread can't be running anywhere.
 *
 *		We're only going to be duplicating user context here.  That means that we will have to 
 *		eliminate any floating point or vector kernel contexts and carry across the user state ones.
 */

void act_thread_dup(thread_act_t old, thread_act_t new) {

  	savearea		*sv, *osv; 
  	savearea_fpu	*fsv, *fsvn;
  	savearea_vec	*vsv, *vsvn;
	unsigned int	spc, i, *srs;
	
	fpu_save(old->mact.curctx);						/* Make certain floating point state is all saved */
	vec_save(old->mact.curctx);						/* Make certain the vector state is all saved */
	
	sv = get_user_regs(new);						/* Allocate and initialze context in the new activation */
	
	osv = find_user_regs(old);						/* Find the original context */
	if(!osv) {
		panic("act_thread_dup: old activation (%08X) has no general user context\n", old);
	}
	
	bcopy((char *)((unsigned int)osv + sizeof(savearea_comm)),	/* Copy everything but the headers */
		(char *)((unsigned int)sv + sizeof(savearea_comm)), 
		sizeof(struct savearea) - sizeof(savearea_comm));
	
	sv->save_srr1 &= ~(MASK(MSR_FP) | MASK(MSR_VEC));	/* Make certain that floating point and vector are turned off */

	fsv = find_user_fpu(old);						/* Get any user floating point */
	
	new->mact.curctx->FPUsave = 0;					/* Assume no floating point */

	if(fsv) {										/* Did we find one? */
		fsvn = (savearea_fpu *)save_alloc();		/* If we still don't have one, get a new one */
		fsvn->save_hdr.save_flags = (fsvn->save_hdr.save_flags & ~SAVtype) | (SAVfloat << SAVtypeshft);	/* Mark as in use as float */
		fsvn->save_hdr.save_act = new;				/* Point to the activation */
		fsvn->save_hdr.save_prev = 0;				/* Mark no more */
		fsvn->save_hdr.save_level = 0;				/* Mark user state */

		new->mact.curctx->FPUsave = fsvn;			/* Chain in the floating point */

		bcopy((char *)((unsigned int)fsv + sizeof(savearea_comm)),	/* Copy everything but the headers */
			(char *)((unsigned int)fsvn + sizeof(savearea_comm)), 
			sizeof(struct savearea) - sizeof(savearea_comm));
	}

	vsv = find_user_vec(old);						/* Get any user vector */
	
	new->mact.curctx->VMXsave = 0;					/* Assume no vector */

	if(vsv) {										/* Did we find one? */
		vsvn = (savearea_vec *)save_alloc();		/* If we still don't have one, get a new one */
		vsvn->save_hdr.save_flags = (vsvn->save_hdr.save_flags & ~SAVtype) | (SAVvector << SAVtypeshft);	/* Mark as in use as float */
		vsvn->save_hdr.save_act = new;				/* Point to the activation */
		vsvn->save_hdr.save_prev = 0;				/* Mark no more */
		vsvn->save_hdr.save_level = 0;				/* Mark user state */

		new->mact.curctx->VMXsave = vsvn;			/* Chain in the floating point */

		bcopy((char *)((unsigned int)vsv + sizeof(savearea_comm)),	/* Copy everything but the headers */
			(char *)((unsigned int)vsvn + sizeof(savearea_comm)), 
			sizeof(struct savearea) - sizeof(savearea_comm));
	}

	return;											/* Bye bye... */
}

/*
 *		Initializes a fresh set of user state values.  If there is no user state context,
 *		one is created. Floats and VMX are not created. 
 *		
 *		We only set initial values if there was no context found.
 */

savearea *get_user_regs(thread_act_t act) {

  	savearea		*sv, *osv;
	unsigned int	spc, i, *srs;

	sv = act->mact.pcb;								/* Get the top savearea on the stack */
	osv = 0;										/* Set no user savearea yet */	
	
	while(sv) {										/* Find the user context */
		if(sv->save_srr1 & MASK(MSR_PR)) return sv;	/* We found a user state context... */

		osv = sv;									/* Save the last one */
		sv = sv->save_hdr.save_prev;				/* Get the previous context */
	}

	sv = save_alloc();								/* Get one */
	sv->save_hdr.save_flags = (sv->save_hdr.save_flags & ~SAVtype) | (SAVgeneral << SAVtypeshft);	/* Mark as in use as general */
	sv->save_hdr.save_act = act;					/* Point to the activation */
	sv->save_hdr.save_prev = 0;						/* Mark no more */
	sv->save_hdr.save_level = 0;					/* Mark user state */
	
	if(osv) {										/* Did we already have one? */
		osv->save_hdr.save_prev = sv;				/* Chain us on the end */
	}
	else {											/* We are the first */
		act->mact.pcb = sv;							/* Put it there */
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

	sv->save_fpscr = 0;								/* Clear all floating point exceptions */

	sv->save_vrsave = 0;							/* Set the vector save state */
	sv->save_vscr[0] = 0x00000000;					
	sv->save_vscr[1] = 0x00000000;					
	sv->save_vscr[2] = 0x00000000;					
	sv->save_vscr[3] = 0x00010000;					/* Supress java mode and clear saturated */
	
	spc = (unsigned int)act->map->pmap->space;		/* Get the space we're in */
	
	srs = (unsigned int *)&sv->save_sr0;			/* Point to the SRs */
	for(i = 0; i < 16; i++) {						/* Fill in the SRs for the new context */
		srs[i] = SEG_REG_PROT | (i<<20) | spc;		/* Set the SR */
	}
	
	return sv;										/* Bye bye... */
}

/*
 *		Find the user state context.  If there is no user state context,
 *		we just return a 0.
 */

savearea *find_user_regs(thread_act_t act) {

  	savearea		*sv;

	sv = act->mact.pcb;								/* Get the top savearea on the stack */
	
	while(sv) {										/* Find the user context */
		if(sv->save_srr1 & MASK(MSR_PR)) {			/* Are we looking at the user context? */
			break;									/* Outta here */
		}
		sv = sv->save_hdr.save_prev;				/* Get the previous context */
	}
	
	return sv;										/* Bye bye... */
}

/*
 *		Find the user state floating point context.  If there is no user state context,
 *		we just return a 0.
 */

savearea_fpu *find_user_fpu(thread_act_t act) {

  	savearea_fpu	*fsv;

	fsv = act->mact.curctx->FPUsave;				/* Get the start of the floating point chain */
	
	while(fsv) {									/* Look until the end or we find it */
		if(!(fsv->save_hdr.save_level)) break;		/* Is the the user state stuff? (the level is 0 if so) */	
		fsv = (savearea_fpu *)fsv->save_hdr.save_prev;	/* Try the previous one */
	}
	
	return fsv;										/* Bye bye... */
}

/*
 *		Find the user state vector context.  If there is no user state context,
 *		we just return a 0.
 */

savearea_vec *find_user_vec(thread_act_t act) {

  	savearea_vec	*vsv;

	vsv = act->mact.curctx->VMXsave;				/* Get the start of the vector chain */
	
	while(vsv) {									/* Look until the end or we find it */
		if(!(vsv->save_hdr.save_level)) break;		/* Is the the user state stuff? (the level is 0 if so) */	
		vsv = (savearea_vec *)vsv->save_hdr.save_prev;	/* Try the previous one */
	}
	
	return vsv;										/* Bye bye... */
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

	if (customstack)
		*customstack = 0;

        switch (flavor) {
        case PPC_THREAD_STATE:
                if (count < PPC_THREAD_STATE_COUNT)
                        return (KERN_INVALID_ARGUMENT);
 
                state = (struct ppc_thread_state *) tstate;
    
                /* If a valid user stack is specified, use it. */
		if (state->r1)
			*user_stack = state->r1;

		if (customstack && state->r1)
			*customstack = 1;

                break;
        default :
                return (KERN_INVALID_ARGUMENT);
        }
                
        return (KERN_SUCCESS);
}    


/*
 * thread_setuserstack:
 *
 * Sets the user stack pointer into the machine
 * dependent thread state info.
 */
void thread_setuserstack(struct thread_activation *act, unsigned int user_stack)
{
	savearea *sv;
	
	sv = get_user_regs(act);		/* Get the user state registers */
	
	sv->save_r1 = user_stack;
	
	return;
}    

/*
 * thread_adjuserstack:
 *
 * Returns the adjusted user stack pointer from the machine
 * dependent thread state info.
 */
unsigned int thread_adjuserstack(struct thread_activation *act, int adjust)
{
	savearea *sv;
	
	sv = get_user_regs(act);		/* Get the user state registers */
	
	sv->save_r1 += adjust;			/* Adjust the stack */
	
	return sv->save_r1;				/* Return the adjusted stack */
	
}    

/*
 * thread_setentrypoint:
 *
 * Sets the user PC into the machine
 * dependent thread state info.
 */

void thread_setentrypoint(struct thread_activation *act, unsigned int entry)
{
	savearea *sv;
	
	sv = get_user_regs(act);		/* Get the user state registers */
	
	sv->save_srr0 = entry;
	
	return;
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
	struct savearea *child_state;
	
	child_state = get_user_regs(child);
	
	child_state->save_r3 = pid;
	child_state->save_r4 = 1;
}
void  thread_set_parent(thread_act_t parent, int pid)
{
	struct savearea *parent_state;
	
	parent_state = get_user_regs(parent);
	
	parent_state->save_r3 = pid;
	parent_state->save_r4 = 0;
}

/*
 *		Saves the complete context (general, floating point, and vector) of the current activation.
 *		We will collect everything into an opaque block of 1 to 3 saveareas and pass back a 
 *		pointer to that.
 *
 *		The savearea is made to look like it belongs to the source activation.  This needs to 
 *		be adjusted when these contexts are attached to a new activation.
 *
 */

void *act_thread_csave(void) {

  	savearea		*sv, *osv;
  	savearea_fpu	*fsv, *ofsv;
  	savearea_vec	*vsv, *ovsv;
	unsigned int	spc, i, *srs;
	
	thread_act_t act;	
	
	act = current_act();							/* Find ourselves */	
	
	fpu_save(act->mact.curctx);						/* Make certain floating point state is all saved */
	vec_save(act->mact.curctx);						/* Make certain the vector state is all saved */

	osv = find_user_regs(act);						/* Get our savearea */

	if(!osv) {
		panic("act_thread_csave: attempting to preserve the context of an activation with none (%08X)\n", act);
	}
	
	sv = save_alloc();								/* Get a fresh save area to save into */
	sv->save_hdr.save_flags = (sv->save_hdr.save_flags & ~SAVtype) | (SAVgeneral << SAVtypeshft);	/* Mark as in use as general */
	sv->save_hdr.save_act = act;					/* Point to the activation */
	sv->save_hdr.save_prev = 0;						/* Mark no more */
	sv->save_hdr.save_level = 0;					/* Mark user state */
	
	
	bcopy((char *)((unsigned int)osv + sizeof(savearea_comm)),	/* Copy everything but the headers */
		(char *)((unsigned int)sv + sizeof(savearea_comm)), 
		sizeof(struct savearea) - sizeof(savearea_comm));
	
	sv->save_srr1 &= ~(MASK(MSR_FP) | MASK(MSR_VEC));	/* Make certain that floating point and vector are turned off */	
	
	sv->save_hdr.save_misc2 = 0xDEBB1ED0;			/* Eye catcher for debug */
	sv->save_hdr.save_misc3 = 0xE5DA11A5;			/* Eye catcher for debug */
	

	ofsv = find_user_fpu(act);						/* Get any user floating point */

	sv->save_hdr.save_misc0 = 0;					/* Assume no floating point */

	if(ofsv) {										/* Did we find one? */
		fsv = (savearea_fpu *)save_alloc();			/* If we still don't have one, get a new one */
		fsv->save_hdr.save_flags = (fsv->save_hdr.save_flags & ~SAVtype) | (SAVfloat << SAVtypeshft);	/* Mark as in use as float */
		fsv->save_hdr.save_act = act;				/* Point to the activation */
		fsv->save_hdr.save_prev = 0;				/* Mark no more */
		fsv->save_hdr.save_level = 0;				/* Mark user state */
		fsv->save_hdr.save_misc2 = 0xDEBB1ED0;		/* Eye catcher for debug */
		fsv->save_hdr.save_misc3 = 0xE5DA11A5;		/* Eye catcher for debug */

		sv->save_hdr.save_misc0 = (unsigned int)fsv;	/* Remember this one */

		bcopy((char *)((unsigned int)ofsv + sizeof(savearea_comm)),	/* Copy everything but the headers */
			(char *)((unsigned int)fsv + sizeof(savearea_comm)), 
			sizeof(struct savearea) - sizeof(savearea_comm));
	}

	ovsv = find_user_vec(act);						/* Get any user vector */
	
	sv->save_hdr.save_misc1 = 0;					/* Assume no vector */

	if(ovsv) {										/* Did we find one? */
		vsv = (savearea_vec *)save_alloc();			/* If we still don't have one, get a new one */
		vsv->save_hdr.save_flags = (vsv->save_hdr.save_flags & ~SAVtype) | (SAVvector << SAVtypeshft);	/* Mark as in use as float */
		vsv->save_hdr.save_act = act;				/* Point to the activation */
		vsv->save_hdr.save_prev = 0;				/* Mark no more */
		vsv->save_hdr.save_level = 0;				/* Mark user state */
		vsv->save_hdr.save_misc2 = 0xDEBB1ED0;		/* Eye catcher for debug */
		vsv->save_hdr.save_misc3 = 0xE5DA11A5;		/* Eye catcher for debug */

		sv->save_hdr.save_misc1 = (unsigned int)vsv;	/* Chain in the floating point */

		bcopy((char *)((unsigned int)ovsv + sizeof(savearea_comm)),	/* Copy everything but the headers */
			(char *)((unsigned int)vsv + sizeof(savearea_comm)), 
			sizeof(struct savearea) - sizeof(savearea_comm));
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

  	savearea		*sv, *osv, *psv;
  	savearea_fpu	*fsv, *ofsv, *pfsv;
  	savearea_vec	*vsv, *ovsv, *pvsv;
	unsigned int	spc, i, *srs;
	thread_act_t act;	
	
	sv = (savearea *)ctx;							/* Make this easier for C */
	
	fsv = (savearea_fpu *)sv->save_hdr.save_misc0;	/* Get a possible floating point savearea */
	vsv = (savearea_vec *)sv->save_hdr.save_misc1;	/* Get a possible vector savearea */
	
	if((sv->save_hdr.save_misc2 != 0xDEBB1ED0) || (sv->save_hdr.save_misc3 != 0xE5DA11A5)) {	/* See if valid savearea */
		panic("act_thread_catt: attempt to attach invalid general context savearea - %08X\n", sv);	/* Die */
	}

	if(fsv && ((fsv->save_hdr.save_misc2 != 0xDEBB1ED0) || (fsv->save_hdr.save_misc3 != 0xE5DA11A5))) {	/* See if valid savearea */
		panic("act_thread_catt: attempt to attach invalid float context savearea - %08X\n", fsv);	/* Die */
	}

	if(vsv && ((vsv->save_hdr.save_misc2 != 0xDEBB1ED0) || (vsv->save_hdr.save_misc3 != 0xE5DA11A5))) {	/* See if valid savearea */
		panic("act_thread_catt: attempt to attach invalid vector context savearea - %08X\n", vsv);	/* Die */
	}

	act = current_act();							/* Find ourselves */	

	toss_live_fpu(act->mact.curctx);				/* Toss my floating point if live anywhere */
	toss_live_vec(act->mact.curctx);				/* Toss my vector if live anywhere */
		
	sv->save_hdr.save_misc2 = 0;					/* Eye catcher for debug */
	sv->save_hdr.save_misc3 = 0;					/* Eye catcher for debug */
	sv->save_hdr.save_act = act;					/* Set us as owner */
	
	spc = (unsigned int)act->map->pmap->space;		/* Get the space we're in */
	
	srs = (unsigned int *)&sv->save_sr0;			/* Point to the SRs */
	for(i = 0; i < 16; i++) {						/* Fill in the SRs for the new context */
		srs[i] = SEG_REG_PROT | (i<<20) | spc;		/* Set the SRs */
	}
	
	osv = act->mact.pcb;							/* Get the top general savearea */
	psv = 0;
	while(osv) {									/* Any saved state? */
		if(osv->save_srr1 & MASK(MSR_PR)) break;	/* Leave if this is user state */
		psv = osv;									/* Save previous savearea address */
		osv = osv->save_hdr.save_prev;				/* Get one underneath our's */
	}
	
	if(osv) {										/* Did we find one? */
		if(psv) psv->save_hdr.save_prev = 0;		/* Yes, clear pointer to it (it should always be last) or */	
		else act->mact.pcb = 0;						/* to the start if the only one */

		save_release(osv);							/* Nope, release it */
		
	}

	if(psv)	psv->save_hdr.save_prev = sv;			/* Chain us to the end or */
	else act->mact.pcb = (pcb_t)sv;					/* to the start if the only one */
	
	ovsv = act->mact.curctx->VMXsave;				/* Get the top vector savearea */
	
	pvsv = 0;
	while(ovsv) {									/* Any VMX saved state? */
		if(!(ovsv->save_hdr.save_level)) break;		/* Leave if this is user state */
		pvsv = ovsv;								/* Save previous savearea address */
		ovsv = (savearea_vec *)ovsv->save_hdr.save_prev;	/* Get one underneath our's */
	}
	
	if(ovsv) {										/* Did we find one? */
		if(pvsv) pvsv->save_hdr.save_prev = 0;		/* Yes, clear pointer to it (it should always be last) or */	
		else act->mact.curctx->VMXsave = 0;			/* to the start if the only one */

		save_release((savearea *)ovsv);				/* Nope, release it */
	}
	
	if(vsv) {										/* Are we sticking any vector on this one? */
		if(pvsv) pvsv->save_hdr.save_prev = (savearea *)vsv;	/* Yes, chain us to the end or */
		else act->mact.curctx->VMXsave = vsv;		/* to the start if the only one */

		vsv->save_hdr.save_misc2 = 0;				/* Eye catcher for debug */
		vsv->save_hdr.save_misc3 = 0;				/* Eye catcher for debug */
		vsv->save_hdr.save_act = act;				/* Set us as owner */
	}
	
	ofsv = act->mact.curctx->FPUsave;				/* Get the top float savearea */
	
	pfsv = 0;
	while(ofsv) {									/* Any float saved state? */
		if(!(ofsv->save_hdr.save_level)) break;		/* Leave if this is user state */
		pfsv = ofsv;								/* Save previous savearea address */
		ofsv = (savearea_fpu *)ofsv->save_hdr.save_prev;	/* Get one underneath our's */
	}
	
	if(ofsv) {										/* Did we find one? */
		if(pfsv) pfsv->save_hdr.save_prev = 0;		/* Yes, clear pointer to it (it should always be last) or */	
		else act->mact.curctx->FPUsave = 0;			/* to the start if the only one */

		save_release((savearea *)ofsv);				/* Nope, release it */
	}
	
	if(fsv) {										/* Are we sticking any vector on this one? */
		if(pfsv) pfsv->save_hdr.save_prev = (savearea *)fsv;	/* Yes, chain us to the end or */
		else act->mact.curctx->FPUsave = fsv;		/* to the start if the only one */

		fsv->save_hdr.save_misc2 = 0;				/* Eye catcher for debug */
		fsv->save_hdr.save_misc3 = 0;				/* Eye catcher for debug */
		fsv->save_hdr.save_act = act;				/* Set us as owner */
	}
	
}



/*
 *		Releases saved context.  We need this because the saved context is opague.
 *		be adjusted when these contexts are attached to a new activation.
 *
 */

void act_thread_cfree(void *ctx) {

  	savearea		*sv, *osv;
  	savearea_fpu	*fsv, *ofsv;
  	savearea_vec	*vsv, *ovsv, *pvsv;

	sv = (savearea *)ctx;							/* Make this easier for C */
	
	fsv = (savearea_fpu *)sv->save_hdr.save_misc0;	/* Get a possible floating point savearea */
	vsv = (savearea_vec *)sv->save_hdr.save_misc1;	/* Get a possible vector savearea */
	
	if((sv->save_hdr.save_misc2 != 0xDEBB1ED0) || (sv->save_hdr.save_misc3 != 0xE5DA11A5)) {	/* See if valid savearea */
		panic("act_thread_cfree: attempt to detatch invalid general context savearea - %08X\n", sv);	/* Die */
	}
	
	save_release(sv);								/* Toss the general savearea */

	if(fsv) {										/* See if there is any saved floating point */ 
		if((fsv->save_hdr.save_misc2 != 0xDEBB1ED0) || (fsv->save_hdr.save_misc3 != 0xE5DA11A5)) {	/* See if valid savearea */
			panic("act_thread_cfree: attempt to detatch invalid float context savearea - %08X\n", fsv);	/* Die */
		}
		
		save_release((savearea *)fsv);				/* Toss saved context */
	}

	if(vsv) {										/* See if there is any saved floating point */ 
		if((vsv->save_hdr.save_misc2 != 0xDEBB1ED0) || (vsv->save_hdr.save_misc3 != 0xE5DA11A5)) {	/* See if valid savearea */
			panic("act_thread_cfree: attempt to detatch invalid vector context savearea - %08X\n", vsv);	/* Die */
		}
		
		save_release((savearea *)vsv);				/* Toss saved context */
	}
	
	return;
}

/*
 * thread_enable_fpe:
 *
 * enables or disables floating point exceptions for the thread.
 * returns old state
 */
int thread_enable_fpe(thread_act_t act, int onoff)
{
        savearea *sv;
        unsigned int oldmsr;

        sv = find_user_regs(act);                                               /* Find the user registers */
        if(!sv) sv = get_user_regs(act);                                /* Didn't find any, allocate and initialize o
ne */

        oldmsr = sv->save_srr1;                                                 /* Get the old msr */

        if(onoff) sv->save_srr1 = oldmsr | MASK(MSR_FE0) | MASK(MSR_FE1);       /* Flip on precise FP exceptions */
        else sv->save_srr1 = oldmsr & ~(MASK(MSR_FE0) | MASK(MSR_FE1)); /* Flip on precise FP exceptions */

        return ((oldmsr & (MASK(MSR_FE0) | MASK(MSR_FE1))) != 0);       /* Return if it was enabled or not */
}   
