/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 * 
 */

#include <kern/thread.h>
#include <kern/misc_protos.h>
#include <mach/ppc/thread_status.h>
#include <ppc/proc_reg.h>
#include <ppc/cpu_internal.h>
#include <ppc/exception.h>
#include <ppc/misc_protos.h>
#include <ppc/savearea.h>
#include <ppc/thread.h>
#include <ppc/Firmware.h>

//#include <sys/time.h>
typedef	unsigned int fixpt_t;	/* XXX <sys/resource.h> not self contained */
#include <ppc/vmparam.h>	/* USRSTACK, etc. */

#include <vm/vm_map.h>

extern unsigned int killprint;
extern double FloatInit;
extern unsigned long QNaNbarbarian[4];

#define       USRSTACK        0xc0000000

kern_return_t
thread_userstack(
    thread_t,
    int,
    thread_state_t,
    unsigned int,
	mach_vm_offset_t *,
	int *
);

kern_return_t
thread_entrypoint(
    thread_t,
    int,
    thread_state_t,
    unsigned int,
    mach_vm_offset_t *
); 

unsigned int get_msr_exportmask(void);
unsigned int get_msr_nbits(void);
unsigned int get_msr_rbits(void);
void ppc_checkthreadstate(void *, int);
void thread_set_child(thread_t child, int pid);
void thread_set_parent(thread_t parent, int pid);
void save_release(struct savearea *save);
		
/*
 * Maps state flavor to number of words in the state:
 */
__private_extern__
unsigned int _MachineStateCount[] = {
	/* FLAVOR_LIST */ 0,
	PPC_THREAD_STATE_COUNT,
	PPC_FLOAT_STATE_COUNT,
	PPC_EXCEPTION_STATE_COUNT,
	PPC_VECTOR_STATE_COUNT,
	PPC_THREAD_STATE64_COUNT,
	PPC_EXCEPTION_STATE64_COUNT,
};

/*
 * thread_getstatus:
 *
 * Get the status of the specified thread.
 */

kern_return_t 
machine_thread_get_state(
	thread_t				thread,
	thread_flavor_t			flavor,
	thread_state_t			tstate,
	mach_msg_type_number_t	*count)
{
	
	register struct savearea *sv;						/* Pointer to the context savearea */
	register savearea_fpu *fsv;
	register savearea_vec *vsv;
	savearea *genuser;
	int i, j;
	unsigned int vrvalidwrk;

	register struct ppc_thread_state *ts;
	register struct ppc_thread_state64 *xts;
	register struct ppc_exception_state *es;
	register struct ppc_exception_state64 *xes;
	register struct ppc_float_state *fs;
	register struct ppc_vector_state *vs;
	
	genuser = find_user_regs(thread);

	switch (flavor) {
		
		case THREAD_STATE_FLAVOR_LIST:
			
			if (*count < 6)  {
				return (KERN_INVALID_ARGUMENT);
			}
		
			tstate[0] = PPC_THREAD_STATE;
			tstate[1] = PPC_FLOAT_STATE;
			tstate[2] = PPC_EXCEPTION_STATE;
			tstate[3] = PPC_VECTOR_STATE;
			tstate[4] = PPC_THREAD_STATE64;
			tstate[5] = PPC_EXCEPTION_STATE64;
			*count = 6;
		
			return KERN_SUCCESS;
	
		case PPC_THREAD_STATE:
	
			if (*count < PPC_THREAD_STATE_COUNT) {			/* Is the count ok? */
				return KERN_INVALID_ARGUMENT;
			}
		
			ts = (struct ppc_thread_state *) tstate;

			sv = genuser;									/* Copy this over */
			
			if(sv) {										/* Is there a save area yet? */
				ts->r0	= (unsigned int)sv->save_r0;
				ts->r1	= (unsigned int)sv->save_r1;
				ts->r2	= (unsigned int)sv->save_r2;
				ts->r3	= (unsigned int)sv->save_r3;
				ts->r4	= (unsigned int)sv->save_r4;
				ts->r5	= (unsigned int)sv->save_r5;
				ts->r6	= (unsigned int)sv->save_r6;
				ts->r7	= (unsigned int)sv->save_r7;
				ts->r8	= (unsigned int)sv->save_r8;
				ts->r9	= (unsigned int)sv->save_r9;
				ts->r10	= (unsigned int)sv->save_r10;
				ts->r11	= (unsigned int)sv->save_r11;
				ts->r12	= (unsigned int)sv->save_r12;
				ts->r13	= (unsigned int)sv->save_r13;
				ts->r14	= (unsigned int)sv->save_r14;
				ts->r15	= (unsigned int)sv->save_r15;
				ts->r16	= (unsigned int)sv->save_r16;
				ts->r17	= (unsigned int)sv->save_r17;
				ts->r18	= (unsigned int)sv->save_r18;
				ts->r19	= (unsigned int)sv->save_r19;
				ts->r20	= (unsigned int)sv->save_r20;
				ts->r21	= (unsigned int)sv->save_r21;
				ts->r22	= (unsigned int)sv->save_r22;
				ts->r23	= (unsigned int)sv->save_r23;
				ts->r24	= (unsigned int)sv->save_r24;
				ts->r25	= (unsigned int)sv->save_r25;
				ts->r26	= (unsigned int)sv->save_r26;
				ts->r27	= (unsigned int)sv->save_r27;
				ts->r28	= (unsigned int)sv->save_r28;
				ts->r29	= (unsigned int)sv->save_r29;
				ts->r30	= (unsigned int)sv->save_r30;
				ts->r31	= (unsigned int)sv->save_r31;
				ts->cr	= (unsigned int)sv->save_cr;
				ts->xer	= (unsigned int)sv->save_xer;
				ts->lr	= (unsigned int)sv->save_lr;
				ts->ctr	= (unsigned int)sv->save_ctr;
				ts->srr0 = (unsigned int)sv->save_srr0;
				ts->srr1 = (unsigned int)sv->save_srr1;
				ts->mq	= 0;							/* MQ register (601 only) */
				ts->vrsave	= (unsigned int)sv->save_vrsave;			/* VRSAVE register (Altivec only) */
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
	
	
		case PPC_THREAD_STATE64:
	
			if (*count < PPC_THREAD_STATE64_COUNT) {	/* Is the count ok? */
				return KERN_INVALID_ARGUMENT;
			}
		
			xts = (struct ppc_thread_state64 *) tstate;

			sv = genuser;								/* Copy this over */
			
			if(sv) {									/* Is there a save area yet? */
				xts->r0		= sv->save_r0;
				xts->r1		= sv->save_r1;
				xts->r2		= sv->save_r2;
				xts->r3		= sv->save_r3;
				xts->r4		= sv->save_r4;
				xts->r5		= sv->save_r5;
				xts->r6		= sv->save_r6;
				xts->r7		= sv->save_r7;
				xts->r8		= sv->save_r8;
				xts->r9		= sv->save_r9;
				xts->r10	= sv->save_r10;
				xts->r11	= sv->save_r11;
				xts->r12	= sv->save_r12;
				xts->r13	= sv->save_r13;
				xts->r14	= sv->save_r14;
				xts->r15	= sv->save_r15;
				xts->r16	= sv->save_r16;
				xts->r17	= sv->save_r17;
				xts->r18	= sv->save_r18;
				xts->r19	= sv->save_r19;
				xts->r20	= sv->save_r20;
				xts->r21	= sv->save_r21;
				xts->r22	= sv->save_r22;
				xts->r23	= sv->save_r23;
				xts->r24	= sv->save_r24;
				xts->r25	= sv->save_r25;
				xts->r26	= sv->save_r26;
				xts->r27	= sv->save_r27;
				xts->r28	= sv->save_r28;
				xts->r29	= sv->save_r29;
				xts->r30	= sv->save_r30;
				xts->r31	= sv->save_r31;
				xts->cr		= sv->save_cr;
				xts->xer	= sv->save_xer;
				xts->lr		= sv->save_lr;
				xts->ctr	= sv->save_ctr;
				xts->srr0 	= sv->save_srr0;
				xts->srr1 	= sv->save_srr1;
				xts->vrsave	= sv->save_vrsave;			/* VRSAVE register (Altivec only) */
			}
			else {										/* No user state yet. Save seemingly random values. */
						
				for(i=0; i < 32; i++) {					/* Fill up with defaults */
					((unsigned long long *)&xts->r0)[i] = ((unsigned long long *)&FloatInit)[0];
				}
				xts->cr		= 0;
				xts->xer	= 0;
				xts->lr		= ((unsigned long long *)&FloatInit)[0];
				xts->ctr	= ((unsigned long long *)&FloatInit)[0];
				xts->srr0	= ((unsigned long long *)&FloatInit)[0];
				xts->srr1 	= MSR_EXPORT_MASK_SET;
				if(task_has_64BitAddr(thread->task)) 
					xts->srr1 |= (uint64_t)MASK32(MSR_SF) << 32;	/* If 64-bit task, force 64-bit mode */
				xts->vrsave	= 0;						/* VRSAVE register (Altivec only) */
			}
		
			*count = PPC_THREAD_STATE64_COUNT;			/* Pass back the amount we actually copied */
			return KERN_SUCCESS;
	
		case PPC_EXCEPTION_STATE:
	
			if (*count < PPC_EXCEPTION_STATE_COUNT) {
				return KERN_INVALID_ARGUMENT;
			}
		
			es = (struct ppc_exception_state *) tstate;
			sv = genuser;								/* Copy this over */
		
			if(sv) {									/* See if valid state yet */
				es->dar = (unsigned int)sv->save_dar;
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
	
		case PPC_EXCEPTION_STATE64:
	
			if (*count < PPC_EXCEPTION_STATE64_COUNT) {
				return KERN_INVALID_ARGUMENT;
			}
		
			xes = (struct ppc_exception_state64 *) tstate;
			sv = genuser;								/* Copy this over */
		
			if(sv) {									/* See if valid state yet */
				xes->dar = sv->save_dar;
				xes->dsisr = sv->save_dsisr;
				xes->exception = sv->save_exception;
			}
			else {										/* Nope, not yet */
				xes->dar = 0;
				xes->dsisr = 0;
				xes->exception = ((unsigned int *)&FloatInit)[0];
			}
		
			*count = PPC_EXCEPTION_STATE64_COUNT;
			return KERN_SUCCESS;
	
		case PPC_FLOAT_STATE: 
		
			if (*count < PPC_FLOAT_STATE_COUNT)  {
				return KERN_INVALID_ARGUMENT;
			}
		
			fpu_save(thread->machine.curctx);				/* Just in case it's live, save it */
		
			fs = (struct ppc_float_state *) tstate;		/* Point to destination */
			
			fsv = find_user_fpu(thread);				/* Get the user's fpu savearea */
			
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
		
			vec_save(thread->machine.curctx);				/* Just in case it's live, save it */
		
			vs = (struct ppc_vector_state *) tstate;	/* Point to destination */
			
			vsv = find_user_vec(thread);				/* Find the vector savearea */
			
			if(vsv) {									/* See if we have any */
				
				vrvalidwrk = vsv->save_vrvalid;			/* Get the valid flags */
				vs->save_vrvalid = vsv->save_vrvalid;	/* Set the valid flags */
				if(genuser) for(j=0; j < 4; j++) vs->save_vscr[j] = genuser->save_vscr[j];	/* Set value for vscr */
				else {
					vs->save_vscr[0] = 0;				/* Set an initial value if no general user yet */
					vs->save_vscr[1] = 0;
					vs->save_vscr[2] = 0;
					vs->save_vscr[3] = 0x00010000;		/* Always start with Java mode off */
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
					vs->save_vscr[3] = 0x00010000;		/* Always start with Java mode off */
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
/* Close cousin of machine_thread_get_state(). 
 * This function is currently incomplete since we don't really need vector
 * or FP for the core dump (the save area can be accessed directly if the 
 * user is so inclined). Also the function name is something of a misnomer,
 * see the comment above find_kern_regs(). 
 */

kern_return_t 
machine_thread_get_kern_state(
	thread_t				thread,
	thread_flavor_t			flavor,
	thread_state_t			tstate,
	mach_msg_type_number_t	*count)
{
	
	register struct savearea *sv;						/* Pointer to the context savearea */
	savearea *genkern;
	int i;

	register struct ppc_thread_state *ts;
	register struct ppc_thread_state64 *xts;
	register struct ppc_exception_state *es;
	register struct ppc_exception_state64 *xes;
	
	genkern = find_kern_regs(thread);

	switch (flavor) {
		
		case THREAD_STATE_FLAVOR_LIST:
			
			if (*count < 6)  {
				return (KERN_INVALID_ARGUMENT);
			}
		
			tstate[0] = PPC_THREAD_STATE;
			tstate[1] = PPC_FLOAT_STATE;
			tstate[2] = PPC_EXCEPTION_STATE;
			tstate[3] = PPC_VECTOR_STATE;
			tstate[4] = PPC_THREAD_STATE64;
			tstate[5] = PPC_EXCEPTION_STATE64;
			*count = 6;
		
			return KERN_SUCCESS;
	
		case PPC_THREAD_STATE:
	
			if (*count < PPC_THREAD_STATE_COUNT) {			/* Is the count ok? */
				return KERN_INVALID_ARGUMENT;
			}
		
			ts = (struct ppc_thread_state *) tstate;

			sv = genkern;									/* Copy this over */
			
			if(sv) {										/* Is there a save area yet? */
				ts->r0	= (unsigned int)sv->save_r0;
				ts->r1	= (unsigned int)sv->save_r1;
				ts->r2	= (unsigned int)sv->save_r2;
				ts->r3	= (unsigned int)sv->save_r3;
				ts->r4	= (unsigned int)sv->save_r4;
				ts->r5	= (unsigned int)sv->save_r5;
				ts->r6	= (unsigned int)sv->save_r6;
				ts->r7	= (unsigned int)sv->save_r7;
				ts->r8	= (unsigned int)sv->save_r8;
				ts->r9	= (unsigned int)sv->save_r9;
				ts->r10	= (unsigned int)sv->save_r10;
				ts->r11	= (unsigned int)sv->save_r11;
				ts->r12	= (unsigned int)sv->save_r12;
				ts->r13	= (unsigned int)sv->save_r13;
				ts->r14	= (unsigned int)sv->save_r14;
				ts->r15	= (unsigned int)sv->save_r15;
				ts->r16	= (unsigned int)sv->save_r16;
				ts->r17	= (unsigned int)sv->save_r17;
				ts->r18	= (unsigned int)sv->save_r18;
				ts->r19	= (unsigned int)sv->save_r19;
				ts->r20	= (unsigned int)sv->save_r20;
				ts->r21	= (unsigned int)sv->save_r21;
				ts->r22	= (unsigned int)sv->save_r22;
				ts->r23	= (unsigned int)sv->save_r23;
				ts->r24	= (unsigned int)sv->save_r24;
				ts->r25	= (unsigned int)sv->save_r25;
				ts->r26	= (unsigned int)sv->save_r26;
				ts->r27	= (unsigned int)sv->save_r27;
				ts->r28	= (unsigned int)sv->save_r28;
				ts->r29	= (unsigned int)sv->save_r29;
				ts->r30	= (unsigned int)sv->save_r30;
				ts->r31	= (unsigned int)sv->save_r31;
				ts->cr	= (unsigned int)sv->save_cr;
				ts->xer	= (unsigned int)sv->save_xer;
				ts->lr	= (unsigned int)sv->save_lr;
				ts->ctr	= (unsigned int)sv->save_ctr;
				ts->srr0 = (unsigned int)sv->save_srr0;
				ts->srr1 = (unsigned int)sv->save_srr1;
				ts->mq	= 0;							/* MQ register (601 only) */
				ts->vrsave	= (unsigned int)sv->save_vrsave;			/* VRSAVE register (Altivec only) */
			}
			else {										/* No state yet. Save seemingly random values. */
						
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
	
	
		case PPC_THREAD_STATE64:
	
			if (*count < PPC_THREAD_STATE64_COUNT) {	/* Is the count ok? */
				return KERN_INVALID_ARGUMENT;
			}
		
			xts = (struct ppc_thread_state64 *) tstate;

			sv = genkern;								/* Copy this over */
			
			if(sv) {									/* Is there a save area yet? */
				xts->r0		= sv->save_r0;
				xts->r1		= sv->save_r1;
				xts->r2		= sv->save_r2;
				xts->r3		= sv->save_r3;
				xts->r4		= sv->save_r4;
				xts->r5		= sv->save_r5;
				xts->r6		= sv->save_r6;
				xts->r7		= sv->save_r7;
				xts->r8		= sv->save_r8;
				xts->r9		= sv->save_r9;
				xts->r10	= sv->save_r10;
				xts->r11	= sv->save_r11;
				xts->r12	= sv->save_r12;
				xts->r13	= sv->save_r13;
				xts->r14	= sv->save_r14;
				xts->r15	= sv->save_r15;
				xts->r16	= sv->save_r16;
				xts->r17	= sv->save_r17;
				xts->r18	= sv->save_r18;
				xts->r19	= sv->save_r19;
				xts->r20	= sv->save_r20;
				xts->r21	= sv->save_r21;
				xts->r22	= sv->save_r22;
				xts->r23	= sv->save_r23;
				xts->r24	= sv->save_r24;
				xts->r25	= sv->save_r25;
				xts->r26	= sv->save_r26;
				xts->r27	= sv->save_r27;
				xts->r28	= sv->save_r28;
				xts->r29	= sv->save_r29;
				xts->r30	= sv->save_r30;
				xts->r31	= sv->save_r31;
				xts->cr		= sv->save_cr;
				xts->xer	= sv->save_xer;
				xts->lr		= sv->save_lr;
				xts->ctr	= sv->save_ctr;
				xts->srr0 	= sv->save_srr0;
				xts->srr1 	= sv->save_srr1;
				xts->vrsave	= sv->save_vrsave;			/* VRSAVE register (Altivec only) */
			}
			else {										/* No user state yet. Save seemingly random values. */
						
				for(i=0; i < 32; i++) {					/* Fill up with defaults */
					((unsigned long long *)&xts->r0)[i] = ((unsigned long long *)&FloatInit)[0];
				}
				xts->cr		= 0;
				xts->xer	= 0;
				xts->lr		= ((unsigned long long *)&FloatInit)[0];
				xts->ctr	= ((unsigned long long *)&FloatInit)[0];
				xts->srr0	= ((unsigned long long *)&FloatInit)[0];
				xts->srr1 	= MSR_EXPORT_MASK_SET;
				xts->vrsave	= 0;						/* VRSAVE register (Altivec only) */
			}
		
			*count = PPC_THREAD_STATE64_COUNT;			/* Pass back the amount we actually copied */
			return KERN_SUCCESS;
	
		case PPC_EXCEPTION_STATE:
	
			if (*count < PPC_EXCEPTION_STATE_COUNT) {
				return KERN_INVALID_ARGUMENT;
			}
		
			es = (struct ppc_exception_state *) tstate;
			sv = genkern;								/* Copy this over */
		
			if(sv) {									/* See if valid state yet */
				es->dar = (unsigned int)sv->save_dar;
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
	
		case PPC_EXCEPTION_STATE64:
	
			if (*count < PPC_EXCEPTION_STATE64_COUNT) {
				return KERN_INVALID_ARGUMENT;
			}
		
			xes = (struct ppc_exception_state64 *) tstate;
			sv = genkern;								/* Copy this over */
		
			if(sv) {									/* See if valid state yet */
				xes->dar = sv->save_dar;
				xes->dsisr = sv->save_dsisr;
				xes->exception = sv->save_exception;
			}
			else {										/* Nope, not yet */
				xes->dar = 0;
				xes->dsisr = 0;
				xes->exception = ((unsigned int *)&FloatInit)[0];
			}
		
			*count = PPC_EXCEPTION_STATE64_COUNT;
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
machine_thread_set_state(
	thread_t				thread,
	thread_flavor_t			flavor,
	thread_state_t			tstate,
	mach_msg_type_number_t	count)
{
  
  	savearea		*genuser;
  	savearea_fpu	*fsv, *fsvn, *fsvo;
  	savearea_vec	*vsv, *vsvn, *vsvo;
	unsigned int	i;
	unsigned int	clgn;
	register struct ppc_thread_state *ts;
	register struct ppc_thread_state64 *xts;
	register struct ppc_exception_state *es;
	register struct ppc_exception_state *xes;
	register struct ppc_float_state *fs;
	register struct ppc_vector_state *vs;
	
//	dbgTrace((unsigned int)thr_act, (unsigned int)0 /*sv: was never set*/, flavor);	/* (TEST/DEBUG) */

	clgn = count;											/* Get the count */
	
	switch (flavor) {										/* Validate the count before we do anything else */
		case PPC_THREAD_STATE:
			
			if (clgn < PPC_THREAD_STATE_COUNT)  {			/* Is it too short? */
				return KERN_INVALID_ARGUMENT;				/* Yeah, just leave... */
			}
			break;
	
		case PPC_THREAD_STATE64:
			
			if (clgn < PPC_THREAD_STATE64_COUNT)  {			/* Is it too short? */
				return KERN_INVALID_ARGUMENT;				/* Yeah, just leave... */
			}
			break;
			
		case PPC_EXCEPTION_STATE:
			
			if (clgn < PPC_EXCEPTION_STATE_COUNT)  {		/* Is it too short? */
				return KERN_INVALID_ARGUMENT;				/* Yeah, just leave... */
			}
			
		case PPC_EXCEPTION_STATE64:
			
			if (clgn < PPC_EXCEPTION_STATE64_COUNT)  {		/* Is it too short? */
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
	
	genuser = get_user_regs(thread);						/* Find or allocate and initialize one */

	switch (flavor) {
		
		case PPC_THREAD_STATE:
				
			ts = (struct ppc_thread_state *)tstate;

			genuser->save_r0	= (uint64_t)ts->r0;
			genuser->save_r1	= (uint64_t)ts->r1;
			genuser->save_r2	= (uint64_t)ts->r2;
			genuser->save_r3	= (uint64_t)ts->r3;
			genuser->save_r4	= (uint64_t)ts->r4;
			genuser->save_r5	= (uint64_t)ts->r5;
			genuser->save_r6	= (uint64_t)ts->r6;
			genuser->save_r7	= (uint64_t)ts->r7;
			genuser->save_r8	= (uint64_t)ts->r8;
			genuser->save_r9	= (uint64_t)ts->r9;
			genuser->save_r10	= (uint64_t)ts->r10;
			genuser->save_r11	= (uint64_t)ts->r11;
			genuser->save_r12	= (uint64_t)ts->r12;
			genuser->save_r13	= (uint64_t)ts->r13;
			genuser->save_r14	= (uint64_t)ts->r14;
			genuser->save_r15	= (uint64_t)ts->r15;
			genuser->save_r16	= (uint64_t)ts->r16;
			genuser->save_r17	= (uint64_t)ts->r17;
			genuser->save_r18	= (uint64_t)ts->r18;
			genuser->save_r19	= (uint64_t)ts->r19;
			genuser->save_r20	= (uint64_t)ts->r20;
			genuser->save_r21	= (uint64_t)ts->r21;
			genuser->save_r22	= (uint64_t)ts->r22;
			genuser->save_r23	= (uint64_t)ts->r23;
			genuser->save_r24	= (uint64_t)ts->r24;
			genuser->save_r25	= (uint64_t)ts->r25;
			genuser->save_r26	= (uint64_t)ts->r26;
			genuser->save_r27	= (uint64_t)ts->r27;
			genuser->save_r28	= (uint64_t)ts->r28;
			genuser->save_r29	= (uint64_t)ts->r29;
			genuser->save_r30	= (uint64_t)ts->r30;
			genuser->save_r31	= (uint64_t)ts->r31;
		
			genuser->save_cr	= ts->cr;
			genuser->save_xer	= (uint64_t)ts->xer;
			genuser->save_lr	= (uint64_t)ts->lr;
			genuser->save_ctr	= (uint64_t)ts->ctr;
			genuser->save_srr0	= (uint64_t)ts->srr0;
			genuser->save_vrsave	= ts->vrsave;					/* VRSAVE register (Altivec only) */

			genuser->save_srr1 = MSR_PREPARE_FOR_IMPORT(genuser->save_srr1, ts->srr1);	/* Set the bits we can change */

			genuser->save_srr1 |= MSR_EXPORT_MASK_SET;
		
			genuser->save_srr1 &= ~(MASK(MSR_FP) | MASK(MSR_VEC));	/* Make sure we don't enable the floating point unit */
			
			if(task_has_64BitAddr(thread->task)) 
				genuser->save_srr1 |= (uint64_t)MASK32(MSR_SF) << 32;	/* If 64-bit task, force 64-bit mode */
			else
				genuser->save_srr1 &= ~((uint64_t)MASK32(MSR_SF) << 32);	/* else 32-bit mode */
		
			return KERN_SUCCESS;


		case PPC_THREAD_STATE64:
				
			xts = (struct ppc_thread_state64 *)tstate;

			genuser->save_r0	= xts->r0;
			genuser->save_r1	= xts->r1;
			genuser->save_r2	= xts->r2;
			genuser->save_r3	= xts->r3;
			genuser->save_r4	= xts->r4;
			genuser->save_r5	= xts->r5;
			genuser->save_r6	= xts->r6;
			genuser->save_r7	= xts->r7;
			genuser->save_r8	= xts->r8;
			genuser->save_r9	= xts->r9;
			genuser->save_r10	= xts->r10;
			genuser->save_r11	= xts->r11;
			genuser->save_r12	= xts->r12;
			genuser->save_r13	= xts->r13;
			genuser->save_r14	= xts->r14;
			genuser->save_r15	= xts->r15;
			genuser->save_r16	= xts->r16;
			genuser->save_r17	= xts->r17;
			genuser->save_r18	= xts->r18;
			genuser->save_r19	= xts->r19;
			genuser->save_r20	= xts->r20;
			genuser->save_r21	= xts->r21;
			genuser->save_r22	= xts->r22;
			genuser->save_r23	= xts->r23;
			genuser->save_r24	= xts->r24;
			genuser->save_r25	= xts->r25;
			genuser->save_r26	= xts->r26;
			genuser->save_r27	= xts->r27;
			genuser->save_r28	= xts->r28;
			genuser->save_r29	= xts->r29;
			genuser->save_r30	= xts->r30;
			genuser->save_r31	= xts->r31;
		
			genuser->save_cr	= xts->cr;
			genuser->save_xer	= xts->xer;
			genuser->save_lr	= xts->lr;
			genuser->save_ctr	= xts->ctr;
			genuser->save_srr0	= xts->srr0;
			genuser->save_vrsave	= xts->vrsave;					/* VRSAVE register (Altivec only) */

			genuser->save_srr1 = MSR_PREPARE_FOR_IMPORT(genuser->save_srr1, xts->srr1);	/* Set the bits we can change */

			genuser->save_srr1 |= MSR_EXPORT_MASK_SET;
		
			genuser->save_srr1 &= ~(MASK(MSR_FP) | MASK(MSR_VEC));	/* Make sure we don't enable the floating point unit */
			
			if(task_has_64BitAddr(thread->task)) 
				genuser->save_srr1 |= (uint64_t)MASK32(MSR_SF) << 32;	/* If 64-bit task, force 64-bit mode */
			else
				genuser->save_srr1 &= ~((uint64_t)MASK32(MSR_SF) << 32);	/* else 32-bit mode */
		
			return KERN_SUCCESS;
				
				
		case PPC_EXCEPTION_STATE:
			
			es = (struct ppc_exception_state *) tstate;
		
			genuser->save_dar = (uint64_t)es->dar;
			genuser->save_dsisr = es->dsisr;
			genuser->save_exception = es->exception;

			return KERN_SUCCESS;
	
/*
 *		It's pretty worthless to try to change this stuff, but we'll do it anyway.
 */
 
		case PPC_EXCEPTION_STATE64:
			
			xes = (struct ppc_exception_state *) tstate;
		
			genuser->save_dar 	= xes->dar;
			genuser->save_dsisr = xes->dsisr;
			genuser->save_exception = xes->exception;

			return KERN_SUCCESS;
	
		case PPC_FLOAT_STATE:

			toss_live_fpu(thread->machine.curctx);			/* Toss my floating point if live anywhere */
			
			fsv = find_user_fpu(thread);					/* Get the user's floating point context */
		
			if(!fsv) {										/* Do we have one yet? */
				fsv = (savearea_fpu *)save_alloc();			/* If we still don't have one, get a new one */
				fsv->save_hdr.save_flags = (fsv->save_hdr.save_flags & ~SAVtype) | (SAVfloat << SAVtypeshft);	/* Mark as in use as float */
				fsv->save_hdr.save_act = thread;
				fsv->save_hdr.save_prev = 0;				/* Mark no more */
				fsv->save_hdr.save_level = 0;				/* Mark user state */
				
				if(!thread->machine.curctx->FPUsave) thread->machine.curctx->FPUsave = fsv;	/* If no floating point, chain us first */
				else {
				
					fsvn = fsvo = thread->machine.curctx->FPUsave;	/* Remember first one */
					
					while (fsvn) {							/* Go until we hit the end */
						fsvo = fsvn;						/* Remember the previous one */
						fsvn = CAST_DOWN(savearea_fpu *, fsvo->save_hdr.save_prev);	/* Skip on to the next */
					}
					
					fsvo->save_hdr.save_prev = (addr64_t)((uintptr_t)fsv);		/* Queue us on in */
				}
				
			}
			
			fs = (struct ppc_float_state *) tstate;			/* Point to source */

		
			bcopy((char *)fs, (char *)&fsv->save_fp0, 32*8);	/* Move in the 32 registers */
			
			genuser->save_fpscr = fs->fpscr;				/* Copy the fpscr value to normal */	
			
			return KERN_SUCCESS;
			
	
		case PPC_VECTOR_STATE:

			toss_live_vec(thread->machine.curctx);			/* Toss my vector if live anywhere */
			
			vsv = find_user_vec(thread);					/* Get the user's vector context */
		
			if(!vsv) {										/* Do we have one yet? */
				vsv = (savearea_vec *)save_alloc();			/* If we still don't have one, get a new one */
				vsv->save_hdr.save_flags = (vsv->save_hdr.save_flags & ~SAVtype) | (SAVvector << SAVtypeshft);	/* Mark as in use as vector */
				vsv->save_hdr.save_act = thread;
				vsv->save_hdr.save_prev = 0;				/* Mark no more */
				vsv->save_hdr.save_level = 0;				/* Mark user state */
				
				if(!thread->machine.curctx->VMXsave) thread->machine.curctx->VMXsave = vsv;	/* If no vector, chain us first */
				else {
				
					vsvn = vsvo = thread->machine.curctx->VMXsave;	/* Remember first one */
					
					while (vsvn) {							/* Go until we hit the end */
						vsvo = vsvn;						/* Remember the previous one */
						vsvn = CAST_DOWN(savearea_vec *, vsvo->save_hdr.save_prev);	/* Skip on to the next */
					}
					
					vsvo->save_hdr.save_prev = (addr64_t)((uintptr_t)vsv);	/* Queue us on in */
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
 * This is where registers that are not normally specified by the mach-o
 * file on an execve should be nullified, perhaps to avoid a covert channel.
 * We've never bothered to clear FPRs or VRs, but it is important to clear
 * the FPSCR, which is kept in the general state but not set by the general
 * flavor (ie, PPC_THREAD_STATE or PPC_THREAD_STATE64.)
 */
kern_return_t
machine_thread_state_initialize(
	thread_t thread)
{
  	savearea		*sv;
	
	sv = get_user_regs(thread);						/* Find or allocate and initialize one */

	sv->save_fpscr = 0;								/* Clear all floating point exceptions */
	sv->save_vrsave = 0;							/* Set the vector save state */
	sv->save_vscr[0] = 0x00000000;					
	sv->save_vscr[1] = 0x00000000;					
	sv->save_vscr[2] = 0x00000000;					
	sv->save_vscr[3] = 0x00010000;					/* Disable java mode and clear saturated */

    return  KERN_SUCCESS;
}


/*
 *		Duplicates the context of one thread into a new one.
 *		The new thread is assumed to be new and have no user state contexts except maybe a general one.
 *		We also assume that the old thread can't be running anywhere.
 *
 *		We're only going to be duplicating user context here.  That means that we will have to 
 *		eliminate any floating point or vector kernel contexts and carry across the user state ones.
 */

kern_return_t
machine_thread_dup(
	thread_t		self,
	thread_t		target)
{
  	savearea		*sv, *osv; 
  	savearea_fpu	*fsv, *fsvn;
  	savearea_vec	*vsv, *vsvn;
	
	fpu_save(self->machine.curctx);						/* Make certain floating point state is all saved */
	vec_save(self->machine.curctx);						/* Make certain the vector state is all saved */
	
	sv = get_user_regs(target);						/* Allocate and initialze context in the new activation */
	
	osv = find_user_regs(self);						/* Find the original context */
	if(!osv)
		return (KERN_FAILURE);
	
	bcopy((char *)((unsigned int)osv + sizeof(savearea_comm)),	/* Copy everything but the headers */
		(char *)((unsigned int)sv + sizeof(savearea_comm)), 
		sizeof(struct savearea) - sizeof(savearea_comm));
	
	sv->save_srr1 &= (uint64_t)(~(MASK(MSR_FP) | MASK(MSR_VEC)));	/* Make certain that floating point and vector are turned off */

	fsv = find_user_fpu(self);						/* Get any user floating point */
	
	target->machine.curctx->FPUsave = 0;					/* Assume no floating point */

	if(fsv) {										/* Did we find one? */
		fsvn = (savearea_fpu *)save_alloc();		/* If we still don't have one, get a new one */
		fsvn->save_hdr.save_flags = (fsvn->save_hdr.save_flags & ~SAVtype) | (SAVfloat << SAVtypeshft);	/* Mark as in use as float */
		fsvn->save_hdr.save_act = target;
		fsvn->save_hdr.save_prev = 0;				/* Mark no more */
		fsvn->save_hdr.save_level = 0;				/* Mark user state */

		target->machine.curctx->FPUsave = fsvn;			/* Chain in the floating point */

		bcopy((char *)((unsigned int)fsv + sizeof(savearea_comm)),	/* Copy everything but the headers */
			(char *)((unsigned int)fsvn + sizeof(savearea_comm)), 
			sizeof(struct savearea) - sizeof(savearea_comm));
	}

	vsv = find_user_vec(self);						/* Get any user vector */
	
	target->machine.curctx->VMXsave = 0;					/* Assume no vector */

	if(vsv) {										/* Did we find one? */
		vsvn = (savearea_vec *)save_alloc();		/* If we still don't have one, get a new one */
		vsvn->save_hdr.save_flags = (vsvn->save_hdr.save_flags & ~SAVtype) | (SAVvector << SAVtypeshft);	/* Mark as in use as float */
		vsvn->save_hdr.save_act = target;
		vsvn->save_hdr.save_prev = 0;				/* Mark no more */
		vsvn->save_hdr.save_level = 0;				/* Mark user state */

		target->machine.curctx->VMXsave = vsvn;			/* Chain in the floating point */

		bcopy((char *)((unsigned int)vsv + sizeof(savearea_comm)),	/* Copy everything but the headers */
			(char *)((unsigned int)vsvn + sizeof(savearea_comm)), 
			sizeof(struct savearea) - sizeof(savearea_comm));
	}

	return (KERN_SUCCESS);
}

/*
 *		Initializes a fresh set of user state values.  If there is no user state context,
 *		one is created. Floats and VMX are not created. 
 *		
 *		We only set initial values if there was no context found.
 */

savearea *
get_user_regs(
	thread_t	 thread)
{
  	savearea		*sv, *osv;
	unsigned int	i;

	if (thread->machine.upcb)
		return	thread->machine.upcb;

	sv = thread->machine.pcb;								/* Get the top savearea on the stack */
	osv = 0;										/* Set no user savearea yet */	
	
	while(sv) {										/* Find the user context */
		osv = sv;									/* Save the last one */
		sv = CAST_DOWN(savearea *, sv->save_hdr.save_prev);	/* Get the previous context */ 
	}

	sv = save_alloc();								/* Get one */
	sv->save_hdr.save_flags = (sv->save_hdr.save_flags & ~SAVtype) | (SAVgeneral << SAVtypeshft);	/* Mark as in use as general */
	sv->save_hdr.save_act = thread;
	sv->save_hdr.save_prev = 0;						/* Mark no more */
	sv->save_hdr.save_level = 0;					/* Mark user state */
	
	if(osv) {										/* Did we already have one? */
		osv->save_hdr.save_prev = (addr64_t)((uintptr_t)sv);		/* Chain us on the end */
	}
	else {											/* We are the first */
		thread->machine.pcb = sv;							/* Put it there */
	}
	thread->machine.upcb = sv;							/* Set user pcb */

	for(i=0; i < 32; i+=2) {						/* Fill up with defaults */
		((unsigned int *)&sv->save_r0)[i] = ((unsigned int *)&FloatInit)[0];
		((unsigned int *)&sv->save_r0)[i+1] = ((unsigned int *)&FloatInit)[1];
	}
	sv->save_cr	= 0;
	sv->save_xer	= 0;
	sv->save_lr	= (uint64_t)FloatInit;
	sv->save_ctr	= (uint64_t)FloatInit;
	sv->save_srr0	= (uint64_t)FloatInit;
	sv->save_srr1 = (uint64_t)MSR_EXPORT_MASK_SET;
	if(task_has_64BitAddr(thread->task)) 
		sv->save_srr1 |= (uint64_t)MASK32(MSR_SF) << 32;	/* If 64-bit task, force 64-bit mode */

	sv->save_fpscr = 0;								/* Clear all floating point exceptions */

	sv->save_vrsave = 0;							/* Set the vector save state */
	sv->save_vscr[0] = 0x00000000;					
	sv->save_vscr[1] = 0x00000000;					
	sv->save_vscr[2] = 0x00000000;					
	sv->save_vscr[3] = 0x00010000;					/* Disable java mode and clear saturated */
	
	return sv;										/* Bye bye... */
}

/*
 *		Find the user state context.  If there is no user state context,
 *		we just return a 0.
 */

savearea *
find_user_regs(
	thread_t	thread)
{
	return thread->machine.upcb;
}

/* The name of this call is something of a misnomer since the mact.pcb can 
 * contain chained saveareas, but it will do for now..
 */
savearea *
find_kern_regs(
	thread_t	thread)
{
        return thread->machine.pcb;
}

/*
 *		Find the user state floating point context.  If there is no user state context,
 *		we just return a 0.
 */

savearea_fpu *
find_user_fpu(
	thread_t	thread)
{
  	savearea_fpu	*fsv;
	boolean_t		intr;

	intr = ml_set_interrupts_enabled(FALSE);
	fsv = thread->machine.curctx->FPUsave;				/* Get the start of the floating point chain */
	
	while(fsv) {									/* Look until the end or we find it */
		if(!(fsv->save_hdr.save_level)) break;		/* Is the the user state stuff? (the level is 0 if so) */	
		fsv = CAST_DOWN(savearea_fpu *, fsv->save_hdr.save_prev);	/* Try the previous one */ 
	}
	(void) ml_set_interrupts_enabled(intr);
	
	return fsv;										/* Bye bye... */
}

/*
 *		Find the user state vector context.  If there is no user state context,
 *		we just return a 0.
 */

savearea_vec *
find_user_vec(
	thread_t	thread)
{
  	savearea_vec	*vsv;
	boolean_t		intr;

	intr = ml_set_interrupts_enabled(FALSE);
	vsv = thread->machine.curctx->VMXsave;				/* Get the start of the vector chain */
	
	while(vsv) {									/* Look until the end or we find it */
		if(!(vsv->save_hdr.save_level)) break;		/* Is the the user state stuff? (the level is 0 if so) */	
		vsv = CAST_DOWN(savearea_vec *, vsv->save_hdr.save_prev);	/* Try the previous one */ 
	}
	(void) ml_set_interrupts_enabled(intr);
	
	return vsv;										/* Bye bye... */
}
/*
 *		Find the user state vector context for the current thread.  If there is no user state context,
 *		we just return a 0.
 */

savearea_vec *find_user_vec_curr(void) {

  	savearea_vec	*vsv;
	thread_t		thread = current_thread();
	boolean_t		intr;
	
	vec_save(thread->machine.curctx);						/* Force save if live */

	intr = ml_set_interrupts_enabled(FALSE);
	vsv = thread->machine.curctx->VMXsave;				/* Get the start of the vector chain */
	
	while(vsv) {									/* Look until the end or we find it */
		if(!(vsv->save_hdr.save_level)) break;		/* Is the the user state stuff? (the level is 0 if so) */	
		vsv = CAST_DOWN(savearea_vec *, vsv->save_hdr.save_prev);	/* Try the previous one */ 
	}
	(void) ml_set_interrupts_enabled(intr);
	
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
    __unused thread_t	thread,
    int                 flavor,
    thread_state_t      tstate,
    unsigned int        count,
    mach_vm_offset_t	*user_stack,
	int					*customstack
)
{
        /*
         * Set a default.
         */

        switch (flavor) {
        case PPC_THREAD_STATE:
		{
			struct ppc_thread_state *state;

                if (count < PPC_THREAD_STATE_COUNT)
                        return (KERN_INVALID_ARGUMENT);
 
                state = (struct ppc_thread_state *) tstate;
    
                /*
                 * If a valid user stack is specified, use it.
                 */
			if (state->r1) {
				*user_stack = CAST_USER_ADDR_T(state->r1);
				if (customstack)
					*customstack = 1;
			} else {
				*user_stack = CAST_USER_ADDR_T(USRSTACK);
				if (customstack)
					*customstack = 0;
			}
		}
                break;
					
	case PPC_THREAD_STATE64:
		{
			struct ppc_thread_state64 *state64;
					
			if (count < PPC_THREAD_STATE64_COUNT)
				return (KERN_INVALID_ARGUMENT);

			state64 = (struct ppc_thread_state64 *)tstate;

			/*
			 * If a valid user stack is specified, use it.
			 */
			if (state64->r1 != MACH_VM_MIN_ADDRESS) {
				*user_stack = state64->r1;
				if (customstack)
					*customstack = 1;
			} else {
				*user_stack = USRSTACK64;
				if (customstack)
					*customstack = 0;
			}
		}
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
void
thread_setuserstack(thread_t thread, mach_vm_address_t user_stack)
{
	savearea *sv;
	
	sv = get_user_regs(thread);	/* Get the user state registers */
	
	sv->save_r1 = user_stack;
	
	return;
}    

/*
 * thread_adjuserstack:
 *
 * Returns the adjusted user stack pointer from the machine
 * dependent thread state info.  Usef for small (<2G) deltas.
 */
uint64_t
thread_adjuserstack(thread_t thread, int adjust)
{
	savearea *sv;
	
	sv = get_user_regs(thread);	/* Get the user state registers */
	
	sv->save_r1 += adjust;		/* Adjust the stack */
	
	return sv->save_r1;		/* Return the adjusted stack */
	
}    

/*
 * thread_setentrypoint:
 *
 * Sets the user PC into the machine
 * dependent thread state info.
 */

void
thread_setentrypoint(thread_t thread, uint64_t entry)
{
	savearea *sv;
	
	sv = get_user_regs(thread);	/* Get the user state registers */
	
	sv->save_srr0 = entry;
	
	return;
}    

kern_return_t
thread_entrypoint(
    __unused thread_t	thread,
    int                 flavor,
    thread_state_t      tstate,
    unsigned int        count,
    mach_vm_offset_t	*entry_point
)
{ 
#if 0
	/* Silly code: "if *entry_point is 0, make it 0" */
    /*
     * Set a default.
     */
    if (*entry_point == 0ULL)
        *entry_point = MACH_VM_MIN_ADDRESS;
#endif
    
    switch (flavor) {   
    case PPC_THREAD_STATE:
    	{
	    struct ppc_thread_state     *state;

        if (count < PPC_THREAD_STATE_COUNT)
            return (KERN_INVALID_ARGUMENT);

        state = (struct ppc_thread_state *) tstate;

        /* 
         * If a valid entry point is specified, use it.
         */     
	    if (state->srr0) {
		*entry_point = CAST_USER_ADDR_T(state->srr0);
	    } else {
		*entry_point = CAST_USER_ADDR_T(VM_MIN_ADDRESS);
	    }
	}
        break; 

    case PPC_THREAD_STATE64:
    	{
	    struct ppc_thread_state64     *state64;

	    if (count < PPC_THREAD_STATE_COUNT)
		return (KERN_INVALID_ARGUMENT);

	    state64 = (struct ppc_thread_state64 *)tstate;

	    /* 
	     * If a valid entry point is specified, use it.
	     */     
	    if (state64->srr0) {
		*entry_point = state64->srr0;
	    } else {
		*entry_point = MACH_VM_MIN_ADDRESS;
	    }
	}
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

void ppc_checkthreadstate(void * tsptr, int flavor)
{
	if (flavor == PPC_THREAD_STATE64) {
		struct ppc_thread_state64 *ts64 =(struct ppc_thread_state64 *)tsptr;

		/* Make sure naughty bits are off and necessary bits are on */
		ts64->srr1 &= ~(MASK(MSR_POW)|MASK(MSR_ILE)|MASK(MSR_IP)|MASK(MSR_LE));
		ts64->srr1 |= (MASK(MSR_PR)|MASK(MSR_ME)|MASK(MSR_IR)|MASK(MSR_DR)|MASK(MSR_EE));
	} else {
		struct ppc_thread_state *ts =(struct ppc_thread_state *)tsptr;

		/* Make sure naughty bits are off and necessary bits are on */
		ts->srr1 &= ~(MASK(MSR_POW)|MASK(MSR_ILE)|MASK(MSR_IP)|MASK(MSR_LE));
		ts->srr1 |= (MASK(MSR_PR)|MASK(MSR_ME)|MASK(MSR_IR)|MASK(MSR_DR)|MASK(MSR_EE));
	}
	return;
}

void
thread_set_child(
	thread_t	child,
	int			pid)
{
	struct savearea *child_state;
	
	child_state = get_user_regs(child);
	
	child_state->save_r3 = (uint_t)pid;
	child_state->save_r4 = 1ULL;
}
void
thread_set_parent(
	thread_t	parent,
	int			pid)
{
	struct savearea *parent_state;
	
	parent_state = get_user_regs(parent);
	
	parent_state->save_r3 = (uint64_t)pid;
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
	
	thread_t thread;	
	
	thread = current_thread();
	
	fpu_save(thread->machine.curctx);						/* Make certain floating point state is all saved */
	vec_save(thread->machine.curctx);						/* Make certain the vector state is all saved */

	osv = find_user_regs(thread);						/* Get our savearea */

	if(!osv) {
		panic("act_thread_csave: attempting to preserve the context of an activation with none (%08X)\n", thread);
	}
	
	sv = save_alloc();								/* Get a fresh save area to save into */
	sv->save_hdr.save_flags = (sv->save_hdr.save_flags & ~SAVtype) | (SAVgeneral << SAVtypeshft);	/* Mark as in use as general */
	sv->save_hdr.save_act = thread;
	sv->save_hdr.save_prev = 0;						/* Mark no more */
	sv->save_hdr.save_level = 0;					/* Mark user state */
	
	
	bcopy((char *)((unsigned int)osv + sizeof(savearea_comm)),	/* Copy everything but the headers */
		(char *)((unsigned int)sv + sizeof(savearea_comm)), 
		sizeof(struct savearea) - sizeof(savearea_comm));
	
	sv->save_srr1 &= (uint64_t)(~(MASK(MSR_FP) | MASK(MSR_VEC)));	/* Make certain that floating point and vector are turned off */	
	
	sv->save_hdr.save_misc2 = 0xDEBB1ED0;			/* Eye catcher for debug */
	sv->save_hdr.save_misc3 = 0xE5DA11A5;			/* Eye catcher for debug */
	

	ofsv = find_user_fpu(thread);						/* Get any user floating point */

	sv->save_hdr.save_misc0 = 0;					/* Assume no floating point */

	if(ofsv) {										/* Did we find one? */
		fsv = (savearea_fpu *)save_alloc();			/* If we still don't have one, get a new one */
		fsv->save_hdr.save_flags = (fsv->save_hdr.save_flags & ~SAVtype) | (SAVfloat << SAVtypeshft);	/* Mark as in use as float */
		fsv->save_hdr.save_act = thread;
		fsv->save_hdr.save_prev = 0;				/* Mark no more */
		fsv->save_hdr.save_level = 0;				/* Mark user state */
		fsv->save_hdr.save_misc2 = 0xDEBB1ED0;		/* Eye catcher for debug */
		fsv->save_hdr.save_misc3 = 0xE5DA11A5;		/* Eye catcher for debug */

		sv->save_hdr.save_misc0 = (uint64_t)((uintptr_t)fsv);	/* Remember this one */

		bcopy((char *)((unsigned int)ofsv + sizeof(savearea_comm)),	/* Copy everything but the headers */
			(char *)((unsigned int)fsv + sizeof(savearea_comm)), 
			sizeof(struct savearea) - sizeof(savearea_comm));
	}

	ovsv = find_user_vec(thread);						/* Get any user vector */
	
	sv->save_hdr.save_misc1 = 0;					/* Assume no vector */

	if(ovsv) {										/* Did we find one? */
		vsv = (savearea_vec *)save_alloc();			/* If we still don't have one, get a new one */
		vsv->save_hdr.save_flags = (vsv->save_hdr.save_flags & ~SAVtype) | (SAVvector << SAVtypeshft);	/* Mark as in use as float */
		vsv->save_hdr.save_act = thread;
		vsv->save_hdr.save_prev = 0;				/* Mark no more */
		vsv->save_hdr.save_level = 0;				/* Mark user state */
		vsv->save_hdr.save_misc2 = 0xDEBB1ED0;		/* Eye catcher for debug */
		vsv->save_hdr.save_misc3 = 0xE5DA11A5;		/* Eye catcher for debug */

		sv->save_hdr.save_misc1 = (uint64_t)((uintptr_t)vsv);	/* Chain in the floating point */

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
	unsigned int	spc;
	thread_t thread;	
	
	sv = (savearea *)ctx;							/* Make this easier for C */
	
	fsv = CAST_DOWN(savearea_fpu *, sv->save_hdr.save_misc0);	/* Get a possible floating point savearea */ 
	vsv = CAST_DOWN(savearea_vec *, sv->save_hdr.save_misc1);	/* Get a possible vector savearea */ 
	
	if((sv->save_hdr.save_misc2 != 0xDEBB1ED0) || (sv->save_hdr.save_misc3 != 0xE5DA11A5)) {	/* See if valid savearea */
		panic("act_thread_catt: attempt to attach invalid general context savearea - %08X\n", sv);	/* Die */
	}

	if(fsv && ((fsv->save_hdr.save_misc2 != 0xDEBB1ED0) || (fsv->save_hdr.save_misc3 != 0xE5DA11A5))) {	/* See if valid savearea */
		panic("act_thread_catt: attempt to attach invalid float context savearea - %08X\n", fsv);	/* Die */
	}

	if(vsv && ((vsv->save_hdr.save_misc2 != 0xDEBB1ED0) || (vsv->save_hdr.save_misc3 != 0xE5DA11A5))) {	/* See if valid savearea */
		panic("act_thread_catt: attempt to attach invalid vector context savearea - %08X\n", vsv);	/* Die */
	}

	thread = current_thread();

	act_machine_sv_free(thread);					/* Blow away any current kernel FP or vector.
													   We do not support those across a vfork */
	toss_live_fpu(thread->machine.curctx);			/* Toss my floating point if live anywhere */
	toss_live_vec(thread->machine.curctx);			/* Toss my vector if live anywhere */
		
	sv->save_hdr.save_misc2 = 0;					/* Eye catcher for debug */
	sv->save_hdr.save_misc3 = 0;					/* Eye catcher for debug */
	sv->save_hdr.save_act = thread;
	
	spc = (unsigned int)thread->map->pmap->space;	/* Get the space we're in */
	
	osv = thread->machine.pcb;						/* Get the top general savearea */
	psv = 0;
	while(osv) {									/* Any saved state? */
		if(osv->save_srr1 & MASK(MSR_PR)) break;	/* Leave if this is user state */
		psv = osv;									/* Save previous savearea address */
		osv = CAST_DOWN(savearea *, osv->save_hdr.save_prev);	/* Get one underneath our's */
	}
	
	if(osv) {										/* Did we find one? */
		if(psv) psv->save_hdr.save_prev = 0;		/* Yes, clear pointer to it (it should always be last) or */	
		else thread->machine.pcb = 0;						/* to the start if the only one */

		save_release(osv);							/* Nope, release it */
		
	}

	if(psv)	psv->save_hdr.save_prev = (addr64_t)((uintptr_t)sv);	/* Chain us to the end or */
	else thread->machine.pcb = (pcb_t)sv;					/* to the start if the only one */
	thread->machine.upcb = (pcb_t)sv;						/* Set the user pcb */
	
	ovsv = thread->machine.curctx->VMXsave;				/* Get the top vector savearea */
	
	pvsv = 0;
	while(ovsv) {									/* Any VMX saved state? */
		if(!(ovsv->save_hdr.save_level)) break;		/* Leave if this is user state */
		pvsv = ovsv;								/* Save previous savearea address */
		ovsv = CAST_DOWN(savearea_vec *, ovsv->save_hdr.save_prev);	/* Get one underneath our's */ 
	}
	
	if(ovsv) {										/* Did we find one? */
		if(pvsv) pvsv->save_hdr.save_prev = 0;		/* Yes, clear pointer to it (it should always be last) or */	
		else thread->machine.curctx->VMXsave = 0;	/* to the start if the only one */

		save_release((savearea *)ovsv);				/* Nope, release it */
	}
	
	if(vsv) {										/* Are we sticking any vector on this one? */
		if(pvsv) pvsv->save_hdr.save_prev = (addr64_t)((uintptr_t)vsv);	/* Yes, chain us to the end or */
		else {
			thread->machine.curctx->VMXsave = vsv;	/* to the start if the only one */
			thread->machine.curctx->VMXlevel = 0;	/* Insure that we don't have a leftover level */
		}

		vsv->save_hdr.save_misc2 = 0;				/* Eye catcher for debug */
		vsv->save_hdr.save_misc3 = 0;				/* Eye catcher for debug */
		vsv->save_hdr.save_act = thread;
	}
	
	ofsv = thread->machine.curctx->FPUsave;			/* Get the top float savearea */
	
	pfsv = 0;
	while(ofsv) {									/* Any float saved state? */
		if(!(ofsv->save_hdr.save_level)) break;		/* Leave if this is user state */
		pfsv = ofsv;								/* Save previous savearea address */
		ofsv = CAST_DOWN(savearea_fpu *, ofsv->save_hdr.save_prev);	/* Get one underneath our's */
	}
	
	if(ofsv) {										/* Did we find one? */
		if(pfsv) pfsv->save_hdr.save_prev = 0;		/* Yes, clear pointer to it (it should always be last) or */	
		else thread->machine.curctx->FPUsave = 0;	/* to the start if the only one */

		save_release((savearea *)ofsv);				/* Nope, release it */
	}
	
	if(fsv) {										/* Are we sticking any vector on this one? */
		if(pfsv) pfsv->save_hdr.save_prev = (addr64_t)((uintptr_t)fsv);	/* Yes, chain us to the end or */
		else {
			thread->machine.curctx->FPUsave = fsv;	/* to the start if the only one */
			thread->machine.curctx->FPUlevel = 0;	/* Insure that we don't have a leftover level */
		}

		fsv->save_hdr.save_misc2 = 0;				/* Eye catcher for debug */
		fsv->save_hdr.save_misc3 = 0;				/* Eye catcher for debug */
		fsv->save_hdr.save_act = thread;
	}
	
}



/*
 *		Releases saved context.  We need this because the saved context is opague.
 *		be adjusted when these contexts are attached to a new activation.
 *
 */

void
act_thread_cfree(void *ctx)
{

  	savearea	*sv;
  	savearea_fpu	*fsv;
  	savearea_vec	*vsv;

	sv = (savearea *)ctx;							/* Make this easier for C */
	
	fsv = CAST_DOWN(savearea_fpu *, sv->save_hdr.save_misc0);	/* Get a possible floating point savearea */ 
	vsv = CAST_DOWN(savearea_vec *, sv->save_hdr.save_misc1);	/* Get a possible vector savearea */ 
	
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
int thread_enable_fpe(
	thread_t		thread,
	int				onoff)
{
        savearea *sv;
        uint64_t oldmsr;

        sv = find_user_regs(thread);										/* Find the user registers */
        if(!sv) sv = get_user_regs(thread);									/* Didn't find any, allocate and initialize one */

        oldmsr = sv->save_srr1;												/* Get the old msr */

        if(onoff) sv->save_srr1 = oldmsr | (uint64_t)(MASK(MSR_FE0) | MASK(MSR_FE1));	/* Flip on precise FP exceptions */
        else sv->save_srr1 = oldmsr & (uint64_t)(~(MASK(MSR_FE0) | MASK(MSR_FE1)));		/* Flip on precise FP exceptions */

        return ((oldmsr & (MASK(MSR_FE0) | MASK(MSR_FE1))) != 0);			/* Return if it was enabled or not */
}   
