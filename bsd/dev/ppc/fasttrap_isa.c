/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * #pragma ident	"@(#)fasttrap_isa.c	1.23	06/09/19 SMI"
 */

#ifdef KERNEL
#ifndef _KERNEL
#define _KERNEL /* Solaris vs. Darwin */
#endif
#endif

#define MACH__POSIX_C_SOURCE_PRIVATE 1 /* pulls in suitable savearea from mach/ppc/thread_status.h */
#include <sys/fasttrap_isa.h>
#include <sys/fasttrap_impl.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <sys/dtrace_ptss.h>
#include <kern/debug.h>
#include <ppc/decodePPC.h>
#include <kern/task.h>
#include <mach/vm_param.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <vm/pmap.h>
#include <vm/vm_map.h> /* All the bits we care about are guarded by MACH_KERNEL_PRIVATE :-( */
extern dtrace_id_t dtrace_probeid_error;

#define proc_t struct proc

static int32_t branchtaken(int32_t bo, int32_t bi, ppc_saved_state_t *sv);
static int32_t dtrace_decode_ppc(uint32_t inst);
int patchInst(task_t task, addr64_t vaddr, uint32_t inst);
kern_return_t dtrace_user_probe(ppc_saved_state_t *sv);

/*
 * Lossless User-Land Tracing on PPC
 * ---------------------------------
 *
 * PPC uses a different technique to emulate user-land instruction replaces by a probe
 * trap than x86.
 *
 * Like x86, it will emulate all forms of branch instructions.  We will not attempt
 * to emulate any instruction that we know will cause an interruption or exception
 * (system call, trap, privileged instruction, instruction that uses a privileged
 * register).
 *
 * NOTE: I am thinking that we should punish tight loopers, e.g., branch-to-dot.
 * Depending upon clock resolution and how fast we can process these guys, it is
 * possible that its quantum will never decrease.  Maybe we could just manually
 * end the guy's quantum and let the next guy go...
 *
 * When fasttrap_tracepoint_init is called, we fetch the instruction and decode it.
 * If we don't recognize it or find it is a "banned" instruction, we return -1,
 * telling our caller to forget it.  Otherwise we save the instruction image and
 * enough of the decode to quickly handle it at probe time.  We cram it into
 * the fasttrap_machtp_t structure.
 *
 * When the probe hits, we verify that the PC is still a probe point and if not,
 * we bail.  Otherwise we have a bit more to do.
 *
 * If DTFTP_ENTRY is set, we have an entry probe and need to call dtrace_probe.
 *
 * If DTFTP_IS_ENABLED is set, all we need to do is to return a 1.
 *
 * If ftp_argmap is NULL, we call dtrace_probe
 *
 * Otherwise, we figure out what the arguments are and pass them to dtrace_probe
 *
 * Next, we need to set up to emulate the probed instruction and here is where we are
 * the most different than the x86 code.
 *
 * Like x86, we first check to see if the instruction is any form of branch.  If so, 
 * we emulate it completely within the kernel and are done.
 *
 * If it is anything else, we build a code stream within the kernel to execute the
 * instruction.  Note that this is very different from x86 which build the code in
 * userland.
 *
 * The generated stream needs to be executed within the kernel's code space but with
 * the user address space and registers.  Because PPC allows different translation modes
 * for instruction fetch and data fetch, this is not too difficult.
 *
 * There are two kinds streams needed: execute and continue, and execute and return,
 * which are used for entry/offset and exit probes respectivily. 
 *
 * The probe code will copy the instruction image into the current user savearea (which
 * also contains the complete user state register context).  A flag that requests either
 * execute/continue or execute/return is also set in the savearea.
 *
 * We now exit the dtrace code and the marked context makes its way back to the point
 * where it will be dispatched on the processor.
 *
 * The exception return code will start to restore the user context, including registers
 * and address space.  However, before dispatching the user, it will notice that the
 * emulate flags are set.  At this point the code will build a code stream 
 * in an area in the per_proc that consists of
 * the original instruction followed by a trap instruction.  It will set the new MSR (in
 * SRR1) to have address translation enable for data, translation disabled for instruction
 * fetches, interruptions disabled, and supervisor state.
 *
 * The new PC and MSR are loaded via a RFID and the generated stream is executed. If a
 * synchronous fault occurs, it is either handled (PTE miss, FPU or vector unavailable),
 * emulated (alignment or denorm), or passed on to the user.
 *
 * Assuming the emulated instruction completes, the trap will execute.  When that happens, 
 * low-level trap handler will check its flags.  If the trap corresponds to an
 * execute/continue stream, the trap handler will adjust the PC and complete the
 * transition into user space. 
 *
 * If the trap corresponds to an execute/return stream, the handler will generate 
 * a T_DTRACE_RET exception and let the trap handler pass it along to dtrace_user_probe.
 *
 */


static uint64_t
fasttrap_anarg(ppc_saved_state_t *sv, int function_entry, int argno)
{
#pragma unused(function_entry)
	uint32_t farg;
 	uint64_t value;
 	
 	/* The first 8 arguments (argno 0-7) are in registers */
 	if (argno < 8) {
 		value = (&sv->save_r3)[argno];
 	} else {
 		if (sv->save_srr1 & 0x8000000000000000ULL) {
 			/* 64-bit */
 			/* Grab argument >= 8 from stack */
 			fasttrap_fuword64_noerr(sv->save_r1 + 48 + ((argno)* sizeof(uint64_t)), &value);
 		} else {
 			/* 32-bit */
			/* Grab argument >= 8 from stack */
 			fasttrap_fuword32_noerr(sv->save_r1 + 24 + ((argno) * sizeof(uint32_t)), &farg);
			value = (uint64_t)farg;
 		}
 	}
 	
 	return (value);
}

/*ARGSUSED*/
int
fasttrap_tracepoint_init(proc_t *p, fasttrap_tracepoint_t *tp, user_addr_t pc,
    fasttrap_probe_type_t type)
{
#pragma unused(type)

	uint32_t instr, testr1, testr2, testr3;
	user_addr_t targpc;
	int32_t target, optype;

	/*
	 * Read the instruction at the given address out of the process's
	 * address space. We don't have to worry about a debugger
	 * changing this instruction before we overwrite it with our trap
	 * instruction since P_PR_LOCK is set. Since instructions can span
	 * pages, we potentially read the instruction in two parts. If the
	 * second part fails, we just zero out that part of the instruction.
	 */
	/*
	 * APPLE NOTE: Of course, we do not have a P_PR_LOCK, so this is racey...
	 */

	if (uread(p, &instr, 4, pc) != 0) return (-1);	/* Grab instruction, return suddenly if read fails... */
		
	optype = dtrace_decode_ppc(instr);		/* See if we have an instruction we can probe */
	
	tp->ftt_instr = instr;					/* Save the instruction image */
	testr1 = tp->ftt_bo = (uint8_t)((instr >> (31 - 10)) & 0x1F);	/* Extract branch options */
	testr2 = tp->ftt_bi = (uint8_t)((instr >> (31 - 15)) & 0x1F);	/* Extract condition register bit */
	testr3 = (instr >> (31 - 20)) & 0x1F;	/* Get that last register */
	tp->ftt_flgs = (uint8_t)(instr & 3);	/* Set the absolute address and link flags */

	switch(optype) {						/* Do instruction specific decode */
		
		case diCMN:							/* Common instruction */
			tp->ftt_type = ftmtCommon;		/* Mark as common instruction */
			break;
			
		case diINV: 						/* Invalid */
		case diTRP:							/* Trap */
		case diSC:							/* System Call */
		case diRFI: 						/* Return from interrupt */
		case diPRV:							/* Priviliged instruction */
			return (-1);					/* We will not emulate these... */
			break;
		
		case diB:							/* Branch */
			tp->ftt_type = ftmtB;			/* Mark as branch instruction */
			target = instr & 0x03FFFFFC;	/* Extract address or offset */
			if(target & 0x02000000) target |= 0xFC000000;	/* Sign extend */
			tp->ftt_trgt = target;			/* Trim back down and save */
			
			targpc = (user_addr_t)((int64_t)target);	/* Generate a target address, hopefully we sign extend... */
			if(!(tp->ftt_flgs & ftmtAbs)) {	/* Are we dealing with an offset here? */
				targpc = targpc + pc;		/* Apply offset to get target address */
			}
			
			if(targpc == pc) return -1;		/* Branching to self is a sin and is forbidden... */
			break;
			
		case diBC:							/* Branch conditional */
			tp->ftt_type = ftmtBC;			/* Mark as branch conditional */
			target = instr & 0x0000FFFC;	/* Extract address or offset */
			if(target & 0x00008000) target |= 0xFFFF0000;	/* Sign extend */
			tp->ftt_trgt = target;			/* Trim back down and save */
			
			targpc = (user_addr_t)((int64_t)target);	/* Generate a target address, hopefully we sign extend... */
			if(!(tp->ftt_flgs & ftmtAbs)) {		/* Are we dealing with an offset here? */
				targpc = targpc + pc;		/* Apply offset to get target address */
			}
			
			if(targpc == pc) return -1;		/* Branching to self is a sin and is forbidden... */
			break;
			
		case diBLR:							/* Branch conditional to link register */
			tp->ftt_type = ftmtBLR;			/* Mark as branch conditional to link register */
			break;
			
		case diBCTR:						/* Branch conditional to count register */
			tp->ftt_type = ftmtBCTR;		/* Mark as branch conditional to count register */
			break;
			
		case diOR:							/* OR */
			if((instr >> 26) == 24) {		/* Is this the ORI nop? */
				if((testr1 == testr2) && ((instr & 0x0000FFFF) == 0)) tp->ftt_type = ftmtNOP;	/* Remember if this is a NOP instruction */
				else tp->ftt_type = ftmtCommon;	/* Otherwise it is a common ORI instruction */
			}
			else if((testr1 == testr2) && (testr1 == testr3)) tp->ftt_type = ftmtNOP;	/* If all three registers are the same, this is a NOP */
			else tp->ftt_type = ftmtCommon;	/* Otherwise it is a common OR instruction */

			break;
			
		default:
			panic("fasttrap_tracepoint_init: invalid branch decode, inst = %08X, optype = %d\n", instr, optype);
			break;
			
	}

	return (0);
}

int
fasttrap_tracepoint_install(proc_t *p, fasttrap_tracepoint_t *tp)
{
	return patchInst(p->task, tp->ftt_pc, FASTTRAP_INSTR);	/* Patch the instruction and flush it */
}

extern void dbgTrace(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);

int
fasttrap_tracepoint_remove(proc_t *p, fasttrap_tracepoint_t *tp)
{
	uint32_t instr;

	/*
	 * Distinguish between read or write failures and a changed
	 * instruction.
	 */
	if (uread(p, &instr, 4, tp->ftt_pc) != 0) return (0);	/* Get the instruction, but exit if not mapped */

//	dbgTrace(0x99999999, (uint32_t)tp->ftt_pc, tp->ftt_instr, instr, 0);	/* (TRACE/DEBUG) */

	if (instr != FASTTRAP_INSTR) return (0);	/* Did someone change it? If so, just leave */

	return patchInst(p->task, tp->ftt_pc, tp->ftt_instr);	/* Patch the old instruction back in and flush it */
}

static void
fasttrap_return_common(ppc_saved_state_t *sv, user_addr_t pc, pid_t pid, user_addr_t new_pc)
{

	fasttrap_tracepoint_t *tp;
	fasttrap_bucket_t *bucket;
	fasttrap_id_t *id;
	lck_mtx_t *pid_mtx;

	pid_mtx = &cpu_core[CPU->cpu_id].cpuc_pid_lock;
	lck_mtx_lock(pid_mtx);
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
		    !tp->ftt_proc->ftpc_defunct)
			break;
	}

	/*
	 * Don't sweat it if we can't find the tracepoint again. Unlike
	 * when we're in fasttrap_pid_probe(), finding the tracepoint here
	 * is not essential to the correct execution of the process.
	 */
	if (tp == NULL) {
		lck_mtx_unlock(pid_mtx);
		return;
	}

	for (id = tp->ftt_retids; id != NULL; id = id->fti_next) {
		/*
		 * If there's a branch that could act as a return site, we
		 * need to trace it, and check here if the program counter is
		 * external to the function.
		 */
		if((new_pc - id->fti_probe->ftp_faddr) < id->fti_probe->ftp_fsize)	/* Is target within the function? */
			continue;							/* Yeah, skip this one... */

		DTRACE_CPUFLAG_SET(CPU_DTRACE_USTACK_FP);
		if (ISSET(current_proc()->p_lflag, P_LNOATTACH)) {
			dtrace_probe(dtrace_probeid_error, 0 /* state */, 
				     id->fti_probe->ftp_id, 1 /* ndx */, -1 /* offset */, 
				     DTRACEFLT_UPRIV);
		} else {
			dtrace_probe(id->fti_probe->ftp_id,
				pc - id->fti_probe->ftp_faddr,
				sv->save_r3, sv->save_r4, 0, 0);
		}
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_USTACK_FP);
	}

	lck_mtx_unlock(pid_mtx);
}

static void
fasttrap_usdt_args(fasttrap_probe_t *probe, ppc_saved_state_t *sv, int argc,
    uint64_t *argv)
{
	int i, x, cap = MIN(argc, probe->ftp_nargs);
	uint32_t farg;

	for (i = 0; i < cap; i++) {
		x = probe->ftp_argmap[i];

		if (x <= 8) {							/* Is this argument in a register? */
			argv[i] = (&sv->save_r0)[x];
		} else {
			if(sv->save_srr1 & 0x8000000000000000ULL) {	/* Are we running in 64-bit? */
				fasttrap_fuword64_noerr(sv->save_r1 + 48 + (x * sizeof(uint64_t)), &argv[i]);	/* Grab argument > 8 from stack */
			}
			else {
				fasttrap_fuword32_noerr(sv->save_r1 + 24 + (x * sizeof(uint32_t)), &farg);	/* Grab argument > 8 from stack */
				argv[i] = (uint64_t)farg;		/* Convert to 64-bit */
			}
		}
	}

	for (; i < argc; i++) {
		argv[i] = 0;
	}
}

int
fasttrap_pid_probe(ppc_saved_state_t *sv)
{
	proc_t *p = current_proc();
	fasttrap_bucket_t *bucket;
	lck_mtx_t *pid_mtx;
	fasttrap_tracepoint_t *tp, tp_local;
	pid_t pid;
	dtrace_icookie_t cookie;
	uint_t is_enabled = 0;
	user_addr_t new_pc = 0;
	user_addr_t pc;
	user_addr_t addrmask;

	pc = sv->save_srr0;							/* Remember the PC for later */
	if(sv->save_srr1 & 0x8000000000000000ULL) addrmask = 0xFFFFFFFFFFFFFFFFULL;	/* Set 64-bit addressing if enabled */
	else addrmask = 0x00000000FFFFFFFFULL;		/* Otherwise set 32-bit */

	uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());

	/*
	 * Clear all user tracing flags.
	 */
	uthread->t_dtrace_ft = 0;

	/*
	 * Treat a child created by a call to vfork(2) as if it were its
	 * parent. We know that there's only one thread of control in such a
	 * process: this one.
	 */
	/*
	 * APPLE NOTE: Terry says: "You need to hold the process locks (currently: kernel funnel) for this traversal"
	 * FIXME: How do we assert this?
	 */
	while (p->p_lflag & P_LINVFORK) p = p->p_pptr;	/* Search the end */

	pid = p->p_pid;
	pid_mtx = &cpu_core[CPU->cpu_id].cpuc_pid_lock;
	lck_mtx_lock(pid_mtx);
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, sv->save_srr0)];	/* Get the bucket that corresponds to out PC */

	/*
	 * Lookup the tracepoint that the process just hit.
	 */
	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && (sv->save_srr0 == tp->ftt_pc) &&
		    !tp->ftt_proc->ftpc_defunct)
			break;
	}

	/*
	 * If we couldn't find a matching tracepoint, either a tracepoint has
	 * been inserted without using the pid<pid> ioctl interface (see
	 * fasttrap_ioctl), or somehow we have mislaid this tracepoint.
	 */
	if (tp == NULL) {
		lck_mtx_unlock(pid_mtx);
		return (-1);
	}

	if (tp->ftt_ids != NULL) {
		fasttrap_id_t *id;
		
		for (id = tp->ftt_ids; id != NULL; id = id->fti_next) {
			fasttrap_probe_t *probe = id->fti_probe;
			
			if (ISSET(current_proc()->p_lflag, P_LNOATTACH)) {
				dtrace_probe(dtrace_probeid_error, 0 /* state */, 
				     id->fti_probe->ftp_id, 1 /* ndx */, -1 /* offset */, 
				     DTRACEFLT_UPRIV);
			} else if (id->fti_ptype == DTFTP_ENTRY) {
				/*
				 * We note that this was an entry
				 * probe to help ustack() find the
				 * first caller.
				 */
				cookie = dtrace_interrupt_disable();
				DTRACE_CPUFLAG_SET(CPU_DTRACE_USTACK_FP | CPU_DTRACE_ENTRY);
				dtrace_probe(probe->ftp_id, sv->save_r3, sv->save_r4,	/* Call the main probe routine with the first 5 args */
					sv->save_r5, sv->save_r6, sv->save_r7);
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_USTACK_FP | CPU_DTRACE_ENTRY);
				dtrace_interrupt_enable(cookie);
				
			} else if (id->fti_ptype == DTFTP_IS_ENABLED) {
				/*
				 * Note that in this case, we don't
				 * call dtrace_probe() since it's only
				 * an artificial probe meant to change
				 * the flow of control so that it
				 * encounters the true probe.
				 */
				is_enabled = 1;
				
			} else if (probe->ftp_argmap == NULL) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_USTACK_FP);
				dtrace_probe(probe->ftp_id, sv->save_r3, sv->save_r4,	/* Call the main probe routine with the first 5 args */
					     sv->save_r5, sv->save_r6, sv->save_r7);
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_USTACK_FP);
					     
			} else {
				uint64_t t[5];
				
				fasttrap_usdt_args(probe, sv, 5, t);	/* Grab 5 arguments */
				
				DTRACE_CPUFLAG_SET(CPU_DTRACE_USTACK_FP);
				dtrace_probe(probe->ftp_id, t[0], t[1],
					     t[2], t[3], t[4]);
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_USTACK_FP);
			}

			/* APPLE NOTE: Oneshot probes get one and only one chance... */
			if (probe->ftp_prov->ftp_provider_type == DTFTP_PROVIDER_ONESHOT) {
				fasttrap_tracepoint_remove(p, tp);
			}
		}
	}

	/*
	 * We're about to do a bunch of work so we cache a local copy of
	 * the tracepoint to emulate the instruction, and then find the
	 * tracepoint again later if we need to light up any return probes.
	 */
	tp_local = *tp;
	lck_mtx_unlock(pid_mtx);
	tp = &tp_local;

	/*
	 * If there's an is-enabled probe connected to this tracepoint it
	 * means that there was a 'xor r3,r3,r3'
	 * instruction that was placed there by DTrace when the binary was
	 * linked. As this probe is, in fact, enabled, we need to stuff 1
	 * into R3. Accordingly, we can bypass all the instruction
	 * emulation logic since we know the inevitable result. It's possible
	 * that a user could construct a scenario where the 'is-enabled'
	 * probe was on some other instruction, but that would be a rather
	 * exotic way to shoot oneself in the foot.
	 */
	if (is_enabled) {
		sv->save_r3 = 1;				/* Set condition to true */
		new_pc = (sv->save_srr0 + 4) & addrmask;		/* Just fall through to the next instruction */
		goto done;
	}

	/*
	 * We emulate certain types of instructions to ensure correctness
	 * (in the case of position dependent instructions) or optimize
	 * common cases. The rest we execute in the kernel, but with
	 * most of the user's context active.
	 */
	switch (tp->ftt_type) {
	
		case ftmtNOP:					/* NOP  */
			new_pc = (sv->save_srr0 + 4) & addrmask;	/* Just fall through to the next instruction */
			break;

		case ftmtB:						/* Plain unconditional branch */
			new_pc = (user_addr_t)((int64_t)tp->ftt_trgt);	/* Assume target is absolute address for the moment */
			if(!(tp->ftt_flgs & ftmtAbs)) new_pc = (new_pc + sv->save_srr0) & addrmask;	/* We don't have absolute address, use as offset from instruction address */

			if(tp->ftt_flgs & ftmtLink) sv->save_lr = (sv->save_srr0 + 4) & addrmask;	/* Set the LR to the next instruction if needed */
			break;
		
		case ftmtBC:					/* Conditional PC relative or absolute branch */
			new_pc = (user_addr_t)((int64_t)tp->ftt_trgt);	/* Assume target is absolute address for the moment */
			if(!(tp->ftt_flgs & ftmtAbs)) new_pc = new_pc + sv->save_srr0;	/* We don't have absolute address, use as offset from instruction address */

			if(tp->ftt_flgs & ftmtLink) sv->save_lr = (sv->save_srr0 + 4) & addrmask;	/* Set the LR to the next instruction if needed */
			if(!branchtaken(tp->ftt_bo, tp->ftt_bi, sv)) new_pc = (sv->save_srr0 + 4) & addrmask;	/* If branch was not taken, set PC to next address */
			break;
		
		case ftmtBLR:					/* Conditional branch to LR */
			new_pc = sv->save_lr;		/* Branch target comes from the LR */

			if(tp->ftt_flgs & ftmtLink) sv->save_lr = (sv->save_srr0 + 4) & addrmask;	/* Set the LR to the next instruction if needed */			
			if(!branchtaken(tp->ftt_bo, tp->ftt_bi, sv)) new_pc = (sv->save_srr0 + 4) & addrmask;	/* If branch was not taken, set PC to next address */
			break;
		
		case ftmtBCTR:					/* Conditional branch to CTR */
			new_pc = sv->save_ctr;		/* Branch target comes from the CTR */

			if(tp->ftt_flgs & ftmtLink) sv->save_lr = (sv->save_srr0 + 4) & addrmask;	/* Set the LR to the next instruction if needed */			
			if(!branchtaken(tp->ftt_bo, tp->ftt_bi, sv)) new_pc = (sv->save_srr0 + 4) & addrmask;	/* If branch was not taken, set PC to next address */
			break;
		
		case ftmtCommon:				/* Common, non-in-kernel emulated instruction */
			sv->save_instr[0] = 1;		/* We only have one instruction to inject */
			sv->save_instr[1] = tp->ftt_instr;	/* Set the instruction */
			sv->save_hdr.save_flags = sv->save_hdr.save_flags | SAVinject;	/* Tell low-level exception return to inject the instruction */
			uthread->t_dtrace_step = 1;	/* Let it be known that a trace return is imminent */
			return 0;					/* Go and don't dome back until you are done... */
			
		default:
			panic("fasttrap_pid_probe: invalid ftt_type = %08X\n", tp->ftt_type);	/* Huh, wha happened? */
			break;
	}
		

done:
	
	/*
	 * If there were no return probes when we first found the tracepoint,
	 * we should feel no obligation to honor any return probes that were
	 * subsequently enabled -- they'll just have to wait until the next
	 * time around.
	 */
	sv->save_srr0 = new_pc;				/* Set the new PC */
	if (tp->ftt_retids != NULL) fasttrap_return_common(sv, pc, pid, new_pc);

	return (0);
}


int
fasttrap_return_probe(ppc_saved_state_t *sv)
{

	user_addr_t pc, npc;
	
	proc_t *p = current_proc();


	/*
	 * Treat a child created by a call to vfork(2) as if it were its
	 * parent. We know that there's only one thread of control in such a
	 * process: this one.
	 */
	/*
	 * APPLE NOTE: Terry says: "You need to hold the process locks (currently: kernel funnel) for this traversal"
	 * How do we assert this?
	 */
	while (p->p_lflag & P_LINVFORK) {
		p = p->p_pptr;
	}

	pc = sv->save_srr0;		/* Get the PC of the probed instruction */
	npc = pc + 4;			/* Get next PC */	
	if(!(sv->save_srr1 & 0x8000000000000000ULL)) npc &= 0x00000000FFFFFFFF;	/* Wrap new PC if running 32-bit */
	fasttrap_return_common(sv, pc, p->p_pid, npc);

	return (0);
}

uint64_t
fasttrap_pid_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
    int aframes)
{
#pragma unused(arg, id, parg, aframes)
	return (fasttrap_anarg((ppc_saved_state_t *)find_user_regs(current_thread()), 1, argno));
}

uint64_t
fasttrap_usdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
    int aframes)
{
#pragma unused(arg, id, parg, aframes)
	return (fasttrap_anarg((ppc_saved_state_t *)find_user_regs(current_thread()), 0, argno));
}


static int32_t branchtaken(int32_t bo, int32_t bi, ppc_saved_state_t *sv) {
	int32_t bcond, czero, crmatch;
	uint64_t ctr;
	
	if((bo & 0x14) == 0x14) return 1;	/* If this is a branch always, exit with true... */
	
	czero = 0;							/* Assume that we have not just decremented the CTR to 0 */
	
	if(!(bo & 4)) {						/* Skip the next bit if we do NOT muck with the CTR */
		ctr = sv->save_ctr = sv->save_ctr - 1;	/* Decrement the CTR */
		if(!(sv->save_srr1 & 0x8000000000000000ULL)) ctr &= 0x00000000FFFFFFFF;	/* Only look at the bottom 32 bits if 32-bit mode */
		czero = (ctr == 0);				/* Remember if we just hit zero */
	}
	
	bcond = (bo >> 3);					/* If 1, branch if CR flag is 1.  If 0, branch if 0 */
	crmatch = bo >> 4;					/* If bo[0] is set, do not check CR flag */
	crmatch = crmatch | (((sv->save_cr >> (31 - bi)) ^ bcond) ^ 1);	/* Low bit is now set if CR flag matches or CR is not checked. Other bits are trash. */

//	dbgTrace(0x77777777, bo, bi, sv->save_cr, ((czero | crmatch) & 1));	/* (TRACE/DEBUG) */

	return ((czero | crmatch) & 1);		/* Return 1 if branch taken, 0 if not... */	
}

static int32_t dtrace_decode_ppc(uint32_t inst) {

	int32_t curdcd, lastmask, newmask, spr, bit, bito, word;
	uint16_t xop = 0;
	dcdtab *dcd;
	
	curdcd = inst >> 26;				/* Isolate major op code to start decode */
	lastmask = 99;						/* Always force a new xop at the start */
	
	while(1) {							/* Loop until we find instruction or fail */
		dcd = &insts[curdcd];			/* Point to the current decode table entry */
		if(dcd->dcdFlgs & dcdJump) {	/* Should we jump to a new spot in the decode table? */
			curdcd = dcd->dcdMatch;		/* Jump */
			continue;
		}
		
		newmask = dcd->dcdFlgs & dcdMask;	/* Isolate the mask index */
		if(lastmask != newmask) {		/* Are we changing masks? */
			if(!newmask) break;			/* If the mask is 0, we match everything and succeed... (note: lastmask can never be 0) */
			xop = inst & masktab[newmask];	/* Clear all extra bits to make match */
			lastmask = newmask;			/* Remember */
		}
		
		if(xop == dcd->dcdMatch) break;	/* We found our guy! */
		
		if(!(dcd->dcdFlgs & dcdStep)) {	/* No stepping, we failed */
			dcd = &dcdfail;				/* Point to a failure entry */
			break;						/* Leave... */
		}
		
		curdcd = curdcd + 1;			/* Step to the next decode entry */
	}

	if(dcd->dcdType != diSPR) return (int32_t)(dcd->dcdType);	/* Return what we found */
	
	spr = (inst >> (31 - 20)) & 0x3FF;	/* Get the source */
	spr = ((spr << 5) & 0x3E0) | ((spr >> 5) & 0x1F);	/* Flip to right order */
	
	word = spr >> 5;					/* Get word index into table */
	bito = spr & 0x1F;					/* Get bit offset into entry */
	bit = 0x80000000 >> bito;			/* Position bit for a test */
	
	if(!(sprtbl[word] & bit)) return (diINV);	/* Bogus SPR so whole instruction is invalid... */
	
	if(spr & 0x10) return (diPRV);		/* This is a priviliged SPR so instruction is priviliged... */
	return (diCMN);						/* Just a common SPR so instruction is the same... */
}
