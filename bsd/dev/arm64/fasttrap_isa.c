/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
 */
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * #pragma ident	"@(#)fasttrap_isa.c	1.19	05/09/14 SMI"
 */

#ifdef KERNEL
#ifndef _KERNEL
#define _KERNEL			/* Solaris vs. Darwin */
#endif
#endif

#include <sys/fasttrap_isa.h>
#include <sys/fasttrap_impl.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <kern/task.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <mach/mach_vm.h>
#include <arm/proc_reg.h>
#include <arm/thread.h>
#include <arm/caches_internal.h>

#include <sys/dtrace_ptss.h>
#include <kern/debug.h>

#include <pexpert/pexpert.h>

extern dtrace_id_t dtrace_probeid_error;

/* Solaris proc_t is the struct. Darwin's proc_t is a pointer to it. */
#define proc_t struct proc /* Steer clear of the Darwin typedef for proc_t */

extern int dtrace_decode_arm64(uint32_t instr);
extern int dtrace_decode_arm(uint32_t instr);
extern int dtrace_decode_thumb(uint32_t instr);

/*
 * Lossless User-Land Tracing on ARM
 * ---------------------------------
 *
 * The details here will be fleshed out as more of this is implemented. The
 * basic design will be the same way as tracing works in x86.
 *
 * Some ARM specific issues:
 *
 * We need to patch differently for ARM instructions and Thumb instructions.
 * When we hit a probe, we check to see if the mode we're currently in is the
 * same as the mode we're patching for. If not, we remove the tracepoint and
 * abort. This ARM/Thumb information is pulled in from the arch specific
 * information in the fasttrap probe.
 *
 * On ARM, any instruction that uses registers can also use the pc as a
 * register. This presents problems during emulation because we have copied
 * the instruction and thus the pc can be different. Currently we've emulated
 * any instructions that use the pc if they can be used in a return probe.
 * Eventually we will want to support all instructions that use the pc, but
 * to do so requires disassembling the instruction and reconstituting it by
 * substituting a different register.
 *
 */

#define THUMB_INSTR(x) (*(uint16_t*) &(x))

#define SIGNEXTEND(x,v) ((((int) (x)) << (32-(v))) >> (32-(v)))
#define ALIGNADDR(x,v) (((x) >> (v)) << (v))
#define GETITSTATE(x) ((((x) >> 8) & 0xFC) | (((x) >> 25) & 0x3))
#define ISLASTINIT(x) (((x) & 0xF) == 8)

#define SET16(x,w) *((uint16_t*) (x)) = (w)
#define SET32(x,w) *((uint32_t*) (x)) = (w)

#define IS_ARM32_NOP(x) ((x) == 0xE1A00000)
/* Marker for is-enabled probes */
#define IS_ARM32_IS_ENABLED(x) ((x) == 0xE0200000)

#define IS_ARM64_NOP(x) ((x) == 0xD503201F)
/* Marker for is-enabled probes */
#define IS_ARM64_IS_ENABLED(x) ((x) == 0xD2800000)

#define IS_THUMB32_NOP(x) ((x) == 0x46C0)
/* Marker for is-enabled probes */
#define IS_THUMB32_IS_ENABLED(x) ((x) == 0x4040)

#define ARM_LDM_UF (1 << 23)
#define ARM_LDM_PF (1 << 24)
#define ARM_LDM_WF (1 << 21)

#define ARM_LDR_UF (1 << 23)
#define ARM_LDR_BF (1 << 22)

static void
flush_caches(void)
{
	/* TODO There were some problems with flushing just the cache line that had been modified.
	 * For now, we'll flush the entire cache, until we figure out how to flush just the patched block.
	 */
	FlushPoU_Dcache();
	InvalidatePoU_Icache();
}


static int fasttrap_tracepoint_init32 (proc_t *, fasttrap_tracepoint_t *, user_addr_t, fasttrap_probe_type_t);
static int fasttrap_tracepoint_init64 (proc_t *, fasttrap_tracepoint_t *, user_addr_t, fasttrap_probe_type_t);

int
fasttrap_tracepoint_init(proc_t *p, fasttrap_tracepoint_t *tp,
			 user_addr_t pc, fasttrap_probe_type_t type)
{
	if (proc_is64bit(p)) {
		return fasttrap_tracepoint_init64(p, tp, pc, type);
	} else {
		return fasttrap_tracepoint_init32(p, tp, pc, type);
	}
}

static int
fasttrap_tracepoint_init32(proc_t *p, fasttrap_tracepoint_t *tp,
			 user_addr_t pc, fasttrap_probe_type_t type)
{
#pragma unused(type)
	uint32_t instr;

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

	if (uread(p, &instr, 4, pc) != 0)
		return (-1);

	/* We want &instr to always point to the saved instruction, so just copy the
	 * whole thing When cast to a pointer to a uint16_t, that will give us a
	 * pointer to the first two bytes, which is the thumb instruction.
	 */
	tp->ftt_instr = instr;

	if (tp->ftt_fntype != FASTTRAP_FN_DONE_INIT) {
		switch(tp->ftt_fntype) {
			case FASTTRAP_FN_UNKNOWN:
				/* Can't instrument without any information. We can add some heuristics later if necessary. */
				return (-1);

			case FASTTRAP_FN_USDT:
				if (IS_ARM32_NOP(instr) || IS_ARM32_IS_ENABLED(instr)) {
					tp->ftt_thumb = 0;
				} else if (IS_THUMB32_NOP(THUMB_INSTR(instr)) || IS_THUMB32_IS_ENABLED(THUMB_INSTR(instr))) {
					tp->ftt_thumb = 1;
				} else {
					/* Shouldn't reach here - this means we don't recognize
					 * the instruction at one of the USDT probe locations
					 */
					return (-1);
				}
				tp->ftt_fntype = FASTTRAP_FN_DONE_INIT;
				break;

			case FASTTRAP_FN_ARM:
				tp->ftt_thumb = 0;
				tp->ftt_fntype = FASTTRAP_FN_DONE_INIT;
				break;

			case FASTTRAP_FN_THUMB:
				tp->ftt_thumb = 1;
				tp->ftt_fntype = FASTTRAP_FN_DONE_INIT;
				break;

			default:
				return (-1);
		}
	}

	if (tp->ftt_thumb) {
		tp->ftt_type = dtrace_decode_thumb(instr);
	} else {
		tp->ftt_type = dtrace_decode_arm(instr);
	}

	if (tp->ftt_type == FASTTRAP_T_INV) {
		/* This is an instruction we either don't recognize or can't instrument */
		printf("dtrace: fasttrap init32: Unrecognized instruction: %08x at %08llx\n",
			(tp->ftt_thumb && dtrace_instr_size(tp->ftt_instr,tp->ftt_thumb) == 2) ? tp->ftt_instr1 : instr, pc);
		return (-1);
	}

	return (0);
}


static int
fasttrap_tracepoint_init64(proc_t *p, fasttrap_tracepoint_t *tp,
			 user_addr_t pc, fasttrap_probe_type_t type)
{
#pragma unused(type)
	uint32_t instr = 0;

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

	if (uread(p, &instr, 4, pc) != 0)
		return (-1);

	tp->ftt_instr = instr;
	tp->ftt_thumb = 0;	/* Always zero on 64bit */

	if (tp->ftt_fntype != FASTTRAP_FN_DONE_INIT) {
		switch(tp->ftt_fntype) {
		case FASTTRAP_FN_UNKNOWN:
			/*
			 * On arm64 there is no distinction between
			 * arm vs. thumb mode instruction types.
			 */
			tp->ftt_fntype = FASTTRAP_FN_DONE_INIT;
			break;

		case FASTTRAP_FN_USDT:
			if (IS_ARM64_NOP(instr) || IS_ARM64_IS_ENABLED(instr)) {
				tp->ftt_fntype = FASTTRAP_FN_DONE_INIT;				
			} else {
				/*
				 * Shouldn't reach here - this means we don't
				 * recognize the instruction at one of the
				 * USDT probe locations
				 */
				return (-1);
			}

			break;

		case FASTTRAP_FN_ARM:
		case FASTTRAP_FN_THUMB:
		default:
			/*
			 * If we get an arm or thumb mode type
			 * then we are clearly in the wrong path.
			*/
			return (-1);
		}
	}

	tp->ftt_type = dtrace_decode_arm64(instr);

	if (tp->ftt_type == FASTTRAP_T_ARM64_EXCLUSIVE_MEM) {
		kprintf("Detected attempt to place DTrace probe on exclusive memory instruction (pc = 0x%llx); refusing to trace (or exclusive operation could never succeed).\n", pc);
		tp->ftt_type = FASTTRAP_T_INV;
		return (-1);
	}

	if (tp->ftt_type == FASTTRAP_T_INV) {
		/* This is an instruction we either don't recognize or can't instrument */
		printf("dtrace: fasttrap init64: Unrecognized instruction: %08x at %08llx\n", instr, pc);
		return (-1);
	}

	return (0);
}

// These are not exported from vm_map.h.
extern kern_return_t vm_map_write_user(vm_map_t map, void *src_p, vm_map_address_t dst_addr, vm_size_t size);

/* Patches the instructions. Almost like uwrite, but need special instructions on ARM to flush the caches. */
static
int patchInst(proc_t *p, void *buf, user_size_t len, user_addr_t a)
{
	kern_return_t ret;

	ASSERT(p != NULL);
	ASSERT(p->task != NULL);

	task_t task = p->task;

	/*
	 * Grab a reference to the task vm_map_t to make sure
	 * the map isn't pulled out from under us.
	 *
	 * Because the proc_lock is not held at all times on all code
	 * paths leading here, it is possible for the proc to have
	 * exited. If the map is null, fail.
	 */
	vm_map_t map = get_task_map_reference(task);
	if (map) {
		/* Find the memory permissions. */
		uint32_t nestingDepth=999999;
		vm_region_submap_short_info_data_64_t info;
		mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
		mach_vm_address_t address = (mach_vm_address_t)a;
		mach_vm_size_t sizeOfRegion = (mach_vm_size_t)len;

		ret = mach_vm_region_recurse(map, &address, &sizeOfRegion, &nestingDepth, (vm_region_recurse_info_t)&info, &count);
		if (ret != KERN_SUCCESS)
			goto done;

		vm_prot_t reprotect;

		if (!(info.protection & VM_PROT_WRITE)) {
			/* Save the original protection values for restoration later */
			reprotect = info.protection;
			if (info.max_protection & VM_PROT_WRITE) {
				/* The memory is not currently writable, but can be made writable. */
				/* Making it both writable and executable at the same time causes warning on embedded */
				ret = mach_vm_protect (map, (mach_vm_offset_t)a, (mach_vm_size_t)len, 0, (reprotect & ~VM_PROT_EXECUTE) | VM_PROT_WRITE);
			} else {
				/*
				 * The memory is not currently writable, and cannot be made writable. We need to COW this memory.
				 *
				 * Strange, we can't just say "reprotect | VM_PROT_COPY", that fails.
				 */
				ret = mach_vm_protect (map, (mach_vm_offset_t)a, (mach_vm_size_t)len, 0, VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE);
			}

			if (ret != KERN_SUCCESS)
				goto done;

		} else {
			/* The memory was already writable. */
			reprotect = VM_PROT_NONE;
		}

		ret = vm_map_write_user( map,
					 buf,
					 (vm_map_address_t)a,
					 (vm_size_t)len);

		flush_caches();

		if (ret != KERN_SUCCESS)
			goto done;

		if (reprotect != VM_PROT_NONE) {
			ASSERT(reprotect & VM_PROT_EXECUTE);
			ret = mach_vm_protect (map, (mach_vm_offset_t)a, (mach_vm_size_t)len, 0, reprotect);
		}

done:
		vm_map_deallocate(map);
	} else
		ret = KERN_TERMINATED;

	return (int)ret;
}

int
fasttrap_tracepoint_install(proc_t *p, fasttrap_tracepoint_t *tp)
{
	/* The thumb patch is a 2 byte instruction regardless of the size of the original instruction */
	uint32_t instr;
	int size;

	if (proc_is64bit(p)) {
		size = 4;
		instr = FASTTRAP_ARM64_INSTR;
	}
	else {
		size = tp->ftt_thumb ? 2 : 4;
		if (tp->ftt_thumb) {
			*((uint16_t*) &instr) = FASTTRAP_THUMB32_INSTR;
		} else {
			instr = FASTTRAP_ARM32_INSTR;
		}
	}

	if (patchInst(p, &instr, size, tp->ftt_pc) != 0)
		return (-1);

	tp->ftt_installed = 1;

	return (0);
}

int
fasttrap_tracepoint_remove(proc_t *p, fasttrap_tracepoint_t *tp)
{
	/* The thumb patch is a 2 byte instruction regardless of the size of the original instruction */
	uint32_t instr;
	int size;

	if (proc_is64bit(p)) {
		/*
		 * Distinguish between read or write failures and a changed
		 * instruction.
		 */
		size = 4;
		if (uread(p, &instr, size, tp->ftt_pc) != 0)
			goto end;

		if (instr != FASTTRAP_ARM64_INSTR)
			goto end;
	} else {
		/*
		 * Distinguish between read or write failures and a changed
		 * instruction.
		 */
		size = tp->ftt_thumb ? 2 : 4;	
		if (uread(p, &instr, size, tp->ftt_pc) != 0)
			goto end;
	
		if (tp->ftt_thumb) {
			if (*((uint16_t*) &instr) != FASTTRAP_THUMB32_INSTR)
				goto end;
		} else {
			if (instr != FASTTRAP_ARM32_INSTR)
				goto end;
		}
	}

	if (patchInst(p, &tp->ftt_instr, size, tp->ftt_pc) != 0)
		return (-1);

end:
	tp->ftt_installed = 0;

	return (0);
}

static void
fasttrap_return_common(proc_t *p, arm_saved_state_t *regs, user_addr_t pc, user_addr_t new_pc)
{
	pid_t pid = p->p_pid;
	fasttrap_tracepoint_t *tp;
	fasttrap_bucket_t *bucket;
	fasttrap_id_t *id;
	lck_mtx_t *pid_mtx;
	int retire_tp = 1;
	pid_mtx = &cpu_core[CPU->cpu_id].cpuc_pid_lock;
	lck_mtx_lock(pid_mtx);
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid, pc)];

	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
	    	tp->ftt_proc->ftpc_acount != 0)
			break;
	}

	/*
	 * Don't sweat it if we can't find the tracepoint again; unlike
	 * when we're in fasttrap_pid_probe(), finding the tracepoint here
	 * is not essential to the correct execution of the process.
 	 */
	if (tp == NULL) {
		lck_mtx_unlock(pid_mtx);
		return;
	}

	for (id = tp->ftt_retids; id != NULL; id = id->fti_next) {
		fasttrap_probe_t *probe = id->fti_probe;
		/*
		 * If there's a branch that could act as a return site, we
		 * need to trace it, and check here if the program counter is
		 * external to the function.
		 */
		if (is_saved_state32(regs))
		{
			if (tp->ftt_type != FASTTRAP_T_LDM_PC &&
			    tp->ftt_type != FASTTRAP_T_POP_PC &&
			    new_pc - probe->ftp_faddr < probe->ftp_fsize)
				continue;
		}
		else {
			/* ARM64_TODO  - check for FASTTRAP_T_RET */
			if ((tp->ftt_type != FASTTRAP_T_ARM64_RET) &&
				new_pc - probe->ftp_faddr < probe->ftp_fsize)
				continue;
		}
		if (probe->ftp_prov->ftp_provider_type == DTFTP_PROVIDER_ONESHOT) {
			uint8_t already_triggered = atomic_or_8(&probe->ftp_triggered, 1);
			if (already_triggered) {
				continue;
			}
		}
		/*
		 * If we have at least one probe associated that
		 * is not a oneshot probe, don't remove the
		 * tracepoint
		 */
		else {
			retire_tp = 0;
		}

#ifndef CONFIG_EMBEDDED
		if (ISSET(current_proc()->p_lflag, P_LNOATTACH)) {
			dtrace_probe(dtrace_probeid_error, 0 /* state */, id->fti_probe->ftp_id,
				     1 /* ndx */, -1 /* offset */, DTRACEFLT_UPRIV);
#else
		if (FALSE) {
#endif
		} else {
			if (is_saved_state32(regs)) {
				dtrace_probe(probe->ftp_id,
						 pc - id->fti_probe->ftp_faddr,
				                 saved_state32(regs)->r[0], 0, 0, 0);
			} else {
				dtrace_probe(probe->ftp_id,
						 pc - id->fti_probe->ftp_faddr,
						 saved_state64(regs)->x[0], 0, 0, 0);
			}
		}
	}
	if (retire_tp) {
		fasttrap_tracepoint_retire(p, tp);
	}

	lck_mtx_unlock(pid_mtx);
}

static void
fasttrap_sigsegv(proc_t *p, uthread_t t, user_addr_t addr, arm_saved_state_t *regs)
{
	/* TODO: This function isn't implemented yet. In debug mode, panic the system to
	 * find out why we're hitting this point. In other modes, kill the process.
	 */
#if DEBUG
#pragma unused(p,t,addr,arm_saved_state)
	panic("fasttrap: sigsegv not yet implemented");
#else
#pragma unused(p,t,addr)
	/* Kill the process */
	set_saved_state_pc(regs, 0);
#endif

#if 0
	proc_lock(p);

	/* Set fault address and mark signal */
	t->uu_code = addr;
	t->uu_siglist |= sigmask(SIGSEGV);

	/* 
	 * XXX These two line may be redundant; if not, then we need
	 * XXX to potentially set the data address in the machine
	 * XXX specific thread state structure to indicate the address.
	 */         
	t->uu_exception = KERN_INVALID_ADDRESS;         /* SIGSEGV */
	t->uu_subcode = 0;      /* XXX pad */
                
	proc_unlock(p); 
                                     
	/* raise signal */
	signal_setast(t->uu_context.vc_thread);
#endif
}

static void
fasttrap_usdt_args32(fasttrap_probe_t *probe, arm_saved_state32_t *regs32, int argc,
    uint64_t *argv)
{
	int i, x, cap = MIN(argc, probe->ftp_nargs);

	for (i = 0; i < cap; i++) {
		x = probe->ftp_argmap[i];

		/* Up to 4 args are passed in registers on arm */
		if (x < 4) {
			argv[i] = regs32->r[x];
		} else {
			uint32_t arg;
			fasttrap_fuword32_noerr(regs32->sp + (x - 4) * sizeof(uint32_t), &arg);

			argv[i] = arg;
		}
	}

	for (; i < argc; i++) {
		argv[i] = 0;
	}
}

static void
fasttrap_usdt_args64(fasttrap_probe_t *probe, arm_saved_state64_t *regs64, int argc,
    uint64_t *argv)
{
	int i, x, cap = MIN(argc, probe->ftp_nargs);

	for (i = 0; i < cap; i++) {
		x = probe->ftp_argmap[i];

		/* Up to 8 args are passed in registers on arm64 */
		if (x < 8) {
			argv[i] = regs64->x[x];
		} else {
			fasttrap_fuword64_noerr(regs64->sp + (x - 8) * sizeof(uint64_t), &argv[i]);
		}
	}

	for (; i < argc; i++) {
		argv[i] = 0;
	}	
}

static int condition_true(int cond, int cpsr)
{
	int taken = 0;
	int zf = (cpsr & PSR_ZF) ? 1 : 0,
	    nf = (cpsr & PSR_NF) ? 1 : 0,
	    cf = (cpsr & PSR_CF) ? 1 : 0,
	    vf = (cpsr & PSR_VF) ? 1 : 0;

	switch(cond) {
		case 0: taken = zf; break;
		case 1: taken = !zf; break;
		case 2: taken = cf; break;
		case 3: taken = !cf; break;
		case 4: taken = nf; break;
		case 5: taken = !nf; break;
		case 6: taken = vf; break;
		case 7: taken = !vf; break;
		case 8: taken = (cf && !zf); break;
		case 9: taken = (!cf || zf); break;
		case 10: taken = (nf == vf); break;
		case 11: taken = (nf != vf); break;
		case 12: taken = (!zf && (nf == vf)); break;
		case 13: taken = (zf || (nf != vf)); break;
		case 14: taken = 1; break;
		case 15: taken = 1; break; /* always "true" for ARM, unpredictable for THUMB. */
	}

	return taken;
}

static void set_thumb_flag(arm_saved_state32_t *regs32, user_addr_t pc)
{
	if (pc & 1) {
		regs32->cpsr |= PSR_TF;
	} else {
		regs32->cpsr &= ~PSR_TF;
	}
}

static int 
fasttrap_pid_probe_thumb_state_valid(arm_saved_state32_t *state32, fasttrap_tracepoint_t *tp)
{
	uint32_t cpsr = state32->cpsr;
	uint32_t itstate = GETITSTATE(cpsr);

	/* If in IT block, make sure it's the last statement in the block */
	if ((itstate != 0) && !ISLASTINIT(itstate)) {
		printf("dtrace: fasttrap: Tried to trace instruction %08x at %08x but not at end of IT block\n",
				(tp->ftt_thumb && dtrace_instr_size(tp->ftt_instr,tp->ftt_thumb) == 2) ? tp->ftt_instr1 : tp->ftt_instr, state32->pc);
		return 0;
	}

	if (!(cpsr & PSR_TF)) {
		return 0;
	}

	return 1;
}

static int  
fasttrap_get_condition_code(arm_saved_state32_t *regs32, fasttrap_tracepoint_t *tp)
{
	/* Default to always execute */
	int condition_code = 0xE; 
	if (tp->ftt_thumb) {
		uint32_t itstate = GETITSTATE(regs32->cpsr);
		if (itstate != 0) { 
			/* In IT block, make sure it's the last statement in the block */
			assert(ISLASTINIT(itstate));
			condition_code = itstate >> 4;
		}    
	} else {
		condition_code = ARM_CONDCODE(tp->ftt_instr);
	}    

	return condition_code;
}

static void 
fasttrap_pid_probe_handle_patched_instr32(arm_saved_state_t *state, fasttrap_tracepoint_t *tp, uthread_t uthread, 
		proc_t *p, uint_t is_enabled, int *was_simulated)
{
	arm_saved_state32_t *regs32 = saved_state32(state);
	uint32_t new_pc = 0;
	uint32_t pc = regs32->pc;
	int instr_size;
	int condition_code;

	*was_simulated = 1;

	/*
	 * If there's an is-enabled probe connected to this tracepoint it
	 * means that there was a 'eor r0,r0,r0'
	 * instruction that was placed there by DTrace when the binary was
	 * linked. As this probe is, in fact, enabled, we need to stuff 1
	 * into R0. Accordingly, we can bypass all the instruction
	 * emulation logic since we know the inevitable result. It's possible
	 * that a user could construct a scenario where the 'is-enabled'
	 * probe was on some other instruction, but that would be a rather
	 * exotic way to shoot oneself in the foot.
	 */
	
	if (is_enabled) {
		regs32->r[0] = 1;
		new_pc = regs32->pc + (tp->ftt_thumb ? 2 : 4);
		goto done;
	}

	/* For USDT probes, bypass all the emulation logic for the nop instruction */
	if ((tp->ftt_thumb && IS_THUMB32_NOP(THUMB_INSTR(tp->ftt_instr))) ||
	    (!tp->ftt_thumb && IS_ARM32_NOP(tp->ftt_instr))) {
		new_pc = regs32->pc + (tp->ftt_thumb ? 2 : 4);
		goto done;
	}

	condition_code = fasttrap_get_condition_code(regs32, tp);
	instr_size = dtrace_instr_size(tp->ftt_instr,tp->ftt_thumb);

	switch (tp->ftt_type) {
		case FASTTRAP_T_MOV_PC_REG:
		case FASTTRAP_T_CPY_PC:
		{
			if (!condition_true(condition_code, regs32->cpsr)) {
				new_pc = pc + instr_size;
				break;
			}

			int rm;
			if (tp->ftt_thumb) {
				rm = THUMB16_HRM(tp->ftt_instr1);
			} else {
				rm = tp->ftt_instr & 0xF;
			}
			new_pc = regs32->r[rm];

			/* This instruction does not change the Thumb state */

			break;
		}

		case FASTTRAP_T_STM_LR:
		case FASTTRAP_T_PUSH_LR:
		{
			/*
			 * This is a very common case, so we want to emulate this instruction if
			 * possible. However, on a push, it is possible that we might reach the end
			 * of a page and have to allocate a new page. Most of the time this will not
			 * happen, and we know that the push instruction can store at most 16 words,
			 * so check to see if we are far from the boundary, and if so, emulate. This
			 * can be made more aggressive by checking the actual number of words being
			 * pushed, but we won't do that for now.
			 *
			 * Some of the same issues that apply to POP_PC probably apply here also.
			 */

			int reglist;
			int ret;
			uint32_t base;

			if (!condition_true(condition_code, regs32->cpsr)) {
				new_pc = pc + instr_size;
				break;
			}

			base = regs32->sp;
			if (((base-16*4) >> PAGE_SHIFT) != (base >> PAGE_SHIFT)) {
				/* Crosses the page boundary, go to emulation */
				goto instr_emulate;
			}

			if (tp->ftt_thumb) {
				if (instr_size == 4) {
					/* We know we have to push lr, never push sp or pc */
					reglist = tp->ftt_instr2 & 0x1FFF;
				} else {
					reglist = tp->ftt_instr1 & 0xFF;
				}
			} else {
				/* We know we have to push lr, never push sp or pc */
				reglist = tp->ftt_instr & 0x1FFF;
			}

			/* Push the link register */
			base -= 4;
			ret = fasttrap_suword32(base, regs32->lr);
			if (ret == -1) {
				fasttrap_sigsegv(p, uthread, (user_addr_t) base, state);
				new_pc = regs32->pc;
				break;
			}

			/* Start pushing from $r12 */
			int regmask = 1 << 12;
			int regnum = 12;

			while (regmask) {
				if (reglist & regmask) {
					base -= 4;
					ret = fasttrap_suword32(base, regs32->r[regnum]);
					if (ret == -1) {
						fasttrap_sigsegv(p, uthread, (user_addr_t) base, state);
						new_pc = regs32->pc;
						break;
					}
				}
				regmask >>= 1;
				regnum--;
			}

			regs32->sp = base;

			new_pc = pc + instr_size;

			break;
		}


		case FASTTRAP_T_LDM_PC:
		case FASTTRAP_T_POP_PC:
		{
			/* TODO Two issues that will eventually need to be resolved:
			 *
			 * 1. Understand what the hardware does if we have to segfault (data abort) in
			 * the middle of a load multiple. We currently don't have a working segfault
			 * handler anyway, and with no swapfile we should never segfault on this load.
			 * If we do, we'll just kill the process by setting the pc to 0.
			 *
			 * 2. The emulation is no longer atomic. We currently only emulate pop for
			 * function epilogues, and so we should never have a race here because one
			 * thread should never be trying to manipulate another thread's stack frames.
			 * That is almost certainly a bug in the program.
			 * 
			 * This will need to be fixed if we ever:
			 *   a. Ship dtrace externally, as this could be a potential attack vector
			 *   b. Support instruction level tracing, as we might then pop/ldm non epilogues.
			 *
			 */

			/* Assume ldmia! sp/pop ... pc */

			int regnum = 0, reglist;
			int ret;
			uint32_t base;

			if (!condition_true(condition_code, regs32->cpsr)) {
				new_pc = pc + instr_size;
				break;
			}

			if (tp->ftt_thumb) {
				if (instr_size == 4) {
					/* We know we have to load the pc, don't do it twice */
					reglist = tp->ftt_instr2 & 0x7FFF;
				} else {
					reglist = tp->ftt_instr1 & 0xFF;
				}
			} else {
				/* We know we have to load the pc, don't do it twice */
				reglist = tp->ftt_instr & 0x7FFF;
			}

			base = regs32->sp;
			while (reglist) {
				if (reglist & 1) {
					ret = fasttrap_fuword32((user_addr_t)base, &regs32->r[regnum]);
					if (ret == -1) {
						fasttrap_sigsegv(p, uthread, (user_addr_t) base, state);
						new_pc = regs32->pc;
						break;
					}
					base += 4;
				}
				reglist >>= 1;
				regnum++;
			}

			ret = fasttrap_fuword32((user_addr_t)base, &new_pc);
			if (ret == -1) {
				fasttrap_sigsegv(p, uthread, (user_addr_t) base, state);
				new_pc = regs32->pc;
				break;
			}
			base += 4;

			regs32->sp = base;

			set_thumb_flag(regs32, new_pc);

			break;
		}

		case FASTTRAP_T_CB_N_Z:
		{
			/* Thumb mode instruction, and not permitted in IT block, so skip the condition code check */
			int rn = tp->ftt_instr1 & 0x7;
			int offset = (((tp->ftt_instr1 & 0x00F8) >> 2) | ((tp->ftt_instr1 & 0x0200) >> 3)) + 4;
			int nonzero = tp->ftt_instr1 & 0x0800;
			if (!nonzero != !(regs32->r[rn] == 0)) {
				new_pc = pc + offset;
			} else {
				new_pc = pc + instr_size;
			}
			break;
		}

		case FASTTRAP_T_B_COND:
		{
			/* Use the condition code in the instruction and ignore the ITSTATE */

			int code, offset;
			if (tp->ftt_thumb) {
				if (instr_size == 4) {
					code = (tp->ftt_instr1 >> 6) & 0xF;
					if (code == 14 || code == 15) {
						panic("fasttrap: Emulation of invalid branch");
					}
					int S = (tp->ftt_instr1 >> 10) & 1,
					    J1 = (tp->ftt_instr2 >> 13) & 1,
					    J2 = (tp->ftt_instr2 >> 11) & 1;
					offset = 4 + SIGNEXTEND(
					    (S << 20) | (J2 << 19) | (J1 << 18) |
					    ((tp->ftt_instr1 & 0x003F) << 12) |
					    ((tp->ftt_instr2 & 0x07FF) << 1),
					    21);
				} else {
					code = (tp->ftt_instr1 >> 8) & 0xF;
					if (code == 14 || code == 15) {
						panic("fasttrap: Emulation of invalid branch");
					}
					offset = 4 + (SIGNEXTEND(tp->ftt_instr1 & 0xFF, 8) << 1);
				}
			} else {
				code = ARM_CONDCODE(tp->ftt_instr);
				if (code == 15) {
					panic("fasttrap: Emulation of invalid branch");
				}
				offset = 8 + (SIGNEXTEND(tp->ftt_instr & 0x00FFFFFF, 24) << 2);
			}

			if (condition_true(code, regs32->cpsr)) {
				new_pc = pc + offset;
			} else {
				new_pc = pc + instr_size;
			}

			break;
		}

		case FASTTRAP_T_B_UNCOND:
		{
			int offset;

			/* Unconditional branches can only be taken from Thumb mode */
			/* (This is different from an ARM branch with condition code "always") */
			ASSERT(tp->ftt_thumb == 1);

			if (!condition_true(condition_code, regs32->cpsr)) {
				new_pc = pc + instr_size;
				break;
			}

			if (instr_size == 4) {
				int S = (tp->ftt_instr1 >> 10) & 1,
				    J1 = (tp->ftt_instr2 >> 13) & 1,
				    J2 = (tp->ftt_instr2 >> 11) & 1;
				int I1 = (J1 != S) ? 0 : 1, I2 = (J2 != S) ? 0 : 1;
				offset = 4 + SIGNEXTEND(
				    (S << 24) | (I1 << 23) | (I2 << 22) |
				    ((tp->ftt_instr1 & 0x03FF) << 12) |
				    ((tp->ftt_instr2 & 0x07FF) << 1),
				    25);
			} else {
				uint32_t instr1 = tp->ftt_instr1;
				offset = 4 + (SIGNEXTEND(instr1 & 0x7FF, 11) << 1);
			}

			new_pc = pc + offset;

			break;
		}

		case FASTTRAP_T_BX_REG:
		{
			int reg;

			if (!condition_true(condition_code, regs32->cpsr)) {
				new_pc = pc + instr_size;
				break;
			}

			if (tp->ftt_thumb) {
				reg = THUMB16_HRM(tp->ftt_instr1);
			} else {
				reg = ARM_RM(tp->ftt_instr);
			}
			new_pc = regs32->r[reg];
			set_thumb_flag(regs32, new_pc);

			break;
		}

		case FASTTRAP_T_LDR_PC_IMMED:
		case FASTTRAP_T_VLDR_PC_IMMED:
			/* Handle these instructions by replacing the PC in the instruction with another
			 * register. They are common, so we'd like to support them, and this way we do so
			 * without any risk of having to simulate a segfault.
			 */

			/* Fall through */

		instr_emulate:
		case FASTTRAP_T_COMMON:
		{
			user_addr_t addr;
			uint8_t scratch[32];
			uint_t i = 0;
			fasttrap_instr_t emul_instr;
			emul_instr.instr32 = tp->ftt_instr;
			int emul_instr_size;

			/*
			 * Unfortunately sometimes when we emulate the instruction and have to replace the
			 * PC, there is no longer a thumb mode equivalent. We end up having to run the
			 * modified instruction in ARM mode. We use this variable to keep track of which
			 * mode we should emulate in. We still use the original variable to determine
			 * what mode to return to.
			 */
			uint8_t emul_thumb = tp->ftt_thumb;
			int save_reg = -1;
			uint32_t save_val = 0;

			/*
			 * Dealing with condition codes and emulation:
			 * We can't just uniformly do a condition code check here because not all instructions
			 * have condition codes. We currently do not support an instruction by instruction trace,
			 * so we can assume that either: 1. We are executing a Thumb instruction, in which case
			 * we either are not in an IT block and should execute always, or we are last in an IT
			 * block. Either way, the traced instruction will run correctly, and we won't have any
			 * problems when we return to the original code, because we will no longer be in the IT
			 * block. 2. We are executing an ARM instruction, in which case we are ok as long as
			 * we don't attempt to change the condition code.
			 */
			if (tp->ftt_type == FASTTRAP_T_LDR_PC_IMMED) {
				/* We know we always have a free register (the one we plan to write the
				 * result value to!). So we'll replace the pc with that one.
				 */
				int new_reg;
				if (tp->ftt_thumb) {
					/* Check to see if thumb or thumb2 */
					if (instr_size == 2) {
						/*
						 * Sadness. We need to emulate this instruction in ARM mode
						 * because it has an 8 bit immediate offset. Instead of having
						 * to deal with condition codes in the ARM instruction, we'll
						 * just check the condition and abort if the condition is false.
						 */
						if (!condition_true(condition_code, regs32->cpsr)) {
							new_pc = pc + instr_size;
							break;
						}

						new_reg = (tp->ftt_instr1 >> 8) & 0x7;
						regs32->r[new_reg] = ALIGNADDR(regs32->pc + 4, 2);
						emul_thumb = 0;
						emul_instr.instr32 = 0xE5900000 | (new_reg << 16) | (new_reg << 12) | ((tp->ftt_instr1 & 0xFF) << 2);
					} else {
						/* Thumb2. Just replace the register. */
						new_reg = (tp->ftt_instr2 >> 12) & 0xF;
						regs32->r[new_reg] = ALIGNADDR(regs32->pc + 4, 2);
						emul_instr.instr16.instr1 &= ~0x000F;
						emul_instr.instr16.instr1 |= new_reg;
					}
				} else {
					/* ARM. Just replace the register. */
					new_reg = (tp->ftt_instr >> 12) & 0xF;
					regs32->r[new_reg] = ALIGNADDR(regs32->pc + 8,2);
					emul_instr.instr32 &= ~0x000F0000;
					emul_instr.instr32 |= new_reg << 16;
				}
			} else if (tp->ftt_type == FASTTRAP_T_VLDR_PC_IMMED) {
				/* This instruction only uses one register, and if we're here, we know
				 * it must be the pc. So we'll just replace it with R0.
				 */
				save_reg = 0;
				save_val = regs32->r[0];
				regs32->r[save_reg] = ALIGNADDR(regs32->pc + (tp->ftt_thumb ? 4 : 8), 2);
				if (tp->ftt_thumb) {
					emul_instr.instr16.instr1 &= ~0x000F;
				} else {
					emul_instr.instr32 &= ~0x000F0000;
				}
			}

			emul_instr_size = dtrace_instr_size(emul_instr.instr32, emul_thumb);

			/*
			 * At this point:
			 *   tp->ftt_thumb = thumb mode of original instruction
			 *   emul_thumb = thumb mode for emulation
			 *   emul_instr = instruction we are using to emulate original instruction
			 *   emul_instr_size = size of emulating instruction
			 */

			addr = uthread->t_dtrace_scratch->addr;

			if (addr == 0LL) {
				fasttrap_sigtrap(p, uthread, pc); // Should be killing target proc
				new_pc = pc;
				break;
			}

			uthread->t_dtrace_scrpc = addr;
			if (emul_thumb) {
				/*
				 * No way to do an unconditional branch in Thumb mode, shove the address
				 * onto the user stack and go to the next location with a pop. This can
				 * segfault if this push happens to cross a stack page, but that's ok, since
				 * we are running in userland, and the kernel knows how to handle userland
				 * stack expansions correctly.
				 *
				 * Layout of scratch space for Thumb mode:
				 *   Emulated instruction
				 *   ldr save_reg, [pc, #16] (if necessary, restore any register we clobbered)
				 *   push { r0, r1 }
				 *   ldr r0, [pc, #4]
				 *   str r0, [sp, #4]
				 *   pop { r0, pc }
				 *   Location we should return to in original program
				 *   Saved value of clobbered register (if necessary)
				 */

				bcopy(&emul_instr, &scratch[i], emul_instr_size); i += emul_instr_size;

				if (save_reg != -1) {
					uint16_t restore_inst = 0x4803;
					restore_inst |= (save_reg & 0x7) << 8;
					SET16(scratch+i, restore_inst); i += 2;		// ldr reg, [pc , #16]
				}

				SET16(scratch+i, 0xB403); i += 2;			// push { r0, r1 }
				SET16(scratch+i, 0x4801); i += 2;			// ldr r0, [pc, #4]
				SET16(scratch+i, 0x9001); i += 2;			// str r0, [sp, #4]
				SET16(scratch+i, 0xBD01); i += 2;			// pop { r0, pc }

				if (i % 4) {
					SET16(scratch+i, 0); i += 2;			// padding - saved 32 bit words must be aligned
				}
				SET32(scratch+i, pc + instr_size + (tp->ftt_thumb ? 1 : 0)); i += 4;	// Return address
				if (save_reg != -1) {
					SET32(scratch+i, save_val); i += 4;		// saved value of clobbered register
				}

				uthread->t_dtrace_astpc = addr + i;
				bcopy(&emul_instr, &scratch[i], emul_instr_size); i += emul_instr_size;
				SET16(scratch+i, FASTTRAP_THUMB32_RET_INSTR); i += 2;
			} else {
				/*
				 * Layout of scratch space for ARM mode:
				 *   Emulated instruction
				 *   ldr save_reg, [pc, #12] (if necessary, restore any register we clobbered)
				 *   ldr pc, [pc, #4]
				 *   Location we should return to in original program
				 *   Saved value of clobbered register (if necessary)
				 */

				bcopy(&emul_instr, &scratch[i], emul_instr_size); i += emul_instr_size;

				if (save_reg != -1) {
					uint32_t restore_inst = 0xE59F0004;
					restore_inst |= save_reg << 12;
					SET32(scratch+i, restore_inst); i += 4;		// ldr reg, [pc, #12]
				}
				SET32(scratch+i, 0xE51FF004); i += 4;			// ldr pc, [pc, #4]

				SET32(scratch+i, pc + instr_size + (tp->ftt_thumb ? 1 : 0)); i += 4;	// Return address
				if (save_reg != -1) {
					SET32(scratch+i, save_val); i += 4;		// Saved value of clobbered register
				}

				uthread->t_dtrace_astpc = addr + i;
				bcopy(&emul_instr, &scratch[i], emul_instr_size); i += emul_instr_size;
				SET32(scratch+i, FASTTRAP_ARM32_RET_INSTR); i += 4;
			}

			if (patchInst(p, scratch, i, uthread->t_dtrace_scratch->write_addr) != KERN_SUCCESS) {
				fasttrap_sigtrap(p, uthread, pc);
				new_pc = pc;
				break;
			}

			if (tp->ftt_retids != NULL) {
				uthread->t_dtrace_step = 1;
				uthread->t_dtrace_ret = 1;
				new_pc = uthread->t_dtrace_astpc + (emul_thumb ? 1 : 0);
			} else {
				new_pc = uthread->t_dtrace_scrpc + (emul_thumb ? 1 : 0);
			}

			uthread->t_dtrace_pc = pc;
			uthread->t_dtrace_npc = pc + instr_size;
			uthread->t_dtrace_on = 1;
			*was_simulated = 0;
			set_thumb_flag(regs32, new_pc);
			break;
		}

		default:
			panic("fasttrap: mishandled an instruction");
	}
done:
	set_saved_state_pc(state, new_pc);	
	return;
}

/*
 * Copy out an instruction for execution in userland.
 * Trap back to kernel to handle return to original flow of execution, because
 * direct branches don't have sufficient range (+/- 128MB) and we 
 * cannot clobber a GPR.  Note that we have to specially handle PC-rel loads/stores
 * as well, which have range +/- 1MB (convert to an indirect load).  Instruction buffer
 * layout:
 *
 *    [ Thunked instruction sequence ]
 *    [ Trap for return to original code and return probe handling ]
 *
 * This *does* make it impossible for an ldxr/stxr pair to succeed if we trace on or between
 * them... may need to get fancy at some point.
 */
static void
fasttrap_pid_probe_thunk_instr64(arm_saved_state_t *state, fasttrap_tracepoint_t *tp, proc_t *p, uthread_t uthread,
		const uint32_t *instructions, uint32_t num_instrs, user_addr_t *pc_out)
{
	uint32_t local_scratch[8];
	user_addr_t pc = get_saved_state_pc(state);
	user_addr_t user_scratch_area;

	assert(num_instrs < 8);

	bcopy(instructions, local_scratch, num_instrs * sizeof(uint32_t));
	local_scratch[num_instrs] = FASTTRAP_ARM64_RET_INSTR;

	uthread->t_dtrace_astpc = uthread->t_dtrace_scrpc = uthread->t_dtrace_scratch->addr;
	user_scratch_area = uthread->t_dtrace_scratch->write_addr;

	if (user_scratch_area == (user_addr_t)0) {
		fasttrap_sigtrap(p, uthread, pc); // Should be killing target proc
		*pc_out = pc;
		return;
	}

	if (patchInst(p, local_scratch, (num_instrs + 1) * sizeof(uint32_t), user_scratch_area) != KERN_SUCCESS) {
		fasttrap_sigtrap(p, uthread, pc);
		*pc_out = pc;
		return;
	}

	/* We're stepping (come back to kernel to adjust PC for return to regular code). */
	uthread->t_dtrace_step = 1;

	/* We may or may not be about to run a return probe (but we wouldn't thunk ret lr)*/
	uthread->t_dtrace_ret = (tp->ftt_retids != NULL);
	assert(tp->ftt_type != FASTTRAP_T_ARM64_RET);

	/* Set address of instruction we've patched */
	uthread->t_dtrace_pc = pc;

	/* Any branch would be emulated, next instruction should be one ahead */
	uthread->t_dtrace_npc = pc + 4;

	/* We are certainly handling a probe */
	uthread->t_dtrace_on = 1;

	/* Let's jump to the scratch area */
	*pc_out = uthread->t_dtrace_scratch->addr;
}

/*
 * Sign-extend bit "sign_bit_index" out to bit 64.
 */
static int64_t
sign_extend(int64_t input, uint32_t sign_bit_index) 
{
	assert(sign_bit_index < 63);
	if (input & (1ULL << sign_bit_index)) {
		/* All 1's & ~[1's from 0 to sign bit] */
		input |= ((~0ULL) & ~((1ULL << (sign_bit_index + 1)) - 1ULL));
	}

	return input;
}

/*
 * Handle xzr vs. sp, fp, lr, etc.  Will *not* read the SP.
 */
static uint64_t 
get_saved_state64_regno(arm_saved_state64_t *regs64, uint32_t regno, int use_xzr)
{
	/* Set PC to register value */
	switch (regno) {
		case 29:
			return regs64->fp;
		case 30:
			return regs64->lr;
		case 31:
			/* xzr */
			if (use_xzr) {
				return 0;
			} else {
				return regs64->sp;
			}
		default:
			return regs64->x[regno];
	}
}

static void 
set_saved_state64_regno(arm_saved_state64_t *regs64, uint32_t regno, int use_xzr, register_t value)
{
	/* Set PC to register value */
	switch (regno) {
		case 29:
			regs64->fp = value;
			break;
		case 30:
			regs64->lr = value;
			break;
		case 31:
			if (!use_xzr) {
				regs64->sp = value;
			}
			break;
		default:
			regs64->x[regno] = value;
			break;
	}
}

/* 
 * Common operation: extract sign-extended PC offset from instruction
 * Left-shifts result by two bits.
 */
static uint64_t
extract_address_literal_sign_extended(uint32_t instr, uint32_t base, uint32_t numbits)
{
	uint64_t offset;

	offset = (instr >> base) & ((1 << numbits) - 1);
	offset = sign_extend(offset, numbits - 1);
	offset = offset << 2;

	return offset;
}

static void
do_cbz_cnbz(arm_saved_state64_t *regs64, uint32_t regwidth, uint32_t instr, int is_cbz, user_addr_t *pc_out)
{
	uint32_t regno;
	uint64_t regval;
	uint64_t offset;

	/* Extract register */
	regno = (instr & 0x1f);
	assert(regno <= 31);
	regval = get_saved_state64_regno(regs64, regno, 1);

	/* Control for size */
	if (regwidth == 32) {
		regval &= 0xFFFFFFFFULL;
	}

	/* Extract offset */
	offset = extract_address_literal_sign_extended(instr, 5, 19); 

	/* Do test */
	if ((is_cbz && regval == 0) || ((!is_cbz) && regval != 0)) {
		/* Set PC from label */
		*pc_out = regs64->pc + offset;
	} else {
		/* Advance PC */
		*pc_out = regs64->pc + 4;
	}
}

static void
do_tbz_tbnz(arm_saved_state64_t *regs64, uint32_t instr, int is_tbz, user_addr_t *pc_out)
{
	uint64_t offset, regval;
	uint32_t bit_index, b5, b40, regno, bit_set;

	/* Compute offset */
	offset = extract_address_literal_sign_extended(instr, 5, 14);

	/* Extract bit index */
	b5 = (instr >> 31);
	b40 = ((instr >> 19) & 0x1f);
	bit_index = (b5 << 5) | b40;
	assert(bit_index <= 63);

	/* Extract register */
	regno = (instr & 0x1f);
	assert(regno <= 31);
	regval = get_saved_state64_regno(regs64, regno, 1);

	/* Test bit */
	bit_set = ((regval & (1 << bit_index)) != 0);

	if ((is_tbz && (!bit_set)) || ((!is_tbz) && bit_set)) {
		/* Branch: unsigned addition so overflow defined */
		*pc_out = regs64->pc + offset;
	} else {
		/* Advance PC */
		*pc_out = regs64->pc + 4;
	}
}


static void
fasttrap_pid_probe_handle_patched_instr64(arm_saved_state_t *state, fasttrap_tracepoint_t *tp __unused, uthread_t uthread, 
		proc_t *p, uint_t is_enabled, int *was_simulated)
{
	int res1, res2;
	arm_saved_state64_t *regs64 = saved_state64(state);
	uint32_t instr = tp->ftt_instr;
	user_addr_t new_pc = 0;
	
	/* Neon state should be threaded throw, but hack it until we have better arm/arm64 integration */
	arm_neon_saved_state64_t *ns64 = &(get_user_neon_regs(uthread->uu_thread)->ns_64);

	/* is-enabled probe: set x0 to 1 and step forwards */
	if (is_enabled) {
		regs64->x[0] = 1;
		set_saved_state_pc(state, regs64->pc + 4);
		return;
	}

        /* For USDT probes, bypass all the emulation logic for the nop instruction */
	if (IS_ARM64_NOP(tp->ftt_instr)) {
		set_saved_state_pc(state, regs64->pc + 4);
		return;
	}
	

	/* Only one of many cases in the switch doesn't simulate */
	switch(tp->ftt_type) {
		/* 
		 * Function entry: emulate for speed.
		 * stp fp, lr, [sp, #-16]!
		 */
		case FASTTRAP_T_ARM64_STANDARD_FUNCTION_ENTRY:
		{
			/* Store values to stack */
			res1 = fasttrap_suword64(regs64->sp - 16, regs64->fp);
			res2 = fasttrap_suword64(regs64->sp - 8, regs64->lr);
			if (res1 != 0 || res2 != 0) {
				fasttrap_sigsegv(p, uthread, regs64->sp - (res1 ? 16 : 8), state);
				new_pc = regs64->pc; /* Bit of a hack */
				break;
			}

			/* Move stack pointer */
			regs64->sp -= 16;

			/* Move PC forward */
			new_pc = regs64->pc + 4;
			*was_simulated = 1;
			break;
		}

		/* 
		 * PC-relative loads/stores: emulate for correctness.   
		 * All loads are 32bits or greater (no need to handle byte or halfword accesses).
		 *	LDR Wt, addr
		 *	LDR Xt, addr
		 *	LDRSW Xt, addr
		 *
		 * 	LDR St, addr
		 * 	LDR Dt, addr
		 * 	LDR Qt, addr
		 * 	PRFM label -> becomes a NOP
		 */
		case FASTTRAP_T_ARM64_LDR_S_PC_REL:
		case FASTTRAP_T_ARM64_LDR_W_PC_REL:
		case FASTTRAP_T_ARM64_LDR_D_PC_REL:
		case FASTTRAP_T_ARM64_LDR_X_PC_REL:
		case FASTTRAP_T_ARM64_LDR_Q_PC_REL:
		case FASTTRAP_T_ARM64_LDRSW_PC_REL:
		{
			uint64_t offset;
			uint32_t valsize, regno;
			user_addr_t address;
			union {
				uint32_t val32;
				uint64_t val64;
				uint128_t val128;
			} value;

			/* Extract 19-bit offset, add to pc */
			offset = extract_address_literal_sign_extended(instr, 5, 19);
			address = regs64->pc + offset;

			/* Extract destination register */
			regno = (instr & 0x1f);
			assert(regno <= 31);

			/* Read value of desired size from memory */
			switch (tp->ftt_type) {
				case FASTTRAP_T_ARM64_LDR_S_PC_REL:
				case FASTTRAP_T_ARM64_LDR_W_PC_REL:
				case FASTTRAP_T_ARM64_LDRSW_PC_REL:
					valsize = 4;
					break;
				case FASTTRAP_T_ARM64_LDR_D_PC_REL:
				case FASTTRAP_T_ARM64_LDR_X_PC_REL:
					valsize = 8;
					break;
				case FASTTRAP_T_ARM64_LDR_Q_PC_REL:
					valsize = 16;
					break;
				default:
					panic("Should never get here!");
					valsize = -1;
					break;
			}

			if (copyin(address, &value, valsize) != 0) {
				fasttrap_sigsegv(p, uthread, address, state);
				new_pc = regs64->pc; /* Bit of a hack, we know about update in fasttrap_sigsegv() */
				break;
			}

			/* Stash in correct register slot */
			switch (tp->ftt_type) {
				case FASTTRAP_T_ARM64_LDR_W_PC_REL:
					set_saved_state64_regno(regs64, regno, 1, value.val32);
					break;
				case FASTTRAP_T_ARM64_LDRSW_PC_REL:
					set_saved_state64_regno(regs64, regno, 1, sign_extend(value.val32, 31));
					break;
				case FASTTRAP_T_ARM64_LDR_X_PC_REL:
					set_saved_state64_regno(regs64, regno, 1, value.val64);
					break;
				case FASTTRAP_T_ARM64_LDR_S_PC_REL:
					ns64->v.s[regno][0] = value.val32;
					break;
				case FASTTRAP_T_ARM64_LDR_D_PC_REL:
					ns64->v.d[regno][0] = value.val64;
					break;
				case FASTTRAP_T_ARM64_LDR_Q_PC_REL:
					ns64->v.q[regno] = value.val128;
					break;
				default:
					panic("Should never get here!");
			}


			/* Move PC forward */
			new_pc = regs64->pc + 4;
			*was_simulated = 1;
			break;

		}

		case FASTTRAP_T_ARM64_PRFM:
		{
			/* Becomes a NOP (architecturally permitted).  Just move PC forward */
			new_pc = regs64->pc + 4;
			*was_simulated = 1;
			break;
		}

		/*
		 * End explicit memory accesses.
		 */

		/* 
		 * Branches: parse condition codes if needed, emulate for correctness and
		 * in the case of the indirect branches, convenience
		 * 	B.cond
		 * 	CBNZ Wn, label
		 * 	CBNZ Xn, label
		 * 	CBZ Wn, label
		 * 	CBZ Xn, label
		 * 	TBNZ, Xn|Wn, #uimm16, label
		 * 	TBZ, Xn|Wn, #uimm16, label
		 *	
		 * 	B label
		 * 	BL label
		 *	
		 *	BLR Xm
		 *	BR Xm
		 *	RET Xm
		 */
		case FASTTRAP_T_ARM64_B_COND:
		{
			int cond;

			/* Extract condition code */
			cond = (instr & 0xf);

			/* Determine if it passes */
			if (condition_true(cond, regs64->cpsr)) {
				uint64_t offset;

				/* Extract 19-bit target offset, add to PC */
				offset = extract_address_literal_sign_extended(instr, 5, 19);
				new_pc = regs64->pc + offset;
			} else {
				/* Move forwards */
				new_pc = regs64->pc + 4;
			}

			*was_simulated = 1;
			break;
		}

		case FASTTRAP_T_ARM64_CBNZ_W:
		{
			do_cbz_cnbz(regs64, 32, instr, 0, &new_pc);
			*was_simulated = 1;
			break;
		}
		case FASTTRAP_T_ARM64_CBNZ_X:
		{
			do_cbz_cnbz(regs64, 64, instr, 0, &new_pc);
			*was_simulated = 1;
			break;
		}
		case FASTTRAP_T_ARM64_CBZ_W:
		{
			do_cbz_cnbz(regs64, 32, instr, 1, &new_pc);
			*was_simulated = 1;
			break;
		}
		case FASTTRAP_T_ARM64_CBZ_X:
		{
			do_cbz_cnbz(regs64, 64, instr, 1, &new_pc);
			*was_simulated = 1;
			break;
		}

		case FASTTRAP_T_ARM64_TBNZ:
		{
			do_tbz_tbnz(regs64, instr, 0, &new_pc);
			*was_simulated = 1;
			break;
		}
		case FASTTRAP_T_ARM64_TBZ:
		{
			do_tbz_tbnz(regs64, instr, 1, &new_pc);
			*was_simulated = 1;
			break;
		}
		case FASTTRAP_T_ARM64_B:
		case FASTTRAP_T_ARM64_BL:
		{
			uint64_t offset;

			/* Extract offset from instruction */
			offset = extract_address_literal_sign_extended(instr, 0, 26);

			/* Update LR if appropriate */
			if (tp->ftt_type == FASTTRAP_T_ARM64_BL) {
				regs64->lr = regs64->pc + 4;
			}

			/* Compute PC (unsigned addition for defined overflow) */
			new_pc = regs64->pc + offset;
			*was_simulated = 1;
			break;
		}

		case FASTTRAP_T_ARM64_BLR:
		case FASTTRAP_T_ARM64_BR:
		{
			uint32_t regno;

			/* Extract register from instruction */
			regno = ((instr >> 5) & 0x1f);
			assert(regno <= 31);

			/* Update LR if appropriate */
			if (tp->ftt_type == FASTTRAP_T_ARM64_BLR) {
				regs64->lr = regs64->pc + 4;
			}

			/* Update PC in saved state */
			new_pc = get_saved_state64_regno(regs64, regno, 1);
			*was_simulated = 1;
			break;
		}

		case FASTTRAP_T_ARM64_RET:
		{
			/* Extract register */
			unsigned regno = ((instr >> 5) & 0x1f);
			assert(regno <= 31);

			/* Set PC to register value (xzr, not sp) */
			new_pc = get_saved_state64_regno(regs64, regno, 1);
			*was_simulated = 1;
			break;
		}

		/*
		 * End branches.
		 */

		/* 
		 * Address calculations: emulate for correctness.
		 *
		 * 	ADRP Xd, label
		 * 	ADR Xd, label
		 */
		case FASTTRAP_T_ARM64_ADRP:
		case FASTTRAP_T_ARM64_ADR:
		{
			uint64_t immhi, immlo, offset, result;
			uint32_t regno;

			/* Extract destination register */
			regno = (instr & 0x1f);
			assert(regno <= 31);

			/* Extract offset */
			immhi = ((instr & 0x00ffffe0) >> 5); 		/* bits [23,5]: 19 bits */
			immlo = ((instr & 0x60000000) >> 29);		/* bits [30,29]: 2 bits */

			/* Add to PC.  Use unsigned addition so that overflow wraps (rather than being undefined). */
			if (tp->ftt_type == FASTTRAP_T_ARM64_ADRP) {
				offset =  (immhi << 14) | (immlo << 12); 	/* Concatenate bits into [32,12]*/
				offset = sign_extend(offset, 32);		/* Sign extend from bit 32 */
				result = (regs64->pc & ~0xfffULL) + offset; 	/* And add to page of current pc */
			} else {
				assert(tp->ftt_type == FASTTRAP_T_ARM64_ADR);
				offset =  (immhi << 2) | immlo; 		/* Concatenate bits into [20,0] */
				offset = sign_extend(offset, 20);		/* Sign-extend */
				result = regs64->pc + offset;			/* And add to page of current pc */
			}

			/* xzr, not sp */
			set_saved_state64_regno(regs64, regno, 1, result);

			/* Move PC forward */
			new_pc = regs64->pc + 4;
			*was_simulated = 1;
			break;
		}

		/*
		 *  End address calculations.
		 */

		/* 
		 * Everything else: thunk to userland 
		 */
		case FASTTRAP_T_COMMON:
		{
			fasttrap_pid_probe_thunk_instr64(state, tp, p, uthread, &tp->ftt_instr, 1, &new_pc);
			*was_simulated = 0;
			break;
		}
		default:
		{
			panic("An instruction DTrace doesn't expect: %d\n", tp->ftt_type);
			break;
		}
	}

	set_saved_state_pc(state, new_pc);
	return;
}

int
fasttrap_pid_probe(arm_saved_state_t *state)
{
	proc_t *p = current_proc();
	fasttrap_bucket_t *bucket;
	lck_mtx_t *pid_mtx;
	fasttrap_tracepoint_t *tp, tp_local;
	pid_t pid;
	dtrace_icookie_t cookie;
	uint_t is_enabled = 0;
	int was_simulated, retire_tp = 1;
	int is_64_bit = is_saved_state64(state);

	uint64_t pc = get_saved_state_pc(state);

	assert(is_64_bit || (pc <= UINT32_MAX));

	uthread_t uthread = (uthread_t) get_bsdthread_info(current_thread());

	/*
	 * It's possible that a user (in a veritable orgy of bad planning)
	 * could redirect this thread's flow of control before it reached the
	 * return probe fasttrap. In this case we need to kill the process
	 * since it's in a unrecoverable state.
	 */
	if (uthread->t_dtrace_step) {
		ASSERT(uthread->t_dtrace_on);
		fasttrap_sigtrap(p, uthread, (user_addr_t)pc);
		return (0);
	}

	/*
	 * Clear all user tracing flags.
	 */
	uthread->t_dtrace_ft = 0;
	uthread->t_dtrace_pc = 0;
	uthread->t_dtrace_npc = 0;
	uthread->t_dtrace_scrpc = 0;
	uthread->t_dtrace_astpc = 0;
	uthread->t_dtrace_reg = 0;

	/*
	 * Treat a child created by a call to vfork(2) as if it were its
	 * parent. We know that there's only one thread of control in such a
	 * process: this one.
	 */
	if (p->p_lflag & P_LINVFORK) {
		proc_list_lock();
		while (p->p_lflag & P_LINVFORK)
			p = p->p_pptr;
		proc_list_unlock();
	}

	pid = p->p_pid;
	pid_mtx = &cpu_core[CPU->cpu_id].cpuc_pid_lock;
	lck_mtx_lock(pid_mtx);
	bucket = &fasttrap_tpoints.fth_table[FASTTRAP_TPOINTS_INDEX(pid,pc)];

	/*
	 * Lookup the tracepoint that the process just hit.
	 */
	for (tp = bucket->ftb_data; tp != NULL; tp = tp->ftt_next) {
		if (pid == tp->ftt_pid && pc == tp->ftt_pc &&
		    tp->ftt_proc->ftpc_acount != 0)
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

	/* Validation of THUMB-related state */
	if (tp->ftt_thumb) {
		if (!fasttrap_pid_probe_thumb_state_valid(saved_state32(state), tp)) {
			fasttrap_tracepoint_remove(p, tp);
			lck_mtx_unlock(pid_mtx);
			return (-1);
		}
	}

	/* Execute the actual probe */
	if (tp->ftt_ids != NULL) {
		fasttrap_id_t *id;
		uint64_t arg4;

		if (is_saved_state64(state)) {
			arg4 = get_saved_state_reg(state, 4);
		} else {
			uint32_t arg;
			user_addr_t stack = (user_addr_t)get_saved_state_sp(state);

			fasttrap_fuword32_noerr(stack, &arg);
			arg4 = arg;
		}


		/* First four parameters are passed in registers */

		for (id = tp->ftt_ids; id != NULL; id = id->fti_next) {
			fasttrap_probe_t *probe = id->fti_probe;

#ifndef CONFIG_EMBEDDED
			if (ISSET(current_proc()->p_lflag, P_LNOATTACH)) {
				dtrace_probe(dtrace_probeid_error, 0 /* state */, probe->ftp_id,
					     1 /* ndx */, -1 /* offset */, DTRACEFLT_UPRIV);
#else
			if (FALSE) {
#endif
			} else {
				if (probe->ftp_prov->ftp_provider_type == DTFTP_PROVIDER_ONESHOT) {
					uint8_t already_triggered = atomic_or_8(&probe->ftp_triggered, 1);
					if (already_triggered) {
						continue;
					}
				}
				/*
				 * If we have at least one probe associated that
				 * is not a oneshot probe, don't remove the
				 * tracepoint
				 */
				else {
					retire_tp = 0;
				}
				if (id->fti_ptype == DTFTP_ENTRY) {
					/*
					 * We note that this was an entry
					 * probe to help ustack() find the
					 * first caller.
					 */
					cookie = dtrace_interrupt_disable();
					DTRACE_CPUFLAG_SET(CPU_DTRACE_ENTRY);
					dtrace_probe(probe->ftp_id,
							get_saved_state_reg(state, 0),
							get_saved_state_reg(state, 1),
							get_saved_state_reg(state, 2),
							get_saved_state_reg(state, 3),
							arg4);
					DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_ENTRY);
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
					dtrace_probe(probe->ftp_id,
							get_saved_state_reg(state, 0),
							get_saved_state_reg(state, 1),
							get_saved_state_reg(state, 2),
							get_saved_state_reg(state, 3),
							arg4);

				} else {
					uint64_t t[5];

					if (is_64_bit) {
						fasttrap_usdt_args64(probe, saved_state64(state), 5, t);
					} else {
						fasttrap_usdt_args32(probe, saved_state32(state), 5, t);
					}
					dtrace_probe(probe->ftp_id, t[0], t[1], t[2], t[3], t[4]);
				}
			}
		}
		if (retire_tp) {
			fasttrap_tracepoint_retire(p, tp);
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
	 * APPLE NOTE:
	 *
	 * Subroutines should update PC.
	 * We're setting this earlier than Solaris does, to get a "correct"
	 * ustack() output. In the Sun code,  a() -> b() -> c() -> d() is
	 * reported at: d, b, a. The new way gives c, b, a, which is closer
	 * to correct, as the return instruction has already exectued.
	 */
	if (is_64_bit) {
		fasttrap_pid_probe_handle_patched_instr64(state, tp, uthread, p, is_enabled, &was_simulated);
	} else {
		fasttrap_pid_probe_handle_patched_instr32(state, tp, uthread, p, is_enabled, &was_simulated);
	}

	/*                      
	 * If there were no return probes when we first found the tracepoint,
	 * we should feel no obligation to honor any return probes that were
	 * subsequently enabled -- they'll just have to wait until the next
	 * time around. 
	 */                     
	if (tp->ftt_retids != NULL) {
		/*
		 * We need to wait until the results of the instruction are
		 * apparent before invoking any return probes. If this
		 * instruction was emulated we can just call
		 * fasttrap_return_common(); if it needs to be executed, we
		 * need to wait until the user thread returns to the kernel.
		 */
		/*
		 * It used to be that only common instructions were simulated.
		 * For performance reasons, we now simulate some instructions
		 * when safe and go back to userland otherwise. The was_simulated
		 * flag means we don't need to go back to userland.
		 */
		if (was_simulated) {
			fasttrap_return_common(p, state, (user_addr_t)pc, (user_addr_t)get_saved_state_pc(state));
		} else {
			ASSERT(uthread->t_dtrace_ret != 0);
			ASSERT(uthread->t_dtrace_pc == pc);
			ASSERT(uthread->t_dtrace_scrpc != 0);
			ASSERT(((user_addr_t)get_saved_state_pc(state)) == uthread->t_dtrace_astpc);
		}
	}

	return (0);
}

int
fasttrap_return_probe(arm_saved_state_t *regs)
{
	proc_t *p = current_proc();
	uthread_t uthread = (uthread_t)get_bsdthread_info(current_thread());
	user_addr_t pc = uthread->t_dtrace_pc;
	user_addr_t npc = uthread->t_dtrace_npc;

	uthread->t_dtrace_pc = 0;
	uthread->t_dtrace_npc = 0;
	uthread->t_dtrace_scrpc = 0;
	uthread->t_dtrace_astpc = 0;

	/*
	 * Treat a child created by a call to vfork(2) as if it were its
	 * parent. We know that there's only one thread of control in such a
	 * process: this one.
	 */
	if (p->p_lflag & P_LINVFORK) {
		proc_list_lock();
		while (p->p_lflag & P_LINVFORK)
			p = p->p_pptr;
		proc_list_unlock();
	}

	/*
	 * We set rp->r_pc to the address of the traced instruction so
	 * that it appears to dtrace_probe() that we're on the original
	 * instruction, and so that the user can't easily detect our
	 * complex web of lies. dtrace_return_probe() (our caller)
	 * will correctly set %pc after we return.
	 */
	set_saved_state_pc(regs, pc);

	fasttrap_return_common(p, regs, pc, npc);

	return (0);
}

uint64_t
fasttrap_pid_getarg(void *arg, dtrace_id_t id, void *parg, int argno,
		int aframes)
{
#pragma unused(arg, id, parg, aframes)
	arm_saved_state_t* regs = find_user_regs(current_thread());

	if (is_saved_state32(regs)) {
		/* First four arguments are in registers */
		if (argno < 4)
			return saved_state32(regs)->r[argno];

		/* Look on the stack for the rest */
		uint32_t value;
		uint32_t* sp = (uint32_t*)(uintptr_t) saved_state32(regs)->sp;
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		value = dtrace_fuword32((user_addr_t) (sp+argno-4));
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT | CPU_DTRACE_BADADDR);

		return value;
	}
	else {
		/* First eight arguments are in registers */
		if (argno < 8)
			return saved_state64(regs)->x[argno];

		/* Look on the stack for the rest */
		uint64_t value;
		uint64_t* sp = (uint64_t*) saved_state64(regs)->sp;
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		value = dtrace_fuword64((user_addr_t) (sp+argno-8));
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT | CPU_DTRACE_BADADDR);

		return value;		
	}
	
}

uint64_t
fasttrap_usdt_getarg(void *arg, dtrace_id_t id, void *parg, int argno, int aframes)
{
#pragma unused(arg, id, parg, argno, aframes)
#if 0
	return (fasttrap_anarg(ttolwp(curthread)->lwp_regs, 0, argno));
#endif

	return 0;
}

