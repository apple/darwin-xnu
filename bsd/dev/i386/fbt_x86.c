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

#include <kern/thread.h>
#include <mach/thread_status.h>
#include <mach/vm_param.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <libkern/kernel_mach_header.h>
#include <libkern/OSAtomic.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <miscfs/devfs/devfs.h>

#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <sys/fbt.h>

#include <sys/dtrace_glue.h>

#include <san/kasan.h>
#include <machine/trap.h>


#define DTRACE_INVOP_NOP_SKIP 1
#define DTRACE_INVOP_MOVL_ESP_EBP 10
#define DTRACE_INVOP_MOVL_ESP_EBP_SKIP 2
#define DTRACE_INVOP_MOV_RSP_RBP 11
#define DTRACE_INVOP_MOV_RSP_RBP_SKIP 3
#define DTRACE_INVOP_POP_RBP 12
#define DTRACE_INVOP_POP_RBP_SKIP 1
#define DTRACE_INVOP_LEAVE_SKIP 1

#define	FBT_PUSHL_EBP			0x55
#define	FBT_MOVL_ESP_EBP0_V0	0x8b
#define	FBT_MOVL_ESP_EBP1_V0	0xec
#define	FBT_MOVL_ESP_EBP0_V1	0x89
#define	FBT_MOVL_ESP_EBP1_V1	0xe5

#define	FBT_PUSH_RBP			0x55
#define	FBT_REX_RSP_RBP			0x48
#define	FBT_MOV_RSP_RBP0		0x89
#define	FBT_MOV_RSP_RBP1		0xe5
#define	FBT_POP_RBP				0x5d

#define	FBT_POPL_EBP			0x5d
#define	FBT_RET					0xc3
#define	FBT_RET_IMM16			0xc2
#define	FBT_LEAVE				0xc9
#define	FBT_JMP_SHORT_REL		0xeb /* Jump short, relative, displacement relative to next instr. */
#define	FBT_JMP_NEAR_REL		0xe9 /* Jump near, relative, displacement relative to next instr. */
#define	FBT_JMP_FAR_ABS			0xea /* Jump far, absolute, address given in operand */
#define FBT_RET_LEN				1
#define FBT_RET_IMM16_LEN		3
#define	FBT_JMP_SHORT_REL_LEN	2
#define	FBT_JMP_NEAR_REL_LEN	5
#define	FBT_JMP_FAR_ABS_LEN		5

#define	FBT_PATCHVAL			0xf0
#define FBT_AFRAMES_ENTRY		7
#define FBT_AFRAMES_RETURN		6

#define	FBT_ENTRY	"entry"
#define	FBT_RETURN	"return"
#define	FBT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & fbt_probetab_mask)

extern dtrace_provider_id_t	fbt_id;
extern fbt_probe_t		**fbt_probetab;
extern int			fbt_probetab_mask;

kern_return_t fbt_perfCallback(int, x86_saved_state_t *, uintptr_t *, __unused int);

int
fbt_invop(uintptr_t addr, uintptr_t *state, uintptr_t rval)
{
	fbt_probe_t *fbt = fbt_probetab[FBT_ADDR2NDX(addr)];

	for (; fbt != NULL; fbt = fbt->fbtp_hashnext) {
		if ((uintptr_t)fbt->fbtp_patchpoint == addr) {

			if (fbt->fbtp_roffset == 0) {
				x86_saved_state64_t *regs = (x86_saved_state64_t *)state;

				CPU->cpu_dtrace_caller = *(uintptr_t *)(((uintptr_t)(regs->isf.rsp))+sizeof(uint64_t)); // 8(%rsp)
				/* 64-bit ABI, arguments passed in registers. */
				dtrace_probe(fbt->fbtp_id, regs->rdi, regs->rsi, regs->rdx, regs->rcx, regs->r8);
				CPU->cpu_dtrace_caller = 0;
			} else {

				dtrace_probe(fbt->fbtp_id, fbt->fbtp_roffset, rval, 0, 0, 0);
				CPU->cpu_dtrace_caller = 0;
			}

			return (fbt->fbtp_rval);
		}
	}

	return (0);
}

#define IS_USER_TRAP(regs) (regs && (((regs)->isf.cs & 3) != 0))
#define FBT_EXCEPTION_CODE T_INVALID_OPCODE

kern_return_t
fbt_perfCallback(
                int         		trapno,
                x86_saved_state_t 	*tagged_regs,
		uintptr_t		*lo_spp,
                __unused int        unused2)
{
	kern_return_t retval = KERN_FAILURE;
	x86_saved_state64_t *saved_state = saved_state64(tagged_regs);

	if (FBT_EXCEPTION_CODE == trapno && !IS_USER_TRAP(saved_state)) {
		boolean_t oldlevel;
		uint64_t rsp_probe, fp, delta = 0;
		uintptr_t old_sp;
		uint32_t *pDst;
		int emul;


		oldlevel = ml_set_interrupts_enabled(FALSE);

		/* Calculate where the stack pointer was when the probe instruction "fired." */
		rsp_probe = saved_state->isf.rsp; /* Easy, x86_64 establishes this value in idt64.s */

		__asm__ volatile(
			"Ldtrace_invop_callsite_pre_label:\n"
			".data\n"
			".private_extern _dtrace_invop_callsite_pre\n"
			"_dtrace_invop_callsite_pre:\n"
			"  .quad Ldtrace_invop_callsite_pre_label\n"
			".text\n"
				 );

		emul = dtrace_invop( saved_state->isf.rip, (uintptr_t *)saved_state, saved_state->rax );

		__asm__ volatile(
			"Ldtrace_invop_callsite_post_label:\n"
			".data\n"
			".private_extern _dtrace_invop_callsite_post\n"
			"_dtrace_invop_callsite_post:\n"
			"  .quad Ldtrace_invop_callsite_post_label\n"
			".text\n"
				 );

		switch (emul) {
		case DTRACE_INVOP_NOP:
			saved_state->isf.rip += DTRACE_INVOP_NOP_SKIP;	/* Skip over the patched NOP (planted by sdt). */
			retval = KERN_SUCCESS;
			break;

		case DTRACE_INVOP_MOV_RSP_RBP:
			saved_state->rbp = rsp_probe;							/* Emulate patched mov %rsp,%rbp */
			saved_state->isf.rip += DTRACE_INVOP_MOV_RSP_RBP_SKIP;	/* Skip over the bytes of the patched mov %rsp,%rbp */
			retval = KERN_SUCCESS;
			break;

		case DTRACE_INVOP_POP_RBP:
		case DTRACE_INVOP_LEAVE:
/*
 * Emulate first micro-op of patched leave: mov %rbp,%rsp
 * fp points just below the return address slot for target's ret
 * and at the slot holding the frame pointer saved by the target's prologue.
 */
			fp = saved_state->rbp;
/* Emulate second micro-op of patched leave: patched pop %rbp
 * savearea rbp is set for the frame of the caller to target
 * The *live* %rsp will be adjusted below for pop increment(s)
 */
			saved_state->rbp = *(uint64_t *)fp;
/* Skip over the patched leave */
			saved_state->isf.rip += DTRACE_INVOP_LEAVE_SKIP;
/*
 * Lift the stack to account for the emulated leave
 * Account for words local in this frame
 * (in "case DTRACE_INVOP_POPL_EBP:" this is zero.)
 */
			delta = ((uint32_t *)fp) - ((uint32_t *)rsp_probe); /* delta is a *word* increment */
/* Account for popping off the rbp (just accomplished by the emulation
 * above...)
 */
			delta += 2;
			saved_state->isf.rsp += (delta << 2);
/* Obtain the stack pointer recorded by the trampolines */
			old_sp = *lo_spp;
/* Shift contents of stack */
			for (pDst = (uint32_t *)fp;
			     pDst > (((uint32_t *)old_sp));
				 pDst--)
				*pDst = pDst[-delta];

#if KASAN
			/*
			 * The above has moved stack objects so they are no longer in sync
			 * with the shadow.
			 */
			uintptr_t base = (uintptr_t)((uint32_t *)old_sp - delta);
			uintptr_t size = (uintptr_t)fp - base;
			if (base >= VM_MIN_KERNEL_AND_KEXT_ADDRESS) {
				kasan_unpoison_stack(base, size);
			}
#endif

/* Track the stack lift in "saved_state". */
			saved_state = (x86_saved_state64_t *) (((uintptr_t)saved_state) + (delta << 2));
/* Adjust the stack pointer utilized by the trampolines */
			*lo_spp = old_sp + (delta << 2);

			retval = KERN_SUCCESS;
			break;

		default:
			retval = KERN_FAILURE;
			break;
		}

		/* Trick trap_from_kernel into not attempting to handle pending AST_URGENT */
		saved_state->isf.trapno = T_PREEMPT;

		ml_set_interrupts_enabled(oldlevel);
	}

	return retval;
}

void
fbt_provide_probe(struct modctl *ctl, const char *modname, const char* symbolName, machine_inst_t* symbolStart, machine_inst_t* instrHigh)
{
	unsigned int			j;
	unsigned int			doenable = 0;
	dtrace_id_t			thisid;

	fbt_probe_t *newfbt, *retfbt, *entryfbt;
	machine_inst_t *instr, *limit, theInstr, i1, i2, i3;
	int size;

	/*
	 * Guard against null symbols
	 */
	if (!symbolStart || !instrHigh || instrHigh < symbolStart) {
		kprintf("dtrace: %s has an invalid address\n", symbolName);
		return;
	}

	for (j = 0, instr = symbolStart, theInstr = 0;
	     (j < 4) && (instrHigh > (instr + 2)); j++) {
		theInstr = instr[0];
		if (theInstr == FBT_PUSH_RBP || theInstr == FBT_RET || theInstr == FBT_RET_IMM16)
			break;

		if ((size = dtrace_instr_size(instr)) <= 0)
			break;

		instr += size;
	}

	if (theInstr != FBT_PUSH_RBP)
		return;

	i1 = instr[1];
	i2 = instr[2];
	i3 = instr[3];

	limit = (machine_inst_t *)instrHigh;

	if (i1 == FBT_REX_RSP_RBP && i2 == FBT_MOV_RSP_RBP0 && i3 == FBT_MOV_RSP_RBP1) {
		instr += 1; /* Advance to the mov %rsp,%rbp */
		theInstr = i1;
	} else {
		return;
	}
#if 0
	else {
		/*
		 * Sometimes, the compiler will schedule an intervening instruction
		 * in the function prologue. Example:
		 *
		 * _mach_vm_read:
		 * 000006d8        pushl   %ebp
		 * 000006d9        movl    $0x00000004,%edx
		 * 000006de        movl    %esp,%ebp
		 *
		 * Try the next instruction, to see if it is a movl %esp,%ebp
		 */

		instr += 1; /* Advance past the pushl %ebp */
		if ((size = dtrace_instr_size(instr)) <= 0)
			return;

		instr += size;

		if ((instr + 1) >= limit)
			return;

		i1 = instr[0];
		i2 = instr[1];

		if (!(i1 == FBT_MOVL_ESP_EBP0_V0 && i2 == FBT_MOVL_ESP_EBP1_V0) &&
		    !(i1 == FBT_MOVL_ESP_EBP0_V1 && i2 == FBT_MOVL_ESP_EBP1_V1))
			return;

		/* instr already points at the movl %esp,%ebp */
		theInstr = i1;
	}
#endif
	thisid = dtrace_probe_lookup(fbt_id, modname, symbolName, FBT_ENTRY);
	newfbt = kmem_zalloc(sizeof (fbt_probe_t), KM_SLEEP);
	strlcpy( (char *)&(newfbt->fbtp_name), symbolName, MAX_FBTP_NAME_CHARS );

	if (thisid != 0) {
		/*
		 * The dtrace_probe previously existed, so we have to hook
		 * the newfbt entry onto the end of the existing fbt's chain.
		 * If we find an fbt entry that was previously patched to
		 * fire, (as indicated by the current patched value), then
		 * we want to enable this newfbt on the spot.
		 */
		entryfbt = dtrace_probe_arg (fbt_id, thisid);
		ASSERT (entryfbt != NULL);
		for(; entryfbt != NULL; entryfbt = entryfbt->fbtp_next) {
			if (entryfbt->fbtp_currentval == entryfbt->fbtp_patchval)
				doenable++;

			if (entryfbt->fbtp_next == NULL) {
				entryfbt->fbtp_next = newfbt;
				newfbt->fbtp_id = entryfbt->fbtp_id;
				break;
			}
		}
	}
	else {
		/*
		 * The dtrace_probe did not previously exist, so we
		 * create it and hook in the newfbt.  Since the probe is
		 * new, we obviously do not need to enable it on the spot.
		 */
		newfbt->fbtp_id = dtrace_probe_create(fbt_id, modname, symbolName, FBT_ENTRY, FBT_AFRAMES_ENTRY, newfbt);
		doenable = 0;
	}

	newfbt->fbtp_patchpoint = instr;
	newfbt->fbtp_ctl = ctl;
	newfbt->fbtp_loadcnt = ctl->mod_loadcnt;
	newfbt->fbtp_rval = DTRACE_INVOP_MOV_RSP_RBP;
	newfbt->fbtp_savedval = theInstr;
	newfbt->fbtp_patchval = FBT_PATCHVAL;
	newfbt->fbtp_currentval = 0;
	newfbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
	fbt_probetab[FBT_ADDR2NDX(instr)] = newfbt;

	if (doenable)
		fbt_enable(NULL, newfbt->fbtp_id, newfbt);

	/*
	 * The fbt entry chain is in place, one entry point per symbol.
	 * The fbt return chain can have multiple return points per symbol.
	 * Here we find the end of the fbt return chain.
	 */

	doenable=0;

	thisid = dtrace_probe_lookup(fbt_id, modname, symbolName, FBT_RETURN);
	if (thisid != 0) {
		/* The dtrace_probe previously existed, so we have to
		 * find the end of the existing fbt chain.  If we find
		 * an fbt return that was previously patched to fire,
		 * (as indicated by the currrent patched value), then
		 * we want to enable any new fbts on the spot.
		 */
		retfbt = dtrace_probe_arg (fbt_id, thisid);
		ASSERT(retfbt != NULL);
		for (;  retfbt != NULL; retfbt =  retfbt->fbtp_next) {
			if (retfbt->fbtp_currentval == retfbt->fbtp_patchval)
				doenable++;
			if(retfbt->fbtp_next == NULL)
				break;
		}
	}
	else {
		doenable = 0;
		retfbt = NULL;
	}

again:
	if (instr >= limit)
		return;

	/*
	 * If this disassembly fails, then we've likely walked off into
	 * a jump table or some other unsuitable area.  Bail out of the
	 * disassembly now.
	 */
	if ((size = dtrace_instr_size(instr)) <= 0)
		return;

	/*
	 * We (desperately) want to avoid erroneously instrumenting a
	 * jump table, especially given that our markers are pretty
	 * short:  two bytes on x86, and just one byte on amd64.  To
	 * determine if we're looking at a true instruction sequence
	 * or an inline jump table that happens to contain the same
	 * byte sequences, we resort to some heuristic sleeze:  we
	 * treat this instruction as being contained within a pointer,
	 * and see if that pointer points to within the body of the
	 * function.  If it does, we refuse to instrument it.
	 */
	for (j = 0; j < sizeof (uintptr_t); j++) {
		uintptr_t check = (uintptr_t)instr - j;
		uint8_t *ptr;

		if (check < (uintptr_t)symbolStart)
			break;

		if (check + sizeof (uintptr_t) > (uintptr_t)limit)
			continue;

		ptr = *(uint8_t **)check;

		if (ptr >= (uint8_t *)symbolStart && ptr < limit) {
			instr += size;
			goto again;
		}
	}

	/*
	 * OK, it's an instruction.
	 */
	theInstr = instr[0];

	/* Walked onto the start of the next routine? If so, bail out of this function. */
	if (theInstr == FBT_PUSH_RBP)
		return;

	if (!(size == 1 && (theInstr == FBT_POP_RBP || theInstr == FBT_LEAVE))) {
		instr += size;
		goto again;
	}

	/*
	 * Found the pop %rbp; or leave.
	 */
	machine_inst_t *patch_instr = instr;

	/*
	 * Scan forward for a "ret", or "jmp".
	 */
	instr += size;
	if (instr >= limit)
		return;

	size = dtrace_instr_size(instr);
	if (size <= 0) /* Failed instruction decode? */
		return;

	theInstr = instr[0];

	if (!(size == FBT_RET_LEN && (theInstr == FBT_RET)) &&
	    !(size == FBT_RET_IMM16_LEN && (theInstr == FBT_RET_IMM16)) &&
	    !(size == FBT_JMP_SHORT_REL_LEN && (theInstr == FBT_JMP_SHORT_REL)) &&
	    !(size == FBT_JMP_NEAR_REL_LEN && (theInstr == FBT_JMP_NEAR_REL)) &&
	    !(size == FBT_JMP_FAR_ABS_LEN && (theInstr == FBT_JMP_FAR_ABS)))
		return;

	/*
	 * pop %rbp; ret; or leave; ret; or leave; jmp tailCalledFun; -- We have a winner!
	 */
	newfbt = kmem_zalloc(sizeof (fbt_probe_t), KM_SLEEP);
	strlcpy( (char *)&(newfbt->fbtp_name), symbolName, MAX_FBTP_NAME_CHARS );

	if (retfbt == NULL) {
		newfbt->fbtp_id = dtrace_probe_create(fbt_id, modname,
						      symbolName, FBT_RETURN, FBT_AFRAMES_RETURN, newfbt);
	} else {
		retfbt->fbtp_next = newfbt;
		newfbt->fbtp_id = retfbt->fbtp_id;
	}

	retfbt = newfbt;
	newfbt->fbtp_patchpoint = patch_instr;
	newfbt->fbtp_ctl = ctl;
	newfbt->fbtp_loadcnt = ctl->mod_loadcnt;

	if (*patch_instr == FBT_POP_RBP) {
		newfbt->fbtp_rval = DTRACE_INVOP_POP_RBP;
	} else {
		ASSERT(*patch_instr == FBT_LEAVE);
		newfbt->fbtp_rval = DTRACE_INVOP_LEAVE;
	}
	newfbt->fbtp_roffset =
	(uintptr_t)(patch_instr - (uint8_t *)symbolStart);

	newfbt->fbtp_savedval = *patch_instr;
	newfbt->fbtp_patchval = FBT_PATCHVAL;
	newfbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(patch_instr)];
	fbt_probetab[FBT_ADDR2NDX(patch_instr)] = newfbt;

	if (doenable)
		fbt_enable(NULL, newfbt->fbtp_id, newfbt);

	instr += size;
	goto again;
}

