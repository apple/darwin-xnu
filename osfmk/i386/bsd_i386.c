/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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
#ifdef  MACH_BSD
#include <mach_debug.h>
#include <mach_ldebug.h>

#include <mach/kern_return.h>
#include <mach/mach_traps.h>
#include <mach/thread_status.h>
#include <mach/vm_param.h>

#include <kern/counters.h>
#include <kern/cpu_data.h>
#include <kern/mach_param.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/spl.h>
#include <kern/syscall_sw.h>
#include <ipc/ipc_port.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <i386/cpu_number.h>
#include <i386/eflags.h>
#include <i386/proc_reg.h>
#include <i386/tss.h>
#include <i386/user_ldt.h>
#include <i386/fpu.h>
#include <i386/machdep_call.h>
#include <i386/vmparam.h>
#include <i386/mp_desc.h>
#include <i386/misc_protos.h>
#include <i386/thread.h>
#include <i386/trap.h>
#include <i386/seg.h>
#include <mach/i386/syscall_sw.h>
#include <sys/syscall.h>
#include <sys/kdebug.h>
#include <sys/errno.h>
#include <../bsd/sys/sysent.h>

#ifdef MACH_BSD
extern void     mach_kauth_cred_uthread_update(void);
extern void throttle_lowpri_io(int);
#endif

void * find_user_regs(thread_t);

unsigned int get_msr_exportmask(void);

unsigned int get_msr_nbits(void);

unsigned int get_msr_rbits(void);

/*
 * thread_userstack:
 *
 * Return the user stack pointer from the machine
 * dependent thread state info.
 */
kern_return_t
thread_userstack(
	__unused thread_t   thread,
	int                 flavor,
	thread_state_t      tstate,
	__unused unsigned int        count,
	mach_vm_offset_t    *user_stack,
	int                 *customstack,
	__unused boolean_t  is64bit
	)
{
	if (customstack) {
		*customstack = 0;
	}

	switch (flavor) {
	case x86_THREAD_STATE32:
	{
		x86_thread_state32_t *state25;

		state25 = (x86_thread_state32_t *) tstate;

		if (state25->esp) {
			*user_stack = state25->esp;
			if (customstack) {
				*customstack = 1;
			}
		} else {
			*user_stack = VM_USRSTACK32;
			if (customstack) {
				*customstack = 0;
			}
		}
		break;
	}

	case x86_THREAD_FULL_STATE64:
	/* FALL THROUGH */
	case x86_THREAD_STATE64:
	{
		x86_thread_state64_t *state25;

		state25 = (x86_thread_state64_t *) tstate;

		if (state25->rsp) {
			*user_stack = state25->rsp;
			if (customstack) {
				*customstack = 1;
			}
		} else {
			*user_stack = VM_USRSTACK64;
			if (customstack) {
				*customstack = 0;
			}
		}
		break;
	}

	default:
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}

/*
 * thread_userstackdefault:
 *
 * Return the default stack location for the
 * thread, if otherwise unknown.
 */
kern_return_t
thread_userstackdefault(
	mach_vm_offset_t *default_user_stack,
	boolean_t is64bit)
{
	if (is64bit) {
		*default_user_stack = VM_USRSTACK64;
	} else {
		*default_user_stack = VM_USRSTACK32;
	}
	return KERN_SUCCESS;
}

kern_return_t
thread_entrypoint(
	__unused thread_t   thread,
	int                 flavor,
	thread_state_t      tstate,
	__unused unsigned int        count,
	mach_vm_offset_t    *entry_point
	)
{
	/*
	 * Set a default.
	 */
	if (*entry_point == 0) {
		*entry_point = VM_MIN_ADDRESS;
	}

	switch (flavor) {
	case x86_THREAD_STATE32:
	{
		x86_thread_state32_t *state25;

		state25 = (i386_thread_state_t *) tstate;
		*entry_point = state25->eip ? state25->eip : VM_MIN_ADDRESS;
		break;
	}

	case x86_THREAD_STATE64:
	{
		x86_thread_state64_t *state25;

		state25 = (x86_thread_state64_t *) tstate;
		*entry_point = state25->rip ? state25->rip : VM_MIN_ADDRESS64;
		break;
	}
	}
	return KERN_SUCCESS;
}

/*
 * FIXME - thread_set_child
 */

void thread_set_child(thread_t child, int pid);
void
thread_set_child(thread_t child, int pid)
{
	pal_register_cache_state(child, DIRTY);

	if (thread_is_64bit_addr(child)) {
		x86_saved_state64_t     *iss64;

		iss64 = USER_REGS64(child);

		iss64->rax = pid;
		iss64->rdx = 1;
		iss64->isf.rflags &= ~EFL_CF;
	} else {
		x86_saved_state32_t     *iss32;

		iss32 = USER_REGS32(child);

		iss32->eax = pid;
		iss32->edx = 1;
		iss32->efl &= ~EFL_CF;
	}
}



/*
 * System Call handling code
 */

extern long fuword(vm_offset_t);

__attribute__((noreturn))
void
machdep_syscall(x86_saved_state_t *state)
{
	int                     args[machdep_call_count];
	int                     trapno;
	int                     nargs;
	const machdep_call_t    *entry;
	x86_saved_state32_t     *regs;

	assert(is_saved_state32(state));
	regs = saved_state32(state);

	trapno = regs->eax;
#if DEBUG_TRACE
	kprintf("machdep_syscall(0x%08x) code=%d\n", regs, trapno);
#endif

	DEBUG_KPRINT_SYSCALL_MDEP(
		"machdep_syscall: trapno=%d\n", trapno);

	if (trapno < 0 || trapno >= machdep_call_count) {
		regs->eax = (unsigned int)kern_invalid(NULL);

		thread_exception_return();
		/* NOTREACHED */
	}
	entry = &machdep_call_table[trapno];
	nargs = entry->nargs;

	if (nargs != 0) {
		if (copyin((user_addr_t) regs->uesp + sizeof(int),
		    (char *) args, (nargs * sizeof(int)))) {
			regs->eax = KERN_INVALID_ADDRESS;

			thread_exception_return();
			/* NOTREACHED */
		}
	}
	switch (nargs) {
	case 0:
		regs->eax = (*entry->routine.args_0)();
		break;
	case 1:
		regs->eax = (*entry->routine.args_1)(args[0]);
		break;
	case 2:
		regs->eax = (*entry->routine.args_2)(args[0], args[1]);
		break;
	case 3:
		if (!entry->bsd_style) {
			regs->eax = (*entry->routine.args_3)(args[0], args[1], args[2]);
		} else {
			int     error;
			uint32_t        rval;

			error = (*entry->routine.args_bsd_3)(&rval, args[0], args[1], args[2]);
			if (error) {
				regs->eax = error;
				regs->efl |= EFL_CF;    /* carry bit */
			} else {
				regs->eax = rval;
				regs->efl &= ~EFL_CF;
			}
		}
		break;
	case 4:
		regs->eax = (*entry->routine.args_4)(args[0], args[1], args[2], args[3]);
		break;

	default:
		panic("machdep_syscall: too many args");
	}

	DEBUG_KPRINT_SYSCALL_MDEP("machdep_syscall: retval=%u\n", regs->eax);

#if DEBUG || DEVELOPMENT
	kern_allocation_name_t
	prior __assert_only = thread_get_kernel_state(current_thread())->allocation_name;
	assertf(prior == NULL, "thread_set_allocation_name(\"%s\") not cleared", kern_allocation_get_name(prior));
#endif /* DEBUG || DEVELOPMENT */

	throttle_lowpri_io(1);

	thread_exception_return();
	/* NOTREACHED */
}

__attribute__((noreturn))
void
machdep_syscall64(x86_saved_state_t *state)
{
	int                     trapno;
	const machdep_call_t    *entry;
	x86_saved_state64_t     *regs;

	assert(is_saved_state64(state));
	regs = saved_state64(state);

	trapno = (int)(regs->rax & SYSCALL_NUMBER_MASK);

	DEBUG_KPRINT_SYSCALL_MDEP(
		"machdep_syscall64: trapno=%d\n", trapno);

	if (trapno < 0 || trapno >= machdep_call_count) {
		regs->rax = (unsigned int)kern_invalid(NULL);

		thread_exception_return();
		/* NOTREACHED */
	}
	entry = &machdep_call_table64[trapno];

	switch (entry->nargs) {
	case 0:
		regs->rax = (*entry->routine.args_0)();
		break;
	case 1:
		regs->rax = (*entry->routine.args64_1)(regs->rdi);
		break;
	case 2:
		regs->rax = (*entry->routine.args64_2)(regs->rdi, regs->rsi);
		break;
	case 3:
		if (!entry->bsd_style) {
			regs->rax = (*entry->routine.args64_3)(regs->rdi, regs->rsi, regs->rdx);
		} else {
			int             error;
			uint32_t        rval;

			error = (*entry->routine.args64_bsd_3)(&rval, regs->rdi, regs->rsi, regs->rdx);
			if (error) {
				regs->rax = (uint64_t)error;
				regs->isf.rflags |= EFL_CF;    /* carry bit */
			} else {
				regs->rax = rval;
				regs->isf.rflags &= ~(uint64_t)EFL_CF;
			}
		}
		break;
	default:
		panic("machdep_syscall64: too many args");
	}

	DEBUG_KPRINT_SYSCALL_MDEP("machdep_syscall: retval=%llu\n", regs->rax);

#if DEBUG || DEVELOPMENT
	kern_allocation_name_t
	prior __assert_only = thread_get_kernel_state(current_thread())->allocation_name;
	assertf(prior == NULL, "thread_set_allocation_name(\"%s\") not cleared", kern_allocation_get_name(prior));
#endif /* DEBUG || DEVELOPMENT */

	throttle_lowpri_io(1);

	thread_exception_return();
	/* NOTREACHED */
}

#endif  /* MACH_BSD */


typedef kern_return_t (*mach_call_t)(void *);

struct mach_call_args {
	syscall_arg_t arg1;
	syscall_arg_t arg2;
	syscall_arg_t arg3;
	syscall_arg_t arg4;
	syscall_arg_t arg5;
	syscall_arg_t arg6;
	syscall_arg_t arg7;
	syscall_arg_t arg8;
	syscall_arg_t arg9;
};

static kern_return_t
mach_call_arg_munger32(uint32_t sp, struct mach_call_args *args, const mach_trap_t *trapp);


static kern_return_t
mach_call_arg_munger32(uint32_t sp, struct mach_call_args *args, const mach_trap_t *trapp)
{
	if (copyin((user_addr_t)(sp + sizeof(int)), (char *)args, trapp->mach_trap_u32_words * sizeof(int))) {
		return KERN_INVALID_ARGUMENT;
	}
#if CONFIG_REQUIRES_U32_MUNGING
	trapp->mach_trap_arg_munge32(args);
#else
#error U32 mach traps on x86_64 kernel requires munging
#endif
	return KERN_SUCCESS;
}


__private_extern__ void mach_call_munger(x86_saved_state_t *state);

extern const char *mach_syscall_name_table[];

__attribute__((noreturn))
void
mach_call_munger(x86_saved_state_t *state)
{
	int argc;
	int call_number;
	mach_call_t mach_call;
	kern_return_t retval;
	struct mach_call_args args = {
		.arg1 = 0,
		.arg2 = 0,
		.arg3 = 0,
		.arg4 = 0,
		.arg5 = 0,
		.arg6 = 0,
		.arg7 = 0,
		.arg8 = 0,
		.arg9 = 0
	};
	x86_saved_state32_t     *regs;

	struct uthread *ut = get_bsdthread_info(current_thread());
	uthread_reset_proc_refcount(ut);

	assert(is_saved_state32(state));
	regs = saved_state32(state);

	call_number = -(regs->eax);

	DEBUG_KPRINT_SYSCALL_MACH(
		"mach_call_munger: code=%d(%s)\n",
		call_number, mach_syscall_name_table[call_number]);
#if DEBUG_TRACE
	kprintf("mach_call_munger(0x%08x) code=%d\n", regs, call_number);
#endif

	if (call_number < 0 || call_number >= mach_trap_count) {
		i386_exception(EXC_SYSCALL, call_number, 1);
		/* NOTREACHED */
	}
	mach_call = (mach_call_t)mach_trap_table[call_number].mach_trap_function;

	if (mach_call == (mach_call_t)kern_invalid) {
		DEBUG_KPRINT_SYSCALL_MACH(
			"mach_call_munger: kern_invalid 0x%x\n", regs->eax);
		i386_exception(EXC_SYSCALL, call_number, 1);
		/* NOTREACHED */
	}

	argc = mach_trap_table[call_number].mach_trap_arg_count;
	if (argc) {
		retval = mach_call_arg_munger32(regs->uesp, &args, &mach_trap_table[call_number]);
		if (retval != KERN_SUCCESS) {
			regs->eax = retval;

			DEBUG_KPRINT_SYSCALL_MACH(
				"mach_call_munger: retval=0x%x\n", retval);

			thread_exception_return();
			/* NOTREACHED */
		}
	}

#ifdef MACH_BSD
	mach_kauth_cred_uthread_update();
#endif

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) | DBG_FUNC_START,
	    args.arg1, args.arg2, args.arg3, args.arg4, 0);

	retval = mach_call(&args);

	DEBUG_KPRINT_SYSCALL_MACH("mach_call_munger: retval=0x%x\n", retval);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) | DBG_FUNC_END,
	    retval, 0, 0, 0, 0);

	regs->eax = retval;

#if DEBUG || DEVELOPMENT
	kern_allocation_name_t
	prior __assert_only = thread_get_kernel_state(current_thread())->allocation_name;
	assertf(prior == NULL, "thread_set_allocation_name(\"%s\") not cleared", kern_allocation_get_name(prior));
#endif /* DEBUG || DEVELOPMENT */

	throttle_lowpri_io(1);

#if PROC_REF_DEBUG
	if (__improbable(uthread_get_proc_refcount(ut) != 0)) {
		panic("system call returned with uu_proc_refcount != 0");
	}
#endif

	thread_exception_return();
	/* NOTREACHED */
}


__private_extern__ void mach_call_munger64(x86_saved_state_t *regs);

__attribute__((noreturn))
void
mach_call_munger64(x86_saved_state_t *state)
{
	int call_number;
	int argc;
	mach_call_t mach_call;
	struct mach_call_args args = {
		.arg1 = 0,
		.arg2 = 0,
		.arg3 = 0,
		.arg4 = 0,
		.arg5 = 0,
		.arg6 = 0,
		.arg7 = 0,
		.arg8 = 0,
		.arg9 = 0
	};
	x86_saved_state64_t     *regs;

	struct uthread *ut = get_bsdthread_info(current_thread());
	uthread_reset_proc_refcount(ut);

	assert(is_saved_state64(state));
	regs = saved_state64(state);

	call_number = (int)(regs->rax & SYSCALL_NUMBER_MASK);

	DEBUG_KPRINT_SYSCALL_MACH(
		"mach_call_munger64: code=%d(%s)\n",
		call_number, mach_syscall_name_table[call_number]);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) | DBG_FUNC_START,
	    regs->rdi, regs->rsi, regs->rdx, regs->r10, 0);

	if (call_number < 0 || call_number >= mach_trap_count) {
		i386_exception(EXC_SYSCALL, regs->rax, 1);
		/* NOTREACHED */
	}
	mach_call = (mach_call_t)mach_trap_table[call_number].mach_trap_function;

	if (mach_call == (mach_call_t)kern_invalid) {
		i386_exception(EXC_SYSCALL, regs->rax, 1);
		/* NOTREACHED */
	}
	argc = mach_trap_table[call_number].mach_trap_arg_count;
	if (argc) {
		int args_in_regs = MIN(6, argc);
		__nochk_memcpy(&args.arg1, &regs->rdi, args_in_regs * sizeof(syscall_arg_t));

		if (argc > 6) {
			int copyin_count;

			assert(argc <= 9);
			copyin_count = (argc - 6) * (int)sizeof(syscall_arg_t);

			if (copyin((user_addr_t)(regs->isf.rsp + sizeof(user_addr_t)), (char *)&args.arg7, copyin_count)) {
				regs->rax = KERN_INVALID_ARGUMENT;

				thread_exception_return();
				/* NOTREACHED */
			}
		}
	}

#ifdef MACH_BSD
	mach_kauth_cred_uthread_update();
#endif

	regs->rax = (uint64_t)mach_call((void *)&args);

	DEBUG_KPRINT_SYSCALL_MACH( "mach_call_munger64: retval=0x%llx\n", regs->rax);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) | DBG_FUNC_END,
	    regs->rax, 0, 0, 0, 0);

#if DEBUG || DEVELOPMENT
	kern_allocation_name_t
	prior __assert_only = thread_get_kernel_state(current_thread())->allocation_name;
	assertf(prior == NULL, "thread_set_allocation_name(\"%s\") not cleared", kern_allocation_get_name(prior));
#endif /* DEBUG || DEVELOPMENT */

	throttle_lowpri_io(1);

#if PROC_REF_DEBUG
	if (__improbable(uthread_get_proc_refcount(ut) != 0)) {
		panic("system call returned with uu_proc_refcount != 0");
	}
#endif

	thread_exception_return();
	/* NOTREACHED */
}


/*
 * thread_setuserstack:
 *
 * Sets the user stack pointer into the machine
 * dependent thread state info.
 */
void
thread_setuserstack(
	thread_t        thread,
	mach_vm_address_t       user_stack)
{
	pal_register_cache_state(thread, DIRTY);
	if (thread_is_64bit_addr(thread)) {
		x86_saved_state64_t     *iss64;

		iss64 = USER_REGS64(thread);

		iss64->isf.rsp = (uint64_t)user_stack;
	} else {
		x86_saved_state32_t     *iss32;

		iss32 = USER_REGS32(thread);

		iss32->uesp = CAST_DOWN_EXPLICIT(unsigned int, user_stack);
	}
}

/*
 * thread_adjuserstack:
 *
 * Returns the adjusted user stack pointer from the machine
 * dependent thread state info.  Used for small (<2G) deltas.
 */
uint64_t
thread_adjuserstack(
	thread_t        thread,
	int             adjust)
{
	pal_register_cache_state(thread, DIRTY);
	if (thread_is_64bit_addr(thread)) {
		x86_saved_state64_t     *iss64;

		iss64 = USER_REGS64(thread);

		iss64->isf.rsp += adjust;

		return iss64->isf.rsp;
	} else {
		x86_saved_state32_t     *iss32;

		iss32 = USER_REGS32(thread);

		iss32->uesp += adjust;

		return CAST_USER_ADDR_T(iss32->uesp);
	}
}

/*
 * thread_setentrypoint:
 *
 * Sets the user PC into the machine
 * dependent thread state info.
 */
void
thread_setentrypoint(thread_t thread, mach_vm_address_t entry)
{
	pal_register_cache_state(thread, DIRTY);
	if (thread_is_64bit_addr(thread)) {
		x86_saved_state64_t     *iss64;

		iss64 = USER_REGS64(thread);

		iss64->isf.rip = (uint64_t)entry;
	} else {
		x86_saved_state32_t     *iss32;

		iss32 = USER_REGS32(thread);

		iss32->eip = CAST_DOWN_EXPLICIT(unsigned int, entry);
	}
}


kern_return_t
thread_setsinglestep(thread_t thread, int on)
{
	pal_register_cache_state(thread, DIRTY);
	if (thread_is_64bit_addr(thread)) {
		x86_saved_state64_t     *iss64;

		iss64 = USER_REGS64(thread);

		if (on) {
			iss64->isf.rflags |= EFL_TF;
		} else {
			iss64->isf.rflags &= ~EFL_TF;
		}
	} else {
		x86_saved_state32_t     *iss32;

		iss32 = USER_REGS32(thread);

		if (on) {
			iss32->efl |= EFL_TF;
			/* Ensure IRET */
			if (iss32->cs == SYSENTER_CS) {
				iss32->cs = SYSENTER_TF_CS;
			}
		} else {
			iss32->efl &= ~EFL_TF;
		}
	}

	return KERN_SUCCESS;
}

void *
get_user_regs(thread_t th)
{
	pal_register_cache_state(th, DIRTY);
	return USER_STATE(th);
}

void *
find_user_regs(thread_t thread)
{
	return get_user_regs(thread);
}

#if CONFIG_DTRACE
/*
 * DTrace would like to have a peek at the kernel interrupt state, if available.
 */
x86_saved_state_t *find_kern_regs(thread_t);

x86_saved_state_t *
find_kern_regs(thread_t thread)
{
	if (thread == current_thread() &&
	    NULL != current_cpu_datap()->cpu_int_state &&
	    !(USER_STATE(thread) == current_cpu_datap()->cpu_int_state &&
	    current_cpu_datap()->cpu_interrupt_level == 1)) {
		return current_cpu_datap()->cpu_int_state;
	} else {
		return NULL;
	}
}

vm_offset_t dtrace_get_cpu_int_stack_top(void);

vm_offset_t
dtrace_get_cpu_int_stack_top(void)
{
	return current_cpu_datap()->cpu_int_stack_top;
}
#endif
