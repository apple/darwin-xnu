/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
#include <mach/vm_param.h>

#include <kern/counters.h>
#include <kern/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <kern/mach_param.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/spl.h>
#include <kern/syscall_sw.h>
#include <ipc/ipc_port.h>
#include <vm/vm_kern.h>
#include <mach/thread_status.h>
#include <vm/pmap.h>

#include <sys/kdebug.h>

#include <sys/syscall.h>

extern void throttle_lowpri_io(int);
void mach_syscall(struct arm_saved_state*);
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

static void
arm_set_mach_syscall_ret(struct arm_saved_state *state, int retval)
{
	if (is_saved_state32(state)) {
		saved_state32(state)->r[0] = retval;
	} else {
		saved_state64(state)->x[0] = retval;
	}
}

static kern_return_t
arm_get_mach_syscall_args(struct arm_saved_state *state, struct mach_call_args *dest, const mach_trap_t *trapp)
{
	uint32_t reg_count;

	if (is_saved_state32(state)) {
		/* The trap table entry defines the number of 32-bit words to be copied in from userspace. */
		reg_count = trapp->mach_trap_u32_words;

		/*
		 * We get 7 contiguous words; r0-r6, hop over r7
		 * (frame pointer), optionally r8
		 */
		if (reg_count <= 7) {
			bcopy((char*)saved_state32(state), (char*)dest, sizeof(uint32_t) * reg_count);
		} else if (reg_count <= 9) {
			bcopy((char*)saved_state32(state), (char*)dest, sizeof(uint32_t) * 7);
			bcopy((char*)&saved_state32(state)->r[8], ((char*)dest) + sizeof(uint32_t) * 7,
			    reg_count - 7);
		} else {
			panic("Trap with %d words of args? We only support 9.", reg_count);
		}

#if CONFIG_REQUIRES_U32_MUNGING
		trapp->mach_trap_arg_munge32(dest);
#else
#error U32 mach traps on ARM64 kernel requires munging
#endif
	} else {
		assert(is_saved_state64(state));
		bcopy((char*)saved_state64(state), (char*)dest, trapp->mach_trap_arg_count * sizeof(uint64_t));
	}

	return KERN_SUCCESS;
}

kern_return_t
thread_setsinglestep(__unused thread_t thread, __unused int on)
{
	return KERN_FAILURE; /* XXX TODO */
}

#if CONFIG_DTRACE

vm_offset_t dtrace_get_cpu_int_stack_top(void);

vm_offset_t
dtrace_get_cpu_int_stack_top(void)
{
	return getCpuDatap()->intstack_top;
}
#endif /* CONFIG_DTRACE */
extern const char *mach_syscall_name_table[];

/* ARM64_TODO: remove this. still TODO?*/
extern struct proc* current_proc(void);
extern int proc_pid(struct proc*);

void
mach_syscall(struct arm_saved_state *state)
{
	kern_return_t retval;
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
	int call_number = get_saved_state_svc_number(state);
	int64_t exc_code;
	int argc;

	struct uthread *ut = get_bsdthread_info(current_thread());
	uthread_reset_proc_refcount(ut);

	assert(call_number < 0); /* Otherwise it would be a Unix syscall */
	call_number = -call_number;

	if (call_number >= MACH_TRAP_TABLE_COUNT) {
		goto bad;
	}

	DEBUG_KPRINT_SYSCALL_MACH(
		"mach_syscall: code=%d(%s) (pid %d, tid %lld)\n",
		call_number, mach_syscall_name_table[call_number],
		proc_pid(current_proc()), thread_tid(current_thread()));

#if DEBUG_TRACE
	kprintf("mach_syscall(0x%08x) code=%d\n", state, call_number);
#endif

	mach_call = (mach_call_t)mach_trap_table[call_number].mach_trap_function;

	if (mach_call == (mach_call_t)kern_invalid) {
		DEBUG_KPRINT_SYSCALL_MACH(
			"mach_syscall: kern_invalid 0x%x\n", call_number);
		goto bad;
	}

	argc = mach_trap_table[call_number].mach_trap_arg_count;
	if (argc) {
		retval = arm_get_mach_syscall_args(state, &args, &mach_trap_table[call_number]);
		if (retval != KERN_SUCCESS) {
			arm_set_mach_syscall_ret(state, retval);

			DEBUG_KPRINT_SYSCALL_MACH(
				"mach_syscall: retval=0x%x\n", retval);
			return;
		}
	}

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) | DBG_FUNC_START,
	    args.arg1, args.arg2, args.arg3, args.arg4, 0);

	retval = mach_call(&args);

	DEBUG_KPRINT_SYSCALL_MACH("mach_syscall: retval=0x%x (pid %d, tid %lld)\n", retval,
	    proc_pid(current_proc()), thread_tid(current_thread()));

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) | DBG_FUNC_END,
	    retval, 0, 0, 0, 0);

	arm_set_mach_syscall_ret(state, retval);

	throttle_lowpri_io(1);

#if DEBUG || DEVELOPMENT
	kern_allocation_name_t
	prior __assert_only = thread_get_kernel_state(current_thread())->allocation_name;
	assertf(prior == NULL, "thread_set_allocation_name(\"%s\") not cleared", kern_allocation_get_name(prior));
#endif /* DEBUG || DEVELOPMENT */

#if PROC_REF_DEBUG
	if (__improbable(uthread_get_proc_refcount(ut) != 0)) {
		panic("system call returned with uu_proc_refcount != 0");
	}
#endif

	return;

bad:
	exc_code = call_number;
	exception_triage(EXC_SYSCALL, &exc_code, 1);
	/* NOTREACHED */
	panic("Returned from exception_triage()?\n");
}
#endif /* MACH_BSD */
