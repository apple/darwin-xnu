/*
 * Copyright (c) 2003-2006 Apple Computer, Inc. All rights reserved.
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

#include <stdint.h>
#include <mach/boolean.h>
#include <mach/mach_types.h>

#include <sys/syscall.h>
#include <sys/types.h> /* u_int */
#include <sys/proc.h> /* proc_t */
#include <sys/systm.h> /* struct sysent */
#include <sys/sysproto.h>
#include <sys/kdebug.h>	/* KDEBUG_ENABLE_CHUD */
#include <libkern/OSAtomic.h>

#ifdef __ppc__
#include <ppc/savearea.h>

#define FM_ARG0				0x38ULL	// offset from r1 to first argument
#define SPILLED_WORD_COUNT	7		// number of 32-bit words spilled to the stack

extern struct savearea * find_user_regs( thread_t act);
#endif

#pragma mark **** kern debug ****
typedef void (*chudxnu_kdebug_callback_func_t)(uint32_t debugid, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4);
static void chud_null_kdebug(uint32_t debugid, uintptr_t arg0, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4);
static chudxnu_kdebug_callback_func_t kdebug_callback_fn = chud_null_kdebug;

kern_return_t chudxnu_kdebug_callback_enter(chudxnu_kdebug_callback_func_t);
kern_return_t chudxnu_kdebug_callback_cancel(void);

extern void kdbg_control_chud(int val, void *fn);

static void chud_null_kdebug(uint32_t debugid __unused, uintptr_t arg0 __unused,
	uintptr_t arg1 __unused, uintptr_t arg2 __unused, uintptr_t arg3 __unused, 
	uintptr_t arg4 __unused) {
	return;
}

static void
chudxnu_private_kdebug_callback(
	uint32_t debugid,
	uintptr_t arg0,
	uintptr_t arg1,
	uintptr_t arg2,
	uintptr_t arg3,
	uintptr_t arg4)
{
    chudxnu_kdebug_callback_func_t fn = kdebug_callback_fn;
    
    if(fn) {
        (fn)(debugid, arg0, arg1, arg2, arg3, arg4);
    }
}

__private_extern__ kern_return_t
chudxnu_kdebug_callback_enter(chudxnu_kdebug_callback_func_t func)
{
	/* Atomically set the callback. */
	if(OSCompareAndSwapPtr(chud_null_kdebug, func, 
		(void * volatile *)&kdebug_callback_fn)) {
		
		kdbg_control_chud(TRUE, (void *)chudxnu_private_kdebug_callback);
		OSBitOrAtomic((UInt32)KDEBUG_ENABLE_CHUD, (volatile UInt32 *)&kdebug_enable);
		
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

__private_extern__ kern_return_t
chudxnu_kdebug_callback_cancel(void)
{
	OSBitAndAtomic((UInt32)~(KDEBUG_ENABLE_CHUD), (volatile UInt32 *)&kdebug_enable);
	kdbg_control_chud(FALSE, NULL);

	chudxnu_kdebug_callback_func_t old = kdebug_callback_fn;

	while(!OSCompareAndSwapPtr(old, chud_null_kdebug, 
		(void * volatile *)&kdebug_callback_fn)) {
		old = kdebug_callback_fn;
	}

    return KERN_SUCCESS;
}

#pragma mark **** CHUD syscall ****
typedef kern_return_t (*chudxnu_syscall_callback_func_t)(uint64_t code, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);

static kern_return_t chud_null_syscall(uint64_t code, uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);
static chudxnu_syscall_callback_func_t syscall_callback_fn = chud_null_syscall;

kern_return_t chudxnu_syscall_callback_enter(chudxnu_syscall_callback_func_t func);
kern_return_t chudxnu_syscall_callback_cancel(void);

static kern_return_t chud_null_syscall(uint64_t code __unused, 
	uint64_t arg0 __unused, uint64_t arg1 __unused, uint64_t arg2 __unused, 
	uint64_t arg3 __unused, uint64_t arg4 __unused) {
	return (kern_return_t)EINVAL;
}

/*
 * chud
 *
 * Performs performance-related tasks.  A private interface registers a handler for this
 * system call.  The implementation is in the CHUDProf kernel extension.
 *
 * chud() is a callback style system call used by the CHUD Tools suite of performance tools.  If the CHUD 
 * kexts are not loaded, this system call will always return EINVAL.  The CHUD kexts contain the 
 * implementation of the system call.
 * 
 * The current behavior of the chud() system call is as follows: 
 *
 * Parameters:	p	(ignored)
 * 		uap	User argument descriptor (see below)
 * 		retval	return value of fn (the function returned by syscall_callback_fn) 
 *
 * Indirect parameters:	uap->code	Selects the operation to do.  This is broken down into a
 * 					16-bit facility and a 16-bit action.
 *
 * The rest of the indirect parameters depend on the facility and the action that is selected:
 *
 * Facility: 1    Amber instruction tracer
 * 	Action: 1	Indicate that a new thread has been created.  No arguments are used.
 *
 * 	Action: 2	Indicate that a thread is about to exit.  No arguments are used.
 *
 * Facility: 2   Not Supported for this system call
 *
 * Facility: 3	 CHUD Trace facility
 * 	Action: 1	Record a backtrace of the calling process into the CHUD Trace facility sample
 * 			buffer.
 * 		
 * 			uap->arg1	Number of frames to skip
 * 			uap->arg2	Pointer to a uint64_t containing a timestamp for the
 * 					beginning of the sample.  NULL uses the current time.
 * 			uap->arg3	Pointer to a uint64_t containing a timestamp for the end
 * 					of the sample.  NULL uses the current time.
 * 			uap->arg4	Pointer to auxiliary data to be recorded with the sample
 * 			uap->arg5	Size of the auxiliary data pointed to by arg4.
 * 		
 * Returns:	EINVAL		If syscall_callback_fn returns an invalid function
 * 		KERN_SUCCESS	Success
 *		KERN_FAILURE	Generic failure
 *		KERN_NO_SPACE	Auxiliary data is too large (only used by Facility: 3)
 *
 * Implicit returns:	retval		return value of fn (the function returned by syscall_callback_fn)
 */
int
chud(__unused proc_t p, struct chud_args *uap, int32_t *retval)
{
    chudxnu_syscall_callback_func_t fn = syscall_callback_fn;
    
	if(!fn) {
		return EINVAL;
	}

#ifdef __ppc__
	// ppc32 user land spills 2.5 64-bit args (5 x 32-bit) to the stack
	// here we have to copy them out.  r1 is the stack pointer in this world.
	// the offset is calculated according to the PPC32 ABI
	// Important: this only happens for 32-bit user threads

	if(!IS_64BIT_PROCESS(p)) {
		struct savearea *regs = find_user_regs(current_thread());
		if(!regs) {
			return EINVAL;
		}

		// %r1 is the stack pointer on ppc32
		uint32_t stackPointer = regs->save_r1;

		// calculate number of bytes spilled to the stack
		uint32_t spilledSize = sizeof(struct chud_args) - (sizeof(uint32_t) * SPILLED_WORD_COUNT);

		// obtain offset to arguments spilled onto user-thread stack
		user_addr_t incomingAddr = (user_addr_t)stackPointer + FM_ARG0;

		// destination is halfway through arg3
		uint8_t *dstAddr = (uint8_t*)(&(uap->arg3)) + sizeof(uint32_t);
		
		copyin(incomingAddr, dstAddr, spilledSize);
	}
#endif
	
	*retval = fn(uap->code, uap->arg1, uap->arg2, uap->arg3, uap->arg4, uap->arg5);
		
	return 0;
}

__private_extern__ kern_return_t 
chudxnu_syscall_callback_enter(chudxnu_syscall_callback_func_t func)
{
	if(OSCompareAndSwapPtr(chud_null_syscall, func, 
		(void * volatile *)&syscall_callback_fn)) {
		return KERN_SUCCESS;
	}
	return KERN_FAILURE;
}

__private_extern__ kern_return_t
chudxnu_syscall_callback_cancel(void)
{
	chudxnu_syscall_callback_func_t old = syscall_callback_fn;

	while(!OSCompareAndSwapPtr(old, chud_null_syscall,
		(void * volatile *)&syscall_callback_fn)) {
		old = syscall_callback_fn;
	}

    return KERN_SUCCESS;
}

/* DTrace callback */
typedef kern_return_t (*chudxnu_dtrace_callback_t)(uint64_t selector, 
	uint64_t *args, uint32_t count);
int chudxnu_dtrace_callback(uint64_t selector, uint64_t *args, uint32_t count);
kern_return_t chudxnu_dtrace_callback_enter(chudxnu_dtrace_callback_t fn);
void chudxnu_dtrace_callback_cancel(void);

int
chud_null_dtrace(uint64_t selector, uint64_t *args, uint32_t count);

static chudxnu_dtrace_callback_t 
	dtrace_callback = (chudxnu_dtrace_callback_t) chud_null_dtrace;

int
chud_null_dtrace(uint64_t selector __unused, uint64_t *args __unused, 
	uint32_t count __unused) {
	return ENXIO;
}

int
chudxnu_dtrace_callback(uint64_t selector, uint64_t *args, uint32_t count)
{
	/* If no callback is hooked up, let's return ENXIO */
	int ret = ENXIO;

	/* Make a local stack copy of the function ptr */
	chudxnu_dtrace_callback_t fn = dtrace_callback;

	if(fn) {
		ret = fn(selector, args, count);
	}

	return ret;
}

__private_extern__ kern_return_t
chudxnu_dtrace_callback_enter(chudxnu_dtrace_callback_t fn)
{
	/* Atomically enter the call back */
	if(!OSCompareAndSwapPtr(chud_null_dtrace, fn, 
		(void * volatile *) &dtrace_callback)) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

__private_extern__ void
chudxnu_dtrace_callback_cancel(void)
{
	chudxnu_dtrace_callback_t old_fn = dtrace_callback;

	/* Atomically clear the call back */
	while(!OSCompareAndSwapPtr(old_fn, chud_null_dtrace, 
		(void * volatile *) &dtrace_callback)) {
		old_fn = dtrace_callback;
	}
}

