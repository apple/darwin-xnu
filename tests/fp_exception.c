/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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
/**
 * On devices that support it, this test ensures that a mach exception is
 * generated when an ARMv8 floating point exception is triggered.
 */
#include <darwintest.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/thread_status.h>
#include <mach/exception.h>
#include <pthread.h>

#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

/* The bit to set in FPCR to enable the divide-by-zero floating point exception. */
#define FPCR_DIV_EXC 0x200

/* Whether we caught the EXC_ARITHMETIC mach exception or not. */
static volatile bool mach_exc_caught = false;

/**
 * mach_exc_server() is a MIG-generated function that verifies the message
 * that was received is indeed a mach exception and then calls
 * catch_mach_exception_raise_state() to handle the exception.
 */
extern boolean_t mach_exc_server(mach_msg_header_t *, mach_msg_header_t *);

/**
 * This has to be defined for linking purposes, but it's unused in this test.
 */
kern_return_t
catch_mach_exception_raise(
	mach_port_t exception_port,
	mach_port_t thread,
	mach_port_t task,
	exception_type_t type,
	exception_data_t codes,
	mach_msg_type_number_t code_count)
{
#pragma unused(exception_port, thread, task, type, codes, code_count)
	T_FAIL("Triggered catch_mach_exception_raise() which shouldn't happen...");
	__builtin_unreachable();
}

/**
 * Called by mach_exc_server() to handle the exception. This will verify the
 * exception is a floating point divide-by-zero exception and will then modify
 * the thread state to move to the next instruction.
 */
kern_return_t
catch_mach_exception_raise_state(
	mach_port_t exception_port,
	exception_type_t type,
	exception_data_t codes,
	mach_msg_type_number_t code_count,
	int *flavor,
	thread_state_t in_state,
	mach_msg_type_number_t in_state_count,
	thread_state_t out_state,
	mach_msg_type_number_t *out_state_count)
{
#pragma unused(exception_port, type, codes, code_count, flavor, in_state, in_state_count, out_state, out_state_count)
#ifdef __arm64__
	T_LOG("Caught a mach exception!\n");

	/* Floating point divide by zero should cause an EXC_ARITHMETIC exception. */
	T_ASSERT_EQ(type, EXC_ARITHMETIC, "Caught an EXC_ARITHMETIC exception");

	/* There should only be two code vales. */
	T_ASSERT_EQ(code_count, 2, "Two code values were provided with the mach exception");

	/**
	 * The code values should be 64-bit since MACH_EXCEPTION_CODES was specified
	 * when setting the exception port.
	 */
	uint64_t *codes_64 = (uint64_t*)codes;
	T_LOG("Mach exception codes[0]: %#llx, codes[1]: %#llx\n", codes_64[0], codes_64[1]);

	/* Verify that we're receiving 64-bit ARM thread state values. */
	T_ASSERT_EQ(*flavor, ARM_THREAD_STATE64, "The thread state flavor is ARM_THREAD_STATE64");
	T_ASSERT_EQ(in_state_count, ARM_THREAD_STATE64_COUNT, "The thread state count is ARM_THREAD_STATE64_COUNT");

	/* Verify the exception is a floating point divide-by-zero exception. */
	T_ASSERT_EQ(codes_64[0], EXC_ARM_FP_DZ, "The subcode is EXC_ARM_FP_DZ (floating point divide-by-zero)");

	/**
	 * Increment the PC to the next instruction so the thread doesn't cause
	 * another exception when it resumes.
	 */
	*out_state_count = in_state_count; /* size of state object in 32-bit words */
	memcpy((void*)out_state, (void*)in_state, in_state_count * 4);
	arm_thread_state64_t *state = (arm_thread_state64_t*)out_state;

	void *pc = (void*)(arm_thread_state64_get_pc(*state) + 4);
#if __has_feature(ptrauth_calls)
	/* Have to sign the new PC value when pointer authentication is enabled. */
	pc = ptrauth_sign_unauthenticated(pc, ptrauth_key_function_pointer, 0);
#endif
	arm_thread_state64_set_pc_fptr(*state, pc);

	mach_exc_caught = true;
#endif /* __arm64__ */

	/* Return KERN_SUCCESS to tell the kernel to keep running the victim thread. */
	return KERN_SUCCESS;
}

/**
 * This has to be defined for linking purposes, but it's unused in this test.
 */
kern_return_t
catch_mach_exception_raise_state_identity(
	mach_port_t exception_port,
	mach_port_t thread,
	mach_port_t task,
	exception_type_t type,
	exception_data_t codes,
	mach_msg_type_number_t code_count,
	int *flavor,
	thread_state_t in_state,
	mach_msg_type_number_t in_state_count,
	thread_state_t out_state,
	mach_msg_type_number_t *out_state_count)
{
#pragma unused(exception_port, thread, task, type, codes, code_count, flavor, in_state, in_state_count, out_state, out_state_count)
	T_FAIL("Triggered catch_mach_exception_raise_state_identity() which shouldn't happen...");
	__builtin_unreachable();
}

/**
 * Thread to handle the mach exception generated by the floating point exception.
 *
 * @param arg The exception port to wait for a message on.
 */
void *
exc_server_thread(void *arg)
{
	mach_port_t exc_port = *(mach_port_t*)arg;

	/**
	 * mach_msg_server_once is a helper function provided by libsyscall that
	 * handles creating mach messages, blocks waiting for a message on the
	 * exception port, calls mach_exc_server() to handle the exception, and
	 * sends a reply based on the return value of mach_exc_server().
	 */
#define MACH_MSG_REPLY_SIZE 4096
	kern_return_t kr = mach_msg_server_once(mach_exc_server, MACH_MSG_REPLY_SIZE, exc_port, 0);
	T_ASSERT_MACH_SUCCESS(kr, "Received mach exception message");

	pthread_exit((void*)0);
	__builtin_unreachable();
}

T_DECL(armv8_fp_exception,
    "Test that ARMv8 floating point exceptions generate mach exceptions.")
{
#ifndef __arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else
	pthread_t exc_thread;
	mach_port_t exc_port = MACH_PORT_NULL;
	mach_port_t task = mach_task_self();
	mach_port_t thread = mach_thread_self();
	kern_return_t kr = KERN_SUCCESS;

	/* Attempt to enable Divide-by-Zero floating point exceptions in hardware. */
	uint64_t fpcr = __builtin_arm_rsr64("FPCR") | FPCR_DIV_EXC;
	__builtin_arm_wsr64("FPCR", fpcr);
#define DSB_ISH 0xb
	__builtin_arm_dsb(DSB_ISH);

	/* Devices that don't support floating point exceptions have FPCR as RAZ/WI. */
	if (__builtin_arm_rsr64("FPCR") != fpcr) {
		T_SKIP("Running on a device that doesn't support floating point exceptions, skipping...");
	}

	/* Create the mach port the exception messages will be sent to. */
	kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &exc_port);
	T_ASSERT_MACH_SUCCESS(kr, "Allocated mach exception port");

	/**
	 * Insert a send right into the exception port that the kernel will use to
	 * send the exception thread the exception messages.
	 */
	kr = mach_port_insert_right(task, exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);
	T_ASSERT_MACH_SUCCESS(kr, "Inserted a SEND right into the exception port");

	/* Tell the kernel what port to send EXC_ARITHMETIC exceptions to. */
	kr = thread_set_exception_ports(
		thread,
		EXC_MASK_ARITHMETIC,
		exc_port,
		EXCEPTION_STATE | MACH_EXCEPTION_CODES,
		ARM_THREAD_STATE64);
	T_ASSERT_MACH_SUCCESS(kr, "Set the exception port to my custom handler");

	/* Spawn the exception server's thread. */
	int err = pthread_create(&exc_thread, (pthread_attr_t*)0, exc_server_thread, (void*)&exc_port);
	T_ASSERT_POSIX_ZERO(err, "Spawned exception server thread");

	/* No need to wait for the exception server to be joined when it exits. */
	pthread_detach(exc_thread);

	/**
	 * This should cause a floating point divide-by-zero exception to get triggered.
	 *
	 * The kernel shouldn't resume this thread until the mach exception is handled
	 * by the exception server that was just spawned. The exception handler will
	 * explicitly increment the PC += 4 to move to the next instruction.
	 */
	float a = 6.5f;
	float b = 0.0f;
	__asm volatile ("fdiv %s0, %s1, %s2" : "=w" (a) : "w" (a), "w" (b));

	if (mach_exc_caught) {
		T_PASS("The expected floating point divide-by-zero exception was caught!");
	} else {
		T_FAIL("The floating point divide-by-zero exception was not captured :(");
	}
#endif /* __arm64__ */
}
