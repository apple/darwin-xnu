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
#include <debug.h>
#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <mach/thread_status.h>
#include <kern/thread.h>
#include <kern/kalloc.h>
#include <arm/vmparam.h>
#include <arm/cpu_data_internal.h>
#include <arm64/proc_reg.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif

struct arm_vfpv2_state {
	__uint32_t __r[32];
	__uint32_t __fpscr;
};

typedef struct arm_vfpv2_state arm_vfpv2_state_t;

#define ARM_VFPV2_STATE_COUNT \
	((mach_msg_type_number_t)(sizeof (arm_vfpv2_state_t)/sizeof(uint32_t)))

/*
 * Forward definitions
 */
void thread_set_child(thread_t child, int pid);
void thread_set_parent(thread_t parent, int pid);

/*
 * Maps state flavor to number of words in the state:
 */
/* __private_extern__ */
unsigned int _MachineStateCount[] = {
	[ARM_UNIFIED_THREAD_STATE] = ARM_UNIFIED_THREAD_STATE_COUNT,
	[ARM_VFP_STATE] = ARM_VFP_STATE_COUNT,
	[ARM_EXCEPTION_STATE] = ARM_EXCEPTION_STATE_COUNT,
	[ARM_DEBUG_STATE] = ARM_DEBUG_STATE_COUNT,
	[ARM_THREAD_STATE64] = ARM_THREAD_STATE64_COUNT,
	[ARM_EXCEPTION_STATE64] = ARM_EXCEPTION_STATE64_COUNT,
	[ARM_THREAD_STATE32] = ARM_THREAD_STATE32_COUNT,
	[ARM_DEBUG_STATE32] = ARM_DEBUG_STATE32_COUNT,
	[ARM_DEBUG_STATE64] = ARM_DEBUG_STATE64_COUNT,
	[ARM_NEON_STATE] = ARM_NEON_STATE_COUNT,
	[ARM_NEON_STATE64] = ARM_NEON_STATE64_COUNT,
	[ARM_PAGEIN_STATE] = ARM_PAGEIN_STATE_COUNT,
};

extern zone_t ads_zone;

#if __arm64__
/*
 * Copy values from saved_state to ts64.
 */
void
saved_state_to_thread_state64(const arm_saved_state_t * saved_state,
    arm_thread_state64_t *    ts64)
{
	uint32_t i;

	assert(is_saved_state64(saved_state));

	ts64->fp = get_saved_state_fp(saved_state);
	ts64->lr = get_saved_state_lr(saved_state);
	ts64->sp = get_saved_state_sp(saved_state);
	ts64->pc = get_saved_state_pc(saved_state);
	ts64->cpsr = get_saved_state_cpsr(saved_state);
	for (i = 0; i < 29; i++) {
		ts64->x[i] = get_saved_state_reg(saved_state, i);
	}
}

/*
 * Copy values from ts64 to saved_state
 */
void
thread_state64_to_saved_state(const arm_thread_state64_t * ts64,
    arm_saved_state_t *          saved_state)
{
	uint32_t i;

	assert(is_saved_state64(saved_state));

	set_saved_state_fp(saved_state, ts64->fp);
	set_saved_state_lr(saved_state, ts64->lr);
	set_saved_state_sp(saved_state, ts64->sp);
	set_saved_state_pc(saved_state, ts64->pc);
	set_saved_state_cpsr(saved_state, (ts64->cpsr & ~PSR64_MODE_MASK) | PSR64_MODE_RW_64);
	for (i = 0; i < 29; i++) {
		set_saved_state_reg(saved_state, i, ts64->x[i]);
	}
}

#endif /* __arm64__ */

static kern_return_t
handle_get_arm32_thread_state(thread_state_t            tstate,
    mach_msg_type_number_t *  count,
    const arm_saved_state_t * saved_state)
{
	if (*count < ARM_THREAD_STATE32_COUNT) {
		return KERN_INVALID_ARGUMENT;
	}
	if (!is_saved_state32(saved_state)) {
		return KERN_INVALID_ARGUMENT;
	}

	(void)saved_state_to_thread_state32(saved_state, (arm_thread_state32_t *)tstate);
	*count = ARM_THREAD_STATE32_COUNT;
	return KERN_SUCCESS;
}

static kern_return_t
handle_get_arm64_thread_state(thread_state_t            tstate,
    mach_msg_type_number_t *  count,
    const arm_saved_state_t * saved_state)
{
	if (*count < ARM_THREAD_STATE64_COUNT) {
		return KERN_INVALID_ARGUMENT;
	}
	if (!is_saved_state64(saved_state)) {
		return KERN_INVALID_ARGUMENT;
	}

	(void)saved_state_to_thread_state64(saved_state, (arm_thread_state64_t *)tstate);
	*count = ARM_THREAD_STATE64_COUNT;
	return KERN_SUCCESS;
}


static kern_return_t
handle_get_arm_thread_state(thread_state_t            tstate,
    mach_msg_type_number_t *  count,
    const arm_saved_state_t * saved_state)
{
	/* In an arm64 world, this flavor can be used to retrieve the thread
	 * state of a 32-bit or 64-bit thread into a unified structure, but we
	 * need to support legacy clients who are only aware of 32-bit, so
	 * check the count to see what the client is expecting.
	 */
	if (*count < ARM_UNIFIED_THREAD_STATE_COUNT) {
		return handle_get_arm32_thread_state(tstate, count, saved_state);
	}

	arm_unified_thread_state_t *unified_state = (arm_unified_thread_state_t *) tstate;
	bzero(unified_state, sizeof(*unified_state));
#if __arm64__
	if (is_saved_state64(saved_state)) {
		unified_state->ash.flavor = ARM_THREAD_STATE64;
		unified_state->ash.count = ARM_THREAD_STATE64_COUNT;
		(void)saved_state_to_thread_state64(saved_state, thread_state64(unified_state));
	} else
#endif
	{
		unified_state->ash.flavor = ARM_THREAD_STATE32;
		unified_state->ash.count = ARM_THREAD_STATE32_COUNT;
		(void)saved_state_to_thread_state32(saved_state, thread_state32(unified_state));
	}
	*count = ARM_UNIFIED_THREAD_STATE_COUNT;
	return KERN_SUCCESS;
}


static kern_return_t
handle_set_arm32_thread_state(const thread_state_t   tstate,
    mach_msg_type_number_t count,
    arm_saved_state_t *    saved_state)
{
	if (count != ARM_THREAD_STATE32_COUNT) {
		return KERN_INVALID_ARGUMENT;
	}

	(void)thread_state32_to_saved_state((const arm_thread_state32_t *)tstate, saved_state);
	return KERN_SUCCESS;
}

static kern_return_t
handle_set_arm64_thread_state(const thread_state_t   tstate,
    mach_msg_type_number_t count,
    arm_saved_state_t *    saved_state)
{
	if (count != ARM_THREAD_STATE64_COUNT) {
		return KERN_INVALID_ARGUMENT;
	}

	(void)thread_state64_to_saved_state((const arm_thread_state64_t *)tstate, saved_state);
	return KERN_SUCCESS;
}


static kern_return_t
handle_set_arm_thread_state(const thread_state_t   tstate,
    mach_msg_type_number_t count,
    arm_saved_state_t *    saved_state)
{
	/* In an arm64 world, this flavor can be used to set the thread state of a
	 * 32-bit or 64-bit thread from a unified structure, but we need to support
	 * legacy clients who are only aware of 32-bit, so check the count to see
	 * what the client is expecting.
	 */
	if (count < ARM_UNIFIED_THREAD_STATE_COUNT) {
		if (!is_saved_state32(saved_state)) {
			return KERN_INVALID_ARGUMENT;
		}
		return handle_set_arm32_thread_state(tstate, count, saved_state);
	}

	const arm_unified_thread_state_t *unified_state = (const arm_unified_thread_state_t *) tstate;
#if __arm64__
	if (is_thread_state64(unified_state)) {
		if (!is_saved_state64(saved_state)) {
			return KERN_INVALID_ARGUMENT;
		}
		(void)thread_state64_to_saved_state(const_thread_state64(unified_state), saved_state);
	} else
#endif
	{
		if (!is_saved_state32(saved_state)) {
			return KERN_INVALID_ARGUMENT;
		}
		(void)thread_state32_to_saved_state(const_thread_state32(unified_state), saved_state);
	}

	return KERN_SUCCESS;
}


/*
 * Translate thread state arguments to userspace representation
 */

kern_return_t
machine_thread_state_convert_to_user(
	thread_t thread,
	thread_flavor_t flavor,
	thread_state_t tstate,
	mach_msg_type_number_t *count)
{
#if __has_feature(ptrauth_calls)
	arm_thread_state64_t *ts64;

	switch (flavor) {
	case ARM_THREAD_STATE:
	{
		arm_unified_thread_state_t *unified_state = (arm_unified_thread_state_t *)tstate;

		if (*count < ARM_UNIFIED_THREAD_STATE_COUNT || !is_thread_state64(unified_state)) {
			return KERN_SUCCESS;
		}
		ts64 = thread_state64(unified_state);
		break;
	}
	case ARM_THREAD_STATE64:
	{
		if (*count < ARM_THREAD_STATE64_COUNT) {
			return KERN_SUCCESS;
		}
		ts64 = (arm_thread_state64_t *)tstate;
		break;
	}
	default:
		return KERN_SUCCESS;
	}

	// Note that kernel threads never have disable_user_jop set
	if (current_thread()->machine.disable_user_jop || !thread_is_64bit_addr(current_thread()) ||
	    thread->machine.disable_user_jop || !thread_is_64bit_addr(thread) ||
	    (BootArgs->bootFlags & kBootFlagsDisableUserThreadStateJOP)) {
		ts64->flags = __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH;
		return KERN_SUCCESS;
	}

	ts64->flags = 0;
	if (ts64->lr) {
		// lr might contain an IB-signed return address (strip is a no-op on unsigned addresses)
		uintptr_t stripped_lr = (uintptr_t)ptrauth_strip((void *)ts64->lr,
		    ptrauth_key_return_address);
		if (ts64->lr != stripped_lr) {
			// Need to allow already-signed lr value to round-trip as is
			ts64->flags |= __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR;
		}
		// Note that an IB-signed return address that happens to have a 0 signature value
		// will round-trip correctly even if IA-signed again below (and IA-authd later)
	}

	if (BootArgs->bootFlags & kBootFlagsDisableUserJOP) {
		return KERN_SUCCESS;
	}

	if (ts64->pc) {
		ts64->pc = (uintptr_t)pmap_sign_user_ptr((void*)ts64->pc,
		    ptrauth_key_process_independent_code, ptrauth_string_discriminator("pc"));
	}
	if (ts64->lr && !(ts64->flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR)) {
		ts64->lr = (uintptr_t)pmap_sign_user_ptr((void*)ts64->lr,
		    ptrauth_key_process_independent_code, ptrauth_string_discriminator("lr"));
	}
	if (ts64->sp) {
		ts64->sp = (uintptr_t)pmap_sign_user_ptr((void*)ts64->sp,
		    ptrauth_key_process_independent_data, ptrauth_string_discriminator("sp"));
	}
	if (ts64->fp) {
		ts64->fp = (uintptr_t)pmap_sign_user_ptr((void*)ts64->fp,
		    ptrauth_key_process_independent_data, ptrauth_string_discriminator("fp"));
	}

	return KERN_SUCCESS;
#else
	// No conversion to userspace representation on this platform
	(void)thread; (void)flavor; (void)tstate; (void)count;
	return KERN_SUCCESS;
#endif /* __has_feature(ptrauth_calls) */
}

/*
 * Translate thread state arguments from userspace representation
 */

kern_return_t
machine_thread_state_convert_from_user(
	thread_t thread,
	thread_flavor_t flavor,
	thread_state_t tstate,
	mach_msg_type_number_t count)
{
#if __has_feature(ptrauth_calls)
	arm_thread_state64_t *ts64;

	switch (flavor) {
	case ARM_THREAD_STATE:
	{
		arm_unified_thread_state_t *unified_state = (arm_unified_thread_state_t *)tstate;

		if (count < ARM_UNIFIED_THREAD_STATE_COUNT || !is_thread_state64(unified_state)) {
			return KERN_SUCCESS;
		}
		ts64 = thread_state64(unified_state);
		break;
	}
	case ARM_THREAD_STATE64:
	{
		if (count != ARM_THREAD_STATE64_COUNT) {
			return KERN_SUCCESS;
		}
		ts64 = (arm_thread_state64_t *)tstate;
		break;
	}
	default:
		return KERN_SUCCESS;
	}

	// Note that kernel threads never have disable_user_jop set
	if (current_thread()->machine.disable_user_jop || !thread_is_64bit_addr(current_thread())) {
		if (thread->machine.disable_user_jop || !thread_is_64bit_addr(thread)) {
			ts64->flags = __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH;
			return KERN_SUCCESS;
		}
		// A JOP-disabled process must not set thread state on a JOP-enabled process
		return KERN_PROTECTION_FAILURE;
	}

	if (ts64->flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH) {
		if (thread->machine.disable_user_jop || !thread_is_64bit_addr(thread) ||
		    (BootArgs->bootFlags & kBootFlagsDisableUserThreadStateJOP)) {
			return KERN_SUCCESS;
		}
		// Disallow setting unsigned thread state on JOP-enabled processes.
		// Ignore flag and treat thread state arguments as signed, ptrauth
		// poisoning will cause resulting thread state to be invalid
		ts64->flags &= ~__DARWIN_ARM_THREAD_STATE64_FLAGS_NO_PTRAUTH;
	}

	if (ts64->flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR) {
		// lr might contain an IB-signed return address (strip is a no-op on unsigned addresses)
		uintptr_t stripped_lr = (uintptr_t)ptrauth_strip((void *)ts64->lr,
		    ptrauth_key_return_address);
		if (ts64->lr == stripped_lr) {
			// Don't allow unsigned pointer to be passed through as is. Ignore flag and
			// treat as IA-signed below (where auth failure may poison the value).
			ts64->flags &= ~__DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR;
		}
		// Note that an IB-signed return address that happens to have a 0 signature value
		// will also have been IA-signed (without this flag being set) and so will IA-auth
		// correctly below.
	}

	if (BootArgs->bootFlags & kBootFlagsDisableUserJOP) {
		return KERN_SUCCESS;
	}

	if (ts64->pc) {
		ts64->pc = (uintptr_t)pmap_auth_user_ptr((void*)ts64->pc,
		    ptrauth_key_process_independent_code, ptrauth_string_discriminator("pc"));
	}
	if (ts64->lr && !(ts64->flags & __DARWIN_ARM_THREAD_STATE64_FLAGS_IB_SIGNED_LR)) {
		ts64->lr = (uintptr_t)pmap_auth_user_ptr((void*)ts64->lr,
		    ptrauth_key_process_independent_code, ptrauth_string_discriminator("lr"));
	}
	if (ts64->sp) {
		ts64->sp = (uintptr_t)pmap_auth_user_ptr((void*)ts64->sp,
		    ptrauth_key_process_independent_data, ptrauth_string_discriminator("sp"));
	}
	if (ts64->fp) {
		ts64->fp = (uintptr_t)pmap_auth_user_ptr((void*)ts64->fp,
		    ptrauth_key_process_independent_data, ptrauth_string_discriminator("fp"));
	}

	return KERN_SUCCESS;
#else
	// No conversion from userspace representation on this platform
	(void)thread; (void)flavor; (void)tstate; (void)count;
	return KERN_SUCCESS;
#endif /* __has_feature(ptrauth_calls) */
}

/*
 * Translate signal context data pointer to userspace representation
 */

kern_return_t
machine_thread_siguctx_pointer_convert_to_user(
	__assert_only thread_t thread,
	user_addr_t *uctxp)
{
#if __has_feature(ptrauth_calls)
	if (current_thread()->machine.disable_user_jop || !thread_is_64bit_addr(current_thread())) {
		assert(thread->machine.disable_user_jop || !thread_is_64bit_addr(thread));
		return KERN_SUCCESS;
	}

	if (BootArgs->bootFlags & kBootFlagsDisableUserJOP) {
		return KERN_SUCCESS;
	}

	if (*uctxp) {
		*uctxp = (uintptr_t)pmap_sign_user_ptr((void*)*uctxp,
		    ptrauth_key_process_independent_data, ptrauth_string_discriminator("uctx"));
	}

	return KERN_SUCCESS;
#else
	// No conversion to userspace representation on this platform
	(void)thread; (void)uctxp;
	return KERN_SUCCESS;
#endif /* __has_feature(ptrauth_calls) */
}

/*
 * Translate array of function pointer syscall arguments from userspace representation
 */

kern_return_t
machine_thread_function_pointers_convert_from_user(
	__assert_only thread_t thread,
	user_addr_t *fptrs,
	uint32_t count)
{
#if __has_feature(ptrauth_calls)
	if (current_thread()->machine.disable_user_jop || !thread_is_64bit_addr(current_thread())) {
		assert(thread->machine.disable_user_jop || !thread_is_64bit_addr(thread));
		return KERN_SUCCESS;
	}

	if (BootArgs->bootFlags & kBootFlagsDisableUserJOP) {
		return KERN_SUCCESS;
	}

	while (count--) {
		if (*fptrs) {
			*fptrs = (uintptr_t)pmap_auth_user_ptr((void*)*fptrs,
			    ptrauth_key_function_pointer, 0);
		}
		fptrs++;
	}

	return KERN_SUCCESS;
#else
	// No conversion from userspace representation on this platform
	(void)thread; (void)fptrs; (void)count;
	return KERN_SUCCESS;
#endif /* __has_feature(ptrauth_calls) */
}

/*
 * Routine: machine_thread_get_state
 *
 */
kern_return_t
machine_thread_get_state(thread_t                 thread,
    thread_flavor_t          flavor,
    thread_state_t           tstate,
    mach_msg_type_number_t * count)
{
	switch (flavor) {
	case THREAD_STATE_FLAVOR_LIST:
		if (*count < 4) {
			return KERN_INVALID_ARGUMENT;
		}

		tstate[0] = ARM_THREAD_STATE;
		tstate[1] = ARM_VFP_STATE;
		tstate[2] = ARM_EXCEPTION_STATE;
		tstate[3] = ARM_DEBUG_STATE;
		*count = 4;
		break;

	case THREAD_STATE_FLAVOR_LIST_NEW:
		if (*count < 4) {
			return KERN_INVALID_ARGUMENT;
		}

		tstate[0] = ARM_THREAD_STATE;
		tstate[1] = ARM_VFP_STATE;
		tstate[2] = thread_is_64bit_data(thread) ? ARM_EXCEPTION_STATE64 : ARM_EXCEPTION_STATE;
		tstate[3] = thread_is_64bit_data(thread) ? ARM_DEBUG_STATE64 : ARM_DEBUG_STATE32;
		*count = 4;
		break;

	case THREAD_STATE_FLAVOR_LIST_10_15:
		if (*count < 5) {
			return KERN_INVALID_ARGUMENT;
		}

		tstate[0] = ARM_THREAD_STATE;
		tstate[1] = ARM_VFP_STATE;
		tstate[2] = thread_is_64bit_data(thread) ? ARM_EXCEPTION_STATE64 : ARM_EXCEPTION_STATE;
		tstate[3] = thread_is_64bit_data(thread) ? ARM_DEBUG_STATE64 : ARM_DEBUG_STATE32;
		tstate[4] = ARM_PAGEIN_STATE;
		*count = 5;
		break;

	case ARM_THREAD_STATE:
	{
		kern_return_t rn = handle_get_arm_thread_state(tstate, count, thread->machine.upcb);
		if (rn) {
			return rn;
		}
		break;
	}
	case ARM_THREAD_STATE32:
	{
		if (thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		kern_return_t rn = handle_get_arm32_thread_state(tstate, count, thread->machine.upcb);
		if (rn) {
			return rn;
		}
		break;
	}
#if __arm64__
	case ARM_THREAD_STATE64:
	{
		if (!thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		kern_return_t rn = handle_get_arm64_thread_state(tstate, count, thread->machine.upcb);
		if (rn) {
			return rn;
		}
		break;
	}
#endif
	case ARM_EXCEPTION_STATE:{
		struct arm_exception_state *state;
		struct arm_saved_state32 *saved_state;

		if (*count < ARM_EXCEPTION_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		if (thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (struct arm_exception_state *) tstate;
		saved_state = saved_state32(thread->machine.upcb);

		state->exception = saved_state->exception;
		state->fsr = saved_state->esr;
		state->far = saved_state->far;

		*count = ARM_EXCEPTION_STATE_COUNT;
		break;
	}
	case ARM_EXCEPTION_STATE64:{
		struct arm_exception_state64 *state;
		struct arm_saved_state64 *saved_state;

		if (*count < ARM_EXCEPTION_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		if (!thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (struct arm_exception_state64 *) tstate;
		saved_state = saved_state64(thread->machine.upcb);

		state->exception = saved_state->exception;
		state->far = saved_state->far;
		state->esr = saved_state->esr;

		*count = ARM_EXCEPTION_STATE64_COUNT;
		break;
	}
	case ARM_DEBUG_STATE:{
		arm_legacy_debug_state_t *state;
		arm_debug_state32_t *thread_state;

		if (*count < ARM_LEGACY_DEBUG_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (arm_legacy_debug_state_t *) tstate;
		thread_state = find_debug_state32(thread);

		if (thread_state == NULL) {
			bzero(state, sizeof(arm_legacy_debug_state_t));
		} else {
			bcopy(thread_state, state, sizeof(arm_legacy_debug_state_t));
		}

		*count = ARM_LEGACY_DEBUG_STATE_COUNT;
		break;
	}
	case ARM_DEBUG_STATE32:{
		arm_debug_state32_t *state;
		arm_debug_state32_t *thread_state;

		if (*count < ARM_DEBUG_STATE32_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (arm_debug_state32_t *) tstate;
		thread_state = find_debug_state32(thread);

		if (thread_state == NULL) {
			bzero(state, sizeof(arm_debug_state32_t));
		} else {
			bcopy(thread_state, state, sizeof(arm_debug_state32_t));
		}

		*count = ARM_DEBUG_STATE32_COUNT;
		break;
	}

	case ARM_DEBUG_STATE64:{
		arm_debug_state64_t *state;
		arm_debug_state64_t *thread_state;

		if (*count < ARM_DEBUG_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (arm_debug_state64_t *) tstate;
		thread_state = find_debug_state64(thread);

		if (thread_state == NULL) {
			bzero(state, sizeof(arm_debug_state64_t));
		} else {
			bcopy(thread_state, state, sizeof(arm_debug_state64_t));
		}

		*count = ARM_DEBUG_STATE64_COUNT;
		break;
	}

	case ARM_VFP_STATE:{
		struct arm_vfp_state *state;
		arm_neon_saved_state32_t *thread_state;
		unsigned int max;

		if (*count < ARM_VFP_STATE_COUNT) {
			if (*count < ARM_VFPV2_STATE_COUNT) {
				return KERN_INVALID_ARGUMENT;
			} else {
				*count =  ARM_VFPV2_STATE_COUNT;
			}
		}

		if (*count == ARM_VFPV2_STATE_COUNT) {
			max = 32;
		} else {
			max = 64;
		}

		state = (struct arm_vfp_state *) tstate;
		thread_state = neon_state32(thread->machine.uNeon);
		/* ARM64 TODO: set fpsr and fpcr from state->fpscr */

		bcopy(thread_state, state, (max + 1) * sizeof(uint32_t));
		*count = (max + 1);
		break;
	}
	case ARM_NEON_STATE:{
		arm_neon_state_t *state;
		arm_neon_saved_state32_t *thread_state;

		if (*count < ARM_NEON_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (arm_neon_state_t *)tstate;
		thread_state = neon_state32(thread->machine.uNeon);

		assert(sizeof(*thread_state) == sizeof(*state));
		bcopy(thread_state, state, sizeof(arm_neon_state_t));

		*count = ARM_NEON_STATE_COUNT;
		break;
	}

	case ARM_NEON_STATE64:{
		arm_neon_state64_t *state;
		arm_neon_saved_state64_t *thread_state;

		if (*count < ARM_NEON_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (arm_neon_state64_t *)tstate;
		thread_state = neon_state64(thread->machine.uNeon);

		/* For now, these are identical */
		assert(sizeof(*state) == sizeof(*thread_state));
		bcopy(thread_state, state, sizeof(arm_neon_state64_t));

		*count = ARM_NEON_STATE64_COUNT;
		break;
	}


	case ARM_PAGEIN_STATE: {
		arm_pagein_state_t *state;

		if (*count < ARM_PAGEIN_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (arm_pagein_state_t *)tstate;
		state->__pagein_error = thread->t_pagein_error;

		*count = ARM_PAGEIN_STATE_COUNT;
		break;
	}


	default:
		return KERN_INVALID_ARGUMENT;
	}
	return KERN_SUCCESS;
}


/*
 * Routine: machine_thread_get_kern_state
 *
 */
kern_return_t
machine_thread_get_kern_state(thread_t                 thread,
    thread_flavor_t          flavor,
    thread_state_t           tstate,
    mach_msg_type_number_t * count)
{
	/*
	 * This works only for an interrupted kernel thread
	 */
	if (thread != current_thread() || getCpuDatap()->cpu_int_state == NULL) {
		return KERN_FAILURE;
	}

	switch (flavor) {
	case ARM_THREAD_STATE:
	{
		kern_return_t rn = handle_get_arm_thread_state(tstate, count, getCpuDatap()->cpu_int_state);
		if (rn) {
			return rn;
		}
		break;
	}
	case ARM_THREAD_STATE32:
	{
		kern_return_t rn = handle_get_arm32_thread_state(tstate, count, getCpuDatap()->cpu_int_state);
		if (rn) {
			return rn;
		}
		break;
	}
#if __arm64__
	case ARM_THREAD_STATE64:
	{
		kern_return_t rn = handle_get_arm64_thread_state(tstate, count, getCpuDatap()->cpu_int_state);
		if (rn) {
			return rn;
		}
		break;
	}
#endif
	default:
		return KERN_INVALID_ARGUMENT;
	}
	return KERN_SUCCESS;
}

void
machine_thread_switch_addrmode(thread_t thread)
{
	if (task_has_64Bit_data(thread->task)) {
		thread->machine.upcb->ash.flavor = ARM_SAVED_STATE64;
		thread->machine.upcb->ash.count = ARM_SAVED_STATE64_COUNT;
		thread->machine.uNeon->nsh.flavor = ARM_NEON_SAVED_STATE64;
		thread->machine.uNeon->nsh.count = ARM_NEON_SAVED_STATE64_COUNT;

		/*
		 * Reinitialize the NEON state.
		 */
		bzero(&thread->machine.uNeon->uns, sizeof(thread->machine.uNeon->uns));
		thread->machine.uNeon->ns_64.fpcr = FPCR_DEFAULT;
	} else {
		thread->machine.upcb->ash.flavor = ARM_SAVED_STATE32;
		thread->machine.upcb->ash.count = ARM_SAVED_STATE32_COUNT;
		thread->machine.uNeon->nsh.flavor = ARM_NEON_SAVED_STATE32;
		thread->machine.uNeon->nsh.count = ARM_NEON_SAVED_STATE32_COUNT;

		/*
		 * Reinitialize the NEON state.
		 */
		bzero(&thread->machine.uNeon->uns, sizeof(thread->machine.uNeon->uns));
		thread->machine.uNeon->ns_32.fpcr = FPCR_DEFAULT_32;
	}
}

extern long long arm_debug_get(void);

/*
 * Routine: machine_thread_set_state
 *
 */
kern_return_t
machine_thread_set_state(thread_t               thread,
    thread_flavor_t        flavor,
    thread_state_t         tstate,
    mach_msg_type_number_t count)
{
	kern_return_t rn;

	switch (flavor) {
	case ARM_THREAD_STATE:
		rn = handle_set_arm_thread_state(tstate, count, thread->machine.upcb);
		if (rn) {
			return rn;
		}
		break;

	case ARM_THREAD_STATE32:
		if (thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		rn = handle_set_arm32_thread_state(tstate, count, thread->machine.upcb);
		if (rn) {
			return rn;
		}
		break;

#if __arm64__
	case ARM_THREAD_STATE64:
		if (!thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		rn = handle_set_arm64_thread_state(tstate, count, thread->machine.upcb);
		if (rn) {
			return rn;
		}
		break;
#endif
	case ARM_EXCEPTION_STATE:{
		if (count != ARM_EXCEPTION_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		if (thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		break;
	}
	case ARM_EXCEPTION_STATE64:{
		if (count != ARM_EXCEPTION_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		if (!thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		break;
	}
	case ARM_DEBUG_STATE:
	{
		arm_legacy_debug_state_t *state;
		boolean_t enabled = FALSE;
		unsigned int    i;

		if (count != ARM_LEGACY_DEBUG_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		if (thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (arm_legacy_debug_state_t *) tstate;

		for (i = 0; i < 16; i++) {
			/* do not allow context IDs to be set */
			if (((state->bcr[i] & ARM_DBGBCR_TYPE_MASK) != ARM_DBGBCR_TYPE_IVA)
			    || ((state->bcr[i] & ARM_DBG_CR_LINKED_MASK) != ARM_DBG_CR_LINKED_UNLINKED)
			    || ((state->wcr[i] & ARM_DBGBCR_TYPE_MASK) != ARM_DBGBCR_TYPE_IVA)
			    || ((state->wcr[i] & ARM_DBG_CR_LINKED_MASK) != ARM_DBG_CR_LINKED_UNLINKED)) {
				return KERN_PROTECTION_FAILURE;
			}
			if ((((state->bcr[i] & ARM_DBG_CR_ENABLE_MASK) == ARM_DBG_CR_ENABLE_ENABLE))
			    || ((state->wcr[i] & ARM_DBG_CR_ENABLE_MASK) == ARM_DBG_CR_ENABLE_ENABLE)) {
				enabled = TRUE;
			}
		}

		if (!enabled) {
			arm_debug_state32_t *thread_state = find_debug_state32(thread);
			if (thread_state != NULL) {
				void *pTmp = thread->machine.DebugData;
				thread->machine.DebugData = NULL;
				zfree(ads_zone, pTmp);
			}
		} else {
			arm_debug_state32_t *thread_state = find_debug_state32(thread);
			if (thread_state == NULL) {
				thread->machine.DebugData = zalloc(ads_zone);
				bzero(thread->machine.DebugData, sizeof *(thread->machine.DebugData));
				thread->machine.DebugData->dsh.flavor = ARM_DEBUG_STATE32;
				thread->machine.DebugData->dsh.count = ARM_DEBUG_STATE32_COUNT;
				thread_state = find_debug_state32(thread);
			}
			assert(NULL != thread_state);

			for (i = 0; i < 16; i++) {
				/* set appropriate privilege; mask out unknown bits */
				thread_state->bcr[i] = (state->bcr[i] & (ARM_DBG_CR_ADDRESS_MASK_MASK
				    | ARM_DBGBCR_MATCH_MASK
				    | ARM_DBG_CR_BYTE_ADDRESS_SELECT_MASK
				    | ARM_DBG_CR_ENABLE_MASK))
				    | ARM_DBGBCR_TYPE_IVA
				    | ARM_DBG_CR_LINKED_UNLINKED
				    | ARM_DBG_CR_SECURITY_STATE_BOTH
				    | ARM_DBG_CR_MODE_CONTROL_USER;
				thread_state->bvr[i] = state->bvr[i] & ARM_DBG_VR_ADDRESS_MASK;
				thread_state->wcr[i] = (state->wcr[i] & (ARM_DBG_CR_ADDRESS_MASK_MASK
				    | ARM_DBGWCR_BYTE_ADDRESS_SELECT_MASK
				    | ARM_DBGWCR_ACCESS_CONTROL_MASK
				    | ARM_DBG_CR_ENABLE_MASK))
				    | ARM_DBG_CR_LINKED_UNLINKED
				    | ARM_DBG_CR_SECURITY_STATE_BOTH
				    | ARM_DBG_CR_MODE_CONTROL_USER;
				thread_state->wvr[i] = state->wvr[i] & ARM_DBG_VR_ADDRESS_MASK;
			}

			thread_state->mdscr_el1 = 0ULL;         // Legacy customers issuing ARM_DEBUG_STATE dont drive single stepping.
		}

		if (thread == current_thread()) {
			arm_debug_set32(thread->machine.DebugData);
		}

		break;
	}
	case ARM_DEBUG_STATE32:
		/* ARM64_TODO  subtle bcr/wcr semantic differences e.g. wcr and ARM_DBGBCR_TYPE_IVA */
	{
		arm_debug_state32_t *state;
		boolean_t enabled = FALSE;
		unsigned int    i;

		if (count != ARM_DEBUG_STATE32_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		if (thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (arm_debug_state32_t *) tstate;

		if (state->mdscr_el1 & 0x1) {
			enabled = TRUE;
		}

		for (i = 0; i < 16; i++) {
			/* do not allow context IDs to be set */
			if (((state->bcr[i] & ARM_DBGBCR_TYPE_MASK) != ARM_DBGBCR_TYPE_IVA)
			    || ((state->bcr[i] & ARM_DBG_CR_LINKED_MASK) != ARM_DBG_CR_LINKED_UNLINKED)
			    || ((state->wcr[i] & ARM_DBGBCR_TYPE_MASK) != ARM_DBGBCR_TYPE_IVA)
			    || ((state->wcr[i] & ARM_DBG_CR_LINKED_MASK) != ARM_DBG_CR_LINKED_UNLINKED)) {
				return KERN_PROTECTION_FAILURE;
			}
			if ((((state->bcr[i] & ARM_DBG_CR_ENABLE_MASK) == ARM_DBG_CR_ENABLE_ENABLE))
			    || ((state->wcr[i] & ARM_DBG_CR_ENABLE_MASK) == ARM_DBG_CR_ENABLE_ENABLE)) {
				enabled = TRUE;
			}
		}

		if (!enabled) {
			arm_debug_state32_t *thread_state = find_debug_state32(thread);
			if (thread_state != NULL) {
				void *pTmp = thread->machine.DebugData;
				thread->machine.DebugData = NULL;
				zfree(ads_zone, pTmp);
			}
		} else {
			arm_debug_state32_t *thread_state = find_debug_state32(thread);
			if (thread_state == NULL) {
				thread->machine.DebugData = zalloc(ads_zone);
				bzero(thread->machine.DebugData, sizeof *(thread->machine.DebugData));
				thread->machine.DebugData->dsh.flavor = ARM_DEBUG_STATE32;
				thread->machine.DebugData->dsh.count = ARM_DEBUG_STATE32_COUNT;
				thread_state = find_debug_state32(thread);
			}
			assert(NULL != thread_state);

			if (state->mdscr_el1 & 0x1) {
				thread_state->mdscr_el1 |= 0x1;
			} else {
				thread_state->mdscr_el1 &= ~0x1;
			}

			for (i = 0; i < 16; i++) {
				/* set appropriate privilege; mask out unknown bits */
				thread_state->bcr[i] = (state->bcr[i] & (ARM_DBG_CR_ADDRESS_MASK_MASK
				    | ARM_DBGBCR_MATCH_MASK
				    | ARM_DBG_CR_BYTE_ADDRESS_SELECT_MASK
				    | ARM_DBG_CR_ENABLE_MASK))
				    | ARM_DBGBCR_TYPE_IVA
				    | ARM_DBG_CR_LINKED_UNLINKED
				    | ARM_DBG_CR_SECURITY_STATE_BOTH
				    | ARM_DBG_CR_MODE_CONTROL_USER;
				thread_state->bvr[i] = state->bvr[i] & ARM_DBG_VR_ADDRESS_MASK;
				thread_state->wcr[i] = (state->wcr[i] & (ARM_DBG_CR_ADDRESS_MASK_MASK
				    | ARM_DBGWCR_BYTE_ADDRESS_SELECT_MASK
				    | ARM_DBGWCR_ACCESS_CONTROL_MASK
				    | ARM_DBG_CR_ENABLE_MASK))
				    | ARM_DBG_CR_LINKED_UNLINKED
				    | ARM_DBG_CR_SECURITY_STATE_BOTH
				    | ARM_DBG_CR_MODE_CONTROL_USER;
				thread_state->wvr[i] = state->wvr[i] & ARM_DBG_VR_ADDRESS_MASK;
			}
		}

		if (thread == current_thread()) {
			arm_debug_set32(thread->machine.DebugData);
		}

		break;
	}

	case ARM_DEBUG_STATE64:
	{
		arm_debug_state64_t *state;
		boolean_t enabled = FALSE;
		unsigned int i;

		if (count != ARM_DEBUG_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		if (!thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (arm_debug_state64_t *) tstate;

		if (state->mdscr_el1 & 0x1) {
			enabled = TRUE;
		}

		for (i = 0; i < 16; i++) {
			/* do not allow context IDs to be set */
			if (((state->bcr[i] & ARM_DBGBCR_TYPE_MASK) != ARM_DBGBCR_TYPE_IVA)
			    || ((state->bcr[i] & ARM_DBG_CR_LINKED_MASK) != ARM_DBG_CR_LINKED_UNLINKED)
			    || ((state->wcr[i] & ARM_DBG_CR_LINKED_MASK) != ARM_DBG_CR_LINKED_UNLINKED)) {
				return KERN_PROTECTION_FAILURE;
			}
			if ((((state->bcr[i] & ARM_DBG_CR_ENABLE_MASK) == ARM_DBG_CR_ENABLE_ENABLE))
			    || ((state->wcr[i] & ARM_DBG_CR_ENABLE_MASK) == ARM_DBG_CR_ENABLE_ENABLE)) {
				enabled = TRUE;
			}
		}

		if (!enabled) {
			arm_debug_state64_t *thread_state = find_debug_state64(thread);
			if (thread_state != NULL) {
				void *pTmp = thread->machine.DebugData;
				thread->machine.DebugData = NULL;
				zfree(ads_zone, pTmp);
			}
		} else {
			arm_debug_state64_t *thread_state = find_debug_state64(thread);
			if (thread_state == NULL) {
				thread->machine.DebugData = zalloc(ads_zone);
				bzero(thread->machine.DebugData, sizeof *(thread->machine.DebugData));
				thread->machine.DebugData->dsh.flavor = ARM_DEBUG_STATE64;
				thread->machine.DebugData->dsh.count = ARM_DEBUG_STATE64_COUNT;
				thread_state = find_debug_state64(thread);
			}
			assert(NULL != thread_state);

			if (state->mdscr_el1 & 0x1) {
				thread_state->mdscr_el1 |= 0x1;
			} else {
				thread_state->mdscr_el1 &= ~0x1;
			}

			for (i = 0; i < 16; i++) {
				/* set appropriate privilege; mask out unknown bits */
				thread_state->bcr[i] = (state->bcr[i] & (0         /* Was ARM_DBG_CR_ADDRESS_MASK_MASK deprecated in v8 */
				    | 0                             /* Was ARM_DBGBCR_MATCH_MASK, ignored in AArch64 state */
				    | ARM_DBG_CR_BYTE_ADDRESS_SELECT_MASK
				    | ARM_DBG_CR_ENABLE_MASK))
				    | ARM_DBGBCR_TYPE_IVA
				    | ARM_DBG_CR_LINKED_UNLINKED
				    | ARM_DBG_CR_SECURITY_STATE_BOTH
				    | ARM_DBG_CR_MODE_CONTROL_USER;
				thread_state->bvr[i] = state->bvr[i] & ARM_DBG_VR_ADDRESS_MASK64;
				thread_state->wcr[i] = (state->wcr[i] & (ARM_DBG_CR_ADDRESS_MASK_MASK
				    | ARM_DBGWCR_BYTE_ADDRESS_SELECT_MASK
				    | ARM_DBGWCR_ACCESS_CONTROL_MASK
				    | ARM_DBG_CR_ENABLE_MASK))
				    | ARM_DBG_CR_LINKED_UNLINKED
				    | ARM_DBG_CR_SECURITY_STATE_BOTH
				    | ARM_DBG_CR_MODE_CONTROL_USER;
				thread_state->wvr[i] = state->wvr[i] & ARM_DBG_VR_ADDRESS_MASK64;
			}
		}

		if (thread == current_thread()) {
			arm_debug_set64(thread->machine.DebugData);
		}

		break;
	}

	case ARM_VFP_STATE:{
		struct arm_vfp_state *state;
		arm_neon_saved_state32_t *thread_state;
		unsigned int    max;

		if (count != ARM_VFP_STATE_COUNT && count != ARM_VFPV2_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (count == ARM_VFPV2_STATE_COUNT) {
			max = 32;
		} else {
			max = 64;
		}

		state = (struct arm_vfp_state *) tstate;
		thread_state = neon_state32(thread->machine.uNeon);
		/* ARM64 TODO: combine fpsr and fpcr into state->fpscr */

		bcopy(state, thread_state, (max + 1) * sizeof(uint32_t));

		thread->machine.uNeon->nsh.flavor = ARM_NEON_SAVED_STATE32;
		thread->machine.uNeon->nsh.count = ARM_NEON_SAVED_STATE32_COUNT;
		break;
	}

	case ARM_NEON_STATE:{
		arm_neon_state_t *state;
		arm_neon_saved_state32_t *thread_state;

		if (count != ARM_NEON_STATE_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (arm_neon_state_t *)tstate;
		thread_state = neon_state32(thread->machine.uNeon);

		assert(sizeof(*state) == sizeof(*thread_state));
		bcopy(state, thread_state, sizeof(arm_neon_state_t));

		thread->machine.uNeon->nsh.flavor = ARM_NEON_SAVED_STATE32;
		thread->machine.uNeon->nsh.count = ARM_NEON_SAVED_STATE32_COUNT;
		break;
	}

	case ARM_NEON_STATE64:{
		arm_neon_state64_t *state;
		arm_neon_saved_state64_t *thread_state;

		if (count != ARM_NEON_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}

		if (!thread_is_64bit_data(thread)) {
			return KERN_INVALID_ARGUMENT;
		}

		state = (arm_neon_state64_t *)tstate;
		thread_state = neon_state64(thread->machine.uNeon);

		assert(sizeof(*state) == sizeof(*thread_state));
		bcopy(state, thread_state, sizeof(arm_neon_state64_t));

		thread->machine.uNeon->nsh.flavor = ARM_NEON_SAVED_STATE64;
		thread->machine.uNeon->nsh.count = ARM_NEON_SAVED_STATE64_COUNT;
		break;
	}


	default:
		return KERN_INVALID_ARGUMENT;
	}
	return KERN_SUCCESS;
}

mach_vm_address_t
machine_thread_pc(thread_t thread)
{
	struct arm_saved_state *ss = get_user_regs(thread);
	return (mach_vm_address_t)get_saved_state_pc(ss);
}

void
machine_thread_reset_pc(thread_t thread, mach_vm_address_t pc)
{
	set_saved_state_pc(get_user_regs(thread), (register_t)pc);
}

/*
 * Routine: machine_thread_state_initialize
 *
 */
kern_return_t
machine_thread_state_initialize(thread_t thread)
{
	arm_context_t *context = thread->machine.contextData;

	/*
	 * Should always be set up later. For a kernel thread, we don't care
	 * about this state. For a user thread, we'll set the state up in
	 * setup_wqthread, bsdthread_create, load_main(), or load_unixthread().
	 */

	if (context != NULL) {
		bzero(&context->ss.uss, sizeof(context->ss.uss));
		bzero(&context->ns.uns, sizeof(context->ns.uns));

		if (context->ns.nsh.flavor == ARM_NEON_SAVED_STATE64) {
			context->ns.ns_64.fpcr = FPCR_DEFAULT;
		} else {
			context->ns.ns_32.fpcr = FPCR_DEFAULT_32;
		}
	}

	thread->machine.DebugData = NULL;

#if defined(HAS_APPLE_PAC)
	/* Sign the initial user-space thread state */
	if (thread->machine.upcb != NULL) {
		ml_sign_thread_state(thread->machine.upcb, 0, 0, 0, 0, 0);
	}
#endif /* defined(HAS_APPLE_PAC) */

	return KERN_SUCCESS;
}

/*
 * Routine: machine_thread_dup
 *
 */
kern_return_t
machine_thread_dup(thread_t self,
    thread_t target,
    __unused boolean_t is_corpse)
{
	struct arm_saved_state *self_saved_state;
	struct arm_saved_state *target_saved_state;

	target->machine.cthread_self = self->machine.cthread_self;
	target->machine.cthread_data = self->machine.cthread_data;

	self_saved_state = self->machine.upcb;
	target_saved_state = target->machine.upcb;
	bcopy(self_saved_state, target_saved_state, sizeof(struct arm_saved_state));
#if defined(HAS_APPLE_PAC)
	if (!is_corpse && is_saved_state64(self_saved_state)) {
		check_and_sign_copied_thread_state(target_saved_state, self_saved_state);
	}
#endif /* defined(HAS_APPLE_PAC) */

	return KERN_SUCCESS;
}

/*
 * Routine: get_user_regs
 *
 */
struct arm_saved_state *
get_user_regs(thread_t thread)
{
	return thread->machine.upcb;
}

arm_neon_saved_state_t *
get_user_neon_regs(thread_t thread)
{
	return thread->machine.uNeon;
}

/*
 * Routine: find_user_regs
 *
 */
struct arm_saved_state *
find_user_regs(thread_t thread)
{
	return thread->machine.upcb;
}

/*
 * Routine: find_kern_regs
 *
 */
struct arm_saved_state *
find_kern_regs(thread_t thread)
{
	/*
	 * This works only for an interrupted kernel thread
	 */
	if (thread != current_thread() || getCpuDatap()->cpu_int_state == NULL) {
		return (struct arm_saved_state *) NULL;
	} else {
		return getCpuDatap()->cpu_int_state;
	}
}

arm_debug_state32_t *
find_debug_state32(thread_t thread)
{
	if (thread && thread->machine.DebugData) {
		return &(thread->machine.DebugData->uds.ds32);
	} else {
		return NULL;
	}
}

arm_debug_state64_t *
find_debug_state64(thread_t thread)
{
	if (thread && thread->machine.DebugData) {
		return &(thread->machine.DebugData->uds.ds64);
	} else {
		return NULL;
	}
}

/*
 * Routine: thread_userstack
 *
 */
kern_return_t
thread_userstack(__unused thread_t  thread,
    int                flavor,
    thread_state_t     tstate,
    unsigned int       count,
    mach_vm_offset_t * user_stack,
    int *              customstack,
    boolean_t          is_64bit_data
    )
{
	register_t sp;

	switch (flavor) {
	case ARM_THREAD_STATE:
		if (count == ARM_UNIFIED_THREAD_STATE_COUNT) {
#if __arm64__
			if (is_64bit_data) {
				sp = ((arm_unified_thread_state_t *)tstate)->ts_64.sp;
			} else
#endif
			{
				sp = ((arm_unified_thread_state_t *)tstate)->ts_32.sp;
			}

			break;
		}

	/* INTENTIONAL FALL THROUGH (see machine_thread_set_state) */
	case ARM_THREAD_STATE32:
		if (count != ARM_THREAD_STATE32_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		if (is_64bit_data) {
			return KERN_INVALID_ARGUMENT;
		}

		sp = ((arm_thread_state32_t *)tstate)->sp;
		break;
#if __arm64__
	case ARM_THREAD_STATE64:
		if (count != ARM_THREAD_STATE64_COUNT) {
			return KERN_INVALID_ARGUMENT;
		}
		if (!is_64bit_data) {
			return KERN_INVALID_ARGUMENT;
		}

		sp = ((arm_thread_state32_t *)tstate)->sp;
		break;
#endif
	default:
		return KERN_INVALID_ARGUMENT;
	}

	if (sp) {
		*user_stack = CAST_USER_ADDR_T(sp);
		if (customstack) {
			*customstack = 1;
		}
	} else {
		*user_stack = CAST_USER_ADDR_T(USRSTACK64);
		if (customstack) {
			*customstack = 0;
		}
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
thread_userstackdefault(mach_vm_offset_t * default_user_stack,
    boolean_t          is64bit)
{
	if (is64bit) {
		*default_user_stack = USRSTACK64;
	} else {
		*default_user_stack = USRSTACK;
	}

	return KERN_SUCCESS;
}

/*
 * Routine: thread_setuserstack
 *
 */
void
thread_setuserstack(thread_t          thread,
    mach_vm_address_t user_stack)
{
	struct arm_saved_state *sv;

	sv = get_user_regs(thread);

	set_saved_state_sp(sv, user_stack);

	return;
}

/*
 * Routine: thread_adjuserstack
 *
 */
uint64_t
thread_adjuserstack(thread_t thread,
    int      adjust)
{
	struct arm_saved_state *sv;
	uint64_t sp;

	sv = get_user_regs(thread);

	sp = get_saved_state_sp(sv);
	sp += adjust;
	set_saved_state_sp(sv, sp);;

	return sp;
}

/*
 * Routine: thread_setentrypoint
 *
 */
void
thread_setentrypoint(thread_t         thread,
    mach_vm_offset_t entry)
{
	struct arm_saved_state *sv;

	sv = get_user_regs(thread);

	set_saved_state_pc(sv, entry);

	return;
}

/*
 * Routine: thread_entrypoint
 *
 */
kern_return_t
thread_entrypoint(__unused thread_t  thread,
    int                flavor,
    thread_state_t     tstate,
    unsigned int       count __unused,
    mach_vm_offset_t * entry_point
    )
{
	switch (flavor) {
	case ARM_THREAD_STATE:
	{
		struct arm_thread_state *state;

		state = (struct arm_thread_state *) tstate;

		/*
		 * If a valid entry point is specified, use it.
		 */
		if (state->pc) {
			*entry_point = CAST_USER_ADDR_T(state->pc);
		} else {
			*entry_point = CAST_USER_ADDR_T(VM_MIN_ADDRESS);
		}
	}
	break;

	case ARM_THREAD_STATE64:
	{
		struct arm_thread_state64 *state;

		state = (struct arm_thread_state64*) tstate;

		/*
		 * If a valid entry point is specified, use it.
		 */
		if (state->pc) {
			*entry_point = CAST_USER_ADDR_T(state->pc);
		} else {
			*entry_point = CAST_USER_ADDR_T(VM_MIN_ADDRESS);
		}

		break;
	}
	default:
		return KERN_INVALID_ARGUMENT;
	}

	return KERN_SUCCESS;
}


/*
 * Routine: thread_set_child
 *
 */
void
thread_set_child(thread_t child,
    int      pid)
{
	struct arm_saved_state *child_state;

	child_state = get_user_regs(child);

	set_saved_state_reg(child_state, 0, pid);
	set_saved_state_reg(child_state, 1, 1ULL);
}


/*
 * Routine: thread_set_parent
 *
 */
void
thread_set_parent(thread_t parent,
    int      pid)
{
	struct arm_saved_state *parent_state;

	parent_state = get_user_regs(parent);

	set_saved_state_reg(parent_state, 0, pid);
	set_saved_state_reg(parent_state, 1, 0);
}


struct arm_act_context {
	struct arm_unified_thread_state ss;
#if __ARM_VFP__
	struct arm_neon_saved_state ns;
#endif
};

/*
 * Routine: act_thread_csave
 *
 */
void *
act_thread_csave(void)
{
	struct arm_act_context *ic;
	kern_return_t   kret;
	unsigned int    val;
	thread_t thread = current_thread();

	ic = (struct arm_act_context *) kalloc(sizeof(struct arm_act_context));
	if (ic == (struct arm_act_context *) NULL) {
		return (void *) 0;
	}

	val = ARM_UNIFIED_THREAD_STATE_COUNT;
	kret = machine_thread_get_state(thread, ARM_THREAD_STATE, (thread_state_t)&ic->ss, &val);
	if (kret != KERN_SUCCESS) {
		kfree(ic, sizeof(struct arm_act_context));
		return (void *) 0;
	}

#if __ARM_VFP__
	if (thread_is_64bit_data(thread)) {
		val = ARM_NEON_STATE64_COUNT;
		kret = machine_thread_get_state(thread,
		    ARM_NEON_STATE64,
		    (thread_state_t)&ic->ns,
		    &val);
	} else {
		val = ARM_NEON_STATE_COUNT;
		kret = machine_thread_get_state(thread,
		    ARM_NEON_STATE,
		    (thread_state_t)&ic->ns,
		    &val);
	}
	if (kret != KERN_SUCCESS) {
		kfree(ic, sizeof(struct arm_act_context));
		return (void *) 0;
	}
#endif
	return ic;
}

/*
 * Routine: act_thread_catt
 *
 */
void
act_thread_catt(void * ctx)
{
	struct arm_act_context *ic;
	kern_return_t   kret;
	thread_t thread = current_thread();

	ic = (struct arm_act_context *) ctx;
	if (ic == (struct arm_act_context *) NULL) {
		return;
	}

	kret = machine_thread_set_state(thread, ARM_THREAD_STATE, (thread_state_t)&ic->ss, ARM_UNIFIED_THREAD_STATE_COUNT);
	if (kret != KERN_SUCCESS) {
		goto out;
	}

#if __ARM_VFP__
	if (thread_is_64bit_data(thread)) {
		kret = machine_thread_set_state(thread,
		    ARM_NEON_STATE64,
		    (thread_state_t)&ic->ns,
		    ARM_NEON_STATE64_COUNT);
	} else {
		kret = machine_thread_set_state(thread,
		    ARM_NEON_STATE,
		    (thread_state_t)&ic->ns,
		    ARM_NEON_STATE_COUNT);
	}
	if (kret != KERN_SUCCESS) {
		goto out;
	}
#endif
out:
	kfree(ic, sizeof(struct arm_act_context));
}

/*
 * Routine: act_thread_catt
 *
 */
void
act_thread_cfree(void *ctx)
{
	kfree(ctx, sizeof(struct arm_act_context));
}

kern_return_t
thread_set_wq_state32(thread_t       thread,
    thread_state_t tstate)
{
	arm_thread_state_t *state;
	struct arm_saved_state *saved_state;
	struct arm_saved_state32 *saved_state_32;
	thread_t curth = current_thread();
	spl_t s = 0;

	assert(!thread_is_64bit_data(thread));

	saved_state = thread->machine.upcb;
	saved_state_32 = saved_state32(saved_state);

	state = (arm_thread_state_t *)tstate;

	if (curth != thread) {
		s = splsched();
		thread_lock(thread);
	}

	/*
	 * do not zero saved_state, it can be concurrently accessed
	 * and zero is not a valid state for some of the registers,
	 * like sp.
	 */
	thread_state32_to_saved_state(state, saved_state);
	saved_state_32->cpsr = PSR64_USER32_DEFAULT;

	if (curth != thread) {
		thread_unlock(thread);
		splx(s);
	}

	return KERN_SUCCESS;
}

kern_return_t
thread_set_wq_state64(thread_t       thread,
    thread_state_t tstate)
{
	arm_thread_state64_t *state;
	struct arm_saved_state *saved_state;
	struct arm_saved_state64 *saved_state_64;
	thread_t curth = current_thread();
	spl_t s = 0;

	assert(thread_is_64bit_data(thread));

	saved_state = thread->machine.upcb;
	saved_state_64 = saved_state64(saved_state);
	state = (arm_thread_state64_t *)tstate;

	if (curth != thread) {
		s = splsched();
		thread_lock(thread);
	}

	/*
	 * do not zero saved_state, it can be concurrently accessed
	 * and zero is not a valid state for some of the registers,
	 * like sp.
	 */
	thread_state64_to_saved_state(state, saved_state);
	set_saved_state_cpsr(saved_state, PSR64_USER64_DEFAULT);

	if (curth != thread) {
		thread_unlock(thread);
		splx(s);
	}

	return KERN_SUCCESS;
}
