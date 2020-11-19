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
 * @OSF_COPYRIGHT@
 */

#ifndef _ARM_MISC_PROTOS_H_
#define _ARM_MISC_PROTOS_H_

#include <kern/kern_types.h>

typedef struct boot_args boot_args;
/* The address of the end of the kernelcache. */
extern vm_offset_t end_kern;
/* The lowest address in the kernelcache. */
extern vm_offset_t segLOWEST;

extern void machine_startup(__unused boot_args *args) __attribute__((noinline));


extern void arm_auxkc_init(void *mh, void *base);

extern void arm_vm_init(uint64_t memory_size, boot_args *args);
extern void arm_vm_prot_init(boot_args *args);
extern void arm_vm_prot_finalize(boot_args *args);

extern kern_return_t DebuggerXCallEnter(boolean_t);
extern void DebuggerXCallReturn(void);

#if __arm64__ && DEBUG
extern void dump_kva_space(void);
#endif /* __arm64__ && DEBUG */

extern void Load_context(thread_t);
extern void Idle_load_context(void) __attribute__((noreturn));
extern thread_t Switch_context(thread_t, thread_continue_t, thread_t);
extern thread_t Shutdown_context(void (*doshutdown)(processor_t), processor_t  processor);
extern void __dead2 Call_continuation(thread_continue_t, void *, wait_result_t, boolean_t enable_interrupts);


/**
 * Indicate during a context-switch event that we have updated some CPU
 * state which requires a later context-sync event.
 *
 * On ARMv8.5 and later CPUs, this function sets a flag that will trigger an
 * explicit isb instruction sometime before the upcoming eret instruction.
 *
 * Prior to ARMv8.5, the eret instruction itself is always synchronizing, and
 * this function is an empty stub which serves only as documentation.
 */
static inline void
arm_context_switch_requires_sync(void)
{
}

#if __has_feature(ptrauth_calls)
extern boolean_t arm_user_jop_disabled(void);
#endif /* __has_feature(ptrauth_calls) */

extern void DebuggerCall(unsigned int reason, void *ctx);
extern void DebuggerXCall(void *ctx);

extern int copyout_kern(const char *kernel_addr, user_addr_t user_addr, vm_size_t nbytes);
extern int copyin_kern(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes);

extern void bcopy_phys(addr64_t from, addr64_t to, vm_size_t nbytes);

extern void dcache_incoherent_io_flush64(addr64_t pa, unsigned int count, unsigned int remaining, unsigned int *res);
extern void dcache_incoherent_io_store64(addr64_t pa, unsigned int count, unsigned int remaining, unsigned int *res);

#if defined(__arm__)
extern void copy_debug_state(arm_debug_state_t * src, arm_debug_state_t *target, __unused boolean_t all);
#elif defined(__arm64__)
extern void copy_legacy_debug_state(arm_legacy_debug_state_t * src, arm_legacy_debug_state_t *target, __unused boolean_t all);
extern void copy_debug_state32(arm_debug_state32_t * src, arm_debug_state32_t *target, __unused boolean_t all);
extern void copy_debug_state64(arm_debug_state64_t * src, arm_debug_state64_t *target, __unused boolean_t all);

extern boolean_t debug_legacy_state_is_valid(arm_legacy_debug_state_t *ds);
extern boolean_t debug_state_is_valid32(arm_debug_state32_t *ds);
extern boolean_t debug_state_is_valid64(arm_debug_state64_t *ds);

extern int copyio_check_user_addr(user_addr_t user_addr, vm_size_t nbytes);

/*
 * Get a quick virtual mapping of a physical page and run a callback on that
 * page's virtual address.
 */
extern int apply_func_phys(addr64_t src64, vm_size_t bytes, int (*func)(void * buffer, vm_size_t bytes, void * arg), void * arg);

/* Top-Byte-Ignore */
#define TBI_MASK           0xff00000000000000
#define tbi_clear(addr)    ((addr) & ~(TBI_MASK))

#else /* !defined(__arm__) && !defined(__arm64__) */
#error Unknown architecture.
#endif /* defined(__arm__) */

#endif /* _ARM_MISC_PROTOS_H_ */
