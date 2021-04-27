/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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
#ifdef XNU_KERNEL_PRIVATE

#ifndef _KERN_COUNTER_H
#define _KERN_COUNTER_H

/*!
 * @file <kern/counter.h>
 *
 * @brief
 * Module for working with 64bit relaxed atomic counters.
 *
 * @discussion
 * Different counter types have different speed-memory tradeoffs, but
 * they all share a common interface.
 *
 * Counters can be statically allocated or dynamically allocated.
 *
 * Statically allocated counters are always backed by per-cpu storage which means
 * writes take place on the current CPUs value and reads sum all of the per-cpu values.
 *
 * Dynamically allocated counters can be either per-cpu or use a single 64bit value.
 * To create a per-cpu counter, use the scalable_counter_t type. Note that this
 * trades of additional memory for better scalability.
 * To create a single 64bit counter, use the atomic_counter_t type.
 *
 * For most counters you can just use the counter_t type and the choice of
 * scalable or atomic will be made at compile time based on the target.
 *
 * The counter types are opaque handles. They ARE NOT COPYABLE. If you need
 * to make a copy of a counter, you should do so like this:
 * <code>
 * counter_t original;
 * ...
 * counter_t copy;
 * counter_alloc(&copy);
 * counter_add(&copy, counter_load(&original));
 * ...
 * // Make sure to free them at some point.
 * counter_free(&original);
 * counter_free(&copy);
 * </code>
 *
 * Static counter example:
 * <code>
 * SCALABLE_COUNTER_DEFINE(my_counter);
 * ...
 * counter_inc(&my_counter);
 * assert(counter_load(&my_counter) == 1);
 * </code>
 *
 * Dynamic Counter Example:
 * <code>
 * scalable_counter_t my_percpu_counter;
 * atomic_counter_t my_atomic_counter;
 * counter_t my_counter;
 *
 * // All three counters share the same interface. So to change the speed-memory
 * // tradeoff just change the type.
 * counter_init(&my_scalable_counter);
 * counter_init(&my_atomic_counter);
 * counter_init(&my_counter);
 *
 * counter_inc(&my_scalable_counter);
 * counter_inc(&my_atomic_counter);
 * counter_inc(&my_counter);
 *
 * assert(counter_load(&my_scalable_counter) == 1);
 * assert(counter_load(&my_atomic_counter) == 1);
 * assert(counter_load(&my_counter) == 1);
 * </code>
 */

#include <mach/mach_types.h>
#include <kern/macro_help.h>
#include <kern/startup.h>
#include <kern/zalloc.h>

typedef __zpercpu uint64_t *scalable_counter_t;
typedef uint64_t atomic_counter_t;
/* Generic counter base type. Does not have an implementation. */
struct generic_counter_t;

/*!
 * @macro SCALABLE_COUNTER_DECLARE
 *
 * @abstract
 * (optionally) declares a static per-cpu counter (in a header).
 *
 * @param var           the name of the counter.
 */
#define SCALABLE_COUNTER_DECLARE(name) \
	extern scalable_counter_t name;

/*!
 * @macro SCALABLE_COUNTER_DEFINE
 *
 * @abstract
 * Defines a static per-cpu counter.
 * Counter can only be accessed after the TUNABLES phase of startup.
 *
 * @param var           the name of the counter.
 */
#define SCALABLE_COUNTER_DEFINE(name) \
	__startup_data uint64_t __ ##name##_early_storage = 0;                                   \
	scalable_counter_t name = {&__##name##_early_storage};                                   \
	STARTUP_ARG(TUNABLES, STARTUP_RANK_MIDDLE, scalable_counter_static_boot_mangle, &name);  \
	STARTUP_ARG(PERCPU, STARTUP_RANK_SECOND, scalable_counter_static_init, &name);

/*
 * Initialize a per-cpu counter.
 * May block and will never fail.
 * This counter must be freed with counter_free.
 */
OS_OVERLOADABLE
extern void counter_alloc(struct generic_counter_t *);

OS_OVERLOADABLE
extern void counter_free(struct generic_counter_t *);
/*
 * Add amount to counter.
 * @param amount: The amount to add.
 */
OS_OVERLOADABLE
extern void counter_add(struct generic_counter_t *, uint64_t amount);

/*
 * Add 1 to this counter.
 */
OS_OVERLOADABLE
extern void counter_inc(struct generic_counter_t *);

/*
 * Subtract 1 from this counter.
 */
OS_OVERLOADABLE
extern void counter_dec(struct generic_counter_t *);

/* Variants of the above operations where the caller takes responsibility for disabling preemption. */
OS_OVERLOADABLE
extern void counter_add_preemption_disabled(struct generic_counter_t *, uint64_t amount);
OS_OVERLOADABLE
extern void counter_inc_preemption_disabled(struct generic_counter_t *);
OS_OVERLOADABLE
extern void counter_dec_preemption_disabled(struct generic_counter_t *);

/*
 * Read the value of the percpu counter.
 * Note that this will cause synchronization of all the sharded values.
 */
OS_OVERLOADABLE
extern uint64_t counter_load(struct generic_counter_t *);

#pragma mark implementation details
/* NB: Nothing below here should be used directly. */

__startup_func void scalable_counter_static_boot_mangle(scalable_counter_t *counter);
__startup_func void scalable_counter_static_init(scalable_counter_t *counter);

#if XNU_TARGET_OS_WATCH || XNU_TARGET_OS_TV
#define ATOMIC_COUNTER_USE_PERCPU 0
#else
#define ATOMIC_COUNTER_USE_PERCPU 1
#endif /* XNU_TARGET_OS_OSX */

#if ATOMIC_COUNTER_USE_PERCPU
typedef scalable_counter_t counter_t;
#else
typedef atomic_counter_t counter_t;
#endif /* ATOMIC_COUNTER_USE_PERCPU */

#define COUNTER_MAKE_PROTOTYPES(counter_t)                                 \
OS_OVERLOADABLE                                                            \
extern void counter_alloc(counter_t *);                                    \
                                                                           \
OS_OVERLOADABLE                                                            \
extern void counter_free(counter_t *);                                     \
                                                                           \
OS_OVERLOADABLE                                                            \
extern void counter_add(counter_t *, uint64_t amount);                     \
                                                                           \
OS_OVERLOADABLE                                                            \
extern void counter_inc(counter_t *);                                      \
                                                                           \
OS_OVERLOADABLE                                                            \
extern void counter_dec(counter_t *);                                      \
                                                                           \
OS_OVERLOADABLE                                                            \
extern void counter_add_preemption_disabled(counter_t *, uint64_t amount); \
                                                                           \
OS_OVERLOADABLE                                                            \
extern void counter_inc_preemption_disabled(counter_t *);                  \
                                                                           \
OS_OVERLOADABLE                                                            \
extern void counter_dec_preemption_disabled(counter_t *);                  \
                                                                           \
OS_OVERLOADABLE                                                            \
extern uint64_t counter_load(counter_t *);

COUNTER_MAKE_PROTOTYPES(scalable_counter_t);
COUNTER_MAKE_PROTOTYPES(atomic_counter_t);

#endif /* _KERN_COUNTER_H */

#endif /* XNU_KERNEL_PRIVATE */
