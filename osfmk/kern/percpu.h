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

#ifndef _KERN_PERCPU_H_
#define _KERN_PERCPU_H_

#include <mach/vm_types.h>

__BEGIN_DECLS

#if XNU_KERNEL_PRIVATE
#include <libkern/section_keywords.h>
#include <os/atomic_private.h>

#pragma GCC visibility push(hidden)

/*!
 * @macro PERCPU_DECL
 *
 * @abstract
 * Declares a per-CPU variable in a header.
 *
 * @param type_t        the per-CPU variable type
 * @param name          the per-CPU variable name
 */
#define PERCPU_DECL(type_t, name) \
	extern type_t __PERCPU_NAME(name)

/*!
 * @macro PERCPU_DATA
 *
 * @abstract
 * Defines a per-CPU variable in a translation unit.
 *
 * @discussion
 * @c PERCPU_DECL can be used in headers to export the variable to clients.
 *
 * By default, per-cpu data is 0-initialized. Per-CPU data is allocated during
 * the STARTUP_SUB_KMEM_ALLOC phase and can be initialized with a STARTUP
 * callback in any later phase.
 *
 * Usage is:
 * <code>
 *   [ static ] type PERCPU_DATA(name);
 * </code>
 *
 * @param name          the per-CPU variable name
 */
#define PERCPU_DATA(name) \
	__percpu __PERCPU_NAME(name) = {0}

/*!
 * @macro PERCPU_GET
 *
 * @abstract
 * Gets a pointer to the per-CPU instance of the variable for the processor the
 * code is currently running on.
 *
 * @discussion
 * It is expected that preemption or interrupts are disabled when this is used,
 * as a context-switch might move the current thread to another CPU.
 *
 * It is also valid in code that wasn't already disabling preemption and cares
 * about code-gen size a lot to use this outside of a preemption-disabled
 * section provided that the data is modified using atomics.
 *
 * Note that if several per-CPU pointers are acquired in short succession,
 * @c PERCPU_GET_WITH_BASE can be used to avoid the repeated calls to
 * @c current_percpu_base() which the compiler wont't elide.
 *
 * @param name          the per-CPU variable name
 */
#define PERCPU_GET(name) \
	__PERCPU_CAST(name, current_percpu_base() + __PERCPU_ADDR(name))

/*!
 * @function current_percpu_base()
 *
 * @abstract
 * Returns an offset that can be passed to @c PERCPU_GET_WITH_BASE().
 *
 * @see PERCPU_GET() for conditions of use.
 */
extern vm_offset_t current_percpu_base(void);

/*!
 * @macro PERCPU_GET_MASTER
 *
 * @abstract
 * Gets a pointer to the master per-CPU instance of the variable.
 *
 * @param base          the per-CPU base to use
 * @param name          the per-CPU variable name
 */
#define PERCPU_GET_MASTER(name) \
	(&__PERCPU_NAME(name))

/*!
 * @macro PERCPU_GET_WITH_BASE
 *
 * @abstract
 * Gets a pointer to the per-CPU instance of the variable for the specified
 * base.
 *
 * @param base          the per-CPU base to use
 * @param name          the per-CPU variable name
 */
#define PERCPU_GET_WITH_BASE(base, name) \
	__PERCPU_CAST(name, base + __PERCPU_ADDR(name))

/*!
 * @macro PERCPU_GET_RELATIVE
 *
 * @abstract
 * Gets a pointer to the per-CPU instance of a variable relative to another
 * known one.
 *
 * @description
 * When a per-CPU slot address is known, but the caller doesn't know the base
 * from which it was derived, then this allows to compute another per-CPU slot
 * address for a different variable but for the same CPU, without any loads.
 *
 * @param name          the per-CPU variable name
 * @param other         the other per-CPU variable name
 * @param ptr           a pointer to the other variable slot
 */
#define PERCPU_GET_RELATIVE(name, other, ptr) ({ \
	__PERCPU_TYPE(other) __other_ptr = (ptr); /* type check */ \
	vm_offset_t __offs = __PERCPU_ADDR(name) - __PERCPU_ADDR(other); \
	__PERCPU_CAST(name, (vm_address_t)__other_ptr + __offs); \
})

/*!
 * @macro percpu_foreach_base()
 *
 * @abstract
 * Enumerates all Per-CPU variable bases.
 *
 * @param it            the name of the iterator
 */
#define percpu_foreach_base(it) \
	for (vm_offset_t it = 0, \
	    __next_ ## it = percpu_base.start, \
	    __end_ ## it = percpu_base.end; \
        \
	    it <= __end_ ## it; \
        \
	    it = __next_ ## it, \
	    __next_ ## it += percpu_section_size())

/*!
 * @macro percpu_foreach()
 *
 * @abstract
 * Enumerates all Per-CPU variable instances.
 *
 * @param it            the name of the iterator
 * @param name          the per-CPU variable name
 */
#define percpu_foreach(it, name) \
	for (__PERCPU_TYPE(name) it, \
	    __base_ ## it = NULL, \
	    __next_ ## it = (typeof(it))percpu_base.start, \
	    __end_ ## it = (typeof(it))percpu_base.end; \
        \
	    (it = (typeof(it))(__PERCPU_ADDR(name) + (vm_address_t)__base_ ## it), \
	    __base_ ## it <= __end_ ## it); \
        \
	    __base_ ## it = __next_ ## it, \
	    __next_ ## it = (typeof(it))((vm_address_t)__base_ ## it + percpu_section_size()))

/*!
 * @macro percpu_foreach_secondary_base()
 *
 * @abstract
 * Enumerates all Per-CPU variable bases, skipping the master slot.
 *
 * @param it            the name of the iterator
 */
#define percpu_foreach_secondary_base(it) \
	for (vm_offset_t it = percpu_base.start, __end_ ## it = percpu_base.end; \
	    it <= __end_ ## it; it += percpu_section_size())

/*!
 * @macro percpu_foreach_secondary()
 *
 * @abstract
 * Enumerates all Per-CPU variable instances, skipping the master slot.
 *
 * @param it            the name of the iterator
 * @param name          the per-CPU variable name
 */
#define percpu_foreach_secondary(it, name) \
	for (__PERCPU_TYPE(name) it, \
	    __base_ ## it = (typeof(it))percpu_base.start, \
	    __end_ ## it = (typeof(it))percpu_base.end; \
        \
	    (it = (typeof(it))(__PERCPU_ADDR(name) + (vm_address_t)__base_ ## it), \
	    __base_ ## it <= __end_ ## it); \
        \
	    __base_ ## it = (typeof(it))((vm_address_t)__base_ ## it + percpu_section_size()))

#pragma mark - implementation details

/*
 * Below this point are implementation details that should not be used directly,
 * except by the macros above, or architecture specific code.
 */

#define __percpu                        __attribute__((section("__DATA, __percpu")))
#define __PERCPU_NAME(name)             percpu_slot_ ## name
#define __PERCPU_ADDR(name)             ((vm_offset_t)&__PERCPU_NAME(name))
#define __PERCPU_TYPE(name)             typeof(&__PERCPU_NAME(name))
#define __PERCPU_CAST(name, expr)       ((__PERCPU_TYPE(name))(expr))

/*
 * Note for implementors:
 *
 * A `base` represents a pointer in the percpu allocation offset by
 * `percpu_section_start()` so that PERCPU_GET() is a single addition.
 *
 * percpu_base.end is inclusive, so that percpu_foreach() and
 * percpu_foreach_base() can do a `<=` comparison.
 *
 * Because the first base is `0` (because the master CPU is using the static
 * percpu section), it allows for the compiler to know that for the first
 * iteration the comparison is always true.
 */
extern struct percpu_base {
	vm_address_t start;
	vm_address_t end;
	vm_offset_t  size;
} percpu_base;

static __pure2 inline vm_offset_t
percpu_section_start(void)
{
	extern char __percpu_section_start[] __SECTION_START_SYM("__DATA", "__percpu");
	return (vm_offset_t)__percpu_section_start;
}

static __pure2 inline vm_offset_t
percpu_section_end(void)
{
	extern char __percpu_section_end[] __SECTION_END_SYM("__DATA", "__percpu");
	return (vm_offset_t)__percpu_section_end;
}

static __pure2 inline vm_size_t
percpu_section_size(void)
{
	return percpu_section_end() - percpu_section_start();
}

#pragma GCC visibility pop
#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERN_PERCPU_H_ */
