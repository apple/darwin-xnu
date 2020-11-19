/*
 * Copyright (c) 2000-2020 Apple Computer, Inc. All rights reserved.
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
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	mach/vm_param.h
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young
 *	Date:	1985
 *
 *	Machine independent virtual memory parameters.
 *
 */

#ifndef _MACH_VM_PARAM_H_
#define _MACH_VM_PARAM_H_

#include <mach/machine/vm_param.h>

#ifdef  KERNEL

#ifndef ASSEMBLER
#include <mach/vm_types.h>
#endif  /* ASSEMBLER */

#include <os/base.h>
#include <os/overflow.h>

/*
 *	The machine independent pages are refered to as PAGES.  A page
 *	is some number of hardware pages, depending on the target machine.
 */

#ifndef ASSEMBLER

#define PAGE_SIZE_64 (unsigned long long)PAGE_SIZE              /* pagesize in addr units */
#define PAGE_MASK_64 (unsigned long long)PAGE_MASK              /* mask for off in page */

/*
 *	Convert addresses to pages and vice versa.  No rounding is used.
 *      The atop_32 and ptoa_32 macros should not be use on 64 bit types.
 *      The round_page_64 and trunc_page_64 macros should be used instead.
 */

#define atop_32(x) ((uint32_t)(x) >> PAGE_SHIFT)
#define ptoa_32(x) ((uint32_t)(x) << PAGE_SHIFT)
#define atop_64(x) ((uint64_t)(x) >> PAGE_SHIFT)
#define ptoa_64(x) ((uint64_t)(x) << PAGE_SHIFT)

#define atop_kernel(x) ((vm_address_t)(x) >> PAGE_SHIFT)
#define ptoa_kernel(x) ((vm_address_t)(x) << PAGE_SHIFT)

/*
 *      While the following block is enabled, the legacy atop and ptoa
 *      macros will behave correctly.  If not, they will generate
 *      invalid lvalue errors.
 */

#if 1
#define atop(x) ((vm_address_t)(x) >> PAGE_SHIFT)
#define ptoa(x) ((vm_address_t)(x) << PAGE_SHIFT)
#else
#define atop(x) (0UL = 0)
#define ptoa(x) (0UL = 0)
#endif

/*
 *	Page-size rounding macros for the Public fixed-width VM types.
 */
#define mach_vm_round_page(x) (((mach_vm_offset_t)(x) + PAGE_MASK) & ~((signed)PAGE_MASK))
#define mach_vm_trunc_page(x) ((mach_vm_offset_t)(x) & ~((signed)PAGE_MASK))

#define round_page_overflow(in, out) __os_warn_unused(({ \
	        bool __ovr = os_add_overflow(in, (__typeof__(*out))PAGE_MASK, out); \
	        *out &= ~((__typeof__(*out))PAGE_MASK); \
	        __ovr; \
	}))

static inline int OS_WARN_RESULT
mach_vm_round_page_overflow(mach_vm_offset_t in, mach_vm_offset_t *out)
{
	return round_page_overflow(in, out);
}

#define memory_object_round_page(x) (((memory_object_offset_t)(x) + PAGE_MASK) & ~((signed)PAGE_MASK))
#define memory_object_trunc_page(x) ((memory_object_offset_t)(x) & ~((signed)PAGE_MASK))

/*
 *	Rounding macros for the legacy (scalable with the current task's
 *	address space size) VM types.
 */

#define round_page(x) (((vm_offset_t)(x) + PAGE_MASK) & ~((vm_offset_t)PAGE_MASK))
#define trunc_page(x) ((vm_offset_t)(x) & ~((vm_offset_t)PAGE_MASK))

/*
 *	Round off or truncate to the nearest page.  These will work
 *	for either addresses or counts.  (i.e. 1 byte rounds to 1 page
 *	bytes.  The round_page_32 and trunc_page_32 macros should not be
 *      use on 64 bit types.  The round_page_64 and trunc_page_64 macros
 *      should be used instead.
 *
 *	These should only be used in the rare case the size of the address
 *	or length is hard-coded as 32 or 64 bit.  Otherwise, the macros
 *	associated with the specific VM type should be used.
 */

#define round_page_32(x) (((uint32_t)(x) + PAGE_MASK) & ~((uint32_t)PAGE_MASK))
#define trunc_page_32(x) ((uint32_t)(x) & ~((uint32_t)PAGE_MASK))
#define round_page_64(x) (((uint64_t)(x) + PAGE_MASK_64) & ~((uint64_t)PAGE_MASK_64))
#define trunc_page_64(x) ((uint64_t)(x) & ~((uint64_t)PAGE_MASK_64))

#define round_page_mask_32(x, mask) (((uint32_t)(x) + (mask)) & ~((uint32_t)(mask)))
#define trunc_page_mask_32(x, mask) ((uint32_t)(x) & ~((uint32_t)(mask)))
#define round_page_mask_64(x, mask) (((uint64_t)(x) + (mask)) & ~((uint64_t)(mask)))
#define trunc_page_mask_64(x, mask) ((uint64_t)(x) & ~((uint64_t)(mask)))

/*
 *      Enable the following block to find uses of xxx_32 macros that should
 *      be xxx_64.  These macros only work in C code, not C++.  The resulting
 *      binaries are not functional.  Look for invalid lvalue errors in
 *      the compiler output.
 *
 *      Enabling the following block will also find use of the xxx_64 macros
 *      that have been passed pointers.  The parameters should be case to an
 *      unsigned long type first.  Look for invalid operands to binary + error
 *      in the compiler output.
 */

#if 0
#undef atop_32
#undef ptoa_32
#undef round_page_32
#undef trunc_page_32
#undef atop_64
#undef ptoa_64
#undef round_page_64
#undef trunc_page_64

#ifndef __cplusplus

#define atop_32(x) \
    (__builtin_choose_expr (sizeof(x) != sizeof(uint64_t), \
	(*(long *)0), \
	(0UL)) = 0)

#define ptoa_32(x) \
    (__builtin_choose_expr (sizeof(x) != sizeof(uint64_t), \
	(*(long *)0), \
	(0UL)) = 0)

#define round_page_32(x) \
    (__builtin_choose_expr (sizeof(x) != sizeof(uint64_t), \
	(*(long *)0), \
	(0UL)) = 0)

#define trunc_page_32(x) \
    (__builtin_choose_expr (sizeof(x) != sizeof(uint64_t), \
	(*(long *)0), \
	(0UL)) = 0)
#else

#define atop_32(x) (0)
#define ptoa_32(x) (0)
#define round_page_32(x) (0)
#define trunc_page_32(x) (0)

#endif /* ! __cplusplus */

#define atop_64(x) ((uint64_t)((x) + (uint8_t *)0))
#define ptoa_64(x) ((uint64_t)((x) + (uint8_t *)0))
#define round_page_64(x) ((uint64_t)((x) + (uint8_t *)0))
#define trunc_page_64(x) ((uint64_t)((x) + (uint8_t *)0))

#endif

/*
 *	Determine whether an address is page-aligned, or a count is
 *	an exact page multiple.
 */

#define page_aligned(x) (((x) & PAGE_MASK) == 0)

extern vm_size_t        mem_size;               /* 32-bit size of memory - limited by maxmem - deprecated */
extern uint64_t         max_mem;                /* 64-bit size of memory - limited by maxmem */

/*
 * The default pager does not handle 64-bit offsets inside its objects,
 * so this limits the size of anonymous memory objects to 4GB minus 1 page.
 * When we need to allocate a chunk of anonymous memory over that size,
 * we have to allocate more than one chunk.
 */
#define ANON_MAX_SIZE   0xFFFFF000ULL
/*
 * Work-around for <rdar://problem/6626493>
 * Break large anonymous memory areas into 128MB chunks to alleviate
 * the cost of copying when copy-on-write is not possible because a small
 * portion of it being wired.
 */
#define ANON_CHUNK_SIZE (128ULL * 1024 * 1024) /* 128MB */

/*
 * The 'medium' malloc allocator would like its regions
 * to be chunked up into MALLOC_MEDIUM_CHUNK_SIZE chunks
 * and backed by different objects. This avoids contention
 * on a single large object and showed solid improvements on high
 * core machines with workloads involving video and graphics processing.
 */
#define MALLOC_MEDIUM_CHUNK_SIZE (8ULL * 1024 * 1024) /* 8 MB */

#ifdef  XNU_KERNEL_PRIVATE

#include <kern/debug.h>

extern uint64_t         mem_actual;             /* 64-bit size of memory - not limited by maxmem */
extern uint64_t         max_mem_actual;         /* Size of physical memory adjusted by maxmem */
extern uint64_t         sane_size;              /* Memory size to use for defaults calculations */
extern addr64_t         vm_last_addr;   /* Highest kernel virtual address known to the VM system */

extern const vm_offset_t        vm_min_kernel_address;
extern const vm_offset_t        vm_max_kernel_address;

extern vm_offset_t              vm_kernel_stext;
extern vm_offset_t              vm_kernel_etext;
extern vm_offset_t              vm_kernel_slid_base;
extern vm_offset_t              vm_kernel_slid_top;
extern vm_offset_t              vm_kernel_slide;
extern vm_offset_t              vm_kernel_addrperm;
extern vm_offset_t              vm_kext_base;
extern vm_offset_t              vm_kext_top;
extern vm_offset_t              vm_kernel_base;
extern vm_offset_t              vm_kernel_top;
extern vm_offset_t              vm_hib_base;

extern vm_offset_t              vm_kernel_builtinkmod_text;
extern vm_offset_t              vm_kernel_builtinkmod_text_end;

#define VM_KERNEL_IS_SLID(_o)                                             \
	(((vm_offset_t)VM_KERNEL_STRIP_PTR(_o) >= vm_kernel_slid_base) && \
	 ((vm_offset_t)VM_KERNEL_STRIP_PTR(_o) <  vm_kernel_slid_top))

#define VM_KERNEL_SLIDE(_u) ((vm_offset_t)(_u) + vm_kernel_slide)

/*
 * The following macros are to be used when exposing kernel addresses to
 * userspace via any of the various debug or info facilities that might exist
 * (e.g. stackshot, proc_info syscall, etc.). It is important to understand
 * the goal of each macro and choose the right one depending on what you are
 * trying to do. Misuse of these macros can result in critical data leaks
 * which in turn lead to all sorts of system vulnerabilities. It is invalid to
 * call these macros on a non-kernel address (NULL is allowed).
 *
 * VM_KERNEL_UNSLIDE:
 *     Use this macro when you are exposing an address to userspace which is
 *     *guaranteed* to be a "static" kernel or kext address (i.e. coming from text
 *     or data sections). These are the addresses which get "slid" via ASLR on
 *     kernel or kext load, and it's precisely the slide value we are trying to
 *     protect from userspace.
 *
 * VM_KERNEL_ADDRHIDE:
 *     Use when exposing an address for internal purposes: debugging, tracing,
 *     etc. The address will be unslid if necessary. Other addresses will be
 *     hidden on customer builds, and unmodified on internal builds.
 *
 * VM_KERNEL_ADDRHASH:
 *     Use this macro when exposing a kernel address to userspace on customer
 *     builds. The address can be from the static kernel or kext regions, or the
 *     kernel heap. The address will be unslid or hashed as appropriate.
 *
 *
 * ** SECURITY WARNING: The following macros can leak kernel secrets.
 *                      Use *only* in performance *critical* code.
 *
 * VM_KERNEL_ADDRPERM:
 * VM_KERNEL_UNSLIDE_OR_PERM:
 *     Use these macros when exposing a kernel address to userspace on customer
 *     builds. The address can be from the static kernel or kext regions, or the
 *     kernel heap. The address will be unslid or permuted as appropriate.
 *
 * Nesting of these macros should be considered invalid.
 */

__BEGIN_DECLS
#if XNU_KERNEL_PRIVATE
extern vm_offset_t vm_kernel_addrhash(vm_offset_t addr)
__XNU_INTERNAL(vm_kernel_addrhash);
#else
extern vm_offset_t vm_kernel_addrhash(vm_offset_t addr);
#endif
__END_DECLS

#define __DO_UNSLIDE(_v) ((vm_offset_t)VM_KERNEL_STRIP_PTR(_v) - vm_kernel_slide)

#if DEBUG || DEVELOPMENT
#define VM_KERNEL_ADDRHIDE(_v) (VM_KERNEL_IS_SLID(_v) ? __DO_UNSLIDE(_v) : (vm_address_t)VM_KERNEL_STRIP_PTR(_v))
#else
#define VM_KERNEL_ADDRHIDE(_v) (VM_KERNEL_IS_SLID(_v) ? __DO_UNSLIDE(_v) : (vm_address_t)0)
#endif /* DEBUG || DEVELOPMENT */

#define VM_KERNEL_ADDRHASH(_v) vm_kernel_addrhash((vm_offset_t)(_v))

#define VM_KERNEL_UNSLIDE_OR_PERM(_v) ({ \
	        VM_KERNEL_IS_SLID(_v) ? __DO_UNSLIDE(_v) : \
	        VM_KERNEL_ADDRESS(_v) ? ((vm_offset_t)VM_KERNEL_STRIP_PTR(_v) + vm_kernel_addrperm) : \
	        (vm_offset_t)VM_KERNEL_STRIP_PTR(_v); \
	})

#define VM_KERNEL_UNSLIDE(_v) ({ \
	        VM_KERNEL_IS_SLID(_v) ? __DO_UNSLIDE(_v) : (vm_offset_t)0; \
	})

#define VM_KERNEL_ADDRPERM(_v) VM_KERNEL_UNSLIDE_OR_PERM(_v)

#undef mach_vm_round_page
#undef round_page
#undef round_page_32
#undef round_page_64

static inline mach_vm_offset_t
mach_vm_round_page(mach_vm_offset_t x)
{
	if (round_page_overflow(x, &x)) {
		panic("overflow detected");
	}
	return x;
}

static inline vm_offset_t
round_page(vm_offset_t x)
{
	if (round_page_overflow(x, &x)) {
		panic("overflow detected");
	}
	return x;
}

static inline mach_vm_offset_t
round_page_64(mach_vm_offset_t x)
{
	if (round_page_overflow(x, &x)) {
		panic("overflow detected");
	}
	return x;
}

static inline uint32_t
round_page_32(uint32_t x)
{
	if (round_page_overflow(x, &x)) {
		panic("overflow detected");
	}
	return x;
}


/*!
 * @typedef vm_packing_params_t
 *
 * @brief
 * Data structure representing the packing parameters for a given packed pointer
 * encoding.
 *
 * @discussion
 * Several data structures wish to pack their pointers on less than 64bits
 * on LP64 in order to save memory.
 *
 * Adopters are supposed to define 3 macros:
 * - @c *_BITS:  number of storage bits used for the packing,
 * - @c *_SHIFT: number of non significant low bits (expected to be 0),
 * - @c *_BASE:  the base against which to encode.
 *
 * The encoding is a no-op when @c *_BITS is equal to @c __WORDSIZE and
 * @c *_SHIFT is 0.
 *
 *
 * The convenience macro @c VM_PACKING_PARAMS can be used to create
 * a @c vm_packing_params_t structure out of those definitions.
 *
 * It is customary to declare a constant global per scheme for the sake
 * of debuggers to be able to dynamically decide how to unpack various schemes.
 *
 *
 * This uses 2 possible schemes (who both preserve @c NULL):
 *
 * 1. When the storage bits and shift are sufficiently large (strictly more than
 *    VM_KERNEL_POINTER_SIGNIFICANT_BITS), a sign-extension scheme can be used.
 *
 *    This allows to represent any kernel pointer.
 *
 * 2. Else, a base-relative scheme can be used, typical bases are:
 *
 *     - @c KERNEL_PMAP_HEAP_RANGE_START when only pointers to heap (zone)
 *       allocated objects need to be packed,
 *
 *     - @c VM_MIN_KERNEL_AND_KEXT_ADDRESS when pointers to kernel globals also
 *       need this.
 *
 *    When such an ecoding is used, @c zone_restricted_va_max() must be taught
 *    about it.
 */
typedef struct vm_packing_params {
	vm_offset_t vmpp_base;
	uint8_t     vmpp_bits;
	uint8_t     vmpp_shift;
	bool        vmpp_base_relative;
} vm_packing_params_t;


/*!
 * @macro VM_PACKING_IS_BASE_RELATIVE
 *
 * @brief
 * Whether the packing scheme with those parameters will be base-relative.
 */
#define VM_PACKING_IS_BASE_RELATIVE(ns) \
	(ns##_BITS + ns##_SHIFT <= VM_KERNEL_POINTER_SIGNIFICANT_BITS)


/*!
 * @macro VM_PACKING_PARAMS
 *
 * @brief
 * Constructs a @c vm_packing_params_t structure based on the convention that
 * macros with the @c _BASE, @c _BITS and @c _SHIFT suffixes have been defined
 * to the proper values.
 */
#define VM_PACKING_PARAMS(ns) \
	(vm_packing_params_t){ \
	    .vmpp_base  = ns##_BASE, \
	    .vmpp_bits  = ns##_BITS, \
	    .vmpp_shift = ns##_SHIFT, \
	    .vmpp_base_relative = VM_PACKING_IS_BASE_RELATIVE(ns), \
	}

/**
 * @function vm_pack_pointer
 *
 * @brief
 * Packs a pointer according to the specified parameters.
 *
 * @discussion
 * The convenience @c VM_PACK_POINTER macro allows to synthesize
 * the @c params argument.
 *
 * @param ptr           The pointer to pack.
 * @param params        The encoding parameters.
 * @returns             The packed pointer.
 */
static inline vm_offset_t
vm_pack_pointer(vm_offset_t ptr, vm_packing_params_t params)
{
	if (!params.vmpp_base_relative) {
		return ptr >> params.vmpp_shift;
	}
	if (ptr) {
		return (ptr - params.vmpp_base) >> params.vmpp_shift;
	}
	return (vm_offset_t)0;
}
#define VM_PACK_POINTER(ptr, ns) \
	vm_pack_pointer(ptr, VM_PACKING_PARAMS(ns))

/**
 * @function vm_unpack_pointer
 *
 * @brief
 * Unpacks a pointer packed with @c vm_pack_pointer().
 *
 * @discussion
 * The convenience @c VM_UNPACK_POINTER macro allows to synthesize
 * the @c params argument.
 *
 * @param packed        The packed value to decode.
 * @param params        The encoding parameters.
 * @returns             The unpacked pointer.
 */
static inline vm_offset_t
vm_unpack_pointer(vm_offset_t packed, vm_packing_params_t params)
{
	if (!params.vmpp_base_relative) {
		intptr_t addr = (intptr_t)packed;
		addr <<= __WORDSIZE - params.vmpp_bits;
		addr >>= __WORDSIZE - params.vmpp_bits - params.vmpp_shift;
		return (vm_offset_t)addr;
	}
	if (packed) {
		return (packed << params.vmpp_shift) + params.vmpp_base;
	}
	return (vm_offset_t)0;
}
#define VM_UNPACK_POINTER(packed, ns) \
	vm_unpack_pointer(packed, VM_PACKING_PARAMS(ns))

/**
 * @function vm_packing_max_packable
 *
 * @brief
 * Returns the largest packable address for the given parameters.
 *
 * @discussion
 * The convenience @c VM_PACKING_MAX_PACKABLE macro allows to synthesize
 * the @c params argument.
 *
 * @param params        The encoding parameters.
 * @returns             The largest packable pointer.
 */
static inline vm_offset_t
vm_packing_max_packable(vm_packing_params_t params)
{
	if (!params.vmpp_base_relative) {
		return VM_MAX_KERNEL_ADDRESS;
	}

	vm_offset_t ptr = params.vmpp_base +
	    (((1ul << params.vmpp_bits) - 1) << params.vmpp_shift);

	return ptr >= params.vmpp_base ? ptr : VM_MAX_KERNEL_ADDRESS;
}
#define VM_PACKING_MAX_PACKABLE(ns) \
	vm_packing_max_packable(VM_PACKING_PARAMS(ns))


__abortlike
extern void
vm_packing_pointer_invalid(vm_offset_t ptr, vm_packing_params_t params);

/**
 * @function vm_verify_pointer_packable
 *
 * @brief
 * Panics if the specified pointer cannot be packed with the specified
 * parameters.
 *
 * @discussion
 * The convenience @c VM_VERIFY_POINTER_PACKABLE macro allows to synthesize
 * the @c params argument.
 *
 * The convenience @c VM_ASSERT_POINTER_PACKABLE macro allows to synthesize
 * the @c params argument, and is erased when assertions are disabled.
 *
 * @param ptr           The packed value to decode.
 * @param params        The encoding parameters.
 */
static inline void
vm_verify_pointer_packable(vm_offset_t ptr, vm_packing_params_t params)
{
	if (ptr & ((1ul << params.vmpp_shift) - 1)) {
		vm_packing_pointer_invalid(ptr, params);
	}
	if (!params.vmpp_base_relative || ptr == 0) {
		return;
	}
	if (ptr <= params.vmpp_base || ptr > vm_packing_max_packable(params)) {
		vm_packing_pointer_invalid(ptr, params);
	}
}
#define VM_VERIFY_POINTER_PACKABLE(ptr, ns) \
	vm_verify_pointer_packable(ptr, VM_PACKING_PARAMS(ns))

#if DEBUG || DEVELOPMENT
#define VM_ASSERT_POINTER_PACKABLE(ptr, ns) \
    VM_VERIFY_POINTER_PACKABLE(ptr, ns)
#else
#define VM_ASSERT_POINTER_PACKABLE(ptr, ns) ((void)(ptr))
#endif

/**
 * @function vm_verify_pointer_range
 *
 * @brief
 * Panics if some pointers in the specified range can't be packed with the
 * specified parameters.
 *
 * @param subsystem     The subsystem requiring the packing.
 * @param min_address   The smallest address of the range.
 * @param max_address   The largest address of the range.
 * @param params        The encoding parameters.
 */
extern void
vm_packing_verify_range(
	const char         *subsystem,
	vm_offset_t         min_address,
	vm_offset_t         max_address,
	vm_packing_params_t params);

#endif  /* XNU_KERNEL_PRIVATE */

extern vm_size_t        page_size;
extern vm_size_t        page_mask;
extern int              page_shift;

/* We need a way to get rid of compiler warnings when we cast from   */
/* a 64 bit value to an address (which may be 32 bits or 64-bits).   */
/* An intptr_t is used convert the value to the right precision, and */
/* then to an address. This macro is also used to convert addresses  */
/* to 32-bit integers, which is a hard failure for a 64-bit kernel   */
#include <stdint.h>
#ifndef __CAST_DOWN_CHECK
#define __CAST_DOWN_CHECK

#define CAST_DOWN( type, addr ) \
    ( ((type)((uintptr_t) (addr)/(sizeof(type) < sizeof(uintptr_t) ? 0 : 1))) )

#define CAST_DOWN_EXPLICIT( type, addr )  ( ((type)((uintptr_t) (addr))) )

#endif /* __CAST_DOWN_CHECK */

#endif  /* ASSEMBLER */

#endif  /* KERNEL */

#endif  /* _MACH_VM_PARAM_H_ */
