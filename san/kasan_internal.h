/*
 * Copyright (c) 2000-2014 Apple Inc. All rights reserved.
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

#ifndef _KASAN_INTERNAL_H_
#define _KASAN_INTERNAL_H_

#include <stdbool.h>
#include <mach/mach_vm.h>
#include <kern/zalloc.h>

typedef uintptr_t uptr;

#define MiB(x) ((x) * 1024UL * 1024)

/*
 * KASAN features and config
 */
#define KASAN_DEBUG   1
#define FAKESTACK     1
#define MEMINTRINSICS 1
/* KASAN_KALLOC defined in kasan.h */
/* KASAN_ZALLOC defined in kasan.h */
#define FAKESTACK_QUARANTINE (1 && FAKESTACK)

#define QUARANTINE_ENTRIES 5000
#define QUARANTINE_MAXSIZE MiB(10)

/*
 * The amount of physical memory stolen by KASan at boot to back the shadow memory
 * and page tables. Larger memory systems need to steal proportionally less.
 */
#ifdef __arm64__
/* Works out at about 25% of 512 MiB and 15% of 3GiB system */
# define STOLEN_MEM_PERCENT  13UL
# define STOLEN_MEM_BYTES    MiB(62)
#else
# define STOLEN_MEM_PERCENT  25UL
# define STOLEN_MEM_BYTES    0
#endif

#ifndef KASAN
# error KASAN undefined
#endif

#ifndef KASAN_SHIFT
# error KASAN_SHIFT undefined
#endif

#define ADDRESS_FOR_SHADOW(x) (((x) - KASAN_SHIFT) << 3)
#define SHADOW_FOR_ADDRESS(x) (uint8_t *)(((x) >> 3) + KASAN_SHIFT)

#define NOINLINE __attribute__ ((noinline))
#define ALWAYS_INLINE inline __attribute__((always_inline))

#define CLANG_MIN_VERSION(x) (defined(__apple_build_version__) && (__apple_build_version__ >= (x)))

#define BIT(x) (1U << (x))

enum kasan_access_type {
	/* exactly one of these bits must be set */
	TYPE_LOAD       = BIT(0),
	TYPE_STORE      = BIT(1),
	TYPE_KFREE      = BIT(2),
	TYPE_ZFREE      = BIT(3),
	TYPE_FSFREE     = BIT(4), /* fakestack free */
	TYPE_MEMLD      = BIT(5), /* memory intrinsic - load */
	TYPE_MEMSTR     = BIT(6), /* memory intrinsic - store */
	TYPE_STRINGLD   = BIT(7), /* string intrinsic - load */
	TYPE_STRINGSTR  = BIT(8), /* string intrinsic - store */
	TYPE_TEST       = BIT(15),

	/* masks */
	TYPE_LDSTR      = TYPE_LOAD|TYPE_STORE, /* regular loads and stores */
	TYPE_FREE       = TYPE_KFREE|TYPE_ZFREE|TYPE_FSFREE,
	TYPE_MEM        = TYPE_MEMLD|TYPE_MEMSTR,
	TYPE_STRING     = TYPE_STRINGLD|TYPE_STRINGSTR,
	TYPE_LOAD_ALL   = TYPE_LOAD|TYPE_MEMLD|TYPE_STRINGLD,
	TYPE_STORE_ALL  = TYPE_STORE|TYPE_MEMSTR|TYPE_STRINGSTR,
	TYPE_ALL        = ~0U
};

bool kasan_range_poisoned(vm_offset_t base, vm_size_t size, vm_offset_t *first_invalid);
void kasan_check_range(const void *x, size_t sz, unsigned access_type);
void kasan_test(int testno, int fail);
void kasan_handle_test(void);
void kasan_unpoison_curstack(void);
void kasan_free_internal(void **addrp, vm_size_t *sizep, int type, zone_t *, vm_size_t user_size, int locked, bool doquarantine);
void kasan_poison(vm_offset_t base, vm_size_t size, vm_size_t leftrz, vm_size_t rightrz, uint8_t flags);
void kasan_unpoison(void *base, vm_size_t size);
void kasan_lock(boolean_t *b);
void kasan_unlock(boolean_t b);
void kasan_init_fakestack(void);

/* dynamic blacklist */
void kasan_init_dybl(void);
bool kasan_is_blacklisted(unsigned type);
void kasan_dybl_load_kext(uintptr_t addr, const char *kextname);
void kasan_dybl_unload_kext(uintptr_t addr);

/* arch-specific interface */
void kasan_arch_init(void);

extern vm_address_t kernel_vbase;
extern vm_address_t kernel_vtop;

extern long shadow_pages_used;

/* Describes the source location where a global is defined. */
struct asan_global_source_location {
	const char *filename;
	int line_no;
	int column_no;
};

/* Describes an instrumented global variable. */
struct asan_global {
	uptr addr;
	uptr size;
	uptr size_with_redzone;
	const char *name;
	const char *module;
	uptr has_dynamic_init;
	struct asan_global_source_location *location;
#if CLANG_MIN_VERSION(8020000)
	uptr odr_indicator;
#endif
};

#if defined(__x86_64__)
# define _JBLEN ((9 * 2) + 3 + 16)
#elif defined(__arm64__)
# define _JBLEN ((14 + 8 + 2) * 2)
#else
# error "Unknown arch"
#endif

typedef int jmp_buf[_JBLEN];
void _longjmp(jmp_buf env, int val);
int _setjmp(jmp_buf env);

#endif /* _KASAN_INTERNAL_H_ */
