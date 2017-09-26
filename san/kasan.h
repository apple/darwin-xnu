/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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

#ifndef _KASAN_H_
#define _KASAN_H_

#if KERNEL_PRIVATE

#if KASAN && !__has_feature(address_sanitizer)
# error "KASAN selected, but not enabled in compiler"
#endif

#if !KASAN && __has_feature(address_sanitizer)
# error "ASAN enabled in compiler, but kernel is not configured for KASAN"
#endif

#define KASAN_GLOBAL_SEGNAME  "__DATA"
#define KASAN_GLOBAL_SECTNAME "__asan_globals"

typedef uintptr_t uptr;

#if KASAN

#define KASAN_KALLOC 1
#define KASAN_ZALLOC 1
#define KASAN_DYNAMIC_BLACKLIST 1

#define KASAN_GUARD_SIZE (16)
#define KASAN_GUARD_PAD  (KASAN_GUARD_SIZE * 2)

#define KASAN_HEAP_ZALLOC    0
#define KASAN_HEAP_KALLOC    1
#define KASAN_HEAP_FAKESTACK 2
#define KASAN_HEAP_TYPES     3

/* shadow map byte values */
#define ASAN_VALID          0x00
#define ASAN_PARTIAL1       0x01
#define ASAN_PARTIAL2       0x02
#define ASAN_PARTIAL3       0x03
#define ASAN_PARTIAL4       0x04
#define ASAN_PARTIAL5       0x05
#define ASAN_PARTIAL6       0x06
#define ASAN_PARTIAL7       0x07
#define ASAN_ARRAY_COOKIE   0xac
#define ASAN_STACK_RZ       0xf0
#define ASAN_STACK_LEFT_RZ  0xf1
#define ASAN_STACK_MID_RZ   0xf2
#define ASAN_STACK_RIGHT_RZ 0xf3
#define ASAN_STACK_FREED    0xf5
#define ASAN_GLOBAL_RZ      0xf9
#define ASAN_HEAP_RZ        0xe9
#define ASAN_HEAP_LEFT_RZ   0xfa
#define ASAN_HEAP_RIGHT_RZ  0xfb
#define ASAN_HEAP_FREED     0xfd

/*
 * KASAN internal interface
 */

__BEGIN_DECLS
void kasan_map_shadow(vm_offset_t address, vm_size_t size, bool is_zero);
void kasan_disable(void);
void kasan_reserve_memory(void *);
void kasan_late_init(void);
void kasan_init(void);
void kasan_notify_stolen(vm_offset_t top);

void kasan_load_kext(vm_offset_t base, vm_size_t size, const void *bundleid);
void kasan_unload_kext(vm_offset_t base, vm_size_t size);

void kasan_poison_range(vm_offset_t base, vm_size_t sz, uint8_t flags);
void kasan_notify_address(vm_offset_t address, vm_size_t size);
void kasan_notify_address_nopoison(vm_offset_t address, vm_size_t size);
void kasan_unpoison_stack(vm_offset_t stack, vm_size_t size);
void kasan_unpoison_fakestack(thread_t thread);

struct kasan_test;
void __kasan_runtests(struct kasan_test *, int numtests);

#if XNU_KERNEL_PRIVATE
extern long shadow_pages_total;

#if __arm64__
void kasan_notify_address_zero(vm_offset_t, vm_size_t);
#elif __x86_64__
extern void kasan_map_low_fixed_regions(void);
extern unsigned shadow_stolen_idx;
extern vm_offset_t shadow_pnext, shadow_ptop;
#endif
#endif
/*
 * Allocator hooks
 */

vm_size_t kasan_alloc_resize(vm_size_t size);
vm_size_t kasan_user_size(vm_offset_t addr);

vm_address_t kasan_alloc(vm_offset_t addr, vm_size_t size, vm_size_t req, vm_size_t leftrz);
vm_address_t kasan_dealloc(vm_offset_t addr, vm_size_t *size);

void kasan_check_free(vm_offset_t addr, vm_size_t size, unsigned type);
void kasan_free(void **addr, vm_size_t *size, int type, zone_t *zone, vm_size_t user_size, bool doquarantine);

__END_DECLS

/* thread interface */
struct kasan_thread_data {
	int in_fakestack;
	LIST_HEAD(fakestack_header_list, fakestack_header) fakestack_head;
};
struct kasan_thread_data *kasan_get_thread_data(thread_t);
void kasan_init_thread(struct kasan_thread_data *);

#endif /* KASAN */

#if __has_feature(address_sanitizer)
# define NOKASAN __attribute__ ((no_sanitize_address))
#else
# define NOKASAN
#endif

/*
 * Delimit areas of code that may do kasan-unsafe operations
 */
__BEGIN_DECLS
#if KASAN
void kasan_unsafe_start(void);
void kasan_unsafe_end(void);
#else
static inline void kasan_unsafe_start(void) {}
static inline void kasan_unsafe_end(void) {}
#endif
__END_DECLS

/*
 * ASAN callbacks - inserted by the compiler
 */

extern int __asan_option_detect_stack_use_after_return;
extern const uintptr_t __asan_shadow_memory_dynamic_address;

__BEGIN_DECLS
void __asan_report_load1(uptr p);
void __asan_report_load2(uptr p);
void __asan_report_load4(uptr p);
void __asan_report_load8(uptr p);
void __asan_report_load16(uptr p);
void __asan_report_store1(uptr p);
void __asan_report_store2(uptr p);
void __asan_report_store4(uptr p);
void __asan_report_store8(uptr p);
void __asan_report_store16(uptr p);
void __asan_report_load_n(uptr p, unsigned long size);
void __asan_report_store_n(uptr p, unsigned long size);
void __asan_handle_no_return(void);
uptr __asan_stack_malloc_0(size_t);
uptr __asan_stack_malloc_1(size_t);
uptr __asan_stack_malloc_2(size_t);
uptr __asan_stack_malloc_3(size_t);
uptr __asan_stack_malloc_4(size_t);
uptr __asan_stack_malloc_5(size_t);
uptr __asan_stack_malloc_6(size_t);
uptr __asan_stack_malloc_7(size_t);
uptr __asan_stack_malloc_8(size_t);
uptr __asan_stack_malloc_9(size_t);
uptr __asan_stack_malloc_10(size_t);
void __asan_stack_free_0(uptr, size_t);
void __asan_stack_free_1(uptr, size_t);
void __asan_stack_free_2(uptr, size_t);
void __asan_stack_free_3(uptr, size_t);
void __asan_stack_free_4(uptr, size_t);
void __asan_stack_free_5(uptr, size_t);
void __asan_stack_free_6(uptr, size_t);
void __asan_stack_free_7(uptr, size_t);
void __asan_stack_free_8(uptr, size_t);
void __asan_stack_free_9(uptr, size_t);
void __asan_stack_free_10(uptr, size_t);
void __asan_poison_cxx_array_cookie(uptr);
uptr __asan_load_cxx_array_cookie(uptr *);
void __asan_poison_stack_memory(uptr addr, size_t size);
void __asan_unpoison_stack_memory(uptr addr, size_t size);
void __asan_alloca_poison(uptr addr, uptr size);
void __asan_allocas_unpoison(uptr top, uptr bottom);
void __asan_load1(uptr);
void __asan_load2(uptr);
void __asan_load4(uptr);
void __asan_load8(uptr);
void __asan_load16(uptr);
void __asan_loadN(uptr, size_t);
void __asan_store1(uptr);
void __asan_store2(uptr);
void __asan_store4(uptr);
void __asan_store8(uptr);
void __asan_store16(uptr);
void __asan_storeN(uptr, size_t);
void __sanitizer_ptr_sub(uptr a, uptr b);
void __sanitizer_ptr_cmp(uptr a, uptr b);
void __sanitizer_annotate_contiguous_container(const void *beg, const void *end, const void *old_mid, const void *new_mid);

void __asan_set_shadow_00(uptr, size_t);
void __asan_set_shadow_f1(uptr, size_t);
void __asan_set_shadow_f2(uptr, size_t);
void __asan_set_shadow_f3(uptr, size_t);
void __asan_set_shadow_f5(uptr, size_t);
void __asan_set_shadow_f8(uptr, size_t);

void __asan_init_v5(void);
void __asan_before_dynamic_init(uptr);
void __asan_after_dynamic_init(void);
void __asan_unregister_globals(uptr a, uptr b);
void __asan_register_globals(uptr a, uptr b);
void __asan_init(void);
void __asan_unregister_image_globals(uptr);
void __asan_register_image_globals(uptr);
__END_DECLS

#endif /* KERNEL_PRIVATE */
#endif /* _KASAN_H_ */
