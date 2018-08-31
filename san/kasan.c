/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <vm/vm_map.h>
#include <kern/assert.h>
#include <kern/cpu_data.h>
#include <kern/backtrace.h>
#include <machine/machine_routines.h>
#include <kern/locks.h>
#include <kern/simple_lock.h>
#include <kern/debug.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>
#include <mach/mach_vm.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <mach/machine/vm_param.h>
#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>
#include <libkern/kernel_mach_header.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <kern/thread.h>
#include <machine/atomic.h>

#include <kasan.h>
#include <kasan_internal.h>
#include <memintrinsics.h>

const uintptr_t __asan_shadow_memory_dynamic_address = KASAN_SHIFT;

static unsigned kexts_loaded;
unsigned shadow_pages_total;
unsigned shadow_pages_used;

vm_offset_t kernel_vbase;
vm_offset_t kernel_vtop;

static unsigned kasan_enabled;
static unsigned quarantine_enabled;
static unsigned enabled_checks = TYPE_ALL; /* bitmask of enabled checks */
static unsigned report_ignored;            /* issue non-fatal report for disabled/blacklisted checks */
static unsigned free_yield = 0;            /* ms yield after each free */

/* forward decls */
static void kasan_crash_report(uptr p, uptr width, access_t access, violation_t reason);
static void kasan_log_report(uptr p, uptr width, access_t access, violation_t reason);

/* imported osfmk functions */
extern vm_offset_t ml_stack_base(void);
extern vm_size_t ml_stack_size(void);

/*
 * unused: expected to be called, but (currently) does nothing
 */
#define UNUSED_ABI(func, ...) \
	_Pragma("clang diagnostic push") \
	_Pragma("clang diagnostic ignored \"-Wunused-parameter\"") \
	void func(__VA_ARGS__); \
	void func(__VA_ARGS__) {}; \
	_Pragma("clang diagnostic pop") \

static const size_t BACKTRACE_BITS       = 4;
static const size_t BACKTRACE_MAXFRAMES  = (1UL << BACKTRACE_BITS) - 1;

decl_simple_lock_data(, kasan_vm_lock);
static thread_t kasan_lock_holder;

/*
 * kasan is called from the interrupt path, so we need to disable interrupts to
 * ensure atomicity manipulating the global objects
 */
void
kasan_lock(boolean_t *b)
{
	*b = ml_set_interrupts_enabled(false);
	simple_lock(&kasan_vm_lock);
	kasan_lock_holder = current_thread();
}

void
kasan_unlock(boolean_t b)
{
	kasan_lock_holder = THREAD_NULL;
	simple_unlock(&kasan_vm_lock);
	ml_set_interrupts_enabled(b);
}

/* Return true if 'thread' holds the kasan lock. Only safe if 'thread' == current
 * thread */
bool
kasan_lock_held(thread_t thread)
{
	return thread && thread == kasan_lock_holder;
}

static inline bool
kasan_check_enabled(access_t access)
{
	return kasan_enabled && (enabled_checks & access) && !kasan_is_blacklisted(access);
}

static inline bool
kasan_poison_active(uint8_t flags)
{
	switch (flags) {
	case ASAN_GLOBAL_RZ:
		return kasan_check_enabled(TYPE_POISON_GLOBAL);
	case ASAN_HEAP_RZ:
	case ASAN_HEAP_LEFT_RZ:
	case ASAN_HEAP_RIGHT_RZ:
	case ASAN_HEAP_FREED:
		return kasan_check_enabled(TYPE_POISON_HEAP);
	default:
		return true;
	};
}

/*
 * poison redzones in the shadow map
 */
void NOINLINE
kasan_poison(vm_offset_t base, vm_size_t size, vm_size_t leftrz, vm_size_t rightrz, uint8_t flags)
{
	uint8_t *shadow = SHADOW_FOR_ADDRESS(base);
	uint8_t partial = size & 0x07;
	vm_size_t total = leftrz + size + rightrz;
	vm_size_t i = 0;

	/* base must be 8-byte aligned */
	/* any left redzone must be a multiple of 8 */
	/* total region must cover 8-byte multiple */
	assert((base & 0x07) == 0);
	assert((leftrz & 0x07) == 0);
	assert((total & 0x07) == 0);

	if (!kasan_enabled || !kasan_poison_active(flags)) {
		return;
	}

	leftrz /= 8;
	size /= 8;
	total /= 8;

	uint8_t l_flags = flags;
	uint8_t r_flags = flags;

	if (flags == ASAN_STACK_RZ) {
		l_flags = ASAN_STACK_LEFT_RZ;
		r_flags = ASAN_STACK_RIGHT_RZ;
	} else if (flags == ASAN_HEAP_RZ) {
		l_flags = ASAN_HEAP_LEFT_RZ;
		r_flags = ASAN_HEAP_RIGHT_RZ;
	}

	/*
	 * poison the redzones and unpoison the valid bytes
	 */
	for (; i < leftrz; i++) {
		shadow[i] = l_flags;
	}
	for (; i < leftrz + size; i++) {
		shadow[i] = ASAN_VALID; /* XXX: should not be necessary */
	}
	if (partial && (i < total)) {
		shadow[i] = partial;
		i++;
	}
	for (; i < total; i++) {
		shadow[i] = r_flags;
	}
}

void
kasan_poison_range(vm_offset_t base, vm_size_t size, uint8_t flags)
{
	/* base must be 8-byte aligned */
	/* total region must cover 8-byte multiple */
	assert((base & 0x07) == 0);
	assert((size & 0x07) == 0);
	kasan_poison(base, 0, 0, size, flags);
}

void NOINLINE
kasan_unpoison(void *base, vm_size_t size)
{
	kasan_poison((vm_offset_t)base, size, 0, 0, 0);
}

void NOINLINE
kasan_unpoison_stack(vm_offset_t base, vm_size_t size)
{
	assert(base);
	assert(size);

	/* align base and size to 8 bytes */
	vm_offset_t align = base & 0x7;
	base -= align;
	size += align;
	size = (size + 7) & ~0x7;

	kasan_unpoison((void *)base, size);
}

/*
 * write junk into the redzones
 */
static void NOINLINE
kasan_rz_clobber(vm_offset_t base, vm_size_t size, vm_size_t leftrz, vm_size_t rightrz)
{
#if KASAN_DEBUG
	vm_size_t i;
	const uint8_t deadbeef[] = { 0xde, 0xad, 0xbe, 0xef };
	const uint8_t c0ffee[] = { 0xc0, 0xff, 0xee, 0xc0 };
	uint8_t *buf = (uint8_t *)base;

	/* base must be 8-byte aligned */
	/* any left redzone must be a multiple of 8 */
	/* total region must cover 8-byte multiple */
	assert((base & 0x07) == 0);
	assert((leftrz & 0x07) == 0);
	assert(((size + leftrz + rightrz) & 0x07) == 0);

	for (i = 0; i < leftrz; i++) {
		buf[i] = deadbeef[i % 4];
	}

	for (i = 0; i < rightrz; i++) {
		buf[i + size + leftrz] = c0ffee[i % 4];
	}
#else
	(void)base;
	(void)size;
	(void)leftrz;
	(void)rightrz;
#endif
}

/*
 * Report a violation that may be disabled and/or blacklisted. This can only be
 * called for dynamic checks (i.e. where the fault is recoverable). Use
 * kasan_crash_report() for static (unrecoverable) violations.
 *
 * access: what we were trying to do when the violation occured
 * reason: what failed about the access
 */
static void
kasan_violation(uintptr_t addr, size_t size, access_t access, violation_t reason)
{
	assert(__builtin_popcount(access) == 1);
	if (!kasan_check_enabled(access)) {
		if (report_ignored) {
			kasan_log_report(addr, size, access, reason);
		}
		return;
	}
	kasan_crash_report(addr, size, access, reason);
}

void NOINLINE
kasan_check_range(const void *x, size_t sz, access_t access)
{
	uintptr_t invalid;
	uintptr_t ptr = (uintptr_t)x;
	if (kasan_range_poisoned(ptr, sz, &invalid)) {
		size_t remaining = sz - (invalid - ptr);
		kasan_violation(invalid, remaining, access, 0);
	}
}

/*
 * Return true if [base, base+sz) is unpoisoned or has given shadow value.
 */
static bool
kasan_check_shadow(vm_address_t base, vm_size_t sz, uint8_t shadow)
{
	sz -= 8 - (base % 8);
	base += 8 - (base % 8);

	vm_address_t end = base + sz;

	while (base < end) {
		uint8_t *sh = SHADOW_FOR_ADDRESS(base);
		if (*sh && *sh != shadow) {
			return false;
		}
		base += 8;
	}
	return true;
}

/*
 *
 * KASAN violation reporting
 *
 */

static const char *
access_str(access_t type)
{
	if (type & TYPE_READ) {
		return "load from";
	} else if (type & TYPE_WRITE) {
		return "store to";
	} else if (type & TYPE_FREE) {
		return "free of";
	} else {
		return "access of";
	}
}

static const char *shadow_strings[] = {
	[ASAN_VALID] =          "VALID",
	[ASAN_PARTIAL1] =       "PARTIAL1",
	[ASAN_PARTIAL2] =       "PARTIAL2",
	[ASAN_PARTIAL3] =       "PARTIAL3",
	[ASAN_PARTIAL4] =       "PARTIAL4",
	[ASAN_PARTIAL5] =       "PARTIAL5",
	[ASAN_PARTIAL6] =       "PARTIAL6",
	[ASAN_PARTIAL7] =       "PARTIAL7",
	[ASAN_STACK_LEFT_RZ] =  "STACK_LEFT_RZ",
	[ASAN_STACK_MID_RZ] =   "STACK_MID_RZ",
	[ASAN_STACK_RIGHT_RZ] = "STACK_RIGHT_RZ",
	[ASAN_STACK_FREED] =    "STACK_FREED",
	[ASAN_STACK_OOSCOPE] =  "STACK_OOSCOPE",
	[ASAN_GLOBAL_RZ] =      "GLOBAL_RZ",
	[ASAN_HEAP_LEFT_RZ] =   "HEAP_LEFT_RZ",
	[ASAN_HEAP_RIGHT_RZ] =  "HEAP_RIGHT_RZ",
	[ASAN_HEAP_FREED] =     "HEAP_FREED",
	[0xff] =                NULL
};

#define CRASH_CONTEXT_BEFORE 5
#define CRASH_CONTEXT_AFTER  5

static size_t
kasan_shadow_crashlog(uptr p, char *buf, size_t len)
{
	int i,j;
	size_t n = 0;
	int before = CRASH_CONTEXT_BEFORE;
	int after = CRASH_CONTEXT_AFTER;

	uptr shadow = (uptr)SHADOW_FOR_ADDRESS(p);
	uptr shadow_p = shadow;
	uptr shadow_page = vm_map_round_page(shadow_p, PAGE_MASK);

	/* rewind to start of context block */
	shadow &= ~((uptr)0xf);
	shadow -= 16 * before;

	n += snprintf(buf+n, len-n,
			" Shadow             0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f\n");

	for (i = 0; i < 1 + before + after; i++, shadow += 16) {
		if ((vm_map_round_page(shadow, PAGE_MASK) != shadow_page) && !kasan_is_shadow_mapped(shadow)) {
			/* avoid unmapped shadow when crossing page boundaries */
			continue;
		}

		n += snprintf(buf+n, len-n, " %16lx:", shadow);

		char *left = " ";
		char *right;

		for (j = 0; j < 16; j++) {
			uint8_t *x = (uint8_t *)(shadow + j);

			right = " ";
			if ((uptr)x == shadow_p) {
				left = "[";
				right = "]";
			} else if ((uptr)(x + 1) == shadow_p) {
				right = "";
			}

			n += snprintf(buf+n, len-n, "%s%02x%s", left, (unsigned)*x, right);
			left = "";
		}
		n += snprintf(buf+n, len-n, "\n");
	}

	n += snprintf(buf+n, len-n, "\n");
	return n;
}

static void
kasan_report_internal(uptr p, uptr width, access_t access, violation_t reason, bool dopanic)
{
	const size_t len = 4096;
	static char buf[len];
	size_t n = 0;

	uint8_t *shadow_ptr = SHADOW_FOR_ADDRESS(p);
	uint8_t shadow_type = *shadow_ptr;
	const char *shadow_str = shadow_strings[shadow_type];
	if (!shadow_str) {
		shadow_str = "<invalid>";
	}
	buf[0] = '\0';

	if (reason == REASON_MOD_OOB || reason == REASON_BAD_METADATA) {
		n += snprintf(buf+n, len-n, "KASan: free of corrupted/invalid object %#lx\n", p);
	} else if (reason == REASON_MOD_AFTER_FREE) {
		n += snprintf(buf+n, len-n, "KASan: UaF of quarantined object %#lx\n", p);
	} else {
		n += snprintf(buf+n, len-n, "KASan: invalid %lu-byte %s %#lx [%s]\n",
				width, access_str(access), p, shadow_str);
	}
	n += kasan_shadow_crashlog(p, buf+n, len-n);

	if (dopanic) {
		panic("%s", buf);
	} else {
		printf("%s", buf);
	}
}

static void NOINLINE OS_NORETURN
kasan_crash_report(uptr p, uptr width, access_t access, violation_t reason)
{
	kasan_handle_test();
	kasan_report_internal(p, width, access, reason, true);
	__builtin_unreachable(); /* we cant handle this returning anyway */
}

static void
kasan_log_report(uptr p, uptr width, access_t access, violation_t reason)
{
	const size_t len = 256;
	char buf[len];
	size_t l = 0;
	uint32_t nframes = 14;
	uintptr_t frames[nframes];
	uintptr_t *bt = frames;

	kasan_report_internal(p, width, access, reason, false);

	/*
	 * print a backtrace
	 */

	nframes = backtrace_frame(bt, nframes, __builtin_frame_address(0)); /* ignore current frame */

	buf[0] = '\0';
	l += snprintf(buf+l, len-l, "Backtrace: ");
	for (uint32_t i = 0; i < nframes; i++) {
		l += snprintf(buf+l, len-l, "%lx,", VM_KERNEL_UNSLIDE(bt[i]));
	}
	l += snprintf(buf+l, len-l, "\n");

	printf("%s", buf);
}

#define REPORT_DECLARE(n) \
	void OS_NORETURN __asan_report_load##n(uptr p)  { kasan_crash_report(p, n, TYPE_LOAD,  0); } \
	void OS_NORETURN __asan_report_store##n(uptr p) { kasan_crash_report(p, n, TYPE_STORE, 0); } \
	void UNSUPPORTED_API(__asan_report_exp_load##n, uptr a, int32_t b); \
	void UNSUPPORTED_API(__asan_report_exp_store##n, uptr a, int32_t b);

REPORT_DECLARE(1)
REPORT_DECLARE(2)
REPORT_DECLARE(4)
REPORT_DECLARE(8)
REPORT_DECLARE(16)

void OS_NORETURN __asan_report_load_n(uptr p, unsigned long sz)  { kasan_crash_report(p, sz, TYPE_LOAD,  0); }
void OS_NORETURN __asan_report_store_n(uptr p, unsigned long sz) { kasan_crash_report(p, sz, TYPE_STORE, 0); }

/* unpoison the current stack */
void NOINLINE
kasan_unpoison_curstack(bool whole_stack)
{
	uintptr_t base = ml_stack_base();
	size_t sz = ml_stack_size();
	uintptr_t cur = (uintptr_t)&base;

	if (whole_stack) {
		cur = base;
	}

	if (cur >= base && cur < base + sz) {
		/* unpoison from current stack depth to the top */
		size_t unused = cur - base;
		kasan_unpoison_stack(cur, sz - unused);
	}
}

void NOINLINE
__asan_handle_no_return(void)
{
	kasan_unpoison_curstack(false);
	kasan_unpoison_fakestack(current_thread());
}

bool NOINLINE
kasan_range_poisoned(vm_offset_t base, vm_size_t size, vm_offset_t *first_invalid)
{
	uint8_t *shadow;
	vm_size_t i;

	if (!kasan_enabled) {
		return false;
	}

	size += base & 0x07;
	base &= ~(vm_offset_t)0x07;

	shadow = SHADOW_FOR_ADDRESS(base);
	vm_size_t limit = (size + 7) / 8;

	/* XXX: to make debugging easier, catch unmapped shadow here */

	for (i = 0; i < limit; i++, size -= 8) {
		assert(size > 0);
		uint8_t s = shadow[i];
		if (s == 0 || (size < 8 && s >= size && s <= 7)) {
			/* valid */
		} else {
			goto fail;
		}
	}

	return false;

 fail:
	if (first_invalid) {
		/* XXX: calculate the exact first byte that failed */
		*first_invalid = base + i*8;
	}
	return true;
}

static void NOINLINE
kasan_init_globals(vm_offset_t base, vm_size_t size)
{
	struct asan_global *glob = (struct asan_global *)base;
	struct asan_global *glob_end = (struct asan_global *)(base + size);
	for (; glob < glob_end; glob++) {
		/* handle one global */
		kasan_poison(glob->addr, glob->size, 0, glob->size_with_redzone - glob->size, ASAN_GLOBAL_RZ);
	}
}

void NOINLINE
kasan_load_kext(vm_offset_t base, vm_size_t __unused size, const void *bundleid)
{
	unsigned long sectsz;
	void *sect;

#if KASAN_DYNAMIC_BLACKLIST
	kasan_dybl_load_kext(base, bundleid);
#endif

	/* find the kasan globals segment/section */
	sect = getsectdatafromheader((void *)base, KASAN_GLOBAL_SEGNAME, KASAN_GLOBAL_SECTNAME, &sectsz);
	if (sect) {
		kasan_init_globals((vm_address_t)sect, (vm_size_t)sectsz);
		kexts_loaded++;
	}
}

void NOINLINE
kasan_unload_kext(vm_offset_t base, vm_size_t size)
{
	unsigned long sectsz;
	void *sect;

	/* find the kasan globals segment/section */
	sect = getsectdatafromheader((void *)base, KASAN_GLOBAL_SEGNAME, KASAN_GLOBAL_SECTNAME, &sectsz);
	if (sect) {
		kasan_unpoison((void *)base, size);
		kexts_loaded--;
	}

#if KASAN_DYNAMIC_BLACKLIST
	kasan_dybl_unload_kext(base);
#endif
}

/*
 * Turn off as much as possible for panic path etc. There's no way to turn it back
 * on.
 */
void NOINLINE
kasan_disable(void)
{
	__asan_option_detect_stack_use_after_return = 0;
	fakestack_enabled = 0;
	kasan_enabled = 0;
	quarantine_enabled = 0;
	enabled_checks = 0;
}

static void NOINLINE
kasan_init_xnu_globals(void)
{
	const char *seg = KASAN_GLOBAL_SEGNAME;
	const char *sect = KASAN_GLOBAL_SECTNAME;
	unsigned long _size;
	vm_offset_t globals;
	vm_size_t size;
	kernel_mach_header_t *header = (kernel_mach_header_t *)&_mh_execute_header;

	if (!header) {
		printf("KASan: failed to find kernel mach header\n");
		printf("KASan: redzones for globals not poisoned\n");
		return;
	}

	globals = (vm_offset_t)getsectdatafromheader(header, seg, sect, &_size);
	if (!globals) {
		printf("KASan: failed to find segment %s section %s\n", seg, sect);
		printf("KASan: redzones for globals not poisoned\n");
		return;
	}
	size = (vm_size_t)_size;

	printf("KASan: found (%s,%s) at %#lx + %lu\n", seg, sect, globals, size);
	printf("KASan: poisoning redzone for %lu globals\n", size / sizeof(struct asan_global));

	kasan_init_globals(globals, size);
}

void NOINLINE
kasan_late_init(void)
{
#if KASAN_DYNAMIC_BLACKLIST
	kasan_init_dybl();
#endif

	kasan_init_fakestack();
	kasan_init_xnu_globals();
}

void NOINLINE
kasan_notify_stolen(vm_offset_t top)
{
	kasan_map_shadow(kernel_vtop, top - kernel_vtop, false);
}

static void NOINLINE
kasan_debug_touch_mappings(vm_offset_t base, vm_size_t sz)
{
#if KASAN_DEBUG
	vm_size_t i;
	uint8_t tmp1, tmp2;

	/* Hit every byte in the shadow map. Don't write due to the zero mappings. */
	for (i = 0; i < sz; i += sizeof(uint64_t)) {
		vm_offset_t addr = base + i;
		uint8_t *x = SHADOW_FOR_ADDRESS(addr);
		tmp1 = *x;
		asm volatile("" ::: "memory");
		tmp2 = *x;
		asm volatile("" ::: "memory");
		assert(tmp1 == tmp2);
	}
#else
	(void)base;
	(void)sz;
#endif
}

void NOINLINE
kasan_init(void)
{
	unsigned arg;

	simple_lock_init(&kasan_vm_lock, 0);

	/* Map all of the kernel text and data */
	kasan_map_shadow(kernel_vbase, kernel_vtop - kernel_vbase, false);

	kasan_arch_init();

	/*
	 * handle KASan boot-args
	 */

	if (PE_parse_boot_argn("kasan.checks", &arg, sizeof(arg))) {
		enabled_checks = arg;
	}

	if (PE_parse_boot_argn("kasan", &arg, sizeof(arg))) {
		if (arg & KASAN_ARGS_FAKESTACK) {
			fakestack_enabled = 1;
		}
		if (arg & KASAN_ARGS_REPORTIGNORED) {
			report_ignored = 1;
		}
		if (arg & KASAN_ARGS_NODYCHECKS) {
			enabled_checks &= ~TYPE_DYNAMIC;
		}
		if (arg & KASAN_ARGS_NOPOISON_HEAP) {
			enabled_checks &= ~TYPE_POISON_HEAP;
		}
		if (arg & KASAN_ARGS_NOPOISON_GLOBAL) {
			enabled_checks &= ~TYPE_POISON_GLOBAL;
		}
	}

	if (PE_parse_boot_argn("kasan.free_yield_ms", &arg, sizeof(arg))) {
		free_yield = arg;
	}

	/* kasan.bl boot-arg handled in kasan_init_dybl() */

	quarantine_enabled = 1;
	kasan_enabled = 1;
}

static void NOINLINE
kasan_notify_address_internal(vm_offset_t address, vm_size_t size, bool is_zero)
{
	assert(address < VM_MAX_KERNEL_ADDRESS);

	if (!kasan_enabled) {
		return;
	}

	if (address < VM_MIN_KERNEL_AND_KEXT_ADDRESS) {
		/* only map kernel addresses */
		return;
	}

	if (!size) {
		/* nothing to map */
		return;
	}

	boolean_t flags;
	kasan_lock(&flags);
	kasan_map_shadow(address, size, is_zero);
	kasan_unlock(flags);
	kasan_debug_touch_mappings(address, size);
}

void
kasan_notify_address(vm_offset_t address, vm_size_t size)
{
	kasan_notify_address_internal(address, size, false);
}

/*
 * Allocate read-only, all-zeros shadow for memory that can never be poisoned
 */
void
kasan_notify_address_nopoison(vm_offset_t address, vm_size_t size)
{
	kasan_notify_address_internal(address, size, true);
}

/*
 *
 * allocator hooks
 *
 */

struct kasan_alloc_header {
	uint16_t magic;
	uint16_t crc;
	uint32_t alloc_size;
	uint32_t user_size;
	struct {
		uint32_t left_rz : 32 - BACKTRACE_BITS;
		uint32_t frames  : BACKTRACE_BITS;
	};
};
_Static_assert(sizeof(struct kasan_alloc_header) <= KASAN_GUARD_SIZE, "kasan alloc header exceeds guard size");

struct kasan_alloc_footer {
	uint32_t backtrace[0];
};
_Static_assert(sizeof(struct kasan_alloc_footer) <= KASAN_GUARD_SIZE, "kasan alloc footer exceeds guard size");

#define LIVE_XOR ((uint16_t)0x3a65)
#define FREE_XOR ((uint16_t)0xf233)

static uint16_t
magic_for_addr(vm_offset_t addr, uint16_t magic_xor)
{
	uint16_t magic = addr & 0xFFFF;
	magic ^= (addr >> 16) & 0xFFFF;
	magic ^= (addr >> 32) & 0xFFFF;
	magic ^= (addr >> 48) & 0xFFFF;
	magic ^= magic_xor;
	return magic;
}

static struct kasan_alloc_header *
header_for_user_addr(vm_offset_t addr)
{
	return (void *)(addr - sizeof(struct kasan_alloc_header));
}

static struct kasan_alloc_footer *
footer_for_user_addr(vm_offset_t addr, vm_size_t *size)
{
	struct kasan_alloc_header *h = header_for_user_addr(addr);
	vm_size_t rightrz = h->alloc_size - h->user_size - h->left_rz;
	*size = rightrz;
	return (void *)(addr + h->user_size);
}

/*
 * size: user-requested allocation size
 * ret:  minimum size for the real allocation
 */
vm_size_t
kasan_alloc_resize(vm_size_t size)
{
	vm_size_t tmp;
	if (os_add_overflow(size, 4 * PAGE_SIZE, &tmp)) {
		panic("allocation size overflow (%lu)", size);
	}

	/* add left and right redzones */
	size += KASAN_GUARD_PAD;

	/* ensure the final allocation is an 8-byte multiple */
	size += 8 - (size % 8);

	return size;
}

extern vm_offset_t vm_kernel_slid_base;

static vm_size_t
kasan_alloc_bt(uint32_t *ptr, vm_size_t sz, vm_size_t skip)
{
	uintptr_t buf[BACKTRACE_MAXFRAMES];
	uintptr_t *bt = buf;

	sz /= sizeof(uint32_t);
	vm_size_t frames = sz;

	if (frames > 0) {
		frames = min(frames + skip, BACKTRACE_MAXFRAMES);
		frames = backtrace(bt, frames);

		while (frames > sz && skip > 0) {
			bt++;
			frames--;
			skip--;
		}

		/* only store the offset from kernel base, and cram that into 32
		 * bits */
		for (vm_size_t i = 0; i < frames; i++) {
			ptr[i] = (uint32_t)(bt[i] - vm_kernel_slid_base);
		}
	}
	return frames;
}

/* addr: user address of allocation */
static uint16_t
kasan_alloc_crc(vm_offset_t addr)
{
	struct kasan_alloc_header *h = header_for_user_addr(addr);
	vm_size_t rightrz = h->alloc_size - h->user_size - h->left_rz;

	uint16_t crc_orig = h->crc;
	h->crc = 0;

	uint16_t crc = 0;
	crc = __nosan_crc16(crc, (void *)(addr - h->left_rz), h->left_rz);
	crc = __nosan_crc16(crc, (void *)(addr + h->user_size), rightrz);

	h->crc = crc_orig;

	return crc;
}

/*
 * addr: base address of full allocation (including redzones)
 * size: total size of allocation (include redzones)
 * req:  user-requested allocation size
 * lrz:  size of the left redzone in bytes
 * ret:  address of usable allocation
 */
vm_address_t
kasan_alloc(vm_offset_t addr, vm_size_t size, vm_size_t req, vm_size_t leftrz)
{
	if (!addr) {
		return 0;
	}
	assert(size > 0);
	assert((addr % 8) == 0);
	assert((size % 8) == 0);

	vm_size_t rightrz = size - req - leftrz;

	kasan_poison(addr, req, leftrz, rightrz, ASAN_HEAP_RZ);
	kasan_rz_clobber(addr, req, leftrz, rightrz);

	addr += leftrz;

	/* stash the allocation sizes in the left redzone */
	struct kasan_alloc_header *h = header_for_user_addr(addr);
	h->magic = magic_for_addr(addr, LIVE_XOR);
	h->left_rz = leftrz;
	h->alloc_size = size;
	h->user_size = req;

	/* ... and a backtrace in the right redzone */
	vm_size_t fsize;
	struct kasan_alloc_footer *f = footer_for_user_addr(addr, &fsize);
	h->frames = kasan_alloc_bt(f->backtrace, fsize, 2);

	/* checksum the whole object, minus the user part */
	h->crc = kasan_alloc_crc(addr);

	return addr;
}

/*
 * addr: user pointer
 * size: returns full original allocation size
 * ret:  original allocation ptr
 */
vm_address_t
kasan_dealloc(vm_offset_t addr, vm_size_t *size)
{
	assert(size && addr);
	struct kasan_alloc_header *h = header_for_user_addr(addr);
	*size = h->alloc_size;
	return addr - h->left_rz;
}

/*
 * return the original user-requested allocation size
 * addr: user alloc pointer
 */
vm_size_t
kasan_user_size(vm_offset_t addr)
{
	struct kasan_alloc_header *h = header_for_user_addr(addr);
	assert(h->magic == magic_for_addr(addr, LIVE_XOR));
	return h->user_size;
}

/*
 * Verify that `addr' (user pointer) is a valid allocation of `type'
 */
void
kasan_check_free(vm_offset_t addr, vm_size_t size, unsigned heap_type)
{
	struct kasan_alloc_header *h = header_for_user_addr(addr);

	/* map heap type to an internal access type */
	access_t type = heap_type == KASAN_HEAP_KALLOC    ? TYPE_KFREE  :
	                heap_type == KASAN_HEAP_ZALLOC    ? TYPE_ZFREE  :
	                heap_type == KASAN_HEAP_FAKESTACK ? TYPE_FSFREE : 0;

	/* check the magic and crc match */
	if (h->magic != magic_for_addr(addr, LIVE_XOR)) {
		kasan_violation(addr, size, type, REASON_BAD_METADATA);
	}
	if (h->crc != kasan_alloc_crc(addr)) {
		kasan_violation(addr, size, type, REASON_MOD_OOB);
	}

	/* check the freed size matches what we recorded at alloc time */
	if (h->user_size != size) {
		kasan_violation(addr, size, type, REASON_INVALID_SIZE);
	}

	vm_size_t rightrz_sz = h->alloc_size - h->left_rz - h->user_size;

	/* Check that the redzones are valid */
	if (!kasan_check_shadow(addr - h->left_rz, h->left_rz, ASAN_HEAP_LEFT_RZ) ||
		!kasan_check_shadow(addr + h->user_size, rightrz_sz, ASAN_HEAP_RIGHT_RZ)) {
		kasan_violation(addr, size, type, REASON_BAD_METADATA);
	}

	/* Check the allocated range is not poisoned */
	kasan_check_range((void *)addr, size, type);
}

/*
 *
 * Quarantine
 *
 */

struct freelist_entry {
	uint16_t magic;
	uint16_t crc;
	STAILQ_ENTRY(freelist_entry) list;
	union {
		struct {
			vm_size_t size      : 28;
			vm_size_t user_size : 28;
			vm_size_t frames    : BACKTRACE_BITS; /* number of frames in backtrace */
			vm_size_t __unused  : 8 - BACKTRACE_BITS;
		};
		uint64_t bits;
	};
	zone_t zone;
	uint32_t backtrace[];
};
_Static_assert(sizeof(struct freelist_entry) <= KASAN_GUARD_PAD, "kasan freelist header exceeds padded size");

struct quarantine {
	STAILQ_HEAD(freelist_head, freelist_entry) freelist;
	unsigned long entries;
	unsigned long max_entries;
	vm_size_t size;
	vm_size_t max_size;
};

struct quarantine quarantines[] = {
	{ STAILQ_HEAD_INITIALIZER((quarantines[KASAN_HEAP_ZALLOC].freelist)),    0, QUARANTINE_ENTRIES, 0, QUARANTINE_MAXSIZE },
	{ STAILQ_HEAD_INITIALIZER((quarantines[KASAN_HEAP_KALLOC].freelist)),    0, QUARANTINE_ENTRIES, 0, QUARANTINE_MAXSIZE },
	{ STAILQ_HEAD_INITIALIZER((quarantines[KASAN_HEAP_FAKESTACK].freelist)), 0, QUARANTINE_ENTRIES, 0, QUARANTINE_MAXSIZE }
};

static uint16_t
fle_crc(struct freelist_entry *fle)
{
	return __nosan_crc16(0, &fle->bits, fle->size - offsetof(struct freelist_entry, bits));
}

/*
 * addr, sizep: pointer/size of full allocation including redzone
 */
void NOINLINE
kasan_free_internal(void **addrp, vm_size_t *sizep, int type,
                    zone_t *zone, vm_size_t user_size, int locked,
                    bool doquarantine)
{
	vm_size_t size = *sizep;
	vm_offset_t addr = *(vm_offset_t *)addrp;

	assert(type >= 0 && type < KASAN_HEAP_TYPES);
	if (type == KASAN_HEAP_KALLOC) {
		/* zero-size kalloc allocations are allowed */
		assert(!zone);
	} else if (type == KASAN_HEAP_ZALLOC) {
		assert(zone && user_size);
	} else if (type == KASAN_HEAP_FAKESTACK) {
		assert(zone && user_size);
	}

	/* clobber the entire freed region */
	kasan_rz_clobber(addr, 0, size, 0);

	if (!doquarantine || !quarantine_enabled) {
		goto free_current;
	}

	/* poison the entire freed region */
	uint8_t flags = (type == KASAN_HEAP_FAKESTACK) ? ASAN_STACK_FREED : ASAN_HEAP_FREED;
	kasan_poison(addr, 0, size, 0, flags);

	struct freelist_entry *fle, *tofree = NULL;
	struct quarantine *q = &quarantines[type];
	assert(size >= sizeof(struct freelist_entry));

	/* create a new freelist entry */
	fle = (struct freelist_entry *)addr;
	fle->magic = magic_for_addr((vm_offset_t)fle, FREE_XOR);
	fle->size = size;
	fle->user_size = user_size;
	fle->frames = 0;
	fle->zone = ZONE_NULL;
	if (zone) {
		fle->zone = *zone;
	}
	if (type != KASAN_HEAP_FAKESTACK) {
		/* don't do expensive things on the fakestack path */
		fle->frames = kasan_alloc_bt(fle->backtrace, fle->size - sizeof(struct freelist_entry), 3);
		fle->crc = fle_crc(fle);
	}

	boolean_t flg;
	if (!locked) {
		kasan_lock(&flg);
	}

	if (q->size + size > q->max_size) {
		/*
		 * Adding this entry would put us over the max quarantine size. Free the
		 * larger of the current object and the quarantine head object.
		 */
		tofree = STAILQ_FIRST(&q->freelist);
		if (fle->size > tofree->size) {
			goto free_current_locked;
		}
	}

	STAILQ_INSERT_TAIL(&q->freelist, fle, list);
	q->entries++;
	q->size += size;

	/* free the oldest entry, if necessary */
	if (tofree || q->entries > q->max_entries) {
		tofree = STAILQ_FIRST(&q->freelist);
		STAILQ_REMOVE_HEAD(&q->freelist, list);

		assert(q->entries > 0 && q->size >= tofree->size);
		q->entries--;
		q->size -= tofree->size;

		if (type != KASAN_HEAP_KALLOC) {
			assert((vm_offset_t)zone >= VM_MIN_KERNEL_AND_KEXT_ADDRESS &&
			       (vm_offset_t)zone <= VM_MAX_KERNEL_ADDRESS);
			*zone = tofree->zone;
		}

		size = tofree->size;
		addr = (vm_offset_t)tofree;

		/* check the magic and crc match */
		if (tofree->magic != magic_for_addr(addr, FREE_XOR)) {
			kasan_violation(addr, size, TYPE_UAF, REASON_MOD_AFTER_FREE);
		}
		if (type != KASAN_HEAP_FAKESTACK && tofree->crc != fle_crc(tofree)) {
			kasan_violation(addr, size, TYPE_UAF, REASON_MOD_AFTER_FREE);
		}

		/* clobber the quarantine header */
		__nosan_bzero((void *)addr, sizeof(struct freelist_entry));

	} else {
		/* quarantine is not full - don't really free anything */
		addr = 0;
	}

 free_current_locked:
	if (!locked) {
		kasan_unlock(flg);
	}

 free_current:
	*addrp = (void *)addr;
	if (addr) {
		kasan_unpoison((void *)addr, size);
		*sizep = size;
	}
}

void NOINLINE
kasan_free(void **addrp, vm_size_t *sizep, int type, zone_t *zone,
           vm_size_t user_size, bool quarantine)
{
	kasan_free_internal(addrp, sizep, type, zone, user_size, 0, quarantine);

	if (free_yield) {
		thread_yield_internal(free_yield);
	}
}

uptr
__asan_load_cxx_array_cookie(uptr *p)
{
	uint8_t *shadow = SHADOW_FOR_ADDRESS((uptr)p);
	if (*shadow == ASAN_ARRAY_COOKIE) {
		return *p;
	} else if (*shadow == ASAN_HEAP_FREED) {
		return 0;
	} else {
		return *p;
	}
}

void
__asan_poison_cxx_array_cookie(uptr p)
{
	uint8_t *shadow = SHADOW_FOR_ADDRESS(p);
	*shadow = ASAN_ARRAY_COOKIE;
}

#define ACCESS_CHECK_DECLARE(type, sz, access) \
	void __asan_##type##sz(uptr addr) { \
		kasan_check_range((const void *)addr, sz, access); \
	} \
	void UNSUPPORTED_API(__asan_exp_##type##sz, uptr a, int32_t b);

ACCESS_CHECK_DECLARE(load,  1,  TYPE_LOAD);
ACCESS_CHECK_DECLARE(load,  2,  TYPE_LOAD);
ACCESS_CHECK_DECLARE(load,  4,  TYPE_LOAD);
ACCESS_CHECK_DECLARE(load,  8,  TYPE_LOAD);
ACCESS_CHECK_DECLARE(load,  16, TYPE_LOAD);
ACCESS_CHECK_DECLARE(store, 1,  TYPE_STORE);
ACCESS_CHECK_DECLARE(store, 2,  TYPE_STORE);
ACCESS_CHECK_DECLARE(store, 4,  TYPE_STORE);
ACCESS_CHECK_DECLARE(store, 8,  TYPE_STORE);
ACCESS_CHECK_DECLARE(store, 16, TYPE_STORE);

void
__asan_loadN(uptr addr, size_t sz)
{
	kasan_check_range((const void *)addr, sz, TYPE_LOAD);
}

void
__asan_storeN(uptr addr, size_t sz)
{
	kasan_check_range((const void *)addr, sz, TYPE_STORE);
}

static void
kasan_set_shadow(uptr addr, size_t sz, uint8_t val)
{
	__nosan_memset((void *)addr, val, sz);
}

#define SET_SHADOW_DECLARE(val) \
	void __asan_set_shadow_##val(uptr addr, size_t sz) { \
		kasan_set_shadow(addr, sz, 0x##val); \
	}

SET_SHADOW_DECLARE(00)
SET_SHADOW_DECLARE(f1)
SET_SHADOW_DECLARE(f2)
SET_SHADOW_DECLARE(f3)
SET_SHADOW_DECLARE(f5)
SET_SHADOW_DECLARE(f8)


/*
 * Call 'cb' for each contiguous range of the shadow map. This could be more
 * efficient by walking the page table directly.
 */
int
kasan_traverse_mappings(pmap_traverse_callback cb, void *ctx)
{
	uintptr_t shadow_base = (uintptr_t)SHADOW_FOR_ADDRESS(VM_MIN_KERNEL_AND_KEXT_ADDRESS);
	uintptr_t shadow_top = (uintptr_t)SHADOW_FOR_ADDRESS(VM_MAX_KERNEL_ADDRESS);
	shadow_base = vm_map_trunc_page(shadow_base, PAGE_MASK);
	shadow_top = vm_map_round_page(shadow_top, PAGE_MASK);

	uintptr_t start = 0, end = 0;

	for (uintptr_t addr = shadow_base; addr < shadow_top; addr += PAGE_SIZE) {
		if (kasan_is_shadow_mapped(addr)) {
			if (start == 0) {
				start = addr;
			}
			end = addr + PAGE_SIZE;
		} else if (start && end) {
			cb(start, end, ctx);
			start = end = 0;
		}
	}

	if (start && end) {
		cb(start, end, ctx);
	}

	return 0;
}

/*
 * XXX: implement these
 */

UNUSED_ABI(__asan_alloca_poison, uptr addr, uptr size);
UNUSED_ABI(__asan_allocas_unpoison, uptr top, uptr bottom);
UNUSED_ABI(__sanitizer_ptr_sub, uptr a, uptr b);
UNUSED_ABI(__sanitizer_ptr_cmp, uptr a, uptr b);
UNUSED_ABI(__sanitizer_annotate_contiguous_container, const void *a, const void *b, const void *c, const void *d);
UNUSED_ABI(__asan_poison_stack_memory, uptr addr, size_t size);
UNUSED_ABI(__asan_unpoison_stack_memory, uptr a, uptr b);

/*
 * Miscellaneous unimplemented asan ABI
 */

UNUSED_ABI(__asan_init, void);
UNUSED_ABI(__asan_register_image_globals, uptr a);
UNUSED_ABI(__asan_unregister_image_globals, uptr a);
UNUSED_ABI(__asan_before_dynamic_init, uptr a);
UNUSED_ABI(__asan_after_dynamic_init, void);
UNUSED_ABI(__asan_version_mismatch_check_v8, void);
UNUSED_ABI(__asan_version_mismatch_check_apple_802, void);
UNUSED_ABI(__asan_version_mismatch_check_apple_900, void);
UNUSED_ABI(__asan_version_mismatch_check_apple_902, void);

void UNSUPPORTED_API(__asan_init_v5, void);
void UNSUPPORTED_API(__asan_register_globals, uptr a, uptr b);
void UNSUPPORTED_API(__asan_unregister_globals, uptr a, uptr b);
void UNSUPPORTED_API(__asan_register_elf_globals, uptr a, uptr b, uptr c);
void UNSUPPORTED_API(__asan_unregister_elf_globals, uptr a, uptr b, uptr c);

void UNSUPPORTED_API(__asan_exp_loadN, uptr addr, size_t sz, int32_t e);
void UNSUPPORTED_API(__asan_exp_storeN, uptr addr, size_t sz, int32_t e);
void UNSUPPORTED_API(__asan_report_exp_load_n, uptr addr, unsigned long b, int32_t c);
void UNSUPPORTED_API(__asan_report_exp_store_n, uptr addr, unsigned long b, int32_t c);

/*
 *
 * SYSCTL
 *
 */

static int
sysctl_kasan_test(__unused struct sysctl_oid *oidp, __unused void *arg1, int arg2, struct sysctl_req *req)
{
	int mask = 0;
	int ch;
	int err;
	err = sysctl_io_number(req, 0, sizeof(int), &mask, &ch);

	if (!err && mask) {
		kasan_test(mask, arg2);
	}

	return err;
}

static int
sysctl_fakestack_enable(__unused struct sysctl_oid *oidp, __unused void *arg1, int __unused arg2, struct sysctl_req *req)
{
	int ch, err, val;

	err = sysctl_io_number(req, fakestack_enabled, sizeof(fakestack_enabled), &val, &ch);
	if (err == 0 && ch) {
		fakestack_enabled = !!val;
		__asan_option_detect_stack_use_after_return = !!val;
	}

	return err;
}

SYSCTL_DECL(kasan);
SYSCTL_NODE(_kern, OID_AUTO, kasan, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "");

SYSCTL_COMPAT_INT(_kern_kasan, OID_AUTO, available, CTLFLAG_RD, NULL, KASAN, "");
SYSCTL_UINT(_kern_kasan, OID_AUTO, enabled, CTLFLAG_RD, &kasan_enabled, 0, "");
SYSCTL_UINT(_kern_kasan, OID_AUTO, checks, CTLFLAG_RW, &enabled_checks, 0, "");
SYSCTL_UINT(_kern_kasan, OID_AUTO, quarantine, CTLFLAG_RW, &quarantine_enabled, 0, "");
SYSCTL_UINT(_kern_kasan, OID_AUTO, report_ignored, CTLFLAG_RW, &report_ignored, 0, "");
SYSCTL_UINT(_kern_kasan, OID_AUTO, free_yield_ms, CTLFLAG_RW, &free_yield, 0, "");
SYSCTL_UINT(_kern_kasan, OID_AUTO, memused, CTLFLAG_RD, &shadow_pages_used, 0, "");
SYSCTL_UINT(_kern_kasan, OID_AUTO, memtotal, CTLFLAG_RD, &shadow_pages_total, 0, "");
SYSCTL_UINT(_kern_kasan, OID_AUTO, kexts, CTLFLAG_RD, &kexts_loaded, 0, "");
SYSCTL_COMPAT_UINT(_kern_kasan, OID_AUTO, debug,     CTLFLAG_RD, NULL, KASAN_DEBUG, "");
SYSCTL_COMPAT_UINT(_kern_kasan, OID_AUTO, zalloc,    CTLFLAG_RD, NULL, KASAN_ZALLOC, "");
SYSCTL_COMPAT_UINT(_kern_kasan, OID_AUTO, kalloc,    CTLFLAG_RD, NULL, KASAN_KALLOC, "");
SYSCTL_COMPAT_UINT(_kern_kasan, OID_AUTO, dynamicbl, CTLFLAG_RD, NULL, KASAN_DYNAMIC_BLACKLIST, "");

SYSCTL_PROC(_kern_kasan, OID_AUTO, fakestack,
		CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
		0, 0, sysctl_fakestack_enable, "I", "");

SYSCTL_PROC(_kern_kasan, OID_AUTO, test,
		CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
		0, 0, sysctl_kasan_test, "I", "");

SYSCTL_PROC(_kern_kasan, OID_AUTO, fail,
		CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
		0, 1, sysctl_kasan_test, "I", "");
