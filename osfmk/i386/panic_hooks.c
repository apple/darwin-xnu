/*
 * Copyright (c) 2014-2020 Apple Inc. All rights reserved.
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

#include "panic_hooks.h"

#include <kern/queue.h>
#include <kern/locks.h>
#include <kern/thread.h>
#include <vm/WKdm_new.h>
#include <pexpert/boot.h>

#include "pmap.h"

struct panic_hook {
	uint32_t                        magic1;
	queue_chain_t           chain;
	thread_t                        thread;
	panic_hook_fn_t         hook_fn;
	uint32_t                        magic2;
};

typedef char check1_[sizeof(struct panic_hook)
    <= sizeof(panic_hook_t) ? 1 : -1];
typedef char check2_[PAGE_SIZE == 4096 ? 1 : -1];

static hw_lock_data_t   panic_hooks_lock;
static queue_head_t     panic_hooks;
static uint8_t                  panic_dump_buf[8192];

#define PANIC_HOOK_MAGIC1               0x4A1C400C
#define PANIC_HOOK_MAGIC2               0xC004C1A4

void
panic_hooks_init(void)
{
	hw_lock_init(&panic_hooks_lock);
	queue_init(&panic_hooks);
}

void
panic_hook(panic_hook_t *hook_, panic_hook_fn_t hook_fn)
{
	struct panic_hook *hook = (struct panic_hook *)hook_;

	hook->magic1    = PANIC_HOOK_MAGIC1;
	hook->magic2    = PANIC_HOOK_MAGIC2;
	hook->hook_fn   = hook_fn;
	hook->thread    = current_thread();

	hw_lock_lock(&panic_hooks_lock, LCK_GRP_NULL);
	queue_enter(&panic_hooks, hook, struct panic_hook *, chain);
	hw_lock_unlock(&panic_hooks_lock);
}

void
panic_unhook(panic_hook_t *hook_)
{
	struct panic_hook *hook = (struct panic_hook *)hook_;

	hw_lock_lock(&panic_hooks_lock, LCK_GRP_NULL);
	queue_remove(&panic_hooks, hook, struct panic_hook *, chain);
	hw_lock_unlock(&panic_hooks_lock);
}

void
panic_check_hook(void)
{
	struct panic_hook *hook;
	thread_t thread = current_thread();
	uint32_t count = 0;

	queue_iterate(&panic_hooks, hook, struct panic_hook *, chain) {
		if (++count > 1024
		|| !kvtophys((vm_offset_t)hook)
		|| !kvtophys((vm_offset_t)hook + sizeof(*hook) - 1)
		|| hook->magic1 != PANIC_HOOK_MAGIC1
		|| hook->magic2 != PANIC_HOOK_MAGIC2
		|| !kvtophys((vm_offset_t)hook->hook_fn)) {
			return;
		}

		if (hook->thread == thread) {
			hook->hook_fn((panic_hook_t *)hook);
			return;
		}
	}
}

/*
 * addr should be page aligned and len should be multiple of page
 * size.  This will currently only work if each page can be compressed
 * to no more than 4095 bytes.
 *
 * Remember the debug buffer isn't very big so don't try and dump too
 * much.
 */
void
panic_dump_mem(const void *addr, int len)
{
	void *scratch = panic_dump_buf + 4096;

	for (; len > 0; addr = (const uint8_t *)addr + PAGE_SIZE, len -= PAGE_SIZE) {
		if (!kvtophys((vm_offset_t)addr)) {
			continue;
		}

		// 4095 is multiple of 3 -- see below
		int n = WKdm_compress_new((const WK_word *)addr, (WK_word *)(void *)panic_dump_buf,
		    scratch, 4095);

		if (n == -1) {
			return; // Give up
		}
		kdb_log("%p: ", addr);

		// Dump out base64
		static char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		    "abcdefghijklmnopqrstuvwxyz0123456789+/";

		// Pad to multiple of 3
		switch (n % 3) {
		case 1:
			panic_dump_buf[n++] = 0;
			OS_FALLTHROUGH;
		case 2:
			panic_dump_buf[n++] = 0;
		}

		uint8_t *p = panic_dump_buf;
		while (n) {
			uint8_t c;

			c = p[0] >> 2;
			consdebug_log(base64_table[c]);

			c = (p[0] << 4 | p[1] >> 4) & 0x3f;
			consdebug_log(base64_table[c]);

			c = (p[1] << 2 | p[2] >> 6) & 0x3f;
			consdebug_log(base64_table[c]);

			c = p[2] & 0x3f;
			consdebug_log(base64_table[c]);

			p += 3;
			n -= 3;
		}

		consdebug_log('\n');
	}
}

boolean_t
panic_phys_range_before(const void *addr, uint64_t *pphys,
    panic_phys_range_t *range)
{
	*pphys = kvtophys((vm_offset_t)addr);

	const boot_args *args = PE_state.bootArgs;

	if (!kvtophys((vm_offset_t)args)) {
		return FALSE;
	}

	const EfiMemoryRange *r = PHYSMAP_PTOV((uintptr_t)args->MemoryMap), *closest = NULL;
	const uint32_t size = args->MemoryMapDescriptorSize;
	const uint32_t count = args->MemoryMapSize / size;

	if (count > 1024) {     // Sanity check
		return FALSE;
	}

	for (uint32_t i = 0; i < count; ++i, r = (const EfiMemoryRange *)(const void *)((const uint8_t *)r + size)) {
		if (r->PhysicalStart + r->NumberOfPages * PAGE_SIZE > *pphys) {
			continue;
		}

		if (!closest || r->PhysicalStart > closest->PhysicalStart) {
			closest = r;
		}
	}

	if (!closest) {
		return FALSE;
	}

	range->type             = closest->Type;
	range->phys_start       = closest->PhysicalStart;
	range->len                      = closest->NumberOfPages * PAGE_SIZE;

	return TRUE;
}
