/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
/* Copyright (c) 1995, 1997 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1987, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_malloc.c	8.4 (Berkeley) 5/20/95
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <kern/zalloc.h>
#include <kern/kalloc.h>

#include <sys/malloc.h>
#include <sys/sysctl.h>

#include <libkern/libkern.h>

ZONE_VIEW_DEFINE(ZV_NAMEI, "vfs.namei", KHEAP_ID_DATA_BUFFERS, MAXPATHLEN);

static void *
__MALLOC_ext(
	size_t          size,
	int             type,
	int             flags,
	vm_allocation_site_t *site,
	kalloc_heap_t   heap)
{
	void    *addr = NULL;

	if (type >= M_LAST) {
		panic("_malloc TYPE");
	}

	if (size == 0) {
		return NULL;
	}

	static_assert(sizeof(vm_size_t) == sizeof(size_t));
	static_assert(M_WAITOK == Z_WAITOK);
	static_assert(M_NOWAIT == Z_NOWAIT);
	static_assert(M_ZERO == Z_ZERO);

	addr = kalloc_ext(heap, size,
	    flags & (M_WAITOK | M_NOWAIT | M_ZERO), site).addr;
	if (__probable(addr)) {
		return addr;
	}

	if (flags & (M_NOWAIT | M_NULL)) {
		return NULL;
	}

	/*
	 * We get here when the caller told us to block waiting for memory, but
	 * kalloc said there's no memory left to get.  Generally, this means there's a
	 * leak or the caller asked for an impossibly large amount of memory. If the caller
	 * is expecting a NULL return code then it should explicitly set the flag M_NULL.
	 * If the caller isn't expecting a NULL return code, we just panic. This is less
	 * than ideal, but returning NULL when the caller isn't expecting it doesn't help
	 * since the majority of callers don't check the return value and will just
	 * dereference the pointer and trap anyway.  We may as well get a more
	 * descriptive message out while we can.
	 */
	panic("_MALLOC: kalloc returned NULL (potential leak), size %llu", (uint64_t) size);
}

void *
__MALLOC(size_t size, int type, int flags, vm_allocation_site_t *site)
{
	return __MALLOC_ext(size, type, flags, site, KHEAP_DEFAULT);
}

void *
__REALLOC(
	void            *addr,
	size_t          size,
	int             type __unused,
	int             flags,
	vm_allocation_site_t *site)
{
	addr = kheap_realloc_addr(KHEAP_DEFAULT, addr, size,
	    flags & (M_WAITOK | M_NOWAIT | M_ZERO), site).addr;

	if (__probable(addr)) {
		return addr;
	}

	if (flags & (M_NOWAIT | M_NULL)) {
		return NULL;
	}

	panic("_REALLOC: kalloc returned NULL (potential leak), size %llu", (uint64_t) size);
}

void *
_MALLOC_external(size_t size, int type, int flags);
void *
_MALLOC_external(size_t size, int type, int flags)
{
	static vm_allocation_site_t site = {
		.tag = VM_KERN_MEMORY_KALLOC,
		.flags = VM_TAG_BT,
	};
	return __MALLOC_ext(size, type, flags, &site, KHEAP_KEXT);
}

void
_FREE_external(void *addr, int type);
void
_FREE_external(void *addr, int type __unused)
{
	/*
	 * hashinit and other functions allocate on behalf of kexts and do not have
	 * a matching hashdestroy, so we sadly have to allow this for now.
	 */
	kheap_free_addr(KHEAP_ANY, addr);
}

void
_FREE_ZONE_external(void *elem, size_t size, int type);
void
_FREE_ZONE_external(void *elem, size_t size, int type __unused)
{
	(kheap_free)(KHEAP_KEXT, elem, size);
}

#if DEBUG || DEVELOPMENT

extern unsigned int zone_map_jetsam_limit;

static int
sysctl_zone_map_jetsam_limit SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int oldval = 0, val = 0, error = 0;

	oldval = zone_map_jetsam_limit;
	error = sysctl_io_number(req, oldval, sizeof(int), &val, NULL);
	if (error || !req->newptr) {
		return error;
	}

	if (val <= 0 || val > 100) {
		printf("sysctl_zone_map_jetsam_limit: new jetsam limit value is invalid.\n");
		return EINVAL;
	}

	zone_map_jetsam_limit = val;
	return 0;
}

SYSCTL_PROC(_kern, OID_AUTO, zone_map_jetsam_limit, CTLTYPE_INT | CTLFLAG_RW, 0, 0,
    sysctl_zone_map_jetsam_limit, "I", "Zone map jetsam limit");


extern void get_zone_map_size(uint64_t *current_size, uint64_t *capacity);

static int
sysctl_zone_map_size_and_capacity SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint64_t zstats[2];
	get_zone_map_size(&zstats[0], &zstats[1]);

	return SYSCTL_OUT(req, &zstats, sizeof(zstats));
}

SYSCTL_PROC(_kern, OID_AUTO, zone_map_size_and_capacity,
    CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, &sysctl_zone_map_size_and_capacity, "Q", "Current size and capacity of the zone map");


extern boolean_t run_zone_test(void);

static int
sysctl_run_zone_test SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	/* require setting this sysctl to prevent sysctl -a from running this */
	if (!req->newptr) {
		return 0;
	}

	int ret_val = run_zone_test();
	return SYSCTL_OUT(req, &ret_val, sizeof(ret_val));
}

SYSCTL_PROC(_kern, OID_AUTO, run_zone_test,
    CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, &sysctl_run_zone_test, "I", "Test zone allocator KPI");

#endif /* DEBUG || DEVELOPMENT */

#if CONFIG_ZLEAKS

SYSCTL_DECL(_kern_zleak);
SYSCTL_NODE(_kern, OID_AUTO, zleak, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "zleak");

/*
 * kern.zleak.active
 *
 * Show the status of the zleak subsystem (0 = enabled, 1 = active,
 * and -1 = failed), and if enabled, allow it to be activated immediately.
 */
static int
sysctl_zleak_active SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int oldval, val, error;

	val = oldval = get_zleak_state();
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr) {
		return error;
	}
	/*
	 * Can only be activated if it's off (and not failed.)
	 * Cannot be deactivated once it's on.
	 */
	if (val == 1 && oldval == 0) {
		kern_return_t kr = zleak_activate();

		if (KERN_SUCCESS != kr) {
			printf("zleak_active: failed to activate "
			    "live zone leak debugging (%d).\n", kr);
		}
	}
	if (val == 0 && oldval == 1) {
		printf("zleak_active: active, cannot be disabled.\n");
		return EINVAL;
	}
	return 0;
}

SYSCTL_PROC(_kern_zleak, OID_AUTO, active,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_zleak_active, "I", "zleak activity");

/*
 * kern.zleak.max_zonemap_size
 *
 * Read the value of the maximum zonemap size in bytes; useful
 * as the maximum size that zleak.global_threshold and
 * zleak.zone_threshold should be set to.
 */
static int
sysctl_zleak_max_zonemap_size SYSCTL_HANDLER_ARGS
{
	uint64_t zmap_max_size = *(vm_size_t *)arg1;

	return sysctl_handle_quad(oidp, &zmap_max_size, arg2, req);
}

SYSCTL_PROC(_kern_zleak, OID_AUTO, max_zonemap_size,
    CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_LOCKED,
    &zleak_max_zonemap_size, 0,
    sysctl_zleak_max_zonemap_size, "Q", "zleak max zonemap size");


static int
sysctl_zleak_threshold SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int error;
	uint64_t value = *(vm_size_t *)arg1;

	error = sysctl_io_number(req, value, sizeof(value), &value, NULL);

	if (error || !req->newptr) {
		return error;
	}

	if (value > (uint64_t)zleak_max_zonemap_size) {
		return ERANGE;
	}

	*(vm_size_t *)arg1 = value;
	return 0;
}

/*
 * kern.zleak.global_threshold
 *
 * Set the global zleak threshold size (in bytes).  If the zone map
 * grows larger than this value, zleaks are automatically activated.
 *
 * The default value is set in zleak_init().
 */
SYSCTL_PROC(_kern_zleak, OID_AUTO, global_threshold,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    &zleak_global_tracking_threshold, 0,
    sysctl_zleak_threshold, "Q", "zleak global threshold");

/*
 * kern.zleak.zone_threshold
 *
 * Set the per-zone threshold size (in bytes) above which any
 * zone will automatically start zleak tracking.
 *
 * The default value is set in zleak_init().
 *
 * Setting this variable will have no effect until zleak tracking is
 * activated (See above.)
 */
SYSCTL_PROC(_kern_zleak, OID_AUTO, zone_threshold,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    &zleak_per_zone_tracking_threshold, 0,
    sysctl_zleak_threshold, "Q", "zleak per-zone threshold");

#endif  /* CONFIG_ZLEAKS */

extern uint64_t get_zones_collectable_bytes(void);

static int
sysctl_zones_collectable_bytes SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint64_t zones_free_mem = get_zones_collectable_bytes();

	return SYSCTL_OUT(req, &zones_free_mem, sizeof(zones_free_mem));
}

SYSCTL_PROC(_kern, OID_AUTO, zones_collectable_bytes,
    CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, &sysctl_zones_collectable_bytes, "Q", "Collectable memory in zones");


#if DEBUG || DEVELOPMENT

static int
sysctl_zone_gc_replenish_test SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	/* require setting this sysctl to prevent sysctl -a from running this */
	if (!req->newptr) {
		return 0;
	}

	int ret_val = 0;
	zone_gc_replenish_test();
	return SYSCTL_OUT(req, &ret_val, sizeof(ret_val));
}

static int
sysctl_zone_alloc_replenish_test SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	/* require setting this sysctl to prevent sysctl -a from running this */
	if (!req->newptr) {
		return 0;
	}

	int ret_val = 0;
	zone_alloc_replenish_test();
	return SYSCTL_OUT(req, &ret_val, sizeof(ret_val));
}

SYSCTL_PROC(_kern, OID_AUTO, zone_gc_replenish_test,
    CTLTYPE_INT | CTLFLAG_MASKED | CTLFLAG_LOCKED | CTLFLAG_WR,
    0, 0, &sysctl_zone_gc_replenish_test, "I", "Test zone GC replenish");
SYSCTL_PROC(_kern, OID_AUTO, zone_alloc_replenish_test,
    CTLTYPE_INT | CTLFLAG_MASKED | CTLFLAG_LOCKED | CTLFLAG_WR,
    0, 0, &sysctl_zone_alloc_replenish_test, "I", "Test zone alloc replenish");

#endif /* DEBUG || DEVELOPMENT */
