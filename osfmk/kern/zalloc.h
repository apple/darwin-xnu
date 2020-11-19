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
 *	File:	zalloc.h
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	 1985
 *
 */

#ifdef  KERNEL_PRIVATE

#ifndef _KERN_ZALLOC_H_
#define _KERN_ZALLOC_H_

#include <mach/machine/vm_types.h>
#include <mach_debug/zone_info.h>
#include <kern/kern_types.h>
#include <sys/cdefs.h>

#if XNU_KERNEL_PRIVATE && !defined(ZALLOC_ALLOW_DEPRECATED)
#define __zalloc_deprecated(msg)       __deprecated_msg(msg)
#else
#define __zalloc_deprecated(msg)
#endif

__BEGIN_DECLS

/*!
 * @typedef zone_id_t
 *
 * @abstract
 * The type for a zone ID.
 */
typedef uint16_t zone_id_t;

/**
 * @enum zone_create_flags_t
 *
 * @abstract
 * Set of flags to pass to zone_create().
 *
 * @discussion
 * Some kernel-wide policies affect all possible created zones.
 * Explicit @c ZC_* win over such policies.
 */
__options_decl(zone_create_flags_t, uint64_t, {
	/** The default value to pass to zone_create() */
	ZC_NONE                 = 0x00000000,

	/** Force the created zone to use VA sequestering */
	ZC_SEQUESTER            = 0x00000001,
	/** Force the created zone @b NOT to use VA sequestering */
	ZC_NOSEQUESTER          = 0x00000002,

	/** Enable per-CPU zone caching for this zone */
	ZC_CACHING              = 0x00000010,
	/** Disable per-CPU zone caching for this zone */
	ZC_NOCACHING            = 0x00000020,


	/** Mark zone as a per-cpu zone */
	ZC_PERCPU               = 0x01000000,

	/** Force the created zone to clear every allocation on free */
	ZC_ZFREE_CLEARMEM       = 0x02000000,

	/** Mark zone as non collectable by zone_gc() */
	ZC_NOGC                 = 0x04000000,

	/** Do not encrypt this zone during hibernation */
	ZC_NOENCRYPT            = 0x08000000,

	/** Type requires alignment to be preserved */
	ZC_ALIGNMENT_REQUIRED   = 0x10000000,

	/** Do not track this zone when gzalloc is engaged */
	ZC_NOGZALLOC            = 0x20000000,

	/** Don't asynchronously replenish the zone via callouts */
	ZC_NOCALLOUT            = 0x40000000,

	/** Can be zdestroy()ed, not default unlike zinit() */
	ZC_DESTRUCTIBLE         = 0x80000000,

#ifdef XNU_KERNEL_PRIVATE

	/** This zone will back a kalloc heap */
	ZC_KALLOC_HEAP          = 0x0800000000000000,

	/** This zone can be crammed with foreign pages */
	ZC_ALLOW_FOREIGN        = 0x1000000000000000,

	/** This zone contains bytes / data buffers only */
	ZC_DATA_BUFFERS         = 0x2000000000000000,

	/** Disable kasan quarantine for this zone */
	ZC_KASAN_NOQUARANTINE   = 0x4000000000000000,

	/** Disable kasan redzones for this zone */
	ZC_KASAN_NOREDZONE      = 0x8000000000000000,
#endif
});

/*!
 * @union zone_or_view
 *
 * @abstract
 * A type used for calls that admit both a zone or a zone view.
 *
 * @discussion
 * @c zalloc() and @c zfree() and their variants can act on both
 * zones and zone views.
 */
union zone_or_view {
	struct zone_view *zov_view;
	struct zone      *zov_zone;
#ifdef __cplusplus
	inline zone_or_view(struct zone_view *zv) : zov_view(zv) {
	}
	inline zone_or_view(struct zone *z) : zov_zone(z) {
	}
#endif
};
#ifdef __cplusplus
typedef union zone_or_view zone_or_view_t;
#else
typedef union zone_or_view zone_or_view_t __attribute__((transparent_union));
#endif

/*!
 * @function zone_create
 *
 * @abstract
 * Creates a zone with the specified parameters.
 *
 * @discussion
 * A Zone is a slab allocator that returns objects of a given size very quickly.
 *
 * @param name          the name for the new zone.
 * @param size          the size of the elements returned by this zone.
 * @param flags         a set of @c zone_create_flags_t flags.
 *
 * @returns             the created zone, this call never fails.
 */
extern zone_t   zone_create(
	const char             *name,
	vm_size_t               size,
	zone_create_flags_t     flags);

/*!
 * @function zdestroy
 *
 * @abstract
 * Destroys a zone previously made with zone_create.
 *
 * @discussion
 * Zones must have been made destructible for @c zdestroy() to be allowed,
 * passing @c ZC_DESTRUCTIBLE at @c zone_create() time.
 *
 * @param zone          the zone to destroy.
 */
extern void     zdestroy(
	zone_t          zone);

/*!
 * @function zone_require
 *
 * @abstract
 * Requires for a given pointer to belong to the specified zone.
 *
 * @discussion
 * The function panics if the check fails as it indicates that the kernel
 * internals have been compromised.
 *
 * Note that zone_require() can only work with:
 * - zones not allowing foreign memory
 * - zones in the general submap.
 *
 * @param zone          the zone the address needs to belong to.
 * @param addr          the element address to check.
 */
extern void     zone_require(
	zone_t          zone,
	void           *addr);

/*!
 * @enum zalloc_flags_t
 *
 * @brief
 * Flags that can be passed to @c zalloc_internal or @c zalloc_flags.
 *
 * @discussion
 * It is encouraged that any callsite passing flags uses exactly one of:
 * @c Z_WAITOK, @c Z_NOWAIT or @c Z_NOPAGEWAIT, the default being @c Z_WAITOK
 * if nothing else was specified.
 *
 * If any @c Z_NO*WAIT flag is passed alongside @c Z_WAITOK,
 * then @c Z_WAITOK is ignored.
 *
 * @const Z_WAITOK
 * Means that it's OK for zalloc() to block to wait for memory,
 * when Z_WAITOK is passed, zalloc will never return NULL.
 *
 * @const Z_NOWAIT
 * Passing this flag means that zalloc is not allowed to ever block.
 *
 * @const Z_NOPAGEWAIT
 * Passing this flag means that zalloc is allowed to wait due to lock
 * contention, but will not wait for the VM to wait for pages when
 * under memory pressure.
 *
 * @const Z_ZERO
 * Passing this flags means that the returned memory has been zeroed out.
 *
 * @const Z_NOFAIL
 * Passing this flag means that the caller expects the allocation to always
 * succeed. This will result in a panic if this assumption isn't correct.
 *
 * This flag is incompatible with @c Z_NOWAIT or @c Z_NOPAGEWAIT. It also can't
 * be used on exhaustible zones.
 *
 #if XNU_KERNEL_PRIVATE
 *
 * @const Z_VM_TAG_MASK
 * Represents bits in which a vm_tag_t for the allocation can be passed.
 * (used by kalloc for the zone tagging debugging feature).
 #endif
 */
__options_decl(zalloc_flags_t, uint32_t, {
	// values smaller than 0xff are shared with the M_* flags from BSD MALLOC
	Z_WAITOK        = 0x0000,
	Z_NOWAIT        = 0x0001,
	Z_NOPAGEWAIT    = 0x0002,
	Z_ZERO          = 0x0004,

	Z_NOFAIL        = 0x8000,
#if XNU_KERNEL_PRIVATE
	/** used by kalloc to propagate vm tags for -zt */
	Z_VM_TAG_MASK   = 0xffff0000,

#define Z_VM_TAG_SHIFT        16
#define Z_VM_TAG(tag)         ((zalloc_flags_t)(tag) << Z_VM_TAG_SHIFT)
#endif
});

/*!
 * @function zalloc
 *
 * @abstract
 * Allocates an element from a specified zone.
 *
 * @discussion
 * If the zone isn't exhaustible and is expandable, this call never fails.
 *
 * @param zone_or_view  the zone or zone view to allocate from
 *
 * @returns             NULL or the allocated element
 */
extern void    *zalloc(
	zone_or_view_t  zone_or_view);

/*!
 * @function zalloc_noblock
 *
 * @abstract
 * Allocates an element from a specified zone, but never blocks.
 *
 * @discussion
 * This call is suitable for preemptible code, however allocation
 * isn't allowed from interrupt context.
 *
 * @param zone_or_view  the zone or zone view to allocate from
 *
 * @returns             NULL or the allocated element
 */
extern void    *zalloc_noblock(
	zone_or_view_t  zone_or_view);

/*!
 * @function zalloc_flags()
 *
 * @abstract
 * Allocates an element from a specified zone, with flags.
 *
 * @param zone_or_view  the zone or zone view to allocate from
 * @param flags         a collection of @c zalloc_flags_t.
 *
 * @returns             NULL or the allocated element
 */
extern void    *zalloc_flags(
	zone_or_view_t  zone_or_view,
	zalloc_flags_t  flags);

/*!
 * @function zfree
 *
 * @abstract
 * Frees an element allocated with @c zalloc*.
 *
 * @discussion
 * If the element being freed doesn't belong to the specified zone,
 * then this call will panic.
 *
 * @param zone_or_view  the zone or zone view to free the element to.
 * @param elem          the element to free
 */
extern void     zfree(
	zone_or_view_t  zone_or_view,
	void            *elem);

/* deprecated KPIS */

__zalloc_deprecated("use zone_create()")
extern zone_t   zinit(
	vm_size_t       size,           /* the size of an element */
	vm_size_t       maxmem,         /* maximum memory to use */
	vm_size_t       alloc,          /* allocation size */
	const char      *name);         /* a name for the zone */

#ifdef XNU_KERNEL_PRIVATE
#pragma mark - XNU only interfaces
#include <kern/startup.h>
#include <kern/cpu_number.h>

#pragma GCC visibility push(hidden)

#pragma mark XNU only: zalloc (extended)

#define ZALIGN_NONE             (sizeof(uint8_t)  - 1)
#define ZALIGN_16               (sizeof(uint16_t) - 1)
#define ZALIGN_32               (sizeof(uint32_t) - 1)
#define ZALIGN_PTR              (sizeof(void *)   - 1)
#define ZALIGN_64               (sizeof(uint64_t) - 1)
#define ZALIGN(t)               (_Alignof(t)      - 1)


/*!
 * @function zalloc_permanent()
 *
 * @abstract
 * Allocates a permanent element from the permanent zone
 *
 * @discussion
 * Memory returned by this function is always 0-initialized.
 * Note that the size of this allocation can not be determined
 * by zone_element_size so it should not be used for copyio.
 *
 * @param size          the element size (must be smaller than PAGE_SIZE)
 * @param align_mask    the required alignment for this allocation
 *
 * @returns             the allocated element
 */
extern void    *zalloc_permanent(
	vm_size_t       size,
	vm_offset_t     align_mask);

/*!
 * @function zalloc_permanent_type()
 *
 * @abstract
 * Allocates a permanent element of a given type with its natural alignment.
 *
 * @discussion
 * Memory returned by this function is always 0-initialized.
 *
 * @param type_t        the element type
 *
 * @returns             the allocated element
 */
#define zalloc_permanent_type(type_t) \
	((type_t *)zalloc_permanent(sizeof(type_t), ZALIGN(type_t)))

#pragma mark XNU only: per-cpu allocations

/*!
 * @macro __zpercpu
 *
 * @abstract
 * Annotation that helps denoting a per-cpu pointer that requires usage of
 * @c zpercpu_*() for access.
 */
#define __zpercpu

/*!
 * @macro zpercpu_get_cpu()
 *
 * @abstract
 * Get a pointer to a specific CPU slot of a given per-cpu variable.
 *
 * @param ptr           the per-cpu pointer (returned by @c zalloc_percpu*()).
 * @param cpu           the specified CPU number as returned by @c cpu_number()
 *
 * @returns             the per-CPU slot for @c ptr for the specified CPU.
 */
#define zpercpu_get_cpu(ptr, cpu) \
	__zpcpu_cast(ptr, __zpcpu_demangle(ptr) + ptoa((unsigned)cpu))

/*!
 * @macro zpercpu_get()
 *
 * @abstract
 * Get a pointer to the current CPU slot of a given per-cpu variable.
 *
 * @param ptr           the per-cpu pointer (returned by @c zalloc_percpu*()).
 *
 * @returns             the per-CPU slot for @c ptr for the current CPU.
 */
#define zpercpu_get(ptr) \
	zpercpu_get_cpu(ptr, cpu_number())

/*!
 * @macro zpercpu_foreach()
 *
 * @abstract
 * Enumerate all per-CPU slots by address.
 *
 * @param it            the name for the iterator
 * @param ptr           the per-cpu pointer (returned by @c zalloc_percpu*()).
 */
#define zpercpu_foreach(it, ptr) \
	for (typeof(ptr) it = zpercpu_get_cpu(ptr, 0), \
	    __end_##it = zpercpu_get_cpu(ptr, zpercpu_count()); \
	    it < __end_##it; it = __zpcpu_next(it))

/*!
 * @macro zpercpu_foreach_cpu()
 *
 * @abstract
 * Enumerate all per-CPU slots by CPU slot number.
 *
 * @param cpu           the name for cpu number iterator.
 */
#define zpercpu_foreach_cpu(cpu) \
	for (unsigned cpu = 0; cpu < zpercpu_count(); cpu++)

/*!
 * @function zalloc_percpu()
 *
 * @abstract
 * Allocates an element from a per-cpu zone.
 *
 * @discussion
 * The returned pointer cannot be used directly and must be manipulated
 * through the @c zpercpu_get*() interfaces.
 *
 * @param zone_or_view  the zone or zone view to allocate from
 * @param flags         a collection of @c zalloc_flags_t.
 *
 * @returns             NULL or the allocated element
 */
extern void    *zalloc_percpu(
	zone_or_view_t  zone_or_view,
	zalloc_flags_t  flags);

/*!
 * @function zfree_percpu()
 *
 * @abstract
 * Frees an element previously allocated with @c zalloc_percpu().
 *
 * @param zone_or_view  the zone or zone view to free the element to.
 * @param addr          the address to free
 */
extern void     zfree_percpu(
	zone_or_view_t  zone_or_view,
	void           *addr);

/*!
 * @function zalloc_percpu_permanent()
 *
 * @abstract
 * Allocates a permanent percpu-element from the permanent percpu zone.
 *
 * @discussion
 * Memory returned by this function is always 0-initialized.
 *
 * @param size          the element size (must be smaller than PAGE_SIZE)
 * @param align_mask    the required alignment for this allocation
 *
 * @returns             the allocated element
 */
extern void    *zalloc_percpu_permanent(
	vm_size_t       size,
	vm_offset_t     align_mask);

/*!
 * @function zalloc_percpu_permanent_type()
 *
 * @abstract
 * Allocates a permanent percpu-element from the permanent percpu zone of a given
 * type with its natural alignment.
 *
 * @discussion
 * Memory returned by this function is always 0-initialized.
 *
 * @param type_t        the element type
 *
 * @returns             the allocated element
 */
#define zalloc_percpu_permanent_type(type_t) \
	((type_t *)zalloc_percpu_permanent(sizeof(type_t), ZALIGN(type_t)))

#pragma mark XNU only: zone views

/*!
 * @enum zone_kheap_id_t
 *
 * @brief
 * Enumerate a particular kalloc heap.
 *
 * @discussion
 * More documentation about heaps is available in @c <kern/kalloc.h>.
 *
 * @const KHEAP_ID_NONE
 * This value denotes regular zones, not used by kalloc.
 *
 * @const KHEAP_ID_DEFAULT
 * Indicates zones part of the KHEAP_DEFAULT heap.
 *
 * @const KHEAP_ID_DATA_BUFFERS
 * Indicates zones part of the KHEAP_DATA_BUFFERS heap.
 *
 * @const KHEAP_ID_KEXT
 * Indicates zones part of the KHEAP_KEXT heap.
 */
__enum_decl(zone_kheap_id_t, uint32_t, {
	KHEAP_ID_NONE,
	KHEAP_ID_DEFAULT,
	KHEAP_ID_DATA_BUFFERS,
	KHEAP_ID_KEXT,

#define KHEAP_ID_COUNT (KHEAP_ID_KEXT + 1)
});

/*!
 * @typedef zone_stats_t
 *
 * @abstract
 * The opaque type for per-cpu zone stats that are accumulated per zone
 * or per zone-view.
 */
typedef struct zone_stats *__zpercpu zone_stats_t;

/*!
 * @typedef zone_view_t
 *
 * @abstract
 * A view on a zone for accounting purposes.
 *
 * @discussion
 * A zone view uses the zone it references for the allocations backing store,
 * but does the allocation accounting at the view level.
 *
 * These accounting are surfaced by @b zprint(1) and similar tools,
 * which allow for cheap but finer grained understanding of allocations
 * without any fragmentation cost.
 *
 * Zone views are protected by the kernel lockdown and can't be initialized
 * dynamically. They must be created using @c ZONE_VIEW_DEFINE().
 */
typedef struct zone_view *zone_view_t;
struct zone_view {
	zone_t          zv_zone;
	zone_stats_t    zv_stats;
	const char     *zv_name;
	zone_view_t     zv_next;
};

/*!
 * @macro ZONE_VIEW_DECLARE
 *
 * @abstract
 * (optionally) declares a zone view (in a header).
 *
 * @param var           the name for the zone view.
 */
#define ZONE_VIEW_DECLARE(var) \
	extern struct zone_view var[1]

/*!
 * @macro ZONE_VIEW_DEFINE
 *
 * @abstract
 * Defines a given zone view and what it points to.
 *
 * @discussion
 * Zone views can either share a pre-existing zone,
 * or perform a lookup into a kalloc heap for the zone
 * backing the bucket of the proper size.
 *
 * Zone views are initialized during the @c STARTUP_SUB_ZALLOC phase,
 * as the last rank. If views on zones are created, these must have been
 * created before this stage.
 *
 * @param var           the name for the zone view.
 * @param name          a string describing the zone view.
 * @param heap_or_zone  a @c KHEAP_ID_* constant or a pointer to a zone.
 * @param size          the element size to be allocated from this view.
 */
#define ZONE_VIEW_DEFINE(var, name, heap_or_zone, size) \
	SECURITY_READ_ONLY_LATE(struct zone_view) var[1] = { { \
	    .zv_name = name, \
	} }; \
	static __startup_data struct zone_view_startup_spec \
	__startup_zone_view_spec_ ## var = { var, { heap_or_zone }, size }; \
	STARTUP_ARG(ZALLOC, STARTUP_RANK_LAST, zone_view_startup_init, \
	    &__startup_zone_view_spec_ ## var)


#pragma mark XNU only: zone creation (extended)

/*!
 * @enum zone_reserved_id_t
 *
 * @abstract
 * Well known pre-registered zones, allowing use of zone_id_require()
 *
 * @discussion
 * @c ZONE_ID__* aren't real zone IDs.
 *
 * @c ZONE_ID__ZERO reserves zone index 0 so that it can't be used, as 0 is too
 * easy a value to produce (by malice or accident).
 *
 * @c ZONE_ID__FIRST_DYNAMIC is the first dynamic zone ID that can be used by
 * @c zone_create().
 */
__enum_decl(zone_reserved_id_t, zone_id_t, {
	ZONE_ID__ZERO,

	ZONE_ID_PERMANENT,
	ZONE_ID_PERCPU_PERMANENT,

	ZONE_ID_IPC_PORT,
	ZONE_ID_IPC_PORT_SET,
	ZONE_ID_IPC_VOUCHERS,
	ZONE_ID_TASK,
	ZONE_ID_PROC,
	ZONE_ID_VM_MAP_COPY,
	ZONE_ID_PMAP,

	ZONE_ID__FIRST_DYNAMIC,
});

/*!
 * @const ZONE_ID_ANY
 * The value to pass to @c zone_create_ext() to allocate a non pre-registered
 * Zone ID.
 */
#define ZONE_ID_ANY ((zone_id_t)-1)

/**!
 * @function zone_name
 *
 * @param zone          the specified zone
 * @returns             the name of the specified zone.
 */
const char     *zone_name(
	zone_t                  zone);

/**!
 * @function zone_heap_name
 *
 * @param zone          the specified zone
 * @returns             the name of the heap this zone is part of, or "".
 */
const char     *zone_heap_name(
	zone_t                  zone);

/**!
 * @function zone_submap
 *
 * @param zone          the specified zone
 * @returns             the zone (sub)map this zone allocates from.
 */
extern vm_map_t zone_submap(
	zone_t                  zone);

/*!
 * @function zone_create_ext
 *
 * @abstract
 * Creates a zone with the specified parameters.
 *
 * @discussion
 * This is an extended version of @c zone_create().
 *
 * @param name          the name for the new zone.
 * @param size          the size of the elements returned by this zone.
 * @param flags         a set of @c zone_create_flags_t flags.
 * @param desired_zid   a @c zone_reserved_id_t value or @c ZONE_ID_ANY.
 *
 * @param extra_setup   a block that can perform non trivial initialization
 *                      on the zone before it is marked valid.
 *                      This block can call advanced setups like:
 *                      - zone_set_submap_idx()
 *                      - zone_set_exhaustible()
 *                      - zone_set_noexpand()
 *
 * @returns             the created zone, this call never fails.
 */
extern zone_t   zone_create_ext(
	const char             *name,
	vm_size_t               size,
	zone_create_flags_t     flags,
	zone_id_t               desired_zid,
	void                  (^extra_setup)(zone_t));

/*!
 * @macro ZONE_DECLARE
 *
 * @abstract
 * Declares a zone variable to automatically initialize with the specified
 * parameters.
 *
 * @param var           the name of the variable to declare.
 * @param name          the name for the zone
 * @param size          the size of the elements returned by this zone.
 * @param flags         a set of @c zone_create_flags_t flags.
 */
#define ZONE_DECLARE(var, name, size, flags) \
	SECURITY_READ_ONLY_LATE(zone_t) var; \
	static_assert(((flags) & ZC_DESTRUCTIBLE) == 0); \
	static __startup_data struct zone_create_startup_spec \
	__startup_zone_spec_ ## var = { &var, name, size, flags, \
	    ZONE_ID_ANY, NULL }; \
	STARTUP_ARG(ZALLOC, STARTUP_RANK_MIDDLE, zone_create_startup, \
	    &__startup_zone_spec_ ## var)

/*!
 * @macro ZONE_INIT
 *
 * @abstract
 * Initializes a given zone automatically during startup with the specified
 * parameters.
 *
 * @param var           the name of the variable to initialize.
 * @param name          the name for the zone
 * @param size          the size of the elements returned by this zone.
 * @param flags         a set of @c zone_create_flags_t flags.
 * @param desired_zid   a @c zone_reserved_id_t value or @c ZONE_ID_ANY.
 * @param extra_setup   a block that can perform non trivial initialization
 *                      (@see @c zone_create_ext()).
 */
#define ZONE_INIT(var, name, size, flags, desired_zid, extra_setup) \
	__ZONE_INIT(__LINE__, var, name, size, flags, desired_zid, extra_setup)

/*!
 * @function zone_id_require
 *
 * @abstract
 * Requires for a given pointer to belong to the specified zone, by ID and size.
 *
 * @discussion
 * The function panics if the check fails as it indicates that the kernel
 * internals have been compromised.
 *
 * This is a variant of @c zone_require() which:
 * - isn't sensitive to @c zone_t::elem_size being compromised,
 * - is slightly faster as it saves one load and a multiplication.
 *
 * @param zone_id       the zone ID the address needs to belong to.
 * @param elem_size     the size of elements for this zone.
 * @param addr          the element address to check.
 */
extern void     zone_id_require(
	zone_id_t               zone_id,
	vm_size_t               elem_size,
	void                   *addr);

/*
 * Zone submap indices
 *
 * Z_SUBMAP_IDX_VA_RESTRICTED_MAP (LP64)
 * used to restrict VM allocations lower in the kernel VA space,
 * for pointer packing
 *
 * Z_SUBMAP_IDX_GENERAL_MAP
 * used for unrestricted allocations
 *
 * Z_SUBMAP_IDX_BAG_OF_BYTES_MAP
 * used to sequester bags of bytes from all other allocations and allow VA reuse
 * within the map
 */
#if !defined(__LP64__)
#define Z_SUBMAP_IDX_GENERAL_MAP        0
#define Z_SUBMAP_IDX_BAG_OF_BYTES_MAP   1
#define Z_SUBMAP_IDX_COUNT              2
#else
#define Z_SUBMAP_IDX_VA_RESTRICTED_MAP  0
#define Z_SUBMAP_IDX_GENERAL_MAP        1
#define Z_SUBMAP_IDX_BAG_OF_BYTES_MAP   2
#define Z_SUBMAP_IDX_COUNT              3
#endif

/* Change zone sub-map, to be called from the zone_create_ext() setup hook */
extern void     zone_set_submap_idx(
	zone_t          zone,
	unsigned int    submap_idx);

/* Make zone as non expandable, to be called from the zone_create_ext() setup hook */
extern void     zone_set_noexpand(
	zone_t          zone,
	vm_size_t       maxsize);

/* Make zone exhaustible, to be called from the zone_create_ext() setup hook */
extern void     zone_set_exhaustible(
	zone_t          zone,
	vm_size_t       maxsize);

/* Initially fill zone with specified number of elements */
extern int      zfill(
	zone_t          zone,
	int             nelem);

/* Fill zone with memory */
extern void     zcram(
	zone_t          zone,
	vm_offset_t     newmem,
	vm_size_t       size);

#pragma mark XNU only: misc & implementation details

/*
 * This macro sets "elem" to NULL on free.
 *
 * Note: all values passed to zfree() might be in the element to be freed,
 *       temporaries must be taken, and the resetting to be done prior to free.
 */
#define zfree(zone, elem) ({ \
	_Static_assert(sizeof(elem) == sizeof(void *), "elem isn't pointer sized"); \
	__auto_type __zfree_zone = (zone); \
	__auto_type __zfree_eptr = &(elem); \
	__auto_type __zfree_elem = *__zfree_eptr; \
	*__zfree_eptr = (__typeof__(__zfree_elem))NULL; \
	(zfree)(__zfree_zone, (void *)__zfree_elem); \
})

struct zone_create_startup_spec {
	zone_t                 *z_var;
	const char             *z_name;
	vm_size_t               z_size;
	zone_create_flags_t     z_flags;
	zone_id_t               z_zid;
	void                  (^z_setup)(zone_t);
};

extern void     zone_create_startup(
	struct zone_create_startup_spec *spec);

#define __ZONE_INIT1(ns, var, name, size, flags, zid, setup) \
	static __startup_data struct zone_create_startup_spec \
	__startup_zone_spec_ ## ns = { var, name, size, flags, zid, setup }; \
	STARTUP_ARG(ZALLOC, STARTUP_RANK_MIDDLE, zone_create_startup, \
	    &__startup_zone_spec_ ## ns)

#define __ZONE_INIT(ns, var, name, size, flags, zid, setup) \
	__ZONE_INIT1(ns, var, name, size, flags, zid, setup) \

struct zone_view_startup_spec {
	zone_view_t         zv_view;
	union {
		zone_kheap_id_t zv_heapid;
		zone_t          zv_zone;
	};
	vm_size_t           zv_size;
};

extern void zone_view_startup_init(
	struct zone_view_startup_spec *spec);


#if DEBUG || DEVELOPMENT
#  if __LP64__
#    define ZPCPU_MANGLE_BIT    (1ul << 63)
#  else /* !__LP64__ */
#    define ZPCPU_MANGLE_BIT    (1ul << 31)
#  endif /* !__LP64__ */
#else /* !(DEBUG || DEVELOPMENT) */
#  define ZPCPU_MANGLE_BIT      0ul
#endif /* !(DEBUG || DEVELOPMENT) */

#define __zpcpu_mangle(ptr)     (__zpcpu_addr(ptr) & ~ZPCPU_MANGLE_BIT)
#define __zpcpu_demangle(ptr)   (__zpcpu_addr(ptr) | ZPCPU_MANGLE_BIT)
#define __zpcpu_addr(e)         ((vm_address_t)(e))
#define __zpcpu_cast(ptr, e)    ((typeof(ptr))(e))
#define __zpcpu_next(ptr)       __zpcpu_cast(ptr, __zpcpu_addr(ptr) + PAGE_SIZE)

extern unsigned zpercpu_count(void) __pure2;


/* These functions used for leak detection both in zalloc.c and mbuf.c */
extern uintptr_t hash_mix(uintptr_t);
extern uint32_t hashbacktrace(uintptr_t *, uint32_t, uint32_t);
extern uint32_t hashaddr(uintptr_t, uint32_t);

#if CONFIG_ZLEAKS
/* support for the kern.zleak.* sysctls */

extern kern_return_t zleak_activate(void);
extern vm_size_t zleak_max_zonemap_size;
extern vm_size_t zleak_global_tracking_threshold;
extern vm_size_t zleak_per_zone_tracking_threshold;

extern int get_zleak_state(void);

#endif /* CONFIG_ZLEAKS */
#if DEBUG || DEVELOPMENT

extern boolean_t run_zone_test(void);
extern void zone_gc_replenish_test(void);
extern void zone_alloc_replenish_test(void);

#endif /* DEBUG || DEVELOPMENT */

#pragma GCC visibility pop
#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif  /* _KERN_ZALLOC_H_ */

#endif  /* KERNEL_PRIVATE */
