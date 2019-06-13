/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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

#ifndef _OS_REFCNT_H_
#define _OS_REFCNT_H_

/*
 * os_refcnt reference counting API
 *
 * Two flavors are provided: atomic and locked. Atomic internally uses C11 atomic
 * operations and requires no external synchronization, whereas the locked flavor
 * assumes the refcnt object is locked by the caller. It is NOT safe to
 * mix-and-match locked and atomic calls.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <os/base.h>

struct os_refcnt;
struct os_refgrp;
typedef struct os_refcnt os_refcnt_t;

/* type of the internal counter */
typedef uint32_t os_ref_count_t;

#if DEVELOPMENT || DEBUG
# define OS_REFCNT_DEBUG 1
#else
# define OS_REFCNT_DEBUG 0
#endif

/*
 * Debugging is keyed off ref_group, so leave that field for kexts so that the
 * combination of dev/debug kernel and release kext works.
 */
#if XNU_KERNEL_PRIVATE
# define OS_REFCNT_HAS_GROUP OS_REFCNT_DEBUG
#else
# define OS_REFCNT_HAS_GROUP 1
#endif

struct os_refcnt {
	_Atomic os_ref_count_t ref_count;
#if OS_REFCNT_HAS_GROUP
	struct os_refgrp *ref_group;
#endif
};

#if OS_REFCNT_DEBUG
struct os_refgrp {
	const char *const grp_name;
	_Atomic os_ref_count_t grp_children; /* number of refcount objects in group */
	_Atomic os_ref_count_t grp_count;    /* current reference count of group */
	_Atomic uint64_t grp_retain_total;
	_Atomic uint64_t grp_release_total;
	struct os_refgrp *grp_parent;
	void *grp_log;                       /* refcount logging context */
};
#endif

#if __has_attribute(diagnose_if)
# define os_error_if(cond, msg) __attribute__((diagnose_if((cond), (msg), "error")))
#else
# define os_error_if(...)
#endif

__BEGIN_DECLS

/*
 * os_ref_init: initialize an os_refcnt with a count of 1
 * os_ref_init_count: initialize an os_refcnt with a specific count >= 1
 */
#define os_ref_init(rc, grp) os_ref_init_count((rc), (grp), 1)
void os_ref_init_count(struct os_refcnt *, struct os_refgrp *, os_ref_count_t count)
	os_error_if(count == 0, "Reference count must be non-zero initialized");

#if OS_REFCNT_DEBUG
# define os_refgrp_decl(qual, var, name, parent) \
	qual struct os_refgrp __attribute__((section("__DATA,__refgrps"))) var = { \
		.grp_name =          (name), \
		.grp_children =      ATOMIC_VAR_INIT(0), \
		.grp_count =         ATOMIC_VAR_INIT(0), \
		.grp_retain_total =  ATOMIC_VAR_INIT(0), \
		.grp_release_total = ATOMIC_VAR_INIT(0), \
		.grp_parent =        (parent), \
		.grp_log =           NULL, \
	}

/* Create a default group based on the init() callsite if no explicit group
 * is provided. */
# define os_ref_init_count(rc, grp, count) ({ \
		os_refgrp_decl(static, __grp, __func__, NULL); \
		(os_ref_init_count)((rc), (grp) ? (grp) : &__grp, (count)); \
	})
#else
# define os_refgrp_decl(...)
# define os_ref_init_count(rc, grp, count) (os_ref_init_count)((rc), NULL, (count))
#endif /* OS_REFCNT_DEBUG */

/*
 * os_ref_retain: acquire a reference (increment reference count by 1) atomically.
 *
 * os_ref_release: release a reference (decrement reference count) atomically and
 *		return the new count. Memory is synchronized such that the dealloc block
 *		(i.e. code handling the final release() == 0 call) sees up-to-date memory
 *		with respect to all prior release()s on the same refcnt object. This
 *		memory ordering is sufficient for most use cases.
 *
 * os_ref_release_relaxed: same as release() but with weaker relaxed memory ordering.
 *		This can be used when the dealloc block is already synchronized with other
 *		accesses to the object (for example, with a lock).
 *
 * os_ref_release_live: release a reference that is guaranteed not to be the last one.
 */
void os_ref_retain(struct os_refcnt *);

os_ref_count_t os_ref_release_explicit(struct os_refcnt *rc,
		memory_order release_order, memory_order dealloc_order) OS_WARN_RESULT;

static inline os_ref_count_t OS_WARN_RESULT
os_ref_release(struct os_refcnt *rc)
{
	return os_ref_release_explicit(rc, memory_order_release, memory_order_acquire);
}

static inline os_ref_count_t OS_WARN_RESULT
os_ref_release_relaxed(struct os_refcnt *rc)
{
	return os_ref_release_explicit(rc, memory_order_relaxed, memory_order_relaxed);
}

static inline void
os_ref_release_live(struct os_refcnt *rc)
{
	if (__improbable(os_ref_release_explicit(rc,
			memory_order_release, memory_order_relaxed) == 0)) {
		panic("os_refcnt: unexpected release of final reference (rc=%p)\n", rc);
		__builtin_unreachable();
	}
}


/*
 * os_ref_retain_try: a variant of atomic retain that fails for objects with a
 *		zero reference count. The caller must therefore ensure that the object
 *		remains alive for any possible retain_try() caller, usually by using a
 *		lock protecting both the retain and dealloc paths. This variant is useful
 *		for objects stored in a collection, because no lock is required on the
 *		release() side until the object is deallocated.
 */
bool os_ref_retain_try(struct os_refcnt *) OS_WARN_RESULT;


/*
 * os_ref_retain_locked: acquire a reference on an object protected by a held
 *		lock. The caller must ensure mutual exclusivity of retain_locked() and
 *		release_locked() calls on the same object.
 *
 * os_ref_release_locked: release a reference on an object protected by a held
 *		lock.
 */
void os_ref_retain_locked(struct os_refcnt *);
os_ref_count_t os_ref_release_locked(struct os_refcnt *) OS_WARN_RESULT;


/*
 * os_ref_get_count: return the current reference count. This is unsafe for
 *		synchronization.
 */
static inline os_ref_count_t
os_ref_get_count(struct os_refcnt *rc)
{
	return atomic_load_explicit(&rc->ref_count, memory_order_relaxed);
}

__END_DECLS

#endif
