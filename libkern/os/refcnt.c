#if KERNEL
#include <kern/assert.h>
#include <kern/debug.h>
#include <pexpert/pexpert.h>
#include <kern/btlog.h>
#include <kern/backtrace.h>
#include <libkern/libkern.h>
#endif
#include <os/atomic_private.h>

#include "refcnt.h"

#define OS_REFCNT_MAX_COUNT     ((os_ref_count_t)0x0FFFFFFFUL)

#if OS_REFCNT_DEBUG
extern struct os_refgrp global_ref_group;
os_refgrp_decl(, global_ref_group, "all", NULL);

extern bool ref_debug_enable;
bool ref_debug_enable = false;
static const size_t ref_log_nrecords = 1000000;

#define REFLOG_BTDEPTH   10

__enum_closed_decl(reflog_op_t, uint8_t, {
	REFLOG_RETAIN  = 1,
	REFLOG_RELEASE = 2
});

#define __debug_only
#else
# define __debug_only __unused
#endif /* OS_REFCNT_DEBUG */

void
os_ref_panic_live(void *rc)
{
	panic("os_refcnt: unexpected release of final reference (rc=%p)\n", rc);
	__builtin_unreachable();
}

__abortlike
static void
os_ref_panic_underflow(void *rc)
{
	panic("os_refcnt: underflow (rc=%p)\n", rc);
	__builtin_unreachable();
}

__abortlike
static void
os_ref_panic_resurrection(void *rc)
{
	panic("os_refcnt: attempted resurrection (rc=%p)\n", rc);
	__builtin_unreachable();
}

__abortlike
static void
os_ref_panic_overflow(void *rc)
{
	panic("os_refcnt: overflow (rc=%p)\n", rc);
	__builtin_unreachable();
}

static inline void
os_ref_check_underflow(void *rc, os_ref_count_t count, os_ref_count_t n)
{
	if (__improbable(count < n)) {
		os_ref_panic_underflow(rc);
	}
}

static inline void
os_ref_check_overflow(os_ref_atomic_t *rc, os_ref_count_t count)
{
	if (__improbable(count >= OS_REFCNT_MAX_COUNT)) {
		os_ref_panic_overflow(rc);
	}
}

static inline void
os_ref_check_retain(os_ref_atomic_t *rc, os_ref_count_t count, os_ref_count_t n)
{
	if (__improbable(count < n)) {
		os_ref_panic_resurrection(rc);
	}
	os_ref_check_overflow(rc, count);
}

#if OS_REFCNT_DEBUG
#if KERNEL
__attribute__((cold, noinline))
static void
ref_log_op(struct os_refgrp *grp, void *elem, reflog_op_t op)
{
	if (grp == NULL) {
		return;
	}

	if (grp->grp_log == NULL) {
		ref_log_op(grp->grp_parent, elem, op);
		return;
	}

	uintptr_t bt[REFLOG_BTDEPTH];
	uint32_t nframes = backtrace(bt, REFLOG_BTDEPTH, NULL);
	btlog_add_entry((btlog_t *)grp->grp_log, elem, op, (void **)bt, nframes);
}

__attribute__((cold, noinline))
static void
ref_log_drop(struct os_refgrp *grp, void *elem)
{
	if (!ref_debug_enable || grp == NULL) {
		return;
	}

	if (grp->grp_log == NULL) {
		ref_log_drop(grp->grp_parent, elem);
		return;
	}

	btlog_remove_entries_for_element(grp->grp_log, elem);
}

__attribute__((cold, noinline))
static void
ref_log_init(struct os_refgrp *grp)
{
	if (grp->grp_log != NULL) {
		return;
	}

	char grpbuf[128];
	char *refgrp = grpbuf;
	if (!PE_parse_boot_argn("rlog", refgrp, sizeof(grpbuf))) {
		return;
	}

	/*
	 * Enable refcount statistics if the rlog boot-arg is present,
	 * even when no specific group is logged.
	 */
	ref_debug_enable = true;

	const char *g;
	while ((g = strsep(&refgrp, ",")) != NULL) {
		if (strcmp(g, grp->grp_name) == 0) {
			/* enable logging on this refgrp */
			grp->grp_log = btlog_create(ref_log_nrecords, REFLOG_BTDEPTH, true);
			return;
		}
	}
}
#else

#ifndef ref_log_init
static inline void
ref_log_init(struct os_refgrp *grp __unused)
{
}
#endif
#ifndef ref_log_op
static inline void
ref_log_op(struct os_refgrp *grp __unused, void *rc __unused, reflog_op_t op __unused)
{
}
#endif
#ifndef ref_log_drop
static inline void
ref_log_drop(struct os_refgrp *grp __unused, void *rc __unused)
{
}
#endif

#endif /* KERNEL */

/*
 * attach a new refcnt to a group
 */
__attribute__((cold, noinline))
static void
ref_attach_to_group(os_ref_atomic_t *rc, struct os_refgrp *grp, os_ref_count_t init_count)
{
	if (grp == NULL) {
		return;
	}

	if (atomic_fetch_add_explicit(&grp->grp_children, 1, memory_order_relaxed) == 0) {
		/* First reference count object in this group. Check if we should enable
		 * refcount logging. */
		ref_log_init(grp);
	}

	atomic_fetch_add_explicit(&grp->grp_count, init_count, memory_order_relaxed);
	atomic_fetch_add_explicit(&grp->grp_retain_total, init_count, memory_order_relaxed);

	if (grp == &global_ref_group) {
		return;
	}

	if (grp->grp_parent == NULL) {
		grp->grp_parent = &global_ref_group;
	}

	ref_attach_to_group(rc, grp->grp_parent, init_count);
}

static void
ref_retain_group(struct os_refgrp *grp)
{
	if (grp) {
		atomic_fetch_add_explicit(&grp->grp_count, 1, memory_order_relaxed);
		atomic_fetch_add_explicit(&grp->grp_retain_total, 1, memory_order_relaxed);
		ref_retain_group(grp->grp_parent);
	}
}

__attribute__((cold, noinline))
static void
ref_release_group(struct os_refgrp *grp, bool final)
{
	if (grp) {
		atomic_fetch_sub_explicit(&grp->grp_count, 1, memory_order_relaxed);
		atomic_fetch_add_explicit(&grp->grp_release_total, 1, memory_order_relaxed);
		if (final) {
			atomic_fetch_sub_explicit(&grp->grp_children, 1, memory_order_relaxed);
		}

		ref_release_group(grp->grp_parent, final);
	}
}

__attribute__((cold, noinline))
static void
ref_init_debug(os_ref_atomic_t *rc, struct os_refgrp * __debug_only grp, os_ref_count_t count)
{
	ref_attach_to_group(rc, grp, count);

	for (os_ref_count_t i = 0; i < count; i++) {
		ref_log_op(grp, (void *)rc, REFLOG_RETAIN);
	}
}

__attribute__((cold, noinline))
static void
ref_retain_debug(os_ref_atomic_t *rc, struct os_refgrp * __debug_only grp)
{
	ref_retain_group(grp);
	ref_log_op(grp, (void *)rc, REFLOG_RETAIN);
}
#endif

void
os_ref_init_count_internal(os_ref_atomic_t *rc, struct os_refgrp * __debug_only grp, os_ref_count_t count)
{
	os_ref_check_underflow(rc, count, 1);
	atomic_init(rc, count);

#if OS_REFCNT_DEBUG
	if (__improbable(ref_debug_enable && grp)) {
		ref_init_debug(rc, grp, count);
	}
#endif
}

void
os_ref_retain_internal(os_ref_atomic_t *rc, struct os_refgrp * __debug_only grp)
{
	os_ref_count_t old = atomic_fetch_add_explicit(rc, 1, memory_order_relaxed);
	os_ref_check_retain(rc, old, 1);

#if OS_REFCNT_DEBUG
	if (__improbable(grp && ref_debug_enable)) {
		ref_retain_debug(rc, grp);
	}
#endif
}

bool
os_ref_retain_try_internal(os_ref_atomic_t *rc, struct os_refgrp * __debug_only grp)
{
	os_ref_count_t cur, next;

	os_atomic_rmw_loop(rc, cur, next, relaxed, {
		if (__improbable(cur == 0)) {
		        os_atomic_rmw_loop_give_up(return false);
		}

		next = cur + 1;
	});

	os_ref_check_overflow(rc, cur);

#if OS_REFCNT_DEBUG
	if (__improbable(grp && ref_debug_enable)) {
		ref_retain_debug(rc, grp);
	}
#endif

	return true;
}

__attribute__((always_inline))
static inline os_ref_count_t
_os_ref_release_inline(os_ref_atomic_t *rc, os_ref_count_t n,
    struct os_refgrp * __debug_only grp,
    memory_order release_order, memory_order dealloc_order)
{
	os_ref_count_t val;

#if OS_REFCNT_DEBUG
	if (__improbable(grp && ref_debug_enable)) {
		/*
		 * Care not to use 'rc' after the decrement because it might be deallocated
		 * under us.
		 */
		ref_log_op(grp, (void *)rc, REFLOG_RELEASE);
	}
#endif

	val = atomic_fetch_sub_explicit(rc, n, release_order);
	os_ref_check_underflow(rc, val, n);
	val -= n;
	if (__improbable(val < n)) {
		atomic_load_explicit(rc, dealloc_order);
	}

#if OS_REFCNT_DEBUG
	if (__improbable(grp && ref_debug_enable)) {
		if (val < n) {
			ref_log_drop(grp, (void *)rc); /* rc is only used as an identifier */
		}
		ref_release_group(grp, !val);
	}
#endif

	return val;
}

#if OS_REFCNT_DEBUG
__attribute__((noinline))
static os_ref_count_t
os_ref_release_n_internal(os_ref_atomic_t *rc, os_ref_count_t n,
    struct os_refgrp * __debug_only grp,
    memory_order release_order, memory_order dealloc_order)
{
	// Legacy exported interface with bad codegen due to the barriers
	// not being immediate
	//
	// Also serves as the debug function
	return _os_ref_release_inline(rc, n, grp, release_order, dealloc_order);
}
#endif

__attribute__((noinline))
os_ref_count_t
os_ref_release_internal(os_ref_atomic_t *rc, struct os_refgrp * __debug_only grp,
    memory_order release_order, memory_order dealloc_order)
{
	// Legacy exported interface with bad codegen due to the barriers
	// not being immediate
	//
	// Also serves as the debug function
	return _os_ref_release_inline(rc, 1, grp, release_order, dealloc_order);
}

os_ref_count_t
os_ref_release_barrier_internal(os_ref_atomic_t *rc,
    struct os_refgrp * __debug_only grp)
{
#if OS_REFCNT_DEBUG
	if (__improbable(grp && ref_debug_enable)) {
		return os_ref_release_internal(rc, grp,
		           memory_order_release, memory_order_acquire);
	}
#endif
	return _os_ref_release_inline(rc, 1, NULL,
	           memory_order_release, memory_order_acquire);
}

os_ref_count_t
os_ref_release_relaxed_internal(os_ref_atomic_t *rc,
    struct os_refgrp * __debug_only grp)
{
#if OS_REFCNT_DEBUG
	if (__improbable(grp && ref_debug_enable)) {
		return os_ref_release_internal(rc, grp,
		           memory_order_relaxed, memory_order_relaxed);
	}
#endif
	return _os_ref_release_inline(rc, 1, NULL,
	           memory_order_relaxed, memory_order_relaxed);
}

void
os_ref_retain_locked_internal(os_ref_atomic_t *rc, struct os_refgrp * __debug_only grp)
{
	os_ref_count_t val = os_ref_get_count_internal(rc);
	os_ref_check_retain(rc, val, 1);
	atomic_store_explicit(rc, ++val, memory_order_relaxed);

#if OS_REFCNT_DEBUG
	if (__improbable(grp && ref_debug_enable)) {
		ref_retain_debug(rc, grp);
	}
#endif
}

os_ref_count_t
os_ref_release_locked_internal(os_ref_atomic_t *rc, struct os_refgrp * __debug_only grp)
{
	os_ref_count_t val = os_ref_get_count_internal(rc);
	os_ref_check_underflow(rc, val, 1);
	atomic_store_explicit(rc, --val, memory_order_relaxed);

#if OS_REFCNT_DEBUG
	if (__improbable(grp && ref_debug_enable)) {
		ref_release_group(grp, !val);
		ref_log_op(grp, (void *)rc, REFLOG_RELEASE);
		if (val == 0) {
			ref_log_drop(grp, (void *)rc);
		}
	}
#endif

	return val;
}

/*
 * Bitwise API
 */

#undef os_ref_init_count_mask
void
os_ref_init_count_mask(os_ref_atomic_t *rc, uint32_t b,
    struct os_refgrp *__debug_only grp,
    os_ref_count_t init_count, uint32_t init_bits)
{
	assert(init_bits < (1U << b));
	atomic_init(rc, (init_count << b) | init_bits);
	os_ref_check_underflow(rc, (init_count << b), 1u << b);

#if OS_REFCNT_DEBUG
	if (__improbable(ref_debug_enable && grp)) {
		ref_init_debug(rc, grp, init_count);
	}
#endif
}

__attribute__((always_inline))
static inline void
os_ref_retain_mask_inline(os_ref_atomic_t *rc, uint32_t n,
    struct os_refgrp *__debug_only grp, memory_order mo)
{
	os_ref_count_t old = atomic_fetch_add_explicit(rc, n, mo);
	os_ref_check_retain(rc, old, n);

#if OS_REFCNT_DEBUG
	if (__improbable(grp && ref_debug_enable)) {
		ref_retain_debug(rc, grp);
	}
#endif
}

void
os_ref_retain_mask_internal(os_ref_atomic_t *rc, uint32_t n,
    struct os_refgrp *__debug_only grp)
{
	os_ref_retain_mask_inline(rc, n, grp, memory_order_relaxed);
}

void
os_ref_retain_acquire_mask_internal(os_ref_atomic_t *rc, uint32_t n,
    struct os_refgrp *__debug_only grp)
{
	os_ref_retain_mask_inline(rc, n, grp, memory_order_acquire);
}

uint32_t
os_ref_release_barrier_mask_internal(os_ref_atomic_t *rc, uint32_t n,
    struct os_refgrp *__debug_only grp)
{
#if OS_REFCNT_DEBUG
	if (__improbable(grp && ref_debug_enable)) {
		return os_ref_release_n_internal(rc, n, grp,
		           memory_order_release, memory_order_acquire);
	}
#endif

	return _os_ref_release_inline(rc, n, NULL,
	           memory_order_release, memory_order_acquire);
}

uint32_t
os_ref_release_relaxed_mask_internal(os_ref_atomic_t *rc, uint32_t n,
    struct os_refgrp *__debug_only grp)
{
#if OS_REFCNT_DEBUG
	if (__improbable(grp && ref_debug_enable)) {
		return os_ref_release_n_internal(rc, n, grp,
		           memory_order_relaxed, memory_order_relaxed);
	}
#endif

	return _os_ref_release_inline(rc, n, NULL,
	           memory_order_relaxed, memory_order_relaxed);
}

bool
os_ref_retain_try_mask_internal(os_ref_atomic_t *rc, uint32_t n,
    uint32_t reject_mask, struct os_refgrp *__debug_only grp)
{
	os_ref_count_t cur, next;

	os_atomic_rmw_loop(rc, cur, next, relaxed, {
		if (__improbable(cur < n || (cur & reject_mask))) {
		        os_atomic_rmw_loop_give_up(return false);
		}
		next = cur + n;
	});

	os_ref_check_overflow(rc, cur);

#if OS_REFCNT_DEBUG
	if (__improbable(grp && ref_debug_enable)) {
		ref_retain_debug(rc, grp);
	}
#endif

	return true;
}

bool
os_ref_retain_try_acquire_mask_internal(os_ref_atomic_t *rc, uint32_t n,
    uint32_t reject_mask, struct os_refgrp *__debug_only grp)
{
	os_ref_count_t cur, next;

	os_atomic_rmw_loop(rc, cur, next, acquire, {
		if (__improbable(cur < n || (cur & reject_mask))) {
		        os_atomic_rmw_loop_give_up(return false);
		}
		next = cur + n;
	});

	os_ref_check_overflow(rc, cur);

#if OS_REFCNT_DEBUG
	if (__improbable(grp && ref_debug_enable)) {
		ref_retain_debug(rc, grp);
	}
#endif

	return true;
}
