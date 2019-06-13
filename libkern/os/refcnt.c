#include <kern/assert.h>
#include <kern/debug.h>
#include <pexpert/pexpert.h>
#include <kern/btlog.h>
#include <kern/backtrace.h>
#include <libkern/libkern.h>
#include "refcnt.h"

#define OS_REFCNT_MAX_COUNT     ((os_ref_count_t)0x0FFFFFFFUL)

#if OS_REFCNT_DEBUG
os_refgrp_decl(static, global_ref_group, "all", NULL);
static bool ref_debug_enable = false;
static const size_t ref_log_nrecords = 1000000;

#define REFLOG_BTDEPTH   10
#define REFLOG_RETAIN    1
#define REFLOG_RELEASE   2

#define __debug_only
#else
# define __debug_only __unused
#endif /* OS_REFCNT_DEBUG */

static const char *
ref_grp_name(struct os_refcnt __debug_only *rc)
{
#if OS_REFCNT_DEBUG
	if (rc && rc->ref_group && rc->ref_group->grp_name) {
		return rc->ref_group->grp_name;
	}
#endif
	return "<null>";
}

static void
os_ref_check_underflow(struct os_refcnt *rc, os_ref_count_t count)
{
	if (__improbable(count == 0)) {
		panic("os_refcnt: underflow (rc=%p, grp=%s)\n", rc, ref_grp_name(rc));
		__builtin_unreachable();
	}
}

static void
os_ref_assert_referenced(struct os_refcnt *rc, os_ref_count_t count)
{
	if (__improbable(count == 0)) {
		panic("os_refcnt: used unsafely when zero (rc=%p, grp=%s)\n", rc, ref_grp_name(rc));
		__builtin_unreachable();
	}
}

static void
os_ref_check_overflow(struct os_refcnt *rc, os_ref_count_t count)
{
	if (__improbable(count >= OS_REFCNT_MAX_COUNT)) {
		panic("os_refcnt: overflow (rc=%p, grp=%s)\n", rc, ref_grp_name(rc));
		__builtin_unreachable();
	}
}

static void
os_ref_check_retain(struct os_refcnt *rc, os_ref_count_t count)
{
	os_ref_assert_referenced(rc, count);
	os_ref_check_overflow(rc, count);
}

#if OS_REFCNT_DEBUG
static void
ref_log_op(struct os_refgrp *grp, void *elem, int op)
{
	if (!ref_debug_enable || grp == NULL) {
		return;
	}

	if (grp->grp_log == NULL) {
		ref_log_op(grp->grp_parent, elem, op);
		return;
	}

	uintptr_t bt[REFLOG_BTDEPTH];
	uint32_t nframes = backtrace(bt, REFLOG_BTDEPTH);
	btlog_add_entry((btlog_t *)grp->grp_log, elem, op, (void **)bt, nframes);
}

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

	const char *g;
	while ((g = strsep(&refgrp, ",")) != NULL) {
		if (strcmp(g, grp->grp_name) == 0) {
			/* enable logging on this refgrp */
			grp->grp_log = btlog_create(ref_log_nrecords, REFLOG_BTDEPTH, true);
			assert(grp->grp_log);
			ref_debug_enable = true;
			return;
		}
	}

}

/*
 * attach a new refcnt to a group
 */
static void
ref_attach_to_group(struct os_refcnt *rc, struct os_refgrp *grp, os_ref_count_t init_count)
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

static inline void
ref_retain_group(struct os_refgrp *grp)
{
	if (grp) {
		atomic_fetch_add_explicit(&grp->grp_count, 1, memory_order_relaxed);
		atomic_fetch_add_explicit(&grp->grp_retain_total, 1, memory_order_relaxed);
		ref_retain_group(grp->grp_parent);
	}
}

static inline void
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
#endif

#undef os_ref_init_count
void
os_ref_init_count(struct os_refcnt *rc, struct os_refgrp __debug_only *grp, os_ref_count_t count)
{
	atomic_init(&rc->ref_count, count);

#if OS_REFCNT_DEBUG
	assert(count > 0);
	if (grp) {
		rc->ref_group = grp;
	} else {
		rc->ref_group = &global_ref_group;
	}

	ref_attach_to_group(rc, rc->ref_group, count);

	for (os_ref_count_t i = 0; i < count; i++) {
		ref_log_op(rc->ref_group, (void *)rc, REFLOG_RETAIN);
	}
#endif
}

void
os_ref_retain(struct os_refcnt *rc)
{
	os_ref_count_t old = atomic_fetch_add_explicit(&rc->ref_count, 1, memory_order_relaxed);
	os_ref_check_retain(rc, old);

#if OS_REFCNT_DEBUG
	ref_retain_group(rc->ref_group);
	ref_log_op(rc->ref_group, (void *)rc, REFLOG_RETAIN);
#endif
}

bool
os_ref_retain_try(struct os_refcnt *rc)
{
	os_ref_count_t cur = os_ref_get_count(rc);

	while (1) {
		if (__improbable(cur == 0)) {
			return false;
		}

		os_ref_check_retain(rc, cur);

		if (atomic_compare_exchange_weak_explicit(&rc->ref_count, &cur, cur+1,
					memory_order_relaxed, memory_order_relaxed)) {
#if OS_REFCNT_DEBUG
			ref_retain_group(rc->ref_group);
			ref_log_op(rc->ref_group, (void *)rc, REFLOG_RETAIN);
#endif
			return true;
		}
	}
}

os_ref_count_t
os_ref_release_explicit(struct os_refcnt *rc, memory_order release_order, memory_order dealloc_order)
{
#if OS_REFCNT_DEBUG
	/*
	 * Care not to use 'rc' after the decrement because it might be deallocated
	 * under us.
	 */
	struct os_refgrp *grp = rc->ref_group;
	ref_log_op(grp, (void *)rc, REFLOG_RELEASE);
#endif

	os_ref_count_t val = atomic_fetch_sub_explicit(&rc->ref_count, 1, release_order);
	os_ref_check_underflow(rc, val);
	if (__improbable(--val == 0)) {
		atomic_load_explicit(&rc->ref_count, dealloc_order);
#if OS_REFCNT_DEBUG
		ref_log_drop(grp, (void *)rc); /* rc is only used as an identifier */
#endif
	}

#if OS_REFCNT_DEBUG
	ref_release_group(grp, !val);
#endif

	return val;
}

void
os_ref_retain_locked(struct os_refcnt *rc)
{
	os_ref_count_t val = rc->ref_count;
	os_ref_check_retain(rc, val);
	rc->ref_count = ++val;

#if OS_REFCNT_DEBUG
	ref_retain_group(rc->ref_group);
	ref_log_op(rc->ref_group, (void *)rc, REFLOG_RETAIN);
#endif
}

os_ref_count_t
os_ref_release_locked(struct os_refcnt *rc)
{
	os_ref_count_t val = rc->ref_count;
	os_ref_check_underflow(rc, val);
	rc->ref_count = --val;

#if OS_REFCNT_DEBUG
	ref_release_group(rc->ref_group, !val);
	ref_log_op(rc->ref_group, (void *)rc, REFLOG_RELEASE);
	if (val == 0) {
		ref_log_drop(rc->ref_group, (void *)rc);
	}
#endif
	return val;
}

