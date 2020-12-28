#include <darwintest.h>
#include <darwintest_utils.h>
#include <stdio.h>
#include <assert.h>
#include <setjmp.h>

#define DEVELOPMENT 1
#define DEBUG 0
#define XNU_KERNEL_PRIVATE 1

#define OS_REFCNT_DEBUG 1
#define STRESS_TESTS 0

void handle_panic(const char *func, char *str, ...);
#define panic(...) handle_panic(__func__, __VA_ARGS__)

#include "../libkern/os/refcnt.h"
#include "../libkern/os/refcnt.c"

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

/* import some of the refcnt internal state for testing */
extern bool ref_debug_enable;
os_refgrp_decl_extern(global_ref_group);

T_GLOBAL_META(
	T_META_NAMESPACE("os_refcnt"),
	T_META_CHECK_LEAKS(false)
	);

T_DECL(os_refcnt, "Basic atomic refcount")
{
	struct os_refcnt rc;
	os_ref_init(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 1, "refcount correctly initialized");

	os_ref_retain(&rc);
	os_ref_retain(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 3, "retain increased count");

	os_ref_count_t x = os_ref_release(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 2, "release decreased count");
	T_ASSERT_EQ_UINT(x, 2, "release returned correct count");

	os_ref_release_live(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 1, "release_live decreased count");

	x = os_ref_release(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 0, "released");
	T_ASSERT_EQ_UINT(x, 0, "returned released");

	os_ref_init(&rc, NULL);
	x = os_ref_retain_try(&rc);
	T_ASSERT_GT_INT(x, 0, "try retained");

	(void)os_ref_release(&rc);
	(void)os_ref_release(&rc);
	T_QUIET; T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 0, "release");

	x = os_ref_retain_try(&rc);
	T_ASSERT_EQ_INT(x, 0, "try failed");
}

T_DECL(refcnt_raw, "Raw refcount")
{
	os_ref_atomic_t rc;
	os_ref_init_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 1, "refcount correctly initialized");

	os_ref_retain_raw(&rc, NULL);
	os_ref_retain_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 3, "retain increased count");

	os_ref_count_t x = os_ref_release_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 2, "release decreased count");
	T_ASSERT_EQ_UINT(x, 2, "release returned correct count");

	os_ref_release_live_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 1, "release_live decreased count");

	x = os_ref_release_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 0, "released");
	T_ASSERT_EQ_UINT(x, 0, "returned released");

	os_ref_init_raw(&rc, NULL);
	x = os_ref_retain_try_raw(&rc, NULL);
	T_ASSERT_GT_INT(x, 0, "try retained");

	(void)os_ref_release_raw(&rc, NULL);
	(void)os_ref_release_raw(&rc, NULL);
	T_QUIET; T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 0, "release");

	x = os_ref_retain_try_raw(&rc, NULL);
	T_ASSERT_EQ_INT(x, 0, "try failed");
}

T_DECL(refcnt_locked, "Locked refcount")
{
	struct os_refcnt rc;
	os_ref_init(&rc, NULL);

	os_ref_retain_locked(&rc);
	os_ref_retain_locked(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 3, "retain increased count");

	os_ref_count_t x = os_ref_release_locked(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 2, "release decreased count");
	T_ASSERT_EQ_UINT(x, 2, "release returned correct count");

	(void)os_ref_release_locked(&rc);
	x = os_ref_release_locked(&rc);
	T_ASSERT_EQ_UINT(os_ref_get_count(&rc), 0, "released");
	T_ASSERT_EQ_UINT(x, 0, "returned released");
}

T_DECL(refcnt_raw_locked, "Locked raw refcount")
{
	os_ref_atomic_t rc;
	os_ref_init_raw(&rc, NULL);

	os_ref_retain_locked_raw(&rc, NULL);
	os_ref_retain_locked_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 3, "retain increased count");

	os_ref_count_t x = os_ref_release_locked_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 2, "release decreased count");
	T_ASSERT_EQ_UINT(x, 2, "release returned correct count");

	(void)os_ref_release_locked_raw(&rc, NULL);
	x = os_ref_release_locked_raw(&rc, NULL);
	T_ASSERT_EQ_UINT(os_ref_get_count_raw(&rc), 0, "released");
	T_ASSERT_EQ_UINT(x, 0, "returned released");
}

T_DECL(refcnt_mask_locked, "Locked bitwise refcount")
{
	const os_ref_count_t b = 12;
	os_ref_atomic_t rc;
	os_ref_count_t reserved = 0xaaa;
	os_ref_init_count_mask(&rc, NULL, 1, reserved, b);

	os_ref_retain_locked_mask(&rc, NULL, b);
	os_ref_retain_locked_mask(&rc, NULL, b);
	T_ASSERT_EQ_UINT(os_ref_get_count_mask(&rc, b), 3, "retain increased count");

	os_ref_count_t x = os_ref_release_locked_mask(&rc, NULL, b);
	T_ASSERT_EQ_UINT(os_ref_get_count_mask(&rc, b), 2, "release decreased count");
	T_ASSERT_EQ_UINT(x, 2, "release returned correct count");
	T_ASSERT_EQ_UINT(rc & ((1U << b) - 1), reserved, "Reserved bits not modified");

	(void)os_ref_release_locked_mask(&rc, NULL, b);
	x = os_ref_release_locked_mask(&rc, NULL, b);
	T_ASSERT_EQ_UINT(os_ref_get_count_mask(&rc, b), 0, "released");
	T_ASSERT_EQ_UINT(x, 0, "returned released");
	T_ASSERT_EQ_UINT(rc & ((1U << b) - 1), reserved, "Reserved bits not modified");
}

static void
do_bitwise_test(const os_ref_count_t bits)
{
	os_ref_atomic_t rc;
	os_ref_count_t reserved = 0xaaaaaaaaU & ((1U << bits) - 1);
	os_ref_init_count_mask(&rc, NULL, 1, reserved, bits);

	T_ASSERT_EQ_UINT(os_ref_get_count_mask(&rc, bits), 1, "[%u bits] refcount initialized", bits);

	os_ref_retain_mask(&rc, NULL, bits);
	os_ref_retain_mask(&rc, NULL, bits);
	T_ASSERT_EQ_UINT(os_ref_get_count_mask(&rc, bits), 3, "retain increased count");

	os_ref_count_t x = os_ref_release_mask(&rc, NULL, bits);
	T_ASSERT_EQ_UINT(x, 2, "release returned correct count");

	os_ref_release_live_mask(&rc, NULL, bits);
	T_ASSERT_EQ_UINT(os_ref_get_count_mask(&rc, bits), 1, "release_live decreased count");

	x = os_ref_release_mask(&rc, NULL, bits);
	T_ASSERT_EQ_UINT(os_ref_get_count_mask(&rc, bits), 0, "released");
	T_ASSERT_EQ_UINT(x, 0, "returned released");

	T_ASSERT_EQ_UINT(rc & ((1U << bits) - 1), reserved, "Reserved bits not modified");

	os_ref_init_count_mask(&rc, NULL, 1, reserved, bits);
	x = os_ref_retain_try_mask(&rc, NULL, bits);
	T_ASSERT_GT_INT(x, 0, "try retained");

	(void)os_ref_release_mask(&rc, NULL, bits);
	(void)os_ref_release_mask(&rc, NULL, bits);
	T_QUIET; T_ASSERT_EQ_UINT(os_ref_get_count_mask(&rc, bits), 0, "release");

	x = os_ref_retain_try_mask(&rc, NULL, bits);
	T_ASSERT_EQ_INT(x, 0, "try failed");

	T_ASSERT_EQ_UINT(rc & ((1U << bits) - 1), reserved, "Reserved bits not modified");
}

T_DECL(refcnt_bitwise, "Bitwise refcount")
{
	do_bitwise_test(0);
	do_bitwise_test(1);
	do_bitwise_test(8);
	do_bitwise_test(26);

	os_ref_atomic_t rc = 0xaaaaaaaa;

	const os_ref_count_t nbits = 3;
	const os_ref_count_t count = 5;
	const os_ref_count_t bits = 7;
	os_ref_init_count_mask(&rc, NULL, count, bits, nbits);

	os_ref_count_t mask = (1U << nbits) - 1;
	T_ASSERT_EQ_UINT(rc & mask, bits, "bits correctly initialized");
	T_ASSERT_EQ_UINT(rc >> nbits, count, "count correctly initialized");
}

os_refgrp_decl(static, g1, "test group", NULL);
os_refgrp_decl_extern(g1);

T_DECL(refcnt_groups, "Group accounting")
{
#if OS_REFCNT_DEBUG
	ref_debug_enable = true;

	struct os_refcnt rc;
	os_ref_init(&rc, &g1);

	T_ASSERT_EQ_UINT(g1.grp_children, 1, "group attached");
	T_ASSERT_EQ_UINT(global_ref_group.grp_children, 1, "global group attached");
	T_ASSERT_EQ_UINT(g1.grp_count, 1, "group count");
	T_ASSERT_EQ_ULLONG(g1.grp_retain_total, 1ULL, "group retains");
	T_ASSERT_EQ_ULLONG(g1.grp_release_total, 0ULL, "group releases");

	os_ref_retain(&rc);
	os_ref_retain(&rc);
	os_ref_release_live(&rc);
	os_ref_release_live(&rc);

	T_EXPECT_EQ_ULLONG(g1.grp_retain_total, 3ULL, "group retains");
	T_EXPECT_EQ_ULLONG(g1.grp_release_total, 2ULL, "group releases");

	os_ref_count_t x = os_ref_release(&rc);
	T_QUIET; T_ASSERT_EQ_UINT(x, 0, "released");

	T_ASSERT_EQ_UINT(g1.grp_children, 0, "group detatched");
	T_ASSERT_EQ_UINT(g1.grp_count, 0, "group count");
#else
	T_SKIP("Refcount debugging disabled");
#endif
}

enum {
	OSREF_UNDERFLOW    = 1,
	OSREF_OVERFLOW     = 2,
	OSREF_RESURRECTION = 3,
	OSREF_DEALLOC_LIVE = 4,
};

static jmp_buf jb;
static bool expect_panic = false;

void
handle_panic(const char *func, char *__unused str, ...)
{
	int ret = -1;
	if (!expect_panic) {
		T_FAIL("unexpected panic from %s", func);
		T_LOG("corrupt program state, aborting");
		abort();
	}
	expect_panic = false;

	if (strcmp(func, "os_ref_panic_underflow") == 0) {
		ret = OSREF_UNDERFLOW;
	} else if (strcmp(func, "os_ref_panic_overflow") == 0) {
		ret = OSREF_OVERFLOW;
	} else if (strcmp(func, "os_ref_panic_resurrection") == 0) {
		ret = OSREF_RESURRECTION;
	} else if (strcmp(func, "os_ref_panic_live") == 0) {
		ret = OSREF_DEALLOC_LIVE;
	} else {
		T_LOG("unexpected panic from %s", func);
	}

	longjmp(jb, ret);
}

T_DECL(refcnt_underflow, "Underflow")
{
	os_ref_atomic_t rc;
	os_ref_init_raw(&rc, NULL);
	(void)os_ref_release_raw(&rc, NULL);

	int x = setjmp(jb);
	if (x == 0) {
		expect_panic = true;
		(void)os_ref_release_raw(&rc, NULL);
		T_FAIL("underflow not caught");
	} else {
		T_ASSERT_EQ_INT(x, OSREF_UNDERFLOW, "underflow caught");
	}
}

T_DECL(refcnt_overflow, "Overflow")
{
	os_ref_atomic_t rc;
	os_ref_init_count_raw(&rc, NULL, 0x0fffffffU);

	int x = setjmp(jb);
	if (x == 0) {
		expect_panic = true;
		(void)os_ref_retain_raw(&rc, NULL);
		T_FAIL("overflow not caught");
	} else {
		T_ASSERT_EQ_INT(x, OSREF_OVERFLOW, "overflow caught");
	}
}

T_DECL(refcnt_resurrection, "Resurrection")
{
	os_ref_atomic_t rc;
	os_ref_init_raw(&rc, NULL);
	os_ref_count_t n = os_ref_release_raw(&rc, NULL);

	T_QUIET; T_EXPECT_EQ_UINT(n, 0, "reference not released");

	int x = setjmp(jb);
	if (x == 0) {
		expect_panic = true;
		(void)os_ref_retain_raw(&rc, NULL);
		T_FAIL("resurrection not caught");
	} else {
		T_ASSERT_EQ_INT(x, OSREF_RESURRECTION, "resurrection caught");
	}
}

T_DECL(refcnt_dealloc_live, "Dealloc expected live object")
{
	os_ref_atomic_t rc;
	os_ref_init_raw(&rc, NULL);

	expect_panic = true;
	int x = setjmp(jb);
	if (x == 0) {
		expect_panic = true;
		os_ref_release_live_raw(&rc, NULL);
		T_FAIL("dealloc live not caught");
	} else {
		T_ASSERT_EQ_INT(x, OSREF_DEALLOC_LIVE, "dealloc live caught");
	}
}

T_DECL(refcnt_initializer, "Static intializers")
{
	struct os_refcnt rc = OS_REF_INITIALIZER;
	os_ref_atomic_t rca = OS_REF_ATOMIC_INITIALIZER;

	T_ASSERT_EQ_INT(0, os_ref_retain_try(&rc), NULL);
	T_ASSERT_EQ_INT(0, os_ref_get_count_raw(&rca), NULL);
}

#if STRESS_TESTS

static const unsigned long iters = 1024 * 1024 * 32;

static void *
func(void *_rc)
{
	struct os_refcnt *rc = _rc;
	for (unsigned long i = 0; i < iters; i++) {
		os_ref_retain(rc);
		os_ref_release_live(rc);
	}
	return NULL;
}

T_DECL(refcnt_stress, "Stress test")
{
	pthread_t th1, th2;

	struct os_refcnt rc;
	os_ref_init(&rc, NULL);

	T_ASSERT_POSIX_ZERO(pthread_create(&th1, NULL, func, &rc), "pthread_create");
	T_ASSERT_POSIX_ZERO(pthread_create(&th2, NULL, func, &rc), "pthread_create");

	void *r1, *r2;
	T_ASSERT_POSIX_ZERO(pthread_join(th1, &r1), "pthread_join");
	T_ASSERT_POSIX_ZERO(pthread_join(th2, &r2), "pthread_join");

	os_ref_count_t x = os_ref_release(&rc);
	T_ASSERT_EQ_INT(x, 0, "Consistent refcount");
}

#endif
