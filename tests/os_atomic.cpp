#include <darwintest.h>
#include <os/atomic_private.h>

T_GLOBAL_META(
	T_META_RUN_CONCURRENTLY(true),
	T_META_CHECK_LEAKS(false)
	);

T_DECL(os_atomic, "Just to make sure things build at all in c++ mode")
{
	os_atomic(int) i = 0;
	int old_i = 0;
	volatile int v_i = 0;
	int a, b;

	T_ASSERT_EQ(os_atomic_inc_orig(&i, relaxed), 0, "atomic inc");
	T_ASSERT_EQ(os_atomic_cmpxchg(&i, 1, 0, relaxed), true, "os_atomic_cmpxchg");
	os_atomic_rmw_loop(&i, a, b, relaxed, {
		b = a;
	});

	T_ASSERT_EQ(os_atomic_inc_orig(&old_i, relaxed), 0, "atomic inc");
	T_ASSERT_EQ(os_atomic_cmpxchg(&old_i, 1, 0, relaxed), true, "os_atomic_cmpxchg");
	os_atomic_rmw_loop(&old_i, a, b, relaxed, {
		b = a;
	});

	T_ASSERT_EQ(os_atomic_inc_orig(&v_i, relaxed), 0, "atomic inc");
	T_ASSERT_EQ(os_atomic_cmpxchg(&v_i, 1, 0, relaxed), true, "os_atomic_cmpxchg");
	os_atomic_rmw_loop(&v_i, a, b, relaxed, {
		b = a;
	});
}
