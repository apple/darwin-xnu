#include <stdatomic.h>
#include <sys/kern_sysctl.h>

#include <darwintest_utils.h>
#include <darwintest.h>

#include "counter/common.h"
#include "test_utils.h"

static unsigned int ncpu(void);

static uint64_t
sysctl_read(const char *name)
{
	int result;
	uint64_t value;
	size_t size = sizeof(value);
	result = sysctlbyname(name, &value, &size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(result, "Read from %s", name);
	return value;
}

static void
sysctl_write(const char* name, int64_t amount)
{
	kern_return_t result;
	result = sysctlbyname(name, NULL, NULL, &amount, sizeof(int64_t));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(result, "Write to %s", name);
}

static void
scalable_counter_add(int64_t amount)
{
	sysctl_write("kern.scalable_counter_test_add", amount);
}

static void
static_scalable_counter_add(int64_t amount)
{
	sysctl_write("kern.static_scalable_counter_test_add", amount);
}

static int64_t
scalable_counter_load(void)
{
	return (int64_t) sysctl_read("kern.scalable_counter_test_load");
}

static int64_t
static_scalable_counter_load(void)
{
	return (int64_t) sysctl_read("kern.static_scalable_counter_test_load");
}

/*
 * A background thread that bangs on the percpu counter and then exits.
 * @param num_iterations How many times to bang on the counter. Each iteration makes the counter
 * bigger by 100.
 */
static void*
background_scalable_counter_thread(void* num_iterations_ptr)
{
	int64_t i, num_iterations;
	num_iterations = (int64_t)(num_iterations_ptr);
	for (i = 0; i < num_iterations; i++) {
		scalable_counter_add(-25);
		scalable_counter_add(75);
		scalable_counter_add(-100);
		scalable_counter_add(150);
	}
	atomic_thread_fence(memory_order_release);
	return 0;
}

static
void
darwin_test_fini_scalable_counter_test()
{
	int ret = fini_scalable_counter_test();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "fini_scalable_counter_test");
}

static
void
darwin_test_setup(void)
{
	T_SETUPBEGIN;
	int dev_kernel = is_development_kernel();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(dev_kernel, "sysctlbyname kern.development");
	if (is_development_kernel() != 1) {
		T_SKIP("Skipping test on non development kernel.");
	}
	init_scalable_counter_test();
	T_SETUPEND;
	T_ATEND(darwin_test_fini_scalable_counter_test);
}

T_DECL(test_scalable_counters_single_threaded, "Test single threaded operations on scalable_counters", T_META_ASROOT(true))
{
	static int64_t kNumIterations = 100, i, expected_value = 0;
	darwin_test_setup();
	T_QUIET; T_EXPECT_EQ(scalable_counter_load(), 0LL, "Counter starts at zero");

	/* Simple add, subtract, and read */
	scalable_counter_add(1);
	T_QUIET; T_EXPECT_EQ(scalable_counter_load(), 1LL, "0 + 1 == 1");
	scalable_counter_add(-1);
	T_QUIET; T_EXPECT_EQ(scalable_counter_load(), 0LL, "1 - 1 == 0");
	for (i = 0; i < kNumIterations; i++) {
		scalable_counter_add(i);
		expected_value += i;
	}
	for (i = 0; i < kNumIterations / 2; i++) {
		scalable_counter_add(-i);
		expected_value -= i;
	}
	T_QUIET; T_EXPECT_EQ(scalable_counter_load(), expected_value, "Counter value is correct.");
	T_END;
}

T_DECL(test_static_counter, "Test staticly declared counter", T_META_ASROOT(true))
{
	static size_t kNumIterations = 100;
	int64_t start_value;
	darwin_test_setup();
	start_value = static_scalable_counter_load();
	for (size_t i = 0; i < kNumIterations; i++) {
		static_scalable_counter_add(1);
	}
	T_QUIET; T_EXPECT_EQ(static_scalable_counter_load(), (long long) kNumIterations + start_value, "Counter value is correct");
	T_END;
}

T_DECL(test_scalable_counters_multithreaded, "Test multi-threaded operations on scalable_counters", T_META_ASROOT(true))
{
	unsigned int kNumThreads = ncpu() * 5;
	int ret;
	int64_t i;
	pthread_attr_t pthread_attr;
	pthread_t *threads;

	darwin_test_setup();

	threads = malloc(sizeof(pthread_t) * kNumThreads);
	T_QUIET; T_ASSERT_NOTNULL(threads, "Out of memory");

	ret = pthread_attr_init(&pthread_attr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_attr_init");

	int64_t expected_value = 0;
	for (i = 0; i < kNumThreads; i++) {
		ret = pthread_create(&threads[i], &pthread_attr, background_scalable_counter_thread, (void*)(i));
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_create");
		expected_value += 100 * i;
	}

	for (i = 0; i < kNumThreads; i++) {
		void *exit_code;
		ret = pthread_join(threads[i], &exit_code);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_join");
		T_QUIET; T_ASSERT_EQ((ptrdiff_t) exit_code, (ptrdiff_t) 0, "Background thread exited sucessfully.");
	}
	atomic_thread_fence(memory_order_acquire);

	T_QUIET; T_EXPECT_EQ(scalable_counter_load(), expected_value, "Counter value is correct.");

	ret = pthread_attr_destroy(&pthread_attr);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_attr_destroy");
	free(threads);
}

static unsigned int
ncpu()
{
	kern_return_t result;
	int ncpu;
	size_t size = sizeof(ncpu);
	result = sysctlbyname("hw.ncpu", &ncpu, &size, NULL, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(result, "hw.npu");
	return (unsigned int) ncpu;
}
