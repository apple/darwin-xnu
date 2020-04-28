#include <time.h>
#include <errno.h>

#include <mach/mach.h>
#include <sys/kern_sysctl.h>
#include <sys/mman.h>

#include <darwintest.h>
#include <darwintest_utils.h>


static const char *g_sysctl_no_wire_name = "vm.global_no_user_wire_amount";
static const char *g_sysctl_wire_name = "vm.global_user_wire_limit";
static const char *g_sysctl_per_task_wire_name = "vm.user_wire_limit";
static const char *g_sysctl_current_wired_count_name = "vm.page_wire_count";
static const char *g_sysctl_current_free_count_name = "vm.lopage_free_count";
static const char *g_sysctl_vm_page_size_name = "vm.pagesize";
static const char *g_sysctl_memsize_name = "hw.memsize";

static size_t
ptoa(size_t num_pages)
{
	static size_t page_size = 0;
	int ret;
	size_t page_size_size = sizeof(page_size);
	if (page_size == 0) {
		ret = sysctlbyname(g_sysctl_vm_page_size_name, &page_size, &page_size_size, NULL, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "Unable to get page size");
	}
	return num_pages * (size_t) page_size;
}


T_DECL(global_no_user_wire_amount, "no_user_wire_amount <= 32G") {
	int ret;
	vm_map_size_t no_wire;
	size_t no_wire_size = sizeof(no_wire);
	ret = sysctlbyname(g_sysctl_no_wire_name, &no_wire, &no_wire_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "no_user_wire sysctl failed");
	T_QUIET; T_EXPECT_LE(no_wire, 32 * 2ULL << 30, "no_user_wire_amount is too big.");
}

T_DECL(user_wire_amount, "max_mem > user_wire_amount >= 0.7 * max_mem") {
	int ret;
	vm_map_size_t wire;
	uint64_t max_mem;
	size_t max_mem_size = sizeof(max_mem);
	size_t wire_size = sizeof(wire);
	ret = sysctlbyname(g_sysctl_memsize_name, &max_mem, &max_mem_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "memsize sysctl failed");
	ret = sysctlbyname(g_sysctl_wire_name, &wire, &wire_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "user_wire sysctl failed");
	T_QUIET; T_ASSERT_LT(wire, max_mem, "wire limit is too big");
	T_QUIET; T_ASSERT_GE(wire, max_mem * 70 / 100, "wire limit is too small.");
}

/*
 * Sets the no wire limit, and ensures that the wire_limit
 * changes correctly.
 */
static void
set_no_wire_limit(vm_map_size_t value, uint64_t max_mem)
{
	vm_map_size_t wire;
	size_t wire_size = sizeof(wire);
	int ret;
	ret = sysctlbyname(g_sysctl_no_wire_name, NULL, 0, &value, sizeof(value));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "no_user_wire sysctl set failed");
	ret = sysctlbyname(g_sysctl_wire_name, &wire, &wire_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "user_wire sysctl failed");
	T_QUIET; T_ASSERT_EQ(max_mem - wire, value, "no wire size is incorrect");
}

/*
 * Sets the wire limit, and ensures that the no_wire_limit
 * changes correctly.
 */
static void
set_wire_limit(vm_map_size_t value, uint64_t max_mem)
{
	vm_map_size_t no_wire;
	size_t no_wire_size = sizeof(no_wire);
	int ret;
	ret = sysctlbyname(g_sysctl_wire_name, NULL, 0, &value, sizeof(value));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "user_wire sysctl set failed");
	ret = sysctlbyname(g_sysctl_no_wire_name, &no_wire, &no_wire_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "no_user_wire sysctl failed");
	T_QUIET; T_ASSERT_EQ(max_mem - value, no_wire, "no wire size is incorrect");
}

T_DECL(set_global_no_user_wire_amount, "Setting no_user_wire_amount changes global_user_wire_amount", T_META_ASROOT(true)) {
	int ret;
	vm_map_size_t no_wire, wire;
	vm_map_size_t no_wire_delta = 16 * (1 << 10);
	uint64_t max_mem;
	size_t no_wire_size = sizeof(no_wire);
	size_t wire_size = sizeof(wire);
	size_t max_mem_size = sizeof(max_mem);
	ret = sysctlbyname(g_sysctl_memsize_name, &max_mem, &max_mem_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "max_mem sysctl failed");
	ret = sysctlbyname(g_sysctl_no_wire_name, &no_wire, &no_wire_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "no_user_wire sysctl failed");
	ret = sysctlbyname(g_sysctl_wire_name, &wire, &wire_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "user_wire sysctl failed");
	T_QUIET; T_ASSERT_EQ(max_mem - wire, no_wire, "no wire size is incorrect");

	// Set the no_wire limit and ensure that the wire_size changed.
	set_no_wire_limit(no_wire + no_wire_delta, max_mem);
	set_no_wire_limit(no_wire, max_mem);
	// Set the wire limit and ensure that the no_wire_limit has changed
	set_wire_limit(wire - no_wire_delta, max_mem);
	set_wire_limit(wire, max_mem);
}

T_DECL(set_user_wire_limit, "Set user_wire_limit", T_META_ASROOT(true)) {
	vm_map_size_t wire, original_wire;
	size_t wire_size = sizeof(wire);
	int ret;
	vm_map_size_t wire_delta = 48 * (1 << 10);
	ret = sysctlbyname(g_sysctl_per_task_wire_name, &original_wire, &wire_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "user_wire sysctl get failed");
	wire = original_wire + wire_delta;
	ret = sysctlbyname(g_sysctl_per_task_wire_name, NULL, 0, &wire, wire_size);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "user_wire sysctl set failed");
	ret = sysctlbyname(g_sysctl_per_task_wire_name, &wire, &wire_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "user_wire sysctl get failed");
	T_QUIET; T_ASSERT_EQ(wire, original_wire + wire_delta, "user_wire sysctl didn't set the correct value.");

	// Cleanup
	ret = sysctlbyname(g_sysctl_per_task_wire_name, NULL, 0, &original_wire, wire_size);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "user_wire sysctl set failed");
}

#if TARGET_OS_OSX
/*
 * Test that wiring up to the limit doesn't hang the system.
 * We only test this on OS X. On all other platforms, we'd expect
 * to get jetsamm'ed for doing this.
 */
static void *
wire_to_limit(size_t limit, size_t *size)
{
	// Trying to wire directly to the limit is likely to fail
	// repeatedly since other wired pages are probably coming and going
	// so we just try to get close.
	const unsigned int wiggle_room_pages = 1000;
	int ret;
	unsigned int current_wired, current_free;
	size_t buffer_size, offset_from_limit;
	void *buffer;
	size_t current_wired_size = sizeof(current_wired);
	size_t current_free_size = sizeof(current_free);
	while (true) {
		ret = sysctlbyname(g_sysctl_current_wired_count_name, &current_wired, &current_wired_size, NULL, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "get current wired count failed");
		ret = sysctlbyname(g_sysctl_current_free_count_name, &current_free, &current_free_size, NULL, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "get current free count failed");
		offset_from_limit = ptoa(current_wired + current_free + wiggle_room_pages);
		T_QUIET; T_ASSERT_GE(limit, offset_from_limit, "more pages are wired than the limit.");
		buffer_size = limit - offset_from_limit;
		buffer = malloc(buffer_size);
		T_QUIET; T_ASSERT_NOTNULL(buffer, "Unable to allocate buffer");
		ret = mlock(buffer, buffer_size);
		if (ret == 0) {
			break;
		}
		free(buffer);
	}
	*size = buffer_size;
	return buffer;
}

T_DECL(wire_stress_test, "wire up to global_user_wire_limit and spin for 120 seconds.") {
	static const int kNumSecondsToSpin = 120;
	int ret;
	struct timespec start, now;
	size_t buffer_size;
	size_t wire_limit;
	size_t wire_limit_size = sizeof(wire_limit);
	void *buffer;

	ret = sysctlbyname(g_sysctl_wire_name, &wire_limit, &wire_limit_size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "user_wire sysctl failed");
	buffer = wire_to_limit(wire_limit, &buffer_size);
	ret = clock_gettime(CLOCK_MONOTONIC, &start);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "Unable to get current time.");
	while (true) {
		ret = clock_gettime(CLOCK_MONOTONIC, &now);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "Unable to get current time.");
		if (now.tv_sec - start.tv_sec >= kNumSecondsToSpin) {
			break;
		}
	}
	ret = munlock(buffer, buffer_size);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "Unable to unlock memory.");
	free(buffer);
}
#endif /* TARGET_OS_OSX */
