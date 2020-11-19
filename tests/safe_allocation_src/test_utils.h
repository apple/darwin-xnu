#ifndef TESTS_SAFE_ALLOCATION_TEST_UTILS_H
#define TESTS_SAFE_ALLOCATION_TEST_UTILS_H

#include <libkern/c++/bounded_ptr.h>
#include <libkern/c++/safe_allocation.h>
#include <darwintest_utils.h>
#include <cassert>
#include <cstddef>
#include <cstdlib>

namespace {
struct assert_trapping_policy {
	static void
	trap(char const*)
	{
		assert(false);
	}
};

struct malloc_allocator {
	static void*
	allocate(size_t n)
	{
		return std::malloc(n);
	}

	static void
	deallocate(void* p, size_t n)
	{
		std::free(p);
	}
};

struct tracking_allocator {
	static void
	reset()
	{
		allocated_size = 0;
		deallocated_size = 0;
		did_allocate = false;
		did_deallocate = false;
	}
	static std::size_t allocated_size;
	static std::size_t deallocated_size;
	static bool did_allocate;
	static bool did_deallocate;

	static void*
	allocate(std::size_t n)
	{
		did_allocate = true;
		allocated_size = n;
		return std::malloc(n);
	}

	static void
	deallocate(void* p, std::size_t n)
	{
		did_deallocate = true;
		deallocated_size = n;
		std::free(p);
	}
};

std::size_t tracking_allocator::allocated_size = 0;
std::size_t tracking_allocator::deallocated_size = 0;
bool tracking_allocator::did_allocate = false;
bool tracking_allocator::did_deallocate = false;

struct tracking_trapping_policy {
	static void
	reset()
	{
		did_trap = false;
	}
	static bool did_trap;
	static void
	trap(char const*)
	{
		did_trap = true;
	}
};
bool tracking_trapping_policy::did_trap = false;

template <typename T>
using test_safe_allocation = libkern::safe_allocation<T, malloc_allocator, assert_trapping_policy>;

template <typename T>
using tracked_safe_allocation = libkern::safe_allocation<T, tracking_allocator, assert_trapping_policy>;

template <typename T>
using test_bounded_ptr = libkern::bounded_ptr<T, assert_trapping_policy>;
} // end anonymous namespace

#define CHECK(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

#endif // !TESTS_SAFE_ALLOCATION_TEST_UTILS_H
