#ifndef TESTS_BOUNDED_ARRAY_SRC_TEST_POLICY_H
#define TESTS_BOUNDED_ARRAY_SRC_TEST_POLICY_H

#include <assert.h>
#include <darwintest_utils.h>
#include <libkern/c++/bounded_array.h>
#include <libkern/c++/bounded_ptr.h>
#include <stddef.h>

struct test_policy {
	static void
	trap(char const*)
	{
		assert(false);
	}
};

template <typename T, size_t N>
using test_bounded_array = libkern::bounded_array<T, N, test_policy>;

template <typename T>
using test_bounded_ptr = libkern::bounded_ptr<T, test_policy>;

#define CHECK(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

#endif // !TESTS_BOUNDED_ARRAY_SRC_TEST_POLICY_H
