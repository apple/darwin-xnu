#ifndef TESTS_BOUNDED_ARRAY_REF_SRC_TEST_POLICY_H
#define TESTS_BOUNDED_ARRAY_REF_SRC_TEST_POLICY_H

#include <assert.h>
#include <darwintest_utils.h>
#include <libkern/c++/bounded_array.h>
#include <libkern/c++/bounded_array_ref.h>
#include <libkern/c++/bounded_ptr.h>
#include <stddef.h>
#include <string>

namespace {
struct test_policy {
	static void
	trap(char const*)
	{
		assert(false);
	}
};

struct tracking_policy {
	static bool did_trap;
	static std::string message;
	static void
	trap(char const* m)
	{
		did_trap = true;
		message.assign(m);
	}
	static void
	reset()
	{
		did_trap = false;
		message = "";
	}
};
bool tracking_policy::did_trap = false;
std::string tracking_policy::message = "";
}

template <typename T>
using test_bounded_array_ref = libkern::bounded_array_ref<T, test_policy>;

template <typename T, size_t N>
using test_bounded_array = libkern::bounded_array<T, N, test_policy>;

template <typename T>
using test_bounded_ptr = libkern::bounded_ptr<T, test_policy>;

#define CHECK(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

#endif // !TESTS_BOUNDED_ARRAY_REF_SRC_TEST_POLICY_H
