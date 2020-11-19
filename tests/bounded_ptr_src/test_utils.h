#ifndef TESTS_BOUNDED_PTR_TEST_UTILS_H
#define TESTS_BOUNDED_PTR_TEST_UTILS_H

#include <cassert>
#include <libkern/c++/bounded_ptr.h>

namespace {
struct test_policy {
	static void
	trap(char const*)
	{
		assert(false);
	}
};

template <typename T>
using test_bounded_ptr = libkern::bounded_ptr<T, test_policy>;
} // end anonymous namespace

#endif // !TESTS_BOUNDED_PTR_TEST_UTILS_H
