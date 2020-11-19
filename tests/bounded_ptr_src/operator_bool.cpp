//
// Tests for
//  explicit operator bool() const;
//

#include <libkern/c++/bounded_ptr.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

#define _assert(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

struct T { };

template <typename T>
static void
tests()
{
	{
		test_bounded_ptr<T> p = nullptr;
		if (p) {
			_assert(false);
		}
		_assert(!p);
	}
	{
		T t;
		test_bounded_ptr<T> p(&t, &t, &t + 1);
		if (p) {
		} else {
			_assert(false);
		}
		_assert(!!p);
	}
}

T_DECL(operator_bool, "bounded_ptr.operator.bool") {
	tests<T>();
	tests<T const>();
	tests<T volatile>();
	tests<T const volatile>();
}
