//
// Tests for
//  bounded_ptr(std::nullptr_t);
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
	// Test with nullptr
	{
		test_bounded_ptr<T> p = nullptr;
		_assert(p == nullptr);
	}
	{
		test_bounded_ptr<T> p{nullptr};
		_assert(p == nullptr);
	}
	{
		test_bounded_ptr<T> p(nullptr);
		_assert(p == nullptr);
	}
	{
		test_bounded_ptr<T> p = static_cast<test_bounded_ptr<T> >(nullptr);
		_assert(p == nullptr);
	}
	{
		auto f = [](test_bounded_ptr<T> p) {
			    _assert(p == nullptr);
		    };
		f(nullptr);
	}

	// Test with NULL
	{
		test_bounded_ptr<T> p = NULL;
		_assert(p == nullptr);
	}
	{
		test_bounded_ptr<T> p{NULL};
		_assert(p == nullptr);
	}
	{
		test_bounded_ptr<T> p(NULL);
		_assert(p == nullptr);
	}
	{
		test_bounded_ptr<T> p = static_cast<test_bounded_ptr<T> >(NULL);
		_assert(p == nullptr);
	}
	{
		auto f = [](test_bounded_ptr<T> p) {
			    _assert(p == nullptr);
		    };
		f(NULL);
	}

	// Test with 0
	{
		test_bounded_ptr<T> p = 0;
		_assert(p == nullptr);
	}
	{
		test_bounded_ptr<T> p{0};
		_assert(p == nullptr);
	}
	{
		test_bounded_ptr<T> p(0);
		_assert(p == nullptr);
	}
	{
		test_bounded_ptr<T> p = static_cast<test_bounded_ptr<T> >(0);
		_assert(p == nullptr);
	}
	{
		auto f = [](test_bounded_ptr<T> p) {
			    _assert(p == nullptr);
		    };
		f(0);
	}
}

T_DECL(ctor_nullptr, "bounded_ptr.ctor.nullptr") {
	tests<T>();
	tests<T const>();
	tests<T volatile>();
	tests<T const volatile>();
}
