//
// Tests for
//  bounded_ptr& operator=(std::nullptr_t);
//

#include <cstddef>
#include <libkern/c++/bounded_ptr.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

#define _assert(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

struct T { };

template <typename T, typename TQual>
static void
tests()
{
	T obj{};

	// Assign from nullptr
	{
		test_bounded_ptr<TQual> p(&obj, &obj, &obj + 1);
		_assert(p != nullptr);
		test_bounded_ptr<TQual>& ref = (p = nullptr);
		_assert(&ref == &p);
		_assert(p == nullptr);
	}

	// Assign from NULL
	{
		test_bounded_ptr<TQual> p(&obj, &obj, &obj + 1);
		_assert(p != nullptr);
		test_bounded_ptr<TQual>& ref = (p = NULL);
		_assert(&ref == &p);
		_assert(p == nullptr);
	}

	// Assign from 0
	{
		test_bounded_ptr<TQual> p(&obj, &obj, &obj + 1);
		_assert(p != nullptr);
		test_bounded_ptr<TQual>& ref = (p = 0);
		_assert(&ref == &p);
		_assert(p == nullptr);
	}
}

T_DECL(assign_nullptr, "bounded_ptr.assign.nullptr") {
	tests<T, T>();
	tests<T, T const>();
	tests<T, T volatile>();
	tests<T, T const volatile>();
}
