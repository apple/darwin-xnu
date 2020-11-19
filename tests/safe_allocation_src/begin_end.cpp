//
// Tests for
//  iterator begin();
//  const_iterator begin() const;
//
//  iterator end();
//  const_iterator end() const;
//

#include <libkern/c++/safe_allocation.h>
#include <darwintest.h>
#include "test_utils.h"
#include <type_traits>

struct T {
	int i;
};

template <typename T>
static void
tests()
{
	using A = test_safe_allocation<T>;

	// Check begin()/end() for a non-null allocation
	{
		A array(10, libkern::allocate_memory);
		T* data = array.data();
		test_bounded_ptr<T> begin = array.begin();
		test_bounded_ptr<T> end = array.end();
		CHECK(begin.discard_bounds() == data);
		CHECK(end.unsafe_discard_bounds() == data + 10);
	}
	{
		A const array(10, libkern::allocate_memory);
		T const* data = array.data();
		test_bounded_ptr<T const> begin = array.begin();
		test_bounded_ptr<T const> end = array.end();
		CHECK(begin.discard_bounds() == data);
		CHECK(end.unsafe_discard_bounds() == data + 10);
	}

	// Check begin()/end() for a null allocation
	{
		A array = nullptr;
		test_bounded_ptr<T> begin = array.begin();
		test_bounded_ptr<T> end = array.end();
		CHECK(begin.unsafe_discard_bounds() == nullptr);
		CHECK(end.unsafe_discard_bounds() == nullptr);
		CHECK(begin == end);
	}
	{
		A const array = nullptr;
		test_bounded_ptr<T const> begin = array.begin();
		test_bounded_ptr<T const> end = array.end();
		CHECK(begin.unsafe_discard_bounds() == nullptr);
		CHECK(end.unsafe_discard_bounds() == nullptr);
		CHECK(begin == end);
	}

	// Check associated types
	{
		static_assert(std::is_same_v<typename A::iterator, test_bounded_ptr<T> >);
		static_assert(std::is_same_v<typename A::const_iterator, test_bounded_ptr<T const> >);
	}
}

T_DECL(begin_end, "safe_allocation.begin_end") {
	tests<T>();
	tests<T const>();
}
