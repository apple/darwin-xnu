//
// Tests for
//  iterator begin();
//  const_iterator begin() const;
//
//  iterator end();
//  const_iterator end() const;
//

#include <libkern/c++/bounded_array.h>
#include "test_policy.h"
#include <darwintest.h>
#include <type_traits>

struct T { int i; };

template <typename T>
static void
tests()
{
	// Check begin()/end() for a non-empty array
	{
		test_bounded_array<T, 5> array = {T{0}, T{1}, T{2}, T{3}, T{4}};
		test_bounded_ptr<T> begin = array.begin();
		test_bounded_ptr<T> end = array.end();
		CHECK(begin.discard_bounds() == array.data());
		CHECK(end.unsafe_discard_bounds() == array.data() + 5);
	}
	{
		test_bounded_array<T, 5> const array = {T{0}, T{1}, T{2}, T{3}, T{4}};
		test_bounded_ptr<T const> begin = array.begin();
		test_bounded_ptr<T const> end = array.end();
		CHECK(begin.discard_bounds() == array.data());
		CHECK(end.unsafe_discard_bounds() == array.data() + 5);
	}

	// Check begin()/end() for an empty array
	{
		test_bounded_array<T, 0> array = {};
		test_bounded_ptr<T> begin = array.begin();
		test_bounded_ptr<T> end = array.end();
		CHECK(begin.unsafe_discard_bounds() == array.data());
		CHECK(end.unsafe_discard_bounds() == array.data());
	}
	{
		test_bounded_array<T, 0> const array = {};
		test_bounded_ptr<T const> begin = array.begin();
		test_bounded_ptr<T const> end = array.end();
		CHECK(begin.unsafe_discard_bounds() == array.data());
		CHECK(end.unsafe_discard_bounds() == array.data());
	}

	// Check associated types
	{
		using A = test_bounded_array<T, 10>;
		static_assert(std::is_same_v<typename A::iterator, test_bounded_ptr<T> >);
		static_assert(std::is_same_v<typename A::const_iterator, test_bounded_ptr<T const> >);
	}
}

T_DECL(begin_end, "bounded_array.begin_end") {
	tests<T>();
}
