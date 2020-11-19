//
// Tests for
//  aggregate-initialization of `bounded_array`
//

#include <libkern/c++/bounded_array.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_policy.h"

struct T {
	T() : i(4)
	{
	}
	T(int k) : i(k)
	{
	}
	int i;
	friend bool
	operator==(T const& a, T const& b)
	{
		return a.i == b.i;
	}
};

template <typename T>
static void
tests()
{
	{
		test_bounded_array<T, 5> array = {T(1), T(2), T(3), T(4), T(5)};
		CHECK(array.size() == 5);
		CHECK(array[0] == T(1));
		CHECK(array[1] == T(2));
		CHECK(array[2] == T(3));
		CHECK(array[3] == T(4));
		CHECK(array[4] == T(5));
	}

	{
		test_bounded_array<T, 5> array{T(1), T(2), T(3), T(4), T(5)};
		CHECK(array.size() == 5);
		CHECK(array[0] == T(1));
		CHECK(array[1] == T(2));
		CHECK(array[2] == T(3));
		CHECK(array[3] == T(4));
		CHECK(array[4] == T(5));
	}

	// Check with a 0-sized array
	{
		test_bounded_array<T, 0> array = {};
		CHECK(array.size() == 0);
	}
}

T_DECL(ctor_aggregate_init, "bounded_array.ctor.aggregate_init") {
	tests<T>();
}
