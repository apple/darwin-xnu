//
// Tests for
//  bounded_array();
//

#include <libkern/c++/bounded_array.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_policy.h"

struct T {
	T() : i(4)
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
		test_bounded_array<T, 10> array;
		CHECK(array.size() == 10);
		T* end = array.data() + array.size();
		for (auto it = array.data(); it != end; ++it) {
			CHECK(*it == T());
		}
	}
	{
		test_bounded_array<T, 10> array{};
		CHECK(array.size() == 10);
		T* end = array.data() + array.size();
		for (auto it = array.data(); it != end; ++it) {
			CHECK(*it == T());
		}
	}
	{
		test_bounded_array<T, 10> array = {};
		CHECK(array.size() == 10);
		T* end = array.data() + array.size();
		for (auto it = array.data(); it != end; ++it) {
			CHECK(*it == T());
		}
	}
	{
		test_bounded_array<T, 10> array = test_bounded_array<T, 10>();
		CHECK(array.size() == 10);
		T* end = array.data() + array.size();
		for (auto it = array.data(); it != end; ++it) {
			CHECK(*it == T());
		}
	}

	// Check with a 0-sized array
	{
		test_bounded_array<T, 0> array;
		CHECK(array.size() == 0);
	}
}

T_DECL(ctor_default, "bounded_array.ctor.default") {
	tests<T>();
}
