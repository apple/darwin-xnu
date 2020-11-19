//
// Tests for
//  template <size_t N>
//  bounded_array_ref(bounded_array<T, N, TrappingPolicy>& data);
//

#include <libkern/c++/bounded_array_ref.h>
#include "test_policy.h"
#include <darwintest.h>
#include <darwintest_utils.h>

struct T { int i; };
inline bool
operator==(T const& a, T const& b)
{
	return a.i == b.i;
};

template <typename T>
static void
tests()
{
	{
		test_bounded_array<T, 5> array = {T{0}, T{1}, T{2}, T{3}, T{4}};
		test_bounded_array_ref<T> view(array);
		CHECK(view.data() == array.data());
		CHECK(view.size() == 5);
		CHECK(view[0] == T{0});
		CHECK(view[1] == T{1});
		CHECK(view[2] == T{2});
		CHECK(view[3] == T{3});
		CHECK(view[4] == T{4});
	}

	{
		test_bounded_array<T, 1> array = {T{11}};
		test_bounded_array_ref<T> view(array);
		CHECK(view.data() == array.data());
		CHECK(view.size() == 1);
		CHECK(view[0] == T{11});
	}

	{
		test_bounded_array<T, 0> array = {};
		test_bounded_array_ref<T> view(array);
		CHECK(view.data() == array.data());
		CHECK(view.size() == 0);
	}

	// Also test implicit construction
	{
		test_bounded_array<T, 1> array = {T{11}};
		test_bounded_array_ref<T> view = array;
		CHECK(view.data() == array.data());
		CHECK(view.size() == 1);
	}
	{
		test_bounded_array<T, 1> array = {T{11}};
		auto check = [&array](test_bounded_array_ref<T> view) {
			    CHECK(view.data() == array.data());
			    CHECK(view.size() == 1);
		    };
		check(array);
	}
}

T_DECL(ctor_bounded_array, "bounded_array_ref.ctor.bounded_array") {
	tests<T>();
}
