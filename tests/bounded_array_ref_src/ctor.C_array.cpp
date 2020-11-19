//
// Tests for
//  template <size_t N>
//  bounded_array_ref(T (&array)[N]);
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
		T array[5] = {T{0}, T{1}, T{2}, T{3}, T{4}};
		test_bounded_array_ref<T> view(array);
		CHECK(view.data() == &array[0]);
		CHECK(view.size() == 5);
		CHECK(view[0] == T{0});
		CHECK(view[1] == T{1});
		CHECK(view[2] == T{2});
		CHECK(view[3] == T{3});
		CHECK(view[4] == T{4});
	}

	{
		T array[1] = {T{11}};
		test_bounded_array_ref<T> view(array);
		CHECK(view.data() == &array[0]);
		CHECK(view.size() == 1);
		CHECK(view[0] == T{11});
	}

	// Also test implicit construction
	{
		T array[1] = {T{11}};
		test_bounded_array_ref<T> view = array;
		CHECK(view.data() == &array[0]);
		CHECK(view.size() == 1);
	}
	{
		T array[1] = {T{11}};
		auto check = [&array](test_bounded_array_ref<T> view) {
			    CHECK(view.data() == &array[0]);
			    CHECK(view.size() == 1);
		    };
		check(array);
	}
}

T_DECL(ctor_C_array, "bounded_array_ref.ctor.C_array") {
	tests<T>();
}
