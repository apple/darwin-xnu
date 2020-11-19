//
// Tests for
//  T& operator[](ptrdiff_t n);
//  T const& operator[](ptrdiff_t n) const;
//

#include <libkern/c++/bounded_array.h>
#include "test_policy.h"
#include <darwintest.h>
#include <type_traits>

struct T { int i; };
inline bool
operator==(T const& a, T const& b)
{
	return a.i == b.i;
}

template <typename T>
static void
tests()
{
	{
		test_bounded_array<T, 5> array = {T{0}, T{1}, T{2}, T{3}, T{4}};
		T& a0 = array[0];
		CHECK(&a0 == array.data());
		CHECK(a0 == T{0});
		T& a1 = array[1];
		CHECK(a1 == T{1});
		T& a2 = array[2];
		CHECK(a2 == T{2});
		T& a3 = array[3];
		CHECK(a3 == T{3});
		T& a4 = array[4];
		CHECK(a4 == T{4});
	}

	{
		test_bounded_array<T, 5> const array = {T{0}, T{1}, T{2}, T{3}, T{4}};
		T const& a0 = array[0];
		CHECK(&a0 == array.data());
		CHECK(a0 == T{0});
		T const& a1 = array[1];
		CHECK(a1 == T{1});
		T const& a2 = array[2];
		CHECK(a2 == T{2});
		T const& a3 = array[3];
		CHECK(a3 == T{3});
		T const& a4 = array[4];
		CHECK(a4 == T{4});
	}
}

T_DECL(operator_subscript, "bounded_array.operator.subscript") {
	tests<T>();
}
