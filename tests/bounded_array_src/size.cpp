//
// Tests for
//  size_t size() const;
//

#include <libkern/c++/bounded_array.h>
#include "test_policy.h"
#include <darwintest.h>
#include <stddef.h>

struct T { int i; };

template <typename T>
static void
tests()
{
	{
		test_bounded_array<T, 5> const array = {T{0}, T{1}, T{2}, T{3}, T{4}};
		size_t size = array.size();
		CHECK(size == 5);
	}
	{
		test_bounded_array<T, 0> const array = {};
		size_t size = array.size();
		CHECK(size == 0);
	}
}

T_DECL(size, "bounded_array.size") {
	tests<T>();
}
