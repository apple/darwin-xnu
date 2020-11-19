//
// Make sure `bounded_array` works nicely with the range-based for-loop.
//

#include <libkern/c++/bounded_array.h>
#include <darwintest.h>
#include "test_policy.h"

struct T {
	int i;
};

template <typename T>
static void
tests()
{
	test_bounded_array<T, 5> array = {T{0}, T{1}, T{2}, T{3}, T{4}};
	for (T& element : array) {
		element = T{3};
	}

	for (T const& element : array) {
		CHECK(element.i == 3);
	}
}

T_DECL(for_loop, "bounded_array.for_loop") {
	tests<T>();
}
