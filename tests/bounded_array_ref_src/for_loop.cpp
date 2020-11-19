//
// Make sure `bounded_array_ref` works nicely with the range-based for-loop.
//

#include <libkern/c++/bounded_array_ref.h>
#include <darwintest.h>
#include "test_policy.h"

struct T {
	int i;
};

template <typename T>
static void
tests()
{
	T array[5] = {T{0}, T{1}, T{2}, T{3}, T{4}};
	test_bounded_array_ref<T> view(array);
	for (T& element : view) {
		element = T{3};
	}

	for (T const& element : view) {
		CHECK(element.i == 3);
	}
}

T_DECL(for_loop, "bounded_array_ref.for_loop") {
	tests<T>();
}
