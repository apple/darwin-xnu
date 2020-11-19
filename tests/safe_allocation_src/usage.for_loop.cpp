//
// Make sure `safe_allocation` works nicely with the range-based for-loop.
//

#include <libkern/c++/safe_allocation.h>
#include <darwintest.h>
#include "test_utils.h"

struct T {
	int i;
};

template <typename T>
static void
tests()
{
	test_safe_allocation<T> array(10, libkern::allocate_memory);
	for (T& element : array) {
		element = T{3};
	}

	for (T const& element : array) {
		CHECK(element.i == 3);
	}
}

T_DECL(usage_for_loop, "safe_allocation.usage.for_loop") {
	tests<T>();
}
