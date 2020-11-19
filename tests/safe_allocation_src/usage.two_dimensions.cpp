//
// Make sure `safe_allocation` can be used to create a two-dimensional array.
//
// Note that we don't really recommend using that representation for two
// dimensional arrays because other representations are better, but it
// should at least work.
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
	test_safe_allocation<test_safe_allocation<int> > array(10, libkern::allocate_memory);

	for (int i = 0; i < 10; i++) {
		array[i] = test_safe_allocation<int>(10, libkern::allocate_memory);
		for (int j = 0; j < 10; ++j) {
			array[i][j] = i + j;
		}
	}

	for (int i = 0; i < 10; i++) {
		for (int j = 0; j < 10; ++j) {
			CHECK(array[i][j] == i + j);
		}
	}
}

T_DECL(usage_two_dimensions, "safe_allocation.usage.two_dimensions") {
	tests<T>();
}
