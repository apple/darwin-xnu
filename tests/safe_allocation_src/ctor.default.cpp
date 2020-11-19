//
// Tests for
//  explicit safe_allocation();
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
	{
		test_safe_allocation<T> array;
		CHECK(array.data() == nullptr);
		CHECK(array.size() == 0);
		CHECK(array.begin() == array.end());
	}
	{
		test_safe_allocation<T> array{};
		CHECK(array.data() == nullptr);
		CHECK(array.size() == 0);
		CHECK(array.begin() == array.end());
	}
	{
		test_safe_allocation<T> array = test_safe_allocation<T>();
		CHECK(array.data() == nullptr);
		CHECK(array.size() == 0);
		CHECK(array.begin() == array.end());
	}
}

T_DECL(ctor_default, "safe_allocation.ctor.default") {
	tests<T>();
	tests<T const>();
}
