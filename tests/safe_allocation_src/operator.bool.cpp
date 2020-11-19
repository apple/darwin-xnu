//
// Tests for
//      explicit operator bool() const;
//

#include <libkern/c++/safe_allocation.h>
#include <darwintest.h>
#include "test_utils.h"
#include <type_traits>

struct T {
	int i;
};

template <typename T>
static void
tests()
{
	{
		test_safe_allocation<T> const array(10, libkern::allocate_memory);
		CHECK(static_cast<bool>(array));
		if (array) {
		} else {
			CHECK(FALSE);
		}
	}
	{
		test_safe_allocation<T> const array = nullptr;
		CHECK(!static_cast<bool>(array));
		if (!array) {
		} else {
			CHECK(FALSE);
		}
	}

	static_assert(!std::is_convertible_v<test_safe_allocation<T>, bool>);
}

T_DECL(operator_bool, "safe_allocation.operator.bool") {
	tests<T>();
	tests<T const>();
}
