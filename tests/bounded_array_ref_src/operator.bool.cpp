//
// Tests for
//  explicit operator bool() const;
//

#include <libkern/c++/bounded_array_ref.h>
#include "test_policy.h"
#include <darwintest.h>
#include <darwintest_utils.h>

struct T { int i; };

template <typename T>
static void
tests()
{
	{
		test_bounded_array_ref<T> const view;
		if (view) {
			CHECK(false);
		}
		CHECK(!view);
	}
	{
		T array[5] = {};
		test_bounded_array_ref<T> const view(array);
		if (view) {
		} else {
			CHECK(false);
		}
		CHECK(!!view);
	}
}

T_DECL(operator_bool, "bounded_array_ref.operator.bool") {
	tests<T>();
	tests<T const>();
}
