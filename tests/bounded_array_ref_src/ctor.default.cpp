//
// Tests for
//  bounded_array_ref();
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
		test_bounded_array_ref<T> view;
		CHECK(view.data() == nullptr);
		CHECK(view.size() == 0);
	}
	{
		test_bounded_array_ref<T> view{};
		CHECK(view.data() == nullptr);
		CHECK(view.size() == 0);
	}
	{
		test_bounded_array_ref<T> view = test_bounded_array_ref<T>();
		CHECK(view.data() == nullptr);
		CHECK(view.size() == 0);
	}
}

T_DECL(ctor_default, "bounded_array_ref.ctor.default") {
	tests<T>();
	tests<T const>();
}
