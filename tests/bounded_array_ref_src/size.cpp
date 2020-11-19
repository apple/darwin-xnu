//
// Tests for
//  size_t size() const;
//

#include <libkern/c++/bounded_array_ref.h>
#include "test_policy.h"
#include <cstddef>
#include <darwintest.h>
#include <darwintest_utils.h>

struct T { int i; };

template <typename T>
static void
tests()
{
	T array[5] = {T{0}, T{1}, T{2}, T{3}, T{4}};

	{
		test_bounded_array_ref<T> const view(&array[0], static_cast<std::size_t>(0));
		std::size_t size = view.size();
		CHECK(size == 0);
	}
	{
		test_bounded_array_ref<T> const view(&array[0], 1);
		std::size_t size = view.size();
		CHECK(size == 1);
	}
	{
		test_bounded_array_ref<T> const view(&array[0], 2);
		std::size_t size = view.size();
		CHECK(size == 2);
	}
	{
		test_bounded_array_ref<T> const view(&array[0], 5);
		std::size_t size = view.size();
		CHECK(size == 5);
	}
}

T_DECL(size, "bounded_array_ref.size") {
	tests<T>();
	tests<T const>();
}
