//
// Tests for
//  T* data() const;
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
		T* data = view.data();
		CHECK(data == &array[0]);
	}
	{
		test_bounded_array_ref<T> const view(&array[0], 1);
		T* data = view.data();
		CHECK(data == &array[0]);
	}

	{
		test_bounded_array_ref<T> const view(&array[1], 2);
		T* data = view.data();
		CHECK(data == &array[1]);
	}
	{
		test_bounded_array_ref<T> const view(&array[2], 2);
		T* data = view.data();
		CHECK(data == &array[2]);
	}
}

T_DECL(data, "bounded_array_ref.data") {
	tests<T>();
	tests<T const>();
}
