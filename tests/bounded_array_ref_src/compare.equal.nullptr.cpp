//
// Tests for
//  template <typename T, typename P>
//  bool operator==(bounded_array_ref<T, P> const& x, std::nullptr_t);
//
//  template <typename T, typename P>
//  bool operator!=(bounded_array_ref<T, P> const& x, std::nullptr_t);
//
//  template <typename T, typename P>
//  bool operator==(std::nullptr_t, bounded_array_ref<T, P> const& x);
//
//  template <typename T, typename P>
//  bool operator!=(std::nullptr_t, bounded_array_ref<T, P> const& x);
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
		T array[5] = {T{0}, T{1}, T{2}, T{3}, T{4}};
		test_bounded_array_ref<T> view(array);
		CHECK(!(view == nullptr));
		CHECK(!(nullptr == view));
		CHECK(view != nullptr);
		CHECK(nullptr != view);
	}
	{
		test_bounded_array_ref<T> view;
		CHECK(view == nullptr);
		CHECK(nullptr == view);
		CHECK(!(view != nullptr));
		CHECK(!(nullptr != view));
	}
}

T_DECL(compare_equal_nullptr, "bounded_array_ref.compare.equal.nullptr") {
	tests<T>();
}
