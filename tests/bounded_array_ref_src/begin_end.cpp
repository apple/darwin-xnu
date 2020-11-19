//
// Tests for
//  iterator begin() const;
//  iterator end() const;
//

#include <libkern/c++/bounded_array_ref.h>
#include "test_policy.h"
#include <darwintest.h>
#include <type_traits>

struct T { int i; };

template <typename T>
static void
tests()
{
	using AR = test_bounded_array_ref<T>;

	// Check begin()/end() for a non-null array ref
	{
		T array[5] = {T{0}, T{1}, T{2}, T{3}, T{4}};
		AR const view(array);
		test_bounded_ptr<T> begin = view.begin();
		test_bounded_ptr<T> end = view.end();
		CHECK(begin.discard_bounds() == &array[0]);
		CHECK(end.unsafe_discard_bounds() == &array[5]);
	}

	// Check begin()/end() for a null array ref
	{
		AR const view;
		test_bounded_ptr<T> begin = view.begin();
		test_bounded_ptr<T> end = view.end();
		CHECK(begin.unsafe_discard_bounds() == nullptr);
		CHECK(end.unsafe_discard_bounds() == nullptr);
	}

	// Check associated types
	{
		static_assert(std::is_same_v<typename AR::iterator, test_bounded_ptr<T> >);
	}
}

T_DECL(begin_end, "bounded_array_ref.begin_end") {
	tests<T>();
}
