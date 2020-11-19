//
// Tests for
//  explicit bounded_array_ref(T* first, T* last);
//

#include <libkern/c++/bounded_array_ref.h>
#include "test_policy.h"
#include <darwintest.h>
#include <darwintest_utils.h>

struct T { int i; };
inline bool
operator==(T const& a, T const& b)
{
	return a.i == b.i;
};

template <typename T>
static void
tests()
{
	T array[5] = {T{0}, T{1}, T{2}, T{3}, T{4}};

	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//   ^                                                ^
	//   |                                                |
	// first                                             last
	{
		T* first = &array[0];
		T* last = &array[5];
		test_bounded_array_ref<T> view(first, last);
		CHECK(view.data() == &array[0]);
		CHECK(view.size() == 5);
		CHECK(view[0] == T{0});
		CHECK(view[1] == T{1});
		CHECK(view[2] == T{2});
		CHECK(view[3] == T{3});
		CHECK(view[4] == T{4});
	}

	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//   ^        ^
	//   |        |
	// first     last
	{
		T* first = &array[0];
		T* last = &array[1];
		test_bounded_array_ref<T> view(first, last);
		CHECK(view.data() == &array[0]);
		CHECK(view.size() == 1);
		CHECK(view[0] == T{0});
	}

	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//   ^
	//   |
	// first,last
	{
		T* first = &array[0];
		T* last = &array[0];
		test_bounded_array_ref<T> view(first, last);
		CHECK(view.size() == 0);
	}

	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//                                                    ^
	//                                                    |
	//                                               first,last
	{
		T* first = &array[5];
		T* last = &array[5];
		test_bounded_array_ref<T> view(first, last);
		CHECK(view.size() == 0);
	}
}

T_DECL(ctor_begin_end, "bounded_array_ref.ctor.begin_end") {
	tests<T>();
	tests<T const>();
}
