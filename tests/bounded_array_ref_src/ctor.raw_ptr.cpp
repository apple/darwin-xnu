//
// Tests for
//  explicit bounded_array_ref(T* data, size_t n);
//

#include <libkern/c++/bounded_array_ref.h>
#include "test_policy.h"
#include <cstddef>
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
	//   ^
	//   |
	//  ptr
	//
	//   ^------------------- view -----------------------^
	{
		T* ptr = &array[0];
		test_bounded_array_ref<T> view(ptr, 5);
		CHECK(view.data() == &array[0]);
		CHECK(view.size() == 5);
		CHECK(view[0] == T{0});
		CHECK(view[1] == T{1});
		CHECK(view[2] == T{2});
		CHECK(view[3] == T{3});
		CHECK(view[4] == T{4});
	}
	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//   ^
	//   |
	//  ptr
	//
	//   ^----- view -----^
	{
		T* ptr = &array[0];
		test_bounded_array_ref<T> view(ptr, 3);
		CHECK(view.data() == &array[0]);
		CHECK(view.size() == 3);
		CHECK(view[0] == T{0});
		CHECK(view[1] == T{1});
		CHECK(view[2] == T{2});
	}
	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//                              ^
	//                              |
	//                             ptr
	//
	//                              ^------- view --------^
	{
		T* ptr = &array[3];
		test_bounded_array_ref<T> view(ptr, 2);
		CHECK(view.data() == &array[3]);
		CHECK(view.size() == 2);
		CHECK(view[0] == T{3});
		CHECK(view[1] == T{4});
	}
	// Check with a valid pointer and a size of 0.
	{
		T* ptr = &array[0];
		test_bounded_array_ref<T> view(ptr, static_cast<std::size_t>(0));
		CHECK(view.size() == 0);
	}
	// Check with a null pointer and a size of 0.
	{
		T* ptr = nullptr;
		test_bounded_array_ref<T> view(ptr, static_cast<std::size_t>(0));
		CHECK(view.size() == 0);
	}
	// Check with a non-null but invalid pointer and a size of 0.
	{
		T* ptr = &array[5];
		test_bounded_array_ref<T> view(ptr, static_cast<std::size_t>(0));
		CHECK(view.size() == 0);
	}
	// Make sure there's no ambiguity between constructors.
	{
		T* ptr = &array[0];
		std::ptrdiff_t size = 5;
		test_bounded_array_ref<T> view(ptr, size);
		CHECK(view.data() == &array[0]);
		CHECK(view.size() == 5);
	}

	// Make sure we can create nested bounded_array_refs
	{
		int array1[] = {1, 2, 3, 4, 5};
		int array2[] = {6, 7, 8};
		int array3[] = {9, 10, 11, 12, 13, 14};
		test_bounded_array_ref<int> views[] = {
			test_bounded_array_ref<int>(array1, 5),
			test_bounded_array_ref<int>(array2, 3),
			test_bounded_array_ref<int>(array3, 6)
		};

		test_bounded_array_ref<test_bounded_array_ref<int> > two_dim(views, 3);
		CHECK(two_dim.size() == 3);
		CHECK(two_dim.data() == &views[0]);
		CHECK(&two_dim[0] == &views[0]);
		CHECK(&two_dim[1] == &views[1]);
		CHECK(&two_dim[2] == &views[2]);
	}
}

T_DECL(ctor_raw_ptr, "bounded_array_ref.ctor.raw_ptr") {
	tests<T>();
	tests<T const>();
}
