//
// Tests for
//  friend bounded_ptr operator-(bounded_ptr p, std::ptrdiff_t n);
//

#include <libkern/c++/bounded_ptr.h>
#include "test_utils.h"
#include <array>
#include <cstddef>
#include <darwintest.h>
#include <darwintest_utils.h>

#define _assert(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

struct T {
	int i;
};

template <typename T, typename QualT>
static void
tests()
{
	std::array<T, 5> array = {T{0}, T{1}, T{2}, T{3}, T{4}};

	// Subtract positive offsets
	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//   ^                                                ^
	//   |                                                |
	// begin                                           end,ptr
	{
		test_bounded_ptr<QualT> const ptr(array.end(), array.begin(), array.end());

		{
			test_bounded_ptr<QualT> res = ptr - static_cast<std::ptrdiff_t>(0);
			_assert(ptr == array.end());
		}
		{
			test_bounded_ptr<QualT> res = ptr - 1;
			_assert(&*res == &array[4]);
		}
		{
			test_bounded_ptr<QualT> res = ptr - 2;
			_assert(&*res == &array[3]);
		}
		{
			test_bounded_ptr<QualT> res = ptr - 3;
			_assert(&*res == &array[2]);
		}
		{
			test_bounded_ptr<QualT> res = ptr - 4;
			_assert(&*res == &array[1]);
		}
		{
			test_bounded_ptr<QualT> res = ptr - 5;
			_assert(&*res == &array[0]);
		}
	}

	// Subtract negative offsets
	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//   ^                                                ^
	//   |                                                |
	// begin,ptr                                         end
	{
		test_bounded_ptr<QualT> const ptr(array.begin(), array.begin(), array.end());

		{
			test_bounded_ptr<QualT> res = ptr - static_cast<std::ptrdiff_t>(0);
			_assert(&*res == &array[0]);
		}
		{
			test_bounded_ptr<QualT> res = ptr - -1;
			_assert(&*res == &array[1]);
		}
		{
			test_bounded_ptr<QualT> res = ptr - -2;
			_assert(&*res == &array[2]);
		}
		{
			test_bounded_ptr<QualT> res = ptr - -3;
			_assert(&*res == &array[3]);
		}
		{
			test_bounded_ptr<QualT> res = ptr - -4;
			_assert(&*res == &array[4]);
		}
		{
			test_bounded_ptr<QualT> res = ptr - -5;
			_assert(res == array.end());
		}
	}

	// Make sure the original pointer isn't modified
	{
		test_bounded_ptr<QualT> const ptr(array.begin() + 4, array.begin(), array.end());
		(void)(ptr - 2);
		_assert(&*ptr == &array[4]);
	}
}

T_DECL(arith_subtract, "bounded_ptr.arith.subtract") {
	tests<T, T>();
	tests<T, T const>();
	tests<T, T volatile>();
	tests<T, T const volatile>();
}
