//
// Tests for
//  friend bounded_ptr operator+(bounded_ptr p, std::ptrdiff_t n);
//  friend bounded_ptr operator+(std::ptrdiff_t n, bounded_ptr p);
//
// The heavy lifting is done in operator+=, so we only check basic functioning.
//

#include <libkern/c++/bounded_ptr.h>
#include <array>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

#define _assert(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

struct T {
	int i;
};

template <typename T, typename QualT>
static void
tests()
{
	std::array<T, 5> array = {T{0}, T{1}, T{2}, T{3}, T{4}};

	// Add positive offsets
	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//   ^                                                ^
	//   |                                                |
	// begin, ptr                                        end
	{
		test_bounded_ptr<QualT> const ptr(array.begin(), array.begin(), array.end());

		{
			test_bounded_ptr<QualT> res = ptr + 0;
			_assert(&*res == &array[0]);
		}
		{
			test_bounded_ptr<QualT> res = ptr + 1;
			_assert(&*res == &array[1]);
		}
		{
			test_bounded_ptr<QualT> res = ptr + 2;
			_assert(&*res == &array[2]);
		}
		{
			test_bounded_ptr<QualT> res = ptr + 3;
			_assert(&*res == &array[3]);
		}
		{
			test_bounded_ptr<QualT> res = ptr + 4;
			_assert(&*res == &array[4]);
		}
		{
			test_bounded_ptr<QualT> res = ptr + 5;
			_assert(res == array.end());
		}
	}

	// Add negative offsets
	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//   ^                                                ^
	//   |                                                |
	// begin                                           end,ptr
	{
		test_bounded_ptr<QualT> const ptr(array.end(), array.begin(), array.end());

		{
			test_bounded_ptr<QualT> res = ptr + 0;
			_assert(res == array.end());
		}
		{
			test_bounded_ptr<QualT> res = ptr + -1;
			_assert(&*res == &array[4]);
		}
		{
			test_bounded_ptr<QualT> res = ptr + -2;
			_assert(&*res == &array[3]);
		}
		{
			test_bounded_ptr<QualT> res = ptr + -3;
			_assert(&*res == &array[2]);
		}
		{
			test_bounded_ptr<QualT> res = ptr + -4;
			_assert(&*res == &array[1]);
		}
		{
			test_bounded_ptr<QualT> res = ptr + -5;
			_assert(&*res == &array[0]);
		}
	}

	// Make sure the original pointer isn't modified
	{
		test_bounded_ptr<QualT> const ptr(array.begin() + 1, array.begin(), array.end());
		(void)(ptr + 3);
		_assert(&*ptr == &array[1]);
	}

	// Make sure the operator is commutative
	{
		{
			test_bounded_ptr<QualT> const ptr(array.begin(), array.begin(), array.end());
			test_bounded_ptr<QualT> res = 0 + ptr;
			_assert(&*res == &array[0]);
		}
		{
			test_bounded_ptr<QualT> const ptr(array.begin(), array.begin(), array.end());
			test_bounded_ptr<QualT> res = 3 + ptr;
			_assert(&*res == &array[3]);
		}
		{
			test_bounded_ptr<QualT> const ptr(array.begin() + 3, array.begin(), array.end());
			test_bounded_ptr<QualT> res = -2 + ptr;
			_assert(&*res == &array[1]);
		}
	}
}

T_DECL(arith_add, "bounded_ptr.arith.add") {
	tests<T, T>();
	tests<T, T const>();
	tests<T, T volatile>();
	tests<T, T const volatile>();
}
