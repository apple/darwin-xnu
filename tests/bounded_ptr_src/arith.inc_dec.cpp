//
// Tests for
//  bounded_ptr& operator++();
//  bounded_ptr operator++(int);
//  bounded_ptr& operator--();
//  bounded_ptr operator--(int);
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

	{
		// Test pre-increment and pre-decrement
		test_bounded_ptr<QualT> ptr(array.begin(), array.begin(), array.end());
		_assert(&*ptr == &array[0]);

		{
			auto& ref = ++ptr;
			_assert(&ref == &ptr);
			_assert(&*ptr == &array[1]);
		}

		{
			auto& ref = ++ptr;
			_assert(&ref == &ptr);
			_assert(&*ptr == &array[2]);
		}
		{
			auto& ref = ++ptr;
			_assert(&ref == &ptr);
			_assert(&*ptr == &array[3]);
		}
		{
			auto& ref = ++ptr;
			_assert(&ref == &ptr);
			_assert(&*ptr == &array[4]);
		}
		{
			auto& ref = ++ptr;
			_assert(&ref == &ptr);
			// ptr is now one-past-last
		}
		{
			auto& ref = --ptr;
			_assert(&ref == &ptr);
			_assert(&*ptr == &array[4]);
		}
		{
			auto& ref = --ptr;
			_assert(&ref == &ptr);
			_assert(&*ptr == &array[3]);
		}
		{
			auto& ref = --ptr;
			_assert(&ref == &ptr);
			_assert(&*ptr == &array[2]);
		}
		{
			auto& ref = --ptr;
			_assert(&ref == &ptr);
			_assert(&*ptr == &array[1]);
		}
		{
			auto& ref = --ptr;
			_assert(&ref == &ptr);
			_assert(&*ptr == &array[0]);
		}
	}
	{
		// Test post-increment and post-decrement
		test_bounded_ptr<QualT> ptr(array.begin(), array.begin(), array.end());
		_assert(&*ptr == &array[0]);

		{
			auto prev = ptr++;
			_assert(&*prev == &array[0]);
			_assert(&*ptr == &array[1]);
		}
		{
			auto prev = ptr++;
			_assert(&*prev == &array[1]);
			_assert(&*ptr == &array[2]);
		}
		{
			auto prev = ptr++;
			_assert(&*prev == &array[2]);
			_assert(&*ptr == &array[3]);
		}
		{
			auto prev = ptr++;
			_assert(&*prev == &array[3]);
			_assert(&*ptr == &array[4]);
		}
		{
			auto prev = ptr++;
			_assert(&*prev == &array[4]);
			_assert(ptr == array.end());
		}
		{
			auto prev = ptr--;
			_assert(prev == array.end());
			_assert(&*ptr == &array[4]);
		}
		{
			auto prev = ptr--;
			_assert(&*prev == &array[4]);
			_assert(&*ptr == &array[3]);
		}
		{
			auto prev = ptr--;
			_assert(&*prev == &array[3]);
			_assert(&*ptr == &array[2]);
		}
		{
			auto prev = ptr--;
			_assert(&*prev == &array[2]);
			_assert(&*ptr == &array[1]);
		}
		{
			auto prev = ptr--;
			_assert(&*prev == &array[1]);
			_assert(&*ptr == &array[0]);
		}
	}
}

T_DECL(arith_inc_dec, "bounded_ptr.arith.inc_dec") {
	tests<T, T>();
	tests<T, T const>();
	tests<T, T volatile>();
	tests<T, T const volatile>();
}
