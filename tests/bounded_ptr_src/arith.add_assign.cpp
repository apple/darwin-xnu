//
// Tests for
//  bounded_ptr& operator+=(std::ptrdiff_t n);
//

#include <libkern/c++/bounded_ptr.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

#define _assert(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

struct T { int i; };

namespace {
struct tracking_policy {
	static bool did_trap;
	static void
	trap(char const*)
	{
		did_trap = true;
	}
};
bool tracking_policy::did_trap = false;
}

template <typename T, typename QualT>
static void
tests()
{
	std::array<T, 5> array = {T{0}, T{1}, T{2}, T{3}, T{4}};

	// Add-assign positive offsets
	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//   ^                                                ^
	//   |                                                |
	// begin,ptr                                         end
	{
		test_bounded_ptr<QualT> ptr(array.begin(), array.begin(), array.end());
		auto& ref = ptr += 0;
		_assert(&ref == &ptr);
		_assert(&*ptr == &array[0]);
	}
	{
		test_bounded_ptr<QualT> ptr(array.begin(), array.begin(), array.end());
		auto& ref = ptr += 1;
		_assert(&ref == &ptr);
		_assert(&*ptr == &array[1]);
	}
	{
		test_bounded_ptr<QualT> ptr(array.begin(), array.begin(), array.end());
		auto& ref = ptr += 2;
		_assert(&ref == &ptr);
		_assert(&*ptr == &array[2]);
	}
	{
		test_bounded_ptr<QualT> ptr(array.begin(), array.begin(), array.end());
		auto& ref = ptr += 3;
		_assert(&ref == &ptr);
		_assert(&*ptr == &array[3]);
	}
	{
		test_bounded_ptr<QualT> ptr(array.begin(), array.begin(), array.end());
		auto& ref = ptr += 4;
		_assert(&ref == &ptr);
		_assert(&*ptr == &array[4]);
	}
	{
		test_bounded_ptr<QualT> ptr(array.begin(), array.begin(), array.end());
		auto& ref = ptr += 5;
		_assert(&ref == &ptr);
		_assert(ptr == array.end());
	}

	// Add-assign negative offsets
	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//   ^                                                ^
	//   |                                                |
	// begin                                           end,ptr
	{
		test_bounded_ptr<QualT> ptr(array.end(), array.begin(), array.end());
		auto& ref = ptr += 0;
		_assert(&ref == &ptr);
		_assert(ptr == array.end());
	}
	{
		test_bounded_ptr<QualT> ptr(array.end(), array.begin(), array.end());
		auto& ref = ptr += -1;
		_assert(&ref == &ptr);
		_assert(&*ptr == &array[4]);
	}
	{
		test_bounded_ptr<QualT> ptr(array.end(), array.begin(), array.end());
		auto& ref = ptr += -2;
		_assert(&ref == &ptr);
		_assert(&*ptr == &array[3]);
	}
	{
		test_bounded_ptr<QualT> ptr(array.end(), array.begin(), array.end());
		auto& ref = ptr += -3;
		_assert(&ref == &ptr);
		_assert(&*ptr == &array[2]);
	}
	{
		test_bounded_ptr<QualT> ptr(array.end(), array.begin(), array.end());
		auto& ref = ptr += -4;
		_assert(&ref == &ptr);
		_assert(&*ptr == &array[1]);
	}
	{
		test_bounded_ptr<QualT> ptr(array.end(), array.begin(), array.end());
		auto& ref = ptr += -5;
		_assert(&ref == &ptr);
		_assert(&*ptr == &array[0]);
	}

	// Make sure we trap on arithmetic overflow in the number of bytes calculation
	{
		std::ptrdiff_t sizeof_T = sizeof(T); // avoid promotion to unsigned in calculations

		// largest (most positive) n for the number of bytes `n * sizeof(T)` not to overflow ptrdiff_t
		std::ptrdiff_t max_n = std::numeric_limits<std::ptrdiff_t>::max() / sizeof_T;

		// smallest (most negative) n for the number of bytes `n * sizeof(T)` not to overflow ptrdiff_t
		std::ptrdiff_t min_n = std::numeric_limits<std::ptrdiff_t>::min() / sizeof_T;

		// Overflow with a positive offset
		{
			libkern::bounded_ptr<QualT, tracking_policy> ptr(array.begin(), array.begin(), array.end());
			tracking_policy::did_trap = false;
			ptr += max_n + 1;
			_assert(tracking_policy::did_trap);
		}

		// Overflow with a negative offset
		{
			libkern::bounded_ptr<QualT, tracking_policy> ptr(array.begin(), array.begin(), array.end());
			tracking_policy::did_trap = false;
			ptr += min_n - 1;
			_assert(tracking_policy::did_trap);
		}
	}

	// Make sure we trap on arithmetic overflow in the offset calculation
	//
	// To avoid running into the overflow of `n * sizeof(T)` when ptrdiff_t
	// is the same size as int32_t, we test the offset overflow check by
	// successive addition of smaller offsets.
	//
	// We basically push the offset right to its limit, and then push it
	// past its limit to watch it overflow.
	{
		std::int64_t sizeof_T = sizeof(T); // avoid promotion to unsigned in calculations

		// largest (most positive) n for the number of bytes `n * sizeof(T)` not to overflow the int32_t offset
		std::int64_t max_n = std::numeric_limits<std::int32_t>::max() / sizeof_T;

		// smallest (most negative) n for the number of bytes `n * sizeof(T)` not to overflow the int32_t offset
		std::int64_t min_n = std::numeric_limits<std::int32_t>::min() / sizeof_T;

		// Add positive offsets
		{
			libkern::bounded_ptr<QualT, tracking_policy> ptr(array.begin(), array.begin(), array.end());
			tracking_policy::did_trap = false;
			ptr += static_cast<ptrdiff_t>(max_n / 2);
			_assert(!tracking_policy::did_trap);
			ptr += static_cast<ptrdiff_t>(max_n / 2);
			_assert(!tracking_policy::did_trap);
			ptr += (max_n % 2);
			_assert(!tracking_policy::did_trap); // offset is now right at its positive limit
			ptr += 1;
			_assert(tracking_policy::did_trap);
		}

		// Add negative offsets
		{
			libkern::bounded_ptr<QualT, tracking_policy> ptr(array.begin(), array.begin(), array.end());
			tracking_policy::did_trap = false;
			ptr += static_cast<ptrdiff_t>(min_n / 2);
			_assert(!tracking_policy::did_trap);
			ptr += static_cast<ptrdiff_t>(min_n / 2);
			_assert(!tracking_policy::did_trap);
			ptr += (min_n % 2);
			_assert(!tracking_policy::did_trap); // offset is now right at its negative limit
			ptr += -1;
			_assert(tracking_policy::did_trap);
		}
	}
}

T_DECL(arith_add_assign, "bounded_ptr.arith.add_assign") {
	tests<T, T>();
	tests<T, T const>();
	tests<T, T volatile>();
	tests<T, T const volatile>();
}
