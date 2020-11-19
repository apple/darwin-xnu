//
// Tests for
//  bounded_array_ref<T, TrappingPolicy> slice(size_t n, size_t m) const;
//

#include <libkern/c++/bounded_array_ref.h>
#include "test_policy.h"
#include <cstddef>
#include <cstdint>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <limits>

struct T { int i; };

template <typename T>
using tracking_bounded_array_ref = libkern::bounded_array_ref<T, tracking_policy>;

template <typename T>
static void
tests()
{
	T array[5] = {T{0}, T{1}, T{2}, T{3}, T{4}};

	// Slices starting at 0
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(0, 0);
		CHECK(slice.size() == 0);
	}
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(0, 1);
		CHECK(slice.size() == 1);
		CHECK(&slice[0] == &array[0]);
	}
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(0, 2);
		CHECK(slice.size() == 2);
		CHECK(&slice[0] == &array[0]);
		CHECK(&slice[1] == &array[1]);
	}
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(0, 5);
		CHECK(slice.size() == 5);
		CHECK(&slice[0] == &array[0]);
		CHECK(&slice[1] == &array[1]);
		CHECK(&slice[2] == &array[2]);
		CHECK(&slice[3] == &array[3]);
		CHECK(&slice[4] == &array[4]);
	}
	{
		tracking_bounded_array_ref<T> view(array);
		tracking_policy::reset();
		tracking_bounded_array_ref<T> slice = view.slice(0, 6);
		CHECK(tracking_policy::did_trap);
		CHECK(tracking_policy::message == "bounded_array_ref: invalid slice provided, the indices are of bounds for the bounded_array_ref");
	}

	// Slices starting at 1 (near the beginning)
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(1, 0);
		CHECK(slice.size() == 0);
	}
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(1, 3);
		CHECK(slice.size() == 3);
		CHECK(&slice[0] == &array[1]);
		CHECK(&slice[1] == &array[2]);
		CHECK(&slice[2] == &array[3]);
	}
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(1, 4);
		CHECK(slice.size() == 4);
		CHECK(&slice[0] == &array[1]);
		CHECK(&slice[1] == &array[2]);
		CHECK(&slice[2] == &array[3]);
		CHECK(&slice[3] == &array[4]);
	}
	{
		tracking_bounded_array_ref<T> view(array);
		tracking_policy::reset();
		tracking_bounded_array_ref<T> slice = view.slice(1, 5);
		CHECK(tracking_policy::did_trap);
	}
	{
		tracking_bounded_array_ref<T> view(array);
		tracking_policy::reset();
		tracking_bounded_array_ref<T> slice = view.slice(1, 10);
		CHECK(tracking_policy::did_trap);
	}

	// Slices starting at 3 (in the middle)
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(3, 0);
		CHECK(slice.size() == 0);
	}
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(3, 2);
		CHECK(slice.size() == 2);
		CHECK(&slice[0] == &array[3]);
		CHECK(&slice[1] == &array[4]);
	}
	{
		tracking_bounded_array_ref<T> view(array);
		tracking_policy::reset();
		tracking_bounded_array_ref<T> slice = view.slice(3, 3);
		CHECK(tracking_policy::did_trap);
	}
	{
		tracking_bounded_array_ref<T> view(array);
		tracking_policy::reset();
		tracking_bounded_array_ref<T> slice = view.slice(3, 100);
		CHECK(tracking_policy::did_trap);
	}

	// Slices starting at 4 (near the end)
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(4, 0);
		CHECK(slice.size() == 0);
	}
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(4, 1);
		CHECK(slice.size() == 1);
		CHECK(&slice[0] == &array[4]);
	}
	{
		tracking_bounded_array_ref<T> view(array);
		tracking_policy::reset();
		tracking_bounded_array_ref<T> slice = view.slice(4, 2);
		CHECK(tracking_policy::did_trap);
	}

	// Slices starting at the end
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(5, 0);
		CHECK(slice.size() == 0);
	}
	{
		tracking_bounded_array_ref<T> view(array);
		tracking_policy::reset();
		tracking_bounded_array_ref<T> slice = view.slice(5, 1);
		CHECK(tracking_policy::did_trap);
	}
	{
		tracking_bounded_array_ref<T> view(array);
		tracking_policy::reset();
		tracking_bounded_array_ref<T> slice = view.slice(5, 10);
		CHECK(tracking_policy::did_trap);
	}

	// Slices starting after the end
	{
		tracking_bounded_array_ref<T> view(array);
		tracking_policy::reset();
		tracking_bounded_array_ref<T> slice = view.slice(6, 0);
		CHECK(tracking_policy::did_trap);
	}
	{
		tracking_bounded_array_ref<T> view(array);
		tracking_policy::reset();
		tracking_bounded_array_ref<T> slice = view.slice(6, 1);
		CHECK(tracking_policy::did_trap);
	}
	{
		tracking_bounded_array_ref<T> view(array);
		tracking_policy::reset();
		tracking_bounded_array_ref<T> slice = view.slice(8, 10);
		CHECK(tracking_policy::did_trap);
	}

	// Slices overflowing a uint32_t
	{
		std::uint32_t n = std::numeric_limits<std::uint32_t>::max() / 2 + 1;
		std::uint32_t m = std::numeric_limits<std::uint32_t>::max() / 2 + 1;
		tracking_bounded_array_ref<T> view(array);
		tracking_policy::reset();
		tracking_bounded_array_ref<T> slice = view.slice(n, m);
		CHECK(tracking_policy::did_trap);
		CHECK(tracking_policy::message == "bounded_array_ref: n + m is larger than the size of any bounded_array_ref");
	}

	// Check the documented range equivalent
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(3, 2);
		CHECK(slice.begin() == view.begin() + 3);
		CHECK(slice.end() == view.begin() + 3 + 2);
	}

	// Chaining calls to slice()
	{
		test_bounded_array_ref<T> view(array);
		test_bounded_array_ref<T> slice = view.slice(1, 4).slice(2, 2);
		CHECK(slice.size() == 2);
		CHECK(&slice[0] == &array[3]);
		CHECK(&slice[1] == &array[4]);
	}

	// Slicing an empty view
	{
		test_bounded_array_ref<T> view;
		test_bounded_array_ref<T> slice = view.slice(0, 0);
		CHECK(slice.size() == 0);
	}
	{
		tracking_bounded_array_ref<T> view;
		tracking_policy::reset();
		tracking_bounded_array_ref<T> slice = view.slice(0, 1);
		CHECK(tracking_policy::did_trap);
	}
}

T_DECL(slice, "bounded_array_ref.slice") {
	tests<T>();
	tests<T const>();
}
