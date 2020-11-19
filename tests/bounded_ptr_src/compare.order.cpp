//
// Tests for
//  template <typename T, typename U, typename P1, typename P2>
//  bool operator<(bounded_ptr<T, P1> const& a, bounded_ptr<U, P2> const& b);
//
//  template <typename T, typename U, typename P1, typename P2>
//  bool operator<=(bounded_ptr<T, P1> const& a, bounded_ptr<U, P2> const& b);
//
//  template <typename T, typename U, typename P1, typename P2>
//  bool operator>(bounded_ptr<T, P1> const& a, bounded_ptr<U, P2> const& b);
//
//  template <typename T, typename U, typename P1, typename P2>
//  bool operator>=(bounded_ptr<T, P1> const& a, bounded_ptr<U, P2> const& b);
//

#include <libkern/c++/bounded_ptr.h>
#include <array>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

#define _assert(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

struct dummy_policy1 {
	static constexpr void
	trap(char const*)
	{
	}
};
struct dummy_policy2 {
	static constexpr void
	trap(char const*)
	{
	}
};

template <typename T, typename U>
static void
check_lt(T t, U u)
{
	_assert(t < u);
	_assert(t <= u);
	_assert(!(t >= u));
	_assert(!(t > u));

	_assert(!(u < t));
	_assert(!(u <= t));
	_assert(u > t);
	_assert(u >= t);
}

template <typename T, typename U>
static void
check_eq(T t, U u)
{
	_assert(!(t < u));
	_assert(t <= u);
	_assert(t >= u);
	_assert(!(t > u));

	_assert(!(u < t));
	_assert(u <= t);
	_assert(!(u > t));
	_assert(u >= t);
}

template <typename T, typename TQual>
static void
tests()
{
	std::array<T, 5> array = {T{0}, T{1}, T{2}, T{3}, T{4}};

	// Pointers with the same bounds
	{
		test_bounded_ptr<TQual> const a(array.begin(), array.begin(), array.end());
		test_bounded_ptr<TQual> const b(array.begin(), array.begin(), array.end());
		check_eq(a, b);
	}
	{
		test_bounded_ptr<TQual> const a(array.begin(), array.begin(), array.end());
		test_bounded_ptr<TQual> const b(array.begin() + 1, array.begin(), array.end());
		check_lt(a, b);
	}
	{
		test_bounded_ptr<TQual> const a(array.begin(), array.begin(), array.end());
		test_bounded_ptr<TQual> const b(array.begin() + 2, array.begin(), array.end());
		check_lt(a, b);
	}
	{
		test_bounded_ptr<TQual> const a(array.begin(), array.begin(), array.end());
		test_bounded_ptr<TQual> const b(array.end(), array.begin(), array.end());
		check_lt(a, b);
	}
	{
		test_bounded_ptr<TQual> const a(array.end(), array.begin(), array.end());
		test_bounded_ptr<TQual> const b(array.end(), array.begin(), array.end());
		check_eq(a, b);
	}

	// Compare null pointers
	{
		test_bounded_ptr<TQual> const a;
		test_bounded_ptr<TQual> const b(array.begin(), array.begin(), array.end());
		check_lt(a, b);
	}
	{
		test_bounded_ptr<TQual> const a;
		test_bounded_ptr<TQual> const b;
		check_eq(a, b);
	}

	// Pointers with different bounds
	{
		// Overlapping bounds, equal
		test_bounded_ptr<TQual> const a(array.begin(), array.begin() + 2, array.end());
		test_bounded_ptr<TQual> const b(array.begin(), array.begin(), array.end());
		check_eq(a, b);
	}
	{
		// Overlapping bounds, not equal
		test_bounded_ptr<TQual> const a(array.begin(), array.begin() + 2, array.end());
		test_bounded_ptr<TQual> const b(array.begin() + 2, array.begin(), array.end());
		check_lt(a, b);
	}
	{
		// Non-overlapping bounds, equal
		test_bounded_ptr<TQual> const a(array.begin(), array.begin(), array.begin() + 1);
		test_bounded_ptr<TQual> const b(array.begin(), array.begin() + 2, array.end());
		check_eq(a, b);
	}
	{
		// Non-overlapping bounds, not equal
		test_bounded_ptr<TQual> const a(array.begin(), array.begin(), array.begin() + 1);
		test_bounded_ptr<TQual> const b(array.begin() + 3, array.begin() + 2, array.end());
		check_lt(a, b);
	}

	// Test with different policies
	{
		libkern::bounded_ptr<TQual, dummy_policy1> const a(array.begin(), array.begin(), array.end());
		libkern::bounded_ptr<TQual, dummy_policy2> const b(array.begin(), array.begin(), array.end());
		check_eq(a, b);
	}
}

struct Base { int i; };
struct Derived : Base { };

template <typename Related>
static void
tests_convert()
{
	std::array<Derived, 5> array = {Derived{0}, Derived{1}, Derived{2}, Derived{3}, Derived{4}};
	test_bounded_ptr<Derived> const a(array.begin(), array.begin(), array.end() - 1);
	test_bounded_ptr<Related> const b(array.begin(), array.begin(), array.end() - 1);
	check_eq(a, b);
}

T_DECL(compare_order, "bounded_ptr.compare.order") {
	tests<Derived, Derived>();
	tests<Derived, Derived const>();
	tests<Derived, Derived volatile>();
	tests<Derived, Derived const volatile>();
	tests_convert<Base>();
	tests_convert<Base const>();
	tests_convert<Base volatile>();
	tests_convert<Base const volatile>();
}
