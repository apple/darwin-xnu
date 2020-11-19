//
// Tests for
//  template <typename T, typename P, typename U>
//  bool operator==(bounded_ptr<T, P> const& a, U* b);
//
//  template <typename T, typename P, typename U>
//  bool operator==(U* a, bounded_ptr<T, P> const& b);
//
//  template <typename T, typename P, typename U>
//  bool operator!=(bounded_ptr<T, P> const& a, U* b);
//
//  template <typename T, typename P, typename U>
//  bool operator!=(U* a, bounded_ptr<T, P> const& b);
//

#include <libkern/c++/bounded_ptr.h>
#include <array>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

#define _assert(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

template <typename T, typename U>
static void
check_eq(T t, U u)
{
	_assert(t == u);
	_assert(u == t);
	_assert(!(t != u));
	_assert(!(u != t));
}

template <typename T, typename U>
static void
check_ne(T t, U u)
{
	_assert(!(t == u));
	_assert(!(u == t));
	_assert(t != u);
	_assert(u != t);
}

template <typename T, typename TQual>
static void
tests()
{
	std::array<T, 5> array = {T{0}, T{1}, T{2}, T{3}, T{4}};

	// Compare pointers within the bounds
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                                                ^
		//   |                                                |
		// begin,a,b                                         end
		test_bounded_ptr<TQual> const a(array.begin(), array.begin(), array.end());
		TQual* b = array.begin();
		check_eq(a, b);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^        ^                                       ^
		//   |        |                                       |
		// begin     a,b                                     end
		test_bounded_ptr<TQual> const a(array.begin() + 1, array.begin(), array.end());
		TQual* b = array.begin() + 1;
		check_eq(a, b);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                 ^                              ^
		//   |                 |                              |
		// begin,a             b                             end
		test_bounded_ptr<TQual> const a(array.begin(), array.begin(), array.end());
		TQual* b = array.begin() + 2;
		check_ne(a, b);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                                                ^
		//   |                                                |
		// begin                                           end,a,b
		test_bounded_ptr<TQual> const a(array.end(), array.begin(), array.end());
		TQual* b = array.end();
		check_eq(a, b);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                 ^        ^        ^
		//   |                 |        |        |
		// begin               a       end       b
		test_bounded_ptr<TQual> const a(array.begin() + 2, array.begin(), array.begin() + 3);
		TQual* b = array.begin() + 4;
		check_ne(a, b);
	}

	// Check when the bounded_ptr is outside of its bounds
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                 ^                              ^
		//   |                 |                              |
		//  a,b              begin                           end
		test_bounded_ptr<TQual> const a(array.begin(), array.begin() + 2, array.end());
		TQual* b = array.begin();
		check_eq(a, b);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                          ^        ^
		//   |                          |        |
		// begin                       end      a,b
		test_bounded_ptr<TQual> const a(array.end() - 1, array.begin(), array.end() - 2);
		TQual* b = array.end() - 1;
		check_eq(a, b);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                                   ^            ^
		//   |                                   |            |
		// begin                                end          a,b
		test_bounded_ptr<TQual> const a(array.end(), array.begin(), array.end() - 1);
		TQual* b = array.end();
		check_eq(a, b);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                          ^        ^            ^
		//   |                          |        |            |
		// begin                       end       a            b
		test_bounded_ptr<TQual> const a(array.end() - 1, array.begin(), array.end() - 2);
		TQual* b = array.end();
		check_ne(a, b);
	}

	// Test comparing against a null pointer
	{
		test_bounded_ptr<TQual> a = nullptr;
		TQual* b = nullptr;
		check_eq(a, b);
	}
	{
		test_bounded_ptr<TQual> a(array.end() - 1, array.begin(), array.end() - 2);
		TQual* b = nullptr;
		check_ne(a, b);
	}
	{
		test_bounded_ptr<TQual> a = nullptr;
		TQual* b = array.begin();
		check_ne(a, b);
	}
}

struct Base { int i; };
struct Derived : Base { };

template <typename Related>
static void
tests_convert()
{
	std::array<Derived, 5> array = {Derived{0}, Derived{1}, Derived{2}, Derived{3}, Derived{4}};

	{
		test_bounded_ptr<Derived> const a(array.begin(), array.begin(), array.end() - 1);
		Related* b = array.begin();
		check_eq(a, b);
	}
	{
		test_bounded_ptr<Related> const a(array.begin(), array.begin(), array.end() - 1);
		Derived* b = array.begin();
		check_eq(a, b);
	}

	// Test comparisons against cv-void*
	{
		test_bounded_ptr<Related> const a(array.begin(), array.begin(), array.end() - 1);
		void* b = array.begin();
		check_eq(a, b);
	}
}

T_DECL(compare_equal_raw, "bounded_ptr.compare.equal.raw") {
	tests<Derived, Derived>();
	tests<Derived, Derived const>();
	tests<Derived, Derived volatile>();
	tests<Derived, Derived const volatile>();
	tests_convert<Base>();
	tests_convert<Base const>();
	tests_convert<Base volatile>();
	tests_convert<Base const volatile>();
}
