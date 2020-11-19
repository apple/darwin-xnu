//
// Tests for
//  explicit bounded_ptr(T* pointer, T const* begin, T const* end);
//

#include <libkern/c++/bounded_ptr.h>
#include <array>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

#define _assert(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

struct T {
	int i;
	friend constexpr bool
	operator==(T const volatile& a, T const& b)
	{
		return a.i == b.i;
	}
};

template <typename T, typename QualT>
static void
tests()
{
	std::array<T, 5> array = {T{0}, T{1}, T{2}, T{3}, T{4}};
	{
		test_bounded_ptr<QualT> p(array.begin() + 0, array.begin(), array.end());
		_assert(*p == T{0});
	}
	{
		test_bounded_ptr<QualT> p(array.begin() + 1, array.begin(), array.end());
		_assert(*p == T{1});
	}
	{
		test_bounded_ptr<QualT> p(array.begin() + 2, array.begin(), array.end());
		_assert(*p == T{2});
	}
	{
		test_bounded_ptr<QualT> p(array.begin() + 3, array.begin(), array.end());
		_assert(*p == T{3});
	}
	{
		test_bounded_ptr<QualT> p(array.begin() + 4, array.begin(), array.end());
		_assert(*p == T{4});
	}

	// It must be valid to construct out-of-bounds pointers, but we obviously
	// can't dereference them.
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//            ^                 ^                     ^
		//            |                 |                     |
		//           ptr              begin                  end
		test_bounded_ptr<QualT> p(array.begin() + 1, array.begin() + 3, array.end());
		_assert(p.unsafe_discard_bounds() == array.begin() + 1);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                          ^        ^
		//   |                          |        |
		// begin                       end      ptr
		test_bounded_ptr<QualT> p(array.begin() + 4, array.begin(), array.begin() + 3);
		_assert(p.unsafe_discard_bounds() == array.begin() + 4);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                                                ^
		//   |                                                |
		// begin                                             end,ptr
		test_bounded_ptr<QualT> p(array.end(), array.begin(), array.end());
		_assert(p.unsafe_discard_bounds() == array.end());
	}

	// Test creating a bounded_ptr from a null pointer.
	{
		test_bounded_ptr<QualT> p(nullptr, nullptr, nullptr);
		_assert(p.unsafe_discard_bounds() == nullptr);
	}
}

struct Base { };
struct Derived : Base { };

T_DECL(ctor_begin_end, "bounded_ptr.ctor.begin_end") {
	tests<T, T>();
	tests<T, T const>();
	tests<T, T volatile>();
	tests<T, T const volatile>();

	// Make sure we can construct a `bounded_ptr<Base>` from `Derived*` pointers
	{
		std::array<Derived, 5> array = {};
		test_bounded_ptr<Base> p(static_cast<Derived*>(array.begin()),
		    static_cast<Derived*>(array.begin()),
		    static_cast<Derived*>(array.end()));
	}
}
