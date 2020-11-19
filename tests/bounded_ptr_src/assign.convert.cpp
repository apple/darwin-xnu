//
// Tests for
//  template <typename U, typename Policy>
//  bounded_ptr& operator=(bounded_ptr<U, Policy> const& other);
//

#include <libkern/c++/bounded_ptr.h>
#include <array>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

#define _assert(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

struct Base { int i; };
struct Derived : Base { };

struct Base1 { int i; };
struct Base2 { long l; };
struct DerivedMultiple : Base1, Base2 {
	DerivedMultiple(int i) : Base1{i}, Base2{i + 10}
	{
	}
};

struct Unrelated { };

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

template <typename Stored, typename From, typename To>
static void
tests()
{
	std::array<Stored, 5> array = {Stored{0}, Stored{1}, Stored{2}, Stored{3}, Stored{4}};
	Stored* const ptr1 = array.begin() + 2;
	Stored* const ptr2 = array.begin() + 3;

	{
		test_bounded_ptr<From> const from(ptr1, array.begin(), array.end());
		test_bounded_ptr<To> to;
		test_bounded_ptr<To>& ref = (to = from);
		_assert(to.discard_bounds() == static_cast<To const*>(ptr1));
		_assert(&ref == &to); // make sure we return *this
	}

	// Test assigning to a non-null pointer
	{
		test_bounded_ptr<From> const from(ptr1, array.begin(), array.end());
		test_bounded_ptr<To> to(ptr2, array.begin(), array.end());
		_assert(to.discard_bounds() == static_cast<To const*>(ptr2));

		test_bounded_ptr<To>& ref = (to = from);
		_assert(to.discard_bounds() == static_cast<To const*>(ptr1));
		_assert(&ref == &to); // make sure we return *this
	}

	// Test assigning from a null pointer
	{
		test_bounded_ptr<From> const from = nullptr;
		test_bounded_ptr<To> to;
		test_bounded_ptr<To>& ref = (to = from);
		_assert(to.unsafe_discard_bounds() == nullptr);
		_assert(&ref == &to); // make sure we return *this
	}

	// Test with different policies
	{
		libkern::bounded_ptr<From, dummy_policy1> from(ptr1, array.begin(), array.end());
		libkern::bounded_ptr<To, dummy_policy2> to;
		libkern::bounded_ptr<To, dummy_policy2>& ref = (to = from);
		_assert(to.discard_bounds() == static_cast<To const*>(ptr1));
		_assert(&ref == &to); // make sure we return *this
	}

	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//   ^        ^                                       ^
	//   |        |                                       |
	// from     begin                                    end
	{
		test_bounded_ptr<From> const from(array.begin(), array.begin() + 1, array.end());
		test_bounded_ptr<To> to;
		to = from;
		_assert(to.unsafe_discard_bounds() == static_cast<To const*>(array.begin()));
	}
}

T_DECL(assign_convert, "bounded_ptr.assign.convert") {
	tests</*stored*/ Derived, /*from*/ Derived, /*to*/ Derived>();
	tests</*stored*/ Derived, /*from*/ Derived const, /*to*/ Derived const>();
	tests</*stored*/ Derived, /*from*/ Derived volatile, /*to*/ Derived volatile>();
	tests</*stored*/ Derived, /*from*/ Derived const volatile, /*to*/ Derived const volatile>();

	tests</*stored*/ Derived, /*from*/ Derived, /*to*/ Base>();
	tests</*stored*/ Derived, /*from*/ Derived const, /*to*/ Base const>();
	tests</*stored*/ Derived, /*from*/ Derived volatile, /*to*/ Base volatile>();
	tests</*stored*/ Derived, /*from*/ Derived const volatile, /*to*/ Base const volatile>();

	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple, /*to*/ Base1>();
	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple const, /*to*/ Base1 const>();
	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple volatile, /*to*/ Base1 volatile>();
	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple const volatile, /*to*/ Base1 const volatile>();

	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple, /*to*/ Base2>();
	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple const, /*to*/ Base2 const>();
	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple volatile, /*to*/ Base2 volatile>();
	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple const volatile, /*to*/ Base2 const volatile>();

	tests</*stored*/ Derived, /*from*/ Derived, /*to*/ void>();
	tests</*stored*/ Derived, /*from*/ Derived const, /*to*/ void const>();
	tests</*stored*/ Derived, /*from*/ Derived volatile, /*to*/ void volatile>();
	tests</*stored*/ Derived, /*from*/ Derived const volatile, /*to*/ void const volatile>();

	// Make sure downcasts are disabled
	static_assert(!std::is_assignable_v</*to*/ test_bounded_ptr<Derived>, /*from*/ test_bounded_ptr<Base> >);
	static_assert(!std::is_assignable_v</*to*/ test_bounded_ptr<DerivedMultiple>, /*from*/ test_bounded_ptr<Base1> >);
	static_assert(!std::is_assignable_v</*to*/ test_bounded_ptr<DerivedMultiple>, /*from*/ test_bounded_ptr<Base2> >);
	static_assert(!std::is_assignable_v</*to*/ test_bounded_ptr<Base2>, /*from*/ test_bounded_ptr<Base1> >);

	// Make sure const-casting away doesn't work
	static_assert(!std::is_assignable_v</*to*/ test_bounded_ptr<Derived>, /*from*/ test_bounded_ptr<Derived const> >);

	// Make sure casting to unrelated types doesn't work implicitly
	static_assert(!std::is_assignable_v</*to*/ test_bounded_ptr<char>, /*from*/ test_bounded_ptr<Derived> >);
	static_assert(!std::is_assignable_v</*to*/ test_bounded_ptr<Unrelated>, /*from*/ test_bounded_ptr<Derived> >);
	static_assert(!std::is_assignable_v</*to*/ test_bounded_ptr<Base2>, /*from*/ test_bounded_ptr<Base1> >);

	// Make sure we can't assign from raw pointers
	static_assert(!std::is_assignable_v</*to*/ test_bounded_ptr<Derived>, /*from*/ Derived*>);
}
