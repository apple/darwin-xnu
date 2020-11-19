//
// Tests for
//  template <typename U, typename Policy>
//  bounded_ptr(bounded_ptr<U, Policy> const& other);
//

#include <libkern/c++/bounded_ptr.h>
#include <array>
#include <type_traits>
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
	Stored* const ptr = array.begin() + 2;

	{
		test_bounded_ptr<From> const from(ptr, array.begin(), array.end());
		test_bounded_ptr<To> to = from; // conversion (implicit)
		_assert(to.discard_bounds() == static_cast<To const*>(ptr));
	}
	{
		test_bounded_ptr<From> const from(ptr, array.begin(), array.end());
		test_bounded_ptr<To> to(from); // conversion (explicit)
		_assert(to.discard_bounds() == static_cast<To const*>(ptr));
	}
	{
		test_bounded_ptr<From> const from(ptr, array.begin(), array.end());
		test_bounded_ptr<To> to{from}; // conversion (explicit)
		_assert(to.discard_bounds() == static_cast<To const*>(ptr));
	}
	{
		test_bounded_ptr<From> const from(ptr, array.begin(), array.end());
		test_bounded_ptr<To> to = static_cast<test_bounded_ptr<To> >(from); // conversion (explicit)
		_assert(to.discard_bounds() == static_cast<To const*>(ptr));
	}

	// Test converting from a null pointer
	{
		test_bounded_ptr<From> from = nullptr;
		test_bounded_ptr<To> to = from; // conversion (implicit)
		_assert(to.unsafe_discard_bounds() == nullptr);
	}

	// Test with different policies
	{
		libkern::bounded_ptr<From, dummy_policy1> from(ptr, array.begin(), array.end());
		libkern::bounded_ptr<To, dummy_policy2> to = from; // conversion (implicit)
		_assert(to.discard_bounds() == static_cast<To const*>(ptr));
	}

	// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
	//   ^        ^                                       ^
	//   |        |                                       |
	// from     begin                                    end
	{
		test_bounded_ptr<From> const from(array.begin(), array.begin() + 1, array.end());
		test_bounded_ptr<To> to(from);
		_assert(to.unsafe_discard_bounds() == static_cast<To const*>(array.begin()));
	}
}

T_DECL(ctor_convert, "bounded_ptr.ctor.convert") {
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
	static_assert(!std::is_convertible_v</*from*/ test_bounded_ptr<Base>, /*to*/ test_bounded_ptr<Derived> >);
	static_assert(!std::is_convertible_v</*from*/ test_bounded_ptr<Base1>, /*to*/ test_bounded_ptr<DerivedMultiple> >);
	static_assert(!std::is_convertible_v</*from*/ test_bounded_ptr<Base2>, /*to*/ test_bounded_ptr<DerivedMultiple> >);
	static_assert(!std::is_convertible_v</*from*/ test_bounded_ptr<Base1>, /*to*/ test_bounded_ptr<Base2> >);

	// Make sure const-casting away doesn't work
	static_assert(!std::is_convertible_v</*from*/ test_bounded_ptr<Derived const>, /*to*/ test_bounded_ptr<Derived> >);

	// Make sure casting to unrelated types doesn't work implicitly
	static_assert(!std::is_convertible_v</*from*/ test_bounded_ptr<Derived>, /*to*/ test_bounded_ptr<char> >);
	static_assert(!std::is_convertible_v</*from*/ test_bounded_ptr<Derived>, /*to*/ test_bounded_ptr<Unrelated> >);
	static_assert(!std::is_convertible_v</*from*/ test_bounded_ptr<Base1>, /*to*/ test_bounded_ptr<Base2> >);

	// Make sure even explicit conversion to unrelated types doesn't work
	static_assert(!std::is_constructible_v</*to*/ test_bounded_ptr<char>, /*from*/ test_bounded_ptr<Derived> >);
	static_assert(!std::is_constructible_v</*to*/ test_bounded_ptr<Unrelated>, /*from*/ test_bounded_ptr<Derived> >);
	static_assert(!std::is_constructible_v</*to*/ test_bounded_ptr<Base2>, /*from*/ test_bounded_ptr<Base1> >);

	// Make sure construction from a raw pointer doesn't work
	static_assert(!std::is_constructible_v</*to*/ test_bounded_ptr<Derived>, /*from*/ Derived*>);
}
