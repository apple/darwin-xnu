//
// Tests for
//  template <typename T, typename U, typename Policy>
//  bounded_ptr<T, Policy> reinterpret_pointer_cast(bounded_ptr<U, Policy> const& p) noexcept
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

struct non_default_policy {
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

	{
		test_bounded_ptr<From> from(array.begin() + 2, array.begin(), array.end());
		test_bounded_ptr<To> to = libkern::reinterpret_pointer_cast<To>(from);
		_assert(to.discard_bounds() == reinterpret_cast<To const*>(from.discard_bounds()));
	}

	{
		test_bounded_ptr<From> from(array.begin() + 2, array.begin(), array.end());
		test_bounded_ptr<To> to = libkern::reinterpret_pointer_cast<To>(from);
		_assert(to.discard_bounds() == reinterpret_cast<To const volatile*>(from.discard_bounds()));
	}

	// Test `reinterpret_pointer_cast`ing a null pointer
	{
		test_bounded_ptr<From> from(nullptr, nullptr, nullptr);
		test_bounded_ptr<To> to = libkern::reinterpret_pointer_cast<To>(from);
		_assert(to.unsafe_discard_bounds() == nullptr);
	}

	// Test with a non-default policy
	{
		libkern::bounded_ptr<From, non_default_policy> from(array.begin(), array.begin(), array.end());
		libkern::bounded_ptr<To, non_default_policy> to = libkern::reinterpret_pointer_cast<To>(from);
		_assert(to.discard_bounds() == reinterpret_cast<To const*>(from.discard_bounds()));
	}
}

T_DECL(reinterpret_cast_, "bounded_ptr.reinterpret_cast") {
	tests</*stored*/ Derived, /*from*/ Derived, /*to*/ Base>();
	tests</*stored*/ Derived, /*from*/ Derived const, /*to*/ Base const>();
	tests</*stored*/ Derived, /*from*/ Derived volatile, /*to*/ Base volatile>();
	tests</*stored*/ Derived, /*from*/ Derived const volatile, /*to*/ Base const volatile>();

	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple, /*to*/ Base1>();
	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple const, /*to*/ Base1 const>();
	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple volatile, /*to*/ Base1 volatile>();
	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple const volatile, /*to*/ Base1 const volatile>();

	tests</*stored*/ Derived, /*from*/ Derived, /*to*/ void>();
	tests</*stored*/ Derived, /*from*/ Derived const, /*to*/ void const>();
	tests</*stored*/ Derived, /*from*/ Derived volatile, /*to*/ void volatile>();
	tests</*stored*/ Derived, /*from*/ Derived const volatile, /*to*/ void const volatile>();

	tests</*stored*/ Derived, /*from*/ Derived, /*to*/ char>();
	tests</*stored*/ Derived, /*from*/ Derived const, /*to*/ char const>();
	tests</*stored*/ Derived, /*from*/ Derived volatile, /*to*/ char volatile>();
	tests</*stored*/ Derived, /*from*/ Derived const volatile, /*to*/ char const volatile>();
}
