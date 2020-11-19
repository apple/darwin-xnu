//
// Tests for
//  template <typename U>
//  intrusive_shared_ptr& operator=(intrusive_shared_ptr<U, RefcountPolicy> const& other);
//
//  intrusive_shared_ptr& operator=(intrusive_shared_ptr const& other);
//

#include <libkern/c++/intrusive_shared_ptr.h>
#include <darwintest.h>
#include <type_traits>
#include "test_policy.h"

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

template <typename Stored, typename From, typename To>
static void
tests()
{
	Stored obj1{1};
	Stored obj2{2};

	// Copy-assign non-null to non-null
	{
		tracked_shared_ptr<From> const from(&obj1, libkern::retain);
		tracked_shared_ptr<To> to(&obj2, libkern::retain);
		tracking_policy::reset();
		tracked_shared_ptr<To>& ref = (to = from);
		CHECK(tracking_policy::releases == 1);
		CHECK(tracking_policy::retains == 1);
		CHECK(&ref == &to);
		CHECK(from.get() == &obj1);
		CHECK(to.get() == &obj1);
	}

	// Copy-assign non-null to null
	{
		tracked_shared_ptr<From> const from(&obj1, libkern::retain);
		tracked_shared_ptr<To> to = nullptr;
		tracking_policy::reset();
		tracked_shared_ptr<To>& ref = (to = from);
		CHECK(tracking_policy::releases == 0);
		CHECK(tracking_policy::retains == 1);
		CHECK(&ref == &to);
		CHECK(from.get() == &obj1);
		CHECK(to.get() == &obj1);
	}

	// Copy-assign null to non-null
	{
		tracked_shared_ptr<From> const from = nullptr;
		tracked_shared_ptr<To> to(&obj2, libkern::retain);
		tracking_policy::reset();
		tracked_shared_ptr<To>& ref = (to = from);
		CHECK(tracking_policy::releases == 1);
		CHECK(tracking_policy::retains == 0);
		CHECK(&ref == &to);
		CHECK(from.get() == nullptr);
		CHECK(to.get() == nullptr);
	}

	// Copy-assign null to null
	{
		tracked_shared_ptr<From> const from = nullptr;
		tracked_shared_ptr<To> to = nullptr;
		tracking_policy::reset();
		tracked_shared_ptr<To>& ref = (to = from);
		CHECK(tracking_policy::releases == 0);
		CHECK(tracking_policy::retains == 0);
		CHECK(&ref == &to);
		CHECK(from.get() == nullptr);
		CHECK(to.get() == nullptr);
	}
}

T_DECL(assign_copy, "intrusive_shared_ptr.assign.copy") {
	tests</*stored*/ Derived, /*from*/ Derived, /*to*/ Derived>();
	tests</*stored*/ Derived, /*from*/ Derived, /*to*/ Derived const>();
	tests</*stored*/ Derived, /*from*/ Derived const, /*to*/ Derived const>();

	tests</*stored*/ Derived, /*from*/ Derived, /*to*/ Base>();
	tests</*stored*/ Derived, /*from*/ Derived, /*to*/ Base const>();
	tests</*stored*/ Derived, /*from*/ Derived const, /*to*/ Base const>();

	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple, /*to*/ Base1>();
	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple const, /*to*/ Base1 const>();

	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple, /*to*/ Base2>();
	tests</*stored*/ DerivedMultiple, /*from*/ DerivedMultiple const, /*to*/ Base2 const>();

	// Make sure basic trait querying works
	static_assert(std::is_copy_assignable_v<test_shared_ptr<Derived> >);

	// Make sure downcasts are disabled
	static_assert(!std::is_assignable_v</*to*/ test_shared_ptr<Derived>, /*from*/ test_shared_ptr<Base> const&>);
	static_assert(!std::is_assignable_v</*to*/ test_shared_ptr<DerivedMultiple>, /*from*/ test_shared_ptr<Base1> const&>);
	static_assert(!std::is_assignable_v</*to*/ test_shared_ptr<DerivedMultiple>, /*from*/ test_shared_ptr<Base2> const&>);
	static_assert(!std::is_assignable_v</*to*/ test_shared_ptr<Base2>, /*from*/ test_shared_ptr<Base1> const&>);

	// Make sure const-casting away doesn't work
	static_assert(!std::is_assignable_v</*to*/ test_shared_ptr<Derived>, /*from*/ test_shared_ptr<Derived const> const&>);

	// Make sure casting to unrelated types doesn't work
	static_assert(!std::is_assignable_v</*to*/ test_shared_ptr<char>, /*from*/ test_shared_ptr<Derived> const&>);
	static_assert(!std::is_assignable_v</*to*/ test_shared_ptr<Unrelated>, /*from*/ test_shared_ptr<Derived> const&>);
	static_assert(!std::is_assignable_v</*to*/ test_shared_ptr<Base2>, /*from*/ test_shared_ptr<Base1> const&>);

	// Make sure constructing with different policies doesn't work
	static_assert(!std::is_assignable_v</*to*/ libkern::intrusive_shared_ptr<Derived, dummy_policy<2> >, /*from*/ libkern::intrusive_shared_ptr<Derived, dummy_policy<1> > const &>);
}
