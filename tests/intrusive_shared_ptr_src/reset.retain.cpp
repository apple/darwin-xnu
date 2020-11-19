//
// Tests for
//  void reset(pointer p, retain_t) noexcept;
//

#include <libkern/c++/intrusive_shared_ptr.h>
#include <darwintest.h>
#include "test_policy.h"

struct T {
	int i;
};

template <typename T>
static void
tests()
{
	T obj1{1};
	T obj2{2};

	// reset() non-null shared pointer to non-null raw pointer
	{
		tracked_shared_ptr<T> ptr(&obj1, libkern::retain);
		tracking_policy::reset();
		ptr.reset(&obj2, libkern::retain);
		CHECK(tracking_policy::releases == 1);
		CHECK(tracking_policy::retains == 1);
		CHECK(ptr.get() == &obj2);
	}

	// reset() non-null shared pointer to null raw pointer
	{
		tracked_shared_ptr<T> ptr(&obj1, libkern::retain);
		tracking_policy::reset();
		ptr.reset(nullptr, libkern::retain);
		CHECK(tracking_policy::releases == 1);
		CHECK(tracking_policy::retains == 0);
		CHECK(ptr.get() == nullptr);
	}

	// reset() null shared pointer to non-null raw pointer
	{
		tracked_shared_ptr<T> ptr = nullptr;
		tracking_policy::reset();
		ptr.reset(&obj2, libkern::retain);
		CHECK(tracking_policy::releases == 0);
		CHECK(tracking_policy::retains == 1);
		CHECK(ptr.get() == &obj2);
	}

	// reset() null shared pointer to null raw pointer
	{
		tracked_shared_ptr<T> ptr = nullptr;
		tracking_policy::reset();
		ptr.reset(nullptr, libkern::retain);
		CHECK(tracking_policy::releases == 0);
		CHECK(tracking_policy::retains == 0);
		CHECK(ptr.get() == nullptr);
	}

	// self-reset() should not cause the refcount to hit 0, ever
	{
		tracking_policy::reset();
		tracked_shared_ptr<T> ptr(&obj1, libkern::retain);
		CHECK(tracking_policy::retains == 1);
		ptr.reset(ptr.get(), libkern::retain);
		CHECK(tracking_policy::retains == 2);
		CHECK(tracking_policy::releases == 1);
		CHECK(tracking_policy::refcount == 1);
		CHECK(!tracking_policy::hit_zero);
		CHECK(ptr.get() == &obj1);
	}

	// reset() as a self-reference
	{
		tracked_shared_ptr<T> ptr;
		tracked_shared_ptr<T> ptr2;
		CHECK(ptr.reset(&obj2, libkern::retain));

		// check short-circuiting
		bool ok =  (ptr.reset() && ptr2.reset(&obj1, libkern::retain));
		CHECK(ptr2.get() == nullptr);
	}
}

T_DECL(reset_retain, "intrusive_shared_ptr.reset.retain") {
	tests<T>();
	tests<T const>();
}
