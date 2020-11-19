//
// Tests for
//  intrusive_shared_ptr& operator=(std::nullptr_t);
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
	T obj{3};

	// Assign nullptr to non-null
	{
		tracked_shared_ptr<T> ptr(&obj, libkern::retain);
		tracking_policy::reset();
		tracked_shared_ptr<T>& ref = (ptr = nullptr);
		CHECK(tracking_policy::releases == 1);
		CHECK(tracking_policy::retains == 0);
		CHECK(&ref == &ptr);
		CHECK(ptr.get() == nullptr);
	}

	// Assign nullptr to null
	{
		tracked_shared_ptr<T> ptr = nullptr;
		tracking_policy::reset();
		tracked_shared_ptr<T>& ref = (ptr = nullptr);
		CHECK(tracking_policy::releases == 0);
		CHECK(tracking_policy::retains == 0);
		CHECK(&ref == &ptr);
		CHECK(ptr.get() == nullptr);
	}
}

T_DECL(assign_nullptr, "intrusive_shared_ptr.assign.nullptr") {
	tests<T>();
	tests<T const>();
}
