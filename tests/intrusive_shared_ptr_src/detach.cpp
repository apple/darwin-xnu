//
// Tests for
//  pointer detach() noexcept;
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

	tracking_policy::reset();
	tracked_shared_ptr<T> ptr(&obj, libkern::retain);
	T* raw = ptr.detach();
	CHECK(raw == &obj);
	CHECK(ptr.get() == nullptr); // ptr was set to null
	CHECK(tracking_policy::retains == 1);
	CHECK(tracking_policy::releases == 0);
}

T_DECL(detach, "intrusive_shared_ptr.detach") {
	tests<T>();
	tests<T const>();
}
