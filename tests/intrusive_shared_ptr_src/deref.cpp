//
// Tests for
//  T& operator*() const noexcept;
//  T* operator->() const noexcept;
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
	tracked_shared_ptr<T> ptr(&obj, libkern::no_retain);

	{
		T& ref = *ptr;
		CHECK(&ref == &obj);
		CHECK(ref.i == 3);
	}

	{
		int const& ref = ptr->i;
		CHECK(&ref == &obj.i);
		CHECK(ref == 3);
	}
}

T_DECL(deref, "intrusive_shared_ptr.deref") {
	tests<T>();
	tests<T const>();
}
