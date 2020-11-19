//
// Tests for
//  intrusive_shared_ptr(nullptr_t);
//

#include <libkern/c++/intrusive_shared_ptr.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_policy.h"

struct T { int i; };

template <typename T>
static void
tests()
{
	{
		libkern::intrusive_shared_ptr<T, test_policy> ptr = nullptr;
		CHECK(ptr.get() == nullptr);
	}
	{
		libkern::intrusive_shared_ptr<T, test_policy> ptr{nullptr};
		CHECK(ptr.get() == nullptr);
	}
	{
		libkern::intrusive_shared_ptr<T, test_policy> ptr(nullptr);
		CHECK(ptr.get() == nullptr);
	}
}

T_DECL(ctor_nullptr, "intrusive_shared_ptr.ctor.nullptr") {
	tests<T>();
}
