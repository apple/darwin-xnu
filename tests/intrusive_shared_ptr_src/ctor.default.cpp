//
// Tests for
//  intrusive_shared_ptr();
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
		libkern::intrusive_shared_ptr<T, test_policy> ptr;
		CHECK(ptr.get() == nullptr);
	}
	{
		libkern::intrusive_shared_ptr<T, test_policy> ptr{};
		CHECK(ptr.get() == nullptr);
	}
	{
		libkern::intrusive_shared_ptr<T, test_policy> ptr = libkern::intrusive_shared_ptr<T, test_policy>();
		CHECK(ptr.get() == nullptr);
	}
	{
		libkern::intrusive_shared_ptr<T, test_policy> ptr = {};
		CHECK(ptr.get() == nullptr);
	}
}

T_DECL(ctor_default, "intrusive_shared_ptr.ctor.default") {
	tests<T>();
}
