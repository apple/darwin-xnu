//
// Tests for
//  ~intrusive_shared_ptr();
//

#include <libkern/c++/intrusive_shared_ptr.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_policy.h"

struct T { int i; };

T_DECL(dtor, "intrusive_shared_ptr.dtor") {
	// Destroy a non-null shared pointer
	{
		T obj{0};
		test_policy::retain_count = 3;

		{
			libkern::intrusive_shared_ptr<T, test_policy> ptr(&obj, libkern::no_retain);
			CHECK(test_policy::retain_count == 3);
		}

		CHECK(test_policy::retain_count == 2);
	}

	// Destroy a null shared pointer
	{
		test_policy::retain_count = 3;

		{
			libkern::intrusive_shared_ptr<T, test_policy> ptr = nullptr;
			CHECK(test_policy::retain_count == 3);
		}

		CHECK(test_policy::retain_count == 3); // not decremented
	}
}
