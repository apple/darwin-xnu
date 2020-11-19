//
// Tests for
//  explicit intrusive_shared_ptr(pointer p, retain_t);
//

#include <libkern/c++/intrusive_shared_ptr.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_policy.h"

struct T { int i; };

template <typename T, typename TQual>
static void
tests()
{
	T obj{0};

	{
		test_policy::retain_count = 0;
		libkern::intrusive_shared_ptr<TQual, test_policy> ptr(&obj, libkern::retain);
		CHECK(ptr.get() == &obj);
		CHECK(test_policy::retain_count == 1);
	}
	{
		test_policy::retain_count = 0;
		libkern::intrusive_shared_ptr<TQual, test_policy> ptr{&obj, libkern::retain};
		CHECK(ptr.get() == &obj);
		CHECK(test_policy::retain_count == 1);
	}
}

T_DECL(ctor_ptr_retain, "intrusive_shared_ptr.ctor.ptr.retain") {
	tests<T, T>();
	tests<T, T const>();
}
