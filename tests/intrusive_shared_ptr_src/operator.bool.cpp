//
// Tests for
//      explicit constexpr operator bool() const noexcept;
//

#include <libkern/c++/intrusive_shared_ptr.h>
#include <type_traits>
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

	{
		test_shared_ptr<T> const ptr(&obj, libkern::no_retain);
		CHECK(static_cast<bool>(ptr));
		if (ptr) {
		} else {
			CHECK(false);
		}
	}

	{
		test_shared_ptr<T> const ptr = nullptr;
		CHECK(!static_cast<bool>(ptr));
		if (!ptr) {
		} else {
			CHECK(false);
		}
	}

	static_assert(!std::is_convertible_v<test_shared_ptr<T>, bool>);
}

T_DECL(operator_bool, "intrusive_shared_ptr.operator.bool") {
	tests<T>();
	tests<T const>();
}
