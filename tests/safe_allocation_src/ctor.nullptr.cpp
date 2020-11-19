//
// Tests for
//  safe_allocation(std::nullptr_t);
//

#include <libkern/c++/safe_allocation.h>
#include <darwintest.h>
#include "test_utils.h"

struct T {
	int i;
};

template <typename T>
static void
tests()
{
	{
		test_safe_allocation<T> array(nullptr);
		CHECK(array.data() == nullptr);
		CHECK(array.size() == 0);
		CHECK(array.begin() == array.end());
	}
	{
		test_safe_allocation<T> array{nullptr};
		CHECK(array.data() == nullptr);
		CHECK(array.size() == 0);
		CHECK(array.begin() == array.end());
	}
	{
		test_safe_allocation<T> array = nullptr;
		CHECK(array.data() == nullptr);
		CHECK(array.size() == 0);
		CHECK(array.begin() == array.end());
	}
	{
		auto f = [](test_safe_allocation<T> array) {
			    CHECK(array.data() == nullptr);
			    CHECK(array.size() == 0);
			    CHECK(array.begin() == array.end());
		    };
		f(nullptr);
	}
}

T_DECL(ctor_nullptr, "safe_allocation.ctor.nullptr") {
	tests<T>();
	tests<T const>();
}
