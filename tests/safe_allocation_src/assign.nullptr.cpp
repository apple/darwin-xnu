//
// Tests for
//  safe_allocation& operator=(std::nullptr_t);
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
	// Assign to a non-null allocation
	{
		tracked_safe_allocation<T> array(10, libkern::allocate_memory);
		tracking_allocator::reset();

		tracked_safe_allocation<T>& ref = (array = nullptr);
		CHECK(&ref == &array);
		CHECK(array.data() == nullptr);
		CHECK(array.size() == 0);
		CHECK(tracking_allocator::did_deallocate);
	}

	// Assign to a null allocation
	{
		tracked_safe_allocation<T> array = nullptr;
		tracking_allocator::reset();

		tracked_safe_allocation<T>& ref = (array = nullptr);
		CHECK(&ref == &array);
		CHECK(array.data() == nullptr);
		CHECK(array.size() == 0);
		CHECK(!tracking_allocator::did_deallocate);
	}
}

T_DECL(assign_nullptr, "safe_allocation.assign.nullptr") {
	tests<T>();
	tests<T const>();
}
