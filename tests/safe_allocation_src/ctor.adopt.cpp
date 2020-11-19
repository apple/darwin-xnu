//
// Tests for
//  explicit safe_allocation(T* data, size_t n, adopt_memory_t);
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
		T* memory = reinterpret_cast<T*>(tracking_allocator::allocate(10 * sizeof(T)));
		tracking_allocator::reset();
		{
			tracked_safe_allocation<T> array(memory, 10, libkern::adopt_memory);
			CHECK(!tracking_allocator::did_allocate);
			CHECK(array.data() == memory);
			CHECK(array.size() == 10);
			CHECK(array.begin() == array.data());
			CHECK(array.end() == array.data() + 10);
		}
		CHECK(tracking_allocator::deallocated_size == 10 * sizeof(T));
	}
}

T_DECL(ctor_adopt, "safe_allocation.ctor.adopt") {
	tests<T>();
	tests<T const>();
}
