//
// Tests for
//      T* data();
//      T const* data() const;
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
		test_safe_allocation<T> array(10, libkern::allocate_memory);
		CHECK(array.data() != nullptr);
	}
	{
		T* memory = reinterpret_cast<T*>(malloc_allocator::allocate(10 * sizeof(T)));
		test_safe_allocation<T> array(memory, 10, libkern::adopt_memory);
		T* data = array.data();
		CHECK(data == memory);
	}
	{
		T* memory = reinterpret_cast<T*>(malloc_allocator::allocate(10 * sizeof(T)));
		test_safe_allocation<T> const array(memory, 10, libkern::adopt_memory);
		T const* data = array.data();
		CHECK(data == memory);
	}
}

T_DECL(data, "safe_allocation.data") {
	tests<T>();
	tests<T const>();
}
