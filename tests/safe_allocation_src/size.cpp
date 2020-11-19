//
// Tests for
//      size_t size() const;
//

#include <libkern/c++/safe_allocation.h>
#include <darwintest.h>
#include "test_utils.h"
#include <cstddef>
#include <type_traits>
#include <utility>

struct T {
	int i;
};

template <typename T>
static void
tests()
{
	{
		test_safe_allocation<T> const array(10, libkern::allocate_memory);
		CHECK(array.size() == 10);
	}
	{
		T* memory = reinterpret_cast<T*>(malloc_allocator::allocate(10 * sizeof(T)));
		test_safe_allocation<T> const array(memory, 10, libkern::adopt_memory);
		CHECK(array.size() == 10);
	}
	{
		test_safe_allocation<T> const array(nullptr, 0, libkern::adopt_memory);
		CHECK(array.size() == 0);
	}
	{
		test_safe_allocation<T> const array;
		CHECK(array.size() == 0);
	}

	{
		using Size = decltype(std::declval<test_safe_allocation<T> const&>().size());
		static_assert(std::is_same_v<Size, std::size_t>);
	}
}

T_DECL(size, "safe_allocation.size") {
	tests<T>();
	tests<T const>();
}
