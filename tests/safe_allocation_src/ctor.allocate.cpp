//
// Tests for
//  explicit safe_allocation(size_t n, allocate_memory_t);
//

#include <libkern/c++/safe_allocation.h>
#include <darwintest.h>
#include "test_utils.h"
#include <cstddef>
#include <limits>

struct T {
	int i;
};

struct TrackInit {
	bool initialized;
	TrackInit() : initialized(true)
	{
	}
};

template <typename T>
static void
tests()
{
	{
		tracking_allocator::reset();
		{
			tracked_safe_allocation<T> array(10, libkern::allocate_memory);
			CHECK(tracking_allocator::allocated_size == 10 * sizeof(T));
			CHECK(array.data() != nullptr);
			CHECK(array.size() == 10);
			CHECK(array.begin() == array.data());
			CHECK(array.end() == array.data() + 10);
		}
		CHECK(tracking_allocator::deallocated_size == 10 * sizeof(T));
	}

	// Check with a huge number of elements that will overflow size_t
	{
		std::size_t max_n = std::numeric_limits<std::size_t>::max() / sizeof(T);
		tracking_allocator::reset();

		{
			tracked_safe_allocation<T> array(max_n + 1, libkern::allocate_memory);
			CHECK(array.data() == nullptr);
			CHECK(array.size() == 0);
			CHECK(array.begin() == array.end());
			CHECK(!tracking_allocator::did_allocate);
		}
		CHECK(!tracking_allocator::did_deallocate);
	}
}

T_DECL(ctor_allocate, "safe_allocation.ctor.allocate") {
	tests<T>();
	tests<T const>();

	// Make sure we value-initialize elements
	{
		tracked_safe_allocation<TrackInit> array(10, libkern::allocate_memory);
		for (int i = 0; i != 10; ++i) {
			CHECK(array[i].initialized == true);
		}
	}
}
