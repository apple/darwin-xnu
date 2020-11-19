//
// Tests for
//  ~safe_allocation();
//

#include <libkern/c++/safe_allocation.h>
#include <darwintest.h>
#include "test_utils.h"

struct TriviallyDestructible {
	int i;
};

struct NonTriviallyDestructible {
	int i;
	~NonTriviallyDestructible()
	{
	}
};

template <typename T>
static void
tests()
{
	// Destroy a non-null allocation
	{
		{
			tracked_safe_allocation<T> array(10, libkern::allocate_memory);
			tracking_allocator::reset();
		}
		CHECK(tracking_allocator::deallocated_size == 10 * sizeof(T));
	}

	// Destroy a null allocation
	{
		{
			tracked_safe_allocation<T> array = nullptr;
			tracking_allocator::reset();
		}
		CHECK(!tracking_allocator::did_deallocate);
	}
}

T_DECL(dtor, "safe_allocation.dtor") {
	tests<TriviallyDestructible>();
	tests<TriviallyDestructible const>();

	tests<NonTriviallyDestructible>();
	tests<NonTriviallyDestructible const>();
}
