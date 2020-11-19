//
// Tests for
//  safe_allocation(safe_allocation&& other);
//

#include <libkern/c++/safe_allocation.h>
#include <darwintest.h>
#include "test_utils.h"
#include <utility>

struct T {
	int i;
};

template <typename T>
static void
tests()
{
	// Move-construct from a non-null allocation (with different syntaxes)
	{
		{
			tracked_safe_allocation<T> from(10, libkern::allocate_memory);
			tracking_allocator::reset();

			T* memory = from.data();

			{
				tracked_safe_allocation<T> to(std::move(from));
				CHECK(!tracking_allocator::did_allocate);
				CHECK(to.data() == memory);
				CHECK(to.size() == 10);
				CHECK(from.data() == nullptr);
				CHECK(from.size() == 0);
			}
			CHECK(tracking_allocator::did_deallocate);
			tracking_allocator::reset();
		}
		CHECK(!tracking_allocator::did_deallocate);
	}
	{
		{
			tracked_safe_allocation<T> from(10, libkern::allocate_memory);
			tracking_allocator::reset();

			T* memory = from.data();

			{
				tracked_safe_allocation<T> to{std::move(from)};
				CHECK(!tracking_allocator::did_allocate);
				CHECK(to.data() == memory);
				CHECK(to.size() == 10);
				CHECK(from.data() == nullptr);
				CHECK(from.size() == 0);
			}
			CHECK(tracking_allocator::did_deallocate);
			tracking_allocator::reset();
		}
		CHECK(!tracking_allocator::did_deallocate);
	}
	{
		{
			tracked_safe_allocation<T> from(10, libkern::allocate_memory);
			tracking_allocator::reset();

			T* memory = from.data();

			{
				tracked_safe_allocation<T> to = std::move(from);
				CHECK(!tracking_allocator::did_allocate);
				CHECK(to.data() == memory);
				CHECK(to.size() == 10);
				CHECK(from.data() == nullptr);
				CHECK(from.size() == 0);
			}
			CHECK(tracking_allocator::did_deallocate);
			tracking_allocator::reset();
		}
		CHECK(!tracking_allocator::did_deallocate);
	}

	// Move-construct from a null allocation
	{
		{
			tracked_safe_allocation<T> from = nullptr;
			tracking_allocator::reset();

			{
				tracked_safe_allocation<T> to(std::move(from));
				CHECK(!tracking_allocator::did_allocate);
				CHECK(to.data() == nullptr);
				CHECK(to.size() == 0);
				CHECK(from.data() == nullptr);
				CHECK(from.size() == 0);
			}
			CHECK(!tracking_allocator::did_deallocate);
			tracking_allocator::reset();
		}
		CHECK(!tracking_allocator::did_deallocate);
	}
}

T_DECL(ctor_move, "safe_allocation.ctor.move") {
	tests<T>();
	tests<T const>();
}
