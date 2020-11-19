//
// Tests for
//      safe_allocation& operator=(safe_allocation&& other);
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
	// Move-assign non-null to non-null
	{
		{
			tracked_safe_allocation<T> from(10, libkern::allocate_memory);
			T* memory = from.data();
			{
				tracked_safe_allocation<T> to(20, libkern::allocate_memory);
				tracking_allocator::reset();

				tracked_safe_allocation<T>& ref = (to = std::move(from));
				CHECK(&ref == &to);
				CHECK(to.data() == memory);
				CHECK(to.size() == 10);
				CHECK(from.data() == nullptr);
				CHECK(from.size() == 0);

				CHECK(!tracking_allocator::did_allocate);
				CHECK(tracking_allocator::deallocated_size == 20 * sizeof(T));
				tracking_allocator::reset();
			}
			CHECK(tracking_allocator::deallocated_size == 10 * sizeof(T));
			tracking_allocator::reset();
		}
		CHECK(!tracking_allocator::did_deallocate);
	}

	// Move-assign null to non-null
	{
		{
			tracked_safe_allocation<T> from = nullptr;
			{
				tracked_safe_allocation<T> to(20, libkern::allocate_memory);
				tracking_allocator::reset();

				tracked_safe_allocation<T>& ref = (to = std::move(from));
				CHECK(&ref == &to);
				CHECK(to.data() == nullptr);
				CHECK(to.size() == 0);
				CHECK(from.data() == nullptr);
				CHECK(from.size() == 0);

				CHECK(!tracking_allocator::did_allocate);
				CHECK(tracking_allocator::deallocated_size == 20 * sizeof(T));
				tracking_allocator::reset();
			}
			CHECK(!tracking_allocator::did_deallocate);
			tracking_allocator::reset();
		}
		CHECK(!tracking_allocator::did_deallocate);
	}

	// Move-assign non-null to null
	{
		{
			tracked_safe_allocation<T> from(10, libkern::allocate_memory);
			T* memory = from.data();
			{
				tracked_safe_allocation<T> to = nullptr;
				tracking_allocator::reset();

				tracked_safe_allocation<T>& ref = (to = std::move(from));
				CHECK(&ref == &to);
				CHECK(to.data() == memory);
				CHECK(to.size() == 10);
				CHECK(from.data() == nullptr);
				CHECK(from.size() == 0);

				CHECK(!tracking_allocator::did_allocate);
				CHECK(!tracking_allocator::did_deallocate);
				tracking_allocator::reset();
			}
			CHECK(tracking_allocator::deallocated_size == 10 * sizeof(T));
			tracking_allocator::reset();
		}
		CHECK(!tracking_allocator::did_deallocate);
	}

	// Move-assign null to null
	{
		{
			tracked_safe_allocation<T> from = nullptr;
			{
				tracked_safe_allocation<T> to = nullptr;
				tracking_allocator::reset();

				tracked_safe_allocation<T>& ref = (to = std::move(from));
				CHECK(&ref == &to);
				CHECK(to.data() == nullptr);
				CHECK(to.size() == 0);
				CHECK(from.data() == nullptr);
				CHECK(from.size() == 0);

				CHECK(!tracking_allocator::did_allocate);
				CHECK(!tracking_allocator::did_deallocate);
				tracking_allocator::reset();
			}
			CHECK(!tracking_allocator::did_deallocate);
			tracking_allocator::reset();
		}
		CHECK(!tracking_allocator::did_deallocate);
	}

	// Move-assign to self
	{
		{
			tracked_safe_allocation<T> obj(10, libkern::allocate_memory);
			T* memory = obj.data();

			tracking_allocator::reset();
			tracked_safe_allocation<T>& ref = (obj = std::move(obj));
			CHECK(&ref == &obj);
			CHECK(obj.data() == memory);
			CHECK(obj.size() == 10);
			CHECK(!tracking_allocator::did_allocate);
			CHECK(!tracking_allocator::did_deallocate);
			tracking_allocator::reset();
		}
		CHECK(tracking_allocator::deallocated_size == 10 * sizeof(T));
	}
}

T_DECL(assign_move, "safe_allocation.assign.move") {
	tests<T>();
	tests<T const>();
}
