//
// Tests for
//  void swap(safe_allocation& a, safe_allocation& b);
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
	// Swap non-null with non-null
	{
		tracked_safe_allocation<T> a(10, libkern::allocate_memory);
		tracked_safe_allocation<T> b(20, libkern::allocate_memory);
		T* a_mem = a.data();
		T* b_mem = b.data();
		tracking_allocator::reset();

		swap(a, b); // ADL call

		CHECK(!tracking_allocator::did_allocate);
		CHECK(!tracking_allocator::did_deallocate);
		CHECK(a.data() == b_mem);
		CHECK(b.data() == a_mem);
		CHECK(a.size() == 20);
		CHECK(b.size() == 10);
	}

	// Swap non-null with null
	{
		tracked_safe_allocation<T> a(10, libkern::allocate_memory);
		tracked_safe_allocation<T> b = nullptr;
		T* a_mem = a.data();
		tracking_allocator::reset();

		swap(a, b); // ADL call

		CHECK(!tracking_allocator::did_allocate);
		CHECK(!tracking_allocator::did_deallocate);
		CHECK(a.data() == nullptr);
		CHECK(b.data() == a_mem);
		CHECK(a.size() == 0);
		CHECK(b.size() == 10);
	}

	// Swap null with non-null
	{
		tracked_safe_allocation<T> a = nullptr;
		tracked_safe_allocation<T> b(20, libkern::allocate_memory);
		T* b_mem = b.data();
		tracking_allocator::reset();

		swap(a, b); // ADL call

		CHECK(!tracking_allocator::did_allocate);
		CHECK(!tracking_allocator::did_deallocate);
		CHECK(a.data() == b_mem);
		CHECK(b.data() == nullptr);
		CHECK(a.size() == 20);
		CHECK(b.size() == 0);
	}

	// Swap null with null
	{
		tracked_safe_allocation<T> a = nullptr;
		tracked_safe_allocation<T> b = nullptr;
		tracking_allocator::reset();

		swap(a, b); // ADL call

		CHECK(!tracking_allocator::did_allocate);
		CHECK(!tracking_allocator::did_deallocate);
		CHECK(a.data() == nullptr);
		CHECK(b.data() == nullptr);
		CHECK(a.size() == 0);
		CHECK(b.size() == 0);
	}

	// Swap with self
	{
		tracked_safe_allocation<T> a(10, libkern::allocate_memory);
		T* a_mem = a.data();
		tracking_allocator::reset();

		swap(a, a); // ADL call

		CHECK(!tracking_allocator::did_allocate);
		CHECK(!tracking_allocator::did_deallocate);
		CHECK(a.data() == a_mem);
		CHECK(a.size() == 10);
	}
}

T_DECL(swap, "safe_allocation.swap") {
	tests<T>();
	tests<T const>();
}
