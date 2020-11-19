//
// Tests for
//  template <typename T, typename Alloc, typename TrappingPolicy>
//  bool operator==(std::nullptr_t, safe_allocation<T, Alloc, TrappingPolicy> const& x);
//
//  template <typename T, typename Alloc, typename TrappingPolicy>
//  bool operator!=(std::nullptr_t, safe_allocation<T, Alloc, TrappingPolicy> const& x);
//
//  template <typename T, typename Alloc, typename TrappingPolicy>
//  bool operator==(safe_allocation<T, Alloc, TrappingPolicy> const& x, std::nullptr_t);
//
//  template <typename T, typename Alloc, typename TrappingPolicy>
//  bool operator!=(safe_allocation<T, Alloc, TrappingPolicy> const& x, std::nullptr_t);
//

#include <libkern/c++/safe_allocation.h>
#include <darwintest.h>
#include "test_utils.h"

struct T { };

template <typename T>
static void
tests()
{
	{
		test_safe_allocation<T> const array(10, libkern::allocate_memory);
		CHECK(!(array == nullptr));
		CHECK(!(nullptr == array));
		CHECK(array != nullptr);
		CHECK(nullptr != array);
	}
	{
		test_safe_allocation<T> const array = nullptr;
		CHECK(array == nullptr);
		CHECK(nullptr == array);
		CHECK(!(array != nullptr));
		CHECK(!(nullptr != array));
	}
}

T_DECL(compare_equal_nullptr, "safe_allocation.compare.equal.nullptr") {
	tests<T>();
	tests<T const>();
}
