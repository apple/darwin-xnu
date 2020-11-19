//
// Tests for
//  template <typename T, typename Policy>
//  bool operator==(std::nullptr_t, bounded_ptr<T, Policy> const& p);
//
//  template <typename T, typename Policy>
//  bool operator!=(std::nullptr_t, bounded_ptr<T, Policy> const& p);
//
//  template <typename T, typename Policy>
//  bool operator==(bounded_ptr<T, Policy> const& p, std::nullptr_t);
//
//  template <typename T, typename Policy>
//  bool operator!=(bounded_ptr<T, Policy> const& p, std::nullptr_t);
//

#include <libkern/c++/bounded_ptr.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

#define _assert(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

struct T { };

struct non_default_policy {
	static constexpr void
	trap(char const*)
	{
	}
};

template <typename T, typename QualT>
static void
tests()
{
	T t;

	{
		test_bounded_ptr<QualT> const ptr(&t, &t, &t + 1);
		_assert(!(ptr == nullptr));
		_assert(!(nullptr == ptr));
		_assert(ptr != nullptr);
		_assert(nullptr != ptr);
	}
	{
		test_bounded_ptr<QualT> const ptr = nullptr;
		_assert(ptr == nullptr);
		_assert(nullptr == ptr);
		_assert(!(ptr != nullptr));
		_assert(!(nullptr != ptr));
	}

	// Test with a custom policy
	{
		libkern::bounded_ptr<QualT, non_default_policy> const ptr = nullptr;
		_assert(ptr == nullptr);
		_assert(nullptr == ptr);
		_assert(!(ptr != nullptr));
		_assert(!(nullptr != ptr));
	}
}

T_DECL(compare_equal_nullptr, "bounded_ptr.compare.equal.nullptr") {
	tests<T, T>();
	tests<T, T const>();
	tests<T, T volatile>();
	tests<T, T const volatile>();
}
