//
// Tests for
//  safe_allocation& operator=(safe_allocation const&) = delete;
//

#include <libkern/c++/safe_allocation.h>
#include <type_traits>
#include <darwintest.h>
#include "test_utils.h"

struct T { };

T_DECL(assign_copy, "safe_allocation.assign.copy") {
	static_assert(!std::is_copy_assignable_v<test_safe_allocation<T> >);
	T_PASS("safe_allocation.assign.copy passed");
}
