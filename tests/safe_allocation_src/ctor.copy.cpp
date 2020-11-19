//
// Tests for
//  safe_allocation(safe_allocation const&) = delete;
//

#include <libkern/c++/safe_allocation.h>
#include <type_traits>
#include <darwintest.h>
#include "test_utils.h"

struct T {
	int i;
};

T_DECL(ctor_copy, "safe_allocation.ctor.copy") {
	static_assert(!std::is_copy_constructible_v<test_safe_allocation<T> >);
	T_PASS("safe_allocation.ctor.copy passed");
}
