//
// Make sure we can #include OSPtr.h under various version of the C++ Standard.
//

#include <darwintest.h>
#include <libkern/c++/OSPtr.h>

T_GLOBAL_META(
	T_META_NAMESPACE("osptr"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(true)
	);

#define CONCAT_PRIM(x, y) x ## y
#define CONCAT(x, y) CONCAT_PRIM(x, y)
T_DECL(CONCAT(osptr_compat_, OSPTR_STD), "osptr.compat") {
	T_PASS("OSPtr compatibility test passed");
}
