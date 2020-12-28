#include <stdint.h>
#include <darwintest.h>
#include <darwintest_utils.h>

#include "../libkern/os/ptrtools.h"

#define CHECK_ALIGNMENT(T) \
{ \
	T *__p; \
	T_QUIET; T_EXPECT_EQ_ULONG(__alignof__(*__p), sizeof(*__p), #T " native alignment"); \
	T_ASSERT_EQ_ULONG(__alignof__(os_unaligned_deref(__p)), 1UL, #T " alignment"); \
}

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

struct A {
	int a;
};

T_DECL(os_unaligned, "Unaligned pointer access")
{
	int x = 0x914842;
	int *p = &x;

	T_ASSERT_EQ_INT(os_unaligned_deref(p), x, "load");
	os_unaligned_deref(&x) = INT_MIN;
	T_ASSERT_EQ_INT(x, INT_MIN, "store");

	CHECK_ALIGNMENT(unsigned);
	CHECK_ALIGNMENT(long long);
	CHECK_ALIGNMENT(uintptr_t);
	CHECK_ALIGNMENT(int16_t);
	CHECK_ALIGNMENT(uint64_t);
	CHECK_ALIGNMENT(struct A);
	CHECK_ALIGNMENT(void *);
}
