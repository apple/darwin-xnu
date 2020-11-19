//
// This tests that we can call functions implemented using raw pointers from
// an API vending itself as returning shared pointers, because both are ABI
// compatible.
//
// In this TU, SharedPtr<T> is intrusive_shared_ptr<T>, since USE_SHARED_PTR
// is defined.
//

#define USE_SHARED_PTR

#include <libkern/c++/intrusive_shared_ptr.h>
#include <darwintest.h>
#include "abi_helper.h"

static_assert(sizeof(SharedPtr<T>) == sizeof(T*));
static_assert(alignof(SharedPtr<T>) == alignof(T*));

// Receive a shared pointer from a function that actually returns a raw pointer
T_DECL(abi_caller_smart, "intrusive_shared_ptr.abi.caller.smart") {
	T obj{3};
	T* expected = &obj;
	SharedPtr<T> result = return_raw_as_shared(expected);
	CHECK(result.get() == expected);

	// Sometimes the test above passes even though it should fail, if the
	// right address happens to be on the stack in the right location. This
	// can happen if abi.caller.raw is run just before this test. This second
	// test makes sure it fails when it should.
	CHECK(result->i == 3);
}
