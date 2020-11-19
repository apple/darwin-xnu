//
// This tests that we can call functions implemented using shared pointers
// from an API vending itself as returning raw pointers, because both are
// ABI compatible.
//
// In this TU, SharedPtr<T> is just T*, since USE_SHARED_PTR is not defined.
//

#include <darwintest.h>
#include "abi_helper.h"

// Receive a raw pointer from a function that actually returns a smart pointer
T_DECL(abi_caller_raw, "intrusive_shared_ptr.abi.caller.raw") {
	T obj{10};
	T* expected = &obj;
	T* result = return_shared_as_raw(expected);
	CHECK(result == expected);

	// Sometimes the test above passes even though it should fail, if the
	// right address happens to be on the stack in the right location. This
	// can happen if abi.caller.smart is run just before this test. This
	// second test makes sure it fails when it should.
	CHECK(result->i == 10);
}
