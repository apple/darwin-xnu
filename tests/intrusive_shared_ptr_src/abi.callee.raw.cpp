//
// Declare a function as returning a shared pointer (in the header), but
// implement it by returning a raw pointer. This represents a TU that would
// not have been translated to shared pointers yet.
//
// In this TU, SharedPtr<T> is just T* since USE_SHARED_PTR is not defined.
//

#include "abi_helper.h"

SharedPtr<T>
return_raw_as_shared(T* ptr)
{
	return ptr;
}
