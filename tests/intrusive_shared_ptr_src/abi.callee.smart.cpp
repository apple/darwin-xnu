//
// Declare a function as returning a raw pointer (in the header), but
// implement it by returning a shared pointer. This represents a TU that
// would have been translated to shared pointers.
//
// In this TU, SharedPtr<T> is intrusive_shared_ptr<T>, since USE_SHARED_PTR
// is defined.
//

#define USE_SHARED_PTR

#include "abi_helper.h"

SharedPtr<T>
return_shared_as_raw(T* ptr)
{
	return SharedPtr<T>(ptr, libkern::no_retain);
}
