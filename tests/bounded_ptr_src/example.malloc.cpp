//
// Example of providing a malloc() wrapper that returns a `bounded_ptr`.
//
// This test serves as some kind of integration test, ensuring that we're
// able to convert existing code using raw pointers to using `bounded_ptr`s
// without too much hassle. This code was lifted from existing code in XNU,
// and the variable names were changed to make it more generic.
//

#include <libkern/c++/bounded_ptr.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <darwintest.h>
#include "test_utils.h"

test_bounded_ptr<void>
bounded_malloc(std::size_t size)
{
	void* p = std::malloc(size);
	void* end = static_cast<char*>(p) + size;
	test_bounded_ptr<void> with_bounds(p, p, end);
	return with_bounds;
}

void
bounded_free(test_bounded_ptr<void> ptr)
{
	std::free(ptr.discard_bounds());
}

struct SomeType {
	std::uint32_t idx;
};

// Pretend that those functions are already part of the code base being
// transitioned over to `bounded_ptr`s, and we can't change their signature.
// The purpose of having those functions is to make sure that we're able to
// integrate into existing code bases with decent ease.
void
use(SomeType*)
{
}
void
require(bool condition)
{
	if (!condition) {
		std::exit(EXIT_FAILURE);
	}
}

T_DECL(example_malloc, "bounded_ptr.example.malloc") {
	test_bounded_ptr<SomeType> array = nullptr;
	std::uint32_t count = 100;
	std::uint32_t alloc_size = count * sizeof(SomeType);

	// (1) must use a bounded version of malloc
	// (2) must use a reinterpret_pointer_cast to go from void* to SomeType*
	array = libkern::reinterpret_pointer_cast<SomeType>(bounded_malloc(alloc_size));

	require(array != nullptr); // use != nullptr instead of relying on implicit conversion to bool
	use(array.discard_bounds()); // must manually discard bounds here

	for (std::uint32_t i = 0; i < count; i++) {
		std::uint32_t& idx = array[i].idx;
		idx = i;
		use(&array[idx]);
	}

	if (array) {
		bounded_free(array); // must use a bounded version of free
	}

	T_PASS("bounded_ptr.example.malloc test done");
}
