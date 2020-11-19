//
// Tests for
//  T* unsafe_discard_bounds() const;
//

#include <libkern/c++/bounded_ptr.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

#define _assert(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

namespace {
struct tracking_policy {
	static bool did_trap;
	static void
	trap(char const*)
	{
		did_trap = true;
	}
};
bool tracking_policy::did_trap = false;
}

struct T { int i; };

template <typename T, typename QualT>
static void
tests()
{
	std::array<T, 5> array = {T{0}, T{1}, T{2}, T{3}, T{4}};

	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                                                ^
		//   |                                                |
		// begin, ptr                                        end
		test_bounded_ptr<QualT> const ptr(array.begin() + 0, array.begin(), array.end());
		QualT* raw = ptr.unsafe_discard_bounds();
		_assert(raw == &array[0]);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^        ^                                       ^
		//   |        |                                       |
		// begin     ptr                                     end
		test_bounded_ptr<QualT> const ptr(array.begin() + 1, array.begin(), array.end());
		QualT* raw = ptr.unsafe_discard_bounds();
		_assert(raw == &array[1]);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                 ^                              ^
		//   |                 |                              |
		// begin              ptr                            end
		test_bounded_ptr<QualT> const ptr(array.begin() + 2, array.begin(), array.end());
		QualT* raw = ptr.unsafe_discard_bounds();
		_assert(raw == &array[2]);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                                   ^            ^
		//   |                                   |            |
		// begin                                ptr          end
		test_bounded_ptr<QualT> const ptr(array.begin() + 4, array.begin(), array.end());
		QualT* raw = ptr.unsafe_discard_bounds();
		_assert(raw == &array[4]);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                                                ^
		//   |                                                |
		// begin                                           end,ptr
		test_bounded_ptr<QualT> const ptr(array.end(), array.begin(), array.end());
		QualT* raw = ptr.unsafe_discard_bounds();
		_assert(raw == array.end());
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                          ^        ^
		//   |                          |        |
		// begin                       end      ptr
		test_bounded_ptr<QualT> ptr(array.end() - 1, array.begin(), array.end() - 2);
		QualT* raw = ptr.unsafe_discard_bounds();
		_assert(raw == &array[4]);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^        ^                                        ^
		//   |        |                                        |
		// begin     ptr                                      end
		test_bounded_ptr<QualT> ptr(array.begin() + 1, array.begin(), array.end());
		QualT* raw = ptr.unsafe_discard_bounds();
		_assert(raw == &array[1]);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^        ^                                        ^
		//   |        |                                        |
		//  ptr     begin                                     end
		test_bounded_ptr<QualT> ptr(array.begin(), array.begin() + 1, array.end());
		QualT* raw = ptr.unsafe_discard_bounds();
		_assert(raw == &array[0]);
	}

	// Test discarding the bounds of a null pointer
	{
		test_bounded_ptr<QualT> const ptr(nullptr, nullptr, nullptr);
		QualT* raw = ptr.unsafe_discard_bounds();
		_assert(raw == nullptr);
	}

	// Test discarding the bounds on a pointer outside of representable memory.
	// Even `unsafe_discard_bounds()` will trap in such conditions.
	//
	// To do this, we setup an imaginary object with a very high address, and
	// we add a large-ish offset to it, such that adding the base to the offset
	// would fall outside of the representable memory.
	{
		tracking_policy::did_trap = false;

		QualT* end_of_memory = reinterpret_cast<QualT*>(std::numeric_limits<std::uintptr_t>::max());
		QualT* base = end_of_memory - 500; // yeah, technically UB
		std::ptrdiff_t offset = 501;

		libkern::bounded_ptr<QualT, tracking_policy> ptr(base, base, base + 1);
		ptr += offset; // now, `base_ + offset_` points outside of representable memory

		_assert(!tracking_policy::did_trap);
		(void)ptr.unsafe_discard_bounds();
		_assert(tracking_policy::did_trap);
	}
}

T_DECL(unsafe_discard_bounds, "bounded_ptr.unsafe_discard_bounds") {
	tests<T, T>();
	tests<T, T const>();
	tests<T, T volatile>();
	tests<T, T const volatile>();
}
