//
// Tests for
//  T* discard_bounds() const;
//

#include <libkern/c++/bounded_ptr.h>
#include <array>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

#define _assert(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

struct T { int i; };

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
		QualT* raw = ptr.discard_bounds();
		_assert(raw == &array[0]);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^        ^                                       ^
		//   |        |                                       |
		// begin     ptr                                     end
		test_bounded_ptr<QualT> const ptr(array.begin() + 1, array.begin(), array.end());
		QualT* raw = ptr.discard_bounds();
		_assert(raw == &array[1]);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                 ^                              ^
		//   |                 |                              |
		// begin              ptr                            end
		test_bounded_ptr<QualT> const ptr(array.begin() + 2, array.begin(), array.end());
		QualT* raw = ptr.discard_bounds();
		_assert(raw == &array[2]);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                                   ^            ^
		//   |                                   |            |
		// begin                                ptr          end
		test_bounded_ptr<QualT> const ptr(array.begin() + 4, array.begin(), array.end());
		QualT* raw = ptr.discard_bounds();
		_assert(raw == &array[4]);
	}
	// Make sure we don't trap when discarding the bounds of an in-bounds pointer
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^        ^                                        ^
		//   |        |                                        |
		// begin     ptr                                      end
		libkern::bounded_ptr<QualT, tracking_policy> ptr(array.begin() + 1, array.begin(), array.end());
		tracking_policy::did_trap = false;
		(void)*ptr;
		(void)ptr->i;
		_assert(!tracking_policy::did_trap);
	}

	// Make sure we trap when discarding the bounds of an out-of-bounds pointer
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                          ^        ^
		//   |                          |        |
		// begin                       end      ptr
		libkern::bounded_ptr<QualT, tracking_policy> ptr(array.end() - 1, array.begin(), array.end() - 2);
		tracking_policy::did_trap = false;
		(void)ptr.discard_bounds();
		_assert(tracking_policy::did_trap);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^        ^                                        ^
		//   |        |                                        |
		//  ptr     begin                                     end
		libkern::bounded_ptr<QualT, tracking_policy> ptr(array.begin(), array.begin() + 1, array.end());
		tracking_policy::did_trap = false;
		(void)ptr.discard_bounds();
		_assert(tracking_policy::did_trap);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                             ^     ^
		//   |            (just a bit off) |     |
		// begin                          ptr   end
		T* t3 = const_cast<T*>(array.begin() + 3);
		char* just_off = reinterpret_cast<char*>(t3) + 1; // 1 byte off
		libkern::bounded_ptr<QualT, tracking_policy> ptr(reinterpret_cast<QualT*>(just_off), array.begin(), array.end() - 1);

		tracking_policy::did_trap = false;
		(void)ptr.discard_bounds();
		_assert(tracking_policy::did_trap);
	}
}

T_DECL(discard_bounds, "bounded_ptr.discard_bounds") {
	tests<T, T>();
	tests<T, T const>();
	tests<T, T volatile>();
	tests<T, T const volatile>();
}
