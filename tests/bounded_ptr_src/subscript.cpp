//
// Tests for
//  T& operator[](std::ptrdiff_t n) const;
//

#include <libkern/c++/bounded_ptr.h>
#include <array>
#include <cstddef>
#include <darwintest.h>
#include <darwintest_utils.h>
#include "test_utils.h"

#define _assert(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

struct T {
	int i;
	friend constexpr bool
	operator==(T const& a, T const& b)
	{
		return a.i == b.i;
	}
};

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
		test_bounded_ptr<QualT> ptr(array.begin() + 0, array.begin(), array.end());
		QualT& ref0 = ptr[0];
		_assert(&ref0 == &array[0]);

		QualT& ref1 = ptr[1];
		_assert(&ref1 == &array[1]);

		QualT& ref2 = ptr[2];
		_assert(&ref2 == &array[2]);

		QualT& ref3 = ptr[3];
		_assert(&ref3 == &array[3]);

		QualT& ref4 = ptr[4];
		_assert(&ref4 == &array[4]);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^        ^                                       ^
		//   |        |                                       |
		// begin     ptr                                     end
		test_bounded_ptr<QualT> ptr(array.begin() + 1, array.begin(), array.end());
		QualT& ref0 = ptr[-1];
		_assert(&ref0 == &array[0]);

		QualT& ref1 = ptr[0];
		_assert(&ref1 == &array[1]);

		QualT& ref2 = ptr[1];
		_assert(&ref2 == &array[2]);

		QualT& ref3 = ptr[2];
		_assert(&ref3 == &array[3]);

		QualT& ref4 = ptr[3];
		_assert(&ref4 == &array[4]);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                 ^                              ^
		//   |                 |                              |
		// begin              ptr                            end
		test_bounded_ptr<QualT> ptr(array.begin() + 2, array.begin(), array.end());
		QualT& ref0 = ptr[-2];
		_assert(&ref0 == &array[0]);

		QualT& ref1 = ptr[-1];
		_assert(&ref1 == &array[1]);

		QualT& ref2 = ptr[0];
		_assert(&ref2 == &array[2]);

		QualT& ref3 = ptr[1];
		_assert(&ref3 == &array[3]);

		QualT& ref4 = ptr[2];
		_assert(&ref4 == &array[4]);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                                   ^            ^
		//   |                                   |            |
		// begin                                ptr          end
		test_bounded_ptr<QualT> ptr(array.begin() + 4, array.begin(), array.end());
		QualT& ref0 = ptr[-4];
		_assert(&ref0 == &array[0]);

		QualT& ref1 = ptr[-3];
		_assert(&ref1 == &array[1]);

		QualT& ref2 = ptr[-2];
		_assert(&ref2 == &array[2]);

		QualT& ref3 = ptr[-1];
		_assert(&ref3 == &array[3]);

		QualT& ref4 = ptr[0];
		_assert(&ref4 == &array[4]);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                                                ^
		//   |                                                |
		// begin                                           end,ptr
		test_bounded_ptr<QualT> ptr(array.end(), array.begin(), array.end());
		QualT& ref0 = ptr[-5];
		_assert(&ref0 == &array[0]);

		QualT& ref1 = ptr[-4];
		_assert(&ref1 == &array[1]);

		QualT& ref2 = ptr[-3];
		_assert(&ref2 == &array[2]);

		QualT& ref3 = ptr[-2];
		_assert(&ref3 == &array[3]);

		QualT& ref4 = ptr[-1];
		_assert(&ref4 == &array[4]);
	}

	// Make sure we trap when we subscript a pointer at an out-of-bounds offset
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^                          ^        ^
		//   |                          |        |
		// begin                       end      ptr
		libkern::bounded_ptr<QualT, tracking_policy> ptr(array.end() - 1, array.begin(), array.end() - 2);

		tracking_policy::did_trap = false;
		(void)ptr[-4];
		_assert(!tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[-3];
		_assert(!tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[-2];
		_assert(!tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[-1]; // trap
		_assert(tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[0]; // trap
		_assert(tracking_policy::did_trap);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^        ^                                        ^
		//   |        |                                        |
		// begin     ptr                                      end
		libkern::bounded_ptr<QualT, tracking_policy> ptr(array.begin() + 1, array.begin(), array.end());

		tracking_policy::did_trap = false;
		(void)ptr[-1];
		_assert(!tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[0];
		_assert(!tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[1];
		_assert(!tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[2];
		_assert(!tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[3];
		_assert(!tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[4]; // trap
		_assert(tracking_policy::did_trap);
	}
	{
		// T{0}     T{1}     T{2}     T{3}     T{4}     <one-past-last>
		//   ^        ^                          ^
		//   |        |                          |
		//  ptr     begin                       end
		libkern::bounded_ptr<QualT, tracking_policy> ptr(array.begin(), array.begin() + 1, array.end() - 1);

		tracking_policy::did_trap = false;
		(void)ptr[0]; // trap
		_assert(tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[1];
		_assert(!tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[2];
		_assert(!tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[3];
		_assert(!tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[4]; // trap
		_assert(tracking_policy::did_trap);

		tracking_policy::did_trap = false;
		(void)ptr[5]; // trap
		_assert(tracking_policy::did_trap);
	}
}

T_DECL(subscript, "bounded_ptr.subscript") {
	tests<T, T>();
	tests<T, T const>();
	tests<T, T volatile>();
	tests<T, T const volatile>();

	// Make sure that we don't hard-error in the definition of operator[]
	// when instantiating a `bounded_ptr<cv-void>`
	test_bounded_ptr<void> p1;
	test_bounded_ptr<void const> p2;
	test_bounded_ptr<void volatile> p3;
	test_bounded_ptr<void const volatile> p4;
}
