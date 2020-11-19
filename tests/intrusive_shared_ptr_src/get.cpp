//
// Tests for
//  pointer get() const noexcept;
//

#include <libkern/c++/intrusive_shared_ptr.h>
#include "test_policy.h"
#include <darwintest.h>
#include <utility>

struct T {
	int i;
};

template <typename T>
static constexpr auto
can_call_get_on_temporary(int)->decltype(std::declval<test_shared_ptr<T> >().get(), bool ())
{
	return true;
}

template <typename T>
static constexpr auto
can_call_get_on_temporary(...)->bool
{
	return false;
}

template <typename T>
static void
tests()
{
	{
		T obj{3};
		tracking_policy::reset();
		tracked_shared_ptr<T> const ptr(&obj, libkern::retain);
		T* raw = ptr.get();
		CHECK(raw == &obj);
		CHECK(ptr.get() == raw); // ptr didn't change
		CHECK(tracking_policy::retains == 1);
		CHECK(tracking_policy::releases == 0);
	}

	static_assert(!can_call_get_on_temporary<T>(int{}), "");
}

T_DECL(get, "intrusive_shared_ptr.get") {
	tests<T>();
	tests<T const>();
}
