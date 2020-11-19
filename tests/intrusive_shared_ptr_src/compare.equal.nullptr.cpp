//
// Tests for
//  template <typename T, typename R>
//  bool operator==(intrusive_shared_ptr<T, R> const& x, std::nullptr_t);
//
//  template <typename T, typename R>
//  bool operator!=(intrusive_shared_ptr<T, R> const& x, std::nullptr_t);
//
//  template <typename T, typename R>
//  bool operator==(std::nullptr_t, intrusive_shared_ptr<T, R> const& x);
//
//  template <typename T, typename R>
//  bool operator!=(std::nullptr_t, intrusive_shared_ptr<T, R> const& x);
//

#include <libkern/c++/intrusive_shared_ptr.h>
#include <darwintest.h>
#include "test_policy.h"

struct T { int i; };

template <typename T, typename U>
static void
check_eq(T t, U u)
{
	CHECK(t == u);
	CHECK(u == t);
	CHECK(!(t != u));
	CHECK(!(u != t));
}

template <typename T, typename U>
static void
check_ne(T t, U u)
{
	CHECK(!(t == u));
	CHECK(!(u == t));
	CHECK(t != u);
	CHECK(u != t);
}

template <typename T, typename TQual>
static void
tests()
{
	T obj{3};

	{
		test_shared_ptr<TQual> const a(&obj, libkern::no_retain);
		check_ne(a, nullptr);
	}

	{
		test_shared_ptr<TQual> const a = nullptr;
		check_eq(a, nullptr);
	}
}

T_DECL(compare_equal_nullptr, "intrusive_shared_ptr.compare.equal.nullptr") {
	tests<T, T>();
	tests<T, T const>();
}
