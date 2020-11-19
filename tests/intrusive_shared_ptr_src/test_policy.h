#ifndef TESTS_INTRUSIVE_SHARED_PTR_TEST_POLICY_H
#define TESTS_INTRUSIVE_SHARED_PTR_TEST_POLICY_H

#include <libkern/c++/intrusive_shared_ptr.h>
#include <darwintest_utils.h>

struct test_policy {
	static inline int retain_count = 0;

	template <typename T>
	static void
	retain(T&)
	{
		++retain_count;
	}
	template <typename T>
	static void
	release(T&)
	{
		--retain_count;
	}
};

struct tracking_policy {
	static inline int retains = 0;
	static inline int releases = 0;
	static inline int refcount = 0;
	static inline bool hit_zero = false;

	static void
	reset()
	{
		retains = 0;
		releases = 0;
		refcount = 0;
		hit_zero = false;
	}

	template <typename T>
	static void
	retain(T&)
	{
		++retains;
		++refcount;
	}
	template <typename T>
	static void
	release(T&)
	{
		++releases;
		--refcount;
		if (refcount == 0) {
			hit_zero = true;
		}
	}
};

template <int>
struct dummy_policy {
	template <typename T>
	static void
	retain(T&)
	{
	}
	template <typename T>
	static void
	release(T&)
	{
	}
};

template <typename T>
using tracked_shared_ptr = libkern::intrusive_shared_ptr<T, tracking_policy>;

template <typename T>
using test_shared_ptr = libkern::intrusive_shared_ptr<T, test_policy>;

#define CHECK(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

#endif // !TESTS_INTRUSIVE_SHARED_PTR_TEST_POLICY_H
