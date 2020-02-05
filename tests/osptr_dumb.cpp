#include <darwintest.h>
#include <darwintest_utils.h>
#include <stdio.h>
#include <assert.h>
#include <typeinfo>

#if 0
# define OSPTR_LOG T_LOG
#elif 0
# define OSPTR_LOG printf
#else
# define OSPTR_LOG(x...)  do { } while(0)
#endif

T_GLOBAL_META(
	T_META_NAMESPACE("osptr"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(true)
	);

class OSMetaClassBase
{
public:
	virtual void
	retain() const
	{
	}
	virtual void
	release() const
	{
	}
	virtual void
	taggedRetain(void *tag) const
	{
	}
	virtual void
	taggedRelease(void *tag) const
	{
	}

	static void *type_id;
};

void *OSMetaClassBase::type_id;

#define OSTypeAlloc(T) new T
#define OSTypeID(T) T::type_id

#include <libkern/c++/OSPtr.h>

class Base : public OSMetaClassBase {
public:
	Base() : OSMetaClassBase()
	{
	}
};

class Derived : public Base {
public:
	Derived() : Base()
	{
	}
};

typedef OSPtr<Base> BasePtr;
typedef OSPtr<Derived> DerivedPtr;

T_DECL(dumb_osptr, "Dumb OSPtrs work")
{
	BasePtr x = nullptr;
	T_ASSERT_EQ_PTR(x, nullptr, NULL);
	T_ASSERT_TRUE(typeid(BasePtr) == typeid(Base *), NULL);
	T_ASSERT_TRUE(typeid(DerivedPtr) == typeid(Derived *), NULL);

	OSTaggedPtr<Base, Base> y = nullptr;
	OSTaggedPtr<Derived, Base> z = nullptr;
	T_ASSERT_EQ_PTR(y, nullptr, NULL);
	T_ASSERT_TRUE(typeid(y) == typeid(Base *), NULL);
	T_ASSERT_TRUE(typeid(z) == typeid(Derived *), NULL);
}
