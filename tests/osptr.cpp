#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++11-extensions"

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

static int num_instances = 0;
static int num_retains = 0;
static int num_releases = 0;

class OSMetaClassBase
{
	static int id_counter;
	static OSMetaClassBase *freelist;

public:
	int inst_id;
	mutable int refcount;
	mutable OSMetaClassBase *next;
	static void *type_id;

	OSMetaClassBase() : refcount(1), next(nullptr)
	{
		inst_id = id_counter++;
		num_instances++;
		OSPTR_LOG("[%p, %d] constructed\n", this, inst_id);
	}

	virtual ~OSMetaClassBase()
	{
		OSPTR_LOG("[%p, %d] destroyed\n", this, inst_id);
	}

	virtual void
	retain() const
	{
		T_QUIET; T_EXPECT_GT_INT(refcount, 0, "Instance resurrected");
		refcount++;
		num_retains++;
		OSPTR_LOG("[%p, %d] retain, refcount=%d\n", this, inst_id, refcount);
	}

	virtual void
	release() const
	{
		T_QUIET; T_EXPECT_GT_INT(refcount, 0, "Double free");
		refcount--;
		num_releases++;
		OSPTR_LOG("[%p, %d] release, refcount=%d\n", this, inst_id, refcount);

		/*
		 * Don't delete the object, but keep it around so that we
		 * can detect double frees
		 */
		if (refcount == 0) {
			num_instances--;
			this->next = freelist;
			freelist = const_cast<OSMetaClassBase *>(this);
		}
	}

	virtual void
	taggedRetain(void *tag) const
	{
		OSPTR_LOG("tag[%p] ", tag);
		retain();
	}

	virtual void
	taggedRelease(void *tag) const
	{
		OSPTR_LOG("tag[%p] ", tag);
		release();
	}
};

int OSMetaClassBase::id_counter;
OSMetaClassBase *OSMetaClassBase::freelist;

void *OSMetaClassBase::type_id;

#define OSTypeID(T) T::type_id
#define OSTypeAlloc(T) new T
#define OSDynamicCast(T, p) dynamic_cast<T *>(p)

#define LIBKERN_SMART_POINTERS
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

class Other : public OSMetaClassBase {
public:
	Other() : OSMetaClassBase()
	{
	}
};

typedef OSPtr<Base> BasePtr;
typedef OSPtr<Derived> DerivedPtr;
typedef OSPtr<Other> OtherPtr;

static void
default_constructor()
{
	BasePtr a;
	T_ASSERT_NULL(a.get(), "Default NULL construction");
	T_ASSERT_EQ_INT(num_instances, 0, "No instances created");
}

static void
null_constructor()
{
	BasePtr a(nullptr);
	T_ASSERT_NULL(a.get(), "Default NULL construction");
	T_ASSERT_EQ_INT(num_instances, 0, "No instances created");
}

static void
raw_constructor()
{
	Base *a = new Base();
	T_ASSERT_EQ_INT(num_instances, 1, "Created instance");

	{
		BasePtr p(a);

		T_ASSERT_EQ_INT(num_instances, 1, "No new instance");
		T_ASSERT_EQ_PTR(p.get(), a, "osptr bound to correct object");
		T_ASSERT_EQ_INT(a->refcount, 2, "Object refcount incremented");
	}

	T_ASSERT_EQ_INT(a->refcount, 1, "Object refcount decremented");
	a->release();
	T_ASSERT_EQ_INT(num_instances, 0, "All instances released");
}

static void
alloc()
{
	BasePtr a = BasePtr::alloc();

	T_ASSERT_NOTNULL(a.get(), "osptr seated");
	T_ASSERT_EQ_INT(num_instances, 1, "Instance created");
	T_ASSERT_EQ_INT(a->refcount, 1, "Reference created");
}

static void
destroy()
{
	{
		BasePtr a = BasePtr::alloc();
		T_ASSERT_EQ_INT(num_instances, 1, "Instance created");
	}

	T_ASSERT_EQ_INT(num_instances, 0, "All instances released");
}

static void
copy()
{
	BasePtr a = BasePtr::alloc();
	BasePtr b;
	int a_id = a->inst_id;

	BasePtr a_copy(a);

	T_ASSERT_EQ_INT(a_copy->inst_id, a_id, NULL);
	T_ASSERT_EQ_INT(a->refcount, 2, NULL);
	T_ASSERT_EQ_INT(a_copy->refcount, 2, NULL);
	T_ASSERT_EQ_INT(num_instances, 1, NULL);
	T_EXPECT_EQ_INT(num_retains, 1, NULL);

	BasePtr b_copy(b);
	T_ASSERT_NULL(b_copy.get(), "Copy null osptr");

	T_ASSERT_EQ_INT(num_instances, 1, NULL);
	T_EXPECT_EQ_INT(num_retains, 1, NULL);

	BasePtr a_copy2 = a;
	T_ASSERT_EQ_PTR(a_copy2.get(), a.get(), NULL);

	T_ASSERT_EQ_INT(num_instances, 1, NULL);
	T_EXPECT_EQ_INT(num_retains, 2, NULL);
	T_EXPECT_EQ_INT(num_releases, 0, NULL);
}

static void
copy_subclass()
{
	auto a = DerivedPtr::alloc();
	BasePtr b(a);

	T_ASSERT_EQ_PTR(a.get(), b.get(), NULL);
	T_ASSERT_EQ_INT(b->refcount, 2, NULL);
	T_ASSERT_EQ_INT(num_instances, 1, NULL);

	a = nullptr;
	T_ASSERT_NOTNULL(b.get(), NULL);
	T_ASSERT_EQ_INT(b->refcount, 1, NULL);
	T_ASSERT_EQ_INT(num_instances, 1, NULL);
}

static void
assign()
{
	int a_id, b_id;

	BasePtr p;
	BasePtr a = BasePtr::alloc();
	BasePtr b = BasePtr::alloc();

	a_id = a->inst_id;
	b_id = b->inst_id;

	p = a;

	T_ASSERT_EQ_PTR(p.get(), a.get(), "Assigned osptr references same object");
	T_ASSERT_EQ_INT(p->inst_id, a_id, NULL);
	T_ASSERT_EQ_INT(a->refcount, 2, "Assigned osptr bumps refcount");
	T_QUIET; T_ASSERT_TRUE(b->refcount == 1, NULL);

	p = b;

	T_ASSERT_EQ_PTR(p.get(), b.get(), "Assigned osptr references same object");
	T_ASSERT_EQ_INT(p->inst_id, b_id, NULL);
	T_ASSERT_EQ_INT(a->refcount, 1, "Previous assignee drops reference");
	T_ASSERT_EQ_INT(b->refcount, 2, "New assignee bumps reference");

	T_ASSERT_EQ_INT(a->inst_id, a_id, NULL);
	T_ASSERT_EQ_INT(b->inst_id, b_id, NULL);

	a = nullptr;

	T_ASSERT_EQ_INT(num_instances, 1, "Assignment to null releases object");

	b = nullptr;
	p = nullptr;

	T_ASSERT_EQ_INT(num_instances, 0, "All instances released");
}

static void
assign_raw()
{
	Base *a1 = new Base();
	Base *a2 = new Base();

	{
		BasePtr p;

		p = a1;
		T_ASSERT_EQ_PTR(p.get(), a1, NULL);
		T_ASSERT_EQ_INT(a1->refcount, 2, NULL);
		T_ASSERT_EQ_INT(a2->refcount, 1, NULL);

		p = a2;
		T_ASSERT_EQ_PTR(p.get(), a2, NULL);
		T_ASSERT_EQ_INT(a1->refcount, 1, NULL);
		T_ASSERT_EQ_INT(a2->refcount, 2, NULL);
	}

	T_ASSERT_EQ_INT(a1->refcount, 1, NULL);
	T_ASSERT_EQ_INT(a2->refcount, 1, NULL);

	a1->release();
	a2->release();

	T_ASSERT_EQ_INT(num_instances, 0, "All instances released");
}

static void
assign_null()
{
	BasePtr a = BasePtr::alloc();
	T_ASSERT_EQ_INT(num_instances, 1, NULL);

	a = nullptr;

	T_ASSERT_NULL(a.get(), NULL);
	T_ASSERT_EQ_INT(num_instances, 0, "No instances created");

	a = BasePtr::alloc();
	BasePtr b(a.get());

	T_ASSERT_EQ_INT(a->refcount, 2, NULL);
	T_ASSERT_EQ_INT(num_instances, 1, NULL);

	b = nullptr;

	T_ASSERT_EQ_INT(a->refcount, 1, NULL);
	T_ASSERT_EQ_INT(num_instances, 1, NULL);

	a = nullptr;

	T_ASSERT_EQ_INT(num_instances, 0, "All instances released");
}

static void
assign_subclass()
{
	int a_id, b_id;

	OSPtr<OSMetaClassBase> base;
	BasePtr a = BasePtr::alloc();
	BasePtr b = BasePtr::alloc();

	a_id = a->inst_id;
	b_id = b->inst_id;

	base = a;

	T_ASSERT_TRUE(base.get() == static_cast<OSMetaClassBase *>(a.get()), NULL);
	T_ASSERT_TRUE(base->inst_id == a_id, NULL);
	T_ASSERT_TRUE(a->refcount == 2, NULL);
	T_ASSERT_TRUE(b->refcount == 1, NULL);

	base = b;

	T_ASSERT_TRUE(base.get() == static_cast<OSMetaClassBase *>(b.get()), NULL);
	T_ASSERT_TRUE(base->inst_id == b_id, NULL);
	T_ASSERT_TRUE(a->refcount == 1, NULL);
	T_ASSERT_TRUE(b->refcount == 2, NULL);

	T_ASSERT_TRUE(a->inst_id == a_id, NULL);
	T_ASSERT_TRUE(b->inst_id == b_id, NULL);

	a = nullptr;

	T_ASSERT_TRUE(num_instances == 1, NULL);

	b = nullptr;
	base = nullptr;

	T_ASSERT_EQ_INT(num_instances, 0, "All instances released");
}

static void
assign_compatible()
{
	OSPtr<Base> a = OSPtr<Base>::alloc();
	OSPtr<const Base> b = a;
	T_ASSERT_EQ_PTR(a.get(), b.get(), NULL);

	OSPtr<Derived> c = OSPtr<Derived>::alloc();
	OSPtr<Base> d = c;
	T_ASSERT_EQ_PTR(c.get(), d.get(), NULL);
}

static void
move()
{
	OSPtr<const Base> a = OSPtr<const Base>::alloc();
	int a_id = a->inst_id;

	OSPtr<const Base> b(os::move(a));

	T_ASSERT_TRUE(a.get() == NULL, NULL);
	T_ASSERT_TRUE(b->inst_id == a_id, NULL);
	T_ASSERT_TRUE(b->refcount == 1, NULL);
	T_ASSERT_TRUE(num_instances == 1, NULL);
	T_EXPECT_EQ_INT(num_retains, 0, NULL);
}

static void
move_assign()
{
	OSPtr<const Base> a = OSPtr<const Base>::alloc();
	OSPtr<const Base> b = OSPtr<const Base>::alloc();
	int a_id = a->inst_id;
	int b_id = b->inst_id;

	OSPtr<const Base> d;

	d = os::move(a);

	T_ASSERT_TRUE(a.get() == NULL, NULL);
	T_ASSERT_TRUE(d->inst_id == a_id, NULL);
	T_ASSERT_TRUE(d->refcount == 1, NULL);
	T_ASSERT_TRUE(num_instances == 2, NULL);

	d = os::move(b);
	T_ASSERT_TRUE(a.get() == NULL, NULL);
	T_ASSERT_TRUE(b.get() == NULL, NULL);
	T_ASSERT_TRUE(d->inst_id == b_id, NULL);
	T_ASSERT_TRUE(d->refcount == 1, NULL);
	T_ASSERT_TRUE(num_instances == 1, NULL);
	T_EXPECT_EQ_INT(num_retains, 0, NULL);
}

static void
move_assign_null()
{
	BasePtr a = BasePtr::alloc();
	BasePtr b = a;

	T_EXPECT_EQ_INT(num_retains, 1, NULL);

	a = os::move(nullptr);

	T_ASSERT_TRUE(a.get() == NULL, NULL);
	T_ASSERT_TRUE(b->refcount == 1, NULL);

	b = os::move(nullptr);

	T_ASSERT_EQ_INT(num_instances, 0, "All instances released");
	T_EXPECT_EQ_INT(num_retains, 1, NULL);
}

static void
move_assign_raw()
{
	BasePtr a = BasePtr::alloc();
	Base *b = new Base;
	Base *tmp = b;

	T_ASSERT_EQ_INT(num_instances, 2, NULL);

	a = os::move(tmp);

	T_ASSERT_EQ_INT(num_instances, 1, NULL);
	T_ASSERT_NULL(tmp, NULL);
	T_ASSERT_EQ_PTR(a.get(), b, NULL);
	T_ASSERT_EQ_INT(a->refcount, 2, NULL);
	b->release();
	T_ASSERT_EQ_INT(a->refcount, 1, NULL);
}

static void
move_assign_subclass()
{
	auto a = DerivedPtr::alloc();
	BasePtr b;

	b = os::move(a);

	T_ASSERT_NULL(a.get(), NULL);
	T_ASSERT_NOTNULL(b.get(), NULL);
	T_ASSERT_EQ_INT(b->refcount, 1, NULL);
	T_ASSERT_EQ_INT(num_instances, 1, NULL);
}

static void
move_assign_self()
{
	OSPtr<const Base> a = OSPtr<const Base>::alloc();
	int a_id = a->inst_id;

	a = os::move(a);

	T_ASSERT_NOTNULL(a.get(), "osptr seated");
	T_ASSERT_TRUE(a->inst_id == a_id, NULL);
	T_ASSERT_TRUE(a->refcount == 1, NULL);
	T_ASSERT_TRUE(num_instances == 1, NULL);
	T_EXPECT_EQ_INT(num_retains, 0, NULL);
}

static void
test_const_cast()
{
	OSPtr<const Base> a = OSPtr<const Base>::alloc();

	OSPtr<Base> b;

	b = a.const_pointer_cast<Base>();

	T_ASSERT_TRUE(a.get() == b.get(), NULL);
	T_ASSERT_TRUE(a->refcount == 2, NULL);
	T_ASSERT_TRUE(b->refcount == 2, NULL);

	T_ASSERT_TRUE(num_instances == 1, NULL);
	T_EXPECT_EQ_INT(num_retains, 1, NULL);
}

static void
const_cast_move()
{
	OSPtr<const Base> a = OSPtr<const Base>::alloc();
	int a_id = a->inst_id;

	OSPtr<Base> b;

	b = os::move(a).const_pointer_cast<Base>();

	T_ASSERT_TRUE(a.get() == NULL, NULL);
	T_ASSERT_TRUE(b->inst_id == a_id, NULL);
	T_ASSERT_TRUE(b->refcount == 1, NULL);

	T_ASSERT_TRUE(num_instances == 1, NULL);
	T_EXPECT_EQ_INT(num_retains, 0, NULL);
}

static void
const_cast_move_self()
{
	BasePtr a = BasePtr::alloc();
	int a_id = a->inst_id;

	a = os::move(a).const_pointer_cast<Base>();

	T_ASSERT_NOTNULL(a.get(), "osptr seated");
	T_ASSERT_TRUE(a->inst_id == a_id, NULL);
	T_ASSERT_TRUE(a->refcount == 1, NULL);
	T_ASSERT_TRUE(num_instances == 1, NULL);
	T_ASSERT_TRUE(num_retains == 0, NULL);
}

static void
test_static_cast()
{
	DerivedPtr a = DerivedPtr::alloc();

	BasePtr b;

	b = a.static_pointer_cast<Base>();

	T_ASSERT_TRUE(a.get() == b.get(), NULL);
	T_ASSERT_TRUE(a->refcount == 2, NULL);
	T_ASSERT_TRUE(b->refcount == 2, NULL);

	T_ASSERT_TRUE(num_instances == 1, NULL);
	T_EXPECT_TRUE(num_retains == 1, NULL);
}

static void
static_cast_move()
{
	DerivedPtr a = DerivedPtr::alloc();
	int a_id = a->inst_id;

	BasePtr b;

	b = os::move(a).static_pointer_cast<Base>();

	T_ASSERT_NULL(a.get(), NULL);
	T_ASSERT_EQ_INT(b->inst_id, a_id, NULL);
	T_ASSERT_EQ_INT(b->refcount, 1, NULL);

	T_ASSERT_EQ_INT(num_instances, 1, NULL);
	T_EXPECT_EQ_INT(num_retains, 0, NULL);
}

static void
static_cast_move_self()
{
	BasePtr a = BasePtr::alloc();
	int a_id = a->inst_id;

	a = os::move(a).static_pointer_cast<Base>();

	T_ASSERT_NOTNULL(a.get(), "osptr seated");
	T_ASSERT_TRUE(a->inst_id == a_id, NULL);
	T_ASSERT_TRUE(a->refcount == 1, NULL);
	T_ASSERT_TRUE(num_instances == 1, NULL);
	T_ASSERT_TRUE(num_retains == 0, NULL);
}

static void
tagged_ptr()
{
	OSTaggedPtr<Base, Derived> a;
	auto b = OSTaggedPtr<Derived, Base>::alloc();

	T_ASSERT_NULL(a.get(), NULL);
	T_ASSERT_NOTNULL(b.get(), NULL);

	T_ASSERT_TRUE(typeid(a.get()) == typeid(Base *), NULL);
	T_ASSERT_TRUE(typeid(b.get()) == typeid(Derived *), NULL);
}

static void
attach()
{
	Base *a = new Base();
	BasePtr b;
	b.attach(os::move(a));

	T_ASSERT_NULL(a, NULL);
	T_ASSERT_NOTNULL(b.get(), NULL);
	T_ASSERT_EQ_INT(b->refcount, 1, NULL);
	T_ASSERT_EQ_INT(num_instances, 1, NULL);
	T_ASSERT_EQ_INT(num_retains, 0, NULL);

	b.attach(new Base);
	T_ASSERT_NOTNULL(b.get(), NULL);
	T_ASSERT_EQ_INT(b->refcount, 1, NULL);
	T_ASSERT_EQ_INT(num_instances, 1, NULL);
	T_ASSERT_EQ_INT(num_retains, 0, NULL);
	T_ASSERT_EQ_INT(num_releases, 1, NULL);
}

static void
detach()
{
	BasePtr a = BasePtr::alloc();
	Base *p = a.detach();

	T_ASSERT_NULL(a.get(), NULL);
	T_ASSERT_NOTNULL(p, NULL);
	T_ASSERT_EQ_INT(p->refcount, 1, NULL);
	T_ASSERT_EQ_INT(num_instances, 1, NULL);
	T_ASSERT_EQ_INT(num_retains, 0, NULL);
	T_ASSERT_EQ_INT(num_releases, 0, NULL);

	BasePtr b(os::move(p), os::no_retain); // re-seat so that 'p' gets freed
}

static void
foreign()
{
	auto a = OSPtr<Base>::alloc();
	auto b = OSTaggedPtr<Base, Derived>::alloc();

	void *a_ptr = a.get();
	void *b_ptr = b.get();

	a.swap(b);

	T_ASSERT_EQ_PTR(b.get(), a_ptr, NULL);
	T_ASSERT_EQ_PTR(a.get(), b_ptr, NULL);
	T_ASSERT_EQ_INT(a->refcount, 1, NULL);
	T_ASSERT_EQ_INT(b->refcount, 1, NULL);
	T_ASSERT_EQ_INT(num_instances, 2, NULL);
	T_ASSERT_GE_INT(num_retains, 2, NULL);
}

static void
test_dynamic_cast()
{
	auto a = DerivedPtr::alloc();
	T_ASSERT_NOTNULL(a.get(), NULL);
	BasePtr b = a;

	auto c = b.dynamic_pointer_cast<Derived>();
	T_ASSERT_NOTNULL(c.get(), NULL);

	T_ASSERT_EQ_INT(c->refcount, 3, NULL);
	T_ASSERT_EQ_INT(num_instances, 1, NULL);

	auto d = OtherPtr::alloc();
	auto e = d.dynamic_pointer_cast<Derived>();
	auto f = OSDynamicCastPtr<Derived>(OtherPtr::alloc());

	T_ASSERT_NULL(e.get(), NULL);
	T_ASSERT_NULL(f.get(), NULL);

	T_ASSERT_EQ_INT(num_instances, 2, NULL);
	T_ASSERT_EQ_INT(d->refcount, 1, NULL);

	auto g = OSDynamicCastPtr<Base>(DerivedPtr::alloc());
	T_ASSERT_EQ_INT(num_instances, 3, NULL);
	T_ASSERT_EQ_INT(g->refcount, 1, NULL);
}

#define OSPTR_TEST_DECL(name) \
	T_DECL(name, #name) { \
	        num_instances = 0; \
	        num_retains = 0; \
	        num_releases = 0; \
	        name(); \
	        T_QUIET; T_ASSERT_EQ_INT(num_instances, 0, "Instance leak"); \
	}

OSPTR_TEST_DECL(default_constructor)
OSPTR_TEST_DECL(null_constructor)
OSPTR_TEST_DECL(raw_constructor)
OSPTR_TEST_DECL(alloc)
OSPTR_TEST_DECL(destroy)
OSPTR_TEST_DECL(copy)
OSPTR_TEST_DECL(copy_subclass)
OSPTR_TEST_DECL(assign)
OSPTR_TEST_DECL(assign_raw)
OSPTR_TEST_DECL(assign_null)
OSPTR_TEST_DECL(assign_subclass)
OSPTR_TEST_DECL(assign_compatible)
OSPTR_TEST_DECL(move)
OSPTR_TEST_DECL(move_assign)
OSPTR_TEST_DECL(move_assign_null)
OSPTR_TEST_DECL(move_assign_raw)
OSPTR_TEST_DECL(move_assign_subclass)
OSPTR_TEST_DECL(move_assign_self)
OSPTR_TEST_DECL(test_const_cast)
OSPTR_TEST_DECL(const_cast_move)
OSPTR_TEST_DECL(const_cast_move_self)
OSPTR_TEST_DECL(test_static_cast)
OSPTR_TEST_DECL(static_cast_move)
OSPTR_TEST_DECL(static_cast_move_self)
OSPTR_TEST_DECL(tagged_ptr)
OSPTR_TEST_DECL(attach)
OSPTR_TEST_DECL(detach)
OSPTR_TEST_DECL(foreign)
OSPTR_TEST_DECL(test_dynamic_cast)


/*
 * Test that the "trivial_abi" attribute works as expected
 */

struct Complex {
	uintptr_t val;
	Complex() : val(71)
	{
	}
	~Complex()
	{
	}
};

struct Trivial {
	uintptr_t val;
	Trivial() : val(42)
	{
	}
	~Trivial()
	{
	}
} __attribute__((trivial_abi));

/* defined in osptr_helper.cpp */
__BEGIN_DECLS
extern uintptr_t pass_trivial(Trivial);
extern uintptr_t pass_complex(Complex);
__END_DECLS
Trivial return_trivial(uintptr_t);
Complex return_complex(uintptr_t);

T_DECL(trivial_abi, "Test trivial_abi classes are passed by value")
{
	Trivial a;
	uintptr_t x = pass_trivial(a);
	T_EXPECT_EQ_ULONG(a.val, x, "Trivial class argument passed by-value");

	Complex b;
	uintptr_t y = pass_complex(b);
	T_EXPECT_NE_ULONG(b.val, y, "Non-trivial class argument passed by-reference");

	Trivial c = return_trivial(55);
	T_EXPECT_EQ_ULONG(c.val, 55UL, "Trivial class returned by-value");

	Complex d = return_complex(99);
	T_EXPECT_NE_ULONG(d.val, 99UL, "Non-trivial class returned by-reference");
}

#pragma clang diagnostic pop
