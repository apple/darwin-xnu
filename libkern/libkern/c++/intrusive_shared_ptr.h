//
// Copyright (c) 2019 Apple, Inc. All rights reserved.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_START@
//
// This file contains Original Code and/or Modifications of Original Code
// as defined in and that are subject to the Apple Public Source License
// Version 2.0 (the 'License'). You may not use this file except in
// compliance with the License. The rights granted to you under the License
// may not be used to create, or enable the creation or redistribution of,
// unlawful or unlicensed copies of an Apple operating system, or to
// circumvent, violate, or enable the circumvention or violation of, any
// terms of an Apple operating system software license agreement.
//
// Please obtain a copy of the License at
// http://www.opensource.apple.com/apsl/ and read it before using this file.
//
// The Original Code and all software distributed under the License are
// distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
// EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
// Please see the License for the specific language governing rights and
// limitations under the License.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_END@
//

#ifndef XNU_LIBKERN_LIBKERN_CXX_INTRUSIVE_SHARED_PTR_H
#define XNU_LIBKERN_LIBKERN_CXX_INTRUSIVE_SHARED_PTR_H

namespace libkern {
namespace isp_detail {
// TODO: Consolidate these utilities with the ones used in other similar places.
using nullptr_t = decltype(nullptr);

template <typename T> T && declval() noexcept;

template <typename ...> using void_t = void;

template <typename T> struct is_lvalue_reference { static constexpr bool value = false; };
template <typename T> struct is_lvalue_reference<T&> { static constexpr bool value = true; };
template <typename T> constexpr bool is_lvalue_reference_v = is_lvalue_reference<T>::value;

template <typename T> constexpr bool is_empty_v = __is_empty(T);

template <typename T> struct remove_reference { using type = T; };
template <typename T> struct remove_reference<T&> { using type = T; };
template <typename T> struct remove_reference<T &&> { using type = T; };
template <typename T> using remove_reference_t = typename remove_reference<T>::type;

template <bool Cond, typename T = void> struct enable_if;
template <typename T> struct enable_if<true, T> { using type = T; };
template <bool Cond, typename T = void> using enable_if_t = typename enable_if<Cond, T>::type;

template <typename From, typename To> constexpr bool is_convertible_v = __is_convertible_to(From, To);

template <typename T>
constexpr T && forward(remove_reference_t<T>&t) noexcept {
	return static_cast<T &&>(t);
}

template <typename T>
constexpr T && forward(remove_reference_t<T>&& t) noexcept {
	static_assert(!is_lvalue_reference_v<T>,
	    "can not forward an rvalue as an lvalue");
	return static_cast<T &&>(t);
}

template <typename T>
constexpr remove_reference_t<T>&& move(T && t) noexcept {
	using RvalueRef = remove_reference_t<T>&&;
	return static_cast<RvalueRef>(t);
}

template <typename T, typename U>
using WhenComparable = void_t<
	decltype(declval<T>() == declval<U>()),
	decltype(declval<T>() != declval<U>())
	>;
} // end namespace isp_detail

struct no_retain_t {
	explicit constexpr no_retain_t()
	{
	}
};
struct retain_t {
	explicit constexpr retain_t()
	{
	}
};
inline constexpr no_retain_t no_retain{};
inline constexpr retain_t retain{};

// Smart pointer representing a shared resource.
//
// This shared pointer class implements a refcounted resource that uses
// a policy to manage the refcount. This allows various refcount
// implementations, notably ones where the refcount is contained
// in the pointed-to object.
//
// The refcounting policy must consist of the following two static functions:
//
//      static void RefcountPolicy::retain(T&);
//      static void RefcountPolicy::release(T&);
//
// The `retain` function is called whenever a new reference to the pointed-to
// object is created, and should increase the refcount. The `release` function
// is called whenever a reference to the pointed-to object is removed, and
// should decrease the refcount. These functions are always called with a
// reference to a valid object, i.e. there is no need to check whether the
// reference is null in `retain()` and `release()` (since this is already
// handled by the shared pointer).
//
// One notable difference between this shared pointer and most other shared
// pointer classes is that this shared pointer never destroys the pointed-to
// object. It relies on the `release()` function to do it whenever the refcount
// hits 0.
//
// Since this class represents a pointer to an object (as opposed to a range
// of objects), pointer arithmetic is not allowed on `intrusive_shared_ptr`s.
template <typename T, typename RefcountPolicy>
struct __attribute__((trivial_abi)) intrusive_shared_ptr {
	static_assert(isp_detail::is_empty_v<RefcountPolicy>,
	    "intrusive_shared_ptr only allows a stateless RefcountPolicy "
	    "because it must be ABI compatible with raw pointers.");

	// TODO: Add a check that `T` can be used with the `RefcountPolicy`

	using pointer = T *;
	using element_type = T;

	// Constructs a null shared pointer.
	//
	// A null shared pointer can't be dereferenced, but it can be checked
	// for nullness, assigned to, reset, etc.
	constexpr intrusive_shared_ptr() noexcept : ptr_(nullptr) {
	}
	constexpr intrusive_shared_ptr(isp_detail::nullptr_t) noexcept : ptr_(nullptr) {
	}

	// Constructs a shared pointer to the given object, incrementing the
	// refcount for that object.
	//
	// This constructor is adequate when transforming a raw pointer with
	// shared ownership into a shared pointer, when the raw pointer is at
	// +1. This can be done by replacing the raw pointer and the manual call
	// to `retain()` by a shared pointer constructed with this constructor,
	// which will retain the pointed-to object.
	//
	// If the original code did not contain a manual retain and you use this
	// constructor, you will create a leak.
	explicit
	intrusive_shared_ptr(pointer p, retain_t) noexcept : ptr_(p) {
		if (ptr_ != nullptr) {
			RefcountPolicy::retain(*ptr_);
		}
	}

	// Constructs a shared pointer to the given object, without incrementing
	// the refcount for that object.
	//
	// This constructor is adequate when transforming a raw pointer with
	// shared ownership into a shared pointer, when the raw pointer is at
	// +0. This can be done by replacing the raw pointer by a shared
	// pointer constructed with this constructor, which does not retain
	// the pointed-to object.
	//
	// If the original code contained a manual retain that you removed and
	// you use this constructor, you will cause a use-after-free bug.
	explicit constexpr
	intrusive_shared_ptr(pointer p, no_retain_t) noexcept : ptr_(p) {
	}

	// Makes a copy of a shared pointer, incrementing the refcount.
	//
	// Since this creates a new reference to the pointed-to object, the
	// refcount is increased. Unlike for move operations, the source
	// pointer is left untouched.
	intrusive_shared_ptr(intrusive_shared_ptr const & other) : ptr_(other.ptr_) {
		if (ptr_ != nullptr) {
			RefcountPolicy::retain(*ptr_);
		}
	}

	// Makes a copy of a shared pointer from another compatible shared pointer,
	// increasing the refcount.
	//
	// This converting constructor is enabled whenever `U*` is implicitly
	// convertible to `T*`. This allows the usual implicit conversions
	// between base-and-derived types.
	//
	// Since this creates a new reference to the pointed-to object, the
	// refcount is increased. Unlike for move operations, the source
	// pointer is left untouched.
	template <typename U, typename = isp_detail::enable_if_t<isp_detail::is_convertible_v<U*, T*> > >
	intrusive_shared_ptr(intrusive_shared_ptr<U, RefcountPolicy> const & other) : ptr_(other.ptr_) {
		if (ptr_ != nullptr) {
			RefcountPolicy::retain(*ptr_);
		}
	}

	// Moves a shared pointer into another one, nulling the source.
	//
	// Since this moves the ownership from one pointer to another, no
	// refcount increment or decrement is required. The moved-from pointer
	// becomes a null pointer, as if it had been default-constructed.
	constexpr intrusive_shared_ptr(intrusive_shared_ptr && other) noexcept : ptr_(other.ptr_) {
		other.ptr_ = nullptr;
	}

	// Moves a shared pointer to a type `U` into a shared pointer
	// to a type `T`.
	//
	// This converting constructor is enabled whenever `U*` is implicitly
	// convertible to `T*`. This allows the usual implicit conversions
	// between base-and-derived types.
	//
	// Since this moves the ownership from one pointer to another, no
	// refcount increment or decrement is required. The moved-from pointer
	// becomes a null pointer, as if it had been default-constructed.
	template <typename U, typename = isp_detail::enable_if_t<isp_detail::is_convertible_v<U*, T*> > >
	constexpr intrusive_shared_ptr(intrusive_shared_ptr<U, RefcountPolicy>&& other) noexcept : ptr_(other.ptr_) {
		other.ptr_ = nullptr;
	}

	// Destroys a shared pointer.
	//
	// The destruction of the shared pointer implies that one fewer reference
	// to the pointed-to object exist, which means that the refcount of the
	// pointed-to object is decremented.
	//
	// If that decrement causes the refcount to reach 0, the refcounting
	// policy must destroy the pointed-to object and perform any cleanup
	// associated to it (such as freeing the allocated memory).
	~intrusive_shared_ptr() {
		reset();
	}

	// Copy-assigns a shared pointer.
	//
	// Since this creates a new reference to the pointed-to object, the
	// refcount is increased. Unlike for move operations, the source
	// pointer is left untouched.
	//
	// If the destination shared pointer is pointing to an object before
	// the assignment, the refcount is decremented on that object after
	// the assignment is performed.
	intrusive_shared_ptr&
	operator=(intrusive_shared_ptr const& other)
	{
		reset(other.get(), retain);
		return *this;
	}

	// Copy-assigns a shared pointer, enabling implicit conversions.
	//
	// This converting copy-assignment is enabled whenever `U*` is implicitly
	// convertible to `T*`. This allows the usual implicit conversions
	// between base-and-derived types.
	//
	// Since this creates a new reference to the pointed-to object, the
	// refcount is increased. Unlike for move operations, the source
	// pointer is left untouched.
	//
	// If the destination shared pointer is pointing to an object before
	// the assignment, the refcount is decremented on that object after
	// the assignment is performed.
	template <typename U, typename = isp_detail::enable_if_t<isp_detail::is_convertible_v<U*, T*> > >
	intrusive_shared_ptr&
	operator=(intrusive_shared_ptr<U, RefcountPolicy> const& other)
	{
		reset(other.get(), retain);
		return *this;
	}

	// Move-assigns a shared pointer.
	//
	// Since this moves the ownership from one pointer to another, no
	// refcount increment or decrement is required. The moved-from pointer
	// becomes a null pointer, as if it had been default-constructed.
	//
	// If the destination shared pointer is pointing to an object before
	// the assignment, the refcount is decremented on that object after
	// the assignment is performed.
	intrusive_shared_ptr&
	operator=(intrusive_shared_ptr&& other)
	{
		reset(other.get(), no_retain);
		other.ptr_ = nullptr;
		return *this;
	}

	// Move-assigns a shared pointer, enabling implicit conversions.
	//
	// This converting move-assignment is enabled whenever `U*` is implicitly
	// convertible to `T*`. This allows the usual implicit conversions
	// between base-and-derived types.
	//
	// Since this moves the ownership from one pointer to another, no
	// refcount increment or decrement is required. The moved-from pointer
	// becomes a null pointer, as if it had been default-constructed.
	//
	// If the destination shared pointer is pointing to an object before
	// the assignment, the refcount is decremented on that object after
	// the assignment is performed.
	template <typename U, typename = isp_detail::enable_if_t<isp_detail::is_convertible_v<U*, T*> > >
	intrusive_shared_ptr&
	operator=(intrusive_shared_ptr<U, RefcountPolicy>&& other)
	{
		reset(other.get(), no_retain);
		other.ptr_ = nullptr;
		return *this;
	}

	// Resets a shared pointer to a null pointer, as if calling `reset()`.
	//
	// If the destination shared pointer is pointing to an object before
	// the assignment, the refcount is decremented on that object after
	// the assignment is performed.
	intrusive_shared_ptr&
	operator=(isp_detail::nullptr_t) noexcept
	{
		reset();
		return *this;
	}

	// Returns a reference to the object pointed-to by the shared pointer.
	constexpr T&
	operator*() const noexcept
	{
		return *ptr_;
	}
	constexpr pointer
	operator->() const noexcept
	{
		return ptr_;
	}

	// Implicit conversion to bool, returning whether the shared pointer is null.
	explicit constexpr
	operator bool() const noexcept
	{
		return ptr_ != nullptr;
	}

	// Sets a shared pointer to null.
	//
	// If the shared pointer is pointing to an object, the refcount is
	// decremented on that object.
	intrusive_shared_ptr&
	reset() noexcept
	{
		if (ptr_ != nullptr) {
			RefcountPolicy::release(*ptr_);
		}
		ptr_ = nullptr;
		return *this;
	}

	// Sets the object pointed-to by the shared pointer to the given object.
	//
	// This variant of `reset()` does not increment the refcount on the object
	// assigned to the shared pointer.
	//
	// If the shared pointer is pointing to an object before calling `reset`,
	// the refcount is decremented on that object.
	intrusive_shared_ptr&
	reset(pointer p, no_retain_t) noexcept
	{
		if (ptr_ != nullptr) {
			RefcountPolicy::release(*ptr_);
		}
		ptr_ = p;
		return *this;
	}

	// Sets the object pointed-to by the shared pointer to the given object.
	//
	// This variant of `reset()` increments the refcount on the object
	// assigned to the shared pointer.
	//
	// If the shared pointer is pointing to an object before calling `reset`,
	// the refcount is decremented on that object.
	intrusive_shared_ptr&
	reset(pointer p, retain_t) noexcept
	{
		// Make sure we don't release-before-we-retain in case of self-reset
		pointer old = ptr_;
		ptr_ = p;
		if (ptr_ != nullptr) {
			RefcountPolicy::retain(*ptr_);
		}
		if (old != nullptr) {
			RefcountPolicy::release(*old);
		}
		return *this;
	}

	// Retrieves the raw pointer held by a shared pointer.
	//
	// The primary intended usage of this function is to aid bridging between
	// code that uses shared pointers and code that does not, or simply to
	// obtain a non-owning reference to the object managed by the shared pointer.
	//
	// After this operation, the shared pointer still manages the object it
	// points to (unlike for `detach()`).
	//
	// One must not hold on to the pointer returned by `.get()` after the
	// last shared pointer pointing to that object goes out of scope, since
	// it will then be a dangling pointer. To try and catch frequent cases of
	// misuse, calling `.get()` on a temporary shared pointer is not allowed.
	constexpr pointer
	get() const & noexcept
	{
		return ptr_;
	}

	constexpr pointer
	    get() const&& noexcept = delete;

	// Returns the raw pointer contained in a shared pointer, detaching
	// ownership management from the shared pointer.
	//
	// This operation returns a pointer to the object pointed-to by the
	// shared pointer, and severes the link between the shared pointer and
	// that object. After this operation, the shared pointer is no longer
	// responsible for managing the object, and instead whoever called
	// `detach()` has that responsibility.
	//
	// `detach()` does _not_ decrement the refcount of the pointee, since
	// the caller of `detach()` is responsible for managing the lifetime of
	// that object.
	//
	// After a call to `detach()`, the shared pointer is null since it has
	// no more object to manage.
	constexpr pointer
	detach() noexcept
	{
		pointer tmp = ptr_;
		ptr_ = nullptr;
		return tmp;
	}

private:
	friend constexpr void
	swap(intrusive_shared_ptr& a, intrusive_shared_ptr& b) noexcept
	{
		pointer tmp = a.ptr_;
		a.ptr_ = b.ptr_;
		b.ptr_ = tmp;
	}

	// For access to other.ptr_ in converting operations
	template <typename U, typename Policy>
	friend struct intrusive_shared_ptr;

	pointer ptr_;
};

// Casts a shared pointer to a type `T` to a shared pointer to a type `U`
// using `static_cast` on the underlying pointer type.
//
// The version of this function that takes a const reference to the source
// shared pointer makes a copy, and as such it increments the refcount of the
// pointed-to object (since a new reference is created). It leaves the source
// shared pointer untouched.
//
// The version of this function that takes a rvalue-reference moves the
// ownership from the source shared pointer to the destination shared pointer.
// It does not increment the refcount, and the source shared pointer is in a
// moved-from state (i.e. null).
template <typename To, typename From, typename R>
intrusive_shared_ptr<To, R>
static_pointer_cast(intrusive_shared_ptr<From, R> const& ptr)
{
	return intrusive_shared_ptr<To, R>(static_cast<To*>(ptr.get()), retain);
}
template <typename To, typename From, typename R>
intrusive_shared_ptr<To, R>
static_pointer_cast(intrusive_shared_ptr<From, R>&& ptr)
{
	return intrusive_shared_ptr<To, R>(static_cast<To*>(ptr.detach()), no_retain);
}

// Const-casts a shared pointer to a type `cv-T` to a shared pointer to a
// type `T` (without cv-qualifiers) using `const_cast` on the underlying
// pointer type.
//
// The version of this function that takes a const reference to the source
// shared pointer makes a copy, and as such it increments the refcount of the
// pointed-to object (since a new reference is created). It leaves the source
// shared pointer untouched.
//
// The version of this function that takes a rvalue-reference moves the
// ownership from the source shared pointer to the destination shared pointer.
// It does not increment the refcount, and the source shared pointer is in a
// moved-from state (i.e. null).
template <typename To, typename From, typename R>
intrusive_shared_ptr<To, R>
const_pointer_cast(intrusive_shared_ptr<From, R> const& ptr) noexcept
{
	return intrusive_shared_ptr<To, R>(const_cast<To*>(ptr.get()), retain);
}
template <typename To, typename From, typename R>
intrusive_shared_ptr<To, R>
const_pointer_cast(intrusive_shared_ptr<From, R>&& ptr) noexcept
{
	return intrusive_shared_ptr<To, R>(const_cast<To*>(ptr.detach()), no_retain);
}

// Casts a shared pointer to a type `T` to a shared pointer to a type `U`
// using `reinterpret_cast` on the underlying pointer type.
//
// The version of this function that takes a const reference to the source
// shared pointer makes a copy, and as such it increments the refcount of the
// pointed-to object (since a new reference is created). It leaves the source
// shared pointer untouched.
//
// The version of this function that takes a rvalue-reference moves the
// ownership from the source shared pointer to the destination shared pointer.
// It does not increment the refcount, and the source shared pointer is in a
// moved-from state (i.e. null).
//
// WARNING:
// This function makes it possible to cast pointers between unrelated types.
// This rarely makes sense, and when it does, it can often point to a design
// problem. You should have red lights turning on when you're about to use
// this function.
template<typename To, typename From, typename R>
intrusive_shared_ptr<To, R>
reinterpret_pointer_cast(intrusive_shared_ptr<From, R> const& ptr) noexcept
{
	return intrusive_shared_ptr<To, R>(reinterpret_cast<To*>(ptr.get()), retain);
}
template<typename To, typename From, typename R>
intrusive_shared_ptr<To, R>
reinterpret_pointer_cast(intrusive_shared_ptr<From, R>&& ptr) noexcept
{
	return intrusive_shared_ptr<To, R>(reinterpret_cast<To*>(ptr.detach()), no_retain);
}

// Comparison operations between:
// - two shared pointers
// - a shared pointer and nullptr_t
// - a shared pointer and a raw pointer
template <typename T, typename U, typename R, typename = isp_detail::WhenComparable<T*, U*> >
bool
operator==(intrusive_shared_ptr<T, R> const& x, intrusive_shared_ptr<U, R> const& y)
{
	return x.get() == y.get();
}

template <typename T, typename U, typename R, typename = isp_detail::WhenComparable<T*, U*> >
bool
operator!=(intrusive_shared_ptr<T, R> const& x, intrusive_shared_ptr<U, R> const& y)
{
	return x.get() != y.get();
}

template <typename T, typename U, typename R, typename = isp_detail::WhenComparable<T*, U*> >
bool
operator==(intrusive_shared_ptr<T, R> const& x, U* y)
{
	return x.get() == y;
}

template <typename T, typename U, typename R, typename = isp_detail::WhenComparable<T*, U*> >
bool
operator!=(intrusive_shared_ptr<T, R> const& x, U* y)
{
	return x.get() != y;
}

template <typename T, typename U, typename R, typename = isp_detail::WhenComparable<T*, U*> >
bool
operator==(T* x, intrusive_shared_ptr<U, R> const& y)
{
	return x == y.get();
}

template <typename T, typename U, typename R, typename = isp_detail::WhenComparable<T*, U*> >
bool
operator!=(T* x, intrusive_shared_ptr<U, R> const& y)
{
	return x != y.get();
}

template <typename T, typename R>
bool
operator==(intrusive_shared_ptr<T, R> const& x, isp_detail::nullptr_t) noexcept
{
	return x.get() == nullptr;
}

template <typename T, typename R>
bool
operator==(isp_detail::nullptr_t, intrusive_shared_ptr<T, R> const& x) noexcept
{
	return nullptr == x.get();
}

template <typename T, typename R>
bool
operator!=(intrusive_shared_ptr<T, R> const& x, isp_detail::nullptr_t) noexcept
{
	return x.get() != nullptr;
}

template <typename T, typename R>
bool
operator!=(isp_detail::nullptr_t, intrusive_shared_ptr<T, R> const& x) noexcept
{
	return nullptr != x.get();
}
} // end namespace libkern

#endif // !XNU_LIBKERN_LIBKERN_CXX_INTRUSIVE_SHARED_PTR_H
