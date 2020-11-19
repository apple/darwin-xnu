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

#ifndef XNU_LIBKERN_LIBKERN_CXX_BOUNDED_PTR_H
#define XNU_LIBKERN_LIBKERN_CXX_BOUNDED_PTR_H

#include <stddef.h>
#include <stdint.h>
#include <os/overflow.h>
#include <os/base.h>

#if !defined(__improbable)
#   define __improbable(...) __builtin_expect((__VA_ARGS__), 0)
#endif

namespace libkern {
namespace detail {
// Reimplementation of things in <type_traits> because we don't seem
// to have the right to rely on the C++ Standard Library (based on
// attempts to compile IOHIDFamily).
// TODO: Do we really need to re-implement this here?
template <typename ...> using void_t = void;
template <typename T> T && declval() noexcept;
using nullptr_t = decltype(nullptr);
template <bool Cond, typename T = void> struct enable_if;
template <typename T> struct enable_if<true, T> { using type = T; };
template <bool Cond, typename T = void> using enable_if_t = typename enable_if<Cond, T>::type;
template <typename T1, typename T2>
constexpr bool is_convertible_v = __is_convertible_to(T1, T2);

template <typename T> inline constexpr bool is_void_v = false;
template <> inline constexpr bool is_void_v<void> = true;
template <> inline constexpr bool is_void_v<void const> = true;

template <typename T, typename U> struct copy_const { using type = U; };
template <typename T, typename U> struct copy_const<T const, U> { using type = U const; };
template <typename T, typename U> using copy_const_t = typename copy_const<T, U>::type;

template <typename T, typename U> struct copy_cv { using type = U; };
template <typename T, typename U> struct copy_cv<T const, U> { using type = U const; };
template <typename T, typename U> struct copy_cv<T volatile, U> { using type = U volatile; };
template <typename T, typename U> struct copy_cv<T const volatile, U> { using type = U const volatile; };
template <typename T, typename U> using copy_cv_t = typename copy_cv<T, U>::type;

template <typename T, typename U>
using WhenComparable = void_t<
	decltype(declval<T>() == declval<U>()),
	decltype(declval<T>() != declval<U>())
	>;

template <typename T, typename U>
using WhenOrderable = void_t <
    decltype(declval<T>() < declval<U>()),
decltype(declval<T>() > declval<U>()),
decltype(declval<T>() >= declval<U>()),
decltype(declval<T>() <= declval<U>())
>;

// Pretend that sizeof(void) is 1, otherwise the in-bounds check doesn't
// make sense for `bounded_ptr<void>`.
template <typename T> constexpr size_t sizeof_v = sizeof(T);
template <>           inline constexpr size_t sizeof_v<void> = 1;
template <>           inline constexpr size_t sizeof_v<void const> = 1;
template <>           inline constexpr size_t sizeof_v<void volatile> = 1;
template <>           inline constexpr size_t sizeof_v<void const volatile> = 1;
} // end namespace detail

// Non-owning pointer to an object (or a range of objects) of type `T`
// that validates that the address is within some specified bounds on
// dereference-like operations.
//
// Conceptually, a `bounded_ptr` points within a range of memory `[begin, end)`.
// If accessing any part of the result of dereferencing the pointer would
// lead to an access outside of the `[begin, end)` range, the pointer is
// said to be out-of-bounds. Due to representational constraints, the range
// of in-bounds memory must be no larger than 4GB.
//
// Dereference-like operations (dereference, subscript, pointer member access)
// validate that the pointer is not out-of-bounds. If an out-of-bounds pointer
// is dereferenced, the `TrappingPolicy` is called as
// `TrappingPolicy::trap(some-message)`, and the operation is said to "trap".
// This terminology is used below to describe the behavior of the `TrappingPolicy`.
//
// Pointer arithmetic is allowed (and the bounds are not validated), so it is
// entirely possible to make a `bounded_ptr` point outside of its range.
// However, overflow checking is performed on arithmetic operations, and
// any operation resulting in an overflow will also "trap".
//
// The behavior of the `TrappingPolicy` can be customized as desired, however
// a trap should never return, causing the current `bounded_ptr` operation to
// be aborted. This is important since the trap could signify an integer
// overflow, a null-pointer dereference or something else that would lead to
// undefined behavior (UB) if `TrappingPolicy::trap` were to return.
//
// Creation of `bounded_ptr`s
// ==========================
// `bounded_ptr` provides a single constructor allowing the bounds of the
// pointer to be specified. When integrating `bounded_ptr` into an existing
// code base, it is recommended to use `bounded_ptr` as an iterator obtained
// from other container-like abstractions, instead of manually using the
// constructor that allows specifying a range. Specifying the range manually
// on construction is error-prone, and `bounded_ptr` can't help reduce
// out-of-bounds accesses if the bounds are specified incorrectly.
//
// Furthermore, it is a design choice to not provide a constructor that uses
// relative offsets from the pointer itself to determine the range, because
// such a constructor is deemed more confusing than helpful. For example, is
// the offset a number of bytes or a number of objects? Is the offset inclusive
// or exclusive? Instead, factory functions should be used to create `bounded_ptr`s.
//
// Remark on const-ness
// ====================
// Like for raw pointers, the const-ness of a `bounded_ptr` has no bearing on
// whether the pointee is const. Hence, it is possible to obtain a non-const
// reference to an object from a const `bounded_ptr`. To encode a
// pointer-to-const, simply create a `bounded_ptr<T const>`.
template <typename T, typename TrappingPolicy>
struct __attribute__((trivial_abi)) bounded_ptr {
private:
	using CharType = detail::copy_cv_t<T, char>;

public:
	// Creates a null `bounded_ptr`.
	//
	// A null `bounded_ptr` does not point to any object and is conceptually
	// out of bounds, so dereferencing it will trap. "Observing" operations
	// like comparison and check-for-null, along with assignment, are valid
	// operations on a null `bounded_ptr`.
	OS_ALWAYS_INLINE constexpr
	bounded_ptr(detail::nullptr_t)
		: base_(nullptr), count_(0), offset_(0)
	{
	}

	OS_ALWAYS_INLINE constexpr
	explicit
	bounded_ptr()
		: bounded_ptr(nullptr)
	{
	}

	// Creates a `bounded_ptr` pointing to the given object, and whose bounds
	// are described by the provided `[begin, end)` range.
	//
	// This constructor does not check whether the constructed pointer is
	// within its bounds. However, it does check that the provided `[begin, end)`
	// range is a valid range (that is, `begin <= end`).
	//
	// Furthermore, the number of bytes in the range of in-bounds memory must be
	// representable by a uint32_t, which means that there can be no more than
	// 2^32 bytes (i.e. 4GB) in that range. Otherwise, the constructor will trap.
	OS_ALWAYS_INLINE explicit
	bounded_ptr(T* pointer, T const* begin, T const* end)
	{
		base_ = reinterpret_cast<CharType*>(const_cast<T*>(begin));

		// Store (end - begin) into count_, making sure we don't overflow
		if (__improbable(os_sub_overflow(reinterpret_cast<uintptr_t>(end),
		    reinterpret_cast<uintptr_t>(begin),
		    &count_))) {
			TrappingPolicy::trap("The range of valid memory is too large to be represented "
			    "by this type, or [begin, end) is not a well-formed range");
		}

		// Store (pointer - begin) into offset_, making sure we don't overflow.
		// Note that offset_ can be negative if `pointer` is outside of the
		// range delimited by [begin, end), which can be valid if it represents
		// e.g. a subrange of an array.
		if (__improbable(os_sub_overflow(reinterpret_cast<uintptr_t>(pointer),
		    reinterpret_cast<uintptr_t>(begin),
		    &offset_))) {
			TrappingPolicy::trap("The offset of the pointer inside its valid memory "
			    "range can't be represented using int32_t");
		}
	}

	// Creates a `bounded_ptr` to a type `T` from a `bounded_ptr` to a type `U`.
	//
	// This converting constructor is enabled whenever `U*` is implicitly
	// convertible to `T*`. This allows the usual implicit conversions
	// between base-and-derived types, and also from any type `U*` to a
	// `void*`. If other casts (like between unrelated pointer types) are
	// desired, `libkern::reinterpret_pointer_cast` can be used instead.
	//
	// The bounds on the resulting `bounded_ptr` are inherited from the
	// original `bounded_ptr`.
	template <typename U, typename Policy, typename = detail::enable_if_t<detail::is_convertible_v<U*, T*> > >
	OS_ALWAYS_INLINE
	bounded_ptr(bounded_ptr<U, Policy> const & other)
		: base_(other.base_)
		, count_(other.count_)
		, offset_(static_cast<int32_t>(reinterpret_cast<CharType*>(static_cast<T*>(other.get_ptr_())) - other.base_))
	{
	}

	// Assigns a `bounded_ptr` to a type `U` to a `bounded_ptr` to a type `T`,
	// as long as `U*` is convertible to `T*`.
	//
	// This is a rebinding operation, like assignment between raw pointers,
	// and the destination `bounded_ptr` will inherit the bounds of the
	// source `bounded_ptr`.
	template <typename U, typename Policy, typename = detail::enable_if_t<detail::is_convertible_v<U*, T*> > >
	OS_ALWAYS_INLINE bounded_ptr&
	operator=(bounded_ptr<U, Policy> const& other)
	{
		base_ = other.base_;
		count_ = other.count_;
		offset_ = static_cast<int32_t>(reinterpret_cast<CharType*>(static_cast<T*>(other.get_ptr_())) - other.base_);
		return *this;
	}

	// Sets a `bounded_ptr` to null.
	//
	// This is effectively equivalent to assigning a default-constructed
	// `bounded_ptr` to the target. As a result, the original bounds of
	// the `bounded_ptr` are discarded, and the resulting `bounded_ptr`
	// is both out-of-bounds and also has no bounds assigned to it (like
	// a default-constructed `bounded_ptr`).
	OS_ALWAYS_INLINE bounded_ptr&
	operator=(detail::nullptr_t)
	{
		*this = bounded_ptr();
		return *this;
	}

	// Returns a reference to the object pointed-to by the `bounded_ptr`.
	//
	// Traps if the pointer is pointing outside of its bounds.
	//
	// Also note that this function will trap when dereferencing a null
	// `bounded_ptr`, unless the bounds of the pointer have been set and
	// include address 0, in which case there's effectively nothing to
	// diagnose.
	template <typename T_ = T> // delay instantiation to avoid forming invalid ref for bounded_ptr<void>
	OS_ALWAYS_INLINE T_&
	operator*() const
	{
		if (__improbable(!in_bounds_())) {
			TrappingPolicy::trap("bounded_ptr<T>::operator*: Dereferencing this pointer "
			    "would access memory outside of the bounds set originally");
		}
		return *get_ptr_();
	}

	OS_ALWAYS_INLINE T*
	operator->() const
	{
		if (__improbable(!in_bounds_())) {
			TrappingPolicy::trap("bounded_ptr<T>::operator->: Accessing a member through this pointer "
			    "would access memory outside of the bounds set originally");
		}
		return get_ptr_();
	}

	// Provides access to the n-th element past the given pointer.
	//
	// The `bounded_ptr` validates whether the provided index is within the
	// bounds of the `bounded_ptr`. Like for raw pointers, a negative index
	// may be passed, in which case the pointer is accessed at a negative
	// offset (which must still be in bounds).
	template <typename T_ = T> // delay instantiation to avoid forming invalid ref for bounded_ptr<void>
	OS_ALWAYS_INLINE T_&
	operator[](ptrdiff_t n) const
	{
		return *(*this + n);
	}

	// Converts a `bounded_ptr` to a raw pointer, after checking it is within
	// its bounds.
	//
	// The primary intended usage of this function is to aid bridging between
	// code that uses `bounded_ptr`s and code that does not.
	OS_ALWAYS_INLINE T*
	discard_bounds() const
	{
		if (__improbable(!in_bounds_())) {
			TrappingPolicy::trap("bounded_ptr<T>::discard_bounds: Discarding the bounds on "
			    "this pointer would lose the fact that it is outside of the "
			    "bounds set originally");
		}
		return get_ptr_();
	}

	// Converts a `bounded_ptr` to a raw pointer, without checking whether the
	// pointer is within its bounds.
	//
	// Like `discard_bounds()`, the primary intended usage of this function
	// is to aid bridging between code that uses `bounded_ptr`s and code that
	// does not. However, unlike `discard_bounds()`, this function does not
	// validate that the returned pointer is in bounds. This functionality is
	// necessary when the pointer represents something that can't be
	// dereferenced (hence it's OK for it to be out-of-bounds), but that
	// is still useful for other purposes like comparing against other
	// pointers. An example of that is the `end` pointer in a half-open
	// interval `[begin, end)`, where the `end` pointer is out-of-bounds and
	// can't be dereferenced, yet it's still useful to delimit the range.
	OS_ALWAYS_INLINE T*
	unsafe_discard_bounds() const
	{
		return get_ptr_();
	}

	// Implicit conversion to bool, returning whether the pointer is null.
	//
	// This operation does not perform any validation of the bounds.
	OS_ALWAYS_INLINE explicit
	operator bool() const
	{
		return get_ptr_() != nullptr;
	}

	// Increment/decrement a `bounded_ptr`.
	//
	// Like for other arithmetic operations, this does not check whether the
	// increment or decrement operation results in an out-of-bounds pointer.
	OS_ALWAYS_INLINE bounded_ptr&
	operator++()
	{
		*this += 1;
		return *this;
	}
	OS_ALWAYS_INLINE bounded_ptr
	operator++(int)
	{
		bounded_ptr old = *this;
		++*this;
		return old;
	}
	OS_ALWAYS_INLINE bounded_ptr&
	operator--()
	{
		*this -= 1;
		return *this;
	}
	OS_ALWAYS_INLINE bounded_ptr
	operator--(int)
	{
		bounded_ptr old = *this;
		--*this;
		return old;
	}

	// Increment or decrement a `bounded_ptr` by a given offset.
	//
	// This is equivalent to adding the given offset to the underlying raw
	// pointer. In particular, the bounds of the `bounded_ptr` are left
	// untouched by this operation. Furthermore, like for raw pointers, it
	// is possible to provide a negative offset, which will have the effect
	// of decrementing the `bounded_ptr` instead of incrementing it.
	//
	// Also note that the offset is NOT a number of bytes -- just like for
	// raw pointers, it is a number of "positions" to move the pointer from,
	// which essentially means `n * sizeof(T)` bytes. Again, this works exactly
	// the same as a raw pointer to an object of type `T`.
	//
	// Like other arithmetic operations, this does not check whether the
	// increment or decrement operation results in an out-of-bounds pointer.
	// However, this does check whether the arithmetic operation would result
	// in an overflow, in which case the operation will trap.
	template <typename T_ = T>
	OS_ALWAYS_INLINE bounded_ptr&
	operator+=(ptrdiff_t n)
	{
		static_assert(!detail::is_void_v<T_>, "Arithmetic on bounded_ptr<void> is not allowed.");

		ptrdiff_t bytes;
		if (__improbable(os_mul_overflow(n, sizeof(T), &bytes))) {
			TrappingPolicy::trap(
				"bounded_ptr<T>::operator+=(n): Calculating the number of bytes to "
				"add to the offset (n * sizeof(T)) would trigger an overflow");
		}
		if (__improbable(os_add_overflow(offset_, bytes, &offset_))) {
			TrappingPolicy::trap(
				"bounded_ptr<T>::operator+=(n): Adding the specified number of bytes "
				"to the offset representing the current position would overflow.");
		}
		return *this;
	}

	template <typename T_ = T>
	OS_ALWAYS_INLINE bounded_ptr&
	operator-=(ptrdiff_t n)
	{
		static_assert(!detail::is_void_v<T_>, "Arithmetic on bounded_ptr<void> is not allowed.");

		ptrdiff_t bytes;
		if (__improbable(os_mul_overflow(n, sizeof(T), &bytes))) {
			TrappingPolicy::trap(
				"bounded_ptr<T>::operator-=(n): Calculating the number of bytes to "
				"subtract from the offset (n * sizeof(T)) would trigger an overflow");
		}
		if (__improbable(os_sub_overflow(offset_, bytes, &offset_))) {
			TrappingPolicy::trap(
				"bounded_ptr<T>::operator-=(n): Subtracting the specified number of bytes "
				"from the offset representing the current position would overflow.");
		}
		return *this;
	}

	friend OS_ALWAYS_INLINE bounded_ptr
	operator+(bounded_ptr p, ptrdiff_t n)
	{
		p += n;
		return p;
	}
	friend OS_ALWAYS_INLINE bounded_ptr
	operator+(ptrdiff_t n, bounded_ptr p)
	{
		p += n;
		return p;
	}
	friend OS_ALWAYS_INLINE bounded_ptr
	operator-(bounded_ptr p, ptrdiff_t n)
	{
		p -= n;
		return p;
	}

	// Returns the difference between two `bounded_ptr`s.
	//
	// This is semantically equivalent to subtracting the two underlying
	// pointers. The bounds of the pointers are not validated by this
	// operation.
	friend OS_ALWAYS_INLINE ptrdiff_t
	operator-(bounded_ptr const& a, bounded_ptr const& b)
	{
		return a.get_ptr_() - b.get_ptr_();
	}

	friend OS_ALWAYS_INLINE ptrdiff_t
	operator-(bounded_ptr const& a, T const* b)
	{
		return a.get_ptr_() - b;
	}

	friend OS_ALWAYS_INLINE ptrdiff_t
	operator-(T const* a, bounded_ptr const& b)
	{
		return a - b.get_ptr_();
	}

private:
	OS_ALWAYS_INLINE bool
	in_bounds_() const
	{
		static_assert(detail::sizeof_v<T> <= UINT32_MAX - INT32_MAX,
		    "The type pointed-to by bounded_ptr is too large, which would defeat "
		    "our optimization to check for inboundedness using arithmetic on unsigned");
		return offset_ >= 0 && static_cast<uint32_t>(offset_) + static_cast<uint32_t>(detail::sizeof_v<T>) <= count_;
	}

	OS_ALWAYS_INLINE T*
	get_ptr_() const
	{
		// Compute `base_ + offset_`, catching overflows.
		uintptr_t ptr;
		if (__improbable(os_add_overflow(reinterpret_cast<uintptr_t>(base_), offset_, &ptr))) {
			TrappingPolicy::trap("This bounded_ptr is pointing to memory outside of what can "
			    "be represented by a native pointer.");
		}
		return reinterpret_cast<T*>(ptr);
	}

	template <typename T_, typename U, typename Policy>
	friend bounded_ptr<T_, Policy> reinterpret_pointer_cast(bounded_ptr<U, Policy> const&) noexcept;

	template <typename U, typename P> friend struct bounded_ptr; // for cross-type operations and conversions

	CharType* base_; // pointer to the beginning of the valid address range
	uint32_t count_; // number of bytes considered in-bounds (non-negative)
	int32_t offset_; // current offset into the range, in bytes
};

// Returns whether two `bounded_ptr`s point to the same object.
//
// This comparison is semantically equivalent to comparing the underlying
// raw pointers. In particular, it doesn't validate the bounds of either
// `bounded_ptr`, nor does it compare whether the two `bounded_ptr`s have
// the same bounds.
//
// This comparison is enabled between `bounded_ptr`s whenever the two
// corresponding raw pointer types are comparable. Comparison between a
// raw pointer and a `bounded_ptr` is also allowed, so long as the
// two corresponding raw pointer types are comparable.
template <typename T, typename P1, typename U, typename P2, typename = detail::WhenComparable<T*, U*> >
OS_ALWAYS_INLINE bool
operator==(bounded_ptr<T, P1> const& a, bounded_ptr<U, P2> const& b)
{
	return a.unsafe_discard_bounds() == b.unsafe_discard_bounds();
}

template <typename T, typename P1, typename U, typename P2, typename = detail::WhenComparable<T*, U*> >
OS_ALWAYS_INLINE bool
operator!=(bounded_ptr<T, P1> const& a, bounded_ptr<U, P2> const& b)
{
	return !(a == b);
}

template <typename T, typename P, typename U, typename = detail::WhenComparable<T*, U*> >
OS_ALWAYS_INLINE bool
operator==(bounded_ptr<T, P> const& a, U* b)
{
	return a.unsafe_discard_bounds() == b;
}

template <typename T, typename P, typename U, typename = detail::WhenComparable<T*, U*> >
OS_ALWAYS_INLINE bool
operator==(U* a, bounded_ptr<T, P> const& b)
{
	return a == b.unsafe_discard_bounds();
}

template <typename T, typename P, typename U, typename = detail::WhenComparable<T*, U*> >
OS_ALWAYS_INLINE bool
operator!=(bounded_ptr<T, P> const& a, U* b)
{
	return !(a == b);
}

template <typename T, typename P, typename U, typename = detail::WhenComparable<T*, U*> >
OS_ALWAYS_INLINE bool
operator!=(U* a, bounded_ptr<T, P> const& b)
{
	return !(a == b);
}

template <typename T, typename Policy>
OS_ALWAYS_INLINE bool
operator==(detail::nullptr_t, bounded_ptr<T, Policy> const& p)
{
	return p.unsafe_discard_bounds() == nullptr;
}

template <typename T, typename Policy>
OS_ALWAYS_INLINE bool
operator!=(detail::nullptr_t, bounded_ptr<T, Policy> const& p)
{
	return p.unsafe_discard_bounds() != nullptr;
}

template <typename T, typename Policy>
OS_ALWAYS_INLINE bool
operator==(bounded_ptr<T, Policy> const& p, detail::nullptr_t)
{
	return p.unsafe_discard_bounds() == nullptr;
}

template <typename T, typename Policy>
OS_ALWAYS_INLINE bool
operator!=(bounded_ptr<T, Policy> const& p, detail::nullptr_t)
{
	return p.unsafe_discard_bounds() != nullptr;
}

// Returns whether a `bounded_ptr` points to an address that is {less-than,
// less-than-or-equal-to, greater-than, greater-than-or-equal-to} the address
// held in another `bounded_ptr`.
//
// This doesn't validate the bounds of either `bounded_ptr`, nor does it
// compare those bounds to determine the ordering result. This ordering is
// semantically equivalent to ordering the result of calling `get()` on both
// `bounded_ptr`s.
//
// This ordering is enabled between `bounded_ptr`s whenever the two
// corresponding raw pointer types are orderable. Ordering between a
// raw pointer and a `bounded_ptr` is also allowed, so long as the
// two corresponding raw pointer types are orderable.
//

template <typename T, typename U, typename P1, typename P2, typename = detail::WhenOrderable<T*, U*> >
OS_ALWAYS_INLINE bool
operator<(bounded_ptr<T, P1> const& a, bounded_ptr<U, P2> const& b)
{
	return a.unsafe_discard_bounds() < b.unsafe_discard_bounds();
}

template <typename T, typename U, typename P1, typename P2, typename = detail::WhenOrderable<T*, U*> >
OS_ALWAYS_INLINE bool
operator<=(bounded_ptr<T, P1> const& a, bounded_ptr<U, P2> const& b)
{
	return a.unsafe_discard_bounds() <= b.unsafe_discard_bounds();
}

template <typename T, typename U, typename P1, typename P2, typename = detail::WhenOrderable<T*, U*> >
OS_ALWAYS_INLINE bool
operator>(bounded_ptr<T, P1> const& a, bounded_ptr<U, P2> const& b)
{
	return a.unsafe_discard_bounds() > b.unsafe_discard_bounds();
}

template <typename T, typename U, typename P1, typename P2, typename = detail::WhenOrderable<T*, U*> >
OS_ALWAYS_INLINE bool
operator>=(bounded_ptr<T, P1> const& a, bounded_ptr<U, P2> const& b)
{
	return a.unsafe_discard_bounds() >= b.unsafe_discard_bounds();
}

template <typename T, typename U, typename P, typename = detail::WhenOrderable<T*, U*> >
OS_ALWAYS_INLINE bool
operator<(T* a, bounded_ptr<U, P> const& b)
{
	return a < b.unsafe_discard_bounds();
}

template <typename T, typename U, typename P, typename = detail::WhenOrderable<T*, U*> >
OS_ALWAYS_INLINE bool
operator<(bounded_ptr<T, P> const& a, U* b)
{
	return a.unsafe_discard_bounds() < b;
}

template <typename T, typename U, typename P, typename = detail::WhenOrderable<T*, U*> >
OS_ALWAYS_INLINE bool
operator<=(T* a, bounded_ptr<U, P> const& b)
{
	return a <= b.unsafe_discard_bounds();
}

template <typename T, typename U, typename P, typename = detail::WhenOrderable<T*, U*> >
OS_ALWAYS_INLINE bool
operator<=(bounded_ptr<T, P> const& a, U* b)
{
	return a.unsafe_discard_bounds() <= b;
}

template <typename T, typename U, typename P, typename = detail::WhenOrderable<T*, U*> >
OS_ALWAYS_INLINE bool
operator>(T* a, bounded_ptr<U, P> const& b)
{
	return a > b.unsafe_discard_bounds();
}

template <typename T, typename U, typename P, typename = detail::WhenOrderable<T*, U*> >
OS_ALWAYS_INLINE bool
operator>(bounded_ptr<T, P> const& a, U* b)
{
	return a.unsafe_discard_bounds() > b;
}

template <typename T, typename U, typename P, typename = detail::WhenOrderable<T*, U*> >
OS_ALWAYS_INLINE bool
operator>=(T* a, bounded_ptr<U, P> const& b)
{
	return a >= b.unsafe_discard_bounds();
}

template <typename T, typename U, typename P, typename = detail::WhenOrderable<T*, U*> >
OS_ALWAYS_INLINE bool
operator>=(bounded_ptr<T, P> const& a, U* b)
{
	return a.unsafe_discard_bounds() >= b;
}

template <typename T, typename U>
OS_ALWAYS_INLINE T*
reinterpret_pointer_cast(U* p) noexcept
{
	return reinterpret_cast<T*>(p);
}

// Reinterprets a `bounded_ptr` to a type `T` to a `bounded_ptr` to a type `U`.
//
// This is equivalent to `reinterpret_cast`ing the underlying pointer as well
// as the bounds of the original pointer. Like for a raw `reinterpret_cast`,
// no offset adjustment is performed (even if needed, e.g. for derived-to-base
// casts with multiple inheritance). Because this is extremely unsafe, it should
// be used extremely sparingly.
template <typename T, typename U, typename Policy>
OS_ALWAYS_INLINE bounded_ptr<T, Policy>
reinterpret_pointer_cast(bounded_ptr<U, Policy> const& p) noexcept
{
	using CharType = detail::copy_cv_t<T, char>;
	CharType* new_begin = reinterpret_cast<CharType*>(p.base_);
	CharType* new_end = new_begin + p.count_;
	return bounded_ptr<T, Policy>(reinterpret_cast<T*>(p.get_ptr_()),
	           reinterpret_cast<T const*>(new_begin),
	           reinterpret_cast<T const*>(new_end));
}
} // end namespace libkern

#endif // !XNU_LIBKERN_LIBKERN_CXX_BOUNDED_PTR_H
