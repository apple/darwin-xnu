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

#ifndef XNU_LIBKERN_LIBKERN_CXX_SAFE_ALLOCATION_H
#define XNU_LIBKERN_LIBKERN_CXX_SAFE_ALLOCATION_H

#include <stddef.h>
#include <stdint.h>
#include <os/base.h>
#include <libkern/c++/bounded_ptr.h>

void* operator new(size_t, void*); // forward declaration needed for placement-new

namespace libkern {
namespace sa_detail {
// TODO: Deduplicate these utilities with other smart pointer utilities
using nullptr_t = decltype(nullptr);
template <typename T>
constexpr bool is_trivially_destructible_v = __is_trivially_destructible(T);
template <typename T>
constexpr bool is_empty_v = __is_empty(T);
template <typename T>
constexpr bool is_nothrow_default_constructible_v = __is_nothrow_constructible(T);

template <bool Cond, typename T = void> struct enable_if;
template <typename T> struct enable_if<true, T> { using type = T; };
template <bool Cond, typename T = void> using enable_if_t = typename enable_if<Cond, T>::type;

template <typename T> struct remove_const { using type = T; };
template <typename T> struct remove_const<T const> { using type = T; };
template <typename T> using remove_const_t = typename remove_const<T>::type;

template <typename T>
void
generic_swap(T& a, T& b)
{
	T tmp = a;
	a = b;
	b = tmp;
}

template <typename T, enable_if_t<!is_trivially_destructible_v<T> >* = nullptr>
void
destroy(T* first, T* last)
{
	for (; first != last; ++first) {
		first->~T();
	}
}

template <typename T, enable_if_t<is_trivially_destructible_v<T> >* = nullptr>
void
destroy(T*, T*)
{
	// Nothing to do, the elements are trivially destructible
}

template <typename T>
void
uninitialized_value_construct(T* first, T* last)
{
	for (; first != last; ++first) {
		::new (static_cast<void*>(first)) T();
	}
}
} // end namespace sa_detail

struct adopt_memory_t {
	explicit constexpr
	adopt_memory_t() = default;
};
inline constexpr adopt_memory_t adopt_memory{};

struct allocate_memory_t {
	explicit constexpr
	allocate_memory_t() = default;
};
inline constexpr allocate_memory_t allocate_memory{};

// Lightweight utility class representing a dynamically allocated slab of
// memory, with contiguous objects in it.
//
// The main purpose `safe_allocation` is to:
// 1. Manage a uniquely-owned allocation of memory containing multiple objects
// 2. Check that the allocation is accessed within its bounds on indexing operations
// 3. Act as a source for obtaining (non-owning) `bounded_ptr`s to the underlying memory
//
// In fact, `safe_allocation` should be the primary source of `bounded_ptr`s to
// heap-allocated memory, via its `.begin()` and `.end()` methods. `safe_allocation`
// is optimized for use cases where simple scratch space is needed for calculation
// and deallocated once the calculation is done. As such, it is not a full-blown
// container class, which drives many design choices behind `safe_allocation`:
//
// 1. It can't be copied or compared for equality -- `safe_allocation` is not a proper value type
// 2. It can't be resized -- this keeps the design extremely simple and free of overhead
// 3. You can transfer ownership of `safe_allocation` by using std::move
//
// Design decision: stateless allocators
// =====================================
// Only allow stateless allocators. While we could technically handle stateful
// allocators (as the C++ Standard Library) does, the benefit of doing so
// compared to the added complexity is absolutely not worth it. Supporting
// stateful allocators everywhere in C++ is regarded (at least in the
// Standardization Committee) as one of the worst design mistakes we've made,
// and so we won't repeat it here.
//
// Design decision: size() is 0 when allocation is null
// ====================================================
// When the `safe_allocation` is null (because it's been moved-from, or because
// allocation failed, or whatever), we could technically leave the `size_`
// undefined (as long as we make `data_` null). However, this would mean
// that querying the size of the allocation in that case is undefined behavior
// (UB), which is seen as something bad in the context of a type that vends
// itself as safe. So instead, we "overimplement" the type to provide stronger
// guarantees than would be strictly required if performance were the main goal.
template <typename T, typename Allocator, typename TrappingPolicy>
struct safe_allocation {
	static_assert(sa_detail::is_empty_v<Allocator>,
	    "safe_allocation<T, Alloc, ...> requires the Allocator to be stateless");

	// Create a null allocation, pointing to no memory.
	//
	// A null allocation can be destroyed, assigned-to, checked for nullness,
	// and otherwise queries for length, but trying to access an element of
	// the allocation will fail.
	//
	// A null allocation basically behaves as an empty array, i.e. `begin()`
	// and `end()` will return iterators that are equal and `size()` will
	// return `0`.
	explicit constexpr safe_allocation() noexcept : data_(nullptr), size_(0)
	{
	}

	constexpr safe_allocation(sa_detail::nullptr_t) noexcept : safe_allocation()
	{
	}

	// Create an allocation pointing to already-allocated and initialized memory.
	//
	// This constructor attaches existing memory to a `safe_allocation`, such
	// that it will be released automatically when the `safe_allocation` goes
	// out of scope. The objects in that memory must already have been
	// initialized, or they must be initialized before the `safe_allocation`
	// goes out of scope.
	//
	// The `n` argument is the number of objects of type `T` in the allocation,
	// i.e. `n * sizeof(T)` bytes should have been allocated.
	//
	// Note that the memory MUST have been allocated with an allocator compatible
	// with the `safe_allocation`'s `Allocator`, since the memory will be
	// deallocated using that `Allocator`. Bad things will happen if, for
	// example, `adopt_memory` is used with memory allocated on the stack:
	// the destructor will try to deallocate that memory and will fail to do so.
	explicit safe_allocation(T* data, size_t n, adopt_memory_t) : data_(data)
	{
		if (__improbable(n > UINT32_MAX)) {
			TrappingPolicy::trap("safe_allocation size exceeds UINT32_MAX");
		}

		size_ = static_cast<uint32_t>(n);
	}

	// Allocate memory for `n` objects of type `T`, and manage it.
	//
	// This constructor allocates enough memory for `n` objects of type `T`
	// using the `Allocator`, and manages that. Each object in the allocation
	// is value-initialized (either set to 0 or the default-constructor called).
	//
	// If either `n * sizeof(T)` overflows or the allocation fails, the
	// resulting `safe_allocation` will be null. It is therefore necessary
	// to check whether the allocation is null after using this constructor.
	explicit safe_allocation(size_t n, allocate_memory_t)
	{
		size_t bytes;
		if (__improbable(os_mul_overflow(n, sizeof(T), &bytes) || (n > UINT32_MAX))) {
			data_ = nullptr;
			size_ = 0;
		} else {
			data_ = reinterpret_cast<T*>(Allocator::allocate(bytes));
			size_ = static_cast<uint32_t>(n);
			using RawT = sa_detail::remove_const_t<T>;
			RawT* data = const_cast<RawT*>(data_);
			sa_detail::uninitialized_value_construct(data, data + size_);
		}
	}

	// A `safe_allocation` can't be copied, because it is not a proper value
	// type and it doesn't assume that the elements of the allocation can be
	// copied.
	safe_allocation(safe_allocation const&) = delete;
	safe_allocation& operator=(safe_allocation const&) = delete;

	// Moves the ownership of an allocation from one `safe_allocation` to
	// another one.
	//
	// After this operation, the moved-from `safe_allocation` is null, and
	// any iterator into the moved-from `safe_allocation` are now tied to
	// the `safe_allocation` that's the target of the assignment, in the
	// sense that the iterators will be invalidated when the target of the
	// assignment goes out of scope, not when the moved-from allocation
	// goes out of scope.
	safe_allocation(safe_allocation&& other) noexcept : data_(other.data_), size_(other.size_)
	{
		other.data_ = nullptr;
		other.size_ = 0;
	}

	// Clears a `safe_allocation`, making it a null allocation.
	//
	// If the `safe_allocation` was pointing to valid memory, the objects
	// in that memory are destroyed and that memory is freed.
	safe_allocation&
	operator=(sa_detail::nullptr_t)
	{
		if (data_ != nullptr) {
			destroy_dealloc_(data_, size_);
		}
		data_ = nullptr;
		size_ = 0;
		return *this;
	}

	// Moves the ownership of an allocation from one `safe_allocation` to
	// another one.
	//
	// After this operation, the moved-from `safe_allocation` is null, and
	// any iterator to the moved-from `safe_allocation` obtained before the
	// move operation are invalidated.
	//
	// If the destination `safe_allocation` was pointing to memory before the
	// move-assignment, the objects in that memory are destroyed and the
	// memory itself is freed.
	//
	// In case of self-move-assignment, nothing is done.
	safe_allocation&
	operator=(safe_allocation&& other)
	{
		if (&other == this) {
			return *this;
		}

		T* old_data = data_;
		size_t old_size = size_;

		data_ = other.data_;
		size_ = other.size_;
		other.data_ = nullptr;
		other.size_ = 0;

		if (old_data != nullptr) {
			destroy_dealloc_(old_data, old_size);
		}

		return *this;
	}

	// Destroys a `safe_allocation`, destroying the objects in it and
	// deallocating the underlying memory with the `Allocator`.
	//
	// If the `safe_allocation` is null, this destructor does nothing.
	~safe_allocation()
	{
		if (data_ != nullptr) {
			destroy_dealloc_(data_, size_);
		}
	}

	// Returns whether a `safe_allocation` is non-null, i.e. whether it is
	// pointing to some memory.
	explicit
	operator bool() const noexcept
	{
		return data_ != nullptr;
	}

	using iterator = bounded_ptr<T, TrappingPolicy>;
	using const_iterator = bounded_ptr<T const, TrappingPolicy>;

	// The following methods allow obtaining iterators (i.e. cursors) to
	// objects inside a `safe_allocation`.
	//
	// The iterators of a `safe_allocation` are `bounded_ptr`s, which know
	// the bounds of the allocation and will trap when dereferenced outside
	// of those bounds.
	//
	// `begin()` returns a (const) iterator to the first element in the
	// allocation, and `end()` returns a (const) iterator to one-past-the-last
	// element in the allocation. The `end()` iterator can't be dereferenced,
	// since it is out of bounds.
	//
	// If the allocation is null, these methods will return null `bounded_ptr`s,
	// which can be checked for equality but can't be dereferenced.
	OS_ALWAYS_INLINE iterator
	begin() noexcept
	{
		if (data_ == nullptr) {
			return iterator();
		} else {
			return iterator(data_, data_, data_ + size_);
		}
	}
	OS_ALWAYS_INLINE const_iterator
	begin() const noexcept
	{
		if (data_ == nullptr) {
			return const_iterator();
		} else {
			return const_iterator(data_, data_, data_ + size_);
		}
	}
	iterator
	end() noexcept
	{
		if (data_ == nullptr) {
			return iterator();
		} else {
			return iterator(data_ + size_, data_, data_ + size_);
		}
	}
	const_iterator
	end() const noexcept
	{
		if (data_ == nullptr) {
			return const_iterator();
		} else {
			return const_iterator(data_ + size_, data_, data_ + size_);
		}
	}

	// Returns the number of objects in the allocation.
	//
	// This method returns `0` if the allocation is null, since such an
	// allocation behaves the same as an empty range.
	size_t
	size() const
	{
		return size_;
	}

	// Returns a non-owning pointer to the underlying memory managed by a
	// `safe_allocation`.
	//
	// This method can be called even if the `safe_allocation` is null, in
	// which case the returned pointer will be null.
	T*
	data() noexcept
	{
		return data_;
	}
	T const*
	data() const noexcept
	{
		return data_;
	}

	// Access the n-th element of an allocation.
	//
	// If `n` is out of the bounds of the allocation, this operation will
	// trap. If the allocation is null, this operation will trap too.
	//
	// Design note:
	// We voluntarily use a signed type to represent the index even though a
	// negative index will always cause a trap. If we used an unsigned type,
	// we could get an implicit conversion from signed to unsigned, which
	// could silently wrap around. We think trapping early is more likely
	// to be helpful in this situation.
	OS_ALWAYS_INLINE T&
	operator[](ptrdiff_t n)
	{
		return begin()[n]; // trap happens in `bounded_ptr` if null or OOB
	}
	OS_ALWAYS_INLINE T const&
	operator[](ptrdiff_t n) const
	{
		return begin()[n]; // trap happens in `bounded_ptr` if null or OOB
	}

private:
	// Swap support
	friend void
	swap(safe_allocation& a, safe_allocation& b) noexcept
	{
		sa_detail::generic_swap(a.data_, b.data_);
		sa_detail::generic_swap(a.size_, b.size_);
	}

	static void
	destroy_dealloc_(T* ptr, size_t size)
	{
		sa_detail::destroy(ptr, ptr + size);
		// `size * sizeof(T)` can't overflow, because it would have
		// overflowed when the allocation was performed otherwise.
		using RawT = sa_detail::remove_const_t<T>;
		Allocator::deallocate(const_cast<RawT*>(ptr), size * sizeof(T));
	}

	T* data_;
	uint32_t size_;
};

// The comparison functions against `nullptr` all return whether the allocation
// is null or not.
template <typename T, typename A, typename P>
bool
operator==(safe_allocation<T, A, P> const& x, sa_detail::nullptr_t)
{
	return !static_cast<bool>(x);
}

template <typename T, typename A, typename P>
bool
operator!=(safe_allocation<T, A, P> const& x, sa_detail::nullptr_t)
{
	return !(x == nullptr);
}

template <typename T, typename A, typename P>
bool
operator==(sa_detail::nullptr_t, safe_allocation<T, A, P> const& x)
{
	return x == nullptr;
}

template <typename T, typename A, typename P>
bool
operator!=(sa_detail::nullptr_t, safe_allocation<T, A, P> const& x)
{
	return !(x == nullptr);
}
} // end namespace libkern

#endif // !XNU_LIBKERN_LIBKERN_CXX_SAFE_ALLOCATION_H
