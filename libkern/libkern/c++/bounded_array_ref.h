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

#ifndef XNU_LIBKERN_LIBKERN_CXX_BOUNDED_ARRAY_REF_H
#define XNU_LIBKERN_LIBKERN_CXX_BOUNDED_ARRAY_REF_H

#include <libkern/c++/bounded_array.h>
#include <libkern/c++/bounded_ptr.h>
#include <stddef.h>
#include <os/base.h>

namespace libkern {
namespace bar_detail {
using nullptr_t = decltype(nullptr);
}

// Represents a reference to a sequence of 0 or more elements consecutively in
// memory, i.e. a start pointer and a length.
//
// When elements of the sequence are accessed, `bounded_array_ref` ensures
// that those elements are in the bounds of the sequence (which are provided
// when the `bounded_array_ref` is constructed).
//
// This class does not own the underlying data, it is expected to be used in
// situations where the data resides in some other buffer, whose lifetime
// extends past that of the `bounded_array_ref`. For this reason, it is not
// in general safe to store a `bounded_array_ref`.
//
// `bounded_array_ref` is trivially copyable and it should be passed by value.
template <typename T, typename TrappingPolicy>
struct bounded_array_ref {
	// Creates an empty `bounded_array_ref`.
	//
	// An empty `bounded_array_ref` does not reference anything, so its
	// `data()` is null and its `size()` is 0.
	explicit constexpr bounded_array_ref() noexcept : data_(nullptr), size_(0)
	{
	}

	// Creates a `bounded_array_ref` from a bounded pointer and a size.
	//
	// The resulting `bounded_array_ref` starts at the location where the
	// pointer points, and has the given number of elements. All the elements
	// must be in the bounds of the `bounded_ptr`, otherwise this constructor
	// will trap.
	explicit constexpr bounded_array_ref(bounded_ptr<T, TrappingPolicy> data, size_t n)
		: data_(data.unsafe_discard_bounds()), size_(static_cast<uint32_t>(n))
	{
		if (n != 0) {
			data[n - 1]; // make sure the bounds are valid
			// TODO: find a better way to do that
		}
		if (__improbable(n > UINT32_MAX)) {
			TrappingPolicy::trap("bounded_array_ref: Can't construct from a size greater than UINT32_MAX");
		}
	}

	// Creates a `bounded_array_ref` from a raw pointer and a size.
	//
	// The resulting `bounded_array_ref` starts at the location where the
	// pointer points, and has the given number of elements. This constructor
	// trusts that `n` elements are reachable from the given pointer.
	explicit constexpr bounded_array_ref(T* data, size_t n) : data_(data), size_(static_cast<uint32_t>(n))
	{
		if (__improbable(n > UINT32_MAX)) {
			TrappingPolicy::trap("bounded_array_ref: Can't construct from a size greater than UINT32_MAX");
		}
	}

	// Creates a `bounded_array_ref` from a `[first, last)` half-open range.
	//
	// The resulting `bounded_array_ref` starts at the location pointed-to by
	// `first`, and contains `last - first` elements. The `[first, last)`
	// half-open range must be a valid range, i.e. it must be the case that
	// `first <= last`, otherwise the constructor traps.
	explicit constexpr bounded_array_ref(T* first, T* last) : data_(first), size_(static_cast<uint32_t>(last - first))
	{
		if (__improbable(first > last)) {
			TrappingPolicy::trap("bounded_array_ref: The [first, last) constructor requires a valid range.");
		}
		if (__improbable(last - first > UINT32_MAX)) {
			TrappingPolicy::trap("bounded_array_ref: Can't construct from a size greater than UINT32_MAX");
		}
	}

	// Creates a `bounded_array_ref` from a `bounded_array`.
	//
	// The resulting `bounded_array_ref` starts at the first element of the
	// `bounded_array`, and has the number of elements in the `bounded_array`.
	template <size_t N>
	constexpr bounded_array_ref(bounded_array<T, N, TrappingPolicy>& data) : data_(data.data()), size_(static_cast<uint32_t>(data.size()))
	{
		if (__improbable(data.size() > UINT32_MAX)) {
			TrappingPolicy::trap("bounded_array_ref: Can't construct from a size greater than UINT32_MAX");
		}
	}

	// Creates a `bounded_array_ref` from a C-style array.
	//
	// The resulting `bounded_array_ref` starts at the first element of the
	// C-style array, and has the number of elements in that array.
	template <size_t N>
	constexpr bounded_array_ref(T (&array)[N]) : data_(array), size_(static_cast<uint32_t>(N))
	{
		if (__improbable(N > UINT32_MAX)) {
			TrappingPolicy::trap("bounded_array_ref: Can't construct from a size greater than UINT32_MAX");
		}
	}

	constexpr
	bounded_array_ref(bounded_array_ref const&) = default;
	constexpr
	bounded_array_ref(bounded_array_ref&& other) noexcept = default;

	constexpr bounded_array_ref& operator=(bounded_array_ref const&) = default;
	constexpr bounded_array_ref& operator=(bounded_array_ref&& other) = default;
	~bounded_array_ref() = default;

	// Returns whether the `bounded_array_ref` points to a sequence or not.
	//
	// Note that pointing to a sequence at all is different from pointing to
	// a valid sequence, or having a size of 0. If a `bounded_array_ref`
	// points to a sequence (regardless of whether it is valid or whether
	// the size of that sequence is 0), this operator will return true.
	explicit
	operator bool() const noexcept
	{
		return data_ != nullptr;
	}

	using iterator = bounded_ptr<T, TrappingPolicy>;

	// The following methods allow obtaining iterators (i.e. cursors) to
	// objects inside a `bounded_array_ref`.
	//
	// The iterators of a `bounded_array_ref` are `bounded_ptr`s, which know
	// the bounds of the sequence and will trap when dereferenced outside
	// of those bounds.
	//
	// `begin()` returns an iterator to the first element in the range, and
	// `end()` returns an iterator to one-past-the-last element in the range.
	// The `end()` iterator can't be dereferenced, since it is out of bounds.
	//
	// If the `bounded_array_ref` is empty, these methods will return null
	// `bounded_ptr`s, which can be checked for equality but can't be
	// dereferenced.
	iterator
	begin() const noexcept
	{
		return iterator(data_, data_, data_ + size_);
	}
	iterator
	end() const noexcept
	{
		return iterator(data_ + size_, data_, data_ + size_);
	}

	// Returns the number of elements in the range referenced by the
	// `bounded_array_ref`.
	//
	// This method returns `0` if the `bounded_array_ref` is null, since
	// such an array ref behaves the same as an empty range.
	constexpr size_t
	size() const
	{
		return size_;
	}

	// Returns a non-owning pointer to the underlying memory referenced by a
	// `bounded_array_ref`.
	//
	// This method can be called even if the `bounded_array_ref` is null, in
	// which case the returned pointer will be null.
	constexpr T*
	data() const noexcept
	{
		return data_;
	}

	// Access the n-th element of a `bounded_array_ref`.
	//
	// If `n` is out of the bounds of the sequence, this operation will
	// trap. If the array ref is null, this operation will trap too.
	//
	// Design note:
	// We voluntarily use a signed type to represent the index even though a
	// negative index will always cause a trap. If we used an unsigned type,
	// we could get an implicit conversion from signed to unsigned, which
	// could silently wrap around. We think trapping early is more likely
	// to be helpful in this situation.
	OS_ALWAYS_INLINE T&
	operator[](ptrdiff_t n) const
	{
		return begin()[n];
	}

	// Chop off the first `n` elements of the array, and keep `m` elements
	// in the array.
	//
	// The resulting range can be described by `[beg + n, beg + n + m)`, where
	// `beg` is the `begin()` of the range being sliced. This operation traps
	// if `n + m` is larger than the number of elements in the array.
	//
	// Since `bounded_array_ref` checks (or assumes) that the range it is
	// given on construction is within bounds and `slice()` checks that the
	// produced slice is within the original range, it is impossible to create
	// a `bounded_array_ref` that isn't a subset of a valid range using this
	// function.
	bounded_array_ref<T, TrappingPolicy>
	slice(size_t n, size_t m) const
	{
		uint32_t total;
		if (__improbable(os_add_overflow(n, m, &total))) {
			TrappingPolicy::trap("bounded_array_ref: n + m is larger than the size of any bounded_array_ref");
		}
		if (__improbable(total > size())) {
			TrappingPolicy::trap("bounded_array_ref: invalid slice provided, the indices are of bounds for the bounded_array_ref");
		}
		return bounded_array_ref(data_ + n, m);
	}

private:
	T* data_;
	uint32_t size_;
};

// The comparison functions against `nullptr` all return whether the
// `bounded_array_ref` references a sequence or not.
template <typename T, typename P>
bool
operator==(bounded_array_ref<T, P> const& x, bar_detail::nullptr_t)
{
	return !static_cast<bool>(x);
}

template <typename T, typename P>
bool
operator!=(bounded_array_ref<T, P> const& x, bar_detail::nullptr_t)
{
	return !(x == nullptr);
}

template <typename T, typename P>
bool
operator==(bar_detail::nullptr_t, bounded_array_ref<T, P> const& x)
{
	return x == nullptr;
}

template <typename T, typename P>
bool
operator!=(bar_detail::nullptr_t, bounded_array_ref<T, P> const& x)
{
	return x != nullptr;
}
} // end namespace libkern

#endif // !XNU_LIBKERN_LIBKERN_CXX_BOUNDED_ARRAY_REF_H
