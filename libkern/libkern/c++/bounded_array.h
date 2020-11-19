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

#ifndef XNU_LIBKERN_LIBKERN_CXX_BOUNDED_ARRAY_H
#define XNU_LIBKERN_LIBKERN_CXX_BOUNDED_ARRAY_H

#include <libkern/c++/bounded_ptr.h>
#include <stddef.h>
#include <os/base.h>

namespace libkern {
// `bounded_array` is a simple abstraction for a C-style array.
//
// Unlike C-style arrays, however, it ensures that the array is not accessed
// outside of its bounds. Furthermore, the iterators of the `bounded_array`
// are `bounded_ptr`, which track the range they're allowed to access.
//
// TODO:
// - Should we provide deep comparison operators?
// - Document individual methods
template <typename T, size_t N, typename TrappingPolicy>
struct bounded_array {
	// DO NOT USE THIS MEMBER DIRECTLY OR WE WILL BREAK YOUR CODE IN THE FUTURE.
	// THIS HAS TO BE PUBLIC FOR THIS TYPE TO SUPPORT AGGREGATE-INITIALIZATION.
	T data_[N];

	using iterator = bounded_ptr<T, TrappingPolicy>;
	using const_iterator = bounded_ptr<T const, TrappingPolicy>;

	iterator
	begin() noexcept
	{
		return iterator(data_, data_, data_ + N);
	}
	const_iterator
	begin() const noexcept
	{
		return const_iterator(data_, data_, data_ + N);
	}
	iterator
	end() noexcept
	{
		return iterator(data_ + N, data_, data_ + N);
	}
	const_iterator
	end() const noexcept
	{
		return const_iterator(data_ + N, data_, data_ + N);
	}

	constexpr size_t
	size() const
	{
		return N;
	}
	constexpr T*
	data() noexcept
	{
		return data_;
	}
	constexpr T const*
	data() const noexcept
	{
		return data_;
	}
	OS_ALWAYS_INLINE T&
	operator[](ptrdiff_t n)
	{
		return begin()[n];
	}
	OS_ALWAYS_INLINE T const&
	operator[](ptrdiff_t n) const
	{
		return begin()[n];
	}
};
} // end namespace libkern

#endif // !XNU_LIBKERN_LIBKERN_CXX_BOUNDED_ARRAY_H
