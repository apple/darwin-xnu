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

#ifndef XNU_LIBKERN_LIBKERN_CXX_OS_PTR_H
#define XNU_LIBKERN_LIBKERN_CXX_OS_PTR_H

//
// The declarations in this file are a transition tool from raw pointers to
// the new OSSharedPtr class.
//
// Basically, code in headers that wants to be able to vend both a raw pointer
// and a shared pointer interface should use `OSPtr<T>` instead of `T*`.
// Then, users that want to opt into using `OSSharedPtr` can define the
// `IOKIT_ENABLE_SHARED_PTR` macro in their translation unit (.cpp file),
// and `OSPtr<T>` will suddenly be `OSSharedPtr<T>`.
//
// When the `IOKIT_ENABLE_SHARED_PTR` macro is not enabled, however, `OSPtr<T>`
// will simply be `T*`, so that clients that do not wish to migrate to smart
// pointers don't need to.
//
// Note that defining `IOKIT_ENABLE_SHARED_PTR` requires C++17, because the
// implementation of `OSSharedPtr` requires that.
//

#if !defined(PRIVATE) // only ask to opt-in explicitly for third-party developers
#   if defined(IOKIT_ENABLE_SHARED_PTR)
#       if !defined(IOKIT_ENABLE_EXPERIMENTAL_SHARED_PTR_IN_API)
#           error It seems that you have defined IOKIT_ENABLE_SHARED_PTR to \
        ask IOKit to return shared pointers from many of its API \
        functions. This is great! However, please note that we may \
        transition more IOKit APIs to shared pointers in the future, \
        so if you enable IOKIT_ENABLE_SHARED_PTR right now, your \
        code may fail to compile with future versions of IOKit \
        (which would return shared pointers where you expect raw \
        pointers). If you are OK with that, please define the \
        IOKIT_ENABLE_EXPERIMENTAL_SHARED_PTR_IN_API macro to \
        silence this error. If that is not acceptable, please hold \
        off on enabling shared pointers in IOKit APIs until we have \
        committed to API stability for it.
#       endif
#   endif
#endif

#if defined(IOKIT_ENABLE_SHARED_PTR)

#if __cplusplus < 201703L
#error "Your code must compile with C++17 or later to adopt shared pointers. Use Xcode's 'C++ Language Dialect' setting, or on clang's command-line use -std=gnu++17"
#endif

#include <libkern/c++/OSSharedPtr.h>

template <typename T>
using OSPtr = OSSharedPtr<T>;

class OSCollection; // Forward declare only because OSCollection.h needs OSPtr.h

template <typename T>
using OSTaggedPtr = OSTaggedSharedPtr<T, OSCollection>;

#else

template <typename T>
class __attribute__((trivial_abi)) OSSharedPtr;

template <typename T, typename Tag>
class __attribute__((trivial_abi)) OSTaggedSharedPtr;

// We're not necessarily in C++11 mode, so we need to disable warnings
// for C++11 extensions
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wc++11-extensions"

template <typename T>
using OSPtr = T *;

template <typename T>
using OSTaggedPtr = T *;

#pragma clang diagnostic pop

#endif

// Allow C++98 code to use nullptr.
//
// This isn't the right place to put this, however the old OSPtr.h header
// had it and some code has now started relying on nullptr being defined.
#if !__has_feature(cxx_nullptr) && !defined(nullptr)
# define nullptr NULL
#endif

#endif // !XNU_LIBKERN_LIBKERN_CXX_OS_PTR_H
