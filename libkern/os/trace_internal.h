/*
 * Copyright (c) 2013-2015 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef libtrace_trace_internal_h
#define libtrace_trace_internal_h

#include <os/log.h>
#include <uuid/uuid.h>
#include <firehose/firehose_types_private.h>

__BEGIN_DECLS

typedef union {
    struct {
#if __LP64__
        uintptr_t pc : 48;
#else
        uintptr_t pc;
#endif
        // not encoded
        firehose_tracepoint_flags_t flags;
        uintptr_t dso;
        uuid_t uuid;
    };

    uint32_t offset;
    uint64_t vlocation : 48; // we never use the full 64-bits

#if defined(__LP64__)
    uint8_t encode_value[6]; // 48-bits
#else
    uint8_t encode_value[sizeof(uintptr_t)];
#endif
} os_trace_location_u;

typedef os_trace_location_u *os_trace_location_t;

OS_ALWAYS_INLINE
inline uint32_t
_os_trace_offset(const void *dso, const void *addr, _firehose_tracepoint_flags_activity_t flags __unused)
{
    return (uint32_t) ((uintptr_t)addr - (uintptr_t)dso);
}

bool
_os_trace_addr_in_text_segment(const void *dso, const void *addr);

__END_DECLS

#endif
