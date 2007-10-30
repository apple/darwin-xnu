/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#ifndef __CHUD_DTRACE_H__
#define __CHUD_DTRACE_H__

/* Definitions for arguments to the chud() dtrace builtin */

#define CHUD_DTRACE_START_SHARK		((uint64_t)0x1ULL)
#define CHUD_DTRACE_STOP_SHARK		((uint64_t)0x2ULL)
#define CHUD_DTRACE_RECORD_SAMPLE	((uint64_t)0x3ULL)
#define CHUD_DTRACE_SIGNPOST_POINT	((uint64_t)0x4ULL)
#define CHUD_DTRACE_SIGNPOST_START	((uint64_t)0x5ULL)
#define CHUD_DTRACE_SIGNPOST_END	((uint64_t)0x6ULL)

#endif /* __CHUD_DTRACE_H__ */
