/*
 * Copyright (c) 2015 Apple Inc. All rights reserved.
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

#ifndef _SECTION_KEYWORDS_H
#define _SECTION_KEYWORDS_H

#define __PLACE_IN_SECTION(__segment__section) \
	__attribute__((used, section(__segment__section)))

#define __SEGMENT_START_SYM(seg)       asm("segment$start$" seg)
#define __SEGMENT_END_SYM(seg)         asm("segment$end$" seg)

#define __SECTION_START_SYM(seg, sect) asm("section$start$" seg "$" sect)
#define __SECTION_END_SYM(seg, sect)   asm("section$end$" seg "$" sect)

#if defined(__arm64__) || defined (__x86_64__)

#define SECURITY_SEGMENT_NAME           "__DATA"
#define SECURITY_SECTION_NAME           "__const"
#define SECURITY_SEGMENT_SECTION_NAME   "__DATA,__const"

#define __security_const_early const
#define __security_const_late __attribute__((section(SECURITY_SEGMENT_SECTION_NAME)))
#define __security_read_write

#if HIBERNATION
#define MARK_AS_HIBERNATE_TEXT __attribute__((section("__HIB, __text, regular, pure_instructions")))
#define MARK_AS_HIBERNATE_DATA __attribute__((section("__HIB, __data")))
#define MARK_AS_HIBERNATE_DATA_CONST_LATE __attribute__((section("__HIB, __const")))
#endif /* HIBERNATION */
#endif /* __arm64__ || __x86_64__ */

#ifndef __security_const_early
#define __security_const_early const
#endif
#ifndef __security_const_late
#define __security_const_late
#endif
#ifndef __security_read_write
#define __security_read_write
#endif
#ifndef MARK_AS_HIBERNATE_TEXT
#define MARK_AS_HIBERNATE_TEXT
#endif
#ifndef MARK_AS_HIBERNATE_DATA
#define MARK_AS_HIBERNATE_DATA
#endif

#define SECURITY_READ_ONLY_SPECIAL_SECTION(_t, __segment__section) \
	__security_const_early _t __PLACE_IN_SECTION(__segment__section)

#define SECURITY_READ_ONLY_EARLY(_t) _t __security_const_early __attribute__((used))
#define SECURITY_READ_ONLY_LATE(_t)  _t __security_const_late  __attribute__((used))
#define SECURITY_READ_WRITE(_t)      _t __security_read_write  __attribute__((used))

#endif /* _SECTION_KEYWORDS_H_ */
