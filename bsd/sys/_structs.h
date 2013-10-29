/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
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

#include <sys/cdefs.h>
#include <sys/_types.h>

#ifdef __need_ucontext_t
#ifndef __need_struct_ucontext
#define __need_struct_ucontext
#endif /* __need_struct_ucontext */
#endif /* __need_ucontext_t */

#ifdef __need_ucontext64_t
#ifndef __need_struct_ucontext64
#define __need_struct_ucontext64
#endif /* __need_struct_ucontext64 */
#endif /* __need_ucontext64_t */

#ifdef __need_struct_ucontext
#ifndef __need_struct_mcontext
#define __need_struct_mcontext
#endif /* __need_struct_mcontext */
#endif /* __need_struct_ucontext */

#ifdef __need_struct_ucontext64
#ifndef __need_struct_mcontext64
#define __need_struct_mcontext64
#endif /* __need_struct_mcontext64 */
#endif /* __need_struct_ucontext64 */

#if defined(__need_struct_mcontext) || defined(__need_struct_mcontext64)
#include <machine/_structs.h>
#endif /* __need_struct_mcontext || __need_struct_mcontext64 */

#if defined(__need_stack_t) || defined(__need_struct_ucontext) || defined(__need_struct_ucontext64)
#ifndef __need_struct_sigaltstack
#define __need_struct_sigaltstack
#endif /* __need_struct_sigaltstack */
#endif /* __need_stack_t || __need_struct_ucontext || __need_struct_ucontext64 */

#ifdef __need_struct_sigaltstack
#undef __need_struct_sigaltstack
#include <sys/_types/_sigaltstack.h>
#endif /* __need_struct_sigaltstack */

#ifdef __need_struct_timespec
#undef __need_struct_timespec
#include <sys/_types/_timespec.h>
#endif /* __need_struct_timespec */

#ifdef __need_struct_timeval
#undef __need_struct_timeval
#include <sys/_types/_timeval.h>
#endif /* __need_struct_timeval */

#ifdef __need_struct_timeval32
#undef __need_struct_timeval32
#include <sys/_types/_timeval32.h>
#endif /* __need_struct_timeval32 */

#ifdef __need_struct_ucontext
#undef __need_struct_ucontext
#include <sys/_types/_ucontext.h>
#endif /* __need_struct_ucontext */

#ifdef __need_struct_ucontext64
#undef __need_struct_ucontext64
#include <sys/_types/_ucontext64.h>
#endif /* __need_struct_ucontext64 */

#ifdef KERNEL
/* LP64 version of struct timespec.  time_t is a long and must grow when 
 * we're dealing with a 64-bit process.
 * WARNING - keep in sync with struct timespec
 */
#ifdef __need_struct_user_timespec
#undef __need_struct_user_timespec
#include <sys/_types/_user_timespec.h>
#endif /* __need_struct_user_timespec */

#ifdef __need_struct_user64_timespec
#undef __need_struct_user64_timespec
#include <sys/_types/_user64_timespec.h>
#endif /* __need_struct_user64_timespec */

#ifdef __need_struct_user32_timespec
#undef __need_struct_user32_timespec
#include <sys/_types/_user32_timespec.h>
#endif /* __need_struct_user32_timespec */

#ifdef __need_struct_user_timeval
#undef __need_struct_user_timeval
#include <sys/_types/_user_timeval.h>
#endif /* __need_struct_user_timeval */

#ifdef __need_struct_user64_timeval
#undef __need_struct_user64_timeval
#include <sys/_types/_user64_timeval.h>
#endif /* __need_struct_user64_timeval */

#ifdef __need_struct_user32_timeval
#undef __need_struct_user32_timeval
#include <sys/_types/_user32_timeval.h>
#endif /* __need_struct_user32_timeval */

#ifdef __need_struct_user64_itimerval
#undef __need_struct_user64_itimerval
#include <sys/_types/_user64_itimerval.h>
#endif /* __need_struct_user64_itimerval */

#ifdef __need_struct_user32_itimerval
#undef __need_struct_user32_itimerval
#include <sys/_types/_user32_itimerval.h>
#endif /* __need_struct_user32_itimerval */

#endif	/* KERNEL */

#ifdef __need_fd_set
#undef __need_fd_set
#include <sys/_types/_fd_def.h>
#endif /* __need_fd_set */

#ifdef __need_stack_t
#undef __need_stack_t
#endif /* __need_stack_t */

#ifdef __need_ucontext_t
#undef __need_ucontext_t
#endif /* __need_ucontext_t */

#ifdef __need_ucontext64_t
#undef __need_ucontext64_t
#endif /* __need_ucontext64_t */
