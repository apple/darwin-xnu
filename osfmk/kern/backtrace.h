/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

#ifndef BACKTRACE_H
#define BACKTRACE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

/*
 * Backtrace the current thread, storing up to max_frames return addresses in
 * bt.  Returns the number of return addresses stored.
 */
uint32_t backtrace(uintptr_t *bt, uint32_t max_frames)
__attribute__((noinline));

/*
 * Backtrace the current thread starting at the frame pointer start_fp, storing
 * up to max_frames return addresses in bt.  Returns the number of return
 * addresses stored.
 */
uint32_t backtrace_frame(uintptr_t *bt, uint32_t max_frames, void *start_frame)
__attribute__((noinline, not_tail_called));

/*
 * Backtrace the kernel stack of the context that was interrupted, storing up
 * to max_frames return addresses in bt.  Returns 0 on success, and non-zero
 * otherwise.  On success, the number of frames written is stored at the value
 * pointed to by frames_out.
 *
 * Must be called from interrupt context.
 */
uint32_t backtrace_interrupted(uintptr_t *bt, uint32_t max_frames);

/*
 * Backtrace the user stack of the current thread, storing up to max_frames
 * return addresses in bt.  Returns 0 on success, and non-zero otherwise.  On
 * success, the number of frames written is stored at the value pointed to by
 * frames_out and the value pointed to by user_64_out is set true if the user
 * space thread was running in 64-bit mode, and false otherwise.
 *
 * Must not be called from interrupt context or with interrupts disabled.
 */
int backtrace_user(uintptr_t *bt, uint32_t max_frames, uint32_t *frames_out,
    bool *user_64_out);

/*
 * Backtrace the user stack of the given thread, storing up to max_frames return
 * addresses in bt.  Returns 0 on success, and non-zero otherwise.  On success,
 * the number of frames written is stored at the value pointed to by frames_out
 * and the value pointed to by user_64_out is set true if the user space thread
 * was running in 64-bit mode, and false otherwise.
 *
 * Must not be called from interrupt context or with interrupts disabled.
 */
int backtrace_thread_user(void *thread, uintptr_t *bt, uint32_t max_frames,
    uint32_t *frames_out, bool *user_64_out);

__END_DECLS

#endif /* !defined(BACKTRACE_H) */
