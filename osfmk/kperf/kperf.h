/*
 * Copyright (c) 2011 Apple Computer, Inc. All rights reserved.
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

/* XXX: still needed? just access directly? */

#define TRIGGER_TYPE_TIMER (0)
#define TRIGGER_TYPE_PMI   (1)
#define TRIGGER_TYPE_TRACE (2)

extern uint32_t kperf_get_thread_bits( thread_t thread );
extern void     kperf_set_thread_bits( thread_t thread, uint32_t bits );
extern void     kperf_set_thread_ast( thread_t thread );

#define KPERF_SAMPLING_OFF 0
#define KPERF_SAMPLING_ON  1
#define KPERF_SAMPLING_SHUTDOWN 2

extern int kperf_init(void);
extern unsigned kperf_sampling_status(void);
extern int kperf_sampling_enable(void);
extern int kperf_sampling_disable(void);
