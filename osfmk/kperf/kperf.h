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

#ifndef __KPERF_H__
#define __KPERF_H__

#include <kern/thread.h>

/* The various trigger types supported by kperf */
#define TRIGGER_TYPE_TIMER   (0)
#define TRIGGER_TYPE_PMI     (1)
#define TRIGGER_TYPE_TRACE   (2)
#define TRIGGER_TYPE_CSWITCH (3)

/* Helpers to get and set AST bits on a thread */
extern uint32_t kperf_get_thread_bits( thread_t thread );
extern void     kperf_set_thread_bits( thread_t thread, uint32_t bits );
extern void     kperf_set_thread_ast( thread_t thread );

/* Possible states of kperf sampling */
#define KPERF_SAMPLING_OFF 0
#define KPERF_SAMPLING_ON  1
#define KPERF_SAMPLING_SHUTDOWN 2

/* Init kperf module. Must be called before use, can be called as many
 * times as you like.
 */
extern int kperf_init(void);

/* Get and set sampling status */
extern unsigned kperf_sampling_status(void);
extern int kperf_sampling_enable(void);
extern int kperf_sampling_disable(void);

/* kperf AST handler
 */
extern void kperf_thread_ast_handler( thread_t thread );

/* kperf kdebug callback
 */
extern void kperf_kdebug_callback(uint32_t debugid);

/* get and set whether we're recording stacks on interesting kdebug events */
extern int kperf_kdbg_get_stacks(void);
extern int kperf_kdbg_set_stacks(int);

/* get and set whether to trigger an action on signposts */
extern int kperf_signpost_action_get(void);
extern int kperf_signpost_action_set(int newval);

extern int kperf_cswitch_callback_set;

/* get and set whether to output tracepoints on context-switch */
extern int kperf_kdbg_cswitch_get(void);
extern int kperf_kdbg_cswitch_set(int newval);

/* get and set whether to trigger an action on context-switch */
extern int kperf_cswitch_action_get(void);
extern int kperf_cswitch_action_set(int newval);

/* given a task port, find out its pid */
int kperf_port_to_pid(mach_port_name_t portname);

/* Check whether the current process has been blessed to allow access
 * to kperf facilities.
 */
extern int kperf_access_check(void);

/* track recursion on kdebug tracepoint tracking */
extern int kperf_kdbg_recurse(int step);
#define KPERF_RECURSE_IN  (1)
#define KPERF_RECURSE_OUT (-1)

/* context switch tracking */
extern void kperf_switch_context( thread_t old, thread_t new );

/* bootstrap */
extern void kperf_bootstrap(void);

#endif /* __KPERF_H__ */
