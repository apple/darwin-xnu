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

/* fwd decl */
struct kperf_sample;
struct kperf_context;

/* bits for defining what to do on an action */
#define SAMPLER_TINFO      (1<<0)
#define SAMPLER_TINFOEX    (1<<1)
#define SAMPLER_KSTACK     (1<<2)
#define SAMPLER_USTACK     (1<<3)
#define SAMPLER_PMC_THREAD (1<<4)
#define SAMPLER_PMC_CPU    (1<<5)
#define SAMPLER_PMC_CONFIG (1<<6)
#define SAMPLER_MEMINFO    (1<<7)

/* flags for sample calls*/
#define SAMPLE_FLAG_PEND_USER    (1<<0)
#define SAMPLE_FLAG_IDLE_THREADS (1<<1)
#define SAMPLE_FLAG_EMPTY_CALLSTACK (1<<2)

/*  Take a sample into "sbuf" using current thread "cur_thread" */
extern kern_return_t kperf_sample(struct kperf_sample *sbuf,
                                  struct kperf_context*,
                                  unsigned actionid,
                                  unsigned sample_flags);

/* return codes from taking a sample
 * either keep trigger, or something went wrong (or we're shutting down)
 * so turn off.
 */
#define SAMPLE_CONTINUE (0)
#define SAMPLE_SHUTDOWN (1)
#define SAMPLE_OFF      (2)

/* Get the sample buffer to use from interrupt handler context. Only
 * valid in interrupt contexts.
 */
extern struct kperf_sample* kperf_intr_sample_buffer(void);

/* Interface functions  */
extern unsigned kperf_action_get_count(void);
extern int kperf_action_set_count(unsigned count);

extern int kperf_action_set_samplers(unsigned actionid,
                                     uint32_t samplers);
extern int kperf_action_get_samplers(unsigned actionid,
                                     uint32_t *samplers_out);

extern int kperf_action_set_userdata(unsigned actionid,
                                     uint32_t userdata);
extern int kperf_action_get_userdata(unsigned actionid,
                                     uint32_t *userdata_out);

extern int kperf_action_set_filter(unsigned actionid,
                                   int pid);
extern int kperf_action_get_filter(unsigned actionid,
                                   int *pid_out);
