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

#ifndef __AP_THREADINFO_H__
#define __AP_THREADINFO_H__

/* 'live' threadinfo */
struct threadinfo
{
	uint64_t pid;
	uint64_t tid;
	uint64_t dq_addr;
	uint64_t runmode;
};

/* extra info we sample out of bounds */
#define CHUD_MAXPCOMM 16  /* copy from kernel somewhere :P */
struct tinfo_ex
{
	char p_comm[CHUD_MAXPCOMM+1]; /* XXX: 16 + 1 */
};

struct kperf_context;
extern void kperf_threadinfo_sample(struct threadinfo *ti, struct kperf_context *);
extern void kperf_threadinfo_log(struct threadinfo *ti);

extern void kperf_threadinfo_extra_sample(struct tinfo_ex *, struct kperf_context *);
extern int kperf_threadinfo_extra_pend(struct kperf_context *);
extern void kperf_threadinfo_extra_log(struct tinfo_ex *);

#endif /* __AP_THREADINFO_H__ */
