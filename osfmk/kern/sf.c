/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 * 
 */

#include <kern/sf.h>
#include <kern/mk_sp.h>
#include <mach/policy.h>

sched_policy_t	sched_policy[MAX_SCHED_POLS];

void
sf_init(void)
{
	sched_policy[POLICY_TIMESHARE].policy_id = POLICY_TIMESHARE;
	sched_policy[POLICY_RR].policy_id = POLICY_RR;
	sched_policy[POLICY_FIFO].policy_id = POLICY_FIFO;

	sched_policy[POLICY_TIMESHARE].sp_ops = 
		sched_policy[POLICY_RR].sp_ops =
		sched_policy[POLICY_FIFO].sp_ops = mk_sp_ops;
}
