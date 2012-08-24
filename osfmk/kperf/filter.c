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

/*  Toy filtering. Allow system-wide or filtering on 4 PIDs */

#include <mach/mach_types.h>
#include <sys/types.h> /* NULL */
// #include <libkern/libkern.h>

#include <kperf/context.h>
#include <kperf/filter.h>

// Filter params... dodge for now
#define NPIDS (4)
int pid_list[NPIDS];

// function to determine whether we should take a sample
int
kperf_filter_should_sample(struct kperf_context *context)
{
	int i, restricted = 0;

	/* see if the pids are restricted */
	for( i = 0; i < NPIDS; i++ )
	{
		if( context->cur_pid == pid_list[i] )
			return 1;

		if( pid_list[i] != -1 )
			restricted = 1;
	}

	/* wasn't in the pid list, but something was */
	if( restricted )
		return 0;

	/* not fitered, sample it */
	return 1;
}

/* check whether pid filtering is enabled */
int
kperf_filter_on_pid(void)
{
	int i;

	for( i = 0; i < NPIDS; i++ )
		if( pid_list[i] != -1 )
			return 1;

	return 0;
}

/* create a list of pids to filter */
void
kperf_filter_pid_list( int *outcount, int **outv )
{
	int i, found = 0;

	for( i = 0; i < NPIDS; i++ )
		if( pid_list[i] != -1 )
			found = 1;

	if( !found )
	{
		*outcount = 0;
		*outv = NULL;
		return;
	}

	/* just return our list */
	*outcount = NPIDS;
	*outv = pid_list;
}

/* free a list we created*/
void
kperf_filter_free_pid_list( int *incount, int **inv )
{
	// no op
	(void) incount;
	(void) inv;
}

/* init the filters to nothing */
void
kperf_filter_init(void)
{
	int i;
	for( i = 0; i < NPIDS; i++ )
		pid_list[i] = -1;
}
