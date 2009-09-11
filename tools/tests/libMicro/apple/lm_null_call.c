/*
 * Copyright (c) 2006 Apple Inc.  All Rights Reserved.
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


/*
 *	Order of Execution
 *
 *	benchmark_init
 *
 *	benchmark_optswitch
 *
 *		benchmark_initrun
 *
 *			benchmark_initworker
 *				benchmark_initbatch
 *					benchmark
 *				benchmark_finibatch
 *				benchmark_initbatch
 *					benchmark
 *				benchmark_finibatch, etc.
 *			benchmark_finiworker
 *
 *		benchmark_result
 *
 *		benchmark_finirun
 *
 *	benchmark_fini
 */



#ifdef	__sun
#pragma ident	"@(#)socket.c	1.3	05/08/04 Apple Inc."
#endif



#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "../libmicro.h"

/*
 *	Your state variables should live in the tsd_t struct below
 */
typedef struct {
	int fd;
	char* file;
} tsd_t;

/*ARGSUSED*/
int
benchmark_initbatch(void *tsd)
{
	return (0);
}

int
benchmark_finirun()
{
	return (0);
}

int
benchmark_init()
{
	/* 
	 *	the lm_optstr must be defined here or no options for you
	 *
	 * 	...and the framework will throw an error
	 *
	 */
	(void) sprintf(lm_optstr, "t:");
	/*
	 *	working hypothesis:
	 *	
	 * 	tsd_t is the struct that we can pass around our
	 *	state info in
	 *
	 *	 will allocate the space we need for this
	 *	structure throughout the rest of the framework
	 */
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_usage,
	    "       [-t int (default 1)]\n"
	    "notes: measures nothing\n");
	return (0);
}

int
benchmark_fini()
{
	(void) fprintf(stderr, "benchmark_fini\n");
	return (0);
}

int
benchmark_finibatch(void *tsd)
{
	return (0);
}

char *
benchmark_result()
{
	static char		result = '\0';
	(void) fprintf(stderr, "null_call (getppid)\n");
	return (&result);
}

int
benchmark_finiworker(void *tsd)
{
	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	return (0);
}

int
benchmark_initworker(void *tsd)
{
	/*
	 *	initialize your state variables here first
	 */
	return (0);
}

int
benchmark_initrun()
{
	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	/* 
	 *	initialize your state variables here last
	 * 
	 * 	and realize that you are paying for your initialization here
	 *	and it is really a bad idea
	 */
	int			i;
	
	for (i = 0; i < lm_optB; i++) {
		/*
		 *	just to show that ts really contains state
		 */
		getppid();
	}
	res->re_count = i;

	return (0);
}
