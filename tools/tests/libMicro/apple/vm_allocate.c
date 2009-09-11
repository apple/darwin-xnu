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
#pragma ident	"@(#)vm_allocate.c	1.0	09/17/06 Apple Inc."
#endif



#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <mach/mach.h>

#include "../libmicro.h"

/*
 *	Your state variables should live in the tsd_t struct below
 */
typedef struct {
        int     ts_once;
} tsd_t;

unsigned char * arena;
unsigned int    arenaSize = 1;

static int 	optt = 0;

/*ARGSUSED*/
int
benchmark_initbatch(void *tsd)
{
	/*
	 * initialize your state variables here second
	 */
	//tsd_t			*ts = (tsd_t *)tsd;
	//(void) fprintf(stderr, "benchmark_initbatch: ts_once = %i\n",ts->ts_once);
	return (0);
}

int
benchmark_finirun()
{
	(void) fprintf(stderr, "benchmark_finirun\n");
	return (0);
}

int
benchmark_init()
{
	(void) fprintf(stderr, "benchmark_init\n");
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
	 *	lm_tsdsize will allocate the space we need for this
	 *	structure throughout the rest of the framework
	 */
	lm_tsdsize = sizeof (tsd_t);
	lm_defB = 1;


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
	tsd_t			*ts = (tsd_t *)tsd;
	/* 
	 *	more proof of state passing
	 */
	ts->ts_once = optt;
	//(void) fprintf(stderr, "benchmark_finibatch: ts_once = %i\n",ts->ts_once);
	return (0);
}

char *
benchmark_result()
{
	static char		result = '\0';
	(void) fprintf(stderr, "benchmark_result\n");
	return (&result);
}

int
benchmark_finiworker(void *tsd)
{
	//tsd_t			*ts = (tsd_t *)tsd;
	//(void) fprintf(stderr, "benchmark_finiworker: ts_once = %i\n",ts->ts_once);
	//vm_deallocate( mach_task_self(), (vm_address_t) arena, arenaSize * vm_page_size);

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	(void) fprintf(stderr, "benchmark_optswitch\n");
	
	switch (opt) {
	case 't':
		optt = sizetoint(optarg);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initworker(void *tsd)
{
	/*
	 *	initialize your state variables here first
	 */
	//tsd_t			*ts = (tsd_t *)tsd;
	//ts->ts_once = optt;
	//(void) fprintf(stderr, "benchmark_initworker: ts_once = %i\n",ts->ts_once);
	if ( optt > 0 ) {
		arenaSize = optt;
	}
	// warmup
	vm_allocate( mach_task_self(), (vm_address_t *) &arena, arenaSize * vm_page_size, 1);
	
	vm_deallocate( mach_task_self(), (vm_address_t) arena, arenaSize * vm_page_size);
	//arena = ( unsigned char * )malloc( arenaSize);
	return (0);
}

int
benchmark_initrun()
{
	//(void) fprintf(stderr, "benchmark_initrun\n");
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
	//tsd_t			*ts = (tsd_t *)tsd;
	int			i;
	
	//(void) fprintf(stderr, "in to benchmark - optB = %i\n", lm_optB);
	for (i = 0; i < lm_optB; i++) {
		/*
		 *	just to show that ts really contains state
		 */
		 //(void) fprintf(stderr, "i is %i\n",i);
		if (vm_allocate( mach_task_self(), (vm_address_t *) &arena, arenaSize * vm_page_size, 1))
			abort();
		if (vm_deallocate( mach_task_self(), (vm_address_t) arena, arenaSize * vm_page_size))
			abort();

	}
	res->re_count = i;
	//(void) fprintf(stderr, "out of benchmark - optB = %i : ts_once = %i\n", lm_optB, ts->ts_once);

	return (0);
}
