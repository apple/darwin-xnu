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
#pragma ident	"@(#)trivial.c	1.0	08/17/06 Apple Inc."
#endif



#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
// add additional headers needed here.
#include <fcntl.h>

#include "../libmicro.h"

#if DEBUG
# define debug(fmt, args...)	(void) fprintf(stderr, fmt "\n" , ##args)
#else
# define debug(fmt, args...)
#endif

#define MAXPATHLEN	1024
/*
 *	Your state variables should live in the tsd_t struct below
 */
typedef struct {
        int     ts_once;
} tsd_t;

/*
 * You can have any lower-case option you want to define.
 * options are specified in the lm_optstr as either a 
 * single lower-case letter, or a single lower case letter 
 * with a colon after it.  In this example, you can optionally
 * specify -c {str} -e or -t {number}  
 *    -c takes a string (quote the string if blanks)
 *    -e is a boolean 
 *    -t takes a numeric
 * argument.
 */
static char *	optf; // allocated in benchmark_init, freed in benchmark_fini.


int
benchmark_init()
{
	debug("benchmark_init\n");
	/* 
	 *	the lm_optstr must be defined here or no options for you
	 *
	 * 	...and the framework will throw an error
	 *
	 */
	(void) sprintf(lm_optstr, "f:");
	/*
	 * 	tsd_t is the state info struct that we pass around 
	 *
	 *	lm_tsdsize will allocate the space we need for this
	 *	structure throughout the rest of the framework
	 */
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_usage,
		"		-f filename\n"
	    "notes: measures file creation using open(2)\n");
	
	optf = malloc(MAXPATHLEN);
	sprintf(optf, "/tmp/create_file_%d", getpid());
	return (0);
}

/*
 * This is where you parse your lower-case arguments.
 * the format was defined in the lm_optstr assignment
 * in benchmark_init
 */
int
benchmark_optswitch(int opt, char *optarg)
{
	debug("benchmark_optswitch\n");
	
	switch (opt) {
	case 'f':
		strncpy(optf, optarg, 20);
		(void)fprintf(stderr, "optf = %s\n", optf);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initrun()
{
	debug("benchmark_initrun\n");
	return (0);
}

int
benchmark_initworker(void *tsd)
{
	/*
	 *	initialize your state variables here first
	 */
//	tsd_t			*ts = (tsd_t *)tsd;
//	debug("benchmark_initworker: ts_once = %i\n",ts->ts_once);	
	return (0);
}

/*ARGSUSED*/
int
benchmark_initbatch(void *tsd)
{
	/*
	 * initialize your state variables here second
	 */
	tsd_t			*ts = (tsd_t *)tsd;
	// useless code to show what you can do.
	 ts->ts_once++;
	 ts->ts_once--;
	debug("benchmark_initbatch: ts_once = %i\n",ts->ts_once);
	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	/* 
	 *	try not to initialize things here.  This is the main
	 *  loop of things to get timed.  Start a server in 
	 *  benchmark_initbatch
	 */
//	tsd_t			*ts = (tsd_t *)tsd;
	int			i;
	
	debug("in to benchmark - optB = %i : ts_once = %i\n", lm_optB, ts->ts_once);
	for (i = 0; i < lm_optB; i++) {
		 if (!open(optf, O_CREAT))
		 	res->re_errors++;
	}
	res->re_count = i;
	debug("out of benchmark - optB = %i : ts_once = %i\n", lm_optB, ts->ts_once);

	return (0);
}

int
benchmark_finibatch(void *tsd)
{
//	tsd_t			*ts = (tsd_t *)tsd;
//	debug("benchmark_finibatch: ts_once = %i\n",ts->ts_once);
	return (0);
}

int
benchmark_finiworker(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	// useless code to show what you can do.
	 ts->ts_once++;
	 ts->ts_once--;
	debug("benchmark_finiworker: ts_once = %i\n",ts->ts_once);
	return (0);
}

char *
benchmark_result()
{
	static char		result = '\0';
	debug("benchmark_result\n");
	return (&result);
}

int
benchmark_finirun()
{
	debug("benchmark_finirun\n");
	return (0);
}


int
benchmark_fini()
{
	debug("benchmark_fini\n");
	free(optf);
	return (0);
}

