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
#pragma ident	"@(#)lmbench_lat_sig_catch.c	1.0	08/16/06 Apple Inc."
#endif



#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>

#include "../libmicro.h"

/*
 *	Your state variables should live in the tsd_t struct below
 */
 
static int optp = 1;
static int optw = 0;
static int optn = -1;

u_int64_t	caught, n;
double	adj;
void	handler(int s) { }
jmp_buf	prot_env;

typedef struct {
        int     pid;
} tsd_t;

/*ARGSUSED*/
int
benchmark_initbatch(void *tsd)
{
	/*
	 * initialize your state variables here second
	 */
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
	(void) sprintf(lm_optstr, "p:w:n");
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

	(void) sprintf(lm_usage,
	    "       [-p <parallelism>]\n"	    
	    "       [-w <warmup>]\n"
	    "       [-n <repetitions>]\n"
	    "notes: measures lmbench lat_sig install\n");
	lm_defB = 1;
	return (0);
}

int
benchmark_fini()
{
	return (0);
}

int
benchmark_finibatch(void *tsd)
{
	/* 
	 *	more proof of state passing
	 */
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
	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	
	switch (opt) {
	case 'w':
		optw = sizetoint(optarg);
		break;
	case 'n':
		optn = sizetoint(optarg);
		break;
	case 'p':
		optp = sizetoint(optarg);
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
	tsd_t* ts = (tsd_t*)tsd;
	struct	sigaction sa, old;
	
	sa.sa_handler = handler;
	(void) sigemptyset(&sa.sa_mask);	
	sa.sa_flags = 0;
	(void) sigaction(SIGUSR1, &sa, &old);

    ts->pid = getpid();
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
	int i;
	tsd_t* ts = (tsd_t*)tsd;
	
	for (i = 0; i < lm_optB; i++) {
		(void) kill(ts->pid, SIGUSR1);
	}
	res->re_count = i;

	return (0);
}
