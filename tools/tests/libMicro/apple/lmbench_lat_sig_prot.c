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
#pragma ident	"@(#)lmbench_lat_sig_prot.c	1.0	08/16/06 Apple Inc."
#endif



#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <errno.h>


#include "../libmicro.h"

/*
 *	Your state variables should live in the tsd_t struct below
 */
 
static int optp = 1;
static int optw = 0;
static int optn = -1;
static char	*optf = "/Volumes/data/darbench/bin-i386/lmbench_lat_sig_prot";
static int *mappedfile;
jmp_buf jumper;

u_int64_t	caught, n;
double	adj;
void	handler(int s) { }
jmp_buf	prot_env;

typedef struct {
	char*	fname;
	char*	where;
} tsd_t;


void
prot(int s)
{
	_longjmp(jumper, s);

}


/*ARGSUSED*/
int
benchmark_initbatch(void *tsd)
{
	/*
	 * initialize your state variables here second
	 */
	(void) fprintf(stderr, "benchmark_initbatch: entry\n");

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
	(void) sprintf(lm_optstr, "p:w:n:f");
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
	    "       [-f <filename>]\n"
	    "notes: measures lmbench lat_sig prot\n");
	(void) fprintf(stderr, "benchmark_init: entry\n");
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
	(void) fprintf(stderr, "benchmark_optswitch: entry\n");

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
	case 'f':
		(void) fprintf(stderr, "benchmark_optswitch: FILENAME entry = %s\n",optf);
		//strcpy(optf, optarg);
		(void) fprintf(stderr, "benchmark_optswitch: FILENAME exit\n");
		break;
	default:
		return (-1);
	}
	(void) fprintf(stderr, "benchmark_optswitch: exit\n");
	return (0);
}

int
benchmark_initworker(void *tsd)
{
	/*
	 *	initialize your state variables here first
	 */
	tsd_t* ts = (tsd_t*)tsd;
	int fd;
	struct	sigaction sa;
	(void) fprintf(stderr, "benchmark_initworker: entry = %s\n",optf);

    ts->fname = optf;
    fd = open(ts->fname, 0);
    (void) fprintf(stderr, "benchmark_initworker: open result is %i\n",fd);
	(void) fprintf(stderr, "benchmark_initworker: errno result is %d - \"%s\"\n",errno, strerror(errno));

    ts->where = mmap(0,4096, PROT_READ, MAP_SHARED, fd, 0);
    (void) fprintf(stderr, "benchmark_initworker: mmap result is %i\n",ts->where);
	*mappedfile = (int) ts->where;
	(void) fprintf(stderr, "benchmark_initworker: mappedfile result is %i\n",*mappedfile);

    if ((long)ts->where == -1) {
    	perror("mmap");
    	exit(1);
    }
    
    sa.sa_handler = prot;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGSEGV, &sa, 0);
	sigaction(SIGBUS, &sa, 0);
	

    caught = 0;
    n = lm_optB;
	return (0);
}

int
benchmark_initrun()
{
	(void) fprintf(stderr, "benchmark_initrun: entry\n");

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
	//tsd_t* ts = (tsd_t*)tsd;
	(void) fprintf(stderr, "benchmark: lm_optB = %i\n",lm_optB);
	for (i = 0; i < lm_optB; i++) {
		if (_setjmp(jumper) == 0) {
			
			*mappedfile= 1;
		}
	}
	res->re_count = i;

	return (0);
}
