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
#include <sys/socket.h>
#include <signal.h>

#include "../libmicro.h"

void	writer(int controlfd, int writefd, char* buf, void* cookie);
void	touch(char *buf, int nbytes);

#if DEBUG
# define debug(fmt, args...)	(void) fprintf(stderr, fmt "\n" , ##args)
#else
# define debug(fmt, args...)
#endif

/*
 *	Your state variables should live in the tsd_t struct below
 */
typedef struct {
	int	pid;
	size_t	xfer;	/* bytes to read/write per "packet" */
	size_t	bytes;	/* bytes to read/write in one iteration */
	char	*buf;	/* buffer memory space */
	int	pipes[2];
	int	control[2];
	int	initerr;
	int	parallel;
	int warmup;
	int repetitions;
} tsd_t;

size_t	XFER	= 10*1024*1024;
#ifndef XFERSIZE
#define XFERSIZE    (64*1024)   /* all bandwidth I/O should use this */
#endif

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
static int	optm = XFERSIZE;
static int	opts = 10*1024*1024;
static int	optw = 0;

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
	(void) sprintf(lm_optstr, "m:s:w:");
	/*
	 *	
	 * 	tsd_t is the state_information struct 
	 *
	 *	lm_tsdsize will allocate the space we need for this
	 *	structure throughout the rest of the framework
	 */
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_usage,
		"		[-m <message size>]\n"
		"		[-s <total bytes>]\n"
		"		[-w <warmup>]\n");
	
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
		case 'm':
			optm = atoi(optarg);
			break;
		case 's':
			opts = atoi(optarg);
			break;
		case 'w':
			optw = atoi(optarg);
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
	tsd_t	*state = (tsd_t *)tsd;
	state->xfer = optm;
	state->bytes = opts;
	state->parallel = lm_optP;
	state->warmup = optw;
	state->repetitions = lm_optB;
	debug("benchmark_initworker: repetitions = %i\n",state->repetitions);	
	return (0);
}

/*ARGSUSED*/
int
benchmark_initbatch(void *tsd)
{
	tsd_t	*state = (tsd_t *)tsd;

	state->buf = valloc(XFERSIZE);
	touch(state->buf, XFERSIZE);
	state->initerr = 0;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, state->pipes) == -1) {
		perror("socketpair");
		state->initerr = 1;
		return(0);
	}
	if (pipe(state->control) == -1) {
		perror("pipe");
		state->initerr = 2;
		return(0);
	}
//	handle_scheduler(benchmp_childid(), 0, 1);
	switch (state->pid = fork()) {
	    case 0:
//	      handle_scheduler(benchmp_childid(), 1, 1);
		close(state->control[1]);
		close(state->pipes[0]);
		writer(state->control[0], state->pipes[1], state->buf, state);
		return (0);
		/*NOTREACHED*/
	    
	    case -1:
		perror("fork");
		state->initerr = 3;
		return (0);
		/*NOTREACHED*/

	    default:
		break;
	}
	close(state->control[0]);
	close(state->pipes[1]);
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
	tsd_t	*state = (tsd_t *)tsd;
	size_t	done, n;
	size_t	todo = state->bytes;
	int		i;
	
	debug("in to benchmark - optB = %i : repetitions = %i\n", lm_optB, state->repetitions);
	for (i = 0; i < lm_optB; i++) {
		write(state->control[1], &todo, sizeof(todo));
		for (done = 0; done < todo; done += n) {
			if ((n = read(state->pipes[0], state->buf, state->xfer)) <= 0) {
				/* error! */
				debug("error (n = %d) exiting now\n", n);
				exit(1);
			}
		}
	}
	res->re_count = i;
	debug("out of benchmark - optB = %i : repetitions = %i\n", lm_optB, state->repetitions);

	return (0);
}

int
benchmark_finibatch(void *tsd)
{
	tsd_t			*state = (tsd_t *)tsd;

	close(state->control[1]);
	close(state->pipes[0]);
	if (state->pid > 0) {
		kill(state->pid, SIGKILL);
		waitpid(state->pid, NULL, 0);
	}
	state->pid = 0;
	return (0);
}

int
benchmark_finiworker(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	// useless code to show what you can do.
	 ts->repetitions++;
	 ts->repetitions--;
	debug("benchmark_finiworker: repetitions = %i\n",ts->repetitions);
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
	return (0);
}

/*
 * functions from bw_unix.c
 */
void
writer(int controlfd, int writefd, char* buf, void* cookie)
{
	size_t	todo, n, done;
	tsd_t	*state = (tsd_t *)cookie;

	for ( ;; ) {
		read(controlfd, &todo, sizeof(todo));
		for (done = 0; done < todo; done += n) {
#ifdef TOUCH
			touch(buf, XFERSIZE);
#endif
			if ((n = write(writefd, buf, state->xfer)) < 0) {
				/* error! */
				exit(1);
			}
		}
	}
}

void
touch(char *buf, int nbytes)
{
    static int	psize;

    if (!psize) {
        psize = getpagesize();
    }
    while (nbytes > 0) {
        *buf = 1;
        buf += psize;
        nbytes -= psize;
    }
}

