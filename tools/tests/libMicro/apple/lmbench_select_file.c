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
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "../libmicro.h"

/*
 * lmbench routines, etc. brought over for this benchmark
 */
int  open_file(void* tsd);
void server(void* tsd);


typedef int (*open_f)(void* tsd);
/*
 * end of lmbench support routines
 */

/*
 *	Your state variables should live in the tsd_t struct below
 */
typedef struct {
	char	fname[L_tmpnam];
	open_f	fid_f;
	pid_t	pid;
	int	sock;
	int	fid;
	int	num;
	int	max;
	fd_set  set;
} tsd_t;

static int 	optt = 1;
static int 	optn = -1;
static int 	optp = 1;
static int	optw = 0;

/*
 * lmbench routines, etc. brought over for this benchmark
 */
 
void
morefds(void)
{
#ifdef  RLIMIT_NOFILE
        struct  rlimit r;

        getrlimit(RLIMIT_NOFILE, &r);
        r.rlim_cur = r.rlim_max;
        setrlimit(RLIMIT_NOFILE, &r);
#endif
}

int
open_file(void* tsd)
{
	tsd_t* ts = (tsd_t*)tsd;
	//(void) fprintf(stderr, "open_file: ts->fname = %s\n",ts->fname);
	return (int) open(ts->fname, O_RDONLY);
}

void
server(void* tsd)
{
	int pid;
	tsd_t* ts = (tsd_t*)tsd;

	pid = getpid();
	ts->pid = 0;
	//(void) fprintf(stderr, "server: state->fid_f = %i\n",ts->fid_f);
	
	if (ts->fid_f == open_file) {
		/* Create a temporary file for clients to open */
		sprintf(ts->fname, "/tmp/lat_selectXXXXXX");
		//(void) fprintf(stderr, "server: ts->fname = %s\n",ts->fname);
		ts->fid = mkstemp(ts->fname);
		//(void) fprintf(stderr, "server: ts->fname = %s: ts->fid = %d\n",ts->fname, ts->fid);

		if (ts->fid <= 0) {
			char buf[L_tmpnam+128];
			sprintf(buf, "lat_select: Could not create temp file %s", ts->fname);
			perror(buf);
			exit(1);
		}
		close(ts->fid);
		return;
	}
//
//	this is all for the tcp version of this test only
//
// 	/* Create a socket for clients to connect to */
// 	state->sock = tcp_server(TCP_SELECT, SOCKOPT_REUSE);
// 	if (state->sock <= 0) {
// 		perror("lat_select: Could not open tcp server socket");
// 		exit(1);
// 	}

	/* Start a server process to accept client connections */
// 	switch(state->pid = fork()) {
// 	case 0:
// 		/* child server process */
// 		while (pid == getppid()) {
// 			int newsock = tcp_accept(state->sock, SOCKOPT_NONE);
// 			read(newsock, &state->fid, 1);
// 			close(newsock);
// 		}
// 		exit(0);
// 	case -1:
// 		/* error */
// 		perror("lat_select::server(): fork() failed");
// 		exit(1);
// 	default:
// 		break;
// 	}
}


/*
 * end of lmbench support routines
 */

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
	//(void) fprintf(stderr, "benchmark_finirun\n");
	return (0);
}

int
benchmark_init()
{
	//(void) fprintf(stderr, "benchmark_init\n");
	/* 
	 *	the lm_optstr must be defined here or no options for you
	 *
	 * 	...and the framework will throw an error
	 *
	 */
	(void) sprintf(lm_optstr, "p:w:n:t:");
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
		"       [-p parallelism (default 1)]\n"			
		"       [-w warmup (default 0)]\n"
		"       [-n number of descriptors (default 1)]\n"
	    "       [-t int (default 1)]\n"
	    "notes: measures lmbench_select_file\n");
	lm_defB = 1;
	return (0);
}

int
benchmark_fini()
{
	//(void) fprintf(stderr, "benchmark_fini\n");
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
	//(void) fprintf(stderr, "benchmark_result\n");
	return (&result);
}

int
benchmark_finiworker(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int i;
	// pulls in the lmbench cleanup code
	//(void) fprintf(stderr, "benchmark_finiworker\n");
	for (i = 0; i <= ts->max; ++i) {
		if (FD_ISSET(i, &(ts->set)))
			close(i);
	}
	FD_ZERO(&(ts->set));
	unlink(ts->fname);
	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	//(void) fprintf(stderr, "benchmark_optswitch\n");
	
	switch (opt) {
	case 't':
		optt = sizetoint(optarg);
		break;
	case 'n':
		optn = sizetoint(optarg);
		break;
	case 'p':
		optp = sizetoint(optarg);
		break;
	case 'w':
		optw = sizetoint(optarg);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initworker(void *tsd)
{	
	// pulls in code from lmbench main and initialize
	int		n = 0;
	/*
	 *	initialize your state variables here first
	 */
	tsd_t			*ts = (tsd_t *)tsd;
	int	N, fid, fd;
	
	/*
	 * default number of file descriptors
	 */
	//(void) fprintf(stderr, "benchmark_initworker\n");
	ts->num = 200;
	if (optn > 0) {
		ts->num = optn;
	}
	N = ts->num;
	//(void) fprintf(stderr, "benchmark_initworker ts->num is %i\n",ts->num);
	
	/*
	 *	grab more file descriptors
	 */
	 
	morefds();
	
	ts->fid_f = open_file;
	server(ts);
	//(void) fprintf(stderr, "benchmark_initworker: returned from server call\n");
	/* 
	 * Initialize function from lmbench
	 * for this test
	 */
	fid = (*ts->fid_f)(ts);
	//(void) fprintf(stderr, "initworker: fid is %i\n",fid);
	if (fid <= 0) {
		perror("Could not open device");
		exit(1);
	}
	ts->max = 0;
	FD_ZERO(&(ts->set));
	//(void) fprintf(stderr, "initworker FD_ZERO: ts->set result is %i\n",ts->set);
	//(void) fprintf(stderr, "initworker: N is %i\n",N);
	for (n = 0; n < N; n++) {
		//(void) fprintf(stderr, "benchmark_initworker: in the loop - N is %i: n is %i\n",N, n);
		fd = dup(fid);
		//(void) fprintf(stderr, "benchmark_initworker: dup result is %i\n",fd);
		//(void) fprintf(stderr, "benchmark_initworker: errno result is %d - \"%s\"\n",errno, strerror(errno));

		if (fd == -1) break;
		if (fd > ts->max)
			ts->max = fd;
		FD_SET(fd, &(ts->set));
		//(void) fprintf(stderr, "initworker FD_SET: ts->set result is %i\n",ts->set);

	}
	//(void) fprintf(stderr, "benchmark_initworker: after second macro/loop\n");

	ts->max++;
	close(fid);
	//(void) fprintf(stderr, "benchmark_initworker: N is %i: n is %i\n",N, n);
	if (n != N)
		exit(1);
	/* end of initialize function */
	//(void) fprintf(stderr, "benchmark_initworker: about to exit\n");
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
	tsd_t			*ts = (tsd_t *)tsd;
	fd_set		nosave;
	static struct timeval tv;

	//(void) fprintf(stderr, "benchmark\n");

	int			i;
	//int 		sel_res;
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	
	for (i = 0; i < lm_optB; i++) {
		 nosave = ts->set;
		 //(void) fprintf(stderr, "benchmark: nosave is %i\n", nosave);

		 select(ts->num, 0, &nosave, 0, &tv);
		 //(void) fprintf(stderr, "benchmark: select result is %i\n",sel_res);
		 //(void) fprintf(stderr, "benchmark: errno result is %d - \"%s\"\n",errno, strerror(errno));

		 
	}
	res->re_count = i;
	return (0);
}

