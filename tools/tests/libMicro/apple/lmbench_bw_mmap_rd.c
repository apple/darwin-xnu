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
#pragma ident	"@(#)lmbench_bw_mmap_rd.c	1.0	08/17/06 Apple Inc."
#endif



#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
// add additional headers needed here.
#include <fcntl.h>
#include <limits.h>
#include <sys/mman.h>

#include "../libmicro.h"

#if DEBUG
# define debug(fmt, args...)	(void) fprintf(stderr, fmt "\n" , ##args)
#else
# define debug(fmt, args...)
#endif

/*
 *	Your state variables should live in the tsd_t struct below
 */
typedef struct {
	size_t	nbytes;
	char 	filename[_POSIX_PATH_MAX];
	int 	fd;
	int 	clone;
	void	*buf;
	bool open_read_close;
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
static char 	optf[_POSIX_PATH_MAX]; 
static int		opts = 1024;
static bool 	opti = false;	// io_only or read and i/o (default read and i/o)

#ifdef MAP_FILE
#	define	MMAP_FLAGS	MAP_FILE|MAP_SHARED
#else
#	define	MMAP_FLAGS	MAP_SHARED
#endif

#define	CHK(x)		if ((int)(x) == -1) { perror(#x); exit(1); }
#ifndef	MIN
#define	MIN(a, b)	((a) < (b) ? (a) : (b))
#endif

#define	TYPE	int
#define	MINSZ	(sizeof(TYPE) * 128)

void	*buf;		/* do the I/O here */
size_t	xfersize;	/* do it in units of this */
size_t	count;		/* bytes to move (can't be modified) */

/* analogous to bzero, bcopy, etc., except that it just reads
 * data into the processor
 */
long
bread(void* buf, long nbytes)
{
	long sum = 0;
	register long *p, *next;
	register char *end;

	p = (long*)buf;
	end = (char*)buf + nbytes;
	for (next = p + 128; (void*)next <= (void*)end; p = next, next += 128) {
		sum +=
			p[0]+p[1]+p[2]+p[3]+p[4]+p[5]+p[6]+p[7]+
			p[8]+p[9]+p[10]+p[11]+p[12]+p[13]+p[14]+
			p[15]+p[16]+p[17]+p[18]+p[19]+p[20]+p[21]+
			p[22]+p[23]+p[24]+p[25]+p[26]+p[27]+p[28]+
			p[29]+p[30]+p[31]+p[32]+p[33]+p[34]+p[35]+
			p[36]+p[37]+p[38]+p[39]+p[40]+p[41]+p[42]+
			p[43]+p[44]+p[45]+p[46]+p[47]+p[48]+p[49]+
			p[50]+p[51]+p[52]+p[53]+p[54]+p[55]+p[56]+
			p[57]+p[58]+p[59]+p[60]+p[61]+p[62]+p[63]+
			p[64]+p[65]+p[66]+p[67]+p[68]+p[69]+p[70]+
			p[71]+p[72]+p[73]+p[74]+p[75]+p[76]+p[77]+
			p[78]+p[79]+p[80]+p[81]+p[82]+p[83]+p[84]+
			p[85]+p[86]+p[87]+p[88]+p[89]+p[90]+p[91]+
			p[92]+p[93]+p[94]+p[95]+p[96]+p[97]+p[98]+
			p[99]+p[100]+p[101]+p[102]+p[103]+p[104]+
			p[105]+p[106]+p[107]+p[108]+p[109]+p[110]+
			p[111]+p[112]+p[113]+p[114]+p[115]+p[116]+
			p[117]+p[118]+p[119]+p[120]+p[121]+p[122]+
			p[123]+p[124]+p[125]+p[126]+p[127];
	}
	for (next = p + 16; (void*)next <= (void*)end; p = next, next += 16) {
		sum +=
			p[0]+p[1]+p[2]+p[3]+p[4]+p[5]+p[6]+p[7]+
			p[8]+p[9]+p[10]+p[11]+p[12]+p[13]+p[14]+
			p[15];
	}
	for (next = p + 1; (void*)next <= (void*)end; p = next, next++) {
		sum += *p;
	}
	return sum;
}

int
cp(char* src, char* dst, mode_t mode)
{
    int sfd, dfd;
    char buf[8192];
    ssize_t size;

    if ((sfd = open(src, O_RDONLY)) < 0) {
        return -1;
    }
    if ((dfd = open(dst, O_CREAT|O_TRUNC|O_RDWR, mode)) < 0) {
        return -1;
    }
    while ((size = read(sfd, buf, 8192)) > 0) {
        if (write(dfd, buf, size) < size) return -1;
    }
    fsync(dfd);
    close(sfd);
    close(dfd);
    return 0;
}


int
benchmark_init()
{
	debug("benchmark_init");
	/* 
	 *	the lm_optstr must be defined here or no options for you
	 *
	 * 	...and the framework will throw an error
	 *
	 */
	(void) sprintf(lm_optstr, "f:is:");
	/*
	 * 	tsd_t is the state info struct that we pass around 
	 *
	 *	lm_tsdsize will allocate the space we need for this
	 *	structure throughout the rest of the framework
	 */
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_usage,
		"		-f filename\n"
		"		-s size\n"
		"		[-i] io_only (no open/close)\n"
	    "notes: read and sum file via memory mapping mmap(2) interface");
	sprintf(optf, "/tmp/%d", (int)getpid());
	opts = 1024;
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
	debug("benchmark_optswitch");
	
	switch (opt) {
	case 'f':
		strncpy(optf, optarg, 255);
		debug("optf = %s\n", optf);
		break;
	case 'i':
		opti = true;
		debug("opti = %s\n", opti? "true": "false");
		break;
	case 's':
		opts = sizetoint(optarg);
		debug("opts = %d\n", opts);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initrun()
{
	debug("benchmark_initrun");
	return (0);
}

int
benchmark_initworker(void *tsd)
{
	/*
	 *	initialize your state variables here first
	 */
	tsd_t	*state = (tsd_t *)tsd;
	
	strncpy(state->filename, optf, 255);
	state->nbytes = opts;
	state->open_read_close = opti;

	debug("benchmark_initworker\n");	
	return (0);
}

/*ARGSUSED*/
int
benchmark_initbatch(void *tsd)
{
	tsd_t	*state = (tsd_t *)tsd;
	state->fd = -1;
	state->buf = NULL;

	if (state->clone) {
		char buf[8192];
		char* s;

		/* copy original file into a process-specific one */
		sprintf(buf, "/tmp/%d", (int)getpid());
		s = (char*)malloc(strlen(state->filename) + strlen(buf) + 1);
		sprintf(s, "/tmp/%s%d", state->filename, (int)getpid());
		if (cp(state->filename, s, S_IREAD|S_IWRITE) < 0) {
			perror("creating private tempfile");
			unlink(s);
			exit(1);
		}
		strcpy(state->filename, s);
	}

	CHK(state->fd = open(state->filename, 0));
	CHK(state->buf = mmap(0, state->nbytes, PROT_READ,
				     MMAP_FLAGS, state->fd, 0));
	debug("benchmark_initbatch");
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
	int		i;
	int		fd;
	void	*p;
	
	debug("in to benchmark - optB = %i", lm_optB);
	for (i = 0; i < lm_optB; i++) {
		if (state->open_read_close) {
			CHK(fd = open(state->filename, 0));
			CHK(p = mmap(0, state->nbytes, PROT_READ, MMAP_FLAGS, fd, 0));
			bread(p, state->nbytes);
			close(fd);
			munmap(p, state->nbytes);
		} else {
			bread(state->buf, state->nbytes);
		}
	}
	res->re_count = i;
	debug("out of benchmark - optB = %i", lm_optB);

	return (0);
}

int
benchmark_finibatch(void *tsd)
{
	tsd_t	*state = (tsd_t *)tsd;
	if (state->buf) munmap(state->buf, state->nbytes);
	if (state->fd >= 0) close(state->fd);
	if (state->clone) unlink(state->filename);
	debug("benchmark_finibatch");
	return (0);
}

int
benchmark_finiworker(void *tsd)
{
	debug("benchmark_finiworker");
	return (0);
}

char *
benchmark_result()
{
	static char		result = '\0';
	debug("benchmark_result");
	return (&result);
}

int
benchmark_finirun()
{
	debug("benchmark_finirun");
	return (0);
}


int
benchmark_fini()
{
	debug("benchmark_fini");
	return (0);
}

