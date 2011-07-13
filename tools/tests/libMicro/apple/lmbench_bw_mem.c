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

/*
 * To port to libmicro, I had to add options for
 * some items which were just arguments before.
 * -s is the size (more than 512)
 * -x is the command to execute (rd wr rdwr cp fwr frd fcp bzero bcopy)
 * see usage string for command options.
 */

#ifdef	__sun
#pragma ident	"@(#)lmbench_bw_mem.c	1.0 20060814 Apple Inc."
#endif


#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../libmicro.h"

#define	TRIES		11	// value from bench.h in lmbench
#define TYPE    	int

/* Added as part of the fix for <rdar://problem/7508837> */
static volatile u_int64_t       use_result_dummy;
void use_int(int result) { use_result_dummy += result; }

/*
 * rd - 4 byte read, 32 byte stride
 * wr - 4 byte write, 32 byte stride
 * rdwr - 4 byte read followed by 4 byte write to same place, 32 byte stride
 * cp - 4 byte read then 4 byte write to different place, 32 byte stride
 * fwr - write every 4 byte word
 * frd - read every 4 byte word
 * fcp - copy every 4 byte word
 *
 * All tests do 512 byte chunks in a loop.
 *
 * XXX - do a 64bit version of this.
 */
void	rd(iter_t iterations, void *cookie);
void	wr(iter_t iterations, void *cookie);
void	rdwr(iter_t iterations, void *cookie);
void	mcp(iter_t iterations, void *cookie);
void	fwr(iter_t iterations, void *cookie);
void	frd(iter_t iterations, void *cookie);
void	fcp(iter_t iterations, void *cookie);
void	loop_bzero(iter_t iterations, void *cookie);
void	loop_bcopy(iter_t iterations, void *cookie);
void	init_overhead(iter_t iterations, void *cookie);
void	init_loop(iter_t iterations, void *cookie);
void	cleanup(iter_t iterations, void *cookie);

typedef struct _state {
	double	overhead;
	size_t	nbytes;
	int	need_buf2;
	int	aligned;
	TYPE	*buf;
	TYPE	*buf2;
	TYPE	*buf2_orig;
	TYPE	*lastone;
	size_t	N;
} state_t;


/*
 *	Your state variables should live in the tsd_t struct below
 */
typedef struct {
	double	overhead;
	size_t	nbytes;
	int	need_buf2;
	int	aligned;
	TYPE	*buf;
	TYPE	*buf2;
	TYPE	*buf2_orig;
	TYPE	*lastone;
	size_t	N;
	int	parallel;
	int	warmup;
	int	repetitions;
} tsd_t;


static int 	optp = 1;
static int	optw = 0;
static int	optn = TRIES;
static int	opt_size = 0;
static char	*opt_what;	// maximum "what" command string size

void
init_overhead(iter_t iterations, void *cookie)
{
}

void
init_loop(iter_t iterations, void *cookie)
{
	tsd_t			*ts = (tsd_t *)cookie;

	if (iterations) return;

    ts->buf = (TYPE *)valloc(ts->nbytes);
	ts->buf2_orig = NULL;
	ts->lastone = (TYPE*)ts->buf - 1;
	ts->lastone = (TYPE*)((char *)ts->buf + ts->nbytes - 512);
	ts->N = ts->nbytes;

	if (!ts->buf) {
		perror("malloc");
		exit(1);
	}
	bzero((void*)ts->buf, ts->nbytes);

	if (ts->need_buf2 == 1) {
		ts->buf2_orig = ts->buf2 = (TYPE *)valloc(ts->nbytes + 2048);
		if (!ts->buf2) {
			perror("malloc");
			exit(1);
		}

		/* default is to have stuff unaligned wrt each other */
		/* XXX - this is not well tested or thought out */
		if (ts->aligned) {
			char	*tmp = (char *)ts->buf2;

			tmp += 2048 - 128;
			ts->buf2 = (TYPE *)tmp;
		}
	}
}

void
cleanup(iter_t iterations, void *cookie)
{
	tsd_t			*ts = (tsd_t *)cookie;

	if (iterations) return;

	free(ts->buf);
	if (ts->buf2_orig) free(ts->buf2_orig);
}

void
rd(iter_t iterations, void *cookie)
{	
	tsd_t			*ts = (tsd_t *)cookie;
	register TYPE *lastone = ts->lastone;
	register int sum = 0;

	while (iterations-- > 0) {
	    register TYPE *p = ts->buf;
	    while (p <= lastone) {
		sum += 
#define	DOIT(i)	p[i]+
		DOIT(0) DOIT(4) DOIT(8) DOIT(12) DOIT(16) DOIT(20) DOIT(24)
		DOIT(28) DOIT(32) DOIT(36) DOIT(40) DOIT(44) DOIT(48) DOIT(52)
		DOIT(56) DOIT(60) DOIT(64) DOIT(68) DOIT(72) DOIT(76)
		DOIT(80) DOIT(84) DOIT(88) DOIT(92) DOIT(96) DOIT(100)
		DOIT(104) DOIT(108) DOIT(112) DOIT(116) DOIT(120) 
		p[124];
		p +=  128;
	    }
	}
	use_int(sum);
}
#undef	DOIT

void
wr(iter_t iterations, void *cookie)
{	
	tsd_t			*ts = (tsd_t *)cookie;
	register TYPE *lastone = ts->lastone;

	while (iterations-- > 0) {
	    register TYPE *p = ts->buf;
	    while (p <= lastone) {
#define	DOIT(i)	p[i] = 1;
		DOIT(0) DOIT(4) DOIT(8) DOIT(12) DOIT(16) DOIT(20) DOIT(24)
		DOIT(28) DOIT(32) DOIT(36) DOIT(40) DOIT(44) DOIT(48) DOIT(52)
		DOIT(56) DOIT(60) DOIT(64) DOIT(68) DOIT(72) DOIT(76)
		DOIT(80) DOIT(84) DOIT(88) DOIT(92) DOIT(96) DOIT(100)
		DOIT(104) DOIT(108) DOIT(112) DOIT(116) DOIT(120) DOIT(124);
		p +=  128;
	    }
	}
}
#undef	DOIT

void
rdwr(iter_t iterations, void *cookie)
{	
	tsd_t			*ts = (tsd_t *)cookie;
	register TYPE *lastone = ts->lastone;
	register int sum = 0;

	while (iterations-- > 0) {
	    register TYPE *p = ts->buf;
	    while (p <= lastone) {
#define	DOIT(i)	sum += p[i]; p[i] = 1;
		DOIT(0) DOIT(4) DOIT(8) DOIT(12) DOIT(16) DOIT(20) DOIT(24)
		DOIT(28) DOIT(32) DOIT(36) DOIT(40) DOIT(44) DOIT(48) DOIT(52)
		DOIT(56) DOIT(60) DOIT(64) DOIT(68) DOIT(72) DOIT(76)
		DOIT(80) DOIT(84) DOIT(88) DOIT(92) DOIT(96) DOIT(100)
		DOIT(104) DOIT(108) DOIT(112) DOIT(116) DOIT(120) DOIT(124);
		p +=  128;
	    }
	}
	use_int(sum);
}
#undef	DOIT

void
mcp(iter_t iterations, void *cookie)
{	
	tsd_t			*ts = (tsd_t *)cookie;
	register TYPE *lastone = ts->lastone;
	TYPE* p_save = NULL;

	while (iterations-- > 0) {
	    register TYPE *p = ts->buf;
	    register TYPE *dst = ts->buf2;
	    while (p <= lastone) {
#define	DOIT(i)	dst[i] = p[i];
		DOIT(0) DOIT(4) DOIT(8) DOIT(12) DOIT(16) DOIT(20) DOIT(24)
		DOIT(28) DOIT(32) DOIT(36) DOIT(40) DOIT(44) DOIT(48) DOIT(52)
		DOIT(56) DOIT(60) DOIT(64) DOIT(68) DOIT(72) DOIT(76)
		DOIT(80) DOIT(84) DOIT(88) DOIT(92) DOIT(96) DOIT(100)
		DOIT(104) DOIT(108) DOIT(112) DOIT(116) DOIT(120) DOIT(124);
		p += 128;
		dst += 128;
	    }
	    p_save = p;
	}
}
#undef	DOIT

void
fwr(iter_t iterations, void *cookie)
{	
	tsd_t			*ts = (tsd_t *)cookie;
	register TYPE *lastone = ts->lastone;
	TYPE* p_save = NULL;

	while (iterations-- > 0) {
	    register TYPE *p = ts->buf;
	    while (p <= lastone) {
#define	DOIT(i)	p[i]=
		DOIT(0) DOIT(1) DOIT(2) DOIT(3) DOIT(4) DOIT(5) DOIT(6)
		DOIT(7) DOIT(8) DOIT(9) DOIT(10) DOIT(11) DOIT(12)
		DOIT(13) DOIT(14) DOIT(15) DOIT(16) DOIT(17) DOIT(18)
		DOIT(19) DOIT(20) DOIT(21) DOIT(22) DOIT(23) DOIT(24)
		DOIT(25) DOIT(26) DOIT(27) DOIT(28) DOIT(29) DOIT(30)
		DOIT(31) DOIT(32) DOIT(33) DOIT(34) DOIT(35) DOIT(36)
		DOIT(37) DOIT(38) DOIT(39) DOIT(40) DOIT(41) DOIT(42)
		DOIT(43) DOIT(44) DOIT(45) DOIT(46) DOIT(47) DOIT(48)
		DOIT(49) DOIT(50) DOIT(51) DOIT(52) DOIT(53) DOIT(54)
		DOIT(55) DOIT(56) DOIT(57) DOIT(58) DOIT(59) DOIT(60)
		DOIT(61) DOIT(62) DOIT(63) DOIT(64) DOIT(65) DOIT(66)
		DOIT(67) DOIT(68) DOIT(69) DOIT(70) DOIT(71) DOIT(72)
		DOIT(73) DOIT(74) DOIT(75) DOIT(76) DOIT(77) DOIT(78)
		DOIT(79) DOIT(80) DOIT(81) DOIT(82) DOIT(83) DOIT(84)
		DOIT(85) DOIT(86) DOIT(87) DOIT(88) DOIT(89) DOIT(90)
		DOIT(91) DOIT(92) DOIT(93) DOIT(94) DOIT(95) DOIT(96)
		DOIT(97) DOIT(98) DOIT(99) DOIT(100) DOIT(101) DOIT(102)
		DOIT(103) DOIT(104) DOIT(105) DOIT(106) DOIT(107)
		DOIT(108) DOIT(109) DOIT(110) DOIT(111) DOIT(112)
		DOIT(113) DOIT(114) DOIT(115) DOIT(116) DOIT(117)
		DOIT(118) DOIT(119) DOIT(120) DOIT(121) DOIT(122)
		DOIT(123) DOIT(124) DOIT(125) DOIT(126) DOIT(127) 1;
		p += 128;
	    }
	    p_save = p;
	}
}
#undef	DOIT

void
frd(iter_t iterations, void *cookie)
{	
	tsd_t			*ts = (tsd_t *)cookie;
	register int sum = 0;
	register TYPE *lastone = ts->lastone;

	while (iterations-- > 0) {
	    register TYPE *p = ts->buf;
	    while (p <= lastone) {
		sum +=
#define	DOIT(i)	p[i]+
		DOIT(0) DOIT(1) DOIT(2) DOIT(3) DOIT(4) DOIT(5) DOIT(6)
		DOIT(7) DOIT(8) DOIT(9) DOIT(10) DOIT(11) DOIT(12)
		DOIT(13) DOIT(14) DOIT(15) DOIT(16) DOIT(17) DOIT(18)
		DOIT(19) DOIT(20) DOIT(21) DOIT(22) DOIT(23) DOIT(24)
		DOIT(25) DOIT(26) DOIT(27) DOIT(28) DOIT(29) DOIT(30)
		DOIT(31) DOIT(32) DOIT(33) DOIT(34) DOIT(35) DOIT(36)
		DOIT(37) DOIT(38) DOIT(39) DOIT(40) DOIT(41) DOIT(42)
		DOIT(43) DOIT(44) DOIT(45) DOIT(46) DOIT(47) DOIT(48)
		DOIT(49) DOIT(50) DOIT(51) DOIT(52) DOIT(53) DOIT(54)
		DOIT(55) DOIT(56) DOIT(57) DOIT(58) DOIT(59) DOIT(60)
		DOIT(61) DOIT(62) DOIT(63) DOIT(64) DOIT(65) DOIT(66)
		DOIT(67) DOIT(68) DOIT(69) DOIT(70) DOIT(71) DOIT(72)
		DOIT(73) DOIT(74) DOIT(75) DOIT(76) DOIT(77) DOIT(78)
		DOIT(79) DOIT(80) DOIT(81) DOIT(82) DOIT(83) DOIT(84)
		DOIT(85) DOIT(86) DOIT(87) DOIT(88) DOIT(89) DOIT(90)
		DOIT(91) DOIT(92) DOIT(93) DOIT(94) DOIT(95) DOIT(96)
		DOIT(97) DOIT(98) DOIT(99) DOIT(100) DOIT(101) DOIT(102)
		DOIT(103) DOIT(104) DOIT(105) DOIT(106) DOIT(107)
		DOIT(108) DOIT(109) DOIT(110) DOIT(111) DOIT(112)
		DOIT(113) DOIT(114) DOIT(115) DOIT(116) DOIT(117)
		DOIT(118) DOIT(119) DOIT(120) DOIT(121) DOIT(122)
		DOIT(123) DOIT(124) DOIT(125) DOIT(126) p[127];
		p += 128;
	    }
	}
	use_int(sum);
}
#undef	DOIT

void
fcp(iter_t iterations, void *cookie)
{	
	tsd_t			*ts = (tsd_t *)cookie;
	register TYPE *lastone = ts->lastone;

	while (iterations-- > 0) {
	    register TYPE *p = ts->buf;
	    register TYPE *dst = ts->buf2;
	    while (p <= lastone) {
#define	DOIT(i)	dst[i]=p[i];
		DOIT(0) DOIT(1) DOIT(2) DOIT(3) DOIT(4) DOIT(5) DOIT(6)
		DOIT(7) DOIT(8) DOIT(9) DOIT(10) DOIT(11) DOIT(12)
		DOIT(13) DOIT(14) DOIT(15) DOIT(16) DOIT(17) DOIT(18)
		DOIT(19) DOIT(20) DOIT(21) DOIT(22) DOIT(23) DOIT(24)
		DOIT(25) DOIT(26) DOIT(27) DOIT(28) DOIT(29) DOIT(30)
		DOIT(31) DOIT(32) DOIT(33) DOIT(34) DOIT(35) DOIT(36)
		DOIT(37) DOIT(38) DOIT(39) DOIT(40) DOIT(41) DOIT(42)
		DOIT(43) DOIT(44) DOIT(45) DOIT(46) DOIT(47) DOIT(48)
		DOIT(49) DOIT(50) DOIT(51) DOIT(52) DOIT(53) DOIT(54)
		DOIT(55) DOIT(56) DOIT(57) DOIT(58) DOIT(59) DOIT(60)
		DOIT(61) DOIT(62) DOIT(63) DOIT(64) DOIT(65) DOIT(66)
		DOIT(67) DOIT(68) DOIT(69) DOIT(70) DOIT(71) DOIT(72)
		DOIT(73) DOIT(74) DOIT(75) DOIT(76) DOIT(77) DOIT(78)
		DOIT(79) DOIT(80) DOIT(81) DOIT(82) DOIT(83) DOIT(84)
		DOIT(85) DOIT(86) DOIT(87) DOIT(88) DOIT(89) DOIT(90)
		DOIT(91) DOIT(92) DOIT(93) DOIT(94) DOIT(95) DOIT(96)
		DOIT(97) DOIT(98) DOIT(99) DOIT(100) DOIT(101) DOIT(102)
		DOIT(103) DOIT(104) DOIT(105) DOIT(106) DOIT(107)
		DOIT(108) DOIT(109) DOIT(110) DOIT(111) DOIT(112)
		DOIT(113) DOIT(114) DOIT(115) DOIT(116) DOIT(117)
		DOIT(118) DOIT(119) DOIT(120) DOIT(121) DOIT(122)
		DOIT(123) DOIT(124) DOIT(125) DOIT(126) DOIT(127)
		p += 128;
		dst += 128;
	    }
	}
}

void
loop_bzero(iter_t iterations, void *cookie)
{	
	tsd_t			*ts = (tsd_t *)cookie;
	register TYPE *p = ts->buf;
	register size_t  N = ts->N;

	while (iterations-- > 0) {
		bzero(p, N);
	}
}

void
loop_bcopy(iter_t iterations, void *cookie)
{	
	tsd_t			*ts = (tsd_t *)cookie;
	register TYPE *p = ts->buf;
	register TYPE *dst = ts->buf2;
	register size_t  N = ts->N;

	while (iterations-- > 0) {
		bcopy(p,dst,N);
	}
}

#pragma mark libmicro routines

/*ARGSUSED*/
int
benchmark_initbatch(void *tsd)
{
	/*
	 * initialize your state variables here second
	 */
	tsd_t			*ts = (tsd_t *)tsd;
    ts->buf = (TYPE *)valloc(ts->nbytes);
	ts->buf2_orig = NULL;
	ts->lastone = (TYPE*)ts->buf - 1;
	ts->lastone = (TYPE*)((char *)ts->buf + ts->nbytes - 512);
	ts->N = ts->nbytes;

	if (!ts->buf) {
		perror("malloc");
		exit(1);
	}
	bzero((void*)ts->buf, ts->nbytes);

	if (ts->need_buf2 == 1) {
		ts->buf2_orig = ts->buf2 = (TYPE *)valloc(ts->nbytes + 2048);
		if (!ts->buf2) {
			perror("malloc");
			exit(1);
		}

		/* default is to have stuff unaligned wrt each other */
		/* XXX - this is not well tested or thought out */
		if (ts->aligned) {
			char	*tmp = (char *)ts->buf2;

			tmp += 2048 - 128;
			ts->buf2 = (TYPE *)tmp;
		}
	}
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
	(void) sprintf(lm_optstr, "p:w:n:s:x:");
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
	opt_what = (char *)malloc(30);

	(void) sprintf(lm_usage,
	    "	[-p <parallelism>]\n"
	    "	[-w <warmup>]\n"
	    "	[-n <repetitions>]\n"
	    "	-s <size>\n"
	    "		<size> must be larger than 512"
	    "	-x what\n"
	    " 		what: rd wr rdwr cp fwr frd fcp bzero bcopy\n"
	    "	  [conflict] -- unknown option?\n"
	);
	return (0);
}

int
benchmark_fini()
{
	free(opt_what);
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
	return (&result);
}

int
benchmark_finiworker(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	free(ts->buf);
	if (ts->buf2_orig) free(ts->buf2_orig);
	return (0);
}

/* return -1 to display usage (i.e. if can't parse arguments */
int
benchmark_optswitch(int opt, char *optarg)
{
	
	switch (opt) {
		case 'p':
			optp = sizetoint(optarg);
			if (optp <= 0) 
				return (-1);
			break;
		case 'w':
			optw = sizetoint(optarg);
			break;
		case 'n':
			optn = sizetoint(optarg);
			break;
		case 's':
			opt_size = sizetoint(optarg);
			break;
		case 'x':
			strcpy(opt_what, optarg);
			break;
		default:
			return(-1);
			break;
	}
//	(void) fprintf(stderr, "optp = %i optw = %i optn = %i opt_size = %i\n",
//						optp, optw, optn, opt_size);
//	(void) fprintf(stderr, "opt_what = %s\n", opt_what);						
	return (0);
}

int
benchmark_initworker(void *tsd)
{
	/*
	 *	initialize your state variables here first
	 */
	tsd_t			*ts = (tsd_t *)tsd;
	ts->parallel = optp;
	ts->warmup = optw;
	ts->repetitions = optn;
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
	tsd_t			*ts = (tsd_t *)tsd;
	size_t	nbytes;
	int	i;

	ts->overhead = 0;


	/* should have two, possibly three [indicates align] arguments left */
	ts->aligned = ts->need_buf2 = 0;

	nbytes = ts->nbytes = opt_size;
	if (ts->nbytes < 512) { /* this is the number of bytes in the loop */
		return(-1);
	}

	if (STREQ(opt_what, "cp") ||
	    STREQ(opt_what, "fcp") || STREQ(opt_what, "bcopy")) {
		ts->need_buf2 = 1;
	}
	
	for (i = 0 ; i < lm_optB ; i++)
	{
		if (STREQ(opt_what, "rd")) {
			rd( ts->repetitions, tsd ); 
		} else if (STREQ(opt_what, "wr")) {
			wr( ts->repetitions, tsd ); 
		} else if (STREQ(opt_what, "rdwr")) {
			rdwr( ts->repetitions, tsd ); 
		} else if (STREQ(opt_what, "cp")) {
			mcp( ts->repetitions, tsd ); 
		} else if (STREQ(opt_what, "frd")) {
			frd( ts->repetitions, tsd ); 
		} else if (STREQ(opt_what, "fwr")) {
			fwr( ts->repetitions, tsd ); 
		} else if (STREQ(opt_what, "fcp")) {
			fcp( ts->repetitions, tsd ); 
		} else if (STREQ(opt_what, "bzero")) {
			loop_bzero( ts->repetitions, tsd ); 
		} else if (STREQ(opt_what, "bcopy")) {
			loop_bcopy( ts->repetitions, tsd ); 
		} else {
			return(-1);
		}
	}
	res->re_count = i;

	return (0);
}
