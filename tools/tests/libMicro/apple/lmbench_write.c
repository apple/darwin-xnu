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


#ifdef	__sun
#pragma ident	"@(#)write.c	1.3	05/08/04 Apple Inc."
#endif

#ifdef linux
#define	_XOPEN_SOURCE 500
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include "../libmicro.h"

typedef struct {
	char			*ts_buf;
	int			ts_fd;
} tsd_t;

#define	DEFF			"/dev/null"
#define	DEFS			1024

static int			optc = 0;
static char			*optf = DEFF;
static long long		opts = DEFS;
static int			optd;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_optstr, "cdf:s:");

	(void) sprintf(lm_usage,
	    "       [-f file-to-write (default %s)]\n"
	    "       [-s buffer-size (default %d)]\n"
	    "       [-c ] (make sure buffer is in cache)\n"
#ifdef __sun
	    "       [-d ] use directio"
#endif
	    "notes: measures lmbench_write()\n",
	    DEFF, DEFS);

	(void) sprintf(lm_header, "%8s", "size");

	lm_defB = 1;

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {

	case 'd':
		optd++;
		break;
	case 'c':
		optc++;
		break;
	case 'f':
		optf = optarg;
		break;
	case 's':
		opts = sizetoll(optarg);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initbatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;

	if (ts->ts_buf == NULL) {
		ts->ts_buf = malloc(opts);
		ts->ts_fd = open(optf, O_WRONLY);

#ifdef __sun
		if (optd)
			(void) directio(ts->ts_fd, DIRECTIO_ON);
#endif
		/*
		 * bring buf into cache if specified.
		 */

		if (optc)
			for (i = 0; i < opts; i++)
				ts->ts_buf[i] = 0;
	}

	(void) lseek(ts->ts_fd, 0, SEEK_SET);

	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;

/*
 * The libmicro test uses a for loop as below:
 *   for (i = 0; i < lm_optB; i++) {
 *
 * we can probably get away with using lm_optB
 * in the while loop below
 *
 */
	i = 0;
	
	while (i++ < lm_optB) {
		if (write(ts->ts_fd, ts->ts_buf, opts) != opts) {
			res->re_errors++;
		}
	}
	res->re_count = i;

	return (0);
}

char *
benchmark_result()
{
	static char		result[256];

	(void) sprintf(result, "%8lld", opts);

	return (result);
}
