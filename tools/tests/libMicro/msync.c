/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the "License").  You may not use this file except
 * in compliance with the License.
 *
 * You can obtain a copy of the license at
 * src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * HEADER in each file and include the License file at
 * usr/src/OPENSOLARIS.LICENSE.  If applicable,
 * add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your
 * own identifying information: Portions Copyright [yyyy]
 * [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <strings.h>

#include "libmicro.h"

typedef struct {
	char 			*ts_map;
	int			ts_foo; /* defeat optimizers */
} tsd_t;

#define	DEFF			"/dev/zero"
#define	DEFL			8192

static char			*optf = DEFF;
static long long		optl = DEFL;
static int			optr = 0;
static int			opts = 0;
static int			optw = 0;
static int			opta = MS_SYNC;
static int			opti = 0;
static int			anon = 0;
static int			pagesize;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_optstr, "af:il:rsw");

	(void) sprintf(lm_usage,
	    "       [-f file-to-map (default %s)]\n"
	    "       [-l mapping-length (default %d)]\n"
	    "       [-r] (read a byte from each page between msyncs)\n"
	    "       [-w] (write a byte to each page between msyncs)\n"
	    "       [-s] (use MAP_SHARED instead of MAP_PRIVATE)\n"
	    "       [-a (specify MS_ASYNC rather than default MS_SYNC)\n"
	    "       [-i (specify MS_INVALIDATE)\n"
	    "notes: measures msync()\n",
	    DEFF, DEFL);

	(void) sprintf(lm_header, "%8s %6s", "length", "flags");

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'a':
		opta = MS_ASYNC;
		break;

	case 'f':
		optf = optarg;
		break;

	case 'i':
		opti = MS_INVALIDATE;
		break;

	case 'l':
		optl = sizetoll(optarg);
		break;
	case 'r':
		optr = 1;
		break;
	case 's':
		opts = 1;
		break;
	case 'w':
		optw = 1;
		break;
	default:
		return (-1);
	}

	pagesize = getpagesize();

	return (0);
}

int
benchmark_initworker(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;

	int fd;

	if ((fd = open(optf, O_RDWR)) < 0) {
		perror("open:");
		return (1);
	}

	(void) ftruncate(fd, optl);

	if ((ts->ts_map = (char *)mmap(NULL, optl,
	    PROT_READ | PROT_WRITE, opts ? MAP_SHARED : MAP_PRIVATE,
	    fd, 0L)) == MAP_FAILED) {
		perror("mmap:");
		(void) close(fd);
		return (1);
	}

	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i, j;

	for (i = 0; i < lm_optB; i++) {

		if (msync(ts->ts_map, optl, opta | opti) < 0) {
			perror("msync:");
			res->re_errors++;
			break;
		}

		if (optr) {
			for (j = 0; j < optl; j += pagesize) {
				ts->ts_foo += ts->ts_map[j];
			}
		}

		if (optw) {
			for (j = 0; j < optl; j += pagesize) {
				ts->ts_map[j] = 1;
			}
		}
	}
	res->re_count = i;

	return (0);
}

char *
benchmark_result()
{
	static char		result[256];
	char			flags[6];

	flags[0] = anon ? 'a' : '-';
	flags[1] = optr ? 'r' : '-';
	flags[2] = optw ? 'w' : '-';
	flags[3] = opts ? 's' : '-';
	flags[4] = opti ? 'i' : '-';
	flags[5] = 0;

	(void) sprintf(result, "%8lld %6s", optl, flags);

	return (result);
}
