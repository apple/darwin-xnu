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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <strings.h>

#include "libmicro.h"

typedef volatile char		vchar_t;

typedef struct {
	int			ts_once;
	vchar_t **		ts_map;
	vchar_t			ts_foo;
} tsd_t;

#define	DEFF			"/dev/zero"
#define	DEFL			8192

static char			*optf = DEFF;
static long long		optl = DEFL;
static int			optr = 0;
static int			optw = 0;
static int			opts = 0;
static int			fd = -1;
static int			anon = 0;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_optstr, "f:l:rsw");

	(void) sprintf(lm_usage,
	    "       [-f file-to-map (default %s)]\n"
	    "       [-l mapping-length (default %d)]\n"
	    "       [-r] (read a byte from each page)\n"
	    "       [-w] (write a byte on each page)\n"
	    "       [-s] (use MAP_SHARED)\n"
	    "notes: measures munmap()\n",
	    DEFF, DEFL);

	(void) sprintf(lm_header, "%8s %5s", "size", "flags");

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'f':
		optf = optarg;
		anon = strcmp(optf, "MAP_ANON") == 0;
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
	return (0);
}

int
benchmark_initrun()
{
	if (!anon)
		fd = open(optf, O_RDWR);

	return (0);
}

int
benchmark_initbatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i, j;
	int			errors = 0;

	if (ts->ts_once++ == 0) {
		ts->ts_map = (vchar_t **)malloc(lm_optB * sizeof (void *));
		if (ts->ts_map == NULL) {
			errors++;
		}
	}

	for (i = 0; i < lm_optB; i++) {
		if (anon) {
			ts->ts_map[i] = (vchar_t *)mmap(NULL, optl,
			    PROT_READ | PROT_WRITE,
			    MAP_ANON | (opts ? MAP_SHARED : MAP_PRIVATE),
			    -1, 0L);
		} else {
			ts->ts_map[i] = (vchar_t *)mmap(NULL, optl,
			    PROT_READ | PROT_WRITE,
			    opts ? MAP_SHARED : MAP_PRIVATE,
			    fd, 0L);
		}

		if (ts->ts_map[i] == MAP_FAILED) {
			errors++;
			continue;
		}
		if (optr) {
			for (j = 0; j < optl; j += 4096) {
				ts->ts_foo += ts->ts_map[i][j];
			}
		}
		if (optw) {
			for (j = 0; j < optl; j += 4096) {
				ts->ts_map[i][j] = 1;
			}
		}
	}

	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;

	for (i = 0; i < lm_optB; i++) {
		if (munmap((void *)ts->ts_map[i], optl) == -1) {
			res->re_errors++;
		}
	}
	res->re_count += lm_optB;

	return (0);
}

char *
benchmark_result()
{
	static char		result[256];
	char			flags[5];

	flags[0] = anon ? 'a' : '-';
	flags[1] = optr ? 'r' : '-';
	flags[2] = optw ? 'w' : '-';
	flags[3] = opts ? 's' : '-';
	flags[4] = 0;

	(void) sprintf(result, "%8lld %5s", optl, flags);

	return (result);
}
