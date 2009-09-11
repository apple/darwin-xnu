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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <strings.h>

#include "libmicro.h"

typedef volatile char		vchar_t;

typedef struct {
	int			ts_batch;
	int			ts_res;
} tsd_t;

#define	DEFF			"/dev/zero"
#define	DEFL			8192

static char			*optf = DEFF;
static long long		optl = DEFL;
static int			optr = 0;
static int			optw = 0;
static int			opts = 0;
static int			optt = 0;
static int			fd = -1;
static int			anon = 0;
static int			foo = 0;
static vchar_t			*seg;
static int			pagesize;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_optstr, "f:l:rstw");

	(void) sprintf(lm_usage,
	    "       [-f file-to-map (default %s)]\n"
	    "       [-l mapping-length (default %d)]\n"
	    "       [-r] (read a byte from each page)\n"
	    "       [-w] (write a byte on each page)\n"
	    "       [-s] (use MAP_SHARED)\n"
	    "       [-t] (touch each page after restoring permissions)\n"
	    "notes: measures mprotect()\n",
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
	case 't':
		optt = 1;
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
	int			flags;
	int			i;

	if (!anon)
		fd = open(optf, O_RDWR);

	flags = opts ? MAP_SHARED : MAP_PRIVATE;
	flags |= anon ? MAP_ANON : 0;

	seg = (vchar_t *)mmap(NULL, lm_optB * optl, PROT_READ | PROT_WRITE,
	    flags, anon ? -1 : fd, 0L);

	if (seg == MAP_FAILED) {
		return (-1);
	}

	if (optr) {
		for (i = 0; i < lm_optB * optl; i += 4096) {
			foo += seg[i];
		}
	}

	if (optw) {
		for (i = 0; i < lm_optB * optl; i += 4096) {
			seg[i] = 1;
		}
	}

	pagesize = getpagesize();

	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;
	int			us;
	int			prot = PROT_NONE;
	int			j, k;

#if !defined(__APPLE__)
    us = (getpindex() * lm_optT) + gettindex();
#else
    us = gettsdindex(tsd);
#endif /* __APPLE__ */
	
	for (i = 0; i < lm_optB; i++) {
		switch ((us + ts->ts_batch + i) % 2) {
		case 0:
			prot = PROT_NONE;
			if (optt) {
				for (j = k = 0; j < optl; j += pagesize)
					k += seg[i * optl + j];
				ts->ts_res += k;
			}
			break;
		default:
			prot = PROT_READ | PROT_WRITE;
			break;
		}

		if (mprotect((void *)&seg[i * optl], optl, prot) == -1) {
			res->re_errors++;
		}
	}
	res->re_count += lm_optB;
	ts->ts_batch++;

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
	flags[4] = optt ? 't' : '-';
	flags[5] = 0;

	(void) sprintf(result, "%8lld %5s", optl, flags);

	return (result);
}
