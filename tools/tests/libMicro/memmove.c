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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * memmove
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "libmicro.h"

#define	DEFS			8192
#define	DEFR			1

static long long		opts = DEFS;
static int			optf;
static int			optt;
static int			opta;

typedef struct {
	char			*ts_src;
	char 			*ts_dest;
	int			ts_srcsize;
	int			ts_destsize;
} tsd_t;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_optstr, "a:s:ft");

	(void) sprintf(lm_usage,
	    "       [-s buffer-size (default %d)]\n"
	    "       [-a relative alignment (default page aligned)]\n"
	    "       [-f (rotate \"from\" buffer to keep it out of cache)]\n"
	    "       [-t (rotate \"to\" buffer to keep it out of cache)]\n"
	    "notes: measures memmove()\n",
	    DEFS);

	(void) sprintf(lm_header, "%8s", "size");

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'f':
		optf++;
		break;
	case 't':
		optt++;
		break;
	case 's':
		opts = sizetoll(optarg);
		break;
	case 'a':
		opta = sizetoint(optarg);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initworker(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;

	if (optf)
		ts->ts_srcsize = 64 * 1024 * 1024;
	else
		ts->ts_srcsize = opts + opta;

	if (optt)
		ts->ts_destsize = 64 * 1024 * 1024;
	else
		ts->ts_destsize = (int)opts;


	ts->ts_src = opta + (char *)valloc(ts->ts_srcsize);
	ts->ts_dest = valloc(ts->ts_destsize);

	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;
	char			*src = ts->ts_src;
	char			*dest = ts->ts_dest;

	int bump = (int)opts;

	if (bump < 1024)
		bump = 1024; /* avoid prefetched area */
	for (i = 0; i < lm_optB; i++) {
		(void) memmove(dest, src, opts);
		if (optf) {
			src += bump;
			if (src + opts > ts->ts_src + ts->ts_srcsize)
				src = ts->ts_src;
		}
		if (optt) {
			dest += bump;
			if (dest + opts > ts->ts_dest + ts->ts_destsize)
				dest = ts->ts_dest;
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
