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
 * memset
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "libmicro.h"

#define	DEFS			8192

static long long		opts = DEFS;
static int			opta = 0;
static int			optu = 0;

static char 			*optas = "4k";

typedef struct {
	char 			*ts_buff;
	int			ts_size;
	int			ts_offset;
} tsd_t;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_optstr, "a:us:");

	(void) sprintf(lm_usage,
	    "       [-s buffer-size (default %d)]\n"
	    "       [-a alignment (force buffer alignment)]\n"
	    "       [-u (try to always use uncached memory)]"
	    "notes: measures memset()\n",
	    DEFS);

	(void) sprintf(lm_header, "%8s%16s", "size", "alignment");

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'u':
		optu = 1;
		break;
	case 's':
		opts = sizetoll(optarg);
		break;
	case 'a':
		opta = sizetoll(optarg);
		if (opta > 4096)
			opta = 0;
		else
			optas = optarg;
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initworker(void *tsd)
{
	tsd_t 			*ts = (tsd_t *)tsd;
	int			errors = 0;
	int i;

	if (optu) {
		ts->ts_size 	= 1024 * 1024 * 64;
		ts->ts_offset 	= opta;
	} else {
		ts->ts_size 	= opta + opts;
		ts->ts_offset 	= opta;
	}

	if ((ts->ts_buff = (char *)valloc(ts->ts_size)) == NULL)
		errors++;

	for (i = 0; i < ts->ts_size; i++)
		ts->ts_buff[i] = 0;
	return (errors);
}

/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	int			i;
	tsd_t			*ts = (tsd_t *)tsd;


	if (optu) {
		char *buf = ts->ts_buff + ts->ts_offset;
		char *end = ts->ts_buff + ts->ts_size;
		int offset = ts->ts_offset;
		
		unsigned long tmp;

		for (i = 0; i < lm_optB; i ++) {
			(void) memset(buf, 0, opts);
			tmp = (((unsigned long)buf + opts + 4095) & ~4095) + offset;
			buf = (char *) tmp;
			if (buf + opts > end)
				buf = ts->ts_buff + offset;
		}
	} else {
		char *buf = ts->ts_buff + ts->ts_offset;

		for (i = 0; i < lm_optB; i += 10) {
			(void) memset(buf, 0, opts);
			(void) memset(buf, 0, opts);
			(void) memset(buf, 0, opts);
			(void) memset(buf, 0, opts);
			(void) memset(buf, 0, opts);
			(void) memset(buf, 0, opts);
			(void) memset(buf, 0, opts);
			(void) memset(buf, 0, opts);
			(void) memset(buf, 0, opts);
			(void) memset(buf, 0, opts);
		}
	}
	res->re_count = i;

	return (0);
}

char *
benchmark_result()
{
	static char		result[256];

	(void) sprintf(result, "%8lld%12s", opts, optas);

	return (result);
}
