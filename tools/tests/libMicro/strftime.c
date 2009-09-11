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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "libmicro.h"

#define	DEFF		"%c"
#define	MAXSIZE			80

static char *optf = DEFF;

typedef struct {
	int		ts_once;
	struct tm 	ts_tm1;
	struct tm 	ts_tm2;
} tsd_t;

int
benchmark_init()
{

	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_optstr, "f:");

	(void) sprintf(lm_usage,
	    "       [-f format (default = \"%s\")]\n"
	    "notes: measures strftime()\n",
	    DEFF);

	(void) sprintf(lm_header, "%8s", "format");

	return (0);
}
int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {

	case 'f':
		optf = optarg;
		break;
	default:
		return (-1);
	}
	return (0);
}


char *
benchmark_result()
{
	static char	result[256];

	(void) sprintf(result, "%8s", optf);

	return (result);
}


int
benchmark_initbatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;

	static time_t		clock1 = 0L;
	static time_t		clock2 = 1L;

	(void) localtime_r(&clock1, &ts->ts_tm1);
	(void) localtime_r(&clock2, &ts->ts_tm2);

	return (0);
}


int
benchmark(void *tsd, result_t *res)
{
	int			i;
	tsd_t			*ts = (tsd_t *)tsd;
	char			s[MAXSIZE];

	for (i = 0; i < lm_optB; i += 10) {
		(void) strftime(s, MAXSIZE, optf, &ts->ts_tm1);
		(void) strftime(s, MAXSIZE, optf, &ts->ts_tm2);
		(void) strftime(s, MAXSIZE, optf, &ts->ts_tm1);
		(void) strftime(s, MAXSIZE, optf, &ts->ts_tm2);
		(void) strftime(s, MAXSIZE, optf, &ts->ts_tm1);
		(void) strftime(s, MAXSIZE, optf, &ts->ts_tm2);
		(void) strftime(s, MAXSIZE, optf, &ts->ts_tm1);
		(void) strftime(s, MAXSIZE, optf, &ts->ts_tm2);
		(void) strftime(s, MAXSIZE, optf, &ts->ts_tm1);
		(void) strftime(s, MAXSIZE, optf, &ts->ts_tm2);
	}
	res->re_count = i;

	return (0);
}
