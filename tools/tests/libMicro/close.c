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
 * benchmark for close
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include "libmicro.h"

#define	DEFF			"/dev/null"
static char			*optf = DEFF;
static int 			optb = 0;

typedef struct {
	int			*ts_fds;
} tsd_t;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	lm_defB = 256;

	(void) sprintf(lm_optstr, "f:b");

	(void) sprintf(lm_usage,
	    "       [-f file-to-close (default %s)]\n"
	    "       [-b] (try to close an unopened fd)\n"
	    "notes: measures close()",
	    DEFF);

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'f':
		optf = optarg;
		break;
	case 'b':
		optb = 1;
		break;
	default:
		return (-1);
	}

	return (0);
}

int
benchmark_initrun()
{
	(void) setfdlimit(lm_optB * lm_optT + 10);

	return (0);
}

int
benchmark_initworker(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;

	ts->ts_fds = (int *)malloc(lm_optB * sizeof (int));
	if (ts->ts_fds == NULL) {
		return (1);
	}
	return (0);
}

/*
 * don't need a finiworker; we're exiting anyway
 */

int
benchmark_initbatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;
	int			errors = 0;

	for (i = 0; i < lm_optB; i++) {
		ts->ts_fds[i] = ((optb == 0) ?
		    open(optf, O_RDONLY) : i + 1024);
		if (ts->ts_fds[i] == -1) {
			errors++;
		}
	}

	return (errors);
}

int
benchmark(void *tsd, result_t *res)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;

	for (i = 0; i < lm_optB; i++) {
		if (close(ts->ts_fds[i]) == -1 && !optb) {
			res->re_errors++;
		}
	}
	res->re_count = i;

	return (0);
}
