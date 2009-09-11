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
 * benchmark fork
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "libmicro.h"

static barrier_t		*b;

typedef struct {
	int			ts_once;
	int			*ts_pids;
} tsd_t;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);
	(void) sprintf(lm_usage, "notes: measures fork()\n");

	return (0);
}

int
benchmark_initrun()
{
	b = barrier_create(lm_optP * lm_optT * (lm_optB + 1), 0);

	return (0);
}

int
benchmark_finirun()
{
	(void) barrier_destroy(b);

	return (0);
}

int
benchmark_initbatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			errors = 0;

	if (ts->ts_once++ == 0) {
		ts->ts_pids = (int *)malloc(lm_optB * sizeof (pid_t));
		if (ts->ts_pids == NULL) {
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
		ts->ts_pids[i] = fork();
		switch (ts->ts_pids[i]) {
		case 0:
			(void) barrier_queue(b, NULL);
			exit(0);
			break;
		case -1:
			res->re_errors++;
			break;
		default:
			continue;
		}
	}
	res->re_count = lm_optB;

	(void) barrier_queue(b, NULL);

	return (0);
}

int
benchmark_finibatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;

	for (i = 0; i < lm_optB; i++) {
		if (ts->ts_pids[i] > 0) {
			(void) waitpid(ts->ts_pids[i], NULL, 0);
		}
	}

	return (0);
}
