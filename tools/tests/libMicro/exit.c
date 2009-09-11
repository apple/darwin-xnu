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
 * benchmark exit
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "libmicro.h"

typedef struct {
	int			ts_once;
	int			*ts_pids;
} tsd_t;

static int			opte = 0;
static barrier_t		*b;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);
	(void) sprintf(lm_optstr, "e");

	(void) sprintf(lm_usage,
	    "       [-e] (uses _exit() rather than exit())"
	    "notes: measures exit()\n");

	return (0);
}

/*ARGSUSED*/
int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'e':
		opte = 1;
		break;
	default:
		return (-1);
	}
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
	int			i;
	int			errors = 0;

	if (ts->ts_once++ == 0) {
		ts->ts_pids = (int *)malloc(lm_optB * sizeof (pid_t));
		if (ts->ts_pids == NULL) {
			errors ++;
		}
	}

	/*
	 * create processes to exit
	 */

	for (i = 0; i < lm_optB; i++) {
		ts->ts_pids[i] = fork();
		switch (ts->ts_pids[i]) {
		case 0:
			(void) barrier_queue(b, NULL);
			if (opte)
				_exit(0);
			exit(0);
			break;
		case -1:
			errors ++;
			break;
		default:
			continue;
		}
	}

	return (errors);
}

/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	int			i;

	/*
	 * start them all exiting
	 */

	(void) barrier_queue(b, NULL);

	/*
	 * wait for them all to exit
	 */

	for (i = 0; i < lm_optB; i++) {
		switch (waitpid((pid_t)-1, NULL, 0)) {
		case 0:
			continue;
		case -1:
			res->re_errors++;
		}
	}

	res->re_count = i;

	return (0);
}
