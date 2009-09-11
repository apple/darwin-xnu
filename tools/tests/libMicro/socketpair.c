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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "libmicro.h"

typedef struct {
	int			ts_once;
	int			*ts_fds;
} tsd_t;

#define	DEFN		256


int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	lm_defB = 256;

	(void) sprintf(lm_usage,
	    "notes: measures socketpair\n");

	return (0);
}


int
benchmark_initrun()
{
	(void) setfdlimit(lm_optB * lm_optT + 10);
	return (0);
}

int
benchmark_initbatch(void *tsd)
{
	int			i;
	tsd_t			*ts = (tsd_t *)tsd;

	if (ts->ts_once++ == 0) {
		ts->ts_fds = (int *)malloc(lm_optB * sizeof (int));
		if (ts->ts_fds == NULL) {
			return (1);
		}
		for (i = 0; i < lm_optB; i++) {
			ts->ts_fds[i] = -1;
		}
	}

	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	int			i;
	tsd_t			*ts = (tsd_t *)tsd;

	res->re_count = 0;
	res->re_errors = 0;

	for (i = 0; i < lm_optB; i += 2) {
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, &ts->ts_fds[i])
		    == -1) {
			res->re_errors++;
		}
	}
	res->re_count = i / 2;

	return (0);
}

int
benchmark_finibatch(void *tsd)
{
	int			i;
	tsd_t			*ts = (tsd_t *)tsd;

	for (i = 0; i < lm_optB; i++) {
		(void) close(ts->ts_fds[i]);
	}

	return (0);
}
