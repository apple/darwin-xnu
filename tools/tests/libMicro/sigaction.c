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
#include <signal.h>

#include "libmicro.h"

#ifdef __sun
static void
nop()
{
}
#else
static void
nop(int sig)
{
}
#endif


typedef struct {
	struct sigaction ts_act;
} tsd_t;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_usage, "notes: measures sigaction()\n");

	return (0);
}

int
benchmark_initbatch(void *tsd)
{

	tsd_t 			*ts = (tsd_t *)tsd;
	ts->ts_act.sa_handler = nop;
	ts->ts_act.sa_flags = 0;
	(void) sigemptyset(&ts->ts_act.sa_mask);

	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	int			i;
	tsd_t			*ts = (tsd_t *)tsd;
	struct sigaction	oact;

	res->re_errors = 0;

	for (i = 0; i < lm_optB; i++) {
		if (sigaction(SIGUSR1, &ts->ts_act, &oact))
			res->re_errors++;
	}

	res->re_count += lm_optB;

	return (0);
}
