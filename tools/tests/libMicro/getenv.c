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
 * test getenv
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#include "libmicro.h"

#define	DEFS			100

static int			opts = DEFS;

int
benchmark_init()
{
	(void) sprintf(lm_optstr, "s:");

	lm_tsdsize = 0;

	(void) sprintf(lm_usage,
	    "       [-s search-size (default = %d)]\n"
	    "notes: measures time to search env for missing string\n",
	    DEFS);

	lm_nsecs_per_op = 200;

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 's':
		opts = atoi(optarg);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initrun()
{
	extern char **		environ;
	int			i, j;

	/* count environment strings */

	for (i = 0; environ[i++]; )
		;

	/*
	 * pad to desired count
	 */

	if (opts < i)
		opts = i;

	for (j = i; j < opts; j++) {
		char buf[80];
		(void) sprintf(buf, "VAR_%d=%d", j, j);
		(void) putenv(strdup(buf));
	}

	return (0);
}

/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	int			i;
	char 			*search = "RUMPLSTILTSKIN";

	for (i = 0; i < lm_optB; i += 10) {
		(void) getenv(search);
		(void) getenv(search);
		(void) getenv(search);
		(void) getenv(search);
		(void) getenv(search);
		(void) getenv(search);
		(void) getenv(search);
		(void) getenv(search);
		(void) getenv(search);
		(void) getenv(search);
	}
	res->re_count = i;

	return (0);
}
