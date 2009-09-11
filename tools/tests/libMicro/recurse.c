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
#include <string.h>

#include "libmicro.h"

#define	DEFD		100

static int			optd = DEFD;

int recurse2(int x, int y, char *s);

/*ARGSUSED*/
int
recurse1(int x, int y, char *s)
{
	char			str[32];

	if (x < y) {
		return (recurse2(x + 1, y, str));
	}

	return (x);
}

int
benchmark_init()
{
	lm_tsdsize = 0;

	(void) sprintf(lm_optstr, "d:");

	(void) sprintf(lm_usage,
	    "       [-d depth-limit (default = %d)]\n"
	    "notes: measures recursion performance\n",
	    DEFD);

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'd':
		optd = atoi(optarg);
		break;
	default:
		return (-1);
	}
	return (0);
}

/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	int			i;

	for (i = 0; i < lm_optB; i++) {
		(void) recurse1(0, optd, NULL);
	}
	res->re_count = i;

	return (0);
}
