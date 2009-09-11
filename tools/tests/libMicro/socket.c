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

#define	DEFF		"PF_UNIX"

static char			*optf = DEFF;
static int			family;

int
lookup_family(char *name)
{
	if (strcmp("PF_UNIX", name) == 0) {
		return (PF_UNIX);
	} else if (strcmp("PF_INET", name) == 0) {
		return (PF_INET);
	} else if (strcmp("PF_INET6", name) == 0) {
		return (PF_INET6);
	}

	return (-1);
}

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	lm_defB = 256;

	(void) sprintf(lm_optstr, "f:n");

	(void) sprintf(lm_usage,
	    "       [-f socket-family (default %s)]\n"
	    "notes: measures socket\n",
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
	default:
		return (-1);
	}

	return (0);
}


int
benchmark_initrun()
{
	(void) setfdlimit(lm_optB * lm_optT + 10);
	family = lookup_family(optf);

	return (0);
}

int
benchmark_finirun()
{
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

	for (i = 0; i < lm_optB; i++) {
		ts->ts_fds[i] = socket(family, SOCK_STREAM, 0);
		if (ts->ts_fds[i] == -1) {
			res->re_errors++;
		}
	}
	res->re_count += lm_optB;

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
