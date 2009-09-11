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

#include <sys/uio.h>
#include <limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#ifndef IOV_MAX
#define	IOV_MAX			UIO_MAXIOV
#endif

#include "libmicro.h"

typedef struct {
	int			ts_once;
	struct iovec		*ts_iov;
	int 			ts_fd;
} tsd_t;

#define	DEFF			"/dev/null"
#define	DEFS			1024
#define	DEFV			10

static char			*optf = DEFF;
static int			opts = DEFS;
static int			optv = DEFV;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_optstr, "f:s:v:");

	(void) sprintf(lm_usage,
	    "       [-f file-to-write (default %s)]\n"
	    "       [-s buffer-size (default %d)]\n"
	    "       [-v vector-size (default %d)]\n"
	    "notes: measures writev()\n"
	    "       IOV_MAX is %d\n"
	    "       SSIZE_MAX is %ld\n",
	    DEFF, DEFS, DEFV, IOV_MAX, SSIZE_MAX);

	(void) sprintf(lm_header, "%8s %4s", "size", "vec");

	lm_defB = 1;

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'f':
		optf = optarg;
		break;
	case 's':
		opts = sizetoint(optarg);
		break;
	case 'v':
		optv = atoi(optarg);
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initbatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;
	int			errors = 0;

	if (ts->ts_once++ == 0) {
		ts->ts_fd = open(optf, O_WRONLY);
		if (ts->ts_fd == -1) {
			errors++;
		}
		ts->ts_iov = (struct iovec *)malloc(
		    optv * sizeof (struct iovec));
		for (i = 0; i < optv; i++) {
			ts->ts_iov[i].iov_base = malloc(opts);
			ts->ts_iov[i].iov_len = opts;
		}
	}

	(void) lseek(ts->ts_fd, 0, SEEK_SET);

	return (errors);
}

int
benchmark(void *tsd, result_t *res)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;

	for (i = 0; i < lm_optB; i++) {
		if (writev(ts->ts_fd, ts->ts_iov, optv) != opts * optv) {
			res->re_errors++;
		}
	}
	res->re_count = i;

	return (0);
}

char *
benchmark_result()
{
	static char		result[256];

	(void) sprintf(result, "%8d %4d", opts, optv);

	return (result);
}
