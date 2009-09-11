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

#ifdef linux
#define	_XOPEN_SOURCE 500
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include "libmicro.h"

typedef struct {
	char			*ts_buf;
	int			ts_fd;
} tsd_t;

#define	DEFF			"/dev/null"
#define	DEFS			1024

static int			optc = 0;
static char			*optf = DEFF;
static long long		opts = DEFS;
static int			optd;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_optstr, "cdf:s:");

	(void) sprintf(lm_usage,
	    "       [-f file-to-write (default %s)]\n"
	    "       [-s buffer-size (default %d)]\n"
	    "       [-c ] (make sure buffer is in cache)\n"
#ifdef __sun
	    "       [-d ] use directio"
#endif
	    "notes: measures write()\n",
	    DEFF, DEFS);

	(void) sprintf(lm_header, "%8s", "size");

	lm_defB = 1;

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {

	case 'd':
		optd++;
		break;
	case 'c':
		optc++;
		break;
	case 'f':
		optf = optarg;
		break;
	case 's':
		opts = sizetoll(optarg);
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

	if (ts->ts_buf == NULL) {
		ts->ts_buf = malloc(opts);
		ts->ts_fd = open(optf, O_WRONLY);

#ifdef __sun
		if (optd)
			(void) directio(ts->ts_fd, DIRECTIO_ON);
#endif
		/*
		 * bring buf into cache if specified.
		 */

		if (optc)
			for (i = 0; i < opts; i++)
				ts->ts_buf[i] = 0;
	}

	(void) lseek(ts->ts_fd, 0, SEEK_SET);

	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;

	for (i = 0; i < lm_optB; i++) {
		if (write(ts->ts_fd, ts->ts_buf, opts) != opts) {
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

	(void) sprintf(result, "%8lld", opts);

	return (result);
}
