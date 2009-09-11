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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * malloc benchmark (crude)
 */


#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#include "libmicro.h"

static int		optg = 100;
static int		opts[32] = {32};
static int		optscnt = 0;

typedef struct {
	void 			**ts_glob;
} tsd_t;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_optstr, "s:g:");

	(void) sprintf(lm_usage,
	    "       [-g number of mallocs before free (default %d)]\n"
	    "       [-s size to malloc (default %d)."
	    "  Up to 32 sizes accepted\n"
	    "notes: measures malloc()/free()",
	    optg, opts[0]);

	(void) sprintf(lm_header, "%6s %6s", "glob", "sizes");

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	int tmp;
	switch (opt) {
	case 'g':
		optg = sizetoint(optarg);
		break;
	case 's':
		opts[optscnt] = sizetoint(optarg);
		tmp = ((++optscnt) & (0x1F));
		optscnt = tmp;
		break;
	default:
		return (-1);
	}

	return (0);
}

int
benchmark_initworker(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;

	if (optscnt == 0)
		optscnt = 1;

	ts->ts_glob = malloc(sizeof (void *)* optg);
	if (ts->ts_glob == NULL) {
		return (1);
	}
	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i, j, k;

	for (i = 0; i < lm_optB; i++) {
		for (k = j = 0; j < optg; j++) {
			if ((ts->ts_glob[j] = malloc(opts[k++])) == NULL)
				res->re_errors++;
			if (k >= optscnt)
				k = 0;
		}
		for (j = 0; j < optg; j++) {
			free(ts->ts_glob[j]);
		}
	}

	res->re_count = i * j;

	return (0);
}

char *
benchmark_result()
{
	static char  result[256];
	int i;

	(void) sprintf(result, "%6d ", optg);

	for (i = 0; i < optscnt; i++)
		(void) sprintf(result + strlen(result), "%d ", opts[i]);
	return (result);
}
