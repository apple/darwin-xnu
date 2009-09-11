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
 * change directory benchmark
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "libmicro.h"

#define	DEFAULTDIR		"/"
#define	MAXPATHLEN		1024

static int			optg = 0;

static int			dircount;
static char **			dirlist;

int
benchmark_init()
{
	(void) sprintf(lm_optstr, "g");
	lm_tsdsize = 0;

	(void) sprintf(lm_usage,
	    "       [-g] (do getcwd() also)\n"
	    "       directory ... (default = %s)\n"
	    "notes: measures chdir() and (optionally) getcwd()",
	    DEFAULTDIR);

	(void) sprintf(lm_header, "%5s %5s", "dirs", "gets");

	return (0);
}

/*ARGSUSED*/
int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'g':
		optg = 1;
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initrun()
{
	extern int		optind;
	int			i;

	dircount = lm_argc - optind;
	if (dircount <= 0) {
		dirlist = (char **)malloc(sizeof (char *));
		dirlist[0] = DEFAULTDIR;
		dircount = 1;
	} else {
		dirlist = (char **)malloc(dircount * sizeof (char *));
		for (i = 0; i < dircount; i++) {
			dirlist[i] = lm_argv[optind++];
		}
	}

	return (0);
}

/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	int			i, j;
	char 			buf[MAXPATHLEN];

	j = 0;
	for (i = 0; i < lm_optB; i++) {
		if (chdir(dirlist[j]) == -1)
			res->re_errors++;
		j++;
		j %= dircount;

		if (optg && (getcwd(buf, MAXPATHLEN) == NULL)) {
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

	(void) sprintf(result, "%5d %5s", dircount, optg ? "y" : "n");

	return (result);
}
