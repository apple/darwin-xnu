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
 * exec benchmark
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "libmicro.h"

static char exec_path[1024];
static char *argv[3];

int
benchmark_init()
{
	lm_defB = 128;
	lm_tsdsize = 0;

	(void) sprintf(lm_usage,
	    "notes: measures execv time of simple process()\n");

	return (0);
}

/*ARGSUSED*/
int
benchmark_initbatch(void *tsd)
{
	char			buffer[80];

	(void) strcpy(exec_path, lm_procpath);
	(void) strcat(exec_path, "/exec_bin");

	(void) sprintf(buffer, "%d", lm_optB);
	argv[0] = exec_path;
	argv[1] = strdup(buffer);
	argv[2] = NULL;

	return (0);
}

/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	int c;
	int status;

	switch (c = fork()) {
	case -1:
		res->re_errors++;
		break;
	default:
		if (waitpid(c, &status, 0) < 0)
			res->re_errors++;

		if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
			res->re_errors++;
		break;
	case 0:
		if (execv(exec_path, argv) < 0)
			res->re_errors++;
	}

	res->re_count = lm_optB;

	return (0);
}
