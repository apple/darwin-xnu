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
 * test file locking
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include "libmicro.h"

static int 			file;

int
block(int index)
{
	struct flock		fl;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = index;
	fl.l_len = 1;
	return (fcntl(file, F_SETLKW, &fl) == -1);
}

int
unblock(int index)
{
	struct flock		fl;

	fl.l_type = F_UNLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = index;
	fl.l_len = 1;
	return (fcntl(file, F_SETLK, &fl) == -1);
}
int
benchmark_init()
{
	char			fname[80];
	int	errors = 0;

	(void) sprintf(fname, "/private/tmp/oneflock.%ld", getpid());

	file = open(fname, O_CREAT | O_TRUNC | O_RDWR, 0600);

	if (file == -1) {
		errors++;
	}
	if (unlink(fname)) {
		errors++;
	}

	lm_tsdsize = 0;

	return (errors);
}

/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	int			i;
	int			e = 0;

	for (i = 0; i < lm_optB; i ++) {
		e += block(0);
		e += unblock(0);
	}
	res->re_count = i;
	res->re_errors = e;

	return (0);
}
