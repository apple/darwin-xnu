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

int
benchmark_init()
{
	lm_tsdsize = 0;

	(void) sprintf(lm_usage, "notes: measures signal()\n");

	return (0);
}

int
benchmark_initrun()
{
	struct sigaction act;

	act.sa_handler = nop;
	act.sa_flags = 0;

	(void) sigemptyset(&act.sa_mask);
	(void) sigaction(SIGUSR1, &act, NULL);

	return (0);
}

/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	int			i;
	int			pid;

	pid = getpid();

	for (i = 0; i < lm_optB; i += 10) {
		(void) kill(pid, SIGUSR1);
		(void) kill(pid, SIGUSR1);
		(void) kill(pid, SIGUSR1);
		(void) kill(pid, SIGUSR1);
		(void) kill(pid, SIGUSR1);
		(void) kill(pid, SIGUSR1);
		(void) kill(pid, SIGUSR1);
		(void) kill(pid, SIGUSR1);
		(void) kill(pid, SIGUSR1);
		(void) kill(pid, SIGUSR1);
	}
	res->re_count += i;

	return (0);
}
