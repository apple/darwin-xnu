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
 * mutex
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/mman.h>

#include "libmicro.h"

static int			optt = 0;
static int			optp = 0;
static int			opth = 0;
static int			opto = 0;

pthread_mutex_t			*lock;

typedef struct {
	int			ts_once;
	pthread_mutex_t		*ts_lock;
} tsd_t;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_usage,
	    "       [-t] (create dummy thread so we are multithreaded)\n"
	    "       [-p] (use inter-process mutex (not support everywhere))\n"
	    "       [-h usecs] (specify mutex hold time (default 0)\n"
	    "notes: measures uncontended pthread_mutex_[un,]lock\n");

	(void) sprintf(lm_optstr, "tph:o:");

	(void) sprintf(lm_header, "%8s", "holdtime");

	return (0);
}

/*ARGSUSED*/
int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'p':
		optp = 1;
		break;

	case 't':
		optt = 1;
		break;

	case 'h':
		opth = sizetoint(optarg);
		break;

	case 'o':
		opto = sizetoint(optarg);
		break;

	default:
		return (-1);
	}
	return (0);
}

void *
dummy(void *arg)
{
	(void) pause();
	return (arg);
}

int
benchmark_initrun()
{
	pthread_mutexattr_t	attr;
	int errors = 0;

	/*LINTED*/
	lock = (pthread_mutex_t *)mmap(NULL,
	    getpagesize(),
	    PROT_READ | PROT_WRITE,
	    optp?(MAP_ANON | MAP_SHARED):MAP_ANON|MAP_PRIVATE,
	    -1, 0L) + opto;

	if (lock == MAP_FAILED) {
		errors++;
	} else {
		(void) pthread_mutexattr_init(&attr);
		if (optp)
			(void) pthread_mutexattr_setpshared(&attr,
			    PTHREAD_PROCESS_SHARED);

		if (pthread_mutex_init(lock, &attr) != 0)
			errors++;
	}

	return (errors);
}

int
benchmark_initworker(void *tsd)
{
	int errors = 0;
	tsd_t			*ts = (tsd_t *)tsd;


	if (optt) {
		pthread_t		tid;



		if (pthread_create(&tid, NULL, dummy, NULL) != 0) {
			errors++;
		}
	}

	ts->ts_lock = lock;

	return (errors);
}

void
spinme(int usecs)
{
	long long s = getusecs();

	while (getusecs() - s < usecs)
		;
}

int
benchmark(void *tsd, result_t *res)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;

	for (i = 0; i < lm_optB; i ++) {

		(void) pthread_mutex_lock(ts->ts_lock);
		if (opth)
			spinme(opth);
		(void) pthread_mutex_unlock(ts->ts_lock);

	}

	res->re_count = lm_optB;

	return (0);
}

char *
benchmark_result()
{
	static char		result[256];

	(void) sprintf(result, "%8d", opth);

	return (result);
}
