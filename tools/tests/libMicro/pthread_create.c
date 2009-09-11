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
#include <pthread.h>
#include <errno.h>

#include "libmicro.h"

typedef struct {
	pthread_t 		*ts_threads;
	pthread_attr_t		*ts_attr;
	pthread_mutex_t		ts_lock;
} tsd_t;

static int				opts = 0;

int
benchmark_init()
{
	lm_defN = "pthread";

	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_usage,
	    "       [-s stacksize] (specify stacksize)\n"
	    "notes: measures pthread_create\n");

	(void) sprintf(lm_optstr, "s:");

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 's':
		opts = sizetoll(optarg);
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
	int errors = 0;

	ts->ts_threads = calloc(lm_optB, sizeof (pthread_t));
	(void) pthread_mutex_init(&ts->ts_lock, NULL);

	if (opts) {
		ts->ts_attr = malloc(sizeof (pthread_attr_t));
		(void) pthread_attr_init(ts->ts_attr);
		if ((errors = pthread_attr_setstacksize(ts->ts_attr, opts))
		    != 0) {
			errno = errors;
			perror("pthread_attr_setstacksize");
		}
	} else
		ts->ts_attr = NULL;

	return (errors?1:0);
}

int
benchmark_initbatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;

	(void) pthread_mutex_lock(&ts->ts_lock);

	return (0);
}


void *
func(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;

	(void) pthread_mutex_lock(&ts->ts_lock);
	(void) pthread_mutex_unlock(&ts->ts_lock);

	return (tsd);
}

int
benchmark(void *tsd, result_t *res)
{
	int			i;
	tsd_t			*ts = (tsd_t *)tsd;
	int error;

	for (i = 0; i < lm_optB; i++) {
		if ((error = pthread_create(ts->ts_threads + i,
		    ts->ts_attr, func, tsd)) != 0) {
			errno = error;
			perror("pthread_create");
			ts->ts_threads[i] = 0;
			res->re_errors++;
			return (0);
		}
	}
	res->re_count = lm_optB;

	return (0);
}

int
benchmark_finibatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int i;
	int errors = 0;

	(void) pthread_mutex_unlock(&ts->ts_lock);

	for (i = 0; i < lm_optB; i++)
		if (ts->ts_threads[i] == 0 ||
		    pthread_join(ts->ts_threads[i], NULL) < 0) {
			errors++;
		}
	return (errors);
}
