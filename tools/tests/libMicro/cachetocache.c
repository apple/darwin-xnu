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
 * routine to benchmark cache-to-cache transfer times... uses
 * solaris features to find and bind to cpus in the current
 * processor set, so not likely to work elsewhere.
 */


#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/processor.h>
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>
#include <sys/pset.h>

#include "libmicro.h"

static long			opts = 1024*512;

typedef struct {
	long			**ts_data;
	long			ts_result;
	pthread_mutex_t		ts_lock;
} tsd_t;

static unsigned int ncpu = 1024;

static tsd_t *thread_data[1024];
static processorid_t cpus[1024];

int traverse_ptrchain(long **, int, int);

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_optstr, "s:");

	(void) sprintf(lm_usage,
	    "       [-s size] size of access area in bytes"
	    " (default %ld)\n"
	    "notes: measures cache to cache transfer times on Solaris\n",
	    opts);

	(void) sprintf(lm_header, "%8s", "size");

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 's':
		opts = sizetoint(optarg);
		break;
	default:
		return (-1);
	}

	return (0);
}

int
benchmark_initrun()
{
	if (pset_info(PS_MYID, NULL, &ncpu, cpus) < 0) {
		perror("pset_info");
		return (1);
	}

	return (0);
}

int
benchmark_initworker(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int i, j;
	processorid_t cpu;

	ts->ts_data = malloc(opts);

	if (ts->ts_data == NULL) {
		return (1);
	}

	(void) pthread_mutex_init(&ts->ts_lock, NULL);


	if (processor_bind(P_LWPID, P_MYID,
	    cpu = cpus[(pthread_self() - 1) % ncpu],
	    NULL) < 0) {
		perror("processor_bind:");
		return (1);
	}

	(void) printf("# thread %d using processor %d\n", pthread_self(), cpu);

	/*
	 * use lmbench style backwards stride
	 */

	for (i = 0; i < opts / sizeof (long); i++) {
		j = i - 128;
		if (j < 0)
			j = j + opts / sizeof (long);
		ts->ts_data[i] = (long *)&(ts->ts_data[j]);
	}

	thread_data[pthread_self() - 1] = ts;

	return (0);
}

/*
 * here we go in order for each thread, causing inherent serialization
 * this is normally not a good idea, but in this case we're trying to
 * measure cache-to-cache transfer times, and if we run threads in
 * parallel we're likely to see saturation effects rather than cache-to-cache,
 * esp. on wimpy memory platforms like P4.
 */


/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	tsd_t			*ts;
	int			i, j;
	int 			count = opts / 128 / sizeof (long);

	for (j = 0; j < lm_optB; j++)
		for (i = 0; i < lm_optT; i++) {
			ts = thread_data[i];
			(void) pthread_mutex_lock(&ts->ts_lock);
			ts->ts_result += traverse_ptrchain(
			    (long **)ts->ts_data, count, 0);
			(void) pthread_mutex_unlock(&ts->ts_lock);
		}

	res->re_count = lm_optB * lm_optT * count;

	return (0);
}

int
traverse_ptrchain(long **ptr, int count, int value)
{
	int i;

	for (i = 0; i < count; i += 10) {
		*ptr = *ptr + value;
		ptr = (long **)*ptr;
		*ptr = *ptr + value;
		ptr = (long **)*ptr;
		*ptr = *ptr + value;
		ptr = (long **)*ptr;
		*ptr = *ptr + value;
		ptr = (long **)*ptr;
		*ptr = *ptr + value;
		ptr = (long **)*ptr;
		*ptr = *ptr + value;
		ptr = (long **)*ptr;
		*ptr = *ptr + value;
		ptr = (long **)*ptr;
		*ptr = *ptr + value;
		ptr = (long **)*ptr;
		*ptr = *ptr + value;
		ptr = (long **)*ptr;
		*ptr = *ptr + value;
		ptr = (long **)*ptr;
		*ptr = *ptr + value;
	}
	return ((int)*ptr); /* bogus return */
}


char *
benchmark_result()
{
	static char  result[256];

	(void) sprintf(result, "%8ld ", opts);


	return (result);
}
