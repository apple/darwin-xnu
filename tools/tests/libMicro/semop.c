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
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include "libmicro.h"


typedef struct {
	int	ts_semid;
} tsd_t;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_usage, "notes: measures semop()\n");

	return (0);
}

int
benchmark_initbatch(void *tsd)
{

	tsd_t			*ts = (tsd_t *)tsd;

	if ((ts->ts_semid = semget(IPC_PRIVATE, 2, 0600)) == -1) {
		return (-1);
	}

	return (0);
}

int
benchmark_finibatch(void *tsd)
{
	tsd_t 			*ts = (tsd_t *)tsd;

	(void) semctl(ts->ts_semid, 0, IPC_RMID);

	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	int			i;
	tsd_t			*ts = (tsd_t *)tsd;
	struct sembuf		s[1];

	for (i = 0; i < lm_optB; i++) {
		s[0].sem_num = 0;
		s[0].sem_op  = 1;
		s[0].sem_flg = 0;
		if (semop(ts->ts_semid, s, 1) == -1) {
			res->re_errors++;
		}
		s[0].sem_num = 0;
		s[0].sem_op  = -1;
		s[0].sem_flg = 0;
		if (semop(ts->ts_semid, s, 1) == -1) {
			res->re_errors++;
		}
	}

	res->re_count += lm_optB;

	return (0);
}
