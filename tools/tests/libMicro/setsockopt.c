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


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "libmicro.h"

typedef struct {
	int	ts_fd;
} tsd_t;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_usage, "setsockopt(TCP_NODELAY)\n");

	return (0);
}

int
benchmark_initbatch(void *tsd)
{

	tsd_t			*ts = (tsd_t *)tsd;

	if ((ts->ts_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return (1);
	return (0);
}

int
benchmark_finibatch(void *tsd)
{
	tsd_t 			*ts = (tsd_t *)tsd;

	(void) close(ts->ts_fd);
	return (0);
}

int
benchmark(void *tsd, result_t *res)
{
	int			i;
	tsd_t			*ts = (tsd_t *)tsd;
	int			opt;

	res->re_errors = 0;

	for (i = 0; i < lm_optB; i++) {
		opt = 1 & i;
		if (setsockopt(ts->ts_fd, IPPROTO_TCP, TCP_NODELAY,
		    &opt, sizeof (int)) == -1) {
			res->re_errors ++;
		}
	}
	res->re_count += lm_optB;

	return (0);
}
