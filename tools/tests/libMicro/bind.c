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
 * benchmark for bind... keep in mind tcp hash chain effects
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
#include <fcntl.h>
#include <errno.h>

#include "libmicro.h"

#define	FIRSTPORT		12345

typedef struct {
	int 			*ts_lsns;
	struct sockaddr_in 	*ts_adds;
} tsd_t;

static int optz = -0;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	lm_defB = 256;
	(void) sprintf(lm_optstr, "z");

	(void) sprintf(lm_usage,
	    "		[-z bind to port 0 rather than seq. number\n"
	    "notes: measures bind() on TCP");

	return (0);
}

int
benchmark_initrun()
{
	(void) setfdlimit(lm_optB * lm_optT + 10);

	return (0);
}

/*ARGSUSED*/
int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'z':
		optz = 1;
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initbatch(void *tsd)
{
	tsd_t 			*ts = (tsd_t *)tsd;
	int			i, j;
	int			opt = 1;
	struct hostent		*host;
	int			errors = 0;

	ts->ts_lsns = (int *)malloc(lm_optB * sizeof (int));
	if (ts->ts_lsns == NULL)
		errors ++;

	ts->ts_adds = (struct sockaddr_in *)malloc(lm_optB *
	    sizeof (struct sockaddr_in));
	if (ts->ts_adds == NULL)
		errors ++;

	j = FIRSTPORT;
	for (i = 0; i < lm_optB; i++) {
		if ((ts->ts_lsns[i] = socket(PF_INET, SOCK_STREAM, 0)) == -1)
			errors ++;

		if (setsockopt(ts->ts_lsns[i], SOL_SOCKET, SO_REUSEADDR,
		    &opt, sizeof (int)) == -1)
			errors ++;

		if ((host = gethostbyname("localhost")) == NULL)
			errors ++;

		(void) memset(&ts->ts_adds[i], 0,
		    sizeof (struct sockaddr_in));
		ts->ts_adds[i].sin_family = AF_INET;
		ts->ts_adds[i].sin_port = (optz ? 0 : htons(j++));
		(void) memcpy(&ts->ts_adds[i].sin_addr.s_addr,
		    host->h_addr_list[0], sizeof (struct in_addr));
	}
	return (errors);
}

int
benchmark(void *tsd, result_t *res)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;

	for (i = 0; i < lm_optB; i++) {
		if ((bind(ts->ts_lsns[i],
		    (struct sockaddr *)&ts->ts_adds[i],
		    sizeof (struct sockaddr_in)) != 0) &&
		    (errno != EADDRINUSE))
			res->re_errors ++;
	}
	res->re_count = i;

	return (0);
}

int
benchmark_finibatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;

	for (i = 0; i < lm_optB; i++)
		(void) close(ts->ts_lsns[i]);
	return (0);
}
