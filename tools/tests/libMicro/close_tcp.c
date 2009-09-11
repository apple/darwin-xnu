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
 * benchmark to measure time to close a local tcp connection
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
	int			*ts_lsns;
	int			*ts_accs;
	int			*ts_cons;
	struct sockaddr_in	*ts_adds;
} tsd_t;

int
benchmark_init()
{
	lm_tsdsize = sizeof (tsd_t);

	lm_defB = 256;

	(void) sprintf(lm_usage,
	    "notes: measures close() on local TCP connections");

	return (0);
}

int
benchmark_initrun()
{
	(void) setfdlimit(3 * lm_optB * lm_optT + 10);

	return (0);
}

int
benchmark_initworker(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i, j;
	int			opt = 1;
	struct hostent	*host;
	int			errors = 0;

	ts->ts_lsns = (int *)malloc(lm_optB * sizeof (int));
	if (ts->ts_lsns == NULL) {
		errors ++;
	}
	ts->ts_accs = (int *)malloc(lm_optB * sizeof (int));
	if (ts->ts_accs == NULL) {
		errors ++;
	}
	ts->ts_cons = (int *)malloc(lm_optB * sizeof (int));
	if (ts->ts_cons == NULL) {
		errors ++;
	}
	ts->ts_adds = (struct sockaddr_in *)malloc(lm_optB *
	    sizeof (struct sockaddr_in));
	if (ts->ts_adds == NULL) {
		errors ++;
	}

	j = FIRSTPORT;
	for (i = 0; i < lm_optB; i++) {
		ts->ts_lsns[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (ts->ts_lsns[i] == -1) {
			perror("socket");
			errors ++;
		}

		if (setsockopt(ts->ts_lsns[i], SOL_SOCKET, SO_REUSEADDR,
		    &opt, sizeof (int)) == -1) {
			perror("setsockopt");
			errors ++;
		}

		if ((host = gethostbyname("localhost")) == NULL) {
			errors ++;
		}

		for (;;) {
			(void) memset(&ts->ts_adds[i], 0,
			    sizeof (struct sockaddr_in));
			ts->ts_adds[i].sin_family = AF_INET;
			ts->ts_adds[i].sin_port = htons(j++);
			(void) memcpy(&ts->ts_adds[i].sin_addr.s_addr,
			    host->h_addr_list[0], sizeof (struct in_addr));

			if (bind(ts->ts_lsns[i],
			    (struct sockaddr *)&ts->ts_adds[i],
			    sizeof (struct sockaddr_in)) == 0) {
				break;
			}

			if (errno != EADDRINUSE) {
				perror("bind");
				errors ++;
			}
		}

		if (listen(ts->ts_lsns[i], 5) == -1) {
			perror("listen");
			errors ++;
		}

	}
	return (errors);
}

int
benchmark_initbatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;
	int			result;
	struct sockaddr_in	addr;
	socklen_t		size;
	int			errors = 0;

	for (i = 0; i < lm_optB; i++) {
		ts->ts_cons[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (ts->ts_cons[i] == -1) {
			perror("socket");
			errors ++;
			continue;
		}

		if (fcntl(ts->ts_cons[i], F_SETFL, O_NDELAY) == -1) {
			perror("fcnt");
			errors ++;
			continue;
		}

		result = connect(ts->ts_cons[i],
		    (struct sockaddr *)&ts->ts_adds[i],
		    sizeof (struct sockaddr_in));

		if ((result == -1) && (errno != EINPROGRESS)) {
			perror("connect");
			errors ++;
			continue;
		}

		size = sizeof (struct sockaddr);
		result = accept(ts->ts_lsns[i], (struct sockaddr *)&addr,
		    &size);
		if (result == -1) {
			perror("accept");
			errors ++;
			continue;
		}
		ts->ts_accs[i] = result;
	}

	return (errors);
}

int
benchmark(void *tsd, result_t *res)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;

	for (i = 0; i < lm_optB; i++) {
		if (close(ts->ts_accs[i]) == -1) {
			res->re_errors ++;
		}
	}
	res->re_count = i;

	return (0);
}

int
benchmark_finibatch(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;

	for (i = 0; i < lm_optB; i++) {
		(void) close(ts->ts_cons[i]);
	}

	return (0);
}

int
benchmark_finiworker(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;

	for (i = 0; i < lm_optB; i++) {
		(void) close(ts->ts_lsns[i]);
	}
	return (0);
}
