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
#include <fcntl.h>
#include <errno.h>
#include <sys/poll.h>

#include "libmicro.h"

#define	FIRSTPORT		12345

typedef struct {
	int			ts_once;
	int			*ts_lsns;
	int			*ts_accs;
	int			*ts_cons;
	struct sockaddr_in	*ts_adds;
} tsd_t;

static int			opta = 0;
static int			optc = 0;
static struct hostent		*host;

int
benchmark_init()
{
	lm_defB = 256;
	lm_tsdsize = sizeof (tsd_t);

	(void) sprintf(lm_optstr, "ac");

	(void) sprintf(lm_usage,
	    "       [-a] (measure accept() only)\n"
	    "       [-c] (measure connect() only)\n"
	    "notes: measures connect()/accept()\n");

	return (0);
}

/*ARGSUSED*/
int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'a':
		opta = 1;
		break;
	case 'c':
		optc = 1;
		break;
	default:
		return (-1);
	}

	if (opta && optc) {
		(void) printf("warning: -a overrides -c\n");
		optc = 0;
	}

	return (0);
}

int
benchmark_initrun()
{
	(void) setfdlimit(3 * lm_optB * lm_optT + 10);

	return (0);
}

int
benchmark_initbatch_once(void *tsd)
{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i, j;

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
	ts->ts_adds =
	    (struct sockaddr_in *)malloc(lm_optB *
	    sizeof (struct sockaddr_in));
	if (ts->ts_accs == NULL) {
		errors ++;
	}

	j = FIRSTPORT;
	for (i = 0; i < lm_optB; i++) {
		ts->ts_lsns[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (ts->ts_lsns[i] == -1) {
			perror("socket");
			errors ++;
		}

		/*
		 * make accept socket non-blocking so in case of errors
		 * we don't hang
		 */

		if (fcntl(ts->ts_lsns[i], F_SETFL, O_NDELAY) == -1) {
			perror("fcntl");
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
	int			errors = 0;
	int			result;

	if (ts->ts_once++ == 0) {
		if (errors += benchmark_initbatch_once(tsd) == -1) {
			return (-1);
		}
	}


	for (i = 0; i < lm_optB; i++) {
		ts->ts_cons[i] = socket(AF_INET, SOCK_STREAM, 0);
		if (ts->ts_cons[i] == -1) {
			perror("init:socket");
			errors ++;
		}

		if (fcntl(ts->ts_cons[i], F_SETFL, O_NDELAY) == -1) {
			perror("init:fcntl");
			errors ++;
		}

		if (opta) {
			result = connect(ts->ts_cons[i],
			    (struct sockaddr *)&ts->ts_adds[i],
			    sizeof (struct sockaddr_in));
			if ((result == -1) && (errno != EINPROGRESS)) {
				perror("init:connect");
				errors ++;
			}
		}
	}

	return (errors);
}

int
benchmark(void *tsd, result_t *res)



{
	tsd_t			*ts = (tsd_t *)tsd;
	int			i;
	int			result;
	struct sockaddr_in	addr;
	socklen_t		size;

	for (i = 0; i < lm_optB; i++) {
		if (!opta) {
		again:
			result = connect(ts->ts_cons[i],
			    (struct sockaddr *)&ts->ts_adds[i],
			    sizeof (struct sockaddr_in));
			if (result != 0 && errno != EISCONN) {
				if (errno == EINPROGRESS) {
					struct pollfd pollfd;
					if (optc)
						continue;
					pollfd.fd = ts->ts_cons[i];
					pollfd.events = POLLOUT;
					if (poll(&pollfd, 1, -1) == 1)
						goto again;
				}

				res->re_errors ++;
				perror("benchmark:connect");
				continue;
			}
		}

		if (!optc) {
			size = sizeof (struct sockaddr);
			for (;;) {
				struct pollfd pollfd;
				result = accept(ts->ts_lsns[i],
				    (struct sockaddr *)&addr, &size);
				if (result > 0 || (result == -1 &&
				    errno != EAGAIN))
					break;
				pollfd.fd = ts->ts_lsns[i];
				pollfd.events = POLLIN;
				if (poll(&pollfd, 1, -1) != 1)
					break;
			}

			ts->ts_accs[i] = result;
			if (result == -1) {
				res->re_errors ++;
				perror("benchmark:accept");
				continue;
			}
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

		if (!optc) {
			(void) close(ts->ts_accs[i]);
		}
		(void) close(ts->ts_cons[i]);
	}

	return (0);
}
