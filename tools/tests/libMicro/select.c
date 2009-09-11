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

#define	MAX(x, y)		((x) > (y) ? (x) : (y))
#define	MIN(x, y)		((x) > (y) ? (y) : (x))

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/socket.h>

#include "libmicro.h"

#define	DEFN			256

static int			optn = DEFN;
static int			optr = 0;
static int			optw = 0;
static int			optx = 0;
static int			*fds;
static fd_set			iset;
static fd_set			oset;
static int			maxfd = 0;
static int			target = 0;

int
benchmark_init()
{
	(void) sprintf(lm_optstr, "n:r:w:x");

	lm_tsdsize = 0;

	(void) sprintf(lm_usage,
	    "       [-n fds-per-thread (default %d)]\n"
	    "       [-r readable-fds (default 0)]\n"
	    "       [-w writeable-fds (default 0)]\n"
	    "       [-x] (start -r option with highest fd first; "
	    "default is lowest first)\n"
	    "notes: measures select()\n",
	    DEFN);

	(void) sprintf(lm_header, "%8s %5s", "maxfd", "flags");

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'n':
		optn = atoi(optarg);
		break;
	case 'r':
		optr = atoi(optarg);
		break;
	case 'w':
		optw = atoi(optarg);
		break;
	case 'x':
		optx = 1;
		break;
	default:
		return (-1);
	}
	return (0);
}

int
benchmark_initrun()
{
	int			i;
	int			j;
	int			pair[2];

	if (optn % 2 != 0) {
		(void) printf("ERROR: -n value must be even\n");
		optn = optr = optw = 0;
		return (-1);
	}

	if (optn < 0 || optr < 0 || optw < 0) {
		(void) printf("ERROR: -n, -r and -w values must be > 0\n");
		optn = optr = optw = 0;
		return (-1);
	}

	if (optr > optn || optw > optn) {
		(void) printf("ERROR: -r and -w values must be <= maxfd\n");
		optn = optr = optw = 0;
		return (-1);
	}

	fds = (int *)malloc(optn * sizeof (int));
	if (fds == NULL) {
		(void) printf("ERROR: malloc() failed\n");
		optn = optr = optw = 0;
		return (-1);
	}

	(void) setfdlimit(optn + 10);

	target = optr + optw;

	FD_ZERO(&iset);
	FD_ZERO(&oset);

	for (i = 0; i < optn; i += 2) {
		if (socketpair(PF_UNIX, SOCK_STREAM, 0, pair) == -1) {
			(void) printf("ERROR: socketpair() failed\n");
			return (-1);
		}

		fds[i] = MIN(pair[0], pair[1]);
		fds[i+1] = MAX(pair[0], pair[1]);
		maxfd = fds[i+1] + 1;

		if (maxfd > FD_SETSIZE) {
			(void) printf("WARNING: FD_SETSIZE is too small!\n");
			return (-1);
		}

		FD_SET(fds[i], &iset);
		FD_SET(fds[i+1], &iset);
	}

	for (i = 0; i < optw; i++) {
		FD_SET(fds[i], &oset);
	}
	if (optx) {
		for (i = 0, j = optn - 1; i < optr; i++, j--) {
			(void) write(fds[j+1 - (2*(j%2))], "", 1);
		}
	} else {
		for (i = 0; i < optr; i++) {
			(void) write(fds[i+1 - (2*(i%2))], "", 1);
		}
	}

	return (0);
}

/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	int			i;
	fd_set			set1;
	fd_set			set2;
	fd_set		*my_iset = &set1;
	fd_set		*my_oset = NULL;
	struct timeval		tv = {0, 0};

	if (optw) {
		my_oset = &set2;
	}

	for (i = 0; i < lm_optB; i++) {
		(void) memcpy(&set1, &iset, sizeof (fd_set));
		(void) memcpy(&set2, &oset, sizeof (fd_set));

		if (select(maxfd, my_iset, my_oset, NULL, &tv) != target) {
			res->re_errors++;
		}
	}
	res->re_count = i;

	return (0);
}

char *
benchmark_result()
{
	static char		result[256];
	char			flags[4];

	flags[0] = optr ? 'r' : '-';
	flags[1] = optw ? 'w' : '-';
	flags[2] = optx ? 'x' : '-';
	flags[3] = 0;

	(void) sprintf(result, "%8d %5s", optn, flags);

	return (result);
}
