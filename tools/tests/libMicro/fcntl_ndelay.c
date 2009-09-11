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
 * measures  O_NDELAY on socket
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
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

static int			fd = -1;

int
benchmark_init()
{
	(void) sprintf(lm_usage,
	    "notes: measures F_GETFL/F_SETFL O_NDELAY on socket\n");

	lm_tsdsize = 0;

	return (0);
}

int
benchmark_initrun()
{
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1) {
		perror("socket");
		exit(1);
	}

	return (0);
}

/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	int			i;
	int			flags;

	for (i = 0; i < lm_optB; i += 4) {
		if (fcntl(fd, F_GETFL, &flags) < 0)
			res->re_errors++;
		flags |= O_NDELAY;

		if (fcntl(fd, F_SETFL, &flags) < 0)
			res->re_errors++;

		if (fcntl(fd, F_GETFL, &flags) < 0)
			res->re_errors++;
		flags &= ~O_NDELAY;

		if (fcntl(fd, F_SETFL, &flags) < 0)
			res->re_errors++;
	}
	res->re_count = i;

	return (0);
}
