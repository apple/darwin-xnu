/*
 * Copyright (c) 2006 Apple Inc.  All Rights Reserved.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

 
#ifdef	__sun
#pragma ident	"@(#)lmbench_openclose.c	1.4	06/21/06 Apple Inc."
#endif


#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../libmicro.h"

#define	DEFF			"/dev/null"
static char			*optf = DEFF;

int
benchmark_init()
{

	(void) sprintf(lm_optstr, "f:");

	lm_tsdsize = 0;

	(void) sprintf(lm_usage,
	    "       [-f file-to-stat (default %s)]\n"
	    "notes: measures stat()\n",
	    DEFF);

	return (0);
}

int
benchmark_optswitch(int opt, char *optarg)
{
	switch (opt) {
	case 'f':
		optf = optarg;
		break;
	default:
		return (-1);
	}
	return (0);
}

/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	int			i;
	int			fd;

	res->re_errors = 0;
	
/*
 * The libmicro test uses a for loop as below:
 *   for (i = 0; i < lm_optB; i++) {
 *
 * we can probably get away with using lm_optB
 * in the while loop below
 *
 */
 	i = 0;

	while (i++ < lm_optB) {
		fd = open(optf, 0);
		if (fd == -1) {
			res->re_errors++;
		}
		close(fd);
	}

	res->re_count += lm_optB;

	return (0);
}
