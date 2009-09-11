/*
 * Copyright (c) 2008 Apple Inc.  All Rights Reserved.
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


#ifdef  __sun
#pragma ident   "@(#)posix_spawn.c  1.0     08/21/08 Apple Inc."
#endif

/*
 * posix_spawn benchmark
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <spawn.h>

#include "../libmicro.h"

static char exec_path[1024];
static char *argv[3];

int
benchmark_init()
{
	lm_defB = 128;
	lm_tsdsize = 0;

	(void) sprintf(lm_usage,
	    "notes: measures posix_spawn time of simple process()\n");

	return (0);
}

/*ARGSUSED*/
int
benchmark_initbatch(void *tsd)
{
	char			buffer[80];

	(void) strcpy(exec_path, lm_procpath);
	(void) strcat(exec_path, "/posix_spawn_bin");

	(void) sprintf(buffer, "%d", lm_optB);
	argv[0] = exec_path;
	argv[1] = strdup(buffer);
	argv[2] = NULL;

	return (0);
}

/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	int c;
	int pid;
	int status;

	if (( c = posix_spawn(&pid, exec_path, NULL, NULL, argv, NULL) != 0))
	{
		res->re_errors++;
	}

	if (waitpid(pid, &status, 0) < 0)
	{
		res->re_errors++;
	}

	if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
	{
		res->re_errors++;
	}
	
	res->re_count = lm_optB;

	return (0);
}
