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
#pragma ident   "@(#)posix_spawn_bin.c  1.0     08/21/08 Apple Inc."
#endif

/*
 * time program to recursively test posix_spawn time
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <spawn.h>

int
main(int argc, char *argv[])
{
	int left;
        int pid;

	if (argc == 1) {
		exit(1);
	}

	left = atoi(argv[1]);

	left--;

	if (left <= 0) {
		exit(0);
	} else {
		char buffer[80];
		(void) sprintf(buffer, "%d", left);
		argv[1] = buffer;
		if (posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL)) {
			exit(2);
		}
	}

	return (0);
}
