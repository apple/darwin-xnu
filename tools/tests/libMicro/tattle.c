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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <tattle.h>
#include "libmicro.h"
#include <math.h>


#ifdef USE_RDTSC
#ifdef __GNUC__
#define	ENABLE_RDTSC 1
#endif
#endif

/*
 * dummy so we can link w/ libmicro
 */

/*ARGSUSED*/
int
benchmark(void *tsd, result_t *res)
{
	return (0);
}

static void
cleanup(char *s)
{
	char *o = s;
	char *e;

	while (*s == ' ')
		s++;

	if (o != s)
		(void) strcpy(o, s);

	e = o;

	while (*e != 0)
		e++;

	e--;

	while (*e == ' ' && e > o)
		*e-- = 0;

}


int
main(int argc, char *argv[])
{
	int c;

	if (strlen(compiler_version) > 30)
		compiler_version[30] = 0;

	cleanup(compiler_version);
	cleanup(extra_compiler_flags);

	while ((c = getopt(argc, argv, "vcfrsVTR")) != -1) {
		switch (c) {
		case 'V':
			(void) printf("%s\n", LIBMICRO_VERSION);
			break;
		case 'v':
			(void) printf("%s\n", compiler_version);
			break;
		case 'c':
			(void) printf("%s\n", CC);
			break;
		case 'f':
			if (strlen(extra_compiler_flags) == 0)
				(void) printf("[none]\n");
			else
				(void) printf("%s\n", extra_compiler_flags);
			break;

		case 's':
			(void) printf("%d\n", sizeof (long));
			break;

		case 'r':

			(void) printf("%lld nsecs\n", get_nsecs_resolution());
			break;

		case 'R':
#ifdef ENABLE_RDTSC
			{
				struct timeval 	s;
				struct timeval	f;
				long long 	start_nsecs;
				long long 	end_nsecs;
				long 		elapsed_usecs;

				gettimeofday(&s, NULL);
				start_nsecs = rdtsc();
				for (;;) {
					gettimeofday(&f, NULL);
					elapsed_usecs = (f.tv_sec - s.tv_sec) *
					    1000000 + (f.tv_usec - s.tv_usec);
					if (elapsed_usecs > 1000000)
						break;
				}
				end_nsecs = rdtsc();
				(void) printf("LIBMICRO_HZ=%lld\n",
				    (long long)elapsed_usecs *
				    (end_nsecs - start_nsecs) / 1000000LL);
			}
#else
			(void) printf("\n");
#endif
			break;
		}
	}

	exit(0);
	return (0);
}
