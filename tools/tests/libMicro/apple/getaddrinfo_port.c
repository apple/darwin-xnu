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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>

// add additional headers needed here.

#include "../libmicro.h"

#if DEBUG
# define debug(fmt, args...)    (void) fprintf(stderr, fmt "\n" , ##args)
#else
# define debug(fmt, args...)
#endif


// This exercises "ssh" port
//
// Correct use case
//
//    getaddrinfo_port -E  -L -S -W -B 200 -C 100
//
//      libMicro default benchmark run options are "-E -L -S -W -C 200"
//
// -B is batch size: loop iteration per each benchmark run. Needs to match # of
//                   real lookups. This is total number of lookups to issue.
// -C is min sample number: how many benchmark needs to run to get proper sample
//                          1 is mimumum, but you get at least 3 benchmark run
//                          samples. Do not set to zero. Default is 200 for most
//                          runs in libMicro.
//

extern int gL1CacheEnabled;

/*
 *    Your state variables should live in the tsd_t struct below
 */
typedef struct {
} tsd_t;


int
benchmark_init()
{
    debug("benchmark_init");

    (void) sprintf(lm_optstr,  "l:");
    lm_tsdsize = sizeof (tsd_t);
    lm_defB = 100;

    return (0);
}


/*
 * This is where you parse your lower-case arguments.
 */
int
benchmark_optswitch(int opt, char *optarg)
{
    debug("benchmark_optswitch");

    switch (opt) {
        case 'l':
            gL1CacheEnabled = atoi(optarg);
            break;
    }

    return 0;
}


// Initialize all structures that will be used in benchmark()
//
int
benchmark_initrun()
{
    debug("\nbenchmark_initrun");

    return (0);
}


int
benchmark(void *tsd, result_t *res)
{
    int         i, err;
    struct addrinfo *addi;

    res->re_errors = 0;

    debug("in to benchmark - optB = %i", lm_optB);
    for (i = 0; i < lm_optB; i++) {

        err = getaddrinfo(NULL, "ssh", NULL, &addi);

        if (err) {
            debug("error: %s", gai_strerror(err));
            res->re_errors++;
        }

        freeaddrinfo (addi);
    }
    res->re_count = i;

    return (0);
}

// We need to release all the structures we allocated in benchmark_initrun()
int
benchmark_finirun(void *tsd)
{
    // tsd_t    *ts = (tsd_t *)tsd;
    debug("benchmark_finirun ");

    return (0);
}

char *
benchmark_result()
{
    static char    result = '\0';
    debug("benchmark_result");
    return (&result);
}

