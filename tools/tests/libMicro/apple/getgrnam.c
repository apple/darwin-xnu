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

// add additional headers needed here.

#include "../libmicro.h"
#include <grp.h>
#include <uuid/uuid.h>

#if DEBUG
# define debug(fmt, args...)    (void) fprintf(stderr, fmt "\n" , ##args)
#else
# define debug(fmt, args...)
#endif


// Correct use case
//
//    getgrnam -E  -L -S -W -B 200 -C 10 -r 10
//
//      libMicro default benchmark run options are "-E -L -S -W -C 200"
//
// -B is batch size: loop iteration per each benchmark run. Needs to match # of
//                   real lookups. This is total number of lookups to issue.
// -C is min sample number: how many benchmark needs to run to get proper sample
//                          1 is mimumum, but you get at least 3 benchmark run
//                          samples. Do not set to zero. Default is 200 for most
//                          runs in libMicro.
// -r is the number of total groups (from "local_test_group1" to "local_test_group#")

extern int gL1CacheEnabled;

/*
 *    Your state variables should live in the tsd_t struct below
 */
typedef struct {
} tsd_t;

// temporary buffer size
#define BUFSIZE 200

// the number of record lookup to issue is covered by standard option optB
static int  optRecords =    10;  // the number of total records

// This will use local users (local_test_*)
static char *default_gprefix = "ds_test_group";

#define GROUPNAME_LEN	30
static char *grpname_list;

int
benchmark_init()
{
    debug("benchmark_init");
    (void) sprintf(lm_optstr,  "l:r:g:");

    lm_tsdsize = sizeof (tsd_t);
    lm_defB = 100;

    (void) sprintf(lm_usage,
                "\n     ------- getgrnam specific options (default: *)\n"
                "       [-r total number of group records (10*)]\n"
                "       [-g group prefix(ds_test_group)]\n"
                "\n" );
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
    case 'r':    // total number of records. default is 100
        optRecords = atoi(optarg);
        debug("optRecords = %d\n", optRecords);
        break;

    case 'l':
        gL1CacheEnabled = atoi(optarg);
        break;

    case 'g':	// base name for the groups to use
	default_gprefix = strdup(optarg);
	debug("default_gprefix = %s\n", default_gprefix);
	break;

    default:
        return -1;
    }

    return 0;
}


// Initialize all structures that will be used in benchmark()
// moved template init from benchmark_initworker -> benchmark_initrun
//  since username_list is static across threads and processes
//
int
benchmark_initrun()
{
    int i;

    debug("\nbenchmark_initrun");

    // create an array of usernames to use in benchmark before their use
    // realtime generation in benchmark effects performance measurements
    grpname_list = malloc( optRecords * GROUPNAME_LEN );
    if (!grpname_list) {
        debug ("malloc error");
        exit (1);
    }

    for (i = 0; i < optRecords; i++) {
        sprintf(&grpname_list[i*GROUPNAME_LEN], "%s%d", default_gprefix, i+1);
        debug("creating group name %s", &grpname_list[i*GROUPNAME_LEN]);
    }

    return (0);
}


int
benchmark(void *tsd, result_t *res)
{
    int          i, err;
    struct group *grp = NULL;

    res->re_errors = 0;

    debug("in to benchmark - optB = %i", lm_optB);
    srandom(getpid());

    for (i = 0; i < lm_optB; i++) {
        int index = (random() % optRecords) * GROUPNAME_LEN;

        if (lm_optT > 1) {
            struct group gd;
            struct group *grp_ptr = &gd;
            struct group *tmp_ptr;
            char gbuf[BUFSIZE];

            err = getgrnam_r( &grpname_list[index], grp_ptr, gbuf, BUFSIZE, &tmp_ptr);
            // non-NULL err means failure and NULL result ptr means no matching
            // entry
            if (err) {
                debug("error: %s -> %s",  &grpname_list[index], strerror(err));
                res->re_errors++;
            }
            else if ( !tmp_ptr) {
                debug("not found: %s",  &grpname_list[index] );
                res->re_errors++;
            }
        }
        else {
            errno = 0;
            grp = getgrnam( &grpname_list[index] );

            if (!grp) {
                if (errno) {
                    debug("error: %s -> %s", &grpname_list[index], strerror(errno));
                    res->re_errors++;
                }
                else {
                    debug("not found: %s",  &grpname_list[index] );
                    res->re_errors++;
                }
            }
        }
    }
    res->re_count = i;

    return (0);
}

// We need to release all the structures we allocated in benchmark_initrun()
int
benchmark_finirun(void *tsd)
{
    // tsd_t    *ts = (tsd_t *)tsd;
    debug("benchmark_finiworker: deallocating structures");

    free (grpname_list);

    return (0);
}

char *
benchmark_result()
{
    static char    result = '\0';
    debug("benchmark_result");
    return (&result);
}

