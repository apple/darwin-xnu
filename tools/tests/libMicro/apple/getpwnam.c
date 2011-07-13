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
#include <membership.h>
#include <pwd.h>
#include <uuid/uuid.h>

#if DEBUG
# define debug(fmt, args...)    (void) fprintf(stderr, fmt "\n" , ##args)
#else
# define debug(fmt, args...)
#endif


// Correct use case
//
//    getpwnam -E  -L -S -W -B 200 -C 10 -c 100 -r 300 -U test_user_
//
//      libMicro default benchmark run options are "-E -L -S -W -C 200"
//
// -B is batch size: loop iteration per each benchmark run. Needs to match # of
//                   real lookups. This is total number of lookups to issue.
// -C is min sample number: how many benchmark needs to run to get proper sample
//                          1 is mimumum, but you get at least 3 benchmark run
//                          samples. Do not set to zero. Default is 200 for most
//                          runs in libMicro.
// -r is the number of total users
// -c is the cache hit rate for lookup. set to 10%, you need -c 10.
//                ie. -B 100 -c 50 -r 1000 -C 200 (out of 1000 records, I want 50%
//                     lookup, and batch size is 100. 
//                     To get 50% cache hit rate, you need 500 record lookups.
//                     Batch size will be adjusted to 500 to get 500 record
//                     lookup in each benchmark. If -r size is smaller than -B,
//                     then -B will not be adjusted. 
// -u prefix: the user name prefix to use in front the user number as the
//		login name to lookup

extern int gL1CacheEnabled;

/*
 *    Your state variables should live in the tsd_t struct below
 */
typedef struct {
} tsd_t;

// temporary buffer size
#define BUFSIZE 200

// the number of record lookup to issue is covered by standard option optB
static int  optRecords =    100;  // the number of total records
static int  optCachehit =   100;  // specify cache hit rate (% of record re-lookup)

// This will use local users (local_test_*)
static char *default_uprefix = "local_test_";

#define USERNAME_LEN	20
static char *username_list;

int
benchmark_init()
{
    debug("benchmark_init");
    (void) sprintf(lm_optstr,  "l:c:r:u:");

    lm_tsdsize = sizeof (tsd_t);
    lm_defB = 100;

    (void) sprintf(lm_usage,
                "\n     ------- getpwnam specific options (default: *)\n"
                "       [-c hitrate%% (100%%*)]\n"
                "       [-r total number of records (100*)]\n"
		"	[-u username_prefix (local_test_)]\n"
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
    case 'c':    // cache hit rate. 100% means lookup the same records over and over
        optCachehit = atoi(optarg);
        debug("optCachehit = %d\n", optCachehit);
        if (optCachehit > 100 || optCachehit < 0) {
            printf("cache hit rate should be in between 0%% and 100%%");
            return (-1);
        }
        break;

    case 'l':
        gL1CacheEnabled = atoi(optarg);
        break;

    case 'r':    // total number of records. default is 100
        optRecords = atoi(optarg);
        debug("optRecords = %d\n", optRecords);
        break;

    case 'u':
	default_uprefix = strdup(optarg);
	debug("default_uprefix = %s\n", default_uprefix);
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

    // Adjust # of record lookups to reflect cache hit rate
    if (optCachehit < 100) {
        optRecords  = (int) ((float) optRecords * ((float) optCachehit / 100));
        debug("# of records adjusted to %d for cache hit rate %d%%\n", optRecords, optCachehit);
    }

    // if batch size (one benchmark run) is less than the number records, adjust
    // it to match the number record lookups in one batch run
    if (lm_optB < optRecords) {
        lm_optB = optRecords;
        debug("Adjusting batch size to %d to match the lookups required in benchmark run\n", lm_optB);
    }

    // create an array of usernames to use in benchmark before their use
    // realtime generation in benchmark effects performance measurements
    username_list = malloc( optRecords * USERNAME_LEN );
    if (!username_list) {
        debug ("malloc error");
        exit (1);
    }

    for (i = 0; i < optRecords; i++) {
        sprintf(&username_list[i*USERNAME_LEN], "%s%d", default_uprefix, i+1);
        // debug("creating username %s", &username_list[i*USERNAME_LEN]);
    }

    return (0);
}


int
benchmark(void *tsd, result_t *res)
{
    int         i, err;
    struct passwd *passwd = NULL;

    res->re_errors = 0;

    debug("in to benchmark - optB = %i", lm_optB);
    for (i = 0; i < lm_optB; i++) {
        int index = (random() % optRecords) * USERNAME_LEN;

        if (lm_optT > 1) {
            struct passwd pd;
            struct passwd *pwd_ptr = &pd;
            struct passwd *tmp_ptr;
            char pbuf[BUFSIZE];

            err = getpwnam_r( &username_list[index], pwd_ptr, pbuf, BUFSIZE, &tmp_ptr);
            if (err) {
                printf("error: %s -> %s", &username_list[index], strerror(err));
                res->re_errors++;
            }
            else if (!tmp_ptr) {
                debug("not found: %s", &username_list[index]);
                res->re_errors++;
            }
        }
        else {
            errno = 0;
            passwd = getpwnam( &username_list[index] );

            if (!passwd) {
                if (errno) {
                    debug("error: %s -> %s", &username_list[index], strerror(errno));
                    res->re_errors++;
                }
                else {
                    debug("not found: %s", &username_list[index]);
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
    debug("benchmark_finirun: deallocating structures");

    free (username_list);

    return (0);
}

char *
benchmark_result()
{
    static char    result = '\0';
    debug("benchmark_result");
    return (&result);
}

