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
#include <grp.h>

#if DEBUG
# define debug(fmt, args...)    (void) fprintf(stderr, fmt "\n" , ##args)
#else
# define debug(fmt, args...)
#endif


// Correct use case
//
//    getgrgid -E  -L -S -W -B 200 -C 10 -g 1211-1213
//
//      libMicro default benchmark run options are "-E -L -S -W -C 200"
//
// -B is batch size: loop iteration per each benchmark run. Needs to match # of
//                   real lookups. This is total number of lookups to issue.
// -C is min sample number: how many benchmark needs to run to get proper sample
//                          1 is mimumum, but you get at least 3 benchmark run
//                          samples. Do not set to zero. Default is 200 for most
//                          runs in libMicro.
// -g gid range in the form of "min-max". For example, -g 1211-1213
//

extern int gL1CacheEnabled;

/*
 *    Your state variables should live in the tsd_t struct below
 */
typedef struct {
} tsd_t;

// temporary buffer size
#define BUFSIZE 200
#define INVALID_ID  -1

static gid_t  gid_min = INVALID_ID;
static int    gid_range = 0;  // gid_max = gid_min + gid_range

int
benchmark_init()
{
    debug("benchmark_init");
    (void) sprintf(lm_optstr,  "l:g:");

    lm_tsdsize = sizeof (tsd_t);
    lm_defB = 100;

    (void) sprintf(lm_usage,
                "\n     ------- getgrgid specific options (default: *)\n"
                "       [-g GID range (min-max)]\n"
                "\n" );
    return (0);
}


int
parse_range(gid_t *min, int *offset, char *buf)
{
    char *value, *tmp_ptr = strdup(buf);
    int range=0;
    debug("parse_range");

    value = strsep(&tmp_ptr, "-");
    *min = atoi(value);
    debug("min = %d", *min);
    if (tmp_ptr) {
        value = strsep(&tmp_ptr, "-");
        range = atoi(value);
        if (range < *min) {
            printf("max id should be larger than min id\n");
            return -1;
        }
        *offset = range - *min + 1;
        debug("range = %d", *offset);
    }
    else {
        printf("argument should be in the form of min-max\n");
        return -1;
    }

    return 0;

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
            
    case 'g':    // GID range
        return parse_range( &gid_min, &gid_range, optarg);
        break;

    default:
        return -1;
    }

    return 0;
}


// Initialize all structures that will be used in benchmark()
// moved template init from benchmark_initworker -> benchmark_initrun
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
    struct group *grp = NULL;

    res->re_errors = 0;

    debug("in to benchmark - optB = %i", lm_optB);
    for (i = 0; i < lm_optB; i++) {
        gid_t gid = gid_min + random() % gid_range ;

        if (lm_optT > 1) {
            struct group gd;
            struct group *grp_ptr = &gd;
            struct group *tmp_ptr;
            char gbuf[BUFSIZE];

            err = getgrgid_r( gid, grp_ptr, gbuf, BUFSIZE, &tmp_ptr);
            if (err) {
                debug("error: GID %d -> %s", gid, strerror(err));
                res->re_errors++;
            }
            else if (!tmp_ptr) {
                debug("not found: GID %d", gid);
                res->re_errors++;
            }
        }
        else {
            errno = 0;
            grp = getgrgid( gid );

            if (!grp) {
                if (errno) {
                    debug("error: GID %d -> %s", gid, strerror(errno));
                    res->re_errors++;
                }
                else {
                    debug("not found: GID %d", gid);
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

