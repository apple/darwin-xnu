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


//
// Correct use case
//
//    getaddrinfo_host -E  -L -S -W -B 200 -C 100 -s "server%d"
//
//      libMicro default benchmark run options are "-E -L -S -W -C 200"
//
// -B is batch size: loop iteration per each benchmark run. Needs to match # of
//                   real lookups. This is total number of lookups to issue.
// -C is min sample number: how many benchmark needs to run to get proper sample
//                          1 is mimumum, but you get at least 3 benchmark run
//                          samples. Do not set to zero. Default is 200 for most
//                          runs in libMicro.
// -h is hostname format: for example, "server-%d.performance.rack"
//                        this is C language string format that can include %d
// -r hostname digit range in the form of "min-max". For example, -r 100-112
//    With -h and -r, resulting hostnames are
//      server-100.performance.rack - server-112.performance.rack
//

extern int gL1CacheEnabled;

/*
 *    Your state variables should live in the tsd_t struct below
 */
typedef struct {
} tsd_t;

#define HOSTNAME_LEN    125
static int host_min=-1, host_range=0;
static char *hostname_format=NULL;
static char *hostname_list=NULL;

int
benchmark_init()
{
    debug("benchmark_init");
    (void) sprintf(lm_optstr,  "l:h:r:");

    lm_tsdsize = sizeof (tsd_t);
    lm_defB = 100;

    (void) sprintf(lm_usage,
                "\n       ------- getaddrinfo_host specific options (default: *)\n"
                "       [-h \"hostname format\"]. ie. \"server-%%d.perf\"\n"
                "       [-r min-max]\n"
                "\n" );

    return (0);
}


int
parse_range(int *min, int *offset, char *buf)
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
        *offset = range - *min + 1; // 1-based
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
    case 'h':   // hostname string format
        hostname_format = strdup(optarg);
        debug ("hostname format: %s", hostname_format);
        break;

	case 'l':
		gL1CacheEnabled = atoi(optarg);
		break;

    case 'r':    // UID range
        return parse_range( &host_min, &host_range, optarg);
        break;

    default:
        return -1;
    }

    

    return 0;
}


// Initialize all structures that will be used in benchmark()
//
int
benchmark_initrun()
{
    int i;

    debug("\nbenchmark_initrun");

    if (host_min == -1) {
        printf("-r min-max needs to be specified\n");
        exit (1);
    }

    if (!hostname_format) {
        printf("-h hostname_format needs to be specified\n");
        exit (1);
    }

    hostname_list = malloc ( host_range * HOSTNAME_LEN );
    if (!hostname_list) {
        debug("malloc error");
        exit (1);
    }

    for (i = 0; i < host_range; i++) {
        sprintf( &hostname_list[i*HOSTNAME_LEN], hostname_format, i+host_min);
        // debug("hostname: %s", &hostname_list[i*HOSTNAME_LEN]);
    }
    return (0);
}


int
benchmark(void *tsd, result_t *res)
{
    int         i, index, err;
    struct addrinfo *addi;

    res->re_errors = 0;

    debug("in to benchmark - optB = %i", lm_optB);
    srandom(getpid());

    for (i = 0; i < lm_optB; i++) {
        index = HOSTNAME_LEN * (random() % host_range);

        err = getaddrinfo( &hostname_list[index], NULL, NULL, &addi);

        if (err) {
            debug("%s: error: %s", &hostname_list[index], gai_strerror(err));
            res->re_errors++;
        }
        else {
            debug("host %s done", &hostname_list[index]);
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

    free(hostname_list);

    return (0);
}

char *
benchmark_result()
{
    static char    result = '\0';
    debug("benchmark_result");
    return (&result);
}

