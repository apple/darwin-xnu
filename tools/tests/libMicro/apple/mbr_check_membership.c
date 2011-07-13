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
//    mbr_check_membership -E  -L -S -W -B 200 -C 10 -g 1211-1213 -u 5000-5200
//
//      libMicro default benchmark run options are "-E -C 200 -L -S -W"
//
// -B is batch size: loop iteration per each benchmark run. (default: 100)
// -C is min sample number: how many benchmark needs to run to get proper sample
//                          1 is mimumum, but you get at least 3 benchmark run
//                          samples. Do not set to zero. Default is 200 for most
//                          runs in libMicro.
// -u uid range in the form of "min-max". For example, -u 5000-5200
// -g gid range or gid

/*
 *    Your state variables should live in the tsd_t struct below
 */
typedef struct {
} tsd_t;

#define INVALID_ID  -1

static uid_t uid_min = INVALID_ID;
static gid_t gid_min = INVALID_ID;;

static int   uid_range = 0;  // uid_max = uid_min + uid_range
static int   gid_range = 0; // gid_max = gid_min + gid_range

static uuid_t *u_uuid_list = NULL;  // user uuid list
static uuid_t *g_uuid_list = NULL;  // group uuid list

int
benchmark_init()
{
    debug("benchmark_init");
    (void) sprintf(lm_optstr,  "g:u:");

    lm_tsdsize = sizeof(tsd_t);
    lm_defB = 100;

    (void) sprintf(lm_usage,
                "\n       ------- mbr_check_membership specific options\n"
                "       [-u UID range (min-max)]\n"
                "       [-g GID or GID range (gid or min-max)]\n"
                "\n" );
    return (0);
}

int
parse_range(uint *min, int *offset, char *buf)
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
        *offset = range - *min;
        debug("range = %d", *offset);
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
    case 'g':    // GID or GID range
        return parse_range( &gid_min, &gid_range, optarg);
        break;

    case 'u':    // UID range
        return parse_range( &uid_min, &uid_range, optarg);
        break;
    default:
        return -1;
    }

    return 0;
}


// Initialize all structures that will be used in benchmark()
// 1. make local or network node for OD query
// 2. create user key 
int
benchmark_initrun(void *tsd)
{
    int i;
    //tsd_t *ts = (tsd_t *)tsd;

    debug("benchmark_initrun");

    if (uid_min == INVALID_ID || gid_min == INVALID_ID) {
        printf("Both -u and -g need to be specified\n");
        return -1;
    }

    // create an array of usernames to use in benchmark before their use
    // realtime generation in benchmark effects performance measurements

    u_uuid_list = malloc( sizeof(*u_uuid_list) * (uid_range+1) );
    g_uuid_list = malloc( sizeof(*g_uuid_list) * (gid_range+1) );

    for (i = 0; i <= uid_range; i++) {

        if (mbr_uid_to_uuid(uid_min+i, u_uuid_list[i])) {
            printf("error converting uid %d to UUID\n", uid_min+i);
            return -1;
        }
    }

    for (i = 0; i <= gid_range; i++) {

        if (mbr_gid_to_uuid(gid_min+i, g_uuid_list[i])) {
            printf("error converting gid %d to UUID\n", gid_min+i);
            return -1;
        }
    }

    return (0);
}

int
benchmark(void *tsd, result_t *res)
{
    int         i, index, gindex, err, isMember=0;
    //tsd_t *ts = (tsd_t *)tsd;

#ifdef DEBUG
    uid_t       uid;
    int         id_type;
#endif

    res->re_errors = 0;

    // debug("in to benchmark - optB = %i", lm_optB);

    for (i = 0; i < lm_optB; i++) {

        index = random() % (uid_range+1);
        gindex = random() % (gid_range+1);
        err = mbr_check_membership(u_uuid_list[index], g_uuid_list[gindex], &isMember);

#ifdef DEBUG
        //mbr_uuid_to_id(u_uuid_list[index], &uid, &id_type);
        //debug ("loop %d: uid %d is %s (gindex %d)", i, uid, (isMember)?"member":"not a member", gindex);
#endif

        if (err) {
            if (err == EIO) {
                debug("mbr_check_membership returned EIO. Unable to communicate with DS daemon");
            }
            else if (err == ENOENT) {
                debug("mbr_check_membership returned ENOENT. User not found");
            }
            else {
                debug("error: %s", strerror(err));
            }
            res->re_errors++;
        }
    }
    res->re_count = i;

    return (0);
}


// We need to release all the structures we allocated in benchmark_initrun()
int
benchmark_finirun(void *tsd)
{
    //tsd_t    *ts = (tsd_t *)tsd;
	
    debug("benchmark_result: deallocating structures");

    free(u_uuid_list);
    free(g_uuid_list);

    return (0);
}

char *
benchmark_result()
{
    static char    result = '\0';
    debug("benchmark_result");
    return (&result);
}

