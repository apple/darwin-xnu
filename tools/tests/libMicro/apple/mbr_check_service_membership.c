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
//    mbr_check_service_membership -E  -L -S -W -B 200 -C 10 -r 100 -s "SACL" -u user_prefix
//
//      libMicro default benchmark run options are "-E -C 200 -L -S -W"
//
// -B is batch size: loop iteration per each benchmark run. Needs to match # of
//                   real lookups. This is total number of lookups to issue.
// -C is min sample number: how many benchmark needs to run to get proper sample
//                          1 is mimumum, but you get at least 3 benchmark run
//                          samples. Do not set to zero. Default is 200 for most
//                          runs in libMicro.
// -r is the number of total records.
// -s is SACL string: ie. "ssh"
// -u user_prefix that preceeds the user number

typedef struct {
	uuid_t *uuid_list;
} tsd_t;

// the number of record lookup to issue is covered by standard option optB
static int  optRecords =    100;  // the number of total records
static int  optSACL = 0;          // option SACL specified?

static char **sacl = NULL;
static char *default_sacl[] = { "com.apple.access_dsproxy",
                                "com.apple.access_screensharing",
                                "com.apple.access_ssh",
                                ""};
static int  numSACL = 3;          // number of SACLs


// This will use local users (local_test_*)
static char *default_uprefix = "local_test_";

int
benchmark_init()
{
    debug("benchmark_init");
    (void) sprintf(lm_optstr,  "r:s:u:");

    lm_tsdsize = sizeof(tsd_t);
    lm_defB = 100;

    (void) sprintf(lm_usage,
                "\n       ------- mbr_check_service_membership specific options (default: *)\n"
                "       [-r total number of records (100*)]\n"
                "       [-s SACL]\n"
		"	[-u user_prefix]\n"
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

    case 's':    // SACL
        if (optSACL) {
            printf("SACL already specified. Skipping");
            break;
        }
        sacl = malloc(2 * sizeof(char *));
        if (!sacl) {
            printf("Error: no memory available for strdup\n");
            return -1;
        }
        sacl[0] = strdup(optarg);
        sacl[1] = "";
        optSACL = 1;
        numSACL = 1;

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


int
benchmark_initrun()
{
    int i;
    debug("benchmark_initrun");

    if (!sacl) {
        sacl = default_sacl;
    }

    for (i=0; strcmp(sacl[i], "") && i <= numSACL; i++) {
        debug("SACL = %s", sacl[i]);
    }

    return (0);
}

// Initialize all structures that will be used in benchmark()
// 1. make local or network node for OD query
// 2. create user key 
int
benchmark_initworker(void *tsd)
{
    int i;
    tsd_t *ts = (tsd_t *)tsd;
    char *uprefix = default_uprefix;              // local user is default
    char username[30] = "";
    struct passwd *info = NULL;

    debug("benchmark_initworker");

    // create an array of usernames to use in benchmark before their use
    // realtime generation in benchmark effects performance measurements

    ts->uuid_list = calloc(optRecords, sizeof(uuid_t));

    for (i = 0; i < optRecords; i++) {

        sprintf(username, "%s%d", uprefix, i+1);
        info = getpwnam(username);
        if (!info) {
            debug ("error converting username %s to uuid", username);
            exit (1);
        }

        (void) mbr_uid_to_uuid(info->pw_uid, ts->uuid_list[i]);

#if DEBUG
        char buf[30];
        uid_t uid;
        int id_type; 
        uuid_unparse(ts->uuid_list[i], buf);
        mbr_uuid_to_id(ts->uuid_list[i], &uid, &id_type);
        debug ("username (%s), uid %d, uuid %s, back to uid %d", username, info->pw_uid, buf, uid);
#endif
    }

    // if batch size (one benchmark run) is less than the number records, adjust
    // it to match the number record lookups in one batch run
    if (optRecords < lm_optB) {
        lm_optB = optRecords;
        debug("Reducing batch size to %d to match the record #\n", lm_optB);
    }

    debug("benchmark_initworker");
    return (0);
}

int
benchmark(void *tsd, result_t *res)
{
    tsd_t *ts = (tsd_t *)tsd;
    int         i;
    int         err;
    int         isMember=0;
    char        *sacl_chosen;

#ifdef DEBUG
    uid_t       uid;
    int         id_type;
#endif

    res->re_errors = 0;

    debug("in to benchmark - optB = %i", lm_optB);
    for (i = 0; i < lm_optB; i++) {

        sacl_chosen = sacl[random() % numSACL];
        err = mbr_check_service_membership(ts->uuid_list[i], sacl_chosen, &isMember);

#ifdef DEBUG
        mbr_uuid_to_id(ts->uuid_list[i], &uid, &id_type);
        debug ("loop %d: uid %d is %s a member of %s", i, uid, (isMember) ? "" : "not", sacl_chosen);
#endif

        if (err) {
            debug("error: %s", strerror(err));
            res->re_errors++;
        }
    }
    res->re_count = i;

    return (0);
}


// We need to release all the structures we allocated in benchmark_initworker()
int
benchmark_finiworker(void *tsd)
{
    tsd_t *ts = (tsd_t *)tsd;
    debug("benchmark_result: deallocating structures");

    free(ts->uuid_list);

    return (0);
}

int
benchmark_finirun(void *tsd)
{
	if (optSACL)
        free(sacl);
	
	return 0;
}

char *
benchmark_result()
{
    static char    result = '\0';
    debug("benchmark_result");
    return (&result);
}

