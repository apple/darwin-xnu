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
#include <string.h>

// add additional headers needed here.

#include "../libmicro.h"
#include <CoreFoundation/CFArray.h>
#include <CoreFoundation/CFString.h>
#include <CoreFoundation/CFDictionary.h>
#include <OpenDirectory/OpenDirectory.h>
#include <DirectoryService/DirectoryService.h>

#if DEBUG
# define debug(fmt, args...)    (void) fprintf(stderr, fmt , ##args)
// # define debug(fmt, args...)    (void) fprintf(stderr, fmt "\n" , ##args)
#else
# define debug(fmt, args...)
#endif


// Correct use case
//
//    od_query_create_with_node -E  -L -S -W -B 200 -C 10 -c 100 -r 300
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
// -c is the cache hit rate for lookup. set to 10%, you need -c 10.
//                ie. -B 100 -c 50 -r 1000 -C 200 (out of 1000 records, I want 50%
//                     lookup, and batch size is 100. 
//                     To get 50% cache hit rate, you need 500 record lookups.
//                     Batch size will be adjusted to 500 to get 500 record
//                     lookup in each benchmark. If -r size is smaller than -B,
//                     then -B will not be adjusted. 

// Defining prefix for user and group name
// make sure that these match the ones in LDAP records
// ie. local_test_1 , od_test_4525, od_test_group_43, od_test_host_63
#define LOCAL_U_PREFIX     CFSTR("local_test_")
#define OD_U_PREFIX        CFSTR("od_test_")
#define LOCAL_G_PREFIX     CFSTR("local_test_group_")
#define OD_G_PREFIX        CFSTR("od_test_group_")
#define LOCAL_H_PREFIX     CFSTR("local_test_host_")
#define OD_H_PREFIX        CFSTR("od_test_host_")

/*
 *    Your state variables should live in the tsd_t struct below
 */
typedef struct {
    ODNodeRef    node;
} tsd_t;

// dsRecTypeStandard type dictionary
enum {rectype_users=0, rectype_groups, rectype_hosts};
CFStringRef rectype_dict[] = { CFSTR(kDSStdRecordTypeUsers),
                               CFSTR(kDSStdRecordTypeGroups), 
                               CFSTR(kDSStdRecordTypeHosts) };

// the number of record lookup to issue is covered by standard option optB
static int  optRecords =    100;  // the number of total records
static int  optCachehit =   100;  // specify cache hit rate (% of record re-lookup)
static bool optNodeLocal =  1;    // which node to search. Local node is default
static int  optType =       rectype_users;    // dsRecType to search for. "Users"" is the default
static const char *nodename = "/LDAPv3/127.0.0.1";

static CFStringRef *key;                // username array

// parse -t option and return enum type: user, group, and host
// called by benchmark_optswitch()
int
ds_rec_type(char *name)
{
    if (strcasecmp("u", name) == 0) {
        return (rectype_users);
    } else if (strcasecmp("g", name) == 0) {
        return (rectype_groups);
    } else if (strcasecmp("h", name) == 0) {
        return (rectype_hosts);
    }

    return (-1);
}

int
benchmark_init()
{
    debug("benchmark_init");
    (void) sprintf(lm_optstr,  "c:n:r:t:");

    lm_tsdsize = sizeof (tsd_t);
    lm_defB = 1000;

    (void) sprintf(lm_usage,
                "\n       ------- od_query_create_with_node specific options (default: *)\n"
                "       [-c hitrate%% (100%%*)]\n"
                "       [-r total number of records (100*)]\n"
                "       [-n nodename] node name to use for test\n"
                "       [-t record type: 'u'sers, 'g'roups, 'h'osts]\n"
                "       use -B option to specify total number of record lookups to issue"
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

    case 'r':    // total number of records. default is 100
        optRecords = atoi(optarg);
        debug("optRecords = %d\n", optRecords);
        break;

    case 'n':    // node
        nodename = optarg;
        break;

    case 't':    // dsRecType: user, group, hots
        optType = ds_rec_type(optarg);
        debug("optType = %d\n", optType);

        if (optType == -1) {
            printf("wrong -t record type option\n");
            return (-1);
        }
        break;

    default:
        return (-1);
    }

    return (0);
}


int
benchmark_initrun()
{
    int i;
    CFStringRef prefix;              // local user is default
    
    debug("benchmark_initrun\n");

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

    switch (optType) {
        case rectype_users:
            prefix = (optNodeLocal) ? LOCAL_U_PREFIX : OD_U_PREFIX;
            break;
        case rectype_groups:
            prefix = (optNodeLocal) ? LOCAL_G_PREFIX : OD_G_PREFIX;
            break;
        case rectype_hosts:
            prefix = (optNodeLocal) ? LOCAL_H_PREFIX : OD_H_PREFIX;
            break;
    }
    // create an array of usernames to use in benchmark before their use
    // realtime generation in benchmark effects performance measurements

    key = malloc(sizeof(CFStringRef) * optRecords);

    // user, group, hosts key to lookup
    switch (optType) {

    case rectype_users:     // users query
    case rectype_groups:    // groups query
    case rectype_hosts:     // hosts query
        for (i = 0; i < optRecords; i++) {
            key[i] = CFStringCreateWithFormat( kCFAllocatorDefault, 
                                               NULL, 
                                               CFSTR("%@%d"), 
                                               prefix, 
                                               i+1);
            // CFShow(key[i]);  // print user name to check
        }
        break;
    }

    return (0);
}


// Initialize all structures that will be used in benchmark()
// 1. make local or network node for OD query
// 2. create user key 
int
benchmark_initworker(void *tsd)
{
    CFErrorRef    error;
    tsd_t *ts = (tsd_t *)tsd;

    debug("benchmark_initworker: %s", (optNodeLocal) ? "local" : "network");


    // create OD node for local or OD query
    if (optNodeLocal) {
        ts->node = ODNodeCreateWithNodeType(NULL, kODSessionDefault, kODNodeTypeLocalNodes, &error);
    }
    else {
        CFStringRef nodenameStr = CFStringCreateWithCString(kCFAllocatorDefault, nodename, kCFStringEncodingUTF8);
        ts->node = ODNodeCreateWithName(NULL, kODSessionDefault, nodenameStr, &error);
        CFRelease(nodenameStr);
    }

    if (!ts->node) {
        debug("error calling ODNodeCreateWithNodeType\n");
        exit(1);
    }

    CFRetain (ts->node);

    debug("benchmark_initworker: ODNodeRef = 0x%lx\n", ts->node);
    return (0);
}

int
benchmark(void *tsd, result_t *res)
{

    tsd_t        *ts = (tsd_t *)tsd;
    int          i;
    ODNodeRef    node;
    CFErrorRef   error;
    CFArrayRef   results;
    ODQueryRef   query;

   res->re_errors = 0;
    node = ts->node;

    debug("in to benchmark - optB = %i, node = 0x%lx \n", lm_optB, node);
    for (i = 0; i < lm_optB; i++) {

        debug("loop %d: querying\n", i);
        query = ODQueryCreateWithNode(NULL,
                        node,                        // inNode
                        rectype_dict[optType],       // inRecordTypeOrList
                        CFSTR(kDSNAttrRecordName),   // inAttribute
                        kODMatchInsensitiveEqualTo,  // inMatchType
                        key[i % optRecords],                      // inQueryValueOrList
                        NULL,                        // inReturnAttributeOrList
                        1,                           // inMaxResults
                        &error);

        if (query) {
            // we do not want to factually fetch the result in benchmark run
            // debug("loop %d: calling ODQueryCopyResults\n", i);
            results = ODQueryCopyResults(query, FALSE, &error);
            CFRelease(query);
            if (results) {
#if DEBUG
                int c;
                c = CFArrayGetCount(results);
                if (c > 0) {
                    debug("Successful run: %d results, ", c);
                }
                else {
                    debug("no result for ");
                }
                CFShow (key[i % optRecords]);
                debug("\n");
#endif
                CFRelease(results);
            }
            else {
                debug("loop %d: ODQueryCopyResults returned empty result for ", i);
                res->re_errors++;
                CFShow (key[i % optRecords]);
                debug("\n");
            } // if (results)

        } // if (query)
        else {
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
    tsd_t    *ts = (tsd_t *)tsd;

    debug("benchmark_result: deallocating structures\n");

    // free the node
    if (ts->node)
        CFRelease (ts->node);
    ts->node = NULL;

    return (0);
}

int
benchmark_finirun()
{
    int i;

    for (i = 0; i < optRecords; i++){
        CFRelease(key[i]);
    }

    free(key);

    return (0);
}

char *
benchmark_result()
{
    static char    result = '\0';
    debug("\n\n# of records adjusted to %d for cache hit rate %d%%\n", optRecords, optCachehit);
    debug("benchmark_result\n");
    return (&result);
}

