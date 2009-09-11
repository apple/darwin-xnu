/*
 * Copyright (c) 2007-2008 Apple Inc. All rights reserved.
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
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include "kxld_dict.h"
#include "kxld_util.h"

#define KEYLEN 40
#define STRESSNUM 10000

typedef struct {
    char * key;
    int * value;
} Stress;


void kxld_test_log(KXLDLogSubsystem sys, KXLDLogLevel level,
    const char *format, va_list ap, void *user_data);

void 
kxld_test_log(KXLDLogSubsystem sys __unused, KXLDLogLevel level __unused,
    const char *format, va_list ap, void *user_data __unused)
{
    va_list args;

    va_copy(args, ap);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

int 
main(int argc __unused, char *argv[] __unused)
{
    kern_return_t result = KERN_SUCCESS;
    KXLDDict dict;
    int a1 = 1, a2 = 3, i = 0, j = 0;
    void * b = NULL;
    u_int test_num = 0;
    u_long size = 0;
    Stress stress_test[STRESSNUM];

    kxld_set_logging_callback(kxld_test_log);

    bzero(&dict, sizeof(dict));
    
    fprintf(stderr, "%d: Initialize\n", ++test_num);
    result = kxld_dict_init(&dict, kxld_dict_string_hash, kxld_dict_string_cmp, 10);
    assert(result == KERN_SUCCESS);
    size = kxld_dict_get_num_entries(&dict);
    assert(size == 0);
    
    fprintf(stderr, "%d: Find nonexistant key\n", ++test_num);
    b = kxld_dict_find(&dict, "hi");
    assert(b == NULL);
    
    fprintf(stderr, "%d: Insert and find\n", ++test_num);
    result = kxld_dict_insert(&dict, "hi", &a1);
    assert(result == KERN_SUCCESS);
    b = kxld_dict_find(&dict, "hi");
    assert(b && *(int*)b == a1);
    size = kxld_dict_get_num_entries(&dict);
    assert(size == 1);
    
    fprintf(stderr, "%d: Insert same key with different values\n", ++test_num);
    result = kxld_dict_insert(&dict, "hi", &a2);
    assert(result == KERN_SUCCESS);
    b = kxld_dict_find(&dict, "hi");
    assert(b && *(int*)b == a2);
    size = kxld_dict_get_num_entries(&dict);
    assert(size == 1);
    
    fprintf(stderr, "%d: Clear and find of nonexistant key\n", ++test_num);
    kxld_dict_clear(&dict);
    result = kxld_dict_init(&dict, kxld_dict_string_hash, kxld_dict_string_cmp, 10);
    b = kxld_dict_find(&dict, "hi");
    assert(b == NULL);
    size = kxld_dict_get_num_entries(&dict);
    assert(size == 0);
    
    fprintf(stderr, "%d: Insert multiple keys\n", ++test_num);
    result = kxld_dict_insert(&dict, "hi", &a1);
    assert(result == KERN_SUCCESS);
    result = kxld_dict_insert(&dict, "hello", &a2);
    assert(result == KERN_SUCCESS);
    b = kxld_dict_find(&dict, "hi");
    assert(result == KERN_SUCCESS);
    assert(b && *(int*)b == a1);
    b = kxld_dict_find(&dict, "hello");
    assert(b && *(int*)b == a2);
    size = kxld_dict_get_num_entries(&dict);
    assert(size == 2);
    
    fprintf(stderr, "%d: Remove keys\n", ++test_num);
    kxld_dict_remove(&dict, "hi", &b);
    assert(b && *(int*)b == a1);
    b = kxld_dict_find(&dict, "hi");
    assert(b == NULL);
    kxld_dict_remove(&dict, "hi", &b);
    assert(b == NULL);
    size = kxld_dict_get_num_entries(&dict);
    assert(size == 1);
    
    fprintf(stderr, "%d: Stress test - %d insertions and finds\n", ++test_num, STRESSNUM);

    kxld_dict_clear(&dict);
    result = kxld_dict_init(&dict, kxld_dict_string_hash, kxld_dict_string_cmp, 10);
    for (i = 0; i < STRESSNUM; ++i) {
        int * tmp_value = kxld_alloc(sizeof(int));
        char * tmp_key = kxld_alloc(sizeof(char) * (KEYLEN + 1));
        
        *tmp_value = i;
        for (j = 0; j < KEYLEN; ++j) {
            tmp_key[j] = (rand() % 26) + 'a';
        }
        tmp_key[KEYLEN] = '\0';
        
        kxld_dict_insert(&dict, tmp_key, tmp_value);
        stress_test[i].key = tmp_key;
        stress_test[i].value = tmp_value;
    }
    
    for (i = 0; i < STRESSNUM; ++i) {
        int target_value;
        void * tmp_value;
        char * key = stress_test[i].key;
        
        target_value = *stress_test[i].value;
        tmp_value = kxld_dict_find(&dict, key);
        assert(target_value == *(int *)tmp_value);

        kxld_free(stress_test[i].key, sizeof(char) * (KEYLEN + 1));
        kxld_free(stress_test[i].value, sizeof(int));
    }

    fprintf(stderr, "%d: Destroy\n", ++test_num);
    kxld_dict_deinit(&dict);
    
    fprintf(stderr, "\nAll tests passed!  Now check for memory leaks...\n");
    
    kxld_print_memory_report();
    
    return 0;
}

