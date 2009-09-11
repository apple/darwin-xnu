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
#include <string.h>
#include <sys/types.h>

#define DEBUG_ASSERT_COMPONENT_NAME_STRING "kxld"
#include <AssertMacros.h>

#include "kxld_dict.h"
#include "kxld_util.h"

/*******************************************************************************
* Types and macros
*******************************************************************************/

/* Ratio of num_entries:num_buckets that will cause a resize */
#define RESIZE_NUMER 7
#define RESIZE_DENOM 10
#define RESIZE_THRESHOLD(x) (((x)*RESIZE_NUMER) / RESIZE_DENOM)
#define MIN_BUCKETS(x) (((x)*RESIZE_DENOM) / RESIZE_NUMER) 

/* Selected for good scaling qualities when resizing dictionary
 * ... see: http://www.concentric.net/~ttwang/tech/hashsize.htm
 */
#define DEFAULT_DICT_SIZE 89

typedef struct dict_entry DictEntry;

typedef enum {
    EMPTY = 0,
    USED = 1,
    DELETED = 2
} DictEntryState;

struct dict_entry {
    const void *key;
    void *value;
    DictEntryState state;
};

/*******************************************************************************
* Function prototypes
*******************************************************************************/

static kern_return_t get_locate_index(const KXLDDict *dict, const void *key, 
    u_int *idx);
static kern_return_t get_insert_index(const KXLDDict *dict, const void *key, 
    u_int *idx);
static kern_return_t resize_dict(KXLDDict *dict);

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_dict_init(KXLDDict * dict, kxld_dict_hash hash, kxld_dict_cmp cmp, 
    u_int num_entries) 
{
    kern_return_t rval = KERN_FAILURE;
    u_int min_buckets = MIN_BUCKETS(num_entries);
    u_int num_buckets = DEFAULT_DICT_SIZE;
    
    check(dict);
    check(hash);
    check(cmp);
    
    /* We want the number of allocated buckets to be at least twice that of the 
     * number to be inserted.
     */
    while (min_buckets > num_buckets) {
        num_buckets *= 2;
        num_buckets++;
    }
    
    /* Allocate enough buckets for the anticipated number of entries */
    rval = kxld_array_init(&dict->buckets, sizeof(DictEntry), num_buckets);
    require_noerr(rval, finish);
    
    /* Initialize */
    dict->hash = hash;
    dict->cmp = cmp;
    dict->num_entries = 0;
    dict->resize_threshold = RESIZE_THRESHOLD(num_buckets);
    
    rval = KERN_SUCCESS;
    
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
void
kxld_dict_clear(KXLDDict *dict)
{
    check(dict);

    dict->hash = NULL;
    dict->cmp = NULL;
    dict->num_entries = 0;
    dict->resize_threshold = 0;
    kxld_array_clear(&dict->buckets);
    kxld_array_clear(&dict->resize_buckets);
}

/*******************************************************************************
*******************************************************************************/
void
kxld_dict_iterator_init(KXLDDictIterator *iter, const KXLDDict *dict)
{
    check(iter);
    check(dict);

    iter->idx = 0;
    iter->dict = dict;
}

/*******************************************************************************
*******************************************************************************/
void
kxld_dict_deinit(KXLDDict *dict)
{
    check(dict);
    
    kxld_array_deinit(&dict->buckets);
    kxld_array_deinit(&dict->resize_buckets);
}

/*******************************************************************************
*******************************************************************************/
u_int
kxld_dict_get_num_entries(const KXLDDict *dict)
{
    check(dict);

    return dict->num_entries;
}

/*******************************************************************************
*******************************************************************************/
void *
kxld_dict_find(const KXLDDict *dict, const void *key)
{
    kern_return_t rval = KERN_FAILURE;
    DictEntry *entry = NULL;
    u_int idx = 0;
   
    check(dict);
    check(key);
   
    rval = get_locate_index(dict, key, &idx);
    if (rval) return NULL; 

    entry = kxld_array_get_item(&dict->buckets, idx);
    
    return entry->value;
}

/*******************************************************************************
* This dictionary uses linear probing, which means that when there is a
* collision, we just walk along the buckets until a free bucket shows up.
* A consequence of this is that when looking up an item, items that lie between
* its hash value and its actual bucket may have been deleted since it was
* inserted.  Thus, we should only stop a lookup when we've wrapped around the
* dictionary or encountered an EMPTY bucket.
********************************************************************************/
static kern_return_t
get_locate_index(const KXLDDict *dict, const void *key, u_int *_idx)
{
    kern_return_t rval = KERN_FAILURE;
    DictEntry *entry = NULL;
    u_int base, idx;

    base = idx = dict->hash(dict, key);
    
    /* Iterate until we match the key, wrap, or hit an empty bucket */
    entry = kxld_array_get_item(&dict->buckets, idx);
    while (!dict->cmp(entry->key, key)) {
        if (entry->state == EMPTY) goto finish;

        idx = (idx + 1) % dict->buckets.nitems;
        if (idx == base) goto finish;

        entry = kxld_array_get_item(&dict->buckets, idx);
    }

    check(idx < dict->buckets.nitems);

    *_idx = idx;
    rval = KERN_SUCCESS;

finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_dict_insert(KXLDDict *dict, const void *key, void *value)
{
    kern_return_t rval = KERN_FAILURE;
    DictEntry *entry = NULL;
    u_int idx = 0;
    
    check(dict);
    check(key);
    check(value);
    
    /* Resize if we are greater than the capacity threshold.
     * Note: this is expensive, but the dictionary can be sized correctly at
     * construction to avoid ever having to do this.
     */
    while (dict->num_entries > dict->resize_threshold) { 
        rval = resize_dict(dict); 
        require_noerr(rval, finish);
    }
    
    /* If this function returns FULL after we've already resized appropriately
     * something is very wrong and we should return an error.
     */
    rval = get_insert_index(dict, key, &idx);
    require_noerr(rval, finish);
    
    /* Insert the new key-value pair into the bucket, but only count it as a 
     * new entry if we are not overwriting an existing entry.
     */
    entry = kxld_array_get_item(&dict->buckets, idx);
    if (entry->state != USED) {
        dict->num_entries++;
        entry->key = key;
        entry->state = USED;
    }
    entry->value = value;

    rval = KERN_SUCCESS;
    
finish:
    return rval;
}

/*******************************************************************************
* Increases the hash table's capacity by 2N+1.  Uses dictionary API.  Not
* fast; just correct.
*******************************************************************************/
static kern_return_t
resize_dict(KXLDDict *dict)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDArray tmparray;
    DictEntry *entry = NULL;
    u_int nbuckets = (dict->buckets.nitems * 2 + 1);
    u_int i = 0;

    check(dict);

    /* Initialize a new set of buckets to hold more entries */
    rval = kxld_array_init(&dict->resize_buckets, sizeof(DictEntry), nbuckets);
    require_noerr(rval, finish);

    /* Swap the new buckets with the old buckets */
    tmparray = dict->buckets;
    dict->buckets = dict->resize_buckets;
    dict->resize_buckets = tmparray; 

    /* Reset dictionary parameters */
    dict->num_entries = 0;
    dict->resize_threshold = RESIZE_THRESHOLD(dict->buckets.nitems);

    /* Rehash all of the entries */
    for (i = 0; i < dict->resize_buckets.nitems; ++i) {
        entry = kxld_array_get_item(&dict->resize_buckets, i);
        if (entry->state == USED) {
            rval = kxld_dict_insert(dict, entry->key, entry->value);
            require_noerr(rval, finish);
        }
    }

    /* Clear the old buckets */
    kxld_array_clear(&dict->resize_buckets);

    rval = KERN_SUCCESS;
    
finish:
    return rval;
}

/*******************************************************************************
* Simple function to find the first empty cell
*******************************************************************************/
static kern_return_t
get_insert_index(const KXLDDict *dict, const void *key, u_int *r_index)
{
    kern_return_t rval = KERN_FAILURE;
    DictEntry *entry = NULL;
    u_int base, idx;

    base = idx = dict->hash(dict, key);
    
    /* Iterate through the buckets until we find an EMPTY bucket, a DELETED
     * bucket, or a key match.
     */
    entry = kxld_array_get_item(&dict->buckets, idx);
    while (entry->state == USED && !dict->cmp(entry->key, key)) {
        idx = (idx + 1) % dict->buckets.nitems;
        require_action(base != idx, finish, rval=KERN_FAILURE);
        entry = kxld_array_get_item(&dict->buckets, idx);
    }
    
    *r_index = idx;
    rval = KERN_SUCCESS;
    
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
void
kxld_dict_remove(KXLDDict *dict, const void *key, void **value)
{
    kern_return_t rval = KERN_FAILURE;
    DictEntry *entry = NULL;
    u_int idx = 0;
   
    check(dict);
    check(key);
    
    /* Find the item */
    rval = get_locate_index(dict, key, &idx);
    if (rval) {
        if (value) *value = NULL;
        return;
    }

    entry = kxld_array_get_item(&dict->buckets, idx);

    /* Save the value if requested */    
    if (value) *value = entry->value;

    /* Delete the item from the dictionary */
    entry->key = NULL;
    entry->value = NULL;
    entry->state = DELETED;
    dict->num_entries--;
}

/*******************************************************************************
*******************************************************************************/
void 
kxld_dict_iterator_get_next(KXLDDictIterator *iter, const void **key, 
    void **value)
{
    DictEntry *entry = NULL;

    check(iter);
    check(key);
    check(value);

    *key = NULL;
    *value = NULL;

    /* Walk over the dictionary looking for USED buckets */
    for (; iter->idx < iter->dict->buckets.nitems; ++(iter->idx)) {
        entry = kxld_array_get_item(&iter->dict->buckets, iter->idx);
        if (entry->state == USED) {
            *key = entry->key;
            *value = entry->value;
            ++(iter->idx);
            break;
        }
    }
}

/*******************************************************************************
*******************************************************************************/
void 
kxld_dict_iterator_reset(KXLDDictIterator *iter)
{
    iter->idx = 0;
}

/*******************************************************************************
* This is Daniel Bernstein's hash algorithm from comp.lang.c
* It's fast and distributes well.  Returns an idx into the symbol hash table.
* NOTE: Will not check for a valid pointer - performance
*******************************************************************************/
u_int
kxld_dict_string_hash(const KXLDDict *dict, const void *_key) 
{
    const char *key = _key;
    u_int c = 0;
    u_int hash_val = 5381;

    check(dict);
    check(_key);

    while ((c = *key++)) {
        /* hash(i) = hash(i-1) *33 ^ name[i] */
        hash_val = ((hash_val << 5) + hash_val) ^ c;    
    }
    
    return (hash_val % dict->buckets.nitems);
}

u_int
kxld_dict_uint32_hash(const KXLDDict *dict, const void *_key)
{
    uint32_t key = *(const uint32_t *) _key;

    check(_key);

    return (u_int) (key % dict->buckets.nitems);
}

u_int
kxld_dict_kxldaddr_hash(const KXLDDict *dict, const void *_key)
{
    kxld_addr_t key = *(const kxld_addr_t *) _key;

    check(_key);

    return (u_int) (key % dict->buckets.nitems);
}

u_int
kxld_dict_string_cmp(const void *key1, const void *key2)
{
    return streq(key1, key2);
}

u_int
kxld_dict_uint32_cmp(const void *key1, const void *key2)
{
    const uint32_t *a = key1;
    const uint32_t *b = key2;

    return (a && b && (*a == *b));
}

u_int
kxld_dict_kxldaddr_cmp(const void *key1, const void *key2)
{
    const kxld_addr_t *a = key1;
    const kxld_addr_t *b = key2;

    return (a && b && (*a == *b));
}

