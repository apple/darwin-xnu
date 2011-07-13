/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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

#if KERNEL
    #include <mach/vm_param.h>
#else
    #include <mach/mach_init.h>
#endif

#define DEBUG_ASSERT_COMPONENT_NAME_STRING "kxld"
#include <AssertMacros.h>

#include "kxld_array.h"
#include "kxld_util.h"

static kern_return_t array_init(KXLDArray *array, size_t itemsize, u_int nitems);
static KXLDArrayPool * pool_create(size_t capacity);
static void pool_destroy(KXLDArrayPool *pool, size_t capacity);
static u_int reinit_pools(KXLDArray *array, u_int nitems);

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_array_init(KXLDArray *array, size_t itemsize, u_int nitems)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDArrayPool *dstpool = NULL, *srcpool = NULL, *tmp = NULL;
    KXLDArrayHead srcpools = STAILQ_HEAD_INITIALIZER(srcpools);
    size_t srcpool_capacity = 0;
    u_long offset = 0;

    check(array);

    if (!nitems) {
        kxld_array_reset(array);
        rval = KERN_SUCCESS;
        goto finish;
    }

    require_action(itemsize, finish, rval=KERN_INVALID_ARGUMENT);

    /* If the array has some pools, we need to see if there is enough space in
     * those pools to accomodate the requested size array.  If there isn't
     * enough space, we save the existing pools to a temporary STAILQ and zero
     * out the array structure.  This will cause a new pool of sufficient size
     * to be created, and we then copy the data from the old pools into the new
     * pool.
     */
    if (array->npools) {
        /* Update the array's maxitems based on the new itemsize */
        array->pool_maxitems = (u_int) (array->pool_capacity / itemsize);
        array->maxitems = 0;
        STAILQ_FOREACH(srcpool, &array->pools, entries) {
            array->maxitems += array->pool_maxitems;
        }

        /* If there's not enough space, save the pools to a temporary STAILQ
         * and zero out the array structure.  Otherwise, rescan the pools to
         * update their internal nitems counts.
         */
        if (array->maxitems < nitems) {
            STAILQ_FOREACH_SAFE(srcpool, &array->pools, entries, tmp) {
                STAILQ_REMOVE(&array->pools, srcpool, kxld_array_pool, entries);
                STAILQ_INSERT_TAIL(&srcpools, srcpool, entries);
            }
            srcpool_capacity = array->pool_capacity;
            bzero(array, sizeof(*array));
        } else {
            nitems = reinit_pools(array, nitems);
            require_action(nitems == 0, finish, rval=KERN_FAILURE);
        }
    } 
            
    array->itemsize = itemsize;

    /* If array->maxitems is zero, it means we are either rebuilding an array
     * that was too small, or we're initializing an array for the first time.
     * In either case, we need to set up a pool of the requested size, and
     * if we're rebuilding an old array, we'll also copy the data from the old
     * pools into the new pool.
     */
    if (array->maxitems == 0) {

        rval = array_init(array, itemsize, nitems);
        require_noerr(rval, finish);

        dstpool = STAILQ_FIRST(&array->pools);
        require_action(dstpool, finish, rval=KERN_FAILURE);

        STAILQ_FOREACH_SAFE(srcpool, &srcpools, entries, tmp) {
            memcpy(dstpool->buffer + offset, srcpool->buffer, srcpool_capacity);
            offset += srcpool_capacity;

            STAILQ_REMOVE(&srcpools, srcpool, kxld_array_pool, entries);
            pool_destroy(srcpool, srcpool_capacity);
        }

    }

    rval = KERN_SUCCESS;
finish:
    if (rval) kxld_array_deinit(array);
    return rval;
}

/*******************************************************************************
* This may only be called to initialize (or reinitialize) an array with exactly
* zero or one pool.  Calling this on an array with more than one pool is an
* error.
*******************************************************************************/
static kern_return_t
array_init(KXLDArray *array, size_t itemsize, u_int nitems)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDArrayPool *pool = NULL;
    
    require_action(itemsize, finish, rval=KERN_INVALID_ARGUMENT);
    require_action(array->npools < 2, finish, rval=KERN_INVALID_ARGUMENT);
 
    array->itemsize = itemsize;

    pool = STAILQ_FIRST(&array->pools);
    if (pool) {
        require_action(itemsize * nitems < array->pool_capacity,
            finish, rval=KERN_FAILURE);
        require_action(array->npools == 1, finish, rval=KERN_FAILURE);
        bzero(pool->buffer, array->pool_capacity);
    } else {
        array->pool_capacity = round_page(array->itemsize * nitems);

        pool = pool_create(array->pool_capacity);
        require_action(pool, finish, rval=KERN_RESOURCE_SHORTAGE);
        STAILQ_INSERT_HEAD(&array->pools, pool, entries);
    }
    pool->nitems = nitems;

    array->pool_maxitems = (u_int) (array->pool_capacity / array->itemsize);
    array->maxitems = array->pool_maxitems;
    array->nitems = nitems;
    array->npools = 1;

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static KXLDArrayPool *
pool_create(size_t capacity)
{
    KXLDArrayPool *pool = NULL, *rval = NULL;

    pool = kxld_alloc(sizeof(*pool));
    require(pool, finish);

    pool->buffer = kxld_page_alloc(capacity);
    require(pool->buffer, finish);
    bzero(pool->buffer, capacity);

    rval = pool;
    pool = NULL;

finish:
    if (pool) pool_destroy(pool, capacity);
    return rval;
}

/*******************************************************************************
*******************************************************************************/
static void
pool_destroy(KXLDArrayPool *pool, size_t capacity)
{
    if (pool) {
        if (pool->buffer) kxld_page_free(pool->buffer, capacity);
        kxld_free(pool, sizeof(*pool));
    }
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_array_copy(KXLDArray *dstarray, const KXLDArray *srcarray)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDArrayPool *dstpool = NULL, *srcpool = NULL;
    u_long needed_capacity = 0;
    u_long current_capacity = 0;
    u_long copysize = 0;
    u_long offset = 0;

    check(dstarray);
    check(srcarray);

    /* When copying array, we only want to copy to an array with a single
     * pool.  If the array has more than one pool or the array is too small,
     * we destroy the array and build it from scratch for the copy.
     */
    needed_capacity = round_page(srcarray->nitems * srcarray->itemsize);
    current_capacity = dstarray->npools * dstarray->pool_capacity;
    if (dstarray->npools > 1 || needed_capacity > current_capacity) {
        kxld_array_deinit(dstarray);
    }

    rval = array_init(dstarray, srcarray->itemsize, srcarray->nitems);
    require_noerr(rval, finish);

    dstpool = STAILQ_FIRST(&dstarray->pools);
    require_action(dstpool, finish, rval=KERN_FAILURE);

    /* Copy the data from the source pools to the single destination pool. */
    STAILQ_FOREACH(srcpool, &srcarray->pools, entries) {
        copysize = srcpool->nitems * srcarray->itemsize;
        memcpy(dstpool->buffer + offset, srcpool->buffer, copysize);
        offset += copysize;
    }

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
void 
kxld_array_reset(KXLDArray *array)
{
    KXLDArrayPool *pool = NULL;

    if (array) {
        STAILQ_FOREACH(pool, &array->pools, entries) {
            pool->nitems = 0;
        }
        array->nitems = 0;
    }
}

/*******************************************************************************
*******************************************************************************/
void 
kxld_array_clear(KXLDArray *array)
{
    KXLDArrayPool *pool = NULL;

    if (array) {
        kxld_array_reset(array);
        STAILQ_FOREACH(pool, &array->pools, entries) {
            bzero(pool->buffer, array->pool_capacity);
        }
    }
}

/*******************************************************************************
*******************************************************************************/
void 
kxld_array_deinit(KXLDArray *array)
{
    KXLDArrayPool *pool = NULL, *tmp = NULL;

    if (array) {
        STAILQ_FOREACH_SAFE(pool, &array->pools, entries, tmp) {
            STAILQ_REMOVE(&array->pools, pool, kxld_array_pool, entries);
            pool_destroy(pool, array->pool_capacity);
        }
        bzero(array, sizeof(*array));
    }
}

/*******************************************************************************
*******************************************************************************/
void *
kxld_array_get_item(const KXLDArray *array, u_int idx)
{
    KXLDArrayPool *pool = NULL;
    void *item = NULL;

    check(array);

    if (idx >= array->nitems) goto finish;

    STAILQ_FOREACH(pool, &array->pools, entries) {
        if (idx < pool->nitems) {
            item = (void *) (pool->buffer + (array->itemsize * idx));
            break;
        }
            
        idx -= array->pool_maxitems;
    }

finish:
    return item;
}

/*******************************************************************************
*******************************************************************************/
void *
kxld_array_get_slot(const KXLDArray *array, u_int idx)
{
    KXLDArrayPool *pool = NULL;
    void *item = NULL;

    check(array);

    if (idx >= array->maxitems) goto finish;

    STAILQ_FOREACH(pool, &array->pools, entries) {
        if (idx < array->pool_maxitems) {
            item = (void *) (pool->buffer + (array->itemsize * idx));
            break;
        }
            
        idx -= array->pool_maxitems;
    }

finish:
    return item;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_array_get_index(const KXLDArray *array, const void *item, u_int *_idx)
{ 
    kern_return_t rval = KERN_FAILURE;
    KXLDArrayPool *pool = NULL;
    u_long diff = 0;
    u_int idx = 0;
    u_int base_idx = 0;
    const u_char *it;

    check(array);
    check(item);
    check(_idx);

    it = item;

    STAILQ_FOREACH(pool, &array->pools, entries) {
        if (pool->buffer <= it && it < pool->buffer + array->pool_capacity) {
            diff = it - pool->buffer;
            idx = (u_int) (diff / array->itemsize);

            idx += base_idx;
            *_idx = idx;

            rval = KERN_SUCCESS;
            goto finish;
        }

        base_idx += array->pool_maxitems;
    }

    rval = KERN_FAILURE;
finish:
    return rval;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t 
kxld_array_resize(KXLDArray *array, u_int nitems)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDArrayPool *pool = NULL;

    /* Grow the list of pools until we have enough to fit all of the entries */

    while (nitems > array->maxitems) {
        pool = pool_create(array->pool_capacity);
        require_action(pool, finish, rval=KERN_FAILURE);

        STAILQ_INSERT_TAIL(&array->pools, pool, entries);

        array->maxitems += array->pool_maxitems;
        array->npools += 1;
    }

    nitems = reinit_pools(array, nitems);
    require_action(nitems == 0, finish, rval=KERN_FAILURE);

    rval = KERN_SUCCESS;
finish:
    return rval;
}

/*******************************************************************************
* Sets the number of items for the array and each pool.  Returns zero if there
* is enough space for all items, and the number of additional items needed
* if there is not enough space.
*******************************************************************************/
static u_int
reinit_pools(KXLDArray *array, u_int nitems)
{
    KXLDArrayPool *pool = NULL;
    u_int pool_nitems = 0;

    /* Set the number of items for each pool */

    pool_nitems = nitems;
    STAILQ_FOREACH(pool, &array->pools, entries) {
        if (pool_nitems > array->pool_maxitems) {
            pool->nitems = array->pool_maxitems;
            pool_nitems -= array->pool_maxitems;
        } else {
            pool->nitems = pool_nitems;
            pool_nitems = 0;
        }
    }
    array->nitems = nitems;

    return pool_nitems;
}

/*******************************************************************************
*******************************************************************************/
kern_return_t
kxld_array_remove(KXLDArray *array, u_int idx)
{
    kern_return_t rval = KERN_FAILURE;
    KXLDArrayPool *pool = NULL;
    u_char *dst = NULL;
    u_char *src = NULL;
    u_int nitems = 0;

    check(array);

    if (idx >= array->nitems) {
        rval = KERN_SUCCESS;
        goto finish;
    }

    /* We only support removing an item if all the items are contained in a
     * single pool (for now).
     */
    require_action(array->npools < 2 || array->nitems < array->pool_maxitems, 
        finish, rval=KERN_NOT_SUPPORTED);

    pool = STAILQ_FIRST(&array->pools);
    require_action(pool, finish, rval=KERN_FAILURE);

    dst = pool->buffer;
    dst += idx * array->itemsize;

    src = pool->buffer;
    src += ((idx + 1) * array->itemsize);

    nitems = pool->nitems - idx - 1;
    memmove(dst, src, array->itemsize * nitems);

    --pool->nitems;
    --array->nitems;
 
    dst = pool->buffer;
    dst += pool->nitems * array->itemsize;
    bzero(dst, array->itemsize);

    rval = KERN_SUCCESS;
finish:
    return rval;
}

