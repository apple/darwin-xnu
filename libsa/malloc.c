/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
#include <vm/vm_kern.h>
#include <kern/queue.h>
#include <string.h>

#include <libsa/malloc.h>

#undef CLIENT_DEBUG


/*********************************************************************
* I'm not sure this is really necessary....
*********************************************************************/
static inline size_t round_to_long(size_t size) {
    return (size + sizeof(long int)) & ~(sizeof(long int) - 1);
}


typedef struct queue_entry queue_entry;

/*********************************************************************
* Structure for an allocation region. Each one is created using
* kmem_alloc(), and the whole list of these is destroyed by calling
* malloc_reset(). Client blocks are allocated from a linked list of these
* regions, on a first-fit basis, and are never freed.
*********************************************************************/
typedef struct malloc_region {
    queue_entry   links;         // Uses queue.h for linked list
    vm_size_t     region_size;   // total size w/ this bookeeping info

    queue_entry   block_list;    // list of allocated blocks; uses queue.h

    vm_size_t     free_size;     // size of unused area
    void        * free_address;  // points at the unused area

    char          buffer[0];     // beginning of useable area
} malloc_region;


/*********************************************************************
* Structure for a client memory block. Contains linked-list pointers,
* a size field giving the TOTAL size of the block, including this
* header, and the address of the client's block. The client block
* field is guaranteed to lie on a 16-byte boundary.
*********************************************************************/
typedef struct malloc_block {
    queue_entry     links;       // Uses queue.h for linked list
    malloc_region * region;
#ifdef CLIENT_DEBUG
    size_t         request_size;
#endif /* CLIENT_DEBUG */
    size_t         block_size;  // total size w/ all bookeeping info

    // the client's memory block
    char           buffer[0] __attribute__((aligned(16)));
} malloc_block;


/*********************************************************************
* Private functions.
*
* malloc_create_region()
*   size - The size in bytes of the region. This is rounded up
*          to a multiple of the VM page size.
*   Returns a pointer to the new region.
*
* malloc_free_region()
*   region - The region to free.
*   Returns whatever vm_deallocate() returns.
*
* malloc_create_block_in_region()
*   region - The region to alloate a block from.
*   size - The total size, including the header, of the block to
*          allocate.
*   Returns a pointer to the block, or NULL on failure.
*
* malloc_find_block()
*   address - The address of the client buffer to find a block for.
*   block (out) - The block header for the address.
*   region (out) - The region the block was found in, or NULL.
*********************************************************************/
static malloc_region * malloc_create_region(vm_size_t size);
static kern_return_t malloc_free_region(malloc_region * region);
static malloc_block * malloc_create_block_in_region(
    malloc_region * region,
    size_t size);
static void malloc_find_block(
    void * address,
    malloc_block  ** block,
    malloc_region ** region);
static void malloc_get_free_block(
    size_t size,
    malloc_block  ** block,
    malloc_region ** region);


/*********************************************************************
* Pointers to the linked list of VM-allocated regions, and a high
* water mark used in testing/debugging.
*********************************************************************/
static queue_entry malloc_region_list = {
    &malloc_region_list,   // the "next" field
    &malloc_region_list    // the "prev" field
};

static queue_entry sorted_free_block_list = {
    &sorted_free_block_list,
    &sorted_free_block_list
};

#ifdef CLIENT_DEBUG
static size_t   malloc_hiwater_mark   = 0;
static long int num_regions = 0;

static size_t   current_block_total = 0;
static double   peak_usage = 0.0;
static double   min_usage = 100.0;
#endif /* CLIENT_DEBUG */


/*********************************************************************
* malloc()
*********************************************************************/
__private_extern__
void * malloc(size_t size) {
    size_t need_size;
    malloc_region * cur_region = NULL;
    malloc_region * use_region = NULL;
    malloc_block  * client_block = NULL;
    void      * client_buffer = NULL;

   /* Add the size of the block header to the request size.
    */
    need_size = round_to_long(size + sizeof(malloc_block));


   /* See if there's a previously-freed block that we can reuse.
    */
    malloc_get_free_block(need_size,
        &client_block, &use_region);


   /* If we found a free block that we can reuse, then reuse it.
    */
    if (client_block != NULL) {

       /* Remove the found block from the list of free blocks
        * and tack it onto the list of allocated blocks.
        */
        queue_remove(&sorted_free_block_list, client_block, malloc_block *, links);
        queue_enter(&use_region->block_list, client_block, malloc_block *, links);

        client_buffer = client_block->buffer;
        // Don't return here! There's bookkeeping done below.

    } else {

       /* Didn't find a freed block to reuse. */

       /* Look for a region with enough unused space to carve out a new block.
        */
        queue_iterate(&malloc_region_list, cur_region, malloc_region *, links) {
            if (use_region == NULL && cur_region->free_size >= need_size) {
                use_region = cur_region;
                break;
            }
        }

    
       /* If we haven't found a region with room, create a new one and
        * put it at the end of the list of regions.
        */
        if (use_region == NULL) {
            use_region = malloc_create_region(need_size);
            if (use_region == NULL) {
                return NULL;
                // FIXME: panic?
            }
        }
    
       /* Create a new block in the found/created region.
        */
        client_block = malloc_create_block_in_region(use_region, need_size);
        if (client_block != NULL) {
            client_buffer = client_block->buffer;
            // Don't return here! There's bookkeeping done below.
        }
    }

#ifdef CLIENT_DEBUG
    if (client_block != NULL) {
        size_t region_usage = malloc_region_usage();
        double current_usage;

        current_block_total += client_block->block_size;
        if (region_usage > 0) {
            current_usage = (double)current_block_total / (double)malloc_region_usage();
            if (current_usage > peak_usage) {
                peak_usage = current_usage;
            }
    
            if (current_usage < min_usage) {
                min_usage = current_usage;
            }
        }

        client_block->request_size = size;
    }
#endif /* CLIENT_DEBUG */

    return client_buffer;

} /* malloc() */


/*********************************************************************
* free()
*
* Moves a block from the allocated list to the free list. Neither
* list is kept sorted!
*********************************************************************/
__private_extern__
void free(void * address) {
    malloc_region * found_region = NULL;
    malloc_block  * found_block = NULL;
    malloc_block  * cur_block = NULL;

   /* Find the block and region for the given address.
    */
    malloc_find_block(address, &found_block, &found_region);

    if (found_block == NULL) {
        return;
        // FIXME: panic?
    }


   /* Remove the found block from the list of allocated blocks
    * and tack it onto the list of free blocks.
    */
    queue_remove(&found_region->block_list, found_block, malloc_block *, links);

    found_block->links.next = NULL;
    queue_iterate(&sorted_free_block_list, cur_block, malloc_block *, links) {
        if (cur_block->block_size > found_block->block_size) {
            queue_insert_before(&sorted_free_block_list, found_block, cur_block,
                malloc_block *, links);
            break;
        }
    }


   /* If the "next" link is still NULL, then either the list is empty or the
    * freed block has to go on the end, so just tack it on.
    */
    if (found_block->links.next == NULL) {
        queue_enter(&sorted_free_block_list, found_block, malloc_block *, links);
    }


#ifdef CLIENT_DEBUG
    current_block_total -= found_block->block_size;
#endif /* CLIENT_DEBUG */

    return;

} /* free() */


/*********************************************************************
* malloc_reset()
*
* Walks through the list of VM-allocated regions, destroying them
* all. Any subsequent access by clients to allocated data will cause
* a segmentation fault.
*********************************************************************/
__private_extern__
void malloc_reset(void) {
    malloc_region * cur_region;

    while (! queue_empty(&malloc_region_list)) {
        kern_return_t kern_result;
        queue_remove_first(&malloc_region_list, cur_region,
            malloc_region *, links);
        kern_result = malloc_free_region(cur_region);
        if (kern_result != KERN_SUCCESS) {
            // what sort of error checking can we even do here?
            // printf("malloc_free_region() failed.\n");
            // panic();
        }
    }

    return;

} /* malloc_reset() */


/*********************************************************************
* realloc()
*
* This function simply allocates a new block and copies the existing
* data into it. Nothing too clever here, as cleanup and efficient
* memory usage are not important in this allocator package.
*********************************************************************/
__private_extern__
void * realloc(void * address, size_t new_client_size) {
    malloc_region * found_region = NULL;
    malloc_block  * found_block = NULL;
    void * new_address;
    size_t new_block_size;
    size_t copy_bytecount;


    malloc_find_block(address, &found_block, &found_region);


   /* If we couldn't find the requested block, 
    * the caller is in error so return NULL.
    */
    if (found_block == NULL) {
        // printf("realloc() called with invalid block.\n");
        return NULL;
        // FIXME: panic?
    }


   /* Figure out how much memory is actually needed.
    */
    new_block_size = new_client_size + sizeof(malloc_block);


   /* If the new size is <= the current size, don't bother.
    */
    if (new_block_size <= found_block->block_size) {
#ifdef CLIENT_DEBUG
        if (new_client_size > found_block->request_size) {
            found_block->request_size = new_client_size;
        }
#endif /* CLIENT_DEBUG */
        return address;
    }


   /* Create a new block of the requested size.
    */
    new_address = malloc(new_client_size);

    if (new_address == NULL) {
        // printf("error in realloc()\n");
        return NULL;
        // FIXME: panic?
    }


   /* Copy the data from the old block to the new one.
    * Make sure to copy only the lesser of the existing and
    * requested new size. (Note: The code above currently
    * screens out a realloc to a smaller size, but it might
    * not always do that.)
    */
    copy_bytecount = found_block->block_size - sizeof(malloc_block);

    if (new_client_size < copy_bytecount) {
        copy_bytecount = new_client_size;
    }

    memcpy(new_address, address, copy_bytecount);


   /* Free the old block.
    */
    free(address);

    return (void *)new_address;

} /* realloc() */


/*********************************************************************
**********************************************************************
*****           PACKAGE-INTERNAL FUNCTIONS BELOW HERE            *****
**********************************************************************
*********************************************************************/



/*********************************************************************
* malloc_create_region()
*
* Package-internal function. VM-allocates a new region and adds it to
* the given region list.
*********************************************************************/
__private_extern__
malloc_region * malloc_create_region(vm_size_t block_size) {

    malloc_region * new_region;
    vm_address_t    vm_address;
    vm_size_t       region_size;
    kern_return_t   kern_result;


   /* Figure out how big the region needs to be and allocate it.
    */
    region_size = block_size + sizeof(malloc_region);
    region_size = round_page(region_size);

    kern_result = kmem_alloc(kernel_map,
        &vm_address, region_size);

    if (kern_result != KERN_SUCCESS) {
        // printf("kmem_alloc() failed in malloc_create_region()\n");
        return NULL;
        // panic();
    }


   /* Cast the allocated pointer to a region header.
    */
    new_region = (malloc_region *)vm_address;


   /* Initialize the region header fields and link it onto
    * the previous region.
    */
    new_region->region_size = region_size;
    queue_init(&new_region->block_list);
//    queue_init(&new_region->free_list);

    new_region->free_size = region_size - sizeof(malloc_region);
    new_region->free_address = &new_region->buffer;

    queue_enter(&malloc_region_list, new_region, malloc_region *, links);

   /* If debugging, add the new region's size to the total.
    */
#ifdef CLIENT_DEBUG
    malloc_hiwater_mark += region_size;
    num_regions++;
#endif /* CLIENT_DEBUG */

    return new_region;

} /* malloc_create_region() */


/*********************************************************************
* malloc_free_region()
*
* Package-internal function. VM-deallocates the given region.
*********************************************************************/
__private_extern__
kern_return_t malloc_free_region(malloc_region * region) {

    kmem_free(kernel_map,
        (vm_address_t)region,
        region->region_size);

#ifdef CLIENT_DEBUG
    num_regions--;
#endif /* CLIENT_DEBUG */
    return KERN_SUCCESS;

} /* malloc_free_region() */


/*********************************************************************
* malloc_create_block_in_region()
*
* Package-internal function. Allocates a new block out of the given
* region. The requested size must include the block header. If the
* size requested is larger than the region's free size, returns NULL.
*********************************************************************/
__private_extern__
malloc_block * malloc_create_block_in_region(
    malloc_region * region,
    size_t block_size) {

    malloc_block * new_block = NULL;


   /* Sanity checking.
    */
    if (block_size > region->free_size) {
        return NULL;
        // FIXME: panic?
    }


   /* Carve out a new block.
    */
    new_block = (malloc_block *)region->free_address;
    region->free_address = (char *)region->free_address + block_size;
    region->free_size -= block_size;

    memset(new_block, 0, sizeof(malloc_block));

    new_block->region = region;
    new_block->block_size = block_size;

   /* Record the new block as the last one in the region.
    */
    queue_enter(&region->block_list, new_block, malloc_block *, links);

    return new_block;

} /* malloc_create_block_in_region() */


/*********************************************************************
* malloc_find_block()
*
* Package-internal function. Given a client buffer address, find the
* malloc_block for it.
*********************************************************************/
__private_extern__
void malloc_find_block(void * address,
    malloc_block ** block,
    malloc_region ** region) {

    malloc_region * cur_region;

    *block = NULL;
    *region = NULL;

    queue_iterate(&malloc_region_list, cur_region, malloc_region *, links) {

        malloc_block  * cur_block;

        queue_iterate(&cur_region->block_list, cur_block, malloc_block *, links) {
            if (cur_block->buffer == address) {
                *block = cur_block;
                *region = cur_region;
                return;
            }
        }
    }

    return;

} /* malloc_find_block() */


/*********************************************************************
* malloc_get_free_block()
*********************************************************************/
__private_extern__
void malloc_get_free_block(
    size_t size,
    malloc_block  ** block,
    malloc_region ** region) {

    malloc_block * cur_block;
    size_t fit_threshold = 512;

    *block = NULL;
    *region = NULL;

    queue_iterate(&sorted_free_block_list, cur_block, malloc_block *, links) {

       /* If we find a block large enough, but not too large to waste memory,
        * pull it out and return it, along with its region.
        */
        if (cur_block->block_size >= size &&
            cur_block->block_size < (size + fit_threshold)) {

            queue_remove(&sorted_free_block_list, cur_block, malloc_block *, links);
            *block = cur_block;
            *region = cur_block->region;
            return;
        }
    }
    return;
}
