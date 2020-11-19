/*
 * Copyright (c) 2012 Apple Inc. All rights reserved.
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

#include <stddef.h>
#include <kern/btlog.h>
#include <kern/assert.h>
#include <kern/startup.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>
#include <mach/vm_param.h>
#define _SYS_TYPES_H_
#include <libkern/crypto/md5.h>
#include <libkern/crypto/crypto_internal.h>

/*
 * Since all records are located contiguously in memory,
 * we use indices to them as the primary lookup mechanism,
 * and to maintain the linked list of active records
 * in chronological order.
 */
#define BTLOG_MAX_RECORDS (0xFFFFFF /* 16777215 */ )
#define BTLOG_RECORDINDEX_NONE (0xFFFFFF)

/*
 * Each record is a stack with a reference count and a list of
 * log elements that refer to it.
 *
 * Each log element is placed in a hash bucket that is contained
 * within the btlog structure. It contains the index to the record
 * that it references.
 *
 * So you can go from an address to the corresp. stack by hashing the address,
 * finding the hash head and traversing the chain of log elements
 * till you find the hash bucket with an address that matches your
 * address (if it exists) or creating a new bucket to hold this new address.
 */

#define ELEMENT_HASH_BUCKET_COUNT (256)
#define BTLOG_HASHELEMINDEX_NONE BTLOG_RECORDINDEX_NONE

#define ZELEMS_DEFAULT  (8000)
size_t  zelems_count = 0;

typedef uint32_t btlog_recordindex_t; /* only 24 bits used */

/*
 * Queue head for the queue of elements connected to a particular record (stack).
 * For quick removal of the oldest element referencing the least popular stack. Useful for LEAKS mode.
 */
TAILQ_HEAD(_element_record_queue, btlog_element);

/*
 * Queue head for the queue of elements that hash to the same bucket.
 * For quick removal of the oldest element ever logged.  Useful for CORRUPTION mode where we use only bucket i.e. FIFO.
 */
TAILQ_HEAD(_element_hash_queue, btlog_element);

typedef struct btlog_record {
	btlog_recordindex_t next:24,
	    operation:8;
	uint32_t            ref_count;
	uint32_t            bthash;
	struct _element_record_queue        element_record_queue;
	void                *bt[];/* variable sized, based on btlog_t params */
} btlog_record_t;

typedef struct btlog_element {
	btlog_recordindex_t     recindex:24,
	    operation:8;
	uintptr_t elem;
	TAILQ_ENTRY(btlog_element) element_record_link; /* Links to other elements pointing to the same stack. */

	TAILQ_ENTRY(btlog_element) element_hash_link; /* Links to other elements in the same hash chain.
	                                               * During LEAKS mode, this is used as a singly-linked list because
	                                               * we don't want to initialize ELEMENT_HASH_BUCKET_COUNT heads.
	                                               *
	                                               * During CORRUPTION mode with a single hash chain, this is used as a doubly-linked list.
	                                               */
} btlog_element_t;

struct btlog {
	vm_address_t    btlog_buffer;   /* all memory for this btlog_t */
	vm_size_t       btlog_buffersize;

	uintptr_t       btrecords;  /* use btlog_recordindex_t to lookup */
	size_t          btrecord_btdepth;/* BT entries per record */
	size_t          btrecord_size;

	btlog_recordindex_t head; /* active record list */
	btlog_recordindex_t tail;
	btlog_recordindex_t activerecord;
	btlog_recordindex_t freelist_records;

	size_t              active_record_count;
	size_t              active_element_count;
	btlog_element_t     *freelist_elements;
	union {
		btlog_element_t                 **elem_recindex_hashtbl; /* LEAKS mode: We use an array of ELEMENT_HASH_BUCKET_COUNT buckets. */
		struct _element_hash_queue      *element_hash_queue; /* CORRUPTION mode: We use a single hash bucket i.e. queue */
	} elem_linkage_un;

	decl_simple_lock_data(, btlog_lock);
	boolean_t   caller_will_remove_entries_for_element;/* If TRUE, this means that the caller is interested in keeping track of abandoned / leaked elements.
	                                                    * And so they want to be in charge of explicitly removing elements. Depending on this variable we
	                                                    * will choose what kind of data structure to use for the elem_linkage_un union above.
	                                                    */
};

#define lookup_btrecord(btlog, index) \
	((btlog_record_t *)(btlog->btrecords + index * btlog->btrecord_size))

uint32_t calculate_hashidx_for_element(uintptr_t elem, btlog_t *btlog);
uint32_t lookup_btrecord_byhash(btlog_t *btlog, uint32_t md5_hash, void *bt[], size_t btcount);

void btlog_add_elem_to_freelist(btlog_t *btlog, btlog_element_t *hash_elem);
btlog_element_t* btlog_get_elem_from_freelist(btlog_t *btlog);

uint32_t
lookup_btrecord_byhash(btlog_t *btlog, uint32_t md5_hash, void *bt[], size_t btcount)
{
	btlog_recordindex_t     recindex = BTLOG_RECORDINDEX_NONE;
	btlog_record_t          *record = NULL;
	size_t                  i = 0;
	boolean_t               stack_matched = TRUE;

	assert(btcount);
	assert(bt);

	recindex = btlog->head;
	record = lookup_btrecord(btlog, recindex);
	while (recindex != BTLOG_RECORDINDEX_NONE) {
		assert(!TAILQ_EMPTY(&record->element_record_queue));
		if (record->bthash == md5_hash) {
			/*
			 * Make sure that the incoming stack actually matches the
			 * stack in this record. Since we only save off a
			 * part of the md5 hash there can be collisions sometimes.
			 * This comparison isn't costly because, in case of collisions,
			 * usually the first few frames are different.
			 */

			stack_matched = TRUE;

			if (btcount < btlog->btrecord_btdepth) {
				if (record->bt[btcount] != NULL) {
					/*
					 * If the stack depth passed in is smaller than
					 * the recorded stack and we have a valid pointer
					 * in the recorded stack at that depth, then we
					 * don't need to do any further checks.
					 */
					stack_matched = FALSE;
					goto next;
				}
			}

			for (i = 0; i < MIN(btcount, btlog->btrecord_btdepth); i++) {
				if (record->bt[i] != bt[i]) {
					stack_matched = FALSE;
					goto next;
				}
			}

			if (stack_matched == TRUE) {
				break;
			}
		}
next:
		recindex = record->next;
		record = lookup_btrecord(btlog, recindex);
	}

	return recindex;
}

uint32_t
calculate_hashidx_for_element(uintptr_t elem, btlog_t *btlog)
{
	if (btlog->caller_will_remove_entries_for_element) {
		uint32_t addr = 0;

		addr = (uint32_t) ((elem & 0xFF00) >> 0x8);

		return addr;
	} else {
		return 0;
	}
}

static void
btlog_lock(btlog_t *btlog)
{
	simple_lock(&btlog->btlog_lock, LCK_GRP_NULL);
}
static void
btlog_unlock(btlog_t *btlog)
{
	simple_unlock(&btlog->btlog_lock);
}

btlog_t *
btlog_create(size_t numrecords,
    size_t record_btdepth,
    boolean_t caller_will_remove_entries_for_element)
{
	btlog_t *btlog;
	vm_size_t buffersize_needed = 0, elemsize_needed = 0;
	vm_address_t buffer = 0, elem_buffer = 0, elem_hash_buffer = 0;
	size_t i = 0;
	kern_return_t ret;
	size_t btrecord_size = 0;
	uintptr_t free_elem = 0, next_free_elem = 0;

	if (startup_phase >= STARTUP_SUB_VM_KERNEL &&
	    startup_phase < STARTUP_SUB_KMEM_ALLOC) {
		return NULL;
	}

	if (numrecords > BTLOG_MAX_RECORDS) {
		return NULL;
	}

	if (numrecords == 0) {
		return NULL;
	}

	if (record_btdepth > BTLOG_MAX_DEPTH) {
		return NULL;
	}

	/* btlog_record_t is variable-sized, calculate needs now */
	btrecord_size = sizeof(btlog_record_t)
	    + sizeof(void *) * record_btdepth;

	buffersize_needed = sizeof(btlog_t) + numrecords * btrecord_size;
	buffersize_needed = round_page(buffersize_needed);

	if (zelems_count == 0) {
		zelems_count = ((max_mem + (1024 * 1024 * 1024) /*GB*/) >> 30) * ZELEMS_DEFAULT;

		if (PE_parse_boot_argn("zelems", &zelems_count, sizeof(zelems_count)) == TRUE) {
			/*
			 * Need a max? With this scheme, it should be possible to tune the default
			 * so that we don't need a boot-arg to request more elements.
			 */
			printf("Set number of log elements per btlog to: %ld\n", zelems_count);
		}
	}
	elemsize_needed = sizeof(btlog_element_t) * zelems_count;
	elemsize_needed = round_page(elemsize_needed);

	/* since rounding to a page size might hold more, recalculate */
	numrecords = MIN(BTLOG_MAX_RECORDS,
	    (buffersize_needed - sizeof(btlog_t)) / btrecord_size);

	if (__probable(startup_phase >= STARTUP_SUB_KMEM_ALLOC)) {
		ret = kmem_alloc(kernel_map, &buffer, buffersize_needed, VM_KERN_MEMORY_DIAG);
		if (ret != KERN_SUCCESS) {
			return NULL;
		}

		ret = kmem_alloc(kernel_map, &elem_buffer, elemsize_needed, VM_KERN_MEMORY_DIAG);
		if (ret != KERN_SUCCESS) {
			kmem_free(kernel_map, buffer, buffersize_needed);
			buffer = 0;
			return NULL;
		}

		if (caller_will_remove_entries_for_element == TRUE) {
			ret = kmem_alloc(kernel_map, &elem_hash_buffer, ELEMENT_HASH_BUCKET_COUNT * sizeof(btlog_element_t*), VM_KERN_MEMORY_DIAG);
		} else {
			ret = kmem_alloc(kernel_map, &elem_hash_buffer, 2 * sizeof(btlog_element_t*), VM_KERN_MEMORY_DIAG);
		}

		if (ret != KERN_SUCCESS) {
			kmem_free(kernel_map, buffer, buffersize_needed);
			buffer = 0;

			kmem_free(kernel_map, elem_buffer, elemsize_needed);
			elem_buffer = 0;
			return NULL;
		}
	} else {
		buffer = (vm_address_t)pmap_steal_memory(buffersize_needed);
		elem_buffer = (vm_address_t)pmap_steal_memory(elemsize_needed);
		if (caller_will_remove_entries_for_element == TRUE) {
			elem_hash_buffer = (vm_address_t)pmap_steal_memory(ELEMENT_HASH_BUCKET_COUNT * sizeof(btlog_element_t*));
		} else {
			elem_hash_buffer = (vm_address_t)pmap_steal_memory(2 * sizeof(btlog_element_t*));
		}
		ret = KERN_SUCCESS;
	}

	btlog = (btlog_t *)buffer;
	btlog->btlog_buffer = buffer;
	btlog->btlog_buffersize = buffersize_needed;
	btlog->freelist_elements = (btlog_element_t *)elem_buffer;

	simple_lock_init(&btlog->btlog_lock, 0);

	btlog->caller_will_remove_entries_for_element = caller_will_remove_entries_for_element;

	if (caller_will_remove_entries_for_element == TRUE) {
		btlog->elem_linkage_un.elem_recindex_hashtbl = (btlog_element_t **)elem_hash_buffer;
	} else {
		btlog->elem_linkage_un.element_hash_queue = (struct _element_hash_queue*) elem_hash_buffer;
		TAILQ_INIT(btlog->elem_linkage_un.element_hash_queue);
	}

	btlog->btrecords = (uintptr_t)(buffer + sizeof(btlog_t));
	btlog->btrecord_btdepth = record_btdepth;
	btlog->btrecord_size = btrecord_size;

	btlog->head = BTLOG_RECORDINDEX_NONE;
	btlog->tail = BTLOG_RECORDINDEX_NONE;
	btlog->active_record_count = 0;
	btlog->activerecord = BTLOG_RECORDINDEX_NONE;

	for (i = 0; i < ELEMENT_HASH_BUCKET_COUNT; i++) {
		btlog->elem_linkage_un.elem_recindex_hashtbl[i] = 0;
	}

	/* populate freelist_records with all records in order */
	btlog->freelist_records = 0;
	for (i = 0; i < (numrecords - 1); i++) {
		btlog_record_t *rec = lookup_btrecord(btlog, i);
		rec->next = (btlog_recordindex_t)(i + 1);
	}
	lookup_btrecord(btlog, i)->next = BTLOG_RECORDINDEX_NONE; /* terminate */

	/* populate freelist_elements with all elements in order */
	free_elem = (uintptr_t)btlog->freelist_elements;

	for (i = 0; i < (zelems_count - 1); i++) {
		next_free_elem = free_elem + sizeof(btlog_element_t);
		*(uintptr_t*)free_elem = next_free_elem;
		free_elem = next_free_elem;
	}
	*(uintptr_t*)next_free_elem = BTLOG_HASHELEMINDEX_NONE;

	return btlog;
}

/* Assumes btlog is already locked */
static btlog_recordindex_t
btlog_get_record_from_freelist(btlog_t *btlog)
{
	btlog_recordindex_t     recindex = btlog->freelist_records;

	if (recindex == BTLOG_RECORDINDEX_NONE) {
		/* nothing on freelist */
		return BTLOG_RECORDINDEX_NONE;
	} else {
		/* remove the head of the freelist_records */
		btlog_record_t *record = lookup_btrecord(btlog, recindex);
		btlog->freelist_records = record->next;
		return recindex;
	}
}

static void
btlog_add_record_to_freelist(btlog_t *btlog, btlog_recordindex_t recindex)
{
	btlog_recordindex_t precindex = BTLOG_RECORDINDEX_NONE;
	btlog_record_t *precord = NULL, *record = NULL;

	record = lookup_btrecord(btlog, recindex);

	assert(TAILQ_EMPTY(&record->element_record_queue));

	record->bthash = 0;

	precindex = btlog->head;
	precord = lookup_btrecord(btlog, precindex);

	if (precindex == recindex) {
		btlog->head = precord->next;
		btlog->active_record_count--;

		record->next = btlog->freelist_records;
		btlog->freelist_records = recindex;

		if (btlog->head == BTLOG_RECORDINDEX_NONE) {
			/* active list is now empty, update tail */
			btlog->tail = BTLOG_RECORDINDEX_NONE;
			assert(btlog->active_record_count == 0);
		}
	} else {
		while (precindex != BTLOG_RECORDINDEX_NONE) {
			if (precord->next == recindex) {
				precord->next = record->next;
				btlog->active_record_count--;

				record->next = btlog->freelist_records;
				btlog->freelist_records = recindex;

				if (btlog->tail == recindex) {
					btlog->tail = precindex;
				}
				break;
			} else {
				precindex = precord->next;
				precord = lookup_btrecord(btlog, precindex);
			}
		}
	}
}


/* Assumes btlog is already locked */
static void
btlog_evict_elements_from_record(btlog_t *btlog, int num_elements_to_evict)
{
	btlog_recordindex_t     recindex = btlog->head;
	btlog_record_t          *record = NULL;
	btlog_element_t         *recelem = NULL;

	if (recindex == BTLOG_RECORDINDEX_NONE) {
		/* nothing on active list */
		panic("BTLog: Eviction requested on btlog (0x%lx) with an empty active list.\n", (uintptr_t) btlog);
	} else {
		while (num_elements_to_evict) {
			/*
			 * LEAKS: reap the oldest element within the record with the lowest refs.
			 * CORRUPTION: reap the oldest element overall and drop its reference on the record
			 */

			if (btlog->caller_will_remove_entries_for_element) {
				uint32_t                max_refs_threshold = UINT32_MAX;
				btlog_recordindex_t     precindex = 0, prev_evictindex = 0, evict_index = 0;

				prev_evictindex = evict_index = btlog->head;
				precindex = recindex = btlog->head;

				while (recindex != BTLOG_RECORDINDEX_NONE) {
					record  = lookup_btrecord(btlog, recindex);

					if (btlog->activerecord == recindex || record->ref_count > max_refs_threshold) {
						/* skip this record */
					} else {
						prev_evictindex = precindex;
						evict_index = recindex;
						max_refs_threshold = record->ref_count;
					}

					if (record->next != BTLOG_RECORDINDEX_NONE) {
						precindex = recindex;
					}

					recindex = record->next;
				}

				recindex = evict_index;
				assert(recindex != BTLOG_RECORDINDEX_NONE);
				record  = lookup_btrecord(btlog, recindex);

				recelem = TAILQ_LAST(&record->element_record_queue, _element_record_queue);
			} else {
				recelem = TAILQ_LAST(btlog->elem_linkage_un.element_hash_queue, _element_hash_queue);
				recindex = recelem->recindex;
				record = lookup_btrecord(btlog, recindex);
			}

			/*
			 * Here we have the element to drop (recelem), its record and the record index.
			 */

			while (recelem && num_elements_to_evict) {
				TAILQ_REMOVE(&record->element_record_queue, recelem, element_record_link);

				if (btlog->caller_will_remove_entries_for_element) {
					btlog_element_t *prev_hashelem = NULL, *hashelem = NULL;
					uint32_t                        hashidx = 0;

					hashidx = calculate_hashidx_for_element(~recelem->elem, btlog);

					prev_hashelem = hashelem = btlog->elem_linkage_un.elem_recindex_hashtbl[hashidx];
					while (hashelem != NULL) {
						if (hashelem == recelem) {
							break;
						} else {
							prev_hashelem = hashelem;
							hashelem = TAILQ_NEXT(hashelem, element_hash_link);
						}
					}

					if (hashelem == NULL) {
						panic("BTLog: Missing hashelem for element list of record 0x%lx\n", (uintptr_t) record);
					}

					if (prev_hashelem != hashelem) {
						TAILQ_NEXT(prev_hashelem, element_hash_link) = TAILQ_NEXT(hashelem, element_hash_link);
					} else {
						btlog->elem_linkage_un.elem_recindex_hashtbl[hashidx] = TAILQ_NEXT(hashelem, element_hash_link);
					}
				} else {
					TAILQ_REMOVE(btlog->elem_linkage_un.element_hash_queue, recelem, element_hash_link);
				}

				btlog_add_elem_to_freelist(btlog, recelem);
				btlog->active_element_count--;

				num_elements_to_evict--;

				assert(record->ref_count);

				record->ref_count--;

				if (record->ref_count == 0) {
					btlog_add_record_to_freelist(btlog, recindex);

					/*
					 * LEAKS: All done with this record. Need the next least popular record.
					 * CORRUPTION: We don't care about records. We'll just pick the next oldest element.
					 */

					if (btlog->caller_will_remove_entries_for_element) {
						break;
					}
				}

				if (btlog->caller_will_remove_entries_for_element) {
					recelem = TAILQ_LAST(&record->element_record_queue, _element_record_queue);
				} else {
					recelem = TAILQ_LAST(btlog->elem_linkage_un.element_hash_queue, _element_hash_queue);
					recindex = recelem->recindex;
					record = lookup_btrecord(btlog, recindex);
				}
			}
		}
	}
}

/* Assumes btlog is already locked */
static void
btlog_append_record_to_activelist(btlog_t *btlog, btlog_recordindex_t recindex)
{
	assert(recindex != BTLOG_RECORDINDEX_NONE);

	if (btlog->head == BTLOG_RECORDINDEX_NONE) {
		/* empty active list, update both head and tail */
		btlog->head = btlog->tail = recindex;
	} else {
		btlog_record_t *record = lookup_btrecord(btlog, btlog->tail);
		record->next = recindex;
		btlog->tail = recindex;
	}
	btlog->active_record_count++;
}

btlog_element_t*
btlog_get_elem_from_freelist(btlog_t *btlog)
{
	btlog_element_t *free_elem = NULL;

retry:
	free_elem = btlog->freelist_elements;

	if ((uintptr_t)free_elem == BTLOG_HASHELEMINDEX_NONE) {
		/* nothing on freelist */
		btlog_evict_elements_from_record(btlog, 1);
		goto retry;
	} else {
		/* remove the head of the freelist */
		uintptr_t next_elem = *(uintptr_t*)free_elem;
		btlog->freelist_elements = (btlog_element_t *)next_elem;
		return free_elem;
	}
}

void
btlog_add_elem_to_freelist(btlog_t *btlog, btlog_element_t *elem)
{
	btlog_element_t *free_elem = btlog->freelist_elements;

	TAILQ_NEXT(elem, element_hash_link) = (btlog_element_t *) BTLOG_HASHELEMINDEX_NONE;
	TAILQ_NEXT(elem, element_record_link) = (btlog_element_t *) BTLOG_HASHELEMINDEX_NONE;

	*(uintptr_t*)elem = (uintptr_t)free_elem;
	btlog->freelist_elements = elem;
}

void
btlog_add_entry(btlog_t *btlog,
    void *element,
    uint8_t operation,
    void *bt[],
    size_t btcount)
{
	btlog_recordindex_t     recindex = 0;
	btlog_record_t          *record = NULL;
	size_t                  i;
	u_int32_t               md5_buffer[4];
	MD5_CTX                 btlog_ctx;
	uint32_t                hashidx = 0;

	btlog_element_t *hashelem = NULL;

	if (g_crypto_funcs == NULL) {
		return;
	}

	btlog_lock(btlog);

	MD5Init(&btlog_ctx);
	for (i = 0; i < MIN(btcount, btlog->btrecord_btdepth); i++) {
		MD5Update(&btlog_ctx, (u_char *) &bt[i], sizeof(bt[i]));
	}
	MD5Final((u_char *) &md5_buffer, &btlog_ctx);

	recindex = lookup_btrecord_byhash(btlog, md5_buffer[0], bt, btcount);

	if (recindex != BTLOG_RECORDINDEX_NONE) {
		record = lookup_btrecord(btlog, recindex);
		record->ref_count++;
		assert(record->operation == operation);
	} else {
retry:
		/* If there's a free record, use it */
		recindex = btlog_get_record_from_freelist(btlog);
		if (recindex == BTLOG_RECORDINDEX_NONE) {
			/* Use the first active record (FIFO age-out) */
			btlog_evict_elements_from_record(btlog, ((2 * sizeof(btlog_record_t)) / sizeof(btlog_element_t)));
			goto retry;
		}

		record = lookup_btrecord(btlog, recindex);

		/* we always add to the tail, so there is no next pointer */
		record->next = BTLOG_RECORDINDEX_NONE;
		record->operation = operation;
		record->bthash = md5_buffer[0];
		record->ref_count = 1;
		TAILQ_INIT(&record->element_record_queue);

		for (i = 0; i < MIN(btcount, btlog->btrecord_btdepth); i++) {
			record->bt[i] = bt[i];
		}

		for (; i < btlog->btrecord_btdepth; i++) {
			record->bt[i] = NULL;
		}

		btlog_append_record_to_activelist(btlog, recindex);
	}

	btlog->activerecord = recindex;

	hashidx = calculate_hashidx_for_element((uintptr_t)element, btlog);
	hashelem = btlog_get_elem_from_freelist(btlog);

	hashelem->elem = ~((uintptr_t)element);
	hashelem->operation = record->operation;
	hashelem->recindex = recindex;

	TAILQ_INSERT_HEAD(&record->element_record_queue, hashelem, element_record_link);

	if (btlog->caller_will_remove_entries_for_element) {
		TAILQ_NEXT(hashelem, element_hash_link) = btlog->elem_linkage_un.elem_recindex_hashtbl[hashidx];
		btlog->elem_linkage_un.elem_recindex_hashtbl[hashidx] = hashelem;
	} else {
		TAILQ_INSERT_HEAD(btlog->elem_linkage_un.element_hash_queue, hashelem, element_hash_link);
	}

	btlog->active_element_count++;

	btlog->activerecord = BTLOG_RECORDINDEX_NONE;

	btlog_unlock(btlog);
}

void
btlog_remove_entries_for_element(btlog_t *btlog,
    void *element)
{
	btlog_recordindex_t     recindex = BTLOG_RECORDINDEX_NONE;
	btlog_record_t          *record = NULL;
	uint32_t                hashidx = 0;

	btlog_element_t *prev_hashelem = NULL, *hashelem = NULL;

	if (btlog->caller_will_remove_entries_for_element == FALSE) {
		panic("Explicit removal of entry is not permitted for this btlog (%p).\n", btlog);
	}

	if (g_crypto_funcs == NULL) {
		return;
	}

	btlog_lock(btlog);

	hashidx = calculate_hashidx_for_element((uintptr_t) element, btlog);
	prev_hashelem = hashelem = btlog->elem_linkage_un.elem_recindex_hashtbl[hashidx];

	while (hashelem != NULL) {
		if (~hashelem->elem == (uintptr_t)element) {
			break;
		} else {
			prev_hashelem = hashelem;
			hashelem = TAILQ_NEXT(hashelem, element_hash_link);
		}
	}

	if (hashelem) {
		btlog_element_t *recelem = NULL;

		if (prev_hashelem != hashelem) {
			TAILQ_NEXT(prev_hashelem, element_hash_link) = TAILQ_NEXT(hashelem, element_hash_link);
		} else {
			btlog->elem_linkage_un.elem_recindex_hashtbl[hashidx] = TAILQ_NEXT(hashelem, element_hash_link);
		}

		recindex = hashelem->recindex;
		record = lookup_btrecord(btlog, recindex);

		recelem = hashelem;
		TAILQ_REMOVE(&record->element_record_queue, recelem, element_record_link);

		btlog_add_elem_to_freelist(btlog, hashelem);
		btlog->active_element_count--;

		assert(record->ref_count);

		record->ref_count--;

		if (record->ref_count == 0) {
			btlog_add_record_to_freelist(btlog, recindex);
		}
	}

	btlog_unlock(btlog);
}

#if DEBUG || DEVELOPMENT

void
btlog_copy_backtraces_for_elements(btlog_t      * btlog,
    uintptr_t    * instances,
    uint32_t     * countp,
    uint32_t       zoneSize,
    leak_site_proc proc,
    void         * refCon)
{
	btlog_recordindex_t       recindex;
	btlog_record_t          * record;
	btlog_element_t     * hashelem;
	uint32_t                      hashidx, idx, dups, numSites, siteCount;
	uintptr_t             element, site;
	uint32_t              count;

	btlog_lock(btlog);

	count = *countp;
	for (numSites = 0, idx = 0; idx < count; idx++) {
		element = instances[idx];

		if (kInstanceFlagReferenced & element) {
			continue;
		}
		element = INSTANCE_PUT(element) & ~kInstanceFlags;

		site = 0;
		hashidx = calculate_hashidx_for_element(element, btlog);
		hashelem = btlog->elem_linkage_un.elem_recindex_hashtbl[hashidx];
		while (hashelem != NULL) {
			if (~hashelem->elem == element) {
				break;
			}
			hashelem = TAILQ_NEXT(hashelem, element_hash_link);
		}
		if (hashelem) {
			recindex = hashelem->recindex;
			site = (uintptr_t) lookup_btrecord(btlog, recindex);
		}
		if (site) {
			element = (site | kInstanceFlagReferenced);
		}
		instances[numSites] = INSTANCE_PUT(element);
		numSites++;
	}

	for (idx = 0; idx < numSites; idx++) {
		site = instances[idx];
		if (!site) {
			continue;
		}
		if (!(kInstanceFlagReferenced & site)) {
			continue;
		}
		for (siteCount = 1, dups = (idx + 1); dups < numSites; dups++) {
			if (instances[dups] == site) {
				siteCount++;
				instances[dups] = 0;
			}
		}
		record = (typeof(record))(INSTANCE_PUT(site) & ~kInstanceFlags);
		(*proc)(refCon, siteCount, zoneSize, (uintptr_t *) &record->bt[0], (uint32_t) btlog->btrecord_btdepth);
	}

	*countp = numSites;

	btlog_unlock(btlog);
}

/*
 * Returns the number of records in the btlog struct.
 *
 * Called by the mach_zone_get_btlog_records() MIG routine.
 */
size_t
get_btlog_records_count(btlog_t *btlog)
{
	if (btlog->btlog_buffersize < sizeof(btlog_t)) {
		return 0;
	}
	return (btlog->btlog_buffersize - sizeof(btlog_t)) / btlog->btrecord_size;
}

/*
 * Copies out relevant info from btlog_record_t's to zone_btrecord_t's. 'numrecs' points to the number of records
 * the 'records' buffer can hold. Upon return 'numrecs' points to the number of records actually copied out.
 *
 * Called by the mach_zone_get_btlog_records() MIG routine.
 */
void
get_btlog_records(btlog_t *btlog, zone_btrecord_t *records, unsigned int *numrecs)
{
	unsigned int count, recs_copied, frame;
	zone_btrecord_t *current_rec;
	btlog_record_t *zstack_record;
	btlog_recordindex_t     zstack_index = BTLOG_RECORDINDEX_NONE;

	btlog_lock(btlog);

	count = 0;
	if (btlog->btlog_buffersize > sizeof(btlog_t)) {
		count = (unsigned int)((btlog->btlog_buffersize - sizeof(btlog_t)) / btlog->btrecord_size);
	}
	/* Copy out only as many records as the pre-allocated buffer size permits. */
	if (count > *numrecs) {
		count = *numrecs;
	}
	zstack_index = btlog->head;

	current_rec = &records[0];
	recs_copied = 0;
	while (recs_copied < count && (zstack_index != BTLOG_RECORDINDEX_NONE)) {
		zstack_record = lookup_btrecord(btlog, zstack_index);
		current_rec->operation_type = (uint32_t)(zstack_record->operation);
		current_rec->ref_count = zstack_record->ref_count;

		frame = 0;
		while (frame < MIN(btlog->btrecord_btdepth, MAX_ZTRACE_DEPTH)) {
			current_rec->bt[frame] = (uint64_t)VM_KERNEL_UNSLIDE(zstack_record->bt[frame]);
			frame++;
		}

		zstack_index = zstack_record->next;
		recs_copied++;
		current_rec++;
	}
	*numrecs = recs_copied;

	btlog_unlock(btlog);
}

#endif  /* DEBUG || DEVELOPMENT */
