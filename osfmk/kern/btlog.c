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
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/pmap.h>
#include <mach/vm_param.h>

/*
 * Since all records are located contiguously in memory,
 * we use indices to them as the primary lookup mechanism,
 * and to maintain the linked list of active records
 * in chronological order.
 */
typedef uint32_t btlog_recordindex_t; /* only 24 bits used */
#define BTLOG_RECORDINDEX_NONE (0xFFFFFF)
#define BTLOG_MAX_RECORDS (0xFFFFFF /* 16777215 */)

typedef struct btlog_record {
    btlog_recordindex_t next:24;
    uint8_t         operation;
#if __LP64__
    uint32_t        _pad;
#endif
    void           *element;
    void           *bt[]; /* variable sized, based on btlog_t params */
} btlog_record_t;

struct btlog {
    vm_address_t    btlog_buffer;       /* all memory for this btlog_t */
    vm_size_t       btlog_buffersize;

    btlog_lock_t    lock_callback;      /* caller-provided locking */
    btlog_unlock_t  unlock_callback;
    void           *callback_context;

    uintptr_t       btrecords;      /* use btlog_recordindex_t to lookup */
    size_t          btrecord_count;
    size_t          btrecord_btdepth; /* BT entries per record */
    size_t          btrecord_size;

    btlog_recordindex_t head; /* active record list */
    btlog_recordindex_t tail;
    size_t          activecount;

    btlog_recordindex_t freelist;
};

extern boolean_t vm_kernel_ready;
extern boolean_t kmem_alloc_ready;

#define lookup_btrecord(btlog, index) \
	((btlog_record_t *)(btlog->btrecords + index * btlog->btrecord_size))

btlog_t *
btlog_create(size_t numrecords,
			 size_t record_btdepth,
			 btlog_lock_t lock_callback,
			 btlog_unlock_t unlock_callback,
			 void *callback_context)
{
	btlog_t *btlog;
	vm_size_t buffersize_needed;
	vm_address_t buffer = 0;
	size_t i;
	kern_return_t ret;
	size_t btrecord_size;

	if (vm_kernel_ready && !kmem_alloc_ready)
		return NULL;

	if (numrecords > BTLOG_MAX_RECORDS)
		return NULL;

	if (numrecords == 0)
		return NULL;

	if (record_btdepth > BTLOG_MAX_DEPTH)
		return NULL;

	if ((lock_callback && !unlock_callback) ||
		(!lock_callback && unlock_callback))
		return NULL;

	/* btlog_record_t is variable-sized, calculate needs now */
	btrecord_size = sizeof(btlog_record_t)
		+ sizeof(void *) * record_btdepth;

	buffersize_needed = sizeof(btlog_t) + numrecords * btrecord_size;
	buffersize_needed = round_page(buffersize_needed);

	/* since rounding to a page size might hold more, recalculate */
	numrecords = MIN(BTLOG_MAX_RECORDS,
					 (buffersize_needed - sizeof(btlog_t))/btrecord_size);

	if (kmem_alloc_ready) {
		ret = kmem_alloc(kernel_map, &buffer, buffersize_needed, VM_KERN_MEMORY_DIAG);
	} else {
		buffer = (vm_address_t)pmap_steal_memory(buffersize_needed);
		ret = KERN_SUCCESS;
	}
	if (ret != KERN_SUCCESS)
		return NULL;

	btlog = (btlog_t *)buffer;
	btlog->btlog_buffer = buffer;
	btlog->btlog_buffersize = buffersize_needed;

	btlog->lock_callback = lock_callback;
	btlog->unlock_callback = unlock_callback;
	btlog->callback_context = callback_context;

	btlog->btrecords = (uintptr_t)(buffer + sizeof(btlog_t));
	btlog->btrecord_count = numrecords;
	btlog->btrecord_btdepth = record_btdepth;
	btlog->btrecord_size = btrecord_size;

	btlog->head = BTLOG_RECORDINDEX_NONE;
	btlog->tail = BTLOG_RECORDINDEX_NONE;
	btlog->activecount = 0;

	/* populate freelist with all records in order */
	btlog->freelist = 0;
	for (i=0; i < (numrecords - 1); i++) {
		btlog_record_t *rec = lookup_btrecord(btlog, i);
		rec->next = (btlog_recordindex_t)(i + 1);
	}
	lookup_btrecord(btlog, i)->next = BTLOG_RECORDINDEX_NONE; /* terminate */

	return btlog;
}

/* Assumes btlog is already locked */
static btlog_recordindex_t
btlog_get_record_from_freelist(btlog_t *btlog)
{
	btlog_recordindex_t	recindex = btlog->freelist;

	if (recindex == BTLOG_RECORDINDEX_NONE) {
		/* nothing on freelist */
		return BTLOG_RECORDINDEX_NONE;
	} else {
		/* remove the head of the freelist */
		btlog_record_t *record = lookup_btrecord(btlog, recindex);
		btlog->freelist = record->next;
		return recindex;
	}
}

/* Assumes btlog is already locked */
static btlog_recordindex_t
btlog_evict_record_from_activelist(btlog_t *btlog)
{
	btlog_recordindex_t	recindex = btlog->head;

	if (recindex == BTLOG_RECORDINDEX_NONE) {
		/* nothing on active list */
		return BTLOG_RECORDINDEX_NONE;
	} else {
		/* remove the head of the active list */
		btlog_record_t *record = lookup_btrecord(btlog, recindex);
		btlog->head = record->next;
		btlog->activecount--;
		if (btlog->head == BTLOG_RECORDINDEX_NONE) {
			/* active list is now empty, update tail */
			btlog->tail = BTLOG_RECORDINDEX_NONE;
		}
		return recindex;
	}
}

/* Assumes btlog is already locked */
static void
btlog_append_record_to_activelist(btlog_t *btlog, btlog_recordindex_t recindex)
{
	if (btlog->head == BTLOG_RECORDINDEX_NONE) {
		/* empty active list, update both head and tail */
		btlog->head = btlog->tail = recindex;
	} else {
		btlog_record_t *record = lookup_btrecord(btlog, btlog->tail);
		record->next = recindex;
		btlog->tail = recindex;
	}
	btlog->activecount++;
}

void
btlog_add_entry(btlog_t *btlog,
				void *element,
				uint8_t operation,
				void *bt[],
				size_t btcount)
{
	btlog_recordindex_t recindex;
	btlog_record_t *record;
	size_t i;

	if (btlog->lock_callback)
		btlog->lock_callback(btlog->callback_context);

	/* If there's a free record, use it */
	recindex = btlog_get_record_from_freelist(btlog);
	if (recindex == BTLOG_RECORDINDEX_NONE) {
		/* Use the first active record (FIFO age-out) */
		recindex = btlog_evict_record_from_activelist(btlog);
		assert(recindex != BTLOG_RECORDINDEX_NONE);
	}

	record = lookup_btrecord(btlog, recindex);

	/* we always add to the tail, so there is no next pointer */
	record->next = BTLOG_RECORDINDEX_NONE;
	record->operation = operation;
	record->element = element;
	for (i=0; i < MIN(btcount, btlog->btrecord_btdepth); i++) {
		record->bt[i] = bt[i];
	}
	for (; i < btlog->btrecord_btdepth; i++) {
		record->bt[i] = NULL;
	}

	btlog_append_record_to_activelist(btlog, recindex);

	if (btlog->unlock_callback)
		btlog->unlock_callback(btlog->callback_context);
}

void
btlog_remove_entries_for_element(btlog_t *btlog,
								 void *element)
{
	btlog_recordindex_t recindex;
	btlog_record_t *record;

	if (btlog->lock_callback)
		btlog->lock_callback(btlog->callback_context);

	/*
	 * Since the btlog_t anchors the active
	 * list with a pointer to the head of
	 * the list, first loop making sure
	 * the head is correct (and doesn't
	 * match the element being removed).
	 */
	recindex = btlog->head;
	record = lookup_btrecord(btlog, recindex);
	while (recindex != BTLOG_RECORDINDEX_NONE) {
		if (record->element == element) {
			/* remove head of active list */
			btlog->head = record->next;
			btlog->activecount--;

			/* add to freelist */
			record->next = btlog->freelist;
			btlog->freelist = recindex;

			/* check the new head */
			recindex = btlog->head;
			record = lookup_btrecord(btlog, recindex);
		} else {
			/* head didn't match, so we can move on */
			break;
		}
	}

	if (recindex == BTLOG_RECORDINDEX_NONE) {
		/* we iterated over the entire active list removing the element */
		btlog->tail = BTLOG_RECORDINDEX_NONE;
	} else {
		/* the head of the active list is stable, now remove other entries */
		btlog_recordindex_t precindex = recindex;
		btlog_record_t *precord = record;
		
		recindex = precord->next;
		record = lookup_btrecord(btlog, recindex);
		while (recindex != BTLOG_RECORDINDEX_NONE) {
			if (record->element == element) {
				/* remove in place */
				precord->next = record->next;
				btlog->activecount--;

				/* add to freelist */
				record->next = btlog->freelist;
				btlog->freelist = recindex;

				/* check the next record */
				recindex = precord->next;
				record = lookup_btrecord(btlog, recindex);
			} else {
				/* check the next record */
				precindex = recindex;
				precord = record;

				recindex = record->next;
				record = lookup_btrecord(btlog, recindex);
			}
		}

		/* We got to the end of the active list. Update the tail */
		btlog->tail = precindex;
	}

	if (btlog->unlock_callback)
		btlog->unlock_callback(btlog->callback_context);

}
