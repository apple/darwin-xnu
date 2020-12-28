/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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

#include <kern/priority_queue.h>
#include <mach/vm_param.h>

#ifdef __LP64__
static_assert(PRIORITY_QUEUE_ENTRY_CHILD_BITS >= VM_KERNEL_POINTER_SIGNIFICANT_BITS,
    "Priority Queue child pointer packing failed");
#endif

priority_queue_entry_t
pqueue_pair_meld(priority_queue_entry_t elt, priority_queue_compare_fn_t cmp_fn)
{
	priority_queue_entry_t pq_meld_result = NULL;
	priority_queue_entry_t pair_list = NULL;

	assert(elt); // caller needs to check this.

	/* Phase 1: */
	/* Split the list into a set of pairs going front to back. */
	/* Hook these pairs onto an intermediary list in reverse order of traversal.*/

	do {
		/* Consider two elements at a time for pairing */
		priority_queue_entry_t pair_item_a = elt;
		priority_queue_entry_t pair_item_b = elt->next;
		if (pair_item_b == NULL) {
			/* Odd number of elements in the list; link the odd element */
			/* as it is on the intermediate list. */
			pair_item_a->prev = pair_list;
			pair_list = pair_item_a;
			break;
		}
		/* Found two elements to pair up */
		elt = pair_item_b->next;
		priority_queue_entry_t pair = pqueue_merge(pair_item_a, pair_item_b, cmp_fn);
		/* Link the pair onto the intermediary list */
		pair->prev = pair_list;
		pair_list = pair;
	} while (elt != NULL);

	/* Phase 2: Merge all the pairs in the pair_list */
	do {
		elt = pair_list->prev;
		pq_meld_result = pqueue_merge(pq_meld_result, pair_list, cmp_fn);
		pair_list = elt;
	} while (pair_list != NULL);

	return pq_meld_result;
}

void
pqueue_destroy(struct priority_queue *q, size_t offset,
    void (^callback)(void *e))
{
	assert(callback != NULL);
	priority_queue_entry_t head = pqueue_unpack_root(q);
	priority_queue_entry_t tail = head;

	while (head != NULL) {
		priority_queue_entry_t child_list = pqueue_entry_unpack_child(head);
		if (child_list) {
			tail->next = child_list;
			while (tail->next) {
				tail = tail->next;
			}
		}

		priority_queue_entry_t elt = head;
		head = head->next;
		callback((void *)elt - offset);
	}

	/* poison the queue now that it's destroyed */
	q->pq_root_packed = ~0UL;
}
