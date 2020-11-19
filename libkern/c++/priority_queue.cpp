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

#if KERNEL
#include <kern/priority_queue.h>
#include <mach/vm_param.h>

#ifdef __LP64__
static_assert(PRIORITY_QUEUE_ENTRY_CHILD_BITS >= VM_KERNEL_POINTER_SIGNIFICANT_BITS,
    "Priority Queue child pointer packing failed");
#endif
#endif // KERNEL

#pragma mark priority queue helpers

/*
 * These traits allow to parametrize `struct pqueue` below.
 */

template <typename queue_t, typename entry_t>
struct pqueue_entry_traits {
	/*
	 * Explain how to compare two elements in the natural order.
	 */
	static inline int
	compare(queue_t que, entry_t a, entry_t b);
};

template <typename queue_t>
struct pqueue_entry_traits<queue_t, priority_queue_entry_t> {
	static inline int
	compare(queue_t que, priority_queue_entry_t e1, priority_queue_entry_t e2)
	{
		return que->pq_cmp_fn(e1, e2);
	}
};

template <typename queue_t>
struct pqueue_entry_traits<queue_t, priority_queue_entry_deadline_t> {
	static inline int
	compare(queue_t que __unused,
	    priority_queue_entry_deadline_t e1, priority_queue_entry_deadline_t e2)
	{
		return priority_heap_compare_ints(e1->deadline, e2->deadline);
	}
};

template <typename queue_t>
struct pqueue_entry_traits<queue_t, priority_queue_entry_sched_t> {
	static inline int
	compare(queue_t que __unused,
	    priority_queue_entry_sched_t e1, priority_queue_entry_sched_t e2)
	{
		return (int)e2->key - (int)e1->key;
	}
};

template <typename queue_t>
struct pqueue_entry_traits<queue_t, priority_queue_entry_stable_t> {
	static inline int
	compare(queue_t que __unused,
	    priority_queue_entry_stable_t e1, priority_queue_entry_stable_t e2)
	{
		/*
		 * the key is (2 * pri + preempted) so preempted entries
		 * sort "higher" than non preempted entries at the same priority.
		 */
		if (e1->key != e2->key) {
			return (int)e2->key - (int)e1->key;
		}
		if (e1->stamp != e2->stamp) {
			/*
			 * preempted entries:     younger (bigger timestamp)  is "higher"
			 * non preempted entries: older   (smaller timestamp) is "higher"
			 */
			if (e1->key & PRIORITY_QUEUE_ENTRY_PREEMPTED) {
				return e1->stamp < e2->stamp ? 1 : -1;
			} else {
				return e1->stamp > e2->stamp ? 1 : -1;
			}
		}
		return 0;
	}
};

#pragma mark main template

/*
 * Template for our priority queue.
 *
 * It is parametrized with:
 * - `queue_t`: the queue type
 * - `entry_t`: the element type
 *
 * It will use:
 * - priority_queue_is_min_heap() to determine if it is a min/max heap
 * - pqueue_entry_traits<queue_t, entry_t>::compare for the ordering
 */
template <typename queue_t, typename entry_t>
struct pqueue {
	using entry_traits = pqueue_entry_traits<queue_t, entry_t>;

	static inline void
	pack_child(entry_t e, const entry_t child)
	{
		e->child = (long)child;
	}

	static inline entry_t
	unpack_child(entry_t e)
	{
		return (entry_t)e->child;
	}

private:
	static inline bool
	merge_parent_is_subtree_b(queue_t que, entry_t subtree_a, entry_t subtree_b)
	{
		if (priority_queue_is_max_heap((queue_t)nullptr)) {
			return entry_traits::compare(que, subtree_a, subtree_b) > 0;
		}
		return entry_traits::compare(que, subtree_a, subtree_b) < 0;
	}

	static inline entry_t
	merge_pair_inline(queue_t que, entry_t subtree_a, entry_t subtree_b)
	{
		entry_t merge_result = NULL;
		if (subtree_a == NULL) {
			merge_result = subtree_b;
		} else if (subtree_b == NULL || (subtree_a == subtree_b)) {
			merge_result = subtree_a;
		} else {
			entry_t parent = subtree_a;
			entry_t child = subtree_b;
			if (merge_parent_is_subtree_b(que, subtree_a, subtree_b)) {
				parent = subtree_b;
				child = subtree_a;
			}
			/* Insert the child as the first element in the parent's child list */
			child->next = unpack_child(parent);
			child->prev = parent;
			if (unpack_child(parent) != NULL) {
				unpack_child(parent)->prev = child;
			}
			/* Create the parent child relationship */
			pack_child(parent, child);
			parent->next = NULL;
			parent->prev = NULL;
			merge_result = parent;
		}
		return merge_result;
	}

	OS_NOINLINE
	static entry_t
	merge_pair(queue_t que, entry_t subtree_a, entry_t subtree_b)
	{
		return merge_pair_inline(que, subtree_a, subtree_b);
	}

	OS_NOINLINE
	static entry_t
	meld_pair(queue_t que, entry_t elt)
	{
		entry_t pq_meld_result = NULL;
		entry_t pair_list = NULL;

		assert(elt); // caller needs to check this.

		/* Phase 1: */
		/* Split the list into a set of pairs going front to back. */
		/* Hook these pairs onto an intermediary list in reverse order of traversal.*/

		do {
			/* Consider two elements at a time for pairing */
			entry_t pair_item_a = elt;
			entry_t pair_item_b = elt->next;
			if (pair_item_b == NULL) {
				/* Odd number of elements in the list; link the odd element */
				/* as it is on the intermediate list. */
				pair_item_a->prev = pair_list;
				pair_list = pair_item_a;
				break;
			}
			/* Found two elements to pair up */
			elt = pair_item_b->next;
			entry_t pair = merge_pair_inline(que, pair_item_a, pair_item_b);
			/* Link the pair onto the intermediary list */
			pair->prev = pair_list;
			pair_list = pair;
		} while (elt != NULL);

		/* Phase 2: Merge all the pairs in the pair_list */
		do {
			elt = pair_list->prev;
			pq_meld_result = merge_pair_inline(que, pq_meld_result, pair_list);
			pair_list = elt;
		} while (pair_list != NULL);

		return pq_meld_result;
	}

	static inline void
	list_remove(entry_t elt)
	{
		assert(elt->prev != NULL);
		/* Check if elt is head of list at its level;        */
		/* If yes, make the next node the head at that level */
		/* Else, remove elt from the list at that level      */
		if (unpack_child(elt->prev) == elt) {
			pack_child(elt->prev, elt->next);
		} else {
			elt->prev->next = elt->next;
		}
		/* Update prev for next element in list */
		if (elt->next != NULL) {
			elt->next->prev = elt->prev;
		}
	}

	static inline bool
	sift_down(queue_t que, entry_t elt)
	{
		bool was_root = remove(que, elt);
		insert(que, elt);
		return was_root;
	}

	static inline bool
	sift_up(queue_t que, entry_t elt)
	{
		if (elt == que->pq_root) {
			return true;
		}

		/* Remove the element from its current level list */
		list_remove(elt);
		/* Re-insert the element into the heap with a merge */
		return insert(que, elt);
	}

	static inline entry_t
	remove_non_root(queue_t que, entry_t elt)
	{
		entry_t child, new_root;

		/* To remove a non-root element with children levels, */
		/* - Remove element from its current level list */
		/* - Pairwise split all the elements in the child level list */
		/* - Meld all these splits (right-to-left) to form new subtree */
		/* - Merge the root subtree with the newly formed subtree */
		list_remove(elt);

		child = unpack_child(elt);
		if (child) {
			child = meld_pair(que, child);
			new_root = merge_pair(que, que->pq_root, child);
			que->pq_root = new_root;
		}

		return elt;
	}

public:

	/*
	 * exposed interfaces
	 */

	OS_NOINLINE
	static void
	destroy(queue_t que, uintptr_t offset, void (^callback)(void *e))
	{
		assert(callback != NULL);
		entry_t head = que->pq_root;
		entry_t tail = head;

		while (head != NULL) {
			entry_t child_list = unpack_child(head);
			if (child_list) {
				tail->next = child_list;
				while (tail->next) {
					tail = tail->next;
				}
			}

			entry_t elt = head;
			head = head->next;
			callback((void *)((char *)elt - offset));
		}

		/* poison the queue now that it's destroyed */
		que->pq_root = (entry_t)(~0ul);
	}

	static inline bool
	insert(queue_t que, entry_t elt)
	{
		return (que->pq_root = merge_pair(que, que->pq_root, elt)) == elt;
	}

	static inline entry_t
	remove_root(queue_t que, entry_t old_root)
	{
		entry_t new_root = unpack_child(old_root);
		que->pq_root = new_root ? meld_pair(que, new_root) : NULL;
		return old_root;
	}

	static inline bool
	remove(queue_t que, entry_t elt)
	{
		if (elt == que->pq_root) {
			remove_root(que, elt);
			elt->next = elt->prev = NULL;
			elt->child = 0;
			return true;
		} else {
			remove_non_root(que, elt);
			elt->next = elt->prev = NULL;
			elt->child = 0;
			return false;
		}
	}

	static inline bool
	entry_increased(queue_t que, entry_t elt)
	{
		if (priority_queue_is_max_heap(que)) {
			return sift_up(que, elt);
		} else {
			return sift_down(que, elt);
		}
	}

	static inline bool
	entry_decreased(queue_t que, entry_t elt)
	{
		if (priority_queue_is_min_heap(que)) {
			return sift_up(que, elt);
		} else {
			return sift_down(que, elt);
		}
	}
};

#pragma mark instantiation

#define PRIORITY_QUEUE_MAKE_IMPL(pqueue_t, queue_t, entry_t)                    \
                                                                                \
using pqueue_t = pqueue<queue_t, entry_t>;                                      \
                                                                                \
extern "C" {                                                                    \
                                                                                \
__pqueue_overloadable void                                                      \
_priority_queue_destroy(queue_t que, uintptr_t offset, void (^cb)(void *e))     \
{                                                                               \
	pqueue_t::destroy(que, offset, cb);                                     \
}                                                                               \
                                                                                \
__pqueue_overloadable extern bool                                               \
priority_queue_insert(queue_t que, entry_t elt)                                 \
{                                                                               \
	return pqueue_t::insert(que, elt);                                      \
}                                                                               \
                                                                                \
__pqueue_overloadable extern entry_t                                            \
_priority_queue_remove_root(queue_t que)                                        \
{                                                                               \
	return pqueue_t::remove_root(que, que->pq_root);                        \
}                                                                               \
                                                                                \
__pqueue_overloadable extern bool                                               \
priority_queue_remove(queue_t que, entry_t elt)                                 \
{                                                                               \
	return pqueue_t::remove(que, elt);                                      \
}                                                                               \
                                                                                \
__pqueue_overloadable extern bool                                               \
priority_queue_entry_decreased(queue_t que, entry_t elt)                        \
{                                                                               \
	return pqueue_t::entry_decreased(que, elt);                             \
}                                                                               \
                                                                                \
__pqueue_overloadable extern bool                                               \
priority_queue_entry_increased(queue_t que, entry_t elt)                        \
{                                                                               \
	return pqueue_t::entry_increased(que, elt);                             \
}                                                                               \
                                                                                \
}

PRIORITY_QUEUE_MAKE_IMPL(pqueue_min_t,
    struct priority_queue_min *, priority_queue_entry_t);
PRIORITY_QUEUE_MAKE_IMPL(pqueue_max_t,
    struct priority_queue_max *, priority_queue_entry_t);

PRIORITY_QUEUE_MAKE_IMPL(pqueue_sched_min_t,
    struct priority_queue_sched_min *, priority_queue_entry_sched_t);
PRIORITY_QUEUE_MAKE_IMPL(pqueue_sched_max_t,
    struct priority_queue_sched_max *, priority_queue_entry_sched_t);

PRIORITY_QUEUE_MAKE_IMPL(pqueue_deadline_min_t,
    struct priority_queue_deadline_min *, priority_queue_entry_deadline_t);
PRIORITY_QUEUE_MAKE_IMPL(pqueue_deadline_max_t,
    struct priority_queue_deadline_max *, priority_queue_entry_deadline_t);

PRIORITY_QUEUE_MAKE_IMPL(pqueue_sched_stable_min_t,
    struct priority_queue_sched_stable_min *, priority_queue_entry_stable_t);
PRIORITY_QUEUE_MAKE_IMPL(pqueue_sched_stable_max_t,
    struct priority_queue_sched_stable_max *, priority_queue_entry_stable_t);
