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

#ifndef _KERN_PRIORITY_QUEUE_H_
#define _KERN_PRIORITY_QUEUE_H_

#if KERNEL
#include <kern/kern_types.h>
#include <kern/macro_help.h>
#include <kern/assert.h>
#endif

#include <stdbool.h>
#include <sys/cdefs.h>

#pragma GCC visibility push(hidden)

__BEGIN_DECLS

/*
 * A generic priorty ordered queue implementation based on pairing heaps.
 *
 * Reference Papers:
 * - A Back-to-Basics Empirical Study of Priority Queues (https://arxiv.org/abs/1403.0252)
 * - The Pairing Heap: A New Form of Self-Adjusting Heap
 *   (https://www.cs.cmu.edu/~sleator/papers/pairing-heaps.pdf)
 *
 * The XNU implementation is a basic version of the pairing heap.
 * It allows for O(1) insertion and amortized O(log n) deletion.
 *
 * It is not a stable data structure by default since adding stability would
 * need more pointers and hence more memory.
 *
 * Type of queues
 *
 *         There are several types of priority queues, with types named:
 *
 *         struct priority_queue_<subtype>_<min|max>
 *
 *         In the rest of this header, `struct priority_queue` is used as
 *         a generic type to mean any priority_queue type.
 *
 *         min/max refers to whether the priority queue is a min or a max heap.
 *
 *         the subtype can be:
 *
 *         - sched, in which case the key is built in the linkage and assumed to
 *           be a scheduler priority.
 *
 *         - sched_stable, in which case the key is a combination of:
 *             * a scheduler priority
 *             * whether the entry was preempted or not
 *             * a timestamp.
 *
 *         - generic, in which case a comparison function must be passed to
 *           the priority_queue_init.
 *
 * Element Linkage:
 *
 *         Both types use a common queue head and linkage pattern.
 *         The head of a priority queue is declared as:
 *
 *              struct priority_queue_<subtype>_<min|max> pq_head;
 *
 *         Elements in this queue are linked together using one of the struct
 *         priority_queue_entry_<subtype> objects embedded within a structure:
 *
 *              struct some_data {
 *                      int field1;
 *                      int field2;
 *                      ...
 *                      struct priority_queue_entry link;
 *                      ...
 *                      int last_field;
 *              };
 *         struct some_data is referred to as the queue "element"
 *
 *         This method uses the next, prev and child pointers of the struct
 *         priority_queue_entry linkage object embedded in a queue element to
 *         point to other elements in the queue. The head of the priority queue
 *         (the priority_queue object) will point to the root of the pairing
 *         heap (NULL if heap is empty). This method allows multiple chains
 *         through a given object, by embedding multiple priority_queue_entry
 *         objects in the structure, while simultaneously providing fast removal
 *         and insertion into the heap using only priority_queue_entry object
 *         pointers.
 */


/*
 * Priority keys maintained by the data structure.
 * Since the priority is packed in the node itself, it restricts keys to be 16-bits only.
 */
#define PRIORITY_QUEUE_KEY_NONE             0
typedef uint16_t priority_queue_key_t;

#ifdef __LP64__

/*
 * For 64-bit platforms, pack the priority key into the child pointer
 * The packing/unpacking is done using a compiler trick to sign extend long.
 * This avoids additional NULL checks which are needed in typical packing
 * implementation. The idea is to define the packed location as a long and
 * for unpacking simply cast it to a full pointer which sign extends it.
 */
#define PRIORITY_QUEUE_ENTRY_CHILD_BITS     48
#define PRIORITY_QUEUE_ENTRY_KEY_BITS       16

typedef struct priority_queue_entry {
	struct priority_queue_entry        *next;
	struct priority_queue_entry        *prev;
	long                                __key: PRIORITY_QUEUE_ENTRY_KEY_BITS;
	long                                child: PRIORITY_QUEUE_ENTRY_CHILD_BITS;
} *priority_queue_entry_t;

typedef struct priority_queue_entry_deadline {
	struct priority_queue_entry_deadline *next;
	struct priority_queue_entry_deadline *prev;
	long                                  __key: PRIORITY_QUEUE_ENTRY_KEY_BITS;
	long                                  child: PRIORITY_QUEUE_ENTRY_CHILD_BITS;
	uint64_t                              deadline;
} *priority_queue_entry_deadline_t;

typedef struct priority_queue_entry_sched {
	struct priority_queue_entry_sched  *next;
	struct priority_queue_entry_sched  *prev;
	long                                key: PRIORITY_QUEUE_ENTRY_KEY_BITS;
	long                                child: PRIORITY_QUEUE_ENTRY_CHILD_BITS;
} *priority_queue_entry_sched_t;

typedef struct priority_queue_entry_stable {
	struct priority_queue_entry_stable *next;
	struct priority_queue_entry_stable *prev;
	long                                key: PRIORITY_QUEUE_ENTRY_KEY_BITS;
	long                                child: PRIORITY_QUEUE_ENTRY_CHILD_BITS;
	uint64_t                            stamp;
} *priority_queue_entry_stable_t;

#else /* __LP64__ */

typedef struct priority_queue_entry {
	struct priority_queue_entry        *next;
	struct priority_queue_entry        *prev;
	long                                child;
} *priority_queue_entry_t;

typedef struct priority_queue_entry_deadline {
	struct priority_queue_entry_deadline *next;
	struct priority_queue_entry_deadline *prev;
	long                                  child;
	uint64_t                              deadline;
} *priority_queue_entry_deadline_t;

/*
 * For 32-bit platforms, use an extra field to store the key since child pointer packing
 * is not an option. The child is maintained as a long to use the same packing/unpacking
 * routines that work for 64-bit platforms.
 */
typedef struct priority_queue_entry_sched {
	struct priority_queue_entry_sched  *next;
	struct priority_queue_entry_sched  *prev;
	long                                child;
	priority_queue_key_t                key;
} *priority_queue_entry_sched_t;

typedef struct priority_queue_entry_stable {
	struct priority_queue_entry_stable *next;
	struct priority_queue_entry_stable *prev;
	long                                child;
	priority_queue_key_t                key;
	uint64_t                            stamp;
} *priority_queue_entry_stable_t;

#endif /* __LP64__ */

/*
 * Comparator block prototype
 * Args:
 *      - elements to compare
 * Return:
 * comparision result to indicate relative ordering of elements according to the heap type
 */
typedef int (^priority_queue_compare_fn_t)(struct priority_queue_entry *e1,
    struct priority_queue_entry *e2);

#define priority_heap_compare_ints(a, b) ((a) < (b) ? 1 : -1)

#define priority_heap_make_comparator(name1, name2, type, field, ...) \
	(^int(priority_queue_entry_t __e1, priority_queue_entry_t __e2){        \
	    type *name1 = pqe_element_fast(__e1, type, field);                  \
	    type *name2 = pqe_element_fast(__e2, type, field);                  \
	    __VA_ARGS__;                                                        \
	})

/*
 * Type for any priority queue, only used for documentation purposes.
 */
struct priority_queue;

/*
 * Type of generic heaps
 */
struct priority_queue_min {
	struct priority_queue_entry *pq_root;
	priority_queue_compare_fn_t  pq_cmp_fn;
};
struct priority_queue_max {
	struct priority_queue_entry *pq_root;
	priority_queue_compare_fn_t  pq_cmp_fn;
};

/*
 * Type of deadline heaps
 */
struct priority_queue_deadline_min {
	struct priority_queue_entry_deadline *pq_root;
};
struct priority_queue_deadline_max {
	struct priority_queue_entry_deadline *pq_root;
};

/*
 * Type of scheduler priority based heaps
 */
struct priority_queue_sched_min {
	struct priority_queue_entry_sched *pq_root;
};
struct priority_queue_sched_max {
	struct priority_queue_entry_sched *pq_root;
};

/*
 * Type of scheduler priority based stable heaps
 */
struct priority_queue_sched_stable_min {
	struct priority_queue_entry_stable *pq_root;
};
struct priority_queue_sched_stable_max {
	struct priority_queue_entry_stable *pq_root;
};

#pragma mark generic interface

#define PRIORITY_QUEUE_INITIALIZER { .pq_root = NULL }

#define __pqueue_overloadable  __attribute__((overloadable))

#define priority_queue_is_min_heap(pq) _Generic(pq, \
	struct priority_queue_min *: true, \
	struct priority_queue_max *: false, \
	struct priority_queue_deadline_min *: true, \
	struct priority_queue_deadline_max *: false, \
	struct priority_queue_sched_min *: true, \
	struct priority_queue_sched_max *: false, \
	struct priority_queue_sched_stable_min *: true, \
	struct priority_queue_sched_stable_max *: false)

#define priority_queue_is_max_heap(pq) \
	(!priority_queue_is_min_heap(pq))

/*
 *      Macro:          pqe_element_fast
 *      Function:
 *              Convert a priority_queue_entry_t to a queue element pointer.
 *              Get a pointer to the user-defined element containing
 *              a given priority_queue_entry_t
 *
 *              The fast variant assumes that `qe` is not NULL
 *      Header:
 *              pqe_element_fast(qe, type, field)
 *                      <priority_queue_entry_t> qe
 *                      <type> type of element in priority queue
 *                      <field> chain field in (*<type>)
 *      Returns:
 *              <type *> containing qe
 */
#define pqe_element_fast(qe, type, field)  __container_of(qe, type, field)

/*
 *      Macro:          pqe_element
 *      Function:
 *              Convert a priority_queue_entry_t to a queue element pointer.
 *              Get a pointer to the user-defined element containing
 *              a given priority_queue_entry_t
 *
 *              The non fast variant handles NULL `qe`
 *      Header:
 *              pqe_element(qe, type, field)
 *                      <priority_queue_entry_t> qe
 *                      <type> type of element in priority queue
 *                      <field> chain field in (*<type>)
 *      Returns:
 *              <type *> containing qe
 */
#define pqe_element(qe, type, field)  ({                                        \
	__auto_type _tmp_entry = (qe);                                          \
	_tmp_entry ? pqe_element_fast(_tmp_entry, type, field) : ((type *)NULL);\
})

/*
 * Priority Queue functionality routines
 */

/*
 *      Macro:          priority_queue_empty
 *      Function:
 *              Tests whether a priority queue is empty.
 *      Header:
 *              boolean_t priority_queue_empty(pq)
 *                      <struct priority_queue *> pq
 */
#define priority_queue_empty(pq)         ((pq)->pq_root == NULL)

/*
 *      Macro:          priority_queue_init
 *      Function:
 *              Initialize a <struct priority_queue *>.
 *      Header:
 *              priority_queue_init(pq)
 *                      <struct priority_queue *> pq
 *                      (optional) <cmp_fn> comparator function
 *      Returns:
 *              None
 */
__pqueue_overloadable
extern void
priority_queue_init(struct priority_queue *pq, ...);

/*
 *      Macro:          priority_queue_entry_init
 *      Function:
 *              Initialize a priority_queue_entry_t
 *      Header:
 *              priority_queue_entry_init(qe)
 *                      <priority_queue_entry_t> qe
 *      Returns:
 *              None
 */
#define priority_queue_entry_init(qe) \
	__builtin_bzero(qe, sizeof(*(qe)))

/*
 *      Macro:          priority_queue_destroy
 *      Function:
 *              Destroy a priority queue safely. This routine accepts a callback
 *              to handle any cleanup for elements in the priority queue. The queue does
 *              not maintain its invariants while getting destroyed. The priority queue and
 *              the linkage nodes need to be re-initialized before re-using them.
 *      Header:
 *              priority_queue_destroy(pq, type, field, callback)
 *                      <struct priority_queue *> pq
 *                      <callback> callback for each element
 *
 *      Returns:
 *              None
 */
#define priority_queue_destroy(pq, type, field, callback)                       \
MACRO_BEGIN                                                                     \
	void (^__callback)(type *) = (callback); /* type check */               \
	_priority_queue_destroy(pq, offsetof(type, field),                      \
	    (void (^)(void *))(__callback));                                    \
MACRO_END

/*
 *      Macro:          priority_queue_min
 *      Function:
 *              Lookup the minimum in a min-priority queue.
 *
 *      Header:
 *              priority_queue_min(pq, type, field)
 *                      <struct priority_queue *> pq
 *                      <type> type of element in priority queue
 *                      <field> chain field in (*<type>)
 *      Returns:
 *              <type *> root element
 */
#define priority_queue_min(pq, type, field) ({                                  \
	static_assert(priority_queue_is_min_heap(pq), "queue is min heap");     \
	pqe_element((pq)->pq_root, type, field);                                \
})

/*
 *      Macro:          priority_queue_max
 *      Function:
 *              Lookup the maximum element in a max-priority queue.
 *
 *      Header:
 *              priority_queue_max(pq, type, field)
 *                      <struct priority_queue *> pq
 *                      <type> type of element in priority queue
 *                      <field> chain field in (*<type>)
 *      Returns:
 *              <type *> root element
 */
#define priority_queue_max(pq, type, field) ({                                  \
	static_assert(priority_queue_is_max_heap(pq), "queue is max heap");     \
	pqe_element((pq)->pq_root, type, field);                                \
})

/*
 *      Macro:          priority_queue_insert
 *      Function:
 *              Insert an element into the priority queue
 *
 *              The caller must have set the key prio to insertion
 *
 *      Header:
 *              priority_queue_insert(pq, elt, new_key)
 *                      <struct priority_queue *> pq
 *                      <priority_queue_entry_t> elt
 *      Returns:
 *              Whether the inserted element became the new root
 */
extern bool
priority_queue_insert(struct priority_queue *pq,
    struct priority_queue_entry *elt) __pqueue_overloadable;

/*
 *      Macro:          priority_queue_remove_min
 *      Function:
 *              Remove the minimum element in a min-heap priority queue.
 *      Header:
 *              priority_queue_remove_min(pq, type, field)
 *                      <struct priority_queue *> pq
 *                      <type> type of element in priority queue
 *                      <field> chain field in (*<type>)
 *      Returns:
 *              <type *> max element
 */
#define priority_queue_remove_min(pq, type, field) ({                           \
	static_assert(priority_queue_is_min_heap(pq), "queue is min heap");     \
	pqe_element(_priority_queue_remove_root(pq), type, field);              \
})

/*
 *      Macro:          priority_queue_remove_max
 *      Function:
 *              Remove the maximum element in a max-heap priority queue.
 *      Header:
 *              priority_queue_remove_max(pq, type, field)
 *                      <struct priority_queue *> pq
 *                      <type> type of element in priority queue
 *                      <field> chain field in (*<type>)
 *      Returns:
 *              <type *> max element
 */
#define priority_queue_remove_max(pq, type, field) ({                           \
	static_assert(priority_queue_is_max_heap(pq), "queue is max heap");     \
	pqe_element(_priority_queue_remove_root(pq), type, field);              \
})

/*
 *      Macro:          priority_queue_remove
 *      Function:
 *              Removes an element from the priority queue
 *      Header:
 *              priority_queue_remove(pq, elt)
 *                      <struct priority_queue *> pq
 *                      <priority_queue_entry_t> elt
 *      Returns:
 *              Whether the removed element was the root
 */
extern bool
priority_queue_remove(struct priority_queue *pq,
    struct priority_queue_entry *elt) __pqueue_overloadable;


/*
 *      Macro:          priority_queue_entry_decreased
 *
 *      Function:
 *              Signal the priority queue that the entry priority has decreased.
 *
 *              The new value for the element priority must have been set
 *              prior to calling this function.
 *
 *      Header:
 *              priority_queue_entry_decreased(pq, elt)
 *                      <struct priority_queue *> pq
 *                      <priority_queue_entry_t> elt
 *      Returns:
 *              Whether the update caused the root or its key to change.
 */
extern bool
priority_queue_entry_decreased(struct priority_queue *pq,
    struct priority_queue_entry *elt) __pqueue_overloadable;

/*
 *      Macro:          priority_queue_entry_increased
 *
 *      Function:
 *              Signal the priority queue that the entry priority has increased.
 *
 *              The new value for the element priority must have been set
 *              prior to calling this function.
 *
 *      Header:
 *              priority_queue_entry_increased(pq, elt, new_key)
 *                      <struct priority_queue *> pq
 *                      <priority_queue_entry_t> elt
 *      Returns:
 *              Whether the update caused the root or its key to change.
 */
extern bool
priority_queue_entry_increased(struct priority_queue *pq,
    struct priority_queue_entry *elt) __pqueue_overloadable;


#pragma mark priority_queue_sched_*

__enum_decl(priority_queue_entry_sched_modifier_t, uint8_t, {
	PRIORITY_QUEUE_ENTRY_NONE      = 0,
	PRIORITY_QUEUE_ENTRY_PREEMPTED = 1,
});

#define priority_queue_is_sched_heap(pq) _Generic(pq, \
	struct priority_queue_sched_min *: true, \
	struct priority_queue_sched_max *: true, \
	struct priority_queue_sched_stable_min *: true, \
	struct priority_queue_sched_stable_max *: true, \
	default: false)

/*
 *      Macro:          priority_queue_entry_set_sched_pri
 *
 *      Function:
 *              Sets the scheduler priority on an entry supporting this concept.
 *
 *              The priority is expected to fit on 8 bits.
 *              An optional sorting modifier.
 *
 *      Header:
 *              priority_queue_entry_set_sched_pri(pq, elt, pri, modifier)
 *                      <struct priority_queue *> pq
 *                      <priority_queue_entry_t> elt
 *                      <uint8_t> pri
 *                      <priority_queue_entry_sched_modifier_t> modifier
 */
#define priority_queue_entry_set_sched_pri(pq, elt, pri, modifier)              \
MACRO_BEGIN                                                                     \
	static_assert(priority_queue_is_sched_heap(pq), "is a sched heap");     \
	(elt)->key = (priority_queue_key_t)(((pri) << 8) + (modifier));         \
MACRO_END

/*
 *      Macro:          priority_queue_entry_sched_pri
 *
 *      Function:
 *              Return the scheduler priority on an entry supporting this
 *              concept.
 *
 *      Header:
 *              priority_queue_entry_sched_pri(pq, elt)
 *                      <struct priority_queue *> pq
 *                      <priority_queue_entry_t> elt
 *
 *      Returns:
 *              The scheduler priority of this entry
 */
#define priority_queue_entry_sched_pri(pq, elt) ({                              \
	static_assert(priority_queue_is_sched_heap(pq), "is a sched heap");     \
	(priority_queue_key_t)((elt)->key >> 8);                                \
})

/*
 *      Macro:          priority_queue_entry_sched_modifier
 *
 *      Function:
 *              Return the scheduler modifier on an entry supporting this
 *              concept.
 *
 *      Header:
 *              priority_queue_entry_sched_modifier(pq, elt)
 *                      <struct priority_queue *> pq
 *                      <priority_queue_entry_t> elt
 *
 *      Returns:
 *              The scheduler priority of this entry
 */
#define priority_queue_entry_sched_modifier(pq, elt) ({                         \
	static_assert(priority_queue_is_sched_heap(pq), "is a sched heap");     \
	(priority_queue_entry_sched_modifier_t)(elt)->key;                      \
})

/*
 *      Macro:          priority_queue_min_sched_pri
 *
 *      Function:
 *              Return the scheduler priority of the minimum element
 *              of a scheduler priority queue.
 *
 *      Header:
 *              priority_queue_min_sched_pri(pq)
 *                      <struct priority_queue *> pq
 *
 *      Returns:
 *              The scheduler priority of this entry
 */
#define priority_queue_min_sched_pri(pq) ({                                     \
	static_assert(priority_queue_is_min_heap(pq), "queue is min heap");     \
	priority_queue_entry_sched_pri(pq, (pq)->pq_root);                      \
})

/*
 *      Macro:          priority_queue_max_sched_pri
 *
 *      Function:
 *              Return the scheduler priority of the maximum element
 *              of a scheduler priority queue.
 *
 *      Header:
 *              priority_queue_max_sched_pri(pq)
 *                      <struct priority_queue *> pq
 *
 *      Returns:
 *              The scheduler priority of this entry
 */
#define priority_queue_max_sched_pri(pq) ({                                     \
	static_assert(priority_queue_is_max_heap(pq), "queue is max heap");     \
	priority_queue_entry_sched_pri(pq, (pq)->pq_root);                      \
})


#pragma mark implementation details

#define PRIORITY_QUEUE_MAKE_BASE(pqueue_t, pqelem_t) \
                                                                                \
__pqueue_overloadable extern void                                               \
_priority_queue_destroy(pqueue_t pq, uintptr_t offset, void (^cb)(void *));     \
                                                                                \
__pqueue_overloadable extern bool                                               \
priority_queue_insert(pqueue_t que, pqelem_t elt);                              \
                                                                                \
__pqueue_overloadable extern pqelem_t                                           \
_priority_queue_remove_root(pqueue_t que);                                      \
                                                                                \
__pqueue_overloadable extern bool                                               \
priority_queue_remove(pqueue_t que, pqelem_t elt);                              \
                                                                                \
__pqueue_overloadable extern bool                                               \
priority_queue_entry_decreased(pqueue_t que, pqelem_t elt);                     \
                                                                                \
__pqueue_overloadable extern bool                                               \
priority_queue_entry_increased(pqueue_t que, pqelem_t elt)

#define PRIORITY_QUEUE_MAKE(pqueue_t, pqelem_t) \
__pqueue_overloadable                                                           \
static inline void                                                              \
priority_queue_init(pqueue_t que)                                               \
{                                                                               \
	__builtin_bzero(que, sizeof(*que));                                     \
}                                                                               \
                                                                                \
PRIORITY_QUEUE_MAKE_BASE(pqueue_t, pqelem_t)

#define PRIORITY_QUEUE_MAKE_CB(pqueue_t, pqelem_t) \
__pqueue_overloadable                                                           \
static inline void                                                              \
priority_queue_init(pqueue_t pq, priority_queue_compare_fn_t cmp_fn)            \
{                                                                               \
	pq->pq_root = NULL;                                                     \
	pq->pq_cmp_fn = cmp_fn;                                                 \
}                                                                               \
                                                                                \
PRIORITY_QUEUE_MAKE_BASE(pqueue_t, pqelem_t)

PRIORITY_QUEUE_MAKE_CB(struct priority_queue_min *, priority_queue_entry_t);
PRIORITY_QUEUE_MAKE_CB(struct priority_queue_max *, priority_queue_entry_t);

PRIORITY_QUEUE_MAKE(struct priority_queue_deadline_min *, priority_queue_entry_deadline_t);
PRIORITY_QUEUE_MAKE(struct priority_queue_deadline_max *, priority_queue_entry_deadline_t);

PRIORITY_QUEUE_MAKE(struct priority_queue_sched_min *, priority_queue_entry_sched_t);
PRIORITY_QUEUE_MAKE(struct priority_queue_sched_max *, priority_queue_entry_sched_t);

PRIORITY_QUEUE_MAKE(struct priority_queue_sched_stable_min *, priority_queue_entry_stable_t);
PRIORITY_QUEUE_MAKE(struct priority_queue_sched_stable_max *, priority_queue_entry_stable_t);

__END_DECLS

#pragma GCC visibility pop

#endif /* _KERN_PRIORITY_QUEUE_H_ */
