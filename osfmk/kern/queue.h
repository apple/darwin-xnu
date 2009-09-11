/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon rights
 * to redistribute these changes.
 */
/*
 */
/*
 *	File:	queue.h
 *	Author:	Avadis Tevanian, Jr.
 *	Date:	1985
 *
 *	Type definitions for generic queues.
 *
 */

#ifndef	_KERN_QUEUE_H_
#define	_KERN_QUEUE_H_

#include <mach/mach_types.h>
#include <kern/macro_help.h>

/*
 *	Queue of abstract objects.  Queue is maintained
 *	within that object.
 *
 *	Supports fast removal from within the queue.
 *
 *	How to declare a queue of elements of type "foo_t":
 *		In the "*foo_t" type, you must have a field of
 *		type "queue_chain_t" to hold together this queue.
 *		There may be more than one chain through a
 *		"foo_t", for use by different queues.
 *
 *		Declare the queue as a "queue_t" type.
 *
 *		Elements of the queue (of type "foo_t", that is)
 *		are referred to by reference, and cast to type
 *		"queue_entry_t" within this module.
 */

/*
 *	A generic doubly-linked list (queue).
 */

struct queue_entry {
	struct queue_entry	*next;		/* next element */
	struct queue_entry	*prev;		/* previous element */
};

typedef struct queue_entry	*queue_t;
typedef	struct queue_entry	queue_head_t;
typedef	struct queue_entry	queue_chain_t;
typedef	struct queue_entry	*queue_entry_t;

/*
 *	enqueue puts "elt" on the "queue".
 *	dequeue returns the first element in the "queue".
 *	remqueue removes the specified "elt" from the specified "queue".
 */

#define enqueue(queue,elt)	enqueue_tail(queue, elt)
#define	dequeue(queue)		dequeue_head(queue)

#if	!defined(__GNUC__)

#include <sys/cdefs.h>
__BEGIN_DECLS

/* Enqueue element to head of queue */
extern void		enqueue_head(
				queue_t		que,
				queue_entry_t	elt);

/* Enqueue element to tail of queue */
extern void		enqueue_tail(
				queue_t		que,
				queue_entry_t	elt);

/* Dequeue element from head of queue */
extern queue_entry_t	dequeue_head(
				queue_t	que);

/* Dequeue element from tail of queue */
extern queue_entry_t	dequeue_tail(
				queue_t	que);

/* Dequeue element */
extern void		remqueue(
				queue_t		que,
				queue_entry_t	elt);

/* Enqueue element after a particular elem */
extern void		insque(
				queue_entry_t	entry,
				queue_entry_t	pred);

/* Dequeue element */
extern void		remque(
				queue_entry_t elt);

__END_DECLS

#else	/* !__GNUC__ */

static __inline__ void
enqueue_head(
	queue_t		que,
	queue_entry_t	elt)
{
	elt->next = que->next;
	elt->prev = que;
	elt->next->prev = elt;
	que->next = elt;
}

static __inline__ void
enqueue_tail(
		queue_t		que,
		queue_entry_t	elt)
{
	elt->next = que;
	elt->prev = que->prev;
	elt->prev->next = elt;
	que->prev = elt;
}

static __inline__ queue_entry_t
dequeue_head(
	queue_t	que)
{
	register queue_entry_t	elt = (queue_entry_t) 0;

	if (que->next != que) {
		elt = que->next;
		elt->next->prev = que;
		que->next = elt->next;
	}

	return (elt);
}

static __inline__ queue_entry_t
dequeue_tail(
	queue_t	que)
{
	register queue_entry_t	elt = (queue_entry_t) 0;

	if (que->prev != que) {
		elt = que->prev;
		elt->prev->next = que;
		que->prev = elt->prev;
	}

	return (elt);
}

static __inline__ void
remqueue(
	__unused queue_t		que,
	queue_entry_t	elt)
{
	elt->next->prev = elt->prev;
	elt->prev->next = elt->next;
}

static __inline__ void
insque(
	queue_entry_t	entry,
	queue_entry_t	pred)
{
	entry->next = pred->next;
	entry->prev = pred;
	(pred->next)->prev = entry;
	pred->next = entry;
}

static __inline__ void
remque(
	register queue_entry_t elt)
{
	(elt->next)->prev = elt->prev;
	(elt->prev)->next = elt->next;
}

#endif	/* !__GNUC__ */

/*
 *	Macro:		queue_init
 *	Function:
 *		Initialize the given queue.
 *	Header:
 *		void queue_init(q)
 *			queue_t		q;	\* MODIFIED *\
 */
#define queue_init(q)	\
MACRO_BEGIN		\
	(q)->next = (q);\
	(q)->prev = (q);\
MACRO_END

/*
 *	Macro:		queue_first
 *	Function:
 *		Returns the first entry in the queue,
 *	Header:
 *		queue_entry_t queue_first(q)
 *			queue_t	q;		\* IN *\
 */
#define	queue_first(q)	((q)->next)

/*
 *	Macro:		queue_next
 *	Function:
 *		Returns the entry after an item in the queue.
 *	Header:
 *		queue_entry_t queue_next(qc)
 *			queue_t qc;
 */
#define	queue_next(qc)	((qc)->next)

/*
 *	Macro:		queue_last
 *	Function:
 *		Returns the last entry in the queue.
 *	Header:
 *		queue_entry_t queue_last(q)
 *			queue_t	q;		\* IN *\
 */
#define	queue_last(q)	((q)->prev)

/*
 *	Macro:		queue_prev
 *	Function:
 *		Returns the entry before an item in the queue.
 *	Header:
 *		queue_entry_t queue_prev(qc)
 *			queue_t qc;
 */
#define	queue_prev(qc)	((qc)->prev)

/*
 *	Macro:		queue_end
 *	Function:
 *		Tests whether a new entry is really the end of
 *		the queue.
 *	Header:
 *		boolean_t queue_end(q, qe)
 *			queue_t q;
 *			queue_entry_t qe;
 */
#define	queue_end(q, qe)	((q) == (qe))

/*
 *	Macro:		queue_empty
 *	Function:
 *		Tests whether a queue is empty.
 *	Header:
 *		boolean_t queue_empty(q)
 *			queue_t q;
 */
#define	queue_empty(q)		queue_end((q), queue_first(q))


/*----------------------------------------------------------------*/
/*
 * Macros that operate on generic structures.  The queue
 * chain may be at any location within the structure, and there
 * may be more than one chain.
 */

/*
 *	Macro:		queue_enter
 *	Function:
 *		Insert a new element at the tail of the queue.
 *	Header:
 *		void queue_enter(q, elt, type, field)
 *			queue_t q;
 *			<type> elt;
 *			<type> is what's in our queue
 *			<field> is the chain field in (*<type>)
 */
#define queue_enter(head, elt, type, field)			\
MACRO_BEGIN							\
	register queue_entry_t __prev;				\
								\
	__prev = (head)->prev;					\
	if ((head) == __prev) {					\
		(head)->next = (queue_entry_t) (elt);		\
	}							\
	else {							\
		((type)__prev)->field.next = (queue_entry_t)(elt);\
	}							\
	(elt)->field.prev = __prev;				\
	(elt)->field.next = head;				\
	(head)->prev = (queue_entry_t) elt;			\
MACRO_END

/*
 *	Macro:		queue_enter_first
 *	Function:
 *		Insert a new element at the head of the queue.
 *	Header:
 *		void queue_enter_first(q, elt, type, field)
 *			queue_t q;
 *			<type> elt;
 *			<type> is what's in our queue
 *			<field> is the chain field in (*<type>)
 */
#define queue_enter_first(head, elt, type, field)		\
MACRO_BEGIN							\
	register queue_entry_t __next;				\
								\
	__next = (head)->next;					\
	if ((head) == __next) {					\
		(head)->prev = (queue_entry_t) (elt);		\
	}							\
	else {							\
		((type)__next)->field.prev = (queue_entry_t)(elt);\
	}							\
	(elt)->field.next = __next;				\
	(elt)->field.prev = head;				\
	(head)->next = (queue_entry_t) elt;			\
MACRO_END

/*
 *	Macro:		queue_insert_before
 *	Function:
 *		Insert a new element before a given element.
 *	Header:
 *		void queue_insert_before(q, elt, cur, type, field)
 *			queue_t q;
 *			<type> elt;
 *			<type> cur;
 *			<type> is what's in our queue
 *			<field> is the chain field in (*<type>)
 */
#define queue_insert_before(head, elt, cur, type, field)		\
MACRO_BEGIN								\
	register queue_entry_t __prev;					\
									\
	if ((head) == (queue_entry_t)(cur)) {				\
		(elt)->field.next = (head);				\
		if ((head)->next == (head)) {	/* only element */	\
			(elt)->field.prev = (head);			\
			(head)->next = (queue_entry_t)(elt);		\
		} else {			/* last element */	\
			__prev = (elt)->field.prev = (head)->prev;	\
			((type)__prev)->field.next = (queue_entry_t)(elt);\
		}							\
		(head)->prev = (queue_entry_t)(elt);			\
	} else {							\
		(elt)->field.next = (queue_entry_t)(cur);		\
		if ((head)->next == (queue_entry_t)(cur)) {		\
						/* first element */	\
			(elt)->field.prev = (head);			\
			(head)->next = (queue_entry_t)(elt);		\
		} else {			/* middle element */	\
			__prev = (elt)->field.prev = (cur)->field.prev;	\
			((type)__prev)->field.next = (queue_entry_t)(elt);\
		}							\
		(cur)->field.prev = (queue_entry_t)(elt);		\
	}								\
MACRO_END

/*
 *	Macro:		queue_insert_after
 *	Function:
 *		Insert a new element after a given element.
 *	Header:
 *		void queue_insert_after(q, elt, cur, type, field)
 *			queue_t q;
 *			<type> elt;
 *			<type> cur;
 *			<type> is what's in our queue
 *			<field> is the chain field in (*<type>)
 */
#define queue_insert_after(head, elt, cur, type, field)			\
MACRO_BEGIN								\
	register queue_entry_t __next;					\
									\
	if ((head) == (queue_entry_t)(cur)) {				\
		(elt)->field.prev = (head);				\
		if ((head)->next == (head)) {	/* only element */	\
			(elt)->field.next = (head);			\
			(head)->prev = (queue_entry_t)(elt);		\
		} else {			/* first element */	\
			__next = (elt)->field.next = (head)->next;	\
			((type)__next)->field.prev = (queue_entry_t)(elt);\
		}							\
		(head)->next = (queue_entry_t)(elt);			\
	} else {							\
		(elt)->field.prev = (queue_entry_t)(cur);		\
		if ((head)->prev == (queue_entry_t)(cur)) {		\
						/* last element */	\
			(elt)->field.next = (head);			\
			(head)->prev = (queue_entry_t)(elt);		\
		} else {			/* middle element */	\
			__next = (elt)->field.next = (cur)->field.next;	\
			((type)__next)->field.prev = (queue_entry_t)(elt);\
		}							\
		(cur)->field.next = (queue_entry_t)(elt);		\
	}								\
MACRO_END

/*
 *	Macro:		queue_field [internal use only]
 *	Function:
 *		Find the queue_chain_t (or queue_t) for the
 *		given element (thing) in the given queue (head)
 */
#define	queue_field(head, thing, type, field)			\
		(((head) == (thing)) ? (head) : &((type)(thing))->field)

/*
 *	Macro:		queue_remove
 *	Function:
 *		Remove an arbitrary item from the queue.
 *	Header:
 *		void queue_remove(q, qe, type, field)
 *			arguments as in queue_enter
 */
#define	queue_remove(head, elt, type, field)			\
MACRO_BEGIN							\
	register queue_entry_t	__next, __prev;			\
								\
	__next = (elt)->field.next;				\
	__prev = (elt)->field.prev;				\
								\
	if ((head) == __next)					\
		(head)->prev = __prev;				\
	else							\
		((type)__next)->field.prev = __prev;		\
								\
	if ((head) == __prev)					\
		(head)->next = __next;				\
	else							\
		((type)__prev)->field.next = __next;		\
								\
	(elt)->field.next = NULL;				\
	(elt)->field.prev = NULL;				\
MACRO_END

/*
 *	Macro:		queue_remove_first
 *	Function:
 *		Remove and return the entry at the head of
 *		the queue.
 *	Header:
 *		queue_remove_first(head, entry, type, field)
 *		entry is returned by reference
 */
#define	queue_remove_first(head, entry, type, field)		\
MACRO_BEGIN							\
	register queue_entry_t	__next;				\
								\
	(entry) = (type) ((head)->next);			\
	__next = (entry)->field.next;				\
								\
	if ((head) == __next)					\
		(head)->prev = (head);				\
	else							\
		((type)(__next))->field.prev = (head);		\
	(head)->next = __next;					\
								\
	(entry)->field.next = NULL;				\
	(entry)->field.prev = NULL;				\
MACRO_END

/*
 *	Macro:		queue_remove_last
 *	Function:
 *		Remove and return the entry at the tail of
 *		the queue.
 *	Header:
 *		queue_remove_last(head, entry, type, field)
 *		entry is returned by reference
 */
#define	queue_remove_last(head, entry, type, field)		\
MACRO_BEGIN							\
	register queue_entry_t	__prev;				\
								\
	(entry) = (type) ((head)->prev);			\
	__prev = (entry)->field.prev;				\
								\
	if ((head) == __prev)					\
		(head)->next = (head);				\
	else							\
		((type)(__prev))->field.next = (head);		\
	(head)->prev = __prev;					\
								\
	(entry)->field.next = NULL;				\
	(entry)->field.prev = NULL;				\
MACRO_END

/*
 *	Macro:		queue_assign
 */
#define	queue_assign(to, from, type, field)			\
MACRO_BEGIN							\
	((type)((from)->prev))->field.next = (to);		\
	((type)((from)->next))->field.prev = (to);		\
	*to = *from;						\
MACRO_END

/*
 *	Macro:		queue_new_head
 *	Function:
 *		rebase old queue to new queue head
 *	Header:
 *		queue_new_head(old, new, type, field)
 *			queue_t old;
 *			queue_t new;
 *			<type> is what's in our queue
 *                      <field> is the chain field in (*<type>)
 */
#define queue_new_head(old, new, type, field)			\
MACRO_BEGIN							\
	if (!queue_empty(old)) {				\
		*(new) = *(old);				\
		((type)((new)->next))->field.prev = (new);	\
		((type)((new)->prev))->field.next = (new);	\
	} else {						\
		queue_init(new);				\
	}							\
MACRO_END

/*
 *	Macro:		queue_iterate
 *	Function:
 *		iterate over each item in the queue.
 *		Generates a 'for' loop, setting elt to
 *		each item in turn (by reference).
 *	Header:
 *		queue_iterate(q, elt, type, field)
 *			queue_t q;
 *			<type> elt;
 *			<type> is what's in our queue
 *			<field> is the chain field in (*<type>)
 */
#define queue_iterate(head, elt, type, field)			\
	for ((elt) = (type) queue_first(head);			\
	     !queue_end((head), (queue_entry_t)(elt));		\
	     (elt) = (type) queue_next(&(elt)->field))

#ifdef	MACH_KERNEL_PRIVATE

#include <kern/lock.h>

/*----------------------------------------------------------------*/
/*
 *	Define macros for queues with locks.
 */
struct mpqueue_head {
	struct queue_entry	head;		/* header for queue */
	decl_simple_lock_data(,	lock)		/* lock for queue */
};

typedef struct mpqueue_head	mpqueue_head_t;

#define	round_mpq(size)		(size)

#define mpqueue_init(q)					\
MACRO_BEGIN						\
	queue_init(&(q)->head);				\
	simple_lock_init(&(q)->lock, 0);	\
MACRO_END

#define mpenqueue_tail(q, elt)				\
MACRO_BEGIN						\
	simple_lock(&(q)->lock);			\
	enqueue_tail(&(q)->head, elt);			\
	simple_unlock(&(q)->lock);			\
MACRO_END

#define mpdequeue_head(q, elt)				\
MACRO_BEGIN						\
	simple_lock(&(q)->lock);			\
	if (queue_empty(&(q)->head))			\
		*(elt) = 0;				\
	else						\
		*(elt) = dequeue_head(&(q)->head);	\
	simple_unlock(&(q)->lock);			\
MACRO_END

#endif	/* MACH_KERNEL_PRIVATE */

#endif	/* _KERN_QUEUE_H_ */
