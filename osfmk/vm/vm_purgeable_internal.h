/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

/*
 * Purgeable spelling rules
 * It is believed that the correct spelling is 
 * { 'p', 'u', 'r', 'g', 'e', 'a', 'b', 'l', 'e' }.
 * However, there is one published API that likes to spell it without the
 * first 'e', vm_purgable_control(). Since we can't change that API,
 * here are the rules.
 * All qualifiers defined in vm_purgable.h are spelled without the e.
 * All other qualifiers are spelled with the e.
 * Right now, there are remains of the wrong spelling throughout the code,
 * vm_object_t.purgable for example. We expect to change these on occasion.
 */

#ifndef __VM_PURGEABLE_INTERNAL__
#define __VM_PURGEABLE_INTERNAL__

#include <kern/queue.h>

enum purgeable_q_type {
	PURGEABLE_Q_TYPE_OBSOLETE,
	PURGEABLE_Q_TYPE_FIFO,
	PURGEABLE_Q_TYPE_LIFO,
	PURGEABLE_Q_TYPE_MAX
};

#if (CONFIG_TOKEN_QUEUE_SMALL == 1)
typedef uint16_t token_idx_t;
typedef uint16_t token_cnt_t;
#define TOKEN_COUNT_MAX UINT16_MAX
#else
typedef uint32_t token_idx_t;
typedef uint32_t token_cnt_t;
#define TOKEN_COUNT_MAX UINT32_MAX
#endif

#define NUM_VOLATILE_GROUPS 8
struct purgeable_q {
	token_idx_t token_q_head;    /* first token */
	token_idx_t token_q_tail;    /* last token  */
	token_idx_t token_q_unripe;  /* first token which is not ripe */
	int32_t new_pages;
	queue_head_t objq[NUM_VOLATILE_GROUPS];
	enum purgeable_q_type type;
#if MACH_ASSERT
	int debug_count_tokens;
	int debug_count_objects;
#endif
};

typedef struct purgeable_q * purgeable_q_t;

extern struct purgeable_q purgeable_queues[PURGEABLE_Q_TYPE_MAX];
extern int32_t token_new_pagecount;
#define TOKEN_NEW_PAGECOUNT_MAX INT32_MAX
extern int available_for_purge;


/*
 * Locking:
 * the token counters are protected by the vm_page_queue_lock, since they're
 * mostly used in that context and we don't want to do a lot of extra locking
 * the purgeable page queues are protected by a separate lock since they're
 * mostly used on a user context and we don't want any contention with the
 * pageout daemon.
 */
decl_lck_mtx_data(extern,vm_purgeable_queue_lock)

/* add a new token to queue. called by vm_object_purgeable_control */
/* enter with page queue locked */
kern_return_t vm_purgeable_token_add(purgeable_q_t queue);

/* enter with page queue locked */
void vm_purgeable_token_delete_first(purgeable_q_t queue);

/*
 * decrement token counters.
 * enter with page queue locked
 */
void vm_purgeable_q_advance_all(void);

/* the object purger. purges the next eligible object from memory. */
/* returns TRUE if an object was purged, otherwise FALSE. */
boolean_t vm_purgeable_object_purge_one(void);

/* purge all volatile objects now */
void vm_purgeable_object_purge_all(void);

/* insert purgeable object into queue */
void vm_purgeable_object_add(vm_object_t object, purgeable_q_t queue, int group);

/* look for object. If found, remove from purgeable queue. */
purgeable_q_t vm_purgeable_object_remove(vm_object_t object);

#endif /* __VM_PURGEABLE_INTERNAL__ */
