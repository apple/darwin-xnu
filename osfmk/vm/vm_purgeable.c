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

#include <mach/mach_types.h>
#include <vm/vm_page.h>
#include <vm/vm_kern.h>		/* kmem_alloc */
#include <vm/vm_purgeable_internal.h>
#include <sys/kdebug.h>
#include <kern/sched_prim.h>

struct token {
	token_cnt_t     count;
	token_idx_t     next;
};

struct token	*tokens;
token_idx_t	token_q_max_cnt = 0;
vm_size_t	token_q_cur_size = 0;

token_idx_t     token_free_idx = 0;		/* head of free queue */
token_idx_t     token_init_idx = 1;		/* token 0 is reserved!! */
int32_t		token_new_pagecount = 0;	/* count of pages that will
						 * be added onto token queue */

int             available_for_purge = 0;	/* increase when ripe token
						 * added, decrease when ripe
						 * token removed protect with
						 * page_queue_lock */

static int token_q_allocating = 0;		/* flag to singlethread allocator */

struct purgeable_q purgeable_queues[PURGEABLE_Q_TYPE_MAX];

#define TOKEN_ADD           0x40/* 0x100 */
#define TOKEN_DELETE        0x41/* 0x104 */
#define TOKEN_QUEUE_ADVANCE 0x42/* 0x108 actually means "token ripened" */
#define TOKEN_OBJECT_PURGED 0x43/* 0x10c */
#define OBJECT_ADDED        0x50/* 0x140 */
#define OBJECT_REMOVED      0x51/* 0x144 */

static token_idx_t vm_purgeable_token_remove_first(purgeable_q_t queue);

#if MACH_ASSERT
static void
vm_purgeable_token_check_queue(purgeable_q_t queue)
{
	int             token_cnt = 0, page_cnt = 0;
	token_idx_t     token = queue->token_q_head;
	token_idx_t     unripe = 0;
	int             our_inactive_count;

	while (token) {
		if (tokens[token].count != 0) {
			assert(queue->token_q_unripe);
			if (unripe == 0) {
				assert(token == queue->token_q_unripe);
				unripe = token;
			}
			page_cnt += tokens[token].count;
		}
		if (tokens[token].next == 0)
			assert(queue->token_q_tail == token);

		token_cnt++;
		token = tokens[token].next;
	}

	if (unripe)
		assert(queue->token_q_unripe == unripe);
	assert(token_cnt == queue->debug_count_tokens);
	
	/* obsolete queue doesn't maintain token counts */
	if(queue->type != PURGEABLE_Q_TYPE_OBSOLETE)
	{
		our_inactive_count = page_cnt + queue->new_pages + token_new_pagecount;
		assert(our_inactive_count >= 0);
		assert((uint32_t) our_inactive_count == vm_page_inactive_count);
	}
}
#endif

kern_return_t
vm_purgeable_token_add(purgeable_q_t queue)
{
	/* new token */
	token_idx_t     token;
	enum purgeable_q_type i;

find_available_token:

	if (token_free_idx) {				/* unused tokens available */
		token = token_free_idx;
		token_free_idx = tokens[token_free_idx].next;
	} else if (token_init_idx < token_q_max_cnt) {	/* lazy token array init */
		token = token_init_idx;
		token_init_idx++;
	} else {					/* allocate more memory */
		/* Wait if another thread is inside the memory alloc section */
		while(token_q_allocating) {
			wait_result_t res = thread_sleep_mutex((event_t)&token_q_allocating, 
							       &vm_page_queue_lock,
							       THREAD_UNINT);
			if(res != THREAD_AWAKENED) return KERN_ABORTED;
		};
		
		/* Check whether memory is still maxed out */
		if(token_init_idx < token_q_max_cnt)
			goto find_available_token;
		
		/* Still no memory. Allocate some. */
		token_q_allocating = 1;
		
		/* Drop page queue lock so we can allocate */
		vm_page_unlock_queues();
		
		struct token *new_loc;
		vm_size_t alloc_size = token_q_cur_size + PAGE_SIZE;
		kern_return_t result;
		
		if (token_q_cur_size) {
			result=kmem_realloc(kernel_map, (vm_offset_t)tokens, token_q_cur_size,
					    (vm_offset_t*)&new_loc, alloc_size);
		} else {
			result=kmem_alloc(kernel_map, (vm_offset_t*)&new_loc, alloc_size);
		}
		
		vm_page_lock_queues();
		
		if (result) {
			/* Unblock waiting threads */
			token_q_allocating = 0;
			thread_wakeup((event_t)&token_q_allocating);
			return result;
		}
		
		/* If we get here, we allocated new memory. Update pointers and
		 * dealloc old range */
		struct token *old_tokens=tokens;
		tokens=new_loc;
		vm_size_t old_token_q_cur_size=token_q_cur_size;
		token_q_cur_size=alloc_size;
		token_q_max_cnt = token_q_cur_size / sizeof(struct token);
		assert (token_init_idx < token_q_max_cnt);	/* We must have a free token now */
		
		if (old_token_q_cur_size) {	/* clean up old mapping */
			vm_page_unlock_queues();
			/* kmem_realloc leaves the old region mapped. Get rid of it. */
			kmem_free(kernel_map, (vm_offset_t)old_tokens, old_token_q_cur_size);
			vm_page_lock_queues();
		}
		
		/* Unblock waiting threads */
		token_q_allocating = 0;
		thread_wakeup((event_t)&token_q_allocating);
		
		goto find_available_token;
	}
	
	assert (token);
	
	/*
	 * the new pagecount we got need to be applied to all queues except
	 * obsolete
	 */
	for (i = PURGEABLE_Q_TYPE_FIFO; i < PURGEABLE_Q_TYPE_MAX; i++) {
		int64_t pages = purgeable_queues[i].new_pages += token_new_pagecount;
		assert(pages >= 0);
		assert(pages <= TOKEN_COUNT_MAX);
		purgeable_queues[i].new_pages=pages;
	}
	token_new_pagecount = 0;

	/* set token counter value */
	if (queue->type != PURGEABLE_Q_TYPE_OBSOLETE)
		tokens[token].count = queue->new_pages;
	else
		tokens[token].count = 0;	/* all obsolete items are
						 * ripe immediately */
	queue->new_pages = 0;

	/* put token on token counter list */
	tokens[token].next = 0;
	if (queue->token_q_tail == 0) {
		assert(queue->token_q_head == 0 && queue->token_q_unripe == 0);
		queue->token_q_head = token;
	} else {
		tokens[queue->token_q_tail].next = token;
	}
	if (queue->token_q_unripe == 0) {	/* only ripe tokens (token
						 * count == 0) in queue */
		if (tokens[token].count > 0)
			queue->token_q_unripe = token;	/* first unripe token */
		else
			available_for_purge++;	/* added a ripe token?
						 * increase available count */
	}
	queue->token_q_tail = token;

#if MACH_ASSERT
	queue->debug_count_tokens++;
	/* Check both queues, since we modified the new_pages count on each */
	vm_purgeable_token_check_queue(&purgeable_queues[PURGEABLE_Q_TYPE_FIFO]);
	vm_purgeable_token_check_queue(&purgeable_queues[PURGEABLE_Q_TYPE_LIFO]);

	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, TOKEN_ADD)),
			      queue->type,
			      tokens[token].count,	/* num pages on token
							 * (last token) */
			      queue->debug_count_tokens,
			      0,
			      0);
#endif

	return KERN_SUCCESS;
}

/*
 * Remove first token from queue and return its index. Add its count to the
 * count of the next token.
 */
static token_idx_t 
vm_purgeable_token_remove_first(purgeable_q_t queue)
{
	token_idx_t     token;
	token = queue->token_q_head;

	assert(token);

	if (token) {
		assert(queue->token_q_tail);
		if (queue->token_q_head == queue->token_q_unripe) {
			/* no ripe tokens... must move unripe pointer */
			queue->token_q_unripe = tokens[token].next;
		} else {
			/* we're removing a ripe token. decrease count */
			available_for_purge--;
			assert(available_for_purge >= 0);
		}

		if (queue->token_q_tail == queue->token_q_head)
			assert(tokens[token].next == 0);

		queue->token_q_head = tokens[token].next;
		if (queue->token_q_head) {
			tokens[queue->token_q_head].count += tokens[token].count;
		} else {
			/* currently no other tokens in the queue */
			/*
			 * the page count must be added to the next newly
			 * created token
			 */
			queue->new_pages += tokens[token].count;
			/* if head is zero, tail is too */
			queue->token_q_tail = 0;
		}

#if MACH_ASSERT
		queue->debug_count_tokens--;
		vm_purgeable_token_check_queue(queue);

		KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, TOKEN_DELETE)),
				      queue->type,
				      tokens[queue->token_q_head].count,	/* num pages on new
										 * first token */
				      token_new_pagecount,	/* num pages waiting for
								 * next token */
				      available_for_purge,
				      0);
#endif
	}
	return token;
}

/* Delete first token from queue. Return token to token queue. */
void
vm_purgeable_token_delete_first(purgeable_q_t queue)
{
	token_idx_t     token = vm_purgeable_token_remove_first(queue);

	if (token) {
		/* stick removed token on free queue */
		tokens[token].next = token_free_idx;
		token_free_idx = token;
	}
}


void
vm_purgeable_q_advance_all()
{
	/* check queue counters - if they get really large, scale them back.
	 * They tend to get that large when there is no purgeable queue action */
	int i;
	if(token_new_pagecount > (TOKEN_NEW_PAGECOUNT_MAX >> 1))	/* a system idling years might get there */
	{
		for (i = PURGEABLE_Q_TYPE_FIFO; i < PURGEABLE_Q_TYPE_MAX; i++) {
			int64_t pages = purgeable_queues[i].new_pages += token_new_pagecount;
			assert(pages >= 0);
			assert(pages <= TOKEN_COUNT_MAX);
			purgeable_queues[i].new_pages=pages;
		}
		token_new_pagecount = 0;
	}
	
	/*
	 * Decrement token counters. A token counter can be zero, this means the
	 * object is ripe to be purged. It is not purged immediately, because that
	 * could cause several objects to be purged even if purging one would satisfy
	 * the memory needs. Instead, the pageout thread purges one after the other
	 * by calling vm_purgeable_object_purge_one and then rechecking the memory
	 * balance.
	 *
	 * No need to advance obsolete queue - all items are ripe there,
	 * always
	 */
	for (i = PURGEABLE_Q_TYPE_FIFO; i < PURGEABLE_Q_TYPE_MAX; i++) {
		purgeable_q_t queue = &purgeable_queues[i];
		uint32_t num_pages = 1;
		
		/* Iterate over tokens as long as there are unripe tokens. */
		while (queue->token_q_unripe) {
			if (tokens[queue->token_q_unripe].count && num_pages)
			{
				tokens[queue->token_q_unripe].count -= 1;
				num_pages -= 1;
			}

			if (tokens[queue->token_q_unripe].count == 0) {
				queue->token_q_unripe = tokens[queue->token_q_unripe].next;
				available_for_purge++;
				KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, TOKEN_QUEUE_ADVANCE)),
						      queue->type,
						      tokens[queue->token_q_head].count,	/* num pages on new
											 * first token */
						      0,
						      available_for_purge,
						      0);
				continue;	/* One token ripened. Make sure to
						 * check the next. */
			}
			if (num_pages == 0)
				break;	/* Current token not ripe and no more pages.
					 * Work done. */
		}

		/*
		 * if there are no unripe tokens in the queue, decrement the
		 * new_pages counter instead new_pages can be negative, but must be
		 * canceled out by token_new_pagecount -- since inactive queue as a
		 * whole always contains a nonnegative number of pages
		 */
		if (!queue->token_q_unripe) {
			queue->new_pages -= num_pages;
			assert((int32_t) token_new_pagecount + queue->new_pages >= 0);
		}
#if MACH_ASSERT
		vm_purgeable_token_check_queue(queue);
#endif
	}
}

/*
 * grab any ripe object and purge it obsolete queue first. then, go through
 * each volatile group. Select a queue with a ripe token.
 * Start with first group (0)
 * 1. Look at queue. Is there an object?
 *   Yes - purge it. Remove token.
 *   No - check other queue. Is there an object?
 *     No - increment group, then go to (1)
 *     Yes - purge it. Remove token. If there is no ripe token, remove ripe
 *      token from other queue and migrate unripe token from this
 *      queue to other queue.
 */
static void
vm_purgeable_token_remove_ripe(purgeable_q_t queue)
{
	assert(queue->token_q_head && tokens[queue->token_q_head].count == 0);
	/* return token to free list. advance token list. */
	token_idx_t     new_head = tokens[queue->token_q_head].next;
	tokens[queue->token_q_head].next = token_free_idx;
	token_free_idx = queue->token_q_head;
	queue->token_q_head = new_head;
	if (new_head == 0)
		queue->token_q_tail = 0;

#if MACH_ASSERT
	queue->debug_count_tokens--;
	vm_purgeable_token_check_queue(queue);
#endif

	available_for_purge--;
	assert(available_for_purge >= 0);
}

/*
 * Delete a ripe token from the given queue. If there are no ripe tokens on
 * that queue, delete a ripe token from queue2, and migrate an unripe token
 * from queue to queue2
 */
static void
vm_purgeable_token_choose_and_delete_ripe(purgeable_q_t queue, purgeable_q_t queue2)
{
	assert(queue->token_q_head);

	if (tokens[queue->token_q_head].count == 0) {
		/* This queue has a ripe token. Remove. */
		vm_purgeable_token_remove_ripe(queue);
	} else {
		assert(queue2);
		/*
		 * queue2 must have a ripe token. Remove, and migrate one
		 * from queue to queue2.
		 */
		vm_purgeable_token_remove_ripe(queue2);
		/* migrate unripe token */
		token_idx_t     token;
		token_cnt_t     count;

		/* remove token from queue1 */
		assert(queue->token_q_unripe == queue->token_q_head);	/* queue1 had no unripe
									 * tokens, remember? */
		token = vm_purgeable_token_remove_first(queue);
		assert(token);

		count = tokens[token].count;

		/* migrate to queue2 */
		/* go to migration target loc */
		token_idx_t    *token_in_queue2 = &queue2->token_q_head;
		while (*token_in_queue2 && count > tokens[*token_in_queue2].count) {
			count -= tokens[*token_in_queue2].count;
			token_in_queue2 = &tokens[*token_in_queue2].next;
		}

		if ((*token_in_queue2 == queue2->token_q_unripe) ||	/* becomes the first
									 * unripe token */
		    (queue2->token_q_unripe == 0))
			queue2->token_q_unripe = token;	/* must update unripe
							 * pointer */

		/* insert token */
		tokens[token].count = count;
		tokens[token].next = *token_in_queue2;

		/*
		 * if inserting at end, reduce new_pages by that value if
		 * inserting before token, reduce counter of that token
		 */
		if (*token_in_queue2 == 0) {	/* insertion at end of queue2 */
			queue2->token_q_tail = token;	/* must update tail
							 * pointer */
			assert(queue2->new_pages >= (int32_t) count);
			queue2->new_pages -= count;
		} else {
			assert(tokens[*token_in_queue2].count >= count);
			tokens[*token_in_queue2].count -= count;
		}
		*token_in_queue2 = token;

#if MACH_ASSERT
		queue2->debug_count_tokens++;
		vm_purgeable_token_check_queue(queue2);
#endif
	}
}

/* Find an object that can be locked. Returns locked object. */
static          vm_object_t
vm_purgeable_object_find_and_lock(purgeable_q_t queue, int group)
{
	/*
	 * Usually we would pick the first element from a queue. However, we
	 * might not be able to get a lock on it, in which case we try the
	 * remaining elements in order.
	 */

	vm_object_t     object;
	for (object = (vm_object_t) queue_first(&queue->objq[group]);
	     !queue_end(&queue->objq[group], (queue_entry_t) object);
	     object = (vm_object_t) queue_next(&object->objq)) {
		if (vm_object_lock_try(object)) {
			/* Locked. Great. We'll take it. Remove and return. */
			queue_remove(&queue->objq[group], object,
				     vm_object_t, objq);
			object->objq.next = 0;
			object->objq.prev = 0;
#if MACH_ASSERT
			queue->debug_count_objects--;
#endif
			return object;
		}
	}

	return 0;
}

void
vm_purgeable_object_purge_one(void)
{
	enum purgeable_q_type i;
	int             group;
	vm_object_t     object = 0;
	purgeable_q_t   queue, queue2;

	mutex_lock(&vm_purgeable_queue_lock);
	/* Cycle through all queues */
	for (i = PURGEABLE_Q_TYPE_OBSOLETE; i < PURGEABLE_Q_TYPE_MAX; i++) {
		queue = &purgeable_queues[i];

		/*
		 * Are there any ripe tokens on this queue? If yes, we'll
		 * find an object to purge there
		 */
		if (!(queue->token_q_head && tokens[queue->token_q_head].count == 0))
			continue;	/* no token? Look at next purgeable
					 * queue */

		/*
		 * Now look through all groups, starting from the lowest. If
		 * we find an object in that group, try to lock it (this can
		 * fail). If locking is successful, we can drop the queue
		 * lock, remove a token and then purge the object.
		 */
		for (group = 0; group < NUM_VOLATILE_GROUPS; group++) {
			if (!queue_empty(&queue->objq[group]) && 
			    (object = vm_purgeable_object_find_and_lock(queue, group))) {
				mutex_unlock(&vm_purgeable_queue_lock);
				vm_purgeable_token_choose_and_delete_ripe(queue, 0);
				goto purge_now;
			}
			if (i != PURGEABLE_Q_TYPE_OBSOLETE) { 
				/* This is the token migration case, and it works between
				 * FIFO and LIFO only */
				queue2 = &purgeable_queues[i != PURGEABLE_Q_TYPE_FIFO ? 
							   PURGEABLE_Q_TYPE_FIFO : 
							   PURGEABLE_Q_TYPE_LIFO];

				if (!queue_empty(&queue2->objq[group]) && 
				    (object = vm_purgeable_object_find_and_lock(queue2, group))) {
					mutex_unlock(&vm_purgeable_queue_lock);
					vm_purgeable_token_choose_and_delete_ripe(queue2, queue);
					goto purge_now;
				}
			}
			assert(queue->debug_count_objects >= 0);
		}
	}
	/*
         * because we have to do a try_lock on the objects which could fail,
         * we could end up with no object to purge at this time, even though
         * we have objects in a purgeable state
         */
	mutex_unlock(&vm_purgeable_queue_lock);
	return;

purge_now:

	assert(object);
	(void) vm_object_purge(object);
	vm_object_unlock(object);

	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, TOKEN_OBJECT_PURGED)),
			      (unsigned int) object,	/* purged object */
			      0,
			      available_for_purge,
			      0,
			      0);
}

void
vm_purgeable_object_add(vm_object_t object, purgeable_q_t queue, int group)
{
	mutex_lock(&vm_purgeable_queue_lock);

	if (queue->type == PURGEABLE_Q_TYPE_OBSOLETE)
		group = 0;
	if (queue->type != PURGEABLE_Q_TYPE_LIFO)	/* fifo and obsolete are
							 * fifo-queued */
		queue_enter(&queue->objq[group], object, vm_object_t, objq);	/* last to die */
	else
		queue_enter_first(&queue->objq[group], object, vm_object_t, objq);	/* first to die */

#if MACH_ASSERT
	queue->debug_count_objects++;
	KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, OBJECT_ADDED)),
			      0,
			      tokens[queue->token_q_head].count,
			      queue->type,
			      group,
			      0);
#endif

	mutex_unlock(&vm_purgeable_queue_lock);
}

/* Look for object. If found, remove from purgeable queue. */
purgeable_q_t
vm_purgeable_object_remove(vm_object_t object)
{
	enum purgeable_q_type i;
	int             group;

	mutex_lock(&vm_purgeable_queue_lock);
	for (i = PURGEABLE_Q_TYPE_OBSOLETE; i < PURGEABLE_Q_TYPE_MAX; i++) {
		purgeable_q_t   queue = &purgeable_queues[i];
		for (group = 0; group < NUM_VOLATILE_GROUPS; group++) {
			vm_object_t     o;
			for (o = (vm_object_t) queue_first(&queue->objq[group]);
			 !queue_end(&queue->objq[group], (queue_entry_t) o);
			     o = (vm_object_t) queue_next(&o->objq)) {
				if (o == object) {
					queue_remove(&queue->objq[group], object,
						     vm_object_t, objq);
#if MACH_ASSERT
					queue->debug_count_objects--;
					KERNEL_DEBUG_CONSTANT((MACHDBG_CODE(DBG_MACH_VM, OBJECT_REMOVED)),
							      0,
					  tokens[queue->token_q_head].count,
							      queue->type,
							      group,
							      0);
#endif
					mutex_unlock(&vm_purgeable_queue_lock);
					object->objq.next = 0;
					object->objq.prev = 0;
					return &purgeable_queues[i];
				}
			}
		}
	}
	mutex_unlock(&vm_purgeable_queue_lock);
	return 0;
}
