/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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

#include <kern/affinity.h>
#include <kern/task.h>
#include <kern/kalloc.h>
#include <machine/cpu_affinity.h>

/*
 * Affinity involves 2 objects:
 * - affinity namespace:
 *	shared by a task family, this controls affinity tag lookup and
 *	allocation; it anchors all affinity sets in one namespace
 * - affinity set:
 * 	anchors all threads with membership of this affinity set
 *	and which share an affinity tag in the owning namespace.
 * 
 * Locking:
 * - The task lock protects the creation of an affinity namespace.
 * - The affinity namespace mutex protects the inheritance of a namespace
 *   and its thread membership. This includes its destruction when the task
 *   reference count goes to zero.
 * - The thread mutex protects a thread's affinity set membership, but in
 *   addition, the thread_lock is taken to write thread->affinity_set since this
 *   field (representng the active affinity set) is read by the scheduler.
 * 
 * The lock ordering is: task lock, thread mutex, namespace mutex, thread lock.
 */

#if AFFINITY_DEBUG
#define DBG(x...)	kprintf("DBG: " x)
#else
#define DBG(x...)
#endif

struct affinity_space {
	lck_mtx_t		aspc_lock;
	uint32_t		aspc_task_count;
	queue_head_t	aspc_affinities;
};
typedef struct affinity_space *affinity_space_t;

static affinity_space_t affinity_space_alloc(void);
static void affinity_space_free(affinity_space_t aspc);
static affinity_set_t affinity_set_alloc(void);
static void affinity_set_free(affinity_set_t aset);
static affinity_set_t affinity_set_find(affinity_space_t aspc, uint32_t tag);
static void affinity_set_place(affinity_space_t aspc, affinity_set_t aset);
static void affinity_set_add(affinity_set_t aset, thread_t thread);
static affinity_set_t affinity_set_remove(affinity_set_t aset, thread_t thread);

/*
 * The following globals may be modified by the sysctls
 *   kern.affinity_sets_enabled	- disables hinting if cleared
 *   kern.affinity_sets_mapping	- controls cache distribution policy
 * See bsd/kern_sysctl.c
 */
boolean_t	affinity_sets_enabled = TRUE;
int		affinity_sets_mapping = 1;

boolean_t
thread_affinity_is_supported(void)
{
	return (ml_get_max_affinity_sets() != 0);
}


/*
 * thread_affinity_get() 
 * Return the affinity tag for a thread. 
 * Called with the thread mutex held.
 */
uint32_t
thread_affinity_get(thread_t thread)
{
	uint32_t tag;

	if (thread->affinity_set != NULL)
		tag = thread->affinity_set->aset_tag;
	else
		tag = THREAD_AFFINITY_TAG_NULL;

	return tag;
}


/*
 * thread_affinity_set() 
 * Place a thread in an affinity set identified by a tag.
 * Called with thread referenced but not locked.
 */
kern_return_t
thread_affinity_set(thread_t thread, uint32_t tag)
{
	affinity_set_t		aset;
	affinity_set_t		empty_aset = NULL;
	affinity_space_t	aspc;
	affinity_space_t	new_aspc = NULL;

	DBG("thread_affinity_set(%p,%u)\n", thread, tag);

	task_lock(thread->task);
	aspc = thread->task->affinity_space;
	if (aspc == NULL) {
		task_unlock(thread->task);
		new_aspc = affinity_space_alloc();
		if (new_aspc == NULL)
			return KERN_RESOURCE_SHORTAGE;
		task_lock(thread->task);
		if (thread->task->affinity_space == NULL) {
			thread->task->affinity_space = new_aspc;
			new_aspc = NULL;
		}
		aspc = thread->task->affinity_space;
	}
	task_unlock(thread->task);
	if (new_aspc)
		affinity_space_free(new_aspc);

	thread_mtx_lock(thread);
	if (!thread->active) {
		/* Beaten to lock and the thread is dead */
		thread_mtx_unlock(thread);
		return KERN_TERMINATED;
	}

	lck_mtx_lock(&aspc->aspc_lock);
	aset = thread->affinity_set;
	if (aset != NULL) {
		/*
		 * Remove thread from current affinity set
		 */
		DBG("thread_affinity_set(%p,%u) removing from aset %p\n",
			thread, tag, aset);
		empty_aset = affinity_set_remove(aset, thread);
	}

	if (tag != THREAD_AFFINITY_TAG_NULL) {
		aset = affinity_set_find(aspc, tag);
		if (aset != NULL) {
			/*
			 * Add thread to existing affinity set
			 */
			DBG("thread_affinity_set(%p,%u) found aset %p\n",
				thread, tag, aset);
		} else {
			/*
			 * Use the new affinity set, add this thread
			 * and place it in a suitable processor set.
			 */
			if (empty_aset != NULL) {
				aset = empty_aset;
				empty_aset = NULL;
			} else {
				aset = affinity_set_alloc();
				if (aset == NULL) {
					lck_mtx_unlock(&aspc->aspc_lock);
					thread_mtx_unlock(thread);
					return KERN_RESOURCE_SHORTAGE;
				}
			}
			DBG("thread_affinity_set(%p,%u) (re-)using aset %p\n",
				thread, tag, aset);
			aset->aset_tag = tag;
			affinity_set_place(aspc, aset);
		}
		affinity_set_add(aset, thread);
	}

	lck_mtx_unlock(&aspc->aspc_lock);
	thread_mtx_unlock(thread);

	/*
	 * If we wound up not using an empty aset we created,
	 * free it here.
	 */
	if (empty_aset != NULL)
		affinity_set_free(empty_aset);

	if (thread == current_thread())
	        thread_block(THREAD_CONTINUE_NULL);

	return KERN_SUCCESS;
}

/*
 * task_affinity_create()
 * Called from task create.
 */
void
task_affinity_create(task_t parent_task, task_t child_task)
{
	affinity_space_t	aspc = parent_task->affinity_space;

	DBG("task_affinity_create(%p,%p)\n", parent_task, child_task);

	assert(aspc);

	/*
	 * Bump the task reference count on the shared namespace and
	 * give it to the child.
	 */
	lck_mtx_lock(&aspc->aspc_lock);
	aspc->aspc_task_count++;
	child_task->affinity_space = aspc;
	lck_mtx_unlock(&aspc->aspc_lock);
}

/*
 * task_affinity_deallocate()
 * Called from task_deallocate() when there's a namespace to dereference.
 */
void
task_affinity_deallocate(task_t	task)
{
	affinity_space_t	aspc = task->affinity_space;

	DBG("task_affinity_deallocate(%p) aspc %p task_count %d\n",
		task, aspc, aspc->aspc_task_count);

	lck_mtx_lock(&aspc->aspc_lock);
	if (--(aspc->aspc_task_count) == 0) {
		assert(queue_empty(&aspc->aspc_affinities));
		lck_mtx_unlock(&aspc->aspc_lock);
		affinity_space_free(aspc);
	} else {
		lck_mtx_unlock(&aspc->aspc_lock);
	}
}

/*
 * task_affinity_info()
 * Return affinity tag info (number, min, max) for the task.
 *
 * Conditions: task is locked.
 */
kern_return_t
task_affinity_info(
	task_t			task,
	task_info_t		task_info_out,
	mach_msg_type_number_t	*task_info_count)
{
	affinity_set_t			aset;
	affinity_space_t		aspc;
	task_affinity_tag_info_t	info;

	*task_info_count = TASK_AFFINITY_TAG_INFO_COUNT;
	info = (task_affinity_tag_info_t) task_info_out;
	info->set_count = 0;
	info->task_count = 0;
	info->min = THREAD_AFFINITY_TAG_NULL;
	info->max = THREAD_AFFINITY_TAG_NULL;

	aspc = task->affinity_space;
	if (aspc) {
		lck_mtx_lock(&aspc->aspc_lock);
		queue_iterate(&aspc->aspc_affinities,
				 aset, affinity_set_t, aset_affinities) {	
			info->set_count++;
			if (info->min == THREAD_AFFINITY_TAG_NULL ||
			    aset->aset_tag < (uint32_t) info->min)
				info->min = aset->aset_tag;
			if (info->max == THREAD_AFFINITY_TAG_NULL ||
			    aset->aset_tag > (uint32_t) info->max)
				info->max = aset->aset_tag;
		}
		info->task_count = aspc->aspc_task_count;
		lck_mtx_unlock(&aspc->aspc_lock);
	}
	return KERN_SUCCESS;
}

/*
 * Called from thread_dup() during fork() with child's mutex held.
 * Set the child into the parent's affinity set.
 * Note the affinity space is shared.
 */
void
thread_affinity_dup(thread_t parent, thread_t child)
{
	affinity_set_t			aset;
	affinity_space_t		aspc;

	thread_mtx_lock(parent);
	aset = parent->affinity_set;
	DBG("thread_affinity_dup(%p,%p) aset %p\n", parent, child, aset);
	if (aset == NULL) {
		thread_mtx_unlock(parent);
		return;
	}

	aspc = aset->aset_space;
	assert(aspc == parent->task->affinity_space);
	assert(aspc == child->task->affinity_space);

	lck_mtx_lock(&aspc->aspc_lock);
	affinity_set_add(aset, child);
	lck_mtx_unlock(&aspc->aspc_lock);

	thread_mtx_unlock(parent);
}

/*
 * thread_affinity_terminate() 
 * Remove thread from any affinity set.
 * Called with the thread mutex locked.
 */
void
thread_affinity_terminate(thread_t thread)
{
	affinity_set_t		aset = thread->affinity_set;
	affinity_space_t	aspc;

	DBG("thread_affinity_terminate(%p)\n", thread);

	aspc = aset->aset_space;
	lck_mtx_lock(&aspc->aspc_lock);
	if (affinity_set_remove(aset, thread)) {
		affinity_set_free(aset);
	}
	lck_mtx_unlock(&aspc->aspc_lock);
}

/*
 * thread_affinity_exec()
 * Called from execve() to cancel any current affinity - a new image implies
 * the calling thread terminates any expressed or inherited affinity.
 */
void
thread_affinity_exec(thread_t thread)
{
	if (thread->affinity_set != AFFINITY_SET_NULL)
		thread_affinity_terminate(thread);
}

/*
 * Create an empty affinity namespace data structure.
 */
static affinity_space_t
affinity_space_alloc(void) 
{
	affinity_space_t	aspc;

	aspc = (affinity_space_t) kalloc(sizeof(struct affinity_space));
	if (aspc == NULL)
		return NULL;

	lck_mtx_init(&aspc->aspc_lock, &task_lck_grp, &task_lck_attr);
	queue_init(&aspc->aspc_affinities);
	aspc->aspc_task_count = 1;

	DBG("affinity_space_create() returns %p\n", aspc);
	return aspc;
}

/*
 * Destroy the given empty affinity namespace data structure.
 */
static void
affinity_space_free(affinity_space_t aspc)
{
	assert(queue_empty(&aspc->aspc_affinities));

	lck_mtx_destroy(&aspc->aspc_lock, &task_lck_grp);
	DBG("affinity_space_free(%p)\n", aspc);
	kfree(aspc, sizeof(struct affinity_space));
}


/*
 * Create an empty affinity set data structure
 * entering it into a list anchored by the owning task.
 */
static affinity_set_t
affinity_set_alloc(void) 
{
	affinity_set_t	aset;

	aset = (affinity_set_t) kalloc(sizeof(struct affinity_set));
	if (aset == NULL)
		return NULL;

	aset->aset_thread_count = 0;
	queue_init(&aset->aset_affinities);
	queue_init(&aset->aset_threads);
	aset->aset_num = 0;
	aset->aset_pset = PROCESSOR_SET_NULL;
	aset->aset_space = NULL;

	DBG("affinity_set_create() returns %p\n", aset);
	return aset;
}

/*
 * Destroy the given empty affinity set data structure
 * after removing it from the parent task.
 */
static void
affinity_set_free(affinity_set_t aset)
{
	assert(queue_empty(&aset->aset_threads));

	DBG("affinity_set_free(%p)\n", aset);
	kfree(aset, sizeof(struct affinity_set));
}

/*
 * Add a thread to an affinity set.
 * The caller must have the thread mutex and space locked.
 */
static void
affinity_set_add(affinity_set_t aset, thread_t thread)
{
	spl_t	s;

	DBG("affinity_set_add(%p,%p)\n", aset, thread);
	queue_enter(&aset->aset_threads,
		thread, thread_t, affinity_threads);
	aset->aset_thread_count++;
	s = splsched();
	thread_lock(thread);
	thread->affinity_set = affinity_sets_enabled ? aset : NULL;
	thread_unlock(thread);
	splx(s);
}

/*
 * Remove a thread from an affinity set returning the set if now empty.
 * The caller must have the thread mutex and space locked.
 */
static affinity_set_t
affinity_set_remove(affinity_set_t aset, thread_t thread)
{
	spl_t	s;

	s = splsched();
	thread_lock(thread);
	thread->affinity_set = NULL;
	thread_unlock(thread);
	splx(s);

	aset->aset_thread_count--;
	queue_remove(&aset->aset_threads,
		thread, thread_t, affinity_threads);
	if (queue_empty(&aset->aset_threads)) {
		queue_remove(&aset->aset_space->aspc_affinities,
				aset, affinity_set_t, aset_affinities);
		assert(aset->aset_thread_count == 0);
		aset->aset_tag = THREAD_AFFINITY_TAG_NULL;
		aset->aset_num = 0;
		aset->aset_pset = PROCESSOR_SET_NULL;
		aset->aset_space = NULL;
		DBG("affinity_set_remove(%p,%p) set now empty\n", aset, thread);
		return aset;
	} else {
		DBG("affinity_set_remove(%p,%p)\n", aset, thread);
		return NULL;
	}
}

/*
 * Find an affinity set in the parent task with the given affinity tag.
 * The caller must have the space locked.
 */
static affinity_set_t
affinity_set_find(affinity_space_t space, uint32_t tag)
{
	affinity_set_t	aset;

	queue_iterate(&space->aspc_affinities,
			 aset, affinity_set_t, aset_affinities) {	
		if (aset->aset_tag == tag) {
			DBG("affinity_set_find(%p,%u) finds %p\n",
		 	    space, tag, aset);
			return aset;
		}
	}
	DBG("affinity_set_find(%p,%u) not found\n", space, tag);
	return NULL;
}

/*
 * affinity_set_place() assigns an affinity set to a suitable processor_set.
 * The selection criteria is:
 *  - the set currently occupied by the least number of affinities
 *    belonging to the owning the task.
 * The caller must have the space locked.
 */
static void
affinity_set_place(affinity_space_t aspc, affinity_set_t new_aset)
{
	unsigned int	num_cpu_asets = ml_get_max_affinity_sets();
	unsigned int	set_occupancy[num_cpu_asets];
	unsigned int	i;
	unsigned int	i_least_occupied;
	affinity_set_t	aset;

	for (i = 0; i < num_cpu_asets; i++)
		set_occupancy[i] = 0;

	/*
	 * Scan the affinity sets calculating the number of sets
	 * occupy the available physical affinities.
	 */
	queue_iterate(&aspc->aspc_affinities,
			 aset, affinity_set_t, aset_affinities) {
		if(aset->aset_num < num_cpu_asets)
			set_occupancy[aset->aset_num]++;
		else
			panic("aset_num = %d in %s\n", aset->aset_num, __FUNCTION__);
	}

	/*
	 * Find the least occupied set (or the first empty set).
	 * To distribute placements somewhat, start searching from
	 * a cpu affinity chosen randomly per namespace:
	 *   [(unsigned int)aspc % 127] % num_cpu_asets
	 * unless this mapping policy is overridden.
	 */
	if (affinity_sets_mapping == 0)
		i_least_occupied = 0;
	else
		i_least_occupied = (unsigned int)(((uintptr_t)aspc % 127) % num_cpu_asets);
	for (i = 0; i < num_cpu_asets; i++) {
		unsigned int	j = (i_least_occupied + i) % num_cpu_asets;
		if (set_occupancy[j] == 0) {
			i_least_occupied = j;
			break;
		}
		if (set_occupancy[j] < set_occupancy[i_least_occupied])
			i_least_occupied = j;
	}
	new_aset->aset_num = i_least_occupied;
	new_aset->aset_pset = ml_affinity_to_pset(i_least_occupied);

	/* Add the new affinity set to the group */
	new_aset->aset_space = aspc;
	queue_enter(&aspc->aspc_affinities,
			new_aset, affinity_set_t, aset_affinities);

	DBG("affinity_set_place(%p,%p) selected affinity %u pset %p\n",
	    aspc, new_aset, new_aset->aset_num, new_aset->aset_pset);
}
