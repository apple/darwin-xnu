/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */
/*      
 *	        File:	kern/task_swap.c
 *      
 *	Task residency management primitives implementation.
 */
#include <mach_assert.h>
#include <task_swapper.h>

#include <kern/spl.h>
#include <kern/lock.h>
#include <kern/queue.h>
#include <kern/host.h>
#include <kern/task.h>
#include <kern/task_swap.h>
#include <kern/thread.h>
#include <kern/thread_swap.h>
#include <kern/host_statistics.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <mach/policy.h>

#include <ipc/ipc_port.h>	/* We use something from in here */

/*
 * Note:  if TASK_SWAPPER is disabled, then this file defines only
 * a stub version of task_swappable(), so that the service can always
 * be defined, even if swapping has been configured out of the kernel.
 */
#if TASK_SWAPPER

/* temporary debug flags */
#define TASK_SW_DEBUG 1
#define TASK_SW_STATS 1

int task_swap_debug = 0;
int task_swap_stats = 0;
int task_swap_enable = 1;
int task_swap_on = 1;

queue_head_t	swapped_tasks;		/* completely swapped out tasks */
queue_head_t	swapout_thread_q;	/* threads to be swapped out */
mutex_t		task_swapper_lock;	/* protects above queue */

#define task_swapper_lock()	mutex_lock(&task_swapper_lock)
#define task_swapper_unlock()	mutex_unlock(&task_swapper_lock)

queue_head_t	eligible_tasks;		/* tasks eligible for swapout */
mutex_t		task_swapout_list_lock;	/* protects above queue */
#define task_swapout_lock()	mutex_lock(&task_swapout_list_lock)
#define task_swapout_unlock()	mutex_unlock(&task_swapout_list_lock)

/*
 * The next section of constants and globals are tunable parameters
 * used in making swapping decisions.  They may be changed dynamically
 * without adversely affecting the robustness of the system; however,
 * the policy will change, one way or the other.
 */

#define SHORT_AVG_INTERVAL	5	/* in seconds */
#define LONG_AVG_INTERVAL	30	/* in seconds */
#define AVE_SCALE		1024

unsigned int short_avg_interval = SHORT_AVG_INTERVAL;
unsigned int long_avg_interval = LONG_AVG_INTERVAL;

#ifndef MIN_SWAP_PAGEOUT_RATE
#define MIN_SWAP_PAGEOUT_RATE	10
#endif

/*
 * The following are all stored in fixed-point representation (the actual
 * value times AVE_SCALE), to allow more accurate computing of decaying
 * averages.  So all variables that end with "avg" must be divided by
 * AVE_SCALE to convert them or compare them to ints.
 */
unsigned int vm_grab_rate_avg;
unsigned int vm_pageout_rate_avg = MIN_SWAP_PAGEOUT_RATE * AVE_SCALE;
unsigned int vm_pageout_rate_longavg = MIN_SWAP_PAGEOUT_RATE * AVE_SCALE;
unsigned int vm_pageout_rate_peakavg = MIN_SWAP_PAGEOUT_RATE * AVE_SCALE;
unsigned int vm_page_free_avg;	/* average free pages over short_avg_interval */
unsigned int vm_page_free_longavg; /* avg free pages over long_avg_interval */

/*
 * Trigger task swapping when paging activity reaches
 * SWAP_HIGH_WATER_MARK per cent of the maximum paging activity ever observed.
 * Turn off task swapping when paging activity goes back down to below
 * SWAP_PAGEOUT_LOW_WATER_MARK per cent of the maximum.
 * These numbers have been found empirically and might need some tuning...
 */
#ifndef SWAP_PAGEOUT_HIGH_WATER_MARK
#define SWAP_PAGEOUT_HIGH_WATER_MARK	30
#endif
#ifndef SWAP_PAGEOUT_LOW_WATER_MARK
#define SWAP_PAGEOUT_LOW_WATER_MARK	10
#endif

#ifndef MAX_GRAB_RATE
#define MAX_GRAB_RATE	((unsigned int) -1)	/* XXX no maximum */
#endif

/*
 * swap_{start,stop}_pageout_rate start at the minimum value, then increase
 * to adjust to the hardware's performance, following the paging rate peaks.
 */
unsigned int swap_pageout_high_water_mark = SWAP_PAGEOUT_HIGH_WATER_MARK;
unsigned int swap_pageout_low_water_mark = SWAP_PAGEOUT_LOW_WATER_MARK;
unsigned int swap_start_pageout_rate = MIN_SWAP_PAGEOUT_RATE * AVE_SCALE *
					SWAP_PAGEOUT_HIGH_WATER_MARK / 100;
unsigned int swap_stop_pageout_rate = MIN_SWAP_PAGEOUT_RATE * AVE_SCALE *
					SWAP_PAGEOUT_LOW_WATER_MARK / 100;
#if	TASK_SW_DEBUG
unsigned int fixed_swap_start_pageout_rate = 0;	/* only for testing purpose */
unsigned int fixed_swap_stop_pageout_rate = 0;	/* only for testing purpose */
#endif	/* TASK_SW_DEBUG */
unsigned int max_grab_rate = MAX_GRAB_RATE;

#ifndef MIN_SWAP_TIME
#define MIN_SWAP_TIME	1
#endif

int min_swap_time = MIN_SWAP_TIME;			/* in seconds */

#ifndef MIN_RES_TIME
#define MIN_RES_TIME	6
#endif

int min_res_time = MIN_RES_TIME;			/* in seconds */

#ifndef MIN_ACTIVE_TASKS
#define MIN_ACTIVE_TASKS	4
#endif

int min_active_tasks = MIN_ACTIVE_TASKS;

#ifndef TASK_SWAP_CYCLE_TIME
#define TASK_SWAP_CYCLE_TIME	2
#endif

int task_swap_cycle_time = TASK_SWAP_CYCLE_TIME;	/* in seconds */

int last_task_swap_cycle = 0;

/* temporary statistics */
int task_swapouts = 0;
int task_swapins = 0;
int task_swaprss_out = 0;	/* total rss at swapout time */
int task_swaprss_in = 0;	/* total rss at swapin time */
int task_swap_total_time = 0;	/* total time spent swapped out */
int tasks_swapped_out = 0;	/* number of tasks swapped out now */

#ifdef	TASK_SW_STATS
#define TASK_STATS_INCR(cnt)	(cnt)++
#else
#define TASK_STATS_INCR(cnt)
#endif	/* TASK_SW_STATS */

#if	TASK_SW_DEBUG
boolean_t on_swapped_list(task_t task);	/* forward */
/*
 * Debug function to determine if a task is already on the
 * swapped out tasks list.  It also checks for tasks on the list
 * that are in an illegal state (i.e. swapped in).
 */
boolean_t
on_swapped_list(task_t task)
{
	task_t ltask;
	/* task_swapper_lock is locked. */

	if (queue_empty(&swapped_tasks)) {
		return(FALSE);
	}
	ltask = (task_t)queue_first(&swapped_tasks);
	while (!queue_end(&swapped_tasks, (queue_entry_t)ltask)) {
		/* check for illegal state */
		if (ltask->swap_state == TASK_SW_IN) {
			printf("on_swapped_list and in: 0x%X\n",ltask);
			Debugger("");
		}
		if (ltask == task)
			return(TRUE);
		ltask = (task_t)queue_next(&ltask->swapped_tasks);
	}
	return(FALSE);
}
#endif	/* TASK_SW_DEBUG */

/*
 *	task_swapper_init: [exported]
 */
void
task_swapper_init()
{
	queue_init(&swapped_tasks);
	queue_init(&eligible_tasks);
	queue_init(&swapout_thread_q);
	mutex_init(&task_swapper_lock, ETAP_THREAD_TASK_SWAP);
	mutex_init(&task_swapout_list_lock, ETAP_THREAD_TASK_SWAPOUT);
	vm_page_free_avg = vm_page_free_count * AVE_SCALE;
	vm_page_free_longavg = vm_page_free_count * AVE_SCALE;
}

#endif	/* TASK_SWAPPER */

/*
 *	task_swappable:	[exported]
 *
 *	Make a task swappable or non-swappable. If made non-swappable,
 *	it will be swapped in.
 *
 *	Locking: task_swapout_lock is taken before task lock.
 */
kern_return_t
task_swappable(
	host_priv_t host_priv,
	task_t task,
	boolean_t make_swappable)
{
	if (host_priv == HOST_PRIV_NULL)
		return(KERN_INVALID_ARGUMENT);

	if (task == TASK_NULL)
		return(KERN_INVALID_ARGUMENT);

#if	!TASK_SWAPPER

	/*
	 * If we don't support swapping, this call is purely advisory.
	 */
	return(KERN_SUCCESS);

#else	/* TASK_SWAPPER */
	
	task_lock(task);
	if (make_swappable) {
		/* make task swappable */
		if (task->swap_state == TASK_SW_UNSWAPPABLE) {
			task->swap_state = TASK_SW_IN; 
			task_unlock(task);
			task_swapout_eligible(task);
		}
	} else {
	    switch (task->swap_state) {
		case TASK_SW_IN:
			task->swap_state = TASK_SW_UNSWAPPABLE;
			task_unlock(task);
			task_swapout_ineligible(task);
			break;
		case TASK_SW_UNSWAPPABLE:
			task_unlock(task);
			break;
		default:
			/*
			 * swap_state could be TASK_SW_OUT, TASK_SW_GOING_OUT,
			 * or TASK_SW_COMING_IN.  task_swapin handles all
			 * three, and its default case will catch any bad
			 * states.
			 */
			task_unlock(task);
			task_swapin(task, TRUE);
			break;
	    }
	}
	return(KERN_SUCCESS);

#endif	/* TASK_SWAPPER */

}

#if	TASK_SWAPPER

/*
 *	task_swapout:
 * 	A reference to the task must be held.
 *
 *	Start swapping out a task by sending an AST_SWAPOUT to each thread.
 *	When the threads reach a clean point, they queue themselves up on the
 *	swapout_thread_q to be swapped out by the task_swap_swapout_thread.
 *	The task can be swapped in at any point in this process.
 *
 *	A task will not be fully swapped out (i.e. its map residence count
 *	at zero) until all currently-swapped threads run and reach
 *	a clean point, at which time they will be swapped again,
 *	decrementing the swap_ast_waiting count on the task.
 *
 *	Locking: no locks held upon entry and exit.
 *		 Task_lock is held throughout this function.
 */
kern_return_t
task_swapout(task_t task)
{
	thread_act_t thr_act;
	thread_t thread;
	queue_head_t *list;
	int s;

	task_swapout_lock();
	task_lock(task);
	/*
	 * NOTE: look into turning these into assertions if they
	 * are invariants.
	 */
	if ((task->swap_state != TASK_SW_IN) || (!task->active)) {
		task_unlock(task);
		task_swapout_unlock();
		return(KERN_FAILURE);
	}
	if (task->swap_flags & TASK_SW_ELIGIBLE) {
		queue_remove(&eligible_tasks, task, task_t, swapped_tasks);
		task->swap_flags &= ~TASK_SW_ELIGIBLE;
	}
	task_swapout_unlock();

	/* set state to avoid races with task_swappable(FALSE) */
	task->swap_state = TASK_SW_GOING_OUT;
	task->swap_rss = pmap_resident_count(task->map->pmap);
	task_swaprss_out += task->swap_rss;
	task->swap_ast_waiting = task->thr_act_count;

	/*
	 * halt all threads in this task:
	 * We don't need the thread list lock for traversal.
	 */
	list = &task->thr_acts;
	thr_act = (thread_act_t) queue_first(list);
	while (!queue_end(list, (queue_entry_t) thr_act)) {
		boolean_t swappable;
		thread_act_t ract;

		thread = act_lock_thread(thr_act);
		s = splsched();
		if (!thread)
			swappable = (thr_act->swap_state != TH_SW_UNSWAPPABLE);
		else {
			thread_lock(thread);
			swappable = TRUE;
			for (ract = thread->top_act; ract; ract = ract->lower)
				if (ract->swap_state == TH_SW_UNSWAPPABLE) {
					swappable = FALSE;
					break;
				}
		}
		if (swappable)
			thread_ast_set(thr_act, AST_SWAPOUT);
		if (thread)
			thread_unlock(thread);
		splx(s);
		assert((thr_act->ast & AST_TERMINATE) == 0);
		act_unlock_thread(thr_act);
		thr_act = (thread_act_t) queue_next(&thr_act->thr_acts);
	}

	task->swap_stamp = sched_tick;
	task->swap_nswap++;
	assert((task->swap_flags&TASK_SW_WANT_IN) == 0);
	/* put task on the queue of swapped out tasks */
	task_swapper_lock();
#if	TASK_SW_DEBUG
	if (task_swap_debug && on_swapped_list(task)) {
		printf("task 0x%X already on list\n", task);
		Debugger("");
	}
#endif	/* TASK_SW_DEBUG */
	queue_enter(&swapped_tasks, task, task_t, swapped_tasks);
	tasks_swapped_out++;
	task_swapouts++;
	task_swapper_unlock();
	task_unlock(task);

	return(KERN_SUCCESS);
}

#ifdef	TASK_SW_STATS
int	task_sw_race_in = 0;
int	task_sw_race_coming_in = 0;
int	task_sw_race_going_out = 0;
int	task_sw_before_ast = 0;
int	task_sw_before_swap = 0;
int	task_sw_after_swap = 0;
int	task_sw_race_in_won = 0;
int	task_sw_unswappable = 0;
int	task_sw_act_inactive = 0;
#endif	/* TASK_SW_STATS */

/*
 *	thread_swapout_enqueue is called by thread_halt_self when it 
 *	processes AST_SWAPOUT to enqueue threads to be swapped out.
 *	It must be called at normal interrupt priority for the
 *	sake of the task_swapper_lock.
 *
 *	There can be races with task swapin here.
 *	First lock task and decrement swap_ast_waiting count, and if
 *	it's 0, we can decrement the residence count on the task's map
 *	and set the task's swap state to TASK_SW_OUT.
 */
void
thread_swapout_enqueue(thread_act_t thr_act)
{
	task_t task = thr_act->task;
	task_lock(task);
	/*
	 * If the swap_state is not TASK_SW_GOING_OUT, then
	 * task_swapin has beaten us to this operation, and
	 * we have nothing to do.
	 */
	if (task->swap_state != TASK_SW_GOING_OUT) {
		task_unlock(task);
		return;
	}
	if (--task->swap_ast_waiting == 0) {
		vm_map_t map = task->map;
		task->swap_state = TASK_SW_OUT;
		task_unlock(task);
		mutex_lock(&map->s_lock);
		vm_map_res_deallocate(map);
		mutex_unlock(&map->s_lock);
	} else
		task_unlock(task);

	task_swapper_lock();
	act_lock(thr_act);
	if (! (thr_act->swap_state & TH_SW_TASK_SWAPPING)) {
		/*
		 * We lost a race with task_swapin(): don't enqueue.
		 */
	} else {
		queue_enter(&swapout_thread_q, thr_act,
			    thread_act_t, swap_queue);
		thread_wakeup((event_t)&swapout_thread_q);
	}
	act_unlock(thr_act);
	task_swapper_unlock();
}

/*
 *	task_swap_swapout_thread: [exported]
 *
 *	Executes as a separate kernel thread.
 *	Its job is to swap out threads that have been halted by AST_SWAPOUT.
 */
void
task_swap_swapout_thread(void)
{
	thread_act_t thr_act;
	thread_t thread, nthread;
	task_t task;
	int s;

	thread_swappable(current_act(), FALSE);
	stack_privilege(current_thread());

	spllo();

	while (TRUE) {
		task_swapper_lock();
		while (! queue_empty(&swapout_thread_q)) {

			queue_remove_first(&swapout_thread_q, thr_act,
					   thread_act_t, swap_queue);
			/*
			 * If we're racing with task_swapin, we need
			 * to make it safe for it to do remque on the
			 * thread, so make its links point to itself.
			 * Allowing this ugliness is cheaper than 
			 * making task_swapin search the entire queue.
			 */
			act_lock(thr_act);
			queue_init((queue_t) &thr_act->swap_queue);
			act_unlock(thr_act);
			task_swapper_unlock();
			/*
			 * Wait for thread's RUN bit to be deasserted.
			 */
			thread = act_lock_thread(thr_act);
			if (thread == THREAD_NULL)
				act_unlock_thread(thr_act);
			else {
				boolean_t r;

				thread_reference(thread);
				thread_hold(thr_act);
				act_unlock_thread(thr_act);
				r = thread_stop_wait(thread);
				nthread = act_lock_thread(thr_act);
				thread_release(thr_act);
				thread_deallocate(thread);
				act_unlock_thread(thr_act);
				if (!r || nthread != thread) {
					task_swapper_lock();
					continue;
				}
			}
			task = thr_act->task;
			task_lock(task);
			/* 
			 * we can race with swapin, which would set the
			 * state to TASK_SW_IN. 
			 */
			if ((task->swap_state != TASK_SW_OUT) &&
			    (task->swap_state != TASK_SW_GOING_OUT)) {
				task_unlock(task);
				task_swapper_lock();
				TASK_STATS_INCR(task_sw_race_in_won);
				if (thread != THREAD_NULL)
					thread_unstop(thread);
				continue;
			}
			nthread = act_lock_thread(thr_act);
			if (nthread != thread || thr_act->active == FALSE) {
				act_unlock_thread(thr_act);
				task_unlock(task);
				task_swapper_lock();
				TASK_STATS_INCR(task_sw_act_inactive);
				if (thread != THREAD_NULL)
					thread_unstop(thread);
				continue;
			}
			s = splsched();
			if (thread != THREAD_NULL)
				thread_lock(thread);
			/* 
			 * Thread cannot have been swapped out yet because
			 * TH_SW_TASK_SWAPPING was set in AST.  If task_swapin
			 * beat us here, we either wouldn't have found it on
			 * the queue, or the task->swap_state would have
			 * changed.  The synchronization is on the
			 * task's swap_state and the task_lock.
			 * The thread can't be swapped in any other way
			 * because its task has been swapped.
			 */
			assert(thr_act->swap_state & TH_SW_TASK_SWAPPING);
			assert(thread == THREAD_NULL ||
			       !(thread->state & (TH_SWAPPED_OUT|TH_RUN)));
			assert((thr_act->swap_state & TH_SW_STATE) == TH_SW_IN);
			/* assert(thread->state & TH_HALTED); */
			/* this also clears TH_SW_TASK_SWAPPING flag */
			thr_act->swap_state = TH_SW_GOING_OUT;
			if (thread != THREAD_NULL) {
				if (thread->top_act == thr_act) {
					thread->state |= TH_SWAPPED_OUT;
					/*
					 * Once we unlock the task, things can happen
					 * to the thread, so make sure it's consistent
					 * for thread_swapout.
					 */
				}
				thread->ref_count++;
				thread_unlock(thread);
				thread_unstop(thread);
			}
			splx(s);
			act_locked_act_reference(thr_act);
			act_unlock_thread(thr_act);
			task_unlock(task);

			thread_swapout(thr_act);	/* do the work */

			if (thread != THREAD_NULL)
				thread_deallocate(thread);
			act_deallocate(thr_act);
			task_swapper_lock();
		}
		assert_wait((event_t)&swapout_thread_q, THREAD_UNINT);
		task_swapper_unlock();
		thread_block((void (*)(void)) 0);
	}
}

/*
 *	task_swapin:
 *
 *	Make a task resident.
 *	Performs all of the work to make a task resident and possibly
 *	non-swappable.  If we race with a competing task_swapin call,
 *	we wait for its completion, then return.
 *
 *	Locking: no locks held upon entry and exit.
 *
 *	Note that TASK_SW_MAKE_UNSWAPPABLE can only be set when the
 *	state is TASK_SW_COMING_IN.
 */

kern_return_t
task_swapin(task_t task, boolean_t make_unswappable)
{
	register queue_head_t	*list;
	register thread_act_t	thr_act, next;
	thread_t		thread;
	int			s;
	boolean_t		swappable = TRUE;

	task_lock(task);
	switch (task->swap_state) {
	    case TASK_SW_OUT:
			{
			vm_map_t map = task->map;
			/*
			 * Task has made it all the way out, which means
			 * that vm_map_res_deallocate has been done; set 
			 * state to TASK_SW_COMING_IN, then bring map
			 * back in.  We could actually be racing with
			 * the thread_swapout_enqueue, which does the
			 * vm_map_res_deallocate, but that race is covered.
			 */
			task->swap_state = TASK_SW_COMING_IN;
			assert(task->swap_ast_waiting == 0);
			assert(map->res_count >= 0);
			task_unlock(task);
			mutex_lock(&map->s_lock);
			vm_map_res_reference(map);
			mutex_unlock(&map->s_lock);
			task_lock(task);
			assert(task->swap_state == TASK_SW_COMING_IN);
			}
			break;

	    case TASK_SW_GOING_OUT:
			/*
			 * Task isn't all the way out yet.  There is
			 * still at least one thread not swapped, and
			 * vm_map_res_deallocate has not been done.
			 */
			task->swap_state = TASK_SW_COMING_IN;
			assert(task->swap_ast_waiting > 0 ||
			       (task->swap_ast_waiting == 0 &&
				task->thr_act_count == 0));
			assert(task->map->res_count > 0);
			TASK_STATS_INCR(task_sw_race_going_out);
			break;
	    case TASK_SW_IN:
			assert(task->map->res_count > 0);
#if	TASK_SW_DEBUG
			task_swapper_lock();
			if (task_swap_debug && on_swapped_list(task)) {
				printf("task 0x%X on list, state is SW_IN\n",
					task);
				Debugger("");
			}
			task_swapper_unlock();
#endif	/* TASK_SW_DEBUG */
			TASK_STATS_INCR(task_sw_race_in);
			if (make_unswappable) {
				task->swap_state = TASK_SW_UNSWAPPABLE;
				task_unlock(task);
				task_swapout_ineligible(task);
			} else
				task_unlock(task);
			return(KERN_SUCCESS);
	    case TASK_SW_COMING_IN:
			/* 
			 * Raced with another task_swapin and lost;
			 * wait for other one to complete first
			 */
			assert(task->map->res_count >= 0);
			/*
			 * set MAKE_UNSWAPPABLE so that whoever is swapping
			 * the task in will make it unswappable, and return
			 */
			if (make_unswappable)
				task->swap_flags |= TASK_SW_MAKE_UNSWAPPABLE;
			task->swap_flags |= TASK_SW_WANT_IN;
			assert_wait((event_t)&task->swap_state, THREAD_UNINT);
			task_unlock(task);
			thread_block((void (*)(void)) 0);
			TASK_STATS_INCR(task_sw_race_coming_in);
			return(KERN_SUCCESS);
	    case TASK_SW_UNSWAPPABLE:
			/* 
			 * This can happen, since task_terminate 
			 * unconditionally calls task_swapin.
			 */
			task_unlock(task);
			return(KERN_SUCCESS);
	    default:
			panic("task_swapin bad state");
			break;
	}
	if (make_unswappable)
		task->swap_flags |= TASK_SW_MAKE_UNSWAPPABLE;
	assert(task->swap_state == TASK_SW_COMING_IN);
	task_swapper_lock();
#if	TASK_SW_DEBUG
	if (task_swap_debug && !on_swapped_list(task)) {
		printf("task 0x%X not on list\n", task);
		Debugger("");
	}
#endif	/* TASK_SW_DEBUG */
	queue_remove(&swapped_tasks, task, task_t, swapped_tasks);
	tasks_swapped_out--;
	task_swapins++;
	task_swapper_unlock();

	/*
	 * Iterate through all threads for this task and 
	 * release them, as required.  They may not have been swapped
	 * out yet.  The task remains locked throughout.
	 */
	list = &task->thr_acts;
	thr_act = (thread_act_t) queue_first(list);
	while (!queue_end(list, (queue_entry_t) thr_act)) {
		boolean_t need_to_release;
		next = (thread_act_t) queue_next(&thr_act->thr_acts);
		/*
		 * Keep task_swapper_lock across thread handling
		 * to synchronize with task_swap_swapout_thread
		 */
		task_swapper_lock();
		thread = act_lock_thread(thr_act);
		s = splsched();
		if (thr_act->ast & AST_SWAPOUT) {
			/* thread hasn't gotten the AST yet, just clear it */
			thread_ast_clear(thr_act, AST_SWAPOUT);
			need_to_release = FALSE;
			TASK_STATS_INCR(task_sw_before_ast);
			splx(s);
			act_unlock_thread(thr_act);
		} else {
			/*
			 * If AST_SWAPOUT was cleared, then thread_hold,
			 * or equivalent was done.
			 */
			need_to_release = TRUE;
			/*
			 * Thread has hit AST, but it may not have
			 * been dequeued yet, so we need to check.
			 * NOTE: the thread may have been dequeued, but
			 * has not yet been swapped (the task_swapper_lock
			 * has been dropped, but the thread is not yet
			 * locked), and the TH_SW_TASK_SWAPPING flag may 
			 * not have been cleared.  In this case, we will do 
			 * an extra remque, which the task_swap_swapout_thread
			 * has made safe, and clear the flag, which is also
			 * checked by the t_s_s_t before doing the swapout.
			 */
			if (thread)
				thread_lock(thread);
			if (thr_act->swap_state & TH_SW_TASK_SWAPPING) {
				/* 
				 * hasn't yet been dequeued for swapout,
				 * so clear flags and dequeue it first.
				 */
				thr_act->swap_state &= ~TH_SW_TASK_SWAPPING;
				assert(thr_act->thread == THREAD_NULL || 
				       !(thr_act->thread->state &
					 TH_SWAPPED_OUT));
				queue_remove(&swapout_thread_q, thr_act,
					     thread_act_t, swap_queue);
				TASK_STATS_INCR(task_sw_before_swap);
			} else {
				TASK_STATS_INCR(task_sw_after_swap);
				/*
				 * It's possible that the thread was
				 * made unswappable before hitting the
				 * AST, in which case it's still running.
				 */
				if (thr_act->swap_state == TH_SW_UNSWAPPABLE) {
					need_to_release = FALSE;
					TASK_STATS_INCR(task_sw_unswappable);
				}
			}
			if (thread)
				thread_unlock(thread);
			splx(s);
			act_unlock_thread(thr_act);
		}
		task_swapper_unlock();

		/* 
		 * thread_release will swap in the thread if it's been
		 * swapped out.
		 */
		if (need_to_release) {
			act_lock_thread(thr_act);
			thread_release(thr_act);
			act_unlock_thread(thr_act);
		}
		thr_act = next;
	}

	if (task->swap_flags & TASK_SW_MAKE_UNSWAPPABLE) {
		task->swap_flags &= ~TASK_SW_MAKE_UNSWAPPABLE;
		task->swap_state = TASK_SW_UNSWAPPABLE;
		swappable = FALSE;
	} else {
		task->swap_state = TASK_SW_IN;
	}

	task_swaprss_in += pmap_resident_count(task->map->pmap);
	task_swap_total_time += sched_tick - task->swap_stamp;
	/* note when task came back in */
	task->swap_stamp = sched_tick;
	if (task->swap_flags & TASK_SW_WANT_IN) {
		task->swap_flags &= ~TASK_SW_WANT_IN;
		thread_wakeup((event_t)&task->swap_state);
	}
	assert((task->swap_flags & TASK_SW_ELIGIBLE) == 0);
	task_unlock(task);
#if	TASK_SW_DEBUG
	task_swapper_lock();
	if (task_swap_debug && on_swapped_list(task)) {
		printf("task 0x%X on list at end of swap in\n", task);
		Debugger("");
	}
	task_swapper_unlock();
#endif	/* TASK_SW_DEBUG */
	/*
	 * Make the task eligible to be swapped again
	 */
	if (swappable)
		task_swapout_eligible(task);
	return(KERN_SUCCESS);
}

void wake_task_swapper(boolean_t now);	/* forward */

/*
 *	wake_task_swapper: [exported]
 *
 *	Wakes up task swapper if now == TRUE or if at least
 *	task_swap_cycle_time has elapsed since the last call.
 *
 *	NOTE: this function is not multithreaded, so if there is
 *	more than one caller, it must be modified.
 */
void
wake_task_swapper(boolean_t now)
{
	/* last_task_swap_cycle may require locking */
	if (now ||
	    (sched_tick > (last_task_swap_cycle + task_swap_cycle_time))) {
		last_task_swap_cycle = sched_tick;
		if (task_swap_debug)
			printf("wake_task_swapper: waking swapper\n");
		thread_wakeup((event_t)&swapped_tasks); /* poke swapper */
	}
}

task_t pick_intask(void);	/* forward */
/*
 * pick_intask:
 * returns a task to be swapped in, or TASK_NULL if nothing suitable is found.
 *
 * current algorithm: Return the task that has been swapped out the 
 *	longest, as long as it is > min_swap_time.  It will be dequeued
 *	if actually swapped in.
 *
 * NOTE:**********************************************
 * task->swap_rss (the size when the task was swapped out) could be used to
 * further refine the selection.  Another possibility would be to look at
 * the state of the thread(s) to see if the task/threads would run if they
 * were swapped in.
 * ***************************************************
 *
 * Locking:  no locks held upon entry and exit.
 */
task_t
pick_intask(void)
{
	register task_t		task = TASK_NULL;

	task_swapper_lock();
	/* the oldest task is the first one */
	if (!queue_empty(&swapped_tasks)) {
		task = (task_t) queue_first(&swapped_tasks);
		assert(task != TASK_NULL);
		/* Make sure it's been out min_swap_time */
		if ((sched_tick - task->swap_stamp) < min_swap_time)
			task = TASK_NULL;
	}
	task_swapper_unlock();
	return(task);
#if	0
	/*
	 * This code looks at the entire list of swapped tasks, but since
	 * it does not yet do anything but look at time swapped, we 
	 * can simply use the fact that the queue is ordered, and take 
	 * the first one off the queue.
	 */
	task = (task_t)queue_first(&swapped_tasks);
	while (!queue_end(&swapped_tasks, (queue_entry_t)task)) {
		task_lock(task);
		tmp_time = sched_tick - task->swap_stamp;
		if (tmp_time > min_swap_time && tmp_time > time_swapped) {
			target_task = task;
			time_swapped = tmp_time;
		}
		task_unlock(task);
		task = (task_t)queue_next(&task->swapped_tasks);
	}
	task_swapper_unlock();
	return(target_task);
#endif
}

task_t pick_outtask(void);	/* forward */
/*
 * pick_outtask:
 * returns a task to be swapped out, with a reference on the task,
 * or NULL if no suitable task is found.
 *
 * current algorithm:
 * 
 * Examine all eligible tasks.  While looking, use the first thread in 
 * each task as an indication of the task's activity.  Count up 
 * "active" threads (those either runnable or sleeping).  If the task 
 * is active (by these criteria), swapped in, and resident 
 * for at least min_res_time, then select the task with the largest 
 * number of pages in memory.  If there are less 
 * than min_active_tasks active tasks in the system, then don't 
 * swap anything out (this avoids swapping out the only running task 
 * in the system, for example).
 *
 * NOTE:  the task selected will not be removed from the eligible list.
 *	  This means that it will be selected again if it is not swapped
 *	  out, where it is removed from the list.
 *
 * Locking: no locks held upon entry and exit.  Task_swapout_lock must be
 *	    taken before task locks.
 *
 * ***************************************************
 * TBD:
 * This algorithm only examines the first thread in the task.  Currently, since
 * most swappable tasks in the system are single-threaded, this generalization
 * works reasonably well.  However, the algorithm should be changed
 * to consider all threads in the task if more multi-threaded tasks were used.  
 * ***************************************************
 */

#ifdef	TASK_SW_STATS
int inactive_task_count = 0;
int empty_task_count = 0;
#endif	/* TASK_SW_STATS */

task_t
pick_outtask(void)
{
	register task_t		task;
	register task_t		target_task = TASK_NULL;
	unsigned long		task_rss;
	unsigned long		target_rss = 0;
	boolean_t		wired;
	boolean_t		active;
	int			nactive = 0;

	task_swapout_lock();
	if (queue_empty(&eligible_tasks)) {
		/* not likely to happen */
		task_swapout_unlock();
		return(TASK_NULL);
	}
	task = (task_t)queue_first(&eligible_tasks);
	while (!queue_end(&eligible_tasks, (queue_entry_t)task)) {
		int s;
		register thread_act_t thr_act;
		thread_t th;
		

		task_lock(task);
		/*
		 * Don't swap real-time tasks.
		 * XXX Should we enforce that or can we let really critical
		 * tasks use task_swappable() to make sure they never end up
		 * n the eligible list ?
		 */
		if (task->policy & POLICYCLASS_FIXEDPRI) {
			goto tryagain;
		}
		if (!task->active) {
			TASK_STATS_INCR(inactive_task_count);
			goto tryagain;
		}
		if (task->res_act_count == 0) {
			TASK_STATS_INCR(empty_task_count);
			goto tryagain;
		}
		assert(!queue_empty(&task->thr_acts));
		thr_act = (thread_act_t)queue_first(&task->thr_acts);
		active = FALSE;
		th = act_lock_thread(thr_act);
		s = splsched();
		if (th != THREAD_NULL)
			thread_lock(th);
		if ((th == THREAD_NULL) ||
		    (th->state == TH_RUN) ||
		    (th->state & TH_WAIT)) {
			/*
		 	 * thread is "active": either runnable 
			 * or sleeping.  Count it and examine 
			 * it further below.
	 		 */
			nactive++;
			active = TRUE;
		}
		if (th != THREAD_NULL)
			thread_unlock(th);
		splx(s);
		act_unlock_thread(thr_act);
		if (active &&
		    (task->swap_state == TASK_SW_IN) &&
		    ((sched_tick - task->swap_stamp) > min_res_time)) {
			long rescount = pmap_resident_count(task->map->pmap);
			/*
			 * thread must be "active", task must be swapped
			 * in and resident for at least min_res_time
			 */
#if 0
/* DEBUG Test round-robin strategy.  Picking biggest task could cause extreme
 * unfairness to such large interactive programs as xterm.  Instead, pick the
 * first task that has any pages resident:
 */
			if (rescount > 1) {
				task->ref_count++;
				target_task = task;
				task_unlock(task);
				task_swapout_unlock();
				return(target_task);
			}
#else
			if (rescount > target_rss) {
				/*
				 * task is not swapped, and it has the
				 * largest rss seen so far.
				 */
				task->ref_count++;
				target_rss = rescount;
				assert(target_task != task);
				if (target_task != TASK_NULL)
					task_deallocate(target_task);
				target_task = task;
			}
#endif
		}
tryagain:
		task_unlock(task);
		task = (task_t)queue_next(&task->swapped_tasks);
	}
	task_swapout_unlock();
	/* only swap out if there are at least min_active_tasks */
	if (nactive < min_active_tasks) {
		if (target_task != TASK_NULL) {
			task_deallocate(target_task);
			target_task = TASK_NULL;
		}
	}
	return(target_task);
}

#if	TASK_SW_DEBUG
void print_pid(task_t task, unsigned long n1, unsigned long n2,
	       const char *comp, const char *inout);	/* forward */
void
print_pid(
	task_t task,
	unsigned long n1,
	unsigned long n2,
	const char *comp,
	const char *inout)
{
	long rescount;
	task_lock(task);
	rescount = pmap_resident_count(task->map->pmap);
	task_unlock(task);
	printf("task_swapper: swapped %s task %x; %d %s %d; res=%d\n",
		inout, task, n1, comp, n2, rescount);
}
#endif

/*
 *	task_swapper: [exported]
 *
 *	Executes as a separate kernel thread.
 */
#define MAX_LOOP 3
void
task_swapper(void)
{
	task_t	outtask, intask;
	int timeout;
	int loopcnt = 0;
	boolean_t start_swapping;
	boolean_t stop_swapping;
	int local_page_free_avg;
	extern int hz;

	thread_swappable(current_act(), FALSE);
	stack_privilege(current_thread());

	spllo();

	for (;;) {
	local_page_free_avg = vm_page_free_avg;
	while (TRUE) {
#if	0
		if (task_swap_debug)
			printf("task_swapper: top of loop; cnt = %d\n",loopcnt);
#endif
		intask = pick_intask();

		start_swapping = ((vm_pageout_rate_avg > swap_start_pageout_rate) ||
				  (vm_grab_rate_avg > max_grab_rate));
		stop_swapping = (vm_pageout_rate_avg < swap_stop_pageout_rate);

		/*
		 * If a lot of paging is going on, or another task should come
		 * in but memory is tight, find something to swap out and start
		 * it.  Don't swap any task out if task swapping is disabled.
		 * vm_page_queue_free_lock protects the vm globals.
		 */
		outtask = TASK_NULL;
		if (start_swapping ||
		    (!stop_swapping && intask &&
		     ((local_page_free_avg / AVE_SCALE) < vm_page_free_target))
		   ) {
			if (task_swap_enable &&
			    (outtask = pick_outtask()) &&
			    (task_swapout(outtask) == KERN_SUCCESS)) {
				unsigned long rss;
#if	TASK_SW_DEBUG
				if (task_swap_debug)
				    print_pid(outtask, local_page_free_avg / AVE_SCALE,
					      vm_page_free_target, "<",
					      "out");
#endif
				rss = outtask->swap_rss;
				if (outtask->swap_nswap == 1)
					rss /= 2; /* divide by 2 if never out */
				local_page_free_avg += (rss/short_avg_interval) * AVE_SCALE;
			}
			if (outtask != TASK_NULL)
				task_deallocate(outtask);
		}

		/*
		 * If there is an eligible task to bring in and there are at
		 * least vm_page_free_target free pages, swap it in.  If task
		 * swapping has been disabled, bring the task in anyway.
		 */
		if (intask && ((local_page_free_avg / AVE_SCALE) >=
							vm_page_free_target ||
				stop_swapping || !task_swap_enable)) {
			if (task_swapin(intask, FALSE) == KERN_SUCCESS) {
				unsigned long rss;
#if	TASK_SW_DEBUG
				if (task_swap_debug)
				    print_pid(intask, local_page_free_avg / AVE_SCALE,
					      vm_page_free_target, ">=",
					      "in");
#endif
				rss = intask->swap_rss;
				if (intask->swap_nswap == 1)
					rss /= 2; /* divide by 2 if never out */
				local_page_free_avg -= (rss/short_avg_interval) * AVE_SCALE;
			}
		}
		/*
		 * XXX
		 * Here we have to decide whether to continue swapping
		 * in and/or out before sleeping.  The decision should
		 * be made based on the previous action (swapin/out) and
		 * current system parameters, such as paging rates and
		 * demand.
		 * The function, compute_vm_averages, which does these
		 * calculations, depends on being called every second,
		 * so we can't just do the same thing.
		 */
		if (++loopcnt < MAX_LOOP)
			continue;

		/*
		 * Arrange to be awakened if paging is still heavy or there are
		 * any tasks partially or completely swapped out.  (Otherwise,
		 * the wakeup will come from the external trigger(s).)
		 */
		timeout = 0;
		if (start_swapping)
			timeout = task_swap_cycle_time;
		else {
			task_swapper_lock();
			if (!queue_empty(&swapped_tasks))
				timeout = min_swap_time;
			task_swapper_unlock();
		}
		assert_wait((event_t)&swapped_tasks, THREAD_UNINT);
		if (timeout) {
			if (task_swap_debug)
				printf("task_swapper: set timeout of %d\n",
								timeout);
			thread_set_timeout(timeout, NSEC_PER_SEC);
		}
		if (task_swap_debug)
			printf("task_swapper: blocking\n");
		thread_block((void (*)(void)) 0);
		if (timeout) {
			thread_cancel_timeout(current_thread());
		}
		/* reset locals */
		loopcnt = 0;
		local_page_free_avg = vm_page_free_avg;
	}
	}
}

/* from BSD */
#define ave(smooth, cnt, time) \
	smooth = ((time - 1) * (smooth) + ((cnt) * AVE_SCALE)) / (time)

/*
 * We estimate the system paging load in more than one metric: 
 *	1) the total number of calls into the function, vm_page_grab, 
 * 	   which allocates all page frames for real pages.
 *	2) the total number of pages paged in and out of paging files.
 *	   This is a measure of page cleaning and faulting from backing
 *	   store.
 *
 * When either metric passes a threshold, tasks are swapped out.
 */
long last_grab_count = 0;
long last_pageout_count = 0;

/*
 * compute_vm_averages: [exported]
 *
 * This function is to be called once a second to calculate average paging
 * demand and average numbers of free pages for use by the task swapper.
 * Can also be used to wake up task swapper at desired thresholds.
 *
 * NOTE: this function is single-threaded, and requires locking if
 *	ever there are multiple callers.
 */
void
compute_vm_averages(void)
{
	extern unsigned long vm_page_grab_count;
	long grab_count, pageout_count;
	int i;

	ave(vm_page_free_avg, vm_page_free_count, short_avg_interval);
	ave(vm_page_free_longavg, vm_page_free_count, long_avg_interval);

	/* 
	 * NOTE: the vm_page_grab_count and vm_stat structure are 
	 * under control of vm_page_queue_free_lock.  We're simply reading
	 * memory here, and the numbers don't depend on each other, so
	 * no lock is taken.
	 */

	grab_count = vm_page_grab_count;
	pageout_count = 0;
	for (i = 0; i < NCPUS; i++) {
		pageout_count += vm_stat[i].pageouts;
	}

	ave(vm_pageout_rate_avg, pageout_count - last_pageout_count,
	    short_avg_interval);
	ave(vm_pageout_rate_longavg, pageout_count - last_pageout_count,
	    long_avg_interval);
	ave(vm_grab_rate_avg, grab_count - last_grab_count,
	    short_avg_interval);
	last_grab_count = grab_count;
	last_pageout_count = pageout_count;

	/*
	 * Adjust swap_{start,stop}_pageout_rate to the paging rate peak.
	 * This is an attempt to find the optimum paging rates at which
	 * to trigger task swapping on or off to regulate paging activity,
	 * depending on the hardware capacity.
	 */
	if (vm_pageout_rate_avg > vm_pageout_rate_peakavg) {
		unsigned int desired_max;

		vm_pageout_rate_peakavg = vm_pageout_rate_avg;
		swap_start_pageout_rate =
			vm_pageout_rate_peakavg * swap_pageout_high_water_mark / 100;
		swap_stop_pageout_rate = 
			vm_pageout_rate_peakavg * swap_pageout_low_water_mark / 100;
	}

#if	TASK_SW_DEBUG
	/*
	 * For measurements, allow fixed values.
	 */
	if (fixed_swap_start_pageout_rate)
		swap_start_pageout_rate = fixed_swap_start_pageout_rate;
	if (fixed_swap_stop_pageout_rate)
		swap_stop_pageout_rate = fixed_swap_stop_pageout_rate;
#endif	/* TASK_SW_DEBUG */

#if	TASK_SW_DEBUG
	if (task_swap_stats)
		printf("vm_avgs: pageout_rate: %d %d (on/off: %d/%d); page_free: %d %d (tgt: %d)\n",
		       vm_pageout_rate_avg / AVE_SCALE,
		       vm_pageout_rate_longavg / AVE_SCALE,
		       swap_start_pageout_rate / AVE_SCALE,
		       swap_stop_pageout_rate / AVE_SCALE,
		       vm_page_free_avg / AVE_SCALE,
		       vm_page_free_longavg / AVE_SCALE,
		       vm_page_free_target);
#endif	/* TASK_SW_DEBUG */
	
	if (vm_page_free_avg / AVE_SCALE <= vm_page_free_target) {
		if (task_swap_on) {
			/* The following is a delicate attempt to balance the
			 * need for reasonably rapid response to system
			 * thrashing, with the equally important desire to
			 * prevent the onset of swapping simply because of a
			 * short burst of paging activity.
			 */
			if ((vm_pageout_rate_longavg > swap_stop_pageout_rate) &&
			    (vm_pageout_rate_avg > swap_start_pageout_rate) ||
			    (vm_pageout_rate_avg > vm_pageout_rate_peakavg) ||
			    (vm_grab_rate_avg > max_grab_rate))
				wake_task_swapper(FALSE);
		}
	} else /* page demand is low; should consider swapin */ {
		if (tasks_swapped_out != 0)
			wake_task_swapper(TRUE);
	}
}

void
task_swapout_eligible(task_t task)
{
#if	TASK_SW_DEBUG
	task_swapper_lock();
	if (task_swap_debug && on_swapped_list(task)) {
		printf("swapout_eligible: task 0x%X on swapped list\n", task);
		Debugger("");
	}
	task_swapper_unlock();
#endif
	task_swapout_lock();
	task_lock(task);
#if	TASK_SW_DEBUG
	if (task->swap_flags & TASK_SW_ELIGIBLE) {
		printf("swapout_eligible: task 0x%X already eligible\n", task);
	}
#endif	/* TASK_SW_DEBUG */
	if ((task->swap_state == TASK_SW_IN) &&
	    ((task->swap_flags & TASK_SW_ELIGIBLE) == 0)) {
		queue_enter(&eligible_tasks,task,task_t,swapped_tasks);
		task->swap_flags |= TASK_SW_ELIGIBLE;
	}
	task_unlock(task);
	task_swapout_unlock();
}

void
task_swapout_ineligible(task_t task)
{
#if	TASK_SW_DEBUG
	task_swapper_lock();
	if (task_swap_debug && on_swapped_list(task)) {
		printf("swapout_ineligible: task 0x%X on swapped list\n", task);
		Debugger("");
	}
	task_swapper_unlock();
#endif
	task_swapout_lock();
	task_lock(task);
#if	TASK_SW_DEBUG
	if (!(task->swap_flags & TASK_SW_ELIGIBLE))
		printf("swapout_ineligible: task 0x%X already inel.\n", task);
#endif	/* TASK_SW_DEBUG */
	if ((task->swap_state != TASK_SW_IN) && 
	    (task->swap_flags & TASK_SW_ELIGIBLE)) {
		queue_remove(&eligible_tasks, task, task_t, swapped_tasks);
		task->swap_flags &= ~TASK_SW_ELIGIBLE;
	}
	task_unlock(task);
	task_swapout_unlock();
}

int task_swap_ast_aborted = 0;

/*
 *	Process an AST_SWAPOUT.
 */
void
swapout_ast()
{
	spl_t		s;
	thread_act_t	act;
	thread_t	thread;

	act = current_act();

	/*
	 * Task is being swapped out.  First mark it as suspended
	 * and halted, then call thread_swapout_enqueue to put
	 * the thread on the queue for task_swap_swapout_threads
	 * to swap out the thread.
	 */
	/*
	 * Don't swap unswappable threads
	 */
	thread = act_lock_thread(act);
	s = splsched();
	if (thread)
		thread_lock(thread);
	if ((act->ast & AST_SWAPOUT) == 0) {
		/*
		 * Race with task_swapin. Abort swapout.
		 */
		task_swap_ast_aborted++;	/* not locked XXX */
		if (thread)
			thread_unlock(thread);
		splx(s);
		act_unlock_thread(act);
	} else if (act->swap_state == TH_SW_IN) {
		/*
		 * Mark swap_state as TH_SW_TASK_SWAPPING to avoid
		 * race with thread swapper, which will only
		 * swap thread if swap_state is TH_SW_IN.
		 * This way, the thread can only be swapped by
		 * the task swapping mechanism.
		 */
		act->swap_state |= TH_SW_TASK_SWAPPING;
		/* assert(act->suspend_count == 0); XXX ? */
		if (thread)
			thread_unlock(thread);
		if (act->suspend_count++ == 0)	/* inline thread_hold */
			install_special_handler(act);
		/* self->state |= TH_HALTED; */
		thread_ast_clear(act, AST_SWAPOUT);
		/*
		 * Initialize the swap_queue fields to allow an extra
		 * queue_remove() in task_swapin if we lose the race
		 * (task_swapin can be called before we complete
		 * thread_swapout_enqueue).
		 */
		queue_init((queue_t) &act->swap_queue);
		splx(s);
		act_unlock_thread(act);
		/* this must be called at normal interrupt level */
		thread_swapout_enqueue(act);
	} else {
		/* thread isn't swappable; continue running */
		assert(act->swap_state == TH_SW_UNSWAPPABLE);
		if (thread)
			thread_unlock(thread);
		thread_ast_clear(act, AST_SWAPOUT);
		splx(s);
		act_unlock_thread(act);
	}
}

#endif	/* TASK_SWAPPER */
