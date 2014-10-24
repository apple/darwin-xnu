/*
 * Copyright (c) 2011 Apple Computer, Inc. All rights reserved.
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

/* all thread states code */
#include <mach/mach_types.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOLocks.h>
#include <sys/errno.h>

#include <chud/chud_xnu.h>

#include <kperf/buffer.h>
#include <kperf/sample.h>
#include <kperf/context.h>
#include <kperf/action.h>
#include <kperf/pet.h>
#include <kperf/timetrigger.h>

extern kern_return_t task_resume_internal(task_t);
extern kern_return_t task_suspend_internal(task_t);

/* timer id to call back on */
static unsigned pet_timerid = 0;

/* aciton ID to call
 * We also use this as the sync point for waiting, for no good reason
 */
static unsigned pet_actionid = 0;

/* the actual thread pointer */
static thread_t pet_thread = NULL;

/* Lock on which to synchronise */
static IOLock *pet_lock = NULL;

/* where to sample data to */
static struct kperf_sample pet_sample_buf;

static int pet_idle_rate = 15;

/* sample an actual, honest to god thread! */
static void
pet_sample_thread( thread_t thread )
{
	struct kperf_context ctx;
	task_t task;
	unsigned skip_callstack;

	/* work out the context */
	ctx.cur_thread = thread;
	ctx.cur_pid = 0;

	task = chudxnu_task_for_thread(thread);
	if(task)
		ctx.cur_pid = chudxnu_pid_for_task(task);

	skip_callstack = (chudxnu_thread_get_dirty(thread) == TRUE) || ((thread->kperf_pet_cnt % (uint64_t)pet_idle_rate) == 0) ? 0 : SAMPLE_FLAG_EMPTY_CALLSTACK;

	/* do the actual sample */
	kperf_sample( &pet_sample_buf, &ctx, pet_actionid,
	              SAMPLE_FLAG_IDLE_THREADS | skip_callstack );

	if (!skip_callstack)
		chudxnu_thread_set_dirty(thread, FALSE);

	thread->kperf_pet_cnt++;
}

/* given a list of threads, preferably stopped, sample 'em! */
static void
pet_sample_thread_list( mach_msg_type_number_t threadc, thread_array_t threadv )
{
	unsigned int i;
	int ncpu;

	for( i = 0; i < threadc; i++ )
	{
		thread_t thread = threadv[i];

		if( !thread )
			/* XXX? */
			continue;

		for (ncpu = 0; ncpu < machine_info.logical_cpu_max; ++ncpu)
		{
			thread_t candidate = kperf_thread_on_cpus[ncpu];
			if (candidate && candidate->thread_id == thread->thread_id)
				break;
		}

		/* the thread was not on a CPU */
		if (ncpu == machine_info.logical_cpu_max)
			pet_sample_thread( thread );
	}
}

/* given a task (preferably stopped), sample all the threads in it */
static void
pet_sample_task( task_t task )
{
	mach_msg_type_number_t threadc;
	thread_array_t threadv;
	kern_return_t kr;

	kr = chudxnu_task_threads(task, &threadv, &threadc);
	if( kr != KERN_SUCCESS )
	{
		BUF_INFO2(PERF_PET_ERROR, ERR_THREAD, kr);
		return;
	}

	pet_sample_thread_list( threadc, threadv );

	chudxnu_free_thread_list(&threadv, &threadc);
}

/* given a list of tasks, sample all the threads in 'em */
static void
pet_sample_task_list( int taskc, task_array_t taskv  )
{
	int i;

	for( i = 0; i < taskc; i++ )
	{
		kern_return_t kr;
		task_t task = taskv[i];

		/* FIXME: necessary? old code did this, our hacky
		 * filtering code does, too
		 */
		if(!task) {
			continue;
		}

		/* try and stop any task other than the kernel task */
		if( task != kernel_task )
		{
			kr = task_suspend_internal( task );

			/* try the next task */
			if( kr != KERN_SUCCESS )
				continue;
		}

		/* sample it */
		pet_sample_task( task );

		/* if it wasn't the kernel, resume it */
		if( task != kernel_task )
			(void) task_resume_internal(task);
	}
}

static void
pet_sample_all_tasks(void)
{
	task_array_t taskv = NULL;
	mach_msg_type_number_t taskc = 0;
	kern_return_t kr;

	kr = chudxnu_all_tasks(&taskv, &taskc);

	if( kr != KERN_SUCCESS )
	{
		BUF_INFO2(PERF_PET_ERROR, ERR_TASK, kr);
		return;
	}

	pet_sample_task_list( taskc, taskv );
	chudxnu_free_task_list(&taskv, &taskc);
}

#if 0
static void
pet_sample_pid_filter(void)
{
	task_t *taskv = NULL;
	int *pidv, pidc, i;
	vm_size_t asize;

	kperf_filter_pid_list( &pidc, &pidv );
	if( pidc == 0  )
	{
		BUF_INFO2(PERF_PET_ERROR, ERR_PID, 0);
		return;
	}

	asize = pidc * sizeof(task_t);
	taskv = kalloc( asize );

	if( taskv == NULL )
		goto out;

	/* convert the pid list into a task list */
	for( i = 0; i < pidc; i++ )
	{
		int pid = pidv[i];
		if( pid == -1 )
			taskv[i] = NULL;
		else
			taskv[i] = chudxnu_task_for_pid(pid);
	}

	/* now sample the task list */
	pet_sample_task_list( pidc, taskv );

	kfree(taskv, asize);

out:
	kperf_filter_free_pid_list( &pidc, &pidv );
}
#endif

/* do the pet sample */
static void
pet_work_unit(void)
{
	int pid_filter;

	/* check if we're filtering on pid  */
	// pid_filter = kperf_filter_on_pid();
	pid_filter = 0;  // FIXME

#if 0
	if( pid_filter )
	{
		BUF_INFO1(PERF_PET_SAMPLE | DBG_FUNC_START, 1);
		pet_sample_pid_filter();
	}
	else
#endif
	{
		/* otherwise filter everything */
		BUF_INFO1(PERF_PET_SAMPLE | DBG_FUNC_START, 0);
		pet_sample_all_tasks();
	}

	BUF_INFO1(PERF_PET_SAMPLE | DBG_FUNC_END, 0);

}

/* sleep indefinitely */
static void 
pet_idle(void)
{
	IOLockSleep(pet_lock, &pet_actionid, THREAD_UNINT);
}

/* loop between sampling and waiting */
static void
pet_thread_loop( __unused void *param, __unused wait_result_t wr )
{
	uint64_t work_unit_ticks;

	BUF_INFO1(PERF_PET_THREAD, 1);

	IOLockLock(pet_lock);
	while(1)
	{
		BUF_INFO1(PERF_PET_IDLE, 0);
		pet_idle();

		BUF_INFO1(PERF_PET_RUN, 0);

		/* measure how long the work unit takes */
		work_unit_ticks = mach_absolute_time();
		pet_work_unit();
		work_unit_ticks = mach_absolute_time() - work_unit_ticks;

		/* re-program the timer */
		kperf_timer_pet_set( pet_timerid, work_unit_ticks );

		/* FIXME: break here on a condition? */
	}
}

/* make sure the thread takes a new period value */
void
kperf_pet_timer_config( unsigned timerid, unsigned actionid )
{
	if( !pet_lock )
		return;

	/* hold the lock so pet thread doesn't run while we do this */
	IOLockLock(pet_lock);

	BUF_INFO1(PERF_PET_THREAD, 3);

	/* set values */
	pet_timerid = timerid;
	pet_actionid = actionid;

	/* done */
	IOLockUnlock(pet_lock);
}

/* make the thread run! */
void
kperf_pet_thread_go(void)
{
	if( !pet_lock )
		return;

	/* Make the thread go */
	IOLockWakeup(pet_lock, &pet_actionid, FALSE);
}


/* wait for the pet thread to finish a run */
void
kperf_pet_thread_wait(void)
{
	if( !pet_lock )
		return;

	/* acquire the lock to ensure the thread is parked. */
	IOLockLock(pet_lock);
	IOLockUnlock(pet_lock);
}

/* keep the pet thread around while we run */
int
kperf_pet_init(void)
{
	kern_return_t rc;
	thread_t t;

	if( pet_thread != NULL )
		return 0;

	/* make the sync poing */
	pet_lock = IOLockAlloc();
	if( pet_lock == NULL )
		return ENOMEM;

	/* create the thread */
	BUF_INFO1(PERF_PET_THREAD, 0);
	rc = kernel_thread_start( pet_thread_loop, NULL, &t );
	if( rc != KERN_SUCCESS )
	{
		IOLockFree( pet_lock );
		pet_lock = NULL;
		return ENOMEM;
	}

	/* OK! */
	return 0;
}

int
kperf_get_pet_idle_rate( void )
{
	return pet_idle_rate;
}

void
kperf_set_pet_idle_rate( int val )
{
	pet_idle_rate = val;
}
