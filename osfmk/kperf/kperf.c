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
#include <mach/mach_types.h>
#include <kern/thread.h>
#include <kern/machine.h>
#include <kern/kalloc.h>
#include <sys/errno.h>

#include <kperf/sample.h>
#include <kperf/pet.h>
#include <kperf/action.h>
#include <kperf/kperf.h>
#include <kperf/timetrigger.h>

#include <kern/ipc_tt.h> /* port_name_to_task */

/** misc functions **/
#include <chud/chud_xnu.h> /* XXX: should bust this out */

/* thread on CPUs before starting the PET thread */
thread_t *kperf_thread_on_cpus = NULL;

/* interupt sample buffers -- one wired per CPU */
static struct kperf_sample *intr_samplev = NULL;
static unsigned intr_samplec = 0;

/* track recursion in the trace code */
static struct
{
	int active;
	int pad[64 / sizeof(int)];
} *kpdbg_recursev;
static unsigned kpdbg_recursec = 0;

/* Curren sampling status */
static unsigned sampling_status = KPERF_SAMPLING_OFF;

/* Make sure we only init once */
static unsigned kperf_initted = 0;

extern void (*chudxnu_thread_ast_handler)(thread_t);

struct kperf_sample*
kperf_intr_sample_buffer(void)
{
	unsigned ncpu = chudxnu_cpu_number();

	// XXX: assert?
	if( ncpu >= intr_samplec )
		return NULL;

	return &intr_samplev[ncpu];
}

int
kperf_kdbg_recurse(int step)
{
	unsigned ncpu = chudxnu_cpu_number();

	// XXX: assert?
	if( ncpu >= kpdbg_recursec )
		return 1;

	/* recursing in, available */
	if( (step > 0)
	    && (kpdbg_recursev[ncpu].active == 0) )
	{
		kpdbg_recursev[ncpu].active = 1;
		return 0;
	}

	/* recursing in, unavailable */
	if( (step > 0)
	    && (kpdbg_recursev[ncpu].active != 0) )
	{
		return 1;
	}

	/* recursing out, unavailable */
	if( (step < 0)
	    && (kpdbg_recursev[ncpu].active != 0) )
	{
		kpdbg_recursev[ncpu].active = 0;
		return 0;
	}

	/* recursing out, available */
	if( (step < 0)
	    && (kpdbg_recursev[ncpu].active == 0) )
		panic( "return from non-recursed kperf kdebug call" );

	panic( "unknown kperf kdebug call" );
	return 1;
}

/* setup interrupt sample buffers */
int
kperf_init(void)
{
	unsigned ncpus = 0;
	int err;

	if( kperf_initted )
		return 0;

	/* get number of cpus */
	ncpus = machine_info.logical_cpu_max;

	kperf_thread_on_cpus = kalloc( ncpus * sizeof(*kperf_thread_on_cpus) );
	if( kperf_thread_on_cpus == NULL )
	{
		err = ENOMEM;
		goto error;
	}

	/* clear it */
	bzero( kperf_thread_on_cpus, ncpus * sizeof(*kperf_thread_on_cpus) );

	/* make the CPU array
	 * FIXME: cache alignment
	 */
	intr_samplev = kalloc( ncpus * sizeof(*intr_samplev));
	intr_samplec = ncpus;

	if( intr_samplev == NULL )
	{
		err = ENOMEM;
		goto error;
	}

	/* clear it */
	bzero( intr_samplev, ncpus * sizeof(*intr_samplev) );

	/* make the recursion array */
	kpdbg_recursev = kalloc( ncpus * sizeof(*kpdbg_recursev));
	kpdbg_recursec = ncpus;

	/* clear it */
	bzero( kpdbg_recursev, ncpus * sizeof(*kpdbg_recursev) );

	/* we're done */
	kperf_initted = 1;

	return 0;
error:
	if( intr_samplev )
		kfree( intr_samplev, ncpus * sizeof(*intr_samplev) );
	if( kperf_thread_on_cpus )
		kfree( kperf_thread_on_cpus, ncpus * sizeof(*kperf_thread_on_cpus) );
	return err;
}

/* random misc-ish functions */
uint32_t
kperf_get_thread_bits( thread_t thread )
{
	return thread->t_chud;
}

void
kperf_set_thread_bits( thread_t thread, uint32_t bits )
{
	thread->t_chud = bits;
}

/* mark an AST to fire on a thread */
void
kperf_set_thread_ast( thread_t thread )
{
	/* FIXME: only call this on current thread from an interrupt
	 * handler for now... 
	 */
	if( thread != current_thread() )
		panic( "unsafe AST set" );

	act_set_kperf(thread);
}

unsigned
kperf_sampling_status(void)
{
	return sampling_status;
}

int
kperf_sampling_enable(void)
{
	/* already running! */
	if( sampling_status == KPERF_SAMPLING_ON )
		return 0;

	if ( sampling_status != KPERF_SAMPLING_OFF )
		panic( "kperf: sampling wasn't off" );

	/* make sure interrupt tables and actions are initted */
	if( !kperf_initted
	    || (kperf_action_get_count() == 0) )
		return ECANCELED;

	/* mark as running */
	sampling_status = KPERF_SAMPLING_ON;

	/* tell timers to enable */
	kperf_timer_go();

	return 0;
}

int
kperf_sampling_disable(void)
{
	if( sampling_status != KPERF_SAMPLING_ON )
		return 0;

	/* mark a shutting down */
	sampling_status = KPERF_SAMPLING_SHUTDOWN;

	/* tell timers to disable */
	kperf_timer_stop();

	/* mark as off */
	sampling_status = KPERF_SAMPLING_OFF;

	return 0;
}

int
kperf_port_to_pid(mach_port_name_t portname)
{
	task_t task;
	int pid;

	if( !MACH_PORT_VALID(portname) )
		return -1;

	task = port_name_to_task(portname);
	
	if( task == TASK_NULL )
		return -1;


	pid = chudxnu_pid_for_task(task);

	task_deallocate_internal(task);

	return pid;
}
