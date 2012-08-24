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

#include <kperf/filter.h>
#include <kperf/sample.h>
#include <kperf/kperfbsd.h>
#include <kperf/pet.h>
#include <kperf/action.h>
#include <kperf/kperf.h>
#include <kperf/timetrigger.h>

/** misc functions **/
#include <chud/chud_xnu.h> /* XXX: should bust this out */

static struct kperf_sample *intr_samplev = NULL;
static unsigned intr_samplec = 0;
static unsigned sampling_status = KPERF_SAMPLING_OFF;
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

/* setup interrupt sample buffers */
int
kperf_init(void)
{
	unsigned ncpus = 0;

	if( kperf_initted )
		return 0;

	/* get number of cpus */
	ncpus = machine_info.logical_cpu_max;

	/* make the CPU array 
	 * FIXME: cache alignment
	 */
	intr_samplev = kalloc( ncpus * sizeof(*intr_samplev));

	if( intr_samplev == NULL )
		return ENOMEM;

	/* clear it */
	bzero( intr_samplev, ncpus * sizeof(*intr_samplev) );
	
	chudxnu_thread_ast_handler = kperf_thread_ast_handler;

	/* we're done */
	intr_samplec = ncpus;
	kperf_initted = 1;

	return 0;
}


/** kext start/stop functions **/
kern_return_t kperf_start (kmod_info_t * ki, void * d);

kern_return_t
kperf_start (kmod_info_t * ki, void * d)
{
	(void) ki;
	(void) d;

	/* say hello */
	printf( "aprof: kext starting\n" );

	/* register modules */
	// kperf_action_init();
	kperf_filter_init();
	kperf_pet_init();

	/* register the sysctls */
	//kperf_register_profiling();

	return KERN_SUCCESS;
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
