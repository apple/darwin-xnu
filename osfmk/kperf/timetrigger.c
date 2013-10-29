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

/*  Manage time triggers */

#include <mach/mach_types.h>
#include <kern/cpu_data.h> /* current_thread() */
#include <kern/kalloc.h>
#include <sys/errno.h>

#include <machine/machine_routines.h>

#include <chud/chud_xnu.h>

#include <kperf/kperf.h>
#include <kperf/buffer.h>
#include <kperf/context.h>
#include <kperf/action.h>
#include <kperf/timetrigger.h>
#include <kperf/kperf_arch.h>
#include <kperf/pet.h>
#include <kperf/sample.h>

/* make up for arm signal deficiencies */
void kperf_signal_handler(void);

/* represents a periodic timer */
struct time_trigger
{
	struct timer_call tcall;
	uint64_t period;
	unsigned actionid;
	volatile unsigned active;

#ifdef USE_SIMPLE_SIGNALS
	/* firing accounting */
	uint64_t fire_count;
	uint64_t last_cpu_fire[MAX_CPUS];
#endif
};

/* the list of timers */
static unsigned timerc = 0;
static struct time_trigger *timerv;
static unsigned pet_timer = 999;

/* maximum number of timers we can construct */
#define TIMER_MAX 16

/* minimal interval for a timer (10usec in nsec) */
#define MIN_TIMER_NS (10000)
/* minimal interval for pet timer (2msec in nsec) */
#define MIN_PET_TIMER_NS (2000000)

static void
kperf_timer_schedule( struct time_trigger *trigger, uint64_t now )
{
	uint64_t deadline;

	BUF_INFO1(PERF_TM_SCHED, trigger->period);

	/* if we re-programmed the timer to zero, just drop it */
	if( !trigger->period )
		return;

	/* calculate deadline */
	deadline = now + trigger->period;
	
	/* re-schedule the timer, making sure we don't apply slop */
	timer_call_enter( &trigger->tcall, deadline, TIMER_CALL_SYS_CRITICAL);
}

static void
kperf_ipi_handler( void *param )
{
	int r;
	int ncpu;
	struct kperf_sample *intbuf = NULL;
	struct kperf_context ctx;
	struct time_trigger *trigger = param;
	task_t task = NULL;

	/* Always cut a tracepoint to show a sample event occurred */
	BUF_DATA1(PERF_TM_HNDLR | DBG_FUNC_START, 0);

	/* In an interrupt, get the interrupt buffer for this CPU */
	intbuf = kperf_intr_sample_buffer();

	/* On a timer, we can see the "real" current thread */
	ctx.cur_pid = 0; /* remove this? */
	ctx.cur_thread = current_thread();

	task = chudxnu_task_for_thread(ctx.cur_thread);
	if (task)
		ctx.cur_pid = chudxnu_pid_for_task(task);

	/* who fired */
	ctx.trigger_type = TRIGGER_TYPE_TIMER;
	ctx.trigger_id = (unsigned)(trigger-timerv); /* computer timer number */

	ncpu = chudxnu_cpu_number();
	if (ctx.trigger_id == pet_timer && ncpu < machine_info.logical_cpu_max)
		kperf_thread_on_cpus[ncpu] = ctx.cur_thread;

	/* check samppling is on */
	if( kperf_sampling_status() == KPERF_SAMPLING_OFF ) {
		BUF_INFO1(PERF_TM_HNDLR | DBG_FUNC_END, SAMPLE_OFF);
		return;
	} else if( kperf_sampling_status() == KPERF_SAMPLING_SHUTDOWN ) {
		BUF_INFO1(PERF_TM_HNDLR | DBG_FUNC_END, SAMPLE_SHUTDOWN);
		return;
	}

	/* call the action -- kernel-only from interrupt, pend user */
	r = kperf_sample( intbuf, &ctx, trigger->actionid, SAMPLE_FLAG_PEND_USER );

	/* end tracepoint is informational */
	BUF_INFO1(PERF_TM_HNDLR | DBG_FUNC_END, r);
}

#ifdef USE_SIMPLE_SIGNALS
/* if we can't pass a (function, arg) pair through a signal properly,
 * we do it the simple way. When a timer fires, we increment a counter
 * in the time trigger and broadcast a generic signal to all cores. Cores
 * search the time trigger list for any triggers for which their last seen
 * firing counter is lower than the current one.
 */
void
kperf_signal_handler(void)
{
	int i, cpu;
	struct time_trigger *tr = NULL;

	OSMemoryBarrier();

	cpu = chudxnu_cpu_number();
	for( i = 0; i < (int) timerc; i++ )
	{
		tr = &timerv[i];
		if( tr->fire_count <= tr->last_cpu_fire[cpu] )
			continue; /* this trigger hasn't fired */

		/* fire the trigger! */
		tr->last_cpu_fire[cpu] = tr->fire_count;
		kperf_ipi_handler( tr );
	}
}
#else
void
kperf_signal_handler(void)
{
	// so we can link...
}
#endif

static void
kperf_timer_handler( void *param0, __unused void *param1 )
{
	struct time_trigger *trigger = param0;
	unsigned ntimer = (unsigned)(trigger - timerv);
	unsigned ncpus  = machine_info.logical_cpu_max;

	trigger->active = 1;

	/* along the lines of do not ipi if we are all shutting down */
	if( kperf_sampling_status() == KPERF_SAMPLING_SHUTDOWN )
		goto deactivate;

	/* clean-up the thread-on-CPUs cache */
	bzero(kperf_thread_on_cpus, ncpus * sizeof(*kperf_thread_on_cpus));

	/* ping all CPUs */
#ifndef USE_SIMPLE_SIGNALS
	kperf_mp_broadcast( kperf_ipi_handler, trigger );
#else
	trigger->fire_count++;
	OSMemoryBarrier();
	kperf_mp_signal();
#endif

	/* release the pet thread? */
	if( ntimer == pet_timer )
	{
		/* timer re-enabled when thread done */
		kperf_pet_thread_go();
	}
	else
	{
		/* re-enable the timer
		 * FIXME: get the current time from elsewhere
		 */
		uint64_t now = mach_absolute_time();
		kperf_timer_schedule( trigger, now );
	}

deactivate:
	trigger->active = 0;
}

/* program the timer from the pet thread */
int
kperf_timer_pet_set( unsigned timer, uint64_t elapsed_ticks )
{
	static uint64_t pet_min_ticks = 0;

	uint64_t now;
	struct time_trigger *trigger = NULL;
	uint64_t period = 0;
	uint64_t deadline;

	/* compute ns -> ticks */
	if( pet_min_ticks == 0 )
		nanoseconds_to_absolutetime(MIN_PET_TIMER_NS, &pet_min_ticks);

	if( timer != pet_timer )
		panic( "PET setting with bogus ID\n" );

	if( timer >= timerc )
		return EINVAL;

	if( kperf_sampling_status() == KPERF_SAMPLING_OFF ) {
		BUF_INFO1(PERF_PET_END, SAMPLE_OFF);
		return 0;
	}

	// don't repgram the timer if it's been shutdown
	if( kperf_sampling_status() == KPERF_SAMPLING_SHUTDOWN ) {
		BUF_INFO1(PERF_PET_END, SAMPLE_SHUTDOWN);
		return 0;
	}

	/* CHECKME: we probably took so damn long in the PET thread,
	 * it makes sense to take the time again.
	 */
	now = mach_absolute_time();
	trigger = &timerv[timer];

	/* if we re-programmed the timer to zero, just drop it */
	if( !trigger->period )
		return 0;

	/* subtract the time the pet sample took being careful not to underflow */
	if ( trigger->period > elapsed_ticks )
		period = trigger->period - elapsed_ticks;

	/* make sure we don't set the next PET sample to happen too soon */
	if ( period < pet_min_ticks )
		period = pet_min_ticks;

	/* calculate deadline */
	deadline = now + period;

	BUF_INFO(PERF_PET_SCHED, trigger->period, period, elapsed_ticks, deadline);

	/* re-schedule the timer, making sure we don't apply slop */
	timer_call_enter( &trigger->tcall, deadline, TIMER_CALL_SYS_CRITICAL);

	return 0;
}


/* turn on all the timers */
extern int
kperf_timer_go(void)
{
	unsigned i;
	uint64_t now = mach_absolute_time();

	for( i = 0; i < timerc; i++ )
	{
		if( timerv[i].period == 0 )
			continue;

		kperf_timer_schedule( &timerv[i], now );
	}

	return 0;
}


extern int
kperf_timer_stop(void)
{
	unsigned i;

	for( i = 0; i < timerc; i++ )
	{
		if( timerv[i].period == 0 )
			continue;

		while (timerv[i].active)
			;

		timer_call_cancel( &timerv[i].tcall );
	}

	/* wait for PET to stop, too */
	kperf_pet_thread_wait();

	return 0;
}

unsigned
kperf_timer_get_petid(void)
{
	return pet_timer;
}

int
kperf_timer_set_petid(unsigned timerid)
{
	struct time_trigger *trigger = NULL;

	/* they can program whatever... */
	pet_timer = timerid;
	
	/* clear them if it's a bogus ID */
	if( pet_timer >= timerc )
	{
		kperf_pet_timer_config( 0, 0 );

		return 0;
	}

	/* update the values */
	trigger = &timerv[pet_timer];
	kperf_pet_timer_config( pet_timer, trigger->actionid );

	return 0;
}

int
kperf_timer_get_period( unsigned timer, uint64_t *period )
{
	if( timer >= timerc )
		return EINVAL;

	*period = timerv[timer].period;

	return 0;
}

int
kperf_timer_set_period( unsigned timer, uint64_t period )
{
	static uint64_t min_timer_ticks = 0;

	if( timer >= timerc )
		return EINVAL;

	/* compute us -> ticks */
	if( min_timer_ticks == 0 )
		nanoseconds_to_absolutetime(MIN_TIMER_NS, &min_timer_ticks);

	/* check actual timer */
	if( period && (period < min_timer_ticks) )
		period = min_timer_ticks;

	timerv[timer].period = period;

	/* FIXME: re-program running timers? */

	return 0;
}

int
kperf_timer_get_action( unsigned timer, uint32_t *action )
{
	if( timer >= timerc )
		return EINVAL;

	*action = timerv[timer].actionid;

	return 0;
}

int
kperf_timer_set_action( unsigned timer, uint32_t action )
{
	if( timer >= timerc )
		return EINVAL;

	timerv[timer].actionid = action;

	return 0;
}

unsigned
kperf_timer_get_count(void)
{
	return timerc;
}

static void
setup_timer_call( struct time_trigger *trigger )
{
	timer_call_setup( &trigger->tcall, kperf_timer_handler, trigger );
}

extern int
kperf_timer_set_count(unsigned count)
{
	struct time_trigger *new_timerv = NULL, *old_timerv = NULL;
	unsigned old_count, i;

	/* easy no-op */
	if( count == timerc )
		return 0;

	/* TODO: allow shrinking? */
	if( count < timerc )
		return EINVAL;

	/* cap it for good measure */
	if( count > TIMER_MAX )
		return EINVAL;

	/* creating the action arror for the first time. create a few
	 * more things, too.
	 */
	if( timerc == 0 )
	{
		int r;

		/* main kperf */
		r = kperf_init();
		if( r )
			return r;

		/* get the PET thread going */
		r = kperf_pet_init();
		if( r )
			return r;
	}

	/* first shut down any running timers since we will be messing
	 * with the timer call structures
	 */
	if( kperf_timer_stop() )
		return EBUSY;

	/* create a new array */
	new_timerv = kalloc( count * sizeof(*new_timerv) );
	if( new_timerv == NULL )
		return ENOMEM;

	old_timerv = timerv;
	old_count = timerc;

	if( old_timerv != NULL )
		bcopy( timerv, new_timerv, timerc * sizeof(*timerv) );

	/* zero the new entries */
	bzero( &new_timerv[timerc], (count - old_count) * sizeof(*new_timerv) );

	/* (re-)setup the timer call info for all entries */
	for( i = 0; i < count; i++ )
		setup_timer_call( &new_timerv[i] );

	timerv = new_timerv;
	timerc = count;

	if( old_timerv != NULL )
		kfree( old_timerv, old_count * sizeof(*timerv) );

	return 0;
}
