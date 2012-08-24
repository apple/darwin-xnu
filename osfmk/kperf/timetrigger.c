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

#include <chud/chud_xnu.h>

#include <kperf/kperf.h>
#include <kperf/buffer.h>
#include <kperf/context.h>
#include <kperf/action.h>
#include <kperf/timetrigger.h>
#include <kperf/kperf_arch.h>
#include <kperf/pet.h>

/* represents a periodic timer */
struct time_trigger
{
	struct timer_call tcall;
	uint64_t period;
	unsigned actionid;
	volatile unsigned active;
};

/* the list of timers */
static unsigned timerc = 0;
static struct time_trigger *timerv;
static unsigned pet_timer = 999;

/* maximum number of timers we can construct */
#define TIMER_MAX 16

/* minimal interval for a timer (100usec in nsec) */
#define MIN_TIMER (100000)

static void
kperf_timer_schedule( struct time_trigger *trigger, uint64_t now )
{
	uint64_t deadline;

	BUF_INFO1(PERF_TM_SCHED, trigger->period);

	/* calculate deadline */
	deadline = now + trigger->period;
	
	/* re-schedule the timer, making sure we don't apply slop */
	timer_call_enter( &trigger->tcall, deadline, TIMER_CALL_CRITICAL);
}

static void
kperf_ipi_handler( void *param )
{
	int r;
	struct kperf_sample *intbuf = NULL;
	struct kperf_context ctx;
	struct time_trigger *trigger = param;
	task_t task = NULL;
	
	BUF_INFO1(PERF_TM_HNDLR | DBG_FUNC_START, 0);

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

	/* call the action -- kernel-only from interrupt, pend user */
	r = kperf_sample( intbuf, &ctx, trigger->actionid, TRUE );
	
	BUF_INFO1(PERF_TM_HNDLR | DBG_FUNC_END, r);
}

static void
kperf_timer_handler( void *param0, __unused void *param1 )
{
	struct time_trigger *trigger = param0;
	unsigned ntimer = (unsigned)(trigger - timerv);

	trigger->active = 1;

	/* along the lines of do not ipi if we are all shutting down */
	if( kperf_sampling_status() == KPERF_SAMPLING_SHUTDOWN )
		goto deactivate;

	/* ping all CPUs */
	kperf_mp_broadcast( kperf_ipi_handler, trigger );

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
kperf_timer_pet_set( unsigned timer )
{
	uint64_t now;
	struct time_trigger *trigger = NULL;

	if( timer != pet_timer )
		panic( "PET setting with bogus ID\n" );

	if( timer >= timerc )
		return EINVAL;

	/* CHECKME: we probably took so damn long in the PET thread,
	 * it makes sense to take the time again.
	 */
	now = mach_absolute_time();
	trigger = &timerv[timer];

	/* reprogram */
	kperf_timer_schedule( trigger, now );

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
	printf( "get timer %u / %u\n", timer, timerc );

	if( timer >= timerc )
		return EINVAL;

	*period = timerv[timer].period;

	return 0;
}

int
kperf_timer_set_period( unsigned timer, uint64_t period )
{
	printf( "set timer %u\n", timer );

	if( timer >= timerc )
		return EINVAL;

	if( period < MIN_TIMER )
		period = MIN_TIMER;

	timerv[timer].period = period;

	/* FIXME: re-program running timers? */

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
	{
		printf( "already got %d timers\n", timerc );
		return 0;
	}

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

	/* setup the timer call info */
	for( i = old_count; i < count; i++ )
		setup_timer_call( &new_timerv[i] );

	timerv = new_timerv;
	timerc = count;

	if( old_timerv != NULL )
		kfree( old_timerv, old_count * sizeof(*timerv) );

	printf( "kperf: done timer alloc, timerc %d\n", timerc );

	return 0;
}
