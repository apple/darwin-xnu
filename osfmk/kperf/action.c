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

/*
 * Called from a trigger. Actually takes the data from the different
 * modules and puts them in a buffer
 */

#include <mach/mach_types.h>
#include <machine/machine_routines.h>
// #include <libkern/libkern.h>
#include <kern/kalloc.h>
#include <kern/debug.h> /* panic */
#include <kern/thread.h>
#include <sys/errno.h>

#include <chud/chud_xnu.h>
#include <kperf/kperf.h>

#include <kperf/buffer.h>
#include <kperf/timetrigger.h>
#include <kperf/threadinfo.h>
#include <kperf/callstack.h>
#include <kperf/sample.h>
#include <kperf/filter.h>
#include <kperf/action.h>
#include <kperf/context.h>
#include <kperf/ast.h>

#define ACTION_MAX 32

/* XXX: callback handler from chudxnu */
/* FIXME: hook this up to something */
//void (*kperf_thread_ast_handler)(thread_t);

/* the list of different actions to take */
struct action
{
	unsigned sample;
};

/* the list of actions */
static unsigned actionc = 0;
static struct action *actionv = NULL;


/* Do the real work! */
/* this can be called in any context ... right? */
static kern_return_t
kperf_sample_internal( struct kperf_sample *sbuf,
              struct kperf_context *context,
              unsigned sample_what, boolean_t pend_user )
{
	boolean_t enabled;
	int did_ucallstack = 0, did_tinfo_extra = 0;

	/* not much point continuing here, but what to do ? return
	 * Shutdown? cut a tracepoint and continue?
	 */
	if( sample_what == 0 )
		return SAMPLE_CONTINUE;

	int is_kernel = (context->cur_pid == 0);

	/*  an event occurred. Sample everything and dump it in a
	 *  buffer.
	 */

	/* collect data from samplers */
	if( sample_what & SAMPLER_TINFO ) {
		kperf_threadinfo_sample( &sbuf->threadinfo, context );
		
		/* XXX FIXME This drops events when the thread is idle.
		 * This should be configurable. */
		if (sbuf->threadinfo.runmode & 0x40)
			return SAMPLE_CONTINUE;
	}

	if( sample_what & SAMPLER_KSTACK )
		kperf_kcallstack_sample( &sbuf->kcallstack, context );

	/* sensitive ones */
	if ( !is_kernel ) {
		if( pend_user )
		{
			if( sample_what & SAMPLER_USTACK )
				did_ucallstack = kperf_ucallstack_pend( context );

			if( sample_what & SAMPLER_TINFOEX )
				did_tinfo_extra = kperf_threadinfo_extra_pend( context );
		}
		else
		{
			if( sample_what & SAMPLER_USTACK )
				kperf_ucallstack_sample( &sbuf->ucallstack, context );

			if( sample_what & SAMPLER_TINFOEX )
				kperf_threadinfo_extra_sample( &sbuf->tinfo_ex,
							       context );
		}
	}

	/* stash the data into the buffer
	 * interrupts off to ensure we don't get split
	 */
	enabled = ml_set_interrupts_enabled(FALSE);

	if ( pend_user )
		BUF_DATA1( PERF_GEN_EVENT | DBG_FUNC_START, sample_what );

	/* dump threadinfo */
	if( sample_what & SAMPLER_TINFO )
		kperf_threadinfo_log( &sbuf->threadinfo );

	/* dump kcallstack */
	if( sample_what & SAMPLER_KSTACK )
		kperf_kcallstack_log( &sbuf->kcallstack );


	/* dump user stuff */
	if ( !is_kernel ) {
		if ( pend_user )
		{
			if ( did_ucallstack )
				BUF_INFO1( PERF_CS_UPEND, 0 );

			if ( did_tinfo_extra )
				BUF_INFO1( PERF_TI_XPEND, 0 );
		}
		else
		{
			if( sample_what & SAMPLER_USTACK )
				kperf_ucallstack_log( &sbuf->ucallstack );

			if( sample_what & SAMPLER_TINFOEX )
				kperf_threadinfo_extra_log( &sbuf->tinfo_ex );
		}
	}

	if ( pend_user )
		BUF_DATA1( PERF_GEN_EVENT | DBG_FUNC_END, sample_what );

	/* intrs back on */
	ml_set_interrupts_enabled(enabled);

	return SAMPLE_CONTINUE;
}

/* Translate actionid into sample bits and take a sample */
kern_return_t
kperf_sample( struct kperf_sample *sbuf,
	      struct kperf_context *context,
              unsigned actionid, boolean_t pend_user )
{
	unsigned sample_what = 0;

	/* check samppling is on, or panic */
	if( kperf_sampling_status() == KPERF_SAMPLING_OFF )
		panic("trigger fired while sampling off");
	else if( kperf_sampling_status() == KPERF_SAMPLING_SHUTDOWN )
		return SAMPLE_SHUTDOWN;

	/* work out what to sample, if anything */
	if( actionid >= actionc )
		return SAMPLE_SHUTDOWN;

	sample_what = actionv[actionid].sample;

	return kperf_sample_internal( sbuf, context, sample_what, pend_user );
}

/* ast callback on a thread */
void
kperf_thread_ast_handler( thread_t thread )
{
	int r;
	uint32_t t_chud;
	unsigned sample_what = 0;
	/* we know we're on a thread, so let's do stuff */
	task_t task = NULL;

	/* Don't sample if we are shutting down or off */
	if( kperf_sampling_status() != KPERF_SAMPLING_ON )
		return;

	BUF_INFO1(PERF_AST_HNDLR | DBG_FUNC_START, thread);

	/* FIXME: probably want a faster allocator here... :P */
	struct kperf_sample *sbuf = kalloc( sizeof(*sbuf) );
	if( sbuf == NULL )
	{
		/* FIXME: error code */
		BUF_INFO1( PERF_AST_ERROR, 0 );
		goto error;
	}

	/* make a context, take a sample */
	struct kperf_context ctx;
	ctx.cur_thread = thread;
	ctx.cur_pid = -1;

	task = chudxnu_task_for_thread(thread);
	if(task)
		ctx.cur_pid = chudxnu_pid_for_task(task);

	/* decode the chud bits so we know what to sample */
	t_chud = kperf_get_thread_bits(thread);
	
	if (t_chud & T_AST_NAME)
		sample_what |= SAMPLER_TINFOEX;
	
	if (t_chud & T_AST_CALLSTACK)
		sample_what |= SAMPLER_USTACK;

	/* do the sample, just of the user stuff */
	r = kperf_sample_internal( sbuf, &ctx, sample_what, FALSE );

	/* free it again */
	kfree( sbuf, sizeof(*sbuf) );

error:
	BUF_INFO1(PERF_AST_HNDLR | DBG_FUNC_END, r);

}

/* register AST bits */
int
kperf_ast_pend( thread_t cur_thread, uint32_t check_bits,
		uint32_t set_bits )
{
	/* pend on the thread */
	uint32_t t_chud, set_done = 0;
 
	/* can only pend on the current thread */
	if( cur_thread != chudxnu_current_thread() )
		panic("pending to non-current thread");

	/* get our current bits */
	t_chud = kperf_get_thread_bits(cur_thread);

	/* see if it's already been done or pended */
	if( !(t_chud & check_bits ) )
	{
		/* set the bit on the thread */
		t_chud |= set_bits;
		kperf_set_thread_bits(cur_thread, t_chud);

		/* set the actual AST */
		kperf_set_thread_ast( cur_thread );

		set_done = 1;
	}

	return set_done;

//	BUF_INFO3( dbg_code, (uintptr_t)cur_thread, t_chud, set_done );
}

unsigned
kperf_action_get_count(void)
{
	return actionc;
}

int
kperf_action_set_samplers( unsigned actionid, uint32_t samplers )
{
	if( actionid >= actionc )
		return EINVAL;

	actionv[actionid].sample = samplers;

	return 0;
}

int
kperf_action_get_samplers( unsigned actionid, uint32_t *samplers_out )
{
	if( actionid >= actionc )
		return EINVAL;

	*samplers_out = actionv[actionid].sample;

	return 0;
}

int
kperf_action_set_count(unsigned count)
{
	struct action *new_actionv = NULL, *old_actionv = NULL;
	unsigned old_count;

	/* easy no-op */
	if( count == actionc )
		return 0;

	/* TODO: allow shrinking? */
	if( count < actionc )
		return EINVAL;

	/* cap it for good measure */
	if( count > ACTION_MAX )
		return EINVAL;

	/* creating the action arror for the first time. create a few
	 * more things, too.
	 */
       	if( actionc == 0 )
	{
		int r;
		r = kperf_init();

		if( r != 0 )
			return r;
	}

	/* create a new array */
	new_actionv = kalloc( count * sizeof(*new_actionv) );
	if( new_actionv == NULL )
		return ENOMEM;

	old_actionv = actionv;
	old_count = actionc;

	if( old_actionv != NULL )
		bcopy( actionv, new_actionv, actionc * sizeof(*actionv) );

	bzero( &new_actionv[actionc], (count - old_count) * sizeof(*actionv) );

	actionv = new_actionv;
	actionc = count;

	if( old_actionv != NULL )
		kfree( old_actionv, old_count * sizeof(*actionv) );

	printf( "kperf: done the alloc\n" );

	return 0;
}
