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


/*  Sample thread data */

#include <mach/mach_types.h>
#include <kern/thread.h> /* thread_* */
#include <kern/debug.h> /* panic */
// #include <sys/proc.h>

#include <chud/chud_xnu.h>
#include <kperf/kperf.h>

#include <kperf/buffer.h>
#include <kperf/context.h>
#include <kperf/threadinfo.h>
#include <kperf/ast.h>

// kAppleProfileTriggerClientThreadModeIdle				= 0x40, // TH_IDLE
// #define TH_IDLE 0x40

//kAppleProfileTriggerClientThreadModeNotIdle				= kAppleProfileTriggerClientThreadModeIdle << 16, // !TH_IDLE
#define TH_IDLE_N (TH_IDLE << 16)

static uint64_t
make_runmode(thread_t thread)
{
	/* CEG: This is a translation of
	 * AppleProfileGetRunModeOfThread below... kinda magic :/
	 */
	const int mode = chudxnu_thread_get_scheduler_state(thread);
	
	if( 0 == mode)
	{
		return (chudxnu_thread_get_idle(thread) ? TH_IDLE : TH_IDLE_N);
	}
	else
	{
		// Today we happen to know there's a one-to-one mapping.
		return ((mode & 0xffff) | ((~mode & 0xffff) << 16));
	}
}


/* code to collect current thread info */
void
kperf_threadinfo_sample(struct threadinfo *ti, struct kperf_context *context)
{
	thread_t cur_thread = context->cur_thread;
	BUF_INFO1( PERF_TI_SAMPLE, (uintptr_t)cur_thread );

	// fill out the fields
	ti->pid = context->cur_pid;
	ti->tid = thread_tid(cur_thread);
	ti->dq_addr = thread_dispatchqaddr(cur_thread);
	ti->runmode = make_runmode(cur_thread);
}

/* log an existing sample into the buffer */
void
kperf_threadinfo_log(struct threadinfo *ti)
{
	/* XXX: K64 only? */
	BUF_DATA( PERF_TI_DATA, ti->pid, ti->tid, ti->dq_addr, ti->runmode );
}

/* 'extra' thread-info functions that are deferred 'til thread-context
 * time
 */
void
kperf_threadinfo_extra_sample(struct tinfo_ex *tex, struct kperf_context *context)
{
	thread_t cur_thread = context->cur_thread;
	uint32_t t_chud;

	/* can only pend on the current thread */
	/* this is valid from PET mode... */
	/*
	if( cur_thread != chudxnu_current_thread() )
		panic("pending to non-current thread");
	*/

	/* get our current bits */
	t_chud = kperf_get_thread_bits(cur_thread);

	/* check if there's anything for us to do */
	if( t_chud & T_AST_NAME )
	{
		BUF_INFO1( PERF_TI_XSAMPLE, (uintptr_t)cur_thread );

		/* get the name out */
#ifdef FIXME
		/* need kperfbsd.c? */
		proc_name( context->cur_pid, 
		           &tex->p_comm[0], CHUD_MAXPCOMM );
#endif

		/* mark that it's done */
		t_chud &= ~T_AST_NAME;
		t_chud |= T_NAME_DONE;

		kperf_set_thread_bits(cur_thread, t_chud);
	}
	else
		/* empty string */
		tex->p_comm[0] = '\0';

}

/* log it if there's anyting useful there */
void
kperf_threadinfo_extra_log(struct tinfo_ex *tex)
{
	/* no data */
	if( tex->p_comm[0] == '\0' )
		return;

	/* FIXME: log more */
	BUF_DATA1( PERF_TI_XDATA, (uintptr_t)*(uintptr_t*)&tex->p_comm[0] );
}

/* pend a flag on a thread */
int
kperf_threadinfo_extra_pend(struct kperf_context *context)
{
	return kperf_ast_pend( context->cur_thread, T_NAME_DONE | T_AST_NAME,
	                       T_AST_NAME );
}


#if 0

/* transalted from the APF */

APTIAKernelEntry_t *threadInfo = (APTIAKernelEntry_t*)(threadInfos + account->offset);

context->timeStamp = mach_absolute_time();
context->cpuNum = chudxnu_cpu_number();

// record the process info from the callback context
context->pid = chudxnu_current_pid();
threadInfo->pid = context->generic->pid;

// thread_tid is a thread_t to ID function in the kernel
context->threadID = chudxnu_current_thread();
threadInfo->tid = thread_tid(context->generic->threadID);

// also a kernel function
threadInfo->dispatch_queue_addr = thread_dispatchqaddr(context->generic->threadID);

// see below
threadInfo->runMode = AppleProfileGetRunModeOfThread(context->generic->threadID);


/****** WTF is this?! *******/

/*!enum AppleProfileTriggerClientThreadRunMode
 *
 * Specifies the thread mode in which to record samples.
 */
typedef enum { // Target Thread State - can be OR'd
	// Basic Building Blocks:
	// for Time Profile, use kAppleProfileTriggerClientThreadModeRunning (optionally with kAppleProfileTriggerClientThreadModeNotIdle).
	// for Time Profile (All Thread States), use kAppleProfileTriggerClientThreadModeAny (or just don't specify any thread mode filters).
	// for Time Profile (Blocked Threads), use kIOProfileTriggerClientThreadModeBlocked.
	// etc...
	
	kAppleProfileTriggerClientThreadModeNone				= 0x0,
	
	kAppleProfileTriggerClientThreadModeRunning				= 0x1, // On a core
	kAppleProfileTriggerClientThreadModeRunnable			= 0x2, // TH_RUN
	kAppleProfileTriggerClientThreadModeBlocked				= 0x4, // TH_WAIT
	kAppleProfileTriggerClientThreadModeUninterruptible		= 0x8, // TH_UNINT
	kAppleProfileTriggerClientThreadModeSuspended			= 0x10, // TH_SUSP
	kAppleProfileTriggerClientThreadModeTerminating			= 0x20, // TH_TERMINATE
	kAppleProfileTriggerClientThreadModeIdle				= 0x40, // TH_IDLE
	
	kAppleProfileTriggerClientThreadModeNotRunning			= kAppleProfileTriggerClientThreadModeRunning << 16, // Not on a core
	kAppleProfileTriggerClientThreadModeNotRunnable			= kAppleProfileTriggerClientThreadModeRunnable << 16, // !TH_RUN
	kAppleProfileTriggerClientThreadModeNotBlocked			= kAppleProfileTriggerClientThreadModeBlocked << 16, // !TH_WAIT
	kAppleProfileTriggerClientThreadModeNotUninterruptible	= kAppleProfileTriggerClientThreadModeUninterruptible << 16, // !TH_UNINT
	kAppleProfileTriggerClientThreadModeNotSuspended		= kAppleProfileTriggerClientThreadModeSuspended << 16, // !TH_SUSP
	kAppleProfileTriggerClientThreadModeNotTerminating		= kAppleProfileTriggerClientThreadModeTerminating << 16, // !TH_TERMINATE
	kAppleProfileTriggerClientThreadModeNotIdle				= kAppleProfileTriggerClientThreadModeIdle << 16, // !TH_IDLE
	
	kAppleProfileTriggerClientThreadModeAny					= (   kAppleProfileTriggerClientThreadModeRunning
																| kAppleProfileTriggerClientThreadModeNotRunning),
} AppleProfileTriggerClientThreadRunMode;

extern "C" AppleProfileTriggerClientThreadRunMode AppleProfileGetRunModeOfThread(thread_t thread) {	
	const int mode = chudxnu_thread_get_scheduler_state(thread);
	
	if (0 == mode) {
		return (chudxnu_thread_get_idle(thread) ? kAppleProfileTriggerClientThreadModeIdle : kAppleProfileTriggerClientThreadModeNotIdle);
	} else
	return (AppleProfileTriggerClientThreadRunMode)((mode & 0xffff) | ((~mode & 0xffff) << 16)); // Today we happen to know there's a one-to-one mapping.
}

#endif
