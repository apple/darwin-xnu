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

/* Collect kernel callstacks */

#include <mach/mach_types.h>
#include <machine/machine_routines.h>  /* XXX: remove me */
#include <kern/thread.h>

#include <chud/chud_xnu.h>

#include <kperf/buffer.h>
#include <kperf/context.h>
#include <kperf/callstack.h>
#include <kperf/ast.h>

static void
callstack_sample( struct callstack *cs, 
                  struct kperf_context *context,
                  uint32_t is_user )
{
	kern_return_t kr;
	mach_msg_type_number_t nframes; /* WTF with the type? */
	uint32_t code;

	if( is_user )
		code = PERF_CS_USAMPLE;
	else
		code = PERF_CS_KSAMPLE;

	BUF_INFO1( code, (uintptr_t)context->cur_thread );

	/* fill out known flags */
	cs->flags = 0;
	if( !is_user )
	{
		cs->flags |= CALLSTACK_KERNEL;
#ifdef __LP64__
		cs->flags |= CALLSTACK_64BIT;
#endif
	}
	else
	{
		/* FIXME: detect 32 vs 64-bit? */
	}

	/* collect the callstack */
	nframes = MAX_CALLSTACK_FRAMES;
	kr = chudxnu_thread_get_callstack64_kperf( context->cur_thread, 
						   cs->frames, 
						   &nframes,
						   is_user );

	/* check for overflow */
	if( kr == KERN_SUCCESS )
	{
		cs->flags |= CALLSTACK_VALID;
		cs->nframes = nframes;
	}
	else if( kr == KERN_RESOURCE_SHORTAGE )
	{
		/* FIXME: more here */
		cs->flags |= CALLSTACK_TRUNCATED;
		cs->flags |= CALLSTACK_VALID;
		cs->nframes = nframes;
	}
	else
	{
		BUF_INFO2(PERF_CS_ERROR, ERR_GETSTACK, kr);
		cs->nframes = 0;
	}

	if( cs->nframes >= MAX_CALLSTACK_FRAMES )
	{
		/* necessary? */
		BUF_INFO1(PERF_CS_ERROR, ERR_FRAMES);
		cs->nframes = 0;
	}

}

void
kperf_kcallstack_sample( struct callstack *cs, struct kperf_context *context )
{
	callstack_sample( cs, context, 0 );
}

void
kperf_ucallstack_sample( struct callstack *cs, struct kperf_context *context )
{
	callstack_sample( cs, context, 1 );
}

static void
callstack_log( struct callstack *cs, uint32_t hcode, uint32_t dcode )
{
	unsigned int i, j, n, of = 4;

	/* Header on the stack */
	BUF_DATA2( hcode, cs->flags, cs->nframes );

	/* look for how many batches of 4 */
	n  = cs->nframes / 4;
	of = cs->nframes % 4;
	if( of != 0 )
		n++;

	/* print all the stack data, and zero the overflow */
	for( i = 0; i < n; i++ )
	{
#define SCRUB_FRAME(x) (((x)<cs->nframes)?cs->frames[x]:0)
		j = i * 4;
		BUF_DATA ( dcode, 
		           SCRUB_FRAME(j+0),
		           SCRUB_FRAME(j+1),
		           SCRUB_FRAME(j+2),
		           SCRUB_FRAME(j+3) );
#undef SCRUB_FRAME
	}
}

void
kperf_kcallstack_log( struct callstack *cs )
{
	callstack_log( cs, PERF_CS_KHDR, PERF_CS_KDATA );
}

void
kperf_ucallstack_log( struct callstack *cs )
{
	callstack_log( cs, PERF_CS_UHDR, PERF_CS_UDATA );
}

int
kperf_ucallstack_pend( struct kperf_context * context )
{
	return kperf_ast_pend( context->cur_thread, T_AST_CALLSTACK,
	                       T_AST_CALLSTACK );
}

// 	kr = chudxnu_thread_get_callstack(context->generic->threadID, 
//              (uint32_t*)frames, &frameCount, !collectingSupervisorStack);
