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
 * Mach Operating System
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <mach_assert.h>
#include <mach_kdb.h>
#include <mach_kgdb.h>
#include <mach_kdp.h>
#include <cpus.h>

#include <kern/cpu_number.h>
#include <kern/lock.h>
#include <kern/spl.h>
#include <kern/thread.h>
#include <kern/assert.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <vm/vm_kern.h>
#include <stdarg.h>

#ifdef	__ppc__
#include <ppc/Firmware.h>
#include <ppc/low_trace.h>
#endif

unsigned int	halt_in_debugger = 0;
unsigned int	switch_debugger = 0;
unsigned int	current_debugger = 0;
unsigned int	active_debugger = 0;
unsigned int	debug_mode=0;
unsigned int 	disableDebugOuput = TRUE;
unsigned int 	systemLogDiags = FALSE;
unsigned int    logPanicDataToScreen = FALSE;
#ifdef __ppc__
        unsigned int 	panicDebugging = FALSE;
#else
        unsigned int 	panicDebugging = TRUE;
#endif

int mach_assert = 1;

const char		*panicstr = (char *) 0;
decl_simple_lock_data(,panic_lock)
int			paniccpu;
volatile int		panicwait;
volatile int		nestedpanic= 0;
unsigned int		panic_is_inited = 0;
unsigned int		return_on_panic = 0;
wait_queue_t		save_waits[NCPUS];

char *debug_buf;
char *debug_buf_ptr;
unsigned int debug_buf_size = 0;

void
Assert(
	const char	*file,
	int		line,
	const char	*expression)
{
	if (!mach_assert) {
		return;
	}
	panic("{%d} Assertion failed: file \"%s\", line %d: %s\n", 
	       cpu_number(), file, line, expression);
}

/*
 *	Carefully use the panic_lock.  There's always a chance that
 *	somehow we'll call panic before getting to initialize the
 *	panic_lock -- in this case, we'll assume that the world is
 *	in uniprocessor mode and just avoid using the panic lock.
 */
#define	PANIC_LOCK()							\
MACRO_BEGIN								\
	if (panic_is_inited)						\
		simple_lock(&panic_lock);				\
MACRO_END

#define	PANIC_UNLOCK()							\
MACRO_BEGIN								\
	if (panic_is_inited)						\
		simple_unlock(&panic_lock);				\
MACRO_END


void
panic_init(void)
{
	simple_lock_init(&panic_lock, ETAP_NO_TRACE);
	panic_is_inited = 1;
}

void
panic(const char *str, ...)
{
	va_list	listp;
	spl_t	s;
	thread_t thread;

	s = splhigh();
	disable_preemption();

#ifdef	__ppc__
	lastTrace = LLTraceSet(0);		/* Disable low-level tracing */
#endif

	thread = current_thread();		/* Get failing thread */
	save_waits[cpu_number()] = thread->wait_queue;	/* Save the old value */
	thread->wait_queue = 0;			/* Clear the wait so we do not get double panics when we try locks */

	if( logPanicDataToScreen )
		disableDebugOuput = FALSE;
		
	debug_mode = TRUE;
restart:
	PANIC_LOCK();
	if (panicstr) {
		if (cpu_number() != paniccpu) {
			PANIC_UNLOCK();
			/*
			 * Wait until message has been printed to identify correct
			 * cpu that made the first panic.
			 */
			while (panicwait)
				continue;
			goto restart;
	    } else {
			nestedpanic +=1;
			PANIC_UNLOCK();
			Debugger("double panic");
			printf("double panic:  We are hanging here...\n");
			while(1);
			/* NOTREACHED */
		}
	}
	panicstr = str;
	paniccpu = cpu_number();
	panicwait = 1;

	PANIC_UNLOCK();
	kdb_printf("panic(cpu %d): ", (unsigned) paniccpu);
	va_start(listp, str);
	_doprnt(str, &listp, consdebug_putc, 0);
	va_end(listp);
	kdb_printf("\n");

	/*
	 * Release panicwait indicator so that other cpus may call Debugger().
	 */
	panicwait = 0;
	Debugger("panic");
	/*
	 * Release panicstr so that we can handle normally other panics.
	 */
	PANIC_LOCK();
	panicstr = (char *)0;
	PANIC_UNLOCK();
	thread->wait_queue = save_waits[cpu_number()]; 	/* Restore the wait queue */
	if (return_on_panic) {
		enable_preemption();
		splx(s);
		return;
	}
	kdb_printf("panic: We are hanging here...\n");
	while(1);
	/* NOTREACHED */
}

void
log(int level, char *fmt, ...)
{
	va_list	listp;

#ifdef lint
	level++;
#endif /* lint */
#ifdef	MACH_BSD
	disable_preemption();
	va_start(listp, fmt);
	_doprnt(fmt, &listp, conslog_putc, 0);
	va_end(listp);
	enable_preemption();
#endif
}

void
debug_log_init(void)
{
	if (debug_buf_size != 0)
		return;
	if (kmem_alloc(kernel_map, (vm_offset_t *) &debug_buf, PAGE_SIZE) != KERN_SUCCESS)
		panic("cannot allocate debug_buf \n");
	debug_buf_ptr = debug_buf;
	debug_buf_size = PAGE_SIZE;
}

void
debug_putc(char c)
{
	if ((debug_buf_size != 0) && ((debug_buf_ptr-debug_buf) < debug_buf_size)) {
		*debug_buf_ptr=c;
		debug_buf_ptr++;
	}
}
