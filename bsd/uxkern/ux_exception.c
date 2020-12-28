/*
 * Copyright (c) 2000-2017 Apple Inc. All rights reserved.
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
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */

#include <sys/param.h>

#include <mach/boolean.h>
#include <mach/exception.h>
#include <mach/kern_return.h>

#include <sys/proc.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/vmparam.h>        /* MAXSSIZ */

#include <sys/ux_exception.h>

/*
 * Translate Mach exceptions to UNIX signals.
 *
 * ux_exception translates a mach exception, code and subcode to
 * a signal.  Calls machine_exception (machine dependent)
 * to attempt translation first.
 */
static int
ux_exception(int                        exception,
    mach_exception_code_t      code,
    mach_exception_subcode_t   subcode)
{
	int machine_signal = 0;

	/* Try machine-dependent translation first. */
	if ((machine_signal = machine_exception(exception, code, subcode)) != 0) {
		return machine_signal;
	}

	switch (exception) {
	case EXC_BAD_ACCESS:
		if (code == KERN_INVALID_ADDRESS) {
			return SIGSEGV;
		} else {
			return SIGBUS;
		}

	case EXC_BAD_INSTRUCTION:
		return SIGILL;

	case EXC_ARITHMETIC:
		return SIGFPE;

	case EXC_EMULATION:
		return SIGEMT;

	case EXC_SOFTWARE:
		switch (code) {
		case EXC_UNIX_BAD_SYSCALL:
			return SIGSYS;
		case EXC_UNIX_BAD_PIPE:
			return SIGPIPE;
		case EXC_UNIX_ABORT:
			return SIGABRT;
		case EXC_SOFT_SIGNAL:
			return SIGKILL;
		}
		break;

	case EXC_BREAKPOINT:
		return SIGTRAP;
	}

	return 0;
}

/*
 * Sends the corresponding UNIX signal to a thread that has triggered a Mach exception.
 */
kern_return_t
handle_ux_exception(thread_t                    thread,
    int                         exception,
    mach_exception_code_t       code,
    mach_exception_subcode_t    subcode)
{
	/* Returns +1 proc reference */
	proc_t p = proc_findthread(thread);

	/* Can't deliver a signal without a bsd process reference */
	if (p == NULL) {
		return KERN_FAILURE;
	}

	/* Translate exception and code to signal type */
	int ux_signal = ux_exception(exception, code, subcode);

	uthread_t ut = get_bsdthread_info(thread);

	/*
	 * Stack overflow should result in a SIGSEGV signal
	 * on the alternate stack.
	 * but we have one or more guard pages after the
	 * stack top, so we would get a KERN_PROTECTION_FAILURE
	 * exception instead of KERN_INVALID_ADDRESS, resulting in
	 * a SIGBUS signal.
	 * Detect that situation and select the correct signal.
	 */
	if (code == KERN_PROTECTION_FAILURE &&
	    ux_signal == SIGBUS) {
		user_addr_t sp = subcode;

		user_addr_t stack_max = p->user_stack;
		user_addr_t stack_min = p->user_stack - MAXSSIZ;
		if (sp >= stack_min && sp < stack_max) {
			/*
			 * This is indeed a stack overflow.  Deliver a
			 * SIGSEGV signal.
			 */
			ux_signal = SIGSEGV;

			/*
			 * If the thread/process is not ready to handle
			 * SIGSEGV on an alternate stack, force-deliver
			 * SIGSEGV with a SIG_DFL handler.
			 */
			int mask = sigmask(ux_signal);
			struct sigacts *ps = p->p_sigacts;
			if ((p->p_sigignore & mask) ||
			    (ut->uu_sigwait & mask) ||
			    (ut->uu_sigmask & mask) ||
			    (ps->ps_sigact[SIGSEGV] == SIG_IGN) ||
			    (!(ps->ps_sigonstack & mask))) {
				p->p_sigignore &= ~mask;
				p->p_sigcatch &= ~mask;
				ps->ps_sigact[SIGSEGV] = SIG_DFL;
				ut->uu_sigwait &= ~mask;
				ut->uu_sigmask &= ~mask;
			}
		}
	}

	/* Send signal to thread */
	if (ux_signal != 0) {
		ut->uu_exception = exception;
		//ut->uu_code = code; // filled in by threadsignal
		ut->uu_subcode = subcode;
		threadsignal(thread, ux_signal, code, TRUE);
	}

	proc_rele(p);

	return KERN_SUCCESS;
}
