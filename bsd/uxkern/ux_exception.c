/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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

/*
 *********************************************************************
 * HISTORY
 **********************************************************************
 */

#include <sys/param.h>

#include <mach/boolean.h>
#include <mach/exception.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/mach_port.h>
#include <mach/mig_errors.h>
#include <mach/exc_server.h>
#include <mach/mach_exc_server.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/kalloc.h>

#include <sys/proc.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/ux_exception.h>
#include <sys/vmparam.h>	/* MAXSSIZ */

#include <vm/vm_protos.h>	/* get_task_ipcspace() */
/*
 * XXX Things that should be retrieved from Mach headers, but aren't
 */
struct ipc_object;
extern kern_return_t ipc_object_copyin(ipc_space_t space, mach_port_name_t name,
		mach_msg_type_name_t msgt_name, struct ipc_object **objectp);
extern mach_msg_return_t mach_msg_receive(mach_msg_header_t *msg,
		mach_msg_option_t option, mach_msg_size_t rcv_size,
		mach_port_name_t rcv_name, mach_msg_timeout_t rcv_timeout,
		void (*continuation)(mach_msg_return_t),
		mach_msg_size_t slist_size);
extern mach_msg_return_t mach_msg_send(mach_msg_header_t *msg,
		mach_msg_option_t option, mach_msg_size_t send_size,
		mach_msg_timeout_t send_timeout, mach_port_name_t notify);
extern thread_t convert_port_to_thread(ipc_port_t port);
extern void ipc_port_release_send(ipc_port_t port);




/*
 *	Unix exception handler.
 */

static void	ux_exception(int exception, mach_exception_code_t code, 
				mach_exception_subcode_t subcode,
				int *ux_signal, mach_exception_code_t *ux_code);

#if defined(__x86_64__) || defined(__arm64__)
mach_port_t			ux_exception_port;
#else
mach_port_name_t		ux_exception_port;
#endif /* __x86_64__ */

static task_t			ux_handler_self;

static
void
ux_handler(void)
{
    task_t		self = current_task();
    mach_port_name_t	exc_port_name;
    mach_port_name_t	exc_set_name;

    /* self->kernel_vm_space = TRUE; */
    ux_handler_self = self;


    /*
     *	Allocate a port set that we will receive on.
     */
    if (mach_port_allocate(get_task_ipcspace(ux_handler_self), MACH_PORT_RIGHT_PORT_SET,  &exc_set_name) != MACH_MSG_SUCCESS)
	    panic("ux_handler: port_set_allocate failed");

    /*
     *	Allocate an exception port and use object_copyin to
     *	translate it to the global name.  Put it into the set.
     */
    if (mach_port_allocate(get_task_ipcspace(ux_handler_self), MACH_PORT_RIGHT_RECEIVE, &exc_port_name) != MACH_MSG_SUCCESS)
	panic("ux_handler: port_allocate failed");
    if (mach_port_move_member(get_task_ipcspace(ux_handler_self),
    			exc_port_name,  exc_set_name) != MACH_MSG_SUCCESS)
	panic("ux_handler: port_set_add failed");

    if (ipc_object_copyin(get_task_ipcspace(self), exc_port_name,
			MACH_MSG_TYPE_MAKE_SEND, 
			(void *) &ux_exception_port) != MACH_MSG_SUCCESS)
		panic("ux_handler: object_copyin(ux_exception_port) failed");

    proc_list_lock();
    thread_wakeup(&ux_exception_port);
    proc_list_unlock();

    /* Message handling loop. */

    for (;;) {
	struct rep_msg {
		mach_msg_header_t Head;
		NDR_record_t NDR;
		kern_return_t RetCode;
	} rep_msg;
	struct exc_msg {
		mach_msg_header_t Head;
		/* start of the kernel processed data */
		mach_msg_body_t msgh_body;
		mach_msg_port_descriptor_t thread;
		mach_msg_port_descriptor_t task;
		/* end of the kernel processed data */
		NDR_record_t NDR;
		exception_type_t exception;
		mach_msg_type_number_t codeCnt;
		mach_exception_data_t code;
		/* some times RCV_TO_LARGE probs */
		char pad[512];
	} exc_msg;
	mach_port_name_t	reply_port;
	kern_return_t	 result;

	exc_msg.Head.msgh_local_port = CAST_MACH_NAME_TO_PORT(exc_set_name);
	exc_msg.Head.msgh_size = sizeof (exc_msg);
#if 0
	result = mach_msg_receive(&exc_msg.Head);
#else
	result = mach_msg_receive(&exc_msg.Head, MACH_RCV_MSG,
			     sizeof (exc_msg), exc_set_name,
			     MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL,
			     0);
#endif
	if (result == MACH_MSG_SUCCESS) {
	    reply_port = CAST_MACH_PORT_TO_NAME(exc_msg.Head.msgh_remote_port);

	    if (mach_exc_server(&exc_msg.Head, &rep_msg.Head)) {
		result = mach_msg_send(&rep_msg.Head, MACH_SEND_MSG,
			sizeof (rep_msg),MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL);
		if (reply_port != 0 && result != MACH_MSG_SUCCESS)
			mach_port_deallocate(get_task_ipcspace(ux_handler_self), reply_port);
	    }

	}
	else if (result == MACH_RCV_TOO_LARGE)
		/* ignore oversized messages */;
	else
		panic("exception_handler");
    }
}

void
ux_handler_init(void)
{
	thread_t	thread = THREAD_NULL;

	ux_exception_port = MACH_PORT_NULL;
	(void) kernel_thread_start((thread_continue_t)ux_handler, NULL, &thread);
	thread_deallocate(thread);
	proc_list_lock();
	if (ux_exception_port == MACH_PORT_NULL)  {
		(void)msleep(&ux_exception_port, proc_list_mlock, 0, "ux_handler_wait", 0);
	}
	proc_list_unlock();
}

kern_return_t
catch_exception_raise(
        __unused mach_port_t exception_port,
        mach_port_t thread,
        mach_port_t task,
        exception_type_t exception,
        exception_data_t code,
        __unused mach_msg_type_number_t codeCnt
)
{
	mach_exception_data_type_t big_code[EXCEPTION_CODE_MAX];
	big_code[0] = code[0];
	big_code[1] = code[1];

	return catch_mach_exception_raise(exception_port,
			thread,
			task,
			exception,
			big_code,
			codeCnt);

}

kern_return_t
catch_mach_exception_raise(
        __unused mach_port_t exception_port,
        mach_port_t thread,
        mach_port_t task,
        exception_type_t exception,
        mach_exception_data_t code,
        __unused mach_msg_type_number_t codeCnt
)
{
	task_t			self = current_task();
	thread_t		th_act;
	ipc_port_t 		thread_port;
	struct proc		*p;
	kern_return_t		result = MACH_MSG_SUCCESS;
	int			ux_signal = 0;
	mach_exception_code_t 	ucode = 0;
	struct uthread 		*ut;
	mach_port_name_t thread_name = CAST_MACH_PORT_TO_NAME(thread);
	mach_port_name_t task_name = CAST_MACH_PORT_TO_NAME(task);

	/*
	 *	Convert local thread name to global port.
	 */
   if (MACH_PORT_VALID(thread_name) &&
       (ipc_object_copyin(get_task_ipcspace(self), thread_name,
		       MACH_MSG_TYPE_PORT_SEND,
		       (void *) &thread_port) == MACH_MSG_SUCCESS)) {
        if (IPC_PORT_VALID(thread_port)) {
	   th_act = convert_port_to_thread(thread_port);
	   ipc_port_release_send(thread_port);
	} else {
	   th_act = THREAD_NULL;
	}

	/*
	 *	Catch bogus ports
	 */
	if (th_act != THREAD_NULL) {

	    /*
	     *	Convert exception to unix signal and code.
	     */
	    ux_exception(exception, code[0], code[1], &ux_signal, &ucode);

	    ut = get_bsdthread_info(th_act);
	    p = proc_findthread(th_act);

	    /* Can't deliver a signal without a bsd process reference */
	    if (p == NULL) {
		    ux_signal = 0;
		    result = KERN_FAILURE;
	    }

	    /*
	     * Stack overflow should result in a SIGSEGV signal
	     * on the alternate stack.
	     * but we have one or more guard pages after the
	     * stack top, so we would get a KERN_PROTECTION_FAILURE
	     * exception instead of KERN_INVALID_ADDRESS, resulting in
	     * a SIGBUS signal.
	     * Detect that situation and select the correct signal.
	     */
	    if (code[0] == KERN_PROTECTION_FAILURE &&
		ux_signal == SIGBUS) {
		    user_addr_t		sp, stack_min, stack_max;
		    int			mask;
		    struct sigacts	*ps;

		    sp = code[1];

		    stack_max = p->user_stack;
		    stack_min = p->user_stack - MAXSSIZ;
		    if (sp >= stack_min &&
			sp < stack_max) {
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
			    mask = sigmask(ux_signal);
			    ps = p->p_sigacts;
			    if ((p->p_sigignore & mask) ||
				(ut->uu_sigwait & mask) ||
				(ut->uu_sigmask & mask) ||
				(ps->ps_sigact[SIGSEGV] == SIG_IGN) ||
				(! (ps->ps_sigonstack & mask))) {
				    p->p_sigignore &= ~mask;
				    p->p_sigcatch &= ~mask;
				    ps->ps_sigact[SIGSEGV] = SIG_DFL;
				    ut->uu_sigwait &= ~mask;
				    ut->uu_sigmask &= ~mask;
			    }
		    }
	    }
	    /*
	     *	Send signal.
	     */
	    if (ux_signal != 0) {
			ut->uu_exception = exception;
			//ut->uu_code = code[0]; // filled in by threadsignal
			ut->uu_subcode = code[1];			
			threadsignal(th_act, ux_signal, code[0]);
	    }
	    if (p != NULL) 
		    proc_rele(p);
	    thread_deallocate(th_act);
	}
	else
	    result = KERN_INVALID_ARGUMENT;
    }
    else
    	result = KERN_INVALID_ARGUMENT;

    /*
     *	Delete our send rights to the task port.
     */
    (void)mach_port_deallocate(get_task_ipcspace(ux_handler_self), task_name);

    return (result);
}

kern_return_t
catch_exception_raise_state(
        __unused mach_port_t exception_port,
        __unused exception_type_t exception,
        __unused const exception_data_t code,
        __unused mach_msg_type_number_t codeCnt,
        __unused int *flavor,
        __unused const thread_state_t old_state,
        __unused mach_msg_type_number_t old_stateCnt,
        __unused thread_state_t new_state,
        __unused mach_msg_type_number_t *new_stateCnt)
{
	return(KERN_INVALID_ARGUMENT);
}

kern_return_t
catch_mach_exception_raise_state(
        __unused mach_port_t exception_port,
        __unused exception_type_t exception,
        __unused const mach_exception_data_t code,
        __unused mach_msg_type_number_t codeCnt,
        __unused int *flavor,
        __unused const thread_state_t old_state,
        __unused mach_msg_type_number_t old_stateCnt,
        __unused thread_state_t new_state,
        __unused mach_msg_type_number_t *new_stateCnt)
{
	return(KERN_INVALID_ARGUMENT);
}

kern_return_t
catch_exception_raise_state_identity(
        __unused mach_port_t exception_port,
        __unused mach_port_t thread,
        __unused mach_port_t task,
        __unused exception_type_t exception,
        __unused exception_data_t code,
        __unused mach_msg_type_number_t codeCnt,
        __unused int *flavor,
        __unused thread_state_t old_state,
        __unused mach_msg_type_number_t old_stateCnt,
        __unused thread_state_t new_state,
        __unused mach_msg_type_number_t *new_stateCnt)
{
	return(KERN_INVALID_ARGUMENT);
}

kern_return_t
catch_mach_exception_raise_state_identity(
        __unused mach_port_t exception_port,
        __unused mach_port_t thread,
        __unused mach_port_t task,
        __unused exception_type_t exception,
        __unused mach_exception_data_t code,
        __unused mach_msg_type_number_t codeCnt,
        __unused int *flavor,
        __unused thread_state_t old_state,
        __unused mach_msg_type_number_t old_stateCnt,
        __unused thread_state_t new_state,
        __unused mach_msg_type_number_t *new_stateCnt)
{
	return(KERN_INVALID_ARGUMENT);
}


/*
 *	ux_exception translates a mach exception, code and subcode to
 *	a signal and u.u_code.  Calls machine_exception (machine dependent)
 *	to attempt translation first.
 */

static
void ux_exception(
		int			exception,
		mach_exception_code_t 	code,
		mach_exception_subcode_t subcode,
		int			*ux_signal,
		mach_exception_code_t 	*ux_code)
{
    /*
     *	Try machine-dependent translation first.
     */
    if (machine_exception(exception, code, subcode, ux_signal, ux_code))
	return;
	
    switch(exception) {

	case EXC_BAD_ACCESS:
		if (code == KERN_INVALID_ADDRESS)
			*ux_signal = SIGSEGV;
		else
			*ux_signal = SIGBUS;
		break;

	case EXC_BAD_INSTRUCTION:
	    *ux_signal = SIGILL;
	    break;

	case EXC_ARITHMETIC:
	    *ux_signal = SIGFPE;
	    break;

	case EXC_EMULATION:
	    *ux_signal = SIGEMT;
	    break;

	case EXC_SOFTWARE:
	    switch (code) {

	    case EXC_UNIX_BAD_SYSCALL:
		*ux_signal = SIGSYS;
		break;
	    case EXC_UNIX_BAD_PIPE:
		*ux_signal = SIGPIPE;
		break;
	    case EXC_UNIX_ABORT:
		*ux_signal = SIGABRT;
		break;
	    case EXC_SOFT_SIGNAL:
		*ux_signal = SIGKILL;
		break;
	    }
	    break;

	case EXC_BREAKPOINT:
	    *ux_signal = SIGTRAP;
	    break;
    }
}
