/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/kalloc.h>

#include <sys/proc.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/ux_exception.h>

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
extern void ipc_port_release(ipc_port_t);




/*
 *	Unix exception handler.
 */

static void	ux_exception(int exception, int code, int subcode,
				int *ux_signal, int *ux_code);

mach_port_name_t		ux_exception_port;
static task_t			ux_handler_self;

static
void
ux_handler(void)
{
    task_t		self = current_task();
    mach_port_name_t	exc_port_name;
    mach_port_name_t	exc_set_name;

    (void) thread_funnel_set(kernel_flock, TRUE);

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

    thread_wakeup(&ux_exception_port);

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
		exception_data_t code;
		/* some times RCV_TO_LARGE probs */
		char pad[512];
	} exc_msg;
	mach_port_name_t	reply_port;
	kern_return_t	 result;

	exc_msg.Head.msgh_local_port = (mach_port_t)exc_set_name;
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
	    reply_port = (mach_port_name_t)exc_msg.Head.msgh_remote_port;

	    if (exc_server(&exc_msg.Head, &rep_msg.Head))
		(void) mach_msg_send(&rep_msg.Head, MACH_SEND_MSG,
			sizeof (rep_msg),MACH_MSG_TIMEOUT_NONE,MACH_PORT_NULL);

	    if (reply_port != MACH_PORT_NULL)
		(void) mach_port_deallocate(get_task_ipcspace(ux_handler_self), reply_port);
	}
	else if (result == MACH_RCV_TOO_LARGE)
		/* ignore oversized messages */;
	else
		panic("exception_handler");
    }
	thread_funnel_set(kernel_flock, FALSE);
}

void
ux_handler_init(void)
{
	ux_exception_port = MACH_PORT_NULL;
	(void) kernel_thread(kernel_task, ux_handler);
	if (ux_exception_port == MACH_PORT_NULL)  {
		assert_wait(&ux_exception_port, THREAD_UNINT);
		thread_block(THREAD_CONTINUE_NULL);
		}
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
	task_t		self = current_task();
	thread_t	th_act;
	ipc_port_t 	thread_port;
	kern_return_t	result = MACH_MSG_SUCCESS;
	int		ux_signal = 0;
	u_long		ucode = 0;
	struct uthread *ut;
	mach_port_name_t thread_name = (mach_port_name_t)thread; /* XXX */
	mach_port_name_t task_name = (mach_port_name_t)task;	/* XXX */

   /*
     *	Convert local thread name to global port.
     */
   if (MACH_PORT_VALID(thread_name) &&
       (ipc_object_copyin(get_task_ipcspace(self), thread_name,
		       MACH_MSG_TYPE_PORT_SEND,
		       (void *) &thread_port) == MACH_MSG_SUCCESS)) {
        if (IPC_PORT_VALID(thread_port)) {
	   th_act = convert_port_to_thread(thread_port);
	   ipc_port_release(thread_port);
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
		ut = get_bsdthread_info(th_act);
	    ux_exception(exception, code[0], code[1],
	    			&ux_signal, (int *)&ucode);

	    /*
	     *	Send signal.
	     */
	    if (ux_signal != 0) {
			ut->uu_exception = exception;
			//ut->uu_code = code[0]; // filled in by threadsignal
			ut->uu_subcode = code[1];			
			threadsignal(th_act, ux_signal, code[0]);
		}

	    thread_deallocate(th_act);
	}
	else
	    result = KERN_INVALID_ARGUMENT;
    }
    else
    	result = KERN_INVALID_ARGUMENT;

    /*
     *	Delete our send rights to the task and thread ports.
     */
    (void)mach_port_deallocate(get_task_ipcspace(ux_handler_self), task_name);
    (void)mach_port_deallocate(get_task_ipcspace(ux_handler_self), thread_name);

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

/*
 *	ux_exception translates a mach exception, code and subcode to
 *	a signal and u.u_code.  Calls machine_exception (machine dependent)
 *	to attempt translation first.
 */

static
void ux_exception(
    int			exception,
    int			code,
    int			subcode,
    int			*ux_signal,
    int			*ux_code
)
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
