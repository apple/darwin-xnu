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
#include <mach/kern_return.h>
#include <kern/thread.h>
#include <ppc/exception.h>
#include <kern/ipc_tt.h>
#include <ipc/ipc_port.h>
#include <ppc/atomic_switch.h>
#include <kern/thread_act.h>

int	debugNotify = 0;

/*
** Function:	NotifyInterruption
**
** Inputs:	port			- mach_port for main thread
**		ppcInterrupHandler	- interrupt handler to execute
**		interruptStatePtr	- current interrupt state
**		emulatorDescriptor	- where in emulator to notify
**		originalPC		- where the emulator was executing
**		originalR2		- new R2
**
** Outputs:
**
** Notes:
**
*/

unsigned long
syscall_notify_interrupt(mach_port_t, UInt32, UInt32 *, EmulatorDescriptor *,
				void **	, void **, void *);

unsigned long
syscall_notify_interrupt(	mach_port_t		port_thread,
				UInt32			ppcInterruptHandler,
				UInt32 *		interruptStatePtr,
				EmulatorDescriptor *	emulatorDescriptor,
				void **			originalPC,
				void **			originalR2,
				void			*othread )
{
    kern_return_t	result; 
    struct ppc_saved_state	*mainPCB;
    thread_t		thread, nthread;
    thread_act_t	act;
    UInt32		interruptState, currentState, postIntMask;
    extern thread_act_t port_name_to_act(mach_port_t);
    boolean_t		isSelf, runningInKernel;
	static unsigned long	sequence =0;

#define	COPYIN_INTSTATE() { \
	(void) copyin((char *) interruptStatePtr, (char *)&interruptState, sizeof(interruptState)); \
	if (emulatorDescriptor) \
		(void) copyin((char *) &emulatorDescriptor->postIntMask, (char *)&postIntMask, sizeof(postIntMask));  }
#define	COPYOUT_INTSTATE() (void) copyout((char *) &interruptState, (char *)interruptStatePtr, sizeof(interruptState))


    act = port_name_to_act(port_thread);

   
    if (act == THR_ACT_NULL) 
	return port_thread;

    runningInKernel = (act->mact.ksp == 0);
    isSelf = (current_act() == act);

    if (!isSelf) {
    	/* First.. suspend the thread */
	    result = thread_suspend(act);
	
	    if (result) {
		act_deallocate(act);
		return port_thread;
	   }
	
	    /* Now try to find and wait for any pending activitations
	     * to complete.. (the following is an expansion of 
	     * thread_set_state())
	     */
	
	    thread = act_lock_thread(act);
	    if (!act->active) {
		act_unlock_thread(act);
		act_deallocate(act);
		return port_thread;
	   }
	
	   thread_hold(act);
	
	   while (1) {
		if (!thread || act != thread->top_act)
			break;
	
		act_unlock_thread(act);
		(void) thread_stop_wait(thread);
		nthread = act_lock_thread(act);
		if (nthread == thread)
			break;
		thread_unstop(thread);
		thread = nthread;
	   }
	
	}

	COPYIN_INTSTATE()
	if (isSelf)
		currentState = kOutsideMain;
	else
    		currentState = (interruptState & kInterruptStateMask) >> kInterruptStateShift; 

    if (debugNotify > 5) {
	printf("\nNotifyInterruption: %X, %X, %X, %X, %X, %X\n",
		port_thread, ppcInterruptHandler, interruptStatePtr,
		emulatorDescriptor, originalPC, originalR2 );
    }
    mainPCB = USER_REGS(act);

    switch (currentState)
    {
    case kNotifyPending:
    case kInUninitialized:
	if (debugNotify > 2)
		printf("NotifyInterrupt: kInUninitialized\n");
	break;
		
    case kInPseudoKernel:
    case kOutsideMain:
	if (debugNotify > 2)
		printf("NotifyInterrupt: kInPseudoKernel/kOutsideMain\n");
	interruptState = interruptState
		| ((postIntMask >> kCR2ToBackupShift) & kBackupCR2Mask);
	COPYOUT_INTSTATE();
	break;
		
    case kInSystemContext:
	if (debugNotify > 2) 
		printf("kInSystemContext: old CR %x, postIntMask %x, new CR %x\n",
		mainPCB->cr, postIntMask, mainPCB->cr | postIntMask);
	mainPCB->cr |= postIntMask;
	break;
		
    case kInAlternateContext:
	if (debugNotify > 2)
	printf("kInAlternateContext: IN InterruptState %x, postIntMask %x\n",
			interruptState, postIntMask);
	interruptState = interruptState | ((postIntMask >> kCR2ToBackupShift) & kBackupCR2Mask);
	interruptState = (interruptState & ~kInterruptStateMask);

	if (runningInKernel)
		interruptState |= (kNotifyPending << kInterruptStateShift);
	else
		interruptState |= (kInPseudoKernel << kInterruptStateShift);
		
	(void) copyout((char *)&mainPCB->srr0, (char *)originalPC, sizeof(originalPC));
	(void) copyout((char *)&mainPCB->r2, (char *)originalR2, sizeof(originalR2));
	COPYOUT_INTSTATE();
	if (debugNotify > 2)
	printf("kInAlternateContext: Out interruptState %x, Old PC %x, New %x, R2 %x\n",
		interruptState, mainPCB->srr0, ppcInterruptHandler, mainPCB->r2);

	mainPCB->srr0 = ppcInterruptHandler;
	break;
		
    case kInExceptionHandler:
	if (debugNotify > 2)
		printf("NotifyInterrupt: kInExceptionHandler\n");
	interruptState = interruptState | ((postIntMask >> kCR2ToBackupShift) & kBackupCR2Mask);
	COPYOUT_INTSTATE();
	break;
		
    default:
	if (debugNotify)
		printf("NotifyInterrupt: default ");
		printf("Interruption while running in unknown state\n");
		printf("interruptState = 0x%X\n",currentState);
	break;
    }

	if (!isSelf) {
		if (thread && act == thread->top_act)
			thread_unstop(thread);
		thread_release(act);
   		act_unlock_thread(act);
   		thread_resume(act);
	}

    act_deallocate(act);

   return port_thread;
}
