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

/*
 */
#include	<mach_prof.h>

#include	<mach/task_server.h>
#include	<mach/thread_act_server.h>

#if MACH_PROF
#include        <cpus.h>
#include	<kern/thread.h>
#include	<kern/thread_swap.h>
#include	<kern/queue.h>
#include	<kern/profile.h>
#include	<kern/sched_prim.h>
#include	<kern/spl.h>
#include	<kern/misc_protos.h>
#include	<ipc/ipc_space.h>
#include        <machine/machparam.h>
#include	<mach/prof.h>

thread_t profile_thread_id = THREAD_NULL;
int profile_sample_count = 0;	/* Provided for looking at from kdb. */
extern kern_return_t task_suspend(task_t task);	/* ack */

/* Forwards */
prof_data_t	pbuf_alloc(void);
void		pbuf_free(
			prof_data_t	pbuf);
void		profile_thread(void);
void		send_last_sample_buf(
			prof_data_t	pbuf);

/*
 *****************************************************************************
 * profile_thread is the profile/trace kernel support thread. It is started
 * by a server/user request through task_sample, or thread_sample. The profile
 * thread dequeues messages and sends them to the receive_prof thread, in the
 * server, via the send_samples and send_notices mig interface functions. If
 * there are no messages in the queue profile thread blocks until wakened by
 * profile (called in from mach_clock), or last_sample (called by thread/task_
 * sample).
*/

void
profile_thread(void)
{
    spl_t	    s;
    buffer_t	    buf_entry;
    queue_entry_t   prof_queue_entry;
    prof_data_t	    pbuf;
    kern_return_t   kr;
    int		    j;

    thread_swappable(current_act(), FALSE);

    /* Initialise the queue header for the prof_queue */
    mpqueue_init(&prof_queue);

    while (TRUE) {

	/* Dequeue the first buffer. */
	s = splsched();
	mpdequeue_head(&prof_queue, &prof_queue_entry);
	splx(s);

	if ((buf_entry = (buffer_t) prof_queue_entry) == NULLPBUF) { 
	    assert_wait((event_t) profile_thread, THREAD_UNINT);
	    thread_block((void (*)(void)) 0);
	    if (current_thread()->wait_result != THREAD_AWAKENED)
		break;
	} else 
	{
	    int		    dropped;

	    pbuf = buf_entry->p_prof;
	    kr = send_samples(pbuf->prof_port, (void *)buf_entry->p_zone,
			(mach_msg_type_number_t)buf_entry->p_index);
	    profile_sample_count += buf_entry->p_index;
	    if (kr != KERN_SUCCESS)
	      printf("send_samples(%x, %x, %d) error %x\n",
			pbuf->prof_port, buf_entry->p_zone, buf_entry->p_index, kr); 
	    dropped = buf_entry->p_dropped;
	    if (dropped > 0) {
		printf("kernel: profile dropped %d sample%s\n", dropped,
		       dropped == 1 ? "" : "s");
		buf_entry->p_dropped = 0;
	    }

	    /* Indicate you've finished the dirty job */
	    buf_entry->p_full = FALSE;
	    if (buf_entry->p_wakeme)
	      thread_wakeup((event_t) &buf_entry->p_wakeme);
	}

    }
    /* The profile thread has been signalled to exit.  Any threads waiting
       for the last buffer of samples to be acknowledged should be woken
       up now.  */
    profile_thread_id = THREAD_NULL;
    while (1) {
	s = splsched();
	mpdequeue_head(&prof_queue, &prof_queue_entry);
	splx(s);
	if ((buf_entry = (buffer_t) prof_queue_entry) == NULLPBUF)
	    break;
	if (buf_entry->p_wakeme)
	    thread_wakeup((event_t) &buf_entry->p_wakeme);
    }
#if 0	/* XXXXX */
    thread_halt_self();
#else
	panic("profile_thread(): halt_self");
#endif	/* XXXXX */
}

/*
 *****************************************************************************
 * send_last_sample is the drain mechanism to allow partial profiled buffers
 * to be sent to the receive_prof thread in the server.
 *****************************************************************************
*/

void
send_last_sample_buf(prof_data_t pbuf)
{
    spl_t    s;
    buffer_t buf_entry;

    if (pbuf == NULLPROFDATA)
	return;

    /* Ask for the sending of the last PC buffer.
     * Make a request to the profile_thread by inserting
     * the buffer in the send queue, and wake it up. 
     * The last buffer must be inserted at the head of the
     * send queue, so the profile_thread handles it immediatly. 
     */ 
    buf_entry = pbuf->prof_area + pbuf->prof_index;
    buf_entry->p_prof = pbuf;

    /* 
       Watch out in case profile thread exits while we are about to
       queue data for it.
     */
    s = splsched();
    if (profile_thread_id == THREAD_NULL)
	splx(s);
    else {
	buf_entry->p_wakeme = 1;
	mpenqueue_tail(&prof_queue, &buf_entry->p_list);
	thread_wakeup((event_t) profile_thread);
	assert_wait((event_t) &buf_entry->p_wakeme, THREAD_ABORTSAFE);
	splx(s); 
	thread_block((void (*)(void)) 0);
    }
}


/*
 *****************************************************************************
 * add clock tick parameters to profile/trace buffers. Called from the mach_
 * clock heritz_tick function. DCI version stores thread, sp, and pc values
 * into the profile/trace buffers. MACH_PROF version just stores pc values.
 *****************************************************************************
 */

void
profile(natural_t	pc,
	prof_data_t	pbuf)
{
    natural_t inout_val = pc; 
    buffer_t buf_entry;

    if (pbuf == NULLPROFDATA)
	return;
    
    /* Inserts the PC value in the buffer of the thread */
    set_pbuf_value(pbuf, &inout_val); 
    switch((int)inout_val) {
    case 0: 
	if (profile_thread_id == THREAD_NULL) {
	  reset_pbuf_area(pbuf);
	}
	break;
    case 1: 
	/* Normal case, value successfully inserted */
	break;
    case 2 : 
	/*
	 * The value we have just inserted caused the
	 * buffer to be full, and ready to be sent.
	 * If profile_thread_id is null, the profile
	 * thread has been killed.  Since this generally
	 * happens only when the O/S server task of which
	 * it is a part is killed, it is not a great loss
	 * to throw away the data.
	 */
	if (profile_thread_id == THREAD_NULL) {
	  reset_pbuf_area(pbuf);
	  break;
	}

	buf_entry = (buffer_t) &pbuf->prof_area[pbuf->prof_index];
	buf_entry->p_prof = pbuf;
	mpenqueue_tail(&prof_queue, &buf_entry->p_list);
	
	/* Switch to another buffer */
	reset_pbuf_area(pbuf);
	
	/* Wake up the profile thread */
	if (profile_thread_id != THREAD_NULL)
	  thread_wakeup((event_t) profile_thread);
	break;
      
      default: 
	printf("profile : unexpected case\n"); 
    }
}

/*
 *****************************************************************************
 * pbuf_alloc creates a profile/trace buffer and assoc. zones for storing
 * profiled items.
 *****************************************************************************
 */

prof_data_t
pbuf_alloc(void)
{
	register prof_data_t pbuf;
	register int i;
	register natural_t *zone;

	pbuf = (prof_data_t)kalloc(sizeof(struct prof_data));
	if (!pbuf)
		return(NULLPROFDATA);
	pbuf->prof_port = MACH_PORT_NULL;
	for (i=0; i< NB_PROF_BUFFER; i++) {
		zone = (natural_t *)kalloc(SIZE_PROF_BUFFER*sizeof(natural_t));
		if (!zone) {
			i--;
			while (i--)
				kfree((vm_offset_t)pbuf->prof_area[i].p_zone,
				      SIZE_PROF_BUFFER*sizeof(natural_t));
			kfree((vm_offset_t)pbuf, sizeof(struct prof_data));
			return(NULLPROFDATA);
		}
		pbuf->prof_area[i].p_zone = zone;
		pbuf->prof_area[i].p_full = FALSE;
	}
	pbuf->prof_port = MACH_PORT_NULL;
	return(pbuf);
}

/*
 *****************************************************************************
 * pbuf_free free memory allocated for storing profile/trace items. Called
 * when a task is no longer profiled/traced. Pbuf_free tears down the memory
 * alloced in pbuf_alloc. It does not check to see if the structures are valid
 * since it is only called by functions in this file.
 *****************************************************************************
 */
void
pbuf_free(
	prof_data_t	pbuf)
{
	register int i;

	if (pbuf->prof_port)
		ipc_port_release_send(pbuf->prof_port);
	
	for(i=0; i < NB_PROF_BUFFER ; i++)
		kfree((vm_offset_t)pbuf->prof_area[i].p_zone,
		      SIZE_PROF_BUFFER*sizeof(natural_t));
	kfree((vm_offset_t)pbuf, sizeof(struct prof_data));
}

#endif /* MACH_PROF */

/*
 *****************************************************************************
 * Thread_sample is used by MACH_PROF to profile a single thread, and is only
 * stub in DCI.
 *****************************************************************************
 */

kern_return_t
thread_sample(
	thread_act_t	thr_act,
	ipc_port_t	reply)
{
    /* 
     * This routine is called every time that a new thread has made
     * a request for the sampling service. We must keep track of the 
     * correspondance between its identity (thread) and the port
     * we are going to use as a reply port to send out the samples resulting 
     * from its execution. 
     */
#if !MACH_PROF
    return KERN_FAILURE;
#else 
    prof_data_t	    pbuf;
    vm_offset_t	    vmpbuf;

    if (reply != MACH_PORT_NULL) {
	if (thr_act->act_profiled) 	/* yuck! */
		return KERN_INVALID_ARGUMENT;
	/* Start profiling this activation, do the initialization. */
	pbuf = pbuf_alloc();
	if ((thr_act->profil_buffer = pbuf) == NULLPROFDATA) {
	    printf("thread_sample: cannot allocate pbuf\n");
	    return KERN_RESOURCE_SHORTAGE;
	} 
	else {
	    if (!set_pbuf_nb(pbuf, NB_PROF_BUFFER-1)) {
		printf("mach_sample_thread: cannot set pbuf_nb\n");
		return KERN_FAILURE;
	    }
	    reset_pbuf_area(pbuf);
	}
	pbuf->prof_port = reply;
	thr_act->act_profiled = TRUE;
	thr_act->act_profiled_own = TRUE;
	if (profile_thread_id == THREAD_NULL)
	    profile_thread_id = kernel_thread(kernel_task, profile_thread);
    } else {
	if (!thr_act->act_profiled)
		return(KERN_INVALID_ARGUMENT);

	thr_act->act_profiled = FALSE;
	/* do not stop sampling if thread is not profiled by its own */

	if (!thr_act->act_profiled_own)
	    return KERN_SUCCESS;
	else
	    thr_act->act_profiled_own = FALSE;

	send_last_sample_buf(thr_act->profil_buffer);
	pbuf_free(thr_act->profil_buffer);
	thr_act->profil_buffer = NULLPROFDATA;
    }
    return KERN_SUCCESS;
#endif /* MACH_PROF */
}

/*
 *****************************************************************************
 * Task_sample is used to profile/trace tasks - all thread within a task using
 * a common profile buffer to collect items generated by the hertz_tick. For
 * each task profiled a profile buffer is created that associates a reply port
 * (used to send the data to a server thread), task (used for throttling), and
 * a zone area (used to store profiled/traced items).
 *****************************************************************************
 */

kern_return_t
task_sample(
	task_t		task,
	ipc_port_t	reply)
{
#if !MACH_PROF
    return KERN_FAILURE;
#else
    prof_data_t	    pbuf=task->profil_buffer;
    vm_offset_t	    vmpbuf;
    boolean_t	    turnon = (reply != MACH_PORT_NULL);

    if (task == TASK_NULL)
	    return KERN_INVALID_ARGUMENT;
    if (turnon)			/* Do we want to profile this task? */
    {
	pbuf = pbuf_alloc();	/* allocate a profile buffer */
	task_lock(task);
	if (task->task_profiled) { /* if it is already profiled return so */
		task_unlock(task);
		if (pbuf != NULLPROFDATA)
		    pbuf_free(pbuf);
		return(KERN_INVALID_ARGUMENT);
	}
	if (pbuf == NULLPROFDATA) {
	    task_unlock(task);
	    return KERN_RESOURCE_SHORTAGE; /* can't allocate a buffer, quit */
	}
	task->profil_buffer = pbuf;
	
	if (!set_pbuf_nb(pbuf, NB_PROF_BUFFER-1)) {
	    pbuf_free(pbuf);
	    task_unlock(task);
	    return KERN_FAILURE;
	}
	reset_pbuf_area(pbuf);
	pbuf->prof_port = reply; /* assoc. buffer with reply port */
    } else {			/* We want to stop profiling/tracing */
	task_lock(task);
	if (!task->task_profiled) { /* but this task is not being profiled */
	    task_unlock(task);
	    return(KERN_INVALID_ARGUMENT);
	}
    }

    /*
     * turnon = FALSE && task_profile = TRUE ||
     * turnon = TRUE  && task_profile = FALSE
     */

    if (turnon != task->task_profiled) {
	int actual, i;
	thread_act_t thr_act;

	if (turnon && profile_thread_id == THREAD_NULL)	/* 1st time thru? */
	    profile_thread_id =	/* then start profile thread. */
		kernel_thread(kernel_task, profile_thread);
	task->task_profiled = turnon;  
	actual = task->thr_act_count; 
	for (i = 0, thr_act = (thread_act_t)queue_first(&task->thr_acts);
	     i < actual;
	     i++, thr_act = (thread_act_t)queue_next(&thr_act->thr_acts)) {
		  if (!thr_act->act_profiled_own) {
		    thr_act->act_profiled = turnon;
		    if (turnon) {
			thr_act->profil_buffer = task->profil_buffer;
		  	thr_act->act_profiled = TRUE;
		    } else {
			thr_act->act_profiled = FALSE;
		        thr_act->profil_buffer = NULLPROFDATA;
		    }
		  }
	}
	if (!turnon) {		/* drain buffers and clean-up */
	    send_last_sample_buf(task->profil_buffer);
	    pbuf_free(task->profil_buffer);
	    task->profil_buffer = NULLPROFDATA;
	}
    }

    task_unlock(task);
    return KERN_SUCCESS;
#endif /* MACH_PROF */
}

