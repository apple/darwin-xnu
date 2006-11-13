/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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

#ifndef _KERN_PROFILE_H
#define _KERN_PROFILE_H

#include <mach/boolean.h>
#include <vm/vm_kern.h> 

#define	NB_PROF_BUFFER		4	/* number of buffers servicing a */
#define	SIZE_PROF_BUFFER	200	/* size of a profil buffer (in natural_t) */
					/* -> at most 1 packet every 2 secs */
					/*	profiled thread */

struct	prof_data {
	struct ipc_port *prof_port;	/* where to send a full buffer */

	struct buffer {
	    queue_chain_t p_list;
	    natural_t	*p_zone;	/* points to the actual storage area */
	    int p_index;		/* next slot to be filled */
	    int p_dropped;		/* # dropped samples when full */
	    boolean_t p_full;		/* is the current buffer full ? */ 
	    struct prof_data *p_prof;	/* base to get prof_port */
	    char p_wakeme;		/* do wakeup when sent */
	} prof_area[NB_PROF_BUFFER];

	int		prof_index;	/* index of the buffer structure */
					/*   currently in use */

};

typedef struct prof_data	*prof_data_t;
#define NULLPROFDATA ((prof_data_t) 0)
typedef struct buffer		*buffer_t;
#define NULLPBUF ((buffer_t) 0)

/* Macros */

#define	set_pbuf_nb(pbuf, nb) \
         (((nb) >= 0 && (nb) < NB_PROF_BUFFER) \
	 ? (pbuf)->prof_index = (nb), 1 \
	 : 0)


#define	get_pbuf_nb(pbuf) \
	(pbuf)->prof_index


/* MACRO set_pbuf_value 
** 
** enters the value 'val' in the buffer 'pbuf' and returns the following
** indications:     0: means that a fatal error occurred: the buffer was full
**                       (it hasn't been sent yet)
**                  1: means that a value has been inserted successfully
**		    2: means that we'v just entered the last value causing 
**			the current buffer to be full.(must switch to 
** 			another buffer and signal the sender to send it)
*/ 

#if	MACH_PROF

#define set_pbuf_value(pbuf, val) \
	 { \
	  register buffer_t a = &((pbuf)->prof_area[(pbuf)->prof_index]); \
	  register int i ;\
	  register boolean_t f = a->p_full; \
			  \
	  if (f == TRUE ) {\
	     a->p_dropped++; \
             *(val) = 0L; \
	  } else { \
	    i = a->p_index++; \
	    a->p_zone[i] = *(val); \
	    if (i == SIZE_PROF_BUFFER-1) { \
               a->p_full = TRUE; \
               *(val) = 2; \
            } \
            else \
		*(val) = 1; \
          } \
	}
         
#define	reset_pbuf_area(pbuf) \
	{ \
	 int i; \
	 (pbuf)->prof_index = ((pbuf)->prof_index + 1) % NB_PROF_BUFFER; \
	 i = (pbuf)->prof_index; \
	 (pbuf)->prof_area[i].p_index = 0; \
	 (pbuf)->prof_area[i].p_dropped = 0; \
	}

#endif	/* MACH_PROF */

/*
** Global variable: the head of the queue of buffers to send 
** It is a queue with locks (uses macros from queue.h) and it
** is shared by hardclock() and the sender_thread() 
*/

mpqueue_head_t prof_queue; 

extern void	profile(
			natural_t	pc,         /* program counter */
			prof_data_t	pbuf);      /* trace/prof data area */

#if MACH_PROF

#define task_prof_init(task) \
	task->task_profiled = FALSE; \
     	task->profil_buffer = NULLPROFDATA;

#define thread_prof_init(thread, task) \
	thread->profiled = task->profiled;	\
	thread->profil_buffer = task->profil_buffer;

#define task_prof_deallocate(task) \
	if (task->profil_buffer) \
		task_sample(task, MACH_PORT_NULL); \

#define thread_prof_deallocate(thread) \
	if (thread->profiled_own && thread->profil_buffer)  \
		thread_sample(thread, MACH_PORT_NULL); \

extern kern_return_t thread_sample(thread_t, ipc_port_t);
extern kern_return_t task_sample(task_t, ipc_port_t);

#else /* !MACH_PROT */

#define task_prof_init(task)
#define thread_prof_init(thread, task)
#define task_prof_deallocate(task)
#define thread_prof_deallocate(thread)
		
#endif	/* !MACH_PROF */

#endif	/* _KERN_PROFILE_H */
