/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * TimerElem.c 
 *
 * From v01.00  04/15/90 mbs
 *    Modified for MP, 1996 by Tuyen Nguyen
 *   Modified, April 9, 1997 by Tuyen Nguyen for MacOSX.
*/

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <machine/spl.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/mbuf.h>
#include <sys/socket.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

atlock_t adsptmr_lock;

extern	void DoTimerElem();	/* (TimerElemPtr t);  
				 * External routine called to 
				 * process each one. */

/*
 * InsertTimerElem
 * 
 * INPUTS:
 * 	qhead		Address of ptr to first item in list
 *	t		timer element to link in
 *	vbl		timer value to use
 * OUTPUTS:
 * 	void
 */
void InsertTimerElem(qhead, t, val)
    /* (TimerElemPtr *qhead, TimerElemPtr t, word val) */
    TimerElemPtr *qhead, t;
    int val;
{
    TimerElemPtr p;		/* parent pointer */
    TimerElemPtr n;		/* current */
    int	s;
	
    ATDISABLE(s, adsptmr_lock);
	
    if (t->onQ) {
        /*
	 * someone else beat us to the punch and put this
	 * element back on the queue, just return in this case
	 */
        ATENABLE(s, adsptmr_lock);
	return;
    }
    p = (TimerElemPtr)qhead;

    while (n = p->link) {
	if (val <= n->timer)	/* Do we go in front of this? */
	{
	    n->timer -= val;	/* Yes, adjust his delta */
	    break;		/* and go link us in */
	}
	val -= n->timer;	/* No, subtract off delta from our value */
	p = n;
    }				/* while */
	
    /* It must go after item pointed to by p and in front of item 
     * pointed to by n */

    t->onQ = 1;	/* we're linked in now */
    p->link = t;		/* parent points to us */
    t->timer = val;		/* this is our value */
    t->link = n;		/* we point to n */
    
    ATENABLE(s, adsptmr_lock);
}


/*
 * RemoveTimerElem
 * 
 * INPUTS:
 *	qhead		Address of ptr to first item in list
 *	t		timer element to link in
 * OUTPUTS:
 * 	void
 */
void RemoveTimerElem(qhead, t)	/* (TimerElemPtr *qhead, TimerElemPtr t) */
    TimerElemPtr *qhead, t;
{
    TimerElemPtr p;		/* parent pointer */
    TimerElemPtr n;		/* current */
    int	s;
	
    ATDISABLE(s, adsptmr_lock);
	
    if ( !t->onQ) {
        /*
	 * someone else beat us to the punch and took this
	 * element off of the queue, just return in this case
	 */
        ATENABLE(s, adsptmr_lock);
	return;
    }
    p = (TimerElemPtr)qhead;

    while (n = p->link)	/* Get next item in queue */
    {
	if (n == t)		/* Is it us? */
	{
	    if (p->link = n->link) /* Link our parent to our child */
	    {
		n->link->timer += t->timer; /* and update child's timer */
	    }
	    n->onQ = 0;		/* Not on linked list anymore */
	    break;
	}
	p = n;
    }				/* while */
	
    ATENABLE(s, adsptmr_lock);
}


/*
 * TimerQueueTick
 * 
 * INPUTS:
 * 	qhead		Address of ptr to first item in list
 * 	
 * OUTPUTS:
 * 	void
 */
void TimerQueueTick(qhead)	/* (TimerElemPtr *qhead) */
    TimerElemPtr *qhead;
{
    TimerElemPtr p;		/* parent pointer */
    TimerElemPtr n;		/* current */
    int	s;
	
    ATDISABLE(s, adsptmr_lock);
	
    p = (TimerElemPtr)qhead;
    if (p->link)		/* Is anything on queue? */
	p->link->timer--;	/* Yes, decrement by a tick */
    else
	goto done;		/* No, we're outta' here */
		
    while ((n = p->link) && 
	   (n->timer == 0)) /* Next guy needs to be serviced */
    {
	p->link = n->link;	/* Unlink us */
	n->onQ	= 0;

	ATENABLE(s, adsptmr_lock);
	DoTimerElem(n);
	ATDISABLE(s, adsptmr_lock);

	p = (TimerElemPtr)qhead;
    }				/* while */
	
done:
    ATENABLE(s, adsptmr_lock);
}
