/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
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

/*
 * These function replace the Mk68 assembly routines found in qAddToEnd.s and
 * q????.s
 *    Modified for MP, 1996 by Tuyen Nguyen
 *   Modified, April 9, 1997 by Tuyen Nguyen for MacOSX.
 */
extern atlock_t adspgen_lock;


struct qlink {
	struct qlink *qlinkp;
};

/* ----------------------------------------------------------------------
 * void qAddToEnd(void *qhead, void *qelem)
 * 
 * INPUTS:
 * 		Ptr		to ptr to 1st item in queue
 *		Ptr		to item to add to end of queue
 * OUTPUTS:
 * 		none
 *
 * Assumptions: The link field is the FIRST field of the qelem structure.
 * ----------------------------------------------------------------------
 */
int qAddToEnd(qhead, qelem)
	struct qlink **qhead;
	struct qlink *qelem;
{
	/* define our own type to access the next field. NOTE THAT THE "NEXT"
         * FIELD IS ASSUMED TO BE THE FIRST FIELD OF THE STRUCTURE
	 */

	register struct qlink *q;

	/* Scan the linked list to the end and update the previous
         * element next field. (do that protocted).
         */

	q = *qhead;
	if (q) {
		while (q->qlinkp) {
			/* are we about to link to ourself */
			if (q == qelem)
				goto breakit;
			q = q->qlinkp;
		}
		q->qlinkp = qelem;
	}
	else {
		*qhead = qelem;
	}
	qelem->qlinkp = (struct qlink *) 0;
breakit:
#ifdef NOTDEF
	DPRINTF("%s: qhead=%x added elem=%x\n","qAddToEnd", qhead, qelem);
#endif
	return 0;
}



/* ----------------------------------------------------------------------
 *  qfind_m
 * 	void* qfind_m(void *qhead, void NPTR match, ProcPtr compare_fnx)
 *  
 *  Hunt down a linked list of queue elements calling the compare 
 *  function on each item. When the compare function returns true, 
 *  return ptr to the queue element.
 * 
 * 
 *  INPUTS:
 *  		qhead	Address of ptr to first item in queue
 * 		match	
 * 		compare_fnx
 *  OUTPUTS:
 *  		D0 & A0	Ptr to queue element or NIL
 *  REGISTERS:
 * 	D0,D1,A0,A1
 * ----------------------------------------------------------------------
 */
void* qfind_m(qhead, match, compare_fnx)
	CCBPtr  qhead;
	void  *match;
	ProcPtr compare_fnx;
{
	int s;
	CCBPtr queue_item = qhead;

	ATDISABLE(s, adspgen_lock);
	while (queue_item) { 
		if ((*compare_fnx)(queue_item,match)) 
			break;
		
		queue_item = queue_item->ccbLink;
	}
	ATENABLE(s, adspgen_lock);

	return (queue_item);
}
